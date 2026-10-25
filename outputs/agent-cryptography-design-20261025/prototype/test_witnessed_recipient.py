import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519
import test_delivery_transport as base
import test_mixed_delivery_transport as fixture
from test_encrypted_mixed_ledger import vault
from test_witnessed_mixed_ledger import backup
from witnessed_recipient import WitnessedMixedRecipientInbox,TLSWitnessedMixedRecipientInbox
from mixed_delivery_terminal import (MixedTerminalDeliveryLedger,MixedTerminalDeliverySender,terminal_attempt,parse_receipt)
from mixed_delivery_transport import attempt,parse_ack
from delivery_transport import StateVault,public,Rejected
from witness_transport import WitnessTLSService,TLSWitnessClient,trusted_register_peer,trusted_revoke_peer,certificate_fingerprint
from witnessed_ledger import ReferenceWitness,canonical,pack_cell,image_hash
from wire import verify_sign1

CRASHES=[]
RECEIVER_WITNESS_REQUESTS=0
LOCK=threading.Lock()


def child(config,point):
    c=json.loads(Path(config).read_text());route=base.unpack_route(c['route'])
    def fault(here):
        if here==point:os._exit(96)
    w=TLSWitnessClient(port=c['port'],cafile=c['ca'],certfile=c['cert'],keyfile=c['cert_key'],witness_public_key=bytes.fromhex(c['witness_key']))
    i=TLSWitnessedMixedRecipientInbox(c['inbox'],deployment=c['deployment'],route=route,vault=StateVault(bytes.fromhex(c['inbox_key']),b'inbox-fixture-01'),clock=lambda:c['now'],witness=w,witness_namespace=c['namespace'],witness_fault=fault)
    if c['recovery']:i.recover_from_witness(fault)
    else:i.accept(bytes.fromhex(c['request']),route['sender_cert'],ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['receiver_key'])),fault)
    raise RuntimeError('cut not reached')


class RecipientWitnessTests(unittest.TestCase):
    ledger_class=MixedTerminalDeliveryLedger
    sender_class=MixedTerminalDeliverySender
    setUpClass=fixture.MixedDeliveryTests.__dict__['setUpClass']
    tearDownClass=fixture.MixedDeliveryTests.__dict__['tearDownClass']
    wclient=fixture.MixedDeliveryTests.wclient
    sender_for=fixture.MixedDeliveryTests.sender_for
    ticket=fixture.MixedDeliveryTests.ticket
    prepared=fixture.MixedDeliveryTests.prepared
    reject=fixture.MixedDeliveryTests.reject
    inbox_rows=fixture.MixedDeliveryTests.inbox_rows

    def setUp(self):
        self.receiver_initialized=False;self.rns='d'*32
        fixture.MixedDeliveryTests.setUp(self)
    def tearDown(self):
        self.rs.__exit__();self.rws.__exit__();self.l.close();self.ws.__exit__();self.tmp.cleanup()
    def start_receiver_authority(self):
        dispatch=self.rws.dispatch
        def counted(*args):
            global RECEIVER_WITNESS_REQUESTS
            with LOCK:RECEIVER_WITNESS_REQUESTS+=1
            return dispatch(*args)
        self.rws.dispatch=counted;self.rws.__enter__()
    def receiver_client(self,role='writer',**kw):
        return TLSWitnessClient(port=self.rws.port,cafile=self.certs['ca'],certfile=self.certs[role][0],keyfile=self.certs[role][1],witness_public_key=kw.pop('witness_public_key',public(self.rwsign)),**kw)
    def kwargs(self,role='writer'):
        return dict(deployment=self.ns,route=self.route,vault=StateVault(self.ivkey,b'inbox-fixture-01'),clock=lambda:self.now,witness=self.receiver_client(role),witness_namespace=self.rns)
    def inbox(self):
        if not self.receiver_initialized:
            # Explicit fixture-only trusted setup. Production open never creates.
            self.rwp=self.root/'recipient-authority';self.rwsign=ed25519.Ed25519PrivateKey.generate()
            for role in ('admin','writer','restorer','observer'):
                trusted_register_peer(self.rwp,self.rns,certificate_fingerprint(self.certs[role][0]),role)
            self.rws=WitnessTLSService(self.rwp,cafile=self.certs['ca'],certfile=self.certs['server'][0],keyfile=self.certs['server'][1],signing_key=self.rwsign)
            self.start_receiver_authority()
            i=TLSWitnessedMixedRecipientInbox.create(self.ip,**self.kwargs('admin'));i.close();self.receiver_initialized=True
        return TLSWitnessedMixedRecipientInbox(self.ip,**self.kwargs())
    def closed_rows(self):
        i=self.inbox()
        try:return [dict(r) for r in i.db.execute('SELECT * FROM inbox_closed')]
        finally:i.close()
    def clone(self,path,role='writer'):return TLSWitnessedMixedRecipientInbox(path,**self.kwargs(role))
    def snapshot(self,path):
        i=self.inbox()
        try:backup(i.db,path)
        finally:i.close()
    def control(self):
        self.now=160
        return self.l.prepare_terminal('t','d',self.gsign)
    def crash(self,point,request=b'',recovery=False,operation='accept'):
        c=dict(route={k:v.hex() if isinstance(v,bytes) else v for k,v in self.route.items()},deployment=self.ns,namespace=self.rns,
            inbox=str(self.ip),inbox_key=self.ivkey.hex(),now=self.now,recovery=recovery,request=request.hex(),receiver_key=base.keybytes(self.rsign).hex(),
            port=self.rws.port,ca=str(self.certs['ca']),cert=str(self.certs['writer'][0]),cert_key=str(self.certs['writer'][1]),witness_key=public(self.rwsign).hex())
        path=self.root/'child.json'
        with os.fdopen(os.open(str(path),os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600),'w') as f:json.dump(c,f)
        result=subprocess.run([sys.executable,__file__,'--child',str(path),point],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,96,result.stderr);path.unlink();CRASHES.append(dict(operation=operation,point=point))

    def test_complete_mixed_pipeline_with_independent_receiver_authority(self):
        self.ticket(ttl=1);self.l.admit_delivery('t','c','reader','count','gateway','session',60)
        self.now=101;accounts=[tuple(r) for r in self.l.db.execute('SELECT * FROM accounts')]
        self.assertEqual(self.sender.reconcile(self.l,'t','d'),'CLOSED');self.assertEqual(self.sender.deliver(self.l,'t','count'),'ACKED')
        i=self.inbox()
        try:
            self.assertEqual(i.audit(),[]);self.assertEqual(i.next_sequence(),3);self.assertNotEqual(i.namespace,self.l.namespace)
            image=self.receiver_client().head(self.rns,True)['image'];self.assertNotIn(self.ivkey.hex().encode(),image)
        finally:i.close()
        self.assertEqual([tuple(r) for r in self.l.db.execute('SELECT * FROM accounts')],accounts);self.assertEqual(self.l.audit(),[])

    def test_stale_accepted_copy_cannot_reaccept_and_restores_original_time(self):
        raw,route=self.prepared();old=self.root/'old';self.snapshot(old)
        request=attempt(raw,b'a'*32);self.sender.exchange(request,route);self.now=110
        i=self.clone(old)
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:i.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign))
            self.assertEqual(i.db.execute('SELECT count(*) FROM inbox').fetchone()[0],0)
            i.recover_from_witness();ack=i.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign)
            self.assertEqual(parse_ack(ack,attempt(raw,b'b'*32),raw,self.ns,route)['accepted_at'],100);self.assertEqual(i.audit(),[])
        finally:i.close()

    def test_stale_closed_copy_restores_barrier_and_first_closure(self):
        envelope,route=self.prepared();old=self.root/'old';self.snapshot(old);control,_=self.control();request=terminal_attempt(control,b'c'*32)
        self.sender.exchange(request,route);self.now=170;i=self.clone(old)
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:i.accept(request,route['sender_cert'],self.rsign))
            i.recover_from_witness();receipt=i.accept(terminal_attempt(control,b'd'*32),route['sender_cert'],self.rsign)
            self.assertEqual(parse_receipt(receipt,terminal_attempt(control,b'd'*32),control,self.ns,route)['event_at'],160)
            self.reject('DELIVERY_CLOSED',lambda:i.accept(attempt(envelope,b'e'*32),route['sender_cert'],self.rsign));self.assertEqual(i.audit(),[])
        finally:i.close()

    def test_fresh_replica_restores_ciphertexts_sequences_and_both_event_kinds(self):
        self.ticket(ttl=1);self.l.admit_delivery('t','c','reader','count','gateway','session',60);self.now=101
        self.sender.reconcile(self.l,'t','d');self.sender.deliver(self.l,'t','count');original=self.inbox()
        try:expected=original.state_image()
        finally:original.close()
        i=TLSWitnessedMixedRecipientInbox.restore_new(self.root/'fresh',**self.kwargs('restorer'))
        try:self.assertEqual(i.state_image(),expected);self.assertEqual(i.audit(),[])
        finally:i.close()

    def test_no_automatic_rebootstrap_missing_store_authority_or_old_profile(self):
        from mixed_delivery_terminal import MixedTerminalRecipientInbox
        self.reject('INBOX_RECOVERY_REQUIRED',lambda:self.clone(self.root/'missing'))
        self.reject('WITNESS_ALREADY_INITIALIZED',lambda:TLSWitnessedMixedRecipientInbox.create(self.root/'new',**self.kwargs('admin')))
        self.reject('FRESH_REPLICA_REQUIRED',lambda:TLSWitnessedMixedRecipientInbox.restore_new(self.ip,**self.kwargs()))
        self.reject('INBOX_PROFILE_MISMATCH',lambda:MixedTerminalRecipientInbox(self.ip,deployment=self.ns,route=self.route,vault=StateVault(self.ivkey,b'inbox-fixture-01'),clock=lambda:100))
        bad=dict(self.kwargs(),witness_namespace=self.ns)
        self.reject('INVALID_RECIPIENT_AUTHORITY',lambda:TLSWitnessedMixedRecipientInbox(self.ip,**bad))
        bad=dict(self.kwargs(),witness=ReferenceWitness(self.root/'reference'))
        try:self.reject('AUTHENTICATED_WITNESS_REQUIRED',lambda:TLSWitnessedMixedRecipientInbox(self.ip,**bad))
        finally:bad['witness'].close()

    def test_receiver_writer_cannot_use_sender_authority_and_roles_separate_restore(self):
        self.reject('WITNESS_ACCESS_DENIED',lambda:self.receiver_client().head(self.ns))
        self.reject('WITNESS_ACCESS_DENIED',lambda:self.wclient().head(self.rns))
        raw,route=self.prepared();old=self.root/'old';self.snapshot(old);self.sender.exchange(attempt(raw,b'a'*32),route)
        restorer=self.clone(old,'restorer')
        try:
            restorer.recover_from_witness();self.assertEqual(restorer.audit(),[])
            self.reject('WITNESS_ACCESS_DENIED',lambda:restorer.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign))
        finally:restorer.close()
        observer=self.inbox();observer.witness=self.receiver_client('observer')
        try:self.reject('WITNESS_ACCESS_DENIED',observer.recover_from_witness)
        finally:observer.close()

    def test_wrong_witness_key_and_revoked_receiver_writer_cannot_sign_receipt(self):
        raw,route=self.prepared();i=self.inbox();i.witness=self.receiver_client(witness_public_key=public(self.gsign))
        try:
            with self.assertRaises(Rejected):i.accept(attempt(raw,b'a'*32),route['sender_cert'],self.rsign)
            self.assertEqual(i.db.execute('SELECT count(*) FROM inbox').fetchone()[0],0)
        finally:i.close()
        trusted_revoke_peer(self.rwp,self.rns,certificate_fingerprint(self.certs['writer'][0]))
        i=self.inbox()
        try:self.reject('WITNESS_ACCESS_DENIED',lambda:i.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign))
        finally:i.close()

    def test_rejected_expired_request_persists_witnessed_clock_floor(self):
        raw,route=self.prepared();old=self.root/'old';self.snapshot(old);self.now=160;i=self.inbox()
        try:self.reject('TICKET_EXPIRED',lambda:i.accept(attempt(raw,b'a'*32),route['sender_cert'],self.rsign))
        finally:i.close()
        self.now=100;i=self.clone(old)
        try:
            i.recover_from_witness();self.assertEqual(i.db.execute('SELECT observed FROM inbox_clock').fetchone()[0],160)
            self.reject('INBOX_CLOCK_ROLLBACK',lambda:i.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign))
        finally:i.close()

    def test_local_record_deletion_or_event_time_edit_is_fenced_and_repaired(self):
        raw,route=self.prepared();self.sender.exchange(attempt(raw,b'a'*32),route);i=self.inbox()
        try:
            for sql in ['DELETE FROM inbox','UPDATE inbox SET accepted_at=101','UPDATE inbox_clock SET observed=0']:
                i.db.execute(sql);self.reject('LOCAL_STATE_DIVERGED',lambda:i.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign))
                i.recover_from_witness();self.assertEqual(i.audit(),[])
            self.assertEqual(i.db.execute('SELECT accepted_at FROM inbox').fetchone()[0],100)
        finally:i.close()

    def test_competing_clones_at_same_authority_head_only_one_commits(self):
        raw,route=self.prepared();paths=[self.root/'a',self.root/'b']
        for path in paths:self.snapshot(path)
        barrier=threading.Barrier(2)
        def call(path):
            i=self.clone(path)
            def fault(point):
                if point=='before_witness_accept':barrier.wait(timeout=5)
            i.witness_fault=fault
            try:
                try:i.accept(attempt(raw,os.urandom(32)),route['sender_cert'],self.rsign);return 'accepted'
                except Rejected as e:return str(e)
            finally:i.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(call,paths))
        self.assertEqual(sorted(results),['WITNESS_CAS_CONFLICT','accepted'])
        for path in paths:
            i=self.clone(path)
            try:i.recover_from_witness();self.assertEqual(i.db.execute('SELECT count(*) FROM inbox').fetchone()[0],1)
            finally:i.close()

    def test_unknown_commit_from_dropped_authenticated_reply_recovers_exact_acceptance(self):
        raw,route=self.prepared();i=self.inbox();original=self.rws.fault
        def fault(point):
            if point=='after_dispatch':raise ConnectionError('reply lost')
        # Drop only CAS reply; head must still pass.
        dispatch=self.rws.dispatch
        def drop_after_cas(raw_meta,body,request,peer):
            result=dispatch(raw_meta,body,request,peer)
            if request['method']=='cas':raise ConnectionError('accepted CAS reply lost')
            return result
        self.rws.dispatch=drop_after_cas
        try:
            with self.assertRaises((OSError,ConnectionError)):i.accept(attempt(raw,b'a'*32),route['sender_cert'],self.rsign)
            self.assertEqual(i.db.execute('SELECT count(*) FROM inbox').fetchone()[0],0)
            self.rws.dispatch=dispatch;i.recover_from_witness()
            self.assertEqual(i.db.execute('SELECT accepted_at FROM inbox').fetchone()[0],100)
        finally:self.rws.dispatch=dispatch;self.rws.fault=original;i.close()

    def test_wrong_key_or_route_and_malformed_authoritative_image_fail_atomically(self):
        raw,route=self.prepared();self.sender.exchange(attempt(raw,b'a'*32),route);i=self.inbox();before=i.state_image()
        admin=self.receiver_client('admin');head=admin.head(self.rns,True)
        state=json.loads(head['image']);state['rows']['inbox'][0][3]=pack_cell(200)
        admin.compare_and_store(self.rns,head['seq'],head['digest'],canonical(state),'a'*32)
        try:
            self.reject('INBOX_AUDIT_FAILED',i.recover_from_witness);self.assertEqual(i.state_image(),before)
        finally:i.close()
        wrong=dict(self.kwargs(),vault=StateVault(bytes(32),b'inbox-fixture-01'))
        self.reject('INBOX_PROFILE_MISMATCH',lambda:TLSWitnessedMixedRecipientInbox(self.ip,**wrong))
        changed=dict(self.kwargs(),route=dict(self.route,session='other'))
        self.reject('INBOX_PROFILE_MISMATCH',lambda:TLSWitnessedMixedRecipientInbox(self.ip,**changed))

    def test_authority_changes_during_restore_aborts_without_partial_records(self):
        raw,route=self.prepared();old=self.root/'old';self.snapshot(old);self.sender.exchange(attempt(raw,b'a'*32),route)
        i=self.clone(old);before=i.state_image();client=i.witness;original=client.head
        def raced(namespace,include_image=False):
            value=original(namespace,include_image)
            if not include_image:return dict(value,seq=value['seq']+1)
            return value
        try:
            with patch.object(client,'head',side_effect=raced):self.reject('WITNESS_CHANGED_DURING_RECOVERY',i.recover_from_witness)
            self.assertEqual(i.state_image(),before)
        finally:i.close()

    def test_size_limit_fails_without_losing_prior_records_or_emitting_ack(self):
        raw,route=self.prepared();i=self.inbox();head=i.witness.head(self.rns);limit=len(i.state_image())
        try:
            with patch('witnessed_ledger.MAX_IMAGE',limit):self.reject('INVALID_WITNESS_IMAGE',lambda:i.accept(attempt(raw,b'a'*32),route['sender_cert'],self.rsign))
            self.assertEqual(i.witness.head(self.rns),head);self.assertEqual(i.db.execute('SELECT count(*) FROM inbox').fetchone()[0],0)
            self.assertEqual(i.audit(),[])
        finally:i.close()

    def test_process_death_accept_and_close_authority_boundaries(self):
        scenarios=[('accept','before_witness_accept'),('accept','after_witness_accept'),('accept','after_local_anchor_write'),('accept','after_inbox_commit'),
                   ('close','before_inbox_terminal_commit'),('close','after_witness_accept'),('close','after_inbox_terminal_commit')]
        for operation,point in scenarios:
            with self.subTest(operation=operation,point=point):
                raw,route=self.prepared()
                if operation=='close':raw,_=self.control();request=terminal_attempt(raw,b'c'*32)
                else:request=attempt(raw,b'a'*32)
                self.crash(point,request,operation=operation);i=self.inbox()
                try:i.recover_from_witness();i.accept(request,route['sender_cert'],self.rsign);self.assertEqual(i.audit(),[])
                finally:i.close()
                self.assertEqual(len(self.closed_rows() if operation=='close' else self.inbox_rows()),1)
                self.tearDown();self.setUp()

    def test_process_death_recovery_is_atomic(self):
        raw,route=self.prepared();old=self.root/'old';self.snapshot(old);self.sender.exchange(attempt(raw,b'a'*32),route)
        for point in ['after_recovery_delete','before_recovery_commit','after_recovery_commit']:
            shutil.copyfile(old,self.ip);self.crash(point,recovery=True,operation='restore');i=self.inbox()
            try:
                count=i.db.execute('SELECT count(*) FROM inbox').fetchone()[0]
                self.assertEqual(count,1 if point=='after_recovery_commit' else 0)
                i.recover_from_witness();self.assertEqual(i.audit(),[])
            finally:i.close()

    def test_rolling_back_both_receiver_and_authority_remains_negative_control(self):
        raw,route=self.prepared();old=self.root/'old';oldw=self.root/'old-authority';self.snapshot(old)
        db=sqlite3.connect(str(self.rwp));backup(db,oldw);db.close()
        self.sender.exchange(attempt(raw,b'a'*32),route)
        # Stop live authority before restoring its complete historical file.
        self.rws.__exit__();shutil.copyfile(old,self.ip);shutil.copyfile(oldw,self.rwp)
        self.rws=WitnessTLSService(self.rwp,cafile=self.certs['ca'],certfile=self.certs['server'][0],keyfile=self.certs['server'][1],signing_key=self.rwsign);self.start_receiver_authority()
        self.now=110;i=self.inbox()
        try:
            self.assertEqual(i.audit(),[]);ack=i.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign)
            self.assertEqual(parse_ack(ack,attempt(raw,b'b'*32),raw,self.ns,route)['accepted_at'],110)
        finally:i.close()


    def test_deleted_closed_barrier_is_restored_before_any_new_receipt(self):
        envelope,route=self.prepared();raw,_=self.control();request=terminal_attempt(raw,b'a'*32)
        self.sender.exchange(request,route);i=self.inbox()
        try:
            i.db.execute('DELETE FROM inbox_closed')
            self.reject('LOCAL_STATE_DIVERGED',lambda:i.accept(request,route['sender_cert'],self.rsign))
            i.recover_from_witness();self.assertEqual(i.db.execute('SELECT closed_at FROM inbox_closed').fetchone()[0],160)
            self.reject('DELIVERY_CLOSED',lambda:i.accept(attempt(envelope,b'b'*32),route['sender_cert'],self.rsign))
        finally:i.close()

    def test_missing_authority_head_is_not_automatically_bootstrapped(self):
        raw,route=self.prepared();self.sender.exchange(attempt(raw,b'a'*32),route);i=self.inbox()
        db=sqlite3.connect(str(self.rwp));db.execute('DELETE FROM heads WHERE namespace=?',(self.rns,));db.commit();db.close()
        try:
            self.reject('WITNESS_UNINITIALIZED',lambda:i.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign))
            self.assertEqual(i.db.execute('SELECT count(*) FROM inbox').fetchone()[0],1)
            self.reject('WITNESS_UNINITIALIZED',i.recover_from_witness)
        finally:i.close()

    def test_real_receiver_authority_outage_yields_no_confirmation(self):
        raw,route=self.prepared();i=self.inbox();self.rws.__exit__()
        try:
            with self.assertRaises(OSError):i.accept(attempt(raw,b'a'*32),route['sender_cert'],self.rsign)
            self.assertEqual(i.db.execute('SELECT count(*) FROM inbox').fetchone()[0],0)
        finally:
            i.close();self.rws=WitnessTLSService(self.rwp,cafile=self.certs['ca'],certfile=self.certs['server'][0],keyfile=self.certs['server'][1],signing_key=self.rwsign)
            self.start_receiver_authority()
        i=self.inbox()
        try:i.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign);self.assertEqual(i.audit(),[])
        finally:i.close()

    def test_changed_local_schema_requires_trusted_fresh_restore(self):
        raw,route=self.prepared();self.sender.exchange(attempt(raw,b'a'*32),route);i=self.inbox()
        try:
            i.db.execute('CREATE TABLE injected (value TEXT)')
            self.reject('WITNESS_SCHEMA_MISMATCH',i.recover_from_witness)
        finally:i.close()
        self.reject('WITNESS_SCHEMA_MISMATCH',lambda:self.inbox())
        clean=TLSWitnessedMixedRecipientInbox.restore_new(self.root/'clean',**self.kwargs('restorer'))
        try:self.assertEqual(clean.audit(),[]);self.assertEqual(clean.db.execute('SELECT count(*) FROM inbox').fetchone()[0],1)
        finally:clean.close()


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':child(sys.argv[2],sys.argv[3])
    else:
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RecipientWitnessTests));p=Path(__file__).parent
        names=['witnessed_recipient.py','test_witnessed_recipient.py','delivery_transport.py','delivery_terminal.py','mixed_delivery_transport.py','mixed_delivery_terminal.py',
            'witnessed_ledger.py','witness_transport.py','wire.py','encrypted_ledger.py','witnessed_mixed_ledger.py','encrypted_mixed_ledger.py','mixed_delegated_ledger.py','histogram_ledger.py','delegated_ledger.py','signed_ledger.py','scheduled_ledger.py','dp_ledger.py','ledger.py','../fixed_work_model.py','../histogram_kernel.py',
            'test_delivery_transport.py','test_mixed_delivery_transport.py','test_encrypted_mixed_ledger.py','test_mixed_delegated_ledger.py','test_witnessed_mixed_ledger.py','test_witness_transport.py']
        report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,authenticated_receiver_witness_requests=RECEIVER_WITNESS_REQUESTS,delivery_exchange_attempts=base.NETWORK_CALLS,
            observed_delivery_tls_versions=sorted(base.TLS_VERSIONS),ssl_library=ssl.OPENSSL_VERSION,actual_process_crash_scenarios=CRASHES,crash_scenario_count=len(CRASHES),
            source_sha256={n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in names},failures=[str(x) for x in result.failures],errors=[str(x) for x in result.errors],
            scope='Synthetic mixed terminal inbox with separate authenticated loopback CAS authority; local rollback fenced conditional on authority nonrollback. No pruning, production failure-domain proof, external-effect exactly-once or full observation proof.')
        (p/'witnessed_recipient_test_results.json').write_text(json.dumps(report,indent=2)+'\n');sys.exit(not result.wasSuccessful())
