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
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519
import test_delivery_transport as base
from delivery_transport import RecipientTLSService,StateVault,public,MAX_FRAME
from mixed_delivery_transport import (MixedDeliveryLedger,MixedRecipientInbox,MixedDeliverySender,
    PROFILE,ENVELOPE_TYPE,ACK_TYPE,parse_envelope,parse_ack,attempt,Rejected)
from witness_transport import WitnessTLSService,TLSWitnessClient,certificate_fingerprint,trusted_register_peer
from test_encrypted_mixed_ledger import vault,register
from test_witnessed_mixed_ledger import populate,backup
from test_mixed_delegated_ledger import finish
from histogram_ledger import canonical,HISTOGRAM
from wire import encode,decode,sign1,verify_sign1

CRASHES=[]
MAXIMUM_SHAPE_FRAME_BYTES=0


def child(config_path,point):
    c=json.loads(Path(config_path).read_text());route=base.unpack_route(c['route'])
    def fault(here):
        if here==point or (point=='after_witness_accept_ack_commit' and here=='after_witness_accept'):os._exit(97)
    if 'inbox' in point:
        i=MixedRecipientInbox(c['inbox'],deployment=c['namespace'],route=route,vault=StateVault(bytes.fromhex(c['inbox_key']),b'inbox-fixture-01'),clock=lambda:100)
        i.accept(bytes.fromhex(c['request']),route['sender_cert'],ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['receiver_key'])),fault)
    else:
        w=TLSWitnessClient(port=c['port'],cafile=c['ca'],certfile=c['cert'],keyfile=c['cert_key'],witness_public_key=bytes.fromhex(c['witness_key']))
        l=MixedDeliveryLedger(c['ledger'],clock=lambda:100,vault=vault(),witness=w,witness_fault=fault)
        if 'ack_commit' in point:l.confirm_ack('t','d',bytes.fromhex(c['request']),bytes.fromhex(c['ack']),fault)
        elif 'delivery_commit' in point:l.admit_delivery('t','a','reader','d','gateway','session',fault=fault)
        else:l.prepare_send('t','d',ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['sender_key'])),fault)
    raise RuntimeError('crash cut not reached')


class MixedDeliveryTests(unittest.TestCase):
    ledger_class=MixedDeliveryLedger
    inbox_class=MixedRecipientInbox
    sender_class=MixedDeliverySender
    setUpClass=classmethod(base.DeliveryTests.setUpClass.__func__)
    tearDownClass=classmethod(base.DeliveryTests.tearDownClass.__func__)
    wclient=base.DeliveryTests.wclient
    inbox=base.DeliveryTests.inbox
    sender_for=base.DeliveryTests.sender_for
    ticket=base.DeliveryTests.ticket
    prepared=base.DeliveryTests.prepared
    inbox_rows=base.DeliveryTests.inbox_rows
    reject=base.DeliveryTests.reject
    def reopen(self):
        self.l.close();self.l=self.ledger_class(self.lp,clock=lambda:self.now,vault=vault(),witness=self.wclient())
    tearDown=base.DeliveryTests.tearDown

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.lp=self.root/'ledger';self.ip=self.root/'inbox';self.wp=self.root/'witness';self.now=100
        self.route=dict(tenant='t',recipient='reader',gateway='gateway',session='session',sender_cert=certificate_fingerprint(self.certs['writer'][0]),
            receiver_cert=certificate_fingerprint(self.certs['server'][0]),sender_key=public(self.gsign),receiver_key=public(self.rsign),sender_kid=b'gateway',receiver_kid=b'recipient')
        self.ns=vault().deployment_id.hex()
        template=Path(self.ct.name)/'mixed-template'
        if template.exists():
            shutil.copyfile(template,self.lp);shutil.copyfile(str(template)+'-witness',self.wp)
        else:trusted_register_peer(self.wp,self.ns,certificate_fingerprint(self.certs['admin'][0]),'admin')
        self.ws=WitnessTLSService(self.wp,cafile=self.certs['ca'],certfile=self.certs['server'][0],keyfile=self.certs['server'][1],signing_key=self.wsign)
        self.ws.__enter__();self.w=self.wclient()
        if template.exists():self.l=self.ledger_class(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w)
        else:
            self.l=populate(self.ledger_class.create(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w))
            self.l.register_route(**self.route);register(self.l);register(self.l,'c',False);finish(self.l)
            backup(self.l.db,template)
            db=sqlite3.connect(str(self.wp));backup(db,str(template)+'-witness');db.close()
        self.rs=RecipientTLSService(inbox_factory=self.inbox,cafile=self.certs['ca'],certfile=self.certs['server'][0],keyfile=self.certs['server'][1],signer=self.rsign)
        self.rs.__enter__();self.sender=self.sender_for()

    def crash(self,point,request=b'',ack=b''):
        config=dict(route={k:v.hex() if isinstance(v,bytes) else v for k,v in self.route.items()},namespace=self.ns,
            sender_key=base.keybytes(self.gsign).hex(),receiver_key=base.keybytes(self.rsign).hex(),inbox_key=self.ivkey.hex(),inbox=str(self.ip),
            ledger=str(self.lp),port=self.ws.port,ca=str(self.certs['ca']),cert=str(self.certs['admin'][0]),cert_key=str(self.certs['admin'][1]),
            witness_key=public(self.wsign).hex(),request=request.hex(),ack=ack.hex())
        path=self.root/'child.json'
        with os.fdopen(os.open(str(path),os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600),'w') as f:json.dump(config,f)
        r=subprocess.run([sys.executable,__file__,'--child',str(path),point],capture_output=True,text=True,timeout=30)
        self.assertEqual(r.returncode,97,r.stderr);CRASHES.append(point);path.unlink()

    def signed(self,obj,kind=ENVELOPE_TYPE):return sign1(encode(obj),self.route['sender_kid'],self.gsign,kind)
    def stored(self):
        i=self.inbox()
        try:return [parse_envelope(i.vault.open('inbox-envelope',(self.ns,'t',r['id']),r['envelope']),self.ns,self.route) for r in i.db.execute('SELECT * FROM inbox ORDER BY seq')]
        finally:i.close()

    def test_complete_vector_then_count_same_route_and_unchanged_shared_ancestor_spend(self):
        before=[tuple(r) for r in self.l.db.execute('SELECT * FROM accounts')]
        self.ticket();self.l.admit_delivery('t','c','reader','count','gateway','session')
        self.reject('DELIVERY_ORDER',lambda:self.sender.deliver(self.l,'t','count'))
        self.assertEqual(self.sender.deliver(self.l,'t','d'),'ACKED');self.assertEqual(self.sender.deliver(self.l,'t','count'),'ACKED')
        objs=self.stored();self.assertEqual([len(o['result']) for o in objs],[32,8]);self.assertEqual(objs[0]['labels'],['one','two','three','four'])
        for obj,oid in zip(objs,['a','c']):
            op=self.l.op('t',oid);self.assertEqual(obj['result'],op['result']);self.assertEqual(obj['action_digest'],bytes.fromhex(op['digest']))
        self.assertEqual([tuple(r) for r in self.l.db.execute('SELECT * FROM accounts')],before);self.assertEqual(self.l.audit(),[])
        with patch.object(self.sender,'exchange',side_effect=AssertionError('duplicate send')):self.assertEqual(self.sender.deliver(self.l,'t','d'),'ACKED')

    def test_lost_network_ack_retries_identical_vector_and_preserves_first_acceptance(self):
        self.ticket()
        def lose(point):
            if point=='before_ack_send':raise ConnectionError('lost ACK')
        self.rs.fault=lose
        with self.assertRaises(OSError):self.sender.deliver(self.l,'t','d')
        row=dict(self.l.outbox('t','d'));self.assertEqual(row['state'],'READY');self.assertEqual(len(self.inbox_rows()),1)
        self.rs.fault=lambda p:None;self.now=110;self.reopen();self.sender.deliver(self.l,'t','d')
        self.assertEqual(self.l.outbox('t','d')['envelope'],row['envelope']);self.assertEqual(self.inbox_rows()[0]['accepted_at'],100)
        self.assertEqual(len(self.inbox_rows()),1);self.assertEqual(self.l.audit(),[])

    def test_short_partial_extra_and_out_of_range_vectors_never_enter_inbox(self):
        raw,route=self.prepared();obj=parse_envelope(raw,self.ns,route)
        for result in [b'',obj['result'][:8],obj['result'][:-1],obj['result']+b'\0'*8,(4).to_bytes(8,'big')+obj['result'][8:]]:
            bad=self.signed(dict(obj,result=result));i=self.inbox()
            try:self.reject('INVALID_DELIVERY_VECTOR',lambda:i.accept(attempt(bad,b'x'*32),route['sender_cert'],self.rsign))
            finally:i.close()
        self.assertFalse(self.inbox_rows())

    def test_signed_shape_catalog_order_and_closed_schema_rejections(self):
        raw,route=self.prepared();obj=parse_envelope(raw,self.ns,route)
        changes=[{'bucket_count':3},{'capacity':True},{'capacity':0},{'k':39},{'codec':'wrong'},
            {'labels':list(reversed(obj['labels']))},{'labels':['one']*4},{'catalog_digest':b'x'*32},{'action_digest':b''},
            {'labels':[1,2,3,4]},{'mechanism':'unknown'},{'snapshot':''}]
        for change in changes:
            with self.assertRaises(Rejected):parse_envelope(self.signed(dict(obj,**change)),self.ns,route)
        with self.assertRaises(Rejected):parse_envelope(self.signed(dict(obj,extra=1)),self.ns,route)
        self.assertFalse(self.inbox_rows())

    def test_reencrypted_valid_but_wrong_shape_is_detected_by_sender_audit(self):
        raw,route=self.prepared();obj=parse_envelope(raw,self.ns,route)
        for change in [{'domain':'other'},{'snapshot':'other'},{'action_digest':b'x'*32},{'catalog':'other'}]:
            bad=self.signed(dict(obj,**change));parse_envelope(bad,self.ns,route)
            original=self.l.outbox('t','d')['envelope']
            self.l.db.execute('UPDATE delivery_outbox SET envelope=?',(self.l.vault.seal('delivery-envelope',('t','d'),bad),))
            self.reject('LOCAL_STATE_DIVERGED',self.l.audit)
            self.reject('OUTBOX_BINDING',lambda:self.l.validate_payload_binding(parse_envelope(bad,self.ns,route),self.l.op('t','a')))
            self.l.db.execute('UPDATE delivery_outbox SET envelope=?',(original,))
        self.assertEqual(self.l.audit(),[])

    def test_count_and_mixed_profile_aad_attempt_and_inbox_are_not_interchangeable(self):
        import delivery_transport as old
        raw,route=self.prepared();obj=parse_envelope(raw,self.ns,route)
        with self.assertRaises(Rejected):old.parse_envelope(raw,self.ns,route)
        with self.assertRaises(Rejected):parse_envelope(self.signed(obj,old.ENVELOPE_TYPE),self.ns,route)
        i=self.inbox()
        try:
            with self.assertRaises(Rejected):i.accept(old.attempt(raw,b'x'*32),route['sender_cert'],self.rsign)
        finally:i.close()
        self.reject('INBOX_PROFILE_MISMATCH',lambda:old.RecipientInbox(self.ip,deployment=self.ns,route=self.route,vault=StateVault(self.ivkey,b'inbox-fixture-01'),clock=lambda:100))
        with self.assertRaises(Rejected):old.DeliveryLedger(self.lp,clock=lambda:100,vault=vault(),witness=self.w)

    def test_ack_binds_every_byte_request_challenge_and_mixed_aad(self):
        raw,route=self.prepared();request=attempt(raw,b'a'*32);ack=self.sender.exchange(request,route)
        parse_ack(ack,request,raw,self.ns,route)
        self.reject('DELIVERY_ACK_BINDING',lambda:self.l.confirm_ack('t','d',attempt(raw,b'b'*32),ack))
        _,obj=verify_sign1(ack,route['receiver_key'],ACK_TYPE)
        for change in [{'seq':2},{'envelope_hash':b'x'*32},{'request_hash':b'x'*32},{'receiver_cert':b'x'*32},{'accepted_at':160}]:
            altered=sign1(encode(dict(obj,**change)),route['receiver_kid'],self.rsign,ACK_TYPE)
            with self.assertRaises(Rejected):self.l.confirm_ack('t','d',request,altered)
        self.l.confirm_ack('t','d',request,ack);self.assertEqual(self.l.audit(),[])

    def test_stale_sender_recovers_ack_and_all_ancestor_history_without_resending(self):
        self.ticket();stale=self.root/'old';backup(self.l.db,stale);self.sender.deliver(self.l,'t','d')
        clone=self.ledger_class(stale,clock=lambda:100,vault=vault(),witness=self.wclient())
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:self.sender.deliver(clone,'t','d'))
            clone.recover_from_witness();self.assertEqual(clone.audit(),[])
            self.assertEqual(clone.state_image(),self.l.state_image())
            with patch.object(self.sender,'exchange',side_effect=AssertionError('resend')):self.assertEqual(self.sender.deliver(clone,'t','d'),'ACKED')
        finally:clone.close()

    def test_max64_labels_and_full512_byte_vector_fit_framing_and_inbox(self):
        raw,route=self.prepared();obj=parse_envelope(raw,self.ns,route)
        labels=[f'{i:02d}'+('界'*20)+'xx' for i in range(64)]
        self.assertTrue(all(len(x.encode())==64 for x in labels))
        obj.update(bucket_count=64,labels=labels,catalog_digest=hashlib.sha256(canonical(labels).encode()).digest(),result=b'\0'*512)
        # Exercise parser/transport boundary, not a claim that this signature
        # came from a 64-bucket job in the fixture.
        raw=self.signed(obj);request=attempt(raw,b'm'*32);self.assertLessEqual(len(request),MAX_FRAME)
        ack=self.sender.exchange(request,route);parse_ack(ack,request,raw,self.ns,route)
        self.assertEqual(len(self.stored()[0]['result']),512)
        worst_route=dict(route,**{k:k[0]*128 for k in ('tenant','recipient','gateway','session')},sender_kid=b'k'*32,receiver_kid=b'j'*32)
        worst=dict(obj,**{k:worst_route[k] for k in ('tenant','recipient','gateway','session')},delivery='d'*128,operation='o'*128,
            domain='D'*128,snapshot='S'*128,catalog='C'*128,capacity=65535,seq=2**62-1,issued_at=2**62-60,expires_at=2**62)
        raw=sign1(encode(worst),worst_route['sender_kid'],self.gsign,ENVELOPE_TYPE)
        parse_envelope(raw,self.ns,worst_route)
        global MAXIMUM_SHAPE_FRAME_BYTES
        MAXIMUM_SHAPE_FRAME_BYTES=len(attempt(raw,b'q'*32));self.assertLessEqual(MAXIMUM_SHAPE_FRAME_BYTES,MAX_FRAME)


    def test_vector_delivery_process_cuts(self):
        # Each cut gets an independent copy of the complete mixed fixture.
        for point in ['before_delivery_commit','after_delivery_commit','before_outbox_commit','after_outbox_commit',
                      'before_inbox_commit','after_inbox_commit','before_ack_commit','after_ack_commit']:
            with self.subTest(point=point):
                if 'delivery_commit' not in point:self.ticket()
                request=ack=b''
                if 'inbox' in point or 'ack_commit' in point:
                    raw,route=self.l.prepare_send('t','d',self.gsign);request=attempt(raw,b'c'*32)
                if 'ack_commit' in point:ack=self.sender.exchange(request,route)
                self.crash(point,request,ack);self.reopen()
                if 'delivery_commit' in point:self.ticket()
                self.sender.deliver(self.l,'t','d');self.assertEqual(len(self.inbox_rows()),1);self.assertEqual(self.l.audit(),[])
                self.tearDown();self.setUp()

    def test_witness_accepts_outbox_then_process_dies_before_local_commit(self):
        self.ticket();self.crash('after_witness_accept');self.reopen()
        self.assertEqual(self.l.outbox('t','d')['state'],'QUEUED')
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:self.l.prepare_send('t','d',self.gsign))
        self.l.recover_from_witness();self.assertEqual(self.l.outbox('t','d')['state'],'READY')
        self.sender.deliver(self.l,'t','d');self.assertEqual(len(self.inbox_rows()),1);self.assertEqual(self.l.audit(),[])

    def test_expiry_before_first_acceptance_leaves_sequence_blocked_pending_terminal_protocol(self):
        self.ticket(ttl=1);raw,route=self.l.prepare_send('t','d',self.gsign);self.now=101
        i=self.inbox()
        try:self.reject('TICKET_EXPIRED',lambda:i.accept(attempt(raw,b'e'*32),route['sender_cert'],self.rsign))
        finally:i.close()
        self.assertFalse(self.inbox_rows());self.assertEqual(self.l.delivery_status('t','d'),'READY')
        self.l.admit_delivery('t','c','reader','next','gateway','session')
        self.reject('DELIVERY_ORDER',lambda:self.sender.deliver(self.l,'t','next'))

    def test_concurrent_retries_have_one_vector_acceptance(self):
        raw,route=self.prepared()
        def call(_):return self.sender.exchange(attempt(raw,os.urandom(32)),route)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:self.assertEqual(len(list(pool.map(call,range(4)))),4)
        self.assertEqual(len(self.inbox_rows()),1);self.sender.deliver(self.l,'t','d');self.assertEqual(self.l.audit(),[])

    def test_tls_peer_pins_hostname_ca_and_signer_before_vector_disclosure(self):
        raw,route=self.prepared();request=attempt(raw,b't'*32)
        with patch('delivery_transport.send_packet',side_effect=AssertionError('sent before pin')):
            self.reject('WRONG_RECIPIENT_IDENTITY',lambda:self.sender.exchange(request,dict(route,receiver_cert=b'x'*32)))
        bad=self.sender_for('observer');self.reject('WRONG_GATEWAY_IDENTITY',lambda:bad.deliver(self.l,'t','d'))
        bad.fingerprint=route['sender_cert']
        with self.assertRaises(OSError):bad.exchange(request,route)
        for sender in (self.sender_for(server_hostname='wrong.invalid'),self.sender_for(cafile=self.othercerts['ca'])):
            with self.assertRaises(ssl.SSLError):sender.deliver(self.l,'t','d')
        self.reject('WRONG_GATEWAY_SIGNER',lambda:self.sender_for(signer=self.rsign).deliver(self.l,'t','d'))
        self.assertFalse(self.inbox_rows())

    def test_no_partial_job_can_create_delivery_or_outbox(self):
        from test_mixed_delegated_ledger import tick
        register(self.l,'pending');tick(self.l)
        self.assertEqual(self.l.op('t','pending')['state'],'STARTED')
        self.reject('PUBLICATION_PENDING_OR_WITHHELD',lambda:self.l.admit_delivery('t','pending','reader','early','gateway','session'))
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM delivery_outbox').fetchone()[0],0)
        self.assertIsNone(self.l.op('t','pending')['result'])

    def test_historical_ack_after_expiry_and_route_revocation_needs_no_disclosure(self):
        raw,route=self.prepared();request=attempt(raw,b'h'*32);ack=self.sender.exchange(request,route)
        self.l.revoke_route('t','reader','gateway','session');self.now=170
        self.l.confirm_ack('t','d',request,ack)
        self.assertEqual(self.l.outbox('t','d')['state'],'ACKED');self.assertEqual(self.inbox_rows()[0]['accepted_at'],100)
        self.assertEqual(self.l.audit(),[])

    def test_receiver_rejected_expiry_preserves_clock_floor(self):
        raw,route=self.prepared();self.now=160;i=self.inbox()
        try:
            self.reject('TICKET_EXPIRED',lambda:i.accept(attempt(raw,b'x'*32),route['sender_cert'],self.rsign))
            self.now=100
            self.reject('INBOX_CLOCK_ROLLBACK',lambda:i.accept(attempt(raw,b'y'*32),route['sender_cert'],self.rsign))
        finally:i.close()

    def test_recipient_whole_database_rollback_negative_control(self):
        raw,route=self.prepared();i=self.inbox();old=self.root/'old-inbox'
        try:backup(i.db,old)
        finally:i.close()
        self.sender.exchange(attempt(raw,b'r'*32),route);self.assertEqual(self.inbox_rows()[0]['accepted_at'],100)
        # Deliberate replay of a complete prior inbox, with valid field keys.
        shutil.copyfile(old,self.ip);self.now=110
        self.sender.exchange(attempt(raw,b's'*32),route)
        self.assertEqual(self.inbox_rows()[0]['accepted_at'],110)
        # This repeated first acceptance proves recipient antirollback is still
        # an external assumption even though the sender has a witness.

    def test_ack_witness_commit_survives_process_death_before_local_record(self):
        raw,route=self.prepared();request=attempt(raw,b'w'*32);ack=self.sender.exchange(request,route)
        # Child selects confirm_ack and dies at the shared witness hook.
        self.crash('after_witness_accept_ack_commit',request,ack);self.reopen()
        self.assertEqual(self.l.outbox('t','d')['state'],'READY')
        self.l.recover_from_witness();self.assertEqual(self.l.outbox('t','d')['state'],'ACKED')
        self.assertEqual(self.l.audit(),[])
        with patch.object(self.sender,'exchange',side_effect=AssertionError('resend')):self.assertEqual(self.sender.deliver(self.l,'t','d'),'ACKED')

    test_l3_ticket_and_outbox_share_one_transaction=base.DeliveryTests.test_l3_ticket_and_outbox_share_one_transaction
    test_unknown_route_and_rebinding_are_rejected=base.DeliveryTests.test_unknown_route_and_rebinding_are_rejected


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':child(sys.argv[2],sys.argv[3])
    else:
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MixedDeliveryTests))
        p=Path(__file__).parent
        names=['mixed_delivery_transport.py','test_mixed_delivery_transport.py','delivery_transport.py','witnessed_mixed_ledger.py','witnessed_ledger.py','witness_transport.py','encrypted_mixed_ledger.py','encrypted_ledger.py','mixed_delegated_ledger.py','delegated_ledger.py','signed_ledger.py','histogram_ledger.py','scheduled_ledger.py','dp_ledger.py','ledger.py','wire.py','../histogram_kernel.py','../fixed_work_model.py','test_delivery_transport.py','test_witnessed_mixed_ledger.py','test_encrypted_mixed_ledger.py','test_mixed_delegated_ledger.py','test_witness_transport.py']
        report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,network_calls=base.NETWORK_CALLS,maximum_shape_frame_bytes=MAXIMUM_SHAPE_FRAME_BYTES,tls_versions=sorted(base.TLS_VERSIONS),actual_process_crash_scenarios=CRASHES,crash_scenario_count=len(CRASHES),ssl_library=ssl.OPENSSL_VERSION,
            source_sha256={n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in names},failures=[str(x) for x in result.failures],errors=[str(x) for x in result.errors],
            scope='Synthetic mixed signed/encrypted/witnessed jobs to authenticated cooperative inbox. B4/N3 full path plus B64 wire-only boundary. No mixed terminal protocol, receiver nonrollback recovery, full observation proof or external business exactly-once.')
        (p/'mixed_delivery_test_results.json').write_text(json.dumps(report,indent=2)+'\n');sys.exit(not result.wasSuccessful())
