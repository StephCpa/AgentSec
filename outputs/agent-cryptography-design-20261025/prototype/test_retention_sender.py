import ast
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import cryptography
from retention_sender import RetentionSender,TLSRetentionSender,u64,number
from witnessed_ledger import ReferenceWitness,image_hash
from test_witnessed_mixed_ledger import populate,backup
from test_encrypted_mixed_ledger import vault,register,TAPE
from test_mixed_delegated_ledger import finish
from test_retention_wire import fixture
from wire import encode,decode
from ledger import Rejected
import retention_wire as r
import retention_delivery as d

HERE=Path(__file__).parent
CRASHES=[]
TLS_CALLS=0
TLS_VERSIONS=set()


def context():
    c,s,k=fixture();c.update(deployment=vault().deployment_id,sender_authority=vault().deployment_id,recipient='reader')
    return c,s,k


def child(config_path,operation,point):
    cfg=json.loads(Path(config_path).read_text());c,s,k=context();h=r.context_hash(c)
    def fault(p):
        if p==point:os._exit(99)
    w=ReferenceWitness(cfg['witness']);l=RetentionSender(cfg['ledger'],clock=lambda:cfg['now'],vault=vault(),witness=w,witness_fault=fault)
    did=r.delivery_id(c,1)
    if operation=='admit':l.admit_v2(h,'request','a',fault=fault)
    elif operation=='prepare':l.prepare_envelope('t',did,s,fault)
    elif operation=='control':l.prepare_terminal('t',did,s,fault)
    elif operation=='confirm':l.confirm('t',did,bytes.fromhex(cfg['request']),bytes.fromhex(cfg['ack']),fault)
    elif operation=='offer':l.prepare_retirement(h,1,s,fault)
    elif operation=='checkpoint':l.confirm_retirement(h,bytes.fromhex(cfg['request']),bytes.fromhex(cfg['ack']),fault)
    elif operation=='restore':l.recover_from_witness(fault)
    else:raise RuntimeError('unknown child operation')
    raise RuntimeError('fault cut not reached')


class RetentionSenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.templates=tempfile.TemporaryDirectory();root=Path(cls.templates.name)
        cls.template=root/'ledger';cls.wtemplate=root/'witness'
        w=ReferenceWitness(cls.wtemplate);l=populate(RetentionSender.create(cls.template,clock=lambda:100,vault=vault(),witness=w))
        try:
            register(l);register(l,'c',False)
            with patch('histogram_ledger.fresh_tape',return_value=TAPE):finish(l)
            c,_,_=context();l.register_context(c);assert l.audit()==[]
        finally:l.close();w.close()
    @classmethod
    def tearDownClass(cls):cls.templates.cleanup()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.lp=self.root/'ledger';self.wp=self.root/'witness'
        shutil.copyfile(self.template,self.lp);shutil.copyfile(self.wtemplate,self.wp)
        self.now=100;self.c,self.s,self.k=context();self.h=r.context_hash(self.c);self.w=ReferenceWitness(self.wp)
        self.l=RetentionSender(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w)
    def tearDown(self):
        if self.l is not None:self.l.close()
        self.w.close();self.tmp.cleanup()
    def reopen(self):
        if self.l is not None:self.l.close()
        self.l=RetentionSender(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w)
    def reject(self,code,fn):
        with self.assertRaises(Rejected) as caught:fn()
        self.assertEqual(str(caught.exception),code)
    def admit(self):return self.l.admit_v2(self.h,'request','a')
    def prepared(self):
        row=self.admit();return row,self.l.prepare_envelope('t',row['id'],self.s)
    def accepted(self):
        row,env=self.prepared();req=d.attempt('DELIVERY',env,b'q'*32,self.c,self.s)
        fact=d.accepted_fact(env,100,self.c);ack=d.receipt(fact,req,self.c,self.k)
        return row,env,req,ack,fact
    def confirmed(self):
        values=self.accepted();self.l.confirm('t',values[0]['id'],values[2],values[3]);return values
    def retirement(self):
        values=self.confirmed();offer=self.l.prepare_retirement(self.h,1,self.s)
        req=r.retire_attempt(offer,b'z'*32,self.c,self.s);root=r.extend_prefix(r.genesis(self.c),values[4],self.c,1)
        ack=r.checkpoint(req,self.c,'RETIRE_ACK',floor=1,root=root,high=1,key=self.k)
        return req,ack
    def recover_if_needed(self):
        try:self.l.check_current_state()
        except Rejected:self.l.recover_from_witness()
        self.assertEqual(self.l.audit(),[])
    def crash(self,operation,point,request=b'',ack=b''):
        cfg=self.root/'child.json';cfg.write_text(json.dumps(dict(ledger=str(self.lp),witness=str(self.wp),now=self.now,request=request.hex(),ack=ack.hex())))
        self.l.close();self.l=None
        proc=subprocess.run([sys.executable,__file__,'--child',str(cfg),operation,point],capture_output=True,text=True,timeout=30)
        self.assertEqual(proc.returncode,99,proc.stderr);CRASHES.append({'operation':operation,'point':point});self.reopen()

    def test_atomic_l3_retry_identity_original_expiry_and_shared_spending(self):
        before=[tuple(x) for x in self.l.db.execute('SELECT * FROM accounts')]
        first=self.admit();self.now=110;again=self.admit()
        self.assertEqual(first,again);self.assertEqual(number(first['seq']),1);self.assertEqual(first['id'],r.delivery_id(self.c,1))
        self.assertEqual(self.l.ticket(first)['expires_at'],160)
        second=self.l.admit_v2(self.h,'count','c');self.assertEqual(number(second['seq']),2)
        self.assertEqual([tuple(x) for x in self.l.db.execute('SELECT * FROM accounts')],before);self.assertEqual(self.l.audit(),[])
        self.reject('V2_REQUEST_CONFLICT',lambda:self.l.admit_v2(self.h,'request','c'))
        self.reject('V2_REQUEST_CONFLICT',lambda:self.l.admit_v2(self.h,'request','a',ttl=30))
        self.now=160;self.reject('TICKET_EXPIRED',self.admit)
        self.assertEqual(number(self.l.route(self.h)[0]['high']),2)

    def test_same_request_race_creates_one_identity(self):
        def worker(_):
            w=ReferenceWitness(self.wp);l=RetentionSender(self.lp,clock=lambda:100,vault=vault(),witness=w)
            try:return l.admit_v2(self.h,'request','a')['id']
            finally:l.close();w.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:ids=list(pool.map(worker,range(4)))
        self.assertEqual(set(ids),{r.delivery_id(self.c,1)})
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM v2_requests').fetchone()[0],1);self.assertEqual(self.l.audit(),[])

    def test_distinct_request_race_allocates_distinct_contiguous_sequences(self):
        def worker(key):
            w=ReferenceWitness(self.wp);l=RetentionSender(self.lp,clock=lambda:100,vault=vault(),witness=w)
            try:return number(l.admit_v2(self.h,key,'a')['seq'])
            finally:l.close();w.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:seq=list(pool.map(worker,['one','two']))
        self.assertEqual(set(seq),{1,2});self.assertEqual(self.l.audit(),[])

    def test_root_and_route_revocation_block_new_admission_but_keep_old_evidence(self):
        row,env=self.prepared();self.l.revoke_credential('t','root')
        self.reject('ACTION_OR_KEY_INACTIVE',self.admit)
        self.assertEqual(self.l.prepare_envelope('t',row['id'],self.s),env)
        self.l.revoke_context(self.h)
        self.reject('V2_ROUTE_REVOKED',lambda:self.l.prepare_envelope('t',row['id'],self.s))
        self.now=160;control=self.l.prepare_terminal('t',row['id'],self.s)
        self.assertEqual(d.parse_control(control,self.c)['envelope_hash'],r.sha(env));self.assertEqual(self.l.audit(),[])

    def test_context_cannot_be_rebound_and_legacy_entrypoints_are_disabled(self):
        self.reject('V2_ROUTE_IMMUTABLE',lambda:self.l.register_context(dict(self.c,epoch=b'Z'*16)))
        self.reject('V2_ROUTE_BINDING',lambda:self.l.register_context(dict(self.c,sender_authority=b'Z'*16)))
        self.reject('V2_ADMISSION_REQUIRED',lambda:self.l.admit_delivery('t','a','reader','old','g','s'))
        self.reject('V2_SIGNED_DELIVERY_REQUIRED',lambda:self.l.emit('t','old','reader','g','s'))

    def test_pending_publication_is_not_bypassed(self):
        # A valid new signed job remains RESERVED and unpublished.
        register(self.l,'new',False)
        self.reject('PUBLICATION_PENDING_OR_WITHHELD',lambda:self.l.admit_v2(self.h,'new','new'))
        self.assertEqual(number(self.l.route(self.h)[0]['high']),0)

    def test_scheduler_root_revocation_blocks_fresh_and_retry_admission(self):
        self.admit();tick=self.l.db.execute('SELECT tick FROM schedulers').fetchone()[0]
        self.l.advance('t','domain','revoke-root',tick,command={'kind':'revoke','root':'root','actor':'manager'})
        self.reject('REVOKED',self.admit)
        self.reject('REVOKED',lambda:self.l.admit_v2(self.h,'new','c'))
        self.assertEqual(number(self.l.route(self.h)[0]['high']),1)

    def test_prepared_control_is_revalidated_before_return(self):
        row,env=self.prepared();self.now=160;self.l.prepare_terminal('t',row['id'],self.s)
        wrong=d.control(row['descriptor'],b'X'*32,self.c,self.s)
        # Inject a trusted-writer bug into the authority, not just a local file.
        with self.l.tx():self.l.db.execute('UPDATE v2_outbox SET control=?',(self.l.seal('control',row,wrong),))
        self.reject('V2_CONTROL_BINDING',lambda:self.l.prepare_terminal('t',row['id'],self.s))

    def test_wrong_signer_never_prepares_envelope(self):
        row=self.admit()
        self.reject('RETENTION_SIGNING_KEY',lambda:self.l.prepare_envelope('t',row['id'],self.k))
        self.assertIsNone(self.l.outbox('t',row['id'])['envelope'])

    def test_competing_local_clones_cannot_both_commit_distinct_requests(self):
        first=self.root/'clone-one';second=self.root/'clone-two';backup(self.l.db,first);backup(self.l.db,second)
        def worker(item):
            path,key=item;w=ReferenceWitness(self.wp);l=RetentionSender(path,clock=lambda:100,vault=vault(),witness=w)
            try:
                try:return ('ok',l.admit_v2(self.h,key,'a')['id'])
                except Rejected as err:return ('rejected',str(err))
            finally:l.close();w.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(worker,[(first,'one'),(second,'two')]))
        self.assertEqual(sum(x[0]=='ok' for x in results),1)
        self.assertIn(next(x[1] for x in results if x[0]=='rejected'),('WITNESS_CAS_CONFLICT','WITNESS_RECOVERY_REQUIRED'))
        self.l.recover_from_witness();self.assertEqual(self.l.db.execute('SELECT count(*) FROM v2_requests').fetchone()[0],1)
        self.assertEqual(self.l.audit(),[])

    def test_immutable_envelope_and_terminal_are_encrypted_and_ordered(self):
        row,env=self.prepared();cipher=self.l.outbox('t',row['id'])['envelope']
        self.assertNotEqual(cipher,env);self.reopen();self.assertEqual(self.l.prepare_envelope('t',row['id'],self.s),env)
        self.assertEqual(self.l.outbox('t',row['id'])['envelope'],cipher)
        second=self.l.admit_v2(self.h,'count','c')
        self.reject('V2_DELIVERY_ORDER',lambda:self.l.prepare_envelope('t',second['id'],self.s))
        self.reject('TERMINAL_NOT_EXPIRED',lambda:self.l.prepare_terminal('t',row['id'],self.s))
        self.now=160
        with patch.object(self.l,'op',side_effect=AssertionError('terminal opened private result')):
            control=self.l.prepare_terminal('t',row['id'],self.s)
        self.assertEqual(self.l.prepare_terminal('t',row['id'],self.s),control)
        self.assertEqual(self.l.audit(),[])

    def test_only_persisted_confirmation_allows_offer(self):
        row,env,req,ack,fact=self.accepted()
        self.reject('V2_UNCONFIRMED_RETIREMENT',lambda:self.l.prepare_retirement(self.h,1,self.s))
        self.assertEqual(self.l.confirm('t',row['id'],req,ack),'ACCEPTED')
        offer=self.l.prepare_retirement(self.h,1,self.s);self.reopen()
        self.assertEqual(self.l.prepare_retirement(self.h,1,self.s),offer)
        self.assertEqual(r.parse_offer(offer,self.c)['target_root'],r.extend_prefix(r.genesis(self.c),fact,self.c,1));self.assertEqual(self.l.audit(),[])

    def test_conflicting_valid_first_time_is_rejected_in_both_arrival_orders(self):
        for terminal_first in (False,True):
            row,env,req,ack,fact=self.accepted();self.now=160
            ctl=self.l.prepare_terminal('t',row['id'],self.s);term=d.attempt('TERMINAL',ctl,b't'*32,self.c,self.s)
            changed=d.accepted_fact(env,110,self.c);other=d.receipt(changed,term,self.c,self.k)
            first=(term,other) if terminal_first else (req,ack)
            second=(req,ack) if terminal_first else (term,other)
            self.l.confirm('t',row['id'],*first)
            self.reject('V2_FACT_CONFLICT',lambda:self.l.confirm('t',row['id'],*second))
            self.assertEqual(self.l.audit(),[])
            self.tearDown();self.setUp()

    def test_unprepared_close_has_no_result_and_next_count_can_prepare(self):
        row=self.admit();self.now=160
        ctl=self.l.prepare_terminal('t',row['id'],self.s);self.assertEqual(d.parse_control(ctl,self.c)['envelope_hash'],b'')
        fact=d.closed_fact(ctl,160,self.c);req=d.attempt('TERMINAL',ctl,b't'*32,self.c,self.s)
        self.l.confirm('t',row['id'],req,d.receipt(fact,req,self.c,self.k))
        next_row=self.l.admit_v2(self.h,'count','c');env=self.l.prepare_envelope('t',next_row['id'],self.s)
        self.assertEqual(len(d.parse_envelope(env,self.c)['result']),8);self.assertEqual(self.l.audit(),[])

    def test_receipt_requires_stored_prepared_evidence(self):
        row=self.admit();env=d.envelope(row['descriptor'],self.l.op('t','a')['result'],self.c,self.s)
        req=d.attempt('DELIVERY',env,b'q'*32,self.c,self.s);ack=d.receipt(d.accepted_fact(env,100,self.c),req,self.c,self.k)
        self.reject('V2_UNPREPARED_EVIDENCE',lambda:self.l.confirm('t',row['id'],req,ack))

    def test_retirement_checkpoint_saved_and_restored_with_archive(self):
        req,ack=self.retirement();self.assertEqual(self.l.confirm_retirement(self.h,req,ack),1)
        route=self.l.route(self.h)[0];self.assertIsNotNone(route['retirement_evidence'])
        restored=RetentionSender.restore_new(self.root/'restored',clock=lambda:100,vault=vault(),witness=self.w)
        try:self.assertEqual(restored.state_image(),self.l.state_image());self.assertEqual(restored.audit(),[])
        finally:restored.close()
        self.reject('V2_UNCONFIRMED_RETIREMENT',lambda:self.l.prepare_retirement(self.h,1,self.s))

    def test_checkpoint_cannot_claim_receiver_ahead_or_unconfirmed_floor(self):
        row,env,req,ack,fact=self.confirmed();query=r.query(self.c,'CHECKPOINT',0,b'q'*32,self.s)
        root=r.extend_prefix(r.genesis(self.c),fact,self.c,1)
        wrong=r.checkpoint(query,self.c,'CHECKPOINT',floor=1,root=root,high=2,key=self.k)
        self.reject('V2_RECEIVER_AHEAD_OF_ADMISSION',lambda:self.l.confirm_retirement(self.h,query,wrong))
        changed=r.checkpoint(query,self.c,'CHECKPOINT',floor=1,root=b'X'*32,high=1,key=self.k)
        self.reject('RETENTION_ARCHIVE_MISMATCH',lambda:self.l.confirm_retirement(self.h,query,changed))

    def test_old_replica_fenced_then_exact_request_mapping_restored(self):
        stale=self.root/'stale';backup(self.l.db,stale);row=self.admit()
        clone=RetentionSender(stale,clock=lambda:100,vault=vault(),witness=self.w)
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:clone.admit_v2(self.h,'request','a'))
            clone.recover_from_witness();self.assertEqual(clone.admit_v2(self.h,'request','a')['id'],row['id']);self.assertEqual(clone.audit(),[])
        finally:clone.close()

    def test_uint64_storage_order_and_exhaustion_gate(self):
        values=[0,2**63-1,2**63,2**64-1]
        db=sqlite3.connect(':memory:');db.execute("CREATE TABLE q(n BLOB CHECK(typeof(n)='blob' AND length(n)=8))")
        for value in reversed(values):db.execute('INSERT INTO q VALUES(?)',(u64(value),))
        self.assertEqual([number(x[0]) for x in db.execute('SELECT n FROM q ORDER BY n')],values)
        with self.assertRaises(sqlite3.IntegrityError):db.execute('INSERT INTO q VALUES(1)')
        db.close()
        # Deliberate allocator boundary fixture, not a claim to have generated
        # 2^64-1 real historical records or passed full-history audit here.
        with self.l.tx():self.l.db.execute('UPDATE v2_routes SET high=?',(u64(r.MAX_SEQ),))
        self.reject('V2_SEQUENCE_EXHAUSTED',self.admit)
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM deliveries').fetchone()[0],0)

    def test_invalid_authority_image_fails_subclass_audit_before_restore_commit(self):
        self.confirmed();before=self.l.state_image();head=self.w.head(self.l.namespace)
        self.l.db.execute('BEGIN IMMEDIATE');self.l.db.execute('UPDATE v2_routes SET confirmed_root=?',(b'X'*32,));bad=self.l.state_image();self.l.db.rollback()
        self.w.compare_and_store(self.l.namespace,head['seq'],head['digest'],bad,'a'*32)
        self.reject('V2_RECOVERY_AUDIT_FAILED',self.l.recover_from_witness)
        self.assertEqual(self.l.state_image(),before)

    def test_schema_and_context_tampering_are_rejected(self):
        self.l.close();self.l=None
        db=sqlite3.connect(self.lp);db.execute('ALTER TABLE v2_routes ADD COLUMN ignored TEXT');db.close()
        self.reject('V2_SCHEMA_MISMATCH',lambda:RetentionSender(self.lp,clock=lambda:100,vault=vault(),witness=self.w))

    def test_process_crashes_at_admission_boundaries(self):
        for point in ('after_v2_ticket_write','after_v2_request_write','before_v2_admission_commit','after_v2_admission_commit','after_witness_accept'):
            self.crash('admit',point);self.recover_if_needed();row=self.admit()
            self.assertEqual(row['id'],r.delivery_id(self.c,1));self.assertEqual(number(self.l.route(self.h)[0]['high']),1);self.assertEqual(self.l.audit(),[])
            self.tearDown();self.setUp()

    def test_process_crashes_at_prepare_confirm_offer_and_checkpoint(self):
        cases=[('prepare','before_v2_envelope_commit'),('prepare','after_v2_envelope_commit'),('prepare','after_witness_accept'),
               ('control','before_v2_control_commit'),('control','after_v2_control_commit'),('control','after_witness_accept'),
               ('confirm','before_v2_confirmation_commit'),('confirm','after_v2_confirmation_commit'),('confirm','after_witness_accept'),
               ('offer','before_v2_retirement_offer_commit'),('offer','after_v2_retirement_offer_commit'),('offer','after_witness_accept'),
               ('checkpoint','before_v2_retirement_checkpoint_commit'),('checkpoint','after_v2_retirement_checkpoint_commit'),('checkpoint','after_witness_accept')]
        for operation,point in cases:
            req=ack=b''
            if operation=='prepare':row=self.admit()
            elif operation=='control':row=self.admit();self.now=160
            elif operation=='confirm':row,env,req,ack,fact=self.accepted()
            elif operation=='offer':self.confirmed()
            else:req,ack=self.retirement()
            self.crash(operation,point,req,ack);self.recover_if_needed()
            if operation=='prepare':self.l.prepare_envelope('t',row['id'],self.s)
            elif operation=='control':self.l.prepare_terminal('t',row['id'],self.s)
            elif operation=='confirm':self.l.confirm('t',row['id'],req,ack)
            elif operation=='offer':self.l.prepare_retirement(self.h,1,self.s)
            else:self.l.confirm_retirement(self.h,req,ack)
            self.assertEqual(self.l.audit(),[]);self.tearDown();self.setUp()

    def test_process_crashes_during_exact_recovery(self):
        for point in ('after_recovery_delete','before_recovery_commit','after_recovery_commit'):
            self.admit();self.l.close();self.l=None;shutil.copyfile(self.template,self.lp);self.reopen()
            self.crash('restore',point);self.recover_if_needed()
            self.assertEqual(self.admit()['id'],r.delivery_id(self.c,1));self.assertEqual(self.l.audit(),[])
            self.tearDown();self.setUp()

    def test_authenticated_witness_profile_completes_count_admission_and_confirmation(self):
        from test_witness_transport import certificates,public
        from witness_transport import WitnessTLSService,TLSWitnessClient,trusted_register_peer,certificate_fingerprint
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        certs=certificates(self.root);wp=self.root/'tls-witness';signer=Ed25519PrivateKey.generate();ns=vault().deployment_id.hex()
        trusted_register_peer(wp,ns,certificate_fingerprint(certs['admin'][0]),'admin')
        with WitnessTLSService(wp,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signing_key=signer) as server:
            client=TLSWitnessClient(port=server.port,cafile=certs['ca'],certfile=certs['admin'][0],keyfile=certs['admin'][1],witness_public_key=public(signer))
            original=client.exchange
            def exchange(raw,body):
                global TLS_CALLS
                TLS_CALLS+=1;value=original(raw,body)
                if client.last_tls_version:TLS_VERSIONS.add(client.last_tls_version)
                return value
            client.exchange=exchange
            l=populate(TLSRetentionSender.create(self.root/'tls-ledger',clock=lambda:100,vault=vault(),witness=client),capacity=1)
            try:
                register(l,'c',False);finish(l);h=l.register_context(self.c);row=l.admit_v2(h,'count','c');env=l.prepare_envelope('t',row['id'],self.s)
                req=d.attempt('DELIVERY',env,b'q'*32,self.c,self.s);fact=d.accepted_fact(env,100,self.c);ack=d.receipt(fact,req,self.c,self.k)
                l.confirm('t',row['id'],req,ack);l.prepare_retirement(h,1,self.s);self.assertEqual(l.audit(),[])
            finally:l.close()
        self.reject('AUTHENTICATED_WITNESS_REQUIRED',lambda:TLSRetentionSender(self.lp,clock=lambda:100,vault=vault(),witness=self.w))


def source_hashes():
    pending=['test_retention_sender.py'];seen={}
    while pending:
        name=pending.pop();path=HERE/name
        if name in seen or not path.exists():continue
        raw=path.read_bytes();seen[name]=hashlib.sha256(raw).hexdigest()
        for node in ast.walk(ast.parse(raw)):
            mods=[x.name for x in node.names] if isinstance(node,ast.Import) else ([node.module] if isinstance(node,ast.ImportFrom) else [])
            pending.extend(mod.split('.')[0]+'.py' for mod in mods if mod)
    return seen


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':child(*sys.argv[2:]);raise SystemExit(1)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RetentionSenderTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,actual_process_crash_scenarios=CRASHES,
        crash_scenario_count=len(CRASHES),authenticated_witness_requests=TLS_CALLS,observed_witness_tls_versions=sorted(TLS_VERSIONS),
        sender_L3_outbox_atomic=True,receiver_facts='synthetic signed receiver replies; no v2 receiver implementation or result transport',
        source_sha256=source_hashes(),python=platform.python_version(),cryptography=cryptography.__version__,
        scope='Sender persistence and conditional rollback recovery only; reference-authority crash cuts plus separate authenticated-loopback count fixture. No production nonrollback or v2 receiver GC.')
    (HERE/'retention_sender_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
