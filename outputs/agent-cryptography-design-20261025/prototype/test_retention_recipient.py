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
from encrypted_ledger import StateVault
from witnessed_ledger import ReferenceWitness
from retention_sender import RetentionSender,TLSRetentionSender,u64,number
from retention_recipient import RetentionRecipient,TLSRetentionRecipient,capacity_certificate
from test_retention_sender import RetentionSenderTests,context
from test_witnessed_mixed_ledger import backup,populate
from test_encrypted_mixed_ledger import vault,register,TAPE
from test_mixed_delegated_ledger import finish
from ledger import Rejected
from wire import encode,decode,sign1
import retention_wire as r
import retention_delivery as d

HERE=Path(__file__).parent
CRASHES=[]
NETWORK={'sender_witness':0,'receiver_witness':0,'delivery_attempts':0}
TLS_VERSIONS=set()
LONG_RUN=0
CAPACITY={}


def recipient_vault():return StateVault(b'i'*32,b'recipient-v2-001')


def child(config_path,operation,point):
    cfg=json.loads(Path(config_path).read_text());c,s,k=context()
    def fault(p):
        if p==point:os._exit(99)
    w=ReferenceWitness(cfg['witness']);i=RetentionRecipient(cfg['inbox'],context=c,vault=recipient_vault(),clock=lambda:cfg['now'],witness=w,witness_fault=fault)
    if operation=='restore':i.recover_from_witness(fault)
    else:i.accept(bytes.fromhex(cfg['request']),c['sender_cert'],k,fault)
    raise RuntimeError('cut not reached')


class RetentionRecipientTests(unittest.TestCase):
    setUpClass=classmethod(RetentionSenderTests.setUpClass.__func__)
    tearDownClass=classmethod(RetentionSenderTests.tearDownClass.__func__)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.sp=self.root/'sender';self.swp=self.root/'sender-witness';self.ip=self.root/'inbox';self.wp=self.root/'receiver-witness'
        shutil.copyfile(self.template,self.sp);shutil.copyfile(self.wtemplate,self.swp)
        self.c,self.s,self.k=context();self.h=r.context_hash(self.c);self.now=100
        self.sw=ReferenceWitness(self.swp);self.w=ReferenceWitness(self.wp)
        self.l=RetentionSender(self.sp,clock=lambda:self.now,vault=vault(),witness=self.sw)
        self.i=RetentionRecipient.create(self.ip,context=self.c,vault=recipient_vault(),clock=lambda:self.now,witness=self.w)
    def tearDown(self):
        if self.i is not None:self.i.close()
        self.l.close();self.w.close();self.sw.close();self.tmp.cleanup()
    def reopen(self):
        if self.i is not None:self.i.close()
        self.i=RetentionRecipient(self.ip,context=self.c,vault=recipient_vault(),clock=lambda:self.now,witness=self.w)
    def reject(self,code,fn):
        with self.assertRaises(Rejected) as caught:fn()
        self.assertEqual(str(caught.exception),code)
    def send(self,req):return self.i.accept(req,self.c['sender_cert'],self.k)
    def prepared(self,key='request',oid='a'):
        row=self.l.admit_v2(self.h,key,oid);env=self.l.prepare_envelope('t',row['id'],self.s)
        return row,env,d.attempt('DELIVERY',env,b'q'*32,self.c,self.s)
    def delivered(self,key='request',oid='a'):
        row,env,req=self.prepared(key,oid);ack=self.send(req);self.l.confirm('t',row['id'],req,ack)
        return row,env,req,d.parse_receipt(ack,req,self.c)
    def retirement_request(self,target):
        offer=self.l.prepare_retirement(self.h,target,self.s)
        return r.retire_attempt(offer,b'z'*32,self.c,self.s)
    def retire(self,target):
        request=self.retirement_request(target);ack=self.send(request);self.l.confirm_retirement(self.h,request,ack);return request,ack
    def count(self):return self.i.db.execute('SELECT count(*) FROM v2_recipient_live').fetchone()[0]
    def recover_if_needed(self):
        try:self.i.check_current_state()
        except Rejected:self.i.recover_from_witness()
        self.assertEqual(self.i.audit(),[])
    def crash(self,operation,point,request=b''):
        cfg=self.root/'child.json';cfg.write_text(json.dumps(dict(inbox=str(self.ip),witness=str(self.wp),now=self.now,request=request.hex())))
        self.i.close();self.i=None
        p=subprocess.run([sys.executable,__file__,'--child',str(cfg),operation,point],capture_output=True,text=True,timeout=30)
        self.assertEqual(p.returncode,99,p.stderr);CRASHES.append({'operation':operation,'point':point});self.reopen()

    def test_real_mixed_sender_and_receiver_confirm_then_retire(self):
        before=[tuple(x) for x in self.l.db.execute('SELECT * FROM accounts')]
        first=self.delivered();second=self.delivered('count','c')
        self.assertEqual([len(d.parse_envelope(x[1],self.c)['result']) for x in [first,second]],[32,8])
        image_before=len(self.i.state_image());self.retire(2)
        self.assertEqual((self.i.state()['floor'],self.i.state()['high'],self.count()),(2,2,0))
        self.assertLess(len(self.i.state_image()),image_before)
        self.assertEqual([tuple(x) for x in self.l.db.execute('SELECT * FROM accounts')],before)
        self.assertEqual(self.l.audit(),[]);self.assertEqual(self.i.audit(),[])

    def test_capacity_rejects_oversized_window_before_file_or_authority_write(self):
        c=dict(self.c,window=65535);path=self.root/'too-large'
        head=self.w.head(self.i.namespace,True)
        self.reject('V2_RECIPIENT_CAPACITY',lambda:RetentionRecipient.create(path,context=c,
            vault=recipient_vault(),clock=lambda:100,witness=self.w))
        self.assertFalse(path.exists());self.assertEqual(head,self.w.head(self.i.namespace,True))

    def test_capacity_exact_bound_admits_and_one_byte_less_rejects(self):
        bound=self.i.capacity['bound_bytes']
        with patch('witnessed_ledger.MAX_IMAGE',bound-1):
            path=self.root/'one-byte-less'
            self.reject('V2_RECIPIENT_CAPACITY',lambda:RetentionRecipient.new_replica(path,
                context=self.c,vault=recipient_vault(),clock=lambda:100,witness=self.w))
            self.assertFalse(path.exists())
        with patch('witnessed_ledger.MAX_IMAGE',bound):
            other_w=ReferenceWitness(self.root/'boundary-witness')
            try:
                i=RetentionRecipient.create(self.root/'exact-bound',context=self.c,
                    vault=recipient_vault(),clock=lambda:100,witness=other_w)
                try:self.assertEqual(i.capacity['bound_bytes'],bound);self.assertEqual(i.audit(),[])
                finally:i.close()
            finally:other_w.close()

    def test_capacity_serializer_bound_saturates_maximum_admitted_window(self):
        # Storage envelope adversary: maximal ciphertext lengths are intentionally
        # not valid signed events. This measures the actual state_image serializer,
        # not protocol acceptance, encryption integrity or a realistic workload.
        import witnessed_ledger as ws
        c=dict(self.c,window=65535)
        for k in ('tenant','recipient','gateway','session'):c[k]='z'*64
        for k in ('sender_kid','receiver_kid'):c[k]=b'z'*32
        estimate=capacity_certificate(c,TLSRetentionRecipient.inbox_profile,recipient_vault().key_check,self.i._trusted_schema)
        c['window']=estimate['safe_window_upper_limit']
        cert=capacity_certificate(c,TLSRetentionRecipient.inbox_profile,recipient_vault().key_check,self.i._trusted_schema)
        c_above=dict(c,window=c['window']+1)
        above=capacity_certificate(c_above,TLSRetentionRecipient.inbox_profile,recipient_vault().key_check,self.i._trusted_schema)
        self.assertLessEqual(cert['bound_bytes'],ws.MAX_IMAGE);self.assertGreater(above['bound_bytes'],ws.MAX_IMAGE)
        self.i.db.execute('BEGIN IMMEDIATE')
        try:
            blob=b'\xff'*cert['encrypted_field_bytes']
            self.i.db.execute('UPDATE v2_recipient_meta SET profile=?,context=?,high=?,floor=?,root=?,observed=?,last_offer=?',
                (TLSRetentionRecipient.inbox_profile,encode(c),b'\xff'*8,b'\xff'*8,b'\xff'*32,r.MAX_TIME,blob))
            self.i.db.executemany('INSERT INTO v2_recipient_live VALUES(?,?,?,?)',
                [(u64(n),format(n,'064x'),blob,blob) for n in range(1,c['window']+1)])
            actual=len(self.i.state_image())
            self.assertEqual(actual,cert['bound_bytes']-1)
            CAPACITY.update(maximum_context_certificate=cert,serializer_fixture_bytes=actual,
                one_more_window_bound_bytes=above['bound_bytes'],fixture_has_valid_signed_facts=False)
        finally:self.i.db.rollback()
        self.assertEqual(self.i.audit(),[])

    def test_capacity_real_encryption_overhead_and_state_lifecycle(self):
        cert=self.i.capacity;v=recipient_vault()
        cipher=v.seal('capacity-test',(),b'a'*r.MAX_FRAME)
        self.assertEqual(len(cipher),cert['encrypted_field_bytes'])
        lengths=[len(self.i.state_image())]
        for n in range(self.c['window']):
            self.delivered('capacity-'+str(n));lengths.append(len(self.i.state_image()))
        self.retire(self.c['window']);lengths.append(len(self.i.state_image()))
        self.i.recover_from_witness();lengths.append(len(self.i.state_image()))
        self.assertTrue(all(n<=cert['bound_bytes'] for n in lengths))
        self.assertEqual(self.i.audit(),[])
        CAPACITY.update(default_context_certificate=cert,actual_lifecycle_image_bytes=lengths,
            actual_vault_overhead_bytes=len(cipher)-r.MAX_FRAME)

    def test_capacity_recovery_open_rejects_incompatible_limit_without_mutation(self):
        original=self.ip.read_bytes();head=self.w.head(self.i.namespace,True)
        with patch('witnessed_ledger.MAX_IMAGE',self.i.capacity['bound_bytes']-1):
            self.reject('V2_RECIPIENT_CAPACITY',lambda:RetentionRecipient(self.ip,context=self.c,
                vault=recipient_vault(),clock=lambda:100,witness=self.w))
        self.assertEqual(self.ip.read_bytes(),original);self.assertEqual(self.w.head(self.i.namespace,True),head)
        for cap in [0,-1,True,2**64]:
            self.reject('V2_CAPACITY_LIMIT',lambda:capacity_certificate(self.c,self.i.inbox_profile,
                recipient_vault().key_check,self.i._trusted_schema,image_limit=cap))

    def test_lost_acceptance_reply_reuses_original_time_and_ciphertext(self):
        row,env,req=self.prepared();self.send(req)
        stored=[tuple(x) for x in self.i.db.execute('SELECT * FROM v2_recipient_live')]
        self.now=110;self.reopen();retry=d.attempt('DELIVERY',env,b'n'*32,self.c,self.s)
        ack=self.send(retry);fact=d.parse_receipt(ack,retry,self.c)
        self.assertEqual(r.parse_fact(fact,self.c)['event_at'],100);self.assertEqual(stored,[tuple(x) for x in self.i.db.execute('SELECT * FROM v2_recipient_live')])
        self.l.confirm('t',row['id'],retry,ack);self.retire(1)

    def test_lost_retirement_reply_retries_without_changing_floor_or_root(self):
        self.delivered();req=self.retirement_request(1);self.send(req)
        state=self.i.state();self.now=110
        offered=r.parse_retire_attempt(req,self.c)['offer'];retry=r.retire_attempt(offered,b'n'*32,self.c,self.s)
        ack=self.send(retry);self.l.confirm_retirement(self.h,retry,ack)
        self.assertEqual((self.i.state()['floor'],self.i.state()['root'],self.i.state()['high']),(state['floor'],state['root'],state['high']))
        self.assertEqual(self.count(),0)

    def test_lost_retirement_ack_can_reconcile_via_authenticated_checkpoint_query(self):
        self.delivered();self.send(self.retirement_request(1))
        query=r.query(self.c,'CHECKPOINT',0,b'c'*32,self.s);ack=self.send(query)
        self.assertEqual(self.l.confirm_retirement(self.h,query,ack),1);self.assertEqual(self.l.audit(),[])

    def test_window_full_rejects_new_event_until_prefix_retired(self):
        for n in range(3):self.delivered('key'+str(n))
        row,env,req=self.prepared('fourth')
        self.reject('V2_RECIPIENT_WINDOW_FULL',lambda:self.send(req));self.assertEqual(self.count(),3)
        self.retire(2);ack=self.send(req);self.l.confirm('t',row['id'],req,ack)
        self.assertEqual((self.i.state()['floor'],self.i.state()['high'],self.count()),(2,4,2))
        self.assertEqual(self.i.audit(),[])

    def test_retired_requests_never_recreate_fact_or_claim_closed(self):
        row,env,req,fact=self.delivered();self.retire(1)
        self.reject('V2_RETIRED',lambda:self.send(req))
        final=r.query(self.c,'FINAL',1,b'f'*32,self.s);self.reject('V2_RETIRED',lambda:self.send(final))
        retired=r.query(self.c,'RETIRED',1,b'r'*32,self.s);checkpoint=r.parse_checkpoint(self.send(retired),retired,self.c)
        self.assertEqual(checkpoint['status'],'RETIRED');self.assertNotIn('outcome',checkpoint);self.assertNotIn('event_at',checkpoint)
        self.assertEqual(self.count(),0)

    def test_unconfirmed_sender_cannot_produce_retirement_request(self):
        row,env,req=self.prepared();self.send(req)
        self.reject('V2_UNCONFIRMED_RETIREMENT',lambda:self.retirement_request(1))
        self.assertEqual(self.count(),1);self.assertEqual(self.i.state()['floor'],0)

    def test_wrong_root_and_stale_base_cannot_delete_live_tail(self):
        self.delivered();second=self.delivered('second');root2=self.l.archive_root(self.h,2)
        stale=r.offer(self.c,0,r.genesis(self.c),2,root2,self.s)
        self.retire(1);before=self.i.live_facts()
        self.reject('RETENTION_STALE_BASE',lambda:self.send(r.retire_attempt(stale,b'x'*32,self.c,self.s)))
        wrong=r.offer(self.c,1,self.i.state()['root'],2,b'X'*32,self.s)
        self.reject('RETENTION_PREFIX_MISMATCH',lambda:self.send(r.retire_attempt(wrong,b'x'*32,self.c,self.s)))
        self.assertEqual(self.i.live_facts(),before);self.assertEqual(self.count(),1)

    def test_old_smaller_offer_returns_current_checkpoint_only(self):
        self.delivered();self.delivered('second')
        small=self.retirement_request(1);self.retire(2)
        ack=self.send(small);cp=r.parse_checkpoint(ack,small,self.c)
        self.assertEqual(cp['floor'],2);self.assertEqual(cp['root'],self.l.archive_root(self.h,2));self.assertEqual(self.count(),0)

    def test_accept_then_terminal_and_close_then_late_accept(self):
        for accepted_first in (True,False):
            row,env,req=self.prepared();self.now=160
            ctl=self.l.prepare_terminal('t',row['id'],self.s);term=d.attempt('TERMINAL',ctl,b't'*32,self.c,self.s)
            if accepted_first:
                self.now=159;ack=self.send(req);self.now=160;other=self.send(term)
                self.assertEqual(d.parse_receipt(ack,req,self.c),d.parse_receipt(other,term,self.c))
            else:
                self.send(term);self.reject('V2_DELIVERY_CLOSED',lambda:self.send(req))
            self.assertEqual(self.count(),1);self.assertEqual(self.i.audit(),[])
            self.tearDown();self.setUp()

    def test_accept_close_race_establishes_exactly_one_first_event(self):
        row,env,req=self.prepared();self.now=160
        ctl=self.l.prepare_terminal('t',row['id'],self.s);term=d.attempt('TERMINAL',ctl,b't'*32,self.c,self.s)
        def worker(item):
            request,now=item;w=ReferenceWitness(self.wp);i=RetentionRecipient(self.ip,context=self.c,vault=recipient_vault(),clock=lambda:now,witness=w)
            try:
                try:return ('ok',d.parse_receipt(i.accept(request,self.c['sender_cert'],self.k),request,self.c))
                except Rejected as error:return ('rejected',str(error))
            finally:i.close();w.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:outcomes=list(pool.map(worker,[(req,159),(term,160)]))
        facts=[x[1] for x in outcomes if x[0]=='ok'];self.assertTrue(facts);self.assertEqual(len(set(facts)),1)
        self.assertEqual(self.count(),1);self.assertEqual(self.i.audit(),[])

    def test_rejected_early_terminal_preserves_clock_floor(self):
        row,env,req=self.prepared();self.now=160;ctl=self.l.prepare_terminal('t',row['id'],self.s)
        term=d.attempt('TERMINAL',ctl,b't'*32,self.c,self.s);self.now=150
        self.reject('TERMINAL_NOT_EXPIRED',lambda:self.send(term));self.now=140
        self.reject('INBOX_CLOCK_ROLLBACK',lambda:self.send(req));self.assertEqual(self.count(),0)
        self.reopen();self.assertEqual(self.i.state()['observed'],150)

    def test_sender_peer_and_signature_domains_checked_before_state_access(self):
        row,env,req=self.prepared();head=self.w.head(self.i.namespace)
        self.reject('UNAUTHORIZED_GATEWAY',lambda:self.i.accept(req,b'X'*32,self.k))
        self.reject('WRONG_RECIPIENT_SIGNER',lambda:self.i.accept(req,self.c['sender_cert'],self.s))
        raw=bytearray(req);raw[-1]^=1
        self.reject('INVALID_SIGNATURE',lambda:self.send(bytes(raw)))
        self.assertEqual(self.w.head(self.i.namespace),head);self.assertEqual(self.count(),0)

    def test_payload_conflict_cannot_change_first_event(self):
        row,env,req,fact=self.delivered();other=d.envelope(row['descriptor'],b'\0'*32,self.c,self.s)
        if other==env:other=d.envelope(row['descriptor'],(3).to_bytes(8,'big')*4,self.c,self.s)
        self.reject('V2_EVENT_CONFLICT',lambda:self.send(d.attempt('DELIVERY',other,b'x'*32,self.c,self.s)))
        self.assertEqual(self.i.live_facts(),[fact])

    def test_old_replica_after_gc_cannot_resurrect_deleted_history(self):
        row,env,req,fact=self.delivered();old=self.root/'old';backup(self.i.db,old);self.retire(1)
        clone=RetentionRecipient(old,context=self.c,vault=recipient_vault(),clock=lambda:100,witness=self.w)
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:clone.accept(req,self.c['sender_cert'],self.k))
            clone.recover_from_witness();self.assertEqual(clone.state()['floor'],1)
            self.reject('V2_RETIRED',lambda:clone.accept(req,self.c['sender_cert'],self.k))
            self.assertEqual(clone.db.execute('SELECT count(*) FROM v2_recipient_live').fetchone()[0],0)
        finally:clone.close()

    def test_missing_database_requires_explicit_restore_and_wrong_key_rejected(self):
        self.delivered();image=self.i.state_image()
        self.reject('INBOX_RECOVERY_REQUIRED',lambda:RetentionRecipient(self.root/'missing',context=self.c,vault=recipient_vault(),clock=lambda:100,witness=self.w))
        restored=RetentionRecipient.restore_new(self.root/'restored',context=self.c,vault=recipient_vault(),clock=lambda:100,witness=self.w)
        try:self.assertEqual(restored.state_image(),image);self.assertEqual(restored.audit(),[])
        finally:restored.close()
        bad=StateVault(b'X'*32,b'recipient-v2-001')
        self.reject('V2_RECIPIENT_PROFILE',lambda:RetentionRecipient(self.ip,context=self.c,vault=bad,clock=lambda:100,witness=self.w))

    def test_invalid_authority_frontier_image_rejected_before_recovery_commit(self):
        self.delivered();before=self.i.state_image();head=self.w.head(self.i.namespace)
        self.i.db.execute('BEGIN IMMEDIATE');self.i.db.execute('UPDATE v2_recipient_meta SET high=?',(u64(2),));bad=self.i.state_image();self.i.db.rollback()
        self.w.compare_and_store(self.i.namespace,head['seq'],head['digest'],bad,'a'*32)
        self.reject('RETENTION_LIVE_WINDOW',self.i.recover_from_witness);self.assertEqual(self.i.state_image(),before)

    def test_image_cap_failure_preserves_previous_head_without_reply(self):
        row,env,req=self.prepared();head=self.w.head(self.i.namespace);image=self.i.state_image()
        with patch('witnessed_ledger.MAX_IMAGE',len(image)+10):self.reject('INVALID_WITNESS_IMAGE',lambda:self.send(req))
        self.assertEqual(self.w.head(self.i.namespace),head);self.assertEqual(self.i.state_image(),image);self.assertEqual(self.count(),0)

    def test_rolling_back_both_authority_and_inbox_remains_negative_control(self):
        row,env,req=self.prepared();old_i=self.root/'old-inbox';old_w=self.root/'old-witness'
        backup(self.i.db,old_i);backup(self.w.db,old_w)
        first=d.parse_receipt(self.send(req),req,self.c);self.i.close();self.i=None;self.w.close()
        shutil.copyfile(old_i,self.ip);shutil.copyfile(old_w,self.wp);self.w=ReferenceWitness(self.wp);self.now=110;self.reopen()
        later=d.parse_receipt(self.send(req),req,self.c)
        self.assertEqual((r.parse_fact(first,self.c)['event_at'],r.parse_fact(later,self.c)['event_at']),(100,110))
        self.assertEqual(self.i.audit(),[])

    def test_repeated_real_sender_delivery_gc_keeps_current_live_rows_bounded(self):
        global LONG_RUN
        for n in range(1,33):
            self.delivered('loop'+str(n));self.assertLessEqual(self.count(),self.c['window']);self.retire(n)
            self.assertEqual(self.count(),0)
        self.assertEqual(self.i.state()['high'],32);self.assertEqual(self.i.state()['floor'],32)
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM v2_outbox').fetchone()[0],32)
        self.assertEqual(self.i.audit(),[]);self.assertEqual(self.l.audit(),[]);LONG_RUN=32

    def test_process_cuts_on_first_accept_and_close(self):
        for operation in ('accept','close'):
            for point in ('after_v2_recipient_record','before_v2_recipient_event_commit','after_v2_recipient_event_commit','after_witness_accept'):
                row,env,req=self.prepared()
                if operation=='close':
                    self.now=160;ctl=self.l.prepare_terminal('t',row['id'],self.s);req=d.attempt('TERMINAL',ctl,b't'*32,self.c,self.s)
                self.crash(operation,point,req);self.recover_if_needed();ack=self.send(req)
                self.l.confirm('t',row['id'],req,ack);self.assertEqual(self.count(),1);self.assertEqual(self.i.audit(),[])
                self.tearDown();self.setUp()

    def test_process_cuts_on_retirement_and_recovery(self):
        for point in ('after_v2_recipient_delete','before_v2_recipient_retire_commit','after_v2_recipient_retire_commit','after_witness_accept'):
            self.delivered();req=self.retirement_request(1);self.crash('retire',point,req);self.recover_if_needed()
            self.l.confirm_retirement(self.h,req,self.send(req));self.assertEqual(self.count(),0);self.assertEqual(self.i.state()['high'],1)
            self.tearDown();self.setUp()
        for point in ('after_recovery_delete','before_recovery_commit','after_recovery_commit'):
            self.delivered();old=self.root/'old-inbox';backup(self.i.db,old);self.retire(1)
            self.i.close();self.i=None;shutil.copyfile(old,self.ip);self.reopen()
            self.crash('restore',point);self.recover_if_needed()
            self.assertEqual((self.i.state()['floor'],self.i.state()['high'],self.count()),(1,1,0))
            self.tearDown();self.setUp()

    def test_authenticated_mixed_network_with_both_authorities_and_lost_replies(self):
        from test_witness_transport import certificates,public
        from witness_transport import WitnessTLSService,TLSWitnessClient,trusted_register_peer,certificate_fingerprint
        from delivery_transport import RecipientTLSService,DeliverySender
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        certs=certificates(self.root);swp=self.root/'tls-sw';rwp=self.root/'tls-rw'
        c=dict(self.c,sender_cert=certificate_fingerprint(certs['writer'][0]),receiver_cert=certificate_fingerprint(certs['server'][0]))
        skey=Ed25519PrivateKey.generate();rkey=Ed25519PrivateKey.generate()
        for path,ns in ((swp,c['sender_authority'].hex()),(rwp,c['receiver_authority'].hex())):
            trusted_register_peer(path,ns,certificate_fingerprint(certs['admin'][0]),'admin')
        with WitnessTLSService(swp,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signing_key=skey) as sws, WitnessTLSService(rwp,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signing_key=rkey) as rws:
            def client(which):
                server,key=(sws,skey) if which=='sender_witness' else (rws,rkey)
                value=TLSWitnessClient(port=server.port,cafile=certs['ca'],certfile=certs['admin'][0],keyfile=certs['admin'][1],witness_public_key=public(key));original=value.exchange
                def exchange(raw,body):
                    NETWORK[which]+=1;result=original(raw,body)
                    if value.last_tls_version:TLS_VERSIONS.add(value.last_tls_version)
                    return result
                value.exchange=exchange;return value
            sender=populate(TLSRetentionSender.create(self.root/'tls-sender',clock=lambda:self.now,vault=vault(),witness=client('sender_witness')))
            ip=self.root/'tls-inbox'
            def inbox():return TLSRetentionRecipient(ip,context=c,vault=recipient_vault(),clock=lambda:self.now,witness=client('receiver_witness'))
            created=TLSRetentionRecipient.create(ip,context=c,vault=recipient_vault(),clock=lambda:self.now,witness=client('receiver_witness'));created.close()
            try:
                register(sender);register(sender,'c',False)
                with patch('histogram_ledger.fresh_tape',return_value=TAPE):finish(sender)
                h=sender.register_context(c)
                with RecipientTLSService(inbox_factory=inbox,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signer=self.k) as service:
                    transport=DeliverySender(port=service.port,cafile=certs['ca'],certfile=certs['writer'][0],keyfile=certs['writer'][1],signer=self.s)
                    def exchange(request):
                        NETWORK['delivery_attempts']+=1
                        try:return transport.exchange(request,c)
                        finally:
                            if transport.last_tls_version:TLS_VERSIONS.add(transport.last_tls_version)
                    def lose(point):
                        if point=='before_ack_send':raise ConnectionError('deliberately lost reply')
                    row=sender.admit_v2(h,'hist','a');env=sender.prepare_envelope('t',row['id'],self.s);req=d.attempt('DELIVERY',env,b'd'*32,c,self.s)
                    service.fault=lose
                    with self.assertRaises(OSError):exchange(req)
                    service.fault=lambda point:None;self.now=110;retry=d.attempt('DELIVERY',env,b'e'*32,c,self.s)
                    ack=exchange(retry);self.assertEqual(r.parse_fact(d.parse_receipt(ack,retry,c),c)['event_at'],100);sender.confirm('t',row['id'],retry,ack)
                    row=sender.admit_v2(h,'count','c');self.now=170;ctl=sender.prepare_terminal('t',row['id'],self.s)
                    term=d.attempt('TERMINAL',ctl,b't'*32,c,self.s);sender.confirm('t',row['id'],term,exchange(term))
                    offer=sender.prepare_retirement(h,2,self.s);retire=r.retire_attempt(offer,b'r'*32,c,self.s);service.fault=lose
                    with self.assertRaises(OSError):exchange(retire)
                    service.fault=lambda point:None;retry=r.retire_attempt(offer,b's'*32,c,self.s);sender.confirm_retirement(h,retry,exchange(retry))
                    query=r.query(c,'RETIRED',1,b'q'*32,self.s);cp=r.parse_checkpoint(exchange(query),query,c)
                    self.assertEqual(cp['floor'],2);self.assertNotIn('outcome',cp)
                    check=inbox()
                    try:self.assertEqual(check.db.execute('SELECT count(*) FROM v2_recipient_live').fetchone()[0],0);self.assertEqual(check.audit(),[])
                    finally:check.close()
                    self.assertEqual(sender.audit(),[])
            finally:sender.close()


def source_hashes():
    pending=['test_retention_recipient.py'];seen={}
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
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RetentionRecipientTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,actual_process_crash_scenarios=CRASHES,crash_scenario_count=len(CRASHES),
        authenticated_network_requests=NETWORK,observed_tls_versions=sorted(TLS_VERSIONS),repeated_delivery_retirement_cycles=LONG_RUN,
        source_sha256=source_hashes(),python=platform.python_version(),cryptography=cryptography.__version__,
        logical_recipient_gc=True,production_nonrollback=False,secure_erasure=False,global_storage_bound=False,
        recipient_byte_capacity_admission=True,capacity_validation=CAPACITY,
        scope='Actual sender/receiver authority transactions and logical prefix removal. Reference-authority crash cuts; separate loopback mTLS mixed fixture with reply loss; no multihost or complete P2/DP observation proof.')
    (HERE/'retention_recipient_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
