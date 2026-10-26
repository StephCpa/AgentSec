"""Compact same-image CAS preserves ordering, write authority and unknown outcomes."""
import concurrent.futures
import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
import test_witness_transport as original
from witnessed_ledger import ReferenceWitness,image_hash,Rejected
from witness_transport import (AuthorizedWitness,TLSWitnessedLedger,parse_request,
    trusted_revoke_peer,certificate_fingerprint,PROFILE,SERVICE,REPLY_TYPE)
from test_encrypted_ledger import vault
from wire import encode,decode,sign1


class CompactLocalTests(unittest.TestCase):
    def test_bounded_full_cas_refinement(self):
        from compact_witness_model import run
        result=run()
        self.assertEqual(result['cases'],1296)
        self.assertEqual(result['compared_transitions'],5184)
        self.assertGreater(result['candidate_methods']['reassert'],0)
        self.assertGreater(result['candidate_methods']['cas'],0)

    def test_versions_tokens_and_equivalent_full_cas_retries(self):
        with tempfile.TemporaryDirectory() as td:
            w=ReferenceWitness(Path(td)/'w')
            try:
                a=w.bootstrap('n',b'A');b=w.reassert('n',0,a['digest'],'a'*32)
                self.assertEqual(b,dict(seq=1,digest=a['digest']))
                self.assertEqual(w.compare_and_store('n',0,a['digest'],b'A','a'*32),b)
                c=w.compare_and_store('n',1,b['digest'],b'A','b'*32)
                self.assertEqual(w.reassert('n',1,b['digest'],'b'*32),c)
                self.assertEqual(w.reassert('n',2,c['digest'],'c'*32)['seq'],3)
                self.assertEqual(w.head('n',True),dict(seq=3,digest=a['digest'],image=b'A'))
                self.assertEqual(w.db.execute('SELECT count(*) FROM commits').fetchone()[0],3)
            finally:w.close()

    def test_aba_stale_attempt_and_changed_content_token_conflict(self):
        with tempfile.TemporaryDirectory() as td:
            w=ReferenceWitness(Path(td)/'w')
            try:
                a=w.bootstrap('n',b'A');b=w.compare_and_store('n',0,a['digest'],b'B','a'*32)
                with self.assertRaisesRegex(Rejected,'WITNESS_REQUEST_CONFLICT'):w.reassert('n',0,a['digest'],'a'*32)
                c=w.compare_and_store('n',1,b['digest'],b'A','b'*32)
                with self.assertRaisesRegex(Rejected,'WITNESS_CAS_CONFLICT'):w.reassert('n',0,a['digest'],'c'*32)
                with self.assertRaisesRegex(Rejected,'WITNESS_CAS_CONFLICT'):w.reassert('n',2,b['digest'],'c'*32)
                self.assertEqual(w.head('n'),c)
            finally:w.close()

    def test_reassert_does_not_execute_image_column_update(self):
        with tempfile.TemporaryDirectory() as td:
            w=ReferenceWitness(Path(td)/'w')
            try:
                a=w.bootstrap('n',b'A')
                w.db.execute("CREATE TRIGGER image_write BEFORE UPDATE OF image ON heads BEGIN SELECT RAISE(FAIL,'image write'); END")
                self.assertEqual(w.reassert('n',0,a['digest'],'a'*32)['seq'],1)
                with self.assertRaisesRegex(sqlite3.IntegrityError,'image write'):
                    w.compare_and_store('n',1,a['digest'],b'A','b'*32)
                self.assertEqual(w.head('n',True)['image'],b'A')
            finally:w.close()

    def test_corrupt_retained_image_is_not_reasserted(self):
        with tempfile.TemporaryDirectory() as td:
            w=ReferenceWitness(Path(td)/'w')
            try:
                a=w.bootstrap('n',b'A')
                w.db.execute('UPDATE heads SET image=? WHERE namespace=?',(b'corrupt','n'))
                with self.assertRaisesRegex(Rejected,'INVALID_WITNESS_IMAGE'):w.reassert('n',0,a['digest'],'a'*32)
                self.assertEqual(w.head('n'),a)
                self.assertEqual(w.db.execute('SELECT count(*) FROM commits').fetchone()[0],0)
            finally:w.close()

    def test_local_and_wire_input_validation(self):
        with tempfile.TemporaryDirectory() as td:
            w=ReferenceWitness(Path(td)/'w')
            try:
                a=w.bootstrap('n',b'A')
                for seq,digest,token in ((True,a['digest'],'a'*32),(-1,a['digest'],'a'*32),(2**62,a['digest'],'a'*32),(0,'A'*64,'a'*32),(0,a['digest'],'g'*32)):
                    with self.assertRaises(Rejected):w.reassert('n',seq,digest,token)
                self.assertEqual(w.head('n'),a)
            finally:w.close()
        req=dict(profile=PROFILE,service=SERVICE,method='reassert',namespace='a'*32,challenge=b'c'*32,
                 body_size=0,body_hash=hashlib.sha256(b'').digest(),expected_seq=0,expected_digest=image_hash(b'A'),request_id='a'*32)
        self.assertEqual(parse_request(encode(req),b''),req)
        for change in ({'expected_seq':True},{'expected_digest':'Z'*64},{'request_id':'x'},{'extra':1},{'include_image':0}):
            with self.assertRaises(Rejected):parse_request(encode(dict(req,**change)),b'')
        req.update(body_size=1,body_hash=hashlib.sha256(b'A').digest())
        with self.assertRaises(Rejected):parse_request(encode(req),b'A')


class CompactTransportTests(unittest.TestCase):
    setUpClass=classmethod(original.TransportTests.setUpClass.__func__)
    tearDownClass=classmethod(original.TransportTests.tearDownClass.__func__)
    tearDown=original.TransportTests.tearDown
    reject=original.TransportTests.reject
    initialize=original.TransportTests.initialize
    setup_ledger=original.TransportTests.setup_ledger
    client=original.TransportTests.client

    def setUp(self):
        original.TransportTests.setUp(self)
        self.server.allow_reassert=True;self.writer.compact_reassert=True

    def test_only_same_image_uses_empty_body_and_default_stays_full(self):
        a=self.initialize();seen=[];exchange=self.writer.exchange
        def observe(raw,body):seen.append((decode(raw)['method'],len(body)));return exchange(raw,body)
        self.writer.exchange=observe
        b=self.writer.compare_and_store(self.ns,0,a['digest'],b'initial-state','a'*32)
        c=self.writer.compare_and_store(self.ns,1,b['digest'],b'changed','b'*32)
        self.assertEqual(seen,[('reassert',0),('cas',7)])
        self.writer.compact_reassert=False
        self.writer.compare_and_store(self.ns,2,c['digest'],b'changed','c'*32)
        self.assertEqual(seen[-1],('cas',7))

    def test_server_opt_in_has_no_fallback_or_commit(self):
        a=self.initialize();self.server.allow_reassert=False
        with self.assertRaises((OSError,Rejected)):
            self.writer.compare_and_store(self.ns,0,a['digest'],b'initial-state','a'*32)
        self.assertEqual(self.admin.head(self.ns),a)
        self.writer.compact_reassert=False
        self.assertEqual(self.writer.compare_and_store(self.ns,0,a['digest'],b'initial-state','a'*32)['seq'],1)

    def test_empty_body_still_requires_write_role_and_namespace(self):
        a=self.initialize()
        for role in ('observer','restorer','unregistered'):
            client=self.client(role,compact_reassert=True)
            self.reject('WITNESS_ACCESS_DENIED',lambda:client.compare_and_store(self.ns,0,a['digest'],b'initial-state','a'*32))
        self.reject('WITNESS_ACCESS_DENIED',lambda:self.writer.compare_and_store('b'*32,0,a['digest'],b'initial-state','a'*32))
        self.assertEqual(self.admin.head(self.ns),a)

    def test_revocation_precedes_new_reassert_and_cached_receipt(self):
        a=self.initialize();fp=certificate_fingerprint(self.certs['writer'][0])
        self.writer.compare_and_store(self.ns,0,a['digest'],b'initial-state','a'*32)
        trusted_revoke_peer(self.wp,self.ns,fp)
        for seq,token in ((0,'a'*32),(1,'b'*32)):
            self.reject('WITNESS_ACCESS_DENIED',lambda:self.writer.compare_and_store(self.ns,seq,a['digest'],b'initial-state',token))
        self.assertEqual(self.admin.head(self.ns)['seq'],1)

    def test_revocation_after_handshake_is_checked_at_dispatch(self):
        a=self.initialize();fp=certificate_fingerprint(self.certs['writer'][0])
        def revoke(point,request):
            if point=='before_dispatch' and request['method']=='reassert':trusted_revoke_peer(self.wp,self.ns,fp)
        self.server.fault=revoke
        self.reject('WITNESS_ACCESS_DENIED',lambda:self.writer.compare_and_store(self.ns,0,a['digest'],b'initial-state','a'*32))
        self.assertEqual(self.admin.head(self.ns),a)

    def test_reassert_permission_check_and_update_share_write_lock(self):
        a=self.initialize();checked=threading.Event();resume=threading.Event();authorize=AuthorizedWitness.authorize_operation
        def gate(w,namespace,operation):
            authorize(w,namespace,operation)
            if operation=='cas':checked.set();self.assertTrue(resume.wait(3))
        with patch.object(AuthorizedWitness,'authorize_operation',gate),concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(self.writer.compare_and_store,self.ns,0,a['digest'],b'initial-state','a'*32)
            try:
                self.assertTrue(checked.wait(3));db=sqlite3.connect(self.wp,timeout=0,isolation_level=None)
                try:
                    with self.assertRaisesRegex(sqlite3.OperationalError,'locked'):db.execute('UPDATE witness_clients SET revoked=1')
                finally:db.close()
            finally:resume.set()
            self.assertEqual(future.result(3)['seq'],1)

    def test_competing_distinct_reassertions_do_not_collapse(self):
        a=self.initialize();clients=[self.client('writer',compact_reassert=True) for _ in range(2)]
        def send(i):
            try:return clients[i].compare_and_store(self.ns,0,a['digest'],b'initial-state',str(i)*32)['seq']
            except Rejected as e:return str(e)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(send,range(2)))
        self.assertCountEqual(results,[1,'WITNESS_CAS_CONFLICT'])
        self.assertEqual(self.admin.head(self.ns)['seq'],1)

    def test_reassert_replies_bind_challenge_method_sequence_and_digest(self):
        a=self.initialize();exchange=self.writer.exchange;captured=[]
        def capture(raw,body):result=exchange(raw,body);captured.append(result);return result
        self.writer.exchange=capture
        self.writer.compare_and_store(self.ns,0,a['digest'],b'initial-state','a'*32)
        self.writer.exchange=lambda *args:captured[0]
        self.reject('WITNESS_REPLY_BINDING',lambda:self.writer.compare_and_store(self.ns,0,a['digest'],b'initial-state','a'*32))
        for field,value,code in (('method','cas','WITNESS_REPLY_BINDING'),('seq',9,'INVALID_WITNESS_REPLY'),('digest','f'*64,'INVALID_WITNESS_REPLY')):
            def alter(raw,body):
                meta,data=exchange(raw,body);obj=decode(decode(meta[1:])[2])
                if field=='method':obj[field]=value
                else:obj['result'][field]=value
                return sign1(encode(obj),b'witness',self.signer,REPLY_TYPE),data
            self.writer.exchange=alter
            self.reject(code,lambda:self.writer.compare_and_store(self.ns,0,a['digest'],b'initial-state','a'*32))

    def test_noop_guard_unknown_outcomes_restore_exact_image(self):
        ledger=self.setup_ledger()
        try:
            for index,point in enumerate(('before_dispatch','after_dispatch','after_witness_accept','after_local_anchor_write')):
                before=self.admin.head(self.ns,True);anchor=ledger.local_anchor()
                def network_fault(p,request):
                    if p==point and request['method']=='reassert':raise OSError('injected response loss')
                def local_fault(p):
                    if p==point:raise OSError('injected local abort')
                self.server.fault=network_fault;ledger.witness_fault=local_fault
                with self.assertRaises(OSError):
                    with ledger.tx():pass
                self.server.fault=lambda *args:None;ledger.witness_fault=lambda *args:None
                after=self.admin.head(self.ns,True);committed=point!='before_dispatch'
                self.assertEqual(after['seq'],before['seq']+int(committed));self.assertEqual(after['image'],before['image'])
                self.assertEqual(ledger.local_anchor(),anchor)
                if committed:self.reject('WITNESS_RECOVERY_REQUIRED',ledger.check_current_state)
                restored=TLSWitnessedLedger.restore_new(self.root/('restore-'+str(index)),clock=lambda:100,vault=vault(),witness=self.writer)
                self.assertEqual(restored.state_image(),before['image']);self.assertEqual(restored.audit(),[])
                ledger.close();ledger=restored
        finally:ledger.close()

    def test_compressed_frames_can_carry_reassert(self):
        self.server.frame_mode='deflate-v1';self.admin.frame_mode='deflate-v1';self.writer.frame_mode='deflate-v1'
        a=self.initialize();b=self.writer.compare_and_store(self.ns,0,a['digest'],b'initial-state','a'*32)
        self.assertEqual(self.writer.head(self.ns,True),dict(b,image=b'initial-state'))

if __name__=='__main__':unittest.main()
