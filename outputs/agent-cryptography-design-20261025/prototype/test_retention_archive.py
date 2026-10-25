import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest
from unittest.mock import patch
import cryptography
from ledger import Rejected
from wire import encode,decode
from witnessed_ledger import ReferenceWitness
from retention_sender import RetentionSender,number
from retention_archive import ArchiveVerifier,archive_page,checkpoint_binding,parse_page,PROFILE,MAX_FACTS
from test_retention_sender import RetentionSenderTests,context
from test_retention_recipient import RetentionRecipientTests
from test_encrypted_mixed_ledger import vault
from test_witnessed_mixed_ledger import backup
import retention_wire as r
import retention_delivery as d

HERE=Path(__file__).parent
METRICS={}
CUTS=[]


def child(path,point):
    cfg=json.loads(Path(path).read_text());c,_,_=context();w=ReferenceWitness(cfg['witness'])
    l=RetentionSender(cfg['sender'],clock=lambda:100,vault=vault(),witness=w)
    def fault(p):
        if p==point:os._exit(99)
    archive_page(l,r.context_hash(c),bytes.fromhex(cfg['request']),bytes.fromhex(cfg['ack']),1,fault=fault)
    raise RuntimeError('cut not reached')


class ArchiveTests(unittest.TestCase):
    setUpClass=classmethod(RetentionSenderTests.setUpClass.__func__)
    tearDownClass=classmethod(RetentionSenderTests.tearDownClass.__func__)
    setUp=RetentionRecipientTests.setUp
    tearDown=RetentionRecipientTests.tearDown
    reject=RetentionRecipientTests.reject
    prepared=RetentionRecipientTests.prepared
    delivered=RetentionRecipientTests.delivered
    send=RetentionRecipientTests.send
    retirement_request=RetentionRecipientTests.retirement_request
    retire=RetentionRecipientTests.retire

    def history(self,n=3):
        facts=[]
        for index in range(n):
            facts.append(self.delivered('archive-'+str(index),'a' if index%2==0 else 'c')[3])
            request,ack=self.retire(index+1)
        return facts,request,ack

    def test_actual_accepted_and_closed_facts_survive_recipient_cleanup(self):
        first=self.delivered()[3]
        row=self.l.admit_v2(self.h,'closed','c');self.now=160
        ctl=self.l.prepare_terminal('t',row['id'],self.s);request=d.attempt('TERMINAL',ctl,b't'*32,self.c,self.s)
        ack=self.send(request);second=d.parse_receipt(ack,request,self.c);self.l.confirm('t',row['id'],request,ack)
        req,cp=self.retire(2)
        self.assertEqual(self.i.live_facts(),[])
        for target,fact in enumerate([first,second],1):
            v=ArchiveVerifier(self.c,req,cp,target);page=archive_page(self.l,self.h,req,cp,1)
            self.assertTrue(v.accept(page)['complete']);self.assertEqual(v.result(),fact)
        self.assertEqual([r.parse_fact(x,self.c)['outcome'] for x in [first,second]],['ACCEPTED','CLOSED'])

    def test_many_retirements_paginate_to_exact_middle_fact(self):
        facts,request,ack=self.history(35);v=ArchiveVerifier(self.c,request,ack,17);sizes=[]
        while not v.complete:
            page=archive_page(self.l,self.h,request,ack,v.next,limit=7);sizes.append(len(page));v.accept(page)
            if not v.complete:self.reject('ARCHIVE_INCOMPLETE',v.result)
        self.assertEqual(v.result(),facts[16]);self.assertEqual(len(sizes),5)
        self.assertTrue(all(n<=r.MAX_FRAME for n in sizes));self.assertEqual(self.i.live_facts(),[])
        METRICS.update(real_archived_facts=35,pages=len(sizes),page_bytes=sizes,selected_sequence=17)

    def test_export_is_read_only_and_does_not_open_results(self):
        _,request,ack=self.history(2)
        image=self.l.state_image();head=self.sw.head(self.l.namespace,True);file=self.sp.read_bytes()
        original=self.l.open;kinds=[]
        def opened(kind,row):
            self.assertEqual(kind,'fact');kinds.append(kind);return original(kind,row)
        with patch.object(self.l,'op',side_effect=AssertionError('result access')),patch.object(self.l,'open',side_effect=opened),\
             patch.object(self.l,'now',side_effect=AssertionError('clock update')),\
             patch.object(self.sw,'compare_and_store',side_effect=AssertionError('authority write')):
            page=archive_page(self.l,self.h,request,ack,1)
        self.assertTrue(kinds);self.assertEqual(self.l.state_image(),image);self.assertEqual(self.sp.read_bytes(),file)
        self.assertEqual(self.sw.head(self.l.namespace,True),head)
        payload=decode(page);self.assertNotIn('result',payload);self.assertNotIn('envelope',payload)

    def test_partial_pages_never_release_selected_fact(self):
        facts,req,ack=self.history(3);v=ArchiveVerifier(self.c,req,ack,1)
        v.accept(archive_page(self.l,self.h,req,ack,1,1));self.reject('ARCHIVE_INCOMPLETE',v.result)
        v.accept(archive_page(self.l,self.h,req,ack,2,1));self.reject('ARCHIVE_INCOMPLETE',v.result)
        v.accept(archive_page(self.l,self.h,req,ack,3,1));self.assertEqual(v.result(),facts[0])

    def test_missing_duplicate_and_reordered_pages_reject(self):
        _,req,ack=self.history(3);one=archive_page(self.l,self.h,req,ack,1,1);two=archive_page(self.l,self.h,req,ack,2,1)
        v=ArchiveVerifier(self.c,req,ack,1);self.reject('ARCHIVE_CURSOR',lambda:v.accept(two));self.assertEqual(v.next,1)
        v.accept(one);self.reject('ARCHIVE_CURSOR',lambda:v.accept(one));self.assertEqual(v.next,2)
        self.reject('ARCHIVE_INCOMPLETE',v.result)

    def test_forged_last_fact_rejected_without_advancing_verifier(self):
        facts,req,ack=self.history(2);v=ArchiveVerifier(self.c,req,ack,2)
        v.accept(archive_page(self.l,self.h,req,ack,1,1));good=archive_page(self.l,self.h,req,ack,2,1)
        obj=decode(good);fact=r.parse_fact(obj['facts'][0],self.c);fact['event_at']+=1;obj['facts'][0]=r.fact_bytes(fact,self.c)
        self.reject('ARCHIVE_ROOT_MISMATCH',lambda:v.accept(encode(obj)));self.assertEqual(v.next,2)
        self.reject('ARCHIVE_INCOMPLETE',v.result);v.accept(good);self.assertEqual(v.result(),facts[1])

    def test_tampered_early_page_cannot_become_an_authenticated_result(self):
        _,req,ack=self.history(2);v=ArchiveVerifier(self.c,req,ack,1);obj=decode(archive_page(self.l,self.h,req,ack,1,1))
        fact=r.parse_fact(obj['facts'][0],self.c);fact['action_digest']=b'x'*32;obj['facts'][0]=r.fact_bytes(fact,self.c)
        self.assertFalse(v.accept(encode(obj))['complete']);self.reject('ARCHIVE_INCOMPLETE',v.result)
        self.reject('ARCHIVE_CURSOR',lambda:v.accept(archive_page(self.l,self.h,req,ack,2,1)))
        self.reject('ARCHIVE_INCOMPLETE',v.result)

    def test_checkpoint_challenge_route_and_signature_are_pinned(self):
        _,req,ack=self.history(1);query=r.query(self.c,'CHECKPOINT',0,b'n'*32,self.s)
        query_ack=self.send(query);other_query=r.query(self.c,'CHECKPOINT',0,b'm'*32,self.s)
        self.reject('RETENTION_REPLY_BINDING',lambda:ArchiveVerifier(self.c,other_query,query_ack,1))
        # A RETIRE_ACK cannot be rebound to a different request object family.
        self.reject('INVALID_SIGNATURE',lambda:ArchiveVerifier(self.c,query,ack,1))
        bad=bytearray(ack);bad[-1]^=1
        self.reject('INVALID_SIGNATURE',lambda:ArchiveVerifier(self.c,req,bytes(bad),1))
        with self.assertRaises(Rejected):ArchiveVerifier(dict(self.c,epoch=b'x'*16),req,ack,1)

    def test_pages_cannot_switch_checkpoints(self):
        _,req,ack=self.history(2);query=r.query(self.c,'CHECKPOINT',0,b'n'*32,self.s);new_ack=self.send(query)
        page=archive_page(self.l,self.h,query,new_ack,1)
        v=ArchiveVerifier(self.c,req,ack,1);self.reject('ARCHIVE_CHECKPOINT_BINDING',lambda:v.accept(page))

    def test_old_checkpoint_remains_historical_after_new_retirement(self):
        facts,req,ack=self.history(1);self.delivered('later');self.retire(2)
        v=ArchiveVerifier(self.c,req,ack,1);v.accept(archive_page(self.l,self.h,req,ack,1));self.assertEqual(v.result(),facts[0])
        self.reject('ARCHIVE_TARGET_NOT_RETIRED',lambda:ArchiveVerifier(self.c,req,ack,2))

    def test_sender_must_persist_retirement_checkpoint_before_export(self):
        self.delivered();req=self.retirement_request(1);ack=self.send(req)
        self.reject('ARCHIVE_UNCONFIRMED_CHECKPOINT',lambda:archive_page(self.l,self.h,req,ack,1))
        self.l.confirm_retirement(self.h,req,ack);v=ArchiveVerifier(self.c,req,ack,1)
        v.accept(archive_page(self.l,self.h,req,ack,1));self.assertTrue(v.complete)

    def test_revocation_does_not_erase_privileged_historical_evidence(self):
        facts,req,ack=self.history(1);self.l.revoke_context(self.h)
        v=ArchiveVerifier(self.c,req,ack,1);v.accept(archive_page(self.l,self.h,req,ack,1));self.assertEqual(v.result(),facts[0])

    def test_stale_sender_requires_restore_before_archive_export(self):
        stale=self.root/'old-sender';backup(self.l.db,stale);facts,req,ack=self.history(1)
        clone=RetentionSender(stale,clock=lambda:100,vault=vault(),witness=self.sw)
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:archive_page(clone,self.h,req,ack,1))
            clone.recover_from_witness();v=ArchiveVerifier(self.c,req,ack,1)
            v.accept(archive_page(clone,self.h,req,ack,1));self.assertEqual(v.result(),facts[0])
        finally:clone.close()

    def test_authority_change_during_read_prevents_return(self):
        _,req,ack=self.history(1);old=self.sw.head(self.l.namespace,True)
        def fault(point):
            if point=='before_archive_fence':self.sw.compare_and_store(self.l.namespace,old['seq'],old['digest'],old['image'],'a'*32)
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:archive_page(self.l,self.h,req,ack,1,fault=fault))
        self.assertFalse(self.l.db.in_transaction);self.l.recover_from_witness()
        self.assertTrue(archive_page(self.l,self.h,req,ack,1))

    def test_local_archive_corruption_and_missing_facts_fail_closed(self):
        _,req,ack=self.history(1);image=self.l.state_image()
        self.l.db.execute('UPDATE v2_outbox SET fact=?',(b'x'*50,))
        self.reject('LOCAL_STATE_DIVERGED',lambda:archive_page(self.l,self.h,req,ack,1))
        self.l.recover_from_witness();self.assertEqual(self.l.state_image(),image)
        # Trusted local repair bypass is not a public API. Model a missing row
        # even if an authority were erroneously made to attest the corrupted DB.
        self.l.db.execute('DELETE FROM v2_requests');self.l.db.execute('DELETE FROM v2_outbox')
        old=self.sw.head(self.l.namespace);new=self.sw.compare_and_store(self.l.namespace,old['seq'],old['digest'],self.l.state_image(),'b'*32)
        self.l.db.execute('UPDATE witness_anchor SET seq=?,digest=?',(new['seq'],new['digest']))
        self.reject('V2_ARCHIVE_GAP',lambda:archive_page(self.l,self.h,req,ack,1))

    def test_invalid_limits_schema_counts_and_sequence_overflow(self):
        _,req,ack=self.history(1)
        for limit in [0,17,True,-1]:self.reject('ARCHIVE_PAGE_LIMIT',lambda:archive_page(self.l,self.h,req,ack,1,limit))
        self.reject('RETENTION_INTEGER',lambda:archive_page(self.l,self.h,req,ack,r.MAX_SEQ+1))
        page=decode(archive_page(self.l,self.h,req,ack,1))
        for changed,code in [(dict(page,extra=1),'ARCHIVE_SCHEMA'),(dict(page,facts=[]),'ARCHIVE_PAGE_COUNT'),(dict(page,facts=page['facts']*17),'ARCHIVE_PAGE_COUNT')]:
            self.reject(code,lambda:ArchiveVerifier(self.c,req,ack,1).accept(encode(changed)))
        self.reject('RETENTION_FRAME',lambda:ArchiveVerifier(self.c,req,ack,1).accept(b'x'*(r.MAX_FRAME+1)))
        self.l.db.execute('BEGIN')
        try:self.reject('ARCHIVE_TRANSACTION_ACTIVE',lambda:archive_page(self.l,self.h,req,ack,1))
        finally:self.l.db.rollback()

    def test_no_empty_checkpoint_or_post_completion_extension(self):
        req=r.query(self.c,'CHECKPOINT',0,b'q'*32,self.s);ack=self.send(req)
        self.reject('ARCHIVE_TARGET_NOT_RETIRED',lambda:ArchiveVerifier(self.c,req,ack,1))
        _,req,ack=self.history(1);v=ArchiveVerifier(self.c,req,ack,1);page=archive_page(self.l,self.h,req,ack,1)
        obj=decode(page);obj['facts']*=2
        self.reject('ARCHIVE_PAST_CHECKPOINT',lambda:v.accept(encode(obj)))
        v.accept(page);self.reject('ARCHIVE_ALREADY_COMPLETE',lambda:v.accept(page))

    def test_maximal_field_page_size(self):
        facts=[]
        for seq in range(r.MAX_SEQ-15,r.MAX_SEQ+1):
            facts.append(r.fact_bytes(dict(profile=r.PROFILE,context_hash=self.h,seq=seq,delivery=r.delivery_id(self.c,seq),
                action_digest=b'a'*32,descriptor_hash=b'd'*32,issued_at=r.MAX_TIME-60,expires_at=r.MAX_TIME,
                event_at=r.MAX_TIME-1,outcome='ACCEPTED',envelope_hash=b'e'*32),self.c))
        page=r.frame(encode(dict(profile=PROFILE,context_hash=self.h,checkpoint_hash=b'c'*32,first=r.MAX_SEQ-15,base_root=b'b'*32,facts=facts)))
        self.assertEqual(len(parse_page(page,self.c,b'c'*32)['facts']),16);self.assertLessEqual(len(page),8192)
        METRICS.update(maximum_fact_bytes=max(map(len,facts)),maximum_field_page_bytes=len(page),maximum_field_fixture='codec only; not a full uint64 history')

    def test_process_exit_during_archive_read_has_no_state_effect(self):
        facts,req,ack=self.history(1);image=self.l.state_image();head=self.sw.head(self.l.namespace,True)
        cfg=self.root/'archive-child.json';cfg.write_text(json.dumps(dict(sender=str(self.sp),witness=str(self.swp),request=req.hex(),ack=ack.hex())))
        for point in ['after_archive_roots','before_archive_fence','after_archive_read']:
            process=subprocess.run([sys.executable,__file__,'--child',str(cfg),point],capture_output=True,text=True,timeout=30)
            self.assertEqual(process.returncode,99,process.stderr);CUTS.append(point)
            self.assertEqual(self.l.state_image(),image);self.assertEqual(self.sw.head(self.l.namespace,True),head)
            v=ArchiveVerifier(self.c,req,ack,1);v.accept(archive_page(self.l,self.h,req,ack,1));self.assertEqual(v.result(),facts[0])


def source_hashes():
    pending=['test_retention_archive.py'];seen={}
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
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,actual_process_crash_scenarios=CUTS,
        crash_scenario_count=len(CUTS),metrics=METRICS,source_sha256=source_hashes(),python=platform.python_version(),cryptography=cryptography.__version__,
        archive_network_service=False,archive_availability_guarantee=False,production_nonrollback=False,
        scope='Actual retained sender archive after actual receiver logical GC, read-only current authority fencing, bounded unsigned pages and complete-prefix verification against pinned receiver checkpoint. No new result delivery or public endpoint.')
    (HERE/'retention_archive_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
