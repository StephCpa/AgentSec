import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import cryptography

from contribution_delivery import ContributionRetentionSender, TLSContributionRetentionSender
from contribution_ingestion import ContributionLedger
from contribution_scenario import run_contribution_scenario, USERS, RECORDS
from dp_ledger import EPSILON_COST as E, DELTA_COST as D
from ledger import Rejected
from p2_scenario import writer_report
from retention_sender import RetentionSender, u64
from retention_recipient import RetentionRecipient
from retention_archive import archive_page, ArchiveVerifier
from witnessed_ledger import ReferenceWitness
from test_encrypted_mixed_ledger import vault, register
from test_mixed_delegated_ledger import KEYS, finish
from test_witness_transport import public
from test_retention_sender import context
from test_retention_recipient import recipient_vault
import retention_wire as r
import retention_delivery as d

HERE = Path(__file__).resolve().parent
CUTS = []
METRICS = {}


def provision(l):
    l.provision_domain('t','domain',3,4*E,4*D)
    l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
    l.install_catalog('t','domain','cat',['one','two','three','four'])
    l.bind_contribution_domain('t','domain',b'L'*32,USERS)
    l.ingest_pair('t','domain','batch','cat','count','hist',RECORDS)
    for name,key in KEYS.items():
        l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',public(key))
    l.bind_root_authority('t','root',b'authority')
    register(l,'hist_op',True);register(l,'count_op',False);finish(l)
    c,_,_=context();l.register_context(c)
    assert l.audit()==[]
    return l


def child(path, wp, operation, point):
    c,s,_=context();h=r.context_hash(c)
    def fault(p):
        if p==point:os._exit(95)
    w=ReferenceWitness(wp)
    l=ContributionRetentionSender(path,clock=lambda:100,vault=vault(),witness=w,witness_fault=fault)
    if operation=='admit':l.admit_v2(h,'request','hist_op',fault=fault)
    elif operation=='prepare':l.prepare_envelope('t',r.delivery_id(c,1),s,fault)
    elif operation=='restore':l.recover_from_witness(fault)
    else:raise RuntimeError('bad operation')
    raise RuntimeError('cut not reached')


class CombinedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.templates=tempfile.TemporaryDirectory();root=Path(cls.templates.name)
        cls.template=root/'ledger';cls.wtemplate=root/'witness'
        w=ReferenceWitness(cls.wtemplate)
        l=provision(ContributionRetentionSender.create(cls.template,clock=lambda:100,vault=vault(),witness=w))
        l.close();w.close()
        cls.report,cls.inputs=run_contribution_scenario()
        (HERE/'contribution_scenario_results.json').write_text(json.dumps(cls.report,ensure_ascii=False,indent=2)+'\n')

    @classmethod
    def tearDownClass(cls):cls.templates.cleanup()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.lp=self.root/'ledger';self.wp=self.root/'witness'
        shutil.copyfile(self.template,self.lp);shutil.copyfile(self.wtemplate,self.wp)
        self.now=100;self.c,self.s,self.k=context();self.h=r.context_hash(self.c)
        self.w=ReferenceWitness(self.wp)
        self.l=ContributionRetentionSender(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w)
        self.rw=ReferenceWitness(self.root/'receiver-witness')
        self.i=RetentionRecipient.create(self.root/'receiver',context=self.c,vault=recipient_vault(),clock=lambda:self.now,witness=self.rw)

    def tearDown(self):
        self.l.close();self.i.close();self.w.close();self.rw.close();self.tmp.cleanup()

    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()

    def admit(self,oid='hist_op',key='request'):
        return self.l.admit_v2(self.h,key,oid)

    def deliver(self,oid='hist_op',key='request'):
        row=self.admit(oid,key);env=self.l.prepare_envelope('t',row['id'],self.s)
        req=d.attempt('DELIVERY',env,b'q'*32,self.c,self.s)
        ack=self.i.accept(req,self.c['sender_cert'],self.k)
        self.l.confirm('t',row['id'],req,ack)
        return row,env,req,ack

    def retire(self,target):
        offer=self.l.prepare_retirement(self.h,target,self.s)
        req=r.retire_attempt(offer,b'z'*32,self.c,self.s)
        ack=self.i.accept(req,self.c['sender_cert'],self.k)
        self.l.confirm_retirement(self.h,req,ack)
        return req,ack

    def test_full_network_scenario_starts_from_compiled_records(self):
        c=self.report['contribution']
        for name in ['paired_snapshots_verified','duplicate_records_clipped','private_roster_encrypted',
                     'witness_acceptance_local_rollback','stale_replica_fenced','exact_pair_restored_without_recompile','direct_import_disabled']:
            self.assertTrue(c[name])
        self.assertEqual(c['storage_profile'],'mtls-contribution-retention-v2')
        self.assertEqual(len(self.report['events']),9)
        self.assertEqual(self.report['randomness_draws'],{'analysis_count':1,'analysis_hist':1})
        self.assertEqual(self.report['network_requests']['delivery'],4)
        self.assertGreater(self.report['network_requests']['sender_witness'],0)
        self.assertGreater(self.report['network_requests']['receiver_witness'],0)
        self.assertEqual(self.report['budget']['checked_accounts'],10)
        self.assertFalse(self.report['full_p2_production_acceptance'])

    def test_writer_still_accepts_only_authenticated_envelopes(self):
        self.assertEqual(writer_report(**self.inputs),self.report['writer'])
        evidence=list(self.inputs['evidence'])
        evidence[0]=dict(evidence[0],raw_records=RECORDS)
        self.reject('WRITER_INPUT',lambda:writer_report(self.inputs['context'],evidence,self.inputs['expected_operations']))
        for user in USERS:self.assertNotIn(user.hex(),json.dumps(self.report))

    def test_combined_schema_and_no_profile_downgrade(self):
        tables={row[0] for row in self.l.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({'contribution_domains','contribution_batches','v2_outbox','v2_routes','v2_requests','v2_retire_offers'}<=tables)
        for cls in (ContributionLedger,RetentionSender):
            self.reject('STORAGE_PROFILE_MISMATCH',lambda:cls(self.lp,clock=lambda:100,vault=vault(),witness=self.w))
        self.reject('AUTHENTICATED_WITNESS_REQUIRED',lambda:TLSContributionRetentionSender(self.lp,clock=lambda:100,vault=vault(),witness=self.w))
        self.reject('CONTRIBUTION_INGESTION_REQUIRED',lambda:self.l.install_snapshot('t','domain','x',[1,1,1]))
        self.reject('V2_ADMISSION_REQUIRED',lambda:self.l.admit_delivery())
        self.reject('V2_SIGNED_DELIVERY_REQUIRED',lambda:self.l.emit())

    def test_compiled_snapshots_remain_paired_after_retirement_and_archive(self):
        first=self.deliver();self.deliver('count_op','count-request')
        req,ack=self.retire(2)
        self.assertEqual(self.i.live_facts(),[])
        v=ArchiveVerifier(self.c,req,ack,1);v.accept(archive_page(self.l,self.h,req,ack,1))
        self.assertEqual(v.result(),d.parse_receipt(first[3],first[2],self.c))
        self.assertEqual(self.l.private_roster('t','domain'),USERS)
        self.assertEqual(self.l.audit(),[]);self.assertEqual(self.i.audit(),[])
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM contribution_batches').fetchone()[0],1)

    def test_expired_terminal_path_does_not_decrypt_result_or_refund(self):
        row=self.admit();before=[tuple(x) for x in self.l.db.execute('SELECT * FROM accounts ORDER BY id')]
        self.now=160
        with patch.object(self.l,'op',side_effect=AssertionError('result read')),patch.object(self.l,'open_snapshot',side_effect=AssertionError('snapshot read')):
            ctl=self.l.prepare_terminal('t',row['id'],self.s)
        req=d.attempt('TERMINAL',ctl,b't'*32,self.c,self.s);ack=self.i.accept(req,self.c['sender_cert'],self.k)
        self.assertEqual(self.l.confirm('t',row['id'],req,ack),'CLOSED')
        self.assertEqual(before,[tuple(x) for x in self.l.db.execute('SELECT * FROM accounts ORDER BY id')])
        retire_req,retire_ack=self.retire(1)
        v=ArchiveVerifier(self.c,retire_req,retire_ack,1);v.accept(archive_page(self.l,self.h,retire_req,retire_ack,1))
        self.assertEqual(r.parse_fact(v.result(),self.c)['outcome'],'CLOSED')
        self.assertEqual(self.l.audit(),[])

    def test_recovery_checks_contribution_audit_with_valid_delivery_history(self):
        self.deliver();self.retire(1)
        with self.l.tx():
            raw=self.l.protect_snapshot('t','domain','count',[0,0,0])
            self.l.db.execute('UPDATE snapshots SET rows_json=? WHERE id=?',(raw,'count'))
        self.assertEqual(self.l.audit_v2(),[])
        self.reject('CONTRIBUTION_AUDIT_FAILED',lambda:ContributionRetentionSender.restore_new(self.root/'restored',clock=lambda:100,vault=vault(),witness=self.w))

    def test_recovery_checks_delivery_audit_with_valid_contributions(self):
        self.deliver()
        with self.l.tx():self.l.db.execute('UPDATE v2_routes SET confirmed_root=?',(b'x'*32,))
        self.l.audit_contributions()
        self.reject('V2_RECOVERY_AUDIT_FAILED',lambda:ContributionRetentionSender.restore_new(self.root/'restored',clock=lambda:100,vault=vault(),witness=self.w))

    def test_fresh_restore_keeps_inputs_outputs_and_retirement_evidence(self):
        self.deliver();req,ack=self.retire(1);image=self.l.state_image()
        with patch('contribution_ingestion.compile_contributions',side_effect=AssertionError('recompile')),patch.object(ContributionRetentionSender,'operation_randomness',side_effect=AssertionError('resample')):
            restored=ContributionRetentionSender.restore_new(self.root/'fresh',clock=lambda:100,vault=vault(),witness=self.w)
        try:
            self.assertEqual(restored.state_image(),image)
            self.assertEqual(restored.audit(),[])
            v=ArchiveVerifier(self.c,req,ack,1);v.accept(archive_page(restored,self.h,req,ack,1));self.assertTrue(v.complete)
        finally:restored.close()

    def test_reply_loss_after_preparation_recovers_same_envelope(self):
        row=self.admit();before=self.l.op('t','hist_op')['result']
        def fault(point):
            if point=='after_witness_accept':raise ConnectionError('lost')
        self.l.witness_fault=fault
        with self.assertRaises(ConnectionError):self.l.prepare_envelope('t',row['id'],self.s)
        self.l.witness_fault=lambda p:None
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:self.l.prepare_envelope('t',row['id'],self.s))
        self.l.recover_from_witness();persisted=self.l.open('envelope',self.l.outbox('t',row['id']))
        self.assertEqual(self.l.prepare_envelope('t',row['id'],self.s),persisted)
        self.assertEqual(d.parse_envelope(persisted,self.c)['result'],before)
        self.assertEqual(self.l.audit(),[])

    def test_actual_process_cuts_preserve_both_state_families(self):
        cases=[('admit','after_v2_ticket_write',False),('admit','after_witness_accept',True),
               ('admit','after_v2_admission_commit',True),('prepare','after_witness_accept',True),
               ('restore','after_recovery_delete',False),('restore','before_recovery_commit',False)]
        for operation,point,admitted in cases:
            with tempfile.TemporaryDirectory() as td:
                lp=Path(td)/'ledger';wp=Path(td)/'witness'
                shutil.copyfile(self.template,lp);shutil.copyfile(self.wtemplate,wp)
                w=ReferenceWitness(wp);l=ContributionRetentionSender(lp,clock=lambda:100,vault=vault(),witness=w)
                old_results={oid:(l.op('t',oid)['seed'],l.op('t',oid)['result']) for oid in ('count_op','hist_op')}
                if operation=='prepare':l.admit_v2(self.h,'request','hist_op')
                l.close()
                proc=subprocess.run([sys.executable,__file__,'--child',str(lp),str(wp),operation,point],capture_output=True,text=True,timeout=30)
                self.assertEqual(proc.returncode,95,proc.stderr)
                l=ContributionRetentionSender(lp,clock=lambda:100,vault=vault(),witness=w)
                try:
                    l.recover_from_witness()
                    self.assertEqual(l.db.execute('SELECT count(*) FROM v2_outbox').fetchone()[0],int(admitted))
                    self.assertEqual(l.db.execute('SELECT count(*) FROM snapshots').fetchone()[0],2)
                    self.assertEqual(l.private_roster('t','domain'),USERS)
                    for oid,pair in old_results.items():self.assertEqual((l.op('t',oid)['seed'],l.op('t',oid)['result']),pair)
                    self.assertEqual(l.audit(),[])
                finally:l.close();w.close()
                CUTS.append(dict(operation=operation,point=point))


def source_hashes():
    pending=['test_contribution_delivery.py'];seen={}
    while pending:
        name=pending.pop();path=HERE/name
        if not path.exists():path=HERE.parent/name
        key=str(path.relative_to(HERE.parent))
        if key in seen or not path.exists():continue
        raw=path.read_bytes();seen[key]=hashlib.sha256(raw).hexdigest()
        for node in ast.walk(ast.parse(raw)):
            mods=[x.name for x in node.names] if isinstance(node,ast.Import) else ([node.module] if isinstance(node,ast.ImportFrom) else [])
            pending.extend(mod.split('.')[0]+'.py' for mod in mods if mod)
    return seen


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':child(*sys.argv[2:]);raise SystemExit(1)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CombinedTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,source_sha256=source_hashes(),
        source_paths_relative_to='delivery root',actual_process_crash_scenarios=CUTS,crash_scenario_count=len(CUTS),
        scenario_report='contribution_scenario_results.json',
        scenario_report_sha256=hashlib.sha256((HERE/'contribution_scenario_results.json').read_bytes()).hexdigest(),
        python=platform.python_version(),cryptography=cryptography.__version__,
        scope='Compiled synthetic user records through full loopback mTLS workflow; additional local combined-profile terminal/retirement/archive/recovery audit and actual process cuts. No real identity/classifier or production observation guarantee.')
    (HERE/'contribution_delivery_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
