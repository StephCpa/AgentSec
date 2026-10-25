import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from histogram_ledger import HistogramLedger, HISTOGRAM
from scheduled_ledger import ScheduledLedger
from dp_ledger import EPSILON_COST as E, DELTA_COST as D, Rejected

CRASHES=[]


def setup(path,limit=4,buckets=None,rows=None):
    buckets=['a','b','c','d'] if buckets is None else buckets
    rows=[1,2,0] if rows is None else rows
    l=HistogramLedger.create(path,clock=lambda:100)
    l.provision_domain('t','domain',len(rows),limit*E,limit*D)
    l.authorize_root('t','domain','root','agent','reader',expires_at=1000)
    l.install_catalog('t','domain','cat',buckets)
    l.install_histogram_snapshot('t','domain','hist','cat',rows)
    l.install_snapshot('t','domain','count',[int(x!=0) for x in rows])
    return l


def reserve(l,oid='h',hist=True,root='root',actor='agent',fault=lambda p:None):
    if hist:return l.reserve_histogram('t',oid,root,'reader','domain','hist','cat',actor,fault)
    return l.reserve_count('t',oid,root,'reader','domain','count',actor,fault)


def tick(l,command=None,fault=lambda p:None):
    current=l.db.execute('SELECT tick FROM schedulers').fetchone()[0]
    return l.advance('t','domain','tick'+str(current+1),current,command,fault)


def child(path,point):
    l=HistogramLedger(path,clock=lambda:100)
    def fault(p):
        if p==point:os._exit(93)
    if 'reserve' in point:reserve(l,fault=fault)
    else:tick(l,fault=fault)
    raise RuntimeError('fault not reached')


class HistogramLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'db';self.l=setup(self.path)
    def tearDown(self):
        self.assertEqual(self.l.audit(),[]);self.l.close();self.tmp.cleanup()
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()
    def job(self,oid='h',l=None):
        return (l or self.l).db.execute('SELECT * FROM jobs WHERE operation_id=?',(oid,)).fetchone()
    def finish(self,l=None):
        l=l or self.l
        for _ in range(20000):
            if not l.db.execute('SELECT 1 FROM jobs WHERE publication IS NULL').fetchone():return
            tick(l)
        self.fail('bounded work did not finish')
    def balances(self,l=None):
        return {r['id']:tuple(r[k] for k in ('free','reserved','spent')) for r in (l or self.l).db.execute('SELECT * FROM accounts')}
    def events(self,l=None):
        return [e for e in (l or self.l).journal_internal('t','domain') if e['kind']!='CONTROL_ACK']

    def test_mixed_queries_share_domain_accounts_and_cost_once_per_vector(self):
        reserve(self.l);reserve(self.l,'c',False)
        self.assertEqual(self.balances(),{'domain:epsilon':(2*E,2*E,0),'domain:delta':(2*D,2*D,0)})
        tick(self.l);tick(self.l)
        expected={oid:self.l.compute_internal('t',oid) for oid in ('h','c')}
        self.finish()
        self.assertEqual(self.balances(),{'domain:epsilon':(2*E,0,2*E),'domain:delta':(2*D,0,2*D)})
        self.assertEqual(self.job()['work'],337);self.assertEqual(self.job('c')['work'],85)
        self.assertEqual([(e['tick'],e['subject']) for e in self.events()],[(422,'h'),(422,'c')])
        for oid in ('h','c'):
            self.assertEqual(self.l.op('t',oid)['result'],expected[oid])
            self.l.admit_delivery('t',oid,'reader','ticket'+oid,'gw','session')
            self.assertEqual(self.l.emit('t','ticket'+oid,'reader','gw','session'),expected[oid])
        self.assertEqual(len(expected['h']),32)

    def test_full_random_tape_is_durable_before_any_private_read(self):
        reserve(self.l)
        def abort(p):
            if p=='before_tick_commit':raise RuntimeError('abort')
        with patch.object(self.l,'open_snapshot',side_effect=AssertionError('early read')):
            with self.assertRaisesRegex(RuntimeError,'abort'):tick(self.l,fault=abort)
            self.assertIsNone(self.l.op('t','h')['seed']);tick(self.l)
        tape=self.l.op('t','h')['seed'];self.assertEqual(len(tape),40)
        original=self.l.open_snapshot
        def observer(*args):
            db=sqlite3.connect(str(self.path))
            try:self.assertEqual(db.execute("SELECT state,seed FROM operations WHERE id='h'").fetchone(),('STARTED',tape))
            finally:db.close()
            return original(*args)
        with patch.object(self.l,'open_snapshot',side_effect=observer):tick(self.l)

    def test_partial_bucket_completion_never_commits_or_releases(self):
        reserve(self.l)
        for _ in range(85):tick(self.l)
        self.assertEqual(self.job()['pc'],85)
        op=self.l.op('t','h');self.assertEqual(op['state'],'STARTED');self.assertIsNone(op['result']);self.assertIsNone(op['result_digest'])
        self.assertEqual(self.events(),[])
        self.assertEqual(self.balances()['domain:epsilon'],(3*E,E,0))
        self.reject('PUBLICATION_PENDING_OR_WITHHELD',lambda:self.l.admit_delivery('t','h','reader','d','g','s'))
        self.finish();self.assertEqual(self.events()[0]['tick'],337)

    def test_restart_after_each_bucket_preserves_full_tape_and_state(self):
        reserve(self.l);tick(self.l);expected=self.l.compute_internal('t','h');tape=self.l.op('t','h')['seed']
        for target in (32,85,169,253):
            while self.job()['pc']<target:tick(self.l)
            state=dict(self.job());self.l.close();self.l=HistogramLedger(self.path,clock=lambda:100)
            self.assertEqual(dict(self.job()),state);self.assertEqual(self.l.op('t','h')['seed'],tape)
        with patch('histogram_ledger.fresh_tape',side_effect=AssertionError('reseed')):self.finish()
        self.assertEqual(self.l.op('t','h')['result'],expected)

    def test_maximum_64_bucket_width_and_offsets_match_independent_kernel(self):
        l=setup(Path(self.tmp.name)/'max',buckets=['b'+str(i) for i in range(64)],rows=[64])
        try:
            reserve(l);tick(l);self.assertEqual(len(l.op('t','h')['seed']),640)
            expected=l.compute_internal('t','h');self.finish(l)
            self.assertEqual(l.op('t','h')['result'],expected);self.assertEqual(len(expected),512)
            self.assertEqual(self.job(l=l)['work'],5249);self.assertEqual(l.audit(),[])
        finally:l.close()

    def test_cancel_before_and_after_start_has_correct_accounting_and_dummy_work(self):
        for started in (False,True):
            l=setup(Path(self.tmp.name)/('cancel'+str(started)))
            try:
                reserve(l)
                if started:tick(l)
                tick(l,{'kind':'cancel','operation':'h','actor':'agent'})
                self.assertEqual(l.op('t','h')['state'],'BURNED' if started else 'CANCELED')
                self.finish(l);self.assertEqual([(e['tick'],e['kind']) for e in self.events(l)],[(337,'WITHHELD')])
                self.assertEqual(self.balances(l)['domain:epsilon'],(3*E,0,E) if started else (4*E,0,0))
                self.assertIsNone(l.op('t','h')['result']);self.assertEqual(l.audit(),[])
            finally:l.close()

    def test_revocation_and_expiry_withhold_complete_vector_without_refund(self):
        for mode in ('revoke','expire'):
            l=setup(Path(self.tmp.name)/mode)
            try:
                reserve(l);tick(l);tape=l.op('t','h')['seed']
                if mode=='revoke':tick(l,{'kind':'revoke','root':'root','actor':'agent'})
                else:l.clock=lambda:1000
                self.finish(l);self.assertEqual(l.op('t','h')['state'],'COMMITTED')
                self.assertEqual(l.op('t','h')['seed'],tape);self.assertEqual(self.events(l)[0]['kind'],'WITHHELD')
                self.assertEqual(self.balances(l)['domain:delta'],(3*D,0,D));self.assertEqual(l.audit(),[])
            finally:l.close()

    def test_catalog_is_immutable_and_does_not_create_budget(self):
        before=self.balances()
        with self.assertRaises(sqlite3.IntegrityError):self.l.install_catalog('t','domain','cat',['changed'])
        self.l.install_catalog('t','domain','other',['b','a'])
        self.assertEqual(self.balances(),before)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM accounts').fetchone()[0],2)
        with self.assertRaises(sqlite3.IntegrityError):self.l.provision_domain('t','domain',3,99*E,99*D)
        self.assertEqual(self.balances(),before)

    def test_new_catalog_after_spending_preserves_history_and_exhausts_same_budget(self):
        l=setup(Path(self.tmp.name)/'history',limit=2)
        try:
            reserve(l,'c',False);self.finish(l)
            before=self.balances(l)
            l.install_catalog('t','domain','later',['z','x'])
            l.install_histogram_snapshot('t','domain','later','later',[2,1,0])
            self.assertEqual(self.balances(l),before)
            l.reserve_histogram('t','h','root','reader','domain','later','later','agent')
            self.finish(l)
            self.assertEqual(self.balances(l)['domain:epsilon'],(0,0,2*E))
            self.assertEqual(self.balances(l)['domain:delta'],(0,0,2*D))
            self.reject('BUDGET_EXHAUSTED',lambda:reserve(l,'third'))
            self.assertEqual(l.db.execute('SELECT COUNT(*) FROM accounts').fetchone()[0],2)
            self.assertEqual(l.audit(),[])
        finally:l.close()

    def test_snapshot_type_and_catalog_cannot_be_confused(self):
        self.reject('SNAPSHOT_MECHANISM_MISMATCH',lambda:self.l.reserve_count('t','bad','root','reader','domain','hist','agent'))
        self.reject('SNAPSHOT_MECHANISM_MISMATCH',lambda:self.l.reserve_histogram('t','bad','root','reader','domain','count','cat','agent'))
        self.l.install_catalog('t','domain','other',['d','c','b','a'])
        self.reject('SNAPSHOT_CATALOG_MISMATCH',lambda:self.l.reserve_histogram('t','bad','root','reader','domain','hist','other','agent'))
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],0)

    def test_action_binds_public_shape_catalog_digest_and_registered_cost(self):
        reserve(self.l);base=json.loads(self.l.op('t','h')['action'])
        changes={'bucket_count':True,'capacity':4,'k':39,'codec':'wrong','catalog_digest':'00','mechanism':'unknown','accountant':'wrong'}
        for k,v in changes.items():
            action=json.loads(json.dumps(base));action['id']='bad';action['parameters'][k]=v
            self.reject('PROFILE_MISMATCH',lambda:self.l.reserve(action,'agent'))
        action=json.loads(json.dumps(base));action['id']='bad';action['costs']['domain:epsilon']=1
        self.reject('REGISTERED_COST_MISMATCH',lambda:self.l.reserve(action,'agent'))
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],1)

    def test_operation_id_cannot_switch_mechanism_and_retries_do_not_double_charge(self):
        first=reserve(self.l);self.assertEqual(reserve(self.l),first)
        self.reject('ACTION_CONFLICT',lambda:reserve(self.l,'h',False))
        self.assertEqual(self.balances()['domain:epsilon'],(3*E,E,0))
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],1)

    def test_profiles_cannot_silently_open_or_upgrade_each_others_database(self):
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:ScheduledLedger(self.path))
        path=Path(self.tmp.name)/'old';old=ScheduledLedger.create(path);old.close()
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:HistogramLedger.create(path))

    def test_epsilon_and_delta_both_gate_atomic_registration(self):
        for field in ('epsilon','delta'):
            l=setup(Path(self.tmp.name)/field,limit=1)
            try:
                with l.tx():
                    amount=E if field=='epsilon' else D
                    l.db.execute('UPDATE accounts SET total=?,free=? WHERE id=?',(amount-1,amount-1,'domain:'+field))
                self.reject('BUDGET_EXHAUSTED',lambda:reserve(l))
                self.assertEqual(l.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],0)
                self.assertEqual(l.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0)
                self.assertEqual(l.db.execute('SELECT COUNT(*) FROM charges').fetchone()[0],0);self.assertEqual(l.audit(),[])
            finally:l.close()

    def test_multiagent_count_histogram_budget_race_has_one_winner(self):
        path=Path(self.tmp.name)/'race';l=setup(path,limit=1)
        l.authorize_root('t','domain','root2','agent2','reader',expires_at=1000);l.close();gate=threading.Barrier(8)
        def attempt(i):
            x=HistogramLedger(path,clock=lambda:100)
            try:
                gate.wait();reserve(x,'op'+str(i),i%2==0,'root2' if i%2 else 'root','agent2' if i%2 else 'agent');return 'ok'
            except Rejected as e:return str(e)
            finally:x.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:outcomes=list(pool.map(attempt,range(8)))
        self.assertEqual(outcomes.count('ok'),1);self.assertEqual(outcomes.count('BUDGET_EXHAUSTED'),7)
        l=HistogramLedger(path,clock=lambda:100)
        try:
            self.finish(l);self.assertEqual(self.balances(l)['domain:epsilon'],(0,0,E));self.assertEqual(l.audit(),[])
        finally:l.close()

    def test_tick_replay_and_pause_do_not_reseed_or_advance_twice(self):
        reserve(self.l);response=tick(self.l);tape=self.l.op('t','h')['seed']
        self.assertEqual(self.l.advance('t','domain','tick1',0),response)
        self.assertEqual(self.job()['pc'],1)
        tick(self.l,{'kind':'pause'});self.assertEqual(self.job()['pc'],1)
        self.assertEqual(self.l.op('t','h')['seed'],tape)
        self.finish();self.assertEqual(self.events()[0]['tick'],338)

    def test_private_categories_and_noise_do_not_change_public_journal(self):
        journals=[]
        for i,rows in enumerate(([0,0,0],[1,2,3],[4,4,4])):
            l=setup(Path(self.tmp.name)/('rows'+str(i)),rows=rows)
            try:
                reserve(l);reserve(l,'c',False)
                with patch('histogram_ledger.fresh_tape',return_value=bytes([0 if i==0 else 255])*40):tick(l)
                self.finish(l);journals.append(l.journal_internal('t','domain'));self.assertEqual(l.audit(),[])
            finally:l.close()
        self.assertTrue(all(j==journals[0] for j in journals))

    def test_invalid_catalog_and_snapshot_inputs_leave_no_registration(self):
        for buckets in ([],['a','a'],[''],['x'*65],[1],['x'+str(i) for i in range(65)]):
            self.reject('INVALID_CATALOG',lambda:self.l.install_catalog('t','domain','bad',buckets))
        for rows in ([1,2],[1,2,5],[True,0,0],[-1,0,0]):
            self.reject('INVALID_SNAPSHOT',lambda:self.l.install_histogram_snapshot('t','domain','bad','cat',rows))
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM histogram_snapshots').fetchone()[0],1)

    def test_direct_execution_bypass_is_rejected(self):
        reserve(self.l)
        for method in ('execute_histogram','execute_count','claim','commit'):
            self.reject('SCHEDULER_REQUIRED',lambda:getattr(self.l,method)('t','h',1))

    def test_eleven_real_process_crash_scenarios_preserve_full_vector_and_charges(self):
        scenarios=[('before_reserve_commit',0),('after_reserve_commit',0),('after_scheduled_claim',0),
                   ('after_work_step',1),('after_work_step',84),('after_scheduled_result_write',336),
                   ('after_account_settle',336),('after_publication_write',336),('before_tick_commit',336),
                   ('after_tick_commit',336),('after_control_write',169)]
        for i,(point,pc) in enumerate(scenarios):
            with self.subTest(point=point,pc=pc):
                path=Path(self.tmp.name)/('crash'+str(i));l=setup(path)
                if 'reserve' not in point:reserve(l)
                for _ in range(pc):tick(l)
                tape=l.op('t','h')['seed'] if pc else None
                before=dict(self.job(l=l)) if pc else None
                l.close();proc=subprocess.run([sys.executable,__file__,'--crash',str(path),point],capture_output=True,timeout=30)
                self.assertEqual(proc.returncode,93,proc.stderr.decode())
                l=HistogramLedger(path,clock=lambda:100)
                try:
                    self.assertEqual(l.db.execute('PRAGMA integrity_check').fetchone()[0],'ok');self.assertEqual(l.audit(),[])
                    if point=='before_reserve_commit':
                        self.assertEqual(l.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0);reserve(l)
                    if pc:
                        self.assertEqual(l.op('t','h')['seed'],tape)
                        if point!='after_tick_commit':self.assertEqual(dict(self.job(l=l)),before)
                    self.finish(l);self.assertEqual(l.op('t','h')['result'],l.compute_internal('t','h'))
                    self.assertEqual([(e['tick'],e['kind']) for e in self.events(l)],[(337,'RELEASE')])
                    self.assertEqual(self.balances(l)['domain:epsilon'],(3*E,0,E));self.assertEqual(l.audit(),[])
                finally:l.close()
                CRASHES.append({'point':point,'preceding_pc':pc})


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash':child(sys.argv[2],sys.argv[3])
    else:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(HistogramLedgerTests)
        result=unittest.TextTestRunner(verbosity=2).run(suite);root=Path(__file__).resolve().parent
        names=('ledger.py','dp_ledger.py','scheduled_ledger.py','histogram_ledger.py','test_histogram_ledger.py','../histogram_kernel.py','../fixed_work_model.py')
        report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,actual_process_crash_scenarios=CRASHES,
                    crash_scenario_count=len(CRASHES),source_sha256={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names},
                    failures=[(str(t),m) for t,m in result.failures],errors=[(str(t),m) for t,m in result.errors],
                    python_version=sys.version,sqlite_version=sqlite3.sqlite_version,
                    scope='Synthetic plaintext mixed-mechanism accounting and durable logical scheduling; no signed delegated histogram, encrypted vector state, witness or authenticated vector network integration')
        (root/'histogram_ledger_test_results.json').write_text(json.dumps(report,indent=2)+'\n');sys.exit(0 if result.wasSuccessful() else 1)
