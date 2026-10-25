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

from dp_ledger import DPLedger, Rejected, EPSILON_COST as E, DELTA_COST as D

CRASH_CUTS = []


def provision(path, epsilon=2*E, delta=2*D):
    ledger = DPLedger.create(path)
    ledger.provision_domain('t','domain',4,epsilon,delta)
    ledger.authorize_root('t','domain','root','agent','reader')
    ledger.install_snapshot('t','domain','snap',[0,1,1,0])
    return ledger


def reserve(ledger, oid='a', root='root', snapshot='snap', fault=lambda point: None):
    return ledger.reserve_count('t',oid,root,'reader','domain',snapshot,'agent',fault)


def crash_child(path, point):
    ledger = DPLedger(path)
    def fault(here):
        if here == point:
            os._exit(92)
    if 'reserve' in point:
        reserve(ledger,fault=fault)
    elif 'claim' in point:
        ledger.claim('t','a','agent',fault)
    else:
        ledger.execute_count('t','a',ledger.op('t','a')['generation'],fault)
    raise RuntimeError('cut not reached')


class TypedLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'typed.sqlite'
        self.l = provision(self.path)

    def tearDown(self):
        self.assertEqual(self.l.audit(),[])
        self.l.close()
        self.tmp.cleanup()

    def reject(self, code, call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):
            call()

    def balances(self, ledger=None):
        ledger = ledger or self.l
        return {r['id'].split(':')[1]:tuple(r[x] for x in ('free','reserved','spent'))
                for r in ledger.db.execute("SELECT * FROM accounts WHERE tenant='t'")}

    def assert_both(self, free, held, spent, ledger=None):
        self.assertEqual(self.balances(ledger),{'epsilon':(free*E,held*E,spent*E),'delta':(free*D,held*D,spent*D)})

    def start(self, oid='a'):
        reserve(self.l,oid)
        return self.l.claim('t',oid,'agent')

    def test_registered_costs_exact_retry_and_parameter_binding(self):
        a=reserve(self.l)
        body=json.loads(self.l.op('t','a')['action'])
        self.assertEqual(body['costs'],{'domain:epsilon':E,'domain:delta':D})
        reserve(self.l)
        self.assert_both(1,1,0)
        self.l.install_snapshot('t','domain','another',[1,0,0,0])
        self.reject('ACTION_CONFLICT',lambda:reserve(self.l,snapshot='another'))

    def test_registration_never_exposes_seed_output_or_private_readiness(self):
        original=reserve(self.l)
        self.assertEqual(set(original),{'operation_id','action_digest','registration'})
        self.l.claim('t','a','agent')
        self.assertEqual(reserve(self.l),original)
        self.l.execute_count('t','a',1)
        self.assertEqual(reserve(self.l),original)
        self.assert_both(1,0,1)

    def test_request_cannot_omit_undercharge_or_redirect_dimensions(self):
        reserve(self.l)
        a=json.loads(self.l.op('t','a')['action']); a['id']='b'
        for costs in ({'domain:epsilon':E},{'domain:delta':D},
                      {'domain:epsilon':E-1,'domain:delta':D},
                      {'domain:epsilon':E,'domain:delta':D-1},
                      {'other:epsilon':E,'other:delta':D}):
            changed=dict(a,costs=costs)
            self.reject('REGISTERED_COST_MISMATCH',lambda:self.l.reserve(changed,'agent'))
        self.assert_both(1,1,0)

    def test_profile_and_mechanism_downgrade_rejected(self):
        reserve(self.l)
        a=json.loads(self.l.op('t','a')['action']); a['id']='b'
        for key,value in (('accountant','rdp_alpha16'),('mechanism','mock-v1')):
            changed=json.loads(json.dumps(a)); changed['parameters'][key]=value
            self.reject('PROFILE_MISMATCH',lambda:self.l.reserve(changed,'agent'))
        self.reject('TYPED_PROVISION_REQUIRED',lambda:self.l.provision('t','x','a','b',{}))
        self.assert_both(1,1,0)

    def test_root_cannot_access_another_domain_even_with_valid_accounts(self):
        self.l.provision_domain('t','other',4,2*E,2*D)
        self.l.install_snapshot('t','other','snap',[1,1,1,1])
        self.reject('UNAUTHORIZED_DOMAIN',lambda:self.l.reserve_count('t','a','root','reader','other','snap','agent'))
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],0)

    def test_new_root_and_snapshot_share_existing_domain_budget(self):
        self.l.authorize_root('t','domain','root2','agent','reader')
        self.l.install_snapshot('t','domain','snap2',[0,0,0,1])
        reserve(self.l,'a'); reserve(self.l,'b',root='root2',snapshot='snap2')
        self.reject('BUDGET_EXHAUSTED',lambda:reserve(self.l,'c',root='root2'))
        self.assert_both(0,2,0)
        with self.assertRaises(sqlite3.IntegrityError):
            self.l.provision_domain('t','domain',4,20*E,20*D)
        with self.assertRaises(sqlite3.IntegrityError):
            self.l.install_snapshot('t','domain','snap',[1,1,1,1])
        self.assert_both(0,2,0)

    def test_either_dimension_exhaustion_rolls_back_both(self):
        for epsilon,delta in ((E-1,2*D),(2*E,D-1)):
            with self.subTest(epsilon=epsilon,delta=delta):
                path=Path(self.tmp.name)/str(epsilon)
                local=provision(path,epsilon,delta)
                self.reject('BUDGET_EXHAUSTED',lambda:reserve(local))
                self.assertEqual(self.balances(local),{'epsilon':(epsilon,0,0),'delta':(delta,0,0)})
                self.assertEqual(local.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],0)
                self.assertEqual(local.audit(),[]); local.close()

    def test_prestart_refund_and_started_burn_cover_both_dimensions(self):
        reserve(self.l)
        self.reject('INVALID_STATE',lambda:self.l.compute_internal('t','a'))
        self.l.cancel('t','a','agent'); self.assert_both(2,0,0)
        self.assertEqual(reserve(self.l)['registration'],'REGISTERED')
        self.assertEqual(self.l.op('t','a')['state'],'CANCELED')
        op=self.start('b')
        self.l.cancel('t','b','agent'); self.assert_both(1,0,1)
        self.reject('INVALID_STATE',lambda:self.l.execute_count('t','b',op['generation']))

    def test_recovery_uses_same_bits_and_fences_old_worker(self):
        original=self.start()
        expected=self.l.compute_internal('t','a')
        self.l.close(); self.l=DPLedger(self.path)
        recovered=self.l.recover('t','a',original['generation'])
        self.assertEqual(recovered['seed'],original['seed'])
        self.assertEqual(self.l.compute_internal('t','a'),expected)
        self.reject('STALE_WORKER',lambda:self.l.execute_count('t','a',original['generation']))
        self.l.execute_count('t','a',recovered['generation'])
        self.l.execute_count('t','a',recovered['generation'])
        self.assertEqual(self.l.op('t','a')['result'],expected)
        self.assertEqual(len(expected),8); self.assertLessEqual(int.from_bytes(expected,'big'),4)
        self.assert_both(1,0,1)

    def test_same_query_new_operation_draws_independent_persisted_seed(self):
        a=self.start('a'); b=self.start('b')
        # Seed distinctness is diagnostic only, not a randomness security proof.
        self.assertNotEqual(a['seed'],b['seed'])
        self.assertEqual(self.l.claim('t','a','agent')['seed'],a['seed'])
        self.assert_both(0,2,0)

    def test_revocation_allows_prior_computation_but_blocks_new_delivery(self):
        self.start(); self.l.revoke('t','root')
        self.l.execute_count('t','a',1)
        self.reject('REVOKED',lambda:self.l.admit_delivery('t','a','reader','ticket','gw','sess'))
        self.assert_both(1,0,1)

    def test_committed_output_delivers_identically_without_additional_cost(self):
        self.start(); self.l.execute_count('t','a',1)
        expected=self.l.op('t','a')['result']
        self.l.admit_delivery('t','a','reader','ticket','gw','sess')
        for _ in range(3):
            self.assertEqual(self.l.emit('t','ticket','reader','gw','sess'),expected)
        self.assert_both(1,0,1)

    def test_snapshot_and_parameter_validation(self):
        for rows in ([0,1],[0,1,1,2],[0,1,1,True]):
            self.reject('INVALID_SNAPSHOT',lambda:self.l.install_snapshot('t','domain','bad',rows))
        self.reject('UNKNOWN_SNAPSHOT',lambda:reserve(self.l,snapshot='absent'))
        self.reject('INVALID_ID',lambda:reserve(self.l,oid='bad:id'))
        self.assert_both(2,0,0)

    def test_typed_audit_detects_balanced_missing_delta_charge(self):
        reserve(self.l)
        # Simulate an otherwise balanced cross-table defect, then restore fixture.
        self.l.db.execute('BEGIN IMMEDIATE')
        try:
            self.l.db.execute("DELETE FROM charges WHERE account_id='domain:delta'")
            self.l.db.execute("UPDATE accounts SET free=free+?,reserved=reserved-? WHERE id='domain:delta'",(D,D))
            self.assertIn('TYPED_CHARGE_BINDING',self.l.audit())
        finally:
            self.l.db.rollback()

    def concurrent_reserve(self, same_id):
        gate=threading.Barrier(8)
        def attempt(i):
            local=DPLedger(self.path)
            try:
                gate.wait(); reserve(local,'a' if same_id else str(i)); return 'accepted'
            except Rejected as e:
                return str(e)
            finally:
                local.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            return list(pool.map(attempt,range(8)))

    def test_concurrent_different_operations_cannot_overspend_either_dimension(self):
        outcomes=self.concurrent_reserve(False)
        self.assertEqual(outcomes.count('accepted'),2)
        self.assertEqual(outcomes.count('BUDGET_EXHAUSTED'),6)
        self.assert_both(0,2,0)

    def test_concurrent_same_operation_debits_both_dimensions_once(self):
        self.assertEqual(self.concurrent_reserve(True),['accepted']*8)
        self.assert_both(1,1,0)

    def test_actual_process_death_at_nine_typed_cuts(self):
        points=('after_account_reserve','before_reserve_commit','after_reserve_commit',
                'before_claim_commit','after_claim_commit','after_result_write',
                'after_account_settle','before_result_commit','after_result_commit')
        for point in points:
            with self.subTest(point=point):
                path=Path(self.tmp.name)/(point+'.sqlite'); local=provision(path)
                seed=expected=None
                if 'reserve' not in point:
                    reserve(local)
                if 'reserve' not in point and 'claim' not in point:
                    seed=local.claim('t','a','agent')['seed']; expected=local.compute_internal('t','a')
                local.close()
                proc=subprocess.run([sys.executable,__file__,'--crash',str(path),point],capture_output=True,timeout=30)
                self.assertEqual(proc.returncode,92,proc.stderr.decode())
                local=DPLedger(path)
                self.assertEqual(local.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                self.assertEqual(local.audit(),[])
                op=local.db.execute('SELECT * FROM operations').fetchone()
                if point in ('after_account_reserve','before_reserve_commit'):
                    self.assertIsNone(op); self.assert_both(2,0,0,local)
                elif point in ('after_reserve_commit','before_claim_commit'):
                    self.assertEqual(op['state'],'RESERVED'); self.assert_both(1,1,0,local)
                else:
                    self.assertEqual(op['state'],'COMMITTED' if point=='after_result_commit' else 'STARTED')
                    if seed is not None:
                        self.assertEqual(op['seed'],seed)
                        self.assertEqual(local.compute_internal('t','a'),expected)
                    if op['state']=='STARTED':
                        fixed_seed=op['seed']
                        recovered=local.recover('t','a',op['generation'])
                        self.assertEqual(recovered['seed'],fixed_seed)
                        local.execute_count('t','a',recovered['generation'])
                    if expected is not None:
                        self.assertEqual(local.op('t','a')['result'],expected)
                    self.assert_both(1,0,1,local)
                self.assertEqual(local.audit(),[]); local.close(); CRASH_CUTS.append(point)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash':
        crash_child(sys.argv[2],sys.argv[3])
    else:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(TypedLedgerTests)
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        root=Path(__file__).resolve().parent
        sources=['ledger.py','dp_ledger.py','test_dp_ledger.py','../fixed_work_model.py']
        report={'passed':result.wasSuccessful(),'test_methods':result.testsRun,
                'actual_process_crash_cuts':CRASH_CUTS,'crash_cut_count':len(CRASH_CUTS),
                'python_version':sys.version,'sqlite_version':sqlite3.sqlite_version,
                'source_sha256':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in sources},
                'failures':[(str(t),msg) for t,msg in result.failures],
                'errors':[(str(t),msg) for t,msg in result.errors],
                'scope':'Synthetic typed domain accounts, fixed-bit count execution and replay, internal L3; no public scheduler or production cryptographic guarantee'}
        (root/'dp_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
        sys.exit(0 if result.wasSuccessful() else 1)
