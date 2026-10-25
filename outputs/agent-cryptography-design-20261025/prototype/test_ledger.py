import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import threading
import unittest

from ledger import Ledger, Rejected


COMPLETED_CRASH_CUTS = []


def action(oid='a', tenant='t', costs=None):
    return dict(tenant=tenant,id=oid,root='root',recipient='reader',
                parameters={'snapshot':'synthetic-v1','mechanism':'mock-v1'},
                costs=costs if costs is not None else {'privacy':1,'calls':1})


def crash_child(path, point):
    ledger = Ledger(path)
    def fault(here):
        if here == point:
            os._exit(91)
    if 'delivery' in point:
        ledger.admit_delivery('t','a','reader','ticket','gateway-a','session-a',fault=fault)
    elif 'emit' in point:
        ledger.emit('t','ticket','reader','gateway-a','session-a',fault=fault)
    elif 'reserve' in point:
        ledger.reserve(action(), 'agent', fault)
    elif 'claim' in point:
        ledger.claim('t','a','agent',fault)
    else:
        op = ledger.op('t','a')
        ledger.commit('t','a',op['generation'],op['digest'],b'synthetic-output',fault)
    raise RuntimeError('crash point not reached')


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'ledger.sqlite'
        self.l = Ledger.create(self.path)
        self.l.provision('t','root','agent','reader',{'privacy':2,'calls':2})

    def tearDown(self):
        self.assertEqual(self.l.audit(), [])
        self.l.close()
        self.tmp.cleanup()

    def balance(self, name='privacy'):
        return tuple(self.l.db.execute('SELECT free,reserved,spent FROM accounts WHERE tenant=? AND id=?',('t',name)).fetchone())

    def started(self, oid='a'):
        self.l.reserve(action(oid), 'agent')
        return self.l.claim('t',oid,'agent')

    def committed(self, oid='a'):
        op = self.started(oid)
        self.l.commit('t',oid,op['generation'],op['digest'],b'synthetic-output')
        return op

    def rejects(self, code, call):
        with self.assertRaisesRegex(Rejected, '^'+code+'$'):
            call()

    def test_multi_account_insufficient_rolls_back_everything(self):
        self.rejects('BUDGET_EXHAUSTED',lambda:self.l.reserve(action(costs={'calls':1,'privacy':3}),'agent'))
        self.assertEqual(self.balance('calls'),(2,0,0))
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],0)

    def test_exact_retry_and_changed_action(self):
        self.l.reserve(action(),'agent')
        self.l.reserve(action(),'agent')
        self.assertEqual(self.balance(),(1,1,0))
        changed=action(); changed['parameters']['snapshot']='synthetic-v2'
        self.rejects('ACTION_CONFLICT',lambda:self.l.reserve(changed,'agent'))

    def test_negative_boolean_and_zero_costs(self):
        for cost in (-1,0,True,1.5,2**63):
            self.rejects('INVALID_COST',lambda:self.l.reserve(action(costs={'privacy':cost}),'agent'))

    def test_wrong_actor_and_recipient(self):
        self.rejects('UNAUTHORIZED',lambda:self.l.reserve(action(),'intruder'))
        changed=action(); changed['recipient']='intruder'
        self.rejects('UNAUTHORIZED',lambda:self.l.reserve(changed,'agent'))

    def test_cross_tenant_namespace_and_output(self):
        self.l.provision('other','root','other-agent','reader',{'privacy':2,'calls':2})
        self.committed()
        self.l.reserve(action(tenant='other'),'other-agent')
        self.rejects('UNAUTHORIZED',lambda:self.l.claim('other','a','agent'))
        self.rejects('NOT_COMMITTED',lambda:self.l.admit_delivery('other','a','reader','d','gateway-a','session-a'))
        self.l.admit_delivery('t','a','reader','d','gateway-a','session-a')
        self.rejects('UNAUTHORIZED',lambda:self.l.emit('other','d','reader','gateway-a','session-a'))

    def test_prestart_cancel_returns_and_tombstone_prevents_restart(self):
        self.l.reserve(action(),'agent')
        self.assertEqual(self.l.cancel('t','a','agent'),'CANCELED')
        self.assertEqual(self.balance(),(2,0,0))
        self.assertEqual(self.l.reserve(action(),'agent')['state'],'CANCELED')
        self.rejects('INVALID_STATE',lambda:self.l.claim('t','a','agent'))

    def test_started_cancel_burns_and_fences_late_commit(self):
        op=self.started()
        self.assertEqual(self.l.cancel('t','a','agent'),'BURNED')
        self.assertEqual(self.balance(),(1,0,1))
        self.rejects('INVALID_STATE',lambda:self.l.commit('t','a',1,op['digest'],b'late'))

    def test_resume_preserves_seed_and_fences_worker(self):
        old=self.started()
        new=self.l.recover('t','a',1)
        self.assertEqual(new['seed'],old['seed'])
        self.assertEqual(new['generation'],2)
        self.rejects('STALE_WORKER',lambda:self.l.commit('t','a',1,old['digest'],b'old'))
        self.l.commit('t','a',2,old['digest'],b'new')

    def test_double_recovery_generation_compare_and_swap(self):
        self.started()
        self.l.recover('t','a',1)
        self.rejects('STALE_WORKER',lambda:self.l.recover('t','a',1))

    def test_action_digest_and_output_cannot_change(self):
        op=self.started()
        self.rejects('ACTION_CONFLICT',lambda:self.l.commit('t','a',1,'wrong',b'result'))
        self.l.commit('t','a',1,op['digest'],b'result')
        self.l.commit('t','a',1,op['digest'],b'result')
        self.rejects('OUTPUT_CONFLICT',lambda:self.l.commit('t','a',1,op['digest'],b'another'))
        self.assertEqual(self.balance(),(1,0,1))

    def test_revoke_before_claim_blocks_new_l1(self):
        self.l.reserve(action(),'agent'); self.l.revoke('t','root')
        self.rejects('REVOKED',lambda:self.l.claim('t','a','agent'))

    def test_revoke_after_claim_allows_internal_completion_not_delivery(self):
        op=self.started(); self.l.revoke('t','root')
        self.assertEqual(self.l.claim('t','a','agent')['seed'],op['seed'])
        self.l.commit('t','a',1,op['digest'],b'result')
        self.rejects('REVOKED',lambda:self.l.admit_delivery('t','a','reader','fresh','gateway-a','session-a'))

    def test_l3_before_revoke_can_finish_but_new_l3_fails(self):
        self.committed(); self.l.admit_delivery('t','a','reader','inflight','gateway-a','session-a')
        self.l.revoke('t','root')
        self.assertEqual(self.l.emit('t','inflight','reader','gateway-a','session-a'),b'synthetic-output')
        self.rejects('REVOKED',lambda:self.l.admit_delivery('t','a','reader','new','gateway-a','session-a'))

    def test_delivery_cannot_precede_commit_or_change_recipient(self):
        self.started()
        self.rejects('NOT_COMMITTED',lambda:self.l.admit_delivery('t','a','reader','d','gateway-a','session-a'))
        self.rejects('UNAUTHORIZED',lambda:self.l.admit_delivery('t','a','intruder','d','gateway-a','session-a'))

    def test_delivery_id_cannot_move_to_another_operation(self):
        self.committed('a'); self.committed('b')
        self.l.admit_delivery('t','a','reader','d','gateway-a','session-a')
        self.rejects('DELIVERY_CONFLICT',lambda:self.l.admit_delivery('t','b','reader','d','gateway-a','session-a'))

    def test_delivery_replay_keeps_result_and_charge(self):
        self.committed()
        for i in range(3):
            self.l.admit_delivery('t','a','reader',str(i),'gateway-a','session-a')
            self.assertEqual(self.l.emit('t',str(i),'reader','gateway-a','session-a'),b'synthetic-output')
        self.assertEqual(self.balance(),(1,0,1))

    def fake_clock(self):
        value=[self.l.db.execute('SELECT observed FROM clock_floor').fetchone()[0]+1]
        self.l.clock=lambda:value[0]
        return value

    def ticket(self, ttl=60):
        return self.l.admit_delivery('t','a','reader','ticket','gateway-a','session-a',ttl=ttl)

    def resume(self, gateway='gateway-a',session='session-a'):
        return self.l.recover_delivery('t','ticket','reader',gateway,session)

    def test_old_ticket_cannot_bypass_fresh_fetch_authorization(self):
        self.fake_clock(); self.committed(); self.ticket()
        self.l.revoke('t','root')
        self.rejects('REVOKED',lambda:self.ticket())
        self.assertEqual(self.resume()['id'],'ticket')
        self.assertEqual(self.l.emit('t','ticket','reader','gateway-a','session-a'),b'synthetic-output')

    def test_ticket_bound_to_gateway_and_session(self):
        self.fake_clock(); self.committed(); self.ticket()
        for gateway,session in [('gateway-b','session-a'),('gateway-a','session-b')]:
            self.rejects('UNAUTHORIZED',lambda:self.resume(gateway,session))
            self.rejects('UNAUTHORIZED',lambda:self.l.emit('t','ticket','reader',gateway,session))
            self.rejects('DELIVERY_CONFLICT',lambda:self.l.admit_delivery('t','a','reader','ticket',gateway,session))

    def test_exact_expiry_rejects_resume_and_emit(self):
        clock=self.fake_clock(); self.committed(); ticket=self.ticket(ttl=5)
        clock[0]=ticket['expires_at']-1
        self.assertEqual(self.resume()['id'],'ticket')
        clock[0]+=1
        self.rejects('TICKET_EXPIRED',lambda:self.resume())
        self.rejects('TICKET_EXPIRED',lambda:self.l.emit('t','ticket','reader','gateway-a','session-a'))

    def test_ticket_retry_does_not_extend_lifetime(self):
        clock=self.fake_clock(); self.committed(); first=self.ticket(ttl=60)
        clock[0]+=30
        second=self.ticket(ttl=60)
        self.assertEqual(second['expires_at'],first['expires_at'])
        self.assertEqual(second['issued_at'],first['issued_at'])

    def test_expired_ticket_cannot_be_reissued_with_same_id(self):
        clock=self.fake_clock(); self.committed(); first=self.ticket(ttl=5)
        clock[0]=first['expires_at']
        self.rejects('TICKET_EXPIRED',lambda:self.ticket(ttl=60))
        second=self.l.admit_delivery('t','a','reader','fresh-ticket','gateway-a','session-a')
        self.assertEqual(second['issued_at'],clock[0])
        self.assertEqual(self.balance(),(1,0,1))

    def test_root_expiry_caps_ticket_lifetime(self):
        clock=self.fake_clock()
        self.l.db.execute("UPDATE roots SET expires_at=? WHERE tenant='t' AND id='root'",(clock[0]+10,))
        self.committed(); ticket=self.ticket(ttl=60)
        self.assertEqual(ticket['expires_at'],clock[0]+10)
        clock[0]+=10
        self.rejects('EXPIRED',lambda:self.ticket())
        self.rejects('TICKET_EXPIRED',lambda:self.resume())

    def test_expired_root_rejects_reserve_and_claim(self):
        clock=self.fake_clock()
        self.l.db.execute("UPDATE roots SET expires_at=? WHERE tenant='t' AND id='root'",(clock[0]+2,))
        self.l.reserve(action(),'agent')
        clock[0]+=2
        self.rejects('EXPIRED',lambda:self.l.claim('t','a','agent'))
        self.rejects('EXPIRED',lambda:self.l.reserve(action('b'),'agent'))
        self.assertEqual(self.balance(),(1,1,0))

    def test_invalid_ticket_lifetimes(self):
        self.fake_clock(); self.committed()
        for ttl in (0,-1,61,True,1.5):
            self.rejects('INVALID_TTL',lambda:self.ticket(ttl=ttl))

    def test_rejected_expiry_persists_clock_floor_across_restart(self):
        clock=self.fake_clock(); self.committed(); ticket=self.ticket(ttl=5)
        clock[0]=ticket['expires_at']
        self.rejects('TICKET_EXPIRED',lambda:self.resume())
        self.l.close()
        clock[0]-=1
        self.l=Ledger(self.path,clock=lambda:clock[0])
        self.rejects('CLOCK_ROLLBACK',lambda:self.resume())
        clock[0]+=1
        self.rejects('TICKET_EXPIRED',lambda:self.resume())

    def test_invalid_trusted_clock_is_rejected(self):
        self.committed(); self.ticket()
        for value in (True,1.5,-1,2**62):
            self.l.clock=lambda:value
            self.rejects('INVALID_CLOCK',lambda:self.resume())

    def test_two_connections_cannot_rebind_same_ticket(self):
        self.committed(); gate=threading.Barrier(2)
        def attempt(session):
            local=Ledger(self.path)
            try:
                gate.wait()
                return local.admit_delivery('t','a','reader','ticket','gateway-a',session)['session']
            except Rejected as e:
                return str(e)
            finally:
                local.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(attempt,['one','two']))
        self.assertEqual(outcomes.count('DELIVERY_CONFLICT'),1)
        self.assertEqual(sum(x in ('one','two') for x in outcomes),1)

    def test_actual_process_death_at_four_delivery_cuts(self):
        for point in ('before_delivery_commit','after_delivery_commit','before_emit_commit','after_emit_commit'):
            with self.subTest(point=point):
                path=Path(self.tmp.name)/(point+'.sqlite')
                local=Ledger.create(path)
                local.provision('t','root','agent','reader',{'privacy':2,'calls':2})
                local.reserve(action(),'agent'); op=local.claim('t','a','agent')
                local.commit('t','a',1,op['digest'],b'synthetic-output')
                if 'emit' in point:
                    local.admit_delivery('t','a','reader','ticket','gateway-a','session-a')
                local.close()
                result=subprocess.run([sys.executable,__file__,'--crash',str(path),point],capture_output=True,timeout=30)
                self.assertEqual(result.returncode,91,result.stderr.decode())
                local=Ledger(path)
                self.assertEqual(local.audit(),[])
                row=local.db.execute('SELECT * FROM deliveries').fetchone()
                if point=='before_delivery_commit':
                    self.assertIsNone(row)
                else:
                    self.assertEqual(row['handoff_admitted'],int(point=='after_emit_commit'))
                    self.assertEqual(local.emit('t','ticket','reader','gateway-a','session-a'),b'synthetic-output')
                local.close()
                COMPLETED_CRASH_CUTS.append(point)

    def test_concurrent_reservations_do_not_overspend(self):
        gate=threading.Barrier(8)
        def reserve(i):
            local=Ledger(self.path)
            try:
                gate.wait()
                local.reserve(action(str(i)),'agent')
                return 'accepted'
            except Rejected as e:
                return str(e)
            finally:
                local.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(reserve,range(8)))
        self.assertEqual(results.count('accepted'),2)
        self.assertEqual(results.count('BUDGET_EXHAUSTED'),6)
        self.assertEqual(self.balance(),(0,2,0))

    def test_concurrent_same_id_only_reserves_once(self):
        gate=threading.Barrier(8)
        def reserve(_):
            local=Ledger(self.path)
            try:
                gate.wait(); return local.reserve(action(),'agent')['digest']
            finally:
                local.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            hashes=list(pool.map(reserve,range(8)))
        self.assertEqual(len(set(hashes)),1)
        self.assertEqual(self.balance(),(1,1,0))

    def test_actual_process_death_at_seven_persistence_cuts(self):
        phases=['before_reserve_commit','after_reserve_commit',
                'before_claim_commit','after_claim_commit',
                'after_result_write','before_result_commit','after_result_commit']
        for point in phases:
            with self.subTest(point=point):
                path=Path(self.tmp.name)/(point+'.sqlite')
                local=Ledger.create(path)
                local.provision('t','root','agent','reader',{'privacy':2,'calls':2})
                if 'reserve' not in point:
                    local.reserve(action(),'agent')
                if 'claim' not in point and 'reserve' not in point:
                    local.claim('t','a','agent')
                local.close()
                result=subprocess.run([sys.executable,__file__,'--crash',str(path),point],capture_output=True,timeout=30)
                self.assertEqual(result.returncode,91,result.stderr.decode())
                local=Ledger(path)
                self.assertEqual(local.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                self.assertEqual(local.audit(),[])
                if point == 'before_reserve_commit':
                    self.assertEqual(local.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],0)
                else:
                    op=local.op('t','a')
                    expected={'after_reserve_commit':'RESERVED','before_claim_commit':'RESERVED',
                              'after_claim_commit':'STARTED','after_result_write':'STARTED',
                              'before_result_commit':'STARTED','after_result_commit':'COMMITTED'}[point]
                    self.assertEqual(op['state'],expected)
                    if expected=='COMMITTED':
                        self.assertEqual(op['result'],b'synthetic-output')
                    if expected=='STARTED':
                        old_seed=op['seed']
                        self.assertEqual(local.claim('t','a','agent')['seed'],old_seed)
                local.close()
                COMPLETED_CRASH_CUTS.append(point)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash':
        crash_child(sys.argv[2],sys.argv[3])
    else:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(LedgerTests)
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        report={'test_methods':result.testsRun,'crash_cuts':len(COMPLETED_CRASH_CUTS),
                'completed_crash_cuts':COMPLETED_CRASH_CUTS,
                'python_version':sys.version,'sqlite_version':sqlite3.sqlite_version,
                'source_sha256':{name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                 for name in ('ledger.py','test_ledger.py')},
                'failures':[(str(t),msg) for t,msg in result.failures],
                'errors':[(str(t),msg) for t,msg in result.errors],
                'passed':result.wasSuccessful(),
                'scope':'SQLite transaction consistency with synthetic values, not cryptographic or DP validation'}
        Path(__file__).with_name('test_results.json').write_text(json.dumps(report,indent=2)+'\n')
        sys.exit(0 if result.wasSuccessful() else 1)
