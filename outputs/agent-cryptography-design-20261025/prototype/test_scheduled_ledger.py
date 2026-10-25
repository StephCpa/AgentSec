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

from scheduled_ledger import ScheduledLedger, Rejected
from dp_ledger import EPSILON_COST as E, DELTA_COST as D

CRASHES=[]


def setup(path, rows=None):
    rows=[0,1] if rows is None else rows
    l=ScheduledLedger.create(path,clock=lambda:100)
    l.provision_domain('t','domain',len(rows),4*E,4*D)
    l.authorize_root('t','domain','root','agent','reader',expires_at=1000)
    l.install_snapshot('t','domain','snap',rows)
    return l


def reserve(l,oid='a',fault=lambda p:None):
    return l.reserve_count('t',oid,'root','reader','domain','snap','agent',fault)


def tick(l,command=None,fault=lambda p:None):
    current=l.db.execute('SELECT tick FROM schedulers').fetchone()[0]
    return l.advance('t','domain','tick'+str(current+1),current,command,fault)


def child(path, point):
    l=ScheduledLedger(path,clock=lambda:100)
    def fault(p):
        if p==point:
            os._exit(93)
    if 'reserve' in point:
        reserve(l,fault=fault)
    else:
        tick(l,fault=fault)
    raise RuntimeError('fault not reached')


class ScheduledTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'db'
        self.l=setup(self.path)
    def tearDown(self):
        self.assertEqual(self.l.audit(),[])
        self.l.close(); self.tmp.cleanup()
    def reject(self, code, call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):
            call()
    def job(self,oid='a'):
        return self.l.db.execute('SELECT * FROM jobs WHERE operation_id=?',(oid,)).fetchone()
    def finish(self,l=None):
        l=l or self.l
        for _ in range(500):
            if not l.db.execute('SELECT 1 FROM jobs WHERE publication IS NULL').fetchone():
                return
            tick(l)
        self.fail('no bounded completion')
    def publications(self,l=None):
        return [(e['tick'],e['kind'],e['subject']) for e in (l or self.l).journal_internal('t','domain') if e['kind']!='CONTROL_ACK']
    def balances(self,l=None):
        return {r['id']:tuple(r[x] for x in ('free','reserved','spent')) for r in (l or self.l).db.execute('SELECT * FROM accounts')}

    def test_reservation_registers_queue_once_atomically(self):
        reserve(self.l); reserve(self.l)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],1)
        self.assertEqual(self.job()['seq'],1)
        self.assertEqual(self.job()['pc'],0)
        self.assertEqual(self.job()['work'],84)

    def test_private_read_requires_seed_committed_by_an_earlier_transaction(self):
        reserve(self.l)
        def stop(point):
            if point=='before_tick_commit':raise RuntimeError('abort admission')
        with patch.object(self.l,'open_snapshot',side_effect=AssertionError('early private read')):
            with self.assertRaisesRegex(RuntimeError,'abort admission'):
                self.l.advance('t','domain','abort',0,fault=stop)
            self.assertEqual(self.l.op('t','a')['state'],'RESERVED')
            self.assertIsNone(self.l.op('t','a')['seed'])
            tick(self.l)
        seed=self.l.op('t','a')['seed'];original=self.l.open_snapshot
        def read_after_durable_admission(*args):
            observer=sqlite3.connect(str(self.path))
            try:
                self.assertEqual(observer.execute("SELECT state,seed FROM operations WHERE id='a'").fetchone(),('STARTED',seed))
                self.assertEqual(observer.execute('SELECT pc FROM jobs').fetchone()[0],1)
            finally:observer.close()
            return original(*args)
        with patch.object(self.l,'open_snapshot',side_effect=read_after_durable_admission) as observed:
            tick(self.l);self.assertEqual(observed.call_count,1)

    def test_round_robin_order_and_exact_kernel_output(self):
        reserve(self.l,'a'); reserve(self.l,'b')
        tick(self.l); tick(self.l)
        self.assertEqual(self.job('a')['pc'],1); self.assertEqual(self.job('b')['pc'],1)
        expected={oid:self.l.compute_internal('t',oid) for oid in ('a','b')}
        self.finish()
        self.assertEqual(self.publications(),[(167,'RELEASE','a'),(168,'RELEASE','b')])
        for oid in ('a','b'):
            self.assertEqual(self.l.op('t',oid)['result'],expected[oid])
            self.l.admit_delivery('t',oid,'reader','ticket'+oid,'gw','session')
            self.assertEqual(self.l.emit('t','ticket'+oid,'reader','gw','session'),expected[oid])
        self.assertEqual(self.balances(),{'domain:epsilon':(2*E,0,2*E),'domain:delta':(2*D,0,2*D)})

    def test_new_dynamic_job_joins_queue_without_reset(self):
        reserve(self.l)
        for _ in range(5): tick(self.l)
        reserve(self.l,'b'); self.finish()
        self.assertEqual([x[2] for x in self.publications()],['a','b'])
        self.assertEqual(self.l.db.execute('SELECT tick FROM schedulers').fetchone()[0],168)

    def test_partial_work_survives_restart_with_same_seed_and_accumulator(self):
        reserve(self.l)
        for _ in range(31): tick(self.l)
        old=dict(self.job()); seed=self.l.op('t','a')['seed']; expected=self.l.compute_internal('t','a')
        self.l.close(); self.l=ScheduledLedger(self.path,clock=lambda:100)
        self.assertEqual(dict(self.job()),old)
        self.assertEqual(self.l.op('t','a')['seed'],seed)
        self.finish(); self.assertEqual(self.l.op('t','a')['result'],expected)
        self.assertEqual(self.publications()[0][0],84)

    def test_retry_does_not_advance_twice_and_changed_request_conflicts(self):
        reserve(self.l)
        first=self.l.advance('t','domain','request',0)
        seed=self.l.op('t','a')['seed']
        self.assertEqual(self.l.advance('t','domain','request',0),first)
        self.assertEqual(self.job()['pc'],1)
        self.assertEqual(self.l.op('t','a')['seed'],seed)
        self.reject('TICK_CONFLICT',lambda:self.l.advance('t','domain','request',0,{'kind':'pause'}))
        self.reject('STALE_TICK',lambda:self.l.advance('t','domain','other',0))

    def test_pause_ack_is_immediate_and_does_not_move_work(self):
        reserve(self.l)
        tick(self.l,{'kind':'pause'})
        self.assertEqual(self.job()['pc'],0)
        event=self.l.journal_internal('t','domain')[0]
        self.assertEqual((event['tick'],event['kind']),(1,'CONTROL_ACK'))
        self.finish(); self.assertEqual(self.publications()[0][0],85)

    def test_cancel_before_start_refunds_but_keeps_public_slot_work(self):
        reserve(self.l)
        tick(self.l,{'kind':'cancel','operation':'a','actor':'agent'})
        self.assertEqual(self.l.op('t','a')['state'],'CANCELED')
        self.assertEqual(self.balances(),{'domain:epsilon':(4*E,0,0),'domain:delta':(4*D,0,0)})
        self.finish(); self.assertEqual(self.publications(),[(84,'WITHHELD','a')])

    def test_cancel_after_start_burns_both_dimensions(self):
        reserve(self.l); tick(self.l)
        tick(self.l,{'kind':'cancel','operation':'a','actor':'agent'})
        self.assertEqual(self.l.op('t','a')['state'],'BURNED')
        self.finish(); self.assertEqual(self.publications(),[(84,'WITHHELD','a')])
        self.assertEqual(self.balances(),{'domain:epsilon':(3*E,0,E),'domain:delta':(3*D,0,D)})

    def test_revocation_midwork_blocks_release_without_new_sample(self):
        reserve(self.l); tick(self.l); seed=self.l.op('t','a')['seed']
        tick(self.l,{'kind':'revoke','root':'root','actor':'agent'})
        self.finish()
        self.assertEqual(self.publications(),[(84,'WITHHELD','a')])
        self.assertEqual(self.l.op('t','a')['state'],'COMMITTED')
        self.assertEqual(self.l.op('t','a')['seed'],seed)
        self.reject('REVOKED',lambda:self.l.admit_delivery('t','a','reader','d','gw','session'))

    def test_expiry_before_start_refunds_and_after_start_withholds(self):
        for start in (False,True):
            path=Path(self.tmp.name)/str(start); l=setup(path); reserve(l)
            if start: tick(l)
            l.clock=lambda:1000
            self.finish(l)
            self.assertEqual(self.publications(l)[0][1],'WITHHELD')
            self.assertEqual(l.op('t','a')['state'],'COMMITTED' if start else 'CANCELED')
            self.assertEqual(l.audit(),[]); l.close()

    def test_delivery_gate_and_preexisting_finite_ticket_semantics(self):
        reserve(self.l)
        self.reject('PUBLICATION_PENDING_OR_WITHHELD',lambda:self.l.admit_delivery('t','a','reader','d','gw','session'))
        self.finish()
        self.l.admit_delivery('t','a','reader','d','gw','session',ttl=3)
        tick(self.l,{'kind':'revoke','root':'root','actor':'agent'})
        expected=self.l.op('t','a')['result']
        self.assertEqual(self.l.emit('t','d','reader','gw','session'),expected)
        self.reject('REVOKED',lambda:self.l.admit_delivery('t','a','reader','new','gw','session'))
        self.l.clock=lambda:103
        self.reject('TICKET_EXPIRED',lambda:self.l.emit('t','d','reader','gw','session'))

    def test_direct_execution_and_control_bypasses_rejected(self):
        reserve(self.l)
        for name,args in [('claim',('t','a','agent')),('recover',('t','a',1)),
                          ('execute_count',('t','a',1)),('commit',('t','a',1,'x',b'x')),
                          ('cancel',('t','a','agent')),('revoke',('t','root'))]:
            self.reject('SCHEDULER_REQUIRED',lambda:getattr(self.l,name)(*args))

    def test_invalid_control_rolls_back_entire_tick(self):
        reserve(self.l)
        self.reject('UNAUTHORIZED',lambda:tick(self.l,{'kind':'revoke','root':'root','actor':'intruder'}))
        self.assertEqual(self.job()['pc'],0)
        self.assertEqual(self.l.journal_internal('t','domain'),[])
        self.assertEqual(self.l.root('t','root')['revoked'],0)

    def test_adaptive_cancel_uses_only_already_committed_published_result(self):
        reserve(self.l,'a'); reserve(self.l,'b')
        for _ in range(167): tick(self.l)
        self.l.admit_delivery('t','a','reader','a','gw','session')
        result=int.from_bytes(self.l.emit('t','a','reader','gw','session'),'big')
        command={'kind':'cancel','operation':'b','actor':'agent'} if result==0 else {'kind':'noop'}
        tick(self.l,command)
        self.assertEqual(self.publications()[-1][1],'WITHHELD' if result==0 else 'RELEASE')
        self.assertEqual(self.l.audit(),[])

    def test_relational_public_journal_ignores_private_rows(self):
        journals=[]
        for rows in ([0,0],[0,1],[1,0],[1,1]):
            path=Path(self.tmp.name)/('rows'+''.join(map(str,rows)))
            l=setup(path,rows); reserve(l,'a'); reserve(l,'b')
            for i in range(169):
                tick(l,{'kind':'pause'} if i==15 else None)
            journals.append(l.journal_internal('t','domain'))
            self.assertEqual(l.audit(),[]); l.close()
        self.assertTrue(all(j==journals[0] for j in journals))

    def race(self, same):
        reserve(self.l); gate=threading.Barrier(8)
        def attempt(i):
            l=ScheduledLedger(self.path,clock=lambda:100)
            try:
                gate.wait(); l.advance('t','domain','same' if same else 'r'+str(i),0); return 'accepted'
            except Rejected as e: return str(e)
            finally: l.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            return list(pool.map(attempt,range(8)))
    def test_concurrent_distinct_ticks_have_one_cas_winner(self):
        outcomes=self.race(False)
        self.assertEqual(outcomes.count('accepted'),1); self.assertEqual(outcomes.count('STALE_TICK'),7)
        self.assertEqual(self.job()['pc'],1)
    def test_concurrent_same_tick_request_is_idempotent(self):
        self.assertEqual(self.race(True),['accepted']*8)
        self.assertEqual(self.job()['pc'],1)
        self.assertEqual(len(self.l.journal_internal('t','domain')),1)

    def test_ten_actual_process_crash_cuts(self):
        points=('before_reserve_commit','after_reserve_commit','after_control_write','after_scheduled_claim',
                'after_work_step','after_scheduled_result_write','after_account_settle','after_publication_write',
                'before_tick_commit','after_tick_commit')
        final_points=set(points[5:])
        for point in points:
            with self.subTest(point=point):
                path=Path(self.tmp.name)/point; l=setup(path)
                if 'reserve' not in point: reserve(l)
                if point in final_points:
                    for _ in range(83): tick(l)
                seed=l.op('t','a')['seed'] if point in final_points else None
                l.close()
                proc=subprocess.run([sys.executable,__file__,'--crash',str(path),point],capture_output=True,timeout=30)
                self.assertEqual(proc.returncode,93,proc.stderr.decode())
                l=ScheduledLedger(path,clock=lambda:100)
                self.assertEqual(l.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                self.assertEqual(l.audit(),[])
                if point=='before_reserve_commit':
                    self.assertEqual(l.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0)
                    self.assertEqual(l.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],0)
                    reserve(l)
                if point in final_points:
                    self.assertEqual(l.op('t','a')['seed'],seed)
                    done=point=='after_tick_commit'
                    self.assertEqual(l.op('t','a')['state'],'COMMITTED' if done else 'STARTED')
                    self.assertEqual(len(self.publications(l)),int(done))
                    self.assertEqual(l.db.execute('SELECT pc FROM jobs').fetchone()[0],84 if done else 83)
                    if done:
                        self.assertEqual(l.advance('t','domain','tick84',83),{'request_id':'tick84','tick':84})
                        self.assertEqual(len(self.publications(l)),1)
                self.finish(l)
                self.assertEqual(self.publications(l),[(84,'RELEASE','a')])
                self.assertEqual(l.op('t','a')['result'],l.compute_internal('t','a'))
                self.assertEqual(l.audit(),[]); l.close(); CRASHES.append(point)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash': child(sys.argv[2],sys.argv[3])
    else:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(ScheduledTests)
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        root=Path(__file__).resolve().parent
        report={'passed':result.wasSuccessful(),'test_methods':result.testsRun,'crash_cut_count':len(CRASHES),'actual_process_crash_cuts':CRASHES,
                'python_version':sys.version,'sqlite_version':sqlite3.sqlite_version,
                'source_sha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('ledger.py','dp_ledger.py','scheduled_ledger.py','test_scheduled_ledger.py','../fixed_work_model.py')},
                'failures':[(str(t),m) for t,m in result.failures],'errors':[(str(t),m) for t,m in result.errors],
                'scope':'Durable logical slots and internal publication eligibility; synthetic data; not public transport or physical timing privacy'}
        (root/'scheduled_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
        sys.exit(0 if result.wasSuccessful() else 1)
