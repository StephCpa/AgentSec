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

from cryptography.hazmat.primitives import serialization
from witnessed_ledger import WitnessedLedger,ReferenceWitness,Rejected,image_hash
from encrypted_ledger import EncryptedLedger
from dp_ledger import EPSILON_COST as E,DELTA_COST as D
from test_delegated_ledger import KEYS,chain_fixture,packet,finish
from test_encrypted_ledger import vault,setup as encrypted_setup,register,step,raw_op,raw_job,SEED,MASTER

CRASHES=[]


def backup(source,path):
    target=sqlite3.connect(str(path));source.backup(target);target.close()


def setup(path,witness):
    l=WitnessedLedger.create(path,clock=lambda:100,vault=vault(),witness=witness)
    l.provision_domain('t','domain',2,3*E,3*D)
    l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
    l.install_snapshot('t','domain','snap',[0,1])
    for name,key in KEYS.items():
        pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',pub)
    l.bind_root_authority('t','root',b'authority');return l


def child(path,witness_path,point,recovery=False):
    w=ReferenceWitness(witness_path)
    def fault(here):
        if here==point:os._exit(97)
    l=WitnessedLedger(path,clock=lambda:100,vault=vault(),witness=w,witness_fault=fault)
    if recovery:l.recover_from_witness(fault)
    else:
        with patch('scheduled_ledger.secrets.token_bytes',side_effect=lambda n:SEED if n==32 else os.urandom(n)):
            step(l,fault)
    raise RuntimeError('cut not reached')


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'witness';self.w=ReferenceWitness(self.path)
    def tearDown(self):self.w.close();self.tmp.cleanup()
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()

    def test_compare_and_store_is_monotonic_and_exact_retry_is_idempotent(self):
        a=self.w.bootstrap('n',b'genesis');b=self.w.compare_and_store('n',a['seq'],a['digest'],b'next','a'*32)
        c=self.w.compare_and_store('n',b['seq'],b['digest'],b'last','b'*32)
        self.assertEqual(self.w.compare_and_store('n',a['seq'],a['digest'],b'next','a'*32),b)
        self.assertEqual(self.w.head('n'),c);self.assertEqual(c['seq'],2)
        self.reject('WITNESS_CAS_CONFLICT',lambda:self.w.compare_and_store('n',a['seq'],a['digest'],b'fork','c'*32))
        self.reject('WITNESS_REQUEST_CONFLICT',lambda:self.w.compare_and_store('n',a['seq'],a['digest'],b'changed','a'*32))
        self.reject('WITNESS_CAS_CONFLICT',lambda:self.w.compare_and_store('n',a['seq'],a['digest'],b'next','d'*32))
        self.reject('WITNESS_ALREADY_INITIALIZED',lambda:self.w.bootstrap('n',b'reset'))

    def test_two_connections_cannot_accept_divergent_successors(self):
        a=self.w.bootstrap('n',b'genesis');barrier=threading.Barrier(2)
        def run(i):
            w=ReferenceWitness(self.path)
            try:
                barrier.wait()
                try:return w.compare_and_store('n',a['seq'],a['digest'],str(i).encode(),str(i)*32)
                except Rejected as e:return str(e)
            finally:w.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:r=list(pool.map(run,range(2)))
        self.assertEqual(sum(isinstance(x,dict) for x in r),1);self.assertIn('WITNESS_CAS_CONFLICT',r)
        self.assertEqual(self.w.head('n')['seq'],1)

    def test_missing_namespace_is_never_automatically_initialized(self):
        self.reject('WITNESS_UNINITIALIZED',lambda:self.w.head('unknown'))
        self.reject('WITNESS_UNINITIALIZED',lambda:self.w.compare_and_store('unknown',0,'0'*64,b'state','a'*32))
        self.assertEqual(self.w.db.execute('SELECT COUNT(*) FROM heads').fetchone()[0],0)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.wp=self.root/'witness';self.path=self.root/'ledger';self.w=ReferenceWitness(self.wp);self.l=setup(self.path,self.w)
    def tearDown(self):self.l.close();self.w.close();self.tmp.cleanup()
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()
    def open_clone(self,p):return WitnessedLedger(p,clock=lambda:100,vault=vault(),witness=self.w)

    def test_counterexample_encryption_alone_accepts_old_state_and_new_noise(self):
        p=self.root/'unwitnessed';l=encrypted_setup(p);register(l);old=self.root/'oldplain';backup(l.db,old)
        outputs=[]
        for current,seed in [(l,bytes(32)),(EncryptedLedger(old,clock=lambda:100,vault=vault()),b'\xff'*5+bytes(27))]:
            with patch('scheduled_ledger.secrets.token_bytes',side_effect=lambda n:seed if n==32 else os.urandom(n)):
                step(current)
            finish(current);current.admit_delivery('t','a','reader','ticket','gw','session')
            outputs.append(current.emit('t','ticket','reader','gw','session'))
            self.assertEqual(current.db.execute("SELECT spent FROM accounts WHERE id='domain:epsilon'").fetchone()[0],E)
            self.assertEqual(current.audit(),[]);current.close()
        self.assertEqual([int.from_bytes(x,'big') for x in outputs],[1,2])

    def test_stale_snapshot_is_fenced_then_restores_exact_seed_result_and_spend(self):
        register(self.l);old=self.root/'old';backup(self.l.db,old);step(self.l);finish(self.l)
        original=raw_op(self.l);stale=self.open_clone(old)
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:step(stale))
            self.assertEqual(raw_op(stale)['state'],'RESERVED')
            stale.recover_from_witness();self.assertEqual(raw_op(stale),original)
            self.assertEqual(stale.db.execute("SELECT spent,reserved FROM accounts WHERE id='domain:epsilon'").fetchone()[:],(E,0))
            register(stale,proof_id=b'q'*16)
            self.assertEqual(raw_op(stale)['seed'],original['seed']);self.assertEqual(raw_op(stale)['result'],original['result'])
            self.assertEqual(stale.audit(),[])
        finally:stale.close()

    def test_witness_accept_then_lost_reply_requires_recovery_without_resampling(self):
        register(self.l);before=self.w.head(self.l.namespace)
        def lost(point):
            if point=='after_witness_accept':raise ConnectionError('simulated lost witness reply')
        self.l.witness_fault=lost
        with patch('scheduled_ledger.secrets.token_bytes',side_effect=lambda n:SEED if n==32 else os.urandom(n)):
            with self.assertRaises(ConnectionError):step(self.l)
        self.l.witness_fault=lambda point:None
        self.assertEqual(raw_op(self.l)['state'],'RESERVED')
        self.assertEqual(self.w.head(self.l.namespace)['seq'],before['seq']+1)
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:step(self.l))
        self.l.recover_from_witness();self.assertEqual(self.l.op('t','a')['seed'],SEED)
        with patch('scheduled_ledger.secrets.token_bytes',side_effect=lambda n:(_ for _ in ()).throw(AssertionError('new seed')) if n==32 else os.urandom(n)):
            finish(self.l)
        self.assertEqual(self.l.audit(),[])

    def test_result_accepted_only_by_witness_is_restored_not_recomputed(self):
        register(self.l)
        for _ in range(83):step(self.l)
        expected=self.l.compute_internal('t','a');seed=raw_op(self.l)['seed']
        def lost(point):
            if point=='after_witness_accept':raise ConnectionError('lost')
        self.l.witness_fault=lost
        with self.assertRaises(ConnectionError):step(self.l)
        self.l.witness_fault=lambda point:None;self.assertEqual(raw_op(self.l)['state'],'STARTED')
        self.l.recover_from_witness()
        self.assertEqual(raw_op(self.l)['seed'],seed);self.assertEqual(self.l.op('t','a')['result'],expected)
        self.assertEqual(raw_job(self.l)['publication'],'RELEASE');self.assertEqual(self.l.audit(),[])

    def test_local_state_edit_with_unchanged_anchor_is_detected(self):
        register(self.l);self.l.db.execute("UPDATE accounts SET free=free+1,total=total+1 WHERE id='domain:epsilon'")
        self.reject('LOCAL_STATE_DIVERGED',lambda:step(self.l))
        self.l.recover_from_witness();self.assertEqual(self.l.db.execute("SELECT total FROM accounts WHERE id='domain:epsilon'").fetchone()[0],3*E)
        self.assertEqual(self.l.audit(),[])

    def test_revocations_replay_tombstones_and_clock_floor_are_recovered(self):
        chain=chain_fixture();raw,p=packet(self.l,chain);old=self.root/'old';backup(self.l.db,old)
        self.l.register_delegated(raw,p,chain);self.l.revoke_credential('t','workergrant')
        stale=self.open_clone(old)
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:stale.register_delegated(raw,p,chain))
            stale.recover_from_witness()
            self.assertEqual(stale.db.execute('SELECT COUNT(*) FROM used_proofs').fetchone()[0],1)
            self.reject('CREDENTIAL_REVOKED',lambda:stale.register_delegated(raw,p,chain))
            stale.clock=lambda:200
            self.reject('INVALID_COMMAND',lambda:stale.advance('t','domain','bad',0,{'kind':'invalid'}))
            self.assertEqual(stale.db.execute('SELECT observed FROM clock_floor').fetchone()[0],200)
            restored=WitnessedLedger.restore_new(self.root/'fresh',clock=lambda:199,vault=vault(),witness=self.w)
            try:self.reject('CLOCK_ROLLBACK',lambda:step(restored))
            finally:restored.close()
            self.assertEqual(stale.audit(),[])
        finally:stale.close()

    def test_existing_ticket_and_emit_record_survive_recovery(self):
        register(self.l);finish(self.l);self.l.admit_delivery('t','a','reader','ticket','gw','session')
        old=self.root/'old';backup(self.l.db,old)
        result=self.l.emit('t','ticket','reader','gw','session');self.l.revoke_credential('t','workergrant')
        stale=self.open_clone(old)
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:stale.emit('t','ticket','reader','gw','session'))
            stale.recover_from_witness()
            self.assertEqual(stale.db.execute('SELECT handoff_admitted FROM deliveries').fetchone()[0],1)
            self.assertEqual(stale.emit('t','ticket','reader','gw','session'),result)
            self.reject('ACTION_OR_KEY_INACTIVE',lambda:stale.admit_delivery('t','a','reader','new','gw','session'))
            self.assertEqual(stale.audit(),[])
        finally:stale.close()

    def test_missing_or_unavailable_witness_blocks_all_mutating_admission(self):
        register(self.l);before=raw_op(self.l)
        with patch.object(self.w,'head',side_effect=ConnectionError('offline')):
            with self.assertRaises(ConnectionError):step(self.l)
        self.assertEqual(raw_op(self.l),before)
        empty=ReferenceWitness(self.root/'empty');self.l.witness=empty
        try:
            self.reject('WITNESS_UNINITIALIZED',lambda:step(self.l))
            self.reject('WITNESS_UNINITIALIZED',self.l.recover_from_witness)
            self.assertEqual(empty.db.execute('SELECT COUNT(*) FROM heads').fetchone()[0],0)
        finally:self.l.witness=self.w;empty.close()

    def test_no_unwitnessed_service_can_open_witnessed_storage(self):
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:EncryptedLedger(self.path,clock=lambda:100,vault=vault()))

    def test_invalid_witness_receipt_never_commits_local_success(self):
        register(self.l);real=self.w.compare_and_store
        def bad(*args,**kwargs):
            result=real(*args,**kwargs);return dict(result,digest='0'*64)
        with patch.object(self.w,'compare_and_store',side_effect=bad):
            self.reject('INVALID_WITNESS_RECEIPT',lambda:step(self.l))
        self.assertEqual(raw_op(self.l)['state'],'RESERVED')
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:step(self.l))
        self.l.recover_from_witness();self.assertEqual(raw_op(self.l)['state'],'STARTED')
        self.assertEqual(self.l.audit(),[])

    def test_head_change_during_recovery_rolls_back_partial_restore(self):
        register(self.l);old=self.root/'old';backup(self.l.db,old);step(self.l);stale=self.open_clone(old)
        try:
            def interleave(point):
                if point=='after_recovery_delete':step(self.l)
            self.reject('WITNESS_CHANGED_DURING_RECOVERY',lambda:stale.recover_from_witness(interleave))
            self.assertEqual(raw_op(stale)['state'],'RESERVED')
            stale.recover_from_witness();self.assertEqual(raw_job(stale)['pc'],2)
            self.assertEqual(stale.audit(),[])
        finally:stale.close()

    def test_witness_images_store_ciphertext_not_private_seed_or_master_key(self):
        register(self.l)
        with patch('scheduled_ledger.secrets.token_bytes',side_effect=lambda n:SEED if n==32 else os.urandom(n)):
            step(self.l)
        image=self.w.head(self.l.namespace,include_image=True)['image']
        for secret in (SEED,MASTER,SEED.hex().encode(),MASTER.hex().encode()):
            self.assertNotIn(secret,image);self.assertNotIn(secret,self.wp.read_bytes())
        restored=WitnessedLedger.restore_new(self.root/'fresh',clock=lambda:100,vault=vault(),witness=self.w)
        try:self.assertEqual(restored.op('t','a')['seed'],SEED);self.assertEqual(restored.audit(),[])
        finally:restored.close()

    def test_two_cloned_writers_past_precheck_have_one_cas_winner(self):
        register(self.l);paths=[self.root/'clone1',self.root/'clone2']
        for p in paths:backup(self.l.db,p)
        barrier=threading.Barrier(2)
        def run(p):
            w=ReferenceWitness(self.wp)
            l=WitnessedLedger(p,clock=lambda:100,vault=vault(),witness=w,
                witness_fault=lambda point:barrier.wait(timeout=10) if point=='before_witness_accept' else None)
            try:
                try:step(l);return 'accepted'
                except Rejected as e:return str(e)
            finally:l.close();w.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:r=list(pool.map(run,paths))
        self.assertCountEqual(r,['accepted','WITNESS_CAS_CONFLICT'])
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:step(self.l));self.l.recover_from_witness()
        self.assertEqual(raw_job(self.l)['pc'],1);self.assertEqual(self.l.audit(),[])

    def test_recovery_refuses_corrupt_image_and_incompatible_schema(self):
        register(self.l);before=self.l.state_image()
        row=self.w.head(self.l.namespace,include_image=True)
        self.w.db.execute('UPDATE heads SET image=?',(row['image']+b'x',))
        self.reject('WITNESS_IMAGE_CORRUPT',self.l.recover_from_witness)
        self.assertEqual(self.l.state_image(),before)
        self.w.db.execute('UPDATE heads SET image=?',(row['image'],))
        self.l.db.execute('CREATE TABLE sqlitex_extra (secret TEXT)')
        self.reject('WITNESS_SCHEMA_MISMATCH',self.l.recover_from_witness)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],1)

    def test_restoring_both_stores_is_outside_the_witness_assumption(self):
        register(self.l);old_db=self.root/'both-ledger';old_w=self.root/'both-witness'
        backup(self.l.db,old_db);backup(self.w.db,old_w);step(self.l)
        rolled=ReferenceWitness(old_w);replica=WitnessedLedger(old_db,clock=lambda:100,vault=vault(),witness=rolled)
        try:
            # Deliberate negative control: rolling back the trusted authority too
            # cannot be detected by this protocol. Never advertise unconditional protection.
            self.assertEqual(replica.audit(),[]);self.assertEqual(raw_op(replica)['state'],'RESERVED')
        finally:replica.close();rolled.close()

    def test_four_commit_and_three_recovery_process_death_cuts(self):
        commit_points=('before_witness_accept','after_witness_accept','after_local_anchor_write','after_tick_commit')
        for point in commit_points:
            with self.subTest(point=point):
                wpath=self.root/(point+'-w');p=self.root/point;w=ReferenceWitness(wpath);l=setup(p,w);register(l)
                old_head=w.head(l.namespace);l.close();w.close()
                proc=subprocess.run([sys.executable,__file__,'--crash',str(p),str(wpath),point],capture_output=True,timeout=30)
                self.assertEqual(proc.returncode,97,proc.stderr.decode())
                w=ReferenceWitness(wpath);l=WitnessedLedger(p,clock=lambda:100,vault=vault(),witness=w)
                accepted=point!='before_witness_accept'
                self.assertEqual(w.head(l.namespace)['seq'],old_head['seq']+int(accepted))
                if point in ('after_witness_accept','after_local_anchor_write'):
                    self.reject('WITNESS_RECOVERY_REQUIRED',lambda:step(l))
                l.recover_from_witness()
                self.assertEqual(raw_job(l)['pc'],int(accepted))
                if accepted:self.assertEqual(l.op('t','a')['seed'],SEED)
                else:step(l)
                expected=l.compute_internal('t','a');finish(l);self.assertEqual(l.op('t','a')['result'],expected)
                self.assertEqual(l.audit(),[]);l.close();w.close();CRASHES.append(point)
        register(self.l);old=self.root/'recovery-old';backup(self.l.db,old);step(self.l);saved=raw_op(self.l)
        for point in ('after_recovery_delete','before_recovery_commit','after_recovery_commit'):
            with self.subTest(point=point):
                p=self.root/point;source=sqlite3.connect(str(old));backup(source,p);source.close()
                proc=subprocess.run([sys.executable,__file__,'--recover-crash',str(p),str(self.wp),point],capture_output=True,timeout=30)
                self.assertEqual(proc.returncode,97,proc.stderr.decode());l=self.open_clone(p)
                if point!='after_recovery_commit':self.reject('WITNESS_RECOVERY_REQUIRED',lambda:step(l))
                l.recover_from_witness();self.assertEqual(raw_op(l),saved);self.assertEqual(l.audit(),[]);l.close();CRASHES.append(point)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1] in ('--crash','--recover-crash'):
        child(sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[1]=='--recover-crash')
    else:
        suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in (WitnessTests,RecoveryTests)])
        result=unittest.TextTestRunner(verbosity=2).run(suite);root=Path(__file__).resolve().parent
        sources=('witnessed_ledger.py','test_witnessed_ledger.py','encrypted_ledger.py','ledger.py','dp_ledger.py',
                 'scheduled_ledger.py','signed_ledger.py','delegated_ledger.py','wire.py','test_encrypted_ledger.py',
                 'test_delegated_ledger.py','test_signed_ledger.py','../fixed_work_model.py','requirements-crypto.txt')
        report={'passed':result.wasSuccessful(),'test_methods':result.testsRun,'crash_cut_count':len(CRASHES),
                'actual_process_crash_cuts':CRASHES,'source_sha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in sources},
                'python_version':sys.version,'sqlite_version':sqlite3.sqlite_version,'cryptography_version':__import__('cryptography').__version__,
                'failures':[(str(t),m) for t,m in result.failures],'errors':[(str(t),m) for t,m in result.errors],
                'scope':'Local ledger rollback fencing and exact state recovery assuming an independent linearizable nonrollback witness; witness is a local SQLite simulation, not production infrastructure'}
        (root/'witnessed_test_results.json').write_text(json.dumps(report,indent=2)+'\n');sys.exit(0 if result.wasSuccessful() else 1)
