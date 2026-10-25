import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from encrypted_mixed_ledger import EncryptedMixedLedger
from encrypted_ledger import EncryptedLedger,StateVault,FIELDS,MAGIC
from mixed_delegated_ledger import MixedDelegatedLedger
from histogram_ledger import HistogramLedger
from ledger import Rejected
from dp_ledger import EPSILON_COST as E,DELTA_COST as D
from test_mixed_delegated_ledger import KEYS,chain_fixture,packet,tick,finish

MASTER=hashlib.sha256(b'public mixed encryption fixture only').digest()
DEPLOYMENT=b'mixed-vault-0001'
TAPE=hashlib.sha256(b'public synthetic tape part one').digest()+hashlib.sha256(b'public synthetic tape part two').digest()[:8]
CRASHES=[]


def vault():return StateVault(MASTER,DEPLOYMENT)


def setup(path,rows=None,buckets=None):
    rows=[1,2,0] if rows is None else rows;buckets=['one','two','three','four'] if buckets is None else buckets
    l=EncryptedMixedLedger.create(path,clock=lambda:100,vault=vault())
    l.provision_domain('t','domain',len(rows),4*E,4*D)
    l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
    l.install_catalog('t','domain','cat',buckets)
    l.install_histogram_snapshot('t','domain','hist','cat',rows)
    l.install_snapshot('t','domain','count',[int(x!=0) for x in rows])
    for name,key in KEYS.items():
        l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
    l.bind_root_authority('t','root',b'authority');return l


def register(l,oid='a',hist=True):
    chain=chain_fixture(l);domain=l.domain('t','domain');changes={'capacity':domain['capacity']}
    if hist:changes['bucket_count']=len(json.loads(l.catalog('t','domain','cat')['buckets_json']))
    return l.register_delegated(*packet(l,chain,oid,hist,**changes),chain)


def raw_op(l,oid='a'):return dict(l.db.execute('SELECT * FROM operations WHERE id=?',(oid,)).fetchone())
def raw_job(l,oid='a'):return l.db.execute('SELECT * FROM jobs WHERE operation_id=?',(oid,)).fetchone()
def stable(l):
    return {name:[tuple(r) for r in l.db.execute('SELECT * FROM '+name)] for name in
            ('accounts','charges','operations','jobs','schedulers','tick_requests','publication_events','deliveries')}


def child(path,point):
    l=EncryptedMixedLedger(path,clock=lambda:100,vault=vault())
    def fault(p):
        if p==point:os._exit(97)
    with patch('histogram_ledger.fresh_tape',return_value=TAPE):tick(l,fault)
    raise RuntimeError('cut not reached')


class EncryptedMixedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'db';self.l=setup(self.path)
    def tearDown(self):self.l.close();self.tmp.cleanup()
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()
    def reopen(self):
        self.l.close();self.l=EncryptedMixedLedger(self.path,clock=lambda:100,vault=vault())

    def test_signed_mixed_execution_encrypts_all_private_fields_and_retains_caps(self):
        register(self.l);register(self.l,'c',False)
        with patch('histogram_ledger.fresh_tape',return_value=TAPE):tick(self.l)
        tick(self.l);expected={oid:self.l.compute_internal('t',oid) for oid in ('a','c')};finish(self.l)
        for oid,widths in [('a',(76,68,84)),('c',(68,44,44))]:
            op=raw_op(self.l,oid);job=raw_job(self.l,oid)
            self.assertEqual(tuple(len(x) for x in (op['seed'],op['result'],job['private_state'])),widths)
            self.assertTrue(all(x.startswith(MAGIC) for x in (op['seed'],op['result'],job['private_state'])))
            self.assertEqual(tuple(job[k] for k in FIELDS),(0,1,1,0,0));self.assertTrue(op['result_digest'].startswith('hmac-v1:'))
            self.assertNotEqual(op['result_digest'],hashlib.sha256(expected[oid]).hexdigest())
            self.l.admit_delivery('t',oid,'reader','ticket'+oid,'g','s')
        self.reopen()
        for oid in ('a','c'):self.assertEqual(self.l.emit('t','ticket'+oid,'reader','g','s'),expected[oid])
        self.assertTrue(all(r[0]==2*E for r in self.l.db.execute("SELECT spent FROM accounts WHERE id LIKE '%:epsilon'")))
        self.assertTrue(all(r[0]==2*D for r in self.l.db.execute("SELECT spent FROM accounts WHERE id LIKE '%:delta'")))
        for r in self.l.db.execute('SELECT rows_json FROM snapshots'):self.assertEqual(len(r[0]),39);self.assertTrue(r[0].startswith(MAGIC))
        self.assertEqual(self.l.audit(),[])

    def test_full_encrypted_tape_commits_before_snapshot_read(self):
        register(self.l)
        with patch.object(self.l,'open_snapshot',side_effect=AssertionError('early private read')):
            tick(self.l)
        sealed=raw_op(self.l)['seed'];original=self.l.open_snapshot
        def read(*args):
            db=sqlite3.connect(str(self.path))
            try:self.assertEqual(db.execute("SELECT state,seed FROM operations WHERE id='a'").fetchone(),('STARTED',sealed))
            finally:db.close()
            return original(*args)
        with patch.object(self.l,'open_snapshot',side_effect=read):tick(self.l)
        self.assertEqual(self.l.audit(),[])

    def test_maximum_bucket_ciphertext_widths_and_replay(self):
        l=setup(Path(self.tmp.name)/'max',rows=[64],buckets=['b'+str(i) for i in range(64)])
        try:
            register(l);tick(l);expected=l.compute_internal('t','a');finish(l)
            self.assertEqual((len(raw_op(l)['seed']),len(raw_op(l)['result']),len(raw_job(l)['private_state'])),(676,548,804))
            self.assertEqual(l.op('t','a')['result'],expected);self.assertEqual(raw_job(l)['pc'],5249);self.assertEqual(l.audit(),[])
        finally:l.close()

    def test_maximum_public_capacity_snapshot_fits_vault_without_truncation(self):
        rows=[i%5 for i in range(65535)];l=setup(Path(self.tmp.name)/'capacity',rows=rows)
        try:
            sealed=l.db.execute("SELECT rows_json FROM snapshots WHERE id='hist'").fetchone()[0]
            self.assertEqual(len(sealed),65571)
            self.assertEqual(l.open_snapshot('t','domain','hist',sealed),rows)
            register(l);tick(l)
            self.assertEqual(raw_job(l)['work'],262465);self.assertEqual(raw_job(l)['pc'],1)
            self.assertEqual(l.audit(),[])
        finally:l.close()

    def test_ciphertext_lengths_do_not_depend_on_private_categories_or_partial_counts(self):
        lengths=[]
        for i,rows in enumerate(([0,0,0],[1,2,4],[4,4,4])):
            l=setup(Path(self.tmp.name)/('shape'+str(i)),rows=rows)
            try:
                register(l);tick(l)
                samples=[]
                for _ in range(90):tick(l);samples.append(len(raw_job(l)['private_state']))
                finish(l);lengths.append((len(raw_op(l)['seed']),len(raw_op(l)['result']),samples))
                self.assertEqual(l.audit(),[])
            finally:l.close()
        self.assertTrue(all(x==lengths[0] for x in lengths));self.assertEqual(set(lengths[0][2]),{84})

    def test_midvector_reopen_preserves_tape_ciphertext_and_checkpoint(self):
        register(self.l)
        with patch('histogram_ledger.fresh_tape',return_value=TAPE):tick(self.l)
        for _ in range(168):tick(self.l)
        before=dict(raw_job(self.l));seed=raw_op(self.l)['seed'];expected=self.l.compute_internal('t','a');self.reopen()
        self.assertEqual(dict(raw_job(self.l)),before)
        with patch('histogram_ledger.fresh_tape',side_effect=AssertionError('resample')):finish(self.l)
        self.assertEqual(raw_op(self.l)['seed'],seed);self.assertEqual(self.l.op('t','a')['result'],expected);self.assertEqual(self.l.audit(),[])

    def test_wrong_key_deployment_or_plaintext_profile_cannot_open(self):
        for cls in (HistogramLedger,MixedDelegatedLedger):self.reject('STORAGE_PROFILE_MISMATCH',lambda:cls(self.path))
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:EncryptedLedger(self.path,vault=vault()))
        for v in (StateVault(bytes(32),DEPLOYMENT),StateVault(MASTER,b'mixed-vault-0002')):
            self.reject('STORAGE_PROFILE_MISMATCH',lambda:EncryptedMixedLedger(self.path,vault=v))
        with self.assertRaises(TypeError):EncryptedMixedLedger(self.path)
        path=Path(self.tmp.name)/'plain';plain=MixedDelegatedLedger.create(path);plain.close();before=path.read_bytes()
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:EncryptedMixedLedger.create(path,vault=vault()))
        self.assertEqual(path.read_bytes(),before)

    def test_seed_and_state_corruption_fail_without_refund_resample_or_progress(self):
        register(self.l);tick(self.l)
        for table,column in [('operations','seed'),('jobs','private_state')]:
            original=self.l.db.execute('SELECT '+column+' FROM '+table).fetchone()[0]
            corrupt=original[:-1]+bytes([original[-1]^1]);self.l.db.execute('UPDATE '+table+' SET '+column+'=?',(corrupt,));before=stable(self.l)
            with patch('histogram_ledger.fresh_tape',side_effect=AssertionError('resample')):
                self.reject('STORAGE_INTEGRITY',lambda:tick(self.l))
            self.assertEqual(stable(self.l),before)
            self.l.db.execute('UPDATE '+table+' SET '+column+'=?',(original,))
        finish(self.l);self.assertEqual(self.l.audit(),[])

    def test_snapshot_substitution_and_type_remapping_fail_after_durable_start(self):
        register(self.l);tick(self.l)
        original=self.l.db.execute("SELECT rows_json FROM snapshots WHERE id='hist'").fetchone()[0]
        other=self.l.db.execute("SELECT rows_json FROM snapshots WHERE id='count'").fetchone()[0]
        self.l.db.execute("UPDATE snapshots SET rows_json=? WHERE id='hist'",(other,));before=stable(self.l)
        self.reject('STORAGE_INTEGRITY',lambda:tick(self.l));self.assertEqual(stable(self.l),before)
        self.l.db.execute("UPDATE snapshots SET rows_json=? WHERE id='hist'",(original,))
        self.l.db.execute('DELETE FROM histogram_snapshots');before=stable(self.l)
        self.reject('STORAGE_INTEGRITY',lambda:tick(self.l));self.assertEqual(stable(self.l),before)

    def test_snapshot_id_and_ordered_catalog_binding_reject_swaps(self):
        self.l.install_histogram_snapshot('t','domain','other','cat',[4,3,0])
        original=self.l.db.execute("SELECT rows_json FROM snapshots WHERE id='hist'").fetchone()[0]
        other=self.l.db.execute("SELECT rows_json FROM snapshots WHERE id='other'").fetchone()[0]
        self.reject('STORAGE_INTEGRITY',lambda:self.l.open_snapshot('t','domain','hist',other))
        row=dict(self.l.catalog('t','domain','cat'));labels=json.loads(row['buckets_json']);labels.reverse();body=json.dumps(labels,separators=(',',':'))
        self.l.db.execute('UPDATE histogram_catalogs SET buckets_json=?',(body,))
        self.reject('STORAGE_INTEGRITY',lambda:self.l.open_snapshot('t','domain','hist',original))
        self.l.db.execute('UPDATE histogram_catalogs SET digest=?',(hashlib.sha256(body.encode()).hexdigest(),))
        self.reject('STORAGE_INTEGRITY',lambda:self.l.open_snapshot('t','domain','hist',original))

    def test_operation_and_scalar_vector_ciphertext_substitution_rejected(self):
        register(self.l);register(self.l,'b');register(self.l,'c',False)
        tick(self.l);tick(self.l);tick(self.l)
        for table,column,key in [('operations','seed','id'),('jobs','private_state','operation_id')]:
            original=self.l.db.execute(f'SELECT {column} FROM {table} WHERE {key}=?',('a',)).fetchone()[0]
            for other_id in ('b','c'):
                other=self.l.db.execute(f'SELECT {column} FROM {table} WHERE {key}=?',(other_id,)).fetchone()[0]
                self.l.db.execute(f'UPDATE {table} SET {column}=? WHERE {key}=?',(other,'a'));before=stable(self.l)
                self.reject('STORAGE_INTEGRITY',lambda:tick(self.l));self.assertEqual(stable(self.l),before)
            self.l.db.execute(f'UPDATE {table} SET {column}=? WHERE {key}=?',(original,'a'))
        finish(self.l);self.assertEqual(self.l.audit(),[])

    def test_job_checkpoint_cannot_be_replayed_at_new_pc_or_sequence(self):
        register(self.l);old=raw_job(self.l)['private_state'];tick(self.l);current=dict(raw_job(self.l))
        self.l.db.execute('UPDATE jobs SET private_state=?',(old,));before=stable(self.l)
        self.reject('STORAGE_INTEGRITY',lambda:tick(self.l));self.assertEqual(stable(self.l),before)
        self.l.db.execute('UPDATE jobs SET private_state=?,seq=2',(current['private_state'],))
        self.reject('STORAGE_INTEGRITY',lambda:tick(self.l))

    def test_action_shape_and_work_tampering_reject_before_secret_use(self):
        register(self.l);tick(self.l);original=raw_op(self.l);action=json.loads(original['action']);action['parameters']['bucket_count']=3
        self.l.db.execute('UPDATE operations SET action=?',(json.dumps(action,sort_keys=True,separators=(',',':')),));before=stable(self.l)
        self.reject('STORAGE_INTEGRITY',lambda:tick(self.l));self.assertEqual(stable(self.l),before)
        self.l.db.execute('UPDATE operations SET action=?',(original['action'],));self.l.db.execute('UPDATE jobs SET work=work+1')
        self.reject('SCHEDULE_PROFILE_MISMATCH',lambda:tick(self.l))
        self.reject('STORAGE_INTEGRITY',lambda:self.l.load_private_state(raw_job(self.l)))

    def test_valid_aead_with_wrong_field_width_is_still_rejected(self):
        register(self.l);tick(self.l);op=raw_op(self.l);identity=self.l.operation_identity('t','a',op['digest'])
        bad=self.l.vault.seal('mixed-seed',identity,bytes(32));self.l.db.execute('UPDATE operations SET seed=?',(bad,))
        self.reject('STORAGE_INTEGRITY',lambda:self.l.op('t','a'))
        self.l.db.execute('UPDATE operations SET seed=?',(op['seed'],));job=raw_job(self.l);identity,shape=self.l.private_metadata(job,job['pc'])
        bad=self.l.vault.seal('mixed-job-state',identity,bytes(8));self.l.db.execute('UPDATE jobs SET private_state=?',(bad,))
        self.reject('STORAGE_INTEGRITY',lambda:self.l.load_private_state(raw_job(self.l)))
        self.reject('STORAGE_INTEGRITY',lambda:self.l.protect_operation_field('result','t','a',op['digest'],bytes(8)))
        self.reject('STORAGE_INTEGRITY',lambda:self.l.protect_operation_field('result','t','a',op['digest'],(4).to_bytes(8,'big')*4))

    def test_valid_aead_state_out_of_range_is_rejected(self):
        register(self.l);job=raw_job(self.l);identity,shape=self.l.private_metadata(job,0)
        good=struct.pack('>I4BI',0,1,1,0,0,0)
        for values in [(4,1,1,0,0,0),(0,2,1,0,0,0),(0,1,1,41,0,0),(0,1,1,0,0,4)]:
            data=struct.pack('>I4BI',*values)+good*3;sealed=self.l.vault.seal('mixed-job-state',identity,data)
            self.l.db.execute('UPDATE jobs SET private_state=?',(sealed,))
            self.reject('STORAGE_INTEGRITY',lambda:self.l.load_private_state(raw_job(self.l)))
        self.l.db.execute('UPDATE jobs SET count_value=1')
        self.reject('STORAGE_INTEGRITY',lambda:self.l.load_private_state(raw_job(self.l)))

    def test_result_corruption_or_bare_hash_cannot_be_delivered(self):
        register(self.l);finish(self.l);self.l.admit_delivery('t','a','reader','d','g','s');op=raw_op(self.l)
        for field,bad in [('result',bytes(len(op['result']))),('result_digest',hashlib.sha256(self.l.op('t','a')['result']).hexdigest()),('result_digest',b'not-a-text-token')]:
            self.l.db.execute('UPDATE operations SET '+field+'=?',(bad,));before=stable(self.l)
            self.reject('STORAGE_INTEGRITY',lambda:self.l.emit('t','d','reader','g','s'));self.assertEqual(stable(self.l),before)
            self.l.db.execute('UPDATE operations SET '+field+'=?',(op[field],))
        self.assertEqual(self.l.audit(),[])

    def test_concurrent_identical_tick_returns_same_durable_ciphertext(self):
        register(self.l);gate=threading.Barrier(2)
        def attempt(_):
            l=EncryptedMixedLedger(self.path,clock=lambda:100,vault=vault())
            try:gate.wait();ack=l.advance('t','domain','same',0);return ack,raw_op(l)['seed'],raw_job(l)['private_state']
            finally:l.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(attempt,range(2)))
        self.assertEqual(results[0],results[1]);self.assertEqual(raw_job(self.l)['pc'],1);self.assertEqual(self.l.audit(),[])

    def test_cancel_and_ancestor_revocation_keep_encrypted_state_and_all_cap_rules(self):
        register(self.l);tick(self.l);tape=raw_op(self.l)['seed']
        self.l.advance('t','domain','cancel',1,{'kind':'cancel','operation':'a','actor':'leaf'});finish(self.l)
        self.assertEqual(raw_op(self.l)['state'],'BURNED');self.assertEqual(raw_op(self.l)['seed'],tape)
        register(self.l,'b');self.l.revoke_credential('t','workergrant');finish(self.l)
        self.assertEqual(raw_op(self.l,'b')['state'],'CANCELED')
        self.assertTrue(all(r[0]==E and r[1]==0 for r in self.l.db.execute("SELECT spent,reserved FROM accounts WHERE id LIKE '%:epsilon'")))
        self.assertEqual(self.l.audit(),[])

    def test_wal_files_do_not_contain_tape_key_or_categorical_snapshot_sentinels(self):
        path=Path(self.tmp.name)/'waldb';rows=[hashlib.sha256(bytes([i])).digest()[0]%5 for i in range(128)]
        l=setup(path,rows=rows)
        try:
            l.db.execute('PRAGMA journal_mode=WAL');register(l)
            with patch('histogram_ledger.fresh_tape',return_value=TAPE):tick(l)
            for _ in range(5):tick(l)
            for f in path.parent.glob('waldb*'):
                for secret in (TAPE,MASTER,bytes(rows),json.dumps(rows,separators=(',',':')).encode()):self.assertNotIn(secret,f.read_bytes())
            self.assertEqual(l.audit(),[])
        finally:l.close()

    def test_whole_database_rollback_remains_undetectable_without_external_witness(self):
        register(self.l);copy=Path(self.tmp.name)/'oldcopy';self.l.close();shutil.copyfile(self.path,copy)
        self.l=EncryptedMixedLedger(self.path,clock=lambda:100,vault=vault());finish(self.l)
        self.assertEqual(raw_op(self.l)['state'],'COMMITTED');self.l.close();shutil.copyfile(copy,self.path)
        self.l=EncryptedMixedLedger(self.path,clock=lambda:100,vault=vault())
        self.assertEqual(raw_op(self.l)['state'],'RESERVED');self.assertEqual(self.l.audit(),[])
        self.assertEqual(self.l.db.execute("SELECT spent,reserved FROM accounts WHERE id='domain:epsilon'").fetchone()[:],(0,E))

    def test_six_real_process_crash_cuts_preserve_ciphertexts_vector_and_all_charges(self):
        cuts=[('after_scheduled_claim',0),('before_tick_commit',1),('after_work_step',84),('after_scheduled_result_write',336),('after_account_settle',336),('after_tick_commit',336)]
        for i,(point,pc) in enumerate(cuts):
            with self.subTest(point=point):
                path=Path(self.tmp.name)/('crash'+str(i));l=setup(path);register(l)
                with patch('histogram_ledger.fresh_tape',return_value=TAPE):
                    for _ in range(pc):tick(l)
                seed=raw_op(l)['seed'];l.close();proc=subprocess.run([sys.executable,__file__,'--crash',str(path),point],capture_output=True,timeout=30)
                self.assertEqual(proc.returncode,97,proc.stderr.decode())
                for f in path.parent.glob(path.name+'*'):
                    for secret in (TAPE,MASTER):self.assertNotIn(secret,f.read_bytes())
                l=EncryptedMixedLedger(path,clock=lambda:100,vault=vault())
                try:
                    self.assertEqual(l.audit(),[]);self.assertEqual(l.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                    self.assertEqual(raw_op(l)['seed'],seed);self.assertEqual(raw_job(l)['pc'],337 if point=='after_tick_commit' else pc)
                    if pc==0:tick(l)
                    expected=l.compute_internal('t','a');finish(l);self.assertEqual(l.op('t','a')['result'],expected)
                    self.assertTrue(all(r[0]==E for r in l.db.execute("SELECT spent FROM accounts WHERE id LIKE '%:epsilon'")))
                    self.assertTrue(all(r[0]==D for r in l.db.execute("SELECT spent FROM accounts WHERE id LIKE '%:delta'")))
                    self.assertEqual(l.audit(),[])
                finally:l.close()
                CRASHES.append({'point':point,'preceding_pc':pc})


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash':child(sys.argv[2],sys.argv[3])
    else:
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EncryptedMixedTests));root=Path(__file__).resolve().parent
        names=('encrypted_mixed_ledger.py','test_encrypted_mixed_ledger.py','encrypted_ledger.py','mixed_delegated_ledger.py','test_mixed_delegated_ledger.py','histogram_ledger.py','delegated_ledger.py','signed_ledger.py','scheduled_ledger.py','dp_ledger.py','ledger.py','wire.py','../histogram_kernel.py','../fixed_work_model.py','requirements-crypto.txt')
        report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,actual_process_crash_scenarios=CRASHES,crash_scenario_count=len(CRASHES),
                    whole_database_rollback_negative_control='Old consistent database reopens and audits successfully; external witness still required',
                    source_sha256={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names},python_version=sys.version,sqlite_version=sqlite3.sqlite_version,
                    cryptography_version=__import__('cryptography').__version__,failures=[(str(t),m) for t,m in result.failures],errors=[(str(t),m) for t,m in result.errors],
                    scope='AEAD fixed-public-width fields for signed mixed count/histogram; no authoritative witness, KMS/rotation or authenticated vector network')
        (root/'encrypted_mixed_test_results.json').write_text(json.dumps(report,indent=2)+'\n');sys.exit(0 if result.wasSuccessful() else 1)
