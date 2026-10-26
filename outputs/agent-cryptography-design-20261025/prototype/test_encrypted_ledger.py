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
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from encrypted_ledger import EncryptedLedger, StateVault, Rejected, MAGIC, FIELDS
from delegated_ledger import DelegatedLedger
from dp_ledger import DPLedger, EPSILON_COST as E, DELTA_COST as D
from ledger import Ledger
from scheduled_ledger import ScheduledLedger
from signed_ledger import SignedLedger
from test_delegated_ledger import KEYS, chain_fixture, packet, finish

# Public synthetic fixture secrets. Production keys must never be hard-coded.
MASTER=hashlib.sha256(b'public fixture storage key, not a deployment key').digest()
DEPLOYMENT=b'fixture-vault-01'
SEED=hashlib.sha256(b'public fixture private random tape sentinel').digest()
CRASHES=[]


def vault():
    return StateVault(MASTER,DEPLOYMENT)


def setup(path, rows=None):
    rows=[0,1] if rows is None else rows
    l=EncryptedLedger.create(path,clock=lambda:100,vault=vault())
    l.provision_domain('t','domain',len(rows),3*E,3*D)
    l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
    l.install_snapshot('t','domain','snap',rows)
    for name,key in KEYS.items():
        pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',pub)
    l.bind_root_authority('t','root',b'authority')
    return l


def register(l, oid='a', proof_id=b'p'*16):
    chain=chain_fixture(); raw,proof=packet(l,chain,oid,proof_id)
    return l.register_delegated(raw,proof,chain)


def step(l, fault=lambda point:None):
    t=l.db.execute('SELECT tick FROM schedulers').fetchone()[0]
    return l.advance('t','domain','tick'+str(t),t,fault=fault)


def raw_op(l,oid='a'):
    return dict(l.db.execute('SELECT * FROM operations WHERE id=?',(oid,)).fetchone())


def raw_job(l,oid='a'):
    return l.db.execute('SELECT * FROM jobs WHERE operation_id=?',(oid,)).fetchone()


def stable(l):
    # Exclude clock_floor: a rejected attempt intentionally retains its clock.
    return {name:[tuple(r) for r in l.db.execute('SELECT * FROM '+name)] for name in
            ('accounts','charges','operations','jobs','schedulers','tick_requests','publication_events','deliveries')}


def child(path,point):
    l=EncryptedLedger(path,clock=lambda:100,vault=vault())
    def fault(here):
        if here==point:os._exit(96)
    with patch('scheduled_ledger.secrets.token_bytes',side_effect=lambda n:SEED if n==32 else os.urandom(n)):
        step(l,fault)
    raise RuntimeError('crash cut not reached')


class VaultTests(unittest.TestCase):
    def test_rfc8452_aes256_known_answers(self):
        a=AESGCMSIV(b'\x01'+bytes(31));nonce=b'\x03'+bytes(11)
        for plaintext,hex_result in ((b'','07f5f4169bbf55a8400cd47ea6fd400f'),
                (b'\x01'+bytes(7),'c2ef328e5c71c83b843122130f7364b761e0b97427e3df28')):
            self.assertEqual(a.encrypt(nonce,plaintext,b''),bytes.fromhex(hex_result))
            self.assertEqual(a.decrypt(nonce,bytes.fromhex(hex_result),b''),plaintext)

    def test_envelope_context_key_and_deployment_substitution(self):
        v=vault();identity=('t','a','action-digest');sealed=v.seal('seed',identity,SEED)
        self.assertEqual(v.open('seed',identity,sealed),SEED)
        cases=[(v,'result',identity),(v,'seed',('u','a','action-digest')),
               (v,'seed',('t','b','action-digest')),(v,'seed',('t','a','changed-action')),
               (StateVault(bytes(32),DEPLOYMENT),'seed',identity),
               (StateVault(MASTER,b'fixture-vault-02'),'seed',identity)]
        for obj,kind,ids in cases:
            with self.subTest(kind=kind,ids=ids),self.assertRaisesRegex(Rejected,'STORAGE_INTEGRITY'):
                obj.open(kind,ids,sealed)

    def test_all_envelope_bytes_and_truncations_reject(self):
        v=vault();identity=('t','a','digest');sealed=v.seal('seed',identity,SEED)
        for i in range(len(sealed)):
            changed=bytearray(sealed);changed[i]^=1
            with self.subTest(byte=i),self.assertRaisesRegex(Rejected,'STORAGE_INTEGRITY'):
                v.open('seed',identity,bytes(changed))
        for invalid in [sealed[:i] for i in range(len(sealed))]+[sealed+b'x',b'x'*65573,'plaintext']:
            with self.assertRaisesRegex(Rejected,'STORAGE_INTEGRITY'):v.open('seed',identity,invalid)

    def test_ciphertext_lengths_are_fixed_by_public_plaintext_size(self):
        v=vault()
        for size in (0,8,32,65535,65536):
            a=v.seal('snapshot',('t','d','s'),bytes(size));b=v.seal('snapshot',('t','d','s'),b'\x01'*size)
            self.assertEqual(len(a),size+36);self.assertEqual(len(a),len(b))
            self.assertEqual(v.open('snapshot',('t','d','s'),b),b'\x01'*size)
        with self.assertRaisesRegex(Rejected,'INVALID_SECRET_RECORD'):v.seal('seed',(),bytes(65537))

    def test_result_binding_is_contextual_and_uses_separate_purpose(self):
        v=vault();r=bytes(8)
        tokens={v.bind_result((t,o,'digest'),r) for t,o in [('t','a'),('u','a'),('t','b')]}
        self.assertEqual(len(tokens),3)
        self.assertNotIn(hashlib.sha256(r).hexdigest(),tokens)
        self.assertNotEqual(v.bind_result(('t','a','digest'),r),v.key_check)

    def test_nonce_reuse_known_limitation_remains_authenticated(self):
        v=vault();ids=('t','a','digest')
        with patch('encrypted_ledger.secrets.token_bytes',return_value=bytes(12)):
            a=v.seal('seed',ids,bytes(32));same=v.seal('seed',ids,bytes(32));b=v.seal('seed',ids,b'1'*32)
        # Equality under repeated nonce is explicitly NOT hidden by this test.
        self.assertEqual(a,same);self.assertNotEqual(a,b)
        self.assertEqual(v.open('seed',ids,b),b'1'*32)


class EncryptedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'db';self.l=setup(self.path)
    def tearDown(self):
        self.l.close();self.tmp.cleanup()
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()
    def reopen(self):
        self.l.close();self.l=EncryptedLedger(self.path,clock=lambda:100,vault=vault())

    def test_end_to_end_protects_every_private_column_and_delivers_same_result(self):
        register(self.l)
        with patch('scheduled_ledger.secrets.token_bytes',side_effect=lambda n:SEED if n==32 else os.urandom(n)):
            step(self.l)
        seed=self.l.op('t','a')['seed'];self.assertEqual(seed,SEED)
        expected=self.l.compute_internal('t','a');finish(self.l)
        op=raw_op(self.l);job=raw_job(self.l)
        self.assertEqual((len(op['seed']),len(op['result']),len(job['private_state'])),(68,44,44))
        for value in (op['seed'],op['result'],job['private_state'],self.l.db.execute('SELECT rows_json FROM snapshots').fetchone()[0]):
            self.assertTrue(value.startswith(MAGIC))
        self.assertEqual(tuple(job[k] for k in FIELDS),(0,1,1,0,0))
        self.assertTrue(op['result_digest'].startswith('hmac-v1:'))
        self.assertNotEqual(op['result_digest'],hashlib.sha256(expected).hexdigest())
        self.l.admit_delivery('t','a','reader','ticket','gw','session')
        self.reopen()
        self.assertEqual(self.l.op('t','a')['seed'],seed)
        self.assertEqual(self.l.emit('t','ticket','reader','gw','session'),expected)
        self.assertEqual(self.l.audit(),[])
        for p in self.path.parent.glob('db*'):
            self.assertNotIn(SEED,p.read_bytes());self.assertNotIn(MASTER,p.read_bytes())

    def test_plain_service_wrong_key_and_missing_key_cannot_open(self):
        for cls in (Ledger,DPLedger,ScheduledLedger,SignedLedger,DelegatedLedger):
            self.reject('STORAGE_PROFILE_MISMATCH',lambda:cls(self.path,clock=lambda:100))
        before=stable(self.l)
        for v in (StateVault(bytes(32),DEPLOYMENT),StateVault(MASTER,b'fixture-vault-02')):
            self.reject('STORAGE_PROFILE_MISMATCH',lambda:EncryptedLedger(self.path,clock=lambda:100,vault=v))
        with self.assertRaises(TypeError):EncryptedLedger(self.path)
        self.assertEqual(stable(self.l),before)

    def test_encrypted_profile_refuses_existing_plaintext_database(self):
        p=Path(self.tmp.name)/'plain';plain=DelegatedLedger.create(p,clock=lambda:100);plain.close()
        before=p.read_bytes()
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:EncryptedLedger.create(p,clock=lambda:100,vault=vault()))
        self.assertEqual(p.read_bytes(),before)

    def test_metadata_profile_is_rechecked_before_every_transaction(self):
        register(self.l);self.l.db.execute("UPDATE storage_metadata SET profile='synthetic-plaintext-v1'")
        before=stable(self.l);self.reject('STORAGE_PROFILE_MISMATCH',lambda:step(self.l))
        self.assertEqual(stable(self.l),before)

    def test_seed_corruption_does_not_refund_resample_or_advance(self):
        register(self.l);step(self.l);raw=raw_op(self.l)['seed']
        self.l.db.execute('UPDATE operations SET seed=?',(raw[:-1]+bytes([raw[-1]^1]),))
        before=stable(self.l)
        with patch('scheduled_ledger.secrets.token_bytes',side_effect=AssertionError('must not resample')):
            for _ in range(2):self.reject('STORAGE_INTEGRITY',lambda:step(self.l))
        self.assertEqual(stable(self.l),before)
        self.l.db.execute('UPDATE operations SET seed=?',(raw,));self.reopen();finish(self.l)
        self.assertEqual(self.l.audit(),[])

    def test_snapshot_substitution_after_durable_l1_preserves_held_budget(self):
        self.l.install_snapshot('t','domain','other',[1,0])
        sealed=self.l.db.execute("SELECT rows_json FROM snapshots WHERE id='other'").fetchone()[0]
        register(self.l);self.l.db.execute("UPDATE snapshots SET rows_json=? WHERE id='snap'",(sealed,))
        step(self.l)  # L1 commits without reading the corrupted private snapshot.
        before=stable(self.l);self.reject('STORAGE_INTEGRITY',lambda:step(self.l))
        self.assertEqual(stable(self.l),before);self.assertEqual(raw_op(self.l)['state'],'STARTED')
        self.reject('STORAGE_INTEGRITY',self.l.audit)

    def test_private_state_cannot_be_replayed_at_a_later_step(self):
        register(self.l);old=raw_job(self.l)['private_state'];step(self.l)
        self.l.db.execute('UPDATE jobs SET private_state=?',(old,))
        before=stable(self.l);self.reject('STORAGE_INTEGRITY',lambda:step(self.l))
        self.assertEqual(stable(self.l),before)

    def test_seed_and_job_state_cannot_move_between_operations(self):
        register(self.l);register(self.l,'b',b'q'*16);step(self.l);step(self.l)
        for table,column,key in [('operations','seed','id'),('jobs','private_state','operation_id')]:
            a=self.l.db.execute(f'SELECT {column} FROM {table} WHERE {key}=?',('a',)).fetchone()[0]
            b=self.l.db.execute(f'SELECT {column} FROM {table} WHERE {key}=?',('b',)).fetchone()[0]
            self.l.db.execute(f'UPDATE {table} SET {column}=? WHERE {key}=?',(b,'a'))
            before=stable(self.l);self.reject('STORAGE_INTEGRITY',lambda:step(self.l))
            self.assertEqual(stable(self.l),before)
            self.l.db.execute(f'UPDATE {table} SET {column}=? WHERE {key}=?',(a,'a'))
        finish(self.l);self.assertEqual(self.l.audit(),[])

    def test_result_or_binding_corruption_cannot_be_delivered(self):
        register(self.l);finish(self.l);self.l.admit_delivery('t','a','reader','ticket','gw','session')
        original=raw_op(self.l)
        for field,value in [('result',bytes(44)),('result_digest',hashlib.sha256(self.l.op('t','a')['result']).hexdigest())]:
            self.l.db.execute(f'UPDATE operations SET {field}=?',(value,));before=stable(self.l)
            self.reject('STORAGE_INTEGRITY',lambda:self.l.emit('t','ticket','reader','gw','session'))
            self.assertEqual(stable(self.l),before)
            self.l.db.execute(f'UPDATE operations SET {field}=?',(original[field],))
        self.assertEqual(self.l.audit(),[])

    def test_cancel_and_revocation_preserve_encrypted_state_and_accounting(self):
        register(self.l);step(self.l);seed=raw_op(self.l)['seed']
        self.l.advance('t','domain','cancel',1,{'kind':'cancel','operation':'a','actor':'leaf'})
        self.reopen();finish(self.l)
        self.assertEqual(raw_op(self.l)['seed'],seed);self.assertEqual(raw_op(self.l)['state'],'BURNED')
        self.assertEqual(raw_job(self.l)['publication'],'WITHHELD')
        register(self.l,'b',b'q'*16);self.l.revoke_credential('t','workergrant',root_id='root',kind='delegation',issuer_kid=b'manager');finish(self.l)
        self.assertEqual(raw_op(self.l,'b')['state'],'CANCELED')
        self.assertEqual(self.l.db.execute("SELECT spent,free FROM accounts WHERE id='domain:epsilon'").fetchone()[:],(E,2*E))
        self.assertEqual(self.l.audit(),[])

    def test_concurrent_duplicate_tick_has_one_durable_ciphertext(self):
        register(self.l);barrier=threading.Barrier(2)
        def run():
            l=EncryptedLedger(self.path,clock=lambda:100,vault=vault())
            try:
                barrier.wait();return l.advance('t','domain','tick0',0),raw_op(l)['seed']
            finally:l.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:run(),range(2)))
        self.assertEqual(results[0],results[1]);self.assertEqual(raw_job(self.l)['pc'],1)
        self.assertEqual(self.l.audit(),[])

    def test_snapshot_and_private_tape_never_enter_sqlite_wal_as_plaintext(self):
        path=Path(self.tmp.name)/'waldb';rows=[(i*i+3*i+7)%11%2 for i in range(128)]
        l=setup(path,rows);l.db.execute('PRAGMA journal_mode=WAL');register(l)
        with patch('scheduled_ledger.secrets.token_bytes',side_effect=lambda n:SEED if n==32 else os.urandom(n)):
            step(l)
        for _ in range(6):step(l)
        for p in path.parent.glob('waldb*'):
            data=p.read_bytes()
            for secret in (SEED,MASTER,bytes(rows),json.dumps(rows,separators=(',',':')).encode()):
                self.assertNotIn(secret,data)
        self.assertEqual(l.audit(),[]);l.close()

    def test_four_actual_process_crash_cuts_preserve_seed_result_and_charges(self):
        for point,prepare in [('after_scheduled_claim',0),('before_tick_commit',1),
                              ('after_scheduled_result_write',83),('after_tick_commit',83)]:
            with self.subTest(point=point):
                path=Path(self.tmp.name)/point;l=setup(path);register(l)
                with patch('scheduled_ledger.secrets.token_bytes',side_effect=lambda n:SEED if n==32 else os.urandom(n)):
                    for _ in range(prepare):step(l)
                before_seed=raw_op(l)['seed'];l.close()
                proc=subprocess.run([sys.executable,__file__,'--crash',str(path),point],capture_output=True,timeout=30)
                self.assertEqual(proc.returncode,96,proc.stderr.decode())
                # Inspect hot-journal files BEFORE SQLite recovery, too.
                for p in path.parent.glob(point+'*'):
                    for secret in (SEED,MASTER):self.assertNotIn(secret,p.read_bytes())
                l=EncryptedLedger(path,clock=lambda:100,vault=vault());self.assertEqual(l.audit(),[])
                self.assertEqual(raw_job(l)['pc'],84 if point=='after_tick_commit' else prepare)
                self.assertEqual(raw_op(l)['seed'],before_seed)
                if prepare==0:step(l)
                expected=l.compute_internal('t','a');seed=raw_op(l)['seed'];finish(l)
                self.assertEqual(raw_op(l)['seed'],seed)
                self.assertEqual(l.op('t','a')['result'],expected)
                self.assertEqual(l.db.execute("SELECT spent,reserved FROM accounts WHERE id='domain:epsilon'").fetchone()[:],(E,0))
                self.assertEqual(l.audit(),[]);l.close();CRASHES.append(point)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash':child(sys.argv[2],sys.argv[3])
    else:
        suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in (VaultTests,EncryptedTests)])
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        root=Path(__file__).resolve().parent
        sources=('encrypted_ledger.py','test_encrypted_ledger.py','delegated_ledger.py','ledger.py','dp_ledger.py',
                 'scheduled_ledger.py','signed_ledger.py','wire.py','test_delegated_ledger.py','test_signed_ledger.py',
                 '../fixed_work_model.py','requirements-crypto.txt')
        report={'passed':result.wasSuccessful(),'test_methods':result.testsRun,'crash_cut_count':len(CRASHES),
                'actual_process_crash_cuts':CRASHES,'source_sha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in sources},
                'python_version':sys.version,'sqlite_version':sqlite3.sqlite_version,'cryptography_version':__import__('cryptography').__version__,
                'failures':[(str(t),m) for t,m in result.failures],'errors':[(str(t),m) for t,m in result.errors],
                'scope':'AES-256-GCM-SIV field encryption and HMAC result bindings for synthetic delegated counts; external bootstrap key; no KMS, rotation, memory erasure or rollback prevention'}
        (root/'encrypted_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
        sys.exit(0 if result.wasSuccessful() else 1)
