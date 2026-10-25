import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519
from witnessed_mixed_ledger import WitnessedMixedLedger,TLSWitnessedMixedLedger
from witnessed_ledger import ReferenceWitness,Rejected,image_hash
from witness_transport import WitnessTLSService,TLSWitnessClient,TLSWitnessedLedger,trusted_register_peer,trusted_revoke_peer,certificate_fingerprint
from encrypted_mixed_ledger import EncryptedMixedLedger
from mixed_delegated_ledger import MixedDelegatedLedger
from dp_ledger import EPSILON_COST as E,DELTA_COST as D
from test_encrypted_mixed_ledger import vault,register,raw_op,raw_job,TAPE,MASTER
from test_mixed_delegated_ledger import KEYS,chain_fixture,packet,tick,finish
from test_witness_transport import certificates,public

CRASHES=[]
NETWORK_REQUESTS=0
TLS_VERSIONS=set()
COUNTER_LOCK=threading.Lock()


def backup(db,path):
    target=sqlite3.connect(str(path));db.backup(target);target.close()


def populate(l,capacity=3):
    l.provision_domain('t','domain',capacity,4*E,4*D)
    l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
    l.install_catalog('t','domain','cat',['one','two','three','four'])
    rows=([1,2,0] if capacity==3 else [i%5 for i in range(capacity)])
    l.install_histogram_snapshot('t','domain','hist','cat',rows)
    l.install_snapshot('t','domain','count',[int(x!=0) for x in rows])
    for name,key in KEYS.items():l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',public(key))
    l.bind_root_authority('t','root',b'authority');return l


def setup(path,witness):return populate(WitnessedMixedLedger.create(path,clock=lambda:100,vault=vault(),witness=witness))


def crash_child(config_path,point):
    c=json.loads(Path(config_path).read_text())
    if c.get('tls'):
        witness=TLSWitnessClient(port=c['port'],cafile=c['ca'],certfile=c['cert'],keyfile=c['key'],witness_public_key=bytes.fromhex(c['witness_public']))
        cls=TLSWitnessedMixedLedger
    else:witness=ReferenceWitness(c['witness']);cls=WitnessedMixedLedger
    def fault(p):
        if p==point:os._exit(98)
    l=cls(c['ledger'],clock=lambda:100,vault=vault(),witness=witness,witness_fault=fault)
    if c.get('recovery'):l.recover_from_witness(fault)
    else:
        with patch('histogram_ledger.fresh_tape',return_value=TAPE):tick(l,fault)
    raise RuntimeError('cut not reached')


class MixedWitnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.path=self.root/'ledger';self.wp=self.root/'witness'
        self.w=ReferenceWitness(self.wp);self.l=setup(self.path,self.w)
    def tearDown(self):self.l.close();self.w.close();self.tmp.cleanup()
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()
    def clone(self,path):return WitnessedMixedLedger(path,clock=lambda:100,vault=vault(),witness=self.w)
    def crash(self,path,wp,point,recovery=False):
        f=self.root/'child.json';f.write_text(json.dumps(dict(ledger=str(path),witness=str(wp),recovery=recovery)))
        r=subprocess.run([sys.executable,__file__,'--child',str(f),point],capture_output=True,text=True,timeout=30)
        self.assertEqual(r.returncode,98,r.stderr);CRASHES.append({'transport':'reference','point':point})

    def test_stale_prestart_copy_restores_complete_mixed_results_and_every_cap(self):
        register(self.l);register(self.l,'c',False);old=self.root/'old';backup(self.l.db,old);finish(self.l)
        original=self.l.state_image();stale=self.clone(old)
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:tick(stale))
            self.assertEqual(raw_op(stale)['state'],'RESERVED')
            with patch('histogram_ledger.fresh_tape',side_effect=AssertionError('new tape')):stale.recover_from_witness()
            self.assertEqual(stale.state_image(),original)
            self.assertEqual(len(stale.op('t','a')['result']),32);self.assertEqual(len(stale.op('t','c')['result']),8)
            self.assertTrue(all(r[0]==2*E and r[1]==0 for r in stale.db.execute("SELECT spent,reserved FROM accounts WHERE id LIKE '%:epsilon'")))
            self.assertTrue(all(r[0]==2*D and r[1]==0 for r in stale.db.execute("SELECT spent,reserved FROM accounts WHERE id LIKE '%:delta'")))
            self.assertEqual(stale.audit(),[])
        finally:stale.close()

    def test_witness_acceptance_without_local_l1_commit_restores_full_tape(self):
        register(self.l);head=self.w.head(self.l.namespace)
        def lost(p):
            if p=='after_witness_accept':raise ConnectionError('lost witness acknowledgement')
        self.l.witness_fault=lost
        with patch('histogram_ledger.fresh_tape',return_value=TAPE):
            with self.assertRaises(ConnectionError):tick(self.l)
        self.l.witness_fault=lambda p:None
        self.assertEqual(raw_op(self.l)['state'],'RESERVED');self.assertEqual(self.w.head(self.l.namespace)['seq'],head['seq']+1)
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:tick(self.l))
        with patch('histogram_ledger.fresh_tape',side_effect=AssertionError('resample')):
            self.l.recover_from_witness();finish(self.l)
        self.assertEqual(self.l.op('t','a')['seed'],TAPE);self.assertEqual(self.l.audit(),[])

    def test_witness_only_final_vector_and_ancestor_spend_restore_without_new_job_step(self):
        register(self.l)
        for _ in range(336):tick(self.l)
        expected=self.l.compute_internal('t','a');seed=raw_op(self.l)['seed']
        def lost(p):
            if p=='after_witness_accept':raise ConnectionError('lost final reply')
        self.l.witness_fault=lost
        with self.assertRaises(ConnectionError):tick(self.l)
        self.l.witness_fault=lambda p:None
        self.assertEqual(raw_op(self.l)['state'],'STARTED')
        with patch.object(self.l,'advance_private_step',side_effect=AssertionError('new work step')),patch('histogram_ledger.fresh_tape',side_effect=AssertionError('new tape')):
            self.l.recover_from_witness()
        self.assertEqual(raw_op(self.l)['seed'],seed);self.assertEqual(self.l.op('t','a')['result'],expected)
        self.assertEqual(raw_job(self.l)['publication'],'RELEASE')
        self.assertTrue(all(r[0]==E for r in self.l.db.execute("SELECT spent FROM accounts WHERE id LIKE '%:epsilon'")))
        self.assertEqual(self.l.audit(),[])

    def test_catalog_snapshot_links_caps_signatures_and_checkpoint_are_all_witnessed(self):
        register(self.l);tick(self.l);clean=self.l.state_image()
        edits=["UPDATE histogram_catalogs SET buckets_json='[]'",
               "DELETE FROM histogram_snapshots",
               "UPDATE accounts SET free=free+1,total=total+1 WHERE id LIKE 'credential:%:epsilon'",
               "UPDATE signed_actions SET action=x'00'",
               "UPDATE jobs SET private_state=x'00'",
               "UPDATE operations SET seed=x'00'"]
        for statement in edits:
            self.l.db.execute(statement)
            self.reject('LOCAL_STATE_DIVERGED',lambda:tick(self.l))
            self.l.recover_from_witness();self.assertEqual(self.l.state_image(),clean)
        self.assertEqual(self.l.audit(),[])

    def test_partial_vector_snapshot_restores_exact_encrypted_progress(self):
        register(self.l)
        for _ in range(169):tick(self.l)
        old_state=dict(raw_job(self.l));old_op=raw_op(self.l)
        restored=WitnessedMixedLedger.restore_new(self.root/'fresh',clock=lambda:100,vault=vault(),witness=self.w)
        try:
            self.assertEqual(dict(raw_job(restored)),old_state);self.assertEqual(raw_op(restored),old_op)
            finish(restored);self.assertEqual(restored.op('t','a')['result'],restored.compute_internal('t','a'))
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:tick(self.l));self.assertEqual(restored.audit(),[])
        finally:restored.close()

    def test_revocations_used_proofs_and_rejected_attempt_clock_survive_restore(self):
        chain=chain_fixture(self.l);raw,proof=packet(self.l,chain);old=self.root/'old';backup(self.l.db,old)
        self.l.register_delegated(raw,proof,chain);self.l.revoke_credential('t','workergrant');self.l.clock=lambda:200
        self.reject('INVALID_COMMAND',lambda:self.l.advance('t','domain','bad',0,{'kind':'invalid'}))
        stale=self.clone(old)
        try:
            stale.recover_from_witness()
            self.assertEqual(stale.db.execute('SELECT COUNT(*) FROM used_proofs').fetchone()[0],1)
            self.assertEqual(stale.db.execute('SELECT observed FROM clock_floor').fetchone()[0],200)
            self.reject('CLOCK_ROLLBACK',lambda:tick(stale));stale.clock=lambda:200
            self.reject('CREDENTIAL_REVOKED',lambda:stale.register_delegated(raw,proof,chain))
            self.assertEqual(stale.audit(),[])
        finally:stale.close()

    def test_local_result_ticket_and_handoff_record_restore_with_original_vector(self):
        register(self.l);finish(self.l);self.l.admit_delivery('t','a','reader','d','g','s')
        old=self.root/'old';backup(self.l.db,old);result=self.l.emit('t','d','reader','g','s');self.l.revoke_credential('t','root')
        stale=self.clone(old)
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:stale.emit('t','d','reader','g','s'))
            stale.recover_from_witness();self.assertEqual(stale.db.execute('SELECT handoff_admitted FROM deliveries').fetchone()[0],1)
            self.assertEqual(stale.emit('t','d','reader','g','s'),result)
            self.reject('ACTION_OR_KEY_INACTIVE',lambda:stale.admit_delivery('t','a','reader','new','g','s'));self.assertEqual(stale.audit(),[])
        finally:stale.close()

    def test_two_cloned_signed_writers_have_only_one_authoritative_l1(self):
        register(self.l);paths=[self.root/'clone1',self.root/'clone2']
        for path in paths:backup(self.l.db,path)
        gate=threading.Barrier(2)
        def run(path):
            witness=ReferenceWitness(self.wp);l=WitnessedMixedLedger(path,clock=lambda:100,vault=vault(),witness=witness,
                witness_fault=lambda p:gate.wait(timeout=10) if p=='before_witness_accept' else None)
            try:
                try:tick(l);return 'accepted'
                except Rejected as e:return str(e)
            finally:l.close();witness.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:outcomes=list(pool.map(run,paths))
        self.assertCountEqual(outcomes,['accepted','WITNESS_CAS_CONFLICT'])
        self.l.recover_from_witness();self.assertEqual(raw_job(self.l)['pc'],1);self.assertEqual(self.l.audit(),[])

    def test_witness_image_contains_mixed_metadata_and_ciphertext_only_for_secrets(self):
        register(self.l)
        with patch('histogram_ledger.fresh_tape',return_value=TAPE):tick(self.l)
        image=self.w.head(self.l.namespace,True)['image'];state=json.loads(image)
        for table in ('histogram_catalogs','histogram_snapshots','signed_actions','credentials','operation_chains','accounts','jobs','operations'):
            self.assertIn(table,state['rows'])
        for secret in (TAPE,MASTER,TAPE.hex().encode(),MASTER.hex().encode()):self.assertNotIn(secret,image)
        restored=WitnessedMixedLedger.restore_new(self.root/'restore',clock=lambda:100,vault=vault(),witness=self.w)
        try:self.assertEqual(restored.op('t','a')['seed'],TAPE);self.assertEqual(restored.audit(),[])
        finally:restored.close()

    def test_corrupt_or_incompatible_image_and_changed_head_leave_local_copy_intact(self):
        register(self.l);old=self.root/'old';backup(self.l.db,old);tick(self.l);stale=self.clone(old)
        try:
            before=stale.state_image();head=self.w.head(stale.namespace,True)
            self.w.db.execute('UPDATE heads SET image=?',(head['image']+b'x',))
            self.reject('WITNESS_IMAGE_CORRUPT',stale.recover_from_witness);self.assertEqual(stale.state_image(),before)
            self.w.db.execute('UPDATE heads SET image=?',(head['image'],))
            def interleave(p):
                if p=='after_recovery_delete':tick(self.l)
            self.reject('WITNESS_CHANGED_DURING_RECOVERY',lambda:stale.recover_from_witness(interleave));self.assertEqual(stale.state_image(),before)
            stale.db.execute('CREATE TABLE unexpected (x TEXT)')
            self.reject('WITNESS_SCHEMA_MISMATCH',stale.recover_from_witness)
        finally:stale.close()

    def test_unavailable_or_missing_witness_never_reinitializes_or_refunds(self):
        register(self.l);before=raw_op(self.l)
        with patch.object(self.w,'head',side_effect=ConnectionError('offline')):
            with self.assertRaises(ConnectionError):tick(self.l)
        self.assertEqual(raw_op(self.l),before)
        empty=ReferenceWitness(self.root/'empty');self.l.witness=empty
        try:
            self.reject('WITNESS_UNINITIALIZED',lambda:tick(self.l));self.reject('WITNESS_UNINITIALIZED',self.l.recover_from_witness)
            self.assertEqual(empty.db.execute('SELECT COUNT(*) FROM heads').fetchone()[0],0)
        finally:self.l.witness=self.w;empty.close()

    def test_image_growth_limit_fails_closed_without_losing_seed_or_held_charges(self):
        register(self.l);tick(self.l);before=self.l.state_image();head=self.w.head(self.l.namespace);seed=raw_op(self.l)['seed']
        # Simulate reaching the public 16 MiB profile ceiling without allocating
        # a large test history; the same image_hash size check is exercised.
        with patch('witnessed_ledger.MAX_IMAGE',len(before)+1),patch('histogram_ledger.fresh_tape',side_effect=AssertionError('new noise')):
            self.reject('INVALID_WITNESS_IMAGE',lambda:tick(self.l))
        self.assertEqual(self.l.state_image(),before);self.assertEqual(self.w.head(self.l.namespace),head)
        self.assertEqual(raw_op(self.l)['seed'],seed);self.assertEqual(raw_op(self.l)['state'],'STARTED')
        self.assertTrue(all(r[0]==E and r[1]==0 for r in self.l.db.execute("SELECT reserved,spent FROM accounts WHERE id LIKE '%:epsilon'")))
        self.assertEqual(self.l.audit(),[])

    def test_unwitnessed_profiles_cannot_open_or_restore_this_storage(self):
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:EncryptedMixedLedger(self.path,vault=vault()))
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:MixedDelegatedLedger(self.path))
        self.reject('FRESH_REPLICA_REQUIRED',lambda:WitnessedMixedLedger.restore_new(self.path,vault=vault(),witness=self.w))

    def test_rollback_of_both_trusted_witness_and_ledger_remains_undetectable(self):
        register(self.l);old=self.root/'both-ledger';oldw=self.root/'both-witness';backup(self.l.db,old);backup(self.w.db,oldw);tick(self.l)
        w=ReferenceWitness(oldw);l=WitnessedMixedLedger(old,clock=lambda:100,vault=vault(),witness=w)
        try:self.assertEqual(l.audit(),[]);self.assertEqual(raw_op(l)['state'],'RESERVED')
        finally:l.close();w.close()

    def test_four_commit_and_three_recovery_real_process_death_cuts(self):
        for point in ('before_witness_accept','after_witness_accept','after_local_anchor_write','after_tick_commit'):
            path=self.root/point;wp=self.root/(point+'-w');w=ReferenceWitness(wp);l=setup(path,w);register(l);head=w.head(l.namespace);l.close();w.close()
            self.crash(path,wp,point);w=ReferenceWitness(wp);l=WitnessedMixedLedger(path,clock=lambda:100,vault=vault(),witness=w)
            try:
                accepted=point!='before_witness_accept';self.assertEqual(w.head(l.namespace)['seq'],head['seq']+int(accepted))
                l.recover_from_witness();self.assertEqual(raw_job(l)['pc'],int(accepted))
                if accepted:self.assertEqual(l.op('t','a')['seed'],TAPE)
                else:tick(l)
                expected=l.compute_internal('t','a');finish(l);self.assertEqual(l.op('t','a')['result'],expected);self.assertEqual(l.audit(),[])
            finally:l.close();w.close()
        register(self.l);old=self.root/'recover-old';backup(self.l.db,old);tick(self.l);saved=self.l.state_image()
        for point in ('after_recovery_delete','before_recovery_commit','after_recovery_commit'):
            path=self.root/point;source=sqlite3.connect(str(old));backup(source,path);source.close();self.crash(path,self.wp,point,True)
            l=self.clone(path)
            try:
                if point!='after_recovery_commit':self.reject('WITNESS_RECOVERY_REQUIRED',lambda:tick(l))
                l.recover_from_witness();self.assertEqual(l.state_image(),saved);self.assertEqual(l.audit(),[])
            finally:l.close()


class TLSMixedWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ct=tempfile.TemporaryDirectory();cls.certs=certificates(cls.ct.name);cls.signer=ed25519.Ed25519PrivateKey.generate();cls.pub=public(cls.signer)
    @classmethod
    def tearDownClass(cls):cls.ct.cleanup()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.path=self.root/'ledger';self.wp=self.root/'witness';self.ns=vault().deployment_id.hex()
        for role in ('admin','writer','restorer','observer'):trusted_register_peer(self.wp,self.ns,certificate_fingerprint(self.certs[role][0]),role)
        cert,key=self.certs['server'];self.server=WitnessTLSService(self.wp,cafile=self.certs['ca'],certfile=cert,keyfile=key,signing_key=self.signer)
        original=self.server.dispatch
        def observed(*args):
            global NETWORK_REQUESTS
            with COUNTER_LOCK:NETWORK_REQUESTS+=1
            return original(*args)
        self.server.dispatch=observed;self.server.__enter__();self.writer=self.client('writer')
        self.l=TLSWitnessedMixedLedger.create(self.path,clock=lambda:100,vault=vault(),witness=self.client('admin'));self.l.witness=self.writer;populate(self.l)
    def tearDown(self):self.l.close();self.server.__exit__();self.tmp.cleanup()
    def client(self,role,**kwargs):
        cert,key=self.certs[role];client=TLSWitnessClient(port=self.server.port,cafile=self.certs['ca'],certfile=cert,keyfile=key,witness_public_key=kwargs.pop('witness_public_key',self.pub),**kwargs)
        original=client.exchange
        def exchange(*args):
            result=original(*args)
            if client.last_tls_version:TLS_VERSIONS.add(client.last_tls_version)
            return result
        client.exchange=exchange;return client
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()

    def test_authenticated_complete_vector_restore_and_stale_local_fencing(self):
        register(self.l);old=self.root/'old';backup(self.l.db,old);finish(self.l)
        stale=TLSWitnessedMixedLedger(old,clock=lambda:100,vault=vault(),witness=self.client('writer'))
        try:
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:tick(stale));stale.recover_from_witness()
            self.assertEqual(stale.state_image(),self.l.state_image());self.assertEqual(len(stale.op('t','a')['result']),32)
            self.assertEqual(stale.audit(),[])
        finally:stale.close()
        self.assertIn(self.writer.last_tls_version,('TLSv1.2','TLSv1.3'))

    def test_server_committed_but_dropped_cas_reply_requires_authenticated_recovery(self):
        register(self.l);fired=[]
        def drop(point,request):
            if point=='after_dispatch' and request['method']=='cas' and not fired:fired.append(True);raise OSError('drop accepted response')
        self.server.fault=drop
        with patch('histogram_ledger.fresh_tape',return_value=TAPE):
            with self.assertRaises((OSError,Rejected)):tick(self.l)
        self.server.fault=lambda *args:None
        self.assertEqual(raw_op(self.l)['state'],'RESERVED');self.reject('WITNESS_RECOVERY_REQUIRED',lambda:tick(self.l))
        with patch('histogram_ledger.fresh_tape',side_effect=AssertionError('new sample')):self.l.recover_from_witness()
        self.assertEqual(self.l.op('t','a')['seed'],TAPE);self.assertEqual(self.l.audit(),[])

    def test_restorer_cannot_write_and_observer_cannot_restore_image(self):
        register(self.l);tick(self.l)
        restored=TLSWitnessedMixedLedger.restore_new(self.root/'restored',clock=lambda:100,vault=vault(),witness=self.client('restorer'))
        try:
            self.assertEqual(restored.state_image(),self.l.state_image());before=restored.state_image()
            self.reject('WITNESS_ACCESS_DENIED',lambda:tick(restored));self.assertEqual(restored.state_image(),before)
        finally:restored.close()
        self.reject('WITNESS_ACCESS_DENIED',lambda:TLSWitnessedMixedLedger.restore_new(self.root/'observer',clock=lambda:100,vault=vault(),witness=self.client('observer')))

    def test_revoked_or_wrong_witness_identity_blocks_progress_without_fallback(self):
        register(self.l);before=self.l.state_image();wrong=self.client('writer',witness_public_key=bytes(32));self.l.witness=wrong
        self.reject('INVALID_SIGNATURE',lambda:tick(self.l));self.assertEqual(self.l.state_image(),before);self.l.witness=self.writer
        trusted_revoke_peer(self.wp,self.ns,certificate_fingerprint(self.certs['writer'][0]))
        self.reject('WITNESS_ACCESS_DENIED',lambda:tick(self.l));self.assertEqual(self.l.state_image(),before)
        ref=ReferenceWitness(self.root/'reference')
        try:self.reject('AUTHENTICATED_WITNESS_REQUIRED',lambda:TLSWitnessedMixedLedger(self.path,vault=vault(),witness=ref))
        finally:ref.close()
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:TLSWitnessedLedger(self.path,vault=vault(),witness=self.client('admin')))

    def test_authenticated_image_larger_than_cbor_limit_preserves_max_capacity_snapshot(self):
        self.l.provision_domain('t','large',65535,E,D);self.l.install_catalog('t','large','cat',['one','two','three','four'])
        rows=[i%5 for i in range(65535)];self.l.install_histogram_snapshot('t','large','hist','cat',rows)
        head=self.writer.head(self.ns,True);self.assertGreater(len(head['image']),65536)
        restored=TLSWitnessedMixedLedger.restore_new(self.root/'large',clock=lambda:100,vault=vault(),witness=self.client('restorer'))
        try:
            self.assertEqual(restored.state_image(),head['image'])
            sealed=restored.db.execute("SELECT rows_json FROM snapshots WHERE domain_id='large'").fetchone()[0]
            self.assertEqual(restored.open_snapshot('t','large','hist',sealed),rows);self.assertEqual(restored.audit(),[])
        finally:restored.close()

    def test_real_process_exit_after_authenticated_final_cas_recovers_vector_and_caps(self):
        register(self.l)
        for _ in range(336):tick(self.l)
        expected=self.l.compute_internal('t','a');seed=raw_op(self.l)['seed']
        config=dict(tls=True,ledger=str(self.path),port=self.server.port,ca=str(self.certs['ca']),cert=str(self.certs['writer'][0]),key=str(self.certs['writer'][1]),witness_public=self.pub.hex())
        f=self.root/'child.json';f.write_text(json.dumps(config))
        result=subprocess.run([sys.executable,__file__,'--child',str(f),'after_witness_accept'],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,98,result.stderr);CRASHES.append({'transport':'mTLS','point':'after_witness_accept_final_vector'})
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:tick(self.l))
        with patch.object(self.l,'advance_private_step',side_effect=AssertionError('new business work')):self.l.recover_from_witness()
        self.assertEqual(raw_op(self.l)['seed'],seed);self.assertEqual(self.l.op('t','a')['result'],expected)
        self.assertTrue(all(r[0]==E for r in self.l.db.execute("SELECT spent FROM accounts WHERE id LIKE '%:epsilon'")));self.assertEqual(self.l.audit(),[])


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':crash_child(sys.argv[2],sys.argv[3])
    else:
        suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in (MixedWitnessTests,TLSMixedWitnessTests)])
        result=unittest.TextTestRunner(verbosity=2).run(suite);root=Path(__file__).resolve().parent
        names=('witnessed_mixed_ledger.py','test_witnessed_mixed_ledger.py','witnessed_ledger.py','witness_transport.py','encrypted_mixed_ledger.py','encrypted_ledger.py','mixed_delegated_ledger.py','histogram_ledger.py','delegated_ledger.py','signed_ledger.py','scheduled_ledger.py','dp_ledger.py','ledger.py','wire.py','test_encrypted_mixed_ledger.py','test_mixed_delegated_ledger.py','test_witness_transport.py','../histogram_kernel.py','../fixed_work_model.py','requirements-crypto.txt')
        report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,actual_process_crash_scenarios=CRASHES,crash_scenario_count=len(CRASHES),
                    authenticated_server_requests=NETWORK_REQUESTS,observed_tls_versions=sorted(TLS_VERSIONS),ssl_library=ssl.OPENSSL_VERSION,
                    source_sha256={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names},python_version=sys.version,sqlite_version=sqlite3.sqlite_version,
                    failures=[(str(t),m) for t,m in result.failures],errors=[(str(t),m) for t,m in result.errors],
                    negative_control='Rolling back both local ledger and trusted witness remains undetectable',
                    scope='Full signed encrypted mixed state recovery, reference witness and authenticated loopback mTLS; witness nonrollback/linearizability assumed; no vector result transport or production failure-domain guarantee')
        (root/'witnessed_mixed_test_results.json').write_text(json.dumps(report,indent=2)+'\n');sys.exit(0 if result.wasSuccessful() else 1)
