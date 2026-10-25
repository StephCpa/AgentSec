import ast
import concurrent.futures
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from contribution_ingestion import ContributionLedger, compile_contributions, RULE
from witnessed_ledger import ReferenceWitness
from witnessed_mixed_ledger import WitnessedMixedLedger
from ledger import Rejected
from dp_ledger import EPSILON_COST as E, DELTA_COST as D
from test_encrypted_mixed_ledger import vault, register
from test_mixed_delegated_ledger import KEYS, finish
from test_witness_transport import public

HERE = Path(__file__).resolve().parent
USERS = tuple(hashlib.sha256(('synthetic-user-'+str(i)).encode()).digest() for i in range(3))
RECORDS = [(USERS[0], 4), (USERS[0], 1), (USERS[0], 1), (USERS[1], 2), (USERS[2], 0)]
LINEAGE = b'L'*32
CUTS = []
METRICS = {}


def setup(path, witness):
    l = ContributionLedger.create(path, clock=lambda:100, vault=vault(), witness=witness)
    l.provision_domain('t', 'domain', 3, 4*E, 4*D)
    l.authorize_root('t', 'domain', 'root', 'manager', 'reader', expires_at=1000)
    l.install_catalog('t', 'domain', 'cat', ['one', 'two', 'three', 'four'])
    l.bind_contribution_domain('t', 'domain', LINEAGE, USERS)
    for name, key in KEYS.items():
        l.install_key('t', name.encode(), name, 'root' if name == 'authority' else 'instance', public(key))
    l.bind_root_authority('t', 'root', b'authority')
    return l


def ingest(l, **kwargs):
    return l.ingest_pair('t', 'domain', 'batch', 'cat', 'count', 'hist', RECORDS, **kwargs)


def child(path, wp, point):
    w = ReferenceWitness(wp)
    def fault(p):
        if p == point: os._exit(96)
    l = ContributionLedger(path, clock=lambda:100, vault=vault(), witness=w, witness_fault=fault)
    ingest(l, fault=fault)
    raise RuntimeError('cut not reached')


class ContributionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.path = self.root/'db'; self.wp = self.root/'witness'
        self.w = ReferenceWitness(self.wp); self.l = setup(self.path, self.w)

    def tearDown(self):
        self.l.close(); self.w.close(); self.tmp.cleanup()

    def reject(self, code, call):
        with self.assertRaisesRegex(Rejected, '^'+code+'$'): call()

    def read(self, sid):
        raw = self.l.db.execute('SELECT rows_json FROM snapshots WHERE id=?', (sid,)).fetchone()[0]
        return self.l.open_snapshot('t', 'domain', sid, raw)

    def test_exhaustive_user_removal_is_one_slot_one_bucket(self):
        # Each user's records reduce to any subset of 3 positive labels.
        # Exhaustive subsets cover every possible min rule outcome, not all
        # record sequences. Duplicate/order invariance is checked separately.
        cases = edges = 0
        for masks in itertools.product(range(8), repeat=3):
            records = [(u, b+1) for u, mask in zip(USERS, masks) for b in range(3) if mask & (1 << b)]
            c, h = compile_contributions(USERS, records, 3)
            for i, u in enumerate(USERS):
                c2, h2 = compile_contributions(USERS, [r for r in records if r[0] != u], 3)
                self.assertEqual(c, [int(x != 0) for x in h])
                self.assertEqual([h[j] for j in range(3) if j != i], [h2[j] for j in range(3) if j != i])
                self.assertEqual(h2[i], 0)
                v = [h.count(b) for b in range(1, 4)]; v2 = [h2.count(b) for b in range(1, 4)]
                self.assertLessEqual(sum(abs(a-b) for a,b in zip(v,v2)), 1)
                self.assertLessEqual(abs(sum(c)-sum(c2)), 1)
                edges += 1
            cases += 1
        METRICS.update(subset_datasets=cases, directed_removal_checks=edges)

    def test_duplicates_order_and_ineligible_records(self):
        expected = ([1,1,0], [1,2,0])
        for records in (RECORDS, list(reversed(RECORDS)), RECORDS*30, RECORDS+[(USERS[2],0)]*5):
            self.assertEqual(compile_contributions(USERS, records, 4), expected)
        self.assertEqual(compile_contributions(USERS, [], 4), ([0]*3, [0]*3))

    def test_negative_controls_replacement_aliases_and_joint_release(self):
        _, a = compile_contributions(USERS, [(USERS[0],1)], 4)
        _, b = compile_contributions(USERS, [(USERS[0],2)], 4)
        self.assertEqual(sum(abs(a.count(j)-b.count(j)) for j in range(1,5)), 2)
        c, h = compile_contributions(USERS, [(USERS[0],1),(USERS[1],2)], 4)
        self.assertEqual(sum(c), 2)  # Same human assigned two tokens defeats identity premise.
        c, h = compile_contributions(USERS, [(USERS[0],1)], 4)
        self.assertEqual(sum(c)+sum(h.count(j) for j in range(1,5)), 2)
        METRICS['negative_controls'] = ['replacement sensitivity two', 'two tokens per human contributes twice', 'exact count plus histogram combined sensitivity two']

    def test_invalid_private_inputs_have_no_identity_in_error(self):
        bad = [[(b'unknown'.ljust(32,b'x'),1)], [(USERS[0],True)], [(USERS[0],5)], [(USERS[0],-1)], [(USERS[0],)], 'records']
        for records in bad:
            self.reject('INVALID_PRIVATE_INGESTION', lambda:compile_contributions(USERS,records,4))
        for roster in ([USERS[0]]*3, [], [b'x'], [None]):
            self.reject('INVALID_PRIVATE_INGESTION',lambda:compile_contributions(roster,[],4))
        for buckets in (0,65,True):
            self.reject('INVALID_PRIVATE_INGESTION',lambda:compile_contributions(USERS,[],buckets))

    def test_pair_ciphertext_and_receipt_do_not_contain_private_identity(self):
        receipt = ingest(self.l)
        self.assertEqual(self.read('count'),[1,1,0]); self.assertEqual(self.read('hist'),[1,2,0])
        image = self.l.state_image()
        self.assertTrue(all(u.hex().encode() not in image for u in USERS))
        self.assertEqual(receipt,dict(batch='batch',count='count',histogram='hist',rule=RULE))
        self.assertEqual(self.l.audit(),[])
        METRICS['private_storage_scope'] = 'Encrypted roster and both fixed-width views; no raw record or raw content digest stored.'

    def test_direct_import_and_duplicate_immutable_bindings_rejected(self):
        self.reject('CONTRIBUTION_INGESTION_REQUIRED', lambda:self.l.install_snapshot('t','domain','x',[1,1,1]))
        self.reject('CONTRIBUTION_INGESTION_REQUIRED', lambda:self.l.install_histogram_snapshot('t','domain','x','cat',[1,1,1]))
        self.reject('CONTRIBUTION_BINDING_EXISTS',lambda:self.l.bind_contribution_domain('t','domain',b'Z'*32,USERS[::-1]))
        ingest(self.l)
        self.reject('CONTRIBUTION_BATCH_EXISTS',lambda:ingest(self.l))
        self.reject('CONTRIBUTION_ALIAS_CONFLICT',lambda:self.l.ingest_pair('t','domain','new','cat','count','hist2',RECORDS))
        self.assertEqual(self.read('count'),[1,1,0]); self.assertEqual(self.l.audit(),[])

    def test_lineage_cannot_rebind_to_fresh_budget_in_same_tenant(self):
        self.l.provision_domain('t','otherdomain',3,4*E,4*D)
        self.reject('CONTRIBUTION_BINDING_EXISTS',lambda:self.l.bind_contribution_domain('t','otherdomain',LINEAGE,USERS))
        self.reject('INVALID_PRIVATE_INGESTION',lambda:self.l.bind_contribution_domain('t','otherdomain',b'N'*32,USERS[:2]))
        # Inventing a different lineage remains privileged misconfiguration.
        self.l.bind_contribution_domain('t','otherdomain',b'N'*32,USERS)
        METRICS['global_lineage_enforcement'] = False

    def test_unknown_user_rejection_does_not_install_partial_pair(self):
        self.reject('INVALID_PRIVATE_INGESTION',lambda:self.l.ingest_pair('t','domain','batch','cat','count','hist',RECORDS+[(b'?'*32,1)]))
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM snapshots').fetchone()[0],0)
        self.assertEqual(self.l.audit(),[])

    def test_signed_mixed_operations_charge_same_domain_and_ancestors(self):
        ingest(self.l)
        with patch.object(self.l,'private_roster',side_effect=AssertionError('private roster read at admission')), patch.object(self.l,'open_snapshot',side_effect=AssertionError('snapshot read before L1')):
            register(self.l,'h',True); register(self.l,'c',False)
        finish(self.l)
        self.assertEqual(len(self.l.op('t','h')['result']),32); self.assertEqual(len(self.l.op('t','c')['result']),8)
        for row in self.l.db.execute('SELECT id,spent,reserved FROM accounts'):
            self.assertEqual(row['reserved'],0)
            self.assertEqual(row['spent'],2*(E if row['id'].endswith(':epsilon') else D))
        self.assertEqual(self.l.audit(),[])
        METRICS['signed_operations'] = 2

    def test_multiple_snapshots_reuse_same_roster_and_accounts(self):
        ingest(self.l)
        before = [tuple(r) for r in self.l.db.execute('SELECT * FROM accounts')]
        self.l.ingest_pair('t','domain','second','cat','count2','hist2',[(USERS[1],3),(USERS[2],4)])
        self.assertEqual(self.read('hist2'),[0,3,4]); self.assertEqual(self.read('count2'),[0,1,1])
        self.assertEqual(before,[tuple(r) for r in self.l.db.execute('SELECT * FROM accounts')])
        self.assertEqual(self.l.audit(),[])

    def test_maximum_compiler_shape_and_bucket_boundary(self):
        roster = tuple(i.to_bytes(32,'big') for i in range(65535))
        c,h = compile_contributions(roster, [(roster[-1],64),(roster[0],1),(roster[-1],64)],64)
        self.assertEqual(len(h),65535);self.assertEqual(h[-1],64);self.assertEqual(sum(c),2)
        METRICS['maximum_compiler_shape'] = dict(capacity=65535,buckets=64,scope='compiler only; not maximum witnessed image or production load')

    def test_concurrent_ingestion_same_alias_has_one_immutable_winner(self):
        def attempt(records):
            w=ReferenceWitness(self.wp); l=ContributionLedger(self.path,clock=lambda:100,vault=vault(),witness=w)
            try:
                l.ingest_pair('t','domain','batch','cat','count','hist',records)
                return 'success'
            except Rejected as e:return str(e)
            finally:l.close();w.close()
        alternative=[(USERS[2],4)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results=list(executor.map(attempt,[RECORDS,alternative]))
        self.assertEqual(sorted(results),['CONTRIBUTION_BATCH_EXISTS','success'])
        self.assertIn(self.read('hist'),[[1,2,0],[0,0,4]])
        self.assertEqual(self.read('count'),[int(x!=0) for x in self.read('hist')])
        self.assertEqual(self.l.audit(),[])

    def test_restore_rejects_authority_image_with_inconsistent_pair(self):
        ingest(self.l)
        # Deliberately corrupt using the trusted administrator and valid AEAD,
        # then get the reference witness to accept it. Recovery audit still
        # refuses this internal inconsistency; witness is not a semantic proof.
        with self.l.tx():
            raw=self.l.protect_snapshot('t','domain','count',[0,0,0])
            self.l.db.execute('UPDATE snapshots SET rows_json=? WHERE id=?',(raw,'count'))
        self.reject('CONTRIBUTION_AUDIT_FAILED',self.l.audit)
        self.reject('CONTRIBUTION_AUDIT_FAILED',lambda:ContributionLedger.restore_new(self.root/'restored',clock=lambda:100,vault=vault(),witness=self.w))

    def test_legacy_profile_cannot_open_contribution_database(self):
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:WitnessedMixedLedger(self.path,clock=lambda:100,vault=vault(),witness=self.w))

    def test_orphan_admin_insert_detected_and_unsigned_provenance_rejected(self):
        # Administrator can bypass Python methods; it remains trusted, but an
        # accidental base-class import has no contribution provenance.
        from dp_ledger import DPLedger
        DPLedger.install_snapshot(self.l,'t','domain','count',[1,1,1])
        self.reject('CONTRIBUTION_PROVENANCE_REQUIRED',lambda:register(self.l,'c',False))
        self.reject('CONTRIBUTION_AUDIT_FAILED',self.l.audit)

    def test_roster_tampering_fenced_and_exact_restored(self):
        ingest(self.l); image=self.l.state_image()
        self.l.db.execute('UPDATE contribution_domains SET roster=?',(b'x'*132,))
        self.reject('LOCAL_STATE_DIVERGED',self.l.audit)
        self.l.recover_from_witness(); self.assertEqual(self.l.state_image(),image)
        self.assertEqual(self.l.private_roster('t','domain'),USERS);self.assertEqual(self.l.audit(),[])

    def test_mid_write_exception_rolls_back_both_views(self):
        def fault(p):
            if p=='after_count_snapshot':raise RuntimeError('injected')
        with self.assertRaises(RuntimeError):ingest(self.l,fault=fault)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM snapshots').fetchone()[0],0)
        self.assertEqual(self.l.audit(),[])

    def test_witness_reply_loss_restores_pair_without_recompilation(self):
        def fault(p):
            if p=='after_witness_accept':raise ConnectionError('lost')
        self.l.witness_fault=fault
        with self.assertRaises(ConnectionError):ingest(self.l)
        self.l.witness_fault=lambda p:None
        self.reject('WITNESS_RECOVERY_REQUIRED',self.l.audit)
        with patch('contribution_ingestion.compile_contributions',side_effect=AssertionError('recompile')):
            self.l.recover_from_witness()
        self.assertEqual(self.read('hist'),[1,2,0]);self.assertEqual(self.l.audit(),[])

    def test_actual_process_cuts_have_no_half_pair(self):
        for point, durable in [('after_count_snapshot',False),('before_ingestion_commit',False),('before_witness_accept',False),('after_witness_accept',True),('after_local_anchor_write',True),('after_ingestion_commit',True)]:
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'db'; wp=Path(directory)/'w'
                w=ReferenceWitness(wp); l=setup(path,w); l.close()
                result=subprocess.run([sys.executable,__file__,'--child',str(path),str(wp),point],capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,96,result.stderr)
                l=ContributionLedger(path,clock=lambda:100,vault=vault(),witness=w)
                try:
                    l.recover_from_witness()
                    self.assertEqual(l.db.execute('SELECT COUNT(*) FROM snapshots').fetchone()[0],2 if durable else 0)
                    self.assertEqual(l.db.execute('SELECT COUNT(*) FROM contribution_batches').fetchone()[0],int(durable))
                    self.assertEqual(l.audit(),[])
                finally:l.close();w.close()
                CUTS.append(point)


def source_hashes():
    pending=['test_contribution_ingestion.py'];seen={}
    while pending:
        name=pending.pop()
        path=HERE/name
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
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ContributionTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,source_sha256=source_hashes(),
                source_paths_relative_to='delivery root',metrics=METRICS,actual_process_crash_scenarios=CUTS,
                crash_scenario_count=len(CUTS),python=platform.python_version(),sqlite=sqlite3.sqlite_version,
                public_ingestion_endpoint=False,real_identity_resolution=False,global_lineage_enforcement=False,
                full_observation_privacy=False,production_acceptance=False)
    (HERE/'contribution_ingestion_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
