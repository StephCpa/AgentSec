from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from constructive_trace import FixtureSigningOracle
from private_recovery_trace import run_kernel,KernelRuntime,target_tick
from private_state_relation import assert_private_relation,planned_tape
from kernel_recovery_simulator import KernelRecoverySimulator,phase_cuts
from recovery_simulator import DURABLE_CUTS
from public_recovery_trace import RecoveryRuntime
from public_gateway import PublicGatewayLedger
from public_trace_adapter import PublicTraceAdapter,ViewMismatch
from state_relation import StateRelationMismatch
from wire import decode


class PrivateRecoveryTests(unittest.TestCase):
    def test_sampling_attempts_are_distinct_from_committed_l1(self):
        for cut in phase_cuts('l1'):
            with self.subTest(cut=cut):
                c=run_kernel(False,'l1',cut)
                discarded=int(cut not in DURABLE_CUTS and cut!='before_sampling')
                self.assertEqual(c['check']['physical_draws'],1+discarded)
                self.assertEqual(c['check']['committed_draws'],1)
                self.assertEqual(c['check']['discarded_draws'],discarded)
                self.assertEqual(sum(x['discarded_tape_differs'] for x in c['physical_draws']),discarded)
                self.assertEqual(c['private_diagnostics'][0]['snapshot_reads'],0)
                self.assertEqual([x['outcome'] for x in c['check']['final']],['ACCEPTED'])

    def test_private_prefixes_survive_pre_and_postcommit_cuts(self):
        for hist,phase in ((False,'row'),(False,'bit'),(False,'final'),(True,'row'),(True,'bit'),(True,'bucket'),(True,'final')):
            for cut in ('after_private_step','after_witness_accept'):
                with self.subTest(hist=hist,phase=phase,cut=cut):
                    c=run_kernel(hist,phase,cut)
                    self.assertEqual(c['check']['committed_draws'],1)
                    self.assertEqual(c['check']['discarded_draws'],0)
                    restored=next(x for x in c['checkpoints'] if x['kind']=='RECOVER')
                    self.assertEqual(set(restored['relation']),{'R'+str(i) for i in range(1,11)})

    def test_partial_settlement_and_publication_rollback(self):
        for hist in (False,True):
            for cut in ('after_account_settle','after_publication_write','after_public_decision_write'):
                with self.subTest(hist=hist,cut=cut):
                    c=run_kernel(hist,'final',cut)
                    self.assertFalse(c['cut_diagnostics'][0]['witness_advanced'])
                    self.assertEqual([x['outcome'] for x in c['check']['final']],['ACCEPTED'])

    def test_validly_resealed_replacement_tape_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            r=KernelRuntime(td,3)
            try:
                r.submit();r.advance();op=r.l.op('t','a')
                with r.l.tx():
                    r.l.db.execute('UPDATE operations SET seed=? WHERE tenant=? AND id=?',
                        (r.l.protect_operation_field('seed','t','a',op['digest'],planned_tape(r.slots,False,2)),'t','a'))
                RecoveryRuntime.relation(r) # R1-R8 project no private tape bytes.
                with self.assertRaisesRegex(StateRelationMismatch,'R10.durable_tape'):assert_private_relation(r)
            finally:r.close()

    def test_validly_resealed_accumulator_mutation_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            r=KernelRuntime(td,3)
            try:
                r.submit();r.advance();r.advance()
                row=r.l.db.execute('SELECT * FROM jobs WHERE tenant=? AND operation_id=?',('t','a')).fetchone()
                state=r.l.load_private_state(row);state['count_value']+=1
                with r.l.tx():r.l.save_private_state(row,state,row['pc'])
                RecoveryRuntime.relation(r)
                with self.assertRaisesRegex(StateRelationMismatch,'R10.private_prefix'):assert_private_relation(r)
            finally:r.close()

    def test_private_read_before_durable_l1_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            r=KernelRuntime(td,3)
            try:
                r.submit()
                with self.assertRaisesRegex(StateRelationMismatch,'R10.private_access_count'):
                    r.advance_cut(False,'l1','after_sampling',mutant_read_at_sample=True)
            finally:r.close()

    def test_wrong_commit_classification_is_detected(self):
        for cut,wrong in (('after_witness_accept',False),('before_witness_accept',True)):
            with self.subTest(cut=cut),patch.object(KernelRecoverySimulator,'tick_commits',return_value=wrong):
                with self.assertRaises(StateRelationMismatch):run_kernel(False,'l1',cut)

    def test_replay_uses_public_commands_only(self):
        case=run_kernel(True,'bucket','after_local_anchor_write');signer=FixtureSigningOracle()
        with patch('sqlite3.connect',side_effect=AssertionError('DB')),patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('runtime')),patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('response')):
            sim=KernelRecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),case['approved_outputs'],signer)
            generated=sim.generate(deepcopy(case['commands']))
        self.assertEqual(generated,case['expected_records']);self.assertEqual(signer.calls,case['signing_calls'])

    def test_cut_reachability_and_exact_retry_are_enforced(self):
        c=run_kernel(False,'row','after_private_step')
        idx=next(i for i,x in enumerate(c['commands']) if x['kind']=='TICK_CUT')
        sim=KernelRecoverySimulator(decode(bytes.fromhex(c['config_cbor_hex'])),c['approved_outputs'],FixtureSigningOracle())
        sim.generate(c['commands'][:idx]);before=deepcopy(sim.state.__dict__)
        for change,reason in (({'cut':'after_sampling'},'CUT_NOT_REACHED'),({'cut':'after_account_settle'},'CUT_NOT_REACHED'),({'at':1001},'KERNEL_PROFILE')):
            with self.assertRaisesRegex(ViewMismatch,reason):sim.emit(dict(c['commands'][idx],**change))
            self.assertEqual(sim.state.__dict__,before)
        sim.emit(c['commands'][idx])
        with self.assertRaisesRegex(ViewMismatch,'RECOVERY_REQUIRED'):sim.emit(dict(kind='TICK_RETRY',at=100,tick=2))
        sim.emit(dict(kind='RECOVER',at=100))
        with self.assertRaisesRegex(ViewMismatch,'TICK_RETRY_BINDING'):sim.emit(dict(kind='TICK_RETRY',at=100,tick=3))
        with self.assertRaisesRegex(ViewMismatch,'TICK_RETRY_REQUIRED'):sim.emit(dict(kind='TICK',at=100,tick=2))
        sim.emit(dict(kind='TICK_RETRY',at=100,tick=2))
        self.assertIsNone(sim.pending_tick)

    def test_conditioned_neighbors_have_identical_public_trace(self):
        cases=[run_kernel(True,'l1','after_sampling',mask) for mask in (0,7)]
        self.assertEqual(cases[0]['expected_records'],cases[1]['expected_records'])
        self.assertEqual(cases[0]['checkpoints'],cases[1]['checkpoints'])

if __name__=='__main__':unittest.main()
