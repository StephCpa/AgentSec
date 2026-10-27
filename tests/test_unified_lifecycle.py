"""Cross-phase recovery must preserve one shared state and typed obligations."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
P = Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from unified_lifecycle_simulator import UnifiedLifecycleSimulator
from unified_lifecycle_trace import run_unified, SCHEDULES, UnifiedLifecycleRuntime
from retirement_recovery_trace import protected_archive
from constructive_trace import FixtureSigningOracle
from public_trace_adapter import ViewMismatch
from state_relation import StateRelationMismatch, digest
from wire import decode


class UnifiedLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = [run_unified(s, 'cleanup_before_b' if i % 2 == 0 else 'cleanup_after_b', bool(i % 2))
                     for i, s in enumerate(SCHEDULES)]

    def model(self, case):
        signer = FixtureSigningOracle()
        return UnifiedLifecycleSimulator(decode(bytes.fromhex(case['config_cbor_hex'])),
            {k: tuple(v) for k, v in case['approved_outputs'].items()}, signer), signer

    def pending(self):
        case = self.cases[0]; sim, signer = self.model(case)
        index = next(i for i, c in enumerate(case['commands']) if c['kind'] == 'PREPARE_CUT')
        sim.generate(case['commands'][:index+1])
        return sim, case

    def snapshot(self, sim):
        return digest(dict(state=sim.state.__dict__, retirement=sim.retirement, pending=sim.pending,
            obligation=sim.obligation, needs_recovery=sim.needs_recovery, pending_tick=sim.pending_tick,
            records=sim.records, projected=sim.projected_records, events=sim.events.__dict__))

    def test_real_exits_and_final_budget_across_all_schedules(self):
        for case in self.cases:
            self.assertEqual(len(case['diagnostics']), 7)
            self.assertEqual(len(case['recovery_diagnostics']), 14)
            expected = [96 if c['kind'] == 'PREPARE_CUT' else 95 if c['kind'] in ('RECEIVE_CUT', 'CONFIRM_CUT') else 97
                        for c in case['commands'] if c['kind'].endswith('_CUT') and c['kind'] != 'RECOVERY_CUT']
            self.assertEqual([x['exit_code'] for x in case['diagnostics']], expected)
            self.assertEqual([x['exit_code'] for x in case['recovery_diagnostics']], [96] * 14)
            self.assertEqual([x['operation'] for x in case['check']['mechanism_calls']], ['a', 'b'])
            self.assertEqual([x['outcome'] for x in case['check']['final']], ['ACCEPTED', 'ACCEPTED'])
            self.assertEqual(len(case['checkpoints']), len(case['commands'])+1)

    def test_independent_model_replays_combined_trace_without_database(self):
        with patch('sqlite3.connect', side_effect=AssertionError('DB access')):
            for case in self.cases:
                sim, signer = self.model(case)
                self.assertEqual(sim.generate(case['commands']), case['expected_records'])
                self.assertEqual(signer.calls, case['signing_calls'])
                self.assertIsNone(sim.obligation); self.assertIsNone(sim.needs_recovery)
                self.assertEqual(sim.state.final, case['check']['final'])

    def test_wrong_recovery_phase_side_target_and_clock_are_atomic(self):
        sim, case = self.pending(); now = sim.state.now
        bad = [dict(kind='DELIVERY_RECOVER', at=now, side='sender', operation='a'),
               dict(kind='RETIRE_RECOVER', at=now, side='sender', route='a'),
               dict(kind='PREPARE_RECOVER', at=now, operation='b'),
               dict(kind='PREPARE_RECOVER', at=now-1, operation='a'),
               dict(kind='RECOVERY_CUT', at=now, side='receiver', operation='a', cut='after_recovery_commit'),
               dict(kind='TICK', at=now, tick=sim.state.tick+1)]
        before = self.snapshot(sim)
        for command in bad:
            with self.subTest(command=command), self.assertRaises(ViewMismatch): sim.emit(command)
            self.assertEqual(self.snapshot(sim), before)

    def test_recovery_commit_is_stutter_until_explicit_completion(self):
        sim, _ = self.pending()
        state = deepcopy(sim.state.__dict__); obligation = deepcopy(sim.obligation)
        sim.emit(dict(kind='RECOVERY_CUT', at=sim.state.now, side='sender', operation='a', cut='after_recovery_commit'))
        self.assertEqual(sim.state.__dict__, state); self.assertEqual(sim.obligation, obligation)
        with self.assertRaises(ViewMismatch): sim.emit(dict(kind='TICK', at=sim.state.now, tick=sim.state.tick+1))

    def test_ordinary_request_and_private_work_faults_use_same_owner(self):
        from public_recovery_trace import run_recovery
        from private_recovery_trace import run_kernel
        for case in (run_recovery('submit', 'after_witness_accept'), run_kernel(False, 'l1', 'after_sampling')):
            sim, signer = self.model(case)
            self.assertEqual(sim.generate(case['commands']), case['expected_records'])
            self.assertEqual(signer.calls, case['signing_calls'])
            self.assertIsNone(sim.pending_tick)

    def test_mutant_dropping_shared_request_cache_is_detected(self):
        class DropsCache(UnifiedLifecycleSimulator):
            def _recovery(self, command):
                result = super()._recovery(command)
                if command['kind'] == 'PREPARE_RECOVER': self.state.cache.clear()
                return result
        with patch('unified_lifecycle_trace.UnifiedLifecycleSimulator', DropsCache):
            with self.assertRaises(StateRelationMismatch): run_unified()

    def test_cleanup_and_new_preparation_are_really_interleaved(self):
        for case in self.cases:
            commands = case['commands']
            cleanup = next(i for i, c in enumerate(commands) if c['kind'] == 'RETIRE_PREPARE_CUT')
            b = next(i for i, c in enumerate(commands) if c['kind'] == 'PREPARE_CUT' and c['operation'] == 'b')
            self.assertEqual(cleanup < b, case['order'] == 'cleanup_before_b')
            phases = [c['cut'] for c in commands if c['kind'].endswith('_CUT') and c['kind'] != 'RECOVERY_CUT']
            if case['cut'].startswith('alternating'):
                self.assertTrue(all(a != b for a, b in zip(phases, phases[1:])))

    def test_opaque_reencryption_is_not_hidden_by_semantic_relation(self):
        with tempfile.TemporaryDirectory() as directory:
            run = UnifiedLifecycleRuntime(directory, 3)
            try:
                run.submit(); run.finish(); run.send(); run.confirm()
                run.retirement_archive = protected_archive(run.l)
                row = run.l.db.execute('SELECT o.* FROM v2_outbox o JOIN deliveries d ON o.id=d.id AND o.tenant=d.tenant WHERE d.operation_id=?', ('a',)).fetchone()
                raw = run.l.open('envelope', row)
                rewritten = run.l.seal('envelope', row, raw)
                self.assertNotEqual(rewritten, row['envelope'])
                run.l.db.execute('UPDATE v2_outbox SET envelope=? WHERE id=?', (rewritten, row['id']))
                # Validly re-encrypted equal plaintext still passes the semantic
                # projection. The additional opaque-preservation check must fail.
                run.relation()
                with self.assertRaisesRegex(AssertionError, 'opaque archive'):
                    run.assert_retirement_archive()
            finally: run.close()


if __name__ == '__main__': unittest.main()
