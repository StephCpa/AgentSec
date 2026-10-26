"""Sender preparation crashes: retained body, deadline, first fact and budget."""
from copy import deepcopy
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
P = Path(__file__).resolve().parents[1] / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from preparation_recovery_trace import (run_preparation_recovery, PreparationRecoveryRuntime,
                                        protected_state, PLANS, plan_kind)
from preparation_recovery_simulator import PreparationRecoverySimulator, preparation_cuts, DURABLE_CUTS
from constructive_trace import FixtureSigningOracle
from public_trace_adapter import ViewMismatch
from state_relation import StateRelationMismatch
from wire import decode


class PreparationRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {(p, c): run_preparation_recovery(p, c) for p in PLANS for c in preparation_cuts(plan_kind(p))}

    def simulator(self, case):
        return PreparationRecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),
                                            {k: tuple(v) for k, v in case['approved_outputs'].items()}, FixtureSigningOracle())

    def test_all_declared_hooks_exit_and_restore_authority(self):
        self.assertEqual(len(self.cases), 66)
        for (plan, cut), case in self.cases.items():
            with self.subTest(plan=plan, cut=cut):
                diag = case['diagnostics'][0]
                self.assertEqual(diag['exit_code'], 96)
                self.assertEqual(diag['witness_advanced'], cut in DURABLE_CUTS)
                self.assertEqual(diag['stale_guard_blocked'], cut in ('after_witness_accept', 'after_local_anchor_write'))
                self.assertTrue(diag['receiver_authorities_unchanged'])
                fault = next(x for x in case['checkpoints'] if x['kind'] == 'PREPARE_CUT')
                self.assertEqual(set(fault['relation']), {'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R13'})

    def test_failed_observation_contains_neither_body_nor_commit_bit(self):
        for p in PLANS:
            events = [next(e for e in self.cases[p, c]['expected_records'] if e['kind'] == 'PREPARATION_UNAVAILABLE')
                      for c in preparation_cuts(plan_kind(p))]
            self.assertTrue(all(e == events[0] for e in events))
            self.assertEqual(set(events[0]), {'kind', 'at', 'operation', 'delivery_kind'})

    def test_deadline_boundary_closes_but_binds_only_durable_preparation(self):
        for c in preparation_cuts('DELIVERY'):
            case = self.cases['envelope_expire', c]
            self.assertEqual(bool(case['check']['terminal_envelope_hash']), c in DURABLE_CUTS)
            self.assertEqual((case['check']['facts']['a']['outcome'], case['check']['facts']['a']['event_at']), ('CLOSED', 160))
            denials = [e for e in case['expected_records'] if e['kind'] == 'PREPARATION_REJECTED']
            self.assertIn('TICKET_EXPIRED', [e['reason'] for e in denials])

    def test_failed_exact_retry_keeps_original_prepared_envelope(self):
        hashes = {self.cases['envelope_retry_expire', c]['check']['terminal_envelope_hash'] for c in preparation_cuts('DELIVERY')}
        self.assertEqual(len(hashes), 1)
        self.assertNotIn('', hashes)
        for c in preparation_cuts('DELIVERY'):
            case = self.cases['envelope_retry_expire', c]
            self.assertEqual(case['check']['facts']['a']['event_at'], 170)
            self.assertEqual(case['check']['draws'], [('a', 'count')])

    def test_terminal_empty_prepared_and_existing_fact_are_distinct(self):
        for c in preparation_cuts('TERMINAL'):
            self.assertEqual(self.cases['terminal_empty', c]['check']['terminal_envelope_hash'], '')
            self.assertTrue(self.cases['terminal_prepared', c]['check']['terminal_envelope_hash'])
            fact = self.cases['terminal_existing_fact', c]['check']['facts']['a']
            self.assertEqual((fact['outcome'], fact['event_at']), ('ACCEPTED', 100))
            self.assertEqual(self.cases['terminal_prepared', c]['check']['facts']['a']['outcome'], 'CLOSED')

    def test_completed_preparation_and_terminal_retries_reuse_exact_body(self):
        for (p, c), case in self.cases.items():
            bodies = [e['body'] for e in case['expected_records'] if e['kind'] == 'PREPARATION' and
                      e['delivery_kind'] == ('TERMINAL' if 'terminal_envelope_hash' in case['check'] else 'DELIVERY')]
            self.assertGreaterEqual(len(bodies), 2)
            self.assertEqual(len(set(bodies)), 1)
            self.assertTrue(case['check']['preparation_retries_byte_equal'])
            self.assertTrue(case['check']['protected_preserved'])

    def test_cross_route_order_and_withheld_tail(self):
        for p in ('envelope_cross_route', 'terminal_cross_route', 'envelope_withheld_tail'):
            for c in preparation_cuts(plan_kind(p)):
                case = self.cases[p, c]
                outcomes = [e['outcome'] for e in case['check']['final']]
                if p.endswith('cross_route'):
                    self.assertIn('DOMAIN_FINAL_ORDER', [e.get('reason') for e in case['expected_records']])
                    self.assertEqual(outcomes, ['CLOSED', 'CLOSED'] if p.startswith('terminal') else ['ACCEPTED', 'ACCEPTED'])
                else:
                    self.assertEqual(outcomes, ['ACCEPTED', 'WITHHELD'])

    def test_histogram_draw_is_not_repeated(self):
        for c in preparation_cuts('DELIVERY'):
            self.assertEqual(self.cases['envelope_histogram', c]['check']['draws'], [('a', 'histogram')])

    def test_archived_input_replay_never_reads_database(self):
        with patch('sqlite3.connect', side_effect=AssertionError('DB forbidden')):
            for case in self.cases.values():
                case = json.loads(json.dumps(case)); sim = self.simulator(case)
                self.assertEqual(sim.generate(case['commands']), case['expected_records'])
                self.assertEqual(sim.sign.calls, case['signing_calls'])
                self.assertIsNone(sim.needs_recovery)

    def test_recovery_gate_and_unreachable_or_untrusted_commands(self):
        case = self.cases['envelope_expire', 'after_witness_accept']; sim = self.simulator(case)
        for command in case['commands']:
            sim.emit(command)
            if command['kind'] == 'PREPARE_CUT':
                break
        for command in (dict(kind='TICK', at=100, tick=sim.state.tick + 1),
                        dict(kind='PREPARE_RECOVER', at=100, operation='b'),
                        dict(kind='PREPARE_RECOVER', at=100, operation='a', image='private')):
            with self.assertRaises(ViewMismatch):
                sim.emit(command)
        sim.emit(dict(kind='PREPARE_RECOVER', at=160, operation='a'))
        before = deepcopy(sim.state.__dict__)
        with self.assertRaisesRegex(ViewMismatch, 'CUT_NOT_REACHED'):
            sim.emit(dict(kind='PREPARE_CUT', at=160, operation='a', delivery_kind='DELIVERY', cut='before_witness_accept'))
        self.assertEqual(sim.state.__dict__, before)
        with self.assertRaises(ViewMismatch):
            sim.emit(dict(kind='DELIVERY_RECOVER', at=160, operation='a', side='sender'))
        with self.assertRaises(ValueError):
            run_preparation_recovery('envelope_count', 'before_v2_control_commit')

    def test_wrong_commit_boundary_mutant_changes_terminal_public_evidence(self):
        case = self.cases['envelope_expire', 'before_witness_accept']
        with patch('preparation_recovery_simulator.DURABLE_CUTS', DURABLE_CUTS | {'before_witness_accept'}):
            sim = self.simulator(case); generated = sim.generate(case['commands'])
        self.assertNotEqual(generated, case['expected_records'])

    def test_renewed_deadline_mutant_disagrees_with_actual_expiry_rejection(self):
        case = self.cases['envelope_expire', 'after_witness_accept']; sim = self.simulator(case)
        for command in case['commands']:
            sim.emit(command)
            if command['kind'] == 'PREPARE_RECOVER':
                break
        sim.state.by_id['a']['expires_at'] = 220
        event = sim.emit(dict(kind='PREPARE', at=160, operation='a', delivery_kind='DELIVERY'))
        self.assertEqual(event['kind'], 'PREPARATION')
        actual = next(e for e in case['expected_records'] if e.get('reason') == 'TICKET_EXPIRED')
        self.assertNotEqual(event, actual)

    def test_relation_rejects_dropped_preparation_and_changed_opaque_seed(self):
        with tempfile.TemporaryDirectory() as td:
            run = PreparationRecoveryRuntime(td)
            try:
                run.submit(); run.finish(); run.protected = protected_state(run.l)
                run.prepare_call(); run.simulator.state.prepared.clear()
                with self.assertRaisesRegex(StateRelationMismatch, 'R5.prepared'):
                    run.relation()
                run.l.db.execute("UPDATE operations SET seed=? WHERE id='a'", (b'corrupt',))
                with self.assertRaisesRegex(AssertionError, 'protected_tape_result_budget_ticket'):
                    run.assert_protected()
            finally:
                run.close()

    def test_conditioned_empty_and_full_rosters_agree(self):
        for p, c in (('envelope_expire', 'after_witness_accept'), ('terminal_existing_fact', 'before_witness_accept')):
            a = run_preparation_recovery(p, c, 0); b = run_preparation_recovery(p, c, 7)
            self.assertEqual(a['expected_records'], b['expected_records'])
            self.assertEqual(a['checkpoints'], b['checkpoints'])


if __name__ == '__main__':
    unittest.main()
