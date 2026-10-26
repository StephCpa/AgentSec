"""Cleanup must not resurrect facts, lose archives or hide denial persistence."""
from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path
import sys
import json
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
P = Path(__file__).resolve().parents[1] / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from retirement_recovery_trace import (run_retirement_recovery, RetirementRecoveryRuntime,
                                      protected_archive, PLANS, applicable_cuts, stage_for)
from retirement_recovery_simulator import RetirementRecoverySimulator, DURABLE_CUTS
from retirement_cost_experiment import run_cost_trial
from constructive_trace import FixtureSigningOracle
from delivery_state_relation import assert_delivery_relation
from state_relation import StateRelationMismatch
from public_trace_adapter import ViewMismatch
from wire import decode
import retention_wire as r


class RetirementRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {(p, c): run_retirement_recovery(p, c) for p in PLANS for c in applicable_cuts(p)}

    def simulator(self, case):
        return RetirementRecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),
                                            {k: tuple(v) for k, v in case['approved_outputs'].items()}, FixtureSigningOracle())

    def test_full_declared_cut_matrix_and_authority_projection(self):
        self.assertEqual(len(self.cases), 44)
        for (p, c), case in self.cases.items():
            with self.subTest(plan=p, cut=c):
                diag = case['diagnostics'][0]; self.assertEqual(diag['exit_code'], 97)
                self.assertEqual(diag['witness_advanced'], c in DURABLE_CUTS)
                self.assertEqual(diag['stale_guard_blocked'], c in ('after_witness_accept', 'after_local_anchor_write'))
                self.assertTrue(diag['other_authorities_unchanged']); self.assertTrue(diag['protected_archive'])
                point = next(x for x in case['checkpoints'] if x['kind'].endswith('_CUT'))
                self.assertEqual(set(point['relation']), {'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R14'})

    def test_same_failed_call_observation_hides_commit_boundary(self):
        for p in PLANS:
            events = [next(e for e in self.cases[p, c]['expected_records'] if e['kind'].endswith('_UNAVAILABLE')) for c in applicable_cuts(p)]
            self.assertTrue(all(e == events[0] for e in events))
            self.assertNotIn('body', events[0]); self.assertNotIn('cut', events[0])
            if stage_for(p) != 'RETIRE_CONFIRM': self.assertNotIn('response', events[0])

    def test_recovered_query_distinguishes_old_and_new_live_window(self):
        for p in ('retire_partial', 'retire_second'):
            for c in applicable_cuts(p):
                case = self.cases[p, c]
                idx = next(i for i, x in enumerate(case['expected_records']) if x['kind'] == 'RETIRE_RECOVER')
                event = case['expected_records'][idx + 1]; self.assertEqual(event['kind'], 'RETENTION_QUERY')
                self.assertEqual(event.get('reason'), 'V2_RETIRED' if c in DURABLE_CUTS else None)
                self.assertEqual('response' in event, c not in DURABLE_CUTS)

    def test_duplicate_offer_precommit_failure_keeps_prior_retirement(self):
        for c in applicable_cuts('retire_duplicate'):
            case = self.cases['retire_duplicate', c]
            idx = next(i for i, x in enumerate(case['expected_records']) if x['kind'] == 'RETIRE_RECOVER')
            self.assertEqual(case['expected_records'][idx + 1].get('reason'), 'V2_RETIRED')
            self.assertEqual(case['check']['receiver_live'], [2])
        with self.assertRaises(ValueError): run_retirement_recovery('retire_duplicate', 'after_v2_recipient_delete')

    def test_deleted_first_fact_stays_in_sender_archive_and_final_prefix(self):
        for (p, c), case in self.cases.items():
            check = case['check']; self.assertTrue(check['sender_archive_preserved'])
            self.assertEqual(check['sender_archive_rows'], len(check['final']))
            self.assertEqual(check['facts']['a']['outcome'], 'ACCEPTED')
            if len(check['final']) == 2:
                self.assertEqual(check['facts']['b']['outcome'], 'CLOSED')
                self.assertEqual(check['facts']['b']['event_at'], 170)
            event = next(e for e in reversed(case['expected_records']) if e['kind'] == 'DELIVERY_REPLAY')
            self.assertEqual(event.get('reason'), 'V2_RETIRED')

    def test_stale_offer_returns_current_checkpoint_without_reconstructing_fact(self):
        for c in applicable_cuts('retire_second'):
            case = self.cases['retire_second', c]; ctx = decode(bytes.fromhex(case['config_cbor_hex']))['roots']['root']['context']
            event = next(e for e in reversed(case['expected_records']) if e['kind'] == 'RETIRE_DELIVERY')
            request = bytes.fromhex(event['request']); offer = r.parse_offer(r.parse_retire_attempt(request, ctx)['offer'], ctx)
            checkpoint = r.parse_checkpoint(bytes.fromhex(event['response']), request, ctx)
            self.assertEqual((offer['target'], checkpoint['floor'], checkpoint['high']), (1, 2, 2))
            self.assertNotIn('fact', checkpoint)

    def test_sender_confirmation_cut_frontier_and_exact_retry(self):
        for c in applicable_cuts('confirm_checkpoint'):
            case = self.cases['confirm_checkpoint', c]; sim = self.simulator(case)
            for command in case['commands']:
                sim.emit(command)
                if command['kind'] == 'RETIRE_CONFIRM_CUT': break
            h, _ = sim.context('root')
            self.assertEqual(sim.retirement['sender'][h]['floor'], 2 if c in DURABLE_CUTS else 0)
        for c in applicable_cuts('confirm_retry'):
            case = self.cases['confirm_retry', c]
            unavailable = next(e for e in case['expected_records'] if e['kind'] == 'RETIRE_CONFIRM_UNAVAILABLE')
            index = case['expected_records'].index(unavailable)
            retry = next(e for e in case['expected_records'][index + 1:] if e['kind'] == 'RETIRE_CONFIRMATION')
            self.assertEqual((unavailable['request'], unavailable['response']), (retry['request'], retry['response']))

    def test_histogram_sampling_is_not_repeated_by_cleanup(self):
        for c in applicable_cuts('offer_histogram'):
            self.assertEqual(self.cases['offer_histogram', c]['check']['draws'], [('a', 'histogram')])

    def test_all_archived_inputs_generate_without_runtime_database(self):
        with patch('sqlite3.connect', side_effect=AssertionError('DB forbidden')):
            for case in self.cases.values():
                case = json.loads(json.dumps(case)); sim = self.simulator(case)
                self.assertEqual(sim.generate(case['commands']), case['expected_records'])
                self.assertEqual(sim.sign.calls, case['signing_calls']); self.assertIsNone(sim.needs_recovery)

    def test_wrong_delete_commit_boundary_changes_recovered_public_query(self):
        case = self.cases['retire_partial', 'after_v2_recipient_delete']
        with patch('retirement_recovery_simulator.DURABLE_CUTS', DURABLE_CUTS | {'after_v2_recipient_delete'}):
            generated = self.simulator(case).generate(case['commands'])
        self.assertNotEqual(generated, case['expected_records'])

    def test_invalid_scope_and_recovery_gate_leave_state_unchanged(self):
        case = self.cases['retire_partial', 'after_witness_accept']; sim = self.simulator(case)
        for c in case['commands']:
            sim.emit(c)
            if c['kind'] == 'RETIRE_SEND_CUT': break
        before = deepcopy(sim.retirement)
        for command in (dict(kind='RETIRE_RECOVER', at=180, side='sender', route='root'),
                        dict(kind='RETIRE_RECOVER', at=180, side='receiver', route='root', image='private'),
                        dict(kind='RETIRE_PREPARE', at=180, route='root', target=1)):
            with self.assertRaises(ViewMismatch): sim.emit(command)
            self.assertEqual(sim.retirement, before)
        sim.emit(dict(kind='RETIRE_RECOVER', at=190, side='receiver', route='root'))
        with self.assertRaisesRegex(ViewMismatch, 'CUT_NOT_REACHED'):
            sim.emit(dict(kind='RETIRE_SEND_CUT', at=190, route='root', base=0, target=1, challenge='00' * 32, cut='after_v2_recipient_delete'))

    @contextmanager
    def retired(self, td):
        run = RetirementRecoveryRuntime(td)
        try:
            run.submit(); run.finish(); run.send(); run.confirm(); run.protected = protected_archive(run.l)
            run.prepare_retirement(1); run.send_retirement(0, 1); run.confirm_retirement()
            yield run
        finally: run.close()

    def test_original_no_retirement_relation_remains_strict(self):
        with tempfile.TemporaryDirectory() as td, self.retired(td) as run:
            with self.assertRaisesRegex(StateRelationMismatch, 'R5.no_retirement'):
                assert_delivery_relation(run, SimpleNamespace(state=run.simulator.state, records=run.simulator.projected_records),
                                         initialized_contexts=run.simulator.initialized_contexts)

    def test_resurrected_model_window_is_rejected(self):
        with tempfile.TemporaryDirectory() as td, self.retired(td) as run:
            h, ctx = run.simulator.context('root')
            run.simulator.retirement['receiver'][h].update(floor=0, root=r.genesis(ctx), last_offer=None)
            with self.assertRaisesRegex(StateRelationMismatch, 'R6.'):
                run.relation()
            run.l.db.execute("UPDATE v2_outbox SET acknowledgement=?", (b'corrupt-archive',))
            with self.assertRaisesRegex(AssertionError, 'R14.sender_archive_budget_or_final_changed'):
                run.assert_protected()

    def test_denial_is_not_a_noop_for_receiver_observed_time(self):
        with tempfile.TemporaryDirectory() as td, self.retired(td) as run:
            run.now = 110
            with patch.object(run.simulator, 'receiver_event', return_value=None):
                with self.assertRaisesRegex(StateRelationMismatch, 'R6.receiver_metadata'):
                    run.query_retention('FINAL', 1)

    def test_zero_floor_checkpoint_does_not_create_retirement_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            run = RetirementRecoveryRuntime(td)
            try:
                run.submit(); run.finish(); run.send(); run.confirm()
                run.query_retention('CHECKPOINT', 0); run.confirm_retirement()
                h, _ = run.simulator.context('root')
                self.assertIsNone(run.simulator.retirement['sender'][h]['evidence'])
                self.assertEqual(run.simulator.retirement['sender'][h]['floor'], 0)
            finally: run.close()

    def test_conditioned_empty_and_full_rosters_agree(self):
        for p, c in (('retire_second', 'after_witness_accept'), ('confirm_checkpoint', 'before_witness_accept')):
            a = run_retirement_recovery(p, c, 0); b = run_retirement_recovery(p, c, 7)
            self.assertEqual(a['expected_records'], b['expected_records']); self.assertEqual(a['checkpoints'], b['checkpoints'])


class RetirementCostTests(unittest.TestCase):
    def test_same_workload_batching_changes_commit_count_without_pruning_archives(self):
        for hist in (False, True):
            single = run_cost_trial(hist, 2, 3, batch_size=1); batch = run_cost_trial(hist, 2, 3, batch_size=2)
            self.assertEqual(single['cleanup_totals']['cas_commits'], 6)
            self.assertEqual(batch['cleanup_totals']['cas_commits'], 3)
            self.assertGreater(single['cleanup_totals']['cas_image_bytes'], batch['cleanup_totals']['cas_image_bytes'])
            for x in (single, batch):
                self.assertTrue(x['archive_budget_final_preserved'])
                self.assertEqual(x['after_cleanup']['sender_archive_rows'], 2)
                self.assertEqual(x['after_queries']['receiver_live_rows'], 0)
                self.assertEqual(x['after_queries']['receiver_witness_commit_rows'] - x['after_cleanup']['receiver_witness_commit_rows'], 3)
                self.assertTrue(x['same_files_without_restore_or_vacuum'])
            self.assertEqual(single['after_cleanup']['sender_offer_rows'], 2)
            self.assertEqual(batch['after_cleanup']['sender_offer_rows'], 1)


if __name__ == '__main__': unittest.main()
