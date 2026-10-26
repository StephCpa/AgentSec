"""Window refill must compose with actual retirement/recovery failures."""
from copy import deepcopy
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
P = Path(__file__).resolve().parents[1] / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from window_lifecycle_trace import (run_window_lifecycle, WindowLifecycleRuntime, PLANS, CUTS, MODES)
from window_lifecycle_simulator import WindowLifecycleSimulator
from retirement_recovery_simulator import RetirementRecoverySimulator, DURABLE_CUTS
from recovery_interruption_simulator import RecoveryInterruptionSimulator, REPEATED_CUTS
from constructive_trace import FixtureSigningOracle
from public_trace_adapter import ViewMismatch
from state_relation import StateRelationMismatch
from public_gateway import parse_request
from wire import decode
import retention_delivery as d
import retention_wire as r


class WindowLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {(p, c, m): run_window_lifecycle(p, c, m) for p in PLANS for c in CUTS for m in MODES}

    def simulator(self, case, strict=False):
        signer = FixtureSigningOracle()
        base = (RetirementRecoverySimulator if strict else WindowLifecycleSimulator)(
            decode(bytes.fromhex(case['config_cbor_hex'])), {k: tuple(v) for k, v in case['approved_outputs'].items()}, signer)
        return RecoveryInterruptionSimulator(base), signer

    def test_declared_matrix_runs_real_exits_and_relations(self):
        self.assertEqual(len(self.cases), 36)
        for (p, c, m), x in self.cases.items():
            with self.subTest(plan=p, cut=c, mode=m):
                self.assertEqual([a['exit_code'] for a in x['diagnostics']], [97])
                self.assertEqual([a['cut'] for a in x['recovery_diagnostics']], list(REPEATED_CUTS))
                self.assertTrue(all(a['exit_code'] == 96 and a['authority_unchanged'] and a['business_dispatch_guarded'] for a in x['recovery_diagnostics']))
                for point in x['checkpoints']:
                    self.assertTrue({'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R15'} <= set(point['relation']))
                self.assertEqual(x['check']['receiver_live'], [])
                self.assertEqual(x['check']['sender_floor'], 1 if p.endswith('cancel') else 2)
                self.assertEqual(x['check']['sender_floor'], x['check']['receiver_floor'])

    def test_full_window_denial_and_recovered_capacity(self):
        for (p, c, m), x in self.cases.items():
            denied = [e for e in x['expected_records'] if e['kind'] == 'DELIVERY_REJECTED']
            self.assertEqual(len(denied), (1 + int(c not in DURABLE_CUTS)) if p.startswith('queued_') else 0)
            self.assertTrue(all(e['reason'] == 'V2_RECIPIENT_WINDOW_FULL' for e in denied))
            if p.startswith('queued_'):
                expected = (180 if p == 'queued_expire' else 120) + int(c not in DURABLE_CUTS)
                self.assertEqual(x['check']['facts']['b']['event_at'], expected)
            self.assertEqual(x['check']['facts']['a']['event_at'], 100)

    def test_refill_then_retire_never_resurrects_old_fact(self):
        for x in self.cases.values():
            replays = [e for e in x['expected_records'] if e['kind'] == 'DELIVERY_REPLAY']
            self.assertTrue(replays)
            self.assertTrue(all(e.get('reason') == 'V2_RETIRED' and 'response' not in e for e in replays))
            finals = [e for e in x['expected_records'] if e['kind'] == 'RETENTION_QUERY' and e.get('reason')]
            self.assertTrue(finals); self.assertTrue(all(e['reason'] == 'V2_RETIRED' for e in finals))

    def test_cached_submit_and_single_mechanism_call(self):
        for (p, c, m), x in self.cases.items():
            events = [e for e in x['expected_records'] if e['kind'] == 'PUBLIC' and parse_request(bytes.fromhex(e['request']))['method'] == 'SUBMIT']
            self.assertEqual(len(events), 3)
            self.assertEqual(events[1]['request'], events[2]['request']); self.assertEqual(events[1]['response'], events[2]['response'])
            expected = [('a', 'count')] + ([] if p.endswith('cancel') else [('b', 'histogram' if p.endswith('histogram') else 'count')])
            self.assertEqual(x['check']['draws'], expected)
            self.assertEqual(len(x['check']['mechanism_calls']), len(expected))
            self.assertEqual(x['check']['final'][1]['outcome'], 'WITHHELD' if p.endswith('cancel') else 'CLOSED' if p.endswith('expire') else 'ACCEPTED')

    def test_late_terminal_keeps_original_envelope_binding_and_deadline(self):
        for c in CUTS:
            x = self.cases['queued_expire', c, 'fresh']; ctx = decode(bytes.fromhex(x['config_cbor_hex']))['roots']['root']['context']
            envelope = None; terminal = None
            for e in x['expected_records']:
                if e['kind'] not in ('DELIVERY', 'DELIVERY_REJECTED'): continue
                a = d.parse_attempt(bytes.fromhex(e['request']), ctx); body = d.parse_body(a['kind'], a['body'], ctx)
                desc = d.parse_descriptor(body['descriptor'], ctx)
                if desc['operation'] != 'b': continue
                self.assertEqual((desc['issued_at'], desc['expires_at']), (110, 170))
                if a['kind'] == 'DELIVERY': envelope = a['body']
                else: terminal = body
            self.assertIsNotNone(envelope); self.assertIsNotNone(terminal)
            self.assertEqual(terminal['envelope_hash'], r.sha(envelope))

    def test_archive_replay_without_database_or_observed_response_inputs(self):
        with patch('sqlite3.connect', side_effect=AssertionError('replay DB')):
            for x in self.cases.values():
                x = json.loads(json.dumps(x)); sim, signer = self.simulator(x)
                self.assertEqual(sim.generate(x['commands']), x['expected_records'])
                self.assertEqual(signer.calls, x['signing_calls']); self.assertEqual(sim.state.final, x['check']['final'])
                self.assertIsNone(sim.needs_recovery)

    def test_malformed_loss_is_rejected_before_window_rewrite(self):
        x = self.cases['queued_count', CUTS[0], 'existing']; sim, signer = self.simulator(x)
        index = next(i for i, e in enumerate(x['expected_records']) if e['kind'] == 'DELIVERY_REJECTED')
        sim.generate(x['commands'][:index])
        before = deepcopy((sim.state.__dict__, sim.records, sim.projected_records, sim.pending, signer.calls))
        with self.assertRaisesRegex(ViewMismatch, 'LOSS_SCOPE'):
            sim.emit(dict(x['commands'][index], loss='invalid'))
        self.assertEqual((sim.state.__dict__, sim.records, sim.projected_records, sim.pending, signer.calls), before)

    def test_business_requires_explicit_recovery_completion(self):
        x = self.cases['queued_count', CUTS[1], 'fresh']; sim, _ = self.simulator(x)
        end = next(i for i, e in enumerate(x['commands']) if e['kind'] == 'RETIRE_RECOVER')
        sim.generate(x['commands'][:end])
        with self.assertRaisesRegex(ViewMismatch, 'RECOVERY_REQUIRED'):
            sim.emit(dict(kind='TICK', at=sim.state.now, tick=999))

    def test_frozen_retirement_profile_does_not_silently_expand(self):
        x = self.cases['after_retire_count', CUTS[0], 'existing']; sim, _ = self.simulator(x, strict=True)
        idx = next(i for i, e in enumerate(x['commands']) if e['kind'] == 'RETIRE_RECOVER')
        sim.generate(x['commands'][:idx + 3])
        with self.assertRaisesRegex(ViewMismatch, 'CLEANUP_ONLY_PROFILE'): sim.emit(x['commands'][idx + 3])

    @contextmanager
    def occupied(self):
        with tempfile.TemporaryDirectory() as td:
            run = WindowLifecycleRuntime(td)
            try:
                run.submit(); run.finish(); run.send(); run.confirm()
                run.now = 110; run.submit('b'); run.finish()
                yield run
            finally: run.close()

    def test_denial_observed_clock_negative_control(self):
        with self.occupied() as run:
            with patch.object(run.simulator, 'receiver_event', return_value=None):
                with self.assertRaisesRegex(StateRelationMismatch, 'R6.receiver_metadata'): run.send('b')

    def test_old_ciphertext_archive_negative_control(self):
        with self.occupied() as run:
            run.l.db.execute('UPDATE v2_outbox SET acknowledgement=? WHERE id=?', (b'corrupted', run.decision('a')['delivery_id']))
            with self.assertRaisesRegex(AssertionError, 'R15.confirmed_archive_changed'): run.assert_protected()

    def test_conditioned_neighbor_endpoints(self):
        a = run_window_lifecycle('queued_histogram', CUTS[1], 'fresh', 0)
        b = run_window_lifecycle('queued_histogram', CUTS[1], 'fresh', 7)
        self.assertEqual(a['expected_records'], b['expected_records']); self.assertEqual(a['checkpoints'], b['checkpoints'])


if __name__ == '__main__': unittest.main()
