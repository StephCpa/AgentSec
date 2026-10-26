"""Common events must preserve observations without exposing harness causes."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
P = ROOT/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from observation_events import normalize, to_legacy, caller_view, EventStream, EventError, COMMANDS, ALLOWED
from observation_events_audit import audit_case


class ObservationEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = json.loads((ROOT/'tests/fixtures/observation-events.json').read_text())['cases']

    def pair(self, command_kind, event_kind=None, **fields):
        for row in self.fixtures:
            c, e = row['command'], row['event']
            if c['kind'] == command_kind and (event_kind is None or e['kind'] == event_kind) and all(c.get(k) == v for k, v in fields.items()):
                return deepcopy(c), deepcopy(e)
        self.fail('missing test fixture')

    def test_all_command_event_forms_roundtrip_without_database(self):
        seen = set()
        with patch('sqlite3.connect', side_effect=AssertionError('event adapter accessed storage')):
            for x in self.fixtures:
                c, e = x['command'], x['event']; before = deepcopy((c, e))
                n = normalize(c, e)
                self.assertEqual(to_legacy(n), before)
                self.assertEqual((c, e), before)
                seen.add((c['kind'], e['kind']))
        self.assertEqual(seen, {(c, e) for c in COMMANDS for e in ALLOWED[c]})
        self.assertEqual({x['public_method'] for x in self.fixtures if x['public_method']},
                         {'CHALLENGE', 'SUBMIT', 'POLL', 'CONTROL', 'FINAL'})
        self.assertEqual({x['public_status'] for x in self.fixtures if x['public_status']},
                         {'CHALLENGE', 'RECORDED', 'POLL', 'CONTROL_RECORDED', 'FINAL', 'REJECTED'})

    def test_confirmation_receipt_is_input_not_new_output(self):
        for kind in ('CONFIRM', 'CONFIRM_CUT', 'RETIRE_CONFIRM', 'RETIRE_CONFIRM_CUT'):
            c, e = self.pair(kind); n = normalize(c, e)
            self.assertEqual(n['call']['wire']['receipt'], e['response'])
            self.assertNotIn('value', n['outcome'])
            n['outcome'] = dict(kind='returned_bytes', value=e['response'])
            with self.assertRaises(EventError):
                to_legacy(n)

    def test_cut_and_commit_location_do_not_enter_caller_view(self):
        c, e = self.pair('PUBLIC_CUT'); before = normalize(c, e)
        c['cut'] = 'before_witness_accept'; pre = normalize(c, e)
        c['cut'] = 'after_witness_accept'; post = normalize(c, e)
        self.assertEqual(caller_view(pre), caller_view(post))
        self.assertNotEqual(pre, post)
        self.assertEqual(before['outcome'], {'kind': 'no_return'})
        self.assertNotIn('environment', caller_view(before)); self.assertNotIn('source', caller_view(before))

    def test_packet_loss_and_ack_loss_preserved_only_as_environment(self):
        c, e = self.pair('SEND', loss='packet'); packet = normalize(c, e)
        c['loss'] = 'ack'; e['response'] = 'ACK_LOST'; ack = normalize(c, e)
        self.assertEqual(caller_view(packet), caller_view(ack))
        self.assertNotEqual(to_legacy(packet), to_legacy(ack))
        e['response'] = 'PACKET_LOST'
        with self.assertRaises(EventError):
            normalize(c, e)

    def test_exact_exception_code_is_never_erased_or_invented(self):
        for kind in ('PUBLIC', 'TICK', 'RETENTION_QUERY'):
            c, e = self.pair(kind, {'PUBLIC':'PUBLIC_UNAVAILABLE', 'TICK':'TICK_UNAVAILABLE', 'RETENTION_QUERY':'RETENTION_UNAVAILABLE'}[kind])
            self.assertEqual(normalize(c, e)['outcome'], dict(kind='exception', code='WITNESS_RECOVERY_REQUIRED'))
            del e['error']
            with self.assertRaises(EventError):
                normalize(c, e)
        c, e = self.pair('PUBLIC_CUT'); e['error'] = 'WITNESS_RECOVERY_REQUIRED'
        with self.assertRaises(EventError):
            normalize(c, e)

    def test_signed_rejection_is_preserved_as_signed_bytes(self):
        from wire import decode, inspect_sign1
        from public_gateway import RESPONSE_TYPE
        row = next(x for x in self.fixtures if x.get('public_status') == 'REJECTED')
        c, e = deepcopy((row['command'], row['event']))
        self.assertEqual(decode(inspect_sign1(bytes.fromhex(e['response']), RESPONSE_TYPE)[1])['status'], 'REJECTED')
        n = normalize(c, e)
        self.assertEqual(n['outcome'], dict(kind='returned_bytes', value=e['response']))
        # Neither method/status parsing nor generic business-error aliases can
        # replace the complete signed reply in this vocabulary.
        e['reason'] = 'GW_PAYLOAD'
        with self.assertRaises(EventError):
            normalize(c, e)

    def test_confirmation_requires_previously_observed_exact_pair(self):
        c, e = self.pair('CONFIRM'); stream = EventStream()
        with self.assertRaisesRegex(EventError, 'unobserved receipt'):
            stream.append(c, e)
        self.assertEqual((stream.now, stream.count, stream.receipts), (0, 0, set()))
        send, delivery = self.pair('SEND', loss='none')
        send['at'] = c['at']; delivery['at'] = c['at']
        delivery['request'] = e['request']; delivery['response'] = e['response']
        stream.append(send, delivery); stream.append(c, e)
        forged = deepcopy(e); forged['response'] += '00'
        with self.assertRaisesRegex(EventError, 'unobserved receipt'):
            stream.append(c, forged)
        self.assertEqual(stream.count, 2)

    def test_ack_loss_cannot_authorize_confirmation(self):
        c, e = self.pair('CONFIRM'); send, delivery = self.pair('SEND', loss='ack')
        send['at'] = c['at']; delivery.update(at=c['at'], request=e['request'])
        stream = EventStream(); stream.append(send, delivery)
        with self.assertRaisesRegex(EventError, 'unobserved receipt'):
            stream.append(c, e)

    def test_replayed_delivery_receipt_is_an_observed_input(self):
        c, e = self.pair('CONFIRM'); replay, received = self.pair('DELIVERY_REPLAY')
        replay['at'] = c['at']; received.update(at=c['at'], request=e['request'], response=e['response'])
        del received['reason']
        stream = EventStream(); stream.append(replay, received); stream.append(c, e)
        self.assertEqual(stream.count, 2)

    def test_invocation_binding_clock_and_boolean_integer_mutants(self):
        c, e = self.pair('TICK')
        for change in ({'at': c['at'] + 1}, {'tick': c['tick'] + 1}, {'tick': True}, {'kind': 'RECOVER'}):
            with self.subTest(change=change), self.assertRaises(EventError):
                normalize(c, dict(e, **change))
        c['tick'] = True; e['tick'] = True
        with self.assertRaises(EventError):
            normalize(c, e)
        c, e = self.pair('PREPARE', 'PREPARATION'); e['operation'] = 'wrong-operation'
        with self.assertRaises(EventError):
            normalize(c, e)

    def test_unknown_fields_malformed_hex_and_channel_changes_fail_closed(self):
        c, e = self.pair('PUBLIC', 'PUBLIC')
        for bad in (dict(e, commit=True), dict(e, response='ab zz'), dict(e, response='AABB'), dict(e, response='0')):
            with self.assertRaises(EventError):
                normalize(c, bad)
        n = normalize(c, e); n['call']['endpoint'] = 'recipient.accept'
        with self.assertRaises(EventError):
            caller_view(n)
        n = normalize(c, e); n['outcome']['private_progress'] = 7
        with self.assertRaises(EventError):
            to_legacy(n)
        n = normalize(c, e); n['call']['caller'] = 'trusted_scheduler'
        with self.assertRaises(EventError):
            caller_view(n)

    def test_trace_time_regression_is_atomic(self):
        c, e = self.pair('TICK'); c['at'] = e['at'] = 100
        stream = EventStream(); stream.append(c, e)
        c['at'] = e['at'] = 99
        with self.assertRaises(EventError):
            stream.append(c, e)
        self.assertEqual((stream.now, stream.count), (100, 1))

    def test_audit_rejects_omitted_events_and_preserves_error_distinction(self):
        c, e = self.pair('PUBLIC', 'PUBLIC_UNAVAILABLE')
        with self.assertRaises(ValueError):
            audit_case(dict(commands=[c], expected_records=[]))
        one = audit_case(dict(commands=[c], expected_records=[e]))
        c2, e2 = self.pair('PUBLIC_CUT'); c2.update(at=c['at'], request=c['request'], peer=c['peer'])
        e2.update(at=c['at'], request=c['request'], peer=c['peer'])
        two = audit_case(dict(commands=[c2], expected_records=[e2]))
        self.assertNotEqual(one['caller_view_sha256'], two['caller_view_sha256'])


class FreshRuntimeObservationTests(unittest.TestCase):
    def test_all_nine_runtime_families_share_event_contract(self):
        from constructive_trace import run_constructed
        from public_recovery_trace import run_recovery
        from private_recovery_trace import run_kernel
        from delivery_recovery_trace import run_delivery_recovery
        from recovery_interruption_trace import run_interrupted
        from preparation_recovery_trace import run_preparation_recovery
        from retirement_recovery_trace import run_retirement_recovery
        from window_lifecycle_trace import run_window_lifecycle
        from cross_route_isolation_trace import run_cross_route_isolation
        normal = run_constructed('normal')
        cases = [('normal', dict(commands=normal['commands'], expected_records=normal['records'])),
            ('public', run_recovery('submit', 'after_witness_accept')),
            ('private', run_kernel(False, 'l1', 'after_sampling')),
            ('delivery', run_delivery_recovery('receive_count', 'after_witness_accept')),
            ('recovery', run_interrupted('public_submit_post', 'fresh')),
            ('preparation', run_preparation_recovery('envelope_count', 'after_witness_accept')),
            ('retirement', run_retirement_recovery('confirm_checkpoint', 'after_witness_accept')),
            ('window', run_window_lifecycle('after_retire_count', 'after_witness_accept')),
            ('isolation', run_cross_route_isolation('sender', 'after_witness_accept', 'count', 'after_fault'))]
        for name, case in cases:
            with self.subTest(family=name):
                result = audit_case(case)
                self.assertEqual(result['events'], len(case['commands']))


if __name__ == '__main__':
    unittest.main()
