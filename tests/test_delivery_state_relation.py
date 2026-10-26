"""Negative controls for durable transport state beyond R1--R4."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

P = Path(__file__).resolve().parents[1] / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from delivery_relation_trace import DeliveryRelationRuntime, DEFERRED_PLANS, run_delivery_relation
from delivery_state_relation import assert_delivery_relation
from restricted_trace import PLANS
from state_relation import assert_state_relation, StateRelationMismatch
from wire import decode, encode
import retention_delivery as d
import retention_wire as r


@contextmanager
def runtime(two=False):
    with tempfile.TemporaryDirectory() as directory:
        instance = DeliveryRelationRuntime(directory)
        try:
            instance.submit()
            if two:
                instance.submit('b')
                instance.call('CONTROL', dict(kind='cancel', operation='b'))
            instance.finish()
            yield instance
        finally:
            instance.close()


class DeliveryStateRelationTests(unittest.TestCase):
    def check(self, instance):
        return assert_delivery_relation(instance, instance.simulator)

    def row(self, instance):
        return instance.l.outbox('t', instance.decision('a')['delivery_id'])

    def test_all_existing_and_deferred_plans_check_eight_relations(self):
        for plan in PLANS + DEFERRED_PLANS:
            with self.subTest(plan=plan):
                result = run_delivery_relation(plan)
                self.assertEqual(len(result['checkpoints']), len(result['records']) + 1)
                self.assertTrue(all(set(point['relation']) == {'R' + str(i) for i in range(1, 9)} for point in result['checkpoints']))

    def test_visible_receipt_and_idle_slot_do_not_confirm_sender(self):
        with runtime() as instance:
            instance.send_unconfirmed()
            self.assertEqual(self.row(instance)['state'], 'READY')
            self.assertEqual(len(instance.simulator.state.receiver), 1)
            self.assertEqual(instance.simulator.state.final, [])
            self.assertIsNone(self.row(instance)['fact'])
            instance.advance()
            self.assertEqual(instance.l.final_frontier('t', 'domain'), 0)
            instance.confirm_deferred()
            self.assertEqual(instance.l.final_frontier('t', 'domain'), 1)
            self.check(instance)

    def test_packet_loss_and_ack_loss_have_different_recipient_states(self):
        with runtime() as instance:
            instance.deliver(loss='packet')
            self.assertEqual(instance.receivers, {})
            self.assertIsNotNone(self.row(instance)['envelope'])
            instance.deliver(loss='ack')
            self.assertEqual(len(instance.receivers), 1)
            self.assertEqual(self.row(instance)['state'], 'READY')
            self.assertIsNone(self.row(instance)['fact'])
            self.check(instance)

    def test_replaced_or_unauthenticated_prepared_bytes_are_detected(self):
        for broken_ciphertext in (False, True):
            with self.subTest(broken_ciphertext=broken_ciphertext), runtime() as instance:
                instance.deliver(loss='packet')
                row = self.row(instance)
                if broken_ciphertext:
                    value = row['envelope'][:-1] + bytes([row['envelope'][-1] ^ 1])
                else:
                    context = instance.cfg['roots']['root']['context']
                    # Valid signature and ciphertext, but a different authorized
                    # output than the model's operation-bound mechanism value.
                    altered = d.envelope(row['descriptor'], (0).to_bytes(8, 'big'), context, instance.s)
                    value = instance.l.seal('envelope', row, altered)
                instance.l.db.execute('UPDATE v2_outbox SET envelope=? WHERE id=?', (value, row['id']))
                assert_state_relation(instance, instance.simulator.state)
                with self.assertRaisesRegex(StateRelationMismatch, 'R5.prepared'):
                    self.check(instance)

    def test_missing_terminal_and_changed_handoff_are_detected(self):
        with runtime() as instance:
            instance.now = 170
            instance.deliver(terminal=True, loss='packet')
            instance.l.db.execute('UPDATE v2_outbox SET control=NULL')
            with self.assertRaisesRegex(StateRelationMismatch, 'R5.prepared'):
                self.check(instance)
        with runtime() as instance:
            instance.deliver(loss='packet')
            instance.l.db.execute('UPDATE deliveries SET handoff_admitted=0')
            with self.assertRaisesRegex(StateRelationMismatch, 'R5.handoff'):
                self.check(instance)

    def test_validly_resealed_changed_first_time_breaks_correspondence(self):
        with runtime() as instance:
            instance.send_unconfirmed()
            inbox = instance.receivers['reader'][0]
            row = inbox.db.execute('SELECT * FROM v2_recipient_live').fetchone()
            body = inbox.open('evidence', row)
            changed = d.accepted_fact(body, 101, inbox.context)
            encrypted = inbox.seal('fact', 1, row['id'], changed)
            inbox.db.execute('UPDATE v2_recipient_live SET fact=?', (encrypted,))
            inbox.db.execute('UPDATE v2_recipient_meta SET observed=101')
            self.assertEqual(inbox.audit_local(), [])
            with self.assertRaisesRegex(StateRelationMismatch, 'R6.first_facts_and_evidence'):
                self.check(instance)

    def test_terminal_after_visible_unconfirmed_receipt_preserves_first_fact(self):
        with runtime() as instance:
            instance.send_unconfirmed()
            original = next(iter(instance.simulator.state.receiver.values()))
            instance.now = 170
            instance.deliver(terminal=True)
            self.assertEqual(next(iter(instance.simulator.state.receiver.values())), original)
            fact = r.parse_fact(original, instance.cfg['roots']['root']['context'])
            self.assertEqual((fact['outcome'], fact['event_at']), ('ACCEPTED', 100))
            self.assertEqual(self.row(instance)['state'], 'ACCEPTED')
            self.check(instance)

    def test_confirmation_without_recorded_confirm_event_is_detected(self):
        with runtime() as instance:
            instance.send_unconfirmed()
            did, request, ack = instance.deferred['a']
            instance.l.confirm('t', did, request, ack)
            assert_state_relation(instance, instance.simulator.state)
            with self.assertRaisesRegex(StateRelationMismatch, 'R7.sender_states'):
                self.check(instance)

    def test_sender_receipt_must_bind_original_confirmed_attempt(self):
        with runtime() as instance:
            instance.deliver()
            row = self.row(instance)
            stored = decode(instance.l.open('acknowledgement', row))
            context = instance.cfg['roots']['root']['context']
            attempt = d.parse_attempt(stored['request'], context)
            stored['request'] = d.attempt(attempt['kind'], attempt['body'], b'X' * 32, context, instance.s)
            value = instance.l.seal('acknowledgement', row, encode(stored))
            instance.l.db.execute('UPDATE v2_outbox SET acknowledgement=?', (value,))
            with self.assertRaisesRegex(StateRelationMismatch, 'R7.sender_facts_and_receipts'):
                self.check(instance)

    def test_sender_confirmed_prefix_root_is_checked(self):
        with runtime() as instance:
            instance.deliver()
            instance.l.db.execute('UPDATE v2_routes SET confirmed_root=?', (b'X' * 32,))
            with self.assertRaisesRegex(StateRelationMismatch, 'R7.route_confirmed_prefix'):
                self.check(instance)

    def test_early_final_row_and_missing_withheld_suffix_are_detected(self):
        with runtime() as instance:
            instance.send_unconfirmed()
            instance.l.db.execute('INSERT INTO final_events VALUES(?,?,?,?,?)', ('t', 'domain', 1, 'ACCEPTED', self.row(instance)['id']))
            assert_state_relation(instance, instance.simulator.state)
            with self.assertRaisesRegex(StateRelationMismatch, 'R8.durable_final_rows'):
                self.check(instance)
        with runtime(two=True) as instance:
            instance.send_unconfirmed()
            self.assertEqual(instance.l.final_frontier('t', 'domain'), 0)
            instance.confirm_deferred()
            self.assertEqual(instance.l.final_frontier('t', 'domain'), 2)
            instance.l.db.execute('DELETE FROM final_events WHERE seq=2')
            with self.assertRaisesRegex(StateRelationMismatch, 'R8.durable_final_rows'):
                self.check(instance)

    def test_unmodeled_retirement_cannot_be_silently_ignored(self):
        with runtime() as instance:
            instance.deliver()
            instance.l.db.execute('UPDATE v2_routes SET retired=?,retirement_evidence=?', ((1).to_bytes(8, 'big'), b'x'))
            with self.assertRaisesRegex(StateRelationMismatch, 'R5.no_retirement'):
                self.check(instance)

    def test_checker_is_read_only_and_never_reads_private_computation(self):
        with runtime() as instance:
            instance.deliver()
            denied = []
            def authorize(action, table, column, database, trigger):
                if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE) or (action == sqlite3.SQLITE_READ and table in {'operations', 'jobs', 'snapshots'}):
                    denied.append((action, table, column))
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            connections = [instance.l.db] + [inbox.db for inbox, _ in instance.receivers.values()]
            for connection in connections:
                connection.set_authorizer(authorize)
            try:
                self.check(instance)
                self.assertEqual(denied, [])
            finally:
                for connection in connections:
                    connection.set_authorizer(None)


if __name__ == '__main__':
    unittest.main()
