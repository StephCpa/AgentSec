"""State-level controls that byte equality or total-budget checks can miss."""
from contextlib import contextmanager
from pathlib import Path
import sys
import sqlite3
import tempfile
import unittest

P = Path(__file__).resolve().parents[1] / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from restricted_trace import PLANS
from stepwise_trace import StepwiseRuntime, run_stepwise
from state_relation import StateRelationMismatch, assert_state_relation


@contextmanager
def runtime(**kwargs):
    with tempfile.TemporaryDirectory() as directory:
        instance = StepwiseRuntime(directory, **kwargs)
        try:
            yield instance
        finally:
            instance.close()


class StateRelationTests(unittest.TestCase):
    def check(self, instance):
        return assert_state_relation(instance, instance.simulator.state)

    def test_all_plans_hold_at_initial_and_every_completed_event(self):
        for plan in PLANS:
            with self.subTest(plan=plan):
                result = run_stepwise(plan)
                self.assertEqual(len(result['checkpoints']), len(result['records']) + 1)
                self.assertTrue(all(set(c['relation']) == {'R1', 'R2', 'R3', 'R4'} for c in result['checkpoints']))

    def test_adaptive_count_branch_and_neighbor_state_projections(self):
        reference = run_stepwise('adaptive', mask=0, target=2)
        other = run_stepwise('adaptive', mask=7, target=2)
        self.assertEqual(reference['checkpoints'], other['checkpoints'])
        self.assertEqual(reference['check']['draws'], [('a', 'count'), ('b', 'count')])

    def test_corrupted_cached_response_is_detected_before_a_retry(self):
        with runtime() as instance:
            instance.submit()
            instance.l.db.execute("UPDATE gw_requests SET response=x'00' WHERE seq=1")
            with self.assertRaisesRegex(StateRelationMismatch, 'R1.request_cache'):
                self.check(instance)

    def test_relation_is_read_only_and_does_not_read_private_work_columns(self):
        with runtime() as instance:
            instance.submit()
            instance.advance()
            denied = []
            def authorize(action, table, column, database, trigger):
                private = table == 'snapshots' or (table == 'jobs' and column in {'private_state', 'count_value', 'alive0', 'alive1', 'g0', 'g1'})
                if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE) or (action == sqlite3.SQLITE_READ and private):
                    denied.append((action, table, column))
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            instance.l.db.set_authorizer(authorize)
            try:
                self.check(instance)
                self.assertEqual(denied, [])
            finally:
                instance.l.db.set_authorizer(None)

    def test_challenge_and_proof_association_are_checked(self):
        for mutation, label in [("UPDATE challenges SET used=0", 'R1.challenges'),
                                ("UPDATE used_proofs SET operation_id='wrong'", 'R1.proof_consumption')]:
            with self.subTest(label=label), runtime() as instance:
                instance.submit()
                instance.l.db.execute(mutation)
                with self.assertRaisesRegex(StateRelationMismatch, label):
                    self.check(instance)

    def test_premature_spending_cannot_hide_behind_same_allocated_total(self):
        with runtime() as instance:
            instance.submit()
            before = instance.l.db.execute('SELECT sum(reserved+spent) FROM accounts').fetchone()[0]
            instance.l.db.execute('UPDATE accounts SET spent=spent+reserved,reserved=0')
            after = instance.l.db.execute('SELECT sum(reserved+spent) FROM accounts').fetchone()[0]
            self.assertEqual(before, after)
            with self.assertRaisesRegex(StateRelationMismatch, 'R2.accounts'):
                self.check(instance)

    def test_charge_disposition_cannot_advance_before_l2(self):
        with runtime() as instance:
            instance.submit()
            instance.advance()
            instance.l.db.execute("UPDATE charges SET disposition='SPENT'")
            with self.assertRaisesRegex(StateRelationMismatch, 'R2.charges'):
                self.check(instance)

    def test_wrong_l1_tick_is_detected_with_unchanged_outputs(self):
        with runtime() as instance:
            instance.submit()
            instance.advance()
            instance.runtime_draws[0] = ('a', 'count', 2)
            with self.assertRaisesRegex(StateRelationMismatch, 'R2.L1_calls'):
                self.check(instance)

    def test_wrong_cursor_and_work_while_paused_are_detected(self):
        with runtime() as instance:
            instance.submit()
            instance.advance()
            instance.l.db.execute('UPDATE schedulers SET cursor=0')
            with self.assertRaisesRegex(StateRelationMismatch, 'R3.scheduler'):
                self.check(instance)
        with runtime() as instance:
            instance.submit()
            instance.call('CONTROL', dict(kind='pause'), 'manager')
            instance.advance()
            instance.l.db.execute('UPDATE jobs SET pc=1')
            with self.assertRaisesRegex(StateRelationMismatch, 'R3.jobs'):
                self.check(instance)

    def test_original_ticket_deadline_and_descriptor_are_bound(self):
        for mutation, label in [("UPDATE deliveries SET expires_at=expires_at+1", 'R4.tickets'),
                                ("UPDATE v2_outbox SET descriptor=x'00'", 'R4.outbox_identity')]:
            with self.subTest(label=label), runtime() as instance:
                instance.submit()
                instance.finish()
                instance.l.db.execute(mutation)
                with self.assertRaisesRegex(StateRelationMismatch, label):
                    self.check(instance)

    def test_missing_publication_decision_is_detected_before_poll(self):
        with runtime() as instance:
            instance.submit()
            instance.finish()
            instance.l.db.execute('DELETE FROM pub_decisions')
            with self.assertRaisesRegex(StateRelationMismatch, 'R4.decisions'):
                self.check(instance)

    def test_authorization_ceiling_includes_every_ancestor_key(self):
        for kid in (b'authority', b'manager', b'worker', b'leaf'):
            with self.subTest(kid=kid), runtime(ancestor_expiries={kid: 110}) as instance:
                instance.submit()
                self.assertEqual(instance.simulator.state.by_id['a']['authorization_expiry'], 110)
                instance.simulator.state.by_id['a']['authorization_expiry'] = 160
                with self.assertRaisesRegex(StateRelationMismatch, 'R4.authorization_ceiling'):
                    self.check(instance)

    def test_expiry_before_l1_and_before_publication_keep_distinct_charges(self):
        for started in (False, True):
            with self.subTest(started=started), runtime(ancestor_expiries={b'authority': 110}) as instance:
                instance.submit()
                if started:
                    instance.advance()
                instance.now = 110
                instance.finish()
                job = instance.simulator.state.by_id['a']
                self.assertEqual(job['publication'], 'WITHHELD')
                self.assertEqual(job['state'], 'COMMITTED' if started else 'CANCELED')
                disposition = instance.l.db.execute('SELECT DISTINCT disposition FROM charges').fetchone()[0]
                self.assertEqual(disposition, 'SPENT' if started else 'RETURNED')


if __name__ == '__main__':
    unittest.main()
