"""The proof harness must fail on vacuity, unknown, missing scope and tampering."""
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import z3 as z
from check import run, solve_obligation
from model import Obligation
from replay import checked_file, validate_report


class ProofHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(); cls.root = Path(cls.temp.name)
        with redirect_stdout(StringIO()): cls.report = run(cls.root / 'proofs')
        cls.contract = json.loads((Path(__file__).parent / 'contract.json').read_text())

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def solve(self, obligation):
        with tempfile.TemporaryDirectory() as td: return solve_obligation(obligation, Path(td), 1000)

    def test_all_declared_obligations_and_nonvacuity_checks(self):
        counts = validate_report(self.report, self.contract)
        self.assertEqual(counts, dict(obligations_count=37, proved_implications=23, detected_mutations=14, satisfiable_premises=37))
        self.assertTrue(all(row['premise']['result'] == 'sat' for row in self.report['obligations']))
        for row in self.report['obligations']:
            if row['expected_counterexample_result'] == 'unsat':
                self.assertEqual(row['counterexample']['constructive_witness_substitution'], {})

    def test_witness_cannot_mask_a_false_universal_claim(self):
        width = z.Int('test_width')
        obligation = Obligation('false_universal', width >= 1, width <= 3, 'unsat', {'width': width},
                                'Only the SAT witness may choose width=1.', ((width, z.IntVal(1)),), z.BoolVal(True))
        row = self.solve(obligation)
        self.assertEqual(row['premise']['result'], 'sat')
        self.assertEqual(row['counterexample']['result'], 'sat'); self.assertFalse(row['passed'])
        self.assertGreater(int(row['counterexample']['values']['width']), 3)

    def test_inconsistent_premise_does_not_pass_by_vacuity(self):
        row = self.solve(Obligation('vacuous', z.BoolVal(False), z.BoolVal(True), 'unsat', {}, 'Contradictory premise.'))
        self.assertFalse(row['passed']); self.assertEqual(row['premise']['result'], 'unsat')

    def test_unknown_is_failure(self):
        with patch('check.z.Solver') as cls:
            cls.return_value.to_smt2.return_value = '(check-sat)\n'
            cls.return_value.check.return_value = z.unknown
            cls.return_value.reason_unknown.return_value = 'forced timeout'
            row = self.solve(Obligation('unknown', z.BoolVal(True), z.BoolVal(True), 'unsat', {}, 'Injected timeout.'))
        self.assertFalse(row['passed']); self.assertEqual(row['premise']['reason_unknown'], 'forced timeout')

    def test_missing_obligation_is_not_a_complete_replay(self):
        report = deepcopy(self.report); report['obligations'].pop()
        with self.assertRaisesRegex(ValueError, 'obligation matrix'): validate_report(report, self.contract)

    def test_duplicate_obligation_is_rejected(self):
        report = deepcopy(self.report); report['obligations'][-1] = report['obligations'][0]
        with self.assertRaisesRegex(ValueError, 'obligation matrix'): validate_report(report, self.contract)

    def test_restricted_positive_proof_is_rejected(self):
        report = deepcopy(self.report)
        report['obligations'][0]['counterexample']['constructive_witness_substitution'] = {'width': '1'}
        with self.assertRaisesRegex(ValueError, 'restricted positive'): validate_report(report, self.contract)

    def test_wrong_expected_result_is_rejected(self):
        report = deepcopy(self.report); report['obligations'][0]['counterexample']['expected'] = 'sat'
        with self.assertRaisesRegex(ValueError, 'result differs'): validate_report(report, self.contract)

    def test_changed_query_and_path_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); path = root / 'query.smt2'; path.write_text('(assert false)\n(check-sat)\n')
            h = hashlib.sha256(path.read_bytes()).hexdigest(); self.assertEqual(checked_file(root, path.name, h), path.resolve())
            path.write_text('(check-sat)\n')
            with self.assertRaisesRegex(ValueError, 'digest differs'): checked_file(root, path.name, h)
            with self.assertRaises(ValueError): checked_file(root, '../outside.smt2', h)


if __name__ == '__main__': unittest.main()
