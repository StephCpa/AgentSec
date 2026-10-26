#!/usr/bin/env python3
"""Check symbolic obligations, export exact SMT-LIB inputs, fail on unknown.

Every implication also has a separate SAT premise-consistency check, so an
inconsistent precondition cannot masquerade as a successful safety proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys
from importlib.metadata import version
import z3 as z
from model import obligations, MAX_SEQ, MAX_TIME, MAX_WINDOW


def solve_obligation(obligation, output, timeout_ms):
    row = dict(name=obligation.name, expected_counterexample_result=obligation.expected, explanation=obligation.explanation, passed=False)
    for label, formula, expected in (('premise', obligation.premise, 'sat'),
                                    ('counterexample', z.And(obligation.premise, z.Not(obligation.conclusion)), obligation.expected)):
        substitutions = obligation.witness_substitution if expected == 'sat' else ()
        if substitutions:
            formula = z.And(z.substitute(formula, *substitutions), obligation.witness_bounds)
        formula = z.simplify(formula)
        solver = z.Solver(); solver.set(timeout=timeout_ms); solver.add(formula)
        raw = solver.to_smt2(); name = obligation.name + '.' + label + '.smt2'
        (output / name).write_text(raw)
        status = str(solver.check())
        item = dict(result=status, expected=expected, smt2=name, sha256=hashlib.sha256(raw.encode()).hexdigest())
        item['constructive_witness_substitution'] = {str(a): b.sexpr() for a, b in substitutions}
        if status == 'unknown': item['reason_unknown'] = solver.reason_unknown()
        if status == 'sat':
            model = solver.model()
            item['values'] = {key: str(model.eval(z.substitute(value, *substitutions) if substitutions else value, model_completion=True))
                              for key, value in obligation.inspect.items()}
            if label == 'counterexample': item['model'] = model.sexpr()
        row[label] = item
        if status != expected: return row
    row['passed'] = True
    return row


def run(output, timeout_ms=30000):
    contract = json.loads((Path(__file__).parent / 'contract.json').read_text())
    declared = obligations()
    if (len(declared) != len(contract['obligations']) or {o.name: o.expected for o in declared} != contract['obligations'] or
        (MAX_SEQ, MAX_TIME, MAX_WINDOW) != (contract['max_sequence'], contract['max_time'], contract['max_window'])):
        raise AssertionError('model differs from declared obligation contract')
    if 'z3-solver==' + version('z3-solver') != contract['solver_package']: raise AssertionError('solver package differs from contract')
    output.mkdir(parents=True, exist_ok=False)
    report = dict(profile='retention-induction-v1', passed=False, solver=z.get_full_version(),
                  solver_version=z.get_version_string(), solver_package=version('z3-solver'),
                  python=sys.version, platform=platform.platform(), timeout_ms=timeout_ms, obligations=[],
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.iterdir()
                                 if p.is_file() and p.suffix in ('.py', '.txt', '.json')})
    for obligation in declared:
        row = solve_obligation(obligation, output, timeout_ms)
        report['obligations'].append(row)
        if not row['passed']:
            (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
            raise AssertionError('obligation failed: ' + obligation.name)
        print('PASS', obligation.name, 'premise=sat', 'counterexample=' + obligation.expected, flush=True)
    report.update(passed=True, obligations_count=len(report['obligations']),
                  proved_implications=sum(r['expected_counterexample_result'] == 'unsat' for r in report['obligations']),
                  detected_mutations=sum(r['expected_counterexample_result'] == 'sat' for r in report['obligations']),
                  satisfiable_premises=len(report['obligations']))
    (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout-ms', type=int, default=30000); args = parser.parse_args()
    if args.output.exists() or args.timeout_ms <= 0: parser.error('choose a new output directory and positive timeout')
    run(args.output, args.timeout_ms)


if __name__ == '__main__': main()
