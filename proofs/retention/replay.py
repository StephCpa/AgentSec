#!/usr/bin/env python3
"""Replay exported SMT-LIB in fresh Z3 CLI processes, without importing model.py.

This uses the same solver implementation through a separate entry point; it is
not independent theorem-prover certification or an independent proof kernel.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def checked_file(root, name, expected_hash):
    path = (root / name).resolve(); path.relative_to(root.resolve())
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash: raise ValueError('digest differs: ' + name)
    return path


def validate_report(report, contract):
    rows = report['obligations']
    if report['profile'] != contract['profile'] or not report['passed']: raise ValueError('unverified or wrong profile')
    if 'z3-solver==' + report['solver_package'] != contract['solver_package']: raise ValueError('solver contract differs')
    expected = contract['obligations']
    if len(rows) != len(expected) or {x['name']: x['expected_counterexample_result'] for x in rows} != expected:
        raise ValueError('obligation matrix differs')
    for row in rows:
        if not row['passed']: raise ValueError('failed obligation')
        for label, result in (('premise', 'sat'), ('counterexample', expected[row['name']])):
            item = row[label]
            if item['expected'] != result or item['result'] != result: raise ValueError('result differs from contract')
            if item['smt2'] != row['name'] + '.' + label + '.smt2': raise ValueError('wrong query identity')
            if result == 'unsat' and item['constructive_witness_substitution']: raise ValueError('restricted positive proof')
    counts = dict(obligations_count=len(rows), proved_implications=sum(v == 'unsat' for v in expected.values()),
                  detected_mutations=sum(v == 'sat' for v in expected.values()), satisfiable_premises=len(rows))
    if any(report[k] != v for k, v in counts.items()): raise ValueError('summary totals differ')
    return counts


def replay(evidence, solver=None, timeout_seconds=30):
    report_path = evidence / 'summary.json'; report = json.loads(report_path.read_text())
    contract = json.loads((HERE / 'contract.json').read_text()); counts = validate_report(report, contract)
    for name, h in report['source_sha256'].items(): checked_file(HERE, name, h)
    solver = solver or shutil.which('z3')
    if not solver: raise RuntimeError('Z3 CLI is required')
    version = subprocess.run([solver, '-version'], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    if version.split()[2] != report['solver_version']: raise ValueError('CLI solver version differs')
    results = []
    for row in report['obligations']:
        for label in ('premise', 'counterexample'):
            item = row[label]; path = checked_file(evidence, item['smt2'], item['sha256'])
            proc = subprocess.run([solver, '-T:' + str(timeout_seconds), '-smt2', str(path)],
                                  capture_output=True, text=True, timeout=timeout_seconds + 5)
            status = proc.stdout.strip()
            if proc.returncode != 0 or status != item['expected']: raise AssertionError(path.name + ': ' + status + ' ' + proc.stderr)
            results.append(dict(query=path.name, sha256=item['sha256'], result=status))
    return dict(passed=True, **counts, queries=len(results), solver_cli_version=version, results=results,
                summary_sha256=hashlib.sha256(report_path.read_bytes()).hexdigest(),
                source_sha256=report['source_sha256'], scope=__doc__)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('evidence', type=Path); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--solver'); args = parser.parse_args()
    if args.output.exists(): parser.error('output exists')
    result = replay(args.evidence, args.solver); args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('PASS', result['queries'], 'fresh-process SMT-LIB replays')


if __name__ == '__main__': main()
