#!/usr/bin/env python3
"""Regenerate archived public observations from commands, without a runtime DB.

Expected responses are used only after generation, for comparison. All signing
keys in this research archive are synthetic fixtures, not production material.
"""
import argparse
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PROTOTYPE = ROOT / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(PROTOTYPE))
from constructive_trace import FixtureSigningOracle
from public_gateway import PublicGatewayLedger
from public_simulator import PublicSimulator
from public_trace_adapter import PublicTraceAdapter
from wire import decode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output exists; choose a new path')
    summary_path = args.evidence / 'summary.json'
    archive_path = args.evidence / 'inputs-and-expected.json.gz'
    summary = json.loads(summary_path.read_text())
    for name, expected in summary['source_sha256'].items():
        if Path(name).name != name:
            raise ValueError('source name must be a basename')
        actual = hashlib.sha256((PROTOTYPE / name).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError('source differs from experiment: ' + name)
    with gzip.open(archive_path, 'rt') as stream:
        cases = json.load(stream)
    if len(cases) != summary['cases_count'] or len(cases) != len(summary['cases']):
        raise ValueError('case count differs from summary')
    results = []
    for case, expected_case in zip(cases, summary['cases']):
        identity = {key: case[key] for key in ('plan', 'target', 'mask')}
        if any(expected_case[key] != value for key, value in identity.items()):
            raise ValueError('case ordering differs from summary')
        config = decode(bytes.fromhex(case['config_cbor_hex']))
        outputs = {key: tuple(value) for key, value in case['approved_outputs'].items()}
        commands = deepcopy(case['commands'])
        signer = FixtureSigningOracle()
        with patch('sqlite3.connect', side_effect=AssertionError('DB access')), \
             patch.object(PublicGatewayLedger, 'handle_public', side_effect=AssertionError('runtime access')), \
             patch.object(PublicTraceAdapter, '_public', side_effect=AssertionError('observed response access')):
            generated = PublicSimulator(config, outputs, signer).generate(commands)
        # Expected observations are deliberately accessed only after generation.
        if generated != case['expected_records'] or signer.calls != case['signing_calls']:
            raise AssertionError('archive replay differs: ' + str(identity))
        digest = hashlib.sha256(json.dumps(generated, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if digest != expected_case['trace_sha256']:
            raise AssertionError('trace hash differs from summary: ' + str(identity))
        results.append(dict(identity, trace_sha256=digest, records=len(generated)))
    report = dict(passed=True, cases_count=len(results), cases=results,
                  source_sha256=summary['source_sha256'],
                  replay_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  input_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in (summary_path, archive_path)})
    with args.output.open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print('PASS', len(results), 'archived input sequences regenerated without runtime access')


if __name__ == '__main__':
    main()
