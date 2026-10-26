#!/usr/bin/env python3
"""Replay the source-bound one-slot lifecycle archive without database access.

Reconstruct signed observations and final model state; bind archived checkpoint
digests. This replay does not rerun process exits or inspect original databases.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import sys
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
P = ROOT / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from window_lifecycle_simulator import WindowLifecycleSimulator
from window_lifecycle_trace import PLANS, CUTS, MODES
from recovery_interruption_simulator import RecoveryInterruptionSimulator, REPEATED_CUTS
from constructive_trace import FixtureSigningOracle
from state_relation import digest
from wire import decode


def replay(evidence):
    summary = evidence / 'summary.json'; archive = evidence / 'cases.jsonl.xz'
    report = json.loads(summary.read_text())
    if not report['passed'] or report['profile'] != 'window-lifecycle-correspondence-v1': raise ValueError('unsupported or failed input')
    for name, expected in report['source_sha256'].items():
        source = (P / name).resolve(); source.relative_to(P.resolve())
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected: raise ValueError('source differs: ' + name)
    groups = {}; signings = 0; count = 0; original_exits = 0; recovery_exits = 0; checkpoints = 0
    with lzma.open(archive, 'rt') as f, patch('sqlite3.connect', side_effect=AssertionError('replay DB access')):
        for line in f:
            x = json.loads(line); signer = FixtureSigningOracle()
            sim = RecoveryInterruptionSimulator(WindowLifecycleSimulator(decode(bytes.fromhex(x['config_cbor_hex'])),
                {k: tuple(v) for k, v in x['approved_outputs'].items()}, signer))
            generated = sim.generate(x['commands'])
            if generated != x['expected_records'] or signer.calls != x['signing_calls'] or sim.state.final != x['check']['final'] or sim.needs_recovery is not None:
                raise AssertionError('observation/signing/final replay differs')
            if [list(v) for v in sim.state.draws] != x['check']['draws'] or sim.state.mechanism_calls != x['check']['mechanism_calls']:
                raise AssertionError('mechanism accounting differs')
            h, _ = sim.context('root'); floor = sim.retirement['receiver'][h]['floor']
            live = sorted(seq for hh, seq in sim.state.receiver if hh == h and seq > floor)
            if (sim.retirement['sender'][h]['floor'], floor, live) != (x['check']['sender_floor'], x['check']['receiver_floor'], x['check']['receiver_live']):
                raise AssertionError('window/frontier replay differs')
            if len(x['diagnostics']) != 1 or x['diagnostics'][0]['exit_code'] != 97: raise AssertionError('original exit evidence missing')
            if [a['cut'] for a in x['recovery_diagnostics']] != list(REPEATED_CUTS) or any(a['exit_code'] != 96 for a in x['recovery_diagnostics']):
                raise AssertionError('repeated recovery evidence missing')
            row = report['cases'][count]; identity = ('plan', 'cut', 'replica_mode', 'mask')
            if any(row[k] != x[k] for k in identity) or row['trace_sha256'] != digest(generated): raise AssertionError('case identity/digest differs')
            signature = digest(dict(records=generated, checkpoints=x['checkpoints']))
            if signature != row['correspondence_sha256'] or len(x['checkpoints']) != row['checkpoints']: raise AssertionError('checkpoint binding differs')
            group = groups.setdefault(tuple(x[k] for k in identity[:-1]), {})
            if type(x['mask']) is not int or x['mask'] in group: raise AssertionError('duplicate/noninteger mask')
            group[x['mask']] = signature
            count += 1; signings += len(signer.calls); original_exits += len(x['diagnostics'])
            recovery_exits += len(x['recovery_diagnostics']); checkpoints += len(x['checkpoints'])
    if set(groups) != {(p, c, m) for p in PLANS for c in CUTS for m in MODES}: raise AssertionError('missing plan/cut/mode')
    neighbors = 0
    for group in groups.values():
        if set(group) != set(range(8)): raise AssertionError('missing dataset mask')
        for mask in range(8):
            for bit in range(3):
                if group[mask] != group[mask ^ (1 << bit)]: raise AssertionError('neighbor correspondence differs')
                neighbors += 1
    totals = dict(cases_count=count, groups=len(groups), process_exits=original_exits, recovery_exits=recovery_exits,
                  operational_restores=count, checkpoints_count=checkpoints, directed_neighbor_comparisons=neighbors)
    if any(report[k] != value for k, value in totals.items()) or count != len(report['cases']): raise AssertionError('summary totals differ')
    return dict(passed=True, **totals, signing_calls=signings, source_sha256=report['source_sha256'],
                input_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (summary, archive)},
                replay_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), scope=__doc__)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('evidence', type=Path); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('output exists')
    result = replay(args.evidence); args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('PASS', result['cases_count'], 'window lifecycle transcript replays')


if __name__ == '__main__': main()
