"""Replay one-owner transitions; original process and DB evidence remain separate."""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
from unittest.mock import patch
from unified_lifecycle_simulator import UnifiedLifecycleSimulator
from unified_lifecycle_trace import SCHEDULES, ORDERS
from constructive_trace import FixtureSigningOracle
from observation_events import normalize, caller_view
from state_relation import digest
from wire import decode


def replay(directory):
    report = json.loads((directory/'summary.json').read_text())
    if report.get('passed') is not True or report['profile'] != 'unified-lifecycle-transitions-v1':
        raise ValueError('invalid source report')
    for name, expected in report['source_sha256'].items():
        path = (Path(__file__).parent/name).resolve(); path.relative_to(Path(__file__).parent.resolve())
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected: raise ValueError('source differs: ' + name)
    groups = {}; count = exits = checkpoints = 0
    with lzma.open(directory/'cases.jsonl.xz', 'rt') as stream, patch('sqlite3.connect', side_effect=AssertionError('replay DB access')):
        for line in stream:
            x = json.loads(line); signer = FixtureSigningOracle()
            if type(x['histogram']) is not bool or type(x['mask']) is not int:
                raise AssertionError('typed case identity')
            sim = UnifiedLifecycleSimulator(decode(bytes.fromhex(x['config_cbor_hex'])),
                {k: tuple(v) for k, v in x['approved_outputs'].items()}, signer)
            if len(x['commands']) != len(x['expected_records']) or len(x['checkpoints']) != len(x['commands']) + 1:
                raise AssertionError('event/checkpoint layout')
            canonical = []; business = []; recoveries = []
            for i, (command, expected) in enumerate(zip(x['commands'], x['expected_records']), 1):
                event = sim.emit(command)
                if event != expected: raise AssertionError('observation differs')
                point = x['checkpoints'][i]
                if point['index'] != i or point['kind'] != command['kind'] or point['relation']['unified_obligation'] != digest(sim.obligation):
                    raise AssertionError('typed obligation differs')
                canonical.append(normalize(command, event))
                if command['kind'] == 'RECOVERY_CUT': recoveries.append(command)
                elif command['kind'].endswith('_CUT'): business.append(command)
            if signer.calls != x['signing_calls'] or sim.obligation is not None or sim.needs_recovery is not None:
                raise AssertionError('signer/pending state differs')
            if sim.state.final != x['check']['final'] or sim.state.mechanism_calls != x['check']['mechanism_calls']:
                raise AssertionError('final/accounting differs')
            if [list(t) for t in sim.state.draws] != x['check']['draws']:
                raise AssertionError('mechanism draw sequence differs')
            if digest(canonical) != x['canonical_sha256'] or digest([caller_view(e) for e in canonical]) != x['caller_view_sha256']:
                raise AssertionError('common observation projection differs')
            if len(business) != 7 or len(recoveries) != 14 or len(x['diagnostics']) != 7 or len(x['recovery_diagnostics']) != 14:
                raise AssertionError('fault schedule length')
            for command, diagnostic in zip(business, x['diagnostics']):
                code = 96 if command['kind'] == 'PREPARE_CUT' else 95 if command['kind'] in ('RECEIVE_CUT', 'CONFIRM_CUT') else 97
                if diagnostic['cut'] != command['cut'] or diagnostic['exit_code'] != code:
                    raise AssertionError('business exit binding')
                if diagnostic['witness_advanced'] != (command['cut'] == 'after_witness_accept') or diagnostic['local_committed'] is not False or diagnostic['stale_guard_blocked'] != (command['cut'] == 'after_witness_accept'):
                    raise AssertionError('business authority/local outcome')
            for command, diagnostic in zip(recoveries, x['recovery_diagnostics']):
                if diagnostic['cut'] != command['cut'] or diagnostic['side'] != command['side'] or diagnostic['exit_code'] != 96:
                    raise AssertionError('recovery exit binding')
                if diagnostic['local_commit'] != (command['cut'] == 'after_recovery_commit') or diagnostic['authority_unchanged'] is not True or diagnostic['local_atomicity'] is not True:
                    raise AssertionError('recovery atomicity binding')
            identity = (x['cut'], x['order'], x['histogram']); signature = digest(dict(records=sim.records, checkpoints=x['checkpoints']))
            group = groups.setdefault(identity, {})
            if type(x['mask']) is not int or x['mask'] in group: raise AssertionError('duplicate dataset')
            group[x['mask']] = signature
            row = report['cases'][count]
            if any(row[k] != x[k] for k in ('cut', 'order', 'histogram', 'mask')) or row['correspondence_sha256'] != signature or row['events'] != len(canonical) or row['exits'] != 21 or row['canonical_sha256'] != x['canonical_sha256']:
                raise AssertionError('summary binding')
            count += 1; exits += 21; checkpoints += len(x['checkpoints'])
    if set(groups) != {(s, o, h) for s in SCHEDULES for o in ORDERS for h in (False, True)}:
        raise AssertionError('matrix groups')
    neighbors = 0
    for group in groups.values():
        if set(group) != set(range(8)): raise AssertionError('dataset coverage')
        for mask in range(8):
            for bit in range(3):
                if group[mask] != group[mask ^ (1 << bit)]: raise AssertionError('conditional neighbor differs')
                neighbors += 1
    if report['cases_count'] != count or len(report['cases']) != count or report['actual_exits'] != exits or report['directed_neighbors'] != neighbors:
        raise AssertionError('summary totals')
    return dict(passed=True, cases=count, checkpoints=checkpoints, archived_exits=exits, directed_neighbors=neighbors,
        source_sha256=report['source_sha256'], replay_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        input_sha256={name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in ('summary.json','cases.jsonl.xz')},
        scope=__doc__)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('directory', type=Path); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('choose a new result file')
    result = replay(args.directory)
    with args.output.open('x') as stream: json.dump(result, stream, indent=2); stream.write('\n')
    print('PASS', result['cases'], 'unified lifecycle replays')


if __name__ == '__main__': main()
