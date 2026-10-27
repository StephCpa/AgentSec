"""Check the shared model against mask=3 representatives of seven old profiles.

This replays archived public commands, not real processes. Window-full and
component-local availability profiles are explicitly outside this comparison.
"""
import argparse
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
from observation_events_audit import SOURCES, rows, file_hash
from unified_lifecycle_simulator import UnifiedLifecycleSimulator
from constructive_trace import FixtureSigningOracle
from wire import decode
from state_relation import digest


def replay(research):
    result = dict(passed=False, scope=__doc__, cases=0, events=0, sources=[])
    for name, profile, filename in SOURCES[:7]:
        directory = research/(name + '-evidence-20261026'); archive = directory/filename
        summary = json.loads((directory/'summary.json').read_text())
        if summary.get('passed') is not True or summary['profile'] != profile: raise ValueError('source profile')
        selected = []
        with patch('sqlite3.connect', side_effect=AssertionError('shared model opened DB')):
            for index, case in enumerate(rows(archive)):
                if type(case['mask']) is not int: raise ValueError('dataset type')
                if case['mask'] != 3: continue
                signer = FixtureSigningOracle()
                sim = UnifiedLifecycleSimulator(decode(bytes.fromhex(case['config_cbor_hex'])),
                    {k: tuple(v) for k, v in case['approved_outputs'].items()}, signer)
                for i, (command, expected) in enumerate(zip(case['commands'], case['expected_records'])):
                    if sim.emit(command) != expected: raise AssertionError('{} case {} event {}'.format(name, index, i))
                if len(case['commands']) != len(case['expected_records']) or signer.calls != case['signing_calls']:
                    raise AssertionError('shape/signing differs')
                if sim.obligation is not None or sim.pending_tick is not None: raise AssertionError('unresolved obligation')
                selected.append(dict(index=index, commands=len(case['commands']), input_sha256=digest(case),
                    trace_sha256=digest(sim.records), final_sha256=digest(sim.state.final), mechanism_calls=sim.state.mechanism_calls))
                result['events'] += len(case['commands'])
        if not selected: raise AssertionError('empty profile selection')
        result['sources'].append(dict(name=name, profile=profile, cases=len(selected),
            archive_sha256=file_hash(archive), summary_sha256=file_hash(directory/'summary.json'), selected=selected))
        result['cases'] += len(selected)
        print('PASS', name, len(selected), flush=True)
    result.update(passed=True, source_sha256={p.name: file_hash(p) for p in Path(__file__).parent.glob('*.py')})
    return result


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('choose a new output file')
    result = replay(Path(__file__).resolve().parents[3]/'docs/research')
    with args.output.open('x') as stream: json.dump(result, stream, indent=2); stream.write('\n')


if __name__ == '__main__': main()
