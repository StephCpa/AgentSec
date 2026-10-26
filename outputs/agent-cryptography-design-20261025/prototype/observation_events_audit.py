"""Audit archived command/observation pairs under one lossless event vocabulary.

Does not replay state transitions, authenticate wire bytes, or rerun failures.
The hashes bind historical inputs; they do not upgrade their original claims.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import lzma
from pathlib import Path

from observation_events import EventStream, to_legacy, caller_view, COMMANDS, ALLOWED

SOURCES = (
    ('constructive', 'constructive-restricted-public-v1', 'inputs-and-expected.json.gz'),
    ('public-recovery', 'public-request-recovery-v1', 'cases.jsonl.gz'),
    ('private-work-recovery', 'private-work-recovery-v1', 'cases.jsonl.xz'),
    ('delivery-recovery', 'delivery-recovery-correspondence-v1', 'cases.jsonl.xz'),
    ('repeated-recovery', 'repeated-recovery-interruption-v1', 'cases.jsonl.xz'),
    ('preparation-recovery', 'preparation-recovery-correspondence-v1', 'cases.jsonl.xz'),
    ('retirement-recovery', 'retirement-recovery-correspondence-v1', 'cases.jsonl.xz'),
    ('window-lifecycle', 'window-lifecycle-correspondence-v1', 'cases.jsonl.xz'),
    ('cross-route-isolation', 'cross-route-retention-isolation-v1', 'cases.jsonl.xz'),
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def rows(path):
    opener = lzma.open if path.suffix == '.xz' else gzip.open
    with opener(path, 'rt') as stream:
        if '.jsonl.' in path.name:
            for line in stream:
                yield json.loads(line)
        else:
            yield from json.load(stream)


def extract_fixtures(research_root):
    """Select first examples of forms/methods/statuses; no signature claim."""
    from public_gateway import parse_request, RESPONSE_TYPE
    from wire import decode, inspect_sign1
    from ledger import Rejected
    fixtures = {}; sources = {}
    for name, profile, filename in SOURCES:
        directory = research_root/(name + '-evidence-20261026'); archive = directory/filename
        sources[name] = dict(profile=profile, archive='docs/research/' + directory.name + '/' + filename,
                             sha256=file_hash(archive))
        for case_index, case in enumerate(rows(archive)):
            for event_index, (command, event) in enumerate(zip(case['commands'], case['expected_records'])):
                method = status = None
                if command['kind'] in ('PUBLIC', 'PUBLIC_CUT'):
                    try:
                        method = parse_request(bytes.fromhex(command['request']))['method']
                    except Rejected:
                        method = 'unparseable'
                    if event['kind'] == 'PUBLIC':
                        status = decode(inspect_sign1(bytes.fromhex(event['response']), RESPONSE_TYPE)[1])['status']
                shape = (command['kind'], event['kind'], tuple(sorted(event)), command.get('loss'),
                         event.get('reason'), event.get('error'), method, status)
                if shape not in fixtures:
                    fixtures[shape] = dict(source=name, case_index=case_index, event_index=event_index,
                        public_method=method, public_status=status, command=command, event=event)
    return dict(sources=sources, cases=list(fixtures.values()))


def audit_case(case):
    commands = case['commands']; events = case['expected_records']
    if len(commands) != len(events) or not commands:
        raise ValueError('empty/mismatched command/event stream')
    stream = EventStream(); counts = Counter(); commands_seen = Counter(); pair_counts = Counter()
    canonical_hash = hashlib.sha256(); caller_hash = hashlib.sha256()
    for i, (command, event) in enumerate(zip(commands, events)):
        try:
            value = stream.append(command, event)
            if to_legacy(value) != (command, event):
                raise ValueError('lossy round trip')
            counts[value['outcome']['kind']] += 1; commands_seen[command['kind']] += 1
            pair_counts[command['kind'] + '/' + event['kind']] += 1
            canonical_hash.update((digest(value) + '\n').encode())
            caller_hash.update((digest(caller_view(value)) + '\n').encode())
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError('event {}: {}'.format(i, exc)) from exc
    return dict(events=stream.count, outcomes=dict(counts), commands=dict(commands_seen), pairs=dict(pair_counts),
                canonical_sha256=canonical_hash.hexdigest(), caller_view_sha256=caller_hash.hexdigest())


def audit(research_root, fixtures_path=None):
    fixtures = None
    if fixtures_path is not None:
        fixtures = json.loads(fixtures_path.read_text())
        if fixtures != extract_fixtures(research_root):
            raise ValueError('test fixtures differ from source archives')
    all_commands = Counter(); all_pairs = Counter(); all_outcomes = Counter(); sources = []
    for name, profile, filename in SOURCES:
        directory = research_root/(name + '-evidence-20261026')
        summary_path = directory/'summary.json'; archive = directory/filename
        summary = json.loads(summary_path.read_text())
        if summary.get('passed') is not True or summary.get('profile') != profile:
            raise ValueError('failed/unsupported source: ' + name)
        count = 0; events = 0; case_bindings = []
        for index, case in enumerate(rows(archive)):
            try:
                result = audit_case(case)
            except ValueError as exc:
                raise ValueError('{} case {}: {}'.format(name, index, exc)) from exc
            count += 1; events += result['events']
            all_commands.update(result['commands']); all_pairs.update(result['pairs']); all_outcomes.update(result['outcomes'])
            # Bind the entire original case, including evidence not projected into
            # a caller view. We make no additional semantic claim about it.
            case_bindings.append(dict(index=index, input_sha256=digest(case), **result))
        if summary.get('cases_count') != count:
            raise ValueError('source case count mismatch: ' + name)
        sources.append(dict(name=name, profile=profile, cases=count, events=events,
            input_sha256={p.name: file_hash(p) for p in (summary_path, archive)}, case_bindings=case_bindings))
    if set(all_commands) != set(COMMANDS):
        raise ValueError('command vocabulary not covered')
    permitted_pairs = {c + '/' + e for c, events in ALLOWED.items() for e in events}
    if set(all_pairs) != permitted_pairs:
        raise ValueError('command/event vocabulary not covered')
    return dict(passed=True, scope=__doc__, sources=sources, cases=sum(s['cases'] for s in sources),
        events=sum(s['events'] for s in sources), commands=dict(all_commands), pairs=dict(all_pairs), outcomes=dict(all_outcomes),
        fixtures=None if fixtures is None else dict(sha256=file_hash(fixtures_path), count=len(fixtures['cases']),
            exact_archive_extraction=True),
        source_sha256={p.name: file_hash(p) for p in (Path(__file__), Path(__file__).with_name('observation_events.py'))},
        limitations=['Historical inputs only; new runtime cases are a separate test gate.',
                     'Caller views are local role observations; no arbitrary-adversary or timing model.',
                     'Unknown legacy failure results remain unknown; no invented exception or durability.',
                     'No state-machine composition, wire authentication or DP proof is established.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--research-root', type=Path, default=Path(__file__).resolve().parents[3]/'docs/research')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--extract-fixtures', action='store_true', help='Write deterministic source-bound test inputs instead of an audit.')
    parser.add_argument('--fixtures', type=Path, help='Also verify test inputs against their exact archive positions.')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('choose a new output file; preserve prior evidence')
    if args.extract_fixtures and args.fixtures:
        parser.error('choose fixture extraction or verification')
    result = extract_fixtures(args.research_root) if args.extract_fixtures else audit(args.research_root, args.fixtures)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    if args.extract_fixtures:
        print('EXTRACTED {} fixtures'.format(len(result['cases'])))
    else:
        print('PASS {} cases, {} events, {} command/event pairs'.format(result['cases'], result['events'], len(result['pairs'])))


if __name__ == '__main__':
    main()
