#!/usr/bin/env python3
"""Source-bound replay of generated preparation failure/recovery observations.

Reconstructs transcripts, signing calls and final model state. Does not rerun
child processes or independently reconstruct the archived runtime DB projections.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import sys
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];P=ROOT/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from preparation_recovery_simulator import PreparationRecoverySimulator, preparation_cuts
from preparation_recovery_trace import PLANS, plan_kind
from constructive_trace import FixtureSigningOracle
from state_relation import digest
from wire import decode


def main():
    parser=argparse.ArgumentParser();parser.add_argument('evidence',type=Path);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    summary=args.evidence/'summary.json';archive=args.evidence/'cases.jsonl.xz';report=json.loads(summary.read_text())
    if not report['passed']:raise ValueError('input run failed')
    for name,expected in report['source_sha256'].items():
        source=(P/name).resolve();source.relative_to(P.resolve())
        if hashlib.sha256(source.read_bytes()).hexdigest()!=expected:raise ValueError('source differs: '+name)
    count=0;signings=0;groups={}
    with lzma.open(archive,'rt') as f,patch('sqlite3.connect',side_effect=AssertionError('replay DB access')):
        for line in f:
            case=json.loads(line);signer=FixtureSigningOracle();sim=PreparationRecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),{k:tuple(v) for k,v in case['approved_outputs'].items()},signer)
            generated=sim.generate(case['commands'])
            if generated!=case['expected_records'] or signer.calls!=case['signing_calls'] or sim.state.final!=case['check']['final'] or sim.needs_recovery is not None:raise AssertionError('replay differs')
            row=report['cases'][count]
            if (row['plan'],row['cut'],row['mask'])!=(case['plan'],case['cut'],case['mask']) or row['trace_sha256']!=digest(generated):raise AssertionError('case identity/digest differs')
            signature=digest(dict(records=generated,checkpoints=case['checkpoints']))
            if signature!=row['correspondence_sha256'] or len(case['checkpoints'])!=row['checkpoints']:raise AssertionError('archived checkpoint binding differs')
            key=(case['plan'],case['cut']);group=groups.setdefault(key,{})
            if case['mask'] in group:raise AssertionError('duplicate dataset mask')
            group[case['mask']]=signature
            count+=1;signings+=len(signer.calls)
    if count!=report['cases_count'] or count!=len(report['cases']):raise AssertionError('case count differs')
    expected_groups={(p,c) for p in PLANS for c in preparation_cuts(plan_kind(p))}
    if set(groups)!=expected_groups:raise AssertionError('incomplete declared plan/cut matrix')
    neighbor_pairs=0
    for group in groups.values():
        if set(group)!=set(range(8)):raise AssertionError('incomplete roster group')
        for mask in range(8):
            for bit in range(3):
                if group[mask]!=group[mask^(1<<bit)]:raise AssertionError('neighbor correspondence differs')
                neighbor_pairs+=1
    args.output.write_text(json.dumps(dict(passed=True,cases=count,signing_calls=signings,directed_neighbor_comparisons=neighbor_pairs,source_sha256=report['source_sha256'],input_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (summary,archive)},replay_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),scope=__doc__),indent=2)+'\n')
    print('PASS',count,'preparation failure/recovery transcript replays')

if __name__=='__main__':main()
