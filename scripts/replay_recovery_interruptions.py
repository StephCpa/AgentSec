#!/usr/bin/env python3
"""Rebuild composed public observations; does not rerun process/DB experiments."""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import sys
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT/'outputs/agent-cryptography-design-20261025'
sys.path.insert(0,str(SOURCE/'prototype'))
from recovery_interruption_simulator import RecoveryInterruptionSimulator
from recovery_simulator import RecoverySimulator
from kernel_recovery_simulator import KernelRecoverySimulator
from delivery_recovery_simulator import DeliveryRecoverySimulator
from constructive_trace import FixtureSigningOracle
from state_relation import digest
from wire import decode


def main():
    parser=argparse.ArgumentParser();parser.add_argument('evidence',type=Path);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    summary=args.evidence/'summary.json';archive=args.evidence/'cases.jsonl.xz';report=json.loads(summary.read_text())
    if not report['passed']:raise ValueError('input run failed')
    for name,h in report['source_sha256'].items():
        p=(SOURCE/name).resolve();p.relative_to(SOURCE.resolve())
        if hashlib.sha256(p.read_bytes()).hexdigest()!=h:raise ValueError('source differs: '+name)
    groups={};modes={};count=0;events=0
    with lzma.open(archive,'rt') as f,patch('sqlite3.connect',side_effect=AssertionError('replay DB access')):
        for line in f:
            c=json.loads(line);signer=FixtureSigningOracle();cls={'public':RecoverySimulator,'kernel':KernelRecoverySimulator,'delivery':DeliveryRecoverySimulator}[c['family']]
            sim=RecoveryInterruptionSimulator(cls(decode(bytes.fromhex(c['config_cbor_hex'])),{k:tuple(v) for k,v in c['approved_outputs'].items()},signer))
            generated=sim.generate(c['commands']);fingerprint=digest(dict(records=generated,checkpoints=c['checkpoints']));row=report['cases'][count]
            if generated!=c['expected_records'] or signer.calls!=c['signing_calls'] or sim.state.final!=c['check']['final'] or sim.needs_recovery:raise AssertionError('replay differs')
            if (row['scenario'],row['replica_mode'],row['mask'])!=(c['scenario'],c['replica_mode'],c['mask']) or row['trace_sha256']!=digest(generated) or row['correspondence_sha256']!=fingerprint or row['checkpoints']!=len(c['checkpoints']):raise AssertionError('case/diagnostic binding differs')
            key=(c['scenario'],c['replica_mode']);group=groups.setdefault(key,{})
            if c['mask'] in group:raise AssertionError('duplicate case')
            group[c['mask']]=fingerprint;modes.setdefault((c['scenario'],c['mask']),{})[c['replica_mode']]=digest(generated)
            count+=1;events+=sum(x['kind']=='RECOVERY_UNAVAILABLE' for x in generated)
    if count!=report['cases_count']:raise AssertionError('case count differs')
    neighbors=0
    for group in groups.values():
        if set(group)!=set(range(8)):raise AssertionError('missing dataset')
        for mask in range(8):
            for bit in range(3):
                if group[mask]!=group[mask^(1<<bit)]:raise AssertionError('neighbor mismatch')
                neighbors+=1
    for modes_pair in modes.values():
        if set(modes_pair)!={'existing','fresh'} or modes_pair['existing']!=modes_pair['fresh']:raise AssertionError('replica-mode public view differs')
    result=dict(passed=True,cases=count,recovery_unavailable_events=events,directed_neighbor_comparisons=neighbors,replica_mode_public_comparisons=len(modes),source_sha256=report['source_sha256'],input_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (summary,archive)},replay_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),scope='Re-executes generator/signing transcript and final state checks, verifies archived checkpoint binding and compares dataset neighbors and replica-mode public views. Does not rerun actual process exits or independently reconstruct DB projections.')
    args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS',count,'composed recovery transcript replays;',neighbors,'neighbor pairs;',len(modes),'replica-mode comparisons')

if __name__=='__main__':main()
