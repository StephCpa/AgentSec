#!/usr/bin/env python3
"""Stream/regenerate recovery cases from public commands; no runtime DB access."""
import argparse
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
PROTOTYPE=ROOT/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(PROTOTYPE))
from constructive_trace import FixtureSigningOracle
from public_gateway import PublicGatewayLedger
from public_trace_adapter import PublicTraceAdapter
from recovery_simulator import RecoverySimulator
from state_relation import digest
from wire import decode


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('evidence',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    summary_path=args.evidence/'summary.json';archive_path=args.evidence/'cases.jsonl.gz'
    summary=json.loads(summary_path.read_text())
    for name,expected in summary['source_sha256'].items():
        if Path(name).name!=name:raise ValueError('invalid source name')
        if hashlib.sha256((PROTOTYPE/name).read_bytes()).hexdigest()!=expected:raise ValueError('source differs: '+name)
    results=[]
    with gzip.open(archive_path,'rt') as stream:
        for index,line in enumerate(stream):
            case=json.loads(line)
            if index>=len(summary['cases']):raise ValueError('extra case')
            expected=summary['cases'][index];identity={k:case[k] for k in ('plan','cut','mask')}
            if any(expected[k]!=v for k,v in identity.items()):raise ValueError('case order differs')
            config=decode(bytes.fromhex(case['config_cbor_hex']));outputs={k:tuple(v) for k,v in case['approved_outputs'].items()}
            commands=deepcopy(case['commands']);signer=FixtureSigningOracle()
            with patch('sqlite3.connect',side_effect=AssertionError('DB')),patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('runtime')),patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('observed response')):
                simulator=RecoverySimulator(config,outputs,signer);generated=simulator.generate(commands)
            if generated!=case['expected_records'] or signer.calls!=case['signing_calls']:raise AssertionError('regeneration differs')
            if digest(generated)!=expected['trace_sha256']:raise AssertionError('trace hash differs')
            if digest(dict(records=generated,checkpoints=case['checkpoints']))!=expected['correspondence_sha256']:raise AssertionError('archived checkpoint hash differs')
            results.append(dict(identity,records=len(generated),trace_sha256=digest(generated)))
    if len(results)!=summary['cases_count'] or len(results)!=len(summary['cases']):raise ValueError('case count differs')
    report=dict(passed=True,cases_count=len(results),cases=results,source_sha256=summary['source_sha256'],
        scope='Regenerates public observations. Checks archived checkpoint hashes only; does not re-execute actual process cuts or SQL relation checks.',
        replay_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        input_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (summary_path,archive_path)})
    with args.output.open('x') as f:f.write(json.dumps(report,indent=2)+'\n')
    print('PASS',len(results),'recovery traces regenerated without runtime access')

if __name__=='__main__':main()
