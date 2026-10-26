#!/usr/bin/env python3
"""Reconstruct source-bound cross-route observations without real DB access.

Checkpoint hashes bind the archived runtime evidence; replay does not execute
the original exits or independently verify the original database projections.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import sys
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
P=ROOT/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from cross_route_isolation_simulator import CrossRouteIsolationSimulator, SIDES, CUTS
from cross_route_isolation_trace import WORKLOADS, ADMISSIONS
from constructive_trace import FixtureSigningOracle
from state_relation import digest
from wire import decode, encode
from retirement_recovery_simulator import DURABLE_CUTS, LOCAL_CUTS
import retention_wire as r


def replay(evidence):
    summary=evidence/'summary.json';archive=evidence/'cases.jsonl.xz'
    report=json.loads(summary.read_text())
    if not report['passed'] or report['profile']!='cross-route-retention-isolation-v1':raise ValueError('failed/unsupported evidence')
    for name,expected in report['source_sha256'].items():
        source=(P/name).resolve();source.relative_to(P.resolve())
        if hashlib.sha256(source.read_bytes()).hexdigest()!=expected:raise ValueError('source differs: '+name)
    count=0;checkpoints=0;signings=0;groups={}
    with lzma.open(archive,'rt') as f, patch('sqlite3.connect',side_effect=AssertionError('replay DB access')):
        for line in f:
            x=json.loads(line);signer=FixtureSigningOracle()
            sim=CrossRouteIsolationSimulator(decode(bytes.fromhex(x['config_cbor_hex'])),{k:tuple(v) for k,v in x['approved_outputs'].items()},signer)
            restore_count=0
            if len(x['checkpoints'])!=len(x['commands'])+1 or x['checkpoints'][0]['kind']!='INITIAL':
                raise AssertionError('checkpoint layout differs')
            for index,command in enumerate(x['commands'],1):
                if command['kind']=='RETIRE_RECOVER':
                    restore_count+=1
                    draws=[[v['operation'],sim.state.by_id[v['operation']]['action']['operation_kind'],v['l1_tick']] for v in sim.state.mechanism_calls]
                    if sim.state.final!=x['before_restore']['final'] or draws!=x['before_restore']['draws']:
                        raise AssertionError('before-recovery availability/accounting differs')
                sim.emit(command)
                point=x['checkpoints'][index]
                relation=digest(dict(pending=sim.fault,authority_projection=True,opaque_preservation=True))
                if point['index']!=index or point['kind']!=command['kind'] or point['relation']['R16']!=relation:
                    raise AssertionError('component-scoped relation differs')
            if restore_count!=1 or sim.records!=x['expected_records'] or signer.calls!=x['signing_calls'] or sim.fault is not None or sim.needs_recovery is not None:
                raise AssertionError('public observations/signing/recovery differ')
            if sim.state.final!=x['check']['final'] or [list(v) for v in sim.state.draws]!=x['check']['draws'] or sim.state.mechanism_calls!=x['check']['mechanism_calls']:
                raise AssertionError('final/mechanism accounting differs')
            facts={}
            for job in sim.state.jobs:
                if job['publication']=='ADMITTED':
                    fact=sim.state.receiver[r.context_hash(job['context']),job['route_seq']]
                    parsed=r.parse_fact(fact,job['context'])
                    facts[job['id']]=dict(outcome=parsed['outcome'],event_at=parsed['event_at'],seq=parsed['seq'],fact_cbor_hex=encode(parsed).hex())
            if facts!=x['check']['facts']:raise AssertionError('first facts differ')
            for route in sim.state.cfg['roots']:
                h,_=sim.context(route);high,confirmed=sim.frontiers(h)
                front=dict(high=high,confirmed=confirmed,sender_floor=sim.retirement['sender'][h]['floor'],receiver_floor=sim.retirement['receiver'][h]['floor'])
                if front!=x['check']['frontiers'][route]:raise AssertionError('retention frontier differs')
            expected=dict(stage='RETIRE_SEND' if x['side']=='receiver' else 'RETIRE_PREPARE',cut=x['cut'],exit_code=97,
                          witness_advanced=x['cut'] in DURABLE_CUTS,local_committed=x['cut'] in LOCAL_CUTS,
                          stale_guard_blocked=x['cut'] in DURABLE_CUTS and x['cut'] not in LOCAL_CUTS,
                          other_authorities_unchanged=True,protected_archive=True)
            if x['diagnostics']!=[expected] or not x['commands'][x['fault_index']-1]['kind'].endswith('_CUT'):
                raise AssertionError('exit evidence differs')
            row=report['cases'][count];identity=('side','cut','workload','admission','mask')
            if any(row[k]!=x[k] for k in identity) or row['trace_sha256']!=digest(sim.records):raise AssertionError('identity/trace differs')
            signature=digest(dict(records=sim.records,checkpoints=x['checkpoints']))
            if row['correspondence_sha256']!=signature or row['checkpoints']!=len(x['checkpoints']) or row['process_exits']!=1:
                raise AssertionError('checkpoint/exit binding differs')
            group=groups.setdefault(tuple(x[k] for k in identity[:-1]),{})
            if type(x['mask']) is not int or x['mask'] in group:raise AssertionError('duplicate/noninteger mask')
            group[x['mask']]=signature
            count+=1;checkpoints+=len(x['checkpoints']);signings+=len(signer.calls)
    if set(groups)!={(s,c,w,a) for s in SIDES for c in CUTS[s] for w in WORKLOADS for a in ADMISSIONS}:raise AssertionError('missing matrix group')
    neighbors=0
    for group in groups.values():
        if set(group)!=set(range(8)):raise AssertionError('missing dataset')
        for mask in range(8):
            for bit in range(3):
                if group[mask]!=group[mask^(1<<bit)]:raise AssertionError('conditional neighbor differs')
                neighbors+=1
    totals=dict(cases_count=count,groups_count=len(groups),process_exits=count,operational_restores=count,
                checkpoints_count=checkpoints,directed_neighbor_comparisons=neighbors)
    if count!=len(report['cases']) or any(report[k]!=v for k,v in totals.items()):raise AssertionError('summary counts differ')
    return dict(passed=True,**totals,signing_calls=signings,source_sha256=report['source_sha256'],
                input_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (summary,archive)},
                replay_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),scope=__doc__)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('evidence',type=Path);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('choose a new output file')
    result=replay(args.evidence);args.output.write_text(json.dumps(result,indent=2)+'\n')
    print('PASS',result['cases_count'],'cross-route isolation replays')


if __name__=='__main__':main()
