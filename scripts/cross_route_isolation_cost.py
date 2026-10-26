#!/usr/bin/env python3
"""Count successful parent-process CAS payloads around cross-route recovery.

The original child exit is excluded; phase baselines start after that child has
finished. No timing, compression, performance or physical-space claim is made.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
P=ROOT/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
import cross_route_isolation_trace as trace
from witnessed_ledger import ReferenceWitness
from state_relation import digest


class MeteredRuntime(trace.CrossRouteIsolationRuntime):
    def __init__(self,*args,**kwargs):
        self.measure_phase=None;self.measured=[];self.phase_reports={}
        super().__init__(*args,**kwargs)

    def commit_rows(self):
        owners={'sender':(self.l,self.w),**self.receivers}
        return {name:w.db.execute('SELECT count(*) FROM commits WHERE namespace=?',(obj.namespace,)).fetchone()[0]
                for name,(obj,w) in owners.items()}

    def end_phase(self):
        now=self.commit_rows();rows={}
        for owner in now:
            values=[v['bytes'] for v in self.measured if v['phase']==self.measure_phase and v['owner']==owner]
            growth=now[owner]-self.phase_start_rows[owner]
            if growth!=len(values):raise AssertionError('meter/commit row mismatch: '+owner)
            rows[owner]=dict(cas=len(values),image_payload_bytes=sum(values),commit_rows_added=growth)
        self.phase_reports[self.measure_phase]=rows

    def _observe(self,actual):
        super()._observe(actual)
        kind=self.commands[len(self.simulator.records)-1]['kind']
        if kind.endswith('_CUT'):
            self.measure_phase='while_pending';self.phase_start_rows=self.commit_rows()
        elif kind=='RETIRE_RECOVER':
            self.end_phase();self.measure_phase='after_recovery';self.phase_start_rows=self.commit_rows()

    def close(self):
        if self.measure_phase is not None:
            self.end_phase();self.measure_phase=None
        super().close()


def trial(side,workload,admission):
    instances=[];original=ReferenceWitness.compare_and_store
    def create(*args,**kwargs):
        obj=MeteredRuntime(*args,**kwargs);instances.append(obj);return obj
    def measured(w,namespace,expected_seq,expected_digest,image,request_id):
        result=original(w,namespace,expected_seq,expected_digest,image,request_id)
        if instances and instances[0].measure_phase is not None:
            name=Path(w.path).name;owner='sender' if name=='w' else name[:-2] if name.endswith('-w') else None
            if owner not in ('sender','reader','reader2'):raise AssertionError('unknown witness owner')
            obj=instances[0];obj.measured.append(dict(phase=obj.measure_phase,owner=owner,bytes=len(image)))
        return result
    with patch.object(trace,'CrossRouteIsolationRuntime',side_effect=create),patch.object(ReferenceWitness,'compare_and_store',new=measured):
        case=trace.run_cross_route_isolation(side,'after_witness_accept',workload,admission)
    rows=instances[0].phase_reports
    if set(rows)!={'while_pending','after_recovery'}:raise AssertionError('incomplete measurement')
    pending=rows['while_pending']
    if side=='receiver':
        if pending['reader']['cas']!=0 or pending['reader2']['cas']!=1 or pending['sender']['cas']<=0:
            raise AssertionError('healthy-route persistence differs')
    else:
        if pending['sender']['cas']!=0 or pending['reader']['cas']!=1 or pending['reader2']['cas']!=0:
            raise AssertionError('shared-sender persistence differs')
    return dict(side=side,workload=workload,admission=admission,phases=rows,
                trace_sha256=digest(case['expected_records']),final=case['check']['final'],draws=case['check']['draws'])


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('choose a new output file')
    rows=[]
    for side in trace.SIDES:
        for workload in trace.WORKLOADS:
            for admission in trace.ADMISSIONS:
                pair=[]
                for repeat in range(2):
                    row=trial(side,workload,admission);rows.append(dict(row,repeat=repeat));pair.append(row)
                if pair[0]!=pair[1]:raise AssertionError('repeated counts or observations differ')
                print('PASS',side,workload,admission,'two repetitions',flush=True)
    sources=list(P.glob('*.py'))+[Path(__file__).resolve()]
    result=dict(passed=True,trials=rows,trials_count=len(rows),scope=__doc__,
                source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
                measurement='Successful whole-image CAS calls in the parent process, independently checked against witness commit-row growth. Original child commit, setup/bootstrap and pre-fault work are excluded. Fresh recovery writes local state but no authority CAS; local writes and physical files are not counted.')
    args.output.write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
