"""Measured local persistence costs for the frozen synthetic gateway profile.

Reports actual CAS payload bytes and state-image work, not estimated TLS traffic.
Never changes ledger transaction granularity or correctness/timeout policies.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import platform
import sqlite3
import ssl
import sys
import tempfile
import time
from unittest.mock import patch
import cryptography
from restricted_trace import Runtime
from public_gateway import PublicGatewayLedger
from test_encrypted_mixed_ledger import vault
from ledger import Rejected


class Meter:
    def __init__(self,runtime):
        self.r=runtime;self.cas=[];self.images=[];self.latencies=[]
        self.cas_fn=runtime.w.compare_and_store;self.image_fn=runtime.l.state_image
        def cas(namespace,seq,digest,image,request_id):
            start=time.perf_counter_ns()
            result=self.cas_fn(namespace,seq,digest,image,request_id)
            self.cas.append(dict(bytes=len(image),ns=time.perf_counter_ns()-start));return result
        def image():
            start=time.perf_counter_ns();raw=self.image_fn()
            self.images.append(dict(bytes=len(raw),ns=time.perf_counter_ns()-start));return raw
        self.patches=[patch.object(runtime.w,'compare_and_store',side_effect=cas),patch.object(runtime.l,'state_image',side_effect=image)]
        for p in self.patches:p.start()
    def close(self):
        for p in reversed(self.patches):p.stop()
    def measure(self,fn):
        start=time.perf_counter_ns();result=fn();self.latencies.append(time.perf_counter_ns()-start);return result
    def summary(self):
        ms=sorted(x/1e6 for x in self.latencies);n=len(ms)
        return dict(samples=n,latency_ms=dict(p50=ms[max(0,math.ceil(n*.5)-1)] if n else None,p95=ms[max(0,math.ceil(n*.95)-1)] if n else None),
            operations_per_second=n/(sum(self.latencies)/1e9) if sum(self.latencies) else None,
            elapsed_operation_ms=sum(self.latencies)/1e6,cas_commits=len(self.cas),cas_image_bytes=sum(x['bytes'] for x in self.cas),
            state_image_builds=len(self.images),state_image_encoded_bytes=sum(x['bytes'] for x in self.images),
            state_image_build_ms=sum(x['ns'] for x in self.images)/1e6,cas_ms=sum(x['ns'] for x in self.cas),
            cas_payload_bytes=[x['bytes'] for x in self.cas],latencies_ms=[x/1e6 for x in self.latencies])


def timed(r,fn,repetitions=1):
    meter=Meter(r)
    try:
        for _ in range(repetitions):meter.measure(fn)
        return meter.summary()
    finally:meter.close()


def state_summary(r):
    return dict(image_bytes=len(r.l.state_image()),gateway_requests=r.l.db.execute('SELECT count(*) FROM gw_requests').fetchone()[0],
        witness_commit_rows=r.w.db.execute('SELECT count(*) FROM commits').fetchone()[0],
        db_file_bytes=Path(r.l.path).stat().st_size,witness_file_bytes=Path(r.w.path).stat().st_size)


def poll_trial(q,mode='new',samples=8):
    with tempfile.TemporaryDirectory() as td:
        r=Runtime(td)
        try:
            r.submit();r.call('POLL',dict(operation='a'));raw=bytes.fromhex(r.records[-1]['request'])
            start=state_summary(r)
            growth=timed(r,lambda:r.call('POLL',dict(operation='a')),q)
            before=state_summary(r)
            fn=(lambda:r.exchange(raw)) if mode=='retry' else (lambda:r.call('POLL',dict(operation=[]))) if mode=='denial' else (lambda:r.call('POLL',dict(operation='a')))
            measurements=timed(r,fn,samples);after=state_summary(r)
            recover=[]
            for i in range(3):
                t=time.perf_counter_ns()
                restored=PublicGatewayLedger.restore_new(Path(td)/('replica-'+str(i)),clock=lambda:100,vault=vault(),witness=r.w)
                recover.append((time.perf_counter_ns()-t)/1e6)
                if restored.audit():raise AssertionError('recovery audit')
                restored.close()
            if r.l.audit():raise AssertionError('ledger audit')
            return dict(history_polls=q,mode=mode,start=start,growth=growth,before=before,measurements=measurements,after=after,recovery_ms=recover)
        finally:r.close()


def query_trial(hist=False,poll_every=0):
    with tempfile.TemporaryDirectory() as td:
        r=Runtime(td)
        try:
            registration=timed(r,lambda:r.submit(hist=hist))
            meter=Meter(r)
            try:
                while r.l.db.execute('SELECT 1 FROM jobs WHERE publication IS NULL').fetchone():
                    meter.measure(r.advance)
                    if poll_every and r.steps%poll_every==0:meter.measure(lambda:r.call('POLL',dict(operation='a')))
                execution=meter.summary()
            finally:meter.close()
            slots=1+(4 if hist else 1)*(3+81)
            expected_polls=slots//poll_every if poll_every else 0
            if r.steps!=slots or execution['cas_commits']!=slots+expected_polls:raise AssertionError('persistence accounting mismatch')
            before=state_summary(r);delivery_cost=timed(r,r.deliver)
            if r.l.audit():raise AssertionError('ledger audit')
            return dict(kind='histogram' if hist else 'count',N=3,B=4 if hist else 1,logical_slots=slots,poll_every=poll_every,
                polls=expected_polls,registration=registration,execution=execution,delivery=delivery_cost,state_before_delivery=before,
                completed=True)
        finally:r.close()


def head_of_line_trial(delay=70):
    with tempfile.TemporaryDirectory() as td:
        r=Runtime(td,two_routes=True)
        try:
            r.submit(hist=True);r.submit('b',root='root2');r.finish()
            r.deliver(loss='ack')
            start=state_summary(r);blocked=[]
            for at in (100,130,100+delay):
                r.now=at
                try:r.prepare('b',terminal=at>=160)
                except Rejected as exc:blocked.append(dict(at=at,error=str(exc)))
                else:raise AssertionError('head-of-line bypass')
            r.deliver(terminal=r.now>=160);r.deliver('b',terminal=r.now>=160)
            result=r.checked()
            return dict(public_delay=delay,blocked=blocked,before=start,after=state_summary(r),final=result['final'],
                        qualification='Logical public-clock experiment; not a wall-clock outage benchmark.')
        finally:r.close()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    report=dict(profile='local-persistence-v1',python=sys.version,cryptography=cryptography.__version__,openssl=ssl.OPENSSL_VERSION,
        sqlite=sqlite3.sqlite_version,platform=platform.platform(),transport='in-process ReferenceWitness; no TLS bandwidth measurement',
        timer='perf_counter_ns; nearest-rank p50/p95; sequential calls; no concurrency',source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},
        poll_trials=[],query_trials=[],head_of_line=None)
    for q in (0,16,64,128):
        for mode in ('new','retry','denial'):
            report['poll_trials'].append(poll_trial(q,mode));print('poll',q,mode,flush=True)
    for hist in (False,True):
        for cadence in (0,1,8):
            report['query_trials'].append(query_trial(hist,cadence));print('query',hist,cadence,flush=True)
    report['head_of_line']=head_of_line_trial()
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
