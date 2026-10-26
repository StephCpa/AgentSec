"""Reference byte equality and paired cost of canonical row-byte reuse.

The frozen reference below is the pre-optimization state_image implementation
from commit 06005e36cec9040fb35eaa9d03858c75ac0be0e7. It is a test/measurement
oracle, never selected by the production path. Full image checks and CAS remain.
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

from witnessed_ledger import WitnessedLedger,canonical,pack_cell,quote_identifier,image_hash
from constructive_trace import RecordingRuntime,FixtureSigningOracle
from public_simulator import PublicSimulator
from public_trace_adapter import PublicTraceAdapter
from public_gateway import PublicGatewayLedger
from state_relation import assert_state_relation,digest
from delivery_state_relation import assert_delivery_relation
from test_encrypted_mixed_ledger import vault

REFERENCE_COMMIT='06005e36cec9040fb35eaa9d03858c75ac0be0e7'
OPTIMIZED_IMAGE=WitnessedLedger.state_image


def reference_state_image(self):
    # Frozen original; retain its materialize/sort/re-encode structure.
    objects,tables=self.schema();rows={}
    for name,columns in tables.items():
        values=[[pack_cell(v) for v in row] for row in self.db.execute('SELECT * FROM '+quote_identifier(name))]
        rows[name]=sorted(values,key=canonical)
    image=canonical({'format':'agent-ledger-image-v1','schema':objects,'columns':tables,'rows':rows})
    image_hash(image)
    return image


def stats(values):
    ordered=sorted(values)
    return dict(samples=len(values),values_ms=values,p50_ms=ordered[math.ceil(.5*len(values))-1],
                p95_ms=ordered[math.ceil(.95*len(values))-1])


def check_relation(runtime,sim):
    return dict(**assert_state_relation(runtime,sim.state),**assert_delivery_relation(runtime,sim))


class ImageEquivalence:
    """Compare both encoders on every image request, including fault/recovery."""
    def __init__(self):
        self.calls=0;self.bytes=0
        def checked(ledger):
            actual=OPTIMIZED_IMAGE(ledger);expected=reference_state_image(ledger)
            if actual!=expected:raise AssertionError('canonical image changed')
            self.calls+=1;self.bytes+=len(actual)
            return actual
        self.patch=patch.object(WitnessedLedger,'state_image',new=checked)
    def __enter__(self):self.patch.start();return self
    def __exit__(self,*args):self.patch.stop()


def paired_image_trial(ledger,samples=16):
    if type(samples) is not int or samples<1:raise ValueError('positive samples required')
    expected=reference_state_image(ledger)
    timings={name:[] for name in ('reference','row_reuse')};order=[]
    methods={'reference':reference_state_image,'row_reuse':OPTIMIZED_IMAGE}
    for i in range(samples):
        names=('reference','row_reuse') if i%2==0 else ('row_reuse','reference');order.append(names)
        for name in names:
            start=time.process_time_ns();result=methods[name](ledger);elapsed=time.process_time_ns()-start
            if result!=expected:raise AssertionError('paired image encoding differs')
            timings[name].append(elapsed/1e6)
    return dict(image_bytes=len(expected),image_hash=image_hash(expected),order=order,
                cpu={name:stats(values) for name,values in timings.items()})


def public_check(runtime):
    with patch('sqlite3.connect',side_effect=AssertionError('simulator DB access')),patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('runtime as simulator')),patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('observed response as generator')):
        sim=PublicSimulator(runtime.cfg,runtime.oracle,FixtureSigningOracle());generated=sim.generate(runtime.commands)
    if generated!=runtime.records:raise AssertionError('public transcript changed')
    return sim


def measured_query(hist=False,poll_every=0,encoder='row_reuse',diagnostic=False):
    method={'reference':reference_state_image,'row_reuse':OPTIMIZED_IMAGE}[encoder]
    with tempfile.TemporaryDirectory() as td,patch.object(WitnessedLedger,'state_image',new=method):
        runtime=RecordingRuntime(td)
        try:
            runtime.submit(hist=hist);calls=[];cas=[]
            original=runtime.l.state_image;store=runtime.w.compare_and_store
            def image():
                start=time.process_time_ns();raw=original();calls.append((time.process_time_ns()-start,len(raw)));return raw
            def commit(namespace,seq,old_digest,raw,token):
                result=store(namespace,seq,old_digest,raw,token);cas.append(len(raw));return result
            with patch.object(runtime.l,'state_image',side_effect=image),patch.object(runtime.w,'compare_and_store',side_effect=commit):
                start=time.perf_counter_ns();runtime.finish(poll_every=poll_every);elapsed=time.perf_counter_ns()-start
            slots=1+(4 if hist else 1)*84;polls=slots//poll_every if poll_every else 0
            if runtime.steps!=slots or len(cas)!=slots+polls or len(calls)!=2*len(cas):raise AssertionError('persistence schedule changed')
            runtime.deliver();runtime.checked();sim=public_check(runtime)
            expected_relation=check_relation(runtime,sim)
            # Cost excludes setup, delivery, model generation and audits.
            result=dict(kind='histogram' if hist else 'count',poll_every=poll_every,encoder=encoder,
                logical_slots=slots,polls=polls,execution_ms=elapsed/1e6,image_builds=len(calls),
                image_build_cpu_ms=sum(x[0] for x in calls)/1e6,image_build_bytes=sum(x[1] for x in calls),
                cas_commits=len(cas),cas_body_bytes=sum(cas),transcript_hash=digest(runtime.records),relation=expected_relation)
            if diagnostic:
                with ImageEquivalence() as equivalent:
                    restored=PublicGatewayLedger.restore_new(Path(td)/'restored',clock=lambda:runtime.now,vault=vault(),witness=runtime.w)
                    try:
                        if restored.state_image()!=runtime.l.state_image() or restored.audit():raise AssertionError('restored image differs')
                        with patch.object(runtime,'l',restored):observed=check_relation(runtime,sim)
                        if observed!=expected_relation:raise AssertionError('restored relation differs')
                    finally:restored.close()
                result['restored_image_checks']=equivalent.calls
                result['paired_snapshot']=paired_image_trial(runtime.l)
            return result
        finally:runtime.close()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    report=dict(profile='canonical-row-reuse-cost-v1',passed=False,reference_commit=REFERENCE_COMMIT,
        python=sys.version,platform=platform.platform(),cryptography=cryptography.__version__,sqlite=sqlite3.sqlite_version,openssl=ssl.OPENSSL_VERSION,
        timer='Image build uses process_time_ns; execution uses perf_counter_ns. Sequential local ReferenceWitness, no TLS. 3 alternating query pairs per workload, nearest-rank median; 16 alternating same-snapshot CPU pairs on the final optimized run.',
        scope='Reference algorithm preserved in experiment only. Query pairs use same public schedule/data/approved output with fresh encrypted state; sizes, CAS count, generated public transcript and R1-R8 final relation must agree. Same-snapshot serializer comparison requires exact bytes.',
        source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},cases=[])
    for hist in (False,True):
        for cadence in (0,1,8):
            runs=[]
            for repeat in range(3):
                order=('reference','row_reuse') if repeat%2==0 else ('row_reuse','reference')
                pair=[measured_query(hist,cadence,mode,diagnostic=repeat==2 and mode=='row_reuse') for mode in order]
                left,right=pair
                for key in ('logical_slots','polls','image_builds','image_build_bytes','cas_commits','cas_body_bytes','transcript_hash','relation'):
                    if left[key]!=right[key]:raise AssertionError('query comparison mismatch: '+key)
                runs.append(dict(repetition=repeat,order=list(order),measurements=pair))
                print('PASS',hist,cadence,repeat,flush=True)
            report['cases'].append(dict(kind='histogram' if hist else 'count',poll_every=cadence,runs=runs))
    report['passed']=True
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
