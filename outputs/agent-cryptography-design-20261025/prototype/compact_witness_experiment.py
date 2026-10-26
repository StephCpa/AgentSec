"""Paired cached public POLL calls with full vs compact same-image witness CAS.

Real loopback mTLS witness RPCs; public gateway invoked in-process. Same frozen
ledger image within each workload, alternating modes; metadata commits and two
full local image builds remain. No general query-throughput or disk-write claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import ssl
import sys
import tempfile
import time
from unittest.mock import patch
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519
from constructive_trace import RecordingRuntime
from image_serialization_experiment import public_check,check_relation
from compression_experiment import FrameMeter,distribution
from public_gateway import PublicGatewayLedger
from test_encrypted_mixed_ledger import vault
from test_witness_transport import certificates,public
from witness_transport import WitnessTLSService,TLSWitnessClient,trusted_register_peer,certificate_fingerprint
from wire import decode
from state_relation import digest
from witnessed_ledger import image_hash


def measured_cached_polls(hist,history,certs,signer,samples=24):
    with tempfile.TemporaryDirectory() as td:
        r=RecordingRuntime(td)
        try:
            r.submit(hist=hist);r.finish();r.deliver()
            for _ in range(history):r.call('POLL',dict(operation='a'))
            expected_reply=r.call('POLL',dict(operation='a'));raw=bytes.fromhex(r.commands[-1]['request'])
            frozen=r.l.state_image();ns=r.l.namespace
            cert,key=certs['writer'];trusted_register_peer(r.w.path,ns,certificate_fingerprint(cert),'writer')
            scert,skey=certs['server']
            with WitnessTLSService(r.w.path,cafile=certs['ca'],certfile=scert,keyfile=skey,signing_key=signer,allow_reassert=True) as server:
                client=TLSWitnessClient(port=server.port,cafile=certs['ca'],certfile=cert,keyfile=key,witness_public_key=public(signer))
                r.l.witness=client;meter=FrameMeter('raw');exchanges=[];exchange=client.exchange
                def observed(raw,body):
                    exchanges.append(dict(method=decode(raw)['method'],body_bytes=len(body)))
                    return exchange(raw,body)
                client.exchange=observed
                measurements=[];order=[];initial=r.w.head(ns);initial_commits=r.w.db.execute('SELECT count(*) FROM commits WHERE namespace=?',(ns,)).fetchone()[0]
                try:
                    for i in range(samples):
                        modes=('full','compact') if i%2==0 else ('compact','full');order.append(modes)
                        for mode in modes:
                            client.compact_reassert=mode=='compact';head=r.w.head(ns);calls=[];image=r.l.state_image
                            def counted_image():
                                value=image();calls.append(len(value));return value
                            start_frames=len(meter.rows);start_rpc=len(exchanges)
                            with patch.object(r.l,'state_image',side_effect=counted_image):
                                start=time.perf_counter_ns();reply=r.exchange(raw);elapsed=(time.perf_counter_ns()-start)/1e6
                            frame=meter.totals(start_frames);rpc=exchanges[start_rpc:];after=r.w.head(ns,True)
                            if reply!=expected_reply:raise AssertionError('cached public reply changed')
                            if calls!=[len(frozen)]*2:raise AssertionError('full local image checks changed')
                            if after!=dict(seq=head['seq']+1,digest=image_hash(frozen),image=frozen):raise AssertionError('witness image/version changed')
                            method='reassert' if mode=='compact' else 'cas'
                            if rpc!=[dict(method='head',body_bytes=0),dict(method=method,body_bytes=0 if mode=='compact' else len(frozen))]:raise AssertionError('RPC shape differs')
                            if frame['frames']!=4:raise AssertionError('RPC frame count changed')
                            measurements.append(dict(mode=mode,latency_ms=elapsed,frames=frame,rpc=rpc,image_builds=len(calls)))
                    final=r.w.head(ns);commits=r.w.db.execute('SELECT count(*) FROM commits WHERE namespace=?',(ns,)).fetchone()[0]
                    if final['seq']-initial['seq']!=2*samples or commits-initial_commits!=2*samples:raise AssertionError('distinct attempts were collapsed')
                    # A new POLL journals a new request, so opt-in must still use full CAS.
                    client.compact_reassert=True;start_rpc=len(exchanges)
                    r.call('POLL',dict(operation='a'));fallback=exchanges[start_rpc:]
                    if [x['method'] for x in fallback]!=['head','cas'] or not fallback[-1]['body_bytes']:raise AssertionError('changed state took reassert')
                    r.checked();sim=public_check(r);expected_relation=check_relation(r,sim)
                    before=r.w.head(ns,True)
                    restored=PublicGatewayLedger.restore_new(Path(td)/'restored',clock=lambda:r.now,vault=vault(),witness=client)
                    try:
                        if restored.audit() or restored.state_image()!=before['image'] or r.w.head(ns,True)!=before:raise AssertionError('restore differs')
                        with patch.object(r,'l',restored):
                            if check_relation(r,sim)!=expected_relation:raise AssertionError('restored relation differs')
                    finally:restored.close()
                finally:meter.close()
            modes={}
            for mode in ('full','compact'):
                rows=[x for x in measurements if x['mode']==mode]
                modes[mode]=dict(latency=distribution([x['latency_ms'] for x in rows]),
                    request_frame_bytes=sum(x['frames']['request_bytes'] for x in rows),response_frame_bytes=sum(x['frames']['response_bytes'] for x in rows),
                    cas_body_bytes=sum(x['rpc'][1]['body_bytes'] for x in rows),cas_commits=len(rows),image_builds=sum(x['image_builds'] for x in rows))
            return dict(kind='histogram' if hist else 'count',history_polls=history,samples_per_mode=samples,image_bytes=len(frozen),order=order,
                measurements=measurements,modes=modes,new_poll_fallback=fallback,transcript_sha256=digest(r.records),relation=expected_relation,
                restored=True,request_frame_reduction=1-modes['compact']['request_frame_bytes']/modes['full']['request_frame_bytes'],
                p50_latency_change=modes['compact']['latency']['p50_ms']/modes['full']['latency']['p50_ms']-1)
        finally:r.close()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    report=dict(profile='compact-witness-reassert-cost-v1',passed=False,python=sys.version,platform=platform.platform(),
        cryptography=cryptography.__version__,sqlite=sqlite3.sqlite_version,openssl=ssl.OPENSSL_VERSION,
        scope='Cached signed public POLL replay via in-process gateway with real loopback mTLS witness RPCs. Same ledger snapshot within each workload, 24 alternating pairs. Counts application frames before TLS wrapping, not TLS records/physical disk writes. Two full image builds and one metadata commit per attempt remain. New POLLs still use full CAS. No end-to-end query-throughput or general privacy claim.',
        source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},cases=[])
    with tempfile.TemporaryDirectory() as td:
        certs=certificates(td);signer=ed25519.Ed25519PrivateKey.generate()
        for hist in (False,True):
            for history in (0,16,64):
                result=measured_cached_polls(hist,history,certs,signer);report['cases'].append(result)
                print('PASS',hist,history,'image',result['image_bytes'],'request reduction',result['request_frame_reduction'],'p50 change',result['p50_latency_change'],flush=True)
    report['passed']=True;args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
