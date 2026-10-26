"""Paired canonical-image codec cost and actual loopback mTLS snapshot RPCs.

The whole query's CAS image stream is encoded locally for byte/CPU accounting;
only the final snapshot is sent through both network modes. No claim about full
query network throughput, TLS record bytes, disk savings or general refinement.
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
import zlib
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519

from constructive_trace import RecordingRuntime,FixtureSigningOracle
from public_simulator import PublicSimulator
from public_trace_adapter import PublicTraceAdapter
from public_gateway import PublicGatewayLedger
from state_relation import assert_state_relation,digest
from delivery_state_relation import assert_delivery_relation
from test_encrypted_mixed_ledger import vault
from test_witness_transport import certificates,public
from witnessed_ledger import ReferenceWitness,image_hash
from witness_transport import WitnessTLSService,TLSWitnessClient,trusted_register_peer,certificate_fingerprint
from witness_compression import compress_body,decompress_body,LEVEL
import witness_transport
import witness_compression


def distribution(values):
    ordered=sorted(values)
    return dict(samples=len(values),values_ms=values,
                p50_ms=ordered[math.ceil(len(values)*.5)-1],p95_ms=ordered[math.ceil(len(values)*.95)-1])


class CodecMeter:
    """Keep counters, not a quadratic list of full state images."""
    def __init__(self,runtime):
        self.rows=[];self.phase='registration';original=runtime.w.compare_and_store
        def cas(namespace,seq,old_digest,image,request_id):
            start=time.process_time_ns();encoded=compress_body(image);encode_ns=time.process_time_ns()-start
            start=time.process_time_ns();recovered=decompress_body(encoded,len(image));decode_ns=time.process_time_ns()-start
            if recovered!=image:raise AssertionError('codec changed canonical image')
            result=original(namespace,seq,old_digest,image,request_id)
            self.rows.append(dict(phase=self.phase,raw_bytes=len(image),encoded_bytes=len(encoded),
                                  encode_cpu_ns=encode_ns,decode_cpu_ns=decode_ns))
            return result
        self.patch=patch.object(runtime.w,'compare_and_store',side_effect=cas);self.patch.start()

    def close(self):self.patch.stop()

    def summary(self,phase):
        rows=[row for row in self.rows if row['phase']==phase]
        raw=sum(r['raw_bytes'] for r in rows);encoded=sum(r['encoded_bytes'] for r in rows)
        return dict(commits=len(rows),raw_body_bytes=raw,encoded_body_bytes=encoded,
                    byte_reduction_fraction=1-encoded/raw,
                    encode_cpu_ms=sum(r['encode_cpu_ns'] for r in rows)/1e6,
                    decode_cpu_ms=sum(r['decode_cpu_ns'] for r in rows)/1e6)


class FrameMeter:
    """Count actual application frame sendall bytes, before TLS record wrapping."""
    def __init__(self,mode):
        self.rows=[]
        module=witness_transport if mode=='raw' else witness_compression
        name='send_frame' if mode=='raw' else 'send_compressed_frame'
        original=getattr(module,name);rows=self.rows
        class CountSocket:
            def __init__(self,sock):self.sock=sock
            def __getattr__(self,name):return getattr(self.sock,name)
            def sendall(self,data):
                # Register before send: the peer can finish its RPC as soon as
                # it receives the bytes. Failed RPCs abort this experiment and
                # never produce a report containing partial-send counts.
                rows.append(dict(direction='response' if self.sock.server_side else 'request',bytes=len(data)))
                self.sock.sendall(data)
        self.patch=patch.object(module,name,side_effect=lambda sock,*args:original(CountSocket(sock),*args))
        self.patch.start()

    def close(self):self.patch.stop()

    def totals(self,start):
        rows=self.rows[start:]
        return dict(frames=len(rows),request_bytes=sum(r['bytes'] for r in rows if r['direction']=='request'),
                    response_bytes=sum(r['bytes'] for r in rows if r['direction']=='response'))


def relation(runtime,sim):
    return dict(**assert_state_relation(runtime,sim.state),**assert_delivery_relation(runtime,sim))


def snapshot_trial(directory,certs,signer,mode,image,runtime,sim,expected_relation,samples):
    directory=Path(directory);directory.mkdir();wp=directory/'witness'
    ns=runtime.l.namespace;cert,key=certs['admin']
    trusted_register_peer(wp,ns,certificate_fingerprint(cert),'admin')
    scert,skey=certs['server']
    with WitnessTLSService(wp,cafile=certs['ca'],certfile=scert,keyfile=skey,signing_key=signer,frame_mode=mode) as server:
        client=TLSWitnessClient(port=server.port,cafile=certs['ca'],certfile=cert,keyfile=key,
                                witness_public_key=public(signer),frame_mode=mode)
        meter=FrameMeter(mode)
        try:
            start=len(meter.rows);head=client.bootstrap(ns,image);bootstrap_frames=meter.totals(start)
            cas_times=[];get_times=[];cas_frames=[];get_frames=[]
            for i in range(samples):
                start=len(meter.rows);t=time.perf_counter_ns()
                head=client.compare_and_store(ns,head['seq'],head['digest'],image,(i+1).to_bytes(16,'big').hex())
                cas_times.append((time.perf_counter_ns()-t)/1e6);cas_frames.append(meter.totals(start))
                start=len(meter.rows);t=time.perf_counter_ns();observed=client.head(ns,True)
                get_times.append((time.perf_counter_ns()-t)/1e6);get_frames.append(meter.totals(start))
                if observed!=dict(head,image=image):raise AssertionError('snapshot RPC mismatch')
            start=len(meter.rows);t=time.perf_counter_ns()
            restored=PublicGatewayLedger.restore_new(directory/'restored',clock=lambda:runtime.now,vault=vault(),witness=client)
            restore_ms=(time.perf_counter_ns()-t)/1e6;restore_frames=meter.totals(start)
            try:
                if restored.state_image()!=image or restored.audit():raise AssertionError('restore changed canonical state')
                with patch.object(runtime,'l',restored):recovered_relation=relation(runtime,sim)
                if recovered_relation!=expected_relation:raise AssertionError('restored state relation mismatch')
            finally:restored.close()
            storage=ReferenceWitness(wp)
            try:
                stored=storage.head(ns,True)
                commits=storage.db.execute('SELECT count(*) FROM commits WHERE namespace=?',(ns,)).fetchone()[0]
                if stored!=dict(head,image=image) or commits!=samples:raise AssertionError('witness storage mismatch')
            finally:storage.close()
            return dict(mode=mode,tls_version=client.last_tls_version,bootstrap_frames=bootstrap_frames,
                cas=distribution(cas_times),get_image=distribution(get_times),cas_frames=cas_frames,get_image_frames=get_frames,
                restore_ms=restore_ms,restore_frames=restore_frames,restored_image_hash=image_hash(image),
                restored_relation=recovered_relation,witness_raw_image_bytes=len(stored['image']),witness_commit_rows=commits)
        finally:meter.close()


def query_trial(hist=False,poll_every=0,samples=8,mode_order=('raw','deflate-v1')):
    if type(samples) is not int or samples<1:raise ValueError('positive sample count required')
    if tuple(sorted(mode_order))!=('deflate-v1','raw'):raise ValueError('both modes required exactly once')
    with tempfile.TemporaryDirectory() as td:
        directory=Path(td);r=RecordingRuntime(td)
        try:
            meter=CodecMeter(r)
            try:
                r.submit(hist=hist);meter.phase='execution';r.finish(poll_every=poll_every)
                meter.phase='delivery';r.deliver()
            finally:meter.close()
            slots=1+(4 if hist else 1)*(3+81);polls=slots//poll_every if poll_every else 0
            if r.steps!=slots or meter.summary('execution')['commits']!=slots+polls:
                raise AssertionError('logical/CAS schedule changed')
            r.checked()
            with patch('sqlite3.connect',side_effect=AssertionError('simulator DB access')),patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('real handler used as simulator')),patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('observed response used to generate')):
                sim=PublicSimulator(r.cfg,r.oracle,FixtureSigningOracle());generated=sim.generate(r.commands)
            if generated!=r.records:raise AssertionError('public transcript changed')
            expected=relation(r,sim);image=r.l.state_image()
            certdir=directory/'certificates';certdir.mkdir();certs=certificates(certdir);signer=ed25519.Ed25519PrivateKey.generate()
            modes=[snapshot_trial(directory/mode,certs,signer,mode,image,r,sim,expected,samples) for mode in mode_order]
            return dict(kind='histogram' if hist else 'count',poll_every=poll_every,logical_slots=slots,polls=polls,
                stream={phase:meter.summary(phase) for phase in ('registration','execution','delivery')},
                final_image_bytes=len(image),final_image_hash=image_hash(image),public_records=len(r.records),
                transcript_hash=digest(generated),source_relation=expected,network_mode_order=list(mode_order),snapshot_trials=modes)
        finally:r.close()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    report=dict(profile='witness-deflate-cost-v1',passed=False,python=sys.version,platform=platform.platform(),
        cryptography=cryptography.__version__,openssl=ssl.OPENSSL_VERSION,sqlite=sqlite3.sqlite_version,
        zlib_compile=zlib.ZLIB_VERSION,zlib_runtime=zlib.ZLIB_RUNTIME_VERSION,compression_level=LEVEL,
        measurement='Sequential local CAS stream codec CPU (process_time_ns); final identical snapshot RPC RTT (perf_counter_ns), fresh mTLS connection per call. 8 samples; nearest-rank p95 is maximum. Frame bytes exclude TLS/TCP/IP/handshake and physical disk traffic.',
        scope='Six synthetic count/histogram schedules. Final state only: generated public records and R1-R8 restored projections. Full query is not executed over mTLS; snapshot authorities are fresh isolated test fixtures. No deployment migration, arbitrary crashes, retirement or general privacy proof.',
        source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},cases=[])
    for hist in (False,True):
        for cadence in (0,1,8):
            index=len(report['cases']);order=('raw','deflate-v1') if index%2==0 else ('deflate-v1','raw')
            report['cases'].append(query_trial(hist,cadence,mode_order=order))
            print('PASS',hist,cadence,flush=True)
    report['passed']=True
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
