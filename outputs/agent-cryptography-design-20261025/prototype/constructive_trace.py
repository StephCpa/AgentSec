"""Compare constructed signed observations to actual restricted runtime.

Inputs are recorded before the corresponding runtime call; no output stripping
or response-derived challenge extraction is used. All keys/data are synthetic.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
from unittest.mock import patch
from wire import encode,sign1
from public_gateway import parse_request,PublicGatewayLedger
from public_trace_adapter import PublicTraceAdapter
from public_simulator import PublicSimulator
from restricted_trace import Runtime,run_plan,PLANS
from public_observation import seed_for_output_one
from test_public_gateway import SERVER_KEY,SERVER_KID,PEER
from test_retention_sender import context
import retention_wire as retention


class RecordingRuntime(Runtime):
    def __init__(self,*args,target=1,**kwargs):
        self.commands=[];self.target=target
        super().__init__(*args,**kwargs)

    def exchange(self,raw,peer=PEER):
        obj=parse_request(raw)
        coin=hashlib.sha256(('public-challenge:'+str(int.from_bytes(obj['request_id'],'big'))).encode()).hexdigest() if obj['method']=='CHALLENGE' else ''
        self.commands.append(dict(kind='PUBLIC',at=self.now,request=raw.hex(),peer=peer.hex(),challenge_coin=coin))
        return super().exchange(raw,peer)

    def submit(self,oid='a',hist=False,root='root'):
        out=super().submit(oid,hist,root)
        self.oracle[oid]=(self.target,0,0,0) if hist else (self.target,)
        return out

    def _randomness(self,op):
        self.runtime_draws.append((op['id'],'histogram' if self.kinds[op['id']] else 'count',self.steps+1))
        seed=seed_for_output_one(sum(self.slots)+1-self.target)
        return seed[:10]+bytes(30) if self.kinds[op['id']] else seed

    def advance(self):
        self.commands.append(dict(kind='TICK',at=self.now,tick=self.steps+1))
        return super().advance()

    def deliver(self,oid='a',terminal=False,loss=None):
        self.commands.append(dict(kind='SEND',at=self.now,operation=oid,delivery_kind='TERMINAL' if terminal else 'DELIVERY',
                                 challenge=(len(self.records)+1).to_bytes(32,'big').hex(),loss=loss or 'none'))
        confirm=self.l.confirm
        def observed_confirm(*args,**kwargs):
            self.commands.append(dict(kind='CONFIRM',at=self.now,operation=oid))
            return confirm(*args,**kwargs)
        with patch.object(self.l,'confirm',side_effect=observed_confirm):return super().deliver(oid,terminal,loss)


class FixtureSigningOracle:
    def __init__(self):self.calls=[];self.sender=context()[1];self.receiver=context()[2]
    def __call__(self,role,object_type,payload,ctx):
        self.calls.append(dict(role=role,object_type=object_type,payload_sha256=hashlib.sha256(encode(payload)).hexdigest()))
        if role=='gateway':return sign1(encode(payload),SERVER_KID,SERVER_KEY,object_type)
        if role not in ('sender','receiver'):raise ValueError('unknown signing role')
        return retention.signed(payload,ctx,self.sender if role=='sender' else self.receiver,role,object_type)


def run_constructed(plan,mask=3,target=1):
    if type(target) is not int or not 0<=target<=3:raise ValueError('output outside public capacity')
    instances=[]
    def create(*args,**kwargs):
        r=RecordingRuntime(*args,target=target,**kwargs);instances.append(r);return r
    with patch('restricted_trace.Runtime',side_effect=create):run=run_plan(plan,mask)
    commands=deepcopy(instances[0].commands);signer=FixtureSigningOracle()
    # The runtime is already closed. Disallow opening a DB, calling the real
    # gateway or using the checker's observed-response entry point to generate.
    with patch('sqlite3.connect',side_effect=AssertionError('simulator DB access')),patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('runtime used as simulator')),patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('observed response used to generate')):
        sim=PublicSimulator(run['config'],run['approved_outputs'],signer)
        generated=sim.generate(commands)
    if generated!=run['records']:
        first=next((i for i,(a,b) in enumerate(zip(generated,run['records'])) if a!=b),min(len(generated),len(run['records'])))
        raise AssertionError('constructed transcript differs at record '+str(first))
    run.update(commands=commands,generated=generated,signing_calls=signer.calls,target=target)
    return run


def main():
    import argparse
    import gzip
    import json
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    args.output.mkdir(parents=True)
    report=dict(profile='constructive-restricted-public-v1',scope='Explicit signing resources and independent public coins; finite conditional correspondence, not a general proof.',
        source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},cases=[],conditioned_groups=[])
    traces=[]
    groups=[(plan,1) for plan in PLANS]+[(plan,target) for target in (0,2,3) for plan in ('normal','adaptive')]
    for plan,target in groups:
        reference=None
        for mask in range(8):
            run=run_constructed(plan,mask,target)
            wire=json.dumps(run['generated'],sort_keys=True,separators=(',',':')).encode()
            if reference is None:reference=wire
            if wire!=reference:raise AssertionError('conditional constructed bytes differ')
            report['cases'].append(dict(plan=plan,target=target,mask=mask,records=len(run['records']),commands=len(run['commands']),
                trace_sha256=hashlib.sha256(wire).hexdigest(),signing_calls=len(run['signing_calls']),
                draws=run['check']['draws'],calls=run['check']['mechanism_calls'],final=run['check']['final'],pending=run['check']['pending']))
            traces.append(dict(plan=plan,target=target,mask=mask,config_cbor_hex=encode(run['config']).hex(),approved_outputs=run['approved_outputs'],
                commands=run['commands'],expected_records=run['records'],signing_calls=run['signing_calls']))
        report['conditioned_groups'].append(dict(plan=plan,target=target));print('PASS',plan,'target',target,'8 inputs',flush=True)
    report.update(passed=True,cases_count=len(traces),directed_neighbor_comparisons=24*len(groups))
    (args.output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    with (args.output/'inputs-and-expected.json.gz').open('wb') as f:
        with gzip.GzipFile(fileobj=f,mode='wb',mtime=0) as gz:gz.write(json.dumps(traces,separators=(',',':')).encode())

if __name__=='__main__':main()
