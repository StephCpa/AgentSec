"""Real receiver/confirmation process exits with constructed recovery observations.

All receiver contexts are bootstrapped empty in trusted setup. Sender preparation
completes before receiver cuts. Reference SQLite witnesses, no TLS/power-loss or
retirement/recovery-interruption claim. Cut schedule is independent of data.
"""
from copy import deepcopy
import hashlib
import json
import lzma
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tempfile
from unittest.mock import patch
from constructive_trace import RecordingRuntime,FixtureSigningOracle
from delivery_recovery_simulator import DeliveryRecoverySimulator,RECEIVE_CUTS,CONFIRM_CUTS,WITNESS_CUTS,DURABLE_CUTS,LOCAL_CUTS
from delivery_state_relation import assert_delivery_relation
from state_relation import assert_state_relation,digest
from stepwise_trace import ObservedRecords
from public_gateway import PublicGatewayLedger,parse_request
from mixed_delegated_ledger import parse_mixed_action
from public_trace_adapter import PublicTraceAdapter
from retention_recipient import RetentionRecipient
from witnessed_ledger import ReferenceWitness,image_hash
from ledger import Rejected
from test_encrypted_mixed_ledger import vault
from test_retention_recipient import recipient_vault
from test_retention_sender import context
from wire import encode,decode
import retention_wire as rw

EXIT_CODE=95
PLANS=('receive_count','receive_histogram','receive_expire','receive_terminal','receive_existing','receive_cross_route',
       'confirm_count','confirm_histogram','confirm_expired','confirm_withheld_tail','confirm_cross_route','confirm_exact_retry')


def applicable_cuts(plan):
    if plan=='receive_existing':return tuple(c for c in RECEIVE_CUTS if c!='after_v2_recipient_record')
    if plan=='confirm_exact_retry':return WITNESS_CUTS+('response_drop',)
    return RECEIVE_CUTS if plan.startswith('receive_') else CONFIRM_CUTS


def child(path):
    cfg=json.loads(Path(path).read_text())
    def stop(point):
        if point==cfg['cut']:os._exit(EXIT_CODE)
    witness=ReferenceWitness(cfg['witness'])
    if cfg['side']=='receiver':
        ctx=decode(bytes.fromhex(cfg['context']))
        obj=RetentionRecipient(cfg['local'],context=ctx,vault=recipient_vault(),clock=lambda:cfg['at'],witness=witness,witness_fault=stop)
        obj.accept(bytes.fromhex(cfg['request']),ctx['sender_cert'],context()[2],stop)
    else:
        obj=PublicGatewayLedger(cfg['local'],clock=lambda:cfg['at'],vault=vault(),witness=witness,witness_fault=stop)
        obj.confirm('t',cfg['delivery_id'],bytes.fromhex(cfg['request']),bytes.fromhex(cfg['response']),stop)
    if cfg['cut']=='response_drop':os._exit(EXIT_CODE)
    raise RuntimeError('configured cut was not reached')


class DeliveryRecoveryRuntime(RecordingRuntime):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        for root in self.cfg['roots'].values():
            ctx=root['context'];name=ctx['recipient'];w=ReferenceWitness(self.directory/(name+'-w'))
            self.receivers[name]=(RetentionRecipient.create(self.directory/(name+'-db'),context=ctx,vault=recipient_vault(),clock=lambda:self.now,witness=w),w)
        self.signer=FixtureSigningOracle();self.simulator=DeliveryRecoverySimulator(self.cfg,{},self.signer)
        self.checkpoints=[];self.diagnostics=[];self.restores=0;self.receipts={};self.active_cut=None
        self.records=ObservedRecords(self._observe)
        self.checkpoints.append(dict(index=0,kind='INITIAL',relation=self.relation()))

    def relation(self):
        sim=self.simulator
        projection=SimpleNamespace(state=sim.state,records=sim.projected_records)
        return dict(**assert_state_relation(self,sim.state),**assert_delivery_relation(self,projection,initialized_contexts=sim.initialized_contexts))

    def _observe(self,actual):
        command=self.commands[len(self.simulator.records)]
        if command['kind']=='PUBLIC':
            req=parse_request(bytes.fromhex(command['request']))
            if req['method']=='SUBMIT':
                action=parse_mixed_action(req['payload']['action']);width=action['bucket_count'] if action['operation_kind']=='histogram' else 1
                self.simulator.state.oracle.setdefault(action['operation'],(self.target,)+(0,)*(width-1))
        with patch('sqlite3.connect',side_effect=AssertionError('generator DB access')),patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('generator runtime access')),patch.object(RetentionRecipient,'accept',side_effect=AssertionError('generator recipient access')),patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('generator observed response access')):
            generated=self.simulator.emit(command)
        if generated!=actual:raise AssertionError('delivery recovery observation differs at '+str(len(self.records)))
        if command['kind'] in ('RECEIVE_CUT','CONFIRM_CUT'):
            # Inspect the authoritative image via an ephemeral diagnostic replica;
            # no fields, bytes or outcomes are returned to the generator.
            side,oid=self.active_cut
            obj,w,ctx=self.owner(side,oid);head=w.head(obj.namespace,True)
            restored=self.new_replica(side,oid,self.directory/('diagnostic-'+str(len(self.diagnostics))))
            try:
                if restored.state_image()!=head['image'] or restored.audit() or w.head(obj.namespace,True)!=head:raise AssertionError('diagnostic restore changed authority')
                if side=='sender':
                    with patch.object(self,'l',restored):relation=self.relation()
                else:
                    name=ctx['recipient'];old=self.receivers[name];self.receivers[name]=(restored,w)
                    try:relation=self.relation()
                    finally:self.receivers[name]=old
            finally:restored.close()
            relation['R11']=digest(self.diagnostics[-1])
        else:
            relation=self.relation()
            if command['kind']=='DELIVERY_RECOVER':relation['R11']=digest(dict(restored=True,head_unchanged=True,image_equal=True))
        self.checkpoints.append(dict(index=len(self.simulator.records),kind=command['kind'],relation=relation))

    def context_for(self,oid):
        return self.cfg['roots']['root2' if oid=='b' and 'root2' in self.cfg['roots'] else 'root']['context']

    def owner(self,side,oid):
        ctx=self.context_for(oid)
        if side=='sender':return self.l,self.w,ctx
        obj,w=self.receivers[ctx['recipient']];return obj,w,ctx

    def new_replica(self,side,oid,path):
        _,w,ctx=self.owner(side,oid)
        if side=='sender':return PublicGatewayLedger.restore_new(path,clock=lambda:self.now,vault=vault(),witness=w)
        return RetentionRecipient.restore_new(path,context=ctx,clock=lambda:self.now,vault=recipient_vault(),witness=w)

    def process_cut(self,side,oid,cut,request,response=None):
        obj,w,ctx=self.owner(side,oid);before=w.head(obj.namespace);path=obj.path;ns=obj.namespace
        other=self.w.head(self.l.namespace) if side=='receiver' else {n:ww.head(ii.namespace) for n,(ii,ww) in self.receivers.items()}
        did=self.decision(oid)['delivery_id']
        obj.close();cfg=dict(side=side,cut=cut,at=self.now,local=str(path),witness=str(w.path),context=encode(ctx).hex(),request=request.hex())
        if response is not None:cfg.update(response=response.hex(),delivery_id=did)
        config=self.directory/'cut.json';config.write_text(json.dumps(cfg))
        proc=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--child',str(config)],capture_output=True,text=True,timeout=30)
        if side=='sender':self.l=PublicGatewayLedger(path,clock=lambda:self.now,vault=vault(),witness=w);obj=self.l
        else:
            obj=RetentionRecipient(path,context=ctx,clock=lambda:self.now,vault=recipient_vault(),witness=w);self.receivers[ctx['recipient']]=(obj,w)
        if proc.returncode!=EXIT_CODE:raise AssertionError('process cut not reached: '+str(proc.returncode)+' '+proc.stderr[-1600:])
        head=w.head(ns,True);anchor={k:head[k] for k in ('seq','digest')};durable=cut in DURABLE_CUTS;local_commit=cut in LOCAL_CUTS
        if anchor['seq']!=before['seq']+int(durable) or image_hash(head['image'])!=anchor['digest']:raise AssertionError('R11.authority')
        if not durable and anchor!=before:raise AssertionError('R11.precommit_authority')
        local=obj.local_anchor()
        if local!=(anchor if local_commit else before) or image_hash(obj.state_image())!=local['digest']:raise AssertionError('R11.local_atomicity')
        stale=local!=anchor
        try:obj.check_current_state()
        except Rejected as exc:
            if not stale or str(exc)!='WITNESS_RECOVERY_REQUIRED':raise
        else:
            if stale:raise AssertionError('R11.stale_guard')
        after_other=self.w.head(self.l.namespace) if side=='receiver' else {n:ww.head(ii.namespace) for n,(ii,ww) in self.receivers.items()}
        if other!=after_other:raise AssertionError('R11.other_authority_changed')
        self.diagnostics.append(dict(side=side,cut=cut,exit_code=proc.returncode,witness_advanced=durable,local_committed=local_commit,stale_guard_blocked=stale,other_authority_unchanged=True))
        self.active_cut=(side,oid)

    def restore(self,side,oid='a'):
        self.commands.append(dict(kind='DELIVERY_RECOVER',at=self.now,side=side,operation=oid))
        old,w,ctx=self.owner(side,oid);head=w.head(old.namespace,True);self.restores+=1
        restored=self.new_replica(side,oid,self.directory/('restored-'+str(self.restores)))
        if restored.state_image()!=head['image'] or restored.audit() or w.head(old.namespace,True)!=head:restored.close();raise AssertionError('R11.restore')
        old.close()
        if side=='sender':self.l=restored
        else:self.receivers[ctx['recipient']]=(restored,w)
        self.records.append(dict(kind='DELIVERY_RECOVER',at=self.now,side=side,operation=oid));self.active_cut=None

    def send(self,oid='a',terminal=False,cut=None):
        command=dict(kind='RECEIVE_CUT' if cut else 'SEND',at=self.now,operation=oid,delivery_kind='TERMINAL' if terminal else 'DELIVERY',challenge=(len(self.records)+1).to_bytes(32,'big').hex())
        command.update({'cut':cut} if cut else {'loss':'none'});self.commands.append(command)
        request,ctx,decision=self.prepare(oid,terminal)
        if cut:
            self.process_cut('receiver',oid,cut,request)
            self.records.append(dict(kind='DELIVERY_UNAVAILABLE',at=self.now,request=request.hex()))
        else:
            ack=self.receivers[ctx['recipient']][0].accept(request,ctx['sender_cert'],self.k)
            self.receipts[oid]=(request,ack)
            self.records.append(dict(kind='DELIVERY',at=self.now,request=request.hex(),response=ack.hex()))

    def confirm(self,oid='a',cut=None):
        command=dict(kind='CONFIRM_CUT' if cut else 'CONFIRM',at=self.now,operation=oid)
        if cut:command['cut']=cut
        self.commands.append(command);request,ack=self.receipts[oid]
        if cut:self.process_cut('sender',oid,cut,request,ack)
        else:self.l.confirm('t',self.decision(oid)['delivery_id'],request,ack)
        self.records.append(dict(kind='CONFIRM_UNAVAILABLE' if cut else 'CONFIRM',at=self.now,request=request.hex(),response=ack.hex()))

    def checked(self):
        if self.simulator.needs_recovery is not None:raise AssertionError('unfinished restore')
        if self.l.audit() or any(i.audit() for i,_ in self.receivers.values()):raise AssertionError('audit')
        m=self.simulator.state;self.relation()
        if m.draws!=[(o,k) for o,k,_ in self.runtime_draws] or len(m.final)!=len(m.jobs):raise AssertionError('final/draw relation')
        facts={job['id']:rw.parse_fact(m.receiver[(rw.context_hash(job['context']),job['route_seq'])],job['context']) for job in m.jobs if job['publication']=='ADMITTED'}
        facts={oid:dict(outcome=f['outcome'],event_at=f['event_at'],seq=f['seq'],fact_cbor_hex=encode(f).hex()) for oid,f in facts.items()}
        return dict(final=deepcopy(m.final),draws=m.draws,mechanism_calls=m.mechanism_calls,facts=facts)


def run_delivery_recovery(plan,cut,mask=3):
    if plan not in PLANS or cut not in applicable_cuts(plan) or type(mask) is not int or not 0<=mask<8:raise ValueError('outside profile')
    cross=plan.endswith('cross_route')
    with tempfile.TemporaryDirectory() as td:
        r=DeliveryRecoveryRuntime(td,mask,two_routes=cross)
        try:
            r.submit(hist=plan.endswith('histogram'))
            if cross:r.submit('b',root='root2')
            if plan=='confirm_withheld_tail':r.submit('b');r.call('CONTROL',dict(kind='cancel',operation='b'))
            r.finish()
            if plan.startswith('receive_'):
                if plan=='receive_existing':r.send();r.now=130
                if plan=='receive_terminal':r.now=170
                r.send(terminal=r.now>=160,cut=cut)
                if plan in ('receive_expire','receive_existing'):r.now=170
                r.restore('receiver')
                if cross:
                    try:r.prepare('b',terminal=r.now>=160)
                    except Rejected as exc:
                        if str(exc)!='DOMAIN_FINAL_ORDER':raise
                    else:raise AssertionError('unconfirmed receive advanced final prefix')
                r.call('POLL',dict(operation='a'));r.call('FINAL',dict(cursor=0,limit=16))
                r.send(terminal=r.now>=160);r.confirm()
            else:
                r.send()
                if plan=='confirm_expired':r.now=170
                if plan=='confirm_exact_retry':r.confirm()
                r.confirm(cut=cut);r.restore('sender')
                r.call('POLL',dict(operation='a'));r.call('FINAL',dict(cursor=0,limit=16))
                r.confirm()  # Exact request + receipt, including after expiration.
            if cross:r.send('b',terminal=r.now>=160);r.confirm('b')
            r.call('FINAL',dict(cursor=0,limit=16));check=r.checked()
            return dict(plan=plan,cut=cut,mask=mask,config_cbor_hex=encode(r.cfg).hex(),approved_outputs=r.oracle,commands=r.commands,
                expected_records=list(r.records),checkpoints=r.checkpoints,diagnostics=r.diagnostics,signing_calls=r.signer.calls,check=check)
        finally:r.close()


def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--child',type=Path);parser.add_argument('--output',type=Path);args=parser.parse_args()
    if args.child:return child(args.child)
    if args.output is None or args.output.exists():parser.error('choose a new output directory')
    args.output.mkdir(parents=True)
    report=dict(profile='delivery-recovery-correspondence-v1',passed=False,cases=[],source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},
        scope='Explicit dataset-independent receiver/confirmation cuts, actual child exits, local SQLite witnesses. Preparation completes before receiver cuts. Empty receivers initialized in trusted setup. Diagnostic authority projections and fresh operational restore. No preparation/recovery/retirement cuts, TLS, arbitrary concurrency, full observation privacy or power-loss proof.')
    with lzma.open(args.output/'cases.jsonl.xz','wt') as archive:
        for plan in PLANS:
            for cut in applicable_cuts(plan):
                reference=None
                for mask in range(8):
                    case=run_delivery_recovery(plan,cut,mask);signature=digest(dict(records=case['expected_records'],checkpoints=case['checkpoints']))
                    if reference is None:reference=signature
                    if signature!=reference:raise AssertionError('conditioned trace/relation differs')
                    report['cases'].append(dict(plan=plan,cut=cut,mask=mask,correspondence_sha256=signature,trace_sha256=digest(case['expected_records']),checkpoints=len(case['checkpoints']),final=case['check']['final'],diagnostics=case['diagnostics']))
                    archive.write(json.dumps(case,separators=(',',':'))+'\n')
                print('PASS',plan,cut,'8 datasets',flush=True)
    count=len(report['cases']);report.update(passed=True,cases_count=count,process_exits=count,operational_restores=count,diagnostic_restores=count,groups=count//8,directed_neighbor_comparisons=count*3,checkpoints_count=sum(c['checkpoints'] for c in report['cases']))
    (args.output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
