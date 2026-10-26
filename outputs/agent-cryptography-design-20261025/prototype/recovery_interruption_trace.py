"""Compose real recovery exits with public, private-slot and delivery failures.

Existing and fresh empty replicas are each interrupted at all three recovery
hooks, twice in succession, followed by an ordinary fresh operational restore.
No production methods or persistence policies are changed.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch
from public_recovery_trace import RecoveryRuntime,run_recovery
from private_recovery_trace import KernelRuntime,run_kernel
from delivery_recovery_trace import DeliveryRecoveryRuntime,run_delivery_recovery
from recovery_interruption_simulator import RecoveryInterruptionSimulator,RECOVERY_CUTS,REPEATED_CUTS
from public_gateway import PublicGatewayLedger
from retention_recipient import RetentionRecipient
from public_trace_adapter import PublicTraceAdapter
from state_relation import digest
from test_encrypted_mixed_ledger import vault
from test_retention_recipient import recipient_vault
from witnessed_ledger import ReferenceWitness,Rejected
from wire import encode,decode

EXIT_CODE=96
SCENARIOS={
 'public_submit_pre':('public',('submit','before_witness_accept')),
 'public_submit_post':('public',('submit','after_witness_accept')),
 'count_l1_pre':('kernel',(False,'l1','after_sampling')),
 'histogram_l1_post':('kernel',(True,'l1','after_witness_accept')),
 'count_final_pre':('kernel',(False,'final','before_witness_accept')),
 'histogram_final_post':('kernel',(True,'final','after_witness_accept')),
 'receive_expire_pre':('delivery',('receive_expire','before_witness_accept')),
 'receive_expire_post':('delivery',('receive_expire','after_witness_accept')),
 'confirm_withheld_pre':('delivery',('confirm_withheld_tail','before_final_event_write')),
 'confirm_cross_post':('delivery',('confirm_cross_route','after_witness_accept')),
}


def child(path):
    cfg=json.loads(Path(path).read_text());w=ReferenceWitness(cfg['witness'])
    def stop(point):
        if point==cfg['cut']:os._exit(EXIT_CODE)
    if cfg['side']=='sender':obj=PublicGatewayLedger(cfg['local'],clock=lambda:cfg['at'],vault=vault(),witness=w)
    else:obj=RetentionRecipient(cfg['local'],context=decode(bytes.fromhex(cfg['context'])),clock=lambda:cfg['at'],vault=recipient_vault(),witness=w)
    with ExitStack() as stack:
        # Recovery may audit/decrypt state. It must not dispatch business work,
        # sample, prepare transport, confirm facts or create an authority commit.
        for name in ('operation_randomness','advance_private_step','advance','handle_public','publish','admit_v2','confirm','prepare_envelope','prepare_terminal','accept'):
            if hasattr(obj,name):stack.enter_context(patch.object(obj,name,side_effect=AssertionError('business invoked during recovery: '+name)))
        for name in ('bootstrap','compare_and_store','reassert'):
            if hasattr(w,name):stack.enter_context(patch.object(w,name,side_effect=AssertionError('authority write during recovery: '+name)))
        obj.recover_from_witness(stop)
    raise RuntimeError('recovery cut was not reached')


def anchor(obj):
    try:return obj.local_anchor()
    except Rejected as exc:
        if str(exc)!='WITNESS_RECOVERY_REQUIRED':raise
        return None


class RecoveryInterruptionMixin:
    def __init__(self,*args,replica_mode='existing',recovery_cuts=REPEATED_CUTS,**kwargs):
        if replica_mode not in ('existing','fresh') or not recovery_cuts or any(c not in RECOVERY_CUTS for c in recovery_cuts):raise ValueError('recovery scope')
        self.replica_mode=replica_mode;self.recovery_cuts=tuple(recovery_cuts);self.recovery_diagnostics=[];self.interruption_done=False
        super().__init__(*args,**kwargs)
        self.simulator=RecoveryInterruptionSimulator(self.simulator)

    def recovery_owner(self,side,oid):
        if side=='sender':return self.l,self.w,None
        ctx=self.context_for(oid);obj,w=self.receivers[ctx['recipient']];return obj,w,ctx

    def set_owner(self,side,oid,obj):
        if side=='sender':self.l=obj
        else:
            ctx=self.context_for(oid);_,w=self.receivers[ctx['recipient']];self.receivers[ctx['recipient']]=(obj,w)

    def open_owner(self,side,oid,path,*,fresh=False,restore=False):
        _,w,ctx=self.recovery_owner(side,oid)
        cls=PublicGatewayLedger if side=='sender' else RetentionRecipient
        options=dict(clock=lambda:self.now,vault=vault() if side=='sender' else recipient_vault(),witness=w)
        if ctx is not None:options['context']=ctx
        fn=cls.restore_new if restore else cls.new_replica if fresh else cls
        return fn(path,**options)

    def authority_heads(self):
        return dict(sender=self.w.head(self.l.namespace,True),receivers={name:w.head(obj.namespace,True) for name,(obj,w) in self.receivers.items()})

    def _observe(self,actual):
        command=self.commands[len(self.simulator.records)]
        if command['kind']!='RECOVERY_CUT':return super()._observe(actual)
        with patch('sqlite3.connect',side_effect=AssertionError('generator DB access')),patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('generator runtime access')),patch.object(RetentionRecipient,'accept',side_effect=AssertionError('generator recipient access')),patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('generator observed response access')):
            generated=self.simulator.emit(command)
        if generated!=actual:raise AssertionError('recovery unavailable observation differs')
        side,oid=command['side'],command['operation'];old,w,_=self.recovery_owner(side,oid);heads=self.authority_heads()
        restored=self.open_owner(side,oid,self.directory/('interruption-diagnostic-'+str(len(self.recovery_diagnostics))),restore=True)
        try:
            if restored.state_image()!=w.head(old.namespace,True)['image'] or restored.audit():raise AssertionError('R12.diagnostic_image')
            self.set_owner(side,oid,restored)
            try:relation=self.relation()
            finally:self.set_owner(side,oid,old)
            if self.authority_heads()!=heads:raise AssertionError('R12.diagnostic_authority_write')
        finally:restored.close()
        relation['R12']=digest(self.recovery_diagnostics[-1])
        self.checkpoints.append(dict(index=len(self.simulator.records),kind='RECOVERY_CUT',relation=relation))

    def recover_cut(self,side,oid,cut):
        command=dict(kind='RECOVERY_CUT',at=self.now,side=side,operation=oid,cut=cut);self.commands.append(command)
        obj,w,ctx=self.recovery_owner(side,oid);path=obj.path;ns=obj.namespace
        heads=self.authority_heads();head=w.head(ns,True);before_image=obj.state_image();before_anchor=anchor(obj);obj.close()
        cfg=dict(side=side,at=self.now,cut=cut,local=str(path),witness=str(w.path))
        if ctx is not None:cfg['context']=encode(ctx).hex()
        config=self.directory/'recovery-cut.json';config.write_text(json.dumps(cfg))
        proc=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--child',str(config)],capture_output=True,text=True,timeout=30)
        restored=self.open_owner(side,oid,path);self.set_owner(side,oid,restored)
        if proc.returncode!=EXIT_CODE:raise AssertionError('recovery child failed: '+str(proc.returncode)+' '+proc.stderr[-1800:])
        if self.authority_heads()!=heads:raise AssertionError('R12.recovery_changed_authority')
        committed=cut=='after_recovery_commit';expected_anchor={k:head[k] for k in ('seq','digest')} if committed else before_anchor
        if anchor(restored)!=expected_anchor or restored.state_image()!=(head['image'] if committed else before_image):raise AssertionError('R12.local_recovery_atomicity')
        current=anchor(restored)=={k:head[k] for k in ('seq','digest')}
        try:restored.check_current_state()
        except Rejected as exc:
            if current or str(exc)!='WITNESS_RECOVERY_REQUIRED':raise
        else:
            if not current:raise AssertionError('R12.incomplete_replica_not_frozen')
        self.recovery_diagnostics.append(dict(side=side,cut=cut,ordinal=len(self.recovery_diagnostics)+1,exit_code=proc.returncode,
            replica_mode=self.replica_mode,local_commit=committed,local_current=current,anchor_present=anchor(restored) is not None,
            authority_unchanged=True,local_atomicity=True,stale_guard_blocked=not current,business_dispatch_guarded=True))
        self.records.append(dict(kind='RECOVERY_UNAVAILABLE',at=self.now,side=side,operation=oid))

    def restore(self,*args,**kwargs):
        side,oid=self.simulator.target()
        if self.interruption_done:raise AssertionError('single recovery episode scope')
        self.interruption_done=True
        if self.replica_mode=='fresh':
            old,_,_=self.recovery_owner(side,oid);fresh=self.open_owner(side,oid,self.directory/'fresh-interrupted-replica',fresh=True)
            old.close();self.set_owner(side,oid,fresh)
        for cut in self.recovery_cuts:self.recover_cut(side,oid,cut)
        return super().restore(*args,**kwargs)


class InterruptedPublicRuntime(RecoveryInterruptionMixin,RecoveryRuntime):pass
class InterruptedKernelRuntime(RecoveryInterruptionMixin,KernelRuntime):pass
class InterruptedDeliveryRuntime(RecoveryInterruptionMixin,DeliveryRecoveryRuntime):pass


def run_interrupted(scenario,mode,mask=3,cuts=REPEATED_CUTS):
    if scenario not in SCENARIOS or mode not in ('existing','fresh') or type(mask) is not int or not 0<=mask<8:raise ValueError('outside profile')
    family,arguments=SCENARIOS[scenario];instances=[]
    cls,entry,target={'public':(InterruptedPublicRuntime,run_recovery,'public_recovery_trace.RecoveryRuntime'),
        'kernel':(InterruptedKernelRuntime,run_kernel,'private_recovery_trace.KernelRuntime'),
        'delivery':(InterruptedDeliveryRuntime,run_delivery_recovery,'delivery_recovery_trace.DeliveryRecoveryRuntime')}[family]
    def create(*a,**kw):
        obj=cls(*a,replica_mode=mode,recovery_cuts=cuts,**kw);instances.append(obj);return obj
    with patch(target,side_effect=create):case=entry(*arguments,mask=mask)
    runtime=instances[0]
    if not runtime.interruption_done or len(runtime.recovery_diagnostics)!=len(cuts):raise AssertionError('recovery episode incomplete')
    case.update(scenario=scenario,family=family,replica_mode=mode,recovery_cuts=list(cuts),recovery_diagnostics=runtime.recovery_diagnostics)
    return case


def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--child',type=Path);parser.add_argument('--output',type=Path);args=parser.parse_args()
    if args.child:return child(args.child)
    if args.output is None or args.output.exists():parser.error('choose a new output directory')
    args.output.mkdir(parents=True);root=Path(__file__).parent
    sources=list(root.glob('*.py'))+[root.parent/n for n in ('fixed_work_model.py','histogram_kernel.py')]
    report=dict(profile='repeated-recovery-interruption-v1',passed=False,source_sha256={str(p.relative_to(root.parent)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},cases=[],
        scope='Ten specified original failure states across public, private and delivery simulators. Existing and fresh replicas, three restore cuts repeated twice, explicit fixed public schedule. Local SQLite authority; no authority rollback/power loss, concurrent writes, retirement or general refinement proof.')
    with lzma.open(args.output/'cases.jsonl.xz','wt') as archive:
        for scenario in SCENARIOS:
            for mode in ('existing','fresh'):
                reference=None
                for mask in range(8):
                    case=run_interrupted(scenario,mode,mask);fingerprint=digest(dict(records=case['expected_records'],checkpoints=case['checkpoints']))
                    if reference is None:reference=fingerprint
                    if fingerprint!=reference:raise AssertionError('conditioned repeated recovery differs')
                    report['cases'].append(dict(scenario=scenario,replica_mode=mode,mask=mask,trace_sha256=digest(case['expected_records']),correspondence_sha256=fingerprint,checkpoints=len(case['checkpoints']),recovery_diagnostics=case['recovery_diagnostics']))
                    archive.write(json.dumps(case,separators=(',',':'))+'\n')
                print('PASS',scenario,mode,'8 datasets, 48 recovery exits',flush=True)
    count=len(report['cases']);report.update(passed=True,cases_count=count,groups_count=count//8,original_failure_exits=count,recovery_exits=count*len(REPEATED_CUTS),operational_restores=count,recovery_diagnostic_restores=count*len(REPEATED_CUTS),original_failure_diagnostic_restores=sum(SCENARIOS[c['scenario']][0]=='delivery' for c in report['cases']),checkpoints_count=sum(c['checkpoints'] for c in report['cases']))
    (args.output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
