"""Dataset-independent TICK cuts and exact retry over authoritative model state."""
from copy import deepcopy
from ledger import Rejected
from public_trace_adapter import ViewMismatch,require
from recovery_simulator import RecoverySimulator,DURABLE_CUTS

COMMON_CUTS=('after_work_step','before_tick_commit','before_witness_accept',
             'after_witness_accept','after_local_anchor_write','response_drop')
SAMPLING_CUTS=('before_sampling','after_sampling','after_scheduled_claim')
FINAL_CUTS=('after_scheduled_result_write','after_account_settle','after_publication_write',
            'before_public_decision_write','after_public_decision_write')
TICK_CUTS=COMMON_CUTS+SAMPLING_CUTS+('after_private_step',)+FINAL_CUTS


def phase_cuts(phase):
    if phase=='l1':return SAMPLING_CUTS+COMMON_CUTS
    if phase in ('row','bit','bucket'):return ('after_private_step',)+COMMON_CUTS
    if phase=='final':return ('after_private_step',)+FINAL_CUTS+COMMON_CUTS
    raise ValueError('unknown private-work phase')


class KernelRecoverySimulator(RecoverySimulator):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.pending_tick=None

    def tick_commits(self,cut):return cut in DURABLE_CUTS

    def emit(self,command):
        require(type(command) is dict,'COMMAND_SCOPE');kind=command.get('kind')
        if kind=='RECOVER':return super().emit(command)
        if kind not in ('TICK_CUT','TICK_RETRY'):
            require(self.pending_tick is None,'TICK_RETRY_REQUIRED')
            return super().emit(command)
        m=self.state
        require(not self.needs_recovery,'RECOVERY_REQUIRED')
        require(type(command.get('at')) is int and m.now<=command['at']<2**62,'PUBLIC_CLOCK')
        fields={'kind','at','tick'}|({'cut'} if kind=='TICK_CUT' else set())
        require(set(command)==fields and type(command.get('tick')) is int,'TICK_COMMAND_SCOPE')
        if kind=='TICK_CUT':
            require(self.pending_tick is None and command['tick']==m.tick+1,'TICK_CUT_SCOPE')
            cut=command['cut'];require(type(cut) is str and cut in TICK_CUTS,'CUT_SCOPE')
            # Freeze one active operation. Reachability uses only public pc/work,
            # authorization and operation phase, never the private accumulator.
            require(len(m.jobs)==1 and not m.paused,'KERNEL_PROFILE')
            job=m.jobs[0]
            require(job['pc']<job['work'] and job['state'] in ('RESERVED','STARTED') ,'KERNEL_PROFILE')
            root=m.cfg['roots'][job['action']['root']]
            require(not root.get('revoked',False) and command['at']<min(root['expires_at'],job['action']['deadline'],job['authorization_expiry']),'KERNEL_PROFILE')
            if cut in SAMPLING_CUTS:require(job['state']=='RESERVED' and job['pc']==0,'CUT_NOT_REACHED')
            if cut=='after_private_step':require(job['state']=='STARTED' and job['pc']>=1,'CUT_NOT_REACHED')
            if cut in FINAL_CUTS:require(job['state']=='STARTED' and job['pc']==job['work']-1,'CUT_NOT_REACHED')
        else:
            require(self.pending_tick is not None and command['tick']==self.pending_tick['tick'],'TICK_RETRY_BINDING')
        before=deepcopy(m.__dict__);pending=deepcopy(self.pending_tick)
        try:
            m.now=command['at']
            if kind=='TICK_CUT':
                committed=self.tick_commits(command['cut'])
                m.consume(dict(kind='TICK',at=m.now,tick=command['tick']))
                if not committed:m.__dict__=before;m.now=command['at']
                self.pending_tick=dict(tick=command['tick'],committed=committed);self.needs_recovery=True
                event=dict(kind='TICK_UNAVAILABLE',at=command['at'],tick=command['tick'])
            else:
                if not pending['committed']:m.consume(dict(kind='TICK',at=m.now,tick=command['tick']))
                else:require(m.tick==command['tick'],'TICK_RETRY_STATE')
                self.pending_tick=None;event=dict(command)
            self.records.append(event);return deepcopy(event)
        except BaseException as exc:
            m.__dict__=before;self.pending_tick=pending;self.needs_recovery=False
            if isinstance(exc,(Rejected,ValueError,KeyError,TypeError)):raise ViewMismatch(str(exc)) from exc
            raise
