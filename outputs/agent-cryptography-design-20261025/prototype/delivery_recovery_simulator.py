"""Delivery crash candidate with explicit public environment cuts, never DB input.

projected_records is generated logical history for the state relation, NOT an
attacker observation. A precommit receiver exit projects to no receive; a
postcommit exit projects to a lost ACK. The public event is identical in both.
"""
from copy import deepcopy
from ledger import Rejected
from public_simulator import PublicSimulator
from public_trace_adapter import require,ViewMismatch
import retention_wire as r

WITNESS_CUTS=('before_witness_accept','after_witness_accept','after_local_anchor_write')
RECEIVE_CUTS=('after_v2_recipient_record','before_v2_recipient_event_commit')+WITNESS_CUTS+('after_v2_recipient_event_commit','response_drop')
CONFIRM_CUTS=('before_final_event_write','after_final_event_write','before_v2_confirmation_commit')+WITNESS_CUTS+('after_v2_confirmation_commit','response_drop')
DURABLE_CUTS=frozenset(('after_witness_accept','after_local_anchor_write','after_v2_recipient_event_commit','after_v2_confirmation_commit','response_drop'))
LOCAL_CUTS=frozenset(('after_v2_recipient_event_commit','after_v2_confirmation_commit','response_drop'))


class DeliveryRecoverySimulator(PublicSimulator):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.projected_records=[];self.needs_recovery=None
        # This profile bootstraps empty receivers for each public route at setup.
        self.initialized_contexts={r.context_hash(x['context']) for x in self.state.cfg['roots'].values()}

    def emit(self,command):
        require(type(command) is dict,'COMMAND_SCOPE');kind=command.get('kind')
        if kind not in ('RECEIVE_CUT','CONFIRM_CUT','DELIVERY_RECOVER'):
            require(self.needs_recovery is None,'RECOVERY_REQUIRED')
            event=super().emit(command);self.projected_records.append(deepcopy(event));return event
        m=self.state
        require(type(command.get('at')) is int and m.now<=command['at']<2**62,'PUBLIC_CLOCK')
        before=deepcopy(m.__dict__);pending=deepcopy(self.pending)
        old_recovery=self.needs_recovery;n=len(self.records);p=len(self.projected_records)
        try:
            if kind=='DELIVERY_RECOVER':
                require(set(command)=={'kind','at','side','operation'} and self.needs_recovery==(command['side'],command['operation']),'RECOVER_SCOPE')
                m.now=command['at'];self.needs_recovery=None;event=dict(command)
            else:
                require(self.needs_recovery is None,'RECOVERY_REQUIRED')
                fields={'kind','at','operation','cut'} | ({'delivery_kind','challenge'} if kind=='RECEIVE_CUT' else set())
                require(set(command)==fields and type(command['cut']) is str,'CUT_SCOPE')
                cut=command['cut'];job=m.by_id.get(command['operation']);require(job is not None,'CUT_OPERATION')
                m.now=command['at']
                if kind=='RECEIVE_CUT':
                    require(cut in RECEIVE_CUTS,'CUT_SCOPE')
                    key=(r.context_hash(job['context']),job['route_seq'])
                    require(cut!='after_v2_recipient_record' or key not in m.receiver,'CUT_NOT_REACHED')
                    # The fault location is supplied by the public environment,
                    # not discovered from an actual response or storage value.
                    logical=self._send(dict(command,kind='SEND',loss='ack' if cut in DURABLE_CUTS else 'packet'))
                    self.projected_records.append(deepcopy(logical))
                    event=dict(kind='DELIVERY_UNAVAILABLE',at=m.now,request=logical['request'])
                    side='receiver'
                else:
                    require(cut in CONFIRM_CUTS,'CUT_SCOPE')
                    if job.get('confirmed') is not None:
                        require(cut in WITNESS_CUTS+('response_drop',),'CUT_NOT_REACHED')
                    logical=super().emit(dict(kind='CONFIRM',at=m.now,operation=command['operation']))
                    self.records.pop()
                    if cut in DURABLE_CUTS:self.projected_records.append(deepcopy(logical))
                    else:m.__dict__=before;m.now=command['at'];self.pending=pending
                    event=dict(kind='CONFIRM_UNAVAILABLE',at=m.now,request=logical['request'],response=logical['response'])
                    side='sender'
                self.needs_recovery=(side,command['operation'])
            self.records.append(event);return deepcopy(event)
        except BaseException as exc:
            m.__dict__=before;self.pending=pending;self.needs_recovery=old_recovery
            del self.records[n:];del self.projected_records[p:]
            if isinstance(exc,(Rejected,ValueError,KeyError,TypeError)):raise ViewMismatch(str(exc)) from exc
            raise
