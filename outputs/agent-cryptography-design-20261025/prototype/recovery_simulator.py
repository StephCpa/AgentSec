"""Constructive candidate for public-request crash/recovery experiments.

Fault cuts are explicit, dataset-independent environment inputs. They are NOT
inferred from real exceptions, witness data or service responses. Availability
here means an in-process caller receives no response; no timing/TLS claim.
"""
from copy import deepcopy
from ledger import Rejected
from public_simulator import PublicSimulator
from public_trace_adapter import ViewMismatch,require

CUTS=('after_public_effect','after_public_journal_write','before_witness_accept',
      'after_witness_accept','after_local_anchor_write','response_drop')
DURABLE_CUTS=frozenset(('after_witness_accept','after_local_anchor_write','response_drop'))


class RecoverySimulator(PublicSimulator):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.needs_recovery=False

    def commits(self,cut):return cut in DURABLE_CUTS

    def emit(self,command):
        require(type(command) is dict,'COMMAND_SCOPE')
        kind=command.get('kind')
        if kind not in ('PUBLIC_CUT','RECOVER'):
            require(not self.needs_recovery,'RECOVERY_REQUIRED')
            return super().emit(command)
        m=self.state
        require(type(command.get('at')) is int and m.now<=command['at']<2**62,'PUBLIC_CLOCK')
        if kind=='RECOVER':
            require(set(command)=={'kind','at'} and self.needs_recovery,'RECOVER_SCOPE')
            # Restore the authoritative logical state already chosen by the
            # fault schedule; neither DB contents nor an image digest is input.
            m.now=command['at'];self.needs_recovery=False
            event=dict(command);self.records.append(event);return deepcopy(event)
        require(not self.needs_recovery,'RECOVERY_REQUIRED')
        require(set(command)=={'kind','at','request','peer','challenge_coin','cut'} and
                type(command['cut']) is str and command['cut'] in CUTS,'CUT_SCOPE')
        before=deepcopy(m.__dict__)
        try:
            m.now=command['at']
            # Construct the candidate response/cache effects using public inputs
            # and the ideal signer. The unavailable observation has no response.
            previous_sequence=m.journal_seq
            self._public(command)
            # Cached requests and early authentication/expiry denials return
            # before the new-dispatch hooks. Such cuts cannot be injected there.
            if command['cut'] in ('after_public_effect','after_public_journal_write'):
                require(m.journal_seq==previous_sequence+1,'CUT_NOT_REACHED')
            if not self.commits(command['cut']):m.__dict__=before;m.now=command['at']
            event=dict(kind='PUBLIC_UNAVAILABLE',at=command['at'],request=command['request'],peer=command['peer'])
            self.needs_recovery=True;self.records.append(event);return deepcopy(event)
        except BaseException as exc:
            m.__dict__=before
            if isinstance(exc,(Rejected,ValueError,KeyError,TypeError)):raise ViewMismatch(str(exc)) from exc
            raise
