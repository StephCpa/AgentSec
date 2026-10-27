"""One state owner for request/work/preparation/delivery/retirement transitions.

Transition rules reuse the independently constructed models; no actual responses
or database images enter this object. A typed recovery obligation distinguishes
operation targets from route targets. One pending fault at a time; business is
paused until explicit recovery. Component-local availability is not composed yet.
"""
from copy import deepcopy
from retirement_recovery_simulator import RetirementRecoverySimulator
from preparation_recovery_simulator import PreparationRecoverySimulator, preparation_cuts, DURABLE_CUTS
from delivery_recovery_simulator import DeliveryRecoverySimulator
from recovery_simulator import RecoverySimulator
from kernel_recovery_simulator import KernelRecoverySimulator
from recovery_interruption_simulator import RECOVERY_CUTS
from public_trace_adapter import require
from observation_events import EventStream


class UnifiedLifecycleSimulator(RetirementRecoverySimulator):
    commits = RecoverySimulator.commits
    tick_commits = KernelRecoverySimulator.tick_commits

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pending_tick = None
        self.obligation = None
        self.events = EventStream()

    def require_business_scope(self, command):
        # Cleanup of a confirmed prefix does not prohibit later business.
        pass

    def require_cleanup_scope(self):
        require(any(j.get('confirmed') is not None for j in self.state.jobs), 'CLEANUP_WITHOUT_CONFIRMED_PREFIX')

    def _prepare_event(self, command):
        kind = command['kind']; cut = kind == 'PREPARE_CUT'; m = self.state
        require(set(command) == {'kind', 'at', 'operation', 'delivery_kind'} | ({'cut'} if cut else set()), 'PREPARATION_SCOPE')
        require(command['delivery_kind'] in ('DELIVERY', 'TERMINAL'), 'PREPARATION_SCOPE')
        if cut:
            require(command['cut'] in preparation_cuts(command['delivery_kind']), 'CUT_SCOPE')
        before = deepcopy(m.__dict__); m.now = command['at']
        # Explicit unbound call avoids the retirement _prepare name collision.
        body, denial = PreparationRecoverySimulator._prepare(self, command['operation'], command['delivery_kind'])
        event = dict(at=m.now, operation=command['operation'], delivery_kind=command['delivery_kind'])
        if cut:
            require(denial is None, 'CUT_NOT_REACHED')
            if command['cut'] not in DURABLE_CUTS:
                m.__dict__ = before; m.now = command['at']
            self.needs_recovery = ('sender', command['operation'])
            event['kind'] = 'PREPARATION_UNAVAILABLE'
        elif denial is not None:
            event.update(kind='PREPARATION_REJECTED', reason=denial)
        else:
            event.update(kind='PREPARATION', body=body.hex())
        self.records.append(event)
        return event

    def _recovery(self, command):
        pending = self.obligation
        require(pending is not None, 'RECOVERY_NOT_PENDING')
        kind = command['kind']
        if kind == 'RECOVERY_CUT':
            require(set(command) == {'kind', 'at', 'side', 'operation', 'cut'} and
                    command['cut'] in RECOVERY_CUTS and
                    (command['side'], command['operation']) == (pending['side'], pending['target']), 'RECOVERY_TARGET')
            event = dict(kind='RECOVERY_UNAVAILABLE', at=command['at'], side=command['side'], operation=command['operation'])
        else:
            require(kind == pending['recovery'], 'RECOVERY_DOMAIN')
            fields = {'kind', 'at'}
            if kind in ('DELIVERY_RECOVER', 'RETIRE_RECOVER'):
                fields.add('side'); require(command.get('side') == pending['side'], 'RECOVERY_SIDE')
            if kind in ('DELIVERY_RECOVER', 'PREPARE_RECOVER', 'RETIRE_RECOVER'):
                field = 'route' if kind == 'RETIRE_RECOVER' else 'operation'
                fields.add(field); require(command.get(field) == pending['target'], 'RECOVERY_TARGET')
            require(set(command) == fields, 'RECOVERY_SCOPE')
            event = deepcopy(command); self.obligation = None; self.needs_recovery = None
        self.state.now = command['at']; self.records.append(event)
        return event

    def emit(self, command):
        require(type(command) is dict and type(command.get('kind')) is str, 'COMMAND_SCOPE')
        require(type(command.get('at')) is int and self.state.now <= command['at'] < 2**62, 'PUBLIC_CLOCK')
        # Model transitions are atomic on rejected commands. Signing is an
        # external ideal resource; this does not rewind external signer calls.
        before = {k: deepcopy(v) for k, v in self.__dict__.items() if k != 'sign'}
        try:
            kind = command['kind']
            if kind in ('RECOVER', 'DELIVERY_RECOVER', 'PREPARE_RECOVER', 'RETIRE_RECOVER', 'RECOVERY_CUT'):
                event = self._recovery(command)
            else:
                require(self.obligation is None, 'RECOVERY_REQUIRED')
                require(self.pending_tick is None or kind == 'TICK_RETRY', 'TICK_RETRY_REQUIRED')
                if kind in ('PREPARE', 'PREPARE_CUT'):
                    event = self._prepare_event(command)
                elif kind == 'PUBLIC_CUT':
                    event = RecoverySimulator.emit(self, command)
                elif kind in ('TICK_CUT', 'TICK_RETRY'):
                    event = KernelRecoverySimulator.emit(self, command)
                elif kind in ('RECEIVE_CUT', 'CONFIRM_CUT'):
                    event = DeliveryRecoverySimulator.emit(self, command)
                else:
                    event = super().emit(command)
                if kind.endswith('_CUT'):
                    if kind in ('PUBLIC_CUT', 'TICK_CUT'):
                        phase, side, target, recovery = ('public' if kind == 'PUBLIC_CUT' else 'work'), 'sender', '', 'RECOVER'
                    elif kind == 'PREPARE_CUT':
                        phase, side, target, recovery = 'preparation', 'sender', command['operation'], 'PREPARE_RECOVER'
                    elif kind in ('RECEIVE_CUT', 'CONFIRM_CUT'):
                        phase, side, target, recovery = 'delivery', ('receiver' if kind == 'RECEIVE_CUT' else 'sender'), command['operation'], 'DELIVERY_RECOVER'
                    else:
                        phase, side, target, recovery = 'retirement', ('receiver' if kind == 'RETIRE_SEND_CUT' else 'sender'), command['route'], 'RETIRE_RECOVER'
                    self.obligation = dict(phase=phase, side=side, target=target, recovery=recovery)
                    self.needs_recovery = (side, target)
            self.events.append(command, event)
            return deepcopy(event)
        except BaseException:
            for k in tuple(self.__dict__):
                if k != 'sign': del self.__dict__[k]
            self.__dict__.update(before)
            raise
