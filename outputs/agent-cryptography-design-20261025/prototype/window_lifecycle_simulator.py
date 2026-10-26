"""One-slot receiver lifecycle: new business, full-window denial and recovery.

The frozen retirement profile remains strict. This explicit profile permits
business after cleanup and cleanup of a confirmed prefix with a pending suffix.
"""
from retirement_recovery_simulator import RetirementRecoverySimulator
from public_trace_adapter import require
import retention_wire as r


class WindowLifecycleSimulator(RetirementRecoverySimulator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        require(set(self.state.cfg['roots']) == {'root'} and self.state.cfg['roots']['root']['context']['window'] == 1,
                'SINGLE_WINDOW_SETUP_REQUIRED')

    def require_business_scope(self, command):
        # Original PUBLIC/TICK/SEND/CONFIRM validation, authorization and the
        # two-operation bound still apply in the base constructive simulator.
        pass

    def require_cleanup_scope(self):
        require(any(j.get('confirmed') is not None for j in self.state.jobs), 'CLEANUP_WITHOUT_CONFIRMED_PREFIX')

    def _send(self, command):
        if command['kind'] != 'SEND': return super()._send(command)
        require(command['loss'] in ('none', 'packet', 'ack'), 'LOSS_SCOPE')
        m = self.state; job = m.by_id.get(command['operation'])
        require(job is not None and job['publication'] == 'ADMITTED', 'SEND_BEFORE_ADMISSION')
        h = r.context_hash(job['context']); key = h, job['route_seq']
        high, _ = self.frontiers(h); floor = self.retirement['receiver'][h]['floor']
        if command['loss'] != 'packet' and key not in m.receiver and high - floor >= job['context']['window']:
            # Sender preparation completes. No receiver fact or receipt is
            # created, but the authenticated denial commits observed time.
            logical = super()._send(dict(command, loss='packet'))
            self.receiver_event(h)
            return dict(kind='DELIVERY_REJECTED', at=m.now, request=logical['request'], reason='V2_RECIPIENT_WINDOW_FULL')
        return super()._send(command)

    def emit(self, command):
        # PublicSimulator rolls its state back on malformed calls; preserve the
        # retirement projection as well if a window-aware send fails validation.
        n = len(self.projected_records)
        try: return super().emit(command)
        except BaseException:
            del self.projected_records[n:]
            raise
