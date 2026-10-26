"""Construct preparation observations without storage or observed response inputs.

The environment supplies a dataset-independent cut schedule. A failed call has
no body or commit bit. Model state follows authority, not the failed caller's
knowledge. Existing delivery/confirmation cuts are outside this profile.
"""
from copy import deepcopy
from ledger import Rejected
from delivery_recovery_simulator import DeliveryRecoverySimulator, WITNESS_CUTS
from public_trace_adapter import require, ViewMismatch
import retention_delivery as d
import retention_wire as r

DURABLE_CUTS = frozenset(('after_witness_accept', 'after_local_anchor_write',
                          'after_v2_envelope_commit', 'after_v2_control_commit', 'response_drop'))
LOCAL_CUTS = frozenset(('after_v2_envelope_commit', 'after_v2_control_commit', 'response_drop'))


def preparation_cuts(kind):
    if kind not in ('DELIVERY', 'TERMINAL'):
        raise ValueError('unsupported preparation kind')
    field = 'envelope' if kind == 'DELIVERY' else 'control'
    return ('before_v2_' + field + '_commit',) + WITNESS_CUTS + ('after_v2_' + field + '_commit', 'response_drop')


class PreparationRecoverySimulator(DeliveryRecoverySimulator):
    def _prepare(self, operation, kind):
        m = self.state
        job = m.by_id.get(operation)
        require(job is not None and job['publication'] == 'ADMITTED', 'PREPARATION_BEFORE_ADMISSION')
        require(job.get('confirmed') is None, 'PREPARATION_AFTER_CONFIRMATION_OUT_OF_SCOPE')
        # The implementation checks terminal expiration before final ordering;
        # envelope ordering is checked before expiration.
        if kind == 'TERMINAL' and m.now < job['expires_at']:
            return None, 'TERMINAL_NOT_EXPIRED'
        if job['seq'] != len(m.final) + 1:
            return None, 'DOMAIN_FINAL_ORDER'
        if kind == 'DELIVERY' and m.now >= job['expires_at']:
            return None, 'TICKET_EXPIRED'
        ctx = job['context']; h = r.context_hash(ctx); key = (h, job['route_seq'])
        body = m.prepared.get((key, kind))
        if body is None:
            desc = d.descriptor(ctx, seq=job['route_seq'], operation=job['id'],
                                issued_at=job['issued_at'], expires_at=job['expires_at'], shape=m._shape(job))
            payload = dict(profile=d.PROFILE, context_hash=h, descriptor=desc)
            if kind == 'DELIVERY':
                payload['result'] = b''.join(x.to_bytes(8, 'big') for x in job['value'])
                object_type = d.ENVELOPE_TYPE
            else:
                envelope = m.prepared.get((key, 'DELIVERY'))
                payload['envelope_hash'] = b'' if envelope is None else r.sha(envelope)
                object_type = d.CONTROL_TYPE
            body = self._signed('sender', object_type, payload, ctx)
        d.parse_body(kind, body, ctx)
        m.prepared[(key, kind)] = body
        return body, None

    def emit(self, command):
        require(type(command) is dict, 'COMMAND_SCOPE')
        kind = command.get('kind')
        require(kind not in ('RECEIVE_CUT', 'CONFIRM_CUT', 'DELIVERY_RECOVER'), 'COMMAND_SCOPE')
        if kind not in ('PREPARE', 'PREPARE_CUT', 'PREPARE_RECOVER'):
            return super().emit(command)
        m = self.state
        require(type(command.get('at')) is int and m.now <= command['at'] < 2**62, 'PUBLIC_CLOCK')
        before = deepcopy(m.__dict__); old_recovery = self.needs_recovery
        n = len(self.records)
        try:
            if kind == 'PREPARE_RECOVER':
                require(set(command) == {'kind', 'at', 'operation'} and
                        self.needs_recovery == ('sender', command['operation']), 'RECOVER_SCOPE')
                m.now = command['at']; self.needs_recovery = None; event = dict(command)
            else:
                require(self.needs_recovery is None, 'RECOVERY_REQUIRED')
                fields = {'kind', 'at', 'operation', 'delivery_kind'} | ({'cut'} if kind == 'PREPARE_CUT' else set())
                require(set(command) == fields and command['delivery_kind'] in ('DELIVERY', 'TERMINAL'), 'PREPARATION_SCOPE')
                if kind == 'PREPARE_CUT':
                    require(command['cut'] in preparation_cuts(command['delivery_kind']), 'CUT_SCOPE')
                m.now = command['at']
                body, denial = self._prepare(command['operation'], command['delivery_kind'])
                event = dict(at=m.now, operation=command['operation'], delivery_kind=command['delivery_kind'])
                if kind == 'PREPARE_CUT':
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
            return deepcopy(event)
        except BaseException as exc:
            m.__dict__ = before; self.needs_recovery = old_recovery
            del self.records[n:]
            if isinstance(exc, (Rejected, ValueError, KeyError, TypeError)):
                raise ViewMismatch(str(exc)) from exc
            raise
