"""Component-scoped availability after one declared retirement process exit.

Two routes share a sender and final-order domain, but have distinct recipients.
Cut locations are explicit environment inputs, never inferred from real state.
This finite profile is not a general concurrency or availability proof.
"""
from copy import deepcopy
from retirement_recovery_simulator import RetirementRecoverySimulator, DURABLE_CUTS, LOCAL_CUTS
from public_trace_adapter import require, require_public_call_frame
import retention_wire as r

SIDES = ('receiver', 'sender')
CUTS = {
    'receiver': ('before_witness_accept', 'after_witness_accept', 'after_v2_recipient_retire_commit'),
    'sender': ('before_witness_accept', 'after_witness_accept', 'after_v2_retirement_offer_commit'),
}


class CrossRouteIsolationSimulator(RetirementRecoverySimulator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        roots = self.state.cfg['roots']
        require(set(roots) == {'root', 'root2'} and
                len({x['context']['recipient'] for x in roots.values()}) == 2 and
                all(x['context']['window'] == 1 for x in roots.values()),
                'TWO_DISTINCT_RECIPIENTS_REQUIRED')
        self.fault = None

    def require_business_scope(self, command):
        pass

    def require_cleanup_scope(self):
        require(any(j.get('confirmed') is not None for j in self.state.jobs),
                'CLEANUP_WITHOUT_CONFIRMED_PREFIX')

    def _unavailable(self, command):
        kind = command['kind']; m = self.state
        if kind == 'PUBLIC':
            require(set(command) == {'kind', 'at', 'request', 'peer', 'challenge_coin'}, 'COMMAND_SCOPE')
            require_public_call_frame(bytes.fromhex(command['request']), bytes.fromhex(command['peer']))
            require(len(bytes.fromhex(command['challenge_coin'])) in (0, 32), 'PUBLIC_COIN_SHAPE')
            event = dict(kind='PUBLIC_UNAVAILABLE', at=command['at'], request=command['request'], peer=command['peer'])
        elif kind == 'TICK':
            require(set(command) == {'kind', 'at', 'tick'} and type(command['tick']) is int and command['tick'] == m.tick + 1,
                    'TICK_SCOPE')
            event = dict(kind='TICK_UNAVAILABLE', at=command['at'], tick=command['tick'])
        else:
            require(kind == 'RETENTION_QUERY' and set(command) == {'kind', 'at', 'route', 'query_kind', 'seq', 'challenge'},
                    'UNAVAILABLE_CALL_SCOPE')
            h, ctx = self.context(command['route']); seq = command['seq']; qkind = command['query_kind']
            q = dict(profile=r.PROFILE, context_hash=h, kind=qkind, seq=seq,
                     delivery='' if qkind == 'CHECKPOINT' else r.delivery_id(ctx, seq), challenge=bytes.fromhex(command['challenge']))
            r.validate_query(q, ctx)
            request = self._signed('sender', r.QUERY_TYPE, q, ctx)
            event = dict(kind='RETENTION_UNAVAILABLE', at=command['at'], route=command['route'], request=request.hex())
        # An availability failure is not a business rejection: no journal,
        # observed-time write, mechanism invocation or signing of a reply.
        event['error'] = 'WITNESS_RECOVERY_REQUIRED'
        m.now = command['at']; self.records.append(event)
        return deepcopy(event)

    def emit(self, command):
        require(type(command) is dict and type(command.get('kind')) is str, 'COMMAND_SCOPE')
        kind = command['kind']
        require(type(command.get('at')) is int and self.state.now <= command['at'] < 2**62, 'PUBLIC_CLOCK')
        if kind.endswith('_CUT'):
            require(self.fault is None and command.get('route') == 'root', 'SINGLE_FAULT_SCOPE')
            side = 'receiver' if kind == 'RETIRE_SEND_CUT' else 'sender'
            require(kind == ('RETIRE_SEND_CUT' if side == 'receiver' else 'RETIRE_PREPARE_CUT') and
                    command.get('cut') in CUTS[side], 'ISOLATION_CUT_SCOPE')
            result = super().emit(command)
            self.fault = dict(side=side, route='root', stale=command['cut'] in DURABLE_CUTS and command['cut'] not in LOCAL_CUTS)
            return result
        if kind == 'RETIRE_RECOVER':
            require(self.fault is not None, 'RECOVERY_NOT_PENDING')
            result = super().emit(command); self.fault = None
            return result
        if self.fault is None:
            return super().emit(command)
        fault = self.fault
        require(kind in ('PUBLIC', 'TICK', 'SEND', 'CONFIRM', 'RETENTION_QUERY'), 'PENDING_ISOLATION_SCOPE')
        if fault['stale'] and fault['side'] == 'sender':
            require(kind in ('PUBLIC', 'TICK', 'RETENTION_QUERY'), 'STALE_SENDER_CALL_SCOPE')
            if kind != 'RETENTION_QUERY': return self._unavailable(command)
        if fault['stale'] and fault['side'] == 'receiver':
            if kind == 'RETENTION_QUERY' and command.get('route') == fault['route']:
                return self._unavailable(command)
            if kind == 'SEND':
                job = self.state.by_id.get(command.get('operation'))
                require(job is not None and job['action']['root'] != fault['route'], 'FAILED_RECIPIENT_SEND_OUT_OF_SCOPE')
        # The original strict profile freezes the whole execution. Here a
        # declared pending component does not freeze unrelated healthy owners.
        pending = self.needs_recovery
        self.needs_recovery = None
        try: return super().emit(command)
        finally: self.needs_recovery = pending
