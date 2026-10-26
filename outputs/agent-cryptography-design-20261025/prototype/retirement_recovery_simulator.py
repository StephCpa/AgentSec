"""Construct signed retention observations from public inputs, never real state.

Historical first facts remain in the model; receiver floor selects the live
window. A checkpoint authenticates the current prefix, not deleted fact bytes.
"""
from copy import deepcopy
from ledger import Rejected
from delivery_recovery_simulator import DeliveryRecoverySimulator, WITNESS_CUTS
from public_gateway import parse_request
from public_trace_adapter import require, ViewMismatch
import retention_wire as r
import retention_delivery as d

PREPARE_CUTS = ('before_v2_retirement_offer_commit',) + WITNESS_CUTS + ('after_v2_retirement_offer_commit', 'response_drop')
SEND_CUTS = ('after_v2_recipient_delete', 'before_v2_recipient_retire_commit') + WITNESS_CUTS + ('after_v2_recipient_retire_commit', 'response_drop')
CONFIRM_CUTS = ('before_v2_retirement_checkpoint_commit',) + WITNESS_CUTS + ('after_v2_retirement_checkpoint_commit', 'response_drop')
LOCAL_CUTS = frozenset(('after_v2_retirement_offer_commit', 'after_v2_recipient_retire_commit', 'after_v2_retirement_checkpoint_commit', 'response_drop'))
DURABLE_CUTS = LOCAL_CUTS | {'after_witness_accept', 'after_local_anchor_write'}
CUTS = {'RETIRE_PREPARE': PREPARE_CUTS, 'RETIRE_SEND': SEND_CUTS, 'RETIRE_CONFIRM': CONFIRM_CUTS}


class RetirementRecoverySimulator(DeliveryRecoverySimulator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        contexts = {r.context_hash(x['context']): x['context'] for x in self.state.cfg['roots'].values()}
        self.retirement = dict(sender={h: dict(floor=0, root=r.genesis(ctx), evidence=None) for h, ctx in contexts.items()},
                               receiver={h: dict(floor=0, root=r.genesis(ctx), last_offer=None) for h, ctx in contexts.items()}, offers={})
        self.retention_pending = {}; self.cleanup_started = False

    def context(self, route):
        require(route in self.state.cfg['roots'], 'RETENTION_ROUTE')
        ctx = self.state.cfg['roots'][route]['context']
        return r.context_hash(ctx), ctx

    def prefix(self, h, ctx, target):
        root = r.genesis(ctx)
        for seq in range(1, target + 1):
            require((h, seq) in self.state.receiver, 'RETENTION_ARCHIVE_GAP')
            root = r.extend_prefix(root, self.state.receiver[h, seq], ctx, seq)
        return root

    def frontiers(self, h):
        high = max((seq for hh, seq in self.state.receiver if hh == h), default=0)
        confirmed = max((j['route_seq'] for j in self.state.jobs if j.get('confirmed') is not None and r.context_hash(j['context']) == h), default=0)
        return high, confirmed

    def receiver_event(self, h):
        # Authenticated business denials also persist receiver observed time.
        self.projected_records.append(dict(kind='RETENTION_RECEIVE', at=self.state.now, context_hash=h.hex()))

    def checkpoint(self, request, ctx, status):
        h = r.context_hash(ctx); state = self.retirement['receiver'][h]; high, _ = self.frontiers(h)
        q, _ = r.request_binding(request, ctx, status)
        raw = self._signed('receiver', r.CHECKPOINT_TYPE, dict(profile=r.PROFILE, context_hash=h, status=status,
                           floor=state['floor'], root=state['root'], high=high, challenge=q['challenge'], request_hash=r.sha(request)), ctx)
        r.parse_checkpoint(raw, request, ctx)
        return raw

    def _prepare(self, command):
        h, ctx = self.context(command['route']); state = self.retirement['sender'][h]; target = command['target']
        r.uint(target, 1); _, confirmed = self.frontiers(h)
        event = dict(at=self.state.now, route=command['route'], target=target)
        if not state['floor'] < target <= confirmed:
            return dict(event, kind='RETIRE_PREPARATION_REJECTED', reason='V2_UNCONFIRMED_RETIREMENT')
        key = h, state['floor'], target
        raw = self.retirement['offers'].get(key)
        if raw is None:
            raw = self._signed('sender', r.OFFER_TYPE, dict(profile=r.PROFILE, context_hash=h, base=state['floor'],
                               base_root=state['root'], target=target, target_root=self.prefix(h, ctx, target)), ctx)
            r.parse_offer(raw, ctx); self.retirement['offers'][key] = raw
        return dict(event, kind='RETIRE_PREPARATION', body=raw.hex())

    def _send(self, command):
        # PublicSimulator uses this name for ordinary delivery as well.
        if command['kind'] == 'SEND':
            return super()._send(command)
        h, ctx = self.context(command['route']); state = self.retirement['receiver'][h]
        key = (h, command['base'], command['target']); require(key in self.retirement['offers'], 'RETIRE_WITHOUT_PREPARED_OFFER')
        raw = self.retirement['offers'][key]; challenge = bytes.fromhex(command['challenge']); r.blob(challenge)
        request = self._signed('sender', r.ATTEMPT_TYPE, dict(profile=r.PROFILE, context_hash=h, offer=raw, challenge=challenge), ctx)
        offer = r.parse_offer(raw, ctx); high, _ = self.frontiers(h)
        if offer['target'] > state['floor']:
            live = tuple(self.state.receiver[h, seq] for seq in range(state['floor'] + 1, high + 1))
            new = r.retirement_transition(raw, ctx, floor=state['floor'], root=state['root'], high=high, live=live)
            state.update(floor=new['floor'], root=new['root'], last_offer=raw)
        elif offer['target'] == state['floor']:
            require(offer['target_root'] == state['root'], 'RETENTION_PREFIX_MISMATCH')
        self.receiver_event(h)
        if command['loss'] == 'ack':
            response = 'ACK_LOST'
        else:
            ack = self.checkpoint(request, ctx, 'RETIRE_ACK'); response = ack.hex()
            self.retention_pending[command['route']] = (request, ack)
        return dict(kind='RETIRE_DELIVERY', at=self.state.now, route=command['route'], request=request.hex(), response=response)

    def _confirm(self, command):
        route = command['route']; h, ctx = self.context(route)
        require(route in self.retention_pending, 'RETIRE_CONFIRM_WITHOUT_RECEIPT')
        request, ack = self.retention_pending[route]; checkpoint = r.parse_checkpoint(ack, request, ctx)
        _, confirmed = self.frontiers(h)
        if checkpoint['status'] == 'RETIRE_ACK':
            raw = r.parse_retire_attempt(request, ctx)['offer']; offer = r.parse_offer(raw, ctx)
            require(self.retirement['offers'].get((h, offer['base'], offer['target'])) == raw, 'RETIRE_UNKNOWN_OFFER')
        state = self.retirement['sender'][h]
        floor, root = r.reconcile_checkpoint(ack, request, ctx, known_floor=state['floor'], confirmed=confirmed,
                                             archived_root=self.prefix(h, ctx, checkpoint['floor']))
        state.update(floor=floor, root=root, evidence=None if floor == 0 else dict(request=request, ack=ack))
        return dict(kind='RETIRE_CONFIRMATION', at=self.state.now, route=route, request=request.hex(), response=ack.hex())

    def _query(self, command):
        h, ctx = self.context(command['route']); kind = command['query_kind']; seq = command['seq']
        q = dict(profile=r.PROFILE, context_hash=h, kind=kind, seq=seq,
                 delivery='' if kind == 'CHECKPOINT' else r.delivery_id(ctx, seq), challenge=bytes.fromhex(command['challenge']))
        r.validate_query(q, ctx); request = self._signed('sender', r.QUERY_TYPE, q, ctx)
        floor = self.retirement['receiver'][h]['floor']; high, _ = self.frontiers(h)
        denial = ('V2_RETIRED' if seq <= floor else 'V2_NO_FINAL_RECORD' if seq > high else None) if kind == 'FINAL' else ('RETENTION_NOT_RETIRED' if kind == 'RETIRED' and seq > floor else None)
        self.receiver_event(h)
        event = dict(kind='RETENTION_QUERY', at=self.state.now, route=command['route'], request=request.hex())
        if denial:
            return dict(event, reason=denial)
        if kind == 'FINAL':
            ack = self._signed('receiver', r.FINAL_TYPE, dict(profile=r.PROFILE, context_hash=h, fact=self.state.receiver[h, seq],
                               challenge=q['challenge'], request_hash=r.sha(request)), ctx)
            r.parse_final_receipt(ack, request, ctx)
        else:
            ack = self.checkpoint(request, ctx, kind); self.retention_pending[command['route']] = (request, ack)
        return dict(event, response=ack.hex())

    def _replay(self, command):
        job = self.state.by_id.get(command['operation']); require(job is not None and job.get('confirmed') is not None, 'REPLAY_UNCONFIRMED')
        request = bytes.fromhex(self.pending[command['operation']][0]); ctx = job['context']; h = r.context_hash(ctx)
        attempt = d.parse_attempt(request, ctx); self.receiver_event(h)
        event = dict(kind='DELIVERY_REPLAY', at=self.state.now, operation=job['id'], request=request.hex())
        if job['route_seq'] <= self.retirement['receiver'][h]['floor']:
            return dict(event, reason='V2_RETIRED')
        ack = self._signed('receiver', d.RECEIPT_TYPE, dict(profile=d.PROFILE, context_hash=h,
                           fact=self.state.receiver[h, job['route_seq']], challenge=attempt['challenge'], request_hash=r.sha(request)), ctx)
        d.parse_receipt(ack, request, ctx)
        return dict(event, response=ack.hex())

    def require_business_scope(self, command):
        if self.cleanup_started:
            require(command['kind'] == 'PUBLIC' and parse_request(bytes.fromhex(command['request']))['method'] in ('POLL', 'FINAL'), 'CLEANUP_ONLY_PROFILE')

    def require_cleanup_scope(self):
        require(self.state.jobs and len(self.state.final) == len(self.state.jobs), 'CLEANUP_BEFORE_FINAL_OUT_OF_SCOPE')

    def emit(self, command):
        require(type(command) is dict and type(command.get('kind')) is str, 'COMMAND_SCOPE')
        kind = command['kind']; cut = kind.endswith('_CUT'); base = kind[:-4] if cut else kind
        fields = {'RETIRE_PREPARE': {'route', 'target'}, 'RETIRE_SEND': {'route', 'base', 'target', 'challenge'},
                  'RETIRE_CONFIRM': {'route'}, 'RETENTION_QUERY': {'route', 'query_kind', 'seq', 'challenge'},
                  'DELIVERY_REPLAY': {'operation'}, 'RETIRE_RECOVER': {'route', 'side'}}
        if base not in fields:
            require(kind in ('PUBLIC', 'TICK', 'SEND', 'CONFIRM'), 'COMMAND_SCOPE')
            self.require_business_scope(command)
            return super().emit(command)
        require(not cut or base in CUTS, 'CUT_SCOPE')
        expected = {'kind', 'at'} | fields[base] | ({'cut'} if cut else {'loss'} if base == 'RETIRE_SEND' else set())
        require(set(command) == expected, 'COMMAND_SCOPE')
        m = self.state; require(type(command['at']) is int and m.now <= command['at'] < 2**62, 'PUBLIC_CLOCK')
        before = deepcopy(m.__dict__); old = deepcopy(self.retirement); pending = deepcopy(self.retention_pending)
        recovery = self.needs_recovery; started = self.cleanup_started; n = len(self.records); p = len(self.projected_records)
        try:
            m.now = command['at']
            if base == 'RETIRE_RECOVER':
                require(not cut and self.needs_recovery == (command['side'], command['route']), 'RECOVER_SCOPE')
                self.needs_recovery = None; event = dict(command)
            else:
                require(self.needs_recovery is None, 'RECOVERY_REQUIRED')
                self.require_cleanup_scope()
                self.cleanup_started = True
                if base == 'RETIRE_SEND' and not cut:
                    require(command['loss'] in ('none', 'ack'), 'LOSS_SCOPE')
                if cut:
                    require(command['cut'] in CUTS[base], 'CUT_SCOPE')
                    if command['cut'] == 'after_v2_recipient_delete':
                        h, _ = self.context(command['route'])
                        require(command['target'] > self.retirement['receiver'][h]['floor'], 'CUT_NOT_REACHED')
                logical = dict(command, kind=base)
                if cut and base == 'RETIRE_SEND': logical['loss'] = 'ack'
                event = {'RETIRE_PREPARE': self._prepare, 'RETIRE_SEND': self._send, 'RETIRE_CONFIRM': self._confirm,
                         'RETENTION_QUERY': self._query, 'DELIVERY_REPLAY': self._replay}[base](logical)
                if cut:
                    require('reason' not in event, 'CUT_NOT_REACHED')
                    if command['cut'] not in DURABLE_CUTS:
                        m.__dict__ = before; m.now = command['at']; self.retirement = old; self.retention_pending = pending
                        del self.projected_records[p:]
                    side = 'receiver' if base == 'RETIRE_SEND' else 'sender'
                    self.needs_recovery = side, command['route']
                    if base == 'RETIRE_PREPARE':
                        event = dict(kind='RETIRE_PREPARATION_UNAVAILABLE', at=m.now, route=command['route'], target=command['target'])
                    else:
                        event = {k: v for k, v in event.items() if k != 'response' or base == 'RETIRE_CONFIRM'}
                        event['kind'] = 'RETIRE_DELIVERY_UNAVAILABLE' if base == 'RETIRE_SEND' else 'RETIRE_CONFIRM_UNAVAILABLE'
            self.records.append(event)
            return deepcopy(event)
        except BaseException as exc:
            m.__dict__ = before; self.retirement = old; self.retention_pending = pending
            self.needs_recovery = recovery; self.cleanup_started = started
            del self.records[n:]; del self.projected_records[p:]
            if isinstance(exc, (Rejected, KeyError, ValueError, TypeError)): raise ViewMismatch(str(exc)) from exc
            raise
