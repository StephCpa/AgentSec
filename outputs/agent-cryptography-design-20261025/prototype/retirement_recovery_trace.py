"""Actual offer/delete/checkpoint exits with constructive retention observations.

Restricted to one route, at most two completed operations and local witnesses.
Cleanup retains sender archives and does not constitute physical secure erasure.
"""
from copy import deepcopy
import hashlib
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from constructive_trace import FixtureSigningOracle
from delivery_recovery_trace import DeliveryRecoveryRuntime
from delivery_state_relation import assert_delivery_relation
from preparation_recovery_trace import protected_state
from retirement_recovery_simulator import RetirementRecoverySimulator, CUTS, DURABLE_CUTS, LOCAL_CUTS
from state_relation import assert_state_relation, digest
from public_gateway import PublicGatewayLedger
from public_trace_adapter import PublicTraceAdapter
from retention_recipient import RetentionRecipient
from witnessed_ledger import ReferenceWitness, image_hash
from test_encrypted_mixed_ledger import vault
from test_retention_recipient import recipient_vault
from test_retention_sender import context
from ledger import Rejected
from wire import encode, decode
import retention_wire as r

EXIT_CODE = 97
PLANS = ('offer_histogram', 'offer_retry', 'retire_partial', 'retire_duplicate', 'retire_second', 'confirm_checkpoint', 'confirm_retry')


def stage_for(plan):
    if plan not in PLANS: raise ValueError('outside retirement profile')
    return 'RETIRE_PREPARE' if plan.startswith('offer_') else 'RETIRE_SEND' if plan.startswith('retire_') else 'RETIRE_CONFIRM'


def applicable_cuts(plan):
    cuts = CUTS[stage_for(plan)]
    return tuple(c for c in cuts if c != 'after_v2_recipient_delete') if plan == 'retire_duplicate' else cuts


def child(path):
    cfg = json.loads(Path(path).read_text()); ctx = decode(bytes.fromhex(cfg['context']))
    def stop(point):
        if point == cfg['cut']: os._exit(EXIT_CODE)
    w = ReferenceWitness(cfg['witness'])
    if cfg['stage'] == 'RETIRE_SEND':
        obj = RetentionRecipient(cfg['local'], context=ctx, clock=lambda: cfg['at'], vault=recipient_vault(), witness=w, witness_fault=stop)
        obj.accept(bytes.fromhex(cfg['request']), ctx['sender_cert'], context()[2], stop)
    else:
        obj = PublicGatewayLedger(cfg['local'], clock=lambda: cfg['at'], vault=vault(), witness=w, witness_fault=stop)
        if cfg['stage'] == 'RETIRE_PREPARE': obj.prepare_retirement(r.context_hash(ctx), cfg['target'], context()[1], stop)
        else: obj.confirm_retirement(r.context_hash(ctx), bytes.fromhex(cfg['request']), bytes.fromhex(cfg['response']), stop)
    if cfg['cut'] == 'response_drop': os._exit(EXIT_CODE)
    raise RuntimeError('retirement cut was not reached')


def protected_archive(obj):
    out = protected_state(obj)
    out['outbox_archive'] = [tuple(row) for row in obj.db.execute('SELECT * FROM v2_outbox ORDER BY id')]
    out['final_events'] = [tuple(row) for row in obj.db.execute('SELECT * FROM final_events ORDER BY seq')]
    return out


class RetirementRecoveryRuntime(DeliveryRecoveryRuntime):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.signer = FixtureSigningOracle(); self.simulator = RetirementRecoverySimulator(self.cfg, {}, self.signer)
        self.checkpoints[0]['relation'] = self.relation()
        self.offers = {}; self.retention_receipts = {}; self.protected = None; self.cut_owner = None

    def relation(self):
        sim = self.simulator; projection = SimpleNamespace(state=sim.state, records=sim.projected_records)
        return dict(**assert_state_relation(self, sim.state), **assert_delivery_relation(self, projection,
                    initialized_contexts=sim.initialized_contexts, retirement=getattr(sim, 'retirement', None)))

    def assert_protected(self):
        if self.protected is not None and protected_archive(self.l) != self.protected:
            raise AssertionError('R14.sender_archive_budget_or_final_changed')

    def owner_ret(self, side, route):
        ctx = self.cfg['roots'][route]['context']
        if side == 'sender': return self.l, self.w, ctx
        obj, w = self.receivers[ctx['recipient']]; return obj, w, ctx

    def new_ret_replica(self, side, route, path):
        _, w, ctx = self.owner_ret(side, route)
        if side == 'sender': return PublicGatewayLedger.restore_new(path, clock=lambda: self.now, vault=vault(), witness=w)
        return RetentionRecipient.restore_new(path, context=ctx, clock=lambda: self.now, vault=recipient_vault(), witness=w)

    def replace(self, side, route, obj):
        if side == 'sender': self.l = obj
        else:
            _, w, ctx = self.owner_ret(side, route); self.receivers[ctx['recipient']] = obj, w

    def heads(self):
        return dict(sender=self.w.head(self.l.namespace), **{n: w.head(obj.namespace) for n, (obj, w) in self.receivers.items()})

    def _observe(self, actual):
        command = self.commands[len(self.simulator.records)]
        if command['kind'] in ('PUBLIC', 'TICK', 'SEND', 'CONFIRM'):
            return super()._observe(actual)
        with patch('sqlite3.connect', side_effect=AssertionError('generator DB access')), \
             patch.object(PublicGatewayLedger, 'prepare_retirement', side_effect=AssertionError('generator runtime offer')), \
             patch.object(PublicGatewayLedger, 'confirm_retirement', side_effect=AssertionError('generator runtime confirm')), \
             patch.object(RetentionRecipient, 'accept', side_effect=AssertionError('generator recipient access')), \
             patch.object(PublicTraceAdapter, '_public', side_effect=AssertionError('generator observed response')):
            generated = self.simulator.emit(command)
        if generated != actual: raise AssertionError('retirement observation differs at ' + str(len(self.records)))
        if command['kind'].endswith('_CUT'):
            side, route = self.cut_owner; old, w, ctx = self.owner_ret(side, route); head = w.head(old.namespace, True)
            restored = self.new_ret_replica(side, route, self.directory / ('diagnostic-' + str(len(self.diagnostics))))
            try:
                if restored.state_image() != head['image'] or restored.audit() or w.head(old.namespace, True) != head:
                    raise AssertionError('R14.diagnostic_restore')
                self.replace(side, route, restored)
                try: self.assert_protected(); relation = self.relation()
                finally: self.replace(side, route, old)
            finally: restored.close()
            relation['R14'] = digest(self.diagnostics[-1])
        else:
            self.assert_protected(); relation = self.relation()
            relation['R14'] = digest(dict(protected_archive=True, recovered=command['kind'] == 'RETIRE_RECOVER'))
        self.checkpoints.append(dict(index=len(self.simulator.records), kind=command['kind'], relation=relation))

    def crash(self, stage, route, cut, **inputs):
        side = 'receiver' if stage == 'RETIRE_SEND' else 'sender'
        old, w, ctx = self.owner_ret(side, route); path = old.path; ns = old.namespace
        before = w.head(ns); other = self.heads(); key = ctx['recipient'] if side == 'receiver' else 'sender'; del other[key]
        cfg = dict(stage=stage, cut=cut, at=self.now, local=str(path), witness=str(w.path), context=encode(ctx).hex(), **inputs)
        old.close(); config = self.directory / 'retire-cut.json'; config.write_text(json.dumps(cfg))
        proc = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--child', str(config)], capture_output=True, text=True, timeout=30)
        reopened = (PublicGatewayLedger(path, clock=lambda: self.now, vault=vault(), witness=w) if side == 'sender' else
                    RetentionRecipient(path, context=ctx, clock=lambda: self.now, vault=recipient_vault(), witness=w))
        self.replace(side, route, reopened)
        if proc.returncode != EXIT_CODE: raise AssertionError('retirement cut not reached: ' + str(proc.returncode) + ' ' + proc.stderr[-1600:])
        head = w.head(ns, True); anchor = {k: head[k] for k in ('seq', 'digest')}; local = reopened.local_anchor()
        durable = cut in DURABLE_CUTS; committed = cut in LOCAL_CUTS
        if anchor['seq'] != before['seq'] + int(durable) or image_hash(head['image']) != anchor['digest']: raise AssertionError('R14.authority')
        if not durable and anchor != before: raise AssertionError('R14.precommit_authority')
        if local != (anchor if committed else before) or image_hash(reopened.state_image()) != local['digest']: raise AssertionError('R14.local_atomicity')
        stale = local != anchor
        try: reopened.check_current_state()
        except Rejected as exc:
            if not stale or str(exc) != 'WITNESS_RECOVERY_REQUIRED': raise
        else:
            if stale: raise AssertionError('R14.stale_guard')
        after = self.heads(); del after[key]
        if other != after: raise AssertionError('R14.other_authority_changed')
        self.assert_protected()
        self.diagnostics.append(dict(stage=stage, cut=cut, exit_code=proc.returncode, witness_advanced=durable,
                                     local_committed=committed, stale_guard_blocked=stale, other_authorities_unchanged=True,
                                     protected_archive=True))
        self.cut_owner = side, route

    def restore_retirement(self, route='root'):
        side, expected = self.cut_owner
        if route != expected: raise AssertionError('restore wrong route')
        self.commands.append(dict(kind='RETIRE_RECOVER', at=self.now, route=route, side=side))
        old, w, _ = self.owner_ret(side, route); head = w.head(old.namespace, True); self.restores += 1
        restored = self.new_ret_replica(side, route, self.directory / ('restored-' + str(self.restores)))
        if restored.state_image() != head['image'] or restored.audit() or w.head(old.namespace, True) != head:
            restored.close(); raise AssertionError('R14.restore')
        old.close(); self.replace(side, route, restored)
        self.records.append(dict(kind='RETIRE_RECOVER', at=self.now, route=route, side=side)); self.cut_owner = None

    def prepare_retirement(self, target, route='root', cut=None):
        self.commands.append(dict(kind='RETIRE_PREPARE_CUT' if cut else 'RETIRE_PREPARE', at=self.now, route=route, target=target, **({'cut': cut} if cut else {})))
        event = dict(at=self.now, route=route, target=target); ctx = self.cfg['roots'][route]['context']
        if cut:
            self.crash('RETIRE_PREPARE', route, cut, target=target); event['kind'] = 'RETIRE_PREPARATION_UNAVAILABLE'
        else:
            try: raw = self.l.prepare_retirement(r.context_hash(ctx), target, self.s)
            except Rejected as exc: event.update(kind='RETIRE_PREPARATION_REJECTED', reason=str(exc))
            else:
                offer = r.parse_offer(raw, ctx); self.offers[route, offer['base'], offer['target']] = raw
                event.update(kind='RETIRE_PREPARATION', body=raw.hex())
        self.records.append(event); return event

    def send_retirement(self, base, target, route='root', cut=None, loss='none'):
        challenge = (len(self.records) + 1).to_bytes(32, 'big'); ctx = self.cfg['roots'][route]['context']
        command = dict(kind='RETIRE_SEND_CUT' if cut else 'RETIRE_SEND', at=self.now, route=route, base=base, target=target,
                       challenge=challenge.hex(), **({'cut': cut} if cut else {'loss': loss}))
        self.commands.append(command); request = r.retire_attempt(self.offers[route, base, target], challenge, ctx, self.s)
        event = dict(at=self.now, route=route, request=request.hex())
        if cut:
            self.crash('RETIRE_SEND', route, cut, request=request.hex()); event['kind'] = 'RETIRE_DELIVERY_UNAVAILABLE'
        else:
            ack = self.receivers[ctx['recipient']][0].accept(request, ctx['sender_cert'], self.k)
            if loss == 'none': self.retention_receipts[route] = request, ack
            event.update(kind='RETIRE_DELIVERY', response='ACK_LOST' if loss == 'ack' else ack.hex())
        self.records.append(event); return event

    def confirm_retirement(self, route='root', cut=None):
        self.commands.append(dict(kind='RETIRE_CONFIRM_CUT' if cut else 'RETIRE_CONFIRM', at=self.now, route=route, **({'cut': cut} if cut else {})))
        request, ack = self.retention_receipts[route]; ctx = self.cfg['roots'][route]['context']
        event = dict(at=self.now, route=route, request=request.hex(), response=ack.hex())
        if cut:
            self.crash('RETIRE_CONFIRM', route, cut, request=request.hex(), response=ack.hex()); event['kind'] = 'RETIRE_CONFIRM_UNAVAILABLE'
        else:
            self.l.confirm_retirement(r.context_hash(ctx), request, ack); event['kind'] = 'RETIRE_CONFIRMATION'
        self.records.append(event)

    def query_retention(self, kind, seq, route='root'):
        ctx = self.cfg['roots'][route]['context']; challenge = (len(self.records) + 1).to_bytes(32, 'big')
        self.commands.append(dict(kind='RETENTION_QUERY', at=self.now, route=route, query_kind=kind, seq=seq, challenge=challenge.hex()))
        request = r.query(ctx, kind, seq, challenge, self.s)
        event = dict(kind='RETENTION_QUERY', at=self.now, route=route, request=request.hex())
        try: ack = self.receivers[ctx['recipient']][0].accept(request, ctx['sender_cert'], self.k)
        except Rejected as exc: event['reason'] = str(exc)
        else:
            event['response'] = ack.hex()
            if kind != 'FINAL': self.retention_receipts[route] = request, ack
        self.records.append(event); return event

    def replay_delivery(self, oid='a'):
        self.commands.append(dict(kind='DELIVERY_REPLAY', at=self.now, operation=oid))
        request, _ = self.receipts[oid]; ctx = self.context_for(oid)
        event = dict(kind='DELIVERY_REPLAY', at=self.now, operation=oid, request=request.hex())
        try: ack = self.receivers[ctx['recipient']][0].accept(request, ctx['sender_cert'], self.k)
        except Rejected as exc: event['reason'] = str(exc)
        else: event['response'] = ack.hex()
        self.records.append(event); return event


def run_retirement_recovery(plan, cut, mask=3):
    if cut not in applicable_cuts(plan) or type(mask) is not int or not 0 <= mask < 8: raise ValueError('outside retirement profile')
    two = plan in ('retire_partial', 'retire_duplicate', 'retire_second', 'confirm_checkpoint')
    with tempfile.TemporaryDirectory() as td:
        run = RetirementRecoveryRuntime(td, mask)
        try:
            run.submit(hist=plan == 'offer_histogram')
            if two: run.submit('b')
            run.finish(); run.send(); run.confirm()
            if two:
                run.now = 170; run.send('b', terminal=True); run.confirm('b')
            run.protected = protected_archive(run.l); run.now = 180
            run.prepare_retirement(3)  # Target beyond the durable sender prefix.
            run.query_retention('FINAL', 1); run.query_retention('RETIRED', 1)
            target = 2 if plan in ('retire_second', 'confirm_checkpoint') else 1; base = 0
            if plan == 'retire_second':
                run.prepare_retirement(1); run.send_retirement(0, 1); run.confirm_retirement(); base = 1
            if plan in ('offer_retry', 'retire_partial', 'retire_duplicate', 'retire_second', 'confirm_checkpoint', 'confirm_retry'):
                run.prepare_retirement(target)
            if plan in ('retire_duplicate', 'confirm_checkpoint', 'confirm_retry'):
                run.send_retirement(base, target, loss='ack' if plan == 'confirm_checkpoint' else 'none')
            if plan == 'confirm_checkpoint': run.query_retention('CHECKPOINT', 0)
            if plan == 'confirm_retry': run.confirm_retirement()
            stage = stage_for(plan)
            if stage == 'RETIRE_PREPARE': run.prepare_retirement(target, cut=cut)
            elif stage == 'RETIRE_SEND': run.send_retirement(base, target, cut=cut)
            else: run.confirm_retirement(cut=cut)
            run.now = 190; run.restore_retirement()
            # Probe the recovered window before completing a precommit retry.
            run.query_retention('FINAL', target)
            if plan != 'confirm_retry': run.query_retention('CHECKPOINT', 0)
            run.call('FINAL', dict(cursor=0, limit=16))
            if stage == 'RETIRE_PREPARE': run.prepare_retirement(target)
            if stage != 'RETIRE_CONFIRM': run.send_retirement(base, target)
            # confirm_checkpoint uses a fresh current-floor receipt;
            # confirm_retry retains the exact pre-cut request and receipt.
            run.confirm_retirement()
            if plan == 'retire_second': run.send_retirement(0, 1); run.confirm_retirement()
            run.now = 200
            run.query_retention('FINAL', 1); run.query_retention('RETIRED', 1); run.replay_delivery()
            if two: run.query_retention('FINAL', 2)
            run.call('FINAL', dict(cursor=0, limit=16)); run.call('POLL', dict(operation='a'))
            check = run.checked(); run.assert_protected()
            h = r.context_hash(run.cfg['roots']['root']['context']); state = run.simulator.retirement
            check.update(sender_floor=state['sender'][h]['floor'], receiver_floor=state['receiver'][h]['floor'],
                         receiver_live=sorted(seq for hh, seq in run.simulator.state.receiver if hh == h and seq > state['receiver'][h]['floor']),
                         sender_archive_preserved=True, sender_archive_rows=run.l.db.execute('SELECT count(*) FROM v2_outbox').fetchone()[0])
            return dict(plan=plan, cut=cut, mask=mask, config_cbor_hex=encode(run.cfg).hex(), approved_outputs=run.oracle,
                        commands=run.commands, expected_records=list(run.records), checkpoints=run.checkpoints, diagnostics=run.diagnostics,
                        signing_calls=run.signer.calls, check=check)
        finally: run.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument('--child', type=Path); parser.add_argument('--output', type=Path); args = parser.parse_args()
    if args.child: return child(args.child)
    if args.output is None or args.output.exists(): parser.error('choose a new output directory')
    args.output.mkdir(parents=True)
    report = dict(profile='retirement-recovery-correspondence-v1', passed=False, cases=[], scope=__doc__,
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')})
    with lzma.open(args.output / 'cases.jsonl.xz', 'wt') as archive:
        for plan in PLANS:
            for cut in applicable_cuts(plan):
                reference = None
                for mask in range(8):
                    case = run_retirement_recovery(plan, cut, mask); signature = digest(dict(records=case['expected_records'], checkpoints=case['checkpoints']))
                    if reference is None: reference = signature
                    if signature != reference: raise AssertionError('conditioned retirement correspondence differs')
                    report['cases'].append(dict(plan=plan, cut=cut, mask=mask, correspondence_sha256=signature,
                                                trace_sha256=digest(case['expected_records']), checkpoints=len(case['checkpoints']), diagnostics=case['diagnostics'], check=case['check']))
                    archive.write(json.dumps(case, separators=(',', ':')) + '\n')
                print('PASS', plan, cut, '8 datasets', flush=True)
    count = len(report['cases']); report.update(passed=True, cases_count=count, process_exits=count, diagnostic_restores=count,
        operational_restores=count, groups=count // 8, directed_neighbor_comparisons=count * 3, checkpoints_count=sum(c['checkpoints'] for c in report['cases']))
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__': main()
