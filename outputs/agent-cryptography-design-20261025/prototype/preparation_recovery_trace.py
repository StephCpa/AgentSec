"""Actual sender preparation exits and authority-based trace correspondence.

Reference local witnesses, at most two jobs, fixed public cut schedule. Private
tapes/results are compared as opaque stored bytes, never input to the simulator.
This does not test retirement, concurrent authority writers, TLS or power loss.
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
from unittest.mock import patch
from constructive_trace import FixtureSigningOracle
from delivery_recovery_trace import DeliveryRecoveryRuntime
from preparation_recovery_simulator import (PreparationRecoverySimulator, preparation_cuts,
                                             DURABLE_CUTS, LOCAL_CUTS)
from public_gateway import PublicGatewayLedger
from public_trace_adapter import PublicTraceAdapter
from retention_recipient import RetentionRecipient
from witnessed_ledger import ReferenceWitness, image_hash
from ledger import Rejected
from state_relation import digest
from test_encrypted_mixed_ledger import vault
from test_retention_sender import context
from wire import encode
import retention_delivery as delivery

EXIT_CODE = 96
PLANS = ('envelope_count', 'envelope_histogram', 'envelope_expire', 'envelope_retry_expire',
         'terminal_empty', 'terminal_prepared', 'terminal_existing_fact', 'terminal_retry',
         'envelope_cross_route', 'terminal_cross_route', 'envelope_withheld_tail')


def plan_kind(plan):
    if plan not in PLANS:
        raise ValueError('outside preparation profile')
    return 'TERMINAL' if plan.startswith('terminal_') else 'DELIVERY'


def child(path):
    cfg = json.loads(Path(path).read_text())
    def stop(point):
        if point == cfg['cut']:
            os._exit(EXIT_CODE)
    w = ReferenceWitness(cfg['witness'])
    obj = PublicGatewayLedger(cfg['local'], clock=lambda: cfg['at'], vault=vault(), witness=w, witness_fault=stop)
    method = obj.prepare_envelope if cfg['delivery_kind'] == 'DELIVERY' else obj.prepare_terminal
    method('t', cfg['delivery_id'], context()[1], stop)
    if cfg['cut'] == 'response_drop':
        os._exit(EXIT_CODE)
    raise RuntimeError('preparation cut was not reached')


def protected_state(obj):
    # Compare opaque ciphertext and exact account/descriptor/ticket fields.
    # Keep these bytes within the harness; only equality booleans are archived.
    out = {table: sorted((tuple(row) for row in obj.db.execute('SELECT * FROM ' + table)), key=repr)
           for table in ('operations', 'jobs', 'accounts', 'charges', 'pub_decisions')}
    out['tickets'] = [tuple(row) for row in obj.db.execute('SELECT id,operation_id,recipient,gateway,session,issued_at,expires_at,result_digest FROM deliveries ORDER BY id')]
    out['descriptors'] = [tuple(row) for row in obj.db.execute('SELECT id,descriptor FROM v2_outbox ORDER BY id')]
    return out


class PreparationRecoveryRuntime(DeliveryRecoveryRuntime):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.signer = FixtureSigningOracle()
        self.simulator = PreparationRecoverySimulator(self.cfg, {}, self.signer)
        self.protected = None

    def assert_protected(self, owner=None):
        if self.protected is not None and protected_state(owner or self.l) != self.protected:
            raise AssertionError('R13.protected_tape_result_budget_ticket')

    def _observe(self, actual):
        command = self.commands[len(self.simulator.records)]
        if command['kind'] not in ('PREPARE', 'PREPARE_CUT', 'PREPARE_RECOVER'):
            return super()._observe(actual)
        with patch('sqlite3.connect', side_effect=AssertionError('generator DB access')), \
             patch.object(PublicGatewayLedger, 'handle_public', side_effect=AssertionError('generator gateway access')), \
             patch.object(PublicGatewayLedger, 'prepare_envelope', side_effect=AssertionError('generator preparation access')), \
             patch.object(PublicGatewayLedger, 'prepare_terminal', side_effect=AssertionError('generator preparation access')), \
             patch.object(RetentionRecipient, 'accept', side_effect=AssertionError('generator recipient access')), \
             patch.object(PublicTraceAdapter, '_public', side_effect=AssertionError('generator observed response access')):
            generated = self.simulator.emit(command)
        if generated != actual:
            raise AssertionError('preparation observation differs at ' + str(len(self.records)))
        if command['kind'] == 'PREPARE_CUT':
            head = self.w.head(self.l.namespace, True)
            restored = self.new_replica('sender', command['operation'], self.directory / ('diagnostic-' + str(len(self.diagnostics))))
            try:
                if restored.state_image() != head['image'] or restored.audit() or self.w.head(self.l.namespace, True) != head:
                    raise AssertionError('R13.diagnostic_restore')
                self.assert_protected(restored)
                with patch.object(self, 'l', restored):
                    relation = self.relation()
            finally:
                restored.close()
            relation['R13'] = digest(self.diagnostics[-1])
        else:
            self.assert_protected()
            relation = self.relation()
            relation['R13'] = digest(dict(protected_preserved=True, recovered=command['kind'] == 'PREPARE_RECOVER'))
        self.checkpoints.append(dict(index=len(self.simulator.records), kind=command['kind'], relation=relation))

    def prepare_call(self, oid='a', terminal=False, cut=None):
        kind = 'TERMINAL' if terminal else 'DELIVERY'
        command = dict(kind='PREPARE_CUT' if cut else 'PREPARE', at=self.now, operation=oid, delivery_kind=kind)
        if cut:
            command['cut'] = cut
        self.commands.append(command)
        event = dict(at=self.now, operation=oid, delivery_kind=kind)
        if cut:
            self.preparation_cut(oid, kind, cut)
            event['kind'] = 'PREPARATION_UNAVAILABLE'
        else:
            try:
                method = self.l.prepare_terminal if terminal else self.l.prepare_envelope
                raw = method('t', self.decision(oid)['delivery_id'], self.s)
            except Rejected as exc:
                event.update(kind='PREPARATION_REJECTED', reason=str(exc))
            else:
                event.update(kind='PREPARATION', body=raw.hex())
        self.records.append(event)
        return event

    def preparation_cut(self, oid, kind, cut):
        obj = self.l; w = self.w; ns = obj.namespace; path = obj.path
        before = w.head(ns); other = {n: ww.head(i.namespace) for n, (i, ww) in self.receivers.items()}
        cfg = dict(cut=cut, at=self.now, delivery_kind=kind, delivery_id=self.decision(oid)['delivery_id'],
                   local=str(path), witness=str(w.path))
        obj.close()
        config = self.directory / 'prepare-cut.json'; config.write_text(json.dumps(cfg))
        proc = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--child', str(config)],
                              capture_output=True, text=True, timeout=30)
        self.l = PublicGatewayLedger(path, clock=lambda: self.now, vault=vault(), witness=w)
        if proc.returncode != EXIT_CODE:
            raise AssertionError('preparation cut not reached: ' + str(proc.returncode) + ' ' + proc.stderr[-1600:])
        head = w.head(ns, True); anchor = {k: head[k] for k in ('seq', 'digest')}
        durable = cut in DURABLE_CUTS; local_commit = cut in LOCAL_CUTS
        if anchor['seq'] != before['seq'] + int(durable) or image_hash(head['image']) != anchor['digest']:
            raise AssertionError('R13.authority')
        if not durable and anchor != before:
            raise AssertionError('R13.precommit_authority')
        local = self.l.local_anchor()
        if local != (anchor if local_commit else before) or image_hash(self.l.state_image()) != local['digest']:
            raise AssertionError('R13.local_atomicity')
        stale = local != anchor
        try:
            self.l.check_current_state()
        except Rejected as exc:
            if not stale or str(exc) != 'WITNESS_RECOVERY_REQUIRED':
                raise
        else:
            if stale:
                raise AssertionError('R13.stale_guard')
        if other != {n: ww.head(i.namespace) for n, (i, ww) in self.receivers.items()}:
            raise AssertionError('R13.receiver_changed')
        self.assert_protected()
        self.diagnostics.append(dict(cut=cut, exit_code=proc.returncode, witness_advanced=durable,
                                     local_committed=local_commit, stale_guard_blocked=stale,
                                     receiver_authorities_unchanged=True, protected_preserved=True))

    def restore_preparation(self, oid='a'):
        self.commands.append(dict(kind='PREPARE_RECOVER', at=self.now, operation=oid))
        old = self.l; head = self.w.head(old.namespace, True); self.restores += 1
        restored = self.new_replica('sender', oid, self.directory / ('restored-' + str(self.restores)))
        if restored.state_image() != head['image'] or restored.audit() or self.w.head(old.namespace, True) != head:
            restored.close(); raise AssertionError('R13.restore')
        self.assert_protected(restored)
        old.close(); self.l = restored
        self.records.append(dict(kind='PREPARE_RECOVER', at=self.now, operation=oid))


def run_preparation_recovery(plan, cut, mask=3):
    kind = plan_kind(plan)
    if cut not in preparation_cuts(kind) or type(mask) is not int or not 0 <= mask < 8:
        raise ValueError('outside preparation profile')
    cross = plan.endswith('cross_route')
    with tempfile.TemporaryDirectory() as td:
        run = PreparationRecoveryRuntime(td, mask, two_routes=cross)
        try:
            run.submit(hist=plan == 'envelope_histogram')
            if cross:
                run.submit('b', root='root2')
            if plan == 'envelope_withheld_tail':
                run.submit('b'); run.call('CONTROL', dict(kind='cancel', operation='b'))
            run.finish(); run.protected = protected_state(run.l)
            # Normal terminal preparation must fail before expiry.
            run.prepare_call(terminal=True)
            if plan in ('envelope_retry_expire', 'terminal_prepared'):
                run.prepare_call()
            if plan == 'terminal_existing_fact':
                run.send()  # ACK obtained, sender confirmation still pending.
            if kind == 'TERMINAL':
                run.now = 160
            if plan == 'terminal_retry':
                run.prepare_call(terminal=True); run.now = 170
            run.prepare_call(terminal=kind == 'TERMINAL', cut=cut)
            if plan == 'envelope_expire':
                run.now = 160  # Exact original expiry, not a renewed deadline.
            if plan == 'envelope_retry_expire':
                run.now = 170
            run.restore_preparation()
            if cross:
                run.prepare_call('b', terminal=run.now >= 160)
            run.call('POLL', dict(operation='a')); run.call('FINAL', dict(cursor=0, limit=16))
            if run.now >= 160:
                run.prepare_call()  # Existing envelope is not an expiry bypass.
            event = run.prepare_call(terminal=run.now >= 160)
            retry = run.prepare_call(terminal=run.now >= 160)
            if retry != event:
                raise AssertionError('preparation retry changed bytes')
            run.send(terminal=run.now >= 160); run.confirm()
            if cross:
                run.send('b', terminal=run.now >= 160); run.confirm('b')
            run.call('FINAL', dict(cursor=0, limit=16)); check = run.checked(); run.assert_protected()
            check['protected_preserved'] = True
            check['preparation_retries_byte_equal'] = True
            if run.now >= 160:
                check['terminal_envelope_hash'] = delivery.parse_control(bytes.fromhex(event['body']), run.context_for('a'))['envelope_hash'].hex()
            return dict(plan=plan, cut=cut, mask=mask, config_cbor_hex=encode(run.cfg).hex(), approved_outputs=run.oracle,
                        commands=run.commands, expected_records=list(run.records), checkpoints=run.checkpoints,
                        diagnostics=run.diagnostics, signing_calls=run.signer.calls, check=check)
        finally:
            run.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument('--child', type=Path); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.child:
        return child(args.child)
    if args.output is None or args.output.exists():
        parser.error('choose a new output directory')
    args.output.mkdir(parents=True)
    report = dict(profile='preparation-recovery-correspondence-v1', passed=False, cases=[], scope=__doc__,
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')})
    with lzma.open(args.output / 'cases.jsonl.xz', 'wt') as archive:
        for plan in PLANS:
            for cut in preparation_cuts(plan_kind(plan)):
                reference = None
                for mask in range(8):
                    case = run_preparation_recovery(plan, cut, mask)
                    signature = digest(dict(records=case['expected_records'], checkpoints=case['checkpoints']))
                    if reference is None:
                        reference = signature
                    if signature != reference:
                        raise AssertionError('conditioned preparation trace/relation differs')
                    report['cases'].append(dict(plan=plan, cut=cut, mask=mask, correspondence_sha256=signature,
                                                trace_sha256=digest(case['expected_records']), checkpoints=len(case['checkpoints']),
                                                diagnostics=case['diagnostics'], final=case['check']['final']))
                    archive.write(json.dumps(case, separators=(',', ':')) + '\n')
                print('PASS', plan, cut, '8 datasets', flush=True)
    count = len(report['cases'])
    report.update(passed=True, cases_count=count, process_exits=count, operational_restores=count, diagnostic_restores=count,
                  groups=count // 8, directed_neighbor_comparisons=count * 3,
                  checkpoints_count=sum(c['checkpoints'] for c in report['cases']))
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
