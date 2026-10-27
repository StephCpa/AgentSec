"""Run successive phase faults on one real two-route lifecycle and one model.

Local reference authorities, one pending failure, serial business during healthy
periods. No concurrency, component-local progress while pending, or DP proof.
"""
from copy import deepcopy
import hashlib
import json
import lzma
from pathlib import Path
import tempfile
from unittest.mock import patch

from constructive_trace import FixtureSigningOracle
from retirement_recovery_trace import RetirementRecoveryRuntime
from preparation_recovery_trace import PreparationRecoveryRuntime, protected_state
from delivery_recovery_trace import DeliveryRecoveryRuntime
from recovery_interruption_trace import RecoveryInterruptionMixin
from unified_lifecycle_simulator import UnifiedLifecycleSimulator
from public_gateway import PublicGatewayLedger, parse_request
from mixed_delegated_ledger import parse_mixed_action
from public_trace_adapter import PublicTraceAdapter
from retention_recipient import RetentionRecipient
from state_relation import digest
from observation_events import EventStream, caller_view
from wire import encode

CUTS = ('before_witness_accept', 'after_witness_accept')
SCHEDULES = CUTS + ('alternating_pre', 'alternating_post')
ORDERS = ('cleanup_before_b', 'cleanup_after_b')


class UnifiedLifecycleRuntime(RetirementRecoveryRuntime):
    prepare_call = PreparationRecoveryRuntime.prepare_call
    preparation_cut = PreparationRecoveryRuntime.preparation_cut
    restore_preparation = PreparationRecoveryRuntime.restore_preparation
    recovery_owner = RecoveryInterruptionMixin.recovery_owner
    set_owner = RecoveryInterruptionMixin.set_owner
    open_owner = RecoveryInterruptionMixin.open_owner
    authority_heads = RecoveryInterruptionMixin.authority_heads
    recover_cut = RecoveryInterruptionMixin.recover_cut

    def __init__(self, *args, **kwargs):
        super().__init__(*args, two_routes=True, **kwargs)
        self.signer = FixtureSigningOracle()
        self.simulator = UnifiedLifecycleSimulator(self.cfg, {}, self.signer)
        self.checkpoints[0]['relation'] = self.relation()
        self.actual_events = EventStream(); self.canonical = []
        self.recovery_diagnostics = []; self.replica_mode = 'existing'

    def context_for(self, target):
        if target in self.cfg['roots']: return self.cfg['roots'][target]['context']
        return super().context_for(target)

    def assert_protected(self, owner=None):
        if self.protected is not None and protected_state(owner or self.l) != self.protected:
            raise AssertionError('unified protected computation/budget changed')

    def _observe(self, actual):
        command = self.commands[len(self.simulator.records)]
        if command['kind'] == 'PUBLIC':
            req = parse_request(bytes.fromhex(command['request']))
            if req['method'] == 'SUBMIT':
                action = parse_mixed_action(req['payload']['action'])
                width = action['bucket_count'] if action['operation_kind'] == 'histogram' else 1
                self.simulator.state.oracle.setdefault(action['operation'], (self.target,) + (0,) * (width - 1))
        with patch('sqlite3.connect', side_effect=AssertionError('model DB access')), \
             patch.object(PublicGatewayLedger, 'handle_public', side_effect=AssertionError('model runtime access')), \
             patch.object(PublicGatewayLedger, 'prepare_envelope', side_effect=AssertionError('model runtime preparation')), \
             patch.object(PublicGatewayLedger, 'prepare_retirement', side_effect=AssertionError('model runtime retirement')), \
             patch.object(RetentionRecipient, 'accept', side_effect=AssertionError('model receiver access')), \
             patch.object(PublicTraceAdapter, '_public', side_effect=AssertionError('model observed reply access')):
            generated = self.simulator.emit(command)
        if actual != generated: raise AssertionError('unified observation mismatch')
        self.canonical.append(self.actual_events.append(command, actual))
        pending = self.simulator.obligation
        if pending is not None:
            side, target = pending['side'], pending['target']
            old, w, _ = self.recovery_owner(side, target); heads = self.authority_heads()
            restored = self.open_owner(side, target, self.directory/('unified-diagnostic-' + str(len(self.simulator.records))), restore=True)
            try:
                if restored.state_image() != w.head(old.namespace, True)['image'] or restored.audit():
                    raise AssertionError('unified authority projection')
                self.set_owner(side, target, restored)
                try:
                    self.assert_protected(); relation = self.relation()
                finally: self.set_owner(side, target, old)
                if self.authority_heads() != heads: raise AssertionError('diagnostic changed authority')
            finally: restored.close()
        else:
            self.assert_protected(); relation = self.relation()
        relation['unified_obligation'] = digest(pending)
        self.checkpoints.append(dict(index=len(self.simulator.records), kind=command['kind'], relation=relation))

    def interrupt_recovery(self):
        pending = self.simulator.obligation
        for cut in ('before_recovery_commit', 'after_recovery_commit'):
            self.recover_cut(pending['side'], pending['target'], cut)


def run_unified(cut='after_witness_accept', order='cleanup_before_b', hist=False, mask=3):
    if cut not in SCHEDULES or order not in ORDERS or type(hist) is not bool or type(mask) is not int or not 0 <= mask < 8:
        raise ValueError('outside unified lifecycle experiment')
    fault_index = 0
    def next_cut():
        nonlocal fault_index
        result = cut if cut in CUTS else CUTS[(fault_index + int(cut == 'alternating_post')) % 2]
        fault_index += 1
        return result
    with tempfile.TemporaryDirectory() as td:
        run = UnifiedLifecycleRuntime(td, mask)
        try:
            run.submit('a'); run.submit('b', hist=hist, root='root2'); run.finish()
            run.protected = protected_state(run.l)
            # Preparation fault, interrupted restore, then exact body retry.
            run.prepare_call('a', cut=next_cut()); run.interrupt_recovery(); run.restore_preparation('a')
            first = run.prepare_call('a'); retry = run.prepare_call('a')
            if first != retry: raise AssertionError('prepared bytes changed')
            run.send('a', cut=next_cut()); run.interrupt_recovery(); run.restore('receiver', 'a'); run.send('a')
            run.confirm('a', cut=next_cut()); run.interrupt_recovery(); run.restore('sender', 'a'); run.confirm('a')

            def clean_a():
                run.prepare_retirement(1, cut=next_cut()); run.interrupt_recovery(); run.restore_retirement()
                run.prepare_retirement(1)
                run.send_retirement(0, 1, cut=next_cut()); run.interrupt_recovery(); run.restore_retirement()
                run.query_retention('CHECKPOINT', 0)
                # A precommit delete still needs the original signed offer.
                run.send_retirement(0, 1)
                run.confirm_retirement(cut=next_cut()); run.interrupt_recovery(); run.restore_retirement()
                run.confirm_retirement(); run.query_retention('FINAL', 1)

            if order == 'cleanup_before_b': clean_a()
            run.prepare_call('b', cut=next_cut()); run.interrupt_recovery(); run.restore_preparation('b')
            run.prepare_call('b'); run.send('b'); run.confirm('b')
            if order == 'cleanup_after_b': clean_a()
            run.call('POLL', dict(operation='b')); run.call('FINAL', dict(cursor=0, limit=16))
            check = run.checked(); run.assert_protected()
            if len(run.diagnostics) != 7 or len(run.recovery_diagnostics) != 14 or run.simulator.obligation is not None:
                raise AssertionError('incomplete fault schedule')
            return dict(cut=cut, order=order, histogram=hist, mask=mask, config_cbor_hex=encode(run.cfg).hex(),
                approved_outputs=run.oracle, commands=run.commands, expected_records=list(run.records),
                checkpoints=run.checkpoints, diagnostics=run.diagnostics, recovery_diagnostics=run.recovery_diagnostics,
                signing_calls=run.signer.calls, check=check, canonical_sha256=digest(run.canonical),
                caller_view_sha256=digest([caller_view(x) for x in run.canonical]))
        finally: run.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): parser.error('choose a new evidence directory')
    args.output.mkdir(parents=True)
    report = dict(passed=False, profile='unified-lifecycle-transitions-v1', cases=[],
        source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')})
    neighbors = 0
    with lzma.open(args.output/'cases.jsonl.xz', 'wt') as stream:
        for cut in SCHEDULES:
            for order in ORDERS:
                for hist in (False, True):
                    signatures = {}
                    for mask in range(8):
                        case = run_unified(cut, order, hist, mask)
                        stream.write(json.dumps(case, separators=(',', ':')) + '\n')
                        signature = digest(dict(records=case['expected_records'], checkpoints=case['checkpoints']))
                        signatures[mask] = signature
                        report['cases'].append(dict(cut=cut, order=order, histogram=hist, mask=mask,
                            correspondence_sha256=signature, canonical_sha256=case['canonical_sha256'], events=len(case['commands']), exits=21))
                    for mask in range(8):
                        for bit in range(3):
                            if signatures[mask] != signatures[mask ^ (1 << bit)]: raise AssertionError('conditional neighbor differs')
                            neighbors += 1
                    print('PASS', cut, order, hist, flush=True)
    report.update(passed=True, cases_count=len(report['cases']), actual_exits=21*len(report['cases']), directed_neighbors=neighbors)
    (args.output/'summary.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__': main()
