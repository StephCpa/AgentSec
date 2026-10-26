"""Run R1--R8 boundary checks, including visible receipts held unconfirmed."""
import hashlib
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

from delivery_state_relation import assert_delivery_relation
from ledger import Rejected
from restricted_trace import PLANS, run_plan
from retention_recipient import RetentionRecipient
from state_relation import digest
from stepwise_trace import StepwiseRuntime
from test_retention_recipient import recipient_vault
from witnessed_ledger import ReferenceWitness

DEFERRED_PLANS = ('receipt_wait', 'cross_route_receipt_wait', 'receipt_then_terminal', 'withheld_behind_unconfirmed')


class DeliveryRelationRuntime(StepwiseRuntime):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.deferred = {}
        self.checkpoints[0]['relation'].update(assert_delivery_relation(self, self.simulator))

    def _observe(self, actual):
        super()._observe(actual)
        self.checkpoints[-1]['relation'].update(assert_delivery_relation(self, self.simulator))

    def send_unconfirmed(self, oid='a'):
        self.commands.append(dict(kind='SEND', at=self.now, operation=oid, delivery_kind='DELIVERY',
                                  challenge=(len(self.records) + 1).to_bytes(32, 'big').hex(), loss='none'))
        request, context, decision = self.prepare(oid)
        recipient = context['recipient']
        if recipient not in self.receivers:
            witness = ReferenceWitness(self.directory / (recipient + '-w'))
            inbox = RetentionRecipient.create(self.directory / (recipient + '-db'), context=context,
                vault=recipient_vault(), clock=lambda: self.now, witness=witness)
            self.receivers[recipient] = inbox, witness
        ack = self.receivers[recipient][0].accept(request, context['sender_cert'], self.k)
        self.records.append(dict(kind='DELIVERY', at=self.now, request=request.hex(), response=ack.hex()))
        self.deferred[oid] = decision['delivery_id'], request, ack

    def confirm_deferred(self, oid='a'):
        did, request, ack = self.deferred[oid]
        if self.simulator.pending.get(oid) != (request.hex(), ack.hex()):
            raise ValueError('This profile confirms only the latest generated receipt')
        self.commands.append(dict(kind='CONFIRM', at=self.now, operation=oid))
        self.l.confirm('t', did, request, ack)
        self.records.append(dict(kind='CONFIRM', at=self.now, request=request.hex(), response=ack.hex()))
        del self.deferred[oid]


def run_delivery_relation(plan, mask=3, target=1):
    if type(target) is not int or not 0 <= target <= 3 or type(mask) is not int or not 0 <= mask < 8:
        raise ValueError('outside fixture scope')
    if plan in PLANS:
        instances = []
        def create(*args, **kwargs):
            runtime = DeliveryRelationRuntime(*args, target=target, **kwargs)
            instances.append(runtime)
            return runtime
        with patch('restricted_trace.Runtime', side_effect=create):
            result = run_plan(plan, mask)
        result.update(checkpoints=instances[0].checkpoints, target=target)
        return result
    if plan not in DEFERRED_PLANS:
        raise ValueError('unknown plan')
    cross = plan == 'cross_route_receipt_wait'
    with tempfile.TemporaryDirectory() as directory:
        runtime = DeliveryRelationRuntime(directory, mask, cross, target=target)
        try:
            runtime.submit(hist=cross)
            if cross:
                runtime.submit('b', root='root2')
            elif plan == 'withheld_behind_unconfirmed':
                runtime.submit('b')
                runtime.call('CONTROL', dict(kind='cancel', operation='b'))
            runtime.finish()
            runtime.send_unconfirmed()
            poll = runtime.call('POLL', dict(operation='a'))['body']
            page = runtime.call('FINAL', dict(cursor=0, limit=16))['body']
            if poll['final'] != 'UNFINALIZED' or page != dict(events=[], cursor=0):
                raise AssertionError('Visible receipt incorrectly advanced final prefix')
            if cross:
                try:
                    runtime.prepare('b')
                except Rejected as exc:
                    if str(exc) != 'DOMAIN_FINAL_ORDER':
                        raise
                else:
                    raise AssertionError('Unconfirmed receipt unlocked the other route')
            if plan == 'receipt_then_terminal':
                runtime.now = 170
                runtime.deliver(terminal=True)
            else:
                runtime.advance()  # A public idle slot cannot imply confirmation.
                runtime.confirm_deferred()
            if cross:
                runtime.deliver('b')
            runtime.call('FINAL', dict(cursor=0, limit=1))
            if cross or plan == 'withheld_behind_unconfirmed':
                runtime.call('FINAL', dict(cursor=1, limit=1))
            result = dict(plan=plan, target=target, mask=mask, records=runtime.records,
                          checkpoints=runtime.checkpoints, check=runtime.checked())
            return result
        finally:
            runtime.close()


def main():
    import argparse
    import gzip
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output exists')
    args.output.mkdir(parents=True)
    groups = [(plan, 1) for plan in PLANS] + [(plan, target) for target in (0, 2, 3) for plan in ('normal', 'adaptive')]
    groups += [(plan, 1) for plan in DEFERRED_PLANS]
    report = dict(profile='restricted-delivery-state-relation-v1', passed=False,
        source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},
        scope='Selected R1-R8 projections at completed events; no retirement/crash/recovery or universal induction.', cases=[])
    archives = []
    for plan, target in groups:
        reference = None
        for mask in range(8):
            result = run_delivery_relation(plan, mask, target)
            wire = json.dumps(result['records'], sort_keys=True, separators=(',', ':')).encode()
            signature = (hashlib.sha256(wire).hexdigest(), digest(result['checkpoints']))
            if reference is not None and signature != reference:
                raise AssertionError('Conditioned trace or projection differs')
            reference = signature
            report['cases'].append(dict(plan=plan, target=target, mask=mask, records=len(result['records']),
                checkpoints=len(result['checkpoints']), trace_sha256=signature[0], checkpoint_sha256=signature[1], final=result['check']['final']))
            archives.append(dict(plan=plan, target=target, mask=mask, records=result['records'], checkpoints=result['checkpoints']))
        print('PASS', plan, 'target', target, '8 inputs', flush=True)
    report.update(passed=True, cases_count=len(report['cases']), checkpoint_count=sum(c['checkpoints'] for c in report['cases']),
                  directed_neighbor_comparisons=24 * len(groups))
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    with (args.output / 'traces-and-checkpoints.json.gz').open('wb') as stream:
        with gzip.GzipFile(fileobj=stream, mode='wb', mtime=0) as compressed:
            compressed.write(json.dumps(archives, separators=(',', ':')).encode())


if __name__ == '__main__':
    main()
