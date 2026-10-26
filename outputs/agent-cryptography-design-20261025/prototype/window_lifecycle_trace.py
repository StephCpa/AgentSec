"""Compose a one-slot window, new business and six actual recovery exits.

One route, two operations and a fixed public schedule. Opaque archive equality
is checked by the harness only; it never becomes input to the public generator.
"""
import hashlib
import json
import lzma
from pathlib import Path
import tempfile
from unittest.mock import patch
from constructive_trace import FixtureSigningOracle
from retirement_recovery_trace import RetirementRecoveryRuntime
from recovery_interruption_trace import RecoveryInterruptionMixin
from window_lifecycle_simulator import WindowLifecycleSimulator
from test_retention_sender import context
from state_relation import digest
from ledger import Rejected
from wire import encode
import retention_wire as r

PLANS = ('after_retire_count', 'after_retire_histogram', 'after_retire_cancel',
         'queued_count', 'queued_histogram', 'queued_expire')
CUTS = ('after_v2_recipient_delete', 'after_witness_accept', 'after_v2_recipient_retire_commit')
MODES = ('existing', 'fresh')


def window_context():
    ctx, sender, receiver = context()
    return dict(ctx, window=1), sender, receiver


class WindowLifecycleRuntime(RetirementRecoveryRuntime):
    def __init__(self, *args, **kwargs):
        self.frozen_operations = {}; self.frozen_confirmed = {}; self.frozen_final = {}
        with patch('restricted_trace.context', window_context), patch('test_atomic_publication.context', window_context):
            super().__init__(*args, **kwargs)
        self.signer = FixtureSigningOracle(); self.simulator = WindowLifecycleSimulator(self.cfg, {}, self.signer)
        self.checkpoints[0]['relation'] = self.relation()

    def operation_snapshot(self, oid):
        result = {}
        for table, column in (('operations', 'id'), ('jobs', 'operation_id'), ('charges', 'operation_id'), ('pub_decisions', 'operation_id')):
            result[table] = sorted((tuple(row) for row in self.l.db.execute(
                'SELECT * FROM ' + table + ' WHERE tenant=? AND ' + column + '=?', ('t', oid))), key=repr)
        result['tickets'] = [tuple(row) for row in self.l.db.execute(
            'SELECT id,operation_id,recipient,gateway,session,issued_at,expires_at,result_digest FROM deliveries WHERE tenant=? AND operation_id=? ORDER BY id', ('t', oid))]
        return result

    def confirmed_snapshot(self, oid):
        did = self.decision(oid)['delivery_id']
        return [tuple(row) for row in self.l.db.execute('SELECT * FROM v2_outbox WHERE tenant=? AND id=?', ('t', did))]

    def assert_protected(self):
        # Shared accounts may legitimately change for B. R2 checks their exact
        # model budget; the completed A rows and original ciphertext stay fixed.
        for oid, expected in self.frozen_operations.items():
            if self.operation_snapshot(oid) != expected: raise AssertionError('R15.completed_operation_changed')
        for oid, expected in self.frozen_confirmed.items():
            if self.confirmed_snapshot(oid) != expected: raise AssertionError('R15.confirmed_archive_changed')
        rows = {row['seq']: tuple(row) for row in self.l.db.execute('SELECT * FROM final_events')}
        if any(rows.get(seq) != value for seq, value in self.frozen_final.items()): raise AssertionError('R15.final_prefix_changed')

    def relation(self):
        relation = super().relation()
        self.assert_protected()
        for job in self.simulator.state.jobs:
            if job['publication'] is not None:
                self.frozen_operations.setdefault(job['id'], self.operation_snapshot(job['id']))
            if job.get('confirmed') is not None:
                self.frozen_confirmed.setdefault(job['id'], self.confirmed_snapshot(job['id']))
        for row in self.l.db.execute('SELECT * FROM final_events'):
            self.frozen_final.setdefault(row['seq'], tuple(row))
        windows = []
        for root in self.cfg['roots'].values():
            ctx = root['context']; h = r.context_hash(ctx)
            high = max((seq for hh, seq in self.simulator.state.receiver if hh == h), default=0)
            retirement = getattr(self.simulator, 'retirement', None)
            floor = retirement['receiver'][h]['floor'] if retirement else 0
            obj, _ = self.receivers[ctx['recipient']]
            meta = obj.db.execute('SELECT high,floor FROM v2_recipient_meta').fetchone()
            actual = tuple(int.from_bytes(x, 'big') for x in meta)
            live = obj.db.execute('SELECT count(*) FROM v2_recipient_live').fetchone()[0]
            if actual != (high, floor) or live != high - floor or not 0 <= live <= ctx['window']:
                raise AssertionError('R15.window_capacity')
            windows.append(dict(high=high, floor=floor, live=live, capacity=ctx['window']))
        # Do not archive hashes of private ciphertext, seeds or unreleased data.
        relation['R15'] = digest(dict(windows=windows, frozen_operations=sorted(self.frozen_operations),
                                     frozen_confirmed=sorted(self.frozen_confirmed), frozen_final=sorted(self.frozen_final),
                                     opaque_equality=True))
        return relation

    def send(self, oid='a', terminal=False):
        self.commands.append(dict(kind='SEND', at=self.now, operation=oid,
            delivery_kind='TERMINAL' if terminal else 'DELIVERY',
            challenge=(len(self.records) + 1).to_bytes(32, 'big').hex(), loss='none'))
        request, ctx, _ = self.prepare(oid, terminal)
        event = dict(at=self.now, request=request.hex())
        try: ack = self.receivers[ctx['recipient']][0].accept(request, ctx['sender_cert'], self.k)
        except Rejected as exc:
            if str(exc) != 'V2_RECIPIENT_WINDOW_FULL': raise
            event.update(kind='DELIVERY_REJECTED', reason=str(exc))
        else:
            self.receipts[oid] = request, ack; event.update(kind='DELIVERY', response=ack.hex())
        self.records.append(event); return event

    def restore_retirement(self, route='root'):
        return self.restore(route)

    def restore(self, route='root'):
        return super().restore_retirement(route)


class InterruptedWindowRuntime(RecoveryInterruptionMixin, WindowLifecycleRuntime):
    pass


def run_window_lifecycle(plan, cut, mode='existing', mask=3):
    if plan not in PLANS or cut not in CUTS or mode not in MODES or type(mask) is not int or not 0 <= mask < 8:
        raise ValueError('outside window lifecycle profile')
    queued = plan.startswith('queued_'); expired = plan == 'queued_expire'; canceled = plan == 'after_retire_cancel'
    with tempfile.TemporaryDirectory() as td:
        run = InterruptedWindowRuntime(td, mask, replica_mode=mode)
        try:
            run.submit(); run.finish(); run.send(); run.confirm()
            run.now = 110
            if queued:
                run.submit('b', hist=plan.endswith('histogram')); submit = bytes.fromhex(run.commands[-1]['request'])
                run.finish(); run.send('b')
            run.prepare_retirement(1); run.send_retirement(0, 1, cut=cut)
            run.now = 180 if expired else 120; run.restore_retirement()
            if queued: run.send('b', terminal=expired)
            run.send_retirement(0, 1); run.confirm_retirement()
            if queued:
                run.now += 1; run.send('b', terminal=expired)
            else:
                run.now = 130; run.submit('b', hist=plan.endswith('histogram')); submit = bytes.fromhex(run.commands[-1]['request'])
                if canceled: run.call('CONTROL', dict(kind='cancel', operation='b'))
                run.finish()
                if not canceled: run.send('b')
            if not canceled:
                run.now += 1; run.send('b', terminal=expired); run.confirm('b')
            run.exchange(submit)  # Exact signed SUBMIT retry, including after its expiry.
            run.replay_delivery('a')
            if not canceled:
                run.prepare_retirement(2); run.send_retirement(1, 2); run.confirm_retirement()
                run.query_retention('FINAL', 2); run.replay_delivery('b')
            run.query_retention('FINAL', 1); run.query_retention('RETIRED', 1)
            run.call('POLL', dict(operation='b')); run.call('FINAL', dict(cursor=0, limit=16))
            check = run.checked(); h, _ = run.simulator.context('root')
            check.update(sender_floor=run.simulator.retirement['sender'][h]['floor'],
                         receiver_floor=run.simulator.retirement['receiver'][h]['floor'],
                         receiver_live=sorted(seq for hh, seq in run.simulator.state.receiver if hh == h and seq > run.simulator.retirement['receiver'][h]['floor']))
            return dict(plan=plan, cut=cut, replica_mode=mode, mask=mask, config_cbor_hex=encode(run.cfg).hex(),
                        approved_outputs=run.oracle, commands=run.commands, expected_records=list(run.records),
                        checkpoints=run.checkpoints, diagnostics=run.diagnostics, recovery_diagnostics=run.recovery_diagnostics,
                        signing_calls=run.signer.calls, check=check)
        finally: run.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): parser.error('choose a new output directory')
    args.output.mkdir(parents=True)
    report = dict(profile='window-lifecycle-correspondence-v1', passed=False, cases=[],
        source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},
        scope='One route, window=1, two jobs, six schedules, three retirement cuts and six recovery exits on existing/fresh replicas. Fixed public schedule, conditional output=1, local SQLite authority. No arbitrary induction, cross-host/power-loss, authority races or long-run storage bound.')
    with lzma.open(args.output / 'cases.jsonl.xz', 'wt') as archive:
        for plan in PLANS:
            for cut in CUTS:
                for mode in MODES:
                    reference = None
                    for mask in range(8):
                        case = run_window_lifecycle(plan, cut, mode, mask)
                        signature = digest(dict(records=case['expected_records'], checkpoints=case['checkpoints']))
                        if reference is None: reference = signature
                        if signature != reference: raise AssertionError('conditioned lifecycle differs')
                        report['cases'].append(dict(plan=plan, cut=cut, replica_mode=mode, mask=mask,
                            correspondence_sha256=signature, trace_sha256=digest(case['expected_records']),
                            checkpoints=len(case['checkpoints']), process_exits=len(case['diagnostics']),
                            recovery_exits=len(case['recovery_diagnostics'])))
                        archive.write(json.dumps(case, separators=(',', ':')) + '\n')
                    print('PASS', plan, cut, mode, '8 datasets', flush=True)
    count = len(report['cases'])
    report.update(passed=True, cases_count=count, groups=count // 8, directed_neighbor_comparisons=count * 3,
                  process_exits=sum(c['process_exits'] for c in report['cases']),
                  recovery_exits=sum(c['recovery_exits'] for c in report['cases']),
                  operational_restores=count, checkpoints_count=sum(c['checkpoints'] for c in report['cases']))
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__': main()
