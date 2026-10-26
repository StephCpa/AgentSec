"""Two-route retirement isolation with real exits and an independent generator.

The test harness may inspect replicas and restore diagnostic copies. None of
their contents, heads or staleness results are supplied to the generator.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import lzma
from pathlib import Path
import tempfile
from unittest.mock import patch
from constructive_trace import FixtureSigningOracle
from cross_route_isolation_simulator import CrossRouteIsolationSimulator, SIDES, CUTS
from retirement_recovery_trace import RetirementRecoveryRuntime
from public_gateway import PublicGatewayLedger, parse_request
from public_trace_adapter import PublicTraceAdapter
from mixed_delegated_ledger import parse_mixed_action, parse_mixed_credential
from retention_recipient import RetentionRecipient
from state_relation import digest
from test_public_gateway import SERVER_KEY, PEER, make_request, parse_reply
from test_mixed_delegated_ledger import chain_fixture, credential, packet, tick
from window_lifecycle_trace import WindowLifecycleRuntime, window_context
from ledger import Rejected
from wire import encode
import retention_wire as r

WORKLOADS = ('count', 'histogram')
ADMISSIONS = ('before_fault', 'after_fault')


class CrossRouteIsolationRuntime(RetirementRecoveryRuntime):
    def __init__(self, *args, **kwargs):
        self.isolation_fault = None; self.diagnostic_replica = None
        self.frozen_operations = {}; self.frozen_confirmed = {}; self.frozen_final = {}
        with patch('restricted_trace.context', window_context), patch('test_atomic_publication.context', window_context):
            super().__init__(*args, two_routes=True, **kwargs)
        self.signer = FixtureSigningOracle()
        self.simulator = CrossRouteIsolationSimulator(self.cfg, {}, self.signer)
        self.checkpoints[0]['relation'] = self.relation()

    # Reuse the established opaque-row preservation checks without invoking the
    # one-route simulator or forwarding the rows to the new generator.
    operation_snapshot = WindowLifecycleRuntime.operation_snapshot
    confirmed_snapshot = WindowLifecycleRuntime.confirmed_snapshot
    assert_protected = WindowLifecycleRuntime.assert_protected

    def projected_relation(self):
        result = super().relation(); self.assert_protected()
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
            live = obj.db.execute('SELECT count(*) FROM v2_recipient_live').fetchone()[0]
            if tuple(int.from_bytes(x, 'big') for x in meta) != (high, floor) or live != high-floor or not 0 <= live <= ctx['window']:
                raise AssertionError('R15.window_capacity')
            windows.append(dict(high=high, floor=floor, live=live, capacity=ctx['window']))
        result['R15'] = digest(dict(windows=windows, frozen_operations=sorted(self.frozen_operations),
                                   frozen_confirmed=sorted(self.frozen_confirmed), frozen_final=sorted(self.frozen_final),
                                   opaque_equality=True))
        return result

    def relation(self):
        fault = self.isolation_fault
        if fault is not None:
            old, w, _ = self.owner_ret(fault['side'], fault['route'])
            current = old.local_anchor() == w.head(old.namespace)
            if current == fault['stale']: raise AssertionError('R16.freshness_classification')
            if fault['stale']:
                if (w.head(old.namespace, True) != fault['head'] or old.state_image() != fault['local_image'] or
                        old.local_anchor() != fault['local_anchor']):
                    raise AssertionError('R16.failed_component_changed')
                try: old.check_current_state()
                except Rejected as exc:
                    if str(exc) != 'WITNESS_RECOVERY_REQUIRED': raise
                else: raise AssertionError('R16.stale_guard_open')
                diagnostic = self.diagnostic_replica
                if diagnostic.state_image() != fault['head']['image'] or diagnostic.local_anchor() != w.head(old.namespace):
                    raise AssertionError('R16.diagnostic_identity')
                self.replace(fault['side'], fault['route'], diagnostic)
                try: result = self.projected_relation()
                finally: self.replace(fault['side'], fault['route'], old)
            else:
                old.check_current_state(); result = self.projected_relation()
        else: result = self.projected_relation()
        result['R16'] = digest(dict(pending=None if fault is None else dict(side=fault['side'], route=fault['route'], stale=fault['stale']),
                                    authority_projection=True, opaque_preservation=True))
        return result

    def _observe(self, actual):
        command = self.commands[len(self.simulator.records)]
        if command['kind'] == 'PUBLIC':
            request = parse_request(bytes.fromhex(command['request']))
            if request['method'] == 'SUBMIT':
                action = parse_mixed_action(request['payload']['action'])
                width = action['bucket_count'] if action['operation_kind'] == 'histogram' else 1
                self.simulator.state.oracle.setdefault(action['operation'], (self.target,) + (0,) * (width - 1))
        with ExitStack() as guards:
            guards.enter_context(patch('sqlite3.connect', side_effect=AssertionError('generator DB access')))
            for owner, names in ((PublicGatewayLedger, ('handle_public', 'prepare_retirement', 'confirm_retirement')),
                                 (RetentionRecipient, ('accept',)), (PublicTraceAdapter, ('_public',))):
                for name in names:
                    guards.enter_context(patch.object(owner, name, side_effect=AssertionError('generator runtime/response access')))
            generated = self.simulator.emit(command)
        if generated != actual: raise AssertionError('cross-route observation differs at ' + str(len(self.records)))
        relation = self.relation()
        if command['kind'].endswith('_CUT'): relation['R14'] = digest(self.diagnostics[-1])
        self.checkpoints.append(dict(index=len(self.simulator.records), kind=command['kind'], relation=relation))

    def crash(self, stage, route, cut, **inputs):
        if self.isolation_fault is not None: raise AssertionError('one pending fault only')
        super().crash(stage, route, cut, **inputs)
        side, _ = self.cut_owner; obj, w, _ = self.owner_ret(side, route)
        stale = self.diagnostics[-1]['stale_guard_blocked']
        self.isolation_fault = dict(side=side, route=route, stale=stale,
                                    head=w.head(obj.namespace, True), local_anchor=obj.local_anchor(), local_image=obj.state_image())
        if stale:
            self.diagnostic_replica = self.new_ret_replica(side, route, self.directory/'isolation-authority-projection')
            if self.diagnostic_replica.audit() or self.diagnostic_replica.state_image() != self.isolation_fault['head']['image']:
                raise AssertionError('R16.diagnostic_restore')

    def exchange(self, raw, peer=PEER):
        request = parse_request(raw)
        coin = hashlib.sha256(('public-challenge:' + str(int.from_bytes(request['request_id'], 'big'))).encode()).hexdigest() if request['method'] == 'CHALLENGE' else ''
        self.commands.append(dict(kind='PUBLIC', at=self.now, request=raw.hex(), peer=peer.hex(), challenge_coin=coin))
        event = dict(at=self.now, request=raw.hex(), peer=peer.hex())
        try: reply = self.l.handle_public(raw, peer, SERVER_KEY)
        except Rejected as exc:
            if str(exc) != 'WITNESS_RECOVERY_REQUIRED': raise
            event['kind'] = 'PUBLIC_UNAVAILABLE'; self.records.append(event); return None
        event.update(kind='PUBLIC', response=reply.hex()); self.records.append(event)
        return parse_reply(reply, raw)

    def advance(self):
        self.commands.append(dict(kind='TICK', at=self.now, tick=self.steps + 1))
        try:
            with patch.object(self.l, 'operation_randomness', side_effect=self._randomness): tick(self.l)
        except Rejected as exc:
            if str(exc) != 'WITNESS_RECOVERY_REQUIRED': raise
            self.records.append(dict(kind='TICK_UNAVAILABLE', at=self.now, tick=self.steps + 1)); return
        self.steps += 1; self.records.append(dict(kind='TICK', at=self.now, tick=self.steps))

    def query_retention(self, kind, seq, route='root'):
        ctx = self.cfg['roots'][route]['context']; challenge = (len(self.records) + 1).to_bytes(32, 'big')
        self.commands.append(dict(kind='RETENTION_QUERY', at=self.now, route=route, query_kind=kind, seq=seq, challenge=challenge.hex()))
        request = r.query(ctx, kind, seq, challenge, self.s)
        event = dict(kind='RETENTION_QUERY', at=self.now, route=route, request=request.hex())
        try: ack = self.receivers[ctx['recipient']][0].accept(request, ctx['sender_cert'], self.k)
        except Rejected as exc:
            if str(exc) == 'WITNESS_RECOVERY_REQUIRED': event['kind'] = 'RETENTION_UNAVAILABLE'
            else: event['reason'] = str(exc)
        else:
            event['response'] = ack.hex()
            if kind != 'FINAL': self.retention_receipts[route] = request, ack
        self.records.append(event); return event

    def prepare_b_request(self, histogram):
        # Caller fixture construction only. The signed SUBMIT is not dispatched
        # until exchange(raw); model input is the public request, never the DB.
        challenge = self.call('CHALLENGE', {})['body']; chain = []
        for raw in chain_fixture(self.l):
            obj = parse_mixed_credential(raw); obj.update(root='root2', id=obj['id'] + '2')
            obj['policy']['recipients'] = ['reader2']
            obj['parent_digest'] = hashlib.sha256(chain[-1]).digest() if chain else b''
            chain.append(credential(obj))
        with patch.object(self.l, 'issue_challenge', return_value=challenge):
            action, proof = packet(self.l, chain, 'b', histogram, proof_id=self.rid.to_bytes(16, 'big'), root='root2', recipient='reader2')
        self.rid += 1
        self.kinds['b'] = histogram; self.oracle['b'] = (1, 0, 0, 0) if histogram else (1,)
        return make_request('SUBMIT', dict(action=action, proof=proof, chain=chain), self.rid, 'leaf', self.now)

    def restore_retirement(self, route='root'):
        side, expected = self.cut_owner
        if route != expected: raise AssertionError('restore wrong route')
        self.commands.append(dict(kind='RETIRE_RECOVER', at=self.now, route=route, side=side))
        old, w, _ = self.owner_ret(side, route); head = w.head(old.namespace, True); self.restores += 1
        restored = self.new_ret_replica(side, route, self.directory/('restored-' + str(self.restores)))
        if restored.state_image() != head['image'] or restored.audit() or w.head(old.namespace, True) != head:
            restored.close(); raise AssertionError('R16.restore')
        old.close(); self.replace(side, route, restored)
        if self.diagnostic_replica is not None: self.diagnostic_replica.close(); self.diagnostic_replica = None
        self.isolation_fault = None; self.cut_owner = None
        self.records.append(dict(kind='RETIRE_RECOVER', at=self.now, route=route, side=side))

    def close(self):
        if self.diagnostic_replica is not None: self.diagnostic_replica.close(); self.diagnostic_replica = None
        super().close()


def run_cross_route_isolation(side, cut, workload='count', admission='after_fault', mask=3):
    if side not in SIDES or cut not in CUTS[side] or workload not in WORKLOADS or admission not in ADMISSIONS or type(mask) is not int or not 0 <= mask < 8:
        raise ValueError('outside cross-route isolation profile')
    with tempfile.TemporaryDirectory() as td:
        run = CrossRouteIsolationRuntime(td, mask)
        try:
            run.submit(); run.finish(); run.send(); run.confirm()
            run.now = 110; request_b = run.prepare_b_request(workload == 'histogram')
            if admission == 'before_fault': run.exchange(request_b)
            run.now = 115
            if side == 'sender': run.prepare_retirement(1, cut=cut)
            else: run.prepare_retirement(1); run.send_retirement(0, 1, cut=cut)
            fault_index = len(run.records)
            run.query_retention('FINAL', 1)
            run.exchange(request_b); run.call('POLL', dict(operation='b')); run.advance()
            blocked_sender = side == 'sender' and cut == 'after_witness_accept'
            if not blocked_sender:
                run.finish(); run.send('b'); run.confirm('b')
            before_restore = dict(final=deepcopy(run.simulator.state.final), draws=deepcopy(run.runtime_draws))
            run.now = 120; run.restore_retirement()
            run.exchange(request_b)
            if blocked_sender: run.finish(); run.send('b'); run.confirm('b')
            if side == 'sender': run.prepare_retirement(1)
            run.send_retirement(0, 1); run.confirm_retirement()
            run.prepare_retirement(1, 'root2'); run.send_retirement(0, 1, 'root2'); run.confirm_retirement('root2')
            run.query_retention('FINAL', 1, 'root2')
            run.call('POLL', dict(operation='b')); run.call('FINAL', dict(cursor=0, limit=16))
            check = run.checked()
            check['frontiers'] = {}
            for route in run.cfg['roots']:
                h, _ = run.simulator.context(route)
                high, confirmed = run.simulator.frontiers(h)
                check['frontiers'][route] = dict(high=high, confirmed=confirmed,
                    sender_floor=run.simulator.retirement['sender'][h]['floor'],
                    receiver_floor=run.simulator.retirement['receiver'][h]['floor'])
            return dict(side=side, cut=cut, workload=workload, admission=admission, mask=mask,
                        config_cbor_hex=encode(run.cfg).hex(), approved_outputs=run.oracle,
                        commands=run.commands, expected_records=list(run.records), checkpoints=run.checkpoints,
                        diagnostics=run.diagnostics, signing_calls=run.signer.calls, check=check,
                        fault_index=fault_index, before_restore=before_restore)
        finally: run.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): parser.error('choose a new output directory')
    args.output.mkdir(parents=True)
    sources = list(Path(__file__).parent.glob('*.py')) + [Path(__file__).with_name('cross-route-isolation-contract.json')]
    report = dict(profile='cross-route-retention-isolation-v1', passed=False, cases=[],
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
                  scope='Two routes, two operations, one declared sender/recipient retirement exit, existing local replica, then fresh recovery. Fixed public schedule and conditioned outputs; no network timing, general concurrency or arbitrary-input proof.')
    with lzma.open(args.output/'cases.jsonl.xz', 'wt') as archive:
        for side in SIDES:
            for cut in CUTS[side]:
                for workload in WORKLOADS:
                    for admission in ADMISSIONS:
                        reference = None
                        for mask in range(8):
                            case = run_cross_route_isolation(side, cut, workload, admission, mask)
                            signature = digest(dict(records=case['expected_records'], checkpoints=case['checkpoints']))
                            if reference is None: reference = signature
                            if signature != reference: raise AssertionError('conditional cross-route correspondence differs')
                            report['cases'].append(dict(side=side, cut=cut, workload=workload, admission=admission, mask=mask,
                                trace_sha256=digest(case['expected_records']), correspondence_sha256=signature,
                                checkpoints=len(case['checkpoints']), process_exits=len(case['diagnostics'])))
                            archive.write(json.dumps(case, separators=(',', ':')) + '\n')
                        print('PASS', side, cut, workload, admission, '8 datasets', flush=True)
    count = len(report['cases'])
    report.update(passed=True, cases_count=count, groups_count=count//8, process_exits=count, operational_restores=count,
                  checkpoints_count=sum(x['checkpoints'] for x in report['cases']), directed_neighbor_comparisons=count*3)
    (args.output/'summary.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__': main()
