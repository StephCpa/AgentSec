#!/usr/bin/env python3
"""Count persistence work under a full one-slot receiver window, without timing.

Both callers already hold the same valid prepared envelope. Compare fresh
attempts using that body with calling prepare_envelope again before each attempt.
No revocation, route/key change, loss of caller memory, expiry or authority race
occurs in this bounded experiment. This does not authorize a general SDK cache.
Receiver exchanges match; sender method-call observations intentionally differ.
"""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import cryptography
ROOT = Path(__file__).resolve().parents[1]
P = ROOT / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from restricted_trace import Runtime
from window_lifecycle_trace import window_context
from preparation_recovery_trace import protected_state
from retirement_cost_experiment import state
from state_relation import digest
from ledger import Rejected
import retention_wire as r
import retention_delivery as d

MODES = ('reuse_prepared', 'reprepare')
ATTEMPTS = (0, 1, 8, 32)


def counted(owner, fn):
    """Actual successful CAS payloads and image builds; no elapsed-time sampling."""
    cas = []; images = []; original_cas = owner.w.compare_and_store; original_image = owner.l.state_image
    def compare_and_store(namespace, seq, prior_digest, image, request_id):
        result = original_cas(namespace, seq, prior_digest, image, request_id)
        cas.append(len(image)); return result
    def state_image():
        image = original_image(); images.append(len(image)); return image
    with ExitStack() as stack:
        stack.enter_context(patch.object(owner.w, 'compare_and_store', side_effect=compare_and_store))
        stack.enter_context(patch.object(owner.l, 'state_image', side_effect=state_image))
        result = fn()
    return result, dict(cas_commits=len(cas), cas_image_bytes=sum(cas), cas_payload_bytes=cas,
                        state_image_builds=len(images), state_image_encoded_bytes=sum(images))


def totals(calls):
    return {k: sum(x[k] for x in calls) for k in ('cas_commits', 'cas_image_bytes', 'state_image_builds', 'state_image_encoded_bytes')}


def trial(histogram, attempts, mode):
    if type(histogram) is not bool or type(attempts) is not int or attempts not in ATTEMPTS or mode not in MODES:
        raise ValueError('outside window pressure profile')
    with tempfile.TemporaryDirectory() as td:
        with patch('restricted_trace.context', window_context), patch('test_atomic_publication.context', window_context): run = Runtime(td)
        try:
            run.submit(); run.finish(); run.deliver()
            run.now = 110; run.submit('b', hist=histogram); run.finish()
            ctx = run.cfg['roots']['root']['context']; h = r.context_hash(ctx); did = run.decision('b')['delivery_id']
            inbox, receiver_w = run.receivers[ctx['recipient']]; receiver = SimpleNamespace(l=inbox, w=receiver_w)
            old_archive = tuple(run.l.outbox('t', run.decision('a')['delivery_id']))
            old_final = [tuple(row) for row in run.l.db.execute('SELECT * FROM final_events ORDER BY seq')]
            protected = protected_state(run.l)
            def preserved():
                if protected_state(run.l) != protected: raise AssertionError('prepared/pressure work changed operation, charge, budget or ticket')
                if tuple(run.l.outbox('t', run.decision('a')['delivery_id'])) != old_archive: raise AssertionError('old confirmed archive changed')
                if [tuple(row) for row in run.l.db.execute('SELECT * FROM final_events ORDER BY seq')][:len(old_final)] != old_final:
                    raise AssertionError('old final prefix changed')
            envelope, prepare = counted(run, lambda: run.l.prepare_envelope('t', did, run.s))
            preserved()
            before = state(run, inbox, receiver_w); sender_image = run.l.state_image()
            live = [tuple(row) for row in inbox.db.execute('SELECT * FROM v2_recipient_live ORDER BY seq')]
            sender_calls = []; receiver_calls = []; wire = []
            for i in range(attempts):
                run.now = 111 + i
                if mode == 'reprepare':
                    retried, cost = counted(run, lambda: run.l.prepare_envelope('t', did, run.s))
                    if retried != envelope: raise AssertionError('retry changed original envelope')
                    sender_calls.append(cost)
                request = d.attempt('DELIVERY', envelope, (i + 1).to_bytes(32, 'big'), ctx, run.s)
                def receive_denial():
                    try: inbox.accept(request, ctx['sender_cert'], run.k)
                    except Rejected as exc:
                        if str(exc) != 'V2_RECIPIENT_WINDOW_FULL': raise
                        return str(exc)
                    raise AssertionError('full window admitted a new fact')
                reason, cost = counted(receiver, receive_denial); receiver_calls.append(cost)
                wire.append(dict(at=run.now, request=request.hex(), reason=reason))
                preserved()
                if [tuple(row) for row in inbox.db.execute('SELECT * FROM v2_recipient_live ORDER BY seq')] != live:
                    raise AssertionError('denial changed existing receiver fact')
                observed = inbox.db.execute('SELECT observed FROM v2_recipient_meta').fetchone()[0]
                if observed != run.now: raise AssertionError('denial did not persist clock')
            after = state(run, inbox, receiver_w)
            sender_totals = totals(sender_calls); receiver_totals = totals(receiver_calls)
            if sender_totals['cas_commits'] != (attempts if mode == 'reprepare' else 0) or receiver_totals['cas_commits'] != attempts:
                raise AssertionError('pressure CAS count')
            for who, measured in (('sender', sender_totals), ('receiver', receiver_totals)):
                key = who + '_witness_commit_rows'
                if after[key] - before[key] != measured['cas_commits']: raise AssertionError('CAS meter does not match persistent history')
            if before['receiver_live_rows'] != 1 or after['receiver_live_rows'] != 1 or after['receiver_floor'] != 0:
                raise AssertionError('pressure changed capacity')
            same_sender_image = run.l.state_image() == sender_image
            cleanup_calls = []
            def cleanup(target):
                offer, a = counted(run, lambda: run.l.prepare_retirement(h, target, run.s))
                request = r.retire_attempt(offer, (1000 + target).to_bytes(32, 'big'), ctx, run.s)
                ack, b = counted(receiver, lambda: inbox.accept(request, ctx['sender_cert'], run.k))
                _, c = counted(run, lambda: run.l.confirm_retirement(h, request, ack))
                cleanup_calls.extend((a, b, c)); wire.append(dict(at=run.now, request=request.hex(), response=ack.hex()))
                preserved()
            run.now = 150; cleanup(1)
            after_release = state(run, inbox, receiver_w)
            if after_release['receiver_live_rows'] != 0 or after_release['receiver_floor'] != 1:
                raise AssertionError('cleanup did not release one position')
            run.now = 151
            request = d.attempt('DELIVERY', envelope, (999).to_bytes(32, 'big'), ctx, run.s)
            ack, receive = counted(receiver, lambda: inbox.accept(request, ctx['sender_cert'], run.k))
            run.records.append(dict(kind='DELIVERY', at=run.now, request=request.hex(), response=ack.hex()))
            _, confirm = counted(run, lambda: run.l.confirm('t', did, request, ack))
            run.records.append(dict(kind='CONFIRM', at=run.now, request=request.hex(), response=ack.hex()))
            wire.append(dict(at=run.now, request=request.hex(), response=ack.hex()))
            fact = r.parse_fact(d.parse_receipt(ack, request, ctx), ctx)
            if fact['outcome'] != 'ACCEPTED' or fact['event_at'] != 151 or fact['expires_at'] != 170:
                raise AssertionError('retries changed final fact or original deadline')
            run.now = 152; cleanup(2); final = state(run, inbox, receiver_w); preserved(); check = run.checked()
            if final['receiver_live_rows'] != 0 or final['receiver_floor'] != 2 or final['sender_archive_rows'] != 2:
                raise AssertionError('final cleanup/archive state')
            if [x[0] for x in check['draws']] != ['a', 'b']: raise AssertionError('retry resampled a mechanism')
            return dict(histogram=histogram, attempts=attempts, mode=mode, initial_prepare=prepare,
                pressure=dict(sender_calls=sender_calls, receiver_calls=receiver_calls, sender_totals=sender_totals,
                              receiver_totals=receiver_totals, sender_image_unchanged=same_sender_image),
                before_pressure=before, after_pressure=after, after_release=after_release, final=final,
                cleanup_totals=totals(cleanup_calls), final_receive=receive, final_confirmation=confirm,
                receiver_exchanges=wire, receiver_exchange_sha256=digest(wire), check=check,
                original_envelope_preserved=True, original_archive_budget_final_preserved=True,
                same_files_without_restore_or_vacuum=True)
        finally: run.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): parser.error('output exists')
    trials = []; comparisons = []
    for hist in (False, True):
        for attempts in ATTEMPTS:
            for repeat in range(2):
                pair = []
                for mode in MODES:
                    x = trial(hist, attempts, mode); x['repeat'] = repeat; pair.append(x); trials.append(x)
                if pair[0]['receiver_exchanges'] != pair[1]['receiver_exchanges'] or pair[0]['check'] != pair[1]['check']:
                    raise AssertionError('paired receiver exchanges or business accounting differ')
                saved_commits = pair[1]['pressure']['sender_totals']['cas_commits'] - pair[0]['pressure']['sender_totals']['cas_commits']
                saved_bytes = pair[1]['pressure']['sender_totals']['cas_image_bytes'] - pair[0]['pressure']['sender_totals']['cas_image_bytes']
                comparisons.append(dict(histogram=hist, attempts=attempts, repeat=repeat,
                    receiver_exchange_sha256=pair[0]['receiver_exchange_sha256'], identical_receiver_exchanges=True,
                    saved_sender_cas=saved_commits, saved_sender_image_bytes=saved_bytes,
                    receiver_cas=pair[0]['pressure']['receiver_totals']['cas_commits']))
            print('PASS pressure accounting', 'histogram' if hist else 'count', attempts, 'attempts, 2 paired repetitions', flush=True)
    report = dict(passed=True, profile='window-pressure-accounting-v1', scope=__doc__, trials=trials, comparisons=comparisons,
        trials_count=len(trials), python=sys.version, cryptography=cryptography.__version__, sqlite=sqlite3.sqlite_version,
        platform=platform.platform(), source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in P.glob('*.py')},
        experiment_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        limitations=['Counts only; no timing data collected, other verification workloads may run concurrently.',
                     'One route, two operations, one-slot receiver, fixed clocks and unchanged authorization/keys.',
                     'Receiver-facing bytes match; sender preparation calls differ and are not claimed observationally equivalent.',
                     'No new SDK policy, network throughput, physical write volume or long-run bounded-state claim.',
                     'Image bytes are actual CAS payload bytes; file sizes are current allocated files, not peak I/O.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__': main()
