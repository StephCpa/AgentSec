"""Measure cleanup costs on the same live files, without crash/restore confounds.

One/two actual published jobs; local SQLite witnesses; method timings exclude
trace simulation/projection. This is not a scale or physical-erasure benchmark.
"""
import hashlib
import json
import platform
from pathlib import Path
import sqlite3
import statistics
import sys
import tempfile
from types import SimpleNamespace
import cryptography
from restricted_trace import Runtime
from persistence_experiment import timed
from retirement_recovery_trace import protected_archive
from ledger import Rejected
import retention_wire as r


def file_state(obj):
    path = Path(obj.path)
    files = {suffix or 'main': Path(str(path) + suffix).stat().st_size if Path(str(path) + suffix).exists() else 0
             for suffix in ('', '-wal', '-shm', '-journal')}
    page_size = obj.db.execute('PRAGMA page_size').fetchone()[0]
    return dict(files_bytes=files, total_files_bytes=sum(files.values()), page_size=page_size,
                page_count=obj.db.execute('PRAGMA page_count').fetchone()[0],
                freelist_count=obj.db.execute('PRAGMA freelist_count').fetchone()[0],
                journal_mode=obj.db.execute('PRAGMA journal_mode').fetchone()[0])


def state(run, inbox, receiver_w):
    sender_image = run.l.state_image(); receiver_image = inbox.state_image()
    return dict(sender_image_bytes=len(sender_image), receiver_image_bytes=len(receiver_image),
                combined_current_image_bytes=len(sender_image) + len(receiver_image),
                sender_archive_rows=run.l.db.execute('SELECT count(*) FROM v2_outbox').fetchone()[0],
                sender_offer_rows=run.l.db.execute('SELECT count(*) FROM v2_retire_offers').fetchone()[0],
                receiver_live_rows=inbox.db.execute('SELECT count(*) FROM v2_recipient_live').fetchone()[0],
                receiver_floor=inbox.state()['floor'],
                sender_witness_commit_rows=run.w.db.execute('SELECT count(*) FROM commits').fetchone()[0],
                receiver_witness_commit_rows=receiver_w.db.execute('SELECT count(*) FROM commits').fetchone()[0],
                sender=file_state(run.l), receiver=file_state(inbox),
                sender_witness=file_state(run.w), receiver_witness=file_state(receiver_w))


def run_cost_trial(hist=False, jobs=1, rejected_queries=16, batch_size=None):
    if batch_size is None: batch_size = jobs
    if type(hist) is not bool or type(jobs) is not int or jobs not in (1, 2) or type(batch_size) is not int or batch_size not in (1, jobs) or type(rejected_queries) is not int or not 1 <= rejected_queries <= 64:
        raise ValueError('outside bounded cost profile')
    with tempfile.TemporaryDirectory() as td:
        run = Runtime(td)
        try:
            run.submit(hist=hist)
            if jobs == 2: run.submit('b')
            run.finish(); run.deliver()
            if jobs == 2: run.deliver('b')
            run.checked(); protected = protected_archive(run.l)
            ctx = run.cfg['roots']['root']['context']; h = r.context_hash(ctx)
            inbox, receiver_w = run.receivers[ctx['recipient']]
            receiver = SimpleNamespace(l=inbox, w=receiver_w)
            before = state(run, inbox, receiver_w); run.now = 170; outputs = {}
            phases = dict(offer=[], retire=[], confirm=[], rejected_query=[])
            for target in range(batch_size, jobs + 1, batch_size):
                def prepare(): outputs['offer'] = run.l.prepare_retirement(h, target, run.s)
                phases['offer'].append(timed(run, prepare))
                request = r.retire_attempt(outputs['offer'], target.to_bytes(32, 'big'), ctx, run.s)
                def receive(): outputs['ack'] = inbox.accept(request, ctx['sender_cert'], run.k)
                phases['retire'].append(timed(receiver, receive))
                phases['confirm'].append(timed(run, lambda: run.l.confirm_retirement(h, request, outputs['ack'])))
            after = state(run, inbox, receiver_w); run.now = 200; attempts = []
            # Signing caller requests is outside measured service invocation.
            requests = [r.query(ctx, 'FINAL', 1, i.to_bytes(32, 'big'), run.s) for i in range(1, rejected_queries + 1)]
            def rejected_query():
                request = requests[len(attempts)]
                try: inbox.accept(request, ctx['sender_cert'], run.k)
                except Rejected as exc:
                    if str(exc) != 'V2_RETIRED': raise
                    attempts.append(str(exc))
                else: raise AssertionError('cleaned fact reappeared')
            phases['rejected_query'].append(timed(receiver, rejected_query, rejected_queries))
            after_queries = state(run, inbox, receiver_w)
            if protected_archive(run.l) != protected or run.l.audit() or inbox.audit(): raise AssertionError('cleanup changed protected archive or failed audit')
            if before['receiver_live_rows'] != jobs or after['receiver_live_rows'] != 0 or after['receiver_floor'] != jobs:
                raise AssertionError('cleanup did not remove the live window')
            if after['sender_archive_rows'] != jobs or after_queries['sender_archive_rows'] != jobs:
                raise AssertionError('sender archive was pruned')
            cycles = jobs // batch_size
            if [sum(x['cas_commits'] for x in phases[k]) for k in ('offer', 'retire', 'confirm', 'rejected_query')] != [cycles, cycles, cycles, rejected_queries]:
                raise AssertionError('cleanup/query CAS accounting')
            if after_queries['receiver_witness_commit_rows'] - after['receiver_witness_commit_rows'] != rejected_queries:
                raise AssertionError('rejected query history accounting')
            if after_queries['receiver_live_rows'] != 0: raise AssertionError('queries resurrected live facts')
            cleanup = [x for k in ('offer', 'retire', 'confirm') for x in phases[k]]
            return dict(histogram=hist, jobs=jobs, batch_size=batch_size, rejected_queries=rejected_queries, before=before, after_cleanup=after,
                        after_queries=after_queries, phases=phases,
                        cleanup_totals={k: sum(x[k] for x in cleanup) for k in ('cas_commits', 'cas_image_bytes', 'elapsed_operation_ms', 'state_image_builds', 'state_image_encoded_bytes')},
                        archive_budget_final_preserved=True, same_files_without_restore_or_vacuum=True)
        finally: run.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): parser.error('choose a new output file')
    trials = []
    configurations = [(hist, jobs, batch) for hist in (False, True) for jobs, batch in ((1, 1), (2, 1), (2, 2))]
    for hist, jobs, batch in configurations:
        for repeat in range(5):
            trial = run_cost_trial(hist, jobs, batch_size=batch); trial['repeat'] = repeat; trials.append(trial)
        print('PASS cleanup cost', 'histogram' if hist else 'count', jobs, 'jobs, batch', batch, '5 repetitions', flush=True)
    groups = []
    for hist, jobs, batch in configurations:
            values = [x for x in trials if x['histogram'] == hist and x['jobs'] == jobs and x['batch_size'] == batch]
            groups.append(dict(histogram=hist, jobs=jobs, batch_size=batch, repetitions=len(values),
                image_bytes={stage: {key: sorted(set(x[stage][key] for x in values)) for key in
                             ('sender_image_bytes', 'receiver_image_bytes', 'combined_current_image_bytes')} for stage in ('before', 'after_cleanup', 'after_queries')},
                cleanup_totals={key: dict(median=statistics.median(v), minimum=min(v), maximum=max(v)) for key in values[0]['cleanup_totals']
                                for v in [[x['cleanup_totals'][key] for x in values]]},
                method_ms={phase: dict(median=statistics.median(v), minimum=min(v), maximum=max(v)) for phase in values[0]['phases']
                           for v in [[ms for x in values for call in x['phases'][phase] for ms in call['latencies_ms']]]}))
    report = dict(passed=True, profile='retirement-cost-v1', scope=__doc__, python=sys.version, cryptography=cryptography.__version__,
                  sqlite=sqlite3.sqlite_version, platform=platform.platform(), trials=trials, groups=groups,
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},
                  limitations=['Local sequential methods; no TLS, throughput or scale claim.', 'Five fresh fixture repetitions per group; no statistical speedup claim.',
                               'SQLite current file sizes include main/WAL/SHM/journal when present, not peak/transient I/O or backups.',
                               'Logical deletion is not physical secure erasure; sender archives and witness commit metadata remain.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__': main()
