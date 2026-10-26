#!/usr/bin/env python3
"""Supplement the frozen seven-plan matrix with two-row delete crash traces.

Uses the same runtime, generator and R1--R8/R14 checks without changing their
source while the original matrix runs. Both facts are ACCEPTED, matching the
two-job cost workloads. The replay tool independently regenerates this archive.
"""
from copy import deepcopy
import hashlib
import json
import lzma
from pathlib import Path
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
P = ROOT / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from retirement_recovery_trace import RetirementRecoveryRuntime, protected_archive
from retirement_recovery_simulator import SEND_CUTS
from state_relation import digest
from wire import encode
import retention_wire as r

PLANS = ('batch_count', 'batch_histogram')


def run_case(plan, cut, mask):
    if plan not in PLANS or cut not in SEND_CUTS or type(mask) is not int or not 0 <= mask < 8:
        raise ValueError('outside two-row batch profile')
    with tempfile.TemporaryDirectory() as td:
        run = RetirementRecoveryRuntime(td, mask)
        try:
            run.submit(hist=plan == 'batch_histogram'); run.submit('b'); run.finish()
            run.send(); run.confirm(); run.send('b'); run.confirm('b')
            run.protected = protected_archive(run.l); run.now = 180
            run.prepare_retirement(2); run.send_retirement(0, 2, cut=cut)
            run.now = 190; run.restore_retirement()
            run.query_retention('FINAL', 1); run.query_retention('FINAL', 2)
            run.send_retirement(0, 2); run.confirm_retirement()
            run.now = 200
            run.query_retention('FINAL', 1); run.query_retention('FINAL', 2)
            run.query_retention('RETIRED', 1); run.query_retention('RETIRED', 2)
            run.replay_delivery(); run.replay_delivery('b')
            run.call('FINAL', dict(cursor=0, limit=16)); check = run.checked(); run.assert_protected()
            h = r.context_hash(run.cfg['roots']['root']['context']); state = run.simulator.retirement
            check.update(sender_floor=state['sender'][h]['floor'], receiver_floor=state['receiver'][h]['floor'],
                         receiver_live=sorted(seq for hh, seq in run.simulator.state.receiver if hh == h and seq > state['receiver'][h]['floor']),
                         sender_archive_preserved=True, sender_archive_rows=run.l.db.execute('SELECT count(*) FROM v2_outbox').fetchone()[0])
            if check['sender_floor'] != 2 or check['receiver_floor'] != 2 or check['receiver_live'] or check['sender_archive_rows'] != 2:
                raise AssertionError('batch cleanup did not finish with both archives retained')
            idx = next(i for i, e in enumerate(run.records) if e['kind'] == 'RETIRE_RECOVER')
            first, second = run.records[idx + 1:idx + 3]
            if first.get('reason') != second.get('reason') or ('response' in first) != ('response' in second):
                raise AssertionError('partial two-row cleanup observed')
            return dict(plan=plan, cut=cut, mask=mask, config_cbor_hex=encode(run.cfg).hex(), approved_outputs=run.oracle,
                        commands=run.commands, expected_records=deepcopy(list(run.records)), checkpoints=run.checkpoints,
                        diagnostics=run.diagnostics, signing_calls=run.signer.calls, check=check)
        finally: run.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): parser.error('choose a new output directory')
    args.output.mkdir(parents=True)
    report = dict(profile='retirement-batch-correspondence-v1', passed=False, cases=[], scope=__doc__,
                  experiment_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in P.glob('*.py')})
    with lzma.open(args.output / 'cases.jsonl.xz', 'wt') as archive:
        for plan in PLANS:
            for cut in SEND_CUTS:
                reference = None
                for mask in range(8):
                    case = run_case(plan, cut, mask); signature = digest(dict(records=case['expected_records'], checkpoints=case['checkpoints']))
                    if reference is None: reference = signature
                    if signature != reference: raise AssertionError('conditioned batch correspondence differs')
                    report['cases'].append(dict(plan=plan, cut=cut, mask=mask, correspondence_sha256=signature,
                                                trace_sha256=digest(case['expected_records']), checkpoints=len(case['checkpoints']),
                                                diagnostics=case['diagnostics'], check=case['check']))
                    archive.write(json.dumps(case, separators=(',', ':')) + '\n')
                print('PASS', plan, cut, '8 datasets', flush=True)
    count = len(report['cases']); report.update(passed=True, cases_count=count, groups=count // 8,
        process_exits=count, operational_restores=count, diagnostic_restores=count, directed_neighbor_comparisons=count * 3,
        checkpoints_count=sum(c['checkpoints'] for c in report['cases']))
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__': main()
