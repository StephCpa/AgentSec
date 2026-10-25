"""Exact ideal-bit mechanism checks and a logical public scheduler reference.

NOT constant-time Python, a cryptographic service, or an integration with Ledger.
All inputs are synthetic. A public padded capacity and a valid contribution-bounded
snapshot are preconditions. Tick is a logical work slot, not a physical clock.
"""
from collections import Counter, defaultdict
from fractions import Fraction as F
from itertools import product
from pathlib import Path
import hashlib
import json


class CountJob:
    """Exactly N+2K+1 step calls; no secret-dependent early completion."""
    def __init__(self, rows, tape, k):
        # Prevalidated trusted snapshot and ideal bit tape, not a public validator.
        assert k >= 1 and len(tape) == 2*k
        assert all(type(x) is int and x in (0, 1) for x in rows+tape)
        self.rows, self.tape, self.k = tuple(rows), tuple(tape), k
        self.n = len(rows)
        self.work = self.n+2*k+1
        self.pc = self.count = 0
        self.alive, self.g = [1, 1], [0, 0]
        self.result = None

    def step(self):
        assert self.pc < self.work
        i = self.pc
        if i < self.n:             # Branch depends only on public program counter.
            self.count += self.rows[i]
        elif i < self.n+2*self.k:
            j = i-self.n
            side = j//self.k
            self.alive[side] &= self.tape[j]
            self.g[side] += self.alive[side]
        else:
            # min/max and Python integers are NOT a physical constant-time claim.
            self.result = min(self.n, max(0, self.count+self.g[0]-self.g[1]))
        self.pc += 1
        return self.pc == self.work


def sample(rows, tape, k):
    job = CountJob(rows, tape, k)
    for _ in range(job.work):
        job.step()
    return job.result, job.pc


def noise_pmf(k):
    geom = {i: F(1, 2**(i+1)) for i in range(k)}
    geom[k] = F(1, 2**k)
    out = defaultdict(F)
    for a, pa in geom.items():
        for b, pb in geom.items():
            out[a-b] += pa*pb
    return dict(out)


def hockey(p, q, multiplier):
    return sum((max(F(), value-multiplier*q.get(x, F()))
                for x, value in p.items()), F())


def clipped_pmf(p, count, n):
    out = defaultdict(F)
    for z, probability in p.items():
        out[min(n, max(0, count+z))] += probability
    return dict(out)


def scheduler(rows, tapes, mode, control_tick, mutant=False):
    """Two pre-STARTED jobs, public round robin, immediate control ACK, ordered publication.

    Results stand in for successful L2 commits. Revocation prevents future L3;
    no preexisting L3 tickets are modeled here. A public pause models a worker
    outage without notification derived from private state. Adaptive cancel may
    inspect A only AFTER it was released. No actual ledger, recovery or network.
    """
    jobs = [CountJob(rows, tape, 2) for tape in tapes]
    start = (0, 2)
    started, finished, suppressed = [False]*2, [False]*2, [False]*2
    cursor, publish = 0, 0
    authorized = True
    trace = []
    adaptive_due = None
    for tick in range(24):
        for j in range(2):
            if tick == start[j]:
                started[j] = True
                trace.append((tick, 'SCHEDULE', j))
        # Public controls take priority at a tick. They do not wait for private work.
        if tick == control_tick:
            trace.append((tick, 'CONTROL_ACK', mode))
            if mode in ('revoke', 'expire'):
                authorized = False
            if mode == 'cancel':
                suppressed[1] = True
        if adaptive_due == tick:
            trace.append((tick, 'ADAPTIVE_CANCEL_ACK', 1))
            suppressed[1] = True
        if not (mode == 'pause' and control_tick <= tick < control_tick+3):
            eligible = [j for j in range(2) if started[j] and not finished[j]]
            if eligible:
                j = next((x for x in (cursor, 1-cursor) if x in eligible))
                finished[j] = jobs[j].step()
                # A negative control: skipping zero rows exposes private completion.
                if mutant:
                    while jobs[j].pc < jobs[j].n and jobs[j].rows[jobs[j].pc] == 0:
                        jobs[j].step()
                cursor = 1-j
        while publish < 2 and finished[publish]:
            j = publish
            if authorized and not suppressed[j]:
                trace.append((tick, 'RESULT', j, jobs[j].result))
                if mode == 'adaptive_cancel' and j == 0 and jobs[j].result == 0:
                    adaptive_due = tick+1
            else:
                trace.append((tick, 'WITHHELD', j))
            publish += 1
    assert all(finished) and publish == 2
    return tuple(trace)


def public_shape(trace):
    # Only used for fixed public control policies, never adaptive_cancel.
    return tuple(event[:3] if event[1] == 'RESULT' else event for event in trace)


def main():
    checked_k = list(range(1, 65))
    raw_checks = clipped_checks = 0
    for k in checked_k:
        p = noise_pmf(k)
        assert sum(p.values()) == 1
        assert p[0] == F(1, 3)+F(2, 3*4**k)
        for z in range(1, k+1):
            expected = F(1, 3*2**z)+F(2**z, 6*2**(2*k))
            assert p[z] == expected == p[-z]
        q = {z+1: v for z, v in p.items()}
        delta = F(1, 2**(k+1))
        assert hockey(p, q, 2) == hockey(q, p, 2) == delta
        raw_checks += 2
        for n in sorted({1, k, 2*k+1}):
            for c in range(n):
                a, b = clipped_pmf(p, c, n), clipped_pmf(p, c+1, n)
                assert hockey(a, b, 2) <= delta
                assert hockey(b, a, 2) <= delta
                clipped_checks += 2
    # Actual kernel enumeration, compared with independent analytic convolution.
    kernel_cases = 0
    for k, n in ((1, 4), (2, 4), (3, 3)):
        tapes = list(product((0, 1), repeat=2*k))
        for rows in product((0, 1), repeat=n):
            outcomes = Counter()
            for tape in tapes:
                y, steps = sample(rows, tape, k)
                assert steps == n+2*k+1
                outcomes[y] += 1
                kernel_cases += 1
            distribution = {y:F(num,len(tapes)) for y,num in outcomes.items()}
            assert distribution == clipped_pmf(noise_pmf(k),sum(rows),n)
    # Full trace distributions include tick, interleavings, control content, results,
    # suppressed releases and adaptive cancellation. All random tapes enumerated.
    tape_set = list(product((0, 1), repeat=4))
    row_set = list(product((0, 1), repeat=2))
    schedules = list(product(('ack','revoke','cancel','expire','pause','adaptive_cancel'), range(18)))
    traces_checked = dp_checks = shape_checks = 0
    max_delta = F()
    witnesses = []
    per_mode = {}
    for mode, control_tick in schedules:
        distributions = {}
        shapes = set()
        for rows in row_set:
            counts = Counter()
            for tapes in product(tape_set, repeat=2):
                trace = scheduler(rows, tapes, mode, control_tick)
                counts[trace] += 1
                traces_checked += 1
                if mode != 'adaptive_cancel':
                    shapes.add(public_shape(trace))
                # ACK must remain at its publicly scheduled tick.
                assert (control_tick, 'CONTROL_ACK', mode) in trace
            distributions[rows] = {t:F(v,256) for t,v in counts.items()}
        if mode != 'adaptive_cancel':
            assert len(shapes) == 1
            shape_checks += 1
        for rows in row_set:
            for position in range(2):
                adjacent = list(rows)
                adjacent[position] ^= 1
                loss = hockey(distributions[rows],distributions[tuple(adjacent)],4)
                assert loss <= F(1,4)  # Two (ln2, 1/8)-DP instances.
                dp_checks += 1
                max_delta = max(max_delta,loss)
                per_mode[mode] = max(per_mode.get(mode,F()),loss)
    # Same constant outputs but secret-dependent work: timing/ordering mutant fails.
    # Force output zero after completion to isolate metadata from the actual release.
    for control_tick in range(18):
        traces = []
        for rows in ((0,0),(0,1)):
            trace = scheduler(rows, ((0,0,0,0),)*2, 'ack',control_tick,mutant=True)
            traces.append(public_shape(trace))
        if traces[0] != traces[1]:
            witnesses.append({'mode':'skip_zero_rows','public_control_tick':control_tick,
                              'adjacent_inputs':[[0,0],[0,1]],'metadata_traces':traces})
            break
    assert witnesses
    # RDP counterexample persists after clipping if N is sufficiently large.
    k, n = 2, 5
    p, q = clipped_pmf(noise_pmf(k),2,n), clipped_pmf(noise_pmf(k),3,n)
    assert p[0] == F(1,8) and q.get(0,F()) == 0
    # Registry/accountant negative control: zero delta would be unsound.
    k40 = noise_pmf(40)
    assert hockey(k40,{z+1:v for z,v in k40.items()},2) > 0
    report = {
        'status':'passed',
        'scope':'Exact ideal-bit distributions; synthetic padded count; finite logical scheduler. No production timing or ledger integration.',
        'mechanism':{'id':'bounded_geometric_count_v1_candidate','epsilon_exact':'ln(2)',
                     'delta_exact':'2^(-(K+1))','K40_delta':str(F(1,2**41)),
                     'fixed_random_bits':'2K','fixed_logical_steps':'N+2K+1',
                     'accountant':'separate approximate-DP epsilon/delta pair; NOT ordinary finite RDP'},
        'analytic_checks':{'K_values':checked_k,'raw_directed_privacy_checks':raw_checks,
                           'clipped_directed_privacy_checks':clipped_checks},
        'kernel_enumerated_cases':kernel_cases,
        'scheduler':{'public_schedules':len(schedules),'evaluated_runs':traces_checked,
                     'directed_joint_trace_dp_checks':dp_checks,
                     'nonadaptive_shape_checks':shape_checks,
                     'control_ack_immediate':True,'two_query_delta_bound':'1/4',
                     'max_observed_hockey_delta':str(max_delta),
                     'max_delta_by_mode':{k:str(v) for k,v in per_mode.items()}},
        'negative_controls':{'secret_dependent_work':witnesses,
                             'finite_rdp_claim':{'K':2,'N':5,'counts':[2,3],
                                                 'event':'output=0','P':'1/8','Q':'0',
                                                 'conclusion':'infinite directed Renyi divergence for every alpha>1'},
                             'pure_dp_truncation':'rejected by positive exact hockey-stick divergence'},
        'excluded':['physical clocks/cache/power/network traces','real cryptographic RNG',
                    'private-length input padding and identity dedup implementation',
                    'durable scheduler, crash recovery and database integration',
                    'production accountant and mixed-profile composition',
                    'histogram implementation','arbitrary adaptive concurrent interaction proof'],
        'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    }
    Path(__file__).with_name('fixed_work_results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('status','analytic_checks','kernel_enumerated_cases','scheduler')},indent=2))


if __name__ == '__main__':
    main()
