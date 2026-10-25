"""Finite relational observation model, not a DP sampler or full proof.

Both operations always output the constant zero (an ideal 0-DP release).
Private input may change hidden completion steps. The observer sees event order
and status values, but no clocks or step numbers. Compare identical public
control schedules across all hidden completion schedules.
"""
from itertools import product
import hashlib
import json
from pathlib import Path


def readiness_trace(completion_step):
    return ('ACCEPTED', 'READY' if completion_step <= 1 else 'PENDING', 'RESULT:0')


def batch_trace(completions, control_step, mode):
    trace = ['BATCH_ACCEPTED']
    next_output = 0
    control_waiting = False
    control_done = False
    for step in range(max(*completions, control_step)+1):
        # A public control command arrives at a fixed scheduler position.
        # Its response is unrelated to private data, but its interleaving may not be.
        if step == control_step:
            if mode == 'immediate_ack':
                trace.append('CONTROL_ACK')
                control_done = True
            else:
                control_waiting = True
        if mode == 'immediate_ack':
            # Output values remain ordered A then B, regardless of completion order.
            while next_output < 2 and completions[next_output] <= step:
                trace.append(('A' if next_output == 0 else 'B')+':0')
                next_output += 1
        elif mode == 'serialized_barrier':
            # Toy sufficient restriction: no externally visible control response
            # while a batch is incomplete. No speculative polling or cancellation
            # status. This trades away responsiveness; not our full target system.
            if next_output == 0 and all(t <= step for t in completions):
                trace.extend(('A:0','B:0'))
                next_output = 2
            if next_output == 2 and control_waiting and not control_done:
                trace.append('CONTROL_ACK')
                control_done = True
        else:
            raise ValueError(mode)
    assert next_output == 2 and control_done
    return tuple(trace)


def main():
    schedules = list(product((1,2,3),repeat=2))
    results = []
    for control_step in range(4):
        for mode in ('immediate_ack','serialized_barrier'):
            traces = {}
            for schedule in schedules:
                trace=batch_trace(schedule,control_step,mode)
                traces.setdefault(trace,[]).append(schedule)
            results.append(dict(mode=mode,public_control_step=control_step,
                                hidden_schedules=len(schedules),
                                distinct_observable_traces=len(traces),
                                examples=[dict(trace=list(t),hidden_schedules=ss)
                                          for t,ss in traces.items()]))
    status_examples=[dict(hidden_completion=c,trace=list(readiness_trace(c))) for c in (1,2)]
    assert status_examples[0]['trace'] != status_examples[1]['trace']
    assert any(r['distinct_observable_traces']>1 for r in results if r['mode']=='immediate_ack')
    assert all(r['distinct_observable_traces']==1 for r in results if r['mode']=='serialized_barrier')
    report={
        'scope':'Two constant-output operations, 9 hidden completion schedules, 4 fixed public control schedules; complete terminating traces without clocks.',
        'findings':[
            'READY versus PENDING reveals hidden runtime even when outputs are identical.',
            'Ordering result messages alone does not hide interleaving with unrelated control acknowledgments.',
            'Serializing all observable responses behind a batch barrier removes these two leaks in this finite toy model only.'
        ],
        'readiness_counterexample':status_examples,
        'batch_cases':results,
        'excluded':['physical timing','nontermination','data-dependent failures','revocation scheduling',
                    'expiry scheduling','variable DP outputs','adaptive query parameters',
                    'actual network','production implementation'],
        'proof_status':'counterexample evidence and finite relational check; no full-system DP proof',
        'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    }
    Path(__file__).with_name('observation_results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'readiness_counterexample':status_examples,
                      'batch_cases':[{k:r[k] for k in ('mode','public_control_step','hidden_schedules','distinct_observable_traces')} for r in results]},indent=2))


if __name__=='__main__':
    main()
