"""Test-only private-prefix oracle. No private values go into public generation.

Shares existing CountJob/HistogramJob kernels, so this is not independent crypto
verification. It compares the durable encrypted integration against kernel steps.
"""
from copy import deepcopy
from fixed_work_model import CountJob
from histogram_kernel import HistogramJob
from state_relation import StateRelationMismatch,digest
from public_observation import seed_for_output_one


def planned_tape(slots,hist,target=1):
    tape=seed_for_output_one(sum(slots)+1-target)
    return tape[:10]+bytes(30) if hist else tape


def prefixes(slots,hist,tape):
    if hist:
        job=HistogramJob(slots,tape,capacity=3,buckets=['one','two','three','four'])
        def state():return dict(counts=job._counts,alive=job._alive,g=job._g,outputs=job._outputs)
    else:
        bits=[(byte>>shift)&1 for byte in tape[:10] for shift in range(7,-1,-1)]
        job=CountJob(slots,bits,40)
        def state():return dict(count_value=job.count,alive0=job.alive[0],alive1=job.alive[1],g0=job.g[0],g1=job.g[1])
    result=[(deepcopy(state()),None),(deepcopy(state()),None)] # pc=0, durable L1 pc=1
    for _ in range(job.work):
        job.step();output=job.result
        if output is not None and not hist:output=output.to_bytes(8,'big')
        result.append((deepcopy(state()),output))
    return result


def assert_private_relation(runtime):
    model=runtime.simulator.state
    if not model.jobs:return {'R10':digest(dict(operations=0))}
    if len(model.jobs)!=1:raise StateRelationMismatch('R10.single_operation')
    job=model.jobs[0];hist=job['action']['operation_kind']=='histogram'
    actual=runtime.l.op('t',job['id']);row=runtime.l.db.execute('SELECT * FROM jobs WHERE tenant=? AND operation_id=?',('t',job['id'])).fetchone()
    expected_seed=planned_tape(runtime.slots,hist) if job['state'] in ('STARTED','COMMITTED') else None
    if actual['seed']!=expected_seed:raise StateRelationMismatch('R10.durable_tape')
    key=(hist,planned_tape(runtime.slots,hist))
    if key not in runtime.prefix_cache:runtime.prefix_cache[key]=prefixes(runtime.slots,hist,key[1])
    expected_state,expected_result=runtime.prefix_cache[key][job['pc']]
    if runtime.l.load_private_state(row)!=expected_state:raise StateRelationMismatch('R10.private_prefix')
    if actual['result']!=expected_result:raise StateRelationMismatch('R10.result_prefix')
    # Digest only public counters and successful predicates. Private values/tape
    # digests would differ across conditioned neighboring datasets.
    return {'R10':digest(dict(pc=job['pc'],seed_present=expected_seed is not None,result_present=expected_result is not None,
        tape_matches=True,prefix_matches=True,result_matches=True,committed_l1_calls=len(runtime.runtime_draws)))}
