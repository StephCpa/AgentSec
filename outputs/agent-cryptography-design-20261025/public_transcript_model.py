"""Executable public-transcript design, not a production gateway or proof.

Two fixed-cost mechanisms, dynamic registration, controls, polling, two routes,
delivery/ACK loss, retries, expiry, and first-outcome reconciliation. Exact
probability enumeration uses toy K=1; operational shape uses configurable K.
The normal simulator accepts only public configuration and approved DP values.
Raw data is passed ONLY to the enumerator's mechanism oracle and negative
controls, never to normal scheduling, status or transport decisions.
"""
from collections import defaultdict
from dataclasses import dataclass
from fractions import Fraction as F
from itertools import product
import hashlib
import json
from pathlib import Path

from fixed_work_model import noise_pmf, clipped_pmf, hockey

N = 2
B = 2
K = 1


@dataclass(frozen=True)
class Plan:
    query: str = 'concurrent'  # concurrent or adaptive after A is received
    control: str = 'none'     # cancel B, revoke, pause, or no-op
    control_round: int = 4
    transport: str = 'normal' # loss/reorder decisions use public state only
    routes: tuple = (0, 1)
    ordering: str = 'global'  # required profile; per_route is comparison only
    k: int = K
    rounds: int = 40


class DrawNeeded(Exception):
    def __init__(self, operation, mechanism):
        self.operation, self.mechanism = operation, mechanism


def mechanism_distribution(slots, mechanism, k=K):
    """Ideal complete output distribution; contribution-bounded private input."""
    if mechanism not in ('count','histogram') or type(k) is not int or not 1<=k<=40:
        raise ValueError('mechanism profile')
    if len(slots) != N or any(type(x) is not int or not 0 <= x <= B for x in slots):
        raise ValueError('private input contract')
    noise = noise_pmf(k)
    counts = [sum(x != 0 for x in slots)] if mechanism == 'count' else [slots.count(j) for j in range(1, B+1)]
    dimensions = [clipped_pmf(noise, count, N) for count in counts]
    out = {}
    for values in product(*(list(p) for p in dimensions)):
        mass = F(1)
        for value, pmf in zip(values, dimensions): mass *= pmf[value]
        out[tuple(values)] = mass
    assert sum(out.values()) == 1
    return out


def simulate(plan, draws, *, mutant=None, private_slots=None):
    """Public simulation from bounded mechanism results and public environment.

    Draws are ordered (operation, kind, result) records available privately at
    L1, released only in delivery packets. They can be supplied lazily by the
    exact enumerator. A missing draw requests another independent mechanism.
    No cryptography, actual DB, physical clock, OS or unbounded failures here.
    """
    if plan.query not in ('concurrent','adaptive') or plan.control not in ('none','cancel','revoke','pause'):
        raise ValueError('public plan')
    if plan.transport not in ('normal','drop_packet','drop_ack','reorder','forever_drop'):
        raise ValueError('public transport')
    if plan.ordering not in ('global','per_route'):raise ValueError('public ordering')
    if tuple(plan.routes) not in ((0,0),(0,1),(1,0)) or type(plan.k) is not int or not 1<=plan.k<=40:
        raise ValueError('public shape')
    if (type(plan.rounds) is not int or not 1<=plan.rounds<=10000 or
            type(plan.control_round) is not int or not 0<=plan.control_round<plan.rounds):
        raise ValueError('public round bounds')
    if mutant is None and private_slots is not None:raise ValueError('normal simulator must not receive raw data')
    if mutant not in (None,'readiness_poll','skip_zero_work','private_failure','private_network'):
        raise ValueError('negative control')
    trace=[];jobs=[];cursor=0;publish=0;app_cursor=0;draw_index=0;active=True
    spent=0;reserved=0;free=2;next_route_seq={0:1,1:1};outboxes=[]
    receiver={};seen_results={};adaptive_decided=False
    public_outcomes={};round_number=0

    def emit(*event):trace.append((round_number,)+event)

    def submit(oid, mechanism, route):
        nonlocal free,reserved
        emit('REQUEST','SUBMIT',oid,mechanism,route)
        if not active or free == 0:
            emit('REPLY','DENIED',oid,'AUTHORIZATION' if not active else 'BUDGET')
            return
        work=1+(N+2*plan.k+1)*(1 if mechanism=='count' else B)
        jobs.append(dict(id=oid,mechanism=mechanism,route=route,work=work,pc=0,
                         state='RESERVED',suppressed=False,value=None))
        free-=1;reserved+=1
        emit('REPLY','RECORDED',oid,len(jobs))

    def settle(job, refund):
        nonlocal spent,reserved,free
        reserved-=1
        if refund:free+=1
        else:spent+=1

    for round_number in range(plan.rounds):
        emit('ROUND')
        if round_number==0:
            submit('A','count',plan.routes[0])
            if plan.query=='concurrent':submit('B','histogram',plan.routes[1])
        if plan.query=='adaptive' and not adaptive_decided and 'A' in seen_results:
            # This is a public adversary decision made only after actual receipt.
            # The second mechanism is conditionally selected from a fixed-cost
            # approved registry. All branches have at most two calls.
            adaptive_decided=True
            kind='count' if seen_results['A'][0]==0 else 'histogram'
            emit('ADAPTIVE_CHOICE',kind)
            submit('B',kind,plan.routes[1])
        if round_number==plan.control_round:
            emit('REQUEST','CONTROL',plan.control)
            if plan.control=='revoke':active=False
            if plan.control=='cancel':
                target=next((j for j in jobs if j['id']=='B'),None)
                if target is not None and 'B' not in public_outcomes:
                    if target['state'] in ('RESERVED','STARTED'):
                        refund=target['state']=='RESERVED';settle(target,refund)
                        target['state']='CANCELED' if refund else 'BURNED'
                    target['suppressed']=True
            # ACK acknowledges command application, not private completion or
            # downstream absence of an effect. Unknown/already-final target is
            # idempotently handled without a private-state status code.
            emit('REPLY','CONTROL_RECORDED',plan.control)
        # Polling exposes only the durable public journal's final outcome, not
        # private completion, partial counts, internal failure or tentative L2.
        for job in jobs:
            emit('REQUEST','POLL',job['id'])
            if mutant=='readiness_poll':
                emit('REPLY','READY' if any(private_slots) else 'PENDING',job['id'])
            else:emit('REPLY','RECORDED',job['id'],public_outcomes.get(job['id'],'UNPUBLISHED'))
        paused=plan.control=='pause' and plan.control_round<=round_number<plan.control_round+3
        candidates=[i for i,j in enumerate(jobs) if j['pc']<j['work']]
        if candidates and not paused:
            index=next((i for i in candidates if i>=cursor),candidates[0]);job=jobs[index];cursor=index+1
            if job['state']=='RESERVED':
                if not active:
                    job['state']='CANCELED';settle(job,True)
                else:
                    if draw_index==len(draws):raise DrawNeeded(job['id'],job['mechanism'])
                    oid,kind,value=draws[draw_index];draw_index+=1
                    if oid!=job['id'] or kind!=job['mechanism']:raise ValueError('draw action mismatch')
                    width=1 if kind=='count' else B
                    if type(value) is not tuple or len(value)!=width or any(type(x) is not int or not 0<=x<=N for x in value):
                        raise ValueError('draw shape')
                    job['value']=value;job['state']='STARTED'
            job['pc']+=1
            if mutant=='skip_zero_work' and job['pc']==2 and not any(private_slots):job['pc']+=1
            if job['pc']==job['work'] and job['state']=='STARTED':
                job['state']='COMMITTED';settle(job,False)
        while publish<len(jobs) and jobs[publish]['pc']==jobs[publish]['work']:
            job=jobs[publish];publish+=1
            allowed=job['state']=='COMMITTED' and not job['suppressed'] and active
            if mutant=='private_failure' and any(private_slots):allowed=False
            # Atomic conceptual publication/L3 decision. This is a design
            # obligation, not what current separate production methods prove.
            if allowed:
                seq=next_route_seq[job['route']];next_route_seq[job['route']]+=1
                outboxes.append(dict(job=job,seq=seq,issued=round_number,expires=round_number+4,
                                     attempts=0,done=False))
                public_outcomes[job['id']]='ADMITTED'
                emit('JOURNAL','ADMITTED',job['id'],job['route'],seq)
            else:
                public_outcomes[job['id']]='WITHHELD'
                emit('JOURNAL','WITHHELD',job['id'])
        # Required profile gates a later ticket on the earlier ticket's final
        # acknowledgement. per_route is a weaker comparison, not a replacement
        # for the original ordered-delivery requirement. Controls remain live.
        for route in (1,0):
            box=next((x for x in outboxes if x['job']['route']==route and not x['done']),None)
            if box is None:continue
            if plan.ordering=='global' and box is not next(x for x in outboxes if not x['done']):continue
            if plan.transport=='reorder' and route==0 and round_number<24:continue
            box['attempts']+=1;job=box['job'];key=(route,box['seq'])
            terminal=round_number>=box['expires']
            kind='TERMINAL' if terminal else 'DELIVERY'
            value=() if terminal else job['value']
            emit('SEND',kind,route,box['seq'],job['id'],value)
            drop=plan.transport=='forever_drop' or (plan.transport=='drop_packet' and box['attempts']==1)
            if mutant=='private_network' and any(private_slots) and box['attempts']==1:drop=True
            if drop:
                emit('NETWORK','PACKET_LOST',route,box['seq']);continue
            if key not in receiver:
                receiver[key]=('CLOSED' if terminal else 'ACCEPTED',round_number)
            outcome,event_at=receiver[key]
            if not terminal and outcome=='ACCEPTED':
                seen_results[job['id']]=job['value']
                emit('RECEIVE','RESULT',route,box['seq'],job['id'],job['value'])
            else:emit('RECEIVE',outcome,route,box['seq'],job['id'])
            if plan.transport=='drop_ack' and box['attempts']==1:
                emit('NETWORK','ACK_LOST',route,box['seq']);continue
            emit('ACK',outcome,route,box['seq'],job['id'],event_at)
            box['done']=True;public_outcomes[job['id']]=outcome
        # Canonical application final events include pre-L3 WITHHELD too. A
        # later cancellation cannot skip an unresolved earlier delivery. Raw
        # transport observations remain included separately in the DP view.
        while app_cursor<len(jobs) and public_outcomes.get(jobs[app_cursor]['id']) in ('ACCEPTED','CLOSED','WITHHELD'):
            oid=jobs[app_cursor]['id'];outcome=public_outcomes[oid]
            emit('APP_FINAL',app_cursor+1,oid,outcome)
            app_cursor+=1
        assert free+reserved+spent==2 and min(free,reserved,spent)>=0
    # Bounded prefix is explicit. Never pretend packet loss establishes CLOSED
    # or that a permanently unresponsive receiver has completed delivery.
    pending=any(not box['done'] for box in outboxes) or publish<len(jobs) or app_cursor<len(jobs)
    emit('PREFIX_END','ACTIVE' if pending else 'QUIESCENT')
    return tuple(trace),dict(draws=draw_index,free=free,reserved=reserved,spent=spent,
                             outcomes=dict(public_outcomes),pending=pending)


def trace_distribution(slots, plan):
    distribution=defaultdict(F);paths=0;calls=set()
    def explore(draws,mass):
        nonlocal paths
        try:trace,state=simulate(plan,draws)
        except DrawNeeded as need:
            assert len(draws)<2
            for value,probability in mechanism_distribution(slots,need.mechanism,plan.k).items():
                explore(draws+[(need.operation,need.mechanism,value)],mass*probability)
            return
        distribution[trace]+=mass;paths+=1;calls.add(state['draws'])
    explore([],F(1))
    assert sum(distribution.values())==1
    return dict(distribution),paths,sorted(calls)


def run_checks():
    datasets=list(product(range(B+1),repeat=N))
    neighbors=[]
    for slots in datasets:
        for i in range(N):
            if slots[i]:
                adjacent=list(slots);adjacent[i]=0
                neighbors.extend([(slots,tuple(adjacent)),(tuple(adjacent),slots)])
    plans=[Plan(query=q,control=c,control_round=t,transport=n,routes=route,ordering=ordering)
           for q,c,t,n,route,ordering in product(('concurrent','adaptive'),('none','cancel','revoke','pause'),
                                      (0,4,12),('normal','drop_packet','drop_ack','reorder','forever_drop'),((0,0),(0,1)),('global','per_route'))]
    checks=paths=0;worst=F();worst_plan=None;max_distinct=0
    for plan in plans:
        distributions={}
        for slots in datasets:
            pmf,num,_=trace_distribution(slots,plan);distributions[slots]=pmf;paths+=num
            max_distinct=max(max_distinct,len(pmf))
        for a,b in neighbors:
            loss=hockey(distributions[a],distributions[b],4)
            assert loss<=F(1,2), (plan,a,b,loss)  # K1: two fixed (ln2,1/4) bounds.
            checks+=1
            if loss>worst:worst=loss;worst_plan=plan.__dict__
    negatives=[]
    constant=[('A','count',(0,)),('B','histogram',(0,0))]
    for mutant in ('readiness_poll','skip_zero_work','private_failure','private_network'):
        a,_=simulate(Plan(),constant,mutant=mutant,private_slots=(0,0))
        b,_=simulate(Plan(),constant,mutant=mutant,private_slots=(0,1))
        assert a!=b
        first=next(i for i,(x,y) in enumerate(zip(a,b)) if x!=y)
        negatives.append(dict(mutant=mutant,constant_approved_outputs=True,first_difference=[a[first],b[first]],
                              directed_hockey_loss='1',claimed_two_query_delta='1/2'))
    return dict(passed=True,scope='Exact finite K1 count/histogram protocol distributions; public logical rounds and explicit public fault plans. Not runtime or cryptographic refinement.',
                plans=len(plans),required_global_order_plans=240,comparison_per_route_plans=240,
                datasets=len(datasets),directed_neighbors=len(neighbors),
                complete_distribution_checks=checks,enumerated_execution_paths=paths,
                max_distinct_traces=max_distinct,epsilon_multiplier=4,delta_bound='1/2',
                maximum_observed_hockey_loss=str(worst),maximum_loss_plan=worst_plan,
                negative_controls=negatives,
                production_K40_bound='Conditional design target only: at most two fixed-cost releases compose to (2 ln 2, 2^-40), before conservative ledger rounding; full deployment observation proof absent.',
                covers=['dynamic second-query mechanism choice after received DP output','concurrent jobs with fixed public logical work','immediate public control acknowledgement','public-journal polling','pre-L3 WITHHELD and cancellation dummy work','required global delivery gate and ordered application final events; per-route comparison separately labeled','packet/ACK loss and original-result retry','expiry and ACCEPTED/CLOSED reconciliation','colluding recipients see all sends, receives, statuses and logical rounds','permanent packet loss stays ACTIVE at finite prefix'],
                excluded=['unbounded-state or arbitrary-adversary proof','physical timing/packet size/CPU/DB leakage','private-dependent outages or failure selection','actual public network gateway','crypto encoding/signatures and replay protocol refinement','production liveness or independent nonrollback guarantees'])


if __name__=='__main__':
    report=run_checks()
    report['source_sha256']={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                             for name in ('public_transcript_model.py','fixed_work_model.py')}
    Path(__file__).with_name('public_transcript_results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('covers','excluded','source_sha256')},ensure_ascii=False,indent=2))
