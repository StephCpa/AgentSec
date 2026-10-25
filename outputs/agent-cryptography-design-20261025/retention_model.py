"""Finite model of a NEW receiver-retention candidate, not a deployed GC API.

Ideal authenticated offers/receipts and collision-free transcript commitments.
Checks dual durable authorities, independently stale local replicas, commit/reply
loss, a bounded live window and sequence-derived IDs. Existing v1 wire/storage
is intentionally NOT compacted. Ghost history below is verification-only state;
the receiver retains a prefix commitment and at most W live records.
"""
from collections import deque
from dataclasses import dataclass,replace
from functools import lru_cache
import hashlib
import json
from pathlib import Path

PROFILE='mixed-receiver-retention-v2-candidate'
# Entry: (sequence, sequence-derived delivery ID, outcome, immutable event token).
# Outcome A/C abstracts valid ACCEPTED/CLOSED; actual expiry is checked elsewhere.
GENESIS='0'*64


@lru_cache(None)
def commit(previous,record):
    return hashlib.sha256(json.dumps(['recipient-final-record',2,previous,list(record)],separators=(',',':')).encode()).hexdigest()


@lru_cache(None)
def digest(history):
    out=GENESIS
    for record in history:out=commit(out,record)
    return out


@dataclass(frozen=True)
class Receiver:
    floor:int=0
    prefix:str=GENESIS
    next_seq:int=1
    live:tuple=()


@dataclass(frozen=True)
class Sender:
    final:int=0
    retired:int=0


@dataclass(frozen=True)
class State:
    history:tuple=()                 # Ghost/oracle, not retained receiver storage
    ra:Receiver=Receiver()          # Receiver authority
    rl:Receiver=Receiver()          # Receiver local copy
    sa:Sender=Sender()              # Sender authority
    sl:Sender=Sender()              # Sender local copy
    receipt:tuple=()                # One delayed/lost authenticated response
    offer:tuple=()                  # (expected floor, target, prefix digest)


def invariant(state,window):
    r=state.ra;h=state.history
    if r.floor>state.sa.final:return 'RETIRED_BEFORE_SENDER_DURABLE_CONFIRMATION'
    if r.floor<0 or r.floor>len(h):return 'INVALID_FLOOR'
    if r.next_seq!=len(h)+1:return 'LOST_NEXT_SEQUENCE'
    if r.prefix!=digest(h[:r.floor]):return 'PREFIX_COMMITMENT_MISMATCH'
    if r.live!=h[r.floor:]:return 'LOST_OR_REWRITTEN_LIVE_HISTORY'
    if len(r.live)>window:return 'LIVE_WINDOW_EXCEEDED'
    if [x[0] for x in h]!=list(range(1,len(h)+1)):return 'DUPLICATE_OR_SKIPPED_SEQUENCE'
    if len({x[1] for x in h})!=len(h):return 'REBOUND_FORGOTTEN_DELIVERY_ID'
    if any(x[1]!=x[0] for x in h):return 'NONCANONICAL_SEQUENCE_ID'
    if not 0<=state.sa.retired<=r.floor<=state.sa.final<=len(h):return 'SENDER_FRONTIER_INCONSISTENT'
    return None


def receiver_write(state,value,history,label):
    # Model both a normal local commit and authority acceptance/local commit loss.
    yield label+' / local committed',replace(state,history=history,ra=value,rl=value)
    yield label+' / local commit lost',replace(state,history=history,ra=value)


def sender_write(state,value,label,**changes):
    yield label+' / local committed',replace(state,sa=value,sl=value,**changes)
    yield label+' / local commit lost',replace(state,sa=value,**changes)


def transitions(state,n,window,mutation=None):
    r=state.ra;h=state.history;s=state.sa
    if state.rl!=r:yield 'recover receiver from authority',replace(state,rl=r)
    if state.sl!=s:yield 'recover sender from authority',replace(state,sl=s)
    if state.rl!=Receiver():yield 'restore old receiver genesis copy',replace(state,rl=Receiver())
    if state.sl!=Sender():yield 'restore old sender genesis copy',replace(state,sl=Sender())
    if state.receipt:yield 'drop delayed receipt',replace(state,receipt=())
    if state.offer:yield 'drop retirement offer',replace(state,offer=())

    if state.rl==r or mutation=='omit_local_fence':
        local=state.rl
        if len(h)<n and (len(local.live)<window or mutation=='omit_window'):
            seq=local.next_seq
            ids=[seq]
            if mutation=='free_text_id' and local.floor:ids.append(h[0][1])
            for did in set(ids):
                if any(x[1]==did for x in local.live):continue
                if did!=seq and mutation!='free_text_id':continue
                for outcome in ('A','C'):
                    record=(seq,did,outcome,'event-'+str(len(h)+1))
                    value=replace(local,next_seq=seq+1,live=local.live+(record,))
                    yield from receiver_write(state,value,h+(record,),'receiver finalizes '+str(record))
        # Recipient only signs a first-event receipt from a current committed copy.
        if local.live:
            for record in local.live:
                if state.receipt!=record:yield 'emit receipt for sequence '+str(record[0]),replace(state,receipt=record)

    if state.sl==s:
        if state.receipt and state.receipt[0]==s.final+1:
            record=state.receipt
            if record==h[s.final]:
                yield from sender_write(state,replace(s,final=s.final+1),'sender confirms sequence '+str(record[0]),receipt=())
        max_target=s.final
        if mutation=='volatile_ack_offer' and state.receipt and state.receipt[0]==s.final+1:
            max_target=s.final+1
        for target in range(s.retired+1,max_target+1):
            offer=(s.retired,target,digest(h[:target]))
            if state.offer!=offer:yield 'sign retire offer '+str(target),replace(state,offer=offer)
        # Authenticated receiver checkpoint can be re-read after a lost reply;
        # sender recomputes the prefix from its still-retained confirmed history.
        if r.floor>s.retired and r.floor<=s.final and r.prefix==digest(h[:r.floor]):
            yield from sender_write(state,replace(s,retired=r.floor),'sender records retire checkpoint')

    if state.rl==r:
        offers=[]
        if state.offer:offers.append(state.offer)
        if mutation=='retire_without_offer' and r.live:
            offers.append((r.floor,r.next_seq-1,digest(h)))
        for base,target,root in offers:
            if base!=r.floor or not r.floor<target<r.next_seq:continue
            if root!=digest(h[:target]):continue
            count=target-r.floor
            value=replace(r,floor=target,prefix=root,live=r.live[count:])
            if mutation=='forget_next':value=replace(value,next_seq=max([x[0] for x in value.live],default=0)+1)
            if mutation=='delete_before_floor':value=replace(r,live=r.live[count:])
            yield from receiver_write(state,value,h,'receiver retires through '+str(target))


def retired_response(state,seq):
    # Deliberately does NOT assert ACCEPTED/CLOSED or reconstruct forgotten time.
    if seq<=state.ra.floor:return ('RETIRED',state.ra.floor,state.ra.prefix)
    for record in state.ra.live:
        if record[0]==seq:return ('FINAL',record)
    return ('NO_FINAL_RECORD',)


def check(n,window,mutation=None,max_states=1000000):
    initial=State();queue=deque([initial]);parents={initial:None};edges=0;terminal_count=0
    max_live=0;retired_queries=0
    while queue:
        current=queue.popleft();max_live=max(max_live,len(current.ra.live))
        if current.ra.floor==n:terminal_count+=1
        for seq in range(1,current.ra.floor+1):
            assert retired_response(current,seq)[0]=='RETIRED'
            retired_queries+=1
        for label,next_state in transitions(current,n,window,mutation):
            if next_state==current:continue
            edges+=1;error=invariant(next_state,window)
            if error:
                trace=[label];cursor=current
                while parents[cursor] is not None:
                    prev,action=parents[cursor];trace.append(action);cursor=prev
                trace.reverse()
                return dict(status='counterexample',mutation=mutation,error=error,states=len(parents),edges=edges,trace=trace)
            if next_state not in parents:
                if len(parents)>=max_states:raise RuntimeError('model state limit reached; no completeness claim')
                parents[next_state]=(current,label);queue.append(next_state)
    assert terminal_count>0
    return dict(status='passed',operations=n,window=window,states=len(parents),edges=edges,
                fully_retired_states=terminal_count,maximum_live_records=max_live,retired_queries=retired_queries)


def constructive_drain(state,n,window):
    """Fair fault-free continuation exists; NOT liveness under permanent outage."""
    state=replace(state,rl=state.ra,sl=state.sa)
    for _ in range(20*n+20):
        if state.ra.floor==n:return state
        r=state.ra;s=state.sa
        # Priority: learn/reconcile known final facts, retire, then accept more.
        if s.final<len(state.history):
            record=state.history[s.final]
            assert record in r.live
            state=replace(state,sa=replace(s,final=s.final+1),sl=replace(s,final=s.final+1),receipt=())
        elif r.floor<s.final:
            value=replace(r,floor=s.final,prefix=digest(state.history[:s.final]),live=state.history[s.final:])
            state=replace(state,ra=value,rl=value)
        elif s.retired<r.floor:
            value=replace(s,retired=r.floor);state=replace(state,sa=value,sl=value)
        elif len(state.history)<n:
            assert len(r.live)<window
            seq=r.next_seq;record=(seq,seq,'A','event-'+str(seq));h=state.history+(record,)
            value=replace(r,next_seq=seq+1,live=r.live+(record,));state=replace(state,history=h,ra=value,rl=value)
        else:raise AssertionError('no safe progress')
        assert invariant(state,window) is None
    raise AssertionError('drain bound exceeded')


def delayed_receipt_examples():
    record=(1,1,'A','event-1');r=Receiver(next_seq=2,live=(record,));state=State(history=(record,),ra=r,rl=r)
    # Receiver has committed, but the reply is absent and sender has no durable fact.
    assert not any('retires through' in label for label,_ in transitions(state,2,1))
    assert constructive_drain(state,2,1).ra.floor==2
    lost_r=replace(state,rl=Receiver())
    assert constructive_drain(lost_r,2,1).ra.floor==2
    # A watermark cannot reconstruct the original event. Returning CLOSED here
    # would contradict the ghost A history, even if the digest is authentic.
    retired=replace(state,ra=Receiver(1,digest((record,)),2,()),sa=Sender(1,0))
    assert retired_response(retired,1)[0]=='RETIRED'
    return dict(lost_receipt_not_retired=True,authority_only_record_has_safe_drain=True,
                retired_is_not_closed=True,full_history_not_reconstructed_from_commitment=True)


def main():
    cases=[check(n,w) for n,w in [(1,1),(2,1),(2,2),(3,1)]]
    mutations=['retire_without_offer','volatile_ack_offer','free_text_id','forget_next','delete_before_floor','omit_local_fence','omit_window']
    negatives=[check(3,1,mode) for mode in mutations]
    assert all(x['status']=='counterexample' for x in negatives)
    examples=delayed_receipt_examples()
    # Concrete long-run candidate schedule demonstrates the operational row
    # bound, while ghost/sender history remains intentionally unbounded.
    long_run=constructive_drain(State(),1000,2)
    assert long_run.ra.floor==1000 and not long_run.ra.live
    report=dict(profile=PROFILE,status='passed',exhaustive_cases=cases,weakening_counterexamples=negatives,
        recovery_examples=examples,constructive_operations=1000,constructive_final_live_records=0,
        assumptions=['ideal unforgeable messages','collision-free transcript commitment abstraction','trusted sender signs offers only after authoritative confirmation','linearizable nonrollback sender/receiver authorities','finite fixed route and operation bound in enumeration','fault-free fair continuation for drain example'],
        exclusions=['production DB/crypto/network implementation','arbitrary physical timing/DP observation proof','indefinite liveness under outages or adversarial noncooperation','bounded total audit archive or witness commit history','existing v1 compatibility or migration','exact old-outcome recovery after retirement without an archive'],
        proof_status='finite safety exploration plus explicit induction obligations and counterexamples, not complete deployed protocol proof',
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    Path(__file__).with_name('retention_results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'cases':cases,'counterexamples':[{'mutation':x['mutation'],'error':x['error'],'trace_length':len(x['trace'])} for x in negatives],'long_run':1000},indent=2))


if __name__=='__main__':main()
