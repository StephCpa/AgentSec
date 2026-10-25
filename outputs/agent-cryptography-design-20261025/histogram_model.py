"""Exact rational checks for the bounded independent-noise histogram candidate.

Finite enumeration supports the stated analytic factorization argument. It is
not a production RNG review, contribution pipeline or ledger/network DP proof.
"""
from collections import Counter,defaultdict
from fractions import Fraction as F
from itertools import product
from pathlib import Path
import hashlib
import json
from histogram_kernel import HistogramJob,pack_bits,fresh_tape,decode_result,dimensions,validate_tape
from fixed_work_model import noise_pmf,clipped_pmf,hockey,sample


def joint_pmf(counts,n,k):
    marginals=[clipped_pmf(noise_pmf(k),c,n) for c in counts]
    out={}
    for entries in product(*(tuple(p.items()) for p in marginals)):
        y=tuple(v[0] for v in entries);prob=F(1)
        for _,p in entries:prob*=p
        out[y]=prob
    return out


def common_noise_pmf(counts,n,k):
    out=defaultdict(F)
    for z,p in noise_pmf(k).items():out[tuple(min(n,max(0,c+z)) for c in counts)]+=p
    return dict(out)


def expect_invalid(call):
    try:call()
    except ValueError:return
    raise AssertionError('invalid input accepted')


def main():
    kernel_cases=distribution_checks=b1_cases=shape_checks=0
    # Exhaust all private categorical snapshots and independent bit tapes in
    # these public toy configurations; compare complete joint PMFs, not marginals.
    configurations=((1,1,3),(2,1,3),(3,1,3),(2,2,2),(3,2,2),(2,3,2)) # B,K,N
    for b,k,n in configurations:
        buckets=tuple('bucket-'+str(j) for j in range(b))
        tapes=[tuple(bits) for bits in product((0,1),repeat=2*k*b)]
        shapes=set()
        for rows in product(range(b+1),repeat=n):
            outcomes=Counter()
            for bits in tapes:
                job=HistogramJob(rows,pack_bits(bits),capacity=n,buckets=buckets,k=k);positions=[]
                for t in range(job.work):
                    assert job.result is None # no partial public output
                    positions.append(job.public_position());done=job.step();assert done==(t+1==job.work)
                assert job.work==b*(n+2*k+1)
                y=decode_result(job.result,b,n);outcomes[y]+=1;kernel_cases+=1;shapes.add(tuple(positions))
                if b==1:
                    answer,steps=sample(tuple(int(x==1) for x in rows),bits,k)
                    assert y==(answer,) and steps==job.work;b1_cases+=1
            counts=tuple(rows.count(j+1) for j in range(b));empirical={y:F(num,len(tapes)) for y,num in outcomes.items()}
            assert empirical==joint_pmf(counts,n,k);distribution_checks+=1
        assert len(shapes)==1;shape_checks+=1
    # General scalar exact identity for K=1..64, with independent unchanged
    # coordinates summing to one. Finite vector enumeration below verifies it
    # directly after clipping across all feasible histograms in each setting.
    scalar_checks=0
    for k in range(1,65):
        p=noise_pmf(k);q={z+1:v for z,v in p.items()};delta=F(1,2**(k+1))
        assert sum(p.values())==1 and hockey(p,q,2)==hockey(q,p,2)==delta;scalar_checks+=2
    privacy_checks=0;max_ratio=F();equality_examples=[];tight_buckets=set()
    for b,k,n in product(range(1,4),range(1,5),range(1,6)):
        vectors=[c for c in product(range(n+1),repeat=b) if sum(c)<=n]
        pmfs={c:joint_pmf(c,n,k) for c in vectors};delta=F(1,2**(k+1))
        for c in vectors:
            if sum(c)==n:continue
            for j in range(b):
                adjacent=list(c);adjacent[j]+=1;adjacent=tuple(adjacent)
                for p,q in ((pmfs[c],pmfs[adjacent]),(pmfs[adjacent],pmfs[c])):
                    loss=hockey(p,q,2);assert loss<=delta;max_ratio=max(max_ratio,loss/delta);privacy_checks+=1
                    if loss==delta and b not in tight_buckets:
                        equality_examples.append(dict(B=b,K=k,N=n,counts=c,adjacent=adjacent,loss=str(loss)));tight_buckets.add(b)
    # K=40 production candidate dimensions and deterministic replay tests. These
    # use synthetic tape patterns, not empirical evidence of RNG correctness.
    replay_cases=0
    for b,n in ((1,1),(2,7),(16,5),(64,3)):
        buckets=tuple('b'+str(j) for j in range(b));rows=tuple(j%(b+1) for j in range(n))
        for byte in (0,255,0x55,0xaa):
            calls=[]
            def bits(size):calls.append(size);return bytes([byte])*size
            tape=fresh_tape(b,randbytes=bits);assert calls==[10*b] and len(tape)==10*b
            a=HistogramJob(rows,tape,capacity=n,buckets=buckets);a.run()
            # Re-instantiation with exact tape and snapshot must reproduce output.
            z=HistogramJob(rows,tape,capacity=n,buckets=buckets);z.run()
            assert a.result==z.result and len(a.result)==8*b and a.work==b*(n+81)
            decode_result(a.result,b,n);replay_cases+=1
    # Deliberately distinct per-bucket bit patterns test offsets beyond a
    # 32-byte legacy count seed; no pseudorandom expansion is assumed here.
    layout_cases=0
    for b in (1,2,4,16,64):
        n=64;bits=[];expected=[]
        rows=tuple(range(1,b+1))+(0,)*(n-b)
        for j in range(b):
            positive=j%41;negative=(2*j+7)%41
            bits.extend([1]*positive+[0]*(40-positive)+[1]*negative+[0]*(40-negative))
            expected.append(min(n,max(0,1+positive-negative)))
        job=HistogramJob(rows,pack_bits(bits),capacity=n,buckets=tuple('b'+str(j) for j in range(b)))
        assert decode_result(job.run(),b,n)==tuple(expected);layout_cases+=1
    # Canonical padding and source-output checks (toy K may not align to byte).
    for b,k in product(range(1,5),range(1,5)):
        bits,size=dimensions(b,k);tape=fresh_tape(b,k,lambda size:bytes([255])*size);validate_tape(tape,b,k)
        if bits%8:expect_invalid(lambda:validate_tape(tape[:-1]+bytes([tape[-1]|1]),b,k))
    invalids=[lambda:HistogramJob([1],b'\0'*10,capacity=2,buckets=['a']),
        lambda:HistogramJob([2],b'\0'*10,capacity=1,buckets=['a']),
        lambda:HistogramJob([True],b'\0'*10,capacity=1,buckets=['a']),
        lambda:HistogramJob([0],b'\0'*20,capacity=1,buckets=['a','a']),
        lambda:HistogramJob([0],b'\0'*10,capacity=1,buckets=[]),
        lambda:HistogramJob([0],b'\0'*32,capacity=1,buckets=['a','b','c','d']),
        lambda:fresh_tape(2,randbytes=lambda n:b'\0'),
        lambda:decode_result(b'\0'*7,1,1),lambda:decode_result((2).to_bytes(8,'big'),1,1)]
    for call in invalids:expect_invalid(call)
    # Negative controls: independent noise and user add/remove adjacency matter.
    k,n=2,5;delta=F(1,8)
    shared=hockey(common_noise_pmf((0,0),n,k),common_noise_pmf((1,0),n,k),2)
    assert shared>delta
    replacement=hockey(joint_pmf((1,0),n,k),joint_pmf((0,1),n,k),2)
    assert replacement>delta
    multi=hockey(joint_pmf((0,0),n,k),joint_pmf((1,1),n,k),2)
    assert multi>delta
    # An output event on one coordinate already exhibits a support hole.
    p,q=joint_pmf((2,0),n,k),joint_pmf((3,0),n,k)
    p0=sum(v for y,v in p.items() if y[0]==0);q0=sum(v for y,v in q.items() if y[0]==0)
    assert p0==F(1,8) and q0==0
    report=dict(status='passed',mechanism='bounded_geometric_histogram_v1_candidate',scope='Exact ideal-bit joint PMFs and fixed logical work; synthetic categorical snapshots; no signed ledger/network integration',
        guarantee=dict(adjacency='add/remove one user assigned to one public bucket',epsilon='ln(2)',delta='2^(-(K+1))',K40_delta=str(F(1,2**41)),ordinary_rdp='infinite in general',bucket_count_multiplier=1),
        dimensions=dict(profile_K=40,bucket_count_range=[1,64],capacity_range=[1,65535],random_bits='2KB',K40_random_bytes='10B',kernel_steps='B(N+2K+1)',planned_durable_steps='1+B(N+81)',output_bytes='8B'),
        kernel_configurations=[dict(B=b,K=k,N=n) for b,k,n in configurations],vector_check_grid=dict(B=[1,2,3],K=[1,2,3,4],N=[1,2,3,4,5]),
        exhaustive_kernel_cases=kernel_cases,complete_joint_distribution_checks=distribution_checks,single_bucket_matches_count_cases=b1_cases,
        public_access_shape_checks=shape_checks,scalar_exact_privacy_checks=scalar_checks,vector_directed_privacy_checks=privacy_checks,max_fraction_of_delta_bound=str(max_ratio),tight_examples=equality_examples,
        K40_replay_cases=replay_cases,K40_distinct_bucket_tape_layout_cases=layout_cases,invalid_contract_cases=len(invalids),negative_controls=dict(shared_noise=dict(K=k,N=n,counts=[0,0],adjacent=[1,0],hockey=str(shared),claimed_delta=str(delta)),replacement_adjacency=dict(K=k,N=n,counts=[1,0],adjacent=[0,1],hockey=str(replacement),claimed_delta=str(delta)),multi_bucket_user=dict(K=k,N=n,counts=[0,0],adjacent=[1,1],hockey=str(multi),claimed_delta=str(delta)),finite_rdp=dict(event='first bucket output=0',P=str(p0),Q=str(q0),conclusion='infinite for every alpha>1; pure DP fails')),
        excluded=['user deduplication and stable bucket classification','snapshot lineage and contribution enforcement','production random-source review','signed action/ledger/vault/scheduler/vector transport integration','physical constant time and complete observable trace proof'])
    root=Path(__file__).parent;report['source_sha256']={f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in ('histogram_kernel.py','histogram_model.py','fixed_work_model.py')}
    (root/'histogram_results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
