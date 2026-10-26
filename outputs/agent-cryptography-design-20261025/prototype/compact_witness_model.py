"""Finite actual SQLite state equivalence: full-image CAS vs same-image reassert.

The old full-image CAS serves as the semantic reference. This is exhaustive over
six action templates at bounded depth, not a general proof or durability test.
"""
import argparse
from collections import Counter
import hashlib
from itertools import product
import json
from pathlib import Path
from witnessed_ledger import ReferenceWitness,Rejected,image_hash

ACTIONS=('same','change','stale','retry','conflict','wrong_digest')


def projection(w):
    return dict(heads=[list(r[:3])+[r[3].hex()] for r in w.db.execute('SELECT namespace,seq,digest,image FROM heads ORDER BY namespace')],
                commits=[list(r) for r in w.db.execute('SELECT namespace,seq,base_digest,digest,token FROM commits ORDER BY namespace,seq')])


def run(depth=4):
    if type(depth) is not int or not 1<=depth<=4:raise ValueError('bounded depth 1..4')
    outcomes=Counter();methods=Counter();cases=0;transitions=0
    for plan in product(ACTIONS,repeat=depth):
        left=ReferenceWitness(':memory:');right=ReferenceWitness(':memory:')
        try:
            for w in (left,right):w.bootstrap('n',b'A');w.bootstrap('other',b'untouched')
            first=None
            for index,action in enumerate(plan):
                head=left.head('n',True);seq=head['seq'];old=head['digest'];image=head['image'];token=format(index,'032x')
                if action=='change':image=b'B' if image==b'A' else b'A'
                elif action=='stale':seq=0;old=image_hash(b'A');image=b'A'
                elif action=='retry' and first is not None:seq,old,image,token=first
                elif action=='conflict' and first is not None:seq,old,_,token=first;image=b'conflicting content'
                elif action=='wrong_digest':old=image_hash(b'wrong head')
                request=(seq,old,image,token)
                if first is None:first=request
                results=[]
                for candidate,w in ((False,left),(True,right)):
                    compact=candidate and image_hash(image)==old
                    try:
                        result=w.reassert('n',seq,old,token) if compact else w.compare_and_store('n',seq,old,image,token)
                        result=('ok',result['seq'],result['digest'])
                    except Rejected as exc:result=('rejected',str(exc))
                    results.append(result)
                    if candidate:methods['reassert' if compact else 'cas']+=1
                if results[0]!=results[1] or projection(left)!=projection(right):raise AssertionError((plan,index,results))
                outcomes[results[0][0]+(':'+results[0][1] if results[0][0]=='rejected' else '')]+=1
                transitions+=1
            cases+=1
        finally:left.close();right.close()
    return dict(passed=True,depth=depth,actions=list(ACTIONS),cases=cases,compared_transitions=transitions,
                outcomes=dict(outcomes),candidate_methods=dict(methods),
                scope='Actual independent in-memory SQLite witnesses, identical initial images/tokens; compare return/error and every head/commit row after each action. Includes stale/ABA-producing sequences, logical retries and token conflicts, plus an untouched namespace. Finite sequential enumeration; no concurrency, corruption, process/disk fault or general proof claim.')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    result=run();root=Path(__file__).parent
    result['source_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (Path(__file__),root/'witnessed_ledger.py')}
    args.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS',result['cases'],'plans',result['compared_transitions'],'state comparisons')

if __name__=='__main__':main()
