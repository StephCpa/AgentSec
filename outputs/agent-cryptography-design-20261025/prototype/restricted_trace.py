"""Frozen synthetic runtime driver for conditional public-trace correspondence.

This driver alone can inspect storage/private fixtures. The checker receives only
explicit public config, signed traffic, trusted scheduling/confirmation events,
and approved output values. Local method calls, not a new TLS/process-isolation test.
"""
import hashlib
import json
import secrets
from pathlib import Path
import tempfile
from unittest.mock import patch

from public_gateway import PublicGatewayLedger
from public_trace_adapter import PublicTraceAdapter
from test_public_gateway import configure, make_request, parse_reply, SERVER_KEY, SERVER_KID, PEER
from test_encrypted_mixed_ledger import vault
from test_mixed_delegated_ledger import KEYS, chain_fixture, packet, tick, credential
from mixed_delegated_ledger import parse_mixed_credential
from test_ordered_publication import bind_second, second_context
from test_retention_sender import context
from test_retention_recipient import recipient_vault
from test_witness_transport import public
from retention_recipient import RetentionRecipient
from witnessed_ledger import ReferenceWitness
from public_observation import seed_for_output_one
from contribution_scenario import USERS
from dp_ledger import EPSILON_COST as E, DELTA_COST as D
from ledger import Rejected
import retention_delivery as delivery

PROFILE='restricted-public-trace-v1'
PLANS=('normal','cancel_before','cancel_after','pause','revoke_before','revoke_after',
       'revoke_after_admission','cancel_after_publication','packet_loss','ack_loss',
       'closed','accepted_then_expired','permanent_loss','retry_and_denial',
       'mixed_same_route','mixed_cross_route','mixed_ack_loss','mixed_expired','adaptive')


def public_config(two_routes=False):
    c,_,_=context()
    roots={'root':dict(actor='manager',recipient='reader',authority=b'authority',expires_at=1000,ttl=60,context=c)}
    if two_routes:roots['root2']=dict(roots['root'],recipient='reader2',context=second_context(c))
    labels=['one','two','three','four']
    return dict(tenant='t',domain='domain',deployment=vault().deployment_id,gateway_key=public(SERVER_KEY),gateway_kid=SERVER_KID,
        keys={n.encode():dict(actor=n,role='root' if n=='authority' else 'instance',public_key=public(k),not_before=0,expires_at=2**62) for n,k in KEYS.items()},
        principals={b'leaf':dict(certificate=PEER,rights=['challenge','submit','poll','final','cancel']),
                    b'manager':dict(certificate=PEER,rights=['pause','resume','revoke','final']),b'other':dict(certificate=PEER,rights=['poll'])},
        roots=roots,capacity=3,catalogs={'cat':dict(labels=labels,digest=hashlib.sha256(json.dumps(labels,separators=(',',':')).encode()).digest())},
        snapshots={'count':dict(kind='count'),'hist':dict(kind='histogram',catalog='cat')},epsilon_limit=4*E,delta_limit=4*D)


class Runtime:
    def __init__(self, directory, mask=3, two_routes=False, witness_type=ReferenceWitness):
        self.directory=Path(directory);self.now=100;self.rid=0;self.steps=0;self.records=[];self.oracle={};self.kinds={};self.runtime_draws=[];self.receivers={}
        self.cfg=public_config(two_routes);self.slots=[(mask>>i)&1 for i in range(3)]
        self.w=witness_type(self.directory/'w')
        self.l=PublicGatewayLedger.create(self.directory/'db',clock=lambda:self.now,vault=vault(),witness=self.w)
        with patch('test_atomic_publication.RECORDS',[(u,self.slots[i]) for i,u in enumerate(USERS)]):configure(self.l)
        if two_routes:bind_second(self.l,self.cfg['roots']['root2']['context'])
        self.s=context()[1];self.k=context()[2]

    def close(self):
        for inbox,w in self.receivers.values():inbox.close();w.close()
        self.l.close();self.w.close()

    def exchange(self,raw,peer=PEER):
        reply=self.l.handle_public(raw,peer,SERVER_KEY)
        self.records.append(dict(kind='PUBLIC',at=self.now,peer=peer.hex(),request=raw.hex(),response=reply.hex()))
        return parse_reply(reply,raw)

    def call(self,method,payload,actor='leaf'):
        self.rid+=1;raw=make_request(method,payload,self.rid,actor,self.now)
        if method=='CHALLENGE':
            token=secrets.token_bytes
            coin=hashlib.sha256(('public-challenge:'+str(self.rid)).encode()).digest()
            with patch('signed_ledger.secrets.token_bytes',side_effect=lambda n:coin if n==32 else token(n)):
                return self.exchange(raw)
        return self.exchange(raw)

    def submit(self,oid='a',hist=False,root='root'):
        ch=self.call('CHALLENGE',{})['body'];chain=chain_fixture(self.l)
        if root!='root':
            rebuilt=[]
            for raw in chain:
                obj=parse_mixed_credential(raw);obj.update(root=root,id=obj['id']+'2')
                obj['policy']['recipients']=['reader2'];obj['parent_digest']=hashlib.sha256(rebuilt[-1]).digest() if rebuilt else b''
                rebuilt.append(credential(obj))
            chain=rebuilt
        with patch.object(self.l,'issue_challenge',return_value=ch):
            raw,proof=packet(self.l,chain,oid,hist,proof_id=self.rid.to_bytes(16,'big'),root=root,recipient=self.cfg['roots'][root]['recipient'])
        out=self.call('SUBMIT',dict(action=raw,proof=proof,chain=chain))
        if out['status']!='RECORDED':raise AssertionError(out)
        self.kinds[oid]=hist;self.oracle[oid]=(1,0,0,0) if hist else (1,)
        return out

    def _randomness(self,op):
        # Valid finite tapes conditioned on one fixed released output, not a
        # distribution experiment. Empty and populated datasets share that output.
        self.runtime_draws.append((op['id'],'histogram' if self.kinds[op['id']] else 'count',self.steps+1))
        seed=seed_for_output_one(sum(self.slots))
        return seed[:10]+bytes(30) if self.kinds[op['id']] else seed

    def advance(self):
        with patch.object(self.l,'operation_randomness',side_effect=self._randomness):tick(self.l)
        self.steps+=1;self.records.append(dict(kind='TICK',at=self.now,tick=self.steps))

    def finish(self,poll_every=0):
        while self.l.db.execute('SELECT 1 FROM jobs WHERE publication IS NULL').fetchone():
            self.advance()
            if poll_every and self.steps%poll_every==0:self.call('POLL',dict(operation='a'))

    def decision(self,oid):
        return next(x for x in self.l.decisions_internal('t','domain') if x['operation_id']==oid)

    def prepare(self,oid,terminal=False):
        decision=self.decision(oid)
        c=self.cfg['roots']['root2' if oid=='b' and 'root2' in self.cfg['roots'] else 'root']['context']
        raw=(self.l.prepare_terminal if terminal else self.l.prepare_envelope)('t',decision['delivery_id'],self.s)
        req=delivery.attempt('TERMINAL' if terminal else 'DELIVERY',raw,(len(self.records)+1).to_bytes(32,'big'),c,self.s)
        return req,c,decision

    def deliver(self,oid='a',terminal=False,loss=None):
        req,c,decision=self.prepare(oid,terminal)
        if loss=='packet':reply='PACKET_LOST'
        else:
            recipient=c['recipient']
            if recipient not in self.receivers:
                w=ReferenceWitness(self.directory/(recipient+'-w'))
                inbox=RetentionRecipient.create(self.directory/(recipient+'-db'),context=c,vault=recipient_vault(),clock=lambda:self.now,witness=w)
                self.receivers[recipient]=(inbox,w)
            ack=self.receivers[recipient][0].accept(req,c['sender_cert'],self.k)
            reply='ACK_LOST' if loss=='ack' else ack.hex()
        self.records.append(dict(kind='DELIVERY',at=self.now,request=req.hex(),response=reply))
        if loss is None:
            self.l.confirm('t',decision['delivery_id'],req,ack)
            self.records.append(dict(kind='CONFIRM',at=self.now,request=req.hex(),response=ack.hex()))
        return req

    def checked(self):
        if self.l.audit():raise AssertionError('runtime audit failed')
        for inbox,_ in self.receivers.values():
            if inbox.audit():raise AssertionError('recipient audit failed')
        with patch('sqlite3.connect',side_effect=AssertionError('checker accessed DB')):
            model=PublicTraceAdapter(self.cfg,self.oracle);result=model.check(self.records)
        expected=[(oid,kind) for oid,kind,_ in self.runtime_draws]
        if result['draws']!=expected:raise AssertionError('L1/oracle mismatch')
        for account in self.l.db.execute('SELECT id,reserved,spent FROM accounts'):
            if account['reserved']+account['spent']!=model.used.get(account['id'],0):raise AssertionError('budget mapping mismatch')
        actual=self.l.final_events_internal('t','domain')
        if [x['outcome'] for x in actual]!=[x['outcome'] for x in result['final']]:raise AssertionError('final mapping mismatch')
        return result


def run_plan(plan,mask=3):
    if plan not in PLANS or not 0<=mask<8:raise ValueError('outside frozen plan set')
    cross=plan in ('mixed_cross_route','mixed_ack_loss','mixed_expired')
    with tempfile.TemporaryDirectory() as td:
        r=Runtime(td,mask,cross)
        try:
            mixed=plan.startswith('mixed_');r.submit(hist=mixed)
            first_submit=bytes.fromhex(r.records[-1]['request'])
            if mixed:r.submit('b',root='root2' if cross else 'root')
            r.call('POLL',dict(operation='a'));r.call('FINAL',dict(cursor=0,limit=1))
            if plan=='retry_and_denial':
                r.exchange(first_submit);r.call('POLL',dict(operation=[]));r.call('POLL',dict(operation='a'),'other')
                r.exchange(first_submit,b'X'*32)
                r.call('FINAL',dict(cursor=1,limit=1))
                # Same immutable request ID with changed method/payload.
                from wire import inspect_sign1,decode
                obj=decode(inspect_sign1(first_submit)[1]);rid=int.from_bytes(obj['request_id'],'big')
                r.exchange(make_request('POLL',dict(operation='a'),rid))
                r.submit('a') # new proof, same action, no new mechanism instance
            if plan in ('cancel_before','revoke_before'):
                r.call('CONTROL',dict(kind='cancel',operation='a') if plan=='cancel_before' else dict(kind='revoke',root='root'), 'leaf' if plan=='cancel_before' else 'manager')
            r.advance()
            if plan in ('cancel_after','revoke_after'):
                r.call('CONTROL',dict(kind='cancel',operation='a') if plan=='cancel_after' else dict(kind='revoke',root='root'), 'leaf' if plan=='cancel_after' else 'manager')
            if plan=='pause':
                r.call('CONTROL',dict(kind='pause'),'manager')
                for _ in range(3):r.advance()
                r.call('POLL',dict(operation='a'));r.call('CONTROL',dict(kind='resume'),'manager')
            r.finish(poll_every=80)
            if plan in ('revoke_after_admission','cancel_after_publication'):
                r.call('CONTROL',dict(kind='revoke',root='root') if plan=='revoke_after_admission' else dict(kind='cancel',operation='a'), 'manager' if plan=='revoke_after_admission' else 'leaf')
            if mixed:
                try:r.prepare('b')
                except Rejected as exc:
                    if str(exc)!='DOMAIN_FINAL_ORDER':raise
                else:raise AssertionError('later route escaped final gate')
            if r.decision('a')['kind']=='ADMITTED':
                if plan in ('packet_loss','permanent_loss'):r.deliver(loss='packet')
                if plan in ('ack_loss','accepted_then_expired','mixed_ack_loss','mixed_expired'):r.deliver(loss='ack')
                if plan in ('closed','accepted_then_expired','mixed_expired'):r.now=170
                if plan!='permanent_loss':r.deliver(terminal=r.now>=160)
            if mixed:
                r.call('FINAL',dict(cursor=0,limit=1))
                r.deliver('b',terminal=r.now>=160)
            if plan=='adaptive':
                # Public output of a determines whether b is a histogram.
                first=r.records[-2]
                body=delivery.parse_attempt(bytes.fromhex(first['request']),r.cfg['roots']['root']['context'])
                val=delivery.parse_envelope(body['body'],r.cfg['roots']['root']['context'])['result']
                r.submit('b',hist=int.from_bytes(val,'big')==1);r.finish();r.deliver('b')
            r.call('POLL',dict(operation='a'));r.call('FINAL',dict(cursor=0,limit=1))
            if mixed or plan=='adaptive':r.call('FINAL',dict(cursor=1,limit=1))
            if plan=='retry_and_denial':r.now=180;r.exchange(first_submit)
            result=r.checked()
            return dict(profile=PROFILE,plan=plan,mask=mask,config=r.cfg,approved_outputs=r.oracle,records=r.records,
                        runtime_draws=r.runtime_draws,check=result)
        finally:r.close()


def main():
    import argparse
    import gzip
    from wire import encode
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('output directory exists')
    args.output.mkdir(parents=True)
    report=dict(profile=PROFILE,scope='Finite conditional correspondence; no full-distribution DP or physical timing claim.',
        public_coins='Deterministic synthetic challenge/proof/attempt coins shared across masks; independence is an assumption, not inferred.',
        source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},cases=[],equal_conditioned_plans=[])
    traces=[]
    for plan in PLANS:
        plan_records=[]
        for mask in range(8):
            run=run_plan(plan,mask);wire=json.dumps(run['records'],sort_keys=True,separators=(',',':')).encode()
            report['cases'].append(dict(plan=plan,mask=mask,record_count=len(run['records']),trace_sha256=hashlib.sha256(wire).hexdigest(),
                ticks=run['check']['logical_ticks'],calls=run['check']['mechanism_calls'],final=run['check']['final'],pending=run['check']['pending']))
            plan_records.append(run['records'])
            traces.append(dict(plan=plan,mask=mask,config_cbor_hex=encode(run['config']).hex(),approved_outputs=run['approved_outputs'],records=run['records']))
        if any(records!=plan_records[0] for records in plan_records):raise AssertionError('conditioned trace mismatch: '+plan)
        report['equal_conditioned_plans'].append(plan);print('PASS',plan,'8 inputs',flush=True)
    report['passed']=True;report['cases_count']=len(traces)
    report['directed_neighbor_comparisons']=len(PLANS)*24
    (args.output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    with (args.output/'traces.json.gz').open('wb') as f:
        with gzip.GzipFile(fileobj=f,mode='wb',mtime=0) as gz:gz.write(json.dumps(traces,separators=(',',':')).encode())

if __name__=='__main__':main()
