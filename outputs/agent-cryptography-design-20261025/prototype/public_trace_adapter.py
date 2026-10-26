"""Public-state transition checker and event adapter for recorded executions.

Inputs: explicit public configuration, public driver events, signed application
traffic and action-bound mechanism outputs. No database or raw dataset input.
This conditional executable refinement check is not a general security proof.
"""
from copy import deepcopy
import hashlib
import json

from ledger import Rejected
from wire import decode,verify_sign1
from public_gateway import parse_request,response,MAX_FRAME,PUBLIC_DENIALS
from public_input import validate_public_payload
from mixed_delegated_ledger import parse_mixed_action,parse_mixed_proof,parse_mixed_credential,COUNT,HISTOGRAM,CODEC,COUNT_CODEC
from dp_ledger import PROFILE as ACCOUNTANT,EPSILON_COST as E,DELTA_COST as D
import retention_delivery as d
import retention_wire as r


class ViewMismatch(ValueError):pass


def require(condition,reason):
    if not condition:raise ViewMismatch(reason)


# PUBLIC_DENIED represents this model's explicitly predicted public policy
# branches. Other exceptions inherit the real gateway's closed denial taxonomy.
MODEL_PUBLIC_DENIALS=frozenset(PUBLIC_DENIALS)|{'PUBLIC_DENIED'}


def require_public_call_frame(raw,peer):
    # The runtime rejects these before entering authentication or dispatch;
    # there is no ordinary signed response to reproduce in this profile.
    require(type(raw) is bytes and len(raw)<=MAX_FRAME and type(peer) is bytes and len(peer)==32,'PUBLIC_CALL_FRAME')


class PublicTraceAdapter:
    """One explicit tenant/domain per machine; unknown event types fail closed."""
    def __init__(self,config,approved_outputs):
        require(set(config)=={'tenant','domain','deployment','gateway_key','gateway_kid','keys','principals','roots','capacity','catalogs','snapshots','epsilon_limit','delta_limit'},'CONFIGURATION_SCOPE')
        self.cfg=deepcopy(config);self.oracle=deepcopy(approved_outputs)
        self.jobs=[];self.by_id={};self.tick=0;self.cursor=0;self.published=0;self.final=[];self.paused=False
        self.cache={};self.journal_seq=0;self.challenges={};self.proofs=set();self.credentials={}
        self.limits={'domain:epsilon':config['epsilon_limit'],'domain:delta':config['delta_limit']};self.used={}
        self.route_high={};self.receiver={};self.receipts={};self.prepared={};self.draws=[];self.mechanism_calls=[];self.events=[];self.now=0

    def _active(self,job):
        a=job['action'];root=self.cfg['roots'][a['root']]
        return not root.get('revoked',False) and self.now<min(root['expires_at'],a['deadline'],job['authorization_expiry'])

    def _drain(self):
        while len(self.final)<len(self.jobs):
            job=self.jobs[len(self.final)]
            if job['publication']=='WITHHELD':outcome='WITHHELD'
            elif job.get('confirmed') is not None:outcome=job['confirmed']
            else:break
            event=dict(sequence=job['seq'],operation=job['id'],outcome=outcome)
            self.final.append(event);self.events.append(('APP_FINAL',job['seq'],job['id'],outcome))

    def _refund(self,job):
        if job['allocated']:
            for account,amount in job['costs'].items():self.used[account]-=amount
            job['allocated']=False

    def _advance(self,record):
        require(type(record['tick']) is int and record['tick']==self.tick+1,'TICK_GAP_OR_REPLAY')
        self.tick+=1;self.events.append(('ROUND',self.tick))
        candidates=[j for j in self.jobs if j['pc']<j['work']]
        if candidates and not self.paused:
            job=next((j for j in candidates if j['seq']>self.cursor),candidates[0]);self.cursor=job['seq']
            if job['state']=='RESERVED':
                if not self._active(job):job['state']='CANCELED';self._refund(job)
                else:
                    require(job['id'] in self.oracle,'MISSING_MECHANISM_ORACLE')
                    value=self.oracle[job['id']];width=job['width']
                    require(type(value) is tuple and len(value)==width and all(type(x) is int and 0<=x<=self.cfg['capacity'] for x in value),'ORACLE_SHAPE')
                    job['value']=value;job['state']='STARTED';self.draws.append((job['id'],job['action']['operation_kind']))
                    self.mechanism_calls.append(dict(operation=job['id'],action_sha256=hashlib.sha256(job['raw_action']).hexdigest(),l1_tick=self.tick,costs=deepcopy(job['costs'])))
            job['pc']+=1
            if job['pc']==job['work'] and job['state']=='STARTED':job['state']='COMMITTED'
        while self.published<len(self.jobs) and self.jobs[self.published]['pc']==self.jobs[self.published]['work']:
            job=self.jobs[self.published];self.published+=1;root=self.cfg['roots'][job['action']['root']]
            allowed=job['state']=='COMMITTED' and not job['suppressed'] and self._active(job) and not root.get('route_revoked',False)
            job['publication']='ADMITTED' if allowed else 'WITHHELD'
            if allowed:
                context=root['context'];h=r.context_hash(context);seq=self.route_high.get(h,0)+1;self.route_high[h]=seq
                job.update(context=context,route_seq=seq,issued_at=self.now,expires_at=min(self.now+root['ttl'],root['expires_at'],job['action']['deadline'],job['authorization_expiry'],self.cfg['keys'][job['action']['kid']]['expires_at']))
                self.events.append(('JOURNAL','ADMITTED',job['id'],h.hex(),seq))
            else:self.events.append(('JOURNAL','WITHHELD',job['id']))
        self._drain()

    def _authorization(self,action,chain):
        """Public signatures/policies only; all static registry facts explicit."""
        cfg=self.cfg;keys=cfg['keys'];root=cfg['roots'].get(action['root'])
        if root is None or root.get('revoked',False) or not self.now<root['expires_at']:raise Rejected('PUBLIC_DENIED')
        if not action['not_before']<=self.now<action['deadline']:raise Rejected('PUBLIC_DENIED')
        if action['capacity']!=cfg['capacity'] or action['accountant']!=ACCOUNTANT or (action['epsilon_max'],action['delta_max'])!=(E,D):raise Rejected('PUBLIC_DENIED')
        snapshot=cfg['snapshots'].get(action['snapshot'])
        if snapshot is None or snapshot['kind']!=action['operation_kind']:raise Rejected('PUBLIC_DENIED')
        if action['operation_kind']=='histogram':
            catalog=cfg['catalogs'].get(action['catalog'])
            if catalog is None or snapshot['catalog']!=action['catalog'] or action['bucket_count']!=len(catalog['labels']) or action['catalog_digest']!=catalog['digest']:raise Rejected('PUBLIC_DENIED')
        costs={'domain:epsilon':E,'domain:delta':D};limits={};previous=None;previous_raw=None;expiry=root['expires_at'];seen=set();new_credentials={}
        for index,raw in enumerate(chain):
            c=parse_mixed_credential(raw);policy=c['policy'];issuer=keys.get(c['issuer_kid']);subject=keys.get(c['subject_kid'])
            if issuer is None or subject is None or c['tenant']!=cfg['tenant'] or c['root']!=action['root'] or (c['tenant'],c['root'],c['kind'],c['issuer_kid'],c['id']) in seen:raise Rejected('PUBLIC_DENIED')
            identity=(c['tenant'],c['root'],c['kind'],c['issuer_kid'],c['id']);seen.add(identity)
            kid,_=verify_sign1(raw,issuer['public_key'],'MixedGrant' if index==0 else 'MixedDelegation')
            if kid!=c['issuer_kid'] or issuer['actor']!=c['issuer'] or subject['actor']!=c['subject'] or subject['role']!='instance':raise Rejected('PUBLIC_DENIED')
            if any(k.get('revoked',False) or not k['not_before']<=self.now<k['expires_at'] for k in (issuer,subject)):raise Rejected('PUBLIC_DENIED')
            if not c['not_before']<=self.now<c['expires_at']:raise Rejected('PUBLIC_DENIED')
            if identity in self.credentials and self.credentials[identity]!=raw:raise Rejected('PUBLIC_DENIED')
            if index==0:
                if (c['kind']!='grant' or c['id']!=action['root'] or c['depth']!=0 or c['parent_digest']!=b'' or kid!=root['authority'] or issuer['role']!='root' or c['subject']!=root['actor'] or c['expires_at']>root['expires_at'] or not set(policy['recipients'])<={root['recipient']} or c['epsilon_cap']>cfg['epsilon_limit'] or c['delta_cap']>cfg['delta_limit']):raise Rejected('PUBLIC_DENIED')
            else:
                if (c['kind']!='delegation' or c['issuer']!=previous['subject'] or c['issuer_kid']!=previous['subject_kid'] or c['parent_digest']!=hashlib.sha256(previous_raw).digest() or c['depth']!=previous['depth']+1 or c['max_depth']>previous['max_depth'] or c['not_before']<previous['not_before'] or c['expires_at']>previous['expires_at'] or c['epsilon_cap']>previous['epsilon_cap'] or c['delta_cap']>previous['delta_cap']):raise Rejected('PUBLIC_DENIED')
                for name in ('snapshots','recipients','mechanisms','operations'):
                    if not set(policy[name])<=set(previous['policy'][name]):raise Rejected('PUBLIC_DENIED')
                if any(previous['policy']['catalogs'].get(k)!=v for k,v in policy['catalogs'].items()):raise Rejected('PUBLIC_DENIED')
            if policy['domain']!=cfg['domain'] or policy['accounts']!={'epsilon':'domain:epsilon','delta':'domain:delta'}:raise Rejected('PUBLIC_DENIED')
            digest=hashlib.sha256(raw).hexdigest()
            for name,cost in [('epsilon',E),('delta',D)]:
                account='credential:'+digest+':'+name;costs[account]=cost;limits[account]=c[name+'_cap']
            expiry=min(expiry,c['expires_at'],issuer['expires_at'],subject['expires_at']);previous=c;previous_raw=raw;new_credentials[identity]=raw
        policy=previous['policy']
        if (action['leaf_digest']!=hashlib.sha256(previous_raw).digest() or previous['subject']!=action['actor'] or previous['subject_kid']!=action['kid'] or action['not_before']<previous['not_before'] or action['deadline']>previous['expires_at'] or action['snapshot'] not in policy['snapshots'] or action['recipient'] not in policy['recipients'] or action['mechanism'] not in policy['mechanisms'] or action['operation_kind'] not in policy['operations']):raise Rejected('PUBLIC_DENIED')
        if action['operation_kind']=='histogram' and policy['catalogs'].get(action['catalog'])!=action['catalog_digest']:raise Rejected('PUBLIC_DENIED')
        return costs,limits,new_credentials,expiry

    def _dispatch(self,obj,rights,observed_body):
        method=obj['method'];payload=obj['payload'];validate_public_payload(method,payload)
        right=payload.get('kind') if method=='CONTROL' else method.lower()
        if right not in rights:raise Rejected('PUBLIC_DENIED')
        if method=='CHALLENGE':
            # Nonce is an explicit public-coin input; independence/uniformity is
            # a premise, not inferred from observing an arbitrary signed nonce.
            nonce=observed_body.get('challenge');require(type(nonce) is bytes and len(nonce)==32,'CHALLENGE_COIN')
            require(nonce not in self.challenges,'CHALLENGE_REUSE')
            body=dict(challenge=nonce,challenge_expiry=min(self.now+60,self.cfg['keys'][obj['kid']]['expires_at']),audience='mixed-gateway-v1')
            self.challenges[nonce]=dict(kid=obj['kid'],expiry=body['challenge_expiry'],used=False)
            return 'CHALLENGE',body
        if method=='SUBMIT':
            a=parse_mixed_action(payload['action'])
            if any(a[k]!=obj[k] for k in ('tenant','domain','actor','kid')):raise Rejected('PUBLIC_DENIED')
            costs,limits,credentials,expiry=self._authorization(a,payload['chain'])
            kid,proof=verify_sign1(payload['proof'],self.cfg['keys'][a['kid']]['public_key'],'MixedActionProof');proof=parse_mixed_proof(proof)
            ch=self.challenges.get(proof['challenge'])
            if (kid!=a['kid'] or proof['action_digest']!=hashlib.sha256(payload['action']).digest() or proof['audience']!='mixed-gateway-v1' or ch is None or ch['kid']!=a['kid'] or ch['expiry']!=proof['challenge_expiry'] or self.now>=ch['expiry'] or ch['used'] or proof['proof_id'] in self.proofs):raise Rejected('PUBLIC_DENIED')
            old=self.by_id.get(a['operation'])
            if old is not None and old['raw_action']!=payload['action']:raise Rejected('PUBLIC_DENIED')
            if old is None and any(self.used.get(k,0)+v>(limits|self.limits)[k] for k,v in costs.items()):raise Rejected('PUBLIC_DENIED')
            ch['used']=True;self.proofs.add(proof['proof_id']);self.credentials.update(credentials);self.limits.update(limits)
            if old is None:
                for account,amount in costs.items():self.used[account]=self.used.get(account,0)+amount
                width=1 if a['operation_kind']=='count' else a['bucket_count']
                job=dict(id=a['operation'],seq=len(self.jobs)+1,action=a,raw_action=payload['action'],costs=costs,allocated=True,authorization_expiry=expiry,width=width,work=1+width*(self.cfg['capacity']+81),pc=0,state='RESERVED',suppressed=False,publication=None,value=None)
                self.jobs.append(job);self.by_id[job['id']]=job;old=job
            self.events.append(('REQUEST','SUBMIT',old['id'],a['operation_kind']))
            self.events.append(('REPLY','RECORDED',old['id'],old['seq']))
            return 'RECORDED',dict(operation=old['id'],sequence=old['seq'])
        if method in ('POLL','CONTROL') and 'operation' in payload:
            job=self.by_id.get(payload['operation'])
            if job is None or job['action']['actor']!=obj['actor']:raise Rejected('PUBLIC_DENIED')
        if method=='POLL':
            final=next((e['outcome'] for e in self.final if e['operation']==job['id']),'UNFINALIZED')
            body=dict(operation=job['id'],sequence=job['seq'],publication=job['publication'] or 'UNPUBLISHED',final=final)
            self.events.append(('REPLY','RECORDED',job['id'],job['publication'] or 'UNPUBLISHED'))
            return 'POLL',body
        if method=='FINAL':
            if not 0<=payload['cursor']<=len(self.final):raise Rejected('PUBLIC_DENIED')
            events=deepcopy(self.final[payload['cursor']:payload['cursor']+payload['limit']])
            return 'FINAL',dict(events=events,cursor=events[-1]['sequence'] if events else payload['cursor'])
        kind=payload['kind']
        if kind in ('pause','resume'):self.paused=kind=='pause'
        elif kind=='cancel':
            if job['publication'] is not None:raise Rejected('PUBLIC_DENIED')
            if job['state']=='RESERVED':self._refund(job);job['state']='CANCELED'
            elif job['state']=='STARTED':job['state']='BURNED'
            job['suppressed']=True
        else:
            root=self.cfg['roots'].get(payload['root'])
            if root is None or root['actor']!=obj['actor']:raise Rejected('PUBLIC_DENIED')
            root['revoked']=True
        self.events.append(('REPLY','CONTROL_RECORDED',kind))
        return 'CONTROL_RECORDED',dict(payload)

    def _public(self,record):
        require(record['response']!='CONNECTION_CLOSED','UNEXPLAINED_CONNECTION_FAILURE')
        raw=bytes.fromhex(record['request']);reply=bytes.fromhex(record['response']);peer=bytes.fromhex(record['peer'])
        require_public_call_frame(raw,peer)
        out=response(reply,raw,self.cfg['gateway_key'],self.cfg['gateway_kid'],self.cfg['deployment'])
        obj=None
        try:
            obj=parse_request(raw);key=self.cfg['keys'].get(obj['kid']);principal=self.cfg['principals'].get(obj['kid'])
            if (obj['tenant']!=self.cfg['tenant'] or obj['domain']!=self.cfg['domain'] or obj['deployment']!=self.cfg['deployment'] or key is None or principal is None or key['actor']!=obj['actor'] or key.get('revoked',False) or principal.get('revoked',False) or not key['not_before']<=self.now<key['expires_at'] or bytes.fromhex(record['peer'])!=principal['certificate']):raise Rejected('PUBLIC_DENIED')
            verify_sign1(raw,key['public_key'],'AgentPublicRequestV1')
        except Rejected:
            require((out['status'],out['body'],out['sequence'])==('REJECTED',{},0),'AUTH_RESPONSE');return
        request_key=(obj['kid'],obj['request_id']);old=self.cache.get(request_key)
        if old is not None:
            if old[0]==raw:require(reply==old[1],'RETRY_RESPONSE_CHANGED')
            else:require((out['status'],out['body'],out['sequence'])==('REJECTED',{},0),'REQUEST_CONFLICT_RESPONSE')
            return
        if not obj['issued_at']<=self.now<obj['expires_at']:
            require((out['status'],out['body'],out['sequence'])==('REJECTED',{},0),'WINDOW_RESPONSE');return
        # Transaction rollback must also hold in the independent public model.
        before=deepcopy(self.__dict__)
        try:status,body=self._dispatch(obj,principal['rights'],out['body'])
        except Rejected as exc:
            self.__dict__=before
            if str(exc) not in MODEL_PUBLIC_DENIALS:raise
            status,body='REJECTED',{}
        self.journal_seq+=1
        require((out['status'],out['body'],out['sequence'])==(status,body,self.journal_seq),'PUBLIC_RESPONSE_MISMATCH')
        self.cache[request_key]=(raw,reply)

    def _shape(self,job):
        a=job['action'];params=dict(domain=a['domain'],snapshot=a['snapshot'],mechanism=a['mechanism'],accountant=a['accountant'])
        histogram=a['operation_kind']=='histogram';catalog=self.cfg['catalogs'][a['catalog']] if histogram else None
        if histogram:params.update(catalog=a['catalog'],catalog_digest=a['catalog_digest'].hex(),bucket_count=a['bucket_count'],capacity=a['capacity'],k=40,codec=CODEC)
        internal=dict(tenant=a['tenant'],id=a['operation'],root=a['root'],recipient=a['recipient'],parameters=params,costs=job['costs'])
        digest=hashlib.sha256(json.dumps(internal,sort_keys=True,separators=(',',':')).encode()).digest()
        return dict(action_digest=digest,domain=a['domain'],snapshot=a['snapshot'],accountant=a['accountant'],mechanism=a['mechanism'],capacity=a['capacity'],bucket_count=job['width'],k=40,codec=CODEC if histogram else COUNT_CODEC,catalog=a['catalog'] if histogram else '',catalog_digest=a['catalog_digest'] if histogram else b'',labels=catalog['labels'] if histogram else [])

    def _delivery(self,record):
        raw=bytes.fromhex(record['request']);contexts=[root['context'] for root in self.cfg['roots'].values()]
        matches=[]
        for context in contexts:
            try:parsed=d.parse_attempt(raw,context);matches.append((context,parsed))
            except Rejected:pass
        require(bool(matches),'DELIVERY_SIGNATURE_OR_CONTEXT');context,parsed=matches[0]
        body=d.parse_body(parsed['kind'],parsed['body'],context);desc=d.parse_descriptor(body['descriptor'],context)
        job=self.by_id.get(desc['operation']);require(job is not None and job['publication']=='ADMITTED','DELIVERY_BEFORE_ADMISSION')
        expected=d.descriptor(job['context'],seq=job['route_seq'],operation=job['id'],issued_at=job['issued_at'],expires_at=job['expires_at'],shape=self._shape(job))
        require(body['descriptor']==expected,'DELIVERY_ACTION_OR_TICKET_BINDING')
        key=(r.context_hash(context),desc['seq']);known=self.prepared.get((key,parsed['kind']))
        if known is None:require(job['seq']==len(self.final)+1,'CROSS_ROUTE_FINAL_ORDER')
        else:require(known==parsed['body'],'PREPARED_BYTES_CHANGED')
        if parsed['kind']=='DELIVERY':
            require(body['result']==b''.join(x.to_bytes(8,'big') for x in job['value']),'RESULT_ORACLE_MISMATCH')
        else:
            require(self.now>=job['expires_at'],'EARLY_TERMINAL')
            envelope=self.prepared.get((key,'DELIVERY'));require(body['envelope_hash']==(b'' if envelope is None else r.sha(envelope)),'TERMINAL_ENVELOPE_BINDING')
        self.prepared[(key,parsed['kind'])]=parsed['body']
        self.events.append(('SEND',parsed['kind'],r.context_hash(context).hex(),desc['seq'],job['id'],job['value'] if parsed['kind']=='DELIVERY' else ()))
        if record['response']=='PACKET_LOST':return
        if key not in self.receiver:
            if parsed['kind']=='DELIVERY':require(self.now<job['expires_at'],'LATE_FIRST_ACCEPTANCE')
            previous=[k[1] for k in self.receiver if k[0]==key[0]]
            require(desc['seq']==max(previous,default=0)+1,'RECIPIENT_ROUTE_ORDER')
            fact=d.accepted_fact(parsed['body'],self.now,context) if parsed['kind']=='DELIVERY' else d.closed_fact(parsed['body'],self.now,context)
            self.receiver[key]=fact
        fact=r.parse_fact(self.receiver[key],context)
        if parsed['kind']=='DELIVERY':require(fact['outcome']=='ACCEPTED','DELIVERY_AFTER_CLOSED')
        self.events.append(('RECEIVE',fact['outcome'],r.context_hash(context).hex(),desc['seq'],job['id']))
        if record['response']=='ACK_LOST':return
        ack=bytes.fromhex(record['response']);actual=d.parse_receipt(ack,raw,context)
        require(actual==self.receiver[key],'FIRST_OUTCOME_OR_TIME_CHANGED')
        self.receipts[(raw,ack)]=job['id']
        self.events.append(('ACK',fact['outcome'],r.context_hash(context).hex(),desc['seq'],job['id'],fact['event_at']))

    def _confirm(self,record):
        raw=bytes.fromhex(record['request']);ack=bytes.fromhex(record['response'])
        require((raw,ack) in self.receipts,'CONFIRM_WITHOUT_OBSERVED_RECEIPT')
        job=self.by_id[self.receipts[(raw,ack)]];parsed=d.parse_receipt(ack,raw,job['context']);fact=r.parse_fact(parsed,job['context'])
        if job.get('confirmed') is not None:require(job['confirmed']==fact['outcome'],'CONFIRM_CONFLICT')
        job['confirmed']=fact['outcome'];self._drain()

    def consume(self,record):
        require(type(record) is dict and type(record.get('at')) is int and self.now<=record['at']<2**62,'PUBLIC_CLOCK')
        kind=record.get('kind')
        fields={'TICK':{'kind','at','tick'},'PUBLIC':{'kind','at','peer','request','response'},
                'DELIVERY':{'kind','at','request','response'},'CONFIRM':{'kind','at','request','response'}}
        require(type(kind) is str and kind in fields and set(record)==fields[kind],'EVENT_SCOPE')
        self.now=record['at']
        if kind=='TICK':self._advance(record)
        elif kind=='PUBLIC':self._public(record)
        elif kind=='DELIVERY':self._delivery(record)
        elif kind=='CONFIRM':self._confirm(record)
        else:raise ViewMismatch('UNSUPPORTED_EVENT')

    def check(self,records):
        for index,record in enumerate(records):
            try:self.consume(record)
            except (Rejected,ViewMismatch,KeyError,TypeError,ValueError) as exc:
                raise ViewMismatch('record '+str(index)+': '+str(exc)) from exc
        return dict(accepted=True,records=len(records),logical_ticks=self.tick,draws=self.draws,mechanism_calls=deepcopy(self.mechanism_calls),final=deepcopy(self.final),journal_requests=self.journal_seq,
                    abstract_events=deepcopy(self.events),pending=any(j['publication'] is None or (j['publication']=='ADMITTED' and j.get('confirmed') is None) for j in self.jobs))
