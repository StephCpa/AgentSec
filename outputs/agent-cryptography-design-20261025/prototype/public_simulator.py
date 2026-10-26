"""Constructive signed transcript candidate for restricted-public-trace-v1.

Consumes public caller commands and explicitly supplied independent coins, not
observed service responses. Uses shared public transition rules/codecs, an
operation-bound output oracle, and ideal role-scoped signing callbacks. No DB.
This executable candidate is not an inductive or cryptographic simulation proof.
"""
from copy import deepcopy
import hashlib
from ledger import Rejected
from wire import verify_sign1
from public_gateway import parse_request, response, PROFILE, RESPONSE_TYPE, REQUEST_TYPE
from public_input import validate_public_response_body
from public_trace_adapter import PublicTraceAdapter, ViewMismatch, require
import retention_delivery as d
import retention_wire as r


class PublicSimulator:
    """sign(role, object_type, payload, context) returns a bound COSE Sign1.

    Keys are NOT inferred from a public key. The signing service is an explicit
    ideal-world resource, assumed independent of the private dataset. Its output
    is checked against the public key, role, signature domain and exact payload.
    """
    def __init__(self,config,approved_outputs,sign):
        self.state=PublicTraceAdapter(config,approved_outputs)
        require(callable(sign),'SIGNING_ORACLE_REQUIRED')
        self.sign=sign;self.records=[];self.pending={}

    def _signed(self,role,object_type,payload,context=None):
        cfg=self.state.cfg
        raw=self.sign(role,object_type,deepcopy(payload),deepcopy(context))
        if role=='gateway':
            kid,actual=verify_sign1(raw,cfg['gateway_key'],object_type)
            require(kid==cfg['gateway_kid'],'SIGNING_ORACLE_KEY')
        else:actual=r.verified(raw,context,role,object_type)
        require(actual==payload,'SIGNING_ORACLE_PAYLOAD')
        return raw

    def _gateway_reply(self,raw,status,body,sequence):
        cfg=self.state.cfg;validate_public_response_body(status,body)
        payload=dict(profile=PROFILE,deployment=cfg['deployment'],request_hash=hashlib.sha256(raw).digest(),
                     status=status,body=body,sequence=sequence)
        reply=self._signed('gateway',RESPONSE_TYPE,payload)
        require(len(reply)<=8192,'PUBLIC_RESPONSE_FRAME')
        response(reply,raw,cfg['gateway_key'],cfg['gateway_kid'],cfg['deployment'])
        return reply

    def _public(self,command):
        m=self.state;cfg=m.cfg;raw=bytes.fromhex(command['request']);peer=bytes.fromhex(command['peer'])
        coin=bytes.fromhex(command['challenge_coin'])
        require(len(coin) in (0,32),'PUBLIC_COIN_SHAPE')
        try:
            obj=parse_request(raw);key=cfg['keys'].get(obj['kid']);principal=cfg['principals'].get(obj['kid'])
            if (obj['tenant']!=cfg['tenant'] or obj['domain']!=cfg['domain'] or obj['deployment']!=cfg['deployment'] or
                key is None or principal is None or key['actor']!=obj['actor'] or key.get('revoked',False) or
                principal.get('revoked',False) or not key['not_before']<=m.now<key['expires_at'] or peer!=principal['certificate']):
                raise Rejected('PUBLIC_DENIED')
            verify_sign1(raw,key['public_key'],REQUEST_TYPE)
        except Rejected:
            return self._gateway_reply(raw,'REJECTED',{},0)
        cache_key=(obj['kid'],obj['request_id']);old=m.cache.get(cache_key)
        if old is not None:
            return old[1] if old[0]==raw else self._gateway_reply(raw,'REJECTED',{},0)
        if not obj['issued_at']<=m.now<obj['expires_at']:
            return self._gateway_reply(raw,'REJECTED',{},0)
        require((obj['method']=='CHALLENGE' and len(coin)==32) or (obj['method']!='CHALLENGE' and not coin),'PUBLIC_COIN_SCOPE')
        before=deepcopy(m.__dict__)
        try:
            # Only this explicit coin is offered; no observed response body exists.
            status,body=m._dispatch(obj,principal['rights'],{'challenge':coin})
        except Rejected:
            m.__dict__=before;status,body='REJECTED',{}
        require(len(m.jobs)<=2,'RESTRICTED_OPERATION_BOUND')
        m.journal_seq+=1
        reply=self._gateway_reply(raw,status,body,m.journal_seq)
        m.cache[cache_key]=(raw,reply)
        return reply

    def _send(self,command):
        m=self.state;job=m.by_id.get(command['operation']);kind=command['delivery_kind'];loss=command['loss']
        require(kind in ('DELIVERY','TERMINAL') and loss in ('none','packet','ack'),'SEND_SCOPE')
        require(job is not None and job['publication']=='ADMITTED','SEND_BEFORE_ADMISSION')
        require(job['seq']==len(m.final)+1,'SEND_OUTSIDE_FINAL_FRONTIER')
        require(job.get('confirmed') is None,'SEND_AFTER_CONFIRMATION')
        ctx=job['context'];h=r.context_hash(ctx);key=(h,job['route_seq'])
        challenge=bytes.fromhex(command['challenge']);require(len(challenge)==32,'ATTEMPT_COIN_SHAPE')
        desc=d.descriptor(ctx,seq=job['route_seq'],operation=job['id'],issued_at=job['issued_at'],expires_at=job['expires_at'],shape=m._shape(job))
        body=m.prepared.get((key,kind))
        if kind=='DELIVERY':
            require(m.now<job['expires_at'],'DELIVERY_PREPARATION_EXPIRED')
            if body is None:
                payload=dict(profile=d.PROFILE,context_hash=h,descriptor=desc,result=b''.join(x.to_bytes(8,'big') for x in job['value']))
                body=self._signed('sender',d.ENVELOPE_TYPE,payload,ctx)
        else:
            require(m.now>=job['expires_at'],'TERMINAL_NOT_EXPIRED')
            if body is None:
                envelope=m.prepared.get((key,'DELIVERY'))
                payload=dict(profile=d.PROFILE,context_hash=h,descriptor=desc,envelope_hash=b'' if envelope is None else r.sha(envelope))
                body=self._signed('sender',d.CONTROL_TYPE,payload,ctx)
        d.parse_body(kind,body,ctx)
        request=self._signed('sender',d.ATTEMPT_TYPE,dict(profile=d.PROFILE,context_hash=h,kind=kind,body=body,challenge=challenge),ctx)
        if loss=='packet':reply='PACKET_LOST'
        elif loss=='ack':reply='ACK_LOST'
        else:
            # First-outcome state is generated from public delivery/clock inputs.
            # No receiver facts are read from the real execution.
            fact=m.receiver.get(key)
            if fact is None:fact=d.accepted_fact(body,m.now,ctx) if kind=='DELIVERY' else d.closed_fact(body,m.now,ctx)
            ack=self._signed('receiver',d.RECEIPT_TYPE,dict(profile=d.PROFILE,context_hash=h,fact=fact,challenge=challenge,request_hash=r.sha(request)),ctx)
            d.parse_receipt(ack,request,ctx);reply=ack.hex()
            self.pending[job['id']]=(request.hex(),reply)
        event=dict(kind='DELIVERY',at=m.now,request=request.hex(),response=reply)
        m.consume(event)
        return event

    def emit(self,command):
        m=self.state
        require(type(command) is dict and type(command.get('at')) is int and m.now<=command['at']<2**62,'PUBLIC_CLOCK')
        fields={'PUBLIC':{'kind','at','request','peer','challenge_coin'},'TICK':{'kind','at','tick'},
                'SEND':{'kind','at','operation','delivery_kind','challenge','loss'},'CONFIRM':{'kind','at','operation'}}
        kind=command.get('kind')
        require(type(kind) is str and kind in fields and set(command)==fields[kind],'COMMAND_SCOPE')
        before=deepcopy(m.__dict__);pending=deepcopy(self.pending)
        try:
            m.now=command['at']
            if kind=='PUBLIC':
                reply=self._public(command)
                event=dict(kind='PUBLIC',at=m.now,request=command['request'],peer=command['peer'],response=reply.hex())
            elif kind=='TICK':event=dict(command);m.consume(event)
            elif kind=='SEND':event=self._send(command)
            else:
                require(command['operation'] in self.pending,'CONFIRM_WITHOUT_DELIVERED_RECEIPT')
                raw,ack=self.pending[command['operation']]
                event=dict(kind='CONFIRM',at=m.now,request=raw,response=ack);m.consume(event)
            self.records.append(event)
            return deepcopy(event)
        except BaseException as exc:
            m.__dict__=before;self.pending=pending
            if isinstance(exc,(Rejected,ValueError,KeyError,TypeError)):
                raise ViewMismatch(str(exc)) from exc
            raise

    def generate(self,commands):
        for command in commands:self.emit(command)
        return deepcopy(self.records)
