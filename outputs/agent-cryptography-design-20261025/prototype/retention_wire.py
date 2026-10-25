"""Strict v2 retention messages and pure transition guards; no storage or GC.

Trusted callers must persist facts/confirmations at their respective authority
BEFORE signing receipts/offers. Signatures do not prove that persistence. Existing
v1 delivery objects cannot be passed as v2 facts. No network service is exposed.
"""
import hashlib
from cryptography.hazmat.primitives import serialization
from ledger import Rejected
from wire import encode,decode,sign1,verify_sign1,identifier

PROFILE='mixed-retention-v2'
MAX_FRAME=8192
MAX_SEQ=2**64-1
MAX_TIME=2**62
CONTEXT_FIELDS={'profile','deployment','tenant','recipient','gateway','session','epoch',
    'sender_authority','receiver_authority','sender_key','receiver_key','sender_kid',
    'receiver_kid','sender_cert','receiver_cert','window'}
FACT_FIELDS={'profile','context_hash','seq','delivery','action_digest','descriptor_hash',
    'issued_at','expires_at','outcome','event_at','envelope_hash'}
OFFER_FIELDS={'profile','context_hash','base','base_root','target','target_root'}
QUERY_FIELDS={'profile','context_hash','kind','seq','delivery','challenge'}
ATTEMPT_FIELDS={'profile','context_hash','offer','challenge'}
FINAL_FIELDS={'profile','context_hash','fact','challenge','request_hash'}
CHECKPOINT_FIELDS={'profile','context_hash','status','floor','root','high','challenge','request_hash'}
OFFER_TYPE='RetentionOfferV2'
QUERY_TYPE='RetentionQueryV2'
ATTEMPT_TYPE='RetentionAttemptV2'
FINAL_TYPE='RetentionFinalReceiptV2'
CHECKPOINT_TYPE='RetentionCheckpointV2'


def sha(raw):return hashlib.sha256(raw).digest()


def uint(value,minimum=0,maximum=MAX_SEQ):
    if type(value) is not int or not minimum<=value<=maximum:raise Rejected('RETENTION_INTEGER')


def blob(value,length=32):
    if type(value) is not bytes or len(value)!=length:raise Rejected('RETENTION_BYTES')


def fields(obj,keys):
    if type(obj) is not dict or set(obj)!=keys or obj.get('profile')!=PROFILE:
        raise Rejected('RETENTION_SCHEMA')


def validate_context(context):
    fields(context,CONTEXT_FIELDS)
    for k in ('tenant','recipient','gateway','session'):identifier(context[k])
    for k in ('deployment','epoch','sender_authority','receiver_authority'):blob(context[k],16)
    for k in ('sender_key','receiver_key','sender_cert','receiver_cert'):blob(context[k])
    for k in ('sender_kid','receiver_kid'):
        if type(context[k]) is not bytes or not 1<=len(context[k])<=32:raise Rejected('RETENTION_KID')
    uint(context['window'],1,65535)
    if context['sender_authority']==context['receiver_authority']:raise Rejected('RETENTION_AUTHORITY_ALIAS')
    return context


def context_hash(context):
    return sha(encode(['retention-context',2,validate_context(context)]))


def bound(obj,keys,context):
    fields(obj,keys)
    if obj['context_hash']!=context_hash(context):raise Rejected('RETENTION_CONTEXT')
    return obj


def frame(raw):
    if type(raw) is not bytes or not 0<len(raw)<=MAX_FRAME:raise Rejected('RETENTION_FRAME')
    return raw


def signed(obj,context,key,role,domain):
    validate_context(context)
    actual=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    if actual!=context[role+'_key']:raise Rejected('RETENTION_SIGNING_KEY')
    return frame(sign1(encode(obj),context[role+'_kid'],key,domain))


def verified(raw,context,role,domain):
    validate_context(context)
    kid,obj=verify_sign1(frame(raw),context[role+'_key'],domain)
    if kid!=context[role+'_kid']:raise Rejected('RETENTION_KID')
    return obj


def delivery_id(context,seq):
    uint(seq,1)
    return sha(encode(['retention-delivery-id',2,context_hash(context),seq])).hex()


def genesis(context):return sha(encode(['retention-prefix-genesis',2,context_hash(context)]))


def validate_fact(obj,context):
    bound(obj,FACT_FIELDS,context);uint(obj['seq'],1)
    if obj['delivery']!=delivery_id(context,obj['seq']):raise Rejected('RETENTION_DELIVERY_ID')
    for k in ('action_digest','descriptor_hash'):blob(obj[k])
    for k in ('issued_at','expires_at','event_at'):uint(obj[k],0,MAX_TIME)
    if not 0<obj['expires_at']-obj['issued_at']<=60:raise Rejected('RETENTION_WINDOW')
    if type(obj['envelope_hash']) is not bytes or len(obj['envelope_hash']) not in (0,32):raise Rejected('RETENTION_BYTES')
    if obj['outcome']=='ACCEPTED':
        if len(obj['envelope_hash'])!=32 or not obj['issued_at']<=obj['event_at']<obj['expires_at']:
            raise Rejected('RETENTION_FINAL_EVENT')
    elif obj['outcome']=='CLOSED':
        if obj['event_at']<obj['expires_at']:raise Rejected('RETENTION_FINAL_EVENT')
    else:raise Rejected('RETENTION_FINAL_EVENT')
    return obj


def parse_fact(raw,context):return validate_fact(decode(frame(raw)),context)


def fact_bytes(obj,context):return frame(encode(validate_fact(obj,context)))


def extend_prefix(root,raw,context,expected_seq):
    blob(root);uint(expected_seq,1);fact=parse_fact(raw,context)
    if fact['seq']!=expected_seq:raise Rejected('RETENTION_SEQUENCE')
    return sha(encode(['retention-prefix-step',2,root,raw]))


def validate_query(obj,context):
    bound(obj,QUERY_FIELDS,context);blob(obj['challenge'])
    if obj['kind']=='CHECKPOINT':
        uint(obj['seq'],0,0)
        if obj['delivery']!='':raise Rejected('RETENTION_DELIVERY_ID')
    elif obj['kind'] in ('FINAL','RETIRED'):
        uint(obj['seq'],1)
        if obj['delivery']!=delivery_id(context,obj['seq']):raise Rejected('RETENTION_DELIVERY_ID')
    else:raise Rejected('RETENTION_QUERY_KIND')
    return obj


def query(context,kind,seq,challenge,key):
    obj=dict(profile=PROFILE,context_hash=context_hash(context),kind=kind,seq=seq,
             delivery='' if kind=='CHECKPOINT' else delivery_id(context,seq),challenge=challenge)
    return signed(validate_query(obj,context),context,key,'sender',QUERY_TYPE)


def parse_query(raw,context):return validate_query(verified(raw,context,'sender',QUERY_TYPE),context)


def final_receipt(raw_fact,request,context,key):
    fact=parse_fact(raw_fact,context);q=parse_query(request,context)
    if q['kind']!='FINAL' or q['seq']!=fact['seq']:raise Rejected('RETENTION_FINAL_REQUEST')
    return signed(dict(profile=PROFILE,context_hash=context_hash(context),fact=raw_fact,
        challenge=q['challenge'],request_hash=sha(request)),context,key,'receiver',FINAL_TYPE)


def parse_final_receipt(raw,request,context):
    q=parse_query(request,context)
    obj=bound(verified(raw,context,'receiver',FINAL_TYPE),FINAL_FIELDS,context)
    if obj['challenge']!=q['challenge'] or obj['request_hash']!=sha(request):raise Rejected('RETENTION_REPLY_BINDING')
    fact=parse_fact(obj['fact'],context)
    if q['kind']!='FINAL' or q['seq']!=fact['seq']:raise Rejected('RETENTION_FINAL_REQUEST')
    return obj['fact']


def validate_offer(obj,context):
    bound(obj,OFFER_FIELDS,context);uint(obj['base']);uint(obj['target'],1)
    blob(obj['base_root']);blob(obj['target_root'])
    if not obj['base']<obj['target']:raise Rejected('RETENTION_OFFER_RANGE')
    if obj['target']-obj['base']>context['window']:raise Rejected('RETENTION_OFFER_WINDOW')
    if obj['base']==0 and obj['base_root']!=genesis(context):raise Rejected('RETENTION_GENESIS')
    return obj


def offer(context,base,base_root,target,target_root,key):
    # Low-level codec: caller MUST enforce target <= durable sender F_S.
    obj=dict(profile=PROFILE,context_hash=context_hash(context),base=base,base_root=base_root,target=target,target_root=target_root)
    return signed(validate_offer(obj,context),context,key,'sender',OFFER_TYPE)


def parse_offer(raw,context):return validate_offer(verified(raw,context,'sender',OFFER_TYPE),context)


def retire_attempt(raw_offer,challenge,context,key):
    parse_offer(raw_offer,context);blob(challenge)
    return signed(dict(profile=PROFILE,context_hash=context_hash(context),offer=raw_offer,challenge=challenge),context,key,'sender',ATTEMPT_TYPE)


def parse_retire_attempt(raw,context):
    obj=bound(verified(raw,context,'sender',ATTEMPT_TYPE),ATTEMPT_FIELDS,context)
    blob(obj['challenge']);parse_offer(obj['offer'],context)
    return obj


def validate_receiver_state(context,floor,root,high,live):
    validate_context(context)
    uint(floor);uint(high);blob(root)
    if floor>high:raise Rejected('RETENTION_FRONTIER')
    if floor==0 and root!=genesis(context):raise Rejected('RETENTION_GENESIS')
    if type(live) not in (list,tuple) or len(live)!=high-floor or len(live)>context['window']:
        raise Rejected('RETENTION_LIVE_WINDOW')
    for seq,raw in enumerate(live,floor+1):
        if parse_fact(raw,context)['seq']!=seq:raise Rejected('RETENTION_SEQUENCE')


def retirement_transition(raw_offer,context,*,floor,root,high,live):
    """Pure current-state guard. Authority CAS and atomic persistence are REQUIRED.

    Duplicate/stale offers do not use this mutation function: caller can answer
    a current authenticated checkpoint, which sender checks against its archive.
    """
    obj=parse_offer(raw_offer,context);validate_receiver_state(context,floor,root,high,live)
    if obj['base']!=floor or obj['base_root']!=root:raise Rejected('RETENTION_STALE_BASE')
    if obj['target']>high:raise Rejected('RETENTION_MISSING_FINAL')
    count=obj['target']-floor;new_root=root
    for seq,raw in enumerate(live[:count],floor+1):new_root=extend_prefix(new_root,raw,context,seq)
    if new_root!=obj['target_root']:raise Rejected('RETENTION_PREFIX_MISMATCH')
    return dict(floor=obj['target'],root=new_root,high=high,live=tuple(live[count:]))


def request_binding(request,context,kind):
    if kind=='RETIRE_ACK':
        q=parse_retire_attempt(request,context);return q,parse_offer(q['offer'],context)
    if kind in ('CHECKPOINT','RETIRED'):
        q=parse_query(request,context)
        if q['kind']!=kind:raise Rejected('RETENTION_CHECKPOINT_KIND')
        return q,None
    raise Rejected('RETENTION_CHECKPOINT_KIND')


def validate_checkpoint(obj,request,context):
    bound(obj,CHECKPOINT_FIELDS,context)
    q,o=request_binding(request,context,obj['status'])
    if obj['challenge']!=q['challenge'] or obj['request_hash']!=sha(request):raise Rejected('RETENTION_REPLY_BINDING')
    uint(obj['floor']);uint(obj['high']);blob(obj['root'])
    if obj['floor']>obj['high']:raise Rejected('RETENTION_FRONTIER')
    if obj['high']-obj['floor']>context['window']:raise Rejected('RETENTION_LIVE_WINDOW')
    if obj['floor']==0 and obj['root']!=genesis(context):raise Rejected('RETENTION_GENESIS')
    if o is not None:
        if obj['floor']<o['target']:raise Rejected('RETENTION_TARGET_NOT_RETIRED')
        if obj['floor']==o['target'] and obj['root']!=o['target_root']:raise Rejected('RETENTION_PREFIX_MISMATCH')
    if obj['status']=='RETIRED' and q['seq']>obj['floor']:raise Rejected('RETENTION_NOT_RETIRED')
    return obj


def checkpoint(request,context,kind,*,floor,root,high,key):
    q,_=request_binding(request,context,kind)
    obj=dict(profile=PROFILE,context_hash=context_hash(context),status=kind,floor=floor,root=root,high=high,
             challenge=q['challenge'],request_hash=sha(request))
    return signed(validate_checkpoint(obj,request,context),context,key,'receiver',CHECKPOINT_TYPE)


def parse_checkpoint(raw,request,context):
    return validate_checkpoint(verified(raw,context,'receiver',CHECKPOINT_TYPE),request,context)


def reconcile_checkpoint(raw,request,context,*,known_floor,confirmed,archived_root):
    """Sender must supply authoritative frontiers and a root from its own archive.

    This function does not load or authenticate durable sender state itself.
    """
    obj=parse_checkpoint(raw,request,context);uint(known_floor);uint(confirmed);blob(archived_root)
    if not known_floor<=obj['floor']<=confirmed:raise Rejected('RETENTION_SENDER_FRONTIER')
    if obj['root']!=archived_root:raise Rejected('RETENTION_ARCHIVE_MISMATCH')
    return obj['floor'],obj['root']
