"""Complete mixed v2 delivery evidence feeding immutable retention facts.

No DB, L3 admission, receiver write lock, authority CAS, or network service here.
Trusted callers establish/persist the first event before signing replies. Sender
signatures attest gateway admission; they do not prove DP computation correctness.
"""
import retention_wire as retention
from ledger import Rejected
from wire import encode,decode
from mixed_delivery_transport import SHAPE_FIELDS,validate_descriptor as validate_shape,validate_shape as validate_result
from delivery_transport import valid_text

PROFILE='mixed-delivery-v2'
DESCRIPTOR_FIELDS=SHAPE_FIELDS|{'profile','context_hash','seq','delivery','operation','issued_at','expires_at'}
ENVELOPE_FIELDS={'profile','context_hash','descriptor','result'}
CONTROL_FIELDS={'profile','context_hash','descriptor','envelope_hash'}
ATTEMPT_FIELDS={'profile','context_hash','kind','body','challenge'}
RECEIPT_FIELDS={'profile','context_hash','fact','challenge','request_hash'}
ENVELOPE_TYPE='RetentionDeliveryEnvelopeV2'
CONTROL_TYPE='RetentionDeliveryTerminalV2'
ATTEMPT_TYPE='RetentionDeliveryAttemptV2'
RECEIPT_TYPE='RetentionDeliveryReceiptV2'


def bound(obj,fields,context):
    if type(obj) is not dict or set(obj)!=fields or obj.get('profile')!=PROFILE:
        raise Rejected('DELIVERY_V2_SCHEMA')
    if obj['context_hash']!=retention.context_hash(context):raise Rejected('DELIVERY_V2_CONTEXT')
    return obj


def validate_descriptor(obj,context):
    bound(obj,DESCRIPTOR_FIELDS,context);retention.uint(obj['seq'],1)
    if obj['delivery']!=retention.delivery_id(context,obj['seq']):raise Rejected('DELIVERY_V2_ID')
    if not valid_text(obj['operation']):raise Rejected('DELIVERY_V2_OPERATION')
    retention.uint(obj['issued_at'],0,retention.MAX_TIME);retention.uint(obj['expires_at'],0,retention.MAX_TIME)
    if not 0<obj['expires_at']-obj['issued_at']<=60:raise Rejected('DELIVERY_V2_WINDOW')
    validate_shape(obj)
    return obj


def descriptor(context,*,seq,operation,issued_at,expires_at,shape):
    # Exact shape-only input prevents caller metadata from overriding route/ID.
    if type(shape) is not dict or set(shape)!=SHAPE_FIELDS:raise Rejected('DELIVERY_V2_SHAPE_FIELDS')
    obj=dict(profile=PROFILE,context_hash=retention.context_hash(context),seq=seq,
        delivery=retention.delivery_id(context,seq),operation=operation,issued_at=issued_at,expires_at=expires_at,**shape)
    return retention.frame(encode(validate_descriptor(obj,context)))


def parse_descriptor(raw,context):return validate_descriptor(decode(retention.frame(raw)),context)


def descriptor_digest(raw,context):
    parse_descriptor(raw,context)
    return retention.sha(encode(['retention-delivery-descriptor',2,raw]))


def envelope(raw_descriptor,result,context,key):
    desc=parse_descriptor(raw_descriptor,context);validate_result(dict(desc,result=result))
    return retention.signed(dict(profile=PROFILE,context_hash=retention.context_hash(context),
        descriptor=raw_descriptor,result=result),context,key,'sender',ENVELOPE_TYPE)


def parse_envelope(raw,context):
    obj=bound(retention.verified(raw,context,'sender',ENVELOPE_TYPE),ENVELOPE_FIELDS,context)
    desc=parse_descriptor(obj['descriptor'],context);validate_result(dict(desc,result=obj['result']))
    return obj


def control(raw_descriptor,envelope_hash,context,key):
    parse_descriptor(raw_descriptor,context)
    if type(envelope_hash) is not bytes or len(envelope_hash) not in (0,32):raise Rejected('DELIVERY_V2_ENVELOPE_HASH')
    return retention.signed(dict(profile=PROFILE,context_hash=retention.context_hash(context),
        descriptor=raw_descriptor,envelope_hash=envelope_hash),context,key,'sender',CONTROL_TYPE)


def parse_control(raw,context):
    obj=bound(retention.verified(raw,context,'sender',CONTROL_TYPE),CONTROL_FIELDS,context)
    parse_descriptor(obj['descriptor'],context)
    if type(obj['envelope_hash']) is not bytes or len(obj['envelope_hash']) not in (0,32):raise Rejected('DELIVERY_V2_ENVELOPE_HASH')
    return obj


def parse_body(kind,body,context):
    if kind=='DELIVERY':return parse_envelope(body,context)
    if kind=='TERMINAL':return parse_control(body,context)
    raise Rejected('DELIVERY_V2_ATTEMPT_KIND')


def attempt(kind,body,challenge,context,key):
    parse_body(kind,body,context);retention.blob(challenge)
    return retention.signed(dict(profile=PROFILE,context_hash=retention.context_hash(context),
        kind=kind,body=body,challenge=challenge),context,key,'sender',ATTEMPT_TYPE)


def parse_attempt(raw,context):
    obj=bound(retention.verified(raw,context,'sender',ATTEMPT_TYPE),ATTEMPT_FIELDS,context)
    retention.blob(obj['challenge']);parse_body(obj['kind'],obj['body'],context)
    return obj


def normalized_fact(raw_descriptor,envelope_hash,outcome,event_at,context):
    desc=parse_descriptor(raw_descriptor,context)
    return retention.fact_bytes(dict(profile=retention.PROFILE,context_hash=retention.context_hash(context),
        seq=desc['seq'],delivery=desc['delivery'],action_digest=desc['action_digest'],
        descriptor_hash=descriptor_digest(raw_descriptor,context),issued_at=desc['issued_at'],expires_at=desc['expires_at'],
        outcome=outcome,event_at=event_at,envelope_hash=envelope_hash),context)


def accepted_fact(raw_envelope,accepted_at,context):
    obj=parse_envelope(raw_envelope,context)
    return normalized_fact(obj['descriptor'],retention.sha(raw_envelope),'ACCEPTED',accepted_at,context)


def closed_fact(raw_control,closed_at,context):
    obj=parse_control(raw_control,context)
    return normalized_fact(obj['descriptor'],obj['envelope_hash'],'CLOSED',closed_at,context)


def verify_fact_evidence(raw_fact,evidence,context):
    """Validate stored first-event fact against complete signed original evidence.

    The caller obtains both bytes from a current authoritative transaction.
    This does not attest whether a first event was durably committed.
    """
    obj=retention.parse_fact(raw_fact,context)
    expected=(accepted_fact(evidence,obj['event_at'],context) if obj['outcome']=='ACCEPTED'
              else closed_fact(evidence,obj['event_at'],context))
    if expected!=raw_fact:raise Rejected('DELIVERY_V2_FACT_EVIDENCE')
    return obj


def fact_matches_request(raw_fact,request,context):
    fact=retention.parse_fact(raw_fact,context);req=parse_attempt(request,context)
    body=parse_body(req['kind'],req['body'],context)
    if req['kind']=='DELIVERY':
        if fact['outcome']!='ACCEPTED':raise Rejected('DELIVERY_V2_CLOSED')
        expected=accepted_fact(req['body'],fact['event_at'],context)
    else:
        # Existing ACCEPTED facts can answer a terminal retry after expiry;
        # never synthesize ACCEPTED from a terminal control with no envelope.
        expected=normalized_fact(body['descriptor'],body['envelope_hash'],fact['outcome'],fact['event_at'],context)
    if expected!=raw_fact:raise Rejected('DELIVERY_V2_FACT_REQUEST')
    return req


def receipt(raw_fact,request,context,key):
    # Caller must establish first-event uniqueness and authority commit ordering.
    req=fact_matches_request(raw_fact,request,context)
    return retention.signed(dict(profile=PROFILE,context_hash=retention.context_hash(context),fact=raw_fact,
        challenge=req['challenge'],request_hash=retention.sha(request)),context,key,'receiver',RECEIPT_TYPE)


def parse_receipt(raw,request,context):
    obj=bound(retention.verified(raw,context,'receiver',RECEIPT_TYPE),RECEIPT_FIELDS,context)
    req=fact_matches_request(obj['fact'],request,context)
    if obj['challenge']!=req['challenge'] or obj['request_hash']!=retention.sha(request):raise Rejected('DELIVERY_V2_REPLY_BINDING')
    return obj['fact']


def terminal_reply_fact(raw_control,existing_fact,context):
    """Validate an already committed fact for post-expiry reconciliation.

    Actual terminal admission must separately check the current clock >= expiry.
    First CLOSED creation uses closed_fact inside the same receiver transaction
    as the no-existing-fact check; this pure function does not perform that check.
    """
    obj=parse_control(raw_control,context);fact=retention.parse_fact(existing_fact,context)
    expected=normalized_fact(obj['descriptor'],obj['envelope_hash'],fact['outcome'],fact['event_at'],context)
    if expected!=existing_fact:raise Rejected('DELIVERY_V2_TERMINAL_CONFLICT')
    return existing_fact
