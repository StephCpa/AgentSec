"""Authenticated full-vector/count delivery over the witnessed mixed ledger.

Version-separated signed shape, ordered public catalog and action digest. Reuses
fixed-route encrypted outbox/inbox and mTLS framing, without changing count-v1.
Only trusted gateway admission is attested: recipient does not recheck the full
credential chain. Receiver nonrollback, public timing proof and terminal closure
are not provided by this profile.
"""
import hashlib
import json
from delivery_transport import (DeliveryLedger,RecipientInbox,DeliverySender,ENVELOPE_FIELDS,
    ACK_FIELDS,expected_bindings,valid_text,Rejected)
from witnessed_mixed_ledger import TLSWitnessedMixedLedger
from histogram_ledger import COUNT,HISTOGRAM,CODEC,canonical
from mixed_delegated_ledger import COUNT_CODEC
from dp_ledger import PROFILE as ACCOUNTANT
from wire import encode,decode,sign1,verify_sign1

PROFILE='mixed-delivery-v1'
ENVELOPE_TYPE='MixedDelivery'
ACK_TYPE='MixedDeliveryAck'
SHAPE_FIELDS={'action_digest','domain','snapshot','accountant','mechanism','capacity','bucket_count','k','codec','catalog','catalog_digest','labels'}
FIELDS=ENVELOPE_FIELDS|SHAPE_FIELDS


def validate_descriptor(obj):
    if (any(not valid_text(obj[k]) for k in ('domain','snapshot')) or
        type(obj['action_digest']) is not bytes or len(obj['action_digest'])!=32 or
        obj['accountant']!=ACCOUNTANT or type(obj['capacity']) is not int or not 1<=obj['capacity']<=65535 or
        type(obj['bucket_count']) is not int or not 1<=obj['bucket_count']<=64 or
        type(obj['k']) is not int or obj['k']!=40 or type(obj['labels']) is not list or
        type(obj['catalog_digest']) is not bytes or type(obj['catalog']) is not str):
        raise Rejected('INVALID_DELIVERY_SHAPE')
    if obj['mechanism']==COUNT:
        if (obj['bucket_count']!=1 or obj['codec']!=COUNT_CODEC or obj['labels']!=[] or
            obj['catalog']!='' or obj['catalog_digest']!=b''):raise Rejected('INVALID_DELIVERY_SHAPE')
    elif obj['mechanism']==HISTOGRAM:
        labels=obj['labels']
        if (not valid_text(obj['catalog']) or obj['codec']!=CODEC or len(labels)!=obj['bucket_count'] or
            any(type(x) is not str or not 1<=len(x.encode('utf-8'))<=64 for x in labels) or
            len(set(labels))!=len(labels) or len(obj['catalog_digest'])!=32 or
            hashlib.sha256(canonical(labels).encode()).digest()!=obj['catalog_digest']):
            raise Rejected('INVALID_DELIVERY_SHAPE')
    else:raise Rejected('INVALID_DELIVERY_SHAPE')


def validate_shape(obj):
    validate_descriptor(obj)
    result=obj['result']
    if (type(result) is not bytes or len(result)!=8*obj['bucket_count'] or
        any(int.from_bytes(result[i:i+8],'big')>obj['capacity'] for i in range(0,len(result),8))):
        raise Rejected('INVALID_DELIVERY_VECTOR')


def parse_envelope(raw,deployment,route):
    kid,obj=verify_sign1(raw,route['sender_key'],ENVELOPE_TYPE)
    if kid!=route['sender_kid'] or type(obj) is not dict or set(obj)!=FIELDS or obj['profile']!=PROFILE:
        raise Rejected('INVALID_DELIVERY_ENVELOPE')
    if any(obj[k]!=v for k,v in expected_bindings(deployment,route).items()):raise Rejected('DELIVERY_CONTEXT')
    if (any(not valid_text(obj[k]) for k in ('delivery','operation')) or type(obj['seq']) is not int or not 1<=obj['seq']<2**62 or
        type(obj['issued_at']) is not int or type(obj['expires_at']) is not int or not 0<=obj['issued_at']<obj['expires_at']<=2**62 or
        not 0<obj['expires_at']-obj['issued_at']<=60):raise Rejected('INVALID_DELIVERY_ENVELOPE')
    validate_shape(obj)
    return obj


def attempt(raw,challenge):return encode({'profile':PROFILE,'challenge':challenge,'envelope':raw})


def parse_attempt(raw):
    obj=decode(raw)
    if (type(obj) is not dict or set(obj)!={'profile','challenge','envelope'} or obj['profile']!=PROFILE or
        type(obj['challenge']) is not bytes or len(obj['challenge'])!=32 or type(obj['envelope']) is not bytes):
        raise Rejected('INVALID_DELIVERY_ATTEMPT')
    return obj


def parse_ack(raw,request,envelope,deployment,route):
    req=parse_attempt(request);obj=parse_envelope(envelope,deployment,route)
    kid,ack=verify_sign1(raw,route['receiver_key'],ACK_TYPE)
    if kid!=route['receiver_kid'] or type(ack) is not dict or set(ack)!=ACK_FIELDS or ack['profile']!=PROFILE:
        raise Rejected('INVALID_DELIVERY_ACK')
    expected=dict(profile=PROFILE,deployment=deployment,tenant=obj['tenant'],delivery=obj['delivery'],seq=obj['seq'],
        envelope_hash=hashlib.sha256(envelope).digest(),challenge=req['challenge'],request_hash=hashlib.sha256(request).digest(),receiver_cert=route['receiver_cert'])
    if req['envelope']!=envelope or any(ack[k]!=v for k,v in expected.items()):raise Rejected('DELIVERY_ACK_BINDING')
    if type(ack['accepted_at']) is not int or not obj['issued_at']<=ack['accepted_at']<obj['expires_at']:raise Rejected('INVALID_DELIVERY_ACK')
    return ack


class MixedDeliveryLedger(DeliveryLedger,TLSWitnessedMixedLedger):
    storage_profile='mtls-mixed-delivery-outbox-v1'
    delivery_profile=PROFILE
    envelope_type=ENVELOPE_TYPE
    parse_envelope=staticmethod(parse_envelope)
    parse_ack=staticmethod(parse_ack)

    def descriptor_fields(self,tenant,oid,digest):
        action,shape=self.operation_metadata(tenant,oid,digest)
        action_digest=bytes.fromhex(digest)
        mechanism,n,b,k,codec,catalog,digest=shape
        labels=[] if mechanism==COUNT else json.loads(self.catalog(tenant,action['parameters']['domain'],catalog)['buckets_json'])
        obj=dict(action_digest=action_digest,domain=action['parameters']['domain'],
            snapshot=action['parameters']['snapshot'],accountant=ACCOUNTANT,mechanism=mechanism,capacity=n,
            bucket_count=b,k=k,codec=codec,catalog=catalog,catalog_digest=digest,labels=labels)
        validate_descriptor(obj)
        return obj

    def payload_fields(self,op):
        obj=dict(self.descriptor_fields(op['tenant'],op['id'],op['digest']),result=op['result'])
        validate_shape(obj)
        return obj


class MixedRecipientInbox(RecipientInbox):
    inbox_profile=PROFILE
    delivery_profile=PROFILE
    ack_type=ACK_TYPE
    parse_attempt=staticmethod(parse_attempt)
    parse_envelope=staticmethod(parse_envelope)


class MixedDeliverySender(DeliverySender):
    attempt=staticmethod(attempt)
