"""Result-free terminal reconciliation for signed count/histogram deliveries.

Reuses the atomic inbox ACCEPTED/CLOSED barrier, with separate signature domains
and a public operation descriptor matching MixedDelivery. Does not repair a
rolled-back recipient store or prove arbitrary external side effects exactly once.
"""
import hashlib
from delivery_transport import BINDINGS,expected_bindings,valid_text,Rejected
from delivery_terminal import (TerminalDeliveryLedger,TerminalRecipientInbox,TerminalDeliverySender,
    CONTROL_FIELDS as COUNT_CONTROL_FIELDS,RECEIPT_FIELDS,ENVELOPE_MATCH_FIELDS)
from mixed_delivery_transport import (MixedDeliveryLedger,MixedRecipientInbox,MixedDeliverySender,
    SHAPE_FIELDS,validate_descriptor)
from wire import encode,decode,sign1,verify_sign1

PROFILE='mixed-delivery-terminal-v1'
CONTROL_TYPE='MixedDeliveryTerminal'
RECEIPT_TYPE='MixedDeliveryTerminalAck'
CONTROL_FIELDS=COUNT_CONTROL_FIELDS|SHAPE_FIELDS


def terminal_attempt(raw,challenge):return encode({'profile':PROFILE,'challenge':challenge,'terminal':raw})


def parse_terminal_attempt(raw):
    obj=decode(raw)
    if (type(obj) is not dict or set(obj)!={'profile','challenge','terminal'} or obj['profile']!=PROFILE or
        type(obj['challenge']) is not bytes or len(obj['challenge'])!=32 or type(obj['terminal']) is not bytes):
        raise Rejected('INVALID_TERMINAL_ATTEMPT')
    return obj


def parse_control(raw,deployment,route):
    kid,obj=verify_sign1(raw,route['sender_key'],CONTROL_TYPE)
    if kid!=route['sender_kid'] or type(obj) is not dict or set(obj)!=CONTROL_FIELDS or obj['profile']!=PROFILE:
        raise Rejected('INVALID_TERMINAL_CONTROL')
    if any(obj[k]!=v for k,v in expected_bindings(deployment,route).items()):raise Rejected('TERMINAL_CONTEXT')
    if (any(not valid_text(obj[k]) for k in ('delivery','operation')) or type(obj['seq']) is not int or not 1<=obj['seq']<2**62 or
        type(obj['issued_at']) is not int or type(obj['expires_at']) is not int or not 0<=obj['issued_at']<obj['expires_at']<=2**62 or
        not 0<obj['expires_at']-obj['issued_at']<=60 or type(obj['envelope_hash']) is not bytes or len(obj['envelope_hash']) not in (0,32)):
        raise Rejected('INVALID_TERMINAL_CONTROL')
    validate_descriptor(obj)
    return obj


def parse_receipt(raw,request,control,deployment,route):
    req=parse_terminal_attempt(request);obj=parse_control(control,deployment,route)
    kid,ack=verify_sign1(raw,route['receiver_key'],RECEIPT_TYPE)
    if kid!=route['receiver_kid'] or type(ack) is not dict or set(ack)!=RECEIPT_FIELDS or ack['profile']!=PROFILE:
        raise Rejected('INVALID_TERMINAL_RECEIPT')
    expected=dict(profile=PROFILE,deployment=deployment,tenant=obj['tenant'],delivery=obj['delivery'],seq=obj['seq'],
        terminal_hash=hashlib.sha256(control).digest(),envelope_hash=obj['envelope_hash'],challenge=req['challenge'],
        request_hash=hashlib.sha256(request).digest(),receiver_cert=route['receiver_cert'])
    if req['terminal']!=control or any(ack[k]!=v for k,v in expected.items()):raise Rejected('TERMINAL_RECEIPT_BINDING')
    if type(ack['event_at']) is not int or not 0<=ack['event_at']<=2**62:raise Rejected('INVALID_TERMINAL_RECEIPT')
    if ack['outcome']=='ACCEPTED':
        if len(obj['envelope_hash'])!=32 or not obj['issued_at']<=ack['event_at']<obj['expires_at']:raise Rejected('INVALID_TERMINAL_RECEIPT')
    elif ack['outcome']=='CLOSED':
        if ack['event_at']<obj['expires_at']:raise Rejected('INVALID_TERMINAL_RECEIPT')
    else:raise Rejected('INVALID_TERMINAL_RECEIPT')
    return ack


class MixedTerminalDeliveryLedger(TerminalDeliveryLedger,MixedDeliveryLedger):
    storage_profile='mtls-mixed-delivery-terminal-v1'
    terminal_profile=PROFILE
    control_type=CONTROL_TYPE
    parse_control=staticmethod(parse_control)
    parse_receipt=staticmethod(parse_receipt)

    def terminal_fields(self,ticket):
        # Public descriptor only; no result/seed opening needed to construct it.
        row=self.db.execute('SELECT digest FROM operations WHERE tenant=? AND id=?',
                            (ticket['tenant'],ticket['operation_id'])).fetchone()
        if row is None:raise Rejected('RESULT_UNAVAILABLE')
        return self.descriptor_fields(ticket['tenant'],ticket['operation_id'],row['digest'])


class MixedTerminalRecipientInbox(TerminalRecipientInbox,MixedRecipientInbox):
    inbox_profile=PROFILE
    terminal_profile=PROFILE
    receipt_type=RECEIPT_TYPE
    parse_terminal_attempt=staticmethod(parse_terminal_attempt)
    parse_control=staticmethod(parse_control)
    envelope_match_fields=ENVELOPE_MATCH_FIELDS|SHAPE_FIELDS


class MixedTerminalDeliverySender(TerminalDeliverySender,MixedDeliverySender):
    terminal_attempt=staticmethod(terminal_attempt)
