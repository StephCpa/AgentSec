"""Pure public-payload syntax validation; no database, key lookup or private state.

Only Rejected from these bounded input parsers is normalized. Do not reuse this
catch boundary around dispatch, storage, cryptography state or a private read.
"""
from ledger import Rejected
from wire import decode,inspect_sign1,identifier
from mixed_delegated_ledger import parse_mixed_action,parse_mixed_proof,parse_mixed_credential


def validate_public_payload(method,payload):
    try:
        if type(payload) is not dict:raise Rejected('GW_PAYLOAD')
        if method=='CHALLENGE':
            if payload:raise Rejected('GW_PAYLOAD')
        elif method=='SUBMIT':
            if set(payload)!={'action','proof','chain'} or type(payload['action']) is not bytes or type(payload['proof']) is not bytes or type(payload['chain']) is not list:raise Rejected('GW_PAYLOAD')
            chain=payload['chain']
            if not 1<=len(chain)<=8 or any(type(x) is not bytes for x in chain) or sum(map(len,chain))>65536:raise Rejected('GW_PAYLOAD')
            parse_mixed_action(payload['action'])
            parse_mixed_proof(decode(inspect_sign1(payload['proof'])[1]))
            for raw in chain:parse_mixed_credential(raw)
        elif method=='POLL':
            if set(payload)!={'operation'}:raise Rejected('GW_PAYLOAD')
            identifier(payload['operation'])
        elif method=='FINAL':
            if set(payload)!={'cursor','limit'} or type(payload['cursor']) is not int or not 0<=payload['cursor']<2**63 or type(payload['limit']) is not int or not 1<=payload['limit']<=16:raise Rejected('GW_PAYLOAD')
        elif method=='CONTROL':
            kind=payload.get('kind')
            if kind in ('pause','resume'):
                if set(payload)!={'kind'}:raise Rejected('GW_PAYLOAD')
            elif kind=='cancel':
                if set(payload)!={'kind','operation'}:raise Rejected('GW_PAYLOAD')
                identifier(payload['operation'])
            elif kind=='revoke':
                if set(payload)!={'kind','root'}:raise Rejected('GW_PAYLOAD')
                identifier(payload['root'])
            else:raise Rejected('GW_PAYLOAD')
        else:raise Rejected('GW_PAYLOAD')
    except Rejected:
        raise Rejected('GW_PAYLOAD') from None


def validate_public_response_body(status,body):
    """Strict output vocabulary, before signing; not an implicit-flow proof."""
    def uint(value,low=0):return type(value) is int and low<=value<2**63
    try:
        if type(body) is not dict:raise Rejected('GW_RESPONSE_BODY')
        if status=='REJECTED':
            if body:raise Rejected('GW_RESPONSE_BODY')
        elif status=='CHALLENGE':
            if set(body)!={'challenge','challenge_expiry','audience'} or type(body['challenge']) is not bytes or len(body['challenge'])!=32 or not uint(body['challenge_expiry']) or body['challenge_expiry']>2**62:raise Rejected('GW_RESPONSE_BODY')
            identifier(body['audience'])
        elif status=='RECORDED':
            if set(body)!={'operation','sequence'} or not uint(body['sequence'],1):raise Rejected('GW_RESPONSE_BODY')
            identifier(body['operation'])
        elif status=='CONTROL_RECORDED':validate_public_payload('CONTROL',body)
        elif status=='POLL':
            if set(body)!={'operation','sequence','publication','final'} or not uint(body['sequence'],1) or body['publication'] not in ('UNPUBLISHED','ADMITTED','WITHHELD') or body['final'] not in ('UNFINALIZED','WITHHELD','ACCEPTED','CLOSED'):raise Rejected('GW_RESPONSE_BODY')
            identifier(body['operation'])
            if body['publication']=='UNPUBLISHED' and body['final']!='UNFINALIZED':raise Rejected('GW_RESPONSE_BODY')
            if body['publication']=='WITHHELD' and body['final'] not in ('UNFINALIZED','WITHHELD'):raise Rejected('GW_RESPONSE_BODY')
            if body['publication']=='ADMITTED' and body['final']=='WITHHELD':raise Rejected('GW_RESPONSE_BODY')
        elif status=='FINAL':
            if set(body)!={'events','cursor'} or not uint(body['cursor']) or type(body['events']) is not list or len(body['events'])>16:raise Rejected('GW_RESPONSE_BODY')
            previous=None
            for event in body['events']:
                if type(event) is not dict or set(event)!={'sequence','outcome','operation'} or not uint(event['sequence'],1) or event['outcome'] not in ('WITHHELD','ACCEPTED','CLOSED'):raise Rejected('GW_RESPONSE_BODY')
                identifier(event['operation'])
                if previous is not None and event['sequence']!=previous+1:raise Rejected('GW_RESPONSE_BODY')
                previous=event['sequence']
            if previous is not None and body['cursor']!=previous:raise Rejected('GW_RESPONSE_BODY')
        else:raise Rejected('GW_RESPONSE_BODY')
    except Rejected:raise Rejected('GW_RESPONSE_BODY') from None
