"""Restricted deterministic CBOR / COSE profile, not a general CBOR library.

RFC 8949 core bytewise deterministic map order; RFC 9052 Sign1 with tag 18;
RFC 9864 algorithm -19. Ed25519 is delegated to cryptography, never reimplemented.
The custom bounded parser is a reference implementation, not security-audited.
"""
import hashlib
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ledger import Rejected

MAX_SIZE=65536
MAX_DEPTH=8
MAX_ITEMS=128
SUITE='Ed25519-SHA256-CBOR-v1'
OBJECT='CountActionProof'


def head(major,n):
    if not 0<=n<2**64: raise Rejected('INTEGER_RANGE')
    prefix=major<<5
    if n<24: return bytes([prefix|n])
    for ai,size in ((24,1),(25,2),(26,4),(27,8)):
        if n<1<<(8*size): return bytes([prefix|ai])+n.to_bytes(size,'big')


def encode(obj,depth=0):
    if depth>MAX_DEPTH: raise Rejected('DEPTH_LIMIT')
    if type(obj) is int:
        out=head(0,obj) if obj>=0 else head(1,-1-obj)
    elif type(obj) in (bytes,str):
        data=obj if type(obj) is bytes else obj.encode('utf-8')
        out=head(2 if type(obj) is bytes else 3,len(data))+data
    elif type(obj) is list:
        if len(obj)>MAX_ITEMS: raise Rejected('ITEM_LIMIT')
        out=head(4,len(obj))+b''.join(encode(x,depth+1) for x in obj)
    elif type(obj) is dict:
        if len(obj)>MAX_ITEMS: raise Rejected('ITEM_LIMIT')
        entries=[]
        for key,value in obj.items():
            if type(key) not in (int,bytes,str): raise Rejected('KEY_TYPE')
            entries.append((encode(key,depth+1),encode(value,depth+1)))
        out=head(5,len(entries))+b''.join(k+v for k,v in sorted(entries))
    else: raise Rejected('UNSUPPORTED_CBOR_TYPE')
    if len(out)>MAX_SIZE: raise Rejected('SIZE_LIMIT')
    return out


def decode(data):
    if type(data) is not bytes or len(data)>MAX_SIZE: raise Rejected('SIZE_LIMIT')
    pos=0
    def take(n):
        nonlocal pos
        if n>len(data)-pos: raise Rejected('TRUNCATED_CBOR')
        out=data[pos:pos+n]; pos+=n; return out
    def parse(depth):
        if depth>MAX_DEPTH: raise Rejected('DEPTH_LIMIT')
        first=take(1)[0]; major,ai=first>>5,first&31
        if major>5: raise Rejected('UNSUPPORTED_CBOR_TYPE')
        if ai<24: n=ai
        elif ai<=27:
            size=1<<(ai-24); n=int.from_bytes(take(size),'big')
            if n<(24 if ai==24 else 1<<(8*(size//2))): raise Rejected('NONCANONICAL_CBOR')
        else: raise Rejected('INDEFINITE_OR_RESERVED')
        if major<2: return n if major==0 else -1-n
        if major in (2,3):
            raw=take(n)
            if major==2: return raw
            try: return raw.decode('utf-8','strict')
            except UnicodeDecodeError: raise Rejected('INVALID_UTF8') from None
        if n>MAX_ITEMS: raise Rejected('ITEM_LIMIT')
        if major==4: return [parse(depth+1) for _ in range(n)]
        obj={}; previous=None
        for _ in range(n):
            begin=pos; key=parse(depth+1); raw=data[begin:pos]
            if type(key) not in (int,bytes,str): raise Rejected('KEY_TYPE')
            if previous is not None and raw<=previous: raise Rejected('MAP_ORDER_OR_DUPLICATE')
            previous=raw; obj[key]=parse(depth+1)
        return obj
    obj=parse(0)
    if pos!=len(data): raise Rejected('TRAILING_CBOR')
    if encode(obj)!=data: raise Rejected('NONCANONICAL_CBOR')
    return obj


def aad(object_type=OBJECT):
    return encode(['agent-action-system',1,object_type,SUITE])


def sign1(payload,kid,private_key,object_type=OBJECT):
    # Trusted test/client primitive; not a production unrestricted signing proxy.
    protected=encode({1:-19,4:kid})
    signature=private_key.sign(encode(['Signature1',protected,aad(object_type),payload]))
    return b'\xd2'+encode([protected,{},payload,signature])


def inspect_sign1(wire,object_type=OBJECT):
    if type(wire) is not bytes or len(wire)>MAX_SIZE or not wire.startswith(b'\xd2'):
        raise Rejected('INVALID_SIGN1_TAG')
    obj=decode(wire[1:])
    if type(obj) is not list or len(obj)!=4: raise Rejected('INVALID_SIGN1_SHAPE')
    protected,unprotected,payload,signature=obj
    if type(protected) is not bytes or type(unprotected) is not dict or unprotected:
        raise Rejected('INVALID_HEADERS')
    headers=decode(protected)
    if type(headers) is not dict or set(headers)!={1,4} or headers[1]!=-19:
        raise Rejected('INVALID_ALGORITHM_OR_HEADERS')
    if type(headers[4]) is not bytes or not 1<=len(headers[4])<=32:
        raise Rejected('INVALID_KEY_ID')
    if type(payload) is not bytes or type(signature) is not bytes or len(signature)!=64:
        raise Rejected('INVALID_SIGN1_CONTENT')
    decode(payload)
    return headers[4],payload,signature,encode(['Signature1',protected,aad(object_type),payload])


def verify_sign1(wire,public_key,object_type=OBJECT):
    kid,payload,signature,message=inspect_sign1(wire,object_type)
    try: Ed25519PublicKey.from_public_bytes(public_key).verify(signature,message)
    except (InvalidSignature,ValueError): raise Rejected('INVALID_SIGNATURE') from None
    return kid,decode(payload)


ACTION_FIELDS={'profile','tenant','operation','root','actor','kid','domain','snapshot','recipient',
               'mechanism','accountant','epsilon_max','delta_max','not_before','deadline'}
PROOF_FIELDS={'profile','action_digest','audience','challenge','challenge_expiry','proof_id'}


def identifier(value):
    if type(value) is not str or re.fullmatch('[A-Za-z0-9_-]{1,64}',value) is None:
        raise Rejected('INVALID_WIRE_ID')


def parse_action(raw):
    obj=decode(raw)
    if type(obj) is not dict or obj.get('profile') not in ('count-direct-v1','count-delegated-v1'):
        raise Rejected('INVALID_ACTION_SCHEMA')
    delegated=obj['profile']=='count-delegated-v1'
    if set(obj)!=(ACTION_FIELDS|{'leaf_digest'} if delegated else ACTION_FIELDS):
        raise Rejected('INVALID_ACTION_SCHEMA')
    if delegated and (type(obj['leaf_digest']) is not bytes or len(obj['leaf_digest'])!=32):
        raise Rejected('INVALID_LEAF_DIGEST')
    for key in ('tenant','operation','root','actor','domain','snapshot','recipient'):
        identifier(obj[key])
    if type(obj['kid']) is not bytes or not 1<=len(obj['kid'])<=32: raise Rejected('INVALID_KEY_ID')
    for key in ('epsilon_max','delta_max','not_before','deadline'):
        if type(obj[key]) is not int or not 0<=obj[key]<=2**62: raise Rejected('INVALID_WIRE_INTEGER')
    if obj['not_before']>=obj['deadline']: raise Rejected('INVALID_ACTION_WINDOW')
    return obj


def parse_proof(obj):
    if type(obj) is not dict or set(obj)!=PROOF_FIELDS or obj['profile'] not in ('count-direct-v1','count-delegated-v1'):
        raise Rejected('INVALID_PROOF_SCHEMA')
    for key in ('action_digest','challenge','proof_id'):
        if type(obj[key]) is not bytes or len(obj[key])!=(16 if key=='proof_id' else 32):
            raise Rejected('INVALID_PROOF_BYTES')
    identifier(obj['audience'])
    if type(obj['challenge_expiry']) is not int or not 0<=obj['challenge_expiry']<=2**62:
        raise Rejected('INVALID_PROOF_EXPIRY')
    return obj


def action_digest(raw):
    parse_action(raw)
    return hashlib.sha256(raw).digest()
