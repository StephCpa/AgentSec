"""Deterministic cross-language corpus; Node receives inputs, never expectations.

Python uses existing production parsers. Node independently implements profile
encoding, signatures and selected response/RPC contracts. Keys are synthetic.
"""
import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import lzma
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from wire import encode,decode,sign1,verify_sign1,inspect_sign1
from ledger import Rejected
from public_gateway import response
from witness_transport import parse_request,TLSWitnessClient,ERRORS
from witnessed_ledger import image_hash,MAX_IMAGE

ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'tests/node/wire-profile.mjs'
KEY=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUB=KEY.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
DER=KEY.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
KID=b'interop';DOMAIN='AgentPublicResponseV1';DEPLOY=b'D'*16
SEED=20261026


def view(v):
    if type(v) is int:return ['i',str(v)]
    if type(v) is bytes:return ['b',v.hex()]
    if type(v) is str:return ['t',v]
    if type(v) is list:return ['a',[view(x) for x in v]]
    if type(v) is dict:return ['m',[[view(k),view(v[k])] for k in sorted(v,key=encode)]]
    if type(v) is bool:return ['bool',v]
    if v is None:return ['null']
    if type(v) is float:return ['float',str(v)]
    raise TypeError(type(v))


def native(v):
    kind=v[0]
    if kind=='i':return int(v[1])
    if kind=='b':return bytes.fromhex(v[1])
    if kind=='t':return v[1]
    if kind=='a':return [native(x) for x in v[1]]
    if kind=='m':return {native(k):native(x) for k,x in v[1]}
    if kind=='bool':return v[1]
    if kind=='null':return None
    if kind=='float':return float(v[1])
    raise ValueError('fixture value')


def python_result(c):
    b=lambda key:bytes.fromhex(c[key]);op=c['op']
    try:
        if op=='decode':out=view(decode(b('raw')))
        elif op=='encode':out=encode(native(c['value'])).hex()
        elif op=='sign':out=sign1(b('payload'),b('kid'),serialization.load_der_private_key(b('private_der'),None),c['object_type']).hex()
        elif op=='verify':
            kid,value=verify_sign1(b('raw'),b('public_key'),c['object_type'])
            out=dict(kid=kid.hex(),value=view(value),message=inspect_sign1(b('raw'),c['object_type'])[3].hex())
        elif op=='public_response':out=view(response(b('raw'),b('request'),b('public_key'),b('kid'),b('deployment')))
        elif op=='witness_request':out=view(parse_request(b('raw'),b('body')))
        elif op=='witness_reply':
            req=parse_request(b('request'),b('request_body'));client=object.__new__(TLSWitnessClient)
            client.public_key=b('public_key');client.kid=b('kid');client.requester=b('requester')
            def exchange(raw,body):
                if raw!=b('request') or body!=b('request_body'):raise AssertionError('fixture request reconstruction differs')
                return b('raw'),b('body')
            client.exchange=exchange
            extra={k:v for k,v in req.items() if k not in ('profile','service','method','namespace','challenge','body_size','body_hash')}
            with patch('witness_transport.secrets.token_bytes',return_value=req['challenge']):
                out=view(client.call(req['method'],req['namespace'],b('request_body'),**extra))
        else:raise ValueError('fixture op')
        return dict(accepted=True,result=out)
    except Rejected as exc:
        if op=='witness_reply' and str(exc) in ERRORS:return dict(accepted=False,rejection=str(exc))
        return dict(accepted=False,error=str(exc))
    except UnicodeEncodeError as exc:
        if op!='encode':raise
        return dict(accepted=False,error='INVALID_UTF8')


def corpus():
    cases=[];rng=random.Random(SEED)
    def add(group,name,op,expected=None,**inputs):
        cases.append(dict(id=group+':'+name,group=group,input=dict(op=op,**inputs),expected=expected))
    # Handwritten canonical examples, including core bytewise rather than length-first map order.
    manual=[('zero','00',0),('negative','20',-1),('uint64','1bffffffffffffffff',2**64-1),
        ('negative64','3bffffffffffffffff',-2**64),('mixed-map-order','a4181800200040006000',{24:0,-1:0,b'':0,'':0}),
        ('bom-preserved','63efbbbf','\ufeff'),('unicode','66e4b8ade69687','中文'),('empty-map','a0',{})]
    for name,raw,value in manual:
        add('canonical',name,'decode',True,raw=raw)
        add('canonical',name+'-encode','encode',True,value=view(value))
        cases[-1]['expected_hex']=raw
    boundaries=[0,23,24,255,256,65535,65536,2**32-1,2**32,2**53-1,2**53,2**53+1,2**62,2**63-1,2**63,2**64-1]
    values=boundaries+[-1-n for n in boundaries]+[b'',b'x'*23,b'x'*24,b'x'*255,b'x'*256,b'x'*65533,
        '', 'e\u0301','é','😀','\ufeffx',[0]*128,{i:i for i in range(128)}]
    nested=0
    for _ in range(8):nested=[nested]
    values.append(nested)
    for i,value in enumerate(values):
        raw=encode(value);add('boundary',str(i),'decode',True,raw=raw.hex());add('boundary',str(i)+'-encode','encode',True,value=view(value))
    for i,value in enumerate((2**64,-2**64-1,True,None,1.5,'\ud800',b'x'*65534,[0]*129,[nested])):
        add('boundary','reject-encode-'+str(i),'encode',False,value=view(value))
    invalid=['','1800','190018','1a00000100','1b0000000000010000','3800','5800','7800','9800','b800',
        '9f00ff','5f40ff','7f60ff','bf00ff','ff','f4','f5','f6','f7','f800','f90000','fa00000000','fb0000000000000000',
        'c000','d200','1c','1d','1e','1f','4100ff','01ff','63c0af00','63eda080','64f4908080',
        'a200000001','a201000000','a280000000','81818181818181818100','5818','590100','a1810000']
    for i,raw in enumerate(invalid):add('malformed',str(i),'decode',False,raw=raw)
    add('malformed','over-size','decode',False,raw=(b'\x00'*65537).hex())
    def random_value(depth=0):
        choices=4 if depth>=3 else 6;kind=rng.randrange(choices)
        if kind==0:return rng.choice(boundaries) * rng.choice((1,-1))
        if kind==1:return bytes(rng.randrange(256) for _ in range(rng.randrange(24)))
        if kind==2:return rng.choice(('','文本','\ufeff','a','é','😀'))+str(rng.randrange(100))
        if kind==3:return rng.randrange(-2000,2000)
        if kind==4:return [random_value(depth+1) for _ in range(rng.randrange(5))]
        return {rng.choice((i,str(i),bytes([i]))):random_value(depth+1) for i in range(rng.randrange(5))}
    for i in range(160):
        value=random_value();raw=encode(value)
        add('generated',str(i),'decode',True,raw=raw.hex());add('generated',str(i)+'-encode','encode',True,value=view(value))
        changed=bytearray(raw);changed[rng.randrange(len(raw))]^=1<<rng.randrange(8)
        add('mutation',str(i),'decode',raw=bytes(changed).hex())
        add('mutation',str(i)+'-truncated','decode',raw=raw[:-1].hex())
    for i in range(400):add('random-bytes',str(i),'decode',raw=bytes(rng.randrange(256) for _ in range(rng.randrange(40))).hex())
    payloads=[{},0,2**63-1,{'large':2**53+1,'unicode':'中文'},[b'\x00\xff',-19,'text']]
    for domain in ('CountActionProof','AgentPublicRequestV1','AgentPublicResponseV1','WitnessResponse'):
        for i,value in enumerate(payloads):
            payload=encode(value);wire=sign1(payload,KID,KEY,domain);base=dict(raw=wire.hex(),public_key=PUB.hex(),object_type=domain)
            add('cose',domain+str(i),'verify',True,**base)
            add('cose',domain+str(i)+'-sign','sign',True,payload=payload.hex(),kid=KID.hex(),private_der=DER.hex(),object_type=domain)
            add('cose',domain+str(i)+'-domain','verify',False,**dict(base,object_type=domain+'-other'))
            add('cose',domain+str(i)+'-key','verify',False,**dict(base,public_key=bytes(32).hex()))
            corrupted=bytearray(wire);corrupted[-1]^=1
            add('cose',domain+str(i)+'-signature','verify',False,**dict(base,raw=bytes(corrupted).hex()))
    normal=sign1(encode({}),KID,KEY,DOMAIN)
    malformed_wires=[normal[1:],b'\xd8\x12'+normal[1:],b'\xd1'+normal[1:],normal+b'\x00',normal[:-1]]
    for protected,unprotected,payload,signature in [
        (encode({1:-8,4:KID}),{},encode({}),bytes(64)),(encode({1:-19,4:KID,2:[]}),{},encode({}),bytes(64)),
        (encode({1:-19,4:b''}),{},encode({}),bytes(64)),(encode({1:-19,4:b'x'*33}),{},encode({}),bytes(64)),
        (encode({1:-19,4:KID}),{4:KID},encode({}),bytes(64)),(encode({1:-19,4:KID}),{},encode({}),bytes(63))]:
        if len(signature)==64:signature=KEY.sign(encode(['Signature1',protected,encode(['agent-action-system',1,DOMAIN,'Ed25519-SHA256-CBOR-v1']),payload]))
        malformed_wires.append(b'\xd2'+encode([protected,unprotected,payload,signature]))
    malformed_wires += [sign1(raw,KID,KEY,DOMAIN) for raw in (b'\x18\x00',b'\xa2\x00\x00\x00\x01',b'\xf6')]
    for i,raw in enumerate(malformed_wires):add('cose-malformed',str(i),'verify',False,raw=raw.hex(),public_key=PUB.hex(),object_type=DOMAIN)
    old=json.loads((ROOT/'tests/vectors/public-responses.json').read_text())
    for row in old['vectors']:
        add('frozen-public',row['name'],'public_response',row['accepted'],raw=row['response_hex'],request=old['request_hex'],public_key=old['gateway_key_hex'],kid=old['gateway_kid_hex'],deployment=old['deployment_hex'])
    request=b'synthetic public request';common=dict(profile='agent-public-gateway-v1',deployment=DEPLOY,request_hash=hashlib.sha256(request).digest(),sequence=1)
    def public_case(name,status,body,expected,outer=None):
        obj=dict(common,status=status,body=body);obj.update(outer or {})
        add('public-body',name,'public_response',expected,raw=sign1(encode(obj),KID,KEY,DOMAIN).hex(),request=request.hex(),public_key=PUB.hex(),kid=KID.hex(),deployment=DEPLOY.hex())
    allowed={('UNPUBLISHED','UNFINALIZED'),('WITHHELD','UNFINALIZED'),('WITHHELD','WITHHELD'),('ADMITTED','UNFINALIZED'),('ADMITTED','ACCEPTED'),('ADMITTED','CLOSED')}
    for publication in ('UNPUBLISHED','WITHHELD','ADMITTED',b'ADMITTED','__proto__'):
        for final in ('UNFINALIZED','WITHHELD','ACCEPTED','CLOSED',b'ACCEPTED'):
            public_case(str(publication)+'/'+str(final),'POLL',dict(operation='a',sequence=1,publication=publication,final=final),(publication,final) in allowed)
    for kind,body in [('pause',dict(kind='pause')),('resume',dict(kind='resume')),('cancel',dict(kind='cancel',operation='a')),('revoke',dict(kind='revoke',root='r'))]:
        public_case(kind,'CONTROL_RECORDED',body,True);public_case(kind+'-extra','CONTROL_RECORDED',dict(body,extra=1),False)
    for operation in ('', 'a'*64,'a'*65,'中文',b'a'):
        public_case('identifier-'+str(operation),'RECORDED',dict(operation=operation,sequence=1),type(operation) is str and 1<=len(operation)<=64 and operation.isascii())
    for name,body,ok in [('empty',dict(events=[],cursor=0),True),('gap',dict(events=[dict(sequence=i,operation='a',outcome='ACCEPTED') for i in (1,3)],cursor=3),False),('cursor',dict(events=[dict(sequence=1,operation='a',outcome='ACCEPTED')],cursor=2),False)]:public_case(name,'FINAL',body,ok)
    for k,v in [('profile','wrong'),('deployment',b'X'*16),('request_hash',bytes(32)),('sequence',0),('extra',0)]:
        public_case('outer-'+k,'RECORDED',dict(operation='a',sequence=1),False,{k:v})
    witness_cases(cases,add)
    if len({c['id'] for c in cases})!=len(cases):raise AssertionError('duplicate corpus identity')
    return cases


def witness_cases(cases,add):
    peer=b'P'*32;ns='a'*32;body=b'synthetic opaque image';digest=image_hash(body)
    def request(method,body=b'',**extra):
        return dict(profile='witness-rpc-v1',service='agent-ledger-witness-v1',method=method,namespace=ns,challenge=b'C'*32,
            body_size=len(body),body_hash=hashlib.sha256(body).digest(),**extra)
    requests=[(request('head',include_image=0),b''),(request('head',include_image=1),b''),(request('bootstrap',body),body),
              (request('cas',body,expected_seq=0,expected_digest=digest,request_id='b'*32),body),
              (request('reassert',expected_seq=2**62-1,expected_digest=digest,request_id='b'*32),b'')]
    for index,(req,data) in enumerate(requests):
        raw=encode(req)
        add('witness-request',str(index),'witness_request',True,raw=raw.hex(),body=data.hex())
        for field,value in [('namespace','A'*32),('challenge',b'C'*31),('body_size',len(data)+1),('body_hash',bytes(32)),('method','unknown'),('extra',0)]:
            add('witness-request',str(index)+'-'+field,'witness_request',False,raw=encode(dict(req,**{field:value})).hex(),body=data.hex())
        for field in req:
            changed=dict(req);del changed[field]
            add('witness-request',str(index)+'-missing-'+field,'witness_request',False,raw=encode(changed).hex(),body=data.hex())
        if req['method'] in ('cas','reassert'):
            for seq in (-1,0,2**62-1,2**62):
                add('witness-request',str(index)+'-seq-'+str(seq),'witness_request',0<=seq<2**62,raw=encode(dict(req,expected_seq=seq)).hex(),body=data.hex())
        response_body=data if req['method']=='head' and req['include_image'] else b''
        if req['method']=='head' and req['include_image']:response_body=body
        result=dict(seq=0 if req['method'] in ('bootstrap','head') else req['expected_seq']+1,digest=digest)
        reply=dict(profile=req['profile'],service=req['service'],method=req['method'],namespace=ns,challenge=req['challenge'],
            request_digest=hashlib.sha256(raw).digest(),requester=peer,status='ok',result=result,
            body_size=len(response_body),body_hash=hashlib.sha256(response_body).digest())
        def add_reply(name,value,reply_body=response_body,expected=True):
            add('witness-reply',str(index)+'-'+name,'witness_reply',expected,raw=sign1(encode(value),KID,KEY,'WitnessResponse').hex(),body=reply_body.hex(),
                request=raw.hex(),request_body=data.hex(),public_key=PUB.hex(),kid=KID.hex(),requester=peer.hex())
        add_reply('valid',reply)
        for field,value in [('challenge',b'X'*32),('requester',bytes(32)),('request_digest',bytes(32)),('method','other'),('namespace','b'*32),('body_size',len(response_body)+1),('body_hash',bytes(32)),('extra',0)]:
            add_reply(field,dict(reply,**{field:value}),expected=False)
        for seq in (-1,2**62+1):add_reply('bad-seq-'+str(seq),dict(reply,result=dict(result,seq=seq)),expected=False)
        if req['method']!='head':
            add_reply('wrong-next-seq',dict(reply,result=dict(result,seq=result['seq']+1)),expected=False)
            add_reply('wrong-result-digest',dict(reply,result=dict(result,digest='f'*64)),expected=False)
        for error in sorted(ERRORS):
            denial=dict(reply,status='rejected',result=dict(error=error),body_size=0,body_hash=hashlib.sha256(b'').digest())
            add_reply(error,denial,b'',False)
            cases[-1]['expected_rejection']=error
        add_reply('unknown-error',dict(reply,status='rejected',result=dict(error='PRIVATE_INTERNAL_ERROR'),body_size=0,body_hash=hashlib.sha256(b'').digest()),b'',False)
        add_reply('unexpected-body',dict(reply,body_size=1,body_hash=hashlib.sha256(b'x').digest()),b'x',False)
    for name,method,data in [('empty-bootstrap','bootstrap',b''),('nonempty-head','head',b'x'),('nonempty-reassert','reassert',b'x')]:
        extra={'include_image':0} if method=='head' else {'expected_seq':0,'expected_digest':digest,'request_id':'b'*32} if method=='reassert' else {}
        add('witness-request',name,'witness_request',False,raw=encode(request(method,data,**extra)).hex(),body=data.hex())
    for size in (MAX_IMAGE,MAX_IMAGE+1):
        data=b'A'*size;req=request('bootstrap',data)
        add('witness-limits',str(size),'witness_request',size<=MAX_IMAGE,raw=encode(req).hex(),body=data.hex())


def run(cases=None,node_source=None):
    cases=corpus() if cases is None else cases;node=shutil.which('node')
    executed=NODE if node_source is None else Path(node_source)
    if node is None:raise RuntimeError('Node.js is required for independent protocol tests; this check is not skipped')
    actual=subprocess.run([node,str(executed)],input=json.dumps([c['input'] for c in cases],ensure_ascii=True),text=True,capture_output=True,timeout=120,check=True)
    output=json.loads(actual.stdout)
    if len(output['results'])!=len(cases):raise AssertionError('Node result count differs')
    failures=[];rows=[]
    for c,observed in zip(cases,output['results']):
        expected=python_result(c['input']);error=None
        if 'fault' in observed:error='Node internal fault: '+observed['fault']
        elif expected['accepted']!=observed['accepted']:error='acceptance differs'
        elif expected['accepted'] and expected['result']!=observed['result']:error='decoded value or encoded/signed bytes differ'
        elif expected.get('rejection')!=observed.get('rejection'):error='authenticated rejection differs'
        if c['expected'] is not None and (expected['accepted']!=c['expected'] or observed.get('accepted')!=c['expected']):error='curated expectation differs'
        if 'expected_hex' in c and (expected.get('result')!=c['expected_hex'] or observed.get('result')!=c['expected_hex']):error='handwritten canonical bytes differ'
        if 'expected_rejection' in c and (expected.get('rejection')!=c['expected_rejection'] or observed.get('rejection')!=c['expected_rejection']):error='curated signed rejection differs'
        if not error and c['input']['op']=='sign' and expected['accepted']:
            verify_sign1(bytes.fromhex(observed['result']),PUB,c['input']['object_type'])
        if error:failures.append(dict(id=c['id'],error=error,python=expected,node=observed))
        rows.append(dict(c,python=expected,node=observed))
    report=dict(passed=not failures,cases=len(cases),groups=dict(Counter(c['group'] for c in cases)),operations=dict(Counter(c['input']['op'] for c in cases)),
        python_accepted=sum(r['python']['accepted'] for r in rows),curated_expectations=sum(c['expected'] is not None for c in cases),
        node=output['node'],node_openssl=output['openssl'],executed_node_sha256=hashlib.sha256(executed.read_bytes()).hexdigest(),node_source_kind='repository' if node_source is None else 'negative-control',python=sys.version,cryptography=cryptography.__version__,python_crypto_backend=backend.openssl_version_text(),seed=SEED,failures=failures,
        scope='Independent Node CBOR/COSE construction and selected public response/witness schemas vs actual Python code. Node receives only typed inputs, not expected values. Deterministic corpus, not exhaustive fuzzing, full protocol interoperability, CDDL-engine validation or independent cryptographic-primitive proof.')
    sources=[Path(__file__),NODE,ROOT/'tests/vectors/public-responses.json']+[Path(__file__).parent/n for n in ('wire.py','public_input.py','public_gateway.py','witness_transport.py','witnessed_ledger.py','public_gateway_v1.cddl','witness_rpc_v1.cddl')]
    report['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    return report,rows



def negative_controls():
    selected=[c for c in corpus() if c['group'] in ('canonical','cose','cose-malformed','frozen-public')]
    source=NODE.read_text()
    variants=[
        ('round-uint64',"if(major===0)return argument;","if(major===0)return BigInt(Number(argument));",'canonical:uint64'),
        ('drop-utf8-bom','ignoreBOM:true','ignoreBOM:false','canonical:bom-preserved'),
        ('length-first-map',"pairs.sort((a,b)=>Buffer.compare(a[0],b[0]));","pairs.sort((a,b)=>a[0].length-b[0].length||Buffer.compare(a[0],b[0]));",'canonical:mixed-map-order'),
        ('allow-polymorphic-alg',"h.get(1n)===-19n","(h.get(1n)===-19n||h.get(1n)===-8n)",'cose-malformed:5'),
        ('relax-audience',"g('audience')==='mixed-gateway-v1'","id(g('audience'))",'frozen-public:audience-other-gateway-v1'),
        ('collapse-signing-domains',"aad(type)","aad('CountActionProof')",'cose:AgentPublicResponseV10')]
    results=[]
    with tempfile.TemporaryDirectory() as td:
        for name,old,new,target in variants:
            if old not in source:raise AssertionError('mutation anchor absent: '+name)
            altered=source.replace(old,new);path=Path(td)/(name+'.mjs');path.write_text(altered)
            report,_=run(selected,path)
            faults=[f for f in report['failures'] if f['error'].startswith('Node internal fault')]
            if faults or target not in {f['id'] for f in report['failures']}:raise AssertionError('negative control ineffective: '+name)
            results.append(dict(name=name,detected=True,target=target,mismatch_count=len(report['failures']),
                source_sha256=hashlib.sha256(altered.encode()).hexdigest(),replacement=dict(old=old,new=new)))
    return dict(passed=True,controls=results,baseline_node_sha256=hashlib.sha256(NODE.read_bytes()).hexdigest(),
                scope='Intentional defects in disposable Node copies. Each must cause the designated semantic/acceptance mismatch, not an internal crash. They are not defects found in the Python implementation.')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    report,rows=run();controls=negative_controls() if report['passed'] else None;args.output.mkdir(parents=True)
    with lzma.open(args.output/'cases.jsonl.xz','wt') as f:
        for row in rows:f.write(json.dumps(row,ensure_ascii=True,separators=(',',':'))+'\n')
    if controls is not None:(args.output/'negative-controls.json').write_text(json.dumps(controls,indent=2)+'\n')
    (args.output/'summary.json').write_text(json.dumps(report,indent=2,ensure_ascii=True)+'\n')
    print('PASS' if report['passed'] else 'FAIL',report['cases'],'cross-language cases;',len(report['failures']),'mismatches')
    for row in report['failures'][:10]:print(row['id'],row['error'])
    return 0 if report['passed'] else 1

if __name__=='__main__':sys.exit(main())
