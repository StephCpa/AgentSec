// Independent restricted-profile implementation for cross-language validation.
// No Python invocation, no production parser imports, no npm dependencies.
// Ed25519 is delegated to node:crypto. Integers stay BigInt end to end.
import {createHash, createPublicKey, createPrivateKey, sign, verify} from 'node:crypto';
import {readFileSync, realpathSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

const LIMIT=65536, DEPTH=8, ITEMS=128, U64=1n<<64n, U62=1n<<62n, U63=1n<<63n;
class ProfileError extends Error {}
const reject = code => {throw new ProfileError(code);};
const require = (ok,code) => {if(!ok) reject(code);};
const bytes = value => Buffer.isBuffer(value);
const equal = (a,b) => bytes(a) && bytes(b) && a.equals(b);
const sha = value => createHash('sha256').update(value).digest();
const isMap = value => value instanceof Map;
const isInt = value => typeof value==='bigint';
const fields = (value,names) => isMap(value) && value.size===names.length && names.every(k=>value.has(k));
const id = value => typeof value==='string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const hexText = (value,n) => typeof value==='string' && value.length===n && /^[0-9a-f]+$/.test(value);
const uint = (value,low=0n,high=U63) => isInt(value) && low<=value && value<high;
const keyType = value => isInt(value)||bytes(value)||typeof value==='string';
const textDecoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});

function prefix(major,value) {
  require(isInt(value)&&value>=0n&&value<U64,'INTEGER_RANGE');
  if(value<24n)return Buffer.from([(major<<5)|Number(value)]);
  for(const [additional,size] of [[24,1],[25,2],[26,4],[27,8]]) {
    if(value<(1n<<BigInt(size*8))) {
      const out=Buffer.alloc(1+size);out[0]=(major<<5)|additional;
      for(let i=size;i>0;i--){out[i]=Number(value&255n);value>>=8n;}
      return out;
    }
  }
}

export function encode(value,level=0) {
  require(level<=DEPTH,'DEPTH_LIMIT');let result;
  if(isInt(value)) result=prefix(value<0n?1:0,value<0n?-1n-value:value);
  else if(bytes(value)) result=Buffer.concat([prefix(2,BigInt(value.length)),value]);
  else if(typeof value==='string') {
    // Buffer.from would replace unpaired UTF-16 surrogates. Reject instead.
    for(const char of value){const cp=char.codePointAt(0);require(cp<0xd800||cp>0xdfff,'INVALID_UTF8');}
    const raw=Buffer.from(value,'utf8');result=Buffer.concat([prefix(3,BigInt(raw.length)),raw]);
  } else if(Array.isArray(value)) {
    require(value.length<=ITEMS,'ITEM_LIMIT');result=Buffer.concat([prefix(4,BigInt(value.length)),...value.map(v=>encode(v,level+1))]);
  } else if(isMap(value)) {
    require(value.size<=ITEMS,'ITEM_LIMIT');const pairs=[];
    for(const [k,v] of value){require(keyType(k),'KEY_TYPE');pairs.push([encode(k,level+1),encode(v,level+1)]);}
    pairs.sort((a,b)=>Buffer.compare(a[0],b[0]));
    for(let i=1;i<pairs.length;i++)require(!pairs[i-1][0].equals(pairs[i][0]),'DUPLICATE_KEY');
    result=Buffer.concat([prefix(5,BigInt(pairs.length)),...pairs.flat()]);
  } else reject('UNSUPPORTED_CBOR_TYPE');
  require(result.length<=LIMIT,'SIZE_LIMIT');return result;
}

export function decode(raw) {
  require(bytes(raw)&&raw.length<=LIMIT,'SIZE_LIMIT');let offset=0;
  function take(size) {
    require(size<=BigInt(raw.length-offset),'TRUNCATED_CBOR');
    const end=offset+Number(size),value=raw.subarray(offset,end);offset=end;return value;
  }
  function item(level) {
    require(level<=DEPTH,'DEPTH_LIMIT');const first=take(1n)[0],major=first>>5,additional=first&31;
    require(major<=5,'UNSUPPORTED_CBOR_TYPE');let argument;
    if(additional<24)argument=BigInt(additional);
    else {
      require(additional<=27,'INDEFINITE_OR_RESERVED');const size=1<<(additional-24),part=take(BigInt(size));argument=0n;
      for(const v of part)argument=(argument<<8n)|BigInt(v);
      const minimum=[24n,256n,65536n,4294967296n][additional-24];require(argument>=minimum,'NONCANONICAL_CBOR');
    }
    if(major===0)return argument;
    if(major===1)return -argument-1n;
    if(major===2||major===3){const value=take(argument);if(major===2)return Buffer.from(value);
      try{return textDecoder.decode(value);}catch{reject('INVALID_UTF8');}}
    require(argument<=BigInt(ITEMS),'ITEM_LIMIT');
    if(major===4)return Array.from({length:Number(argument)},()=>item(level+1));
    const result=new Map();let previous;
    for(let i=0n;i<argument;i++) {
      const start=offset,key=item(level+1),encoded=raw.subarray(start,offset);require(keyType(key),'KEY_TYPE');
      require(previous===undefined||Buffer.compare(previous,encoded)<0,'MAP_ORDER_OR_DUPLICATE');previous=encoded;
      result.set(key,item(level+1));
    }
    return result;
  }
  const result=item(0);require(offset===raw.length,'TRAILING_CBOR');
  require(encode(result).equals(raw),'NONCANONICAL_CBOR');return result;
}

const aad = type => encode(['agent-action-system',1n,type,'Ed25519-SHA256-CBOR-v1']);
function inspect(wire,type) {
  require(bytes(wire)&&wire.length<=LIMIT&&wire[0]===0xd2,'INVALID_SIGN1_TAG');
  const value=decode(wire.subarray(1));require(Array.isArray(value)&&value.length===4,'INVALID_SIGN1_SHAPE');
  const [protectedBytes,unprotected,payload,signature]=value;
  require(bytes(protectedBytes)&&isMap(unprotected)&&unprotected.size===0,'INVALID_HEADERS');
  const h=decode(protectedBytes);require(fields(h,[1n,4n])&&h.get(1n)===-19n,'INVALID_ALGORITHM_OR_HEADERS');
  const kid=h.get(4n);require(bytes(kid)&&kid.length>=1&&kid.length<=32,'INVALID_KEY_ID');
  require(bytes(payload)&&bytes(signature)&&signature.length===64,'INVALID_SIGN1_CONTENT');
  const object=decode(payload),message=encode(['Signature1',protectedBytes,aad(type),payload]);
  return {kid,object,payload,signature,message};
}
export function verifySign1(wire,publicKey,type) {
  const parsed=inspect(wire,type);require(bytes(publicKey)&&publicKey.length===32,'INVALID_SIGNATURE');let valid=false;
  try {
    const key=createPublicKey({format:'jwk',key:{kty:'OKP',crv:'Ed25519',x:publicKey.toString('base64url')}});
    valid=verify(null,parsed.message,key,parsed.signature);
  } catch {reject('INVALID_SIGNATURE');}
  require(valid,'INVALID_SIGNATURE');return parsed;
}
export function sign1(payload,kid,privateDer,type) {
  const protectedBytes=encode(new Map([[1n,-19n],[4n,kid]]));
  const key=createPrivateKey({format:'der',type:'pkcs8',key:privateDer});require(key.asymmetricKeyType==='ed25519','KEY_TYPE');
  const signature=sign(null,encode(['Signature1',protectedBytes,aad(type),payload]),key);
  return Buffer.concat([Buffer.from([0xd2]),encode([protectedBytes,new Map(),payload,signature])]);
}

function control(body) {
  require(isMap(body),'CONTROL');const kind=body.get('kind');
  if(kind==='pause'||kind==='resume')require(fields(body,['kind']),'CONTROL');
  else if(kind==='cancel')require(fields(body,['kind','operation'])&&id(body.get('operation')),'CONTROL');
  else if(kind==='revoke')require(fields(body,['kind','root'])&&id(body.get('root')),'CONTROL');
  else reject('CONTROL');
}
function publicBody(status,body) {
  require(isMap(body),'BODY');const g=k=>body.get(k);
  if(status==='REJECTED')require(body.size===0,'BODY');
  else if(status==='CHALLENGE')require(fields(body,['challenge','challenge_expiry','audience'])&&bytes(g('challenge'))&&g('challenge').length===32&&uint(g('challenge_expiry'),0n,U62+1n)&&g('audience')==='mixed-gateway-v1','BODY');
  else if(status==='RECORDED')require(fields(body,['operation','sequence'])&&id(g('operation'))&&uint(g('sequence'),1n),'BODY');
  else if(status==='CONTROL_RECORDED')control(body);
  else if(status==='POLL') {
    const publication=g('publication'),final=g('final');
    require(fields(body,['operation','sequence','publication','final'])&&id(g('operation'))&&uint(g('sequence'),1n),'BODY');
    const allowed={UNPUBLISHED:['UNFINALIZED'],WITHHELD:['UNFINALIZED','WITHHELD'],ADMITTED:['UNFINALIZED','ACCEPTED','CLOSED']};
    require(typeof publication==='string'&&typeof final==='string'&&Object.hasOwn(allowed,publication)&&allowed[publication].includes(final),'BODY');
  } else if(status==='FINAL') {
    require(fields(body,['events','cursor'])&&uint(g('cursor'))&&Array.isArray(g('events'))&&g('events').length<=16,'BODY');let last;
    for(const event of g('events')) {
      require(fields(event,['sequence','operation','outcome'])&&uint(event.get('sequence'),1n)&&id(event.get('operation'))&&['WITHHELD','ACCEPTED','CLOSED'].includes(event.get('outcome')),'BODY');
      require(last===undefined||event.get('sequence')===last+1n,'BODY');last=event.get('sequence');
    }
    require(last===undefined||last===g('cursor'),'BODY');
  } else reject('STATUS');
}
export function publicResponse(raw,request,publicKey,kid,deployment) {
  const verified=verifySign1(raw,publicKey,'AgentPublicResponseV1'),o=verified.object,g=k=>o.get(k);
  require(equal(verified.kid,kid)&&fields(o,['profile','deployment','request_hash','status','body','sequence']),'RESPONSE');
  require(g('profile')==='agent-public-gateway-v1'&&equal(g('deployment'),deployment)&&equal(g('request_hash'),sha(request)),'RESPONSE');
  require(uint(g('sequence'))&&typeof g('status')==='string'&&(g('status')==='REJECTED'||g('sequence')>0n),'RESPONSE');
  publicBody(g('status'),g('body'));return o;
}

const IMAGE_LIMIT=16*1024*1024;
const imageHash = body => {require(bytes(body)&&body.length>0&&body.length<=IMAGE_LIMIT,'INVALID_IMAGE');return sha(Buffer.concat([Buffer.from('agent-ledger-image-v1\0'),body])).toString('hex');};
const COMMON=['profile','service','method','namespace','challenge','body_size','body_hash'];
const errors=['WITNESS_ACCESS_DENIED','WITNESS_UNINITIALIZED','WITNESS_ALREADY_INITIALIZED','WITNESS_CAS_CONFLICT','WITNESS_REQUEST_CONFLICT','INVALID_WITNESS_IMAGE','INVALID_WITNESS_VERSION','INVALID_WITNESS_REQUEST_ID'];
export function witnessRequest(raw,body) {
  const o=decode(raw);require(isMap(o),'REQUEST');const g=k=>o.get(k),method=g('method');
  const extra={head:['include_image'],bootstrap:[],cas:['expected_seq','expected_digest','request_id'],reassert:['expected_seq','expected_digest','request_id']};
  require(typeof method==='string'&&Object.hasOwn(extra,method)&&fields(o,[...COMMON,...extra[method]]),'REQUEST');
  require(g('profile')==='witness-rpc-v1'&&g('service')==='agent-ledger-witness-v1'&&hexText(g('namespace'),32),'REQUEST');
  require(bytes(g('challenge'))&&g('challenge').length===32&&body.length<=IMAGE_LIMIT&&g('body_size')===BigInt(body.length)&&equal(g('body_hash'),sha(body)),'REQUEST');
  if(method==='head')require(body.length===0&&(g('include_image')===0n||g('include_image')===1n),'REQUEST');
  else {
    if(method==='reassert')require(body.length===0,'REQUEST');else imageHash(body);
    if(method==='cas'||method==='reassert')require(uint(g('expected_seq'),0n,U62)&&hexText(g('expected_digest'),64)&&hexText(g('request_id'),32),'REQUEST');
  }
  return o;
}
export function witnessReply(raw,responseBody,requestRaw,requestBody,publicKey,kid,requester) {
  const request=witnessRequest(requestRaw,requestBody),verified=verifySign1(raw,publicKey,'WitnessResponse'),o=verified.object;
  require(equal(verified.kid,kid)&&fields(o,[...COMMON,'request_digest','requester','status','result']),'REPLY');
  for(const k of ['profile','service','method','namespace'])require(o.get(k)===request.get(k),'BINDING');
  require(equal(o.get('challenge'),request.get('challenge'))&&equal(o.get('request_digest'),sha(requestRaw))&&equal(o.get('requester'),requester),'BINDING');
  require(o.get('body_size')===BigInt(responseBody.length)&&equal(o.get('body_hash'),sha(responseBody)),'BINDING');
  const result=o.get('result');
  if(o.get('status')==='rejected') {
    require(responseBody.length===0&&fields(result,['error'])&&errors.includes(result.get('error')),'REPLY');
    // Authenticated policy rejection is valid wire but is an unsuccessful call.
    return {rejected:result.get('error')};
  }
  require(o.get('status')==='ok'&&fields(result,['seq','digest'])&&uint(result.get('seq'),0n,U62+1n)&&hexText(result.get('digest'),64),'REPLY');
  const method=request.get('method');
  if(method==='head'&&request.get('include_image')===1n){require(imageHash(responseBody)===result.get('digest'),'IMAGE');result.set('image',responseBody);}
  else require(responseBody.length===0,'REPLY');
  if(method==='bootstrap'||method==='cas')require(result.get('seq')===(method==='bootstrap'?0n:request.get('expected_seq')+1n)&&result.get('digest')===imageHash(requestBody),'REPLY');
  if(method==='reassert')require(result.get('seq')===request.get('expected_seq')+1n&&result.get('digest')===request.get('expected_digest'),'REPLY');
  return result;
}

function hex(raw) {require(typeof raw==='string'&&/^(?:[0-9a-f]{2})*$/.test(raw),'FIXTURE_HEX');return Buffer.from(raw,'hex');}
export function fromView(v) {
  switch(v[0]) {
    case 'i':return BigInt(v[1]);case 'b':return hex(v[1]);case 't':return v[1];
    case 'a':return v[1].map(fromView);case 'm':return new Map(v[1].map(([k,val])=>[fromView(k),fromView(val)]));
    case 'bool':return v[1];case 'null':return null;case 'float':return Number(v[1]);
    default:throw new Error('unknown fixture value');
  }
}
export function view(v) {
  if(isInt(v))return ['i',String(v)];if(bytes(v))return ['b',v.toString('hex')];if(typeof v==='string')return ['t',v];
  if(Array.isArray(v))return ['a',v.map(view)];if(isMap(v))return ['m',Array.from(v).sort((a,b)=>Buffer.compare(encode(a[0]),encode(b[0]))).map(([k,val])=>[view(k),view(val)])];
  throw new Error('unexpected decoded value');
}
export function execute(c) {
  try {
    let result;
    if(c.op==='decode')result=view(decode(hex(c.raw)));
    else if(c.op==='encode')result=encode(fromView(c.value)).toString('hex');
    else if(c.op==='sign')result=sign1(hex(c.payload),hex(c.kid),hex(c.private_der),c.object_type).toString('hex');
    else if(c.op==='verify'){const p=verifySign1(hex(c.raw),hex(c.public_key),c.object_type);result={kid:p.kid.toString('hex'),value:view(p.object),message:p.message.toString('hex')};}
    else if(c.op==='public_response')result=view(publicResponse(hex(c.raw),hex(c.request),hex(c.public_key),hex(c.kid),hex(c.deployment)));
    else if(c.op==='witness_request')result=view(witnessRequest(hex(c.raw),hex(c.body)));
    else if(c.op==='witness_reply') {
      const r=witnessReply(hex(c.raw),hex(c.body),hex(c.request),hex(c.request_body),hex(c.public_key),hex(c.kid),hex(c.requester));
      if(r.rejected)return {accepted:false,rejection:r.rejected};result=view(r);
    } else throw new Error('unknown operation');
    return {accepted:true,result};
  } catch(e) {
    if(e instanceof ProfileError)return {accepted:false,error:e.message};
    return {fault:e.constructor.name+': '+e.message};
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(realpathSync(process.argv[1])).href) {
  const cases=JSON.parse(readFileSync(0,'utf8'));
  process.stdout.write(JSON.stringify({node:process.version,openssl:process.versions.openssl,results:cases.map(execute)}));
}
