"""Loopback mTLS and challenge-bound signed witness RPC reference adapter.

No production CA lifecycle, remote deployment, independent fault domain, witness
antirollback, scalable log, or full external privacy protocol is claimed. Private
keys/CA/pins are supplied by trusted bootstrap. There is no public admin endpoint.
"""
import hashlib
from pathlib import Path
import re
import secrets
import socket
import socketserver
import ssl
import struct
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from witnessed_ledger import ReferenceWitness,WitnessedLedger,Rejected,MAX_IMAGE,image_hash
from wire import encode,decode,sign1,verify_sign1


PROFILE='witness-rpc-v1'
SERVICE='agent-ledger-witness-v1'
REPLY_TYPE='WitnessResponse'
MAX_META=8192
AUTH_SCHEMA='''CREATE TABLE IF NOT EXISTS witness_clients (
 namespace TEXT NOT NULL, fingerprint BLOB NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','writer','restorer','observer')),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 PRIMARY KEY(namespace,fingerprint)
)'''
PERMISSIONS={'admin':{'bootstrap','cas','head','image'},'writer':{'cas','head','image'},
             'restorer':{'head','image'},'observer':{'head'}}
COMMON={'profile','service','method','namespace','challenge','body_size','body_hash'}
ERRORS={'WITNESS_ACCESS_DENIED','WITNESS_UNINITIALIZED','WITNESS_ALREADY_INITIALIZED',
        'WITNESS_CAS_CONFLICT','WITNESS_REQUEST_CONFLICT','INVALID_WITNESS_IMAGE',
        'INVALID_WITNESS_VERSION','INVALID_WITNESS_REQUEST_ID'}


def hex_string(value,length):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None


def certificate_fingerprint(certfile):
    return x509.load_pem_x509_certificate(Path(certfile).read_bytes()).fingerprint(hashes.SHA256())


def trusted_register_peer(path,namespace,fingerprint,role):
    # Trusted offline/bootstrap management only, never reachable over this RPC.
    if not hex_string(namespace,32) or type(fingerprint) is not bytes or len(fingerprint)!=32 or role not in PERMISSIONS:
        raise Rejected('INVALID_WITNESS_PEER')
    w=ReferenceWitness(path)
    try:
        w.db.executescript(AUTH_SCHEMA)
        w.db.execute('INSERT INTO witness_clients(namespace,fingerprint,role) VALUES(?,?,?)',(namespace,fingerprint,role))
    finally:w.close()


def trusted_revoke_peer(path,namespace,fingerprint):
    w=ReferenceWitness(path)
    try:
        w.db.execute('BEGIN IMMEDIATE')
        if w.db.execute('UPDATE witness_clients SET revoked=1 WHERE namespace=? AND fingerprint=?',(namespace,fingerprint)).rowcount!=1:
            raise Rejected('UNKNOWN_WITNESS_PEER')
        w.db.commit()
    finally:w.close()


class AuthorizedWitness(ReferenceWitness):
    def __init__(self,path,peer_fingerprint):
        self.peer_fingerprint=peer_fingerprint
        super().__init__(path)

    def authorize_operation(self,namespace,operation):
        row=self.db.execute('SELECT role,revoked FROM witness_clients WHERE namespace=? AND fingerprint=?',
                            (namespace,self.peer_fingerprint)).fetchone()
        if row is None or row['revoked'] or operation not in PERMISSIONS[row['role']]:
            raise Rejected('WITNESS_ACCESS_DENIED')


def parse_request(raw,body):
    request=decode(raw)
    if type(request) is not dict or request.get('profile')!=PROFILE or request.get('service')!=SERVICE:
        raise Rejected('INVALID_WITNESS_RPC')
    method=request.get('method')
    if type(method) is not str:raise Rejected('INVALID_WITNESS_RPC')
    extra={'head':{'include_image'},'bootstrap':set(),
                                      'cas':{'expected_seq','expected_digest','request_id'}}.get(method)
    if extra is None or set(request)!=COMMON|extra:raise Rejected('INVALID_WITNESS_RPC')
    if not hex_string(request['namespace'],32):raise Rejected('INVALID_WITNESS_RPC')
    if type(request['challenge']) is not bytes or len(request['challenge'])!=32:raise Rejected('INVALID_WITNESS_RPC')
    if (type(request['body_size']) is not int or request['body_size']!=len(body) or len(body)>MAX_IMAGE or
            type(request['body_hash']) is not bytes or request['body_hash']!=hashlib.sha256(body).digest()):
        raise Rejected('INVALID_WITNESS_RPC')
    if method=='head':
        if body or type(request['include_image']) is not int or request['include_image'] not in (0,1):
            raise Rejected('INVALID_WITNESS_RPC')
    else:
        image_hash(body)
        if method=='cas' and (type(request['expected_seq']) is not int or not 0<=request['expected_seq']<2**62 or
                not hex_string(request['expected_digest'],64) or not hex_string(request['request_id'],32)):
            raise Rejected('INVALID_WITNESS_RPC')
    return request


def remaining(deadline):
    value=deadline-time.monotonic()
    if value<=0:raise TimeoutError('witness transport deadline')
    return value


def read_exact(sock,size,deadline):
    chunks=[]
    while size:
        sock.settimeout(remaining(deadline));piece=sock.recv(min(size,65536))
        if not piece:raise ConnectionError('incomplete witness frame')
        chunks.append(piece);size-=len(piece)
    return b''.join(chunks)


def receive_frame(sock,deadline):
    header=read_exact(sock,12,deadline)
    if header[:4]!=b'WRP1':raise Rejected('INVALID_WITNESS_FRAME')
    meta_size,body_size=struct.unpack('>II',header[4:])
    if not 1<=meta_size<=MAX_META or body_size>MAX_IMAGE:raise Rejected('WITNESS_FRAME_LIMIT')
    return read_exact(sock,meta_size,deadline),read_exact(sock,body_size,deadline)


def send_frame(sock,meta,body,deadline):
    if not 1<=len(meta)<=MAX_META or len(body)>MAX_IMAGE:raise Rejected('WITNESS_FRAME_LIMIT')
    sock.settimeout(remaining(deadline))
    sock.sendall(b'WRP1'+struct.pack('>II',len(meta),len(body))+meta+body)


def frame_functions(mode):
    # Explicit trusted bootstrap selection; no negotiation or fallback. Resolve
    # raw functions at call time to preserve the existing fault-injection seam.
    if type(mode) is str and mode=='raw':return send_frame,receive_frame
    if type(mode) is str and mode=='deflate-v1':
        from witness_compression import send_compressed_frame,receive_compressed_frame
        return send_compressed_frame,receive_compressed_frame
    raise ValueError('invalid witness frame mode')


def tls_context(cafile,certfile,keyfile,server=False):
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.verify_mode=ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(cafile))
    context.load_cert_chain(str(certfile),str(keyfile))
    # No default root store, environment-driven key logging, session reuse, or
    # application early data is configured by this reference adapter.
    return context


class WitnessTLSService:
    def __init__(self,witness_path,*,cafile,certfile,keyfile,signing_key,kid=b'witness',timeout=5,
                 fault=lambda point,request:None,frame_mode='raw'):
        if type(timeout) not in (int,float) or not 0<timeout<=30:raise ValueError('invalid timeout')
        frame_functions(frame_mode);self.frame_mode=frame_mode
        self.path=str(witness_path);self.signing_key=signing_key;self.kid=kid;self.timeout=timeout;self.fault=fault
        self.context=tls_context(cafile,certfile,keyfile,True)
        outer=self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                deadline=time.monotonic()+outer.timeout
                try:
                    self.request.settimeout(remaining(deadline))
                    with outer.context.wrap_socket(self.request,server_side=True) as channel:
                        peer=hashlib.sha256(channel.getpeercert(binary_form=True)).digest()
                        send,receive=frame_functions(outer.frame_mode)
                        raw,body=receive(channel,deadline);request=parse_request(raw,body)
                        outer.fault('before_dispatch',request)
                        meta,response_body=outer.dispatch(raw,body,request,peer)
                        outer.fault('after_dispatch',request)
                        send(channel,meta,response_body,deadline)
                except (OSError,Rejected):
                    # Malformed frames/TLS failures close the connection; no raw
                    # internal exception or unauthenticated success is returned.
                    return
        class Server(socketserver.ThreadingMixIn,socketserver.TCPServer):
            daemon_threads=True
            allow_reuse_address=False
            def handle_error(self,request,client_address):pass
        self.server=Server(('127.0.0.1',0),Handler)
        self.port=self.server.server_address[1]
        self.thread=None

    def __enter__(self):
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.05},daemon=True)
        self.thread.start();return self

    def __exit__(self,*args):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=5)

    def dispatch(self,raw,body,request,peer):
        w=AuthorizedWitness(self.path,peer)
        response_body=b''
        try:
            if request['method']=='head':result=w.head(request['namespace'],bool(request['include_image']))
            elif request['method']=='bootstrap':result=w.bootstrap(request['namespace'],body)
            else:result=w.compare_and_store(request['namespace'],request['expected_seq'],request['expected_digest'],body,request['request_id'])
            response_body=result.pop('image',b'');status='ok'
        except Rejected as error:
            if str(error) not in ERRORS:raise
            result={'error':str(error)};status='rejected'
        finally:w.close()
        reply=dict(profile=PROFILE,service=SERVICE,method=request['method'],namespace=request['namespace'],
                   challenge=request['challenge'],request_digest=hashlib.sha256(raw).digest(),requester=peer,
                   status=status,result=result,body_size=len(response_body),body_hash=hashlib.sha256(response_body).digest())
        return sign1(encode(reply),self.kid,self.signing_key,REPLY_TYPE),response_body


class TLSWitnessClient:
    def __init__(self,*,port,cafile,certfile,keyfile,witness_public_key,kid=b'witness',server_hostname='localhost',timeout=5,frame_mode='raw'):
        if type(port) is not int or not 1<=port<=65535:raise ValueError('invalid port')
        if type(witness_public_key) is not bytes or len(witness_public_key)!=32:raise ValueError('invalid witness key')
        if type(timeout) not in (int,float) or not 0<timeout<=30:raise ValueError('invalid timeout')
        frame_functions(frame_mode);self.frame_mode=frame_mode
        self.port=port;self.hostname=server_hostname;self.timeout=timeout;self.public_key=witness_public_key;self.kid=kid
        self.requester=certificate_fingerprint(certfile)
        self.context=tls_context(cafile,certfile,keyfile)
        self.last_tls_version=None

    def exchange(self,raw,body):
        deadline=time.monotonic()+self.timeout
        with socket.create_connection(('127.0.0.1',self.port),timeout=remaining(deadline)) as sock:
            sock.settimeout(remaining(deadline))
            with self.context.wrap_socket(sock,server_hostname=self.hostname) as channel:
                self.last_tls_version=channel.version()
                send,receive=frame_functions(self.frame_mode)
                send(channel,raw,body,deadline)
                return receive(channel,deadline)

    def call(self,method,namespace,body=b'',**extra):
        request=dict(profile=PROFILE,service=SERVICE,method=method,namespace=namespace,challenge=secrets.token_bytes(32),
                     body_size=len(body),body_hash=hashlib.sha256(body).digest(),**extra)
        raw=encode(request);parse_request(raw,body)
        response,response_body=self.exchange(raw,body)
        kid,reply=verify_sign1(response,self.public_key,REPLY_TYPE)
        fields={'profile','service','method','namespace','challenge','request_digest','requester','status','result','body_size','body_hash'}
        if kid!=self.kid or type(reply) is not dict or set(reply)!=fields:raise Rejected('INVALID_WITNESS_REPLY')
        for key in ('profile','service','method','namespace','challenge'):
            if reply[key]!=request[key]:raise Rejected('WITNESS_REPLY_BINDING')
        if reply['request_digest']!=hashlib.sha256(raw).digest() or reply['requester']!=self.requester:
            raise Rejected('WITNESS_REPLY_BINDING')
        if (type(reply['body_size']) is not int or reply['body_size']!=len(response_body) or
                reply['body_hash']!=hashlib.sha256(response_body).digest()):raise Rejected('WITNESS_REPLY_BINDING')
        result=reply['result']
        if reply['status']=='rejected':
            if response_body or type(result) is not dict or set(result)!={'error'} or type(result['error']) is not str or result['error'] not in ERRORS:
                raise Rejected('INVALID_WITNESS_REPLY')
            raise Rejected(result['error'])
        if (reply['status']!='ok' or type(result) is not dict or set(result)!={'seq','digest'} or
                type(result['seq']) is not int or not 0<=result['seq']<=2**62 or not hex_string(result['digest'],64)):
            raise Rejected('INVALID_WITNESS_REPLY')
        if method=='head' and extra['include_image']:
            if image_hash(response_body)!=result['digest']:raise Rejected('WITNESS_IMAGE_CORRUPT')
            result=dict(result,image=response_body)
        elif response_body:raise Rejected('INVALID_WITNESS_REPLY')
        if method in ('bootstrap','cas') and (result['digest']!=image_hash(body) or result['seq']!=(0 if method=='bootstrap' else extra['expected_seq']+1)):
            raise Rejected('INVALID_WITNESS_REPLY')
        return result

    def head(self,namespace,include_image=False):return self.call('head',namespace,include_image=int(include_image))
    def bootstrap(self,namespace,image):return self.call('bootstrap',namespace,image)
    def compare_and_store(self,namespace,expected_seq,expected_digest,image,request_id):
        return self.call('cas',namespace,image,expected_seq=expected_seq,expected_digest=expected_digest,request_id=request_id)


class TLSWitnessedLedger(WitnessedLedger):
    storage_profile='mtls-witnessed-delegated-count-v1'
    def __init__(self,path,clock=None,*,vault,witness,witness_fault=lambda point:None):
        if type(witness) is not TLSWitnessClient:raise Rejected('AUTHENTICATED_WITNESS_REQUIRED')
        super().__init__(path,clock=clock,vault=vault,witness=witness,witness_fault=witness_fault)
