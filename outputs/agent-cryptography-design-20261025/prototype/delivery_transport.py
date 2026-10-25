"""Authenticated, durable fixed-count delivery reference. Loopback only.

Trusted driver pushes already-published L3 tickets. No public readiness/fetch API,
network-observation DP proof, production identity lifecycle, or exactly-once
external business effects. Recipient inbox durability/nonrollback is assumed.
"""
import hashlib
import socket
import socketserver
import sqlite3
import struct
import threading
import time
import secrets
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from encrypted_ledger import StateVault
from witness_transport import TLSWitnessedLedger,tls_context,certificate_fingerprint,read_exact,remaining
from wire import encode,decode,sign1,verify_sign1
from ledger import Rejected

PROFILE='count-delivery-v1'
ENVELOPE_TYPE='CountDelivery'
ACK_TYPE='CountDeliveryAck'
MAX_FRAME=8192
ROUTE_KEYS=('tenant','recipient','gateway','session')
BINDINGS=('deployment','tenant','recipient','gateway','session','sender_cert','receiver_cert')
ENVELOPE_FIELDS=set(BINDINGS)|{'profile','delivery','operation','seq','issued_at','expires_at','result'}
ACK_FIELDS={'profile','deployment','tenant','delivery','seq','envelope_hash','challenge','request_hash','receiver_cert','accepted_at'}
SCHEMA='''
CREATE TABLE delivery_routes (
 tenant TEXT NOT NULL, recipient TEXT NOT NULL, gateway TEXT NOT NULL, session TEXT NOT NULL,
 sender_cert BLOB NOT NULL, receiver_cert BLOB NOT NULL,
 sender_key BLOB NOT NULL, receiver_key BLOB NOT NULL,
 sender_kid BLOB NOT NULL, receiver_kid BLOB NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 PRIMARY KEY(tenant,recipient,gateway,session)
);
CREATE TABLE delivery_outbox (
 tenant TEXT NOT NULL, id TEXT NOT NULL, recipient TEXT NOT NULL, gateway TEXT NOT NULL, session TEXT NOT NULL,
 seq INTEGER NOT NULL CHECK(seq>0), state TEXT NOT NULL CHECK(state IN ('QUEUED','READY','ACKED')),
 envelope BLOB, acknowledgement BLOB,
 PRIMARY KEY(tenant,id), UNIQUE(tenant,recipient,gateway,session,seq),
 FOREIGN KEY(tenant,id) REFERENCES deliveries(tenant,id),
 FOREIGN KEY(tenant,recipient,gateway,session) REFERENCES delivery_routes(tenant,recipient,gateway,session),
 CHECK((state IN ('READY','ACKED'))=(envelope IS NOT NULL)),
 CHECK((state='ACKED')=(acknowledgement IS NOT NULL))
);
'''


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)


def valid_text(value):return type(value) is str and 0<len(value.encode('utf-8'))<=128


def validate_route(route):
    if set(route)!=set(ROUTE_KEYS)|{'sender_cert','receiver_cert','sender_key','receiver_key','sender_kid','receiver_kid'}:
        raise Rejected('INVALID_DELIVERY_ROUTE')
    if any(not valid_text(route[k]) for k in ROUTE_KEYS):raise Rejected('INVALID_DELIVERY_ROUTE')
    if any(type(route[k]) is not bytes or len(route[k])!=32 for k in ('sender_cert','receiver_cert','sender_key','receiver_key')):
        raise Rejected('INVALID_DELIVERY_ROUTE')
    # Match the shared restricted COSE parser; accepting longer IDs here would
    # persist an apparently valid route whose signatures can never be decoded.
    if any(type(route[k]) is not bytes or not 1<=len(route[k])<=32 for k in ('sender_kid','receiver_kid')):
        raise Rejected('INVALID_DELIVERY_ROUTE')


def expected_bindings(deployment,route):
    return dict(deployment=deployment,**{k:route[k] for k in ROUTE_KEYS},sender_cert=route['sender_cert'],receiver_cert=route['receiver_cert'])


def parse_envelope(raw,deployment,route):
    kid,obj=verify_sign1(raw,route['sender_key'],ENVELOPE_TYPE)
    if kid!=route['sender_kid'] or type(obj) is not dict or set(obj)!=ENVELOPE_FIELDS or obj['profile']!=PROFILE:
        raise Rejected('INVALID_DELIVERY_ENVELOPE')
    if any(obj[k]!=v for k,v in expected_bindings(deployment,route).items()):raise Rejected('DELIVERY_CONTEXT')
    if (any(not valid_text(obj[k]) for k in ('delivery','operation')) or type(obj['seq']) is not int or not 1<=obj['seq']<2**62 or
        type(obj['issued_at']) is not int or type(obj['expires_at']) is not int or not 0<=obj['issued_at']<obj['expires_at']<=2**62 or
        not 0<obj['expires_at']-obj['issued_at']<=60 or type(obj['result']) is not bytes or len(obj['result'])!=8):
        raise Rejected('INVALID_DELIVERY_ENVELOPE')
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
    if type(ack['accepted_at']) is not int or not obj['issued_at']<=ack['accepted_at']<obj['expires_at']:
        raise Rejected('INVALID_DELIVERY_ACK')
    return ack


class DeliveryLedger(TLSWitnessedLedger):
    storage_profile='mtls-count-delivery-outbox-v1'
    delivery_profile=PROFILE
    envelope_type=ENVELOPE_TYPE
    parse_envelope=staticmethod(parse_envelope)
    parse_ack=staticmethod(parse_ack)

    def payload_fields(self,op):
        return {'result':op['result']}

    def validate_payload_binding(self,obj,op):
        if any(obj.get(k)!=v for k,v in self.payload_fields(op).items()):
            raise Rejected('OUTBOX_BINDING')

    def emit(self,*args,**kwargs):
        raise Rejected('NETWORK_DELIVERY_REQUIRED')

    @classmethod
    def new_replica(cls,path,**kwargs):
        obj=super().new_replica(path,**kwargs)
        obj.db.executescript(SCHEMA)
        return obj

    def register_route(self,**route):
        # Trusted management, not an Agent/public request API. Immutable pins.
        validate_route(route)
        with self.tx():
            values=tuple(route[k] for k in ROUTE_KEYS)
            old=self.db.execute('SELECT * FROM delivery_routes WHERE tenant=? AND recipient=? AND gateway=? AND session=?',values).fetchone()
            if old:
                if any(old[k]!=v for k,v in route.items()):raise Rejected('DELIVERY_ROUTE_CONFLICT')
                if old['revoked']:raise Rejected('DELIVERY_ROUTE_REVOKED')
                return
            columns=ROUTE_KEYS+('sender_cert','receiver_cert','sender_key','receiver_key','sender_kid','receiver_kid')
            self.db.execute('INSERT INTO delivery_routes('+','.join(columns)+') VALUES('+','.join('?' for _ in columns)+')',tuple(route[k] for k in columns))

    def route(self,row,live=True):
        route=self.db.execute('SELECT * FROM delivery_routes WHERE tenant=? AND recipient=? AND gateway=? AND session=?',tuple(row[k] for k in ROUTE_KEYS)).fetchone()
        if route is None:raise Rejected('UNKNOWN_DELIVERY_ROUTE')
        if live and route['revoked']:raise Rejected('DELIVERY_ROUTE_REVOKED')
        return dict(route)

    def revoke_route(self,tenant,recipient,gateway,session):
        with self.tx():
            if self.db.execute('UPDATE delivery_routes SET revoked=1 WHERE tenant=? AND recipient=? AND gateway=? AND session=?',(tenant,recipient,gateway,session)).rowcount!=1:
                raise Rejected('UNKNOWN_DELIVERY_ROUTE')

    def on_delivery_admitted(self,ticket):
        if not valid_text(ticket['id']):raise Rejected('INVALID_DELIVERY_ID')
        self.route(ticket)
        old=self.db.execute('SELECT * FROM delivery_outbox WHERE tenant=? AND id=?',(ticket['tenant'],ticket['id'])).fetchone()
        if old:return
        key=tuple(ticket[k] for k in ROUTE_KEYS)
        seq=self.db.execute('SELECT coalesce(max(seq),0)+1 FROM delivery_outbox WHERE tenant=? AND recipient=? AND gateway=? AND session=?',key).fetchone()[0]
        if seq>=2**62:raise Rejected('DELIVERY_SEQUENCE_EXHAUSTED')
        self.db.execute('INSERT INTO delivery_outbox(tenant,id,recipient,gateway,session,seq,state) VALUES(?,?,?,?,?,?,?)',
            (ticket['tenant'],ticket['id'],ticket['recipient'],ticket['gateway'],ticket['session'],seq,'QUEUED'))

    def delivery_ticket(self,*args):
        ticket=super().delivery_ticket(*args);self.route(ticket)
        return ticket

    def outbox(self,tenant,delivery_id):
        row=self.db.execute('SELECT * FROM delivery_outbox WHERE tenant=? AND id=?',(tenant,delivery_id)).fetchone()
        if row is None:raise Rejected('UNKNOWN_DELIVERY')
        return row

    def delivery_status(self,tenant,delivery_id):
        return self.outbox(tenant,delivery_id)['state']

    def first_pending(self,row):
        return self.db.execute("SELECT min(seq) FROM delivery_outbox WHERE tenant=? AND recipient=? AND gateway=? AND session=? AND state!='ACKED'",tuple(row[k] for k in ROUTE_KEYS)).fetchone()[0]

    def validate_ack_transition(self,row,ack):
        pass

    def prepare_send(self,tenant,delivery_id,signer,fault=lambda point:None):
        with self.tx():
            row=self.outbox(tenant,delivery_id);route=self.route(row)
            if public(signer)!=route['sender_key']:raise Rejected('WRONG_GATEWAY_SIGNER')
            if self.delivery_status(tenant,delivery_id) in ('ACKED','CLOSED'):return None
            first=self.first_pending(row)
            if row['seq']!=first:raise Rejected('DELIVERY_ORDER')
            ticket=self.delivery_ticket(tenant,delivery_id,row['recipient'],row['gateway'],row['session'])
            op=self.op(tenant,ticket['operation_id'])
            if op['state']!='COMMITTED' or op['result_digest']!=ticket['result_digest']:raise Rejected('RESULT_UNAVAILABLE')
            if row['envelope'] is None:
                obj=dict(profile=self.delivery_profile,**expected_bindings(self.namespace,route),delivery=delivery_id,operation=op['id'],seq=row['seq'],
                    issued_at=ticket['issued_at'],expires_at=ticket['expires_at'],**self.payload_fields(op))
                raw=sign1(encode(obj),route['sender_kid'],signer,self.envelope_type)
                sealed=self.vault.seal('delivery-envelope',(tenant,delivery_id),raw)
                self.db.execute("UPDATE delivery_outbox SET envelope=?,state='READY' WHERE tenant=? AND id=?",(sealed,tenant,delivery_id))
            else:raw=self.vault.open('delivery-envelope',(tenant,delivery_id),row['envelope'])
            obj=self.parse_envelope(raw,self.namespace,route)
            self.validate_payload_binding(obj,op)
            if obj['result']!=op['result'] or obj['operation']!=op['id'] or obj['seq']!=row['seq']:raise Rejected('OUTBOX_BINDING')
            self.db.execute('UPDATE deliveries SET handoff_admitted=1 WHERE tenant=? AND id=?',(tenant,delivery_id))
            fault('before_outbox_commit')
        fault('after_outbox_commit')
        return raw,route

    def confirm_ack(self,tenant,delivery_id,request,ack,fault=lambda point:None):
        with self.tx():
            row=self.outbox(tenant,delivery_id);route=self.route(row,live=False)
            if row['envelope'] is None:raise Rejected('OUTBOX_NOT_PREPARED')
            raw=self.vault.open('delivery-envelope',(tenant,delivery_id),row['envelope'])
            parsed=self.parse_ack(ack,request,raw,self.namespace,route)
            self.validate_ack_transition(row,parsed)
            if row['state']!='ACKED':
                sealed=self.vault.seal('delivery-ack',(tenant,delivery_id),encode({'request':request,'ack':ack}))
                self.db.execute("UPDATE delivery_outbox SET state='ACKED',acknowledgement=? WHERE tenant=? AND id=?",(sealed,tenant,delivery_id))
            fault('before_ack_commit')
        fault('after_ack_commit')

    def audit(self):
        errors=super().audit()
        for route in self.db.execute('SELECT * FROM delivery_routes'):
            validate_route({k:route[k] for k in route.keys() if k!='revoked'})
            rows=self.db.execute('SELECT seq FROM delivery_outbox WHERE tenant=? AND recipient=? AND gateway=? AND session=? ORDER BY seq',tuple(route[k] for k in ROUTE_KEYS)).fetchall()
            if [r[0] for r in rows]!=list(range(1,len(rows)+1)):errors.append('OUTBOX_SEQUENCE')
        for ticket in self.db.execute('SELECT * FROM deliveries'):
            row=self.outbox(ticket['tenant'],ticket['id']);route=self.route(row,live=False)
            if any(row[k]!=ticket[k] for k in ROUTE_KEYS):errors.append('OUTBOX_ROUTE')
            if row['envelope'] is not None:
                raw=self.vault.open('delivery-envelope',(row['tenant'],row['id']),row['envelope']);obj=self.parse_envelope(raw,self.namespace,route)
                op=self.op(row['tenant'],ticket['operation_id'])
                self.validate_payload_binding(obj,op)
                if (obj['delivery']!=row['id'] or obj['operation']!=op['id'] or obj['result']!=op['result'] or obj['seq']!=row['seq'] or
                    obj['issued_at']!=ticket['issued_at'] or obj['expires_at']!=ticket['expires_at'] or not ticket['handoff_admitted']):errors.append('OUTBOX_BINDING')
                if row['acknowledgement'] is not None:
                    stored=decode(self.vault.open('delivery-ack',(row['tenant'],row['id']),row['acknowledgement']))
                    self.parse_ack(stored['ack'],stored['request'],raw,self.namespace,route)
        return errors


INBOX_SCHEMA='''
CREATE TABLE inbox_metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), key_check TEXT NOT NULL, route_hash BLOB NOT NULL);
CREATE TABLE inbox (id TEXT PRIMARY KEY, seq INTEGER UNIQUE NOT NULL, envelope BLOB NOT NULL, accepted_at INTEGER NOT NULL);
CREATE TABLE inbox_clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1), observed INTEGER NOT NULL);
INSERT INTO inbox_clock VALUES(1,0);
'''


class RecipientInbox:
    inbox_schema=INBOX_SCHEMA
    inbox_profile=PROFILE
    delivery_profile=PROFILE
    ack_type=ACK_TYPE
    parse_attempt=staticmethod(parse_attempt)
    parse_envelope=staticmethod(parse_envelope)
    def __init__(self,path,*,deployment,route,vault,clock):
        validate_route(route)
        if type(vault) is not StateVault:raise Rejected('INVALID_STORAGE_VAULT')
        self.deployment=deployment;self.route=route;self.vault=vault;self.clock=clock
        self.db=sqlite3.connect(str(path),timeout=5,isolation_level=None);self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        route_hash=hashlib.sha256(encode(dict(profile=self.inbox_profile,deployment=deployment,route=route))).digest()
        try:
            if not self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table'").fetchone():
                self.db.executescript(self.inbox_schema)
                self.db.execute('INSERT INTO inbox_metadata VALUES(1,?,?)',(vault.key_check,route_hash))
            row=self.db.execute('SELECT key_check,route_hash FROM inbox_metadata WHERE singleton=1').fetchone()
            if row is None or tuple(row)!=(vault.key_check,route_hash):raise Rejected('INBOX_PROFILE_MISMATCH')
        except BaseException:self.db.close();raise

    def close(self):self.db.close()

    def begin_transaction_guard(self):
        pass

    def commit_transaction_guard(self):
        pass

    def commit_inbox_transaction(self):
        self.commit_transaction_guard()
        self.db.commit()

    def next_sequence(self):
        return self.db.execute('SELECT coalesce(max(seq),0)+1 FROM inbox').fetchone()[0]

    def authorize_envelope(self,obj):
        pass

    def accept(self,request,peer,signer,fault=lambda point:None):
        if peer!=self.route['sender_cert']:raise Rejected('UNAUTHORIZED_GATEWAY')
        if public(signer)!=self.route['receiver_key']:raise Rejected('WRONG_RECIPIENT_SIGNER')
        req=self.parse_attempt(request);raw=req['envelope'];obj=self.parse_envelope(raw,self.deployment,self.route)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.begin_transaction_guard()
            now=self.clock()
            if type(now) is not int or not 0<=now<=2**62 or now<self.db.execute('SELECT observed FROM inbox_clock').fetchone()[0]:raise Rejected('INBOX_CLOCK_ROLLBACK')
            self.db.execute('UPDATE inbox_clock SET observed=?',(now,))
            # Preserve the observed floor even when the business request rejects.
            self.db.execute('SAVEPOINT business')
            try:
                self.authorize_envelope(obj)
                row=self.db.execute('SELECT * FROM inbox WHERE id=?',(obj['delivery'],)).fetchone()
                if row:
                    old=self.vault.open('inbox-envelope',(self.deployment,obj['tenant'],obj['delivery']),row['envelope'])
                    if old!=raw or row['seq']!=obj['seq']:raise Rejected('INBOX_DELIVERY_CONFLICT')
                    accepted=row['accepted_at']
                else:
                    if not obj['issued_at']<=now<obj['expires_at']:raise Rejected('TICKET_EXPIRED')
                    seq=self.next_sequence()
                    if obj['seq']!=seq:raise Rejected('INBOX_ORDER')
                    accepted=now
                    sealed=self.vault.seal('inbox-envelope',(self.deployment,obj['tenant'],obj['delivery']),raw)
                    self.db.execute('INSERT INTO inbox VALUES(?,?,?,?)',(obj['delivery'],seq,sealed,accepted))
                fault('before_inbox_commit')
            except Rejected:
                self.db.execute('ROLLBACK TO business');self.db.execute('RELEASE business');self.commit_inbox_transaction();raise
            self.db.execute('RELEASE business');self.commit_inbox_transaction()
        except BaseException:
            self.db.rollback();raise
        fault('after_inbox_commit')
        ack=dict(profile=self.delivery_profile,deployment=self.deployment,tenant=obj['tenant'],delivery=obj['delivery'],seq=obj['seq'],
            envelope_hash=hashlib.sha256(raw).digest(),challenge=req['challenge'],request_hash=hashlib.sha256(request).digest(),
            receiver_cert=self.route['receiver_cert'],accepted_at=accepted)
        return sign1(encode(ack),self.route['receiver_kid'],signer,self.ack_type)


def recv_packet(sock,deadline):
    header=read_exact(sock,8,deadline)
    if header[:4]!=b'DLV1':raise Rejected('INVALID_DELIVERY_FRAME')
    size=struct.unpack('>I',header[4:])[0]
    if not 1<=size<=MAX_FRAME:raise Rejected('DELIVERY_FRAME_LIMIT')
    return read_exact(sock,size,deadline)


def send_packet(sock,raw,deadline):
    if not 1<=len(raw)<=MAX_FRAME:raise Rejected('DELIVERY_FRAME_LIMIT')
    sock.settimeout(remaining(deadline));sock.sendall(b'DLV1'+struct.pack('>I',len(raw))+raw)


class RecipientTLSService:
    def __init__(self,*,inbox_factory,cafile,certfile,keyfile,signer,fault=lambda point:None):
        self.context=tls_context(cafile,certfile,keyfile,True)
        self.inbox_factory=inbox_factory;self.signer=signer;self.fault=fault
        self.fingerprint=certificate_fingerprint(certfile)
        # Fail startup if the configured TLS identity is not the signed destination.
        inbox=inbox_factory()
        try:
            if self.fingerprint!=inbox.route['receiver_cert'] or public(signer)!=inbox.route['receiver_key']:
                raise Rejected('WRONG_RECIPIENT_IDENTITY')
        finally:inbox.close()
        outer=self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                deadline=time.monotonic()+5
                try:
                    self.request.settimeout(remaining(deadline))
                    with outer.context.wrap_socket(self.request,server_side=True) as channel:
                        peer=hashlib.sha256(channel.getpeercert(binary_form=True)).digest()
                        request=recv_packet(channel,deadline);inbox=outer.inbox_factory()
                        try:ack=inbox.accept(request,peer,outer.signer,outer.fault)
                        finally:inbox.close()
                        outer.fault('before_ack_send');send_packet(channel,ack,deadline)
                except (OSError,Rejected):return
        class Server(socketserver.ThreadingMixIn,socketserver.TCPServer):
            daemon_threads=True
            def handle_error(self,request,client_address):pass
        self.server=Server(('127.0.0.1',0),Handler);self.port=self.server.server_address[1]
        self.thread=None
    def __enter__(self):
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.05},daemon=True);self.thread.start();return self
    def __exit__(self,*args):self.server.shutdown();self.server.server_close();self.thread.join(timeout=5)


class DeliverySender:
    attempt=staticmethod(attempt)
    def __init__(self,*,port,cafile,certfile,keyfile,signer,server_hostname='localhost',timeout=5):
        if type(port) is not int or not 1<=port<=65535 or type(timeout) not in (int,float) or not 0<timeout<=30:raise ValueError('invalid endpoint')
        self.port=port;self.hostname=server_hostname;self.timeout=timeout;self.signer=signer
        self.fingerprint=certificate_fingerprint(certfile);self.context=tls_context(cafile,certfile,keyfile)
        self.last_tls_version=None

    def exchange(self,request,route):
        if self.fingerprint!=route['sender_cert'] or public(self.signer)!=route['sender_key']:raise Rejected('WRONG_GATEWAY_IDENTITY')
        deadline=time.monotonic()+self.timeout
        with socket.create_connection(('127.0.0.1',self.port),timeout=remaining(deadline)) as sock:
            sock.settimeout(remaining(deadline))
            with self.context.wrap_socket(sock,server_hostname=self.hostname) as channel:
                self.last_tls_version=channel.version()
                if hashlib.sha256(channel.getpeercert(binary_form=True)).digest()!=route['receiver_cert']:
                    raise Rejected('WRONG_RECIPIENT_IDENTITY')
                # No result/application bytes before destination certificate pin.
                send_packet(channel,request,deadline);return recv_packet(channel,deadline)

    def deliver(self,ledger,tenant,delivery_id,fault=lambda point:None):
        prepared=ledger.prepare_send(tenant,delivery_id,self.signer,fault)
        if prepared is None:return ledger.delivery_status(tenant,delivery_id)
        raw,route=prepared
        if self.fingerprint!=route['sender_cert']:raise Rejected('WRONG_GATEWAY_IDENTITY')
        request=self.attempt(raw,secrets.token_bytes(32))
        fault('before_network_send');ack=self.exchange(request,route);fault('after_ack_receive')
        ledger.confirm_ack(tenant,delivery_id,request,ack,fault)
        return 'ACKED'
