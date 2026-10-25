import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import cryptography
from delivery_transport import (DeliveryLedger,RecipientInbox,RecipientTLSService,DeliverySender,StateVault,Rejected,
    parse_envelope,parse_ack,attempt,public,ENVELOPE_TYPE,ACK_TYPE,recv_packet,MAX_FRAME)
from witness_transport import WitnessTLSService,TLSWitnessClient,TLSWitnessedLedger,certificate_fingerprint,trusted_register_peer
from wire import encode,decode,sign1,verify_sign1
from test_witness_transport import certificates
from test_encrypted_ledger import vault,register,step,raw_op
from test_delegated_ledger import KEYS,finish
from dp_ledger import EPSILON_COST as E,DELTA_COST as D

NETWORK_CALLS=0
TLS_VERSIONS=set()
CRASHES=[]


def keybytes(key):return key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())

def unpack_route(route):return {k:bytes.fromhex(v) if k not in ('tenant','recipient','gateway','session') else v for k,v in route.items()}

def child(config_path,point):
    c=json.loads(Path(config_path).read_text());route=unpack_route(c['route']);signer=ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['sender_key']))
    def fault(here):
        if here==point:os._exit(97)
    if 'inbox' in point:
        inbox=RecipientInbox(c['inbox'],deployment=c['namespace'],route=route,vault=StateVault(bytes.fromhex(c['inbox_key']),b'inbox-fixture-01'),clock=lambda:100)
        inbox.accept(bytes.fromhex(c['request']),route['sender_cert'],ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['receiver_key'])),fault)
    else:
        w=TLSWitnessClient(port=c['port'],cafile=c['ca'],certfile=c['cert'],keyfile=c['cert_key'],witness_public_key=bytes.fromhex(c['witness_key']))
        l=DeliveryLedger(c['ledger'],clock=lambda:100,vault=vault(),witness=w)
        if 'ack_commit' in point:l.confirm_ack('t','d',bytes.fromhex(c['request']),bytes.fromhex(c['ack']),fault)
        elif 'delivery_commit' in point:l.admit_delivery('t','a','reader','d','gateway','session',fault=fault)
        else:l.prepare_send('t','d',signer,fault)
    raise RuntimeError('crash point not reached')


class DeliveryTests(unittest.TestCase):
    ledger_class=DeliveryLedger
    inbox_class=RecipientInbox
    sender_class=DeliverySender
    @classmethod
    def setUpClass(cls):
        cls.ct=tempfile.TemporaryDirectory();cls.certs=certificates(cls.ct.name)
        cls.otherct=tempfile.TemporaryDirectory();cls.othercerts=certificates(cls.otherct.name)
        cls.wsign=ed25519.Ed25519PrivateKey.generate();cls.gsign=ed25519.Ed25519PrivateKey.generate();cls.rsign=ed25519.Ed25519PrivateKey.generate()
        cls.ivkey=os.urandom(32)
    @classmethod
    def tearDownClass(cls):cls.ct.cleanup();cls.otherct.cleanup()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.lp=self.root/'ledger';self.ip=self.root/'inbox';self.wp=self.root/'witness';self.now=100
        self.route=dict(tenant='t',recipient='reader',gateway='gateway',session='session',
            sender_cert=certificate_fingerprint(self.certs['writer'][0]),receiver_cert=certificate_fingerprint(self.certs['server'][0]),
            sender_key=public(self.gsign),receiver_key=public(self.rsign),sender_kid=b'gateway',receiver_kid=b'recipient')
        self.ns=vault().deployment_id.hex()
        trusted_register_peer(self.wp,self.ns,certificate_fingerprint(self.certs['admin'][0]),'admin')
        self.ws=WitnessTLSService(self.wp,cafile=self.certs['ca'],certfile=self.certs['server'][0],keyfile=self.certs['server'][1],signing_key=self.wsign)
        self.ws.__enter__();self.w=self.wclient()
        self.l=self.ledger_class.create(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w)
        self.l.provision_domain('t','domain',2,3*E,3*D);self.l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
        self.l.install_snapshot('t','domain','snap',[0,1])
        for name,key in KEYS.items():self.l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',public(key))
        self.l.bind_root_authority('t','root',b'authority');self.l.register_route(**self.route)
        register(self.l);finish(self.l)
        self.rs=RecipientTLSService(inbox_factory=self.inbox,cafile=self.certs['ca'],certfile=self.certs['server'][0],keyfile=self.certs['server'][1],signer=self.rsign)
        self.rs.__enter__();self.sender=self.sender_for()
    def tearDown(self):
        self.l.close();self.rs.__exit__();self.ws.__exit__();self.tmp.cleanup()
    def wclient(self):
        return TLSWitnessClient(port=self.ws.port,cafile=self.certs['ca'],certfile=self.certs['admin'][0],keyfile=self.certs['admin'][1],witness_public_key=public(self.wsign))
    def inbox(self):return self.inbox_class(self.ip,deployment=self.ns,route=self.route,vault=StateVault(self.ivkey,b'inbox-fixture-01'),clock=lambda:self.now)
    def sender_for(self,role='writer',**kw):
        sender=self.sender_class(port=kw.pop('port',self.rs.port),cafile=kw.pop('cafile',self.certs['ca']),certfile=self.certs[role][0],keyfile=self.certs[role][1],signer=kw.pop('signer',self.gsign),**kw)
        original=sender.exchange
        def exchange(request,route):
            global NETWORK_CALLS
            NETWORK_CALLS+=1
            out=original(request,route)
            if sender.last_tls_version:TLS_VERSIONS.add(sender.last_tls_version)
            return out
        sender.exchange=exchange;return sender
    def ticket(self,delivery='d',ttl=60):return self.l.admit_delivery('t','a','reader',delivery,'gateway','session',ttl)
    def prepared(self,delivery='d'):
        self.ticket(delivery);raw,route=self.l.prepare_send('t',delivery,self.gsign);return raw,route
    def inbox_rows(self):
        i=self.inbox()
        try:return [dict(r) for r in i.db.execute('SELECT * FROM inbox ORDER BY seq')]
        finally:i.close()
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()
    def reopen(self):
        self.l.close();self.l=self.ledger_class(self.lp,clock=lambda:self.now,vault=vault(),witness=self.wclient())
    def crash(self,point,request=b'',ack=b''):
        config=dict(route={k:v.hex() if isinstance(v,bytes) else v for k,v in self.route.items()},namespace=self.ns,
            sender_key=keybytes(self.gsign).hex(),receiver_key=keybytes(self.rsign).hex(),inbox_key=self.ivkey.hex(),inbox=str(self.ip),
            ledger=str(self.lp),port=self.ws.port,ca=str(self.certs['ca']),cert=str(self.certs['admin'][0]),cert_key=str(self.certs['admin'][1]),
            witness_key=public(self.wsign).hex(),request=request.hex(),ack=ack.hex())
        path=self.root/'child.json'
        with os.fdopen(os.open(str(path),os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600),'w') as f:json.dump(config,f)
        r=subprocess.run([sys.executable,__file__,'--child',str(path),point],capture_output=True,text=True,timeout=30)
        self.assertEqual(r.returncode,97,r.stderr);CRASHES.append(point);path.unlink()

    def test_end_to_end_authenticated_delivery_and_no_second_send_after_ack(self):
        self.ticket();before=[tuple(r) for r in self.l.db.execute('SELECT * FROM accounts')]
        self.assertEqual(self.sender.deliver(self.l,'t','d'),'ACKED');rows=self.inbox_rows();self.assertEqual(len(rows),1)
        i=self.inbox()
        try:
            raw=i.vault.open('inbox-envelope',(self.ns,'t','d'),rows[0]['envelope'])
            self.assertEqual(parse_envelope(raw,self.ns,self.route)['result'],self.l.op('t','a')['result'])
        finally:i.close()
        with patch.object(self.sender,'exchange',side_effect=AssertionError('second send')):
            self.assertEqual(self.sender.deliver(self.l,'t','d'),'ACKED')
        self.assertEqual([tuple(r) for r in self.l.db.execute('SELECT * FROM accounts')],before);self.assertEqual(self.l.audit(),[])

    def test_l3_ticket_and_outbox_share_one_transaction(self):
        def fault(point):
            if point=='before_delivery_commit':raise RuntimeError('cut')
        with self.assertRaises(RuntimeError):self.l.admit_delivery('t','a','reader','d','gateway','session',fault=fault)
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM deliveries').fetchone()[0],0)
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM delivery_outbox').fetchone()[0],0)
        self.ticket();self.ticket();self.assertEqual(self.l.db.execute('SELECT count(*) FROM delivery_outbox').fetchone()[0],1)

    def test_unknown_route_and_rebinding_are_rejected(self):
        self.reject('UNKNOWN_DELIVERY_ROUTE',lambda:self.l.admit_delivery('t','a','reader','d','gateway','different'))
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM deliveries').fetchone()[0],0)
        changed=dict(self.route,receiver_key=public(self.gsign));self.reject('DELIVERY_ROUTE_CONFLICT',lambda:self.l.register_route(**changed))
        self.reject('NETWORK_DELIVERY_REQUIRED',lambda:self.l.emit('t','d','reader','gateway','session'))

    def test_route_key_id_limit_matches_shared_cose_parser(self):
        for field in ('sender_kid','receiver_kid'):
            route=dict(self.route,session='invalid-key-id');route[field]=b'x'*33
            self.reject('INVALID_DELIVERY_ROUTE',lambda:self.l.register_route(**route))
        route=dict(self.route,session='maximum-key-id',sender_kid=b's'*32,receiver_kid=b'r'*32)
        self.l.register_route(**route)
        self.l.admit_delivery('t','a','reader','maximum','gateway','maximum-key-id')
        raw,pinned=self.l.prepare_send('t','maximum',self.gsign)
        self.assertEqual(parse_envelope(raw,self.ns,pinned)['delivery'],'maximum')
        self.assertEqual(self.l.audit(),[])

    def test_lost_receiver_ack_retries_identical_envelope_once(self):
        self.ticket();original_result=self.l.op('t','a')['result']
        def fault(point):
            if point=='before_ack_send':raise ConnectionError('lost ACK')
        self.rs.fault=fault
        with self.assertRaises((OSError,ConnectionError)):self.sender.deliver(self.l,'t','d')
        self.assertEqual(len(self.inbox_rows()),1);self.assertEqual(self.l.outbox('t','d')['state'],'READY')
        stored=self.l.outbox('t','d')['envelope'];self.rs.fault=lambda point:None;self.reopen()
        self.sender.deliver(self.l,'t','d')
        self.assertEqual(self.l.outbox('t','d')['envelope'],stored);self.assertEqual(len(self.inbox_rows()),1)
        self.assertEqual(self.l.op('t','a')['result'],original_result);self.assertEqual(self.l.audit(),[])

    def test_receiver_ack_loss_after_local_receive_can_retry_without_new_sample(self):
        self.ticket()
        def fault(point):
            if point=='after_ack_receive':raise RuntimeError('gateway lost ACK')
        with self.assertRaises(RuntimeError):self.sender.deliver(self.l,'t','d',fault)
        self.assertEqual(self.l.outbox('t','d')['state'],'READY');self.sender.deliver(self.l,'t','d')
        self.assertEqual(len(self.inbox_rows()),1);self.assertEqual(self.l.audit(),[])

    def test_revocation_preserves_only_original_ticket_recovery(self):
        t=self.ticket();self.l.revoke_credential('t','root')
        self.reject('ACTION_OR_KEY_INACTIVE',lambda:self.ticket('new'))
        self.sender.deliver(self.l,'t','d');self.assertEqual(len(self.inbox_rows()),1)
        self.assertEqual(self.l.db.execute('SELECT expires_at FROM deliveries').fetchone()[0],t['expires_at'])

    def test_route_revocation_blocks_unsent_old_ticket(self):
        self.ticket();self.l.revoke_route('t','reader','gateway','session')
        self.reject('DELIVERY_ROUTE_REVOKED',lambda:self.sender.deliver(self.l,'t','d'));self.assertFalse(self.inbox_rows())

    def test_original_expiry_and_receiver_time_enforced(self):
        raw,route=self.prepared();self.now=160
        self.reject('TICKET_EXPIRED',lambda:self.sender.deliver(self.l,'t','d'))
        i=self.inbox()
        try:self.reject('TICKET_EXPIRED',lambda:i.accept(attempt(raw,b'a'*32),route['sender_cert'],self.rsign))
        finally:i.close()
        self.assertFalse(self.inbox_rows());self.assertEqual(self.l.outbox('t','d')['state'],'READY')

    def test_receiver_rejection_preserves_clock_floor(self):
        raw,route=self.prepared();self.now=160;i=self.inbox()
        try:
            self.reject('TICKET_EXPIRED',lambda:i.accept(attempt(raw,b'a'*32),route['sender_cert'],self.rsign));self.now=100
            self.reject('INBOX_CLOCK_ROLLBACK',lambda:i.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign))
        finally:i.close()

    def test_valid_ca_wrong_gateway_certificate_is_not_authorized(self):
        raw,route=self.prepared();bad=self.sender_for('observer')
        self.reject('WRONG_GATEWAY_IDENTITY',lambda:bad.deliver(self.l,'t','d'))
        # Bypass client-side check to test independent receiver enforcement.
        bad.fingerprint=route['sender_cert']
        with self.assertRaises(OSError):bad.exchange(attempt(raw,b'c'*32),route)
        self.assertFalse(self.inbox_rows())

    def test_destination_pin_checked_before_any_result_bytes(self):
        raw,route=self.prepared();wrong=dict(route,receiver_cert=b'x'*32)
        with patch('delivery_transport.send_packet',side_effect=AssertionError('result sent before pin')):
            self.reject('WRONG_RECIPIENT_IDENTITY',lambda:self.sender.exchange(attempt(raw,b'd'*32),wrong))
        self.assertFalse(self.inbox_rows())

    def test_wrong_hostname_ca_and_gateway_signer(self):
        self.ticket()
        for sender in (self.sender_for(server_hostname='wrong.invalid'),self.sender_for(cafile=self.othercerts['ca'])):
            with self.assertRaises(ssl.SSLError):sender.deliver(self.l,'t','d')
        self.reject('WRONG_GATEWAY_SIGNER',lambda:self.sender_for(signer=self.rsign).deliver(self.l,'t','d'))
        self.assertFalse(self.inbox_rows())

    def test_envelope_signature_context_and_strict_fields(self):
        raw,route=self.prepared();_,obj=verify_sign1(raw,route['sender_key'],ENVELOPE_TYPE)
        for key,value in [('tenant','other'),('recipient','other'),('gateway','other'),('session','other'),('deployment','f'*32),('receiver_cert',b'r'*32),('sender_cert',b's'*32)]:
            changed=dict(obj);changed[key]=value
            packet=sign1(encode(changed),route['sender_kid'],self.gsign,ENVELOPE_TYPE)
            self.reject('DELIVERY_CONTEXT',lambda:parse_envelope(packet,self.ns,route))
        for changed in [dict(obj,extra=1),dict(obj,result=b'long'),dict(obj,expires_at=161),dict(obj,seq=0)]:
            self.reject('INVALID_DELIVERY_ENVELOPE',lambda:parse_envelope(sign1(encode(changed),route['sender_kid'],self.gsign,ENVELOPE_TYPE),self.ns,route))
        with self.assertRaises(Rejected):parse_envelope(raw[:-1]+bytes([raw[-1]^1]),self.ns,route)
        with self.assertRaises(Rejected):parse_envelope(sign1(encode(obj),route['sender_kid'],self.gsign,ACK_TYPE),self.ns,route)

    def test_ack_replay_cross_delivery_and_tampering_rejected(self):
        raw,route=self.prepared();request=attempt(raw,b'e'*32);ack=self.sender.exchange(request,route)
        self.reject('DELIVERY_ACK_BINDING',lambda:self.l.confirm_ack('t','d',attempt(raw,b'f'*32),ack))
        self.assertEqual(self.l.outbox('t','d')['state'],'READY')
        _,obj=verify_sign1(ack,route['receiver_key'],ACK_TYPE)
        for key,value in [('delivery','other'),('receiver_cert',b'r'*32),('seq',2),('envelope_hash',b'z'*32),('request_hash',b'x'*32)]:
            changed=dict(obj);changed[key]=value
            self.reject('DELIVERY_ACK_BINDING',lambda:self.l.confirm_ack('t','d',request,sign1(encode(changed),route['receiver_kid'],self.rsign,ACK_TYPE)))
        with self.assertRaises(Rejected):self.l.confirm_ack('t','d',request,ack[:-1]+bytes([ack[-1]^1]))
        self.l.confirm_ack('t','d',request,ack);self.assertEqual(self.l.audit(),[])

    def test_fifo_delivery_and_concurrent_receiver_deduplication(self):
        raw,route=self.prepared('d');self.ticket('d2')
        self.reject('DELIVERY_ORDER',lambda:self.sender.deliver(self.l,'t','d2'))
        def send(_):return self.sender.exchange(attempt(raw,secrets_bytes()),route)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:acks=list(pool.map(send,range(6)))
        self.assertEqual(len(acks),6);self.assertEqual(len(self.inbox_rows()),1)
        self.sender.deliver(self.l,'t','d');self.sender.deliver(self.l,'t','d2')
        self.assertEqual([r['seq'] for r in self.inbox_rows()],[1,2]);self.assertEqual(self.l.audit(),[])

    def test_receiver_rejects_changed_content_for_same_ticket(self):
        raw,route=self.prepared();self.sender.exchange(attempt(raw,b'g'*32),route)
        _,obj=verify_sign1(raw,route['sender_key'],ENVELOPE_TYPE);obj['result']=(99).to_bytes(8,'big')
        changed=sign1(encode(obj),route['sender_kid'],self.gsign,ENVELOPE_TYPE);i=self.inbox()
        try:self.reject('INBOX_DELIVERY_CONFLICT',lambda:i.accept(attempt(changed,b'h'*32),route['sender_cert'],self.rsign))
        finally:i.close()
        self.assertEqual(len(self.inbox_rows()),1)

    def test_wrong_inbox_key_and_route_cannot_reinterpret_records(self):
        self.reject('INBOX_PROFILE_MISMATCH',lambda:RecipientInbox(self.ip,deployment=self.ns,route=self.route,vault=StateVault(bytes(32),b'inbox-fixture-01'),clock=lambda:100))
        changed=dict(self.route,session='other')
        self.reject('INBOX_PROFILE_MISMATCH',lambda:RecipientInbox(self.ip,deployment=self.ns,route=changed,vault=StateVault(self.ivkey,b'inbox-fixture-01'),clock=lambda:100))
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:TLSWitnessedLedger(self.lp,clock=lambda:100,vault=vault(),witness=self.wclient()))

    def test_outbox_and_ack_survive_authoritative_witness_restore(self):
        self.ticket();backup=self.root/'old'
        db=sqlite3.connect(str(backup));self.l.db.backup(db);db.close()
        self.sender.deliver(self.l,'t','d');before=self.l.op('t','a')['result']
        self.l.close();self.lp.write_bytes(backup.read_bytes());self.l=DeliveryLedger(self.lp,clock=lambda:self.now,vault=vault(),witness=self.wclient())
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:self.sender.deliver(self.l,'t','d'))
        self.l.recover_from_witness();self.assertEqual(self.l.outbox('t','d')['state'],'ACKED')
        self.assertEqual(self.l.op('t','a')['result'],before);self.assertEqual(self.l.audit(),[])
        with patch.object(self.sender,'exchange',side_effect=AssertionError('replayed after recovery')):self.sender.deliver(self.l,'t','d')

    def test_no_queue_before_publication_and_no_bypass_of_expired_head(self):
        register(self.l,'b',b'b'*16)
        self.reject('PUBLICATION_PENDING_OR_WITHHELD',lambda:self.l.admit_delivery('t','b','reader','early','gateway','session'))
        self.ticket('d',ttl=1);self.ticket('d2',ttl=60);self.now=101
        self.reject('TICKET_EXPIRED',lambda:self.sender.deliver(self.l,'t','d'))
        self.reject('DELIVERY_ORDER',lambda:self.sender.deliver(self.l,'t','d2'))
        self.assertFalse(self.inbox_rows())

    def test_witness_acceptance_before_outbox_local_commit_is_recoverable(self):
        self.ticket()
        def fault(point):
            if point=='after_witness_accept':raise RuntimeError('local lost committed outbox')
        self.l.witness_fault=fault
        with self.assertRaises(RuntimeError):self.l.prepare_send('t','d',self.gsign)
        self.assertEqual(self.l.outbox('t','d')['state'],'QUEUED');self.assertFalse(self.inbox_rows())
        self.l.witness_fault=lambda point:None
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:self.sender.deliver(self.l,'t','d'))
        self.l.recover_from_witness();self.assertEqual(self.l.outbox('t','d')['state'],'READY')
        self.sender.deliver(self.l,'t','d');self.assertEqual(len(self.inbox_rows()),1);self.assertEqual(self.l.audit(),[])

    def test_historical_ack_can_be_recorded_after_expiry_without_new_disclosure(self):
        raw,route=self.prepared();request=attempt(raw,b'j'*32);ack=self.sender.exchange(request,route)
        self.now=160;self.l.confirm_ack('t','d',request,ack)
        self.assertEqual(self.l.outbox('t','d')['state'],'ACKED')
        with patch.object(self.sender,'exchange',side_effect=AssertionError('expired retransmission')):self.sender.deliver(self.l,'t','d')
        self.assertEqual(self.l.audit(),[])

    def test_frame_size_and_truncation(self):
        a,b=socket.socketpair()
        try:
            a.sendall(b'DLV1'+struct.pack('>I',MAX_FRAME+1))
            self.reject('DELIVERY_FRAME_LIMIT',lambda:recv_packet(b,__import__('time').monotonic()+1))
        finally:a.close();b.close()
        a,b=socket.socketpair()
        try:
            a.sendall(b'DLV1'+struct.pack('>I',4)+b'x');a.shutdown(socket.SHUT_WR)
            with self.assertRaises(ConnectionError):recv_packet(b,__import__('time').monotonic()+1)
        finally:a.close();b.close()

    def test_actual_process_death_ticket_and_outbox_boundaries(self):
        self.crash('before_delivery_commit');self.reopen()
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM deliveries').fetchone()[0],0)
        self.crash('after_delivery_commit');self.reopen();self.assertEqual(self.l.outbox('t','d')['state'],'QUEUED')
        self.crash('before_outbox_commit');self.reopen();self.assertEqual(self.l.outbox('t','d')['state'],'QUEUED')
        self.crash('after_outbox_commit');self.reopen();self.assertEqual(self.l.outbox('t','d')['state'],'READY')
        self.sender.deliver(self.l,'t','d');self.assertEqual(self.l.audit(),[])

    def test_actual_process_death_inbox_and_ack_boundaries(self):
        raw,route=self.prepared();request=attempt(raw,b'i'*32)
        self.crash('before_inbox_commit',request);self.assertFalse(self.inbox_rows())
        self.crash('after_inbox_commit',request);self.assertEqual(len(self.inbox_rows()),1)
        ack=self.sender.exchange(request,route)
        self.crash('before_ack_commit',request,ack);self.reopen();self.assertEqual(self.l.outbox('t','d')['state'],'READY')
        self.crash('after_ack_commit',request,ack);self.reopen();self.assertEqual(self.l.outbox('t','d')['state'],'ACKED')
        self.assertEqual(len(self.inbox_rows()),1);self.assertEqual(self.l.audit(),[])


def secrets_bytes():return os.urandom(32)

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':child(sys.argv[2],sys.argv[3])
    else:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(DeliveryTests)
        result=unittest.TextTestRunner(verbosity=2).run(suite);p=Path(__file__).parent
        files=['delivery_transport.py','test_delivery_transport.py','ledger.py','dp_ledger.py','scheduled_ledger.py','signed_ledger.py','delegated_ledger.py','encrypted_ledger.py','witnessed_ledger.py','witness_transport.py','wire.py','test_witness_transport.py','test_encrypted_ledger.py','test_delegated_ledger.py','test_signed_ledger.py','../fixed_work_model.py','requirements-crypto.txt']
        report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,network_calls=NETWORK_CALLS,tls_versions=sorted(TLS_VERSIONS),actual_process_crash_cuts=CRASHES,crash_cut_count=len(CRASHES),ssl_library=ssl.OPENSSL_VERSION,python_version=sys.version,sqlite_version=sqlite3.sqlite_version,cryptography_version=cryptography.__version__,source_sha256={n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in files},failures=result.failures,errors=result.errors,scope='Synthetic fixed count; loopback mTLS recipient, durable encrypted outbox and cooperative inbox deduplication; no public publication/physical-observation proof or exactly-once external effects')
        report['failures']=[(str(t),e) for t,e in result.failures];report['errors']=[(str(t),e) for t,e in result.errors]
        (p/'delivery_transport_test_results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        raise SystemExit(0 if result.wasSuccessful() else 1)
