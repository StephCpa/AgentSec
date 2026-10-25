import datetime
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,ed25519
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID

from witness_transport import (WitnessTLSService,TLSWitnessClient,TLSWitnessedLedger,Rejected,
    trusted_register_peer,trusted_revoke_peer,certificate_fingerprint,parse_request,receive_frame,
    send_frame,PROFILE,SERVICE,REPLY_TYPE,MAX_META,AuthorizedWitness)
from witnessed_ledger import ReferenceWitness,WitnessedLedger,image_hash
from wire import encode,decode,sign1
from dp_ledger import EPSILON_COST as E,DELTA_COST as D
from test_delegated_ledger import KEYS,finish
from test_encrypted_ledger import vault,register,step,raw_op

TLS_VERSIONS=set()
NETWORK_CALLS=0


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)


def certificates(directory):
    # Entirely ephemeral test CA and keys. Never use this helper for production.
    directory=Path(directory);now=datetime.datetime.now(datetime.timezone.utc)
    ca_key=ec.generate_private_key(ec.SECP256R1());ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic witness test CA')])
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
        .not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(True,False,False,False,False,True,True,None,None),critical=True).sign(ca_key,hashes.SHA256()))
    ca_path=directory/'ca.pem';ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM));out={'ca':ca_path}
    for name in ('server','admin','writer','restorer','observer','unregistered','expired'):
        key=ec.generate_private_key(ec.SECP256R1());subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
        builder=(x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=2))
            .not_valid_after(now-datetime.timedelta(days=1) if name=='expired' else now+datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,None,None),critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if name=='server' else ExtendedKeyUsageOID.CLIENT_AUTH]),critical=True))
        if name=='server':builder=builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
        cert=builder.sign(ca_key,hashes.SHA256());cp=directory/(name+'.pem');kp=directory/(name+'.key')
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        with os.fdopen(os.open(str(kp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        out[name]=(cp,kp)
    return out


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_tmp=tempfile.TemporaryDirectory();cls.certs=certificates(cls.cert_tmp.name)
        cls.signer=ed25519.Ed25519PrivateKey.generate();cls.pub=public(cls.signer)
    @classmethod
    def tearDownClass(cls):cls.cert_tmp.cleanup()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.wp=self.root/'witness';self.ns=vault().deployment_id.hex()
        for role in ('admin','writer','restorer','observer'):
            trusted_register_peer(self.wp,self.ns,certificate_fingerprint(self.certs[role][0]),role)
        cert,key=self.certs['server']
        self.server=WitnessTLSService(self.wp,cafile=self.certs['ca'],certfile=cert,keyfile=key,signing_key=self.signer)
        self.server.__enter__();self.admin=self.client('admin');self.writer=self.client('writer')
    def tearDown(self):
        self.server.__exit__();self.tmp.cleanup()
    def client(self,role,**kwargs):
        cert,key=self.certs[role]
        client=TLSWitnessClient(port=self.server.port,cafile=kwargs.pop('cafile',self.certs['ca']),certfile=cert,keyfile=key,
            witness_public_key=kwargs.pop('witness_public_key',self.pub),**kwargs)
        original=client.exchange
        def exchange(raw,body):
            global NETWORK_CALLS
            NETWORK_CALLS+=1
            result=original(raw,body)
            if client.last_tls_version:TLS_VERSIONS.add(client.last_tls_version)
            return result
        client.exchange=exchange
        return client
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()
    def initialize(self):return self.admin.bootstrap(self.ns,b'initial-state')
    def setup_ledger(self):
        l=TLSWitnessedLedger.create(self.root/'ledger',clock=lambda:100,vault=vault(),witness=self.admin)
        l.witness=self.writer
        l.provision_domain('t','domain',2,3*E,3*D)
        l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
        l.install_snapshot('t','domain','snap',[0,1])
        for name,key in KEYS.items():l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',public(key))
        l.bind_root_authority('t','root',b'authority');return l

    def test_authenticated_head_cas_and_image_round_trip(self):
        a=self.initialize();self.assertEqual(self.writer.head(self.ns),a)
        b=self.writer.compare_and_store(self.ns,a['seq'],a['digest'],b'new-state','a'*32)
        self.assertEqual(self.writer.head(self.ns,True),dict(b,image=b'new-state'))
        self.assertEqual(self.writer.compare_and_store(self.ns,a['seq'],a['digest'],b'new-state','a'*32),b)
        self.assertIn(self.writer.last_tls_version,('TLSv1.2','TLSv1.3'))

    def test_roles_distinguish_bootstrap_head_image_and_write(self):
        a=self.initialize();observer=self.client('observer');restorer=self.client('restorer')
        self.assertEqual(observer.head(self.ns),a)
        self.reject('WITNESS_ACCESS_DENIED',lambda:observer.head(self.ns,True))
        self.assertEqual(restorer.head(self.ns,True)['image'],b'initial-state')
        for client in (observer,restorer):
            self.reject('WITNESS_ACCESS_DENIED',lambda:client.compare_and_store(self.ns,a['seq'],a['digest'],b'new','b'*32))
        self.reject('WITNESS_ACCESS_DENIED',lambda:self.writer.bootstrap('b'*32,b'reset'))
        self.reject('WITNESS_ACCESS_DENIED',lambda:self.writer.bootstrap(self.ns,b'reset'))

    def test_valid_ca_certificate_is_not_itself_namespace_authority(self):
        self.initialize();unregistered=self.client('unregistered')
        self.reject('WITNESS_ACCESS_DENIED',lambda:unregistered.head(self.ns))
        self.reject('WITNESS_ACCESS_DENIED',lambda:self.writer.head('b'*32))

    def test_peer_revocation_after_tls_handshake_precedes_cas_and_retry(self):
        a=self.initialize();fingerprint=certificate_fingerprint(self.certs['writer'][0])
        def revoke(point,request):
            if point=='before_dispatch' and request['method']=='cas':
                trusted_revoke_peer(self.wp,self.ns,fingerprint)
        self.server.fault=revoke
        self.reject('WITNESS_ACCESS_DENIED',lambda:self.writer.compare_and_store(self.ns,a['seq'],a['digest'],b'new','b'*32))
        self.server.fault=lambda *args:None
        self.assertEqual(self.admin.head(self.ns),a)

    def test_permission_check_holds_same_write_transaction_as_cas(self):
        a=self.initialize();checked=threading.Event();resume=threading.Event()
        original=AuthorizedWitness.authorize_operation
        def gate(obj,namespace,operation):
            original(obj,namespace,operation)
            if operation=='cas':checked.set();self.assertTrue(resume.wait(timeout=3))
        with patch.object(AuthorizedWitness,'authorize_operation',gate),concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(self.writer.compare_and_store,self.ns,a['seq'],a['digest'],b'new','a'*32)
            try:
                self.assertTrue(checked.wait(timeout=3))
                admin_db=sqlite3.connect(str(self.wp),timeout=0,isolation_level=None)
                try:
                    with self.assertRaisesRegex(sqlite3.OperationalError,'locked'):
                        admin_db.execute('UPDATE witness_clients SET revoked=1 WHERE namespace=?',(self.ns,))
                finally:admin_db.close()
            finally:resume.set()
            self.assertEqual(future.result(timeout=3)['seq'],1)
        trusted_revoke_peer(self.wp,self.ns,certificate_fingerprint(self.certs['writer'][0]))
        self.reject('WITNESS_ACCESS_DENIED',lambda:self.writer.head(self.ns))

    def test_revoked_peer_cannot_query_old_success_as_write_retry(self):
        a=self.initialize();b=self.writer.compare_and_store(self.ns,a['seq'],a['digest'],b'new','a'*32)
        trusted_revoke_peer(self.wp,self.ns,certificate_fingerprint(self.certs['writer'][0]))
        self.reject('WITNESS_ACCESS_DENIED',lambda:self.writer.compare_and_store(self.ns,a['seq'],a['digest'],b'new','a'*32))
        self.assertEqual(self.admin.head(self.ns),b)

    def test_wrong_server_hostname_and_untrusted_ca_fail_handshake(self):
        self.initialize()
        with self.assertRaises(ssl.SSLError):self.client('writer',server_hostname='not-localhost').head(self.ns)
        foreign_dir=self.root/'foreign';foreign_dir.mkdir();foreign=certificates(foreign_dir)
        with self.assertRaises(ssl.SSLError):self.client('writer',cafile=foreign['ca']).head(self.ns)

    def test_missing_expired_and_untrusted_client_certificates_are_rejected(self):
        self.initialize()
        with self.assertRaises(OSError):self.client('expired').head(self.ns)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.load_verify_locations(cafile=str(self.certs['ca']))
        with self.assertRaises(OSError):
            with socket.create_connection(('127.0.0.1',self.server.port),timeout=3) as sock:
                with context.wrap_socket(sock,server_hostname='localhost') as channel:
                    channel.sendall(b'x');channel.recv(1)
        foreign_dir=self.root/'foreign';foreign_dir.mkdir();foreign=certificates(foreign_dir)
        client=TLSWitnessClient(port=self.server.port,cafile=self.certs['ca'],certfile=foreign['writer'][0],keyfile=foreign['writer'][1],witness_public_key=self.pub)
        with self.assertRaises(OSError):client.head(self.ns)

    def test_valid_tls_with_wrong_application_signing_pin_is_rejected(self):
        self.initialize();wrong=self.client('writer',witness_public_key=public(ed25519.Ed25519PrivateKey.generate()))
        self.reject('INVALID_SIGNATURE',lambda:wrong.head(self.ns))

    def test_old_signed_head_cannot_answer_a_new_challenge(self):
        self.initialize();captured=[];exchange=self.writer.exchange
        def capture(raw,body):
            result=exchange(raw,body);captured.append(result);return result
        self.writer.exchange=capture;self.writer.head(self.ns)
        self.writer.exchange=lambda *args:captured[0]
        self.reject('WITNESS_REPLY_BINDING',lambda:self.writer.head(self.ns))

    def test_signed_reply_binds_requester_namespace_method_and_request_digest(self):
        self.initialize();exchange=self.writer.exchange
        changes={'requester':bytes(32),'namespace':'b'*32,'method':'cas','request_digest':bytes(32),
                 'service':'other-witness','challenge':bytes(32)}
        for field,value in changes.items():
            with self.subTest(field=field):
                def altered(raw,body):
                    meta,data=exchange(raw,body);obj=decode(decode(meta[1:])[2]);obj[field]=value
                    return sign1(encode(obj),b'witness',self.signer,REPLY_TYPE),data
                self.writer.exchange=altered
                self.reject('WITNESS_REPLY_BINDING',lambda:self.writer.head(self.ns))

    def test_reply_signature_domain_and_body_tampering_reject(self):
        self.initialize();exchange=self.writer.exchange
        def bad_domain(raw,body):
            meta,data=exchange(raw,body);obj=decode(decode(meta[1:])[2]);return sign1(encode(obj),b'witness',self.signer,'Receipt'),data
        self.writer.exchange=bad_domain;self.reject('INVALID_SIGNATURE',lambda:self.writer.head(self.ns))
        def bad_body(raw,body):
            meta,data=exchange(raw,body);return meta,data+b'changed'
        self.writer.exchange=bad_body;self.reject('WITNESS_REPLY_BINDING',lambda:self.writer.head(self.ns,True))

    def test_request_canonical_schema_and_body_binding_are_strict(self):
        request=dict(profile=PROFILE,service=SERVICE,method='head',namespace=self.ns,challenge=b'c'*32,
                     body_size=0,body_hash=hashlib.sha256(b'').digest(),include_image=0)
        self.assertEqual(parse_request(encode(request),b''),request)
        for changes in ({'unknown':1},{'service':'other'},{'body_size':1},{'body_hash':bytes(32)},
                        {'challenge':b'x'},{'include_image':2},{'namespace':'../x'},{'method':'delete'},{'method':[]}):
            self.reject('INVALID_WITNESS_RPC',lambda:parse_request(encode(dict(request,**changes)),b''))
        raw=encode(request)
        with self.assertRaises(Rejected):parse_request(raw+b'\x00',b'')

    def test_frame_lengths_are_bounded_before_body_allocation(self):
        for header in (b'BAD!'+struct.pack('>II',1,0),b'WRP1'+struct.pack('>II',MAX_META+1,0),
                       b'WRP1'+struct.pack('>II',1,16*1024*1024+1)):
            a,b=socket.socketpair()
            try:
                a.sendall(header)
                with self.assertRaises(Rejected):receive_frame(b,time.monotonic()+1)
            finally:a.close();b.close()

    def test_signed_authenticated_rejection_does_not_change_witness_head(self):
        a=self.initialize()
        self.reject('WITNESS_CAS_CONFLICT',lambda:self.writer.compare_and_store(self.ns,9,'0'*64,b'bad','a'*32))
        self.assertEqual(self.writer.head(self.ns),a)

    def test_full_ledger_uses_network_witness_and_recovers_a_lost_cas_reply(self):
        l=self.setup_ledger()
        try:
            register(l);before=self.writer.head(self.ns)
            def drop(point,request):
                if point=='after_dispatch' and request['method']=='cas':raise ConnectionError('drop committed reply')
            self.server.fault=drop
            with self.assertRaises(ConnectionError):step(l)
            self.server.fault=lambda *args:None
            self.assertEqual(raw_op(l)['state'],'RESERVED')
            self.assertEqual(self.writer.head(self.ns)['seq'],before['seq']+1)
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:step(l))
            l.recover_from_witness();seed=raw_op(l)['seed'];finish(l)
            self.assertEqual(raw_op(l)['seed'],seed)
            l.admit_delivery('t','a','reader','ticket','gw','session')
            self.assertEqual(l.emit('t','ticket','reader','gw','session'),l.op('t','a')['result'])
            self.assertEqual(l.audit(),[])
        finally:l.close()

    def test_witness_identity_failure_blocks_local_progress_and_plain_adapter(self):
        l=self.setup_ledger();register(l);before=raw_op(l)
        try:
            with patch.object(self.writer,'public_key',public(ed25519.Ed25519PrivateKey.generate())):
                self.reject('INVALID_SIGNATURE',lambda:step(l))
            self.assertEqual(raw_op(l),before)
            direct=ReferenceWitness(self.wp)
            try:
                self.reject('STORAGE_PROFILE_MISMATCH',lambda:WitnessedLedger(l.path,clock=lambda:100,vault=vault(),witness=direct))
                self.reject('AUTHENTICATED_WITNESS_REQUIRED',lambda:TLSWitnessedLedger(l.path,clock=lambda:100,vault=vault(),witness=direct))
            finally:direct.close()
            self.assertEqual(l.audit(),[])
        finally:l.close()

    def test_invalid_signature_after_cas_does_not_imply_rollback_at_witness(self):
        l=self.setup_ledger();register(l);exchange=self.writer.exchange
        def corrupt(raw,body):
            meta,data=exchange(raw,body)
            if decode(raw)['method']=='cas':meta=meta[:-1]+bytes([meta[-1]^1])
            return meta,data
        try:
            self.writer.exchange=corrupt
            self.reject('INVALID_SIGNATURE',lambda:step(l))
            self.writer.exchange=exchange
            self.assertEqual(raw_op(l)['state'],'RESERVED')
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:step(l))
            l.recover_from_witness();self.assertEqual(raw_op(l)['state'],'STARTED');self.assertEqual(l.audit(),[])
        finally:self.writer.exchange=exchange;l.close()

    def test_client_timeout_after_acceptance_is_an_unknown_outcome(self):
        l=self.setup_ledger();register(l);accepted=threading.Event();resume=threading.Event()
        def delay(point,request):
            if point=='after_dispatch' and request['method']=='cas':
                accepted.set();resume.wait(timeout=3)
        try:
            self.server.fault=delay;self.writer.timeout=0.5
            with self.assertRaises((TimeoutError,socket.timeout)):step(l)
            self.assertTrue(accepted.is_set());self.assertEqual(raw_op(l)['state'],'RESERVED')
            resume.set();self.server.fault=lambda *args:None;self.writer.timeout=5
            self.reject('WITNESS_RECOVERY_REQUIRED',lambda:step(l))
            l.recover_from_witness();self.assertEqual(raw_op(l)['state'],'STARTED');self.assertEqual(l.audit(),[])
        finally:resume.set();l.close()


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TransportTests))
    root=Path(__file__).resolve().parent
    sources=('witness_transport.py','test_witness_transport.py','witnessed_ledger.py','encrypted_ledger.py','ledger.py',
             'scheduled_ledger.py','dp_ledger.py','signed_ledger.py','delegated_ledger.py','wire.py',
             'test_encrypted_ledger.py','test_delegated_ledger.py','test_signed_ledger.py','../fixed_work_model.py','requirements-crypto.txt')
    report={'passed':result.wasSuccessful(),'test_methods':result.testsRun,'network_calls':NETWORK_CALLS,'tls_versions':sorted(TLS_VERSIONS),
            'ssl_library':ssl.OPENSSL_VERSION,'python_version':sys.version,'cryptography_version':__import__('cryptography').__version__,
            'source_sha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in sources},
            'failures':[(str(t),m) for t,m in result.failures],'errors':[(str(t),m) for t,m in result.errors],
            'scope':'Ephemeral loopback mTLS, pinned Ed25519 signed replies, challenge binding, transactionally checked per-namespace writer rights; not production CA, independent nonrollback infrastructure or full observation proof'}
    (root/'witness_transport_test_results.json').write_text(json.dumps(report,indent=2)+'\n');sys.exit(0 if result.wasSuccessful() else 1)
