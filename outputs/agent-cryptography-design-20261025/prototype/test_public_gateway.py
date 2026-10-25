import ast
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from public_gateway import PublicGatewayLedger,TLSPublicGatewayLedger,PROFILE,request,response,parse_request
from public_gateway_transport import PublicGatewayTLSService,PublicGatewayClient
from test_atomic_publication import setup
from test_encrypted_mixed_ledger import vault
from test_mixed_delegated_ledger import KEYS,chain_fixture,packet,finish,tick
from test_retention_sender import context
from test_retention_recipient import recipient_vault
from retention_recipient import RetentionRecipient,TLSRetentionRecipient
from test_witness_transport import public,certificates
from witness_transport import WitnessTLSService,TLSWitnessClient,trusted_register_peer,certificate_fingerprint
from witnessed_ledger import ReferenceWitness
from ledger import Rejected
from dp_ledger import EPSILON_COST as E
from wire import decode,inspect_sign1
import retention_wire as r
import retention_delivery as d

HERE=Path(__file__).resolve().parent
SERVER_KEY=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'public gateway synthetic signing key only').digest())
SERVER_KID=b'public-gateway'
PEER=b'P'*32
SERVER_CERT=b'G'*32
CUTS=[]
NETWORK={}


def configure(l,peer=PEER,certificate=SERVER_CERT,delivery_context=None):
    setup(l,delivery_context is None)
    if delivery_context is not None:l.bind_root_delivery('t','root',l.register_context(delivery_context))
    l.configure_gateway(SERVER_KID,public(SERVER_KEY),certificate)
    l.enroll_public('t',b'leaf','domain',peer,['challenge','submit','poll','final','cancel'])
    l.enroll_public('t',b'manager','domain',peer,['pause','resume','revoke','final'])
    l.enroll_public('t',b'other','domain',peer,['poll'])
    return l


def make_request(method,payload,rid,actor='leaf',now=100,**changes):
    obj=dict(profile=PROFILE,deployment=vault().deployment_id,tenant='t',domain='domain',kid=actor.encode(),actor=actor,
             request_id=rid.to_bytes(16,'big'),issued_at=now,expires_at=now+60,method=method,payload=payload)
    obj.update(changes);return request(obj,KEYS[actor])


def bundle(l,challenge,oid='a',hist=False):
    chain=chain_fixture(l)
    with patch.object(l,'issue_challenge',return_value=challenge):raw,proof=packet(l,chain,oid,hist)
    return dict(action=raw,proof=proof,chain=chain)


def parse_reply(reply,raw):return response(reply,raw,public(SERVER_KEY),SERVER_KID,vault().deployment_id)


def child(config,point):
    cfg=json.loads(Path(config).read_text())
    def fault(p):
        if p==point:os._exit(92)
    w=ReferenceWitness(cfg['witness']);l=PublicGatewayLedger(cfg['ledger'],clock=lambda:100,vault=vault(),witness=w,witness_fault=fault)
    l.handle_public(bytes.fromhex(cfg['request']),PEER,SERVER_KEY,fault)
    raise RuntimeError('cut not reached')


class PublicGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=tempfile.TemporaryDirectory();p=Path(cls.base.name);cls.template=p/'db';cls.wtemplate=p/'w'
        w=ReferenceWitness(cls.wtemplate);l=configure(PublicGatewayLedger.create(cls.template,clock=lambda:100,vault=vault(),witness=w));l.close();w.close()

    @classmethod
    def tearDownClass(cls):cls.base.cleanup()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.lp=self.root/'db';self.wp=self.root/'w'
        shutil.copyfile(self.template,self.lp);shutil.copyfile(self.wtemplate,self.wp)
        self.w=ReferenceWitness(self.wp);self.now=100;self.rid=0
        self.l=PublicGatewayLedger(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w)

    def tearDown(self):self.l.close();self.w.close();self.tmp.cleanup()

    def raw(self,method,payload,actor='leaf',**changes):
        self.rid+=1;return make_request(method,payload,self.rid,actor,self.now,**changes)

    def call(self,method,payload,actor='leaf'):
        raw=self.raw(method,payload,actor);reply=self.l.handle_public(raw,PEER,SERVER_KEY)
        return raw,reply,parse_reply(reply,raw)

    def prepare_submit(self,oid='a',hist=False):
        _,_,challenge=self.call('CHALLENGE',{})
        return self.raw('SUBMIT',bundle(self.l,challenge['body'],oid,hist))

    def submit(self,oid='a',hist=False):
        raw=self.prepare_submit(oid,hist);reply=self.l.handle_public(raw,PEER,SERVER_KEY)
        self.assertEqual(parse_reply(reply,raw)['status'],'RECORDED');return raw,reply

    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()

    def rows(self):return self.l.db.execute('SELECT count(*) FROM gw_requests').fetchone()[0]

    def test_submit_and_exact_retry_after_request_expiry_have_one_effect(self):
        raw=self.prepare_submit();before=self.w.head(self.l.namespace)['seq']
        with patch.object(self.l,'operation_randomness',side_effect=AssertionError('pre-L1 sample')):
            reply=self.l.handle_public(raw,PEER,SERVER_KEY)
        self.assertEqual(self.w.head(self.l.namespace)['seq'],before+1);self.assertEqual(self.rows(),2)
        self.now=180
        with patch.object(self.l,'_dispatch',side_effect=AssertionError('reexecuted')):
            self.assertEqual(self.l.handle_public(raw,PEER,SERVER_KEY),reply)
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM operations').fetchone()[0],1)
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM used_proofs').fetchone()[0],1)
        self.assertEqual(self.l.audit(),[])

    def test_request_identity_conflict_does_not_replace_original_response(self):
        raw,reply=self.submit();obj=parse_request(raw)
        altered=request(dict(obj,method='FINAL',payload=dict(cursor=0,limit=1)),KEYS['leaf'])
        deny=parse_reply(self.l.handle_public(altered,PEER,SERVER_KEY),altered)
        self.assertEqual((deny['status'],deny['sequence']),('REJECTED',0));self.assertEqual(self.rows(),2)
        self.assertEqual(self.l.handle_public(raw,PEER,SERVER_KEY),reply)

    def test_wrong_certificate_signature_actor_deployment_and_expiry_are_generic(self):
        valid=self.raw('CHALLENGE',{})
        cases=[(valid,b'X'*32),(valid[:-1]+bytes([valid[-1]^1]),PEER),
               (self.raw('CHALLENGE',{},deployment=b'X'*16),PEER),
               (self.raw('CHALLENGE',{},issued_at=1,expires_at=2),PEER)]
        obj=parse_request(valid);cases.append((request(dict(obj,actor='manager'),KEYS['leaf']),PEER))
        for raw,peer in cases:
            out=parse_reply(self.l.handle_public(raw,peer,SERVER_KEY),raw)
            self.assertEqual((out['status'],out['body'],out['sequence']),('REJECTED',{},0))
        self.assertEqual(self.rows(),0);self.assertEqual(self.l.db.execute('SELECT count(*) FROM challenges').fetchone()[0],0)

    def test_poll_is_identical_before_and_during_private_work(self):
        self.submit();_,_,a=self.call('POLL',dict(operation='a'))
        tick(self.l)
        with patch.object(self.l,'op',side_effect=AssertionError('private operation read')),patch.object(self.l,'load_private_state',side_effect=AssertionError('private scheduler read')):
            _,_,b=self.call('POLL',dict(operation='a'))
        self.assertEqual(a['body'],b['body']);self.assertEqual(a['body']['publication'],'UNPUBLISHED')
        finish(self.l);_,_,c=self.call('POLL',dict(operation='a'))
        self.assertEqual(c['body']['publication'],'ADMITTED');self.assertEqual(c['body']['final'],'UNFINALIZED')
        self.assertEqual(self.l.audit(),[])

    def test_poll_and_control_cannot_cross_actor_scope(self):
        self.submit();_,_,deny=self.call('POLL',dict(operation='a'),'other');self.assertEqual(deny['status'],'REJECTED')
        _,_,deny=self.call('CONTROL',dict(kind='revoke',root='root'));self.assertEqual(deny['status'],'REJECTED')
        self.assertEqual(self.l.root('t','root')['revoked'],0);self.assertEqual(self.l.audit(),[])

    def test_cancel_does_not_advance_work_or_read_private_result(self):
        self.submit();before=self.l.db.execute('SELECT tick FROM schedulers').fetchone()[0]
        with patch.object(self.l,'op',side_effect=AssertionError('private operation read')):
            raw,reply,out=self.call('CONTROL',dict(kind='cancel',operation='a'))
        self.assertEqual(out['status'],'CONTROL_RECORDED');self.assertEqual(self.l.db.execute('SELECT tick FROM schedulers').fetchone()[0],before)
        self.assertEqual(self.l.op('t','a')['state'],'CANCELED')
        self.assertEqual(self.l.db.execute("SELECT reserved,spent FROM accounts WHERE id='domain:epsilon'").fetchone()[:],(0,0))
        finish(self.l);self.assertEqual(self.l.handle_public(raw,PEER,SERVER_KEY),reply)
        self.assertEqual(self.l.final_frontier('t','domain'),1);self.assertEqual(self.l.audit(),[])

    def test_post_L1_cancel_keeps_spending_with_same_public_ack_shape(self):
        self.submit();tick(self.l);_,_,out=self.call('CONTROL',dict(kind='cancel',operation='a'))
        self.assertEqual(out['body'],dict(kind='cancel',operation='a'))
        self.assertEqual(self.l.op('t','a')['state'],'BURNED')
        self.assertEqual(self.l.db.execute("SELECT spent FROM accounts WHERE id='domain:epsilon'").fetchone()[0],E)
        finish(self.l);self.assertEqual(self.l.audit(),[])

    def test_pause_resume_and_root_revocation_are_authenticated_durable_controls(self):
        self.submit();self.call('CONTROL',dict(kind='pause'),'manager');tick(self.l)
        self.assertEqual(self.l.db.execute('SELECT pc FROM jobs').fetchone()[0],0)
        restored=PublicGatewayLedger.restore_new(self.root/'restored',clock=lambda:100,vault=vault(),witness=self.w)
        try:self.assertEqual(restored.db.execute('SELECT paused FROM gw_domains').fetchone()[0],1);self.assertEqual(restored.audit(),[])
        finally:restored.close()
        self.call('CONTROL',dict(kind='resume'),'manager');tick(self.l)
        self.assertEqual(self.l.db.execute('SELECT pc FROM jobs').fetchone()[0],1)
        self.call('CONTROL',dict(kind='revoke',root='root'),'manager');finish(self.l)
        self.assertEqual(self.l.decisions_internal('t','domain')[0]['kind'],'WITHHELD');self.assertEqual(self.l.audit(),[])

    def test_final_pages_keep_original_response_and_contiguous_cursor(self):
        self.submit('a');self.submit('b');self.call('CONTROL',dict(kind='cancel',operation='b'))
        old,oldreply,_=self.call('FINAL',dict(cursor=0,limit=1));finish(self.l)
        c,s,k=context();decision=self.l.decisions_internal('t','domain')[0];env=self.l.prepare_envelope('t',decision['delivery_id'],s)
        req=d.attempt('DELIVERY',env,b'q'*32,c,s);w=ReferenceWitness(self.root/'rw');i=RetentionRecipient.create(self.root/'inbox',context=c,vault=recipient_vault(),clock=lambda:100,witness=w)
        try:self.l.confirm('t',decision['delivery_id'],req,i.accept(req,c['sender_cert'],k))
        finally:i.close();w.close()
        self.assertEqual(self.l.handle_public(old,PEER,SERVER_KEY),oldreply)
        _,_,first=self.call('FINAL',dict(cursor=0,limit=1));_,_,second=self.call('FINAL',dict(cursor=first['body']['cursor'],limit=1))
        self.assertEqual(first['body'],dict(events=[dict(sequence=1,outcome='ACCEPTED',operation='a')],cursor=1))
        self.assertEqual(second['body'],dict(events=[dict(sequence=2,outcome='WITHHELD',operation='b')],cursor=2))
        _,_,deny=self.call('FINAL',dict(cursor=3,limit=1));self.assertEqual(deny['status'],'REJECTED');self.assertEqual(self.l.audit(),[])

    def test_budget_rejection_rolls_back_proof_but_journals_denial(self):
        for oid in ('a','b','c'):self.submit(oid)
        raw=self.prepare_submit('fourth');reply=self.l.handle_public(raw,PEER,SERVER_KEY)
        self.assertEqual(parse_reply(reply,raw)['status'],'REJECTED')
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM used_proofs').fetchone()[0],3)
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM operations').fetchone()[0],3)
        self.assertEqual(self.l.handle_public(raw,PEER,SERVER_KEY),reply);self.assertEqual(self.l.audit(),[])

    def test_unknown_failure_rolls_back_business_and_journal_not_normal_denial(self):
        raw=self.prepare_submit();before=self.l.state_image();original=self.l.register_delegated
        def bad(*args,**kwargs):original(*args,**kwargs);raise Rejected('INJECTED_STORAGE_FAILURE')
        with patch.object(self.l,'register_delegated',side_effect=bad):self.reject('INJECTED_STORAGE_FAILURE',lambda:self.l.handle_public(raw,PEER,SERVER_KEY))
        self.assertEqual(self.l.state_image(),before);self.assertFalse(self.l._gw_join)
        self.assertEqual(parse_reply(self.l.handle_public(raw,PEER,SERVER_KEY),raw)['status'],'RECORDED')

    def test_live_revocation_blocks_cached_response_replay(self):
        raw,reply=self.submit();self.l.revoke_public('t',b'leaf','domain')
        out=parse_reply(self.l.handle_public(raw,PEER,SERVER_KEY),raw);self.assertEqual(out['status'],'REJECTED');self.assertNotEqual(reply,self.l.handle_public(raw,PEER,SERVER_KEY));self.assertEqual(self.l.audit(),[])

    def test_authority_ahead_requires_restore_before_cached_retry(self):
        raw=self.prepare_submit()
        def lose(point):
            if point=='after_witness_accept':raise ConnectionError('lost witness reply')
        self.l.witness_fault=lose
        with self.assertRaises(ConnectionError):self.l.handle_public(raw,PEER,SERVER_KEY)
        self.l.witness_fault=lambda p:None
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:self.l.handle_public(raw,PEER,SERVER_KEY))
        with patch.object(self.l,'_dispatch',side_effect=AssertionError('reexecution')):
            self.l.recover_from_witness();out=parse_reply(self.l.handle_public(raw,PEER,SERVER_KEY),raw)
        self.assertEqual(out['status'],'RECORDED');self.assertEqual(self.l.audit(),[])

    def test_recovery_rejects_missing_request_coverage_and_pause_state(self):
        self.submit()
        with self.l.tx():self.l.db.execute("DELETE FROM gw_requests WHERE seq=2")
        self.reject('GW_AUDIT_FAILED',lambda:PublicGatewayLedger.restore_new(self.root/'restore',clock=lambda:100,vault=vault(),witness=self.w))

    def test_recovery_rejects_deleted_control_only_journal(self):
        self.call('CONTROL',dict(kind='pause'),'manager');self.call('CONTROL',dict(kind='resume'),'manager')
        self.assertEqual(self.l.db.execute('SELECT paused FROM gw_domains').fetchone()[0],0)
        with self.l.tx():self.l.db.execute('DELETE FROM gw_requests')
        self.reject('GW_AUDIT_FAILED',lambda:PublicGatewayLedger.restore_new(self.root/'bad-control',clock=lambda:100,vault=vault(),witness=self.w))

    def test_recovery_rejects_unsigned_response_corruption(self):
        self.submit()
        with self.l.tx():
            row=self.l.db.execute('SELECT response FROM gw_requests WHERE seq=2').fetchone()[0]
            self.l.db.execute('UPDATE gw_requests SET response=? WHERE seq=2',(row[:-1]+bytes([row[-1]^1]),))
        self.reject('INVALID_SIGNATURE',lambda:PublicGatewayLedger.restore_new(self.root/'restore',clock=lambda:100,vault=vault(),witness=self.w))

    def test_concurrent_duplicate_requests_have_one_operation_and_identical_response(self):
        raw=self.prepare_submit();gate=threading.Barrier(2)
        def worker():
            w=ReferenceWitness(self.wp);l=PublicGatewayLedger(self.lp,clock=lambda:100,vault=vault(),witness=w)
            try:gate.wait();return l.handle_public(raw,PEER,SERVER_KEY)
            finally:l.close();w.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            a=pool.submit(worker);b=pool.submit(worker);self.assertEqual(a.result(),b.result())
        self.assertEqual(self.rows(),2);self.assertEqual(self.l.db.execute('SELECT count(*) FROM used_proofs').fetchone()[0],1);self.assertEqual(self.l.audit(),[])

    def test_core_and_profile_cannot_bypass_public_request_path(self):
        self.reject('PUBLIC_GATEWAY_REQUIRED',lambda:self.l.advance('t','domain','bypass',0,dict(kind='pause')))
        self.reject('PUBLIC_GATEWAY_REQUIRED',lambda:self.l.issue_challenge('t',b'leaf'))
        self.reject('PUBLIC_GATEWAY_REQUIRED',lambda:self.l.register_delegated(b'',b'',[]))
        from ordered_publication import OrderedPublicationSender
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:OrderedPublicationSender(self.lp,clock=lambda:100,vault=vault(),witness=self.w))
        self.l._gw_join=True
        try:self.reject('GW_TRANSACTION_REQUIRED',lambda:self.l.issue_challenge('t',b'leaf'))
        finally:self.l._gw_join=False

    def test_actual_process_cuts_restore_request_effect_and_original_response(self):
        raw=self.prepare_submit();self.l.close();self.w.close();snapshot=self.root/'before';witness=self.root/'before-w'
        shutil.copyfile(self.lp,snapshot);shutil.copyfile(self.wp,witness)
        self.w=ReferenceWitness(self.wp);self.l=PublicGatewayLedger(self.lp,clock=lambda:100,vault=vault(),witness=self.w)
        for point,durable in [('after_public_effect',False),('after_public_journal_write',False),('before_witness_accept',False),('after_witness_accept',True),('after_local_anchor_write',True),('after_public_request_commit',True)]:
            with tempfile.TemporaryDirectory() as td:
                p=Path(td);lp=p/'db';wp=p/'w';shutil.copyfile(snapshot,lp);shutil.copyfile(witness,wp)
                (p/'cfg').write_text(json.dumps(dict(ledger=str(lp),witness=str(wp),request=raw.hex())))
                proc=subprocess.run([sys.executable,__file__,'--child',str(p/'cfg'),point],capture_output=True,text=True,timeout=30)
                self.assertEqual(proc.returncode,92,proc.stderr)
                w=ReferenceWitness(wp);l=PublicGatewayLedger(lp,clock=lambda:100,vault=vault(),witness=w)
                try:
                    l.recover_from_witness();self.assertEqual(l.db.execute('SELECT count(*) FROM operations').fetchone()[0],int(durable))
                    self.assertEqual(l.db.execute('SELECT count(*) FROM used_proofs').fetchone()[0],int(durable))
                    self.assertEqual(l.db.execute('SELECT count(*) FROM gw_requests').fetchone()[0],1+int(durable))
                    expected=l.db.execute('SELECT response FROM gw_requests WHERE seq=2').fetchone()
                    reply=l.handle_public(raw,PEER,SERVER_KEY)
                    if durable:self.assertEqual(reply,expected[0])
                    self.assertEqual(parse_reply(reply,raw)['status'],'RECORDED');self.assertEqual(l.audit(),[])
                finally:l.close();w.close()
                CUTS.append(point)

    def test_request_signature_domain_and_all_signature_bytes_are_checked(self):
        from wire import sign1,encode
        raw=self.raw('CHALLENGE',{});obj=parse_request(raw)
        wrong=sign1(encode(obj),obj['kid'],KEYS['leaf'],'MixedActionProof')
        for altered in [wrong]+[raw[:len(raw)-64+i]+bytes([raw[len(raw)-64+i]^1])+raw[len(raw)-64+i+1:] for i in range(64)]:
            out=parse_reply(self.l.handle_public(altered,PEER,SERVER_KEY),altered)
            self.assertEqual(out['status'],'REJECTED')
        self.assertEqual(self.rows(),0)
        reply=self.l.handle_public(raw,PEER,SERVER_KEY)
        other=self.raw('CHALLENGE',{})
        self.reject('GW_RESPONSE',lambda:parse_reply(reply,other))

    def test_recovery_rejects_unjournaled_pause_and_future_poll_claim(self):
        self.submit();raw,reply,out=self.call('POLL',dict(operation='a'))
        with self.l.tx():
            body=dict(out['body'],publication='ADMITTED')
            forged=self.l._reply(raw,'POLL',body,out['sequence'],SERVER_KEY)
            self.l.db.execute('UPDATE gw_requests SET response=? WHERE seq=?',(forged,out['sequence']))
        self.reject('GW_AUDIT_FAILED',lambda:PublicGatewayLedger.restore_new(self.root/'bad-poll',clock=lambda:100,vault=vault(),witness=self.w))
        with self.l.tx():
            self.l.db.execute('UPDATE gw_requests SET response=? WHERE seq=?',(reply,out['sequence']))
            self.l.db.execute('UPDATE gw_domains SET paused=1')
        self.reject('GW_AUDIT_FAILED',lambda:PublicGatewayLedger.restore_new(self.root/'bad-pause',clock=lambda:100,vault=vault(),witness=self.w))

    def test_cancel_process_cuts_preserve_refund_and_control_journal_together(self):
        self.submit();raw=self.raw('CONTROL',dict(kind='cancel',operation='a'))
        self.l.close();self.w.close();snapshot=self.root/'before';witness=self.root/'before-w'
        shutil.copyfile(self.lp,snapshot);shutil.copyfile(self.wp,witness)
        self.w=ReferenceWitness(self.wp);self.l=PublicGatewayLedger(self.lp,clock=lambda:100,vault=vault(),witness=self.w)
        for point,durable in [('after_public_effect',False),('after_public_journal_write',False),('after_witness_accept',True)]:
            with tempfile.TemporaryDirectory() as td:
                p=Path(td);lp=p/'db';wp=p/'w';shutil.copyfile(snapshot,lp);shutil.copyfile(witness,wp)
                (p/'cfg').write_text(json.dumps(dict(ledger=str(lp),witness=str(wp),request=raw.hex())))
                proc=subprocess.run([sys.executable,__file__,'--child',str(p/'cfg'),point],capture_output=True,text=True,timeout=30)
                self.assertEqual(proc.returncode,92,proc.stderr)
                w=ReferenceWitness(wp);l=PublicGatewayLedger(lp,clock=lambda:100,vault=vault(),witness=w)
                try:
                    l.recover_from_witness();self.assertEqual(l.op('t','a')['state'],'CANCELED' if durable else 'RESERVED')
                    self.assertEqual(l.db.execute("SELECT reserved FROM accounts WHERE id='domain:epsilon'").fetchone()[0],0 if durable else E)
                    self.assertEqual(l.db.execute('SELECT count(*) FROM gw_requests').fetchone()[0],2+int(durable))
                    reply=l.handle_public(raw,PEER,SERVER_KEY);self.assertEqual(parse_reply(reply,raw)['status'],'CONTROL_RECORDED');self.assertEqual(l.audit(),[])
                finally:l.close();w.close()
                CUTS.append('cancel:'+point)

    def test_authenticated_public_network_commits_once_after_socket_reply_loss(self):
        folder=self.root/'tls';folder.mkdir();certs=certificates(folder);wp=folder/'w';wk=Ed25519PrivateKey.generate()
        trusted_register_peer(wp,vault().deployment_id.hex(),certificate_fingerprint(certs['admin'][0]),'admin')
        counts=dict(witness=0,public=0,receiver_witness=0,delivery=0);versions=set()
        with WitnessTLSService(wp,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signing_key=wk) as ws:
            def witness():
                cl=TLSWitnessClient(port=ws.port,cafile=certs['ca'],certfile=certs['admin'][0],keyfile=certs['admin'][1],witness_public_key=public(wk));orig=cl.exchange
                def counted(raw,body):counts['witness']+=1;out=orig(raw,body);versions.add(cl.last_tls_version);return out
                cl.exchange=counted;return cl
            lp=folder/'sender';peer=certificate_fingerprint(certs['writer'][0]);pin=certificate_fingerprint(certs['server'][0])
            delivery_context,delivery_signer,receiver_signer=context();delivery_context.update(session='public-network-result',sender_cert=peer,receiver_cert=pin)
            l=configure(TLSPublicGatewayLedger.create(lp,clock=lambda:100,vault=vault(),witness=witness()),peer,pin,delivery_context)
            try:
                def factory():return TLSPublicGatewayLedger(lp,clock=lambda:100,vault=vault(),witness=witness())
                with PublicGatewayTLSService(ledger_factory=factory,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signer=SERVER_KEY) as service:
                    client=PublicGatewayClient(port=service.port,cafile=certs['ca'],certfile=certs['writer'][0],keyfile=certs['writer'][1],server_certificate=pin,server_public_key=public(SERVER_KEY),server_kid=SERVER_KID,deployment=vault().deployment_id)
                    def send(raw):
                        counts['public']+=1
                        try:return client.exchange(raw)
                        finally:
                            if client.last_tls_version:versions.add(client.last_tls_version)
                    client.pin=b'X'*32
                    self.reject('GW_SERVER_IDENTITY',lambda:client.exchange(make_request('CHALLENGE',{},99)))
                    self.assertEqual(l.db.execute('SELECT count(*) FROM gw_requests').fetchone()[0],0)
                    client.pin=pin
                    challenge_raw=make_request('CHALLENGE',{},1);ch=parse_reply(send(challenge_raw),challenge_raw)
                    raw=make_request('SUBMIT',bundle(l,ch['body'],'network'),2)
                    def lose(point):
                        if point=='before_public_reply_send':raise ConnectionError('lost public response')
                    service.fault=lose
                    with self.assertRaises(OSError):send(raw)
                    service.fault=lambda p:None;reply=send(raw);self.assertEqual(parse_reply(reply,raw)['status'],'RECORDED')
                    self.assertEqual(l.db.execute('SELECT count(*) FROM operations').fetchone()[0],1)
                    self.assertEqual(l.db.execute('SELECT count(*) FROM used_proofs').fetchone()[0],1)
                    poll=make_request('POLL',dict(operation='network'),3);before=parse_reply(send(poll),poll)
                    tick(l);poll2=make_request('POLL',dict(operation='network'),4);during=parse_reply(send(poll2),poll2)
                    self.assertEqual(before['body'],during['body'])
                    cancel=make_request('CONTROL',dict(kind='cancel',operation='network'),5);self.assertEqual(parse_reply(send(cancel),cancel)['status'],'CONTROL_RECORDED')
                    finish(l);final=make_request('FINAL',dict(cursor=0,limit=16),6)
                    self.assertEqual(parse_reply(send(final),final)['body']['events'],[dict(sequence=1,outcome='WITHHELD',operation='network')])
                    challenge2=make_request('CHALLENGE',{},7);ch2=parse_reply(send(challenge2),challenge2)
                    submit2=make_request('SUBMIT',bundle(l,ch2['body'],'histogram',True),8)
                    self.assertEqual(parse_reply(send(submit2),submit2)['status'],'RECORDED');finish(l)
                    poll3=make_request('POLL',dict(operation='histogram'),9)
                    self.assertEqual(parse_reply(send(poll3),poll3)['body']['publication'],'ADMITTED')
                    from delivery_transport import RecipientTLSService,DeliverySender
                    rwp=folder/'receiver-w';rk=Ed25519PrivateKey.generate()
                    trusted_register_peer(rwp,delivery_context['receiver_authority'].hex(),certificate_fingerprint(certs['admin'][0]),'admin')
                    with WitnessTLSService(rwp,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signing_key=rk) as rwservice:
                        def receiver_witness():
                            cl=TLSWitnessClient(port=rwservice.port,cafile=certs['ca'],certfile=certs['admin'][0],keyfile=certs['admin'][1],witness_public_key=public(rk));orig=cl.exchange
                            def counted(raw,body):counts['receiver_witness']+=1;out=orig(raw,body);versions.add(cl.last_tls_version);return out
                            cl.exchange=counted;return cl
                        ip=folder/'inbox';created=TLSRetentionRecipient.create(ip,context=delivery_context,vault=recipient_vault(),clock=lambda:100,witness=receiver_witness());created.close()
                        def inbox():return TLSRetentionRecipient(ip,context=delivery_context,vault=recipient_vault(),clock=lambda:100,witness=receiver_witness())
                        with RecipientTLSService(inbox_factory=inbox,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signer=receiver_signer) as receiver_service:
                            transport=DeliverySender(port=receiver_service.port,cafile=certs['ca'],certfile=certs['writer'][0],keyfile=certs['writer'][1],signer=delivery_signer)
                            decision=l.decisions_internal('t','domain')[1];env=l.prepare_envelope('t',decision['delivery_id'],delivery_signer)
                            req=d.attempt('DELIVERY',env,b'r'*32,delivery_context,delivery_signer)
                            counts['delivery']+=1;ack=transport.exchange(req,delivery_context);versions.add(transport.last_tls_version)
                            self.assertEqual(l.confirm('t',decision['delivery_id'],req,ack),'ACCEPTED')
                        checked=inbox()
                        try:self.assertEqual(checked.audit(),[])
                        finally:checked.close()
                    final2=make_request('FINAL',dict(cursor=1,limit=16),10)
                    self.assertEqual(parse_reply(send(final2),final2)['body']['events'],[dict(sequence=2,outcome='ACCEPTED',operation='histogram')])
                    restored=TLSPublicGatewayLedger.restore_new(folder/'restored',clock=lambda:100,vault=vault(),witness=witness())
                    try:
                        with patch.object(restored,'_dispatch',side_effect=AssertionError('reexecute')):self.assertEqual(restored.handle_public(raw,peer,SERVER_KEY),reply)
                        self.assertEqual(restored.audit(),[])
                    finally:restored.close()
                    self.reject('WITNESS_RECOVERY_REQUIRED',lambda:l.audit());l.recover_from_witness()
                    self.assertEqual(l.audit(),[])
                NETWORK.update(requests=counts,rejected_server_pin_attempts=1,tls_versions=sorted(versions),scope='Actual loopback mTLS public challenge/submit/poll/cancel/final calls, socket response loss, authenticated witness, fresh replica exact response recovery. Trusted local scheduler plus full histogram result over separate mTLS recipient and authenticated recipient witness, followed by signed public final page. All services share one host/CA and synthetic keys.')
            finally:l.close()


def source_hashes():
    pending=['test_public_gateway.py'];seen={}
    while pending:
        name=pending.pop();path=HERE/name
        if not path.exists():path=HERE.parent/name
        if not path.exists():continue
        key=str(path.relative_to(HERE.parent))
        if key in seen:continue
        raw=path.read_bytes();seen[key]=hashlib.sha256(raw).hexdigest()
        for node in ast.walk(ast.parse(raw)):
            mods=[x.name for x in node.names] if isinstance(node,ast.Import) else ([node.module] if isinstance(node,ast.ImportFrom) else [])
            pending.extend(mod.split('.')[0]+'.py' for mod in mods if mod)
    return seen


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':child(*sys.argv[2:]);raise SystemExit(1)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicGatewayTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,actual_process_crash_scenarios=CUTS,crash_scenario_count=len(CUTS),network=NETWORK,source_sha256=source_hashes(),source_paths_relative_to='delivery root',scope='Certificate-bound signed public gateway journal, atomic request/effect/response and exact recovery; authenticated loopback and local process cuts. Partial explicit error mapping, no physical observation or arbitrary-concurrency proof.')
    (HERE/'public_gateway_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
