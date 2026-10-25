import ast
from contextlib import ExitStack
import concurrent.futures
import threading
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ordered_publication import OrderedPublicationSender,TLSOrderedPublicationSender
from atomic_publication import AtomicPublicationSender
from test_atomic_publication import setup
from test_encrypted_mixed_ledger import vault,register
from test_mixed_delegated_ledger import chain_fixture,credential,packet,finish,tick
from mixed_delegated_ledger import parse_mixed_credential
from test_retention_sender import context
from test_retention_recipient import recipient_vault
from retention_recipient import RetentionRecipient,TLSRetentionRecipient
from witnessed_ledger import ReferenceWitness
from ledger import Rejected
import retention_delivery as d
import retention_wire as r

HERE=Path(__file__).resolve().parent
CUTS=[]
NETWORK={}


def second_context(c):return dict(c,recipient='reader2',session='second',receiver_authority=b'2'*16)


def bind_second(l,c):
    l.authorize_root('t','domain','root2','manager','reader2',expires_at=1000)
    l.bind_root_authority('t','root2',b'authority')
    l.bind_root_delivery('t','root2',l.register_context(c))


def register_second(l,oid='b',hist=False):
    chain=[]
    for raw in chain_fixture(l):
        obj=parse_mixed_credential(raw);obj.update(root='root2',id=obj['id']+'2')
        obj['policy']['recipients']=['reader2']
        obj['parent_digest']=hashlib.sha256(chain[-1]).digest() if chain else b''
        chain.append(credential(obj))
    return l.register_delegated(*packet(l,chain,oid,hist,root='root2',recipient='reader2'),chain)


def child(config,point):
    cfg=json.loads(Path(config).read_text())
    def fault(p):
        if p==point:os._exit(93)
    w=ReferenceWitness(cfg['witness']);l=OrderedPublicationSender(cfg['ledger'],clock=lambda:100,vault=vault(),witness=w,witness_fault=fault)
    if cfg['mode']=='confirm':l.confirm('t',cfg['delivery'],bytes.fromhex(cfg['request']),bytes.fromhex(cfg['ack']),fault)
    else:tick(l,fault)
    raise RuntimeError('cut not reached')


class OrderedPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=tempfile.TemporaryDirectory();p=Path(cls.base.name)
        cls.template=p/'db';cls.wtemplate=p/'w'
        w=ReferenceWitness(cls.wtemplate);l=setup(OrderedPublicationSender.create(cls.template,clock=lambda:100,vault=vault(),witness=w))
        c,_,_=context();bind_second(l,second_context(c));l.close();w.close()

    @classmethod
    def tearDownClass(cls):cls.base.cleanup()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.lp=self.root/'db';self.wp=self.root/'w'
        shutil.copyfile(self.template,self.lp);shutil.copyfile(self.wtemplate,self.wp)
        self.w=ReferenceWitness(self.wp);self.now=100
        self.l=OrderedPublicationSender(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w)
        self.c,self.s,self.k=context();self.c2=second_context(self.c)
        self.receivers=[]

    def tearDown(self):
        for i,w in self.receivers:i.close();w.close()
        self.l.close();self.w.close();self.tmp.cleanup()

    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()

    def receiver(self,c):
        n=len(self.receivers);w=ReferenceWitness(self.root/('rw'+str(n)))
        i=RetentionRecipient.create(self.root/('inbox'+str(n)),context=c,vault=recipient_vault(),clock=lambda:self.now,witness=w)
        self.receivers.append((i,w));return i

    def pair(self,hist=False):
        register(self.l,'a',hist);register_second(self.l);finish(self.l)
        return self.l.decisions_internal('t','domain')

    def request(self,decision,terminal=False):
        c=self.c if decision['operation_id']!='b' else self.c2
        method=self.l.prepare_terminal if terminal else self.l.prepare_envelope
        raw=method('t',decision['delivery_id'],self.s)
        return d.attempt('TERMINAL' if terminal else 'DELIVERY',raw,b'q'*32,c,self.s)

    def acknowledge(self,decision,terminal=False):
        c=self.c if decision['operation_id']!='b' else self.c2
        req=self.request(decision,terminal);i=self.receiver(c)
        return req,i.accept(req,c['sender_cert'],self.k)

    def events(self):return self.l.final_events_internal('t','domain')

    def test_two_recipients_cannot_release_out_of_domain_order(self):
        a,b=self.pair(hist=True)
        self.assertNotEqual(a['context_hash'],b['context_hash'])
        with patch.object(self.l,'op',side_effect=AssertionError('private result accessed')):
            self.reject('DOMAIN_FINAL_ORDER',lambda:self.request(b))
        self.assertIsNone(self.l.outbox('t',b['delivery_id'])['envelope'])
        req,ack=self.acknowledge(a);before=self.w.head(self.l.namespace)['seq']
        self.l.confirm('t',a['delivery_id'],req,ack)
        self.assertEqual(self.w.head(self.l.namespace)['seq'],before+1)
        self.assertEqual([x['outcome'] for x in self.events()],['ACCEPTED'])
        req2,ack2=self.acknowledge(b);self.l.confirm('t',b['delivery_id'],req2,ack2)
        self.assertEqual([x['seq'] for x in self.events()],[1,2]);self.assertEqual(self.l.audit(),[])

    def test_receiver_acceptance_without_sender_ack_does_not_unlock_next(self):
        a,b=self.pair();req,ack=self.acknowledge(a)
        self.assertEqual(self.events(),[])
        self.reject('DOMAIN_FINAL_ORDER',lambda:self.request(b))
        retry=self.request(a);self.assertEqual(retry,req)
        self.l.confirm('t',a['delivery_id'],req,ack)
        original=self.events();self.l.confirm('t',a['delivery_id'],req,ack)
        self.assertEqual(self.events(),original);self.assertIsNotNone(self.request(b))

    def test_timeout_alone_never_advances_and_later_terminal_is_blocked(self):
        a,b=self.pair();self.now=170
        self.reject('DOMAIN_FINAL_ORDER',lambda:self.request(b,True))
        self.assertEqual(self.events(),[])
        with patch.object(self.l,'op',side_effect=AssertionError('private result read')):
            req,ack=self.acknowledge(a,True)
            self.l.confirm('t',a['delivery_id'],req,ack)
            req2,ack2=self.acknowledge(b,True)
            self.l.confirm('t',b['delivery_id'],req2,ack2)
        self.assertEqual([x['outcome'] for x in self.events()],['CLOSED','CLOSED'])
        self.assertEqual(self.l.audit(),[])

    def test_expiry_after_lost_ack_preserves_original_accepted_fact(self):
        a,b=self.pair();req,ack=self.acknowledge(a);receiver=self.receivers[0][0]
        self.now=170;term=self.request(a,True);reply=receiver.accept(term,self.c['sender_cert'],self.k)
        self.assertEqual(self.l.confirm('t',a['delivery_id'],term,reply),'ACCEPTED')
        self.reject('TICKET_EXPIRED',lambda:self.request(b))
        req2,ack2=self.acknowledge(b,True);self.l.confirm('t',b['delivery_id'],req2,ack2)
        self.assertEqual([x['outcome'] for x in self.events()],['ACCEPTED','CLOSED'])

    def test_withheld_event_waits_behind_unacknowledged_other_route(self):
        register(self.l,'a',False);register_second(self.l)
        self.l.advance('t','domain','cancel-b',0,dict(kind='cancel',operation='b',actor='leaf'));finish(self.l)
        a,b=self.l.decisions_internal('t','domain')
        self.assertEqual(b['kind'],'WITHHELD');self.assertEqual(self.events(),[])
        req,ack=self.acknowledge(a);self.l.confirm('t',a['delivery_id'],req,ack)
        self.assertEqual([x['outcome'] for x in self.events()],['ACCEPTED','WITHHELD'])
        self.assertEqual(self.l.audit(),[])

    def test_leading_withheld_is_finalized_in_publication_transaction(self):
        register(self.l,'a',False);register_second(self.l)
        self.l.advance('t','domain','cancel-a',0,dict(kind='cancel',operation='a',actor='leaf'));finish(self.l)
        self.assertEqual([x['outcome'] for x in self.events()],['WITHHELD'])
        b=self.l.decisions_internal('t','domain')[1];self.assertIsNotNone(self.request(b));self.assertEqual(self.l.audit(),[])

    def test_revocation_does_not_reset_frontier_or_unblock_pending(self):
        a,b=self.pair();self.l.revoke_context(a['context_hash'])
        self.reject('DOMAIN_FINAL_ORDER',lambda:self.request(b));self.now=170
        req,ack=self.acknowledge(a,True);self.l.confirm('t',a['delivery_id'],req,ack)
        self.assertEqual(self.events()[0]['outcome'],'CLOSED');self.assertEqual(self.l.audit(),[])

    def test_confirmation_failure_rolls_back_fact_and_entire_final_drain(self):
        a,b=self.pair();req,ack=self.acknowledge(a);before=self.l.state_image()
        def fail(point):
            if point=='after_final_event_write':raise RuntimeError('injected')
        with self.assertRaisesRegex(RuntimeError,'injected'):self.l.confirm('t',a['delivery_id'],req,ack,fail)
        self.assertEqual(self.l.state_image(),before);self.assertEqual(self.events(),[])
        self.reject('DOMAIN_FINAL_ORDER',lambda:self.request(b))
        self.l.confirm('t',a['delivery_id'],req,ack);self.assertEqual(self.l.final_frontier('t','domain'),1)

    def test_authority_ahead_restores_final_prefix_without_reconfirmation(self):
        a,b=self.pair();req,ack=self.acknowledge(a)
        def lose(point):
            if point=='after_witness_accept':raise ConnectionError('lost')
        self.l.witness_fault=lose
        with self.assertRaises(ConnectionError):self.l.confirm('t',a['delivery_id'],req,ack)
        self.l.witness_fault=lambda p:None
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:self.request(b))
        with patch.object(self.l,'_advance_final_tx',side_effect=AssertionError('replay')):self.l.recover_from_witness()
        self.assertEqual(self.events()[0]['outcome'],'ACCEPTED');self.assertIsNotNone(self.request(b));self.assertEqual(self.l.audit(),[])

    def test_recovery_rejects_valid_retention_image_with_missing_final_event(self):
        a,b=self.pair();req,ack=self.acknowledge(a);self.l.confirm('t',a['delivery_id'],req,ack)
        with self.l.tx():self.l.db.execute('DELETE FROM final_events')
        self.assertEqual(self.l.audit_v2(),[]);self.l.audit_publication()
        self.reject('FINAL_AUDIT_FAILED',lambda:OrderedPublicationSender.restore_new(self.root/'restore',clock=lambda:100,vault=vault(),witness=self.w))

    def test_recovery_rejects_forged_frontier_without_receipt(self):
        a,b=self.pair()
        with self.l.tx():self.l.db.execute('INSERT INTO final_events VALUES(?,?,?,?,?)',('t','domain',1,'ACCEPTED',a['delivery_id']))
        self.reject('FINAL_AUDIT_FAILED',lambda:OrderedPublicationSender.restore_new(self.root/'restore',clock=lambda:100,vault=vault(),witness=self.w))

    def test_profile_core_guard_and_original_retry_after_frontier_moves(self):
        self.reject('FINAL_TRANSACTION_REQUIRED',lambda:self.l._advance_final_tx('t','domain',lambda p:None))
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:AtomicPublicationSender(self.lp,clock=lambda:100,vault=vault(),witness=self.w))
        self.reject('AUTHENTICATED_WITNESS_REQUIRED',lambda:TLSOrderedPublicationSender(self.lp,clock=lambda:100,vault=vault(),witness=self.w))
        a,b=self.pair();req,ack=self.acknowledge(a);self.l.confirm('t',a['delivery_id'],req,ack)
        self.assertIsNone(self.l.prepare_envelope('t',a['delivery_id'],self.s))
        self.now=170;self.assertIsNotNone(self.request(a,True));self.assertEqual(self.l.final_frontier('t','domain'),1)

    def test_unresolved_domain_does_not_block_disjoint_domain(self):
        from dp_ledger import EPSILON_COST as E,DELTA_COST as D
        from contribution_scenario import USERS,RECORDS
        a,b=self.pair()
        l=self.l;l.provision_domain('t','isolated',3,2*E,2*D)
        l.authorize_root('t','isolated','isolated-root','manager','reader3',expires_at=1000)
        l.install_catalog('t','isolated','isolated-cat',['one','two','three','four'])
        mapped={u:hashlib.sha256(b'disjoint population'+u).digest() for u in USERS}
        l.bind_contribution_domain('t','isolated',b'I'*32,list(mapped.values()))
        l.ingest_pair('t','isolated','isolated-batch','isolated-cat','isolated-count','isolated-hist',[(mapped[u],v) for u,v in RECORDS])
        l.bind_root_authority('t','isolated-root',b'authority')
        c3=dict(self.c,recipient='reader3',session='isolated',receiver_authority=b'3'*16)
        l.bind_root_delivery('t','isolated-root',l.register_context(c3))
        chain=[]
        for raw in chain_fixture(l,root_cap=2,child_cap=2):
            obj=parse_mixed_credential(raw);obj.update(root='isolated-root',id=obj['id']+'-isolated' if chain else 'isolated-root')
            obj['policy'].update(domain='isolated',snapshots=['isolated-count','isolated-hist'],recipients=['reader3'],accounts=dict(epsilon='isolated:epsilon',delta='isolated:delta'),catalogs={'isolated-cat':bytes.fromhex(l.catalog('t','isolated','isolated-cat')['digest'])})
            obj['parent_digest']=hashlib.sha256(chain[-1]).digest() if chain else b'';chain.append(credential(obj))
        l.register_delegated(*packet(l,chain,'isolated-op',False,root='isolated-root',domain='isolated',snapshot='isolated-count',recipient='reader3'),chain)
        while l.db.execute("SELECT 1 FROM jobs WHERE domain_id='isolated' AND publication IS NULL").fetchone():
            n=l.db.execute("SELECT tick FROM schedulers WHERE domain_id='isolated'").fetchone()[0]
            l.advance('t','isolated','tick'+str(n),n)
        item=l.decisions_internal('t','isolated')[0];env=l.prepare_envelope('t',item['delivery_id'],self.s)
        req=d.attempt('DELIVERY',env,b'i'*32,c3,self.s);i=self.receiver(c3);ack=i.accept(req,c3['sender_cert'],self.k)
        l.confirm('t',item['delivery_id'],req,ack)
        self.assertEqual(l.final_frontier('t','isolated'),1);self.assertEqual(l.final_frontier('t','domain'),0)
        self.reject('DOMAIN_FINAL_ORDER',lambda:self.request(b));self.assertEqual(l.audit(),[])

    def test_audit_detects_trusted_base_class_bypass_of_order_gate(self):
        from retention_sender import RetentionSender
        a,b=self.pair()
        # Deliberately weaken the gate: signatures and retention checks alone
        # still permit this other route. Final audit must detect the violation.
        with patch.object(self.l,'first_pending',lambda row:RetentionSender.first_pending(self.l,row)):
            self.assertIsNotNone(self.request(b))
        self.assertEqual(self.l.audit_v2(),[]);self.l.audit_publication()
        self.reject('FINAL_AUDIT_FAILED',lambda:self.l.audit_final())
        self.reject('FINAL_AUDIT_FAILED',lambda:OrderedPublicationSender.restore_new(self.root/'restore',clock=lambda:100,vault=vault(),witness=self.w))

    def test_actual_process_cuts_preserve_ack_and_withheld_drain_atomically(self):
        register(self.l,'a',False);register_second(self.l)
        self.l.advance('t','domain','cancel-b',0,dict(kind='cancel',operation='b',actor='leaf'));finish(self.l)
        a=self.l.decisions_internal('t','domain')[0];req,ack=self.acknowledge(a)
        self.l.close();self.w.close();snapshot=self.root/'before';witness=self.root/'before-w'
        shutil.copyfile(self.lp,snapshot);shutil.copyfile(self.wp,witness)
        self.w=ReferenceWitness(self.wp);self.l=OrderedPublicationSender(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w)
        for point,durable in [('before_final_event_write',False),('after_final_event_write',False),('before_v2_confirmation_commit',False),('after_witness_accept',True),('after_local_anchor_write',True),('after_v2_confirmation_commit',True)]:
            with tempfile.TemporaryDirectory() as td:
                p=Path(td);lp=p/'db';wp=p/'w';shutil.copyfile(snapshot,lp);shutil.copyfile(witness,wp)
                cfg=dict(mode='confirm',ledger=str(lp),witness=str(wp),delivery=a['delivery_id'],request=req.hex(),ack=ack.hex())
                (p/'cfg').write_text(json.dumps(cfg));proc=subprocess.run([sys.executable,__file__,'--child',str(p/'cfg'),point],capture_output=True,text=True,timeout=30)
                self.assertEqual(proc.returncode,93,proc.stderr)
                w=ReferenceWitness(wp);l=OrderedPublicationSender(lp,clock=lambda:100,vault=vault(),witness=w)
                try:
                    l.recover_from_witness();self.assertEqual(l.final_frontier('t','domain'),2 if durable else 0)
                    self.assertEqual(l.outbox('t',a['delivery_id'])['fact'] is not None,durable)
                    l.confirm('t',a['delivery_id'],req,ack)
                    self.assertEqual([x['outcome'] for x in l.final_events_internal('t','domain')],['ACCEPTED','WITHHELD']);self.assertEqual(l.audit(),[])
                finally:l.close();w.close()
                CUTS.append(dict(operation='confirm_withheld_drain',point=point))

    def test_blocked_delivery_does_not_block_public_control_transactions(self):
        a,b=self.pair();n=self.l.db.execute('SELECT tick FROM schedulers').fetchone()[0]
        self.l.advance('t','domain','pause-while-blocked',n,dict(kind='pause'))
        self.assertEqual(self.events(),[])
        self.assertEqual(self.l.db.execute("SELECT count(*) FROM publication_events WHERE kind='CONTROL_ACK' AND tick=?",(n+1,)).fetchone()[0],1)
        self.reject('DOMAIN_FINAL_ORDER',lambda:self.request(b));self.assertEqual(self.l.audit(),[])

    def test_concurrent_confirmation_and_other_route_preparation_are_serialized(self):
        a,b=self.pair();req,ack=self.acknowledge(a);gate=threading.Barrier(2)
        def work(confirm):
            w=ReferenceWitness(self.wp);l=OrderedPublicationSender(self.lp,clock=lambda:100,vault=vault(),witness=w)
            try:
                gate.wait()
                if confirm:return l.confirm('t',a['delivery_id'],req,ack)
                try:
                    raw=l.prepare_envelope('t',b['delivery_id'],self.s)
                    self.assertEqual(l.final_frontier('t','domain'),1)
                    return 'prepared' if raw else 'empty'
                except Rejected as e:return str(e)
            finally:l.close();w.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f=pool.submit(work,True);g=pool.submit(work,False)
            self.assertEqual(f.result(),'ACCEPTED');self.assertIn(g.result(),['prepared','DOMAIN_FINAL_ORDER'])
        self.assertIsNotNone(self.request(b));self.assertEqual(self.l.audit(),[])

    def test_leading_withheld_publication_process_cuts(self):
        register(self.l,'a',False)
        self.l.advance('t','domain','cancel-a',0,dict(kind='cancel',operation='a',actor='leaf'))
        while self.l.db.execute("SELECT pc FROM jobs WHERE operation_id='a'").fetchone()[0]<84:tick(self.l)
        self.l.close();self.w.close();snapshot=self.root/'before';witness=self.root/'before-w'
        shutil.copyfile(self.lp,snapshot);shutil.copyfile(self.wp,witness)
        self.w=ReferenceWitness(self.wp);self.l=OrderedPublicationSender(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w)
        for point,durable in [('after_final_event_write',False),('after_witness_accept',True),('after_tick_commit',True)]:
            with tempfile.TemporaryDirectory() as td:
                p=Path(td);lp=p/'db';wp=p/'w';shutil.copyfile(snapshot,lp);shutil.copyfile(witness,wp)
                (p/'cfg').write_text(json.dumps(dict(mode='publish',ledger=str(lp),witness=str(wp))))
                proc=subprocess.run([sys.executable,__file__,'--child',str(p/'cfg'),point],capture_output=True,text=True,timeout=30)
                self.assertEqual(proc.returncode,93,proc.stderr)
                w=ReferenceWitness(wp);l=OrderedPublicationSender(lp,clock=lambda:100,vault=vault(),witness=w)
                try:
                    l.recover_from_witness();self.assertEqual(l.final_frontier('t','domain'),int(durable))
                    self.assertEqual(len(l.decisions_internal('t','domain')),int(durable))
                    self.assertEqual(l.db.execute('SELECT count(*) FROM v2_outbox').fetchone()[0],0)
                    if not durable:tick(l)
                    self.assertEqual(l.final_events_internal('t','domain')[0]['outcome'],'WITHHELD');self.assertEqual(l.audit(),[])
                finally:l.close();w.close()
                CUTS.append(dict(operation='leading_withheld_publication',point=point))

    def test_authenticated_two_recipient_network_lost_ack_then_ordered_release(self):
        from test_witness_transport import certificates,public
        from witness_transport import WitnessTLSService,TLSWitnessClient,trusted_register_peer,certificate_fingerprint
        from delivery_transport import RecipientTLSService,DeliverySender
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        folder=self.root/'tls';folder.mkdir();certs=certificates(folder)
        c=dict(self.c,session='tls-first',sender_cert=certificate_fingerprint(certs['writer'][0]),receiver_cert=certificate_fingerprint(certs['server'][0]));contexts=[c,second_context(c)]
        counts=dict(sender_witness=0,receiver1_witness=0,receiver2_witness=0,delivery1=0,delivery2=0);versions=set()
        with ExitStack() as stack:
            authorities={}
            for name,ns in [('sender',c['sender_authority']),('receiver1',c['receiver_authority']),('receiver2',contexts[1]['receiver_authority'])]:
                wp=folder/(name+'-w');key=Ed25519PrivateKey.generate();trusted_register_peer(wp,ns.hex(),certificate_fingerprint(certs['admin'][0]),'admin')
                service=stack.enter_context(WitnessTLSService(wp,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signing_key=key));authorities[name]=(service,key)
            def client(name):
                service,key=authorities[name];cl=TLSWitnessClient(port=service.port,cafile=certs['ca'],certfile=certs['admin'][0],keyfile=certs['admin'][1],witness_public_key=public(key));original=cl.exchange
                def exchange(raw,body):
                    counts[name+'_witness']+=1;result=original(raw,body);versions.add(cl.last_tls_version);return result
                cl.exchange=exchange;return cl
            sender=setup(TLSOrderedPublicationSender.create(folder/'sender',clock=lambda:100,vault=vault(),witness=client('sender')),False);stack.callback(sender.close)
            sender.bind_root_delivery('t','root',sender.register_context(c));bind_second(sender,contexts[1])
            register(sender,'a',True);register_second(sender);finish(sender);a,b=sender.decisions_internal('t','domain')
            transports=[];services=[]
            for n,ctx in enumerate(contexts,1):
                ip=folder/('inbox'+str(n));name='receiver'+str(n)
                created=TLSRetentionRecipient.create(ip,context=ctx,vault=recipient_vault(),clock=lambda:100,witness=client(name));created.close()
                def factory(ip=ip,ctx=ctx,name=name):return TLSRetentionRecipient(ip,context=ctx,vault=recipient_vault(),clock=lambda:100,witness=client(name))
                service=stack.enter_context(RecipientTLSService(inbox_factory=factory,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signer=self.k));services.append(service)
                transports.append(DeliverySender(port=service.port,cafile=certs['ca'],certfile=certs['writer'][0],keyfile=certs['writer'][1],signer=self.s))
            def send(n,req):
                counts['delivery'+str(n+1)]+=1
                try:return transports[n].exchange(req,contexts[n])
                finally:
                    if transports[n].last_tls_version:versions.add(transports[n].last_tls_version)
            env=sender.prepare_envelope('t',a['delivery_id'],self.s);req=d.attempt('DELIVERY',env,b'a'*32,c,self.s)
            def lose(point):
                if point=='before_ack_send':raise ConnectionError('lost first reply')
            services[0].fault=lose
            with self.assertRaises(OSError):send(0,req)
            self.reject('DOMAIN_FINAL_ORDER',lambda:sender.prepare_envelope('t',b['delivery_id'],self.s))
            self.assertEqual(counts['delivery2'],0);services[0].fault=lambda point:None
            sender.confirm('t',a['delivery_id'],req,send(0,req))
            env2=sender.prepare_envelope('t',b['delivery_id'],self.s);req2=d.attempt('DELIVERY',env2,b'b'*32,contexts[1],self.s)
            sender.confirm('t',b['delivery_id'],req2,send(1,req2))
            self.assertEqual([e['outcome'] for e in sender.final_events_internal('t','domain')],['ACCEPTED','ACCEPTED'])
            restored=TLSOrderedPublicationSender.restore_new(folder/'restored',clock=lambda:100,vault=vault(),witness=client('sender'))
            try:self.assertEqual(restored.state_image(),sender.state_image());self.assertEqual(restored.audit(),[])
            finally:restored.close()
            NETWORK.update(requests=counts,tls_versions=sorted(versions),scope='Two distinct recipient contexts/services and three authority services over authenticated loopback; histogram then count with actual first ACK socket loss. Shared host/CA and synthetic application keys, not independent infrastructure.')


def source_hashes():
    pending=['test_ordered_publication.py'];seen={}
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
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OrderedPublicationTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,actual_process_crash_scenarios=CUTS,crash_scenario_count=len(CUTS),network=NETWORK,source_sha256=source_hashes(),source_paths_relative_to='delivery root',scope='Domain-wide internal final prefix and guarded preparation across two routes; local process cuts and authenticated loopback mixed delivery. No external gateway, signed final feed or production observation refinement.')
    (HERE/'ordered_publication_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
