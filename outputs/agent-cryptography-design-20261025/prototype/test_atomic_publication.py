import ast
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

from atomic_publication import AtomicPublicationSender,TLSAtomicPublicationSender
from contribution_delivery import ContributionRetentionSender
from retention_sender import RetentionSender
from witnessed_ledger import ReferenceWitness
from ledger import Rejected
from dp_ledger import EPSILON_COST as E,DELTA_COST as D
from contribution_scenario import USERS,RECORDS
from test_encrypted_mixed_ledger import vault,register
from test_mixed_delegated_ledger import KEYS,finish,tick
from test_retention_sender import context
from test_retention_recipient import recipient_vault
from test_witness_transport import public
from test_witness_transport import certificates
from witness_transport import WitnessTLSService,TLSWitnessClient,trusted_register_peer,certificate_fingerprint
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from retention_recipient import RetentionRecipient
import retention_wire as r
import retention_delivery as d

HERE=Path(__file__).resolve().parent
CUTS=[]
NETWORK={}


def setup(l,bound=True):
    l.provision_domain('t','domain',3,4*E,4*D)
    l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
    l.install_catalog('t','domain','cat',['one','two','three','four'])
    l.bind_contribution_domain('t','domain',b'L'*32,USERS)
    l.ingest_pair('t','domain','batch','cat','count','hist',RECORDS)
    for name,key in KEYS.items():l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',public(key))
    l.bind_root_authority('t','root',b'authority')
    c,_,_=context();h=l.register_context(c)
    if bound:l.bind_root_delivery('t','root',h)
    return l


def child(lp,wp,point):
    def fault(p):
        if p==point:os._exit(94)
    w=ReferenceWitness(wp);l=AtomicPublicationSender(lp,clock=lambda:100,vault=vault(),witness=w,witness_fault=fault)
    tick(l,fault)
    raise RuntimeError('cut not reached')


class AtomicPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpbase=tempfile.TemporaryDirectory();p=Path(cls.tmpbase.name)
        cls.template=p/'db';cls.wtemplate=p/'w'
        w=ReferenceWitness(cls.wtemplate);l=setup(AtomicPublicationSender.create(cls.template,clock=lambda:100,vault=vault(),witness=w))
        l.close();w.close()

    @classmethod
    def tearDownClass(cls):cls.tmpbase.cleanup()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.lp=self.root/'db';self.wp=self.root/'w'
        shutil.copyfile(self.template,self.lp);shutil.copyfile(self.wtemplate,self.wp)
        self.w=ReferenceWitness(self.wp);self.now=100
        self.l=AtomicPublicationSender(self.lp,clock=lambda:self.now,vault=vault(),witness=self.w)
        self.c,self.s,self.k=context();self.h=r.context_hash(self.c)

    def tearDown(self):self.l.close();self.w.close();self.tmp.cleanup()

    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()

    def decisions(self):return self.l.decisions_internal('t','domain')

    def ready_count(self):
        register(self.l,'c',False)
        while self.l.db.execute("SELECT pc FROM jobs WHERE operation_id='c'").fetchone()[0]<84:tick(self.l)

    def test_registration_requires_fresh_immutable_public_route_binding(self):
        w=ReferenceWitness(self.root/'w2');l=setup(AtomicPublicationSender.create(self.root/'d2',clock=lambda:100,vault=vault(),witness=w),False)
        try:
            self.reject('PUBLICATION_BINDING_REQUIRED',lambda:register(l,'c',False))
            self.assertEqual(l.db.execute('SELECT count(*) FROM operations').fetchone()[0],0)
            l.bind_root_delivery('t','root',self.h);register(l,'c',False)
            self.reject('PUBLICATION_BINDING_IMMUTABLE',lambda:l.bind_root_delivery('t','root',self.h,30))
        finally:l.close();w.close()

    def test_direct_l3_and_unguarded_core_cannot_bypass_publisher(self):
        self.reject('ATOMIC_PUBLISHER_REQUIRED',lambda:self.l.admit_v2(self.h,'x','c'))
        self.reject('V2_TRANSACTION_REQUIRED',lambda:self.l._admit_v2_tx(self.h,'x','c'))
        self.l.db.execute('BEGIN')
        try:self.reject('V2_TRANSACTION_REQUIRED',lambda:self.l._admit_v2_tx(self.h,'x','c'))
        finally:self.l.db.rollback()

    def test_count_final_tick_commits_result_charges_decision_and_outbox_once(self):
        self.ready_count();self.assertEqual(self.decisions(),[])
        before=self.w.head(self.l.namespace)['seq'];tick(self.l)
        self.assertEqual(self.w.head(self.l.namespace)['seq'],before+1)
        decision=self.decisions()[0];self.assertEqual(decision['kind'],'ADMITTED');self.assertEqual(decision['tick'],85)
        self.assertEqual(self.l.ticket(self.l.outbox('t',decision['delivery_id']))['operation_id'],'c')
        self.assertEqual(self.l.op('t','c')['state'],'COMMITTED')
        self.assertEqual(self.l.db.execute("SELECT spent FROM accounts WHERE id='domain:epsilon'").fetchone()[0],E)
        self.l.advance('t','domain','tick84',84)
        self.assertEqual(len(self.decisions()),1);self.assertEqual(self.l.audit(),[])

    def test_mixed_order_publishes_two_decisions_in_same_final_transaction(self):
        register(self.l,'h',True);register(self.l,'c',False);finish(self.l)
        decisions=self.decisions()
        self.assertEqual([x['operation_id'] for x in decisions],['h','c'])
        self.assertEqual(decisions[0]['tick'],decisions[1]['tick'])
        self.assertEqual([x['kind'] for x in decisions],['ADMITTED','ADMITTED'])
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM v2_outbox').fetchone()[0],2)
        self.assertEqual(self.l.audit(),[])

    def test_prestart_cancel_records_withheld_and_refund_without_ticket(self):
        register(self.l,'c',False)
        n=self.l.db.execute('SELECT tick FROM schedulers').fetchone()[0]
        self.l.advance('t','domain','cancel',n,dict(kind='cancel',operation='c',actor='leaf'))
        finish(self.l)
        self.assertEqual(self.decisions()[0]['kind'],'WITHHELD')
        self.assertIsNone(self.decisions()[0]['delivery_id'])
        self.assertEqual(self.l.op('t','c')['state'],'CANCELED')
        self.assertEqual(self.l.db.execute("SELECT spent FROM accounts WHERE id='domain:epsilon'").fetchone()[0],0)
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM v2_outbox').fetchone()[0],0)
        self.assertEqual(self.l.audit(),[])

    def test_poststart_credential_revoke_withholds_without_refund(self):
        register(self.l,'c',False);tick(self.l);self.l.revoke_credential('t','workergrant',root_id='root',kind='delegation',issuer_kid=b'manager');finish(self.l)
        self.assertEqual(self.decisions()[0]['kind'],'WITHHELD')
        self.assertEqual(self.l.op('t','c')['state'],'COMMITTED')
        self.assertEqual(self.l.db.execute("SELECT spent FROM accounts WHERE id='domain:epsilon'").fetchone()[0],E)
        self.assertEqual(self.l.audit(),[])

    def test_route_revoked_between_registration_and_publication_withholds(self):
        register(self.l,'c',False);tick(self.l);self.l.revoke_context(self.h);finish(self.l)
        self.assertEqual(self.decisions()[0]['kind'],'WITHHELD')
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM deliveries').fetchone()[0],0)
        self.assertEqual(self.l.audit(),[])

    def test_expired_action_produces_withheld_not_an_unhandled_L3_error(self):
        register(self.l,'c',False);tick(self.l);self.now=900;finish(self.l)
        self.assertEqual(self.decisions()[0]['kind'],'WITHHELD');self.assertEqual(self.l.audit(),[])

    def test_unknown_internal_failure_rolls_back_instead_of_becoming_withheld(self):
        self.ready_count();before=self.l.state_image()
        with patch.object(self.l,'_admit_v2_tx',side_effect=Rejected('INJECTED_STORAGE_FAILURE')):
            self.reject('INJECTED_STORAGE_FAILURE',lambda:tick(self.l))
        self.assertEqual(self.l.state_image(),before)
        self.assertEqual(self.decisions(),[]);self.assertEqual(self.l.op('t','c')['state'],'STARTED')
        tick(self.l);self.assertEqual(self.decisions()[0]['kind'],'ADMITTED')

    def test_reply_loss_after_witness_acceptance_restores_complete_decision(self):
        self.ready_count()
        def fault(p):
            if p=='after_witness_accept':raise ConnectionError('lost')
        self.l.witness_fault=fault
        with self.assertRaises(ConnectionError):tick(self.l)
        self.l.witness_fault=lambda p:None
        self.assertEqual(self.decisions(),[])
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:tick(self.l))
        with patch.object(self.l,'publish',side_effect=AssertionError('republish')),patch.object(self.l,'operation_randomness',side_effect=AssertionError('resample')):
            self.l.recover_from_witness();self.l.advance('t','domain','tick84',84)
        self.assertEqual(len(self.decisions()),1);self.assertEqual(self.l.audit(),[])

    def test_restore_rejects_authority_image_missing_decision(self):
        self.ready_count();tick(self.l)
        with self.l.tx():self.l.db.execute('DELETE FROM pub_decisions')
        self.assertEqual(self.l.audit_v2(),[]);self.l.audit_contributions()
        self.reject('PUBLICATION_AUDIT_FAILED',lambda:AtomicPublicationSender.restore_new(self.root/'restored',clock=lambda:100,vault=vault(),witness=self.w))

    def test_admitted_output_uses_existing_recipient_evidence_and_no_new_l3(self):
        self.ready_count();tick(self.l);decision=self.decisions()[0]
        self.l.revoke_credential('t','workergrant',root_id='root',kind='delegation',issuer_kid=b'manager')
        env=self.l.prepare_envelope('t',decision['delivery_id'],self.s)
        w=ReferenceWitness(self.root/'rw');i=RetentionRecipient.create(self.root/'inbox',context=self.c,vault=recipient_vault(),clock=lambda:100,witness=w)
        try:
            req=d.attempt('DELIVERY',env,b'q'*32,self.c,self.s);ack=i.accept(req,self.c['sender_cert'],self.k)
            self.assertEqual(self.l.confirm('t',decision['delivery_id'],req,ack),'ACCEPTED')
            self.assertEqual(len(self.decisions()),1);self.assertEqual(self.l.audit(),[]);self.assertEqual(i.audit(),[])
        finally:i.close();w.close()

    def test_distinct_profile_and_authenticated_variant_requirements(self):
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:ContributionRetentionSender(self.lp,clock=lambda:100,vault=vault(),witness=self.w))
        self.reject('AUTHENTICATED_WITNESS_REQUIRED',lambda:TLSAtomicPublicationSender(self.lp,clock=lambda:100,vault=vault(),witness=self.w))

    def test_authenticated_witness_atomically_accepts_new_profile(self):
        folder=self.root/'tls';folder.mkdir();certs=certificates(folder);key=Ed25519PrivateKey.generate()
        wp=folder/'witness';trusted_register_peer(wp,vault().deployment_id.hex(),certificate_fingerprint(certs['admin'][0]),'admin')
        with WitnessTLSService(wp,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signing_key=key) as service:
            client=TLSWitnessClient(port=service.port,cafile=certs['ca'],certfile=certs['admin'][0],keyfile=certs['admin'][1],witness_public_key=public(key))
            calls=[0];exchange=client.exchange
            def counted(raw,body):calls[0]+=1;return exchange(raw,body)
            client.exchange=counted
            l=setup(TLSAtomicPublicationSender.create(folder/'sender',clock=lambda:100,vault=vault(),witness=client))
            try:
                register(l,'c',False);finish(l)
                self.assertEqual(l.decisions_internal('t','domain')[0]['kind'],'ADMITTED')
                self.assertEqual(l.audit(),[])
                restored=TLSAtomicPublicationSender.restore_new(folder/'restored',clock=lambda:100,vault=vault(),witness=client)
                try:self.assertEqual(restored.state_image(),l.state_image());self.assertEqual(restored.audit(),[])
                finally:restored.close()
                NETWORK.update(witness_requests=calls[0],tls_version=client.last_tls_version,
                    scope='Atomic count publication and fresh restore over actual loopback authenticated witness; no new public gateway or network result receiver.')
            finally:l.close()

    def test_actual_process_cuts_never_restore_half_decision(self):
        self.ready_count();self.l.close();self.w.close()
        snapshots=self.root/'before';witness=self.root/'before-w'
        shutil.copyfile(self.lp,snapshots);shutil.copyfile(self.wp,witness)
        self.w=ReferenceWitness(self.wp);self.l=AtomicPublicationSender(self.lp,clock=lambda:100,vault=vault(),witness=self.w)
        cases=[('after_scheduled_result_write',False),('after_publication_write',False),('after_v2_ticket_write',False),
               ('before_public_decision_write',False),('after_public_decision_write',False),
               ('after_witness_accept',True),('after_local_anchor_write',True),('after_tick_commit',True)]
        for point,durable in cases:
            with tempfile.TemporaryDirectory() as td:
                lp=Path(td)/'db';wp=Path(td)/'w';shutil.copyfile(snapshots,lp);shutil.copyfile(witness,wp)
                proc=subprocess.run([sys.executable,__file__,'--child',str(lp),str(wp),point],capture_output=True,text=True,timeout=30)
                self.assertEqual(proc.returncode,94,proc.stderr)
                w=ReferenceWitness(wp);l=AtomicPublicationSender(lp,clock=lambda:100,vault=vault(),witness=w)
                try:
                    l.recover_from_witness()
                    for table in ('pub_decisions','deliveries','v2_requests','v2_outbox'):
                        self.assertEqual(l.db.execute('SELECT count(*) FROM '+table).fetchone()[0],int(durable))
                    self.assertEqual(l.op('t','c')['state'],'COMMITTED' if durable else 'STARTED')
                    self.assertEqual(l.audit(),[])
                    if not durable:tick(l)
                    else:l.advance('t','domain','tick84',84)
                    self.assertEqual(len(l.decisions_internal('t','domain')),1)
                finally:l.close();w.close()
                CUTS.append(dict(decision='ADMITTED',point=point))

    def test_withheld_process_cuts_preserve_no_ticket_decision(self):
        self.ready_count();self.l.revoke_context(self.h);self.l.close();self.w.close()
        snapshot=self.root/'withheld-before';witness=self.root/'withheld-w'
        shutil.copyfile(self.lp,snapshot);shutil.copyfile(self.wp,witness)
        self.w=ReferenceWitness(self.wp);self.l=AtomicPublicationSender(self.lp,clock=lambda:100,vault=vault(),witness=self.w)
        for point,durable in [('after_public_decision_write',False),('after_witness_accept',True)]:
            with tempfile.TemporaryDirectory() as td:
                lp=Path(td)/'db';wp=Path(td)/'w';shutil.copyfile(snapshot,lp);shutil.copyfile(witness,wp)
                proc=subprocess.run([sys.executable,__file__,'--child',str(lp),str(wp),point],capture_output=True,text=True,timeout=30)
                self.assertEqual(proc.returncode,94,proc.stderr)
                w=ReferenceWitness(wp);l=AtomicPublicationSender(lp,clock=lambda:100,vault=vault(),witness=w)
                try:
                    l.recover_from_witness()
                    self.assertEqual(len(l.decisions_internal('t','domain')),int(durable))
                    self.assertEqual(l.db.execute('SELECT count(*) FROM v2_outbox').fetchone()[0],0)
                    if not durable:tick(l)
                    self.assertEqual(l.decisions_internal('t','domain')[0]['kind'],'WITHHELD')
                    self.assertEqual(l.audit(),[])
                finally:l.close();w.close()
                CUTS.append(dict(decision='WITHHELD',point=point))


def source_hashes():
    pending=['test_atomic_publication.py'];seen={}
    while pending:
        name=pending.pop();path=HERE/name
        if not path.exists():path=HERE.parent/name
        key=str(path.relative_to(HERE.parent))
        if key in seen or not path.exists():continue
        raw=path.read_bytes();seen[key]=hashlib.sha256(raw).hexdigest()
        for node in ast.walk(ast.parse(raw)):
            mods=[x.name for x in node.names] if isinstance(node,ast.Import) else ([node.module] if isinstance(node,ast.ImportFrom) else [])
            pending.extend(mod.split('.')[0]+'.py' for mod in mods if mod)
    return seen


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':child(*sys.argv[2:]);raise SystemExit(1)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AtomicPublicationTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,actual_process_crash_scenarios=CUTS,
        crash_scenario_count=len(CUTS),source_sha256=source_hashes(),source_paths_relative_to='delivery root',
        network=NETWORK,
        scope='Actual atomic scheduled eligibility/L3/outbox/decision under local reference witness; existing recipient acceptance. No external public gateway or cross-route final frontier.')
    (HERE/'atomic_publication_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
