"""Independent regressions for review F1/F2/D1; synthetic fixtures only.

Run with unittest discovery. This module never overwrites historical reports.
"""
import copy
import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

P = Path(__file__).resolve().parents[1] / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from public_gateway import PublicGatewayLedger, response, RESPONSE_TYPE, PROFILE
from test_public_gateway import configure, make_request, parse_reply, SERVER_KEY, SERVER_KID, PEER
from test_mixed_delegated_ledger import KEYS, chain_fixture, credential, packet, tick
from test_encrypted_mixed_ledger import vault
from test_retention_sender import context
from test_retention_recipient import recipient_vault
from test_witness_transport import public
from witnessed_ledger import ReferenceWitness
from retention_recipient import RetentionRecipient
from mixed_delegated_ledger import parse_mixed_credential
from public_trace_adapter import PublicTraceAdapter
from dp_ledger import EPSILON_COST as E, DELTA_COST as D
from wire import encode, sign1
from ledger import Rejected
import retention_delivery as delivery


def rechain(chain, root=None, ids=None):
    result = []
    for i, raw in enumerate(chain):
        obj = parse_mixed_credential(raw)
        if root:
            obj['root'] = root
            if i == 0: obj['id'] = root
        if ids and i in ids: obj['id'] = ids[i]
        obj['parent_digest'] = hashlib.sha256(result[-1]).digest() if result else b''
        result.append(credential(obj))
    return result


class GatewayFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.w = ReferenceWitness(self.root/'w')
        self.now = 100
        self.l = configure(PublicGatewayLedger.create(self.root/'db', clock=lambda:self.now, vault=vault(), witness=self.w))
        self.rid = 0
        self.timeline = []
    def tearDown(self):
        self.l.close(); self.w.close(); self.tmp.cleanup()
    def call(self, method, payload, actor='leaf'):
        self.rid += 1
        raw = make_request(method, payload, self.rid, actor, self.now)
        reply = self.l.handle_public(raw, PEER, SERVER_KEY)
        self.timeline.append(dict(kind='PUBLIC',at=self.now,peer=PEER.hex(),request=raw.hex(),response=reply.hex()))
        return parse_reply(reply, raw)
    def submit(self, chain, oid='a', root='root'):
        ch = self.call('CHALLENGE', {})['body']
        with patch.object(self.l, 'issue_challenge', return_value=ch):
            raw, proof = packet(self.l, chain, oid, False, root=root)
        return self.call('SUBMIT', dict(action=raw,proof=proof,chain=chain))
    def add_root(self):
        self.l.authorize_root('t','domain','victim_root','manager','reader',expires_at=1000)
        self.l.bind_root_authority('t','victim_root',b'authority')
        c,_,_=context()
        self.l.bind_root_delivery('t','victim_root',self.l.register_context(c))


class CredentialNamespaceTests(GatewayFixture):
    def test_child_cannot_squat_another_root_grant(self):
        self.add_root()
        a=rechain(chain_fixture(self.l),ids={2:'victim_root'})
        b=rechain(chain_fixture(self.l),root='victim_root')
        self.assertEqual(self.submit(a)['status'],'RECORDED')
        self.assertEqual(self.submit(b,'b','victim_root')['status'],'RECORDED')
        self.assertEqual(self.l.audit(),[])

    def test_other_root_with_independent_authority_cannot_be_squatted(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'independent victim authority fixture').digest())
        self.l.install_key('t',b'victim-authority','victim-authority','root',public(key))
        self.l.authorize_root('t','domain','victim_root','manager','reader',expires_at=1000)
        self.l.bind_root_authority('t','victim_root',b'victim-authority')
        c,_,_=context();self.l.bind_root_delivery('t','victim_root',self.l.register_context(c))
        a=rechain(chain_fixture(self.l),ids={2:'victim_root'})
        b=[]
        for i,raw in enumerate(rechain(chain_fixture(self.l),root='victim_root')):
            obj=parse_mixed_credential(raw)
            if i==0:obj.update(issuer='victim-authority',issuer_kid=b'victim-authority')
            obj['parent_digest']=hashlib.sha256(b[-1]).digest() if b else b''
            b.append(sign1(encode(obj),obj['issuer_kid'],key if i==0 else KEYS[obj['issuer']], 'MixedGrant' if i==0 else 'MixedDelegation'))
        self.assertEqual(self.submit(a)['status'],'RECORDED')
        self.assertEqual(self.submit(b,'b','victim_root')['status'],'RECORDED')
        self.assertEqual(self.l.audit(),[])

    def test_same_name_from_different_issuers_and_grant_isolated(self):
        a=rechain(chain_fixture(self.l),ids={1:'root',2:'root'})
        self.assertEqual(self.submit(a)['status'],'RECORDED')
        self.assertEqual(self.l.audit(),[])


class ResponseContractTests(unittest.TestCase):
    def signed(self, status, body, seq=1):
        raw=b'public test request'
        obj=dict(profile=PROFILE,deployment=vault().deployment_id,request_hash=hashlib.sha256(raw).digest(),status=status,body=body,sequence=seq)
        return sign1(encode(obj),SERVER_KID,SERVER_KEY,RESPONSE_TYPE),raw
    def check_response(self,status,body,seq=1):
        wire,raw=self.signed(status,body,seq)
        return response(wire,raw,public(SERVER_KEY),SERVER_KID,vault().deployment_id)
    def test_wrong_audience_is_rejected(self):
        with self.assertRaises(Rejected):
            self.check_response('CHALLENGE',dict(challenge=b'C'*32,challenge_expiry=160,audience='other-gateway-v1'))
    def test_journal_sequence_is_sqlite_bounded(self):
        with self.assertRaises(Rejected):self.check_response('REJECTED',{},2**63)



class ScopedRevocationTests(GatewayFixture):
    def test_cross_root_identical_leaf_names_and_scoped_pre_revocation(self):
        self.add_root()
        a=chain_fixture(self.l);b=rechain(a,root='victim_root')
        self.l.revoke_credential('t','leafgrant',root_id='root',kind='delegation',issuer_kid=b'worker')
        self.assertEqual(self.submit(a)['status'],'REJECTED')
        self.assertEqual(self.submit(b,'b','victim_root')['status'],'RECORDED')
        self.assertEqual(self.l.audit(),[])

    def test_issuer_scoped_tombstone_does_not_revoke_other_issuer(self):
        a=chain_fixture(self.l)
        self.l.revoke_credential('t','leafgrant',root_id='root',kind='delegation',issuer_kid=b'manager')
        self.assertEqual(self.submit(a)['status'],'RECORDED')
        self.l.revoke_credential('t','leafgrant',root_id='root',kind='delegation',issuer_kid=b'worker')
        self.assertEqual(self.submit(a,'b')['status'],'REJECTED')
        self.assertEqual(self.l.audit(),[])

    def test_same_identity_cannot_replace_content(self):
        a=chain_fixture(self.l)
        self.assertEqual(self.submit(a)['status'],'RECORDED')
        b=list(a);obj=parse_mixed_credential(b[-1]);obj['epsilon_cap']-=E;b[-1]=credential(obj)
        self.assertEqual(self.submit(b,'b')['status'],'REJECTED')
        self.assertEqual(self.l.stored_chain('t','a'),a)
        self.assertEqual(self.l.audit(),[])

    def test_new_issuer_key_does_not_reset_shared_ancestor_budget(self):
        # Rotation is a new immutable key ID, not an overwrite of an old record.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        fresh=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'review fixture rotation').digest())
        self.l.install_key('t',b'worker2','worker','instance',public(fresh))
        a=chain_fixture(self.l,root_cap=1,child_cap=1)
        self.assertEqual(self.submit(a)['status'],'RECORDED')
        b=[]
        for i,raw in enumerate(a):
            obj=parse_mixed_credential(raw)
            if i==1:obj.update(id='rotated-worker',subject_kid=b'worker2')
            if i==2:obj['issuer_kid']=b'worker2'
            obj['parent_digest']=hashlib.sha256(b[-1]).digest() if b else b''
            b.append(sign1(encode(obj),obj['issuer_kid'],fresh if i==2 else KEYS[obj['issuer']], 'MixedGrant' if i==0 else 'MixedDelegation'))
        self.assertEqual(self.submit(b,'b')['status'],'REJECTED')
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM operations').fetchone()[0],1)

    def test_restore_preserves_scoped_revocations_chains_and_accounts(self):
        self.add_root();a=chain_fixture(self.l);b=rechain(a,root='victim_root')
        self.assertEqual(self.submit(a)['status'],'RECORDED')
        self.assertEqual(self.submit(b,'b','victim_root')['status'],'RECORDED')
        self.l.revoke_credential('t','leafgrant',root_id='root',kind='delegation',issuer_kid=b'worker')
        before=[tuple(x) for x in self.l.db.execute('SELECT * FROM accounts ORDER BY tenant,id')]
        restored=PublicGatewayLedger.restore_new(self.root/'restored',clock=lambda:self.now,vault=vault(),witness=self.w)
        self.l.close();self.l=restored
        self.assertEqual(self.l.stored_chain('t','a'),a)
        self.assertEqual(self.l.stored_chain('t','b'),b)
        self.assertEqual([tuple(x) for x in self.l.db.execute('SELECT * FROM accounts ORDER BY tenant,id')],before)
        with self.l.tx():
            self.assertFalse(self.l.authorization_active(self.l.op('t','a')))
            self.assertTrue(self.l.authorization_active(self.l.op('t','b')))
        self.assertEqual(self.l.audit(),[])

    def test_historical_identity_tampering_is_detected(self):
        self.assertEqual(self.submit(chain_fixture(self.l))['status'],'RECORDED')
        # Deliberate privileged corruption; ensure even an accepted witness image
        # with a false index cannot silently detach chain identity during restore.
        with self.l.tx():
            self.l.db.execute("UPDATE credentials SET id='forged' WHERE id='leafgrant'")
        self.assertIn('CREDENTIAL_STORAGE_BINDING',self.l.audit())
        with self.assertRaisesRegex(Rejected,'RECOVERY_AUDIT_FAILED'):
            PublicGatewayLedger.restore_new(self.root/'badrestore',clock=lambda:100,vault=vault(),witness=self.w)

    def test_legacy_namespace_schema_is_rejected_without_migration(self):
        from delegated_ledger import DelegatedLedger
        from test_delegated_ledger import setup
        old=setup(self.root/'legacy');old.close()
        db=sqlite3.connect(self.root/'legacy')
        db.executescript('DROP TABLE credentials; CREATE TABLE credentials (tenant TEXT, id TEXT, digest BLOB, wire BLOB, revoked INTEGER, PRIMARY KEY(tenant,id));')
        db.close()
        with self.assertRaisesRegex(Rejected,'CREDENTIAL_NAMESPACE_SCHEMA_MISMATCH'):
            DelegatedLedger(self.root/'legacy',clock=lambda:100)


class AdapterExpiryTests(unittest.TestCase):
    def fixture(self, expiring=None, final_at=100):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);p=Path(td.name)
        w=ReferenceWitness(p/'w');self.addCleanup(w.close)
        now=[100]; l=PublicGatewayLedger.create(p/'db',clock=lambda:now[0],vault=vault(),witness=w);self.addCleanup(l.close)
        install=l.install_key
        def install_fixture(tenant,kid,*args,**kwargs):
            if kid==expiring:kwargs['expires_at']=110
            return install(tenant,kid,*args,**kwargs)
        with patch.object(l,'install_key',side_effect=install_fixture):configure(l)
        c,s,k=context()
        # All registry values below are explicit public fixture parameters.
        config=dict(tenant='t',domain='domain',deployment=vault().deployment_id,gateway_key=public(SERVER_KEY),gateway_kid=SERVER_KID,
            keys={name.encode():dict(actor=name,role='root' if name=='authority' else 'instance',public_key=public(key),not_before=0,expires_at=110 if name.encode()==expiring else 2**62) for name,key in KEYS.items()},
            principals={b'leaf':dict(certificate=PEER,rights=['challenge','submit','poll','final','cancel'])},
            roots={'root':dict(actor='manager',recipient='reader',authority=b'authority',expires_at=1000,ttl=60,context=c)},
            capacity=3,catalogs={},snapshots={'count':dict(kind='count')},epsilon_limit=4*E,delta_limit=4*D)
        records=[];rid=[0]
        def call(method,payload):
            rid[0]+=1;raw=make_request(method,payload,rid[0],now=now[0]);reply=l.handle_public(raw,PEER,SERVER_KEY)
            records.append(dict(kind='PUBLIC',at=now[0],peer=PEER.hex(),request=raw.hex(),response=reply.hex()))
            return parse_reply(reply,raw)
        ch=call('CHALLENGE',{})['body'];chain=chain_fixture(l)
        with patch.object(l,'issue_challenge',return_value=ch):raw,proof=packet(l,chain,'a',False)
        self.assertEqual(call('SUBMIT',dict(action=raw,proof=proof,chain=chain))['status'],'RECORDED')
        with patch.object(l,'operation_randomness',return_value=bytes(32)):
            for i in range(85):
                if i==84:now[0]=final_at
                tick(l);records.append(dict(kind='TICK',at=now[0],tick=i+1))
        decision=l.decisions_internal('t','domain')[0];expiry=None
        if decision['kind']=='ADMITTED':
            env=l.prepare_envelope('t',decision['delivery_id'],s)
            expiry=delivery.parse_descriptor(delivery.parse_envelope(env,c)['descriptor'],c)['expires_at']
            req=delivery.attempt('DELIVERY',env,b'R'*32,c,s)
            rw=ReferenceWitness(p/'rw');self.addCleanup(rw.close)
            inbox=RetentionRecipient.create(p/'inbox',context=c,vault=recipient_vault(),clock=lambda:now[0],witness=rw);self.addCleanup(inbox.close)
            ack=inbox.accept(req,c['sender_cert'],k)
            event=dict(at=now[0],request=req.hex(),response=ack.hex())
            records.append(dict(kind='DELIVERY',**event));l.confirm('t',decision['delivery_id'],req,ack);records.append(dict(kind='CONFIRM',**event))
        call('FINAL',dict(cursor=0,limit=16))
        self.assertEqual(l.audit(),[])
        return config,records,expiry

    def test_real_delivery_trace_includes_all_ancestor_key_expiries(self):
        for kid in (None,b'authority',b'manager',b'worker',b'leaf'):
            with self.subTest(kid=kid):
                cfg,records,expiry=self.fixture(kid)
                expected=160 if kid is None else 110
                self.assertEqual(expiry,expected)
                # Checking the trace must not open or inspect the runtime DB.
                with patch('sqlite3.connect',side_effect=AssertionError('DB access in checker')):
                    adapter=PublicTraceAdapter(cfg,{'a':(2,)})
                    result=adapter.check(records)
                self.assertTrue(result['accepted']);self.assertEqual(adapter.jobs[0]['expires_at'],expected)
                self.assertEqual(result['draws'],[('a','count')])
                self.assertEqual(result['final'][0]['outcome'],'ACCEPTED')

    def test_exact_ancestor_expiry_blocks_publication(self):
        for at,expected in ((109,'ACCEPTED'),(110,'WITHHELD')):
            with self.subTest(at=at):
                cfg,records,expiry=self.fixture(b'authority',at)
                result=PublicTraceAdapter(cfg,{'a':(2,)}).check(records)
                self.assertEqual(result['final'][0]['outcome'],expected)
                self.assertEqual(expiry,110 if at==109 else None)

class ResponseVectorTests(unittest.TestCase):
    def test_signed_conformance_vectors(self):
        import json
        fixture=json.loads((Path(__file__).parent/'vectors/public-responses.json').read_text())
        for v in fixture['vectors']:
            with self.subTest(name=v['name']):
                args=(bytes.fromhex(v['response_hex']),bytes.fromhex(fixture['request_hex']),bytes.fromhex(fixture['gateway_key_hex']),bytes.fromhex(fixture['gateway_kid_hex']),bytes.fromhex(fixture['deployment_hex']))
                if v['accepted']:response(*args)
                else:
                    with self.assertRaises(Rejected):response(*args)

if __name__=='__main__':unittest.main()
