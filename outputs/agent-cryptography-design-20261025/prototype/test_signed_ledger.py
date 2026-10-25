import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from signed_ledger import SignedLedger, Rejected, AUDIENCE
from dp_ledger import MECHANISM, PROFILE, EPSILON_COST as E, DELTA_COST as D
from wire import encode,decode,sign1,verify_sign1,inspect_sign1,parse_action,action_digest,aad

# Public RFC 8032 section 7.1 test key, NEVER a deployment secret.
SEED=bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
PUB=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
SIG=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
KEY=Ed25519PrivateKey.from_private_bytes(SEED)
CRASHES=[]


def action(**changes):
    obj=dict(profile='count-direct-v1',tenant='t',operation='a',root='root',actor='agent',kid=b'k1',
             domain='domain',snapshot='snap',recipient='reader',mechanism=MECHANISM,accountant=PROFILE,
             epsilon_max=E,delta_max=D,not_before=0,deadline=900)
    obj.update(changes); return encode(obj)


def proof(raw,challenge,key=KEY,kid=b'k1',proof_id=b'p'*16,object_type='CountActionProof',**changes):
    obj=dict(profile='count-direct-v1',action_digest=hashlib.sha256(raw).digest(),proof_id=proof_id,**challenge)
    obj.update(changes)
    return sign1(encode(obj),kid,key,object_type)


def setup(path,role='instance'):
    l=SignedLedger.create(path,clock=lambda:100)
    l.provision_domain('t','domain',2,2*E,2*D)
    l.authorize_root('t','domain','root','agent','reader')
    l.install_snapshot('t','domain','snap',[0,1])
    l.install_key('t',b'k1','agent',role,PUB)
    return l


def finish(l):
    for i in range(84): l.advance('t','domain','tick'+str(i),i)


def child(path,point,packet):
    l=SignedLedger(path,clock=lambda:100)
    data=json.loads(Path(packet).read_text())
    def fault(p):
        if p==point: os._exit(94)
    l.register_signed(bytes.fromhex(data['action']),bytes.fromhex(data['proof']),fault)
    raise RuntimeError('fault not reached')


class WireTests(unittest.TestCase):
    def test_rfc8032_known_answer(self):
        self.assertEqual(KEY.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw),PUB)
        self.assertEqual(KEY.sign(b''),SIG)
        KEY.public_key().verify(SIG,b'')

    def test_literal_deterministic_cbor_vectors(self):
        cases=[(0,'00'),(23,'17'),(24,'1818'),(1000,'1903e8'),(-19,'32'),
               (b'k1','426b31'),('a','6161'),([1,2,3],'83010203'),
               ({10:0,100:0,-1:0,'z':0},'a40a001864002000617a00')]
        for value,wire in cases:
            self.assertEqual(encode(value).hex(),wire); self.assertEqual(decode(bytes.fromhex(wire)),value)

    def test_reject_noncanonical_and_unsupported_encodings(self):
        corpus=['1800','190017','1a00000100','1b0000000000010000','9f01ff','bf0101ff',
                'a201010102','a202010101','6100ff','61ff','f4','f5','f6','f9a000','c001',
                '8201','5bffffffffffffffff','a1810001','9800']
        for raw in corpus:
            with self.subTest(raw=raw),self.assertRaises(Rejected): decode(bytes.fromhex(raw))
        for raw in (b'\x81'*10+b'\x00',b'\x98\x81'+b'\x00'*129,b'\x00'*65537):
            with self.assertRaises(Rejected): decode(raw)

    def test_all_short_inputs_fail_closed_or_round_trip(self):
        for n in range(65536):
            raw=n.to_bytes(2,'big')
            try: value=decode(raw)
            except Rejected: continue
            self.assertEqual(encode(value),raw)

    def test_cose_context_and_signature_tampering(self):
        ch={'challenge':b'c'*32,'challenge_expiry':160,'audience':AUDIENCE}
        raw=action(); wire=proof(raw,ch)
        self.assertEqual(verify_sign1(wire,PUB)[1]['action_digest'],action_digest(raw))
        wrong=proof(raw,ch,object_type='Receipt')
        with self.assertRaisesRegex(Rejected,'INVALID_SIGNATURE'): verify_sign1(wrong,PUB)
        obj=decode(wire[1:])
        for i in range(64):
            changed=list(obj); sig=bytearray(obj[3]); sig[i]^=1; changed[3]=bytes(sig)
            with self.assertRaisesRegex(Rejected,'INVALID_SIGNATURE'): verify_sign1(b'\xd2'+encode(changed),PUB)

    def test_saved_golden_wire_vector(self):
        vector=json.loads(Path(__file__).with_name('wire_vectors.json').read_text())
        raw=bytes.fromhex(vector['action_cbor_hex'])
        wire=bytes.fromhex(vector['cose_sign1_hex'])
        kid,payload,signature,message=inspect_sign1(wire)
        self.assertEqual(verify_sign1(wire,PUB)[0],kid)
        self.assertEqual(action_digest(raw).hex(),vector['action_sha256_hex'])
        self.assertEqual(message.hex(),vector['sig_structure_cbor_hex'])
        self.assertEqual(KEY.sign(message),signature)
        self.assertEqual(sign1(payload,kid,KEY),wire)

    def test_cose_exact_headers_tag_and_schema(self):
        raw=action(); ch={'challenge':b'c'*32,'challenge_expiry':160,'audience':AUDIENCE}
        wire=proof(raw,ch); obj=decode(wire[1:])
        invalid=[wire[1:],b'\xd8\x12'+wire[1:]]
        for headers in ({1:-8,4:b'k1'},{1:-19},{1:-19,4:b'k1',2:[99]}):
            changed=list(obj); changed[0]=encode(headers); invalid.append(b'\xd2'+encode(changed))
        changed=list(obj); changed[1]={4:b'k1'}; invalid.append(b'\xd2'+encode(changed))
        for data in invalid:
            with self.assertRaises(Rejected): inspect_sign1(data)
        a=decode(raw); a['unknown']=1
        with self.assertRaisesRegex(Rejected,'INVALID_ACTION_SCHEMA'): parse_action(encode(a))


class SignedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'db'; self.l=setup(self.path)
    def tearDown(self):
        self.assertEqual(self.l.audit(),[]); self.l.close(); self.tmp.cleanup()
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'): call()
    def packet(self,raw=None,proof_id=b'p'*16):
        raw=action() if raw is None else raw
        ch=self.l.issue_challenge('t',b'k1')
        return raw,proof(raw,ch,proof_id=proof_id),ch
    def test_verified_registration_execution_and_ack(self):
        raw,p,ch=self.packet(); ack=self.l.register_signed(raw,p)
        self.assertEqual(ack,{'operation_id':'a','action_digest':hashlib.sha256(raw).hexdigest(),'registration':'REGISTERED'})
        finish(self.l); self.assertEqual(self.l.op('t','a')['state'],'COMMITTED')
        self.l.admit_delivery('t','a','reader','d','gw','session')
        self.assertEqual(len(self.l.emit('t','d','reader','gw','session')),8)

    def test_replay_rejected_but_new_proof_retries_same_action_once(self):
        raw,p,ch=self.packet(); ack=self.l.register_signed(raw,p)
        self.reject('PROOF_REPLAY',lambda:self.l.register_signed(raw,p))
        raw,p,ch=self.packet(raw,b'q'*16)
        self.assertEqual(self.l.register_signed(raw,p),ack)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],1)
        self.assertEqual(self.l.db.execute("SELECT reserved FROM accounts WHERE id='domain:delta'").fetchone()[0],D)

    def test_changed_wire_only_field_conflicts(self):
        raw,p,_=self.packet(); self.l.register_signed(raw,p)
        changed,p,ch=self.packet(action(deadline=800),b'q'*16)
        self.reject('WIRE_ACTION_CONFLICT',lambda:self.l.register_signed(changed,p))
        self.assertEqual(self.l.db.execute('SELECT used FROM challenges WHERE nonce=?',(ch['challenge'],)).fetchone()[0],0)

    def test_proof_action_audience_expiry_and_key_binding(self):
        raw,p,ch=self.packet()
        self.reject('PROOF_ACTION_BINDING',lambda:self.l.register_signed(action(deadline=800),p))
        self.reject('WRONG_AUDIENCE',lambda:self.l.register_signed(raw,proof(raw,ch,audience='other')))
        self.reject('CHALLENGE_BINDING',lambda:self.l.register_signed(raw,proof(raw,ch,challenge_expiry=159)))
        self.reject('KEY_BINDING',lambda:self.l.register_signed(raw,proof(raw,ch,kid=b'other')))
        self.l.clock=lambda:160
        self.reject('CHALLENGE_EXPIRED',lambda:self.l.register_signed(raw,p))

    def test_wrong_role_key_or_signature_rejected(self):
        raw,p,ch=self.packet()
        wrong=Ed25519PrivateKey.generate()
        self.reject('INVALID_SIGNATURE',lambda:self.l.register_signed(raw,proof(raw,ch,key=wrong)))
        receipt_pub=wrong.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.l.install_key('t',b'receipt','agent','receipt',receipt_pub)
        raw=action(kid=b'receipt'); ch=self.l.issue_challenge('t',b'receipt')
        self.reject('KEY_ROLE_OR_ACTOR',lambda:self.l.register_signed(raw,proof(raw,ch,kid=b'receipt',key=wrong)))

    def test_same_public_key_cannot_gain_another_role_or_actor(self):
        self.reject('KEY_ROLE_REUSE',lambda:self.l.install_key('t',b'root-key','agent','root',PUB))
        self.reject('KEY_ROLE_REUSE',lambda:self.l.install_key('t',b'other-agent','other','instance',PUB))

    def test_key_revocation_and_deadline_at_l1_l3(self):
        raw,p,_=self.packet(); self.l.register_signed(raw,p)
        self.l.revoke_key('t',b'k1'); finish(self.l)
        self.assertEqual(self.l.op('t','a')['state'],'CANCELED')
        self.assertEqual(self.l.db.execute('SELECT publication FROM jobs').fetchone()[0],'WITHHELD')
        self.reject('KEY_INACTIVE',lambda:self.l.issue_challenge('t',b'k1'))

    def test_deadline_bounds_ticket_and_blocks_new_l3(self):
        raw,p,_=self.packet(action(deadline=105)); self.l.register_signed(raw,p); finish(self.l)
        ticket=self.l.admit_delivery('t','a','reader','d','gw','session')
        self.assertEqual(ticket['expires_at'],105)
        self.l.clock=lambda:105
        self.reject('ACTION_OR_KEY_INACTIVE',lambda:self.l.admit_delivery('t','a','reader','new','gw','session'))
        self.reject('TICKET_EXPIRED',lambda:self.l.emit('t','d','reader','gw','session'))

    def test_unsigned_reserve_and_cost_change_rejected(self):
        self.reject('SIGNATURE_REQUIRED',lambda:self.l.reserve_count('t','a','root','reader','domain','snap','agent'))
        raw,p,_=self.packet(action(epsilon_max=E-1))
        self.reject('COST_LIMIT_MISMATCH',lambda:self.l.register_signed(raw,p))

    def test_failed_budget_does_not_consume_challenge(self):
        for i in range(2):
            raw,p,_=self.packet(action(operation=str(i)),bytes([i])*16); self.l.register_signed(raw,p)
        raw,p,ch=self.packet(action(operation='third'),b'z'*16)
        self.reject('BUDGET_EXHAUSTED',lambda:self.l.register_signed(raw,p))
        self.assertEqual(self.l.db.execute('SELECT used FROM challenges WHERE nonce=?',(ch['challenge'],)).fetchone()[0],0)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM signed_actions').fetchone()[0],2)

    def test_concurrent_proof_replay_has_one_winner(self):
        raw,p,_=self.packet(); gate=threading.Barrier(8)
        def attempt(_):
            l=SignedLedger(self.path,clock=lambda:100)
            try:
                gate.wait(); l.register_signed(raw,p); return 'accepted'
            except Rejected as e: return str(e)
            finally: l.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: outcomes=list(pool.map(attempt,range(8)))
        self.assertEqual(outcomes.count('accepted'),1); self.assertEqual(outcomes.count('PROOF_REPLAY'),7)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],1)

    def test_proof_id_reuse_with_fresh_nonce_is_rejected(self):
        raw,p,_=self.packet(); self.l.register_signed(raw,p)
        raw,p,ch=self.packet()
        self.reject('PROOF_REPLAY',lambda:self.l.register_signed(raw,p))
        self.assertEqual(self.l.db.execute('SELECT used FROM challenges WHERE nonce=?',(ch['challenge'],)).fetchone()[0],0)

    def test_action_expiry_before_l1_returns_both_dimensions(self):
        raw,p,_=self.packet(action(deadline=105)); self.l.register_signed(raw,p)
        self.l.clock=lambda:105; finish(self.l)
        self.assertEqual(self.l.op('t','a')['state'],'CANCELED')
        self.assertEqual(self.l.db.execute("SELECT free FROM accounts WHERE id='domain:delta'").fetchone()[0],2*D)

    def test_revoked_key_does_not_revoke_preexisting_l3_ticket(self):
        raw,p,_=self.packet(); self.l.register_signed(raw,p); finish(self.l)
        self.l.admit_delivery('t','a','reader','old','gw','session',ttl=5)
        self.l.revoke_key('t',b'k1')
        self.reject('ACTION_OR_KEY_INACTIVE',lambda:self.l.admit_delivery('t','a','reader','new','gw','session'))
        self.assertEqual(len(self.l.emit('t','old','reader','gw','session')),8)

    def test_audit_reverifies_saved_signature_after_key_revocation(self):
        raw,p,_=self.packet(); self.l.register_signed(raw,p)
        self.l.revoke_key('t',b'k1')
        self.assertEqual(self.l.audit(),[])
        self.l.db.execute('BEGIN IMMEDIATE')
        try:
            changed=p[:-1]+bytes([p[-1]^1])
            self.l.db.execute('UPDATE used_proofs SET proof_wire=?',(changed,))
            self.assertIn('ACCEPTED_PROOF_BINDING',self.l.audit())
        finally:
            self.l.db.rollback()

    def test_three_actual_admission_crash_cuts(self):
        for point in ('after_proof_consumption','before_reserve_commit','after_reserve_commit'):
            with self.subTest(point=point):
                path=Path(self.tmp.name)/point; l=setup(path); raw=action(); ch=l.issue_challenge('t',b'k1'); p=proof(raw,ch)
                packet=Path(self.tmp.name)/(point+'.json'); packet.write_text(json.dumps({'action':raw.hex(),'proof':p.hex()})); l.close()
                proc=subprocess.run([sys.executable,__file__,'--crash',str(path),point,str(packet)],capture_output=True,timeout=30)
                self.assertEqual(proc.returncode,94,proc.stderr.decode())
                l=SignedLedger(path,clock=lambda:100); self.assertEqual(l.audit(),[])
                committed=point=='after_reserve_commit'
                self.assertEqual(l.db.execute('SELECT used FROM challenges').fetchone()[0],int(committed))
                self.assertEqual(l.db.execute('SELECT COUNT(*) FROM signed_actions').fetchone()[0],int(committed))
                self.assertEqual(l.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],int(committed))
                if committed:
                    self.reject('PROOF_REPLAY',lambda:l.register_signed(raw,p))
                    ch=l.issue_challenge('t',b'k1'); p=proof(raw,ch,proof_id=b'q'*16)
                l.register_signed(raw,p); self.assertEqual(l.audit(),[]); l.close(); CRASHES.append(point)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash': child(sys.argv[2],sys.argv[3],sys.argv[4])
    else:
        suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in (WireTests,SignedTests)])
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        root=Path(__file__).resolve().parent
        report={'passed':result.wasSuccessful(),'test_methods':result.testsRun,'crash_cut_count':len(CRASHES),'actual_process_crash_cuts':CRASHES,
                'short_parser_inputs':65536,'signature_mutations':64,'cryptography_version':cryptography.__version__,
                'python_version':sys.version,'sqlite_version':sqlite3.sqlite_version,
                'source_sha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('wire.py','signed_ledger.py','test_signed_ledger.py','ledger.py','scheduled_ledger.py','dp_ledger.py','count_direct_v1.cddl','wire_vectors.json')},
                'failures':[(str(t),m) for t,m in result.failures],'errors':[(str(t),m) for t,m in result.errors],
                'scope':'Bounded CBOR/COSE direct-root count profile and transactional replay; no workload attestation, delegation or public transport authentication'}
        (root/'signed_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
        sys.exit(0 if result.wasSuccessful() else 1)
