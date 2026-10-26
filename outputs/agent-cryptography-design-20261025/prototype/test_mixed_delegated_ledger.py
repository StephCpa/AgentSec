import concurrent.futures
from copy import deepcopy
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mixed_delegated_ledger import MixedDelegatedLedger,parse_mixed_action,parse_mixed_credential,PROFILE,CHAIN_PROFILE,COUNT_CODEC
from histogram_ledger import HistogramLedger,COUNT,HISTOGRAM,CODEC
from delegated_ledger import DelegatedLedger,cap_accounts
from dp_ledger import PROFILE as ACCOUNTANT,EPSILON_COST as E,DELTA_COST as D
from wire import encode,decode,sign1
from ledger import Rejected

KEYS={n:Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('mixed-fixture:'+n).encode()).digest()) for n in ('authority','manager','worker','leaf','other')}
CRASHES=[]


def setup(path):
    l=MixedDelegatedLedger.create(path,clock=lambda:100)
    l.provision_domain('t','domain',3,4*E,4*D)
    l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
    l.install_catalog('t','domain','cat',['one','two','three','four'])
    l.install_catalog('t','domain','reverse',['four','three','two','one'])
    l.install_histogram_snapshot('t','domain','hist','cat',[1,2,0])
    l.install_histogram_snapshot('t','domain','reverse','reverse',[4,3,0])
    l.install_snapshot('t','domain','count',[1,1,0])
    for name,key in KEYS.items():
        l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',
                      key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
    l.bind_root_authority('t','root',b'authority');return l


def credential(obj,object_type=None):
    return sign1(encode(obj),obj['issuer_kid'],KEYS[obj['issuer']],object_type or ('MixedGrant' if obj['kind']=='grant' else 'MixedDelegation'))


def chain_fixture(l,root_cap=3,child_cap=3,leaf_id='leafgrant',subject='leaf',policy=None):
    if policy is None:
        policy=dict(domain='domain',snapshots=['count','hist'],recipients=['reader'],mechanisms=sorted([COUNT,HISTOGRAM]),
                    operations=['count','histogram'],accountant=ACCOUNTANT,accounts=dict(epsilon='domain:epsilon',delta='domain:delta'),
                    catalogs={'cat':bytes.fromhex(l.catalog('t','domain','cat')['digest'])})
    root=dict(profile=CHAIN_PROFILE,kind='grant',id='root',tenant='t',root='root',issuer='authority',issuer_kid=b'authority',
              subject='manager',subject_kid=b'manager',parent_digest=b'',depth=0,max_depth=3,not_before=0,expires_at=900,
              policy=deepcopy(policy),epsilon_cap=root_cap*E,delta_cap=root_cap*D)
    wires=[credential(root)];child=deepcopy(root)
    child.update(kind='delegation',id='workergrant',issuer='manager',issuer_kid=b'manager',subject='worker',subject_kid=b'worker',
                 parent_digest=hashlib.sha256(wires[-1]).digest(),depth=1,epsilon_cap=child_cap*E,delta_cap=child_cap*D)
    wires.append(credential(child));leaf=deepcopy(child)
    leaf.update(id=leaf_id,issuer='worker',issuer_kid=b'worker',subject=subject,subject_kid=subject.encode(),depth=2,
                parent_digest=hashlib.sha256(wires[-1]).digest())
    wires.append(credential(leaf));return wires


def mutate_leaf(chain,**changes):
    out=list(chain);obj=parse_mixed_credential(out[-1]);obj.update(changes);out[-1]=credential(obj);return out


def packet(l,chain,oid='a',hist=True,proof_id=None,**changes):
    leaf=parse_mixed_credential(chain[-1]);kid=leaf['subject_kid']
    obj=dict(profile=PROFILE,tenant='t',operation=oid,root='root',actor=leaf['subject'],kid=kid,domain='domain',
             snapshot='hist' if hist else 'count',recipient='reader',mechanism=HISTOGRAM if hist else COUNT,
             accountant=ACCOUNTANT,epsilon_max=E,delta_max=D,not_before=0,deadline=900,
             leaf_digest=hashlib.sha256(chain[-1]).digest(),operation_kind='histogram' if hist else 'count',
             capacity=3,k=40,codec=CODEC if hist else COUNT_CODEC)
    if hist:obj.update(catalog='cat',catalog_digest=bytes.fromhex(l.catalog('t','domain','cat')['digest']),bucket_count=4)
    obj.update(changes);raw=encode(obj);ch=l.issue_challenge('t',obj['kid'])
    proof=dict(profile=PROFILE,action_digest=hashlib.sha256(raw).digest(),proof_id=proof_id or os.urandom(16),**ch)
    return raw,sign1(encode(proof),obj['kid'],KEYS[obj['kid'].decode()],'MixedActionProof')


def tick(l,fault=lambda p:None):
    n=l.db.execute('SELECT tick FROM schedulers').fetchone()[0]
    return l.advance('t','domain','tick'+str(n),n,fault=fault)


def finish(l):
    while l.db.execute('SELECT 1 FROM jobs WHERE publication IS NULL').fetchone():tick(l)


def child(path,point,packet_path):
    l=MixedDelegatedLedger(path,clock=lambda:100);data=json.loads(Path(packet_path).read_text())
    def fault(p):
        if p==point:os._exit(96)
    if data['mode']=='tick':tick(l,fault)
    else:l.register_delegated(bytes.fromhex(data['action']),bytes.fromhex(data['proof']),[bytes.fromhex(x) for x in data['chain']],fault)
    raise RuntimeError('cut not reached')


class MixedDelegationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'db';self.l=setup(self.path);self.chain=chain_fixture(self.l)
    def tearDown(self):
        self.assertEqual(self.l.audit(),[]);self.l.close();self.tmp.cleanup()
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'):call()
    def register(self,chain=None,oid='a',hist=True,**changes):
        chain=self.chain if chain is None else chain
        return self.l.register_delegated(*packet(self.l,chain,oid,hist,**changes),chain)
    def assert_spent(self,chain,units):
        for account,cost in [('domain:epsilon',E),('domain:delta',D)]+[(a,c) for w in chain for a,c in zip(cap_accounts(w),(E,D))]:
            row=self.l.db.execute('SELECT spent,reserved FROM accounts WHERE id=?',(account,)).fetchone()
            self.assertEqual(tuple(row),(units*cost,0))

    def test_count_and_histogram_charge_same_domain_and_every_ancestor(self):
        self.register(hist=False);self.register(oid='h');finish(self.l);self.assert_spent(self.chain,2)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM charges').fetchone()[0],16)
        for oid,width in [('a',8),('h',32)]:
            self.assertEqual(self.l.op('t',oid)['result'],self.l.compute_internal('t',oid))
            self.l.admit_delivery('t',oid,'reader','ticket'+oid,'gateway','session')
            self.assertEqual(len(self.l.emit('t','ticket'+oid,'reader','gateway','session')),width)

    def test_count_spending_blocks_histogram_at_shared_intermediate_cap(self):
        self.chain=chain_fixture(self.l,root_cap=3,child_cap=1);self.register(hist=False);finish(self.l)
        fork=chain_fixture(self.l,root_cap=3,child_cap=1,leaf_id='othergrant',subject='other')
        raw,proof=packet(self.l,fork,'h');self.reject('BUDGET_EXHAUSTED',lambda:self.l.register_delegated(raw,proof,fork))
        self.assertEqual(self.l.db.execute("SELECT free FROM accounts WHERE id='domain:epsilon'").fetchone()[0],3*E)
        self.assertEqual(self.l.db.execute("SELECT COUNT(*) FROM credentials WHERE id='othergrant'").fetchone()[0],0)
        self.assertEqual(self.l.db.execute('SELECT used FROM challenges WHERE nonce=?',(decode(__import__('wire').inspect_sign1(proof)[1])['challenge'],)).fetchone()[0],0)

    def test_eight_sibling_mixed_requests_have_one_shared_cap_winner(self):
        chains=[chain_fixture(self.l,root_cap=1,child_cap=1,leaf_id='leaf'+str(i),subject='other' if i%2 else 'leaf') for i in range(8)]
        packets=[packet(self.l,c,'op'+str(i),bool(i%2)) for i,c in enumerate(chains)];gate=threading.Barrier(8)
        def attempt(i):
            l=MixedDelegatedLedger(self.path,clock=lambda:100)
            try:gate.wait();l.register_delegated(*packets[i],chains[i]);return 'ok'
            except Rejected as e:return str(e)
            finally:l.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(attempt,range(8)))
        self.assertEqual(results.count('ok'),1);self.assertEqual(results.count('BUDGET_EXHAUSTED'),7)
        finish(self.l);self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM credentials').fetchone()[0],3)
        self.assertEqual(self.l.db.execute("SELECT spent FROM accounts WHERE id='domain:epsilon'").fetchone()[0],E)

    def test_catalog_order_digest_and_new_catalog_cannot_widen_child(self):
        for catalogs in ({'cat':b'x'*32},{'cat':bytes.fromhex(self.l.catalog('t','domain','cat')['digest']),'reverse':bytes.fromhex(self.l.catalog('t','domain','reverse')['digest'])}):
            policy=deepcopy(parse_mixed_credential(self.chain[-1])['policy']);policy['catalogs']=catalogs
            chain=mutate_leaf(self.chain,policy=policy);raw,proof=packet(self.l,chain)
            self.reject('CATALOG_ATTENUATION',lambda:self.l.register_delegated(raw,proof,chain))

    def test_leaf_can_drop_histogram_or_catalog_scope_without_affecting_count(self):
        for field in ('operations','catalogs','mechanisms'):
            policy=deepcopy(parse_mixed_credential(self.chain[-1])['policy'])
            policy[field]={'operations':['count'],'catalogs':{},'mechanisms':[COUNT]}[field]
            chain=mutate_leaf(self.chain,policy=policy);raw,proof=packet(self.l,chain)
            self.reject('ACTION_CATALOG_OUTSIDE_LEAF' if field=='catalogs' else 'ACTION_OUTSIDE_LEAF',lambda:self.l.register_delegated(raw,proof,chain))
        self.chain=chain;self.register(hist=False);finish(self.l);self.assert_spent(chain,1)

    def test_registered_catalog_check_inside_transaction_rejects_invented_digest(self):
        policy=deepcopy(parse_mixed_credential(self.chain[0])['policy']);policy['catalogs']={'cat':b'x'*32}
        chain=chain_fixture(self.l,policy=policy);raw,proof=packet(self.l,chain,catalog_digest=b'x'*32)
        self.reject('SIGNED_CATALOG_MISMATCH',lambda:self.l.register_delegated(raw,proof,chain))
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM credentials').fetchone()[0],0)

    def test_signed_width_capacity_k_and_codec_are_bound(self):
        for key,value,code in [('bucket_count',3,'SIGNED_CATALOG_MISMATCH'),('capacity',4,'SIGNED_CAPACITY_MISMATCH'),
                               ('k',39,'MIXED_MECHANISM_BINDING'),('codec',COUNT_CODEC,'MIXED_MECHANISM_BINDING'),
                               ('mechanism',COUNT,'MIXED_MECHANISM_BINDING')]:
            raw,proof=packet(self.l,self.chain,**{key:value});self.reject(code,lambda:self.l.register_delegated(raw,proof,self.chain))
        raw,proof=packet(self.l,self.chain,hist=False,capacity=4)
        self.reject('SIGNED_CAPACITY_MISMATCH',lambda:self.l.register_delegated(raw,proof,self.chain))

    def test_valid_signature_cannot_swap_catalog_snapshot_or_action_body(self):
        policy=deepcopy(parse_mixed_credential(self.chain[0])['policy']);policy['snapshots']=['count','hist','reverse']
        self.chain=chain_fixture(self.l,policy=policy)
        raw,proof=packet(self.l,self.chain);obj=decode(raw);obj['operation']='substituted'
        self.reject('PROOF_ACTION_BINDING',lambda:self.l.register_delegated(encode(obj),proof,self.chain))
        raw,proof=packet(self.l,self.chain,snapshot='reverse')
        self.reject('SNAPSHOT_CATALOG_MISMATCH',lambda:self.l.register_delegated(raw,proof,self.chain))
        raw,proof=packet(self.l,self.chain,catalog='reverse',catalog_digest=bytes.fromhex(self.l.catalog('t','domain','reverse')['digest']),snapshot='reverse')
        self.reject('ACTION_CATALOG_OUTSIDE_LEAF',lambda:self.l.register_delegated(raw,proof,self.chain))

    def test_old_signature_domains_and_audience_cannot_cross_protocols(self):
        from wire import inspect_sign1
        raw,proof=packet(self.l,self.chain);obj=decode(inspect_sign1(proof)[1])
        wrong=sign1(encode(obj),b'leaf',KEYS['leaf'],'CountActionProof')
        self.reject('INVALID_SIGNATURE',lambda:self.l.register_delegated(raw,wrong,self.chain))
        obj['audience']='count-gateway-v1';wrong=sign1(encode(obj),b'leaf',KEYS['leaf'],'MixedActionProof')
        self.reject('WRONG_AUDIENCE',lambda:self.l.register_delegated(raw,wrong,self.chain))
        chain=list(self.chain);chain[-1]=credential(parse_mixed_credential(chain[-1]),'Delegation');raw,proof=packet(self.l,chain)
        self.reject('INVALID_SIGNATURE',lambda:self.l.register_delegated(raw,proof,chain))

    def test_raw_proof_replay_rejected_fresh_proof_retry_does_not_recharge(self):
        raw,proof=packet(self.l,self.chain);ack=self.l.register_delegated(raw,proof,self.chain)
        self.reject('PROOF_REPLAY',lambda:self.l.register_delegated(raw,proof,self.chain))
        self.assertEqual(self.register(),ack)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM charges').fetchone()[0],8)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM used_proofs').fetchone()[0],2)

    def test_same_operation_cannot_change_mechanism_or_credential_identity(self):
        self.register()
        raw,proof=packet(self.l,self.chain,hist=False)
        self.reject('WIRE_ACTION_CONFLICT',lambda:self.l.register_delegated(raw,proof,self.chain))
        changed=mutate_leaf(self.chain,epsilon_cap=E,delta_cap=D);raw,proof=packet(self.l,changed,'new')
        self.reject('CREDENTIAL_ID_CONFLICT',lambda:self.l.register_delegated(raw,proof,changed))

    def test_ancestor_revocation_before_start_refunds_every_account(self):
        self.register();self.l.revoke_credential('t','workergrant',root_id='root',kind='delegation',issuer_kid=b'manager');finish(self.l)
        self.assertEqual(self.l.op('t','a')['state'],'CANCELED')
        self.assertTrue(all(x[0]==0 for x in self.l.db.execute('SELECT reserved+spent FROM accounts')))
        self.assertEqual(self.l.db.execute('SELECT publication FROM jobs').fetchone()[0],'WITHHELD')

    def test_ancestor_revocation_after_start_withholds_vector_without_refund(self):
        self.register();tick(self.l);tape=self.l.op('t','a')['seed'];self.l.revoke_key('t',b'manager');finish(self.l)
        self.assertEqual(self.l.op('t','a')['seed'],tape);self.assertEqual(len(tape),40)
        self.assertEqual(self.l.db.execute('SELECT publication FROM jobs').fetchone()[0],'WITHHELD');self.assert_spent(self.chain,1)
        self.reject('PUBLICATION_PENDING_OR_WITHHELD',lambda:self.l.admit_delivery('t','a','reader','new','g','s'))

    def test_old_l3_ticket_survives_revocation_but_new_ticket_does_not(self):
        self.register();finish(self.l);self.l.admit_delivery('t','a','reader','old','g','s')
        self.l.revoke_credential('t','root',root_id='root',kind='grant',issuer_kid=b'authority')
        self.reject('ACTION_OR_KEY_INACTIVE',lambda:self.l.admit_delivery('t','a','reader','new','g','s'))
        self.assertEqual(len(self.l.emit('t','old','reader','g','s')),32)

    def test_root_authority_expiry_limits_vector_ticket(self):
        self.l.db.execute('UPDATE signing_keys SET expires_at=150 WHERE kid=?',(b'authority',))
        self.register();finish(self.l);ticket=self.l.admit_delivery('t','a','reader','d','g','s')
        self.assertEqual(ticket['expires_at'],150);self.l.clock=lambda:150
        self.reject('TICKET_EXPIRED',lambda:self.l.emit('t','d','reader','g','s'))

    def test_chain_scope_time_cap_parent_and_account_widening_rejected(self):
        for changes,code in [({'expires_at':901},'ATTENUATION_BOUNDS'),({'epsilon_cap':4*E},'ATTENUATION_BOUNDS'),
                             ({'delta_cap':4*D},'ATTENUATION_BOUNDS'),({'max_depth':4},'ATTENUATION_BOUNDS'),
                             ({'parent_digest':b'x'*32},'CHAIN_PARENT_BINDING')]:
            chain=mutate_leaf(self.chain,**changes);raw,proof=packet(self.l,chain)
            self.reject(code,lambda:self.l.register_delegated(raw,proof,chain))
        policy=deepcopy(parse_mixed_credential(self.chain[-1])['policy']);policy['accounts']['epsilon']='fresh:epsilon'
        chain=mutate_leaf(self.chain,policy=policy);raw,proof=packet(self.l,chain)
        self.reject('ACCOUNT_REBIND',lambda:self.l.register_delegated(raw,proof,chain))

    def test_unsigned_old_service_or_missing_chain_cannot_bypass_authorization(self):
        raw,proof=packet(self.l,self.chain)
        self.reject('CHAIN_REQUIRED',lambda:self.l.register_signed(raw,proof))
        self.reject('CHAIN_REQUIRED',lambda:self.l.reserve_histogram('t','bad','root','reader','domain','hist','cat','leaf'))
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:HistogramLedger(self.path))
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:DelegatedLedger(self.path))
        legacy=decode(raw);legacy['profile']='count-delegated-v1'
        self.reject('INVALID_MIXED_ACTION_SCHEMA',lambda:self.l.register_delegated(encode(legacy),proof,self.chain))

    def test_strict_closed_schema_and_catalog_policy_types(self):
        raw,_=packet(self.l,self.chain)
        for update in ({'unknown':1},{'bucket_count':0},{'bucket_count':65},{'catalog_digest':b'x'}):
            obj=decode(raw);obj.update(update)
            with self.assertRaises(Rejected):parse_mixed_action(encode(obj))
        for catalogs in ([],{'cat':b'x'}, {'bad:name':b'x'*32}):
            obj=parse_mixed_credential(self.chain[-1]);obj['policy']['catalogs']=catalogs
            with self.assertRaises(Rejected):parse_mixed_credential(credential(obj))
        obj=decode(raw);obj.pop('catalog')
        self.reject('INVALID_MIXED_ACTION_SCHEMA',lambda:parse_mixed_action(encode(obj)))

    def test_revocation_tombstone_blocks_unused_histogram_credential_after_restart(self):
        self.l.revoke_credential('t','workergrant',root_id='root',kind='delegation',issuer_kid=b'manager');self.l.close();self.l=MixedDelegatedLedger(self.path,clock=lambda:100)
        raw,proof=packet(self.l,self.chain)
        self.reject('CREDENTIAL_REVOKED',lambda:self.l.register_delegated(raw,proof,self.chain))

    def test_midvector_restart_retains_signatures_full_tape_and_ancestor_charges(self):
        self.register()
        for _ in range(169):tick(self.l)
        tape=self.l.op('t','a')['seed'];expected=self.l.compute_internal('t','a')
        self.l.close();self.l=MixedDelegatedLedger(self.path,clock=lambda:100);finish(self.l)
        self.assertEqual(self.l.op('t','a')['seed'],tape);self.assertEqual(self.l.op('t','a')['result'],expected);self.assert_spent(self.chain,1)

    def test_saved_wire_vectors_verify_signatures_profiles_and_parent_digests(self):
        from wire import verify_sign1
        v=json.loads(Path(__file__).with_name('mixed_delegation_vectors.json').read_text())
        self.assertEqual(v['chain_cose_hex'],[w.hex() for w in self.chain])
        for i,w in enumerate(self.chain):
            obj=parse_mixed_credential(w)
            verify_sign1(w,bytes.fromhex(v['public_keys_hex'][obj['issuer']]),'MixedGrant' if i==0 else 'MixedDelegation')
            self.assertEqual(hashlib.sha256(w).hexdigest(),v['credential_sha256'][i])
            if i:self.assertEqual(obj['parent_digest'],hashlib.sha256(self.chain[i-1]).digest())
        for item in v['packets']:
            raw=bytes.fromhex(item['action_cbor_hex']);action=parse_mixed_action(raw)
            kid,proof=verify_sign1(bytes.fromhex(item['proof_cose_hex']),bytes.fromhex(v['public_keys_hex']['leaf']),'MixedActionProof')
            self.assertEqual(kid,action['kid']);self.assertEqual(proof['action_digest'],hashlib.sha256(raw).digest())
            self.assertEqual(action['operation_kind'],item['kind']);self.assertEqual(action['leaf_digest'],hashlib.sha256(self.chain[-1]).digest())

    def test_eight_real_process_crash_cuts_cover_registration_and_vector_settlement(self):
        points=('after_proof_consumption','after_chain_registration','after_account_reserve','before_reserve_commit','after_reserve_commit',
                'after_scheduled_result_write','after_account_settle','after_tick_commit')
        for i,point in enumerate(points):
            with self.subTest(point=point):
                path=Path(self.tmp.name)/('crash'+str(i));l=setup(path);chain=chain_fixture(l);raw,proof=packet(l,chain)
                mode='tick' if i>=5 else 'register';tape=None
                if mode=='tick':
                    l.register_delegated(raw,proof,chain)
                    for _ in range(336):tick(l)
                    tape=l.op('t','a')['seed']
                data=dict(mode=mode,action=raw.hex(),proof=proof.hex(),chain=[w.hex() for w in chain]);pf=Path(self.tmp.name)/(str(i)+'.json');pf.write_text(json.dumps(data));l.close()
                proc=subprocess.run([sys.executable,__file__,'--crash',str(path),point,str(pf)],capture_output=True,timeout=30)
                self.assertEqual(proc.returncode,96,proc.stderr.decode());l=MixedDelegatedLedger(path,clock=lambda:100)
                try:
                    self.assertEqual(l.audit(),[]);self.assertEqual(l.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                    if mode=='register':
                        committed=point=='after_reserve_commit'
                        self.assertEqual(l.db.execute('SELECT COUNT(*) FROM accounts').fetchone()[0],8 if committed else 2)
                        self.assertEqual(l.db.execute('SELECT COUNT(*) FROM used_proofs').fetchone()[0],1 if committed else 0)
                        self.assertEqual(l.db.execute('SELECT COUNT(*) FROM credentials').fetchone()[0],3 if committed else 0)
                        if committed:raw,proof=packet(l,chain)
                        l.register_delegated(raw,proof,chain)
                    else:
                        self.assertEqual(l.op('t','a')['seed'],tape)
                        self.assertEqual(l.op('t','a')['state'],'COMMITTED' if point=='after_tick_commit' else 'STARTED')
                    finish(l);self.assertEqual(l.op('t','a')['result'],l.compute_internal('t','a'))
                    self.assertTrue(all(r[0]==E for r in l.db.execute("SELECT spent FROM accounts WHERE id LIKE '%:epsilon'")))
                    self.assertTrue(all(r[0]==D for r in l.db.execute("SELECT spent FROM accounts WHERE id LIKE '%:delta'")))
                    self.assertEqual(l.audit(),[])
                finally:l.close()
                CRASHES.append(point)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash':child(sys.argv[2],sys.argv[3],sys.argv[4])
    else:
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MixedDelegationTests));root=Path(__file__).resolve().parent
        names=('mixed_delegated_ledger.py','test_mixed_delegated_ledger.py','histogram_ledger.py','delegated_ledger.py','signed_ledger.py','scheduled_ledger.py','dp_ledger.py','ledger.py','wire.py','../histogram_kernel.py','../fixed_work_model.py','mixed_delegated_v1.cddl','mixed_delegation_vectors.json')
        report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,actual_process_crash_cuts=CRASHES,crash_cut_count=len(CRASHES),
                    source_sha256={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names},python_version=sys.version,sqlite_version=sqlite3.sqlite_version,
                    cryptography_version=__import__('cryptography').__version__,failures=[(str(t),m) for t,m in result.failures],errors=[(str(t),m) for t,m in result.errors],
                    scope='Signed mixed count/histogram delegation, exact catalog scope and cumulative ancestor caps; synthetic plaintext trusted registry; no vector vault/witness/network integration')
        (root/'mixed_delegated_test_results.json').write_text(json.dumps(report,indent=2)+'\n');sys.exit(0 if result.wasSuccessful() else 1)
