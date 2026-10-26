import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from copy import deepcopy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delegated_ledger import DelegatedLedger, Rejected, parse_credential, cap_accounts
from dp_ledger import MECHANISM, PROFILE, EPSILON_COST as E, DELTA_COST as D
from wire import encode,sign1
from test_signed_ledger import action as direct_action

# Deterministic, public synthetic fixture keys only.
KEYS={name:Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('fixture:'+name).encode()).digest())
      for name in ('authority','manager','worker','leaf','other')}
CRASHES=[]


def credential(obj):
    return sign1(encode(obj),obj['issuer_kid'],KEYS[obj['issuer']],
                 'Grant' if obj['kind']=='grant' else 'Delegation')


def chain_fixture(root_cap=2,child_cap=2,leaf_id='leafgrant',leaf_subject='leaf'):
    policy={'domain':'domain','snapshots':['snap'],'recipients':['reader'],'mechanisms':[MECHANISM],
            'operations':['count'],'accountant':PROFILE,'accounts':{'epsilon':'domain:epsilon','delta':'domain:delta'}}
    root=dict(profile='count-chain-v1',kind='grant',id='root',tenant='t',root='root',issuer='authority',issuer_kid=b'authority',
              subject='manager',subject_kid=b'manager',parent_digest=b'',depth=0,max_depth=3,not_before=0,expires_at=900,
              policy=policy,epsilon_cap=root_cap*E,delta_cap=root_cap*D)
    wires=[credential(root)]
    child=deepcopy(root); child.update(kind='delegation',id='workergrant',issuer='manager',issuer_kid=b'manager',
        subject='worker',subject_kid=b'worker',parent_digest=hashlib.sha256(wires[-1]).digest(),depth=1,
        epsilon_cap=child_cap*E,delta_cap=child_cap*D)
    wires.append(credential(child))
    leaf=deepcopy(child); leaf.update(id=leaf_id,issuer='worker',issuer_kid=b'worker',subject=leaf_subject,
        subject_kid=leaf_subject.encode(),parent_digest=hashlib.sha256(wires[-1]).digest(),depth=2)
    wires.append(credential(leaf))
    return wires


def setup(path):
    l=DelegatedLedger.create(path,clock=lambda:100)
    l.provision_domain('t','domain',2,3*E,3*D)
    l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
    l.install_snapshot('t','domain','snap',[0,1])
    for name,key in KEYS.items():
        pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',pub)
    l.bind_root_authority('t','root',b'authority')
    return l


def packet(l,chain,oid='a',proof_id=b'p'*16,**changes):
    leaf=parse_credential(chain[-1])
    # Explicit new schema, never mutate a direct-root action after signing.
    from wire import decode
    obj=decode(direct_action())
    obj.update(profile='count-delegated-v1',operation=oid,actor=leaf['subject'],kid=leaf['subject_kid'],
               leaf_digest=hashlib.sha256(chain[-1]).digest(),deadline=leaf['expires_at'])
    obj.update(changes); raw=encode(obj)
    ch=l.issue_challenge('t',obj['kid'])
    p=dict(profile='count-delegated-v1',action_digest=hashlib.sha256(raw).digest(),proof_id=proof_id,**ch)
    proof=sign1(encode(p),obj['kid'],KEYS[obj['kid'].decode()])
    return raw,proof


def finish(l):
    while l.db.execute('SELECT 1 FROM jobs WHERE publication IS NULL').fetchone():
        t=l.db.execute('SELECT tick FROM schedulers').fetchone()[0]
        l.advance('t','domain','tick'+str(t),t)


def mutate_leaf(chain,**changes):
    out=list(chain); obj=parse_credential(out[-1]); obj.update(changes); out[-1]=credential(obj); return out


def child(path,point,packet_path):
    l=DelegatedLedger(path,clock=lambda:100); p=json.loads(Path(packet_path).read_text())
    def fault(here):
        if here==point: os._exit(95)
    l.register_delegated(bytes.fromhex(p['action']),bytes.fromhex(p['proof']),[bytes.fromhex(x) for x in p['chain']],fault)
    raise RuntimeError('cut not reached')


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'db'; self.l=setup(self.path); self.chain=chain_fixture()
    def tearDown(self):
        self.assertEqual(self.l.audit(),[]); self.l.close(); self.tmp.cleanup()
    def reject(self,code,call):
        with self.assertRaisesRegex(Rejected,'^'+code+'$'): call()
    def register(self,chain=None,oid='a',proof_id=b'p'*16,**changes):
        chain=self.chain if chain is None else chain
        raw,p=packet(self.l,chain,oid,proof_id,**changes)
        return self.l.register_delegated(raw,p,chain)

    def test_two_level_delegation_executes_and_charges_every_ancestor(self):
        self.register(); finish(self.l)
        self.assertEqual(self.l.op('t','a')['actor'],'leaf')
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM charges').fetchone()[0],8)
        for account in ['domain:epsilon']+[cap_accounts(w)[0] for w in self.chain]:
            self.assertEqual(self.l.db.execute('SELECT spent FROM accounts WHERE id=?',(account,)).fetchone()[0],E)
        self.l.admit_delivery('t','a','reader','ticket','gw','session')
        self.assertEqual(len(self.l.emit('t','ticket','reader','gw','session')),8)

    def test_forked_children_do_not_duplicate_parent_budget(self):
        self.chain=chain_fixture(root_cap=1,child_cap=1)
        self.register()
        fork=chain_fixture(root_cap=1,child_cap=1,leaf_id='otherleaf',leaf_subject='other')
        raw,p=packet(self.l,fork,'b',b'q'*16)
        self.reject('BUDGET_EXHAUSTED',lambda:self.l.register_delegated(raw,p,fork))
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],1)
        self.assertEqual(self.l.db.execute("SELECT COUNT(*) FROM credentials WHERE id='otherleaf'").fetchone()[0],0)

    def test_shared_intermediate_cap_blocks_more_than_global_budget(self):
        self.chain=chain_fixture(root_cap=2,child_cap=1); self.register()
        fork=chain_fixture(root_cap=2,child_cap=1,leaf_id='otherleaf',leaf_subject='other')
        raw,p=packet(self.l,fork,'b',b'q'*16)
        self.reject('BUDGET_EXHAUSTED',lambda:self.l.register_delegated(raw,p,fork))
        self.assertEqual(self.l.db.execute("SELECT free FROM accounts WHERE id='domain:epsilon'").fetchone()[0],2*E)

    def test_scope_widening_and_empty_scope(self):
        for name,value in [('snapshots','other'),('recipients','outside'),('mechanisms','unknown'),('operations','histogram')]:
            p=deepcopy(parse_credential(self.chain[-1])['policy']); p[name]=sorted(p[name]+[value])
            chain=mutate_leaf(self.chain,policy=p); raw,proof=packet(self.l,chain)
            self.reject('ATTENUATION_SCOPE',lambda:self.l.register_delegated(raw,proof,chain))
        p=deepcopy(parse_credential(self.chain[-1])['policy']);p['operations']=[]
        chain=mutate_leaf(self.chain,policy=p);raw,proof=packet(self.l,chain)
        self.reject('ACTION_OUTSIDE_LEAF',lambda:self.l.register_delegated(raw,proof,chain))

    def test_time_depth_and_cumulative_cap_widening(self):
        for changes in ({'expires_at':901},{'max_depth':4},{'epsilon_cap':3*E},{'delta_cap':3*D}):
            chain=mutate_leaf(self.chain,**changes);raw,proof=packet(self.l,chain)
            self.reject('ATTENUATION_BOUNDS',lambda:self.l.register_delegated(raw,proof,chain))
        chain=mutate_leaf(self.chain,depth=3);raw,proof=packet(self.l,chain)
        self.reject('CHAIN_PARENT_BINDING',lambda:self.l.register_delegated(raw,proof,chain))

    def test_parent_hash_issuer_and_signature_domain_substitution(self):
        for changes in ({'parent_digest':b'x'*32},{'issuer':'manager','issuer_kid':b'manager'}):
            chain=mutate_leaf(self.chain,**changes);raw,proof=packet(self.l,chain)
            self.reject('CHAIN_PARENT_BINDING',lambda:self.l.register_delegated(raw,proof,chain))
        chain=list(self.chain);obj=parse_credential(chain[-1]);chain[-1]=sign1(encode(obj),b'worker',KEYS['worker'],'Grant')
        raw,proof=packet(self.l,chain)
        self.reject('INVALID_SIGNATURE',lambda:self.l.register_delegated(raw,proof,chain))

    def test_account_rebinding_and_leaf_binding(self):
        p=deepcopy(parse_credential(self.chain[-1])['policy']);p['accounts']['epsilon']='fresh:epsilon'
        chain=mutate_leaf(self.chain,policy=p);raw,proof=packet(self.l,chain)
        self.reject('ACCOUNT_REBIND',lambda:self.l.register_delegated(raw,proof,chain))
        raw,proof=packet(self.l,self.chain,leaf_digest=b'x'*32)
        self.reject('LEAF_BINDING',lambda:self.l.register_delegated(raw,proof,self.chain))

    def test_revocation_before_first_use_is_durable(self):
        self.l.revoke_credential('t','workergrant',root_id='root',kind='delegation',issuer_kid=b'manager')
        self.l.close();self.l=DelegatedLedger(self.path,clock=lambda:100)
        raw,p=packet(self.l,self.chain)
        self.reject('CREDENTIAL_REVOKED',lambda:self.l.register_delegated(raw,p,self.chain))
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0],0)

    def test_ancestor_revocation_before_l1_refunds_all_caps(self):
        self.register();self.l.revoke_credential('t','workergrant',root_id='root',kind='delegation',issuer_kid=b'manager');finish(self.l)
        self.assertEqual(self.l.op('t','a')['state'],'CANCELED')
        self.assertTrue(all(r[0]==0 for r in self.l.db.execute('SELECT spent+reserved FROM accounts')))

    def test_ancestor_key_revocation_after_l1_withholds_without_refund(self):
        self.register();self.l.advance('t','domain','start',0)
        self.l.revoke_key('t',b'manager');finish(self.l)
        self.assertEqual(self.l.op('t','a')['state'],'COMMITTED')
        self.assertEqual(self.l.db.execute('SELECT publication FROM jobs').fetchone()[0],'WITHHELD')
        self.assertTrue(all(r[0]>0 for r in self.l.db.execute('SELECT spent FROM accounts')))

    def test_existing_ticket_survives_ancestor_revocation_new_l3_fails(self):
        self.register();finish(self.l);self.l.admit_delivery('t','a','reader','old','gw','session')
        self.l.revoke_credential('t','root',root_id='root',kind='grant',issuer_kid=b'authority')
        self.reject('ACTION_OR_KEY_INACTIVE',lambda:self.l.admit_delivery('t','a','reader','new','gw','session'))
        self.assertEqual(len(self.l.emit('t','old','reader','gw','session')),8)

    def test_credential_id_cannot_be_reissued_with_fresh_cap(self):
        self.register();changed=mutate_leaf(self.chain,epsilon_cap=E,delta_cap=D)
        raw,p=packet(self.l,changed,'b',b'q'*16)
        self.reject('CREDENTIAL_ID_CONFLICT',lambda:self.l.register_delegated(raw,p,changed))

    def test_unsigned_and_direct_profile_cannot_bypass_chain(self):
        raw,p=packet(self.l,self.chain)
        self.reject('CHAIN_REQUIRED',lambda:self.l.register_signed(raw,p))
        raw,p=packet(self.l,self.chain,profile='count-direct-v1')
        self.reject('INVALID_ACTION_SCHEMA',lambda:self.l.register_delegated(raw,p,self.chain))
        self.reject('CHAIN_LIMIT',lambda:self.l.register_delegated(b'',b'',self.chain*3))

    def test_same_action_fresh_proof_does_not_recharge_caps(self):
        ack=self.register();self.assertEqual(self.register(proof_id=b'q'*16),ack)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM charges').fetchone()[0],8)
        self.assertEqual(self.l.db.execute('SELECT COUNT(*) FROM operation_chains').fetchone()[0],3)

    def test_concurrent_sibling_operations_cannot_overspend_shared_caps(self):
        self.chain=chain_fixture(root_cap=1,child_cap=1)
        packets=[packet(self.l,self.chain,str(i),bytes([i])*16) for i in range(8)]
        gate=threading.Barrier(8)
        def attempt(i):
            l=DelegatedLedger(self.path,clock=lambda:100)
            try:
                gate.wait();l.register_delegated(*packets[i],self.chain);return 'accepted'
            except Rejected as e:return str(e)
            finally:l.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(attempt,range(8)))
        self.assertEqual(results.count('accepted'),1);self.assertEqual(results.count('BUDGET_EXHAUSTED'),7)

    def test_wrong_root_authority_is_not_trusted_from_chain(self):
        rogue=Ed25519PrivateKey.generate()
        pub=rogue.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.l.install_key('t',b'rogue','rogue','root',pub)
        obj=parse_credential(self.chain[0]);obj.update(issuer='rogue',issuer_kid=b'rogue')
        chain=[sign1(encode(obj),b'rogue',rogue,'Grant')]
        raw,p=packet(self.l,chain)
        self.reject('ROOT_BINDING',lambda:self.l.register_delegated(raw,p,chain))

    def test_valid_sibling_parent_cannot_be_spliced_into_chain(self):
        alternate=list(self.chain)
        obj=parse_credential(alternate[1]);obj['id']='sibling-parent'
        alternate[1]=credential(obj)
        raw,p=packet(self.l,alternate)
        self.reject('CHAIN_PARENT_BINDING',lambda:self.l.register_delegated(raw,p,alternate))

    def test_ancestor_key_expiry_caps_ticket_lifetime(self):
        # Trusted bootstrap fixture with an earlier root authority key expiry.
        self.l.db.execute("UPDATE signing_keys SET expires_at=150 WHERE kid=?",(b'authority',))
        self.register();finish(self.l)
        ticket=self.l.admit_delivery('t','a','reader','d','gw','session')
        self.assertEqual(ticket['expires_at'],150)
        self.l.clock=lambda:150
        self.reject('ACTION_OR_KEY_INACTIVE',lambda:self.l.admit_delivery('t','a','reader','new','gw','session'))
        self.reject('TICKET_EXPIRED',lambda:self.l.emit('t','d','reader','gw','session'))

    def test_saved_chain_vectors_match_exact_parent_digests(self):
        v=json.loads(Path(__file__).with_name('delegation_vectors.json').read_text())
        self.assertEqual([w.hex() for w in self.chain],v['chain_cose_hex'])
        for i,wire in enumerate(self.chain):
            self.assertEqual(hashlib.sha256(wire).hexdigest(),v['credential_sha256'][i])
            if i:
                self.assertEqual(parse_credential(wire)['parent_digest'],hashlib.sha256(self.chain[i-1]).digest())

    def test_direct_service_cannot_bypass_delegated_root_or_new_l3(self):
        from signed_ledger import SignedLedger
        direct=SignedLedger(self.path,clock=lambda:100)
        try:
            raw=direct_action(actor='manager',kid=b'manager')
            ch=direct.issue_challenge('t',b'manager')
            p=sign1(encode(dict(profile='count-direct-v1',action_digest=hashlib.sha256(raw).digest(),proof_id=b'r'*16,**ch)),b'manager',KEYS['manager'])
            self.reject('SERVICE_PROFILE_MISMATCH',lambda:direct.register_signed(raw,p))
            self.register();finish(self.l)
            self.l.revoke_credential('t','workergrant',root_id='root',kind='delegation',issuer_kid=b'manager')
            self.reject('SERVICE_PROFILE_MISMATCH',lambda:direct.admit_delivery('t','a','reader','bypass','gw','session'))
        finally:direct.close()

    def test_root_with_existing_operations_cannot_switch_authorization_mode(self):
        self.register()
        self.reject('ROOT_ALREADY_USED',lambda:self.l.bind_root_authority('t','root',b'authority'))

    def test_three_chain_registration_crash_cuts(self):
        for point in ('after_chain_registration','before_reserve_commit','after_reserve_commit'):
            with self.subTest(point=point):
                path=Path(self.tmp.name)/point;l=setup(path);raw,p=packet(l,self.chain)
                packet_path=Path(self.tmp.name)/(point+'.json')
                packet_path.write_text(json.dumps({'action':raw.hex(),'proof':p.hex(),'chain':[w.hex() for w in self.chain]}));l.close()
                proc=subprocess.run([sys.executable,__file__,'--crash',str(path),point,str(packet_path)],capture_output=True,timeout=30)
                self.assertEqual(proc.returncode,95,proc.stderr.decode())
                l=DelegatedLedger(path,clock=lambda:100);self.assertEqual(l.audit(),[])
                committed=point=='after_reserve_commit'
                self.assertEqual(l.db.execute('SELECT COUNT(*) FROM credentials').fetchone()[0],3 if committed else 0)
                self.assertEqual(l.db.execute('SELECT COUNT(*) FROM accounts').fetchone()[0],8 if committed else 2)
                self.assertEqual(l.db.execute('SELECT COUNT(*) FROM operation_chains').fetchone()[0],3 if committed else 0)
                if committed:raw,p=packet(l,self.chain,proof_id=b'q'*16)
                l.register_delegated(raw,p,self.chain);finish(l)
                self.assertEqual(l.audit(),[]);l.close();CRASHES.append(point)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--crash':child(sys.argv[2],sys.argv[3],sys.argv[4])
    else:
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DelegationTests))
        root=Path(__file__).resolve().parent
        sources=('delegated_ledger.py','test_delegated_ledger.py','ledger.py','dp_ledger.py','scheduled_ledger.py','signed_ledger.py','wire.py','count_delegated_v1.cddl','delegation_vectors.json','test_signed_ledger.py','../fixed_work_model.py')
        report={'passed':result.wasSuccessful(),'test_methods':result.testsRun,'crash_cut_count':len(CRASHES),'actual_process_crash_cuts':CRASHES,
                'source_sha256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in sources},
                'python_version':sys.version,'sqlite_version':__import__('sqlite3').sqlite_version,'cryptography_version':__import__('cryptography').__version__,'failures':[(str(t),m) for t,m in result.failures],'errors':[(str(t),m) for t,m in result.errors],
                'scope':'Signed count delegation chains, monotone policies and all-ancestor cumulative caps; trusted registry, synthetic data; not full object-family protocol'}
        (root/'delegated_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
        sys.exit(0 if result.wasSuccessful() else 1)
