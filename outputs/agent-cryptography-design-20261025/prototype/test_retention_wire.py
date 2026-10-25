import hashlib
import json
from pathlib import Path
import platform
import unittest
import cryptography
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import retention_wire as r
from wire import encode,decode,sign1
from ledger import Rejected

HERE=Path(__file__).parent
SIZE_EVIDENCE={}


def public(k):return k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)


def fixture():
    # Public deterministic synthetic signing material; NEVER deployment secrets.
    sender=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    receiver=Ed25519PrivateKey.from_private_bytes(bytes(range(32,64)))
    ctx=dict(profile=r.PROFILE,deployment=b'd'*16,tenant='t',recipient='r',gateway='g',session='s',epoch=b'e'*16,
        sender_authority=b's'*16,receiver_authority=b'r'*16,sender_key=public(sender),receiver_key=public(receiver),
        sender_kid=b'sender',receiver_kid=b'receiver',sender_cert=b'S'*32,receiver_cert=b'R'*32,window=3)
    return ctx,sender,receiver


def fact(ctx,seq=1,outcome='ACCEPTED',**changes):
    obj=dict(profile=r.PROFILE,context_hash=r.context_hash(ctx),seq=seq,delivery=r.delivery_id(ctx,seq),
        action_digest=b'a'*32,descriptor_hash=b'd'*32,issued_at=100,expires_at=160,outcome=outcome,
        event_at=110 if outcome=='ACCEPTED' else 160,envelope_hash=b'h'*32)
    obj.update(changes);return r.fact_bytes(obj,ctx)


def vectors():
    c,s,k=fixture();f=fact(c);g=r.genesis(c);root=r.extend_prefix(g,f,c,1)
    q=r.query(c,'FINAL',1,b'q'*32,s);ack=r.final_receipt(f,q,c,k)
    o=r.offer(c,0,g,1,root,s);req=r.retire_attempt(o,b'z'*32,c,s)
    done=r.checkpoint(req,c,'RETIRE_ACK',floor=1,root=root,high=1,key=k)
    items=dict(context=encode(c),context_hash=r.context_hash(c),genesis=g,fact=f,prefix=root,
               final_query=q,final_receipt=ack,offer=o,retire_attempt=req,retire_ack=done)
    return {'profile':r.PROFILE,'purpose':'Deterministic synthetic regression vectors, not independent interoperability evidence.',
            'sender_private_seed_hex':bytes(range(32)).hex(),'receiver_private_seed_hex':bytes(range(32,64)).hex(),
            'delivery_id':r.delivery_id(c,1),'hex':{k:v.hex() for k,v in items.items()}}


class RetentionWireTests(unittest.TestCase):
    def setUp(self):
        self.c,self.s,self.k=fixture();self.f=fact(self.c);self.g=r.genesis(self.c)
        self.root=r.extend_prefix(self.g,self.f,self.c,1)
        self.o=r.offer(self.c,0,self.g,1,self.root,self.s)
        self.req=r.retire_attempt(self.o,b'q'*32,self.c,self.s)

    def reject(self,code,fn):
        with self.assertRaises(Rejected) as caught:fn()
        self.assertEqual(str(caught.exception),code)

    def resign(self,obj,domain,role='receiver',kid=None):
        key=self.k if role=='receiver' else self.s
        return sign1(encode(obj),self.c[role+'_kid'] if kid is None else kid,key,domain)

    def test_signed_end_to_end_retirement_transition(self):
        q=r.query(self.c,'FINAL',1,b'f'*32,self.s)
        ack=r.final_receipt(self.f,q,self.c,self.k)
        f=r.parse_final_receipt(ack,q,self.c)
        state=r.retirement_transition(self.o,self.c,floor=0,root=self.g,high=1,live=[f])
        self.assertEqual(state,dict(floor=1,root=self.root,high=1,live=()))
        response=r.checkpoint(self.req,self.c,'RETIRE_ACK',key=self.k,**{k:v for k,v in state.items() if k!='live'})
        self.assertEqual(r.reconcile_checkpoint(response,self.req,self.c,known_floor=0,confirmed=1,archived_root=self.root),(1,self.root))

    def test_retry_receipts_normalize_to_identical_fact_and_root(self):
        packets=[]
        for challenge in (b'1'*32,b'2'*32):
            q=r.query(self.c,'FINAL',1,challenge,self.s);ack=r.final_receipt(self.f,q,self.c,self.k)
            normalized=r.parse_final_receipt(ack,q,self.c)
            self.assertEqual(normalized,self.f);self.assertEqual(r.extend_prefix(self.g,normalized,self.c,1),self.root)
            packets.append((q,ack))
        self.assertNotEqual(packets[0],packets[1])
        self.reject('RETENTION_REPLY_BINDING',lambda:r.parse_final_receipt(packets[0][1],packets[1][0],self.c))

    def test_every_immutable_context_field_changes_identity(self):
        for field in self.c:
            if field=='profile':continue
            c=dict(self.c);value=c[field]
            c[field]=value+1 if type(value) is int else ('x'+value if type(value) is str else bytes([value[0]^1])+value[1:])
            with self.subTest(field=field):
                self.assertNotEqual(r.context_hash(c),r.context_hash(self.c))
                self.assertNotEqual(r.delivery_id(c,1),r.delivery_id(self.c,1))
                self.assertNotEqual(r.genesis(c),self.g)

    def test_cross_epoch_and_authority_offer_rejected_even_same_keys(self):
        for field in ('epoch','sender_authority','receiver_authority','tenant','window'):
            c=dict(self.c);c[field]=b'X'*16 if type(c[field]) is bytes else ('other' if type(c[field]) is str else 2)
            self.reject('RETENTION_CONTEXT',lambda:r.parse_offer(self.o,c))

    def test_context_closed_fields_and_namespace_separation(self):
        for c in (dict(self.c,extra=1),{k:v for k,v in self.c.items() if k!='epoch'}):
            self.reject('RETENTION_SCHEMA',lambda:r.validate_context(c))
        self.reject('RETENTION_AUTHORITY_ALIAS',lambda:r.validate_context(dict(self.c,receiver_authority=self.c['sender_authority'])))
        self.reject('RETENTION_INTEGER',lambda:r.validate_context(dict(self.c,window=True)))
        self.reject('RETENTION_KID',lambda:r.validate_context(dict(self.c,sender_kid=b'x'*33)))

    def test_unrelated_key_and_wrong_role_rejected(self):
        self.reject('RETENTION_SIGNING_KEY',lambda:r.offer(self.c,0,self.g,1,self.root,self.k))
        obj=r.parse_offer(self.o,self.c)
        self.reject('INVALID_SIGNATURE',lambda:r.parse_offer(self.resign(obj,r.OFFER_TYPE),self.c))

    def test_signature_domain_and_kid_are_mandatory(self):
        obj=r.parse_offer(self.o,self.c)
        self.reject('INVALID_SIGNATURE',lambda:r.parse_offer(self.resign(obj,'MixedDeliveryTerminal','sender'),self.c))
        self.reject('RETENTION_KID',lambda:r.parse_offer(self.resign(obj,r.OFFER_TYPE,'sender',b'other'),self.c))

    def test_signature_each_byte_mutation_rejected(self):
        for offset in range(1,65):
            bad=bytearray(self.o);bad[-offset]^=1
            self.reject('INVALID_SIGNATURE',lambda:r.parse_offer(bytes(bad),self.c))

    def test_fact_closed_fields_and_derived_id(self):
        obj=decode(self.f)
        for bad in (dict(obj,extra=b''),{k:v for k,v in obj.items() if k!='descriptor_hash'},dict(obj,profile='mixed-delivery-v1')):
            self.reject('RETENTION_SCHEMA',lambda:r.parse_fact(encode(bad),self.c))
        self.reject('RETENTION_DELIVERY_ID',lambda:r.parse_fact(encode(dict(obj,delivery='old-free-text')),self.c))
        self.reject('RETENTION_INTEGER',lambda:r.parse_fact(encode(dict(obj,seq=0)),self.c))

    def test_event_time_and_outcome_boundaries(self):
        for changes in ({'event_at':99},{'event_at':160},{'envelope_hash':b''},{'outcome':'RETIRED'}):
            self.reject('RETENTION_FINAL_EVENT',lambda:fact(self.c,**changes))
        self.reject('RETENTION_FINAL_EVENT',lambda:fact(self.c,outcome='CLOSED',event_at=159))
        self.assertEqual(r.parse_fact(fact(self.c,outcome='CLOSED',envelope_hash=b''),self.c)['event_at'],160)
        self.reject('RETENTION_WINDOW',lambda:fact(self.c,expires_at=161))

    def test_changed_fact_time_outcome_or_binding_changes_commitment(self):
        for changes in ({'event_at':111},{'outcome':'CLOSED','event_at':160},{'action_digest':b'Z'*32},
                        {'descriptor_hash':b'Z'*32},{'envelope_hash':b'Z'*32}):
            changed=fact(self.c,**changes)
            self.assertNotEqual(r.extend_prefix(self.g,changed,self.c,1),self.root)
            self.reject('RETENTION_PREFIX_MISMATCH',lambda:r.retirement_transition(self.o,self.c,floor=0,root=self.g,high=1,live=[changed]))

    def test_final_receipt_cannot_answer_other_sequence_or_query_kind(self):
        q=r.query(self.c,'FINAL',2,b'q'*32,self.s)
        self.reject('RETENTION_FINAL_REQUEST',lambda:r.final_receipt(self.f,q,self.c,self.k))
        q=r.query(self.c,'RETIRED',1,b'q'*32,self.s)
        self.reject('RETENTION_FINAL_REQUEST',lambda:r.final_receipt(self.f,q,self.c,self.k))

    def test_receiver_live_state_is_exact_and_contiguous(self):
        second=fact(self.c,2,'CLOSED')
        for high,live in ((2,[self.f]),(2,[second,self.f]),(2,[self.f,self.f])):
            code='RETENTION_LIVE_WINDOW' if len(live)!=high else 'RETENTION_SEQUENCE'
            self.reject(code,lambda:r.retirement_transition(self.o,self.c,floor=0,root=self.g,high=high,live=live))
        self.reject('RETENTION_MISSING_FINAL',lambda:r.retirement_transition(self.o,self.c,floor=0,root=self.g,high=0,live=[]))

    def test_partial_prefix_retirement_preserves_tail_and_high(self):
        second=fact(self.c,2,'CLOSED');state=r.retirement_transition(self.o,self.c,floor=0,root=self.g,high=2,live=[self.f,second])
        self.assertEqual(state['high'],2);self.assertEqual(state['live'],(second,))
        root2=r.extend_prefix(self.root,second,self.c,2)
        offer2=r.offer(self.c,1,self.root,2,root2,self.s)
        self.assertEqual(r.retirement_transition(offer2,self.c,**state),dict(floor=2,root=root2,high=2,live=()))

    def test_duplicate_and_stale_offers_cannot_mutate_again(self):
        state=r.retirement_transition(self.o,self.c,floor=0,root=self.g,high=1,live=[self.f])
        self.reject('RETENTION_STALE_BASE',lambda:r.retirement_transition(self.o,self.c,**state))
        # An idempotent handler can return the authoritative checkpoint instead.
        ack=r.checkpoint(self.req,self.c,'RETIRE_ACK',floor=1,root=self.root,high=1,key=self.k)
        self.assertEqual(r.parse_checkpoint(ack,self.req,self.c)['floor'],1)

    def test_offer_interval_and_base_commitment_constraints(self):
        for base,target,code in ((1,1,'RETENTION_OFFER_RANGE'),(2,1,'RETENTION_OFFER_RANGE'),(0,4,'RETENTION_OFFER_WINDOW')):
            self.reject(code,lambda:r.offer(self.c,base,self.g,target,self.root,self.s))
        self.reject('RETENTION_GENESIS',lambda:r.offer(self.c,0,b'x'*32,1,self.root,self.s))
        self.reject('RETENTION_SEQUENCE',lambda:r.extend_prefix(self.g,self.f,self.c,2))

    def test_fresh_request_binding_and_nested_offer_authentication(self):
        ack=r.checkpoint(self.req,self.c,'RETIRE_ACK',floor=1,root=self.root,high=1,key=self.k)
        retry=r.retire_attempt(self.o,b'n'*32,self.c,self.s)
        self.reject('RETENTION_REPLY_BINDING',lambda:r.parse_checkpoint(ack,retry,self.c))
        obj=r.parse_retire_attempt(self.req,self.c);bad=bytearray(obj['offer']);bad[-1]^=1;obj['offer']=bytes(bad)
        raw=self.resign(obj,r.ATTEMPT_TYPE,'sender')
        self.reject('INVALID_SIGNATURE',lambda:r.parse_retire_attempt(raw,self.c))

    def test_checkpoint_cannot_claim_unapplied_target_or_inconsistent_root(self):
        self.reject('RETENTION_TARGET_NOT_RETIRED',lambda:r.checkpoint(self.req,self.c,'RETIRE_ACK',floor=0,root=self.g,high=1,key=self.k))
        self.reject('RETENTION_PREFIX_MISMATCH',lambda:r.checkpoint(self.req,self.c,'RETIRE_ACK',floor=1,root=b'x'*32,high=1,key=self.k))
        self.reject('RETENTION_FRONTIER',lambda:r.checkpoint(self.req,self.c,'RETIRE_ACK',floor=1,root=self.root,high=0,key=self.k))

    def test_lost_ack_later_checkpoint_requires_sender_archive(self):
        second=fact(self.c,2);root2=r.extend_prefix(self.root,second,self.c,2)
        ack=r.checkpoint(self.req,self.c,'RETIRE_ACK',floor=2,root=root2,high=2,key=self.k)
        self.reject('RETENTION_SENDER_FRONTIER',lambda:r.reconcile_checkpoint(ack,self.req,self.c,known_floor=0,confirmed=1,archived_root=root2))
        self.reject('RETENTION_ARCHIVE_MISMATCH',lambda:r.reconcile_checkpoint(ack,self.req,self.c,known_floor=0,confirmed=2,archived_root=self.root))
        self.assertEqual(r.reconcile_checkpoint(ack,self.req,self.c,known_floor=0,confirmed=2,archived_root=root2),(2,root2))
        self.reject('RETENTION_SENDER_FRONTIER',lambda:r.reconcile_checkpoint(ack,self.req,self.c,known_floor=3,confirmed=3,archived_root=root2))

    def test_retired_query_returns_no_reconstructed_outcome_or_time(self):
        q=r.query(self.c,'RETIRED',1,b'q'*32,self.s)
        ack=r.checkpoint(q,self.c,'RETIRED',floor=1,root=self.root,high=1,key=self.k)
        obj=r.parse_checkpoint(ack,q,self.c)
        self.assertNotIn('outcome',obj);self.assertNotIn('event_at',obj);self.assertEqual(obj['status'],'RETIRED')
        self.reject('RETENTION_NOT_RETIRED',lambda:r.checkpoint(q,self.c,'RETIRED',floor=0,root=self.g,high=1,key=self.k))
        self.reject('RETENTION_CHECKPOINT_KIND',lambda:r.checkpoint(q,self.c,'CLOSED',floor=1,root=self.root,high=1,key=self.k))

    def test_checkpoint_request_does_not_authorize_deletion(self):
        q=r.query(self.c,'CHECKPOINT',0,b'q'*32,self.s)
        ack=r.checkpoint(q,self.c,'CHECKPOINT',floor=0,root=self.g,high=1,key=self.k)
        self.assertEqual(r.parse_checkpoint(ack,q,self.c)['floor'],0)
        self.reject('INVALID_SIGNATURE',lambda:r.retirement_transition(q,self.c,floor=0,root=self.g,high=1,live=[self.f]))
        self.reject('RETENTION_CHECKPOINT_KIND',lambda:r.checkpoint(q,self.c,'RETIRED',floor=0,root=self.g,high=1,key=self.k))

    def test_frame_and_canonical_encoding_fail_closed(self):
        self.reject('RETENTION_FRAME',lambda:r.parse_offer(b'x'*(r.MAX_FRAME+1),self.c))
        self.reject('RETENTION_FRAME',lambda:r.parse_fact(b'',self.c))
        self.reject('TRAILING_CBOR',lambda:r.parse_fact(self.f+b'\x00',self.c))
        self.reject('INDEFINITE_OR_RESERVED',lambda:r.parse_fact(b'\xbf\xff',self.c))
        # Valid signature over a noncanonical map does not make it acceptable.
        noncanonical=b'\xb8'+bytes([len(decode(self.f))])+self.f[1:]
        self.reject('NONCANONICAL_CBOR',lambda:r.parse_fact(noncanonical,self.c))

    def test_maximum_sequence_is_not_wrapped_or_reassigned(self):
        last=fact(self.c,r.MAX_SEQ);previous=b'p'*32
        root=r.extend_prefix(previous,last,self.c,r.MAX_SEQ)
        offer=r.offer(self.c,r.MAX_SEQ-1,previous,r.MAX_SEQ,root,self.s)
        self.assertEqual(r.retirement_transition(offer,self.c,floor=r.MAX_SEQ-1,root=previous,high=r.MAX_SEQ,live=[last])['high'],r.MAX_SEQ)
        self.reject('RETENTION_INTEGER',lambda:r.delivery_id(self.c,r.MAX_SEQ+1))
        self.reject('RETENTION_INTEGER',lambda:r.delivery_id(self.c,0))

    def test_maximum_field_frame_sizes(self):
        c=dict(self.c,**{x:'x'*64 for x in ('tenant','recipient','gateway','session')},sender_kid=b's'*32,receiver_kid=b'r'*32,window=65535)
        raw=fact(c,r.MAX_SEQ,issued_at=r.MAX_TIME-60,expires_at=r.MAX_TIME,event_at=r.MAX_TIME-1)
        root=r.extend_prefix(b'p'*32,raw,c,r.MAX_SEQ)
        offer=r.offer(c,r.MAX_SEQ-1,b'p'*32,r.MAX_SEQ,root,self.s)
        attempt=r.retire_attempt(offer,b'q'*32,c,self.s)
        q=r.query(c,'FINAL',r.MAX_SEQ,b'q'*32,self.s);ack=r.final_receipt(raw,q,c,self.k)
        cp=r.checkpoint(attempt,c,'RETIRE_ACK',floor=r.MAX_SEQ,root=root,high=r.MAX_SEQ,key=self.k)
        retired_query=r.query(c,'RETIRED',r.MAX_SEQ,b'q'*32,self.s)
        head_query=r.query(c,'CHECKPOINT',0,b'q'*32,self.s)
        values=dict(context=encode(c),fact=raw,offer=offer,attempt=attempt,final_query=q,
                    retired_query=retired_query,checkpoint_query=head_query,final_receipt=ack,retire_ack=cp)
        SIZE_EVIDENCE.update({k:len(v) for k,v in values.items()})
        self.assertTrue(all(len(v)<=r.MAX_FRAME for v in values.values()))
        self.assertEqual(r.parse_final_receipt(ack,q,c),raw)
        self.assertEqual(r.parse_checkpoint(cp,attempt,c)['floor'],r.MAX_SEQ)

    def test_deterministic_vectors_match_saved_fixture(self):
        self.assertEqual(json.loads((HERE/'retention_vectors.json').read_text()),vectors())

    def test_authenticated_malformed_payloads_still_rejected(self):
        q=r.query(self.c,'FINAL',1,b'f'*32,self.s)
        ack=r.final_receipt(self.f,q,self.c,self.k)
        envelope=decode(decode(ack[1:])[2])
        malformed=decode(self.f);malformed['delivery']='forgotten-id'
        envelope['fact']=encode(malformed)
        self.reject('RETENTION_DELIVERY_ID',lambda:r.parse_final_receipt(self.resign(envelope,r.FINAL_TYPE),q,self.c))
        payload=r.parse_offer(self.o,self.c)
        for change in ({'extra':0},{'profile':'mixed-delivery-v1'}):
            self.reject('RETENTION_SCHEMA',lambda:r.parse_offer(self.resign(dict(payload,**change),r.OFFER_TYPE,'sender'),self.c))
        self.reject('RETENTION_INTEGER',lambda:r.parse_offer(self.resign(dict(payload,target=0),r.OFFER_TYPE,'sender'),self.c))

    def test_full_live_window_blocks_invalid_checkpoint(self):
        q=r.query(self.c,'CHECKPOINT',0,b'f'*32,self.s)
        self.reject('RETENTION_LIVE_WINDOW',lambda:r.checkpoint(q,self.c,'CHECKPOINT',floor=0,root=self.g,high=4,key=self.k))
        payload=dict(profile=r.PROFILE,context_hash=r.context_hash(self.c),status='CHECKPOINT',floor=0,root=self.g,high=4,
                     challenge=b'f'*32,request_hash=r.sha(q))
        self.reject('RETENTION_LIVE_WINDOW',lambda:r.parse_checkpoint(self.resign(payload,r.CHECKPOINT_TYPE),q,self.c))

    def test_signature_alone_does_not_prove_sender_persistence(self):
        # Deliberate negative control: a holder of the trusted sender key can
        # sign an offer without any sender database. The codec cannot detect it.
        # This is why durable sender signing policy is an integration gate.
        parsed=r.parse_offer(self.o,self.c)
        self.assertEqual(parsed['target'],1)
        self.assertEqual(r.retirement_transition(self.o,self.c,floor=0,root=self.g,high=1,live=[self.f])['floor'],1)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RetentionWireTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,signature_byte_mutations=64,
        maximum_field_fixture_bytes=SIZE_EVIDENCE,production_gc=False,network_integration=False,
        independent_interoperability=False,cddl_independently_validated=False,
        scope='Strict signed messages, normalized fact stability and pure guards; durable authority state supplied by caller, no real persistence or crash testing.',
        python=platform.python_version(),cryptography=cryptography.__version__,
        source_sha256={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
            ['retention_wire.py','test_retention_wire.py','retention_vectors.json','retention_v2.cddl','wire.py','ledger.py']})
    (HERE/'retention_wire_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
