import ast
import hashlib
import json
from pathlib import Path
import platform
import tempfile
import unittest
from unittest.mock import patch
import cryptography
import retention_delivery as d
import retention_wire as r
from test_retention_wire import fixture
from wire import encode,decode,sign1
from ledger import Rejected
from histogram_ledger import HISTOGRAM,COUNT,CODEC,canonical
from mixed_delegated_ledger import COUNT_CODEC
from dp_ledger import PROFILE as ACCOUNTANT

HERE=Path(__file__).parent
SIZES={}
PIPELINE_EVIDENCE={}


def shape(hist=True):
    labels=['one','two','three','four'] if hist else []
    return dict(action_digest=b'a'*32,domain='domain',snapshot='hist' if hist else 'count',accountant=ACCOUNTANT,
        mechanism=HISTOGRAM if hist else COUNT,capacity=3,bucket_count=4 if hist else 1,k=40,
        codec=CODEC if hist else COUNT_CODEC,catalog='cat' if hist else '',labels=labels,
        catalog_digest=hashlib.sha256(canonical(labels).encode()).digest() if hist else b'')


def descriptor(context,seq=1,hist=True,**changes):
    return d.descriptor(context,seq=seq,operation='op',issued_at=100,expires_at=160,shape=dict(shape(hist),**changes))


def vectors():
    c,s,k=fixture();desc=descriptor(c);env=d.envelope(desc,(1).to_bytes(8,'big')*4,c,s)
    control=d.control(desc,r.sha(env),c,s);fact=d.accepted_fact(env,110,c)
    request=d.attempt('DELIVERY',env,b'q'*32,c,s);terminal=d.attempt('TERMINAL',control,b't'*32,c,s)
    values=dict(descriptor=desc,descriptor_digest=d.descriptor_digest(desc,c),envelope=env,control=control,
                fact=fact,delivery_attempt=request,terminal_attempt=terminal,
                direct_receipt=d.receipt(fact,request,c,k),terminal_receipt=d.receipt(fact,terminal,c,k),
                prefix=r.extend_prefix(r.genesis(c),fact,c,1))
    return dict(profile=d.PROFILE,keys='Public synthetic fixtures from retention_vectors.json; not deployment secrets.',
                scope='Same-implementation deterministic regression, not independent interoperability.',
                hex={name:raw.hex() for name,raw in values.items()})


class RetentionDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.c,self.s,self.k=fixture();self.desc=descriptor(self.c)
        self.result=b''.join(x.to_bytes(8,'big') for x in [1,0,3,2])
        self.env=d.envelope(self.desc,self.result,self.c,self.s)
        self.control=d.control(self.desc,r.sha(self.env),self.c,self.s)
        self.req=d.attempt('DELIVERY',self.env,b'q'*32,self.c,self.s)
        self.fact=d.accepted_fact(self.env,110,self.c)

    def reject(self,code,fn):
        with self.assertRaises(Rejected) as caught:fn()
        self.assertEqual(str(caught.exception),code)

    def signed(self,obj,domain,role='sender'):
        return sign1(encode(obj),self.c[role+'_kid'],self.s if role=='sender' else self.k,domain)

    def test_complete_count_and_histogram_result_bind_to_fact(self):
        for hist,result in ((True,self.result),(False,(3).to_bytes(8,'big'))):
            desc=descriptor(self.c,hist=hist);env=d.envelope(desc,result,self.c,self.s)
            fact=d.accepted_fact(env,100,self.c);obj=d.verify_fact_evidence(fact,env,self.c)
            self.assertEqual(obj['descriptor_hash'],d.descriptor_digest(desc,self.c))
            self.assertEqual(obj['envelope_hash'],r.sha(env));self.assertEqual(obj['action_digest'],shape(hist)['action_digest'])

    def test_direct_terminal_and_fresh_query_share_one_fact_and_prefix(self):
        a=d.receipt(self.fact,self.req,self.c,self.k)
        direct=d.parse_receipt(a,self.req,self.c)
        req=d.attempt('TERMINAL',self.control,b't'*32,self.c,self.s)
        existing=d.terminal_reply_fact(self.control,self.fact,self.c)
        terminal=d.parse_receipt(d.receipt(existing,req,self.c,self.k),req,self.c)
        query=r.query(self.c,'FINAL',1,b'f'*32,self.s)
        fetched=r.parse_final_receipt(r.final_receipt(self.fact,query,self.c,self.k),query,self.c)
        self.assertEqual(direct,terminal);self.assertEqual(direct,fetched)
        roots={r.extend_prefix(r.genesis(self.c),x,self.c,1) for x in [direct,terminal,fetched]}
        self.assertEqual(len(roots),1)

    def test_closed_unprepared_control_contains_no_result(self):
        control=d.control(self.desc,b'',self.c,self.s);obj=d.parse_control(control,self.c)
        self.assertNotIn('result',obj);self.assertNotIn('result',d.parse_descriptor(obj['descriptor'],self.c))
        fact=d.closed_fact(control,160,self.c);self.assertEqual(r.parse_fact(fact,self.c)['envelope_hash'],b'')
        req=d.attempt('TERMINAL',control,b'c'*32,self.c,self.s)
        self.assertEqual(d.parse_receipt(d.receipt(fact,req,self.c,self.k),req,self.c),fact)
        self.reject('DELIVERY_V2_CLOSED',lambda:d.receipt(fact,self.req,self.c,self.k))

    def test_fact_fields_cannot_be_substituted_even_with_receiver_signature(self):
        for change in ({'action_digest':b'X'*32},{'descriptor_hash':b'X'*32},{'envelope_hash':b'X'*32},
                       {'issued_at':101,'expires_at':159}):
            bad=encode(dict(decode(self.fact),**change))
            payload=dict(profile=d.PROFILE,context_hash=r.context_hash(self.c),fact=bad,challenge=b'q'*32,request_hash=r.sha(self.req))
            self.reject('DELIVERY_V2_FACT_REQUEST',lambda:d.parse_receipt(self.signed(payload,d.RECEIPT_TYPE,'receiver'),self.req,self.c))
            self.reject('DELIVERY_V2_FACT_EVIDENCE',lambda:d.verify_fact_evidence(bad,self.env,self.c))

    def test_changed_first_time_is_different_fact_and_conflicts_with_offer(self):
        changed=d.accepted_fact(self.env,111,self.c)
        root=r.extend_prefix(r.genesis(self.c),self.fact,self.c,1)
        offer=r.offer(self.c,0,r.genesis(self.c),1,root,self.s)
        self.reject('RETENTION_PREFIX_MISMATCH',lambda:r.retirement_transition(offer,self.c,floor=0,root=r.genesis(self.c),high=1,live=[changed]))

    def test_terminal_must_match_original_descriptor_and_envelope(self):
        for desc,envhash in ((descriptor(self.c,capacity=4),r.sha(self.env)),(self.desc,b'X'*32)):
            control=d.control(desc,envhash,self.c,self.s)
            self.reject('DELIVERY_V2_TERMINAL_CONFLICT',lambda:d.terminal_reply_fact(control,self.fact,self.c))
        unprepared=d.control(self.desc,b'',self.c,self.s)
        self.reject('RETENTION_FINAL_EVENT',lambda:d.terminal_reply_fact(unprepared,self.fact,self.c))

    def test_signed_descriptor_binds_all_operation_and_shape_fields(self):
        original=d.parse_descriptor(self.desc,self.c)
        changes=[{'operation':'other'},{'domain':'other'},{'snapshot':'other'},{'action_digest':b'X'*32},
                 {'capacity':4},{'catalog':'other'},{'issued_at':101,'expires_at':160}]
        for change in changes:
            desc=encode(dict(original,**change));d.parse_descriptor(desc,self.c)
            env=d.envelope(desc,self.result,self.c,self.s)
            self.assertNotEqual(d.descriptor_digest(desc,self.c),d.descriptor_digest(self.desc,self.c))
            self.reject('DELIVERY_V2_FACT_EVIDENCE',lambda:d.verify_fact_evidence(self.fact,env,self.c))

    def test_catalog_reorder_requires_matching_digest_and_changes_fact(self):
        labels=list(reversed(shape()['labels']));self.reject('INVALID_DELIVERY_SHAPE',lambda:descriptor(self.c,labels=labels))
        desc=descriptor(self.c,labels=labels,catalog_digest=hashlib.sha256(canonical(labels).encode()).digest())
        env=d.envelope(desc,self.result,self.c,self.s)
        self.assertNotEqual(d.accepted_fact(env,110,self.c),self.fact)

    def test_invalid_shape_descriptors_are_rejected_inside_valid_signature(self):
        obj=d.parse_envelope(self.env,self.c);desc=decode(self.desc)
        for change in ({'bucket_count':3},{'capacity':0},{'k':39},{'codec':'wrong'},
                       {'labels':['one']*4},{'labels':[1,2,3,4]},{'accountant':'wrong'},
                       {'action_digest':b''},{'catalog_digest':b'X'*32},{'mechanism':'other'}):
            raw=encode(dict(desc,**change));packet=self.signed(dict(obj,descriptor=raw),d.ENVELOPE_TYPE)
            self.reject('INVALID_DELIVERY_SHAPE',lambda:d.parse_envelope(packet,self.c))

    def test_vector_must_be_complete_and_in_public_range(self):
        obj=d.parse_envelope(self.env,self.c)
        for result in (b'',self.result[:8],self.result[:-1],self.result+b'\0'*8,(4).to_bytes(8,'big')+self.result[8:]):
            self.reject('INVALID_DELIVERY_VECTOR',lambda:d.parse_envelope(self.signed(dict(obj,result=result),d.ENVELOPE_TYPE),self.c))
        # Independent per-bucket clipping permits sums above N.
        env=d.envelope(self.desc,(3).to_bytes(8,'big')*4,self.c,self.s)
        self.assertEqual(len(d.parse_envelope(env,self.c)['result']),32)

    def test_new_context_id_and_profile_cannot_coerce_v1(self):
        for change,code in (({'profile':'mixed-delivery-v1'},'DELIVERY_V2_SCHEMA'),
                            ({'delivery':'free-text-id'},'DELIVERY_V2_ID'),({'seq':2},'DELIVERY_V2_ID')):
            bad=encode(dict(decode(self.desc),**change));self.reject(code,lambda:d.parse_descriptor(bad,self.c))
        context=dict(self.c,epoch=b'Z'*16)
        self.reject('DELIVERY_V2_CONTEXT',lambda:d.parse_envelope(self.env,context))
        obj=d.parse_envelope(self.env,self.c)
        self.reject('INVALID_SIGNATURE',lambda:d.parse_envelope(self.signed(obj,'MixedDelivery'),self.c))

    def test_all_payloads_have_closed_schema(self):
        for raw,domain,parse in ((self.env,d.ENVELOPE_TYPE,d.parse_envelope),(self.control,d.CONTROL_TYPE,d.parse_control),
                                 (self.req,d.ATTEMPT_TYPE,d.parse_attempt)):
            payload=decode(decode(raw[1:])[2])
            self.reject('DELIVERY_V2_SCHEMA',lambda:parse(self.signed(dict(payload,extra=1),domain),self.c))
        self.reject('DELIVERY_V2_SHAPE_FIELDS',lambda:d.descriptor(self.c,seq=1,operation='op',issued_at=100,expires_at=160,shape=dict(shape(),seq=2)))

    def test_nested_descriptor_encoding_must_be_canonical(self):
        obj=d.parse_envelope(self.env,self.c)
        self.reject('TRAILING_CBOR',lambda:d.parse_envelope(self.signed(dict(obj,descriptor=self.desc+b'\x00'),d.ENVELOPE_TYPE),self.c))
        self.reject('RETENTION_FRAME',lambda:d.parse_descriptor(b'x'*8193,self.c))

    def test_accepted_and_closed_event_time_boundaries(self):
        for time in (99,160):self.reject('RETENTION_FINAL_EVENT',lambda:d.accepted_fact(self.env,time,self.c))
        self.reject('RETENTION_FINAL_EVENT',lambda:d.closed_fact(self.control,159,self.c))
        self.assertEqual(r.parse_fact(d.accepted_fact(self.env,159,self.c),self.c)['event_at'],159)
        self.assertEqual(r.parse_fact(d.closed_fact(self.control,160,self.c),self.c)['event_at'],160)

    def test_challenge_and_full_signed_request_binding(self):
        ack=d.receipt(self.fact,self.req,self.c,self.k)
        retry=d.attempt('DELIVERY',self.env,b'n'*32,self.c,self.s)
        self.reject('DELIVERY_V2_REPLY_BINDING',lambda:d.parse_receipt(ack,retry,self.c))
        terminal=d.attempt('TERMINAL',self.control,b'q'*32,self.c,self.s)
        self.reject('DELIVERY_V2_REPLY_BINDING',lambda:d.parse_receipt(ack,terminal,self.c))

    def test_outer_and_inner_signatures_are_both_checked(self):
        outer=decode(decode(self.req[1:])[2]);bad=bytearray(self.env);bad[-1]^=1
        outer['body']=bytes(bad)
        self.reject('INVALID_SIGNATURE',lambda:d.parse_attempt(self.signed(outer,d.ATTEMPT_TYPE),self.c))
        self.reject('INVALID_SIGNATURE',lambda:d.parse_attempt(self.signed(outer,'RetentionAttemptV2'),self.c))
        self.reject('DELIVERY_V2_ATTEMPT_KIND',lambda:d.attempt('RETIRED',self.env,b'q'*32,self.c,self.s))

    def test_wrong_evidence_type_never_reinterpreted(self):
        self.reject('INVALID_SIGNATURE',lambda:d.accepted_fact(self.control,110,self.c))
        closed=d.closed_fact(self.control,160,self.c)
        self.reject('INVALID_SIGNATURE',lambda:d.verify_fact_evidence(closed,self.env,self.c))
        self.reject('INVALID_SIGNATURE',lambda:d.verify_fact_evidence(self.fact,self.control,self.c))

    def test_evidence_flows_into_retention_offer_without_reconstructed_outcome(self):
        q=d.attempt('TERMINAL',self.control,b't'*32,self.c,self.s)
        raw=d.parse_receipt(d.receipt(self.fact,q,self.c,self.k),q,self.c)
        root=r.extend_prefix(r.genesis(self.c),raw,self.c,1)
        offer=r.offer(self.c,0,r.genesis(self.c),1,root,self.s)
        state=r.retirement_transition(offer,self.c,floor=0,root=r.genesis(self.c),high=1,live=[raw])
        req=r.query(self.c,'RETIRED',1,b'z'*32,self.s)
        ack=r.checkpoint(req,self.c,'RETIRED',key=self.k,**{k:v for k,v in state.items() if k!='live'})
        self.assertEqual(r.parse_checkpoint(ack,req,self.c)['status'],'RETIRED')

    def test_max64_buckets_max_fields_and_unsigned_sequence_fit_frame(self):
        c=dict(self.c,sender_kid=b's'*32,receiver_kid=b'r'*32)
        labels=[f'{i:02d}'+('界'*20)+'xx' for i in range(64)]
        sh=dict(shape(),bucket_count=64,capacity=65535,domain='d'*128,snapshot='s'*128,catalog='c'*128,
                labels=labels,catalog_digest=hashlib.sha256(canonical(labels).encode()).digest())
        desc=d.descriptor(c,seq=r.MAX_SEQ,operation='o'*128,issued_at=r.MAX_TIME-60,expires_at=r.MAX_TIME,shape=sh)
        env=d.envelope(desc,(65535).to_bytes(8,'big')*64,c,self.s)
        ctl=d.control(desc,r.sha(env),c,self.s);request=d.attempt('DELIVERY',env,b'q'*32,c,self.s)
        terminal=d.attempt('TERMINAL',ctl,b't'*32,c,self.s)
        fact=d.accepted_fact(env,r.MAX_TIME-1,c);ack=d.receipt(fact,request,c,self.k)
        SIZES.update({name:len(raw) for name,raw in dict(descriptor=desc,envelope=env,control=ctl,delivery_attempt=request,terminal_attempt=terminal,fact=fact,receipt=ack).items()})
        self.assertTrue(all(size<=8192 for size in SIZES.values()))
        self.assertEqual(d.parse_receipt(ack,request,c),fact)
        self.assertEqual(d.terminal_reply_fact(ctl,fact,c),fact)

    def test_trusted_signer_is_not_computation_or_first_event_proof(self):
        # Deliberate negative controls: syntactically valid results and distinct
        # first times can both be signed without a ledger. Integration MUST check.
        other=d.envelope(self.desc,b'\0'*32,self.c,self.s)
        d.parse_envelope(other,self.c)
        self.assertNotEqual(d.accepted_fact(other,110,self.c),self.fact)
        a=d.receipt(self.fact,self.req,self.c,self.k)
        b=d.receipt(d.accepted_fact(self.env,111,self.c),self.req,self.c,self.k)
        self.assertNotEqual(d.parse_receipt(a,self.req,self.c),d.parse_receipt(b,self.req,self.c))

    def test_deterministic_delivery_vectors(self):
        self.assertEqual(json.loads((HERE/'retention_delivery_vectors.json').read_text()),vectors())

    def test_real_signed_encrypted_mixed_results_as_evidence_inputs(self):
        from test_encrypted_mixed_ledger import setup,register,TAPE
        from test_mixed_delegated_ledger import finish
        from mixed_delivery_transport import MixedDeliveryLedger
        with tempfile.TemporaryDirectory() as tmp:
            ledger=setup(Path(tmp)/'ledger')
            try:
                register(ledger);register(ledger,'c',False)
                with patch('histogram_ledger.fresh_tape',return_value=TAPE):finish(ledger)
                before=[tuple(row) for row in ledger.db.execute('SELECT * FROM accounts')]
                c=dict(self.c,recipient='reader',gateway='gateway',session='session')
                roots=[];widths=[]
                for seq,oid in enumerate(('a','c'),1):
                    op=ledger.op('t',oid)
                    metadata=MixedDeliveryLedger.descriptor_fields(ledger,'t',oid,op['digest'])
                    desc=d.descriptor(c,seq=seq,operation=oid,issued_at=100,expires_at=160,shape=metadata)
                    env=d.envelope(desc,op['result'],c,self.s);fact=d.accepted_fact(env,110,c)
                    d.verify_fact_evidence(fact,env,c)
                    self.assertEqual(d.parse_envelope(env,c)['result'],ledger.compute_internal('t',oid))
                    roots.append(r.extend_prefix(r.genesis(c) if not roots else roots[-1],fact,c,seq));widths.append(len(op['result']))
                self.assertEqual(widths,[32,8]);self.assertEqual([tuple(row) for row in ledger.db.execute('SELECT * FROM accounts')],before)
                self.assertEqual(ledger.audit(),[])
                self.assertEqual(ledger.db.execute('SELECT count(*) FROM deliveries').fetchone()[0],0)
                PIPELINE_EVIDENCE.update(histogram_buckets=4,public_capacity=3,result_widths=widths,
                    source='signed encrypted shared-account jobs; offline encoding only, no v2 L3 or network admission',unchanged_accounts=True)
            finally:ledger.close()


def sources():
    # Hash local transitive imports actually named by this test/module source.
    pending=['test_retention_delivery.py'];seen={}
    while pending:
        name=pending.pop()
        if name in seen:continue
        path=HERE/name
        if not path.exists():continue
        raw=path.read_bytes();seen[name]=hashlib.sha256(raw).hexdigest()
        for node in ast.walk(ast.parse(raw)):
            mods=[alias.name for alias in node.names] if isinstance(node,ast.Import) else ([node.module] if isinstance(node,ast.ImportFrom) else [])
            for mod in mods:
                if mod:pending.append(mod.split('.')[0]+'.py')
    for name in ('retention_delivery_vectors.json','retention_delivery_v2.cddl'):
        seen[name]=hashlib.sha256((HERE/name).read_bytes()).hexdigest()
    return seen


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RetentionDeliveryTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,maximum_field_fixture_bytes=SIZES,
        computed_result_fixture=PIPELINE_EVIDENCE,source_sha256=sources(),python=platform.python_version(),cryptography=cryptography.__version__,
        v2_l3_admission=False,durable_authority_integration=False,network_integration=False,actual_process_crash_scenarios=0,
        independent_interoperability=False,scope='Complete signed descriptors/envelopes/terminal controls to normalized facts; pure codecs with actual mixed-job outputs, no v2 persistence or network execution.')
    (HERE/'retention_delivery_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
