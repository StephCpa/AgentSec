import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from public_gateway import PublicGatewayLedger,PUBLIC_DENIALS,response
from public_input import validate_public_response_body
from public_observation import run_trace
from test_public_gateway import PublicGatewayTests,PEER,SERVER_KEY,SERVER_KID,parse_reply
from test_encrypted_mixed_ledger import vault
from test_mixed_delegated_ledger import chain_fixture,packet,KEYS
from test_witness_transport import certificates,public
from wire import decode,encode,sign1
from ledger import Rejected

HERE=Path(__file__).resolve().parent
EVIDENCE={}


class PublicObservationTests(unittest.TestCase):
    setUpClass=classmethod(PublicGatewayTests.setUpClass.__func__)
    tearDownClass=classmethod(PublicGatewayTests.tearDownClass.__func__)
    setUp=PublicGatewayTests.setUp
    tearDown=PublicGatewayTests.tearDown
    raw=PublicGatewayTests.raw
    call=PublicGatewayTests.call
    prepare_submit=PublicGatewayTests.prepare_submit
    submit=PublicGatewayTests.submit
    reject=PublicGatewayTests.reject
    rows=PublicGatewayTests.rows

    def test_authenticated_malformed_payloads_are_durable_generic_denials(self):
        valid=decode(__import__('wire').inspect_sign1(self.prepare_submit())[1])['payload']
        cases=[('CHALLENGE',{'extra':1}),('POLL',{}),('POLL',dict(operation=[])),('POLL',dict(operation=3)),
               ('POLL',dict(operation='x'*65)),('POLL',dict(operation='a',extra=1)),
               ('FINAL',dict(cursor=-1,limit=1)),('FINAL',dict(cursor=2**63,limit=1)),
               ('FINAL',dict(cursor=0,limit=0)),('FINAL',dict(cursor=0,limit=17)),('FINAL',dict(cursor=b'0',limit=1)),
               ('CONTROL',{}),('CONTROL',dict(kind=[])),('CONTROL',dict(kind='cancel',operation=[])),
               ('CONTROL',dict(kind='pause',extra=1)),('CONTROL',dict(kind='revoke')),
               ('SUBMIT',{}),('SUBMIT',dict(valid,action=b'')),('SUBMIT',dict(valid,action=encode('not an action'))),
               ('SUBMIT',dict(valid,proof=b'')),('SUBMIT',dict(valid,chain=[])),('SUBMIT',dict(valid,chain=valid['chain']*3)),
               ('SUBMIT',dict(valid,chain=[b'bad credential']))]
        action=decode(valid['action']);action['capacity']='3';cases.append(('SUBMIT',dict(valid,action=encode(action))))
        for method,payload in cases:
            raw=self.raw(method,payload)
            with patch.object(self.l,'op',side_effect=AssertionError('private op access')),patch.object(self.l,'open_snapshot',side_effect=AssertionError('private snapshot access')):
                reply=self.l.handle_public(raw,PEER,SERVER_KEY)
            out=parse_reply(reply,raw);self.assertEqual((out['status'],out['body']),('REJECTED',{}));self.assertGreater(out['sequence'],0)
            self.assertEqual(self.l.handle_public(raw,PEER,SERVER_KEY),reply)
        self.assertEqual(self.rows(),len(cases)+1);self.assertEqual(self.l.db.execute('SELECT count(*) FROM operations').fetchone()[0],0)
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM used_proofs').fetchone()[0],0);self.assertEqual(self.l.audit(),[])
        EVIDENCE['malformed_payload_cases']=len(cases)

    def test_public_policy_checks_do_not_disconnect_or_consume_proofs(self):
        cases=[dict(capacity=4),dict(recipient='other'),dict(snapshot='absent'),dict(epsilon_max=1),
               dict(catalog='absent'),dict(catalog_digest=b'x'*32),dict(bucket_count=3)]
        for index,changes in enumerate(cases):
            _,_,challenge=self.call('CHALLENGE',{});chain=chain_fixture(self.l);hist=index>=4
            with patch.object(self.l,'issue_challenge',return_value=challenge['body']):raw_action,proof=packet(self.l,chain,'denied'+str(index),hist,**changes)
            raw=self.raw('SUBMIT',dict(action=raw_action,proof=proof,chain=chain));reply=self.l.handle_public(raw,PEER,SERVER_KEY)
            self.assertEqual(parse_reply(reply,raw)['status'],'REJECTED')
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM used_proofs').fetchone()[0],0)
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM operations').fetchone()[0],0);self.assertEqual(self.l.audit(),[])
        EVIDENCE['public_policy_cases']=len(cases)

    def test_revoked_root_is_durable_rejection_instead_of_connection_failure(self):
        self.call('CONTROL',dict(kind='revoke',root='root'),'manager');raw=self.prepare_submit()
        reply=self.l.handle_public(raw,PEER,SERVER_KEY);self.assertEqual(parse_reply(reply,raw)['status'],'REJECTED')
        self.assertEqual(self.l.handle_public(raw,PEER,SERVER_KEY),reply);self.assertEqual(self.l.audit(),[])

    def test_inactive_ancestor_key_is_generic_policy_denial(self):
        raw=self.prepare_submit();self.l.revoke_key('t',b'worker')
        reply=self.l.handle_public(raw,PEER,SERVER_KEY);self.assertEqual(parse_reply(reply,raw)['status'],'REJECTED')
        self.assertEqual(self.l.db.execute('SELECT count(*) FROM used_proofs').fetchone()[0],0);self.assertEqual(self.l.audit(),[])

    def test_changed_operation_action_is_denied_without_new_release(self):
        self.submit('a');_,_,challenge=self.call('CHALLENGE',{});chain=chain_fixture(self.l)
        with patch.object(self.l,'issue_challenge',return_value=challenge['body']):action,proof=packet(self.l,chain,'a',True)
        raw=self.raw('SUBMIT',dict(action=action,proof=proof,chain=chain));reply=self.l.handle_public(raw,PEER,SERVER_KEY)
        self.assertEqual(parse_reply(reply,raw)['status'],'REJECTED');self.assertEqual(self.l.db.execute('SELECT count(*) FROM used_proofs').fetchone()[0],1)
        self.assertEqual(self.l.audit(),[])

    def test_denial_response_restores_without_reparsing_input_or_redispatch(self):
        raw=self.raw('POLL',dict(operation=[]));reply=self.l.handle_public(raw,PEER,SERVER_KEY)
        restored=PublicGatewayLedger.restore_new(self.root/'restore',clock=lambda:100,vault=vault(),witness=self.w)
        try:
            with patch.object(restored,'_dispatch',side_effect=AssertionError('redispatch')):
                self.assertEqual(restored.handle_public(raw,PEER,SERVER_KEY),reply)
            self.assertEqual(restored.audit(),[])
        finally:restored.close()

    def test_private_and_integrity_failures_are_not_in_public_denial_set(self):
        self.submit();codes=['STORAGE_INTEGRITY','WITNESS_RECOVERY_REQUIRED','REGISTERED_COST_MISMATCH','HISTOGRAM_STATE_CONFLICT','INJECTED_PRIVATE_FAILURE']
        for code in codes:
            self.assertNotIn(code,PUBLIC_DENIALS);raw=self.raw('POLL',dict(operation='a'));before=self.l.state_image()
            with patch.object(self.l,'_dispatch',side_effect=Rejected(code)):
                self.reject(code,lambda:self.l.handle_public(raw,PEER,SERVER_KEY))
            self.assertEqual(self.l.state_image(),before);self.assertFalse(self.l._gw_join)
        EVIDENCE['unmapped_internal_failure_cases']=len(codes)

    def test_parser_programming_failure_is_not_disguised_as_bad_input(self):
        raw=self.prepare_submit();before=self.l.state_image()
        with patch('public_input.parse_mixed_action',side_effect=RuntimeError('parser failure')):
            with self.assertRaisesRegex(RuntimeError,'parser failure'):self.l.handle_public(raw,PEER,SERVER_KEY)
        self.assertEqual(self.l.state_image(),before)

    def test_extra_private_response_fields_are_rejected_before_signing_or_journaling(self):
        self.submit();raw=self.raw('POLL',dict(operation='a'));before=self.l.state_image()
        body=dict(operation='a',sequence=1,publication='UNPUBLISHED',final='UNFINALIZED',private_progress=1)
        with patch.object(self.l,'_dispatch',return_value=('POLL',body,{})):
            self.reject('GW_RESPONSE_BODY',lambda:self.l.handle_public(raw,PEER,SERVER_KEY))
        self.assertEqual(self.l.state_image(),before)

    def test_client_also_rejects_signed_out_of_vocabulary_response(self):
        raw=self.raw('POLL',dict(operation='a'))
        obj=dict(profile='agent-public-gateway-v1',deployment=vault().deployment_id,request_hash=hashlib.sha256(raw).digest(),status='POLL',sequence=1,
                 body=dict(operation='a',sequence=1,publication='UNPUBLISHED',final='UNFINALIZED',private_progress=1))
        forged=sign1(encode(obj),SERVER_KID,SERVER_KEY,'AgentPublicResponseV1')
        self.reject('GW_RESPONSE_BODY',lambda:parse_reply(forged,raw))
        malformed=sign1(encode(dict(obj,status=[])),SERVER_KID,SERVER_KEY,'AgentPublicResponseV1')
        self.reject('GW_RESPONSE',lambda:parse_reply(malformed,raw))
        for bad in [dict(operation='a',sequence=1,publication='UNPUBLISHED',final='ACCEPTED'),dict(operation='a',sequence=1,publication='WITHHELD',final='CLOSED')]:
            self.reject('GW_RESPONSE_BODY',lambda:validate_public_response_body('POLL',bad))

    def test_actual_application_wire_traces_match_across_eight_datasets(self):
        runs=[];checks=0
        for scenario in ('normal','cancel_before','cancel_after','pause'):
            group=[run_trace(mask,scenario) for mask in range(8)]
            for a in range(8):
                for b in range(8):
                    if bin(a^b).count('1')==1:
                        self.assertEqual(group[a]['trace'],group[b]['trace']);checks+=1
            for result in group:
                self.assertEqual(result['logical_steps'],88 if scenario=='pause' else 85)
                self.assertEqual(result['output'],1 if scenario in ('normal','pause') else None)
                runs.append({k:v for k,v in result.items() if k not in ('trace','public_events')})
        self.assertEqual(checks,96)
        EVIDENCE['runtime_trace_comparison']=dict(cases=len(runs),datasets=8,public_control_plans=4,directed_neighbor_comparisons=checks,runs=runs,
            scope='Exact equality of complete signed application request/response and delivery/receipt bytes under matched public coins and valid count tapes coupled to output 1. No equality claim for TLS ciphertext, runtime timing, traces with differing approved results, all random tapes or arbitrary adversaries.')

    def test_real_network_negative_controls_expose_private_failure_channel(self):
        folder=self.root/'tls';folder.mkdir();certs=certificates(folder);cases=[]
        for mutant in ('none','private_failure','private_policy_alias'):
            a=run_trace(0,network_fault=mutant,certs=certs);b=run_trace(1,network_fault=mutant,certs=certs)
            self.assertEqual((a['output'],b['output']),(1,1));self.assertEqual(a['trace'][:-1],b['trace'][:-1])
            self.assertEqual(a['network_outcome'],'POLL')
            expected={'none':'POLL','private_failure':'CONNECTION_CLOSED','private_policy_alias':'REJECTED'}[mutant]
            self.assertEqual(b['network_outcome'],expected)
            if mutant=='none':self.assertEqual(a['trace'],b['trace'])
            else:self.assertNotEqual(a['trace'],b['trace'])
            cases.append(dict(mutant=mutant,approved_outputs=[1,1],observations=[a['network_outcome'],b['network_outcome']],same_prefix=True,
                              trace_hashes=[a['trace_sha256'],b['trace_sha256']],tls_versions=[a['tls_version'],b['tls_version']]))
        EVIDENCE['network_negative_controls']=dict(requests=6,cases=cases,
            scope='Actual loopback mTLS. Deliberate private-bit-dependent dispatch mutants after already released identical approved output. These are negative controls, not claimed defects present in normal dispatch. Generic rejection cannot repair an implicit private-data branch; connection closure is also observable.')


def source_hashes():
    pending=['test_public_observation.py'];seen={}
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
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicObservationTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,verification=EVIDENCE,source_sha256=source_hashes(),source_paths_relative_to='delivery root',scope='Public syntax/policy error handling, strict response vocabulary and paired actual-runtime application traces with real-network private-failure negative controls. OBS-4/6/7 not closed by these finite tests.')
    (HERE/'public_observation_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
