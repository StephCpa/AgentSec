import ast
import hashlib
import json
from pathlib import Path
import platform
import unittest
import cryptography
from ledger import Rejected
from p2_scenario import run_scenario,writer_report
from test_retention_sender import context
import retention_delivery as d
import retention_wire as r

HERE=Path(__file__).parent


class P2ScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report,cls.inputs=run_scenario()
        (HERE/'p2_scenario_results.json').write_text(json.dumps(cls.report,ensure_ascii=False,indent=2)+'\n')

    def test_complete_reference_workflow_has_each_required_stage(self):
        stages=[x['stage'] for x in self.report['events']]
        self.assertEqual(stages,['user_authorization','concurrent_shared_admission','shared_cap_blocks_third_query',
            'committed_reply_loss_and_retry','committed_outputs_then_delivery_admission',
            'revocation_blocks_new_delivery','original_results_delivered','writer_uses_only_authenticated_outputs',
            'audit_matches_consumption_and_output'])
        self.assertEqual(self.report['randomness_draws'],{'analysis_hist':1,'analysis_count':1})
        self.assertEqual(self.report['budget']['charge_rows'],16)
        self.assertEqual(self.report['budget']['checked_accounts'],10)
        self.assertFalse(self.report['full_p2_production_acceptance'])

    def test_writer_reproduces_only_authenticated_admitted_outputs(self):
        self.assertEqual(writer_report(**self.inputs),self.report['writer'])
        self.assertEqual({x['operation']:len(x['values']) for x in self.report['writer']['records']},
            {'analysis_hist':4,'analysis_count':1})

    def test_writer_rejects_missing_ack_or_added_raw_input(self):
        for item in [dict(request=self.inputs['evidence'][0]['request']),dict(self.inputs['evidence'][0],snapshot=[1,2,0])]:
            with self.assertRaisesRegex(Rejected,'WRITER_INPUT'):
                writer_report(self.inputs['context'],[item],self.inputs['expected_operations'])

    def test_writer_rejects_modified_receipt_and_cross_operation_reply(self):
        c=self.inputs['context'];e=self.inputs['evidence'];bad=bytearray(e[0]['ack']);bad[-1]^=1
        for item in [dict(request=e[0]['request'],ack=bytes(bad)),dict(request=e[0]['request'],ack=e[1]['ack'])]:
            with self.assertRaises(Rejected):writer_report(c,[item,e[1]],self.inputs['expected_operations'])

    def test_writer_rejects_unlisted_missing_or_duplicate_operations(self):
        c=self.inputs['context'];e=self.inputs['evidence'];ops=self.inputs['expected_operations']
        for evidence,allowed,code in [(e,ops+['unauthorized'],'WRITER_OPERATION_SET'),
                                      (e[:1],ops,'WRITER_OPERATION_SET'),
                                      (e+[e[0]],ops,'WRITER_DUPLICATE'),
                                      (e,ops+ops,'WRITER_OPERATION_SET')]:
            with self.assertRaisesRegex(Rejected,code):writer_report(c,evidence,allowed)

    def test_writer_rejects_terminal_evidence_even_with_valid_accepted_fact(self):
        c=self.inputs['context'];e=self.inputs['evidence'];_,s,k=context()
        original=d.parse_attempt(e[0]['request'],c);env=d.parse_envelope(original['body'],c)
        fact=d.parse_receipt(e[0]['ack'],e[0]['request'],c)
        ctl=d.control(env['descriptor'],r.sha(original['body']),c,s)
        request=d.attempt('TERMINAL',ctl,b't'*32,c,s);ack=d.receipt(fact,request,c,k)
        with self.assertRaisesRegex(Rejected,'WRITER_RESULT_REQUIRED'):
            writer_report(c,[dict(request=request,ack=ack),e[1]],self.inputs['expected_operations'])

    def test_writer_rejects_changed_route_epoch(self):
        with self.assertRaises(Rejected):
            writer_report(dict(self.inputs['context'],epoch=b'x'*16),self.inputs['evidence'],self.inputs['expected_operations'])

    def test_scenario_reports_transport_and_limits_without_performance_claim(self):
        self.assertGreater(self.report['network_requests']['sender_witness'],0)
        self.assertGreater(self.report['network_requests']['receiver_witness'],0)
        self.assertEqual(self.report['network_requests']['delivery'],4)
        self.assertTrue(self.report['observed_tls_versions'])
        self.assertFalse(self.report['public_observation_proof']);self.assertFalse(self.report['strong_baselines'])
        self.assertNotIn('p95_latency',self.report)


def source_hashes():
    pending=['test_p2_scenario.py'];seen={}
    while pending:
        name=pending.pop();path=HERE/name
        if name in seen or not path.exists():continue
        raw=path.read_bytes();seen[name]=hashlib.sha256(raw).hexdigest()
        for node in ast.walk(ast.parse(raw)):
            mods=[x.name for x in node.names] if isinstance(node,ast.Import) else ([node.module] if isinstance(node,ast.ImportFrom) else [])
            pending.extend(mod.split('.')[0]+'.py' for mod in mods if mod)
    return seen


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(P2ScenarioTests))
    scenario_path=HERE/'p2_scenario_results.json'
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,source_sha256=source_hashes(),
        python=platform.python_version(),cryptography=cryptography.__version__,
        scenario_report=scenario_path.name,scenario_report_sha256=hashlib.sha256(scenario_path.read_bytes()).hexdigest(),
        scope='One complete synthetic reference workflow plus writer input-boundary rejection tests. Two concurrent signed role clients, loopback mTLS authorities/delivery, committed-response loss, fixed-result retry, revoke, reporting and account audit. No real LLM isolation, full P2 production acceptance or strong baselines.')
    (HERE/'p2_scenario_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
