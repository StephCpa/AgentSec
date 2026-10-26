import copy
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from constructive_trace import run_constructed,FixtureSigningOracle
from restricted_trace import PLANS
from public_simulator import PublicSimulator
from public_trace_adapter import ViewMismatch


class ConstructiveSimulatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.normal=run_constructed('normal');cls.mixed=run_constructed('mixed_cross_route')
    def make(self,run=None,signer=None):
        r=self.normal if run is None else run
        return PublicSimulator(r['config'],r['approved_outputs'],FixtureSigningOracle() if signer is None else signer)

    def test_generates_all_observed_bytes_for_nineteen_public_plans(self):
        for plan in PLANS:
            with self.subTest(plan=plan):
                run=run_constructed(plan)
                self.assertEqual(run['generated'],run['records'])
                self.assertNotIn('response',run['commands'][0])

    def test_adaptive_mechanism_choice_uses_generated_public_output(self):
        for target in range(4):
            with self.subTest(target=target):
                run=run_constructed('adaptive',target=target)
                self.assertEqual(run['check']['draws'],[('a','count'),('b','histogram' if target==1 else 'count')])
                self.assertEqual(run['generated'],run['records'])

    def test_changing_or_removing_observed_records_cannot_change_generation(self):
        run=copy.deepcopy(self.normal);expected=run['generated'];run['records']=['forged observed response'];run['generated']=None
        sim=self.make(run)
        with patch('sqlite3.connect',side_effect=AssertionError('DB access')):
            self.assertEqual(sim.generate(run['commands']),expected)
        run.pop('records')
        self.assertEqual(self.make(run).generate(run['commands']),expected)

    def test_observed_response_or_unknown_private_fields_are_not_commands(self):
        for field in ('response','result','raw_dataset','fact'):
            command=dict(self.normal['commands'][0]);command[field]='hidden'
            with self.assertRaisesRegex(ViewMismatch,'COMMAND_SCOPE'):self.make().emit(command)
        with self.assertRaisesRegex(ViewMismatch,'SIGNING_ORACLE_REQUIRED'):
            self.make(signer=42)

    def test_changed_public_coin_changes_outputs_and_invalidates_old_client_proof(self):
        commands=copy.deepcopy(self.normal['commands'][:2]);commands[0]['challenge_coin']='11'*32
        sim=self.make();records=sim.generate(commands)
        self.assertNotEqual(records[0]['response'],self.normal['records'][0]['response'])
        self.assertEqual(len(sim.state.jobs),0)
        self.assertEqual(sim.state.journal_seq,2)

    def test_signer_wrong_payload_and_unknown_failure_never_become_denials(self):
        good=FixtureSigningOracle()
        def wrong(role,kind,payload,context):
            changed=dict(payload);changed['sequence']=42
            return good(role,kind,changed,context)
        sim=self.make(signer=wrong)
        with self.assertRaisesRegex(ViewMismatch,'SIGNING_ORACLE_PAYLOAD'):sim.emit(self.normal['commands'][0])
        self.assertEqual(sim.records,[]);self.assertEqual(sim.state.journal_seq,0)
        def failed(*args):raise ConnectionError('signing oracle unavailable')
        sim=self.make(signer=failed)
        with self.assertRaises(ConnectionError):sim.emit(self.normal['commands'][0])
        self.assertEqual(sim.records,[]);self.assertEqual(sim.state.journal_seq,0)

    def test_only_approved_output_changes_data_bearing_messages(self):
        original=self.normal
        changed=copy.deepcopy(original);changed['approved_outputs']={'a':(0,)}
        generated=self.make(changed).generate(changed['commands'])
        self.assertEqual([r for r in generated if r['kind']=='PUBLIC'],[r for r in original['records'] if r['kind']=='PUBLIC'])
        self.assertNotEqual([r for r in generated if r['kind']=='DELIVERY'],[r for r in original['records'] if r['kind']=='DELIVERY'])

    def test_before_l1_cancellation_needs_no_output_oracle_call(self):
        run=run_constructed('cancel_before');run['approved_outputs']={}
        sim=self.make(run)
        self.assertEqual(sim.generate(run['commands']),run['records'])
        self.assertEqual(sim.state.mechanism_calls,[])

    def test_exact_request_retry_uses_cached_signed_bytes(self):
        signer=FixtureSigningOracle();sim=self.make(signer=signer)
        cmd=self.normal['commands'][0]
        original=sim.emit(cmd);count=len(signer.calls)
        retry=dict(cmd,at=170)
        repeated=sim.emit(retry)
        self.assertEqual(original['response'],repeated['response'])
        self.assertEqual(len(signer.calls),count)
        self.assertEqual(sim.state.journal_seq,1)

    def test_delivery_without_prior_confirmation_cannot_unlock_second_route(self):
        commands=copy.deepcopy(self.mixed['commands']);second=next(i for i,c in enumerate(commands) if c['kind']=='SEND' and c['operation']=='b')
        first=next(i for i,c in enumerate(commands) if c['kind']=='CONFIRM')
        commands=commands[:first]+[commands[second]]+commands[first:second]+commands[second+1:]
        with self.assertRaisesRegex(ViewMismatch,'SEND_OUTSIDE_FINAL_FRONTIER'):self.make(self.mixed).generate(commands)

    def test_no_receipt_cannot_be_confirmed_and_tick_gaps_reject(self):
        sim=self.make()
        with self.assertRaisesRegex(ViewMismatch,'CONFIRM_WITHOUT_DELIVERED_RECEIPT'):
            sim.emit(dict(kind='CONFIRM',at=100,operation='a'))
        with self.assertRaisesRegex(ViewMismatch,'TICK_GAP_OR_REPLAY'):sim.emit(dict(kind='TICK',at=100,tick=2))

if __name__=='__main__':unittest.main()
