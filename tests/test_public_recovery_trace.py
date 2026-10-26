from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from constructive_trace import FixtureSigningOracle
from public_recovery_trace import run_recovery,PLANS,applicable_cuts,EXIT_CODE
from recovery_simulator import RecoverySimulator,CUTS,DURABLE_CUTS
from public_trace_adapter import PublicTraceAdapter,ViewMismatch
from public_gateway import PublicGatewayLedger
from state_relation import StateRelationMismatch,digest
from wire import decode


class PublicRecoveryTests(unittest.TestCase):
    def test_all_six_process_cuts_restore_and_confirm_one_operation(self):
        for cut in CUTS:
            with self.subTest(cut=cut):
                case=run_recovery('submit',cut)
                self.assertEqual(case['diagnostics'],[dict(cut=cut,exit_code=EXIT_CODE,witness_advanced=cut in DURABLE_CUTS,
                    local_committed=cut=='response_drop',stale_guard_blocked=cut in ('after_witness_accept','after_local_anchor_write'))])
                self.assertEqual(case['check']['draws'],[('a','count')])
                self.assertEqual([x['outcome'] for x in case['check']['final']],['ACCEPTED'])
                unavailable=[x for x in case['expected_records'] if x['kind']=='PUBLIC_UNAVAILABLE']
                self.assertEqual(len(unavailable),1)
                self.assertEqual(set(unavailable[0]),{'kind','at','request','peer'})
                checkpoint=next(x for x in case['checkpoints'] if x['kind']=='PUBLIC_CUT')
                self.assertEqual(set(checkpoint['relation']),{'R9'})
                restored=next(x for x in case['checkpoints'] if x['kind']=='RECOVER')
                self.assertEqual(set(restored['relation']),{'R'+str(i) for i in range(1,10)})

    def test_cancel_reservation_vs_started_work_keep_distinct_budget_stages(self):
        for plan,draws in (('cancel_before_l1',[]),('cancel_after_l1',[('a','count')])):
            case=run_recovery(plan,'after_witness_accept')
            self.assertEqual(case['check']['draws'],draws)
            self.assertEqual([x['outcome'] for x in case['check']['final']],['WITHHELD'])

    def test_expired_submit_is_rejected_only_when_no_first_commit_exists(self):
        for cut in CUTS:
            case=run_recovery('expired_submit',cut);committed=cut in DURABLE_CUTS
            self.assertEqual(case['submit_status'],'RECORDED' if committed else 'REJECTED')
            self.assertEqual(len(case['check']['draws']),int(committed))
            self.assertEqual(len(case['check']['final']),int(committed))
            self.assertEqual(case['check']['journal_requests'],3 if committed else 2)

    def test_exact_retry_after_expiry_does_not_register_or_charge_again(self):
        for cut in applicable_cuts('exact_retry'):
            case=run_recovery('exact_retry',cut)
            replies=[x for x in case['expected_records'] if x['kind']=='PUBLIC']
            old=next(x for x in replies if x['at']==100 and x['request']==case['commands'][2]['request'])
            retry=next(x for x in replies if x['at']==161 and x['request']==old['request'])
            self.assertEqual(old['response'],retry['response'])
            self.assertEqual(case['check']['journal_requests'],3)
            self.assertEqual(case['check']['draws'],[('a','count')])

    def test_challenge_denial_histogram_and_final_page_boundaries(self):
        for plan in ('challenge','denied_poll','histogram_submit','final_page'):
            with self.subTest(plan=plan):
                case=run_recovery(plan,'after_public_journal_write')
                self.assertEqual([x['outcome'] for x in case['check']['final']],['ACCEPTED'])
                self.assertEqual(case['check']['draws'],[('a','histogram' if plan=='histogram_submit' else 'count')])

    def test_wrong_commit_classification_is_rejected_after_recovery(self):
        for cut,wrong in (('after_witness_accept',False),('before_witness_accept',True)):
            with self.subTest(cut=cut),patch.object(RecoverySimulator,'commits',return_value=wrong):
                with self.assertRaises(StateRelationMismatch):run_recovery('submit',cut)

    def test_replay_never_reads_real_responses_or_opens_database(self):
        case=run_recovery('submit','after_witness_accept');commands=deepcopy(case['commands'])
        signer=FixtureSigningOracle()
        with patch('sqlite3.connect',side_effect=AssertionError('DB')),patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('runtime')),patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('responses')):
            sim=RecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),case['approved_outputs'],signer)
            generated=sim.generate(commands)
        self.assertEqual(generated,case['expected_records']);self.assertEqual(signer.calls,case['signing_calls'])

    def test_recovery_gate_and_invalid_commands_do_not_mutate_model(self):
        case=run_recovery('submit','after_witness_accept')
        sim=RecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),case['approved_outputs'],FixtureSigningOracle())
        index=next(i for i,x in enumerate(case['commands']) if x['kind']=='PUBLIC_CUT')
        sim.generate(case['commands'][:index]);bad=dict(case['commands'][index],cut='unknown')
        before=deepcopy(sim.state.__dict__)
        with self.assertRaisesRegex(ViewMismatch,'CUT_SCOPE'):sim.emit(bad)
        self.assertEqual(sim.state.__dict__,before)
        sim.emit(case['commands'][index]);before=deepcopy(sim.state.__dict__)
        with self.assertRaisesRegex(ViewMismatch,'RECOVERY_REQUIRED'):sim.emit(case['commands'][index+2])
        with self.assertRaisesRegex(ViewMismatch,'RECOVER_SCOPE'):sim.emit(dict(kind='RECOVER',at=100,image='forbidden'))
        self.assertEqual(sim.state.__dict__,before);self.assertTrue(sim.needs_recovery)
        sim.emit(dict(kind='RECOVER',at=100))
        with self.assertRaisesRegex(ViewMismatch,'RECOVER_SCOPE'):sim.emit(dict(kind='RECOVER',at=100))

    def test_neighbor_datasets_have_same_conditional_fault_observations(self):
        cases=[run_recovery('histogram_submit','after_local_anchor_write',mask) for mask in (0,7)]
        self.assertEqual(cases[0]['expected_records'],cases[1]['expected_records'])
        self.assertEqual(cases[0]['checkpoints'],cases[1]['checkpoints'])

    def test_dispatch_cuts_reject_cached_expired_and_unauthenticated_calls(self):
        case=run_recovery('exact_retry','response_drop')
        for reason in ('cached','expired','unauthenticated'):
            for cut in ('after_public_effect','after_public_journal_write'):
                with self.subTest(reason=reason,cut=cut):
                    sim=RecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),case['approved_outputs'],FixtureSigningOracle())
                    sim.generate(case['commands'][:2 if reason=='cached' else 1])
                    command=dict(case['commands'][2],cut=cut)
                    if reason=='expired':command['at']=161
                    if reason=='unauthenticated':command['peer']=(b'X'*32).hex()
                    before=deepcopy(sim.state.__dict__);records=deepcopy(sim.records)
                    with self.assertRaisesRegex(ViewMismatch,'CUT_NOT_REACHED'):sim.emit(command)
                    self.assertEqual(sim.state.__dict__,before);self.assertEqual(sim.records,records)
                    self.assertFalse(sim.needs_recovery)

if __name__=='__main__':unittest.main()
