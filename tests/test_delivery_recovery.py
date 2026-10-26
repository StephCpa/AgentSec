"""Actual process cuts, first-fact preservation and simulator negative controls."""
from copy import deepcopy
from pathlib import Path
import sys
import json
import unittest
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from delivery_recovery_trace import run_delivery_recovery,applicable_cuts,DeliveryRecoveryRuntime
from delivery_recovery_simulator import DeliveryRecoverySimulator,DURABLE_CUTS
from constructive_trace import FixtureSigningOracle
from wire import decode
from public_trace_adapter import ViewMismatch
from state_relation import StateRelationMismatch


class DeliveryRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases={}
        pairs=[('receive_count',c) for c in applicable_cuts('receive_count')]+[('confirm_count',c) for c in applicable_cuts('confirm_count')]
        pairs += [(p,c) for p in ('receive_expire','receive_existing','receive_terminal','receive_histogram','receive_cross_route','confirm_histogram','confirm_expired','confirm_withheld_tail','confirm_cross_route') for c in ('before_witness_accept','after_witness_accept')]
        pairs += [('confirm_exact_retry',c) for c in applicable_cuts('confirm_exact_retry')]
        for pair in pairs:cls.cases[pair]=run_delivery_recovery(*pair)

    @classmethod
    def tearDownClass(cls):del cls.cases

    def replay(self,case):
        signer=FixtureSigningOracle();sim=DeliveryRecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),{k:tuple(v) for k,v in case['approved_outputs'].items()},signer)
        self.assertEqual(sim.generate(case['commands']),case['expected_records'])
        self.assertEqual(signer.calls,case['signing_calls']);self.assertIsNone(sim.needs_recovery)
        return sim

    def test_all_actual_cut_locations_exit_and_project_authority(self):
        for (plan,cut),case in self.cases.items():
            d=case['diagnostics'][0];self.assertEqual(d['exit_code'],95)
            self.assertEqual(d['witness_advanced'],cut in DURABLE_CUTS)
            self.assertEqual(d['stale_guard_blocked'],cut in ('after_witness_accept','after_local_anchor_write'))
            self.assertTrue(d['other_authority_unchanged'])
            fault=next(x for x in case['checkpoints'] if x['kind'].endswith('_CUT'))
            self.assertEqual(set(fault['relation']),{'R1','R2','R3','R4','R5','R6','R7','R8','R11'})

    def test_cut_observation_does_not_reveal_commit_outcome(self):
        for plan in ('receive_count','confirm_count'):
            events=[]
            for cut in ('before_witness_accept','after_witness_accept'):
                case=self.cases[(plan,cut)]
                events.append(next(e for e in case['expected_records'] if e['kind'].endswith('_UNAVAILABLE')))
            self.assertEqual(*events)

    def test_expired_retry_preserves_first_fact_or_closes_absent_fact(self):
        before=self.cases[('receive_expire','before_witness_accept')]['check']['facts']['a']
        after=self.cases[('receive_expire','after_witness_accept')]['check']['facts']['a']
        self.assertEqual((before['outcome'],before['event_at']),('CLOSED',170))
        self.assertEqual((after['outcome'],after['event_at']),('ACCEPTED',100))
        for p in ('receive_existing','confirm_expired'):
            for cut in ('before_witness_accept','after_witness_accept'):
                fact=self.cases[(p,cut)]['check']['facts']['a'];self.assertEqual((fact['outcome'],fact['event_at']),('ACCEPTED',100))

    def test_terminal_first_event_and_histogram_are_covered(self):
        for c in ('before_witness_accept','after_witness_accept'):
            self.assertEqual(self.cases[('receive_terminal',c)]['check']['facts']['a']['outcome'],'CLOSED')
            for p in ('receive_histogram','confirm_histogram'):
                self.assertEqual(self.cases[(p,c)]['check']['draws'],[('a','histogram')])

    def test_cross_route_and_withheld_tail_final_prefix(self):
        for c in ('before_witness_accept','after_witness_accept'):
            for p in ('receive_cross_route','confirm_cross_route'):
                self.assertEqual([e['outcome'] for e in self.cases[(p,c)]['check']['final']],['ACCEPTED','ACCEPTED'])
            case=self.cases[('confirm_withheld_tail',c)]
            self.assertEqual([e['outcome'] for e in case['check']['final']],['ACCEPTED','WITHHELD'])
            sim=self.replay(case);self.assertEqual(len(sim.state.final),2)

    def test_confirmation_retries_preserve_request_and_receipt(self):
        for (p,c),case in self.cases.items():
            if not p.startswith('confirm_'):continue
            event=next(e for e in case['expected_records'] if e['kind']=='CONFIRM_UNAVAILABLE')
            retry=next(e for e in case['expected_records'][case['expected_records'].index(event)+1:] if e['kind']=='CONFIRM')
            self.assertEqual((event['request'],event['response']),(retry['request'],retry['response']))

    def test_all_archived_style_inputs_replay_without_runtime(self):
        with patch('sqlite3.connect',side_effect=AssertionError('DB forbidden')):
            for case in self.cases.values():self.replay(json.loads(json.dumps(case)))

    def test_recovery_gate_scope_and_unreachable_hooks(self):
        case=self.cases[('receive_count','after_witness_accept')];sim=DeliveryRecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),case['approved_outputs'],FixtureSigningOracle())
        for c in case['commands']:
            sim.emit(c)
            if c['kind']=='RECEIVE_CUT':break
        with self.assertRaises(ViewMismatch):sim.emit(dict(kind='TICK',at=100,tick=sim.state.tick+1))
        with self.assertRaises(ViewMismatch):sim.emit(dict(kind='DELIVERY_RECOVER',at=100,operation='a',side='sender'))
        with self.assertRaises(ViewMismatch):sim.emit(dict(kind='DELIVERY_RECOVER',at=100,operation='a',side='receiver',image='private'))
        sim.emit(dict(kind='DELIVERY_RECOVER',at=100,operation='a',side='receiver'))
        with self.assertRaises(ViewMismatch):sim.emit(dict(kind='DELIVERY_RECOVER',at=100,operation='a',side='receiver'))
        with self.assertRaises(ValueError):run_delivery_recovery('receive_existing','after_v2_recipient_record')
        with self.assertRaises(ValueError):run_delivery_recovery('confirm_exact_retry','before_final_event_write')

    def test_wrong_commit_boundary_mutant_is_detected(self):
        # A generator that treats pre-witness receiver exit as durable invents
        # an ACCEPTED fact. The post-expiry actual execution produces CLOSED.
        case=self.cases[('receive_expire','before_witness_accept')]
        with patch('delivery_recovery_simulator.DURABLE_CUTS',DURABLE_CUTS|{'before_witness_accept'}):
            sim=DeliveryRecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),case['approved_outputs'],FixtureSigningOracle())
            generated=sim.generate(case['commands'])
        self.assertNotEqual(generated,case['expected_records'])

    def test_premature_sender_confirmation_mutant_is_detected(self):
        case=self.cases[('confirm_count','before_final_event_write')]
        with patch('delivery_recovery_simulator.DURABLE_CUTS',DURABLE_CUTS|{'before_final_event_write'}):
            sim=DeliveryRecoverySimulator(decode(bytes.fromhex(case['config_cbor_hex'])),case['approved_outputs'],FixtureSigningOracle())
            generated=sim.generate(case['commands'])
        self.assertNotEqual(generated,case['expected_records'])

    def test_authoritative_relation_rejects_invented_recipient_fact(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            r=DeliveryRecoveryRuntime(td)
            try:
                r.submit();r.finish();r.send()
                r.simulator.state.receiver.clear()
                with self.assertRaises(StateRelationMismatch):r.relation()
            finally:r.close()

    def test_conditioned_empty_and_full_rosters_agree(self):
        for p,c in [('receive_expire','after_witness_accept'),('confirm_withheld_tail','before_witness_accept')]:
            a=run_delivery_recovery(p,c,0);b=run_delivery_recovery(p,c,7)
            self.assertEqual(a['expected_records'],b['expected_records']);self.assertEqual(a['checkpoints'],b['checkpoints'])

if __name__=='__main__':unittest.main()
