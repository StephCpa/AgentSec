"""Composed failure/restore exits, stutter contract and independent scope checks."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from recovery_interruption_trace import run_interrupted,SCENARIOS
from recovery_interruption_simulator import RecoveryInterruptionSimulator,REPEATED_CUTS
from recovery_simulator import RecoverySimulator
from kernel_recovery_simulator import KernelRecoverySimulator
from delivery_recovery_simulator import DeliveryRecoverySimulator
from constructive_trace import FixtureSigningOracle
from public_trace_adapter import ViewMismatch
from wire import decode


def generator(case,wrapper=RecoveryInterruptionSimulator):
    signer=FixtureSigningOracle();cls={'public':RecoverySimulator,'kernel':KernelRecoverySimulator,'delivery':DeliveryRecoverySimulator}[case['family']]
    return wrapper(cls(decode(bytes.fromhex(case['config_cbor_hex'])),{k:tuple(v) for k,v in case['approved_outputs'].items()},signer)),signer


class RecoveryInterruptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.cases={(s,m):run_interrupted(s,m) for s in SCENARIOS for m in ('existing','fresh')}
    @classmethod
    def tearDownClass(cls):del cls.cases

    def test_all_three_recovery_hooks_repeat_twice_with_real_exits(self):
        for case in self.cases.values():
            ds=case['recovery_diagnostics'];self.assertEqual([d['cut'] for d in ds],list(REPEATED_CUTS))
            self.assertTrue(all(d['exit_code']==96 and d['authority_unchanged'] and d['local_atomicity'] and d['business_dispatch_guarded'] for d in ds))
            cps=[c for c in case['checkpoints'] if c['kind']=='RECOVERY_CUT'];self.assertEqual(len(cps),6)
            for cp in cps:self.assertTrue({'R1','R2','R3','R4','R5','R6','R7','R8','R12'}<=set(cp['relation']))

    def test_fresh_replica_keeps_empty_anchor_until_recovery_commit(self):
        for (s,mode),case in self.cases.items():
            if mode!='fresh':continue
            ds=case['recovery_diagnostics']
            self.assertEqual([d['anchor_present'] for d in ds],[False,False,True,True,True,True])
            self.assertEqual([d['stale_guard_blocked'] for d in ds],[True,True,False,False,False,False])
            self.assertEqual([d['local_commit'] for d in ds],[False,False,True,False,False,True])

    def test_existing_current_and_stale_replicas_are_distinguished(self):
        pre=self.cases[('public_submit_pre','existing')]['recovery_diagnostics']
        post=self.cases[('public_submit_post','existing')]['recovery_diagnostics']
        self.assertTrue(all(d['local_current'] for d in pre))
        self.assertEqual([d['local_current'] for d in post],[False,False,True,True,True,True])

    def test_recovery_is_logical_stutter_even_after_local_commit(self):
        for case in self.cases.values():
            sim,_=generator(case)
            for command in case['commands']:
                if command['kind']=='RECOVERY_CUT':
                    before=deepcopy(sim.state.__dict__);pending=deepcopy(sim.base.__dict__.get('pending_tick'));target=sim.target();receipts=deepcopy(sim.pending)
                    sim.emit(command)
                    before['now']=command['at'];self.assertEqual(sim.state.__dict__,before)
                    self.assertEqual(sim.target(),target);self.assertEqual(sim.pending,receipts);self.assertEqual(sim.base.__dict__.get('pending_tick'),pending)
                else:sim.emit(command)

    def test_json_roundtrip_replays_without_database(self):
        with patch('sqlite3.connect',side_effect=AssertionError('DB forbidden')):
            for case in self.cases.values():
                archived=json.loads(json.dumps(case));sim,signer=generator(archived)
                self.assertEqual(sim.generate(archived['commands']),archived['expected_records'])
                self.assertEqual(signer.calls,archived['signing_calls']);self.assertFalse(sim.needs_recovery)

    def test_private_l1_and_final_recovery_do_not_resample_or_refund(self):
        for s in ('count_l1_pre','histogram_l1_post','count_final_pre','histogram_final_post'):
            for mode in ('existing','fresh'):
                case=self.cases[(s,mode)];self.assertEqual(case['check']['committed_draws'],1)
                self.assertEqual(case['check']['discarded_draws'],int(s=='count_l1_pre'))
                cps=[c for c in case['checkpoints'] if c['kind']=='RECOVERY_CUT'];self.assertTrue(all('R10' in c['relation'] for c in cps))

    def test_expired_receiver_recovery_preserves_authoritative_first_fact(self):
        for mode in ('existing','fresh'):
            pre=self.cases[('receive_expire_pre',mode)]['check']['facts']['a']
            post=self.cases[('receive_expire_post',mode)]['check']['facts']['a']
            self.assertEqual((pre['outcome'],pre['event_at']),('CLOSED',170));self.assertEqual((post['outcome'],post['event_at']),('ACCEPTED',100))
            self.assertEqual([x['outcome'] for x in self.cases[('confirm_withheld_pre',mode)]['check']['final']],['ACCEPTED','WITHHELD'])
            self.assertEqual([x['outcome'] for x in self.cases[('confirm_cross_post',mode)]['check']['final']],['ACCEPTED','ACCEPTED'])

    def test_extra_private_fields_wrong_target_and_no_pending_recovery_reject(self):
        case=self.cases[('public_submit_post','fresh')];sim,_=generator(case)
        cut=next(c for c in case['commands'] if c['kind']=='RECOVERY_CUT')
        with self.assertRaises(ViewMismatch):sim.emit(cut)
        for c in case['commands']:
            if c['kind']=='RECOVERY_CUT':break
            sim.emit(c)
        for changed in (dict(cut,image='private'),dict(cut,side='receiver'),dict(cut,cut='unknown'),dict(cut,at=99)):
            before=deepcopy(sim.state.__dict__)
            with self.assertRaises(ViewMismatch):sim.emit(changed)
            self.assertEqual(sim.state.__dict__,before)
        with self.assertRaises(ViewMismatch):sim.emit(dict(kind='TICK',at=100,tick=1))

    def test_mutant_treating_interruption_as_success_is_detected(self):
        class PrematureRecovery(RecoveryInterruptionSimulator):
            def emit(self,c):
                if c.get('kind')=='RECOVERY_CUT':self.base.needs_recovery=False
                return super().emit(c)
        sim,_=generator(self.cases[('public_submit_post','fresh')],PrematureRecovery)
        with self.assertRaises(ViewMismatch):sim.generate(self.cases[('public_submit_post','fresh')]['commands'])

    def test_mutant_advancing_private_tick_during_restore_is_detected(self):
        class ExtraTick(RecoveryInterruptionSimulator):
            def emit(self,c):
                e=super().emit(c)
                if c.get('kind')=='RECOVERY_CUT':self.state.tick+=1
                return e
        case=self.cases[('histogram_l1_post','existing')];sim,_=generator(case,ExtraTick)
        with self.assertRaises(ViewMismatch):sim.generate(case['commands'])

    def test_existing_and_fresh_replica_modes_have_identical_public_view(self):
        for s in SCENARIOS:self.assertEqual(self.cases[(s,'existing')]['expected_records'],self.cases[(s,'fresh')]['expected_records'])

    def test_empty_and_full_rosters_have_same_conditioned_recovery_trace(self):
        a=run_interrupted('receive_expire_post','fresh',0);b=run_interrupted('receive_expire_post','fresh',7)
        self.assertEqual(a['expected_records'],b['expected_records']);self.assertEqual(a['checkpoints'],b['checkpoints'])

if __name__=='__main__':unittest.main()
