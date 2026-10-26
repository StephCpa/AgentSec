"""Failure-domain availability must match runtime, not a global stop rule."""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
P = Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from cross_route_isolation_trace import CrossRouteIsolationRuntime, run_cross_route_isolation, WORKLOADS, ADMISSIONS
from cross_route_isolation_simulator import CrossRouteIsolationSimulator, SIDES, CUTS
from constructive_trace import FixtureSigningOracle
from retirement_recovery_simulator import RetirementRecoverySimulator
from public_trace_adapter import ViewMismatch, PublicTraceAdapter
from public_gateway import PublicGatewayLedger, parse_request
from retention_recipient import RetentionRecipient
from wire import decode


class CrossRouteIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {(s,c,w,a):run_cross_route_isolation(s,c,w,a)
                     for s in SIDES for c in CUTS[s] for w in WORKLOADS for a in ADMISSIONS}

    def simulator(self, x, cls=CrossRouteIsolationSimulator):
        signer=FixtureSigningOracle()
        return cls(decode(bytes.fromhex(x['config_cbor_hex'])),{k:tuple(v) for k,v in x['approved_outputs'].items()},signer),signer

    def case(self, side='receiver', cut='after_witness_accept', workload='count', admission='after_fault'):
        return self.cases[side,cut,workload,admission]

    def prefix_through_fault(self, x):
        sim,signer=self.simulator(x);sim.generate(x['commands'][:x['fault_index']]);return sim,signer

    def test_matrix_has_actual_exit_and_all_state_relations(self):
        self.assertEqual(len(self.cases),24)
        for x in self.cases.values():
            self.assertEqual([d['exit_code'] for d in x['diagnostics']],[97])
            self.assertEqual(len(x['commands']),len(x['expected_records']))
            self.assertEqual(len(x['checkpoints']),len(x['commands'])+1)
            self.assertEqual(x['check']['final'],[
                dict(sequence=1,operation='a',outcome='ACCEPTED'),dict(sequence=2,operation='b',outcome='ACCEPTED')])
            for point in x['checkpoints']:
                self.assertTrue({'R1','R2','R3','R4','R5','R6','R7','R8','R15','R16'} <= set(point['relation']))

    def test_contract_and_two_final_retirement_frontiers(self):
        contract=json.loads((P/'cross-route-isolation-contract.json').read_text())
        self.assertEqual(contract['cuts'],{k:list(v) for k,v in CUTS.items()})
        self.assertEqual(contract['workloads'],list(WORKLOADS));self.assertEqual(contract['admissions'],list(ADMISSIONS))
        self.assertEqual(contract['cases'],len(self.cases)*len(contract['dataset_masks']))
        for x in self.cases.values():
            self.assertEqual(x['check']['frontiers'],{route:dict(high=1,confirmed=1,sender_floor=1,receiver_floor=1) for route in ('root','root2')})

    def test_only_stale_shared_sender_blocks_b_before_recovery(self):
        for (side,cut,workload,admission),x in self.cases.items():
            blocked=side=='sender' and cut=='after_witness_accept'
            self.assertEqual(len(x['before_restore']['final']),1 if blocked else 2)
            self.assertEqual([d[0] for d in x['before_restore']['draws']],['a'] if blocked else ['a','b'])
            self.assertEqual(sum(e['kind']=='PUBLIC_UNAVAILABLE' for e in x['expected_records']),2 if blocked else 0)
            self.assertEqual(sum(e['kind']=='TICK_UNAVAILABLE' for e in x['expected_records']),int(blocked))
            self.assertEqual(x['check']['facts']['b']['event_at'],120 if blocked else 115)
            for event in x['expected_records']:
                if event['kind'] in ('PUBLIC_UNAVAILABLE','TICK_UNAVAILABLE','RETENTION_UNAVAILABLE'):
                    self.assertEqual(event['error'],'WITNESS_RECOVERY_REQUIRED')

    def test_receiver_query_distinguishes_staleness_from_business_denial(self):
        for (side,cut,workload,admission),x in self.cases.items():
            q=x['expected_records'][x['fault_index']]
            if side=='receiver' and cut=='after_witness_accept':
                self.assertEqual(q['kind'],'RETENTION_UNAVAILABLE');self.assertNotIn('reason',q);self.assertNotIn('response',q)
            elif side=='receiver' and cut=='after_v2_recipient_retire_commit':
                self.assertEqual((q['kind'],q['reason']),('RETENTION_QUERY','V2_RETIRED'))
            else:
                self.assertEqual(q['kind'],'RETENTION_QUERY');self.assertIn('response',q)

    def test_exact_retry_and_mechanism_accounting_survive_fault(self):
        for (side,cut,workload,admission),x in self.cases.items():
            submit=[e for e in x['expected_records'] if e['kind']=='PUBLIC' and
                    parse_request(bytes.fromhex(e['request']))['method']=='SUBMIT'][1:]
            self.assertTrue(submit)
            self.assertTrue(all(e['request']==submit[0]['request'] and e['response']==submit[0]['response'] for e in submit))
            self.assertEqual(x['check']['draws'],[('a','count'),('b',workload)])
            self.assertEqual(len(x['check']['mechanism_calls']),2)

    def test_independent_replay_does_not_open_database_or_call_runtime(self):
        with patch('sqlite3.connect',side_effect=AssertionError('DB access')), \
             patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('runtime access')), \
             patch.object(RetentionRecipient,'accept',side_effect=AssertionError('runtime access')), \
             patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('observed reply access')):
            for x in self.cases.values():
                x=json.loads(json.dumps(x));sim,signer=self.simulator(x)
                self.assertEqual(sim.generate(x['commands']),x['expected_records'])
                self.assertEqual(signer.calls,x['signing_calls']);self.assertIsNone(sim.fault);self.assertIsNone(sim.needs_recovery)

    def test_global_stop_mutation_changes_healthy_route_observation(self):
        x=self.case();sim,_=self.prefix_through_fault(x)
        sim.emit(x['commands'][x['fault_index']])
        sim.fault['side']='sender'
        index=x['fault_index']+1
        self.assertNotEqual(sim.emit(x['commands'][index]),x['expected_records'][index])

    def test_stale_sender_bypass_mutation_changes_observation(self):
        x=self.case('sender');sim,_=self.prefix_through_fault(x)
        sim.emit(x['commands'][x['fault_index']])
        sim.fault['stale']=False
        index=x['fault_index']+1
        self.assertNotEqual(sim.emit(x['commands'][index]),x['expected_records'][index])

    def test_stale_recipient_as_business_denial_mutation_changes_observation(self):
        x=self.case();sim,_=self.prefix_through_fault(x);sim.fault['stale']=False
        index=x['fault_index']
        self.assertNotEqual(sim.emit(x['commands'][index]),x['expected_records'][index])

    def test_wrong_recovery_target_is_rejected_without_state_change(self):
        x=self.case();sim,signer=self.prefix_through_fault(x)
        before=deepcopy((sim.state.__dict__,sim.records,sim.projected_records,sim.fault,sim.needs_recovery,signer.calls))
        with self.assertRaisesRegex(ViewMismatch,'RECOVER_SCOPE'):
            sim.emit(dict(kind='RETIRE_RECOVER',at=115,route='root2',side='receiver'))
        self.assertEqual((sim.state.__dict__,sim.records,sim.projected_records,sim.fault,sim.needs_recovery,signer.calls),before)

    def test_malformed_blocked_tick_is_not_a_silent_stutter(self):
        x=self.case('sender');sim,signer=self.prefix_through_fault(x)
        before=deepcopy((sim.state.__dict__,sim.records,sim.fault,sim.needs_recovery,signer.calls))
        with self.assertRaisesRegex(ViewMismatch,'TICK_SCOPE'):
            sim.emit(dict(kind='TICK',at=116,tick=999))
        self.assertEqual((sim.state.__dict__,sim.records,sim.fault,sim.needs_recovery,signer.calls),before)

    def test_original_retirement_profile_remains_strict(self):
        x=self.case();sim,_=self.simulator(x,RetirementRecoverySimulator)
        sim.generate(x['commands'][:x['fault_index']])
        with self.assertRaisesRegex(ViewMismatch,'CLEANUP_ONLY_PROFILE'):
            sim.emit(x['commands'][x['fault_index']+1])

    @contextmanager
    def stale_recipient(self):
        with tempfile.TemporaryDirectory() as td:
            run=CrossRouteIsolationRuntime(td)
            try:
                run.submit();run.finish();run.send();run.confirm();run.now=110
                run.prepare_retirement(1);run.send_retirement(0,1,cut='after_witness_accept')
                yield run
            finally:run.close()

    def test_modified_failed_replica_is_detected(self):
        with self.stale_recipient() as run:
            obj,_,_=run.owner_ret('receiver','root')
            obj.db.execute('UPDATE v2_recipient_meta SET observed=observed+1')
            with self.assertRaisesRegex(AssertionError,'R16.failed_component_changed'):run.relation()

    def test_wrong_authoritative_projection_is_detected(self):
        with self.stale_recipient() as run:
            run.diagnostic_replica.db.execute('UPDATE v2_recipient_meta SET observed=observed+1')
            with self.assertRaisesRegex(AssertionError,'R16.diagnostic_identity'):run.relation()


if __name__=='__main__':unittest.main()
