"""Finite profile correspondence and deliberately invalid observation controls."""
import copy
import hashlib
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from restricted_trace import PLANS,run_plan
from public_trace_adapter import PublicTraceAdapter,ViewMismatch
from public_gateway import RESPONSE_TYPE
from wire import verify_sign1,encode,sign1
from test_public_gateway import SERVER_KEY,SERVER_KID
from test_witness_transport import public


def replay(run,records=None,oracle=None):
    with patch('sqlite3.connect',side_effect=AssertionError('checker DB access')):
        return PublicTraceAdapter(run['config'],run['approved_outputs'] if oracle is None else oracle).check(run['records'] if records is None else records)


def resign(event,change):
    out=copy.deepcopy(event)
    _,obj=verify_sign1(bytes.fromhex(out['response']),public(SERVER_KEY),RESPONSE_TYPE)
    change(obj)
    out['response']=sign1(encode(obj),SERVER_KID,SERVER_KEY,RESPONSE_TYPE).hex()
    return out


class RestrictedTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.normal=run_plan('normal');cls.retry=run_plan('retry_and_denial');cls.mixed=run_plan('mixed_cross_route')

    def test_frozen_scenario_matrix_and_oracle_l1_binding(self):
        for plan in PLANS:
            with self.subTest(plan=plan):
                run=run_plan(plan);check=run['check']
                self.assertEqual([c['l1_tick'] for c in check['mechanism_calls']],[x[2] for x in run['runtime_draws']])
                self.assertEqual(check['pending'],plan=='permanent_loss')
                self.assertEqual(len(check['draws']),0 if plan in ('cancel_before','revoke_before') else 2 if plan.startswith('mixed_') or plan=='adaptive' else 1)

    def test_eight_neighbor_inputs_have_identical_conditioned_observations(self):
        runs=[run_plan('normal',mask) for mask in range(8)]
        self.assertTrue(all(run['records']==runs[0]['records'] for run in runs))

    def test_missing_or_replayed_tick_and_unknown_management_event_rejected(self):
        source=self.normal['records'];index=next(i for i,e in enumerate(source) if e['kind']=='TICK')
        for changed in (source[:index]+source[index+1:],source[:index]+[source[index]]+source[index:],
                        source+[dict(kind='KEY_REVOKE',at=100,kid='worker')]):
            with self.assertRaises(ViewMismatch):replay(self.normal,changed)
        changed=copy.deepcopy(source);changed[index]['tick']=True
        with self.assertRaises(ViewMismatch):replay(self.normal,changed)

    def test_early_publication_and_wrong_final_are_rejected_even_with_valid_signature(self):
        source=self.normal['records']
        for target,status in [('POLL','ADMITTED'),('FINAL','CLOSED')]:
            changed=copy.deepcopy(source)
            if target=='POLL':
                i=next(i for i,e in enumerate(source) if e['kind']=='PUBLIC' and verify_sign1(bytes.fromhex(e['response']),public(SERVER_KEY),RESPONSE_TYPE)[1]['status']=='POLL')
                changed[i]=resign(source[i],lambda o:o['body'].update(publication=status))
            else:
                i=len(source)-1
                changed[i]=resign(source[i],lambda o:o['body']['events'][0].update(outcome=status))
            with self.assertRaisesRegex(ViewMismatch,'PUBLIC_RESPONSE_MISMATCH'):replay(self.normal,changed)

    def test_receipt_does_not_stand_for_sender_durable_confirmation(self):
        changed=[e for e in self.normal['records'] if e['kind']!='CONFIRM']
        with self.assertRaisesRegex(ViewMismatch,'PUBLIC_RESPONSE_MISMATCH'):replay(self.normal,changed)
        first_confirm=next(e for e in self.normal['records'] if e['kind']=='CONFIRM')
        with self.assertRaisesRegex(ViewMismatch,'CONFIRM_WITHOUT_OBSERVED_RECEIPT'):replay(self.normal,[first_confirm])

    def test_changed_retry_and_private_error_alias_are_rejected(self):
        source=self.retry['records'];seen={};index=None
        for i,e in enumerate(source):
            if e['kind']=='PUBLIC' and e['request'] in seen:index=i;break
            if e['kind']=='PUBLIC':seen[e['request']]=i
        changed=copy.deepcopy(source);changed[index]=resign(source[index],lambda o:o.update(status='REJECTED',body={}))
        with self.assertRaisesRegex(ViewMismatch,'RETRY_RESPONSE_CHANGED'):replay(self.retry,changed)
        source=self.normal['records'];changed=copy.deepcopy(source)
        i=next(i for i,e in enumerate(source) if e['kind']=='PUBLIC' and verify_sign1(bytes.fromhex(e['response']),public(SERVER_KEY),RESPONSE_TYPE)[1]['status']=='POLL')
        changed[i]=resign(source[i],lambda o:o.update(status='REJECTED',body={}))
        with self.assertRaisesRegex(ViewMismatch,'PUBLIC_RESPONSE_MISMATCH'):replay(self.normal,changed)
        changed[i]=dict(source[i],response='CONNECTION_CLOSED')
        with self.assertRaisesRegex(ViewMismatch,'UNEXPLAINED_CONNECTION_FAILURE'):replay(self.normal,changed)

    def test_wrong_or_missing_mechanism_output_and_private_extra_fields_rejected(self):
        for oracle in ({},{'a':(0,)}):
            with self.assertRaises(ViewMismatch):replay(self.normal,oracle=oracle)
        changed=copy.deepcopy(self.normal['records']);changed[0]['private_state']=42
        with self.assertRaisesRegex(ViewMismatch,'EVENT_SCOPE'):replay(self.normal,changed)
        config=dict(self.normal['config'],raw_dataset=[1,1,0])
        with self.assertRaisesRegex(ViewMismatch,'CONFIGURATION_SCOPE'):PublicTraceAdapter(config,{'a':(1,)})

    def test_cross_route_send_requires_previous_sender_confirmation(self):
        source=self.mixed['records'];changed=copy.deepcopy(source)
        a=next(i for i,e in enumerate(source) if e['kind']=='CONFIRM')
        b=next(i for i,e in enumerate(source) if i>a and e['kind']=='DELIVERY')
        changed=source[:a]+[source[b]]+source[a:b]+source[b+1:]
        with self.assertRaisesRegex(ViewMismatch,'CROSS_ROUTE_FINAL_ORDER'):replay(self.mixed,changed)

if __name__=='__main__':unittest.main()
