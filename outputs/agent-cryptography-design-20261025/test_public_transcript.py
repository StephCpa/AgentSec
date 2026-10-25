"""Protocol semantic checks separate from exact DP distribution enumeration."""
import hashlib
import json
from pathlib import Path
import unittest
from fractions import Fraction as F
from public_transcript_model import Plan, DrawNeeded, simulate, mechanism_distribution, trace_distribution
from fixed_work_model import hockey

ROOT=Path(__file__).resolve().parent
DRAWS=[('A','count',(0,)),('B','histogram',(0,0))]


class TranscriptTests(unittest.TestCase):
    def test_normal_simulator_has_no_raw_input_access(self):
        with self.assertRaisesRegex(ValueError,'must not receive raw data'):
            simulate(Plan(),DRAWS,private_slots=(0,0))
        with self.assertRaises(DrawNeeded) as need:simulate(Plan(),[])
        self.assertEqual((need.exception.operation,need.exception.mechanism),('A','count'))

    def test_retry_reuses_output_and_original_acceptance_time(self):
        trace,state=simulate(Plan(transport='drop_ack'),DRAWS)
        self.assertEqual(state['draws'],2)
        for oid in ('A','B'):
            sends=[e for e in trace if e[1:3]==('SEND','DELIVERY') and e[5]==oid]
            received=[e for e in trace if e[1:3]==('RECEIVE','RESULT') and e[5]==oid]
            ack=[e for e in trace if e[1]=='ACK' and e[5]==oid]
            self.assertEqual(len(sends),2);self.assertEqual(sends[0][2:],sends[1][2:])
            self.assertEqual(ack[0][-1],received[0][0])
        self.assertEqual(state['spent'],2)

    def test_pre_start_cancel_refunds_but_keeps_public_work(self):
        normal,_=simulate(Plan(),DRAWS)
        canceled,state=simulate(Plan(control='cancel',control_round=0),DRAWS[:1])
        self.assertEqual((state['draws'],state['free'],state['spent']),(1,1,1))
        self.assertEqual(state['outcomes']['B'],'WITHHELD')
        public_round=lambda trace,oid:next(e[0] for e in trace if e[1]=='JOURNAL' and e[3]==oid)
        self.assertEqual(public_round(normal,'B'),public_round(canceled,'B'))

    def test_post_start_cancel_never_refunds_and_keeps_work(self):
        normal,_=simulate(Plan(),DRAWS)
        trace,state=simulate(Plan(control='cancel',control_round=4),DRAWS)
        self.assertEqual((state['draws'],state['free'],state['spent']),(2,0,2))
        self.assertEqual(state['outcomes']['B'],'WITHHELD')
        self.assertEqual(next(e[0] for e in normal if e[1]=='JOURNAL' and e[3]=='B'),
                         next(e[0] for e in trace if e[1]=='JOURNAL' and e[3]=='B'))

    def test_revocation_blocks_later_admission_preserves_old_ticket(self):
        trace,state=simulate(Plan(control='revoke',control_round=12,transport='reorder'),DRAWS)
        self.assertEqual(state['outcomes'],{'A':'CLOSED','B':'WITHHELD'})
        self.assertTrue(any(e[1:3]==('SEND','TERMINAL') and e[5]=='A' for e in trace))
        self.assertFalse(any(e[1]=='SEND' and e[5]=='B' for e in trace))
        self.assertEqual(state['spent'],2)

    def test_weaker_per_route_comparison_reorders_raw_arrivals(self):
        trace,state=simulate(Plan(transport='reorder',ordering='per_route'),DRAWS)
        decisions=[e for e in trace if e[1]=='JOURNAL']
        received=[e for e in trace if e[1]=='RECEIVE']
        self.assertEqual([e[3] for e in decisions],['A','B'])
        self.assertEqual([e[5] for e in received],['B','A'])
        self.assertEqual(state['outcomes'],{'A':'CLOSED','B':'ACCEPTED'})
        self.assertFalse(any(e[1:3]==('SEND','DELIVERY') and e[5]=='A' for e in trace))

    def test_required_global_gate_preserves_final_order_under_reordering(self):
        trace,state=simulate(Plan(transport='reorder'),DRAWS)
        self.assertEqual([e[5] for e in trace if e[1]=='RECEIVE'],['A','B'])
        self.assertEqual([e[3] for e in trace if e[1]=='APP_FINAL'],['A','B'])
        self.assertEqual(state['outcomes'],{'A':'CLOSED','B':'CLOSED'})

    def test_later_withheld_waits_for_earlier_delivery_but_control_does_not(self):
        trace,_=simulate(Plan(control='cancel',control_round=4,transport='reorder'),DRAWS)
        self.assertIn((4,'REPLY','CONTROL_RECORDED','cancel'),trace)
        finals=[e for e in trace if e[1]=='APP_FINAL']
        self.assertEqual([e[3:] for e in finals],[('A','CLOSED'),('B','WITHHELD')])
        self.assertTrue(all(e[0]>=24 for e in finals))

    def test_same_route_remains_fifo(self):
        trace,_=simulate(Plan(transport='drop_ack',routes=(0,0)),DRAWS)
        first_sequence=[e[4] for e in trace if e[1]=='SEND']
        self.assertEqual(first_sequence,[1,1,2,2])

    def test_permanent_loss_never_fabricates_completion(self):
        trace,state=simulate(Plan(transport='forever_drop'),DRAWS)
        self.assertTrue(state['pending']);self.assertEqual(trace[-1][1:],('PREFIX_END','ACTIVE'))
        self.assertFalse(any(e[1] in ('ACK','RECEIVE') for e in trace))
        self.assertEqual(set(state['outcomes'].values()),{'ADMITTED'})
        self.assertEqual(state['spent'],2)

    def test_adaptive_query_reads_only_already_received_result(self):
        for value,kind,out in [(0,'count',(1,)),(1,'histogram',(1,0))]:
            trace,state=simulate(Plan(query='adaptive'),[('A','count',(value,)),('B',kind,out)])
            received=next(i for i,e in enumerate(trace) if e[1:3]==('RECEIVE','RESULT') and e[5]=='A')
            choice=next(i for i,e in enumerate(trace) if e[1]=='ADAPTIVE_CHOICE')
            self.assertLess(received,choice);self.assertEqual(trace[choice][-1],kind)
            self.assertEqual(state['draws'],2)

    def test_poll_never_returns_private_execution_state(self):
        trace,_=simulate(Plan(),DRAWS)
        forbidden={'READY','PENDING','STARTED','COMMITTED','PARTIAL','FAILED'}
        for e in trace:self.assertFalse(forbidden.intersection(x for x in e if isinstance(x,str)))
        self.assertTrue(any(e[1:3]==('REPLY','RECORDED') and e[-1]=='UNPUBLISHED' for e in trace))

    def test_pause_does_not_delay_control_ack(self):
        trace,state=simulate(Plan(control='pause',control_round=4),DRAWS)
        self.assertIn((4,'REPLY','CONTROL_RECORDED','pause'),trace)
        self.assertFalse(state['pending'])

    def test_K40_public_work_matches_existing_count_and_histogram_shapes(self):
        trace,state=simulate(Plan(k=40,rounds=260),DRAWS)
        self.assertEqual([(e[3],e[0]) for e in trace if e[1]=='JOURNAL'],[('A',166),('B',250)])
        self.assertFalse(state['pending']);self.assertEqual(state['draws'],2)

    def test_count_and_histogram_distributions_are_normalized_and_private(self):
        for kind in ('count','histogram'):
            for k in (1,2,4):
                a=mechanism_distribution((0,1),kind,k);b=mechanism_distribution((2,1),kind,k)
                self.assertEqual(sum(a.values()),1);self.assertEqual(sum(b.values()),1)
                self.assertLessEqual(hockey(a,b,2),F(1,2**(k+1)))
                self.assertLessEqual(hockey(b,a,2),F(1,2**(k+1)))

    def test_K2_adaptive_and_network_traces_meet_separate_bound(self):
        for transport in ('normal','drop_ack','reorder','forever_drop'):
            plan=Plan(query='adaptive',k=2,transport=transport)
            a,_,_=trace_distribution((0,1),plan);b,_,_=trace_distribution((2,1),plan)
            self.assertLessEqual(hockey(a,b,4),F(1,4));self.assertLessEqual(hockey(b,a,4),F(1,4))

    def test_invalid_public_configuration_and_wrong_draw_binding(self):
        for plan in (Plan(query='private'),Plan(transport='hidden'),Plan(k=True),Plan(control_round=True),Plan(rounds=0),Plan(routes=(2,0))):
            with self.assertRaises(ValueError):simulate(plan,DRAWS)
        for draws in ([('B','count',(0,))],[('A','histogram',(0,0))],[('A','count',(True,))]):
            with self.assertRaises(ValueError):simulate(Plan(),draws)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TranscriptTests))
    report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,
                source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                               ['test_public_transcript.py','public_transcript_model.py','fixed_work_model.py']},
                scope='Public protocol simulator semantic tests, not a live service or runtime refinement.')
    (ROOT/'public_transcript_test_results.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
