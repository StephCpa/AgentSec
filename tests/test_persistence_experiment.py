import sys
from pathlib import Path
import unittest
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from persistence_experiment import poll_trial,query_trial

class PersistenceMeasurements(unittest.TestCase):
    def test_retry_cas_and_new_request_growth_measured_separately(self):
        for mode in ('new','retry','denial'):
            with self.subTest(mode=mode):
                row=poll_trial(2,mode,samples=2)
                self.assertEqual(row['measurements']['cas_commits'],2)
                self.assertEqual(row['measurements']['state_image_builds'],4)
                self.assertEqual(row['after']['gateway_requests']-row['before']['gateway_requests'],0 if mode=='retry' else 2)
                self.assertGreater(row['measurements']['cas_image_bytes'],0)
                self.assertEqual(row['after']['witness_commit_rows']-row['before']['witness_commit_rows'],2)

    def test_work_slots_and_poll_commits_are_accounted_for(self):
        row=query_trial(poll_every=8)
        self.assertEqual(row['logical_slots'],85)
        self.assertEqual(row['polls'],10)
        self.assertEqual(row['execution']['cas_commits'],95)
        self.assertEqual(row['execution']['state_image_builds'],190)
        self.assertEqual(row['registration']['cas_commits'],2)
        self.assertEqual(row['delivery']['cas_commits'],2)

if __name__=='__main__':unittest.main()
