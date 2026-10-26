import sys
from pathlib import Path
import unittest
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from compression_experiment import query_trial

class CompressionMeasurements(unittest.TestCase):
    def test_paired_transport_restores_identical_state_and_preserves_cas_count(self):
        row=query_trial(poll_every=8,samples=2)
        self.assertEqual((row['logical_slots'],row['polls']),(85,10))
        self.assertEqual([row['stream'][p]['commits'] for p in ('registration','execution','delivery')],[2,95,2])
        a,b=row['snapshot_trials']
        for trial in (a,b):
            self.assertEqual(trial['restored_image_hash'],row['final_image_hash'])
            self.assertEqual(trial['restored_relation'],row['source_relation'])
            self.assertEqual(trial['witness_raw_image_bytes'],row['final_image_bytes'])
            self.assertEqual(trial['witness_commit_rows'],2)
            for key in ('cas_frames','get_image_frames'):
                self.assertEqual([f['frames'] for f in trial[key]],[2,2])
        self.assertLess(b['cas_frames'][0]['request_bytes'],a['cas_frames'][0]['request_bytes'])
        self.assertLess(b['get_image_frames'][0]['response_bytes'],a['get_image_frames'][0]['response_bytes'])
        # Empty request body and empty signed CAS reply gain a 4-byte header.
        self.assertEqual(b['cas_frames'][0]['response_bytes']-a['cas_frames'][0]['response_bytes'],4)
        self.assertEqual(b['get_image_frames'][0]['request_bytes']-a['get_image_frames'][0]['request_bytes'],4)

if __name__=='__main__':unittest.main()
