"""Cross-language acceptance, exact bytes and meaningful validator mutants."""
from pathlib import Path
import json
import sys
import unittest
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from wire_interop import run,negative_controls,corpus


class IndependentWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.report,cls.rows=run()
    @classmethod
    def tearDownClass(cls):del cls.rows

    def test_full_cross_language_corpus(self):
        self.assertTrue(self.report['passed'],[(x['id'],x['error']) for x in self.report['failures'][:10]])
        self.assertGreaterEqual(self.report['cases'],1500)

    def test_node_signatures_and_exact_bytes_checked_in_python(self):
        rows=[r for r in self.rows if r['input']['op']=='sign']
        self.assertEqual(len(rows),20)
        for row in rows:
            self.assertTrue(row['node']['accepted']);self.assertEqual(row['node']['result'],row['python']['result'])

    def test_frozen_response_vectors_include_original_audience_regression(self):
        frozen=[r for r in self.rows if r['group']=='frozen-public']
        old=json.loads((Path(__file__).parent/'vectors/public-responses.json').read_text())
        self.assertEqual(len(frozen),len(old['vectors']))
        bad=next(r for r in frozen if r['id'].endswith('audience-other-gateway-v1'))
        self.assertFalse(bad['node']['accepted']);self.assertFalse(bad['python']['accepted'])

    def test_uint64_bom_and_bytewise_map_order_match_handwritten_bytes(self):
        for name in ('uint64','negative64','bom-preserved','mixed-map-order'):
            row=next(r for r in self.rows if r['id']=='canonical:'+name)
            self.assertTrue(row['node']['accepted']);self.assertEqual(row['node']['result'],row['python']['result'])

    def test_six_semantic_negative_controls_are_detected(self):
        result=negative_controls()
        self.assertTrue(result['passed']);self.assertEqual(len(result['controls']),6)
        self.assertTrue(all(c['detected'] and c['mismatch_count'] for c in result['controls']))

if __name__=='__main__':unittest.main()
