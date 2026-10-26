"""Recovery snapshot identity and fencing under an independently committed head."""
from collections import Counter
from pathlib import Path
import sys
import unittest
P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from authority_race_experiment import (PROFILES,MODES,WRITES,CUTS,EARLY,LATE,
                                     run_case,run_commit_race)


class AuthorityRaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases=[run_case(p,m,w,c) for p in PROFILES for m in MODES for w in WRITES for c in CUTS]
        cls.commits=[run_commit_race(p,m,w) for p in PROFILES for m in MODES for w in WRITES]

    def test_full_declared_matrix_and_actual_rival_advancement(self):
        self.assertEqual(len(self.cases),72)
        self.assertEqual(Counter(c['disposition'] for c in self.cases),
                         {'current_snapshot':12,'rollback':24,'stale_snapshot':36})
        for c in self.cases+self.commits:
            self.assertEqual(c['competing_head']['seq'],c['initial_head']['seq']+1)
            self.assertEqual(c['initial_head']['digest']==c['competing_head']['digest'],c['write']=='same_image')

    def test_observed_early_change_rolls_back_both_image_and_anchor(self):
        for c in self.cases:
            if c['cut'] not in EARLY:continue
            self.assertEqual(c['recovery_rejection'],'WITNESS_CHANGED_DURING_RECOVERY')
            self.assertEqual(c['local_before_anchor'],c['local_after_anchor'])
            self.assertEqual(c['local_before_image_digest'],c['local_after_image_digest'])
            if c['mode']=='fresh':self.assertIsNone(c['local_after_anchor'])

    def test_change_before_image_capture_recovers_the_new_snapshot(self):
        for c in self.cases:
            if c['cut']!='before_image_read':continue
            self.assertEqual(c['returned_head'],c['competing_head'])
            self.assertEqual(c['local_after_anchor'],c['competing_head'])
            self.assertEqual(c['local_after_image_digest'],c['competing_head']['digest'])
            self.assertFalse(c['stale_fenced'])

    def test_late_change_is_counterexample_to_success_means_current(self):
        for c in self.cases:
            if c['cut'] not in LATE:continue
            self.assertIsNone(c['recovery_rejection'])
            self.assertEqual(c['returned_head'],c['initial_head'])
            self.assertNotEqual(c['returned_head'],c['competing_head'])
            self.assertEqual(c['local_after_anchor'],c['initial_head'])
            self.assertEqual(c['local_after_image_digest'],c['initial_head']['digest'])
            self.assertTrue(c['stale_fenced'])

    def test_cas_fences_writer_that_passed_begin_guard_before_rival_commit(self):
        self.assertEqual(len(self.commits),12)
        for c in self.commits:
            self.assertEqual(c['rejection'],'WITNESS_CAS_CONFLICT')
            self.assertTrue(c['local_rollback'])

    def test_recovery_and_replay_preserve_tape_budget_and_first_facts(self):
        for c in self.cases+self.commits:
            self.assertTrue(c['protected_evidence_preserved'])
            self.assertTrue(c['retry_image_unchanged'])
            self.assertTrue(c['reopen_current'])
            self.assertEqual(len(c['retry_response_sha256']),64)

    def test_negative_control_skipping_recovery_recheck_is_detected(self):
        for profile in PROFILES:
            with self.subTest(profile=profile),self.assertRaisesRegex(AssertionError,'early race did not reject'):
                run_case(profile,'fresh','changed_image','after_recovery_delete',mutant='skip_recheck')

    def test_negative_control_digest_only_fence_misses_same_image_new_version(self):
        for profile in PROFILES:
            with self.subTest(profile=profile),self.assertRaisesRegex(AssertionError,'missing rejection: WITNESS_RECOVERY_REQUIRED'):
                run_case(profile,'existing','same_image','before_recovery_commit',mutant='ignore_sequence')

    def test_negative_control_omitted_commit_cas_is_detected(self):
        for profile in PROFILES:
            with self.subTest(profile=profile),self.assertRaisesRegex(AssertionError,'missing rejection: WITNESS_CAS_CONFLICT'):
                run_commit_race(profile,'fresh','changed_image',mutant='omit_cas')

    def test_out_of_scope_case_rejected_before_fixture_creation(self):
        with self.assertRaisesRegex(AssertionError,'unsupported case'):
            run_case('unknown','fresh','same_image','after_head_recheck')

if __name__=='__main__':unittest.main()
