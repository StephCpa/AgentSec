"""Check complete, disjoint CI shards and fail-closed command execution."""
from collections import Counter
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('verification_runner',ROOT/'scripts'/'verify.py')
verify=importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class VerificationRunnerTests(unittest.TestCase):
    def test_four_shards_cover_every_command_exactly_once(self):
        commands=verify.build_commands(ROOT,models=True)
        shards=[verify.select_shard(commands,i,4) for i in range(4)]
        self.assertEqual(Counter(n for shard in shards for n,_ in shard),
                         Counter(n for n,_ in commands))
        self.assertEqual(len({n for n,_ in commands}),len(commands))
        self.assertEqual(verify.select_shard(commands,0,1),commands)
        self.assertTrue(all(shards))

    def test_invalid_or_empty_shards_fail(self):
        commands=[('a',[])]
        for index,count in [(-1,4),(4,4),(0,0),(0,-1),(1,4)]:
            with self.subTest(index=index,count=count),self.assertRaises(ValueError):
                verify.select_shard(commands,index,count)

    def test_only_preserves_all_regressions_and_requested_models(self):
        all_commands=verify.build_commands(ROOT,models=True)
        selected=verify.build_commands(ROOT,['test_ledger.py'],models=True)
        expected=[x for x in all_commands if x[0]=='test_ledger' or
                  x[0].startswith('review_') or x[0]+'.py' in verify.MODELS]
        self.assertEqual(selected,expected)
        with self.assertRaises(ValueError):verify.build_commands(ROOT,['missing_test.py'])

    def test_module_discovery_preserves_all_unittest_ids(self):
        # Collect without executing fixtures. Compare unittest's old discovery
        # against the exact per-module discovery commands, in a fresh process.
        script='''
import json, pathlib, unittest
def ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from ids(test)
        else:
            yield test.id()
loader=unittest.TestLoader()
original=list(ids(loader.discover('tests')))
split=[]
for p in sorted(pathlib.Path('tests').rglob('test*.py')):
    split.extend(ids(loader.discover(str(p.parent),pattern=p.name)))
if loader.errors: raise RuntimeError(loader.errors)
print(json.dumps([original,split]))
'''
        result=subprocess.run([sys.executable,'-c',script],cwd=ROOT,text=True,
                              capture_output=True,timeout=60,check=True)
        original,split=json.loads(result.stdout)
        self.assertTrue(original)
        self.assertEqual(Counter(original),Counter(split))
        self.assertEqual(len(split),len(set(split)))

    def test_nonzero_exit_remains_failed_and_log_is_retained(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            result=verify.run_command('failure',[sys.executable,'-c',
                'print("intentional failure"); raise SystemExit(7)'],p,p)
            self.assertEqual(result['returncode'],7)
            self.assertFalse(result['passed'])
            self.assertFalse(result['timed_out'])
            self.assertIn('intentional failure',(p/result['log']).read_text())

    def test_timeout_remains_failed_and_is_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            result=verify.run_command('timeout',[sys.executable,'-c',
                'import time; time.sleep(30)'],p,p,timeout=0.05)
            self.assertEqual(result['returncode'],124)
            self.assertFalse(result['passed'])
            self.assertTrue(result['timed_out'])
            self.assertIn('exceeded',(p/result['log']).read_text())


if __name__=='__main__':unittest.main()
