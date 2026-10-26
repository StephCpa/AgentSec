"""Exact compatibility with the frozen old serializer, including hostile cells."""
from pathlib import Path
import random
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
from witnessed_ledger import WitnessedLedger,Rejected,quote_identifier
from image_serialization_experiment import reference_state_image,ImageEquivalence,measured_query
from delivery_relation_trace import run_delivery_relation
from restricted_trace import Runtime


class Snapshot:
    schema=WitnessedLedger.schema
    state_image=WitnessedLedger.state_image
    def __init__(self,path=':memory:'):
        self.db=sqlite3.connect(path,isolation_level=None);self.db.row_factory=sqlite3.Row
    def close(self):self.db.close()


class ImageSerializationTests(unittest.TestCase):
    def setUp(self):self.snapshot=Snapshot()
    def tearDown(self):self.snapshot.close()
    def equal_image(self):
        actual=self.snapshot.state_image();self.assertEqual(actual,reference_state_image(self.snapshot));return actual

    def test_empty_schema_and_empty_tables(self):
        self.equal_image()
        for name in ('z','a','中文','😀'):
            self.snapshot.db.execute('CREATE TABLE '+quote_identifier(name)+' (value)')
            self.equal_image()

    def test_unicode_escaping_binary_integers_null_duplicate_rows_and_schema(self):
        db=self.snapshot.db;name='q"\\雪';q=quote_identifier(name)
        db.execute('CREATE TABLE '+q+' ("quoted\"\"column", i, b, n)')
        rows=[('\\\"\n\t\x00雪😀',-(2**63),bytes(range(256)),None),('',2**63-1,b'',None),
              ('é',-1,b'\x00\xff',None),('e\u0301',0,b'\x00\xff',None)]
        for row in rows+rows:db.execute('INSERT INTO '+q+' VALUES(?,?,?,?)',row)
        db.execute('CREATE INDEX "index" ON '+q+'(i)')
        db.execute('CREATE VIEW "view" AS SELECT * FROM '+q)
        db.execute('CREATE TRIGGER "trigger" AFTER INSERT ON '+q+' BEGIN SELECT 1; END')
        self.equal_image()
        db.execute('CREATE TABLE witness_anchor (seq INTEGER,digest TEXT)')
        old=self.equal_image();db.execute('INSERT INTO witness_anchor VALUES(1,?)',('f'*64,))
        self.assertEqual(old,self.equal_image())

    def test_generated_rows_and_insert_order_have_identical_canonical_bytes(self):
        db=self.snapshot.db;db.execute('CREATE TABLE data (x,y,z)')
        rng=random.Random(22026);values=[None,0,-1,2**63-1,-2**63,'','Z','a','é','雪','😀','\n','\\','"',b'',bytes(range(256))]
        rows=[tuple(rng.choice(values) for _ in range(3)) for _ in range(100)]
        db.executemany('INSERT INTO data VALUES(?,?,?)',rows);expected=self.equal_image()
        for _ in range(4):
            rng.shuffle(rows);db.execute('DELETE FROM data');db.executemany('INSERT INTO data VALUES(?,?,?)',rows)
            self.assertEqual(expected,self.equal_image())

    def test_mutation_schema_change_and_rollback_never_reuse_stale_bytes(self):
        db=self.snapshot.db;db.execute('CREATE TABLE data (x)');db.execute('INSERT INTO data VALUES(1)')
        old=self.equal_image();db.execute('BEGIN IMMEDIATE');db.execute('UPDATE data SET x=2')
        self.assertNotEqual(old,self.equal_image());db.rollback();self.assertEqual(old,self.equal_image())
        db.execute('ALTER TABLE data ADD COLUMN extra');new=self.equal_image();self.assertNotEqual(old,new)
        db.execute('DROP TABLE data');self.assertNotEqual(new,self.equal_image())

    def test_other_connection_mutation_is_read_on_next_build(self):
        with tempfile.TemporaryDirectory() as td:
            self.snapshot.close();self.snapshot=Snapshot(str(Path(td)/'db'));db=self.snapshot.db
            db.execute('CREATE TABLE data (x)');db.execute('INSERT INTO data VALUES(1)');old=self.equal_image()
            other=sqlite3.connect(str(Path(td)/'db'),isolation_level=None)
            try:other.execute('UPDATE data SET x=3')
            finally:other.close()
            self.assertNotEqual(old,self.equal_image())
            self.snapshot.close();self.snapshot=Snapshot()

    def test_unsupported_storage_values_still_reject(self):
        self.snapshot.db.execute('CREATE TABLE data (x)');self.snapshot.db.execute('INSERT INTO data VALUES(1.25)')
        for fn in (WitnessedLedger.state_image,reference_state_image):
            with self.assertRaisesRegex(Rejected,'^UNSUPPORTED_STORAGE_VALUE$'):fn(self.snapshot)

    def test_original_image_limit_enforced_on_identical_final_bytes(self):
        size=len(self.equal_image())
        for fn in (WitnessedLedger.state_image,reference_state_image):
            with patch('witnessed_ledger.MAX_IMAGE',size-1):
                with self.assertRaisesRegex(Rejected,'^INVALID_WITNESS_IMAGE$'):fn(self.snapshot)
            with patch('witnessed_ledger.MAX_IMAGE',size):self.assertEqual(len(fn(self.snapshot)),size)

    def test_guard_detects_tampering_after_prior_image_build(self):
        with tempfile.TemporaryDirectory() as td:
            r=Runtime(td)
            try:
                r.submit();r.l.state_image();r.l.db.execute("UPDATE gw_requests SET response=x'00' WHERE seq=1")
                with self.assertRaisesRegex(Rejected,'^LOCAL_STATE_DIVERGED$'):r.l.check_current_state()
            finally:r.close()

    def test_all_image_builds_match_in_delivery_adaptation_and_denial_paths(self):
        with ImageEquivalence() as guard:
            for plan in ('normal','receipt_then_terminal','withheld_behind_unconfirmed','mixed_expired','retry_and_denial','adaptive'):
                with self.subTest(plan=plan):run_delivery_relation(plan)
        self.assertGreater(guard.calls,1000)

    def test_cost_pair_preserves_public_trace_schedule_and_restored_state(self):
        old=measured_query(poll_every=8,encoder='reference')
        new=measured_query(poll_every=8,encoder='row_reuse',diagnostic=True)
        for key in ('logical_slots','polls','image_builds','image_build_bytes','cas_commits','cas_body_bytes','transcript_hash','relation'):
            self.assertEqual(old[key],new[key],key)
        self.assertEqual(new['image_builds'],190)
        self.assertGreater(new['restored_image_checks'],0)
        self.assertEqual(new['paired_snapshot']['cpu']['row_reuse']['samples'],16)

if __name__=='__main__':unittest.main()
