"""Domain-wide final prefix and pre-release gate for atomic publication.

Internal reference profile. Final events are durable local records, not a
signed external journal. A stalled earlier receiver deliberately blocks later
routes. Prepared original bytes remain valid only under their original ticket.
"""
from pathlib import Path
import sqlite3

from atomic_publication import AtomicPublicationSender
from ledger import Rejected
from witness_transport import TLSWitnessedLedger

SCHEMA = """
CREATE TABLE final_events (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL,
 seq INTEGER NOT NULL CHECK(seq>0),
 outcome TEXT NOT NULL CHECK(outcome IN ('WITHHELD','ACCEPTED','CLOSED')),
 delivery_id TEXT,
 PRIMARY KEY(tenant,domain_id,seq),
 CHECK((outcome='WITHHELD')=(delivery_id IS NULL)),
 FOREIGN KEY(tenant,domain_id,seq) REFERENCES pub_decisions(tenant,domain_id,seq),
 FOREIGN KEY(tenant,delivery_id) REFERENCES deliveries(tenant,id)
);
"""
_template=sqlite3.connect(':memory:');_template.executescript(SCHEMA)
TRUSTED_SCHEMA=dict(_template.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"));_template.close()


class OrderedPublicationSender(AtomicPublicationSender):
    storage_profile='witnessed-ordered-publication-v1'

    def __init__(self,path,*args,**kwargs):
        self._final_initial=not Path(path).exists() or not Path(path).stat().st_size
        super().__init__(path,*args,**kwargs)

    @classmethod
    def new_replica(cls,path,**kwargs):
        obj=super().new_replica(path,**kwargs)
        obj.db.executescript(SCHEMA);obj._final_initial=False
        obj.check_storage_profile();return obj

    def check_storage_profile(self,allow_empty=False):
        super().check_storage_profile(allow_empty=allow_empty)
        present=dict(self.db.execute("SELECT name,sql FROM sqlite_master WHERE name GLOB 'final_*' AND type='table'"))
        if not present and self._final_initial:return
        if present!=TRUSTED_SCHEMA:raise Rejected('FINAL_SCHEMA_MISMATCH')

    def final_frontier(self,tenant,domain_id):
        """Trusted diagnostic; no endpoint or public polling semantics."""
        return self.db.execute('SELECT coalesce(max(seq),0) FROM final_events WHERE tenant=? AND domain_id=?',
                               (tenant,domain_id)).fetchone()[0]

    def final_events_internal(self,tenant,domain_id):
        return [dict(x) for x in self.db.execute('SELECT * FROM final_events WHERE tenant=? AND domain_id=? ORDER BY seq',
                                                (tenant,domain_id))]

    def decision_for(self,row):
        decision=self.db.execute('SELECT * FROM pub_decisions WHERE tenant=? AND delivery_id=?',
                                 (row['tenant'],row['id'])).fetchone()
        if decision is None:raise Rejected('FINAL_DECISION_REQUIRED')
        return decision

    def first_pending(self,row):
        # Both data and first terminal preparation call this inside their
        # guarded transaction, before reading/decrypting the private result.
        decision=self.decision_for(row)
        if decision['seq']!=self.final_frontier(decision['tenant'],decision['domain_id'])+1:
            raise Rejected('DOMAIN_FINAL_ORDER')
        return super().first_pending(row)

    def _advance_final_tx(self,tenant,domain_id,fault):
        if not self.db.in_transaction or self._tx_time is None or self._base_anchor is None:
            raise Rejected('FINAL_TRANSACTION_REQUIRED')
        front=self.final_frontier(tenant,domain_id)
        while True:
            decision=self.db.execute('SELECT * FROM pub_decisions WHERE tenant=? AND domain_id=? AND seq=?',
                                     (tenant,domain_id,front+1)).fetchone()
            if decision is None:break
            outcome='WITHHELD'
            if decision['kind']=='ADMITTED':
                row=self.outbox(tenant,decision['delivery_id'])
                if row['state'] not in ('ACCEPTED','CLOSED') or row['fact'] is None:break
                outcome=row['state']
            fault('before_final_event_write')
            self.db.execute('INSERT INTO final_events VALUES(?,?,?,?,?)',
                            (tenant,domain_id,front+1,outcome,decision['delivery_id']))
            fault('after_final_event_write');front+=1

    def publish(self,tenant,domain_id,tick,fault):
        super().publish(tenant,domain_id,tick,fault)
        self._advance_final_tx(tenant,domain_id,fault)

    def confirm(self,tenant,did,request,ack,fault=lambda point:None):
        # Parent hook is inside the same transaction as validated signed fact,
        # route prefix and ACK storage. Duplicate confirmation needs no drain:
        # the original commit already contained the maximal final prefix.
        def checked(point):
            if point=='before_v2_confirmation_commit':
                decision=self.decision_for(self.outbox(tenant,did))
                self._advance_final_tx(tenant,decision['domain_id'],fault)
            fault(point)
        return super().confirm(tenant,did,request,ack,checked)

    def audit_final(self):
        owners={(x[0],x[1]) for x in self.db.execute('SELECT tenant,domain_id FROM pub_bindings')}
        if any((x[0],x[1]) not in owners for x in self.db.execute('SELECT tenant,domain_id FROM final_events')):
            raise Rejected('FINAL_AUDIT_FAILED')
        for tenant,domain in owners:
            expected=[];blocked=False;next_seq=1
            for decision in self.db.execute('SELECT * FROM pub_decisions WHERE tenant=? AND domain_id=? ORDER BY seq',(tenant,domain)):
                if decision['seq']!=next_seq:raise Rejected('FINAL_AUDIT_FAILED')
                next_seq+=1;outcome='WITHHELD'
                if decision['kind']=='ADMITTED':
                    row=self.outbox(tenant,decision['delivery_id'])
                    terminal=row['state'] in ('ACCEPTED','CLOSED') and row['fact'] is not None
                    # Later routes cannot have even prepared data/control while
                    # a prior admitted decision still lacks its final ACK.
                    if blocked and (terminal or row['envelope'] is not None or row['control'] is not None):
                        raise Rejected('FINAL_AUDIT_FAILED')
                    if not terminal:blocked=True
                    outcome=row['state']
                if not blocked:expected.append((tenant,domain,decision['seq'],outcome,decision['delivery_id']))
            actual=[tuple(x) for x in self.db.execute('SELECT * FROM final_events WHERE tenant=? AND domain_id=? ORDER BY seq',(tenant,domain))]
            if actual!=expected:raise Rejected('FINAL_AUDIT_FAILED')

    def audit(self):
        errors=super().audit();self.audit_final();return errors

    def recover_from_witness(self,fault=lambda point:None):
        def checked(point):
            if point=='before_recovery_commit':self.audit_final()
            fault(point)
        return super().recover_from_witness(checked)


class TLSOrderedPublicationSender(TLSWitnessedLedger,OrderedPublicationSender):
    storage_profile='mtls-ordered-publication-v1'
