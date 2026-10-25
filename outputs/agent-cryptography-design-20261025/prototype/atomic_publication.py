"""Atomic scheduled publication decision and retention-v2 L3/outbox.

Trusted internal reference profile, not the external observation gateway.
No cross-route final-delivery frontier or public error mapping is supplied.
"""
from pathlib import Path
import sqlite3

from contribution_delivery import ContributionRetentionSender
from dp_ledger import public_id
from ledger import Rejected
from witness_transport import TLSWitnessedLedger

SCHEMA = """
CREATE TABLE pub_bindings (
 tenant TEXT NOT NULL, root_id TEXT NOT NULL, domain_id TEXT NOT NULL,
 context_hash BLOB NOT NULL REFERENCES v2_routes(context_hash),
 ttl INTEGER NOT NULL CHECK(ttl BETWEEN 1 AND 60),
 PRIMARY KEY(tenant,root_id),
 FOREIGN KEY(tenant,root_id) REFERENCES roots(tenant,id),
 FOREIGN KEY(tenant,domain_id) REFERENCES privacy_domains(tenant,id)
);
CREATE TABLE pub_decisions (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL, seq INTEGER NOT NULL CHECK(seq>0),
 operation_id TEXT NOT NULL, tick INTEGER NOT NULL CHECK(tick>0),
 context_hash BLOB NOT NULL REFERENCES v2_routes(context_hash),
 kind TEXT NOT NULL CHECK(kind IN ('ADMITTED','WITHHELD')),
 delivery_id TEXT,
 PRIMARY KEY(tenant,domain_id,seq), UNIQUE(tenant,operation_id), UNIQUE(tenant,delivery_id),
 CHECK((kind='ADMITTED')=(delivery_id IS NOT NULL)),
 FOREIGN KEY(tenant,operation_id) REFERENCES operations(tenant,id),
 FOREIGN KEY(tenant,delivery_id) REFERENCES deliveries(tenant,id)
);
"""
_template=sqlite3.connect(':memory:');_template.executescript(SCHEMA)
TRUSTED_SCHEMA=dict(_template.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"));_template.close()


class AtomicPublicationSender(ContributionRetentionSender):
    storage_profile='witnessed-atomic-publication-v1'

    def __init__(self,path,*args,**kwargs):
        self._public_initial=not Path(path).exists() or not Path(path).stat().st_size
        super().__init__(path,*args,**kwargs)

    @classmethod
    def new_replica(cls,path,**kwargs):
        obj=super().new_replica(path,**kwargs)
        obj.db.executescript(SCHEMA);obj._public_initial=False
        obj.check_storage_profile();return obj

    def check_storage_profile(self,allow_empty=False):
        super().check_storage_profile(allow_empty=allow_empty)
        present=dict(self.db.execute("SELECT name,sql FROM sqlite_master WHERE name GLOB 'pub_*' AND type='table'"))
        if not present and self._public_initial:return
        if present!=TRUSTED_SCHEMA:raise Rejected('PUBLICATION_SCHEMA_MISMATCH')

    def binding(self,tenant,root_id):
        row=self.db.execute('SELECT * FROM pub_bindings WHERE tenant=? AND root_id=?',(tenant,root_id)).fetchone()
        if row is None:raise Rejected('PUBLICATION_BINDING_REQUIRED')
        return row

    def bind_root_delivery(self,tenant,root_id,digest,ttl=60):
        """Trusted bootstrap, before this root has any operation. No migration."""
        public_id(tenant);public_id(root_id)
        if type(ttl) is not int or not 1<=ttl<=60:raise Rejected('INVALID_TTL')
        with self.tx():
            root=self.root(tenant,root_id);route,context=self.route(digest,live=True)
            domain=self.db.execute('SELECT domain_id FROM domain_roots WHERE tenant=? AND root_id=?',(tenant,root_id)).fetchone()
            if domain is None or context['tenant']!=tenant or context['recipient']!=root['recipient']:
                raise Rejected('PUBLICATION_ROUTE_BINDING')
            if self.db.execute('SELECT 1 FROM pub_bindings WHERE tenant=? AND root_id=?',(tenant,root_id)).fetchone():
                raise Rejected('PUBLICATION_BINDING_IMMUTABLE')
            if self.db.execute('SELECT 1 FROM operations WHERE tenant=? AND root_id=?',(tenant,root_id)).fetchone():
                raise Rejected('PUBLICATION_ROOT_NOT_FRESH')
            if self.db.execute('SELECT 1 FROM pub_bindings WHERE context_hash=? AND (tenant!=? OR domain_id!=?)',
                               (digest,tenant,domain[0])).fetchone():
                raise Rejected('PUBLICATION_CONTEXT_DOMAIN')
            self.db.execute('INSERT INTO pub_bindings VALUES(?,?,?,?,?)',(tenant,root_id,domain[0],digest,ttl))

    def after_reservation(self,action):
        binding=self.binding(action['tenant'],action['root'])
        _,context=self.route(binding['context_hash'],live=True)
        if binding['domain_id']!=action['parameters']['domain'] or context['recipient']!=action['recipient']:
            raise Rejected('PUBLICATION_ROUTE_BINDING')
        super().after_reservation(action)

    def admit_v2(self,*args,**kwargs):
        # A separate caller cannot create another L3 or renew an old decision.
        raise Rejected('ATOMIC_PUBLISHER_REQUIRED')

    @staticmethod
    def publication_key(domain_id,seq):return 'publication:'+domain_id+':'+str(seq)

    def publish(self,tenant,domain_id,tick,fault):
        # Called inside advance's guarded transaction. Parent appends only
        # internal eligibility; no bytes or public permit have been returned.
        super().publish(tenant,domain_id,tick,fault)
        rows=self.db.execute('''SELECT j.*,o.root_id FROM jobs j JOIN operations o
            ON o.tenant=j.tenant AND o.id=j.operation_id
            WHERE j.tenant=? AND j.domain_id=? AND j.publication IS NOT NULL
            AND NOT EXISTS(SELECT 1 FROM pub_decisions p WHERE p.tenant=j.tenant AND p.operation_id=j.operation_id)
            ORDER BY j.seq''',(tenant,domain_id)).fetchall()
        for job in rows:
            binding=self.binding(tenant,job['root_id']);route,_=self.route(binding['context_hash'])
            if binding['domain_id']!=domain_id:raise Rejected('PUBLICATION_ROUTE_BINDING')
            did=None;kind='WITHHELD'
            if job['publication']=='RELEASE' and not route['revoked']:
                row,created=self._admit_v2_tx(binding['context_hash'],self.publication_key(domain_id,job['seq']),
                                              job['operation_id'],binding['ttl'],fault)
                if not created:raise Rejected('PUBLICATION_DUPLICATE_ADMISSION')
                did=row['id'];kind='ADMITTED'
            fault('before_public_decision_write')
            self.db.execute('INSERT INTO pub_decisions VALUES(?,?,?,?,?,?,?,?)',
                            (tenant,domain_id,job['seq'],job['operation_id'],tick,binding['context_hash'],kind,did))
            fault('after_public_decision_write')
        # Clock, kernel L2, charges, eligibility, decision, ticket, outbox and
        # tick retry record are all included in the outer witness/local commit.

    def decisions_internal(self,tenant,domain_id):
        """Trusted diagnostic only. No auth/error/observation gateway claim."""
        return [dict(r) for r in self.db.execute('SELECT * FROM pub_decisions WHERE tenant=? AND domain_id=? ORDER BY seq',(tenant,domain_id))]

    def audit_publication(self):
        contexts={}
        for binding in self.db.execute('SELECT * FROM pub_bindings'):
            root=self.root(binding['tenant'],binding['root_id']);_,context=self.route(binding['context_hash'])
            domain=self.db.execute('SELECT domain_id FROM domain_roots WHERE tenant=? AND root_id=?',(binding['tenant'],binding['root_id'])).fetchone()
            if domain is None or domain[0]!=binding['domain_id'] or context['tenant']!=binding['tenant'] or context['recipient']!=root['recipient']:
                raise Rejected('PUBLICATION_AUDIT_FAILED')
            owner=(binding['tenant'],binding['domain_id'])
            if contexts.setdefault(binding['context_hash'],owner)!=owner:raise Rejected('PUBLICATION_AUDIT_FAILED')
        covered=set();tickets=set()
        for decision in self.db.execute('SELECT * FROM pub_decisions'):
            job=self.db.execute('SELECT * FROM jobs WHERE tenant=? AND operation_id=?',(decision['tenant'],decision['operation_id'])).fetchone()
            if job is None or job['publication'] is None or job['seq']!=decision['seq'] or job['domain_id']!=decision['domain_id']:
                raise Rejected('PUBLICATION_AUDIT_FAILED')
            op=self.db.execute('SELECT * FROM operations WHERE tenant=? AND id=?',(decision['tenant'],decision['operation_id'])).fetchone()
            binding=self.binding(op['tenant'],op['root_id'])
            if binding['context_hash']!=decision['context_hash']:raise Rejected('PUBLICATION_AUDIT_FAILED')
            event=self.db.execute("SELECT tick FROM publication_events WHERE tenant=? AND domain_id=? AND kind IN ('RELEASE','WITHHELD') AND subject=?",
                                  (job['tenant'],job['domain_id'],job['operation_id'])).fetchall()
            if len(event)!=1 or event[0][0]!=decision['tick']:raise Rejected('PUBLICATION_AUDIT_FAILED')
            covered.add((job['tenant'],job['operation_id']))
            if decision['kind']=='ADMITTED':
                if job['publication']!='RELEASE' or op['state']!='COMMITTED':raise Rejected('PUBLICATION_AUDIT_FAILED')
                row=self.outbox(decision['tenant'],decision['delivery_id']);ticket=self.ticket(row)
                if row['context_hash']!=decision['context_hash'] or ticket['operation_id']!=decision['operation_id']:
                    raise Rejected('PUBLICATION_AUDIT_FAILED')
                req=self.db.execute('SELECT * FROM v2_requests WHERE context_hash=? AND request_key=?',
                                    (decision['context_hash'],self.publication_key(job['domain_id'],job['seq']))).fetchone()
                if req is None or req['delivery_id']!=decision['delivery_id'] or req['ttl']!=binding['ttl']:
                    raise Rejected('PUBLICATION_AUDIT_FAILED')
                tickets.add((row['tenant'],row['id']))
            elif job['publication']=='RELEASE' and not self.route(decision['context_hash'])[0]['revoked']:
                raise Rejected('PUBLICATION_AUDIT_FAILED')
        published={(r[0],r[1]) for r in self.db.execute('SELECT tenant,operation_id FROM jobs WHERE publication IS NOT NULL')}
        if covered!=published or tickets!={tuple(r) for r in self.db.execute('SELECT tenant,id FROM v2_outbox')}:
            raise Rejected('PUBLICATION_AUDIT_FAILED')
        for op in self.db.execute('SELECT tenant,root_id FROM operations'):self.binding(*op)

    def audit(self):
        errors=super().audit();self.audit_publication();return errors

    def recover_from_witness(self,fault=lambda point:None):
        def checked(point):
            if point=='before_recovery_commit':self.audit_publication()
            fault(point)
        return super().recover_from_witness(checked)


class TLSAtomicPublicationSender(TLSWitnessedLedger,AtomicPublicationSender):
    storage_profile='mtls-atomic-publication-v1'
