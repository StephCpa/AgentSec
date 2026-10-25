"""Trusted fixed-roster user contribution compiler and witnessed ingestion.

Synthetic reference profile. Identity resolution, eligibility classification,
global domain lineage and all ingestion observations remain trusted assumptions.
No public API or production constant-time/availability claim.
"""
import json

from dp_ledger import public_id
from ledger import Rejected
from witnessed_mixed_ledger import WitnessedMixedLedger

RULE = 'fixed-roster-min-positive-bucket-v1'
SCHEMA = """
CREATE TABLE contribution_domains (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL, lineage BLOB NOT NULL,
 rule TEXT NOT NULL, roster BLOB NOT NULL,
 PRIMARY KEY(tenant,domain_id), UNIQUE(tenant,lineage),
 FOREIGN KEY(tenant,domain_id) REFERENCES privacy_domains(tenant,id)
);
CREATE TABLE contribution_batches (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL, id TEXT NOT NULL,
 catalog_id TEXT NOT NULL, count_snapshot TEXT NOT NULL, histogram_snapshot TEXT NOT NULL,
 PRIMARY KEY(tenant,domain_id,id), UNIQUE(tenant,domain_id,count_snapshot),
 UNIQUE(tenant,domain_id,histogram_snapshot),
 FOREIGN KEY(tenant,domain_id) REFERENCES contribution_domains(tenant,domain_id),
 FOREIGN KEY(tenant,domain_id,catalog_id) REFERENCES histogram_catalogs(tenant,domain_id,id),
 FOREIGN KEY(tenant,domain_id,count_snapshot) REFERENCES snapshots(tenant,domain_id,id),
 FOREIGN KEY(tenant,domain_id,histogram_snapshot) REFERENCES snapshots(tenant,domain_id,id)
);
"""


def validate_roster(roster):
    if (type(roster) not in (tuple, list) or not 1 <= len(roster) <= 65535 or
            any(type(u) is not bytes or len(u) != 32 for u in roster) or
            len(set(roster)) != len(roster)):
        raise Rejected('INVALID_PRIVATE_INGESTION')
    return tuple(roster)


def compile_contributions(roster, records, bucket_count):
    """Each record is (trusted stable user token, public catalog bucket code).

    Code zero means ineligible. Minimum positive code is fixed catalog priority,
    not a rank computed over other users. Duplicates and input order do not
    matter. Caller must keep errors, runtime and both exact views private.
    """
    roster = validate_roster(roster)
    if type(bucket_count) is not int or not 1 <= bucket_count <= 64:
        raise Rejected('INVALID_PRIVATE_INGESTION')
    if type(records) not in (list, tuple):
        raise Rejected('INVALID_PRIVATE_INGESTION')
    positions = {u: i for i, u in enumerate(roster)}
    histogram = [0] * len(roster)
    for record in records:
        if type(record) not in (list, tuple) or len(record) != 2:
            raise Rejected('INVALID_PRIVATE_INGESTION')
        user, bucket = record
        if (type(user) is not bytes or len(user) != 32 or user not in positions or
                type(bucket) is not int or not 0 <= bucket <= bucket_count):
            raise Rejected('INVALID_PRIVATE_INGESTION')
        i = positions[user]
        if bucket and (histogram[i] == 0 or bucket < histogram[i]):
            histogram[i] = bucket
    return [int(x != 0) for x in histogram], histogram


class ContributionLedger(WitnessedMixedLedger):
    """Fresh profile; direct snapshot APIs disabled; pair installed in one TX.

    The Python/database administrator remains trusted. Explicit base-class calls
    and direct SQL are not security-isolated from that administrator.
    """
    storage_profile = 'witnessed-contribution-mixed-v1'

    @classmethod
    def new_replica(cls, path, **kwargs):
        obj = super().new_replica(path, **kwargs)
        obj.db.executescript(SCHEMA)
        return obj

    def install_snapshot(self, *args, **kwargs):
        raise Rejected('CONTRIBUTION_INGESTION_REQUIRED')

    def install_histogram_snapshot(self, *args, **kwargs):
        raise Rejected('CONTRIBUTION_INGESTION_REQUIRED')

    def roster_identity(self, tenant, domain_id, lineage):
        return (self.storage_profile, tenant, domain_id, lineage, RULE)

    def bind_contribution_domain(self, tenant, domain_id, lineage, roster):
        """Privileged one-time assignment; roster is independent of participation."""
        roster = validate_roster(roster)
        if type(lineage) is not bytes or len(lineage) != 32:
            raise Rejected('INVALID_CONTRIBUTION_LINEAGE')
        with self.tx():
            domain = self.domain(tenant, domain_id)
            if len(roster) != domain['capacity']:
                raise Rejected('INVALID_PRIVATE_INGESTION')
            if self.db.execute('SELECT 1 FROM contribution_domains WHERE tenant=? AND (domain_id=? OR lineage=?)',
                               (tenant, domain_id, lineage)).fetchone():
                raise Rejected('CONTRIBUTION_BINDING_EXISTS')
            if self.db.execute('SELECT 1 FROM snapshots WHERE tenant=? AND domain_id=?', (tenant, domain_id)).fetchone():
                raise Rejected('CONTRIBUTION_DOMAIN_NOT_FRESH')
            sealed = self.vault.seal('contribution-roster', self.roster_identity(tenant, domain_id, lineage), b''.join(roster))
            self.db.execute('INSERT INTO contribution_domains VALUES(?,?,?,?,?)', (tenant, domain_id, lineage, RULE, sealed))

    def contribution_domain(self, tenant, domain_id):
        row = self.db.execute('SELECT * FROM contribution_domains WHERE tenant=? AND domain_id=?', (tenant, domain_id)).fetchone()
        if row is None or row['rule'] != RULE or type(row['lineage']) is not bytes or len(row['lineage']) != 32:
            raise Rejected('CONTRIBUTION_DOMAIN_REQUIRED')
        return row

    def private_roster(self, tenant, domain_id):
        row = self.contribution_domain(tenant, domain_id)
        raw = self.vault.open('contribution-roster', self.roster_identity(tenant, domain_id, row['lineage']), row['roster'])
        if len(raw) != 32 * self.domain(tenant, domain_id)['capacity']:
            raise Rejected('STORAGE_INTEGRITY')
        return validate_roster([raw[i:i+32] for i in range(0, len(raw), 32)])

    def ingest_pair(self, tenant, domain_id, batch_id, catalog_id, count_snapshot, histogram_snapshot, records,
                    fault=lambda point: None):
        # Aliases are chosen independently of records by the trusted scheduler.
        for value in (tenant, domain_id, batch_id, catalog_id, count_snapshot, histogram_snapshot):
            public_id(value)
        if count_snapshot == histogram_snapshot:
            raise Rejected('CONTRIBUTION_ALIAS_CONFLICT')
        with self.tx():
            roster = self.private_roster(tenant, domain_id)
            catalog = self.catalog(tenant, domain_id, catalog_id)
            count, histogram = compile_contributions(roster, records, len(json.loads(catalog['buckets_json'])))
            if self.db.execute('SELECT 1 FROM contribution_batches WHERE tenant=? AND domain_id=? AND id=?',
                               (tenant, domain_id, batch_id)).fetchone():
                # No ambiguous success or content-based retry oracle. Recovery is
                # an explicit privileged restore, then audit by immutable alias.
                raise Rejected('CONTRIBUTION_BATCH_EXISTS')
            if self.db.execute('SELECT 1 FROM snapshots WHERE tenant=? AND domain_id=? AND id IN (?,?)',
                               (tenant, domain_id, count_snapshot, histogram_snapshot)).fetchone():
                raise Rejected('CONTRIBUTION_ALIAS_CONFLICT')
            self.db.execute('INSERT INTO snapshots VALUES(?,?,?,?)',
                            (tenant, domain_id, count_snapshot, self.protect_snapshot(tenant, domain_id, count_snapshot, count)))
            fault('after_count_snapshot')
            self.db.execute('INSERT INTO snapshots VALUES(?,?,?,?)',
                            (tenant, domain_id, histogram_snapshot,
                             self.protect_histogram_snapshot(tenant, domain_id, histogram_snapshot, catalog_id, histogram)))
            self.db.execute('INSERT INTO histogram_snapshots VALUES(?,?,?,?)', (tenant, domain_id, histogram_snapshot, catalog_id))
            self.db.execute('INSERT INTO contribution_batches VALUES(?,?,?,?,?,?)',
                            (tenant, domain_id, batch_id, catalog_id, count_snapshot, histogram_snapshot))
            fault('before_ingestion_commit')
        fault('after_ingestion_commit')
        # No private population, hash, roster token or bucket counts in receipt.
        return dict(batch=batch_id, count=count_snapshot, histogram=histogram_snapshot, rule=RULE)

    def validate_reservation(self, action, root):
        super().validate_reservation(action, root)
        p = action['parameters']; tenant = action['tenant']; domain_id = p['domain']
        self.contribution_domain(tenant, domain_id)
        # Public metadata only; no raw snapshot/roster read before durable L1.
        if not self.db.execute('SELECT 1 FROM contribution_batches WHERE tenant=? AND domain_id=? AND (count_snapshot=? OR histogram_snapshot=?)',
                               (tenant, domain_id, p['snapshot'], p['snapshot'])).fetchone():
            raise Rejected('CONTRIBUTION_PROVENANCE_REQUIRED')

    def audit_contributions(self):
        """Privileged private audit. Never expose its data-dependent result."""
        covered = set()
        for row in self.db.execute('SELECT * FROM contribution_domains'):
            self.private_roster(row['tenant'], row['domain_id'])
        for row in self.db.execute('SELECT * FROM contribution_batches'):
            t, d = row['tenant'], row['domain_id']; self.contribution_domain(t, d)
            pair = []
            for key in ('count_snapshot', 'histogram_snapshot'):
                sid = row[key]; identity = (t, d, sid)
                if identity in covered: raise Rejected('CONTRIBUTION_AUDIT_FAILED')
                covered.add(identity)
                raw = self.db.execute('SELECT rows_json FROM snapshots WHERE tenant=? AND domain_id=? AND id=?', identity).fetchone()
                if raw is None: raise Rejected('CONTRIBUTION_AUDIT_FAILED')
                pair.append(self.open_snapshot(t, d, sid, raw[0]))
            if pair[0] != [int(x != 0) for x in pair[1]]:
                raise Rejected('CONTRIBUTION_AUDIT_FAILED')
            cat = self.db.execute('SELECT catalog_id FROM histogram_snapshots WHERE tenant=? AND domain_id=? AND snapshot_id=?',
                                  (t, d, row['histogram_snapshot'])).fetchone()
            count_cat = self.db.execute('SELECT 1 FROM histogram_snapshots WHERE tenant=? AND domain_id=? AND snapshot_id=?',
                                        (t, d, row['count_snapshot'])).fetchone()
            if cat is None or cat[0] != row['catalog_id'] or count_cat is not None:
                raise Rejected('CONTRIBUTION_AUDIT_FAILED')
        if covered != {tuple(r) for r in self.db.execute('SELECT tenant,domain_id,id FROM snapshots')}:
            raise Rejected('CONTRIBUTION_AUDIT_FAILED')

    def audit(self):
        errors = super().audit()
        self.audit_contributions()
        return errors

    def recover_from_witness(self, fault=lambda point: None):
        def checked(point):
            if point == 'before_recovery_commit': self.audit_contributions()
            fault(point)
        return super().recover_from_witness(checked)
