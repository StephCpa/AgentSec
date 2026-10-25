"""Synthetic typed approximate-DP vertical slice; NOT production cryptography.

Adds immutable domain/profile/snapshot bindings to the generic ledger. All setup
and executor methods are trusted internal calls. No public server, real identity
verification, encrypted storage, contribution preprocessing or publication
scheduler is provided. Stored rows, seeds and outputs are plaintext test data.
"""
import json
import re
import sys
from pathlib import Path

from ledger import Ledger, Rejected

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixed_work_model import sample

PROFILE = 'approx_dp_fixed_cost_v1_candidate'
MECHANISM = 'bounded_geometric_count_v1_candidate'
EPSILON_COST = 700000
DELTA_COST = 8388608
K = 40

DP_SCHEMA = """
CREATE TABLE IF NOT EXISTS privacy_domains (
 tenant TEXT NOT NULL, id TEXT NOT NULL, profile TEXT NOT NULL,
 mechanism TEXT NOT NULL, capacity INTEGER NOT NULL,
 epsilon_account TEXT NOT NULL, delta_account TEXT NOT NULL,
 PRIMARY KEY(tenant,id),
 UNIQUE(tenant,epsilon_account), UNIQUE(tenant,delta_account),
 FOREIGN KEY(tenant,epsilon_account) REFERENCES accounts(tenant,id),
 FOREIGN KEY(tenant,delta_account) REFERENCES accounts(tenant,id),
 CHECK(capacity>=1 AND capacity<=65535),
 CHECK(epsilon_account<>delta_account)
);
CREATE TABLE IF NOT EXISTS domain_roots (
 tenant TEXT NOT NULL, root_id TEXT NOT NULL, domain_id TEXT NOT NULL,
 PRIMARY KEY(tenant,root_id),
 FOREIGN KEY(tenant,root_id) REFERENCES roots(tenant,id),
 FOREIGN KEY(tenant,domain_id) REFERENCES privacy_domains(tenant,id)
);
CREATE TABLE IF NOT EXISTS snapshots (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL, id TEXT NOT NULL,
 rows_json TEXT NOT NULL,
 PRIMARY KEY(tenant,domain_id,id),
 FOREIGN KEY(tenant,domain_id) REFERENCES privacy_domains(tenant,id)
);
"""


def public_id(value):
    if type(value) is not str or re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',value) is None:
        raise Rejected('INVALID_ID')
    return value


class DPLedger(Ledger):
    domain_mechanism = MECHANISM
    @classmethod
    def create(cls, path, clock=None, **kwargs):
        obj = super().create(path,clock=clock,**kwargs)
        obj.db.executescript(DP_SCHEMA)
        return obj

    def provision(self, *args, **kwargs):
        raise Rejected('TYPED_PROVISION_REQUIRED')

    def domain(self, tenant, domain_id):
        row = self.db.execute('SELECT * FROM privacy_domains WHERE tenant=? AND id=?',
                              (tenant,domain_id)).fetchone()
        if row is None:
            raise Rejected('UNAUTHORIZED_DOMAIN')
        if row['profile'] != PROFILE or row['mechanism'] != self.domain_mechanism:
            raise Rejected('PROFILE_MISMATCH')
        return row

    def provision_domain(self, tenant, domain_id, capacity, epsilon_limit, delta_limit):
        # Trusted setup; no reset/update/migration API. Existing IDs cannot overwrite.
        public_id(tenant); public_id(domain_id)
        if type(capacity) is not int or not 1 <= capacity <= 65535:
            raise Rejected('INVALID_CAPACITY')
        if any(type(x) is not int or not 0 <= x <= 2**62 for x in (epsilon_limit,delta_limit)):
            raise Rejected('INVALID_LIMIT')
        eps, delta = domain_id+':epsilon', domain_id+':delta'
        with self.tx():
            for account, limit in ((eps,epsilon_limit),(delta,delta_limit)):
                self.db.execute('INSERT INTO accounts(tenant,id,total,free) VALUES(?,?,?,?)',
                                (tenant,account,limit,limit))
            self.db.execute('INSERT INTO privacy_domains VALUES(?,?,?,?,?,?,?)',
                            (tenant,domain_id,PROFILE,self.domain_mechanism,capacity,eps,delta))

    def authorize_root(self, tenant, domain_id, root_id, actor, recipient, expires_at=2**62):
        # Simulated authenticated authority. Multiple roots share the SAME domain.
        for value in (tenant,domain_id,root_id,actor,recipient):
            public_id(value)
        if type(expires_at) is not int or not 0 < expires_at <= 2**62:
            raise Rejected('INVALID_EXPIRY')
        with self.tx():
            self.domain(tenant,domain_id)
            self.db.execute('INSERT INTO roots(tenant,id,actor,recipient,expires_at) VALUES(?,?,?,?,?)',
                            (tenant,root_id,actor,recipient,expires_at))
            self.db.execute('INSERT INTO domain_roots VALUES(?,?,?)',(tenant,root_id,domain_id))

    def install_snapshot(self, tenant, domain_id, snapshot_id, rows):
        # Trusted synthetic fixture ingestion. The alias/capacity are public;
        # no hash of raw data or raw row count is exposed through the action.
        public_id(snapshot_id)
        with self.tx():
            domain = self.domain(tenant,domain_id)
            if (type(rows) is not list or len(rows) != domain['capacity'] or
                any(type(x) is not int or x not in (0,1) for x in rows)):
                raise Rejected('INVALID_SNAPSHOT')
            self.db.execute('INSERT INTO snapshots VALUES(?,?,?,?)',
                            (tenant,domain_id,snapshot_id,self.protect_snapshot(tenant,domain_id,snapshot_id,rows)))

    def protect_snapshot(self, tenant, domain_id, snapshot_id, rows):
        return json.dumps(rows,separators=(',',':'))

    def open_snapshot(self, tenant, domain_id, snapshot_id, value):
        return json.loads(value)

    def registered_costs(self, domain, action=None):
        return {domain['epsilon_account']:EPSILON_COST,domain['delta_account']:DELTA_COST}

    def reserve_count(self, tenant, oid, root_id, recipient, domain_id, snapshot_id, actor,
                      fault=lambda point: None):
        # Gateway-facing registration shape; not a public server. Callers cannot
        # supply costs or K. Never return the internal operation row or readiness.
        for value in (tenant,oid,root_id,recipient,domain_id,snapshot_id,actor):
            public_id(value)
        domain = self.domain(tenant,domain_id)
        action = dict(tenant=tenant,id=oid,root=root_id,recipient=recipient,
                      parameters=dict(domain=domain_id,snapshot=snapshot_id,
                                      mechanism=MECHANISM,accountant=PROFILE),
                      costs=self.registered_costs(domain))
        registered = self.reserve(action,actor,fault)
        return {'operation_id':oid,'action_digest':registered['digest'],
                'registration':'REGISTERED'}

    def validate_reservation(self, action, root):
        # Recheck immutable bindings inside the same transaction as both debits.
        params = action['parameters']
        if type(params) is not dict or set(params) != {'domain','snapshot','mechanism','accountant'}:
            raise Rejected('INVALID_PARAMETERS')
        for value in (action['tenant'],action['id'],action['root'],action['recipient'],
                      params['domain'],params['snapshot']):
            public_id(value)
        domain = self.domain(action['tenant'],params['domain'])
        if params['mechanism'] != MECHANISM or params['accountant'] != PROFILE:
            raise Rejected('PROFILE_MISMATCH')
        binding = self.db.execute('SELECT domain_id FROM domain_roots WHERE tenant=? AND root_id=?',
                                  (action['tenant'],root['id'])).fetchone()
        if binding is None or binding['domain_id'] != domain['id']:
            raise Rejected('UNAUTHORIZED_DOMAIN')
        if action['costs'] != self.registered_costs(domain, action):
            raise Rejected('REGISTERED_COST_MISMATCH')
        exists = self.db.execute('SELECT 1 FROM snapshots WHERE tenant=? AND domain_id=? AND id=?',
                                 (action['tenant'],domain['id'],params['snapshot'])).fetchone()
        if exists is None:
            # Authorized catalog membership, not a predicate on private rows.
            raise Rejected('UNKNOWN_SNAPSHOT')

    def compute_internal(self, tenant, oid):
        # Trusted executor only. No output is handed to an Agent by this method.
        op = self.op(tenant,oid)
        if op['state'] not in ('STARTED','COMMITTED'):
            raise Rejected('INVALID_STATE')
        action = json.loads(op['action'])
        self.validate_reservation(action,self.root(tenant,op['root_id']))
        params = action['parameters']
        row = self.db.execute('SELECT rows_json FROM snapshots WHERE tenant=? AND domain_id=? AND id=?',
                              (tenant,params['domain'],params['snapshot'])).fetchone()
        rows = tuple(self.open_snapshot(tenant,params['domain'],params['snapshot'],row['rows_json']))
        # Exactly the first 80 bits of the persisted 256-bit seed. No fresh RNG,
        # retry counter, generation or clock contributes to the sample. Security
        # of OS-generated seed bits is an assumption, not proven by these tests.
        tape = tuple((byte >> shift)&1 for byte in op['seed'][:10] for shift in range(7,-1,-1))
        value, steps = sample(rows,tape,K)
        assert steps == len(rows)+81
        return value.to_bytes(8,'big')

    def execute_count(self, tenant, oid, generation, fault=lambda point: None):
        # Completion remains internal. L3 admission and emit remain separate.
        op = self.op(tenant,oid)
        if type(generation) is not int or generation != op['generation']:
            raise Rejected('STALE_WORKER')
        result = self.compute_internal(tenant,oid)
        self.commit(tenant,oid,generation,op['digest'],result,fault)
        return {'operation_id':oid,'result_digest':self.op(tenant,oid)['result_digest']}

    def audit(self):
        errors = super().audit()
        for op in self.db.execute('SELECT * FROM operations'):
            try:
                self.validate_reservation(json.loads(op['action']),self.root(op['tenant'],op['root_id']))
            except Rejected:
                errors.append('TYPED_ACTION_BINDING')
            actual = {r['account_id']:r['amount'] for r in self.db.execute(
                'SELECT * FROM charges WHERE tenant=? AND operation_id=?',(op['tenant'],op['id']))}
            if actual != json.loads(op['action'])['costs']:
                errors.append('TYPED_CHARGE_BINDING')
        return errors
