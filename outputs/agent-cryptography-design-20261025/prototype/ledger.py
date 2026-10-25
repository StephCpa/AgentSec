"""Transactional consistency prototype, NOT a deployed cryptographic service.

Inputs come from a simulated trusted verifier/executor. No signature validation,
delegation-chain validation, encryption, DP sampler, public scheduling, or rollback
protection is implemented. All stored values must be synthetic test data.
"""
import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


class Rejected(Exception):
    pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS roots (
 tenant TEXT NOT NULL, id TEXT NOT NULL, actor TEXT NOT NULL,
 recipient TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
 expires_at INTEGER NOT NULL DEFAULT 4611686018427387904,
 authorization_mode TEXT NOT NULL DEFAULT 'direct' CHECK(authorization_mode IN ('direct','delegated')),
 PRIMARY KEY(tenant,id)
);
CREATE TABLE IF NOT EXISTS accounts (
 tenant TEXT NOT NULL, id TEXT NOT NULL, total INTEGER NOT NULL,
 free INTEGER NOT NULL, reserved INTEGER NOT NULL DEFAULT 0,
 spent INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant,id),
 CHECK(total>=0 AND free>=0 AND reserved>=0 AND spent>=0),
 CHECK(total=free+reserved+spent)
);
CREATE TABLE IF NOT EXISTS operations (
 tenant TEXT NOT NULL, id TEXT NOT NULL, root_id TEXT NOT NULL,
 actor TEXT NOT NULL, recipient TEXT NOT NULL, digest TEXT NOT NULL,
 action TEXT NOT NULL, state TEXT NOT NULL,
 generation INTEGER NOT NULL DEFAULT 0, seed BLOB,
 result BLOB, result_digest TEXT,
 PRIMARY KEY(tenant,id),
 FOREIGN KEY(tenant,root_id) REFERENCES roots(tenant,id),
 CHECK(state IN ('RESERVED','STARTED','COMMITTED','CANCELED','BURNED')),
 CHECK((state='COMMITTED')=(result IS NOT NULL)),
 CHECK((state IN ('STARTED','COMMITTED','BURNED'))=(seed IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS charges (
 tenant TEXT NOT NULL, operation_id TEXT NOT NULL,
 account_id TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0),
 disposition TEXT NOT NULL CHECK(disposition IN ('HELD','SPENT','RETURNED')),
 PRIMARY KEY(tenant,operation_id,account_id),
 FOREIGN KEY(tenant,operation_id) REFERENCES operations(tenant,id),
 FOREIGN KEY(tenant,account_id) REFERENCES accounts(tenant,id)
);
CREATE TABLE IF NOT EXISTS deliveries (
 tenant TEXT NOT NULL, id TEXT NOT NULL, operation_id TEXT NOT NULL,
 recipient TEXT NOT NULL, result_digest TEXT NOT NULL,
 gateway TEXT NOT NULL, session TEXT NOT NULL,
 issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 handoff_admitted INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant,id),
 FOREIGN KEY(tenant,operation_id) REFERENCES operations(tenant,id),
 CHECK(expires_at>issued_at)
);
CREATE TABLE IF NOT EXISTS clock_floor (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), observed INTEGER NOT NULL
);
INSERT OR IGNORE INTO clock_floor VALUES(1,0);
"""


class Ledger:
    allowed_root_modes=('direct',)
    storage_profile='synthetic-plaintext-v1'
    def __init__(self, path, clock=None):
        self.path = str(path)
        self.db = sqlite3.connect(self.path, timeout=20, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA synchronous=FULL')
        # Clock is injected by the trusted service bootstrap, never by a request.
        self.clock = clock if clock is not None else lambda: int(time.time())
        self._tx_time = None
        try:
            self.check_storage_profile(allow_empty=True)
        except BaseException:
            self.db.close()
            raise

    @classmethod
    def create(cls, path, clock=None, **kwargs):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        obj = cls(path, clock=clock, **kwargs)
        obj.db.executescript(SCHEMA)
        obj.db.execute('CREATE TABLE IF NOT EXISTS storage_metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), profile TEXT NOT NULL, key_check TEXT NOT NULL)')
        obj.db.execute('INSERT OR IGNORE INTO storage_metadata VALUES(1,?,?)',obj.storage_configuration())
        obj.check_storage_profile()
        return obj

    def storage_configuration(self):
        return (self.storage_profile,'')

    def check_storage_profile(self, allow_empty=False):
        tables={r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if allow_empty and not tables:
            return
        if 'storage_metadata' not in tables:
            raise Rejected('STORAGE_PROFILE_MISMATCH')
        rows=self.db.execute('SELECT profile,key_check FROM storage_metadata').fetchall()
        if len(rows)!=1 or tuple(rows[0])!=self.storage_configuration():
            raise Rejected('STORAGE_PROFILE_MISMATCH')

    def protect_operation_field(self, kind, tenant, oid, digest, value):
        return value

    def open_operation_row(self, row):
        return row

    def result_binding(self, tenant, oid, digest, result):
        return hashlib.sha256(result).hexdigest()

    def close(self):
        self.db.close()

    def begin_transaction_guard(self):
        # Optional authoritative-state check before observing time or business data.
        pass

    def commit_transaction_guard(self):
        # Optional durable authority/fencing step BEFORE the local commit/ACK.
        pass

    @contextmanager
    def tx(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.check_storage_profile()
            self.begin_transaction_guard()
            self._tx_time = self.observe_clock()
            # Preserve the observed clock even when the operation is rejected.
            # Otherwise an expired attempt followed by clock rollback could
            # resurrect a ticket after the rejected transaction lost its floor.
            self.db.execute('SAVEPOINT operation')
            try:
                yield
            except BaseException:
                self.db.execute('ROLLBACK TO operation')
                self.db.execute('RELEASE operation')
                self.commit_transaction_guard()
                self.db.commit()
                raise
            else:
                self.db.execute('RELEASE operation')
                self.commit_transaction_guard()
                self.db.commit()
        except BaseException:
            if self.db.in_transaction:
                self.db.rollback()
            raise
        finally:
            self._tx_time = None

    def root(self, tenant, root_id):
        row = self.db.execute('SELECT * FROM roots WHERE tenant=? AND id=?',
                              (tenant, root_id)).fetchone()
        if row is None:
            raise Rejected('UNAUTHORIZED')
        return row

    def op(self, tenant, operation_id):
        row = self.db.execute('SELECT * FROM operations WHERE tenant=? AND id=?',
                              (tenant, operation_id)).fetchone()
        if row is None:
            raise Rejected('UNAUTHORIZED')
        return self.open_operation_row(row)

    def observe_clock(self):
        # Call only within a write transaction. This detects local clock rollback
        # against retained state; it does NOT protect against DB snapshot rollback.
        value = self.clock()
        if type(value) is not int or value < 0 or value >= 2**62:
            raise Rejected('INVALID_CLOCK')
        floor = self.db.execute('SELECT observed FROM clock_floor WHERE singleton=1').fetchone()[0]
        if value < floor:
            raise Rejected('CLOCK_ROLLBACK')
        self.db.execute('UPDATE clock_floor SET observed=? WHERE singleton=1',(value,))
        return value

    def now(self):
        if self._tx_time is None:
            raise RuntimeError('clock access outside transaction')
        return self._tx_time

    def live_root(self, tenant, root_id):
        root = self.root(tenant, root_id)
        if root['revoked']:
            raise Rejected('REVOKED')
        if self.now() >= root['expires_at']:
            raise Rejected('EXPIRED')
        return root

    def provision(self, tenant, root_id, actor, recipient, accounts, expires_at=2**62):
        with self.tx():
            if type(expires_at) is not int or not 0 < expires_at <= 2**62:
                raise Rejected('INVALID_EXPIRY')
            self.db.execute('INSERT INTO roots(tenant,id,actor,recipient,expires_at) VALUES(?,?,?,?,?)',
                            (tenant, root_id, actor, recipient, expires_at))
            for account, limit in accounts.items():
                if type(limit) is not int or not 0 <= limit <= 2**62:
                    raise Rejected('INVALID_LIMIT')
                self.db.execute('INSERT INTO accounts(tenant,id,total,free) VALUES(?,?,?,?)',
                                (tenant, account, limit, limit))

    def reserve(self, action, actor, fault=lambda point: None):
        # Internal harness JSON, NOT the normative CBOR/COSE wire encoding.
        if set(action) != {'tenant','id','root','recipient','parameters','costs'}:
            raise Rejected('INVALID_ACTION')
        if not isinstance(action['costs'], dict) or not action['costs']:
            raise Rejected('INVALID_COST')
        if any(type(v) is not int or not 0 < v <= 2**62 for v in action['costs'].values()):
            raise Rejected('INVALID_COST')
        body = json.dumps(action, sort_keys=True, separators=(',', ':'), allow_nan=False)
        digest = hashlib.sha256(body.encode()).hexdigest()
        tenant, oid = action['tenant'], action['id']
        with self.tx():
            root = self.root(tenant, action['root'])
            self.require_root_mode(root)
            self.validate_request_identity(action, root, actor)
            self.validate_reservation(action, root)
            self.authorize_reservation(action, root)
            old = self.db.execute('SELECT * FROM operations WHERE tenant=? AND id=?',
                                  (tenant, oid)).fetchone()
            if old is not None:
                if old['digest'] != digest or old['actor'] != actor:
                    raise Rejected('ACTION_CONFLICT')
                return dict(old)
            self.live_root(tenant, action['root'])
            self.db.execute('INSERT INTO operations(tenant,id,root_id,actor,recipient,digest,action,state) VALUES(?,?,?,?,?,?,?,?)',
                            (tenant,oid,action['root'],actor,action['recipient'],digest,body,'RESERVED'))
            for account, amount in sorted(action['costs'].items()):
                n = self.db.execute('UPDATE accounts SET free=free-?,reserved=reserved+? WHERE tenant=? AND id=? AND free>=?',
                                    (amount,amount,tenant,account,amount)).rowcount
                if n != 1:
                    raise Rejected('BUDGET_EXHAUSTED')
                self.db.execute('INSERT INTO charges VALUES(?,?,?,?,?)',
                                (tenant,oid,account,amount,'HELD'))
                fault('after_account_reserve')
            self.after_reservation(action)
            fault('before_reserve_commit')
        fault('after_reserve_commit')
        return dict(self.op(tenant, oid))

    def validate_reservation(self, action, root):
        # Trusted profile extension, evaluated within the reservation transaction.
        # This generic harness leaves mechanism/account authority to its caller.
        pass

    def validate_request_identity(self, action, root, actor):
        if actor != root['actor'] or action['recipient'] != root['recipient']:
            raise Rejected('UNAUTHORIZED')

    def require_root_mode(self, root):
        if root['authorization_mode'] not in self.allowed_root_modes:
            raise Rejected('SERVICE_PROFILE_MISMATCH')

    def after_reservation(self, action):
        # Optional durable work registration in the SAME reservation transaction.
        pass

    def authorize_reservation(self, action, root):
        # Optional cryptographic admission and replay consumption in this tx.
        pass

    def claim(self, tenant, oid, actor, fault=lambda point: None):
        with self.tx():
            op = self.op(tenant,oid)
            if op['actor'] != actor:
                raise Rejected('UNAUTHORIZED')
            if op['state'] == 'STARTED':
                # Continuation of the prior L1, not new authority after revocation.
                return dict(op)
            if op['state'] != 'RESERVED':
                raise Rejected('INVALID_STATE')
            self.live_root(tenant,op['root_id'])
            seed = secrets.token_bytes(32)
            seed = self.protect_operation_field('seed',tenant,oid,op['digest'],seed)
            self.db.execute("UPDATE operations SET state='STARTED',generation=1,seed=? WHERE tenant=? AND id=?",
                            (seed,tenant,oid))
            fault('before_claim_commit')
        fault('after_claim_commit')
        return dict(self.op(tenant,oid))

    def recover(self, tenant, oid, expected_generation):
        # Trusted recovery coordinator; never exposed to an Agent.
        with self.tx():
            op = self.op(tenant,oid)
            if op['state'] != 'STARTED' or op['generation'] != expected_generation:
                raise Rejected('STALE_WORKER')
            self.db.execute('UPDATE operations SET generation=generation+1 WHERE tenant=? AND id=?', (tenant,oid))
        return dict(self.op(tenant,oid))

    def move_charges(self, tenant, oid, target, fault=lambda point: None):
        for row in self.db.execute('SELECT * FROM charges WHERE tenant=? AND operation_id=?', (tenant,oid)).fetchall():
            if row['disposition'] != 'HELD':
                raise Rejected('ALREADY_SETTLED')
            column = 'spent' if target == 'SPENT' else 'free'
            self.db.execute(f'UPDATE accounts SET reserved=reserved-?,{column}={column}+? WHERE tenant=? AND id=?',
                            (row['amount'],row['amount'],tenant,row['account_id']))
            fault('after_account_settle')
        self.db.execute('UPDATE charges SET disposition=? WHERE tenant=? AND operation_id=?', (target,tenant,oid))

    def commit(self, tenant, oid, generation, action_digest, result, fault=lambda point: None):
        if type(result) is not bytes or len(result) > 65536:
            raise Rejected('INVALID_RESULT')
        result_digest = self.result_binding(tenant,oid,action_digest,result)
        with self.tx():
            op = self.op(tenant,oid)
            if op['generation'] != generation:
                raise Rejected('STALE_WORKER')
            if op['digest'] != action_digest:
                raise Rejected('ACTION_CONFLICT')
            if op['state'] == 'COMMITTED':
                if op['result'] != result:
                    raise Rejected('OUTPUT_CONFLICT')
                return op['result']
            if op['state'] != 'STARTED':
                raise Rejected('INVALID_STATE')
            self.db.execute("UPDATE operations SET state='COMMITTED',result=?,result_digest=? WHERE tenant=? AND id=?",
                            (self.protect_operation_field('result',tenant,oid,op['digest'],result),result_digest,tenant,oid))
            fault('after_result_write')
            self.move_charges(tenant,oid,'SPENT',fault)
            fault('before_result_commit')
        fault('after_result_commit')
        return result

    def cancel(self, tenant, oid, actor):
        with self.tx():
            op = self.op(tenant,oid)
            if op['actor'] != actor:
                raise Rejected('UNAUTHORIZED')
            if op['state'] in ('CANCELED','BURNED'):
                return op['state']
            if op['state'] == 'COMMITTED':
                raise Rejected('ALREADY_COMMITTED')
            before = op['state'] == 'RESERVED'
            state = 'CANCELED' if before else 'BURNED'
            self.move_charges(tenant,oid,'RETURNED' if before else 'SPENT')
            self.db.execute('UPDATE operations SET state=? WHERE tenant=? AND id=?', (state,tenant,oid))
        return state

    def revoke(self, tenant, root_id):
        with self.tx():
            self.root(tenant,root_id)
            self.db.execute('UPDATE roots SET revoked=1 WHERE tenant=? AND id=?', (tenant,root_id))

    def admit_delivery(self, tenant, oid, recipient, delivery_id, gateway, session, ttl=60, fault=lambda point: None):
        # Internal L3 primitive, NOT a public fetch endpoint. An external ordered
        # publication controller is still required before calling this primitive.
        with self.tx():
            if type(ttl) is not int or not 0 < ttl <= 60:
                raise Rejected('INVALID_TTL')
            if not gateway or not session:
                raise Rejected('UNAUTHORIZED')
            op = self.op(tenant,oid)
            if op['recipient'] != recipient:
                raise Rejected('UNAUTHORIZED')
            # A new publicly requested fetch always checks authority, even when
            # a caller supplies the ID of an old ticket. Only recover_delivery
            # can resume already-admitted work after revocation.
            root = self.live_root(tenant,op['root_id'])
            self.require_root_mode(root)
            self.validate_delivery(op)
            self.authorize_delivery(op)
            now = self.now()
            existing = self.db.execute('SELECT * FROM deliveries WHERE tenant=? AND id=?', (tenant,delivery_id)).fetchone()
            if existing:
                if existing['operation_id'] != oid or existing['recipient'] != recipient or existing['gateway'] != gateway or existing['session'] != session:
                    raise Rejected('DELIVERY_CONFLICT')
                if now >= existing['expires_at']:
                    raise Rejected('TICKET_EXPIRED')
                # Exact retry cannot extend the original lifetime.
                self.on_delivery_admitted(existing)
                return dict(existing)
            if op['state'] != 'COMMITTED':
                raise Rejected('NOT_COMMITTED')
            expiry = self.delivery_expiry(op,root,now,ttl)
            self.db.execute('INSERT INTO deliveries(tenant,id,operation_id,recipient,result_digest,gateway,session,issued_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)',
                            (tenant,delivery_id,oid,recipient,op['result_digest'],gateway,session,now,expiry))
            self.on_delivery_admitted(self.db.execute('SELECT * FROM deliveries WHERE tenant=? AND id=?', (tenant,delivery_id)).fetchone())
            fault('before_delivery_commit')
        fault('after_delivery_commit')
        return dict(self.db.execute('SELECT * FROM deliveries WHERE tenant=? AND id=?', (tenant,delivery_id)).fetchone())

    def on_delivery_admitted(self, ticket):
        # Optional durable outbox registration in the SAME L3 transaction.
        pass

    def validate_delivery(self, op):
        # Optional publication gate, checked in the SAME transaction as new L3.
        pass

    def authorize_delivery(self, op):
        # Dynamic profile authority checks for NEW L3, not old-ticket recovery.
        pass

    def delivery_expiry(self, op, root, now, ttl):
        return min(now+ttl,root['expires_at'])

    def delivery_ticket(self, tenant, delivery_id, recipient, gateway, session):
        # Internal helper, called inside a transaction by a trusted gateway.
        ticket = self.db.execute('SELECT * FROM deliveries WHERE tenant=? AND id=?', (tenant,delivery_id)).fetchone()
        if ticket is None or ticket['recipient'] != recipient or ticket['gateway'] != gateway or ticket['session'] != session:
            raise Rejected('UNAUTHORIZED')
        if self.now() >= ticket['expires_at']:
            raise Rejected('TICKET_EXPIRED')
        return ticket

    def recover_delivery(self, tenant, delivery_id, recipient, gateway, session):
        # Only the authenticated gateway can resume a prior attempt. No new L3,
        # session rebind, renewed lifetime, or replacement ticket is created.
        with self.tx():
            return dict(self.delivery_ticket(tenant,delivery_id,recipient,gateway,session))

    def emit(self, tenant, delivery_id, recipient, gateway, session, fault=lambda point: None):
        # Records handoff admission using the trusted time sampled in this
        # serialized transaction. It does not attest that any network bytes
        # were sent, or impose a wall-clock bound on their eventual arrival.
        with self.tx():
            ticket = self.delivery_ticket(tenant,delivery_id,recipient,gateway,session)
            op = self.op(tenant,ticket['operation_id'])
            if op['state'] != 'COMMITTED' or op['result_digest'] != ticket['result_digest']:
                raise Rejected('RESULT_UNAVAILABLE')
            self.db.execute('UPDATE deliveries SET handoff_admitted=1 WHERE tenant=? AND id=?', (tenant,delivery_id))
            fault('before_emit_commit')
            result = op['result']
        fault('after_emit_commit')
        return result

    def audit(self):
        # Independent aggregate checks catch missing cross-table writes.
        errors = []
        for a in self.db.execute('SELECT * FROM accounts'):
            totals = dict(self.db.execute('SELECT disposition, SUM(amount) FROM charges WHERE tenant=? AND account_id=? GROUP BY disposition',
                                         (a['tenant'],a['id'])).fetchall())
            if a['reserved'] != totals.get('HELD',0) or a['spent'] != totals.get('SPENT',0):
                errors.append('ACCOUNT_COVERAGE')
        for op in self.db.execute('SELECT * FROM operations'):
            op = self.open_operation_row(op)
            states = [r[0] for r in self.db.execute('SELECT disposition FROM charges WHERE tenant=? AND operation_id=?', (op['tenant'],op['id']))]
            expected = {'RESERVED':'HELD','STARTED':'HELD','COMMITTED':'SPENT','BURNED':'SPENT','CANCELED':'RETURNED'}[op['state']]
            if not states or any(s != expected for s in states):
                errors.append('OPERATION_COVERAGE')
            if op['result'] is not None and self.result_binding(op['tenant'],op['id'],op['digest'],op['result']) != op['result_digest']:
                errors.append('OUTPUT_BINDING')
        for ticket in self.db.execute('SELECT * FROM deliveries'):
            op = self.op(ticket['tenant'],ticket['operation_id'])
            root = self.root(ticket['tenant'],op['root_id'])
            if (op['state'] != 'COMMITTED' or ticket['recipient'] != op['recipient'] or
                ticket['result_digest'] != op['result_digest']):
                errors.append('DELIVERY_BINDING')
            if (not ticket['gateway'] or not ticket['session'] or
                not 0 < ticket['expires_at']-ticket['issued_at'] <= 60 or
                ticket['expires_at'] > root['expires_at']):
                errors.append('DELIVERY_LIFETIME')
        return errors
