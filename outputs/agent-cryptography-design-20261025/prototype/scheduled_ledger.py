"""Durable logical controller for synthetic data. NOT a network privacy proof.

One serialized transaction advances one public logical slot. It journals controls,
executes one public-counted work step, commits any result/charges, and publishes
ordered eligibility. Logical slots are not physical constant-time intervals.
All methods remain trusted service primitives; there is no public HTTP endpoint.
"""
import hashlib
import json
import secrets
from dp_ledger import DPLedger, Rejected, public_id

SCHEDULE_OVERHEAD=82  # One durable admission slot, then 80 noise bits + finalizer.

SCHEMA = """
CREATE TABLE IF NOT EXISTS schedulers (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL,
 tick INTEGER NOT NULL DEFAULT 0, next_seq INTEGER NOT NULL DEFAULT 1,
 publish_seq INTEGER NOT NULL DEFAULT 1, cursor INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant,domain_id),
 FOREIGN KEY(tenant,domain_id) REFERENCES privacy_domains(tenant,id)
);
CREATE TABLE IF NOT EXISTS jobs (
 tenant TEXT NOT NULL, operation_id TEXT NOT NULL, domain_id TEXT NOT NULL,
 seq INTEGER NOT NULL, work INTEGER NOT NULL, pc INTEGER NOT NULL DEFAULT 0,
 count_value INTEGER NOT NULL DEFAULT 0,
 alive0 INTEGER NOT NULL DEFAULT 1, alive1 INTEGER NOT NULL DEFAULT 1,
 g0 INTEGER NOT NULL DEFAULT 0, g1 INTEGER NOT NULL DEFAULT 0,
 suppressed INTEGER NOT NULL DEFAULT 0, publication TEXT,
 private_state BLOB,
 PRIMARY KEY(tenant,operation_id), UNIQUE(tenant,domain_id,seq),
 FOREIGN KEY(tenant,operation_id) REFERENCES operations(tenant,id),
 CHECK(pc>=0 AND pc<=work),
 CHECK(publication IS NULL OR publication IN ('RELEASE','WITHHELD'))
);
CREATE TABLE IF NOT EXISTS tick_requests (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL, id TEXT NOT NULL,
 digest TEXT NOT NULL, tick INTEGER NOT NULL,
 PRIMARY KEY(tenant,domain_id,id), UNIQUE(tenant,domain_id,tick),
 FOREIGN KEY(tenant,domain_id) REFERENCES schedulers(tenant,domain_id)
);
CREATE TABLE IF NOT EXISTS publication_events (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL, event_seq INTEGER NOT NULL,
 tick INTEGER NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL,
 PRIMARY KEY(tenant,domain_id,event_seq),
 FOREIGN KEY(tenant,domain_id) REFERENCES schedulers(tenant,domain_id)
);
"""


class ScheduledLedger(DPLedger):
    @classmethod
    def create(cls, path, clock=None, **kwargs):
        obj=super().create(path,clock=clock,**kwargs)
        obj.db.executescript(SCHEMA)
        return obj

    def after_reservation(self, action):
        tenant, domain_id=action['tenant'],action['parameters']['domain']
        domain=self.domain(tenant,domain_id)
        self.db.execute('INSERT OR IGNORE INTO schedulers(tenant,domain_id) VALUES(?,?)',(tenant,domain_id))
        seq=self.db.execute('SELECT next_seq FROM schedulers WHERE tenant=? AND domain_id=?',(tenant,domain_id)).fetchone()[0]
        self.db.execute('INSERT INTO jobs(tenant,operation_id,domain_id,seq,work) VALUES(?,?,?,?,?)',
                        (tenant,action['id'],domain_id,seq,self.scheduled_work(action)))
        job=self.db.execute('SELECT * FROM jobs WHERE tenant=? AND operation_id=?',(tenant,action['id'])).fetchone()
        self.save_private_state(job,self.initial_private_state(action),0)
        self.db.execute('UPDATE schedulers SET next_seq=next_seq+1 WHERE tenant=? AND domain_id=?',(tenant,domain_id))

    def scheduled_work(self, action):
        return self.domain(action['tenant'],action['parameters']['domain'])['capacity']+SCHEDULE_OVERHEAD

    def initial_private_state(self, action):
        return dict(count_value=0,alive0=1,alive1=1,g0=0,g1=0)

    def operation_randomness(self, op):
        return secrets.token_bytes(32)

    def advance_private_step(self, op, job, private):
        # Called only after a previous transaction durably committed L1.
        pc=job['pc']-1; n=job['work']-SCHEDULE_OVERHEAD
        if pc<n:
            params=json.loads(op['action'])['parameters']
            value=self.db.execute('SELECT rows_json FROM snapshots WHERE tenant=? AND domain_id=? AND id=?',
                                  (op['tenant'],job['domain_id'],params['snapshot'])).fetchone()[0]
            rows=self.open_snapshot(op['tenant'],job['domain_id'],params['snapshot'],value)
            private['count_value']+=rows[pc]
        elif pc<n+80:
            bit_index=pc-n; side=bit_index//40
            bit=(op['seed'][bit_index//8]>>(7-bit_index%8))&1
            alive=private['alive'+str(side)]&bit
            private['alive'+str(side)]=alive
            private['g'+str(side)]+=alive
        else:
            return min(n,max(0,private['count_value']+private['g0']-private['g1'])).to_bytes(8,'big')
        return None

    def load_private_state(self, job):
        return {k:job[k] for k in ('count_value','alive0','alive1','g0','g1')}

    def save_private_state(self, job, state, pc):
        self.db.execute('UPDATE jobs SET count_value=?,alive0=?,alive1=?,g0=?,g1=? WHERE tenant=? AND operation_id=?',
                        tuple(state[k] for k in ('count_value','alive0','alive1','g0','g1'))+(job['tenant'],job['operation_id']))

    def validate_delivery(self, op):
        job=self.db.execute('SELECT publication FROM jobs WHERE tenant=? AND operation_id=?',(op['tenant'],op['id'])).fetchone()
        if job is None or job['publication'] != 'RELEASE':
            raise Rejected('PUBLICATION_PENDING_OR_WITHHELD')

    def authorization_active(self, op):
        root=self.root(op['tenant'],op['root_id'])
        return (root['authorization_mode'] in self.allowed_root_modes and
                not root['revoked'] and self.now()<root['expires_at'])

    # Prevent the normal execution/control API from bypassing the controller.
    # This is API discipline, not a boundary against hostile local Python or SQL.
    def claim(self, *args, **kwargs):
        raise Rejected('SCHEDULER_REQUIRED')
    recover=claim
    execute_count=claim
    commit=claim
    cancel=claim
    revoke=claim

    def append_event(self, tenant, domain_id, tick, kind, subject):
        seq=self.db.execute('SELECT COALESCE(MAX(event_seq),0)+1 FROM publication_events WHERE tenant=? AND domain_id=?',
                            (tenant,domain_id)).fetchone()[0]
        self.db.execute('INSERT INTO publication_events VALUES(?,?,?,?,?,?)',(tenant,domain_id,seq,tick,kind,subject))

    def command(self, tenant, domain_id, command, tick):
        kind=command.get('kind')
        if kind in ('noop','pause'):
            if set(command)!={'kind'}:
                raise Rejected('INVALID_COMMAND')
        elif kind=='revoke':
            if set(command)!={'kind','root','actor'}:
                raise Rejected('INVALID_COMMAND')
            root=self.root(tenant,command['root'])
            binding=self.db.execute('SELECT domain_id FROM domain_roots WHERE tenant=? AND root_id=?',
                                    (tenant,root['id'])).fetchone()
            if root['actor']!=command['actor'] or binding is None or binding['domain_id']!=domain_id:
                raise Rejected('UNAUTHORIZED')
            self.db.execute('UPDATE roots SET revoked=1 WHERE tenant=? AND id=?',(tenant,root['id']))
        elif kind=='cancel':
            if set(command)!={'kind','operation','actor'}:
                raise Rejected('INVALID_COMMAND')
            op=self.op(tenant,command['operation'])
            job=self.db.execute('SELECT * FROM jobs WHERE tenant=? AND operation_id=?',(tenant,op['id'])).fetchone()
            if op['actor']!=command['actor'] or job is None or job['domain_id']!=domain_id:
                raise Rejected('UNAUTHORIZED')
            if job['publication'] is not None:
                raise Rejected('ALREADY_PUBLISHED')
            if op['state'] in ('RESERVED','STARTED'):
                before=op['state']=='RESERVED'
                self.move_charges(tenant,op['id'],'RETURNED' if before else 'SPENT')
                self.db.execute('UPDATE operations SET state=? WHERE tenant=? AND id=?',
                                ('CANCELED' if before else 'BURNED',tenant,op['id']))
            self.db.execute('UPDATE jobs SET suppressed=1 WHERE tenant=? AND operation_id=?',(tenant,op['id']))
        else:
            raise Rejected('INVALID_COMMAND')
        # Subject contains public command metadata only, no hidden completion.
        self.append_event(tenant,domain_id,tick,'CONTROL_ACK',json.dumps(command,sort_keys=True,separators=(',',':')))

    def work_step(self, tenant, domain_id, fault):
        cursor=self.db.execute('SELECT cursor FROM schedulers WHERE tenant=? AND domain_id=?',(tenant,domain_id)).fetchone()[0]
        # Sequence and pc/work are public logical scheduling state.
        job=self.db.execute('SELECT * FROM jobs WHERE tenant=? AND domain_id=? AND pc<work ORDER BY (seq>?) DESC,seq LIMIT 1',
                            (tenant,domain_id,cursor)).fetchone()
        if job is None:
            return
        if job['work']!=self.scheduled_work(json.loads(self.op(tenant,job['operation_id'])['action'])):
            raise Rejected('SCHEDULE_PROFILE_MISMATCH')
        oid=job['operation_id']; op=self.op(tenant,oid)
        private=self.load_private_state(job)
        admission_slot=op['state']=='RESERVED'
        if admission_slot:
            if job['pc']!=0:raise Rejected('SCHEDULER_STATE_CONFLICT')
            root=self.root(tenant,op['root_id'])
            if not self.authorization_active(op):
                self.move_charges(tenant,oid,'RETURNED')
                self.db.execute("UPDATE operations SET state='CANCELED' WHERE tenant=? AND id=?",(tenant,oid))
            else:
                self.db.execute("UPDATE operations SET state='STARTED',seed=?,generation=1 WHERE tenant=? AND id=?",
                                (self.protect_operation_field('seed',tenant,oid,op['digest'],self.operation_randomness(op)),tenant,oid))
                fault('after_scheduled_claim')
            op=self.op(tenant,oid)
        if op['state']=='STARTED' and not admission_slot:
            if job['pc']<1:raise Rejected('SCHEDULER_STATE_CONFLICT')
            result=self.advance_private_step(op,job,private)
            if result is not None:
                digest=self.result_binding(tenant,oid,op['digest'],result)
                self.db.execute("UPDATE operations SET state='COMMITTED',result=?,result_digest=? WHERE tenant=? AND id=?",
                                (self.protect_operation_field('result',tenant,oid,op['digest'],result),digest,tenant,oid))
                fault('after_scheduled_result_write')
                self.move_charges(tenant,oid,'SPENT',fault)
        elif op['state'] not in ('CANCELED','BURNED','STARTED'):
            raise Rejected('SCHEDULER_STATE_CONFLICT')
        # A successful L1 occupies its own public slot. No private row or noise
        # bit is read until a later transaction sees its durable seed and state.
        # Canceled tasks consume dummy slots too; private work never shortens them.
        self.save_private_state(job,private,job['pc']+1)
        self.db.execute('UPDATE jobs SET pc=pc+1 WHERE tenant=? AND operation_id=?',(tenant,oid))
        self.db.execute('UPDATE schedulers SET cursor=? WHERE tenant=? AND domain_id=?',(job['seq'],tenant,domain_id))
        fault('after_work_step')

    def publish(self, tenant, domain_id, tick, fault):
        while True:
            seq=self.db.execute('SELECT publish_seq FROM schedulers WHERE tenant=? AND domain_id=?',(tenant,domain_id)).fetchone()[0]
            job=self.db.execute('SELECT * FROM jobs WHERE tenant=? AND domain_id=? AND seq=?',(tenant,domain_id,seq)).fetchone()
            if job is None or job['pc']<job['work']:
                return
            op=self.op(tenant,job['operation_id']); root=self.root(tenant,op['root_id'])
            allowed=(op['state']=='COMMITTED' and not job['suppressed'] and self.authorization_active(op))
            kind='RELEASE' if allowed else 'WITHHELD'
            self.append_event(tenant,domain_id,tick,kind,op['id'])
            self.db.execute('UPDATE jobs SET publication=? WHERE tenant=? AND operation_id=?',(kind,tenant,op['id']))
            self.db.execute('UPDATE schedulers SET publish_seq=publish_seq+1 WHERE tenant=? AND domain_id=?',(tenant,domain_id))
            fault('after_publication_write')

    def advance(self, tenant, domain_id, request_id, expected_tick, command=None, fault=lambda point:None):
        # Trusted driver. Logical expected_tick is a CAS, request_id a retry key.
        # Neither wall-clock ticking nor a public error/response protocol is implemented.
        public_id(request_id)
        if type(expected_tick) is not int or expected_tick<0:
            raise Rejected('INVALID_TICK')
        command={'kind':'noop'} if command is None else command
        if type(command) is not dict:
            raise Rejected('INVALID_COMMAND')
        body=json.dumps({'expected_tick':expected_tick,'command':command},sort_keys=True,separators=(',',':'),allow_nan=False)
        digest=hashlib.sha256(body.encode()).hexdigest()
        with self.tx():
            self.domain(tenant,domain_id)
            self.db.execute('INSERT OR IGNORE INTO schedulers(tenant,domain_id) VALUES(?,?)',(tenant,domain_id))
            old=self.db.execute('SELECT * FROM tick_requests WHERE tenant=? AND domain_id=? AND id=?',(tenant,domain_id,request_id)).fetchone()
            if old:
                if old['digest']!=digest:
                    raise Rejected('TICK_CONFLICT')
                return {'request_id':request_id,'tick':old['tick']}
            state=self.db.execute('SELECT * FROM schedulers WHERE tenant=? AND domain_id=?',(tenant,domain_id)).fetchone()
            if state['tick']!=expected_tick:
                raise Rejected('STALE_TICK')
            tick=expected_tick+1
            self.command(tenant,domain_id,command,tick)
            fault('after_control_write')
            if command['kind']!='pause':
                self.work_step(tenant,domain_id,fault)
            self.publish(tenant,domain_id,tick,fault)
            self.db.execute('UPDATE schedulers SET tick=? WHERE tenant=? AND domain_id=?',(tick,tenant,domain_id))
            self.db.execute('INSERT INTO tick_requests VALUES(?,?,?,?,?)',(tenant,domain_id,request_id,digest,tick))
            fault('before_tick_commit')
        fault('after_tick_commit')
        return {'request_id':request_id,'tick':tick}

    def journal_internal(self, tenant, domain_id):
        # NOT an external fetch endpoint. Output eligibility is not a bearer permit.
        return [dict(r) for r in self.db.execute('SELECT event_seq,tick,kind,subject FROM publication_events WHERE tenant=? AND domain_id=? ORDER BY event_seq',
                                               (tenant,domain_id))]

    def audit(self):
        errors=super().audit()
        for op in self.db.execute('SELECT * FROM operations'):
            if self.db.execute('SELECT 1 FROM jobs WHERE tenant=? AND operation_id=?',(op['tenant'],op['id'])).fetchone() is None:
                errors.append('MISSING_JOB')
        for state in self.db.execute('SELECT * FROM schedulers'):
            key=(state['tenant'],state['domain_id'])
            jobs=self.db.execute('SELECT * FROM jobs WHERE tenant=? AND domain_id=? ORDER BY seq',key).fetchall()
            if [j['seq'] for j in jobs]!=list(range(1,state['next_seq'])):
                errors.append('QUEUE_SEQUENCE')
            events=self.journal_internal(*key)
            if [e['event_seq'] for e in events]!=list(range(1,len(events)+1)):
                errors.append('EVENT_SEQUENCE')
            ticks=self.db.execute('SELECT tick FROM tick_requests WHERE tenant=? AND domain_id=? ORDER BY tick',key).fetchall()
            if [t[0] for t in ticks]!=list(range(1,state['tick']+1)):
                errors.append('TICK_COVERAGE')
            published=[e for e in events if e['kind'] in ('RELEASE','WITHHELD')]
            expected=[]
            for j in jobs:
                op=self.op(key[0],j['operation_id'])
                if j['work']!=self.scheduled_work(json.loads(op['action'])):
                    errors.append('SCHEDULE_PROFILE_MISMATCH')
                if (op['state']=='RESERVED' and j['pc']!=0) or (op['state']=='STARTED' and not 1<=j['pc']<j['work']):
                    errors.append('ADMISSION_SLOT_STATE')
                if op['state']=='COMMITTED' and j['pc']!=j['work']:
                    errors.append('EARLY_COMMIT')
                if j['seq']<state['publish_seq']:
                    if j['pc']!=j['work'] or j['publication'] is None:
                        errors.append('EARLY_PUBLICATION')
                    if j['publication']=='RELEASE' and op['state']!='COMMITTED':
                        errors.append('UNCOMMITTED_RELEASE')
                    expected.append((j['publication'],j['operation_id']))
                elif j['publication'] is not None:
                    errors.append('OUT_OF_ORDER_PUBLICATION')
            if [(e['kind'],e['subject']) for e in published]!=expected:
                errors.append('PUBLICATION_COVERAGE')
        for ticket in self.db.execute('SELECT * FROM deliveries'):
            try:
                self.validate_delivery(self.op(ticket['tenant'],ticket['operation_id']))
            except Rejected:
                errors.append('DELIVERY_BEFORE_PUBLICATION')
        return errors
