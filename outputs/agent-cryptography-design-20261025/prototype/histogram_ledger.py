"""Mixed count/histogram durable logical execution, synthetic plaintext profile.

Trusted internal setup and controller only. No signature/ancestor-cap extension,
variable-width encrypted vault, witness or network delivery integration yet.
Distinct storage profile prevents opening this database with the count service.
"""
import hashlib
import json

from dp_ledger import MECHANISM as COUNT, PROFILE, Rejected, public_id
from scheduled_ledger import ScheduledLedger
from histogram_kernel import HistogramJob, MECHANISM as HISTOGRAM, fresh_tape, validate_tape, decode_result

REGISTRY='count_histogram_registry_v1_candidate'
CODEC='uint64be_public_bucket_order_v1'
SCHEMA="""
CREATE TABLE IF NOT EXISTS histogram_catalogs (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL, id TEXT NOT NULL,
 buckets_json TEXT NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(tenant,domain_id,id),
 FOREIGN KEY(tenant,domain_id) REFERENCES privacy_domains(tenant,id)
);
CREATE TABLE IF NOT EXISTS histogram_snapshots (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL, snapshot_id TEXT NOT NULL,
 catalog_id TEXT NOT NULL,
 PRIMARY KEY(tenant,domain_id,snapshot_id),
 FOREIGN KEY(tenant,domain_id,snapshot_id) REFERENCES snapshots(tenant,domain_id,id),
 FOREIGN KEY(tenant,domain_id,catalog_id) REFERENCES histogram_catalogs(tenant,domain_id,id)
);
"""


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)


class HistogramLedger(ScheduledLedger):
    storage_profile='synthetic-mixed-count-histogram-v1'
    domain_mechanism=REGISTRY

    @classmethod
    def create(cls,path,clock=None,**kwargs):
        obj=super().create(path,clock=clock,**kwargs)
        obj.db.executescript(SCHEMA)
        return obj

    def install_catalog(self,tenant,domain_id,catalog_id,buckets):
        public_id(catalog_id)
        # Validate only public metadata. Never access a private snapshot here.
        try: HistogramJob([0],fresh_tape(len(buckets),randbytes=lambda n:bytes(n)),capacity=1,buckets=buckets)
        except (ValueError,TypeError,UnicodeError):raise Rejected('INVALID_CATALOG')
        body=canonical(list(buckets));digest=hashlib.sha256(body.encode()).hexdigest()
        with self.tx():
            self.domain(tenant,domain_id)
            self.db.execute('INSERT INTO histogram_catalogs VALUES(?,?,?,?,?)',
                            (tenant,domain_id,catalog_id,body,digest))
        return digest

    def catalog(self,tenant,domain_id,catalog_id):
        public_id(catalog_id)
        row=self.db.execute('SELECT * FROM histogram_catalogs WHERE tenant=? AND domain_id=? AND id=?',
                            (tenant,domain_id,catalog_id)).fetchone()
        if row is None:raise Rejected('UNKNOWN_CATALOG')
        return row

    def install_histogram_snapshot(self,tenant,domain_id,snapshot_id,catalog_id,rows):
        public_id(snapshot_id)
        with self.tx():
            domain=self.domain(tenant,domain_id);catalog=self.catalog(tenant,domain_id,catalog_id)
            b=len(json.loads(catalog['buckets_json']))
            if (type(rows) is not list or len(rows)!=domain['capacity'] or
                    any(type(x) is not int or not 0<=x<=b for x in rows)):
                raise Rejected('INVALID_SNAPSHOT')
            self.db.execute('INSERT INTO snapshots VALUES(?,?,?,?)',
                            (tenant,domain_id,snapshot_id,self.protect_histogram_snapshot(tenant,domain_id,snapshot_id,catalog_id,rows)))
            self.db.execute('INSERT INTO histogram_snapshots VALUES(?,?,?,?)',
                            (tenant,domain_id,snapshot_id,catalog_id))

    def protect_histogram_snapshot(self,tenant,domain_id,snapshot_id,catalog_id,rows):
        return self.protect_snapshot(tenant,domain_id,snapshot_id,rows)

    def reserve_histogram(self,tenant,oid,root_id,recipient,domain_id,snapshot_id,catalog_id,actor,
                          fault=lambda point:None):
        for value in (tenant,oid,root_id,recipient,domain_id,snapshot_id,catalog_id,actor):public_id(value)
        domain=self.domain(tenant,domain_id);catalog=self.catalog(tenant,domain_id,catalog_id)
        action=dict(tenant=tenant,id=oid,root=root_id,recipient=recipient,
                    parameters=dict(domain=domain_id,snapshot=snapshot_id,mechanism=HISTOGRAM,accountant=PROFILE,
                                    catalog=catalog_id,catalog_digest=catalog['digest'],
                                    bucket_count=len(json.loads(catalog['buckets_json'])),capacity=domain['capacity'],
                                    k=40,codec=CODEC),costs=self.registered_costs(domain))
        registered=self.reserve(action,actor,fault)
        return {'operation_id':oid,'action_digest':registered['digest'],'registration':'REGISTERED'}

    def validate_reservation(self,action,root):
        params=action['parameters']
        if type(params) is not dict:raise Rejected('INVALID_PARAMETERS')
        if params.get('mechanism')==COUNT:
            super().validate_reservation(action,root)
            if self.db.execute('SELECT 1 FROM histogram_snapshots WHERE tenant=? AND domain_id=? AND snapshot_id=?',
                               (action['tenant'],params['domain'],params['snapshot'])).fetchone():
                raise Rejected('SNAPSHOT_MECHANISM_MISMATCH')
            return
        expected={'domain','snapshot','mechanism','accountant','catalog','catalog_digest','bucket_count','capacity','k','codec'}
        if set(params)!=expected:raise Rejected('INVALID_PARAMETERS')
        for value in (action['tenant'],action['id'],action['root'],action['recipient'],params['domain'],params['snapshot'],params['catalog']):public_id(value)
        domain=self.domain(action['tenant'],params['domain'])
        catalog=self.catalog(action['tenant'],params['domain'],params['catalog'])
        b=len(json.loads(catalog['buckets_json']))
        if (params['mechanism']!=HISTOGRAM or params['accountant']!=PROFILE or params['codec']!=CODEC or
                params['catalog_digest']!=catalog['digest'] or
                any(type(params[k]) is not int or params[k]!=v for k,v in (('bucket_count',b),('capacity',domain['capacity']),('k',40)))):
            raise Rejected('PROFILE_MISMATCH')
        binding=self.db.execute('SELECT domain_id FROM domain_roots WHERE tenant=? AND root_id=?',
                                (action['tenant'],root['id'])).fetchone()
        if binding is None or binding['domain_id']!=domain['id']:raise Rejected('UNAUTHORIZED_DOMAIN')
        if action['costs']!=self.registered_costs(domain,action):raise Rejected('REGISTERED_COST_MISMATCH')
        snap=self.db.execute('SELECT catalog_id FROM histogram_snapshots WHERE tenant=? AND domain_id=? AND snapshot_id=?',
                             (action['tenant'],domain['id'],params['snapshot'])).fetchone()
        if snap is None:raise Rejected('SNAPSHOT_MECHANISM_MISMATCH')
        if snap['catalog_id']!=params['catalog']:raise Rejected('SNAPSHOT_CATALOG_MISMATCH')

    def scheduled_work(self,action):
        p=action['parameters']
        if p['mechanism']==COUNT:return super().scheduled_work(action)
        return 1+p['bucket_count']*(p['capacity']+81)

    def initial_private_state(self,action):
        p=action['parameters']
        if p['mechanism']==COUNT:return super().initial_private_state(action)
        b=p['bucket_count']
        return dict(counts=[0]*b,alive=[[1,1] for _ in range(b)],g=[[0,0] for _ in range(b)],outputs=[0]*b)

    def is_histogram(self,job):
        return json.loads(self.op(job['tenant'],job['operation_id'])['action'])['parameters']['mechanism']==HISTOGRAM

    def load_private_state(self,job):
        if not self.is_histogram(job):return super().load_private_state(job)
        try:return json.loads(job['private_state'])
        except (TypeError,ValueError):raise Rejected('HISTOGRAM_STATE_CONFLICT')

    def save_private_state(self,job,state,pc):
        if not self.is_histogram(job):return super().save_private_state(job,state,pc)
        self.db.execute('UPDATE jobs SET private_state=? WHERE tenant=? AND operation_id=?',
                        (canonical(state).encode(),job['tenant'],job['operation_id']))

    def operation_randomness(self,op):
        p=json.loads(op['action'])['parameters']
        return fresh_tape(p['bucket_count']) if p['mechanism']==HISTOGRAM else super().operation_randomness(op)

    def advance_private_step(self,op,job,private):
        p=json.loads(op['action'])['parameters']
        if p['mechanism']==COUNT:return super().advance_private_step(op,job,private)
        n=p['capacity'];bucket,index=divmod(job['pc']-1,n+81)
        if index<n:
            value=self.db.execute('SELECT rows_json FROM snapshots WHERE tenant=? AND domain_id=? AND id=?',
                                  (op['tenant'],p['domain'],p['snapshot'])).fetchone()[0]
            rows=self.open_snapshot(op['tenant'],p['domain'],p['snapshot'],value)
            private['counts'][bucket]+=int(rows[index]==bucket+1)
        elif index<n+80:
            offset=index-n;side=offset//40;bit_index=bucket*80+offset
            bit=(op['seed'][bit_index//8]>>(7-bit_index%8))&1
            private['alive'][bucket][side]&=bit
            private['g'][bucket][side]+=private['alive'][bucket][side]
        else:
            private['outputs'][bucket]=min(n,max(0,private['counts'][bucket]+private['g'][bucket][0]-private['g'][bucket][1]))
            if bucket==p['bucket_count']-1:
                return b''.join(x.to_bytes(8,'big') for x in private['outputs'])
        return None

    def compute_internal(self,tenant,oid):
        op=self.op(tenant,oid);action=json.loads(op['action']);p=action['parameters']
        if p['mechanism']==COUNT:return super().compute_internal(tenant,oid)
        if op['state'] not in ('STARTED','COMMITTED'):raise Rejected('INVALID_STATE')
        self.validate_reservation(action,self.root(tenant,op['root_id']))
        value=self.db.execute('SELECT rows_json FROM snapshots WHERE tenant=? AND domain_id=? AND id=?',
                              (tenant,p['domain'],p['snapshot'])).fetchone()[0]
        rows=self.open_snapshot(tenant,p['domain'],p['snapshot'],value)
        buckets=json.loads(self.catalog(tenant,p['domain'],p['catalog'])['buckets_json'])
        return HistogramJob(rows,op['seed'],capacity=p['capacity'],buckets=buckets).run()

    execute_histogram=ScheduledLedger.claim

    def audit(self):
        errors=super().audit()
        for job in self.db.execute('SELECT * FROM jobs'):
            op=self.op(job['tenant'],job['operation_id']);p=json.loads(op['action'])['parameters']
            if p['mechanism']!=HISTOGRAM:continue
            try:
                if op['seed'] is not None:validate_tape(op['seed'],p['bucket_count'],40)
                state=self.load_private_state(job);b=p['bucket_count'];n=p['capacity']
                if set(state)!={'counts','alive','g','outputs'}:raise ValueError()
                for k,maximum in (('counts',n),('outputs',n)):
                    if type(state[k]) is not list or len(state[k])!=b or any(type(x) is not int or not 0<=x<=maximum for x in state[k]):raise ValueError()
                for k,maximum in (('alive',1),('g',40)):
                    if (type(state[k]) is not list or len(state[k])!=b or any(type(pair) is not list or len(pair)!=2 or any(type(x) is not int or not 0<=x<=maximum for x in pair) for pair in state[k])):raise ValueError()
                if op['result'] is not None:
                    decode_result(op['result'],b,n)
                    if op['result']!=self.compute_internal(op['tenant'],op['id']):errors.append('HISTOGRAM_REPLAY_MISMATCH')
            except (ValueError,TypeError,KeyError,Rejected):errors.append('HISTOGRAM_STATE_CONFLICT')
        return errors
