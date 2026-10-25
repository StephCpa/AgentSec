"""AEAD field storage for signed mixed count/histogram execution.

Reuses StateVault (AES-256-GCM-SIV/HKDF/HMAC); no new cryptographic primitive.
Public metadata, access timing and whole-database rollback remain outside field
protection. Keys/deployment come from trusted bootstrap; no KMS or rotation.
"""
import hashlib
import hmac
import json
import struct
from encrypted_ledger import EncryptedLedger,FIELDS
from mixed_delegated_ledger import MixedDelegatedLedger,COUNT_CODEC
from histogram_ledger import COUNT,HISTOGRAM,CODEC,canonical
from dp_ledger import PROFILE
from ledger import Rejected


class EncryptedMixedLedger(EncryptedLedger,MixedDelegatedLedger):
    storage_profile='signed-mixed-aes256-gcm-siv-v1'

    def shape(self,tenant,domain_id,catalog_id=None):
        domain=self.domain(tenant,domain_id);n=domain['capacity']
        if catalog_id is None:return (COUNT,n,1,40,COUNT_CODEC,'',b'')
        catalog=self.catalog(tenant,domain_id,catalog_id)
        try:
            labels=json.loads(catalog['buckets_json'])
            if (type(labels) is not list or not 1<=len(labels)<=64 or
                any(type(x) is not str or not 1<=len(x.encode())<=64 for x in labels) or
                len(set(labels))!=len(labels) or canonical(labels)!=catalog['buckets_json'] or
                hashlib.sha256(catalog['buckets_json'].encode()).hexdigest()!=catalog['digest']):
                raise ValueError()
            return (HISTOGRAM,n,len(labels),40,CODEC,catalog_id,bytes.fromhex(catalog['digest']))
        except (ValueError,TypeError,UnicodeError):raise Rejected('STORAGE_INTEGRITY')

    def operation_metadata(self,tenant,oid,digest):
        row=self.db.execute('SELECT action,digest FROM operations WHERE tenant=? AND id=?',(tenant,oid)).fetchone()
        if row is None:raise Rejected('STORAGE_INTEGRITY')
        try:
            if type(row['action']) is not str or type(digest) is not str:raise ValueError()
            action=json.loads(row['action']);p=action['parameters']
            if row['digest']!=digest or hashlib.sha256(row['action'].encode()).hexdigest()!=digest:
                raise ValueError()
            if action['tenant']!=tenant or action['id']!=oid or p['accountant']!=PROFILE:raise ValueError()
            if p['mechanism']==COUNT:
                if set(p)!={'domain','snapshot','mechanism','accountant'}:raise ValueError()
                shape=self.shape(tenant,p['domain'])
            elif p['mechanism']==HISTOGRAM:
                if set(p)!={'domain','snapshot','mechanism','accountant','catalog','catalog_digest','bucket_count','capacity','k','codec'}:raise ValueError()
                shape=self.shape(tenant,p['domain'],p['catalog'])
                if (p['catalog_digest']!=shape[6].hex() or p['codec']!=shape[4] or
                    any(type(p[k]) is not int or p[k]!=v for k,v in (('capacity',shape[1]),('bucket_count',shape[2]),('k',40)))):raise ValueError()
            else:raise ValueError()
            return action,shape
        except (ValueError,TypeError,KeyError,UnicodeError):raise Rejected('STORAGE_INTEGRITY')

    def operation_identity(self,tenant,oid,digest):
        action,shape=self.operation_metadata(tenant,oid,digest)
        return (tenant,oid,digest,action['parameters']['domain'],PROFILE,*shape)

    def field_size(self,kind,shape):
        if kind=='seed':return 10*shape[2] if shape[0]==HISTOGRAM else 32
        if kind=='result':return 8*shape[2]
        raise Rejected('INVALID_SECRET_RECORD')

    def validate_field(self,kind,value,shape):
        if type(value) is not bytes or len(value)!=self.field_size(kind,shape):raise Rejected('STORAGE_INTEGRITY')
        if kind=='result' and any(int.from_bytes(value[i:i+8],'big')>shape[1] for i in range(0,len(value),8)):
            raise Rejected('STORAGE_INTEGRITY')

    def protect_operation_field(self,kind,tenant,oid,digest,value):
        _,shape=self.operation_metadata(tenant,oid,digest);self.validate_field(kind,value,shape)
        return self.vault.seal('mixed-'+kind,self.operation_identity(tenant,oid,digest),value)

    def open_operation_row(self,row):
        op=dict(row);identity=self.operation_identity(op['tenant'],op['id'],op['digest'])
        _,shape=self.operation_metadata(op['tenant'],op['id'],op['digest'])
        for kind in ('seed','result'):
            if op[kind] is not None:
                op[kind]=self.vault.open('mixed-'+kind,identity,op[kind]);self.validate_field(kind,op[kind],shape)
        if op['result'] is not None and (type(op['result_digest']) is not str or not hmac.compare_digest(self.vault.bind_result(identity,op['result']),op['result_digest'])):
            raise Rejected('STORAGE_INTEGRITY')
        return op

    def result_binding(self,tenant,oid,digest,result):
        _,shape=self.operation_metadata(tenant,oid,digest);self.validate_field('result',result,shape)
        return self.vault.bind_result(self.operation_identity(tenant,oid,digest),result)

    def snapshot_identity(self,tenant,domain_id,snapshot_id,catalog_id=None):
        return (tenant,domain_id,snapshot_id,PROFILE,*self.shape(tenant,domain_id,catalog_id))

    def protect_snapshot(self,tenant,domain_id,snapshot_id,rows):
        return self.vault.seal('mixed-snapshot',self.snapshot_identity(tenant,domain_id,snapshot_id),bytes(rows))

    def protect_histogram_snapshot(self,tenant,domain_id,snapshot_id,catalog_id,rows):
        return self.vault.seal('mixed-snapshot',self.snapshot_identity(tenant,domain_id,snapshot_id,catalog_id),bytes(rows))

    def open_snapshot(self,tenant,domain_id,snapshot_id,value):
        row=self.db.execute('SELECT catalog_id FROM histogram_snapshots WHERE tenant=? AND domain_id=? AND snapshot_id=?',
                            (tenant,domain_id,snapshot_id)).fetchone()
        catalog_id=None if row is None else row[0];shape=self.shape(tenant,domain_id,catalog_id)
        rows=self.vault.open('mixed-snapshot',self.snapshot_identity(tenant,domain_id,snapshot_id,catalog_id),value)
        if len(rows)!=shape[1] or any(x>shape[2] for x in rows):raise Rejected('STORAGE_INTEGRITY')
        return list(rows)

    def private_metadata(self,job,pc):
        row=self.db.execute('SELECT digest FROM operations WHERE tenant=? AND id=?',(job['tenant'],job['operation_id'])).fetchone()
        if row is None:raise Rejected('STORAGE_INTEGRITY')
        action,shape=self.operation_metadata(job['tenant'],job['operation_id'],row[0])
        if (job['domain_id']!=action['parameters']['domain'] or job['work']!=self.scheduled_work(action) or
            type(pc) is not int or not 0<=pc<=job['work'] or type(job['seq']) is not int or job['seq']<1):
            raise Rejected('STORAGE_INTEGRITY')
        identity=(*self.operation_identity(job['tenant'],job['operation_id'],row[0]),job['seq'],job['work'],pc)
        return identity,shape

    def encode_state(self,state,shape):
        try:
            n,b=shape[1:3]
            if shape[0]==COUNT:
                if type(state) is not dict or set(state)!=set(FIELDS):raise ValueError()
                values=[state[k] for k in FIELDS]
                limits=(n,1,1,40,40)
                if any(type(v) is not int or not 0<=v<=lim for v,lim in zip(values,limits)):raise ValueError()
                return struct.pack('>I4B',*values)
            if type(state) is not dict or set(state)!={'counts','alive','g','outputs'}:raise ValueError()
            if any(type(state[k]) is not list or len(state[k])!=b for k in state):raise ValueError()
            data=[]
            for i in range(b):
                if any(type(state[k][i]) is not list or len(state[k][i])!=2 for k in ('alive','g')):raise ValueError()
                values=[state['counts'][i],*state['alive'][i],*state['g'][i],state['outputs'][i]]
                if any(type(v) is not int or not 0<=v<=lim for v,lim in zip(values,(n,1,1,40,40,n))):raise ValueError()
                data.append(struct.pack('>I4BI',*values))
            return b''.join(data)
        except (TypeError,ValueError,KeyError,IndexError,struct.error):raise Rejected('STORAGE_INTEGRITY')

    def decode_state(self,data,shape):
        if shape[0]==COUNT:
            if len(data)!=8:raise Rejected('STORAGE_INTEGRITY')
            state=dict(zip(FIELDS,struct.unpack('>I4B',data)))
        else:
            b=shape[2]
            if len(data)!=12*b:raise Rejected('STORAGE_INTEGRITY')
            rows=[struct.unpack('>I4BI',data[i:i+12]) for i in range(0,len(data),12)]
            state=dict(counts=[r[0] for r in rows],alive=[list(r[1:3]) for r in rows],g=[list(r[3:5]) for r in rows],outputs=[r[5] for r in rows])
        if self.encode_state(state,shape)!=data:raise Rejected('STORAGE_INTEGRITY')
        return state

    def save_private_state(self,job,state,pc):
        identity,shape=self.private_metadata(job,pc);data=self.encode_state(state,shape)
        sealed=self.vault.seal('mixed-job-state',identity,data)
        self.db.execute('UPDATE jobs SET private_state=? WHERE tenant=? AND operation_id=?',(sealed,job['tenant'],job['operation_id']))

    def load_private_state(self,job):
        if tuple(job[k] for k in FIELDS)!=(0,1,1,0,0):raise Rejected('STORAGE_INTEGRITY')
        identity,shape=self.private_metadata(job,job['pc'])
        data=self.vault.open('mixed-job-state',identity,job['private_state'])
        return self.decode_state(data,shape)
