"""Recovery protocol against LOCAL ledger rollback, using a trusted witness.

ReferenceWitness is an independent SQLite simulation, not a remote authenticated
or intrinsically nonrollback service. Safety assumes its linearizable state is
not rolled back/lost/forged. Complete encrypted-field images precede local commit.
This deliberately expensive reference path is not a production replication log.
"""
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3

from encrypted_ledger import EncryptedLedger, Rejected


MAX_IMAGE=16*1024*1024
ANCHOR_SCHEMA='''CREATE TABLE IF NOT EXISTS witness_anchor (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 seq INTEGER NOT NULL, digest TEXT NOT NULL
)'''
WITNESS_SCHEMA='''
CREATE TABLE IF NOT EXISTS heads (
 namespace TEXT PRIMARY KEY, seq INTEGER NOT NULL, digest TEXT NOT NULL,
 image BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS commits (
 namespace TEXT NOT NULL, seq INTEGER NOT NULL, base_digest TEXT NOT NULL,
 digest TEXT NOT NULL, token TEXT NOT NULL,
 PRIMARY KEY(namespace,seq), UNIQUE(namespace,token)
);
'''


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def image_hash(image):
    if type(image) is not bytes or not 0<len(image)<=MAX_IMAGE:
        raise Rejected('INVALID_WITNESS_IMAGE')
    return hashlib.sha256(b'agent-ledger-image-v1\x00'+image).hexdigest()


def pack_cell(value):
    if value is None:return ['null']
    if type(value) is int:return ['int',value]
    if type(value) is str:return ['text',value]
    if type(value) is bytes:return ['bytes',value.hex()]
    raise Rejected('UNSUPPORTED_STORAGE_VALUE')


def unpack_cell(value):
    if value==['null']:return None
    if type(value) is not list or len(value)!=2:raise Rejected('INVALID_WITNESS_IMAGE')
    kind,payload=value
    if kind=='int' and type(payload) is int and -(2**63)<=payload<2**63:return payload
    if kind=='text' and type(payload) is str:return payload
    if kind=='bytes' and type(payload) is str:
        try:result=bytes.fromhex(payload)
        except ValueError:raise Rejected('INVALID_WITNESS_IMAGE') from None
        if result.hex()==payload:return result
    raise Rejected('INVALID_WITNESS_IMAGE')


def quote_identifier(name):
    # Names originate from the trusted local schema; still quote defensively.
    return '"'+name.replace('"','""')+'"'


class ReferenceWitness:
    """Opaque state CAS. Its identity/transport/nonrollback guarantees are assumed."""
    def __init__(self,path):
        self.path=str(path)
        self.db=sqlite3.connect(self.path,timeout=20,isolation_level=None)
        self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript(WITNESS_SCHEMA)

    def close(self):self.db.close()

    def authorize_operation(self,namespace,operation):
        # Network adapters override this hook; check while holding the same
        # witness transaction as the read/CAS, including idempotent retries.
        pass

    def head(self,namespace,include_image=False):
        own_transaction=not self.db.in_transaction
        if own_transaction:self.db.execute('BEGIN')
        try:
            self.authorize_operation(namespace,'image' if include_image else 'head')
            columns='seq,digest,image' if include_image else 'seq,digest'
            row=self.db.execute('SELECT '+columns+' FROM heads WHERE namespace=?',(namespace,)).fetchone()
            if row is None:raise Rejected('WITNESS_UNINITIALIZED')
            if own_transaction:self.db.commit()
            return dict(row)
        except BaseException:
            if own_transaction:self.db.rollback()
            raise

    def bootstrap(self,namespace,image):
        # Trusted administrative bootstrap, never an automatic recovery fallback.
        digest=image_hash(image)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.authorize_operation(namespace,'bootstrap')
            if self.db.execute('SELECT 1 FROM heads WHERE namespace=?',(namespace,)).fetchone():
                raise Rejected('WITNESS_ALREADY_INITIALIZED')
            self.db.execute('INSERT INTO heads VALUES(?,?,?,?)',(namespace,0,digest,image))
            self.db.commit()
        except BaseException:
            self.db.rollback();raise
        return {'seq':0,'digest':digest}

    def compare_and_store(self,namespace,expected_seq,expected_digest,image,request_id):
        if type(expected_seq) is not int or not 0<=expected_seq<2**62:
            raise Rejected('INVALID_WITNESS_VERSION')
        digest=image_hash(image)
        if type(request_id) is not str or len(request_id)!=32 or any(c not in '0123456789abcdef' for c in request_id):
            raise Rejected('INVALID_WITNESS_REQUEST_ID')
        token=request_id
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.authorize_operation(namespace,'cas')
            old=self.db.execute('SELECT seq,base_digest,digest FROM commits WHERE namespace=? AND token=?',(namespace,token)).fetchone()
            if old:
                if (old['seq']!=expected_seq+1 or old['base_digest']!=expected_digest or old['digest']!=digest):
                    raise Rejected('WITNESS_REQUEST_CONFLICT')
                self.db.commit();return {'seq':old['seq'],'digest':old['digest']}
            current=self.head(namespace)
            if current!={'seq':expected_seq,'digest':expected_digest}:
                raise Rejected('WITNESS_CAS_CONFLICT')
            seq=expected_seq+1
            self.db.execute('UPDATE heads SET seq=?,digest=?,image=? WHERE namespace=?',(seq,digest,image,namespace))
            self.db.execute('INSERT INTO commits VALUES(?,?,?,?,?)',(namespace,seq,expected_digest,digest,token))
            self.db.commit()
            return {'seq':seq,'digest':digest}
        except BaseException:
            self.db.rollback();raise


    def reassert(self,namespace,expected_seq,expected_digest,request_id):
        """CAS to the SAME opaque image, retaining version/token/write authority.

        An optional transport optimization, never a read-only success shortcut.
        The trusted witness retains the current image; no client image is sent.
        Tokens identify logical CAS content, so an equivalent full-image CAS
        retransmission and reassert may share one token, but distinct attempts
        still require fresh tokens and advance the version.
        """
        if type(expected_seq) is not int or not 0<=expected_seq<2**62:
            raise Rejected('INVALID_WITNESS_VERSION')
        if (type(expected_digest) is not str or len(expected_digest)!=64 or
                any(c not in '0123456789abcdef' for c in expected_digest)):
            raise Rejected('INVALID_WITNESS_IMAGE')
        if type(request_id) is not str or len(request_id)!=32 or any(c not in '0123456789abcdef' for c in request_id):
            raise Rejected('INVALID_WITNESS_REQUEST_ID')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.authorize_operation(namespace,'cas')
            old=self.db.execute('SELECT seq,base_digest,digest FROM commits WHERE namespace=? AND token=?',(namespace,request_id)).fetchone()
            if old:
                if tuple(old)!=(expected_seq+1,expected_digest,expected_digest):
                    raise Rejected('WITNESS_REQUEST_CONFLICT')
                self.db.commit();return {'seq':old['seq'],'digest':old['digest']}
            if self.head(namespace)!={'seq':expected_seq,'digest':expected_digest}:
                raise Rejected('WITNESS_CAS_CONFLICT')
            # Reuse requires a valid retained image, not merely a matching head.
            # Read/hash under the same write lock; never bless corrupted storage.
            retained=self.db.execute('SELECT image FROM heads WHERE namespace=?',(namespace,)).fetchone()[0]
            if image_hash(retained)!=expected_digest:raise Rejected('INVALID_WITNESS_IMAGE')
            seq=expected_seq+1
            self.db.execute('UPDATE heads SET seq=? WHERE namespace=?',(seq,namespace))
            self.db.execute('INSERT INTO commits VALUES(?,?,?,?,?)',(namespace,seq,expected_digest,expected_digest,request_id))
            self.db.commit();return {'seq':seq,'digest':expected_digest}
        except BaseException:
            self.db.rollback();raise


class WitnessedLedger(EncryptedLedger):
    storage_profile='witnessed-delegated-count-v1'

    def __init__(self,path,clock=None,*,vault,witness,witness_fault=lambda point:None):
        # Passing another witness or deployment is privileged bootstrap, not input.
        self.witness=witness
        self.namespace=vault.deployment_id.hex()
        self.witness_fault=witness_fault
        self._base_anchor=None
        super().__init__(path,clock=clock,vault=vault)
        witness_path=getattr(witness,'path',None)
        if witness_path is not None and Path(self.path).resolve()==Path(witness_path).resolve():
            self.close();raise Rejected('WITNESS_NOT_INDEPENDENT')

    @classmethod
    def new_replica(cls,path,**kwargs):
        if Path(path).exists() and Path(path).stat().st_size:
            raise Rejected('FRESH_REPLICA_REQUIRED')
        obj=super().create(path,**kwargs)
        obj.db.execute(ANCHOR_SCHEMA)
        return obj

    @classmethod
    def create(cls,path,**kwargs):
        obj=cls.new_replica(path,**kwargs)
        try:
            anchor=obj.witness.bootstrap(obj.namespace,obj.state_image())
            obj.db.execute('INSERT INTO witness_anchor VALUES(1,?,?)',(anchor['seq'],anchor['digest']))
            return obj
        except BaseException:
            obj.close();raise

    @classmethod
    def restore_new(cls,path,**kwargs):
        obj=cls.new_replica(path,**kwargs)
        try:
            obj.recover_from_witness();return obj
        except BaseException:
            obj.close();raise

    def schema(self):
        objects=[list(r) for r in self.db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' AND name<>'witness_anchor' AND sql IS NOT NULL ORDER BY type,name")]
        tables={r[1]:[x[1] for x in self.db.execute('PRAGMA table_info('+quote_identifier(r[1])+')')]
                for r in objects if r[0]=='table'}
        return objects,tables

    def state_image(self):
        objects,tables=self.schema();rows={}
        for name,columns in tables.items():
            # Reuse each canonical row's sort key as its final JSON bytes. This
            # is local to this image build: every call still reads every table.
            values=[canonical([pack_cell(v) for v in row])
                    for row in self.db.execute('SELECT * FROM '+quote_identifier(name))]
            rows[name]=b'['+b','.join(sorted(values))+b']'
        # Match canonical(..., sort_keys=True) at both object levels. Nested
        # strings/cells/schema are still encoded by the original JSON encoder.
        image=(b'{"columns":'+canonical(tables)+b',"format":"agent-ledger-image-v1","rows":{'+
               b','.join(canonical(name)+b':'+rows[name] for name in sorted(rows))+
               b'},"schema":'+canonical(objects)+b'}')
        image_hash(image)
        return image

    def local_anchor(self):
        row=self.db.execute('SELECT seq,digest FROM witness_anchor WHERE singleton=1').fetchone()
        if row is None:raise Rejected('WITNESS_RECOVERY_REQUIRED')
        return dict(row)

    def check_current_state(self):
        local=self.local_anchor();head=self.witness.head(self.namespace)
        if local!=head:raise Rejected('WITNESS_RECOVERY_REQUIRED')
        if image_hash(self.state_image())!=local['digest']:
            raise Rejected('LOCAL_STATE_DIVERGED')
        return local

    def begin_transaction_guard(self):
        self._base_anchor=self.check_current_state()
        # Distinct attempts must not be collapsed just because their state images
        # happen to match. Only retransmission of THIS CAS may reuse the ID.
        self._witness_request_id=secrets.token_hex(16)

    def commit_transaction_guard(self):
        if self._base_anchor is None:raise RuntimeError('missing witness base')
        image=self.state_image()
        self.witness_fault('before_witness_accept')
        receipt=self.witness.compare_and_store(self.namespace,self._base_anchor['seq'],self._base_anchor['digest'],image,self._witness_request_id)
        # A lost receipt or process exit here leaves the witness ahead. Never
        # undo the witness or assume that a local rollback refunded the action.
        self.witness_fault('after_witness_accept')
        if receipt!={'seq':self._base_anchor['seq']+1,'digest':image_hash(image)}:
            raise Rejected('INVALID_WITNESS_RECEIPT')
        self.db.execute('UPDATE witness_anchor SET seq=?,digest=? WHERE singleton=1',(receipt['seq'],receipt['digest']))
        self.witness_fault('after_local_anchor_write')

    def recover_from_witness(self,fault=lambda point:None):
        # Trusted coordinator only. Does not create a new witness history, execute
        # business code, rerun sampling, issue tickets, or refund any operation.
        # The returned head identifies the restored snapshot, not a freshness
        # lease: another writer may advance after the final head read. Subsequent
        # business uses both the begin guard and expected-version commit CAS.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            head=self.witness.head(self.namespace,include_image=True)
            if image_hash(head['image'])!=head['digest']:
                raise Rejected('WITNESS_IMAGE_CORRUPT')
            try:state=json.loads(head['image'])
            except (ValueError,UnicodeError):raise Rejected('INVALID_WITNESS_IMAGE') from None
            objects,tables=self.schema()
            if (type(state) is not dict or set(state)!={'format','schema','columns','rows'} or
                    state['format']!='agent-ledger-image-v1' or state['schema']!=objects or
                    state['columns']!=tables or type(state['rows']) is not dict or set(state['rows'])!=set(tables)):
                raise Rejected('WITNESS_SCHEMA_MISMATCH')
            self.db.execute('PRAGMA defer_foreign_keys=ON')
            for name in tables:self.db.execute('DELETE FROM '+quote_identifier(name))
            fault('after_recovery_delete')
            for name,columns in tables.items():
                rows=state['rows'][name]
                if type(rows) is not list:raise Rejected('INVALID_WITNESS_IMAGE')
                for row in rows:
                    if type(row) is not list or len(row)!=len(columns):raise Rejected('INVALID_WITNESS_IMAGE')
                    values=[unpack_cell(x) for x in row]
                    self.db.execute('INSERT INTO '+quote_identifier(name)+' VALUES('+','.join('?' for _ in columns)+')',values)
            if self.state_image()!=head['image'] or self.db.execute('PRAGMA foreign_key_check').fetchall():
                raise Rejected('INVALID_WITNESS_IMAGE')
            self.check_storage_profile()
            errors=super().audit()
            if errors:raise Rejected('RECOVERY_AUDIT_FAILED')
            if self.witness.head(self.namespace)!={'seq':head['seq'],'digest':head['digest']}:
                raise Rejected('WITNESS_CHANGED_DURING_RECOVERY')
            self.db.execute('INSERT OR REPLACE INTO witness_anchor VALUES(1,?,?)',(head['seq'],head['digest']))
            fault('before_recovery_commit')
            self.db.commit()
        except BaseException:
            self.db.rollback();raise
        fault('after_recovery_commit')
        return {'seq':head['seq'],'digest':head['digest']}

    def audit(self):
        self.check_current_state()
        return super().audit()
