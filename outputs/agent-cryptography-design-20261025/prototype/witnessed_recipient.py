"""Conditional local rollback protection for the mixed terminal recipient.

Explicit privileged bootstrap/restore, separate receiver authority namespace,
whole encrypted inbox/closure/clock images before local commit and ACK signing.
No automatic rebootstrap, migration, pruning, external-effect execution or
claim that the reference authority itself cannot roll back.
"""
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from mixed_delivery_terminal import MixedTerminalRecipientInbox
from delivery_transport import validate_route,StateVault,Rejected
from witness_transport import TLSWitnessClient,hex_string
from witnessed_ledger import (WitnessedLedger,ANCHOR_SCHEMA,image_hash,quote_identifier,unpack_cell)
from wire import encode

AUTHORITY_SCHEMA='''CREATE TABLE recipient_authority (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), namespace TEXT NOT NULL
)'''


class WitnessedMixedRecipientInbox(MixedTerminalRecipientInbox):
    inbox_profile='witnessed-mixed-terminal-inbox-v1'

    def __init__(self,path,*,deployment,route,vault,clock,witness,witness_namespace,
                 witness_fault=lambda point:None,_initialize=False):
        validate_route(route)
        if type(vault) is not StateVault:raise Rejected('INVALID_STORAGE_VAULT')
        if not hex_string(witness_namespace,32) or witness_namespace==deployment:
            raise Rejected('INVALID_RECIPIENT_AUTHORITY')
        self.path=str(path);self.witness=witness;self.namespace=witness_namespace
        self.witness_fault=witness_fault;self._base_anchor=None
        witness_path=getattr(witness,'path',None)
        if witness_path is not None and Path(path).resolve()==Path(witness_path).resolve():
            raise Rejected('WITNESS_NOT_INDEPENDENT')
        exists=Path(path).exists() and Path(path).stat().st_size>0
        if not _initialize and not exists:raise Rejected('INBOX_RECOVERY_REQUIRED')
        if _initialize and exists:raise Rejected('FRESH_REPLICA_REQUIRED')
        self._route_hash=hashlib.sha256(encode(dict(profile=self.inbox_profile,deployment=deployment,route=route))).digest()
        template=sqlite3.connect(':memory:')
        try:
            template.executescript(self.inbox_schema+';'+ANCHOR_SCHEMA+';'+AUTHORITY_SCHEMA)
            self._trusted_schema=WitnessedLedger.schema(SimpleNamespace(db=template))
        finally:template.close()
        super().__init__(path,deployment=deployment,route=route,vault=vault,clock=clock)
        try:
            if _initialize:
                self.db.execute(ANCHOR_SCHEMA);self.db.execute(AUTHORITY_SCHEMA)
                self.db.execute('INSERT INTO recipient_authority VALUES(1,?)',(self.namespace,))
            self.check_storage_profile()
        except BaseException:self.close();raise

    # These six methods only depend on db/schema/state_image/witness/namespace;
    # reuse the already-tested image and CAS implementation, not ledger business.
    schema=WitnessedLedger.schema
    state_image=WitnessedLedger.state_image
    local_anchor=WitnessedLedger.local_anchor
    check_current_state=WitnessedLedger.check_current_state
    begin_transaction_guard=WitnessedLedger.begin_transaction_guard
    commit_transaction_guard=WitnessedLedger.commit_transaction_guard

    @classmethod
    def new_replica(cls,path,**kwargs):return cls(path,_initialize=True,**kwargs)

    @classmethod
    def create(cls,path,**kwargs):
        obj=cls.new_replica(path,**kwargs)
        try:
            obj.audit_local()
            receipt=obj.witness.bootstrap(obj.namespace,obj.state_image())
            if receipt!={'seq':0,'digest':image_hash(obj.state_image())}:raise Rejected('INVALID_WITNESS_RECEIPT')
            obj.db.execute('INSERT INTO witness_anchor VALUES(1,?,?)',(receipt['seq'],receipt['digest']))
            return obj
        except BaseException:obj.close();raise

    @classmethod
    def restore_new(cls,path,**kwargs):
        obj=cls.new_replica(path,**kwargs)
        try:obj.recover_from_witness();return obj
        except BaseException:obj.close();raise

    def check_storage_profile(self):
        if self.schema()!=self._trusted_schema:raise Rejected('WITNESS_SCHEMA_MISMATCH')
        metadata=self.db.execute('SELECT key_check,route_hash FROM inbox_metadata WHERE singleton=1').fetchone()
        authority=self.db.execute('SELECT namespace FROM recipient_authority WHERE singleton=1').fetchone()
        if (metadata is None or tuple(metadata)!=(self.vault.key_check,self._route_hash) or
            authority is None or authority[0]!=self.namespace):raise Rejected('INBOX_PROFILE_MISMATCH')

    def audit_local(self):
        self.check_storage_profile()
        clock=self.db.execute('SELECT observed FROM inbox_clock WHERE singleton=1').fetchone()
        if clock is None or type(clock[0]) is not int or not 0<=clock[0]<=2**62:raise Rejected('INBOX_AUDIT_FAILED')
        ids=set();sequences=[]
        for row in self.db.execute('SELECT * FROM inbox'):
            raw=self.vault.open('inbox-envelope',(self.deployment,self.route['tenant'],row['id']),row['envelope'])
            obj=self.parse_envelope(raw,self.deployment,self.route)
            if (row['id']!=obj['delivery'] or row['seq']!=obj['seq'] or type(row['accepted_at']) is not int or
                not obj['issued_at']<=row['accepted_at']<obj['expires_at'] or row['accepted_at']>clock[0]):
                raise Rejected('INBOX_AUDIT_FAILED')
            ids.add(row['id']);sequences.append(row['seq'])
        for row in self.db.execute('SELECT * FROM inbox_closed'):
            raw=self.vault.open('inbox-closed',(self.deployment,self.route['tenant'],row['id']),row['control'])
            obj=self.parse_control(raw,self.deployment,self.route)
            if (row['id'] in ids or row['id']!=obj['delivery'] or row['seq']!=obj['seq'] or
                type(row['closed_at']) is not int or not obj['expires_at']<=row['closed_at']<=clock[0]):
                raise Rejected('INBOX_AUDIT_FAILED')
            ids.add(row['id']);sequences.append(row['seq'])
        if sorted(sequences)!=list(range(1,len(sequences)+1)):raise Rejected('INBOX_AUDIT_FAILED')
        return []

    def audit(self):
        # Consistent local snapshot; remote head can advance later, so audit is
        # evidence at this point, not authorization for a future transaction.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.check_current_state();result=self.audit_local();self.db.commit();return result
        except BaseException:self.db.rollback();raise

    def recover_from_witness(self,fault=lambda point:None):
        # Return the restored snapshot's identity, not a lease on currentness.
        # A rival can advance after the recheck; business begin/CAS guards remain
        # mandatory even after this method returns successfully.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            head=self.witness.head(self.namespace,include_image=True)
            if image_hash(head['image'])!=head['digest']:raise Rejected('WITNESS_IMAGE_CORRUPT')
            try:state=json.loads(head['image'])
            except (ValueError,UnicodeError):raise Rejected('INVALID_WITNESS_IMAGE') from None
            objects,tables=self._trusted_schema
            if (type(state) is not dict or set(state)!={'format','schema','columns','rows'} or
                state['format']!='agent-ledger-image-v1' or state['schema']!=objects or state['columns']!=tables or
                type(state['rows']) is not dict or set(state['rows'])!=set(tables) or self.schema()!=self._trusted_schema):
                raise Rejected('WITNESS_SCHEMA_MISMATCH')
            for name in tables:self.db.execute('DELETE FROM '+quote_identifier(name))
            fault('after_recovery_delete')
            for name,columns in tables.items():
                rows=state['rows'][name]
                if type(rows) is not list:raise Rejected('INVALID_WITNESS_IMAGE')
                for row in rows:
                    if type(row) is not list or len(row)!=len(columns):raise Rejected('INVALID_WITNESS_IMAGE')
                    self.db.execute('INSERT INTO '+quote_identifier(name)+' VALUES('+','.join('?' for _ in columns)+')',[unpack_cell(x) for x in row])
            if self.state_image()!=head['image'] or self.db.execute('PRAGMA foreign_key_check').fetchall():raise Rejected('INVALID_WITNESS_IMAGE')
            self.audit_local()
            if self.witness.head(self.namespace)!={'seq':head['seq'],'digest':head['digest']}:
                raise Rejected('WITNESS_CHANGED_DURING_RECOVERY')
            self.db.execute('INSERT OR REPLACE INTO witness_anchor VALUES(1,?,?)',(head['seq'],head['digest']))
            fault('before_recovery_commit');self.db.commit()
        except BaseException:self.db.rollback();raise
        fault('after_recovery_commit')
        return {'seq':head['seq'],'digest':head['digest']}


class TLSWitnessedMixedRecipientInbox(WitnessedMixedRecipientInbox):
    inbox_profile='mtls-witnessed-mixed-terminal-inbox-v1'

    def __init__(self,path,*,witness,**kwargs):
        if type(witness) is not TLSWitnessClient:raise Rejected('AUTHENTICATED_WITNESS_REQUIRED')
        super().__init__(path,witness=witness,**kwargs)
