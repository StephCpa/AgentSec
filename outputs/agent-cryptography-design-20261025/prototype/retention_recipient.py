"""Witnessed v2 first-event store and logical prefix retirement.

One immutable route per database. Explicit bootstrap/restore, authority-first
commits and no automatic reset. Retired SQL rows leave the current state image;
this is not secure erasure of files/backups nor a bound on all system storage.
"""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from encrypted_ledger import StateVault
from delivery_transport import public
from ledger import Rejected
from wire import encode,decode,inspect_sign1
from witnessed_ledger import WitnessedLedger,ANCHOR_SCHEMA
import witnessed_ledger as witness_storage
from witnessed_recipient import WitnessedMixedRecipientInbox
from witness_transport import TLSWitnessClient
from retention_sender import u64,number
import retention_wire as r
import retention_delivery as delivery

SCHEMA='''
CREATE TABLE v2_recipient_meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), profile TEXT NOT NULL,
 context BLOB NOT NULL, key_check TEXT NOT NULL, namespace TEXT NOT NULL,
 high BLOB NOT NULL CHECK(typeof(high)='blob' AND length(high)=8),
 floor BLOB NOT NULL CHECK(typeof(floor)='blob' AND length(floor)=8), root BLOB NOT NULL,
 observed INTEGER NOT NULL CHECK(observed BETWEEN 0 AND 4611686018427387904), last_offer BLOB,
 CHECK((floor=zeroblob(8))=(last_offer IS NULL))
);
CREATE TABLE v2_recipient_live (
 seq BLOB PRIMARY KEY CHECK(typeof(seq)='blob' AND length(seq)=8), id TEXT UNIQUE NOT NULL,
 fact BLOB NOT NULL, evidence BLOB NOT NULL
);
'''


def capacity_certificate(context,profile,key_check,trusted_schema,*,image_limit=None):
    """Conservative byte bound for ONE current canonical recipient image.

    Every stored fact, evidence and latest offer is parsed through the 8192-byte
    frame gate; StateVault adds exactly 36 bytes. pack_cell hex doubles bytes.
    Fill all bounded cells to these limits, and use the exact trusted schema,
    context and fixed configuration. No signatures/encryption are needed to
    calculate lengths. These synthetic cells are NOT valid event evidence.

    M includes empty live brackets. L includes one complete maximal row plus
    its separating comma: actual bytes <= M + W*L (one byte slack for W>0).
    This sufficient admission bound is deliberately not a maximum legal W.
    SQLite/WAL, backups, transient memory and witness/sender history excluded.
    """
    r.validate_context(context)
    cap=witness_storage.MAX_IMAGE if image_limit is None else image_limit
    if type(cap) is not int or not 0<cap<=witness_storage.MAX_IMAGE:
        raise Rejected('V2_CAPACITY_LIMIT')
    objects,tables=trusted_schema
    ciphertext_limit=r.MAX_FRAME+36
    meta=[1,profile,encode(context),key_check,context['receiver_authority'].hex(),
          b'\xff'*8,b'\xff'*8,b'\xff'*32,r.MAX_TIME,b'\xff'*ciphertext_limit]
    live=[b'\xff'*8,'f'*64,b'\xff'*ciphertext_limit,b'\xff'*ciphertext_limit]
    packed_meta=[witness_storage.pack_cell(x) for x in meta]
    packed_live=[witness_storage.pack_cell(x) for x in live]
    base=witness_storage.canonical(dict(format='agent-ledger-image-v1',schema=objects,columns=tables,
        rows={'v2_recipient_meta':[packed_meta],'v2_recipient_live':[]}))
    row_bytes=len(witness_storage.canonical(packed_live))+1
    metadata_bytes=len(base)
    return dict(basis='v2-frame-bound-canonical-image-v1',frame_bytes=r.MAX_FRAME,
        encrypted_field_bytes=ciphertext_limit,metadata_bytes=metadata_bytes,live_row_bytes=row_bytes,
        window=context['window'],image_limit=cap,
        bound_bytes=metadata_bytes+context['window']*row_bytes,
        safe_window_upper_limit=min(65535,max(0,(cap-metadata_bytes)//row_bytes)))


class RetentionRecipient:
    inbox_profile='witnessed-mixed-retention-recipient-v2'
    schema=WitnessedLedger.schema
    state_image=WitnessedLedger.state_image
    local_anchor=WitnessedLedger.local_anchor
    check_current_state=WitnessedLedger.check_current_state
    begin_transaction_guard=WitnessedLedger.begin_transaction_guard
    recover_from_witness=WitnessedMixedRecipientInbox.recover_from_witness
    create=classmethod(WitnessedMixedRecipientInbox.create.__func__)
    restore_new=classmethod(WitnessedMixedRecipientInbox.restore_new.__func__)
    audit=WitnessedMixedRecipientInbox.audit

    def __init__(self,path,*,context,vault,clock,witness,witness_fault=lambda point:None,_initialize=False):
        r.validate_context(context)
        if type(vault) is not StateVault:raise Rejected('INVALID_STORAGE_VAULT')
        self.path=str(path);self.context=decode(encode(context));self.context_hash=r.context_hash(self.context)
        self.namespace=self.context['receiver_authority'].hex();self.vault=vault;self.clock=clock;self.witness=witness
        self.witness_fault=witness_fault;self._base_anchor=None;self._tx_time=None
        # Same shape as existing transport adapters, but no service is started.
        self.route={k:self.context[k] for k in ('tenant','recipient','gateway','session','sender_key','receiver_key','sender_kid','receiver_kid','sender_cert','receiver_cert')}
        existing=Path(path).exists() and Path(path).stat().st_size>0
        if not _initialize and not existing:raise Rejected('INBOX_RECOVERY_REQUIRED')
        if _initialize and existing:raise Rejected('FRESH_REPLICA_REQUIRED')
        if getattr(witness,'path',None) is not None and Path(witness.path).resolve()==Path(path).resolve():raise Rejected('WITNESS_NOT_INDEPENDENT')
        template=sqlite3.connect(':memory:')
        try:
            template.executescript(SCHEMA+ANCHOR_SCHEMA)
            self._trusted_schema=WitnessedLedger.schema(SimpleNamespace(db=template))
        finally:template.close()
        self.capacity=capacity_certificate(self.context,self.inbox_profile,vault.key_check,self._trusted_schema)
        if self.capacity['bound_bytes']>self.capacity['image_limit']:
            raise Rejected('V2_RECIPIENT_CAPACITY')
        self.db=sqlite3.connect(str(path),timeout=10,isolation_level=None);self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL');self.db.execute('PRAGMA foreign_keys=ON')
        try:
            if _initialize:
                self.db.executescript(SCHEMA+ANCHOR_SCHEMA)
                self.db.execute('INSERT INTO v2_recipient_meta VALUES(1,?,?,?,?,?,?,?,0,NULL)',
                    (self.inbox_profile,encode(self.context),vault.key_check,self.namespace,u64(0),u64(0),r.genesis(self.context)))
            self.check_storage_profile()
        except BaseException:self.close();raise

    @classmethod
    def new_replica(cls,path,**kwargs):return cls(path,_initialize=True,**kwargs)
    def close(self):self.db.close()

    def check_storage_profile(self):
        if self.schema()!=self._trusted_schema:raise Rejected('V2_RECIPIENT_SCHEMA')
        row=self.db.execute('SELECT profile,context,key_check,namespace FROM v2_recipient_meta WHERE singleton=1').fetchone()
        if row is None or tuple(row)!=(self.inbox_profile,encode(self.context),self.vault.key_check,self.namespace):raise Rejected('V2_RECIPIENT_PROFILE')

    def state(self):
        row=self.db.execute('SELECT * FROM v2_recipient_meta WHERE singleton=1').fetchone()
        return dict(high=number(row['high']),floor=number(row['floor']),root=row['root'],observed=row['observed'],last_offer=row['last_offer'])

    def seal(self,kind,seq,did,raw):return self.vault.seal('v2-recipient-'+kind,(self.context_hash,seq,did),raw)
    def open(self,kind,row):return self.vault.open('v2-recipient-'+kind,(self.context_hash,number(row['seq']),row['id']),row[kind])

    def live_facts(self):return [self.open('fact',row) for row in self.db.execute('SELECT * FROM v2_recipient_live ORDER BY seq')]

    def audit_local(self):
        self.check_storage_profile();state=self.state();r.uint(state['observed'],0,r.MAX_TIME)
        r.validate_receiver_state(self.context,state['floor'],state['root'],state['high'],self.live_facts())
        for row in self.db.execute('SELECT * FROM v2_recipient_live ORDER BY seq'):
            fact=delivery.verify_fact_evidence(self.open('fact',row),self.open('evidence',row),self.context)
            if fact['seq']!=number(row['seq']) or fact['delivery']!=row['id'] or fact['event_at']>state['observed']:
                raise Rejected('V2_RECIPIENT_EVENT_BINDING')
        if state['floor']:
            raw=self.vault.open('v2-recipient-last-offer',(self.context_hash,),state['last_offer'])
            offer=r.parse_offer(raw,self.context)
            if offer['target']!=state['floor'] or offer['target_root']!=state['root']:raise Rejected('V2_RECIPIENT_RETIREMENT_BINDING')
        return []

    def commit_transaction_guard(self):
        self.audit_local()
        WitnessedLedger.commit_transaction_guard(self)

    @contextmanager
    def tx(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.check_storage_profile();self.begin_transaction_guard()
            now=self.clock();r.uint(now,0,r.MAX_TIME)
            if now<self.state()['observed']:raise Rejected('INBOX_CLOCK_ROLLBACK')
            self._tx_time=now;self.db.execute('UPDATE v2_recipient_meta SET observed=? WHERE singleton=1',(now,))
            self.db.execute('SAVEPOINT business')
            try:yield
            except Rejected:
                self.db.execute('ROLLBACK TO business');self.db.execute('RELEASE business')
                self.commit_transaction_guard();self.db.commit();raise
            else:
                self.db.execute('RELEASE business');self.commit_transaction_guard();self.db.commit()
        except BaseException:
            if self.db.in_transaction:self.db.rollback()
            raise
        finally:self._tx_time=None

    def _first_event(self,request,parsed,signer,fault):
        body=delivery.parse_body(parsed['kind'],parsed['body'],self.context)
        desc=delivery.parse_descriptor(body['descriptor'],self.context);seq=desc['seq']
        with self.tx():
            state=self.state();now=self._tx_time
            if seq<=state['floor']:raise Rejected('V2_RETIRED')
            if parsed['kind']=='TERMINAL' and now<desc['expires_at']:raise Rejected('TERMINAL_NOT_EXPIRED')
            old=self.db.execute('SELECT * FROM v2_recipient_live WHERE seq=?',(u64(seq),)).fetchone()
            if old:
                raw=self.open('fact',old);fact=delivery.verify_fact_evidence(raw,self.open('evidence',old),self.context)
                if parsed['kind']=='DELIVERY':
                    if fact['outcome']=='CLOSED':raise Rejected('V2_DELIVERY_CLOSED')
                    if self.open('evidence',old)!=parsed['body']:raise Rejected('V2_EVENT_CONFLICT')
                    delivery.fact_matches_request(raw,request,self.context)
                else:delivery.terminal_reply_fact(parsed['body'],raw,self.context)
            else:
                if state['high']==r.MAX_SEQ:raise Rejected('V2_SEQUENCE_EXHAUSTED')
                if seq!=state['high']+1:raise Rejected('V2_RECIPIENT_ORDER')
                if state['high']-state['floor']>=self.context['window']:raise Rejected('V2_RECIPIENT_WINDOW_FULL')
                raw=(delivery.accepted_fact(parsed['body'],now,self.context) if parsed['kind']=='DELIVERY'
                     else delivery.closed_fact(parsed['body'],now,self.context))
                self.db.execute('INSERT INTO v2_recipient_live VALUES(?,?,?,?)',
                    (u64(seq),desc['delivery'],self.seal('fact',seq,desc['delivery'],raw),self.seal('evidence',seq,desc['delivery'],parsed['body'])))
                fault('after_v2_recipient_record')
                self.db.execute('UPDATE v2_recipient_meta SET high=? WHERE singleton=1',(u64(seq),))
            fault('before_v2_recipient_event_commit')
        fault('after_v2_recipient_event_commit')
        return delivery.receipt(raw,request,self.context,signer)

    def _retire(self,request,parsed,signer,fault):
        offer=r.parse_offer(parsed['offer'],self.context)
        with self.tx():
            state=self.state()
            if offer['target']<=state['floor']:
                # Older offers cannot mutate the state. A reply reports only the
                # current checkpoint, NOT validation/reconstruction of old facts.
                if offer['target']==state['floor'] and offer['target_root']!=state['root']:
                    raise Rejected('RETENTION_PREFIX_MISMATCH')
            else:
                next_state=r.retirement_transition(parsed['offer'],self.context,floor=state['floor'],root=state['root'],
                    high=state['high'],live=self.live_facts())
                self.db.execute('DELETE FROM v2_recipient_live WHERE seq<=?',(u64(next_state['floor']),))
                fault('after_v2_recipient_delete')
                last=self.vault.seal('v2-recipient-last-offer',(self.context_hash,),parsed['offer'])
                self.db.execute('UPDATE v2_recipient_meta SET floor=?,root=?,last_offer=? WHERE singleton=1',
                    (u64(next_state['floor']),next_state['root'],last))
            fault('before_v2_recipient_retire_commit');result=self.state()
        fault('after_v2_recipient_retire_commit')
        return r.checkpoint(request,self.context,'RETIRE_ACK',floor=result['floor'],root=result['root'],high=result['high'],key=signer)

    def _query(self,request,parsed,signer,fault):
        with self.tx():
            state=self.state()
            if parsed['kind']=='FINAL':
                if parsed['seq']<=state['floor']:raise Rejected('V2_RETIRED')
                row=self.db.execute('SELECT * FROM v2_recipient_live WHERE seq=?',(u64(parsed['seq']),)).fetchone()
                if row is None:raise Rejected('V2_NO_FINAL_RECORD')
                raw=self.open('fact',row);delivery.verify_fact_evidence(raw,self.open('evidence',row),self.context)
            elif parsed['kind']=='RETIRED' and parsed['seq']>state['floor']:raise Rejected('RETENTION_NOT_RETIRED')
            fault('before_v2_recipient_query_commit')
        fault('after_v2_recipient_query_commit')
        if parsed['kind']=='FINAL':return r.final_receipt(raw,request,self.context,signer)
        return r.checkpoint(request,self.context,parsed['kind'],floor=state['floor'],root=state['root'],high=state['high'],key=signer)

    def accept(self,request,peer,signer,fault=lambda point:None):
        if peer!=self.context['sender_cert']:raise Rejected('UNAUTHORIZED_GATEWAY')
        if public(signer)!=self.context['receiver_key']:raise Rejected('WRONG_RECIPIENT_SIGNER')
        # Unverified content selects a parser ONLY. Every branch subsequently
        # authenticates its exact closed schema and domain before state access.
        _,payload,_,_=inspect_sign1(r.frame(request));routing=decode(payload)
        if type(routing) is not dict:raise Rejected('V2_RECIPIENT_REQUEST')
        if routing.get('profile')==delivery.PROFILE:
            return self._first_event(request,delivery.parse_attempt(request,self.context),signer,fault)
        if routing.get('profile')==r.PROFILE and set(routing)==r.ATTEMPT_FIELDS:
            return self._retire(request,r.parse_retire_attempt(request,self.context),signer,fault)
        if routing.get('profile')==r.PROFILE and set(routing)==r.QUERY_FIELDS:
            return self._query(request,r.parse_query(request,self.context),signer,fault)
        raise Rejected('V2_RECIPIENT_REQUEST')


class TLSRetentionRecipient(RetentionRecipient):
    inbox_profile='mtls-witnessed-mixed-retention-recipient-v2'

    def __init__(self,path,*,witness,**kwargs):
        if type(witness) is not TLSWitnessClient:raise Rejected('AUTHENTICATED_WITNESS_REQUIRED')
        super().__init__(path,witness=witness,**kwargs)
