"""Witnessed v2 sender: atomic L3 identity/outbox, evidence and retirement gate.

Reference and authenticated-witness profiles. No v2 recipient or network driver.
The trusted driver supplies authenticated route context and stable admission key.
Existing v1 databases are not migrated. Sender archives are deliberately retained.
"""
from pathlib import Path
import sqlite3
from ledger import Rejected
from wire import encode,decode
from witnessed_mixed_ledger import WitnessedMixedLedger
from witness_transport import TLSWitnessedLedger
from mixed_delivery_transport import MixedDeliveryLedger
from delivery_transport import public
import retention_wire as r
import retention_delivery as delivery

SCHEMA='''
CREATE TABLE v2_routes (
 context_hash BLOB PRIMARY KEY CHECK(typeof(context_hash)='blob' AND length(context_hash)=32),
 tenant TEXT NOT NULL, recipient TEXT NOT NULL, gateway TEXT NOT NULL, session TEXT NOT NULL,
 context BLOB NOT NULL, high BLOB NOT NULL CHECK(typeof(high)='blob' AND length(high)=8),
 confirmed BLOB NOT NULL CHECK(typeof(confirmed)='blob' AND length(confirmed)=8), confirmed_root BLOB NOT NULL,
 retired BLOB NOT NULL CHECK(typeof(retired)='blob' AND length(retired)=8), retired_root BLOB NOT NULL,
 retirement_evidence BLOB,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 CHECK((retired=zeroblob(8))=(retirement_evidence IS NULL)),
 UNIQUE(tenant,recipient,gateway,session)
);
CREATE TABLE v2_requests (
 context_hash BLOB NOT NULL REFERENCES v2_routes(context_hash), request_key TEXT NOT NULL,
 tenant TEXT NOT NULL, operation_id TEXT NOT NULL, ttl INTEGER NOT NULL CHECK(ttl BETWEEN 1 AND 60),
 delivery_id TEXT NOT NULL, PRIMARY KEY(context_hash,request_key), UNIQUE(tenant,delivery_id),
 FOREIGN KEY(tenant,delivery_id) REFERENCES deliveries(tenant,id)
);
CREATE TABLE v2_outbox (
 tenant TEXT NOT NULL, id TEXT NOT NULL, context_hash BLOB NOT NULL REFERENCES v2_routes(context_hash),
 seq BLOB NOT NULL CHECK(typeof(seq)='blob' AND length(seq)=8), descriptor BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('QUEUED','READY','ACCEPTED','CLOSED')),
 envelope BLOB, control BLOB, fact BLOB, acknowledgement BLOB,
 PRIMARY KEY(tenant,id), UNIQUE(context_hash,seq),
 FOREIGN KEY(tenant,id) REFERENCES deliveries(tenant,id),
 CHECK((state IN ('ACCEPTED','CLOSED'))=(fact IS NOT NULL)),
 CHECK((fact IS NOT NULL)=(acknowledgement IS NOT NULL)),
 CHECK(state!='READY' OR envelope IS NOT NULL)
);
CREATE TABLE v2_retire_offers (
 context_hash BLOB NOT NULL REFERENCES v2_routes(context_hash),
 base BLOB NOT NULL CHECK(typeof(base)='blob' AND length(base)=8),
 target BLOB NOT NULL CHECK(typeof(target)='blob' AND length(target)=8),
 offer BLOB NOT NULL, PRIMARY KEY(context_hash,base,target)
);
'''
_template=sqlite3.connect(':memory:');_template.executescript(SCHEMA)
TRUSTED_SCHEMA=dict(_template.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"));_template.close()


def u64(value):r.uint(value);return value.to_bytes(8,'big')


def number(raw):
    if type(raw) is not bytes or len(raw)!=8:raise Rejected('V2_SEQUENCE_STORAGE')
    return int.from_bytes(raw,'big')


def check_signer(context,signer):
    if public(signer)!=context['sender_key']:raise Rejected('RETENTION_SIGNING_KEY')


class RetentionSender(WitnessedMixedLedger):
    storage_profile='witnessed-mixed-retention-sender-v2'
    descriptor_fields=MixedDeliveryLedger.descriptor_fields

    def __init__(self,path,*args,**kwargs):
        self._initial_empty=not Path(path).exists() or not Path(path).stat().st_size
        self._recovering_v2=False
        super().__init__(path,*args,**kwargs)

    @classmethod
    def new_replica(cls,path,**kwargs):
        obj=super().new_replica(path,**kwargs);obj.db.executescript(SCHEMA)
        obj._initial_empty=False;obj.check_storage_profile();return obj

    def check_storage_profile(self,allow_empty=False):
        super().check_storage_profile(allow_empty=allow_empty)
        present=dict(self.db.execute("SELECT name,sql FROM sqlite_master WHERE name LIKE 'v2_%' AND type='table'"))
        if not present and self._initial_empty:return
        if present!=TRUSTED_SCHEMA:raise Rejected('V2_SCHEMA_MISMATCH')
        if self._recovering_v2 and self.audit_v2():raise Rejected('V2_RECOVERY_AUDIT_FAILED')

    def recover_from_witness(self,*args,**kwargs):
        # The generic restorer invokes check_storage_profile before its commit;
        # include this subclass's evidence/frontier checks at that boundary.
        self._recovering_v2=True
        try:return super().recover_from_witness(*args,**kwargs)
        finally:self._recovering_v2=False

    def admit_delivery(self,*args,**kwargs):raise Rejected('V2_ADMISSION_REQUIRED')
    def on_delivery_admitted(self,*args,**kwargs):raise Rejected('V2_ADMISSION_REQUIRED')
    def emit(self,*args,**kwargs):raise Rejected('V2_SIGNED_DELIVERY_REQUIRED')

    def route(self,context_hash,live=False):
        row=self.db.execute('SELECT * FROM v2_routes WHERE context_hash=?',(context_hash,)).fetchone()
        if row is None:raise Rejected('V2_UNKNOWN_ROUTE')
        if live and row['revoked']:raise Rejected('V2_ROUTE_REVOKED')
        context=decode(row['context']);r.validate_context(context)
        if (r.context_hash(context)!=row['context_hash'] or context['deployment']!=self.vault.deployment_id or
            context['sender_authority'].hex()!=self.namespace or
            any(context[k]!=row[k] for k in ('tenant','recipient','gateway','session'))):raise Rejected('V2_ROUTE_BINDING')
        return row,context

    def register_context(self,context):
        r.validate_context(context);digest=r.context_hash(context)
        if context['deployment']!=self.vault.deployment_id or context['sender_authority'].hex()!=self.namespace:
            raise Rejected('V2_ROUTE_BINDING')
        with self.tx():
            old=self.db.execute('SELECT context_hash,revoked FROM v2_routes WHERE tenant=? AND recipient=? AND gateway=? AND session=?',
                tuple(context[k] for k in ('tenant','recipient','gateway','session'))).fetchone()
            if old:
                if old['context_hash']!=digest:raise Rejected('V2_ROUTE_IMMUTABLE')
                if old['revoked']:raise Rejected('V2_ROUTE_REVOKED')
                return digest
            self.db.execute('INSERT INTO v2_routes VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL,0)',
                (digest,context['tenant'],context['recipient'],context['gateway'],context['session'],encode(context),u64(0),u64(0),r.genesis(context),u64(0),r.genesis(context)))
        return digest

    def revoke_context(self,digest):
        with self.tx():
            self.route(digest);self.db.execute('UPDATE v2_routes SET revoked=1 WHERE context_hash=?',(digest,))

    def outbox(self,tenant,did):
        row=self.db.execute('SELECT * FROM v2_outbox WHERE tenant=? AND id=?',(tenant,did)).fetchone()
        if row is None:raise Rejected('V2_UNKNOWN_DELIVERY')
        return row

    def ticket(self,row):
        ticket=self.db.execute('SELECT * FROM deliveries WHERE tenant=? AND id=?',(row['tenant'],row['id'])).fetchone()
        if ticket is None:raise Rejected('V2_MISSING_TICKET')
        return ticket

    def seal(self,kind,row,raw):return self.vault.seal('v2-'+kind,(row['context_hash'],row['tenant'],row['id']),raw)
    def open(self,kind,row):return self.vault.open('v2-'+kind,(row['context_hash'],row['tenant'],row['id']),row[kind])

    def admit_v2(self,digest,request_key,oid,ttl=60,fault=lambda point:None):
        if type(request_key) is not str or not 1<=len(request_key.encode())<=128:raise Rejected('V2_REQUEST_KEY')
        if type(ttl) is not int or not 0<ttl<=60:raise Rejected('INVALID_TTL')
        with self.tx():
            row,created=self._admit_v2_tx(digest,request_key,oid,ttl,fault)
        if created:fault('after_v2_admission_commit')
        return row

    def _admit_v2_tx(self,digest,request_key,oid,ttl=60,fault=lambda point:None):
        """Trusted transaction core for atomic scheduler/publication integration.

        The enclosing guarded transaction owns witness publication and commit.
        Never performs a nested BEGIN, commits, or emits an after-commit signal.
        """
        if not self.db.in_transaction or self._tx_time is None or self._base_anchor is None:
            raise Rejected('V2_TRANSACTION_REQUIRED')
        if type(request_key) is not str or not 1<=len(request_key.encode())<=128:raise Rejected('V2_REQUEST_KEY')
        if type(ttl) is not int or not 0<ttl<=60:raise Rejected('INVALID_TTL')
        route,context=self.route(digest,live=True);tenant=context['tenant']
        old=self.db.execute('SELECT * FROM v2_requests WHERE context_hash=? AND request_key=?',(digest,request_key)).fetchone()
        if old and (old['operation_id']!=oid or old['ttl']!=ttl):raise Rejected('V2_REQUEST_CONFLICT')
        # Preserve all original new-L3 authorization/publication checks, even
        # on public admission retries. Old admitted recovery is separate.
        op=self.op(tenant,oid)
        if op['recipient']!=context['recipient']:raise Rejected('UNAUTHORIZED')
        root=self.live_root(tenant,op['root_id']);self.require_root_mode(root)
        self.validate_delivery(op);self.authorize_delivery(op)
        if old:
            row=self.outbox(tenant,old['delivery_id']);ticket=self.ticket(row)
            if self.now()>=ticket['expires_at']:raise Rejected('TICKET_EXPIRED')
            return dict(row),False
        if op['state']!='COMMITTED':raise Rejected('NOT_COMMITTED')
        high=number(route['high'])
        if high==r.MAX_SEQ:raise Rejected('V2_SEQUENCE_EXHAUSTED')
        seq=high+1;did=r.delivery_id(context,seq);now=self.now();expiry=self.delivery_expiry(op,root,now,ttl)
        descriptor=delivery.descriptor(context,seq=seq,operation=oid,issued_at=now,expires_at=expiry,
            shape=self.descriptor_fields(tenant,oid,op['digest']))
        self.db.execute('INSERT INTO deliveries(tenant,id,operation_id,recipient,result_digest,gateway,session,issued_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)',
            (tenant,did,oid,context['recipient'],op['result_digest'],context['gateway'],context['session'],now,expiry))
        fault('after_v2_ticket_write')
        self.db.execute('INSERT INTO v2_requests VALUES(?,?,?,?,?,?)',(digest,request_key,tenant,oid,ttl,did))
        fault('after_v2_request_write')
        self.db.execute("INSERT INTO v2_outbox VALUES(?,?,?,?,?,'QUEUED',NULL,NULL,NULL,NULL)",(tenant,did,digest,u64(seq),descriptor))
        self.db.execute('UPDATE v2_routes SET high=? WHERE context_hash=?',(u64(seq),digest))
        fault('before_v2_admission_commit')
        return dict(self.outbox(tenant,did)),True

    def first_pending(self,row):
        return self.db.execute("SELECT min(seq) FROM v2_outbox WHERE context_hash=? AND state NOT IN ('ACCEPTED','CLOSED')",(row['context_hash'],)).fetchone()[0]

    def validate_descriptor_binding(self,row):
        ticket=self.ticket(row);_,context=self.route(row['context_hash'])
        if any(ticket[k]!=context[k] for k in ('tenant','recipient','gateway','session')):raise Rejected('V2_TICKET_ROUTE')
        op=self.db.execute('SELECT digest FROM operations WHERE tenant=? AND id=?',(ticket['tenant'],ticket['operation_id'])).fetchone()
        expected=delivery.descriptor(context,seq=number(row['seq']),operation=ticket['operation_id'],issued_at=ticket['issued_at'],expires_at=ticket['expires_at'],
            shape=self.descriptor_fields(ticket['tenant'],ticket['operation_id'],op['digest']))
        if expected!=row['descriptor'] or row['id']!=r.delivery_id(context,number(row['seq'])):raise Rejected('V2_DESCRIPTOR_BINDING')
        return ticket,context

    def prepare_envelope(self,tenant,did,signer,fault=lambda point:None):
        with self.tx():
            row=self.outbox(tenant,did);_,context=self.route(row['context_hash'],live=True)
            if row['state'] in ('ACCEPTED','CLOSED'):return None
            if row['seq']!=self.first_pending(row):raise Rejected('V2_DELIVERY_ORDER')
            check_signer(context,signer)
            ticket,context=self.validate_descriptor_binding(row)
            if self.now()>=ticket['expires_at']:raise Rejected('TICKET_EXPIRED')
            op=self.op(tenant,ticket['operation_id'])
            if op['state']!='COMMITTED' or op['result_digest']!=ticket['result_digest']:raise Rejected('RESULT_UNAVAILABLE')
            if row['envelope'] is None:
                raw=delivery.envelope(row['descriptor'],op['result'],context,signer)
                self.db.execute("UPDATE v2_outbox SET envelope=?,state='READY' WHERE tenant=? AND id=?",(self.seal('envelope',row,raw),tenant,did))
            else:
                # Validate signer even on retry; no untrusted replacement key.
                check_signer(context,signer)
                raw=self.open('envelope',row)
            parsed=delivery.parse_envelope(raw,context)
            if parsed['descriptor']!=row['descriptor'] or parsed['result']!=op['result']:raise Rejected('V2_OUTPUT_BINDING')
            self.db.execute('UPDATE deliveries SET handoff_admitted=1 WHERE tenant=? AND id=?',(tenant,did))
            fault('before_v2_envelope_commit')
        fault('after_v2_envelope_commit');return raw

    def prepare_terminal(self,tenant,did,signer,fault=lambda point:None):
        with self.tx():
            row=self.outbox(tenant,did);ticket,context=self.validate_descriptor_binding(row)
            if self.now()<ticket['expires_at']:raise Rejected('TERMINAL_NOT_EXPIRED')
            if row['state'] not in ('ACCEPTED','CLOSED') and row['seq']!=self.first_pending(row):raise Rejected('V2_DELIVERY_ORDER')
            expected_hash=b'' if row['envelope'] is None else r.sha(self.open('envelope',row))
            raw=self.open('control',row) if row['control'] is not None else delivery.control(row['descriptor'],expected_hash,context,signer)
            check_signer(context,signer)
            parsed=delivery.parse_control(raw,context)
            if parsed['descriptor']!=row['descriptor'] or parsed['envelope_hash']!=expected_hash:raise Rejected('V2_CONTROL_BINDING')
            if row['control'] is None:self.db.execute('UPDATE v2_outbox SET control=? WHERE tenant=? AND id=?',(self.seal('control',row,raw),tenant,did))
            fault('before_v2_control_commit')
        fault('after_v2_control_commit');return raw

    def confirm(self,tenant,did,request,ack,fault=lambda point:None):
        with self.tx():
            row=self.outbox(tenant,did);_,context=self.route(row['context_hash'])
            req=delivery.parse_attempt(request,context);kind='envelope' if req['kind']=='DELIVERY' else 'control'
            if row[kind] is None or req['body']!=self.open(kind,row):raise Rejected('V2_UNPREPARED_EVIDENCE')
            raw=delivery.parse_receipt(ack,request,context);fact=r.parse_fact(raw,context)
            if row['fact'] is not None:
                if self.open('fact',row)!=raw:raise Rejected('V2_FACT_CONFLICT')
                return fact['outcome']
            self.db.execute('UPDATE v2_outbox SET state=?,fact=?,acknowledgement=? WHERE tenant=? AND id=?',
                (fact['outcome'],self.seal('fact',row,raw),self.seal('acknowledgement',row,encode({'request':request,'ack':ack})),tenant,did))
            route,_=self.route(row['context_hash']);front=number(route['confirmed']);root=route['confirmed_root']
            for later in self.db.execute('SELECT * FROM v2_outbox WHERE context_hash=? AND seq>? ORDER BY seq',(row['context_hash'],u64(front))):
                if later['fact'] is None:break
                if number(later['seq'])!=front+1:raise Rejected('V2_SEQUENCE_GAP')
                front+=1;root=r.extend_prefix(root,self.open('fact',later),context,front)
            self.db.execute('UPDATE v2_routes SET confirmed=?,confirmed_root=? WHERE context_hash=?',(u64(front),root,row['context_hash']))
            fault('before_v2_confirmation_commit')
        fault('after_v2_confirmation_commit');return fact['outcome']

    def archive_root(self,digest,target):
        r.uint(target);_,context=self.route(digest);root=r.genesis(context);seq=0
        for row in self.db.execute('SELECT * FROM v2_outbox WHERE context_hash=? AND seq<=? ORDER BY seq',(digest,u64(target))):
            seq+=1
            if number(row['seq'])!=seq or row['fact'] is None:raise Rejected('V2_ARCHIVE_GAP')
            root=r.extend_prefix(root,self.open('fact',row),context,seq)
        if seq!=target:raise Rejected('V2_ARCHIVE_GAP')
        return root

    def prepare_retirement(self,digest,target,signer,fault=lambda point:None):
        with self.tx():
            route,context=self.route(digest);r.uint(target,1);base=number(route['retired'])
            if not base<target<=number(route['confirmed']):raise Rejected('V2_UNCONFIRMED_RETIREMENT')
            target_root=self.archive_root(digest,target)
            old=self.db.execute('SELECT offer FROM v2_retire_offers WHERE context_hash=? AND base=? AND target=?',(digest,u64(base),u64(target))).fetchone()
            if old:
                check_signer(context,signer)
                raw=self.vault.open('v2-retire-offer',(digest,base,target),old['offer'])
            else:
                raw=r.offer(context,base,route['retired_root'],target,target_root,signer)
                sealed=self.vault.seal('v2-retire-offer',(digest,base,target),raw)
                self.db.execute('INSERT INTO v2_retire_offers VALUES(?,?,?,?)',(digest,u64(base),u64(target),sealed))
            parsed=r.parse_offer(raw,context)
            if parsed['base']!=base or parsed['target']!=target or parsed['base_root']!=route['retired_root'] or parsed['target_root']!=target_root:
                raise Rejected('V2_RETIREMENT_BINDING')
            fault('before_v2_retirement_offer_commit')
        fault('after_v2_retirement_offer_commit');return raw

    def confirm_retirement(self,digest,request,ack,fault=lambda point:None):
        with self.tx():
            route,context=self.route(digest);checkpoint=r.parse_checkpoint(ack,request,context)
            if checkpoint['high']>number(route['high']):raise Rejected('V2_RECEIVER_AHEAD_OF_ADMISSION')
            if checkpoint['status']=='RETIRE_ACK':
                offered=r.parse_offer(r.parse_retire_attempt(request,context)['offer'],context)
                saved=self.db.execute('SELECT offer FROM v2_retire_offers WHERE context_hash=? AND base=? AND target=?',(digest,u64(offered['base']),u64(offered['target']))).fetchone()
                if saved is None or self.vault.open('v2-retire-offer',(digest,offered['base'],offered['target']),saved[0])!=r.parse_retire_attempt(request,context)['offer']:
                    raise Rejected('V2_UNKNOWN_RETIREMENT_OFFER')
            floor,root=r.reconcile_checkpoint(ack,request,context,known_floor=number(route['retired']),confirmed=number(route['confirmed']),
                archived_root=self.archive_root(digest,checkpoint['floor']))
            evidence=None if floor==0 else self.vault.seal('v2-retirement-checkpoint',(digest,),encode({'request':request,'ack':ack}))
            self.db.execute('UPDATE v2_routes SET retired=?,retired_root=?,retirement_evidence=? WHERE context_hash=?',(u64(floor),root,evidence,digest))
            fault('before_v2_retirement_checkpoint_commit')
        fault('after_v2_retirement_checkpoint_commit');return floor

    def audit_v2(self):
        errors=[]
        for route in self.db.execute('SELECT * FROM v2_routes'):
            route,context=self.route(route['context_hash']);high=number(route['high']);confirmed=number(route['confirmed']);retired=number(route['retired'])
            if not retired<=confirmed<=high:errors.append('V2_FRONTIER')
            rows=list(self.db.execute('SELECT * FROM v2_outbox WHERE context_hash=? ORDER BY seq',(route['context_hash'],)))
            if len(rows)!=high or any(number(row['seq'])!=i for i,row in enumerate(rows,1)):errors.append('V2_SEQUENCE')
            actual_confirmed=0
            for row in rows:
                ticket,ctx=self.validate_descriptor_binding(row)
                if row['envelope'] is not None:
                    env=delivery.parse_envelope(self.open('envelope',row),ctx);op=self.op(row['tenant'],ticket['operation_id'])
                    if env['descriptor']!=row['descriptor'] or env['result']!=op['result'] or not ticket['handoff_admitted']:errors.append('V2_OUTPUT_BINDING')
                if row['control'] is not None:
                    ctl=delivery.parse_control(self.open('control',row),ctx)
                    if ctl['descriptor']!=row['descriptor'] or ctl['envelope_hash']!=(b'' if row['envelope'] is None else r.sha(self.open('envelope',row))):errors.append('V2_CONTROL_BINDING')
                if row['fact'] is not None:
                    raw=self.open('fact',row);fact=r.parse_fact(raw,ctx);saved=decode(self.open('acknowledgement',row))
                    if set(saved)!={'request','ack'} or delivery.parse_receipt(saved['ack'],saved['request'],ctx)!=raw or fact['outcome']!=row['state']:errors.append('V2_FACT_BINDING')
                    req=delivery.parse_attempt(saved['request'],ctx);kind='envelope' if req['kind']=='DELIVERY' else 'control'
                    if row[kind] is None or req['body']!=self.open(kind,row):errors.append('V2_REQUEST_EVIDENCE')
                    if actual_confirmed==number(row['seq'])-1:actual_confirmed+=1
            if actual_confirmed!=confirmed:errors.append('V2_CONFIRMED_FRONTIER')
            if self.archive_root(route['context_hash'],confirmed)!=route['confirmed_root'] or self.archive_root(route['context_hash'],retired)!=route['retired_root']:errors.append('V2_ARCHIVE_ROOT')
            if retired:
                saved=decode(self.vault.open('v2-retirement-checkpoint',(route['context_hash'],),route['retirement_evidence']))
                if set(saved)!={'request','ack'}:raise Rejected('V2_CHECKPOINT_EVIDENCE')
                checkpoint=r.parse_checkpoint(saved['ack'],saved['request'],context)
                if checkpoint['floor']!=retired or checkpoint['root']!=route['retired_root'] or checkpoint['high']>high:errors.append('V2_CHECKPOINT_BINDING')
                if checkpoint['status']=='RETIRE_ACK':
                    request=r.parse_retire_attempt(saved['request'],context);offered=r.parse_offer(request['offer'],context)
                    original=self.db.execute('SELECT offer FROM v2_retire_offers WHERE context_hash=? AND base=? AND target=?',
                        (route['context_hash'],u64(offered['base']),u64(offered['target']))).fetchone()
                    if original is None or self.vault.open('v2-retire-offer',(route['context_hash'],offered['base'],offered['target']),original[0])!=request['offer']:
                        errors.append('V2_CHECKPOINT_OFFER')
        tickets={(x['tenant'],x['id']) for x in self.db.execute('SELECT tenant,id FROM deliveries')}
        outboxes={(x['tenant'],x['id']) for x in self.db.execute('SELECT tenant,id FROM v2_outbox')}
        requests=list(self.db.execute('SELECT * FROM v2_requests'))
        if tickets!=outboxes or {(x['tenant'],x['delivery_id']) for x in requests}!=outboxes:errors.append('V2_ADMISSION_COVERAGE')
        for req in requests:
            row=self.outbox(req['tenant'],req['delivery_id']);ticket=self.ticket(row)
            if req['context_hash']!=row['context_hash'] or req['operation_id']!=ticket['operation_id'] or ticket['expires_at']-ticket['issued_at']>req['ttl']:errors.append('V2_REQUEST_BINDING')
        for stored in self.db.execute('SELECT * FROM v2_retire_offers'):
            base,target=number(stored['base']),number(stored['target']);route,ctx=self.route(stored['context_hash'])
            raw=self.vault.open('v2-retire-offer',(stored['context_hash'],base,target),stored['offer']);obj=r.parse_offer(raw,ctx)
            if (obj['base']!=base or obj['target']!=target or target>number(route['confirmed']) or
                obj['base_root']!=self.archive_root(stored['context_hash'],base) or obj['target_root']!=self.archive_root(stored['context_hash'],target)):
                errors.append('V2_RETIREMENT_BINDING')
        return errors

    def audit(self):return super().audit()+self.audit_v2()


class TLSRetentionSender(TLSWitnessedLedger,RetentionSender):
    storage_profile='mtls-mixed-retention-sender-v2'
