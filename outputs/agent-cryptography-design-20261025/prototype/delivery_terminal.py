"""Result-free, post-expiry terminal reconciliation for a fixed delivery route.

The recipient atomically returns ACCEPTED for an existing record or persists a
CLOSED tombstone that fences later arrivals. Absence alone is never a receipt.
This is not a public readiness API or a proof of complete network-observation DP.
"""
import hashlib
import secrets
from delivery_transport import (DeliveryLedger,RecipientInbox,DeliverySender,Rejected,INBOX_SCHEMA,
    BINDINGS,ROUTE_KEYS,expected_bindings,valid_text,public,parse_envelope,PROFILE as DELIVERY_PROFILE)
from wire import encode,decode,sign1,verify_sign1

PROFILE='count-delivery-terminal-v1'
CONTROL_TYPE='CountDeliveryTerminal'
RECEIPT_TYPE='CountDeliveryTerminalAck'
CONTROL_FIELDS=set(BINDINGS)|{'profile','delivery','operation','seq','issued_at','expires_at','envelope_hash'}
RECEIPT_FIELDS={'profile','deployment','tenant','delivery','seq','terminal_hash','envelope_hash','challenge','request_hash','receiver_cert','outcome','event_at'}
TERMINAL_SCHEMA='''
CREATE TABLE delivery_terminal (
 tenant TEXT NOT NULL, id TEXT NOT NULL, control BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('PREPARED','CONFIRMED')), receipt BLOB,
 outcome TEXT CHECK(outcome IN ('ACCEPTED','CLOSED')),
 PRIMARY KEY(tenant,id), FOREIGN KEY(tenant,id) REFERENCES delivery_outbox(tenant,id),
 CHECK((state='CONFIRMED')=(receipt IS NOT NULL)),
 CHECK((state='CONFIRMED')=(outcome IS NOT NULL))
);
'''
CLOSED_SCHEMA='''
CREATE TABLE inbox_closed (id TEXT PRIMARY KEY, seq INTEGER NOT NULL UNIQUE, control BLOB NOT NULL, closed_at INTEGER NOT NULL);
'''


def terminal_attempt(raw,challenge):return encode({'profile':PROFILE,'challenge':challenge,'terminal':raw})


def parse_terminal_attempt(raw):
    obj=decode(raw)
    if (type(obj) is not dict or set(obj)!={'profile','challenge','terminal'} or obj['profile']!=PROFILE or
        type(obj['challenge']) is not bytes or len(obj['challenge'])!=32 or type(obj['terminal']) is not bytes):
        raise Rejected('INVALID_TERMINAL_ATTEMPT')
    return obj


def parse_control(raw,deployment,route):
    kid,obj=verify_sign1(raw,route['sender_key'],CONTROL_TYPE)
    if kid!=route['sender_kid'] or type(obj) is not dict or set(obj)!=CONTROL_FIELDS or obj['profile']!=PROFILE:
        raise Rejected('INVALID_TERMINAL_CONTROL')
    if any(obj[k]!=v for k,v in expected_bindings(deployment,route).items()):raise Rejected('TERMINAL_CONTEXT')
    if (any(not valid_text(obj[k]) for k in ('delivery','operation')) or type(obj['seq']) is not int or not 1<=obj['seq']<2**62 or
        type(obj['issued_at']) is not int or type(obj['expires_at']) is not int or not 0<=obj['issued_at']<obj['expires_at']<=2**62 or
        not 0<obj['expires_at']-obj['issued_at']<=60 or type(obj['envelope_hash']) is not bytes or len(obj['envelope_hash']) not in (0,32)):
        raise Rejected('INVALID_TERMINAL_CONTROL')
    return obj


def parse_receipt(raw,request,control,deployment,route):
    req=parse_terminal_attempt(request);obj=parse_control(control,deployment,route)
    kid,ack=verify_sign1(raw,route['receiver_key'],RECEIPT_TYPE)
    if kid!=route['receiver_kid'] or type(ack) is not dict or set(ack)!=RECEIPT_FIELDS or ack['profile']!=PROFILE:
        raise Rejected('INVALID_TERMINAL_RECEIPT')
    expected=dict(profile=PROFILE,deployment=deployment,tenant=obj['tenant'],delivery=obj['delivery'],seq=obj['seq'],
        terminal_hash=hashlib.sha256(control).digest(),envelope_hash=obj['envelope_hash'],challenge=req['challenge'],
        request_hash=hashlib.sha256(request).digest(),receiver_cert=route['receiver_cert'])
    if req['terminal']!=control or any(ack[k]!=v for k,v in expected.items()):raise Rejected('TERMINAL_RECEIPT_BINDING')
    if type(ack['event_at']) is not int or not 0<=ack['event_at']<=2**62:raise Rejected('INVALID_TERMINAL_RECEIPT')
    if ack['outcome']=='ACCEPTED':
        if len(obj['envelope_hash'])!=32 or not obj['issued_at']<=ack['event_at']<obj['expires_at']:raise Rejected('INVALID_TERMINAL_RECEIPT')
    elif ack['outcome']=='CLOSED':
        if ack['event_at']<obj['expires_at']:raise Rejected('INVALID_TERMINAL_RECEIPT')
    else:raise Rejected('INVALID_TERMINAL_RECEIPT')
    return ack


class TerminalDeliveryLedger(DeliveryLedger):
    storage_profile='mtls-count-delivery-terminal-v1'
    terminal_profile=PROFILE
    control_type=CONTROL_TYPE
    parse_control=staticmethod(parse_control)
    parse_receipt=staticmethod(parse_receipt)

    def terminal_fields(self,ticket):
        return {}

    @classmethod
    def new_replica(cls,path,**kwargs):
        obj=super().new_replica(path,**kwargs);obj.db.executescript(TERMINAL_SCHEMA);return obj

    def terminal(self,tenant,delivery_id):
        return self.db.execute('SELECT * FROM delivery_terminal WHERE tenant=? AND id=?',(tenant,delivery_id)).fetchone()

    def delivery_status(self,tenant,delivery_id):
        row=self.outbox(tenant,delivery_id);terminal=self.terminal(tenant,delivery_id)
        if terminal and terminal['state']=='CONFIRMED':return 'ACKED' if terminal['outcome']=='ACCEPTED' else 'CLOSED'
        return row['state']

    def first_pending(self,row):
        return self.db.execute("""SELECT min(o.seq) FROM delivery_outbox o
          LEFT JOIN delivery_terminal t ON t.tenant=o.tenant AND t.id=o.id
          WHERE o.tenant=? AND o.recipient=? AND o.gateway=? AND o.session=? AND o.state!='ACKED'
          AND (t.state IS NULL OR t.state!='CONFIRMED')""",tuple(row[k] for k in ROUTE_KEYS)).fetchone()[0]

    def validate_ack_transition(self,row,ack):
        terminal=self.terminal(row['tenant'],row['id'])
        if terminal and terminal['outcome']=='CLOSED':raise Rejected('TERMINAL_OUTCOME_CONFLICT')
        if terminal and terminal['state']=='CONFIRMED':
            route=self.route(row,live=False)
            raw=self.vault.open('terminal-control',(row['tenant'],row['id']),terminal['control'])
            stored=decode(self.vault.open('terminal-receipt',(row['tenant'],row['id']),terminal['receipt']))
            prior=self.parse_receipt(stored['receipt'],stored['request'],raw,self.namespace,route)
            if prior['event_at']!=ack['accepted_at']:raise Rejected('TERMINAL_OUTCOME_CONFLICT')

    def validate_receipt_against_ack(self,row,receipt,route):
        if row['state']!='ACKED':return
        if receipt['outcome']!='ACCEPTED':raise Rejected('TERMINAL_OUTCOME_CONFLICT')
        raw=self.vault.open('delivery-envelope',(row['tenant'],row['id']),row['envelope'])
        stored=decode(self.vault.open('delivery-ack',(row['tenant'],row['id']),row['acknowledgement']))
        prior=self.parse_ack(stored['ack'],stored['request'],raw,self.namespace,route)
        if prior['accepted_at']!=receipt['event_at']:raise Rejected('TERMINAL_OUTCOME_CONFLICT')

    def validate_control_binding(self,raw,row,route):
        obj=self.parse_control(raw,self.namespace,route)
        ticket=self.db.execute('SELECT * FROM deliveries WHERE tenant=? AND id=?',(row['tenant'],row['id'])).fetchone()
        expected=dict(delivery=row['id'],operation=ticket['operation_id'],seq=row['seq'],issued_at=ticket['issued_at'],expires_at=ticket['expires_at'],**self.terminal_fields(ticket))
        if any(obj[k]!=v for k,v in expected.items()):raise Rejected('TERMINAL_TICKET_BINDING')
        if row['envelope'] is None:digest=b''
        else:
            envelope=self.vault.open('delivery-envelope',(row['tenant'],row['id']),row['envelope'])
            digest=hashlib.sha256(envelope).digest()
        if obj['envelope_hash']!=digest:raise Rejected('TERMINAL_TICKET_BINDING')
        return obj

    def prepare_terminal(self,tenant,delivery_id,signer,fault=lambda point:None):
        with self.tx():
            row=self.outbox(tenant,delivery_id);route=self.route(row)
            if public(signer)!=route['sender_key']:raise Rejected('WRONG_GATEWAY_SIGNER')
            if self.delivery_status(tenant,delivery_id) in ('ACKED','CLOSED'):return None
            if row['seq']!=self.first_pending(row):raise Rejected('DELIVERY_ORDER')
            ticket=self.db.execute('SELECT * FROM deliveries WHERE tenant=? AND id=?',(tenant,delivery_id)).fetchone()
            if self.now()<ticket['expires_at']:raise Rejected('TERMINAL_NOT_EXPIRED')
            stored=self.terminal(tenant,delivery_id)
            if stored:raw=self.vault.open('terminal-control',(tenant,delivery_id),stored['control'])
            else:
                digest=b'' if row['envelope'] is None else hashlib.sha256(self.vault.open('delivery-envelope',(tenant,delivery_id),row['envelope'])).digest()
                obj=dict(profile=self.terminal_profile,**expected_bindings(self.namespace,route),delivery=delivery_id,operation=ticket['operation_id'],
                    seq=row['seq'],issued_at=ticket['issued_at'],expires_at=ticket['expires_at'],envelope_hash=digest,**self.terminal_fields(ticket))
                raw=sign1(encode(obj),route['sender_kid'],signer,self.control_type)
                sealed=self.vault.seal('terminal-control',(tenant,delivery_id),raw)
                self.db.execute("INSERT INTO delivery_terminal(tenant,id,control,state) VALUES(?,?,?,'PREPARED')",(tenant,delivery_id,sealed))
            self.validate_control_binding(raw,row,route)
            fault('before_terminal_prepare_commit')
        fault('after_terminal_prepare_commit')
        return raw,route

    def confirm_terminal(self,tenant,delivery_id,request,receipt,fault=lambda point:None):
        with self.tx():
            row=self.outbox(tenant,delivery_id);route=self.route(row,live=False);stored=self.terminal(tenant,delivery_id)
            if stored is None:raise Rejected('TERMINAL_NOT_PREPARED')
            raw=self.vault.open('terminal-control',(tenant,delivery_id),stored['control']);self.validate_control_binding(raw,row,route)
            ack=self.parse_receipt(receipt,request,raw,self.namespace,route)
            self.validate_receipt_against_ack(row,ack,route)
            if stored['state']=='CONFIRMED':
                prior=decode(self.vault.open('terminal-receipt',(tenant,delivery_id),stored['receipt']))
                old=self.parse_receipt(prior['receipt'],prior['request'],raw,self.namespace,route)
                if (old['outcome'],old['event_at'])!=(ack['outcome'],ack['event_at']):raise Rejected('TERMINAL_OUTCOME_CONFLICT')
            else:
                sealed=self.vault.seal('terminal-receipt',(tenant,delivery_id),encode({'request':request,'receipt':receipt}))
                self.db.execute("UPDATE delivery_terminal SET state='CONFIRMED',outcome=?,receipt=? WHERE tenant=? AND id=?",(ack['outcome'],sealed,tenant,delivery_id))
            fault('before_terminal_receipt_commit')
        fault('after_terminal_receipt_commit')
        return 'ACKED' if ack['outcome']=='ACCEPTED' else 'CLOSED'

    def audit(self):
        errors=super().audit()
        for stored in self.db.execute('SELECT * FROM delivery_terminal'):
            row=self.outbox(stored['tenant'],stored['id']);route=self.route(row,live=False)
            raw=self.vault.open('terminal-control',(row['tenant'],row['id']),stored['control']);self.validate_control_binding(raw,row,route)
            if stored['receipt'] is not None:
                prior=decode(self.vault.open('terminal-receipt',(row['tenant'],row['id']),stored['receipt']))
                ack=self.parse_receipt(prior['receipt'],prior['request'],raw,self.namespace,route)
                self.validate_receipt_against_ack(row,ack,route)
                if ack['outcome']!=stored['outcome'] or row['state']=='ACKED' and ack['outcome']!='ACCEPTED':errors.append('TERMINAL_OUTCOME_CONFLICT')
        return errors


class TerminalRecipientInbox(RecipientInbox):
    inbox_schema=INBOX_SCHEMA+CLOSED_SCHEMA
    inbox_profile=PROFILE
    terminal_profile=PROFILE
    receipt_type=RECEIPT_TYPE
    parse_terminal_attempt=staticmethod(parse_terminal_attempt)
    parse_control=staticmethod(parse_control)
    envelope_match_fields=set(BINDINGS)|{'delivery','operation','seq','issued_at','expires_at'}

    def next_sequence(self):
        return self.db.execute('SELECT coalesce(max(seq),0)+1 FROM (SELECT seq FROM inbox UNION ALL SELECT seq FROM inbox_closed)').fetchone()[0]

    def authorize_envelope(self,obj):
        if self.db.execute('SELECT 1 FROM inbox_closed WHERE id=? OR seq=?',(obj['delivery'],obj['seq'])).fetchone():raise Rejected('DELIVERY_CLOSED')

    def accept(self,request,peer,signer,fault=lambda point:None):
        obj=decode(request)
        if type(obj) is dict and obj.get('profile')==self.terminal_profile:return self.close_delivery(request,peer,signer,fault)
        return super().accept(request,peer,signer,fault)

    def close_delivery(self,request,peer,signer,fault=lambda point:None):
        if peer!=self.route['sender_cert']:raise Rejected('UNAUTHORIZED_GATEWAY')
        if public(signer)!=self.route['receiver_key']:raise Rejected('WRONG_RECIPIENT_SIGNER')
        req=self.parse_terminal_attempt(request);raw=req['terminal'];obj=self.parse_control(raw,self.deployment,self.route)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.begin_transaction_guard()
            now=self.clock()
            if type(now) is not int or not 0<=now<=2**62 or now<self.db.execute('SELECT observed FROM inbox_clock').fetchone()[0]:raise Rejected('INBOX_CLOCK_ROLLBACK')
            self.db.execute('UPDATE inbox_clock SET observed=?',(now,));self.db.execute('SAVEPOINT business')
            try:
                if now<obj['expires_at']:raise Rejected('TERMINAL_NOT_EXPIRED')
                existing=self.db.execute('SELECT * FROM inbox WHERE id=?',(obj['delivery'],)).fetchone()
                closed=self.db.execute('SELECT * FROM inbox_closed WHERE id=?',(obj['delivery'],)).fetchone()
                if existing and closed:raise Rejected('INBOX_TERMINAL_CONFLICT')
                if existing:
                    envelope=self.vault.open('inbox-envelope',(self.deployment,obj['tenant'],obj['delivery']),existing['envelope'])
                    delivered=self.parse_envelope(envelope,self.deployment,self.route)
                    if (hashlib.sha256(envelope).digest()!=obj['envelope_hash'] or
                        any(delivered[k]!=obj[k] for k in self.envelope_match_fields) or existing['seq']!=obj['seq']):raise Rejected('TERMINAL_DELIVERY_CONFLICT')
                    outcome='ACCEPTED';event_at=existing['accepted_at']
                elif closed:
                    old=self.vault.open('inbox-closed',(self.deployment,obj['tenant'],obj['delivery']),closed['control'])
                    if old!=raw or closed['seq']!=obj['seq']:raise Rejected('TERMINAL_DELIVERY_CONFLICT')
                    outcome='CLOSED';event_at=closed['closed_at']
                else:
                    if obj['seq']!=self.next_sequence():raise Rejected('INBOX_ORDER')
                    sealed=self.vault.seal('inbox-closed',(self.deployment,obj['tenant'],obj['delivery']),raw)
                    self.db.execute('INSERT INTO inbox_closed VALUES(?,?,?,?)',(obj['delivery'],obj['seq'],sealed,now))
                    outcome='CLOSED';event_at=now
                fault('before_inbox_terminal_commit')
            except Rejected:
                self.db.execute('ROLLBACK TO business');self.db.execute('RELEASE business');self.commit_inbox_transaction();raise
            self.db.execute('RELEASE business');self.commit_inbox_transaction()
        except BaseException:self.db.rollback();raise
        fault('after_inbox_terminal_commit')
        ack=dict(profile=self.terminal_profile,deployment=self.deployment,tenant=obj['tenant'],delivery=obj['delivery'],seq=obj['seq'],
            terminal_hash=hashlib.sha256(raw).digest(),envelope_hash=obj['envelope_hash'],challenge=req['challenge'],
            request_hash=hashlib.sha256(request).digest(),receiver_cert=self.route['receiver_cert'],outcome=outcome,event_at=event_at)
        return sign1(encode(ack),self.route['receiver_kid'],signer,self.receipt_type)


ENVELOPE_MATCH_FIELDS=set(BINDINGS)|{'delivery','operation','seq','issued_at','expires_at'}


class TerminalDeliverySender(DeliverySender):
    terminal_attempt=staticmethod(terminal_attempt)
    def reconcile(self,ledger,tenant,delivery_id,fault=lambda point:None):
        prepared=ledger.prepare_terminal(tenant,delivery_id,self.signer,fault)
        if prepared is None:return ledger.delivery_status(tenant,delivery_id)
        raw,route=prepared;request=self.terminal_attempt(raw,secrets.token_bytes(32))
        # Reuses mTLS/hostname/exact certificate pin checks. No envelope/result
        # bytes are sent; only this signed descriptor and a fresh challenge.
        fault('before_terminal_network_send');receipt=self.exchange(request,route);fault('after_terminal_receipt_receive')
        return ledger.confirm_terminal(tenant,delivery_id,request,receipt,fault)
