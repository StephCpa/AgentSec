"""Signed, certificate-bound public journal over ordered publication.

Reference API. Trusted scheduler/management and arbitrary Python stay outside
this public surface. Physical/error availability refinement is not proved.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3

from ordered_publication import OrderedPublicationSender
from ledger import Rejected
from public_input import validate_public_payload,validate_public_response_body
from wire import encode,decode,inspect_sign1,verify_sign1,sign1,identifier
from delivery_transport import public
from witness_transport import TLSWitnessedLedger

PROFILE='agent-public-gateway-v1'
REQUEST_TYPE='AgentPublicRequestV1'
RESPONSE_TYPE='AgentPublicResponseV1'
MAX_FRAME=8192
METHODS={'CHALLENGE','SUBMIT','CONTROL','POLL','FINAL'}
FIELDS={'profile','deployment','tenant','domain','kid','actor','request_id','issued_at','expires_at','method','payload'}
SCHEMA='''
CREATE TABLE gw_meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), kid BLOB NOT NULL,
 public_key BLOB NOT NULL, certificate BLOB NOT NULL
);
CREATE TABLE gw_domains (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL, paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN (0,1)),
 PRIMARY KEY(tenant,domain_id), FOREIGN KEY(tenant,domain_id) REFERENCES privacy_domains(tenant,id)
);
CREATE TABLE gw_principals (
 tenant TEXT NOT NULL, kid BLOB NOT NULL, domain_id TEXT NOT NULL, certificate BLOB NOT NULL,
 rights BLOB NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 PRIMARY KEY(tenant,kid,domain_id), FOREIGN KEY(tenant,kid) REFERENCES signing_keys(tenant,kid),
 FOREIGN KEY(tenant,domain_id) REFERENCES gw_domains(tenant,domain_id)
);
CREATE TABLE gw_requests (
 tenant TEXT NOT NULL, domain_id TEXT NOT NULL, seq INTEGER NOT NULL CHECK(seq>0),
 kid BLOB NOT NULL, request_id BLOB NOT NULL, request BLOB NOT NULL,
 peer BLOB NOT NULL, response BLOB NOT NULL, effect BLOB NOT NULL,
 PRIMARY KEY(tenant,domain_id,seq), UNIQUE(tenant,kid,request_id),
 FOREIGN KEY(tenant,kid,domain_id) REFERENCES gw_principals(tenant,kid,domain_id)
);
'''
_tmp=sqlite3.connect(':memory:');_tmp.executescript(SCHEMA)
TRUSTED_SCHEMA=dict(_tmp.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"));_tmp.close()

# Only pre-private-execution input/policy denials may become durable REJECTED.
# Unknown/integrity/storage failures abort and are never reported as success or
# ordinary policy rejection. Their transport observations remain OBS-4/OBS-6.
PUBLIC_DENIALS={
 # Explicit public registry, authorization, request identity and budget checks.
 'UNAUTHORIZED','BUDGET_EXHAUSTED','REVOKED','EXPIRED','ACTION_CONFLICT',
 'KEY_INACTIVE','KEY_ROLE_OR_ACTOR','KEY_BINDING','UNKNOWN_KEY',
 'ACTION_EXPIRED_OR_EARLY','INVALID_SIGNATURE','UNPINNED_ROOT',
 'CREDENTIAL_INACTIVE','CREDENTIAL_REVOKED','ANCESTOR_KEY_INACTIVE',
 'CREDENTIAL_ID_CONFLICT','CREDENTIAL_IDENTITY','CHAIN_NAMESPACE',
 'ISSUER_KEY_BINDING','ROOT_BINDING','ROOT_SCOPE','ROOT_CAP',
 'CHAIN_PARENT_BINDING','ATTENUATION_BOUNDS','ATTENUATION_SCOPE',
 'CATALOG_ATTENUATION','ACCOUNT_REBIND','LEAF_BINDING','ACTION_OUTSIDE_WINDOW',
 'ACTION_OUTSIDE_LEAF','ACTION_CATALOG_OUTSIDE_LEAF',
 'PROFILE_MISMATCH','COST_LIMIT_MISMATCH','SIGNED_CAPACITY_MISMATCH',
 'SIGNED_CATALOG_MISMATCH','UNAUTHORIZED_DOMAIN','UNKNOWN_CATALOG',
 'UNKNOWN_SNAPSHOT','SNAPSHOT_MECHANISM_MISMATCH','SNAPSHOT_CATALOG_MISMATCH',
 'CHALLENGE_EXPIRED','CHALLENGE_BINDING','PROOF_REPLAY','WRONG_AUDIENCE',
 'PROOF_ACTION_BINDING','PROOF_PROFILE_BINDING','WIRE_ACTION_CONFLICT',
 'ALREADY_PUBLISHED','GW_PAYLOAD','GW_SCOPE','GW_CURSOR',
 'PUBLICATION_ROUTE_BINDING','V2_ROUTE_REVOKED','PUBLICATION_BINDING_REQUIRED'
}


def parse_request(raw):
    if type(raw) is not bytes or len(raw)>MAX_FRAME:raise Rejected('GW_FRAME')
    kid,payload,_,_=inspect_sign1(raw,REQUEST_TYPE);obj=decode(payload)
    if type(obj) is not dict or set(obj)!=FIELDS or obj['profile']!=PROFILE:raise Rejected('GW_SCHEMA')
    for name in ('tenant','domain','actor'):identifier(obj[name])
    if obj['kid']!=kid or type(obj['deployment']) is not bytes or len(obj['deployment'])!=16:raise Rejected('GW_BINDING')
    if type(obj['request_id']) is not bytes or len(obj['request_id'])!=16:raise Rejected('GW_REQUEST_ID')
    if any(type(obj[k]) is not int or not 0<=obj[k]<2**62 for k in ('issued_at','expires_at')):raise Rejected('GW_WINDOW')
    if not 0<obj['expires_at']-obj['issued_at']<=60:raise Rejected('GW_WINDOW')
    if type(obj['method']) is not str or obj['method'] not in METHODS or type(obj['payload']) is not dict:raise Rejected('GW_SCHEMA')
    return obj


def request(obj,key):return sign1(encode(obj),obj['kid'],key,REQUEST_TYPE)


def response(raw,request_wire,public_key,kid,deployment):
    actual,obj=verify_sign1(raw,public_key,RESPONSE_TYPE)
    if (actual!=kid or type(obj) is not dict or set(obj)!={'profile','deployment','request_hash','status','body','sequence'} or
        obj['profile']!=PROFILE or obj['deployment']!=deployment or obj['request_hash']!=hashlib.sha256(request_wire).digest() or
        type(obj['sequence']) is not int or obj['sequence']<0 or type(obj['body']) is not dict or type(obj['status']) is not str or
        obj['status'] not in {'CHALLENGE','RECORDED','CONTROL_RECORDED','POLL','FINAL','REJECTED'}):raise Rejected('GW_RESPONSE')
    validate_public_response_body(obj['status'],obj['body'])
    return obj


class PublicGatewayLedger(OrderedPublicationSender):
    storage_profile='witnessed-public-gateway-v1'

    def __init__(self,path,*args,**kwargs):
        self._gw_initial=not Path(path).exists() or not Path(path).stat().st_size
        self._gw_join=False
        super().__init__(path,*args,**kwargs)

    @classmethod
    def new_replica(cls,path,**kwargs):
        obj=super().new_replica(path,**kwargs);obj.db.executescript(SCHEMA);obj._gw_initial=False
        obj.check_storage_profile();return obj

    def check_storage_profile(self,allow_empty=False):
        super().check_storage_profile(allow_empty=allow_empty)
        present=dict(self.db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name GLOB 'gw_*'"))
        if not present and self._gw_initial:return
        if present!=TRUSTED_SCHEMA:raise Rejected('GW_SCHEMA_MISMATCH')

    @contextmanager
    def tx(self):
        if self._gw_join:
            if not self.db.in_transaction or self._tx_time is None or self._base_anchor is None:raise Rejected('GW_TRANSACTION_REQUIRED')
            # Exactly one outer guarded transaction; the public dispatcher owns
            # rollback of all nested business writes with a dedicated savepoint.
            yield
        else:
            with super().tx():yield

    def configure_gateway(self,kid,key,certificate):
        if type(kid) is not bytes or not 1<=len(kid)<=32 or type(key) is not bytes or len(key)!=32 or type(certificate) is not bytes or len(certificate)!=32:raise Rejected('GW_CONFIG')
        with self.tx():
            if self.db.execute('SELECT 1 FROM gw_meta').fetchone():raise Rejected('GW_CONFIG_IMMUTABLE')
            self.db.execute('INSERT INTO gw_meta VALUES(1,?,?,?)',(kid,key,certificate))

    def gateway_config(self):
        row=self.db.execute('SELECT * FROM gw_meta WHERE singleton=1').fetchone()
        if row is None:raise Rejected('GW_NOT_CONFIGURED')
        return row

    def enroll_public(self,tenant,kid,domain,certificate,rights):
        """Trusted immutable enrollment, not a public management API."""
        allowed={'challenge','submit','poll','final','cancel','revoke','pause','resume'}
        if type(rights) is not list or not rights or len(rights)!=len(set(rights)) or any(type(x) is not str or x not in allowed for x in rights):raise Rejected('GW_RIGHTS')
        if type(certificate) is not bytes or len(certificate)!=32:raise Rejected('GW_CERTIFICATE')
        with self.tx():
            self.key(tenant,kid);self.domain(tenant,domain)
            self.db.execute('INSERT OR IGNORE INTO gw_domains(tenant,domain_id) VALUES(?,?)',(tenant,domain))
            if self.db.execute('SELECT 1 FROM gw_principals WHERE tenant=? AND kid=? AND domain_id=?',(tenant,kid,domain)).fetchone():raise Rejected('GW_PRINCIPAL_IMMUTABLE')
            self.db.execute('INSERT INTO gw_principals VALUES(?,?,?,?,?,0)',(tenant,kid,domain,certificate,encode(sorted(rights))))

    def revoke_public(self,tenant,kid,domain):
        with self.tx():
            if self.db.execute('UPDATE gw_principals SET revoked=1 WHERE tenant=? AND kid=? AND domain_id=?',(tenant,kid,domain)).rowcount!=1:raise Rejected('GW_PRINCIPAL')

    def issue_challenge(self,*args,**kwargs):
        if not self._gw_join:raise Rejected('PUBLIC_GATEWAY_REQUIRED')
        return super().issue_challenge(*args,**kwargs)

    def register_delegated(self,*args,**kwargs):
        if not self._gw_join:raise Rejected('PUBLIC_GATEWAY_REQUIRED')
        return super().register_delegated(*args,**kwargs)

    def command(self,tenant,domain_id,command,tick):
        # The trusted scheduler advances work with noop only. All externally
        # meaningful controls must carry a public request and journal record.
        if command!={'kind':'noop'}:raise Rejected('PUBLIC_GATEWAY_REQUIRED')
        return super().command(tenant,domain_id,command,tick)

    def work_step(self,tenant,domain_id,fault):
        row=self.db.execute('SELECT paused FROM gw_domains WHERE tenant=? AND domain_id=?',(tenant,domain_id)).fetchone()
        if row is not None and row[0]:return
        return super().work_step(tenant,domain_id,fault)

    def _authenticate(self,raw,peer):
        obj=parse_request(raw)
        if obj['deployment']!=self.vault.deployment_id:raise Rejected('GW_DEPLOYMENT')
        key=self.key(obj['tenant'],obj['kid'])
        if key['actor']!=obj['actor'] or not self.key_active(key):raise Rejected('GW_PRINCIPAL')
        verify_sign1(raw,key['public_key'],REQUEST_TYPE)
        principal=self.db.execute('SELECT * FROM gw_principals WHERE tenant=? AND kid=? AND domain_id=?',(obj['tenant'],obj['kid'],obj['domain'])).fetchone()
        if principal is None or principal['revoked'] or principal['certificate']!=peer:raise Rejected('GW_PRINCIPAL')
        return obj,decode(principal['rights'])

    def _reply(self,raw,status,body,seq,signer):
        validate_public_response_body(status,body)
        config=self.gateway_config()
        if public(signer)!=config['public_key']:raise Rejected('GW_SERVER_KEY')
        out=sign1(encode(dict(profile=PROFILE,deployment=self.vault.deployment_id,request_hash=hashlib.sha256(raw).digest(),status=status,body=body,sequence=seq)),config['kid'],signer,RESPONSE_TYPE)
        if len(out)>MAX_FRAME:raise Rejected('GW_RESPONSE_SIZE')
        return out

    def _own_job(self,obj,oid):
        identifier(oid)
        row=self.db.execute('''SELECT j.seq,j.domain_id,o.actor FROM jobs j JOIN operations o
            ON j.tenant=o.tenant AND j.operation_id=o.id WHERE j.tenant=? AND j.operation_id=?''',(obj['tenant'],oid)).fetchone()
        if row is None or row['actor']!=obj['actor'] or row['domain_id']!=obj['domain']:raise Rejected('GW_SCOPE')
        return row

    def _dispatch(self,obj,rights):
        method=obj['method'];payload=obj['payload'];tenant=obj['tenant'];domain=obj['domain']
        validate_public_payload(method,payload)
        required=payload.get('kind') if method=='CONTROL' else method.lower()
        if type(required) is not str or required not in rights:raise Rejected('GW_SCOPE')
        if method=='CHALLENGE':
            if payload:raise Rejected('GW_PAYLOAD')
            body=self.issue_challenge(tenant,obj['kid']);return 'CHALLENGE',body,dict(challenge=body['challenge'])
        if method=='SUBMIT':
            if set(payload)!={'action','proof','chain'} or type(payload['action']) is not bytes or type(payload['proof']) is not bytes or type(payload['chain']) is not list:raise Rejected('GW_PAYLOAD')
            action=self.parse_wire_action(payload['action'])
            if any(action[k]!=obj[k] for k in ('tenant','kid','actor','domain')):raise Rejected('GW_SCOPE')
            self.register_delegated(payload['action'],payload['proof'],payload['chain'])
            job=self._own_job(obj,action['operation'])
            body=dict(operation=action['operation'],sequence=job['seq'])
            return 'RECORDED',body,dict(operation=action['operation'])
        if method=='POLL':
            if set(payload)!={'operation'}:raise Rejected('GW_PAYLOAD')
            job=self._own_job(obj,payload['operation'])
            body=dict(operation=payload['operation'],sequence=job['seq'],publication='UNPUBLISHED',final='UNFINALIZED')
            decision=self.db.execute('SELECT kind FROM pub_decisions WHERE tenant=? AND domain_id=? AND seq=?',(tenant,domain,job['seq'])).fetchone()
            if decision is not None:body['publication']=decision['kind']
            event=self.db.execute('SELECT outcome FROM final_events WHERE tenant=? AND domain_id=? AND seq=?',(tenant,domain,job['seq'])).fetchone()
            if event is not None:body['final']=event['outcome']
            return 'POLL',body,{}
        if method=='FINAL':
            if set(payload)!={'cursor','limit'} or type(payload['cursor']) is not int or type(payload['limit']) is not int or not 1<=payload['limit']<=16:raise Rejected('GW_PAYLOAD')
            cursor=payload['cursor'];front=self.final_frontier(tenant,domain)
            if not 0<=cursor<=front:raise Rejected('GW_CURSOR')
            rows=self.db.execute('''SELECT f.seq,f.outcome,p.operation_id FROM final_events f JOIN pub_decisions p
                ON f.tenant=p.tenant AND f.domain_id=p.domain_id AND f.seq=p.seq
                WHERE f.tenant=? AND f.domain_id=? AND f.seq>? ORDER BY f.seq LIMIT ?''',(tenant,domain,cursor,payload['limit'])).fetchall()
            events=[dict(sequence=x['seq'],outcome=x['outcome'],operation=x['operation_id']) for x in rows]
            return 'FINAL',dict(events=events,cursor=events[-1]['sequence'] if events else cursor),{}
        if method=='CONTROL':
            kind=payload.get('kind')
            if kind in ('pause','resume'):
                if set(payload)!={'kind'}:raise Rejected('GW_PAYLOAD')
                self.db.execute('UPDATE gw_domains SET paused=? WHERE tenant=? AND domain_id=?',(int(kind=='pause'),tenant,domain));cmd=dict(kind=kind)
            elif kind=='cancel':
                if set(payload)!={'kind','operation'}:raise Rejected('GW_PAYLOAD')
                oid=payload['operation'];self._own_job(obj,oid)
                row=self.db.execute('SELECT state FROM operations WHERE tenant=? AND id=?',(tenant,oid)).fetchone()
                published=self.db.execute('SELECT publication FROM jobs WHERE tenant=? AND operation_id=?',(tenant,oid)).fetchone()[0]
                if published is not None:raise Rejected('ALREADY_PUBLISHED')
                if row['state'] in ('RESERVED','STARTED'):
                    before=row['state']=='RESERVED';self.move_charges(tenant,oid,'RETURNED' if before else 'SPENT')
                    self.db.execute('UPDATE operations SET state=? WHERE tenant=? AND id=?',('CANCELED' if before else 'BURNED',tenant,oid))
                self.db.execute('UPDATE jobs SET suppressed=1 WHERE tenant=? AND operation_id=?',(tenant,oid));cmd=dict(kind=kind,operation=oid,actor=obj['actor'])
            elif kind=='revoke':
                if set(payload)!={'kind','root'}:raise Rejected('GW_PAYLOAD')
                identifier(payload['root']);root=self.root(tenant,payload['root'])
                binding=self.binding(tenant,payload['root'])
                if root['actor']!=obj['actor'] or binding['domain_id']!=domain:raise Rejected('GW_SCOPE')
                self.db.execute('UPDATE roots SET revoked=1 WHERE tenant=? AND id=?',(tenant,payload['root']));cmd=dict(kind=kind,root=payload['root'],actor=obj['actor'])
            else:raise Rejected('GW_PAYLOAD')
            self.db.execute('INSERT OR IGNORE INTO schedulers(tenant,domain_id) VALUES(?,?)',(tenant,domain))
            tick=self.db.execute('SELECT tick FROM schedulers WHERE tenant=? AND domain_id=?',(tenant,domain)).fetchone()[0]
            subject=json.dumps(cmd,sort_keys=True,separators=(',',':'));self.append_event(tenant,domain,tick,'CONTROL_ACK',subject)
            seq=self.db.execute('SELECT max(event_seq) FROM publication_events WHERE tenant=? AND domain_id=?',(tenant,domain)).fetchone()[0]
            return 'CONTROL_RECORDED',dict(payload),dict(event_seq=seq,tick=tick,subject=subject)
        raise Rejected('GW_PAYLOAD')

    def handle_public(self,raw,peer,signer,fault=lambda point:None):
        if self._gw_join:raise Rejected('GW_REENTRANT')
        if type(raw) is not bytes or len(raw)>MAX_FRAME or type(peer) is not bytes or len(peer)!=32:raise Rejected('GW_FRAME')
        with self.tx():
            if public(signer)!=self.gateway_config()['public_key']:raise Rejected('GW_SERVER_KEY')
            # Auth failures receive one generic signed rejection, with no
            # operation access or durable public request identity allocated.
            try:obj,rights=self._authenticate(raw,peer)
            except Rejected:return self._reply(raw,'REJECTED',{},0,signer)
            old=self.db.execute('SELECT * FROM gw_requests WHERE tenant=? AND kid=? AND request_id=?',(obj['tenant'],obj['kid'],obj['request_id'])).fetchone()
            if old is not None:
                if old['request']!=raw:return self._reply(raw,'REJECTED',{},0,signer)
                # Authentication is live, but a committed exact retry may be
                # older than its creation window. Never re-execute its proof.
                return old['response']
            if not obj['issued_at']<=self.now()<obj['expires_at']:return self._reply(raw,'REJECTED',{},0,signer)
            self.db.execute('SAVEPOINT public_dispatch');self._gw_join=True
            try:
                try:status,body,effect=self._dispatch(obj,rights)
                except Rejected as exc:
                    if str(exc) not in PUBLIC_DENIALS:raise
                    self.db.execute('ROLLBACK TO public_dispatch');status,body,effect='REJECTED',{},{}
            finally:self._gw_join=False
            self.db.execute('RELEASE public_dispatch')
            fault('after_public_effect')
            seq=self.db.execute('SELECT coalesce(max(seq),0)+1 FROM gw_requests WHERE tenant=? AND domain_id=?',(obj['tenant'],obj['domain'])).fetchone()[0]
            reply=self._reply(raw,status,body,seq,signer)
            self.db.execute('INSERT INTO gw_requests VALUES(?,?,?,?,?,?,?,?,?)',(obj['tenant'],obj['domain'],seq,obj['kid'],obj['request_id'],raw,peer,reply,encode(effect)))
            fault('after_public_journal_write')
        fault('after_public_request_commit');return reply

    def audit_gateway(self):
        rows=list(self.db.execute('SELECT * FROM gw_requests ORDER BY tenant,domain_id,seq'))
        if not rows:
            if any(self.db.execute('SELECT 1 FROM '+table).fetchone() for table in ('signed_actions','challenges','used_proofs')) or self.db.execute('SELECT 1 FROM gw_domains WHERE paused!=0').fetchone() or self.db.execute("SELECT 1 FROM publication_events WHERE kind='CONTROL_ACK' AND subject!=?",(json.dumps({'kind':'noop'},sort_keys=True,separators=(',',':')),)).fetchone():raise Rejected('GW_AUDIT_FAILED')
            return
        config=self.gateway_config();counts={};submitted=set();challenges=set();proofs=set();paused={};controls=set()
        for row in rows:
            obj=parse_request(row['request']);key=self.key(row['tenant'],row['kid']);verify_sign1(row['request'],key['public_key'],REQUEST_TYPE)
            if (obj['deployment']!=self.vault.deployment_id or obj['tenant']!=row['tenant'] or obj['domain']!=row['domain_id'] or obj['kid']!=row['kid'] or obj['request_id']!=row['request_id'] or obj['actor']!=key['actor']):raise Rejected('GW_AUDIT_FAILED')
            principal=self.db.execute('SELECT * FROM gw_principals WHERE tenant=? AND kid=? AND domain_id=?',(row['tenant'],row['kid'],row['domain_id'])).fetchone()
            if principal is None or principal['certificate']!=row['peer']:raise Rejected('GW_AUDIT_FAILED')
            domain=(row['tenant'],row['domain_id']);counts[domain]=counts.get(domain,0)+1
            reply=response(row['response'],row['request'],config['public_key'],config['kid'],self.vault.deployment_id)
            if row['seq']!=counts[domain] or reply['sequence']!=row['seq']:raise Rejected('GW_AUDIT_FAILED')
            body=reply['body'];effect=decode(row['effect']);status=reply['status'];method=obj['method']
            if status=='REJECTED':
                if body or effect:raise Rejected('GW_AUDIT_FAILED')
                continue
            if status!={'CHALLENGE':'CHALLENGE','SUBMIT':'RECORDED','POLL':'POLL','FINAL':'FINAL','CONTROL':'CONTROL_RECORDED'}[method]:raise Rejected('GW_AUDIT_FAILED')
            right=obj['payload'].get('kind') if method=='CONTROL' else method.lower()
            if right not in decode(principal['rights']):raise Rejected('GW_AUDIT_FAILED')
            if method=='CHALLENGE':
                if set(body)!={'challenge','challenge_expiry','audience'} or effect!={'challenge':body['challenge']}:raise Rejected('GW_AUDIT_FAILED')
                ch=self.db.execute('SELECT * FROM challenges WHERE tenant=? AND nonce=?',(row['tenant'],body['challenge'])).fetchone()
                if ch is None or ch['kid']!=row['kid'] or ch['expires_at']!=body['challenge_expiry'] or ch['audience']!=body['audience']:raise Rejected('GW_AUDIT_FAILED')
                challenges.add((row['tenant'],body['challenge']))
            elif method=='SUBMIT':
                action=self.parse_wire_action(obj['payload']['action']);job=self._own_job(obj,action['operation'])
                stored=self.db.execute('SELECT action FROM signed_actions WHERE tenant=? AND operation_id=?',(row['tenant'],action['operation'])).fetchone()
                if body!={'operation':action['operation'],'sequence':job['seq']} or effect!={'operation':action['operation']} or stored is None or stored[0]!=obj['payload']['action']:raise Rejected('GW_AUDIT_FAILED')
                proof=self.parse_wire_proof(decode(inspect_sign1(obj['payload']['proof'])[1]))
                used=self.db.execute('SELECT operation_id,proof_wire FROM used_proofs WHERE tenant=? AND proof_id=?',(row['tenant'],proof['proof_id'])).fetchone()
                if used is None or tuple(used)!=(action['operation'],obj['payload']['proof']):raise Rejected('GW_AUDIT_FAILED')
                proofs.add((row['tenant'],proof['proof_id']))
                submitted.add((row['tenant'],action['operation']))
            elif method=='CONTROL':
                if body!=obj['payload'] or set(effect)!={'event_seq','tick','subject'}:raise Rejected('GW_AUDIT_FAILED')
                controls.add((row['tenant'],row['domain_id'],effect['event_seq']))
                event=self.db.execute('SELECT tick,kind,subject FROM publication_events WHERE tenant=? AND domain_id=? AND event_seq=?',(row['tenant'],row['domain_id'],effect['event_seq'])).fetchone()
                cmd=dict(body)
                if cmd['kind'] in ('pause','resume'):paused[domain]=int(cmd['kind']=='pause')
                if cmd['kind'] in ('cancel','revoke'):cmd['actor']=obj['actor']
                if effect['subject']!=json.dumps(cmd,sort_keys=True,separators=(',',':')) or event is None or tuple(event)!=(effect['tick'],'CONTROL_ACK',effect['subject']):raise Rejected('GW_AUDIT_FAILED')
            elif method=='POLL':
                job=self._own_job(obj,obj['payload']['operation'])
                if (set(body)!={'operation','sequence','publication','final'} or body['operation']!=obj['payload']['operation'] or body['sequence']!=job['seq'] or body['publication'] not in ('UNPUBLISHED','ADMITTED','WITHHELD') or body['final'] not in ('UNFINALIZED','WITHHELD','ACCEPTED','CLOSED') or effect):raise Rejected('GW_AUDIT_FAILED')
                decision=self.db.execute('SELECT kind FROM pub_decisions WHERE tenant=? AND domain_id=? AND seq=?',(row['tenant'],row['domain_id'],job['seq'])).fetchone()
                final=self.db.execute('SELECT outcome FROM final_events WHERE tenant=? AND domain_id=? AND seq=?',(row['tenant'],row['domain_id'],job['seq'])).fetchone()
                if body['publication']!='UNPUBLISHED' and (decision is None or decision[0]!=body['publication']):raise Rejected('GW_AUDIT_FAILED')
                if body['final']!='UNFINALIZED' and (final is None or final[0]!=body['final'] or body['publication']=='UNPUBLISHED'):raise Rejected('GW_AUDIT_FAILED')
            elif method=='FINAL':
                if set(body)!={'events','cursor'} or effect or type(body['events']) is not list or len(body['events'])>obj['payload']['limit']:raise Rejected('GW_AUDIT_FAILED')
                cursor=obj['payload']['cursor']
                for event in body['events']:
                    cursor+=1
                    found=self.db.execute('''SELECT f.outcome,p.operation_id FROM final_events f JOIN pub_decisions p ON f.tenant=p.tenant AND f.domain_id=p.domain_id AND f.seq=p.seq WHERE f.tenant=? AND f.domain_id=? AND f.seq=?''',(row['tenant'],row['domain_id'],cursor)).fetchone()
                    if found is None or event!=dict(sequence=cursor,outcome=found[0],operation=found[1]):raise Rejected('GW_AUDIT_FAILED')
                if body['cursor']!=cursor:raise Rejected('GW_AUDIT_FAILED')
        if submitted!={tuple(x) for x in self.db.execute('SELECT tenant,operation_id FROM signed_actions')} or challenges!={tuple(x) for x in self.db.execute('SELECT tenant,nonce FROM challenges')} or proofs!={tuple(x) for x in self.db.execute('SELECT tenant,proof_id FROM used_proofs')}:raise Rejected('GW_AUDIT_FAILED')
        recorded={tuple(x) for x in self.db.execute("SELECT tenant,domain_id,event_seq FROM publication_events WHERE kind='CONTROL_ACK' AND subject!=?",(json.dumps({'kind':'noop'},sort_keys=True,separators=(',',':')),))}
        if controls!=recorded:raise Rejected('GW_AUDIT_FAILED')
        for row in self.db.execute('SELECT tenant,domain_id,paused FROM gw_domains'):
            if row['paused']!=paused.get((row['tenant'],row['domain_id']),0):raise Rejected('GW_AUDIT_FAILED')

    def audit(self):
        errors=super().audit();self.audit_gateway();return errors

    def recover_from_witness(self,fault=lambda point:None):
        def checked(point):
            if point=='before_recovery_commit':self.audit_gateway()
            fault(point)
        return super().recover_from_witness(checked)


class TLSPublicGatewayLedger(TLSWitnessedLedger,PublicGatewayLedger):
    storage_profile='mtls-public-gateway-v1'
