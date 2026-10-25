"""Signed direct-root count admission; synthetic reference, no delegation chain.

Public keys are installed by a simulated trusted administrator. This verifies
possession and registered roles, not real workload provenance, TLS or attestation.
A consumed challenge never authenticates a retry; retry obtains a new challenge.
"""
import hashlib
import json
import secrets
from scheduled_ledger import ScheduledLedger, Rejected
from dp_ledger import MECHANISM, PROFILE, EPSILON_COST, DELTA_COST
from wire import parse_action, parse_proof, inspect_sign1, verify_sign1, identifier

SCHEMA='''
CREATE TABLE IF NOT EXISTS signing_keys (
 tenant TEXT NOT NULL, kid BLOB NOT NULL, actor TEXT NOT NULL,
 role TEXT NOT NULL, public_key BLOB NOT NULL, not_before INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant,kid)
);
CREATE TABLE IF NOT EXISTS challenges (
 tenant TEXT NOT NULL, nonce BLOB NOT NULL, kid BLOB NOT NULL,
 audience TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant,nonce), FOREIGN KEY(tenant,kid) REFERENCES signing_keys(tenant,kid)
);
CREATE TABLE IF NOT EXISTS used_proofs (
 tenant TEXT NOT NULL, proof_id BLOB NOT NULL, nonce BLOB NOT NULL,
 operation_id TEXT NOT NULL, proof_wire BLOB NOT NULL,
 PRIMARY KEY(tenant,proof_id), FOREIGN KEY(tenant,nonce) REFERENCES challenges(tenant,nonce)
);
CREATE TABLE IF NOT EXISTS signed_actions (
 tenant TEXT NOT NULL, operation_id TEXT NOT NULL, action BLOB NOT NULL,
 digest BLOB NOT NULL, kid BLOB NOT NULL,
 PRIMARY KEY(tenant,operation_id),
 FOREIGN KEY(tenant,operation_id) REFERENCES operations(tenant,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(tenant,kid) REFERENCES signing_keys(tenant,kid)
);
'''
AUDIENCE='count-gateway-v1'


class SignedLedger(ScheduledLedger):
    accepted_profile='count-direct-v1'
    audience=AUDIENCE
    proof_object_type='CountActionProof'
    supported_mechanisms=(MECHANISM,)
    parse_wire_action=staticmethod(parse_action)
    parse_wire_proof=staticmethod(parse_proof)
    @classmethod
    def create(cls,path,clock=None,**kwargs):
        obj=super().create(path,clock=clock,**kwargs); obj.db.executescript(SCHEMA); return obj

    def install_key(self,tenant,kid,actor,role,public_key,not_before=0,expires_at=2**62):
        # Trusted bootstrap; immutable key records, no implicit cross-role reuse.
        identifier(tenant); identifier(actor)
        if type(kid) is not bytes or not 1<=len(kid)<=32 or type(public_key) is not bytes or len(public_key)!=32:
            raise Rejected('INVALID_KEY')
        if role not in ('instance','root','permit','receipt'): raise Rejected('INVALID_KEY_ROLE')
        if type(not_before) is not int or type(expires_at) is not int or not 0<=not_before<expires_at<=2**62:
            raise Rejected('INVALID_KEY_WINDOW')
        with self.tx():
            aliases=self.db.execute('SELECT actor,role FROM signing_keys WHERE tenant=? AND public_key=?',
                                    (tenant,public_key)).fetchall()
            if any(row['actor']!=actor or row['role']!=role for row in aliases):
                raise Rejected('KEY_ROLE_REUSE')
            self.db.execute('INSERT INTO signing_keys(tenant,kid,actor,role,public_key,not_before,expires_at) VALUES(?,?,?,?,?,?,?)',
                            (tenant,kid,actor,role,public_key,not_before,expires_at))

    def key(self,tenant,kid):
        row=self.db.execute('SELECT * FROM signing_keys WHERE tenant=? AND kid=?',(tenant,kid)).fetchone()
        if row is None: raise Rejected('UNKNOWN_KEY')
        return row

    def key_active(self,key):
        return not key['revoked'] and key['not_before']<=self.now()<key['expires_at']

    def revoke_key(self,tenant,kid):
        # Trusted key registry management; identity provenance is out of scope.
        with self.tx():
            self.key(tenant,kid)
            self.db.execute('UPDATE signing_keys SET revoked=1 WHERE tenant=? AND kid=?',(tenant,kid))

    def issue_challenge(self,tenant,kid,ttl=60):
        if type(ttl) is not int or not 0<ttl<=60: raise Rejected('INVALID_TTL')
        with self.tx():
            key=self.key(tenant,kid)
            if not self.key_active(key): raise Rejected('KEY_INACTIVE')
            nonce=secrets.token_bytes(32); expiry=min(self.now()+ttl,key['expires_at'])
            self.db.execute('INSERT INTO challenges(tenant,nonce,kid,audience,expires_at) VALUES(?,?,?,?,?)',
                            (tenant,nonce,kid,self.audience,expiry))
        return {'challenge':nonce,'challenge_expiry':expiry,'audience':self.audience}

    def register_signed(self,raw_action,proof_wire,fault=lambda p:None):
        action=self.parse_wire_action(raw_action)
        # Bounded syntactic validation before SQLite lock; signature and authority
        # validation execute again INSIDE the reservation transaction.
        inspect_sign1(proof_wire)
        if getattr(self,'_signed_request',None) is not None: raise Rejected('REENTRANT_REGISTRATION')
        self._signed_request=(raw_action,proof_wire,fault)
        try:
            receipt=self.reserve_wire_action(action,fault)
            # External wire digest replaces internal harness JSON digest in ACK.
            return {'operation_id':receipt['operation_id'],'action_digest':hashlib.sha256(raw_action).hexdigest(),
                    'registration':'REGISTERED'}
        finally:
            self._signed_request=None

    def reserve_wire_action(self,action,fault):
        return super().reserve_count(action['tenant'],action['operation'],action['root'],action['recipient'],
                                     action['domain'],action['snapshot'],action['actor'],fault)

    def validate_wire_parameters(self,action):
        # Mechanism extension hook; called inside the reservation transaction.
        pass

    def authorize_reservation(self,internal,root):
        ctx=getattr(self,'_signed_request',None)
        if ctx is None: raise Rejected('SIGNATURE_REQUIRED')
        raw,proof_wire,fault=ctx; action=self.parse_wire_action(raw)
        if action['profile']!=self.accepted_profile: raise Rejected('UNSUPPORTED_ACTION_PROFILE')
        kid,_,_,_=inspect_sign1(proof_wire)
        if kid!=action['kid']: raise Rejected('KEY_BINDING')
        key=self.key(action['tenant'],kid)
        if key['role']!='instance' or key['actor']!=action['actor']:
            raise Rejected('KEY_ROLE_OR_ACTOR')
        if not self.key_active(key): raise Rejected('KEY_INACTIVE')
        self.live_root(action['tenant'],action['root'])
        if not action['not_before']<=self.now()<action['deadline']: raise Rejected('ACTION_EXPIRED_OR_EARLY')
        if action['mechanism'] not in self.supported_mechanisms or action['accountant']!=PROFILE: raise Rejected('PROFILE_MISMATCH')
        if (action['epsilon_max'],action['delta_max'])!=(EPSILON_COST,DELTA_COST): raise Rejected('COST_LIMIT_MISMATCH')
        self.validate_wire_parameters(action)
        _,proof=verify_sign1(proof_wire,key['public_key'],self.proof_object_type); proof=self.parse_wire_proof(proof)
        if proof['profile']!=action['profile']: raise Rejected('PROOF_PROFILE_BINDING')
        digest=hashlib.sha256(raw).digest()
        if proof['action_digest']!=digest: raise Rejected('PROOF_ACTION_BINDING')
        if proof['audience']!=self.audience: raise Rejected('WRONG_AUDIENCE')
        challenge=self.db.execute('SELECT * FROM challenges WHERE tenant=? AND nonce=?',
                                  (action['tenant'],proof['challenge'])).fetchone()
        if (challenge is None or challenge['kid']!=kid or challenge['audience']!=self.audience or
            challenge['expires_at']!=proof['challenge_expiry']): raise Rejected('CHALLENGE_BINDING')
        if self.now()>=challenge['expires_at']: raise Rejected('CHALLENGE_EXPIRED')
        if challenge['used'] or self.db.execute('SELECT 1 FROM used_proofs WHERE tenant=? AND proof_id=?',
                                               (action['tenant'],proof['proof_id'])).fetchone(): raise Rejected('PROOF_REPLAY')
        old=self.db.execute('SELECT * FROM signed_actions WHERE tenant=? AND operation_id=?',
                            (action['tenant'],action['operation'])).fetchone()
        if old is not None and old['action']!=raw: raise Rejected('WIRE_ACTION_CONFLICT')
        if old is None:
            if self.db.execute('SELECT 1 FROM operations WHERE tenant=? AND id=?',(action['tenant'],action['operation'])).fetchone():
                raise Rejected('UNSIGNED_EXISTING_OPERATION')
            self.db.execute('INSERT INTO signed_actions VALUES(?,?,?,?,?)',
                            (action['tenant'],action['operation'],raw,digest,kid))
        self.db.execute('UPDATE challenges SET used=1 WHERE tenant=? AND nonce=?',(action['tenant'],proof['challenge']))
        self.db.execute('INSERT INTO used_proofs VALUES(?,?,?,?,?)',
                        (action['tenant'],proof['proof_id'],proof['challenge'],action['operation'],proof_wire))
        fault('after_proof_consumption')

    def authorization_active(self,op):
        if not super().authorization_active(op): return False
        row=self.db.execute('SELECT * FROM signed_actions WHERE tenant=? AND operation_id=?',(op['tenant'],op['id'])).fetchone()
        if row is None: return False
        action=self.parse_wire_action(row['action']); key=self.key(op['tenant'],row['kid'])
        return self.key_active(key) and action['not_before']<=self.now()<action['deadline']

    def authorize_delivery(self,op):
        if not self.authorization_active(op): raise Rejected('ACTION_OR_KEY_INACTIVE')

    def delivery_expiry(self,op,root,now,ttl):
        row=self.db.execute('SELECT * FROM signed_actions WHERE tenant=? AND operation_id=?',(op['tenant'],op['id'])).fetchone()
        action=self.parse_wire_action(row['action']); key=self.key(op['tenant'],row['kid'])
        return min(super().delivery_expiry(op,root,now,ttl),action['deadline'],key['expires_at'])

    def audit(self):
        errors=super().audit()
        for op in self.db.execute('SELECT * FROM operations'):
            row=self.db.execute('SELECT * FROM signed_actions WHERE tenant=? AND operation_id=?',(op['tenant'],op['id'])).fetchone()
            if row is None:
                errors.append('MISSING_SIGNED_ACTION'); continue
            if hashlib.sha256(row['action']).digest()!=row['digest']:
                errors.append('WIRE_DIGEST_BINDING')
            action=self.parse_wire_action(row['action'])
            params=json.loads(op['action'])['parameters']
            if (action['actor']!=op['actor'] or action['root']!=op['root_id'] or action['recipient']!=op['recipient'] or
                action['domain']!=params['domain'] or action['snapshot']!=params['snapshot'] or
                action['mechanism']!=params['mechanism'] or action['accountant']!=params['accountant']):
                errors.append('WIRE_IDENTITY_BINDING')
            proofs=self.db.execute('SELECT * FROM used_proofs WHERE tenant=? AND operation_id=?',(op['tenant'],op['id'])).fetchall()
            if not proofs: errors.append('MISSING_ACCEPTED_PROOF')
            for record in proofs:
                try:
                    kid,proof=verify_sign1(record['proof_wire'],self.key(op['tenant'],row['kid'])['public_key'],self.proof_object_type)
                    proof=self.parse_wire_proof(proof)
                    if (kid!=row['kid'] or proof['action_digest']!=row['digest'] or
                        proof['proof_id']!=record['proof_id'] or proof['challenge']!=record['nonce']):
                        raise Rejected('ACCEPTED_PROOF_BINDING')
                except Rejected:
                    errors.append('ACCEPTED_PROOF_BINDING')
        return errors
