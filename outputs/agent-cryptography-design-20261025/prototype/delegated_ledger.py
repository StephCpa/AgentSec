"""Signed attenuation chains + cumulative ancestor caps for synthetic counts.

A trusted administrator pins each root's authority key. Credentials do not create
new domain budgets. All ancestor caps are additional AND constraints. Revocation
management and workload-key enrollment are still trusted service primitives.
"""
import hashlib
from signed_ledger import SignedLedger, Rejected
from dp_ledger import PROFILE, EPSILON_COST as E, DELTA_COST as D
from wire import encode,decode,inspect_sign1,verify_sign1,parse_action,identifier

FIELDS={'profile','kind','id','tenant','root','issuer','issuer_kid','subject','subject_kid',
        'parent_digest','depth','max_depth','not_before','expires_at','policy','epsilon_cap','delta_cap'}
POLICY_FIELDS={'domain','snapshots','recipients','mechanisms','operations','accountant','accounts'}
SCHEMA='''
CREATE TABLE IF NOT EXISTS root_authorities (
 tenant TEXT NOT NULL, root_id TEXT NOT NULL, kid BLOB NOT NULL,
 PRIMARY KEY(tenant,root_id), FOREIGN KEY(tenant,root_id) REFERENCES roots(tenant,id),
 FOREIGN KEY(tenant,kid) REFERENCES signing_keys(tenant,kid)
);
CREATE TABLE IF NOT EXISTS credentials (
 tenant TEXT NOT NULL, id TEXT NOT NULL, digest BLOB NOT NULL, wire BLOB NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant,id), UNIQUE(tenant,digest)
);
CREATE TABLE IF NOT EXISTS credential_revocations (
 tenant TEXT NOT NULL, credential_id TEXT NOT NULL,
 PRIMARY KEY(tenant,credential_id)
);
CREATE TABLE IF NOT EXISTS operation_chains (
 tenant TEXT NOT NULL, operation_id TEXT NOT NULL, position INTEGER NOT NULL,
 credential_digest BLOB NOT NULL,
 PRIMARY KEY(tenant,operation_id,position),
 FOREIGN KEY(tenant,operation_id) REFERENCES operations(tenant,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(tenant,credential_digest) REFERENCES credentials(tenant,digest)
);
'''


def parse_credential(wire, *, profile='count-chain-v1', extra_policy_fields=()):
    _,payload,_,_=inspect_sign1(wire)
    obj=decode(payload)
    if type(obj) is not dict or set(obj)!=FIELDS or obj['profile']!=profile or obj['kind'] not in ('grant','delegation'):
        raise Rejected('CREDENTIAL_SCHEMA')
    for name in ('id','tenant','root','issuer','subject'): identifier(obj[name])
    for name in ('issuer_kid','subject_kid'):
        if type(obj[name]) is not bytes or not 1<=len(obj[name])<=32: raise Rejected('CREDENTIAL_KEY')
    if type(obj['parent_digest']) is not bytes or len(obj['parent_digest']) not in (0,32): raise Rejected('PARENT_DIGEST')
    for name in ('depth','max_depth','not_before','expires_at','epsilon_cap','delta_cap'):
        if type(obj[name]) is not int or not 0<=obj[name]<=2**62: raise Rejected('CREDENTIAL_INTEGER')
    if not 0<=obj['depth']<=obj['max_depth']<=7 or obj['not_before']>=obj['expires_at']:
        raise Rejected('CREDENTIAL_BOUNDS')
    p=obj['policy']
    if type(p) is not dict or set(p)!=(POLICY_FIELDS|set(extra_policy_fields)): raise Rejected('POLICY_SCHEMA')
    identifier(p['domain'])
    for name in ('snapshots','recipients','mechanisms','operations'):
        values=p[name]
        if type(values) is not list or len(values)>32: raise Rejected('POLICY_SET')
        for value in values: identifier(value)
        if values!=sorted(set(values)): raise Rejected('POLICY_SET')
    if p['accountant']!=PROFILE or type(p['accounts']) is not dict or set(p['accounts'])!={'epsilon','delta'}:
        raise Rejected('POLICY_ACCOUNTANT')
    if any(type(v) is not str for v in p['accounts'].values()): raise Rejected('POLICY_ACCOUNTS')
    return obj


def cap_accounts(wire):
    prefix='credential:'+hashlib.sha256(wire).hexdigest()
    return prefix+':epsilon',prefix+':delta'


class DelegatedLedger(SignedLedger):
    accepted_profile='count-delegated-v1'
    parse_chain_credential=staticmethod(parse_credential)
    allowed_root_modes=('delegated',)

    @classmethod
    def create(cls,path,clock=None,**kwargs):
        obj=super().create(path,clock=clock,**kwargs); obj.db.executescript(SCHEMA); return obj

    def bind_root_authority(self,tenant,root_id,kid):
        # Trusted bootstrap; no overwrite or migration shortcut.
        with self.tx():
            self.root(tenant,root_id)
            if self.db.execute('SELECT 1 FROM operations WHERE tenant=? AND root_id=?',(tenant,root_id)).fetchone():
                raise Rejected('ROOT_ALREADY_USED')
            if self.key(tenant,kid)['role']!='root': raise Rejected('ROOT_KEY_ROLE')
            self.db.execute('INSERT INTO root_authorities VALUES(?,?,?)',(tenant,root_id,kid))
            self.db.execute("UPDATE roots SET authorization_mode='delegated' WHERE tenant=? AND id=?",(tenant,root_id))

    def revoke_credential(self,tenant,credential_id):
        # Trusted control plane; no identity claim is inferred from this method.
        identifier(tenant); identifier(credential_id)
        with self.tx():
            # Tombstones also cover credentials never presented to the service.
            self.db.execute('INSERT OR IGNORE INTO credential_revocations VALUES(?,?)',(tenant,credential_id))
            self.db.execute('UPDATE credentials SET revoked=1 WHERE tenant=? AND id=?',(tenant,credential_id))

    def register_delegated(self,raw,proof,chain,fault=lambda p:None):
        if (type(chain) is not list or not 1<=len(chain)<=8 or
            any(type(w) is not bytes for w in chain) or sum(map(len,chain))>65536):
            raise Rejected('CHAIN_LIMIT')
        if getattr(self,'_chain_request',None) is not None: raise Rejected('REENTRANT_REGISTRATION')
        self._chain_request=tuple(chain)
        try: return self.register_signed(raw,proof,fault)
        finally: self._chain_request=None

    def stored_chain(self,tenant,oid):
        return [r[0] for r in self.db.execute('''SELECT c.wire FROM operation_chains o JOIN credentials c
            ON o.tenant=c.tenant AND o.credential_digest=c.digest
            WHERE o.tenant=? AND o.operation_id=? ORDER BY o.position''',(tenant,oid))]

    def registered_costs(self,domain,action=None):
        costs=super().registered_costs(domain,action)
        # Pending chain during request; persisted chain for replay/audit/execution.
        chain=getattr(self,'_chain_request',None)
        if chain is None and action is not None: chain=self.stored_chain(action['tenant'],action['id'])
        if not chain: raise Rejected('CHAIN_REQUIRED')
        for wire in chain:
            eps,delta=cap_accounts(wire); costs[eps]=E; costs[delta]=D
        return costs

    def check_chain(self,chain,action,current=True):
        if not 1<=len(chain)<=8 or sum(map(len,chain))>65536: raise Rejected('CHAIN_LIMIT')
        tenant=action['tenant']; root=self.root(tenant,action['root']); domain=self.domain(tenant,action['domain'])
        authority=self.db.execute('SELECT kid FROM root_authorities WHERE tenant=? AND root_id=?',(tenant,root['id'])).fetchone()
        if authority is None: raise Rejected('UNPINNED_ROOT')
        previous=None; previous_wire=None; ids=set(); expiry=root['expires_at']
        for index,wire in enumerate(chain):
            obj=self.parse_chain_credential(wire); p=obj['policy']; digest=hashlib.sha256(wire).digest()
            if obj['tenant']!=tenant or obj['root']!=root['id'] or obj['id'] in ids: raise Rejected('CHAIN_NAMESPACE')
            ids.add(obj['id'])
            kid,_,_,_=inspect_sign1(wire)
            if kid!=obj['issuer_kid']: raise Rejected('ISSUER_KEY_BINDING')
            issuer=self.key(tenant,kid); subject=self.key(tenant,obj['subject_kid'])
            if issuer['actor']!=obj['issuer'] or subject['actor']!=obj['subject'] or subject['role']!='instance':
                raise Rejected('CREDENTIAL_IDENTITY')
            if current and (not self.key_active(issuer) or not self.key_active(subject)):
                raise Rejected('ANCESTOR_KEY_INACTIVE')
            if current and not obj['not_before']<=self.now()<obj['expires_at']: raise Rejected('CREDENTIAL_INACTIVE')
            if current and self.db.execute('SELECT 1 FROM credential_revocations WHERE tenant=? AND credential_id=?',
                                           (tenant,obj['id'])).fetchone(): raise Rejected('CREDENTIAL_REVOKED')
            stored=self.db.execute('SELECT * FROM credentials WHERE tenant=? AND id=?',(tenant,obj['id'])).fetchone()
            if stored is not None:
                if stored['wire']!=wire: raise Rejected('CREDENTIAL_ID_CONFLICT')
                if current and stored['revoked']: raise Rejected('CREDENTIAL_REVOKED')
            object_type=self.chain_object_type(index)
            verify_sign1(wire,issuer['public_key'],object_type)
            if index==0:
                if (obj['kind']!='grant' or obj['id']!=root['id'] or obj['depth']!=0 or obj['parent_digest']!=b'' or
                    kid!=authority['kid'] or issuer['role']!='root' or obj['subject']!=root['actor']):
                    raise Rejected('ROOT_BINDING')
                if obj['expires_at']>root['expires_at'] or not set(p['recipients'])<={root['recipient']}:
                    raise Rejected('ROOT_SCOPE')
                for name,account in (('epsilon',domain['epsilon_account']),('delta',domain['delta_account'])):
                    limit=self.db.execute('SELECT total FROM accounts WHERE tenant=? AND id=?',(tenant,account)).fetchone()[0]
                    if obj[name+'_cap']>limit: raise Rejected('ROOT_CAP')
            else:
                if (obj['kind']!='delegation' or issuer['role']!='instance' or
                    obj['issuer']!=previous['subject'] or obj['issuer_kid']!=previous['subject_kid'] or
                    obj['parent_digest']!=hashlib.sha256(previous_wire).digest() or obj['depth']!=previous['depth']+1):
                    raise Rejected('CHAIN_PARENT_BINDING')
                if (obj['max_depth']>previous['max_depth'] or obj['not_before']<previous['not_before'] or
                    obj['expires_at']>previous['expires_at'] or obj['epsilon_cap']>previous['epsilon_cap'] or
                    obj['delta_cap']>previous['delta_cap']): raise Rejected('ATTENUATION_BOUNDS')
                self.check_policy_attenuation(p,previous['policy'])
            expected={'epsilon':domain['epsilon_account'],'delta':domain['delta_account']}
            if p['domain']!=domain['id'] or p['accounts']!=expected: raise Rejected('ACCOUNT_REBIND')
            expiry=min(expiry,obj['expires_at'],issuer['expires_at'],subject['expires_at'])
            previous,previous_wire=obj,wire
        if (hashlib.sha256(chain[-1]).digest()!=action.get('leaf_digest') or previous['subject']!=action['actor'] or
            previous['subject_kid']!=action['kid']): raise Rejected('LEAF_BINDING')
        p=previous['policy']
        self.check_action_scope(action,p)
        if action['not_before']<previous['not_before'] or action['deadline']>previous['expires_at']:
            raise Rejected('ACTION_OUTSIDE_WINDOW')
        return expiry

    def chain_object_type(self,index):
        return 'Grant' if index==0 else 'Delegation'

    def check_policy_attenuation(self,policy,parent):
        for name in ('snapshots','recipients','mechanisms','operations'):
            if not set(policy[name])<=set(parent[name]):raise Rejected('ATTENUATION_SCOPE')

    def check_action_scope(self,action,policy):
        if (action['snapshot'] not in policy['snapshots'] or action['recipient'] not in policy['recipients'] or
            action['mechanism'] not in policy['mechanisms'] or 'count' not in policy['operations']):
            raise Rejected('ACTION_OUTSIDE_LEAF')

    def validate_request_identity(self,internal,root,actor):
        ctx=getattr(self,'_signed_request',None); chain=getattr(self,'_chain_request',None)
        if ctx is None or not chain: raise Rejected('CHAIN_REQUIRED')
        action=self.parse_wire_action(ctx[0])
        if action['profile']!=self.accepted_profile or action['actor']!=actor:
            raise Rejected('UNSUPPORTED_ACTION_PROFILE')
        self.check_chain(chain,action)

    def authorize_reservation(self,internal,root):
        super().authorize_reservation(internal,root)
        action=self.parse_wire_action(self._signed_request[0]); chain=self._chain_request
        for index,wire in enumerate(chain):
            obj=self.parse_chain_credential(wire); digest=hashlib.sha256(wire).digest()
            exists=self.db.execute('SELECT 1 FROM credentials WHERE tenant=? AND id=?',(action['tenant'],obj['id'])).fetchone()
            if not exists:
                self.db.execute('INSERT INTO credentials(tenant,id,digest,wire) VALUES(?,?,?,?)',(action['tenant'],obj['id'],digest,wire))
                for account,limit in zip(cap_accounts(wire),(obj['epsilon_cap'],obj['delta_cap'])):
                    self.db.execute('INSERT INTO accounts(tenant,id,total,free) VALUES(?,?,?,?)',(action['tenant'],account,limit,limit))
            self.db.execute('INSERT OR IGNORE INTO operation_chains VALUES(?,?,?,?)',(action['tenant'],action['operation'],index,digest))
        self._signed_request[2]('after_chain_registration')

    def authorization_active(self,op):
        if not super().authorization_active(op): return False
        raw=self.db.execute('SELECT action FROM signed_actions WHERE tenant=? AND operation_id=?',(op['tenant'],op['id'])).fetchone()[0]
        try: self.check_chain(self.stored_chain(op['tenant'],op['id']),self.parse_wire_action(raw))
        except Rejected: return False
        return True

    def delivery_expiry(self,op,root,now,ttl):
        raw=self.db.execute('SELECT action FROM signed_actions WHERE tenant=? AND operation_id=?',(op['tenant'],op['id'])).fetchone()[0]
        expiry=self.check_chain(self.stored_chain(op['tenant'],op['id']),self.parse_wire_action(raw))
        return min(super().delivery_expiry(op,root,now,ttl),expiry)

    def audit(self):
        errors=super().audit()
        for op in self.db.execute('SELECT * FROM operations'):
            row=self.db.execute('SELECT action FROM signed_actions WHERE tenant=? AND operation_id=?',(op['tenant'],op['id'])).fetchone()
            if row is None: continue
            try: self.check_chain(self.stored_chain(op['tenant'],op['id']),self.parse_wire_action(row[0]),current=False)
            except Rejected: errors.append('HISTORICAL_CHAIN_BINDING')
        return errors
