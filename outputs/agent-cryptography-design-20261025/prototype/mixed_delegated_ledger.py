"""Signed mixed count/histogram admission with all-ancestor cumulative caps.

Synthetic plaintext state. Trusted enrollment/control plane only; no encrypted
vector vault, authoritative witness or authenticated vector transport yet.
New wire/storage profiles have explicit signature-domain separation.
"""
import json
from delegated_ledger import DelegatedLedger,parse_credential
from histogram_ledger import HistogramLedger,COUNT,HISTOGRAM,CODEC
from signed_ledger import SignedLedger
from wire import decode,encode,parse_action,parse_proof,identifier
from ledger import Rejected

PROFILE='mixed-delegated-v1'
CHAIN_PROFILE='mixed-chain-v1'
COUNT_CODEC='uint64be_count_v1'
COMMON={'operation_kind','capacity','k','codec'}
HIST_FIELDS={'catalog','catalog_digest','bucket_count'}


def parse_mixed_action(raw):
    obj=decode(raw)
    if type(obj) is not dict or obj.get('profile')!=PROFILE or obj.get('operation_kind') not in ('count','histogram'):
        raise Rejected('INVALID_MIXED_ACTION_SCHEMA')
    histogram=obj['operation_kind']=='histogram'
    extra=COMMON|(HIST_FIELDS if histogram else set())
    if not extra<=set(obj):raise Rejected('INVALID_MIXED_ACTION_SCHEMA')
    base={k:v for k,v in obj.items() if k not in extra};base['profile']='count-delegated-v1'
    parse_action(encode(base))  # Exact common schema, integer/key/window bounds.
    if (type(obj['capacity']) is not int or not 1<=obj['capacity']<=65535 or
        type(obj['k']) is not int or obj['k']!=40 or
        obj['codec']!=(CODEC if histogram else COUNT_CODEC) or
        obj['mechanism']!=(HISTOGRAM if histogram else COUNT)):
        raise Rejected('MIXED_MECHANISM_BINDING')
    if histogram:
        identifier(obj['catalog'])
        if type(obj['catalog_digest']) is not bytes or len(obj['catalog_digest'])!=32:raise Rejected('INVALID_CATALOG_DIGEST')
        if type(obj['bucket_count']) is not int or not 1<=obj['bucket_count']<=64:raise Rejected('INVALID_BUCKET_COUNT')
    return obj


def parse_mixed_proof(obj):
    if type(obj) is not dict or obj.get('profile')!=PROFILE:raise Rejected('INVALID_MIXED_PROOF_SCHEMA')
    base=dict(obj);base['profile']='count-delegated-v1';parse_proof(base)
    return obj


def parse_mixed_credential(wire):
    obj=parse_credential(wire,profile=CHAIN_PROFILE,extra_policy_fields=('catalogs',))
    catalogs=obj['policy']['catalogs']
    if type(catalogs) is not dict or len(catalogs)>32:raise Rejected('POLICY_CATALOGS')
    for name,digest in catalogs.items():
        identifier(name)
        if type(digest) is not bytes or len(digest)!=32:raise Rejected('POLICY_CATALOGS')
    if any(x not in ('count','histogram') for x in obj['policy']['operations']):raise Rejected('POLICY_OPERATION')
    if any(x not in (COUNT,HISTOGRAM) for x in obj['policy']['mechanisms']):raise Rejected('POLICY_MECHANISM')
    return obj


class MixedDelegatedLedger(DelegatedLedger,HistogramLedger):
    storage_profile='synthetic-signed-mixed-delegated-v1'
    accepted_profile=PROFILE
    audience='mixed-gateway-v1'
    proof_object_type='MixedActionProof'
    supported_mechanisms=(COUNT,HISTOGRAM)
    parse_wire_action=staticmethod(parse_mixed_action)
    parse_wire_proof=staticmethod(parse_mixed_proof)
    parse_chain_credential=staticmethod(parse_mixed_credential)

    def chain_object_type(self,index):
        return 'MixedGrant' if index==0 else 'MixedDelegation'

    def check_policy_attenuation(self,policy,parent):
        super().check_policy_attenuation(policy,parent)
        if any(parent['catalogs'].get(name)!=digest for name,digest in policy['catalogs'].items()):
            raise Rejected('CATALOG_ATTENUATION')

    def check_action_scope(self,action,policy):
        if (action['snapshot'] not in policy['snapshots'] or action['recipient'] not in policy['recipients'] or
            action['mechanism'] not in policy['mechanisms'] or action['operation_kind'] not in policy['operations']):
            raise Rejected('ACTION_OUTSIDE_LEAF')
        if action['operation_kind']=='histogram' and policy['catalogs'].get(action['catalog'])!=action['catalog_digest']:
            raise Rejected('ACTION_CATALOG_OUTSIDE_LEAF')

    def reserve_wire_action(self,action,fault):
        if action['operation_kind']=='histogram':
            return HistogramLedger.reserve_histogram(self,action['tenant'],action['operation'],action['root'],
                action['recipient'],action['domain'],action['snapshot'],action['catalog'],action['actor'],fault)
        return SignedLedger.reserve_wire_action(self,action,fault)

    def validate_wire_parameters(self,action):
        domain=self.domain(action['tenant'],action['domain'])
        if action['capacity']!=domain['capacity']:raise Rejected('SIGNED_CAPACITY_MISMATCH')
        if action['operation_kind']=='histogram':
            catalog=self.catalog(action['tenant'],action['domain'],action['catalog'])
            if (action['catalog_digest'].hex()!=catalog['digest'] or
                action['bucket_count']!=len(json.loads(catalog['buckets_json']))):
                raise Rejected('SIGNED_CATALOG_MISMATCH')

    def audit(self):
        errors=super().audit()
        for row in self.db.execute('SELECT * FROM signed_actions'):
            try:
                action=self.parse_wire_action(row['action']);self.validate_wire_parameters(action)
                op=self.op(row['tenant'],row['operation_id']);params=json.loads(op['action'])['parameters']
                if action['operation_kind']=='histogram':
                    for name in HIST_FIELDS|{'capacity','k','codec'}:
                        expected=action[name].hex() if name=='catalog_digest' else action[name]
                        if params.get(name)!=expected:raise Rejected('SIGNED_INTERNAL_SHAPE_BINDING')
                if action['operation']!=op['id'] or action['tenant']!=op['tenant']:
                    raise Rejected('SIGNED_INTERNAL_ID_BINDING')
            except Rejected:errors.append('MIXED_WIRE_BINDING')
        return errors
