"""Diagnostic R1--R4 relation at completed public event boundaries.

Only this test-side checker receives the real SQLite connection. The public
simulator does not. Checks selected relational state, not ciphertext contents,
crash points, a universal induction, or a production privacy claim.
"""
import hashlib
import json

from public_gateway import parse_request, response
from mixed_delegated_ledger import parse_mixed_proof, parse_mixed_credential
from wire import decode, inspect_sign1
import retention_delivery as delivery
import retention_wire as retention


class StateRelationMismatch(AssertionError):
    pass


def digest(value):
    def normalized(item):
        if isinstance(item, bytes):
            return {'bytes': item.hex()}
        if isinstance(item, dict):
            return {'mapping': [[normalized(k), normalized(v)] for k, v in sorted(item.items(), key=lambda pair: repr(pair[0]))]}
        if isinstance(item, (set, frozenset)):
            return {'set': [normalized(x) for x in sorted(item, key=repr)]}
        if isinstance(item, (list, tuple)):
            return [normalized(x) for x in item]
        return item
    return hashlib.sha256(json.dumps(normalized(value), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def assert_state_relation(runtime, model):
    """Read real state and compare against a separately advanced public model.

    No private rows, seed bytes, result bytes or encrypted work accumulators are
    read. Presence bits at L1/L2 are checked, not encryption/durability itself.
    """
    db = runtime.l.db
    cfg = model.cfg
    tenant, domain = cfg['tenant'], cfg['domain']
    checks = {}

    def equal(label, actual, expected):
        if actual != expected:
            # Diagnostic hashes avoid dumping even accidentally read material.
            raise StateRelationMismatch(label + ': actual=' + digest(actual) + ' expected=' + digest(expected))
        checks[label] = digest(expected)

    def rows(table, columns='*'):
        # Table/column strings are fixed by this module, never public input.
        return db.execute('SELECT ' + columns + ' FROM ' + table + ' WHERE tenant=?', (tenant,)).fetchall()

    journal = db.execute('SELECT * FROM gw_requests WHERE tenant=? AND domain_id=? ORDER BY seq', (tenant, domain)).fetchall()
    equal('R1.journal_sequence', [row['seq'] for row in journal], list(range(1, model.journal_seq + 1)))
    equal('R1.request_cache', {(row['kid'], row['request_id']): (row['request'], row['response']) for row in journal}, model.cache)
    equal('R1.challenges', {row['nonce']: dict(kid=row['kid'], expiry=row['expires_at'], used=bool(row['used'])) for row in rows('challenges')}, model.challenges)
    equal('R1.challenge_audience', {row['audience'] for row in rows('challenges')}, {'mixed-gateway-v1'} if model.challenges else set())
    expected_proofs, expected_chains = {}, {}
    for raw, reply in model.cache.values():
        request = parse_request(raw)
        result = response(reply, raw, cfg['gateway_key'], cfg['gateway_kid'], cfg['deployment'])
        if request['method'] != 'SUBMIT' or result['status'] != 'RECORDED':
            continue
        payload = request['payload']
        proof = parse_mixed_proof(decode(inspect_sign1(payload['proof'])[1]))
        oid = result['body']['operation']
        expected_proofs[proof['proof_id']] = (proof['challenge'], oid, payload['proof'])
        expected_chains.setdefault(oid, tuple(hashlib.sha256(raw).digest() for raw in payload['chain']))
    equal('R1.proof_consumption', {row['proof_id']: (row['nonce'], row['operation_id'], row['proof_wire']) for row in rows('used_proofs')}, expected_proofs)
    equal('R1.model_proof_set', model.proofs, set(expected_proofs))
    equal('R1.credentials', {(row['tenant'], row['root_id'], row['kind'], row['issuer_kid'], row['id']): (row['wire'], row['digest'], row['revoked']) for row in rows('credentials')},
          {key: (raw, hashlib.sha256(raw).digest(), 0) for key, raw in model.credentials.items()})
    equal('R1.credential_tombstones', len(rows('credential_revocations')), 0)
    equal('R1.chain_links', {(row['operation_id'], row['position']): row['credential_digest'] for row in rows('operation_chains')},
          {(oid, pos): sha for oid, chain in expected_chains.items() for pos, sha in enumerate(chain)})
    equal('R1.signed_actions', {row['operation_id']: (row['action'], row['digest'], row['kid']) for row in rows('signed_actions')},
          {job['id']: (job['raw_action'], hashlib.sha256(job['raw_action']).digest(), job['action']['kid']) for job in model.jobs})
    key_fields = ('actor', 'role', 'public_key', 'not_before', 'expires_at', 'revoked')
    equal('R1.keys', {row['kid']: tuple(row[k] for k in key_fields) for row in rows('signing_keys')},
          {kid: tuple(key.get(k, False) for k in key_fields) for kid, key in cfg['keys'].items()})
    equal('R1.principals', {row['kid']: (row['domain_id'], row['certificate'], decode(row['rights']), bool(row['revoked'])) for row in rows('gw_principals')},
          {kid: (domain, p['certificate'], sorted(p['rights']), p.get('revoked', False)) for kid, p in cfg['principals'].items()})

    expected_accounts = {account: [limit, limit, 0, 0] for account, limit in model.limits.items()}
    expected_charges = {}
    for job in model.jobs:
        disposition = 'RETURNED' if job['state'] == 'CANCELED' else 'SPENT' if job['state'] in ('COMMITTED', 'BURNED') else 'HELD'
        equal('R2.allocated.' + job['id'], job['allocated'], disposition != 'RETURNED')
        for account, cost in job['costs'].items():
            expected_charges[(job['id'], account)] = (cost, disposition)
            if disposition != 'RETURNED':
                expected_accounts[account][1] -= cost
                expected_accounts[account][2 if disposition == 'HELD' else 3] += cost
    equal('R2.charges', {(row['operation_id'], row['account_id']): (row['amount'], row['disposition']) for row in rows('charges')}, expected_charges)
    equal('R2.accounts', {row['id']: [row[k] for k in ('total', 'free', 'reserved', 'spent')] for row in rows('accounts')}, expected_accounts)
    equal('R2.model_used', {key: model.used.get(key, 0) for key in model.limits}, {key: v[2] + v[3] for key, v in expected_accounts.items()})
    equal('R2.operation_phase', {row['id']: (row['state'], row['generation'], bool(row['has_seed']), bool(row['has_result'])) for row in rows('operations', 'id,state,generation,seed IS NOT NULL AS has_seed,result IS NOT NULL AS has_result')},
          {job['id']: (job['state'], int(job['state'] in ('STARTED', 'COMMITTED', 'BURNED')), job['state'] in ('STARTED', 'COMMITTED', 'BURNED'), job['state'] == 'COMMITTED') for job in model.jobs})
    equal('R2.L1_calls', runtime.runtime_draws, [(call['operation'], model.by_id[call['operation']]['action']['operation_kind'], call['l1_tick']) for call in model.mechanism_calls])

    scheduler = db.execute('SELECT tick,next_seq,publish_seq,cursor FROM schedulers WHERE tenant=? AND domain_id=?', (tenant, domain)).fetchone()
    equal('R3.scheduler', tuple(scheduler) if scheduler is not None else (0, 1, 1, 0), (model.tick, len(model.jobs) + 1, model.published + 1, model.cursor))
    equal('R3.ticks', [row[0] for row in db.execute('SELECT tick FROM tick_requests WHERE tenant=? AND domain_id=? ORDER BY tick', (tenant, domain))], list(range(1, model.tick + 1)))
    public_jobs = rows('jobs', 'operation_id,seq,pc,work,suppressed,publication')
    equal('R3.jobs', {row['operation_id']: (row['seq'], row['pc'], row['work'], bool(row['suppressed'])) for row in public_jobs},
          {job['id']: (job['seq'], job['pc'], job['work'], job['suppressed']) for job in model.jobs})
    equal('R3.paused', bool(db.execute('SELECT paused FROM gw_domains WHERE tenant=? AND domain_id=?', (tenant, domain)).fetchone()[0]), model.paused)

    equal('R4.roots', {row['id']: (row['actor'], row['recipient'], bool(row['revoked']), row['expires_at']) for row in rows('roots')},
          {rid: (root['actor'], root['recipient'], root.get('revoked', False), root['expires_at']) for rid, root in cfg['roots'].items()})
    equal('R4.authorities', {row['root_id']: row['kid'] for row in rows('root_authorities')}, {rid: root['authority'] for rid, root in cfg['roots'].items()})
    equal('R4.bindings', {row['root_id']: (row['domain_id'], row['context_hash'], row['ttl']) for row in rows('pub_bindings')},
          {rid: (domain, retention.context_hash(root['context']), root['ttl']) for rid, root in cfg['roots'].items()})
    # Derive the authorization ceiling from stored public chain/key records,
    # including each issuer and subject, rather than trusting the model's field.
    stored_keys = {row['kid']: row['expires_at'] for row in rows('signing_keys')}
    stored_roots = {row['id']: row['expires_at'] for row in rows('roots')}
    stored_credentials = {row['digest']: parse_mixed_credential(row['wire']) for row in rows('credentials')}
    ceilings = {}
    for job in model.jobs:
        expiry = stored_roots[job['action']['root']]
        for sha in expected_chains[job['id']]:
            credential = stored_credentials[sha]
            expiry = min(expiry, credential['expires_at'], stored_keys[credential['issuer_kid']], stored_keys[credential['subject_kid']])
        ceilings[job['id']] = expiry
    equal('R4.authorization_ceiling', ceilings, {job['id']: job['authorization_expiry'] for job in model.jobs})
    tick = 0
    published_ticks = {}
    for event in model.events:
        if event[0] == 'ROUND':
            tick = event[1]
        elif event[0] == 'JOURNAL':
            published_ticks[event[2]] = tick
    expected_decisions, expected_tickets, expected_outbox = {}, {}, {}
    expected_eligibility = {}
    for job in model.jobs:
        publication = job['publication']
        expected_eligibility[job['id']] = None if publication is None else 'RELEASE' if publication == 'ADMITTED' else 'WITHHELD'
        if publication is None:
            continue
        ctx = cfg['roots'][job['action']['root']]['context']
        context_hash = retention.context_hash(ctx)
        did = None
        if publication == 'ADMITTED':
            did = retention.delivery_id(ctx, job['route_seq'])
            expected_tickets[did] = (job['id'], ctx['recipient'], ctx['gateway'], ctx['session'], job['issued_at'], job['expires_at'])
            desc = delivery.descriptor(ctx, seq=job['route_seq'], operation=job['id'], issued_at=job['issued_at'], expires_at=job['expires_at'], shape=model._shape(job))
            expected_outbox[did] = (context_hash, job['route_seq'], desc)
        expected_decisions[job['id']] = (job['seq'], published_ticks[job['id']], context_hash, publication, did)
    equal('R4.eligibility', {row['operation_id']: row['publication'] for row in public_jobs}, expected_eligibility)
    equal('R4.decisions', {row['operation_id']: (row['seq'], row['tick'], row['context_hash'], row['kind'], row['delivery_id']) for row in rows('pub_decisions')}, expected_decisions)
    equal('R4.tickets', {row['id']: tuple(row[k] for k in ('operation_id', 'recipient', 'gateway', 'session', 'issued_at', 'expires_at')) for row in rows('deliveries', 'id,operation_id,recipient,gateway,session,issued_at,expires_at')}, expected_tickets)
    equal('R4.outbox_identity', {row['id']: (row['context_hash'], int.from_bytes(row['seq'], 'big'), row['descriptor']) for row in rows('v2_outbox', 'id,context_hash,seq,descriptor')}, expected_outbox)
    equal('R4.route_high', {row['context_hash']: int.from_bytes(row['high'], 'big') for row in rows('v2_routes')},
          {retention.context_hash(root['context']): model.route_high.get(retention.context_hash(root['context']), 0) for root in cfg['roots'].values()})
    return {relation: digest({key: sha for key, sha in checks.items() if key.startswith(relation + '.')}) for relation in ('R1', 'R2', 'R3', 'R4')}
