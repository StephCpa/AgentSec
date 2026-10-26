"""Test-side R5--R8 projections, with strict no-retirement checks by default.

Decrypts stored transport evidence, never private snapshots/work/seed/results.
The generated logical history is the expectation; no database value is passed
back to the simulator. initialized_contexts declares empty receivers from public
trusted setup for recovery profiles. Default completed-event checks are unchanged.
Successful boundary equality is not a general recovery proof.
An explicit retirement model enables offer/checkpoint and live-window checks;
omitting it retains the original strict no-retirement assertions.
"""
from wire import decode
from ledger import Rejected
from state_relation import StateRelationMismatch, digest
import retention_delivery as d
import retention_wire as r


def assert_delivery_relation(runtime, simulator, *, initialized_contexts=(), retirement=None):
    model = simulator.state
    tenant, domain = model.cfg['tenant'], model.cfg['domain']
    sender = runtime.l
    checks = {}

    def equal(label, actual, expected):
        if actual != expected:
            raise StateRelationMismatch(label + ': actual=' + digest(actual) + ' expected=' + digest(expected))
        checks[label] = digest(expected)

    def opened(owner, kind, row, label):
        try:
            return owner.open(kind, row)
        except Rejected as exc:
            raise StateRelationMismatch(label + ': stored evidence cannot be authenticated') from exc

    contexts = {r.context_hash(root['context']): root['context'] for root in model.cfg['roots'].values()}
    routes = {row['context_hash']: row for row in sender.db.execute('SELECT * FROM v2_routes WHERE tenant=?', (tenant,))}
    equal('R5.contexts', {h: (decode(row['context']), row['tenant'], row['recipient'], row['gateway'], row['session'], bool(row['revoked'])) for h, row in routes.items()},
          {h: (ctx, ctx['tenant'], ctx['recipient'], ctx['gateway'], ctx['session'], False) for h, ctx in contexts.items()})
    if retirement is None:
        equal('R5.no_retirement', {h: (int.from_bytes(row['retired'], 'big'), row['retired_root'], row['retirement_evidence']) for h, row in routes.items()},
              {h: (0, r.genesis(ctx), None) for h, ctx in contexts.items()})
        equal('R5.no_retirement_offers', sender.db.execute('SELECT count(*) FROM v2_retire_offers').fetchone()[0], 0)
    else:
        equal('R5.retirement_scope', set(retirement['sender']), set(contexts))
        equal('R6.retirement_scope', set(retirement['receiver']), set(contexts))
        actual_retired = {}
        for h, row in routes.items():
            evidence = None if row['retirement_evidence'] is None else decode(sender.vault.open('v2-retirement-checkpoint', (h,), row['retirement_evidence']))
            actual_retired[h] = (int.from_bytes(row['retired'], 'big'), row['retired_root'], evidence)
        equal('R5.retirement', actual_retired,
              {h: (v['floor'], v['root'], v['evidence']) for h, v in retirement['sender'].items()})
        actual_offers = {}
        for row in sender.db.execute('SELECT * FROM v2_retire_offers'):
            key = (row['context_hash'], int.from_bytes(row['base'], 'big'), int.from_bytes(row['target'], 'big'))
            actual_offers[key] = sender.vault.open('v2-retire-offer', key, row['offer'])
        equal('R5.retirement_offers', actual_offers, retirement['offers'])

    jobs = {(r.context_hash(job['context']), job['route_seq']): job for job in model.jobs if job['publication'] == 'ADMITTED'}
    expected_requests = {}
    for (h, seq), job in jobs.items():
        expected_requests[(h, 'publication:' + domain + ':' + str(job['seq']))] = (job['id'], model.cfg['roots'][job['action']['root']]['ttl'], r.delivery_id(contexts[h], seq))
    equal('R5.admission_requests', {(row['context_hash'], row['request_key']): (row['operation_id'], row['ttl'], row['delivery_id']) for row in sender.db.execute('SELECT * FROM v2_requests WHERE tenant=?', (tenant,))}, expected_requests)
    outbox = {(row['context_hash'], int.from_bytes(row['seq'], 'big')): row for row in sender.db.execute('SELECT * FROM v2_outbox WHERE tenant=?', (tenant,))}
    equal('R5.outbox_keys', set(outbox), set(jobs))
    actual_prepared = {}
    for key, row in outbox.items():
        for column, kind in (('envelope', 'DELIVERY'), ('control', 'TERMINAL')):
            if row[column] is not None:
                actual_prepared[(key, kind)] = opened(sender, column, row, 'R5.prepared')
    equal('R5.prepared', actual_prepared, model.prepared)
    expected_handoff = {r.delivery_id(contexts[h], seq): int(((h, seq), 'DELIVERY') in model.prepared) for h, seq in jobs}
    equal('R5.handoff', {row['id']: row['handoff_admitted'] for row in sender.db.execute('SELECT id,handoff_admitted FROM deliveries WHERE tenant=?', (tenant,))}, expected_handoff)

    # Derive receiver reachability and first sender confirmation from generated
    # observations. Hidden lost ACK bytes are neither invented nor read here.
    reached = {h: 0 for h in initialized_contexts}
    if not set(reached) <= set(contexts):
        raise StateRelationMismatch('R6.initial_context_scope')
    first_confirmations = {}
    for event in simulator.records:
        if retirement is not None and event['kind'] == 'RETENTION_RECEIVE':
            h = bytes.fromhex(event['context_hash'])
            if h not in contexts:
                raise StateRelationMismatch('R6.retention_context')
            reached[h] = event['at']
            continue
        if event['kind'] not in ('DELIVERY', 'CONFIRM'):
            continue
        request = bytes.fromhex(event['request'])
        found = None
        for h, ctx in contexts.items():
            try:
                attempt = d.parse_attempt(request, ctx)
                found = h, ctx, attempt
                break
            except Rejected:
                continue
        if found is None:
            raise StateRelationMismatch('R6.generated_context')
        h, ctx, attempt = found
        body = d.parse_body(attempt['kind'], attempt['body'], ctx)
        descriptor = d.parse_descriptor(body['descriptor'], ctx)
        key = (h, descriptor['seq'])
        if event['kind'] == 'DELIVERY':
            if event['response'] != 'PACKET_LOST':
                reached[h] = event['at']
        else:
            ack = bytes.fromhex(event['response'])
            fact = d.parse_receipt(ack, request, ctx)
            first_confirmations.setdefault(key, (fact, dict(request=request, ack=ack)))

    equal('R6.receiver_instances', set(runtime.receivers), {contexts[h]['recipient'] for h in reached})
    actual_receiver, actual_receiver_meta = {}, {}
    for recipient, (inbox, _) in runtime.receivers.items():
        matches = [(h, ctx) for h, ctx in contexts.items() if ctx['recipient'] == recipient]
        if len(matches) != 1:
            raise StateRelationMismatch('R6.receiver_context_scope')
        h, ctx = matches[0]
        meta = inbox.db.execute('SELECT context,high,floor,root,observed,last_offer FROM v2_recipient_meta WHERE singleton=1').fetchone()
        last_offer = meta['last_offer']
        if retirement is not None and last_offer is not None:
            last_offer = inbox.vault.open('v2-recipient-last-offer', (h,), last_offer)
        actual_receiver_meta[h] = (decode(meta['context']), int.from_bytes(meta['high'], 'big'), int.from_bytes(meta['floor'], 'big'), meta['root'], meta['observed'], last_offer)
        for row in inbox.db.execute('SELECT seq,id,fact,evidence FROM v2_recipient_live ORDER BY seq'):
            fact = opened(inbox, 'fact', row, 'R6.first_fact')
            evidence = opened(inbox, 'evidence', row, 'R6.first_evidence')
            actual_receiver[(h, int.from_bytes(row['seq'], 'big'))] = (row['id'], fact, evidence)
    expected_receiver = {}
    for key, fact in model.receiver.items():
        h, seq = key
        if retirement is not None and seq <= retirement['receiver'][h]['floor']:
            continue
        kind = 'DELIVERY' if r.parse_fact(fact, contexts[h])['outcome'] == 'ACCEPTED' else 'TERMINAL'
        expected_receiver[key] = (r.delivery_id(contexts[h], seq), fact, model.prepared[(key, kind)])
    equal('R6.first_facts_and_evidence', actual_receiver, expected_receiver)
    expected_receiver_meta = {}
    for h, at in reached.items():
        retired = dict(floor=0, root=r.genesis(contexts[h]), last_offer=None) if retirement is None else retirement['receiver'][h]
        expected_receiver_meta[h] = (contexts[h], max((seq for hh, seq in model.receiver if hh == h), default=0),
                                     retired['floor'], retired['root'], at, retired['last_offer'])
    equal('R6.receiver_metadata', actual_receiver_meta, expected_receiver_meta)

    expected_states, actual_facts, expected_facts = {}, {}, {}
    for key, job in jobs.items():
        confirmed = job.get('confirmed')
        expected_states[key] = confirmed if confirmed is not None else 'READY' if (key, 'DELIVERY') in model.prepared else 'QUEUED'
        if confirmed is not None:
            if key not in first_confirmations:
                raise StateRelationMismatch('R7.confirmation_event_missing')
            expected_facts[key] = first_confirmations[key]
            equal('R7.model_fact.' + job['id'], first_confirmations[key][0], model.receiver[key])
    equal('R7.confirmation_event_keys', set(first_confirmations), set(expected_facts))
    equal('R7.sender_states', {key: row['state'] for key, row in outbox.items()}, expected_states)
    for key, row in outbox.items():
        if row['fact'] is not None or row['acknowledgement'] is not None:
            if row['fact'] is None or row['acknowledgement'] is None:
                raise StateRelationMismatch('R7.incomplete_sender_evidence')
            actual_facts[key] = (opened(sender, 'fact', row, 'R7.fact'), decode(opened(sender, 'acknowledgement', row, 'R7.receipt')))
    equal('R7.sender_facts_and_receipts', actual_facts, expected_facts)
    expected_prefixes = {}
    for h, ctx in contexts.items():
        front, root = 0, r.genesis(ctx)
        for hh, seq in sorted(expected_facts):
            if hh != h:
                continue
            if seq != front + 1:
                raise StateRelationMismatch('R7.model_route_gap')
            front = seq
            root = r.extend_prefix(root, expected_facts[(h, seq)][0], ctx, seq)
        expected_prefixes[h] = (front, root)
    equal('R7.route_confirmed_prefix', {h: (int.from_bytes(row['confirmed'], 'big'), row['confirmed_root']) for h, row in routes.items()}, expected_prefixes)

    expected_final, expected_rows = [], []
    for job in model.jobs:
        outcome = 'WITHHELD' if job['publication'] == 'WITHHELD' else job.get('confirmed')
        if outcome is None:
            break
        expected_final.append(dict(sequence=job['seq'], operation=job['id'], outcome=outcome))
        did = None if outcome == 'WITHHELD' else r.delivery_id(job['context'], job['route_seq'])
        expected_rows.append((job['seq'], outcome, did))
    equal('R8.model_final_prefix', model.final, expected_final)
    equal('R8.durable_final_rows', [tuple(row) for row in sender.db.execute('SELECT seq,outcome,delivery_id FROM final_events WHERE tenant=? AND domain_id=? ORDER BY seq', (tenant, domain))], expected_rows)
    # Actual POLL/FINAL responses are already compared byte-for-byte by the
    # driving simulator; this relation supplies their durable backing prefix.
    return {relation: digest({key: sha for key, sha in checks.items() if key.startswith(relation + '.')}) for relation in ('R5', 'R6', 'R7', 'R8')}
