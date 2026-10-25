"""Integrated P2 reference workflow, synthetic roles/data and loopback mTLS.

Two signed analysis-role drivers are ordinary concurrent Python clients, not
LLM agents. The writer is a pure evidence-to-report adapter, not an OS sandbox.
Reuses fixture provisioning; never deploys or accesses external/private data.
"""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import threading
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ledger import Rejected
from wire import decode
from delegated_ledger import cap_accounts
from dp_ledger import EPSILON_COST as E,DELTA_COST as D
from retention_sender import TLSRetentionSender
from retention_recipient import TLSRetentionRecipient
from retention_archive import archive_page,ArchiveVerifier
from witness_transport import WitnessTLSService,TLSWitnessClient,trusted_register_peer,certificate_fingerprint
from delivery_transport import RecipientTLSService,DeliverySender
from test_witness_transport import certificates,public
from test_witnessed_mixed_ledger import populate
from test_encrypted_mixed_ledger import vault
from test_mixed_delegated_ledger import chain_fixture,packet
from test_retention_sender import context
from test_retention_recipient import recipient_vault
import retention_wire as r
import retention_delivery as d


def writer_report(context,evidence,expected_operations):
    """Only authenticated, accepted result envelopes become report inputs.

    This pure adapter has no ledger, vault, file path or snapshot argument.
    Deployment isolation and authorization of the adapter caller are separate.
    """
    if type(evidence) is not list or type(expected_operations) is not list or not expected_operations:
        raise Rejected('WRITER_INPUT')
    if len(set(expected_operations))!=len(expected_operations):raise Rejected('WRITER_OPERATION_SET')
    records=[];seen=set()
    for item in evidence:
        if type(item) is not dict or set(item)!={'request','ack'}:raise Rejected('WRITER_INPUT')
        fact=r.parse_fact(d.parse_receipt(item['ack'],item['request'],context),context)
        req=d.parse_attempt(item['request'],context)
        if req['kind']!='DELIVERY' or fact['outcome']!='ACCEPTED':raise Rejected('WRITER_RESULT_REQUIRED')
        env=d.parse_envelope(req['body'],context);desc=d.parse_descriptor(env['descriptor'],context)
        if desc['operation'] in seen:raise Rejected('WRITER_DUPLICATE')
        seen.add(desc['operation'])
        values=list(struct.unpack('>'+'Q'*(len(env['result'])//8),env['result']))
        records.append(dict(operation=desc['operation'],delivery=desc['delivery'],seq=desc['seq'],
            values=values,event_at=fact['event_at'],descriptor_hash=fact['descriptor_hash'].hex()))
    if seen!=set(expected_operations):raise Rejected('WRITER_OPERATION_SET')
    records.sort(key=lambda x:x['seq'])
    text='已授权统计报告（合成演示）\n'+'\n'.join(x['operation']+': '+json.dumps(x['values']) for x in records)
    return {'records':records,'report_text':text,'input_policy':'Authenticated accepted envelopes only; no raw snapshot input.'}


def run_scenario(*, sender_type=TLSRetentionSender, provision=populate):
    # Trusted harness dependencies, not untrusted endpoint configuration. The
    # default preserves the original fixture scenario and its evidence scope.
    events=[];network={'sender_witness':0,'receiver_witness':0,'delivery':0};versions=set();lock=threading.Lock()
    draws={};now=100
    def record(stage,**details):events.append(dict(stage=stage,**details))
    with tempfile.TemporaryDirectory(prefix='agent-p2-') as td:
        root=Path(td);certs=certificates(root);c,s,k=context()
        c=dict(c,sender_cert=certificate_fingerprint(certs['writer'][0]),receiver_cert=certificate_fingerprint(certs['server'][0]))
        keys={'sender_witness':Ed25519PrivateKey.generate(),'receiver_witness':Ed25519PrivateKey.generate()}
        paths={name:root/name for name in keys}
        for name,ns in [('sender_witness',c['sender_authority'].hex()),('receiver_witness',c['receiver_authority'].hex())]:
            trusted_register_peer(paths[name],ns,certificate_fingerprint(certs['admin'][0]),'admin')
        with WitnessTLSService(paths['sender_witness'],cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signing_key=keys['sender_witness']) as sws,\
             WitnessTLSService(paths['receiver_witness'],cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signing_key=keys['receiver_witness']) as rws:
            services={'sender_witness':sws,'receiver_witness':rws}
            def client(name):
                value=TLSWitnessClient(port=services[name].port,cafile=certs['ca'],certfile=certs['admin'][0],keyfile=certs['admin'][1],witness_public_key=public(keys[name]))
                original=value.exchange
                def exchange(raw,body):
                    with lock:network[name]+=1
                    result=original(raw,body)
                    if value.last_tls_version:
                        with lock:versions.add(value.last_tls_version)
                    return result
                value.exchange=exchange;return value
            sender_path=root/'sender';inbox_path=root/'inbox'
            def open_sender():return sender_type(sender_path,clock=lambda:now,vault=vault(),witness=client('sender_witness'))
            def inbox():return TLSRetentionRecipient(inbox_path,context=c,vault=recipient_vault(),clock=lambda:now,witness=client('receiver_witness'))
            sender=provision(sender_type.create(sender_path,clock=lambda:now,vault=vault(),witness=client('sender_witness')))
            created=TLSRetentionRecipient.create(inbox_path,context=c,vault=recipient_vault(),clock=lambda:now,witness=client('receiver_witness'));created.close()
            try:
                h=sender.register_context(c)
                specs=[('analysis_hist','leaf',True),('analysis_count','other',False)]
                chains={oid:chain_fixture(sender,root_cap=2,child_cap=2,leaf_id=subject+'grant',subject=subject) for oid,subject,_ in specs}
                packets={oid:packet(sender,chains[oid],oid,hist) for oid,_,hist in specs}
                record('user_authorization',root='root',delegation_depth=2,analysis_subjects=['leaf','other'],shared_ancestor_cost_units=2)
                barrier=threading.Barrier(2)
                def register(spec):
                    oid,subject,hist=spec;l=open_sender()
                    try:barrier.wait(timeout=10);l.register_delegated(*packets[oid],chains[oid]);return {'operation':oid,'subject':subject}
                    finally:l.close()
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:registrations=list(pool.map(register,specs))
                assert len(registrations)==2
                record('concurrent_shared_admission',registered=registrations,operation_count=sender.db.execute('SELECT count(*) FROM operations').fetchone()[0])
                extra=packet(sender,chains['analysis_count'],'over_budget',False)
                try:sender.register_delegated(*extra,chains['analysis_count']);raise AssertionError('budget bypass')
                except Rejected as exc:assert str(exc)=='BUDGET_EXHAUSTED'
                record('shared_cap_blocks_third_query',error='BUDGET_EXHAUSTED')
                original_random=sender_type.operation_randomness
                def randomness(instance,op):
                    draws[op['id']]=draws.get(op['id'],0)+1;return original_random(instance,op)
                lost=False;retry_equal=False;lost_tick=None
                with patch.object(sender_type,'operation_randomness',randomness):
                    while sender.db.execute('SELECT 1 FROM jobs WHERE publication IS NULL').fetchone():
                        tick=sender.db.execute('SELECT tick FROM schedulers').fetchone()[0];request_id='scenario-tick-'+str(tick)
                        result_written=[False]
                        def fault(point):
                            if point=='after_scheduled_result_write':result_written[0]=True
                            if point=='after_tick_commit' and result_written[0] and not lost:raise ConnectionError('lost committed scheduler reply')
                        try:sender.advance('t','domain',request_id,tick,fault=fault)
                        except ConnectionError:
                            assert not lost and result_written[0];lost=True;lost_tick=tick
                            before={x['id']:(sender.op('t',x['id'])['seed'],sender.op('t',x['id'])['result']) for x in sender.db.execute("SELECT id FROM operations WHERE state='COMMITTED'")}
                            accounting=[tuple(x) for x in sender.db.execute('SELECT * FROM accounts ORDER BY id')]
                            sender.close();sender=open_sender()
                            reply=sender.advance('t','domain',request_id,tick)
                            retry_equal=reply['tick']==tick+1 and all((sender.op('t',oid)['seed'],sender.op('t',oid)['result'])==value for oid,value in before.items())
                            assert retry_equal and accounting==[tuple(x) for x in sender.db.execute('SELECT * FROM accounts ORDER BY id')]
                            record('committed_reply_loss_and_retry',logical_tick=tick+1,fixed_seed_and_result=True,no_recharge=True)
                assert lost and retry_equal and draws=={'analysis_hist':1,'analysis_count':1}
                raw_outputs={oid:sender.op('t',oid)['result'] for oid,_,_ in specs}
                assert {oid:len(value) for oid,value in raw_outputs.items()}=={'analysis_hist':32,'analysis_count':8}
                tickets=[]
                for row in sender.db.execute('SELECT operation_id FROM jobs ORDER BY seq').fetchall():
                    tickets.append(sender.admit_v2(h,'deliver-'+row['operation_id'],row['operation_id']))
                record('committed_outputs_then_delivery_admission',tickets=len(tickets),randomness_draws=dict(draws))
                evidence=[]
                with RecipientTLSService(inbox_factory=inbox,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signer=k) as service:
                    transport=DeliverySender(port=service.port,cafile=certs['ca'],certfile=certs['writer'][0],keyfile=certs['writer'][1],signer=s)
                    def exchange(req):
                        network['delivery']+=1
                        try:return transport.exchange(req,c)
                        finally:
                            if transport.last_tls_version:versions.add(transport.last_tls_version)
                    first=tickets[0];env=sender.prepare_envelope('t',first['id'],s);req=d.attempt('DELIVERY',env,b'a'*32,c,s)
                    def lose_ack(point):
                        if point=='before_ack_send':raise ConnectionError('lost recipient reply')
                    service.fault=lose_ack
                    try:exchange(req);raise AssertionError('expected dropped acknowledgement')
                    except OSError:pass
                    service.fault=lambda point:None
                    sender.revoke_credential('t','workergrant')
                    try:sender.admit_v2(h,'forbidden-after-revoke',specs[0][0]);raise AssertionError('revocation bypass')
                    except Rejected as exc:revoked_error=str(exc);assert revoked_error=='ACTION_OR_KEY_INACTIVE'
                    record('revocation_blocks_new_delivery',error=revoked_error,old_admitted_tickets_retained=True)
                    same=sender.prepare_envelope('t',first['id'],s);assert same==env
                    req=d.attempt('DELIVERY',same,b'b'*32,c,s);ack=exchange(req);sender.confirm('t',first['id'],req,ack)
                    assert r.parse_fact(d.parse_receipt(ack,req,c),c)['event_at']==100
                    evidence.append(dict(request=req,ack=ack))
                    for row in tickets[1:]:
                        raw=sender.prepare_envelope('t',row['id'],s);req=d.attempt('DELIVERY',raw,b'c'*32,c,s);ack=exchange(req)
                        sender.confirm('t',row['id'],req,ack);evidence.append(dict(request=req,ack=ack))
                    record('original_results_delivered',accepted=len(evidence),lost_receipt_retry_preserved_first_time=True)
                    writer=writer_report(c,evidence,[x[0] for x in specs])
                    for entry in writer['records']:assert struct.pack('>'+'Q'*len(entry['values']),*entry['values'])==raw_outputs[entry['operation']]
                    record('writer_uses_only_authenticated_outputs',input_count=len(evidence),raw_snapshot_arguments=0)
                    offer=sender.prepare_retirement(h,2,s);req=r.retire_attempt(offer,b'r'*32,c,s);ack=exchange(req);sender.confirm_retirement(h,req,ack)
                    v=ArchiveVerifier(c,req,ack,1);v.accept(archive_page(sender,h,req,ack,1));assert r.parse_fact(v.result(),c)['delivery']==tickets[0]['id']
                accounts={row['id']:dict(row) for row in sender.db.execute('SELECT * FROM accounts')}
                common={'domain:epsilon':2*E,'domain:delta':2*D}
                for wire in chains[specs[0][0]][:2]:common.update(dict(zip(cap_accounts(wire),(2*E,2*D))))
                for chain in chains.values():common.update(dict(zip(cap_accounts(chain[-1]),(E,D))))
                assert all(accounts[a]['spent']==cost and accounts[a]['reserved']==0 for a,cost in common.items())
                assert sender.db.execute('SELECT count(*) FROM charges').fetchone()[0]==16
                assert sender.audit()==[]
                checked=inbox()
                try:assert checked.audit()==[] and checked.live_facts()==[];receiver_floor=checked.state()['floor']
                finally:checked.close()
                record('audit_matches_consumption_and_output',charged_operations=2,charge_rows=16,checked_accounts=len(common),receiver_retired_floor=receiver_floor)
                result=dict(passed=True,scenario='P2 integrated reference workflow',roles='Two signed concurrent Python analysis drivers and pure writer adapter; no live LLM or OS isolation claim.',
                    events=events,network_requests=network,observed_tls_versions=sorted(versions),randomness_draws=draws,
                    committed_reply_loss_tick=lost_tick+1,writer=writer,
                    budget=dict(domain_epsilon_spent=2*E,domain_delta_spent=2*D,shared_ancestor_units=2,charged_operations=2,charge_rows=16,checked_accounts=len(common)),
                    full_p2_production_acceptance=False,public_observation_proof=False,strong_baselines=False,
                    trust='Synthetic snapshots/keys, fixture-supplied input contribution bounds, same-host independent authority files/services, nonrollback assumed. No public identity provisioning or complete Agent-facing API.')
                return result,{'context':c,'evidence':evidence,'expected_operations':[x[0] for x in specs]}
            finally:sender.close()


if __name__=='__main__':
    report,_=run_scenario()
    Path(__file__).with_name('p2_scenario_results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False,indent=2))
