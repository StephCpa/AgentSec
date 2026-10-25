"""Paired actual-runtime application-wire traces, not a general DP proof.

Eight fixed-roster subsets and public control plans use valid K40 tapes chosen
so each successful count output is 1. Trace equality is conditional evidence,
not exhaustive distributions or cryptographic/physical noninterference.
"""
import hashlib
import json
from pathlib import Path
import secrets
import tempfile
from unittest.mock import patch

from public_gateway import PublicGatewayLedger
from public_gateway_transport import PublicGatewayTLSService,PublicGatewayClient
from test_public_gateway import configure,make_request,parse_reply,SERVER_KEY,SERVER_KID,PEER,SERVER_CERT
from test_encrypted_mixed_ledger import vault
from test_mixed_delegated_ledger import chain_fixture,packet,tick
from test_retention_sender import context
from test_retention_recipient import recipient_vault
from test_witness_transport import public
from witness_transport import certificate_fingerprint
from contribution_scenario import USERS
from retention_recipient import RetentionRecipient
from witnessed_ledger import ReferenceWitness
from ledger import Rejected
import retention_delivery as delivery


def seed_for_output_one(count):
    seed=bytearray(32)
    for side,n in [(0,max(1-count,0)),(1,max(count-1,0))]:
        for j in range(n):
            index=side*40+j;seed[index//8]|=1<<(7-index%8)
    return bytes(seed)


def run_trace(mask,scenario='normal',*,network_fault=None,certs=None):
    if not 0<=mask<8 or scenario not in ('normal','cancel_before','cancel_after','pause'):raise ValueError('invalid fixture')
    if network_fault is not None and (scenario!='normal' or certs is None):raise ValueError('network counterexample requires normal fixture and certificates')
    slots=[(mask>>i)&1 for i in range(3)];records=[(u,slots[i]) for i,u in enumerate(USERS)]
    trace=[];decoded=[];counter=[0];output=None;steps=0
    with tempfile.TemporaryDirectory() as td:
        p=Path(td);lp=p/'db';wp=p/'w';w=ReferenceWitness(wp)
        peer=PEER if certs is None else certificate_fingerprint(certs['writer'][0])
        pin=SERVER_CERT if certs is None else certificate_fingerprint(certs['server'][0])
        with patch('test_atomic_publication.RECORDS',records):l=configure(PublicGatewayLedger.create(lp,clock=lambda:100,vault=vault(),witness=w),peer,pin)
        try:
            def call(method,payload,actor='leaf'):
                counter[0]+=1;raw=make_request(method,payload,counter[0],actor)
                reply=l.handle_public(raw,peer,SERVER_KEY);out=parse_reply(reply,raw)
                trace.append(['PUBLIC',raw.hex(),reply.hex()]);decoded.append(dict(method=method,status=out['status'],body=out['body']))
                return out
            original_token=secrets.token_bytes
            with patch('signed_ledger.secrets.token_bytes',side_effect=lambda n:b'C'*32 if n==32 else original_token(n)):
                challenge=call('CHALLENGE',{})['body']
            chain=chain_fixture(l)
            with patch.object(l,'issue_challenge',return_value=challenge):raw,proof=packet(l,chain,'a',False,proof_id=b'Q'*16)
            call('SUBMIT',dict(action=raw,proof=proof,chain=chain));call('POLL',dict(operation='a'))
            # An authenticated malformed input is itself public and must not
            # branch on private data or consume a proof/operation.
            call('POLL',dict(operation=[]))
            if scenario=='cancel_before':call('CONTROL',dict(kind='cancel',operation='a'))
            with patch.object(l,'operation_randomness',return_value=seed_for_output_one(sum(slots))):
                while l.db.execute('SELECT 1 FROM jobs WHERE publication IS NULL').fetchone():
                    tick(l);steps+=1
                    if steps in (1,3,40,84):call('POLL',dict(operation='a'))
                    if steps==1:
                        if scenario=='cancel_after':call('CONTROL',dict(kind='cancel',operation='a'))
                        if scenario=='pause':call('CONTROL',dict(kind='pause'),'manager')
                    if steps==4 and scenario=='pause':call('CONTROL',dict(kind='resume'),'manager')
            call('POLL',dict(operation='a'));call('FINAL',dict(cursor=0,limit=16))
            decision=l.decisions_internal('t','domain')[0]
            if decision['kind']=='ADMITTED':
                c,s,k=context();env=l.prepare_envelope('t',decision['delivery_id'],s)
                output=int.from_bytes(delivery.parse_envelope(env,c)['result'],'big')
                if output!=1:raise AssertionError('invalid coupled mechanism tape')
                req=delivery.attempt('DELIVERY',env,b'R'*32,c,s);rw=ReferenceWitness(p/'rw')
                i=RetentionRecipient.create(p/'inbox',context=c,vault=recipient_vault(),clock=lambda:100,witness=rw)
                try:ack=i.accept(req,c['sender_cert'],k);l.confirm('t',decision['delivery_id'],req,ack)
                finally:i.close();rw.close()
                trace.append(['DELIVERY',req.hex(),ack.hex()])
            call('FINAL',dict(cursor=0,limit=16))
            if l.audit():raise AssertionError('runtime audit failed')
            network_outcome=None
            if network_fault is not None:
                # Deliberately unsafe negative controls. The production handler
                # does not inspect this bit. Both runs already released output 1.
                def factory():
                    authority=ReferenceWitness(wp);obj=PublicGatewayLedger(lp,clock=lambda:100,vault=vault(),witness=authority)
                    dispatch=obj._dispatch
                    def altered(request,rights):
                        if request['method']=='POLL' and slots[0]:
                            if network_fault=='private_failure':raise Rejected('STORAGE_INTEGRITY')
                            if network_fault=='private_policy_alias':raise Rejected('GW_PAYLOAD')
                        return dispatch(request,rights)
                    obj._dispatch=altered;close=obj.close
                    def closed():close();authority.close()
                    obj.close=closed;return obj
                with PublicGatewayTLSService(ledger_factory=factory,cafile=certs['ca'],certfile=certs['server'][0],keyfile=certs['server'][1],signer=SERVER_KEY) as service:
                    client=PublicGatewayClient(port=service.port,cafile=certs['ca'],certfile=certs['writer'][0],keyfile=certs['writer'][1],server_certificate=pin,server_public_key=public(SERVER_KEY),server_kid=SERVER_KID,deployment=vault().deployment_id)
                    counter[0]+=1;raw=make_request('POLL',dict(operation='a'),counter[0])
                    try:
                        reply=client.exchange(raw);out=parse_reply(reply,raw);network_outcome=out['status'];trace.append(['PUBLIC_NETWORK',raw.hex(),reply.hex()])
                    except OSError:
                        network_outcome='CONNECTION_CLOSED';trace.append(['PUBLIC_NETWORK',raw.hex(),'CONNECTION_CLOSED'])
                    tls=client.last_tls_version
            else:tls=None
            encoded=json.dumps(trace,separators=(',',':')).encode()
            return dict(mask=mask,scenario=scenario,output=output,logical_steps=steps,trace=trace,
                        trace_sha256=hashlib.sha256(encoded).hexdigest(),public_events=decoded,
                        application_records=len(trace),network_outcome=network_outcome,tls_version=tls)
        finally:l.close();w.close()
