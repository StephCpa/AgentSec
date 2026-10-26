import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519
import test_delivery_transport as base
from delivery_terminal import (TerminalDeliveryLedger,TerminalRecipientInbox,TerminalDeliverySender,Rejected,
    terminal_attempt,parse_terminal_attempt,parse_control,parse_receipt,PROFILE,CONTROL_TYPE,RECEIPT_TYPE)
from delivery_transport import (DeliveryLedger,RecipientInbox,StateVault,attempt,parse_envelope,ENVELOPE_TYPE,ACK_TYPE,public)
from witness_transport import TLSWitnessClient
from test_encrypted_ledger import vault
from wire import encode,decode,sign1,verify_sign1

CRASHES=[]


def child(config_path,point):
    c=json.loads(Path(config_path).read_text());route=base.unpack_route(c['route'])
    def fault(here):
        if here==point:os._exit(98)
    if 'inbox_terminal' in point:
        i=TerminalRecipientInbox(c['inbox'],deployment=c['namespace'],route=route,vault=StateVault(bytes.fromhex(c['inbox_key']),b'inbox-fixture-01'),clock=lambda:160)
        i.accept(bytes.fromhex(c['request']),route['sender_cert'],ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['receiver_key'])),fault)
    else:
        w=TLSWitnessClient(port=c['port'],cafile=c['ca'],certfile=c['cert'],keyfile=c['cert_key'],witness_public_key=bytes.fromhex(c['witness_key']))
        l=TerminalDeliveryLedger(c['ledger'],clock=lambda:160,vault=vault(),witness=w)
        if 'receipt_commit' in point:l.confirm_terminal('t','d',bytes.fromhex(c['request']),bytes.fromhex(c['receipt']),fault)
        else:l.prepare_terminal('t','d',ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c['sender_key'])),fault)
    raise RuntimeError('crash cut not reached')


class TerminalTests(unittest.TestCase):
    ledger_class=TerminalDeliveryLedger
    inbox_class=TerminalRecipientInbox
    sender_class=TerminalDeliverySender

    def closed_rows(self):
        i=self.inbox()
        try:return [dict(r) for r in i.db.execute('SELECT * FROM inbox_closed ORDER BY seq')]
        finally:i.close()

    def control(self):
        self.now=160
        raw,route=self.l.prepare_terminal('t','d',self.gsign)
        return raw,route

    def crash(self,point,request=b'',receipt=b''):
        config=dict(route={k:v.hex() if isinstance(v,bytes) else v for k,v in self.route.items()},namespace=self.ns,
            sender_key=base.keybytes(self.gsign).hex(),receiver_key=base.keybytes(self.rsign).hex(),inbox_key=self.ivkey.hex(),inbox=str(self.ip),
            ledger=str(self.lp),port=self.ws.port,ca=str(self.certs['ca']),cert=str(self.certs['admin'][0]),cert_key=str(self.certs['admin'][1]),
            witness_key=public(self.wsign).hex(),request=request.hex(),receipt=receipt.hex())
        path=self.root/'child.json'
        with os.fdopen(os.open(str(path),os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600),'w') as f:json.dump(config,f)
        r=subprocess.run([sys.executable,__file__,'--child',str(path),point],capture_output=True,text=True,timeout=30)
        self.assertEqual(r.returncode,98,r.stderr);CRASHES.append(point);path.unlink()

    def test_unprepared_expired_ticket_closes_without_result_and_next_can_deliver(self):
        self.ticket('d',ttl=1);self.ticket('next',ttl=60);self.now=101
        before=[tuple(r) for r in self.l.db.execute('SELECT * FROM accounts')]
        self.assertEqual(self.sender.reconcile(self.l,'t','d'),'CLOSED')
        row=self.l.outbox('t','d');self.assertIsNone(row['envelope']);self.assertFalse(self.inbox_rows())
        self.assertEqual([r['seq'] for r in self.closed_rows()],[1])
        self.assertEqual(self.sender.deliver(self.l,'t','next'),'ACKED')
        self.assertEqual([r['seq'] for r in self.inbox_rows()],[2]);self.assertEqual(self.l.audit(),[])
        self.assertEqual([tuple(r) for r in self.l.db.execute('SELECT * FROM accounts')],before)

    def test_lost_delivery_ack_reconciles_after_expiry_without_retransmitting_result(self):
        raw,route=self.prepared();request=attempt(raw,b'a'*32)
        self.sender.exchange(request,route);self.now=160
        original=self.sender.exchange;requests=[]
        def inspect(packet,route):
            obj=parse_terminal_attempt(packet);control=parse_control(obj['terminal'],self.ns,route)
            self.assertNotIn('result',control);self.assertNotIn('envelope',obj)
            self.assertEqual(control['envelope_hash'],hashlib.sha256(raw).digest());requests.append(packet)
            return original(packet,route)
        with patch.object(self.sender,'exchange',side_effect=inspect):self.assertEqual(self.sender.reconcile(self.l,'t','d'),'ACKED')
        self.assertEqual(len(requests),1);self.assertEqual(len(self.inbox_rows()),1);self.assertFalse(self.closed_rows())
        self.assertEqual(self.l.delivery_status('t','d'),'ACKED');self.assertEqual(self.l.audit(),[])

    def test_prepared_but_unsent_expires_to_closed_and_fences_late_arrival(self):
        raw,route=self.prepared();self.now=160
        self.assertEqual(self.sender.reconcile(self.l,'t','d'),'CLOSED')
        i=self.inbox()
        try:self.reject('DELIVERY_CLOSED',lambda:i.accept(attempt(raw,b'b'*32),route['sender_cert'],self.rsign))
        finally:i.close()
        with patch.object(self.sender,'exchange',side_effect=AssertionError('send after closure')):
            self.assertEqual(self.sender.deliver(self.l,'t','d'),'CLOSED');self.assertEqual(self.sender.reconcile(self.l,'t','d'),'CLOSED')
        self.assertEqual(self.l.audit(),[])

    def test_no_close_before_expiry_at_either_endpoint(self):
        self.ticket();self.reject('TERMINAL_NOT_EXPIRED',lambda:self.l.prepare_terminal('t','d',self.gsign))
        raw,route=self.control();self.now=159;i=self.inbox()
        try:self.reject('TERMINAL_NOT_EXPIRED',lambda:i.accept(terminal_attempt(raw,b'c'*32),route['sender_cert'],self.rsign))
        finally:i.close()
        self.assertFalse(self.closed_rows())

    def test_early_recipient_rejection_preserves_monotonic_floor(self):
        self.ticket();raw,route=self.control();self.now=159;i=self.inbox()
        try:
            self.reject('TERMINAL_NOT_EXPIRED',lambda:i.accept(terminal_attempt(raw,b'c'*32),route['sender_cert'],self.rsign))
            self.now=158
            self.reject('INBOX_CLOCK_ROLLBACK',lambda:i.accept(terminal_attempt(raw,b'd'*32),route['sender_cert'],self.rsign))
        finally:i.close()

    def test_terminal_ack_loss_is_idempotent_and_retains_first_closure_time(self):
        self.ticket();self.now=160
        def fault(point):
            if point=='before_ack_send':raise ConnectionError('lost terminal ACK')
        self.rs.fault=fault
        with self.assertRaises(OSError):self.sender.reconcile(self.l,'t','d')
        self.assertEqual(len(self.closed_rows()),1);self.assertEqual(self.l.terminal('t','d')['state'],'PREPARED')
        self.rs.fault=lambda point:None;self.now=170;self.reopen()
        self.assertEqual(self.sender.reconcile(self.l,'t','d'),'CLOSED');self.assertEqual(self.closed_rows()[0]['closed_at'],160)
        self.assertEqual(self.l.audit(),[])

    def test_concurrent_close_requests_create_one_tombstone(self):
        self.ticket();raw,route=self.control()
        def send(_):return self.sender.exchange(terminal_attempt(raw,os.urandom(32)),route)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:receipts=list(pool.map(send,range(6)))
        self.assertEqual(len(receipts),6);self.assertEqual(len(self.closed_rows()),1)
        self.assertEqual(self.sender.reconcile(self.l,'t','d'),'CLOSED')

    def test_acceptance_transaction_wins_before_concurrent_close(self):
        envelope,route=self.prepared();raw,_=self.control();entered=threading.Event();release=threading.Event();closing=threading.Event()
        def accept():
            i=TerminalRecipientInbox(self.ip,deployment=self.ns,route=self.route,vault=StateVault(self.ivkey,b'inbox-fixture-01'),clock=lambda:100)
            def fault(point):
                if point=='before_inbox_commit':entered.set();self.assertTrue(release.wait(5))
            try:return i.accept(attempt(envelope,b'e'*32),route['sender_cert'],self.rsign,fault)
            finally:i.close()
        request=terminal_attempt(raw,b'f'*32)
        def close():
            i=self.inbox();closing.set()
            try:return i.accept(request,route['sender_cert'],self.rsign)
            finally:i.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            a=pool.submit(accept);self.assertTrue(entered.wait(5));c=pool.submit(close);self.assertTrue(closing.wait(5))
            self.assertFalse(c.done());release.set();a.result();receipt=c.result()
        ack=parse_receipt(receipt,request,raw,self.ns,route);self.assertEqual((ack['outcome'],ack['event_at']),('ACCEPTED',100))
        self.assertEqual(len(self.inbox_rows()),1);self.assertFalse(self.closed_rows())
        self.assertEqual(self.l.confirm_terminal('t','d',request,receipt),'ACKED')

    def test_closed_tombstone_blocks_resigned_future_lifetime_and_id_reuse(self):
        envelope,route=self.prepared();self.now=160;self.sender.reconcile(self.l,'t','d')
        _,obj=verify_sign1(envelope,route['sender_key'],ENVELOPE_TYPE)
        obj['issued_at']=160;obj['expires_at']=200
        for did in ('d','changed'):
            obj['delivery']=did;raw=sign1(encode(obj),route['sender_kid'],self.gsign,ENVELOPE_TYPE);i=self.inbox()
            try:self.reject('DELIVERY_CLOSED',lambda:i.accept(attempt(raw,b'g'*32),route['sender_cert'],self.rsign))
            finally:i.close()
        self.assertFalse(self.inbox_rows())

    def test_terminal_replay_context_signature_and_schema_checks(self):
        self.ticket();raw,route=self.control();request=terminal_attempt(raw,b'h'*32);receipt=self.sender.exchange(request,route)
        self.reject('TERMINAL_RECEIPT_BINDING',lambda:self.l.confirm_terminal('t','d',terminal_attempt(raw,b'i'*32),receipt))
        _,obj=verify_sign1(raw,route['sender_key'],CONTROL_TYPE)
        for key,value in [('tenant','other'),('deployment','f'*32),('session','other'),('sender_cert',b's'*32),('receiver_cert',b'r'*32)]:
            changed=dict(obj);changed[key]=value
            self.reject('TERMINAL_CONTEXT',lambda:parse_control(sign1(encode(changed),route['sender_kid'],self.gsign,CONTROL_TYPE),self.ns,route))
        for changed in (dict(obj,result=b'forbidden'),dict(obj,envelope_hash=b'x'),dict(obj,seq=0),dict(obj,expires_at=161)):
            self.reject('INVALID_TERMINAL_CONTROL',lambda:parse_control(sign1(encode(changed),route['sender_kid'],self.gsign,CONTROL_TYPE),self.ns,route))
        with self.assertRaises(Rejected):parse_control(raw[:-1]+bytes([raw[-1]^1]),self.ns,route)
        with self.assertRaises(Rejected):parse_control(sign1(encode(obj),route['sender_kid'],self.gsign,ENVELOPE_TYPE),self.ns,route)
        self.l.confirm_terminal('t','d',request,receipt)

    def test_receipt_tampering_and_impossible_outcomes_rejected(self):
        self.ticket();raw,route=self.control();request=terminal_attempt(raw,b'j'*32);receipt=self.sender.exchange(request,route)
        _,ack=verify_sign1(receipt,route['receiver_key'],RECEIPT_TYPE)
        for key,value in [('delivery','x'),('seq',2),('terminal_hash',b'x'*32),('envelope_hash',b'x'*32),('receiver_cert',b'r'*32)]:
            changed=dict(ack);changed[key]=value
            self.reject('TERMINAL_RECEIPT_BINDING',lambda:self.l.confirm_terminal('t','d',request,sign1(encode(changed),route['receiver_kid'],self.rsign,RECEIPT_TYPE)))
        for changed in (dict(ack,outcome='ABSENT'),dict(ack,event_at=159),dict(ack,outcome='ACCEPTED',event_at=100)):
            self.reject('INVALID_TERMINAL_RECEIPT',lambda:self.l.confirm_terminal('t','d',request,sign1(encode(changed),route['receiver_kid'],self.rsign,RECEIPT_TYPE)))
        self.assertEqual(self.l.terminal('t','d')['state'],'PREPARED')

    def test_no_skip_ahead_or_credential_bypass(self):
        self.ticket('d');self.ticket('d2');self.now=160
        self.reject('DELIVERY_ORDER',lambda:self.l.prepare_terminal('t','d2',self.gsign))
        raw,route=self.l.prepare_terminal('t','d',self.gsign);_,obj=verify_sign1(raw,route['sender_key'],CONTROL_TYPE)
        obj['seq']=2;obj['delivery']='d2';changed=sign1(encode(obj),route['sender_kid'],self.gsign,CONTROL_TYPE);i=self.inbox()
        try:self.reject('INBOX_ORDER',lambda:i.accept(terminal_attempt(changed,b'k'*32),route['sender_cert'],self.rsign))
        finally:i.close()
        wrong=self.sender_for('observer');self.reject('WRONG_GATEWAY_IDENTITY',lambda:wrong.reconcile(self.l,'t','d'))
        self.l.revoke_route('t','reader','gateway','session')
        self.reject('DELIVERY_ROUTE_REVOKED',lambda:self.sender.reconcile(self.l,'t','d'))
        self.assertFalse(self.closed_rows())

    def test_existing_received_result_cannot_be_declared_never_prepared_or_changed(self):
        envelope,route=self.prepared();self.sender.exchange(attempt(envelope,b'l'*32),route);raw,_=self.control()
        _,obj=verify_sign1(raw,route['sender_key'],CONTROL_TYPE)
        for changed in (dict(obj,envelope_hash=b''),dict(obj,envelope_hash=b'x'*32),dict(obj,operation='other')):
            control=sign1(encode(changed),route['sender_kid'],self.gsign,CONTROL_TYPE);i=self.inbox()
            try:self.reject('TERMINAL_DELIVERY_CONFLICT',lambda:i.accept(terminal_attempt(control,b'm'*32),route['sender_cert'],self.rsign))
            finally:i.close()
        self.assertFalse(self.closed_rows());self.assertEqual(len(self.inbox_rows()),1)

    def test_conflicting_signed_receipts_do_not_rewrite_final_outcome(self):
        self.prepared();raw,route=self.control();request=terminal_attempt(raw,b'n'*32);receipt=self.sender.exchange(request,route)
        self.l.confirm_terminal('t','d',request,receipt);_,obj=verify_sign1(receipt,route['receiver_key'],RECEIPT_TYPE)
        for changed in (dict(obj,outcome='ACCEPTED',event_at=100),dict(obj,event_at=161)):
            forged=sign1(encode(changed),route['receiver_kid'],self.rsign,RECEIPT_TYPE)
            self.reject('TERMINAL_OUTCOME_CONFLICT',lambda:self.l.confirm_terminal('t','d',request,forged))
        self.assertEqual(self.l.delivery_status('t','d'),'CLOSED')

    def test_witness_restore_preserves_closed_fence_and_next_sequence(self):
        self.ticket('d',ttl=1);self.ticket('next');backup=self.root/'old'
        db=sqlite3.connect(str(backup));self.l.db.backup(db);db.close();self.now=101
        self.sender.reconcile(self.l,'t','d');self.sender.deliver(self.l,'t','next')
        self.l.close();self.lp.write_bytes(backup.read_bytes());self.l=TerminalDeliveryLedger(self.lp,clock=lambda:self.now,vault=vault(),witness=self.wclient())
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:self.sender.reconcile(self.l,'t','d'))
        self.l.recover_from_witness();self.assertEqual(self.l.delivery_status('t','d'),'CLOSED');self.assertEqual(self.l.delivery_status('t','next'),'ACKED')
        self.assertEqual(self.l.audit(),[])
        with patch.object(self.sender,'exchange',side_effect=AssertionError('send after restore')):self.sender.deliver(self.l,'t','d')

    def test_authority_revocation_does_not_block_result_free_original_reconciliation(self):
        self.ticket();self.l.revoke_credential('t','root',root_id='root',kind='grant',issuer_kid=b'authority');self.now=160
        self.assertEqual(self.sender.reconcile(self.l,'t','d'),'CLOSED')
        self.assertFalse(self.inbox_rows());self.assertEqual(self.l.audit(),[])

    def test_witness_accepted_terminal_receipt_local_failure_recovers_without_requery(self):
        self.ticket();raw,route=self.control();request=terminal_attempt(raw,b'q'*32);receipt=self.sender.exchange(request,route)
        def fault(point):
            if point=='after_witness_accept':raise RuntimeError('local commit lost')
        self.l.witness_fault=fault
        with self.assertRaises(RuntimeError):self.l.confirm_terminal('t','d',request,receipt)
        self.assertEqual(self.l.terminal('t','d')['state'],'PREPARED');self.l.witness_fault=lambda point:None
        self.reject('WITNESS_RECOVERY_REQUIRED',lambda:self.sender.reconcile(self.l,'t','d'))
        self.l.recover_from_witness();self.assertEqual(self.l.delivery_status('t','d'),'CLOSED');self.assertEqual(self.l.audit(),[])
        with patch.object(self.sender,'exchange',side_effect=AssertionError('network after restored finality')):self.sender.reconcile(self.l,'t','d')

    def test_late_conflicting_ordinary_ack_cannot_override_closed_state(self):
        envelope,route=self.prepared();request=attempt(envelope,b'r'*32);self.now=160;self.sender.reconcile(self.l,'t','d')
        # Adversarial signer supplies a second, conflicting claimed history.
        obj=dict(profile='count-delivery-v1',deployment=self.ns,tenant='t',delivery='d',seq=1,
            envelope_hash=hashlib.sha256(envelope).digest(),challenge=b'r'*32,request_hash=hashlib.sha256(request).digest(),
            receiver_cert=route['receiver_cert'],accepted_at=100)
        ack=sign1(encode(obj),route['receiver_kid'],self.rsign,ACK_TYPE)
        self.reject('TERMINAL_OUTCOME_CONFLICT',lambda:self.l.confirm_ack('t','d',request,ack))
        self.assertEqual(self.l.delivery_status('t','d'),'CLOSED');self.assertEqual(self.l.audit(),[])

    def test_profile_downgrade_rejected(self):
        self.reject('STORAGE_PROFILE_MISMATCH',lambda:DeliveryLedger(self.lp,clock=lambda:100,vault=vault(),witness=self.wclient()))
        self.reject('INBOX_PROFILE_MISMATCH',lambda:RecipientInbox(self.ip,deployment=self.ns,route=self.route,vault=StateVault(self.ivkey,b'inbox-fixture-01'),clock=lambda:100))

    def test_actual_process_death_terminal_prepare_and_receipt_boundaries(self):
        self.ticket();self.now=160
        self.crash('before_terminal_prepare_commit');self.reopen();self.assertIsNone(self.l.terminal('t','d'))
        self.crash('after_terminal_prepare_commit');self.reopen();self.assertEqual(self.l.terminal('t','d')['state'],'PREPARED')
        raw,route=self.l.prepare_terminal('t','d',self.gsign);request=terminal_attempt(raw,b'o'*32);receipt=self.sender.exchange(request,route)
        self.crash('before_terminal_receipt_commit',request,receipt);self.reopen();self.assertEqual(self.l.terminal('t','d')['state'],'PREPARED')
        self.crash('after_terminal_receipt_commit',request,receipt);self.reopen();self.assertEqual(self.l.delivery_status('t','d'),'CLOSED')
        self.assertEqual(self.l.audit(),[])

    def test_actual_process_death_recipient_terminal_barrier(self):
        self.ticket();raw,route=self.control();request=terminal_attempt(raw,b'p'*32)
        self.crash('before_inbox_terminal_commit',request);self.assertFalse(self.closed_rows())
        self.crash('after_inbox_terminal_commit',request);self.assertEqual(len(self.closed_rows()),1)
        self.assertEqual(self.sender.reconcile(self.l,'t','d'),'CLOSED');self.assertEqual(self.l.audit(),[])


    def test_terminal_then_ordinary_ack_must_keep_same_first_acceptance_time(self):
        envelope,route=self.prepared();request=attempt(envelope,b'a'*32);ack=self.sender.exchange(request,route)
        raw,_=self.control();terminal_request=terminal_attempt(raw,b'b'*32);receipt=self.sender.exchange(terminal_request,route)
        self.l.confirm_terminal('t','d',terminal_request,receipt)
        _,obj=verify_sign1(ack,route['receiver_key'],ACK_TYPE);obj['accepted_at']=101
        contradictory=sign1(encode(obj),route['receiver_kid'],self.rsign,ACK_TYPE)
        self.reject('TERMINAL_OUTCOME_CONFLICT',lambda:self.l.confirm_ack('t','d',request,contradictory))
        self.l.confirm_ack('t','d',request,ack);self.assertEqual(self.l.audit(),[])

    def test_ordinary_ack_then_terminal_must_keep_same_first_acceptance_time(self):
        envelope,route=self.prepared();request=attempt(envelope,b'a'*32);ack=self.sender.exchange(request,route)
        raw,_=self.control();terminal_request=terminal_attempt(raw,b'b'*32);receipt=self.sender.exchange(terminal_request,route)
        self.l.confirm_ack('t','d',request,ack)
        _,obj=verify_sign1(receipt,route['receiver_key'],RECEIPT_TYPE);obj['event_at']=101
        contradictory=sign1(encode(obj),route['receiver_kid'],self.rsign,RECEIPT_TYPE)
        self.reject('TERMINAL_OUTCOME_CONFLICT',lambda:self.l.confirm_terminal('t','d',terminal_request,contradictory))
        self.l.confirm_terminal('t','d',terminal_request,receipt);self.assertEqual(self.l.audit(),[])



# Reuse only fixture/lifecycle helpers, never inherit unrelated test methods.
for name in ('setUpClass','tearDownClass','setUp','tearDown','wclient','inbox','sender_for','ticket','prepared','inbox_rows','reject','reopen'):
    setattr(TerminalTests,name,base.DeliveryTests.__dict__[name])

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':child(sys.argv[2],sys.argv[3])
    else:
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TerminalTests));p=Path(__file__).parent
        files=['delivery_terminal.py','test_delivery_terminal.py','delivery_transport.py','test_delivery_transport.py','ledger.py','dp_ledger.py','scheduled_ledger.py','signed_ledger.py','delegated_ledger.py','encrypted_ledger.py','witnessed_ledger.py','witness_transport.py','wire.py','test_witness_transport.py','test_encrypted_ledger.py','test_delegated_ledger.py','test_signed_ledger.py','../fixed_work_model.py','requirements-crypto.txt']
        report=dict(passed=result.wasSuccessful(),test_methods=result.testsRun,network_calls=base.NETWORK_CALLS,tls_versions=sorted(base.TLS_VERSIONS),actual_process_crash_cuts=CRASHES,crash_cut_count=len(CRASHES),ssl_library=ssl.OPENSSL_VERSION,python_version=sys.version,sqlite_version=sqlite3.sqlite_version,cryptography_version=cryptography.__version__,source_sha256={n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in files},failures=[(str(t),e) for t,e in result.failures],errors=[(str(t),e) for t,e in result.errors],scope='Post-expiry result-free reconciliation with atomic recipient ACCEPTED/CLOSED barrier; fixed route and honest durable nonrollback recipient assumed; not full external observation proof')
        (p/'delivery_terminal_test_results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');raise SystemExit(0 if result.wasSuccessful() else 1)
