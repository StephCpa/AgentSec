"""Actual child-process cuts and R1--R9 recovery-boundary correspondence.

Public requests only: no crash during private mechanism work, recipient handling
or recovery itself. The witness is a separate SQLite reference file, not an
independent host or a production nonrollback authority. All fixtures synthetic.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from unittest.mock import patch

from constructive_trace import FixtureSigningOracle,RecordingRuntime
from delivery_state_relation import assert_delivery_relation
from mixed_delegated_ledger import parse_mixed_action
from public_gateway import PublicGatewayLedger,parse_request
from public_trace_adapter import PublicTraceAdapter
from recovery_simulator import RecoverySimulator,CUTS,DURABLE_CUTS
from state_relation import assert_state_relation,digest,StateRelationMismatch
from stepwise_trace import ObservedRecords
from test_public_gateway import SERVER_KEY,PEER
from test_mixed_delegated_ledger import chain_fixture,packet
from test_encrypted_mixed_ledger import vault
from witnessed_ledger import ReferenceWitness,image_hash,Rejected
from wire import encode

PLANS=('challenge','submit','histogram_submit','cancel_before_l1','cancel_after_l1',
       'denied_poll','expired_submit','exact_retry','final_page')
EXIT_CODE=93


def applicable_cuts(plan):
    # Cached retries return inside the transaction, before new-dispatch hooks.
    return CUTS[2:] if plan=='exact_retry' else CUTS


def child(config):
    cfg=json.loads(Path(config).read_text())
    def stop(point):
        if point==cfg['cut']:os._exit(EXIT_CODE)
    witness=ReferenceWitness(cfg['witness'])
    ledger=PublicGatewayLedger(cfg['ledger'],clock=lambda:cfg['at'],vault=vault(),witness=witness,witness_fault=stop)
    coin=bytes.fromhex(cfg['challenge_coin']);token=secrets.token_bytes
    with patch('signed_ledger.secrets.token_bytes',side_effect=lambda n:coin if n==32 and coin else token(n)):
        ledger.handle_public(bytes.fromhex(cfg['request']),bytes.fromhex(cfg['peer']),SERVER_KEY,stop)
    if cfg['cut']=='response_drop':os._exit(EXIT_CODE)
    raise RuntimeError('configured process cut was not reached')


class RecoveryRuntime(RecordingRuntime):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.signer=FixtureSigningOracle();self.simulator=RecoverySimulator(self.cfg,{},self.signer)
        self.checkpoints=[];self.armed=None;self.cut_diagnostics=[];self.restorations=0
        self.records=ObservedRecords(self._observe)
        self.checkpoints.append(dict(index=0,kind='INITIAL',relation=self.relation()))

    def relation(self):
        return dict(**assert_state_relation(self,self.simulator.state),**assert_delivery_relation(self,self.simulator))

    def _observe(self,actual):
        command=self.commands[len(self.simulator.records)]
        if command['kind'] in ('PUBLIC','PUBLIC_CUT'):
            obj=parse_request(bytes.fromhex(command['request']))
            if obj['method']=='SUBMIT':
                action=parse_mixed_action(obj['payload']['action']);width=action['bucket_count'] if action['operation_kind']=='histogram' else 1
                self.simulator.state.oracle.setdefault(action['operation'],(self.target,)+(0,)*(width-1))
        with patch('sqlite3.connect',side_effect=AssertionError('generator DB access')),patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('generator runtime access')),patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('observed response generator')):
            generated=self.simulator.emit(command)
        if generated!=actual:raise AssertionError('recovery transcript differs at '+str(len(self.records)))
        # A crashed replica may lag the authoritative state. Do not falsely
        # require local R1--R8 until restore; check explicit R9 skew instead.
        relation={'R9':digest(self.cut_diagnostics[-1])} if command['kind']=='PUBLIC_CUT' else self.relation()
        if command['kind']=='RECOVER':relation['R9']=digest(dict(restored=True,head_unchanged=True,image_equal=True))
        self.checkpoints.append(dict(index=len(self.simulator.records),kind=command['kind'],relation=relation))

    def arm(self,method,cut,retry_at=None):
        if self.armed is not None:raise ValueError('already armed')
        self.armed=dict(method=method,cut=cut,retry_at=retry_at)

    def exchange(self,raw,peer=PEER):
        obj=parse_request(raw)
        if self.armed is not None and obj['method']==self.armed['method']:
            armed=self.armed;self.armed=None
            coin=hashlib.sha256(('public-challenge:'+str(int.from_bytes(obj['request_id'],'big'))).encode()).hexdigest() if obj['method']=='CHALLENGE' else ''
            command=dict(kind='PUBLIC_CUT',at=self.now,request=raw.hex(),peer=peer.hex(),challenge_coin=coin,cut=armed['cut'])
            self.commands.append(command);self.process_cut(command)
            self.records.append(dict(kind='PUBLIC_UNAVAILABLE',at=self.now,request=raw.hex(),peer=peer.hex()))
            if armed['retry_at'] is not None:self.now=armed['retry_at']
            self.restore()
        return super().exchange(raw,peer)

    def process_cut(self,command):
        before=self.w.head(self.l.namespace);old_path=self.l.path;ns=self.l.namespace
        self.l.close()
        cfg=dict(command,ledger=str(old_path),witness=str(self.w.path))
        path=self.directory/'cut.json';path.write_text(json.dumps(cfg))
        proc=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--child',str(path)],capture_output=True,text=True,timeout=30)
        self.l=PublicGatewayLedger(old_path,clock=lambda:self.now,vault=vault(),witness=self.w)
        if proc.returncode!=EXIT_CODE:raise AssertionError('process cut failed: '+str(proc.returncode)+' '+proc.stderr[-1000:])
        after=self.w.head(ns,True);head={k:after[k] for k in ('seq','digest')};durable=command['cut'] in DURABLE_CUTS
        if head['seq']!=before['seq']+int(durable):raise AssertionError('R9.witness_sequence')
        if image_hash(after['image'])!=head['digest']:raise AssertionError('R9.witness_image')
        if not durable and head!=before:raise AssertionError('R9.precommit_head_changed')
        local=self.l.local_anchor();expected=head if command['cut']=='response_drop' else before
        if local!=expected or image_hash(self.l.state_image())!=local['digest']:raise AssertionError('R9.local_atomicity')
        stale=local!=head
        try:self.l.check_current_state()
        except Rejected as exc:
            if not stale or str(exc)!='WITNESS_RECOVERY_REQUIRED':raise
        else:
            if stale:raise AssertionError('R9.stale_guard_not_closed')
        # Do not put private image hashes/sequence numbers into public events or
        # simulator inputs. These diagnostic booleans are dataset-independent.
        self.cut_diagnostics.append(dict(cut=command['cut'],exit_code=proc.returncode,
            witness_advanced=durable,local_committed=command['cut']=='response_drop',stale_guard_blocked=stale))

    def restore(self):
        self.commands.append(dict(kind='RECOVER',at=self.now));self.restorations+=1
        before=self.w.head(self.l.namespace,True);old=self.l
        restored=PublicGatewayLedger.restore_new(self.directory/('restored-'+str(self.restorations)),clock=lambda:self.now,vault=vault(),witness=self.w)
        try:
            if restored.state_image()!=before['image'] or restored.audit():raise AssertionError('R9.restore_state')
            if self.w.head(restored.namespace,True)!=before:raise AssertionError('R9.restore_advanced_witness')
        except BaseException:restored.close();raise
        old.close();self.l=restored
        self.records.append(dict(kind='RECOVER',at=self.now))

    def submit(self,oid='a',hist=False,root='root',allow_expired=False):
        if root!='root':raise ValueError('single-root recovery profile')
        challenge=self.call('CHALLENGE',{})['body'];chain=chain_fixture(self.l)
        # Same public proof ID in every conditioned dataset execution. The
        # general test bundle helper otherwise chooses a fresh random ID.
        with patch.object(self.l,'issue_challenge',return_value=challenge):
            action,proof=packet(self.l,chain,oid,hist,proof_id=self.rid.to_bytes(16,'big'))
        payload=dict(action=action,proof=proof,chain=chain)
        result=self.call('SUBMIT',payload)
        self.kinds[oid]=hist;self.oracle[oid]=(self.target,0,0,0) if hist else (self.target,)
        if result['status']!='RECORDED' and not allow_expired:raise AssertionError(result)
        return result

    def checked(self):
        if self.armed is not None or self.simulator.needs_recovery:raise AssertionError('unfinished recovery scenario')
        if self.l.audit():raise AssertionError('sender audit')
        for inbox,_ in self.receivers.values():
            if inbox.audit():raise AssertionError('receiver audit')
        model=self.simulator.state
        if model.draws!=[(oid,kind) for oid,kind,_ in self.runtime_draws]:raise AssertionError('L1 draws differ')
        if len(model.final)!=len(model.jobs):raise AssertionError('unfinished final prefix')
        self.relation()
        return dict(draws=model.draws,final=deepcopy(model.final),journal_requests=model.journal_seq,
                    ticks=model.tick,mechanism_calls=deepcopy(model.mechanism_calls))


def run_recovery(plan,cut,mask=3):
    if plan not in PLANS or cut not in applicable_cuts(plan) or type(mask) is not int or not 0<=mask<8:raise ValueError('outside recovery profile')
    with tempfile.TemporaryDirectory() as td:
        r=RecoveryRuntime(td,mask)
        try:
            if plan=='challenge':r.arm('CHALLENGE',cut)
            if plan in ('submit','histogram_submit','expired_submit'):r.arm('SUBMIT',cut,161 if plan=='expired_submit' else None)
            out=r.submit(hist=plan=='histogram_submit',allow_expired=plan=='expired_submit')
            submit_raw=bytes.fromhex(r.records[-1]['request'])
            if plan in ('cancel_before_l1','cancel_after_l1'):
                if plan=='cancel_after_l1':r.advance()
                r.arm('CONTROL',cut);r.call('CONTROL',dict(kind='cancel',operation='a'))
            elif plan=='denied_poll':
                r.arm('POLL',cut);r.call('POLL',dict(operation=[]))
            elif plan=='exact_retry':
                r.arm('SUBMIT',cut,retry_at=161);r.exchange(submit_raw)
            r.finish()
            # Publication rows use RELEASE internally; the signed decision
            # vocabulary is ADMITTED. Deliver immediately at publication time.
            if any(d['kind']=='ADMITTED' for d in r.l.decisions_internal('t','domain')):r.deliver()
            if plan=='final_page':r.arm('FINAL',cut)
            r.call('FINAL',dict(cursor=0,limit=1))
            check=r.checked()
            return dict(plan=plan,cut=cut,mask=mask,config_cbor_hex=encode(r.cfg).hex(),approved_outputs=r.oracle,
                commands=r.commands,expected_records=list(r.records),checkpoints=r.checkpoints,
                signing_calls=r.signer.calls,diagnostics=r.cut_diagnostics,check=check,submit_status=out['status'])
        finally:r.close()


def main():
    import argparse,gzip
    parser=argparse.ArgumentParser();parser.add_argument('--child',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.child:return child(args.child)
    if args.output is None or args.output.exists():parser.error('choose a new output directory')
    args.output.mkdir(parents=True)
    report=dict(profile='public-request-recovery-v1',passed=False,cases=[],
        source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},
        scope='Dataset-independent explicit process cuts in public RPCs and fresh sender restore; no TICK/receiver/recovery crash, arbitrary concurrency, TLS failure mapping, timing or power-loss proof.')
    with (args.output/'cases.jsonl.gz').open('wb') as f,gzip.GzipFile(fileobj=f,mode='wb',mtime=0) as archive:
        for plan in PLANS:
            for cut in applicable_cuts(plan):
                reference=None
                for mask in range(8):
                    case=run_recovery(plan,cut,mask)
                    fingerprint=digest(dict(records=case['expected_records'],checkpoints=case['checkpoints']))
                    if reference is None:reference=fingerprint
                    if fingerprint!=reference:raise AssertionError('conditional recovery trace/relation differs')
                    report['cases'].append(dict(plan=plan,cut=cut,mask=mask,trace_sha256=digest(case['expected_records']),
                        correspondence_sha256=fingerprint,records=len(case['expected_records']),checkpoints=len(case['checkpoints']),
                        check=case['check'],submit_status=case['submit_status']))
                    archive.write((json.dumps(case,separators=(',',':'))+'\n').encode())
                print('PASS',plan,cut,'8 datasets',flush=True)
    report.update(passed=True,cases_count=len(report['cases']),groups_count=len(report['cases'])//8,
                  process_exits=len(report['cases']),restores=len(report['cases']),directed_neighbor_comparisons=3*len(report['cases']),
                  checkpoints_count=sum(x['checkpoints'] for x in report['cases']))
    (args.output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
