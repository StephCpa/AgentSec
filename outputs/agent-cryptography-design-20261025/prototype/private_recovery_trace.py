"""Process-cut matrix for fixed-work private computation and exact tick retries.

Physical RNG attempts are logged separately from durable L1 transitions. The
private-prefix checker receives synthetic rows/tapes; the generator never does.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

from public_recovery_trace import RecoveryRuntime
from kernel_recovery_simulator import KernelRecoverySimulator,phase_cuts
from recovery_simulator import DURABLE_CUTS
from private_state_relation import planned_tape,assert_private_relation
from public_gateway import PublicGatewayLedger
from public_trace_adapter import PublicTraceAdapter
from state_relation import digest,StateRelationMismatch
from test_encrypted_mixed_ledger import vault
from witnessed_ledger import ReferenceWitness,image_hash,Rejected
from wire import encode

EXIT_CODE=94


def phases(hist):return ('l1','row','bit','bucket','final') if hist else ('l1','row','bit','final')

def target_tick(hist,phase):
    return {'l1':1,'row':2,'bit':5,'bucket':85,'final':337 if hist else 85}[phase]


def child(config):
    cfg=json.loads(Path(config).read_text());log=Path(cfg['diagnostic_log'])
    def event(kind,**values):
        with log.open('a') as f:
            f.write(json.dumps(dict(kind=kind,**values))+'\n');f.flush();os.fsync(f.fileno())
    def stop(point):
        if point==cfg['cut']:os._exit(EXIT_CODE)
    w=ReferenceWitness(cfg['witness'])
    l=PublicGatewayLedger(cfg['ledger'],clock=lambda:cfg['at'],vault=vault(),witness=w,witness_fault=stop)
    previous=l.op('t','a');previous_seed=previous['seed']
    step=l.advance_private_step;read=l.open_snapshot
    def sample(op):
        stop('before_sampling');tape=bytes.fromhex(cfg['sample_tape']);event('DRAW',tape=tape.hex())
        if cfg.get('mutant_read_at_sample'):
            params=json.loads(op['action'])['parameters']
            row=l.db.execute('SELECT rows_json FROM snapshots WHERE tenant=? AND domain_id=? AND id=?',('t','domain',params['snapshot'])).fetchone()
            l.open_snapshot('t','domain',params['snapshot'],row[0])
        stop('after_sampling');return tape
    def private_step(op,job,state):
        event('PRIVATE_STEP',pc=job['pc'],seed=op['seed'].hex(),previous_state=previous['state'],
              previous_seed=None if previous_seed is None else previous_seed.hex())
        result=step(op,job,state);stop('after_private_step');return result
    def snapshot(*args):
        event('SNAPSHOT_READ',previous_state=previous['state'],previous_seed=None if previous_seed is None else previous_seed.hex())
        return read(*args)
    with patch.object(l,'operation_randomness',side_effect=sample),patch.object(l,'advance_private_step',side_effect=private_step),patch.object(l,'open_snapshot',side_effect=snapshot):
        l.advance('t','domain','tick'+str(cfg['tick']-1),cfg['tick']-1,fault=stop)
    if cfg['cut']=='response_drop':os._exit(EXIT_CODE)
    raise RuntimeError('kernel cut not reached')


class KernelRuntime(RecoveryRuntime):
    def __init__(self,*args,**kwargs):
        self.prefix_cache={};self.physical_draws=[];self.private_diagnostics=[]
        super().__init__(*args,**kwargs)
        self.simulator=KernelRecoverySimulator(self.cfg,{},self.signer)

    def relation(self):
        result=super().relation();result.update(assert_private_relation(self));return result

    def _randomness(self,op):
        tape=super()._randomness(op)
        self.physical_draws.append(dict(source='normal_tick',tick=self.steps+1,committed=True,discarded_tape_differs=False))
        return tape

    def _observe(self,actual):
        command=self.commands[len(self.simulator.records)]
        if command['kind']!='TICK_CUT':return super()._observe(actual)
        with patch('sqlite3.connect',side_effect=AssertionError('generator DB')),patch.object(PublicGatewayLedger,'handle_public',side_effect=AssertionError('generator runtime')),patch.object(PublicTraceAdapter,'_public',side_effect=AssertionError('observed response generator')):
            generated=self.simulator.emit(command)
        if generated!=actual:raise AssertionError('tick unavailable observation differs')
        self.checkpoints.append(dict(index=len(self.simulator.records),kind='TICK_CUT',relation={
            'R9':digest(self.cut_diagnostics[-1]),'R10':digest(self.private_diagnostics[-1])}))

    def advance_cut(self,hist,phase,cut,mutant_read_at_sample=False):
        requested=self.steps+1
        if requested!=target_tick(hist,phase) or cut not in phase_cuts(phase):raise ValueError('phase/cut mismatch')
        command=dict(kind='TICK_CUT',at=self.now,tick=requested,cut=cut);self.commands.append(command)
        self.process_tick_cut(command,hist,phase,mutant_read_at_sample)
        self.records.append(dict(kind='TICK_UNAVAILABLE',at=self.now,tick=requested))
        self.restore()
        # Retry the ORIGINAL request identity/CAS expectation, never a new slot.
        self.commands.append(dict(kind='TICK_RETRY',at=self.now,tick=requested))
        before=self.w.head(self.l.namespace,True)
        with patch.object(self.l,'operation_randomness',side_effect=self._randomness):
            answer=self.l.advance('t','domain','tick'+str(requested-1),requested-1)
        if answer!={'request_id':'tick'+str(requested-1),'tick':requested}:raise AssertionError('R10.retry_reply')
        after=self.w.head(self.l.namespace,True)
        if after['seq']!=before['seq']+1:raise AssertionError('R9.retry_cas')
        if cut in DURABLE_CUTS and after['image']!=before['image']:raise AssertionError('R10.cached_retry_changed_image')
        self.steps=requested
        self.records.append(dict(kind='TICK_RETRY',at=self.now,tick=requested))

    def process_tick_cut(self,command,hist,phase,mutant):
        before=self.w.head(self.l.namespace);old_path=self.l.path;ns=self.l.namespace;self.l.close()
        committed=command['cut'] in DURABLE_CUTS
        planned=planned_tape(self.slots,hist,1 if committed else 2)
        log=self.directory/'kernel-diagnostics.jsonl'
        cfg=dict(command,ledger=str(old_path),witness=str(self.w.path),sample_tape=planned.hex(),
                 diagnostic_log=str(log),mutant_read_at_sample=mutant)
        path=self.directory/'kernel-cut.json';path.write_text(json.dumps(cfg))
        proc=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--child',str(path)],capture_output=True,text=True,timeout=30)
        self.l=PublicGatewayLedger(old_path,clock=lambda:self.now,vault=vault(),witness=self.w)
        if proc.returncode!=EXIT_CODE:raise AssertionError('kernel child failed: '+str(proc.returncode)+' '+proc.stderr[-1000:])
        after=self.w.head(ns,True);head={k:after[k] for k in ('seq','digest')}
        if head['seq']!=before['seq']+int(committed) or image_hash(after['image'])!=head['digest']:raise AssertionError('R9.witness_head')
        if not committed and head!=before:raise AssertionError('R9.precommit_head')
        expected=head if command['cut']=='response_drop' else before
        if self.l.local_anchor()!=expected or image_hash(self.l.state_image())!=expected['digest']:raise AssertionError('R9.local_atomicity')
        stale=expected!=head
        try:self.l.check_current_state()
        except Rejected as exc:
            if not stale or str(exc)!='WITNESS_RECOVERY_REQUIRED':raise
        else:
            if stale:raise AssertionError('R9.stale_guard')
        events=[json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        draws=[e for e in events if e['kind']=='DRAW'];steps=[e for e in events if e['kind']=='PRIVATE_STEP'];reads=[e for e in events if e['kind']=='SNAPSHOT_READ']
        expected_draws=int(phase=='l1' and command['cut']!='before_sampling')
        if len(draws)!=expected_draws or any(e['tape']!=planned.hex() for e in draws):raise StateRelationMismatch('R10.physical_draws')
        if len(steps)!=int(phase!='l1') or len(reads)!=int(phase=='row'):raise StateRelationMismatch('R10.private_access_count')
        final_seed=planned_tape(self.slots,hist)
        for event in steps+reads:
            if event['previous_state']!='STARTED' or event['previous_seed']!=final_seed.hex():raise StateRelationMismatch('R10.private_read_without_prior_L1')
            if event['kind']=='PRIVATE_STEP' and event['seed']!=final_seed.hex():raise StateRelationMismatch('R10.step_tape_changed')
        for _ in draws:
            self.physical_draws.append(dict(source='cut_tick',tick=command['tick'],committed=committed,discarded_tape_differs=not committed and planned!=final_seed))
        if phase=='l1' and committed:self.runtime_draws.append(('a','histogram' if hist else 'count',command['tick']))
        self.steps+=int(committed)
        self.cut_diagnostics.append(dict(cut=command['cut'],exit_code=proc.returncode,witness_advanced=committed,
                                        local_committed=command['cut']=='response_drop',stale_guard_blocked=stale))
        self.private_diagnostics.append(dict(phase=phase,physical_draws=len(draws),private_steps=len(steps),snapshot_reads=len(reads),
            prior_durable_seed_checked=True,attempts_recorded_separately=True))

    def checked(self):
        result=super().checked()
        if self.simulator.pending_tick is not None:raise AssertionError('unretried tick')
        if sum(x['committed'] for x in self.physical_draws)!=len(self.runtime_draws):raise StateRelationMismatch('R10.draw_commit_accounting')
        result.update(physical_draws=len(self.physical_draws),committed_draws=len(self.runtime_draws),
                      discarded_draws=sum(not x['committed'] for x in self.physical_draws))
        return result


def run_kernel(hist,phase,cut,mask=3):
    if type(hist) is not bool or phase not in phases(hist) or cut not in phase_cuts(phase) or type(mask) is not int or not 0<=mask<8:raise ValueError('outside kernel recovery profile')
    with tempfile.TemporaryDirectory() as td:
        r=KernelRuntime(td,mask)
        try:
            r.submit(hist=hist)
            while r.steps<target_tick(hist,phase)-1:r.advance()
            r.advance_cut(hist,phase,cut);r.finish();r.deliver();r.call('FINAL',dict(cursor=0,limit=1))
            check=r.checked()
            return dict(histogram=hist,phase=phase,cut=cut,mask=mask,config_cbor_hex=encode(r.cfg).hex(),approved_outputs=r.oracle,
                commands=r.commands,expected_records=list(r.records),checkpoints=r.checkpoints,signing_calls=r.signer.calls,
                cut_diagnostics=r.cut_diagnostics,private_diagnostics=r.private_diagnostics,physical_draws=r.physical_draws,check=check)
        finally:r.close()


def main():
    import argparse,gzip
    parser=argparse.ArgumentParser();parser.add_argument('--child',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.child:return child(args.child)
    if args.output is None or args.output.exists():parser.error('choose new output directory')
    args.output.mkdir(parents=True);root=Path(__file__).parent
    report=dict(profile='private-work-recovery-v1',passed=False,cases=[],
        source_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('*.py')},
        kernel_source_sha256={n:hashlib.sha256((root.parent/n).read_bytes()).hexdigest() for n in ('fixed_work_model.py','histogram_kernel.py')},
        scope='Fixed one active job; explicit dataset-independent tick cuts, fresh sender restore and exact tick retry. Private diagnostic prefix checks are not generator inputs. No physical privacy, arbitrary concurrency, recovery/recipient crashes or power-loss claim.')
    with (args.output/'cases.jsonl.gz').open('wb') as f,gzip.GzipFile(fileobj=f,mode='wb',mtime=0) as archive:
        for hist in (False,True):
            for phase in phases(hist):
                for cut in phase_cuts(phase):
                    reference=None
                    for mask in range(8):
                        case=run_kernel(hist,phase,cut,mask);fingerprint=digest(dict(records=case['expected_records'],checkpoints=case['checkpoints']))
                        if reference is None:reference=fingerprint
                        if reference!=fingerprint:raise AssertionError('conditional private-recovery observations differ')
                        report['cases'].append(dict(histogram=hist,phase=phase,cut=cut,mask=mask,trace_sha256=digest(case['expected_records']),
                            correspondence_sha256=fingerprint,records=len(case['expected_records']),checkpoints=len(case['checkpoints']),
                            physical_draws=case['check']['physical_draws'],committed_draws=case['check']['committed_draws'],discarded_draws=case['check']['discarded_draws']))
                        archive.write((json.dumps(case,separators=(',',':'))+'\n').encode())
                    print('PASS',hist,phase,cut,'8 datasets',flush=True)
    report.update(passed=True,cases_count=len(report['cases']),groups_count=len(report['cases'])//8,
                  process_exits=len(report['cases']),restores=len(report['cases']),directed_neighbor_comparisons=3*len(report['cases']),
                  checkpoints_count=sum(x['checkpoints'] for x in report['cases']))
    (args.output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
