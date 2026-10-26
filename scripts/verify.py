#!/usr/bin/env python3
"""Run entry points in a disposable copy; preserve historical repository reports."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import cryptography

ROOT=Path(__file__).resolve().parents[1]
REL=Path('outputs/agent-cryptography-design-20261025')
MODELS=['model_check.py','model_v2.py','observation_model.py','fixed_work_model.py','histogram_model.py','retention_model.py','public_transcript_model.py']


def build_commands(root, only=None, models=False):
    entries=sorted((root/REL).rglob('test_*.py'))
    if only:
        entries=[p for p in entries if p.name in only]
        missing=set(only)-{p.name for p in entries}
        if missing:raise ValueError('Unknown test entry point: '+str(sorted(missing)))
    commands=[(p.stem,[sys.executable,str(p.relative_to(root))]) for p in entries]
    # One discovery process per module keeps setUpClass intact, while preventing
    # unrelated modules from consuming a single shared 30-minute deadline.
    for p in sorted((root/'tests').rglob('test*.py')):
        relative=p.relative_to(root/'tests')
        name='review_'+relative.with_suffix('').as_posix().replace('/','__')
        commands.append((name,[sys.executable,'-m','unittest','discover',
            '-s',str(p.parent.relative_to(root)),'-p',p.name,'-v']))
    if models:commands += [(p[:-3],[sys.executable,str(REL/p)]) for p in MODELS]
    if len({name for name,_ in commands}) != len(commands):
        raise ValueError('Duplicate verification log names')
    return commands


def select_shard(commands, index, count):
    if count < 1 or not 0 <= index < count:
        raise ValueError('Require shard-count >= 1 and 0 <= shard-index < shard-count')
    selected=commands[index::count]
    if not selected:raise ValueError('Verification shard is empty')
    return selected


def run_command(name, command, root, out, timeout=1800):
    started=time.monotonic()
    timed_out=False
    with (out/(name+'.log')).open('w') as log:
        try:
            result=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT,
                timeout=timeout,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
            code=result.returncode
        except subprocess.TimeoutExpired:
            code=124
            timed_out=True
            log.write('\nVerification command exceeded its {} second timeout.\n'.format(timeout))
    return dict(name=name,returncode=code,passed=code==0,log=name+'.log',
        timed_out=timed_out,duration_seconds=round(time.monotonic()-started,3))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True,help='New directory for logs, generated reports and source hashes.')
    parser.add_argument('--models',action='store_true')
    parser.add_argument('--only',nargs='*',help='Optional test entry-point basenames (default: all).')
    parser.add_argument('--shard-index',type=int,default=0)
    parser.add_argument('--shard-count',type=int,default=1,help='Run this deterministic slice of the complete command inventory (default: all).')
    args=parser.parse_args();out=args.output.resolve()
    try:
        all_commands=build_commands(ROOT,args.only,args.models)
        commands=select_shard(all_commands,args.shard_index,args.shard_count)
    except ValueError as exc:parser.error(str(exc))
    if out.exists():parser.error('output already exists; preserve evidence by choosing a new directory')
    out.mkdir(parents=True)
    source_paths=sorted(p for p in (ROOT/REL).rglob('*') if p.is_file() and p.suffix in ('.py','.cddl','.json','.md','.txt'))
    source_paths+=sorted(p for p in (ROOT/'tests').rglob('*') if p.is_file() and p.suffix in ('.py','.json','.mjs'))+[Path(__file__).resolve()]
    hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}
    node=shutil.which('node')
    if node is None:raise SystemExit('Node.js is required for independent protocol validation (CI uses Node 24).')
    node_version=subprocess.run([node,'--version'],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
    report=dict(node=node_version,started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),python=sys.version,
        cryptography=cryptography.__version__,openssl=ssl.OPENSSL_VERSION,sqlite=sqlite3.sqlite_version,
        platform=platform.platform(),source_sha256=hashes,
        shard=dict(index=args.shard_index,count=args.shard_count),
        full_suite_selected=not args.only and args.shard_count==1,
        command_inventory=[dict(name=n,command=c) for n,c in all_commands],
        selected_commands=[n for n,_ in commands],results=[],passed=False)
    (out/'run.json').write_text(json.dumps(report,indent=2)+'\n')
    with tempfile.TemporaryDirectory(prefix='agentsec-verify-') as td:
        root=Path(td)
        shutil.copytree(ROOT/REL,root/REL,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        shutil.copytree(ROOT/'tests',root/'tests',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        (root/'scripts').mkdir()
        shutil.copy2(__file__,root/'scripts'/'verify.py')
        for name,command in commands:
            print('RUN '+name,flush=True)
            result=run_command(name,command,root,out)
            report['results'].append(result)
            (out/'run.json').write_text(json.dumps(report,indent=2)+'\n')
            print(('PASS ' if result['passed'] else 'FAIL ')+name,flush=True)
        shutil.copytree(root/REL,out/'generated',ignore=shutil.ignore_patterns('*.py','*.md','*.cddl','*.txt','__pycache__'))
    report['passed']=all(r['passed'] for r in report['results'])
    report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    (out/'run.json').write_text(json.dumps(report,indent=2)+'\n')
    return 0 if report['passed'] else 1


if __name__=='__main__':sys.exit(main())
