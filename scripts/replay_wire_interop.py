#!/usr/bin/env python3
"""Rerun archived cross-language inputs, with source binding and result comparison."""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'outputs/agent-cryptography-design-20261025/prototype'))
from wire_interop import run


def main():
    parser=argparse.ArgumentParser();parser.add_argument('evidence',type=Path);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():parser.error('output exists')
    summary_path=args.evidence/'summary.json';archive=args.evidence/'cases.jsonl.xz';summary=json.loads(summary_path.read_text())
    if not summary['passed']:raise ValueError('input run did not pass')
    for name,expected in summary['source_sha256'].items():
        source=(ROOT/name).resolve();source.relative_to(ROOT.resolve())
        if hashlib.sha256(source.read_bytes()).hexdigest()!=expected:raise ValueError('source differs: '+name)
    with lzma.open(archive,'rt') as f:rows=[json.loads(line) for line in f]
    if len(rows)!=summary['cases']:raise ValueError('case count differs')
    # Node only receives row['input']; archived outcomes are compared afterwards.
    report,actual=run(rows)
    if not report['passed']:raise AssertionError('cross-language replay differs')
    for old,new in zip(rows,actual):
        if old['python']!=new['python'] or old['node']!=new['node']:raise AssertionError('archived result differs: '+old['id'])
    output=dict(passed=True,cases=len(rows),node=report['node'],node_openssl=report['node_openssl'],python_crypto_backend=report['python_crypto_backend'],
        input_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (summary_path,archive)},
        replay_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),source_sha256=summary['source_sha256'],
        scope='Re-executes both implementations on all archived inputs and compares original results. No network service, full protocol deployment or CDDL engine is exercised.')
    args.output.write_text(json.dumps(output,indent=2)+'\n');print('PASS',len(rows),'archived cross-language inputs replayed')

if __name__=='__main__':main()
