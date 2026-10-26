"""Assemble verified, unmodified Archify HTML files into a portable reader."""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import subprocess
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ARCHIFY_REVISION = '81c6be8d87090670c45d08a8f97f9d29c5af0bec'
SOURCE_REVISION = '2b596d41a2b9e217c1273a68f592dc71fcf76439'
VIEWS = [
    ('architecture', 'architecture', '系统架构', '逻辑组件、可信边界与持久化关系'),
    ('dataflow', 'dataflow', '数据流', '私有贡献如何变成受授权的统计输出'),
    ('request-sequence', 'sequence', '请求时序', '从预算预留到接收确认的正常路径'),
    ('recovery-sequence', 'sequence', '恢复时序', '提交失联、业务冻结、镜像恢复与精确重试'),
    ('hierarchy', 'tree', '模块层次', '运行时、持久化和研究证据的职责划分'),
    ('lifecycle', 'lifecycle', '生命周期', '取消、消耗、准入与最终事实的分支'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archify', type=Path, help='Optional pinned Archify checkout; re-finalizes all candidates.')
    parser.add_argument('--evidence-dir', default='rebuild-review', help='Fresh review folder for a changed candidate.')
    args = parser.parse_args()
    if args.archify:
        actual = subprocess.check_output(['git', '-C', str(args.archify), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != ARCHIFY_REVISION:
            raise SystemExit('Archify revision differs from the documented renderer.')
        if subprocess.check_output(['git', '-C', str(args.archify), 'status', '--porcelain'], text=True).strip():
            raise SystemExit('Archify checkout must be unmodified.')
        for slug, kind, _, _ in VIEWS:
            subprocess.run(['node', str(args.archify / 'archify/bin/archify.mjs'), 'finalize', kind,
                            str(HERE / (slug + '.json')), str(HERE / (slug + '.html')),
                            '--repo-root', str(ROOT), '--quality', 'showcase',
                            '--out-dir', str(HERE / args.evidence_dir / slug), '--json'],
                           cwd=ROOT, env={**os.environ, 'ARCHIFY_UPDATE_CHECK_DISABLED': '1'}, check=True)
    views = []
    evidence = []
    for slug, kind, label, description in VIEWS:
        path = HERE / (slug + '.html')
        data = path.read_bytes()
        candidate = HERE / (slug + '.json')
        digest = hashlib.sha256(data).hexdigest()
        candidate_digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        matches = []
        for path in HERE.rglob(slug + '.finalize-summary.json'):
            item = json.loads(path.read_text())
            if (item.get('ok') and item.get('artifact', {}).get('sha256') == digest
                    and item.get('specification', {}).get('sha256') == candidate_digest):
                matches.append((path, item))
        if not matches:
            raise SystemExit('Missing passing receipt for current candidate and HTML: ' + slug)
        summary_path, summary = max(matches, key=lambda pair: pair[0].stat().st_mtime_ns)
        receipt_path = summary_path.with_name(slug + '.finalize.json')
        if any(summary['gates'].get(g) != 'pass' for g in ('validate', 'deliver', 'check', 'browser-check')):
            raise SystemExit('All four Archify gates must pass: ' + slug)
        views.append(dict(slug=slug, label=label, description=description, html=data.decode()))
        evidence.append(dict(slug=slug, type=kind, sha256=digest, bytes=len(data),
                             candidate_sha256=summary['specification']['sha256'],
                             gates=summary['gates'], receipt=str(receipt_path.relative_to(HERE))))
    payload = json.dumps(views, ensure_ascii=False).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    template = (HERE / 'atlas.template.html').read_text()
    result = template.replace('__VIEWS_JSON__', payload)
    result = result.replace('__LICENSE_TEXT__', html.escape('\n\n'.join((HERE / 'licenses' / f).read_text() for f in ['NOTICE', 'LICENSE', 'LICENSE-MIT', 'THIRD_PARTY_NOTICES.md'])))
    (HERE / 'index.html').write_text(result)
    manifest = dict(source_revision=SOURCE_REVISION, archify_revision=ARCHIFY_REVISION,
                    atlas_sha256=hashlib.sha256(result.encode()).hexdigest(), views=evidence)
    (HERE / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    with zipfile.ZipFile(HERE / 'AgentSec-architecture-atlas.zip', 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        files = ['index.html', 'README.md', 'manifest.json', 'build_atlas.py', 'atlas.template.html']
        files.extend(name for name in ['check_atlas.mjs', 'validation.md', 'atlas-browser-check.json', 'atlas-preview.png']
                     if (HERE / name).exists())
        for slug, _, _, _ in VIEWS:
            files.extend([slug + '.html', slug + '.json'])
        for item in evidence:
            receipt = Path(item['receipt'])
            files.extend([str(receipt), str(receipt.with_name(item['slug'] + '.finalize-summary.json')),
                          str(receipt.with_name(item['slug'] + '.browser-check.json')),
                          item['slug'] + '.delivery.json'])
        for name in files:
            archive.write(HERE / name, 'AgentSec-atlas/' + name)
        for path in sorted((HERE / 'licenses').iterdir()):
            archive.write(path, 'AgentSec-atlas/licenses/' + path.name)
    print(json.dumps({'atlas': str(HERE / 'index.html'), 'views': len(views), 'sha256': manifest['atlas_sha256']}))


if __name__ == '__main__':
    main()
