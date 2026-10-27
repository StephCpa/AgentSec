import collections, hashlib, json, re, sys
from pathlib import Path
root=Path(sys.argv[1])
metadata=json.loads((root/'workflow.json').read_text())
assert metadata['status']=='completed' and metadata['conclusion']=='success', metadata
assert metadata['headSha']=='2c939bbe6bd49460251e9dd1ffd1c257f122c90a'
reports=list(root.glob('verification-*/run.json'))
assert len(reports)==8, len(reports)
groups=collections.defaultdict(list)
all_hashes=None
rows=[]
for path in reports:
    report=json.loads(path.read_text())
    match=re.fullmatch(r'verification-(pinned|upgrade)-(3\.(?:9|12))-([0-3])',path.parent.name)
    assert match, path
    dep,version,index=match.groups();index=int(index)
    assert (dep,version) in [('pinned','3.9'),('upgrade','3.12')]
    assert report['python'].startswith(version+'.') and report['node'].startswith('v24.')
    assert report['shard']=={'index':index,'count':4}
    assert report['passed'] and report['finished_utc'] and not report['full_suite_selected']
    inventory=[c['name'] for c in report['command_inventory']]
    assert len(inventory)==len(set(inventory))==60
    assert report['selected_commands']==inventory[index::4]
    assert [r['name'] for r in report['results']]==report['selected_commands']
    assert all(r['passed'] and r['returncode']==0 and not r['timed_out'] for r in report['results'])
    hashes=report['source_sha256']
    if all_hashes is None: all_hashes=hashes
    assert hashes==all_hashes, 'source mismatch'
    test_count=0
    for result in report['results']:
        if result['name'].startswith('review_'):
            text=(path.parent/result['log']).read_text()
            counts=re.findall(r'^Ran (\d+) tests? in ',text,re.M)
            assert counts and text.rstrip().endswith('OK'), result['name']
            test_count+=int(counts[-1])
    row={'dependencies':dep,'python':version,'index':index,'commands':len(report['results']),
         'regression_tests':test_count,'duration_seconds':sum(r['duration_seconds'] for r in report['results'])}
    rows.append(row)
    groups[(dep,version)].append((report,test_count))
assert len(groups)==2
for key,items in groups.items():
    assert len(items)==4
    assert {r['shard']['index'] for r,_ in items}==set(range(4))
    inventory=items[0][0]['command_inventory']
    assert all(r['command_inventory']==inventory for r,_ in items)
    actual=collections.Counter(n for r,_ in items for n in r['selected_commands'])
    assert actual==collections.Counter(c['name'] for c in inventory)
    assert sum(count for _,count in items)==259
result={'run_id':metadata['databaseId'],'head_sha':metadata['headSha'],'conclusion':metadata['conclusion'],
        'verified_environments':len(groups),'commands_per_environment':60,'regression_tests_per_environment':259,
        'no_missing_or_duplicate_commands':True,'same_sources_all_shards':True,'shards':rows}
(root/'coverage-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
