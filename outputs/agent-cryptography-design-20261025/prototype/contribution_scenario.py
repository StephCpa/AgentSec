"""Full loopback P2 workflow starting at bounded user-record ingestion.

All data and identity tokens are synthetic. The upstream identity resolver and
raw-data classifier remain trusted; Python roles are not real isolated LLMs.
"""
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from contribution_delivery import TLSContributionRetentionSender
from contribution_ingestion import RULE
from dp_ledger import EPSILON_COST as E, DELTA_COST as D
from ledger import Rejected
from p2_scenario import run_scenario
from test_mixed_delegated_ledger import KEYS
from test_witness_transport import public

USERS = tuple(hashlib.sha256(('contribution-network-user-'+str(i)).encode()).digest() for i in range(3))
RECORDS = [(USERS[0],4),(USERS[1],2),(USERS[0],1),(USERS[0],1),(USERS[2],0)]


def run_contribution_scenario():
    ingestion = {}

    def provision(l):
        try:
            l.provision_domain('t','domain',3,4*E,4*D)
            l.authorize_root('t','domain','root','manager','reader',expires_at=1000)
            l.install_catalog('t','domain','cat',['one','two','three','four'])
            l.bind_contribution_domain('t','domain',b'L'*32,USERS)
            for name,key in KEYS.items():
                l.install_key('t',name.encode(),name,'root' if name=='authority' else 'instance',public(key))
            l.bind_root_authority('t','root',b'authority')
            original_fault=l.witness_fault
            def lost(point):
                if point=='after_witness_accept':raise ConnectionError('lost authenticated ingestion acknowledgement')
            l.witness_fault=lost
            try:
                l.ingest_pair('t','domain','batch','cat','count','hist',RECORDS)
                raise AssertionError('fault not exercised')
            except ConnectionError:pass
            finally:l.witness_fault=original_fault
            assert l.db.execute('SELECT count(*) FROM snapshots').fetchone()[0]==0
            try:l.audit();raise AssertionError('stale sender not fenced')
            except Rejected as exc:assert str(exc)=='WITNESS_RECOVERY_REQUIRED'
            with patch('contribution_ingestion.compile_contributions',side_effect=AssertionError('recompile after witness acceptance')):
                l.recover_from_witness()
            for sid,expected in [('count',[1,1,0]),('hist',[1,2,0])]:
                raw=l.db.execute('SELECT rows_json FROM snapshots WHERE id=?',(sid,)).fetchone()[0]
                assert l.open_snapshot('t','domain',sid,raw)==expected
            assert l.audit()==[]
            for call in [lambda:l.install_snapshot('t','domain','bypass',[1,1,1]),
                         lambda:l.install_histogram_snapshot('t','domain','bypass','cat',[1,1,1])]:
                try:call();raise AssertionError('direct import allowed')
                except Rejected as exc:assert str(exc)=='CONTRIBUTION_INGESTION_REQUIRED'
            image=l.state_image()
            assert all(u.hex().encode() not in image for u in USERS)
            ingestion.update(rule=RULE,storage_profile=l.storage_profile,capacity=3,buckets=4,
                paired_snapshots_verified=True,duplicate_records_clipped=True,private_roster_encrypted=True,
                witness_acceptance_local_rollback=True,stale_replica_fenced=True,
                exact_pair_restored_without_recompile=True,direct_import_disabled=True,
                ingestion_loss='Injected after authenticated witness CAS receipt, before local commit; not a dropped network reply or process death.')
            return l
        except BaseException:
            l.close();raise

    report,inputs=run_scenario(sender_type=TLSContributionRetentionSender,provision=provision)
    report.update(scenario='P2 contribution ingestion through authenticated retention-v2 delivery',
        contribution=ingestion,
        trust='Synthetic stable identity tokens and preclassified records, actual fixed-roster compiler, paired witnessed ingestion, shared signed mixed operations and loopback authenticated delivery. Upstream real-user resolution/classifier and global lineage are trusted and unimplemented; independent authority files/services share one host. No complete public observation or production guarantee.')
    assert len(report['events'])==9 and report['budget']['charged_operations']==2
    return report,inputs


if __name__=='__main__':
    report,_=run_contribution_scenario()
    Path(__file__).with_name('contribution_scenario_results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False,indent=2))
