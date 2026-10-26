"""Deterministic two-replica authority races; finite evidence, not a proof.

All competing writes use real signed business requests and separate SQLite
connections. Hooks select an interleaving; they are not public protocol inputs.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

from public_gateway import PublicGatewayLedger
from test_public_gateway import configure, make_request, bundle, parse_reply, PEER, SERVER_KEY
from test_encrypted_mixed_ledger import vault
from test_mixed_delegated_ledger import tick
from retention_recipient import RetentionRecipient
from test_retention_recipient import recipient_vault
from test_retention_wire import fixture
from test_retention_delivery import descriptor
from witnessed_ledger import ReferenceWitness, image_hash
from ledger import Rejected
import retention_delivery as delivery
import retention_wire as retention

PROFILES = ('count', 'histogram', 'recipient')
MODES = ('existing', 'fresh')
WRITES = ('same_image', 'changed_image')
CUTS = ('before_image_read', 'after_image_read', 'after_recovery_delete',
        'after_head_recheck', 'before_recovery_commit', 'after_recovery_commit')
EARLY = ('after_image_read', 'after_recovery_delete')
LATE = ('after_head_recheck', 'before_recovery_commit', 'after_recovery_commit')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def copy_db(db, path):
    target = sqlite3.connect(str(path))
    try:
        db.backup(target)
    finally:
        target.close()


def head_only(head):
    return {k: head[k] for k in ('seq', 'digest')}


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def rejects(code, action):
    try:
        action()
    except Rejected as exc:
        require(str(exc) == code, 'wrong rejection: ' + str(exc))
    else:
        raise AssertionError('missing rejection: ' + code)


class Scenario:
    def __init__(self, root, profile, mode):
        self.root, self.profile, self.mode = root, profile, mode
        self.now = 100
        self.resources = ExitStack()
        self.w = self.witness('authority')
        self.rival_w = self.witness('authority')
        self.local_w = self.witness('authority')
        self.old = root / 'old'
        if profile == 'recipient':
            self.context, self.sender_key, self.receiver_key = fixture()
            self.primary = self.track(RetentionRecipient.create(root / 'primary', **self.kwargs(self.w)))
            copy_db(self.primary.db, self.old)
            env = delivery.envelope(descriptor(self.context), (1).to_bytes(8, 'big') * 4,
                                    self.context, self.sender_key)
            self.original_request = delivery.attempt('DELIVERY', env, b'o' * 32, self.context, self.sender_key)
            self.original_response = self.exchange(self.primary, self.original_request)
        else:
            self.primary = self.track(configure(PublicGatewayLedger.create(root / 'primary', **self.kwargs(self.w))))
            challenge_request = make_request('CHALLENGE', {}, 1)
            challenge = parse_reply(self.exchange(self.primary, challenge_request), challenge_request)['body']
            self.original_request = make_request('SUBMIT', bundle(self.primary, challenge, hist=profile == 'histogram'), 2)
            self.original_response = self.exchange(self.primary, self.original_request)
            copy_db(self.primary.db, self.old)
            tick(self.primary)  # Durable L1 and the original protected random tape.
        self.initial = self.w.head(self.primary.namespace, True)
        self.invariant = self.critical(self.primary)
        copy_db(self.primary.db, root / 'rival')
        self.rival = self.open(root / 'rival', self.rival_w)
        self.local = (self.open(self.old, self.local_w) if mode == 'existing'
                      else self.track(type(self.primary).new_replica(root / 'fresh', **self.kwargs(self.local_w))))
        self.before = self.local.state_image()
        self.before_anchor = self.anchor(self.local)

    def witness(self, name):
        obj = ReferenceWitness(self.root / name)
        self.resources.callback(obj.close)
        return obj

    def kwargs(self, witness):
        args = dict(clock=lambda: self.now, witness=witness,
                    vault=recipient_vault() if self.profile == 'recipient' else vault())
        if self.profile == 'recipient':
            args['context'] = self.context
        return args

    def track(self, obj):
        self.resources.callback(obj.close)
        return obj

    def open(self, path, witness):
        cls = RetentionRecipient if self.profile == 'recipient' else PublicGatewayLedger
        return self.track(cls(path, **self.kwargs(witness)))

    @staticmethod
    def anchor(obj):
        row = obj.db.execute('SELECT seq,digest FROM witness_anchor WHERE singleton=1').fetchone()
        return dict(row) if row else None

    def exchange(self, obj, raw):
        if self.profile == 'recipient':
            return obj.accept(raw, self.context['sender_cert'], self.receiver_key)
        return obj.handle_public(raw, PEER, SERVER_KEY)

    def probe(self, obj):
        if self.profile == 'recipient':
            raw = retention.query(self.context, 'CHECKPOINT', 0, b'p' * 32, self.sender_key)
        else:
            raw = make_request('CONTROL', dict(kind='resume'), 60, actor='manager')
        return self.exchange(obj, raw)

    def advance(self, write):
        if write == 'same_image':
            reply = self.exchange(self.rival, self.original_request)
            require(reply == self.original_response, 'competing exact replay changed original response')
        elif self.profile == 'recipient':
            self.now = 101
            raw = retention.query(self.context, 'CHECKPOINT', 0, b'c' * 32, self.sender_key)
            reply = self.exchange(self.rival, raw)
            retention.parse_checkpoint(reply, raw, self.context)
        else:
            raw = make_request('CONTROL', dict(kind='pause'), 50, actor='manager')
            require(parse_reply(self.exchange(self.rival, raw), raw)['status'] == 'CONTROL_RECORDED',
                    'competing command not recorded')
        after = self.w.head(self.primary.namespace, True)
        require(after['seq'] == self.initial['seq'] + 1, 'competing writer must advance exactly once')
        require((after['image'] == self.initial['image']) == (write == 'same_image'), 'wrong image branch')
        require(self.critical(self.rival) == self.invariant, 'competing writer changed protected business evidence')
        return after

    def critical(self, obj):
        if self.profile == 'recipient':
            return [tuple(x) for x in obj.db.execute('SELECT * FROM v2_recipient_live ORDER BY seq')]
        # Ciphertext bytes, accounting rows, and scheduling PC must survive exactly.
        # Restore preserves logical rows, not SQLite's incidental insertion order.
        return {table: sorted((tuple(x) for x in obj.db.execute('SELECT * FROM ' + table)), key=repr)
                for table in ('operations', 'jobs', 'accounts', 'charges')}

    def recover(self, hook=lambda point: None):
        dispatch = '_first_event' if self.profile == 'recipient' else '_dispatch'
        with patch.object(self.local, dispatch, side_effect=AssertionError('recovery dispatched business')), \
             patch.object(self.local_w, 'compare_and_store', side_effect=AssertionError('recovery wrote authority')):
            return self.local.recover_from_witness(hook)

    def finish(self, authority):
        require(self.w.head(self.local.namespace, True) == authority, 'local failure or restore changed authority')
        restored = self.recover()
        require(restored == head_only(authority), 'retry restored wrong head')
        require(self.local.state_image() == authority['image'], 'restore not byte-exact')
        require(self.critical(self.local) == self.invariant, 'random tape/budget/first fact changed')
        require(self.local.audit() == [], 'restored audit failed')
        # A restart is not treated as a logical reset of the local or witness history.
        reopened = self.open(self.local.path, self.local_w)
        require(reopened.check_current_state() == head_only(authority), 'reopen did not preserve anchor')
        reply = self.exchange(reopened, self.original_request)
        require(reply == self.original_response, 'exact business retry changed original response')
        require(self.critical(reopened) == self.invariant, 'business replay changed protected evidence')
        final = self.w.head(self.local.namespace, True)
        require(final['seq'] == authority['seq'] + 1 and final['image'] == authority['image'],
                'exact retry must be a new witness attempt with the same image')
        return dict(retry_response_sha256=digest(reply), protected_evidence_preserved=True,
                    reopen_current=True, retry_image_unchanged=True)


def run_case(profile, mode, write, cut, *, mutant=None):
    require(profile in PROFILES and mode in MODES and write in WRITES and cut in CUTS, 'unsupported case')
    with tempfile.TemporaryDirectory(prefix='agentsec-authority-race-') as td:
        scenario = Scenario(Path(td), profile, mode)
        with scenario.resources, ExitStack() as patches:
            s = scenario
            changed = []
            def advance():
                require(not changed, 'rival triggered twice')
                changed.append(s.advance(write))
            original_head = s.local_w.head
            def racing_head(namespace, include_image=False):
                if include_image and cut == 'before_image_read':
                    advance()
                value = original_head(namespace, include_image)
                if include_image and cut == 'after_image_read':
                    advance()
                if not include_image and cut == 'after_head_recheck':
                    advance()
                if not include_image and mutant == 'skip_recheck':
                    return head_only(s.initial)
                return value
            def hook(point):
                if point == cut:
                    advance()
            with patch.object(s.local_w, 'head', side_effect=racing_head):
                try:
                    returned = s.recover(hook)
                    rejection = None
                except Rejected as exc:
                    returned, rejection = None, str(exc)
            require(len(changed) == 1, 'interleaving was not reached')
            authority = changed[0]
            if cut in EARLY:
                require(rejection == 'WITNESS_CHANGED_DURING_RECOVERY', 'early race did not reject restore')
                require(s.local.state_image() == s.before and s.anchor(s.local) == s.before_anchor,
                        'rejected recovery changed local image or anchor')
                disposition = 'rollback'
            else:
                require(rejection is None, 'unexpected recovery rejection')
                expected = authority if cut == 'before_image_read' else s.initial
                require(returned == head_only(expected), 'wrong restored snapshot receipt')
                require(s.local.state_image() == expected['image'] and s.anchor(s.local) == head_only(expected),
                        'restored image/anchor are not an atomic snapshot')
                disposition = 'current_snapshot' if cut == 'before_image_read' else 'stale_snapshot'
            stale = cut != 'before_image_read'
            if stale:
                if mutant == 'ignore_sequence':
                    def digest_only():
                        anchor = s.local.local_anchor()
                        require(image_hash(s.local.state_image()) == anchor['digest'], 'local corruption')
                        if s.local_w.head(s.local.namespace)['digest'] != anchor['digest']:
                            raise Rejected('WITNESS_RECOVERY_REQUIRED')
                        return anchor
                    patches.enter_context(patch.object(s.local, 'check_current_state', side_effect=digest_only))
                rejects('WITNESS_RECOVERY_REQUIRED', s.local.check_current_state)
                before = s.local.state_image()
                # Recipient frame/signature parsing precedes its transaction;
                # state() is its first guarded business-state observation.
                dispatch = 'state' if profile == 'recipient' else '_dispatch'
                with patch.object(s.local, dispatch, side_effect=AssertionError('stale replica reached business')):
                    rejects('WITNESS_RECOVERY_REQUIRED', lambda: s.probe(s.local))
                require(s.local.state_image() == before, 'blocked business changed local state')
            else:
                require(s.local.check_current_state() == head_only(authority), 'fresh recovery not current')
            require(s.w.head(s.local.namespace, True) == authority, 'recovery mutated competing authority')
            observed = dict(returned_head=returned, local_before_anchor=s.before_anchor,
                            local_after_anchor=s.anchor(s.local),
                            local_before_image_digest=image_hash(s.before),
                            local_after_image_digest=image_hash(s.local.state_image()))
            checks = s.finish(authority)
            return dict(profile=profile, mode=mode, write=write, cut=cut, disposition=disposition,
                        recovery_rejection=rejection, stale_fenced=stale,
                        same_digest_new_sequence=write == 'same_image',
                        initial_head=head_only(s.initial), competing_head=head_only(authority), **observed, **checks)


def run_commit_race(profile, mode, write, *, mutant=None):
    """Authority advances after a successful begin guard but before local CAS."""
    with tempfile.TemporaryDirectory(prefix='agentsec-commit-race-') as td:
        s = Scenario(Path(td), profile, mode)
        with s.resources:
            s.recover()
            before = s.local.state_image()
            before_anchor = s.local.local_anchor()
            original = s.local.begin_transaction_guard
            changed = []
            def after_guard():
                original()
                changed.append(s.advance(write))
            with patch.object(s.local, 'begin_transaction_guard', side_effect=after_guard), ExitStack() as patches:
                if mutant == 'omit_cas':
                    patches.enter_context(patch.object(s.local, 'commit_transaction_guard', return_value=None))
                rejects('WITNESS_CAS_CONFLICT', lambda: s.probe(s.local))
            require(len(changed) == 1, 'commit race was not reached')
            authority = changed[0]
            require(s.local.state_image() == before and s.local.local_anchor() == before_anchor,
                    'losing writer committed local business changes')
            rejects('WITNESS_RECOVERY_REQUIRED', s.local.check_current_state)
            checks = s.finish(authority)
            return dict(profile=profile, mode=mode, write=write, cut='after_business_begin_guard',
                        rejection='WITNESS_CAS_CONFLICT', local_rollback=True,
                        initial_head=head_only(s.initial), competing_head=head_only(authority), **checks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('choose a new evidence directory')
    args.output.mkdir(parents=True)
    cases = [run_case(p, m, w, c) for p in PROFILES for m in MODES for w in WRITES for c in CUTS]
    commits = [run_commit_race(p, m, w) for p in PROFILES for m in MODES for w in WRITES]
    files = list(Path(__file__).parent.glob('*.py'))
    report = dict(profile='authority-race-finite-v1', recovery_cases=len(cases), commit_races=len(commits),
                  source_sha256={p.name:digest(p.read_bytes()) for p in sorted(files)}, cases=cases, commits=commits,
                  scope='Deterministic local interleavings with a single valid rival write; no arbitrary concurrency, TLS, crash composition, liveness or general refinement claim.')
    (args.output/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(recovery_cases=len(cases), commit_races=len(commits), passed=True)))


if __name__ == '__main__':
    main()
