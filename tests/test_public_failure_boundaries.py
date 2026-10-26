"""Distinguish normal public denials from calls with no modeled response."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
from pathlib import Path
import secrets
import sys
import tempfile
import unittest
from unittest.mock import patch

P = Path(__file__).resolve().parents[1] / 'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0, str(P))
from constructive_trace import FixtureSigningOracle
from ledger import Rejected
from public_gateway import PROFILE, RESPONSE_TYPE
from public_simulator import PublicSimulator
from public_trace_adapter import PublicTraceAdapter, ViewMismatch
from restricted_trace import Runtime
from state_relation import assert_state_relation
from test_public_gateway import make_request, parse_reply, bundle, PEER, SERVER_KEY, SERVER_KID
from test_mixed_delegated_ledger import KEYS
from wire import decode, encode, inspect_sign1, sign1


def fake_rejection(runtime, raw, sequence=0):
    body = dict(profile=PROFILE, deployment=runtime.cfg['deployment'], request_hash=hashlib.sha256(raw).digest(),
                status='REJECTED', body={}, sequence=sequence)
    return sign1(encode(body), SERVER_KID, SERVER_KEY, RESPONSE_TYPE)


class Harness:
    def __init__(self, directory):
        self.runtime = Runtime(directory)
        self.signer = FixtureSigningOracle()
        self.sim = PublicSimulator(self.runtime.cfg, {}, self.signer)
        self.checker = PublicTraceAdapter(self.runtime.cfg, {})

    def command(self, raw, peer=PEER, coin=b''):
        return dict(kind='PUBLIC', at=self.runtime.now, request=raw.hex(), peer=peer.hex(), challenge_coin=coin.hex())

    def event(self, raw, reply, peer=PEER):
        return dict(kind='PUBLIC', at=self.runtime.now, request=raw.hex(), peer=peer.hex(), response=reply.hex())

    def compare(self, raw, peer=PEER, coin=b''):
        token = secrets.token_bytes
        with patch('signed_ledger.secrets.token_bytes', side_effect=lambda n: coin if n == 32 and coin else token(n)):
            reply = self.runtime.l.handle_public(raw, peer, SERVER_KEY)
        actual = self.event(raw, reply, peer)
        generated = self.sim.emit(self.command(raw, peer, coin))
        if generated != actual:
            raise AssertionError('generated response differs')
        self.checker.consume(actual)
        assert_state_relation(self.runtime, self.sim.state)
        assert_state_relation(self.runtime, self.checker)
        return parse_reply(reply, raw)


@contextmanager
def harness():
    with tempfile.TemporaryDirectory() as directory:
        instance = Harness(directory)
        try:
            yield instance
        finally:
            instance.runtime.close()


class PublicFailureBoundaryTests(unittest.TestCase):
    def test_invalid_call_frame_has_no_signed_response_or_cache_entry(self):
        request = make_request('POLL', dict(operation='absent'), 1)
        for raw, peer in [(bytes(8193), PEER)] + [(request, bytes(n)) for n in (0, 31, 33)]:
            with self.subTest(frame=len(raw), peer=len(peer)), harness() as h:
                before = deepcopy(h.sim.state.__dict__)
                with self.assertRaisesRegex(Rejected, '^GW_FRAME$'):
                    h.runtime.l.handle_public(raw, peer, SERVER_KEY)
                with self.assertRaisesRegex(ViewMismatch, 'PUBLIC_CALL_FRAME'):
                    h.sim.emit(h.command(raw, peer))
                self.assertEqual(h.sim.state.__dict__, before)
                self.assertEqual(h.signer.calls, [])
                self.assertEqual(h.sim.records, [])
                # Even a validly signed fabricated rejection cannot certify it.
                with self.assertRaisesRegex(ViewMismatch, 'PUBLIC_CALL_FRAME'):
                    h.checker.check([h.event(raw, fake_rejection(h.runtime, raw), peer)])
                self.assertEqual(h.checker.cache, {})
                self.assertEqual(h.runtime.l.db.execute('SELECT count(*) FROM gw_requests').fetchone()[0], 0)

    def test_empty_and_exact_limit_frames_get_authentication_rejections(self):
        for raw in (b'', bytes(8192)):
            with self.subTest(size=len(raw)), harness() as h:
                reply = h.compare(raw)
                self.assertEqual((reply['status'], reply['sequence']), ('REJECTED', 0))

    def test_wrong_full_length_peer_and_request_signature_are_auth_denials(self):
        raw = make_request('POLL', dict(operation='absent'), 1)
        changed = raw[:-1] + bytes([raw[-1] ^ 1])
        for request, peer in ((raw, b'X' * 32), (changed, PEER)):
            with self.subTest(peer=peer == PEER), harness() as h:
                reply = h.compare(request, peer)
                self.assertEqual((reply['status'], reply['sequence']), ('REJECTED', 0))

    def test_payload_syntax_and_policy_denials_remain_journaled(self):
        with harness() as h:
            requests = [('POLL', dict(operation=[])), ('POLL', dict(operation='absent')),
                        ('SUBMIT', dict(action=b'\x00', proof=b'\x00', chain=[b'\x00']))]
            for rid, (method, payload) in enumerate(requests, 1):
                reply = h.compare(make_request(method, payload, rid))
                self.assertEqual((reply['status'], reply['sequence']), ('REJECTED', rid))
            self.assertEqual(h.sim.state.jobs, [])

    def test_wrong_proof_signature_domain_rejects_without_consuming_challenge(self):
        with harness() as h:
            challenge = h.compare(make_request('CHALLENGE', {}, 1), coin=b'C' * 32)['body']
            good = bundle(h.runtime.l, challenge)
            bad = deepcopy(good)
            payload = decode(inspect_sign1(good['proof'])[1])
            bad['proof'] = sign1(encode(payload), b'leaf', KEYS['leaf'], 'WrongDomain')
            denied = h.compare(make_request('SUBMIT', bad, 2))
            self.assertEqual((denied['status'], denied['sequence']), ('REJECTED', 2))
            self.assertFalse(h.sim.state.challenges[challenge['challenge']]['used'])
            accepted = h.compare(make_request('SUBMIT', good, 3))
            self.assertEqual((accepted['status'], accepted['sequence']), ('RECORDED', 3))

    def test_unknown_rejected_failures_abort_and_rollback_predictive_effects(self):
        for code in ('STORAGE_INTEGRITY', 'UNEXPECTED_INTERNAL'):
            with self.subTest(code=code), harness() as h:
                raw = make_request('POLL', dict(operation='absent'), 1)
                def real_failure(*args):
                    h.runtime.l.db.execute('UPDATE gw_domains SET paused=1')
                    raise Rejected(code)
                with patch.object(h.runtime.l, '_dispatch', side_effect=real_failure):
                    with self.assertRaisesRegex(Rejected, code):
                        h.runtime.l.handle_public(raw, PEER, SERVER_KEY)
                for model, action in ((h.sim.state, lambda: h.sim.emit(h.command(raw))),
                                      (h.checker, lambda: h.checker.check([h.event(raw, fake_rejection(h.runtime, raw, 1))]))):
                    def model_failure(*args):
                        model.paused = True
                        raise Rejected(code)
                    with patch.object(model, '_dispatch', side_effect=model_failure):
                        with self.assertRaisesRegex(ViewMismatch, code):
                            action()
                    self.assertFalse(model.paused)
                    self.assertEqual(model.journal_seq, 0)
                    self.assertEqual(model.cache, {})
                self.assertEqual(h.sim.records, [])
                self.assertEqual(h.signer.calls, [])
                assert_state_relation(h.runtime, h.sim.state)

    def test_known_dispatch_denial_rolls_back_then_journals_rejection(self):
        with harness() as h:
            raw = make_request('POLL', dict(operation='absent'), 1)
            def real_denial(*args):
                h.runtime.l.db.execute('UPDATE gw_domains SET paused=1')
                raise Rejected('GW_SCOPE')
            def denied(model):
                def fail(*args):
                    model.paused = True
                    raise Rejected('GW_SCOPE')
                return fail
            with patch.object(h.runtime.l, '_dispatch', side_effect=real_denial), \
                 patch.object(h.sim.state, '_dispatch', side_effect=denied(h.sim.state)), \
                 patch.object(h.checker, '_dispatch', side_effect=denied(h.checker)):
                reply = h.compare(raw)
            self.assertEqual((reply['status'], reply['sequence']), ('REJECTED', 1))
            self.assertFalse(h.sim.state.paused)

    def test_bad_frame_cannot_bypass_validation_using_a_cached_identity(self):
        with harness() as h:
            raw = make_request('CHALLENGE', {}, 1)
            original = h.compare(raw, coin=b'C' * 32)
            before = len(h.signer.calls)
            with self.assertRaisesRegex(Rejected, 'GW_FRAME'):
                h.runtime.l.handle_public(raw, PEER[:-1], SERVER_KEY)
            with self.assertRaisesRegex(ViewMismatch, 'PUBLIC_CALL_FRAME'):
                h.sim.emit(h.command(raw, PEER[:-1]))
            h.runtime.now = 170
            self.assertEqual(h.compare(raw), original)
            self.assertEqual(len(h.signer.calls), before)


if __name__ == '__main__':
    unittest.main()
