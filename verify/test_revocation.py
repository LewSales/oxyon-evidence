#!/usr/bin/env python3
"""Offline adversarial tests for the revocation check (Sprint 012): which bound witnesses count as a revocation,
and when the history-assisted scan of long intervals may conclude. Standard library only; the chain is simulated.

    python verify/test_revocation.py
"""
import io
import json
import os
import sys
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_evidence as v  # noqa: E402

ISSUER = '4e881c8217945f356900eb5e9e66fcbb05da3829'
OTHER = 'ca08120874f071739d932b24da41cc13299123b3'
CHAIN = '4b43a753c8024c0e5000e8ac948ac0063ac624bc'
AUTH = 'dbafea3b4208d166d7922c2a1bf046de83e2c5457ea944cc47f40d41d146a038'
LO, HI = 1000, 1000 + v.DIRECT_SCAN_LIMIT + 50_000  # long: history-assisted
SHORT_HI = LO + 20                                   # short: every block scanned


def revocation(revokes=AUTH):
    return {'schema': v.REVOCATION_SCHEMA, 'revokes': revokes, 'issuer': ISSUER}


def tx(rec, sender=ISSUER, signers=None, chain=CHAIN, schema=v.REVOCATION_SCHEMA):
    hp = {'schema': 'network.xyo.hash', 'hash': v.xyo_hash(rec)}
    return {'schema': 'network.xyo.boundwitness', 'from': sender, 'addresses': signers or [sender], 'chain': chain,
            'payload_schemas': ['network.xyo.hash', schema], 'payload_hashes': [v.xyo_hash(hp), v.xyo_hash(rec)],
            'script': ['elevate|' + v.xyo_hash(hp)], '$signatures': ['00'], 'nbf': 1, 'exp': 2}


def block(n, top=(), elevated=(), with_records=()):
    """A block whose own payload_hashes list `top` (its transactions); `elevated` payloads ride along unlisted."""
    ps = list(top) + list(elevated) + list(with_records)
    return ({'schema': 'network.xyo.boundwitness', 'block': n, 'payload_hashes': [v.xyo_hash(p) for p in top]}, ps)


class World:
    def __init__(self, blocks=None, history=None, span=None, rpc_error=None):
        self.blocks, self.fetched = blocks or {}, []
        self.history = [] if history is None else history
        self.span, self.rpc_error = span or [0, HI + 10], rpc_error

    def fetch(self, url, body=None, attempts=3):
        n = int(url.rsplit('/', 1)[1].split('.')[0])
        self.fetched.append(n)
        if n not in self.blocks:
            if LO <= n <= HI:
                return json.dumps(block(n)).encode()  # an empty block
            raise urllib.error.HTTPError(url, 404, 'not found', {}, io.BytesIO())
        return json.dumps(self.blocks[n]).encode()

    def rpc(self, net, method, params):
        assert method == 'accountBalanceViewer_qualifiedAccountBalanceHistories' and params == [[ISSUER], {}]
        if self.rpc_error:
            raise self.rpc_error
        return [{ISSUER: self.history}, {'head': 'ab' * 32, 'range': self.span}]


def sent(n, frm=ISSUER):
    return [{'block': n, 'schema': 'network.xyo.boundwitness'}, None, {'schema': 'network.xyo.transfer', 'from': frm, 'transfers': {}}]


class Revocation(unittest.TestCase):
    def run_check(self, world, hi=HI, lookup=None):
        old = v.fetch, v.rpc
        v.fetch, v.rpc = world.fetch, world.rpc
        try:
            return v.revocation_check('sequence', ISSUER, AUTH, CHAIN, LO, hi, lookup)
        finally:
            v.fetch, v.rpc = old

    # What counts as a revocation
    def test_valid_revocation_fails_the_record(self):
        r = revocation()
        w = World({5000: block(5000, top=[tx(r)], with_records=[r])}, [sent(5000)])
        ok, detail = self.run_check(w)
        self.assertIs(ok, False, detail)
        self.assertIn('#[5000]', detail)

    def test_valid_revocation_found_by_direct_scan(self):
        r = revocation()
        ok, _ = self.run_check(World({LO + 3: block(LO + 3, top=[tx(r)], with_records=[r])}), hi=SHORT_HI)
        self.assertIs(ok, False)

    def test_elevated_revocation_never_counts(self):
        r = revocation()  # issuer-shaped bound witness carried in, not a transaction of the block
        w = World({LO + 3: block(LO + 3, elevated=[tx(r)], with_records=[r])})
        ok, detail = self.run_check(w, hi=SHORT_HI)
        self.assertIs(ok, True, detail)

    def test_forged_sender_field_never_counts(self):
        r = revocation()  # claims from=issuer but signed by someone else
        w = World({LO + 3: block(LO + 3, top=[tx(r, signers=[OTHER])], with_records=[r])})
        self.assertIs(self.run_check(w, hi=SHORT_HI)[0], True)

    def test_other_sender_never_counts(self):
        r = revocation()
        w = World({LO + 3: block(LO + 3, top=[tx(r, sender=OTHER)], with_records=[r])})
        self.assertIs(self.run_check(w, hi=SHORT_HI)[0], True)

    def test_other_chain_never_counts(self):
        r = revocation()
        w = World({LO + 3: block(LO + 3, top=[tx(r, chain='ff' * 20)], with_records=[r])})
        self.assertIs(self.run_check(w, hi=SHORT_HI)[0], True)

    def test_revocation_of_another_authorization_is_ignored(self):
        r = revocation(revokes='ee' * 32)
        w = World({5000: block(5000, top=[tx(r)], with_records=[r])}, [sent(5000)])
        self.assertIs(self.run_check(w)[0], True)

    def test_unreadable_revocation_target_is_not_evaluated(self):
        r = revocation()  # committed by hash only; the record is nowhere to be read
        w = World({5000: block(5000, top=[tx(r)])}, [sent(5000)])
        ok, detail = self.run_check(w)
        self.assertIsNone(ok)
        self.assertIn('cannot be read', detail)

    def test_published_revocation_record_is_read_when_hash_matches(self):
        r = revocation()
        w = World({5000: block(5000, top=[tx(r)])}, [sent(5000)])
        self.assertIs(self.run_check(w, lookup=lambda h: r if h == v.xyo_hash(r) else None)[0], False)

    def test_tampered_published_record_is_rejected(self):
        r = revocation()
        fake = revocation(revokes='ee' * 32)  # served under the committed hash, but does not re-hash to it
        w = World({5000: block(5000, top=[tx(r)])}, [sent(5000)])
        self.assertIsNone(self.run_check(w, lookup=lambda h: fake)[0])

    # When the history-assisted scan may conclude (fail closed)
    def test_clean_history_verifies_and_reads_only_issuer_blocks(self):
        a = {'schema': 'oxyon.evidence.authorization.v1', 'x': 1}
        w = World({LO: block(LO, top=[tx(a, schema='oxyon.evidence.authorization.v1')])}, [sent(LO), sent(LO + 7, frm=OTHER)])
        ok, detail = self.run_check(w)
        self.assertIs(ok, True, detail)
        self.assertEqual(w.fetched, [LO])
        self.assertIn('balance history', detail)

    def test_history_range_short_of_the_interval_is_not_evaluated(self):
        ok, detail = self.run_check(World(history=[], span=[0, HI - 1]))
        self.assertIsNone(ok)
        self.assertIn('covers', detail)

    def test_history_starting_after_the_authorization_is_not_evaluated(self):
        self.assertIsNone(self.run_check(World(history=[], span=[LO + 1, HI + 10]))[0])

    def test_malformed_history_entry_is_not_evaluated(self):
        self.assertIsNone(self.run_check(World(history=[['oops']]))[0])

    def test_history_unavailable_is_not_evaluated(self):
        self.assertIsNone(self.run_check(World(rpc_error=v.Unavailable('down')))[0])
        self.assertIsNone(self.run_check(World(rpc_error=RuntimeError('rpc error')))[0])

    def test_missing_candidate_block_is_not_evaluated(self):
        ok, detail = self.run_check(World(history=[sent(HI + 5)], span=[0, HI + 10]), hi=HI)
        self.assertIs(ok, True)  # outside the interval: not a candidate
        w = World(history=[sent(5000)])
        w.blocks = {}
        w.fetch = lambda url, body=None, attempts=3: (_ for _ in ()).throw(urllib.error.HTTPError(url, 404, 'nf', {}, io.BytesIO()))
        ok, detail = self.run_check(w)
        self.assertIsNone(ok)
        self.assertIn('could not be read', detail)

    def test_history_block_without_issuer_transaction_is_inconsistent(self):
        ok, detail = self.run_check(World(history=[sent(5000)]))  # block 5000 is empty
        self.assertIsNone(ok)
        self.assertIn('inconsistent', detail)

    def test_duplicate_history_entries_read_once(self):
        a = {'schema': 'oxyon.evidence.authorization.v1', 'x': 2}
        w = World({5000: block(5000, top=[tx(a, schema='oxyon.evidence.authorization.v1')])}, [sent(5000), sent(5000), sent(5000)])
        self.assertIs(self.run_check(w)[0], True)
        self.assertEqual(w.fetched, [5000])

    def test_incoming_transfers_are_not_candidates(self):
        w = World(history=[sent(5000, frm=OTHER)])
        self.assertIs(self.run_check(w)[0], True)
        self.assertEqual(w.fetched, [])

    # Documented limitation, and the direct scan as oracle
    def test_revocation_hidden_from_history_is_a_disclosed_trust(self):
        """If XYO's history omitted an issuer transaction, the long-interval scan would miss it. That trust in XYO's
        transfer index is disclosed in the check's detail; the direct scan (the oracle) still finds it."""
        r = revocation()
        blocks = {LO + 3: block(LO + 3, top=[tx(r)], with_records=[r])}
        ok, detail = self.run_check(World(dict(blocks), history=[]))
        self.assertIs(ok, True)
        self.assertIn('as XYO reports it', detail)
        self.assertIs(self.run_check(World(dict(blocks)), hi=SHORT_HI)[0], False)


if __name__ == '__main__':
    unittest.main(verbosity=2)
