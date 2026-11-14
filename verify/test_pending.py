#!/usr/bin/env python3
"""Offline test (Sprint 004): a transaction awaiting XYO RPC's reported finality is PENDING, not FAILED;
actual integrity failures stay FAILED; an unreachable source stays UNAVAILABLE. Standard library only;
the chain is a synthetic, self-consistent fake behind rpc()/fetch().

    python verify/test_pending.py
"""
import json
import os
import sys
import unittest
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import verify_evidence as ve  # noqa: E402

CHAIN = '4b43a753c8024c0e5000e8ac948ac0063ac624bc'
SIGNER = 'a' * 40
COMMIT = 'c' * 64


def world(head=200, block_at=120, nbf=115, exp=130, tamper=None):
    """A tx committing COMMIT, optionally in block `block_at`; XYO RPC reports finalized head `head`."""
    tx = {'chain': CHAIN, 'addresses': [SIGNER], 'from': SIGNER, 'nbf': nbf, 'exp': exp,
          'payload_hashes': [COMMIT], 'script': []}
    tx_hash = ve.xyo_hash(tx)
    blocks = {}
    if block_at is not None:
        clock = {'schema': 'network.xyo.time', 'epoch': 1_700_000_000_000 + block_at}
        bw = {'block': block_at, 'addresses': ['d' * 40], 'payload_hashes': [tx_hash, ve.xyo_hash(clock)]}
        bw['_hash'] = ve.xyo_hash(bw)
        blocks[block_at] = [bw, [clock]]
    if tamper:
        tamper(tx, blocks)

    def rpc(net, method, params):
        if method == 'finalizationViewer_head':
            return [{'block': head, 'chain': CHAIN}]
        if method == 'transactionViewer_byHash':
            return [tx, []] if params[0] == tx_hash else None
        raise AssertionError(method)

    def fetch(url, body=None, attempts=3):
        n = int(url.rsplit('/', 1)[1].split('.')[0])
        if n not in blocks:
            raise urllib.error.HTTPError(url, 404, 'not found', {}, None)
        return json.dumps(blocks[n]).encode()
    return tx_hash, rpc, fetch


class Leg(unittest.TestCase):
    def run_leg(self, **kw):
        tx_hash, rpc, fetch = world(**kw)
        saved = ve.rpc, ve.fetch
        ve.rpc, ve.fetch = rpc, fetch
        try:
            c = ve.tx_on_chain('sequence', tx_hash)
        finally:
            ve.rpc, ve.fetch = saved
        return c, ve.leg_verdict(c, SIGNER, all(h in c['tx']['payload_hashes'] for h in [COMMIT]))

    def test_finalized_is_verified(self):
        c, (ok, why) = self.run_leg(head=200, block_at=120)
        self.assertTrue(c['final'])
        self.assertFalse(c['pending'])
        self.assertIs(ok, True)
        self.assertIsNone(why)

    def test_in_a_block_above_the_finalized_head_is_pending(self):
        c, (ok, why) = self.run_leg(head=110, block_at=120)
        self.assertFalse(c['final'])
        self.assertTrue(c['pending'])
        self.assertIsNone(ok)
        self.assertIn('Pending', why)
        self.assertIn('finalized head reported by XYO RPC', why)

    def test_not_yet_in_a_block_with_its_window_open_is_pending(self):
        c, (ok, why) = self.run_leg(head=118, block_at=None, nbf=115, exp=130)
        self.assertTrue(c['pending'])
        self.assertIsNone(ok)
        self.assertIn('window runs to #130', why)

    def test_window_passed_and_in_no_block_is_failed(self):
        c, (ok, _) = self.run_leg(head=200, block_at=None, nbf=115, exp=130)
        self.assertFalse(c['pending'])
        self.assertIs(ok, False)

    def test_tampered_block_fails_even_while_pending(self):
        def bad_block(tx, blocks):
            blocks[120][0]['_hash'] = 'f' * 64
        _, (ok, _) = self.run_leg(head=110, block_at=120, tamper=bad_block)
        self.assertIs(ok, False, 'an integrity failure is FAILED, never pending')

    def test_wrong_signer_fails_even_while_pending(self):
        tx_hash, rpc, fetch = world(head=110, block_at=120)
        saved = ve.rpc, ve.fetch
        ve.rpc, ve.fetch = rpc, fetch
        try:
            c = ve.tx_on_chain('sequence', tx_hash)
        finally:
            ve.rpc, ve.fetch = saved
        self.assertIs(ve.leg_verdict(c, 'e' * 40, True)[0], False)
        self.assertIs(ve.leg_verdict(c, SIGNER, False)[0], False, 'missing commitments fail')

    def test_unavailable_source_is_not_a_verdict(self):
        def down(*a, **k):
            raise ve.Unavailable('offline')
        saved = ve.rpc, ve.fetch
        ve.rpc = ve.fetch = down
        try:
            with self.assertRaises(ve.Unavailable):
                ve.tx_on_chain('sequence', 'f' * 64)
        finally:
            ve.rpc, ve.fetch = saved


class ReceiptOutcome(unittest.TestCase):
    """A pending leg is a NOT_EVALUATED check: the receipt is INCONCLUSIVE, never VERIFIED or FAILED."""
    def receipt(self, rows, code):
        run = {'rows': rows, 'statements': [], 'legs': {}}
        return ve.build_receipt(run, code, ['verify_evidence.py', 'x.json'], '2026-11-14T00:00:00Z', '0' * 64, '3', None)

    def test_pending_leg_is_inconclusive(self):
        r = self.receipt([(True, 'a', ''), (None, 'Anchor committed on chain', 'Pending: …')], 0)
        self.assertEqual(r['outcome']['status'], 'INCONCLUSIVE')
        self.assertEqual(r['receiptVersion'], '0.1')

    def test_failed_leg_is_failed(self):
        self.assertEqual(self.receipt([(True, 'a', ''), (False, 'b', '')], 1)['outcome']['status'], 'FAILED')


if __name__ == '__main__':
    unittest.main(verbosity=2)
