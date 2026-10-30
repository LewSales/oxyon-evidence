#!/usr/bin/env python3
"""Offline tests for tx_integrity in verify_evidence.py. No network, standard library only.

    python verify/test_tx_integrity.py

Fixtures in verify/fixtures/tx/:
  sequence-anchor.json, sequence-authorization.json  genuine, public (the first evidence record)
  synthetic-transfer.json                            SYNTHETIC: throwaway key, never broadcast
"""
import copy
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from verify_evidence import tx_integrity, xyo_hash  # noqa: E402


def fixture(name):
    with open(os.path.join(HERE, 'fixtures', 'tx', name), encoding='utf-8') as f:
        return json.load(f)


def check(fx, tx=None, payloads=None, net=None, tx_hash=None):
    return tx_integrity(tx if tx is not None else fx['tx'], payloads if payloads is not None else fx['payloads'],
                        net or fx['network'], fx['txHash'] if tx_hash is None else tx_hash)


def rehashed(p):
    """The payload with its _hash recomputed: what a forger would send to look consistent."""
    q = {k: v for k, v in p.items() if not k.startswith('_')}
    return {**q, '_hash': xyo_hash(q)}


class Genuine(unittest.TestCase):
    def test_historical_evidence_transactions_pass(self):
        for name in ('sequence-anchor.json', 'sequence-authorization.json'):
            out = check(fixture(name))
            self.assertEqual(out['problems'], [], name)
            self.assertEqual(out['elevated'], 1, name)

    def test_synthetic_transfer_passes_and_decodes(self):
        out = check(fixture('synthetic-transfer.json'))
        self.assertEqual(out['problems'], [])
        self.assertEqual(out['unverified'], [])
        self.assertEqual(sorted(a for _, _, a in out['transfers']), [10**18, 2 * 10**18])

    def test_optional_data_is_accepted(self):
        fx = fixture('synthetic-transfer.json')
        # Off-chain payloads are committed by hash but not elevated; storage metadata is not signed.
        extra = fx['payloads'] + fx['offChainPayloads']
        extra = [{**p, '_sequence': '0' * 32, '_dataHash': 'anything'} for p in extra]
        self.assertEqual(check(fx, payloads=extra)['problems'], [])
        # The RPC may return no off-chain payloads at all; only elevated ones are required.
        self.assertEqual(check(fx, payloads=fx['payloads'])['problems'], [])

    def test_unfamiliar_committed_schema_is_accepted(self):
        fx = fixture('synthetic-transfer.json')
        note = fx['offChainPayloads'][0]
        self.assertTrue(note['schema'].startswith('org.example.'))
        self.assertEqual(check(fx, payloads=fx['payloads'] + [note])['problems'], [])


class Tampering(unittest.TestCase):
    def setUp(self):
        self.fx = fixture('synthetic-transfer.json')
        self.transfer = self.fx['payloads'][0]

    def edited(self, **changes):
        return [{**self.transfer, **changes}]

    def assertRejected(self, out, words):
        self.assertTrue(out['problems'], 'expected a problem')
        self.assertTrue(any(words in p for p in out['problems']), out['problems'])

    def test_amount_edited_with_stale_hash_metadata(self):
        moves = dict(self.transfer['transfers'])
        moves[next(iter(moves))] = '8ac7230489e80000'
        out = check(self.fx, payloads=self.edited(transfers=moves))
        self.assertRejected(out, '_hash metadata does not match')
        self.assertRejected(out, 'not committed by the signed transaction')

    def test_amount_edited_with_consistent_hash_metadata(self):
        moves = dict(self.transfer['transfers'])
        moves[next(iter(moves))] = '8ac7230489e80000'
        out = check(self.fx, payloads=[rehashed({**self.transfer, 'transfers': moves})])
        self.assertRejected(out, 'not committed by the signed transaction')
        self.assertRejected(out, 'elevated payload')
        self.assertEqual(out['transfers'], [])  # nothing decoded from an uncommitted payload

    def test_recipient_edited(self):
        amounts = list(self.transfer['transfers'].values())
        moves = {'ef' * 20: amounts[0], **{k: v for k, v in list(self.transfer['transfers'].items())[1:]}}
        self.assertRejected(check(self.fx, payloads=[rehashed({**self.transfer, 'transfers': moves})]), 'not committed')

    def test_asset_edited(self):
        # XL1 has no per-transfer asset field: the native token is fixed by the schema and chain.
        out = check(self.fx, payloads=[rehashed({**self.transfer, 'schema': 'network.xyo.transfer.other'})])
        self.assertRejected(out, 'not committed')
        self.assertRejected(check(self.fx, net='sequence'), 'is not sequence')

    def test_sender_edited(self):
        self.assertRejected(check(self.fx, payloads=[rehashed({**self.transfer, 'from': 'ef' * 20})]), 'not committed')

    def test_wrong_network(self):
        self.assertRejected(check(self.fx, net='sequence'), 'is not sequence')
        self.assertRejected(check(fixture('sequence-anchor.json'), net='mainnet'), 'is not mainnet')
        self.assertRejected(check(self.fx, net='devnet'), 'unknown network')

    def test_chain_field_edited(self):
        tx = {**self.fx['tx'], 'chain': '4b43a753c8024c0e5000e8ac948ac0063ac624bc'}
        out = check(self.fx, tx=tx)
        self.assertRejected(out, 'is not mainnet')
        self.assertRejected(out, 'transaction hashes to')

    def test_signature_edited(self):
        sig = self.fx['tx']['$signatures'][0]
        tx = {**self.fx['tx'], '$signatures': [sig[:-2] + ('00' if sig[-2:] != '00' else '11')]}
        self.assertRejected(check(self.fx, tx=tx), 'transaction hashes to')

    def test_signature_removed(self):
        tx = {**self.fx['tx'], '$signatures': []}
        self.assertRejected(check(self.fx, tx=tx), 'one signature per address')

    def test_missing_commitment(self):
        tx = copy.deepcopy(self.fx['tx'])
        h = tx['script'][0].split('|')[1]
        i = tx['payload_hashes'].index(h)
        del tx['payload_hashes'][i], tx['payload_schemas'][i]
        out = check(self.fx, tx=tx)
        self.assertRejected(out, 'is not in payload_hashes')
        self.assertRejected(out, 'transaction hashes to')

    def test_missing_elevated_payload(self):
        self.assertRejected(check(self.fx, payloads=[]), 'elevated payload')

    def test_malformed_input_fails_without_crashing(self):
        for tx, payloads in ((None, []), ({}, []), (self.fx['tx'], None), (self.fx['tx'], ['x']),
                             ({**self.fx['tx'], 'script': 'elevate|x'}, self.fx['payloads']),
                             ({**self.fx['tx'], 'script': ['elevate|zz']}, self.fx['payloads']),
                             ({**self.fx['tx'], 'nbf': 'one'}, self.fx['payloads'])):
            self.assertTrue(tx_integrity(tx, payloads, 'mainnet', self.fx['txHash'])['problems'])

    def test_transfer_from_another_address_is_unverified_not_accepted_silently(self):
        # Build a consistent case: the tx commits to a transfer whose sender is not the signer.
        # Re-signing is impossible here, so check the rule on a copy without the tx-hash check.
        other = rehashed({**self.transfer, 'from': 'ef' * 20})
        tx = copy.deepcopy(self.fx['tx'])
        old = self.transfer['_hash']
        tx['payload_hashes'] = [other['_hash'] if h == old else h for h in tx['payload_hashes']]
        tx['script'] = [f"elevate|{other['_hash']}" if op == f'elevate|{old}' else op for op in tx['script']]
        tx.pop('_hash', None)
        out = tx_integrity(tx, [other], 'mainnet')
        self.assertEqual(out['problems'], [])
        self.assertTrue(out['unverified'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
