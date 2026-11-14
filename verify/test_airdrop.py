#!/usr/bin/env python3
"""Offline tests for WinLEW airdrop records: the snapshot's shape, and that a distribution pays exactly the anchored
snapshot, as Solana shows it, after the snapshot was on XL1. Synthetic wallets and a simulated Solana RPC only.

    python verify/test_airdrop.py
"""
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_evidence as v  # noqa: E402

MINT = 'DnrcdQVH7fdbmm4EyD7LjT9mNNozF5HuWMeKcpvjpump'
TREASURY = 'Treasury'.ljust(44, 'z')
W = ['Rcpt' + c.ljust(40, 'z') for c in 'abc']  # synthetic, sorted
SIG = ['5ig' + c * 85 for c in 'abc']


def snapshot(**over):
    s = {'schema': v.AIRDROP_SNAPSHOT, 'event': 'winlew-2y-anniversary', 'takenAt': '2026-12-06T00:00:00.000Z', 'source': 's',
         'rule': 'each registered wallet receives 1,000 WinLEW', 'token': {'network': 'solana:mainnet', 'mint': MINT, 'decimals': 6},
         'treasury': TREASURY, 'recipients': [{'wallet': w, 'amountRaw': '1000000000'} for w in W], 'excluded': [],
         'totals': {'recipients': 3, 'amountRaw': '3000000000', 'duplicatesMerged': 0, 'invalidEntries': 0}}
    s.update(over)
    return s


def transfer_tx(pays, sender=TREASURY, mint=MINT, decimals=6, err=None, block_time=1796600000):
    """A parsed Solana transaction moving `pays` ({wallet: raw}) of `mint` from `sender`."""
    total = sum(pays.values())
    pre = [{'accountIndex': 1, 'mint': mint, 'owner': sender, 'uiTokenAmount': {'amount': str(10**15), 'decimals': decimals}}]
    post = [{'accountIndex': 1, 'mint': mint, 'owner': sender, 'uiTokenAmount': {'amount': str(10**15 - total), 'decimals': decimals}}]
    for i, (w, a) in enumerate(pays.items()):
        pre.append({'accountIndex': i + 2, 'mint': mint, 'owner': w, 'uiTokenAmount': {'amount': '5', 'decimals': decimals}})
        post.append({'accountIndex': i + 2, 'mint': mint, 'owner': w, 'uiTokenAmount': {'amount': str(5 + a), 'decimals': decimals}})
    return {'blockTime': block_time, 'slot': 1, 'meta': {'err': err, 'preTokenBalances': pre, 'postTokenBalances': post}}


class Repo:
    """A temporary evidence repository holding one anchored snapshot record."""
    def __init__(self, snap):
        self.root = tempfile.mkdtemp()
        raw = (json.dumps(snap, indent=2) + '\n').encode()
        sha = hashlib.sha256(raw).hexdigest()
        os.makedirs(os.path.join(self.root, 'blobs', 'sha256', sha[:2]))
        self.write(os.path.join('blobs', 'sha256', sha[:2], sha + '.json'), raw)
        rec = {'claim': {'type': 'winlew.airdrop.snapshot'}, 'subject': {'network': 'mainnet'}, 'content': {'sha256': sha, 'bytes': len(raw)}}
        self.hash = v.xyo_hash(rec)
        os.makedirs(os.path.join(self.root, 'records'))
        self.write(os.path.join('records', 's.json'), json.dumps({'record': rec, 'receipt': {'tx': 'aa' * 32}}).encode())
        self.write('index.json', json.dumps({'records': [{'record': self.hash, 'path': 'records/s.json'}]}).encode())

    def write(self, rel, data, mode='wb'):
        with open(os.path.join(self.root, rel), mode) as f:
            f.write(data)

    def close(self):
        shutil.rmtree(self.root)


def distribution(repo, snap, sigs=None):
    sigs = sigs or SIG
    return {'schema': v.AIRDROP_DISTRIBUTION, 'event': snap['event'], 'snapshot': {'record': repo.hash},
            'token': snap['token'], 'treasury': snap['treasury'],
            'transfers': [{'wallet': r['wallet'], 'amountRaw': r['amountRaw'], 'signature': sigs[i]} for i, r in enumerate(snap['recipients'])]}


class Airdrop(unittest.TestCase):
    def run_dist(self, dist, repo, txs, anchor_time=1796500000000, final=True, rpc_error=None):
        rows, old = [], (v.solana_rpc, v.tx_on_chain)

        def fake_rpc(url, method, params):
            if rpc_error:
                raise rpc_error
            return copy.deepcopy(txs.get(params[0]))
        v.solana_rpc = fake_rpc
        v.tx_on_chain = lambda net, h: {'found': True, 'time': anchor_time, 'final': final, 'block': {'block': 42}}
        try:
            v.check_airdrop_distribution(dist, repo.root, 'https://solana.invalid', lambda ok, t, d: rows.append((ok, t, d)),
                                         lambda t, d: rows.append(('STATEMENT', t, d)))
        finally:
            v.solana_rpc, v.tx_on_chain = old
        return {t: ok for ok, t, d in rows if ok != 'STATEMENT'}, rows

    def setUp(self):
        self.snap = snapshot()
        self.repo = Repo(self.snap)
        self.good = {SIG[i]: transfer_tx({W[i]: 1000000000}) for i in range(3)}

    def tearDown(self):
        self.repo.close()

    # The snapshot
    def test_well_formed_snapshot(self):
        self.assertEqual(v.airdrop_snapshot_problems(self.snap), [])

    def test_snapshot_problems(self):
        cases = {
            'a wallet is listed twice': snapshot(recipients=[{'wallet': W[0], 'amountRaw': '1'}] * 2, totals={'recipients': 2, 'amountRaw': '2'}),
            'not in wallet order': snapshot(recipients=list(reversed(snapshot()['recipients']))),
            'totals do not add up': snapshot(totals={'recipients': 3, 'amountRaw': '1'}),
            'not a Solana address': snapshot(recipients=[{'wallet': '0xabc', 'amountRaw': '1'}], totals={'recipients': 1, 'amountRaw': '1'}),
            'positive integer': snapshot(recipients=[{'wallet': W[0], 'amountRaw': '1.5'}], totals={'recipients': 1, 'amountRaw': '1'}),
            'treasury address is also a recipient': snapshot(treasury=W[1]),
            'no recipients': snapshot(recipients=[]),
        }
        for why, s in cases.items():
            self.assertTrue(any(why in p for p in v.airdrop_snapshot_problems(s)), why)

    # The distribution
    def test_exact_distribution_verifies(self):
        res, rows = self.run_dist(distribution(self.repo, self.snap), self.repo, self.good)
        self.assertEqual(set(res.values()), {True}, rows)
        self.assertIn('The snapshot was on XL1 before the first payout', res)
        self.assertTrue(any(ok == 'STATEMENT' and 'solscan.io/tx/' in d for ok, t, d in rows))

    def test_one_transaction_paying_several_wallets(self):
        sig = SIG[0]
        res, _ = self.run_dist(distribution(self.repo, self.snap, [sig] * 3), self.repo, {sig: transfer_tx({w: 1000000000 for w in W})})
        self.assertIs(res['Every payout is on Solana as listed'], True)

    def test_list_differing_from_snapshot_fails(self):
        for mutate in (lambda d: d['transfers'].pop(),
                       lambda d: d['transfers'].append(dict(d['transfers'][0])),
                       lambda d: d['transfers'][0].update(amountRaw='999'),
                       lambda d: d['transfers'][0].update(wallet='Other'.ljust(44, 'z')),
                       lambda d: d.update(treasury=W[0]),
                       lambda d: d['token'].update(mint='Fake'.ljust(44, 'z'))):
            d = copy.deepcopy(distribution(self.repo, self.snap))
            mutate(d)
            res, _ = self.run_dist(d, self.repo, self.good)
            self.assertIs(res['Payouts match the snapshot exactly'], False)

    def test_solana_disagreeing_fails(self):
        cases = [
            transfer_tx({W[0]: 999}),                       # wrong amount
            transfer_tx({W[1]: 1000000000}),                # wrong recipient
            transfer_tx({W[0]: 1000000000}, sender='Else'.ljust(44, 'z')),  # not from the treasury
            transfer_tx({W[0]: 1000000000}, mint='Fake'.ljust(44, 'z')),    # another token
            transfer_tx({W[0]: 1000000000}, decimals=9),    # decimals differ
            transfer_tx({W[0]: 1000000000}, err={'InstructionError': [0, 'x']}),  # failed transaction
            transfer_tx({W[0]: 1000000000, 'Extra'.ljust(44, 'z'): 5}),  # someone else paid too
            None,                                           # not found / not finalized
        ]
        for tx in cases:
            txs = dict(self.good, **{SIG[0]: tx})
            res, rows = self.run_dist(distribution(self.repo, self.snap), self.repo, txs)
            self.assertIs(res['Every payout is on Solana as listed'], False, (tx, rows))

    def test_payout_before_snapshot_anchor_fails(self):
        res, _ = self.run_dist(distribution(self.repo, self.snap), self.repo, self.good, anchor_time=1796600000001)
        self.assertIs(res['The snapshot was on XL1 before the first payout'], False)

    def test_snapshot_anchor_not_final_is_not_evaluated(self):
        res, _ = self.run_dist(distribution(self.repo, self.snap), self.repo, self.good, final=False)
        self.assertIsNone(res['The snapshot was on XL1 before the first payout'])

    def test_solana_unreachable_is_not_evaluated(self):
        res, _ = self.run_dist(distribution(self.repo, self.snap), self.repo, self.good, rpc_error=v.Unavailable('down'))
        self.assertIsNone(res['Every payout is on Solana as listed'])

    def test_missing_or_tampered_snapshot_is_not_evaluated(self):
        d = distribution(self.repo, self.snap)
        d['snapshot']['record'] = 'ff' * 32
        res, _ = self.run_dist(d, self.repo, self.good)
        self.assertIsNone(res['The snapshot it pays is published'])
        blob = next(os.path.join(dp, f) for dp, _, fs in os.walk(os.path.join(self.repo.root, 'blobs')) for f in fs)
        with open(blob, 'ab') as f:
            f.write(b' ')
        res, _ = self.run_dist(distribution(self.repo, self.snap), self.repo, self.good)
        self.assertIsNone(res['The snapshot it pays is published'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
