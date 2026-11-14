#!/usr/bin/env python3
"""Offline adversarial tests (Sprint 005): broken or misleading input never yields VERIFIED, and never a
traceback dressed up as a failed check. Runs with every proxy pointed at a dead port, so no network is used.

    python verify/test_adversarial.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RECORD = os.path.join(ROOT, 'records/sequence/2026/10/09/14-82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05.json')
DEAD = 'http://127.0.0.1:9'
ENV = {**os.environ, 'HTTPS_PROXY': DEAD, 'HTTP_PROXY': DEAD, 'https_proxy': DEAD, 'http_proxy': DEAD,
       'NO_PROXY': '', 'no_proxy': '', 'PYTHONIOENCODING': 'utf-8'}


def run(path, *extra):
    return subprocess.run([sys.executable, os.path.join(HERE, 'verify_evidence.py'), path, *extra],
                          capture_output=True, text=True, encoding='utf-8', errors='replace', env=ENV, timeout=120)


class Adversarial(unittest.TestCase):
    def setUp(self):
        # Inside the repository, so repository-mode records find keys/ and reach the code under test.
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT, prefix='.adv-')
        with open(RECORD, encoding='utf-8') as fh:
            self.genuine = fh.read()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        p = os.path.join(self.tmp.name, name)
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write(text)
        return p

    def assert_incomplete(self, p, why):
        self.assertEqual(p.returncode, 2, why + '\n' + p.stdout + p.stderr[-400:])
        self.assertIn('[INCOMPLETE]', p.stdout)
        self.assertIn('not VERIFIED', p.stdout)
        self.assertNotIn('Traceback', p.stderr)
        self.assertNotIn('[ok]', p.stdout, 'no row may look like success')

    def test_truncated_json_is_incomplete_not_a_crash(self):
        self.assert_incomplete(run(self.write('truncated.json', self.genuine[:300])), 'truncated JSON')

    def test_not_json_at_all(self):
        self.assert_incomplete(run(self.write('text.json', 'this is not evidence')), 'plain text')

    def test_missing_batch_is_incomplete(self):
        d = json.loads(self.genuine)
        d.pop('batch')
        self.assert_incomplete(run(self.write('nobatch.json', json.dumps(d))), 'record without its batch')

    def test_wrong_types_are_incomplete(self):
        d = json.loads(self.genuine)
        d['record'] = 'not an object'
        self.assert_incomplete(run(self.write('types.json', json.dumps(d))), 'record of the wrong type')

    def test_malformed_receipt_is_inconclusive_and_exit_matches(self):
        out = os.path.join(self.tmp.name, 'r.json')
        p = run(self.write('truncated.json', self.genuine[:300]), '--receipt', out)
        self.assertEqual(p.returncode, 2)
        with open(out, encoding='utf-8') as fh:
            r = json.load(fh)
        self.assertEqual(r['outcome']['status'], 'INCONCLUSIVE')
        self.assertEqual(r['outcome']['exitCode'], 2, 'receipt and process exit code agree')

    def test_record_outside_a_clone_is_incomplete(self):
        with tempfile.TemporaryDirectory() as outside:
            p = os.path.join(outside, 'copy.json')
            with open(p, 'w', encoding='utf-8') as fh:
                fh.write(self.genuine)
            r = run(p)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn('[INCOMPLETE] Cannot find the repository root', r.stdout)

    def test_genuine_record_without_network_is_unavailable_never_verified(self):
        p = run(RECORD)
        self.assertEqual(p.returncode, 3)
        self.assertIn('[UNAVAILABLE]', p.stdout)
        self.assertNotIn('[FAIL]', p.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
