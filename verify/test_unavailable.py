#!/usr/bin/env python3
"""Offline test: when XYO's endpoints cannot be reached, the verifier says UNAVAILABLE (exit 3),
never FAIL (exit 1). Standard library only; points the verifier at a proxy that refuses connections.

    python verify/test_unavailable.py
"""
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RECORD = os.path.join(ROOT, 'records/sequence/2026/10/09/14-82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05.json')


class Unreachable(unittest.TestCase):
    def test_unreachable_network_is_unavailable_not_failed(self):
        dead = 'http://127.0.0.1:9'  # nothing listens on port 9 (discard)
        env = {**os.environ, 'HTTPS_PROXY': dead, 'HTTP_PROXY': dead, 'https_proxy': dead, 'http_proxy': dead, 'NO_PROXY': '', 'no_proxy': ''}
        p = subprocess.run([sys.executable, os.path.join(HERE, 'verify_evidence.py'), RECORD],
                           capture_output=True, text=True, encoding='utf-8', errors='replace', env=env, timeout=120)
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr[-500:])
        self.assertIn('[UNAVAILABLE]', p.stdout)
        self.assertIn('Nothing was concluded', p.stdout)
        self.assertNotIn('[FAIL]', p.stdout)
        self.assertNotIn('Traceback', p.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
