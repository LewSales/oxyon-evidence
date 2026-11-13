#!/usr/bin/env python3
"""Offline tests for the opt-in evidence receipt (--receipt <file>). Standard library only.

    python verify/test_receipt.py

No network: end-to-end cases run behind a proxy that refuses connections, so any read fails fast
and shows up as exit 3. The receipt is an output layer only; these tests check that it never
claims more than the verifier established, and that the default output does not change.
"""
import hashlib
import importlib.util
import inspect
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERIFIER = os.path.join(HERE, 'verify_evidence.py')
GENUINE = os.path.join(ROOT, 'records/sequence/2026/10/09/14-82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05.json')
MISSING_AUTH = os.path.join(HERE, 'fixtures/missing-authorization.json')
PENDING = os.path.join(HERE, 'fixtures/winlew/synthetic-pending.json')
LEAKS = os.path.join(HERE, 'fixtures/winlew/leaks-member-id.json')
OFFLINE = {**os.environ, 'HTTPS_PROXY': 'http://127.0.0.1:9', 'HTTP_PROXY': 'http://127.0.0.1:9',
           'https_proxy': 'http://127.0.0.1:9', 'http_proxy': 'http://127.0.0.1:9', 'PYTHONIOENCODING': 'utf-8'}

spec = importlib.util.spec_from_file_location('verify_evidence', VERIFIER)
ve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ve)


def receipt(rows, code, legs=None):
    return ve.build_receipt({'rows': rows, 'legs': legs or {}}, code, ['verify_evidence.py', 'r.json'],
                            '2026-01-01T00:00:00Z', 'a' * 64, '3.13.5')


def run(path, *extra):
    return subprocess.run([sys.executable, VERIFIER, path, *extra], capture_output=True, text=True,
                          encoding='utf-8', errors='replace', env=OFFLINE, timeout=300)


def walk(v):
    if isinstance(v, dict):
        for x in v.values():
            yield from walk(x)
    elif isinstance(v, list):
        for x in v:
            yield from walk(x)
    else:
        yield v


class OutcomeMapping(unittest.TestCase):
    def test_all_passed_is_verified(self):
        self.assertEqual(receipt([(True, 'a', ''), (True, 'b', '')], 0)['outcome']['status'], 'VERIFIED')

    def test_pending_check_never_verified(self):
        r = receipt([(True, 'a', ''), (None, 'b', 'not broadcast yet')], 0)
        self.assertEqual(r['outcome']['status'], 'INCONCLUSIVE')
        self.assertEqual(r['checks'][1]['status'], 'NOT_EVALUATED')

    def test_failed(self):
        self.assertEqual(receipt([(True, 'a', ''), (False, 'b', '')], 1)['outcome']['status'], 'FAILED')

    def test_a_failed_row_wins_even_with_exit_0(self):
        self.assertEqual(receipt([(False, 'b', '')], 0)['outcome']['status'], 'FAILED')

    def test_incomplete_is_inconclusive(self):
        self.assertEqual(receipt([], 2)['outcome']['status'], 'INCONCLUSIVE')

    def test_unavailable_is_not_evaluated(self):
        self.assertEqual(receipt([(True, 'a', '')], 3)['outcome']['status'], 'NOT_EVALUATED')

    def test_no_checks_is_not_evaluated(self):
        self.assertEqual(receipt([], 0)['outcome']['status'], 'NOT_EVALUATED')

    def test_crash_is_not_evaluated(self):
        self.assertEqual(receipt([(True, 'a', '')], 99)['outcome']['status'], 'NOT_EVALUATED')


class Disclosures(unittest.TestCase):
    def setUp(self):
        legs = {'anchorTx': {'network': 'sequence', 'tx': 't', 'rpc': ve.NETS['sequence'][0], 'found': True, 'block': 5,
                             'blockHash': 'h', 'finalizedHead': 9, 'final': True, 'signedTime': 1, 'producerAddress': 'p'}}
        self.r = receipt([(True, 'a', '')], 0, legs)

    def test_signatures_not_evaluated(self):
        self.assertEqual(self.r['scope']['signatures']['status'], 'NOT_EVALUATED')
        self.assertNotIn('signature', ' '.join(c['title'].lower() for c in self.r['checks']))

    def test_finality_is_rpc_reported(self):
        f = self.r['scope']['finality']
        self.assertIs(f['independentlyEstablished'], False)
        self.assertIn('XYO RPC', f['trustDependency'])
        self.assertIn('finalizationViewer_head', f['rule'])
        self.assertEqual(f['legs']['anchorTx']['finalizedHead'], 9)

    def test_producer_attribution_inferred(self):
        self.assertEqual(self.r['scope']['producerAttribution']['status'], 'INFERRED')
        self.assertEqual(self.r['scope']['producerAttribution']['legs']['anchorTx'], 'p')

    def test_reproduction_does_not_promise_identical_bytes(self):
        self.assertIn('not expected to be byte-identical', self.r['reproduce']['mayDiffer'])

    def test_reproduction_is_the_original_invocation(self):
        rp = self.r['reproduce']
        self.assertEqual(rp['argv'], ['python', 'verify_evidence.py', 'r.json'])
        self.assertEqual(shlex.split(rp['command']), rp['argv'])
        self.assertEqual(rp['commandWindows'], subprocess.list2cmdline(rp['argv']))

    def test_awkward_paths_are_quoted(self):
        argv = ['verify/verify_evidence.py', "dir with spaces & 'q' $(x);/rec.json", '--anchor-tx', 'ab']
        rp = ve.build_receipt({'rows': [], 'legs': {}}, 0, argv, 't', 'a' * 64, '3')['reproduce']
        self.assertEqual(rp['argv'], ['python'] + argv)
        self.assertEqual(shlex.split(rp['command']), rp['argv'], 'POSIX quoting must round-trip')

    def test_portable_values_only(self):
        for v in walk(self.r):
            self.assertTrue(v is None or isinstance(v, (str, bool)) or (isinstance(v, int) and abs(v) < 2 ** 53), repr(v))


class NoNewReads(unittest.TestCase):
    def test_receipt_code_has_no_network_calls(self):
        for fn in (ve.build_receipt, ve._write_receipt, ve._leg_facts, ve._take_receipt_arg, ve._receipt_path_problem):
            src = inspect.getsource(fn)
            for call in ('rpc(', 'fetch(', 'tx_on_chain(', 'urlopen('):
                self.assertNotIn(call, src, f'{fn.__name__} calls {call}')

    def test_build_receipt_runs_with_network_disabled(self):
        def boom(*a, **k):
            raise AssertionError('network used during receipt generation')
        saved = ve.rpc, ve.fetch
        ve.rpc = ve.fetch = boom
        try:
            receipt([(True, 'a', '')], 0)
        finally:
            ve.rpc, ve.fetch = saved


class EndToEndOffline(unittest.TestCase):
    """Default output and exit codes are unchanged; the receipt only adds a file."""

    def compare(self, path, want_code, want_status):
        plain = run(path)
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, 'receipt.json')
            withr = run(path, '--receipt', out)
            self.assertEqual(plain.returncode, want_code)
            self.assertEqual(withr.returncode, plain.returncode, 'exit code changed by --receipt')
            self.assertEqual(withr.stdout, plain.stdout, 'stdout changed by --receipt')
            with open(out, encoding='utf-8') as fh:
                r = json.load(fh)
        self.assertEqual(r['outcome']['status'], want_status)
        self.assertEqual(r['outcome']['exitCode'], want_code)
        self.assertEqual(r['scope']['signatures']['status'], 'NOT_EVALUATED')
        self.assertEqual(r['scope']['producerAttribution']['status'], 'INFERRED')
        self.assertNotIn('--receipt', r['reproduce']['command'])
        return r

    def test_incomplete_record(self):
        self.compare(MISSING_AUTH, 2, 'INCONCLUSIVE')

    def test_pending_record_exit_0_is_not_verified(self):
        r = self.compare(PENDING, 0, 'INCONCLUSIVE')
        self.assertGreater(r['outcome']['counts']['notEvaluated'], 0)

    def test_failed_record(self):
        self.compare(LEAKS, 1, 'FAILED')

    def test_unreachable_sources_are_not_evaluated(self):
        r = self.compare(GENUINE, 3, 'NOT_EVALUATED')
        self.assertIn('UNAVAILABLE', r['outcome']['reason'])

    def test_flag_without_path_is_a_usage_error(self):
        p = run(PENDING, '--receipt')
        self.assertEqual(p.returncode, 4)
        self.assertEqual(p.stdout, '')


def sha(path):
    with open(path, 'rb') as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class FileSafety(unittest.TestCase):
    """A receipt never overwrites anything, and never changes the verdict or exit code."""

    def setUp(self):
        # Work on a COPY of the self-contained WinLEW fixture (record + blobs/), never the repository's files.
        self.tmp = tempfile.mkdtemp()
        self.dir = os.path.join(self.tmp, 'winlew')
        shutil.copytree(os.path.dirname(PENDING), self.dir)
        self.record = os.path.join(self.dir, 'synthetic-pending.json')
        self.baseline = run(self.record)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def refused(self, target, record=None, cwd=None, why='never overwrites'):
        record = record or self.record
        before = sha(self.record)
        p = subprocess.run([sys.executable, VERIFIER, record, '--receipt', target], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', env=OFFLINE, timeout=300, cwd=cwd)
        self.assertEqual(p.returncode, self.baseline.returncode, 'exit code changed')
        self.assertEqual(p.stdout, self.baseline.stdout, 'verdict output changed')
        self.assertIn('receipt not written', p.stderr)
        self.assertIn(why, p.stderr)
        self.assertEqual(sha(self.record), before, 'the evidence record was modified')
        return p

    def test_existing_file_is_not_overwritten(self):
        other = os.path.join(self.tmp, 'exists.json')
        with open(other, 'w', encoding='utf-8') as fh:
            fh.write('keep me')
        self.refused(other, why='already exists')
        with open(other, encoding='utf-8') as fh:
            self.assertEqual(fh.read(), 'keep me')

    def test_source_record_same_path(self):
        self.refused(self.record, why='a receipt never overwrites evidence')

    def test_source_record_relative_and_dotdot_spelling(self):
        spelled = os.path.join('winlew', '..', 'winlew', 'synthetic-pending.json')
        self.refused(spelled, record=os.path.join('winlew', 'synthetic-pending.json'), cwd=self.tmp,
                     why='a receipt never overwrites evidence')

    def test_source_record_through_symlink(self):
        link = os.path.join(self.tmp, 'link.json')
        try:
            os.symlink(self.record, link)
        except (OSError, NotImplementedError):
            self.skipTest('this system does not allow creating symbolic links')
        self.refused(link, why='a receipt never overwrites evidence')

    def test_dangling_symlink_is_refused(self):
        link = os.path.join(self.tmp, 'dangling.json')
        try:
            os.symlink(os.path.join(self.tmp, 'nowhere.json'), link)
        except (OSError, NotImplementedError):
            self.skipTest('this system does not allow creating symbolic links')
        self.refused(link, why='already exists')
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'nowhere.json')))

    def test_existing_directory_is_refused(self):
        self.refused(self.dir, why='already exists')


class AwkwardPaths(unittest.TestCase):
    """Paths with spaces and shell-special characters: the receipt is written, and its reproduction
    arguments re-run the same verification."""

    def test_spaces_and_special_characters(self):
        tmp = tempfile.mkdtemp()
        try:
            base = os.path.join(tmp, "evidence dir & (x) 'q'")
            shutil.copytree(os.path.dirname(PENDING), os.path.join(base, 'win lew'))
            rec = os.path.join("evidence dir & (x) 'q'", 'win lew', 'synthetic-pending.json')
            out = os.path.join(tmp, 'receipt with spaces.json')
            first = subprocess.run([sys.executable, VERIFIER, rec, '--receipt', out], capture_output=True, text=True,
                                   encoding='utf-8', errors='replace', env=OFFLINE, timeout=300, cwd=tmp)
            self.assertEqual(first.returncode, 0, first.stderr)
            with open(out, encoding='utf-8') as fh:
                rp = json.load(fh)['reproduce']
            self.assertEqual(rp['argv'][1:], [VERIFIER, rec])
            self.assertEqual(shlex.split(rp['command']), rp['argv'])
            # Re-run from argv exactly as recorded (no shell), substituting this interpreter for 'python'.
            again = subprocess.run([sys.executable] + rp['argv'][1:], capture_output=True, text=True,
                                   encoding='utf-8', errors='replace', env=OFFLINE, timeout=300, cwd=tmp)
            self.assertEqual(again.returncode, first.returncode)
            self.assertEqual(again.stdout, first.stdout)
            if os.name == 'nt':  # the Windows rendering parses back to the same arguments (CreateProcess, no shell)
                win = subprocess.run(rp['commandWindows'].replace('python', f'"{sys.executable}"', 1), capture_output=True,
                                     text=True, encoding='utf-8', errors='replace', env=OFFLINE, timeout=300, cwd=tmp)
                self.assertEqual(win.returncode, first.returncode)
                self.assertEqual(win.stdout, first.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
