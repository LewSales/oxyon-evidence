#!/usr/bin/env python3
"""Self-test: the verifier must ACCEPT the genuine record and REJECT every broken fixture.

    python verify/selftest.py

The fixtures in verify/fixtures/ are deliberately broken copies of the first record.
They are NOT evidence. Exit code 0 means every case behaved as expected.
Needs network access (GitHub and XYO's public endpoints), like the verifier itself.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GENUINE = 'records/sequence/2026/10/09/14-82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05.json'
CASES = [
    # (file, expected exit code, text that must appear, what it shows)
    (GENUINE, 0, '[ok] Published receipt matches the chain (anchorTx)', 'genuine record verifies'),
    ('verify/fixtures/tampered-claim.json', 1, '[FAIL] Record is in the batch', 'one letter of the claim changed'),
    ('verify/fixtures/tampered-sha256.json', 1, '[FAIL] Snapshot bytes match the record', 'committed SHA-256 altered'),
    ('verify/fixtures/false-receipt.json', 1, '[FAIL] Published receipt matches the chain (anchorTx)', 'receipt names the wrong block producer'),
    ('verify/fixtures/missing-authorization.json', 2, '[INCOMPLETE]', 'authorization file missing'),
    # WinLEW claims (synthetic, never anchored): content archived in verify/fixtures/winlew/blobs/.
    ('verify/fixtures/winlew/synthetic-pending.json', 0, '[ok] No member identifiers in the published content', 'a WinLEW game result checks out before anchoring'),
    ('verify/fixtures/winlew/leaks-member-id.json', 1, '[FAIL] No member identifiers in the published content', 'a Discord id and a wallet in the content are refused'),
]

failures = 0
for path, want_code, must, what in CASES:
    p = subprocess.run([sys.executable, os.path.join(HERE, 'verify_evidence.py'), os.path.join(ROOT, path)],
                       capture_output=True, text=True, encoding='utf-8', env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
    ok = p.returncode == want_code and must in p.stdout
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {what}: exit {p.returncode} (expected {want_code})" + ('' if ok else f"\n      expected to see: {must}\n      output: {p.stdout.strip()[:400]}"))
print(f"\n{len(CASES) - failures}/{len(CASES)} cases behaved as expected")
sys.exit(1 if failures else 0)
