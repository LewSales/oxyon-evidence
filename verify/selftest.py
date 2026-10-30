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
# Run every case as a default Windows pipe would (cp1252), so an unprintable character fails
# the self-test instead of crashing a verifier on someone's PC. The output is read as UTF-8.
LEGACY = {**os.environ, 'PYTHONIOENCODING': 'cp1252'}
CASES.append(('verify/fixtures/winlew/synthetic-pending.json', 0, '[ok] Authorization covers this record: ', 'a report with arrows prints on a cp1252 (Windows default) stream'))

# This report prints the verifier's output, so it needs the same guard (see utf8_output there).
for stream in (sys.stdout, sys.stderr):
    try:
        '→…≤�'.encode(stream.encoding or 'ascii')
    except (UnicodeEncodeError, LookupError):
        stream.reconfigure(encoding='utf-8')

EXITS = {0: 'all checks passed', 1: 'a check failed', 2: 'incomplete', 3: 'UNAVAILABLE: a source could not be read (network), not a verdict'}
failed, unavailable = [], []
for path, want_code, must, what in CASES:
    for attempt in (1, 2):  # a case that could not reach its sources is run once more
        p = subprocess.run([sys.executable, os.path.join(HERE, 'verify_evidence.py'), os.path.join(ROOT, path)],
                           capture_output=True, text=True, encoding='utf-8', errors='replace', env=LEGACY)
        if p.returncode != 3:
            break
    ok = p.returncode == want_code and must in p.stdout
    if not ok:
        (unavailable if p.returncode == 3 else failed).append(what)
    print(f"{'PASS' if ok else 'FAIL'}  {what}: exit {p.returncode} (expected {want_code})" + ('' if ok else
          f"\n      case: {path}"
          f"\n      exit {p.returncode} means: {EXITS.get(p.returncode, 'the verifier crashed')}"
          f"\n      expected to see: {must}"
          f"\n      output (last lines): {' | '.join(p.stdout.strip().splitlines()[-4:])[:600] or '(none)'}"
          f"\n      error (last line): {(p.stderr.strip().splitlines() or ['(none)'])[-1][:300]}"))
print(f"\n{len(CASES) - len(failed) - len(unavailable)}/{len(CASES)} cases behaved as expected")
if unavailable:
    print(f"Could not run (network, twice): {'; '.join(unavailable)}")
if failed:
    print(f"Failed: {'; '.join(failed)}")
sys.exit(1 if failed or unavailable else 0)
