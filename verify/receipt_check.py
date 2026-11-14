#!/usr/bin/env python3
"""Read an Oxyon verification receipt (v0.1 from verify_evidence.py, v0.2 from the browser Evidence
Explorer), check that it is well formed and internally consistent, and print how to re-run its checks.

    python verify/receipt_check.py <receipt.json>

Offline and standard library only. It never contacts a network, never runs anything, and never asks
for a key or a recovery phrase. A receipt is unsigned JSON: anyone can write one. This tool can tell
you that a receipt is malformed or contradicts itself; it can NOT tell you that its result is true.
Only re-running the checks can. Reproduction commands are built from validated fields (hashes,
network names, record paths) and fixed templates. Free-text commands inside the receipt are never
echoed, because a receipt could carry anything.

Exit codes describe the receipt, not the evidence:
  0  readable, supported and internally consistent (whatever outcome it claims)
  1  readable but invalid or inconsistent (altered, truncated or not produced by these tools)
  2  not readable (not a file, not UTF-8 JSON, or not an object)
  3  unsupported schema or receiptVersion
"""
import json
import re
import sys

SCHEMA = 'oxyon.evidence.verification-receipt'
VERSIONS = ('0.1', '0.2')
OUTCOMES = ('VERIFIED', 'FAILED', 'INCONCLUSIVE', 'NOT_EVALUATED')
CHECK_STATUSES = ('VERIFIED', 'FAILED', 'NOT_EVALUATED')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
RECORD_PATH = re.compile(r'^records/(sequence|mainnet)/\d{4}/\d{2}/\d{2}/\d{2}-[0-9a-f]{64}\.json$')
# Fixed, published endpoints: a receipt never chooses the URL a command talks to.
RPC = {'sequence': 'https://beta.api.chain.xyo.network/rpc', 'mainnet': 'https://api.chain.xyo.network/rpc'}
REPO = 'https://github.com/LewSales/oxyon-evidence'
LIMITS = [
    'This receipt is unsigned: anyone can edit it. It describes one past run; it is not evidence by itself.',
    'Finality is as reported by XYO RPC (finalizationViewer_head), not established independently.',
    "The block producer (first signer) and the canonical chain are INFERRED from XYO's servers.",
    'A valid hash shows the bytes are unchanged, not that the figures in them are true.',
]


class Invalid(Exception):
    pass


def get(d, *path):
    for k in path:
        if not isinstance(d, dict) or k not in d:
            raise Invalid(f"missing field: {'.'.join(path)}")
        d = d[k]
    return d


def recount(checks, v):
    """Counts and the outcome recomputed from the check rows, with the rules both producers use."""
    if not isinstance(checks, list):
        raise Invalid('checks must be a list')
    n = {'verified': 0, 'failed': 0, 'notEvaluated': 0, 'statements': 0}
    for i, c in enumerate(checks):
        if not isinstance(c, dict):
            raise Invalid(f'checks[{i}] is not an object')
        kind, status = c.get('kind'), c.get('status')
        if not isinstance(c.get('title'), str):
            raise Invalid(f'checks[{i}].title missing')
        if kind == 'statement':
            if status != 'STATEMENT':
                raise Invalid(f'checks[{i}] is a statement with status {status!r}; statements are never checks')
            n['statements'] += 1
        elif kind == 'check':
            if status not in CHECK_STATUSES:
                raise Invalid(f'checks[{i}].status {status!r} is not one of {CHECK_STATUSES}')
            n[{'VERIFIED': 'verified', 'FAILED': 'failed', 'NOT_EVALUATED': 'notEvaluated'}[status]] += 1
        else:
            raise Invalid(f'checks[{i}].kind {kind!r} is not check or statement')
        if v == '0.2' and not isinstance(c.get('layer'), str):
            raise Invalid(f'checks[{i}].layer missing (required in 0.2)')
    real = n['verified'] + n['failed'] + n['notEvaluated']
    if v == '0.1':  # verify_evidence.build_receipt, for exit 0 or 1
        status = ('NOT_EVALUATED' if not real else 'FAILED' if n['failed']
                  else 'INCONCLUSIVE' if n['notEvaluated'] else 'VERIFIED')
    else:  # the browser's outcomeOf
        status = ('FAILED' if n['failed'] else 'NOT_EVALUATED' if not n['verified']
                  else 'INCONCLUSIVE' if n['notEvaluated'] else 'VERIFIED')
    return n, status, real


def check(r):
    """Returns (version, facts) for a valid receipt; raises Invalid otherwise."""
    if not isinstance(r, dict):
        raise Invalid('not a JSON object')
    v = r.get('receiptVersion')
    if v not in VERSIONS:
        raise Invalid(f'receiptVersion {v!r}')
    out = get(r, 'outcome')
    status = get(out, 'status')
    if status not in OUTCOMES:
        raise Invalid(f'outcome.status {status!r} is not one of {OUTCOMES}')
    n, derived, real = recount(get(r, 'checks'), v)
    if get(out, 'counts') != n:
        raise Invalid(f'outcome.counts {out.get("counts")} do not match the check rows {n} (altered?)')
    exit_code = out.get('exitCode', 'absent')
    if v == '0.1':
        if not isinstance(exit_code, int):
            raise Invalid('outcome.exitCode must be an integer in 0.1')
        if exit_code not in (0, 1, 2, 3, 99):
            raise Invalid(f'outcome.exitCode {exit_code} is not a verify_evidence.py exit code')
        expect = ({3: 'NOT_EVALUATED', 99: 'NOT_EVALUATED', 2: 'INCONCLUSIVE', 1: 'FAILED'}.get(exit_code)
                  or ('FAILED' if n['failed'] else derived))
        if exit_code == 0 and n['failed']:
            raise Invalid('exit code 0 with a FAILED check row: the CLI never does that (altered?)')
        if get(r, 'scope', 'signatures', 'status') != 'NOT_EVALUATED':
            raise Invalid('0.1 receipts never evaluate signatures, but this one says it did')
        if not HEX64.match(str(get(r, 'procedure', 'verifierSha256'))):
            raise Invalid('procedure.verifierSha256 is not a SHA-256')
    else:
        if exit_code is not None:
            raise Invalid('outcome.exitCode must be null in 0.2 (a browser has no exit code)')
        if get(r, 'procedure', 'kind') != 'browser':
            raise Invalid('procedure.kind must be "browser" in 0.2')
        if get(r, 'integrity', 'signed') is not False:
            raise Invalid('0.2 receipts are unsigned; integrity.signed must be false')
        expect = derived
        if get(r, 'scope', 'signatures', 'status') not in ('VERIFIED', 'FAILED', 'PARTIAL', 'NOT_EVALUATED'):
            raise Invalid('scope.signatures.status is not a 0.2 value')
    if status != expect:
        raise Invalid(f'outcome.status says {status} but its own check rows give {expect} (altered?)')
    if get(r, 'scope', 'finality', 'independentlyEstablished') is not False:
        raise Invalid('scope.finality.independentlyEstablished must be false: finality is as reported by XYO RPC')
    if get(r, 'scope', 'producerAttribution', 'status') != 'INFERRED':
        raise Invalid('scope.producerAttribution.status must be INFERRED')
    if v == '0.2' and get(r, 'scope', 'chainCanonicity', 'status') != 'INFERRED':
        raise Invalid('scope.chainCanonicity.status must be INFERRED')
    return v, n, real


def reproduction(r, v):
    """Copy-paste commands built only from validated fields. Missing facts are reported, never invented."""
    ev = r.get('evidence') or {}
    record = ev.get('recordHash') if v == '0.1' else ev.get('record')
    net = ev.get('network')
    cmds, missing = [], []
    if not (isinstance(record, str) and HEX64.match(record)):
        missing.append('the record hash')
        record = None
    if net not in RPC:
        missing.append('a known network (sequence or mainnet)')
        net = None
    path = None
    if v == '0.1':
        argv = (r.get('reproduce') or {}).get('argv') or []
        path = next((a for a in argv if isinstance(a, str) and RECORD_PATH.match(a)), None)
    else:
        m = re.search(r'(records/(?:sequence|mainnet)/\d{4}/\d{2}/\d{2}/\d{2}-[0-9a-f]{64}\.json)', str((r.get('reproduce') or {}).get('python') or ''))
        path = m.group(1) if m and RECORD_PATH.match(m.group(1)) else None
    if path and record and not path.endswith(f'-{record}.json'):
        missing.append('a record path that matches the record hash (the receipt names a different record)')
        path = None
    cmds.append(f'git clone {REPO} && cd oxyon-evidence')
    if path:
        cmds.append(f'python verify/verify_evidence.py {path} --receipt my-receipt.json')
    else:
        missing.append('the record path (find it in index.json by the record hash)')
    legs = r.get('chain') or {}
    txs = []
    for key in (('authorizationTx', 'anchorTx') if v == '0.1' else ('authorization', 'anchor')):
        tx = (legs.get(key) or {}).get('tx')
        if isinstance(tx, str) and HEX64.match(tx):
            txs.append(tx)
        else:
            missing.append(f'the {key} transaction hash')
    if net and txs:
        cmds.append('npm i @xyo-network/sdk-protocol@7.4.2')
        cmds += [f'node verify/sigcheck.mjs {RPC[net]} {tx}' for tx in txs]
    if record:
        cmds.append(f'# or in a browser: https://oxyon.io/evidence/record/?h={record}')
    return cmds, missing


def report(r, v, n, real):
    p = r.get('procedure') or {}
    out = r['outcome']
    lines = [f'Receipt {v}: well formed and internally consistent.',
             '',
             f"Procedure: {p.get('id')} ({'Python CLI, verify_evidence.py' if v == '0.1' else 'browser Evidence Explorer'})"]
    if v == '0.1':
        lines.append(f"  verifier sha256 {p.get('verifierSha256')}  git {p.get('gitCommit')}  matches commit: {p.get('verifierMatchesCommit')}")
    else:
        prov = p.get('provenance') or {}
        lines.append(f"  build {(p.get('manifest') or {}).get('build')}  provenance: {prov.get('status', 'NOT RECORDED (receipt made before 2026-11-14)')}")
        for why in prov.get('reasons') or []:
            lines.append(f'    - {why}')
    lines += [f"  performed at {r.get('performedAt')}", '',
              f"Outcome CLAIMED by this receipt: {out['status']} ({n['verified']} of {real} checks verified, {n['failed']} failed, "
              f"{n['notEvaluated']} not evaluated; {n['statements']} statements, not counted)",
              f"  signatures: {r['scope']['signatures']['status']}" + (' (this procedure does not check them)' if v == '0.1' else ' (checked in the browser with the bundled XYO SDK)'),
              '', 'Trust limits:'] + [f'  - {x}' for x in LIMITS]
    cmds, missing = reproduction(r, v)
    lines += ['', 'To reproduce (copy and run yourself; nothing here was run):'] + [f'  {c}' for c in cmds]
    if missing:
        lines += ['', 'Cannot reproduce fully; the receipt lacks:'] + [f'  - {m}' for m in missing]
    return '\n'.join(lines)


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[0])
        print('usage: python verify/receipt_check.py <receipt.json>')
        return 2
    try:
        with open(argv[1], encoding='utf-8') as fh:
            r = json.load(fh)
    except (OSError, UnicodeDecodeError, ValueError) as e:
        print(f'UNREADABLE: {type(e).__name__}: {str(e)[:160]}. Nothing was checked.')
        return 2
    if not isinstance(r, dict):
        print('UNREADABLE: the file is JSON but not an object. Nothing was checked.')
        return 2
    if r.get('schema') != SCHEMA or r.get('receiptVersion') not in VERSIONS:
        print(f"UNSUPPORTED: schema {r.get('schema')!r}, receiptVersion {r.get('receiptVersion')!r}. "
              f"This tool reads {SCHEMA} versions {', '.join(VERSIONS)}.")
        return 3
    try:
        v, n, real = check(r)
    except Invalid as e:
        print(f"INVALID receipt ({r.get('receiptVersion')}): {e}. Do not rely on anything it claims; re-run the checks.")
        return 1
    print(report(r, v, n, real))
    return 0


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, ValueError):
        pass
    sys.exit(main(sys.argv))
