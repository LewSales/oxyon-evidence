#!/usr/bin/env python3
"""Verify an Oxyon evidence record without Oxyon's servers, JavaScript or APIs.

Python 3.9+ standard library only. Reads the evidence bundle (a local file, or a URL you
choose), the snapshot from GitHub at its pinned commit, and the chain from XYO's public
RPC and block CDN. Every hash is recomputed here.

    python verify_evidence.py bundle.json
    python verify_evidence.py bundle.json --plumbing-tx <sequence tx hash>   # chain checks on any real tx
    python verify_evidence.py records.json --authorization-tx <A hash> [--anchor-tx <C hash>]
    python verify/verify_evidence.py records/sequence/2026/10/09/<file>.json  # oxyon-evidence repository mode

bundle.json = {"authorization": {...}, "record": {...}, "batch": {...},
               "anchorTx": {"network": "sequence", "hash": "..."},          # optional until broadcast
               "authorizationTx": {"network": "sequence", "hash": "..."}}   # optional until broadcast

NOT checked here: secp256k1 signatures (the standard library has no secp256k1). This
script shows that the chain committed the hashes and that the producer's signed time
covers them. For signatures, run XYO's own validator (see independent-verification.md).
"""
import hashlib
import json
import sys
import urllib.request

NETS = {
    'sequence': ('https://beta.api.chain.xyo.network/rpc', 'https://blocks.sequence.xyo.space'),
    'mainnet': ('https://api.chain.xyo.network/rpc', 'https://blocks.mainnet.xyo.space'),
}
UA = {'User-Agent': 'evidence-check/1', 'Content-Type': 'application/json'}


def fetch(url, body=None):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def rpc(net, method, params):
    out = json.loads(fetch(NETS[net][0], {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}))
    if 'error' in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out['result']


def xyo_hash(obj, data=False):
    """XYO payload hash: SHA-256 of compact JSON, keys sorted at every level (inside arrays too),
    '_' fields removed; with data=True '$' fields are removed as well (the hash signatures cover)."""
    def deep(v):
        if isinstance(v, dict):
            return {k: deep(v[k]) for k in sorted(v)}
        if isinstance(v, list):
            return [deep(x) for x in v]
        return v
    top = {k: v for k, v in obj.items() if not k.startswith('_') and not (data and k.startswith('$'))}
    return hashlib.sha256(json.dumps(deep(top), separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def tx_on_chain(net, tx_hash):
    head = rpc(net, 'finalizationViewer_head', [])[0]
    found = rpc(net, 'transactionViewer_byHash', [tx_hash])
    if not found:
        return {'found': False}
    tx = found[0]
    block = payloads = None
    for n in range(tx['nbf'], tx['exp'] + 1):  # a transaction can only land in nbf..exp
        try:
            bw, ps = json.loads(fetch(f"{NETS[net][1]}/block/number/{n}.json"))
        except Exception:
            continue
        if tx_hash in bw['payload_hashes']:
            block, payloads = bw, ps
            break
    clock = next((p for p in payloads or [] if p.get('schema') == 'network.xyo.time'), None)
    return {
        'found': True, 'tx': tx, 'head': head, 'block': block,
        'txHashOk': xyo_hash(tx) == tx_hash,
        'blockHashOk': bool(block) and xyo_hash(block) == block['_hash'],
        'clockSigned': bool(clock) and xyo_hash(clock) in block['payload_hashes'],
        'time': clock['epoch'] if clock else None,
        'final': bool(block) and block['block'] <= head['block'],
        'sameChain': head['chain'] == tx['chain'],
        'producer': block['addresses'][0] if block else None,
    }


def load_repo_record(path):
    """Repository mode: a published record file {record, batch, receipt}. The authorization and its
    receipt are found in keys/ by hash; the transaction hashes come from the receipts, which are
    Oxyon's claims and are re-checked against the chain below."""
    import os
    doc = json.load(open(path, encoding='utf-8'))
    root = os.path.dirname(os.path.abspath(path))
    while root and not os.path.isdir(os.path.join(root, 'keys')):
        parent = os.path.dirname(root)
        if parent == root:
            raise SystemExit('cannot find the repository root (no keys/ directory above the record)')
        root = parent
    net = doc['record']['subject']['network']
    auth_path = os.path.join(root, 'keys', net, 'authorizations', doc['record']['authorization'] + '.json')
    if not os.path.exists(auth_path):
        return {'root': root, 'missing': f"authorization file keys/{net}/authorizations/{doc['record']['authorization'][:16]}….json", 'record': doc['record'], 'batch': doc['batch']}
    auth_doc = json.load(open(auth_path, encoding='utf-8'))
    return {
        'root': root, 'authorization': auth_doc['authorization'], 'record': doc['record'], 'batch': doc['batch'],
        'anchorTx': {'network': net, 'hash': doc['receipt']['tx']}, 'authorizationTx': {'network': net, 'hash': auth_doc['receipt']['tx']},
        'receipts': {'anchorTx': doc['receipt'], 'authorizationTx': auth_doc['receipt']},
    }


def main():
    rows = []
    add = lambda ok, title, detail: rows.append((ok, title, detail))
    bundle = json.load(open(sys.argv[1], encoding='utf-8'))
    if 'receipt' in bundle:
        bundle = load_repo_record(sys.argv[1])
        if 'missing' in bundle:
            print(f"[INCOMPLETE] Required file missing: {bundle['missing']}. The evidence chain cannot be followed end to end; nothing else was checked.")
            sys.exit(2)
    for flag, field in (('--authorization-tx', 'authorizationTx'), ('--anchor-tx', 'anchorTx')):
        if flag in sys.argv:
            bundle[field] = {'network': bundle['record']['subject']['network'], 'hash': sys.argv[sys.argv.index(flag) + 1].lower()}
    auth, record, batch = bundle['authorization'], bundle['record'], bundle['batch']

    want = record['content']['sha256']
    try:
        raw, where = fetch(record['source']['url']), 'GitHub at the pinned commit'
    except Exception:
        import os
        blob = os.path.join(bundle.get('root', '.'), 'blobs', 'sha256', want[:2], want + '.json')
        raw, where = (open(blob, 'rb').read(), 'archived copy (GitHub unavailable)') if os.path.exists(blob) else (b'', 'nowhere: source unavailable')
    sha = hashlib.sha256(raw).hexdigest()
    add(sha == want and len(raw) == record['content']['bytes'],
        'Snapshot bytes match the record', f"{len(raw)} bytes from {where}, commit {record['source']['commit'][:10]}, sha256 {sha[:16]}…")

    rh, bh, ah = xyo_hash(record), xyo_hash(batch), xyo_hash(auth)
    add(rh in batch['proofHashes'], 'Record is in the batch', f'record {rh[:16]}…')
    add(record['authorization'] == ah, 'Record cites this authorization', f'authorization {ah[:16]}…')
    scope = auth['scope']
    add(auth['issuer'] == record['issuer'] and auth['delegate'] == record['anchoredBy']
        and scope['network']['chainId'] == record['subject']['chainId'] and record['claim']['type'] in scope['claims'],
        'Authorization covers this record', f"{auth['issuer'][:8]}… → {auth['delegate'][:8]}… for {record['claim']['type']}")

    legs = [('anchorTx', 'Anchor committed on chain by the anchoring key', record['anchoredBy'], [bh, rh]),
            ('authorizationTx', 'Authorization committed on chain by Oxyon', auth['issuer'], [ah])]
    times = {}
    for key, title, signer, hashes in legs:
        ref = bundle.get(key)
        if not ref:
            add(None, title, 'not broadcast yet')
            continue
        c = tx_on_chain(ref['network'], ref['hash'])
        if not c['found']:
            add(False, title, 'XYO RPC does not know this transaction')
            continue
        elevated = xyo_hash({'schema': 'network.xyo.hash', 'hash': hashes[0]})
        commits = all(h in c['tx']['payload_hashes'] for h in hashes + [elevated]) and ('elevate|' + elevated) in c['tx'].get('script', [])
        ok = c['sameChain'] and c['txHashOk'] and c['tx']['addresses'][0] == signer and commits and c['blockHashOk'] and c['clockSigned'] and c['final']
        times[key] = c['time']
        if c['block']:
            bundle.setdefault('_blocks', {})[key] = c['block']['block']
        add(ok, title, f"block #{c['block']['block'] if c['block'] else '?'}, signed time {c['time']}, final={c['final']}, commits={commits}")
        claimed = bundle.get('receipts', {}).get(key)
        if claimed and c['block']:
            facts = {'block': c['block']['block'], 'blockHash': c['block']['_hash'], 'blockTime': c['time'], 'blockProducer': c['producer'], 'chainId': c['tx']['chain']}
            wrong = [k for k, v in facts.items() if claimed.get(k) != v]
            add(not wrong, f"Published receipt matches the chain ({key})", 'block, block hash, signed time, block producer and chain all match' if not wrong else f"differs: {', '.join(wrong)}")
            if c['producer'] in (record['subject'].get('address'), auth['issuer'], auth['delegate']):
                add(True, f'Disclosure ({key})', f"included by {c['producer'][:8]}…, a party to this evidence; inclusion is not verification")
            if claimed.get('inclusionNote'):
                add(True, f"Oxyon's disclosure ({key}, a statement, not a check)", claimed['inclusionNote'])

    if bundle.get('_blocks', {}).keys() >= {'anchorTx', 'authorizationTx'}:
        lo, hi = bundle['_blocks']['authorizationTx'], bundle['_blocks']['anchorTx']
        if hi - lo <= 5000:
            found = []
            net = record['subject']['network']
            for n in range(lo, hi + 1):  # any revocation by the issuer committed before the anchor?
                bw, ps = json.loads(fetch(f"{NETS[net][1]}/block/number/{n}.json"))
                for p in ps:
                    if p.get('schema') == 'network.xyo.boundwitness' and p.get('from') == auth['issuer'] and 'oxyon.evidence.revocation.v1' in p.get('payload_schemas', []):
                        found.append(n)
            add(not found, 'No revocation by the issuer between authorization and anchor', f'scanned blocks #{lo}–#{hi} on chain' + (f'; revocation in #{found}' if found else ''))
        else:
            add(None, 'Revocation scan', f'range #{lo}–#{hi} too large for this script; see index.json (Oxyon\'s claim)')

    if 'anchorTx' in times:
        t = times['anchorTx']
        add(auth['validFrom'] <= t < auth['validUntil'], 'Anchor block time is inside the authorization window', f'{t}')
        if 'authorizationTx' in times:
            add(times['authorizationTx'] <= t, 'Authorization was on chain before the anchor', f"{times['authorizationTx']} ≤ {t}")

    if '--plumbing-tx' in sys.argv:
        h = sys.argv[sys.argv.index('--plumbing-tx') + 1]
        c = tx_on_chain('sequence', h)
        add(c['found'] and c['txHashOk'] and c['blockHashOk'] and c['clockSigned'] and c['final'] and c['sameChain'],
            f'Chain plumbing on tx {h[:10]}…', f"block #{c['block']['block'] if c.get('block') else '?'}, signed time {c.get('time')}, head #{c['head']['block'] if c.get('head') else '?'}")

    for ok, title, detail in rows:
        print(f"{'[pending]' if ok is None else '[ok]' if ok else '[FAIL]'} {title}: {detail}")
    sys.exit(0 if all(ok is not False for ok, _, _ in rows) else 1)


def utf8_output():
    # On Windows, piped or redirected output (and terminals such as Git Bash) uses the ANSI
    # code page, which cannot encode the → … ≤ in this report. The crash would exit 1, the
    # same code as [FAIL], so write UTF-8 instead. Checks and exit codes are unchanged.
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, 'reconfigure') and (s.encoding or '').lower().replace('-', '') != 'utf8':
            s.reconfigure(encoding='utf-8')


if __name__ == '__main__':
    utf8_output()
    main()
