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

Exit codes: 0 no check failed ([pending] rows allowed, e.g. awaiting finality), 1 a check failed, 2 incomplete (a required file is
missing), 3 unavailable (a source could not be read after retries; nothing was concluded).

NOT checked here: secp256k1 signatures (the standard library has no secp256k1). This
script shows that the chain committed the hashes and that the producer's signed time
covers them. For signatures, run XYO's own validator (see independent-verification.md).
"""
import hashlib
import json
import sys
import urllib.error
import urllib.request

NETS = {
    'sequence': ('https://beta.api.chain.xyo.network/rpc', 'https://blocks.sequence.xyo.space'),
    'mainnet': ('https://api.chain.xyo.network/rpc', 'https://blocks.mainnet.xyo.space'),
}
UA = {'User-Agent': 'evidence-check/1', 'Content-Type': 'application/json'}


class Unavailable(Exception):
    """A source could not be read. Nothing about the evidence was concluded (exit 3)."""


def fetch(url, body=None, attempts=3):
    """GET (or POST `body`) with up to `attempts` tries on transient errors. A 404 is an
    answer and is raised as-is; anything still failing after the last try is Unavailable."""
    import time
    host = urllib.request.urlparse(url).netloc
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), headers=UA)
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            last = f'HTTP {e.code}'
        except (urllib.error.URLError, OSError, ValueError) as e:  # refused, reset, DNS, TLS, timeout
            last = type(getattr(e, 'reason', None) or e).__name__
        if attempt < attempts:
            time.sleep(1.5 * attempt)
    raise Unavailable(f'{host} could not be read after {attempts} tries ({last})')


def rpc(net, method, params):
    try:
        out = json.loads(fetch(NETS[net][0], {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}))
    except ValueError as e:
        raise Unavailable(f'{method} answered with something that is not JSON') from e
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


# Each network's chain id, as its own RPC reports it (finalizationViewer_head, 2026-10-29).
CHAIN_IDS = {
    'sequence': '4b43a753c8024c0e5000e8ac948ac0063ac624bc',
    'mainnet': '319e667ced10452a117472811130444ded357f26',
}
MAX_TX_WINDOW = 10000  # exp - nbf limit in XYO's TransactionDurationValidator
TRANSFER = 'network.xyo.transfer'


def tx_integrity(tx, payloads, net, tx_hash=None):
    """Check a hydrated transaction [tx, payloads] from its own bytes. Every hash is recomputed
    here; hash metadata that arrives with the data ('_hash', '_dataHash') is never trusted.

    Returns {'problems': [...], 'unverified': [...], 'transfers': [(from, to, atto)], 'elevated': n}.
    A problem means the data is not what the signed transaction commits to. 'unverified' lists
    what this script cannot decide alone. Unknown schemas, off-chain payloads and storage
    metadata are allowed: only what the signature covers is required to match.
    Integrity is not inclusion: whether and where the transaction landed is checked separately.
    """
    import re
    hex40, hex64 = re.compile(r'[0-9a-f]{40}'), re.compile(r'[0-9a-f]{64}')
    problems, unverified, transfers = [], [], []
    out = {'problems': problems, 'unverified': unverified, 'transfers': transfers, 'elevated': 0}
    if not isinstance(tx, dict) or not isinstance(payloads, list) or not all(isinstance(p, dict) for p in payloads):
        problems.append('not a [transaction, payloads] pair')
        return out
    try:
        is_list = lambda v, pat: isinstance(v, list) and all(isinstance(x, str) and pat.fullmatch(x) for x in v)
        if tx.get('schema') != 'network.xyo.boundwitness':
            problems.append(f"schema is {tx.get('schema')!r}, not a bound witness")
        if net not in CHAIN_IDS:
            problems.append(f'unknown network {net!r}')
        elif tx.get('chain') != CHAIN_IDS[net]:
            problems.append(f"chain {str(tx.get('chain'))[:12]}… is not {net} ({CHAIN_IDS[net][:12]}…)")
        mine = xyo_hash(tx)
        if tx_hash is not None and mine != str(tx_hash).lower():
            problems.append(f'transaction hashes to {mine[:16]}…, not {str(tx_hash)[:16]}… (edited, or another transaction)')
        if '_hash' in tx and tx['_hash'] != mine:
            problems.append("the transaction's _hash metadata does not match its content")
        addresses, hashes, schemas = tx.get('addresses'), tx.get('payload_hashes'), tx.get('payload_schemas')
        if not is_list(addresses, hex40) or not addresses:
            problems.append('addresses are missing or not 40-hex')
            addresses = []
        if not is_list(hashes, hex64):
            problems.append('payload_hashes are missing or not 64-hex')
            hashes = []
        if not isinstance(schemas, list) or len(schemas) != len(hashes):
            problems.append('payload_schemas do not line up with payload_hashes')
            schemas = [None] * len(hashes)
        if not isinstance(tx.get('$signatures'), list) or len(tx['$signatures']) != len(addresses):
            problems.append('one signature per address is required')
        sender = tx.get('from')
        if not (isinstance(sender, str) and hex40.fullmatch(sender) and sender in addresses):
            problems.append('from is not one of the signing addresses')
        nbf, exp = tx.get('nbf'), tx.get('exp')
        if not (isinstance(nbf, int) and isinstance(exp, int) and 0 <= nbf < exp and exp - nbf <= MAX_TX_WINDOW):
            problems.append(f'nbf/exp ({nbf}, {exp}) are not a valid window')
        fees = tx.get('fees')
        if not (isinstance(fees, dict) and all(isinstance(fees.get(k), str) and re.fullmatch(r'[0-9a-f]+', fees[k]) for k in ('base', 'gasLimit', 'gasPrice', 'priority'))):
            problems.append('fees are missing or not hex')

        committed = dict(zip(hashes, schemas))
        by_hash = {}
        for p in payloads:
            h = xyo_hash(p)
            by_hash[h] = p
            if '_hash' in p and p['_hash'] != h:
                problems.append(f"a {p.get('schema')} payload's _hash metadata does not match its content")
            if h not in committed:
                problems.append(f"a {p.get('schema')} payload ({h[:12]}…) is not committed by the signed transaction")
            elif committed[h] != p.get('schema'):
                problems.append(f"payload {h[:12]}… is committed as {committed[h]}, not {p.get('schema')}")

        script = tx.get('script', [])
        if not isinstance(script, list) or not all(isinstance(op, str) for op in script):
            problems.append('script is not a list of strings')
            script = []
        for op in script:
            if not op.startswith('elevate|'):
                continue  # other opcodes are not interpreted here
            h = op[len('elevate|'):]
            if not hex64.fullmatch(h):
                problems.append(f'malformed elevate operation {op[:24]}…')
                continue
            out['elevated'] += 1
            if h not in committed:
                problems.append(f'elevated hash {h[:12]}… is not in payload_hashes')
            p = by_hash.get(h)
            if p is None:
                problems.append(f'elevated payload {h[:12]}… is missing or does not match its hash')
                continue
            if p.get('schema') != TRANSFER:
                continue
            # XL1 transfers move the chain's native token; the chain id above fixes which one.
            src, moves = p.get('from'), p.get('transfers')
            if not (isinstance(src, str) and hex40.fullmatch(src)) or not isinstance(moves, dict) or not moves:
                problems.append(f'transfer {h[:12]}… has no valid sender or recipients')
                continue
            if src != sender:
                unverified.append(f'transfer {h[:12]}… is from {src[:8]}…, not the signer; XYO allows that only under a signer authorization this script does not check')
            for to, amount in moves.items():
                if not (isinstance(to, str) and hex40.fullmatch(to) and isinstance(amount, str) and re.fullmatch(r'(0x)?[0-9a-f]+', amount)):
                    problems.append(f'transfer {h[:12]}… has a malformed recipient or amount')
                    continue
                transfers.append((src, to, int(amount, 16)))
    except Exception as e:  # malformed input must fail the check, never crash the verifier
        problems.append(f'unreadable transaction ({type(e).__name__})')
    return out


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
        except urllib.error.HTTPError:
            continue  # 404: no such block (yet). An unreachable CDN is Unavailable, not "not found".
        if tx_hash in bw['payload_hashes']:
            block, payloads = bw, ps
            break
    clock = next((p for p in payloads or [] if p.get('schema') == 'network.xyo.time'), None)
    return {
        'found': True, 'tx': tx, 'head': head, 'block': block,
        'integrity': tx_integrity(tx, found[1] if len(found) > 1 else [], net, tx_hash),
        'inWindow': bool(block) and tx['nbf'] <= block['block'] <= tx['exp'],
        'txHashOk': xyo_hash(tx) == tx_hash,
        'blockHashOk': bool(block) and xyo_hash(block) == block['_hash'],
        'clockSigned': bool(clock) and xyo_hash(clock) in block['payload_hashes'],
        'time': clock['epoch'] if clock else None,
        'final': bool(block) and block['block'] <= head['block'],
        # Awaiting finality (not a failure): in a block above the finalized head XYO RPC reports, or in no
        # block yet while its nbf..exp window still reaches above that head, so it can still land.
        'pending': (block['block'] > head['block']) if block else tx['exp'] > head['block'],
        'sameChain': head['chain'] == tx['chain'],
        'producer': block['addresses'][0] if block else None,
    }


def leg_verdict(c, signer, commits):
    """One on-chain leg: (True, None) final and intact; (False, None) an actual failure; (None, why) pending.

    FAILED stays for integrity failures: wrong chain, wrong hash, wrong signer, missing commitments, a bad block
    hash or clock, a block outside nbf..exp, or a window that has passed with the transaction in none of its
    blocks. Only an intact transaction still awaiting XYO RPC's reported finality is pending. Finality here is
    always as reported by XYO RPC, never established independently."""
    if not (c['sameChain'] and c['txHashOk'] and c['tx']['addresses'][0] == signer and commits):
        return False, None
    head = c['head']['block']
    if c['block']:
        if not (c['blockHashOk'] and c['clockSigned'] and c['inWindow']):
            return False, None
        if c['final']:
            return True, None
        return None, (f"Pending: block #{c['block']['block']} is above the finalized head reported by XYO RPC "
                      f"(#{head}); not a failure, re-run later")
    if c['pending']:
        return None, (f"Pending: not yet in a block at or below the finalized head reported by XYO RPC (#{head}); "
                      f"its window runs to #{c['tx']['exp']}; not a failure, re-run later")
    return False, None


def find_root(path):
    """The nearest folder above `path` holding blobs/ (the repository root), else the file's own."""
    import os
    here = os.path.dirname(os.path.abspath(path))
    d = here
    while True:
        if os.path.isdir(os.path.join(d, 'blobs')):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return here
        d = parent


def member_identifiers(value, path='content'):
    """Anything in a WinLEW record's content that looks like a person: a 17-20 digit Discord id,
    or a 40-hex XL1/EVM address. Salted commitments are 64-hex, so they never match."""
    import re
    found = []
    if isinstance(value, dict):
        for k, v in value.items():
            found += member_identifiers(v, f'{path}.{k}')
    elif isinstance(value, list):
        for i, v in enumerate(value):
            found += member_identifiers(v, f'{path}[{i}]')
    elif isinstance(value, (str, int)) and not isinstance(value, bool):
        t = str(value)
        if re.fullmatch(r'\d{17,20}', t):
            found.append(f'{path} (a Discord-style id)')
        elif re.fullmatch(r'(0x)?[0-9a-fA-F]{40}', t):
            found.append(f'{path} (an address)')
    return found


def same_match_records(root, record_hash, session):
    """Other winlew.game.result records in this repository that commit to the same match
    (the same sessionCommitment). One match should have one record: a second one, whoever
    issued it, is a duplicate claim about the same play. Every record file is read, not only
    the index, so a record missing from the index is still found."""
    import glob
    import os
    import re
    others = []
    for path in glob.glob(os.path.join(root, 'records', '**', '*.json'), recursive=True):
        try:
            doc = json.load(open(path, encoding='utf-8'))
        except (ValueError, OSError):
            continue
        # A malformed file (not an object, or an odd record) is skipped, never fatal to the check.
        rec = doc.get('record') if isinstance(doc, dict) else None
        if not isinstance(rec, dict) or not isinstance(rec.get('claim'), dict) or rec['claim'].get('type') != 'winlew.game.result':
            continue
        if not isinstance(rec.get('content'), dict):
            continue
        h = xyo_hash(rec)
        if h == record_hash:
            continue
        sha = rec['content'].get('sha256')
        # Only a well-formed SHA-256 names an archived file: anything else (a number, a path) is skipped.
        if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha):
            continue
        blob = os.path.join(root, 'blobs', 'sha256', sha[:2], sha + '.json')
        try:
            other = json.loads(open(blob, 'rb').read().decode('utf-8'))
        except (ValueError, OSError):
            continue
        if isinstance(other, dict) and other.get('sessionCommitment') == session:
            others.append(h)
    return sorted(others)


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


def utf8_output():
    """Windows pipes and redirects default to the ANSI code page (cp1252), which cannot print
    the arrows and ellipses in the report and used to crash the verifier mid-report. Switch to
    UTF-8 whenever the current encoding cannot carry them; a capable stream is left alone."""
    for stream in (sys.stdout, sys.stderr):
        try:
            '→…≤'.encode(stream.encoding or 'ascii')
        except (UnicodeEncodeError, LookupError):
            if hasattr(stream, 'reconfigure'):  # a replaced stream without it is left as it is
                stream.reconfigure(encoding='utf-8')


def main():
    utf8_output()
    rows = []
    _RUN['rows'] = rows  # receipt layer reads the same rows that are printed; nothing else changes
    add = lambda ok, title, detail: rows.append((ok, title, detail))
    # A disclosure is printed exactly like a passing row ([ok]), but it is a statement, not a check.
    # Its row index is recorded so the receipt can tell the two apart without matching text.
    _RUN['statements'] = statements = set()
    state = lambda title, detail: (statements.add(len(rows)), rows.append((True, title, detail)))
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

    import os
    # The archive (blobs/) sits at the repository root; a bundle outside the repository is
    # read beside the folders above it, so an archived source is found wherever this runs.
    root = bundle.get('root') or find_root(sys.argv[1])
    want = record['content']['sha256']
    src = record.get('source') or {}
    blob = os.path.join(root, 'blobs', 'sha256', want[:2], want + '.json')
    if src.get('url'):
        try:
            raw, where = fetch(src['url']), 'GitHub at the pinned commit'
        except Exception:
            raw, where = (open(blob, 'rb').read(), 'archived copy (GitHub unavailable)') if os.path.exists(blob) else (b'', 'nowhere: source unavailable')
    else:
        # A record with no public source (a WinLEW game result or reward trail): the archived
        # copy IS its source, published beside the record so the hash can be recomputed.
        raw, where = (open(blob, 'rb').read(), "the archived copy, this record's only source") if os.path.exists(blob) else (b'', 'nowhere: the archived copy is missing')
    sha = hashlib.sha256(raw).hexdigest()
    commit = f", commit {src['commit'][:10]}" if src.get('commit') else ''
    add(sha == want and len(raw) == record['content']['bytes'],
        'Snapshot bytes match the record', f"{len(raw)} bytes from {where}{commit}, sha256 {sha[:16]}…")

    # WinLEW claims describe members' activity, so their published content may carry only
    # salted commitments -- never a Discord ID, a WinLEW account id or a wallet address.
    if record['claim']['type'].startswith('winlew.') and raw:
        try:
            leaks = member_identifiers(json.loads(raw.decode('utf-8')))
        except ValueError:
            leaks = ['content is not JSON']
        add(not leaks, 'No member identifiers in the published content',
            'only salted commitments' if not leaks else f"found: {', '.join(leaks[:3])}")

    # One match, one record: a game result is identified by its salted session commitment.
    if record['claim']['type'] == 'winlew.game.result' and raw:
        try:
            session = json.loads(raw.decode('utf-8')).get('sessionCommitment')
        except (ValueError, AttributeError):
            session = None
        if not session:
            add(False, 'One match, one record', 'the game result names no sessionCommitment, so duplicates cannot be ruled out')
        else:
            others = same_match_records(root, xyo_hash(record), session)
            add(not others, 'One match, one record',
                'no other record in this repository commits to the same match' if not others
                else f"also recorded by {len(others)} other record(s): {', '.join(o[:16] + '…' for o in others[:3])}")

    rh, bh, ah = xyo_hash(record), xyo_hash(batch), xyo_hash(auth)
    _RUN['evidence'] = {'recordHash': rh, 'batchHash': bh, 'authorizationHash': ah,
                        'network': record['subject'].get('network'), 'chainId': record['subject'].get('chainId'),
                        'claimType': record['claim']['type'],
                        'source': {'url': src.get('url'), 'commit': src.get('commit'), 'readFrom': where,
                                   'expectedSha256': want, 'observedSha256': sha, 'bytes': len(raw)}}
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
        _RUN.setdefault('legs', {})[key] = _leg_facts(ref, c)  # values already fetched above; no new reads
        if not c['found']:
            add(False, title, 'XYO RPC does not know this transaction')
            continue
        elevated = xyo_hash({'schema': 'network.xyo.hash', 'hash': hashes[0]})
        commits = all(h in c['tx']['payload_hashes'] for h in hashes + [elevated]) and ('elevate|' + elevated) in c['tx'].get('script', [])
        ok, pending = leg_verdict(c, signer, commits)
        integrity = c['integrity']
        add(not integrity['problems'], f'Transaction integrity ({key})',
            '; '.join(integrity['problems'][:3]) if integrity['problems'] else
            f"{len(c['tx']['payload_hashes'])} commitments, {integrity['elevated']} elevated payload(s) re-hashed here, chain is {ref['network']}, landed inside nbf..exp={c['inWindow']}")
        for note in integrity['unverified']:
            add(None, f'Not decided by this script ({key})', note)
        if c['time'] is not None:
            times[key] = c['time']
        elif ok is None:
            times.setdefault('_pending', []).append(key)
        if c['block']:
            bundle.setdefault('_blocks', {})[key] = c['block']['block']
        add(ok, title, pending or f"block #{c['block']['block'] if c['block'] else '?'}, signed time {c['time']}, final={c['final']}, commits={commits}")
        claimed = bundle.get('receipts', {}).get(key)
        if claimed and c['block']:
            facts = {'block': c['block']['block'], 'blockHash': c['block']['_hash'], 'blockTime': c['time'], 'blockProducer': c['producer'], 'chainId': c['tx']['chain']}
            wrong = [k for k, v in facts.items() if claimed.get(k) != v]
            add(not wrong, f"Published receipt matches the chain ({key})", 'block, block hash, signed time, block producer and chain all match' if not wrong else f"differs: {', '.join(wrong)}")
            if c['producer'] in (record['subject'].get('address'), auth['issuer'], auth['delegate']):
                state(f'Disclosure ({key})', f"included by {c['producer'][:8]}…, a party to this evidence; inclusion is not verification")
            if claimed.get('inclusionNote'):
                state(f"Oxyon's disclosure ({key}, a statement, not a check)", claimed['inclusionNote'])

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
    elif 'anchorTx' in times.get('_pending', []):
        add(None, 'Anchor block time is inside the authorization window', 'not evaluated yet: the anchor is pending (no block time yet)')

    if '--plumbing-tx' in sys.argv:
        h = sys.argv[sys.argv.index('--plumbing-tx') + 1]
        c = tx_on_chain('sequence', h)
        _RUN.setdefault('legs', {})['plumbingTx'] = _leg_facts({'network': 'sequence', 'hash': h}, c)
        ok, pending = leg_verdict(c, c['tx']['addresses'][0], True) if c['found'] else (False, None)
        if c['found'] and c['integrity']['problems']:
            ok, pending = False, None
        add(ok, f'Chain plumbing on tx {h[:10]}…', pending or f"block #{c['block']['block'] if c.get('block') else '?'}, signed time {c.get('time')}, head #{c['head']['block'] if c.get('head') else '?'}")

    for ok, title, detail in rows:
        print(f"{'[pending]' if ok is None else '[ok]' if ok else '[FAIL]'} {title}: {detail}")
    sys.exit(0 if all(ok is not False for ok, _, _ in rows) else 1)


# ── Evidence receipt v0.1 (opt-in: --receipt <file>) ─────────────────────────────────────────
# An OUTPUT LAYER ONLY. It reads values main() and tx_on_chain() already computed; it makes no
# network request, changes no check, prints nothing to stdout and does not change exit codes.
# Without --receipt the verifier behaves exactly as before.
RECEIPT_SCHEMA = 'oxyon.evidence.verification-receipt'
RECEIPT_VERSION = '0.1'
PROCEDURE = 'oxyon.xl1.evidence-verify'
_RUN = {}


def _leg_facts(ref, c):
    """What one on-chain leg established, read from the chain-check result already in hand."""
    head, block = c.get('head') or {}, c.get('block') or {}
    return {
        'network': ref.get('network'), 'tx': ref.get('hash'),
        'rpc': NETS.get(ref.get('network'), (None, None))[0],
        'found': bool(c.get('found')),
        'block': block.get('block'), 'blockHash': block.get('_hash'),
        'finalizedHead': head.get('block'), 'final': bool(c.get('final')), 'pending': bool(c.get('pending')),
        'signedTime': c.get('time'), 'producerAddress': c.get('producer'),
    }


def _check_status(ok):
    return 'NOT_EVALUATED' if ok is None else 'VERIFIED' if ok else 'FAILED'


def _git_provenance(script_path, runner=None):
    """The git commit of the checkout holding the verifier, when it can be determined locally, and
    whether the verifier file itself differs from that commit. Never a network call. Anything that
    cannot be established is 'UNKNOWN'; the verifier's sha256 stays the authoritative identifier."""
    import os
    import re
    import subprocess
    runner = runner or subprocess.run
    out = {'gitCommit': 'UNKNOWN', 'verifierMatchesCommit': 'UNKNOWN',
           'basis': 'git metadata could not be read (not a git checkout, or git is unavailable)'}
    here = os.path.dirname(os.path.abspath(script_path))
    try:
        head = runner(['git', '-C', here, 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=5)
        commit = (head.stdout or '').strip()
        if head.returncode != 0 or not re.fullmatch(r'[0-9a-f]{40}', commit):
            return out
        out['gitCommit'] = commit
        st = runner(['git', '-C', here, 'status', '--porcelain', '--', os.path.basename(script_path)],
                    capture_output=True, text=True, timeout=5)
        if st.returncode == 0:
            out['verifierMatchesCommit'] = (st.stdout or '').strip() == ''
        out['basis'] = ('HEAD of the local checkout; verifierMatchesCommit compares only verify/verify_evidence.py '
                        'with that commit (the rest of the checkout is not checked)')
    except (OSError, subprocess.SubprocessError):
        pass
    return out


def build_receipt(run, exit_code, argv, performed_at, script_sha256, python_version, note=None, provenance=None):
    """The receipt as a plain dict. Pure: no I/O, no network. Values are strings, safe integers,
    booleans or null (the portable subset of oxyon-sjson-sha256/1)."""
    rows = run.get('rows') or []
    statements = set(run.get('statements') or ())
    # Rows recorded as statements (disclosures) are kept, word for word, but they are not checks:
    # they never count as verified and never decide the outcome.
    checks = [{'title': t, 'detail': str(d), 'kind': 'statement' if i in statements else 'check',
               'status': 'STATEMENT' if i in statements else _check_status(ok)}
              for i, (ok, t, d) in enumerate(rows)]
    real = [c for c in checks if c['kind'] == 'check']
    failed = sum(1 for c in real if c['status'] == 'FAILED')
    pending = sum(1 for c in real if c['status'] == 'NOT_EVALUATED')
    # Overall outcome. Only a run in which EVERY check passed and none was left undecided is
    # VERIFIED; the exit code alone is not enough (exit 0 also allows [pending] checks).
    if exit_code == 3:
        status, reason = 'NOT_EVALUATED', 'a source could not be read (exit 3, UNAVAILABLE); nothing was concluded'
    elif exit_code == 2:
        status, reason = 'INCONCLUSIVE', 'a required file is missing (exit 2, INCOMPLETE); the evidence chain could not be followed'
    elif exit_code == 1 or failed:
        status, reason = 'FAILED', f'{failed} check(s) failed (exit {exit_code})'
    elif exit_code != 0:
        status, reason = 'NOT_EVALUATED', f'the verifier stopped unexpectedly (exit {exit_code})'
    elif not real:
        status, reason = 'NOT_EVALUATED', 'no checks were run'
    elif pending:
        status, reason = 'INCONCLUSIVE', f'{pending} check(s) not evaluated; the run passed only what it could check'
    else:
        status, reason = 'VERIFIED', 'every check run by this procedure passed (scope limits below)'
    if note:
        reason = f'{reason}: {note}'
    legs = run.get('legs') or {}
    ev = run.get('evidence')
    # The original invocation, argument by argument (the --receipt pair already removed). A list is
    # the unambiguous form; the two strings are shell-quoted renderings of the same list.
    import shlex
    import subprocess
    rerun = ['python'] + [str(a) for a in argv]
    prov = provenance or {'gitCommit': 'UNKNOWN', 'verifierMatchesCommit': 'UNKNOWN', 'basis': 'not determined'}
    return {
        'schema': RECEIPT_SCHEMA, 'receiptVersion': RECEIPT_VERSION,
        'procedure': {'id': PROCEDURE, 'verifier': 'verify/verify_evidence.py', 'verifierSha256': script_sha256,
                      'python': python_version, 'standardLibraryOnly': True,
                      'gitCommit': prov['gitCommit'], 'verifierMatchesCommit': prov['verifierMatchesCommit'],
                      'provenanceBasis': prov['basis'],
                      'authoritativeIdentifier': 'verifierSha256 (the exact script bytes that ran)'},
        'performedAt': performed_at,
        'outcome': {'status': status, 'reason': reason, 'exitCode': exit_code,
                    'counts': {'verified': sum(1 for c in real if c['status'] == 'VERIFIED'),
                               'failed': failed, 'notEvaluated': pending,
                               'statements': len(checks) - len(real)}},
        'checks': checks,
        'scope': {
            'signatures': {'status': 'NOT_EVALUATED',
                           'reason': 'secp256k1 signatures are not checked by this standard-library verifier. '
                                     'Signature checks use XYO\'s own validator, separately (see VERIFY.md).'},
            'finality': {'rule': 'block height <= the finalized head reported by XYO RPC (finalizationViewer_head)',
                         'trustDependency': 'XYO RPC: finality is as reported by the RPC; XYO publishes no finality rule '
                                            'that this script checks independently',
                         'independentlyEstablished': False,
                         'legs': {k: {'block': v['block'], 'finalizedHead': v['finalizedHead'], 'final': v['final'],
                                      'pending': v.get('pending', False), 'rpc': v['rpc']} for k, v in legs.items()}},
            'producerAttribution': {'status': 'INFERRED',
                                    'basis': 'the first address that signed the block (block.addresses[0]) is treated as '
                                             'its producer; not cryptographically proven to be the producer',
                                    'legs': {k: v['producerAddress'] for k, v in legs.items()}},
            'chainCanonicity': {'status': 'INFERRED',
                                'basis': 'blocks are read from XYO\'s RPC and block CDN; their hashes are recomputed here, '
                                         'but which chain is canonical is as served by those endpoints'},
        },
        'evidence': ev,
        'chain': {k: {'network': v['network'], 'tx': v['tx'], 'found': v['found'], 'block': v['block'],
                      'blockHash': v['blockHash'], 'signedTime': v['signedTime']} for k, v in legs.items()},
        'reproduce': {
            'argv': rerun,
            'command': shlex.join(rerun),
            'commandWindows': subprocess.list2cmdline(rerun),
            'workingDirectory': 'run from the same directory as the original run: paths are as given on its command '
                                'line. Prefer argv (no shell parsing); command is quoted for POSIX shells, '
                                'commandWindows for Windows programs (cmd.exe metacharacters may need extra escaping)',
            'needs': 'Python 3.9+ standard library; read access to the record files, the pinned source, '
                     'and XYO\'s public RPC and block CDN',
            'deterministic': 'the outcome status, check titles and statuses, evidence hashes, block numbers, block '
                             'hashes and signed times should repeat on a re-run',
            'mayDiffer': 'performedAt, finalizedHead, availability of sources (exit 3) and the verifier hash if the '
                         'script changes. Receipts are not expected to be byte-identical between runs.',
            'pathPrivacy': 'arguments are recorded exactly as given, so absolute paths may show local folder or user '
                           'names; run with paths relative to the repository before sharing a receipt',
        },
    }


def _receipt_path_problem(path, inputs):
    """Why `path` must not be written, or None. Never overwrites anything: an existing path (a file, a
    directory, or any symbolic link, even a dangling one) is refused, and so is any path that is or
    resolves to one of the evidence inputs, however it is spelled (relative, '..', links)."""
    import os
    if os.path.lexists(path):
        target = os.path.realpath(path)
        for given in inputs:
            if os.path.exists(given) and os.path.realpath(given) == target:
                return f'{path} is the evidence file {given}; a receipt never overwrites evidence'
        return f'{path} already exists; a receipt never overwrites a file (choose a new name)'
    for given in inputs:
        if os.path.exists(given) and os.path.realpath(path) == os.path.realpath(given):
            return f'{path} resolves to the evidence file {given}; a receipt never overwrites evidence'
    return None


def _publish_receipt(path, text):
    """Creates `path` holding `text`, completely or not at all, and never over an existing file.

    The text goes to a temporary file in the SAME directory (same filesystem), is flushed to disk,
    and is then published with os.link: an atomic, exclusive step that fails if `path` exists, so a
    concurrent writer or a file that appeared meanwhile is never replaced. The temporary file is
    always removed. An interruption leaves either the complete receipt or no receipt at the final
    name; a hard kill can leave a hidden '.receipt-*.partial' file, never a partial receipt."""
    import os
    import tempfile
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix='.receipt-', suffix='.partial', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.link(tmp, path)  # FileExistsError if anything is already at `path`
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _write_receipt(path, exit_code, note=None):
    """Writes the receipt. The verifier's exit code is the evidence verdict only; whether the receipt
    was written is reported on stderr with one of two stable prefixes:
        'receipt (<STATUS>) written to <path>'   success
        'receipt not written: <reason>'           failure (nothing at <path> was created or changed)
    A receipt problem never changes the exit code."""
    import datetime
    import platform
    try:
        problem = _receipt_path_problem(path, sys.argv[1:2])
        if problem:
            print(f'receipt not written: {problem}', file=sys.stderr)
            return
        with open(__file__, 'rb') as fh:
            script_sha = hashlib.sha256(fh.read()).hexdigest()
        receipt = build_receipt(_RUN, exit_code, sys.argv,
                                datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                                script_sha, platform.python_version(), note, _git_provenance(__file__))
        text = json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + '\n'  # complete before any file exists
        _publish_receipt(path, text)
        print(f'receipt ({receipt["outcome"]["status"]}) written to {path}', file=sys.stderr)
    except FileExistsError:
        print(f'receipt not written: {path} already exists (created by something else meanwhile); '
              'a receipt never overwrites a file', file=sys.stderr)
    except Exception as e:  # the receipt must never alter the verification result
        print(f'receipt not written: {type(e).__name__}: {e}', file=sys.stderr)


def _take_receipt_arg():
    """Removes '--receipt <path>' from sys.argv before main() reads it. Returns the path or None."""
    if '--receipt' not in sys.argv:
        return None
    i = sys.argv.index('--receipt')
    if i + 1 >= len(sys.argv) or sys.argv[i + 1].startswith('--'):
        print('usage: --receipt <output file>', file=sys.stderr)
        sys.exit(4)  # usage error, only possible when the new flag is misused
    path = sys.argv[i + 1]
    del sys.argv[i:i + 2]
    return path


if __name__ == '__main__':
    receipt_path = _take_receipt_arg()
    if receipt_path is None:
        try:
            main()
        except Unavailable as e:
            # A network problem is not a verdict on the evidence: say so, and exit apart from 1 (fail).
            print(f'[UNAVAILABLE] {e}. Nothing was concluded about this evidence; run it again.')
            sys.exit(3)
    else:
        code, note = 1, None
        try:
            main()
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
        except Unavailable as e:
            print(f'[UNAVAILABLE] {e}. Nothing was concluded about this evidence; run it again.')
            code, note = 3, str(e)
        except BaseException as e:
            _write_receipt(receipt_path, 99, f'{type(e).__name__}')
            raise
        _write_receipt(receipt_path, code, note)
        sys.exit(code)
