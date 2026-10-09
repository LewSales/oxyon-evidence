# Verify Oxyon's evidence yourself

You need nothing from Oxyon's servers, JavaScript or APIs. The only inputs are:
- the files in this repository;
- GitHub, at a pinned commit;
- XYO's public XL1 RPC and block CDN.

Every step can be done by hand, or with the two short scripts in `verify/`.

| Layer | Question | Steps |
|---|---|---|
| Cryptographic commitment | Did XL1 record these exact hashes, in which finalized block, at what signed time? | 4, 5 |
| Signature validity | Were the transactions signed by the keys they name? | 6 |
| Authorization validity | Was the anchoring key authorised for this record, network and time? | 3, 5 |
| Source-file integrity | Are these the exact bytes at that GitHub commit? | 1 |
| Truth of the telemetry | Are the numbers in the snapshot correct? | **Not established by any step.** The producer reports them about itself |

Below, `R` is the record file
`records/sequence/2026/10/09/14-82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05.json`,
and `K` is the authorization file
`keys/sequence/authorizations/dbafea3b4208d166d7922c2a1bf046de83e2c5457ea944cc47f40d41d146a038.json`.

**Getting the files.** File names include full 64-character hashes, so on Windows either
clone into a short path (for example `C:\oxyon-evidence`) or allow long paths:

```
git clone -c core.longpaths=true https://github.com/LewSales/oxyon-evidence
```

Network: XL1 Sequence, chain `4b43a753c8024c0e5000e8ac948ac0063ac624bc`.
- RPC: `https://beta.api.chain.xyo.network/rpc`
- Blocks: `https://blocks.sequence.xyo.space/block/number/<n>.json`

## 1. Source-file integrity

```
curl -sL https://raw.githubusercontent.com/LewSales/xl1-status-data/76b3489a817b58ddc7ac3dbada845dcacb156156/windows.json -o windows.json
sha256sum windows.json        # Windows: certutil -hashfile windows.json SHA256
```

Expect `a9951280cfd5175c9b586cc3fcf834641b2f7465f9c398e8a7097768a5df3735` and 34,680 bytes,
equal to `record.content.sha256` and `record.content.bytes` in `R`. The same bytes are
archived at `blobs/sha256/a9/a995…3735.json`.

## 2. Record hashes

The XYO payload hash, as fixed by Evidence spec v1 §1.2:
1. Remove top-level fields starting with `_`.
2. Sort object keys at every depth, including objects inside arrays.
3. Write compact JSON, with non-ASCII characters left as UTF-8.
4. Take the SHA-256.

For the *data hash* that signatures cover, also remove top-level fields starting with `$`.

```python
import json, hashlib
def xyo_hash(o, data=False):
    deep = lambda v: {k: deep(v[k]) for k in sorted(v)} if isinstance(v, dict) else [deep(x) for x in v] if isinstance(v, list) else v
    top = {k: v for k, v in o.items() if not k.startswith('_') and not (data and k.startswith('$'))}
    return hashlib.sha256(json.dumps(deep(top), separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
```

| Object | Expected hash |
|---|---|
| `record` in R | `82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05` |
| `batch` in R | `26c6491b9ddfde3931873b394dc49159b527d26725c1c07e2a72988fd0c37860` |
| `authorization` in K | `dbafea3b4208d166d7922c2a1bf046de83e2c5457ea944cc47f40d41d146a038` |

Then check the links:
- `record.authorization` equals the authorization hash;
- `batch.proofHashes` equals `[recordHash]`.

## 3. Authorization meaning

In K, `authorization` says:
- issuer `4e88…3829` authorises delegate `ee9d…a8bc` as `anchorer`;
- for `xl1.producer.telemetry` records;
- on Sequence chain `4b43a753…` only;
- from 2026-10-09T00:00Z to 2027-01-09T00:00Z.

The record's `issuer` and `anchoredBy` must equal the issuer and delegate.

## 4. The authorization transaction (K's `receipt.tx`)

```
curl -s https://beta.api.chain.xyo.network/rpc -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"transactionViewer_byHash","params":["4cdf748dac18fab2f26b67a155fc192591fc4e5f0d5b16afbb5707b3d9974187"]}'
```

Check the transaction:
- `xyo_hash(tx)` equals the tx hash.
- `from` and `addresses[0]` are 4e88.
- `chain` is `4b43a753…`.
- `payload_hashes` contains the authorization hash and `xyo_hash({"schema":"network.xyo.hash","hash":<authorization hash>})`.
- `script` contains `elevate|<that second hash>`.

Then find its block. A transaction lands between its `nbf` and `exp`; fetch those blocks until
one lists the tx hash in `payload_hashes`. Check the block:
- `xyo_hash(block)` equals `block._hash`.
- The block number is ≤ the block in `finalizationViewer_head`.
- Block number, `_hash`, `addresses[0]` (the producer) and the signed time all equal K's
  `receipt` fields `block`, `blockHash`, `blockProducer` and `blockTime`.

The **signed time** is the `epoch` of the block's `network.xyo.time` payload, whose hash is in
the signed `payload_hashes`. Do not use `$epoch`: the producer's signature does not cover it.

## 5. The anchor transaction (R's `receipt.tx`)

Same as step 4, for tx `6987871cbeb54f245be8600d98a4f043040142b52eccd2d4be9b8b8494b1e5ce`, with
these differences:
- the signer is ee9d;
- `payload_hashes` contains the record hash, the batch hash, and the elevated
  `network.xyo.hash` of the batch.

Then check the ordering:
- the authorization's block ≤ the anchor's block;
- the anchor's signed time falls inside the authorization window.

## 6. Signature validity (needs secp256k1)

The Python standard library has no secp256k1. In an empty folder, use XYO's own published
validator (XYO's code, not Oxyon's):

```
npm i @xyo-network/sdk-protocol@7.4.2
node verify/sigcheck.mjs https://beta.api.chain.xyo.network/rpc 4cdf748dac18fab2f26b67a155fc192591fc4e5f0d5b16afbb5707b3d9974187
node verify/sigcheck.mjs https://beta.api.chain.xyo.network/rpc 6987871cbeb54f245be8600d98a4f043040142b52eccd2d4be9b8b8494b1e5ce
```

Expect `signature valid for 4e881c82…` and `signature valid for ee9d194b…`. Any secp256k1
library works too: the signature covers `xyo_hash(tx, data=True)`.

## 7. All of steps 1–5 in one command

```
python verify/verify_evidence.py records/sequence/2026/10/09/14-82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05.json
```

Every row should read `[ok]`, and the exit code should be 0. Rows marked "Oxyon's disclosure"
are statements, not checks.

## 8. Check that the verifier rejects bad evidence

```
python verify/selftest.py
```

This runs the verifier on the genuine record and on deliberately broken copies in
`verify/fixtures/` (not evidence):
- a one-letter change to the claim;
- an altered SHA-256;
- a receipt naming the wrong block producer;
- a missing authorization.

The genuine record must pass. Each broken copy must fail, or report INCOMPLETE, for the
right reason.

## Limits

- **Revocations.** `verify_evidence.py` scans every block from the authorization to the anchor
  (664,733–664,739 here) for a revocation by the issuer, so this record's check is
  independent. Ranges over 5,000 blocks fall back to `index.json`, whose completeness is
  Oxyon's claim, and the script says so.
- **Block producers.** The blocks were produced by Oxyon-operated producers (README,
  "Disclosure"). That does not change any check above, but they were not produced by an
  unrelated operator.
- **Truth and timing.** The evidence proves that the bytes existed no later than block
  664,739. It does not prove when they were written, or that their contents are true.
