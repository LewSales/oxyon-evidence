# Verify Oxyon's evidence yourself

You need nothing from Oxyon's servers, JavaScript or APIs. The only inputs are:
- the files in this repository;
- GitHub, at a pinned commit;
- XYO's public XL1 RPC and block CDN.

Every step can be done by hand, or with the two short scripts in `verify/`.

**Tools (tested from a clean clone, 2026-11-14):** git; Python 3 (3.13.5 tested; standard library only); curl and
`sha256sum` (or any SHA-256 tool); for the signature steps, Node 22.16 or later with npm 11, run inside the clone.
**What you still trust:** XYO's RPC and block CDN for chain data, finality (as reported) and which chain is canonical;
GitHub for serving the pinned source bytes (their SHA-256 is checked); XYO's npm packages for secp256k1. The
`verify_evidence.py` step runs Oxyon-written code: it is short, standard-library only and readable, and the rules it
applies are written out below so that you can re-implement them instead.

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

The Python standard library has no secp256k1. Inside your clone of this repository (so that
`verify/sigcheck.mjs` is there), install XYO's own published validator (XYO's code, not Oxyon's):

```
npm i @xyo-network/sdk-protocol@7.4.2
node verify/sigcheck.mjs https://beta.api.chain.xyo.network/rpc 4cdf748dac18fab2f26b67a155fc192591fc4e5f0d5b16afbb5707b3d9974187
node verify/sigcheck.mjs https://beta.api.chain.xyo.network/rpc 6987871cbeb54f245be8600d98a4f043040142b52eccd2d4be9b8b8494b1e5ce
```

Expect `signature valid for 4e881c82…` and `signature valid for ee9d194b…`. Any secp256k1
library works too: the signature covers `xyo_hash(tx, data=True)`. `sigcheck.mjs` checks only the
transaction as the RPC returns it; that it is the anchored transaction is step 7's job. Block
signatures are checked only by the browser verifier (§9c).

For the whole transaction under XYO's current rules, run `verify/txcheck.mjs`. It checks:
- the signatures;
- the chain id;
- fees and the nbf/exp window;
- that each elevated payload hashes to what the signature covers.

Run it inside your clone of this repository (so that `verify/txcheck.mjs` is there). It worked with Node 22.16
and npm 11 in a clean-clone test on 2026-11-14; it was written for Node 26:

```
npm i @xyo-network/xl1-protocol@5.8.10 @xyo-network/sdk@8.1.1
node verify/txcheck.mjs sequence 4cdf748dac18fab2f26b67a155fc192591fc4e5f0d5b16afbb5707b3d9974187
node verify/txcheck.mjs sequence 6987871cbeb54f245be8600d98a4f043040142b52eccd2d4be9b8b8494b1e5ce
```

Expect `valid on sequence: signed by 4e881c82…` and `… ee9d194b…`. The script drops any
`_hash`/`_dataHash` that comes with the data and recomputes it.

## 6b. Transaction integrity (in step 7)

`verify_evidence.py` also checks each transaction from its own bytes, with every hash
recomputed (the `Transaction integrity` rows):
- **Network:** the chain id is the expected network's (`CHAIN_IDS` in the script).
- **Transaction:** the transaction hashes to the hash being verified.
- **Signers:** there is one signature per address, and `from` is a signer.
- **Window and fees:** nbf/exp form a valid window, the transaction landed inside it, and
  the fees are present.
- **Payloads:**
  - Every payload the RPC returns hashes to a value the signed transaction commits to, under
    the same schema.
  - Every elevated payload is present and matches its hash.
  - Hash metadata that arrives with the data is not trusted.
- **Transfers:** a transfer has a valid sender, recipients and amounts. A sender other than
  the signer is reported as "not decided by this script", because XYO allows it only under
  a signer authorization this script does not check.

**Integrity is not inclusion.** These checks say the data is what the signature covers.
The rows above them (block, finality, signed time) say where and whether it landed.

## 7. All of steps 1–5 in one command

```
python verify/verify_evidence.py records/sequence/2026/10/09/14-82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05.json
```

Every check row should read `[ok]` (none `[pending]`), and the exit code should be 0. Rows marked
`[statement]` ("Disclosure", "Oxyon's disclosure") are statements, not checks; before 2026-11-14 they printed as `[ok]`.
**Exit 0 alone is not a verdict:** a run with `[pending]` rows also exits 0 (see §9).

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

The transaction checks also have offline tests (no network, standard library only):

```
python verify/test_tx_integrity.py
```

They use the two genuine Sequence transactions above and one **synthetic** transfer
(`verify/fixtures/tx/synthetic-transfer.json`: a throwaway key, never broadcast, not
evidence). Each case must be rejected:
- an edited amount, recipient, sender or schema;
- the wrong network, or an edited chain field;
- an edited or missing signature;
- a missing commitment or a missing elevated payload;
- malformed input.

Off-chain payloads, unfamiliar committed schemas and storage metadata must be accepted.

## 9. Reading a result

Each row the verifier prints is one check, in one of four states:

| Row | Meaning |
|---|---|
| `[ok]` | Checked, and it holds |
| `[statement]` | A disclosure: who included a transaction, or Oxyon's note about it. Not a check, never counted, never changes the exit code (printed as `[ok]` before 2026-11-14) |
| `[FAIL]` | Checked, and it does not hold. The evidence is wrong or has been altered |
| `[pending]` | Not checkable yet, for example an anchor that has not been broadcast, or an intact transaction still awaiting the finalized head reported by XYO RPC (see below). Not a failure |
| Oxyon's disclosure | A statement by Oxyon, not a check |

The exit code is a verdict on the evidence only when one was reached:

| Exit | Meaning |
|---|---|
| `0` | No row failed (`[ok]`, `[statement]` and `[pending]` only) |
| `1` | At least one row is `[FAIL]` |
| `2` | `[INCOMPLETE]`: a file the evidence chain needs is missing, the record is outside a clone of this repository, or the evidence is malformed (not JSON, or an unexpected structure). Nothing was concluded; never VERIFIED. Before 2026-11-14, malformed input crashed with exit 1 |
| `3` | `[UNAVAILABLE]`: GitHub, the RPC or the block CDN could not be read. **Nothing was concluded**; run it again. An unreachable source is never reported as a failed check |

**For scripts: read an explicit verdict, never exit 0 alone.** Exit 0 means only that no check failed. Use
`--receipt <file>` and read `outcome.status` (`VERIFIED`, `FAILED`, `INCONCLUSIVE`, `NOT_EVALUATED`), or require that
no row is `[pending]`. Treat exit 2 as INCONCLUSIVE and exit 3 as NOT_EVALUATED (run again later); neither is a failure
of the evidence.

**Awaiting finality is pending, not failed (since 2026-11-14).** An on-chain leg is `[pending]` when its transaction is intact (right chain, hash, signer and commitments) but is in a block above the finalized head reported by XYO RPC, or is in no block yet while its `nbf..exp` window still reaches above that head. Run it again later. It is `[FAIL]` for any integrity failure (including a bad block hash or clock, or a block outside `nbf..exp`) and when the window has passed with the transaction in none of its blocks. **Intentional exit-code change:** such a run used to exit `1` (`[FAIL]`); it now exits `0` with a `[pending]` row, and its receipt says `INCONCLUSIVE` (it used to say `FAILED`). Finality is still only as XYO RPC reports it.

The same input, against the same chain state, gives the same rows and the same exit code on every run. The checks have no
randomness, and every list they compare is sorted.

## 9b. A machine-readable receipt (optional)

```
python verify/verify_evidence.py <record> --receipt receipt.json
```

`--receipt` writes a JSON receipt (`oxyon.evidence.verification-receipt`, version `0.1`) beside the run. Everything else stays the same: the rows printed, the exit code and the checks themselves. Without the flag, the verifier behaves exactly as before. The receipt is made from what the run already read, with no extra network request, and is unsigned.

| Field | What it says |
|---|---|
| `procedure` | Which script ran: `verifierSha256` (authoritative: the exact bytes that ran) and the Python version. `gitCommit` is the local checkout's HEAD when git can read it, otherwise `UNKNOWN`. `verifierMatchesCommit` says whether this one file differs from that commit; it does not claim the rest of the checkout is clean |
| `performedAt` | When this run finished (UTC, from the local clock) |
| `outcome.status` | Decided by **checks only**, never by statements. `VERIFIED` only when **every** check passed and none was left `[pending]`. A `[pending]` check makes it `INCONCLUSIVE`, even though the exit code is 0. `FAILED` for exit 1, `INCONCLUSIVE` for exit 2, `NOT_EVALUATED` for exit 3 (nothing was concluded) |
| `checks` | Every printed row, word for word, with a `kind`. A `check` is `VERIFIED`, `FAILED` or `NOT_EVALUATED`. A `statement` (the Disclosure and "Oxyon's disclosure" rows, printed as `[statement]`; `[ok]` before 2026-11-14) is `STATEMENT`: it is kept but is not a check and is not counted. Rows are classified where the verifier records them, not by their text. `outcome.counts` gives checks and `statements` separately (Record A: 13 checks, 3 statements) |
| `scope.signatures` | Always `NOT_EVALUATED`: this script does not check secp256k1 signatures (see step 6) |
| `scope.finality` | The rule used: block height ≤ the finalized head XYO's RPC reports. It is a trust in that RPC, not finality established independently. Each leg also gives `pending` (awaiting that head; added 2026-11-14, additive, so `receiptVersion` stays `0.1`) |
| `scope.producerAttribution` | `INFERRED`: the block's first signer is taken as its producer |
| `evidence`, `chain` | The record, batch and authorization hashes, the source's sha256, and each transaction's block, block hash and signed time |
| `reproduce` | The original invocation as an argument list (`argv`, no shell parsing), plus `command` (quoted for POSIX shells) and `commandWindows`. Run it from the same directory: paths are as given. The outcome, check results, hashes, blocks and signed times should repeat. `performedAt` and the finalized head will differ, so two receipts are not byte-identical |

The receipt is written in full to a hidden `.receipt-*.partial` file in the same folder, flushed to disk, then published under its name in one exclusive step (a hard link) that fails if the name exists. The temporary file is always removed. So the final name holds a complete receipt or nothing, even if the run is interrupted or two runs race; only a hard kill can leave a stray `.partial` file. The receipt file is created new and never overwrites anything. If the path already exists (a file, a directory or any symbolic link), or if it is the evidence record however spelled (relative, `..` or a link), no receipt is written and the reason goes to stderr. The verdict and the exit code are unaffected.

**The exit code is the evidence verdict only, not the receipt status.** Whether the receipt was written is reported on stderr, with one of two stable prefixes:

- `receipt (<STATUS>) written to <path>`: success.
- `receipt not written: <reason>`: nothing at the path was created or changed.

Scripts should check the stderr line, or that the file exists.

**Paths and privacy:** arguments are recorded exactly as given, so that the run can be reproduced. Absolute paths can therefore show local folder or user names. Run from the repository with relative paths, as in the examples above, before you share a receipt.

A receipt describes one run. It is not evidence by itself: re-run the command, and the result that counts is yours.

## 9b2. The browser receipt (receipt version 0.2)

After a run, the record page at `oxyon.io/evidence/record/?h=<record>` offers **Download receipt**. It is the same
schema, `oxyon.evidence.verification-receipt`, at **`receiptVersion` 0.2**, because version 0.1 cannot describe a browser
run truthfully: in 0.1, `scope.signatures` is always `NOT_EVALUATED` and `outcome.exitCode` is an integer, while the
browser does check signatures and has no exit code. This script keeps writing 0.1, unchanged.

| Field (0.2) | Difference from 0.1 |
|---|---|
| `procedure.kind` | `browser` (new). `procedure.id` is `oxyon.xl1.evidence-verify.browser`. `procedure.files` gives the SHA-256 of each page file that makes up the procedure (verify.mjs, scope.mjs, data.mjs, receipt.mjs and the bundled XYO SDK), as re-fetched from the same origin when the receipt was made; `null` if a file could not be read |
| `startedAt`, `performedAt` | When the run started and finished, from the reader's clock |
| `outcome.exitCode` | Always `null`. `outcome.browserStatus` is the page's own status (`verified`, `failed`, `incomplete`, `unavailable`). `outcome.status` uses the same four words and rules as 0.1: `VERIFIED` only when every check ran and passed |
| `checks[].layer` | The page layer (commitment, signatures, authorization, source, receipts; `disclosure` for statements) |
| `scope.signatures.status` | Evaluated: `VERIFIED`, `FAILED`, `PARTIAL` (some signature checks not evaluated) or `NOT_EVALUATED`. Trust dependency: the SDK copy served by oxyon.io |
| `scope.truthOfContent` | `NOT_ESTABLISHED`, always |
| `integrity` | `signed: false`. The file is unsigned JSON made by the reader's browser: anyone can edit it, and it is not evidence |

Unchanged meaning: `scope.finality` (as reported by XYO RPC, `independentlyEstablished: false`), `producerAttribution` and
`chainCanonicity` (`INFERRED`), statements (`STATEMENT`, never counted). A consumer that only understands 0.1 must
check `receiptVersion` and must not read a 0.2 receipt's signature scope or exit code with 0.1 rules. Check counts
differ from this script by design (Record A: browser 19, Python 13). The receipt is offered only after a run
that finished; one that could not start offers none.

Since 2026-11-14, a 0.2 receipt also carries `procedure.manifest` (the build manifest that loaded with the page: the
exact SHA-256 of each procedure file in that deploy), `procedure.loadedBuilds` (the build each module that ran reports),
and `procedure.provenance`: `COMPLETE`, `MIXED` (modules from two deploys ran together), `CHANGED_SINCE_LOAD` (the site
was redeployed after the page loaded; the manifest still describes what ran) or `INCOMPLETE` (something could not be
established), with reasons. Provenance never changes `outcome.status`.

## 9b3. Reading any receipt offline

```
python verify/receipt_check.py <receipt.json>
```

Reads 0.1 and 0.2 receipts with no network and runs nothing. It checks the schema and version, the required fields, and
that the receipt agrees with itself: the counts and outcome are recomputed from its own check rows with the rules of the
procedure that wrote it, and claims that procedure cannot make (a 0.1 receipt with evaluated signatures, a signed or
independently-final 0.2 receipt) are rejected. It then prints the procedure, the outcome **the receipt claims**, the
trust limits, and copy-paste commands to re-run the checks. The commands are built only from validated hashes, network
names and record paths, with fixed endpoints; text inside the receipt is never echoed as a command. What it cannot
rebuild, it lists as missing.

A receipt that passes is consistent, not true: it is unsigned, and anyone can write a consistent one. Exit codes describe
the receipt: 0 consistent, 1 invalid or altered, 2 unreadable, 3 unsupported.

## 9c. The browser Evidence Explorer and this script

The record pages at `oxyon.io/evidence/` run their own checks in your browser. They use the same outcome words and the same
scope rules as the receipt, but they are a separate implementation, so their check counts differ (Record A: 19 browser
checks; 13 script checks plus 3 statements). Where both check the same thing, they agree.

| | Browser (Evidence Explorer) | This script |
|---|---|---|
| Signatures | **Checked**, with XYO's SDK (`@xyo-network/sdk-protocol` 7.4.2) bundled and served by oxyon.io. To avoid trusting that copy, run `verify/sigcheck.mjs` with the package from npm (step 6) | Not checked (`NOT_EVALUATED`) |
| Elevated payloads re-hashed (step 6b) | No | Yes |
| Finality | Block height at or below the finalized head **reported by XYO RPC**. A transaction whose window reaches above that head and that isn't yet in a block is *pending*, not failed | Same rule and the same outcome since 2026-11-14: an intact transaction not yet at or below that head is pending, not failed |
| Producer, chain canonicity | `INFERRED` (first block signer; XYO's view of the chain) | Producer `INFERRED` |
| Statements (disclosures) | Shown apart, never counted | `STATEMENT` rows, never counted |
| Outcome | `VERIFIED` only if every check passed and none is unchecked; an unreachable source, RPC or block CDN gives `INCONCLUSIVE` or `NOT_EVALUATED`, never `VERIFIED` | As in 9b |
| Revocation scan | Up to 500 blocks after the authorization | Up to 5,000 blocks |

Neither proves that the telemetry inside the bytes is true.

## 10. WinLEW records: two extra rules

Records with a `winlew.*` claim type (see `tools/README.md` for what each one establishes) get
two more checks:

- **No member identifiers.** The archived content may not contain a Discord-style id (17–20
  digits) or an address (40 hex characters, with or without `0x`). Players appear only as
  salted 64-hex commitments.
- **One match, one record.** A `winlew.game.result` names its match by `sessionCommitment`.
  - The verifier reads **every** file under `records/` (not only `index.json`), loads each other
    `winlew.game.result`'s archived content, and fails if any other record commits to the same
    `sessionCommitment`. The record being checked is excluded, whoever issued the other one.
  - A duplicate fails from both sides.
  - These are not duplicates:
    - files that are not valid JSON, or not a record;
    - other claim types;
    - records whose archived content is missing (they fail their own "Snapshot bytes" check
      instead);
    - records whose `content.sha256` is not 64 lowercase hex characters;
    - results without a `sessionCommitment`.

To reproduce the rule by hand:
1. Take the record's `content.sha256` and open `blobs/sha256/<first 2>/<sha256>.json`.
2. Note its `sessionCommitment`.
3. Look for any other record under `records/` whose `claim.type` is `winlew.game.result` and
   whose archived content has the same value.

There should be none.

## 11. Tests (standard library only; all but selftest run offline)

| Command | What it shows |
|---|---|
| `python verify/selftest.py` | The genuine record passes, and each broken copy in `verify/fixtures/` fails or is INCOMPLETE for the right reason. Uses the network |
| `python verify/test_tx_integrity.py` | Edited transactions are rejected; off-chain payloads, unfamiliar schemas and storage metadata are accepted |
| `python verify/test_unavailable.py` | An unreachable source gives exit 3 and `[UNAVAILABLE]`, never `[FAIL]` |
| `python verify/test_pending.py` | Offline: an intact transaction awaiting the reported finalized head is `[pending]` (receipt `INCONCLUSIVE`); a finalized one passes; tampered blocks, a wrong signer, missing commitments and an expired window still fail; an unreachable source raises UNAVAILABLE. Also pins exit code and receipt status together (VERIFIED 0, FAILED 1, pending 0 + INCONCLUSIVE, UNAVAILABLE 3 + NOT_EVALUATED) and that `selftest.py` never accepts a pending genuine record |
| `python verify/test_adversarial.py` | Offline, behind a dead proxy: truncated or non-JSON records, a missing batch, wrong types and a record outside a clone are `[INCOMPLETE]` (exit 2, receipt `INCONCLUSIVE`, no traceback, no `[ok]` row); the genuine record with no network is `[UNAVAILABLE]` (exit 3), never `[FAIL]` |
| `python verify/test_receipt_check.py` | Offline: `receipt_check.py` accepts valid 0.1 and 0.2 receipts, including pending and unavailable ones; rejects malformed, unsupported, altered (outcome, counts, hidden failure), incomplete and impossible receipts; never echoes receipt text as a command; uses no network and runs nothing |
| `python verify/test_receipt.py` | The `--receipt` file never claims more than the run established. Covers: outcome mapping (a `[pending]` check is never `VERIFIED`); signatures `NOT_EVALUATED`; finality as RPC-reported; producer `INFERRED`; no network calls in receipt code; and, offline, the same stdout and exit code with and without the flag |
| `python verify/test_one_match.py` | One match, one record. Covers: duplicates, from both sides; several duplicates in a stable order; other matches and claim types; malformed record files; malformed content hashes; missing archived content; results without a `sessionCommitment`; repeated runs. It also checks that **every committed record** still hashes to its file name, has its archived content, and that no committed game result shares a match or names a member |

Run them with `python -I` to keep the current directory off Python's import path.

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
