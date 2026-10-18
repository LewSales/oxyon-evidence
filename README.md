# Oxyon evidence

Public evidence records published by Oxyon, each committed on the XL1 network, with
everything needed to check them **without trusting Oxyon**.

> Oxyon is independent. These records are committed on the public XL1 network; this does
> not mean XYO endorses, reviews or verifies them.

**Status: Experimental.** One record so far, on XL1 **Sequence**, XYO's test network. There
is nothing on Mainnet.

## What is here

| Path | What it is |
|---|---|
| `records/<network>/<yyyy>/<mm>/<dd>/<HH>-<recordHash>.json` | An evidence record, the batch that commits it, and the receipt saying where it landed on chain |
| `keys/<network>/authorizations/<authHash>.json` | An authorization (which key may anchor what, where, until when), with its on-chain receipt |
| `keys/README.md` | Oxyon's keys, their roles, and retired keys |
| `blobs/sha256/<aa>/<sha256>.json` | Archived copies of the exact source files, named by their SHA-256 |
| `index.json` | A list of records and authorizations (a convenience; every entry is re-derivable) |
| `verify/verify_evidence.py` | Verifier: Python standard library only |
| `verify/sigcheck.mjs` | Signature check using XYO's own published validator |
| `verification/` | Oxyon's own verification runs, for reference (not independent) |
| `VERIFY.md` | Step-by-step reproduction, by hand or with the scripts |
| `tools/evidence.mjs` + `tools/README.md` | Make a key, authorise it, anchor a record; also the WinLEW claim types and their privacy rule |
| `verify/fixtures/` + `verify/selftest.py` | Deliberately broken copies (**not evidence**) that the verifier must reject |
| `LICENSING.md`, `LICENSE-CC0`, `verify/LICENSE` | CC0 1.0 for the evidence, MIT for the scripts |

## The first record

| | |
|---|---|
| Claim | Oxyon's Windows producer (`2152e6aec996742fb6e52ae1aad87bd44f2ccc91`) published its status snapshot, generated 2026-10-09T06:09:17.490Z |
| Source | `windows.json` at commit [`76b3489a`](https://github.com/LewSales/xl1-status-data/blob/76b3489a817b58ddc7ac3dbada845dcacb156156/windows.json) of `LewSales/xl1-status-data` |
| Source SHA-256 | `a9951280cfd5175c9b586cc3fcf834641b2f7465f9c398e8a7097768a5df3735` (34,680 bytes) |
| Record | `82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05` |
| Batch | `26c6491b9ddfde3931873b394dc49159b527d26725c1c07e2a72988fd0c37860` |
| Anchored by | `ee9d194be80f4bafcb9e9f10f765f3afa431a8bc` (Oxyon's anchoring key) |
| Anchor transaction | [`6987871c…e5ce`](https://explore.xyo.network/xl1/sequence/transaction/6987871cbeb54f245be8600d98a4f043040142b52eccd2d4be9b8b8494b1e5ce), block 664,739, signed block time 2026-10-09T14:15:26.716Z |
| Authorization | `dbafea3b4208d166d7922c2a1bf046de83e2c5457ea944cc47f40d41d146a038`: `4e881c82…3829` (Oxyon) authorises ee9d to anchor producer-telemetry records on Sequence, 2026-10-09 → 2027-01-09 |
| Authorization transaction | [`4cdf748d…4187`](https://explore.xyo.network/xl1/sequence/transaction/4cdf748dac18fab2f26b67a155fc192591fc4e5f0d5b16afbb5707b3d9974187), block 664,733, signed block time 2026-10-09T14:12:34.375Z |

## What this evidence establishes

1. **Committed on chain.** XL1 Sequence recorded these exact hashes in finalized blocks
   664,733 and 664,739, at the producers' signed block times.
2. **Signatures.** The authorization transaction was signed by `4e88…3829`; the anchor by
   `ee9d…a8bc`.
3. **Authorization.** At the anchor's block time, ee9d was authorised by 4e88 for this kind
   of record on this network, and the authorization was on chain first.
4. **Source integrity.** The committed SHA-256 matches the exact bytes of `windows.json` at
   commit `76b3489a`. Those bytes existed, unchanged, **no later than** block 664,739.

## What it does NOT establish

- **That the telemetry is true.** The snapshot is the producer's report about itself. A
  valid hash proves the bytes are unchanged, not that the numbers in them are right.
- **When the bytes were created.** Only that they existed no later than the anchor block.
  Git commit times are self-asserted.
- **Who controls the keys.** That 4e88 is Oxyon rests on Oxyon publicly naming it (on
  oxyon.io and in `keys/README.md`), not on cryptography.
- **That no revocation exists.** XL1's public endpoints have no by-address index, so
  confirming that no revocation preceded a record means scanning the blocks in between.
  `index.json` lists revocations, but its completeness is Oxyon's claim.

## Disclosure: who included the transactions

Both transactions landed in blocks produced by **Oxyon-operated producers**:

- **The authorization (block 664,733)** was produced by `ca08…23b3`.
- **The anchor (block 664,739)** was produced by `2152…cc91`, the Windows producer that is
  also the **subject of the record**.

Including a transaction is a separate property from verifying it. Any producer can include
a valid transaction, and none can alter a signed one. The checks above rest on signatures,
hashes and the GitHub bytes, not on who produced the block. It does mean these blocks were
**not** produced by an unrelated, independent operator.

This evidence has **not** been verified by an independent block producer, and nothing here
claims it has. Independence comes from the fact that anyone can repeat the checks.

## Verify it yourself

```
python verify/verify_evidence.py records/sequence/2026/10/09/14-82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05.json
```

Then check the signatures with XYO's validator (see VERIFY.md). The verifier contacts only
GitHub and XYO's public endpoints, and re-checks every field of every receipt against the
chain. If GitHub is unavailable, it uses the archived copy in `blobs/` and says so.

## Records are permanent

Records and receipts are never edited or deleted. A correction is a new record that
supersedes the old one; both stay published. A revocation takes effect at its own block and
does not invalidate evidence anchored before it.

## In one sentence

The on-chain commitment verifies **integrity and provenance**: these exact bytes, from this
commit, were committed under this authorization, no later than this block. It does **not**
verify the factual accuracy of any telemetry measurement inside them.

## Licensing

- Evidence data (records, receipts, authorizations, index, docs) and the archived
  snapshots, to the extent of Oxyon's rights: **CC0 1.0**.
- The verification scripts in `verify/`: **MIT**.

See `LICENSING.md`, `LICENSE-CC0` and `verify/LICENSE`.

## Formats

The hash rules (canonical serialization) and schemas are the Oxyon Evidence Layer
specification v1, summarised in VERIFY.md §2.
