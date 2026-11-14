# Tools: make a key, authorise it, anchor a record

`tools/evidence.mjs` writes the files `verify/verify_evidence.py` checks, in the same shapes
as the first record. It builds each transaction the way the verifier expects it:

- one elevated `network.xyo.hash` payload, which goes on chain;
- the object itself, referenced by its hash.

It refuses to sign anything that would not pass those checks.

**Requirements:** Node 20+ and the XL1 SDK. By default it uses the copy installed for
GeoHackers in this workspace; set `XL1_SDK_MODULE` to another `dist/neutral/index.mjs` if needed.

**Key files** hold a recovery phrase, either the phrase alone or `NAME="phrase"` on one line.
They are read by the tool and never printed. Keep them offline and out of this repository.

## The four commands

```
node tools/evidence.mjs new-key   --out C:\keys\oxyon-anchor-winlew.key       # prints the new address only
node tools/evidence.mjs address   --key-file C:\keys\oxyon-anchor-winlew.key  # the address to fund
node tools/evidence.mjs authorize --issuer-file <Oxyon identity key file> --delegate <new address> \
                                  --claims winlew.game.result,winlew.reward.trail --until 2027-01-31 [--send]
node tools/evidence.mjs anchor    --key-file C:\keys\oxyon-anchor-winlew.key --authorization <hash> \
                                  --content result.json --claim-type winlew.game.result \
                                  --statement "…" [--send]
```

- **Dry run by default.** Without `--send` the transaction is built and signed, its hash, fee and
  the sender's balance are printed, and nothing is broadcast or written.
- **What `--send` writes:**
  - `keys/<network>/authorizations/<hash>.json` and an `index.json` entry, for `authorize`;
  - `records/<network>/yyyy/mm/dd/HH-<hash>.json`, the archived content in `blobs/`, and an
    `index.json` entry, for `anchor`.
- **Funding:** each signing address needs XL1 on the network it signs on, about 101 XL1 to
  clear the gas ceiling the node checks. The fee actually charged is tiny.
- **Who signs `authorize`:** the issuer must be Oxyon's identity key (`4e88…3829`). Only it can
  make the authorization mean "Oxyon authorises".

## Pinned GitHub sources (Record A's shape)

A record can point at a public file pinned at a commit instead of an archived copy:

```
node tools/evidence.mjs anchor --key-file prompt --authorization <hash> \n  --source-repo LewSales/xl1-status-data --source-commit <40-character commit> --source-path windows.json \n  [--expect-sha256 <sha256>] [--expect-bytes <n>] [--content <local copy to cross-check>] \n  --claim-type xl1.producer.telemetry --statement "…" [--subject <json>] [--observed-at <ms>] [--send]
```

- **The commit must be a full 40-character SHA.** Branch names, tags and short SHAs are refused, because they can move.
- **Before anything is built**, the bytes are read from `raw.githubusercontent.com/<repo>/<commit>/<path>` and checked: they must be JSON, and must match `--expect-sha256`, `--expect-bytes` and a local `--content`, when given.
- **The record gets** `source: { url, repository, commit, path, publisher }`, exactly as Record A has it. With `--send`, the bytes are also archived under `blobs/sha256/`, which is the verifiers' fallback copy.
- **Without the `--source-*` flags**, the archived-source behaviour is unchanged.

## Preview without a key

`anchor --preview` builds and prints the record and batch, using the same arguments without `--key-file`. No key is read, nothing is signed, broadcast or written, and no chain call is made. `issuedAt`, and so both hashes, change when the record is really signed. `--preview` cannot be combined with `--send`.

Offline tests: `node --test tools/test_pinned_source.mjs`.

## Authority transition planner (read-only)

`node tools/authority-plan.mjs [--exposed <addr,addr>] [--json]` reads **only** `index.json`. It lists each identity, delegate and authorization, with validity, whether it is active, the records that cite it, the risk if a stated address is exposed, and who alone could revoke it.

- It never reads a key file, never asks for or derives a phrase, never builds, signs or sends anything, and makes no network call.
- Exposure is whatever the owner states with `--exposed`; the planner doesn't decide it.
- Its output begins and ends with **PLAN — NOT AUTHORIZATION**.

Tests: `node --test tools/test_authority_plan.mjs`.

## WinLEW claim types

| Claim type | What the content is | What it establishes | What it does NOT establish |
|---|---|---|---|
| `winlew.game.result` | One completed match whose result the **server re-derived**: CryptoSpades replays every move from a server-made seed | The exact result bytes existed, unchanged, no later than the anchor block | That the match was fair, or that the player is who they say |
| `winlew.reward.trail` | One reward decision: game, rule version, eligible points, base and multiplier, payout units, the payout transaction if paid | The reward decision existed, unchanged, no later than the anchor block, and links to its payout | That the score behind it was honestly played (arcade scores are reported by the browser) |

**Privacy rule (checked by the verifier):** the content of a `winlew.*` record may not hold a
Discord ID, a WinLEW account ID or a wallet address. Members appear only as salted
commitments, `sha256(salt ‖ id)`, with the salt held by WinLEW. A record that breaks the rule
fails verification.

**One match, one record (checked by the verifier):** a `winlew.game.result` names its match by
`sessionCommitment`, a salted commitment to the server's session. A second record in this
repository committing to the same match is reported as a duplicate, whoever issued it. A result
with no `sessionCommitment` fails the check, because duplicates could not be ruled out. Tests:
`verify/test_one_match.py`.

Fixtures for both rules are in `verify/fixtures/winlew/`. They are synthetic, never anchored,
and not evidence.
