# CryptoSpades game evidence: security requirements for production integration

**Status:** design requirements, 2026-10-31. Nothing here is integrated or anchored yet.

The only `winlew.game.result` record in this repository is a **synthetic** pilot, not a real match.
This document says what a production integration must satisfy **before** a real CryptoSpades result
is recorded or anchored. It complements the claim contract in [`tools/README.md`](../tools/README.md)
and the verifier in [`verify/`](../verify/).

**The guiding rule: public proof must not require public exposure of private identities.**

A verifier must be able to check a result without learning who played it.

## 1. Who may do what

| Operation | Who | How it is authorised | Never |
|---|---|---|---|
| Start a match (server-made seed) | any player | none needed to play; rate-limited per client | A match started without the server's seed cannot produce evidence |
| Submit a finished match | the player's browser | the session ID the server issued; single use; expires | A second submission of the same session; a submission after expiry |
| Decide the result | **the game server only** | it replays every move from its own seed (re-derivation) | Accepting a client-reported score or outcome |
| Write a `winlew.game.result` record | **the game server's evidence writer only** | a server-side credential held only by that service, checked before anything is stored | Any public endpoint writing evidence; any shared or browser-held credential |
| Link a result to a member (for rewards) | the game server | the player's authenticated WinLEW session, checked server-side at submission | Taking a member ID, wallet or role from the request body |
| Anchor a record on XL1 | the anchoring key only (`tools/evidence.mjs anchor`) | a live Oxyon authorisation naming that key, this claim type and an end date | Anchoring by any key the authorisation doesn't name; anchoring without an owner-approved run |
| Authorise the anchoring key | Oxyon's identity key only (`tools/evidence.mjs authorize`) | the owner's decision, recorded on chain | Automatic or unattended authorisation |
| Read and verify a record | anyone | none: the record, its blobs and the chain are public | Needing private data, a login or the operator's servers to verify |

Server-side authorisation is the only authorisation. CORS settings, hidden or unlinked URLs, obscure
paths and checks in the browser **do not count**. Every write is refused before it touches storage
or a queue unless the caller is authorised.

## 2. What a record may contain

- **No direct identifiers** (enforced by the verifier): no Discord ID, WinLEW account ID or wallet address.
- **A member appears only as a salted commitment** `sha256(salt ‖ id)`.
  - The salt is per member and held by WinLEW.
  - It's never published, so the commitment can't be reversed by guessing IDs.
  - A member can reveal their own salt to prove a record is theirs. Nobody else can do that for them.
- **A handle shown on a leaderboard is display text, not identity.** The record must not present it
  as one.
- **Contents:** the seed, the game version, the full move list (or its hash plus the blob) and the
  re-derived outcome. Together these let anyone replay the match.
- **Excluded:** IP addresses, device data, session tokens, cookies and any other operational metadata.
  Records hold only what verification needs.

## 3. Integrity, replay and duplicates

- **One match, one record.** The record ID derives from the content hash, and the session ID appears
  in it at most once. A second record for the same session is a duplicate, and verification must flag it.
- **Single-use sessions.** The session is marked complete atomically **before** a result is written.
  A race between two submissions yields exactly one result.
- **Tampering is caught by the verifier.** The anchored hash must match the record bytes, and the
  replay must reproduce the stated outcome. Tests must include an edited score, an edited move list,
  a swapped seed and a reused session.
- **Seeds come from the server's CSPRNG** and are stored with the session. A result whose seed the
  server didn't issue isn't evidence.

## 4. What the evidence does and does not prove

| Proves | Does not prove |
|---|---|
| These exact result bytes existed, unchanged, no later than the anchor block | That the match was fair to the player, or that the player didn't have outside help |
| The server's replay of these moves from this seed gives this outcome | Who the player is (only that the holder of a salt can claim it) |
| An Oxyon-authorised key anchored it | That the server code was the published version, unless the record names the game version and that version is public |

The public verification page must say both columns plainly, and show **what remains unproven**
alongside what was verified.

## 5. Operations

- **Keys:**
  - the evidence writer's credential is a dedicated, least-privilege service secret;
  - the anchoring key holds only what fees need;
  - the identity key stays offline.
- **Owner approval for anchoring.** Every anchoring run is approved and logged. Nothing is signed or
  broadcast automatically.
- **Rate limits** on match creation and submission (per client), and a cap on stored sessions
  (sessions expire).
- **Logs** record request paths and outcomes, never bodies, tokens, salts or member identifiers.
- **Before a real match is recorded,** the integration must pass:
  - the verifier's privacy check;
  - the duplicate, tamper and replay tests above;
  - an unauthorised-write test on every write route (no credential, a wrong credential, a credential
    in the query string or a cookie).
