# Authority threat model and trust-root transition protocol

Status: research and design (Sprint 010). Nothing here creates, uses or revokes a key.

## What "authority" means here
- **Identity (issuer):** an XL1 address that Oxyon states is Oxyon's. It signs **authorizations** and **revocations**.
- **Delegate (anchorer):** an address the identity authorizes, within a scope (claim types, network, schema, validity window), to anchor evidence records.
- **Verification** (`verify_evidence.py`, the browser verifier) checks that:
  - the record's authorization hashes to the cited hash;
  - the authorization transaction is signed by its issuer and committed on chain;
  - the anchor is signed by the delegate and inside the window;
  - no revocation by the issuer lies between the authorization and the anchor.
- **Organizational trust**, that an identity *is* Oxyon LLC, is **not** cryptographic. It rests on Oxyon's statements on oxyon.io and in this repository.

## Threats

### T1. A delegate key is exposed
- **Attacker can:** anchor records that verify as authorized, until the authorization expires or is revoked.
- **Attacker cannot:** issue authorizations or revocations.
- **Mitigation:** the issuer revokes (a revocation takes effect at its block), and a new delegate is authorized. Records anchored before the revocation still verify. This is by design; nothing can tell them apart from genuine ones cryptographically.

### T2. An identity (issuer) key is exposed
- **Attacker can:**
  - authorize new delegates and anchor records under them;
  - **revoke** genuine authorizations (denial of service);
  - write a conflicting history: a forged authorization plus record, at any later block.
- **Revocation by the same key** is not a defence against T2: the attacker holds the same power. It only reduces the genuine records' exposure.
- **The only remedy is a new trust root:** a fresh identity, bound to Oxyon LLC through channels the exposed key does not control (T4), with the old identity declared **historical**. Verifiers and pages must then treat records by the old identity as "issued by a historical identity". They must not be treated as current Oxyon authority after the transition date.

### T3. Revocation limits (bounded scans are not proof of absence)
- **Revocation is an Oxyon verifier convention**, a bound witness that both verifiers look for. **It is not an XL1 protocol rule:** XL1 does not invalidate anything, and other software won't honour it unless it implements the same rule.
- **The scan is bounded:** the verifiers scan only the interval between the authorization and the anchor (Python up to 5,000 blocks, browser up to 500).
  - A **completed** scan of the whole interval supports "no revocation before this anchor".
  - A **longer** interval is reported as **not checked** (NOT_EVALUATED, so never VERIFIED), never as "unrevoked".
- **The index's revocation list is Oxyon's claim:** a stale or edited index could omit one. Trust comes from the chain scan, not the list.
- **Open:** a revocation outside the interval (before the authorization, or after the anchor) is not relevant to that record by design. Ambiguity remains when two revocations conflict (for example under T2). It should be resolved by the trust-root transition, not by a verifier heuristic.

### T4. oxyon.io or this repository is compromised, but the new identity key is not
- **Publication channels and cryptographic authority are separate.** Someone controlling the website or the repository, but not the key, **can:**
  - change which address the site *says* is Oxyon's identity (an organizational-trust claim);
  - edit `index.json`: hide records, list wrong paths, omit revocations;
  - edit the documentation and the verifier code that the site serves.
- **They cannot:**
  - sign anything as the identity or delegate;
  - make a forged record pass the cryptographic checks, as long as the verifier code is genuine and the identity address used for comparison is genuine.
- **Consequences:**
  - The **record-identity check** (a record must recompute to the requested hash) and **chain-based checks** limit what an edited index can achieve: it can hide things or mislabel, but it cannot make a forged record verify.
  - **Served verifier code is a trust dependency** (disclosed). The defence is reproduction: a clean clone of a pinned commit, `verify_evidence.py`, and XYO's npm packages for signatures.
  - **The identity binding must use more than one channel:** for example oxyon.io *and* a signed repository tag *and* the organization's verified accounts. Then a single compromised channel can't silently swap the identity. Any change to the published identity must be announced in all of them, with the date.

### T5. The index is stale, rolled back or tampered with
- **Effect:** discovery only. Pages say "listed in Oxyon's index", and every verification happens against the record and the chain.
- **Hidden or rolled-back entries:** they make records **unlisted**, not falsely verified.
- **A wrong entry:** pointing a hash at another record is caught by the record-identity check.

## Transition protocol (for the owner's decision; every step marked RED is owner-only)
1. **(RED) Create the new identity and delegate** offline, from a fresh recovery phrase. Never derive them from an exposed one, and never store them in a repository or chat.
2. **Prepare the public binding**, before first use, in at least two independent channels: a page on oxyon.io and a reviewed commit (ideally a signed tag) in this repository. Both state the new identity, the effective date, and the old identity's status ("historical; not current authority from <date>").
3. **(RED) Authorize the new delegate** with the new identity: `tools/evidence.mjs authorize`, a dry run first.
4. **(RED) Revoke or let expire** the old authorizations. Record the decision and the reasons, including that the old issuer can also revoke or forge (T2).
5. **Update the verifiers' presentation** (no verification rule changes): mark old-identity records as historical attribution, and keep them verifying.
6. **Recovery:** if the new identity is ever exposed, repeat from step 1. The binding channels carry the history, so verifiers can tell which identity was current when.

## What would change this model
- **XYO publishing finality, revocation or account-recovery primitives** at the protocol level.
- **A hardware-backed or multi-party identity** for Oxyon (for example a threshold signature). That would turn T2 into a much harder attack.
