# Licensing

This repository holds two kinds of material under two licences.

| Material | Paths | Licence |
|---|---|---|
| Evidence data: records, batches, receipts, authorizations, the index, key notes, verification runs, and the documentation | `records/`, `keys/`, `index.json`, `verification/`, `README.md`, `VERIFY.md`, `LICENSING.md` | **CC0 1.0 Universal** (public-domain dedication), see `LICENSE-CC0` |
| Archived source snapshots | `blobs/` | **CC0 1.0**, to the extent Oxyon holds rights in them (see below) |
| Verification software | `verify/` | **MIT**, see `verify/LICENSE` |

## Why two licences

- **Evidence is dedicated to the public domain (CC0)** so anyone can copy, mirror, archive
  and republish it without asking, attributing or worrying about terms. Evidence that
  cannot be freely copied is harder to check independently.
- **The verification scripts use MIT**, a standard, permissive software licence that
  carries the usual no-warranty disclaimer.

## The archived snapshots (`blobs/`)

Each file in `blobs/` is a byte-exact copy of a status file published by an
Oxyon-operated producer to <https://github.com/LewSales/xl1-status-data>.
- Oxyon dedicates its own rights in these files under CC0 1.0.
- They also contain public XL1 chain facts, such as other producers' public addresses and
  block counts. Oxyon claims no rights in those facts, and the dedication covers only what
  Oxyon can dedicate.

The files are kept **unmodified**. Their SHA-256 is what the on-chain record commits to, so
changing a single byte would break verification. Any licence or attribution notice for them
lives here, never inside the files.

## Not covered

- **Third-party software** that the instructions ask you to install, such as
  `@xyo-network/sdk-protocol` (LGPL-3.0, by XYO). It is not included here and keeps its own
  licence.
- **Names and marks** such as "Oxyon", "XL1" and "XYO". The licences cover content, not
  trademarks. Using XL1 does not imply that XYO endorses this repository.
