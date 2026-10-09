# Oxyon keys

| Role | Address | Since | Status |
|---|---|---|---|
| Oxyon identity (signs authorizations and revocations) | `4e881c8217945f356900eb5e9e66fcbb05da3829` | 2026-10-09 | active |
| Anchoring key (commits evidence under an authorization) | `ee9d194be80f4bafcb9e9f10f765f3afa431a8bc` | 2026-10-09 | active: authorised on Sequence until 2027-01-09 |

That these addresses belong to Oxyon is Oxyon's public statement, not a cryptographic fact.

## Authorizations

| Network | Authorization | Delegate | Scope | Valid | On chain |
|---|---|---|---|---|---|
| Sequence | [`dbafea3b…a038`](sequence/authorizations/dbafea3b4208d166d7922c2a1bf046de83e2c5457ea944cc47f40d41d146a038.json) | ee9d…a8bc | producer telemetry records | 2026-10-09 → 2027-01-09 | tx `4cdf748d…4187`, block 664,733 |

## Revocations

None.

## Retired keys

Oxyon earlier published three GeoProof keys:
- `c2138ec4b0d6466d25e05bba020dd05b9a262e39` (anchorer);
- `99cb3bf68968d93c1c2f1e56bcc219f8d4df74f1` (attester);
- `f117e95f8e7e4422c0d4967293d7599f42911a4a` (verifier).

Their recovery material was lost, so they cannot sign a handover to the keys above. There is
no cryptographic link between the old keys and the new ones; this note is the only link.
Treat anything those keys sign after 2026-10-09 as **not** Oxyon.
