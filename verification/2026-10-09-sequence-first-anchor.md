# Verification run: first Sequence anchor

This is **Oxyon's own run** of the public verifier, recorded for reference. It is not
independent verification. Reproduce it yourself (see VERIFY.md); your result is the
one that counts.

| | |
|---|---|
| Run at (UTC) | 2026-10-09T16:46:23Z |
| Sequence finalized head | #665042 |
| Python | Python 3.13.5 (standard library only) |
| Node.js (signature step) | v22.16.0, @xyo-network/sdk-protocol 7.4.2 |
| verify/verify_evidence.py | sha256 `3de38db4b2e34710f7c433ed2341e2112e7a85484d94fc4630da51d2a9542c86` |
| verify/sigcheck.mjs | sha256 `0ebb8f2d2939c6787bf8871b8834c03407c69c4253806cb1440f82133a7525f9` |

## `python verify/verify_evidence.py records/sequence/2026/10/09/14-82a3779a906c3eb92561300b819a052a98d1fd529bb6183fd834f1b3c0749a05.json`

```
[ok] Snapshot bytes match the record: 34680 bytes from GitHub at the pinned commit, commit 76b3489a81, sha256 a9951280cfd5175c…
[ok] Record is in the batch: record 82a3779a906c3eb9…
[ok] Record cites this authorization: authorization dbafea3b4208d166…
[ok] Authorization covers this record: 4e881c82… → ee9d194b… for xl1.producer.telemetry
[ok] Anchor committed on chain by the anchoring key: block #664739, signed time 1791555326716, final=True, commits=True
[ok] Published receipt matches the chain (anchorTx): block, block hash, signed time, block producer and chain all match
[ok] Disclosure (anchorTx): included by 2152e6ae…, a party to this evidence; inclusion is not verification
[ok] Oxyon's disclosure (anchorTx, a statement, not a check): Included in a block produced by 2152…cc91, Oxyon's Windows producer, which is also the subject of this record. Inclusion is not verification: anyone can check the commitment against signatures, hashes and the GitHub bytes without trusting the block producer.
[ok] Authorization committed on chain by Oxyon: block #664733, signed time 1791555154375, final=True, commits=True
[ok] Published receipt matches the chain (authorizationTx): block, block hash, signed time, block producer and chain all match
[ok] Oxyon's disclosure (authorizationTx, a statement, not a check): Included in a block produced by ca08…23b3, a producer operated by Oxyon. Inclusion is not verification: the commitment is checked against signatures and hashes, not against who produced the block.
[ok] No revocation by the issuer between authorization and anchor: scanned blocks #664733–#664739 on chain
[ok] Anchor block time is inside the authorization window: 1791555326716
[ok] Authorization was on chain before the anchor: 1791555154375 ≤ 1791555326716
exit code: 0
```

## Signatures (`node verify/sigcheck.mjs <rpc> <tx>`, XYO's validator)

```
A 4cdf748d…: signature valid for 4e881c8217945f356900eb5e9e66fcbb05da3829
C 6987871c…: signature valid for ee9d194be80f4bafcb9e9f10f765f3afa431a8bc
```
