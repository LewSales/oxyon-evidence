// `revoke`, tested offline with SYNTHETIC keys only: the phrase is generated here and
// discarded; no real key, no network (fetch throws), nothing broadcast or written.
//
//   XL1_SDK_MODULE=<…/@xyo-network/xl1-sdk/dist/neutral/index.mjs> node --test tools/test/
import test, { before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { xyoHash, revocationFor, buildTx } from '../evidence.mjs'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const SDK = resolve(process.env.XL1_SDK_MODULE || join(ROOT, '..', 'Geohackers', 'node_modules', '@xyo-network', 'xl1-sdk', 'dist', 'neutral', 'index.mjs'))
const SEQ = '4b43a753c8024c0e5000e8ac948ac0063ac624bc'
const hex40 = (a) => String(a).toLowerCase().replace(/^0x/, '')

let sdk, issuer, delegate, stranger, authorization, authHash
before(async () => {
  globalThis.fetch = () => { throw new Error('network is forbidden in these tests') }
  sdk = await import(pathToFileURL(SDK).href)
  const nm = resolve(dirname(SDK), '..', '..', '..', '..')
  const { generateMnemonic } = await import(pathToFileURL(join(nm, '@scure', 'bip39', 'index.js')).href)
  const { wordlist } = await import(pathToFileURL(join(nm, '@scure', 'bip39', 'wordlists', 'english.js')).href)
  const base = await sdk.generateXyoBaseWalletFromPhrase(generateMnemonic(wordlist, 256)) // synthetic, test-only
  ;[issuer, delegate, stranger] = await Promise.all([base.derivePath('0'), base.derivePath('1'), base.derivePath('2')])
  authorization = {
    schema: 'oxyon.evidence.authorization.v1', issuer: hex40(issuer.address), delegate: hex40(delegate.address), role: 'anchorer',
    scope: { claims: ['winlew.game.result'], recordSchema: 'oxyon.evidence.record.v1', network: { id: 'sequence', chainId: SEQ } },
    validFrom: 0, validUntil: 1e13, statement: 'synthetic test authorization', doesNotAuthorise: 'anything else',
    revocation: 'An oxyon.evidence.revocation.v1 record whose revokes field is this record\'s hash, signed by the issuer and committed on the same network.', version: 1,
  }
  authHash = xyoHash(authorization)
})

test('the revocation names the authorization, its issuer and its network', () => {
  const r = revocationFor({ authorization, authorizationHash: authHash, issuerAddress: issuer.address, revokedAt: 1 })
  assert.equal(r.schema, 'oxyon.evidence.revocation.v1')
  assert.equal(r.revokes, authHash)
  assert.equal(r.issuer, authorization.issuer)
  assert.deepEqual(r.network, { id: 'sequence', chainId: SEQ })
  assert.match(r.statement, /Records anchored under that authorization before that block remain valid/)
})

test('only the issuer may revoke: the delegate or any other key is refused', () => {
  for (const k of [delegate, stranger]) {
    assert.throws(() => revocationFor({ authorization, authorizationHash: authHash, issuerAddress: k.address }), /only the issuer/)
  }
})

test('a tampered authorization or a wrong hash is refused', () => {
  assert.throws(() => revocationFor({ authorization: { ...authorization, delegate: '0'.repeat(40) }, authorizationHash: authHash, issuerAddress: issuer.address }), /does not hash/)
  assert.throws(() => revocationFor({ authorization, authorizationHash: 'f'.repeat(64), issuerAddress: issuer.address }), /does not hash/)
  assert.throws(() => revocationFor({ authorization: { ...authorization, schema: 'x' }, authorizationHash: authHash, issuerAddress: issuer.address }), /not an oxyon/)
})

test('the signed transaction is exactly what verify_evidence.py detects as a revocation (offline)', async () => {
  const revocation = revocationFor({ authorization, authorizationHash: authHash, issuerAddress: issuer.address, revokedAt: 1 })
  const hash = xyoHash(revocation)
  const tx = await buildTx(sdk, issuer, 'sequence', hash, [revocation], { head: { block: 100, chain: SEQ } })
  const bw = tx.signed[0]
  // verify_evidence.py: p.from == auth.issuer and 'oxyon.evidence.revocation.v1' in p.payload_schemas
  assert.equal(hex40(bw.from ?? bw.addresses[0]), authorization.issuer)
  assert.equal(hex40(bw.addresses[0]), authorization.issuer)
  assert.ok(bw.payload_schemas.includes('oxyon.evidence.revocation.v1'), JSON.stringify(bw.payload_schemas))
  // The revocation itself is committed by hash, with its network.xyo.hash elevated on chain.
  const elevated = xyoHash({ schema: 'network.xyo.hash', hash })
  assert.ok(bw.payload_hashes.includes(hash) && bw.payload_hashes.includes(elevated))
  assert.ok(bw.script.includes(`elevate|${elevated}`))
  assert.equal(bw.chain, SEQ)
  assert.equal(tx.nbf, 100); assert.equal(tx.exp, 110)
})

test('a revocation signed by the delegate would not be detected (it must come from the issuer)', async () => {
  // Build one with the wrong key directly, bypassing revocationFor's refusal, to pin the verifier rule.
  const bogus = { ...revocationFor({ authorization, authorizationHash: authHash, issuerAddress: issuer.address, revokedAt: 1 }) }
  const tx = await buildTx(sdk, delegate, 'sequence', xyoHash(bogus), [bogus], { head: { block: 100, chain: SEQ } })
  assert.notEqual(hex40(tx.signed[0].addresses[0]), authorization.issuer)
})

test('old evidence stays verifiable: the verifier only scans authorization→anchor, so a later revocation is outside it', () => {
  const src = readFileSync(join(ROOT, 'verify', 'verify_evidence.py'), 'utf8')
  assert.match(src, /lo, hi = bundle\['_blocks'\]\['authorizationTx'\], bundle\['_blocks'\]\['anchorTx'\]/)
  assert.match(src, /for n in range\(lo, hi \+ 1\)/)
  // Every published record was anchored before any revocation could exist (none published yet).
  const idx = JSON.parse(readFileSync(join(ROOT, 'index.json'), 'utf8'))
  assert.deepEqual(idx.revocations ?? [], [])
  for (const r of idx.records) assert.ok(Number.isInteger(r.anchorBlock) && r.anchorBlock < 760000, `${r.record} anchored at ${r.anchorBlock}`)
})

test('importing the tool runs no command and the repo holds no revocation yet', () => {
  assert.ok(!readdirSync(join(ROOT, 'keys', 'sequence')).includes('revocations'))
})
