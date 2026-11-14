// node tools/test_airdrop.mjs — the airdrop artifact builder (synthetic wallets only).
import test from 'node:test'
import assert from 'node:assert/strict'
import { buildSnapshot, buildDistribution, SNAPSHOT_SCHEMA } from './airdrop.mjs'

const W = ['Rcpt' + 'c'.repeat(40), 'Rcpt' + 'a'.repeat(40), 'Rcpt' + 'b'.repeat(40)]
const TREASURY = 'Treasury'.padEnd(44, 'z')
const base = { event: 'winlew-2y-anniversary', rule: 'each registered wallet receives 1,000 WinLEW', takenAt: '2026-12-06T00:00:00Z', treasury: TREASURY }

test('snapshot: dedupes, drops invalid, excludes project addresses, sorts, and never copies other fields', () => {
  const registry = [W[0], { wallet: W[1], discordId: '123456789012345678' }, { address: W[2] }, W[0], 'not-an-address', TREASURY, 'Dev'.padEnd(44, 'z')]
  const s = buildSnapshot({ ...base, registry, amountEach: '1000000000', exclude: { ['Dev'.padEnd(44, 'z')]: 'Developer Reserve' } })
  assert.equal(s.schema, SNAPSHOT_SCHEMA)
  assert.deepEqual(s.recipients.map((r) => r.wallet), [...W].sort())
  assert.deepEqual(s.totals, { recipients: 3, amountRaw: '3000000000', duplicatesMerged: 1, invalidEntries: 1 })
  assert.deepEqual(s.excluded.map((e) => e.reason).sort(), ['Developer Reserve', 'the airdrop treasury'])
  assert.doesNotMatch(JSON.stringify(s), /123456789012345678|discord/i)
  assert.deepEqual(buildSnapshot({ ...base, registry: [...registry].reverse(), amountEach: '1000000000', exclude: { ['Dev'.padEnd(44, 'z')]: 'Developer Reserve' } }), s, 'order-independent')
})

test('snapshot: per-wallet amounts must cover exactly the eligible wallets', () => {
  const amounts = Object.fromEntries(W.map((w, i) => [w, String((i + 1) * 10)]))
  assert.equal(buildSnapshot({ ...base, registry: W, amounts }).totals.amountRaw, '60')
  assert.throws(() => buildSnapshot({ ...base, registry: W, amounts: { [W[0]]: '1' } }), /no amount/)
  assert.throws(() => buildSnapshot({ ...base, registry: [W[0]], amounts }), /not an eligible/)
  assert.throws(() => buildSnapshot({ ...base, registry: W, amountEach: '1.5' }), /non-negative integer/)
  assert.throws(() => buildSnapshot({ ...base, registry: W }), /exactly one/)
  assert.throws(() => buildSnapshot({ ...base, rule: '', registry: W, amountEach: '1' }), /rule text/)
})

test('distribution: every recipient paid exactly once, nobody else', () => {
  const s = buildSnapshot({ ...base, registry: W, amountEach: '5' })
  const sig = (c) => '5ig' + c.repeat(85)
  const payouts = s.recipients.map((r, i) => ({ wallet: r.wallet, signature: sig('abc'[i]) }))
  const d = buildDistribution({ snapshot: s, snapshotRecord: 'ab'.repeat(32), payouts })
  assert.equal(d.transfers.length, 3); assert.equal(d.totals.amountRaw, '15'); assert.equal(d.totals.signatures, 3)
  assert.throws(() => buildDistribution({ snapshot: s, snapshotRecord: 'ab'.repeat(32), payouts: payouts.slice(1) }), /no payout/)
  assert.throws(() => buildDistribution({ snapshot: s, snapshotRecord: 'ab'.repeat(32), payouts: [...payouts, payouts[0]] }), /twice/)
  assert.throws(() => buildDistribution({ snapshot: s, snapshotRecord: 'ab'.repeat(32), payouts: [...payouts, { wallet: TREASURY, signature: sig('d') }] }), /not in the snapshot/)
  assert.throws(() => buildDistribution({ snapshot: s, snapshotRecord: 'nope', payouts }), /record hash/)
})
