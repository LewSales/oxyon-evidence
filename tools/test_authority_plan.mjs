// Offline tests for the read-only authority planner: node --test tools/test_authority_plan.mjs
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { BANNER, plan, render } from './authority-plan.mjs'

const A = (c) => c.repeat(40), H = (c) => c.repeat(64)
const IDX = {
  records: [{ record: H('1'), authorization: H('a') }, { record: H('2'), authorization: H('b') }],
  authorizations: [
    { network: 'sequence', authorization: H('a'), issuer: A('4'), delegate: A('e'), validFrom: 0, validUntil: 2000 },
    { network: 'sequence', authorization: H('b'), issuer: A('4'), delegate: A('e'), validFrom: 0, validUntil: 500 },
    { network: 'sequence', authorization: H('c'), issuer: A('5'), delegate: A('6'), validFrom: 0, validUntil: 2000 },
  ],
  revocations: [{ revokes: H('c') }],
}

test('active authorizations with an exposed delegate and issuer are flagged; expired and revoked ones are not active', () => {
  const p = plan(IDX, { exposed: [A('4'), A('E')], now: 1000 })
  const [a, b, c] = p.authorizations
  assert.equal(a.active, true); assert.equal(a.delegateExposed, true); assert.equal(a.issuerExposed, true)
  assert.match(a.risk, /can anchor records that verifiers accept/)
  assert.match(a.revocation, /Only the issuer .* can sign/); assert.match(a.revocation, /issuer is stated as exposed/)
  assert.equal(b.active, false); assert.equal(b.revocation, 'not needed')
  assert.equal(c.revoked, true); assert.equal(c.active, false)
  assert.deepEqual(a.records, [H('1')])
})

test('the planner only states exposure it is told about', () => {
  const p = plan(IDX, { now: 1000 })
  assert.ok(p.authorizations.every((r) => !r.issuerExposed && !r.delegateExposed))
  assert.deepEqual(p.exposedStated, [])
})

test('output is labelled a plan, names the unknowns, and the tool cannot sign, send or read keys', () => {
  const text = render(plan(IDX, { exposed: [A('4')], now: 1000 }))
  assert.ok(text.startsWith(BANNER) && text.endsWith(BANNER))
  assert.match(text, /not an XL1 protocol feature/)
  assert.match(text, /each is a RED decision/)
  const src = readFileSync(new URL('./authority-plan.mjs', import.meta.url), 'utf8')
  for (const banned of ['fetch(', 'signTransaction', 'loadSdk', 'readPhrase', 'askHidden', 'node:child_process', 'writeFileSync', "join(ROOT, 'keys'"]) assert.ok(!src.includes(banned), banned)
  assert.equal((src.match(/readFileSync\(/g) || []).length, 1, 'reads exactly one file: the index')
})

test('runs against the real public index offline', () => {
  const idx = JSON.parse(readFileSync(new URL('../index.json', import.meta.url), 'utf8'))
  const p = plan(idx, { now: Date.parse('2026-11-14T00:00:00Z') })
  assert.ok(p.authorizations.length >= 1)
  assert.ok(p.authorizations.every((r) => r.network && r.issuer && r.delegate))
})
