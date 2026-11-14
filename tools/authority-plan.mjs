#!/usr/bin/env node
// Read-only authority-transition planner (Sprint 009). PLAN — NOT AUTHORIZATION.
//
//   node tools/authority-plan.mjs [--index index.json] [--exposed <addr,addr>] [--now <ms>] [--json]
//
// Reads ONLY the public evidence index (this repository's index.json by default). It never reads a key file,
// never asks for or derives a phrase, never builds, signs or sends a transaction, and makes no network call.
// `--exposed` lists addresses the owner states are compromised; the planner does not decide that itself.
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const BANNER = 'PLAN — NOT AUTHORIZATION. NO TRANSACTION HAS BEEN CONSTRUCTED OR SENT.'
const HEX40 = /^[0-9a-f]{40}$/
const iso = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : 'unknown')

/** Pure. index: the public evidence index; exposed: addresses stated as compromised; now: ms. */
export function plan(index, { exposed = [], now = Date.now() } = {}) {
  const bad = new Set(exposed.map((a) => String(a).toLowerCase()))
  const revoked = new Set((index?.revocations ?? []).map((r) => r?.revokes ?? r?.authorization).filter(Boolean))
  const auths = (index?.authorizations ?? []).filter((a) => a && HEX40.test(a.issuer ?? '') && HEX40.test(a.delegate ?? ''))
  const records = index?.records ?? []
  const rows = auths.map((a) => {
    const active = !revoked.has(a.authorization) && Number.isFinite(a.validUntil) && now < a.validUntil
    const issuerExposed = bad.has(a.issuer), delegateExposed = bad.has(a.delegate)
    const recs = records.filter((r) => r?.authorization === a.authorization)
    return {
      network: a.network, authorization: a.authorization, issuer: a.issuer, delegate: a.delegate,
      validFrom: iso(a.validFrom), validUntil: iso(a.validUntil), revoked: revoked.has(a.authorization), active,
      issuerExposed, delegateExposed, records: recs.map((r) => r.record),
      risk: active && (issuerExposed || delegateExposed)
        ? `Until ${iso(a.validUntil)} (or a revocation), whoever holds the exposed ${delegateExposed ? 'delegate' : 'issuer'} key can anchor records that verifiers accept under this authorization.`
        : active ? 'Active; no stated exposure.' : 'Not active (expired or revoked); records anchored while it was active keep verifying.',
      revocation: !active ? 'not needed'
        : `Only the issuer ${a.issuer} can sign an oxyon.evidence.revocation.v1 for it (on ${a.network}).${issuerExposed ? ' The issuer is stated as exposed, so revoking also uses exposed authority; an attacker holding it could revoke or re-authorize too.' : ''}`,
    }
  })
  const identities = [...new Set(auths.map((a) => a.issuer))]
  const unknowns = [
    'Revocation is an Oxyon evidence convention, checked by both verifiers (a revocation bound witness from the issuer, between authorization and anchor). It is not an XL1 protocol feature; XL1 itself cannot invalidate an authorization.',
    'Whether an exposed key has been used by anyone else is not known from public data. The index lists only the records Oxyon published.',
    'No revoke command exists in tools/evidence.mjs; constructing a revocation is out of scope for this planner.',
  ]
  const steps = [
    'Owner decides: new identity and new delegate from a fresh phrase (recommended when the issuer is exposed), or a new delegate only.',
    'Publish the new identity through channels the old key does not control: oxyon.io (a page on the evidence site) and a reviewed commit to this repository. A statement signed by the exposed identity alone is not a sufficient binding.',
    'Owner signs, offline, the new authorization(s) with the new identity (tools/evidence.mjs authorize, hidden prompt, dry run first).',
    'Revoke or let expire the active authorizations listed above. Revoking needs the old issuer (see each row).',
    'Keep historical records as they are: they keep verifying, and pages label their issuer as historical, not current authority.',
    'Update the publication points: README, VERIFY.md examples, /evidence/keys/, index.json.',
  ]
  return { banner: BANNER, identities, authorizations: rows, unknowns, steps, exposedStated: [...bad] }
}

export function render(p) {
  const out = [p.banner, '', `Identities (issuers) in the index: ${p.identities.join(', ') || 'none'}`, `Stated exposed: ${p.exposedStated.join(', ') || 'none stated'}`, '']
  for (const r of p.authorizations) {
    out.push(`- ${r.network} authorization ${r.authorization.slice(0, 16)}…  issuer ${r.issuer.slice(0, 8)}…${r.issuerExposed ? ' (EXPOSED)' : ''} → delegate ${r.delegate.slice(0, 8)}…${r.delegateExposed ? ' (EXPOSED)' : ''}`,
      `    valid ${r.validFrom} → ${r.validUntil} · ${r.revoked ? 'revoked' : r.active ? 'ACTIVE' : 'not active'} · records: ${r.records.length}`,
      `    risk: ${r.risk}`, `    revocation: ${r.revocation}`)
  }
  out.push('', 'Unknown or out of scope:', ...p.unknowns.map((u) => `  - ${u}`), '', 'Owner-operated steps (each is a RED decision; nothing here performs them):', ...p.steps.map((s, i) => `  ${i + 1}. ${s}`), '', p.banner)
  return out.join('\n')
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2)
  const opt = (n) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : undefined }
  const indexPath = opt('index') ?? join(dirname(fileURLToPath(import.meta.url)), '..', 'index.json')
  const p = plan(JSON.parse(readFileSync(indexPath, 'utf8')), { exposed: (opt('exposed') ?? '').split(',').filter(Boolean), now: Number(opt('now') ?? Date.now()) })
  console.log(args.includes('--json') ? JSON.stringify(p, null, 2) : render(p))
}
