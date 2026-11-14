#!/usr/bin/env node
// WinLEW airdrop evidence: build the two published artifacts. Pure: reads files, writes one file, no network, no keys.
//
//   node tools/airdrop.mjs snapshot --registry <registry.json> --event <id> --rule "<text>"
//        (--amount-each <raw> | --amounts <wallet→raw.json>) [--exclude <address→label.json>]
//        [--treasury <pubkey>] [--mint <pubkey>] [--decimals 6] [--taken-at <ISO>] --out <file>
//   node tools/airdrop.mjs distribution --snapshot <snapshot.json> --snapshot-record <recordHash>
//        --payouts <payouts.json> --out <file>
//
// The snapshot freezes WHO is paid and HOW MUCH before any token moves; anchoring it on XL1 (tools/evidence.mjs
// anchor --content <file> --claim-type winlew.airdrop.snapshot) timestamps that commitment. The distribution
// lists the Solana transaction signatures that paid it; verifiers check each one against Solana itself.
//
// Registry: a JSON array of wallet strings, or of objects carrying `wallet` or `address` (other fields, such as
// Discord ids, are DROPPED, never copied). Payouts: a JSON array of { wallet, signature }.
// Only Solana wallet addresses are published; they are public on Solscan once paid anyway.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'

export const SNAPSHOT_SCHEMA = 'winlew.airdrop.snapshot.v1'
export const DISTRIBUTION_SCHEMA = 'winlew.airdrop.distribution.v1'
export const WINLEW_MINT = 'DnrcdQVH7fdbmm4EyD7LjT9mNNozF5HuWMeKcpvjpump'
export const BASE58_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/
export const BASE58_SIGNATURE = /^[1-9A-HJ-NP-Za-km-z]{64,90}$/
const RAW = /^(0|[1-9]\d*)$/

class Refused extends Error {}
const refuse = (m) => { throw new Refused(m) }
const byWallet = (a, b) => (a.wallet < b.wallet ? -1 : a.wallet > b.wallet ? 1 : 0)

/** Deterministic snapshot artifact. Throws Refused on anything ambiguous. */
export function buildSnapshot({ registry, event, rule, amountEach, amounts, exclude = {}, treasury = null, mint = WINLEW_MINT, decimals = 6, takenAt }) {
  if (!Array.isArray(registry)) refuse('registry must be a JSON array')
  if (!event || !/^[a-z0-9-]{3,80}$/.test(event)) refuse('event must be a short id (a-z, 0-9, -)')
  if (!rule || typeof rule !== 'string') refuse('rule text is required (the published eligibility and amount rule)')
  if ((amountEach == null) === (amounts == null)) refuse('give exactly one of --amount-each or --amounts')
  if (amountEach != null && !RAW.test(String(amountEach))) refuse('amount-each must be a non-negative integer in base units')
  if (!BASE58_ADDRESS.test(mint)) refuse('mint is not a Solana address')
  if (treasury != null && !BASE58_ADDRESS.test(treasury)) refuse('treasury is not a Solana address')
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) refuse('decimals must be an integer 0..18')
  if (!takenAt || Number.isNaN(Date.parse(takenAt))) refuse('taken-at must be an ISO time')
  const seen = new Map(), excluded = [], invalid = []
  for (const entry of registry) {
    const w = typeof entry === 'string' ? entry : entry && typeof entry === 'object' ? (entry.wallet ?? entry.address) : null
    const wallet = typeof w === 'string' ? w.trim() : null
    if (!wallet || !BASE58_ADDRESS.test(wallet)) { invalid.push(1); continue }
    if (exclude[wallet] != null || wallet === treasury) { if (!excluded.some((e) => e.wallet === wallet)) excluded.push({ wallet, reason: exclude[wallet] ?? 'the airdrop treasury' }); continue }
    seen.set(wallet, (seen.get(wallet) ?? 0) + 1)
  }
  const recipients = [...seen.keys()].map((wallet) => {
    const a = amountEach != null ? String(amountEach) : amounts[wallet]
    if (a == null) refuse(`no amount for registered wallet ${wallet}`)
    if (!RAW.test(String(a))) refuse(`amount for ${wallet} is not a non-negative integer in base units`)
    return { wallet, amountRaw: String(a) }
  }).filter((r) => r.amountRaw !== '0').sort(byWallet)
  if (amounts) for (const w of Object.keys(amounts)) if (!seen.has(w)) refuse(`--amounts names ${w}, which is not an eligible registered wallet`)
  const total = recipients.reduce((s, r) => s + BigInt(r.amountRaw), 0n)
  return {
    schema: SNAPSHOT_SCHEMA,
    event,
    takenAt: new Date(Date.parse(takenAt)).toISOString(),
    source: 'WinLEW airdrop registry (wallets registered with !register), cleaned: duplicates merged, invalid entries and project addresses left out',
    rule,
    token: { network: 'solana:mainnet', mint, decimals },
    treasury,
    recipients,
    excluded: excluded.sort(byWallet),
    totals: { recipients: recipients.length, amountRaw: total.toString(), duplicatesMerged: [...seen.values()].reduce((s, n) => s + n - 1, 0), invalidEntries: invalid.length },
  }
}

/** Distribution artifact: every snapshot recipient paid exactly once, by a listed Solana signature. */
export function buildDistribution({ snapshot, snapshotRecord, payouts }) {
  if (snapshot?.schema !== SNAPSHOT_SCHEMA) refuse('not a winlew.airdrop.snapshot.v1 artifact')
  if (!/^[0-9a-f]{64}$/.test(snapshotRecord ?? '')) refuse('snapshot-record must be the anchored snapshot record hash (64 hex)')
  if (!Array.isArray(payouts)) refuse('payouts must be a JSON array of { wallet, signature }')
  const want = new Map(snapshot.recipients.map((r) => [r.wallet, r.amountRaw]))
  const paid = new Map()
  for (const p of payouts) {
    if (!p || !BASE58_ADDRESS.test(p.wallet ?? '') || !BASE58_SIGNATURE.test(p.signature ?? '')) refuse(`malformed payout ${JSON.stringify(p)}`)
    if (!want.has(p.wallet)) refuse(`payout to ${p.wallet}, who is not in the snapshot`)
    if (paid.has(p.wallet)) refuse(`${p.wallet} appears twice in the payouts`)
    paid.set(p.wallet, p.signature)
  }
  const unpaid = [...want.keys()].filter((w) => !paid.has(w))
  if (unpaid.length) refuse(`${unpaid.length} snapshot recipient(s) have no payout, e.g. ${unpaid[0]}`)
  const transfers = snapshot.recipients.map((r) => ({ wallet: r.wallet, amountRaw: r.amountRaw, signature: paid.get(r.wallet) }))
  return {
    schema: DISTRIBUTION_SCHEMA,
    event: snapshot.event,
    snapshot: { record: snapshotRecord, recipients: snapshot.totals.recipients, amountRaw: snapshot.totals.amountRaw },
    token: snapshot.token,
    treasury: snapshot.treasury,
    transfers,
    totals: { transfers: transfers.length, signatures: new Set(transfers.map((t) => t.signature)).size, amountRaw: snapshot.totals.amountRaw },
  }
}

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())
if (isMain) {
  const args = process.argv.slice(2), cmd = args[0]
  const opt = (k) => { const i = args.indexOf(`--${k}`); return i > 0 ? args[i + 1] : undefined }
  const json = (k) => (opt(k) ? JSON.parse(readFileSync(opt(k), 'utf8')) : undefined)
  try {
    let artifact
    if (cmd === 'snapshot') {
      artifact = buildSnapshot({ registry: json('registry'), event: opt('event'), rule: opt('rule'), amountEach: opt('amount-each'), amounts: json('amounts'),
        exclude: json('exclude') ?? {}, treasury: opt('treasury') ?? null, mint: opt('mint') ?? WINLEW_MINT, decimals: Number(opt('decimals') ?? 6), takenAt: opt('taken-at') ?? new Date().toISOString() })
    } else if (cmd === 'distribution') {
      artifact = buildDistribution({ snapshot: json('snapshot'), snapshotRecord: opt('snapshot-record'), payouts: json('payouts') })
    } else refuse('usage: airdrop.mjs snapshot|distribution … (see the header)')
    const out = opt('out') ?? refuse('--out <file> is required')
    if (existsSync(out)) refuse(`${out} exists; an artifact is never overwritten`)
    writeFileSync(out, `${JSON.stringify(artifact, null, 2)}\n`)
    const t = artifact.totals
    console.log(`${artifact.schema} → ${out}: ${t.recipients ?? t.transfers} ${cmd === 'snapshot' ? 'recipients' : 'transfers'}, ${t.amountRaw} base units${artifact.excluded ? `, ${artifact.excluded.length} excluded` : ''}`)
  } catch (e) {
    console.error(e instanceof Refused ? `refused: ${e.message}` : e)
    process.exit(2)
  }
}
