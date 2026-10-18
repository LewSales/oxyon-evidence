#!/usr/bin/env node
// Oxyon evidence tooling: make a key, authorise it, anchor a record. MIT, like verify/.
//
// Writes exactly the files verify/verify_evidence.py checks, in the same shapes as the first
// record (2026-10-09), and builds each transaction the way the verifier expects it:
// one elevated network.xyo.hash payload, the object itself referenced by its hash.
//
//   node tools/evidence.mjs new-key   --out <file>
//   node tools/evidence.mjs address   --key-file <file>          (the address to fund; no phrase shown)
//
// Anywhere a key file is asked for, `prompt` may be given instead: the phrase is then typed
// at a hidden prompt, used in memory, and never written anywhere -- the way Oxyon's keys are
// kept off disk.
//   node tools/evidence.mjs authorize --issuer-file <file> --delegate <address> --claims <a,b>
//                                     [--network sequence] [--until 2027-01-31] [--send]
//   node tools/evidence.mjs anchor    --key-file <file> --authorization <hash> --content <file.json>
//                                     --claim-type <type> --statement "<text>" [--subject <json>]
//                                     [--observed-at <ms>] [--send]
//
// Without --send nothing is broadcast: the transaction is built and signed, its hash and
// fee are printed, and no file is written. Key files hold a recovery phrase -- either the
// phrase alone or NAME="phrase" on one line. They are read here and never printed.
//
// XL1_SDK_MODULE may point at @xyo-network/xl1-sdk's dist/neutral/index.mjs (absolute);
// by default the copy installed for GeoHackers in this workspace is used.
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const NETS = {
  sequence: { rpc: 'https://beta.api.chain.xyo.network/rpc', chainId: '4b43a753c8024c0e5000e8ac948ac0063ac624bc', name: 'XL1 Sequence' },
  mainnet: { rpc: 'https://api.chain.xyo.network/rpc', chainId: '319e667ced10452a117472811130444ded357f26', name: 'XL1 Mainnet' },
}
const OXYON_PRODUCERS = new Set(['ca08120874f071739d932b24da41cc13299123b3', '2152e6aec996742fb6e52ae1aad87bd44f2ccc91', 'a9304753eade52dd22b1a6fc519b571a4dc2653e'])
const DEFAULT_SDK = resolve(ROOT, '..', 'Geohackers', 'node_modules', '@xyo-network', 'xl1-sdk', 'dist', 'neutral', 'index.mjs')

// ── hashing: Evidence spec v1 §1.2, identical to xyo_hash() in verify_evidence.py ──
export function xyoHash(obj, { data = false } = {}) {
  const deep = (v) => Array.isArray(v) ? v.map(deep)
    : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, deep(v[k])])) : v
  const top = Object.fromEntries(Object.entries(obj).filter(([k]) => !k.startsWith('_') && !(data && k.startsWith('$'))))
  return createHash('sha256').update(JSON.stringify(deep(top)), 'utf8').digest('hex')
}

// ── arguments ──
const [cmd, ...rest] = process.argv.slice(2)
const opt = (name, fallback) => { const i = rest.indexOf(`--${name}`); return i >= 0 ? rest[i + 1] : fallback }
const flag = (name) => rest.includes(`--${name}`)
const need = (name) => { const v = opt(name); if (!v) die(`--${name} is required`); return v }
function die(msg) { console.error(`✗ ${msg}`); process.exit(2) }
const addr = (v) => { const a = String(v ?? '').toLowerCase().replace(/^0x/, ''); if (!/^[0-9a-f]{40}$/.test(a)) die(`not an address: ${v}`); return a }

// ── keys ──
/** Ask for a recovery phrase on the terminal with nothing echoed. It lives in memory only. */
function askHidden(question) {
  if (!process.stdin.isTTY) die('a phrase prompt needs a terminal; run this command yourself in PowerShell or a terminal window')
  return new Promise((done) => {
    process.stdout.write(question)
    const stdin = process.stdin
    let typed = ''
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8')
    const onKey = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\u0003') { process.stdout.write('\n'); process.exit(130) }                      // Ctrl+C
        if (ch === '\r' || ch === '\n' || ch === '\u0004') {
          stdin.setRawMode(false); stdin.pause(); stdin.off('data', onKey); process.stdout.write('\n'); done(typed); return
        }
        if (ch === '\u0008' || ch === '\u007f') { typed = typed.slice(0, -1); continue }             // Backspace
        typed += ch
      }
    }
    stdin.on('data', onKey)
  })
}

async function readPhrase(file) {
  if (file === 'prompt') return checkPhrase(await askHidden('Recovery phrase (typing is hidden, nothing is saved): '), 'the phrase you typed')
  const text = readFileSync(file, 'utf8')
  const m = text.match(/^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*["']([^"'\r\n]+)["']\s*;?\s*$/m)
  return checkPhrase(m ? m[1] : text, file)
}
function checkPhrase(raw, where) {
  const phrase = String(raw).trim().toLowerCase().replace(/\s+/g, ' ')
  if (![12, 15, 18, 21, 24].includes(phrase.split(' ').length)) die(`${where} is not a 12–24 word recovery phrase`)
  return phrase
}
const sdkPath = () => resolve(process.env.XL1_SDK_MODULE || DEFAULT_SDK)
/** The node_modules folder the SDK was installed into, for its own dependencies (bip39). */
const nodeModules = () => resolve(dirname(sdkPath()), '..', '..', '..', '..')
async function loadSdk() {
  if (!existsSync(sdkPath())) die(`XL1 SDK not found at ${sdkPath()}; set XL1_SDK_MODULE`)
  return import(pathToFileURL(sdkPath()).href)
}
async function accountFrom(sdk, file) {
  const base = await sdk.generateXyoBaseWalletFromPhrase(await readPhrase(file))
  return base.derivePath('0')
}

// ── chain ──
async function rpc(net, method, params) {
  const res = await fetch(NETS[net].rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params }) })
  const body = await res.json()
  if (body.error) throw new Error(`${method}: ${body.error.message}`)
  return body.result
}
/** The address's balance through the SDK's own viewer (XYO's RPC has no plain balance method). */
async function balanceAtto(tx) {
  try { const g = await tx.gateway(); return BigInt(await g.connection.viewer.account.balance.accountBalance(tx.from)) } catch { return null }
}
const xl1 = (atto) => { const s = String(atto).padStart(19, '0'); return `${s.slice(0, -18)}.${s.slice(-18, -12)}` }

/** Build and sign one evidence transaction: `elevated` goes on chain as network.xyo.hash of
 *  `hashOf`; `referenced` objects are committed by hash only. Returns the signed pair. */
async function buildTx(sdk, account, net, hashOf, referenced) {
  const { chainId } = NETS[net]
  const head = (await rpc(net, 'xyoViewer_currentBlock', []))[0]
  if (String(head.chain).toLowerCase().replace(/^0x/, '') !== chainId) die(`RPC for ${net} reports chain ${head.chain}, not ${chainId}`)
  const nbf = head.block, exp = nbf + 10
  const elevated = { schema: 'network.xyo.hash', hash: hashOf }
  const signer = await sdk.buildSimpleXyoSignerV2({ config: sdk.ConfigZod.parse({}), caches: {}, singletons: {} }, account)
  const from = addr(account.address)
  const build = (fees) => sdk.buildUnsignedTransaction(chainId, [elevated], referenced, nbf, exp, from, fees)
  const estimate = await signer.signTransaction(await build())
  const gas = BigInt(sdk.transactionRequiredGas(estimate))
  const gasLimit = gas + gas / 5n + 1000n > 10_000_000_000n ? gas + gas / 5n + 1000n : 10_000_000_000n
  const signed = await signer.signTransaction(await build({ ...sdk.defaultTransactionFees, gasLimit }))
  const bw = signed[0]
  // The checks the verifier will make, made before anything is sent.
  const elevatedHash = xyoHash(elevated)
  const ok = bw._hash === xyoHash(bw) && [hashOf, elevatedHash, ...referenced.map((r) => xyoHash(r))].every((h) => bw.payload_hashes.includes(h))
    && (bw.script ?? []).includes(`elevate|${elevatedHash}`) && addr(bw.addresses[0]) === from && bw.chain === chainId
  if (!ok) die('the signed transaction does not have the shape the verifier checks; nothing sent')
  const hex = (v) => BigInt(`0x${String(v ?? '0').replace(/^0x/, '') || '0'}`)
  const maxFee = hex(bw.fees.base) + hex(bw.fees.priority) + hex(bw.fees.gasLimit) * hex(bw.fees.gasPrice)
  return { signed, hash: bw._hash, from, nbf, exp, maxFee, signer, gateway: () => new sdk.GatewayBuilder().name(net).rpcUrl(NETS[net].rpc).build(signer) }
}

/** Broadcast, then wait for the block that holds it -- found the way the verifier finds it. */
async function sendAndLocate(net, tx) {
  const gateway = await tx.gateway()
  const [sent] = await gateway.addTransactionToChain(tx.signed)
  if (String(sent) !== tx.hash) die(`broadcast returned ${sent}, expected ${tx.hash}`)
  console.log(`  broadcast ${tx.hash}; waiting for its block…`)
  const cdn = `https://blocks.${net}.xyo.space/block/number`
  for (let tries = 0; tries < 60; tries++) {
    await new Promise((r) => setTimeout(r, 5000))
    const found = await rpc(net, 'transactionViewer_byHash', [tx.hash]).catch(() => null)
    if (!found) continue
    for (let n = found[0].nbf; n <= found[0].exp; n++) {
      const res = await fetch(`${cdn}/${n}.json`).catch(() => null)
      if (!res?.ok) continue
      const [block, payloads] = await res.json()
      if (!block.payload_hashes.includes(tx.hash)) continue
      const clock = payloads.find((p) => p.schema === 'network.xyo.time')
      return { block: block.block, blockHash: block._hash, blockTime: clock?.epoch, blockProducer: block.addresses[0] }
    }
  }
  die(`${tx.hash} was broadcast but not found in a block within 5 minutes; check the explorer before retrying`)
}

function receiptFor(kind, fields, net, tx, where) {
  const own = OXYON_PRODUCERS.has(where.blockProducer)
  return {
    schema: 'oxyon.evidence.receipt.v1', kind, ...fields, network: net, chainId: NETS[net].chainId,
    tx: tx.hash, signer: tx.from, block: where.block, blockHash: where.blockHash, blockTime: where.blockTime, blockProducer: where.blockProducer,
    ...(own ? { inclusionNote: `Included in a block produced by ${where.blockProducer.slice(0, 4)}…${where.blockProducer.slice(-4)}, a producer operated by Oxyon. Inclusion is not verification: the commitment is checked against signatures and hashes, not against who produced the block.` } : {}),
    version: 1,
  }
}
const writeJson = (path, obj) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, `${JSON.stringify(obj, null, 2)}\n`, 'utf8') }
function updateIndex(section, entry) {
  const p = join(ROOT, 'index.json')
  const idx = JSON.parse(readFileSync(p, 'utf8'))
  idx[section] = [...(idx[section] ?? []).filter((e) => e[section === 'records' ? 'record' : 'authorization'] !== entry[section === 'records' ? 'record' : 'authorization']), entry]
  writeJson(p, idx)
}
async function showCost(net, tx) {
  const bal = await balanceAtto(tx)
  console.log(`  signed tx ${tx.hash} (valid blocks ${tx.nbf}–${tx.exp})`)
  console.log(`  max fee ${xl1(tx.maxFee)} XL1 · ${tx.from} balance ${bal === null ? 'unknown' : `${xl1(bal)} XL1`}`)
  if (bal !== null && bal < tx.maxFee) console.log(`  ! the balance is below the max fee: fund ${tx.from} on ${NETS[net].name} first`)
}

// ── commands ──
if (cmd === 'new-key') {
  const out = need('out')
  if (existsSync(out)) die(`${out} exists; refusing to overwrite a key`)
  const { generateMnemonic } = await import(pathToFileURL(join(nodeModules(), '@scure', 'bip39', 'index.js')).href)
  const { wordlist } = await import(pathToFileURL(join(nodeModules(), '@scure', 'bip39', 'wordlists', 'english.js')).href)
  const phrase = generateMnemonic(wordlist, 256)
  mkdirSync(dirname(resolve(out)), { recursive: true })
  writeFileSync(out, `OXYON_ANCHOR_PHRASE="${phrase}"\n`, { encoding: 'utf8', mode: 0o600 })
  const sdk = await loadSdk()
  const account = await accountFrom(sdk, out)
  console.log(`✓ new anchoring key written to ${resolve(out)} (keep it offline; it is not printed)`)
  console.log(`  address ${addr(account.address)}`)
  process.exit(0)
}

if (cmd === 'address') {
  const sdk = await loadSdk()
  console.log(addr((await accountFrom(sdk, need('key-file'))).address))
  process.exit(0)
}

if (cmd === 'authorize') {
  const net = opt('network', 'sequence'); if (!NETS[net]) die(`unknown network ${net}`)
  const sdk = await loadSdk()
  const issuer = await accountFrom(sdk, need('issuer-file'))
  const delegate = addr(need('delegate'))
  const claims = need('claims').split(',').map((c) => c.trim()).filter(Boolean)
  const day = (d) => Date.parse(`${d}T00:00:00Z`)
  const from = opt('from') ? day(opt('from')) : day(new Date().toISOString().slice(0, 10))
  const until = day(opt('until', new Date(from + 92 * 86_400_000).toISOString().slice(0, 10)))
  if (!(until > from)) die('--until must be after the start')
  const iso = (t) => new Date(t).toISOString().replace(':00.000Z', 'Z')
  const authorization = {
    schema: 'oxyon.evidence.authorization.v1', issuer: addr(issuer.address), delegate, role: 'anchorer',
    scope: { claims, recordSchema: 'oxyon.evidence.record.v1', network: { id: net, chainId: NETS[net].chainId } },
    validFrom: from, validUntil: until,
    statement: `Oxyon, identified on XL1 by address ${addr(issuer.address)}, authorises address ${delegate} to anchor Oxyon evidence records of type ${claims.join(', ')} on ${NETS[net].name} (chain ${NETS[net].chainId}) from ${iso(from)} until ${iso(until)}, unless revoked earlier.`,
    doesNotAuthorise: 'Anything else: speaking for Oxyon on other matters, moving Oxyon funds, issuing further authorisations, or anchoring on any other network.',
    revocation: "An oxyon.evidence.revocation.v1 record whose revokes field is this record's hash, signed by the issuer and committed on the same network. It takes effect at its own block and does not invalidate records anchored before it.",
    version: 1,
  }
  const hash = xyoHash(authorization)
  console.log(`authorization ${hash}`)
  console.log(`  ${authorization.statement}`)
  const tx = await buildTx(sdk, issuer, net, hash, [authorization])
  await showCost(net, tx)
  if (!flag('send')) { console.log('  dry run: nothing broadcast, nothing written (add --send)'); process.exit(0) }
  const where = await sendAndLocate(net, tx)
  const receipt = receiptFor('authorization', { authorization: hash }, net, tx, where)
  const file = join(ROOT, 'keys', net, 'authorizations', `${hash}.json`)
  writeJson(file, { authorization, receipt })
  updateIndex('authorizations', { network: net, authorization: hash, issuer: authorization.issuer, delegate, validFrom: from, validUntil: until, tx: tx.hash, block: where.block, path: file.slice(ROOT.length + 1).replace(/\\/g, '/') })
  console.log(`✓ on chain in block ${where.block}; wrote ${file.slice(ROOT.length + 1)}`)
  process.exit(0)
}

if (cmd === 'anchor') {
  const sdk = await loadSdk()
  const key = await accountFrom(sdk, need('key-file'))
  const authHash = need('authorization')
  const authFile = Object.keys(NETS).map((n) => join(ROOT, 'keys', n, 'authorizations', `${authHash}.json`)).find(existsSync)
  if (!authFile) die(`no authorization ${authHash} in keys/; run authorize --send first`)
  const { authorization } = JSON.parse(readFileSync(authFile, 'utf8'))
  const net = authorization.scope.network.id
  const claimType = need('claim-type')
  if (!authorization.scope.claims.includes(claimType)) die(`authorization ${authHash.slice(0, 12)}… does not cover ${claimType}`)
  if (addr(key.address) !== authorization.delegate) die(`the key file is ${addr(key.address)}, but the authorization names ${authorization.delegate}`)
  const bytes = readFileSync(need('content'))
  JSON.parse(bytes.toString('utf8')) // content must be JSON
  const sha = createHash('sha256').update(bytes).digest('hex')
  const now = Date.now()
  if (now < authorization.validFrom || now >= authorization.validUntil) die('now is outside the authorization window')
  const record = {
    schema: 'oxyon.evidence.record.v1',
    claim: { type: claimType, statement: need('statement') },
    subject: { kind: claimType.split('.').slice(0, 2).join('-'), network: net, chainId: NETS[net].chainId, ...(opt('subject') ? JSON.parse(opt('subject')) : {}) },
    source: { kind: 'archived', path: `blobs/sha256/${sha.slice(0, 2)}/${sha}.json`, publisher: 'the issuer; the archived copy is the only source' },
    content: { mediaType: 'application/json', algorithm: 'sha256', canonicalization: 'none — the exact bytes of the archived copy', sha256: sha, bytes: bytes.length },
    observedAt: Number(opt('observed-at', now)), issuedAt: now,
    issuer: authorization.issuer, anchoredBy: authorization.delegate, authorization: authHash,
    establishes: 'That these exact bytes existed, unchanged, no later than the block that anchors this record, under the authorization it cites.',
    doesNotEstablish: 'That the activity they describe happened as described, or was fair. A commitment proves integrity and timing, not truth.',
    version: 1,
  }
  const recordHash = xyoHash(record)
  const batch = { schema: 'oxyon.geoproof.anchor.batch.v1', proofHashes: [recordHash], network: `xl1:${net}:${NETS[net].chainId}`, anchoredAt: now }
  const batchHash = xyoHash(batch)
  console.log(`record ${recordHash} · batch ${batchHash}`)
  const tx = await buildTx(sdk, key, net, batchHash, [record, batch])
  await showCost(net, tx)
  if (!flag('send')) { console.log('  dry run: nothing broadcast, nothing written (add --send)'); process.exit(0) }
  const where = await sendAndLocate(net, tx)
  // The archive holds the exact bytes that were hashed, never a reformatted copy.
  mkdirSync(dirname(join(ROOT, record.source.path)), { recursive: true })
  writeFileSync(join(ROOT, record.source.path), bytes)
  const receipt = receiptFor('anchor', { record: recordHash, batch: batchHash, authorization: authHash }, net, tx, where)
  const d = new Date(where.blockTime ?? now)
  const rel = `records/${net}/${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}/${String(d.getUTCDate()).padStart(2, '0')}/${String(d.getUTCHours()).padStart(2, '0')}-${recordHash}.json`
  writeJson(join(ROOT, rel), { record, batch, receipt })
  updateIndex('records', { network: net, chainId: NETS[net].chainId, record: recordHash, batch: batchHash, authorization: authHash, claimType, observedAt: record.observedAt, anchorTx: tx.hash, anchorBlock: where.block, anchorBlockTime: where.blockTime, receipt: xyoHash(receipt), path: rel, contentSha256: sha })
  console.log(`✓ anchored in block ${where.block}; wrote ${rel}`)
  console.log(`  verify: python verify/verify_evidence.py ${rel}`)
  process.exit(0)
}

die('usage: node tools/evidence.mjs new-key | address | authorize | anchor  (see the header of this file)')
