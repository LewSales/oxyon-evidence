// Full transaction check with XYO's own published validator (npm @xyo-network/xl1-protocol),
// including secp256k1 signatures. Hash metadata that arrives with the data (`_hash`,
// `_dataHash`) is dropped and recomputed here first: a verifier only trusts hashes it computed.
//
//   node verify/txcheck.mjs <mainnet|sequence> <txHash>        (asks XYO's public RPC)
//   node verify/txcheck.mjs --file verify/fixtures/tx/<name>.json
//
// Needs Node 26 and, in an empty folder: npm i @xyo-network/xl1-protocol@5.8.10 @xyo-network/sdk@8.1.1
import { readFileSync } from 'node:fs'
import { PayloadBuilder } from '@xyo-network/sdk'
import { validateTransaction } from '@xyo-network/xl1-protocol/validation'

const CHAIN_IDS = { sequence: '4b43a753c8024c0e5000e8ac948ac0063ac624bc', mainnet: '319e667ced10452a117472811130444ded357f26' }
const RPC = { sequence: 'https://beta.api.chain.xyo.network/rpc', mainnet: 'https://api.chain.xyo.network/rpc' }

const args = process.argv.slice(2)
let net, txHash, tx, payloads
if (args[0] === '--file') {
  ({ network: net, txHash, tx, payloads } = JSON.parse(readFileSync(args[1], 'utf8')))
} else {
  [net, txHash] = args
  if (!RPC[net] || !/^[0-9a-f]{64}$/.test(txHash ?? '')) { console.error('usage: node verify/txcheck.mjs <mainnet|sequence> <txHash>'); process.exit(2) }
  const body = { jsonrpc: '2.0', id: 1, method: 'transactionViewer_byHash', params: [txHash] }
  const res = await (await fetch(RPC[net], { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json()
  if (!res.result) { console.log(`NOT FOUND: ${net} has no transaction ${txHash}`); process.exit(1) }
  ;[tx, payloads] = res.result
}

const fresh = async (p) => PayloadBuilder.addHashMeta(PayloadBuilder.omitStorageMeta(p))
const hydrated = [await fresh(tx), await Promise.all(payloads.map(fresh))]
const problems = []
if (hydrated[0]._hash !== txHash) problems.push(`transaction hashes to ${hydrated[0]._hash}, not ${txHash}`)
const errors = await validateTransaction({ chainId: CHAIN_IDS[net], singletons: {}, caches: {} }, hydrated)
problems.push(...errors.map(e => e.message))
console.log(problems.length ? `INVALID: ${problems.join('; ')}` : `valid on ${net}: signed by ${hydrated[0].addresses.join(', ')}`)
process.exit(problems.length ? 1 : 0)
