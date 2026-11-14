// Signature check with XYO's own published SDK (npm @xyo-network/sdk-protocol), not Oxyon code.
// Run it inside your clone of this repository after `npm i @xyo-network/sdk-protocol@7.4.2`.
// Boundary: it checks the signatures of ONE transaction exactly as the RPC returns it. That this transaction is
// the anchored one (its hash, chain, commitments, block) is checked by verify_evidence.py, not here; block
// signatures are checked only by the browser verifier.
import { BoundWitnessValidator } from '@xyo-network/sdk-protocol/boundwitness-validator'
import '@xyo-network/sdk-protocol/account' // registers the secp256k1 verifier
const [rpcUrl, txHash] = process.argv.slice(2)
const body = { jsonrpc: '2.0', id: 1, method: 'transactionViewer_byHash', params: [txHash] }
const [tx] = (await (await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json()).result
const strip = (o) => Object.fromEntries(Object.entries(o).filter(([k]) => !k.startsWith('_')))
const errors = (await new BoundWitnessValidator(strip(tx)).validate()).map(String)
console.log(errors.length ? `INVALID: ${errors.join('; ')}` : `signature valid for ${tx.addresses[0]}`)
