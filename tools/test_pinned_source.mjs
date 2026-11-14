// Offline tests for pinned GitHub sources (Sprint 008): node --test tools/test_pinned_source.mjs
// No network (fetch is a fixture), no key, no signing.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { cpSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SourceError, fetchPinned, parsePinned, pinnedFields } from './pinned-source.mjs'

const C = '6024841612e1026b90a3a7d98c3c2957ba0cb838'
const BYTES = Buffer.from('{"label":"windows","chain":{"network":"sequence"}}')
const SHA = createHash('sha256').update(BYTES).digest('hex')
const serve = (body = BYTES, status = 200) => async () => new Response(body, { status })

test('a full commit, owner/repo and safe path give Record A-shaped fields', async () => {
  const spec = parsePinned({ repo: 'https://github.com/LewSales/xl1-status-data', commit: C, path: 'windows.json' })
  assert.equal(spec.url, `https://raw.githubusercontent.com/LewSales/xl1-status-data/${C}/windows.json`)
  const f = await fetchPinned(spec, { fetchFn: serve(), expectSha256: SHA, expectBytes: BYTES.length })
  const { source, content } = pinnedFields(spec, f)
  assert.deepEqual(Object.keys(source), ['url', 'repository', 'commit', 'path', 'publisher'])
  assert.equal(source.commit, C); assert.equal(content.sha256, SHA); assert.equal(content.bytes, BYTES.length)
  assert.equal(content.canonicalization, 'none — the exact bytes served at source.url')
})

test('mutable or ambiguous references are refused', () => {
  for (const commit of ['main', 'master', 'v1.0.0', 'HEAD', C.slice(0, 7), C.toUpperCase(), C + '0', '', undefined]) {
    assert.throws(() => parsePinned({ repo: 'LewSales/xl1-status-data', commit, path: 'windows.json' }), SourceError, String(commit))
  }
})

test('unsafe repositories and paths are refused', () => {
  for (const repo of ['LewSales', 'a/b/c', '../x/y', 'https://evil.example/a/b', 'a/..']) assert.throws(() => parsePinned({ repo, commit: C, path: 'f.json' }), SourceError, repo)
  for (const path of ['../keys/x.json', '/etc/passwd', 'a/../b', 'a b.json', 'dir/', '']) assert.throws(() => parsePinned({ repo: 'a/b', commit: C, path }), SourceError, path)
})

test('the bytes must match the expected SHA-256, length and local copy, and be JSON', async () => {
  const spec = parsePinned({ repo: 'a/b', commit: C, path: 'f.json' })
  await assert.rejects(fetchPinned(spec, { fetchFn: serve(), expectSha256: 'f'.repeat(64) }), /SHA-256 mismatch/)
  await assert.rejects(fetchPinned(spec, { fetchFn: serve(), expectBytes: 1 }), /length mismatch/)
  await assert.rejects(fetchPinned(spec, { fetchFn: serve(), localBytes: Buffer.from('{}') }), /differs from the bytes/)
  await assert.rejects(fetchPinned(spec, { fetchFn: serve('not json') }), /not JSON/)
  await assert.rejects(fetchPinned(spec, { fetchFn: serve('') }), /empty/)
  await assert.rejects(fetchPinned(spec, { fetchFn: serve('nope', 404) }), /HTTP 404/)
  await assert.rejects(fetchPinned(spec, { fetchFn: async () => { throw new TypeError('offline') } }), /could not read/)
  const ok = await fetchPinned(spec, { fetchFn: serve(), localBytes: BYTES })
  assert.equal(ok.sha256, SHA)
})

// The CLI in --preview: no key, no SDK, no signing, nothing written. Run in a scratch copy with a synthetic
// authorization (never the repository's keys/), and an archived --content, so no network is needed.
test('anchor --preview builds an archived record without a key and writes nothing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'oxy-tool-'))
  try {
    mkdirSync(join(dir, 'tools')); mkdirSync(join(dir, 'keys/sequence/authorizations'), { recursive: true })
    for (const f of ['evidence.mjs', 'pinned-source.mjs']) cpSync(fileURLToPath(new URL(f, import.meta.url)), join(dir, 'tools', f))
    const auth = { authorization: { issuer: 'a'.repeat(40), delegate: 'b'.repeat(40), validFrom: 0, validUntil: 4102444800000,
      scope: { claims: ['xl1.producer.telemetry'], network: { id: 'sequence', chainId: '4b43a753c8024c0e5000e8ac948ac0063ac624bc' } } } }
    writeFileSync(join(dir, 'keys/sequence/authorizations', 'f'.repeat(64) + '.json'), JSON.stringify(auth))
    writeFileSync(join(dir, 'content.json'), BYTES)
    const out = execFileSync(process.execPath, [join(dir, 'tools/evidence.mjs'), 'anchor', '--preview', '--authorization', 'f'.repeat(64),
      '--content', join(dir, 'content.json'), '--claim-type', 'xl1.producer.telemetry', '--statement', 'test'], { encoding: 'utf8' })
    assert.match(out, /preview: no key read, nothing signed, broadcast or written/)
    assert.ok(out.includes(`"sha256": "${SHA}"`)); assert.ok(out.includes('"kind": "archived"'))
    const ls = execFileSync(process.execPath, ['-e', `console.log(require('fs').readdirSync(${JSON.stringify(dir)}).sort().join(','))`], { encoding: 'utf8' }).trim()
    assert.equal(ls, 'content.json,keys,tools', 'nothing written: no blobs/, records/ or index.json')
    assert.throws(() => execFileSync(process.execPath, [join(dir, 'tools/evidence.mjs'), 'anchor', '--preview', '--send', '--authorization', 'f'.repeat(64)], { stdio: 'pipe' }), /cannot be combined/)
    assert.throws(() => execFileSync(process.execPath, [join(dir, 'tools/evidence.mjs'), 'anchor', '--preview', '--authorization', 'f'.repeat(64),
      '--source-repo', 'LewSales/xl1-status-data', '--source-commit', 'main', '--source-path', 'windows.json', '--claim-type', 'xl1.producer.telemetry', '--statement', 's'], { stdio: 'pipe' }), /full 40-character/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
