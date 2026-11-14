// Pinned GitHub sources for evidence records (Sprint 008): the shape Record A uses. The record names a
// repository, a full 40-character commit and a path; the bytes are read from that commit, and their length
// and SHA-256 are checked before anything is built. A branch, tag or short SHA is refused: it can move,
// so it is not provenance.
import { createHash } from 'node:crypto'

const OWNER_REPO = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/
const COMMIT = /^[0-9a-f]{40}$/
const PATH = /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*$/

export class SourceError extends Error {}

/** Validates { repo, commit, path }. `repo` is owner/name or https://github.com/owner/name. */
export function parsePinned({ repo, commit, path } = {}) {
  const r = String(repo ?? '').trim().replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, '').replace(/\/$/, '')
  if (!OWNER_REPO.test(r) || r.split('/').some((p) => p === '.' || p === '..')) throw new SourceError(`not a GitHub owner/repository: ${repo}`)
  const c = String(commit ?? '').trim()
  if (!COMMIT.test(c)) {
    throw new SourceError(`--source-commit must be a full 40-character lowercase commit SHA, not "${commit}": a branch name, tag or short SHA can change or collide, so it is not immutable provenance`)
  }
  const p = String(path ?? '').trim()
  if (!PATH.test(p) || p.split('/').some((s) => s === '.' || s === '..')) throw new SourceError(`not a safe repository path: ${path}`)
  return { repository: `https://github.com/${r}`, commit: c, path: p, url: `https://raw.githubusercontent.com/${r}/${c}/${p}` }
}

/**
 * Reads the exact bytes at the pinned commit. Throws unless they arrive, are JSON, and match any expected
 * length and SHA-256. `fetchFn` is injectable for offline tests.
 */
export async function fetchPinned(spec, { fetchFn = fetch, expectSha256, expectBytes, localBytes } = {}) {
  let res
  try { res = await fetchFn(spec.url, { redirect: 'error' }) } catch (e) { throw new SourceError(`could not read ${spec.url}: ${e?.message ?? e}`) }
  if (!res.ok) throw new SourceError(`${spec.url} answered HTTP ${res.status}`)
  const bytes = Buffer.from(await res.arrayBuffer())
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  if (expectSha256 !== undefined && String(expectSha256).toLowerCase() !== sha256) throw new SourceError(`SHA-256 mismatch: expected ${expectSha256}, the commit serves ${sha256}`)
  if (expectBytes !== undefined && Number(expectBytes) !== bytes.length) throw new SourceError(`length mismatch: expected ${expectBytes} bytes, the commit serves ${bytes.length}`)
  if (localBytes !== undefined && !Buffer.from(localBytes).equals(bytes)) throw new SourceError('the local --content file differs from the bytes at the pinned commit')
  if (!bytes.length) throw new SourceError('the pinned file is empty')
  try { JSON.parse(bytes.toString('utf8')) } catch { throw new SourceError('the pinned file is not JSON') }
  return { bytes, sha256 }
}

/** The record's `source` and `content` fields for a pinned source, in Record A's exact shape. */
export function pinnedFields(spec, fetched, publisher = "xl1-publisher (the producer's own public status feed)") {
  return {
    source: { url: spec.url, repository: spec.repository, commit: spec.commit, path: spec.path, publisher },
    content: { mediaType: 'application/json', algorithm: 'sha256', canonicalization: 'none — the exact bytes served at source.url', sha256: fetched.sha256, bytes: fetched.bytes.length },
  }
}
