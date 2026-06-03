/**
 * End-to-end CLI tests for `pack` / `unpack` — zipping a registration into one `.screenreg`
 * and reading it back. Runs the real CLI in mock mode (no network).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync, symlinkSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import { createHash } from 'node:crypto'
import { zipStore } from '../../src/shared/screenreg/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const CLI_PATH = join(REPO_ROOT, 'src', 'cli', 'main.ts')
const TSX = join(REPO_ROOT, 'node_modules', '.bin', 'tsx')

function runCli(args: string[]): { code: number; stdout: string; stderr: string } {
  const r = spawnSync(TSX, [CLI_PATH, ...args], { encoding: 'utf8', env: { ...process.env } })
  return { code: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' }
}

const enc = new TextEncoder()
const FORMAT = 'urn:screenplay-registration-bundle:v1'
const sha = (b: Uint8Array): string => 'sha256:' + createHash('sha256').update(b).digest('hex')

interface CraftPayload {
  name: string
  role: string
  bytes: Uint8Array
}

/**
 * Build a structurally valid evidence .screenreg for adversarial CLI tests, with optional hostile
 * twists: an undeclared physical `extra` entry, or a deliberately wrong declared digest.
 */
function craftEvidenceBundle(
  payload: CraftPayload[],
  opts: { extra?: { name: string; bytes: Uint8Array }[]; badDigestFor?: string } = {},
): Uint8Array {
  const entries = payload
    .map((p) => ({
      path: p.name,
      role: p.role,
      bytes: p.bytes.length,
      sha256: opts.badDigestFor === p.name ? 'sha256:' + '0'.repeat(64) : sha(p.bytes),
    }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  const contents: Record<string, string> = { descriptor: 'screenreg.json' }
  for (const p of payload) {
    if (p.role === 'envelope') contents.envelope = p.name
    else if (p.role === 'ots-proof') contents.otsProof = p.name
    else if (p.role === 'readme') contents.readme = p.name
  }
  const descriptor = { format: FORMAT, bundleType: 'evidence', contents, entries }
  return zipStore([
    { name: 'screenreg.json', bytes: enc.encode(JSON.stringify(descriptor, null, 2) + '\n') },
    ...payload.map((p) => ({ name: p.name, bytes: p.bytes })),
    ...(opts.extra ?? []),
  ])
}

const SAMPLE = `Title: Pack Test

INT. KITCHEN - DAY

A scene.

INT. BEDROOM - NIGHT

Another scene.
`

describe('CLI: pack / unpack .screenreg (mock mode)', () => {
  let tmp: string
  let script: string
  let envelope: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-pack-'))
    script = join(tmp, 'script.fountain')
    envelope = `${script}.manifest.json`
    writeFileSync(script, SAMPLE)
    const reg = runCli(['register', script, '--mock'])
    expect(reg.code).toBe(0)
    expect(existsSync(envelope)).toBe(true)
  })

  afterEach(() => {
    try {
      rmSync(tmp, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  })

  it('packs a full bundle and unpacks it with integrity OK', () => {
    const pack = runCli(['pack', envelope, '--source', script])
    expect(pack.code).toBe(0)
    const bundle = `${script}.screenreg`
    expect(existsSync(bundle)).toBe(true)
    expect(pack.stderr).toMatch(/full bundle/)

    const unpack = runCli(['unpack', bundle])
    expect(unpack.code).toBe(0)
    expect(unpack.stderr).toMatch(/full bundle/)
    expect(unpack.stderr).toMatch(/integrity: OK/)
    const contentsLine = unpack.stderr.split('\n').find((l) => l.includes('contents:')) ?? ''
    expect(contentsLine).toMatch(/script\.fountain/)
  })

  it('packs an evidence (proof-only) bundle without the source text', () => {
    const pack = runCli(['pack', envelope])
    expect(pack.code).toBe(0)
    const bundle = `${script}.evidence.screenreg`
    expect(existsSync(bundle)).toBe(true)
    expect(pack.stderr).toMatch(/proof-only/)

    const unpack = runCli(['unpack', bundle])
    expect(unpack.code).toBe(0)
    expect(unpack.stderr).toMatch(/evidence bundle/)
    // Check the contents listing specifically — the bundle's own path contains "script.fountain".
    const contentsLine = unpack.stderr.split('\n').find((l) => l.includes('contents:')) ?? ''
    expect(contentsLine).not.toMatch(/script\.fountain/)
  })

  it('unpack --out-dir extracts the contained files', () => {
    runCli(['pack', envelope, '--source', script])
    const outDir = join(tmp, 'extracted')
    const unpack = runCli(['unpack', `${script}.screenreg`, '--out-dir', outDir])
    expect(unpack.code).toBe(0)
    for (const f of ['screenreg.json', 'envelope.json', 'proof.ots', 'script.fountain', 'README.txt']) {
      expect(existsSync(join(outDir, f))).toBe(true)
    }
    // The extracted envelope is the same committed claim — bundling changed no commitment bytes.
    const extracted = JSON.parse(readFileSync(join(outDir, 'envelope.json'), 'utf8'))
    const original = JSON.parse(readFileSync(envelope, 'utf8'))
    expect(extracted.committedClaim).toEqual(original.committedClaim)
    expect(extracted.evidenceBundle.committedClaimHash).toBe(original.evidenceBundle.committedClaimHash)
  })

  it('the `open` alias behaves like unpack', () => {
    runCli(['pack', envelope, '--source', script])
    const open = runCli(['open', `${script}.screenreg`])
    expect(open.code).toBe(0)
    expect(open.stderr).toMatch(/integrity: OK/)
  })

  it('refuses to pack a source that does not match the committed contentHash', () => {
    const wrong = join(tmp, 'wrong.fountain')
    writeFileSync(wrong, SAMPLE + '\nEXTRA LINE THAT CHANGES THE HASH\n')
    const pack = runCli(['pack', envelope, '--source', wrong])
    expect(pack.code).not.toBe(0)
    expect(pack.stderr).toMatch(/does not match the envelope's contentHash/)
  })

  it('rejects --evidence together with --source', () => {
    const pack = runCli(['pack', envelope, '--source', script, '--evidence'])
    expect(pack.code).not.toBe(0)
    expect(pack.stderr).toMatch(/mutually exclusive/)
  })

  it('a corrupted .screenreg fails to unpack (non-zero exit)', () => {
    runCli(['pack', envelope, '--source', script])
    const bundle = `${script}.screenreg`
    const bytes = readFileSync(bundle)
    // Flip a byte well inside the archive (past the first local header) to corrupt entry data.
    const mid = Math.floor(bytes.length / 2)
    bytes[mid] = bytes[mid]! ^ 0xff
    writeFileSync(bundle, bytes)
    const unpack = runCli(['unpack', bundle])
    expect(unpack.code).not.toBe(0)
  })

  it('reports a helpful error when the envelope is missing', () => {
    const pack = runCli(['pack', join(tmp, 'does-not-exist.manifest.json')])
    expect(pack.code).not.toBe(0)
    expect(pack.stderr).toMatch(/cannot read envelope/)
  })

  it('pack refuses --out that would overwrite an input', () => {
    const pack = runCli(['pack', envelope, '--out', envelope])
    expect(pack.code).not.toBe(0)
    expect(pack.stderr).toMatch(/would overwrite/)
  })

  it('pack refuses to write through a symlink (no clobber of the link target)', () => {
    const link = join(tmp, 'out.screenreg')
    symlinkSync(envelope, link) // out.screenreg -> the envelope
    const before = readFileSync(envelope)
    const pack = runCli(['pack', envelope, '--out', link])
    expect(pack.code).not.toBe(0)
    expect(pack.stderr).toMatch(/symlink/)
    // The envelope (the link target) is untouched.
    expect(readFileSync(envelope).equals(before)).toBe(true)
  })

  it('unpack rejects a digest-valid bundle whose embedded envelope is malformed', () => {
    const bundle = craftEvidenceBundle([
      { name: 'envelope.json', role: 'envelope', bytes: enc.encode('{}') }, // valid JSON, invalid envelope
      { name: 'proof.ots', role: 'ots-proof', bytes: new Uint8Array([1, 2, 3]) },
      { name: 'README.txt', role: 'readme', bytes: enc.encode('readme') },
    ])
    const p = join(tmp, 'bad-env.screenreg')
    writeFileSync(p, bundle)
    const unpack = runCli(['unpack', p])
    expect(unpack.code).not.toBe(0)
    expect(unpack.stderr).toMatch(/invalid envelope/)
    expect(unpack.stderr).not.toMatch(/Cannot read properties/) // no raw crash
  })

  it('unpack does not extract anything when a declared digest mismatches', () => {
    const realEnv = new Uint8Array(readFileSync(envelope)) // a genuinely valid envelope
    const bundle = craftEvidenceBundle(
      [
        { name: 'envelope.json', role: 'envelope', bytes: realEnv },
        { name: 'proof.ots', role: 'ots-proof', bytes: new Uint8Array([1, 2, 3]) },
        { name: 'README.txt', role: 'readme', bytes: enc.encode('readme') },
      ],
      { badDigestFor: 'envelope.json' }, // valid CRC, wrong declared sha256
    )
    const p = join(tmp, 'tampered.screenreg')
    writeFileSync(p, bundle)
    const outDir = join(tmp, 'out-tampered')
    const unpack = runCli(['unpack', p, '--out-dir', outDir])
    expect(unpack.code).toBe(1)
    expect(unpack.stderr).toMatch(/integrity: FAILED/)
    expect(existsSync(outDir)).toBe(false) // bailed before creating the dir / writing anything
  })

  it('unpack --out-dir extracts only declared entries, ignoring a smuggled extra', () => {
    const realEnv = new Uint8Array(readFileSync(envelope))
    const bundle = craftEvidenceBundle(
      [
        { name: 'envelope.json', role: 'envelope', bytes: realEnv },
        { name: 'proof.ots', role: 'ots-proof', bytes: new Uint8Array([1, 2, 3]) },
        { name: 'README.txt', role: 'readme', bytes: enc.encode('readme') },
      ],
      { extra: [{ name: 'evil.txt', bytes: enc.encode('PWNED') }] }, // not in the descriptor
    )
    const p = join(tmp, 'extra.screenreg')
    writeFileSync(p, bundle)
    const outDir = join(tmp, 'out-extra')
    const unpack = runCli(['unpack', p, '--out-dir', outDir])
    expect(unpack.code).toBe(0)
    expect(existsSync(join(outDir, 'envelope.json'))).toBe(true)
    expect(existsSync(join(outDir, 'evil.txt'))).toBe(false) // smuggled entry never written
  })
})
