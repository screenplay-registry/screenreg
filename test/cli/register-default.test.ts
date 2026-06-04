/**
 * CLI: `register` defaults to a single .screenreg (S-C), `--loose` keeps the separate files, and
 * `finalize` accepts a .screenreg. Runs the real CLI in mock mode (no network).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const CLI_PATH = join(REPO_ROOT, 'src', 'cli', 'main.ts')
const TSX = join(REPO_ROOT, 'node_modules', '.bin', 'tsx')

function runCli(args: string[]): { code: number; stdout: string; stderr: string } {
  const r = spawnSync(TSX, [CLI_PATH, ...args], { encoding: 'utf8', env: { ...process.env } })
  return { code: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' }
}

const SAMPLE = `Title: Default Bundle

INT. ROOM - DAY

A scene.

INT. HALL - NIGHT

Another scene.
`

describe('CLI: register default = single .screenreg (S-C)', () => {
  let tmp: string
  let script: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-regdef-'))
    script = join(tmp, 'draft.fountain')
    writeFileSync(script, SAMPLE)
  })
  afterEach(() => {
    try {
      rmSync(tmp, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  })

  it('produces ONE .screenreg by default (no loose manifest/.ots)', () => {
    const reg = runCli(['register', script, '--mock'])
    expect(reg.code).toBe(0)
    expect(reg.stderr).toMatch(/Bundle:/)
    expect(existsSync(join(tmp, 'draft.screenreg'))).toBe(true)
    expect(existsSync(`${script}.manifest.json`)).toBe(false)
    expect(existsSync(`${script}.proof.ots`)).toBe(false)
  })

  it('the default .screenreg is a complete full bundle (unpack verifies)', () => {
    runCli(['register', script, '--mock'])
    const unpack = runCli(['unpack', join(tmp, 'draft.screenreg')])
    expect(unpack.code).toBe(0)
    expect(unpack.stderr).toMatch(/full bundle/)
    expect(unpack.stderr).toMatch(/integrity: OK/)
  })

  it('--loose keeps the separate manifest + .ots (and writes no bundle)', () => {
    const reg = runCli(['register', script, '--mock', '--loose'])
    expect(reg.code).toBe(0)
    expect(existsSync(`${script}.manifest.json`)).toBe(true)
    expect(existsSync(`${script}.proof.ots`)).toBe(true)
    expect(existsSync(join(tmp, 'draft.screenreg'))).toBe(false)
  })

  it('finalize accepts the .screenreg and reports still-pending on a mock proof (exit 3)', () => {
    runCli(['register', script, '--mock'])
    const fin = runCli(['finalize', join(tmp, 'draft.screenreg')])
    expect(fin.code).toBe(3)
    expect(fin.stderr).toMatch(/[Ss]till pending/)
  })

  it('finalize errors clearly on a missing .screenreg (no crash)', () => {
    const fin = runCli(['finalize', join(tmp, 'does-not-exist.screenreg')])
    expect(fin.code).not.toBe(0)
    expect(fin.stderr).toMatch(/cannot read|not a \.screenreg|finalize/)
  })

  it('finalize --watch polls until --max-checks, then gives up (exit 3)', () => {
    runCli(['register', script, '--mock'])
    const fin = runCli([
      'finalize',
      join(tmp, 'draft.screenreg'),
      '--watch',
      '--interval',
      '1',
      '--max-checks',
      '2',
      '--timeout-ms',
      '1000',
    ])
    expect(fin.code).toBe(3)
    expect(fin.stderr).toMatch(/Still pending after 2 checks/)
  })

  it('finalize rejects --interval / --max-checks without --watch', () => {
    runCli(['register', script, '--mock'])
    const fin = runCli(['finalize', join(tmp, 'draft.screenreg'), '--interval', '5'])
    expect(fin.code).not.toBe(0)
    expect(fin.stderr).toMatch(/only apply with --watch/)
  })

  it('--evidence writes BOTH the full bundle and a proof-only twin', () => {
    const reg = runCli(['register', script, '--mock', '--evidence'])
    expect(reg.code).toBe(0)
    expect(reg.stderr).toMatch(/Shareable:/)
    const full = join(tmp, 'draft.screenreg')
    const evidence = join(tmp, 'draft.evidence.screenreg')
    expect(existsSync(full)).toBe(true)
    expect(existsSync(evidence)).toBe(true)
    // The full bundle verifies with contents; the twin verifies date-only.
    const vFull = runCli(['verify', full])
    expect(vFull.code).toBe(0)
    expect(vFull.stdout).not.toMatch(/DATE ONLY/)
    const vEvidence = runCli(['verify', evidence])
    expect(vEvidence.code).toBe(0)
    expect(vEvidence.stdout).toMatch(/DATE ONLY/)
  })

  it('--evidence is rejected together with --loose, and writes NOTHING', () => {
    // The incompatibility is rejected before stamping or any sidecar/key write, so
    // a bad invocation must not leave a private comparison bundle or .pem on disk.
    const reg = runCli(['register', script, '--mock', '--evidence', '--loose', '--identity'])
    expect(reg.code).not.toBe(0)
    expect(reg.stderr).toMatch(/incompatible/)
    expect(existsSync(join(tmp, 'draft.screenreg'))).toBe(false)
    expect(existsSync(join(tmp, 'draft.evidence.screenreg'))).toBe(false)
    expect(existsSync(`${script}.comparison-bundle.private.json`)).toBe(false)
    expect(existsSync(`${script}.private-key.pem`)).toBe(false)
    expect(existsSync(`${script}.manifest.json`)).toBe(false)
    expect(existsSync(`${script}.proof.ots`)).toBe(false)
  })

  it('--envelope-out implies loose mode (no .screenreg written)', () => {
    const envOut = join(tmp, 'out.manifest.json')
    const otsOut = join(tmp, 'out.proof.ots')
    const reg = runCli(['register', script, '--mock', '--envelope-out', envOut, '--ots-out', otsOut])
    expect(reg.code).toBe(0)
    expect(existsSync(envOut)).toBe(true)
    expect(existsSync(otsOut)).toBe(true)
    expect(existsSync(join(tmp, 'draft.screenreg'))).toBe(false)
  })

  it('--identity writes the private key as a separate .pem, never inside the .screenreg', () => {
    const keyOut = join(tmp, 'key.pem')
    const reg = runCli(['register', script, '--mock', '--identity', '--identity-key-out', keyOut])
    expect(reg.code).toBe(0)
    expect(existsSync(keyOut)).toBe(true)
    const pem = readFileSync(keyOut)
    const bundle = readFileSync(join(tmp, 'draft.screenreg'))
    // The bundle must not embed the PEM private key, by header or by raw bytes.
    expect(bundle.includes(Buffer.from('PRIVATE KEY'))).toBe(false)
    expect(bundle.includes(pem)).toBe(false)
  })
})
