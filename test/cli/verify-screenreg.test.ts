/**
 * CLI ↔ browser parity: `verify <file.screenreg>` verifies a single bundle the
 * same way the /verify/ page does. A FULL bundle confirms contents from the
 * embedded screenplay; a proof-only (.evidence.screenreg) bundle is date-only
 * unless the screenplay is also supplied. Runs the real CLI in mock mode.
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

const SAMPLE = `Title: Parity Check

INT. ROOM - DAY

A scene.

INT. HALL - NIGHT

Another scene.
`

describe('CLI: verify <file.screenreg> (browser parity)', () => {
  let tmp: string
  let script: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-verifybundle-'))
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

  // A FULL bundle embeds the screenplay → verify confirms the contents (no DATE
  // ONLY tag). Mock proofs are calendar-pending, so the headline is PENDING.
  it('verifies a full .screenreg with contents (not date-only)', () => {
    runCli(['register', script, '--mock'])
    const v = runCli(['verify', join(tmp, 'draft.screenreg')])
    expect(v.code).toBe(0)
    expect(v.stdout).toMatch(/VERIFIED \(PENDING\)/)
    expect(v.stdout).not.toMatch(/DATE ONLY/)
    expect(v.stdout).toMatch(/Content hash:/)
    expect(v.stdout).toMatch(/Claim hash:/)
  })

  // A proof-only bundle has no embedded screenplay → date-only verification.
  it('verifies a proof-only .evidence.screenreg as DATE ONLY', () => {
    runCli(['register', script, '--mock', '--loose'])
    const pack = runCli([
      'pack',
      `${script}.manifest.json`,
      '--ots',
      `${script}.proof.ots`,
      '--evidence',
    ])
    expect(pack.code).toBe(0)
    // pack strips the .manifest.json suffix from the base → draft.fountain.evidence.screenreg
    const evidencePath = `${script}.evidence.screenreg`
    expect(existsSync(evidencePath)).toBe(true)
    const v = runCli(['verify', evidencePath])
    expect(v.code).toBe(0)
    expect(v.stdout).toMatch(/VERIFIED \(PENDING, DATE ONLY\)/)
    expect(v.stdout).toMatch(/contents were NOT checked/)
  })

  it('confirms contents when the screenplay is supplied alongside a proof-only bundle', () => {
    runCli(['register', script, '--mock', '--loose'])
    runCli(['pack', `${script}.manifest.json`, '--ots', `${script}.proof.ots`, '--evidence'])
    const evidencePath = `${script}.evidence.screenreg`
    const v = runCli(['verify', evidencePath, script])
    expect(v.code).toBe(0)
    expect(v.stdout).not.toMatch(/DATE ONLY/)
    expect(v.stdout).toMatch(/VERIFIED \(PENDING\)/)
  })

  it('FAILS when a supplied screenplay does not match a proof-only bundle', () => {
    runCli(['register', script, '--mock', '--loose'])
    runCli(['pack', `${script}.manifest.json`, '--ots', `${script}.proof.ots`, '--evidence'])
    const evidencePath = `${script}.evidence.screenreg`
    const wrong = join(tmp, 'wrong.fountain')
    writeFileSync(wrong, SAMPLE + '\nAn extra line that changes the hash.\n')
    const v = runCli(['verify', evidencePath, wrong])
    expect(v.code).toBe(2)
    expect(v.stdout).toMatch(/content hash mismatch/)
  })

  it('FAILS when a wrong screenplay is supplied alongside a FULL bundle (no silent ignore)', () => {
    // An explicitly supplied screenplay must always be checked — even when the
    // bundle embeds its own source. Ignoring it would be a false accept.
    runCli(['register', script, '--mock'])
    const wrong = join(tmp, 'wrong.fountain')
    writeFileSync(wrong, SAMPLE + '\nAn extra line that changes the hash.\n')
    const v = runCli(['verify', join(tmp, 'draft.screenreg'), wrong])
    expect(v.code).toBe(2)
    expect(v.stdout).toMatch(/content hash mismatch/)
  })

  it('--require-bitcoin-anchor exits 2 on a pending bundle', () => {
    runCli(['register', script, '--mock'])
    const v = runCli(['verify', join(tmp, 'draft.screenreg'), '--require-bitcoin-anchor'])
    expect(v.code).toBe(2)
    expect(v.stdout).toMatch(/require-bitcoin-anchor/)
  })

  it('a corrupted .screenreg never verifies as OK', () => {
    runCli(['register', script, '--mock'])
    const bundlePath = join(tmp, 'draft.screenreg')
    const bytes = readFileSync(bundlePath)
    // Flip a byte in the back half (payload/central-directory region) to corrupt
    // an entry without necessarily breaking the outer ZIP framing.
    const idx = Math.floor(bytes.length * 0.6)
    bytes[idx] = bytes[idx]! ^ 0xff
    writeFileSync(bundlePath, bytes)
    const v = runCli(['verify', bundlePath])
    expect(v.code).not.toBe(0)
  })

  // Loose 3-file verification must still work for integrators.
  it('still verifies the loose 3-file artifacts', () => {
    runCli(['register', script, '--mock', '--loose'])
    const v = runCli(['verify', script, `${script}.manifest.json`, `${script}.proof.ots`])
    expect(v.code).toBe(0)
    expect(v.stdout).toMatch(/VERIFIED \(PENDING\)/)
    expect(v.stdout).not.toMatch(/DATE ONLY/)
  })
})
