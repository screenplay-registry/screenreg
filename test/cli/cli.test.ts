/**
 * End-to-end CLI tests exercising the register → verify → diagnose pipeline
 * via the actual CLI binary in mock mode (no network).
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync, appendFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const CLI_PATH = join(REPO_ROOT, 'src', 'cli', 'main.ts')
const TSX = join(REPO_ROOT, 'node_modules', '.bin', 'tsx')

function runCli(args: string[], env: Record<string, string> = {}): { code: number; stdout: string; stderr: string } {
  const result = spawnSync(TSX, [CLI_PATH, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  })
  return {
    code: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  }
}

const SAMPLE_FOUNTAIN = `INT. CAFE - DAY

A bustling cafe at lunch.

A WAITER (50s, weary) approaches.

WAITER
Coffee?

CUSTOMER
Black, please.

EXT. STREET - LATER

The customer walks out into the rain.
`

describe('CLI: register + verify (mock mode, no network)', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-cli-test-'))
  })

  it('register produces envelope + .ots; verify confirms', () => {
    const scriptPath = join(tmp, 'script.fountain')
    writeFileSync(scriptPath, SAMPLE_FOUNTAIN)

    const register = runCli(['register', scriptPath, '--mock'])
    expect(register.code).toBe(0)
    expect(register.stderr).toMatch(/Registration complete/)

    const envelopePath = `${scriptPath}.manifest.json`
    const otsPath = `${scriptPath}.proof.ots`
    expect(existsSync(envelopePath)).toBe(true)
    expect(existsSync(otsPath)).toBe(true)

    const envelope = JSON.parse(readFileSync(envelopePath, 'utf8'))
    expect(envelope.envelopeVersion).toBe('urn:screenplay-registration-envelope:v1')
    expect(envelope.committedClaim.claimVersion).toBe('urn:screenplay-registration-claim:v1')
    expect(envelope.committedClaim.sceneTreeRoot).toBeDefined()
    expect(envelope.committedClaim.sceneCount).toBe(2)

    const verify = runCli(['verify', scriptPath, envelopePath, otsPath])
    expect(verify.code).toBe(0)
    // Mock-OTS placeholder = pending attestation; headline reads "⚠ VERIFIED (PENDING)".
    // The claim hash MATCHES (so verify exits 0), but the proof has not been
    // upgraded to a Bitcoin block attestation yet.
    expect(verify.stdout).toMatch(/VERIFIED \(PENDING\)/)
  })

  it('verify with --require-bitcoin-anchor exits 2 on a pending mock proof', () => {
    const scriptPath = join(tmp, 'script.fountain')
    const envelopePath = join(tmp, 'script.fountain.manifest.json')
    const otsPath = join(tmp, 'script.fountain.proof.ots')
    writeFileSync(
      scriptPath,
      'Title: Test\n\nINT. KITCHEN - DAY\n\nA scene.\n\nINT. BEDROOM - NIGHT\n\nAnother scene.\n',
    )
    const register = runCli(['register', '--mock', scriptPath])
    expect(register.code).toBe(0)
    const verify = runCli(['verify', '--require-bitcoin-anchor', scriptPath, envelopePath, otsPath])
    expect(verify.code).toBe(2)
    expect(verify.stdout).toMatch(/--require-bitcoin-anchor/)
  })

  it('verify FAILS for a tampered file', () => {
    const scriptPath = join(tmp, 'script.fountain')
    writeFileSync(scriptPath, SAMPLE_FOUNTAIN)
    const register = runCli(['register', scriptPath, '--mock'])
    expect(register.code).toBe(0)

    // Tamper
    appendFileSync(scriptPath, '\nEXTRA EDIT\n')

    const verify = runCli(['verify', scriptPath, `${scriptPath}.manifest.json`, `${scriptPath}.proof.ots`])
    expect(verify.code).toBe(2)
    expect(verify.stdout).toMatch(/✗ FAILED/)
    expect(verify.stdout).toMatch(/content hash mismatch/)
  })

  it('diagnose reports honest transform analysis on the candidate file', () => {
    const scriptPath = join(tmp, 'script.fountain')
    // Write with CRLF line endings + BOM to trigger normalization transforms
    const withCrlfAndBom = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from(SAMPLE_FOUNTAIN.replace(/\n/g, '\r\n'), 'utf8'),
    ])
    writeFileSync(scriptPath, withCrlfAndBom)

    const diagnose = runCli(['diagnose', scriptPath])
    expect(diagnose.code).toBe(0)
    expect(diagnose.stdout).toMatch(/stripped-bom/)
    expect(diagnose.stdout).toMatch(/crlf-to-lf/)
    expect(diagnose.stdout).toMatch(/Content hash:/)
  })

  it('diagnose with manifest reports MISMATCH for an edited file', () => {
    const scriptPath = join(tmp, 'script.fountain')
    writeFileSync(scriptPath, SAMPLE_FOUNTAIN)
    const register = runCli(['register', scriptPath, '--mock'])
    expect(register.code).toBe(0)

    appendFileSync(scriptPath, '\nEXTRA\n')

    const diagnose = runCli(['diagnose', scriptPath, `${scriptPath}.manifest.json`])
    expect(diagnose.code).toBe(0)
    expect(diagnose.stdout).toMatch(/✗ MISMATCH/)
    expect(diagnose.stdout).toMatch(/Probable causes/)
    expect(diagnose.stdout).toMatch(/protocol stores ONLY the hash/)
  })
})

describe('CLI: encrypted fields', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-cli-test-'))
  })

  it('register with encrypted title; decrypt-field returns the original', () => {
    const scriptPath = join(tmp, 'script.fountain')
    writeFileSync(scriptPath, SAMPLE_FOUNTAIN)

    const register = runCli(
      ['register', scriptPath, '--mock', '--encrypt-title', 'My Great Movie'],
      { SCREENREG_PASSWORD: 'hunter2' },
    )
    expect(register.code).toBe(0)

    const decrypt = runCli(
      ['decrypt-field', `${scriptPath}.manifest.json`, 'title'],
      { SCREENREG_PASSWORD: 'hunter2' },
    )
    expect(decrypt.code).toBe(0)
    expect(decrypt.stdout.trim()).toBe('My Great Movie')
  })

  it('decrypt-field with wrong password fails', () => {
    const scriptPath = join(tmp, 'script.fountain')
    writeFileSync(scriptPath, SAMPLE_FOUNTAIN)
    runCli(['register', scriptPath, '--mock', '--encrypt-title', 'Secret'], { SCREENREG_PASSWORD: 'right' })

    const decrypt = runCli(['decrypt-field', `${scriptPath}.manifest.json`, 'title'], {
      SCREENREG_PASSWORD: 'wrong',
    })
    expect(decrypt.code).not.toBe(0)
    expect(decrypt.stderr).toMatch(/decryption failed/i)
  })
})

describe('CLI: scene-prove + scene-verify', () => {
  let tmp: string

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-cli-test-'))
  })

  it('scene-prove generates a proof; scene-verify confirms it', () => {
    const scriptPath = join(tmp, 'script.fountain')
    writeFileSync(scriptPath, SAMPLE_FOUNTAIN)
    runCli(['register', scriptPath, '--mock'])

    const proveResult = runCli(['scene-prove', scriptPath, `${scriptPath}.manifest.json`, '0'])
    expect(proveResult.code).toBe(0)
    const proof = JSON.parse(proveResult.stdout)
    expect(proof.sceneTreeProfile).toBe('screenplay-registration-merkle/v1')
    expect(proof.sceneIndex).toBe(0)
    expect(proof.sceneCount).toBe(2)

    const envelope = JSON.parse(readFileSync(`${scriptPath}.manifest.json`, 'utf8'))
    const proofPath = join(tmp, 'scene-0.proof.json')
    writeFileSync(proofPath, JSON.stringify(proof))

    const verifyResult = runCli([
      'scene-verify',
      envelope.committedClaim.sceneTreeRoot,
      proof.sceneBytes,
      proofPath,
    ])
    expect(verifyResult.code).toBe(0)
    expect(verifyResult.stdout).toMatch(/✓ scene proof verifies/)
  })
})
