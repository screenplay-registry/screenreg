/**
 * CLI-flow tests for `screenreg finalize` (alias `upgrade`).
 *
 * These stay HERMETIC — no network. The pending → confirmed path needs live
 * calendars and is covered exhaustively by the engine unit tests
 * (test/shared/finalize/finalize.test.ts) with an injected fetch. Here we pin the
 * CLI wiring: arg parsing, exit codes, in-place vs --out writing, the `upgrade`
 * alias, and graceful error handling. The idempotent path (an already-confirmed
 * proof) short-circuits before any calendar call, so it exercises the full
 * command without touching the network.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'

import { encodeVarUint } from '../../src/shared/anchors/ots-build.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const CLI_PATH = join(REPO_ROOT, 'src', 'cli', 'main.ts')
const TSX = join(REPO_ROOT, 'node_modules', '.bin', 'tsx')

function runCli(args: string[]): { code: number; stdout: string; stderr: string } {
  const r = spawnSync(TSX, [CLI_PATH, ...args], { encoding: 'utf8', env: { ...process.env } })
  return { code: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' }
}

const HEADER_MAGIC = [
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]
const TAG_BITCOIN = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]

/** A minimal already-confirmed proof: a Bitcoin attestation directly on the file digest. */
function confirmedOts(height: number): Uint8Array {
  const digest = new Uint8Array(32).fill(0xcd)
  const payload = encodeVarUint(height)
  const att = [0x00, ...TAG_BITCOIN, ...encodeVarUint(payload.length), ...payload]
  return new Uint8Array([...HEADER_MAGIC, 1, 0x08, ...digest, ...att])
}

describe('CLI: finalize', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-finalize-cli-'))
  })

  it('finalizes an already-confirmed proof in place and exits 0 (no network)', () => {
    const otsPath = join(tmp, 'a.proof.ots')
    writeFileSync(otsPath, Buffer.from(confirmedOts(875_432)))
    const r = runCli(['finalize', otsPath])
    expect(r.code).toBe(0)
    expect(r.stderr).toMatch(/Confirmed on Bitcoin/)
    expect(r.stderr).toMatch(/875432/)
    // The file is still a valid, Bitcoin-bearing proof after the (idempotent) write.
    expect(existsSync(otsPath)).toBe(true)
  })

  it('writes to --out without touching the input', () => {
    const otsPath = join(tmp, 'b.proof.ots')
    const outPath = join(tmp, 'b.final.ots')
    const original = Buffer.from(confirmedOts(900_001))
    writeFileSync(otsPath, original)
    const r = runCli(['finalize', otsPath, '--out', outPath])
    expect(r.code).toBe(0)
    expect(existsSync(outPath)).toBe(true)
    // Input unchanged; output present.
    expect(readFileSync(otsPath).equals(original)).toBe(true)
  })

  it('the `upgrade` alias behaves identically', () => {
    const otsPath = join(tmp, 'c.proof.ots')
    writeFileSync(otsPath, Buffer.from(confirmedOts(123_456)))
    const r = runCli(['upgrade', otsPath])
    expect(r.code).toBe(0)
    expect(r.stderr).toMatch(/Confirmed on Bitcoin/)
  })

  it('errors (exit 1) on an unreadable / unparseable proof', () => {
    const bad = join(tmp, 'bad.ots')
    writeFileSync(bad, Buffer.from([1, 2, 3, 4]))
    const r = runCli(['finalize', bad])
    expect(r.code).toBe(1)
    expect(r.stderr).toMatch(/finalize:/)
  })

  it('errors on a missing file argument', () => {
    const r = runCli(['finalize'])
    expect(r.code).not.toBe(0)
    expect(r.stderr).toMatch(/need <ots>/)
  })

  it('rejects extra positional args (never silently overwrites)', () => {
    const otsPath = join(tmp, 'e.proof.ots')
    writeFileSync(otsPath, Buffer.from(confirmedOts(7)))
    const r = runCli(['finalize', otsPath, join(tmp, 'second.ots')])
    expect(r.code).not.toBe(0)
    expect(r.stderr).toMatch(/too many arguments/)
  })

  it('rejects an unknown flag', () => {
    const otsPath = join(tmp, 'd.proof.ots')
    writeFileSync(otsPath, Buffer.from(confirmedOts(5)))
    const r = runCli(['finalize', otsPath, '--bogus'])
    expect(r.code).not.toBe(0)
    expect(r.stderr).toMatch(/unexpected argument/)
  })
})
