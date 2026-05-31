/**
 * CLI-flow tests for the off-chain registry index:
 *   - `registry-build` builds a record from an envelope (claimHash recomputed;
 *     contentHash forbidden);
 *   - `registry-search` matches by public claimHash / title / author;
 *   - `verify-registry` re-verifies each record's `.ots` per-record only, labels
 *     heights honestly ("OTS-CLAIMED, NOT Bitcoin-final" without an attestation
 *     verifier), enforces strict path-traversal guards on `proofRef`, and REFUSES
 *     to assert a priority ranking when heights are not Bitcoin-final;
 *   - `registry-priority` resolves disputes by Bitcoin block height ONLY.
 *
 * The index is signed/mirrorable, NOT a tamper-proof log. Bitcoin remains the
 * sole time + priority anchor.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, symlinkSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const CLI_PATH = join(REPO_ROOT, 'src', 'cli', 'main.ts')
const TSX = join(REPO_ROOT, 'node_modules', '.bin', 'tsx')

function runCli(args: string[]): { code: number; stdout: string; stderr: string } {
  const result = spawnSync(TSX, [CLI_PATH, ...args], { encoding: 'utf8', env: { ...process.env } })
  return { code: result.status ?? 1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' }
}

const SAMPLE = `INT. CAFE - DAY

A bustling cafe at lunch.

WAITER
Coffee?

EXT. STREET - LATER

Rain.
`

/** Register a script in mock mode; return the script + envelope + ots paths. */
function register(tmp: string, name: string): { scriptPath: string; envelopePath: string; otsPath: string } {
  const scriptPath = join(tmp, name)
  writeFileSync(scriptPath, SAMPLE)
  const reg = runCli(['register', scriptPath, '--mock'])
  expect(reg.code).toBe(0)
  return {
    scriptPath,
    envelopePath: `${scriptPath}.manifest.json`,
    otsPath: `${scriptPath}.proof.ots`,
  }
}

describe('CLI: registry-build + registry-search', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-reg-cli-'))
  })

  it('builds a record from an envelope; contentHash never appears', () => {
    const { envelopePath } = register(tmp, 'a.fountain')
    const recPath = join(tmp, 'a.record.json')
    const build = runCli([
      'registry-build',
      envelopePath,
      '--title', 'THE LAST REWRITE',
      '--proof-ref', 'a.fountain.proof.ots',
      '--out', recPath,
    ])
    expect(build.code).toBe(0)
    const record = JSON.parse(readFileSync(recPath, 'utf8'))
    expect(record.registryRecordVersion).toBe('urn:screenplay-registration-registry-record:v1')
    expect(record.title).toBe('THE LAST REWRITE')
    expect(record.anchors.opentimestamps.proofRef).toBe('a.fountain.proof.ots')
    // The script fingerprint must never be published in the index.
    expect(JSON.stringify(record)).not.toMatch(/contentHash/)
    // claimHash is the envelope's committedClaimHash, recomputed.
    const env = JSON.parse(readFileSync(envelopePath, 'utf8'))
    expect(record.claimHash).toBe(env.evidenceBundle.committedClaimHash)
  })

  it('searches by title and by claimHash', () => {
    const { envelopePath } = register(tmp, 'b.fountain')
    const recPath = join(tmp, 'b.record.json')
    runCli([
      'registry-build', envelopePath,
      '--title', 'NEON DUSK',
      '--proof-ref', 'b.fountain.proof.ots',
      '--out', recPath,
    ])
    const record = JSON.parse(readFileSync(recPath, 'utf8'))
    const snapshotPath = join(tmp, 'snapshot.json')
    writeFileSync(snapshotPath, JSON.stringify({ records: [record] }, null, 2))

    const byTitle = runCli(['registry-search', snapshotPath, '--title', 'neon'])
    expect(byTitle.code).toBe(0)
    expect(byTitle.stdout).toMatch(/NEON DUSK/)

    const byHash = runCli(['registry-search', snapshotPath, '--claim-hash', record.claimHash])
    expect(byHash.code).toBe(0)
    expect(byHash.stdout).toMatch(new RegExp(record.claimHash.slice(0, 20)))

    const noMatch = runCli(['registry-search', snapshotPath, '--title', 'no-such-title'])
    expect(noMatch.code).toBe(1)
  })
})

describe('CLI: verify-registry (per-record .ots; honest finality; path guards)', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-reg-cli-'))
  })

  /** Build a one-record snapshot beside its `.ots`, with a custom proofRef. */
  function buildSnapshot(proofRef: string): { snapshotPath: string; claimHash: string } {
    const { envelopePath } = register(tmp, 'c.fountain')
    const recPath = join(tmp, 'c.record.json')
    runCli(['registry-build', envelopePath, '--proof-ref', proofRef, '--out', recPath])
    const record = JSON.parse(readFileSync(recPath, 'utf8'))
    const snapshotPath = join(tmp, 'snapshot.json')
    writeFileSync(snapshotPath, JSON.stringify({ records: [record] }, null, 2))
    return { snapshotPath, claimHash: record.claimHash }
  }

  it('verifies a valid snapshot, labels heights NOT Bitcoin-final, and refuses to rank', () => {
    const { snapshotPath } = buildSnapshot('c.fountain.proof.ots')
    const verify = runCli(['verify-registry', snapshotPath])
    expect(verify.code).toBe(0)
    expect(verify.stdout).toMatch(/structural \.ots OK/)
    expect(verify.stdout).toMatch(/NOT a tamper-proof log/)
    // Mock proof has no Bitcoin heights (pending) → undetermined, no winner.
    expect(verify.stdout).toMatch(/UNDETERMINED/)
    expect(verify.stdout).not.toMatch(/WINNER/)
  })

  it('registry-build rejects a proofRef that traverses out of the snapshot directory', () => {
    const { envelopePath } = register(tmp, 'c.fountain')
    const recPath = join(tmp, 'c.record.json')
    const res = runCli(['registry-build', envelopePath, '--proof-ref', '../escape.ots', '--out', recPath])
    expect(res.code).not.toBe(0)
    expect(res.stderr + res.stdout).toMatch(/proofRef/)
  })

  it('registry-build rejects an absolute proofRef', () => {
    const { envelopePath } = register(tmp, 'c.fountain')
    const recPath = join(tmp, 'c.record.json')
    const res = runCli(['registry-build', envelopePath, '--proof-ref', '/etc/hosts', '--out', recPath])
    expect(res.code).not.toBe(0)
    expect(res.stderr + res.stdout).toMatch(/proofRef/)
  })

  it('rejects a symlinked proofRef', () => {
    const { envelopePath } = register(tmp, 'd.fountain')
    // Create a symlink inside tmp pointing elsewhere; reference it as proofRef.
    const linkName = 'link.ots'
    symlinkSync('/etc/hosts', join(tmp, linkName))
    const recPath = join(tmp, 'd.record.json')
    runCli(['registry-build', envelopePath, '--proof-ref', linkName, '--out', recPath])
    const record = JSON.parse(readFileSync(recPath, 'utf8'))
    const snapshotPath = join(tmp, 'snapshot.json')
    writeFileSync(snapshotPath, JSON.stringify({ records: [record] }, null, 2))

    const verify = runCli(['verify-registry', snapshotPath])
    expect(verify.code).toBe(2)
    expect(verify.stdout).toMatch(/symlink/)
  })
})

describe('CLI: registry-priority (Bitcoin-only)', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-reg-cli-'))
  })

  it('returns UNDETERMINED when heights are not Bitcoin-final', () => {
    const { envelopePath } = register(tmp, 'e.fountain')
    const recPath = join(tmp, 'e.record.json')
    runCli(['registry-build', envelopePath, '--proof-ref', 'e.fountain.proof.ots', '--out', recPath])
    const record = JSON.parse(readFileSync(recPath, 'utf8'))
    const snapshotPath = join(tmp, 'snapshot.json')
    writeFileSync(snapshotPath, JSON.stringify({ records: [record] }, null, 2))

    const priority = runCli(['registry-priority', snapshotPath])
    expect(priority.code).toBe(0)
    expect(priority.stdout).toMatch(/Bitcoin block height ONLY/)
    expect(priority.stdout).toMatch(/UNDETERMINED/)
    expect(priority.stdout).toMatch(/NOT authorship/)
  })
})
