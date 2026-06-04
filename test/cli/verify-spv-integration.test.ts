/**
 * End-to-end SPV through the real CLI: `verify <bundle> --bitcoin-rpc <url>` against
 * a local mock Bitcoin Core node. Exercises the contract change — a merkle-root
 * MISMATCH fails (exit 2); a match upgrades the verdict to header-confirmed.
 *
 * A Bitcoin-anchored .ots is synthesized: the attestation commits the claim hash
 * itself as the (test) merkle root, so the mock node's `merkleroot` is just the
 * display-order (byte-reversed) claim hash. Real proofs have op chains between the
 * digest and the attestation; the verifier treats the message at the attestation
 * point as the committed root either way, which is exactly what this checks.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { spawn } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import { normalize, contentHashOfNormalized } from '../../src/normalize/v1-strict.js'
import { buildCommittedClaim, buildEnvelope } from '../../src/envelope/build.js'
import { computeClaimHashBytes } from '../../src/envelope/claim-hash.js'
import { buildScreenreg } from '../../src/shared/screenreg/index.js'
import type { Envelope as SharedEnvelope } from '../../src/shared/envelope/types.js'
import {
  HEADER_MAGIC,
  OP_SHA256,
  ATTESTATION_MARKER,
  TAG_BITCOIN_BLOCK_HEADER,
} from '../../src/anchors/ots-verify.js'
import { reverseHexBytes } from '../../src/anchors/bitcoin-spv.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = join(__dirname, '..', '..')
const CLI_PATH = join(REPO_ROOT, 'src', 'cli', 'main.ts')
const TSX = join(REPO_ROOT, 'node_modules', '.bin', 'tsx')

const HEIGHT = 800000
const FAKE_BLOCK_HASH = 'a'.repeat(64)
const SAMPLE = 'Title: SPV\n\nINT. ROOM - DAY\n\nA scene.\n'

function varuint(n: number): Buffer {
  const out: number[] = []
  let v = n
  for (;;) {
    let b = v & 0x7f
    v = Math.floor(v / 128)
    if (v > 0) b |= 0x80
    out.push(b)
    if (v === 0) break
  }
  return Buffer.from(out)
}

/** Build a full .screenreg whose proof is a synthetic Bitcoin attestation at HEIGHT. */
async function buildAnchoredBundle(): Promise<{ bundle: Uint8Array; claimHashHex: string }> {
  const norm = normalize(Buffer.from(SAMPLE, 'utf8'))
  if (!norm.ok) throw new Error('normalize failed')
  const contentHash = contentHashOfNormalized(norm.normalized)
  const claim = buildCommittedClaim({ contentHash })
  const claimHashBytes = Buffer.from(computeClaimHashBytes(claim))
  const claimHashHex = claimHashBytes.toString('hex')

  // magic + v1 + sha256 file-op + digest + bitcoin attestation (no ops → committed root == digest).
  const attPayload = varuint(HEIGHT)
  const otsBytes = Buffer.concat([
    HEADER_MAGIC,
    varuint(1),
    Buffer.from([OP_SHA256]),
    claimHashBytes,
    Buffer.from([ATTESTATION_MARKER]),
    TAG_BITCOIN_BLOCK_HEADER,
    varuint(attPayload.length),
    attPayload,
  ])

  const envelope = buildEnvelope(claim, {
    proofs: [{ type: 'opentimestamps', claimHash: `sha256:${claimHashHex}`, proofRef: 'proof.ots' }],
  })
  const bundle = await buildScreenreg({
    envelope: envelope as unknown as SharedEnvelope,
    otsBytes: new Uint8Array(otsBytes),
    sourceText: new Uint8Array(norm.normalized),
  })
  return { bundle, claimHashHex }
}

/** Mock Bitcoin Core: getblockhash → FAKE_BLOCK_HASH, getblockheader → the given merkleroot. */
function startMockNode(merkleRootDisplay: string): Promise<{ server: Server; url: string }> {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let body = ''
      req.on('data', (c) => (body += c))
      req.on('end', () => {
        const { method } = JSON.parse(body) as { method: string }
        const result =
          method === 'getblockhash'
            ? FAKE_BLOCK_HASH
            : { merkleroot: merkleRootDisplay, hash: FAKE_BLOCK_HASH, height: HEIGHT, time: 1700000000 }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ result, error: null }))
      })
    })
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      resolve({ server, url: `http://127.0.0.1:${port}` })
    })
  })
}

// Async spawn (NOT spawnSync): the mock node runs in this same process, so the
// event loop must stay free to serve the CLI's requests while it runs.
function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(TSX, [CLI_PATH, ...args], { env: { ...process.env } })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (c) => (stdout += c))
    child.stderr.on('data', (c) => (stderr += c))
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }))
  })
}

describe('verify --bitcoin-rpc end-to-end SPV (mock node)', () => {
  let tmp: string
  let bundlePath: string
  let claimHashHex: string
  let server: Server | undefined

  beforeEach(async () => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-spv-'))
    bundlePath = join(tmp, 'draft.screenreg')
    const built = await buildAnchoredBundle()
    claimHashHex = built.claimHashHex
    writeFileSync(bundlePath, Buffer.from(built.bundle))
  })
  afterEach(() => {
    server?.close()
    server = undefined
    try {
      rmSync(tmp, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  })

  it('CONFIRMS when the node header merkle root matches the attestation', async () => {
    const started = await startMockNode(reverseHexBytes(claimHashHex)) // display = reverse(internal)
    server = started.server
    const v = await runCli(['verify', bundlePath, '--bitcoin-rpc', started.url])
    expect(v.code).toBe(0)
    expect(v.stdout).toMatch(/merkle root CONFIRMED/)
    expect(v.stdout).toMatch(new RegExp(`block ${HEIGHT}`, 'i'))
    expect(v.stdout).toMatch(/trustless/)
  })

  it('FAILS (exit 2) when the node header merkle root does not match', async () => {
    const started = await startMockNode('f'.repeat(64))
    server = started.server
    const v = await runCli(['verify', bundlePath, '--bitcoin-rpc', started.url])
    expect(v.code).toBe(2)
    expect(v.stdout).toMatch(/does NOT match Bitcoin/)
  })
})
