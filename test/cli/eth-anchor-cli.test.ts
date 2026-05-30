/**
 * CLI-flow tests for the optional Ethereum-mainnet anchor:
 *   - `attach-eth-anchor` produces a NEW envelope with an additive proof (claim
 *     hash unchanged), re-validated at the integration boundary;
 *   - `verify --eth-rpc` runs the topics-only on-chain check as INFORMATIONAL,
 *     never changing the Bitcoin verdict or the exit status (graceful-degrade on
 *     an unreachable RPC; `verified` against a stub log).
 *
 * The Ethereum anchor is a secondary witness: Bitcoin (via OpenTimestamps)
 * remains the sole time + priority anchor.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { spawnSync, spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
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

The customer walks out into the rain.
`

const CONTRACT = '0x1111111111111111111111111111111111111111'
const REGISTRANT = '0x2222222222222222222222222222222222222222'
const TX_HASH = '0x3333333333333333333333333333333333333333333333333333333333333333'
const LOG_INDEX = 2
const BLOCK_NUMBER = 21345678
const TOPIC0 = '0xd2447c3a89a5ee056ff41d62d513b054faa56c17b9074ead1e0b964a43dcd1e9'

/** Register a script in mock mode and attach an Ethereum anchor; return paths. */
function registerAndAnchor(tmp: string): {
  scriptPath: string
  envelopePath: string
  otsPath: string
  anchoredPath: string
  claimHashHex: string
} {
  const scriptPath = join(tmp, 'script.fountain')
  writeFileSync(scriptPath, SAMPLE)
  const reg = runCli(['register', scriptPath, '--mock'])
  expect(reg.code).toBe(0)
  const envelopePath = `${scriptPath}.manifest.json`
  const otsPath = `${scriptPath}.proof.ots`

  const anchoredPath = join(tmp, 'anchored.json')
  const attach = runCli([
    'attach-eth-anchor',
    envelopePath,
    '--contract', CONTRACT,
    '--registrant', REGISTRANT,
    '--tx-hash', TX_HASH,
    '--log-index', String(LOG_INDEX),
    '--block-number', String(BLOCK_NUMBER),
    '--out', anchoredPath,
  ])
  expect(attach.code).toBe(0)
  const anchored = JSON.parse(readFileSync(anchoredPath, 'utf8'))
  const claimHash: string = anchored.evidenceBundle.committedClaimHash
  return {
    scriptPath,
    envelopePath,
    otsPath,
    anchoredPath,
    claimHashHex: claimHash.slice('sha256:'.length),
  }
}

describe('CLI: attach-eth-anchor', () => {
  let tmp: string
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-eth-cli-'))
  })

  it('attaches an additive ethereum-anchor proof without changing the claim hash', () => {
    const { envelopePath, anchoredPath } = registerAndAnchor(tmp)
    const original = JSON.parse(readFileSync(envelopePath, 'utf8'))
    const anchored = JSON.parse(readFileSync(anchoredPath, 'utf8'))

    // Additive: claim hash + committed claim are byte-identical; only proofs grew.
    expect(anchored.committedClaim).toEqual(original.committedClaim)
    expect(anchored.evidenceBundle.committedClaimHash).toBe(
      original.evidenceBundle.committedClaimHash,
    )
    const types = anchored.evidenceBundle.proofs.map((p: { type: string }) => p.type)
    expect(types).toContain('opentimestamps')
    expect(types).toContain('ethereum-anchor')

    const eth = anchored.evidenceBundle.proofs.find(
      (p: { type: string }) => p.type === 'ethereum-anchor',
    )
    expect(eth.claimHash).toBe(original.evidenceBundle.committedClaimHash)
    expect(eth.profile).toBe('urn:screenplay-registration-evidence-ethereum-anchor:v1')
    expect(eth.chainId).toBe(1)
    expect(eth.contract).toBe(CONTRACT)
  })

  it('rejects a malformed coordinate at the validateEnvelope boundary (exit 2)', () => {
    const scriptPath = join(tmp, 'script.fountain')
    writeFileSync(scriptPath, SAMPLE)
    runCli(['register', scriptPath, '--mock'])
    const attach = runCli([
      'attach-eth-anchor',
      `${scriptPath}.manifest.json`,
      '--contract', '0xNOTHEX',
      '--registrant', REGISTRANT,
      '--tx-hash', TX_HASH,
      '--log-index', String(LOG_INDEX),
      '--block-number', String(BLOCK_NUMBER),
      '--out', join(tmp, 'bad.json'),
    ])
    expect(attach.code).toBe(2)
    expect(attach.stderr).toMatch(/contract/)
    expect(existsSync(join(tmp, 'bad.json'))).toBe(false)
  })

  it('refuses to overwrite the source envelope in place', () => {
    const { envelopePath } = registerAndAnchor(tmp)
    const attach = runCli([
      'attach-eth-anchor',
      envelopePath,
      '--contract', CONTRACT,
      '--registrant', REGISTRANT,
      '--tx-hash', TX_HASH,
      '--log-index', String(LOG_INDEX),
      '--block-number', String(BLOCK_NUMBER),
      '--out', envelopePath,
    ])
    expect(attach.code).not.toBe(0)
    expect(attach.stderr).toMatch(/must differ from the source envelope/)
  })
})

describe('CLI: verify --eth-rpc (informational; never flips the Bitcoin verdict)', () => {
  let tmp: string
  let stub: ChildProcess | undefined

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'screenreg-eth-cli-'))
  })
  afterEach(() => {
    if (stub && !stub.killed) stub.kill('SIGKILL')
    stub = undefined
  })

  /**
   * Spin up a stub JSON-RPC server in a SEPARATE process and resolve once it
   * prints its listening URL. The stub MUST be out-of-process: the CLI is
   * invoked with the blocking `spawnSync`, which would freeze an in-process
   * server's event loop and stall every RPC call.
   */
  async function startStub(claimHashHex: string): Promise<string> {
    const claimTopic = '0x' + claimHashHex
    const registrantTopic = '0x' + '0'.repeat(24) + REGISTRANT.slice(2)
    const stubScript = `
      import { createServer } from 'node:http'
      const log = {
        address: ${JSON.stringify(CONTRACT)},
        topics: [${JSON.stringify(TOPIC0)}, ${JSON.stringify(claimTopic)}, ${JSON.stringify(registrantTopic)}],
        blockNumber: '0x' + (${BLOCK_NUMBER}).toString(16),
        transactionHash: ${JSON.stringify(TX_HASH)},
        logIndex: '0x' + (${LOG_INDEX}).toString(16),
      }
      const srv = createServer((req, res) => {
        let body = ''
        req.on('data', (c) => (body += c))
        req.on('end', () => {
          const { id, method } = JSON.parse(body)
          let result
          if (method === 'eth_chainId') result = '0x1'
          else if (method === 'eth_blockNumber') result = '0x' + (${BLOCK_NUMBER} + 100).toString(16)
          else if (method === 'eth_getLogs') result = [log]
          res.setHeader('content-type', 'application/json')
          res.end(JSON.stringify({ jsonrpc: '2.0', id, result }))
        })
      })
      srv.listen(0, '127.0.0.1', () => {
        const addr = srv.address()
        process.stdout.write('URL http://127.0.0.1:' + addr.port + '\\n')
      })
    `
    const scriptPath = join(tmp, 'stub-rpc.mjs')
    writeFileSync(scriptPath, stubScript)
    stub = spawn(process.execPath, [scriptPath], { stdio: ['ignore', 'pipe', 'inherit'] })
    return await new Promise<string>((resolve, reject) => {
      let buf = ''
      const onData = (chunk: Buffer) => {
        buf += chunk.toString()
        const m = buf.match(/URL (\S+)/)
        if (m) {
          stub!.stdout!.off('data', onData)
          resolve(m[1]!)
        }
      }
      stub!.stdout!.on('data', onData)
      stub!.on('error', reject)
      setTimeout(() => reject(new Error('stub did not start')), 10000)
    })
  }

  it('prints VERIFIED for a matching on-chain log; Bitcoin verdict (PENDING) unchanged', async () => {
    const { scriptPath, otsPath, anchoredPath, claimHashHex } = registerAndAnchor(tmp)
    const url = await startStub(claimHashHex)
    const verify = runCli([
      'verify',
      scriptPath,
      anchoredPath,
      otsPath,
      '--eth-rpc', url,
      '--eth-min-confirmations', '12',
    ])
    // The mock OTS is still pending: the Bitcoin verdict is "VERIFIED (PENDING)"
    // and the exit code is 0. The ETH line is purely informational.
    expect(verify.code).toBe(0)
    expect(verify.stdout).toMatch(/VERIFIED \(PENDING\)/)
    expect(verify.stdout).toMatch(/Ethereum anchor: VERIFIED/)
    expect(verify.stdout).toMatch(/not a priority source/)
  })

  it('graceful-degrades to UNVERIFIED on an unreachable RPC; Bitcoin verdict unchanged', () => {
    const { scriptPath, otsPath, anchoredPath } = registerAndAnchor(tmp)
    // Port 1 is not listening; the verifier must catch the error and degrade.
    const verify = runCli([
      'verify',
      scriptPath,
      anchoredPath,
      otsPath,
      '--eth-rpc', 'http://127.0.0.1:1',
    ])
    expect(verify.code).toBe(0)
    expect(verify.stdout).toMatch(/VERIFIED \(PENDING\)/)
    expect(verify.stdout).toMatch(/Ethereum anchor: UNVERIFIED/)
    expect(verify.stdout).toMatch(/Bitcoin verdict unaffected/)
  })

  it('without --eth-rpc, prints no Ethereum line', () => {
    const { scriptPath, otsPath, anchoredPath } = registerAndAnchor(tmp)
    const verify = runCli(['verify', scriptPath, anchoredPath, otsPath])
    expect(verify.code).toBe(0)
    expect(verify.stdout).not.toMatch(/Ethereum anchor/)
  })
})
