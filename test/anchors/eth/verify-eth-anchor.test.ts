/**
 * Off-chain `ethereum-anchor` log verifier — every taxonomy state, driven by a
 * MOCK provider with canned logs. NONE of these states ever flips a Bitcoin
 * verdict; the verifier is topics-only (no calldata, no signature recovery).
 *
 * The mock provider deliberately exposes NO calldata/receipt method, matching
 * the production interface — there is no way for the verifier to recover a
 * signature off-chain.
 */

import { describe, it, expect, vi } from 'vitest'

import {
  verifyEthAnchor,
  type EthLog,
  type EthLogProvider,
} from '../../../src/anchors/eth/verify-eth-anchor.js'
import { REGISTERED_EVENT_TOPIC0 } from '../../../src/anchors/eth/constants.js'
import type { EthereumAnchorProof } from '../../../src/envelope/types.js'

const CLAIM_HASH = 'sha256:' + 'ab'.repeat(32)
const CLAIM_TOPIC = '0x' + 'ab'.repeat(32)
// A non-checksummed (all-lowercase here, but mixed-case below) 20-byte address.
const REGISTRANT = '0x' + 'cd'.repeat(20)
const REGISTRANT_TOPIC = '0x' + '0'.repeat(24) + 'cd'.repeat(20)
const CONTRACT = '0x' + 'ef'.repeat(20)
const TX_HASH = '0x' + '11'.repeat(32)
const BLOCK = 21345678

function baseProof(overrides: Partial<EthereumAnchorProof> = {}): EthereumAnchorProof {
  return {
    type: 'ethereum-anchor',
    profile: 'urn:screenplay-registration-evidence-ethereum-anchor:v1',
    claimHash: CLAIM_HASH,
    chainId: 1,
    contract: CONTRACT,
    registrant: REGISTRANT,
    txHash: TX_HASH,
    logIndex: 2,
    blockNumber: BLOCK,
    ...overrides,
  }
}

function matchingLog(overrides: Partial<EthLog> = {}): EthLog {
  return {
    address: CONTRACT,
    topics: [REGISTERED_EVENT_TOPIC0, CLAIM_TOPIC, REGISTRANT_TOPIC],
    blockNumber: BLOCK,
    transactionHash: TX_HASH,
    logIndex: 2,
    ...overrides,
  }
}

/** Build a mock provider; tracks that calldata is never read (no such method exists). */
function mockProvider(opts: {
  chainId?: number
  logs?: EthLog[] | (() => Promise<EthLog[]>)
  head?: number
  getLogsThrows?: boolean
  getChainIdThrows?: boolean
}): EthLogProvider {
  return {
    getChainId: vi.fn(async () => {
      if (opts.getChainIdThrows) throw new Error('rpc down')
      return opts.chainId ?? 1
    }),
    getLogs: vi.fn(async () => {
      if (opts.getLogsThrows) throw new Error('rpc timeout')
      const l = opts.logs ?? []
      return typeof l === 'function' ? l() : l
    }),
    getBlockNumber: vi.fn(async () => opts.head ?? BLOCK + 100),
  }
}

const OPTS = { minConfirmations: 12 }

describe('verifyEthAnchor — verified', () => {
  it('matching topics + coordinates + finality → verified', async () => {
    const provider = mockProvider({ logs: [matchingLog()] })
    const result = await verifyEthAnchor(baseProof(), CLAIM_HASH, provider, OPTS)
    expect(result.status).toBe('verified')
    if (result.status === 'verified') {
      expect(result.blockNumber).toBe(BLOCK)
      expect(result.confirmations).toBeGreaterThanOrEqual(OPTS.minConfirmations)
    }
  })

  it('case-insensitive registrant compare: mixed-case proof address still matches a padded topic', async () => {
    const mixed = '0x' + 'Cd'.repeat(20)
    const provider = mockProvider({ logs: [matchingLog()] })
    const result = await verifyEthAnchor(
      baseProof({ registrant: mixed }),
      CLAIM_HASH,
      provider,
      OPTS,
    )
    expect(result.status).toBe('verified')
  })

  it('uses expectedClaimHash for comparison even if proof.claimHash carries no sha256: prefix', async () => {
    const provider = mockProvider({ logs: [matchingLog()] })
    const result = await verifyEthAnchor(
      baseProof({ claimHash: 'ab'.repeat(32) }),
      CLAIM_HASH,
      provider,
      OPTS,
    )
    expect(result.status).toBe('verified')
  })
})

describe('verifyEthAnchor — rejected', () => {
  it('proof.claimHash !== expectedClaimHash → rejected (before any RPC)', async () => {
    const provider = mockProvider({ logs: [matchingLog()] })
    const result = await verifyEthAnchor(
      baseProof({ claimHash: 'sha256:' + 'ff'.repeat(32) }),
      CLAIM_HASH,
      provider,
      OPTS,
    )
    expect(result).toEqual({ status: 'rejected', reason: 'claimHash-mismatch' })
    expect(provider.getChainId).not.toHaveBeenCalled()
    expect(provider.getLogs).not.toHaveBeenCalled()
  })

  it('proof.chainId !== CANONICAL_CHAIN_ID → rejected wrong-chain', async () => {
    const provider = mockProvider({ chainId: 10, logs: [matchingLog()] })
    const result = await verifyEthAnchor(baseProof({ chainId: 10 }), CLAIM_HASH, provider, OPTS)
    expect(result).toEqual({ status: 'rejected', reason: 'wrong-chain' })
  })

  it('provider on a different chain than the proof → rejected wrong-chain', async () => {
    const provider = mockProvider({ chainId: 137, logs: [matchingLog()] })
    const result = await verifyEthAnchor(baseProof(), CLAIM_HASH, provider, OPTS)
    expect(result).toEqual({ status: 'rejected', reason: 'wrong-chain' })
  })

  it('registrant topic decodes to a different address → rejected', async () => {
    const otherRegistrantTopic = '0x' + '0'.repeat(24) + '99'.repeat(20)
    const provider = mockProvider({
      logs: [matchingLog({ topics: [REGISTERED_EVENT_TOPIC0, CLAIM_TOPIC, otherRegistrantTopic] })],
    })
    const result = await verifyEthAnchor(baseProof(), CLAIM_HASH, provider, OPTS)
    expect(result).toEqual({ status: 'rejected', reason: 'registrant-mismatch' })
  })

  it('log blockNumber contradicts the proof → rejected', async () => {
    const provider = mockProvider({ logs: [matchingLog({ blockNumber: BLOCK + 1 })] })
    const result = await verifyEthAnchor(baseProof(), CLAIM_HASH, provider, OPTS)
    expect(result).toEqual({ status: 'rejected', reason: 'block-number-mismatch' })
  })
})

describe('verifyEthAnchor — not-found (disambiguation, never first-match)', () => {
  it('3 logs for the same claimHash topic, matching one LAST → still finds it', async () => {
    const decoy1 = matchingLog({ transactionHash: '0x' + '22'.repeat(32), logIndex: 0 })
    const decoy2 = matchingLog({ transactionHash: '0x' + '33'.repeat(32), logIndex: 1 })
    const real = matchingLog()
    const provider = mockProvider({ logs: [decoy1, decoy2, real] })
    const result = await verifyEthAnchor(baseProof(), CLAIM_HASH, provider, OPTS)
    expect(result.status).toBe('verified')
  })

  it('RPC returns logs but none match txHash + logIndex → not-found', async () => {
    const decoy1 = matchingLog({ transactionHash: '0x' + '22'.repeat(32), logIndex: 0 })
    const decoy2 = matchingLog({ transactionHash: TX_HASH, logIndex: 9 }) // right tx, wrong index
    const provider = mockProvider({ logs: [decoy1, decoy2] })
    const result = await verifyEthAnchor(baseProof(), CLAIM_HASH, provider, OPTS)
    expect(result).toEqual({ status: 'not-found' })
  })
})

describe('verifyEthAnchor — unverified (never a failure)', () => {
  it('getLogs throws (RPC unreachable) → unverified rpc-error, no throw', async () => {
    const provider = mockProvider({ getLogsThrows: true })
    const result = await verifyEthAnchor(baseProof(), CLAIM_HASH, provider, OPTS)
    expect(result).toEqual({ status: 'unverified', reason: 'rpc-error' })
  })

  it('getChainId throws → unverified rpc-error', async () => {
    const provider = mockProvider({ getChainIdThrows: true })
    const result = await verifyEthAnchor(baseProof(), CLAIM_HASH, provider, OPTS)
    expect(result).toEqual({ status: 'unverified', reason: 'rpc-error' })
  })

  it('below minConfirmations → unverified insufficient-confirmations', async () => {
    const provider = mockProvider({ logs: [matchingLog()], head: BLOCK + 2 })
    const result = await verifyEthAnchor(baseProof(), CLAIM_HASH, provider, OPTS)
    expect(result).toEqual({ status: 'unverified', reason: 'insufficient-confirmations' })
  })

  it('a batched proof → unverified batch-reserved, NO Merkle-path check, no RPC', async () => {
    const provider = mockProvider({ logs: [matchingLog()] })
    const result = await verifyEthAnchor(
      baseProof({ batch: { batchId: 'b1', merkleRoot: '0x' + '4'.repeat(64), path: ['0x' + '5'.repeat(64)] } }),
      CLAIM_HASH,
      provider,
      OPTS,
    )
    expect(result).toEqual({ status: 'unverified', reason: 'batch-reserved' })
    // batch check happens before any chain identity / log read.
    expect(provider.getLogs).not.toHaveBeenCalled()
  })
})

describe('verifyEthAnchor — topics-only invariant', () => {
  it('the provider interface exposes no calldata/receipt method', () => {
    const provider = mockProvider({ logs: [matchingLog()] })
    const asRecord = provider as unknown as Record<string, unknown>
    expect(asRecord.getTransaction).toBeUndefined()
    expect(asRecord.getTransactionReceipt).toBeUndefined()
    expect(Object.keys(provider).sort()).toEqual(['getBlockNumber', 'getChainId', 'getLogs'])
  })

  it('filters by the canonical topic[0] and the indexed claimHash topic', async () => {
    const provider = mockProvider({ logs: [matchingLog()] })
    await verifyEthAnchor(baseProof(), CLAIM_HASH, provider, OPTS)
    const calls = (provider.getLogs as ReturnType<typeof vi.fn>).mock.calls
    const call = calls[0]?.[0] as { address: string; topics: (string | null)[] }
    expect(call.topics[0]).toBe(REGISTERED_EVENT_TOPIC0)
    expect((call.topics[1] as string).toLowerCase()).toBe(CLAIM_TOPIC.toLowerCase())
    expect(call.address).toBe(CONTRACT)
  })
})
