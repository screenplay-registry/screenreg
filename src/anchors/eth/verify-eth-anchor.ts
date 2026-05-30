/**
 * Off-chain verifier for an `ethereum-anchor` evidence proof (spec §09).
 *
 * Reads the on-chain `Registered` log's indexed topics + transaction coordinates
 * and confirms they match an INDEPENDENTLY-RECOMPUTED envelope claimHash. It is
 * TOPICS-ONLY: it never fetches calldata and never recovers an EIP-712 signature
 * (recovery is performed exclusively by the on-chain contract). The Ethereum
 * anchor is a SECONDARY, additive witness — a missing, failed, unreachable, or
 * unverified ETH check NEVER fails an otherwise Bitcoin-valid proof, and ETH is
 * NEVER a priority/time source. Bitcoin (via OpenTimestamps) remains the sole
 * time + priority anchor.
 *
 * The RPC provider is INJECTED (and therefore mockable) so the commitment core
 * stays dependency-free and this module needs no network stack. keccak (via
 * `@noble/hashes`, confined to `src/anchors/eth/`) is only used to encode the
 * claimHash → bytes32 topic; no hand-rolled keccak. See spec/v1/09-onchain-anchor.md.
 */

import type { EthereumAnchorProof } from '../../envelope/types.js'
import { CANONICAL_CHAIN_ID, REGISTERED_EVENT_TOPIC0 } from './constants.js'
import { claimHashToBytes32 } from './eip712.js'
import { bytesToHex } from '@noble/hashes/utils.js'

/** A decoded Ethereum log as returned by an `eth_getLogs` provider. */
export interface EthLog {
  address: string
  topics: string[]
  blockNumber: number
  transactionHash: string
  logIndex: number
}

/**
 * Minimal, injectable JSON-RPC surface. Deliberately has NO calldata / receipt
 * method: a topics-only verifier never reads calldata and never recovers a
 * signature (recovery is performed exclusively by the on-chain contract; spec §09).
 */
export interface EthLogProvider {
  getChainId(): Promise<number>
  getLogs(filter: {
    address: string
    topics: (string | null)[]
    fromBlock?: number
    toBlock?: number
  }): Promise<EthLog[]>
  getBlockNumber(): Promise<number>
}

export interface VerifyEthAnchorOptions {
  /** Confirmations required before a log is treated as final. A receipt is not final. */
  minConfirmations: number
}

/**
 * Deterministic result taxonomy. Each state is independently observable and
 * NONE ever flips a Bitcoin verdict:
 *  - `verified`    — RPC ok; the log at (txHash, logIndex) matches every field.
 *  - `not-found`   — RPC ok; no log matched both txHash AND logIndex.
 *  - `unverified`  — RPC failure/timeout/unreachable, a RESERVED batched anchor,
 *                    or insufficient confirmations. Caller treats as "ETH not
 *                    confirmed," never as a failure.
 *  - `rejected`    — claimHash mismatch, wrong chain, or a decoded field
 *                    contradicts the proof. A positive disagreement with chain data.
 */
export type EthAnchorResult =
  | { status: 'verified'; blockNumber: number; confirmations: number }
  | { status: 'not-found' }
  | { status: 'unverified'; reason: EthUnverifiedReason }
  | { status: 'rejected'; reason: EthRejectedReason }

export type EthUnverifiedReason =
  | 'batch-reserved'
  | 'rpc-error'
  | 'insufficient-confirmations'

export type EthRejectedReason =
  | 'claimHash-mismatch'
  | 'wrong-chain'
  | 'contract-mismatch'
  | 'registrant-mismatch'
  | 'claimHash-topic-mismatch'
  | 'block-number-mismatch'

/**
 * Verify an `ethereum-anchor` proof against on-chain logs.
 *
 * @param proof              the evidence proof from the envelope
 * @param expectedClaimHash  the INDEPENDENTLY-RECOMPUTED envelope claimHash
 *                           (defense-in-depth: used for both the topic filter and
 *                           the comparison; `proof.claimHash` alone is never trusted)
 * @param provider           injected, mockable RPC surface
 */
export async function verifyEthAnchor(
  proof: EthereumAnchorProof,
  expectedClaimHash: string,
  provider: EthLogProvider,
  options: VerifyEthAnchorOptions,
): Promise<EthAnchorResult> {
  // 1. Bind to the recomputed envelope claimHash BEFORE any RPC. A proof whose
  //    own claimHash disagrees with the recomputed one is rejected outright.
  if (!sameClaimHash(proof.claimHash, expectedClaimHash)) {
    return { status: 'rejected', reason: 'claimHash-mismatch' }
  }

  // 2. A batched anchor is RESERVED in v1 — no batch wire format is defined, so
  //    make NO Merkle-path claim and verify nothing. Return immediately.
  if (proof.batch !== undefined) {
    return { status: 'unverified', reason: 'batch-reserved' }
  }

  // 3. Chain identity: the proof must target the one canonical chain (mainnet)
  //    AND the provider must actually be on that chain. Any provider error here
  //    degrades gracefully to `unverified`, never a Bitcoin failure.
  if (proof.chainId !== CANONICAL_CHAIN_ID) {
    return { status: 'rejected', reason: 'wrong-chain' }
  }
  let providerChainId: number
  try {
    providerChainId = await provider.getChainId()
  } catch {
    return { status: 'unverified', reason: 'rpc-error' }
  }
  if (providerChainId !== proof.chainId) {
    return { status: 'rejected', reason: 'wrong-chain' }
  }

  // 4. Fetch logs by indexed topics. The claimHash topic uses the RECOMPUTED
  //    hash (not proof.claimHash); the registrant topic is the left-padded
  //    address. eth_getLogs may return MANY logs (no on-chain uniqueness).
  const claimHashTopic = bytes32Topic(expectedClaimHash)
  const registrantTopic = addressTopic(proof.registrant)
  let logs: EthLog[]
  try {
    logs = await provider.getLogs({
      address: proof.contract,
      topics: [REGISTERED_EVENT_TOPIC0, claimHashTopic, registrantTopic],
      fromBlock: proof.blockNumber,
      toBlock: proof.blockNumber,
    })
  } catch {
    return { status: 'unverified', reason: 'rpc-error' }
  }

  // 5. Disambiguate by the EXACT (txHash, logIndex) coordinate — never "first
  //    match": eth_getLogs has no on-chain uniqueness. RPC success but no exact
  //    match → not-found.
  const log = logs.find(
    (l) =>
      l.transactionHash.toLowerCase() === proof.txHash.toLowerCase() &&
      l.logIndex === proof.logIndex,
  )
  if (log === undefined) {
    return { status: 'not-found' }
  }

  // 6. Decode topics and compare (topics-only; never calldata, never recovery).
  if (log.address.toLowerCase() !== proof.contract.toLowerCase()) {
    return { status: 'rejected', reason: 'contract-mismatch' }
  }
  // topic[1] = indexed claimHash (bytes32); topic[2] = indexed registrant (padded address).
  const logClaimTopic = (log.topics[1] ?? '').toLowerCase()
  if (logClaimTopic !== claimHashTopic.toLowerCase()) {
    return { status: 'rejected', reason: 'claimHash-topic-mismatch' }
  }
  const logRegistrant = topicToAddress(log.topics[2] ?? '')
  if (logRegistrant !== proof.registrant.toLowerCase()) {
    return { status: 'rejected', reason: 'registrant-mismatch' }
  }
  if (log.blockNumber !== proof.blockNumber) {
    return { status: 'rejected', reason: 'block-number-mismatch' }
  }

  // 7. Finality: a receipt is not final. Below the confirmation threshold the
  //    anchor is not-yet-final → unverified (graceful, never a failure).
  let head: number
  try {
    head = await provider.getBlockNumber()
  } catch {
    return { status: 'unverified', reason: 'rpc-error' }
  }
  const confirmations = head - log.blockNumber + 1
  if (confirmations < options.minConfirmations) {
    return { status: 'unverified', reason: 'insufficient-confirmations' }
  }

  return { status: 'verified', blockNumber: log.blockNumber, confirmations }
}

/** Compare two claimHash strings ignoring an optional `sha256:` label + case. */
function sameClaimHash(a: string, b: string): boolean {
  const norm = (s: string) =>
    (s.startsWith('sha256:') ? s.slice('sha256:'.length) : s).toLowerCase()
  return norm(a) === norm(b)
}

/** Encode a claimHash as a `0x`-prefixed bytes32 topic (strips `sha256:`). */
function bytes32Topic(claimHash: string): string {
  return '0x' + bytesToHex(claimHashToBytes32(claimHash))
}

/** Left-pad a 20-byte address to a 32-byte indexed-topic word. */
function addressTopic(address: string): string {
  const raw = address.toLowerCase().replace(/^0x/, '')
  return '0x' + '0'.repeat(24) + raw
}

/** Strip the 12-byte (24-hex) zero padding from an indexed address topic. */
function topicToAddress(topic: string): string {
  return ('0x' + topic.slice(topic.length - 40)).toLowerCase()
}
