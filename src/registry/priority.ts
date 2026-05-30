/**
 * Priority / dispute resolution for registry records (Node-side).
 *
 * The ONLY priority source is the Bitcoin block height. The record whose
 * `claimHash` is confirmed in the EARLIER Bitcoin block wins. Same block ⇒ a
 * tie (no sub-block ordering exists). This proves EARLIEST ANCHORED COMMITMENT,
 * not authorship or originality — overlap analysis is a separate, opt-in
 * comparison bundle (Section 06).
 *
 * Three rules are load-bearing and enforced here:
 *  - `registeredAt` is IGNORED. It is an operator-supplied wall-clock label, not
 *    a trust root; ranking on it would let an operator forge priority.
 *  - Ethereum anchors are NEVER a priority source. ETH is a corroborating witness
 *    only; it ranks nothing and can never flip a Bitcoin-derived outcome.
 *  - A height that is NOT Bitcoin-final cannot rank. If any contender carries
 *    only OTS-claimed (header-unverified) heights, the contest is UNDETERMINED —
 *    an unverified `.ots` height could name any block.
 *
 * See spec/v1/10-registry-index.md.
 */

import type { RecordVerifyResult } from './verify-index.js'

/** A single ranking contender: a record's claimHash + its verification result. */
export interface PriorityContender {
  claimHash: string
  result: RecordVerifyResult
}

export type PriorityOutcome =
  | {
      outcome: 'winner'
      /** The claimHash with the earliest Bitcoin-final height. */
      claimHash: string
      bitcoinHeight: number
    }
  | {
      outcome: 'tie'
      /** Two or more contenders share the earliest Bitcoin-final height. */
      claimHashes: string[]
      bitcoinHeight: number
    }
  | {
      outcome: 'undetermined'
      reason: PriorityUndeterminedReason
    }

export type PriorityUndeterminedReason =
  | 'no-contenders'
  | 'heights-not-bitcoin-final'
  | 'no-verified-records'

/**
 * Resolve priority across contenders by earliest Bitcoin-final block height.
 *
 * A contender ranks only if its record verified AND it carries at least one
 * `bitcoin-final` height. The smallest such height across a contender's heights
 * is its candidate height. If ANY contender that verified lacks a Bitcoin-final
 * height, the contest is `undetermined` (`heights-not-bitcoin-final`) — we refuse
 * to rank a field in which some heights are header-unverified, since an unverified
 * `.ots` height cannot be trusted to name an earlier (or any) block.
 */
export function resolvePriority(contenders: PriorityContender[]): PriorityOutcome {
  if (contenders.length === 0) {
    return { outcome: 'undetermined', reason: 'no-contenders' }
  }

  const verified = contenders.filter((c) => c.result.ok)
  if (verified.length === 0) {
    return { outcome: 'undetermined', reason: 'no-verified-records' }
  }

  // Any verified contender that lacks a Bitcoin-final height blocks ranking: we
  // cannot honestly say who is earliest when some heights are header-unverified.
  const candidates: { claimHash: string; height: number }[] = []
  for (const c of verified) {
    const r = c.result
    if (!r.ok) continue
    const finalHeights = r.bitcoinHeights
      .filter((h) => h.finality === 'bitcoin-final')
      .map((h) => h.height)
    if (finalHeights.length === 0) {
      return { outcome: 'undetermined', reason: 'heights-not-bitcoin-final' }
    }
    candidates.push({ claimHash: c.claimHash, height: Math.min(...finalHeights) })
  }

  let earliest = Infinity
  for (const cand of candidates) {
    if (cand.height < earliest) earliest = cand.height
  }
  const winners = candidates.filter((c) => c.height === earliest)

  if (winners.length === 1) {
    return { outcome: 'winner', claimHash: winners[0]!.claimHash, bitcoinHeight: earliest }
  }
  return {
    outcome: 'tie',
    claimHashes: winners.map((w) => w.claimHash),
    bitcoinHeight: earliest,
  }
}
