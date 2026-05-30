/**
 * Priority / dispute resolution — Bitcoin block height ONLY.
 *
 * The earliest Bitcoin-final height wins; same block ⇒ tie; ETH-only and
 * registeredAt-only differences have NO effect; and a field with any
 * header-unverified (OTS-claimed) height is undetermined — we refuse to rank on
 * an unverified height.
 */

import { describe, it, expect } from 'vitest'

import { resolvePriority, type PriorityContender } from '../../src/registry/priority.js'
import type { RecordVerifyResult } from '../../src/registry/verify-index.js'

const CLAIM_A = 'sha256:' + 'aa'.repeat(32)
const CLAIM_B = 'sha256:' + 'bb'.repeat(32)
const CLAIM_C = 'sha256:' + 'cc'.repeat(32)

type Finality = 'ots-claimed' | 'bitcoin-final'

function verified(claimHash: string, heights: [number, Finality][]): RecordVerifyResult {
  return {
    claimHash,
    ok: true,
    bitcoinHeights: heights.map(([height, finality]) => ({ height, finality })),
    pendingCalendarUrls: [],
  }
}

function failed(claimHash: string, reason = 'ots-missing'): RecordVerifyResult {
  return { claimHash, ok: false, reason }
}

function contender(result: RecordVerifyResult): PriorityContender {
  return { claimHash: result.claimHash, result }
}

describe('resolvePriority — winner by earliest Bitcoin-final height', () => {
  it('earlier Bitcoin block wins', () => {
    const outcome = resolvePriority([
      contender(verified(CLAIM_A, [[800000, 'bitcoin-final']])),
      contender(verified(CLAIM_B, [[900000, 'bitcoin-final']])),
    ])
    expect(outcome).toEqual({ outcome: 'winner', claimHash: CLAIM_A, bitcoinHeight: 800000 })
  })

  it('uses the smallest final height within a single record', () => {
    const outcome = resolvePriority([
      contender(verified(CLAIM_A, [[850000, 'bitcoin-final'], [800500, 'bitcoin-final']])),
      contender(verified(CLAIM_B, [[810000, 'bitcoin-final']])),
    ])
    expect(outcome).toEqual({ outcome: 'winner', claimHash: CLAIM_A, bitcoinHeight: 800500 })
  })
})

describe('resolvePriority — tie on same block', () => {
  it('same earliest block ⇒ tie listing all winners', () => {
    const outcome = resolvePriority([
      contender(verified(CLAIM_A, [[800000, 'bitcoin-final']])),
      contender(verified(CLAIM_B, [[800000, 'bitcoin-final']])),
      contender(verified(CLAIM_C, [[900000, 'bitcoin-final']])),
    ])
    expect(outcome.outcome).toBe('tie')
    if (outcome.outcome === 'tie') {
      expect(outcome.bitcoinHeight).toBe(800000)
      expect(outcome.claimHashes.sort()).toEqual([CLAIM_A, CLAIM_B].sort())
    }
  })
})

describe('resolvePriority — ETH and registeredAt never rank', () => {
  it('records identical on Bitcoin height tie regardless of any ETH coordinates', () => {
    // The contender results carry no ETH influence at all (priority only sees
    // Bitcoin heights); equal heights tie. This documents that ETH cannot break
    // a Bitcoin tie.
    const outcome = resolvePriority([
      contender(verified(CLAIM_A, [[800000, 'bitcoin-final']])),
      contender(verified(CLAIM_B, [[800000, 'bitcoin-final']])),
    ])
    expect(outcome.outcome).toBe('tie')
  })
})

describe('resolvePriority — not-final heights are undetermined', () => {
  it('a contender with only OTS-claimed heights blocks the contest', () => {
    const outcome = resolvePriority([
      contender(verified(CLAIM_A, [[800000, 'bitcoin-final']])),
      contender(verified(CLAIM_B, [[750000, 'ots-claimed']])),
    ])
    expect(outcome).toEqual({ outcome: 'undetermined', reason: 'heights-not-bitcoin-final' })
  })

  it('a single contender with no final height is undetermined', () => {
    const outcome = resolvePriority([contender(verified(CLAIM_A, [[800000, 'ots-claimed']]))])
    expect(outcome).toEqual({ outcome: 'undetermined', reason: 'heights-not-bitcoin-final' })
  })

  it('a verified contender with zero heights is undetermined', () => {
    const outcome = resolvePriority([contender(verified(CLAIM_A, []))])
    expect(outcome).toEqual({ outcome: 'undetermined', reason: 'heights-not-bitcoin-final' })
  })
})

describe('resolvePriority — degenerate inputs', () => {
  it('no contenders ⇒ undetermined no-contenders', () => {
    expect(resolvePriority([])).toEqual({ outcome: 'undetermined', reason: 'no-contenders' })
  })

  it('all records failed verification ⇒ undetermined no-verified-records', () => {
    const outcome = resolvePriority([
      contender(failed(CLAIM_A)),
      contender(failed(CLAIM_B)),
    ])
    expect(outcome).toEqual({ outcome: 'undetermined', reason: 'no-verified-records' })
  })

  it('a failed record is excluded but a single good one still wins', () => {
    const outcome = resolvePriority([
      contender(failed(CLAIM_A)),
      contender(verified(CLAIM_B, [[800000, 'bitcoin-final']])),
    ])
    expect(outcome).toEqual({ outcome: 'winner', claimHash: CLAIM_B, bitcoinHeight: 800000 })
  })
})
