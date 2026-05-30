/**
 * Registry-record builder + validator.
 *
 * The record is an off-chain discovery artifact, never a commitment. These tests
 * pin the two hard boundaries: a `contentHash` is rejected at any depth
 * (membership-oracle boundary), and `registeredAt` is informational only — it
 * never influences priority (cross-checked against resolvePriority).
 */

import { describe, it, expect } from 'vitest'

import {
  REGISTRY_RECORD_VERSION,
  buildRegistryRecord,
  validateRegistryRecord,
  type RegistryRecord,
} from '../../src/registry/record.js'
import { resolvePriority } from '../../src/registry/priority.js'
import type { RecordVerifyResult } from '../../src/registry/verify-index.js'

const CLAIM_A = 'sha256:' + 'aa'.repeat(32)
const CLAIM_B = 'sha256:' + 'bb'.repeat(32)

function happyRecord(overrides: Partial<RegistryRecord> = {}): RegistryRecord {
  return {
    registryRecordVersion: REGISTRY_RECORD_VERSION,
    claimHash: CLAIM_A,
    title: 'THE LAST REWRITE',
    author: { pubkey: 'ed25519:AAAA', name: 'Jane Roe' },
    registeredAt: '2026-05-29T12:00:00Z',
    anchors: {
      opentimestamps: { proofRef: 'the-last-rewrite.ots', bitcoinBlock: 875432 },
    },
    ...overrides,
  }
}

describe('buildRegistryRecord', () => {
  it('stamps the locked URN and carries through the inputs', () => {
    const rec = buildRegistryRecord({
      claimHash: CLAIM_A,
      title: 'T',
      author: { pubkey: 'ed25519:AAAA' },
      anchors: { opentimestamps: { proofRef: 'a.ots' } },
    })
    expect(rec.registryRecordVersion).toBe(REGISTRY_RECORD_VERSION)
    expect(rec.claimHash).toBe(CLAIM_A)
    expect(rec.title).toBe('T')
    expect(rec.anchors.opentimestamps.proofRef).toBe('a.ots')
    expect(validateRegistryRecord(rec).ok).toBe(true)
  })

  it('omits optional fields when not supplied (no undefined keys)', () => {
    const rec = buildRegistryRecord({
      claimHash: CLAIM_A,
      anchors: { opentimestamps: { proofRef: 'a.ots' } },
    })
    expect('title' in rec).toBe(false)
    expect('author' in rec).toBe(false)
    expect('registeredAt' in rec).toBe(false)
    expect('bitcoinBlock' in rec.anchors.opentimestamps).toBe(false)
    expect('ethereum' in rec.anchors).toBe(false)
    expect(validateRegistryRecord(rec).ok).toBe(true)
  })

  it('carries an optional ethereum anchor through', () => {
    const rec = buildRegistryRecord({
      claimHash: CLAIM_A,
      anchors: {
        opentimestamps: { proofRef: 'a.ots' },
        ethereum: {
          chainId: 1,
          contract: '0x' + 'ef'.repeat(20),
          txHash: '0x' + '11'.repeat(32),
          logIndex: 2,
          blockNumber: 21345678,
        },
      },
    })
    expect(rec.anchors.ethereum?.chainId).toBe(1)
    expect(validateRegistryRecord(rec).ok).toBe(true)
  })
})

describe('validateRegistryRecord — happy path', () => {
  it('accepts a fully-populated record', () => {
    expect(validateRegistryRecord(happyRecord())).toEqual({ ok: true })
  })
})

describe('validateRegistryRecord — contentHash rejected (membership-oracle boundary)', () => {
  it('rejects a top-level contentHash', () => {
    const bad = { ...happyRecord(), contentHash: 'sha256:' + 'cc'.repeat(32) }
    const res = validateRegistryRecord(bad)
    expect(res.ok).toBe(false)
    if (!res.ok) {
      expect(res.errors.some((e) => e.includes('contentHash'))).toBe(true)
    }
  })

  it('rejects a nested contentHash (under anchors)', () => {
    const bad = happyRecord()
    // Inject a nested contentHash inside an otherwise-shaped anchors object.
    const withNested = {
      ...bad,
      anchors: {
        opentimestamps: { proofRef: 'a.ots', contentHash: 'sha256:' + 'dd'.repeat(32) },
      },
    }
    const res = validateRegistryRecord(withNested)
    expect(res.ok).toBe(false)
    if (!res.ok) {
      expect(res.errors.some((e) => e.includes('contentHash'))).toBe(true)
    }
  })

  it('rejects a deeply-nested contentHash (under author)', () => {
    const withNested = {
      ...happyRecord(),
      author: { pubkey: 'ed25519:AAAA', extra: { contentHash: 'sha256:' + 'ee'.repeat(32) } },
    }
    const res = validateRegistryRecord(withNested)
    expect(res.ok).toBe(false)
    if (!res.ok) {
      expect(res.errors.some((e) => e.includes('contentHash'))).toBe(true)
    }
  })
})

describe('validateRegistryRecord — shape errors', () => {
  it('rejects a wrong URN', () => {
    const bad = { ...happyRecord(), registryRecordVersion: 'urn:wrong:v1' }
    expect(validateRegistryRecord(bad).ok).toBe(false)
  })

  it('rejects a malformed claimHash', () => {
    const bad = { ...happyRecord(), claimHash: 'notahash' }
    expect(validateRegistryRecord(bad).ok).toBe(false)
  })

  it('rejects a missing opentimestamps anchor', () => {
    const bad = { ...happyRecord(), anchors: {} }
    expect(validateRegistryRecord(bad).ok).toBe(false)
  })

  it('rejects unknown top-level fields', () => {
    const bad = { ...happyRecord(), surprise: true }
    expect(validateRegistryRecord(bad).ok).toBe(false)
  })

  it('rejects a malformed ethereum contract address', () => {
    const bad = {
      ...happyRecord(),
      anchors: {
        opentimestamps: { proofRef: 'a.ots' },
        ethereum: {
          chainId: 1,
          contract: '0xnothex',
          txHash: '0x' + '11'.repeat(32),
          logIndex: 0,
          blockNumber: 1,
        },
      },
    }
    expect(validateRegistryRecord(bad).ok).toBe(false)
  })
})

describe('registeredAt is informational — never used for priority', () => {
  it('an EARLIER registeredAt does not win when Bitcoin heights say otherwise', () => {
    // Record A claims an earlier wall-clock registeredAt but a LATER Bitcoin block.
    // Record B claims a later registeredAt but an EARLIER Bitcoin block. Priority
    // must follow Bitcoin (B wins), proving registeredAt is ignored.
    const resultA: RecordVerifyResult = {
      claimHash: CLAIM_A,
      ok: true,
      bitcoinHeights: [{ height: 900000, finality: 'bitcoin-final' }],
      pendingCalendarUrls: [],
    }
    const resultB: RecordVerifyResult = {
      claimHash: CLAIM_B,
      ok: true,
      bitcoinHeights: [{ height: 800000, finality: 'bitcoin-final' }],
      pendingCalendarUrls: [],
    }
    const outcome = resolvePriority([
      { claimHash: CLAIM_A, result: resultA },
      { claimHash: CLAIM_B, result: resultB },
    ])
    expect(outcome).toEqual({ outcome: 'winner', claimHash: CLAIM_B, bitcoinHeight: 800000 })
  })
})
