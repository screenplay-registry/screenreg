/**
 * Per-record registry-snapshot verification.
 *
 * Drives `verifyIndexSnapshot` with INJECTED resolvers and synthetic `.ots`
 * proofs (built from the exported OTS wire constants). Covers the Bitcoin-
 * finality split that the priority layer depends on:
 *   (a) with an attestation verifier → heights labeled bitcoin-final;
 *   (b) without one → labeled ots-claimed and resolvePriority is undetermined;
 *   (c) below minConfirmations → not final.
 * Also covers graceful per-record failure: a missing proof, a digest mismatch,
 * and a malformed claimHash are reported, never thrown.
 */

import { describe, it, expect } from 'vitest'
import { Buffer } from 'node:buffer'

import {
  verifyIndexSnapshot,
  type RegistrySnapshot,
  type VerifyBitcoinAttestation,
} from '../../src/registry/verify-index.js'
import { resolvePriority } from '../../src/registry/priority.js'
import { buildRegistryRecord } from '../../src/registry/record.js'
import {
  HEADER_MAGIC,
  OP_SHA256,
  ATTESTATION_MARKER,
  TAG_BITCOIN_BLOCK_HEADER,
  TAG_PENDING,
} from '../../src/anchors/ots-verify.js'

const CLAIM_A = 'sha256:' + 'aa'.repeat(32)
const CLAIM_B = 'sha256:' + 'bb'.repeat(32)

/** Bitcoin-style varint (low 7 bits + continuation), matching the OTS reader. */
function varint(n: number): Buffer {
  const out: number[] = []
  let v = n
  do {
    let b = v & 0x7f
    v = Math.floor(v / 128)
    if (v > 0) b |= 0x80
    out.push(b)
  } while (v > 0)
  return Buffer.from(out)
}

/**
 * Build a minimal valid `.ots` for a 32-byte digest with a single Bitcoin block
 * attestation terminating the branch immediately after the file digest. Layout:
 *   MAGIC | version(1) | OP_SHA256 | <digest> | 0x00 | <8-byte tag> | varint(len) | varint(height)
 */
function bitcoinOts(digestHex: string, blockHeight: number): Buffer {
  const heightPayload = varint(blockHeight)
  return Buffer.concat([
    HEADER_MAGIC,
    varint(1), // major version
    Buffer.from([OP_SHA256]),
    Buffer.from(digestHex, 'hex'),
    Buffer.from([ATTESTATION_MARKER]),
    TAG_BITCOIN_BLOCK_HEADER,
    varint(heightPayload.length),
    heightPayload,
  ])
}

/** A pending-only `.ots` (no Bitcoin attestation). */
function pendingOts(digestHex: string, url: string): Buffer {
  const urlBytes = Buffer.from(url, 'utf8')
  const payload = Buffer.concat([varint(urlBytes.length), urlBytes])
  return Buffer.concat([
    HEADER_MAGIC,
    varint(1),
    Buffer.from([OP_SHA256]),
    Buffer.from(digestHex, 'hex'),
    Buffer.from([ATTESTATION_MARKER]),
    TAG_PENDING,
    varint(payload.length),
    payload,
  ])
}

function digestHexOf(claimHash: string): string {
  return claimHash.slice('sha256:'.length)
}

function snapshotOf(claimHash: string, proofRef: string, block?: number): RegistrySnapshot {
  return {
    records: [
      buildRegistryRecord({
        claimHash,
        anchors: {
          opentimestamps: { proofRef, ...(block !== undefined ? { bitcoinBlock: block } : {}) },
        },
      }),
    ],
  }
}

/** An attestation verifier that confirms inclusion for any height (header check stubbed). */
const alwaysFinal: VerifyBitcoinAttestation = () => true

describe('verifyIndexSnapshot — structural .ots only', () => {
  it('valid proof → ok, OTS-claimed when no attestation verifier is injected', async () => {
    const proofs = new Map([['a.ots', bitcoinOts(digestHexOf(CLAIM_A), 800000)]])
    const res = await verifyIndexSnapshot(snapshotOf(CLAIM_A, 'a.ots'), {
      loadOtsProof: (_r, ref) => proofs.get(ref),
      minConfirmations: 6,
    })
    expect(res.records).toHaveLength(1)
    const r = res.records[0]!
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.bitcoinHeights).toEqual([{ height: 800000, finality: 'ots-claimed' }])
    }
  })

  it('a digest mismatch (wrong claimHash for the proof) is reported, not thrown', async () => {
    // The proof asserts CLAIM_A's digest, but the record's claimHash is CLAIM_B.
    const proofs = new Map([['b.ots', bitcoinOts(digestHexOf(CLAIM_A), 800000)]])
    const res = await verifyIndexSnapshot(snapshotOf(CLAIM_B, 'b.ots'), {
      loadOtsProof: (_r, ref) => proofs.get(ref),
      minConfirmations: 6,
    })
    const r = res.records[0]!
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toMatch(/does not match/i)
  })

  it('a missing proof → ok:false ots-missing (never throws)', async () => {
    const res = await verifyIndexSnapshot(snapshotOf(CLAIM_A, 'gone.ots'), {
      loadOtsProof: () => undefined,
      minConfirmations: 6,
    })
    const r = res.records[0]!
    expect(r).toEqual({ claimHash: CLAIM_A, ok: false, reason: 'ots-missing' })
  })

  it('a loader that throws is caught and reported', async () => {
    const res = await verifyIndexSnapshot(snapshotOf(CLAIM_A, 'a.ots'), {
      loadOtsProof: () => {
        throw new Error('disk on fire')
      },
      minConfirmations: 6,
    })
    const r = res.records[0]!
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toMatch(/disk on fire/)
  })

  it('a pending-only proof verifies structurally and reports the calendar URL', async () => {
    const proofs = new Map([
      ['p.ots', pendingOts(digestHexOf(CLAIM_A), 'https://calendar.example/')],
    ])
    const res = await verifyIndexSnapshot(snapshotOf(CLAIM_A, 'p.ots'), {
      loadOtsProof: (_r, ref) => proofs.get(ref),
      minConfirmations: 6,
    })
    const r = res.records[0]!
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.bitcoinHeights).toEqual([])
      expect(r.pendingCalendarUrls).toEqual(['https://calendar.example/'])
    }
  })
})

describe('verifyIndexSnapshot — Bitcoin-finality split', () => {
  it('with an attestation verifier → height labeled bitcoin-final', async () => {
    const proofs = new Map([['a.ots', bitcoinOts(digestHexOf(CLAIM_A), 800000)]])
    const res = await verifyIndexSnapshot(snapshotOf(CLAIM_A, 'a.ots'), {
      loadOtsProof: (_r, ref) => proofs.get(ref),
      verifyBitcoinAttestation: alwaysFinal,
      minConfirmations: 6,
    })
    const r = res.records[0]!
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.bitcoinHeights).toEqual([{ height: 800000, finality: 'bitcoin-final' }])
    }
  })

  it('without an attestation verifier → OTS-claimed → resolvePriority undetermined', async () => {
    const proofs = new Map([['a.ots', bitcoinOts(digestHexOf(CLAIM_A), 800000)]])
    const res = await verifyIndexSnapshot(snapshotOf(CLAIM_A, 'a.ots'), {
      loadOtsProof: (_r, ref) => proofs.get(ref),
      minConfirmations: 6,
    })
    const r = res.records[0]!
    expect(r.ok && r.bitcoinHeights[0]?.finality).toBe('ots-claimed')
    const outcome = resolvePriority([{ claimHash: CLAIM_A, result: r }])
    expect(outcome).toEqual({ outcome: 'undetermined', reason: 'heights-not-bitcoin-final' })
  })

  it('an attestation verifier that rejects below minConfirmations keeps the height OTS-claimed', async () => {
    const proofs = new Map([['a.ots', bitcoinOts(digestHexOf(CLAIM_A), 800000)]])
    // Simulate "not enough confirmations": the oracle returns false unless the
    // required confirmations are at most the (stubbed) available depth.
    const shallow: VerifyBitcoinAttestation = ({ minConfirmations }) => minConfirmations <= 2
    const res = await verifyIndexSnapshot(snapshotOf(CLAIM_A, 'a.ots'), {
      loadOtsProof: (_r, ref) => proofs.get(ref),
      verifyBitcoinAttestation: shallow,
      minConfirmations: 100,
    })
    const r = res.records[0]!
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.bitcoinHeights).toEqual([{ height: 800000, finality: 'ots-claimed' }])
    }
  })

  it('an attestation oracle that throws degrades to OTS-claimed, never an error', async () => {
    const proofs = new Map([['a.ots', bitcoinOts(digestHexOf(CLAIM_A), 800000)]])
    const res = await verifyIndexSnapshot(snapshotOf(CLAIM_A, 'a.ots'), {
      loadOtsProof: (_r, ref) => proofs.get(ref),
      verifyBitcoinAttestation: () => {
        throw new Error('headers unreachable')
      },
      minConfirmations: 6,
    })
    const r = res.records[0]!
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.bitcoinHeights).toEqual([{ height: 800000, finality: 'ots-claimed' }])
    }
  })
})

describe('verifyIndexSnapshot → resolvePriority integration', () => {
  it('two bitcoin-final records resolve to the earlier block', async () => {
    const proofs = new Map([
      ['a.ots', bitcoinOts(digestHexOf(CLAIM_A), 810000)],
      ['b.ots', bitcoinOts(digestHexOf(CLAIM_B), 800000)],
    ])
    const snapshot: RegistrySnapshot = {
      records: [
        buildRegistryRecord({
          claimHash: CLAIM_A,
          anchors: { opentimestamps: { proofRef: 'a.ots' } },
        }),
        buildRegistryRecord({
          claimHash: CLAIM_B,
          anchors: { opentimestamps: { proofRef: 'b.ots' } },
        }),
      ],
    }
    const res = await verifyIndexSnapshot(snapshot, {
      loadOtsProof: (_r, ref) => proofs.get(ref),
      verifyBitcoinAttestation: alwaysFinal,
      minConfirmations: 6,
    })
    const outcome = resolvePriority(
      res.records.map((result) => ({ claimHash: result.claimHash, result })),
    )
    expect(outcome).toEqual({ outcome: 'winner', claimHash: CLAIM_B, bitcoinHeight: 800000 })
  })
})
