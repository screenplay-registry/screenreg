/**
 * Strict `EthereumAnchorProof` named type: type-level acceptance (enforced by
 * `tsc -p tsconfig.all.json`) plus a runtime smoke that a fully-populated proof
 * round-trips through `buildEnvelope` / `validateEnvelope` WITHOUT the `as any`
 * cast the open catch-all would otherwise require.
 *
 * Unknown-proof tolerance lives solely in the open catch-all union arm; the
 * named type is not weakened — a typed `EthereumAnchorProof` omitting a required
 * on-chain field would be a compile error, which is the point of the named type.
 */

import { describe, it, expect } from 'vitest'

import { buildCommittedClaim, buildEnvelope } from '../../src/envelope/build.js'
import { computeClaimHash } from '../../src/envelope/claim-hash.js'
import { validateEnvelope } from '../../src/envelope/validate.js'
import type { EthereumAnchorProof, EthereumAnchorBatch } from '../../src/envelope/types.js'

const CONTENT_HASH = 'sha256:' + 'a'.repeat(64)

describe('EthereumAnchorProof strict named type', () => {
  it('round-trips a fully-populated proof through build + validate (no cast)', () => {
    const claim = buildCommittedClaim({ contentHash: CONTENT_HASH })
    const claimHash = computeClaimHash(claim)

    // No `as any`: this object MUST satisfy the named EthereumAnchorProof type,
    // which proves the union accepts the strict shape directly.
    const proof: EthereumAnchorProof = {
      type: 'ethereum-anchor',
      profile: 'urn:screenplay-registration-evidence-ethereum-anchor:v1',
      claimHash,
      chainId: 1,
      contract: '0x' + '1'.repeat(40),
      registrant: '0x' + '2'.repeat(40),
      txHash: '0x' + '3'.repeat(64),
      logIndex: 2,
      blockNumber: 21345678,
    }

    const env = buildEnvelope(claim, { proofs: [proof] })
    expect(validateEnvelope(env).ok).toBe(true)
  })

  it('accepts an optional reserved batch sub-object on the type', () => {
    const batch: EthereumAnchorBatch = {
      batchId: 'b1',
      merkleRoot: '0x' + '4'.repeat(64),
      path: ['0x' + '5'.repeat(64)],
    }
    const proof: EthereumAnchorProof = {
      type: 'ethereum-anchor',
      claimHash: 'sha256:' + 'b'.repeat(64),
      chainId: 1,
      contract: '0x' + '1'.repeat(40),
      registrant: '0x' + '2'.repeat(40),
      txHash: '0x' + '3'.repeat(64),
      logIndex: 0,
      blockNumber: 1,
      batch,
    }
    // The named type carries the optional batch; it is structurally valid.
    expect(proof.batch?.batchId).toBe('b1')
  })
})
