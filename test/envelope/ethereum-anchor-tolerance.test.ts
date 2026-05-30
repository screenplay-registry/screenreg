/**
 * Conformance: an `ethereum-anchor` evidence proof (Section 09) is tolerated as
 * additive evidence and does NOT change the committed claim hash; and the
 * runtime validator rejects an ethereum-anchor proof that carries a `contentHash`
 * (the membership-oracle boundary).
 *
 * Covers both implementations: the Node-side (sync) validator/builder and the
 * cross-runtime (async) ones, asserting parity.
 */

import { describe, it, expect } from 'vitest'

import {
  buildCommittedClaim as legacyBuildCommittedClaim,
  buildEnvelope as legacyBuildEnvelope,
  checkEnvelopeConsistency as legacyCheckEnvelopeConsistency,
} from '../../src/envelope/build.js'
import { computeClaimHash as legacyComputeClaimHash } from '../../src/envelope/claim-hash.js'
import { validateEnvelope as legacyValidateEnvelope } from '../../src/envelope/validate.js'

import {
  buildCommittedClaim as sharedBuildCommittedClaim,
  buildEnvelope as sharedBuildEnvelope,
} from '../../src/shared/envelope/build.js'
import { computeClaimHash as sharedComputeClaimHash } from '../../src/shared/envelope/claim-hash.js'
import { validateEnvelope as sharedValidateEnvelope } from '../../src/shared/envelope/validate.js'

const CONTENT_HASH = 'sha256:' + 'a'.repeat(64)
const CONTRACT = '0x' + '1'.repeat(40)
const REGISTRANT = '0x' + '2'.repeat(40)
const TX_HASH = '0x' + '3'.repeat(64)

function ethAnchorProof(claimHash: string, extra: Record<string, unknown> = {}) {
  return {
    type: 'ethereum-anchor',
    profile: 'urn:screenplay-registration-evidence-ethereum-anchor:v1',
    claimHash,
    chainId: 1,
    contract: CONTRACT,
    registrant: REGISTRANT,
    txHash: TX_HASH,
    logIndex: 2,
    blockNumber: 21345678,
    ...extra,
  }
}

describe('ethereum-anchor proof is tolerated', () => {
  it('validateEnvelope accepts a well-formed ethereum-anchor proof (legacy + shared)', async () => {
    const claim = legacyBuildCommittedClaim({ contentHash: CONTENT_HASH })
    const claimHash = legacyComputeClaimHash(claim)
    const env = legacyBuildEnvelope(claim, { proofs: [ethAnchorProof(claimHash) as any] })

    expect(legacyValidateEnvelope(env).ok).toBe(true)
    expect(sharedValidateEnvelope(env).ok).toBe(true)
  })

  it('unknown proof types remain tolerated (validateEnvelope ok)', () => {
    const claim = legacyBuildCommittedClaim({ contentHash: CONTENT_HASH })
    const claimHash = legacyComputeClaimHash(claim)
    const env = legacyBuildEnvelope(claim, {
      proofs: [
        { type: 'some-future-anchor', claimHash, extra: 'field', nested: { a: 1 } } as any,
      ],
    })
    expect(legacyValidateEnvelope(env).ok).toBe(true)
    expect(sharedValidateEnvelope(env).ok).toBe(true)
  })
})

describe('ethereum-anchor proof does NOT change the committed claim hash', () => {
  it('claim hash with the proof equals bare-claim hash and zero-proofs hash (legacy)', () => {
    const claim = legacyBuildCommittedClaim({ contentHash: CONTENT_HASH })
    const bareHash = legacyComputeClaimHash(claim)
    const zeroProofEnv = legacyBuildEnvelope(claim)
    const withAnchorEnv = legacyBuildEnvelope(claim, {
      proofs: [ethAnchorProof(bareHash) as any],
    })
    expect(legacyComputeClaimHash(zeroProofEnv.committedClaim)).toBe(bareHash)
    expect(legacyComputeClaimHash(withAnchorEnv.committedClaim)).toBe(bareHash)
  })

  it('claim hash with the proof equals bare-claim hash and zero-proofs hash (shared)', async () => {
    const claim = sharedBuildCommittedClaim({ contentHash: CONTENT_HASH })
    const bareHash = await sharedComputeClaimHash(claim)
    const zeroProofEnv = await sharedBuildEnvelope(claim)
    const withAnchorEnv = await sharedBuildEnvelope(claim, {
      proofs: [ethAnchorProof(bareHash) as any],
    })
    expect(await sharedComputeClaimHash(zeroProofEnv.committedClaim)).toBe(bareHash)
    expect(await sharedComputeClaimHash(withAnchorEnv.committedClaim)).toBe(bareHash)
  })
})

describe('envelope consistency rules still bind the ethereum-anchor proof', () => {
  it('a consistent ethereum-anchor envelope passes', () => {
    const claim = legacyBuildCommittedClaim({ contentHash: CONTENT_HASH })
    const claimHash = legacyComputeClaimHash(claim)
    const env = legacyBuildEnvelope(claim, { proofs: [ethAnchorProof(claimHash) as any] })
    expect(legacyCheckEnvelopeConsistency(env, claimHash).ok).toBe(true)
  })

  it("flipping the proof's claimHash trips proof-claim-hash-mismatch", () => {
    const claim = legacyBuildCommittedClaim({ contentHash: CONTENT_HASH })
    const claimHash = legacyComputeClaimHash(claim)
    const env = legacyBuildEnvelope(claim, { proofs: [ethAnchorProof(claimHash) as any] })
    env.evidenceBundle.proofs[0]!.claimHash = 'sha256:' + 'c'.repeat(64)
    const result = legacyCheckEnvelopeConsistency(env, claimHash)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('proof-claim-hash-mismatch')
    }
  })
})

describe('ethereum-anchor proof carrying contentHash is rejected (membership-oracle boundary)', () => {
  it('validateEnvelope is NOT ok for a top-level contentHash (legacy + shared)', () => {
    const claim = legacyBuildCommittedClaim({ contentHash: CONTENT_HASH })
    const claimHash = legacyComputeClaimHash(claim)
    const env = legacyBuildEnvelope(claim, {
      proofs: [ethAnchorProof(claimHash, { contentHash: CONTENT_HASH }) as any],
    })

    const legacyOut = legacyValidateEnvelope(env)
    const sharedOut = sharedValidateEnvelope(env)
    expect(legacyOut.ok).toBe(false)
    expect(sharedOut.ok).toBe(false)
    if (!legacyOut.ok) {
      expect(legacyOut.errors.some((e) => e.includes('contentHash is not permitted'))).toBe(true)
    }
    // legacy and shared must agree byte-for-byte on the error set
    if (!legacyOut.ok && !sharedOut.ok) {
      expect(sharedOut.errors).toEqual(legacyOut.errors)
    }
  })

  it('validateEnvelope is NOT ok for a contentHash nested under batch (legacy + shared)', () => {
    const claim = legacyBuildCommittedClaim({ contentHash: CONTENT_HASH })
    const claimHash = legacyComputeClaimHash(claim)
    const env = legacyBuildEnvelope(claim, {
      proofs: [
        ethAnchorProof(claimHash, {
          batch: { batchId: 'b1', merkleRoot: '0x' + '4'.repeat(64), contentHash: CONTENT_HASH },
        }) as any,
      ],
    })

    const legacyOut = legacyValidateEnvelope(env)
    const sharedOut = sharedValidateEnvelope(env)
    expect(legacyOut.ok).toBe(false)
    expect(sharedOut.ok).toBe(false)
    if (!legacyOut.ok && !sharedOut.ok) {
      expect(sharedOut.errors).toEqual(legacyOut.errors)
    }
  })

  it('a wrong profile const is rejected; a missing required field is rejected', () => {
    const claim = legacyBuildCommittedClaim({ contentHash: CONTENT_HASH })
    const claimHash = legacyComputeClaimHash(claim)

    const wrongProfile = legacyBuildEnvelope(claim, {
      proofs: [ethAnchorProof(claimHash, { profile: 'urn:wrong:v1' }) as any],
    })
    expect(legacyValidateEnvelope(wrongProfile).ok).toBe(false)
    expect(sharedValidateEnvelope(wrongProfile).ok).toBe(false)

    const missingField = ethAnchorProof(claimHash) as Record<string, unknown>
    delete missingField.txHash
    const missing = legacyBuildEnvelope(claim, { proofs: [missingField as any] })
    expect(legacyValidateEnvelope(missing).ok).toBe(false)
    expect(sharedValidateEnvelope(missing).ok).toBe(false)
  })
})
