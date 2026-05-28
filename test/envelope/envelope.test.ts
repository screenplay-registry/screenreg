/**
 * Envelope / committed-claim / claim-hash / consistency-check tests.
 *
 * Asserts:
 *  - Vector-driven correctness for builder + canonicalize + claimHash
 *  - Forward-compatibility property: changing evidenceBundle does NOT change claimHash
 *  - Verifier consistency rules per spec §4.2 (tampered bundles rejected)
 *  - Presence vs absence of optional fields produces different hashes
 */

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  buildCommittedClaim,
  buildEnvelope,
  checkEnvelopeConsistency,
} from '../../src/envelope/build.js'
import { computeClaimHash, canonicalClaimBytes } from '../../src/envelope/claim-hash.js'
import {
  CLAIM_VERSION,
  SCHEMA_ID,
  HASH_ALGORITHM,
  MANIFEST_CANONICALIZATION,
  NORMALIZATION_PROFILE,
  SCENE_TREE_PROFILE,
  ENVELOPE_VERSION,
} from '../../src/envelope/types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CORPUS_DIR = join(__dirname, '..', '..', 'spec', 'v1', 'testvectors', 'envelope')

const HASH_A = 'sha256:' + 'a'.repeat(64)
const HASH_B = 'sha256:' + 'b'.repeat(64)
const HASH_C = 'sha256:' + 'c'.repeat(64)

interface IndexFile {
  canonVectors: Array<{ id: string; name: string; description: string }>
  envelopeVectors: Array<{ id: string; name: string; description: string }>
}

const indexJson = JSON.parse(readFileSync(join(CORPUS_DIR, 'INDEX.json'), 'utf8')) as IndexFile

// ---------------------------------------------------------------------------
// Vector-driven correctness
// ---------------------------------------------------------------------------

describe('envelope vector corpus', () => {
  for (const v of indexJson.envelopeVectors) {
    const prefix = `env-${v.id}-${v.name}`
    it(`${v.id} ${v.name}: canonical bytes match`, () => {
      const expected = readFileSync(join(CORPUS_DIR, `${prefix}.canonical.bin`))
      const valueJson = readFileSync(join(CORPUS_DIR, `${prefix}.value.json`), 'utf8')
      const value = JSON.parse(valueJson)
      const actual = canonicalClaimBytes(
        value.committedClaim ?? value,
      )
      // The vector's canonical.bin file contains the canonical form of the
      // ENTIRE value (envelope or claim). For envelope vectors we recompute
      // the canonical bytes of the COMMITTED CLAIM only and assert the hash
      // matches the recorded claim-hash.txt; for claim-only vectors we
      // assert the canonical bytes directly.
      if (value.committedClaim) {
        // envelope vector — verify the stored claim-hash matches our recomputation
        const expectedHash = readFileSync(
          join(CORPUS_DIR, `${prefix}.claim-hash.txt`),
          'utf8',
        ).trim()
        const computed = computeClaimHash(value.committedClaim)
        expect(computed).toBe(expectedHash)
      } else {
        // claim-only vector — verify canonical bytes directly
        expect(actual.equals(expected)).toBe(true)
      }
    })
  }
})

// ---------------------------------------------------------------------------
// Locked-value sanity
// ---------------------------------------------------------------------------

describe('locked commitment-bearing identifiers', () => {
  it('all URN/profile constants match spec exactly', () => {
    expect(CLAIM_VERSION).toBe('urn:screenplay-registration-claim:v1')
    expect(SCHEMA_ID).toBe('urn:screenplay-registration-claim-schema:v1')
    expect(HASH_ALGORITHM).toBe('sha-256')
    expect(MANIFEST_CANONICALIZATION).toBe('rfc8785')
    expect(NORMALIZATION_PROFILE).toBe('screenplay-registration-norm/v1-strict')
    expect(SCENE_TREE_PROFILE).toBe('screenplay-registration-merkle/v1')
    expect(ENVELOPE_VERSION).toBe('urn:screenplay-registration-envelope:v1')
  })

  it('buildCommittedClaim sets all locked identifiers correctly', () => {
    const claim = buildCommittedClaim({ contentHash: HASH_A })
    expect(claim.claimVersion).toBe(CLAIM_VERSION)
    expect(claim.schemaId).toBe(SCHEMA_ID)
    expect(claim.hashAlgorithm).toBe(HASH_ALGORITHM)
    expect(claim.manifestCanonicalization).toBe(MANIFEST_CANONICALIZATION)
    expect(claim.normalizationProfile).toBe(NORMALIZATION_PROFILE)
  })

  it('claimExtensions is always present (empty by default)', () => {
    const claim = buildCommittedClaim({ contentHash: HASH_A })
    expect(claim.claimExtensions).toBeDefined()
    expect(claim.claimExtensions).toEqual({})
  })
})

// ---------------------------------------------------------------------------
// Scene-tree presence rules (all three fields together)
// ---------------------------------------------------------------------------

describe('scene-tree fields: all-or-none', () => {
  it('builder sets all three when sceneTree is provided', () => {
    const claim = buildCommittedClaim({
      contentHash: HASH_A,
      sceneTree: { root: HASH_B, count: 12 },
    })
    expect(claim.sceneTreeProfile).toBe(SCENE_TREE_PROFILE)
    expect(claim.sceneTreeRoot).toBe(HASH_B)
    expect(claim.sceneCount).toBe(12)
  })

  it('builder omits all three when sceneTree is omitted', () => {
    const claim = buildCommittedClaim({ contentHash: HASH_A })
    expect(claim.sceneTreeProfile).toBeUndefined()
    expect(claim.sceneTreeRoot).toBeUndefined()
    expect(claim.sceneCount).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Hash properties: presence/absence matters; insertion order doesn't
// ---------------------------------------------------------------------------

describe('claim hash: presence vs absence is commitment-bearing', () => {
  it('two claims differing ONLY by absence/presence of preferences produce different hashes', () => {
    const a = buildCommittedClaim({ contentHash: HASH_A })
    const b = buildCommittedClaim({ contentHash: HASH_A, preferences: {} })
    expect(computeClaimHash(a)).not.toBe(computeClaimHash(b))
  })

  it('two claims differing ONLY by absence/presence of scene-tree produce different hashes', () => {
    const a = buildCommittedClaim({ contentHash: HASH_A })
    const b = buildCommittedClaim({ contentHash: HASH_A, sceneTree: { root: HASH_B, count: 0 } })
    expect(computeClaimHash(a)).not.toBe(computeClaimHash(b))
  })

  it('two semantically identical claims produce identical hashes regardless of build order', () => {
    const a = buildCommittedClaim({
      contentHash: HASH_A,
      sceneTree: { root: HASH_B, count: 5 },
      preferences: { trainingMining: 'notAllowed' },
    })
    // Build a manually-constructed claim with fields in a different insertion order.
    // Per the post-refactor schema, per-leaf hashes (sceneContentHashes) are NOT in
    // the committed claim — they live in the opt-in comparison disclosure bundle.
    const b = {
      preferences: { trainingMining: 'notAllowed' },
      sceneCount: 5,
      sceneTreeRoot: HASH_B,
      sceneTreeProfile: SCENE_TREE_PROFILE,
      claimExtensions: {},
      contentHash: HASH_A,
      normalizationProfile: NORMALIZATION_PROFILE,
      manifestCanonicalization: MANIFEST_CANONICALIZATION,
      hashAlgorithm: HASH_ALGORITHM,
      schemaId: SCHEMA_ID,
      claimVersion: CLAIM_VERSION,
    } as any
    expect(computeClaimHash(a)).toBe(computeClaimHash(b))
  })
})

// ---------------------------------------------------------------------------
// Forward-compatibility: changing evidenceBundle does NOT change claimHash
// ---------------------------------------------------------------------------

describe('forward-compatibility: evidenceBundle mutations preserve claimHash', () => {
  it('adding proofs to evidenceBundle does not change the committed claim hash', () => {
    const claim = buildCommittedClaim({ contentHash: HASH_A })
    const hashBefore = computeClaimHash(claim)

    const env1 = buildEnvelope(claim)
    const env2 = buildEnvelope(claim, {
      proofs: [
        { type: 'opentimestamps', claimHash: hashBefore, proofRef: 'a.ots' },
      ],
    })
    const env3 = buildEnvelope(claim, {
      proofs: [
        { type: 'opentimestamps', claimHash: hashBefore, proofRef: 'a.ots' },
        { type: 'opentimestamps', claimHash: hashBefore, proofRef: 'b.ots' },
        { type: 'eas-attestation', claimHash: hashBefore, attestationUid: '0x123' } as any,
      ],
    })

    expect(computeClaimHash(env1.committedClaim)).toBe(hashBefore)
    expect(computeClaimHash(env2.committedClaim)).toBe(hashBefore)
    expect(computeClaimHash(env3.committedClaim)).toBe(hashBefore)
  })

  it('adding bundleExtensions does not change the committed claim hash', () => {
    const claim = buildCommittedClaim({ contentHash: HASH_A })
    const hashBefore = computeClaimHash(claim)
    const env = buildEnvelope(claim, {
      bundleExtensions: { someTooling: 'wrote-this', timestamp: '2026-05-26' },
    })
    expect(computeClaimHash(env.committedClaim)).toBe(hashBefore)
  })
})

// ---------------------------------------------------------------------------
// Verifier consistency rules (spec §4.2)
// ---------------------------------------------------------------------------

describe('verifier consistency rules', () => {
  it('passes a valid, untampered envelope', () => {
    const claim = buildCommittedClaim({ contentHash: HASH_A })
    const env = buildEnvelope(claim, {
      proofs: [
        { type: 'opentimestamps', claimHash: computeClaimHash(claim), proofRef: 'a.ots' },
      ],
    })
    const result = checkEnvelopeConsistency(env, computeClaimHash(claim))
    expect(result.ok).toBe(true)
  })

  it('rejects envelope where committedClaimHash does not match the recomputed claim hash', () => {
    const claim = buildCommittedClaim({ contentHash: HASH_A })
    const env = buildEnvelope(claim)
    // tamper: pretend the bundle says a different hash
    env.evidenceBundle.committedClaimHash = HASH_C
    const result = checkEnvelopeConsistency(env, computeClaimHash(claim))
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('claim-hash-mismatch')
    }
  })

  it("rejects envelope where any proof's claimHash does not match", () => {
    const claim = buildCommittedClaim({ contentHash: HASH_A })
    const realHash = computeClaimHash(claim)
    const env = buildEnvelope(claim, {
      proofs: [
        { type: 'opentimestamps', claimHash: realHash, proofRef: 'a.ots' },
        // poison: this proof's claimHash is wrong
        { type: 'opentimestamps', claimHash: HASH_C, proofRef: 'b.ots' },
      ],
    })
    const result = checkEnvelopeConsistency(env, realHash)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('proof-claim-hash-mismatch')
    }
  })

  it('rejects envelope with wrong envelopeVersion', () => {
    const claim = buildCommittedClaim({ contentHash: HASH_A })
    const env = buildEnvelope(claim)
    ;(env as any).envelopeVersion = 'urn:screenplay-registration-envelope:v2'
    const result = checkEnvelopeConsistency(env, computeClaimHash(claim))
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('envelope-version-mismatch')
    }
  })

  it('rejects envelope where committedClaim itself was tampered after hash was recorded', () => {
    // Build a legit envelope
    const claim = buildCommittedClaim({ contentHash: HASH_A })
    const env = buildEnvelope(claim)
    const originalHash = env.evidenceBundle.committedClaimHash

    // Tamper: change the content hash inside committedClaim
    env.committedClaim.contentHash = HASH_B
    // The evidenceBundle still has the OLD claimHash — verifier should recompute and reject
    const recomputed = computeClaimHash(env.committedClaim)
    expect(recomputed).not.toBe(originalHash)
    const result = checkEnvelopeConsistency(env, recomputed)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('claim-hash-mismatch')
    }
  })
})
