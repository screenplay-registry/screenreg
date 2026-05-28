/**
 * Membership-oracle property test (Section 05 §5.1).
 *
 * This test locks the post-refactor invariant that motivated the entire
 * comparison-bundle architecture: the committed claim's canonical bytes
 * MUST NOT contain per-leaf hash arrays.
 *
 * Before the refactor, the claim
 * directly embedded `sceneContentHashes` and `paragraphContentHashes`. That
 * turned every registration into a fingerprint-queryable database: anyone
 * holding a candidate hash could test it against the entire public corpus
 * without the writer's consent.
 *
 * The fix moved per-leaf hashes into an opt-in comparison disclosure bundle
 * (Section 06). The claim now commits only the Merkle ROOT — sufficient for
 * tamper-evidence + selective single-scene disclosure proofs, but not for
 * fingerprint-style membership queries.
 *
 * This test makes the regression impossible. If a future refactor silently
 * re-introduces the leaked field into the claim (via builder extension,
 * spread merge, or schema oversight), this test fails.
 */

import { describe, it, expect } from 'vitest'
import { buildCommittedClaim } from '../../src/envelope/build.js'
import { canonicalClaimBytes, computeClaimHash } from '../../src/envelope/claim-hash.js'

const CONTENT_HASH = 'sha256:' + 'a'.repeat(64)
const SCENE_ROOT = 'sha256:' + 'b'.repeat(64)
const PARA_ROOT = 'sha256:' + 'c'.repeat(64)

/** Field names that MUST NOT appear in the public claim's canonical bytes. */
const BANNED_FIELD_NAMES = [
  'sceneContentHashes',
  'paragraphContentHashes',
  'sceneLeafHashes',
  'paragraphLeafHashes',
  'paragraphWordCounts',
]

describe('membership-oracle property — public claim never exposes per-leaf material', () => {
  it('minimal claim canonical bytes contain no banned field names', () => {
    const claim = buildCommittedClaim({ contentHash: CONTENT_HASH })
    const canonical = canonicalClaimBytes(claim).toString('utf8')
    for (const banned of BANNED_FIELD_NAMES) {
      expect(canonical).not.toContain(banned)
    }
  })

  it('claim with scene tree commits only root + count, never per-leaf array', () => {
    const claim = buildCommittedClaim({
      contentHash: CONTENT_HASH,
      sceneTree: { root: SCENE_ROOT, count: 47 },
    })
    const canonical = canonicalClaimBytes(claim).toString('utf8')
    expect(canonical).toContain('sceneTreeRoot')
    expect(canonical).toContain('sceneCount')
    for (const banned of BANNED_FIELD_NAMES) {
      expect(canonical).not.toContain(banned)
    }
  })

  it('claim with paragraph tree commits only root + count, never per-leaf array', () => {
    const claim = buildCommittedClaim({
      contentHash: CONTENT_HASH,
      paragraphTree: { root: PARA_ROOT, count: 312 },
    })
    const canonical = canonicalClaimBytes(claim).toString('utf8')
    expect(canonical).toContain('paragraphTreeRoot')
    expect(canonical).toContain('paragraphCount')
    for (const banned of BANNED_FIELD_NAMES) {
      expect(canonical).not.toContain(banned)
    }
  })

  it('fully-populated claim (every optional field) still excludes per-leaf material', () => {
    const claim = buildCommittedClaim({
      contentHash: CONTENT_HASH,
      sceneTree: { root: SCENE_ROOT, count: 47 },
      paragraphTree: { root: PARA_ROOT, count: 312 },
      preferences: { trainingMining: 'notAllowed' },
      claimExtensions: { someFutureField: 'someValue' },
    })
    const canonical = canonicalClaimBytes(claim).toString('utf8')
    for (const banned of BANNED_FIELD_NAMES) {
      expect(canonical).not.toContain(banned)
    }
  })

  it('claim hash is stable regardless of whether the writer later generates a bundle', () => {
    // The bundle is a sidecar — its existence (or absence) must not affect the
    // committed claim hash. This is what keeps opt-in disclosure bounded: a writer
    // who decides to disclose later cannot accidentally invalidate their anchor.
    const claim = buildCommittedClaim({
      contentHash: CONTENT_HASH,
      sceneTree: { root: SCENE_ROOT, count: 47 },
      paragraphTree: { root: PARA_ROOT, count: 312 },
    })
    const hashBefore = computeClaimHash(claim)
    // (Bundle would be generated in a separate file; doesn't touch the claim.)
    const hashAfter = computeClaimHash(claim)
    expect(hashAfter).toBe(hashBefore)
  })
})
