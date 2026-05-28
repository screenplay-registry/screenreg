/**
 * Tests for compareBundles + formatComparisonReport.
 *
 * Operates on OPT-IN ComparisonBundles, NOT on committed claims directly.
 * The refactor moved per-leaf hashes out of the public claim into a separate
 * disclosure bundle (Section 06) so registrations do not double as a public
 * fingerprint queryable database (the "membership oracle attack").
 *
 * Coverage scope:
 *   - Scene-level set Jaccard (back-compat shape from v0.1)
 *   - Multiset Jaccard (new — catches repeated boilerplate copied verbatim)
 *   - Sequence metrics: longestCommonRun + longestCommonSubsequence (new — catches
 *     verbatim-block copying that set Jaccard misses)
 *   - Paragraph-level all of the above (new — robust to global rename)
 *   - Coverage-by-words paragraph metric (new — typically the most legible
 *     single number for a court/journalist)
 *   - exactWholeScriptMatch (claim-hash equality)
 *   - Empty-bundle error path
 */

import { describe, it, expect } from 'vitest'
import { compareBundles, formatComparisonReport } from '../../src/similarity/jaccard.js'
import {
  COMPARISON_BUNDLE_VERSION,
  type ComparisonBundle,
  type ByteRange,
} from '../../src/similarity/comparison-bundle.js'
import {
  reduceSceneTreeRoot,
  reduceParagraphTreeRoot,
  leafHashFromContent,
  paragraphLeafHashFromContent,
} from '../../src/merkle/scene-tree.js'

const HASH_A1 = 'sha256:' + 'a'.repeat(64)
const HASH_A2 = 'sha256:' + 'b'.repeat(64)
const HASH_A3 = 'sha256:' + 'c'.repeat(64)
const HASH_A4 = 'sha256:' + 'd'.repeat(64)
const HASH_A5 = 'sha256:' + 'e'.repeat(64)
const HASH_A6 = 'sha256:' + 'f'.repeat(64)
const HASH_NEW = 'sha256:' + '1'.repeat(64)
const CLAIM_HASH_A = 'sha256:' + '7'.repeat(64)
const CLAIM_HASH_B = 'sha256:' + '8'.repeat(64)

/**
 * Build a fully chain-bound test bundle from a list of opaque content hashes.
 * Per the v1 chain-binding contract (spec §06 §3 + §2.3): the verifier
 * recomputes each leaf from (idx, byteRange, contentHash), then reduces all
 * leaves to the declared root. The helper supplies deterministic byte ranges
 * (idx 0 → [0,10), idx 1 → [10,20), ...) and computes the corresponding leaf
 * hashes so every emitted bundle passes `verifyBundleSelfBinding`.
 *
 * Note: in production, contentHashes derive from raw scene bytes via the
 * SCENE_CONTENT_PROFILE prefix; here we treat contentHashes as opaque inputs
 * because the metrics tests only care about the comparison computation, not
 * the underlying bytes.
 */
function sceneBundle(claimHash: string, sceneContentHashes: string[]): ComparisonBundle {
  const sceneByteRanges = canonicalByteRanges(sceneContentHashes.length)
  const sceneLeafHashes = computeLeafHashes(sceneByteRanges, sceneContentHashes, 'scene')
  const leafBytes = sceneLeafHashes.map(stripSha256Prefix)
  const sceneTreeRoot = `sha256:${reduceSceneTreeRoot(leafBytes).toString('hex')}`
  return {
    bundleVersion: COMPARISON_BUNDLE_VERSION,
    claimHash,
    sceneTreeRoot,
    sceneCount: sceneContentHashes.length,
    sceneLeafHashes,
    sceneByteRanges,
    sceneContentHashes,
  }
}

function paragraphBundle(
  claimHash: string,
  paragraphContentHashes: string[],
  paragraphWordCounts?: number[],
): ComparisonBundle {
  const paragraphByteRanges = canonicalByteRanges(paragraphContentHashes.length)
  const paragraphLeafHashes = computeLeafHashes(paragraphByteRanges, paragraphContentHashes, 'paragraph')
  const leafBytes = paragraphLeafHashes.map(stripSha256Prefix)
  const paragraphTreeRoot = `sha256:${reduceParagraphTreeRoot(leafBytes).toString('hex')}`
  const bundle: ComparisonBundle = {
    bundleVersion: COMPARISON_BUNDLE_VERSION,
    claimHash,
    paragraphTreeRoot,
    paragraphCount: paragraphContentHashes.length,
    paragraphLeafHashes,
    paragraphByteRanges,
    paragraphContentHashes,
  }
  if (paragraphWordCounts) bundle.paragraphWordCounts = paragraphWordCounts
  return bundle
}

function canonicalByteRanges(count: number): ByteRange[] {
  return Array.from({ length: count }, (_, i) => ({ start: i * 10, end: (i + 1) * 10 }))
}

function computeLeafHashes(
  byteRanges: ByteRange[],
  contentHashes: string[],
  layer: 'scene' | 'paragraph',
): string[] {
  return contentHashes.map((ch, i) => {
    const range = byteRanges[i]!
    const contentBytes = stripSha256Prefix(ch)
    const leaf =
      layer === 'scene'
        ? leafHashFromContent({
            sceneIndex: i,
            byteStart: range.start,
            byteEnd: range.end,
            contentHashBytes: contentBytes,
          })
        : paragraphLeafHashFromContent({
            paragraphIndex: i,
            byteStart: range.start,
            byteEnd: range.end,
            contentHashBytes: contentBytes,
          })
    return `sha256:${leaf.toString('hex')}`
  })
}

function stripSha256Prefix(hashString: string): Buffer {
  return Buffer.from(hashString.slice('sha256:'.length), 'hex')
}

// ---------------------------------------------------------------------------
// Scene-level set Jaccard (the v0.1 contract, ported to bundles)
// ---------------------------------------------------------------------------

describe('compareBundles — scene set Jaccard (happy paths)', () => {
  it('identical scripts (same hashes in same order) → exactWholeScriptMatch + 100% Jaccard', () => {
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3])
    const bundleB = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.report.exactWholeScriptMatch).toBe(true)
    expect(result.report.scenes?.set.jaccard).toBe(1)
    expect(result.report.scenes?.set.coverageAInB).toBe(1)
    expect(result.report.scenes?.set.coverageBInA).toBe(1)
    expect(result.report.scenes?.set.shared).toBe(3)
  })

  it('reordered scenes (same set) → 100% set Jaccard (position-independent at set layer)', () => {
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3])
    const bundleB = sceneBundle(CLAIM_HASH_B, [HASH_A3, HASH_A1, HASH_A2])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.report.exactWholeScriptMatch).toBe(false) // different claim hashes
    expect(result.report.scenes?.set.jaccard).toBe(1)
  })

  it('one scene rewritten, others unchanged → Jaccard 0.5', () => {
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3])
    const bundleB = sceneBundle(CLAIM_HASH_B, [HASH_NEW, HASH_A2, HASH_A3])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const set = result.report.scenes!.set
    expect(set.shared).toBe(2)
    expect(set.union).toBe(4) // h1, h2, h3, h1'
    expect(set.jaccard).toBeCloseTo(0.5, 5)
    expect(set.coverageAInB).toBeCloseTo(2 / 3, 5)
    expect(set.coverageBInA).toBeCloseTo(2 / 3, 5)
  })

  it('asymmetric: A is short, B contains all of A plus more → coverageAInB=1', () => {
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3])
    const bundleB = sceneBundle(CLAIM_HASH_B, [HASH_A1, HASH_A2, HASH_A3, HASH_A4, HASH_A5, HASH_A6])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const set = result.report.scenes!.set
    expect(set.shared).toBe(3)
    expect(set.union).toBe(6)
    expect(set.jaccard).toBeCloseTo(0.5, 5)
    expect(set.coverageAInB).toBe(1) // ALL of A appears in B
    expect(set.coverageBInA).toBe(0.5)
  })

  it('completely disjoint → 0% Jaccard, 0% coverage both ways', () => {
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2])
    const bundleB = sceneBundle(CLAIM_HASH_B, [HASH_A3, HASH_A4])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const set = result.report.scenes!.set
    expect(set.shared).toBe(0)
    expect(set.jaccard).toBe(0)
    expect(set.coverageAInB).toBe(0)
    expect(set.coverageBInA).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Multiset Jaccard — the metric that distinguishes set similarity from the
// "copied my boilerplate verbatim 50 times" case. Rule 9: this is WHY the
// refactor exists, not just WHAT it does.
// ---------------------------------------------------------------------------

describe('compareBundles — multiset Jaccard catches repeated-boilerplate reuse', () => {
  it('A has H 5 times, B has H 3 times → multiset shared=3, union=5', () => {
    const H = HASH_A1
    const bundleA = sceneBundle(CLAIM_HASH_A, [H, H, H, H, H])
    const bundleB = sceneBundle(CLAIM_HASH_B, [H, H, H])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.report.scenes!.set.jaccard).toBe(1) // set: {H} ∩ {H} = full
    expect(result.report.scenes!.multiset.multisetSharedCount).toBe(3)
    expect(result.report.scenes!.multiset.multisetUnionCount).toBe(5)
    expect(result.report.scenes!.multiset.multisetJaccard).toBeCloseTo(3 / 5, 5)
  })

  it('multiset Jaccard equals set Jaccard when there are no duplicates', () => {
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3])
    const bundleB = sceneBundle(CLAIM_HASH_B, [HASH_A1, HASH_A2, HASH_NEW])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.report.scenes!.multiset.multisetJaccard).toBeCloseTo(
      result.report.scenes!.set.jaccard,
      5,
    )
  })
})

// ---------------------------------------------------------------------------
// Sequence metrics — longest common run is what catches "I copied the whole
// third act verbatim and changed the names." Set Jaccard would dilute it.
// ---------------------------------------------------------------------------

describe('compareBundles — sequence metrics catch verbatim-block copies', () => {
  it('longestCommonRun finds the largest consecutive matching block', () => {
    // A: [1, 2, 3, 4, 5]; B: [9, 3, 4, 5, 8] — run of 3,4,5 is length 3.
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3, HASH_A4, HASH_A5])
    const bundleB = sceneBundle(CLAIM_HASH_B, [HASH_A6, HASH_A3, HASH_A4, HASH_A5, HASH_NEW])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.report.scenes!.sequence.longestCommonRun).toBe(3)
    expect(result.report.scenes!.sequence.longestCommonRunFraction).toBeCloseTo(3 / 5, 5)
  })

  it('longestCommonSubsequence ≥ longestCommonRun (LCS allows gaps)', () => {
    // A: [1, 2, 3, 4]; B: [1, 9, 2, 9, 3, 9, 4] — LCS=4 (1,2,3,4 in order with gaps); run=1.
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3, HASH_A4])
    const bundleB = sceneBundle(
      CLAIM_HASH_B,
      [HASH_A1, HASH_NEW, HASH_A2, HASH_NEW, HASH_A3, HASH_NEW, HASH_A4],
    )
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.report.scenes!.sequence.longestCommonRun).toBe(1)
    expect(result.report.scenes!.sequence.longestCommonSubsequence).toBe(4)
  })
})

// ---------------------------------------------------------------------------
// Paragraph-level (the layer that's robust to global rename / scene-heading
// adversarial edits) + coverage-by-words.
// ---------------------------------------------------------------------------

describe('compareBundles — paragraph-level + coverage-by-words', () => {
  it('produces paragraph metrics when both bundles have paragraph hashes', () => {
    const bundleA = paragraphBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3], [50, 100, 20])
    const bundleB = paragraphBundle(CLAIM_HASH_B, [HASH_A1, HASH_A2, HASH_NEW], [50, 100, 30])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.report.paragraphs?.set.shared).toBe(2)
    expect(result.report.paragraphs?.set.jaccard).toBeCloseTo(2 / 4, 5)
    // coverage-by-words: A has 170 total words; 150 in matched paragraphs (h1+h2).
    const cw = result.report.paragraphs?.coverageByWords
    expect(cw?.totalWordsA).toBe(170)
    expect(cw?.totalWordsB).toBe(180)
    expect(cw?.sharedWordsInA).toBe(150)
    expect(cw?.sharedWordsInB).toBe(150)
    expect(cw?.coverageAInB).toBeCloseTo(150 / 170, 5)
    expect(cw?.coverageBInA).toBeCloseTo(150 / 180, 5)
  })

  it('omits coverageByWords when paragraphWordCounts is missing from either bundle', () => {
    const bundleA = paragraphBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2])
    const bundleB = paragraphBundle(CLAIM_HASH_B, [HASH_A1, HASH_A2], [10, 20])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.report.paragraphs).toBeDefined()
    expect(result.report.paragraphs?.coverageByWords).toBeUndefined()
  })

  it('paragraph + scene metrics coexist when both layers are populated', () => {
    // Combine the scene + paragraph helpers' outputs into a single bundle.
    const sceneA = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2])
    const paragraphA = paragraphBundle(CLAIM_HASH_A, [HASH_A3, HASH_A4], [50, 50])
    const sceneB = sceneBundle(CLAIM_HASH_B, [HASH_A1, HASH_NEW])
    const paragraphB = paragraphBundle(CLAIM_HASH_B, [HASH_A3, HASH_NEW], [50, 50])
    const bundleA: ComparisonBundle = {
      ...sceneA,
      paragraphTreeRoot: paragraphA.paragraphTreeRoot!,
      paragraphCount: paragraphA.paragraphCount!,
      paragraphLeafHashes: paragraphA.paragraphLeafHashes!,
      paragraphByteRanges: paragraphA.paragraphByteRanges!,
      paragraphContentHashes: paragraphA.paragraphContentHashes!,
      paragraphWordCounts: paragraphA.paragraphWordCounts!,
    }
    const bundleB: ComparisonBundle = {
      ...sceneB,
      paragraphTreeRoot: paragraphB.paragraphTreeRoot!,
      paragraphCount: paragraphB.paragraphCount!,
      paragraphLeafHashes: paragraphB.paragraphLeafHashes!,
      paragraphByteRanges: paragraphB.paragraphByteRanges!,
      paragraphContentHashes: paragraphB.paragraphContentHashes!,
      paragraphWordCounts: paragraphB.paragraphWordCounts!,
    }
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.report.scenes).toBeDefined()
    expect(result.report.paragraphs).toBeDefined()
    expect(result.report.scenes?.set.shared).toBe(1)
    expect(result.report.paragraphs?.set.shared).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Error / empty-bundle paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Binding-failure paths — the central new contract: a bundle whose leaf
// hashes don't reduce to its declared root MUST be rejected before metrics.
// Without this, a malicious party could fabricate contentHashes and the
// similarity report would compute over phantom data.
// ---------------------------------------------------------------------------

describe('compareBundles — bundle binding (Section 06 §3)', () => {
  it('rejects a bundle whose sceneTreeRoot does not match the reduction of its leaf hashes', () => {
    const validBundle = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3])
    const tamperedBundle: ComparisonBundle = {
      ...validBundle,
      // Tamper: replace the declared root with an unrelated hash. Leaf reduction
      // will produce the true root, which won't equal this fabricated one.
      sceneTreeRoot: 'sha256:' + 'f'.repeat(64),
    }
    const otherValid = sceneBundle(CLAIM_HASH_B, [HASH_A1, HASH_A2, HASH_A3])
    const result = compareBundles(tamperedBundle, otherValid)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/bundle A failed self-binding/)
    expect(result.reason).toMatch(/scene tree root mismatch/)
  })

  it('rejects a bundle with orphan sceneContentHashes (no sceneLeafHashes/sceneTreeRoot)', () => {
    // A forger constructs only the array used for metrics, omitting the
    // binding-bearing fields. Without the strict all-or-none guard, this would
    // pass self-binding by virtue of "no scene layer present."
    const orphan: ComparisonBundle = {
      bundleVersion: COMPARISON_BUNDLE_VERSION,
      claimHash: CLAIM_HASH_A,
      sceneContentHashes: [HASH_A1, HASH_A2],
    }
    const otherValid = sceneBundle(CLAIM_HASH_B, [HASH_A1, HASH_A2])
    const result = compareBundles(orphan, otherValid)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/scene layer is partially present/)
  })

  it('rejects a bundle with sceneLeafHashes.length !== sceneCount (truncation/inflation attempt)', () => {
    const valid = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3])
    const lyingCount: ComparisonBundle = { ...valid, sceneCount: 5 }
    const otherValid = sceneBundle(CLAIM_HASH_B, [HASH_A1])
    const result = compareBundles(lyingCount, otherValid)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/sceneLeafHashes\.length \(3\) !== sceneCount \(5\)/)
  })

  it('rejects a bundle with substituted contentHashes that do not chain-bind to leafHashes', () => {
    // Attack case: a malicious bundle keeps valid leafHashes
    // (so leaf reduction → root succeeds AND root matches the on-chain claim),
    // then substitutes fabricated contentHashes to fake similarity. The chain-
    // binding check in verifyLayer catches it: leafHash MUST equal
    // recompute(idx, byteRange, contentHash). Substituted contentHashes break
    // that equation.
    const valid = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3])
    const attack: ComparisonBundle = {
      ...valid,
      // Keep sceneLeafHashes + sceneTreeRoot + sceneByteRanges from `valid`,
      // but substitute the contentHashes with attacker-chosen values.
      sceneContentHashes: [HASH_NEW, HASH_NEW, HASH_NEW],
    }
    const otherValid = sceneBundle(CLAIM_HASH_B, [HASH_A1, HASH_A2, HASH_A3])
    const result = compareBundles(attack, otherValid)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/bundle A failed self-binding/)
    expect(result.reason).toMatch(/scene leaf chain-binding mismatch/)
  })

  it('rejects a bundle with substituted byteRanges (loosens position-binding via the chain)', () => {
    const valid = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2])
    const shifted = valid.sceneByteRanges!.map((r) => ({ start: r.start + 1, end: r.end + 1 }))
    const attack: ComparisonBundle = { ...valid, sceneByteRanges: shifted }
    const otherValid = sceneBundle(CLAIM_HASH_B, [HASH_A1, HASH_A2])
    const result = compareBundles(attack, otherValid)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/scene leaf chain-binding mismatch/)
  })

  it('rejects a bundle with unsupported bundleVersion', () => {
    const valid = sceneBundle(CLAIM_HASH_A, [HASH_A1])
    const wrongVersion = { ...valid, bundleVersion: 'urn:something-else:v2' } as unknown as ComparisonBundle
    const otherValid = sceneBundle(CLAIM_HASH_B, [HASH_A1])
    const result = compareBundles(wrongVersion, otherValid)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/unsupported bundleVersion/)
  })
})

describe('compareBundles — error paths', () => {
  it('returns ok:false with explanatory reason when neither bundle has any content hashes', () => {
    const bundleA: ComparisonBundle = {
      bundleVersion: COMPARISON_BUNDLE_VERSION,
      claimHash: CLAIM_HASH_A,
    }
    const bundleB: ComparisonBundle = {
      bundleVersion: COMPARISON_BUNDLE_VERSION,
      claimHash: CLAIM_HASH_B,
    }
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toMatch(/nothing to compare/i)
    expect(result.reason).toMatch(/disclose-comparison/)
  })

  it('returns ok:false when only one bundle has scene hashes (asymmetric — cannot compare)', () => {
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1])
    const bundleB: ComparisonBundle = {
      bundleVersion: COMPARISON_BUNDLE_VERSION,
      claimHash: CLAIM_HASH_B,
    }
    const result = compareBundles(bundleA, bundleB)
    // With NEITHER layer populated symmetrically + no paragraph hashes,
    // the report has no scenes section AND no paragraphs section → ok:false.
    expect(result.ok).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Human-readable formatter
// ---------------------------------------------------------------------------

describe('formatComparisonReport', () => {
  it('produces the canonical multi-section human-readable output', () => {
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1, HASH_A2, HASH_A3])
    const bundleB = sceneBundle(CLAIM_HASH_B, [HASH_NEW, HASH_A2, HASH_A3])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const report = formatComparisonReport(result.report)
    expect(report).toContain('SCENE-LEVEL')
    expect(report).toContain('Jaccard')
    expect(report).toContain('Coverage:')
    expect(report).toContain('Multiset Jaccard:')
    expect(report).toContain('Longest run:')
    // Caveat about what HIGH/LOW scores mean is non-negotiable for court/journalist use.
    expect(report).toContain('Does NOT measure narrative')
  })

  it('uses provided labels in place of the default A/B', () => {
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1])
    const bundleB = sceneBundle(CLAIM_HASH_B, [HASH_A1])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const report = formatComparisonReport(result.report, { labelA: 'mine.fountain', labelB: 'theirs.fountain' })
    expect(report).toContain('mine.fountain')
    expect(report).toContain('theirs.fountain')
  })

  it('emits the EXACT MATCH banner when claim hashes match', () => {
    const bundleA = sceneBundle(CLAIM_HASH_A, [HASH_A1])
    const bundleB = sceneBundle(CLAIM_HASH_A, [HASH_A1])
    const result = compareBundles(bundleA, bundleB)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const report = formatComparisonReport(result.report)
    expect(report).toContain('EXACT MATCH')
  })
})
