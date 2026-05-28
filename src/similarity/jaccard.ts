/**
 * Comparison metrics between two ComparisonBundles (Section 06).
 *
 * Operates on opt-in COMPARISON DISCLOSURE BUNDLES, NOT directly on manifests.
 * Manifests commit only Merkle ROOTS; the actual per-scene + per-paragraph
 * content hashes are revealed only when a registrant chooses to publish a
 * comparison bundle.
 *
 * Reports a richer set of metrics than raw Jaccard, per the design review
 * convergence: courts/journalists/writers find these more legible:
 *
 *   - exactWholeScriptMatch (boolean, via claimHash equality)
 *   - sceneSetJaccard / sceneSetCoverages (discovery-oriented; deduplicates repeats)
 *   - sceneMultisetJaccard (evidence-oriented; preserves repeated-scene signal)
 *   - sceneSequenceLcs (structure-oriented; longest common run preserved order)
 *   - paragraph variants of all three
 *   - paragraphCoverageByWords (typically the most legible single number)
 */

import { type ComparisonBundle, verifyBundleSelfBinding } from './comparison-bundle.js'

// ---------------------------------------------------------------------------
// Sub-metric types
// ---------------------------------------------------------------------------

export interface JaccardMetric {
  /** Count of distinct items in A (deduplicated; multiset entries collapsed). */
  countA: number
  countB: number
  shared: number
  union: number
  jaccard: number
  coverageAInB: number
  coverageBInA: number
}

export interface MultisetMetric extends JaccardMetric {
  /**
   * Multiset version: if A has paragraph H 5 times and B has it 3 times,
   * intersection counts it 3 times (min), union counts 5 (max).
   * Catches "lots of repeated boilerplate copied verbatim" that set Jaccard misses.
   */
  multisetSharedCount: number
  multisetUnionCount: number
  multisetJaccard: number
}

export interface SequenceMetric {
  /** Length of the longest common consecutive RUN in the two ordered sequences. */
  longestCommonRun: number
  /** Length of the longest common SUBSEQUENCE (may have gaps). */
  longestCommonSubsequence: number
  /** As a fraction of the shorter sequence. */
  longestCommonRunFraction: number
  longestCommonSubsequenceFraction: number
}

export interface CoverageByWordsMetric {
  /** Total words in A, B (sum of paragraph word counts). */
  totalWordsA: number
  totalWordsB: number
  /** Words in A's matched paragraphs (paragraphs whose content hash is in B). */
  sharedWordsInA: number
  sharedWordsInB: number
  /** Coverage fractions. */
  coverageAInB: number
  coverageBInA: number
}

export interface ComparisonReport {
  /** True iff claimHash matches exactly (same registration). */
  exactWholeScriptMatch: boolean
  /** Scene-level metrics (present iff both bundles have scene content hashes). */
  scenes?: {
    set: JaccardMetric
    multiset: Omit<MultisetMetric, keyof JaccardMetric>
    sequence: SequenceMetric
  }
  /** Paragraph-level metrics (present iff both bundles have paragraph content hashes). */
  paragraphs?: {
    set: JaccardMetric
    multiset: Omit<MultisetMetric, keyof JaccardMetric>
    sequence: SequenceMetric
    coverageByWords?: CoverageByWordsMetric
  }
}

export type ComparisonResult =
  | { ok: true; report: ComparisonReport }
  | { ok: false; reason: string }

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export function compareBundles(
  bundleA: ComparisonBundle,
  bundleB: ComparisonBundle,
): ComparisonResult {
  // Section 06 §3 + §5: binding verification BEFORE metrics. A bundle whose
  // leaf hashes don't reduce to its declared root could carry fabricated
  // content hashes and produce plausible-looking but meaningless metrics.
  // Refuse to compute similarity in that case.
  const aBinding = verifyBundleSelfBinding(bundleA)
  if (!aBinding.ok) {
    return { ok: false, reason: `bundle A failed self-binding: ${aBinding.reason}` }
  }
  const bBinding = verifyBundleSelfBinding(bundleB)
  if (!bBinding.ok) {
    return { ok: false, reason: `bundle B failed self-binding: ${bBinding.reason}` }
  }

  const report: ComparisonReport = {
    exactWholeScriptMatch: bundleA.claimHash === bundleB.claimHash,
  }

  // Scene-level: requires BOTH bundles have scene hashes
  if (bundleA.sceneContentHashes && bundleB.sceneContentHashes) {
    const set = computeJaccard(bundleA.sceneContentHashes, bundleB.sceneContentHashes)
    const multisetCounts = computeMultiset(bundleA.sceneContentHashes, bundleB.sceneContentHashes)
    const sequence = computeSequenceMetrics(bundleA.sceneContentHashes, bundleB.sceneContentHashes)
    report.scenes = { set, multiset: multisetCounts, sequence }
  }

  // Paragraph-level: requires BOTH bundles have paragraph hashes
  if (bundleA.paragraphContentHashes && bundleB.paragraphContentHashes) {
    const set = computeJaccard(bundleA.paragraphContentHashes, bundleB.paragraphContentHashes)
    const multisetCounts = computeMultiset(
      bundleA.paragraphContentHashes,
      bundleB.paragraphContentHashes,
    )
    const sequence = computeSequenceMetrics(
      bundleA.paragraphContentHashes,
      bundleB.paragraphContentHashes,
    )
    const paragraphReport: NonNullable<ComparisonReport['paragraphs']> = {
      set,
      multiset: multisetCounts,
      sequence,
    }
    // Coverage-by-words requires word-counts in both bundles
    if (bundleA.paragraphWordCounts && bundleB.paragraphWordCounts) {
      paragraphReport.coverageByWords = computeCoverageByWords(
        bundleA.paragraphContentHashes,
        bundleA.paragraphWordCounts,
        bundleB.paragraphContentHashes,
        bundleB.paragraphWordCounts,
      )
    }
    report.paragraphs = paragraphReport
  }

  if (!report.scenes && !report.paragraphs) {
    return {
      ok: false,
      reason:
        'neither bundle has scene or paragraph content hashes — nothing to compare. Generate disclosure bundles with `screenreg disclose-comparison` first.',
    }
  }

  return { ok: true, report }
}

// ---------------------------------------------------------------------------
// Metric primitives
// ---------------------------------------------------------------------------

function computeJaccard(a: string[], b: string[]): JaccardMetric {
  const setA = new Set(a)
  const setB = new Set(b)
  let shared = 0
  for (const h of setA) if (setB.has(h)) shared++
  const countA = setA.size
  const countB = setB.size
  const union = countA + countB - shared
  return {
    countA,
    countB,
    shared,
    union,
    jaccard: union === 0 ? 0 : shared / union,
    coverageAInB: countA === 0 ? 0 : shared / countA,
    coverageBInA: countB === 0 ? 0 : shared / countB,
  }
}

function computeMultiset(
  a: string[],
  b: string[],
): Omit<MultisetMetric, keyof JaccardMetric> {
  const countsA = countMultiset(a)
  const countsB = countMultiset(b)
  let sharedCount = 0
  let unionCount = 0
  const keys = new Set([...countsA.keys(), ...countsB.keys()])
  for (const k of keys) {
    const ca = countsA.get(k) ?? 0
    const cb = countsB.get(k) ?? 0
    sharedCount += Math.min(ca, cb)
    unionCount += Math.max(ca, cb)
  }
  return {
    multisetSharedCount: sharedCount,
    multisetUnionCount: unionCount,
    multisetJaccard: unionCount === 0 ? 0 : sharedCount / unionCount,
  }
}

function countMultiset(items: string[]): Map<string, number> {
  const m = new Map<string, number>()
  for (const x of items) m.set(x, (m.get(x) ?? 0) + 1)
  return m
}

/**
 * Sequence metrics over ordered hash arrays.
 *
 * - longestCommonRun: longest CONSECUTIVE matching subsequence (preserves order
 *   AND adjacency). Catches "I copied the entire third act verbatim."
 * - longestCommonSubsequence: longest matching subsequence, gaps allowed.
 *   Catches "I copied scenes 1, 5, 7 in order even though the rest is different."
 */
function computeSequenceMetrics(a: string[], b: string[]): SequenceMetric {
  const lcr = longestCommonRun(a, b)
  const lcs = longestCommonSubsequence(a, b)
  const minLen = Math.min(a.length, b.length)
  return {
    longestCommonRun: lcr,
    longestCommonSubsequence: lcs,
    longestCommonRunFraction: minLen === 0 ? 0 : lcr / minLen,
    longestCommonSubsequenceFraction: minLen === 0 ? 0 : lcs / minLen,
  }
}

function longestCommonRun(a: string[], b: string[]): number {
  if (a.length === 0 || b.length === 0) return 0
  const n = a.length
  const m = b.length
  // O(n*m) DP. For typical screenplays (10-200 scenes, 200-2000 paragraphs)
  // this is fine. For huge inputs, switch to suffix-automaton or rolling hash.
  let best = 0
  let prev = new Int32Array(m + 1)
  for (let i = 1; i <= n; i++) {
    const cur = new Int32Array(m + 1)
    for (let j = 1; j <= m; j++) {
      if (a[i - 1] === b[j - 1]) {
        cur[j] = prev[j - 1]! + 1
        if (cur[j]! > best) best = cur[j]!
      }
    }
    prev = cur
  }
  return best
}

function longestCommonSubsequence(a: string[], b: string[]): number {
  if (a.length === 0 || b.length === 0) return 0
  const n = a.length
  const m = b.length
  let prev = new Int32Array(m + 1)
  for (let i = 1; i <= n; i++) {
    const cur = new Int32Array(m + 1)
    for (let j = 1; j <= m; j++) {
      if (a[i - 1] === b[j - 1]) {
        cur[j] = prev[j - 1]! + 1
      } else {
        cur[j] = Math.max(prev[j]!, cur[j - 1]!)
      }
    }
    prev = cur
  }
  return prev[m]!
}

function computeCoverageByWords(
  hashesA: string[],
  wordsA: number[],
  hashesB: string[],
  wordsB: number[],
): CoverageByWordsMetric {
  if (hashesA.length !== wordsA.length) {
    throw new Error(`hashesA/wordsA length mismatch: ${hashesA.length} vs ${wordsA.length}`)
  }
  if (hashesB.length !== wordsB.length) {
    throw new Error(`hashesB/wordsB length mismatch: ${hashesB.length} vs ${wordsB.length}`)
  }
  const setA = new Set(hashesA)
  const setB = new Set(hashesB)
  let totalWordsA = 0
  let totalWordsB = 0
  let sharedWordsInA = 0
  let sharedWordsInB = 0
  for (let i = 0; i < hashesA.length; i++) {
    totalWordsA += wordsA[i]!
    if (setB.has(hashesA[i]!)) sharedWordsInA += wordsA[i]!
  }
  for (let i = 0; i < hashesB.length; i++) {
    totalWordsB += wordsB[i]!
    if (setA.has(hashesB[i]!)) sharedWordsInB += wordsB[i]!
  }
  return {
    totalWordsA,
    totalWordsB,
    sharedWordsInA,
    sharedWordsInB,
    coverageAInB: totalWordsA === 0 ? 0 : sharedWordsInA / totalWordsA,
    coverageBInA: totalWordsB === 0 ? 0 : sharedWordsInB / totalWordsB,
  }
}

// ---------------------------------------------------------------------------
// Human-readable formatter
//
// Moved to src/similarity/report-formatter.ts so the metric math stays
// presentation-free. Re-exported here for backwards-compat — existing callers
// importing `formatComparisonReport` from this module continue to work.
// ---------------------------------------------------------------------------

export {
  formatComparisonReport,
  type FormatComparisonReportOptions,
} from './report-formatter.js'
