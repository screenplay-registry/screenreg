/**
 * Comparison Disclosure Bundle (Section 06).
 *
 * A separate file from the manifest. Holds the per-scene + per-paragraph
 * content hashes that were committed in the manifest's Merkle roots but NOT
 * published in the public claim (to avoid the membership-oracle attack).
 *
 * Workflow:
 *   1. Registrant publishes their manifest publicly (only Merkle roots visible)
 *   2. When dispute / comparison is needed, registrant CHOOSES to generate a
 *      comparison bundle revealing the leaves
 *   3. Comparison happens between two bundles (both registrants opted in)
 *
 * Bundle binding (the property that makes bundles trustworthy):
 *
 *   Each layer carries TWO arrays:
 *     - <layer>LeafHashes:    position-BOUND, the actual bottom level of the
 *                             committed Merkle tree. Reducing these via the
 *                             canonical Merkle reduction (Section 03) MUST
 *                             yield <layer>TreeRoot, AND that root MUST
 *                             match the claim's committedClaim.<layer>TreeRoot.
 *                             This is what proves the bundle is bound to the
 *                             committed claim.
 *     - <layer>ContentHashes: position-INDEPENDENT, used for similarity.
 *                             SHA-256 of the layer's content bytes prefixed
 *                             by a domain-separation profile (see scene-tree.ts).
 *
 *   `verifyBundleSelfBinding(bundle)` recomputes each layer's root from its
 *   leaf hashes and checks equality with the bundle's claimed root.
 *   `verifyBundleAgainstClaim(bundle, claim)` further checks that the bundle's
 *   claimHash + tree roots + counts match a specific committed claim.
 *
 * Privacy: the bundle is OPT-IN. Registrants who never generate one keep their
 * leaves private. The threat model is: bundle disclosure is irrevocable (once
 * you publish, the world knows your fingerprints).
 */

import {
  type Scene,
  type Paragraph,
  type BuiltSceneTree,
  type BuiltParagraphTree,
  paragraphContentHash,
  sceneContentHash,
  reduceSceneTreeRoot,
  reduceParagraphTreeRoot,
  leafHashFromContent,
  paragraphLeafHashFromContent,
} from '../merkle/scene-tree.js'
import {
  type CommittedClaim,
  PARAGRAPH_TREE_PROFILE,
  SCENE_TREE_PROFILE,
} from '../envelope/types.js'
import { computeClaimHash } from '../envelope/claim-hash.js'
import {
  SHA256_HASH_PATTERN,
  formatSha256Hash,
  parseSha256Hash,
} from '../util/sha256-hash.js'

export const COMPARISON_BUNDLE_VERSION = 'urn:screenplay-registration-comparison-bundle:v1' as const

/**
 * A comparison disclosure bundle: reveals per-scene + per-paragraph content
 * hashes for a given claim, with the necessary roots + leaf hashes so a
 * verifier can confirm the bundle's claim membership.
 *
 * In v1 the bundle reveals ALL leaves. (Partial disclosure — "only show scenes
 * 3, 5, 17" — is a v1.1 enhancement that requires per-leaf Merkle inclusion
 * proofs rather than the full leaf array.)
 */
export interface ByteRange {
  start: number
  end: number
}

export interface ComparisonBundle {
  bundleVersion: typeof COMPARISON_BUNDLE_VERSION
  /** The claim hash this bundle discloses for. */
  claimHash: string
  /** The committed scene tree root from the manifest (for verifier cross-check). */
  sceneTreeRoot?: string
  sceneCount?: number
  /**
   * Per-scene Merkle LEAF hashes (position-BOUND). Hex-encoded SHA-256 outputs
   * matching the bottom level of the committed scene tree. Used to recompute
   * sceneTreeRoot for binding verification. Length === sceneCount.
   */
  sceneLeafHashes?: string[]
  /**
   * Per-scene byte ranges in the normalized document. Required for
   * binding verification: the verifier recomputes each leaf from
   * (sceneIndex=i, byteStart=sceneByteRanges[i].start, byteEnd=...,
   *  contentHash=sceneContentHashes[i]) and checks against sceneLeafHashes[i].
   * Length === sceneCount.
   */
  sceneByteRanges?: ByteRange[]
  /**
   * Per-scene content hashes (position-INDEPENDENT, domain-separated). Used
   * for similarity. Treated as MULTISET (repeated identical scenes count
   * multiple times). Order preserved for sequence-similarity metrics.
   * Length === sceneCount. Cryptographically bound to the on-chain root via
   * the two-stage chain bytes → content_hash → leaf_hash → ... → root.
   */
  sceneContentHashes?: string[]
  /** The committed paragraph tree root from the manifest. */
  paragraphTreeRoot?: string
  paragraphCount?: number
  /**
   * Per-paragraph Merkle LEAF hashes (position-BOUND). Used to recompute
   * paragraphTreeRoot for binding verification. Length === paragraphCount.
   */
  paragraphLeafHashes?: string[]
  /** Per-paragraph byte ranges; required for binding verification (same as scene layer). */
  paragraphByteRanges?: ByteRange[]
  /**
   * Per-paragraph content hashes (position-INDEPENDENT, domain-separated).
   * Same convention as sceneContentHashes.
   */
  paragraphContentHashes?: string[]
  /**
   * Per-paragraph WORD COUNTS, in document order. Used to compute
   * "coverage-by-words" metric — typically a better single number for a
   * court/journalist than raw Jaccard ratio.
   */
  paragraphWordCounts?: number[]
}

export interface BuildBundleInput {
  claimHash: string
  scenes?: { tree: BuiltSceneTree; scenes: Scene[] }
  paragraphs?: { tree: BuiltParagraphTree; paragraphs: Paragraph[] }
}

export function buildComparisonBundle(input: BuildBundleInput): ComparisonBundle {
  const bundle: ComparisonBundle = {
    bundleVersion: COMPARISON_BUNDLE_VERSION,
    claimHash: input.claimHash,
  }
  if (input.scenes) {
    bundle.sceneTreeRoot = input.scenes.tree.root
    bundle.sceneCount = input.scenes.tree.sceneCount
    bundle.sceneLeafHashes = sliceLeafHashesAsHex(
      input.scenes.tree.levels[0]!,
      input.scenes.tree.sceneCount,
    )
    bundle.sceneByteRanges = input.scenes.scenes.map((s) => ({ start: s.byteStart, end: s.byteEnd }))
    bundle.sceneContentHashes = input.scenes.scenes.map((s) => sceneContentHash(s))
  }
  if (input.paragraphs) {
    bundle.paragraphTreeRoot = input.paragraphs.tree.root
    bundle.paragraphCount = input.paragraphs.tree.paragraphCount
    bundle.paragraphLeafHashes = sliceLeafHashesAsHex(
      input.paragraphs.tree.levels[0]!,
      input.paragraphs.tree.paragraphCount,
    )
    bundle.paragraphByteRanges = input.paragraphs.paragraphs.map((p) => ({
      start: p.byteStart,
      end: p.byteEnd,
    }))
    bundle.paragraphContentHashes = input.paragraphs.paragraphs.map((p) =>
      paragraphContentHash(p.paragraphBytes),
    )
    bundle.paragraphWordCounts = input.paragraphs.paragraphs.map((p) => countWords(p.paragraphBytes))
  }
  return bundle
}

/**
 * Take the bottom Merkle level (which includes padding) and return the real
 * (unpadded) leaf hashes in "sha256:<hex>" form.
 */
function sliceLeafHashesAsHex(bottomLevel: Buffer[], realCount: number): string[] {
  return bottomLevel.slice(0, realCount).map((b) => `sha256:${b.toString('hex')}`)
}

function countWords(paragraphBytes: Buffer): number {
  const text = paragraphBytes.toString('utf8').trim()
  if (text === '') return 0
  return text.split(/\s+/).length
}

// ---------------------------------------------------------------------------
// Binding verification — Section 06 §3
// ---------------------------------------------------------------------------

export type BindingResult =
  | { ok: true }
  | { ok: false; reason: string }

/**
 * Verify the bundle is internally consistent: the version is locked, each
 * layer's leaf-hash array reduces to the declared tree root, and the
 * count/length invariants hold.
 *
 * Does NOT require the claim — pure bundle-self check. Use this in any
 * compareBundles flow so a forged bundle (with fake content hashes) can't
 * produce plausible similarity metrics.
 *
 * Use `verifyBundleAgainstClaim` additionally when you have the claim to
 * confirm the bundle's roots match the on-chain commitment.
 */
export function verifyBundleSelfBinding(bundle: ComparisonBundle): BindingResult {
  if (bundle.bundleVersion !== COMPARISON_BUNDLE_VERSION) {
    return {
      ok: false,
      reason: `unsupported bundleVersion: ${bundle.bundleVersion}`,
    }
  }
  if (!bundle.claimHash || !SHA256_HASH_PATTERN.test(bundle.claimHash)) {
    return { ok: false, reason: `malformed claimHash: ${bundle.claimHash}` }
  }
  // Scene layer. If ANY scene-layer field is present (including count or
  // word-counts), ALL of the binding-bearing fields MUST be present. The
  // chain-binding check + Merkle reduction guarantee fabricated content
  // hashes are caught, but the all-or-none invariant additionally catches
  // orphan-field bundles per spec §06 §2.5.
  if (
    bundle.sceneTreeRoot !== undefined ||
    bundle.sceneCount !== undefined ||
    bundle.sceneLeafHashes !== undefined ||
    bundle.sceneContentHashes !== undefined ||
    bundle.sceneByteRanges !== undefined
  ) {
    const r = verifyLayer({
      label: 'scene',
      root: bundle.sceneTreeRoot,
      count: bundle.sceneCount,
      leafHashes: bundle.sceneLeafHashes,
      byteRanges: bundle.sceneByteRanges,
      contentHashes: bundle.sceneContentHashes,
      reduce: reduceSceneTreeRoot,
      recomputeLeaf: (idx, range, contentBytes) =>
        leafHashFromContent({
          sceneIndex: idx,
          byteStart: range.start,
          byteEnd: range.end,
          contentHashBytes: contentBytes,
        }),
    })
    if (!r.ok) return r
  }
  // Paragraph layer — same all-or-none discipline + same chain-binding check.
  // Includes paragraphCount + paragraphWordCounts in the presence guard so
  // orphan word-counts (no leaves/root) is caught.
  if (
    bundle.paragraphTreeRoot !== undefined ||
    bundle.paragraphCount !== undefined ||
    bundle.paragraphLeafHashes !== undefined ||
    bundle.paragraphContentHashes !== undefined ||
    bundle.paragraphByteRanges !== undefined ||
    bundle.paragraphWordCounts !== undefined
  ) {
    const r = verifyLayer({
      label: 'paragraph',
      root: bundle.paragraphTreeRoot,
      count: bundle.paragraphCount,
      leafHashes: bundle.paragraphLeafHashes,
      byteRanges: bundle.paragraphByteRanges,
      contentHashes: bundle.paragraphContentHashes,
      reduce: reduceParagraphTreeRoot,
      recomputeLeaf: (idx, range, contentBytes) =>
        paragraphLeafHashFromContent({
          paragraphIndex: idx,
          byteStart: range.start,
          byteEnd: range.end,
          contentHashBytes: contentBytes,
        }),
    })
    if (!r.ok) return r
    if (
      bundle.paragraphWordCounts !== undefined &&
      bundle.paragraphCount !== undefined &&
      bundle.paragraphWordCounts.length !== bundle.paragraphCount
    ) {
      return {
        ok: false,
        reason: `paragraphWordCounts.length (${bundle.paragraphWordCounts.length}) !== paragraphCount (${bundle.paragraphCount})`,
      }
    }
  }
  return { ok: true }
}

function verifyLayer(args: {
  label: 'scene' | 'paragraph'
  root: string | undefined
  count: number | undefined
  leafHashes: string[] | undefined
  byteRanges: ByteRange[] | undefined
  contentHashes: string[] | undefined
  reduce: (leafBytes: Buffer[]) => Buffer
  recomputeLeaf: (idx: number, range: ByteRange, contentBytes: Buffer) => Buffer
}): BindingResult {
  const { label, root, count, leafHashes, byteRanges, contentHashes, reduce, recomputeLeaf } = args
  if (
    root === undefined ||
    count === undefined ||
    leafHashes === undefined ||
    byteRanges === undefined ||
    contentHashes === undefined
  ) {
    return {
      ok: false,
      reason: `${label} layer is partially present — root, count, leafHashes, byteRanges, and contentHashes must be all present or all absent`,
    }
  }
  if (leafHashes.length !== count) {
    return {
      ok: false,
      reason: `${label}LeafHashes.length (${leafHashes.length}) !== ${label}Count (${count})`,
    }
  }
  if (byteRanges.length !== count) {
    return {
      ok: false,
      reason: `${label}ByteRanges.length (${byteRanges.length}) !== ${label}Count (${count})`,
    }
  }
  if (contentHashes.length !== count) {
    return {
      ok: false,
      reason: `${label}ContentHashes.length (${contentHashes.length}) !== ${label}Count (${count})`,
    }
  }
  // Per-index: confirm leafHash = recomputeLeaf(idx, byteRange, contentHash).
  // This is the load-bearing check that binds contentHash to leafHash; without
  // it, a forger could keep valid leafHashes and substitute fabricated
  // contentHashes. With it, breaking the chain requires breaking SHA-256.
  const leafBytes: Buffer[] = []
  for (let i = 0; i < leafHashes.length; i++) {
    const declaredLeaf = leafHashes[i]!
    const contentHash = contentHashes[i]!
    if (!SHA256_HASH_PATTERN.test(declaredLeaf)) {
      return { ok: false, reason: `malformed ${label}LeafHashes[${i}]: ${declaredLeaf}` }
    }
    if (!SHA256_HASH_PATTERN.test(contentHash)) {
      return { ok: false, reason: `malformed ${label}ContentHashes[${i}]: ${contentHash}` }
    }
    const range = byteRanges[i]!
    if (!Number.isInteger(range.start) || !Number.isInteger(range.end) || range.start < 0 || range.end < range.start) {
      return { ok: false, reason: `malformed ${label}ByteRanges[${i}]: ${JSON.stringify(range)}` }
    }
    const declaredLeafBytes = parseSha256Hash(declaredLeaf)
    const contentBytes = parseSha256Hash(contentHash)
    const recomputedLeaf = recomputeLeaf(i, range, contentBytes)
    if (!recomputedLeaf.equals(declaredLeafBytes)) {
      return {
        ok: false,
        reason: `${label} leaf chain-binding mismatch at index ${i}: declared ${declaredLeaf}, recomputed ${formatSha256Hash(recomputedLeaf)} from (idx=${i}, byteRange=[${range.start}..${range.end}], contentHash=${contentHash})`,
      }
    }
    leafBytes.push(declaredLeafBytes)
  }
  // After per-leaf chain-binding, reduce leaves to root.
  const recomputed = reduce(leafBytes)
  const recomputedStr = formatSha256Hash(recomputed)
  if (recomputedStr !== root) {
    return {
      ok: false,
      reason: `${label} tree root mismatch: bundle declares ${root}, leaf reduction yields ${recomputedStr}`,
    }
  }
  return { ok: true }
}

/**
 * Verify the bundle binds to a specific committed claim:
 *   - bundle.claimHash === SHA-256 of canonicalized claim
 *   - bundle's tree roots + counts match the claim's committed roots + counts
 *
 * Should be called AFTER `verifyBundleSelfBinding` to first confirm internal
 * consistency.
 */
export function verifyBundleAgainstClaim(
  bundle: ComparisonBundle,
  claim: CommittedClaim,
): BindingResult {
  const expectedHash = computeClaimHash(claim)
  if (bundle.claimHash !== expectedHash) {
    return {
      ok: false,
      reason: `bundle.claimHash (${bundle.claimHash}) !== computed claim hash (${expectedHash})`,
    }
  }
  // Scene layer
  if (bundle.sceneTreeRoot !== undefined) {
    if (claim.sceneTreeProfile !== SCENE_TREE_PROFILE) {
      return {
        ok: false,
        reason: `bundle has scene tree but claim has no sceneTreeProfile`,
      }
    }
    if (claim.sceneTreeRoot !== bundle.sceneTreeRoot) {
      return {
        ok: false,
        reason: `sceneTreeRoot mismatch: bundle=${bundle.sceneTreeRoot} claim=${claim.sceneTreeRoot}`,
      }
    }
    if (claim.sceneCount !== bundle.sceneCount) {
      return {
        ok: false,
        reason: `sceneCount mismatch: bundle=${bundle.sceneCount} claim=${claim.sceneCount}`,
      }
    }
  }
  // Paragraph layer
  if (bundle.paragraphTreeRoot !== undefined) {
    if (claim.paragraphTreeProfile !== PARAGRAPH_TREE_PROFILE) {
      return {
        ok: false,
        reason: `bundle has paragraph tree but claim has no paragraphTreeProfile`,
      }
    }
    if (claim.paragraphTreeRoot !== bundle.paragraphTreeRoot) {
      return {
        ok: false,
        reason: `paragraphTreeRoot mismatch: bundle=${bundle.paragraphTreeRoot} claim=${claim.paragraphTreeRoot}`,
      }
    }
    if (claim.paragraphCount !== bundle.paragraphCount) {
      return {
        ok: false,
        reason: `paragraphCount mismatch: bundle=${bundle.paragraphCount} claim=${claim.paragraphCount}`,
      }
    }
  }
  return { ok: true }
}
