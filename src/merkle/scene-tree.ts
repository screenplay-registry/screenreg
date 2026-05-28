/**
 * Reference implementation of `screenplay-registration-merkle/v1` (Section 03).
 *
 * Scene detection + scene Merkle tree + selective-disclosure proof.
 *
 * Paragraph-tree code moved to `./paragraph-tree.ts` (Section 03 §3.6); shared
 * primitives moved to `./primitives.ts`. This module re-exports both for
 * backwards-compat — existing imports of `paragraphContentHash`,
 * `buildParagraphTree`, `reduceParagraphTreeRoot`, etc. from
 * `'./merkle/scene-tree.js'` continue to work, but new code should import
 * from the variant-specific modules directly.
 */

import { createHash } from 'node:crypto'
import {
  makeParentHash,
  makePaddingHash,
  reduceMerkleRoot,
  nextPowerOfTwo as nextPowerOfTwoShared,
} from './primitives.js'

export const PROFILE_ID = 'screenplay-registration-merkle/v1' as const
export const SCENE_CONTENT_PROFILE = 'screenplay-registration-scene-content/v1' as const

// Domain tags per spec §3.1, §3.2, §3.4. `as const` narrows to literal types
// so misuse (e.g. passing a paragraph tag) is a type error.
const DOMAIN_LEAF = 0x00 as const
const DOMAIN_PARENT = 0x01 as const
const DOMAIN_PADDING = 0x02 as const

const PROFILE_BYTES = Buffer.from(PROFILE_ID, 'utf8')
const SCENE_CONTENT_PROFILE_BYTES = Buffer.from(SCENE_CONTENT_PROFILE, 'utf8')

const PADDING_HASH: Buffer = makePaddingHash(DOMAIN_PADDING)
export const parentHash = makeParentHash(DOMAIN_PARENT)

// `nextPowerOfTwo` re-exported for callers that previously imported it from this module.
export const nextPowerOfTwo = nextPowerOfTwoShared

// ---------------------------------------------------------------------------
// Scene detection
// ---------------------------------------------------------------------------

const HEADING_PREFIXES = [
  'INT.',
  'INT/EXT.',
  'EXT.',
  'EST.',
  'I/E.',
  'E/I.',
] as const

export interface Scene {
  sceneIndex: number
  byteStart: number
  byteEnd: number
  /** A view into the normalized bytes; do not mutate. */
  sceneBytes: Buffer
}

/**
 * Detect scenes in normalized Fountain bytes per spec §2.
 *
 * - Heading must be at byte 0 OR follow an LF (0x0A).
 * - Prefix matched case-insensitively, followed by space/hyphen/end-of-line.
 * - Preamble bytes before the first heading are NOT a scene leaf in v1.
 */
export function detectScenes(normalized: Buffer): Scene[] {
  const headingPositions: number[] = []
  const n = normalized.length

  for (let i = 0; i < n; i++) {
    const isLineStart = i === 0 || normalized[i - 1] === 0x0a
    if (!isLineStart) continue
    for (const prefix of HEADING_PREFIXES) {
      const prefixLen = prefix.length
      if (i + prefixLen > n) continue
      const slice = normalized.subarray(i, i + prefixLen).toString('utf8')
      if (slice.toUpperCase() !== prefix) continue
      const nextChar = i + prefixLen < n ? normalized[i + prefixLen]! : -1
      if (
        nextChar === 0x20 || // space
        nextChar === 0x2d || // -
        nextChar === 0x0a || // LF
        nextChar === -1 // end of file
      ) {
        headingPositions.push(i)
        break
      }
    }
  }

  const scenes: Scene[] = []
  for (let i = 0; i < headingPositions.length; i++) {
    const start = headingPositions[i]!
    const end = i + 1 < headingPositions.length ? headingPositions[i + 1]! : n
    scenes.push({
      sceneIndex: i,
      byteStart: start,
      byteEnd: end,
      sceneBytes: normalized.subarray(start, end),
    })
  }
  return scenes
}

// ---------------------------------------------------------------------------
// Scene content hash (Section 05/06) — position-INDEPENDENT, domain-separated
// ---------------------------------------------------------------------------

export function sceneContentHash(scene: Scene): string {
  return `sha256:${sceneContentHashBytes(scene).toString('hex')}`
}

export function sceneContentHashBytes(scene: Scene): Buffer {
  const h = createHash('sha256')
  h.update(SCENE_CONTENT_PROFILE_BYTES)
  h.update(scene.sceneBytes)
  return h.digest()
}

export function computeSceneContentHashes(scenes: Scene[]): string[] {
  return scenes.map(sceneContentHash)
}

// ---------------------------------------------------------------------------
// Scene leaf hash (Section 03 §3.1 — two-stage chain through content_hash)
// ---------------------------------------------------------------------------

export function leafHash(scene: Scene): Buffer {
  return leafHashFromContent({
    sceneIndex: scene.sceneIndex,
    byteStart: scene.byteStart,
    byteEnd: scene.byteEnd,
    contentHashBytes: sceneContentHashBytes(scene),
  })
}

export function leafHashFromContent(input: {
  sceneIndex: number
  byteStart: number
  byteEnd: number
  contentHashBytes: Buffer
}): Buffer {
  if (input.contentHashBytes.length !== 32) {
    throw new Error(`leafHashFromContent: contentHashBytes must be 32 bytes, got ${input.contentHashBytes.length}`)
  }
  const sceneIndexBuf = Buffer.alloc(4)
  sceneIndexBuf.writeUInt32BE(input.sceneIndex, 0)
  const byteStartBuf = Buffer.alloc(8)
  byteStartBuf.writeBigUInt64BE(BigInt(input.byteStart), 0)
  const byteEndBuf = Buffer.alloc(8)
  byteEndBuf.writeBigUInt64BE(BigInt(input.byteEnd), 0)

  const h = createHash('sha256')
  h.update(Buffer.from([DOMAIN_LEAF]))
  h.update(PROFILE_BYTES)
  h.update(sceneIndexBuf)
  h.update(byteStartBuf)
  h.update(byteEndBuf)
  h.update(input.contentHashBytes)
  return h.digest()
}

// ---------------------------------------------------------------------------
// Scene tree construction
// ---------------------------------------------------------------------------

export interface BuiltSceneTree {
  rootBytes: Buffer
  root: string
  sceneCount: number
  depth: number
  levels: Buffer[][]
  paddedLeafCount: number
}

export function buildSceneTree(scenes: Scene[]): BuiltSceneTree {
  const sceneCount = scenes.length
  if (sceneCount === 0) {
    return {
      rootBytes: PADDING_HASH,
      root: `sha256:${PADDING_HASH.toString('hex')}`,
      sceneCount: 0,
      depth: 0,
      levels: [[PADDING_HASH]],
      paddedLeafCount: 1,
    }
  }
  for (let i = 0; i < scenes.length; i++) {
    if (scenes[i]!.sceneIndex !== i) {
      throw new Error(
        `buildSceneTree: scene at position ${i} has sceneIndex=${scenes[i]!.sceneIndex}; expected ${i}`,
      )
    }
  }

  const paddedLeafCount = nextPowerOfTwo(sceneCount)
  const leaves: Buffer[] = []
  for (const scene of scenes) leaves.push(leafHash(scene))
  for (let i = sceneCount; i < paddedLeafCount; i++) leaves.push(PADDING_HASH)

  const levels: Buffer[][] = [leaves]
  let depth = 0
  while (levels[levels.length - 1]!.length > 1) {
    const cur = levels[levels.length - 1]!
    const next: Buffer[] = []
    for (let i = 0; i < cur.length; i += 2) {
      next.push(parentHash(cur[i]!, cur[i + 1]!))
    }
    levels.push(next)
    depth++
  }

  const rootBytes = levels[levels.length - 1]![0]!
  return {
    rootBytes,
    root: `sha256:${rootBytes.toString('hex')}`,
    sceneCount,
    depth,
    levels,
    paddedLeafCount,
  }
}

/** Reduce a list of scene leaf hashes to the committed root. */
export function reduceSceneTreeRoot(leafHashes: Buffer[]): Buffer {
  return reduceMerkleRoot(leafHashes, PADDING_HASH, parentHash)
}

// ---------------------------------------------------------------------------
// Selective-disclosure proofs (Section 04)
// ---------------------------------------------------------------------------

export interface SceneProof {
  sceneTreeProfile: typeof PROFILE_ID
  sceneCount: number
  sceneIndex: number
  byteRange: { start: number; end: number }
  /** base64 of normalized scene bytes */
  sceneBytes: string
  /** Each entry is "sha256:<hex>" of a sibling hash from leaf level up. */
  siblingHashes: string[]
}

/** Generate a proof that a specific scene is included in the tree. */
export function buildSceneProof(tree: BuiltSceneTree, sceneIndex: number, scene: Scene): SceneProof {
  if (sceneIndex !== scene.sceneIndex) {
    throw new Error(
      `buildSceneProof: sceneIndex arg (${sceneIndex}) doesn't match scene.sceneIndex (${scene.sceneIndex})`,
    )
  }
  if (sceneIndex < 0 || sceneIndex >= tree.sceneCount) {
    throw new Error(
      `buildSceneProof: sceneIndex ${sceneIndex} out of range [0, ${tree.sceneCount})`,
    )
  }

  const siblingHashes: string[] = []
  let idx = sceneIndex
  for (let level = 0; level < tree.depth; level++) {
    const siblingIdx = idx ^ 1
    const siblingHash = tree.levels[level]![siblingIdx]!
    siblingHashes.push(`sha256:${siblingHash.toString('hex')}`)
    idx >>= 1
  }

  return {
    sceneTreeProfile: PROFILE_ID,
    sceneCount: tree.sceneCount,
    sceneIndex,
    byteRange: { start: scene.byteStart, end: scene.byteEnd },
    sceneBytes: scene.sceneBytes.toString('base64'),
    siblingHashes,
  }
}

export interface VerifySceneProofInput {
  expectedRoot: string
  expectedSceneCount: number
  expectedProfile: string
  proof: SceneProof
}

export type VerifySceneProofResult =
  | { ok: true }
  | {
      ok: false
      reason:
        | 'profile-mismatch'
        | 'scene-count-mismatch'
        | 'depth-mismatch'
        | 'index-out-of-range'
        | 'root-mismatch'
        | 'invalid-base64'
        | 'invalid-byte-range'
      detail: string
    }

export function verifySceneProof(input: VerifySceneProofInput): VerifySceneProofResult {
  const { expectedRoot, expectedSceneCount, expectedProfile, proof } = input

  if (proof.sceneTreeProfile !== expectedProfile) {
    return {
      ok: false,
      reason: 'profile-mismatch',
      detail: `Expected profile ${expectedProfile}, proof has ${proof.sceneTreeProfile}`,
    }
  }
  if (proof.sceneCount !== expectedSceneCount) {
    return {
      ok: false,
      reason: 'scene-count-mismatch',
      detail: `Expected sceneCount ${expectedSceneCount}, proof has ${proof.sceneCount}`,
    }
  }
  if (proof.sceneIndex < 0 || proof.sceneIndex >= proof.sceneCount) {
    return {
      ok: false,
      reason: 'index-out-of-range',
      detail: `sceneIndex ${proof.sceneIndex} out of range [0, ${proof.sceneCount})`,
    }
  }

  const expectedDepth = depthForSceneCount(proof.sceneCount)
  if (proof.siblingHashes.length !== expectedDepth) {
    return {
      ok: false,
      reason: 'depth-mismatch',
      detail: `Expected ${expectedDepth} sibling hashes for sceneCount ${proof.sceneCount}, got ${proof.siblingHashes.length}`,
    }
  }

  let sceneBytes: Buffer
  try {
    sceneBytes = Buffer.from(proof.sceneBytes, 'base64')
  } catch {
    return { ok: false, reason: 'invalid-base64', detail: 'sceneBytes is not valid base64' }
  }

  if (proof.byteRange.start > proof.byteRange.end) {
    return {
      ok: false,
      reason: 'invalid-byte-range',
      detail: `byteRange.start (${proof.byteRange.start}) > byteRange.end (${proof.byteRange.end})`,
    }
  }
  if (sceneBytes.length !== proof.byteRange.end - proof.byteRange.start) {
    return {
      ok: false,
      reason: 'invalid-byte-range',
      detail: `sceneBytes length ${sceneBytes.length} does not match byteRange size ${proof.byteRange.end - proof.byteRange.start}`,
    }
  }

  const reconstructedLeaf = leafHash({
    sceneIndex: proof.sceneIndex,
    byteStart: proof.byteRange.start,
    byteEnd: proof.byteRange.end,
    sceneBytes,
  })

  let acc = reconstructedLeaf
  let idx = proof.sceneIndex
  for (let level = 0; level < proof.siblingHashes.length; level++) {
    const siblingHex = proof.siblingHashes[level]!
    if (!siblingHex.startsWith('sha256:') || siblingHex.length !== 7 + 64) {
      return {
        ok: false,
        reason: 'root-mismatch',
        detail: `siblingHashes[${level}] is malformed: ${siblingHex}`,
      }
    }
    const sibling = Buffer.from(siblingHex.slice('sha256:'.length), 'hex')
    if (idx % 2 === 0) {
      acc = parentHash(acc, sibling)
    } else {
      acc = parentHash(sibling, acc)
    }
    idx >>= 1
  }

  const reconstructedRoot = `sha256:${acc.toString('hex')}`
  if (reconstructedRoot !== expectedRoot) {
    return {
      ok: false,
      reason: 'root-mismatch',
      detail: `Reconstructed root ${reconstructedRoot} does not match expected ${expectedRoot}`,
    }
  }

  return { ok: true }
}

function depthForSceneCount(n: number): number {
  if (n <= 1) return 0
  let depth = 0
  let p = 1
  while (p < n) {
    p <<= 1
    depth++
  }
  return depth
}

// ---------------------------------------------------------------------------
// Backwards-compat re-exports from sibling modules
// ---------------------------------------------------------------------------

export {
  PARAGRAPH_TREE_PROFILE_ID,
  PARAGRAPH_CONTENT_PROFILE,
  type Paragraph,
  type BuiltParagraphTree,
  detectParagraphs,
  detectParagraphsWithPositions,
  paragraphContentHash,
  paragraphContentHashBytes,
  computeParagraphContentHashes,
  paragraphLeafHash,
  paragraphLeafHashFromContent,
  buildParagraphTree,
  reduceParagraphTreeRoot,
} from './paragraph-tree.js'
