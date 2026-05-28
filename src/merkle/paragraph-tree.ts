/**
 * Reference implementation of `screenplay-registration-paragraph-merkle/v1`
 * (Section 03 §3.6).
 *
 * Construction is parallel to the scene tree (`./scene-tree.ts`) with three
 * substitutions: different tree profile, different domain tags
 * (`0x10`/`0x11`/`0x12`), and the paragraph-specific content profile.
 * Disjoint domain tags ensure a paragraph leaf can never collide with a
 * scene leaf even if the underlying bytes happen to match.
 *
 * Like the scene tree, leaves use the two-stage chain:
 *   bytes → content_hash → leaf_hash → ... → root
 * so that comparison disclosure bundles (Section 06) can chain-bind
 * paragraph content hashes to the committed root.
 */

import { createHash } from 'node:crypto'
import { makeParentHash, makePaddingHash, nextPowerOfTwo, reduceMerkleRoot } from './primitives.js'

export const PARAGRAPH_TREE_PROFILE_ID = 'screenplay-registration-paragraph-merkle/v1' as const
export const PARAGRAPH_CONTENT_PROFILE = 'screenplay-registration-paragraph-content/v1' as const

const PARAGRAPH_TREE_PROFILE_BYTES = Buffer.from(PARAGRAPH_TREE_PROFILE_ID, 'utf8')
const PARAGRAPH_CONTENT_PROFILE_BYTES = Buffer.from(PARAGRAPH_CONTENT_PROFILE, 'utf8')

// Domain tags per spec §3.6. Disjoint from scene-tree tags by construction.
const DOMAIN_PARAGRAPH_LEAF = 0x10 as const
const DOMAIN_PARAGRAPH_PARENT = 0x11 as const
const DOMAIN_PARAGRAPH_PADDING = 0x12 as const

const PARAGRAPH_PADDING_HASH: Buffer = makePaddingHash(DOMAIN_PARAGRAPH_PADDING)
const paragraphParentHash = makeParentHash(DOMAIN_PARAGRAPH_PARENT)

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/**
 * Detect paragraphs in normalized bytes (legacy byte-array form).
 * A paragraph is a maximal run of non-blank lines, delimited by one or more
 * blank lines. Leading and trailing blank lines are skipped.
 *
 * Most callers want `detectParagraphsWithPositions` which carries byte ranges
 * needed for Merkle leaf construction and comparison-bundle binding.
 */
export function detectParagraphs(normalized: Buffer): Buffer[] {
  return detectParagraphsWithPositions(normalized).map((p) => p.paragraphBytes)
}

export interface Paragraph {
  paragraphIndex: number
  byteStart: number
  byteEnd: number
  paragraphBytes: Buffer
}

export function detectParagraphsWithPositions(normalized: Buffer): Paragraph[] {
  const out: Paragraph[] = []
  const n = normalized.length
  let i = 0
  let idx = 0
  while (i < n) {
    while (i < n && normalized[i] === 0x0a) i++
    if (i >= n) break
    const start = i
    while (i < n) {
      if (normalized[i] === 0x0a) {
        if (i + 1 >= n || normalized[i + 1] === 0x0a) break
      }
      i++
    }
    if (i > start) {
      out.push({
        paragraphIndex: idx++,
        byteStart: start,
        byteEnd: i,
        paragraphBytes: normalized.subarray(start, i),
      })
    }
  }
  return out
}

// ---------------------------------------------------------------------------
// Content hash (position-independent, domain-separated)
// ---------------------------------------------------------------------------

export function paragraphContentHash(paragraphBytes: Buffer): string {
  return `sha256:${paragraphContentHashBytes(paragraphBytes).toString('hex')}`
}

export function paragraphContentHashBytes(paragraphBytes: Buffer): Buffer {
  const h = createHash('sha256')
  h.update(PARAGRAPH_CONTENT_PROFILE_BYTES)
  h.update(paragraphBytes)
  return h.digest()
}

export function computeParagraphContentHashes(paragraphs: Buffer[]): string[] {
  return paragraphs.map(paragraphContentHash)
}

// ---------------------------------------------------------------------------
// Leaf hash (position-bound, two-stage chain through content_hash)
// ---------------------------------------------------------------------------

/**
 * Per-paragraph Merkle leaf hash:
 *   content_hash := SHA-256(PARAGRAPH_CONTENT_PROFILE || paragraph_bytes)
 *   leaf_hash    := SHA-256(
 *     0x10 || PARAGRAPH_TREE_PROFILE ||
 *     uint32_BE(idx) || uint64_BE(byteStart) || uint64_BE(byteEnd) ||
 *     content_hash
 *   )
 */
export function paragraphLeafHash(input: {
  paragraphIndex: number
  byteStart: number
  byteEnd: number
  paragraphBytes: Buffer
}): Buffer {
  return paragraphLeafHashFromContent({
    paragraphIndex: input.paragraphIndex,
    byteStart: input.byteStart,
    byteEnd: input.byteEnd,
    contentHashBytes: paragraphContentHashBytes(input.paragraphBytes),
  })
}

export function paragraphLeafHashFromContent(input: {
  paragraphIndex: number
  byteStart: number
  byteEnd: number
  contentHashBytes: Buffer
}): Buffer {
  if (input.contentHashBytes.length !== 32) {
    throw new Error(
      `paragraphLeafHashFromContent: contentHashBytes must be 32 bytes, got ${input.contentHashBytes.length}`,
    )
  }
  const idxBuf = Buffer.alloc(4)
  idxBuf.writeUInt32BE(input.paragraphIndex, 0)
  const startBuf = Buffer.alloc(8)
  startBuf.writeBigUInt64BE(BigInt(input.byteStart), 0)
  const endBuf = Buffer.alloc(8)
  endBuf.writeBigUInt64BE(BigInt(input.byteEnd), 0)
  const h = createHash('sha256')
  h.update(Buffer.from([DOMAIN_PARAGRAPH_LEAF]))
  h.update(PARAGRAPH_TREE_PROFILE_BYTES)
  h.update(idxBuf)
  h.update(startBuf)
  h.update(endBuf)
  h.update(input.contentHashBytes)
  return h.digest()
}

// ---------------------------------------------------------------------------
// Tree construction + root reduction
// ---------------------------------------------------------------------------

export interface BuiltParagraphTree {
  rootBytes: Buffer
  root: string
  paragraphCount: number
  depth: number
  levels: Buffer[][]
  paddedLeafCount: number
}

export function buildParagraphTree(paragraphs: Paragraph[]): BuiltParagraphTree {
  const paragraphCount = paragraphs.length
  if (paragraphCount === 0) {
    return {
      rootBytes: PARAGRAPH_PADDING_HASH,
      root: `sha256:${PARAGRAPH_PADDING_HASH.toString('hex')}`,
      paragraphCount: 0,
      depth: 0,
      levels: [[PARAGRAPH_PADDING_HASH]],
      paddedLeafCount: 1,
    }
  }
  const paddedLeafCount = nextPowerOfTwo(paragraphCount)
  const leaves: Buffer[] = []
  for (const p of paragraphs) leaves.push(paragraphLeafHash(p))
  for (let i = paragraphCount; i < paddedLeafCount; i++) leaves.push(PARAGRAPH_PADDING_HASH)
  const levels: Buffer[][] = [leaves]
  let depth = 0
  while (levels[levels.length - 1]!.length > 1) {
    const cur = levels[levels.length - 1]!
    const next: Buffer[] = []
    for (let i = 0; i < cur.length; i += 2) {
      next.push(paragraphParentHash(cur[i]!, cur[i + 1]!))
    }
    levels.push(next)
    depth++
  }
  const rootBytes = levels[levels.length - 1]![0]!
  return {
    rootBytes,
    root: `sha256:${rootBytes.toString('hex')}`,
    paragraphCount,
    depth,
    levels,
    paddedLeafCount,
  }
}

/** Reduce a list of paragraph leaf hashes to the committed root. */
export function reduceParagraphTreeRoot(leafHashes: Buffer[]): Buffer {
  return reduceMerkleRoot(leafHashes, PARAGRAPH_PADDING_HASH, paragraphParentHash)
}
