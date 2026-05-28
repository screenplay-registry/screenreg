/**
 * Shared Merkle primitives used by both the scene tree (Section 03 §3.1-§3.5)
 * and the paragraph tree (Section 03 §3.6).
 *
 * The two trees share construction shape but differ in:
 *   - profile string (`screenplay-registration-merkle/v1` vs
 *     `screenplay-registration-paragraph-merkle/v1`)
 *   - domain tags (0x00/0x01/0x02 vs 0x10/0x11/0x12)
 *   - leaf preimage formula (per-variant content + position binding)
 *
 * Everything else — bottom-up reduction with sibling pairing + power-of-two
 * padding — lives here so the two variant modules don't duplicate it.
 */

import { createHash } from 'node:crypto'

/** Smallest power of two ≥ n. Returns 1 for n ≤ 1. */
export function nextPowerOfTwo(n: number): number {
  if (n <= 1) return 1
  let p = 1
  while (p < n) p <<= 1
  return p
}

/** Build a domain-tagged parent hash: `SHA-256(tag || left || right)`. */
export function makeParentHash(domainTag: number): (left: Buffer, right: Buffer) => Buffer {
  const tagByte = Buffer.from([domainTag])
  return (left, right) => {
    const h = createHash('sha256')
    h.update(tagByte)
    h.update(left)
    h.update(right)
    return h.digest()
  }
}

/** Precompute the padding hash for a tree: `SHA-256(paddingTag)`. */
export function makePaddingHash(paddingTag: number): Buffer {
  return createHash('sha256').update(Buffer.from([paddingTag])).digest()
}

/**
 * Bottom-up Merkle reduction.
 *
 * Pads `leafHashes` with `paddingHash` to the next power of two, then walks
 * up the tree by pairing adjacent nodes with `parentFn`. Returns the root
 * hash. Empty `leafHashes` returns `paddingHash` directly (the "all-padding
 * tree of one leaf" convention from spec §3.5).
 */
export function reduceMerkleRoot(
  leafHashes: Buffer[],
  paddingHash: Buffer,
  parentFn: (left: Buffer, right: Buffer) => Buffer,
): Buffer {
  if (leafHashes.length === 0) return paddingHash
  const paddedLeafCount = nextPowerOfTwo(leafHashes.length)
  const padded: Buffer[] = [...leafHashes]
  while (padded.length < paddedLeafCount) padded.push(paddingHash)
  let level = padded
  while (level.length > 1) {
    const next: Buffer[] = []
    for (let i = 0; i < level.length; i += 2) {
      next.push(parentFn(level[i]!, level[i + 1]!))
    }
    level = next
  }
  return level[0]!
}
