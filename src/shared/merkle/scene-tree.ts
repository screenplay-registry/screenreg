/**
 * Cross-runtime scene-tree Merkle construction.
 *
 * Byte-equivalent to src/merkle/scene-tree.ts. Spec: spec/v1/03-scene-tree.md.
 *
 * Profile / domain identifiers (locked at v1):
 *   PROFILE                screenplay-registration-merkle/v1
 *   SCENE_CONTENT_PROFILE  screenplay-registration-scene-content/v1
 *   leaf tag         0x00
 *   parent tag       0x01
 *   padding tag      0x02
 *
 * Leaf preimage (Section 03 §3.1):
 *   0x00 || PROFILE || uint32BE(sceneIndex) || uint64BE(byteStart)
 *        || uint64BE(byteEnd) || contentHashBytes
 *
 * Scene content hash (position-INDEPENDENT, used by Section 05/06 bundles):
 *   SHA-256(SCENE_CONTENT_PROFILE || sceneBytes)
 *
 * Parent: SHA-256(0x01 || left || right). Padding: SHA-256(0x02).
 */

import { sha256 } from '../crypto.js'

export const PROFILE_ID = 'screenplay-registration-merkle/v1' as const
export const SCENE_CONTENT_PROFILE = 'screenplay-registration-scene-content/v1' as const

const DOMAIN_LEAF = 0x00
const DOMAIN_PARENT = 0x01
const DOMAIN_PADDING = 0x02

const PROFILE_BYTES = new TextEncoder().encode(PROFILE_ID)
const SCENE_CONTENT_PROFILE_BYTES = new TextEncoder().encode(SCENE_CONTENT_PROFILE)

const HEADING_PREFIXES = ['INT.', 'INT/EXT.', 'EXT.', 'EST.', 'I/E.', 'E/I.'] as const

export interface Scene {
  sceneIndex: number
  byteStart: number
  byteEnd: number
  sceneBytes: Uint8Array
}

/**
 * Detect scenes in normalized Fountain bytes per spec §2.
 *
 *   - Heading must be at byte 0 OR follow an LF (0x0A).
 *   - Prefix matched case-insensitively, followed by space / hyphen / LF / EOF.
 *   - Preamble bytes before the first heading are NOT a scene leaf in v1.
 */
export function detectScenes(normalized: Uint8Array): Scene[] {
  const headingPositions: number[] = []
  const n = normalized.length
  const decoder = new TextDecoder('utf-8', { fatal: false })
  for (let i = 0; i < n; i++) {
    const isLineStart = i === 0 || normalized[i - 1] === 0x0a
    if (!isLineStart) continue
    for (const prefix of HEADING_PREFIXES) {
      const prefixLen = prefix.length
      if (i + prefixLen > n) continue
      const slice = decoder.decode(normalized.subarray(i, i + prefixLen))
      if (slice.toUpperCase() !== prefix) continue
      const nextChar = i + prefixLen < n ? normalized[i + prefixLen]! : -1
      if (nextChar === 0x20 || nextChar === 0x2d || nextChar === 0x0a || nextChar === -1) {
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

export async function sceneContentHashBytes(scene: Scene): Promise<Uint8Array> {
  const buf = new Uint8Array(SCENE_CONTENT_PROFILE_BYTES.length + scene.sceneBytes.length)
  buf.set(SCENE_CONTENT_PROFILE_BYTES, 0)
  buf.set(scene.sceneBytes, SCENE_CONTENT_PROFILE_BYTES.length)
  return sha256(buf)
}

export async function leafHash(scene: Scene): Promise<Uint8Array> {
  const contentHashBytes = await sceneContentHashBytes(scene)
  return leafHashFromContent({
    sceneIndex: scene.sceneIndex,
    byteStart: scene.byteStart,
    byteEnd: scene.byteEnd,
    contentHashBytes,
  })
}

export async function leafHashFromContent(input: {
  sceneIndex: number
  byteStart: number
  byteEnd: number
  contentHashBytes: Uint8Array
}): Promise<Uint8Array> {
  if (input.contentHashBytes.length !== 32) {
    throw new Error(
      `leafHashFromContent: contentHashBytes must be 32 bytes, got ${input.contentHashBytes.length}`,
    )
  }
  const sceneIndexBuf = new Uint8Array(4)
  writeUint32BE(sceneIndexBuf, 0, input.sceneIndex)
  const byteStartBuf = new Uint8Array(8)
  writeUint64BE(byteStartBuf, 0, BigInt(input.byteStart))
  const byteEndBuf = new Uint8Array(8)
  writeUint64BE(byteEndBuf, 0, BigInt(input.byteEnd))

  const preimage = concat([
    new Uint8Array([DOMAIN_LEAF]),
    PROFILE_BYTES,
    sceneIndexBuf,
    byteStartBuf,
    byteEndBuf,
    input.contentHashBytes,
  ])
  return sha256(preimage)
}

export interface BuiltSceneTree {
  rootBytes: Uint8Array
  root: string
  sceneCount: number
  depth: number
  paddedLeafCount: number
}

export async function buildSceneTree(scenes: Scene[]): Promise<BuiltSceneTree> {
  const sceneCount = scenes.length
  const paddingHash = await sha256(new Uint8Array([DOMAIN_PADDING]))
  if (sceneCount === 0) {
    return {
      rootBytes: paddingHash,
      root: `sha256:${toHex(paddingHash)}`,
      sceneCount: 0,
      depth: 0,
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
  const leaves: Uint8Array[] = []
  for (const scene of scenes) leaves.push(await leafHash(scene))
  for (let i = sceneCount; i < paddedLeafCount; i++) leaves.push(paddingHash)
  let level = leaves
  let depth = 0
  while (level.length > 1) {
    const next: Uint8Array[] = []
    for (let i = 0; i < level.length; i += 2) {
      next.push(await parentHash(level[i]!, level[i + 1]!))
    }
    level = next
    depth++
  }
  const rootBytes = level[0]!
  return {
    rootBytes,
    root: `sha256:${toHex(rootBytes)}`,
    sceneCount,
    depth,
    paddedLeafCount,
  }
}

async function parentHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(1 + left.length + right.length)
  buf[0] = DOMAIN_PARENT
  buf.set(left, 1)
  buf.set(right, 1 + left.length)
  return sha256(buf)
}

function nextPowerOfTwo(n: number): number {
  if (n <= 1) return 1
  let p = 1
  while (p < n) p <<= 1
  return p
}

function writeUint32BE(out: Uint8Array, offset: number, value: number): void {
  out[offset] = (value >>> 24) & 0xff
  out[offset + 1] = (value >>> 16) & 0xff
  out[offset + 2] = (value >>> 8) & 0xff
  out[offset + 3] = value & 0xff
}

function writeUint64BE(out: Uint8Array, offset: number, value: bigint): void {
  for (let i = 7; i >= 0; i--) {
    out[offset + i] = Number(value & 0xffn)
    value >>= 8n
  }
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

function toHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, '0')
  return out
}
