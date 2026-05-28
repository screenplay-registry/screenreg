/**
 * Tests for the scene-level Merkle tree (`screenplay-registration-merkle/v1`).
 *
 * Vector-driven correctness + adversarial tests for:
 *  - second-preimage attack (rejected by domain separation)
 *  - truncation attack (rejected by sceneCount commitment)
 *  - reorder attack (rejected by sceneIndex binding)
 *  - byte-range substitution (rejected by byteRange binding)
 */

import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import {
  detectScenes,
  buildSceneTree,
  buildSceneProof,
  verifySceneProof,
  leafHash,
  parentHash,
  PROFILE_ID,
  type SceneProof,
  type Scene,
} from '../../src/merkle/scene-tree.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CORPUS_DIR = join(__dirname, '..', '..', 'spec', 'v1', 'testvectors', 'scene-tree')

interface IndexFile {
  profileId: string
  vectors: Array<{ id: string; name: string; description: string; sceneCount: number }>
}

const indexJson = JSON.parse(readFileSync(join(CORPUS_DIR, 'INDEX.json'), 'utf8')) as IndexFile

// ---------------------------------------------------------------------------
// Profile sanity
// ---------------------------------------------------------------------------

describe('profile identifier', () => {
  it('matches the spec exactly', () => {
    expect(PROFILE_ID).toBe('screenplay-registration-merkle/v1')
    expect(indexJson.profileId).toBe(PROFILE_ID)
  })
})

// ---------------------------------------------------------------------------
// Vector-driven correctness
// ---------------------------------------------------------------------------

describe('scene-tree vector corpus', () => {
  for (const v of indexJson.vectors) {
    const prefix = `${v.id}-${v.name}`
    describe(`${v.id} ${v.name} (${v.sceneCount} scenes)`, () => {
      const dir = join(CORPUS_DIR, prefix)
      const normalized = readFileSync(join(dir, 'normalized.bin'))
      const expectedTree = JSON.parse(readFileSync(join(dir, 'tree.json'), 'utf8'))

      it('detects the expected scene count', () => {
        const scenes = detectScenes(normalized)
        expect(scenes.length).toBe(v.sceneCount)
      })

      it('builds the expected root', () => {
        const scenes = detectScenes(normalized)
        const tree = buildSceneTree(scenes)
        expect(tree.root).toBe(expectedTree.root)
        expect(tree.sceneCount).toBe(expectedTree.sceneCount)
        expect(tree.depth).toBe(expectedTree.depth)
        expect(tree.paddedLeafCount).toBe(expectedTree.paddedLeafCount)
      })

      if (v.sceneCount > 0) {
        it('every per-scene proof verifies against the committed root', () => {
          const scenes = detectScenes(normalized)
          const tree = buildSceneTree(scenes)
          for (const scene of scenes) {
            const storedProof = JSON.parse(
              readFileSync(
                join(dir, 'proofs', `${String(scene.sceneIndex).padStart(3, '0')}.json`),
                'utf8',
              ),
            ) as SceneProof
            const result = verifySceneProof({
              expectedRoot: tree.root,
              expectedSceneCount: tree.sceneCount,
              expectedProfile: PROFILE_ID,
              proof: storedProof,
            })
            expect(result.ok).toBe(true)
          }
        })

        it('proofs are reproducible — generating fresh matches committed proof', () => {
          const scenes = detectScenes(normalized)
          const tree = buildSceneTree(scenes)
          for (const scene of scenes) {
            const fresh = buildSceneProof(tree, scene.sceneIndex, scene)
            const stored = JSON.parse(
              readFileSync(
                join(dir, 'proofs', `${String(scene.sceneIndex).padStart(3, '0')}.json`),
                'utf8',
              ),
            ) as SceneProof
            expect(fresh).toEqual(stored)
          }
        })
      }
    })
  }
})

// ---------------------------------------------------------------------------
// Adversarial: second-preimage attack
// ---------------------------------------------------------------------------

describe('second-preimage attack: domain separation prevents leaf↔parent confusion', () => {
  it('a candidate leaf cannot be constructed whose hash equals a parent-node hash', () => {
    // Build a small tree with 2 real scenes
    const sceneA: Scene = {
      sceneIndex: 0,
      byteStart: 0,
      byteEnd: 10,
      sceneBytes: Buffer.from('SCENE A...', 'utf8'),
    }
    const sceneB: Scene = {
      sceneIndex: 1,
      byteStart: 10,
      byteEnd: 20,
      sceneBytes: Buffer.from('SCENE B...', 'utf8'),
    }
    const realLeafA = leafHash(sceneA)
    const realLeafB = leafHash(sceneB)
    const realParent = parentHash(realLeafA, realLeafB)

    // An attacker tries to fabricate a "scene" whose leaf hash equals the parent.
    // The leaf hash domain-separates with 0x00 + profile + metadata; the parent
    // domain-separates with 0x01 + 32 + 32. They CANNOT share a preimage because
    // the leading byte differs (0x00 vs 0x01).

    // Demonstrate: a SHA-256 of [0x00, ...] cannot equal a SHA-256 of [0x01, ...]
    // unless SHA-256 is broken. Since we can't actually find a collision, we instead
    // verify the structural property: the leaf-hashing function and parent-hashing
    // function never share a preimage tag.

    // Show that the parent hash for sceneA/sceneB starts with the parent domain tag
    // by reconstructing it manually:
    const h = createHash('sha256')
    h.update(Buffer.from([0x01]))
    h.update(realLeafA)
    h.update(realLeafB)
    const reconstructedParent = h.digest()
    expect(reconstructedParent.equals(realParent)).toBe(true)

    // And the leaf hash for some scene starts with the leaf domain tag.
    // Per the v1 chain-binding formula, the leaf preimage is:
    //   0x00 || profile || u32(idx) || u64(start) || u64(end) || content_hash
    // where content_hash = SHA-256(SCENE_CONTENT_PROFILE || scene_bytes).
    const fakeScene: Scene = {
      sceneIndex: 0,
      byteStart: 0,
      byteEnd: 0,
      sceneBytes: Buffer.alloc(0),
    }
    const fakeLeaf = leafHash(fakeScene)
    // First reconstruct the content hash:
    const ch = createHash('sha256')
    ch.update(Buffer.from('screenplay-registration-scene-content/v1', 'utf8'))
    ch.update(Buffer.alloc(0))
    const contentHashBytes = ch.digest()
    // Then reconstruct the leaf hash from it:
    const h2 = createHash('sha256')
    h2.update(Buffer.from([0x00]))
    h2.update(Buffer.from('screenplay-registration-merkle/v1', 'utf8'))
    const sceneIndexBuf = Buffer.alloc(4)
    sceneIndexBuf.writeUInt32BE(0, 0)
    const byteStartBuf = Buffer.alloc(8)
    byteStartBuf.writeBigUInt64BE(0n, 0)
    const byteEndBuf = Buffer.alloc(8)
    byteEndBuf.writeBigUInt64BE(0n, 0)
    h2.update(sceneIndexBuf)
    h2.update(byteStartBuf)
    h2.update(byteEndBuf)
    h2.update(contentHashBytes)
    expect(h2.digest().equals(fakeLeaf)).toBe(true)
  })

  it('attempting to verify a malformed proof where sceneBytes were chosen adversarially is rejected', () => {
    // Build real tree
    const scenes: Scene[] = []
    for (let i = 0; i < 4; i++) {
      scenes.push({
        sceneIndex: i,
        byteStart: i * 10,
        byteEnd: i * 10 + 10,
        sceneBytes: Buffer.from(`SCENE_${i}xxx`, 'utf8'),
      })
    }
    const tree = buildSceneTree(scenes)

    // Attacker swaps sceneBytes for scene 2 to something else but keeps the metadata
    const tamperedProof = buildSceneProof(tree, 2, scenes[2]!)
    const fakedScene = Buffer.from('FAKE_SCENE', 'utf8') // different content
    tamperedProof.sceneBytes = fakedScene.toString('base64')
    tamperedProof.byteRange.end = tamperedProof.byteRange.start + fakedScene.length

    const result = verifySceneProof({
      expectedRoot: tree.root,
      expectedSceneCount: tree.sceneCount,
      expectedProfile: PROFILE_ID,
      proof: tamperedProof,
    })
    expect(result.ok).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Adversarial: truncation attack
// ---------------------------------------------------------------------------

describe('truncation attack: sceneCount commitment prevents claiming fewer scenes', () => {
  it('a proof with the wrong sceneCount is rejected', () => {
    const scenes: Scene[] = []
    for (let i = 0; i < 8; i++) {
      scenes.push({
        sceneIndex: i,
        byteStart: i * 10,
        byteEnd: i * 10 + 10,
        sceneBytes: Buffer.from(`SCENE_${i}xxx`, 'utf8'),
      })
    }
    const tree = buildSceneTree(scenes)
    const proof = buildSceneProof(tree, 0, scenes[0]!)

    // Attacker tampers with the proof's sceneCount (claim only 4 scenes existed)
    proof.sceneCount = 4

    const result = verifySceneProof({
      expectedRoot: tree.root,
      expectedSceneCount: 8, // verifier knows the real count from the committed claim
      expectedProfile: PROFILE_ID,
      proof,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('scene-count-mismatch')
    }
  })

  it('a proof with wrong depth (sibling count) for the sceneCount is rejected', () => {
    const scenes: Scene[] = []
    for (let i = 0; i < 4; i++) {
      scenes.push({
        sceneIndex: i,
        byteStart: i * 10,
        byteEnd: i * 10 + 10,
        sceneBytes: Buffer.from(`SCENE_${i}xxx`, 'utf8'),
      })
    }
    const tree = buildSceneTree(scenes)
    const proof = buildSceneProof(tree, 0, scenes[0]!)
    // Drop one sibling from the path
    proof.siblingHashes.pop()

    const result = verifySceneProof({
      expectedRoot: tree.root,
      expectedSceneCount: tree.sceneCount,
      expectedProfile: PROFILE_ID,
      proof,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('depth-mismatch')
    }
  })
})

// ---------------------------------------------------------------------------
// Adversarial: reorder attack
// ---------------------------------------------------------------------------

describe('reorder attack: sceneIndex binding prevents swapping scenes', () => {
  it('a proof claiming scene at index N actually contains scene M\'s bytes is rejected', () => {
    const scenes: Scene[] = []
    for (let i = 0; i < 4; i++) {
      scenes.push({
        sceneIndex: i,
        byteStart: i * 10,
        byteEnd: i * 10 + 10,
        sceneBytes: Buffer.from(`SCENE_${i}xxx`, 'utf8'),
      })
    }
    const tree = buildSceneTree(scenes)

    // Attacker builds proof for scene 2 but claims it is scene 0
    const proof = buildSceneProof(tree, 2, scenes[2]!)
    proof.sceneIndex = 0
    // The siblingHashes path is from index 2's position, but we claim index 0
    const result = verifySceneProof({
      expectedRoot: tree.root,
      expectedSceneCount: tree.sceneCount,
      expectedProfile: PROFILE_ID,
      proof,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('root-mismatch')
    }
  })
})

// ---------------------------------------------------------------------------
// Adversarial: byteRange substitution
// ---------------------------------------------------------------------------

describe('byte-range substitution: byteRange binding prevents bytes-from-elsewhere claims', () => {
  it('a proof with valid sceneBytes but wrong byteRange is rejected', () => {
    const scenes: Scene[] = []
    for (let i = 0; i < 4; i++) {
      scenes.push({
        sceneIndex: i,
        byteStart: i * 100,
        byteEnd: i * 100 + 100,
        sceneBytes: Buffer.alloc(100, 0x41 + i),
      })
    }
    const tree = buildSceneTree(scenes)
    const proof = buildSceneProof(tree, 1, scenes[1]!)
    // Attacker pretends scene 1's bytes came from a different range
    proof.byteRange = { start: 500, end: 600 }
    const result = verifySceneProof({
      expectedRoot: tree.root,
      expectedSceneCount: tree.sceneCount,
      expectedProfile: PROFILE_ID,
      proof,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('root-mismatch')
    }
  })
})

// ---------------------------------------------------------------------------
// Padding sentinel sanity
// ---------------------------------------------------------------------------

describe('padding sentinel', () => {
  it('SHA-256(0x02) precomputed value matches expected', () => {
    const expected = createHash('sha256').update(Buffer.from([0x02])).digest('hex')
    // The expected hex from spec §3.4
    expect(expected).toBe('dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986')
  })
})
