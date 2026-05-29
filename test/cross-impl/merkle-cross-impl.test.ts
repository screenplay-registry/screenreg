/**
 * Cross-impl scene-tree Merkle parity. Asserts:
 *   - detectScenes returns identical (index, byteStart, byteEnd) tuples in
 *     both implementations for the same normalized bytes.
 *   - sceneContentHashBytes and leafHash produce byte-identical digests.
 *   - buildSceneTree produces byte-identical roots.
 *
 * Drift between the browser and CLI would mean a writer who builds a scene
 * tree in /create/ couldn't generate matching scene proofs from the CLI
 * (and vice versa) — the whole point of the scene-tree commitment.
 */

import { describe, it, expect } from 'vitest'

import {
  detectScenes as sharedDetectScenes,
  buildSceneTree as sharedBuildSceneTree,
  sceneContentHashBytes as sharedSceneContentHashBytes,
  leafHash as sharedLeafHash,
} from '../../src/shared/merkle/scene-tree.js'

import {
  detectScenes as legacyDetectScenes,
  buildSceneTree as legacyBuildSceneTree,
  sceneContentHashBytes as legacySceneContentHashBytes,
  leafHash as legacyLeafHash,
} from '../../src/merkle/scene-tree.js'

const SAMPLE_FOUNTAIN = `INT. KITCHEN - DAY

A writer types.

EXT. ROOFTOP - NIGHT

Stars overhead. The end.
`

const MULTISCENE_FOUNTAIN = `INT. KITCHEN - DAY

Action one.

INT. BEDROOM - NIGHT

Action two.

EXT. STREET - DAWN

Action three.

INT/EXT. CAR - DAY

Action four.

EST. CITY - DAY

Action five.
`

describe('cross-impl scene-tree: detectScenes parity', () => {
  it('identical (index, byteStart, byteEnd) tuples for simple input', () => {
    const bytes = new TextEncoder().encode(SAMPLE_FOUNTAIN)
    const buf = Buffer.from(bytes)
    const shared = sharedDetectScenes(bytes)
    const legacy = legacyDetectScenes(buf)
    expect(shared.length).toBe(legacy.length)
    for (let i = 0; i < shared.length; i++) {
      expect(shared[i]!.sceneIndex).toBe(legacy[i]!.sceneIndex)
      expect(shared[i]!.byteStart).toBe(legacy[i]!.byteStart)
      expect(shared[i]!.byteEnd).toBe(legacy[i]!.byteEnd)
    }
  })

  it('identical detection for the 5-scene fixture (incl. INT/EXT and EST)', () => {
    const bytes = new TextEncoder().encode(MULTISCENE_FOUNTAIN)
    const buf = Buffer.from(bytes)
    const shared = sharedDetectScenes(bytes)
    const legacy = legacyDetectScenes(buf)
    expect(shared.length).toBe(5)
    expect(legacy.length).toBe(5)
    for (let i = 0; i < shared.length; i++) {
      expect(shared[i]!.byteStart).toBe(legacy[i]!.byteStart)
      expect(shared[i]!.byteEnd).toBe(legacy[i]!.byteEnd)
    }
  })

  it('returns empty array on input with no scene headings', () => {
    const bytes = new TextEncoder().encode('Just some text, no slug line.\n')
    expect(sharedDetectScenes(bytes)).toEqual([])
    expect(legacyDetectScenes(Buffer.from(bytes))).toEqual([])
  })
})

describe('cross-impl scene-tree: sceneContentHash + leafHash parity', () => {
  it('byte-identical scene content hash for each scene in the 5-scene fixture', async () => {
    const bytes = new TextEncoder().encode(MULTISCENE_FOUNTAIN)
    const buf = Buffer.from(bytes)
    const sharedScenes = sharedDetectScenes(bytes)
    const legacyScenes = legacyDetectScenes(buf)
    for (let i = 0; i < sharedScenes.length; i++) {
      const shared = await sharedSceneContentHashBytes(sharedScenes[i]!)
      const legacy = legacySceneContentHashBytes(legacyScenes[i]!)
      expect(shared.length).toBe(legacy.length)
      for (let j = 0; j < shared.length; j++) {
        expect(shared[j]).toBe(legacy[j])
      }
    }
  })

  it('byte-identical leaf hash for each scene', async () => {
    const bytes = new TextEncoder().encode(MULTISCENE_FOUNTAIN)
    const buf = Buffer.from(bytes)
    const sharedScenes = sharedDetectScenes(bytes)
    const legacyScenes = legacyDetectScenes(buf)
    for (let i = 0; i < sharedScenes.length; i++) {
      const shared = await sharedLeafHash(sharedScenes[i]!)
      const legacy = legacyLeafHash(legacyScenes[i]!)
      for (let j = 0; j < shared.length; j++) {
        expect(shared[j]).toBe(legacy[j])
      }
    }
  })
})

describe('cross-impl scene-tree: buildSceneTree root parity', () => {
  for (const [name, input] of [
    ['simple 2-scene', SAMPLE_FOUNTAIN],
    ['5-scene mixed prefix', MULTISCENE_FOUNTAIN],
  ] as const) {
    it(`${name}: identical root + sceneCount + depth`, async () => {
      const bytes = new TextEncoder().encode(input)
      const buf = Buffer.from(bytes)
      const sharedScenes = sharedDetectScenes(bytes)
      const legacyScenes = legacyDetectScenes(buf)
      const shared = await sharedBuildSceneTree(sharedScenes)
      const legacy = legacyBuildSceneTree(legacyScenes)
      expect(shared.sceneCount).toBe(legacy.sceneCount)
      expect(shared.depth).toBe(legacy.depth)
      expect(shared.paddedLeafCount).toBe(legacy.paddedLeafCount)
      expect(shared.root).toBe(legacy.root)
    })
  }

  it('empty input produces the all-padding root in both impls', async () => {
    const shared = await sharedBuildSceneTree([])
    const legacy = legacyBuildSceneTree([])
    expect(shared.root).toBe(legacy.root)
    expect(shared.sceneCount).toBe(0)
  })
})
