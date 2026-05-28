/**
 * Generate the canonical scene-tree test corpus.
 *
 * Vectors: synthetic Fountain inputs with varying scene counts (0, 1, 2, 3, 5, 8, 13, 50).
 * For each, output:
 *   - input.fountain — raw input
 *   - normalized.bin — output of normalization
 *   - scenes.json — detected scene metadata
 *   - tree.json — root + sceneCount + depth + paddedLeafCount
 *   - proofs/<sceneIndex>.json — selective-disclosure proof for each scene
 *   - description.md
 */

import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync, readdirSync, readFileSync, unlinkSync, existsSync, rmSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalize } from '../src/normalize/v1-strict.js'
import {
  detectScenes,
  buildSceneTree,
  buildSceneProof,
  type Scene,
} from '../src/merkle/scene-tree.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CORPUS_DIR = join(__dirname, '..', 'spec', 'v1', 'testvectors', 'scene-tree')

interface Vector {
  id: string
  name: string
  description: string
  /** A function that builds the input bytes. */
  build: () => Buffer
  /** Expected scene count after detection. */
  expectedSceneCount: number
}

function fountainSceneOfWords(heading: string, body: string): string {
  return `${heading}\n\n${body}\n`
}

const vectors: Vector[] = [
  {
    id: '001',
    name: 'no-scenes',
    description: 'No scene headings — tree contains only the padding sentinel.',
    build: () => Buffer.from('FADE IN:\n\nA title page with no scene heading.\n', 'utf8'),
    expectedSceneCount: 0,
  },
  {
    id: '002',
    name: 'single-scene-int',
    description: 'One INT. scene.',
    build: () =>
      Buffer.from(
        fountainSceneOfWords('INT. CAFE - DAY', 'A bustling cafe.\n\nA WAITER enters.'),
        'utf8',
      ),
    expectedSceneCount: 1,
  },
  {
    id: '003',
    name: 'two-scenes-int-ext',
    description: 'Two scenes (INT then EXT).',
    build: () =>
      Buffer.from(
        fountainSceneOfWords('INT. ROOM - DAY', 'Inside.') +
          fountainSceneOfWords('EXT. STREET - NIGHT', 'Outside.'),
        'utf8',
      ),
    expectedSceneCount: 2,
  },
  {
    id: '004',
    name: 'three-scenes',
    description: 'Three scenes — pads to 4 leaves.',
    build: () => {
      let s = ''
      for (let i = 0; i < 3; i++) {
        s += fountainSceneOfWords(`INT. ROOM ${i} - DAY`, `Scene ${i} body.`)
      }
      return Buffer.from(s, 'utf8')
    },
    expectedSceneCount: 3,
  },
  {
    id: '005',
    name: 'five-scenes',
    description: 'Five scenes — pads to 8 leaves.',
    build: () => {
      let s = ''
      const headings = ['INT.', 'EXT.', 'INT/EXT.', 'EST.', 'I/E.']
      for (let i = 0; i < 5; i++) {
        s += fountainSceneOfWords(`${headings[i]} LOCATION ${i} - DAY`, `Body of scene ${i}.`)
      }
      return Buffer.from(s, 'utf8')
    },
    expectedSceneCount: 5,
  },
  {
    id: '006',
    name: 'eight-scenes',
    description: 'Exactly 8 scenes — no padding needed (already power of 2).',
    build: () => {
      let s = ''
      for (let i = 0; i < 8; i++) {
        s += fountainSceneOfWords(`INT. LOC${i} - DAY`, `Body ${i}.`)
      }
      return Buffer.from(s, 'utf8')
    },
    expectedSceneCount: 8,
  },
  {
    id: '007',
    name: 'thirteen-scenes',
    description: 'Thirteen scenes — pads to 16.',
    build: () => {
      let s = ''
      for (let i = 0; i < 13; i++) {
        s += fountainSceneOfWords(`INT. LOC${i} - DAY`, `Body of thirteen.${i}`)
      }
      return Buffer.from(s, 'utf8')
    },
    expectedSceneCount: 13,
  },
  {
    id: '008',
    name: 'with-preamble',
    description: 'Title page bytes before the first scene heading; preamble is NOT a leaf.',
    build: () =>
      Buffer.from(
        'Title: My Movie\nAuthor: Me\n\n' + fountainSceneOfWords('INT. ROOM - DAY', 'Body.'),
        'utf8',
      ),
    expectedSceneCount: 1,
  },
  {
    id: '009',
    name: 'lowercase-heading',
    description: 'Heading in lowercase ("int. room - day") still detected (case-insensitive prefix).',
    build: () => Buffer.from('int. room - day\n\nBody.\n', 'utf8'),
    expectedSceneCount: 1,
  },
  {
    id: '010',
    name: 'fifty-scenes',
    description: 'Fifty scenes — pads to 64 leaves; tree depth 6.',
    build: () => {
      let s = ''
      for (let i = 0; i < 50; i++) {
        s += fountainSceneOfWords(`INT. LOC${i} - DAY`, `Body of scene ${i}.`)
      }
      return Buffer.from(s, 'utf8')
    },
    expectedSceneCount: 50,
  },
  {
    id: '011',
    name: 'heading-not-at-line-start-not-detected',
    description: 'A line that mentions "INT. ROOM" mid-line is NOT detected as a scene heading.',
    build: () =>
      Buffer.from(
        'INT. REAL - DAY\n\nThe screenwriter writes: "INT. FAKE - NIGHT" in the dialogue.\n',
        'utf8',
      ),
    expectedSceneCount: 1,
  },
  {
    id: '012',
    name: 'prefix-must-end-with-delimiter',
    description: '"INT.MOON" (no space after dot) is NOT a scene heading.',
    build: () => Buffer.from('INT.MOON\n\nThis is not a scene heading.\n', 'utf8'),
    expectedSceneCount: 0,
  },
]

function clearDir(dir: string): void {
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true })
  }
  mkdirSync(dir, { recursive: true })
}

function generate(): void {
  clearDir(CORPUS_DIR)

  const index: Array<{ id: string; name: string; description: string; sceneCount: number }> = []

  for (const v of vectors) {
    const prefix = `${v.id}-${v.name}`
    const vectorDir = join(CORPUS_DIR, prefix)
    mkdirSync(vectorDir, { recursive: true })

    const input = v.build()
    writeFileSync(join(vectorDir, 'input.fountain'), input)

    const normResult = normalize(input)
    if (!normResult.ok) {
      throw new Error(`Vector ${v.id} failed normalization: ${normResult.detail}`)
    }
    writeFileSync(join(vectorDir, 'normalized.bin'), normResult.normalized)

    const scenes = detectScenes(normResult.normalized)
    if (scenes.length !== v.expectedSceneCount) {
      throw new Error(
        `Vector ${v.id}: expected ${v.expectedSceneCount} scenes, detected ${scenes.length}`,
      )
    }
    writeFileSync(
      join(vectorDir, 'scenes.json'),
      JSON.stringify(
        scenes.map((s) => ({
          sceneIndex: s.sceneIndex,
          byteStart: s.byteStart,
          byteEnd: s.byteEnd,
          // Don't include sceneBytes in the index file (too large); they're recomputable from normalized.bin
        })),
        null,
        2,
      ) + '\n',
    )

    const tree = buildSceneTree(scenes)
    writeFileSync(
      join(vectorDir, 'tree.json'),
      JSON.stringify(
        {
          root: tree.root,
          sceneCount: tree.sceneCount,
          depth: tree.depth,
          paddedLeafCount: tree.paddedLeafCount,
        },
        null,
        2,
      ) + '\n',
    )

    if (scenes.length > 0) {
      const proofsDir = join(vectorDir, 'proofs')
      mkdirSync(proofsDir, { recursive: true })
      for (const scene of scenes) {
        const proof = buildSceneProof(tree, scene.sceneIndex, scene)
        writeFileSync(
          join(proofsDir, `${String(scene.sceneIndex).padStart(3, '0')}.json`),
          JSON.stringify(proof, null, 2) + '\n',
        )
      }
    }

    writeFileSync(join(vectorDir, 'description.md'), `# Vector ${v.id} — ${v.name}\n\n${v.description}\n`)
    index.push({
      id: v.id,
      name: v.name,
      description: v.description,
      sceneCount: scenes.length,
    })
  }

  writeFileSync(
    join(CORPUS_DIR, 'INDEX.json'),
    JSON.stringify(
      { profileId: 'screenplay-registration-merkle/v1', vectors: index },
      null,
      2,
    ) + '\n',
  )

  console.log(`Generated ${vectors.length} scene-tree test vectors in ${CORPUS_DIR}`)
}

generate()
