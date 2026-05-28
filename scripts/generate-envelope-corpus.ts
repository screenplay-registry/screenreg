/**
 * Generate the canonical envelope test corpus.
 *
 * Outputs to /spec/v1/testvectors/envelope/.
 * Each vector: (claim.json, canonical.bin, claim-hash.txt, description.md).
 *
 * Plus separate canonicalization-only test vectors covering RFC 8785 edge cases
 * (these have no envelope wrapping; they test the canonicalize function alone).
 */

import { createHash, createPublicKey } from 'node:crypto'
import { mkdirSync, writeFileSync, readdirSync, readFileSync, unlinkSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalize } from '../src/envelope/canonicalize.js'
import { buildCommittedClaim, buildEnvelope } from '../src/envelope/build.js'
import { computeClaimHash } from '../src/envelope/claim-hash.js'
import { loadPrivateKey, signRegistration } from '../src/identity/ed25519-signing.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CORPUS_DIR = join(__dirname, '..', 'spec', 'v1', 'testvectors', 'envelope')

const HASH_PLACEHOLDER_A = 'sha256:' + 'a'.repeat(64)
const HASH_PLACEHOLDER_B = 'sha256:' + 'b'.repeat(64)
const HASH_PLACEHOLDER_C = 'sha256:' + 'c'.repeat(64)

/**
 * A FROZEN test-corpus Ed25519 keypair. Hardcoded so the corpus stays
 * byte-for-byte reproducible across regen runs (Ed25519 signing is
 * deterministic per RFC 8032, so fixed key + fixed message → fixed
 * signature). DO NOT use this keypair for real registrations.
 */
const CORPUS_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEVQMUCmBy5Adfatmsr1/qpsacr25EoPv0l4zEPPPdUI
-----END PRIVATE KEY-----
`

function makeCorpusRegistrantClaim(): unknown {
  const privateKey = loadPrivateKey(CORPUS_PRIVATE_KEY_PEM)
  // Derive the public key from the same PEM via Node's crypto API.
  const publicKey = createPublicKey(privateKey)
  const publicKeyRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)
  const publicKeyEncoded = `ed25519:${publicKeyRaw.toString('base64')}`
  const body = buildCommittedClaim({
    contentHash: HASH_PLACEHOLDER_A,
    sceneTree: { root: HASH_PLACEHOLDER_B, count: 47 },
    paragraphTree: { root: HASH_PLACEHOLDER_C, count: 312 },
    preferences: { trainingMining: 'notAllowed' },
    claimExtensions: { someFutureField: 'someValue' },
  })
  const registrant = signRegistration(body, privateKey, publicKeyEncoded)
  return { ...body, registrant }
}

// ---------------------------------------------------------------------------
// RFC 8785 canonicalization-only vectors (no envelope wrapping)
// ---------------------------------------------------------------------------

interface CanonVector {
  id: string
  name: string
  description: string
  input: unknown
  expectedCanonical: string
}

const canonVectors: CanonVector[] = [
  {
    id: '001',
    name: 'null',
    description: 'null serializes to literal "null"',
    input: null,
    expectedCanonical: 'null',
  },
  {
    id: '002',
    name: 'true',
    description: 'true serializes to literal "true"',
    input: true,
    expectedCanonical: 'true',
  },
  {
    id: '003',
    name: 'false',
    description: 'false serializes to literal "false"',
    input: false,
    expectedCanonical: 'false',
  },
  {
    id: '004',
    name: 'zero',
    description: 'integer 0',
    input: 0,
    expectedCanonical: '0',
  },
  {
    id: '005',
    name: 'negative-zero',
    description: '-0 serializes as "0" per RFC 8785',
    input: -0,
    expectedCanonical: '0',
  },
  {
    id: '006',
    name: 'positive-integer',
    description: 'positive integer 42',
    input: 42,
    expectedCanonical: '42',
  },
  {
    id: '007',
    name: 'negative-integer',
    description: 'negative integer -42',
    input: -42,
    expectedCanonical: '-42',
  },
  {
    id: '008',
    name: 'empty-string',
    description: 'empty string',
    input: '',
    expectedCanonical: '""',
  },
  {
    id: '009',
    name: 'ascii-string',
    description: 'simple ASCII string',
    input: 'hello',
    expectedCanonical: '"hello"',
  },
  {
    id: '010',
    name: 'string-with-quote',
    description: 'string containing a double quote',
    input: 'he said "hi"',
    expectedCanonical: '"he said \\"hi\\""',
  },
  {
    id: '011',
    name: 'string-with-backslash',
    description: 'string containing backslash',
    input: 'a\\b',
    expectedCanonical: '"a\\\\b"',
  },
  {
    id: '012',
    name: 'string-with-newline-tab',
    description: 'string with control char escapes',
    input: 'a\nb\tc',
    expectedCanonical: '"a\\nb\\tc"',
  },
  {
    id: '013',
    name: 'string-with-other-control',
    description: 'string with a non-mnemonic control char (U+0001)',
    input: 'ab',
    expectedCanonical: '"a\\u0001b"',
  },
  {
    id: '014',
    name: 'string-non-ascii-passthrough',
    description: 'non-ASCII passes through as UTF-8 bytes (no \\u escapes)',
    input: 'café',
    expectedCanonical: '"café"',
  },
  {
    id: '015',
    name: 'empty-array',
    description: 'empty array',
    input: [],
    expectedCanonical: '[]',
  },
  {
    id: '016',
    name: 'array-of-numbers',
    description: 'array preserves order',
    input: [3, 1, 2],
    expectedCanonical: '[3,1,2]',
  },
  {
    id: '017',
    name: 'empty-object',
    description: 'empty object',
    input: {},
    expectedCanonical: '{}',
  },
  {
    id: '018',
    name: 'object-key-sort',
    description: 'object keys sorted lexicographically by UTF-16 code unit',
    input: { z: 1, a: 2, m: 3 },
    expectedCanonical: '{"a":2,"m":3,"z":1}',
  },
  {
    id: '019',
    name: 'nested-object',
    description: 'nested object recursion',
    input: { outer: { z: 1, a: 2 } },
    expectedCanonical: '{"outer":{"a":2,"z":1}}',
  },
  {
    id: '020',
    name: 'mixed-types',
    description: 'object containing all primitive types',
    input: { s: 'hi', n: 42, b: true, x: null, a: [1, 2, 3] },
    expectedCanonical: '{"a":[1,2,3],"b":true,"n":42,"s":"hi","x":null}',
  },
  {
    id: '021',
    name: 'key-with-special-chars',
    description: 'object key containing characters that need escaping',
    input: { 'a"b': 1, 'c\\d': 2 },
    expectedCanonical: '{"a\\"b":1,"c\\\\d":2}',
  },
  {
    id: '022',
    name: 'numeric-keys-sort',
    description: 'numeric-string keys sort lexicographically (not numerically) — "10" < "9"',
    input: { '10': 'ten', '9': 'nine', '2': 'two' },
    expectedCanonical: '{"10":"ten","2":"two","9":"nine"}',
  },
]

// ---------------------------------------------------------------------------
// Envelope vectors
// ---------------------------------------------------------------------------

interface EnvelopeVector {
  id: string
  name: string
  description: string
  build: () => unknown
}

const envelopeVectors: EnvelopeVector[] = [
  {
    id: '101',
    name: 'minimal-claim',
    description: 'A claim with only required fields, no optional features.',
    build: () =>
      buildCommittedClaim({
        contentHash: HASH_PLACEHOLDER_A,
      }),
  },
  {
    id: '102',
    name: 'claim-with-scene-tree',
    description:
      'A claim with scene tree root populated. Per-leaf hashes are NOT in the committed claim post-refactor — they live in the opt-in comparison disclosure bundle (Section 06).',
    build: () =>
      buildCommittedClaim({
        contentHash: HASH_PLACEHOLDER_A,
        sceneTree: { root: HASH_PLACEHOLDER_B, count: 47 },
      }),
  },
  {
    id: '103',
    name: 'claim-with-preferences',
    description: 'A claim with user preferences populated.',
    build: () =>
      buildCommittedClaim({
        contentHash: HASH_PLACEHOLDER_A,
        preferences: { trainingMining: 'notAllowed' },
      }),
  },
  {
    id: '104',
    name: 'claim-with-extensions',
    description: 'A claim with non-empty claimExtensions — forward-compatibility.',
    build: () =>
      buildCommittedClaim({
        contentHash: HASH_PLACEHOLDER_A,
        claimExtensions: { someFutureField: 'someValue', anotherField: 42 },
      }),
  },
  {
    id: '105',
    name: 'claim-full',
    description:
      'A claim with every optional field populated: scene tree, paragraph tree, preferences, extensions, AND a signed registrant block from the frozen test-corpus Ed25519 key (deterministic signature per RFC 8032).',
    build: () => makeCorpusRegistrantClaim(),
  },
  {
    id: '109',
    name: 'claim-with-paragraph-tree-only',
    description:
      'A claim with ONLY the paragraph tree populated (no scene tree). Demonstrates the paragraph layer is independently committable for short-form work where scene segmentation is not meaningful.',
    build: () =>
      buildCommittedClaim({
        contentHash: HASH_PLACEHOLDER_A,
        paragraphTree: { root: HASH_PLACEHOLDER_C, count: 89 },
      }),
  },
  {
    id: '110',
    name: 'claim-with-revision-pointer',
    description:
      'A claim pointing to a previous registration (revision lineage / amendment chain).',
    build: () =>
      buildCommittedClaim({
        contentHash: HASH_PLACEHOLDER_A,
        previousRegistration: { claimHash: HASH_PLACEHOLDER_B },
      }),
  },
  {
    id: '106',
    name: 'minimal-envelope',
    description: 'A full envelope wrapping the minimal claim, no proofs.',
    build: () => {
      const claim = buildCommittedClaim({ contentHash: HASH_PLACEHOLDER_A })
      return buildEnvelope(claim)
    },
  },
  {
    id: '107',
    name: 'envelope-with-ots-proof',
    description: 'A full envelope with one OpenTimestamps proof entry.',
    build: () => {
      const claim = buildCommittedClaim({ contentHash: HASH_PLACEHOLDER_A })
      return buildEnvelope(claim, {
        proofs: [
          {
            type: 'opentimestamps',
            claimHash: computeClaimHash(claim),
            proofRef: 'screenplay.proof.ots',
          },
        ],
      })
    },
  },
  {
    id: '108',
    name: 'envelope-with-multiple-proofs',
    description:
      'A full envelope with multiple proofs (forward-compat test: same claim, multiple anchors).',
    build: () => {
      const claim = buildCommittedClaim({ contentHash: HASH_PLACEHOLDER_A })
      const claimHash = computeClaimHash(claim)
      return buildEnvelope(claim, {
        proofs: [
          { type: 'opentimestamps', claimHash, proofRef: 'a.ots' },
          { type: 'opentimestamps', claimHash, proofRef: 'b.ots' },
          { type: 'future-eas-attestation', claimHash, attestationUid: '0x123' } as any,
        ],
      })
    },
  },
]

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

function clearOldFiles(): void {
  const existing = readdirSync(CORPUS_DIR).filter(
    (f) =>
      f.endsWith('.json') ||
      f.endsWith('.canonical.bin') ||
      f.endsWith('.claim-hash.txt') ||
      f.endsWith('.description.md') ||
      f === 'INDEX.json' ||
      f === 'CORPUS_DIGEST.txt',
  )
  for (const f of existing) {
    try {
      unlinkSync(join(CORPUS_DIR, f))
    } catch {
      // ignore
    }
  }
}

function generate(): void {
  mkdirSync(CORPUS_DIR, { recursive: true })
  clearOldFiles()

  const canonIndex: Array<{ id: string; name: string; description: string }> = []
  for (const v of canonVectors) {
    const prefix = `canon-${v.id}-${v.name}`
    writeFileSync(join(CORPUS_DIR, `${prefix}.input.json`), JSON.stringify(v.input) + '\n')
    const actual = canonicalize(v.input).toString('utf8')
    if (actual !== v.expectedCanonical) {
      throw new Error(
        `Canon vector ${v.id} expected:\n  ${JSON.stringify(v.expectedCanonical)}\ngot:\n  ${JSON.stringify(actual)}`,
      )
    }
    writeFileSync(join(CORPUS_DIR, `${prefix}.canonical.bin`), Buffer.from(v.expectedCanonical, 'utf8'))
    writeFileSync(
      join(CORPUS_DIR, `${prefix}.description.md`),
      `# Canon vector ${v.id} — ${v.name}\n\n${v.description}\n\nExpected canonical form:\n\n\`\`\`\n${v.expectedCanonical}\n\`\`\`\n`,
    )
    canonIndex.push({ id: v.id, name: v.name, description: v.description })
  }

  const envIndex: Array<{ id: string; name: string; description: string }> = []
  for (const v of envelopeVectors) {
    const prefix = `env-${v.id}-${v.name}`
    const value = v.build()
    writeFileSync(join(CORPUS_DIR, `${prefix}.value.json`), JSON.stringify(value, null, 2) + '\n')
    const canonical = canonicalize(value)
    writeFileSync(join(CORPUS_DIR, `${prefix}.canonical.bin`), canonical)
    // For envelope vectors, the claim hash is computed over the committedClaim only.
    const committedClaim =
      (value as any).committedClaim ?? value
    const claimHash = computeClaimHash(committedClaim)
    writeFileSync(join(CORPUS_DIR, `${prefix}.claim-hash.txt`), claimHash + '\n')
    writeFileSync(
      join(CORPUS_DIR, `${prefix}.description.md`),
      `# Envelope vector ${v.id} — ${v.name}\n\n${v.description}\n`,
    )
    envIndex.push({ id: v.id, name: v.name, description: v.description })
  }

  writeFileSync(
    join(CORPUS_DIR, 'INDEX.json'),
    JSON.stringify(
      {
        canonVectors: canonIndex,
        envelopeVectors: envIndex,
      },
      null,
      2,
    ) + '\n',
  )

  // corpus digest
  const files = readdirSync(CORPUS_DIR).filter((f) => f !== 'CORPUS_DIGEST.txt').sort()
  const corpusHash = createHash('sha256')
  for (const f of files) {
    const content = readFileSync(join(CORPUS_DIR, f))
    const fileDigest = createHash('sha256').update(content).digest('hex')
    corpusHash.update(f)
    corpusHash.update(':')
    corpusHash.update(fileDigest)
    corpusHash.update('\n')
  }
  writeFileSync(join(CORPUS_DIR, 'CORPUS_DIGEST.txt'), corpusHash.digest('hex') + '\n')

  console.log(
    `Generated ${canonVectors.length} canonicalization vectors + ${envelopeVectors.length} envelope vectors in ${CORPUS_DIR}`,
  )
}

generate()
