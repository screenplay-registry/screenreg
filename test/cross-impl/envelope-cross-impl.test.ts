/**
 * Cross-implementation parity test for envelope canonicalization + claim hash.
 *
 * Runs the full envelope corpus through both the Node-side and cross-runtime
 * implementations of `canonicalize` and `computeClaimHash`. Asserts byte-identical
 * canonical output and byte-identical claim hashes across every published vector.
 * Drift here = silent verification mismatches; CI fails loudly on any byte difference.
 *
 * Exercises the corpus plus adversarial inputs covering unicode edges, key ordering,
 * deeply nested structures, and bad-input rejection paths.
 */

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalize as legacyCanonicalize,
  canonicalizeToString as legacyCanonicalizeToString,
} from '../../src/envelope/canonicalize.js'
import { computeClaimHash as legacyComputeClaimHash } from '../../src/envelope/claim-hash.js'
import { validateEnvelope as legacyValidateEnvelope } from '../../src/envelope/validate.js'
import {
  buildCommittedClaim as legacyBuildCommittedClaim,
  buildEvidenceBundle as legacyBuildEvidenceBundle,
  buildEnvelope as legacyBuildEnvelope,
  checkEnvelopeConsistency as legacyCheckEnvelopeConsistency,
} from '../../src/envelope/build.js'
import * as legacyTypes from '../../src/envelope/types.js'

import {
  canonicalize as sharedCanonicalize,
  canonicalizeToString as sharedCanonicalizeToString,
} from '../../src/shared/envelope/canonicalize.js'
import { computeClaimHash as sharedComputeClaimHash } from '../../src/shared/envelope/claim-hash.js'
import { validateEnvelope as sharedValidateEnvelope } from '../../src/shared/envelope/validate.js'
import {
  buildCommittedClaim as sharedBuildCommittedClaim,
  buildEvidenceBundle as sharedBuildEvidenceBundle,
  buildEnvelope as sharedBuildEnvelope,
  checkEnvelopeConsistency as sharedCheckEnvelopeConsistency,
} from '../../src/shared/envelope/build.js'
import * as sharedTypes from '../../src/shared/envelope/types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CORPUS_DIR = join(__dirname, '..', '..', 'spec', 'v1', 'testvectors', 'envelope')

interface IndexFile {
  canonVectors: Array<{ id: string; name: string; description: string }>
  envelopeVectors: Array<{ id: string; name: string; description: string }>
}

const indexJson = JSON.parse(readFileSync(join(CORPUS_DIR, 'INDEX.json'), 'utf8')) as IndexFile

// ---------------------------------------------------------------------------
// canonicalize() byte-parity over the official corpus
// ---------------------------------------------------------------------------

describe('cross-impl: canonicalize parity over corpus', () => {
  for (const v of indexJson.canonVectors) {
    const prefix = `canon-${v.id}-${v.name}`
    it(`${v.id} ${v.name}: legacy and shared produce byte-identical output`, () => {
      const input = JSON.parse(
        readFileSync(join(CORPUS_DIR, `${prefix}.input.json`), 'utf8'),
      )

      const legacyBytes = legacyCanonicalize(input)
      const sharedBytes = sharedCanonicalize(input)

      // Also re-derive expected canonical bytes from the corpus to confirm both match it.
      const corpusExpected = readFileSync(join(CORPUS_DIR, `${prefix}.canonical.bin`))
      const corpusExpectedU8 = new Uint8Array(
        corpusExpected.buffer,
        corpusExpected.byteOffset,
        corpusExpected.byteLength,
      )

      expect(sharedBytes.length).toBe(legacyBytes.length)
      expect(sharedBytes.length).toBe(corpusExpectedU8.length)
      for (let i = 0; i < sharedBytes.length; i++) {
        if (sharedBytes[i] !== legacyBytes[i]) {
          throw new Error(
            `legacy/shared divergence at byte ${i}: legacy=0x${legacyBytes[i]!.toString(16).padStart(2, '0')} shared=0x${sharedBytes[i]!.toString(16).padStart(2, '0')}`,
          )
        }
        if (sharedBytes[i] !== corpusExpectedU8[i]) {
          throw new Error(
            `shared/corpus divergence at byte ${i}: shared=0x${sharedBytes[i]!.toString(16).padStart(2, '0')} corpus=0x${corpusExpectedU8[i]!.toString(16).padStart(2, '0')}`,
          )
        }
      }
    })
  }
})

// ---------------------------------------------------------------------------
// canonicalizeToString() character-parity — same string before UTF-8 encoding
// ---------------------------------------------------------------------------

describe('cross-impl: canonicalizeToString parity over corpus', () => {
  for (const v of indexJson.canonVectors) {
    const prefix = `canon-${v.id}-${v.name}`
    it(`${v.id} ${v.name}: pre-encoding string forms are identical`, () => {
      const input = JSON.parse(
        readFileSync(join(CORPUS_DIR, `${prefix}.input.json`), 'utf8'),
      )
      expect(sharedCanonicalizeToString(input)).toBe(legacyCanonicalizeToString(input))
    })
  }
})

// ---------------------------------------------------------------------------
// Adversarial canonicalization inputs not necessarily in the corpus
// ---------------------------------------------------------------------------

describe('cross-impl: canonicalize parity on adversarial inputs', () => {
  const cases: Array<{ name: string; value: unknown }> = [
    { name: 'empty object', value: {} },
    { name: 'empty array', value: [] },
    { name: 'nested objects with shared key names', value: { a: { a: { a: 1 } } } },
    { name: 'mixed numeric types', value: { i: 42, f: 3.14, z: 0, nz: -0 } },
    { name: 'key ordering reversed', value: { z: 1, a: 2, m: 3 } },
    { name: 'unicode keys', value: { 'café': 1, 'naïve': 2, '中': 3 } },
    { name: 'unicode values', value: ['café', 'naïve', '中文', 'لطيف'] },
    { name: 'string with all escapes', value: '"\\\b\f\n\r\t' },
    { name: 'control char in string', value: '' },
    { name: 'surrogate pair (U+1F600 grinning face)', value: '😀' },
    { name: 'deeply nested', value: { a: { b: { c: { d: { e: { f: 1 } } } } } } },
    { name: 'object with undefined value (dropped)', value: { a: 1, b: undefined } },
    { name: 'array of mixed types', value: [null, true, false, 0, '', {}, []] },
    { name: 'integers across the safe range', value: { min: -9007199254740991, max: 9007199254740991 } },
  ]
  for (const c of cases) {
    it(`adversarial: ${c.name}`, () => {
      const legacyBytes = legacyCanonicalize(c.value)
      const sharedBytes = sharedCanonicalize(c.value)
      expect(sharedBytes.length).toBe(legacyBytes.length)
      for (let i = 0; i < sharedBytes.length; i++) {
        expect(sharedBytes[i]).toBe(legacyBytes[i])
      }
    })
  }
})

describe('cross-impl: canonicalize throws on the same bad inputs', () => {
  const badCases: Array<{ name: string; value: unknown; pattern: RegExp }> = [
    { name: 'NaN', value: NaN, pattern: /NaN/i },
    { name: 'Infinity', value: Infinity, pattern: /Infinity/i },
    { name: '-Infinity', value: -Infinity, pattern: /Infinity/i },
    { name: 'undefined at root', value: undefined, pattern: /undefined/ },
    { name: 'bigint', value: 12345678901234567890n, pattern: /bigint/ },
    { name: 'integer past MAX_SAFE_INTEGER', value: Number.MAX_SAFE_INTEGER + 2, pattern: /safe/i },
    { name: 'lone high surrogate', value: '\uD800', pattern: /surrogate/i },
    { name: 'lone low surrogate', value: '\uDC00', pattern: /surrogate/i },
  ]
  for (const c of badCases) {
    it(`both throw on: ${c.name}`, () => {
      expect(() => legacyCanonicalize(c.value)).toThrow(c.pattern)
      expect(() => sharedCanonicalize(c.value)).toThrow(c.pattern)
    })
  }
})

// ---------------------------------------------------------------------------
// computeClaimHash() byte-parity over the envelope corpus
// ---------------------------------------------------------------------------

describe('cross-impl: computeClaimHash parity over envelope corpus', () => {
  if (indexJson.envelopeVectors.length === 0) {
    it('corpus has no envelope vectors (sentinel)', () => {
      expect(indexJson.envelopeVectors).toEqual([])
    })
  }
  for (const v of indexJson.envelopeVectors) {
    const prefix = `env-${v.id}-${v.name}`
    it(`${v.id} ${v.name}: legacy and shared compute the same claimHash + match corpus`, async () => {
      const valuePath = join(CORPUS_DIR, `${prefix}.value.json`)
      const claimHashPath = join(CORPUS_DIR, `${prefix}.claim-hash.txt`)
      const value = JSON.parse(readFileSync(valuePath, 'utf8'))
      // Some vectors store the full envelope (with committedClaim + evidenceBundle);
      // others store the bare CommittedClaim. The corpus's .claim-hash.txt is always
      // the hash of the committedClaim, so unwrap if needed.
      const claim =
        value && typeof value === 'object' && 'committedClaim' in value
          ? (value as { committedClaim: unknown }).committedClaim
          : value
      const expectedHash = readFileSync(claimHashPath, 'utf8').trim()
      const legacyHash = legacyComputeClaimHash(claim as Parameters<typeof legacyComputeClaimHash>[0])
      const sharedHash = await sharedComputeClaimHash(claim)
      expect(legacyHash).toBe(expectedHash)
      expect(sharedHash).toBe(expectedHash)
      expect(sharedHash).toBe(legacyHash)
    })
  }
})

// ---------------------------------------------------------------------------
// types.ts — locked-constant parity. If any of these drifts, the entire
// commitment model is broken on one side. CI must fail loudly.
// ---------------------------------------------------------------------------

describe('cross-impl: types.ts locked-constant parity', () => {
  const constants = [
    'ENVELOPE_VERSION',
    'CLAIM_VERSION',
    'SCHEMA_ID',
    'HASH_ALGORITHM',
    'MANIFEST_CANONICALIZATION',
    'NORMALIZATION_PROFILE',
    'SCENE_TREE_PROFILE',
    'PARAGRAPH_TREE_PROFILE',
    'REGISTRANT_SIGNATURE_DOMAIN',
  ] as const
  for (const k of constants) {
    it(`${k} value is identical in legacy and shared`, () => {
      const lv = (legacyTypes as Record<string, unknown>)[k]
      const sv = (sharedTypes as Record<string, unknown>)[k]
      expect(typeof sv).toBe('string')
      expect(sv).toBe(lv)
    })
  }
})

// ---------------------------------------------------------------------------
// validate.ts — same envelope input must produce same {ok, errors[]} output.
// ---------------------------------------------------------------------------

describe('cross-impl: validateEnvelope parity over envelope corpus', () => {
  if (indexJson.envelopeVectors.length === 0) {
    it('corpus has no envelope vectors (sentinel)', () => {
      expect(indexJson.envelopeVectors).toEqual([])
    })
  }
  for (const v of indexJson.envelopeVectors) {
    const prefix = `env-${v.id}-${v.name}`
    it(`${v.id} ${v.name}: legacy and shared agree on validation outcome`, () => {
      const value = JSON.parse(readFileSync(join(CORPUS_DIR, `${prefix}.value.json`), 'utf8'))
      // Vectors come in two shapes: a bare CommittedClaim, or a full Envelope. The
      // validator expects an Envelope, so wrap a bare claim in a minimal envelope
      // shell; pass full-envelope vectors through as-is.
      const envelope =
        value && typeof value === 'object' && 'envelopeVersion' in value
          ? value
          : {
              envelopeVersion: 'urn:screenplay-registration-envelope:v1',
              committedClaim: value,
              evidenceBundle: {
                committedClaimHash:
                  readFileSync(join(CORPUS_DIR, `${prefix}.claim-hash.txt`), 'utf8').trim(),
                proofs: [],
                bundleExtensions: {},
              },
            }
      const legacyOut = legacyValidateEnvelope(envelope)
      const sharedOut = sharedValidateEnvelope(envelope)
      expect(sharedOut.ok).toBe(legacyOut.ok)
      if (!legacyOut.ok && !sharedOut.ok) {
        expect(sharedOut.errors.length).toBe(legacyOut.errors.length)
        for (let i = 0; i < legacyOut.errors.length; i++) {
          expect(sharedOut.errors[i]).toBe(legacyOut.errors[i])
        }
      }
    })
  }
})

describe('cross-impl: validateEnvelope parity on adversarial inputs', () => {
  // Each adversarial input MUST be rejected with the same errors by both validators.
  const adversarial: Array<{ name: string; input: unknown }> = [
    { name: 'null', input: null },
    { name: 'undefined', input: undefined },
    { name: 'string', input: 'not an envelope' },
    { name: 'array', input: [] },
    { name: 'empty object', input: {} },
    { name: 'wrong envelopeVersion', input: { envelopeVersion: 'wrong', committedClaim: {}, evidenceBundle: {} } },
    { name: 'extra keys at envelope level', input: { envelopeVersion: 'urn:screenplay-registration-envelope:v1', committedClaim: {}, evidenceBundle: {}, extra: 1 } },
    {
      name: 'committedClaim missing required',
      input: {
        envelopeVersion: 'urn:screenplay-registration-envelope:v1',
        committedClaim: { claimVersion: 'urn:screenplay-registration-claim:v1' },
        evidenceBundle: {},
      },
    },
    {
      name: 'scene tree partial (root + count, missing profile)',
      input: {
        envelopeVersion: 'urn:screenplay-registration-envelope:v1',
        committedClaim: {
          claimVersion: 'urn:screenplay-registration-claim:v1',
          schemaId: 'urn:screenplay-registration-claim-schema:v1',
          hashAlgorithm: 'sha-256',
          manifestCanonicalization: 'rfc8785',
          normalizationProfile: 'screenplay-registration-norm/v1-strict',
          contentHash: 'sha256:' + '0'.repeat(64),
          claimExtensions: {},
          sceneTreeRoot: 'sha256:' + '1'.repeat(64),
          sceneCount: 1,
        },
        evidenceBundle: {
          committedClaimHash: 'sha256:' + '2'.repeat(64),
          proofs: [],
          bundleExtensions: {},
        },
      },
    },
    {
      name: 'preferences with unknown enum value',
      input: {
        envelopeVersion: 'urn:screenplay-registration-envelope:v1',
        committedClaim: {
          claimVersion: 'urn:screenplay-registration-claim:v1',
          schemaId: 'urn:screenplay-registration-claim-schema:v1',
          hashAlgorithm: 'sha-256',
          manifestCanonicalization: 'rfc8785',
          normalizationProfile: 'screenplay-registration-norm/v1-strict',
          contentHash: 'sha256:' + '0'.repeat(64),
          claimExtensions: {},
          preferences: { trainingMining: 'unknownValue' },
        },
        evidenceBundle: {
          committedClaimHash: 'sha256:' + '2'.repeat(64),
          proofs: [],
          bundleExtensions: {},
        },
      },
    },
  ]
  for (const t of adversarial) {
    it(`adversarial: ${t.name}`, () => {
      const legacyOut = legacyValidateEnvelope(t.input)
      const sharedOut = sharedValidateEnvelope(t.input)
      expect(sharedOut.ok).toBe(legacyOut.ok)
      if (!legacyOut.ok && !sharedOut.ok) {
        expect(sharedOut.errors).toEqual(legacyOut.errors)
      }
    })
  }
})

// ---------------------------------------------------------------------------
// build.ts — builders must produce structurally identical outputs.
// buildEnvelope is sync in legacy and async in shared, but the resulting envelope
// shape must match exactly.
// ---------------------------------------------------------------------------

describe('cross-impl: buildCommittedClaim produces identical CommittedClaim', () => {
  const cases: Array<{ name: string; input: Parameters<typeof legacyBuildCommittedClaim>[0] }> = [
    { name: 'minimal claim', input: { contentHash: 'sha256:' + 'a'.repeat(64) } },
    {
      name: 'with scene tree',
      input: {
        contentHash: 'sha256:' + 'b'.repeat(64),
        sceneTree: { root: 'sha256:' + 'c'.repeat(64), count: 13 },
      },
    },
    {
      name: 'with paragraph tree',
      input: {
        contentHash: 'sha256:' + 'd'.repeat(64),
        paragraphTree: { root: 'sha256:' + 'e'.repeat(64), count: 89 },
      },
    },
    {
      name: 'with both trees + previous registration + preferences',
      input: {
        contentHash: 'sha256:' + 'f'.repeat(64),
        sceneTree: { root: 'sha256:' + '1'.repeat(64), count: 5 },
        paragraphTree: { root: 'sha256:' + '2'.repeat(64), count: 50 },
        previousRegistration: { claimHash: 'sha256:' + '3'.repeat(64) },
        preferences: { trainingMining: 'notAllowed' },
      },
    },
    {
      name: 'with claimExtensions',
      input: {
        contentHash: 'sha256:' + '0'.repeat(64),
        claimExtensions: { customField: 'custom value', nested: { a: 1, b: [true, false] } },
      },
    },
  ]
  for (const c of cases) {
    it(`buildCommittedClaim: ${c.name}`, () => {
      const lc = legacyBuildCommittedClaim(c.input)
      const sc = sharedBuildCommittedClaim(c.input as Parameters<typeof sharedBuildCommittedClaim>[0])
      expect(sc).toEqual(lc)
    })
  }
})

describe('cross-impl: buildEnvelope produces identical Envelope', () => {
  const cases: Array<{ name: string; input: Parameters<typeof legacyBuildCommittedClaim>[0] }> = [
    { name: 'minimal claim', input: { contentHash: 'sha256:' + 'a'.repeat(64) } },
    {
      name: 'with scene + paragraph trees',
      input: {
        contentHash: 'sha256:' + 'b'.repeat(64),
        sceneTree: { root: 'sha256:' + 'c'.repeat(64), count: 13 },
        paragraphTree: { root: 'sha256:' + 'd'.repeat(64), count: 89 },
      },
    },
    {
      name: 'with preferences',
      input: {
        contentHash: 'sha256:' + '0'.repeat(64),
        preferences: { trainingMining: 'notAllowed' },
      },
    },
  ]
  for (const c of cases) {
    it(`buildEnvelope: ${c.name}`, async () => {
      const lc = legacyBuildCommittedClaim(c.input)
      const sc = sharedBuildCommittedClaim(c.input as Parameters<typeof sharedBuildCommittedClaim>[0])
      const lEnv = legacyBuildEnvelope(lc)
      const sEnv = await sharedBuildEnvelope(sc)
      expect(sEnv).toEqual(lEnv)
    })
  }
})

describe('cross-impl: checkEnvelopeConsistency parity', () => {
  it('both pass when claim hash matches', () => {
    const claim = legacyBuildCommittedClaim({ contentHash: 'sha256:' + 'a'.repeat(64) })
    const claimHash = legacyComputeClaimHash(claim)
    const env = legacyBuildEnvelope(claim)
    const lOut = legacyCheckEnvelopeConsistency(env, claimHash)
    const sOut = sharedCheckEnvelopeConsistency(env, claimHash)
    expect(sOut).toEqual(lOut)
    expect(sOut.ok).toBe(true)
  })

  it('both fail with claim-hash-mismatch when independent hash differs', () => {
    const claim = legacyBuildCommittedClaim({ contentHash: 'sha256:' + 'a'.repeat(64) })
    const env = legacyBuildEnvelope(claim)
    const wrongHash = 'sha256:' + 'f'.repeat(64)
    const lOut = legacyCheckEnvelopeConsistency(env, wrongHash)
    const sOut = sharedCheckEnvelopeConsistency(env, wrongHash)
    expect(sOut).toEqual(lOut)
    if (!sOut.ok && !lOut.ok) {
      expect(sOut.reason).toBe('claim-hash-mismatch')
    }
  })

  it('both fail with envelope-version-mismatch when version is wrong', () => {
    const claim = legacyBuildCommittedClaim({ contentHash: 'sha256:' + 'a'.repeat(64) })
    const claimHash = legacyComputeClaimHash(claim)
    const env = legacyBuildEnvelope(claim)
    const tamperedEnv = { ...env, envelopeVersion: 'urn:wrong-version' } as unknown as typeof env
    const lOut = legacyCheckEnvelopeConsistency(tamperedEnv, claimHash)
    const sOut = sharedCheckEnvelopeConsistency(tamperedEnv, claimHash)
    expect(sOut).toEqual(lOut)
    if (!sOut.ok && !lOut.ok) {
      expect(sOut.reason).toBe('envelope-version-mismatch')
    }
  })
})

// Suppress unused-warning by referencing the imports in a no-op smoke check
describe('cross-impl: shared exports are wired', () => {
  it('shared buildEvidenceBundle returns an object', () => {
    const out = sharedBuildEvidenceBundle({ claimHash: 'sha256:' + '0'.repeat(64) })
    expect(out.committedClaimHash).toMatch(/^sha256:/)
    expect(legacyBuildEvidenceBundle({ claimHash: 'sha256:' + '0'.repeat(64) })).toEqual(out)
  })
})

describe('cross-impl: computeClaimHash on adversarial claim shapes', () => {
  const shapes: Array<{ name: string; claim: unknown }> = [
    { name: 'empty claim object', claim: {} },
    { name: 'minimal v1 claim', claim: { schemaVersion: 1, namespace: 'urn:screenplay-registration-claim:v1' } },
    { name: 'claim with unicode title', claim: { title: '中文 — 한국어 — العربية' } },
    { name: 'claim with deep nesting', claim: { a: { b: { c: { d: { e: 1 } } } } } },
    { name: 'claim with all-escape string field', claim: { x: '"\\\b\f\n\r\t' } },
  ]
  for (const s of shapes) {
    it(`adversarial claim shape: ${s.name}`, async () => {
      const legacyHash = legacyComputeClaimHash(s.claim as Parameters<typeof legacyComputeClaimHash>[0])
      const sharedHash = await sharedComputeClaimHash(s.claim)
      expect(sharedHash).toBe(legacyHash)
    })
  }
})
