/**
 * Schema validator tests. Mirrors spec/v1/envelope.schema.json.
 *
 * The validator is the verifier's first gate: malformed envelope shape MUST
 * fail BEFORE any cryptographic recomputation. These tests lock that
 * obligation against the kinds of forger-shape that a thorough adversary
 * would try.
 */

import { describe, it, expect } from 'vitest'
import { validateEnvelope } from '../../src/envelope/validate.js'
import { buildCommittedClaim, buildEnvelope } from '../../src/envelope/build.js'
import { computeClaimHash } from '../../src/envelope/claim-hash.js'
import {
  CLAIM_VERSION,
  ENVELOPE_VERSION,
  SCENE_TREE_PROFILE,
  PARAGRAPH_TREE_PROFILE,
  REGISTRANT_SIGNATURE_DOMAIN,
} from '../../src/envelope/types.js'

const SHA = 'sha256:' + 'a'.repeat(64)
const ED25519_KEY = 'ed25519:' + Buffer.from('a'.repeat(32)).toString('base64')
const ED25519_SIG = 'ed25519:' + Buffer.from('b'.repeat(64)).toString('base64')

function buildValidEnvelope() {
  const claim = buildCommittedClaim({ contentHash: SHA })
  return buildEnvelope(claim)
}

describe('validateEnvelope — happy path', () => {
  it('accepts a minimal valid envelope', () => {
    const env = buildValidEnvelope()
    const result = validateEnvelope(env)
    expect(result.ok).toBe(true)
  })

  it('accepts envelope with scene tree triple', () => {
    const claim = buildCommittedClaim({
      contentHash: SHA,
      sceneTree: { root: SHA, count: 5 },
    })
    expect(validateEnvelope(buildEnvelope(claim)).ok).toBe(true)
  })

  it('accepts envelope with paragraph tree triple', () => {
    const claim = buildCommittedClaim({
      contentHash: SHA,
      paragraphTree: { root: SHA, count: 50 },
    })
    expect(validateEnvelope(buildEnvelope(claim)).ok).toBe(true)
  })

  it('accepts envelope with both tree triples + locked preferences', () => {
    const claim = buildCommittedClaim({
      contentHash: SHA,
      sceneTree: { root: SHA, count: 5 },
      paragraphTree: { root: SHA, count: 50 },
      preferences: { trainingMining: 'notAllowed' },
    })
    expect(validateEnvelope(buildEnvelope(claim)).ok).toBe(true)
  })

  it('accepts envelope with registrant block', () => {
    const claim = buildCommittedClaim({
      contentHash: SHA,
      registrant: {
        publicKey: ED25519_KEY,
        signatureAlgorithm: 'ed25519',
        signatureDomain: REGISTRANT_SIGNATURE_DOMAIN,
        signedDigest: SHA,
        signature: ED25519_SIG,
      },
    })
    expect(validateEnvelope(buildEnvelope(claim)).ok).toBe(true)
  })
})

describe('validateEnvelope — locked-value enforcement', () => {
  it('rejects wrong envelopeVersion', () => {
    const env = buildValidEnvelope() as unknown as Record<string, unknown>
    env.envelopeVersion = 'urn:something-else:v2'
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('envelopeVersion'))).toBe(true)
  })

  it('rejects wrong claimVersion', () => {
    const env = buildValidEnvelope()
    ;(env.committedClaim as unknown as Record<string, unknown>).claimVersion = 'urn:something-else:v2'
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('claimVersion'))).toBe(true)
  })

  it('rejects wrong hashAlgorithm', () => {
    const env = buildValidEnvelope()
    ;(env.committedClaim as unknown as Record<string, unknown>).hashAlgorithm = 'sha-512'
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('hashAlgorithm'))).toBe(true)
  })
})

describe('validateEnvelope — all-or-none triples', () => {
  it('rejects partial scene-tree triple (root without profile)', () => {
    const env = buildValidEnvelope()
    ;(env.committedClaim as unknown as Record<string, unknown>).sceneTreeRoot = SHA
    ;(env.committedClaim as unknown as Record<string, unknown>).sceneCount = 5
    // profile is missing
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('all-or-none'))).toBe(true)
  })

  it('rejects partial paragraph-tree triple (count without root or profile)', () => {
    const env = buildValidEnvelope()
    ;(env.committedClaim as unknown as Record<string, unknown>).paragraphCount = 50
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('paragraph') && e.includes('all-or-none'))).toBe(true)
  })
})

describe('validateEnvelope — preferences closed enum', () => {
  it('rejects unknown trainingMining value', () => {
    const claim = buildCommittedClaim({ contentHash: SHA })
    ;(claim as unknown as Record<string, unknown>).preferences = { trainingMining: 'someNewValue' }
    const env = buildEnvelope(claim)
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('trainingMining'))).toBe(true)
  })

  it('rejects unknown preference field', () => {
    const claim = buildCommittedClaim({ contentHash: SHA })
    ;(claim as unknown as Record<string, unknown>).preferences = { trainingMining: 'allowed', futureField: 'x' }
    const env = buildEnvelope(claim)
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('futureField'))).toBe(true)
  })
})

describe('validateEnvelope — registrant block', () => {
  it('rejects registrant with malformed publicKey', () => {
    const env = buildValidEnvelope()
    ;(env.committedClaim as unknown as Record<string, unknown>).registrant = {
      publicKey: 'not-an-ed25519-key',
      signatureAlgorithm: 'ed25519',
      signatureDomain: REGISTRANT_SIGNATURE_DOMAIN,
      signedDigest: SHA,
      signature: ED25519_SIG,
    }
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('publicKey'))).toBe(true)
  })

  it('rejects registrant with wrong signatureDomain', () => {
    const env = buildValidEnvelope()
    ;(env.committedClaim as unknown as Record<string, unknown>).registrant = {
      publicKey: ED25519_KEY,
      signatureAlgorithm: 'ed25519',
      signatureDomain: 'wrong-domain',
      signedDigest: SHA,
      signature: ED25519_SIG,
    }
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('signatureDomain'))).toBe(true)
  })
})

describe('validateEnvelope — hash format pattern', () => {
  it('rejects malformed contentHash (no prefix)', () => {
    const env = buildValidEnvelope()
    ;(env.committedClaim as unknown as Record<string, unknown>).contentHash = 'a'.repeat(64)
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('contentHash'))).toBe(true)
  })

  it('rejects malformed contentHash (uppercase hex)', () => {
    const env = buildValidEnvelope()
    ;(env.committedClaim as unknown as Record<string, unknown>).contentHash = 'sha256:' + 'A'.repeat(64)
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('contentHash'))).toBe(true)
  })
})

describe('validateEnvelope — accumulates errors instead of short-circuiting', () => {
  it('reports multiple errors in one pass', () => {
    const env = buildValidEnvelope() as unknown as Record<string, unknown>
    env.envelopeVersion = 'wrong'
    ;(env.committedClaim as unknown as Record<string, unknown>).hashAlgorithm = 'sha-512'
    ;(env.committedClaim as unknown as Record<string, unknown>).contentHash = 'invalid'
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.length).toBeGreaterThanOrEqual(3)
  })
})

describe('validateEnvelope — envelope-level shape', () => {
  it('rejects non-object envelope', () => {
    expect(validateEnvelope(null).ok).toBe(false)
    expect(validateEnvelope('string').ok).toBe(false)
    expect(validateEnvelope([1, 2, 3]).ok).toBe(false)
  })

  it('rejects envelope with unknown top-level field', () => {
    const env = buildValidEnvelope() as unknown as Record<string, unknown>
    env.unknownField = 'sneaky'
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('unknownField'))).toBe(true)
  })

  it('rejects evidence proof with wrong claim hash format', () => {
    const claim = buildCommittedClaim({ contentHash: SHA })
    const env = buildEnvelope(claim, {
      proofs: [{ type: 'opentimestamps', claimHash: 'malformed', proofRef: 'a.ots' } as never],
    })
    const r = validateEnvelope(env)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('claimHash'))).toBe(true)
  })
})

describe('validateEnvelope — timelock unlockAt date-time format', () => {
  function withTimelock(unlockAt: string) {
    const env = buildValidEnvelope()
    ;(env.committedClaim as unknown as Record<string, unknown>).timelockFields = [
      {
        name: 'title',
        ciphertext: 'placeholder',
        unlockAtRound: 12345,
        unlockAt,
        drandChainHash: 'a'.repeat(64),
        drandPublicKey: 'a'.repeat(96),
        scheme: 'tlock-bls12-381-quicknet',
      },
    ]
    return env
  }
  it('accepts canonical UTC ISO 8601 (e.g. 2027-01-01T00:00:00Z)', () => {
    expect(validateEnvelope(withTimelock('2027-01-01T00:00:00Z')).ok).toBe(true)
  })
  it('accepts millisecond precision + offset', () => {
    expect(validateEnvelope(withTimelock('2027-01-01T00:00:00.123+00:00')).ok).toBe(true)
  })
  it('rejects shorthand date (just YYYY)', () => {
    const r = validateEnvelope(withTimelock('2027'))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('unlockAt') && e.includes('RFC 3339'))).toBe(true)
  })
  it('rejects free-form date string', () => {
    const r = validateEnvelope(withTimelock('January 1st, 2027'))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('unlockAt'))).toBe(true)
  })
  it('rejects missing time portion', () => {
    const r = validateEnvelope(withTimelock('2027-01-01'))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.some((e) => e.includes('unlockAt'))).toBe(true)
  })
})

describe('validateEnvelope — locked constants sanity', () => {
  it('rejects future schemaId or claimVersion (cannot be silently bumped)', () => {
    expect(CLAIM_VERSION).toBe('urn:screenplay-registration-claim:v1')
    expect(ENVELOPE_VERSION).toBe('urn:screenplay-registration-envelope:v1')
    expect(SCENE_TREE_PROFILE).toBe('screenplay-registration-merkle/v1')
    expect(PARAGRAPH_TREE_PROFILE).toBe('screenplay-registration-paragraph-merkle/v1')
    // Sanity-check: a claim with v2 schemaId fails validation
    const env = buildValidEnvelope()
    ;(env.committedClaim as unknown as Record<string, unknown>).schemaId =
      'urn:screenplay-registration-claim-schema:v2'
    expect(validateEnvelope(env).ok).toBe(false)
  })
})

describe('validateEnvelope — round-trips against computeClaimHash', () => {
  it('a valid envelope validates AND its claim hash recomputes consistently', () => {
    const claim = buildCommittedClaim({
      contentHash: SHA,
      sceneTree: { root: SHA, count: 3 },
      preferences: { trainingMining: 'notAllowed' },
    })
    const env = buildEnvelope(claim)
    expect(validateEnvelope(env).ok).toBe(true)
    // Independent: hash computation works on the same claim
    expect(computeClaimHash(env.committedClaim)).toMatch(/^sha256:[0-9a-f]{64}$/)
  })
})
