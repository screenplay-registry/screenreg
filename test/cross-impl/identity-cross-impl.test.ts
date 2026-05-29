/**
 * Cross-implementation parity for Ed25519 registrant-block signing.
 *
 * Asserts:
 *   - Both implementations agree on the canonical claim-body digest
 *     for the same input (deterministic via canonicalize + sha256).
 *   - A registrant block signed by the SHARED (Web Crypto) impl
 *     verifies via the LEGACY (Node KeyObject) impl.
 *   - A registrant block signed by the LEGACY impl verifies via the
 *     SHARED impl.
 *   - Public-key encoding round-trips byte-identical through both.
 *
 * This pins the property that the browser /create/ page and the CLI
 * produce signatures that the OPPOSITE verifier accepts. Without that,
 * a writer who registers in the browser couldn't later prove identity
 * via the CLI (or vice versa).
 */

import { describe, it, expect } from 'vitest'

import {
  signRegistration as sharedSignRegistration,
  generateKeypair as sharedGenerateKeypair,
  encodePublicKey as sharedEncodePublicKey,
  computeClaimBodyDigest as sharedComputeClaimBodyDigest,
  verifyRegistrantBlock as sharedVerifyRegistrantBlock,
} from '../../src/shared/identity/ed25519-signing.js'

import {
  signRegistration as legacySignRegistration,
  generateKeypair as legacyGenerateKeypair,
  loadPrivateKey as legacyLoadPrivateKey,
  decodePublicKey as legacyDecodePublicKey,
  computeClaimBodyDigest as legacyComputeClaimBodyDigest,
  verifyRegistrationSignature as legacyVerifyRegistrationSignature,
} from '../../src/identity/ed25519-signing.js'

import { buildCommittedClaim } from '../../src/envelope/build.js'

const SAMPLE_CONTENT_HASH = 'sha256:' + 'ab'.repeat(32)

describe('cross-impl identity: computeClaimBodyDigest parity', () => {
  const claims = [
    buildCommittedClaim({ contentHash: SAMPLE_CONTENT_HASH }),
    buildCommittedClaim({
      contentHash: SAMPLE_CONTENT_HASH,
      sceneTree: { root: 'sha256:' + 'cd'.repeat(32), count: 7 },
    }),
    buildCommittedClaim({
      contentHash: SAMPLE_CONTENT_HASH,
      preferences: { trainingMining: 'notAllowed' },
    }),
  ]
  for (const claim of claims) {
    it(`shared and legacy agree on body digest (sceneCount=${claim.sceneCount ?? 0})`, async () => {
      const sharedDigest = await sharedComputeClaimBodyDigest(claim)
      const legacyDigest = legacyComputeClaimBodyDigest(claim)
      expect(sharedDigest).toBe(legacyDigest)
      expect(sharedDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
    })
  }
})

describe('cross-impl identity: shared-signs / legacy-verifies', () => {
  it('a registrant block signed by the shared (Web Crypto) impl verifies via the legacy impl', async () => {
    const claim = buildCommittedClaim({ contentHash: SAMPLE_CONTENT_HASH })
    const { privateKey, publicKey, publicKeyEncoded } = await sharedGenerateKeypair()
    void publicKey
    const block = await sharedSignRegistration(claim, privateKey, publicKeyEncoded)
    expect(block.signatureAlgorithm).toBe('ed25519')
    expect(block.publicKey).toBe(publicKeyEncoded)
    expect(block.signature).toMatch(/^ed25519:/)
    // Legacy verifier: re-attach block to claim and verify
    const claimWithReg = { ...claim, registrant: block }
    const verifyResult = legacyVerifyRegistrationSignature(claimWithReg)
    expect(verifyResult.ok).toBe(true)
  })
})

describe('cross-impl identity: legacy-signs / shared-verifies', () => {
  it('a registrant block signed by the legacy impl verifies via the shared impl', async () => {
    const claim = buildCommittedClaim({ contentHash: SAMPLE_CONTENT_HASH })
    const { privateKeyPem, publicKeyEncoded } = legacyGenerateKeypair()
    const privateKey = legacyLoadPrivateKey(privateKeyPem)
    const block = legacySignRegistration(claim, privateKey, publicKeyEncoded)
    const claimWithReg = { ...claim, registrant: block }
    const ok = await sharedVerifyRegistrantBlock(claimWithReg)
    expect(ok).toBe(true)
  })
})

describe('cross-impl identity: public-key encoding round-trip', () => {
  it('shared-generated public key decodes via legacy', async () => {
    const { publicKey, publicKeyEncoded } = await sharedGenerateKeypair()
    void publicKey
    const decoded = legacyDecodePublicKey(publicKeyEncoded)
    expect(decoded.asymmetricKeyType).toBe('ed25519')
    // Re-encode through legacy and confirm byte-identical
    const legacyEncoded = await sharedEncodePublicKey(
      await (async () => {
        // Use the raw JWK x to roundtrip into a Web Crypto key
        const jwk = decoded.export({ format: 'jwk' }) as {
          kty?: string
          crv?: string
          x?: string
        }
        return globalThis.crypto.subtle.importKey(
          'jwk',
          jwk,
          { name: 'Ed25519' },
          true,
          ['verify'],
        )
      })(),
    )
    expect(legacyEncoded).toBe(publicKeyEncoded)
  })
})

describe('cross-impl identity: verifyRegistrantBlock catches tamper', () => {
  it('returns false when claim contents are mutated post-sign', async () => {
    const claim = buildCommittedClaim({ contentHash: SAMPLE_CONTENT_HASH })
    const { privateKey, publicKeyEncoded } = await sharedGenerateKeypair()
    const block = await sharedSignRegistration(claim, privateKey, publicKeyEncoded)
    const tampered = {
      ...claim,
      contentHash: 'sha256:' + 'ff'.repeat(32),
      registrant: block,
    }
    expect(await sharedVerifyRegistrantBlock(tampered)).toBe(false)
  })

  it('returns false when signature bytes are flipped', async () => {
    const claim = buildCommittedClaim({ contentHash: SAMPLE_CONTENT_HASH })
    const { privateKey, publicKeyEncoded } = await sharedGenerateKeypair()
    const block = await sharedSignRegistration(claim, privateKey, publicKeyEncoded)
    // Flip the first byte of the signature payload
    const tamperedSig = block.signature.slice(0, 8) + 'A' + block.signature.slice(9)
    const tampered = { ...claim, registrant: { ...block, signature: tamperedSig } }
    expect(await sharedVerifyRegistrantBlock(tampered)).toBe(false)
  })
})
