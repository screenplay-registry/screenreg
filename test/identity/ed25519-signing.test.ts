/**
 * Tests for Ed25519 signing (Section 06).
 *
 * Covers:
 *  - Generate keypair → encode/decode round-trip
 *  - Sign challenge → verify (happy path)
 *  - Wrong challenge → verify fails
 *  - Wrong claimHash → verify fails (domain-separation enforced)
 *  - Wrong key → verify fails
 *  - Replay across different protocols → verify fails (transcript prefix prevents)
 */

import { describe, it, expect } from 'vitest'
import { createPublicKey } from 'node:crypto'
import {
  generateKeypair,
  encodePublicKey,
  decodePublicKey,
  loadPrivateKey,
  signChallenge,
  verifySignature,
  buildTranscript,
  TRANSCRIPT_PREFIX,
  PUBLIC_KEY_PREFIX,
} from '../../src/identity/ed25519-signing.js'

const CLAIM_HASH_A = 'sha256:' + 'a'.repeat(64)
const CLAIM_HASH_B = 'sha256:' + 'b'.repeat(64)

describe('locked constants', () => {
  it('TRANSCRIPT_PREFIX is the spec value', () => {
    expect(TRANSCRIPT_PREFIX.toString('utf8')).toBe('screenreg-proof-v1')
  })
  it('PUBLIC_KEY_PREFIX is "ed25519:"', () => {
    expect(PUBLIC_KEY_PREFIX).toBe('ed25519:')
  })
})

describe('keypair generation', () => {
  it('generates a fresh keypair on each call', () => {
    const a = generateKeypair()
    const b = generateKeypair()
    expect(a.publicKeyEncoded).not.toBe(b.publicKeyEncoded)
    expect(a.privateKeyPem).not.toBe(b.privateKeyPem)
  })

  it('encodes the public key with the ed25519: prefix and 32-byte base64', () => {
    const kp = generateKeypair()
    expect(kp.publicKeyEncoded.startsWith('ed25519:')).toBe(true)
    const raw = Buffer.from(kp.publicKeyEncoded.slice('ed25519:'.length), 'base64')
    expect(raw.length).toBe(32)
  })

  it('decodePublicKey round-trips via encodePublicKey', () => {
    const kp = generateKeypair()
    const decoded = decodePublicKey(kp.publicKeyEncoded)
    expect(encodePublicKey(decoded)).toBe(kp.publicKeyEncoded)
  })
})

describe('sign + verify happy path', () => {
  it('signs a challenge and verifies with the matching public key', () => {
    const kp = generateKeypair()
    const privateKey = loadPrivateKey(kp.privateKeyPem)
    const challenge = Buffer.from('hello-world', 'utf8')
    const sig = signChallenge(CLAIM_HASH_A, challenge, privateKey)
    expect(sig.length).toBe(64)
    const ok = verifySignature({
      claimHash: CLAIM_HASH_A,
      challenge,
      publicKeyEncoded: kp.publicKeyEncoded,
      signature: sig,
    })
    expect(ok).toBe(true)
  })
})

describe('domain separation: transcript binds claimHash', () => {
  it('signature for claimHash_A does NOT verify against claimHash_B', () => {
    const kp = generateKeypair()
    const privateKey = loadPrivateKey(kp.privateKeyPem)
    const challenge = Buffer.from('xyz', 'utf8')
    const sigA = signChallenge(CLAIM_HASH_A, challenge, privateKey)
    const ok = verifySignature({
      claimHash: CLAIM_HASH_B,
      challenge,
      publicKeyEncoded: kp.publicKeyEncoded,
      signature: sigA,
    })
    expect(ok).toBe(false)
  })

  it('transcript includes the prefix + 32-byte claim hash + challenge', () => {
    const challenge = Buffer.from([0xde, 0xad, 0xbe, 0xef])
    const transcript = buildTranscript(CLAIM_HASH_A, challenge)
    expect(transcript.length).toBe(
      TRANSCRIPT_PREFIX.length + 32 + challenge.length,
    )
    // Prefix
    expect(transcript.subarray(0, TRANSCRIPT_PREFIX.length).equals(TRANSCRIPT_PREFIX)).toBe(true)
    // Claim hash (32 raw bytes)
    const expectedClaim = Buffer.from('a'.repeat(64), 'hex')
    expect(transcript.subarray(TRANSCRIPT_PREFIX.length, TRANSCRIPT_PREFIX.length + 32).equals(expectedClaim)).toBe(true)
    // Challenge
    expect(transcript.subarray(TRANSCRIPT_PREFIX.length + 32).equals(challenge)).toBe(true)
  })
})

describe('negative paths', () => {
  it('signature with wrong challenge fails verification', () => {
    const kp = generateKeypair()
    const sig = signChallenge(CLAIM_HASH_A, Buffer.from('original'), loadPrivateKey(kp.privateKeyPem))
    const ok = verifySignature({
      claimHash: CLAIM_HASH_A,
      challenge: Buffer.from('different'),
      publicKeyEncoded: kp.publicKeyEncoded,
      signature: sig,
    })
    expect(ok).toBe(false)
  })

  it('signature with wrong key fails verification', () => {
    const signer = generateKeypair()
    const otherKey = generateKeypair()
    const sig = signChallenge(CLAIM_HASH_A, Buffer.from('x'), loadPrivateKey(signer.privateKeyPem))
    const ok = verifySignature({
      claimHash: CLAIM_HASH_A,
      challenge: Buffer.from('x'),
      publicKeyEncoded: otherKey.publicKeyEncoded,
      signature: sig,
    })
    expect(ok).toBe(false)
  })

  it('rejects malformed public key', () => {
    const sig = Buffer.alloc(64, 0)
    const ok = verifySignature({
      claimHash: CLAIM_HASH_A,
      challenge: Buffer.from('x'),
      publicKeyEncoded: 'not-a-valid-encoding',
      signature: sig,
    })
    expect(ok).toBe(false)
  })

  it('rejects signature of wrong length', () => {
    const kp = generateKeypair()
    const ok = verifySignature({
      claimHash: CLAIM_HASH_A,
      challenge: Buffer.from('x'),
      publicKeyEncoded: kp.publicKeyEncoded,
      signature: Buffer.alloc(32, 0), // wrong length
    })
    expect(ok).toBe(false)
  })

  it('buildTranscript rejects bad claimHash format', () => {
    expect(() => buildTranscript('not-sha-prefix', Buffer.from(''))).toThrow(/Invalid claimHash format/)
    expect(() => buildTranscript('sha256:', Buffer.from(''))).toThrow(/Invalid claimHash format/)
    expect(() => buildTranscript('sha256:short', Buffer.from(''))).toThrow(/Invalid claimHash format/)
  })
})

describe('cross-protocol replay resistance', () => {
  it('a signature using the screenreg transcript cannot be reused as a bare-bytes Ed25519 signature', () => {
    // If an attacker signs `screenreg-proof-v1 || claimHash || challenge` for screenreg,
    // they cannot pass that signature off as having signed JUST the challenge in another
    // protocol that expects raw-bytes signatures.
    const kp = generateKeypair()
    const challenge = Buffer.from('attack-payload')
    const sig = signChallenge(CLAIM_HASH_A, challenge, loadPrivateKey(kp.privateKeyPem))

    // Verify via Node's cryptoVerify directly with JUST the challenge as input — should fail
    // because the actual signed bytes include the transcript prefix + claim hash.
    const decodedKey = decodePublicKey(kp.publicKeyEncoded)
    // Direct verify of challenge alone should fail
    const { verify } = require('node:crypto')
    const bareOk = verify(null, challenge, decodedKey, sig)
    expect(bareOk).toBe(false)
  })
})
