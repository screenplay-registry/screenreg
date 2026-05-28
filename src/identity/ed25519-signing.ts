/**
 * Identity binding via Ed25519 signing (Section 06).
 *
 * Workflow:
 *   1. At registration, the writer (optionally) generates a fresh Ed25519
 *      keypair. The PUBLIC key goes in committedClaim.registrantPublicKey.
 *      The PRIVATE key stays with the writer (file on their machine, wallet,
 *      hardware key, etc.).
 *   2. Later, anyone can issue a challenge: "prove you registered claim X"
 *      by providing a random challenge nonce.
 *   3. The writer signs a DOMAIN-SEPARATED TRANSCRIPT (NOT the raw challenge)
 *      using their private key. Transcript:
 *
 *        "screenreg-proof-v1" || claimHash (32 bytes) || challengeBytes
 *
 *   4. The verifier reconstructs the transcript, fetches the public key
 *      from the manifest's committedClaim, and verifies the Ed25519 signature.
 *
 * Domain separation prevents cross-protocol signature reuse (an Ed25519
 * signature from a screenreg key cannot be replayed as a signature in any
 * other protocol that uses the same key, because the transcript prefix is
 * specific to screenreg-proof-v1).
 *
 * Node API note: per Node.js docs, Ed25519 uses `crypto.sign(null, data, key)`
 * (not `'ed25519'` as the algorithm string). The KEY type carries the
 * algorithm identity.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  createHash,
  type KeyObject,
} from 'node:crypto'
import type { CommittedClaim, RegistrantBlock } from '../envelope/types.js'
import { REGISTRANT_SIGNATURE_DOMAIN } from '../envelope/types.js'
import { canonicalize } from '../envelope/canonicalize.js'

export const TRANSCRIPT_PREFIX = Buffer.from('screenreg-proof-v1', 'utf8')
export const PUBLIC_KEY_PREFIX = 'ed25519:' as const
export const SIGNATURE_PREFIX = 'ed25519:' as const

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

export interface KeyPairPem {
  privateKeyPem: string
  publicKeyPem: string
  publicKeyEncoded: string // "ed25519:<base64-of-raw-32-byte-pubkey>"
}

/**
 * Generate a fresh Ed25519 keypair. Returns PEM forms (for storage) and the
 * canonical `ed25519:<base64>` encoding suitable for committedClaim.registrantPublicKey.
 *
 * Per OSR design: prefer a per-registration fresh keypair. Reusing the same
 * key across registrations cryptographically LINKS those registrations (which
 * may be intended OR may leak more than the registrant realizes).
 */
export function generateKeypair(): KeyPairPem {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    publicKeyEncoded: encodePublicKey(publicKey),
  }
}

/**
 * Extract the raw 32-byte Ed25519 public key from a Node KeyObject and encode
 * as `ed25519:<base64>`.
 *
 * We use Node's JWK export (`KeyObject.export({ format: 'jwk' })`) which
 * returns the OKP shape `{ kty: 'OKP', crv: 'Ed25519', x: <base64url(rawBytes)> }`.
 * The `x` field IS the raw public key — no ASN.1 SPKI surgery required.
 * This matches W3C Web Crypto / JOSE conventions, so the encoding logic stays
 * portable to browser crypto.subtle without an ASN.1 polyfill.
 */
export function encodePublicKey(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: 'jwk' }) as { kty?: string; crv?: string; x?: string }
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error(`Expected Ed25519 OKP JWK; got kty=${jwk.kty} crv=${jwk.crv}`)
  }
  // JWK uses base64url; the wire format uses standard base64. Round-trip via
  // raw bytes is the only encoding-agnostic conversion.
  const raw = Buffer.from(jwk.x, 'base64url')
  if (raw.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 raw key from JWK.x, got ${raw.length} bytes`)
  }
  return PUBLIC_KEY_PREFIX + raw.toString('base64')
}

/**
 * Parse an `ed25519:<base64>` string back into a Node KeyObject for verification.
 *
 * Goes via JWK import — the self-describing path that doesn't require
 * constructing the X.509 SPKI DER prefix by hand.
 */
export function decodePublicKey(encoded: string): KeyObject {
  if (!encoded.startsWith(PUBLIC_KEY_PREFIX)) {
    throw new Error(`Expected public key with "${PUBLIC_KEY_PREFIX}" prefix, got "${encoded.slice(0, 12)}…"`)
  }
  const raw = Buffer.from(encoded.slice(PUBLIC_KEY_PREFIX.length), 'base64')
  if (raw.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 raw key, got ${raw.length} bytes`)
  }
  return createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') },
    format: 'jwk',
  })
}

/**
 * Parse a PEM-encoded private key for signing.
 */
export function loadPrivateKey(pem: string): KeyObject {
  return createPrivateKey({ key: pem, format: 'pem' })
}

// ---------------------------------------------------------------------------
// Transcript construction
// ---------------------------------------------------------------------------

/**
 * Build the domain-separated transcript that gets signed.
 *
 *   transcript := "screenreg-proof-v1" || claimHash (32 raw bytes) || challenge
 *
 * @param claimHash the "sha256:<hex>" string from the manifest
 * @param challenge arbitrary bytes from the challenger (typically random)
 */
export function buildTranscript(claimHash: string, challenge: Buffer): Buffer {
  if (!claimHash.startsWith('sha256:') || claimHash.length !== 'sha256:'.length + 64) {
    throw new Error(`Invalid claimHash format: expected "sha256:<64-hex>", got "${claimHash}"`)
  }
  const claimHashBytes = Buffer.from(claimHash.slice('sha256:'.length), 'hex')
  return Buffer.concat([TRANSCRIPT_PREFIX, claimHashBytes, challenge])
}

// ---------------------------------------------------------------------------
// Sign + verify
// ---------------------------------------------------------------------------

/**
 * Sign a challenge for the given claim. Returns the 64-byte Ed25519 signature.
 */
export function signChallenge(
  claimHash: string,
  challenge: Buffer,
  privateKey: KeyObject,
): Buffer {
  const transcript = buildTranscript(claimHash, challenge)
  // Per Node docs: Ed25519 uses null as algorithm; key type carries the curve.
  return cryptoSign(null, transcript, privateKey)
}

/**
 * Verify a signature against (claimHash, challenge, publicKey).
 *
 * Returns true iff the signature is a valid Ed25519 signature over the
 * canonical transcript by the given public key.
 */
export function verifySignature(input: {
  claimHash: string
  challenge: Buffer
  publicKeyEncoded: string
  signature: Buffer
}): boolean {
  let publicKey: KeyObject
  try {
    publicKey = decodePublicKey(input.publicKeyEncoded)
  } catch {
    return false
  }
  if (input.signature.length !== 64) {
    return false
  }
  const transcript = buildTranscript(input.claimHash, input.challenge)
  // Per Node docs: Ed25519 uses null as algorithm.
  return cryptoVerify(null, transcript, publicKey, input.signature)
}

// ---------------------------------------------------------------------------
// REGISTRATION-TIME SIGNING (Section 06)
//
// Stronger than challenge-response alone: proves the keypair was actually used
// to register THIS claim, not just that the holder controls the key today.
//
// Two-phase flow:
//   1. Build claim body WITHOUT the `registrant` field
//   2. Compute claimBodyDigest = SHA-256(RFC8785(claim_body))
//   3. Sign domain || claimBodyDigest with the private key
//   4. Add the resulting RegistrantBlock to the claim
//   5. The full claim (now with `registrant`) is what gets RFC8785-hashed for OTS
//
// Verification flow:
//   1. Extract registrant; reconstruct claim_body by deleting it
//   2. Recompute claimBodyDigest
//   3. Confirm registrant.signedDigest matches
//   4. Verify signature(domain || claimBodyDigest_raw_bytes) against publicKey
// ---------------------------------------------------------------------------

/**
 * Compute the digest that gets signed at registration time.
 *
 *   claimBodyDigest := "sha256:" + hex(SHA-256(RFC8785(claim_body)))
 *
 * where claim_body = committedClaim with the `registrant` field removed.
 */
export function computeClaimBodyDigest(claim: CommittedClaim): string {
  // Build a copy of the claim WITHOUT the registrant field. The signature is
  // computed over THIS body; the registrant block (which CONTAINS the signature)
  // is then added back. Stripping registrant before hashing breaks the chicken-
  // and-egg: we can't sign a value that includes the signature.
  const { registrant, ...claimBody } = claim
  void registrant
  const canonical = canonicalize(claimBody)
  const digest = createHash('sha256').update(canonical).digest('hex')
  return `sha256:${digest}`
}

/**
 * Build the message bytes that get signed at registration time:
 *
 *   message := domain || claimBodyDigest_raw_bytes
 *
 * Domain separation prevents replay across protocols + ensures the signature
 * cannot be confused with a challenge-response signature (different prefixes).
 */
function buildRegistrationMessage(claimBodyDigest: string): Buffer {
  if (!claimBodyDigest.startsWith('sha256:') || claimBodyDigest.length !== 7 + 64) {
    throw new Error(`Invalid claimBodyDigest format`)
  }
  const digestBytes = Buffer.from(claimBodyDigest.slice('sha256:'.length), 'hex')
  return Buffer.concat([
    Buffer.from(REGISTRANT_SIGNATURE_DOMAIN, 'utf8'),
    digestBytes,
  ])
}

/**
 * Sign a claim at registration time. Returns a RegistrantBlock that gets
 * inserted into committedClaim.registrant before OTS anchoring.
 *
 * The claim passed in MUST NOT already have a `registrant` field (the body
 * digest is computed over the body without it).
 */
export function signRegistration(
  claim: CommittedClaim,
  privateKey: KeyObject,
  publicKeyEncoded: string,
): RegistrantBlock {
  if (claim.registrant !== undefined) {
    throw new Error(
      'signRegistration: claim already has a `registrant` block. Strip it before re-signing.',
    )
  }
  const signedDigest = computeClaimBodyDigest(claim)
  const message = buildRegistrationMessage(signedDigest)
  const sigBytes = cryptoSign(null, message, privateKey)
  return {
    publicKey: publicKeyEncoded,
    signatureAlgorithm: 'ed25519',
    signatureDomain: REGISTRANT_SIGNATURE_DOMAIN,
    signedDigest,
    signature: SIGNATURE_PREFIX + sigBytes.toString('base64'),
  }
}

/**
 * Verify a registration-time signature on a claim.
 *
 * Returns true iff:
 *   1. The claim has a registrant block
 *   2. The block's signedDigest matches the independently-recomputed body digest
 *   3. The signature is a valid Ed25519 signature over the canonical message
 */
export function verifyRegistrationSignature(claim: CommittedClaim): {
  ok: boolean
  reason?: string
} {
  if (!claim.registrant) {
    return { ok: false, reason: 'no registrant block on claim' }
  }
  if (claim.registrant.signatureAlgorithm !== 'ed25519') {
    return { ok: false, reason: `unsupported signatureAlgorithm: ${claim.registrant.signatureAlgorithm}` }
  }
  if (claim.registrant.signatureDomain !== REGISTRANT_SIGNATURE_DOMAIN) {
    return { ok: false, reason: `signature domain mismatch: ${claim.registrant.signatureDomain}` }
  }

  // Recompute body digest independently
  const recomputedDigest = computeClaimBodyDigest(claim)
  if (recomputedDigest !== claim.registrant.signedDigest) {
    return {
      ok: false,
      reason: `signedDigest mismatch: claim says ${claim.registrant.signedDigest}, recomputed ${recomputedDigest}`,
    }
  }

  // Verify the signature
  let publicKey: KeyObject
  try {
    publicKey = decodePublicKey(claim.registrant.publicKey)
  } catch (e: any) {
    return { ok: false, reason: `bad public key: ${e?.message ?? e}` }
  }
  if (!claim.registrant.signature.startsWith(SIGNATURE_PREFIX)) {
    return { ok: false, reason: `signature missing "${SIGNATURE_PREFIX}" prefix` }
  }
  const sigBytes = Buffer.from(claim.registrant.signature.slice(SIGNATURE_PREFIX.length), 'base64')
  if (sigBytes.length !== 64) {
    return { ok: false, reason: `signature has wrong length ${sigBytes.length} (expected 64)` }
  }

  const message = buildRegistrationMessage(recomputedDigest)
  const ok = cryptoVerify(null, message, publicKey, sigBytes)
  return ok ? { ok: true } : { ok: false, reason: 'Ed25519 verification failed' }
}
