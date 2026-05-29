/**
 * Cross-runtime Ed25519 registrant-block signing.
 *
 * Web Crypto API only — `globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, ...)`
 * and `crypto.subtle.sign('Ed25519', ...)`. Available natively in Node 20+
 * and Chromium 113+, Firefox 119+, Safari 17+.
 *
 * Produces RegistrantBlock values byte-equivalent to the legacy Node-side
 * implementation in `src/identity/ed25519-signing.ts`. The cross-impl test
 * pins this: a claim signed by either implementation verifies with either
 * implementation.
 */

import { sha256, toHex, fromHex } from '../crypto.js'
import { canonicalize } from '../envelope/canonicalize.js'
import {
  REGISTRANT_SIGNATURE_DOMAIN,
  type CommittedClaim,
  type RegistrantBlock,
} from '../envelope/types.js'

/**
 * Opaque key handle alias. The Node `lib: ['ES2022']` config doesn't expose
 * the global `Ed25519Key` type, and the DOM `Ed25519Key` (browser) and Node's
 * `webcrypto.Ed25519Key` are nominally distinct even though they're
 * structurally identical at runtime. Aliasing to `unknown` lets the module
 * compile in both target configurations and pushes the runtime-type check
 * to the boundary where the caller hands the key to `crypto.subtle.sign`
 * (which validates the key kind itself).
 */
export type Ed25519PublicKey = unknown
export type Ed25519PrivateKey = unknown
/** Convenience alias used internally. */
type Ed25519Key = unknown
interface Ed25519KeyPair {
  publicKey: Ed25519Key
  privateKey: Ed25519Key
}

const PUBLIC_KEY_PREFIX = 'ed25519:'
const SIGNATURE_PREFIX = 'ed25519:'

/**
 * Generate a fresh Ed25519 keypair via Web Crypto. The PRIVATE key is
 * marked `extractable: true` so callers can serialize it for the writer
 * to download as a `.pem` file.
 */
export async function generateKeypair(): Promise<{
  publicKey: Ed25519Key
  privateKey: Ed25519Key
  publicKeyEncoded: string
}> {
  const keyPair = (await globalThis.crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  )) as Ed25519KeyPair
  const publicKeyEncoded = await encodePublicKey(keyPair.publicKey)
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyEncoded,
  }
}

/**
 * Encode a Web Crypto Ed25519 public key as the canonical
 * `ed25519:<base64>` string (raw 32-byte key, standard base64).
 */
export async function encodePublicKey(publicKey: Ed25519Key): Promise<string> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const raw = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('raw', publicKey as any),
  )
  if (raw.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 raw key, got ${raw.length}`)
  }
  return PUBLIC_KEY_PREFIX + uint8ArrayToBase64(raw)
}

/**
 * Decode an `ed25519:<base64>` string back into a Web Crypto verify-only key.
 */
export async function decodePublicKey(encoded: string): Promise<Ed25519Key> {
  if (!encoded.startsWith(PUBLIC_KEY_PREFIX)) {
    throw new Error(`Expected public key with "${PUBLIC_KEY_PREFIX}" prefix`)
  }
  const raw = base64ToUint8Array(encoded.slice(PUBLIC_KEY_PREFIX.length))
  if (raw.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 raw key, got ${raw.length}`)
  }
  // Copy to a plain ArrayBuffer so the DOM `BufferSource` type accepts it.
  const buf = new ArrayBuffer(raw.byteLength)
  new Uint8Array(buf).set(raw)
  return globalThis.crypto.subtle.importKey(
    'raw',
    buf,
    { name: 'Ed25519' },
    true,
    ['verify'],
  )
}

/**
 * Export a private key as PKCS#8 PEM text. The writer downloads this to
 * keep as their identity material; losing it means losing the ability to
 * later prove key control via challenge-response.
 */
export async function exportPrivateKeyPem(privateKey: Ed25519Key): Promise<string> {
  const der = new Uint8Array(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await globalThis.crypto.subtle.exportKey('pkcs8', privateKey as any),
  )
  const b64 = uint8ArrayToBase64(der)
  // Standard PKCS#8 PEM format: 64-char-wrapped base64 inside the BEGIN/END frame.
  const lines: string[] = []
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64))
  }
  return (
    '-----BEGIN PRIVATE KEY-----\n' +
    lines.join('\n') +
    '\n-----END PRIVATE KEY-----\n'
  )
}

/**
 * Compute the canonical sha256 of the claim body with the registrant
 * field stripped — the value an Ed25519 signature commits to.
 *
 * The legacy implementation in src/identity/ed25519-signing.ts produces
 * the same bytes for the same input; cross-impl tests assert that.
 */
export async function computeClaimBodyDigest(claim: CommittedClaim): Promise<string> {
  // Build a copy of the claim WITHOUT the registrant field. The signature
  // is computed over THIS body; the registrant block (which contains the
  // signature) is then added back.
  const { registrant: _, ...claimBody } = claim
  void _
  const canonical = canonicalize(claimBody)
  const digest = await sha256(canonical)
  return `sha256:${toHex(digest)}`
}

/**
 * Sign a claim at registration time. Returns a RegistrantBlock ready to be
 * inserted into committedClaim.registrant before OTS anchoring.
 *
 * The claim passed in MUST NOT already have a `registrant` field.
 */
export async function signRegistration(
  claim: CommittedClaim,
  privateKey: Ed25519Key,
  publicKeyEncoded: string,
): Promise<RegistrantBlock> {
  if (claim.registrant !== undefined) {
    throw new Error(
      'signRegistration: claim already has a `registrant` block. Strip it before re-signing.',
    )
  }
  const signedDigest = await computeClaimBodyDigest(claim)
  const message = buildRegistrationMessage(signedDigest)
  // Copy message into a plain ArrayBuffer — the DOM lib's `BufferSource`
  // rejects Uint8Array<SharedArrayBuffer>, and the generic Uint8Array type
  // permits that subtype. This is the same normalization sha256() applies.
  const messageBuffer = new ArrayBuffer(message.byteLength)
  new Uint8Array(messageBuffer).set(message)
  const sigBuffer = await globalThis.crypto.subtle.sign(
    'Ed25519',
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    privateKey as any,
    messageBuffer,
  )
  const sigBytes = new Uint8Array(sigBuffer)
  return {
    publicKey: publicKeyEncoded,
    signatureAlgorithm: 'ed25519',
    signatureDomain: REGISTRANT_SIGNATURE_DOMAIN,
    signedDigest,
    signature: SIGNATURE_PREFIX + uint8ArrayToBase64(sigBytes),
  }
}

/**
 * Construct the byte sequence the registrant signature commits to:
 *   message := REGISTRANT_SIGNATURE_DOMAIN (utf8) || sha256(claim body)
 */
function buildRegistrationMessage(claimBodyDigest: string): Uint8Array {
  if (
    !claimBodyDigest.startsWith('sha256:') ||
    claimBodyDigest.length !== 'sha256:'.length + 64
  ) {
    throw new Error(`Invalid claimBodyDigest format: ${claimBodyDigest}`)
  }
  const digestBytes = fromHex(claimBodyDigest.slice('sha256:'.length))
  const domainBytes = new TextEncoder().encode(REGISTRANT_SIGNATURE_DOMAIN)
  const out = new Uint8Array(domainBytes.length + digestBytes.length)
  out.set(domainBytes, 0)
  out.set(digestBytes, domainBytes.length)
  return out
}

/**
 * Verify a registrant block against the claim it was signed over.
 * Returns true if the signature is valid; false otherwise.
 *
 * Re-derives the body digest from the supplied claim (with the registrant
 * stripped) and compares to the recorded `signedDigest` to detect tamper
 * BEFORE running the more expensive signature verification.
 */
export async function verifyRegistrantBlock(
  claim: CommittedClaim,
): Promise<boolean> {
  const registrant = claim.registrant
  if (registrant === undefined) return false
  if (registrant.signatureAlgorithm !== 'ed25519') return false
  if (registrant.signatureDomain !== REGISTRANT_SIGNATURE_DOMAIN) return false
  const recomputedDigest = await computeClaimBodyDigest(claim)
  if (recomputedDigest !== registrant.signedDigest) return false
  let publicKey: Ed25519Key
  try {
    publicKey = await decodePublicKey(registrant.publicKey)
  } catch {
    return false
  }
  if (!registrant.signature.startsWith(SIGNATURE_PREFIX)) return false
  const sigBytes = base64ToUint8Array(
    registrant.signature.slice(SIGNATURE_PREFIX.length),
  )
  const message = buildRegistrationMessage(registrant.signedDigest)
  // ArrayBuffer copy mirrors signRegistration (see comment there).
  const sigBuffer = new ArrayBuffer(sigBytes.byteLength)
  new Uint8Array(sigBuffer).set(sigBytes)
  const messageBuffer = new ArrayBuffer(message.byteLength)
  new Uint8Array(messageBuffer).set(message)
  try {
    return await globalThis.crypto.subtle.verify(
      'Ed25519',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      publicKey as any,
      sigBuffer,
      messageBuffer,
    )
  } catch {
    return false
  }
}

// ===========================================================================
// Base64 helpers — `globalThis.btoa`/`atob` work in Node 20+ and the browser
// ===========================================================================

function uint8ArrayToBase64(bytes: Uint8Array): string {
  // Build a binary string from the bytes, then btoa it. The string-builder
  // approach handles arbitrary-length inputs (atob/btoa cap individual
  // String.fromCharCode calls at ~64K args without spread).
  let bin = ''
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]!)
  }
  return globalThis.btoa(bin)
}

function base64ToUint8Array(b64: string): Uint8Array {
  const bin = globalThis.atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
