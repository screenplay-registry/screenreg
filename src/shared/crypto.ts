/**
 * Cross-runtime cryptographic primitives — Web Crypto API only.
 *
 * `globalThis.crypto.subtle` is available natively in Node 20+ and in every
 * evergreen browser. Writing crypto-bearing code paths against Web Crypto gives
 * a single source of truth and removes the parallel-implementation drift surface.
 *
 * All APIs here are async per Web Crypto's design. No external dependencies. No
 * polyfills. No fallbacks for non-evergreen runtimes.
 */

/**
 * Compute SHA-256 of `bytes`. Returns a 32-byte Uint8Array.
 *
 * Per FIPS 180-4. Identical output in Node 20+ and in Chromium / Firefox / WebKit.
 */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  // Copy into a plain ArrayBuffer before handing to crypto.subtle.digest. Node's
  // type definitions accept Uint8Array<ArrayBufferLike> directly; the DOM lib
  // requires Uint8Array<ArrayBuffer> specifically (it rejects SharedArrayBuffer-
  // backed views). The copy normalizes to the narrower type and keeps the input
  // immune to caller-side mutation while the async digest is in flight.
  const ab = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(ab).set(bytes)
  const digest = await globalThis.crypto.subtle.digest('SHA-256', ab)
  return new Uint8Array(digest)
}

/**
 * Convert a byte array to a lowercase hex string.
 *
 * Composed with `sha256()` to produce the canonical "sha256:<hex>" form used
 * throughout the protocol.
 */
export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, '0')
  }
  return out
}

/**
 * Convert a lowercase hex string to bytes. Reverse of toHex.
 *
 * Throws on odd-length input or non-hex characters — strict by design. Useful for
 * decoding the published test vectors (which store digests as hex strings) into
 * the byte arrays the verifier compares against.
 */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`fromHex: odd-length input (${hex.length} chars)`)
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) {
      throw new Error(`fromHex: non-hex character at offset ${i * 2}`)
    }
    out[i] = byte
  }
  return out
}
