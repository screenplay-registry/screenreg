/**
 * Canonical "sha256:<lowercase-hex>" hash string helpers.
 *
 * The wire format for every SHA-256 hash in this protocol is the literal
 * string `"sha256:" + <64 lowercase hex chars>`. Centralizing the parser +
 * formatter prevents the three scattered places (comparison-bundle.ts,
 * scene-tree.ts proofs, ed25519-signing.ts) from drifting on the regex.
 */

import { Buffer } from 'node:buffer'

export const SHA256_PREFIX = 'sha256:'
export const SHA256_HEX_LENGTH = 64
export const SHA256_BYTE_LENGTH = 32

/** Strict regex matching `"sha256:" + 64 lowercase hex chars`. */
export const SHA256_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/

/** Type guard: does the string match the canonical hash format? */
export function isSha256HashString(value: unknown): value is string {
  return typeof value === 'string' && SHA256_HASH_PATTERN.test(value)
}

/**
 * Parse a `"sha256:<hex>"` string into a 32-byte Buffer.
 * Throws if the input doesn't match the canonical format.
 */
export function parseSha256Hash(value: string): Buffer {
  if (!SHA256_HASH_PATTERN.test(value)) {
    throw new Error(`Not a valid sha256:<64-lowercase-hex>: ${value}`)
  }
  return Buffer.from(value.slice(SHA256_PREFIX.length), 'hex')
}

/** Format a 32-byte Buffer as `"sha256:<hex>"`. Throws on wrong length. */
export function formatSha256Hash(bytes: Buffer): string {
  if (bytes.length !== SHA256_BYTE_LENGTH) {
    throw new Error(`formatSha256Hash: expected ${SHA256_BYTE_LENGTH} bytes, got ${bytes.length}`)
  }
  return `${SHA256_PREFIX}${bytes.toString('hex')}`
}
