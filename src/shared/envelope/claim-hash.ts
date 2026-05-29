/**
 * Cross-runtime claim-hash computation per Section 02 §5:
 *
 *   claimHash := "sha256:" || lowercase_hex(SHA-256(RFC8785_canonicalize(committedClaim)))
 *
 * Browser-portable port of src/envelope/claim-hash.ts. Uses Web Crypto SHA-256 (async)
 * and the shared canonicalize.
 *
 * This hash is what gets OTS-anchored to Bitcoin. It is the ONLY commitment-bearing
 * value in the entire protocol. Cross-impl byte-parity is enforced by CI.
 */

import { sha256, toHex } from '../crypto.js'
import { canonicalize } from './canonicalize.js'

/**
 * Compute the canonical claim hash. Returns the canonical "sha256:<lowercase-hex>" string
 * used in `evidenceBundle.committedClaimHash`, `proof.claimHash`, and the 32-byte digest
 * passed to OTS for Bitcoin anchoring.
 *
 * Generic over the claim shape — the hashing logic is shape-agnostic since
 * `canonicalize` accepts any JSON-serializable value.
 */
export async function computeClaimHash(claim: unknown): Promise<string> {
  const canonical = canonicalize(claim)
  const digest = await sha256(canonical)
  return `sha256:${toHex(digest)}`
}

/**
 * Get the raw 32-byte digest for passing to OTS.
 * The OTS layer needs raw bytes, not the prefixed hex string.
 */
export async function computeClaimHashBytes(claim: unknown): Promise<Uint8Array> {
  const canonical = canonicalize(claim)
  return sha256(canonical)
}

/**
 * Get the canonical bytes that would be hashed.
 * Exposed for verifier debugging — to show users exactly what is being hashed.
 */
export function canonicalClaimBytes(claim: unknown): Uint8Array {
  return canonicalize(claim)
}
