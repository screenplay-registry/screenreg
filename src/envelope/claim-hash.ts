/**
 * Compute the `claimHash` of a CommittedClaim per Section 02 §5:
 *
 *   claimHash := "sha256:" || lowercase_hex(SHA-256(RFC8785_canonicalize(committedClaim)))
 *
 * This hash is what gets OTS-anchored to Bitcoin. It is the ONLY commitment-bearing
 * value in the entire protocol.
 */

import { createHash } from 'node:crypto'
import { canonicalize } from './canonicalize.js'
import type { CommittedClaim } from './types.js'

/**
 * Compute the canonical claim hash.
 *
 * Returns the canonical "sha256:<lowercase-hex>" string used in:
 *  - `evidenceBundle.committedClaimHash`
 *  - each `proof.claimHash` in `evidenceBundle.proofs`
 *  - the 32-byte digest passed to OTS for Bitcoin anchoring
 */
export function computeClaimHash(claim: CommittedClaim): string {
  const canonical = canonicalize(claim)
  const digest = createHash('sha256').update(canonical).digest('hex')
  return `sha256:${digest}`
}

/**
 * Get the raw 32-byte digest (Buffer) for passing to OTS.
 * The OTS layer needs raw bytes, not the prefixed hex string.
 */
export function computeClaimHashBytes(claim: CommittedClaim): Buffer {
  const canonical = canonicalize(claim)
  return createHash('sha256').update(canonical).digest()
}

/**
 * Get the canonical bytes that would be hashed.
 * Exposed for verifier debugging — to show users exactly what is being hashed.
 */
export function canonicalClaimBytes(claim: CommittedClaim): Buffer {
  return canonicalize(claim)
}
