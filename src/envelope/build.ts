/**
 * Builder helpers for constructing v1 envelopes.
 *
 * These are convenience functions; callers MAY construct envelopes by hand.
 * Using these helpers guarantees that locked commitment-bearing identifiers
 * (claimVersion, schemaId, profile IDs, etc.) are set correctly.
 */

import {
  CLAIM_VERSION,
  SCHEMA_ID,
  HASH_ALGORITHM,
  MANIFEST_CANONICALIZATION,
  NORMALIZATION_PROFILE,
  SCENE_TREE_PROFILE,
  PARAGRAPH_TREE_PROFILE,
  ENVELOPE_VERSION,
  type CommittedClaim,
  type EvidenceBundle,
  type EvidenceProof,
  type Envelope,
  type EncryptedFieldsBlock,
  type Preferences,
  type TimelockField,
  type RegistrantBlock,
} from './types.js'
import { computeClaimHash } from './claim-hash.js'

export interface BuildClaimInput {
  /** Required: the "sha256:<hex>" content hash from Section 01. */
  contentHash: string

  /**
   * Optional Merkle scene tree. When provided, sceneTreeProfile, sceneTreeRoot,
   * and sceneCount are set together per spec §02 + §03.
   *
   * Per-scene LEAVES are kept PRIVATE with the writer (not in committedClaim).
   * Per spec §06, leaves are revealed only via opt-in comparison disclosure bundles
   * to avoid the membership-oracle attack of publishing the full leaf array.
   */
  sceneTree?: {
    root: string
    count: number
  }

  /**
   * Optional Merkle paragraph tree (Section 05 §2). Same shape + privacy
   * discipline as the scene tree. Robust to global rename — a "Lakehouse" →
   * "Cabin" change only invalidates paragraphs containing the renamed term;
   * most paragraph leaves stay the same.
   *
   * When dispute / comparison happens, the writer generates a comparison
   * disclosure bundle revealing chosen leaves with Merkle proofs.
   */
  paragraphTree?: {
    root: string
    count: number
  }

  /** Optional pointer to a parent registration (revision lineage). */
  previousRegistration?: { claimHash: string }

  /**
   * Optional registrant identity block (Section 06).
   * If provided, must already contain a valid signature over the claim body
   * (use `buildSignedClaim()` rather than `buildCommittedClaim()` directly
   * for the two-phase sign-then-commit flow).
   */
  registrant?: RegistrantBlock

  /** Optional time-locked encrypted fields (Drand tlock; Section 07). */
  timelockFields?: TimelockField[]

  encryptedFields?: EncryptedFieldsBlock
  preferences?: Preferences

  /**
   * Future-proofing extension point. Always present in the output (empty object
   * if omitted here), per spec §3.1.
   */
  claimExtensions?: Record<string, unknown>
}

export function buildCommittedClaim(input: BuildClaimInput): CommittedClaim {
  const claim: CommittedClaim = {
    claimVersion: CLAIM_VERSION,
    schemaId: SCHEMA_ID,
    hashAlgorithm: HASH_ALGORITHM,
    manifestCanonicalization: MANIFEST_CANONICALIZATION,
    normalizationProfile: NORMALIZATION_PROFILE,
    contentHash: input.contentHash,
    claimExtensions: input.claimExtensions ?? {},
  }
  if (input.sceneTree) {
    claim.sceneTreeProfile = SCENE_TREE_PROFILE
    claim.sceneTreeRoot = input.sceneTree.root
    claim.sceneCount = input.sceneTree.count
  }
  if (input.paragraphTree) {
    claim.paragraphTreeProfile = PARAGRAPH_TREE_PROFILE
    claim.paragraphTreeRoot = input.paragraphTree.root
    claim.paragraphCount = input.paragraphTree.count
  }
  if (input.previousRegistration !== undefined) {
    claim.previousRegistration = input.previousRegistration
  }
  if (input.registrant !== undefined) {
    claim.registrant = input.registrant
  }
  if (input.timelockFields !== undefined) {
    claim.timelockFields = input.timelockFields
  }
  if (input.encryptedFields !== undefined) {
    claim.encryptedFields = input.encryptedFields
  }
  if (input.preferences !== undefined) {
    claim.preferences = input.preferences
  }
  return claim
}

export interface BuildEvidenceBundleInput {
  claimHash: string
  proofs?: EvidenceProof[]
  bundleExtensions?: Record<string, unknown>
}

export function buildEvidenceBundle(input: BuildEvidenceBundleInput): EvidenceBundle {
  return {
    committedClaimHash: input.claimHash,
    proofs: input.proofs ?? [],
    bundleExtensions: input.bundleExtensions ?? {},
  }
}

/**
 * Build a complete envelope from a claim + optional proofs.
 * The committedClaimHash inside the evidenceBundle is computed automatically.
 */
export function buildEnvelope(
  claim: CommittedClaim,
  options: { proofs?: EvidenceProof[]; bundleExtensions?: Record<string, unknown> } = {},
): Envelope {
  const claimHash = computeClaimHash(claim)
  return {
    envelopeVersion: ENVELOPE_VERSION,
    committedClaim: claim,
    evidenceBundle: buildEvidenceBundle({
      claimHash,
      proofs: options.proofs ?? [],
      bundleExtensions: options.bundleExtensions ?? {},
    }),
  }
}

// ---------------------------------------------------------------------------
// Verifier consistency checks (per spec §4.2)
// ---------------------------------------------------------------------------

export type VerifierConsistencyResult =
  | { ok: true }
  | {
      ok: false
      reason:
        | 'envelope-version-mismatch'
        | 'claim-hash-mismatch'
        | 'proof-claim-hash-mismatch'
      detail: string
    }

/**
 * Apply the verifier consistency rules from spec §4.2.
 *
 * Does NOT recompute the claim hash (caller passes it in to avoid double-hashing).
 * Does NOT verify cryptographic proofs (each proof type has its own verifier).
 */
export function checkEnvelopeConsistency(
  envelope: Envelope,
  independentlyComputedClaimHash: string,
): VerifierConsistencyResult {
  if (envelope.envelopeVersion !== ENVELOPE_VERSION) {
    return {
      ok: false,
      reason: 'envelope-version-mismatch',
      detail: `Expected envelopeVersion=${ENVELOPE_VERSION}, got ${envelope.envelopeVersion}`,
    }
  }
  if (envelope.evidenceBundle.committedClaimHash !== independentlyComputedClaimHash) {
    return {
      ok: false,
      reason: 'claim-hash-mismatch',
      detail: `evidenceBundle.committedClaimHash (${envelope.evidenceBundle.committedClaimHash}) does not match independently recomputed claimHash (${independentlyComputedClaimHash})`,
    }
  }
  for (let i = 0; i < envelope.evidenceBundle.proofs.length; i++) {
    const proof = envelope.evidenceBundle.proofs[i]!
    if (proof.claimHash !== independentlyComputedClaimHash) {
      return {
        ok: false,
        reason: 'proof-claim-hash-mismatch',
        detail: `proof[${i}] (type=${proof.type}) claimHash (${proof.claimHash}) does not match independently recomputed claimHash (${independentlyComputedClaimHash})`,
      }
    }
  }
  return { ok: true }
}
