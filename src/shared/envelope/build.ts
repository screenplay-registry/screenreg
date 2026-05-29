/**
 * Cross-runtime builder helpers for constructing v1 envelopes.
 *
 * Browser-portable port of src/envelope/build.ts. The pure object-construction helpers
 * (buildCommittedClaim, buildEvidenceBundle) stay sync — they don't touch crypto. The
 * envelope-builder (buildEnvelope) becomes ASYNC because it composes claim-hash, which
 * is async in the shared module (Web Crypto digest is async).
 *
 * checkEnvelopeConsistency stays sync — it operates on already-computed hashes.
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
  contentHash: string
  sceneTree?: { root: string; count: number }
  paragraphTree?: { root: string; count: number }
  previousRegistration?: { claimHash: string }
  registrant?: RegistrantBlock
  timelockFields?: TimelockField[]
  encryptedFields?: EncryptedFieldsBlock
  preferences?: Preferences
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
 * ASYNC because Web Crypto's digest is async.
 */
export async function buildEnvelope(
  claim: CommittedClaim,
  options: { proofs?: EvidenceProof[]; bundleExtensions?: Record<string, unknown> } = {},
): Promise<Envelope> {
  const claimHash = await computeClaimHash(claim)
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
