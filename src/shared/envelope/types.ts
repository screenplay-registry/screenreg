/**
 * TypeScript types for The Screenplay Registry envelope (v1) — cross-runtime canonical copy.
 *
 * Types only; the locked-string constants are the only runtime code. Fully browser-portable.
 *
 * See /spec/v1/02-envelope.md for the authoritative specification.
 */

// ---------------------------------------------------------------------------
// Locked commitment-bearing identifiers
// ---------------------------------------------------------------------------

export const ENVELOPE_VERSION = 'urn:screenplay-registration-envelope:v1' as const
export const CLAIM_VERSION = 'urn:screenplay-registration-claim:v1' as const
export const SCHEMA_ID = 'urn:screenplay-registration-claim-schema:v1' as const
export const HASH_ALGORITHM = 'sha-256' as const
export const MANIFEST_CANONICALIZATION = 'rfc8785' as const
export const NORMALIZATION_PROFILE = 'screenplay-registration-norm/v1-strict' as const
export const SCENE_TREE_PROFILE = 'screenplay-registration-merkle/v1' as const
export const PARAGRAPH_TREE_PROFILE = 'screenplay-registration-paragraph-merkle/v1' as const
export const REGISTRANT_SIGNATURE_DOMAIN = 'screenplay-registry-claim-v1' as const

// ---------------------------------------------------------------------------
// committedClaim
// ---------------------------------------------------------------------------

export interface EncryptedFieldsBlock {
  masterSalt: string
  kdf: 'pbkdf2-hmac-sha256'
  kdfIterations: number
  aadFormat: 'screenplay-registration-aad-v1'
  fields: EncryptedField[]
}

export interface EncryptedField {
  name: string
  iv: string
  ciphertext: string
  tag: string
  paddingBucket: number
}

export type TrainingMiningPreference = 'allowed' | 'notAllowed' | 'constrained'

export interface Preferences {
  trainingMining?: TrainingMiningPreference
}

export interface CommittedClaim {
  claimVersion: typeof CLAIM_VERSION
  schemaId: typeof SCHEMA_ID
  hashAlgorithm: typeof HASH_ALGORITHM
  manifestCanonicalization: typeof MANIFEST_CANONICALIZATION
  normalizationProfile: typeof NORMALIZATION_PROFILE
  contentHash: string
  claimExtensions: Record<string, unknown>
  sceneTreeProfile?: typeof SCENE_TREE_PROFILE
  sceneTreeRoot?: string
  sceneCount?: number
  paragraphTreeProfile?: typeof PARAGRAPH_TREE_PROFILE
  paragraphTreeRoot?: string
  paragraphCount?: number
  previousRegistration?: { claimHash: string }
  registrant?: RegistrantBlock
  timelockFields?: TimelockField[]
  encryptedFields?: EncryptedFieldsBlock
  preferences?: Preferences
}

export interface RegistrantBlock {
  publicKey: string
  signatureAlgorithm: 'ed25519'
  signatureDomain: typeof REGISTRANT_SIGNATURE_DOMAIN
  signedDigest: string
  signature: string
}

export interface TimelockField {
  name: string
  ciphertext: string
  unlockAtRound: number
  unlockAt: string
  drandChainHash: string
  drandPublicKey: string
  scheme: string
}

// ---------------------------------------------------------------------------
// evidenceBundle
// ---------------------------------------------------------------------------

export type ProofType = 'opentimestamps' | string

export interface OpenTimestampsProof {
  type: 'opentimestamps'
  claimHash: string
  proofRef: string
  submittedAt?: string
  upgradedAt?: string
}

export type EvidenceProof = OpenTimestampsProof | (Record<string, unknown> & { type: string; claimHash: string })

export interface EvidenceBundle {
  committedClaimHash: string
  proofs: EvidenceProof[]
  bundleExtensions: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

export interface Envelope {
  envelopeVersion: typeof ENVELOPE_VERSION
  committedClaim: CommittedClaim
  evidenceBundle: EvidenceBundle
}
