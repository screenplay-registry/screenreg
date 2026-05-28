/**
 * TypeScript types for The Screenplay Registry envelope (v1).
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
// committedClaim — the immutable, hashed, OTS-anchored object
// ---------------------------------------------------------------------------

/**
 * Encrypted-field block per Section 04. Optional in the claim — its presence is
 * commitment-bearing (absent and present-with-empty produce different hashes).
 */
export interface EncryptedFieldsBlock {
  masterSalt: string // base64 of 32 random bytes
  kdf: 'pbkdf2-hmac-sha256'
  kdfIterations: number
  aadFormat: 'screenplay-registration-aad-v1'
  fields: EncryptedField[]
}

export interface EncryptedField {
  name: string
  iv: string // base64 of 12 random bytes (96-bit IV)
  ciphertext: string // base64
  tag: string // base64 of 16-byte GCM tag
  paddingBucket: number // 16 | 64 | 256 | 1024 | larger if explicitly opted-in
}

/**
 * AI-training-mining preference value, mirroring the CAWG training-data-mining
 * assertion (`allowed` / `notAllowed` / `constrained`) — see
 * https://cawg.io/training-and-data-mining/1.0. Originally part of the C2PA
 * 1.x spec; C2PA 2.x migrated the assertion to the Creator Assertions
 * Working Group, which now maintains it. Locked at v1.
 *
 * - `allowed` — registrant grants permission for AI training + data mining.
 * - `notAllowed` — registrant denies permission. Honoring this is the C2PA-
 *   coordinated commitment that downstream platforms (Adobe Firefly, Spawning)
 *   pledge to respect.
 * - `constrained` — registrant grants permission only under specified terms;
 *   v1 does NOT carry the terms inline (out-of-band signaling).
 *
 * Adding a new value is a v2 protocol change (new schema id), not a v1 patch —
 * verifiers MUST reject unknown values.
 */
export type TrainingMiningPreference = 'allowed' | 'notAllowed' | 'constrained'

/**
 * User-set preferences. v1 LOCKED shape: only `trainingMining` is defined.
 * The JSON schema sets `additionalProperties: false` — manifests with
 * unknown preference fields MUST be rejected by v1 verifiers. Forward-
 * compatible additions land via a new `schemaId` in v2+, NOT by silent
 * preference-field growth at the v1 schema.
 */
export interface Preferences {
  trainingMining?: TrainingMiningPreference
}

/**
 * The committed claim — what gets canonicalized + hashed + OTS-anchored to Bitcoin.
 *
 * RULES:
 *  - All fields shown as required MUST be present.
 *  - Optional fields are either absent OR present with a valid value.
 *  - Absence vs presence-with-empty changes the commitment hash.
 *  - Unknown fields are part of the commitment (hashed even if not understood).
 */
export interface CommittedClaim {
  // ---- Required, fixed values ----
  claimVersion: typeof CLAIM_VERSION
  schemaId: typeof SCHEMA_ID
  hashAlgorithm: typeof HASH_ALGORITHM
  manifestCanonicalization: typeof MANIFEST_CANONICALIZATION
  normalizationProfile: typeof NORMALIZATION_PROFILE

  // ---- Required, variable values ----
  /** `sha256:<lowercase-hex>` per Section 01 §6 */
  contentHash: string
  /** Always present. Empty object `{}` if no extensions. Commitment-bearing. */
  claimExtensions: Record<string, unknown>

  // ---- Optional ----
  /**
   * If present, requires sceneTreeRoot + sceneCount also present.
   * Per-scene leaves are NOT in the committed claim — they live in the opt-in
   * comparison disclosure bundle (Section 06) to avoid the membership-oracle attack.
   */
  sceneTreeProfile?: typeof SCENE_TREE_PROFILE
  /** `sha256:<lowercase-hex>` root of the Merkle tree (Section 03). */
  sceneTreeRoot?: string
  /** Number of scenes detected. Prevents truncation attacks. */
  sceneCount?: number
  /**
   * Optional ordered paragraph Merkle tree root (Section 05 §2).
   * If present, requires paragraphCount also present.
   * Detects paragraphs by blank-line splitting in normalized bytes.
   * Same RFC 6962-style domain-separated construction as the scene tree,
   * but with a DIFFERENT profile ID (paragraphTreeProfile = "screenplay-registration-paragraph-merkle/v1").
   *
   * Commits ONLY the root — the leaves stay private with the writer.
   * Per-paragraph leaves are revealed only through opt-in comparison
   * disclosure bundles (Section 06). This avoids the membership-oracle attack
   * where publishing the full leaf array would let anyone test whether a
   * guessed paragraph appears in the registered script.
   */
  paragraphTreeProfile?: typeof PARAGRAPH_TREE_PROFILE
  paragraphTreeRoot?: string
  paragraphCount?: number
  /**
   * Optional declarative pointer to the parent registration this revision
   * descends from. Builds a Merkle-DAG of script versions (one full snapshot
   * per registration; revisions linked via parent's claimHash).
   *
   * v1 semantics: UNVERIFIED at v1 (the verifier does NOT fetch the parent
   * registration). The pointer is part of the immutable commitment, so the
   * registrant cannot change it post-registration without invalidating the
   * claim hash; but the parent's existence and authenticity are not enforced
   * by v1 verifiers.
   */
  previousRegistration?: { claimHash: string }
  /**
   * Optional registrant identity binding (Section 06).
   *
   * If present, contains an Ed25519 public key + a registration-time signature
   * over the claim body (the canonical-JSON-hash of committedClaim with the
   * `registrant` field omitted). The signature proves that the keypair was
   * actually used to register THIS claim — stronger than later challenge-
   * response which only proves current key control.
   *
   * Verifier obligations:
   *  1. Reconstruct claim body by deleting committedClaim.registrant
   *  2. Recompute claimBodyHash = SHA-256(RFC8785(claim_body))
   *  3. Verify signature against `<REGISTRANT_SIGNATURE_DOMAIN> || claimBodyHash`
   *  4. Confirm registrant.signedDigest matches recomputed claimBodyHash
   */
  registrant?: RegistrantBlock
  /**
   * Optional time-locked encrypted fields (Section 07, capability-flagged).
   * Uses Drand League of Entropy threshold BLS network for tlock encryption.
   * Content is locked until a specified Drand round (unixTime → round number
   * via the chain's genesis/period).
   *
   * v1 semantics: BEHIND THE timelockCapability:v1 FLAG. Implementations
   * that don't support timelock MUST refuse to claim full v1 conformance
   * for manifests containing this field, but MAY still verify the other
   * commitment-bearing fields.
   */
  timelockFields?: TimelockField[]
  /** Encrypted fields block per Section 04. */
  encryptedFields?: EncryptedFieldsBlock
  /** User-set preferences (e.g. AI-training opt-out). */
  preferences?: Preferences
}

/**
 * Registrant identity + registration-time signature (Section 06).
 *
 * The signature is computed BEFORE the claim's full hash, over the claim body
 * (committedClaim with the `registrant` field omitted). This binds the keypair
 * to the registration at registration time, not just at later challenge-
 * response time.
 */
export interface RegistrantBlock {
  /** "ed25519:<base64 of 32-byte raw public key>" per RFC 8032 */
  publicKey: string
  /** Algorithm identifier; v1 always "ed25519". */
  signatureAlgorithm: 'ed25519'
  /** Domain identifier signed alongside the body hash. v1 = REGISTRANT_SIGNATURE_DOMAIN. */
  signatureDomain: typeof REGISTRANT_SIGNATURE_DOMAIN
  /** "sha256:<hex>" of the canonical claim body (committedClaim minus `registrant`). */
  signedDigest: string
  /** "ed25519:<base64 of 64-byte signature>" over (domain || signedDigest_raw_bytes). */
  signature: string
}

/**
 * One time-locked field. Decrypts when the specified Drand round signature
 * is published (at a deterministic future time).
 */
export interface TimelockField {
  /** Field name (unencrypted; presence + length leak per spec §07). */
  name: string
  /** base64 of the tlock-encrypted ciphertext. */
  ciphertext: string
  /** Drand round number at which decryption becomes possible. */
  unlockAtRound: number
  /** ISO-8601 UTC timestamp of the asserted unlock time (derived from round + chain genesis/period; informational). */
  unlockAt: string
  /** Hex hash identifying the Drand chain (mainnet vs quicknet vs others). Commits which network to fetch from. */
  drandChainHash: string
  /** Hex hash of the Drand chain's group public key (for offline verification). */
  drandPublicKey: string
  /** Encryption scheme identifier. v1: "tlock-bls12-381-quicknet" or similar (Drand chain decides curve/scheme). */
  scheme: string
}

// ---------------------------------------------------------------------------
// evidenceBundle — extensible, untrusted metadata
// ---------------------------------------------------------------------------

export type ProofType = 'opentimestamps' | string // open for future expansion

export interface OpenTimestampsProof {
  type: 'opentimestamps'
  /** MUST equal the verifier's recomputed claimHash. */
  claimHash: string
  /** Relative path to a sibling `.ots` binary file. */
  proofRef: string
  /** Convenience metadata; UNTRUSTED — verifiers derive truth from the .ots itself. */
  submittedAt?: string
  upgradedAt?: string
}

export type EvidenceProof = OpenTimestampsProof | (Record<string, unknown> & { type: string; claimHash: string })

export interface EvidenceBundle {
  /** Sender's assertion of the claim hash. MUST be verified against independent recomputation. */
  committedClaimHash: string
  proofs: EvidenceProof[]
  /** Always present. Empty object `{}` if no extensions. Untrusted. */
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
