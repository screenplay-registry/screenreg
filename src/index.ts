/**
 * Public SDK surface for `@screenplay-registry/cli` (consumed as a library).
 *
 * This module is the SUPPORTED entrypoint for third-party integrators. Reaching
 * into deeper module paths (e.g. `src/merkle/scene-tree`) is unsupported — those
 * may be reorganized without a major version bump. Anything you can import from
 * `@screenplay-registry/cli` is covered by semver-style stability.
 *
 * Stability tiers:
 *   - Locked commitment-bearing constants (CLAIM_VERSION, SCHEMA_ID, profile IDs,
 *     domain tags) — frozen for v1; only change via a new schemaId.
 *   - Envelope build/canonicalize/hash — stable shape; output bytes locked.
 *   - Verifier consistency checks — stable.
 *   - Normalization — stable.
 *   - Comparison bundle build/verify — stable.
 *   - CLI itself (`screenreg`) — separately versioned.
 */

// ---- Locked commitment-bearing identifiers + types ----
export {
  ENVELOPE_VERSION,
  CLAIM_VERSION,
  SCHEMA_ID,
  HASH_ALGORITHM,
  MANIFEST_CANONICALIZATION,
  NORMALIZATION_PROFILE,
  SCENE_TREE_PROFILE,
  PARAGRAPH_TREE_PROFILE,
  REGISTRANT_SIGNATURE_DOMAIN,
  type CommittedClaim,
  type EvidenceBundle,
  type EvidenceProof,
  type OpenTimestampsProof,
  type Envelope,
  type EncryptedFieldsBlock,
  type EncryptedField,
  type RegistrantBlock,
  type TimelockField,
  type Preferences,
  type TrainingMiningPreference,
} from './envelope/types.js'

// ---- Envelope build + canonicalize + hash + consistency ----
export {
  buildCommittedClaim,
  buildEvidenceBundle,
  buildEnvelope,
  checkEnvelopeConsistency,
  type VerifierConsistencyResult,
  type BuildClaimInput,
  type BuildEvidenceBundleInput,
} from './envelope/build.js'
export { canonicalize } from './envelope/canonicalize.js'
export {
  computeClaimHash,
  computeClaimHashBytes,
  canonicalClaimBytes,
} from './envelope/claim-hash.js'
export { validateEnvelope, type ValidationResult } from './envelope/validate.js'

// ---- Normalization ----
export {
  normalize,
  contentHash,
  contentHashOfNormalized,
  type NormalizeResult,
} from './normalize/v1-strict.js'

// ---- Scene Merkle tree (Section 03 §3.1-§3.5) ----
export {
  PROFILE_ID as SCENE_TREE_PROFILE_ID,
  SCENE_CONTENT_PROFILE,
  type Scene,
  type BuiltSceneTree,
  type SceneProof,
  type VerifySceneProofInput,
  type VerifySceneProofResult,
  detectScenes,
  buildSceneTree,
  buildSceneProof,
  verifySceneProof,
  sceneContentHash,
  leafHash,
  leafHashFromContent,
  parentHash,
  reduceSceneTreeRoot,
} from './merkle/scene-tree.js'

// ---- Paragraph Merkle tree (Section 03 §3.6) ----
export {
  PARAGRAPH_TREE_PROFILE_ID,
  PARAGRAPH_CONTENT_PROFILE,
  type Paragraph,
  type BuiltParagraphTree,
  detectParagraphs,
  detectParagraphsWithPositions,
  buildParagraphTree,
  paragraphContentHash,
  paragraphLeafHash,
  paragraphLeafHashFromContent,
  reduceParagraphTreeRoot,
} from './merkle/paragraph-tree.js'

// ---- Shared Merkle primitives ----
export { nextPowerOfTwo, makeParentHash, makePaddingHash, reduceMerkleRoot } from './merkle/primitives.js'

// ---- Encryption ----
export {
  buildEncryptedFieldsBlock,
  decryptFieldsBlock,
} from './encrypt/fields.js'

// ---- Identity (opt-in Ed25519 registrant binding) ----
export {
  generateKeypair,
  loadPrivateKey,
  computeClaimBodyDigest,
  signRegistration,
  verifyRegistrationSignature,
  signChallenge,
  verifySignature,
} from './identity/ed25519-signing.js'

// ---- Comparison disclosure bundle (Section 06) ----
export {
  COMPARISON_BUNDLE_VERSION,
  type ComparisonBundle,
  type ByteRange,
  type BuildBundleInput,
  type BindingResult,
  buildComparisonBundle,
  verifyBundleSelfBinding,
  verifyBundleAgainstClaim,
} from './similarity/comparison-bundle.js'

// ---- Similarity metrics + report formatter ----
export {
  compareBundles,
  formatComparisonReport,
  type ComparisonReport,
  type ComparisonResult,
  type JaccardMetric,
  type MultisetMetric,
  type SequenceMetric,
  type CoverageByWordsMetric,
  type FormatComparisonReportOptions,
} from './similarity/jaccard.js'

// ---- OTS anchoring (Python helper required for submit; verify is pure JS) ----
export { submitOts } from './anchors/ots-submit.js'
export { verifyOtsAgainstFileDigest, parseOts } from './anchors/ots-verify.js'
