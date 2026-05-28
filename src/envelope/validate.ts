/**
 * Schema validator for v1 envelopes.
 *
 * Hand-rolled to mirror `spec/v1/envelope.schema.json` without pulling in ajv
 * (100KB+ runtime dep for the SDK). The validator catches the same defects an
 * external schema validator would: missing required fields, wrong locked
 * values, malformed hash strings, partial all-or-none triples (scene tree,
 * paragraph tree), unknown enum values in preferences, malformed registrant
 * block, malformed timelock field, malformed encrypted fields block.
 *
 * Call this BEFORE recomputing the claim hash in `screenreg verify` — if the
 * envelope is malformed by shape, the hash result is meaningless.
 */

import {
  ENVELOPE_VERSION,
  CLAIM_VERSION,
  SCHEMA_ID,
  HASH_ALGORITHM,
  MANIFEST_CANONICALIZATION,
  NORMALIZATION_PROFILE,
  SCENE_TREE_PROFILE,
  PARAGRAPH_TREE_PROFILE,
  REGISTRANT_SIGNATURE_DOMAIN,
} from './types.js'
import { SHA256_HASH_PATTERN } from '../util/sha256-hash.js'

export type ValidationResult =
  | { ok: true }
  | { ok: false; errors: string[] }

const ED25519_KEY_OR_SIG = /^ed25519:[A-Za-z0-9+/=]+$/
const HEX64 = /^[0-9a-f]{64}$/
const HEX_GENERIC = /^[0-9a-f]+$/

const TRAINING_MINING_VALUES = new Set(['allowed', 'notAllowed', 'constrained'])

/**
 * Validate a parsed envelope object against the v1 schema.
 * Accumulates errors; doesn't short-circuit on the first failure so the user
 * sees every problem at once.
 */
export function validateEnvelope(envelope: unknown): ValidationResult {
  const errors: string[] = []
  if (!isPlainObject(envelope)) {
    return { ok: false, errors: ['envelope: not a plain object'] }
  }
  const env = envelope as Record<string, unknown>

  // Envelope-level required + locked
  requireEqual(errors, 'envelopeVersion', env.envelopeVersion, ENVELOPE_VERSION)
  requirePlainObject(errors, 'committedClaim', env.committedClaim)
  requirePlainObject(errors, 'evidenceBundle', env.evidenceBundle)
  rejectExtraKeys(errors, 'envelope', env, ['envelopeVersion', 'committedClaim', 'evidenceBundle'])

  if (isPlainObject(env.committedClaim)) {
    validateCommittedClaim(env.committedClaim as Record<string, unknown>, errors)
  }
  if (isPlainObject(env.evidenceBundle)) {
    validateEvidenceBundle(env.evidenceBundle as Record<string, unknown>, errors)
  }

  return errors.length === 0 ? { ok: true } : { ok: false, errors }
}

function validateCommittedClaim(claim: Record<string, unknown>, errors: string[]): void {
  // Required + locked-value identifiers
  requireEqual(errors, 'committedClaim.claimVersion', claim.claimVersion, CLAIM_VERSION)
  requireEqual(errors, 'committedClaim.schemaId', claim.schemaId, SCHEMA_ID)
  requireEqual(errors, 'committedClaim.hashAlgorithm', claim.hashAlgorithm, HASH_ALGORITHM)
  requireEqual(
    errors,
    'committedClaim.manifestCanonicalization',
    claim.manifestCanonicalization,
    MANIFEST_CANONICALIZATION,
  )
  requireEqual(
    errors,
    'committedClaim.normalizationProfile',
    claim.normalizationProfile,
    NORMALIZATION_PROFILE,
  )
  requireSha256Hash(errors, 'committedClaim.contentHash', claim.contentHash)
  requirePlainObject(errors, 'committedClaim.claimExtensions', claim.claimExtensions)

  // Scene-tree all-or-none triple
  validateAllOrNoneTriple(errors, claim, 'scene', {
    profile: 'sceneTreeProfile',
    root: 'sceneTreeRoot',
    count: 'sceneCount',
    expectedProfile: SCENE_TREE_PROFILE,
  })

  // Paragraph-tree all-or-none triple
  validateAllOrNoneTriple(errors, claim, 'paragraph', {
    profile: 'paragraphTreeProfile',
    root: 'paragraphTreeRoot',
    count: 'paragraphCount',
    expectedProfile: PARAGRAPH_TREE_PROFILE,
  })

  // Optional fields
  if (claim.previousRegistration !== undefined) {
    validatePreviousRegistration(claim.previousRegistration, errors)
  }
  if (claim.registrant !== undefined) {
    validateRegistrant(claim.registrant, errors)
  }
  if (claim.timelockFields !== undefined) {
    if (!Array.isArray(claim.timelockFields)) {
      errors.push('committedClaim.timelockFields: not an array')
    } else {
      claim.timelockFields.forEach((f, i) => validateTimelockField(f, i, errors))
    }
  }
  if (claim.encryptedFields !== undefined) {
    validateEncryptedFieldsBlock(claim.encryptedFields, errors)
  }
  if (claim.preferences !== undefined) {
    validatePreferences(claim.preferences, errors)
  }
}

function validateAllOrNoneTriple(
  errors: string[],
  claim: Record<string, unknown>,
  label: 'scene' | 'paragraph',
  spec: { profile: string; root: string; count: string; expectedProfile: string },
): void {
  const present = [spec.profile, spec.root, spec.count].filter((k) => claim[k] !== undefined)
  if (present.length === 0) return // all absent — fine
  if (present.length !== 3) {
    errors.push(
      `committedClaim.${label} tree: all-or-none — found ${present.length}/3 fields present (${present.join(', ')}); MUST be all three or none`,
    )
    return
  }
  requireEqual(errors, `committedClaim.${spec.profile}`, claim[spec.profile], spec.expectedProfile)
  requireSha256Hash(errors, `committedClaim.${spec.root}`, claim[spec.root])
  requireNonNegativeInteger(errors, `committedClaim.${spec.count}`, claim[spec.count])
}

function validatePreviousRegistration(value: unknown, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push('committedClaim.previousRegistration: not a plain object')
    return
  }
  const v = value as Record<string, unknown>
  requireSha256Hash(errors, 'committedClaim.previousRegistration.claimHash', v.claimHash)
  rejectExtraKeys(errors, 'committedClaim.previousRegistration', v, ['claimHash'])
}

function validateRegistrant(value: unknown, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push('committedClaim.registrant: not a plain object')
    return
  }
  const r = value as Record<string, unknown>
  requirePatternedString(errors, 'committedClaim.registrant.publicKey', r.publicKey, ED25519_KEY_OR_SIG)
  requireEqual(errors, 'committedClaim.registrant.signatureAlgorithm', r.signatureAlgorithm, 'ed25519')
  requireEqual(
    errors,
    'committedClaim.registrant.signatureDomain',
    r.signatureDomain,
    REGISTRANT_SIGNATURE_DOMAIN,
  )
  requireSha256Hash(errors, 'committedClaim.registrant.signedDigest', r.signedDigest)
  requirePatternedString(errors, 'committedClaim.registrant.signature', r.signature, ED25519_KEY_OR_SIG)
  rejectExtraKeys(errors, 'committedClaim.registrant', r, [
    'publicKey',
    'signatureAlgorithm',
    'signatureDomain',
    'signedDigest',
    'signature',
  ])
}

function validateTimelockField(value: unknown, idx: number, errors: string[]): void {
  const path = `committedClaim.timelockFields[${idx}]`
  if (!isPlainObject(value)) {
    errors.push(`${path}: not a plain object`)
    return
  }
  const f = value as Record<string, unknown>
  requireNonEmptyString(errors, `${path}.name`, f.name)
  requireNonEmptyString(errors, `${path}.ciphertext`, f.ciphertext)
  requireNonNegativeInteger(errors, `${path}.unlockAtRound`, f.unlockAtRound)
  if (f.unlockAtRound !== undefined && typeof f.unlockAtRound === 'number' && f.unlockAtRound < 1) {
    errors.push(`${path}.unlockAtRound: must be >= 1`)
  }
  requireIso8601DateTime(errors, `${path}.unlockAt`, f.unlockAt)
  requirePatternedString(errors, `${path}.drandChainHash`, f.drandChainHash, HEX64)
  requirePatternedString(errors, `${path}.drandPublicKey`, f.drandPublicKey, HEX_GENERIC)
  requireNonEmptyString(errors, `${path}.scheme`, f.scheme)
  rejectExtraKeys(errors, path, f, [
    'name',
    'ciphertext',
    'unlockAtRound',
    'unlockAt',
    'drandChainHash',
    'drandPublicKey',
    'scheme',
  ])
}

function validateEncryptedFieldsBlock(value: unknown, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push('committedClaim.encryptedFields: not a plain object')
    return
  }
  const b = value as Record<string, unknown>
  requireNonEmptyString(errors, 'committedClaim.encryptedFields.masterSalt', b.masterSalt)
  requireEqual(errors, 'committedClaim.encryptedFields.kdf', b.kdf, 'pbkdf2-hmac-sha256')
  requireNonNegativeInteger(errors, 'committedClaim.encryptedFields.kdfIterations', b.kdfIterations)
  if (typeof b.kdfIterations === 'number' && b.kdfIterations < 1) {
    errors.push('committedClaim.encryptedFields.kdfIterations: must be >= 1')
  }
  requireEqual(
    errors,
    'committedClaim.encryptedFields.aadFormat',
    b.aadFormat,
    'screenplay-registration-aad-v1',
  )
  if (!Array.isArray(b.fields)) {
    errors.push('committedClaim.encryptedFields.fields: not an array')
  } else {
    b.fields.forEach((f, i) => validateEncryptedField(f, i, errors))
  }
  rejectExtraKeys(errors, 'committedClaim.encryptedFields', b, [
    'masterSalt',
    'kdf',
    'kdfIterations',
    'aadFormat',
    'fields',
  ])
}

function validateEncryptedField(value: unknown, idx: number, errors: string[]): void {
  const path = `committedClaim.encryptedFields.fields[${idx}]`
  if (!isPlainObject(value)) {
    errors.push(`${path}: not a plain object`)
    return
  }
  const f = value as Record<string, unknown>
  requireNonEmptyString(errors, `${path}.name`, f.name)
  requireNonEmptyString(errors, `${path}.iv`, f.iv)
  requireNonEmptyString(errors, `${path}.ciphertext`, f.ciphertext)
  requireNonEmptyString(errors, `${path}.tag`, f.tag)
  requireNonNegativeInteger(errors, `${path}.paddingBucket`, f.paddingBucket)
  if (typeof f.paddingBucket === 'number' && f.paddingBucket < 1) {
    errors.push(`${path}.paddingBucket: must be >= 1`)
  }
  rejectExtraKeys(errors, path, f, ['name', 'iv', 'ciphertext', 'tag', 'paddingBucket'])
}

function validatePreferences(value: unknown, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push('committedClaim.preferences: not a plain object')
    return
  }
  const p = value as Record<string, unknown>
  if (p.trainingMining !== undefined) {
    if (typeof p.trainingMining !== 'string' || !TRAINING_MINING_VALUES.has(p.trainingMining)) {
      errors.push(
        `committedClaim.preferences.trainingMining: must be one of allowed|notAllowed|constrained, got ${JSON.stringify(p.trainingMining)}`,
      )
    }
  }
  rejectExtraKeys(errors, 'committedClaim.preferences', p, ['trainingMining'])
}

function validateEvidenceBundle(value: Record<string, unknown>, errors: string[]): void {
  requireSha256Hash(errors, 'evidenceBundle.committedClaimHash', value.committedClaimHash)
  if (!Array.isArray(value.proofs)) {
    errors.push('evidenceBundle.proofs: not an array')
  } else {
    value.proofs.forEach((p, i) => validateEvidenceProof(p, i, errors))
  }
  requirePlainObject(errors, 'evidenceBundle.bundleExtensions', value.bundleExtensions)
  rejectExtraKeys(errors, 'evidenceBundle', value, ['committedClaimHash', 'proofs', 'bundleExtensions'])
}

function validateEvidenceProof(value: unknown, idx: number, errors: string[]): void {
  const path = `evidenceBundle.proofs[${idx}]`
  if (!isPlainObject(value)) {
    errors.push(`${path}: not a plain object`)
    return
  }
  const p = value as Record<string, unknown>
  requireNonEmptyString(errors, `${path}.type`, p.type)
  requireSha256Hash(errors, `${path}.claimHash`, p.claimHash)
  // proof types are open-ended (additionalProperties: true in schema); don't reject extras
}

// ---------------------------------------------------------------------------
// Small primitive helpers
// ---------------------------------------------------------------------------

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function requireEqual(errors: string[], path: string, actual: unknown, expected: string): void {
  if (actual !== expected) {
    errors.push(`${path}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)
  }
}

function requirePlainObject(errors: string[], path: string, actual: unknown): void {
  if (!isPlainObject(actual)) {
    errors.push(`${path}: not a plain object`)
  }
}

function requireSha256Hash(errors: string[], path: string, actual: unknown): void {
  if (typeof actual !== 'string' || !SHA256_HASH_PATTERN.test(actual)) {
    errors.push(`${path}: expected "sha256:<64-lowercase-hex>", got ${JSON.stringify(actual)}`)
  }
}

function requirePatternedString(
  errors: string[],
  path: string,
  actual: unknown,
  pattern: RegExp,
): void {
  if (typeof actual !== 'string' || !pattern.test(actual)) {
    errors.push(`${path}: does not match pattern ${pattern}, got ${JSON.stringify(actual)}`)
  }
}

function requireNonEmptyString(errors: string[], path: string, actual: unknown): void {
  if (typeof actual !== 'string' || actual.length === 0) {
    errors.push(`${path}: expected non-empty string, got ${JSON.stringify(actual)}`)
  }
}

function requireNonNegativeInteger(errors: string[], path: string, actual: unknown): void {
  if (typeof actual !== 'number' || !Number.isInteger(actual) || actual < 0) {
    errors.push(`${path}: expected non-negative integer, got ${JSON.stringify(actual)}`)
  }
}

/**
 * Validate an ISO 8601 date-time string per JSON Schema's `format: "date-time"`.
 * Accepts the common RFC 3339 profile (e.g. `2027-01-01T00:00:00Z` /
 * `2027-01-01T00:00:00.123+00:00`). Used for `timelockFields[].unlockAt`.
 */
function requireIso8601DateTime(errors: string[], path: string, actual: unknown): void {
  if (typeof actual !== 'string' || actual.length === 0) {
    errors.push(`${path}: expected ISO 8601 date-time string, got ${JSON.stringify(actual)}`)
    return
  }
  // RFC 3339 date-time: full-date "T" full-time. Accepts millis (optional) and
  // either "Z" or numeric offset. Date.parse + round-trip is the cheap correctness
  // check — JavaScript's Date.parse on a valid ISO string returns a finite number,
  // and the canonical re-serialization should match the canonical form.
  const parsed = Date.parse(actual)
  if (!Number.isFinite(parsed)) {
    errors.push(`${path}: not a parseable ISO 8601 date-time, got ${JSON.stringify(actual)}`)
    return
  }
  // Pattern check on the shape — guards against `Date.parse` accepting things
  // like `"2027"` (which parses to a valid Date but isn't a full date-time).
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/.test(actual)) {
    errors.push(`${path}: not an RFC 3339 date-time (YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)), got ${JSON.stringify(actual)}`)
  }
}

function rejectExtraKeys(
  errors: string[],
  path: string,
  obj: Record<string, unknown>,
  allowed: string[],
): void {
  const allowedSet = new Set(allowed)
  const extras = Object.keys(obj).filter((k) => !allowedSet.has(k))
  if (extras.length > 0) {
    errors.push(`${path}: unknown fields ${extras.map((k) => JSON.stringify(k)).join(', ')}`)
  }
}
