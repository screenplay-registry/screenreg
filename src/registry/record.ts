/**
 * Off-chain registry-index record: builder + validator (Node-side).
 *
 * A registry record is a DISCOVERY artifact, not a commitment. It carries the
 * opaque `claimHash`, optional public labels (title / author), an INFORMATIONAL
 * `registeredAt`, and the anchor coordinates needed to re-verify the record's
 * truth independently (the OTS proof against Bitcoin; an optional Ethereum
 * anchor). It is NOT a `committedClaim` field, is never hashed, and lives wholly
 * outside the frozen v1 commitment surface. See spec/v1/10-registry-index.md.
 *
 * Two hard boundaries this module enforces:
 *  - The script `contentHash` is FORBIDDEN at any nesting depth. Publishing the
 *    script fingerprint next to a public, searchable record would turn the index
 *    into a membership oracle for the work. Its presence is REJECTED, not ignored.
 *  - `registeredAt` is INFORMATIONAL only. Priority and dispute resolution use the
 *    Bitcoin block height from each record's own `.ots`, never an operator-supplied
 *    wall-clock label (see priority.ts).
 */

import { SHA256_HASH_PATTERN } from '../util/sha256-hash.js'

export const REGISTRY_RECORD_VERSION = 'urn:screenplay-registration-registry-record:v1'

const ED25519_PUBLIC_KEY = /^ed25519:[A-Za-z0-9+/=]+$/
const ETH_ADDRESS = /^0x[0-9a-fA-F]{40}$/
const ETH_TX_HASH = /^0x[0-9a-fA-F]{64}$/

/** Optional author labels: a chosen public name over a pseudonymous key. */
export interface RegistryRecordAuthor {
  pubkey: string
  name?: string
}

/** OpenTimestamps anchor: the per-record proof reference + an informational hint. */
export interface RegistryOpenTimestampsAnchor {
  /**
   * Snapshot-relative reference (filename) to the record's `.ots` proof. The
   * loader resolves it ONLY relative to the snapshot directory and rejects
   * absolute paths, `..` traversal, and symlinks.
   */
  proofRef: string
  /**
   * INFORMATIONAL hint only. An OTS-CLAIMED height is NOT Bitcoin-final until an
   * attestation verifier confirms header inclusion; priority never uses this hint.
   */
  bitcoinBlock?: number
}

/** Optional secondary Ethereum-anchor coordinates (Section 09). Never a priority source. */
export interface RegistryEthereumAnchor {
  chainId: number
  contract: string
  txHash: string
  logIndex: number
  blockNumber: number
}

export interface RegistryRecordAnchors {
  opentimestamps: RegistryOpenTimestampsAnchor
  ethereum?: RegistryEthereumAnchor
}

/**
 * An off-chain registry-index record. Note the deliberate absence of any
 * `contentHash` field — it is forbidden, not merely optional.
 */
export interface RegistryRecord {
  registryRecordVersion: typeof REGISTRY_RECORD_VERSION
  claimHash: string
  title?: string
  author?: RegistryRecordAuthor
  /** INFORMATIONAL only; never used for priority/tie resolution. */
  registeredAt?: string
  anchors: RegistryRecordAnchors
}

export interface BuildRegistryRecordInput {
  claimHash: string
  title?: string
  author?: RegistryRecordAuthor
  registeredAt?: string
  anchors: RegistryRecordAnchors
}

export type RegistryRecordValidationResult =
  | { ok: true }
  | { ok: false; errors: string[] }

/**
 * Assemble a registry record from validated inputs. Performs no I/O. The caller
 * is responsible for supplying a `claimHash` recomputed from the envelope and a
 * `proofRef` that resolves to the record's `.ots`. Validate the result before
 * publishing it.
 */
export function buildRegistryRecord(input: BuildRegistryRecordInput): RegistryRecord {
  const record: RegistryRecord = {
    registryRecordVersion: REGISTRY_RECORD_VERSION,
    claimHash: input.claimHash,
    anchors: {
      opentimestamps: {
        proofRef: input.anchors.opentimestamps.proofRef,
        ...(input.anchors.opentimestamps.bitcoinBlock !== undefined
          ? { bitcoinBlock: input.anchors.opentimestamps.bitcoinBlock }
          : {}),
      },
      ...(input.anchors.ethereum !== undefined ? { ethereum: { ...input.anchors.ethereum } } : {}),
    },
  }
  if (input.title !== undefined) record.title = input.title
  if (input.author !== undefined) {
    record.author = {
      pubkey: input.author.pubkey,
      ...(input.author.name !== undefined ? { name: input.author.name } : {}),
    }
  }
  if (input.registeredAt !== undefined) record.registeredAt = input.registeredAt
  return record
}

/**
 * Validate a parsed registry record against spec/v1/registry-record.schema.json.
 * Accumulates errors so the caller sees every problem at once. Rejects a
 * `contentHash` at any depth (membership-oracle boundary).
 */
export function validateRegistryRecord(value: unknown): RegistryRecordValidationResult {
  const errors: string[] = []
  if (!isPlainObject(value)) {
    return { ok: false, errors: ['record: not a plain object'] }
  }
  const r = value as Record<string, unknown>

  requireEqual(errors, 'registryRecordVersion', r.registryRecordVersion, REGISTRY_RECORD_VERSION)
  requireSha256Hash(errors, 'claimHash', r.claimHash)

  if (r.title !== undefined) requireNonEmptyString(errors, 'title', r.title)
  if (r.author !== undefined) validateAuthor(r.author, errors)
  if (r.registeredAt !== undefined) requireIso8601DateTime(errors, 'registeredAt', r.registeredAt)

  if (r.anchors === undefined) {
    errors.push('anchors: required')
  } else {
    validateAnchors(r.anchors, errors)
  }

  rejectExtraKeys(errors, 'record', r, [
    'registryRecordVersion',
    'claimHash',
    'title',
    'author',
    'registeredAt',
    'anchors',
  ])

  // Membership-oracle boundary: contentHash is forbidden anywhere in the record.
  rejectKeyDeep(r, 'contentHash', 'record', errors)

  return errors.length === 0 ? { ok: true } : { ok: false, errors }
}

function validateAuthor(value: unknown, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push('author: not a plain object')
    return
  }
  const a = value as Record<string, unknown>
  requirePatternedString(errors, 'author.pubkey', a.pubkey, ED25519_PUBLIC_KEY)
  if (a.name !== undefined) requireNonEmptyString(errors, 'author.name', a.name)
  rejectExtraKeys(errors, 'author', a, ['pubkey', 'name'])
}

function validateAnchors(value: unknown, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push('anchors: not a plain object')
    return
  }
  const a = value as Record<string, unknown>
  if (a.opentimestamps === undefined) {
    errors.push('anchors.opentimestamps: required')
  } else {
    validateOpenTimestampsAnchor(a.opentimestamps, errors)
  }
  if (a.ethereum !== undefined) validateEthereumAnchor(a.ethereum, errors)
  rejectExtraKeys(errors, 'anchors', a, ['opentimestamps', 'ethereum'])
}

function validateOpenTimestampsAnchor(value: unknown, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push('anchors.opentimestamps: not a plain object')
    return
  }
  const o = value as Record<string, unknown>
  requireNonEmptyString(errors, 'anchors.opentimestamps.proofRef', o.proofRef)
  if (o.bitcoinBlock !== undefined) {
    requireNonNegativeInteger(errors, 'anchors.opentimestamps.bitcoinBlock', o.bitcoinBlock)
  }
  rejectExtraKeys(errors, 'anchors.opentimestamps', o, ['proofRef', 'bitcoinBlock'])
}

function validateEthereumAnchor(value: unknown, errors: string[]): void {
  if (!isPlainObject(value)) {
    errors.push('anchors.ethereum: not a plain object')
    return
  }
  const e = value as Record<string, unknown>
  requireNonNegativeInteger(errors, 'anchors.ethereum.chainId', e.chainId)
  if (typeof e.chainId === 'number' && Number.isInteger(e.chainId) && e.chainId < 1) {
    errors.push('anchors.ethereum.chainId: must be >= 1')
  }
  requirePatternedString(errors, 'anchors.ethereum.contract', e.contract, ETH_ADDRESS)
  requirePatternedString(errors, 'anchors.ethereum.txHash', e.txHash, ETH_TX_HASH)
  requireNonNegativeInteger(errors, 'anchors.ethereum.logIndex', e.logIndex)
  requireNonNegativeInteger(errors, 'anchors.ethereum.blockNumber', e.blockNumber)
  rejectExtraKeys(errors, 'anchors.ethereum', e, [
    'chainId',
    'contract',
    'txHash',
    'logIndex',
    'blockNumber',
  ])
}

// ---------------------------------------------------------------------------
// Primitive helpers (mirror src/envelope/validate.ts; kept local so this
// Node-side registry module has no cross-module coupling to the envelope
// validator's internals).
// ---------------------------------------------------------------------------

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function requireEqual(errors: string[], path: string, actual: unknown, expected: string): void {
  if (actual !== expected) {
    errors.push(`${path}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)
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

function requireIso8601DateTime(errors: string[], path: string, actual: unknown): void {
  if (typeof actual !== 'string' || actual.length === 0) {
    errors.push(`${path}: expected ISO 8601 date-time string, got ${JSON.stringify(actual)}`)
    return
  }
  const parsed = Date.parse(actual)
  if (!Number.isFinite(parsed)) {
    errors.push(`${path}: not a parseable ISO 8601 date-time, got ${JSON.stringify(actual)}`)
    return
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/.test(actual)) {
    errors.push(
      `${path}: not an RFC 3339 date-time (YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)), got ${JSON.stringify(actual)}`,
    )
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

/**
 * Reject `key` anywhere in `obj` (top-level or nested), bounded by a maximum
 * recursion depth so an adversarial deeply-nested input cannot exhaust the
 * stack. Keeps `contentHash` (the script fingerprint) off every published
 * record — its presence would turn the index into a membership oracle.
 */
function rejectKeyDeep(
  obj: Record<string, unknown>,
  key: string,
  path: string,
  errors: string[],
  depth = 0,
): void {
  if (depth > 16) return
  for (const k of Object.keys(obj)) {
    if (k === key) {
      errors.push(
        `${path}.${k}: contentHash is not permitted in a registry record (membership-oracle boundary)`,
      )
    }
    const v = obj[k]
    if (isPlainObject(v)) {
      rejectKeyDeep(v, key, `${path}.${k}`, errors, depth + 1)
    } else if (Array.isArray(v)) {
      v.forEach((item, i) => {
        if (isPlainObject(item)) {
          rejectKeyDeep(item, key, `${path}.${k}[${i}]`, errors, depth + 1)
        }
      })
    }
  }
}
