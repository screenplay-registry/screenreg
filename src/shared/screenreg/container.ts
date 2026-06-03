/**
 * `.screenreg` container build/read (Section 11) — cross-runtime.
 *
 * Packs the artifacts a registration already produces (the v1 envelope, the OpenTimestamps
 * proof, optionally the source text) into one deterministic store-only ZIP. The container is
 * NOT commitment-bearing: `claimHash` is fixed before packing and is invariant under bundling.
 * The only field touched is the OTS `proofRef`, which lives in the unhashed `evidenceBundle`
 * and is rewritten to the in-archive proof name so a reader can resolve it.
 */

import { sha256, toHex } from '../crypto.js'
import type { Envelope, OpenTimestampsProof } from '../envelope/types.js'
import { buildReadme } from './readme.js'
import { zipStore, unzipStore, type ZipEntry } from './zip.js'
import {
  BUNDLE_FORMAT,
  ENTRY_DESCRIPTOR,
  ENTRY_ENVELOPE,
  ENTRY_OTS_PROOF,
  ENTRY_README,
  ENTRY_SOURCE_TEXT,
  type BundleType,
  type DescriptorEntry,
  type ScreenregDescriptor,
} from './types.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: false })

export class ScreenregError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ScreenregError'
  }
}

export interface BuildBundleInput {
  /** The v1 envelope (committedClaim + evidenceBundle). Not mutated. */
  envelope: Envelope
  /** OTS proof bytes. Required iff the envelope carries an `opentimestamps` proof. */
  otsBytes?: Uint8Array
  /**
   * The exact source bytes whose v1-strict normalization hashes to `contentHash`. Required for
   * a full bundle, ignored for an evidence bundle. For PDF input this is the EXTRACTED text
   * (the PDF itself is never the hashed artifact — see Section 08).
   */
  sourceText?: Uint8Array
}

/** Full, self-contained bundle (`<name>.screenreg`): includes the source text. */
export async function buildScreenreg(input: BuildBundleInput): Promise<Uint8Array> {
  if (!input.sourceText) {
    throw new ScreenregError('full bundle requires sourceText (use buildEvidenceScreenreg for proof-only)')
  }
  return buildBundle(input, 'full')
}

/** Evidence (proof-only) bundle (`<name>.evidence.screenreg`): no source text. */
export async function buildEvidenceScreenreg(
  input: Omit<BuildBundleInput, 'sourceText'>,
): Promise<Uint8Array> {
  return buildBundle(input, 'evidence')
}

async function buildBundle(input: BuildBundleInput, type: BundleType): Promise<Uint8Array> {
  const envelope = structuredClone(input.envelope)
  const claimHash = envelope.evidenceBundle?.committedClaimHash
  if (typeof claimHash !== 'string' || claimHash.length === 0) {
    throw new ScreenregError('envelope.evidenceBundle.committedClaimHash is missing')
  }

  // Reconcile the OTS proof with the supplied bytes. proofRef lives in the unhashed evidence
  // bundle, so rewriting it to the in-archive name leaves claimHash untouched.
  const otsProofs = (envelope.evidenceBundle.proofs ?? []).filter(
    (p): p is OpenTimestampsProof => (p as { type?: string }).type === 'opentimestamps',
  )
  if (otsProofs.length > 1) {
    throw new ScreenregError('v1 container supports at most one opentimestamps proof')
  }
  if (otsProofs.length === 1 && !input.otsBytes) {
    throw new ScreenregError('envelope references an opentimestamps proof but no otsBytes were supplied')
  }
  if (otsProofs.length === 0 && input.otsBytes) {
    throw new ScreenregError('otsBytes supplied but envelope has no opentimestamps proof')
  }
  const hasOts = otsProofs.length === 1
  if (hasOts) otsProofs[0]!.proofRef = ENTRY_OTS_PROOF

  const envelopeBytes = encoder.encode(JSON.stringify(envelope, null, 2) + '\n')
  const readmeBytes = encoder.encode(buildReadme({ bundleType: type, claimHash }))

  // Non-descriptor entries, in canonical physical order (envelope, proof, source, readme).
  const payload: ZipEntry[] = [{ name: ENTRY_ENVELOPE, bytes: envelopeBytes }]
  if (hasOts) payload.push({ name: ENTRY_OTS_PROOF, bytes: input.otsBytes! })
  if (type === 'full') payload.push({ name: ENTRY_SOURCE_TEXT, bytes: input.sourceText! })
  payload.push({ name: ENTRY_README, bytes: readmeBytes })

  const roleOf: Record<string, DescriptorEntry['role']> = {
    [ENTRY_ENVELOPE]: 'envelope',
    [ENTRY_OTS_PROOF]: 'ots-proof',
    [ENTRY_SOURCE_TEXT]: 'source-text',
    [ENTRY_README]: 'readme',
  }

  const entries: DescriptorEntry[] = []
  for (const e of payload) {
    entries.push({
      path: e.name,
      role: roleOf[e.name] ?? 'unknown',
      bytes: e.bytes.length,
      sha256: `sha256:${toHex(await sha256(e.bytes))}`,
    })
  }
  // Code-unit sort: deterministic across runtimes (unlike locale-aware comparison).
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))

  const descriptor: ScreenregDescriptor = {
    format: BUNDLE_FORMAT,
    bundleType: type,
    contents: {
      descriptor: ENTRY_DESCRIPTOR,
      envelope: ENTRY_ENVELOPE,
      ...(hasOts ? { otsProof: ENTRY_OTS_PROOF } : {}),
      ...(type === 'full' ? { sourceText: ENTRY_SOURCE_TEXT } : {}),
      readme: ENTRY_README,
    },
    entries,
  }
  const descriptorBytes = encoder.encode(JSON.stringify(descriptor, null, 2) + '\n')

  // Descriptor first, then payload in canonical order (README already last in `payload`).
  return zipStore([{ name: ENTRY_DESCRIPTOR, bytes: descriptorBytes }, ...payload])
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

export interface ParsedBundle {
  descriptor: ScreenregDescriptor
  /** Parsed envelope JSON. Structural validity is the caller's concern (validateEnvelope). */
  envelope: Envelope
  /** Raw envelope.json bytes, as stored. */
  envelopeBytes: Uint8Array
  otsBytes?: Uint8Array
  /** Present only for a full bundle. */
  sourceText?: Uint8Array
  integrity: { ok: boolean; issues: string[] }
}

/**
 * Parse and verify a `.screenreg`. This is the single verified read path: `integrity` folds in
 * the declared SHA-256 of every entry (not just presence/size), so a valid-CRC content swap is
 * caught here. Async because SHA-256 runs via Web Crypto. Does NOT verify the OTS proof against
 * Bitcoin — that is the verifier's job. Throws ScreenregError on a structurally invalid bundle;
 * a structurally valid but tampered bundle parses with `integrity.ok === false`.
 */
export async function readScreenreg(bytes: Uint8Array): Promise<ParsedBundle> {
  const map = new Map<string, Uint8Array>()
  for (const e of unzipStore(bytes)) map.set(e.name, e.bytes)
  const descriptor = parseDescriptor(map)

  const issues = await digestIssues(map, descriptor.entries)

  const envBytes = resolve(map, descriptor.contents.envelope)
  if (!envBytes) throw new ScreenregError('envelope entry is missing from the archive')
  let envelope: Envelope
  try {
    envelope = JSON.parse(decoder.decode(envBytes)) as Envelope
  } catch {
    throw new ScreenregError('envelope.json is not valid JSON')
  }

  const result: ParsedBundle = {
    descriptor,
    envelope,
    envelopeBytes: envBytes,
    integrity: { ok: issues.length === 0, issues },
  }
  // Only attach optional payloads when actually present (exactOptionalPropertyTypes).
  const ots = resolve(map, descriptor.contents.otsProof)
  if (ots) result.otsBytes = ots
  const source = resolve(map, descriptor.contents.sourceText)
  if (source) result.sourceText = source
  return result
}

/**
 * Verify every declared sha256 against the actual entry bytes. Returns the list of failures;
 * empty means all declared digests match. A granular alternative to the integrity field of
 * readScreenreg (which uses this same check).
 */
export async function verifyEntryDigests(bytes: Uint8Array): Promise<string[]> {
  const map = new Map<string, Uint8Array>()
  for (const e of unzipStore(bytes)) map.set(e.name, e.bytes)
  let descriptor: ScreenregDescriptor
  try {
    descriptor = parseDescriptor(map)
  } catch (err) {
    return [err instanceof Error ? err.message : String(err)]
  }
  return digestIssues(map, descriptor.entries)
}

async function digestIssues(
  map: Map<string, Uint8Array>,
  entries: ScreenregDescriptor['entries'],
): Promise<string[]> {
  const issues: string[] = []
  for (const entry of entries) {
    const actual = map.get(entry.path)
    if (!actual) {
      issues.push(`missing entry "${entry.path}"`)
      continue
    }
    if (actual.length !== entry.bytes) {
      issues.push(`entry "${entry.path}": size ${actual.length} != declared ${entry.bytes}`)
    }
    const digest = `sha256:${toHex(await sha256(actual))}`
    if (digest !== entry.sha256) {
      issues.push(`entry "${entry.path}": sha256 mismatch`)
    }
  }
  return issues
}

/** Parse the descriptor entry from the archive and validate its shape. */
function parseDescriptor(map: Map<string, Uint8Array>): ScreenregDescriptor {
  const descriptorBytes = map.get(ENTRY_DESCRIPTOR)
  if (!descriptorBytes) throw new ScreenregError(`not a .screenreg: missing ${ENTRY_DESCRIPTOR}`)
  let raw: unknown
  try {
    raw = JSON.parse(decoder.decode(descriptorBytes))
  } catch {
    throw new ScreenregError(`${ENTRY_DESCRIPTOR} is not valid JSON`)
  }
  return validateDescriptor(raw)
}

/**
 * Validate untrusted descriptor JSON before any field is dereferenced, so a malformed descriptor
 * yields a clear ScreenregError rather than a raw TypeError deep in the read path. Also enforces
 * the variant invariant: bundleType "full" iff a source-text is declared.
 */
function validateDescriptor(raw: unknown): ScreenregDescriptor {
  if (typeof raw !== 'object' || raw === null) throw new ScreenregError('descriptor is not an object')
  const d = raw as Record<string, unknown>
  if (d.format !== BUNDLE_FORMAT) {
    throw new ScreenregError(`unrecognized container format: ${String(d.format)}`)
  }
  if (d.bundleType !== 'full' && d.bundleType !== 'evidence') {
    throw new ScreenregError(`invalid bundleType: ${String(d.bundleType)}`)
  }
  if (typeof d.contents !== 'object' || d.contents === null) {
    throw new ScreenregError('descriptor.contents is not an object')
  }
  const c = d.contents as Record<string, unknown>
  if (typeof c.envelope !== 'string') {
    throw new ScreenregError('descriptor.contents.envelope must be a string')
  }
  for (const key of ['descriptor', 'otsProof', 'sourceText', 'readme'] as const) {
    if (c[key] !== undefined && typeof c[key] !== 'string') {
      throw new ScreenregError(`descriptor.contents.${key} must be a string`)
    }
  }
  const hasSource = typeof c.sourceText === 'string'
  if ((d.bundleType === 'full') !== hasSource) {
    throw new ScreenregError(
      `bundleType "${d.bundleType}" disagrees with source-text presence (full requires source-text; evidence forbids it)`,
    )
  }
  if (!Array.isArray(d.entries)) throw new ScreenregError('descriptor.entries must be an array')
  const entryPaths = new Set<string>()
  d.entries.forEach((e, i) => {
    if (typeof e !== 'object' || e === null) {
      throw new ScreenregError(`descriptor.entries[${i}] is not an object`)
    }
    const en = e as Record<string, unknown>
    if (typeof en.path !== 'string') throw new ScreenregError(`descriptor.entries[${i}].path must be a string`)
    if (typeof en.role !== 'string') throw new ScreenregError(`descriptor.entries[${i}].role must be a string`)
    if (typeof en.sha256 !== 'string') throw new ScreenregError(`descriptor.entries[${i}].sha256 must be a string`)
    if (typeof en.bytes !== 'number' || !Number.isInteger(en.bytes) || en.bytes < 0) {
      throw new ScreenregError(`descriptor.entries[${i}].bytes must be a non-negative integer`)
    }
    entryPaths.add(en.path)
  })

  // Every content the descriptor points at (except itself) MUST be a digest-checked entry. This
  // closes the gap where a "full" bundle could DECLARE a sourceText that is absent from both
  // entries[] and the archive, yet still read as integrity.ok with no source present. With this
  // rule, a declared source missing from entries is a malformed descriptor; one missing only from
  // the archive is caught as a missing entry by the digest check.
  for (const [role, path] of Object.entries(c)) {
    if (role === 'descriptor' || path === undefined) continue
    if (!entryPaths.has(path as string)) {
      throw new ScreenregError(`descriptor.contents.${role} ("${String(path)}") is not listed in entries`)
    }
  }
  return raw as ScreenregDescriptor
}

function resolve(map: Map<string, Uint8Array>, path: string | undefined): Uint8Array | undefined {
  return path ? map.get(path) : undefined
}
