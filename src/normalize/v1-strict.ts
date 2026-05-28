/**
 * Reference implementation of the `screenplay-registration-norm/v1-strict` normalization profile.
 *
 * See /spec/v1/01-normalization.md for the canonical specification.
 *
 * This implementation is COMMITMENT-BEARING: its output is hashed and anchored on Bitcoin
 * via OpenTimestamps. Any divergence from the spec creates proofs that other implementations
 * cannot verify. Treat this file as a frozen artifact; bug fixes that change behavior MUST
 * publish under a new profile identifier per spec §7.
 */

import { createHash } from 'node:crypto'

/**
 * Locked profile identifier per spec §1.
 * Embedded in every claim's `committedClaim.normalizationProfile` field.
 */
export const PROFILE_ID = 'screenplay-registration-norm/v1-strict' as const

/**
 * Unicode database version this implementation is calibrated against.
 * Per spec §2.3 and §4(1), implementations MUST document this in release notes.
 *
 * Node.js's `String.prototype.normalize('NFC')` is backed by ICU; the bundled ICU version
 * depends on the Node binary. For Node 20+ small-ICU (default), this is typically a recent
 * Unicode version. For full coverage, build with `--with-intl=full-icu`. Cross-implementation
 * compatibility is verified via the test corpus in /spec/v1/testvectors/normalization/.
 */
export const UNICODE_VERSION_DECLARED = 'node-icu-runtime' as const

/**
 * The kinds of transforms the normalizer can apply, in spec-order.
 * Used by the `diagnose` mode in the CLI/verifier to report what was done
 * to a candidate file — without claiming to know the registered file's bytes.
 */
export type TransformKind =
  | 'rejected-invalid-utf8'
  | 'stripped-bom'
  | 'applied-nfc'
  | 'crlf-to-lf'
  | 'cr-to-lf'

export interface TransformRecord {
  /** The transform that was applied. */
  kind: TransformKind
  /** Number of byte/character instances affected by this transform (informational). */
  count: number
}

export interface NormalizeOk {
  ok: true
  /** The canonical normalized bytes. SHA-256 of this is the contentHash. */
  normalized: Buffer
  /** Sequence of transforms applied, in the order they were applied. */
  transforms: TransformRecord[]
}

export interface NormalizeErr {
  ok: false
  /** Why normalization failed. The only failure mode in v1-strict is invalid UTF-8. */
  reason: 'invalid-utf8'
  /** Human-readable detail, including byte offset where invalid sequence was detected. */
  detail: string
}

export type NormalizeResult = NormalizeOk | NormalizeErr

/**
 * Validate that a Buffer is well-formed UTF-8 per RFC 3629 (strict).
 *
 * Rejects:
 *  - overlong sequences (e.g. 0xC0 0x80 for U+0000)
 *  - surrogate code points (U+D800..U+DFFF)
 *  - sequences encoding code points > U+10FFFF
 *  - truncated multi-byte sequences
 *  - continuation bytes outside multi-byte sequences
 *
 * Returns { ok: true } if valid; { ok: false, offset } if invalid at byte `offset`.
 */
export function validateStrictUtf8(input: Buffer): { ok: true } | { ok: false; offset: number } {
  let i = 0
  const n = input.length
  while (i < n) {
    const b0 = input[i]!
    if (b0 < 0x80) {
      // ASCII: 1-byte sequence
      i += 1
      continue
    }

    // Determine sequence length from leading byte
    let seqLen: number
    let codepoint: number
    let minCodepoint: number

    if ((b0 & 0xe0) === 0xc0) {
      // 2-byte: 110xxxxx
      seqLen = 2
      codepoint = b0 & 0x1f
      minCodepoint = 0x80
    } else if ((b0 & 0xf0) === 0xe0) {
      // 3-byte: 1110xxxx
      seqLen = 3
      codepoint = b0 & 0x0f
      minCodepoint = 0x800
    } else if ((b0 & 0xf8) === 0xf0) {
      // 4-byte: 11110xxx
      seqLen = 4
      codepoint = b0 & 0x07
      minCodepoint = 0x10000
    } else {
      // Either a stray continuation byte (10xxxxxx) or an invalid leading byte
      return { ok: false, offset: i }
    }

    if (i + seqLen > n) {
      // Truncated sequence at end of input
      return { ok: false, offset: i }
    }

    // Consume continuation bytes
    for (let j = 1; j < seqLen; j++) {
      const bj = input[i + j]!
      if ((bj & 0xc0) !== 0x80) {
        return { ok: false, offset: i + j }
      }
      codepoint = (codepoint << 6) | (bj & 0x3f)
    }

    // Reject overlong encodings (e.g. 2-byte encoding of an ASCII codepoint)
    if (codepoint < minCodepoint) {
      return { ok: false, offset: i }
    }

    // Reject surrogates (U+D800..U+DFFF)
    if (codepoint >= 0xd800 && codepoint <= 0xdfff) {
      return { ok: false, offset: i }
    }

    // Reject codepoints > U+10FFFF
    if (codepoint > 0x10ffff) {
      return { ok: false, offset: i }
    }

    i += seqLen
  }

  return { ok: true }
}

/**
 * Apply the `screenplay-registration-norm/v1-strict` normalization rules.
 *
 * Steps (per spec §2):
 *   1. Validate input is well-formed UTF-8 (else reject)
 *   2. Strip leading BOM (0xEF 0xBB 0xBF) if present
 *   3. Apply Unicode NFC normalization
 *   4. Convert CRLF → LF and lone CR → LF
 *
 * Everything else is preserved byte-for-byte.
 */
export function normalize(input: Buffer): NormalizeResult {
  const transforms: TransformRecord[] = []

  // Step 1: Validate UTF-8
  const utf8Validation = validateStrictUtf8(input)
  if (!utf8Validation.ok) {
    return {
      ok: false,
      reason: 'invalid-utf8',
      detail: `Invalid UTF-8 byte sequence detected at offset ${utf8Validation.offset}`,
    }
  }

  // Step 2: Strip leading BOM (only at start; embedded U+FEFF is preserved per spec §3)
  let working = input
  if (
    working.length >= 3 &&
    working[0] === 0xef &&
    working[1] === 0xbb &&
    working[2] === 0xbf
  ) {
    working = working.subarray(3)
    transforms.push({ kind: 'stripped-bom', count: 1 })
  }

  // Step 3: Apply Unicode NFC normalization
  // We decode to string, normalize, re-encode. Track whether NFC actually changed anything
  // by comparing before/after byte lengths AND content; we report the count of characters
  // that differ in informational diagnose output.
  const decoded = working.toString('utf8')
  const nfcDecoded = decoded.normalize('NFC')
  if (nfcDecoded !== decoded) {
    // Count code units that changed (informational; not load-bearing for verification).
    // We use a coarse measure: number of code units in old that aren't in new at the same position.
    let changed = 0
    const minLen = Math.min(decoded.length, nfcDecoded.length)
    for (let i = 0; i < minLen; i++) {
      if (decoded.charCodeAt(i) !== nfcDecoded.charCodeAt(i)) changed++
    }
    changed += Math.abs(decoded.length - nfcDecoded.length)
    transforms.push({ kind: 'applied-nfc', count: changed })
  }
  working = Buffer.from(nfcDecoded, 'utf8')

  // Step 4: Convert line endings (CRLF first, then lone CR)
  // We do this in a single pass over bytes for determinism and performance.
  const out: number[] = []
  let crlfCount = 0
  let loneCrCount = 0
  for (let i = 0; i < working.length; i++) {
    const b = working[i]!
    if (b === 0x0d) {
      // CR — check if followed by LF
      const next = i + 1 < working.length ? working[i + 1] : undefined
      if (next === 0x0a) {
        // CRLF → LF
        out.push(0x0a)
        i++ // skip the LF; we already emitted it
        crlfCount++
      } else {
        // Lone CR → LF
        out.push(0x0a)
        loneCrCount++
      }
    } else {
      out.push(b)
    }
  }
  if (crlfCount > 0) transforms.push({ kind: 'crlf-to-lf', count: crlfCount })
  if (loneCrCount > 0) transforms.push({ kind: 'cr-to-lf', count: loneCrCount })

  const normalized = Buffer.from(out)

  return {
    ok: true,
    normalized,
    transforms,
  }
}

/**
 * Compute the content hash of an input via the v1-strict normalization profile.
 *
 * Returns the hash string in the canonical "sha256:<lowercase-hex>" form per spec §6.
 * Returns null if normalization fails (invalid UTF-8).
 */
export function contentHash(input: Buffer): string | null {
  const result = normalize(input)
  if (!result.ok) return null
  return contentHashOfNormalized(result.normalized)
}

/**
 * Hash already-normalized bytes. Useful for test vector verification and for callers
 * that have stored the normalized form separately.
 */
export function contentHashOfNormalized(normalized: Buffer): string {
  const digest = createHash('sha256').update(normalized).digest('hex')
  return `sha256:${digest}`
}
