/**
 * Cross-runtime reference implementation of `screenplay-registration-norm/v1-strict`.
 *
 * Uses `Uint8Array` exclusively (not `Buffer`) and Web Crypto SHA-256 for the
 * content-hash step, so the same source compiles for Node and browser bundles.
 *
 * BYTE-EQUIVALENCE GUARANTEE: every input that produces an output here MUST produce
 * the byte-identical output in `src/normalize/v1-strict.ts`. CI enforces this against
 * the full published test corpus; divergence is a hard CI failure.
 *
 * This implementation is COMMITMENT-BEARING: its output is hashed and anchored on Bitcoin
 * via OpenTimestamps. Any divergence from the spec creates proofs that other implementations
 * cannot verify. Treat this file as a frozen artifact; bug fixes that change behavior MUST
 * publish under a new profile identifier per spec §7.
 */

import { sha256, toHex } from '../crypto.js'

/**
 * Locked profile identifier per spec §1.
 * Embedded in every claim's `committedClaim.normalizationProfile` field.
 */
export const PROFILE_ID = 'screenplay-registration-norm/v1-strict' as const

/**
 * Unicode database version this implementation is calibrated against.
 *
 * Both Node `String.prototype.normalize('NFC')` and the browser equivalent delegate to
 * ICU. We rely on ICU producing identical NFC output across both runtimes; the cross-impl
 * test corpus is the empirical verifier of that assumption. If a corpus entry ever diverges,
 * we surface the offending codepoint + ICU version in the failure message.
 */
export const UNICODE_VERSION_DECLARED = 'icu-runtime' as const

export type TransformKind =
  | 'rejected-invalid-utf8'
  | 'stripped-bom'
  | 'applied-nfc'
  | 'crlf-to-lf'
  | 'cr-to-lf'

export interface TransformRecord {
  kind: TransformKind
  count: number
}

export interface NormalizeOk {
  ok: true
  /** The canonical normalized bytes. SHA-256 of this is the contentHash. */
  normalized: Uint8Array
  transforms: TransformRecord[]
}

export interface NormalizeErr {
  ok: false
  reason: 'invalid-utf8'
  detail: string
}

export type NormalizeResult = NormalizeOk | NormalizeErr

/**
 * Validate that a Uint8Array is well-formed UTF-8 per RFC 3629 (strict).
 *
 * Same rejection rules as src/normalize/v1-strict.ts validateStrictUtf8:
 *  - overlong sequences (e.g. 0xC0 0x80 for U+0000)
 *  - surrogate code points (U+D800..U+DFFF)
 *  - sequences encoding code points > U+10FFFF
 *  - truncated multi-byte sequences
 *  - continuation bytes outside multi-byte sequences
 *
 * Logic is byte-by-byte identical to the Node-side implementation. We intentionally do NOT
 * delegate to TextDecoder({ fatal: true }) — different runtimes have historically had
 * subtle differences in surrogate handling, and we treat strict UTF-8 validation as
 * commitment-bearing logic that must be deterministic across all implementations.
 */
export function validateStrictUtf8(input: Uint8Array): { ok: true } | { ok: false; offset: number } {
  let i = 0
  const n = input.length
  while (i < n) {
    const b0 = input[i]!
    if (b0 < 0x80) {
      i += 1
      continue
    }

    let seqLen: number
    let codepoint: number
    let minCodepoint: number

    if ((b0 & 0xe0) === 0xc0) {
      seqLen = 2
      codepoint = b0 & 0x1f
      minCodepoint = 0x80
    } else if ((b0 & 0xf0) === 0xe0) {
      seqLen = 3
      codepoint = b0 & 0x0f
      minCodepoint = 0x800
    } else if ((b0 & 0xf8) === 0xf0) {
      seqLen = 4
      codepoint = b0 & 0x07
      minCodepoint = 0x10000
    } else {
      return { ok: false, offset: i }
    }

    if (i + seqLen > n) {
      return { ok: false, offset: i }
    }

    for (let j = 1; j < seqLen; j++) {
      const bj = input[i + j]!
      if ((bj & 0xc0) !== 0x80) {
        return { ok: false, offset: i + j }
      }
      codepoint = (codepoint << 6) | (bj & 0x3f)
    }

    if (codepoint < minCodepoint) {
      return { ok: false, offset: i }
    }

    if (codepoint >= 0xd800 && codepoint <= 0xdfff) {
      return { ok: false, offset: i }
    }

    if (codepoint > 0x10ffff) {
      return { ok: false, offset: i }
    }

    i += seqLen
  }

  return { ok: true }
}

/**
 * `ignoreBOM: true` is load-bearing. TextDecoder defaults to stripping any leading
 * U+FEFF during decode — that would silently consume a SECOND BOM after the spec's
 * step-2 byte-level BOM strip, producing output that diverges from a faithful
 * `Buffer.toString('utf8')` round-trip. v1-strict preserves embedded U+FEFF per
 * spec §3; double-leading-BOM inputs round-trip through legacy as
 * `EF BB BF <rest>` and MUST do the same here.
 */
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true })
const UTF8_ENCODER = new TextEncoder()

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
 *
 * Pure logic — no crypto. Caller composes with sha256() to produce contentHash.
 */
export function normalize(input: Uint8Array): NormalizeResult {
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
  let working: Uint8Array = input
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
  const decoded = UTF8_DECODER.decode(working)
  const nfcDecoded = decoded.normalize('NFC')
  if (nfcDecoded !== decoded) {
    let changed = 0
    const minLen = Math.min(decoded.length, nfcDecoded.length)
    for (let i = 0; i < minLen; i++) {
      if (decoded.charCodeAt(i) !== nfcDecoded.charCodeAt(i)) changed++
    }
    changed += Math.abs(decoded.length - nfcDecoded.length)
    transforms.push({ kind: 'applied-nfc', count: changed })
  }
  working = UTF8_ENCODER.encode(nfcDecoded)

  // Step 4: Convert line endings (CRLF first, then lone CR)
  const out: number[] = []
  let crlfCount = 0
  let loneCrCount = 0
  for (let i = 0; i < working.length; i++) {
    const b = working[i]!
    if (b === 0x0d) {
      const next = i + 1 < working.length ? working[i + 1] : undefined
      if (next === 0x0a) {
        out.push(0x0a)
        i++
        crlfCount++
      } else {
        out.push(0x0a)
        loneCrCount++
      }
    } else {
      out.push(b)
    }
  }
  if (crlfCount > 0) transforms.push({ kind: 'crlf-to-lf', count: crlfCount })
  if (loneCrCount > 0) transforms.push({ kind: 'cr-to-lf', count: loneCrCount })

  const normalized = new Uint8Array(out)

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
 *
 * ASYNC because Web Crypto's digest is async. Callers that need sync (legacy Node
 * paths) can use src/normalize/v1-strict.ts which wraps the same logic with sync crypto.
 */
export async function contentHash(input: Uint8Array): Promise<string | null> {
  const result = normalize(input)
  if (!result.ok) return null
  return contentHashOfNormalized(result.normalized)
}

/**
 * Hash already-normalized bytes. Useful for test vector verification and for callers
 * that have stored the normalized form separately.
 */
export async function contentHashOfNormalized(normalized: Uint8Array): Promise<string> {
  const digest = await sha256(normalized)
  return `sha256:${toHex(digest)}`
}
