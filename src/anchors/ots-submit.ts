/**
 * OpenTimestamps calendar submission for the CLI — a thin Buffer-facing adapter
 * over the cross-runtime engine in `src/shared/anchors/ots-submit.ts`. Pure
 * TypeScript: no Python, no native deps, no venv. The browser `/create/` page
 * uses the same shared engine, so the CLI and browser submit identically.
 *
 * Only a 32-byte nonce-blinded commitment leaves the machine — never the claim
 * hash itself, which remains the OTS file digest of the proof.
 */

import {
  submitDigestToCalendars,
  buildMockOts,
  type CalendarResult,
} from '../shared/anchors/ots-submit.js'

export interface OtsSubmitOptions {
  /** 32-byte SHA-256 digest. */
  digest: Buffer
  /** Calendar URLs to submit to. Defaults to the public OTS pool calendars. */
  calendars?: string[]
  /** Per-calendar timeout in seconds. */
  timeoutSec?: number
  /** Min number of calendars that must accept the digest. */
  minCalendars?: number
  /** Mock mode: emit a placeholder pending .ots without any network calls. */
  mock?: boolean
}

export type OtsSubmitResult =
  | { ok: true; otsBytes: Buffer }
  | { ok: false; reason: string; stderr: string }

/**
 * Submit a nonce-blinded commitment for this 32-byte digest to the OTS public
 * calendars (the calendars see `SHA256(digest ‖ nonce)`, not the digest) and
 * return the serialized .ots binary, whose file digest is still this digest.
 * With `mock: true`, returns an offline placeholder.
 */
export async function submitOts(opts: OtsSubmitOptions): Promise<OtsSubmitResult> {
  if (opts.digest.length !== 32) {
    return { ok: false, reason: `digest must be 32 bytes, got ${opts.digest.length}`, stderr: '' }
  }
  const digest = new Uint8Array(opts.digest.buffer, opts.digest.byteOffset, opts.digest.byteLength)

  if (opts.mock) {
    return { ok: true, otsBytes: Buffer.from(buildMockOts(digest)) }
  }

  const result = await submitDigestToCalendars({
    fileDigest: digest,
    ...(opts.calendars !== undefined ? { calendars: opts.calendars } : {}),
    ...(opts.minCalendars !== undefined ? { minCalendars: opts.minCalendars } : {}),
    ...(opts.timeoutSec !== undefined ? { timeoutMs: opts.timeoutSec * 1000 } : {}),
  })
  if (!result.ok) {
    const failed = result.results.filter((r: CalendarResult) => !r.ok)
    return { ok: false, reason: result.reason, stderr: failed.map((r) => `${r.url}: ${r.error}`).join('; ') }
  }
  return { ok: true, otsBytes: Buffer.from(result.otsBytes) }
}
