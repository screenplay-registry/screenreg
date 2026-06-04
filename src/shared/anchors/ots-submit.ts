/**
 * Cross-runtime OpenTimestamps calendar submission — pure TypeScript, no Python
 * and no native dependencies. This is the single submit path shared by the CLI
 * (`register`) and the browser `/create/` page. Each calendar's `/digest`
 * endpoint receives a NONCE-BLINDED commitment — `SHA256(claimHash ‖ nonce)`,
 * never the (public) claim hash itself — so a calendar operator can't index the
 * public claim hash against submission metadata. The nonce is embedded in the
 * proof, so it still chains claimHash → blinded → Bitcoin, and the claim hash
 * remains the OTS file digest (verify + finalize walk these ops). The calendar
 * sub-trees are assembled with `buildOtsBytes`.
 *
 * The only thing that leaves the machine is the 32-byte blinded commitment.
 * Uses `globalThis.fetch` (Node 20+ and every evergreen browser); `fetchImpl`
 * is injectable for tests.
 */

import { buildOtsBytes, encodeVarUint, isValidTimestampSubtree } from './ots-build.js'
import { sha256 } from '../crypto.js'

/** Length of the per-submission blinding nonce (matches the upstream OTS client). */
const NONCE_LEN = 16

export const DEFAULT_CALENDARS: readonly string[] = [
  'https://a.pool.opentimestamps.org',
  'https://alice.btc.calendar.opentimestamps.org',
  'https://bob.btc.calendar.opentimestamps.org',
  'https://finney.calendar.eternitywall.com',
]
/** Require at least this many calendars to accept the digest before minting a proof. */
export const DEFAULT_MIN_CALENDARS = 2
export const DEFAULT_TIMEOUT_MS = 15_000
/** Placeholder calendar for an offline (`--mock`) proof — never contacted. */
export const MOCK_CALENDAR_URL = 'https://mock.calendar.example/'

const ATTESTATION_MARKER = 0x00
// OTS PendingAttestation tag (fixed spec constant), used only to mint a mock proof.
const PENDING_TAG = new Uint8Array([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e])

export interface CalendarResult {
  url: string
  ok: boolean
  bytes?: Uint8Array
  error?: string
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n)
  globalThis.crypto.getRandomValues(out)
  return out
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

async function submitToCalendar(
  fetchImpl: typeof fetch,
  url: string,
  digest: Uint8Array,
  timeoutMs: number,
): Promise<CalendarResult> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    // text/plain keeps this in the CORS "simple request" set (no preflight); the
    // public calendars all return access-control-allow-origin: *.
    const resp = await fetchImpl(`${url.replace(/\/+$/, '')}/digest`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: digest,
      mode: 'cors',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: ctrl.signal,
    } as RequestInit)
    if (!resp.ok) return { url, ok: false, error: `HTTP ${resp.status}` }
    const ctype = resp.headers?.get?.('content-type') || ''
    if (ctype && !/octet-stream|opentimestamps/i.test(ctype)) {
      return { url, ok: false, error: `unexpected content-type ${ctype}` }
    }
    const bytes = new Uint8Array(await resp.arrayBuffer())
    if (!isValidTimestampSubtree(bytes)) {
      return { url, ok: false, error: `response is not a valid OTS Timestamp sub-tree (${bytes.length} bytes)` }
    }
    return { url, ok: true, bytes }
  } catch (err) {
    const e = err as { name?: string; message?: string }
    const reason = e?.name === 'AbortError'
      ? `timed out after ${Math.round(timeoutMs / 1000)}s`
      : e?.message ?? String(err)
    return { url, ok: false, error: reason }
  } finally {
    clearTimeout(timer)
  }
}

export interface SubmitOptions {
  /** 32-byte SHA-256 digest (the claim hash). */
  fileDigest: Uint8Array
  calendars?: readonly string[]
  minCalendars?: number
  timeoutMs?: number
  /** Injectable fetch; defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch
  /** Called as each calendar resolves (e.g. to drive per-row UI in the browser). */
  onResult?: (r: CalendarResult) => void
}

export type SubmitResult =
  | { ok: true; otsBytes: Uint8Array; results: CalendarResult[] }
  | { ok: false; reason: string; results: CalendarResult[] }

/**
 * Submit a digest to the calendars in parallel and assemble the initial (pending)
 * `.ots`. Succeeds once at least `minCalendars` accept; never throws on a single
 * calendar failure (each has its own timeout and is reported in `results`).
 */
export async function submitDigestToCalendars(opts: SubmitOptions): Promise<SubmitResult> {
  const digest = opts.fileDigest
  if (!(digest instanceof Uint8Array) || digest.length !== 32) {
    return { ok: false, reason: `digest must be 32 bytes, got ${digest?.length}`, results: [] }
  }
  const calendars = opts.calendars ?? DEFAULT_CALENDARS
  // At least one calendar must accept — a proof with zero attestations is meaningless,
  // and minCalendars=0 would otherwise fall through to buildOtsBytes([]) and throw.
  const minCalendars = Math.max(1, opts.minCalendars ?? DEFAULT_MIN_CALENDARS)
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as typeof fetch | undefined)
  if (typeof fetchImpl !== 'function') {
    return { ok: false, reason: 'no fetch available in this runtime (Node 20+ or a browser required)', results: [] }
  }

  // Blind the (public) claim hash before it touches a calendar: submit
  // SHA256(digest ‖ nonce). The calendars timestamp the blinded value just the
  // same; the proof records the nonce so it still chains digest → blinded →
  // Bitcoin (verify + finalize walk these ops). This denies the calendar
  // operators a tracking handle on the public claim hash. Upstream-OTS standard.
  const nonce = randomBytes(NONCE_LEN)
  const blinded = await sha256(concatBytes([digest, nonce]))

  const settled = await Promise.allSettled(
    calendars.map(async (url) => {
      const r = await submitToCalendar(fetchImpl, url, blinded, timeoutMs)
      opts.onResult?.(r)
      return r
    }),
  )
  const results: CalendarResult[] = settled.map((s, i) =>
    s.status === 'fulfilled' ? s.value : { url: calendars[i] ?? '?', ok: false, error: 'unexpected error' },
  )
  const accepted = results.filter((r) => r.ok && r.bytes)
  if (accepted.length < minCalendars) {
    return {
      ok: false,
      reason: `only ${accepted.length} of ${calendars.length} calendars accepted the digest (need ≥${minCalendars})`,
      results,
    }
  }
  const otsBytes = buildOtsBytes({ fileDigest: digest, calendarTimestamps: accepted.map((r) => r.bytes!), nonce })
  return { ok: true, otsBytes, results }
}

/**
 * Build a pending-only `.ots` for offline/mock use: the claim hash plus a single
 * PendingAttestation against a placeholder calendar. Contacts no network and is
 * NOT a verifiable proof — it has no real calendar or Bitcoin backing.
 */
export function buildMockOts(fileDigest: Uint8Array, calendarUrl: string = MOCK_CALENDAR_URL): Uint8Array {
  const uri = new TextEncoder().encode(calendarUrl)
  const payload = concatBytes([encodeVarUint(uri.length), uri])
  const pendingSubtree = concatBytes([
    new Uint8Array([ATTESTATION_MARKER]),
    PENDING_TAG,
    encodeVarUint(payload.length),
    payload,
  ])
  return buildOtsBytes({ fileDigest, calendarTimestamps: [pendingSubtree] })
}
