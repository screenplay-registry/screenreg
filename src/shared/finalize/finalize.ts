/**
 * The finalize engine — fold a confirmed Bitcoin attestation into a pending
 * `.ots` proof. This is the OpenTimestamps "upgrade" operation, performed
 * cross-runtime (browser + Node 20+) so the browser pages, the CLI, and an
 * integrator all share one implementation.
 *
 * How an OpenTimestamps proof confirms: at registration a claim hash is sent to
 * the public calendars, which return a *pending* attestation — a promise to fold
 * the hash into the next Bitcoin batch. Once that batch is mined and buried, the
 * calendar can hand back the path from the hash to the Bitcoin block. Finalizing
 * fetches that path and splices it in, producing a self-contained proof that
 * verifies against Bitcoin block headers alone.
 *
 * What this does:
 *   1. Parse the proof header; derive the claim hash (the file digest).
 *   2. Walk the timestamp tree, EXECUTING ops, to find each pending attestation
 *      and the exact "commitment" message the calendar signed (the value its
 *      `/timestamp/<commitment>` endpoint is keyed by). The file-digest →
 *      commitment path uses only SHA-256 + APPEND/PREPEND, all available in the
 *      browser via the injected SHA-256.
 *   3. GET `<calendar>/timestamp/<hex(commitment)>` for each pending attestation.
 *      When the response carries a Bitcoin attestation, splice it in place of the
 *      pending leaf.
 *   4. Structurally re-validate the spliced proof and report `confirmed` (a
 *      Bitcoin attestation is present) or `pending` (not yet).
 *
 * What this does NOT do (matching the verifier's scope in `ots-verify.ts`): it
 * does not check that the computed merkle root actually appears in the asserted
 * Bitcoin block — that needs block headers (a Bitcoin node or a block explorer)
 * and is performed by `ots verify` / the CLI against your own node. Finalize
 * establishes that a Bitcoin attestation now EXISTS and is structurally sound.
 *
 * Nothing here is commitment-bearing: the `.ots` is the envelope's mutable
 * `evidenceBundle` sidecar, never hashed into the `claimHash`. A finalize can
 * strengthen evidence; it can never change what was claimed.
 */

import { sha256 as defaultSha256, toHex } from '../crypto.js'
import { isValidTimestampSubtree } from '../anchors/ots-build.js'
import type { FinalizeEvent, FinalizeResult } from './types.js'
import { NoopNotifier, type FinalizeNotifier } from './notifier.js'

// Wire-format constants (spec-locked; mirror src/anchors/ots-verify.ts and
// src/shared/anchors/ots-build.ts — duplicated to keep this module free of any
// Node-side import and self-contained for the browser build).
const HEADER_MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
])
const MAJOR_VERSION = 1
const OP_SHA1 = 0x02
const OP_RIPEMD160 = 0x03
const OP_SHA256 = 0x08
const OP_KECCAK256 = 0x67
const OP_APPEND = 0xf0
const OP_PREPEND = 0xf1
const OP_REVERSE = 0xf2
const OP_HEXLIFY = 0xf3
const FORK_MARKER = 0xff
const ATTESTATION_MARKER = 0x00

const TAG_BITCOIN = new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01])
const TAG_LITECOIN = new Uint8Array([0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45])
const TAG_PENDING = new Uint8Array([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e])

// Caps mirror the strict walker in ots-build.ts so this engine accepts exactly
// the proofs the rest of the codebase considers well-formed.
const MAX_OP_RESULT_LENGTH = 4096
const MAX_BINARY_OP_ARG_LENGTH = 4096
const MAX_ATTESTATION_PAYLOAD_SIZE = 8192
const MAX_FORK_DEPTH = 128
const SHA256_LEN = 32
const SHA1_LEN = 20
const RIPEMD160_LEN = 20
/** Pending-URI rules, matching ots-verify.ts / ots-build.ts so this engine agrees
 *  with the canonical parser on which proofs are well-formed. */
const MAX_PENDING_URI_LENGTH = 1000
/** Cap on a whole proof (input and spliced output), matching `parseOts`. */
const MAX_OTS_BYTES = 8 * 1024 * 1024
/** Cap on one calendar's upgrade response body. Upgrade sub-trees are well under a kilobyte. */
const MAX_CALENDAR_RESPONSE_BYTES = 1024 * 1024

const PENDING_URI_ALLOWED: Set<number> = (() => {
  const s = new Set<number>()
  for (const ch of 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:') {
    s.add(ch.charCodeAt(0))
  }
  return s
})()

export interface FinalizeOptions {
  /** The proof to finalize (pending or already-confirmed). */
  otsBytes: Uint8Array
  /**
   * Injected fetch. Defaults to `globalThis.fetch`. Inject for tests, for a
   * proxy, or for a non-`fetch` runtime. Only ever used for `GET` to a calendar's
   * `/timestamp/<commitment>` endpoint.
   */
  fetchImpl?: typeof fetch
  /** Injected SHA-256. Defaults to the shared `crypto.subtle` implementation. */
  sha256?: (bytes: Uint8Array) => Promise<Uint8Array>
  /**
   * Best-effort lifecycle hook (the email/webhook seam). Defaults to a no-op.
   * A throwing notifier never affects the finalize result.
   */
  notifier?: FinalizeNotifier
  /** Per-calendar request timeout in milliseconds. */
  timeoutMs?: number
}

interface PendingSite {
  /** Calendar base URL from the pending attestation. */
  url: string
  /** The message the calendar signed; its `/timestamp/<hex>` endpoint is keyed by this. */
  commitment: Uint8Array
  /** Byte range of the pending-attestation leaf within the proof, for splicing. */
  attStart: number
  attEnd: number
}

interface CollectedAttestations {
  bitcoinHeights: number[]
  litecoinHeights: number[]
  pendingUrls: string[]
}

const DEFAULT_TIMEOUT_MS = 10_000

/**
 * Finalize a proof. Never throws for ordinary "not ready yet" / "calendar
 * unreachable" conditions — those resolve to `pending`. Returns `error` only
 * when the input cannot be parsed as a proof. The input proof is never mutated;
 * on `pending`/`error` the same bytes come back out.
 */
export async function finalizeProof(opts: FinalizeOptions): Promise<FinalizeResult> {
  const sha256 = opts.sha256 ?? defaultSha256
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as typeof fetch | undefined)
  const notifier: FinalizeNotifier = opts.notifier ?? new NoopNotifier()
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS

  if (opts.otsBytes.length > MAX_OTS_BYTES) {
    return emit(notifier, {
      status: 'error',
      otsBytes: opts.otsBytes,
      bitcoinBlockHeights: [],
      pendingCalendars: [],
      reason: `.ots too large: ${opts.otsBytes.length} bytes (max ${MAX_OTS_BYTES})`,
    }, claimHashOf(undefined))
  }

  let header: { fileDigest: Uint8Array; treeStart: number }
  try {
    header = parseHeader(opts.otsBytes)
  } catch (e) {
    return emit(notifier, {
      status: 'error',
      otsBytes: opts.otsBytes,
      bitcoinBlockHeights: [],
      pendingCalendars: [],
      reason: `cannot parse .ots: ${errMsg(e)}`,
    }, claimHashOf(undefined))
  }
  const claimHash = claimHashOf(header.fileDigest)

  // A proof that already carries a Bitcoin attestation is finished — return it
  // unchanged without any network call. Use the STRUCTURAL walker (no op
  // execution) so a Bitcoin path that uses ops we do not execute (e.g. an
  // already-confirmed proof's merkle ops) cannot turn an idempotent call into
  // an error.
  let structural: CollectedAttestations
  try {
    structural = walkStructural(opts.otsBytes, header.treeStart)
  } catch (e) {
    return emit(notifier, {
      status: 'error',
      otsBytes: opts.otsBytes,
      bitcoinBlockHeights: [],
      pendingCalendars: [],
      reason: `malformed timestamp tree: ${errMsg(e)}`,
    }, claimHash)
  }
  if (structural.bitcoinHeights.length > 0) {
    return emit(notifier, {
      status: 'confirmed',
      otsBytes: opts.otsBytes,
      bitcoinBlockHeights: structural.bitcoinHeights,
      pendingCalendars: structural.pendingUrls,
    }, claimHash)
  }

  // No Bitcoin attestation yet. Derive each pending commitment by executing the
  // ops up to the pending leaf. If the proof uses an op we cannot execute before
  // a pending leaf (sha1/ripemd160/keccak — not produced by the v1 calendars),
  // we cannot derive its commitment; fall back to `pending` rather than error.
  let sites: PendingSite[]
  try {
    sites = await derivePendingSites(opts.otsBytes, header.treeStart, header.fileDigest, sha256)
  } catch (e) {
    return emit(notifier, {
      status: 'pending',
      otsBytes: opts.otsBytes,
      bitcoinBlockHeights: [],
      pendingCalendars: structural.pendingUrls,
      reason: `cannot derive pending commitments: ${errMsg(e)}`,
    }, claimHash)
  }
  if (sites.length === 0 || fetchImpl === undefined) {
    const result: FinalizeResult = {
      status: 'pending',
      otsBytes: opts.otsBytes,
      bitcoinBlockHeights: [],
      pendingCalendars: structural.pendingUrls,
    }
    if (fetchImpl === undefined) result.reason = 'no fetch implementation available'
    return emit(notifier, result, claimHash)
  }

  // Ask each calendar for the Bitcoin path. A calendar that 404s, errors, times
  // out, or returns a non-sub-tree simply yields no candidate for that site —
  // never a failure of the whole call.
  const candidates: { attStart: number; attEnd: number; replacement: Uint8Array }[] = []
  for (const site of sites) {
    const body = await fetchCalendarTimestamp(fetchImpl, site, timeoutMs)
    if (body) candidates.push({ attStart: site.attStart, attEnd: site.attEnd, replacement: body })
  }

  // Apply candidates INDEPENDENTLY. Each is accepted only if splicing it (atop
  // the already-accepted edits) keeps the whole proof structurally valid AND
  // adds Bitcoin weight. This is the authoritative validation: it walks the
  // spliced tree from the file digest, so the response is checked under the
  // ACTUAL commitment message length, not an assumed one. A hostile, useless,
  // or oversized response is dropped without discarding any other calendar's
  // valid upgrade. All offsets are relative to the original bytes, and the
  // edits are non-overlapping pending leaves, so any accepted subset re-splices
  // cleanly from the original.
  const accepted: typeof candidates = []
  let acceptedHeights = 0
  for (const cand of candidates) {
    const trial = applyEdits(opts.otsBytes, [...accepted, cand])
    if (trial.length > MAX_OTS_BYTES) continue
    let walk: CollectedAttestations
    try {
      walk = walkStructural(trial, header.treeStart)
    } catch {
      continue
    }
    if (walk.bitcoinHeights.length > acceptedHeights) {
      accepted.push(cand)
      acceptedHeights = walk.bitcoinHeights.length
    }
  }

  if (accepted.length === 0) {
    return emit(notifier, {
      status: 'pending',
      otsBytes: opts.otsBytes,
      bitcoinBlockHeights: [],
      pendingCalendars: structural.pendingUrls,
    }, claimHash)
  }

  const finalBytes = applyEdits(opts.otsBytes, accepted)
  let after: CollectedAttestations
  try {
    after = walkStructural(finalBytes, header.treeStart)
  } catch {
    // Each accepted edit was validated in a trial, so this should not happen;
    // fail closed to pending rather than return an unvalidated proof.
    return emit(notifier, {
      status: 'pending',
      otsBytes: opts.otsBytes,
      bitcoinBlockHeights: [],
      pendingCalendars: structural.pendingUrls,
      reason: 'spliced proof failed final validation',
    }, claimHash)
  }
  return emit(notifier, {
    status: 'confirmed',
    otsBytes: finalBytes,
    bitcoinBlockHeights: after.bitcoinHeights,
    pendingCalendars: after.pendingUrls,
  }, claimHash)
}

/** Emit the matching lifecycle event (best-effort) and return the result. */
function emit(notifier: FinalizeNotifier, result: FinalizeResult, claimHash: string): FinalizeResult {
  let event: FinalizeEvent
  if (result.status === 'confirmed') {
    event = { type: 'confirmed', claimHash, bitcoinBlockHeights: result.bitcoinBlockHeights, otsBytes: result.otsBytes }
  } else if (result.status === 'error') {
    event = { type: 'error', claimHash, reason: result.reason ?? 'error' }
  } else {
    event = { type: 'pending', claimHash, pendingCalendars: result.pendingCalendars }
  }
  // A notifier failure must never affect proof finalization. Swallow sync throws;
  // a rejected promise from an async notifier is intentionally not awaited here.
  try {
    const maybe = notifier.notify(event)
    if (maybe && typeof (maybe as Promise<void>).catch === 'function') {
      ;(maybe as Promise<void>).catch(() => {})
    }
  } catch {
    /* best-effort delivery only */
  }
  return result
}

function claimHashOf(fileDigest: Uint8Array | undefined): string {
  return fileDigest ? `sha256:${toHex(fileDigest)}` : 'sha256:unknown'
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

function parseHeader(buf: Uint8Array): { fileDigest: Uint8Array; treeStart: number } {
  if (buf.length < HEADER_MAGIC.length + 2 + SHA256_LEN) {
    throw new Error('too short for a v1 .ots header')
  }
  for (let i = 0; i < HEADER_MAGIC.length; i++) {
    if (buf[i] !== HEADER_MAGIC[i]) throw new Error(`header magic mismatch at byte ${i}`)
  }
  let pos = HEADER_MAGIC.length
  const major = buf[pos++]!
  if (major !== MAJOR_VERSION) throw new Error(`unsupported major version ${major}`)
  const opTag = buf[pos++]!
  if (opTag !== OP_SHA256) throw new Error(`expected OP_SHA256 file-hash op, got 0x${opTag.toString(16)}`)
  const fileDigest = buf.slice(pos, pos + SHA256_LEN)
  if (fileDigest.length !== SHA256_LEN) throw new Error('truncated file digest')
  return { fileDigest, treeStart: pos + SHA256_LEN }
}

// ---------------------------------------------------------------------------
// Structural walker — validates shape + collects attestations, no op execution.
// Used to detect an already-confirmed proof and to validate a spliced result.
// ---------------------------------------------------------------------------

function walkStructural(buf: Uint8Array, treeStart: number): CollectedAttestations {
  const out: CollectedAttestations = { bitcoinHeights: [], litecoinHeights: [], pendingUrls: [] }
  const posAfter = walkStructuralBranch(buf, treeStart, 0, SHA256_LEN, out)
  if (posAfter !== buf.length) {
    throw new Error(`trailing bytes after timestamp tree (${buf.length - posAfter} left)`)
  }
  return out
}

function walkStructuralBranch(
  buf: Uint8Array,
  start: number,
  depth: number,
  initialMsgLen: number,
  out: CollectedAttestations,
): number {
  if (depth > MAX_FORK_DEPTH) throw new Error(`exceeds max fork depth ${MAX_FORK_DEPTH}`)
  let pos = start
  let msgLen = initialMsgLen
  while (pos < buf.length) {
    const tag = buf[pos]!
    if (tag === FORK_MARKER) {
      pos = walkStructuralBranch(buf, pos + 1, depth + 1, msgLen, out)
      continue
    }
    if (tag === ATTESTATION_MARKER) {
      pos += 1
      if (pos + 8 > buf.length) throw new Error('truncated attestation tag')
      const tagStart = pos
      pos += 8
      const lenInfo = readVarUint(buf, pos)
      pos = lenInfo.posAfter
      const payloadStart = pos
      const payloadEnd = payloadStart + lenInfo.value
      if (lenInfo.value > MAX_ATTESTATION_PAYLOAD_SIZE) throw new Error('attestation payload too large')
      if (payloadEnd > buf.length) throw new Error('attestation payload exceeds buffer')
      recordAttestation(buf, tagStart, payloadStart, lenInfo.value, out)
      return payloadEnd
    }
    pos = applyOpStructural(buf, pos, tag, (n) => (msgLen = n), () => msgLen)
  }
  throw new Error('branch did not terminate at an attestation')
}

/** Advance past one op, updating msgLen via setters; no message bytes computed. */
function applyOpStructural(
  buf: Uint8Array,
  opPos: number,
  tag: number,
  setMsgLen: (n: number) => void,
  getMsgLen: () => number,
): number {
  let pos = opPos + 1
  if (tag === OP_SHA256) { setMsgLen(SHA256_LEN); return pos }
  if (tag === OP_SHA1) { setMsgLen(SHA1_LEN); return pos }
  if (tag === OP_RIPEMD160) { setMsgLen(RIPEMD160_LEN); return pos }
  if (tag === OP_KECCAK256) throw new Error('OP_KECCAK256 not supported by the verifier')
  if (tag === OP_REVERSE) {
    if (getMsgLen() > MAX_OP_RESULT_LENGTH) throw new Error('OP_REVERSE result too large')
    return pos
  }
  if (tag === OP_HEXLIFY) {
    const n = getMsgLen() * 2
    if (n > MAX_OP_RESULT_LENGTH) throw new Error('OP_HEXLIFY result too large')
    setMsgLen(n)
    return pos
  }
  if (tag === OP_APPEND || tag === OP_PREPEND) {
    const lenInfo = readVarUint(buf, pos)
    if (lenInfo.value < 1 || lenInfo.value > MAX_BINARY_OP_ARG_LENGTH) throw new Error('binary-op arg out of range')
    const argEnd = lenInfo.posAfter + lenInfo.value
    if (argEnd > buf.length) throw new Error('binary-op arg exceeds buffer')
    const n = getMsgLen() + lenInfo.value
    if (n > MAX_OP_RESULT_LENGTH) throw new Error('binary-op result too large')
    setMsgLen(n)
    return argEnd
  }
  throw new Error(`unknown op tag 0x${tag.toString(16)} at offset ${opPos}`)
}

function recordAttestation(
  buf: Uint8Array,
  tagStart: number,
  payloadStart: number,
  payloadLen: number,
  out: CollectedAttestations,
): void {
  if (tagEquals(buf, tagStart, TAG_PENDING)) {
    const urlInfo = readVarUint(buf, payloadStart)
    const urlStart = urlInfo.posAfter
    const urlLen = urlInfo.value
    if (urlLen === 0 || urlStart + urlLen !== payloadStart + payloadLen) {
      throw new Error('malformed pending attestation payload')
    }
    // Match the canonical parser's rules exactly: bounded length, restricted
    // charset, and an http(s):// scheme. Anything else is a proof the verifier
    // would reject, so reject it here too rather than mint or pass it along.
    if (urlLen > MAX_PENDING_URI_LENGTH) throw new Error('pending URL exceeds max length')
    let url = ''
    for (let i = 0; i < urlLen; i++) {
      const b = buf[urlStart + i]!
      if (!PENDING_URI_ALLOWED.has(b)) throw new Error('pending URL has invalid byte')
      url += String.fromCharCode(b)
    }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      throw new Error('pending URL does not start with http:// or https://')
    }
    out.pendingUrls.push(url)
    return
  }
  const isBtc = tagEquals(buf, tagStart, TAG_BITCOIN)
  const isLtc = tagEquals(buf, tagStart, TAG_LITECOIN)
  if (isBtc || isLtc) {
    const h = readVarUint(buf, payloadStart)
    if (h.posAfter !== payloadStart + payloadLen) throw new Error('block-header payload trailing bytes')
    if (h.value < 1) throw new Error('block height < 1')
    if (isBtc) out.bitcoinHeights.push(h.value)
    else out.litecoinHeights.push(h.value)
    return
  }
  // Unknown attestation tag: tolerated structurally (it carries no Bitcoin
  // weight) so the walk over a multi-attestation proof still completes.
}

// ---------------------------------------------------------------------------
// Executing walker — computes the commitment message at each pending leaf so we
// know what to query the calendar with. Only SHA-256 + binary/unary ops are
// executed (the calendar-aggregation path); other crypto ops throw.
// ---------------------------------------------------------------------------

async function derivePendingSites(
  buf: Uint8Array,
  treeStart: number,
  fileDigest: Uint8Array,
  sha256: (b: Uint8Array) => Promise<Uint8Array>,
): Promise<PendingSite[]> {
  const sites: PendingSite[] = []
  await execBranch(buf, treeStart, fileDigest, 0, sha256, sites)
  return sites
}

async function execBranch(
  buf: Uint8Array,
  start: number,
  msgIn: Uint8Array,
  depth: number,
  sha256: (b: Uint8Array) => Promise<Uint8Array>,
  sites: PendingSite[],
): Promise<number> {
  if (depth > MAX_FORK_DEPTH) throw new Error(`exceeds max fork depth ${MAX_FORK_DEPTH}`)
  let pos = start
  let msg = msgIn
  while (pos < buf.length) {
    const tag = buf[pos]!
    if (tag === FORK_MARKER) {
      pos = await execBranch(buf, pos + 1, msg, depth + 1, sha256, sites)
      continue
    }
    if (tag === ATTESTATION_MARKER) {
      const attStart = pos
      pos += 1
      const tagStart = pos
      pos += 8
      const lenInfo = readVarUint(buf, pos)
      pos = lenInfo.posAfter
      const payloadStart = pos
      const payloadEnd = payloadStart + lenInfo.value
      if (payloadEnd > buf.length) throw new Error('attestation payload exceeds buffer')
      if (tagEquals(buf, tagStart, TAG_PENDING)) {
        const urlInfo = readVarUint(buf, payloadStart)
        let url = ''
        for (let i = 0; i < urlInfo.value; i++) url += String.fromCharCode(buf[urlInfo.posAfter + i]!)
        sites.push({ url, commitment: msg.slice(), attStart, attEnd: payloadEnd })
      }
      return payloadEnd
    }
    pos += 1
    if (tag === OP_SHA256) {
      msg = await sha256(msg)
    } else if (tag === OP_APPEND || tag === OP_PREPEND) {
      const lenInfo = readVarUint(buf, pos)
      if (lenInfo.value < 1 || lenInfo.value > MAX_BINARY_OP_ARG_LENGTH) throw new Error('binary-op arg out of range')
      const argEnd = lenInfo.posAfter + lenInfo.value
      if (argEnd > buf.length) throw new Error('binary-op arg exceeds buffer')
      const arg = buf.subarray(lenInfo.posAfter, argEnd)
      const next = new Uint8Array(msg.length + arg.length)
      if (next.length > MAX_OP_RESULT_LENGTH) throw new Error('binary-op result too large')
      if (tag === OP_APPEND) {
        next.set(msg, 0)
        next.set(arg, msg.length)
      } else {
        next.set(arg, 0)
        next.set(msg, arg.length)
      }
      msg = next
      pos = argEnd
    } else if (tag === OP_REVERSE) {
      const r = new Uint8Array(msg.length)
      for (let i = 0; i < msg.length; i++) r[i] = msg[msg.length - 1 - i]!
      msg = r
    } else if (tag === OP_HEXLIFY) {
      msg = new TextEncoder().encode(toHex(msg))
      if (msg.length > MAX_OP_RESULT_LENGTH) throw new Error('OP_HEXLIFY result too large')
    } else if (tag === OP_SHA1 || tag === OP_RIPEMD160 || tag === OP_KECCAK256) {
      // Not produced by the v1 calendars on the path to a pending attestation,
      // and not available via Web Crypto. If one ever appears here we cannot
      // derive the commitment in-engine; surface it so the caller stays pending.
      throw new Error(`cannot execute op 0x${tag.toString(16)} before a pending attestation`)
    } else {
      throw new Error(`unknown op tag 0x${tag.toString(16)} at offset ${pos - 1}`)
    }
  }
  throw new Error('branch did not terminate at an attestation')
}

// ---------------------------------------------------------------------------
// Calendar fetch + splice
// ---------------------------------------------------------------------------

/**
 * Ask one calendar to upgrade a commitment. Returns the candidate sub-tree bytes
 * when the response is a well-formed Timestamp sub-tree; otherwise null
 * (unreachable, 404, oversized, or junk). Never throws.
 *
 * Whether the candidate actually advances the proof to Bitcoin is decided by the
 * caller, by splicing it under the real commitment and re-validating the whole
 * tree — so this function does NOT need to assume the commitment is 32 bytes.
 */
async function fetchCalendarTimestamp(
  fetchImpl: typeof fetch,
  site: PendingSite,
  timeoutMs: number,
): Promise<Uint8Array | null> {
  const base = site.url.replace(/\/+$/, '')
  const endpoint = `${base}/timestamp/${toHex(site.commitment)}`
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const resp = await fetchImpl(endpoint, {
      method: 'GET',
      headers: { Accept: 'application/octet-stream' },
      signal: controller.signal,
      // Calendars are public and require no credentials; never attach any.
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
    } as RequestInit)
    if (!resp.ok) return null
    const body = await readBodyCapped(resp, MAX_CALENDAR_RESPONSE_BYTES)
    if (body === null) return null
    // Cheap junk filter; the authoritative check is the caller's post-splice
    // re-validation of the full tree.
    if (!isValidTimestampSubtree(body)) return null
    return body
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Read a response body, refusing to buffer more than `max` bytes. Prefers a
 * streamed read so an oversized body is abandoned without ever fully
 * allocating; falls back to `arrayBuffer()` (with a post-read size check) when
 * the runtime/response does not expose a readable stream. Returns null if the
 * body exceeds the cap.
 */
async function readBodyCapped(resp: Response, max: number): Promise<Uint8Array | null> {
  const declared = resp.headers?.get?.('content-length')
  if (declared && Number(declared) > max) return null

  const stream = (resp as { body?: ReadableStream<Uint8Array> | null }).body
  if (stream && typeof stream.getReader === 'function') {
    const reader = stream.getReader()
    const chunks: Uint8Array[] = []
    let total = 0
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        if (value) {
          total += value.length
          if (total > max) {
            try { await reader.cancel() } catch { /* ignore */ }
            return null
          }
          chunks.push(value)
        }
      }
    } finally {
      try { reader.releaseLock() } catch { /* ignore */ }
    }
    const out = new Uint8Array(total)
    let off = 0
    for (const c of chunks) { out.set(c, off); off += c.length }
    return out
  }

  const ab = await resp.arrayBuffer()
  if (ab.byteLength > max) return null
  return new Uint8Array(ab)
}

/** Apply non-overlapping byte-range replacements, lowest offset first. */
function applyEdits(
  buf: Uint8Array,
  edits: { attStart: number; attEnd: number; replacement: Uint8Array }[],
): Uint8Array {
  const sorted = [...edits].sort((a, b) => a.attStart - b.attStart)
  const parts: Uint8Array[] = []
  let cursor = 0
  for (const e of sorted) {
    if (e.attStart < cursor) throw new Error('overlapping splice edits')
    parts.push(buf.subarray(cursor, e.attStart))
    parts.push(e.replacement)
    cursor = e.attEnd
  }
  parts.push(buf.subarray(cursor))
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

// ---------------------------------------------------------------------------
// Small readers
// ---------------------------------------------------------------------------

function tagEquals(buf: Uint8Array, start: number, tag: Uint8Array): boolean {
  for (let i = 0; i < tag.length; i++) if (buf[start + i] !== tag[i]) return false
  return true
}

function readVarUint(buf: Uint8Array, start: number): { value: number; posAfter: number } {
  let value = 0n
  let shift = 0n
  let pos = start
  for (let i = 0; i < 9; i++) {
    if (pos >= buf.length) throw new Error('readVarUint: unexpected EOF')
    const b = buf[pos++]!
    value |= BigInt(b & 0x7f) << shift
    if ((b & 0x80) === 0) {
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('readVarUint: exceeds MAX_SAFE_INTEGER')
      return { value: Number(value), posAfter: pos }
    }
    shift += 7n
    if (shift >= 63n) throw new Error('readVarUint: too large')
  }
  throw new Error('readVarUint: missing terminator')
}
