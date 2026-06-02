/**
 * Encode / decode the resumable finalize handle.
 *
 * The handle is the serverless answer to "I closed the tab — how do I come back
 * and finish anchoring my proof?" Everything needed to re-check and upgrade a
 * pending proof is packed into a compact, URL-fragment-safe token. Put it after
 * the `#` in a link (`/create/#p=<token>`) and the browser never sends it to a
 * server, so the resume link works across a tab close — or another device — with
 * no account, no database, and no privacy give-up. The downloaded `.ots` file
 * remains the canonical artifact; the token is a convenience layer on top of it.
 *
 * Wire framing (then base64url, no padding):
 *
 *   byte 0            format version (HANDLE_VERSION)
 *   field × 4         each: uint32 big-endian length, then that many bytes
 *                       1. claimHash   (UTF-8, e.g. "sha256:abcd…")
 *                       2. title       (UTF-8, may be empty)
 *                       3. createdAt   (UTF-8 ISO-8601, may be empty)
 *                       4. ots         (raw pending-proof bytes)
 *
 * The framing is explicit and length-prefixed (not JSON) so the binary `.ots`
 * rides along without a second layer of base64, and so decoding is unambiguous.
 *
 * Pure and runtime-agnostic: `Uint8Array` + `TextEncoder`/`TextDecoder` only
 * (both are web standards present in browsers and Node). No clock is read here —
 * `createdAt` is whatever the caller supplied.
 */

import type { PendingHandleV1 } from './types.js'

const HANDLE_VERSION = 1

/**
 * Generous ceiling on the embedded proof size. A pending proof across a few
 * calendars is well under a kilobyte; this cap is far above any legitimate value
 * and exists only to refuse a hostile or corrupt token that would otherwise
 * decode into a huge allocation.
 */
const MAX_HANDLE_OTS_BYTES = 64 * 1024

/**
 * Hard cap on the encoded token length, checked BEFORE decoding so a hostile or
 * corrupt token cannot force a large allocation in `fromBase64Url`. Sized above
 * the largest legitimate token: a max-size proof plus the small text fields,
 * base64url-expanded (~4/3).
 */
const MAX_HANDLE_TOKEN_CHARS = 100_000

/** Per-field byte caps. A claim hash is ~71 chars; labels and timestamps are short. */
const MAX_CLAIMHASH_BYTES = 128
const MAX_TITLE_BYTES = 512
const MAX_CREATEDAT_BYTES = 64

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

/** Build the reverse lookup once: charCode → 6-bit value, or -1 if not a base64url char. */
const BASE64URL_REVERSE: Int16Array = (() => {
  const table = new Int16Array(128).fill(-1)
  for (let i = 0; i < BASE64URL_ALPHABET.length; i++) {
    table[BASE64URL_ALPHABET.charCodeAt(i)] = i
  }
  return table
})()

/** Encode bytes as unpadded base64url. `charAt` is used over `[]` so the index
 *  type stays `string` (never `string | undefined`) under strict indexing. */
function toBase64Url(bytes: Uint8Array): string {
  const A = BASE64URL_ALPHABET
  let out = ''
  let i = 0
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!
    out += A.charAt((n >> 18) & 63) + A.charAt((n >> 12) & 63) + A.charAt((n >> 6) & 63) + A.charAt(n & 63)
  }
  const rem = bytes.length - i
  if (rem === 1) {
    const n = bytes[i]! << 16
    out += A.charAt((n >> 18) & 63) + A.charAt((n >> 12) & 63)
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8)
    out += A.charAt((n >> 18) & 63) + A.charAt((n >> 12) & 63) + A.charAt((n >> 6) & 63)
  }
  return out
}

/** Decode unpadded base64url back to bytes. Throws on any non-alphabet character. */
function fromBase64Url(s: string): Uint8Array {
  const len = s.length
  // base64url chunks of 4 chars → 3 bytes; the final partial chunk of 2 → 1
  // byte, 3 → 2 bytes. A remainder of exactly 1 char is never valid.
  const full = Math.floor(len / 4)
  const rem = len - full * 4
  if (rem === 1) throw new Error('fromBase64Url: invalid length (dangling character)')
  const outLen = full * 3 + (rem === 0 ? 0 : rem - 1)
  const out = new Uint8Array(outLen)
  let oi = 0
  let si = 0
  const val = (ch: number): number => {
    const v = ch < 128 ? BASE64URL_REVERSE[ch]! : -1
    if (v < 0) throw new Error('fromBase64Url: invalid character')
    return v
  }
  for (let c = 0; c < full; c++) {
    const n = (val(s.charCodeAt(si++)) << 18) | (val(s.charCodeAt(si++)) << 12) | (val(s.charCodeAt(si++)) << 6) | val(s.charCodeAt(si++))
    out[oi++] = (n >> 16) & 0xff
    out[oi++] = (n >> 8) & 0xff
    out[oi++] = n & 0xff
  }
  if (rem === 2) {
    // 2 chars → 1 byte. The 2nd char carries 6 bits but only its top 2 are used;
    // the low 4 must be zero, or the token is non-canonical (malleable) and is rejected.
    const v0 = val(s.charCodeAt(si++))
    const v1 = val(s.charCodeAt(si++))
    if ((v1 & 0x0f) !== 0) throw new Error('fromBase64Url: non-canonical trailing bits')
    out[oi++] = (((v0 << 18) | (v1 << 12)) >> 16) & 0xff
  } else if (rem === 3) {
    // 3 chars → 2 bytes. The 3rd char's low 2 bits are unused and must be zero.
    const v0 = val(s.charCodeAt(si++))
    const v1 = val(s.charCodeAt(si++))
    const v2 = val(s.charCodeAt(si++))
    if ((v2 & 0x03) !== 0) throw new Error('fromBase64Url: non-canonical trailing bits')
    const n = (v0 << 18) | (v1 << 12) | (v2 << 6)
    out[oi++] = (n >> 16) & 0xff
    out[oi++] = (n >> 8) & 0xff
  }
  return out
}

function writeUint32BE(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`writeUint32BE: out of range: ${value}`)
  }
  return new Uint8Array([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff])
}

function readUint32BE(buf: Uint8Array, at: number): number {
  if (at + 4 > buf.length) throw new Error('readUint32BE: out of bounds')
  return ((buf[at]! << 24) | (buf[at + 1]! << 16) | (buf[at + 2]! << 8) | buf[at + 3]!) >>> 0
}

function concat(parts: Uint8Array[]): Uint8Array {
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

/**
 * Encode a pending handle into a URL-fragment-safe token.
 * Throws if the embedded proof is missing or larger than `MAX_HANDLE_OTS_BYTES`.
 */
export function encodePendingHandle(handle: PendingHandleV1): string {
  if (handle.v !== HANDLE_VERSION) {
    throw new Error(`encodePendingHandle: unsupported handle version ${handle.v}`)
  }
  if (!(handle.ots instanceof Uint8Array) || handle.ots.length === 0) {
    throw new Error('encodePendingHandle: ots must be a non-empty Uint8Array')
  }
  if (handle.ots.length > MAX_HANDLE_OTS_BYTES) {
    throw new Error(`encodePendingHandle: ots exceeds ${MAX_HANDLE_OTS_BYTES} bytes`)
  }
  const enc = new TextEncoder()
  const fields: Uint8Array[] = [
    enc.encode(handle.claimHash),
    enc.encode(handle.title ?? ''),
    enc.encode(handle.createdAt ?? ''),
    handle.ots,
  ]
  const parts: Uint8Array[] = [new Uint8Array([HANDLE_VERSION])]
  for (const f of fields) {
    parts.push(writeUint32BE(f.length))
    parts.push(f)
  }
  return toBase64Url(concat(parts))
}

/**
 * Decode a token produced by `encodePendingHandle`. Throws on a malformed token,
 * an unsupported version, an oversized proof, or trailing bytes. A caller
 * resuming from an untrusted URL should treat a throw as "no valid pending
 * handle here" and fall back to asking the user to re-drop their files.
 */
export function decodePendingHandle(token: string): PendingHandleV1 {
  // Bound the work before decoding: reject an over-long token up front so a
  // hostile value cannot force a large base64url allocation.
  if (token.length > MAX_HANDLE_TOKEN_CHARS) {
    throw new Error(`decodePendingHandle: token exceeds ${MAX_HANDLE_TOKEN_CHARS} characters`)
  }
  const buf = fromBase64Url(token)
  if (buf.length < 1) throw new Error('decodePendingHandle: empty token')
  const version = buf[0]!
  if (version !== HANDLE_VERSION) {
    throw new Error(`decodePendingHandle: unsupported handle version ${version}`)
  }
  let pos = 1
  const readField = (maxLen: number): Uint8Array => {
    const len = readUint32BE(buf, pos)
    pos += 4
    if (len > maxLen) throw new Error(`decodePendingHandle: field exceeds ${maxLen} bytes`)
    if (pos + len > buf.length) throw new Error('decodePendingHandle: field length exceeds token')
    const out = buf.subarray(pos, pos + len)
    pos += len
    return out
  }
  // Reject malformed UTF-8 rather than silently substituting replacement
  // characters, so a corrupt or hostile token fails closed.
  const dec = new TextDecoder('utf-8', { fatal: true })
  const claimHash = dec.decode(readField(MAX_CLAIMHASH_BYTES))
  const title = dec.decode(readField(MAX_TITLE_BYTES))
  const createdAt = dec.decode(readField(MAX_CREATEDAT_BYTES))
  const ots = readField(MAX_HANDLE_OTS_BYTES)
  if (pos !== buf.length) throw new Error('decodePendingHandle: trailing bytes after fields')
  if (claimHash.length === 0) throw new Error('decodePendingHandle: missing claimHash')
  if (ots.length === 0) throw new Error('decodePendingHandle: missing ots')
  if (ots.length > MAX_HANDLE_OTS_BYTES) {
    throw new Error(`decodePendingHandle: ots exceeds ${MAX_HANDLE_OTS_BYTES} bytes`)
  }
  const handle: PendingHandleV1 = {
    v: HANDLE_VERSION,
    claimHash,
    // Copy out of the decoded buffer so the returned proof owns its memory.
    ots: ots.slice(),
  }
  if (title.length > 0) handle.title = title
  if (createdAt.length > 0) handle.createdAt = createdAt
  return handle
}
