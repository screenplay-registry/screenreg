/**
 * Minimal, deterministic, store-only ZIP reader/writer — cross-runtime (Uint8Array only).
 *
 * The `.screenreg` container (Section 11) is a ZIP archive restricted to the STORE method
 * (no compression). Store-only is a deliberate constraint, not a limitation:
 *
 *   - Determinism: DEFLATE output differs across implementations (Node zlib vs. the browser
 *     CompressionStream), which would make the same inputs produce different container bytes.
 *     Store-only is byte-identical on every runtime, so a bundle is reproducible.
 *   - Inspectability: any `unzip`/Finder/Explorer opens it; entries are plain files.
 *   - Sufficiency: a screenplay as text is a few hundred KB; compression buys nothing here.
 *
 * The container is NOT commitment-bearing — no byte produced here is hashed into `claimHash` —
 * so this module is a single cross-runtime implementation rather than the dual Node/shared pair
 * the commitment modules carry. CRC-32 is the standard ZIP integrity checksum (IEEE polynomial);
 * it is not a cryptographic function and carries no security weight.
 */

// ---------------------------------------------------------------------------
// CRC-32 (IEEE 802.3, the polynomial ZIP mandates)
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    }
    table[n] = c >>> 0
  }
  return table
})()

export function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC_TABLE[(crc ^ bytes[i]!) & 0xff]! ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

const LOCAL_HEADER_SIG = 0x04034b50
const CENTRAL_HEADER_SIG = 0x02014b50
const EOCD_SIG = 0x06054b50
const VERSION_NEEDED = 20
const METHOD_STORE = 0
/** Fixed DOS date = 1980-01-01, time = 00:00. Canonical ZIP epoch; keeps output deterministic
 *  and avoids the invalid-date warnings some tools emit for an all-zero date field. */
const DOS_DATE = 0x0021
const DOS_TIME = 0x0000

export interface ZipEntry {
  /** Archive-relative path. ASCII expected; encoded as UTF-8. */
  name: string
  bytes: Uint8Array
}

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder('utf-8', { fatal: false })

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/**
 * Build a deterministic store-only ZIP from the given entries, IN THE ORDER PROVIDED.
 * The caller controls ordering (the container writes the descriptor first, README last).
 */
export function zipStore(entries: ZipEntry[]): Uint8Array {
  const localChunks: Uint8Array[] = []
  const centralChunks: Uint8Array[] = []
  let offset = 0

  for (const entry of entries) {
    const nameBytes = textEncoder.encode(entry.name)
    const crc = crc32(entry.bytes)
    const size = entry.bytes.length

    // Local file header (30 bytes + name) followed by the raw stored data.
    const local = new Uint8Array(30 + nameBytes.length)
    const lv = new DataView(local.buffer)
    lv.setUint32(0, LOCAL_HEADER_SIG, true)
    lv.setUint16(4, VERSION_NEEDED, true)
    lv.setUint16(6, 0, true) // general purpose bit flag
    lv.setUint16(8, METHOD_STORE, true)
    lv.setUint16(10, DOS_TIME, true)
    lv.setUint16(12, DOS_DATE, true)
    lv.setUint32(14, crc, true)
    lv.setUint32(18, size, true) // compressed size == uncompressed (store)
    lv.setUint32(22, size, true)
    lv.setUint16(26, nameBytes.length, true)
    lv.setUint16(28, 0, true) // extra field length
    local.set(nameBytes, 30)

    localChunks.push(local, entry.bytes)

    // Central directory header (46 bytes + name).
    const central = new Uint8Array(46 + nameBytes.length)
    const cv = new DataView(central.buffer)
    cv.setUint32(0, CENTRAL_HEADER_SIG, true)
    cv.setUint16(4, VERSION_NEEDED, true) // version made by (DOS host, v2.0)
    cv.setUint16(6, VERSION_NEEDED, true) // version needed
    cv.setUint16(8, 0, true) // flags
    cv.setUint16(10, METHOD_STORE, true)
    cv.setUint16(12, DOS_TIME, true)
    cv.setUint16(14, DOS_DATE, true)
    cv.setUint32(16, crc, true)
    cv.setUint32(20, size, true)
    cv.setUint32(24, size, true)
    cv.setUint16(28, nameBytes.length, true)
    cv.setUint16(30, 0, true) // extra field length
    cv.setUint16(32, 0, true) // comment length
    cv.setUint16(34, 0, true) // disk number start
    cv.setUint16(36, 0, true) // internal attributes
    cv.setUint32(38, 0, true) // external attributes
    cv.setUint32(42, offset, true) // local header offset
    central.set(nameBytes, 46)
    centralChunks.push(central)

    offset += local.length + entry.bytes.length
  }

  const centralSize = centralChunks.reduce((n, c) => n + c.length, 0)
  const centralOffset = offset

  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, EOCD_SIG, true)
  ev.setUint16(4, 0, true) // this disk number
  ev.setUint16(6, 0, true) // disk where central directory starts
  ev.setUint16(8, entries.length, true) // entries on this disk
  ev.setUint16(10, entries.length, true) // total entries
  ev.setUint32(12, centralSize, true)
  ev.setUint32(16, centralOffset, true)
  ev.setUint16(20, 0, true) // comment length

  return concat([...localChunks, ...centralChunks, eocd])
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

export class ZipError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ZipError'
  }
}

/**
 * Parse a store-only ZIP into its entries, preserving central-directory order. Verifies each
 * entry's CRC-32 (raises on mismatch — corruption). Rejects compressed entries: a v1 reader
 * only needs to read what the v1 writer produces (Section 11 §2).
 */
export function unzipStore(bytes: Uint8Array): ZipEntry[] {
  const eocdOffset = findEocd(bytes)
  if (eocdOffset < 0) throw new ZipError('not a ZIP archive: end-of-central-directory not found')

  const len = bytes.length
  // Every multi-byte read below is bounds-checked against `len` before it happens, so malformed
  // or hostile offsets/sizes raise a clean ZipError instead of an uncaught DataView RangeError.
  const need = (end: number, what: string): void => {
    if (end > len || end < 0) throw new ZipError(`truncated/invalid ZIP: ${what} runs past end`)
  }

  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const total = dv.getUint16(eocdOffset + 10, true)
  const centralSize = dv.getUint32(eocdOffset + 12, true)
  const centralOffset = dv.getUint32(eocdOffset + 16, true)
  // The central directory occupies exactly [centralOffset, centralEnd) and must lie wholly before
  // the EOCD that describes it. Every record below is bounded by centralEnd (the DECLARED extent),
  // not merely by the buffer end, and the records must tile that region exactly (checked after the
  // loop) — so crafted name/extra/comment lengths cannot smuggle a record into the gap between the
  // real directory and the EOCD, and a too-small centralSize cannot under-cover the records.
  const centralEnd = centralOffset + centralSize
  if (centralEnd > eocdOffset) {
    throw new ZipError('invalid ZIP: central directory overruns end-of-central-directory record')
  }
  const withinCentral = (end: number, what: string): void => {
    if (end > centralEnd || end < 0) {
      throw new ZipError(`invalid ZIP: ${what} exceeds the declared central directory extent`)
    }
  }

  const entries: ZipEntry[] = []
  let p = centralOffset
  for (let i = 0; i < total; i++) {
    withinCentral(p + 46, `central directory entry ${i} header`)
    if (dv.getUint32(p, true) !== CENTRAL_HEADER_SIG) {
      throw new ZipError(`central directory entry ${i}: bad signature`)
    }
    const method = dv.getUint16(p + 10, true)
    const crc = dv.getUint32(p + 16, true)
    const compSize = dv.getUint32(p + 20, true)
    const uncompSize = dv.getUint32(p + 24, true)
    const nameLen = dv.getUint16(p + 28, true)
    const extraLen = dv.getUint16(p + 30, true)
    const commentLen = dv.getUint16(p + 32, true)
    const localOffset = dv.getUint32(p + 42, true)
    // The whole variable-length record (fixed 46 + name + extra + comment) must fit within the
    // declared central directory, so the advance below cannot step past it on crafted lengths.
    withinCentral(p + 46 + nameLen + extraLen + commentLen, `central directory entry ${i} record`)
    const name = textDecoder.decode(bytes.subarray(p + 46, p + 46 + nameLen))

    if (method !== METHOD_STORE) {
      throw new ZipError(`entry "${name}": unsupported compression method ${method} (store only)`)
    }
    // Store method: the stored size and logical size are the same by definition. A mismatch is a
    // malformed (or deceptively constructed) archive.
    if (compSize !== uncompSize) {
      throw new ZipError(`entry "${name}": store method requires compressed size == uncompressed size`)
    }

    // Read the local header to locate the data (its name/extra lengths can differ from central).
    need(localOffset + 30, `entry "${name}" local header`)
    if (dv.getUint32(localOffset, true) !== LOCAL_HEADER_SIG) {
      throw new ZipError(`entry "${name}": bad local header signature`)
    }
    const localNameLen = dv.getUint16(localOffset + 26, true)
    const localExtraLen = dv.getUint16(localOffset + 28, true)
    const dataStart = localOffset + 30 + localNameLen + localExtraLen
    need(dataStart + compSize, `entry "${name}" data`)
    // Entry data lives in the local-header region, which precedes the central directory; data that
    // runs into the central directory is malformed or an overlap attack.
    if (dataStart + compSize > centralOffset) {
      throw new ZipError(`entry "${name}": data overruns into the central directory`)
    }
    const data = bytes.subarray(dataStart, dataStart + compSize)

    if (crc32(data) !== crc) {
      throw new ZipError(`entry "${name}": CRC-32 mismatch (archive corrupted)`)
    }

    entries.push({ name, bytes: data.slice() })
    p += 46 + nameLen + extraLen + commentLen
  }

  // The records must tile the declared central directory exactly: no slack at the end, and no
  // claim of more/fewer entries than the size accounts for. This rejects e.g. centralSize=0 with
  // records present, or trailing padding inside the directory region.
  if (p !== centralEnd) {
    throw new ZipError('invalid ZIP: central directory records do not fill the declared size')
  }

  return entries
}

function findEocd(bytes: Uint8Array): number {
  // The EOCD is the last record; with a zero-length comment (always, for our writer) it sits at
  // exactly length-22. Scan backward up to 64KB+22 anyway, to tolerate archives with comments.
  const minStart = Math.max(0, bytes.length - (0xffff + 22))
  for (let i = bytes.length - 22; i >= minStart; i--) {
    if (
      bytes[i] === 0x50 &&
      bytes[i + 1] === 0x4b &&
      bytes[i + 2] === 0x05 &&
      bytes[i + 3] === 0x06
    ) {
      return i
    }
  }
  return -1
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0)
  const out = new Uint8Array(total)
  let at = 0
  for (const c of chunks) {
    out.set(c, at)
    at += c.length
  }
  return out
}
