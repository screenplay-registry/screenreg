/**
 * Clean-room TypeScript implementation of the OpenTimestamps `.ots` proof format.
 * Parses the wire format, walks the timestamp tree, and extracts attestations.
 *
 * Verification scope in v1:
 *  - Parse the .ots binary cleanly (no Python dependency)
 *  - Walk all ops and recompute internal hashes from the file_digest
 *  - Extract all attestations (Bitcoin block heights, pending calendar URLs, unknown)
 *  - Confirm structural integrity (every op chain leads to at least one attestation)
 *
 * Verification not done in v1:
 *  - Does the Bitcoin block at height N actually contain the merkle root we computed?
 *    (That requires Bitcoin headers; the CLI can fetch them, the web verifier can
 *    query a public block-explorer API per the hybrid trust model.)
 *
 * Reference: opentimestamps.org spec + opentimestamps-client/python source.
 */

import { createHash } from 'node:crypto'

// ---------------------------------------------------------------------------
// Wire format constants
// ---------------------------------------------------------------------------

export const HEADER_MAGIC = Buffer.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
])
export const MAJOR_VERSION = 1

// Crypto op codes (single-byte tags from OpSHA256.TAG, etc.)
export const OP_SHA1 = 0x02
export const OP_RIPEMD160 = 0x03
export const OP_SHA256 = 0x08
export const OP_KECCAK256 = 0x67

// Binary ops
export const OP_APPEND = 0xf0
export const OP_PREPEND = 0xf1

// Branch / attestation markers
export const FORK_MARKER = 0xff
export const ATTESTATION_MARKER = 0x00

// Attestation type tags (8 bytes each)
export const TAG_BITCOIN_BLOCK_HEADER = Buffer.from([
  0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
])
export const TAG_LITECOIN_BLOCK_HEADER = Buffer.from([
  0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45,
])
export const TAG_PENDING = Buffer.from([
  0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
])

// Map crypto op tags → digest length
const CRYPTO_OP_DIGEST_LEN: Record<number, number> = {
  [OP_SHA1]: 20,
  [OP_RIPEMD160]: 20,
  [OP_SHA256]: 32,
  [OP_KECCAK256]: 32,
}

const CRYPTO_OP_NAME: Record<number, string> = {
  [OP_SHA1]: 'sha1',
  [OP_RIPEMD160]: 'ripemd160',
  [OP_SHA256]: 'sha256',
  [OP_KECCAK256]: 'keccak256',
}

// ---------------------------------------------------------------------------
// Reader (byte stream with position)
// ---------------------------------------------------------------------------

class Reader {
  pos = 0
  constructor(public buf: Buffer) {}
  readByte(): number {
    if (this.pos >= this.buf.length) throw new Error(`unexpected EOF at offset ${this.pos}`)
    return this.buf[this.pos++]!
  }
  readBytes(n: number): Buffer {
    if (this.pos + n > this.buf.length) {
      throw new Error(`unexpected EOF reading ${n} bytes at offset ${this.pos}`)
    }
    const out = this.buf.subarray(this.pos, this.pos + n)
    this.pos += n
    return out
  }
  /**
   * VarUInt encoding per OTS (Bitcoin-style varint): up to 9 bytes, low 7 bits
   * + continuation bit. Returns a JS number.
   *
   * SECURITY: uses BigInt internally because `result |= (b & 0x7f) << shift`
   * with plain numbers truncates to 32 bits in JavaScript (the `<<` and `|`
   * operators coerce both operands to Int32) — for varuints beyond ~4 bytes
   * the result would silently wrap. A subsequent readVarBytes(len) call could
   * under-allocate and the parser would read past the field boundary into the
   * next op.
   *
   * Caps result at Number.MAX_SAFE_INTEGER. A varuint that decodes larger is
   * rejected — no legitimate OTS field needs a length that big, and accepting
   * one would round-trip through a precision-losing number conversion.
   */
  readVarUint(): number {
    let result = 0n
    let shift = 0n
    for (let i = 0; i < 9; i++) {
      const b = this.readByte()
      result |= BigInt(b & 0x7f) << shift
      if ((b & 0x80) === 0) {
        if (result > BigInt(Number.MAX_SAFE_INTEGER)) {
          throw new Error(`varuint too large for safe JS number: ${result}`)
        }
        return Number(result)
      }
      shift += 7n
      if (shift >= 63n) throw new Error('varuint too large')
    }
    throw new Error('varuint missing terminator')
  }
  readVarBytes(): Buffer {
    const len = this.readVarUint()
    // SECURITY: cap declared length to remaining bytes. A malicious .ots could
    // claim a huge length to force a giant Buffer allocation OR read past EOF
    // and trigger an out-of-bounds throw with attacker-controlled offsets.
    if (len > this.remaining()) {
      throw new Error(
        `readVarBytes: declared length ${len} exceeds remaining ${this.remaining()} bytes`,
      )
    }
    return this.readBytes(len)
  }
  expectMagic(magic: Buffer): void {
    const got = this.readBytes(magic.length)
    if (!got.equals(magic)) {
      throw new Error(`magic mismatch: expected ${magic.toString('hex')}, got ${got.toString('hex')}`)
    }
  }
  remaining(): number {
    return this.buf.length - this.pos
  }
  eof(): boolean {
    return this.pos >= this.buf.length
  }
}

// ---------------------------------------------------------------------------
// Parsed result types
// ---------------------------------------------------------------------------

export type ParsedAttestation =
  | { kind: 'bitcoin'; blockHeight: number }
  | { kind: 'litecoin'; blockHeight: number }
  | { kind: 'pending'; calendarUrl: string }
  | { kind: 'unknown'; tag: string; payloadHex: string }

export interface ParsedProof {
  /** The file_hash_op tag (0x08 for SHA-256). */
  fileHashOp: 'sha1' | 'ripemd160' | 'sha256' | 'keccak256'
  /** The digest of the timestamped file/digest (hex). */
  fileDigestHex: string
  /** All attestations found across the timestamp tree. */
  attestations: ParsedAttestation[]
}

export type VerifyOtsResult =
  | { ok: true; parsed: ParsedProof }
  | { ok: false; reason: string; pos?: number }

// ---------------------------------------------------------------------------
// Top-level parser
// ---------------------------------------------------------------------------

export function parseOts(otsBytes: Buffer): VerifyOtsResult {
  // SECURITY: cap the input file size to bound parser memory + CPU. An attacker
  // submitting a multi-GB .ots file would otherwise force Node to load the
  // whole thing into a Buffer before we even start parsing. 8 MiB is generous
  // for legitimate OTS proofs (typical Bitcoin-anchored proofs are <10 KB; even
  // pathological multi-calendar proofs are well under 1 MB).
  const MAX_OTS_BYTES = 8 * 1024 * 1024
  if (otsBytes.length > MAX_OTS_BYTES) {
    return {
      ok: false,
      reason: `.ots file too large: ${otsBytes.length} bytes (max ${MAX_OTS_BYTES})`,
      pos: 0,
    }
  }
  const r = new Reader(otsBytes)
  try {
    r.expectMagic(HEADER_MAGIC)
    const major = r.readVarUint()
    if (major !== MAJOR_VERSION) {
      return { ok: false, reason: `unsupported major version ${major}`, pos: r.pos }
    }
    const opTag = r.readByte()
    const digestLen = CRYPTO_OP_DIGEST_LEN[opTag]
    if (digestLen === undefined) {
      return { ok: false, reason: `unknown file_hash_op tag 0x${opTag.toString(16)}`, pos: r.pos }
    }
    const fileDigest = r.readBytes(digestLen)
    const attestations: ParsedAttestation[] = []
    walkTimestamp(r, fileDigest, attestations, 0)
    if (!r.eof()) {
      return { ok: false, reason: `trailing bytes after timestamp tree (${r.remaining()} bytes left)`, pos: r.pos }
    }
    return {
      ok: true,
      parsed: {
        fileHashOp: CRYPTO_OP_NAME[opTag] as ParsedProof['fileHashOp'],
        fileDigestHex: fileDigest.toString('hex'),
        attestations,
      },
    }
  } catch (e: any) {
    return { ok: false, reason: e?.message ?? String(e), pos: r.pos }
  }
}

/**
 * Maximum nesting depth for fork-recursion in walkTimestamp. Legitimate OTS
 * proofs have a handful of forks (one per active calendar); deep recursion is
 * an adversarial pattern. 128 is well above legitimate usage and well below
 * Node's default stack limit (~10k frames before RangeError).
 */
const MAX_TIMESTAMP_FORK_DEPTH = 128

/**
 * Walk a Timestamp tree starting from the given message bytes.
 * The Timestamp format is:
 *   ([0xff <Timestamp>] zero or more times)
 *   then either one final {<op> <Timestamp>} OR one or more {0x00 <attestation>}.
 *
 * Crypto ops (SHA1/SHA256/...) consume the message and produce a new message (the hash);
 * binary ops (APPEND/PREPEND) take a varbytes argument and concat;
 * attestations terminate a branch.
 */
function walkTimestamp(
  r: Reader,
  msg: Buffer,
  attestations: ParsedAttestation[],
  depth: number,
): void {
  if (depth > MAX_TIMESTAMP_FORK_DEPTH) {
    throw new Error(
      `OTS timestamp tree exceeds maximum fork depth ${MAX_TIMESTAMP_FORK_DEPTH}; possible malicious nesting`,
    )
  }
  while (true) {
    const tag = r.readByte()
    if (tag === FORK_MARKER) {
      // Fork: process a sub-timestamp branch with the SAME msg, then continue.
      // Depth grows for each fork; the cap above stops stack-exhaustion DoS.
      walkTimestamp(r, msg, attestations, depth + 1)
      continue
    }
    if (tag === ATTESTATION_MARKER) {
      // Read attestation type tag (8 bytes) and length-prefixed payload
      const attTag = r.readBytes(8)
      const payload = r.readVarBytes()
      attestations.push(parseAttestation(attTag, payload))
      return
    }
    // Otherwise this is an op tag
    msg = applyOp(tag, r, msg)
    // After applying the op, continue walking with the new msg
  }
}

function applyOp(opTag: number, r: Reader, msg: Buffer): Buffer {
  switch (opTag) {
    case OP_SHA256:
      return createHash('sha256').update(msg).digest()
    case OP_SHA1:
      return createHash('sha1').update(msg).digest()
    case OP_RIPEMD160:
      return createHash('ripemd160').update(msg).digest()
    case OP_KECCAK256:
      // Node doesn't have a native keccak256; this op is rare in OTS practice
      throw new Error('OP_KECCAK256 not implemented in v1')
    case OP_APPEND: {
      const arg = r.readVarBytes()
      return Buffer.concat([msg, arg])
    }
    case OP_PREPEND: {
      const arg = r.readVarBytes()
      return Buffer.concat([arg, msg])
    }
    default:
      throw new Error(`unknown op tag 0x${opTag.toString(16)}`)
  }
}

function parseAttestation(tag: Buffer, payload: Buffer): ParsedAttestation {
  if (tag.equals(TAG_BITCOIN_BLOCK_HEADER)) {
    const r = new Reader(payload)
    const blockHeight = r.readVarUint()
    return { kind: 'bitcoin', blockHeight }
  }
  if (tag.equals(TAG_LITECOIN_BLOCK_HEADER)) {
    const r = new Reader(payload)
    const blockHeight = r.readVarUint()
    return { kind: 'litecoin', blockHeight }
  }
  if (tag.equals(TAG_PENDING)) {
    const r = new Reader(payload)
    const urlBytes = r.readVarBytes()
    return { kind: 'pending', calendarUrl: urlBytes.toString('utf8') }
  }
  return { kind: 'unknown', tag: tag.toString('hex'), payloadHex: payload.toString('hex') }
}

// ---------------------------------------------------------------------------
// Public verification helpers
// ---------------------------------------------------------------------------

export interface VerifyOtsAgainstClaimHashInput {
  otsBytes: Buffer
  /** The committed claimHash this proof SHOULD anchor (Buffer, 32 bytes). */
  expectedFileDigest: Buffer
}

export type VerifyOtsAgainstClaimHashResult =
  | {
      ok: true
      parsed: ParsedProof
      /** True if at least one attestation is a confirmed Bitcoin attestation. */
      bitcoinAnchored: boolean
      bitcoinBlockHeights: number[]
      pendingCalendarUrls: string[]
    }
  | { ok: false; reason: string }

/**
 * Verify that an .ots proof asserts the given file digest.
 * Does NOT verify the Bitcoin block header itself (that requires external data).
 */
export function verifyOtsAgainstFileDigest(input: VerifyOtsAgainstClaimHashInput): VerifyOtsAgainstClaimHashResult {
  const parsed = parseOts(input.otsBytes)
  if (!parsed.ok) {
    return { ok: false, reason: `failed to parse .ots: ${parsed.reason}` }
  }
  if (parsed.parsed.fileHashOp !== 'sha256') {
    return {
      ok: false,
      reason: `expected file_hash_op = sha256, got ${parsed.parsed.fileHashOp}`,
    }
  }
  const expectedHex = input.expectedFileDigest.toString('hex')
  if (parsed.parsed.fileDigestHex !== expectedHex) {
    return {
      ok: false,
      reason: `file digest in .ots (${parsed.parsed.fileDigestHex}) does not match expected (${expectedHex})`,
    }
  }
  const bitcoinHeights: number[] = []
  const pendingUrls: string[] = []
  for (const att of parsed.parsed.attestations) {
    if (att.kind === 'bitcoin') bitcoinHeights.push(att.blockHeight)
    else if (att.kind === 'pending') pendingUrls.push(att.calendarUrl)
  }
  return {
    ok: true,
    parsed: parsed.parsed,
    bitcoinAnchored: bitcoinHeights.length > 0,
    bitcoinBlockHeights: bitcoinHeights,
    pendingCalendarUrls: pendingUrls,
  }
}
