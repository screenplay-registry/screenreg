/**
 * Clean-room TypeScript builder for the OpenTimestamps `.ots` proof binary format.
 *
 * Counterpart to src/anchors/ots-verify.ts (the parser). Given a 32-byte SHA-256
 * digest and one or more calendar response payloads (the byte body returned by an
 * OTS calendar's `/digest` POST endpoint, which is itself a serialized Timestamp
 * sub-tree), assembles a valid `.ots` wire format that the parser accepts.
 *
 * Encoding shape produced (one of several valid OTS encodings):
 *
 *   HEADER_MAGIC                       (31 bytes — fixed)
 *   varuint(MAJOR_VERSION = 1)         (1 byte: 0x01)
 *   file_hash_op_tag (OP_SHA256 = 0x08)(1 byte)
 *   file_digest                        (32 bytes — the SHA-256 of the claim)
 *   timestamp_tree (flat top-level fork shape):
 *     for each calendar response except the last:
 *       FORK_MARKER (0xff)
 *       <calendar response bytes>      (the serialized sub-timestamp from that calendar)
 *     <last calendar response bytes>   (the terminal branch, no fork prefix)
 *
 * NOT a canonical AST normalizer. The OpenTimestamps spec permits multiple valid
 * byte encodings of the same logical Timestamp tree (the Python reference
 * serializer merges common op prefixes across branches; this builder uses the
 * simpler flat-top-level-fork form). Both encodings round-trip through `ots
 * upgrade` and `ots verify` to the same Bitcoin attestation; bytes may differ.
 *
 * Pure logic: no crypto, no network, no I/O. Browser-portable; uses only
 * Uint8Array.
 *
 * Symmetry guarantee: `buildOtsBytes(splitOtsForRoundTrip(b)) === b` for any
 * `b` produced by `buildOtsBytes` (BYTE-REBUILD-IDENTITY). The slice COUNT
 * returned by the splitter is not guaranteed to equal the caller's original
 * input count — when a calendar response starts with `0xff` the flat-fork
 * encoding is genuinely ambiguous between "top-level fork separator" and
 * "calendar-internal leading nested-fork marker"; the splitter conservatively
 * treats leading `0xff` as a separator, so a single fork-leading calendar
 * input splits into multiple slices that still rebuild to the original bytes.
 * See the splitter's JSDoc for the full contract.
 *
 * NOT a general `.ots` decoder — proofs produced by other serializers may
 * have a different tree shape and will not round-trip cleanly (use
 * `parseOts` for those).
 */

// Wire-format constants (duplicated from src/anchors/ots-verify.ts to keep the
// shared module free of Node-side imports; values are spec-locked).
const HEADER_MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
])
const MAJOR_VERSION = 1
const OP_SHA256 = 0x08
const FORK_MARKER = 0xff

/**
 * Encode a non-negative integer as a Bitcoin-style varuint (low 7 bits +
 * continuation bit per byte). Inverse of Reader.readVarUint in ots-verify.ts.
 *
 * Caps input at Number.MAX_SAFE_INTEGER for cross-runtime determinism; values
 * beyond that range cannot be represented faithfully as JS numbers and would
 * round through a precision-losing path.
 */
export function encodeVarUint(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`encodeVarUint: expected non-negative integer, got ${value}`)
  }
  if (value > Number.MAX_SAFE_INTEGER) {
    throw new Error(`encodeVarUint: value ${value} exceeds Number.MAX_SAFE_INTEGER`)
  }
  if (value === 0) return new Uint8Array([0])
  const bytes: number[] = []
  let v = BigInt(value)
  while (v > 0n) {
    let byte = Number(v & 0x7fn)
    v >>= 7n
    if (v > 0n) byte |= 0x80
    bytes.push(byte)
  }
  return new Uint8Array(bytes)
}

/**
 * Validate that `bytes` is a well-formed OpenTimestamps Timestamp sub-tree —
 * the kind of payload an OTS calendar's `/digest` endpoint returns.
 *
 * A well-formed sub-tree:
 *   - Walks to completion via the same state machine the parser uses (forks
 *     recurse, crypto ops continue, APPEND/PREPEND consume their varbytes
 *     argument).
 *   - Terminates EVERY branch at an attestation marker (0x00 + 8-byte tag +
 *     varbytes payload). A walk that runs out of bytes without hitting an
 *     attestation is malformed even if the bytes parsed up to that point are
 *     individually valid.
 *   - Uses only ATTESTATION_TAG_ALLOWLIST values for attestation type tags.
 *     Unknown 8-byte tags suggest an attacker-crafted payload or a calendar
 *     misconfiguration; either way the consumer cannot use the proof so the
 *     gate rejects.
 *   - Has no trailing bytes past the terminal attestation.
 *
 * Callers (e.g. the browser /create/ page) use this to reject calendar
 * responses that look like HTML, redirects, or attacker-crafted noise BEFORE
 * counting the response toward the success-quorum threshold.
 */
export function isValidTimestampSubtree(bytes: Uint8Array): boolean {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return false
  try {
    // OTS calendars receive a SHA-256 digest (32 bytes) and return a sub-tree
    // whose root message is that digest. Track message-length through the
    // walker so OP_APPEND/PREPEND/HEXLIFY/crypto ops can be validated against
    // the upstream `Op.MAX_RESULT_LENGTH = 4096` cap — preventing the browser
    // from minting proofs the CLI verifier later rejects.
    const result = walkOneTimestampStrict(bytes, 0, 0, SHA256_DIGEST_LENGTH)
    return result.posAfter === bytes.length && result.attestationCount > 0
  } catch {
    return false
  }
}

const SHA256_DIGEST_LENGTH = 32
const SHA1_DIGEST_LENGTH = 20
const RIPEMD160_DIGEST_LENGTH = 20
const KECCAK256_DIGEST_LENGTH = 32

/**
 * Upstream Op.MAX_RESULT_LENGTH: the result of any op applied to the current
 * message must not exceed this cap. Combined with MAX_BINARY_OP_ARG_LENGTH
 * (per-arg cap), this means OP_APPEND of any arg whose combined result with
 * the current message would exceed 4096 bytes is rejected — e.g. a 4065-byte
 * arg applied to a 32-byte SHA-256-rooted message produces a 4097-byte
 * result and is rejected; the boundary accepted-case is a 4064-byte arg
 * producing a 4096-byte result.
 */
const MAX_OP_RESULT_LENGTH = 4096

/**
 * Pending-attestation URI structural rules mirror the upstream OpenTimestamps
 * PendingAttestation validator: max 1000 bytes, and a strict ASCII character
 * set deliberately excluding query/fragment/parameter chars (`?`, `&`, `=`,
 * `%`, `#`, space, etc.). The browser's strict validator MUST match the
 * upstream CLI rules — otherwise the page would mint proofs that
 * `ots upgrade` / `ots verify` later reject.
 *
 * ALLOWED_URI_CHARS source — opentimestamps/core/notary.py PendingAttestation:
 *   ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:
 */
const MAX_PENDING_URI_LENGTH = 1000
const HTTP_PREFIX = [0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f] // "http://"
const HTTPS_PREFIX = [0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f] // "https://"
const PENDING_URI_ALLOWED: Set<number> = (() => {
  const s = new Set<number>()
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  const lower = 'abcdefghijklmnopqrstuvwxyz'
  const digits = '0123456789'
  const punct = '-._/:'
  for (const ch of upper + lower + digits + punct) s.add(ch.charCodeAt(0))
  return s
})()

/** Known attestation type tags. Unknown tags are rejected by the strict validator. */
const ATTESTATION_TAG_ALLOWLIST: Uint8Array[] = [
  // Bitcoin block header
  new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]),
  // Litecoin block header
  new Uint8Array([0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45]),
  // Pending (calendar URL)
  new Uint8Array([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]),
]

/**
 * Per-tag payload structural validators. Allowlist outer-shape is not enough:
 * a Pending tag with payload length 0 (no URL) or a Bitcoin tag with payload
 * length 0 (no block height) outwardly parses but produces an unusable proof
 * that the canonical parser then rejects. The strict walker validates each
 * payload's INTERNAL shape against the tag's known structure.
 *
 *   Pending  payload = varbytes(url). URL must be non-empty and start with
 *            "http://" or "https://" — the only shape the CLI verifier knows
 *            how to follow when upgrading a pending proof.
 *   Bitcoin  payload = varuint(blockHeight). blockHeight must be >= 1.
 *   Litecoin payload = varuint(blockHeight). blockHeight must be >= 1.
 */
function validateAttestationPayload(
  buf: Uint8Array,
  tagStart: number,
  payloadStart: number,
  payloadLen: number,
): void {
  // Pending tag
  if (tagMatches(buf, tagStart, ATTESTATION_TAG_ALLOWLIST[2]!)) {
    if (payloadLen === 0) {
      throw new Error('validateAttestationPayload: pending payload is empty')
    }
    const urlLenInfo = readVarUintAt(buf, payloadStart)
    const urlEnd = urlLenInfo.posAfter + urlLenInfo.value
    if (urlEnd !== payloadStart + payloadLen) {
      throw new Error(
        `validateAttestationPayload: pending payload trailing bytes (declared ${payloadLen}, varbytes consumed ${urlEnd - payloadStart})`,
      )
    }
    if (urlLenInfo.value === 0) {
      throw new Error('validateAttestationPayload: pending URL is empty')
    }
    if (urlLenInfo.value > MAX_PENDING_URI_LENGTH) {
      throw new Error(
        `validateAttestationPayload: pending URL exceeds ${MAX_PENDING_URI_LENGTH} bytes`,
      )
    }
    const urlBase = urlLenInfo.posAfter
    // Per the upstream OTS spec, pending URIs use a deliberately restricted
    // character set — no query/fragment/parameter characters. The CLI verifier
    // rejects any URL outside this set when upgrading the proof, so the
    // browser MUST refuse to mint a proof the verifier will reject.
    const startsWithHttps = HTTPS_PREFIX.every((b, i) => buf[urlBase + i] === b)
    const startsWithHttp = HTTP_PREFIX.every((b, i) => buf[urlBase + i] === b)
    if (!startsWithHttps && !startsWithHttp) {
      throw new Error('validateAttestationPayload: pending URL does not start with http:// or https://')
    }
    for (let i = 0; i < urlLenInfo.value; i++) {
      if (!PENDING_URI_ALLOWED.has(buf[urlBase + i]!)) {
        throw new Error(
          `validateAttestationPayload: pending URL contains invalid byte 0x${buf[urlBase + i]!.toString(16).padStart(2, '0')} at offset ${i}`,
        )
      }
    }
    return
  }
  // Bitcoin or Litecoin tag: payload must be exactly one varuint blockHeight >= 1
  const isBitcoin = tagMatches(buf, tagStart, ATTESTATION_TAG_ALLOWLIST[0]!)
  const isLitecoin = tagMatches(buf, tagStart, ATTESTATION_TAG_ALLOWLIST[1]!)
  if (isBitcoin || isLitecoin) {
    if (payloadLen === 0) {
      throw new Error('validateAttestationPayload: block-header payload is empty')
    }
    const heightInfo = readVarUintAt(buf, payloadStart)
    if (heightInfo.posAfter !== payloadStart + payloadLen) {
      throw new Error('validateAttestationPayload: block-header payload has trailing bytes')
    }
    if (heightInfo.value < 1) {
      throw new Error('validateAttestationPayload: block height < 1')
    }
    return
  }
  // Should not reach: allowlist gate runs before this function.
  throw new Error('validateAttestationPayload: tag not in allowlist (internal)')
}

function tagMatches(buf: Uint8Array, start: number, tag: Uint8Array): boolean {
  for (let i = 0; i < tag.length; i++) {
    if (buf[start + i] !== tag[i]) return false
  }
  return true
}

function isAllowlistedAttestationTag(buf: Uint8Array, start: number): boolean {
  for (const tag of ATTESTATION_TAG_ALLOWLIST) {
    if (tagMatches(buf, start, tag)) return true
  }
  return false
}

/**
 * Strict walker used by isValidTimestampSubtree. Returns posAfter (the offset
 * just past the terminal attestation) PLUS the count of attestation markers
 * the walk encountered. Throws on any structural defect including
 * end-of-buffer without an attestation, unknown attestation tag, or unknown
 * op tag.
 */
function walkOneTimestampStrict(
  buf: Uint8Array,
  start: number,
  depth: number,
  initialMsgLen: number,
): { posAfter: number; attestationCount: number } {
  if (depth > MAX_TIMESTAMP_FORK_DEPTH) {
    throw new Error(`walkOneTimestampStrict: exceeds max fork depth ${MAX_TIMESTAMP_FORK_DEPTH}`)
  }
  let pos = start
  let attestationCount = 0
  let msgLen = initialMsgLen
  while (pos < buf.length) {
    const tag = buf[pos]!
    if (tag === FORK_MARKER) {
      // Sub-branch starts with the SAME msg as the parent, so pass current msgLen.
      const sub = walkOneTimestampStrict(buf, pos + 1, depth + 1, msgLen)
      pos = sub.posAfter
      attestationCount += sub.attestationCount
      continue
    }
    if (tag === 0x00) {
      if (pos + 1 + 8 > buf.length) {
        throw new Error(`walkOneTimestampStrict: truncated attestation tag at offset ${pos}`)
      }
      if (!isAllowlistedAttestationTag(buf, pos + 1)) {
        throw new Error(`walkOneTimestampStrict: unknown attestation tag at offset ${pos + 1}`)
      }
      const tagStart = pos + 1
      pos += 1 + 8
      const lenInfo = readVarUintAt(buf, pos)
      const payloadStart = lenInfo.posAfter
      const payloadEnd = payloadStart + lenInfo.value
      if (payloadEnd > buf.length) {
        throw new Error(`walkOneTimestampStrict: attestation payload exceeds buffer (need ${payloadEnd} have ${buf.length})`)
      }
      validateAttestationPayload(buf, tagStart, payloadStart, lenInfo.value)
      return { posAfter: payloadEnd, attestationCount: attestationCount + 1 }
    }
    pos += 1
    // Crypto ops produce a fixed-length digest as the new message.
    if (tag === 0x02) {
      msgLen = SHA1_DIGEST_LENGTH
      continue
    }
    if (tag === 0x03) {
      msgLen = RIPEMD160_DIGEST_LENGTH
      continue
    }
    if (tag === 0x08) {
      msgLen = SHA256_DIGEST_LENGTH
      continue
    }
    if (tag === 0x67) {
      // OP_KECCAK256 — accepted upstream but unimplemented in this codebase's
      // verifier (`src/anchors/ots-verify.ts:applyOp`). Reject at the strict
      // gate so the browser never mints a proof whose verifier path would
      // throw `OP_KECCAK256 not implemented in v1`. If the verifier later
      // gains keccak support, lift this rejection in lockstep.
      throw new Error('walkOneTimestampStrict: OP_KECCAK256 not yet supported by the verifier')
    }
    // KECCAK256_DIGEST_LENGTH retained for symmetry if the rejection above is
    // ever lifted; unreferenced today.
    void KECCAK256_DIGEST_LENGTH
    if (tag === 0xf2) {
      // OP_REVERSE — message bytes reversed; length unchanged.
      // Result length is the same as input length; only the cap is interesting.
      if (msgLen > MAX_OP_RESULT_LENGTH) {
        throw new Error(`walkOneTimestampStrict: OP_REVERSE result exceeds ${MAX_OP_RESULT_LENGTH}`)
      }
      continue
    }
    if (tag === 0xf3) {
      // OP_HEXLIFY — result is 2*msg bytes (each byte becomes 2 ASCII chars).
      msgLen = msgLen * 2
      if (msgLen > MAX_OP_RESULT_LENGTH) {
        throw new Error(`walkOneTimestampStrict: OP_HEXLIFY result exceeds ${MAX_OP_RESULT_LENGTH}`)
      }
      continue
    }
    if (tag === 0xf0 || tag === 0xf1) {
      // OP_APPEND (0xf0) / OP_PREPEND (0xf1) — varbytes arg constrained to
      // 1..MAX_BINARY_OP_ARG_LENGTH bytes, AND msg + arg ≤ MAX_OP_RESULT_LENGTH.
      const lenInfo = readVarUintAt(buf, pos)
      if (lenInfo.value < 1) {
        throw new Error('walkOneTimestampStrict: OP_APPEND/PREPEND arg is empty')
      }
      if (lenInfo.value > MAX_BINARY_OP_ARG_LENGTH) {
        throw new Error(`walkOneTimestampStrict: OP_APPEND/PREPEND arg exceeds ${MAX_BINARY_OP_ARG_LENGTH} bytes`)
      }
      const argEnd = lenInfo.posAfter + lenInfo.value
      if (argEnd > buf.length) {
        throw new Error('walkOneTimestampStrict: op arg exceeds buffer')
      }
      const newMsgLen = msgLen + lenInfo.value
      if (newMsgLen > MAX_OP_RESULT_LENGTH) {
        throw new Error(
          `walkOneTimestampStrict: OP_APPEND/PREPEND result exceeds ${MAX_OP_RESULT_LENGTH} (msg=${msgLen}, arg=${lenInfo.value})`,
        )
      }
      msgLen = newMsgLen
      pos = argEnd
      continue
    }
    throw new Error(`walkOneTimestampStrict: unknown op tag 0x${tag.toString(16)} at offset ${pos - 1}`)
  }
  throw new Error('walkOneTimestampStrict: branch did not terminate at an attestation')
}

/**
 * Upstream OTS BinaryOp constraint: OP_APPEND / OP_PREPEND varbytes argument
 * must be in [1, 4096]. Paired with MAX_OP_RESULT_LENGTH enforced via
 * msg-length tracking in walkOneTimestampStrict.
 */
const MAX_BINARY_OP_ARG_LENGTH = 4096

export interface BuildOtsInput {
  /** 32-byte SHA-256 digest of the committed claim. */
  fileDigest: Uint8Array
  /**
   * One or more calendar response bodies. Each must be the raw bytes returned
   * by an OTS calendar's `/digest` POST — a serialized Timestamp sub-tree. The
   * builder concatenates them with fork markers; it does NOT validate the
   * contents (the parser does that on read-back).
   */
  calendarTimestamps: Uint8Array[]
}

/**
 * Assemble a complete `.ots` proof binary from a digest + N calendar response
 * payloads. Returns the byte sequence ready for download / disk write.
 */
export function buildOtsBytes(input: BuildOtsInput): Uint8Array {
  if (!(input.fileDigest instanceof Uint8Array)) {
    throw new Error('buildOtsBytes: fileDigest must be a Uint8Array')
  }
  if (input.fileDigest.length !== 32) {
    throw new Error(
      `buildOtsBytes: fileDigest must be 32 bytes (SHA-256), got ${input.fileDigest.length}`,
    )
  }
  if (!Array.isArray(input.calendarTimestamps) || input.calendarTimestamps.length === 0) {
    throw new Error('buildOtsBytes: at least one calendar timestamp required')
  }
  for (let i = 0; i < input.calendarTimestamps.length; i++) {
    const cal = input.calendarTimestamps[i]
    if (!(cal instanceof Uint8Array)) {
      throw new Error(`buildOtsBytes: calendarTimestamps[${i}] is not a Uint8Array`)
    }
    // Each calendar sub-tree MUST validate against the strict walker before
    // we mint a proof that embeds it. Skipping this lets a caller smuggle in
    // KECCAK ops, oversized op args, malformed pending URIs, etc. — all of
    // which the upstream CLI verifier would later reject. Match the walker's
    // gate at the build boundary so buildOtsBytes is conservative-by-construction.
    if (!isValidTimestampSubtree(cal)) {
      throw new Error(
        `buildOtsBytes: calendarTimestamps[${i}] is not a valid Timestamp sub-tree`,
      )
    }
  }

  const versionBytes = encodeVarUint(MAJOR_VERSION)
  const parts: Uint8Array[] = [
    HEADER_MAGIC,
    versionBytes,
    new Uint8Array([OP_SHA256]),
    input.fileDigest,
  ]

  // All calendar responses except the last get prefixed with the fork marker.
  // The final one is the "terminal" branch and is appended directly.
  for (let i = 0; i < input.calendarTimestamps.length - 1; i++) {
    parts.push(new Uint8Array([FORK_MARKER]))
    parts.push(input.calendarTimestamps[i]!)
  }
  parts.push(input.calendarTimestamps[input.calendarTimestamps.length - 1]!)

  return concatBytes(parts)
}

/**
 * Decompose an `.ots` previously produced by `buildOtsBytes` into its
 * (fileDigest, calendarTimestamps) components.
 *
 * BYTE-REBUILD-IDENTITY ONLY, NOT COUNT-IDENTITY: the flat-top-level-fork
 * encoding is fundamentally ambiguous when a calendar response itself starts
 * with `0xff` (FORK_MARKER). In that case the splitter cannot distinguish
 * "top-level fork separator" from "calendar-internal leading nested-fork
 * marker", so the returned `calendarTimestamps` array may contain more slices
 * than the original input. Feeding the returned slices back through
 * `buildOtsBytes` still produces byte-identical output to the original — both
 * encodings are valid sub-tree decompositions of the same parser-accepted
 * Timestamp tree — but the slice count is not guaranteed to match the
 * caller's original input count. The test corpus covers this case explicitly.
 *
 * NOT a general OTS decoder. Proofs serialized by other tools (e.g. the
 * Python reference implementation, which merges common op prefixes across
 * branches) have a different top-level tree shape and will return one
 * bundled calendar slice rather than N. Use `parseOts` from
 * src/anchors/ots-verify.ts when the goal is reading arbitrary `.ots` files.
 */
export interface SplitOtsResult {
  fileDigest: Uint8Array
  calendarTimestamps: Uint8Array[]
}

export function splitOtsForRoundTrip(otsBytes: Uint8Array): SplitOtsResult {
  for (let i = 0; i < HEADER_MAGIC.length; i++) {
    if (otsBytes[i] !== HEADER_MAGIC[i]) {
      throw new Error(`splitOtsForRoundTrip: header magic mismatch at byte ${i}`)
    }
  }
  let pos = HEADER_MAGIC.length

  const versionByte = otsBytes[pos]!
  if (versionByte !== MAJOR_VERSION) {
    throw new Error(`splitOtsForRoundTrip: unsupported major version ${versionByte}`)
  }
  pos += 1

  const opTag = otsBytes[pos]!
  if (opTag !== OP_SHA256) {
    throw new Error(`splitOtsForRoundTrip: expected OP_SHA256 (0x08), got 0x${opTag.toString(16)}`)
  }
  pos += 1

  const fileDigest = otsBytes.slice(pos, pos + 32)
  pos += 32

  // Walk each top-level branch using the STRICT walker so the splitter
  // enforces the same op caps + attestation rules as the build-side gate.
  // The split path is used by the round-trip test against builder output;
  // since buildOtsBytes now validates every input through the strict walker,
  // the strict walker accepting on the way back in is the only consistent
  // contract.
  const calendarTimestamps: Uint8Array[] = []
  while (pos < otsBytes.length) {
    if (otsBytes[pos] === FORK_MARKER) {
      const branchStart = pos + 1
      const result = walkOneTimestampStrict(otsBytes, branchStart, 0, SHA256_DIGEST_LENGTH)
      calendarTimestamps.push(otsBytes.slice(branchStart, result.posAfter))
      pos = result.posAfter
    } else {
      const result = walkOneTimestampStrict(otsBytes, pos, 0, SHA256_DIGEST_LENGTH)
      calendarTimestamps.push(otsBytes.slice(pos, result.posAfter))
      pos = result.posAfter
      break
    }
  }

  return { fileDigest, calendarTimestamps }
}

/**
 * Maximum nesting depth for fork-recursion. Mirrors the cap used by the
 * canonical parser; legitimate `.ots` proofs have a handful of forks (one per
 * active calendar). Deep recursion is an adversarial pattern.
 */
const MAX_TIMESTAMP_FORK_DEPTH = 128

// walkOneTimestamp (the loose position-only walker) has been removed.
// splitOtsForRoundTrip now uses walkOneTimestampStrict so the splitter
// enforces the same op caps, attestation allowlist, and OP_KECCAK256
// rejection as the build-side gate. A loose walker creates a class of
// gate-accepts-but-walker-disagrees bugs we should not carry.

function readVarUintAt(buf: Uint8Array, start: number): { value: number; posAfter: number } {
  let value = 0n
  let shift = 0n
  let pos = start
  for (let i = 0; i < 9; i++) {
    if (pos >= buf.length) throw new Error(`readVarUintAt: unexpected EOF at ${pos}`)
    const b = buf[pos++]!
    value |= BigInt(b & 0x7f) << shift
    if ((b & 0x80) === 0) {
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`readVarUintAt: varuint exceeds MAX_SAFE_INTEGER`)
      }
      return { value: Number(value), posAfter: pos }
    }
    shift += 7n
    if (shift >= 63n) throw new Error('readVarUintAt: varuint too large')
  }
  throw new Error('readVarUintAt: missing terminator')
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  let totalLength = 0
  for (const p of parts) totalLength += p.length
  const out = new Uint8Array(totalLength)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}
