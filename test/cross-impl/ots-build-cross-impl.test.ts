/**
 * Parser-builder symmetry test for the OpenTimestamps `.ots` wire format.
 *
 * Two complementary strategies:
 *   1. Generated-input control: synthesize N calendar response payloads with
 *      known content, build via buildOtsBytes, parse with parseOts, assert
 *      every attestation is recovered with the expected URL — proves the
 *      builder produces parser-valid output and the encoding preserves all N
 *      branches.
 *   2. Round-trip on builder-produced bytes: build, split via
 *      splitOtsForRoundTrip, rebuild, assert byte-identical — proves the
 *      splitter is the inverse of the builder.
 *
 * The fixture-01-live proof is NOT round-trip-tested through the splitter
 * because it was produced by the upstream Python serializer which merges
 * common op prefixes across calendar branches; that tree shape is
 * intentionally not producible by this flat-fork builder. The live fixture is
 * exercised only via parseOts to confirm the canonical parser still accepts
 * the upstream encoding (a baseline correctness check, not a builder test).
 *
 * Tests:
 *   - varuint encoder/decoder symmetry across the safe-integer range
 *   - input validation (digest length, empty calendar list, non-Uint8Array)
 *   - fixed-byte structure (header magic, version, op tag, digest placement)
 *   - generated N=1, 2, 3, 4 calendar builds: byte structure + parse roundtrip
 *   - splitter inverse on generated builds with exact branch-count assertions
 *   - fixture-01-mock single-calendar round trip
 *   - fixture-01-live parses but is documented non-round-trippable
 *   - adversarial fork-depth cap (no stack exhaustion on pathological input)
 */

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  buildOtsBytes,
  encodeVarUint,
  isValidTimestampSubtree,
  splitOtsForRoundTrip,
} from '../../src/shared/anchors/ots-build.js'
import { parseOts, TAG_PENDING } from '../../src/anchors/ots-verify.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const OTS_DIR = join(__dirname, '..', '..', 'spec', 'v1', 'testvectors', 'ots')

// ---------------------------------------------------------------------------
// varuint encoder/decoder symmetry
// ---------------------------------------------------------------------------

describe('encodeVarUint: encoder/decoder symmetry', () => {
  const cases: number[] = [
    0,
    1,
    0x7f,
    0x80,
    0xff,
    0x100,
    0x3fff,
    0x4000,
    0xffff,
    0x10000,
    0x1fffff,
    0x200000,
    0xfffffff,
    Number.MAX_SAFE_INTEGER,
  ]

  for (const v of cases) {
    it(`encodes ${v} and the result decodes back via the parser convention`, () => {
      const encoded = encodeVarUint(v)
      let decoded = 0n
      let shift = 0n
      for (let i = 0; i < encoded.length; i++) {
        const b = encoded[i]!
        decoded |= BigInt(b & 0x7f) << shift
        if ((b & 0x80) === 0) break
        shift += 7n
      }
      expect(Number(decoded)).toBe(v)
      expect(encoded[encoded.length - 1]! & 0x80).toBe(0)
    })
  }

  it('rejects negative integers', () => {
    expect(() => encodeVarUint(-1)).toThrow(/non-negative/)
  })
  it('rejects non-integers', () => {
    expect(() => encodeVarUint(1.5)).toThrow(/non-negative/)
  })
  it('rejects values beyond Number.MAX_SAFE_INTEGER', () => {
    expect(() => encodeVarUint(Number.MAX_SAFE_INTEGER + 1)).toThrow(/MAX_SAFE/)
  })
})

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

describe('buildOtsBytes: input validation', () => {
  it('rejects digest of wrong length', () => {
    expect(() =>
      buildOtsBytes({
        fileDigest: new Uint8Array(31),
        calendarTimestamps: [new Uint8Array([0x00])],
      }),
    ).toThrow(/32 bytes/)
  })

  it('rejects empty calendar list', () => {
    expect(() =>
      buildOtsBytes({
        fileDigest: new Uint8Array(32),
        calendarTimestamps: [],
      }),
    ).toThrow(/at least one/)
  })

  it('rejects non-Uint8Array fileDigest', () => {
    expect(() =>
      buildOtsBytes({
        // @ts-expect-error — testing runtime guard
        fileDigest: new Array(32).fill(0),
        calendarTimestamps: [new Uint8Array([0x00])],
      }),
    ).toThrow(/Uint8Array/)
  })

  it('rejects non-Uint8Array calendar timestamp entry', () => {
    expect(() =>
      buildOtsBytes({
        fileDigest: new Uint8Array(32),
        // @ts-expect-error — testing runtime guard
        calendarTimestamps: [new Array(8).fill(0)],
      }),
    ).toThrow(/Uint8Array/)
  })
})

// ---------------------------------------------------------------------------
// Fixed-byte structure
// ---------------------------------------------------------------------------

/** Construct a minimal valid pending-attestation calendar response for URL. */
function pendingResponse(url: string): Uint8Array {
  const urlBytes = new TextEncoder().encode(url)
  // Inner: varuint(urlLen) + url
  const urlVarBytesLen = urlBytes.length < 0x80 ? 1 : 2
  const inner = new Uint8Array(urlVarBytesLen + urlBytes.length)
  if (urlBytes.length < 0x80) {
    inner[0] = urlBytes.length
    inner.set(urlBytes, 1)
  } else {
    inner[0] = (urlBytes.length & 0x7f) | 0x80
    inner[1] = urlBytes.length >> 7
    inner.set(urlBytes, 2)
  }
  // Outer: attestation marker + tag + varbytes(inner)
  const innerLen = inner.length
  const innerVarBytesLen = innerLen < 0x80 ? 1 : 2
  const out = new Uint8Array(1 + 8 + innerVarBytesLen + innerLen)
  out[0] = 0x00 // attestation marker
  out.set(TAG_PENDING, 1) // 8-byte type tag
  if (innerLen < 0x80) {
    out[9] = innerLen
    out.set(inner, 10)
  } else {
    out[9] = (innerLen & 0x7f) | 0x80
    out[10] = innerLen >> 7
    out.set(inner, 11)
  }
  return out
}

describe('buildOtsBytes: fixed-byte structure', () => {
  it('emits canonical header magic + version 1 + OP_SHA256 + digest placement', () => {
    const digest = new Uint8Array(32)
    for (let i = 0; i < 32; i++) digest[i] = i + 1
    const cal = pendingResponse('https://x/')
    const built = buildOtsBytes({ fileDigest: digest, calendarTimestamps: [cal] })

    const expectedMagic = [
      0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
      0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
    ]
    for (let i = 0; i < expectedMagic.length; i++) {
      expect(built[i]).toBe(expectedMagic[i])
    }
    expect(built[31]).toBe(0x01)
    expect(built[32]).toBe(0x08)
    for (let i = 0; i < 32; i++) {
      expect(built[33 + i]).toBe(digest[i])
    }
    for (let i = 0; i < cal.length; i++) {
      expect(built[65 + i]).toBe(cal[i])
    }
  })
})

// ---------------------------------------------------------------------------
// Generated multi-calendar builds — parser sees all N attestations
// ---------------------------------------------------------------------------

describe('buildOtsBytes: generated multi-calendar inputs', () => {
  const digest = new Uint8Array(32).fill(0xa5)

  for (const n of [1, 2, 3, 4, 8]) {
    it(`builds and parses ${n}-calendar input with all ${n} attestations recovered`, () => {
      const urls = Array.from({ length: n }, (_, i) => `https://cal${i + 1}.example/`)
      const calendars = urls.map(pendingResponse)
      const built = buildOtsBytes({ fileDigest: digest, calendarTimestamps: calendars })

      const parsed = parseOts(Buffer.from(built))
      expect(parsed.ok).toBe(true)
      if (!parsed.ok) return

      expect(parsed.parsed.fileHashOp).toBe('sha256')
      expect(parsed.parsed.attestations.length).toBe(n)
      const got = parsed.parsed.attestations
        .filter((a) => a.kind === 'pending')
        .map((a) => (a as { kind: 'pending'; calendarUrl: string }).calendarUrl)
      expect(got).toEqual(urls)
    })
  }

  it('encodes N-1 FORK_MARKER bytes between branches for N=4', () => {
    const calendars = Array.from({ length: 4 }, (_, i) => pendingResponse(`https://c${i}/`))
    const built = buildOtsBytes({ fileDigest: digest, calendarTimestamps: calendars })
    // Count 0xff bytes that appear ONLY at the fork-marker positions (between branches).
    // Easier: the count of FORK_MARKER bytes inside our built output equals the count
    // of inputs we fork-prefixed = (N-1) = 3, plus any 0xff bytes inside the calendar
    // payloads themselves (which our hand-built pending responses do not contain).
    let forkCount = 0
    for (let i = 65; i < built.length; i++) {
      if (built[i] === 0xff) forkCount++
    }
    expect(forkCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// splitOtsForRoundTrip is the inverse of buildOtsBytes on generated inputs
// ---------------------------------------------------------------------------

describe('splitOtsForRoundTrip: inverse of buildOtsBytes on generated inputs', () => {
  const digest = new Uint8Array(32)
  for (let i = 0; i < 32; i++) digest[i] = i

  for (const n of [1, 2, 3, 4, 8]) {
    it(`recovers exactly ${n} calendar slices from a built ${n}-calendar input`, () => {
      const calendars = Array.from({ length: n }, (_, i) => pendingResponse(`https://cal${i}.test/`))
      const built = buildOtsBytes({ fileDigest: digest, calendarTimestamps: calendars })

      const split = splitOtsForRoundTrip(built)
      expect(split.fileDigest.length).toBe(32)
      for (let i = 0; i < 32; i++) {
        expect(split.fileDigest[i]).toBe(digest[i])
      }
      expect(split.calendarTimestamps.length).toBe(n)
      for (let i = 0; i < n; i++) {
        expect(split.calendarTimestamps[i]!.length).toBe(calendars[i]!.length)
        for (let j = 0; j < calendars[i]!.length; j++) {
          expect(split.calendarTimestamps[i]![j]).toBe(calendars[i]![j])
        }
      }

      // Rebuild from the split components — must equal the original.
      const rebuilt = buildOtsBytes({
        fileDigest: split.fileDigest,
        calendarTimestamps: split.calendarTimestamps,
      })
      expect(rebuilt.length).toBe(built.length)
      for (let i = 0; i < built.length; i++) {
        expect(rebuilt[i]).toBe(built[i])
      }
    })
  }
})

// ---------------------------------------------------------------------------
// Adversarial: pathologically deep nesting must throw, not blow the stack
// ---------------------------------------------------------------------------

describe('splitOtsForRoundTrip: adversarial fork-depth cap', () => {
  it('rejects pathologically deep top-level fork nesting', () => {
    // Construct a header + valid digest + a chain of 200 FORK_MARKERS each
    // wrapping the next, terminated by a minimal attestation. The walk-one-timestamp
    // recursion depth-cap (128) must trip BEFORE stack exhaustion.
    const header = new Uint8Array([
      0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
      0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
    ])
    const versionByte = new Uint8Array([0x01])
    const opTagByte = new Uint8Array([0x08])
    const digest = new Uint8Array(32)
    const forks = new Uint8Array(200).fill(0xff)
    const term = new Uint8Array([
      0x00, // attestation marker
      0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e, // PENDING tag
      0x02, 0x01, 0x61, // varbytes(1, 'a')
    ])
    const parts = [header, versionByte, opTagByte, digest, forks, term]
    let totalLen = 0
    for (const p of parts) totalLen += p.length
    const buf = new Uint8Array(totalLen)
    let off = 0
    for (const p of parts) {
      buf.set(p, off)
      off += p.length
    }
    expect(() => splitOtsForRoundTrip(buf)).toThrow(/fork depth/)
  })
})

// ---------------------------------------------------------------------------
// fixture-01-mock: full round trip
// ---------------------------------------------------------------------------

describe('parser-builder symmetry: fixture-01-mock', () => {
  const otsBytes = readFileSync(join(OTS_DIR, 'fixture-01-mock.ots'))
  const u8 = new Uint8Array(otsBytes.buffer, otsBytes.byteOffset, otsBytes.byteLength)

  it('splits to exactly one calendar slice and rebuilds byte-identical', () => {
    const { fileDigest, calendarTimestamps } = splitOtsForRoundTrip(u8)
    expect(fileDigest.length).toBe(32)
    expect(calendarTimestamps.length).toBe(1)

    const rebuilt = buildOtsBytes({ fileDigest, calendarTimestamps })
    expect(rebuilt.length).toBe(u8.length)
    for (let i = 0; i < rebuilt.length; i++) {
      if (rebuilt[i] !== u8[i]) {
        throw new Error(
          `byte divergence at offset ${i}: rebuilt=0x${rebuilt[i]!.toString(16).padStart(2, '0')} original=0x${u8[i]!.toString(16).padStart(2, '0')}`,
        )
      }
    }
  })

  it('rebuilt bytes parse via the canonical parser with the expected attestation', () => {
    const { fileDigest, calendarTimestamps } = splitOtsForRoundTrip(u8)
    const rebuilt = buildOtsBytes({ fileDigest, calendarTimestamps })
    const parsed = parseOts(Buffer.from(rebuilt))
    expect(parsed.ok).toBe(true)
    if (parsed.ok) {
      expect(parsed.parsed.fileHashOp).toBe('sha256')
      expect(parsed.parsed.fileDigestHex).toBe(
        Array.from(fileDigest).map((b) => b.toString(16).padStart(2, '0')).join(''),
      )
      expect(parsed.parsed.attestations.length).toBe(1)
      expect(parsed.parsed.attestations[0]!.kind).toBe('pending')
    }
  })

  it('split digest matches the fixture digest file', () => {
    const expected = readFileSync(join(OTS_DIR, 'fixture-01.digest.txt'), 'utf8').trim()
    const { fileDigest } = splitOtsForRoundTrip(u8)
    const got = Array.from(fileDigest).map((b) => b.toString(16).padStart(2, '0')).join('')
    expect(got).toBe(expected)
  })
})

// ---------------------------------------------------------------------------
// fixture-01-live: parse-only — upstream Python serializer produces a tree
// shape (merged op prefixes across calendars) that this flat-fork builder
// does not reproduce. The canonical parser must still accept it; that is the
// only invariant we assert on this fixture.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// parser-side coverage of the new ops + result-length caps. Mirrors the
// strict-walker tests against parseOts to guard against the parser
// regressing back to "unknown op tag" or accepting bytes the strict walker
// rejects.
// ---------------------------------------------------------------------------

describe('parseOts: accepts OP_REVERSE / OP_HEXLIFY full proofs', () => {
  const digest = new Uint8Array(32).fill(0xab)
  for (const [name, opTag] of [['OP_REVERSE', 0xf2], ['OP_HEXLIFY', 0xf3]] as const) {
    it(`${name} round-trips via parseOts`, () => {
      const att = pendingResponse('https://x/')
      const cal = new Uint8Array(1 + att.length)
      cal[0] = opTag
      cal.set(att, 1)
      const built = buildOtsBytes({ fileDigest: digest, calendarTimestamps: [cal] })
      const parsed = parseOts(Buffer.from(built))
      expect(parsed.ok).toBe(true)
      if (parsed.ok) {
        expect(parsed.parsed.attestations.length).toBe(1)
        expect(parsed.parsed.attestations[0]!.kind).toBe('pending')
      }
    })
  }
})

describe('parseOts: enforces upstream op caps', () => {
  // We can't go through buildOtsBytes for these (the strict walker rejects),
  // so synthesize bytes directly. The parser should mirror the walker's caps
  // even when raw bytes are fed in (e.g. an .ots file loaded from disk).
  const HEADER = new Uint8Array([
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
    0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
  ])
  const VERSION_AND_OP = new Uint8Array([0x01, 0x08])
  const DIGEST = new Uint8Array(32).fill(0xab)
  const PENDING_ATT = (() => {
    const att = pendingResponse('https://x/')
    return att
  })()

  function makeProofWithOpAppendArg(argLen: number): Uint8Array {
    const argLenBytes = argLen < 0x80
      ? new Uint8Array([argLen])
      : new Uint8Array([(argLen & 0x7f) | 0x80, argLen >> 7])
    const arg = new Uint8Array(argLen)
    const total = HEADER.length + VERSION_AND_OP.length + DIGEST.length + 1 + argLenBytes.length + arg.length + PENDING_ATT.length
    const buf = new Uint8Array(total)
    let off = 0
    buf.set(HEADER, off); off += HEADER.length
    buf.set(VERSION_AND_OP, off); off += VERSION_AND_OP.length
    buf.set(DIGEST, off); off += DIGEST.length
    buf[off++] = 0xf0 // OP_APPEND
    buf.set(argLenBytes, off); off += argLenBytes.length
    buf.set(arg, off); off += arg.length
    buf.set(PENDING_ATT, off)
    return buf
  }

  it('rejects an .ots whose OP_APPEND arg exceeds 4096 bytes', () => {
    const proof = makeProofWithOpAppendArg(4097)
    const parsed = parseOts(Buffer.from(proof))
    expect(parsed.ok).toBe(false)
  })

  it('rejects an .ots whose OP_APPEND result exceeds 4096 (32 + 4065)', () => {
    const proof = makeProofWithOpAppendArg(4065)
    const parsed = parseOts(Buffer.from(proof))
    expect(parsed.ok).toBe(false)
  })

  it('accepts an .ots whose OP_APPEND result equals 4096 (32 + 4064)', () => {
    const proof = makeProofWithOpAppendArg(4064)
    const parsed = parseOts(Buffer.from(proof))
    expect(parsed.ok).toBe(true)
  })

  it('rejects an .ots whose OP_APPEND arg is empty', () => {
    const proof = makeProofWithOpAppendArg(0)
    const parsed = parseOts(Buffer.from(proof))
    expect(parsed.ok).toBe(false)
  })

  // OP_PREPEND mirrors OP_APPEND for caps — assert symmetry directly.
  function makeProofWithOpPrependArg(argLen: number): Uint8Array {
    const argLenBytes = argLen < 0x80
      ? new Uint8Array([argLen])
      : new Uint8Array([(argLen & 0x7f) | 0x80, argLen >> 7])
    const arg = new Uint8Array(argLen)
    const total = HEADER.length + VERSION_AND_OP.length + DIGEST.length + 1 + argLenBytes.length + arg.length + PENDING_ATT.length
    const buf = new Uint8Array(total)
    let off = 0
    buf.set(HEADER, off); off += HEADER.length
    buf.set(VERSION_AND_OP, off); off += VERSION_AND_OP.length
    buf.set(DIGEST, off); off += DIGEST.length
    buf[off++] = 0xf1 // OP_PREPEND
    buf.set(argLenBytes, off); off += argLenBytes.length
    buf.set(arg, off); off += arg.length
    buf.set(PENDING_ATT, off)
    return buf
  }

  it('rejects OP_PREPEND arg empty / >4096 / result >4096; accepts result == 4096', () => {
    expect(parseOts(Buffer.from(makeProofWithOpPrependArg(0))).ok).toBe(false)
    expect(parseOts(Buffer.from(makeProofWithOpPrependArg(4097))).ok).toBe(false)
    expect(parseOts(Buffer.from(makeProofWithOpPrependArg(4065))).ok).toBe(false)
    expect(parseOts(Buffer.from(makeProofWithOpPrependArg(4064))).ok).toBe(true)
  })

  it('rejects an .ots whose OP_HEXLIFY result exceeds 4096', () => {
    // Start at 32 bytes, OP_APPEND 2017 → 2049, OP_HEXLIFY → 4098 (reject).
    const argLen = 2017
    const argLenBytes = new Uint8Array([(argLen & 0x7f) | 0x80, argLen >> 7])
    const arg = new Uint8Array(argLen)
    const total = HEADER.length + VERSION_AND_OP.length + DIGEST.length + 1 + argLenBytes.length + arg.length + 1 + PENDING_ATT.length
    const buf = new Uint8Array(total)
    let off = 0
    buf.set(HEADER, off); off += HEADER.length
    buf.set(VERSION_AND_OP, off); off += VERSION_AND_OP.length
    buf.set(DIGEST, off); off += DIGEST.length
    buf[off++] = 0xf0
    buf.set(argLenBytes, off); off += argLenBytes.length
    buf.set(arg, off); off += arg.length
    buf[off++] = 0xf3
    buf.set(PENDING_ATT, off)
    expect(parseOts(Buffer.from(buf)).ok).toBe(false)
  })
})

describe('buildOtsBytes: validates calendar sub-trees through the strict walker', () => {
  const digest = new Uint8Array(32).fill(0xa1)

  it('rejects a calendar sub-tree containing OP_KECCAK256 (verifier-unsupported)', () => {
    const att = pendingResponse('https://x/')
    const calendar = new Uint8Array(1 + att.length)
    calendar[0] = 0x67 // OP_KECCAK256
    calendar.set(att, 1)
    expect(() =>
      buildOtsBytes({ fileDigest: digest, calendarTimestamps: [calendar] }),
    ).toThrow(/not a valid Timestamp sub-tree/)
  })

  it('rejects a calendar sub-tree with a malformed pending URI', () => {
    const url = new TextEncoder().encode('http://x/?q=1')
    const inner = new Uint8Array(1 + url.length)
    inner[0] = url.length
    inner.set(url, 1)
    const calendar = new Uint8Array(1 + 8 + 1 + inner.length)
    calendar[0] = 0x00
    calendar.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
    calendar[9] = inner.length
    calendar.set(inner, 10)
    expect(() =>
      buildOtsBytes({ fileDigest: digest, calendarTimestamps: [calendar] }),
    ).toThrow(/not a valid Timestamp sub-tree/)
  })

  it('rejects a calendar sub-tree with an oversized OP_APPEND arg', () => {
    const att = pendingResponse('https://x/')
    const calendar = new Uint8Array(1 + 2 + 4097 + att.length)
    calendar[0] = 0xf0
    calendar[1] = 0x81
    calendar[2] = 0x20
    calendar.set(att, 3 + 4097)
    expect(() =>
      buildOtsBytes({ fileDigest: digest, calendarTimestamps: [calendar] }),
    ).toThrow(/not a valid Timestamp sub-tree/)
  })
})

describe('parseOts: attestation caps + pending URI rules', () => {
  const HEADER = new Uint8Array([
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
    0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
  ])

  function encVarUint(n: number): Uint8Array {
    const out: number[] = []
    let v = n
    do {
      let b = v & 0x7f
      v >>= 7
      if (v > 0) b |= 0x80
      out.push(b)
    } while (v > 0)
    return new Uint8Array(out)
  }

  function makeProof(attestationBytes: Uint8Array): Uint8Array {
    const digest = new Uint8Array(32).fill(0xaa)
    const parts = [HEADER, new Uint8Array([0x01, 0x08]), digest, attestationBytes]
    let total = 0
    for (const p of parts) total += p.length
    const buf = new Uint8Array(total)
    let off = 0
    for (const p of parts) {
      buf.set(p, off)
      off += p.length
    }
    return buf
  }

  it('rejects an .ots with an unknown attestation payload exceeding 8192 bytes', () => {
    // Synthesize: 0x00 + 8-byte unknown tag + varuint(8193) + 8193-byte payload
    const tag = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef])
    const lenBytes = encVarUint(8193)
    const payload = new Uint8Array(8193)
    const att = new Uint8Array(1 + 8 + lenBytes.length + payload.length)
    att[0] = 0x00
    att.set(tag, 1)
    att.set(lenBytes, 1 + 8)
    att.set(payload, 1 + 8 + lenBytes.length)
    const proof = makeProof(att)
    const parsed = parseOts(Buffer.from(proof))
    expect(parsed.ok).toBe(false)
  })

  it('rejects pending attestation with URI > 1000 bytes', () => {
    const url = new TextEncoder().encode('https://' + 'a'.repeat(993)) // 1001 bytes
    const innerLen = encVarUint(url.length)
    const inner = new Uint8Array(innerLen.length + url.length)
    inner.set(innerLen, 0)
    inner.set(url, innerLen.length)
    const payloadLen = encVarUint(inner.length)
    const att = new Uint8Array(1 + 8 + payloadLen.length + inner.length)
    att[0] = 0x00
    att.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
    att.set(payloadLen, 9)
    att.set(inner, 9 + payloadLen.length)
    const parsed = parseOts(Buffer.from(makeProof(att)))
    expect(parsed.ok).toBe(false)
  })

  it('rejects pending attestation with invalid URI character (?)', () => {
    const url = new TextEncoder().encode('http://x/?q=1')
    const inner = new Uint8Array(1 + url.length)
    inner[0] = url.length
    inner.set(url, 1)
    const att = new Uint8Array(1 + 8 + 1 + inner.length)
    att[0] = 0x00
    att.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
    att[9] = inner.length
    att.set(inner, 10)
    const parsed = parseOts(Buffer.from(makeProof(att)))
    expect(parsed.ok).toBe(false)
  })

  it('rejects pending attestation with empty URI', () => {
    const inner = new Uint8Array([0x00]) // varbytes len = 0
    const att = new Uint8Array(1 + 8 + 1 + inner.length)
    att[0] = 0x00
    att.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
    att[9] = inner.length
    att.set(inner, 10)
    const parsed = parseOts(Buffer.from(makeProof(att)))
    expect(parsed.ok).toBe(false)
  })

  it('rejects pending attestation with trailing bytes past URI', () => {
    const url = new TextEncoder().encode('https://x/')
    // inner = varbytes(url) + 1 trailing byte
    const inner = new Uint8Array(1 + url.length + 1)
    inner[0] = url.length
    inner.set(url, 1)
    inner[1 + url.length] = 0x41
    const payloadLen = inner.length
    const att = new Uint8Array(1 + 8 + 1 + inner.length)
    att[0] = 0x00
    att.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
    att[9] = payloadLen
    att.set(inner, 10)
    const parsed = parseOts(Buffer.from(makeProof(att)))
    expect(parsed.ok).toBe(false)
  })

  it('accepts pending attestation with the canonical OTS calendar URL', () => {
    const url = new TextEncoder().encode('https://a.pool.opentimestamps.org')
    const inner = new Uint8Array(1 + url.length)
    inner[0] = url.length
    inner.set(url, 1)
    const att = new Uint8Array(1 + 8 + 1 + inner.length)
    att[0] = 0x00
    att.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
    att[9] = inner.length
    att.set(inner, 10)
    const parsed = parseOts(Buffer.from(makeProof(att)))
    expect(parsed.ok).toBe(true)
  })
})

describe('splitOtsForRoundTrip: enforces strict walker semantics (no more loose walker)', () => {
  it('rejects an .ots whose terminal branch contains OP_KECCAK256', () => {
    const HEADER = new Uint8Array([
      0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
      0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
    ])
    const digest = new Uint8Array(32).fill(0xab)
    const att = pendingResponse('https://x/')
    const branch = new Uint8Array(1 + att.length)
    branch[0] = 0x67 // OP_KECCAK256 prefix
    branch.set(att, 1)
    const buf = new Uint8Array(HEADER.length + 2 + digest.length + branch.length)
    let off = 0
    buf.set(HEADER, off); off += HEADER.length
    buf[off++] = 0x01
    buf[off++] = 0x08
    buf.set(digest, off); off += digest.length
    buf.set(branch, off)
    expect(() => splitOtsForRoundTrip(buf)).toThrow(/KECCAK|not yet supported/i)
  })
})

describe('fixture-01-live: parser accepts the upstream encoding', () => {
  const otsBytes = readFileSync(join(OTS_DIR, 'fixture-01-live.ots'))
  it('parseOts succeeds and surfaces the 3 expected calendar URLs', () => {
    const parsed = parseOts(otsBytes)
    expect(parsed.ok).toBe(true)
    if (parsed.ok) {
      const pendingUrls = parsed.parsed.attestations
        .filter((a) => a.kind === 'pending')
        .map((a) => (a as { kind: 'pending'; calendarUrl: string }).calendarUrl)
        .sort()
      expect(pendingUrls).toEqual([
        'https://alice.btc.calendar.opentimestamps.org',
        'https://bob.btc.calendar.opentimestamps.org',
        'https://finney.calendar.eternitywall.com',
      ])
    }
  })
})

// ---------------------------------------------------------------------------
// Ambiguity property: a calendar whose first byte is 0xff (a valid nested
// fork marker at branch-position 0) makes the flat-top-level-fork encoding
// undecodable to its original slice count. Document and pin the property
// that BYTE-REBUILD-IDENTITY survives this case even though slice count
// does not.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// isValidTimestampSubtree: the gate the browser /create/ page uses to reject
// HTML / redirect bodies / attacker-crafted noise BEFORE counting a calendar
// response toward the success quorum.
// ---------------------------------------------------------------------------

describe('isValidTimestampSubtree: accepts valid OTS sub-trees, rejects noise', () => {
  it('accepts a minimal pending-attestation response', () => {
    expect(isValidTimestampSubtree(pendingResponse('https://x/'))).toBe(true)
  })

  it('accepts a multi-attestation forked response', () => {
    const a = pendingResponse('https://A/')
    const b = pendingResponse('https://B/')
    const out = new Uint8Array(1 + a.length + b.length)
    out[0] = 0xff
    out.set(a, 1)
    out.set(b, 1 + a.length)
    expect(isValidTimestampSubtree(out)).toBe(true)
  })

  it('rejects empty input', () => {
    expect(isValidTimestampSubtree(new Uint8Array(0))).toBe(false)
  })

  it('rejects HTML masquerading as a calendar response', () => {
    const html = new TextEncoder().encode('<!doctype html><html><body>Service unavailable</body></html>')
    expect(isValidTimestampSubtree(html)).toBe(false)
  })

  it('rejects truncated valid response (cut mid-attestation)', () => {
    const full = pendingResponse('https://x/')
    expect(isValidTimestampSubtree(full.subarray(0, full.length - 2))).toBe(false)
  })

  it('rejects trailing garbage after a valid attestation', () => {
    const full = pendingResponse('https://x/')
    const padded = new Uint8Array(full.length + 3)
    padded.set(full, 0)
    padded[full.length] = 0x41
    padded[full.length + 1] = 0x42
    padded[full.length + 2] = 0x43
    expect(isValidTimestampSubtree(padded)).toBe(false)
  })

  it('rejects unknown op tag', () => {
    expect(isValidTimestampSubtree(new Uint8Array([0x55]))).toBe(false)
  })

  it('rejects lone crypto op with no terminal attestation', () => {
    // OP_SHA256 (0x08) alone consumes 1 byte; the walk runs out of buffer
    // without ever hitting an attestation. A previous version of the
    // validator returned true here because end===length; this case pins the
    // strict-termination requirement.
    expect(isValidTimestampSubtree(new Uint8Array([0x08]))).toBe(false)
    expect(isValidTimestampSubtree(new Uint8Array([0x02]))).toBe(false) // SHA-1
    expect(isValidTimestampSubtree(new Uint8Array([0x03]))).toBe(false) // RIPEMD-160
    expect(isValidTimestampSubtree(new Uint8Array([0x67]))).toBe(false) // KECCAK-256
  })

  it('rejects OP_APPEND with valid empty arg but no terminal attestation', () => {
    // OP_APPEND (0xf0) + varuint(0) for the empty arg = 2 bytes consumed,
    // then walk runs out of buffer.
    expect(isValidTimestampSubtree(new Uint8Array([0xf0, 0x00]))).toBe(false)
    expect(isValidTimestampSubtree(new Uint8Array([0xf1, 0x00]))).toBe(false) // OP_PREPEND
  })

  it('rejects FORK + valid branch without trailing terminal branch', () => {
    // 0xff + valid pending attestation = the sub-branch walks correctly to
    // an attestation, but the OUTER branch then has no terminal — must throw.
    const inner = pendingResponse('https://x/')
    const wrapped = new Uint8Array(1 + inner.length)
    wrapped[0] = 0xff
    wrapped.set(inner, 1)
    // wrapped is "fork + inner attestation". The outer walker pops back to
    // depth 0 after the inner walk completes, then hits EOF without a
    // terminal attestation for the outer branch.
    expect(isValidTimestampSubtree(wrapped)).toBe(false)
  })

  it('rejects attestation with unknown 8-byte type tag', () => {
    // 0x00 marker + 8 unknown bytes + payload — only Bitcoin/Litecoin/Pending
    // tags are in the allowlist.
    const bad = new Uint8Array([
      0x00,
      0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
      0x01, 0x00, // varbytes len=1 + one byte
    ])
    expect(isValidTimestampSubtree(bad)).toBe(false)
  })

  it('rejects attestation with truncated payload (declared length > buffer)', () => {
    // Pending tag, declared payload length = 100, but only 2 bytes follow.
    const truncated = new Uint8Array([
      0x00,
      0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
      0x64, 0x00, 0x01, // varbytes len=100, payload only 2 bytes here
    ])
    expect(isValidTimestampSubtree(truncated)).toBe(false)
  })

  it('rejects OP_APPEND with truncated varbytes arg', () => {
    // OP_APPEND + varuint(5) = arg length 5, but only 3 bytes follow.
    const truncated = new Uint8Array([0xf0, 0x05, 0x41, 0x42, 0x43])
    expect(isValidTimestampSubtree(truncated)).toBe(false)
  })

  it('rejects pending attestation with empty payload', () => {
    // Allowlisted Pending tag + varbytes len = 0 → no URL → must reject.
    const bad = new Uint8Array([
      0x00,
      0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
      0x00, // outer payload length = 0
    ])
    expect(isValidTimestampSubtree(bad)).toBe(false)
  })

  it('rejects pending attestation whose URL does not start with http(s)://', () => {
    // Allowlisted Pending tag + valid varbytes wrapping, but URL is "ftp://"
    const url = new TextEncoder().encode('ftp://x/')
    const inner = new Uint8Array(1 + url.length)
    inner[0] = url.length
    inner.set(url, 1)
    const bad = new Uint8Array(1 + 8 + 1 + inner.length)
    bad[0] = 0x00
    bad.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
    bad[9] = inner.length
    bad.set(inner, 10)
    expect(isValidTimestampSubtree(bad)).toBe(false)
  })

  it('rejects pending attestation with empty URL', () => {
    // Outer payload length = 1, inner varbytes length = 0
    const bad = new Uint8Array([
      0x00,
      0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e,
      0x01, // outer payload length = 1
      0x00, // inner varbytes length = 0 → empty URL
    ])
    expect(isValidTimestampSubtree(bad)).toBe(false)
  })

  it('rejects Bitcoin attestation with empty payload', () => {
    const bad = new Uint8Array([
      0x00,
      0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
      0x00, // outer payload length = 0 → no blockHeight
    ])
    expect(isValidTimestampSubtree(bad)).toBe(false)
  })

  it('rejects Bitcoin attestation with blockHeight 0', () => {
    const bad = new Uint8Array([
      0x00,
      0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
      0x01, 0x00, // outer payload length = 1, varuint = 0
    ])
    expect(isValidTimestampSubtree(bad)).toBe(false)
  })

  it('rejects Litecoin attestation with empty payload', () => {
    const bad = new Uint8Array([
      0x00,
      0x06, 0x86, 0x9a, 0x0d, 0x73, 0xd7, 0x1b, 0x45,
      0x00,
    ])
    expect(isValidTimestampSubtree(bad)).toBe(false)
  })

  it('rejects pending URL containing query character ?', () => {
    // Upstream OTS rejects ? in URIs; we must too, so we never mint a proof
    // the verifier will refuse to upgrade.
    const url = new TextEncoder().encode('http://x/?q=1')
    const inner = new Uint8Array(1 + url.length)
    inner[0] = url.length
    inner.set(url, 1)
    const bad = new Uint8Array(1 + 8 + 1 + inner.length)
    bad[0] = 0x00
    bad.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
    bad[9] = inner.length
    bad.set(inner, 10)
    expect(isValidTimestampSubtree(bad)).toBe(false)
  })

  it('rejects pending URL containing other disallowed characters', () => {
    for (const bad of ['http://x/ space', 'http://x/%20', 'http://x/#frag', 'http://x/&amp', 'http://x/=']) {
      const url = new TextEncoder().encode(bad)
      const inner = new Uint8Array(1 + url.length)
      inner[0] = url.length
      inner.set(url, 1)
      const buf = new Uint8Array(1 + 8 + 1 + inner.length)
      buf[0] = 0x00
      buf.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
      buf[9] = inner.length
      buf.set(inner, 10)
      expect(isValidTimestampSubtree(buf)).toBe(false)
    }
  })

  it('accepts valid public OTS calendar URLs', () => {
    for (const ok of [
      'https://a.pool.opentimestamps.org',
      'https://alice.btc.calendar.opentimestamps.org',
      'https://bob.btc.calendar.opentimestamps.org',
      'https://finney.calendar.eternitywall.com',
    ]) {
      const url = new TextEncoder().encode(ok)
      const inner = new Uint8Array(1 + url.length)
      inner[0] = url.length
      inner.set(url, 1)
      const buf = new Uint8Array(1 + 8 + 1 + inner.length)
      buf[0] = 0x00
      buf.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
      buf[9] = inner.length
      buf.set(inner, 10)
      expect(isValidTimestampSubtree(buf)).toBe(true)
    }
  })

  it('rejects pending URL exceeding MAX_PENDING_URI_LENGTH', () => {
    // 1001-byte URI: rejected. Use a varuint length encoding for > 127.
    const urlStr = 'https://' + 'a'.repeat(993) // 8 + 993 = 1001 bytes
    const url = new TextEncoder().encode(urlStr)
    expect(url.length).toBe(1001)
    // varuint(1001) = 0xE9 0x07
    const inner = new Uint8Array(2 + url.length)
    inner[0] = 0xe9
    inner[1] = 0x07
    inner.set(url, 2)
    // outer varbytes: length = inner.length = 1003 → varuint(1003) = 0xEB 0x07
    const buf = new Uint8Array(1 + 8 + 2 + inner.length)
    buf[0] = 0x00
    buf.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
    buf[9] = 0xeb
    buf[10] = 0x07
    buf.set(inner, 11)
    expect(isValidTimestampSubtree(buf)).toBe(false)
  })

  it('accepts OP_REVERSE (0xf2) and OP_HEXLIFY (0xf3) as unary ops before a terminal attestation', () => {
    const innerAtt = pendingResponse('https://x/')
    for (const opTag of [0xf2, 0xf3]) {
      const buf = new Uint8Array(1 + innerAtt.length)
      buf[0] = opTag
      buf.set(innerAtt, 1)
      expect(isValidTimestampSubtree(buf)).toBe(true)
    }
  })

  it('rejects OP_KECCAK256 — verifier does not implement it', () => {
    // Mirroring the verifier limitation: rejecting at the gate avoids minting
    // proofs the verifier later throws on. If the verifier gains KECCAK
    // support, lift this rejection in lockstep.
    const innerAtt = pendingResponse('https://x/')
    const buf = new Uint8Array(1 + innerAtt.length)
    buf[0] = 0x67
    buf.set(innerAtt, 1)
    expect(isValidTimestampSubtree(buf)).toBe(false)
  })

  it('rejects OP_APPEND with empty arg (arg length 0)', () => {
    const innerAtt = pendingResponse('https://x/')
    const buf = new Uint8Array(2 + innerAtt.length)
    buf[0] = 0xf0
    buf[1] = 0x00 // varuint(0) → empty arg
    buf.set(innerAtt, 2)
    expect(isValidTimestampSubtree(buf)).toBe(false)
  })

  it('rejects OP_PREPEND with empty arg (arg length 0)', () => {
    const innerAtt = pendingResponse('https://x/')
    const buf = new Uint8Array(2 + innerAtt.length)
    buf[0] = 0xf1
    buf[1] = 0x00
    buf.set(innerAtt, 2)
    expect(isValidTimestampSubtree(buf)).toBe(false)
  })

  it('rejects OP_APPEND with arg length > 4096 (per-arg cap)', () => {
    // varuint(4097) = 0x81 0x20 (2 bytes). Per-arg cap catches this before any
    // result-length check; either way it must reject.
    const innerAtt = pendingResponse('https://x/')
    const buf = new Uint8Array(1 + 2 + 4097 + innerAtt.length)
    buf[0] = 0xf0
    buf[1] = 0x81
    buf[2] = 0x20
    buf.set(innerAtt, 3 + 4097)
    expect(isValidTimestampSubtree(buf)).toBe(false)
  })

  it('rejects OP_APPEND when msg + arg exceeds 4096 (result cap)', () => {
    // Starting from a 32-byte SHA-256 digest, an arg of 4065 bytes would
    // produce a 4097-byte result — exceeds the cap. Even though the arg
    // itself is under MAX_BINARY_OP_ARG_LENGTH, the RESULT cap rejects.
    const innerAtt = pendingResponse('https://x/')
    const buf = new Uint8Array(1 + 2 + 4065 + innerAtt.length)
    buf[0] = 0xf0
    buf[1] = 0xe1 // varuint(4065) = 0xE1 0x1F
    buf[2] = 0x1f
    buf.set(innerAtt, 3 + 4065)
    expect(isValidTimestampSubtree(buf)).toBe(false)
  })

  it('accepts OP_APPEND when msg + arg = 4096 exactly (result-cap boundary)', () => {
    // 32-byte SHA-256 + 4064-byte arg = 4096 result, which is the exact cap.
    const innerAtt = pendingResponse('https://x/')
    const buf = new Uint8Array(1 + 2 + 4064 + innerAtt.length)
    buf[0] = 0xf0
    buf[1] = 0xe0 // varuint(4064) = 0xE0 0x1F
    buf[2] = 0x1f
    buf.set(innerAtt, 3 + 4064)
    expect(isValidTimestampSubtree(buf)).toBe(true)
  })

  it('rejects OP_HEXLIFY when 2*msg exceeds 4096', () => {
    // OP_APPEND to grow the message past 2048, then OP_HEXLIFY would push
    // result over 4096. msg starts at 32; append 2017 → msg = 2049; hexlify → 4098.
    // Use varuint(2017) = 0xE1 0x0F
    const innerAtt = pendingResponse('https://x/')
    const buf = new Uint8Array(1 + 2 + 2017 + 1 + innerAtt.length)
    buf[0] = 0xf0
    buf[1] = 0xe1
    buf[2] = 0x0f
    // bytes 3..3+2017 are arg
    buf[3 + 2017] = 0xf3 // OP_HEXLIFY
    buf.set(innerAtt, 3 + 2017 + 1)
    expect(isValidTimestampSubtree(buf)).toBe(false)
  })

  it('accepts Bitcoin attestation with a positive blockHeight', () => {
    // Block height 875432 varuint-encoded
    const ok = new Uint8Array([
      0x00,
      0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01,
      0x03, // outer payload length = 3 (3-byte varuint)
      0xa8, 0xb0, 0x35, // varuint(875432) = 0xA8 0xB0 0x35
    ])
    expect(isValidTimestampSubtree(ok)).toBe(true)
  })

  it('rejects non-Uint8Array inputs', () => {
    // @ts-expect-error — testing runtime guard
    expect(isValidTimestampSubtree(null)).toBe(false)
    // @ts-expect-error — testing runtime guard
    expect(isValidTimestampSubtree('not bytes')).toBe(false)
    // @ts-expect-error — testing runtime guard
    expect(isValidTimestampSubtree([0x00, 0x83])).toBe(false)
  })
})

describe('splitOtsForRoundTrip: ambiguity under 0xff-leading calendar', () => {
  const digest = new Uint8Array(32).fill(0x77)

  // A two-branch calendar response that starts with a nested fork marker:
  // 0xff <inner attestation A> <inner attestation B>. parseOts walks this
  // as one timestamp with two attestations (one fork at branch-pos 0 plus
  // one terminal attestation).
  const forkLeadingCalendar = (() => {
    const innerA = pendingResponse('https://A.example/')
    const innerB = pendingResponse('https://B.example/')
    const out = new Uint8Array(1 + innerA.length + innerB.length)
    out[0] = 0xff
    out.set(innerA, 1)
    out.set(innerB, 1 + innerA.length)
    return out
  })()

  it('parseOts on a single fork-leading calendar surfaces both inner attestations with exact URLs', () => {
    const built = buildOtsBytes({
      fileDigest: digest,
      calendarTimestamps: [forkLeadingCalendar],
    })
    const parsed = parseOts(Buffer.from(built))
    expect(parsed.ok).toBe(true)
    if (parsed.ok) {
      expect(parsed.parsed.attestations.length).toBe(2)
      const urls = parsed.parsed.attestations
        .filter((a) => a.kind === 'pending')
        .map((a) => (a as { kind: 'pending'; calendarUrl: string }).calendarUrl)
        .sort()
      expect(urls).toEqual(['https://A.example/', 'https://B.example/'])
    }
  })

  it('split count diverges from input count but rebuild is byte-identical', () => {
    const built = buildOtsBytes({
      fileDigest: digest,
      calendarTimestamps: [forkLeadingCalendar],
    })
    const split = splitOtsForRoundTrip(built)
    // Splitter sees the leading 0xff as a top-level fork separator, so what
    // was 1 input calendar splits to 2 slices. This is documented behavior.
    expect(split.calendarTimestamps.length).toBe(2)
    // Rebuild must still produce byte-identical output to the original.
    const rebuilt = buildOtsBytes({
      fileDigest: split.fileDigest,
      calendarTimestamps: split.calendarTimestamps,
    })
    expect(rebuilt.length).toBe(built.length)
    for (let i = 0; i < built.length; i++) {
      expect(rebuilt[i]).toBe(built[i])
    }
  })
})
