/**
 * RFC 8785 canonicalization tests.
 *
 * Loads the canon-* vectors from /spec/v1/testvectors/envelope/ and asserts
 * byte-identical output. Adds property tests for sort stability and idempotence.
 */

import { describe, it, expect } from 'vitest'
import * as fc from 'fast-check'
import { readdirSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalize, canonicalizeToString } from '../../src/envelope/canonicalize.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CORPUS_DIR = join(__dirname, '..', '..', 'spec', 'v1', 'testvectors', 'envelope')

interface IndexFile {
  canonVectors: Array<{ id: string; name: string; description: string }>
  envelopeVectors: Array<{ id: string; name: string; description: string }>
}

const indexJson = JSON.parse(readFileSync(join(CORPUS_DIR, 'INDEX.json'), 'utf8')) as IndexFile

describe('canonicalization test vectors', () => {
  for (const v of indexJson.canonVectors) {
    const prefix = `canon-${v.id}-${v.name}`
    it(`${v.id} ${v.name}`, () => {
      const input = JSON.parse(readFileSync(join(CORPUS_DIR, `${prefix}.input.json`), 'utf8'))
      const expected = readFileSync(join(CORPUS_DIR, `${prefix}.canonical.bin`))
      const actual = canonicalize(input)
      expect(actual.equals(expected)).toBe(true)
    })
  }
})

describe('canonicalization throws on non-JSON values', () => {
  it('throws on NaN', () => {
    expect(() => canonicalize(NaN)).toThrow(/NaN/)
  })
  it('throws on Infinity', () => {
    expect(() => canonicalize(Infinity)).toThrow(/Infinity/)
  })
  it('throws on undefined', () => {
    expect(() => canonicalize(undefined)).toThrow(/undefined/)
  })
  it('throws on bigint', () => {
    expect(() => canonicalize(123n)).toThrow(/bigint/)
  })
  it('throws on integers outside the safe range (precision already lost at input)', () => {
    // 2^53 is the boundary; +1 / +3 exceed it. Math: Number(2**53 + 1) === 2**53 (rounded).
    // We catch the value the caller actually passed, not the rounded form.
    expect(() => canonicalize(Number.MAX_SAFE_INTEGER + 2)).toThrow(/SAFE_INTEGER/i)
    expect(() => canonicalize(-(Number.MAX_SAFE_INTEGER + 2))).toThrow(/SAFE_INTEGER/i)
  })
  it('accepts integers at the safe-range boundary', () => {
    expect(canonicalize(Number.MAX_SAFE_INTEGER).toString('utf8')).toBe(String(Number.MAX_SAFE_INTEGER))
    expect(canonicalize(Number.MIN_SAFE_INTEGER).toString('utf8')).toBe(String(Number.MIN_SAFE_INTEGER))
  })
  it('accepts finite non-integer doubles (precision is the caller\'s responsibility)', () => {
    // Non-integer finite doubles are RFC 8785 valid — String(0.1) is canonical.
    // This isn't a "you must avoid these" check, just confirming the safe-integer
    // gate doesn't accidentally reject legitimate floats.
    expect(canonicalize(0.1).toString('utf8')).toBe('0.1')
    expect(canonicalize(-1.5).toString('utf8')).toBe('-1.5')
  })
  it('throws on lone high surrogate (would silently corrupt UTF-8)', () => {
    const loneHigh = String.fromCharCode(0xd800) // unpaired
    expect(() => canonicalize(loneHigh)).toThrow(/lone high surrogate/)
    // Adversarial: high surrogate followed by a non-low-surrogate code unit
    const highThenNonLow = String.fromCharCode(0xd800) + 'a'
    expect(() => canonicalize(highThenNonLow)).toThrow(/lone high surrogate/)
  })
  it('throws on lone low surrogate', () => {
    const loneLow = String.fromCharCode(0xdc00)
    expect(() => canonicalize(loneLow)).toThrow(/lone low surrogate/)
  })
  it('accepts valid surrogate pairs (supplementary-plane code points round-trip)', () => {
    // U+1F4A9 (the pile-of-poo emoji) encodes as UTF-16 high+low pair 0xD83D 0xDCA9.
    // Valid input — must be canonicalized without throwing and round-trip to UTF-8.
    const emoji = '\u{1F4A9}' // === String.fromCodePoint(0x1f4a9)
    const out = canonicalize(emoji).toString('utf8')
    expect(out).toBe(`"${emoji}"`)
    // Sanity: the 4-byte UTF-8 sequence for U+1F4A9 is F0 9F 92 A9
    const utf8 = Buffer.from(emoji, 'utf8')
    expect(Array.from(utf8)).toEqual([0xf0, 0x9f, 0x92, 0xa9])
  })
})

describe('canonicalization properties', () => {
  it('skips undefined object properties (per RFC 8259 — they cannot be JSON values)', () => {
    const result = canonicalizeToString({ a: 1, b: undefined, c: 2 })
    expect(result).toBe('{"a":1,"c":2}')
  })

  it('object key insertion order does not affect output', () => {
    const result1 = canonicalizeToString({ a: 1, b: 2, c: 3 })
    const result2 = canonicalizeToString({ c: 3, a: 1, b: 2 })
    const result3 = canonicalizeToString({ b: 2, c: 3, a: 1 })
    expect(result1).toBe(result2)
    expect(result2).toBe(result3)
  })

  it('arrays preserve order', () => {
    expect(canonicalizeToString([3, 1, 2])).toBe('[3,1,2]')
    expect(canonicalizeToString([1, 2, 3])).toBe('[1,2,3]')
  })

  it('canonicalization is idempotent (canon(parse(canon(x))) === canon(x))', () => {
    fc.assert(
      fc.property(jsonValue(), (v) => {
        const c1 = canonicalizeToString(v)
        const parsed = JSON.parse(c1)
        const c2 = canonicalizeToString(parsed)
        return c1 === c2
      }),
      { numRuns: 200 },
    )
  })
})

// ---------------------------------------------------------------------------
// Helper: fast-check arbitrary for JSON-serializable values
// ---------------------------------------------------------------------------

function jsonValue(): fc.Arbitrary<unknown> {
  return fc.letrec((tie) => ({
    value: fc.oneof(
      { weight: 1, arbitrary: fc.constant(null) },
      { weight: 1, arbitrary: fc.boolean() },
      { weight: 2, arbitrary: fc.integer({ min: -1_000_000, max: 1_000_000 }) },
      { weight: 3, arbitrary: fc.string({ size: 'small' }) },
      { weight: 1, arbitrary: fc.array(tie('value'), { maxLength: 4 }) },
      {
        weight: 1,
        arbitrary: fc.dictionary(fc.string({ size: 'small', minLength: 1 }), tie('value'), {
          maxKeys: 4,
        }),
      },
    ),
  })).value
}
