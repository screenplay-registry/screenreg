/**
 * Vector-driven + property tests for `screenplay-registration-norm/v1-strict`.
 *
 * Loads every committed test vector under /spec/v1/testvectors/normalization/
 * and asserts the reference implementation produces the exact bytes + hash
 * that are stored in the corpus. The corpus itself is committed in the repo
 * and is the canonical truth source for compliance.
 */

import { describe, it, expect } from 'vitest'
import * as fc from 'fast-check'
import { readdirSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  normalize,
  contentHashOfNormalized,
  validateStrictUtf8,
  PROFILE_ID,
  type TransformRecord,
} from '../../src/normalize/v1-strict.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CORPUS_DIR = join(__dirname, '..', '..', 'spec', 'v1', 'testvectors', 'normalization')

interface IndexFile {
  profileId: string
  vectorCount: number
  vectors: Array<{ id: string; name: string; description: string; kind: 'normalize' | 'reject-invalid-utf8' }>
}

const indexJson = JSON.parse(readFileSync(join(CORPUS_DIR, 'INDEX.json'), 'utf8')) as IndexFile

// ---------------------------------------------------------------------------
// Profile sanity
// ---------------------------------------------------------------------------

describe('profile identifier', () => {
  it('matches the spec exactly', () => {
    expect(PROFILE_ID).toBe('screenplay-registration-norm/v1-strict')
    expect(indexJson.profileId).toBe(PROFILE_ID)
  })
})

// ---------------------------------------------------------------------------
// Vector-driven tests
// ---------------------------------------------------------------------------

describe('test vector corpus', () => {
  for (const v of indexJson.vectors) {
    const prefix = `${v.id}-${v.name}`
    describe(`${v.id} ${v.name} (${v.kind})`, () => {
      const input = readFileSync(join(CORPUS_DIR, `${prefix}.input.bin`))

      if (v.kind === 'normalize') {
        const expected = readFileSync(join(CORPUS_DIR, `${prefix}.expected.bin`))
        const expectedHash = readFileSync(join(CORPUS_DIR, `${prefix}.hash.txt`), 'utf8').trim()
        const expectedTransforms = JSON.parse(
          readFileSync(join(CORPUS_DIR, `${prefix}.transforms.json`), 'utf8'),
        ) as TransformRecord[]

        it('normalizes to the exact expected bytes', () => {
          const result = normalize(input)
          expect(result.ok).toBe(true)
          if (result.ok) {
            // Compare buffers byte-for-byte
            expect(result.normalized.equals(expected)).toBe(true)
          }
        })

        it('produces the expected SHA-256 hash', () => {
          const result = normalize(input)
          expect(result.ok).toBe(true)
          if (result.ok) {
            const hash = contentHashOfNormalized(result.normalized)
            expect(hash).toBe(expectedHash)
          }
        })

        it('records the expected transform sequence', () => {
          const result = normalize(input)
          expect(result.ok).toBe(true)
          if (result.ok) {
            // We compare KINDS in order; counts can drift with ICU version changes
            // for the applied-nfc count, so we don't strictly compare counts here.
            const actualKinds = result.transforms.map((t) => t.kind)
            const expectedKinds = expectedTransforms.map((t) => t.kind)
            expect(actualKinds).toEqual(expectedKinds)
          }
        })
      } else {
        const rejectInfo = JSON.parse(
          readFileSync(join(CORPUS_DIR, `${prefix}.reject.json`), 'utf8'),
        ) as { reason: string; detail: string; expectedDetailSubstring?: string }

        it('is rejected as invalid UTF-8', () => {
          const result = normalize(input)
          expect(result.ok).toBe(false)
          if (!result.ok) {
            expect(result.reason).toBe('invalid-utf8')
            if (rejectInfo.expectedDetailSubstring) {
              expect(result.detail).toContain(rejectInfo.expectedDetailSubstring)
            }
          }
        })
      }
    })
  }
})

// ---------------------------------------------------------------------------
// Property tests via fast-check
// ---------------------------------------------------------------------------

describe('property: normalization is idempotent', () => {
  it('normalize(normalize(x)) === normalize(x) for any valid UTF-8 string', () => {
    fc.assert(
      fc.property(fc.string({ size: 'small' }), (s) => {
        const input = Buffer.from(s, 'utf8')
        const r1 = normalize(input)
        if (!r1.ok) {
          // Buffer.from(s, 'utf8') should always produce valid UTF-8, so this shouldn't happen.
          throw new Error(`normalization unexpectedly failed: ${r1.detail}`)
        }
        const r2 = normalize(r1.normalized)
        if (!r2.ok) {
          throw new Error('second-pass normalization failed')
        }
        return r1.normalized.equals(r2.normalized)
      }),
      { numRuns: 200 },
    )
  })
})

describe('property: ASCII (no CR, no BOM) round-trips unchanged', () => {
  it('any pure ASCII string without CR or leading BOM normalizes to itself', () => {
    fc.assert(
      fc.property(
        fc.string({
          size: 'small',
          unit: fc.constantFrom(
            // Printable ASCII excluding CR (0x0D)
            ...Array.from({ length: 95 }, (_, i) => String.fromCharCode(0x20 + i)),
            '\n',
            '\t',
          ),
        }),
        (s) => {
          const input = Buffer.from(s, 'utf8')
          const result = normalize(input)
          if (!result.ok) return false
          return result.normalized.equals(input)
        },
      ),
      { numRuns: 200 },
    )
  })
})

describe('property: invalid UTF-8 is always rejected', () => {
  it('random byte arrays containing invalid UTF-8 patterns are rejected', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 32 }),
        (bytes) => {
          const buf = Buffer.from(bytes)
          const utf8Check = validateStrictUtf8(buf)
          const normResult = normalize(buf)
          // If UTF-8 validation passes, normalize succeeds; if validation fails, normalize fails
          if (utf8Check.ok) {
            return normResult.ok
          } else {
            return !normResult.ok && normResult.reason === 'invalid-utf8'
          }
        },
      ),
      { numRuns: 200 },
    )
  })
})

describe('property: NFC normalization is stable under re-application', () => {
  it('contentHash(x) === contentHash(normalize(x)) for any valid input', () => {
    fc.assert(
      fc.property(fc.string({ size: 'small' }), (s) => {
        const input = Buffer.from(s, 'utf8')
        const r1 = normalize(input)
        if (!r1.ok) return true // skip
        const hash1 = contentHashOfNormalized(r1.normalized)
        const r2 = normalize(r1.normalized)
        if (!r2.ok) return false
        const hash2 = contentHashOfNormalized(r2.normalized)
        return hash1 === hash2
      }),
      { numRuns: 200 },
    )
  })
})

describe('property: no CR bytes in any normalized output', () => {
  it('output never contains 0x0D after normalization', () => {
    fc.assert(
      fc.property(fc.string({ size: 'small' }), (s) => {
        // Inject some CR bytes into the input to make it nontrivial
        const withCr = s.replace(/./g, (c) => c + '\r')
        const input = Buffer.from(withCr, 'utf8')
        const r = normalize(input)
        if (!r.ok) return false
        return !r.normalized.includes(0x0d)
      }),
      { numRuns: 100 },
    )
  })
})
