/**
 * Cross-implementation parity test for `screenplay-registration-norm/v1-strict`.
 *
 * Runs the FULL normalization test corpus through both the Node-side (Buffer + sync)
 * and cross-runtime (Uint8Array + async Web Crypto) implementations. Asserts
 * byte-identical results across every vector — the load-bearing safeguard against
 * normalization drift between the two code paths. CI fails loudly on any byte
 * difference.
 *
 * The corpus is the canonical truth; dual-implementation parity is the canonical
 * safeguard.
 */

import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  normalize as legacyNormalize,
  contentHashOfNormalized as legacyContentHashOfNormalized,
  validateStrictUtf8 as legacyValidateStrictUtf8,
  PROFILE_ID as LEGACY_PROFILE_ID,
  type TransformRecord as LegacyTransformRecord,
} from '../../src/normalize/v1-strict.js'

import {
  normalize as sharedNormalize,
  contentHashOfNormalized as sharedContentHashOfNormalized,
  validateStrictUtf8 as sharedValidateStrictUtf8,
  PROFILE_ID as SHARED_PROFILE_ID,
  type TransformRecord as SharedTransformRecord,
} from '../../src/shared/normalize/v1-strict.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CORPUS_DIR = join(__dirname, '..', '..', 'spec', 'v1', 'testvectors', 'normalization')

interface IndexFile {
  profileId: string
  vectorCount: number
  vectors: Array<{
    id: string
    name: string
    description: string
    kind: 'normalize' | 'reject-invalid-utf8'
  }>
}

const indexJson = JSON.parse(readFileSync(join(CORPUS_DIR, 'INDEX.json'), 'utf8')) as IndexFile

// ---------------------------------------------------------------------------
// Profile identifier parity (both modules MUST declare the same locked ID)
// ---------------------------------------------------------------------------

describe('cross-impl: profile identifier', () => {
  it('legacy and shared declare the same PROFILE_ID', () => {
    expect(LEGACY_PROFILE_ID).toBe(SHARED_PROFILE_ID)
    expect(LEGACY_PROFILE_ID).toBe('screenplay-registration-norm/v1-strict')
  })
})

// ---------------------------------------------------------------------------
// Vector-driven parity tests
// ---------------------------------------------------------------------------

describe('cross-impl: normalization corpus parity', () => {
  for (const v of indexJson.vectors) {
    const prefix = `${v.id}-${v.name}`
    describe(`vector ${v.id} ${v.name} (${v.kind})`, () => {
      const inputBuffer = readFileSync(join(CORPUS_DIR, `${prefix}.input.bin`))
      // Legacy takes Buffer; shared takes Uint8Array. Same backing memory either way.
      const inputBytes = new Uint8Array(
        inputBuffer.buffer,
        inputBuffer.byteOffset,
        inputBuffer.byteLength,
      )

      const legacyResult = legacyNormalize(inputBuffer)
      const sharedResult = sharedNormalize(inputBytes)

      it('both implementations agree on success/failure', () => {
        expect(sharedResult.ok).toBe(legacyResult.ok)
      })

      if (v.kind === 'normalize') {
        it('legacy succeeds (precondition)', () => {
          expect(legacyResult.ok).toBe(true)
        })

        it('shared succeeds (precondition)', () => {
          expect(sharedResult.ok).toBe(true)
        })

        it('normalized bytes are byte-identical', () => {
          if (!legacyResult.ok || !sharedResult.ok) {
            throw new Error('expected both to succeed; gated above')
          }
          const legacyBytes = new Uint8Array(
            legacyResult.normalized.buffer,
            legacyResult.normalized.byteOffset,
            legacyResult.normalized.byteLength,
          )
          expect(sharedResult.normalized.length).toBe(legacyBytes.length)
          // Per-byte compare with helpful diff on the first mismatch
          for (let i = 0; i < legacyBytes.length; i++) {
            if (legacyBytes[i] !== sharedResult.normalized[i]) {
              throw new Error(
                `divergence at byte ${i}: legacy=0x${legacyBytes[i]!.toString(16).padStart(2, '0')} shared=0x${sharedResult.normalized[i]!.toString(16).padStart(2, '0')}`,
              )
            }
          }
        })

        it('transforms are identical', () => {
          if (!legacyResult.ok || !sharedResult.ok) return
          expect(sharedResult.transforms as SharedTransformRecord[]).toEqual(
            legacyResult.transforms as LegacyTransformRecord[],
          )
        })

        it('content hash matches the corpus', async () => {
          if (!legacyResult.ok || !sharedResult.ok) return
          const expectedHash = readFileSync(join(CORPUS_DIR, `${prefix}.hash.txt`), 'utf8').trim()

          const legacyHash = legacyContentHashOfNormalized(legacyResult.normalized)
          const sharedHash = await sharedContentHashOfNormalized(sharedResult.normalized)

          expect(legacyHash).toBe(expectedHash)
          expect(sharedHash).toBe(expectedHash)
          expect(sharedHash).toBe(legacyHash)
        })
      } else {
        it('both reject', () => {
          expect(legacyResult.ok).toBe(false)
          expect(sharedResult.ok).toBe(false)
        })

        it('rejection reason matches', () => {
          if (legacyResult.ok || sharedResult.ok) return
          expect(sharedResult.reason).toBe(legacyResult.reason)
        })

        it('rejection detail describes the same offset', () => {
          if (legacyResult.ok || sharedResult.ok) return
          // The detail format is "Invalid UTF-8 byte sequence detected at offset N".
          // We don't string-equal because legacy/shared could diverge on wording in the
          // future; what we DO insist on is that they identify the SAME offset.
          const extract = (s: string): number | null => {
            const m = s.match(/offset (\d+)/)
            return m ? parseInt(m[1]!, 10) : null
          }
          expect(extract(sharedResult.detail)).toBe(extract(legacyResult.detail))
        })
      }
    })
  }
})

// ---------------------------------------------------------------------------
// UTF-8 validator parity — separate from normalize() because some callers use it standalone
// ---------------------------------------------------------------------------

describe('cross-impl: validateStrictUtf8 parity', () => {
  // Spot-check across all corpus inputs — both validators must agree
  for (const v of indexJson.vectors) {
    const prefix = `${v.id}-${v.name}`
    it(`vector ${v.id} ${v.name}: validators agree`, () => {
      const inputBuffer = readFileSync(join(CORPUS_DIR, `${prefix}.input.bin`))
      const inputBytes = new Uint8Array(
        inputBuffer.buffer,
        inputBuffer.byteOffset,
        inputBuffer.byteLength,
      )
      const legacy = legacyValidateStrictUtf8(inputBuffer)
      const shared = sharedValidateStrictUtf8(inputBytes)
      expect(shared.ok).toBe(legacy.ok)
      if (!legacy.ok && !shared.ok) {
        expect(shared.offset).toBe(legacy.offset)
      }
    })
  }

  // Adversarial bytes the corpus may not cover — direct synthesis
  const adversarial: Array<{ name: string; bytes: Uint8Array }> = [
    { name: 'empty', bytes: new Uint8Array([]) },
    { name: 'single ASCII', bytes: new Uint8Array([0x41]) },
    { name: 'overlong-NUL (0xC0 0x80)', bytes: new Uint8Array([0xc0, 0x80]) },
    { name: 'surrogate (U+D800 via 0xED 0xA0 0x80)', bytes: new Uint8Array([0xed, 0xa0, 0x80]) },
    { name: 'truncated 2-byte (0xC2 alone)', bytes: new Uint8Array([0xc2]) },
    { name: 'truncated 3-byte (0xE2 0x82 alone)', bytes: new Uint8Array([0xe2, 0x82]) },
    { name: 'continuation only (0x80)', bytes: new Uint8Array([0x80]) },
    { name: 'codepoint > U+10FFFF (0xF5 0x80 0x80 0x80)', bytes: new Uint8Array([0xf5, 0x80, 0x80, 0x80]) },
    { name: 'valid Euro sign U+20AC', bytes: new Uint8Array([0xe2, 0x82, 0xac]) },
    { name: 'valid CJK + ASCII', bytes: new Uint8Array([0x41, 0xe4, 0xb8, 0xad, 0x42]) },
  ]
  for (const t of adversarial) {
    it(`adversarial: ${t.name}`, () => {
      const buffer = Buffer.from(t.bytes)
      const legacy = legacyValidateStrictUtf8(buffer)
      const shared = sharedValidateStrictUtf8(t.bytes)
      expect(shared.ok).toBe(legacy.ok)
      if (!legacy.ok && !shared.ok) {
        expect(shared.offset).toBe(legacy.offset)
      }
    })
  }
})

// ---------------------------------------------------------------------------
// Adversarial normalize() parity — inputs the published corpus underspecifies.
// Locks in byte-equivalence for sequences that exercise BOM-strip ordering, NFC
// boundary behavior, embedded controls, and large mixed CR/LF/CRLF combinations.
// ---------------------------------------------------------------------------

describe('cross-impl: normalize() parity on adversarial inputs', () => {
  const cases: Array<{ name: string; bytes: Uint8Array }> = [
    {
      // Regression: TextDecoder default strips a leading BOM; v1-strict must
      // preserve U+FEFF after the spec-mandated single-BOM strip. Without
      // ignoreBOM:true the decoder swallows the second BOM and shared
      // output diverges from Buffer.toString('utf8').
      name: 'double-leading-BOM preserves the second',
      bytes: new Uint8Array([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, 0x41]),
    },
    {
      name: 'triple-leading-BOM preserves second and third',
      bytes: new Uint8Array([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, 0x41]),
    },
    {
      name: 'embedded BOM (middle of input, not stripped)',
      bytes: new Uint8Array([0x41, 0x42, 0xef, 0xbb, 0xbf, 0x43, 0x44]),
    },
    {
      name: 'BOM after newline (not at start, not stripped)',
      bytes: new Uint8Array([0x41, 0x0a, 0xef, 0xbb, 0xbf, 0x42]),
    },
    {
      name: 'mixed CRLF LF CR sequence',
      bytes: new Uint8Array([0x41, 0x0d, 0x0a, 0x42, 0x0a, 0x43, 0x0d, 0x44]),
    },
    {
      name: 'CR at EOF (lone CR)',
      bytes: new Uint8Array([0x41, 0x0d]),
    },
    {
      name: 'CRLF at EOF',
      bytes: new Uint8Array([0x41, 0x0d, 0x0a]),
    },
    {
      name: 'embedded NUL byte (valid UTF-8, must be preserved)',
      bytes: new Uint8Array([0x41, 0x00, 0x42]),
    },
    {
      name: 'NFC decomposed e + combining acute → composed é',
      // U+0065 U+0301 → U+00E9 (canonical composition)
      bytes: new Uint8Array([0x65, 0xcc, 0x81]),
    },
    {
      name: 'BOM then NFC-decomposed pair',
      bytes: new Uint8Array([0xef, 0xbb, 0xbf, 0x65, 0xcc, 0x81]),
    },
    {
      name: 'supplementary plane (U+1F600 grinning face) preserved',
      bytes: new Uint8Array([0xf0, 0x9f, 0x98, 0x80]),
    },
    {
      name: 'lone single LF',
      bytes: new Uint8Array([0x0a]),
    },
    {
      name: 'consecutive blank lines via LF',
      bytes: new Uint8Array([0x41, 0x0a, 0x0a, 0x0a, 0x42]),
    },
  ]
  for (const c of cases) {
    it(`adversarial normalize: ${c.name}`, async () => {
      const legacy = legacyNormalize(Buffer.from(c.bytes))
      const shared = sharedNormalize(c.bytes)
      expect(shared.ok).toBe(legacy.ok)
      if (legacy.ok && shared.ok) {
        const legacyBytes = new Uint8Array(
          legacy.normalized.buffer,
          legacy.normalized.byteOffset,
          legacy.normalized.byteLength,
        )
        expect(shared.normalized.length).toBe(legacyBytes.length)
        for (let i = 0; i < legacyBytes.length; i++) {
          if (legacyBytes[i] !== shared.normalized[i]) {
            throw new Error(
              `divergence at byte ${i}: legacy=0x${legacyBytes[i]!.toString(16).padStart(2, '0')} shared=0x${shared.normalized[i]!.toString(16).padStart(2, '0')}`,
            )
          }
        }
        expect(shared.transforms).toEqual(legacy.transforms)
        const legacyHash = legacyContentHashOfNormalized(legacy.normalized)
        const sharedHash = await sharedContentHashOfNormalized(shared.normalized)
        expect(sharedHash).toBe(legacyHash)
      }
    })
  }
})
