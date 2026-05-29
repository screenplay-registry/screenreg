/**
 * End-to-end smoke test for the compiled browser ES modules at landing/create/lib/.
 *
 * The browser /create/ page imports these compiled artifacts directly. This test
 * runs the full pipeline (normalize → contentHash → buildCommittedClaim →
 * computeClaimHash → buildOtsBytes) through the COMPILED output (not the TS
 * source) under Node, then verifies the resulting bytes match the legacy
 * Node-side implementation and that the assembled `.ots` parses cleanly via
 * the canonical parser.
 *
 * Catches: tsc emit drift between the Node-target and browser-target builds,
 * stale-dist artifacts that disagree with the source, missing exports in the
 * compiled JS that work fine in src/.
 */

import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  normalize as legacyNormalize,
  contentHashOfNormalized as legacyContentHashOfNormalized,
} from '../../src/normalize/v1-strict.js'
import { computeClaimHash as legacyComputeClaimHash } from '../../src/envelope/claim-hash.js'
import { buildCommittedClaim as legacyBuildCommittedClaim } from '../../src/envelope/build.js'
import { parseOts } from '../../src/anchors/ots-verify.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const COMPILED_DIR = join(__dirname, '..', '..', 'landing', 'create', 'lib')

const compiledAvailable = existsSync(join(COMPILED_DIR, 'crypto.js'))

describe.skipIf(!compiledAvailable)(
  'compiled browser modules: full pipeline parity with src',
  () => {
    it('runs the full pipeline through the compiled JS and matches legacy', async () => {
      // Dynamic import the compiled JS so the test runner doesn't try to
      // resolve them at module-load time when they may not exist on a clean
      // checkout that hasn't run `npm run build:browser`.
      const normMod = (await import(
        /* @vite-ignore */ `file://${join(COMPILED_DIR, 'normalize', 'v1-strict.js')}`
      )) as typeof import('../../src/shared/normalize/v1-strict.js')
      const claimHashMod = (await import(
        /* @vite-ignore */ `file://${join(COMPILED_DIR, 'envelope', 'claim-hash.js')}`
      )) as typeof import('../../src/shared/envelope/claim-hash.js')
      const buildMod = (await import(
        /* @vite-ignore */ `file://${join(COMPILED_DIR, 'envelope', 'build.js')}`
      )) as typeof import('../../src/shared/envelope/build.js')
      const otsMod = (await import(
        /* @vite-ignore */ `file://${join(COMPILED_DIR, 'anchors', 'ots-build.js')}`
      )) as typeof import('../../src/shared/anchors/ots-build.js')

      const input = Buffer.from('Title: Test\n\nFADE IN:\n\nINT. ROOM - DAY\n\nA writer types.\n')

      // Legacy path
      const lNorm = legacyNormalize(input)
      if (!lNorm.ok) throw new Error('legacy normalize failed: ' + lNorm.detail)
      const lContentHash = legacyContentHashOfNormalized(lNorm.normalized)
      const lClaim = legacyBuildCommittedClaim({ contentHash: lContentHash })
      const lClaimHash = legacyComputeClaimHash(lClaim)

      // Compiled-browser path
      const inputU8 = new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
      const bNorm = normMod.normalize(inputU8)
      if (!bNorm.ok) throw new Error('browser normalize failed: ' + bNorm.detail)
      const bContentHash = await normMod.contentHashOfNormalized(bNorm.normalized)
      const bClaim = buildMod.buildCommittedClaim({ contentHash: bContentHash })
      const bClaimHash = await claimHashMod.computeClaimHash(bClaim)
      const bClaimHashBytes = await claimHashMod.computeClaimHashBytes(bClaim)

      // Parity assertions
      expect(bContentHash).toBe(lContentHash)
      expect(bClaim).toEqual(lClaim)
      expect(bClaimHash).toBe(lClaimHash)
      expect(bClaimHashBytes.length).toBe(32)

      // Synthesize two minimal pending calendar responses and assemble .ots
      const makePending = (url: string) => {
        const enc = new TextEncoder().encode(url)
        const inner = new Uint8Array(1 + enc.length)
        inner[0] = enc.length
        inner.set(enc, 1)
        const out = new Uint8Array(1 + 8 + 1 + inner.length)
        out[0] = 0x00
        out.set([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e], 1)
        out[9] = inner.length
        out.set(inner, 10)
        return out
      }
      const cals = [
        makePending('https://a.pool.opentimestamps.org'),
        makePending('https://alice.btc.calendar.opentimestamps.org'),
      ]
      const otsBytes = otsMod.buildOtsBytes({
        fileDigest: bClaimHashBytes,
        calendarTimestamps: cals,
      })

      // Canonical parser must accept the assembled bytes and surface both URLs
      const parsed = parseOts(Buffer.from(otsBytes))
      expect(parsed.ok).toBe(true)
      if (parsed.ok) {
        expect(parsed.parsed.fileHashOp).toBe('sha256')
        const got = parsed.parsed.attestations
          .filter((a) => a.kind === 'pending')
          .map((a) => (a as { kind: 'pending'; calendarUrl: string }).calendarUrl)
          .sort()
        expect(got).toEqual([
          'https://a.pool.opentimestamps.org',
          'https://alice.btc.calendar.opentimestamps.org',
        ])
      }

      // Exercise the compiled isValidTimestampSubtree — drift in the strict
      // walker (the calendar-response gate the browser /create/ page depends
      // on) would silently allow attacker-controlled noise to count toward
      // the success quorum. Validate that the compiled validator accepts a
      // valid pending response, rejects HTML, rejects truncation, and
      // rejects a tag the allowlist does not know.
      expect(otsMod.isValidTimestampSubtree(cals[0]!)).toBe(true)
      expect(otsMod.isValidTimestampSubtree(cals[1]!)).toBe(true)
      const htmlNoise = new TextEncoder().encode('<!doctype html><body>oops</body>')
      expect(otsMod.isValidTimestampSubtree(htmlNoise)).toBe(false)
      const truncated = cals[0]!.subarray(0, cals[0]!.length - 1)
      expect(otsMod.isValidTimestampSubtree(truncated)).toBe(false)
      const unknownTag = new Uint8Array([
        0x00, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x00,
      ])
      expect(otsMod.isValidTimestampSubtree(unknownTag)).toBe(false)
      const opOnly = new Uint8Array([0x08])
      expect(otsMod.isValidTimestampSubtree(opOnly)).toBe(false)
    })
  },
)

describe('compiled browser modules: build presence is required', () => {
  it('landing/create/lib/ exists — run `npm run build:browser` if this fails', () => {
    expect(compiledAvailable).toBe(true)
  })

  it('every shared TS source has a compiled JS sibling', () => {
    if (!compiledAvailable) return
    const SHARED_TS = [
      'crypto.ts',
      'normalize/v1-strict.ts',
      'envelope/types.ts',
      'envelope/canonicalize.ts',
      'envelope/claim-hash.ts',
      'envelope/build.ts',
      'envelope/validate.ts',
      'anchors/ots-build.ts',
    ]
    for (const rel of SHARED_TS) {
      const jsPath = join(COMPILED_DIR, rel.replace(/\.ts$/, '.js'))
      const present = existsSync(jsPath)
      if (!present) {
        throw new Error(
          `compiled JS missing for src/shared/${rel}; expected at ${jsPath}. Run \`npm run build:browser\`.`,
        )
      }
    }
  })
})

// (Reference legacy imports used above; kept as a no-op sanity reference)
void [legacyNormalize, legacyContentHashOfNormalized, legacyComputeClaimHash, legacyBuildCommittedClaim]
