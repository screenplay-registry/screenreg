/**
 * Tests for the CLI OTS submit adapter (pure TypeScript, no Python/venv).
 *
 * Mock mode runs offline and always. Live mode hits the public calendars and is
 * gated by SCREENREG_TEST_LIVE_OTS=1 to keep CI deterministic and offline.
 */

import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { submitOts } from '../../src/anchors/ots-submit.js'
import { verifyOtsAgainstFileDigest, parseOts } from '../../src/anchors/ots-verify.js'

describe('OTS submit (mock mode, offline)', () => {
  it('mock submit returns a parseable .ots binary with a PendingAttestation', async () => {
    const digest = createHash('sha256').update('test-digest-input').digest()
    const result = await submitOts({ digest, mock: true })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.otsBytes.length).toBeGreaterThan(50) // header + version + op + digest + attestation
    const parsed = parseOts(result.otsBytes)
    expect(parsed.ok).toBe(true)
    if (parsed.ok) {
      expect(parsed.parsed.fileDigestHex).toBe(digest.toString('hex'))
      expect(parsed.parsed.attestations.length).toBe(1)
      expect(parsed.parsed.attestations[0]?.kind).toBe('pending')
    }
  })

  it('mock submit round-trips through verifyOtsAgainstFileDigest (pending, not anchored)', async () => {
    const digest = createHash('sha256').update('another-test').digest()
    const result = await submitOts({ digest, mock: true })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const verified = verifyOtsAgainstFileDigest({ otsBytes: result.otsBytes, expectedFileDigest: digest })
    expect(verified.ok).toBe(true)
    if (verified.ok) {
      expect(verified.bitcoinAnchored).toBe(false)
      expect(verified.pendingCalendarUrls.length).toBe(1)
    }
  })

  it('rejects a digest of the wrong length', async () => {
    const result = await submitOts({ digest: Buffer.alloc(16, 0xaa), mock: true })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toMatch(/32 bytes/)
  })
})

describe('OTS submit (live mode, opt-in)', () => {
  if (process.env.SCREENREG_TEST_LIVE_OTS !== '1') {
    it.skip('skipped — set SCREENREG_TEST_LIVE_OTS=1 to enable', () => {})
    return
  }

  it(
    'live submit returns a parseable .ots binary with calendar attestations',
    async () => {
      const digest = createHash('sha256').update(`live-test-${Date.now()}`).digest()
      const result = await submitOts({ digest, timeoutSec: 20, minCalendars: 1 })
      expect(result.ok).toBe(true)
      if (!result.ok) {
        console.error('submit failure:', result.reason, result.stderr)
        return
      }
      const parsed = parseOts(result.otsBytes)
      expect(parsed.ok).toBe(true)
      if (parsed.ok) {
        expect(parsed.parsed.fileDigestHex).toBe(digest.toString('hex'))
        const hasPending = parsed.parsed.attestations.some((a) => a.kind === 'pending')
        const hasBitcoin = parsed.parsed.attestations.some((a) => a.kind === 'bitcoin')
        expect(hasPending || hasBitcoin).toBe(true)
      }
    },
    60_000,
  )
})
