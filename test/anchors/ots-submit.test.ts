/**
 * Tests for the Python-helper subprocess wrapper.
 *
 * Uses mock mode by default (no network). Live mode is gated by env var
 * SCREENREG_TEST_LIVE_OTS=1 to keep CI deterministic and offline-runnable.
 */

import { describe, it, expect } from 'vitest'
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { submitOts, DEFAULT_HELPER_PATH } from '../../src/anchors/ots-submit.js'
import { verifyOtsAgainstFileDigest, parseOts } from '../../src/anchors/ots-verify.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const VENV_PYTHON = join(__dirname, '..', '..', '.venv', 'bin', 'python3')
const HAVE_VENV = existsSync(VENV_PYTHON)

describe('OTS submit (mock mode, offline)', () => {
  if (!HAVE_VENV) {
    it.skip('skipped — Python venv not found at ./.venv/bin/python3', () => {})
    return
  }

  it('default helper path is in src/anchors/python/', () => {
    expect(DEFAULT_HELPER_PATH).toContain('ots_stamp_digest.py')
    expect(existsSync(DEFAULT_HELPER_PATH)).toBe(true)
  })

  it('mock submit returns a parseable .ots binary with PendingAttestation', async () => {
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

  it('mock submit round-trips through verifyOtsAgainstFileDigest', async () => {
    const digest = createHash('sha256').update('another-test').digest()
    const result = await submitOts({ digest, mock: true })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const verified = verifyOtsAgainstFileDigest({
      otsBytes: result.otsBytes,
      expectedFileDigest: digest,
    })
    expect(verified.ok).toBe(true)
    if (verified.ok) {
      expect(verified.bitcoinAnchored).toBe(false)
      expect(verified.pendingCalendarUrls.length).toBe(1)
    }
  })

  it('rejects digest of wrong length', async () => {
    const badDigest = Buffer.alloc(16, 0xaa)
    const result = await submitOts({ digest: badDigest, mock: true })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toMatch(/32 bytes/)
    }
  })
})

describe('OTS submit (live mode, opt-in)', () => {
  const liveEnabled = process.env.SCREENREG_TEST_LIVE_OTS === '1'
  if (!liveEnabled || !HAVE_VENV) {
    it.skip('skipped — set SCREENREG_TEST_LIVE_OTS=1 to enable', () => {})
    return
  }

  it(
    'live submit returns a parseable .ots binary with calendar attestations',
    async () => {
      const digest = createHash('sha256')
        .update(`live-test-${Date.now()}`)
        .digest()
      const result = await submitOts({ digest, timeoutSec: 20, minCalendars: 1 })
      expect(result.ok).toBe(true)
      if (!result.ok) {
        console.error('submit stderr:', result.stderr)
        return
      }
      const parsed = parseOts(result.otsBytes)
      expect(parsed.ok).toBe(true)
      if (parsed.ok) {
        expect(parsed.parsed.fileDigestHex).toBe(digest.toString('hex'))
        // At submit time we should have at least pending (no bitcoin yet — that takes hours)
        const hasPending = parsed.parsed.attestations.some((a) => a.kind === 'pending')
        const hasBitcoin = parsed.parsed.attestations.some((a) => a.kind === 'bitcoin')
        expect(hasPending || hasBitcoin).toBe(true)
      }
    },
    60_000,
  )
})
