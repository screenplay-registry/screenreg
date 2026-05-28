/**
 * Tests for Drand timelock (Section 07, capability-flagged).
 *
 * Most tests are pure-math (round-time conversions, validation).
 * Live network tests are gated by SCREENREG_TEST_LIVE_DRAND=1.
 */

import { describe, it, expect } from 'vitest'
import {
  roundAtUnixTime,
  unixTimeOfRound,
  timelockEncrypt,
  timelockDecrypt,
  QUICKNET_CHAIN_HASH,
  QUICKNET_PUBLIC_KEY,
  QUICKNET_GENESIS_TIME,
  QUICKNET_PERIOD_SEC,
} from '../../src/timelock/drand.js'

describe('locked constants', () => {
  it('QUICKNET_CHAIN_HASH matches the published quicknet chain hash', () => {
    expect(QUICKNET_CHAIN_HASH).toBe('52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971')
  })
  it('QUICKNET_PUBLIC_KEY is 192 hex chars (96-byte BLS12-381 G2 element)', () => {
    expect(QUICKNET_PUBLIC_KEY.length).toBe(192)
  })
  it('QUICKNET_PERIOD_SEC is 3 (per Drand quicknet spec)', () => {
    expect(QUICKNET_PERIOD_SEC).toBe(3)
  })
})

describe('roundAtUnixTime / unixTimeOfRound — invertible', () => {
  it('round(unixTimeOfRound(N)) === N for various N', () => {
    for (const round of [1, 2, 100, 12345, 99999999]) {
      const t = unixTimeOfRound(round)
      const recovered = roundAtUnixTime(t)
      expect(recovered).toBe(round)
    }
  })

  it('rounds up: requesting unlock 1s after round N → round N+1', () => {
    const round = 1000
    const tOfRound = unixTimeOfRound(round)
    const t1Later = tOfRound + 1
    const expected = roundAtUnixTime(t1Later)
    // 1 second after round 1000 (which is genesis + 3000s) should round to round 1001
    expect(expected).toBe(round + 1)
  })

  it('rejects unlock time at or before genesis', () => {
    expect(() => roundAtUnixTime(QUICKNET_GENESIS_TIME - 10)).toThrow(/genesis/)
    expect(() => roundAtUnixTime(QUICKNET_GENESIS_TIME)).toThrow(/genesis/)
  })
})

describe('timelockEncrypt — refusal of past times', () => {
  it('refuses to encrypt with unlockAt in the past', async () => {
    const past = new Date(Date.now() - 1_000_000)
    await expect(
      timelockEncrypt({
        name: 'test',
        plaintext: Buffer.from('x'),
        unlockAt: past,
      }),
    ).rejects.toThrow(/Refusing to encrypt/)
  })

  it('refuses unlockAt = now', async () => {
    const now = new Date()
    await expect(
      timelockEncrypt({
        name: 'test',
        plaintext: Buffer.from('x'),
        unlockAt: now,
      }),
    ).rejects.toThrow(/Refusing to encrypt/)
  })
})

describe('timelockDecrypt — refusal when not yet unlocked', () => {
  it('returns not-yet-unlocked when the round is in the future', async () => {
    const farFutureRound = roundAtUnixTime(Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60) // +1 year
    const result = await timelockDecrypt({
      field: {
        name: 'test',
        ciphertext: 'placeholder',
        unlockAtRound: farFutureRound,
        unlockAt: new Date(unixTimeOfRound(farFutureRound) * 1000).toISOString(),
        drandChainHash: QUICKNET_CHAIN_HASH,
        drandPublicKey: QUICKNET_PUBLIC_KEY,
        scheme: 'tlock-bls12-381-quicknet',
      },
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('not-yet-unlocked')
  })

  it('returns chain-mismatch for unknown drandChainHash', async () => {
    const result = await timelockDecrypt({
      field: {
        name: 'test',
        ciphertext: 'placeholder',
        unlockAtRound: 1,
        unlockAt: '2020-01-01T00:00:00Z',
        drandChainHash: 'unknown-chain-hash',
        drandPublicKey: QUICKNET_PUBLIC_KEY,
        scheme: 'tlock-bls12-381-quicknet',
      },
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('chain-mismatch')
  })

  it('returns scheme-mismatch when the field declares an unsupported scheme', async () => {
    // Forger re-anchors a field under a different scheme; verifier must
    // reject before the round/decrypt steps. The on-chain commitment
    // includes `scheme`, so trusting only chainHash silently accepts
    // re-anchored fields from a different cryptographic scheme.
    const result = await timelockDecrypt({
      field: {
        name: 'test',
        ciphertext: 'placeholder',
        unlockAtRound: 1,
        unlockAt: '2020-01-01T00:00:00Z',
        drandChainHash: QUICKNET_CHAIN_HASH,
        drandPublicKey: QUICKNET_PUBLIC_KEY,
        scheme: 'tlock-future-scheme-v2',
      },
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('scheme-mismatch')
  })

  it('returns public-key-mismatch when the field declares a different drandPublicKey', async () => {
    // Forger points at a different (e.g. fork-chain) Drand group public key
    // while keeping matching chainHash + scheme. Verifier must enforce the
    // committed publicKey — otherwise a fork chain decryption would be
    // silently accepted.
    const result = await timelockDecrypt({
      field: {
        name: 'test',
        ciphertext: 'placeholder',
        unlockAtRound: 1,
        unlockAt: '2020-01-01T00:00:00Z',
        drandChainHash: QUICKNET_CHAIN_HASH,
        drandPublicKey: 'a'.repeat(96), // wrong public key (right format, wrong value)
        scheme: 'tlock-bls12-381-quicknet',
      },
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('public-key-mismatch')
  })
})

describe('live network: encrypt → wait → decrypt (opt-in)', () => {
  const liveEnabled = process.env.SCREENREG_TEST_LIVE_DRAND === '1'
  if (!liveEnabled) {
    it.skip('skipped — set SCREENREG_TEST_LIVE_DRAND=1 to enable (takes ~30s)', () => {})
    return
  }

  it('encrypts content with a near-future unlock, waits for it, decrypts to original', async () => {
    const plaintext = Buffer.from('the secret content', 'utf8')
    const unlockAt = new Date(Date.now() + 10_000) // unlock in 10s
    const field = await timelockEncrypt({ name: 'live-test', plaintext, unlockAt })
    expect(field.drandChainHash).toBe(QUICKNET_CHAIN_HASH)
    // Wait until unlock + a couple seconds buffer for round publication
    await new Promise((r) => setTimeout(r, 15_000))
    const result = await timelockDecrypt({ field })
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.plaintext.toString('utf8')).toBe('the secret content')
    }
  }, 30_000)
})
