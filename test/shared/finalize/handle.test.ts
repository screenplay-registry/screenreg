/**
 * Round-trip + robustness tests for the resumable finalize handle codec.
 *
 * The handle is what makes the serverless "come back and finish anchoring" link
 * work, so the contract that matters is: whatever pending `.ots` bytes go in
 * come back out byte-identical, the token is safe to drop in a URL fragment, and
 * a corrupt or hostile token is rejected rather than mis-decoded.
 */

import { describe, it, expect } from 'vitest'

import {
  encodePendingHandle,
  decodePendingHandle,
} from '../../../src/shared/finalize/handle.js'
import type { PendingHandleV1 } from '../../../src/shared/finalize/types.js'

const CLAIM = 'sha256:' + 'ab'.repeat(32)

/** A handle whose proof spans every byte value 0..255, repeated, incl. 0x00 and 0xff. */
function binaryHandle(): PendingHandleV1 {
  const ots = new Uint8Array(1024)
  for (let i = 0; i < ots.length; i++) ots[i] = i & 0xff
  return { v: 1, claimHash: CLAIM, ots, title: 'THE LAST REWRITE', createdAt: '2026-06-01T12:00:00.000Z' }
}

describe('pending-handle codec: round-trip', () => {
  it('restores every field exactly, including binary proof bytes', () => {
    const original = binaryHandle()
    const decoded = decodePendingHandle(encodePendingHandle(original))
    expect(decoded.v).toBe(1)
    expect(decoded.claimHash).toBe(original.claimHash)
    expect(decoded.title).toBe(original.title)
    expect(decoded.createdAt).toBe(original.createdAt)
    expect(Array.from(decoded.ots)).toEqual(Array.from(original.ots))
  })

  it('omits optional fields when absent (no empty-string leakage)', () => {
    const decoded = decodePendingHandle(
      encodePendingHandle({ v: 1, claimHash: CLAIM, ots: new Uint8Array([1, 2, 3]) }),
    )
    expect(decoded.title).toBeUndefined()
    expect(decoded.createdAt).toBeUndefined()
    expect(Array.from(decoded.ots)).toEqual([1, 2, 3])
  })

  it('preserves a Unicode title (UTF-8 round-trip)', () => {
    const decoded = decodePendingHandle(
      encodePendingHandle({ v: 1, claimHash: CLAIM, ots: new Uint8Array([9]), title: 'Café — Draft №3 🎬' }),
    )
    expect(decoded.title).toBe('Café — Draft №3 🎬')
  })

  it('round-trips proof lengths that exercise every base64 remainder (0,1,2 mod 3)', () => {
    for (const n of [1, 2, 3, 4, 5, 31, 32, 33, 256, 257, 511]) {
      const ots = new Uint8Array(n)
      for (let i = 0; i < n; i++) ots[i] = (i * 31 + 7) & 0xff
      const decoded = decodePendingHandle(encodePendingHandle({ v: 1, claimHash: CLAIM, ots }))
      expect(Array.from(decoded.ots)).toEqual(Array.from(ots))
    }
  })
})

describe('pending-handle codec: URL-fragment safety', () => {
  it('emits only unreserved URL-fragment characters (A-Z a-z 0-9 - _)', () => {
    const token = encodePendingHandle(binaryHandle())
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/)
  })
})

describe('pending-handle codec: rejects bad input', () => {
  it('refuses to encode an empty proof', () => {
    expect(() => encodePendingHandle({ v: 1, claimHash: CLAIM, ots: new Uint8Array(0) })).toThrow()
  })

  it('refuses to encode an oversized proof', () => {
    expect(() =>
      encodePendingHandle({ v: 1, claimHash: CLAIM, ots: new Uint8Array(64 * 1024 + 1) }),
    ).toThrow()
  })

  it('refuses an unsupported handle version', () => {
    // @ts-expect-error — exercising the runtime guard with an out-of-contract version
    expect(() => encodePendingHandle({ v: 2, claimHash: CLAIM, ots: new Uint8Array([1]) })).toThrow()
  })

  it('rejects a token with a non-base64url character', () => {
    expect(() => decodePendingHandle('not valid base64url!!')).toThrow()
  })

  it('rejects an empty token', () => {
    expect(() => decodePendingHandle('')).toThrow()
  })

  it('rejects a truncated token (field length exceeds payload)', () => {
    const token = encodePendingHandle(binaryHandle())
    expect(() => decodePendingHandle(token.slice(0, token.length - 8))).toThrow()
  })

  it('rejects an over-long token before allocating', () => {
    // All-alphabet so it passes the charset check; length alone must trip the cap.
    expect(() => decodePendingHandle('A'.repeat(100_001))).toThrow(/exceeds .* characters/)
  })

  it('rejects a non-canonical base64url token, 2-char remainder (nonzero unused bits)', () => {
    // 2-char chunk → 1 byte; "AB" has v1=1, whose low 4 bits are nonzero → rejected.
    expect(() => decodePendingHandle('AB')).toThrow(/non-canonical/)
  })

  it('rejects a non-canonical base64url token, 3-char remainder (nonzero unused bits)', () => {
    // 3-char chunk → 2 bytes; "AAB" has v2=1, whose low 2 bits are nonzero → rejected.
    expect(() => decodePendingHandle('AAB')).toThrow(/non-canonical/)
  })

  it('rejects malformed UTF-8 in a text field (fatal decode)', () => {
    // Build a frame by hand: version 1, a claimHash field containing a lone 0x80
    // continuation byte (invalid UTF-8), then empty title/createdAt and a 1-byte ots.
    const frame = new Uint8Array([
      1,
      0, 0, 0, 1, 0x80, // claimHash: len 1, byte 0x80 (invalid UTF-8 start)
      0, 0, 0, 0, // title: len 0
      0, 0, 0, 0, // createdAt: len 0
      0, 0, 0, 1, 0x09, // ots: len 1
    ])
    // base64url-encode the frame inline (mirror of the codec) to feed decode.
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    let token = ''
    let i = 0
    for (; i + 3 <= frame.length; i += 3) {
      const n = (frame[i]! << 16) | (frame[i + 1]! << 8) | frame[i + 2]!
      token += A[(n >> 18) & 63]! + A[(n >> 12) & 63]! + A[(n >> 6) & 63]! + A[n & 63]!
    }
    const rem = frame.length - i
    if (rem === 1) {
      const n = frame[i]! << 16
      token += A[(n >> 18) & 63]! + A[(n >> 12) & 63]!
    } else if (rem === 2) {
      const n = (frame[i]! << 16) | (frame[i + 1]! << 8)
      token += A[(n >> 18) & 63]! + A[(n >> 12) & 63]! + A[(n >> 6) & 63]!
    }
    expect(() => decodePendingHandle(token)).toThrow()
  })

  it('rejects a token whose leading (version-bearing) byte is corrupted', () => {
    // The first base64url char carries the high bits of the version byte; flipping
    // it changes the decoded version away from 1, which the decoder must reject.
    const ok = encodePendingHandle({ v: 1, claimHash: CLAIM, ots: new Uint8Array([1, 2, 3]) })
    const corrupted = (ok[0] === 'B' ? 'C' : 'B') + ok.slice(1)
    expect(() => decodePendingHandle(corrupted)).toThrow()
  })
})
