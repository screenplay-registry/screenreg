/**
 * Cross-runtime OTS calendar submission (pure TS). Network is mocked via an
 * injected fetch; the mock builder is exercised offline. The same engine backs
 * both the CLI and the browser /create/ page.
 */

import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import {
  submitDigestToCalendars,
  buildMockOts,
  MOCK_CALENDAR_URL,
} from '../../../src/shared/anchors/ots-submit.js'
import { parseOts, verifyOtsAgainstFileDigest } from '../../../src/anchors/ots-verify.js'

const digest = new Uint8Array(createHash('sha256').update('shared-submit-test').digest())

/** A valid OTS pending sub-tree (what a calendar's /digest returns), reused as a fake response. */
const PENDING_SUBTREE = (() => {
  // Reuse buildMockOts to mint a full .ots, then peel off the header+op+digest to
  // recover just the pending sub-tree bytes a calendar would return.
  const full = buildMockOts(digest, 'https://cal.example/')
  // header(magic 31 + version 1 + OP_SHA256 1 + digest 32) = 65 bytes; the rest is the sub-tree.
  return full.slice(65)
})()

function fetchReturning(status: number, body: Uint8Array, ctype = 'application/octet-stream'): typeof fetch {
  return (async () =>
    new Response(body, { status, headers: { 'content-type': ctype } })) as unknown as typeof fetch
}

describe('submitDigestToCalendars', () => {
  it('assembles a proof once ≥minCalendars accept', async () => {
    const r = await submitDigestToCalendars({
      fileDigest: digest,
      calendars: ['https://a.test', 'https://b.test'],
      minCalendars: 2,
      fetchImpl: fetchReturning(200, PENDING_SUBTREE),
    })
    expect(r.ok).toBe(true)
    if (r.ok) {
      const parsed = parseOts(Buffer.from(r.otsBytes))
      expect(parsed.ok).toBe(true)
      if (parsed.ok) {
        expect(parsed.parsed.fileDigestHex).toBe(Buffer.from(digest).toString('hex'))
        expect(parsed.parsed.attestations.length).toBe(2) // one per calendar
      }
    }
  })

  it('fails when fewer than minCalendars accept (and reports per-calendar results)', async () => {
    const r = await submitDigestToCalendars({
      fileDigest: digest,
      calendars: ['https://a.test', 'https://b.test'],
      minCalendars: 2,
      // first ok, second 500
      fetchImpl: (async (url: string) =>
        url.includes('a.test')
          ? new Response(PENDING_SUBTREE, { status: 200, headers: { 'content-type': 'application/octet-stream' } })
          : new Response('nope', { status: 500 })) as unknown as typeof fetch,
    })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.reason).toMatch(/need ≥2/)
      expect(r.results.filter((x) => x.ok).length).toBe(1)
    }
  })

  it('treats a hanging calendar as a timeout (no hang) via the per-request abort', async () => {
    const r = await submitDigestToCalendars({
      fileDigest: digest,
      calendars: ['https://slow.test'],
      minCalendars: 1,
      timeoutMs: 30,
      fetchImpl: ((_url: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })))
        })) as unknown as typeof fetch,
    })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.results[0]?.error).toMatch(/timed out/)
  })

  it('rejects a wrong-length digest', async () => {
    const r = await submitDigestToCalendars({ fileDigest: new Uint8Array(16), fetchImpl: fetchReturning(200, PENDING_SUBTREE) })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toMatch(/32 bytes/)
  })

  it('blinds the submitted value: posts SHA256(digest‖nonce), embeds the nonce, keeps fileDigest', async () => {
    let posted: Uint8Array | undefined
    const r = await submitDigestToCalendars({
      fileDigest: digest,
      calendars: ['https://a.test'],
      minCalendars: 1,
      fetchImpl: (async (_url: string, init: RequestInit) => {
        posted = new Uint8Array(init.body as Uint8Array)
        return new Response(PENDING_SUBTREE, { status: 200, headers: { 'content-type': 'application/octet-stream' } })
      }) as unknown as typeof fetch,
    })
    expect(r.ok).toBe(true)
    if (!r.ok || !posted) return
    // The calendar received a 32-byte value that is NOT the raw (public) claim hash.
    expect(posted.length).toBe(32)
    expect(Buffer.from(posted).equals(Buffer.from(digest))).toBe(false)
    // The proof embeds OP_APPEND(nonce)+OP_SHA256 right after magic(31)+ver(1)+OP_SHA256(1)+digest(32).
    const ots = r.otsBytes
    expect(ots[65]).toBe(0xf0) // OP_APPEND
    expect(ots[66]).toBe(16) // varuint nonce length
    const nonce = ots.slice(67, 67 + 16)
    // The submitted value is exactly SHA256(digest ‖ nonce-from-proof).
    const recomputed = createHash('sha256').update(Buffer.concat([Buffer.from(digest), Buffer.from(nonce)])).digest()
    expect(Buffer.from(posted).equals(recomputed)).toBe(true)
    // The top-level file digest is still the original claim hash.
    const parsed = parseOts(Buffer.from(ots))
    expect(parsed.ok).toBe(true)
    if (parsed.ok) expect(parsed.parsed.fileDigestHex).toBe(Buffer.from(digest).toString('hex'))
  })

  it('invokes onResult per calendar', async () => {
    const seen: string[] = []
    await submitDigestToCalendars({
      fileDigest: digest,
      calendars: ['https://a.test', 'https://b.test'],
      minCalendars: 1,
      fetchImpl: fetchReturning(200, PENDING_SUBTREE),
      onResult: (r) => seen.push(r.url),
    })
    expect(seen.sort()).toEqual(['https://a.test', 'https://b.test'])
  })
})

describe('buildMockOts', () => {
  it('builds a parseable, pending, non-anchored .ots offline', () => {
    const ots = Buffer.from(buildMockOts(digest))
    const parsed = parseOts(ots)
    expect(parsed.ok).toBe(true)
    if (parsed.ok) {
      expect(parsed.parsed.fileDigestHex).toBe(Buffer.from(digest).toString('hex'))
      expect(parsed.parsed.attestations.length).toBe(1)
      expect(parsed.parsed.attestations[0]?.kind).toBe('pending')
      if (parsed.parsed.attestations[0]?.kind === 'pending') {
        expect(parsed.parsed.attestations[0].calendarUrl).toBe(MOCK_CALENDAR_URL)
      }
    }
    const v = verifyOtsAgainstFileDigest({ otsBytes: ots, expectedFileDigest: Buffer.from(digest) })
    expect(v.ok).toBe(true)
    if (v.ok) expect(v.bitcoinAnchored).toBe(false)
  })
})
