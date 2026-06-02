/**
 * Tests for the finalize engine (the OpenTimestamps "upgrade" performed in TS).
 *
 * Strategy: drive the engine with the committed *real* pending fixture
 * (`fixture-01-mock.ots`, which carries a genuine PendingAttestation) and a fake
 * `fetch` standing in for the calendar's `/timestamp/<commitment>` endpoint. The
 * spliced output is cross-checked with the INDEPENDENT Node verifier (`parseOts`)
 * so a structural bug in the splice cannot pass unnoticed.
 *
 * End-to-end confirmation against live public calendars is a separate manual
 * check (it needs a real, mined commitment); these tests pin the structure,
 * the splice, idempotency, graceful pending, and notifier isolation offline.
 */

import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import { finalizeProof } from '../../../src/shared/finalize/finalize.js'
import type { FinalizeEvent } from '../../../src/shared/finalize/types.js'
import type { FinalizeNotifier } from '../../../src/shared/finalize/notifier.js'
import { encodeVarUint } from '../../../src/shared/anchors/ots-build.js'
import { parseOts } from '../../../src/anchors/ots-verify.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(__dirname, '..', '..', '..', 'spec', 'v1', 'testvectors', 'ots')
const mockPending = new Uint8Array(readFileSync(join(FIXTURE_DIR, 'fixture-01-mock.ots')))

/** Copy bytes into a fresh, exactly-sized ArrayBuffer (a `Response.arrayBuffer()` returns `ArrayBuffer`). */
function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(u8.byteLength)
  copy.set(u8)
  return copy.buffer as ArrayBuffer
}

const TAG_BITCOIN = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]
const TAG_PENDING = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]

/** A minimal valid Timestamp sub-tree: the commitment is directly Bitcoin-attested at `height`. */
function bitcoinSubtree(height: number): Uint8Array {
  const payload = encodeVarUint(height)
  const out = [0x00, ...TAG_BITCOIN, ...encodeVarUint(payload.length), ...payload]
  return new Uint8Array(out)
}

/** A still-pending sub-tree (commitment → another pending attestation; no progress). */
function pendingSubtree(url: string): Uint8Array {
  const urlBytes = [...url].map((c) => c.charCodeAt(0))
  const payload = [...encodeVarUint(urlBytes.length), ...urlBytes]
  const out = [0x00, ...TAG_PENDING, ...encodeVarUint(payload.length), ...payload]
  return new Uint8Array(out)
}

const HEADER_MAGIC = [
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]

function pendingLeaf(url: string): number[] {
  const urlBytes = [...url].map((c) => c.charCodeAt(0))
  const payload = [...encodeVarUint(urlBytes.length), ...urlBytes]
  return [0x00, ...TAG_PENDING, ...encodeVarUint(payload.length), ...payload]
}

/** Assemble a v1 .ots from a 32-byte file digest and a raw timestamp-tree body. */
function assembleOts(treeBody: number[]): Uint8Array {
  const fileDigest = new Uint8Array(32).fill(0xab)
  return new Uint8Array([...HEADER_MAGIC, 1, 0x08, ...fileDigest, ...treeBody])
}

const liveFixturePath = join(FIXTURE_DIR, 'fixture-01-live.ots')
const liveFixture = existsSync(liveFixturePath) ? new Uint8Array(readFileSync(liveFixturePath)) : null

interface FakeFetchOptions {
  body?: Uint8Array
  ok?: boolean
  throwErr?: boolean
}

/** Build a fake `fetch` that records the requested URLs and returns a fixed response. */
function fakeFetch(opts: FakeFetchOptions) {
  const calls: string[] = []
  const impl = async (url: string | URL): Promise<Response> => {
    calls.push(String(url))
    if (opts.throwErr) throw new Error('network down')
    const body = opts.body ?? new Uint8Array(0)
    return {
      ok: opts.ok ?? true,
      arrayBuffer: async () => toArrayBuffer(body),
    } as unknown as Response
  }
  return { impl: impl as unknown as typeof fetch, calls }
}

describe('finalizeProof: pending → confirmed splice', () => {
  it('folds a Bitcoin attestation in and the result verifies via the independent parser', async () => {
    const fetcher = fakeFetch({ body: bitcoinSubtree(875_432) })
    const r = await finalizeProof({ otsBytes: mockPending, fetchImpl: fetcher.impl })

    expect(r.status).toBe('confirmed')
    expect(r.bitcoinBlockHeights).toContain(875_432)

    // Queried the calendar from the fixture, at /timestamp/<64-hex commitment>.
    expect(fetcher.calls.length).toBe(1)
    expect(fetcher.calls[0]).toMatch(/^https:\/\/mock\.calendar\.example\/timestamp\/[0-9a-f]{64}$/)

    // Cross-check with the Node verifier: parses, and now carries a Bitcoin attestation.
    const reparsed = parseOts(Buffer.from(r.otsBytes))
    expect(reparsed.ok).toBe(true)
    if (reparsed.ok) {
      expect(reparsed.parsed.attestations.some((a) => a.kind === 'bitcoin')).toBe(true)
    }
  })

  it('leaves the committed claim hash (file digest) untouched', async () => {
    const before = parseOts(Buffer.from(mockPending))
    const fetcher = fakeFetch({ body: bitcoinSubtree(900_000) })
    const r = await finalizeProof({ otsBytes: mockPending, fetchImpl: fetcher.impl })
    const after = parseOts(Buffer.from(r.otsBytes))
    expect(before.ok && after.ok).toBe(true)
    if (before.ok && after.ok) {
      expect(after.parsed.fileDigestHex).toBe(before.parsed.fileDigestHex)
    }
  })
})

describe('finalizeProof: stays pending (no false confirmation)', () => {
  it('stays pending when the calendar 404s, returning the input unchanged', async () => {
    const fetcher = fakeFetch({ ok: false })
    const r = await finalizeProof({ otsBytes: mockPending, fetchImpl: fetcher.impl })
    expect(r.status).toBe('pending')
    expect(r.otsBytes).toBe(mockPending)
  })

  it('stays pending when the calendar returns a still-pending sub-tree', async () => {
    const fetcher = fakeFetch({ body: pendingSubtree('https://mock.calendar.example/') })
    const r = await finalizeProof({ otsBytes: mockPending, fetchImpl: fetcher.impl })
    expect(r.status).toBe('pending')
  })

  it('stays pending (never throws) when the network is down', async () => {
    const fetcher = fakeFetch({ throwErr: true })
    const r = await finalizeProof({ otsBytes: mockPending, fetchImpl: fetcher.impl })
    expect(r.status).toBe('pending')
    expect(r.otsBytes).toBe(mockPending)
  })

  it('stays pending when the calendar returns junk bytes', async () => {
    const fetcher = fakeFetch({ body: new Uint8Array([1, 2, 3, 4, 5]) })
    const r = await finalizeProof({ otsBytes: mockPending, fetchImpl: fetcher.impl })
    expect(r.status).toBe('pending')
  })
})

describe('finalizeProof: idempotent on an already-confirmed proof', () => {
  it('returns confirmed WITHOUT contacting any calendar', async () => {
    // First, finalize the pending fixture into a confirmed proof.
    const first = await finalizeProof({ otsBytes: mockPending, fetchImpl: fakeFetch({ body: bitcoinSubtree(111) }).impl })
    expect(first.status).toBe('confirmed')

    // Feeding the confirmed proof back must short-circuit to confirmed with no fetch.
    const fetcher = fakeFetch({ body: bitcoinSubtree(222) })
    const again = await finalizeProof({ otsBytes: first.otsBytes, fetchImpl: fetcher.impl })
    expect(again.status).toBe('confirmed')
    expect(again.bitcoinBlockHeights).toContain(111)
    expect(fetcher.calls.length).toBe(0)
  })
})

describe('finalizeProof: errors and notifier', () => {
  it('reports error on unparseable input', async () => {
    const r = await finalizeProof({ otsBytes: new Uint8Array([1, 2, 3]), fetchImpl: fakeFetch({}).impl })
    expect(r.status).toBe('error')
    expect(r.reason).toBeTruthy()
  })

  it('emits a confirmed event carrying the upgraded bytes', async () => {
    const events: FinalizeEvent[] = []
    const notifier: FinalizeNotifier = { notify: (e) => { events.push(e) } }
    const r = await finalizeProof({ otsBytes: mockPending, fetchImpl: fakeFetch({ body: bitcoinSubtree(7) }).impl, notifier })
    expect(r.status).toBe('confirmed')
    const confirmed = events.find((e) => e.type === 'confirmed')
    expect(confirmed).toBeDefined()
    if (confirmed && confirmed.type === 'confirmed') {
      expect(confirmed.claimHash).toMatch(/^sha256:[0-9a-f]{64}$/)
      expect(confirmed.bitcoinBlockHeights).toContain(7)
    }
  })

  it('a throwing notifier never breaks finalization', async () => {
    const notifier: FinalizeNotifier = { notify: () => { throw new Error('notifier boom') } }
    const r = await finalizeProof({ otsBytes: mockPending, fetchImpl: fakeFetch({ body: bitcoinSubtree(9) }).impl, notifier })
    expect(r.status).toBe('confirmed')
  })

  it('a rejecting async notifier never breaks finalization', async () => {
    const notifier: FinalizeNotifier = { notify: async () => { throw new Error('async boom') } }
    const r = await finalizeProof({ otsBytes: mockPending, fetchImpl: fakeFetch({ body: bitcoinSubtree(9) }).impl, notifier })
    expect(r.status).toBe('confirmed')
  })
})

describe('finalizeProof: hardening', () => {
  it('errors on an input whose pending URL exceeds the max length (matches the canonical parser)', async () => {
    const ots = assembleOts(pendingLeaf('https://' + 'a'.repeat(1100)))
    const r = await finalizeProof({ otsBytes: ots, fetchImpl: fakeFetch({ body: bitcoinSubtree(1) }).impl })
    expect(r.status).toBe('error')
  })

  it('errors on an input whose pending URL lacks an http(s):// scheme', async () => {
    const ots = assembleOts(pendingLeaf('ftp://mock.calendar.example/'))
    const r = await finalizeProof({ otsBytes: ots, fetchImpl: fakeFetch({ body: bitcoinSubtree(1) }).impl })
    expect(r.status).toBe('error')
  })

  it('errors on an over-large input proof', async () => {
    const huge = new Uint8Array(8 * 1024 * 1024 + 1)
    const r = await finalizeProof({ otsBytes: huge, fetchImpl: fakeFetch({ body: bitcoinSubtree(1) }).impl })
    expect(r.status).toBe('error')
  })

  it('stays pending when a calendar returns an over-large body (capped read)', async () => {
    const fetcher = fakeFetch({ body: new Uint8Array(1024 * 1024 + 1) })
    const r = await finalizeProof({ otsBytes: mockPending, fetchImpl: fetcher.impl })
    expect(r.status).toBe('pending')
  })

  // The live fixture is a real 3-calendar pending proof. Skips cleanly if absent.
  it.skipIf(liveFixture === null)('confirms via ONE calendar while others 404 (independent multi-calendar)', async () => {
    const calls: string[] = []
    const impl = (async (url: string | URL): Promise<Response> => {
      calls.push(String(url))
      const ok = String(url).includes('alice')
      const body = ok ? bitcoinSubtree(875_000) : new Uint8Array(0)
      return { ok, arrayBuffer: async () => toArrayBuffer(body) } as unknown as Response
    }) as unknown as typeof fetch

    const r = await finalizeProof({ otsBytes: liveFixture as Uint8Array, fetchImpl: impl })
    expect(r.status).toBe('confirmed')
    expect(r.bitcoinBlockHeights).toContain(875_000)
    // The two un-upgraded calendars remain listed as pending.
    expect(r.pendingCalendars.length).toBe(2)
    expect(calls.length).toBe(3)
    const reparsed = parseOts(Buffer.from(r.otsBytes))
    expect(reparsed.ok).toBe(true)
    if (reparsed.ok) expect(reparsed.parsed.attestations.some((a) => a.kind === 'bitcoin')).toBe(true)
  })

  it.skipIf(liveFixture === null)("one calendar's junk response cannot discard another's valid upgrade", async () => {
    const impl = (async (url: string | URL): Promise<Response> => {
      const u = String(url)
      let body: Uint8Array = new Uint8Array(0)
      let ok = true
      if (u.includes('alice')) body = bitcoinSubtree(880_000)
      else if (u.includes('bob')) body = new Uint8Array([9, 9, 9, 9]) // junk, individually invalid
      else ok = false // finney 404s
      return { ok, arrayBuffer: async () => toArrayBuffer(body) } as unknown as Response
    }) as unknown as typeof fetch

    const r = await finalizeProof({ otsBytes: liveFixture as Uint8Array, fetchImpl: impl })
    expect(r.status).toBe('confirmed')
    expect(r.bitcoinBlockHeights).toContain(880_000)
  })
})
