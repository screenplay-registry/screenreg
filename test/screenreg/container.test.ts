/**
 * Tests for the `.screenreg` container (Section 11).
 *
 * Covers: deterministic store-only zip round-trips, full vs. evidence variants, descriptor
 * integrity (size + sha256), the invariant that bundling never changes `claimHash`, the OTS
 * `proofRef` rewrite, error paths, and real-world `unzip` compatibility.
 */

import { describe, it, expect } from 'vitest'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { contentHash } from '../../src/shared/normalize/v1-strict.js'
import { buildCommittedClaim, buildEnvelope } from '../../src/shared/envelope/build.js'
import { computeClaimHash } from '../../src/shared/envelope/claim-hash.js'
import { validateEnvelope } from '../../src/shared/envelope/validate.js'
import type { Envelope, OpenTimestampsProof } from '../../src/shared/envelope/types.js'

import {
  buildScreenreg,
  buildEvidenceScreenreg,
  readScreenreg,
  verifyEntryDigests,
  ScreenregError,
} from '../../src/shared/screenreg/index.js'
import { zipStore, unzipStore, ZipError } from '../../src/shared/screenreg/zip.js'

const SCRIPT = `Title: The Doctor's Mom

FADE IN:

INT. KITCHEN - DAY

She stirs the soup. Steam rises.

MOM
You'll be late.
`

const enc = new TextEncoder()

function bytesEqual(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  if (!a || !b) return false
  return Buffer.from(a).equals(Buffer.from(b))
}

/** A realistic envelope with a single OTS proof whose proofRef is a writer-style filename. */
async function makeEnvelope(): Promise<{ envelope: Envelope; sourceBytes: Uint8Array; otsBytes: Uint8Array; claimHash: string }> {
  const sourceBytes = enc.encode(SCRIPT)
  const ch = await contentHash(sourceBytes)
  if (!ch) throw new Error('test fixture: source did not normalize')
  const claim = buildCommittedClaim({ contentHash: ch })
  const claimHash = await computeClaimHash(claim)
  const proof: OpenTimestampsProof = {
    type: 'opentimestamps',
    claimHash,
    proofRef: 'The Doctor’s Mom.proof.ots',
    submittedAt: '2026-05-31T12:00:00Z',
  }
  const envelope = await buildEnvelope(claim, { proofs: [proof] })
  const otsBytes = new Uint8Array([0x00, 0x4f, 0x54, 0x53, 0x01, 0x02, 0x03, 0xff]) // opaque stand-in
  return { envelope, sourceBytes, otsBytes, claimHash }
}

describe('zip: deterministic store-only round-trip', () => {
  it('round-trips entries byte-for-byte', () => {
    const entries = [
      { name: 'a.txt', bytes: enc.encode('hello') },
      { name: 'nested/b.bin', bytes: new Uint8Array([0, 1, 2, 255, 128]) },
      { name: 'empty', bytes: new Uint8Array(0) },
    ]
    const zip = zipStore(entries)
    const out = unzipStore(zip)
    expect(out.map((e) => e.name)).toEqual(['a.txt', 'nested/b.bin', 'empty'])
    expect(bytesEqual(out[0]!.bytes, entries[0]!.bytes)).toBe(true)
    expect(bytesEqual(out[1]!.bytes, entries[1]!.bytes)).toBe(true)
    expect(out[2]!.bytes.length).toBe(0)
  })

  it('is byte-identical across two builds of the same input', () => {
    const entries = [{ name: 'x', bytes: enc.encode('same') }]
    expect(bytesEqual(zipStore(entries), zipStore(entries))).toBe(true)
  })

  it('detects corruption via CRC-32', () => {
    const zip = zipStore([{ name: 'x', bytes: enc.encode('payload') }])
    // Flip a byte inside the stored data region (after the 30-byte local header + 1-byte name).
    zip[32] = zip[32]! ^ 0xff
    expect(() => unzipStore(zip)).toThrow(ZipError)
  })

  it('rejects malformed input with a clean ZipError, not a RangeError', () => {
    expect(() => unzipStore(new Uint8Array([1, 2, 3]))).toThrow(ZipError) // no EOCD
    // Truncated archive: keep the EOCD discoverable but lop off the central directory it points to.
    const zip = zipStore([{ name: 'longname.txt', bytes: enc.encode('some payload here') }])
    const truncated = zip.slice(0, 20) // header only; EOCD scan fails → ZipError, never a crash
    expect(() => unzipStore(truncated)).toThrow(ZipError)
    // Hostile central-directory offset in the EOCD must be caught by bounds checks.
    const bad = zip.slice()
    const eocd = bad.length - 22
    new DataView(bad.buffer, bad.byteOffset, bad.byteLength).setUint32(eocd + 16, 0xffffff, true)
    expect(() => unzipStore(bad)).toThrow(ZipError)
  })

  it('rejects central-directory records that do not tile the declared extent', () => {
    const dvOf = (z: Uint8Array) => new DataView(z.buffer, z.byteOffset, z.byteLength)
    const cdOffsetOf = (z: Uint8Array) => dvOf(z).getUint32(z.length - 22 + 16, true)

    // (a) Subtle: extraLen=10 keeps the record inside the buffer but pushes it past centralEnd —
    // the previous EOF-only check would have accepted this; the extent check must reject it.
    const a = zipStore([{ name: 'x.txt', bytes: enc.encode('hi') }])
    dvOf(a).setUint16(cdOffsetOf(a) + 30, 10, true)
    expect(() => unzipStore(a)).toThrow(ZipError)

    // (b) Gross: a huge extraLen runs past the buffer too.
    const b = zipStore([{ name: 'x.txt', bytes: enc.encode('hi') }])
    dvOf(b).setUint16(cdOffsetOf(b) + 30, 0xffff, true)
    expect(() => unzipStore(b)).toThrow(ZipError)

    // (c) EOCD declares centralSize=0 but a record is present → records don't fill the extent.
    const c = zipStore([{ name: 'x.txt', bytes: enc.encode('hi') }])
    dvOf(c).setUint32(c.length - 22 + 12, 0, true)
    expect(() => unzipStore(c)).toThrow(ZipError)
  })
})

describe('container: full bundle', () => {
  it('round-trips and preserves the envelope, source, and proof', async () => {
    const { envelope, sourceBytes, otsBytes } = await makeEnvelope()
    const bundle = await buildScreenreg({ envelope, otsBytes, sourceText: sourceBytes })
    const parsed = await readScreenreg(bundle)

    expect(parsed.descriptor.bundleType).toBe('full')
    expect(parsed.integrity.ok).toBe(true)
    expect(bytesEqual(parsed.sourceText, sourceBytes)).toBe(true)
    expect(bytesEqual(parsed.otsBytes, otsBytes)).toBe(true)
    expect(validateEnvelope(parsed.envelope).ok).toBe(true)
    expect(await verifyEntryDigests(bundle)).toEqual([])
  })

  it('is byte-deterministic', async () => {
    const { envelope, sourceBytes, otsBytes } = await makeEnvelope()
    const a = await buildScreenreg({ envelope, otsBytes, sourceText: sourceBytes })
    const b = await buildScreenreg({ envelope, otsBytes, sourceText: sourceBytes })
    expect(bytesEqual(a, b)).toBe(true)
  })

  it('rewrites the OTS proofRef to the in-archive name without changing claimHash', async () => {
    const { envelope, sourceBytes, otsBytes, claimHash } = await makeEnvelope()
    const bundle = await buildScreenreg({ envelope, otsBytes, sourceText: sourceBytes })
    const parsed = await readScreenreg(bundle)

    const ots = parsed.envelope.evidenceBundle.proofs.find((p) => p.type === 'opentimestamps') as
      | OpenTimestampsProof
      | undefined
    expect(ots?.proofRef).toBe('proof.ots')
    // The commitment is untouched: the recomputed claimHash equals the original.
    expect(parsed.envelope.evidenceBundle.committedClaimHash).toBe(claimHash)
    expect(await computeClaimHash(parsed.envelope.committedClaim)).toBe(claimHash)
  })

  it('does not mutate the caller-supplied envelope', async () => {
    const { envelope, sourceBytes, otsBytes } = await makeEnvelope()
    await buildScreenreg({ envelope, otsBytes, sourceText: sourceBytes })
    const ots = envelope.evidenceBundle.proofs[0] as OpenTimestampsProof
    expect(ots.proofRef).toBe('The Doctor’s Mom.proof.ots') // original, unchanged
  })
})

describe('container: evidence (proof-only) bundle', () => {
  it('omits the source text but keeps envelope + proof', async () => {
    const { envelope, otsBytes } = await makeEnvelope()
    const bundle = await buildEvidenceScreenreg({ envelope, otsBytes })
    const parsed = await readScreenreg(bundle)

    expect(parsed.descriptor.bundleType).toBe('evidence')
    expect(parsed.sourceText).toBeUndefined()
    expect(parsed.descriptor.contents.sourceText).toBeUndefined()
    expect(bytesEqual(parsed.otsBytes, otsBytes)).toBe(true)
    expect(validateEnvelope(parsed.envelope).ok).toBe(true)
    expect(parsed.integrity.ok).toBe(true)
    // Evidence bundle still proves existence+time: same committed claim hash as the full one.
    expect(await computeClaimHash(parsed.envelope.committedClaim)).toBe(
      envelope.evidenceBundle.committedClaimHash,
    )
  })
})

describe('container: integrity + error paths', () => {
  it('catches valid-CRC tampering in both the read path and verifyEntryDigests', async () => {
    const { envelope, sourceBytes, otsBytes } = await makeEnvelope()
    const bundle = await buildScreenreg({ envelope, otsBytes, sourceText: sourceBytes })
    // Flip a byte of an entry's data, then repack so CRCs are valid again — only the descriptor's
    // declared sha256 still witnesses the swap.
    const out = unzipStore(bundle)
    const idx = out.findIndex((e) => e.name === 'script.fountain')
    out[idx]!.bytes[0] = out[idx]!.bytes[0]! ^ 0xff
    const repacked = zipStore(out)

    const failures = await verifyEntryDigests(repacked)
    expect(failures.some((f) => f.includes('script.fountain'))).toBe(true)
    // The single verified read path must also surface it, not report ok.
    const parsed = await readScreenreg(repacked)
    expect(parsed.integrity.ok).toBe(false)
    expect(parsed.integrity.issues.some((f) => f.includes('script.fountain'))).toBe(true)
  })

  it('rejects a full bundle with no source text', async () => {
    const { envelope, otsBytes } = await makeEnvelope()
    await expect(buildScreenreg({ envelope, otsBytes })).rejects.toThrow(ScreenregError)
  })

  it('rejects an envelope whose OTS proof has no supplied bytes', async () => {
    const { envelope, sourceBytes } = await makeEnvelope()
    await expect(buildScreenreg({ envelope, sourceText: sourceBytes })).rejects.toThrow(ScreenregError)
  })

  it('rejects bytes that are not a .screenreg', async () => {
    const notAScreenreg = zipStore([{ name: 'random.txt', bytes: enc.encode('nope') }])
    await expect(readScreenreg(notAScreenreg)).rejects.toThrow(ScreenregError)
  })

  it('rejects a malformed descriptor with ScreenregError (not a raw TypeError)', async () => {
    // Descriptor that parses as JSON but has no contents/entries — must not throw a bare TypeError.
    const bad = zipStore([
      {
        name: 'screenreg.json',
        bytes: enc.encode(JSON.stringify({ format: 'urn:screenplay-registration-bundle:v1', bundleType: 'full' })),
      },
    ])
    await expect(readScreenreg(bad)).rejects.toThrow(ScreenregError)
  })

  it('rejects a full descriptor that declares a source not listed in entries', async () => {
    // The gap: bundleType "full" + contents.sourceText declared, but script.fountain appears in
    // neither entries[] nor the archive. Must be rejected, not read as intact with no source.
    const descriptor = {
      format: 'urn:screenplay-registration-bundle:v1',
      bundleType: 'full',
      contents: { descriptor: 'screenreg.json', envelope: 'envelope.json', sourceText: 'script.fountain' },
      entries: [{ path: 'envelope.json', role: 'envelope', bytes: 2, sha256: 'sha256:placeholder' }],
    }
    const bad = zipStore([
      { name: 'screenreg.json', bytes: enc.encode(JSON.stringify(descriptor)) },
      { name: 'envelope.json', bytes: enc.encode('{}') },
    ])
    await expect(readScreenreg(bad)).rejects.toThrow(ScreenregError)
  })

  it('reports integrity.ok === false when a declared, listed source is missing from the archive', async () => {
    // sourceText is declared AND listed in entries, but absent from the zip → digest check flags it.
    const descriptor = {
      format: 'urn:screenplay-registration-bundle:v1',
      bundleType: 'full',
      contents: { descriptor: 'screenreg.json', envelope: 'envelope.json', sourceText: 'script.fountain' },
      entries: [
        { path: 'envelope.json', role: 'envelope', bytes: 2, sha256: `sha256:${'0'.repeat(64)}` },
        { path: 'script.fountain', role: 'source-text', bytes: 5, sha256: `sha256:${'0'.repeat(64)}` },
      ],
    }
    const bundle = zipStore([
      { name: 'screenreg.json', bytes: enc.encode(JSON.stringify(descriptor)) },
      { name: 'envelope.json', bytes: enc.encode('{}') },
    ])
    const parsed = await readScreenreg(bundle)
    expect(parsed.integrity.ok).toBe(false)
    expect(parsed.integrity.issues.some((f) => f.includes('script.fountain'))).toBe(true)
  })

  it('rejects a descriptor whose bundleType disagrees with source-text presence', async () => {
    // bundleType "full" but no sourceText declared in contents → invariant violation.
    const descriptor = {
      format: 'urn:screenplay-registration-bundle:v1',
      bundleType: 'full',
      contents: { descriptor: 'screenreg.json', envelope: 'envelope.json' },
      entries: [{ path: 'envelope.json', role: 'envelope', bytes: 2, sha256: 'sha256:00' }],
    }
    const bad = zipStore([
      { name: 'screenreg.json', bytes: enc.encode(JSON.stringify(descriptor)) },
      { name: 'envelope.json', bytes: enc.encode('{}') },
    ])
    await expect(readScreenreg(bad)).rejects.toThrow(ScreenregError)
  })
})

describe('container: external unzip compatibility', () => {
  it('produces an archive the system unzip can list', async () => {
    let unzipAvailable = true
    try {
      execFileSync('unzip', ['-v'], { stdio: 'ignore' })
    } catch {
      unzipAvailable = false
    }
    if (!unzipAvailable) {
      // Rationale: this asserts interop with the OS `unzip`, which is not guaranteed on every
      // CI image. The pure-TS reader round-trip above already covers correctness; we only skip
      // the external-tool cross-check when the tool is absent.
      console.warn('skipping unzip-compat check: `unzip` not on PATH')
      return
    }
    const { envelope, sourceBytes, otsBytes } = await makeEnvelope()
    const bundle = await buildScreenreg({ envelope, otsBytes, sourceText: sourceBytes })
    const dir = mkdtempSync(join(tmpdir(), 'screenreg-'))
    try {
      const file = join(dir, 'test.screenreg')
      writeFileSync(file, bundle)
      const listing = execFileSync('unzip', ['-l', file], { encoding: 'utf8' })
      expect(listing).toContain('screenreg.json')
      expect(listing).toContain('envelope.json')
      expect(listing).toContain('script.fountain')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
