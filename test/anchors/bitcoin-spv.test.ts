/**
 * Bitcoin SPV core: byte-order handling and the merkle-root comparison that
 * decides whether an OTS Bitcoin attestation genuinely commits to a block.
 * All vectors are synthetic or well-known historical blocks — no network.
 */

import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import {
  reverseHexBytes,
  verifyAttestationAgainstHeader,
  verifyAttestationWithSource,
  type BitcoinBlockHeader,
  type BitcoinHeaderSource,
} from '../../src/anchors/bitcoin-spv.js'
import {
  parseOts,
  HEADER_MAGIC,
  OP_SHA256,
  ATTESTATION_MARKER,
  TAG_BITCOIN_BLOCK_HEADER,
} from '../../src/anchors/ots-verify.js'

// Bitcoin genesis block, height 0 — merkle root in Bitcoin Core DISPLAY order.
const GENESIS_MERKLE_DISPLAY = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
const GENESIS_HASH = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'

/** LEB128 unsigned varint, matching the OTS Reader.readVarUint decoder. */
function varuint(n: number): Buffer {
  const out: number[] = []
  let v = n
  for (;;) {
    let b = v & 0x7f
    v = Math.floor(v / 128)
    if (v > 0) b |= 0x80
    out.push(b)
    if (v === 0) break
  }
  return Buffer.from(out)
}

/** Build a minimal .ots: magic + v1 + sha256 file-op + digest + [ops] + a bitcoin attestation. */
function buildOtsWithBitcoinAttestation(digest: Buffer, height: number, ops: Buffer = Buffer.alloc(0)): Buffer {
  const attPayload = varuint(height)
  return Buffer.concat([
    HEADER_MAGIC,
    varuint(1), // major version
    Buffer.from([OP_SHA256]), // file_hash_op
    digest,
    ops,
    Buffer.from([ATTESTATION_MARKER]),
    TAG_BITCOIN_BLOCK_HEADER,
    varuint(attPayload.length),
    attPayload,
  ])
}

describe('reverseHexBytes', () => {
  it('reverses byte-wise', () => {
    expect(reverseHexBytes('0102')).toBe('0201')
    expect(reverseHexBytes('aabbcc')).toBe('ccbbaa')
  })
  it('is its own inverse on a 32-byte root', () => {
    expect(reverseHexBytes(reverseHexBytes(GENESIS_MERKLE_DISPLAY))).toBe(GENESIS_MERKLE_DISPLAY)
  })
  it('throws on odd-length hex', () => {
    expect(() => reverseHexBytes('abc')).toThrow()
  })
})

describe('verifyAttestationAgainstHeader', () => {
  const internal = reverseHexBytes(GENESIS_MERKLE_DISPLAY) // OTS commits internal LE
  const header: BitcoinBlockHeader = {
    height: 0,
    merkleRoot: GENESIS_MERKLE_DISPLAY,
    blockHash: GENESIS_HASH,
    time: 1231006505,
  }

  it('accepts when the internal root reverses to the header display root', () => {
    const v = verifyAttestationAgainstHeader({ blockHeight: 0, merkleRoot: internal }, header)
    expect(v.ok).toBe(true)
    if (v.ok) {
      expect(v.merkleRootDisplay).toBe(GENESIS_MERKLE_DISPLAY)
      expect(v.blockHash).toBe(GENESIS_HASH)
      expect(v.time).toBe(1231006505)
    }
  })

  it('rejects a merkle-root mismatch (forged proof)', () => {
    const wrong = { ...header, merkleRoot: 'f'.repeat(64) }
    const v = verifyAttestationAgainstHeader({ blockHeight: 0, merkleRoot: internal }, wrong)
    expect(v.ok).toBe(false)
    if (!v.ok) expect(v.reason).toMatch(/merkle root mismatch/)
  })

  it('rejects a height mismatch between attestation and header', () => {
    const v = verifyAttestationAgainstHeader({ blockHeight: 1, merkleRoot: internal }, header)
    expect(v.ok).toBe(false)
    if (!v.ok) expect(v.reason).toMatch(/height/)
  })

  it('rejects a malformed attestation root', () => {
    const v = verifyAttestationAgainstHeader({ blockHeight: 0, merkleRoot: 'abcd' }, header)
    expect(v.ok).toBe(false)
    if (!v.ok) expect(v.reason).toMatch(/not 32 bytes/)
  })

  it('comparison is case-insensitive', () => {
    const v = verifyAttestationAgainstHeader(
      { blockHeight: 0, merkleRoot: internal.toUpperCase() },
      { ...header, merkleRoot: GENESIS_MERKLE_DISPLAY.toUpperCase() },
    )
    expect(v.ok).toBe(true)
  })
})

describe('verifyAttestationWithSource', () => {
  const internal = reverseHexBytes(GENESIS_MERKLE_DISPLAY)

  it('verifies against a source that returns a matching header', async () => {
    const source: BitcoinHeaderSource = {
      label: 'fake',
      trustless: true,
      getBlockHeaderByHeight: async (height) => ({
        height,
        merkleRoot: GENESIS_MERKLE_DISPLAY,
        blockHash: GENESIS_HASH,
      }),
    }
    const v = await verifyAttestationWithSource({ blockHeight: 0, merkleRoot: internal }, source)
    expect(v.ok).toBe(true)
  })

  it('reports fetchFailed (not a mismatch) when the source throws', async () => {
    const source: BitcoinHeaderSource = {
      label: 'unreachable',
      trustless: false,
      getBlockHeaderByHeight: async () => {
        throw new Error('ECONNREFUSED')
      },
    }
    const v = await verifyAttestationWithSource({ blockHeight: 0, merkleRoot: internal }, source)
    expect(v.ok).toBe(false)
    if (!v.ok) {
      expect(v.fetchFailed).toBe(true)
      expect(v.reason).toMatch(/could not fetch/)
    }
  })
})

describe('OTS parser exposes the Bitcoin attestation merkle root', () => {
  it('captures the file digest as the merkle root when no ops precede the attestation', () => {
    const digest = Buffer.alloc(32, 0xab)
    const r = parseOts(buildOtsWithBitcoinAttestation(digest, 100))
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.parsed.attestations).toHaveLength(1)
      const att = r.parsed.attestations[0]!
      expect(att.kind).toBe('bitcoin')
      if (att.kind === 'bitcoin') {
        expect(att.blockHeight).toBe(100)
        expect(att.merkleRoot).toBe(digest.toString('hex'))
      }
    }
  })

  it('rejects a bitcoin attestation payload with trailing bytes past the height', () => {
    const digest = Buffer.alloc(32, 0x22)
    // Hand-build a payload of [height=5, 0xff trailing] and an oversized declared length.
    const bad = Buffer.concat([
      HEADER_MAGIC,
      varuint(1),
      Buffer.from([OP_SHA256]),
      digest,
      Buffer.from([ATTESTATION_MARKER]),
      TAG_BITCOIN_BLOCK_HEADER,
      varuint(2), // payload length = 2
      Buffer.from([5, 0xff]), // height varint (5) + a stray trailing byte
    ])
    const r = parseOts(bad)
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.reason).toMatch(/trailing bytes past the height/)
  })

  it('captures the accumulated msg (after an op) as the merkle root, with a multi-byte height', () => {
    const digest = Buffer.alloc(32, 0x11)
    const expected = createHash('sha256').update(digest).digest().toString('hex')
    const r = parseOts(buildOtsWithBitcoinAttestation(digest, 800000, Buffer.from([OP_SHA256])))
    expect(r.ok).toBe(true)
    if (r.ok) {
      const att = r.parsed.attestations[0]!
      if (att.kind === 'bitcoin') {
        expect(att.blockHeight).toBe(800000)
        expect(att.merkleRoot).toBe(expected)
      } else {
        throw new Error('expected a bitcoin attestation')
      }
    }
  })
})
