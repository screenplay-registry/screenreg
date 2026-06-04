import { describe, it, expect } from 'vitest'
import { normalize, contentHashOfNormalized } from '../../src/normalize/v1-strict.js'
import { detectScenes } from '../../src/merkle/scene-tree.js'

/**
 * Regression: the Node reference impl decodes input via Buffer.prototype.toString('utf8').
 * A plain Uint8Array's toString() ignores the encoding and yields comma-joined byte
 * values, which previously corrupted the normalized bytes (and the contentHash) and
 * caused detectScenes to find zero scenes — silently, with no error. SDK consumers
 * commonly hold a Uint8Array (fetch()/File APIs), so the public byte-consuming entry
 * points must treat a Uint8Array identically to the equivalent Buffer.
 */
describe('Uint8Array input parity (Node reference impl)', () => {
  const sample =
    'INT. ROOM - DAY\r\n\r\nA character stands.\r\n\r\nEXT. STREET - NIGHT\r\n\r\nRain falls.\n'
  const asBuffer = Buffer.from(sample, 'utf8')
  // A genuine, non-Buffer Uint8Array view over the same bytes.
  const asUint8 = new Uint8Array(asBuffer.buffer, asBuffer.byteOffset, asBuffer.byteLength)

  it('normalize() produces byte-identical output for Buffer and Uint8Array', () => {
    const a = normalize(asBuffer)
    const b = normalize(asUint8)
    expect(a.ok).toBe(true)
    expect(b.ok).toBe(true)
    if (a.ok && b.ok) {
      expect(Buffer.from(b.normalized).equals(a.normalized)).toBe(true)
      expect(contentHashOfNormalized(b.normalized)).toBe(contentHashOfNormalized(a.normalized))
      // CRLF -> LF actually happened (proves the bytes were decoded, not mangled).
      expect(a.normalized.includes(0x0d)).toBe(false)
    }
  })

  it('detectScenes() finds the same scenes for Buffer and Uint8Array', () => {
    const n = normalize(asBuffer)
    if (!n.ok) throw new Error('normalize failed')
    const fromBuffer = detectScenes(n.normalized)
    const fromUint8 = detectScenes(new Uint8Array(n.normalized))
    expect(fromBuffer.length).toBe(2)
    expect(fromUint8.length).toBe(fromBuffer.length)
    expect(fromUint8.map((s) => [s.byteStart, s.byteEnd])).toEqual(
      fromBuffer.map((s) => [s.byteStart, s.byteEnd]),
    )
  })

  it('a Uint8Array input never silently yields an empty/garbage scene set', () => {
    const n = normalize(asUint8)
    if (!n.ok) throw new Error('normalize failed')
    expect(detectScenes(n.normalized).length).toBe(2)
  })
})
