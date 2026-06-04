/**
 * CLI progress helpers. The spinner and countdown are gated on
 * `process.stderr.isTTY`; under vitest stderr is a pipe, so we exercise the
 * non-TTY paths (plain output, no ANSI codes) directly.
 */

import { describe, it, expect, vi, afterEach } from 'vitest'
import { startSpinner, formatDuration, countdownSleep } from '../../src/cli/progress.js'

function captureStderr(): { writes: string[]; restore: () => void } {
  const writes: string[] = []
  const spy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    writes.push(String(chunk))
    return true
  })
  return { writes, restore: () => spy.mockRestore() }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('formatDuration', () => {
  it('formats seconds, minutes, and hours', () => {
    expect(formatDuration(0)).toBe('0s')
    expect(formatDuration(45)).toBe('45s')
    expect(formatDuration(63)).toBe('1m03s')
    expect(formatDuration(600)).toBe('10m00s')
    expect(formatDuration(3700)).toBe('1h01m')
  })
  it('never goes negative', () => {
    expect(formatDuration(-5)).toBe('0s')
  })
})

describe('startSpinner (non-TTY)', () => {
  it('is silent by default — a pipe/CI log gets no extra bytes', () => {
    const cap = captureStderr()
    const stop = startSpinner('Working…')
    stop()
    stop() // idempotent
    cap.restore()
    expect(cap.writes.join('')).toBe('')
  })

  it('prints the label once (no ANSI/CR) when quietLabel is set', () => {
    const cap = captureStderr()
    const stop = startSpinner('Working…', { quietLabel: true })
    stop()
    cap.restore()
    const out = cap.writes.join('')
    expect(out).toBe('Working…\n')
    // eslint-disable-next-line no-control-regex
    expect(out).not.toMatch(/\x1b\[/)
    expect(out).not.toContain('\r')
  })
})

describe('countdownSleep (non-TTY)', () => {
  it('prints a single pending line and resolves', async () => {
    const cap = captureStderr()
    await countdownSleep(1, 0)
    cap.restore()
    const out = cap.writes.join('')
    expect(out).toMatch(/still pending/)
    expect(out).toMatch(/next check in 1s/)
    expect(out).not.toContain('\r')
  })
})
