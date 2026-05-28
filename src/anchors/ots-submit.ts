/**
 * TypeScript subprocess wrapper for the Python OTS-stamping helper.
 *
 * Subprocesses the Python helper at src/anchors/python/ots_stamp_digest.py.
 * The helper uses the upstream `opentimestamps` LIBRARY (NOT the `stamp` CLI
 * subcommand, which would re-hash the file rather than stamp a raw digest).
 *
 * Adapter boundary: anything that produces a `.ots` Buffer from a 32-byte
 * digest can replace this wrapper. A future v1.1+ can ship a clean-room TS
 * calendar submitter (HTTPS POST to /digest endpoint) without changing the
 * manifest schema or breaking v1 proofs.
 */

import { spawn } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync } from 'node:fs'

const __dirname = dirname(fileURLToPath(import.meta.url))

/** Default path to the Python helper script (in-repo, relative to this file). */
export const DEFAULT_HELPER_PATH = join(__dirname, 'python', 'ots_stamp_digest.py')

/**
 * Default Python interpreter. Callers can override via `python` option.
 * On a typical install we expect the project venv at ./.venv/bin/python3,
 * but this falls back to system python3 if the env var or option isn't set.
 */
function defaultPythonPath(): string {
  // Walk up from this file looking for a .venv/bin/python3
  let cur = __dirname
  for (let i = 0; i < 6; i++) {
    const candidate = join(cur, '.venv', 'bin', 'python3')
    if (existsSync(candidate)) return candidate
    cur = dirname(cur)
  }
  return process.env.PYTHON ?? 'python3'
}

export interface OtsSubmitOptions {
  /** 32-byte SHA-256 digest. */
  digest: Buffer
  /** Calendar URLs to submit to. Defaults to the 4 OTS pool calendars. */
  calendars?: string[]
  /** Per-calendar timeout in seconds. Default 10. */
  timeoutSec?: number
  /** Min number of calendar attestations required to succeed. Default 1. */
  minCalendars?: number
  /** Path override for the Python helper script. */
  helperPath?: string
  /** Python interpreter path. Defaults to ./.venv/bin/python3 if present. */
  python?: string
  /** Mock mode: emit a placeholder unupgraded .ots without network calls. */
  mock?: boolean
}

export type OtsSubmitResult =
  | { ok: true; otsBytes: Buffer }
  | { ok: false; reason: string; stderr: string }

/**
 * Submit a raw 32-byte SHA-256 digest to OTS public calendars and return the
 * serialized .ots binary.
 */
export async function submitOts(opts: OtsSubmitOptions): Promise<OtsSubmitResult> {
  if (opts.digest.length !== 32) {
    return { ok: false, reason: `digest must be 32 bytes, got ${opts.digest.length}`, stderr: '' }
  }
  const helper = opts.helperPath ?? DEFAULT_HELPER_PATH
  const python = opts.python ?? defaultPythonPath()

  const args: string[] = [helper, opts.digest.toString('hex')]
  if (opts.mock) args.push('--mock')
  if (opts.timeoutSec !== undefined) args.push('--timeout', String(opts.timeoutSec))
  if (opts.minCalendars !== undefined) args.push('--min-calendars', String(opts.minCalendars))
  for (const url of opts.calendars ?? []) {
    args.push('--calendar', url)
  }

  return new Promise((resolve) => {
    const child = spawn(python, args, { stdio: ['ignore', 'pipe', 'pipe'] })
    const stdoutChunks: Buffer[] = []
    const stderrChunks: Buffer[] = []
    child.stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk))
    child.stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk))
    child.on('error', (err) => {
      resolve({
        ok: false,
        reason: `failed to spawn Python helper: ${err.message}`,
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
      })
    })
    child.on('close', (code) => {
      const stderr = Buffer.concat(stderrChunks).toString('utf8')
      if (code !== 0) {
        resolve({ ok: false, reason: `Python helper exited with code ${code}`, stderr })
        return
      }
      resolve({ ok: true, otsBytes: Buffer.concat(stdoutChunks) })
    })
  })
}
