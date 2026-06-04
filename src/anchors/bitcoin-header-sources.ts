/**
 * Concrete Bitcoin block-header sources for SPV verification (see bitcoin-spv.ts).
 *
 *  - `makeBitcoinRpcSource` — a local Bitcoin Core JSON-RPC node. TRUSTLESS: you
 *    run it, so its answer needs no further trust. A pruned node works (block
 *    headers are never pruned); no wallet is required.
 *  - `makeExplorerSource` — a public Esplora-compatible explorer (mempool.space
 *    or blockstream.info). NOT trustless: you are trusting that operator's view
 *    of the chain. Opt-in only, and labelled as trusted in the verifier output.
 *
 * All network access is bounded by a timeout and a response-size cap. Hash/height
 * fields are validated before being interpolated into any follow-up URL.
 */

import { readFileSync } from 'node:fs'
import type { BitcoinBlockHeader, BitcoinHeaderSource } from './bitcoin-spv.js'

const HEX64 = /^[0-9a-fA-F]{64}$/
/** Block headers and their JSON wrappers are tiny; 1 MiB is far above any real response. */
const MAX_RESPONSE_BYTES = 1024 * 1024
const DEFAULT_TIMEOUT_MS = 15_000
/** Cap the timeout so a caller can't accidentally disable the DoS bound. */
const MAX_TIMEOUT_MS = 120_000

function clampTimeout(ms: number | undefined): number {
  if (ms === undefined || !Number.isFinite(ms) || ms <= 0) return DEFAULT_TIMEOUT_MS
  return Math.min(ms, MAX_TIMEOUT_MS)
}

/** Strip control chars and truncate a network-supplied string before surfacing it. */
function sanitizeMessage(s: unknown): string {
  // eslint-disable-next-line no-control-regex
  return String(s).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 200)
}

/** Streamed, size-capped body read — abandons an oversized body without buffering it whole. */
async function readCapped(resp: Response, max: number): Promise<Uint8Array | null> {
  const declared = resp.headers?.get?.('content-length')
  if (declared && Number(declared) > max) {
    // Tear down the connection rather than leaving a hostile server holding the socket.
    try { await (resp as { body?: ReadableStream<Uint8Array> | null }).body?.cancel?.() } catch { /* ignore */ }
    return null
  }
  const stream = (resp as { body?: ReadableStream<Uint8Array> | null }).body
  if (!stream || typeof stream.getReader !== 'function') {
    const buf = new Uint8Array(await resp.arrayBuffer())
    return buf.length > max ? null : buf
  }
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (value) {
        total += value.length
        if (total > max) {
          try { await reader.cancel() } catch { /* ignore */ }
          return null
        }
        chunks.push(value)
      }
    }
  } finally {
    try { reader.releaseLock() } catch { /* ignore */ }
  }
  const out = new Uint8Array(total)
  let off = 0
  for (const c of chunks) { out.set(c, off); off += c.length }
  return out
}

async function fetchCapped(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<{ status: number; text: string }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const resp = await fetchImpl(url, {
      ...init,
      signal: controller.signal,
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    } as RequestInit)
    const bytes = await readCapped(resp, MAX_RESPONSE_BYTES)
    if (bytes === null) {
      controller.abort() // ensure the socket is torn down before we return
      throw new Error(`response exceeds ${MAX_RESPONSE_BYTES} bytes`)
    }
    return { status: resp.status, text: new TextDecoder().decode(bytes) }
  } finally {
    clearTimeout(timer)
  }
}

function assertHeight(height: number): void {
  if (!Number.isInteger(height) || height < 0) throw new Error(`invalid block height ${height}`)
}

export interface BitcoinRpcOptions {
  /** JSON-RPC endpoint, e.g. http://127.0.0.1:8332 */
  url: string
  /** Path to Bitcoin Core's `.cookie` file (contents: "user:password"). */
  cookiePath?: string
  /** Explicit rpcuser (alternative to a cookie file). */
  user?: string
  /** Explicit rpcpassword. */
  password?: string
  timeoutMs?: number
  /** Injectable fetch for testing; defaults to global fetch. */
  fetchImpl?: typeof fetch
}

/**
 * A trustless header source backed by a local Bitcoin Core JSON-RPC node:
 * getblockhash(height) → getblockheader(hash) → merkle root.
 */
export function makeBitcoinRpcSource(opts: BitcoinRpcOptions): BitcoinHeaderSource {
  const fetchImpl = opts.fetchImpl ?? fetch
  const timeoutMs = clampTimeout(opts.timeoutMs)

  let parsed: URL
  try {
    parsed = new URL(opts.url)
  } catch {
    throw new Error('invalid --bitcoin-rpc URL')
  }

  // Resolve auth: explicit user/password > cookie file > userinfo embedded in the URL.
  // Collect the secret material so it can be redacted from any surfaced error text
  // (a hostile or buggy RPC endpoint could echo the credentials back in its error
  // body, which would otherwise land in the user's terminal/logs).
  let authHeader: string | undefined
  const secrets: string[] = []
  const setAuth = (raw: string): void => {
    authHeader = 'Basic ' + Buffer.from(raw).toString('base64')
    const password = raw.slice(raw.indexOf(':') + 1)
    for (const s of [raw, password, authHeader.slice('Basic '.length)]) {
      if (s.length > 0) secrets.push(s)
    }
  }
  if (opts.user !== undefined || opts.password !== undefined) {
    setAuth(`${opts.user ?? ''}:${opts.password ?? ''}`)
  } else if (opts.cookiePath !== undefined) {
    setAuth(readFileSync(opts.cookiePath, 'utf8').trim())
  } else if (parsed.username || parsed.password) {
    setAuth(`${decodeURIComponent(parsed.username)}:${decodeURIComponent(parsed.password)}`)
  }
  const redactSecrets = (s: string): string => {
    let out = s
    for (const sec of secrets) out = out.split(sec).join('[redacted]')
    return out
  }
  // Render ANY network-supplied value for an error message: redact known secrets
  // (a malicious node can echo the token/password back in error.message OR in a
  // field like `height`), then strip control chars and truncate.
  const safe = (v: unknown): string => sanitizeMessage(redactSecrets(String(v)))

  // ALWAYS strip userinfo: fetch() rejects a credentialed URL with an error that
  // echoes the URL (leaking the password), and we never want creds in a label or
  // error message. The sanitized URL is the only one we fetch or report.
  parsed.username = ''
  parsed.password = ''
  const sanitizedUrl = parsed.toString()
  const host = parsed.host

  let nextId = 1
  async function rpc<T>(method: string, params: unknown[]): Promise<T> {
    const headers: Record<string, string> = { 'content-type': 'application/json' }
    if (authHeader) headers.authorization = authHeader
    // Bitcoin Core speaks JSON-RPC 1.0; on an RPC error it returns the error in
    // the body (often with HTTP 500), and 401 on bad/missing auth.
    const { status, text } = await fetchCapped(
      fetchImpl,
      sanitizedUrl,
      { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '1.0', id: nextId++, method, params }) },
      timeoutMs,
    )
    if (status === 401) throw new Error('authentication failed (check --bitcoin-rpc-cookie or rpcuser/rpcpassword)')
    let json: { result?: unknown; error?: { message?: string } | null }
    try {
      json = JSON.parse(text) as typeof json
    } catch {
      throw new Error(`non-JSON response from ${method} (HTTP ${status})`)
    }
    if (json.error) {
      // Redact before truncating so a secret split across the 200-char cap can't survive.
      throw new Error(`${method}: ${safe(json.error.message ?? 'RPC error')}`)
    }
    if (status !== 200) throw new Error(`${method}: HTTP ${status}`)
    return json.result as T
  }

  return {
    label: `your node (${host})`,
    trustless: true,
    async getBlockHeaderByHeight(height: number): Promise<BitcoinBlockHeader> {
      assertHeight(height)
      const hash = await rpc<string>('getblockhash', [height])
      if (typeof hash !== 'string' || !HEX64.test(hash)) {
        throw new Error('getblockhash did not return a valid block hash')
      }
      const h = await rpc<{ merkleroot?: unknown; time?: unknown; hash?: unknown; height?: unknown }>(
        'getblockheader',
        [hash, true],
      )
      if (!h || typeof h.merkleroot !== 'string' || !HEX64.test(h.merkleroot)) {
        throw new Error('getblockheader did not return a valid merkleroot')
      }
      // The returned header MUST be for exactly the block we asked for: its height
      // must equal the request and its hash must equal the one getblockhash gave.
      // Don't manufacture a height or echo a network-supplied hash.
      if (h.height !== height) {
        throw new Error(`getblockheader returned height ${safe(h.height)}, expected ${height}`)
      }
      if (typeof h.hash !== 'string' || h.hash.toLowerCase() !== hash.toLowerCase()) {
        throw new Error('getblockheader hash does not match getblockhash')
      }
      const header: BitcoinBlockHeader = { height, merkleRoot: h.merkleroot, blockHash: hash }
      if (typeof h.time === 'number') header.time = h.time
      return header
    },
  }
}

export type ExplorerName = 'mempool' | 'blockstream'

const EXPLORER_BASE: Record<ExplorerName, string> = {
  mempool: 'https://mempool.space/api',
  blockstream: 'https://blockstream.info/api',
}

/**
 * A header source backed by a public Esplora-compatible explorer. NOT trustless:
 * the caller is trusting that operator. Two calls: GET /block-height/<n> → the
 * block hash (validated as 32-byte hex before reuse), then GET /block/<hash>.
 */
export function makeExplorerSource(
  which: ExplorerName,
  opts?: { timeoutMs?: number; fetchImpl?: typeof fetch },
): BitcoinHeaderSource {
  const base = EXPLORER_BASE[which]
  const fetchImpl = opts?.fetchImpl ?? fetch
  const timeoutMs = clampTimeout(opts?.timeoutMs)
  const host = new URL(base).host

  return {
    label: host,
    trustless: false,
    async getBlockHeaderByHeight(height: number): Promise<BitcoinBlockHeader> {
      assertHeight(height)
      const hr = await fetchCapped(fetchImpl, `${base}/block-height/${height}`, { method: 'GET' }, timeoutMs)
      if (hr.status !== 200) throw new Error(`block-height ${height}: HTTP ${hr.status}`)
      const hash = hr.text.trim()
      // Validate BEFORE interpolating into the next URL (prevents path injection).
      if (!HEX64.test(hash)) throw new Error(`block-height ${height} returned an invalid hash`)
      const br = await fetchCapped(fetchImpl, `${base}/block/${hash}`, { method: 'GET' }, timeoutMs)
      if (br.status !== 200) throw new Error(`block ${hash}: HTTP ${br.status}`)
      let j: { merkle_root?: unknown; timestamp?: unknown; id?: unknown; height?: unknown }
      try {
        j = JSON.parse(br.text) as typeof j
      } catch {
        throw new Error('block endpoint returned non-JSON')
      }
      if (typeof j.merkle_root !== 'string' || !HEX64.test(j.merkle_root)) {
        throw new Error('block endpoint returned no valid merkle_root')
      }
      // The returned block MUST be the one we asked for: its height must equal the
      // request and its id must equal the hash /block-height gave us. Don't
      // manufacture a height or echo a network-supplied id.
      if (j.height !== height) {
        throw new Error(`block endpoint returned height ${sanitizeMessage(j.height)}, expected ${height}`)
      }
      if (typeof j.id !== 'string' || j.id.toLowerCase() !== hash.toLowerCase()) {
        throw new Error('block endpoint id does not match the requested hash')
      }
      const header: BitcoinBlockHeader = { height, merkleRoot: j.merkle_root, blockHash: hash }
      if (typeof j.timestamp === 'number') header.time = j.timestamp
      return header
    },
  }
}
