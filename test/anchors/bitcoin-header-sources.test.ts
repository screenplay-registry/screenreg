/**
 * Bitcoin header sources: the local Bitcoin Core RPC node (trustless) and the
 * public Esplora explorers (trusted). Network is mocked via an injected fetch.
 */

import { describe, it, expect } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  makeBitcoinRpcSource,
  makeExplorerSource,
} from '../../src/anchors/bitcoin-header-sources.js'
import { reverseHexBytes, verifyAttestationWithSource } from '../../src/anchors/bitcoin-spv.js'

const GENESIS_MERKLE_DISPLAY = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
const GENESIS_HASH = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'

/** Build a mock fetch that routes Bitcoin Core JSON-RPC by method. */
function rpcFetch(handlers: {
  getblockhash?: (params: unknown[]) => unknown
  getblockheader?: (params: unknown[]) => unknown
  status?: number
  authSink?: (auth: string | undefined) => void
}): typeof fetch {
  return (async (_url: string, init: RequestInit) => {
    const headers = (init.headers ?? {}) as Record<string, string>
    handlers.authSink?.(headers.authorization)
    const body = JSON.parse(String(init.body)) as { method: string; params: unknown[] }
    const status = handlers.status ?? 200
    if (status !== 200) return new Response(JSON.stringify({ error: { message: 'nope' } }), { status })
    const fn = handlers[body.method as 'getblockhash' | 'getblockheader']
    if (!fn) return new Response(JSON.stringify({ error: { message: `no handler for ${body.method}` } }), { status: 500 })
    return new Response(JSON.stringify({ result: fn(body.params), error: null }), { status: 200 })
  }) as unknown as typeof fetch
}

describe('makeBitcoinRpcSource', () => {
  it('fetches a header via getblockhash → getblockheader and is trustless', async () => {
    const source = makeBitcoinRpcSource({
      url: 'http://127.0.0.1:8332',
      user: 'u',
      password: 'p',
      fetchImpl: rpcFetch({
        getblockhash: ([h]) => (h === 0 ? GENESIS_HASH : 'x'),
        getblockheader: ([hash]) =>
          hash === GENESIS_HASH
            ? { merkleroot: GENESIS_MERKLE_DISPLAY, time: 1231006505, hash: GENESIS_HASH, height: 0 }
            : {},
      }),
    })
    expect(source.trustless).toBe(true)
    expect(source.label).toMatch(/127\.0\.0\.1/)
    const h = await source.getBlockHeaderByHeight(0)
    expect(h.merkleRoot).toBe(GENESIS_MERKLE_DISPLAY)
    expect(h.blockHash).toBe(GENESIS_HASH)
    expect(h.height).toBe(0)
    expect(h.time).toBe(1231006505)
  })

  it('sends HTTP Basic auth from user/password', async () => {
    let seen: string | undefined
    const source = makeBitcoinRpcSource({
      url: 'http://127.0.0.1:8332',
      user: 'alice',
      password: 'secret',
      fetchImpl: rpcFetch({
        authSink: (a) => (seen = a),
        getblockhash: () => GENESIS_HASH,
        getblockheader: () => ({ merkleroot: GENESIS_MERKLE_DISPLAY, hash: GENESIS_HASH, height: 0 }),
      }),
    })
    await source.getBlockHeaderByHeight(0)
    expect(seen).toBe('Basic ' + Buffer.from('alice:secret').toString('base64'))
  })

  it('reads auth from a Bitcoin Core .cookie file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'btc-cookie-'))
    try {
      const cookiePath = join(dir, '.cookie')
      writeFileSync(cookiePath, '__cookie__:deadbeef\n')
      let seen: string | undefined
      const source = makeBitcoinRpcSource({
        url: 'http://127.0.0.1:8332',
        cookiePath,
        fetchImpl: rpcFetch({
          authSink: (a) => (seen = a),
          getblockhash: () => GENESIS_HASH,
          getblockheader: () => ({ merkleroot: GENESIS_MERKLE_DISPLAY, hash: GENESIS_HASH, height: 0 }),
        }),
      })
      await source.getBlockHeaderByHeight(0)
      expect(seen).toBe('Basic ' + Buffer.from('__cookie__:deadbeef').toString('base64'))
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('throws a clear error on HTTP 401', async () => {
    const source = makeBitcoinRpcSource({
      url: 'http://127.0.0.1:8332',
      fetchImpl: rpcFetch({ status: 401 }),
    })
    await expect(source.getBlockHeaderByHeight(0)).rejects.toThrow(/authentication failed/)
  })

  it('throws when getblockhash returns junk', async () => {
    const source = makeBitcoinRpcSource({
      url: 'http://127.0.0.1:8332',
      fetchImpl: rpcFetch({ getblockhash: () => 'not-a-hash' }),
    })
    await expect(source.getBlockHeaderByHeight(0)).rejects.toThrow(/valid block hash/)
  })

  it('extracts URL userinfo into Basic auth and never fetches/leaks the credentialed URL', async () => {
    let seenUrl = ''
    let seenAuth: string | undefined
    const fetchImpl = (async (url: string, init: RequestInit) => {
      seenUrl = url
      seenAuth = (init.headers as Record<string, string>).authorization
      const body = JSON.parse(String(init.body)) as { method: string }
      const result =
        body.method === 'getblockhash'
          ? GENESIS_HASH
          : { merkleroot: GENESIS_MERKLE_DISPLAY, hash: GENESIS_HASH, height: 0 }
      return new Response(JSON.stringify({ result, error: null }), { status: 200 })
    }) as unknown as typeof fetch
    const source = makeBitcoinRpcSource({ url: 'http://alice:secret@127.0.0.1:8332', fetchImpl })
    await source.getBlockHeaderByHeight(0)
    expect(seenAuth).toBe('Basic ' + Buffer.from('alice:secret').toString('base64'))
    expect(seenUrl).not.toContain('secret')
    expect(seenUrl).not.toContain('@')
    expect(source.label).not.toContain('secret')
  })

  it('redacts the password AND the Basic token echoed back in a JSON-RPC error message', async () => {
    const token = Buffer.from('alice:secret').toString('base64')
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({ error: { message: `bad creds alice:secret token ${token}` } }),
        { status: 500 },
      )) as unknown as typeof fetch
    const source = makeBitcoinRpcSource({ url: 'http://alice:secret@127.0.0.1:8332', fetchImpl })
    const err = await source.getBlockHeaderByHeight(0).catch((e: Error) => e.message)
    expect(err).toMatch(/\[redacted\]/)
    expect(err).not.toContain('secret')
    expect(err).not.toContain(token)
  })

  it('redacts credentials a malicious node smuggles into the getblockheader height field', async () => {
    const token = Buffer.from('alice:secret').toString('base64')
    const source = makeBitcoinRpcSource({
      url: 'http://alice:secret@127.0.0.1:8332',
      fetchImpl: rpcFetch({
        getblockhash: () => GENESIS_HASH,
        // height is a string carrying the token instead of the expected number.
        getblockheader: () => ({ merkleroot: GENESIS_MERKLE_DISPLAY, hash: GENESIS_HASH, height: token }),
      }),
    })
    const err = await source.getBlockHeaderByHeight(0).catch((e: Error) => e.message)
    expect(err).not.toContain('secret')
    expect(err).not.toContain(token)
    expect(err).toMatch(/\[redacted\]/)
  })

  it('rejects a getblockheader whose height or hash does not match the request', async () => {
    const wrongHeight = makeBitcoinRpcSource({
      url: 'http://127.0.0.1:8332',
      fetchImpl: rpcFetch({
        getblockhash: () => GENESIS_HASH,
        getblockheader: () => ({ merkleroot: GENESIS_MERKLE_DISPLAY, hash: GENESIS_HASH, height: 7 }),
      }),
    })
    await expect(wrongHeight.getBlockHeaderByHeight(0)).rejects.toThrow(/height/)

    const wrongHash = makeBitcoinRpcSource({
      url: 'http://127.0.0.1:8332',
      fetchImpl: rpcFetch({
        getblockhash: () => GENESIS_HASH,
        getblockheader: () => ({ merkleroot: GENESIS_MERKLE_DISPLAY, hash: 'a'.repeat(64), height: 0 }),
      }),
    })
    await expect(wrongHash.getBlockHeaderByHeight(0)).rejects.toThrow(/hash does not match/)
  })

  it('end-to-end verifies a matching genesis attestation', async () => {
    const source = makeBitcoinRpcSource({
      url: 'http://127.0.0.1:8332',
      fetchImpl: rpcFetch({
        getblockhash: () => GENESIS_HASH,
        getblockheader: () => ({ merkleroot: GENESIS_MERKLE_DISPLAY, hash: GENESIS_HASH, height: 0 }),
      }),
    })
    const att = { blockHeight: 0, merkleRoot: reverseHexBytes(GENESIS_MERKLE_DISPLAY) }
    const v = await verifyAttestationWithSource(att, source)
    expect(v.ok).toBe(true)
  })
})

/** Esplora explorer mock: routes /block-height/<n> and /block/<hash>. */
function esploraFetch(opts: {
  hashByHeight: Record<number, string>
  blockByHash: Record<string, unknown>
}): typeof fetch {
  return (async (url: string) => {
    const m = url.match(/\/block-height\/(\d+)$/)
    if (m) {
      const hash = opts.hashByHeight[Number(m[1])]
      return hash ? new Response(hash, { status: 200 }) : new Response('not found', { status: 404 })
    }
    const b = url.match(/\/block\/([0-9a-fA-F]+)$/)
    if (b) {
      const blk = opts.blockByHash[b[1]!.toLowerCase()]
      return blk ? new Response(JSON.stringify(blk), { status: 200 }) : new Response('not found', { status: 404 })
    }
    return new Response('bad', { status: 400 })
  }) as unknown as typeof fetch
}

describe('makeExplorerSource', () => {
  it('fetches a header via block-height → block and is NOT trustless', async () => {
    const source = makeExplorerSource('mempool', {
      fetchImpl: esploraFetch({
        hashByHeight: { 0: GENESIS_HASH },
        blockByHash: {
          [GENESIS_HASH]: { merkle_root: GENESIS_MERKLE_DISPLAY, timestamp: 1231006505, id: GENESIS_HASH, height: 0 },
        },
      }),
    })
    expect(source.trustless).toBe(false)
    expect(source.label).toBe('mempool.space')
    const h = await source.getBlockHeaderByHeight(0)
    expect(h.merkleRoot).toBe(GENESIS_MERKLE_DISPLAY)
    expect(h.blockHash).toBe(GENESIS_HASH)
    expect(h.time).toBe(1231006505)
  })

  it('blockstream uses the blockstream.info host', () => {
    const source = makeExplorerSource('blockstream', { fetchImpl: esploraFetch({ hashByHeight: {}, blockByHash: {} }) })
    expect(source.label).toBe('blockstream.info')
  })

  it('rejects a non-hex hash from block-height (path-injection guard)', async () => {
    const source = makeExplorerSource('mempool', {
      fetchImpl: (async (url: string) =>
        url.includes('/block-height/')
          ? new Response('../../etc/passwd', { status: 200 })
          : new Response('{}', { status: 200 })) as unknown as typeof fetch,
    })
    await expect(source.getBlockHeaderByHeight(0)).rejects.toThrow(/invalid hash/)
  })

  it('throws on a 404 from block-height', async () => {
    const source = makeExplorerSource('mempool', {
      fetchImpl: esploraFetch({ hashByHeight: {}, blockByHash: {} }),
    })
    await expect(source.getBlockHeaderByHeight(999999999)).rejects.toThrow(/HTTP 404/)
  })

  it('rejects a block whose height or id does not match the request', async () => {
    const wrongHeight = makeExplorerSource('mempool', {
      fetchImpl: esploraFetch({
        hashByHeight: { 0: GENESIS_HASH },
        blockByHash: { [GENESIS_HASH]: { merkle_root: GENESIS_MERKLE_DISPLAY, id: GENESIS_HASH, height: 9 } },
      }),
    })
    await expect(wrongHeight.getBlockHeaderByHeight(0)).rejects.toThrow(/height/)

    const wrongId = makeExplorerSource('mempool', {
      fetchImpl: esploraFetch({
        hashByHeight: { 0: GENESIS_HASH },
        blockByHash: { [GENESIS_HASH]: { merkle_root: GENESIS_MERKLE_DISPLAY, id: 'b'.repeat(64), height: 0 } },
      }),
    })
    await expect(wrongId.getBlockHeaderByHeight(0)).rejects.toThrow(/id does not match/)
  })
})
