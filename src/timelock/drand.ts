/**
 * Time-lock encryption via Drand League of Entropy (Section 07, capability-flagged).
 *
 * Uses Drand's threshold BLS signature network. Drand publishes a fresh BLS
 * signature every `period` seconds (typically 3s on quicknet, 30s on mainnet).
 * Each round's signature is determined cryptographically by the network's
 * threshold group key + the round number.
 *
 * tlock encryption against a FUTURE round produces a ciphertext that:
 *  - Cannot be decrypted before Drand publishes that round's signature
 *  - CAN be decrypted by ANYONE after that round, using only public info
 *
 * For OSR: a writer commits today to a Drand round N (corresponding to a
 * future unix time). The committedClaim records {round, chainHash, chainPubkey,
 * unlockAt}. At the unlock time, anyone can fetch round N's signature from
 * Drand's public API and decrypt.
 *
 * Key design choices:
 *  - Default chain: Drand quicknet (period 3s, RFC-9380 BLS12-381). Configurable.
 *  - We commit the chain hash + chain pubkey IN the manifest so verifiers can
 *    validate against the exact chain the writer used (resists "wrong chain"
 *    impersonation if Drand ever spawns a new chain).
 *  - Reject unlock times in the past (unless --allow-unlocked override).
 *  - Per-registration unique unlock rounds are normal; the same round may
 *    appear in multiple registrations (informational metadata only).
 *
 * Library: tlock-js by the Drand team (https://github.com/drand/tlock-js).
 */

import {
  timelockEncrypt as tlockEncrypt,
  timelockDecrypt as tlockDecrypt,
  HttpChainClient,
  HttpCachingChain,
} from 'tlock-js'
import type { TimelockField } from '../envelope/types.js'

// ---------------------------------------------------------------------------
// Default chain configuration (Drand quicknet — fastest, RFC-9380 compliant)
// ---------------------------------------------------------------------------

/**
 * Drand quicknet chain hash. Public knowledge per Drand's reference docs.
 * https://drand.love/docs/dev-guide/
 */
export const QUICKNET_CHAIN_HASH = '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971' as const

/**
 * Drand quicknet group public key (used for off-chain signature verification).
 */
export const QUICKNET_PUBLIC_KEY =
  '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a' as const

/** Drand quicknet API URL. */
export const QUICKNET_URL = 'https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971' as const

/** Period (seconds between Drand rounds) on quicknet. */
export const QUICKNET_PERIOD_SEC = 3

/** Genesis time of quicknet (Unix epoch seconds). */
export const QUICKNET_GENESIS_TIME = 1692803367

/**
 * Compute the Drand round number that will be signed at or after the given
 * unix-time. Uses ceil to ensure decryption is possible AT OR AFTER the
 * specified time, never before.
 *
 *   roundAt(unixSec) := ceil((unixSec - genesisTime) / period)
 *
 * (Drand round 1 happens at genesisTime + period; round N happens at
 *  genesisTime + N * period.)
 */
export function roundAtUnixTime(
  unixSec: number,
  genesisTime: number = QUICKNET_GENESIS_TIME,
  period: number = QUICKNET_PERIOD_SEC,
): number {
  if (unixSec <= genesisTime) {
    throw new Error(`unlockAt (${unixSec}) is at or before Drand chain genesis (${genesisTime})`)
  }
  const offset = unixSec - genesisTime
  return Math.ceil(offset / period)
}

/**
 * Inverse: compute the unix-time at which Drand will publish round N's signature.
 */
export function unixTimeOfRound(
  round: number,
  genesisTime: number = QUICKNET_GENESIS_TIME,
  period: number = QUICKNET_PERIOD_SEC,
): number {
  return genesisTime + round * period
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

export interface TimelockEncryptInput {
  /** Field name (becomes unencrypted in the manifest). */
  name: string
  /** Plaintext bytes to encrypt. */
  plaintext: Buffer
  /** Unix timestamp (seconds, UTC) at which the content becomes decryptable. */
  unlockAt: Date
  /** Allow unlock times in the past (for testing). Default: false. */
  allowUnlocked?: boolean
}

export async function timelockEncrypt(input: TimelockEncryptInput): Promise<TimelockField> {
  const unlockUnixSec = Math.floor(input.unlockAt.getTime() / 1000)
  const nowUnixSec = Math.floor(Date.now() / 1000)
  if (unlockUnixSec <= nowUnixSec && !input.allowUnlocked) {
    throw new Error(
      `Refusing to encrypt with unlockAt (${input.unlockAt.toISOString()}) ≤ now (${new Date(nowUnixSec * 1000).toISOString()}). Pass allowUnlocked=true for testing.`,
    )
  }

  const round = roundAtUnixTime(unlockUnixSec)
  const client = makeQuicknetClient()
  const ciphertextStr = await tlockEncrypt(round, input.plaintext, client)

  return {
    name: input.name,
    ciphertext: Buffer.from(ciphertextStr, 'utf8').toString('base64'),
    unlockAtRound: round,
    unlockAt: new Date(unixTimeOfRound(round) * 1000).toISOString(),
    drandChainHash: QUICKNET_CHAIN_HASH,
    drandPublicKey: QUICKNET_PUBLIC_KEY,
    scheme: 'tlock-bls12-381-quicknet',
  }
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

export interface TimelockDecryptInput {
  field: TimelockField
}

export type TimelockDecryptResult =
  | { ok: true; plaintext: Buffer }
  | {
      ok: false
      reason:
        | 'not-yet-unlocked'
        | 'chain-mismatch'
        | 'scheme-mismatch'
        | 'public-key-mismatch'
        | 'decrypt-failed'
      detail: string
    }

/** Locked v1 scheme identifier; must match what timelockEncrypt emits. */
const SUPPORTED_SCHEME = 'tlock-bls12-381-quicknet' as const

export async function timelockDecrypt(
  input: TimelockDecryptInput,
): Promise<TimelockDecryptResult> {
  // Enforce every committed Drand parameter. The field's chain/scheme/public
  // key are part of the on-chain commitment (spec §07 §5); a verifier that
  // skips any of them silently accepts a re-anchored field from a different
  // chain or scheme as if it belonged to this protocol.
  if (input.field.drandChainHash !== QUICKNET_CHAIN_HASH) {
    return {
      ok: false,
      reason: 'chain-mismatch',
      detail: `Field references Drand chain ${input.field.drandChainHash}; this client only supports quicknet (${QUICKNET_CHAIN_HASH})`,
    }
  }
  if (input.field.scheme !== SUPPORTED_SCHEME) {
    return {
      ok: false,
      reason: 'scheme-mismatch',
      detail: `Field declares scheme ${input.field.scheme}; this client only supports ${SUPPORTED_SCHEME}`,
    }
  }
  if (input.field.drandPublicKey !== QUICKNET_PUBLIC_KEY) {
    return {
      ok: false,
      reason: 'public-key-mismatch',
      detail: `Field's drandPublicKey does not match this client's quicknet public key. Either the field is from a fork/staging chain or the client is misconfigured.`,
    }
  }

  // Check unlock has passed
  const unlockUnixSec = unixTimeOfRound(input.field.unlockAtRound)
  const nowUnixSec = Math.floor(Date.now() / 1000)
  if (nowUnixSec < unlockUnixSec) {
    const waitSec = unlockUnixSec - nowUnixSec
    return {
      ok: false,
      reason: 'not-yet-unlocked',
      detail: `Field unlocks at ${input.field.unlockAt} (~${waitSec}s from now). Try again then.`,
    }
  }

  // Fetch the round signature + decrypt
  const client = makeQuicknetClient()
  const ciphertextStr = Buffer.from(input.field.ciphertext, 'base64').toString('utf8')
  try {
    const plaintext = await tlockDecrypt(ciphertextStr, client)
    return { ok: true, plaintext }
  } catch (e: any) {
    return { ok: false, reason: 'decrypt-failed', detail: e?.message ?? String(e) }
  }
}

// ---------------------------------------------------------------------------
// Client construction
// ---------------------------------------------------------------------------

function makeQuicknetClient(): HttpChainClient {
  // Pass chain-verification params so the client refuses to talk to a chain
  // with a different hash/pubkey than what we committed to in the manifest.
  const chain = new HttpCachingChain(QUICKNET_URL, {
    disableBeaconVerification: false,
    noCache: false,
    chainVerificationParams: {
      chainHash: QUICKNET_CHAIN_HASH,
      publicKey: QUICKNET_PUBLIC_KEY,
    },
  })
  return new HttpChainClient(chain)
}
