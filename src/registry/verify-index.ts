/**
 * Per-record verification of a registry-index snapshot (Node-side).
 *
 * The registry index is a SIGNED, MIRRORABLE discovery convenience — NOT a
 * tamper-proof log. In the v1 MVP it gives ZERO cryptographic protection against
 * an operator that censors, withholds, or equivocates. The protection that DOES
 * hold is per-record and operator-independent: each record's truth is its own
 * `.ots` proof verified against Bitcoin. A future CT-style transparency log (with
 * signed tree heads, append-only consistency proofs, gossip, and a named
 * domain-tagged snapshot-Merkle profile) is the target; until it exists, this
 * verifier makes NO snapshot-root claim. See spec/v1/10-registry-index.md.
 *
 * This module is Node-only by design: it calls `verifyOtsAgainstFileDigest`,
 * which uses `node:crypto` + `Buffer`. It lives OUTSIDE `src/shared/**` so no
 * browser/Web-Crypto module can reach a Node dependency. All I/O is INJECTED
 * (the caller supplies `loadOtsProof`); this module hardwires no filesystem
 * access of its own — the CLI's resolver carries the path-traversal guards.
 */

import { Buffer } from 'node:buffer'
import { parseSha256Hash } from '../util/sha256-hash.js'
import {
  verifyOtsAgainstFileDigest,
  type VerifyOtsAgainstClaimHashResult,
} from '../anchors/ots-verify.js'
import type { RegistryRecord } from './record.js'

/**
 * Finality label for a per-record Bitcoin height. The distinction is
 * load-bearing for priority: only a `bitcoin-final` height may rank a record.
 *
 *  - `ots-claimed`  — the height was parsed straight from the `.ots` attestation
 *                     with NO Bitcoin-header inclusion check. The underlying OTS
 *                     verifier reads heights from the attestation only; an
 *                     OTS-claimed height is NOT proof the block at height N
 *                     contains the timestamp's Merkle root. It MUST NOT rank.
 *  - `bitcoin-final` — an injected attestation verifier confirmed header
 *                     inclusion AND at least `minConfirmations` confirmations.
 */
export type FinalityLabel = 'ots-claimed' | 'bitcoin-final'

/** Per-record verification outcome. */
export type RecordVerifyResult =
  | {
      claimHash: string
      ok: true
      /**
       * Bitcoin block heights asserted by the `.ots`, each with its finality
       * label. Without an injected attestation verifier every height is
       * `ots-claimed` and cannot rank.
       */
      bitcoinHeights: { height: number; finality: FinalityLabel }[]
      pendingCalendarUrls: string[]
    }
  | { claimHash: string; ok: false; reason: string }

export interface VerifyIndexSnapshotResult {
  records: RecordVerifyResult[]
}

/**
 * Loads the raw `.ots` bytes for a record. INJECTED so this module performs no
 * I/O of its own — the CLI implementation resolves `proofRef` strictly relative
 * to the snapshot directory and rejects absolute paths, `..` traversal, and
 * symlinks (the path-traversal guards live with the loader, not here).
 *
 * Return `undefined` when the proof cannot be loaded; the record is then
 * reported as `ok: false` with an `ots-missing` reason rather than throwing.
 */
export type LoadOtsProof = (
  record: RegistryRecord,
  proofRef: string,
) => Promise<Buffer | undefined> | Buffer | undefined

/**
 * Confirms Bitcoin-header inclusion for an OTS-claimed height. INJECTED and
 * OPTIONAL: the core verifier cannot reach Bitcoin headers on its own. When
 * absent, NO height is treated as Bitcoin-final and the snapshot cannot resolve
 * priority. When present, it MUST confirm both header inclusion and that the
 * height has at least `minConfirmations` confirmations against the chain tip.
 */
export type VerifyBitcoinAttestation = (input: {
  blockHeight: number
  fileDigest: Buffer
  minConfirmations: number
}) => Promise<boolean> | boolean

export interface VerifyIndexSnapshotOptions {
  loadOtsProof: LoadOtsProof
  /** Optional Bitcoin-finality oracle. Without it, heights stay OTS-claimed. */
  verifyBitcoinAttestation?: VerifyBitcoinAttestation
  /** Confirmations required for a height to be Bitcoin-final. */
  minConfirmations: number
}

/** A registry snapshot: an array of records, each independently re-verifiable. */
export interface RegistrySnapshot {
  records: RegistryRecord[]
}

/**
 * Verify every record in a snapshot by re-checking its `.ots` against Bitcoin.
 * Per-record only — there is NO snapshot-root step (deferred with the CT-style
 * transparency-log target). Never throws on a missing/invalid proof; reports it.
 */
export async function verifyIndexSnapshot(
  snapshot: RegistrySnapshot,
  options: VerifyIndexSnapshotOptions,
): Promise<VerifyIndexSnapshotResult> {
  const out: RecordVerifyResult[] = []
  for (const record of snapshot.records) {
    out.push(await verifyOneRecord(record, options))
  }
  return { records: out }
}

async function verifyOneRecord(
  record: RegistryRecord,
  options: VerifyIndexSnapshotOptions,
): Promise<RecordVerifyResult> {
  const claimHash = record.claimHash

  // Expected file digest = the record's claimHash as raw 32 bytes. parseSha256Hash
  // throws on a malformed hash; guard it so a bad record is reported, not fatal.
  let expectedDigest: Buffer
  try {
    expectedDigest = parseSha256Hash(claimHash)
  } catch (e: unknown) {
    return { claimHash, ok: false, reason: `invalid claimHash: ${errMsg(e)}` }
  }

  const proofRef = record.anchors.opentimestamps.proofRef
  let otsBytes: Buffer | undefined
  try {
    otsBytes = await options.loadOtsProof(record, proofRef)
  } catch (e: unknown) {
    return { claimHash, ok: false, reason: `failed to load .ots: ${errMsg(e)}` }
  }
  if (otsBytes === undefined) {
    return { claimHash, ok: false, reason: 'ots-missing' }
  }

  // Structural .ots validity: the file digest in the proof MUST equal the
  // record's claimHash, and the proof must parse cleanly. This is the
  // "signed/mirrorable, NOT a tamper-proof log" guarantee — it does NOT by
  // itself assert Bitcoin finality.
  const ots: VerifyOtsAgainstClaimHashResult = verifyOtsAgainstFileDigest({
    otsBytes,
    expectedFileDigest: expectedDigest,
  })
  if (!ots.ok) {
    return { claimHash, ok: false, reason: ots.reason }
  }

  // Bitcoin-finality split. Without an injected attestation verifier, EVERY
  // height is OTS-claimed (parsed from the attestation, NOT header-checked) and
  // cannot rank. With one, a height is Bitcoin-final only after confirmed header
  // inclusion AND minConfirmations.
  const bitcoinHeights: { height: number; finality: FinalityLabel }[] = []
  for (const height of ots.bitcoinBlockHeights) {
    let finality: FinalityLabel = 'ots-claimed'
    if (options.verifyBitcoinAttestation !== undefined) {
      let final = false
      try {
        final = await options.verifyBitcoinAttestation({
          blockHeight: height,
          fileDigest: expectedDigest,
          minConfirmations: options.minConfirmations,
        })
      } catch {
        // A failing attestation oracle degrades to OTS-claimed, never to an error:
        // the per-record .ots structure is still valid, only finality is unproven.
        final = false
      }
      if (final) finality = 'bitcoin-final'
    }
    bitcoinHeights.push({ height, finality })
  }

  return {
    claimHash,
    ok: true,
    bitcoinHeights,
    pendingCalendarUrls: ots.pendingCalendarUrls,
  }
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}
