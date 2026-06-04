/**
 * Bitcoin SPV check for OpenTimestamps attestations.
 *
 * An OTS Bitcoin block-header attestation says "the message at this point in the
 * timestamp tree IS the merkle root of block N." Confirming the proof against
 * Bitcoin therefore reduces to: fetch the real header of block N and check that
 * its merkle root equals the value the proof committed.
 *
 * BYTE ORDER — the load-bearing detail. OTS commits the merkle root in INTERNAL
 * (little-endian) byte order, exactly as it appears in the serialized 80-byte
 * block header. Bitcoin Core's `getblockheader` JSON and block explorers report
 * `merkleroot` as a DISPLAY (big-endian) hex string — the byte-reverse of the
 * internal form. This module reverses the attestation's internal root to display
 * order before comparing, so both sides are in the same convention.
 *
 * This file holds only the PURE comparison + the header-source interface; the
 * concrete sources (a Bitcoin Core RPC node, public explorers) are separate so
 * the security-critical comparison can be unit-tested with no network.
 */

const HEX64 = /^[0-9a-f]{64}$/

/** Reverse a hex string byte-wise (internal little-endian ↔ display big-endian). */
export function reverseHexBytes(hex: string): string {
  if (hex.length % 2 !== 0) throw new Error(`reverseHexBytes: odd-length hex (${hex.length})`)
  let out = ''
  for (let i = hex.length - 2; i >= 0; i -= 2) out += hex.slice(i, i + 2)
  return out
}

/** A block header, as needed for SPV. `merkleRoot` is Bitcoin Core DISPLAY (big-endian) hex. */
export interface BitcoinBlockHeader {
  height: number
  /** Merkle root in display (big-endian) hex — e.g. getblockheader().merkleroot. */
  merkleRoot: string
  /** Block hash in display hex (optional, for reporting). */
  blockHash?: string
  /** Block header timestamp (nTime), Unix seconds (optional, for reporting). */
  time?: number
}

/**
 * A source of Bitcoin block headers by height. Implemented by a trustless local
 * node (Bitcoin Core RPC) or a trusted third-party explorer.
 */
export interface BitcoinHeaderSource {
  /** Human label for trust attribution in messages (e.g. "your node", "mempool.space"). */
  readonly label: string
  /** True for a source you run yourself (trustless); false for a third party. */
  readonly trustless: boolean
  getBlockHeaderByHeight(height: number): Promise<BitcoinBlockHeader>
}

export type BitcoinAttestationVerdict =
  | {
      ok: true
      blockHeight: number
      /** The confirmed merkle root in DISPLAY (big-endian) order — note this is
       * the byte-reverse of the attestation's internal-order `merkleRoot`. */
      merkleRootDisplay: string
      blockHash?: string
      time?: number
    }
  | { ok: false; blockHeight: number; reason: string }

/**
 * Pure check: does an attestation's committed (internal-order) merkle root match
 * the merkle root of the supplied block header? No network — the header is given.
 */
export function verifyAttestationAgainstHeader(
  att: { blockHeight: number; merkleRoot: string },
  header: BitcoinBlockHeader,
): BitcoinAttestationVerdict {
  const internal = att.merkleRoot.toLowerCase()
  if (!HEX64.test(internal)) {
    return {
      ok: false,
      blockHeight: att.blockHeight,
      reason: `attestation merkle root is not 32 bytes of hex (${att.merkleRoot.length / 2} bytes)`,
    }
  }
  const got = header.merkleRoot.toLowerCase()
  if (!HEX64.test(got)) {
    return {
      ok: false,
      blockHeight: att.blockHeight,
      reason: `block header merkle root is not 32 bytes of hex (${header.merkleRoot})`,
    }
  }
  if (header.height !== att.blockHeight) {
    return {
      ok: false,
      blockHeight: att.blockHeight,
      reason: `header is for height ${header.height}, attestation is for ${att.blockHeight}`,
    }
  }
  const expectedDisplay = reverseHexBytes(internal)
  if (got !== expectedDisplay) {
    return {
      ok: false,
      blockHeight: att.blockHeight,
      reason:
        `merkle root mismatch — proof commits ${expectedDisplay} at height ${att.blockHeight}, ` +
        `but block ${header.blockHash ?? '(unknown hash)'} has ${got}`,
    }
  }
  const verdict: BitcoinAttestationVerdict = { ok: true, blockHeight: att.blockHeight, merkleRootDisplay: got }
  if (header.blockHash !== undefined) verdict.blockHash = header.blockHash
  if (header.time !== undefined) verdict.time = header.time
  return verdict
}

/**
 * Verify one attestation against a live header source (fetches the header). A
 * source/network failure is reported as `ok: false` with a reason — the caller
 * decides whether an unreachable source degrades to "unverified" (informational)
 * or hard-fails, exactly as the structural verifier already does for pending
 * proofs. A genuine merkle-root MISMATCH is always a hard failure: it means the
 * proof does not actually commit to that block.
 */
export async function verifyAttestationWithSource(
  att: { blockHeight: number; merkleRoot: string },
  source: BitcoinHeaderSource,
): Promise<BitcoinAttestationVerdict & { fetchFailed?: boolean }> {
  let header: BitcoinBlockHeader
  try {
    header = await source.getBlockHeaderByHeight(att.blockHeight)
  } catch (err) {
    return {
      ok: false,
      blockHeight: att.blockHeight,
      reason: `could not fetch block ${att.blockHeight} from ${source.label}: ${err instanceof Error ? err.message : String(err)}`,
      fetchFailed: true,
    }
  }
  return verifyAttestationAgainstHeader(att, header)
}
