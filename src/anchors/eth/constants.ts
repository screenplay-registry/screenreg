/**
 * Canonical constants for the optional Ethereum-mainnet anchor.
 *
 * These shapes are the cross-boundary contract between three artifacts that
 * MUST agree byte-for-byte:
 *   1. this module (the off-chain TypeScript verifier + EIP-712 typed-data builder),
 *   2. the on-chain `ScreenplayLedger` Solidity contract (Tier-2, reserved),
 *   3. the spec text in `spec/v1/09-onchain-anchor.md`.
 *
 * The Ethereum anchor is a SECONDARY, additive witness to the same 32-byte
 * `claimHash`. It is NEVER a priority/time source — Bitcoin (via OpenTimestamps)
 * remains the sole time + priority anchor. This module lives outside the frozen
 * commitment core (`src/normalize`, `src/envelope`, `src/merkle`, `src/encrypt`,
 * `src/shared`) and is never reachable from any commitment-bearing path.
 *
 * A keccak-256 dependency (`@noble/hashes`) is permitted in this peripheral
 * `src/anchors/eth/` module only — keccak is not in the Web Crypto API and is
 * required to interoperate with the EVM. The commitment core stays dependency-free.
 *
 * See spec/v1/09-onchain-anchor.md.
 */

/**
 * Evidence-proof profile URN for an Ethereum-anchor proof entry. Optional on the
 * proof; when present it MUST equal this value.
 */
export const ETHEREUM_ANCHOR_EVIDENCE_PROFILE =
  'urn:screenplay-registration-evidence-ethereum-anchor:v1' as const

/**
 * The one chain a v1 verifier pins. The optional on-chain ledger is Ethereum
 * mainnet only (not an L2). A proof MUST carry `chainId === CANONICAL_CHAIN_ID`
 * for a v1 verifier to treat it as a candidate.
 */
export const CANONICAL_CHAIN_ID = 1 as const

/**
 * EIP-712 domain. `chainId` and `verifyingContract` are bound at verification
 * time per the actual proof; only `name` and `version` are pinned here.
 */
export const EIP712_DOMAIN_NAME = 'ScreenplayLedger' as const
export const EIP712_DOMAIN_VERSION = '1' as const

/**
 * EIP-712 struct type string for the gasless `registerWithSig` message. The
 * field order and types are part of the typehash and MUST NOT change. The
 * on-chain `REGISTER_TYPEHASH` is `keccak256` of this exact string.
 */
export const REGISTER_TYPE_STRING =
  'Register(bytes32 claimHash,string title,string name,address registrant,uint256 nonce)' as const

/**
 * Precomputed `keccak256(REGISTER_TYPE_STRING)`. Pinned so the off-chain builder,
 * the spec, and the Solidity contract share one literal. Re-derivable from
 * `REGISTER_TYPE_STRING`; the parity test asserts equality once a live keccak is
 * wired into the typed-data builder.
 */
export const REGISTER_TYPEHASH =
  '0x906391fe7c2de371bd901d51d6f0e0075e07208ff18c5198838bd34ffd9477a5' as const

/**
 * Canonical `Registered` event. `claimHash` and `registrant` are indexed
 * (filterable topics); `blockTime`, `title`, and `name` are data. The event IS
 * the canonical on-chain ledger — there is no `claimHash → data` storage mapping.
 */
export const REGISTERED_EVENT_ABI = {
  type: 'event',
  name: 'Registered',
  anonymous: false,
  inputs: [
    { name: 'claimHash', type: 'bytes32', indexed: true },
    { name: 'registrant', type: 'address', indexed: true },
    { name: 'blockTime', type: 'uint256', indexed: false },
    { name: 'title', type: 'string', indexed: false },
    { name: 'name', type: 'string', indexed: false },
  ],
} as const

/**
 * Canonical event signature string whose `keccak256` is the topic[0] of every
 * `Registered` log.
 */
export const REGISTERED_EVENT_SIGNATURE =
  'Registered(bytes32,address,uint256,string,string)' as const

/**
 * Precomputed `keccak256(REGISTERED_EVENT_SIGNATURE)` — the log's topic[0].
 * Pinned so the off-chain log filter does not need a keccak at module load.
 */
export const REGISTERED_EVENT_TOPIC0 =
  '0xd2447c3a89a5ee056ff41d62d513b054faa56c17b9074ead1e0b964a43dcd1e9' as const

/**
 * Length caps for the user-chosen `title` and `name` strings, in UTF-8 bytes.
 * The on-chain contract enforces length ONLY (no UTF-8 / control-char checks);
 * these are part of the cross-boundary contract.
 */
export const TITLE_MAX_BYTES = 128 as const
export const NAME_MAX_BYTES = 64 as const
