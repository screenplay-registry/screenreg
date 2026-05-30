/**
 * EIP-712 typed-data builder for the gasless `registerWithSig` ledger message.
 *
 * This is the additive hook for the optional Ethereum-mainnet ledger: it BUILDS
 * the exact 32-byte digest a user signs to authorize an on-chain registration of
 * their `claimHash`. The previewed fields (`claimHash`, `title`, `name`,
 * `registrant`, `nonce`, `chainId`, `verifyingContract`) MUST be exactly the
 * payload the user signs — a UI/relayer mismatch would defeat the consent
 * ceremony (spec §09 consent UX).
 *
 * This module BUILDS digests only. It NEVER recovers or verifies a signature:
 * signature recovery is performed exclusively by the on-chain contract. The
 * off-chain log verifier reads event topics, never recovers EIP-712 (spec §09).
 *
 * Cryptographic boundary: keccak-256 is not in the Web Crypto API and is
 * required to interoperate with the EVM, so the widely-reviewed `@noble/hashes`
 * keccak is used HERE. This dependency is confined to the peripheral
 * `src/anchors/eth/` modules and never reaches the frozen commitment core or any
 * `src/shared/**` module. No hand-rolled keccak or ABI encoding.
 *
 * See spec/v1/09-onchain-anchor.md.
 */

import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js'

import {
  EIP712_DOMAIN_NAME,
  EIP712_DOMAIN_VERSION,
  REGISTER_TYPE_STRING,
} from './constants.js'

/** EIP-712 domain rendered for a consent preview / typed-data object. */
export interface RegisterDomain {
  name: typeof EIP712_DOMAIN_NAME
  version: typeof EIP712_DOMAIN_VERSION
  chainId: number
  verifyingContract: string
}

/** The `Register` struct message a user signs. */
export interface RegisterMessage {
  /** Envelope claimHash, with or without the `sha256:` prefix; encoded as bytes32. */
  claimHash: string
  title: string
  name: string
  /** 20-byte `0x`-prefixed address. */
  registrant: string
  /** Per-registrant strict replay nonce. */
  nonce: number | bigint
  chainId: number
  verifyingContract: string
}

/** The EIP-712 typed-data object (the consent-preview = signed-payload shape). */
export interface RegisterTypedData {
  domain: RegisterDomain
  types: {
    EIP712Domain: { name: string; type: string }[]
    Register: { name: string; type: string }[]
  }
  primaryType: 'Register'
  message: {
    claimHash: string
    title: string
    name: string
    registrant: string
    nonce: string
    chainId: number
    verifyingContract: string
  }
}

const HEX32 = /^0x[0-9a-fA-F]{64}$/
const ADDRESS = /^0x[0-9a-fA-F]{40}$/

function keccak(bytes: Uint8Array): Uint8Array {
  return keccak_256(bytes)
}

function hex0x(bytes: Uint8Array): string {
  return '0x' + bytesToHex(bytes)
}

/**
 * Encode the claimHash as an EVM `bytes32` word. Strips a leading `sha256:`
 * label if present (the on-chain `claimHash` is the raw 32-byte digest, never the
 * `sha256:`-tagged string). Returns 32 bytes; throws on a malformed input.
 */
export function claimHashToBytes32(claimHash: string): Uint8Array {
  const stripped = claimHash.startsWith('sha256:') ? claimHash.slice('sha256:'.length) : claimHash
  const withPrefix = stripped.startsWith('0x') ? stripped : '0x' + stripped
  if (!HEX32.test(withPrefix)) {
    throw new Error(`claimHash is not a 32-byte hex digest: ${JSON.stringify(claimHash)}`)
  }
  return hexToBytes(withPrefix.slice(2))
}

/** Left-pad a 20-byte address to a 32-byte EVM word (ABI encoding of `address`). */
function addressWord(address: string): Uint8Array {
  if (!ADDRESS.test(address)) {
    throw new Error(`not a 20-byte address: ${JSON.stringify(address)}`)
  }
  const raw = hexToBytes(address.slice(2))
  const word = new Uint8Array(32)
  word.set(raw, 12)
  return word
}

/** Encode a `uint256` (number or bigint) as a 32-byte big-endian EVM word. */
function uint256Word(value: number | bigint): Uint8Array {
  let v = typeof value === 'bigint' ? value : BigInt(value)
  if (v < 0n) throw new Error(`uint256 cannot be negative: ${value}`)
  const word = new Uint8Array(32)
  for (let i = 31; i >= 0 && v > 0n; i--) {
    word[i] = Number(v & 0xffn)
    v >>= 8n
  }
  if (v > 0n) throw new Error(`uint256 overflow: ${value}`)
  return word
}

/**
 * `keccak256(REGISTER_TYPE_STRING)` — the EIP-712 `REGISTER_TYPEHASH`.
 * Re-derived live (not read from the pinned constant) so the parity test can
 * assert the pinned literal equals this computed value.
 */
export function registerTypehash(): Uint8Array {
  return keccak(utf8ToBytes(REGISTER_TYPE_STRING))
}

/**
 * The EIP-712 domain separator for the actual `(chainId, verifyingContract)`.
 * Computed per the proof's chain — NEVER hard-coded to mainnet — so a verifier
 * on any chain derives the correct separator.
 */
export function registerDomainSeparator(chainId: number, verifyingContract: string): string {
  const domainTypehash = keccak(
    utf8ToBytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
  )
  const encoded = concatBytes(
    domainTypehash,
    keccak(utf8ToBytes(EIP712_DOMAIN_NAME)),
    keccak(utf8ToBytes(EIP712_DOMAIN_VERSION)),
    uint256Word(chainId),
    addressWord(verifyingContract),
  )
  return hex0x(keccak(encoded))
}

/**
 * The EIP-712 struct hash for a `Register` message:
 *   keccak256(REGISTER_TYPEHASH ‖ claimHash ‖ keccak(title) ‖ keccak(name) ‖
 *             registrant ‖ nonce)
 * Dynamic `string` fields (`title`, `name`) are encoded as `keccak256(utf8)` per
 * the EIP-712 struct-encoding rules; `bytes32`/`address`/`uint256` are inline.
 */
export function registerStructHash(message: RegisterMessage): string {
  const encoded = concatBytes(
    registerTypehash(),
    claimHashToBytes32(message.claimHash),
    keccak(utf8ToBytes(message.title)),
    keccak(utf8ToBytes(message.name)),
    addressWord(message.registrant),
    uint256Word(message.nonce),
  )
  return hex0x(keccak(encoded))
}

/**
 * The 32-byte EIP-712 digest the user signs:
 *   keccak256(0x1901 ‖ domainSeparator ‖ structHash)
 */
export function registerDigest(message: RegisterMessage): string {
  const domainSeparator = hexToBytes(registerDomainSeparator(message.chainId, message.verifyingContract).slice(2))
  const structHash = hexToBytes(registerStructHash(message).slice(2))
  const prefix = new Uint8Array([0x19, 0x01])
  return hex0x(keccak(concatBytes(prefix, domainSeparator, structHash)))
}

/**
 * Build the EIP-712 typed-data object for a `Register` message. This is the
 * exact structure a wallet renders and signs, and the exact field set the
 * consent preview MUST show (spec §09). `nonce` is rendered as a decimal string
 * (wallet `uint256` convention). `claimHash` is normalized to the bytes32 hex
 * form (`sha256:` stripped) that the contract sees.
 */
export function buildRegisterTypedData(message: RegisterMessage): RegisterTypedData {
  return {
    domain: {
      name: EIP712_DOMAIN_NAME,
      version: EIP712_DOMAIN_VERSION,
      chainId: message.chainId,
      verifyingContract: message.verifyingContract,
    },
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Register: [
        { name: 'claimHash', type: 'bytes32' },
        { name: 'title', type: 'string' },
        { name: 'name', type: 'string' },
        { name: 'registrant', type: 'address' },
        { name: 'nonce', type: 'uint256' },
      ],
    },
    primaryType: 'Register',
    message: {
      claimHash: hex0x(claimHashToBytes32(message.claimHash)),
      title: message.title,
      name: message.name,
      registrant: message.registrant,
      nonce: (typeof message.nonce === 'bigint' ? message.nonce : BigInt(message.nonce)).toString(),
      chainId: message.chainId,
      verifyingContract: message.verifyingContract,
    },
  }
}
