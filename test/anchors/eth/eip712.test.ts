/**
 * Unit suite for the EIP-712 `Register` typed-data builder.
 *
 * Asserts keccak known-answers, the live REGISTER_TYPEHASH derivation, the
 * per-chain domain separator (a different chainId yields a different separator),
 * the struct hash, the final signed digest, and the claimHash → bytes32 encoding
 * (with `sha256:` stripped). Solidity-generated cross-repo parity is asserted
 * separately against the committed static vector.
 */

import { describe, it, expect } from 'vitest'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js'

import {
  buildRegisterTypedData,
  registerDomainSeparator,
  registerStructHash,
  registerDigest,
  registerTypehash,
  claimHashToBytes32,
  type RegisterMessage,
} from '../../../src/anchors/eth/eip712.js'
import {
  REGISTER_TYPE_STRING,
  REGISTER_TYPEHASH,
  EIP712_DOMAIN_NAME,
  EIP712_DOMAIN_VERSION,
} from '../../../src/anchors/eth/constants.js'

const HEX32 = /^0x[0-9a-f]{64}$/
const CLAIM = 'sha256:' + 'ab'.repeat(32)
const VERIFYING_CONTRACT = '0x' + '12'.repeat(20)
const REGISTRANT = '0x' + '34'.repeat(20)

const baseMessage: RegisterMessage = {
  claimHash: CLAIM,
  title: 'THE LAST REWRITE',
  name: 'Jane Roe',
  registrant: REGISTRANT,
  nonce: 0,
  chainId: 1,
  verifyingContract: VERIFYING_CONTRACT,
}

describe('keccak256 known-answers', () => {
  it('hashes the empty string to the canonical keccak digest', () => {
    expect('0x' + bytesToHex(keccak_256(utf8ToBytes('')))).toBe(
      '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    )
  })

  it('derives REGISTER_TYPEHASH live, equal to the pinned constant', () => {
    expect('0x' + bytesToHex(registerTypehash())).toBe(REGISTER_TYPEHASH)
    // and the live keccak of the type string equals the same value
    expect('0x' + bytesToHex(keccak_256(utf8ToBytes(REGISTER_TYPE_STRING)))).toBe(REGISTER_TYPEHASH)
  })
})

describe('claimHashToBytes32', () => {
  it('strips the sha256: prefix and yields a 32-byte hex word', () => {
    const out = claimHashToBytes32(CLAIM)
    expect(out.length).toBe(32)
    expect('0x' + bytesToHex(out)).toBe('0x' + 'ab'.repeat(32))
  })

  it('accepts a bare 64-hex digest (no prefix)', () => {
    expect('0x' + bytesToHex(claimHashToBytes32('ab'.repeat(32)))).toBe('0x' + 'ab'.repeat(32))
  })

  it('throws on a malformed digest', () => {
    expect(() => claimHashToBytes32('sha256:notahash')).toThrow()
  })
})

describe('registerDomainSeparator', () => {
  it('is a well-formed bytes32', () => {
    expect(registerDomainSeparator(1, VERIFYING_CONTRACT)).toMatch(HEX32)
  })

  it('differs by chainId (computed per actual chain, never hard-coded to 1)', () => {
    const sep1 = registerDomainSeparator(1, VERIFYING_CONTRACT)
    const sep137 = registerDomainSeparator(137, VERIFYING_CONTRACT)
    expect(sep1).not.toBe(sep137)
  })

  it('differs by verifyingContract', () => {
    const a = registerDomainSeparator(1, VERIFYING_CONTRACT)
    const b = registerDomainSeparator(1, '0x' + '56'.repeat(20))
    expect(a).not.toBe(b)
  })
})

describe('registerStructHash / registerDigest', () => {
  it('produce well-formed bytes32 values', () => {
    expect(registerStructHash(baseMessage)).toMatch(HEX32)
    expect(registerDigest(baseMessage)).toMatch(HEX32)
  })

  it('are deterministic for the same message', () => {
    expect(registerStructHash(baseMessage)).toBe(registerStructHash({ ...baseMessage }))
    expect(registerDigest(baseMessage)).toBe(registerDigest({ ...baseMessage }))
  })

  it('change when the title changes (string fields are keccak-hashed inline)', () => {
    expect(registerStructHash(baseMessage)).not.toBe(
      registerStructHash({ ...baseMessage, title: 'DIFFERENT' }),
    )
  })

  it('change when the nonce changes', () => {
    expect(registerDigest(baseMessage)).not.toBe(registerDigest({ ...baseMessage, nonce: 1 }))
  })

  it('the digest depends on the domain (chainId flows through)', () => {
    expect(registerDigest(baseMessage)).not.toBe(registerDigest({ ...baseMessage, chainId: 137 }))
  })

  it('accepts a bigint nonce equal to a number nonce', () => {
    expect(registerDigest({ ...baseMessage, nonce: 5 })).toBe(
      registerDigest({ ...baseMessage, nonce: 5n }),
    )
  })
})

describe('buildRegisterTypedData', () => {
  it('renders the exact consent-preview field set', () => {
    const td = buildRegisterTypedData(baseMessage)
    expect(td.primaryType).toBe('Register')
    expect(td.domain).toEqual({
      name: EIP712_DOMAIN_NAME,
      version: EIP712_DOMAIN_VERSION,
      chainId: 1,
      verifyingContract: VERIFYING_CONTRACT,
    })
    // The signed message carries ONLY the Register struct fields. chainId and
    // verifyingContract are bound through the EIP-712 domain, not the struct, so
    // they MUST NOT appear as untyped extra keys in `message`.
    expect(Object.keys(td.message).sort()).toEqual(
      ['claimHash', 'name', 'nonce', 'registrant', 'title'].sort(),
    )
  })

  it('encodes claimHash as bytes32 (sha256: stripped) and nonce as a decimal string', () => {
    const td = buildRegisterTypedData({ ...baseMessage, nonce: 42 })
    expect(td.message.claimHash).toBe('0x' + 'ab'.repeat(32))
    expect(td.message.nonce).toBe('42')
  })

  it('declares the Register field order/types matching the pinned type string', () => {
    const td = buildRegisterTypedData(baseMessage)
    expect(td.types.Register).toEqual([
      { name: 'claimHash', type: 'bytes32' },
      { name: 'title', type: 'string' },
      { name: 'name', type: 'string' },
      { name: 'registrant', type: 'address' },
      { name: 'nonce', type: 'uint256' },
    ])
  })
})
