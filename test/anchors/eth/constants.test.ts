/**
 * Pinned-constant well-formedness for the optional Ethereum anchor.
 *
 * These constants are the cross-boundary contract shared by the off-chain
 * verifier, the spec text (spec/v1/09), and the reserved Solidity ledger. This
 * suite asserts they are well-formed and self-consistent. Full
 * keccak256(REGISTER_TYPE_STRING) equality is asserted once a live keccak is
 * wired into the typed-data builder; here we assert shape + presence.
 */

import { describe, it, expect } from 'vitest'
import {
  ETHEREUM_ANCHOR_EVIDENCE_PROFILE,
  CANONICAL_CHAIN_ID,
  EIP712_DOMAIN_NAME,
  EIP712_DOMAIN_VERSION,
  REGISTER_TYPE_STRING,
  REGISTER_TYPEHASH,
  REGISTERED_EVENT_ABI,
  REGISTERED_EVENT_SIGNATURE,
  REGISTERED_EVENT_TOPIC0,
  TITLE_MAX_BYTES,
  NAME_MAX_BYTES,
} from '../../../src/anchors/eth/constants.js'

const BYTES32_HEX = /^0x[0-9a-f]{64}$/

describe('ethereum-anchor canonical constants', () => {
  it('pins the evidence profile URN exactly', () => {
    expect(ETHEREUM_ANCHOR_EVIDENCE_PROFILE).toBe(
      'urn:screenplay-registration-evidence-ethereum-anchor:v1',
    )
  })

  it('pins mainnet as the canonical chain', () => {
    expect(CANONICAL_CHAIN_ID).toBe(1)
  })

  it('pins the EIP-712 domain name + version', () => {
    expect(EIP712_DOMAIN_NAME).toBe('ScreenplayLedger')
    expect(EIP712_DOMAIN_VERSION).toBe('1')
  })

  it('pins the REGISTER struct type string with exact field order/types', () => {
    expect(REGISTER_TYPE_STRING).toBe(
      'Register(bytes32 claimHash,string title,string name,address registrant,uint256 nonce)',
    )
  })

  it('REGISTER_TYPEHASH is a well-formed bytes32 hex', () => {
    expect(REGISTER_TYPEHASH).toMatch(BYTES32_HEX)
  })

  it('REGISTERED_EVENT_TOPIC0 is a well-formed bytes32 hex', () => {
    expect(REGISTERED_EVENT_TOPIC0).toMatch(BYTES32_HEX)
  })

  it('the event signature string matches the ABI fragment', () => {
    const inputTypes = REGISTERED_EVENT_ABI.inputs.map((i) => i.type).join(',')
    expect(REGISTERED_EVENT_SIGNATURE).toBe(`Registered(${inputTypes})`)
  })

  it('the event ABI indexes exactly claimHash + registrant', () => {
    expect(REGISTERED_EVENT_ABI.name).toBe('Registered')
    expect(REGISTERED_EVENT_ABI.type).toBe('event')
    const indexed = REGISTERED_EVENT_ABI.inputs
      .filter((i) => i.indexed)
      .map((i) => i.name)
    expect(indexed).toEqual(['claimHash', 'registrant'])
    const claimHashInput = REGISTERED_EVENT_ABI.inputs.find((i) => i.name === 'claimHash')
    expect(claimHashInput?.type).toBe('bytes32')
    const registrantInput = REGISTERED_EVENT_ABI.inputs.find((i) => i.name === 'registrant')
    expect(registrantInput?.type).toBe('address')
  })

  it('byte caps are the pinned length-only limits', () => {
    expect(TITLE_MAX_BYTES).toBe(128)
    expect(NAME_MAX_BYTES).toBe(64)
  })
})
