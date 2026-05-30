/**
 * Runtime-validation battery for the strict `ethereum-anchor` evidence proof,
 * asserting legacy (sync) and shared (cross-runtime) validators agree.
 *
 * The validator BRANCHES on `type`: an `ethereum-anchor` proof gets strict shape
 * + address/hash-format checks and a recursive `contentHash` rejection (the
 * membership-oracle boundary). An UNKNOWN proof type stays open-ended and is
 * tolerated per spec §02 §4.2 — that tolerance is asserted here so the strict
 * branch never leaks into unknown types.
 */

import { describe, it, expect } from 'vitest'

import { validateEnvelope as legacyValidateEnvelope } from '../../src/envelope/validate.js'
import { validateEnvelope as sharedValidateEnvelope } from '../../src/shared/envelope/validate.js'
import { buildCommittedClaim, buildEnvelope } from '../../src/envelope/build.js'
import { computeClaimHash } from '../../src/envelope/claim-hash.js'

const CONTENT_HASH = 'sha256:' + 'a'.repeat(64)
const CONTRACT = '0x' + '1'.repeat(40)
const REGISTRANT = '0x' + '2'.repeat(40)
const TX_HASH = '0x' + '3'.repeat(64)

function envelopeWithProof(proof: Record<string, unknown>) {
  const claim = buildCommittedClaim({ contentHash: CONTENT_HASH })
  return buildEnvelope(claim, { proofs: [proof as any] })
}

function wellFormed(extra: Record<string, unknown> = {}): Record<string, unknown> {
  const claim = buildCommittedClaim({ contentHash: CONTENT_HASH })
  const claimHash = computeClaimHash(claim)
  return {
    type: 'ethereum-anchor',
    profile: 'urn:screenplay-registration-evidence-ethereum-anchor:v1',
    claimHash,
    chainId: 1,
    contract: CONTRACT,
    registrant: REGISTRANT,
    txHash: TX_HASH,
    logIndex: 2,
    blockNumber: 21345678,
    ...extra,
  }
}

/** Validate against BOTH impls and assert they agree on ok/not-ok and errors. */
function bothAgree(proof: Record<string, unknown>): { ok: boolean; errors: string[] } {
  const env = envelopeWithProof(proof)
  const legacy = legacyValidateEnvelope(env)
  const shared = sharedValidateEnvelope(env)
  expect(shared.ok).toBe(legacy.ok)
  if (!legacy.ok && !shared.ok) {
    expect(shared.errors).toEqual(legacy.errors)
    return { ok: false, errors: legacy.errors }
  }
  return { ok: legacy.ok, errors: [] }
}

describe('ethereum-anchor: happy path', () => {
  it('a well-formed proof validates in both impls', () => {
    expect(bothAgree(wellFormed()).ok).toBe(true)
  })

  it('a well-formed proof WITHOUT the optional profile still validates', () => {
    const p = wellFormed()
    delete p.profile
    expect(bothAgree(p).ok).toBe(true)
  })
})

describe('ethereum-anchor: each required field is enforced', () => {
  for (const field of ['chainId', 'contract', 'registrant', 'txHash', 'logIndex', 'blockNumber']) {
    it(`rejects a proof missing "${field}"`, () => {
      const p = wellFormed()
      delete p[field]
      const out = bothAgree(p)
      expect(out.ok).toBe(false)
      expect(out.errors.some((e) => e.includes(field))).toBe(true)
    })
  }
})

describe('ethereum-anchor: format checks', () => {
  it('rejects a non-hex contract', () => {
    expect(bothAgree(wellFormed({ contract: '0xZZZ' })).ok).toBe(false)
  })

  it('rejects a registrant of the wrong length', () => {
    expect(bothAgree(wellFormed({ registrant: '0x' + '2'.repeat(38) })).ok).toBe(false)
  })

  it('rejects a txHash of the wrong length', () => {
    expect(bothAgree(wellFormed({ txHash: '0x' + '3'.repeat(63) })).ok).toBe(false)
  })

  it('rejects a chainId below 1', () => {
    expect(bothAgree(wellFormed({ chainId: 0 })).ok).toBe(false)
  })

  it('rejects a negative logIndex', () => {
    expect(bothAgree(wellFormed({ logIndex: -1 })).ok).toBe(false)
  })

  it('rejects a wrong profile const', () => {
    const out = bothAgree(wellFormed({ profile: 'urn:wrong:v1' }))
    expect(out.ok).toBe(false)
    expect(out.errors.some((e) => e.includes('profile'))).toBe(true)
  })
})

describe('ethereum-anchor: contentHash membership-oracle boundary', () => {
  it('rejects a top-level contentHash', () => {
    const out = bothAgree(wellFormed({ contentHash: CONTENT_HASH }))
    expect(out.ok).toBe(false)
    expect(out.errors.some((e) => e.includes('contentHash is not permitted'))).toBe(true)
  })

  it('rejects a contentHash nested under batch', () => {
    const out = bothAgree(
      wellFormed({
        batch: { batchId: 'b1', merkleRoot: '0x' + '4'.repeat(64), contentHash: CONTENT_HASH },
      }),
    )
    expect(out.ok).toBe(false)
    expect(out.errors.some((e) => e.includes('contentHash is not permitted'))).toBe(true)
  })

  it('rejects a contentHash nested inside an array element', () => {
    const out = bothAgree(
      wellFormed({
        extras: [{ inner: { contentHash: CONTENT_HASH } }],
      }),
    )
    expect(out.ok).toBe(false)
    expect(out.errors.some((e) => e.includes('contentHash is not permitted'))).toBe(true)
  })
})

describe('unknown proof types remain tolerated (strict branch does not leak)', () => {
  it('an unknown type with extra keys still validates', () => {
    const claim = buildCommittedClaim({ contentHash: CONTENT_HASH })
    const claimHash = computeClaimHash(claim)
    const out = bothAgree({
      type: 'some-future-anchor',
      claimHash,
      arbitrary: 'field',
      nested: { a: 1 },
      // contentHash on an UNKNOWN type is tolerated — the boundary is enforced
      // only on the known ethereum-anchor type.
      contentHash: CONTENT_HASH,
    })
    expect(out.ok).toBe(true)
  })
})
