/**
 * JSON-Schema conditional-dispatch conformance for the envelope schema.
 *
 * `evidenceBundle.proofs.items` is a narrow `if/then` dispatch: the open
 * `EvidenceProof` catch-all applies to every proof (incl. unknown types), and
 * the strict `EthereumAnchorProof` `$def` is layered on ONLY when
 * `type === 'ethereum-anchor'`. This suite proves the dispatch is narrow:
 * existing vectors (opentimestamps, the unknown-type future-eas vector) still
 * validate; a well-formed ethereum-anchor validates; a malformed or
 * wrong-profile ethereum-anchor fails the strict `$def`.
 *
 * Uses ajv (test-only) to evaluate the published schema as a real JSON-Schema
 * 2020-12 document — the reference runtime validator is hand-rolled, so this is
 * the independent check that the schema text itself dispatches correctly.
 */

import { describe, it, expect, beforeAll } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Ajv2020 } from 'ajv/dist/2020.js'
import type { ValidateFunction } from 'ajv'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SPEC_DIR = join(__dirname, '..', '..', 'spec', 'v1')
const CORPUS_DIR = join(SPEC_DIR, 'testvectors', 'envelope')

interface IndexFile {
  envelopeVectors: Array<{ id: string; name: string }>
}

let validate: ValidateFunction
let indexJson: IndexFile

beforeAll(() => {
  const schema = JSON.parse(readFileSync(join(SPEC_DIR, 'envelope.schema.json'), 'utf8'))
  // The schema's $id is a urn:; ajv would otherwise try to resolve $ref against
  // it. We compile the schema in isolation (all $refs are internal #/$defs).
  const ajv = new Ajv2020({ strict: false, allErrors: true })
  validate = ajv.compile(schema)
  indexJson = JSON.parse(readFileSync(join(CORPUS_DIR, 'INDEX.json'), 'utf8')) as IndexFile
})

function loadEnvelopeVector(id: string, name: string): unknown {
  const prefix = `env-${id}-${name}`
  const value = JSON.parse(readFileSync(join(CORPUS_DIR, `${prefix}.value.json`), 'utf8'))
  if (value && typeof value === 'object' && 'envelopeVersion' in value) return value
  // bare-claim vectors: wrap in a minimal envelope shell so the schema applies
  const claimHash = readFileSync(join(CORPUS_DIR, `${prefix}.claim-hash.txt`), 'utf8').trim()
  return {
    envelopeVersion: 'urn:screenplay-registration-envelope:v1',
    committedClaim: value,
    evidenceBundle: { committedClaimHash: claimHash, proofs: [], bundleExtensions: {} },
  }
}

describe('schema dispatch: existing corpus still validates (tolerance preserved)', () => {
  it('every published envelope vector validates against the schema', () => {
    for (const v of indexJson.envelopeVectors) {
      const env = loadEnvelopeVector(v.id, v.name)
      const ok = validate(env)
      expect(ok, `vector env-${v.id}-${v.name} should validate: ${JSON.stringify(validate.errors)}`).toBe(true)
    }
  })

  it('the unknown-type future-eas vector (env-108) validates — open catch-all preserved', () => {
    const env = loadEnvelopeVector('108', 'envelope-with-multiple-proofs')
    expect(validate(env)).toBe(true)
  })

  it('the ethereum-anchor vector (env-111) validates', () => {
    const env = loadEnvelopeVector('111', 'envelope-with-ethereum-anchor')
    expect(validate(env)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Synthetic dispatch cases
// ---------------------------------------------------------------------------

const CLAIM_HASH = 'sha256:' + 'a'.repeat(64)

function envWithProofs(proofs: unknown[]): unknown {
  return {
    envelopeVersion: 'urn:screenplay-registration-envelope:v1',
    committedClaim: {
      claimVersion: 'urn:screenplay-registration-claim:v1',
      schemaId: 'urn:screenplay-registration-claim-schema:v1',
      hashAlgorithm: 'sha-256',
      manifestCanonicalization: 'rfc8785',
      normalizationProfile: 'screenplay-registration-norm/v1-strict',
      contentHash: CLAIM_HASH,
      claimExtensions: {},
    },
    evidenceBundle: { committedClaimHash: CLAIM_HASH, proofs, bundleExtensions: {} },
  }
}

function wellFormedEthAnchor(extra: Record<string, unknown> = {}) {
  return {
    type: 'ethereum-anchor',
    profile: 'urn:screenplay-registration-evidence-ethereum-anchor:v1',
    claimHash: CLAIM_HASH,
    chainId: 1,
    contract: '0x' + '1'.repeat(40),
    registrant: '0x' + '2'.repeat(40),
    txHash: '0x' + '3'.repeat(64),
    logIndex: 2,
    blockNumber: 21345678,
    ...extra,
  }
}

describe('schema dispatch: narrow if/then on type === ethereum-anchor', () => {
  it('an unknown-type proof with extra keys still validates (open catch-all)', () => {
    const env = envWithProofs([{ type: 'novel-anchor', claimHash: CLAIM_HASH, whatever: 1 }])
    expect(validate(env)).toBe(true)
  })

  it('a well-formed ethereum-anchor proof validates against the strict $def', () => {
    expect(validate(envWithProofs([wellFormedEthAnchor()]))).toBe(true)
  })

  it('a well-formed ethereum-anchor without the optional profile validates', () => {
    const p = wellFormedEthAnchor() as Record<string, unknown>
    delete p.profile
    expect(validate(envWithProofs([p]))).toBe(true)
  })

  it('an ethereum-anchor missing a required field fails the strict $def', () => {
    const p = wellFormedEthAnchor() as Record<string, unknown>
    delete p.contract
    expect(validate(envWithProofs([p]))).toBe(false)
  })

  it('an ethereum-anchor with a malformed address fails the strict $def', () => {
    const env = envWithProofs([wellFormedEthAnchor({ registrant: '0xnothex' })])
    expect(validate(env)).toBe(false)
  })

  it('an ethereum-anchor with a wrong profile const fails the strict $def', () => {
    const env = envWithProofs([wellFormedEthAnchor({ profile: 'urn:wrong:v1' })])
    expect(validate(env)).toBe(false)
  })
})
