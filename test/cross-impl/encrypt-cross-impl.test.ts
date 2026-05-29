/**
 * Cross-impl AES-256-GCM encrypted-field parity. Asserts:
 *   - Same password + masterSalt + claimVersion derives the same master key
 *     in both implementations.
 *   - A field encrypted by the SHARED (Web Crypto) impl decrypts via the
 *     LEGACY (Node node:crypto) impl with the original plaintext.
 *   - A field encrypted by the LEGACY impl decrypts via the SHARED impl.
 *   - Wrong password fails authentication (no plaintext leak).
 *   - Tampered AAD (modified field name) fails authentication.
 */

import { describe, it, expect } from 'vitest'

import {
  deriveMasterKey as sharedDeriveMasterKey,
  encryptField as sharedEncryptField,
  decryptField as sharedDecryptField,
  buildEncryptedFieldsBlock as sharedBuildEncryptedFieldsBlock,
} from '../../src/shared/encrypt/fields.js'

import {
  deriveMasterKey as legacyDeriveMasterKey,
  encryptField as legacyEncryptField,
  decryptField as legacyDecryptField,
  buildEncryptedFieldsBlock as legacyBuildEncryptedFieldsBlock,
} from '../../src/encrypt/fields.js'

const PASSWORD = 'correct horse battery staple'
const CLAIM_VERSION = 'urn:screenplay-registration-claim:v1'
const SALT = new Uint8Array(32).fill(0x42)

describe('cross-impl encrypt: master-key derivation parity', () => {
  it('shared and legacy derive byte-identical master keys for the same inputs', async () => {
    const shared = await sharedDeriveMasterKey({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      masterSaltRaw: SALT,
    })
    const legacy = legacyDeriveMasterKey({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      masterSaltRaw: Buffer.from(SALT),
    })
    expect(shared.kdfIterations).toBe(legacy.kdfIterations)
    expect(shared.masterKey.length).toBe(legacy.masterKey.length)
    for (let i = 0; i < shared.masterKey.length; i++) {
      expect(shared.masterKey[i]).toBe(legacy.masterKey[i])
    }
  })
})

describe('cross-impl encrypt: shared-encrypts / legacy-decrypts', () => {
  it('roundtrips a short plaintext field', async () => {
    const sharedMat = await sharedDeriveMasterKey({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      masterSaltRaw: SALT,
    })
    const legacyMat = legacyDeriveMasterKey({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      masterSaltRaw: Buffer.from(SALT),
    })
    const plaintext = new TextEncoder().encode('My Secret Screenplay Title')
    const sharedField = await sharedEncryptField({
      name: 'title',
      plaintext,
      material: sharedMat,
    })
    const result = legacyDecryptField({
      field: {
        name: sharedField.name,
        iv: sharedField.iv,
        ciphertext: sharedField.ciphertext,
        tag: sharedField.tag,
        paddingBucket: sharedField.paddingBucket,
      },
      material: legacyMat,
    })
    expect(result.ok).toBe(true)
    if (result.ok) {
      const decoded = new TextDecoder().decode(result.plaintext)
      expect(decoded).toBe('My Secret Screenplay Title')
    }
  })
})

describe('cross-impl encrypt: legacy-encrypts / shared-decrypts', () => {
  it('roundtrips a short plaintext field', async () => {
    const sharedMat = await sharedDeriveMasterKey({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      masterSaltRaw: SALT,
    })
    const legacyMat = legacyDeriveMasterKey({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      masterSaltRaw: Buffer.from(SALT),
    })
    const plaintext = Buffer.from('Author Pseudonym', 'utf8')
    const legacyField = legacyEncryptField({
      name: 'author',
      plaintext,
      material: legacyMat,
    })
    const result = await sharedDecryptField({
      field: legacyField,
      material: sharedMat,
    })
    expect(result.ok).toBe(true)
    if (result.ok) {
      const decoded = new TextDecoder().decode(result.plaintext)
      expect(decoded).toBe('Author Pseudonym')
    }
  })
})

describe('cross-impl encrypt: rejects tampered inputs', () => {
  it('wrong password fails GCM auth (no plaintext leak)', async () => {
    const sharedMat = await sharedDeriveMasterKey({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      masterSaltRaw: SALT,
    })
    const wrongMat = await sharedDeriveMasterKey({
      password: 'wrong password',
      claimVersion: CLAIM_VERSION,
      masterSaltRaw: SALT,
    })
    const field = await sharedEncryptField({
      name: 'title',
      plaintext: new TextEncoder().encode('Secret'),
      material: sharedMat,
    })
    const result = await sharedDecryptField({ field, material: wrongMat })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('auth-failed')
  })

  it('tampered field name fails AAD auth', async () => {
    const mat = await sharedDeriveMasterKey({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      masterSaltRaw: SALT,
    })
    const field = await sharedEncryptField({
      name: 'title',
      plaintext: new TextEncoder().encode('Secret'),
      material: mat,
    })
    const tampered = { ...field, name: 'author' }
    const result = await sharedDecryptField({ field: tampered, material: mat })
    expect(result.ok).toBe(false)
  })
})

/**
 * Critical parity: the `fields` array of the EncryptedFieldsBlock is
 * CANONICALIZED via RFC 8785 JCS, which sorts object KEYS but preserves
 * ARRAY order. If shared and legacy disagree on field order, the resulting
 * claim bytes differ → the OTS-anchored claim hash differs → cross-impl
 * proofs cannot match for the same underlying plaintext. The S5 review
 * caught this: shared previously iterated Object.entries (insertion order)
 * while legacy sorted by name. Two-field tests would have caught it.
 */
describe('cross-impl encrypt: buildEncryptedFieldsBlock array-ordering parity', () => {
  it('shared sorts field names alphabetically regardless of caller insertion order', async () => {
    const blockA = await sharedBuildEncryptedFieldsBlock({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      fields: { title: 'My Screenplay', author: 'Some Pseudonym' },
    })
    const blockB = await sharedBuildEncryptedFieldsBlock({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      fields: { author: 'Some Pseudonym', title: 'My Screenplay' },
    })
    expect(blockA.fields.map((f) => f.name)).toEqual(['author', 'title'])
    expect(blockB.fields.map((f) => f.name)).toEqual(['author', 'title'])
  })

  it('shared and legacy produce identical field-name ordering for the same input map', async () => {
    const shared = await sharedBuildEncryptedFieldsBlock({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      fields: { title: 'X', author: 'Y' },
    })
    const legacy = legacyBuildEncryptedFieldsBlock({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      plaintextFields: { title: 'X', author: 'Y' },
    })
    expect(shared.fields.map((f) => f.name)).toEqual(legacy.fields.map((f) => f.name))
    expect(shared.kdf).toBe(legacy.kdf)
    expect(shared.kdfIterations).toBe(legacy.kdfIterations)
    expect(shared.aadFormat).toBe(legacy.aadFormat)
  })

  it('legacy can decrypt every field shared encrypts when given the same masterSalt', async () => {
    const shared = await sharedBuildEncryptedFieldsBlock({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      fields: { title: 'My Screenplay', author: 'Some Pseudonym' },
    })
    // Re-derive legacy material with the SHARED block's masterSalt so we
    // can decrypt each field via the legacy path.
    const legacyMat = legacyDeriveMasterKey({
      password: PASSWORD,
      claimVersion: CLAIM_VERSION,
      masterSaltRaw: Buffer.from(shared.masterSalt, 'base64'),
    })
    expect(shared.fields).toHaveLength(2)
    for (const field of shared.fields) {
      const result = legacyDecryptField({ field, material: legacyMat })
      expect(result.ok).toBe(true)
      if (result.ok) {
        const decoded = new TextDecoder().decode(result.plaintext)
        if (field.name === 'title') expect(decoded).toBe('My Screenplay')
        if (field.name === 'author') expect(decoded).toBe('Some Pseudonym')
      }
    }
  })
})
