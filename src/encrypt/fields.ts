/**
 * Reference implementation of The Screenplay Registry v1 encrypted-field layer.
 *
 * See /spec/v1/04-encryption.md for the authoritative specification.
 *
 * AES-256-GCM with a single masterSalt + single PBKDF2 derivation,
 * length-delimited AAD, and length-prefix/zero padding to size buckets.
 */

import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto'

export const KDF_ID = 'pbkdf2-hmac-sha256' as const
export const AAD_FORMAT_ID = 'screenplay-registration-aad-v1' as const
const AAD_FORMAT_BYTES = Buffer.from('screenplay-registration-aad-v1', 'ascii')
export const MIN_KDF_ITERATIONS = 600_000
export const DEFAULT_KDF_ITERATIONS = 600_000
export const MASTER_SALT_LEN = 32
export const IV_LEN = 12
export const GCM_TAG_LEN = 16
export const KEY_LEN = 32 // AES-256

export const DEFAULT_BUCKETS = [16, 64, 256, 1024] as const

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface EncryptedFieldsBlock {
  masterSalt: string // base64 of 32 bytes
  kdf: typeof KDF_ID
  kdfIterations: number
  aadFormat: typeof AAD_FORMAT_ID
  fields: EncryptedField[]
}

export interface EncryptedField {
  name: string
  iv: string // base64 of 12 bytes
  ciphertext: string // base64
  tag: string // base64 of 16 bytes
  paddingBucket: number
}

export interface MasterKeyMaterial {
  masterKey: Buffer // 32 bytes
  masterSaltRaw: Buffer // 32 bytes
  masterSaltBase64: string
  kdfIterations: number
  claimVersion: string
}

// ---------------------------------------------------------------------------
// Master-key derivation (SINGLE PBKDF2 per encrypt/decrypt session)
// ---------------------------------------------------------------------------

export interface DeriveMasterKeyInput {
  password: string
  masterSaltRaw?: Buffer // if omitted, generates 32 fresh random bytes
  kdfIterations?: number
  claimVersion: string
}

export function deriveMasterKey(input: DeriveMasterKeyInput): MasterKeyMaterial {
  const masterSaltRaw = input.masterSaltRaw ?? randomBytes(MASTER_SALT_LEN)
  if (masterSaltRaw.length !== MASTER_SALT_LEN) {
    throw new Error(`masterSalt must be exactly ${MASTER_SALT_LEN} bytes, got ${masterSaltRaw.length}`)
  }
  const kdfIterations = input.kdfIterations ?? DEFAULT_KDF_ITERATIONS
  if (kdfIterations < MIN_KDF_ITERATIONS) {
    throw new Error(`kdfIterations must be ≥ ${MIN_KDF_ITERATIONS} (got ${kdfIterations})`)
  }
  const passwordBuf = Buffer.from(input.password, 'utf8')
  const masterKey = pbkdf2Sync(passwordBuf, masterSaltRaw, kdfIterations, KEY_LEN, 'sha256')
  return {
    masterKey,
    masterSaltRaw,
    masterSaltBase64: masterSaltRaw.toString('base64'),
    kdfIterations,
    claimVersion: input.claimVersion,
  }
}

// ---------------------------------------------------------------------------
// AAD construction (length-delimited per spec §6)
// ---------------------------------------------------------------------------

function buildAad(fieldName: string, material: MasterKeyMaterial): Buffer {
  const nameBuf = Buffer.from(fieldName, 'utf8')
  const cvBuf = Buffer.from(material.claimVersion, 'utf8')
  if (nameBuf.length > 0xffff) {
    throw new Error(`fieldName too long (${nameBuf.length} bytes; max 65535)`)
  }
  if (cvBuf.length > 0xffff) {
    throw new Error(`claimVersion too long (${cvBuf.length} bytes; max 65535)`)
  }
  const nameLenBuf = Buffer.alloc(2)
  nameLenBuf.writeUInt16BE(nameBuf.length, 0)
  const cvLenBuf = Buffer.alloc(2)
  cvLenBuf.writeUInt16BE(cvBuf.length, 0)
  return Buffer.concat([
    AAD_FORMAT_BYTES,
    nameLenBuf,
    nameBuf,
    cvLenBuf,
    cvBuf,
    material.masterSaltRaw,
  ])
}

// ---------------------------------------------------------------------------
// Padding (length-prefix plus zero fill to a chosen bucket)
// ---------------------------------------------------------------------------

const LENGTH_PREFIX_BYTES = 4

export function chooseDefaultBucket(plaintextLen: number): number {
  for (const b of DEFAULT_BUCKETS) {
    if (plaintextLen + LENGTH_PREFIX_BYTES <= b) return b
  }
  // Caller MUST explicitly choose a larger bucket
  throw new Error(
    `plaintext is ${plaintextLen} bytes; default buckets only go up to ${DEFAULT_BUCKETS[DEFAULT_BUCKETS.length - 1]}. ` +
      `Pass an explicit paddingBucket (power-of-2 ≥ ${plaintextLen + LENGTH_PREFIX_BYTES}) to encrypt larger plaintexts.`,
  )
}

function isPowerOfTwo(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0
}

/**
 * Pad plaintext to a length-prefix-then-zero-pad layout per spec §7:
 *   uint32_BE(plaintext_length) || plaintext || zero-bytes-to-bucket
 */
function padToBucket(plaintext: Buffer, bucket: number): Buffer {
  if (!isPowerOfTwo(bucket) || bucket < 16) {
    throw new Error(`paddingBucket must be a power of 2 ≥ 16 (got ${bucket})`)
  }
  if (plaintext.length + LENGTH_PREFIX_BYTES > bucket) {
    throw new Error(
      `plaintext (${plaintext.length} bytes) + length-prefix (${LENGTH_PREFIX_BYTES}) exceeds bucket ${bucket}`,
    )
  }
  const out = Buffer.alloc(bucket) // already zero-filled
  out.writeUInt32BE(plaintext.length, 0)
  plaintext.copy(out, LENGTH_PREFIX_BYTES)
  // remaining bytes are already 0x00 from Buffer.alloc
  return out
}

/**
 * Undo padToBucket. Returns null if padding is malformed.
 */
function unpadFromBucket(padded: Buffer, expectedBucket: number): Buffer | null {
  if (padded.length !== expectedBucket) return null
  if (padded.length < LENGTH_PREFIX_BYTES) return null
  const plaintextLen = padded.readUInt32BE(0)
  if (plaintextLen + LENGTH_PREFIX_BYTES > padded.length) return null
  // Verify trailing bytes are all 0x00
  for (let i = LENGTH_PREFIX_BYTES + plaintextLen; i < padded.length; i++) {
    if (padded[i] !== 0x00) return null
  }
  return padded.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + plaintextLen)
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

export interface EncryptFieldInput {
  /** Field name (becomes unencrypted in the manifest). */
  name: string
  /** Plaintext bytes to encrypt. */
  plaintext: Buffer
  /** Master key material (reuse across multiple fields in the same session). */
  material: MasterKeyMaterial
  /** Override paddingBucket (e.g. for plaintexts > 1024 bytes). */
  paddingBucket?: number
}

export function encryptField(input: EncryptFieldInput): EncryptedField {
  const bucket = input.paddingBucket ?? chooseDefaultBucket(input.plaintext.length)
  if (input.paddingBucket !== undefined) {
    if (!isPowerOfTwo(bucket) || bucket < 16) {
      throw new Error(`paddingBucket must be a power of 2 ≥ 16 (got ${bucket})`)
    }
    if (input.plaintext.length + LENGTH_PREFIX_BYTES > bucket) {
      throw new Error(
        `plaintext (${input.plaintext.length} bytes) plus length-prefix exceeds chosen paddingBucket (${bucket}). Choose a larger bucket.`,
      )
    }
  }
  const padded = padToBucket(input.plaintext, bucket)
  const finalBucket = padded.length
  const iv = randomBytes(IV_LEN)
  const aad = buildAad(input.name, input.material)
  const cipher = createCipheriv('aes-256-gcm', input.material.masterKey, iv)
  cipher.setAAD(aad)
  const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()])
  const tag = cipher.getAuthTag()
  return {
    name: input.name,
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: tag.toString('base64'),
    paddingBucket: finalBucket,
  }
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

export interface DecryptFieldInput {
  field: EncryptedField
  material: MasterKeyMaterial
}

export type DecryptFieldResult =
  | { ok: true; plaintext: Buffer }
  | {
      ok: false
      reason: 'auth-failed' | 'bad-padding' | 'malformed-field'
      detail: string
    }

export function decryptField(input: DecryptFieldInput): DecryptFieldResult {
  let iv: Buffer
  let ciphertext: Buffer
  let tag: Buffer
  try {
    iv = Buffer.from(input.field.iv, 'base64')
    ciphertext = Buffer.from(input.field.ciphertext, 'base64')
    tag = Buffer.from(input.field.tag, 'base64')
  } catch (e: any) {
    return { ok: false, reason: 'malformed-field', detail: `Failed to base64-decode: ${e?.message ?? e}` }
  }
  if (iv.length !== IV_LEN) {
    return { ok: false, reason: 'malformed-field', detail: `IV length ${iv.length} ≠ ${IV_LEN}` }
  }
  if (tag.length !== GCM_TAG_LEN) {
    return { ok: false, reason: 'malformed-field', detail: `tag length ${tag.length} ≠ ${GCM_TAG_LEN}` }
  }
  if (!isPowerOfTwo(input.field.paddingBucket) || input.field.paddingBucket < 16) {
    return {
      ok: false,
      reason: 'malformed-field',
      detail: `paddingBucket ${input.field.paddingBucket} must be a power of 2 ≥ 16`,
    }
  }

  const aad = buildAad(input.field.name, input.material)
  let padded: Buffer
  try {
    const decipher = createDecipheriv('aes-256-gcm', input.material.masterKey, iv)
    decipher.setAAD(aad)
    decipher.setAuthTag(tag)
    padded = Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch {
    // Constant-time-equivalent: don't distinguish wrong password from tampering
    return { ok: false, reason: 'auth-failed', detail: 'authentication failed (wrong password or tampered field)' }
  }

  if (padded.length !== input.field.paddingBucket) {
    return {
      ok: false,
      reason: 'bad-padding',
      detail: `decrypted length ${padded.length} ≠ paddingBucket ${input.field.paddingBucket}`,
    }
  }

  const plaintext = unpadFromBucket(padded, input.field.paddingBucket)
  if (plaintext === null) {
    return { ok: false, reason: 'bad-padding', detail: 'padding bytes are malformed' }
  }
  return { ok: true, plaintext }
}

// ---------------------------------------------------------------------------
// High-level helpers (multi-field convenience)
// ---------------------------------------------------------------------------

export interface BuildEncryptedFieldsBlockInput {
  password: string
  claimVersion: string
  /** Plain key→value map of fields to encrypt. */
  plaintextFields: Record<string, string | Buffer>
  /** Per-field paddingBucket override; default per field uses chooseDefaultBucket. */
  paddingOverrides?: Record<string, number>
  kdfIterations?: number
}

export function buildEncryptedFieldsBlock(input: BuildEncryptedFieldsBlockInput): EncryptedFieldsBlock {
  const material = deriveMasterKey({
    password: input.password,
    claimVersion: input.claimVersion,
    ...(input.kdfIterations !== undefined ? { kdfIterations: input.kdfIterations } : {}),
  })
  const fields: EncryptedField[] = []
  // Sort by name for deterministic output (helps test reproducibility + RFC 8785 canonicalization
  // sorts within objects but arrays are order-preserving, so we sort here for canonical output)
  const names = Object.keys(input.plaintextFields).sort()
  for (const name of names) {
    const value = input.plaintextFields[name]!
    const buf = typeof value === 'string' ? Buffer.from(value, 'utf8') : value
    const override = input.paddingOverrides?.[name]
    const encrypted = encryptField({
      name,
      plaintext: buf,
      material,
      ...(override !== undefined ? { paddingBucket: override } : {}),
    })
    fields.push(encrypted)
  }
  return {
    masterSalt: material.masterSaltBase64,
    kdf: KDF_ID,
    kdfIterations: material.kdfIterations,
    aadFormat: AAD_FORMAT_ID,
    fields,
  }
}

export interface DecryptFieldsBlockInput {
  password: string
  claimVersion: string
  block: EncryptedFieldsBlock
}

export type DecryptFieldsBlockResult =
  | { ok: true; plaintexts: Record<string, Buffer> }
  | { ok: false; failures: Array<{ name: string; reason: string; detail: string }> }

export function decryptFieldsBlock(input: DecryptFieldsBlockInput): DecryptFieldsBlockResult {
  if (input.block.kdf !== KDF_ID) {
    return {
      ok: false,
      failures: [{ name: '*', reason: 'malformed-field', detail: `unsupported KDF: ${input.block.kdf}` }],
    }
  }
  if (input.block.aadFormat !== AAD_FORMAT_ID) {
    return {
      ok: false,
      failures: [
        { name: '*', reason: 'malformed-field', detail: `unsupported aadFormat: ${input.block.aadFormat}` },
      ],
    }
  }
  if (input.block.kdfIterations < MIN_KDF_ITERATIONS) {
    return {
      ok: false,
      failures: [
        {
          name: '*',
          reason: 'malformed-field',
          detail: `kdfIterations ${input.block.kdfIterations} < required ${MIN_KDF_ITERATIONS}`,
        },
      ],
    }
  }
  const masterSaltRaw = Buffer.from(input.block.masterSalt, 'base64')
  const material = deriveMasterKey({
    password: input.password,
    masterSaltRaw,
    kdfIterations: input.block.kdfIterations,
    claimVersion: input.claimVersion,
  })
  const plaintexts: Record<string, Buffer> = {}
  const failures: Array<{ name: string; reason: string; detail: string }> = []
  for (const field of input.block.fields) {
    const res = decryptField({ field, material })
    if (res.ok) {
      plaintexts[field.name] = res.plaintext
    } else {
      failures.push({ name: field.name, reason: res.reason, detail: res.detail })
    }
  }
  if (failures.length > 0) return { ok: false, failures }
  return { ok: true, plaintexts }
}
