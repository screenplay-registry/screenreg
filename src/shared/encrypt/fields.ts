/**
 * Cross-runtime AES-256-GCM encrypted-field layer.
 *
 * Web Crypto API only — `crypto.subtle.deriveBits({ name: 'PBKDF2', ... })`
 * and `crypto.subtle.encrypt({ name: 'AES-GCM', ... })`. Byte-equivalent to
 * the legacy Node-side implementation in `src/encrypt/fields.ts`. Cross-impl
 * tests pin that a field encrypted by either implementation decrypts via
 * either.
 *
 * Spec: spec/v1/04-encryption.md.
 *
 * Key construction:
 *   masterSalt    32 random bytes (per-claim, public)
 *   masterKey     PBKDF2-HMAC-SHA256(password, masterSalt, 600_000, 32)
 *
 * Per-field encryption:
 *   IV            12 random bytes (per-field)
 *   AAD           "screenplay-registration-aad-v1" ||
 *                 uint16BE(name.len) || name ||
 *                 uint16BE(claimVersion.len) || claimVersion ||
 *                 masterSalt
 *   plaintext'    uint32BE(plaintext.len) || plaintext || zeros to bucket
 *   ciphertext    AES-256-GCM(masterKey, IV, plaintext', AAD)
 *   tag           128-bit GCM auth tag (separated from ciphertext per spec)
 */

import { type EncryptedField, type EncryptedFieldsBlock } from '../envelope/types.js'

export const KDF_ID = 'pbkdf2-hmac-sha256' as const
export const AAD_FORMAT_ID = 'screenplay-registration-aad-v1' as const
const AAD_FORMAT_BYTES = new TextEncoder().encode(AAD_FORMAT_ID)
export const MIN_KDF_ITERATIONS = 600_000
export const DEFAULT_KDF_ITERATIONS = 600_000
export const MASTER_SALT_LEN = 32
export const IV_LEN = 12
export const GCM_TAG_LEN = 16
export const KEY_LEN = 32

export const DEFAULT_BUCKETS = [16, 64, 256, 1024] as const

const LENGTH_PREFIX_BYTES = 4

export interface MasterKeyMaterial {
  /** Raw 32-byte AES key (call sites use this via Web Crypto importKey). */
  masterKey: Uint8Array
  masterSaltRaw: Uint8Array
  masterSaltBase64: string
  kdfIterations: number
  claimVersion: string
}

export interface DeriveMasterKeyInput {
  password: string
  claimVersion: string
  masterSaltRaw?: Uint8Array
  kdfIterations?: number
}

export async function deriveMasterKey(
  input: DeriveMasterKeyInput,
): Promise<MasterKeyMaterial> {
  const masterSaltRaw = input.masterSaltRaw ?? randomBytes(MASTER_SALT_LEN)
  if (masterSaltRaw.length !== MASTER_SALT_LEN) {
    throw new Error(
      `masterSalt must be exactly ${MASTER_SALT_LEN} bytes, got ${masterSaltRaw.length}`,
    )
  }
  const kdfIterations = input.kdfIterations ?? DEFAULT_KDF_ITERATIONS
  if (kdfIterations < MIN_KDF_ITERATIONS) {
    throw new Error(
      `kdfIterations must be >= ${MIN_KDF_ITERATIONS} (got ${kdfIterations})`,
    )
  }
  const passwordBytes = new TextEncoder().encode(input.password)
  const passwordBuffer = bytesToArrayBuffer(passwordBytes)
  const saltBuffer = bytesToArrayBuffer(masterSaltRaw)
  const baseKey = await globalThis.crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits'],
  )
  const derivedBuffer = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: kdfIterations,
      hash: 'SHA-256',
    },
    baseKey,
    KEY_LEN * 8,
  )
  return {
    masterKey: new Uint8Array(derivedBuffer),
    masterSaltRaw,
    masterSaltBase64: uint8ArrayToBase64(masterSaltRaw),
    kdfIterations,
    claimVersion: input.claimVersion,
  }
}

export function chooseDefaultBucket(plaintextLen: number): number {
  for (const b of DEFAULT_BUCKETS) {
    if (plaintextLen + LENGTH_PREFIX_BYTES <= b) return b
  }
  throw new Error(
    `plaintext is ${plaintextLen} bytes; default buckets only go up to ${DEFAULT_BUCKETS[DEFAULT_BUCKETS.length - 1]}. Pass an explicit paddingBucket.`,
  )
}

export interface EncryptFieldInput {
  name: string
  plaintext: Uint8Array
  material: MasterKeyMaterial
  paddingBucket?: number
}

export async function encryptField(input: EncryptFieldInput): Promise<EncryptedField> {
  const bucket = input.paddingBucket ?? chooseDefaultBucket(input.plaintext.length)
  if (!isPowerOfTwo(bucket) || bucket < 16) {
    throw new Error(`paddingBucket must be a power of 2 >= 16 (got ${bucket})`)
  }
  if (input.plaintext.length + LENGTH_PREFIX_BYTES > bucket) {
    throw new Error(
      `plaintext (${input.plaintext.length} bytes) + length-prefix exceeds bucket ${bucket}`,
    )
  }
  const padded = padToBucket(input.plaintext, bucket)
  const iv = randomBytes(IV_LEN)
  const aad = buildAad(input.name, input.material)
  const key = await importAesKey(input.material.masterKey)
  // Web Crypto AES-GCM returns ciphertext concatenated with the auth tag.
  const ciphertextAndTag = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: bytesToArrayBuffer(iv),
        additionalData: bytesToArrayBuffer(aad),
        tagLength: GCM_TAG_LEN * 8,
      },
      key as any,
      bytesToArrayBuffer(padded),
    ),
  )
  const ciphertext = ciphertextAndTag.slice(0, ciphertextAndTag.length - GCM_TAG_LEN)
  const tag = ciphertextAndTag.slice(ciphertextAndTag.length - GCM_TAG_LEN)
  return {
    name: input.name,
    iv: uint8ArrayToBase64(iv),
    ciphertext: uint8ArrayToBase64(ciphertext),
    tag: uint8ArrayToBase64(tag),
    paddingBucket: bucket,
  }
}

export interface DecryptFieldInput {
  field: EncryptedField
  material: MasterKeyMaterial
}

export type DecryptFieldResult =
  | { ok: true; plaintext: Uint8Array }
  | { ok: false; reason: 'auth-failed' | 'bad-padding' | 'malformed-field'; detail: string }

export async function decryptField(
  input: DecryptFieldInput,
): Promise<DecryptFieldResult> {
  let iv: Uint8Array
  let ciphertext: Uint8Array
  let tag: Uint8Array
  try {
    iv = base64ToUint8Array(input.field.iv)
    ciphertext = base64ToUint8Array(input.field.ciphertext)
    tag = base64ToUint8Array(input.field.tag)
  } catch (e) {
    return {
      ok: false,
      reason: 'malformed-field',
      detail: `base64 decode: ${e instanceof Error ? e.message : String(e)}`,
    }
  }
  if (iv.length !== IV_LEN) {
    return { ok: false, reason: 'malformed-field', detail: `IV length ${iv.length} != ${IV_LEN}` }
  }
  if (tag.length !== GCM_TAG_LEN) {
    return { ok: false, reason: 'malformed-field', detail: `tag length ${tag.length} != ${GCM_TAG_LEN}` }
  }
  if (!isPowerOfTwo(input.field.paddingBucket) || input.field.paddingBucket < 16) {
    return {
      ok: false,
      reason: 'malformed-field',
      detail: `paddingBucket ${input.field.paddingBucket} must be a power of 2 >= 16`,
    }
  }
  const aad = buildAad(input.field.name, input.material)
  const key = await importAesKey(input.material.masterKey)
  // Re-concatenate ciphertext + tag for Web Crypto's verify+decrypt.
  const combined = new Uint8Array(ciphertext.length + tag.length)
  combined.set(ciphertext, 0)
  combined.set(tag, ciphertext.length)
  let padded: Uint8Array
  try {
    padded = new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: bytesToArrayBuffer(iv),
          additionalData: bytesToArrayBuffer(aad),
          tagLength: GCM_TAG_LEN * 8,
        },
        key as any,
        bytesToArrayBuffer(combined),
      ),
    )
  } catch (e) {
    return {
      ok: false,
      reason: 'auth-failed',
      detail: `GCM auth failed: ${e instanceof Error ? e.message : String(e)}`,
    }
  }
  const unpadded = unpadFromBucket(padded, input.field.paddingBucket)
  if (unpadded === null) {
    return { ok: false, reason: 'bad-padding', detail: 'padding malformed' }
  }
  return { ok: true, plaintext: unpadded }
}

/**
 * Encrypt a {name → plaintext} map under a single derived master key. Returns
 * the full EncryptedFieldsBlock ready to insert into committedClaim.
 *
 * Field names are sorted before encryption so the resulting `fields` array
 * is byte-identical regardless of caller insertion order. The legacy CLI at
 * src/encrypt/fields.ts does the same. RFC 8785 JCS sorts object KEYS but
 * preserves ARRAY order — without sorting here, two writers passing
 * {title,author} vs {author,title} would produce different canonical claim
 * bytes and therefore different OTS-anchored claim hashes for the same
 * underlying plaintext.
 */
export async function buildEncryptedFieldsBlock(input: {
  password: string
  claimVersion: string
  fields: Record<string, string>
}): Promise<EncryptedFieldsBlock> {
  const material = await deriveMasterKey({
    password: input.password,
    claimVersion: input.claimVersion,
  })
  const encryptedFields: EncryptedField[] = []
  const names = Object.keys(input.fields).sort()
  for (const name of names) {
    const plaintext = input.fields[name]!
    const enc = await encryptField({
      name,
      plaintext: new TextEncoder().encode(plaintext),
      material,
    })
    encryptedFields.push(enc)
  }
  return {
    masterSalt: material.masterSaltBase64,
    kdf: KDF_ID,
    kdfIterations: material.kdfIterations,
    aadFormat: AAD_FORMAT_ID,
    fields: encryptedFields,
  }
}

// ===========================================================================
// AAD + padding helpers
// ===========================================================================

function buildAad(fieldName: string, material: MasterKeyMaterial): Uint8Array {
  const enc = new TextEncoder()
  const nameBuf = enc.encode(fieldName)
  const cvBuf = enc.encode(material.claimVersion)
  if (nameBuf.length > 0xffff) throw new Error('fieldName too long')
  if (cvBuf.length > 0xffff) throw new Error('claimVersion too long')
  const out = new Uint8Array(
    AAD_FORMAT_BYTES.length + 2 + nameBuf.length + 2 + cvBuf.length + material.masterSaltRaw.length,
  )
  let off = 0
  out.set(AAD_FORMAT_BYTES, off)
  off += AAD_FORMAT_BYTES.length
  out[off++] = (nameBuf.length >> 8) & 0xff
  out[off++] = nameBuf.length & 0xff
  out.set(nameBuf, off)
  off += nameBuf.length
  out[off++] = (cvBuf.length >> 8) & 0xff
  out[off++] = cvBuf.length & 0xff
  out.set(cvBuf, off)
  off += cvBuf.length
  out.set(material.masterSaltRaw, off)
  return out
}

function padToBucket(plaintext: Uint8Array, bucket: number): Uint8Array {
  if (!isPowerOfTwo(bucket) || bucket < 16) {
    throw new Error(`paddingBucket must be power of 2 >= 16 (got ${bucket})`)
  }
  if (plaintext.length + LENGTH_PREFIX_BYTES > bucket) {
    throw new Error('plaintext exceeds bucket')
  }
  const out = new Uint8Array(bucket)
  // uint32BE(plaintext.length)
  out[0] = (plaintext.length >>> 24) & 0xff
  out[1] = (plaintext.length >>> 16) & 0xff
  out[2] = (plaintext.length >>> 8) & 0xff
  out[3] = plaintext.length & 0xff
  out.set(plaintext, LENGTH_PREFIX_BYTES)
  // trailing zeros from new Uint8Array initialization
  return out
}

function unpadFromBucket(padded: Uint8Array, expectedBucket: number): Uint8Array | null {
  if (padded.length !== expectedBucket) return null
  if (padded.length < LENGTH_PREFIX_BYTES) return null
  const plaintextLen =
    (padded[0]! << 24) | (padded[1]! << 16) | (padded[2]! << 8) | padded[3]!
  if (plaintextLen < 0 || plaintextLen + LENGTH_PREFIX_BYTES > padded.length) return null
  for (let i = LENGTH_PREFIX_BYTES + plaintextLen; i < padded.length; i++) {
    if (padded[i] !== 0x00) return null
  }
  return padded.slice(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + plaintextLen)
}

function isPowerOfTwo(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0
}

async function importAesKey(rawKey: Uint8Array): Promise<unknown> {
  const buf = bytesToArrayBuffer(rawKey)
  return globalThis.crypto.subtle.importKey('raw', buf, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ])
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n)
  globalThis.crypto.getRandomValues(out)
  return out
}

function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(buf).set(bytes)
  return buf
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
  return globalThis.btoa(bin)
}

function base64ToUint8Array(b64: string): Uint8Array {
  const bin = globalThis.atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
