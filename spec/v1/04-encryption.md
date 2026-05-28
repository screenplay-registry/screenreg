# Screenplay Registry Protocol v1.0
## Section 04 — Encrypted Manifest Fields

**AAD format identifier**: `screenplay-registration-aad-v1` (commitment-bearing — embedded in `encryptedFields.aadFormat`)
**KDF identifier**: `pbkdf2-hmac-sha256` (commitment-bearing — embedded in `encryptedFields.kdf`)

---

### 1. Purpose

Allow owners to encrypt selected metadata fields (typically title, author, contact) with a
password they alone hold, while still committing the encrypted form into the on-chain claim.
This gives writers privacy by default while preserving the protocol's tamper-evidence guarantees.

The encryption layer is OPTIONAL. If `committedClaim.encryptedFields` is absent, no encryption
is in use; if present, all of its fields are part of the on-chain commitment.

### 2. Threat model

This layer defends against:
- **Manifest snooper** who has the manifest file but not the password — cannot read plaintext field values.
- **Field-swap attacker** who has the manifest file and tries to swap two ciphertexts between fields — detected by AAD binding (§5).
- **Tamper-then-replay** attacker who modifies a ciphertext, IV, or paddingBucket — detected by GCM authentication tag.

This layer does NOT defend against (these are by design):
- **Plaintext length disclosure** beyond bucket granularity: the paddingBucket value reveals
  `plaintext_length <= paddingBucket`. To hide even bucket-class, encrypt outside the manifest.
- **Field presence**: unencrypted field NAMES appear in `encryptedFields.fields[].name`.
  An observer can see THAT a "title" field exists, just not WHAT the title is. To hide field
  presence itself, omit the field from the manifest entirely (the protocol cannot bind something
  it does not contain).
- **Password recovery**: if the owner forgets the password, the field is unrecoverable. The
  protocol holds no recovery secrets.

### 3. Cryptographic primitives

| Primitive | Algorithm | Reference |
|---|---|---|
| Symmetric cipher | AES-256-GCM (256-bit key, 96-bit IV, 128-bit tag) | NIST SP 800-38D |
| Key derivation | PBKDF2-HMAC-SHA256 | RFC 8018 |
| RNG | Cryptographically secure (CSPRNG) | platform-provided |

### 4. Structure of `encryptedFields`

```jsonc
"encryptedFields": {
  "masterSalt": "<base64 of 32 random bytes>",     // SINGLE salt at root
  "kdf": "pbkdf2-hmac-sha256",                     // FIXED for v1
  "kdfIterations": 600000,                         // OWASP 2024 recommendation
  "aadFormat": "screenplay-registration-aad-v1",                       // FIXED for v1
  "fields": [
    {
      "name": "title",                             // unencrypted field name
      "iv": "<base64 of 12 random bytes>",         // 96-bit IV (CSPRNG, unique per field)
      "ciphertext": "<base64>",                    // padded plaintext, encrypted
      "tag": "<base64 of 16-byte GCM tag>",
      "paddingBucket": 64                          // {16, 64, 256, 1024} default; manual override allowed
    },
    {
      "name": "author",
      "iv": "...",
      "ciphertext": "...",
      "tag": "...",
      "paddingBucket": 64
    }
  ]
}
```

Every field shown is REQUIRED. Per Section 02, every field in `committedClaim` (including
those inside `encryptedFields`) is hashed into the on-chain commitment. Tampering with any
of them invalidates the commitment.

### 5. Key derivation (SINGLE PBKDF2 per encrypt/decrypt cycle)

A single master key is derived from the password + masterSalt and reused for ALL fields. This
is critical for mobile-browser performance: 600,000 PBKDF2 iterations costs ~1-2 seconds, and
running that once per field (vs once total) would create a multi-second wait per decrypt.

```
masterKey := PBKDF2-HMAC-SHA256(
    password = <user-provided UTF-8 bytes>,
    salt = base64_decode(masterSalt),
    iterations = kdfIterations,    // MUST be ≥ 600000 for v1-compliant
    keyLen = 32                    // 256-bit AES key
)
```

Implementations MUST reject `kdfIterations < 600000` at decrypt time (lower iteration counts
are insufficient by OWASP 2024 guidance).

### 6. AEAD: AES-256-GCM with length-delimited AAD

For each field, the Additional Authenticated Data (AAD) MUST be constructed as:

```
AAD := "screenplay-registration-aad-v1"                           // 30 ASCII bytes, exactly; no terminator
    || uint16_BE(len_utf8(fieldName)) || fieldName_utf8
    || uint16_BE(len_utf8(claimVersion)) || claimVersion_utf8
    || masterSalt_raw                         // 32 raw bytes (the decoded masterSalt)
```

**Length-delimited encoding** prevents AAD ambiguity attacks where an unusually long
fieldName could be parsed as part of claimVersion or vice versa. The `uint16_BE` length prefix
fixes each variable-length field's boundary.

`claimVersion` here means the `committedClaim.claimVersion` URN (e.g. `urn:screenplay-registration-claim:v1`)
that the encrypted-fields block belongs to. Binding AAD to claim version means a field encrypted
under v1 cannot be silently transplanted into a v2 claim.

### 7. Padding buckets

Plaintext MUST be padded to one of the standard buckets before encryption:

```
default buckets: { 16, 64, 256, 1024 } bytes
manual override:  any power of 2 ≥ 16 — caller passes paddingBucket explicitly
```

Padding rule: choose the SMALLEST bucket that satisfies `plaintext_length + 4 ≤ bucket` (the
+4 is the length-prefix overhead). If `plaintext_length + 4 > 1024` and no manual override is
provided, encryption MUST fail (callers must explicitly opt-in to larger buckets).

**Padded format**: `uint32_BE(plaintext_length) || plaintext || zero_bytes_to_bucket`

- First 4 bytes: big-endian unsigned 32-bit length prefix.
- Next `plaintext_length` bytes: the plaintext.
- Remaining `paddingBucket - 4 - plaintext_length` bytes: ASCII NUL (`0x00`).

On decrypt, read the length prefix, take that many bytes as plaintext, verify the remaining
bytes are all `0x00`. Tampering with any byte (including padding) fails GCM authentication.

This scheme avoids the 255-byte cap of PKCS#7 and works for any bucket ≥ 8 bytes (the spec's
minimum bucket is 16).

### 8. Encryption procedure

Given inputs (`password`, `fieldName`, `plaintext`, `claimVersion`, `masterSalt`, `paddingBucket`):

1. Derive `masterKey` per §5 (cache and reuse across multiple fields).
2. Pad `plaintext` to `paddingBucket` per §7.
3. Generate `iv` = 12 random bytes from CSPRNG.
4. Build `AAD` per §6.
5. Compute `(ciphertext, tag) = AES-256-GCM_encrypt(masterKey, iv, padded_plaintext, AAD)`.
6. Return the EncryptedField object with `name`, `iv` (base64), `ciphertext` (base64),
   `tag` (base64), `paddingBucket`.

### 9. Decryption procedure

Given inputs (`password`, `field`, `claimVersion`, `masterSalt`, `kdfIterations`):

1. Reject if `kdfIterations < 600000`.
2. Derive `masterKey` per §5.
3. Build `AAD` per §6.
4. Compute `padded_plaintext = AES-256-GCM_decrypt(masterKey, iv, ciphertext, AAD, tag)`.
   On authentication failure, return error WITHOUT distinguishing wrong-password from tampering
   (constant-time comparison via GCM tag verification).
5. Validate `padded_plaintext.length === field.paddingBucket`. If not, return error.
6. Read the first 4 bytes as `plaintext_length` (uint32 big-endian).
7. Validate `plaintext_length + 4 ≤ field.paddingBucket`. If not, return error.
8. Take `plaintext = padded_plaintext.slice(4, 4 + plaintext_length)`.
9. Verify all bytes from offset `4 + plaintext_length` to end are `0x00`. If not, return error.
10. Return `plaintext`.

### 10. Compliance statement

An implementation claims compliance with this section if and only if:

1. It uses AES-256-GCM with 96-bit IVs from a CSPRNG.
2. It uses PBKDF2-HMAC-SHA256 with `kdfIterations >= 600000`.
3. It constructs AAD using the exact length-delimited format in §6.
4. It pads plaintexts to one of `{16, 64, 256, 1024}` by default OR to a caller-provided
   power-of-2 ≥ 16, and refuses to encrypt plaintexts whose length prefix plus payload would
   exceed the chosen bucket.
5. It correctly verifies length-prefix/zero padding on decrypt and rejects malformed padding.
6. It re-derives masterKey exactly ONCE per encrypt/decrypt cycle and reuses it across fields.

---

**End of Section 04.**

References:
- [NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [RFC 8018 — PKCS #5: Password-Based Cryptography Specification Version 2.1](https://datatracker.ietf.org/doc/html/rfc8018)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — current PBKDF2 iteration recommendations
