# Screenplay Registry Protocol v1.0
## Section 02 — Envelope (`urn:screenplay-registration-envelope:v1`)

**Envelope version identifier**: `urn:screenplay-registration-envelope:v1`
**Claim version identifier (commitment-bearing)**: `urn:screenplay-registration-claim:v1`
**Schema identifier (commitment-bearing)**: `urn:screenplay-registration-claim-schema:v1`

**Terminology note**: this spec uses "envelope" to refer to the outer JSON wrapper and "committedClaim" to refer to the inner payload that gets hashed + anchored. The reference CLI writes envelope files with a `.manifest.json` suffix, and user-facing documentation colloquially calls the file "the manifest." Both terms refer to the same object — "manifest" is the file-level / user-facing word, "envelope" is the spec-level / schema word.

---

### 1. Purpose

Define the JSON document structure that wraps a Screenplay Registry claim, separating
the IMMUTABLE COMMITMENT (hashed and OTS-anchored to Bitcoin) from the EXTENSIBLE EVIDENCE
BUNDLE (verifiable proofs, additive over time, never changes the commitment).

This split is the architectural foundation that makes the protocol forward-compatible: v2/v3
features (additional anchors, identity bindings, ZK proofs) attach as new evidence entries
referencing the existing `committedClaimHash` without ever re-committing.

### 2. Top-level structure

```jsonc
{
  "envelopeVersion": "urn:screenplay-registration-envelope:v1",
  "committedClaim": { ... },        // IMMUTABLE — canonicalized, hashed, OTS-anchored
  "evidenceBundle": { ... }          // EXTENSIBLE — references committedClaimHash; not hashed
}
```

The envelope file is a sidecar artifact stored on the owner's machine. The PROTOCOL only
commits to `committedClaim`; everything outside it is convenience metadata.

### 3. `committedClaim` — the immutable commitment

#### 3.1. Required fields (presence + value bound into the hash)

| Field | Type | Value rule |
|---|---|---|
| `claimVersion` | string | MUST equal `urn:screenplay-registration-claim:v1` for v1 claims |
| `schemaId` | string | MUST equal `urn:screenplay-registration-claim-schema:v1` for v1 claims |
| `hashAlgorithm` | string | MUST equal `sha-256` for v1 claims |
| `manifestCanonicalization` | string | MUST equal `rfc8785` for v1 claims |
| `normalizationProfile` | string | MUST equal `screenplay-registration-norm/v1-strict` for v1 claims |
| `contentHash` | string | `sha256:<lowercase-hex>` per §6 of Section 01 |
| `claimExtensions` | object | `{}` if no extensions; non-empty object otherwise. Always present. |

#### 3.2. Optional fields (presence is part of the commitment)

Each optional field is either ABSENT or PRESENT with a valid value. **Absent and present-with-empty
produce DIFFERENT commitment hashes.** Implementations MUST NOT silently add or remove optional
fields.

| Field | Type | Notes |
|---|---|---|
| `sceneTreeProfile` | string | MUST equal `screenplay-registration-merkle/v1`. If present, `sceneTreeRoot` and `sceneCount` MUST also be present. Section 03. |
| `sceneTreeRoot` | string | `sha256:<lowercase-hex>` — root of the scene Merkle tree |
| `sceneCount` | integer | Number of scenes detected; ≥ 0; prevents truncation attacks |
| `paragraphTreeProfile` | string | MUST equal `screenplay-registration-paragraph-merkle/v1` when present. If present, `paragraphTreeRoot` and `paragraphCount` MUST also be present. Section 03 §3.6. |
| `paragraphTreeRoot` | string | `sha256:<lowercase-hex>` — root of the paragraph Merkle tree |
| `paragraphCount` | integer | Number of paragraphs detected; ≥ 0 |
| `previousRegistration` | object | Pointer to parent registration this revision descends from: `{ "claimHash": "sha256:..." }`. v1 verifiers do NOT fetch the parent; pointer is commitment-bearing but unverified. |
| `registrant` | object | Ed25519 registration-time signature binding a keypair to this claim. Schema: `{ publicKey, signatureAlgorithm: "ed25519", signatureDomain: "screenplay-registry-claim-v1", signedDigest, signature }`. Two-phase signing mechanics + verifier obligations: see `src/identity/ed25519-signing.ts` (`computeClaimBodyDigest`, `signRegistration`, `verifyRegistrationSignature`). Locked v1 wire format. |
| `timelockFields` | array | Time-locked encrypted fields per Section 07 (capability-flagged). Implementations without timelock support MAY verify other commitment fields but MUST NOT claim full v1 conformance for manifests containing this field. |
| `encryptedFields` | object | Per Section 04 schema |
| `preferences` | object | User-set preferences. v1 closed shape: `{ "trainingMining"?: "allowed" \| "notAllowed" \| "constrained" }`. Unknown values MUST be rejected; forward-compat lands via a new schemaId, not silent enum growth. |

**All-or-none triples** — the two tree triples are independent. A claim MAY have the scene
tree, the paragraph tree, both, or neither. Within each triple, all three fields MUST be
present or all three MUST be absent.

#### 3.3. Unknown fields

All fields present in `committedClaim` — including unknown ones not described here — are
canonicalized into the hash. Verifiers MUST NOT skip unknown fields during hashing. Verifiers
MAY skip unknown fields during semantic processing AFTER hash verification has succeeded.

This rule prevents a class of attack where an adversary inserts an extra field that an older
verifier would silently ignore, allowing two different claim documents to produce the same
"effective" verification result.

### 4. `evidenceBundle` — extensible, untrusted metadata

#### 4.1. Required structure

```jsonc
{
  "committedClaimHash": "sha256:<lowercase-hex>",  // MUST match the verifier's recomputed hash
  "proofs": [...],                                  // MAY be empty array
  "bundleExtensions": {}                            // MUST be present; MAY be empty
}
```

#### 4.2. Verifier consistency rules (MANDATORY)

The contents of `evidenceBundle` are UNTRUSTED. Verifiers MUST:

1. Compute `claimHash` independently by canonicalizing `committedClaim` per §5 and applying
   SHA-256.
2. Reject the envelope if `evidenceBundle.committedClaimHash !== claimHash` (case-sensitive
   string comparison; both sides are lowercase hex).
3. For each entry in `evidenceBundle.proofs`: reject if `proof.claimHash !== claimHash`.
4. Derive any timestamp/block-height data from the cryptographic proof itself (e.g. parsing
   the `.ots` binary), NOT from convenience metadata fields like `submittedAt` or `upgradedAt`.
5. Treat `bundleExtensions` as untrusted metadata. NEVER base verification decisions on it.

### 5. Canonicalization (RFC 8785)

The commitment hash is computed as:

```
claimHash := "sha256:" || lowercase_hex(SHA-256(canonical_bytes))

where canonical_bytes := RFC8785_canonicalize(committedClaim)
```

RFC 8785 (JSON Canonicalization Scheme, "JCS") defines an unambiguous serialization of any
valid JSON value. The relevant rules for this protocol:

- **Object keys** are sorted lexicographically by UTF-16 code unit value.
- **No insignificant whitespace** — no spaces, no newlines, no indentation.
- **Strings** are escaped per RFC 8259 §7: `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`, and any
  other U+0000–U+001F as `\uXXXX` (lowercase hex). All non-ASCII characters pass through as
  UTF-8 bytes WITHOUT `\u` escaping.
- **Numbers** are serialized per the ECMAScript `Number.prototype.toString()` algorithm
  (which RFC 8785 incorporates). NaN and Infinity are PROHIBITED in canonical JSON.
- **null**, **true**, **false** are emitted as JSON keywords.
- **Arrays** preserve element order.

The output is a sequence of UTF-8 bytes (since RFC 8785's canonical form is UTF-8). SHA-256
is applied to those bytes.

### 6. Schema location and discoverability

The JSON Schema 2020-12 document for the envelope is published at:

```
/spec/v1/envelope.schema.json    (bundled in the spec repository)
```

with internal `$id: "urn:screenplay-registration-claim-schema:v1"`. Implementations bundle this
schema file in their distribution and resolve the URN against the bundled copy. The schema
is NEVER fetched over the network during verification — that would create a DNS dependency
that the URN was specifically designed to avoid.

An advisory `$schema` URL MAY appear in the envelope-level metadata (outside `committedClaim`),
e.g. pointing to a hosted HTML rendering of the schema. Verifiers MUST treat hosted schemas
as advisory only and MUST resolve commitment-bearing validation against the bundled schema.

### 7. Example envelope (illustrative — see test vectors for exact bytes)

```jsonc
{
  "envelopeVersion": "urn:screenplay-registration-envelope:v1",
  "committedClaim": {
    "claimVersion": "urn:screenplay-registration-claim:v1",
    "schemaId": "urn:screenplay-registration-claim-schema:v1",
    "hashAlgorithm": "sha-256",
    "manifestCanonicalization": "rfc8785",
    "normalizationProfile": "screenplay-registration-norm/v1-strict",
    "contentHash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "claimExtensions": {}
  },
  "evidenceBundle": {
    "committedClaimHash": "sha256:<computed by verifier>",
    "proofs": [
      {
        "type": "opentimestamps",
        "claimHash": "sha256:<same as above>",
        "proofRef": "screenplay.proof.ots"
      }
    ],
    "bundleExtensions": {}
  }
}
```

### 8. Versioning rule

The `claimVersion` URN (`urn:screenplay-registration-claim:v1`) is permanently bound to the schema
defined in this document plus Sections 01, 03, 04, 05. Any change that alters which fields
are required, the validation rules for any field, or the canonical hash computation MUST
publish under a new claim version URN (e.g. `urn:screenplay-registration-claim:v2`).

Future claim versions known at v1 release:
- `urn:screenplay-registration-claim:v2` (RESERVED) — anticipated to support additional anchor types,
  identity bindings, ZK proofs as commitment-bearing fields. Old v1 claims will continue to
  verify under v1 rules; both versions coexist.

### 9. Compliance statement

An implementation claims compliance with `urn:screenplay-registration-claim:v1` if and only if:

1. It validates committed claims against the bundled JSON Schema and rejects invalid documents.
2. It implements RFC 8785 canonicalization correctly (tested against the canonical RFC 8785
   test vectors plus the protocol's envelope test vectors at `/spec/v1/testvectors/envelope/`).
3. It enforces all verifier consistency rules in §4.2.
4. It correctly handles the presence-or-absence rule for optional fields (§3.2).

---

**End of Section 02.**

References:
- [RFC 8785 — JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
- [RFC 8259 — The JavaScript Object Notation (JSON) Data Interchange Format](https://datatracker.ietf.org/doc/html/rfc8259)
- [JSON Schema 2020-12](https://json-schema.org/specification.html)
