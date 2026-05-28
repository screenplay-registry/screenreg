# Screenplay Registry Protocol v1.0
## Section 01 — Canonical Normalization (`screenplay-registration-norm/v1-strict`)

**Profile identifier**: `screenplay-registration-norm/v1-strict`
**Status**: COMMITMENT-BEARING. This profile identifier is permanently part of every v1 claim's `committedClaim.normalizationProfile` field and is hashed into the on-chain commitment. The rules defined in this document MUST NEVER change. Future revisions ship under new profile identifiers (e.g. `screenplay-registration-norm/v2-fountain`) that produce DIFFERENT hashes; both profiles coexist forever.

---

### 1. Purpose

Define a deterministic, lossless-where-it-matters transformation of an input byte sequence into a canonical byte sequence whose SHA-256 hash serves as the `contentHash` field of a Screenplay Registry claim.

The transformation MUST be:
1. **Deterministic** — identical input bytes always produce identical output bytes.
2. **Implementable from this document alone** — independent implementations in any programming language MUST produce byte-identical output to the reference TypeScript implementation.
3. **Idempotent** — `normalize(normalize(x)) === normalize(x)` for all inputs `x` that pass step 2.1 below.
4. **Minimal** — only the transformations listed in §2 are performed. All other bytes pass through unchanged.

### 2. Normalization steps (in strict order)

#### 2.1. Validate input is well-formed UTF-8

Inputs that contain invalid UTF-8 byte sequences MUST be rejected with an error before any further processing. There is no v1 mode that accepts invalid UTF-8.

References: RFC 3629 ("UTF-8, a transformation format of ISO 10646").

#### 2.2. Strip Byte Order Mark (BOM) if present at start

If the input begins with the UTF-8 BOM sequence `0xEF 0xBB 0xBF`, those three bytes MUST be removed. BOMs elsewhere in the input (which would be U+FEFF, a zero-width no-break space) are PRESERVED (see §3).

#### 2.3. Apply Unicode Normalization Form C (NFC)

Apply the canonical decomposition + canonical composition transformation defined by Unicode Annex #15. This collapses combining-character sequences into their precomposed equivalents where possible (e.g. `U+0065 U+0301` → `U+00E9` for `é`).

References: Unicode Standard Annex #15 "Unicode Normalization Forms" (UAX-15).

Implementations MUST use a Unicode database version that supports at least Unicode 15.0. (The choice of database version affects NFC composition for characters added after 15.0; v1 implementations SHOULD use the version bundled with their language's standard library and document the version in their release notes. Discrepancies between database versions are a known divergence risk; see §4.)

#### 2.4. Convert line endings to LF

All `CR LF` (`0x0D 0x0A`) sequences MUST be replaced with a single `LF` (`0x0A`). All lone `CR` (`0x0D` not followed by `0x0A`) MUST be replaced with `LF` (`0x0A`).

After this step, no `CR` byte may appear in the output.

### 3. Bytes and characters that are NOT normalized (preserved exactly)

The following are intentionally PRESERVED and contribute to the content hash unchanged. Any future "lossy" normalization that mutates them MUST be a separate profile (e.g. `screenplay-registration-norm/v2-fountain`).

- **Trailing whitespace on lines** — preserved. Fountain's specification uses trailing whitespace in several places (forced line breaks, certain element markers); altering it would be semantically destructive.
- **Leading whitespace on lines** — preserved.
- **Blank lines and their counts** — preserved. Fountain uses blank-line counts to delimit elements.
- **Final newline at end of file** — preserved. A file ending in `\n` and one not ending in `\n` produce different hashes.
- **Tab characters** — preserved.
- **Zero-width characters** (U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF ZWNBSP when not the leading BOM) — preserved. Removing them would mask tampering attacks where an attacker inserts/removes invisible characters.
- **Bidirectional override characters** (U+202A through U+202E, U+2066 through U+2069) — preserved. These can be used adversarially but stripping them is itself a security risk.
- **Homoglyphs** (e.g. Latin `a` U+0061 vs Cyrillic `а` U+0430) — preserved. These are visually identical but cryptographically distinct, by design. Any normalization that collapses them would create commitment ambiguity.
- **Control characters other than `CR` and `LF`** — preserved.

### 4. Known divergence risks (implementer alert)

The following are SOURCES OF POTENTIAL CROSS-IMPLEMENTATION DIVERGENCE. Implementations MUST document their choices and test against the canonical test corpus.

1. **Unicode database version**: NFC composition tables evolve. Two implementations using different Unicode databases may produce different output for characters added after the older database's version. **Mitigation**: every implementation declares its Unicode database version in its release notes. The canonical test corpus is generated against a pinned Unicode version (Unicode 15.1 for v1) and the corpus is included verbatim in the spec repository.

2. **Invalid UTF-8 detection strictness**: Some UTF-8 decoders accept overlong sequences or surrogates (CESU-8); strict decoders reject them. Implementations MUST be strict per RFC 3629 (reject overlong, reject surrogates, reject sequences > U+10FFFF).

3. **Newline-only inputs**: An input consisting solely of `CR` bytes normalizes to an output consisting solely of `LF` bytes; an empty input normalizes to an empty output. Both cases have specific test vectors.

### 5. Reference test corpus

The canonical test corpus is at `/spec/v1/testvectors/normalization/`. Each test vector consists of:

- `NNN-name.input.bin` — the raw input bytes
- `NNN-name.expected.bin` — the expected normalized output bytes
- `NNN-name.hash.txt` — the expected SHA-256 of the normalized output, lowercase hex
- `NNN-name.transforms.json` — the expected sequence of transforms applied (for diagnose mode)
- `NNN-name.description.md` — human-readable description of what the vector tests

Implementations MUST pass ALL test vectors to claim compliance with `screenplay-registration-norm/v1-strict`.

The corpus directory's SHA-256 (computed as `SHA-256(sorted_concatenation(SHA-256(each_file_content)))`) is committed in `/spec/v1/testvectors/normalization/CORPUS_DIGEST.txt` to detect tampering or accidental corpus changes.

### 6. Content hash

After normalization completes successfully, the content hash is computed as:

```
contentHash := "sha256:" || lowercase_hex(SHA-256(normalized_bytes))
```

The literal prefix `sha256:` is REQUIRED in the manifest's `contentHash` field, both as forward-compatibility for future hash algorithms (which would use prefixes like `sha3-256:`, `blake3:`) and as defense against ambiguity attacks where a raw hex string could be misinterpreted.

### 7. Versioning rule

The profile identifier `screenplay-registration-norm/v1-strict` is permanently bound to the rules in this document. Future updates to this document that change normalization semantics in ANY way (including bug fixes that change output bytes) MUST publish under a new profile identifier and update the version number. Implementations MUST refuse to apply a v1-strict normalization that differs in any way from this specification.

Future profiles known at v1 release:
- `screenplay-registration-norm/v2-fountain` (PLANNED, NOT IMPLEMENTED) — Fountain-aware lossy normalization that understands screenplay markup semantics. Will produce DIFFERENT hashes than v1-strict for the same input. v1-strict proofs always verify under v1-strict, regardless of whether v2-fountain ships.
- `screenplay-registration-norm/v2-prose` (RESERVED) — prose-focused normalization for novel/treatment registration.

### 8. Compliance statement

An implementation claims compliance with `screenplay-registration-norm/v1-strict` if and only if:

1. It passes every test vector in `/spec/v1/testvectors/normalization/` byte-for-byte.
2. It rejects every invalid-UTF-8 test vector with a clear error.
3. It documents the Unicode database version used.
4. It exposes the profile identifier as a constant exactly matching `screenplay-registration-norm/v1-strict`.

---

**End of Section 01.**

References:
- [Unicode Standard Annex #15 — Unicode Normalization Forms](https://www.unicode.org/reports/tr15/)
- [RFC 3629 — UTF-8, a transformation format of ISO 10646](https://datatracker.ietf.org/doc/html/rfc3629)
- [FIPS PUB 180-4 — Secure Hash Standard (SHS)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) for SHA-256
