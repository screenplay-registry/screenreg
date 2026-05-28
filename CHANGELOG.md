# Changelog

All notable changes to The Screenplay Registry are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [semver](https://semver.org/) for the v1 protocol commitment-bearing surface.

The **commitment-bearing identifiers** (URN namespace, profile IDs, normalization profile, hash algorithm, canonicalization scheme) are locked at v1 and will never change within the v1 line. Forward-compatible additions land via new URNs in v2+.

## [0.1.0] — Initial public release

The first public release of the protocol + reference TypeScript implementation. Pre-launch development was conducted privately with extensive adversarial review.

### Protocol

- **Locked v1 commitment-bearing surface**: `urn:screenplay-registration-claim:v1`, `urn:screenplay-registration-envelope:v1`, `urn:screenplay-registration-comparison-bundle:v1`
- **Normalization profile**: `screenplay-registration-norm/v1-strict` (UTF-8 NFC + LF + strip BOM)
- **Canonicalization**: RFC 8785 JSON Canonicalization Scheme with safe-integer + lone-surrogate rejection
- **Scene Merkle tree**: `screenplay-registration-merkle/v1` with domain separation (`0x00` leaf / `0x01` parent / `0x02` padding)
- **Paragraph Merkle tree**: `screenplay-registration-paragraph-merkle/v1` with disjoint domain tags (`0x10`/`0x11`/`0x12`)
- **Two-stage hash chain** in Merkle leaves: `bytes → content_hash → leaf_hash → root`, enabling comparison-bundle binding without exposing raw bytes
- **Comparison disclosure bundle** (Section 06): opt-in sidecar revealing per-leaf hashes + word counts + byte ranges for cross-claim similarity comparison; never required for registration
- **Encrypted manifest fields** (Section 04): AES-256-GCM with length-delimited AAD binding field name + claim version + master salt
- **Ed25519 registrant block**: optional opt-in keypair binding via `--identity` — two-phase signing per `src/identity/ed25519-signing.ts`. Locked v1 wire format.
- **Time-locked encrypted fields** (Section 07, capability-flagged): Drand quicknet timelock; fields decrypt at a specified future Drand round
- **OpenTimestamps anchoring**: claim hashes batched into Bitcoin transactions via public OTS calendars; $0 cost to user

### Spec sections

- §01 Normalization
- §02 Envelope (`committedClaim` + `evidenceBundle` schema, RFC 8785 canonicalization, verifier rules)
- §03 Scene + Paragraph Trees (Merkle construction, domain separation, selective-disclosure proofs)
- §04 Encrypted Manifest Fields (AES-256-GCM + PBKDF2 key derivation)
- §05 Similarity Commitment Layer (what the claim commits — Merkle roots only)
- §06 Comparison Disclosure Bundle (opt-in sidecar revealing per-leaf hashes)
- §07 Time-locked Encrypted Fields (Drand quicknet timelock, capability-flagged)
- `envelope.schema.json` (JSON Schema for the full v1 envelope shape)
- 80+ test vectors covering normalization edge cases, Merkle tree construction, canonicalization adversarial inputs, encryption AAD binding, registrant signing

### Reference TypeScript implementation

- `screenreg` CLI: `register`, `verify` (with `--require-bitcoin-anchor` for strict CI), `diagnose`, `similarity` (with `--envelope-a/-b` for external binding), `disclose-comparison` (warn-then-confirm-then-write), `verify-registration`, `sign-challenge`, `verify-signature`, `scene-prove`, `scene-verify`, `decrypt-field`, `timelock-encrypt`, `timelock-decrypt`, `generate-identity`, `upgrade`, `normalize`, `claim`
- Browser-native drag-and-drop verifier (`verifier-web/`) — pure HTML/JS, no backend
- Curated SDK exports via `src/index.ts` for third-party integrators
- 368 tests passing on Node 22+; `npm run check` validates typecheck + tests across `src/` + `test/` + `scripts/`

### Security posture

- All primitives are standard: SHA-256 (FIPS 180-4), RFC 8785 JCS, AES-256-GCM (NIST SP 800-38D), PBKDF2-HMAC-SHA256 600k iterations (OWASP 2024 minimum), Ed25519 (RFC 8032), BLS12-381 via Drand quicknet, OpenTimestamps → Bitcoin
- No hand-rolled cryptography; no custom constructions
- Audited via adversarial LLM-based review prior to release (audit trail in git history)
- Bundle binding via two-stage chain prevents content-hash substitution under SHA-256 collision-resistance assumption
- Membership-oracle attack defense via opt-in comparison bundles
- TOCTOU-resistant sensitive-file writes (lstat + O_CREAT|O_EXCL + fchmod 0o600)
- Argument-injection-resistant subprocess invocation (POSIX `--` separator)
- Bounded JSON + screenplay input reads (16 MiB / 32 MiB respectively); OTS proof parser capped at 8 MiB with depth-limited recursion
- Weak-password runtime warning at encryption time

### Governance

- **Phase 1 (current)**: single-steward maintenance
- **Phase 2** (triggered by 3+ external integrators OR 6 months): stewards council with rotating chair
- **Phase 3** (sustained adoption): fiscal sponsorship under Linux Foundation OpenSSF or equivalent
- All commitment-bearing identifiers are URN-based and brand-neutral — a future stewardship transition does not invalidate any v1 proof

### Known limitations + v0.2 roadmap

- v0.x verifier validates OTS proof structure but does NOT yet perform full SPV / Bitcoin-header verification (lands in v0.2 with checkpoints + public-explorer fallback)
- v0.x registration is CLI-only; browser-native register flow ships in v0.2
- v0.x KDF (PBKDF2) is CPU-hard but not memory-hard; v2 migration to Argon2id planned

### Licenses

- Code: [MIT](LICENSE)
- Spec: [CC-BY 4.0](SPEC-LICENSE)
- Test vectors: [CC0](TESTVECTORS-LICENSE)

[0.1.0]: https://github.com/screenplay-registry/screenreg/releases/tag/v0.1.0
