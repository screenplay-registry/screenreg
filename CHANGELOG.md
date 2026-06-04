# Changelog

All notable changes to The Screenplay Registry are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [semver](https://semver.org/) for the v1 protocol commitment-bearing surface.

The **commitment-bearing identifiers** (URN namespace, profile IDs, normalization profile, hash algorithm, canonicalization scheme) are locked at v1 and will never change within the v1 line. Forward-compatible additions land via new URNs in v2+.

## [Unreleased] — Optional on-chain anchor + registry index (additive tiers)

Two optional, additive tiers layered on top of the frozen v1 core: a secondary Ethereum-mainnet witness and an off-chain registry index. Both are specified, with verification implemented against an injected provider — no contract is deployed and no hosted index exists. Neither is a time or priority source, neither is required, and neither changes any commitment-bearing byte. Bitcoin via OpenTimestamps remains the sole time + priority anchor. The on-chain contract is not yet deployed: its wire interface is frozen here, while the deployed implementation, a security audit, and legal review are deferred to a future release.

### Optional Ethereum on-chain anchor

- **`ethereum-anchor` evidence proof type** (spec §09, `urn:screenplay-registration-evidence-ethereum-anchor:v1`) — a non-hashed entry in `evidenceBundle.proofs[]` that points at a `Registered` log on Ethereum mainnet recording the same opaque `claimHash`. Like every proof entry it is untrusted metadata, not part of the committed claim. Required fields: `type`, `claimHash`, `chainId`, `contract`, `registrant`, `txHash`, `logIndex`, `blockNumber`. The script fingerprint (`contentHash`) is forbidden on the proof at any depth — a verifier rejects it rather than ignoring it, so the public ledger can never become a membership oracle for the work.
- **Pinned on-chain interface** — the `ScreenplayLedger` `Registered(bytes32 indexed claimHash, address indexed registrant, uint256 blockTime, string title, string name)` event ABI, the EIP-712 domain (`name: "ScreenplayLedger"`, `version: "1"`), `REGISTER_TYPEHASH`, and the length-only byte caps (`title` ≤ 128, `name` ≤ 64) are pinned in `src/anchors/eth/constants.ts` and mirror spec §09 verbatim. The canonical chain is mainnet (`chainId = 1`), not an L2.
- **EIP-712 typed-data builder** at `src/anchors/eth/eip712.ts` — computes the domain separator (per the actual chain id, never hard-coded), struct hash, and signing digest for the gasless `registerWithSig` flow. `claimHash` is encoded as `bytes32` with the `sha256:` label stripped. The builder only builds the local signer's digest; signature recovery is never performed off-chain.
- **Off-chain anchor verifier** at `src/anchors/eth/verify-eth-anchor.ts` — reads the `Registered` log via an injected provider, selects the exact log by `txHash` + `logIndex` (never "first match"), and compares the indexed topics + coordinates against the independently recomputed envelope `claimHash` (never `proof.claimHash` alone). Topics-only: it never fetches calldata and never recovers a signature. Deterministic result taxonomy — `verified` / `not-found` / `unverified` / `rejected`; an RPC failure, an unreachable node, insufficient confirmations, or a reserved `batch` anchor degrade to `unverified` and NONE of them ever flips a Bitcoin verdict.
- **`batch` field reserved** — the optional batched-receipt mode carries no defined wire format in v1; a batched anchor verifies to `unverified` and the verifier makes no Merkle-path claim.

### Off-chain registry index

- **Registry record** (spec §10, `urn:screenplay-registration-registry-record:v1`) at `src/registry/record.ts` — an off-chain, never-hashed JSON record keyed by `claimHash` with optional public `title` / `author` labels and the anchors needed to re-verify a registration without trusting the operator. `contentHash` is forbidden at any depth; `registeredAt` is informational only and is ignored for priority.
- **Per-record verification** at `src/registry/verify-index.ts` — each record is checked independently via the existing OTS file-digest verifier against the record's `claimHash` as the expected 32-byte digest, with strict path-traversal guards on the injected proof loader. Heights parsed from an `.ots` attestation stay labeled "OTS-claimed, not Bitcoin-final" unless an injected attestation verifier confirms header inclusion and `minConfirmations`.
- **Bitcoin-only priority** at `src/registry/priority.ts` — disputes resolve by earliest Bitcoin block height alone; same block is a tie; Ethereum anchors and `registeredAt` never rank; a contest carrying only OTS-claimed (header-unverified) heights is reported undetermined rather than ranked dishonestly.
- **Honest tamper-evidence framing** — the MVP index is a signed, mirrorable dataset, NOT a tamper-proof log: it gives zero cryptographic protection against operator censorship or equivocation, and each record's truth is its own `.ots` against Bitcoin. A CT-style append-only transparency log is the roadmap target. A real snapshot-Merkle root is deferred until it has its own named, domain-tagged Merkle profile with wire schema and conformance vectors.

### Spec + schema

- **Spec §09** (Optional Ethereum on-chain anchor) and **§10** (Off-chain registry index) added.
- **`spec/v1/02-envelope.md` §4.2** clarified (additive prose): a verifier MUST NOT reject an envelope solely because a proof carries an unknown `type` or extra fields — an unknown-but-`claimHash`-matching proof is tolerated and reported as UNVERIFIED, never invalid. This codifies behavior the reference verifier already exhibits and changes no committed bytes.
- **`spec/v1/envelope.schema.json`** gains a conditional dispatch: an `ethereum-anchor` proof must satisfy the strict shape (the six required fields plus the `profile` const when present), while all other and unknown proof types keep the open, tolerant catch-all. Existing `opentimestamps` and unknown-type vectors are unaffected.
- **`spec/v1/registry-record.schema.json`** defines the registry-record shape (`additionalProperties: false`; no `contentHash` column).
- New corpus vector `env-111-envelope-with-ethereum-anchor` exercises the tolerant path. Only new vector files were added; no existing vector's claim hash or canonical bytes changed.

### Compatibility

No v1 commitment-bearing surface changed: the normalization profile, canonicalization scheme, claim and envelope URN namespaces, scene-tree and paragraph-tree profile IDs and domain tags, AES-256-GCM AAD format, and Ed25519 registrant wire format are all unchanged byte-for-byte. The new evidence proof type, registry-record URN, and spec sections are additive and non-committing. The peripheral `src/anchors/eth/` module adds a keccak/secp256k1 dependency confined to that module; the commitment-bearing core and the cross-runtime shared modules remain dependency-free.

## [0.2.1] — Bug fixes (reference implementation only; no committed bytes change)

Two fixes surfaced by an end-to-end shakedown of the published package. Neither changes any commitment-bearing byte, profile ID, or the output of any valid `Buffer` input; the v1 conformance corpus and the cross-implementation byte-parity tests are unchanged and pass.

### Fixed

- **SDK: `normalize()`, `detectScenes()`, `contentHash()`, and `contentHashOfNormalized()` accept a `Uint8Array` without silent corruption.** The Node reference implementation decoded input via `Buffer.prototype.toString('utf8')`; a plain `Uint8Array` (as returned by `fetch()`/File APIs) was silently mis-decoded to comma-joined byte values, producing a valid-looking but meaningless `contentHash` and zero detected scenes, with no error raised. The affected functions now coerce to `Buffer` at entry and accept `Uint8Array | Buffer`; output for a `Buffer` input is byte-for-byte unchanged. This matches the cross-runtime `src/shared` implementation, which was already `Uint8Array`-native.
- **CLI: `decrypt-field` honors `--password`** (with the same argv-exposure warning as `register`). Previously the flag was silently ignored and the command fell through to an interactive prompt, failing with a misleading authentication error in non-interactive use.

## [0.2.0] — Browser-native register + PDF input

The v0.1.0 reference shipped CLI-only. v0.2 makes the protocol usable from a browser tab and lays in the PDF-as-source flow without changing any commitment-bearing surface.

### Browser

- **`/create/` page** — drag a `.fountain` file, get back `manifest.json` + `proof.ots`. Script content never leaves the tab; only the 32-byte SHA-256 claim hash is sent to the OpenTimestamps public calendars. No account, no upload, no analytics, no third-party scripts.
- **Cross-runtime shared modules** at `src/shared/` — normalize, canonicalize, claim-hash, envelope build, and OTS proof builder are now compiled for both Node and the browser via `tsconfig.browser.json`. The same source produces the CLI's bytes and the browser's bytes; cross-impl byte-parity tests assert that on every input in the corpus.
- **Multi-calendar quorum** — page POSTs the claim hash to four canonical OTS calendars (a.pool, alice.btc, bob.btc, finney) in parallel with a 15s per-calendar timeout. Requires ≥2 of 4 successful responses; failures surface inline with per-calendar reasons.
- **Strict calendar-response gate** — `isValidTimestampSubtree` walks each calendar response with terminal-attestation enforcement, attestation-tag allowlist (Bitcoin / Litecoin / Pending), Pending URI charset + 1000-byte length cap (matching upstream OTS), OP_APPEND/PREPEND args 1..4096 bytes, message-length tracking enforcing Op.MAX_RESULT_LENGTH=4096, and OP_REVERSE/OP_HEXLIFY unary ops. Rejects HTML, redirects, truncated responses, unknown attestation tags, malformed URIs.
- **Cloudflare Pages headers** — `landing/_headers` ships strict CSP (script-src 'self', no inline JS; connect-src restricted to the four OTS calendars), Strict-Transport-Security preload-eligible, X-Frame-Options DENY, Permissions-Policy locking down every sensor / payment / clipboard API, COOP/CORP same-origin.

### PDF input

- **Pluggable `PdfExtractor` contract** at `src/extractors/types.ts` — operators ship their own extractors for non-FD dialects (OCR, multi-column shooting drafts, bilingual layouts) by exporting a default value conforming to the interface.
- **`screenreg-reference` extractor** at `src/extractors/reference/` — handles FD-convention text PDFs (Final Draft, Highland, WriterDuet, Fade In, Trelby, Slugline). Classifies each line by `(x-position, content rules)` into scene-heading / action / character / parenthetical / dialogue / transition. Strips page numbers and scene numbers by default; opt-out via flags.
- **`screenreg extract <input.pdf>` CLI subcommand** — writes Fountain to stdout (or `--out PATH`). Typed exit codes per `ExtractorError.code` (10–15) so shell scripts can react to specific failure reasons (`EXTRACT_NO_TEXT_LAYER`, `EXTRACT_ENCRYPTED`, `EXTRACT_UNSUPPORTED_LAYOUT`, `EXTRACT_CORRUPTED`, `EXTRACT_AMBIGUOUS_BLOCKS`, `EXTRACT_DEPENDENCY_MISSING`).
- **Source-PDF provenance** — `screenreg register --source-pdf <pdf>` records `evidenceBundle.bundleExtensions.sourceExtractor` with extractor `name + version`, SHA-256 of the source PDF, SHA-256 of the Fountain that was actually registered, and the source filename. This proves which PDF the writer claims as source and pins the Fountain content; it does NOT prove the Fountain is the verbatim output of running `screenreg extract` on the PDF (a writer may edit the extracted Fountain before registering). An archival verifier who wants byte-identical reproducibility must re-run the extractor against the source PDF and compare to the registered Fountain hash themselves.
- **No new normalization profile** — `screenplay-registration-norm/v1-strict` remains the only commitment layer. PDF is one input source among many; Fountain stays canonical.

### Parser hardening

The `parseOts` verifier now enforces every cap that the browser-side strict walker enforces, ending the previous gate-accepts/parser-rejects asymmetry:

- `TimeAttestation.MAX_PAYLOAD_SIZE=8192` on every attestation, including unknown tags.
- Pending attestation URIs: non-empty, ≤ 1000 bytes, character allowlist matching upstream `notary.py`, no trailing bytes past the URI.
- `OP_APPEND` / `OP_PREPEND`: arg ∈ [1, 4096], result ≤ 4096.
- `OP_REVERSE` / `OP_HEXLIFY`: result ≤ 4096.
- Loose position-only walker removed — `splitOtsForRoundTrip` now uses the strict walker so one set of semantics applies everywhere.

### Other

- `globalThis.crypto.subtle` replaces `node:crypto` in shared modules so the same source runs on Node 20+ and every evergreen browser without a parallel implementation surface.
- Cross-impl test corpus expanded with double-leading-BOM, triple-leading-BOM, embedded BOM at multiple positions, mixed CRLF/LF/CR line endings, NFC-decomposed sequences, supplementary-plane characters, lone surrogates, and OTS calendar URIs at character + length boundaries.

### Compatibility

No v1 commitment-bearing surface changed in v0.2: the normalization profile ID (`screenplay-registration-norm/v1-strict`), the canonicalization scheme (RFC 8785 JCS), the claim and envelope URN namespaces, the scene-tree and paragraph-tree profile IDs and domain tags, the AES-256-GCM AAD format, and the Ed25519 registrant wire format are all unchanged byte-for-byte. The new `evidenceBundle.bundleExtensions.sourceExtractor` block is additive and non-committing. Cross-version regression testing of v0.1.0 envelopes against v0.2 verification is tracked as ongoing work; if you re-verify a v0.1.0 proof under v0.2 and see a difference, please file an issue.

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
- Audited via structured adversarial review against the threat model prior to release (audit trail in git history)
- Bundle binding via two-stage chain prevents content-hash substitution under SHA-256 collision-resistance assumption
- Membership-oracle attack defense via opt-in comparison bundles
- TOCTOU-resistant sensitive-file writes (lstat + O_CREAT|O_EXCL + fchmod 0o600)
- Argument-injection-resistant subprocess invocation (POSIX `--` separator)
- Bounded JSON + screenplay input reads (16 MiB / 32 MiB respectively); OTS proof parser capped at 8 MiB with depth-limited recursion
- Weak-password runtime warning at encryption time

### Governance

- **Phase 1 (current)**: maintenance by the initial contributors
- **Phase 2** (triggered by 3+ external integrators OR 6 months): stewards council with rotating chair
- **Phase 3** (sustained adoption): fiscal sponsorship under Linux Foundation OpenSSF or equivalent
- All commitment-bearing identifiers are URN-based and brand-neutral — a future stewardship transition does not invalidate any v1 proof

### Known limitations + roadmap

- The reference verifier validates OTS proof structure but does NOT yet perform full SPV / Bitcoin-header verification against a local Bitcoin node. Today an operator who wants block-header confirmation runs `ots verify` from `opentimestamps-client` against the upgraded `.ots`. Bringing SPV into the reference verifier is deferred to a future minor release.
- v0.1.0 registration is CLI-only; the browser-native register flow ships in [0.2.0].
- The KDF (PBKDF2-HMAC-SHA256, 600k iterations) is CPU-hard but not memory-hard; v2 migration to Argon2id is planned.

### Licenses

- Code: [MIT](LICENSE)
- Spec: [CC-BY 4.0](SPEC-LICENSE)
- Test vectors: [CC0](TESTVECTORS-LICENSE)

[0.1.0]: https://github.com/screenplay-registry/screenreg/releases/tag/v0.1.0
