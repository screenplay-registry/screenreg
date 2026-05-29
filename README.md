# The Screenplay Registry

> **A free and open script registry for dated authorship claims.**

Register a screenplay, pilot, treatment, or draft by creating a dated, cryptographically verifiable authorship claim. The Screenplay Registry anchors the claim to Bitcoin via OpenTimestamps. Your script stays on your machine; only a hash is published.

**Status**: `v0.2.0` — adds the browser-native register flow (`/create/`), the in-browser verifier (`/verify/`), and PDF input via the `screenreg extract` subcommand. No v1 commitment-bearing surface (URN namespaces, profile IDs, normalization profile, canonicalization scheme, scene+paragraph tree formats, AES AAD, Ed25519 wire) changed in v0.2 — a v0.2 verifier should accept v0.1.0 envelopes and `.ots` proofs that are valid against v0.1.0. A fixture-backed cross-version regression test is not yet in place; if you re-verify a v0.1.0 proof under v0.2 and see a difference, please file an issue. See [CHANGELOG.md](CHANGELOG.md) for the full v0.2 scope.

---

## What this is

The Screenplay Registry gives a writer the ability to:

1. **Prove a screenplay existed by a specific date** — anchored to Bitcoin via OpenTimestamps. The proof is mathematically verifiable forever, with no dependence on any company, server, or hosted service.
2. **Signal opt-out from AI training** — a public, machine-readable preference using the C2PA training/mining convention (already honored by Adobe Firefly and Spawning's HaveIBeenTrained registry).
3. **Keep the script private** — the protocol commits the *hash* of the script to Bitcoin, not the script itself. The full content never leaves the writer's machine.
4. **Selectively disclose specific scenes** — via scene-level Merkle proofs ("I can prove scene 47 was in my registered script without revealing the rest").
5. **Encrypt manifest metadata** — title, author, and other fields can be encrypted with a writer-held password while still committing them into the on-chain claim.
6. **Compare two registered scripts for exact byte-content reuse** — via opt-in comparison disclosure bundles (Section 06). Either side can refuse; comparison is consent-bound, never coerced. The public claim never exposes per-scene fingerprints.

## Why this exists

Writers today have two registration options that don't quite work:
- **US Copyright Office** ($45, 4-month processing) gives federal-court teeth but is slow, bureaucratic, and uploads the whole file.
- **WGA registration** ($10-25, 5-year term) is faster but explicitly disclaimed as legally weak, expires, and also uploads the whole file.

Blockchain timestamping services (OriginStamp, Bernstein, Stampd) exist but are paid, vendor-tied, and don't integrate into the writer's tools. C2PA Content Credentials have 6,000+ adopters in image/video — but screenplays are not a first-class asset type.

This protocol fills the gap: **free, open, privacy-first, tool-integrable, asset-agnostic, AI-training-aware, and cryptographically verifiable**.

## What the protocol does NOT do

- **Replace US Copyright Office registration.** For federal-court statutory damages, you still need to register with the Copyright Office. This protocol provides cryptographic evidence; the Copyright Office provides legal procedural standing.
- **Prove authorship.** It proves a specific normalized byte sequence existed by a Bitcoin block timestamp. It does NOT prove who wrote those bytes. Opt-in identity binding via an Ed25519 `registrant` block (RFC 8032) IS available in v1 — pass `--identity` to `screenreg register` — but it only proves the holder of the private key signed the claim; binding that key to a real-world identity is out of scope.
- **Prove originality or novelty.** Two writers can independently arrive at similar ideas; the protocol records the order, not the merit.
- **Enforce AI-training opt-out.** The preference is a public, machine-readable *signal*. Companies that respect it (Adobe Firefly, Spawning) will honor it. Companies that ignore it can still scrape.

See [`docs/threat-model.md`](docs/threat-model.md) for the precise guarantees and limits.

## Quick start

### In the browser (recommended)

Drop your `.fountain` file at [**screenplayregistry.org/create/**](https://screenplayregistry.org/create/). The page hashes the file locally, sends only the 32-byte claim hash to public OpenTimestamps calendars, and gives you back two files to download: `manifest.json` (the envelope) and `proof.ots` (the Bitcoin timestamp proof). The script content never leaves your tab; there is no upload step. No account, no install, no analytics.

Verify any registered proof at [**screenplayregistry.org/verify/**](https://screenplayregistry.org/verify/) by drag-dropping the original file plus the two artifacts. Verification is entirely offline; the page never contacts the protocol's servers.

> **Hosting**: the official build of these pages is served from Cloudflare Pages with the security headers defined in [`landing/_headers`](landing/_headers) (strict CSP, HSTS preload-eligible, COOP/CORP same-origin, locked-down Permissions-Policy). The same HTML, JS, and headers are vendored in this repo under [`landing/`](landing/) and [`verifier-web/`](verifier-web/) — you can self-host either page or serve them from any static-file host. Deploy instructions are in [`landing/README.md`](landing/README.md).

### From the command line

```bash
# Clone + install
git clone https://github.com/screenplay-registry/screenreg.git
cd screenreg
npm install
python3 -m venv .venv && .venv/bin/pip install opentimestamps opentimestamps-client

# Register a Fountain screenplay
./bin/screenreg.mjs register my-screenplay.fountain
#   → my-screenplay.fountain.manifest.json
#   → my-screenplay.fountain.proof.ots

# Verify any time (offline, never needs the protocol's servers)
./bin/screenreg.mjs verify my-screenplay.fountain \
    my-screenplay.fountain.manifest.json \
    my-screenplay.fountain.proof.ots
# → ✓ VERIFIED — content hash matches, claim hash matches, OTS proof valid

# Register from a PDF (v0.2+): two-step so you review the extracted Fountain
./bin/screenreg.mjs extract my-screenplay.pdf > my-screenplay.fountain
# ... review my-screenplay.fountain, edit if the extractor mis-classified anything ...
./bin/screenreg.mjs register my-screenplay.fountain --source-pdf my-screenplay.pdf
#   → the envelope records the source-PDF SHA-256 in
#     evidenceBundle.bundleExtensions.sourceExtractor for archival audit

# If verification fails, diagnose mode reports what it can and cannot determine
./bin/screenreg.mjs diagnose my-screenplay.fountain my-screenplay.fountain.manifest.json
```

## Architecture (one diagram)

```
                     ┌─────────────────────────────┐
WRITER'S MACHINE     │     YOUR SCREENPLAY         │
                     │     (stays here forever)    │
                     └────────────┬────────────────┘
                                  │
                       normalize (UTF-8 NFC + LF + strip BOM)
                                  │
                                  ▼
                            SHA-256 = contentHash
                                  │
                                  │
                ┌─────────────────┼─────────────────┐
                │                 │                 │
                ▼                 ▼                 ▼
        scene-tree Merkle   encrypt opt fields   AI-training pref
              root          (AES-256-GCM)         (C2PA convention)
                │                 │                 │
                └─────────────────┼─────────────────┘
                                  │
                          committedClaim {  }
                                  │
                       canonicalize (RFC 8785)
                                  │
                                  ▼
                            SHA-256 = claimHash  ◄────── this 32-byte hash
                                  │                       is the ONLY thing
                                  ▼                       that leaves your machine
                          OpenTimestamps Bitcoin
                          (public calendars batch
                           thousands of hashes per
                           Bitcoin tx; $0 cost to you)
                                  │
                                  ▼
                              .ots proof
                          (verifiable forever
                          against Bitcoin block headers)
```

## Specifications

The protocol's commitment-bearing rules are documented in `/spec/v1/`:

| Section | Purpose |
|---|---|
| [01 — Normalization](spec/v1/01-normalization.md) | Canonical UTF-8 normalization (`screenplay-registration-norm/v1-strict`) |
| [02 — Envelope](spec/v1/02-envelope.md) | `committedClaim` + `evidenceBundle` schema, RFC 8785 canonicalization, verifier rules |
| [03 — Scene Tree](spec/v1/03-scene-tree.md) | Merkle tree with domain separation (`screenplay-registration-merkle/v1`) |
| [04 — Encryption](spec/v1/04-encryption.md) | AES-256-GCM + length-delimited AAD (`screenplay-registration-aad-v1`) |
| [05 — Similarity Commitment Layer](spec/v1/05-similarity.md) | What the claim commits: scene + paragraph Merkle roots and counts only — NOT per-leaf hashes |
| [06 — Comparison Disclosure Bundle](spec/v1/06-comparison-bundle.md) | Opt-in sidecar revealing per-leaf hashes + word counts + byte ranges so two registrants can compare scripts. Irrevocable once published. |
| [07 — Time-locked Encrypted Fields](spec/v1/07-timelock.md) | Capability-flagged. Drand quicknet timelock — fields decrypt at a deterministic future Drand round, no third-party escrow. |

The committed namespace identifiers are **URN-based and brand-neutral**:
- `urn:screenplay-registration-claim:v1`
- `urn:screenplay-registration-claim-schema:v1`
- `urn:screenplay-registration-comparison-bundle:v1`
- `screenplay-registration-norm/v1-strict`
- `screenplay-registration-merkle/v1`
- `screenplay-registration-paragraph-merkle/v1`

These never change. Brand-related names (CLI command, npm scope, foundation name) live in a separate "Track B" and can be renamed without breaking any v1 proofs.

## Repository layout

```
/spec/v1/                    canonical specification (markdown + JSON schemas + test vectors)
/src/normalize/              normalization reference implementation
/src/envelope/               envelope construction + canonicalization + claim hash
/src/merkle/                 scene-tree Merkle implementation
/src/encrypt/                encrypted-field layer
/src/anchors/                OTS adapter (Python helper + clean-room TS verifier)
/src/cli/                    CLI entry point
/test/                       vitest tests for core behavior, CLI flows, and adversarial cases
/verifier-web/               browser-native drag-and-drop verifier (single HTML+JS)
/docs/                       user-facing documentation (threat model, FAQ, etc.)
/bin/screenreg.mjs                 CLI shim
/scripts/                    test vector corpus generators
```

## Documentation

- [Threat model](docs/threat-model.md) — what the protocol proves and does NOT prove
- [AI-training opt-out signal](docs/ai-training-signal.md) — what the signal means
- [Adoption guide](docs/adoption-guide.md) — for integrators (writing apps, web tools)
- [Comparison: vs WGA, Copyright Office, OTS-bare](docs/comparison.md)
- [FAQ](docs/faq.md)

## Roadmap

### v0.1 (initial public release — shipped)
- Core spec + reference TypeScript implementation
- Python helper for OTS calendar submission
- CLI: register / verify / diagnose / similarity / disclose-comparison / verify-registration / scene-prove / decrypt-field / timelock-encrypt / timelock-decrypt + 6 more
- Browser-native drag-and-drop verifier
- 80+ adversarial test vectors per layer; 368 passing tests
- Forward-compatibility via envelope split (`committedClaim` + `evidenceBundle`)
- See [CHANGELOG.md](CHANGELOG.md) for the full v0.1.0 entry.

### v0.2 (post-launch)
- Browser-side full SPV verification with hardcoded Bitcoin block-header checkpoints + public block-explorer fallback
- Optional Ethereum L2 (Base, via EAS) as a secondary anchor — additive, doesn't change v1 commitments
- Python SDK
- Trademark-cleared brand name + dedicated domain

### v0.3+ (community-driven)
- ZK proofs of script properties (word count, contains-string) — proof-types over existing commitment, no migration
- Sigstore-style optional identity binding via OIDC (carefully — public identity logs need thought)
- C2PA sidecar export for PDF/manifest interop
- `screenplay-registration-norm/v2-fountain` lossy normalization profile (coexists with v1-strict)

## Licenses

- **Code**: [MIT](LICENSE)
- **Spec**: [CC-BY 4.0](SPEC-LICENSE)
- **Test vectors**: [CC0](TESTVECTORS-LICENSE)

## Governance

The Screenplay Registry is an open standard. The protocol spec, the commitment-bearing URN namespace, and the verification semantics are intentionally designed to outlive any single steward or sponsor. Existing proofs remain verifiable forever via the OpenTimestamps Bitcoin anchor regardless of who maintains the reference implementation.

### Roadmap to community governance

- **Phase 1 (current)**: single-steward maintenance by initial contributors.
- **Phase 2** (triggered by 3+ external integrators OR 6 months, whichever first): stewards council with 2-4 external maintainers, decisions by majority, chair role rotated annually.
- **Phase 3** (triggered by sustained adoption): fiscal sponsorship under the Linux Foundation OpenSSF (Sigstore precedent) or Open Source Collective.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). All contributions are accepted under the Developer Certificate of Origin (DCO) — sign off your commits with `git commit -s`.
