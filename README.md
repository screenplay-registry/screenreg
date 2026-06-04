# The Screenplay Registry

```
                        .-**####**=.
                      :*############*-.
                    .*################*:
                   .+###################.
                  .-####################+.
                  .+####################*.
                  .+####################*.
                   :####################+.
                    =##################*.
                    .+################*.
                      -##############+.
                      ..*###########-.
                        .##########-
                         -#########.
                         :#########.
                        .*#########.
                        -##########=
                       .*###########:
                      =##############*.
                      =***************.
                 .=***********************=.
                 .*#######################+.
                 .*#######################+.
      +++**++*#*=+**+=**+=+**==**+=+#*=+**+=*#*++**+++.
      +-------*-------+-------=------+-------#-------+.
      +.     .*.     .+.     ::     .=.     .#.     .+.
      +.     .*.     .+.     ::     .=.     .#.     .+.
      +.     .*.     .+.     ::     .=.     .#.     .+.
      +.     .*.     .+.     ::     .=.     .#.     .+.
      +++**++*#+=+**+=**+=+**==**+=+**=+**++*#*++**+++.
      :==++++++++++++++++++++++++++++++++++++++++++==:.
       .=******************************************+.
             .:------------------------------:.
```

> **A free and open registry for dated, verifiable proof that a screenplay draft existed.**

Register a screenplay, pilot, treatment, or draft by creating a dated, cryptographically verifiable record that the exact draft existed. The Screenplay Registry anchors that record to Bitcoin via OpenTimestamps. Your script stays on your machine; only a hash is published.

**Status**: `v0.2.0` — adds the browser-native register flow (`/create/`), the in-browser verifier (`/verify/`), and PDF input via the `screenreg extract` subcommand. No v1 commitment-bearing surface (URN namespaces, profile IDs, normalization profile, canonicalization scheme, scene+paragraph tree formats, AES AAD, Ed25519 wire) changed in v0.2 — a v0.2 verifier should accept v0.1.0 envelopes and `.ots` proofs that are valid against v0.1.0. A fixture-backed cross-version regression test is not yet in place; if you re-verify a v0.1.0 proof under v0.2 and see a difference, please file an issue. See [CHANGELOG.md](CHANGELOG.md) for the full v0.2 scope.

---

## What this is

The Screenplay Registry gives a writer the ability to:

1. **Prove a screenplay existed by a specific date** — anchored to Bitcoin via OpenTimestamps. The proof is mathematically verifiable forever, with no dependence on any company, server, or hosted service.
2. **Signal opt-out from AI training** — a public, machine-readable preference using the CAWG training-data-mining convention (originally part of C2PA), set via the CLI. Honoring it is voluntary; see [`docs/ai-training-signal.md`](docs/ai-training-signal.md).
3. **Keep the script private** — the protocol commits the *hash* of the script to Bitcoin, not the script itself. The full content never leaves the writer's machine.
4. **Selectively disclose specific scenes** — via scene-level Merkle proofs ("I can prove scene 47 was in my registered script without revealing the rest").
5. **Encrypt manifest metadata** — title, author, and other fields can be encrypted with a writer-held password while still committing them into the claim that gets timestamped.
6. **Compare two registered scripts for exact byte-content reuse** — via opt-in comparison disclosure bundles (Section 06). Either side can refuse; comparison is consent-bound, never coerced. The public claim never exposes per-scene fingerprints.

## Why this exists

Writers today have two registration options that don't quite work:
- **US Copyright Office** ($45, 4-month processing) gives federal-court teeth but is slow, bureaucratic, and uploads the whole file.
- **WGA registration** ($10-25, 5-year term) is faster but explicitly disclaimed as legally weak, expires, and also uploads the whole file.

Blockchain timestamping services (OriginStamp, Bernstein, Stampd) exist but are paid, vendor-tied, and don't integrate into the writer's tools. C2PA Content Credentials have 6,000+ adopters in image/video — but screenplays are not a first-class asset type.

This protocol fills the gap: **free, open, privacy-first, tool-integrable, asset-agnostic, AI-training-aware, and cryptographically verifiable**.

## Registration tiers

The protocol has one commitment-bearing core and two optional, additive tiers layered on top of it. Only Tier 1 is live; Tiers 2 and 3 are specified and reserved.

- **Tier 1 — Free Bitcoin timestamp (live).** Hash your script locally; anchor the 32-byte claim hash to Bitcoin via OpenTimestamps. No wallet, no crypto, no account, no upload. This is the only tier that carries any time or priority weight, and it is the default everywhere. Everything below is optional and changes nothing about what Tier 1 proves.
- **Tier 2 — Public registry index (specified; not live).** An optional, searchable directory of registrations (look up a claim hash, public title, or public author label). It is a discovery convenience, not an authority: the MVP index gives **zero** cryptographic protection against an operator that censors or equivocates, and each record's truth is its own `.ots` verified against Bitcoin. Priority is decided by Bitcoin block height only. The script fingerprint (`contentHash`) is never published. See [spec 10](spec/v1/10-registry-index.md).
- **Tier 3 — Optional on-chain certificate (specified; not live).** An optional, opt-in record of the same claim hash on Ethereum mainnet (a `ScreenplayLedger` event), plus an optional, transferable product NFT. It would be a secondary, additive witness — **never** a time or priority source, never required, and content-neutral by design. As designed, the on-chain record would be permissionless and permanent: the user-chosen title/name would be public and could not be removed. It does **not** prove authorship and is **not** a Copyright-Office replacement. The interface is frozen in [spec 09](spec/v1/09-onchain-anchor.md); the contract is not yet deployed and needs a security audit + legal review before mainnet.

## What the protocol does NOT do

- **Replace US Copyright Office registration.** For federal-court statutory damages, you still need to register with the Copyright Office. This protocol provides cryptographic evidence; the Copyright Office provides legal procedural standing.
- **Prove authorship.** It proves a specific normalized byte sequence existed by a Bitcoin block timestamp. It does NOT prove who wrote those bytes. Opt-in identity binding via an Ed25519 `registrant` block (RFC 8032) IS available in v1 — pass `--identity` to `screenreg register` — but it only proves the holder of the private key signed the claim; binding that key to a real-world identity is out of scope.
- **Prove originality or novelty.** Two writers can independently arrive at similar ideas; the protocol records the order, not the merit.
- **Enforce AI-training opt-out.** The preference is a public, machine-readable *signal*. Honoring it is voluntary; a company that ignores it can still scrape. Its value is as dated evidence of intent, not technical enforcement.

See [`docs/threat-model.md`](docs/threat-model.md) for the precise guarantees and limits.

## Quick start

### In the browser (recommended)

Drop your screenplay — a `.pdf`, `.fountain`, or plain text — at [**screenplayregistry.org/create/**](https://screenplayregistry.org/create/). The page reads and hashes the file locally (a PDF is converted to text right in your browser), sends only a 32-byte nonce-blinded commitment — never the claim hash itself — to public OpenTimestamps calendars, and gives you back a single **`.screenreg`** file: your screenplay, the registration record, and the timestamp proof in one file — plus a shareable proof-only version that omits the script. The proof is usable immediately as a pending calendar attestation; the Bitcoin confirmation becomes available about 1–6 hours later, and the page hands you the finalized `.screenreg` once it lands. The script content never leaves your tab; there is no upload step. No account, no install, no analytics.

Verify any registered proof at [**screenplayregistry.org/verify/**](https://screenplayregistry.org/verify/) by drag-dropping the `.screenreg` (a proof-only file verifies the date; add the screenplay to also confirm the contents). Verification is entirely offline; the page never contacts the protocol's servers.

> **Hosting**: the official build of these pages is served from Cloudflare Pages with the security headers defined in [`landing/_headers`](landing/_headers) (strict CSP, HSTS preload-eligible, COOP/CORP same-origin, locked-down Permissions-Policy). The same HTML, JS, and headers are vendored in this repo under [`landing/`](landing/) and [`verifier-web/`](verifier-web/) — you can self-host either page or serve them from any static-file host. Deploy instructions are in [`landing/README.md`](landing/README.md).

### From the command line

```bash
# Install the CLI — Node ≥20, that's all; no Python, no native deps.
npm install -g screenreg          # global command:  screenreg …
# no global install?              npx screenreg …
# from source?                    git clone https://github.com/screenplay-registry/screenreg.git
#                                 cd screenreg && npm install   # then ./bin/screenreg.mjs in place of screenreg
```

```bash
# Register a Fountain screenplay → ONE self-contained file
screenreg register my-screenplay.fountain
#   → my-screenplay.screenreg   (your screenplay + the proof in one file; Bitcoin confirmation ~1-6h)
#   later, once Bitcoin confirms: screenreg finalize my-screenplay.screenreg

# Verify it — one file, on the CLI or in the browser (drop it at screenplayregistry.org/verify/):
screenreg verify my-screenplay.screenreg
# → ✓ VERIFIED — claim hash matches and the screenplay contents match the registration
#   (a proof-only .evidence.screenreg verifies the date; add the screenplay to confirm contents:
#    screenreg verify my-screenplay.evidence.screenreg my-screenplay.fountain)

# Prefer separate files end-to-end (integrators)? --loose emits the manifest + .ots, no bundle:
screenreg register my-screenplay.fountain --loose
#   → my-screenplay.fountain.manifest.json + my-screenplay.fountain.proof.ots
screenreg verify my-screenplay.fountain \
    my-screenplay.fountain.manifest.json my-screenplay.fountain.proof.ots

# Register from a PDF (v0.2+): two-step so you review the extracted Fountain
screenreg extract my-screenplay.pdf > my-screenplay.fountain
# ... review my-screenplay.fountain, edit if the extractor mis-classified anything ...
screenreg register my-screenplay.fountain --source-pdf my-screenplay.pdf
#   → the envelope records the source-PDF SHA-256 in
#     evidenceBundle.bundleExtensions.sourceExtractor for archival audit
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
| [09 — Optional Ethereum on-chain anchor](spec/v1/09-onchain-anchor.md) | Optional `ethereum-anchor` evidence proof + the pinned `ScreenplayLedger` interface. Secondary, additive witness on Ethereum mainnet; never a time or priority source; never hashed into `claimHash`. Interface frozen, deployed contract reserved. |
| [10 — Off-chain registry index](spec/v1/10-registry-index.md) | Optional searchable directory of registrations (`urn:screenplay-registration-registry-record:v1`). A discovery convenience; per-record truth is each record's own `.ots` against Bitcoin. Priority is Bitcoin-only. |

The committed namespace identifiers are **URN-based and brand-neutral**:
- `urn:screenplay-registration-claim:v1`
- `urn:screenplay-registration-claim-schema:v1`
- `urn:screenplay-registration-comparison-bundle:v1`
- `screenplay-registration-norm/v1-strict`
- `screenplay-registration-merkle/v1`
- `screenplay-registration-paragraph-merkle/v1`

These never change. Brand-related names (CLI command, package/repository name, foundation name) live in a separate "Track B" and can be renamed without breaking any v1 proofs.

## Repository layout

```
/spec/v1/                    canonical specification (markdown + JSON schemas + test vectors)
/src/normalize/              normalization reference implementation
/src/envelope/               envelope construction + canonicalization + claim hash
/src/merkle/                 scene-tree Merkle implementation
/src/encrypt/                encrypted-field layer
/src/anchors/                OTS adapter (clean-room TS calendar submit + verifier) + Bitcoin SPV
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
- Clean-room TypeScript OTS calendar submission + verification (no native deps)
- CLI: register / verify / diagnose / similarity / disclose-comparison / verify-registration / scene-prove / decrypt-field / timelock-encrypt / timelock-decrypt + 6 more
- Browser-native drag-and-drop verifier
- 80+ adversarial test vectors per layer; 368 passing tests
- Forward-compatibility via envelope split (`committedClaim` + `evidenceBundle`)
- See [CHANGELOG.md](CHANGELOG.md) for the full v0.1.0 entry.

### v0.2 (shipped)
- Browser-native register flow (`/create/`) and in-browser verifier (`/verify/`)
- PDF input via the `screenreg extract` subcommand + pluggable extractor
- See [CHANGELOG.md](CHANGELOG.md) for the full v0.2 entry.

### Planned (v0.3+, community-driven; not yet live)
- Browser-side full SPV verification with hardcoded Bitcoin block-header checkpoints + public block-explorer fallback
- Optional Ethereum-mainnet anchor as a secondary, additive witness (never a priority source; Bitcoin remains the sole time/priority anchor) — see [spec 09](spec/v1/09-onchain-anchor.md); additive, doesn't change v1 commitments. Contract not yet deployed; requires a security audit + legal review before mainnet.
- Public off-chain registry index (signed, mirrorable) — see [spec 10](spec/v1/10-registry-index.md)
- Python SDK
- ZK proofs of script properties (word count, contains-string) — proof-types over existing commitment, no migration
- Sigstore-style optional identity binding via OIDC (carefully — public identity logs need thought)
- C2PA sidecar export for PDF/manifest interop
- `screenplay-registration-norm/v2-fountain` lossy normalization profile (coexists with v1-strict)
- Trademark-cleared brand name + dedicated domain

## Licenses

- **Code**: [MIT](LICENSE)
- **Spec**: [CC-BY 4.0](SPEC-LICENSE)
- **Test vectors**: [CC0](TESTVECTORS-LICENSE)

## Governance

The Screenplay Registry is an open standard. The protocol spec, the commitment-bearing URN namespace, and the verification semantics are intentionally designed to outlive any single maintainer or sponsor. Existing proofs remain verifiable forever via the OpenTimestamps Bitcoin anchor regardless of who maintains the reference implementation.

### Roadmap to community governance

- **Phase 1 (current)**: maintenance by the initial contributors.
- **Phase 2** (triggered by 3+ external integrators OR 6 months, whichever first): stewards council with 2-4 external maintainers, decisions by majority, chair role rotated annually.
- **Phase 3** (triggered by sustained adoption): fiscal sponsorship under the Linux Foundation OpenSSF (Sigstore precedent) or Open Source Collective.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). All contributions are accepted under the Developer Certificate of Origin (DCO) — sign off your commits with `git commit -s`.
