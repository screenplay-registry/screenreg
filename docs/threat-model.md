# Threat Model

What The Screenplay Registry proves, and what it does NOT prove. Written honestly, in plain English, with the precise language a court (or a careful skeptic) would respect.

---

## What it PROVES

A successful verification establishes the following facts with cryptographic certainty:

1. **The exact normalized bytes of your screenplay existed by the Bitcoin block timestamp recorded in your proof — ONCE the proof has been upgraded to a Bitcoin attestation.**
   - "Exact normalized bytes" means: the bytes that come out of applying the `screenplay-registration-norm/v1-strict` profile (UTF-8 + NFC + LF + strip BOM) to your input.
   - "Bitcoin block timestamp" means: the median time of the Bitcoin block that anchored your registration's calendar batch. This timestamp is set by Bitcoin's consensus rules and is forgery-resistant under the same assumptions that secure the Bitcoin network.
   - **Pending vs anchored**: immediately after `screenreg register`, the embedded proof contains only a *pending calendar attestation* — a promise from a public OpenTimestamps calendar that your hash will be folded into the next Bitcoin batch. Until you run `screenreg finalize` (typically 1-6 hours later), the proof's trust assumption includes the calendar operator. After finalizing, the calendar attestation is replaced with a self-contained Bitcoin proof. `screenreg verify` distinguishes the two states: `✓ VERIFIED` (a Bitcoin attestation is present) vs `⚠ VERIFIED (PENDING)`. CI/scripted contexts can pass `--require-bitcoin-anchor` to exit 2 unless the proof is fully anchored.
2. **Once anchored, anyone with your `.screenreg` (or, in loose mode, the script + manifest + finalized proof) can independently confirm this fact** without contacting any server, querying any company, or trusting any third party — only a Bitcoin node (or any party who can verify Bitcoin block headers). Pre-upgrade proofs cannot be independently verified against Bitcoin alone; they depend on the named calendar operators in the proof until the upgrade folds in the block proof. (Note: the v0.x reference verifier validates the OTS proof structure but does NOT yet perform full SPV / block-header verification against a local Bitcoin node — that work is deferred to a future minor release. Today an operator who wants Bitcoin-block-header confirmation runs the standard `ots verify` from `opentimestamps-client` against an upgraded `.ots`, which talks to either a local Bitcoin RPC node or a public block-header API.)
3. **If you used the scene-level or paragraph-level Merkle tree:** for any specific scene (or paragraph), you can later prove that unit was part of the registered script WITHOUT revealing any of the others. The paragraph tree is more robust to global rename + scene-heading edits — only paragraphs containing the changed term are invalidated.
4. **If you encrypted manifest fields with a password:** the ciphertext is part of the committed claim that gets timestamped, so the fact that you committed to those values is permanent and unforgeable, even though the values themselves remain private until you reveal them.
5. **If you opt in to comparison** (Section 06): two registrants who BOTH publish comparison disclosure bundles can be compared for exact byte-content reuse — set Jaccard + multiset + longest-common-run + longest-common-subsequence + coverage-by-words for paragraphs. The comparison is independently verifiable from the two bundles alone, with no third-party comparison service required.

## What it does NOT PROVE

These are explicitly OUT OF SCOPE. We document them clearly because overclaiming is worse than under-promising.

1. **It does NOT prove authorship.**
   The protocol records that a specific byte sequence existed by a date. It does NOT record who wrote those bytes. Two people typing the same screenplay would produce the same hash. To bind your identity to a registration, you must combine this with an external attestation (Copyright Office registration, notarized affidavit, public signing key, etc.).
2. **It does NOT prove originality or novelty.**
   The protocol records ORDER (your registration came before someone else's), not MERIT. If two writers independently arrive at similar content, both can register; both registrations are valid, and the protocol does not declare a winner.
3. **It does NOT replace US Copyright Office registration.**
   The Copyright Office gives you:
   - Federal-court standing to file infringement suits
   - Eligibility for statutory damages (up to $150K/willful) + attorney's fees
   - A presumption of validity if registered within 5 years of publication
   These are LEGAL PROCEDURAL benefits that the Copyright Office uniquely provides. This protocol gives you CRYPTOGRAPHIC EVIDENCE that complements the Copyright Office's evidentiary record — it does not substitute for it. **For maximum legal protection, register with the Copyright Office AND create a Screenplay Registry proof.**
4. **It does NOT enforce AI-training opt-out.**
   The preference field in the manifest is a public, machine-readable SIGNAL. Honoring it is voluntary: some systems that consume C2PA/CAWG provenance may choose to, and a company that ignores it can still scrape your work. The signal's value is:
   - As evidence in litigation (you publicly declared intent before the scrape)
   - As a machine-readable preference that opt-in honoring systems could consult
   - As cultural pressure on holdouts
   It is NOT a technical enforcement mechanism. See [`ai-training-signal.md`](ai-training-signal.md) for the full discussion.
5. **It does NOT prove your real-world identity to anyone who doesn't already trust your asserted identity.**
   v1 ships opt-in Ed25519 registrant binding (`--identity`): the registration carries a `registrant` block with a public key + signature over the claim body, proving that whoever HOLDS THE PRIVATE KEY signed this specific claim at registration time. This is strong KEY-binding (you can later prove key control via challenge-response). It is NOT real-world identity binding — the registry does not check that the public key belongs to any specific human or legal entity. To bind a real-world identity, combine the registrant block with an external attestation (Copyright Office registration, notarized affidavit, KYC service that signs your public key, etc.). v2+ may add Sigstore-style ephemeral OIDC binding for in-protocol identity attestation; that requires careful threat modeling because public identity logs have their own risks for writers.
6. **It does NOT survive Bitcoin's failure.**
   If Bitcoin collapses, your proof loses its anchor. This is a multi-decade tail risk. By that time, the protocol is expected to support multiple parallel anchors (an optional Ethereum-mainnet anchor, Sigstore-style transparency logs, etc.) — additive, not replacements — so a single chain's failure does not invalidate proofs anchored to OTHER chains.
7. **The optional public registry index does NOT prove non-censorship or non-equivocation.**
   The optional registry index (a searchable directory of registrations) is specified but not yet live. As designed it would be a discovery convenience, not a transparency log. In its MVP form it would give ZERO cryptographic protection against an operator that censors, withholds, delays, reorders, or equivocates (serves different views to different clients). Treat it as a signed, mirrorable dataset and assume the operator MAY equivocate. The protection that DOES hold is per-record and operator-independent: each record's truth is its OWN `.ots` proof verified against Bitcoin, which anyone can check without trusting the operator. A CT-style append-only transparency log (signed tree heads, consistency proofs, public checkpoints, gossip) is the roadmap target; until it ships, "nothing was altered or removed" is NOT cryptographically established. The index never publishes the script fingerprint (`contentHash`), so it cannot be used as a membership oracle.
8. **The optional on-chain anchor does NOT prove authorship, and its public labels cannot be un-published.**
   The optional Ethereum-mainnet anchor is specified but not yet live (no contract is deployed). As designed it would record the same opaque claim hash plus user-chosen `title`/`name` labels on a permissionless, permanent ledger. It is a secondary, additive witness only: it is NEVER a time or priority source (Bitcoin remains the sole time + priority anchor), a missing or failed on-chain check never invalidates an otherwise Bitcoin-valid proof, and it does NOT prove who wrote the script. The on-chain record is anti-censorship by design — once written, the user-chosen labels are public and CANNOT be removed, so choose them accordingly (the `name` label is blank by default, and the script fingerprint is never published on-chain). Any abuse-control at the relayer or registry intake is content-neutral (admission, rate limits, optional small fee, light proof-of-work) and never gates on content.

## Adversaries this protocol defends against

1. **Idea-theft-then-deny.** "I came up with that scene first, not you." Cryptographic evidence that your bytes existed by a specific Bitcoin block timestamp is strong rebuttal evidence.
2. **AI-training-without-consent.** A dated, signed, machine-readable opt-out declaration. Honoring by any system is voluntary; its evidentiary and cultural weight grows as adoption grows.
3. **Manifest tampering.** Any modification to the manifest, ciphertext, scene tree, or other commitment-bearing fields invalidates the claim hash, which invalidates the OTS proof, which is detected by any verifier.
4. **Scene-substitution.** With scene-level Merkle proofs + domain separation + sceneCount commitment, an attacker cannot claim "scene 47 was in your script" with arbitrary content, cannot reorder scenes without invalidating the tree, and cannot truncate scenes without invalidating the count. The paragraph tree adds an additional layer with the same protection at finer granularity.
5. **Field-swap in encryption.** AES-256-GCM with AAD binding the field name + claim version prevents an attacker from moving a ciphertext from one field to another.
6. **Brand renaming.** The commitment-bearing identifiers are URN-based (no DNS dependency, no brand baked in). A future foundation rename, domain expiry, or org dissolution does not invalidate any v1 proofs.
7. **Membership-oracle queries against the public claim.** Per the Section 05 §5.1 mitigation, per-scene + per-paragraph content hashes are NOT in the public claim — only Merkle roots and counts. An adversary holding a candidate hash CANNOT test "is this scene in any registered script?" against the public corpus. Comparison is gated by opt-in disclosure bundles (Section 06); writers who never publish a bundle expose no fingerprintable surface beyond what was already public (scene count, paragraph count, content hash).

## Adversaries this protocol does NOT defend against

1. **An owner who lies about their password.** If you encrypted the title and then claim a different plaintext, no one can detect that unless they have your password. (Solution: don't encrypt fields you might want to argue about.)
2. **An owner who registers a re-edited script as a "new version."** This is by design — writers should be able to register revisions.
3. **An attacker who has your password AND your `.screenreg` (or its envelope).** They can decrypt your encrypted fields. (Solution: don't use the same password as your email; use a strong unique password for registration.)
4. **An attacker who has your envelope and uses offline password-guessing.** PBKDF2-HMAC-SHA256 at 600,000 iterations is CPU-hard (meets OWASP 2024 minimum) but NOT memory-hard. A motivated attacker with GPU/ASIC infrastructure can guess at ~10⁶–10⁸ candidates/sec. A 12-char random password (≥80 bits entropy) remains infeasible to brute-force in reasonable time; weak passwords (dictionary words, short, common patterns) are at risk. v2 will migrate to Argon2id (memory-hard) for stronger offline-attack resistance; in the meantime, choose a passphrase of ≥4 random dictionary words or use a password manager.
5. **A nation-state that compromises a majority of Bitcoin's hashpower for an extended period.** Out of scope; this is the same threat model as Bitcoin itself.
6. **Loss of all your files.** If you lose your `.screenreg` (or, in `--loose` mode, the script, the manifest, AND the .ots proof), you have no way to demonstrate your prior registration. The Bitcoin chain still contains the hash, but you can't prove which hash was yours without your local files. **Back up your `.screenreg` file.**

## Cryptographic primitives

| Primitive | Algorithm | Standard |
|---|---|---|
| Content hashing | SHA-256 | FIPS 180-4 |
| Canonicalization | RFC 8785 JCS | RFC 8785 |
| Scene-tree | Merkle binary tree with domain-separation tags `0x00`/`0x01`/`0x02` | inspired by RFC 6962 §2.1 |
| Paragraph-tree | Merkle binary tree with domain-separation tags `0x10`/`0x11`/`0x12` (distinct from scene-tree to prevent cross-tree confusion) | inspired by RFC 6962 §2.1 |
| Encryption | AES-256-GCM with 96-bit random IV | NIST SP 800-38D |
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2024 minimum) | RFC 8018 |
| Time anchor | OpenTimestamps protocol → Bitcoin | opentimestamps.org spec |
| Registrant signature (optional) | Ed25519 over `"screenplay-registry-claim-v1" \|\| SHA-256(canonical claim body without registrant block)` | RFC 8032 |

All primitives are standard. No custom cryptography. No novel constructions. The protocol is composed of well-understood building blocks.
