# FAQ

---

## Is this a substitute for the US Copyright Office?

**No.** The Copyright Office gives you federal-court statutory damages + attorney's fees in an infringement suit. This protocol gives you cryptographic evidence that complements that. For maximum protection, register with the Copyright Office AND create a protocol proof. See [`comparison.md`](comparison.md) for details.

## Is this a substitute for WGA registration?

**Not exactly.** WGA registration's main value is credit arbitration if your project gets made. The protocol does NOT carry that guild-internal weight. WGA is also faster (instant), cheaper for members ($10), but expires every 5 years and uploads the file. Use WGA for credit arbitration; use this protocol for everything else.

## What does "Bitcoin-anchored" mean in plain English?

When you register, a 32-byte fingerprint of your manifest goes through a public OpenTimestamps "calendar" server. The calendar batches thousands of fingerprints from different people into one cryptographic tree, and puts only the tree's root into a Bitcoin transaction. Bitcoin's distributed ledger then records that root permanently. Anyone with your `.ots` proof file can later check that your specific fingerprint was part of the tree that was committed in that Bitcoin block — proving your fingerprint existed by the block's timestamp.

You never see Bitcoin, and you never pay any fee. The calendar operators pay the Bitcoin transaction fee themselves as a public-good service (the per-fingerprint marginal cost is fractions of a cent).

## Doesn't Bitcoin use a lot of energy?

Yes. But the marginal energy cost of YOUR registration is essentially zero — the same Bitcoin transaction that anchors your registration also anchors thousands of other unrelated fingerprints. You're not commissioning a new transaction; you're sharing one that would happen anyway.

If you object to Bitcoin for environmental reasons, the protocol's `evidenceBundle` is extensible — v2+ may add Ethereum L2 (post-merge proof-of-stake, ~99% less energy) as a parallel anchor. Old v1 proofs remain valid; new proofs can use both.

## How long does registration take?

Two phases:
1. **Calendar attestation**: seconds. The OTS calendars accept your fingerprint immediately and return an unupgraded `.ots` proof that contains a pending attestation against their internal calendar log.
2. **Bitcoin confirmation**: 1-6 hours. The calendar batches fingerprints into a tree and submits the root in a Bitcoin transaction; Bitcoin confirms in ~10 min/block, and the calendar usually does 6 confirmations for safety. After that, you can run `screenreg upgrade` to download the fully Bitcoin-anchored proof.

You don't have to wait for the upgrade to use your registration — the pending proof carries the same fingerprint and same date claim. The upgrade just consolidates the calendar's attestation into a Bitcoin proof you can verify against block headers alone.

## What if a calendar server disappears?

Existing proofs that have been upgraded to Bitcoin: **continue to verify forever**, against any Bitcoin node, without any calendar in the loop.

Pre-upgrade proofs: lose their pending attestations if all calendars die at once. You'd need to re-submit the fingerprint to a new calendar to get a fresh anchor. (Anyone — including this project's foundation, if needed — can run a calendar.)

The protocol explicitly DOES NOT depend on any particular calendar operator's continued existence.

## What if Bitcoin itself collapses?

Then your proof loses its anchor — Bitcoin block headers wouldn't be verifiable. This is a multi-decade tail risk. By the time it's a realistic threat, the protocol will have additional parallel anchors (Ethereum L2, Sigstore-style logs, etc.) — additive, not replacements — so you can have a single registration that anchors to MULTIPLE chains. As long as ONE survives, the proof verifies.

## Can I register my screenplay anonymously?

**Yes — and you do by default.** The protocol does not bind your real-world identity to a registration in v1. The hash that goes to Bitcoin is just 32 bytes of randomness from Bitcoin's perspective; nothing identifies you.

If you also use encrypted manifest fields (title, author), even your own LOCAL copies of the manifest don't reveal anything without your password.

(v2+ MAY add optional identity binding via Sigstore-style ephemeral OIDC certs. Public identity logs have their own privacy considerations for writers — we're treating that as a careful design problem.)

## Can I prove I wrote a specific scene without revealing the rest of my script?

**Yes** — via the scene-level Merkle tree (`screenplay-registration-merkle/v1`). When you register, the protocol detects scene boundaries in your Fountain file (lines starting with `INT.`, `EXT.`, etc.) and builds a Merkle tree of per-scene hashes. The tree's root is part of your registration's commitment.

Later, to prove a specific scene was registered:

```bash
screenreg scene-prove my-screenplay.fountain my-screenplay.fountain.manifest.json 47
# emits a small JSON proof showing scene 47 was part of the tree
```

The recipient can verify that proof against your registered `sceneTreeRoot` without ever seeing your other scenes.

## What if I lose my password to encrypted fields?

You can't recover them. The protocol does NOT have a recovery mechanism — that's the whole point of encryption.

To mitigate: only encrypt fields you can recreate (or whose absence you'd be fine with). Use a password manager. The encrypted fields are mostly for convenience — your registration is still cryptographically valid even if you never recover the encrypted title.

## What if I edit my script after registering?

Verification will fail. The hash will differ. You should register a NEW version (which produces a new `.manifest.json` + `.proof.ots`). It's normal to have multiple registrations over a script's lifetime.

The `diagnose` mode will show you the transforms applied to the candidate file and the hash difference, but it cannot tell you EXACTLY which bytes changed — the protocol only stores the hash of the registered version, not the bytes.

## What if a court doesn't recognize cryptographic timestamps?

US courts have increasingly accepted blockchain timestamps as evidence (Vermont's blockchain rules, Federal Rules of Evidence Rule 902 self-authenticating data). Italy's Law 12/2019 gives blockchain timestamps eIDAS-equivalent legal effect. The EU's eIDAS 2 (effective Dec 2026) introduces Qualified Electronic Ledgers, and OTS-style Bitcoin anchoring is positioned to qualify.

This protocol's evidentiary value will continue to grow as adoption + legal precedent accumulate. For TODAY: pair with Copyright Office registration for the strongest legal posture.

## Why isn't there a hosted version?

There can be — any vendor may offer a "hosted convenience tier" with extras like email notifications when proofs upgrade, bulk registration, mobile apps, on-chain attestations, etc. The PROTOCOL is always free and runnable yourself. Vendor convenience tiers are optional and orthogonal to the protocol.

The deliberate choice to NOT have a single hosted version is what makes the protocol survive its operators — by design, you never need anyone's server to verify your proof.

## Is this a cryptocurrency thing? Do I need a wallet?

**No.** You don't need a wallet, a token, an ETH balance, or any crypto experience. The protocol uses Bitcoin only as a timestamp medium — you never see Bitcoin, never interact with it, never pay any fee. The "blockchain" part is invisible plumbing.

## What's the difference between this and C2PA Content Credentials?

[C2PA](https://c2pa.org) is the broader industry coalition (Adobe, Microsoft, Sony, BBC, Google, OpenAI, Reuters, etc.) for content provenance, mostly in images and video. It defines a manifest format for embedded provenance + edit history with signed assertions.

The Screenplay Registry is COMPLEMENTARY:
- **C2PA covers images / video / audio / PDFs** — first-class asset types.
- **Screenplay Registry covers screenplay text** — a first-class asset type C2PA hasn't claimed.

Long-term, we expect to emit a C2PA sidecar from registrations so screenplays in PDF form can carry both kinds of provenance. v1 doesn't ship that (it was descoped per design review); v2+ may.

## What if a vendor wants to mint an on-chain certificate for an registration?

The Screenplay Registry itself does NOT ship any on-chain attestation code — that's intentional. The legal/registry weight of a registration lives entirely in the local manifest + Bitcoin OpenTimestamps anchor. Downstream vendors (writing apps, web tools, foundations) MAY ship their own NFTs or attestations that wrap a registration for public display purposes, but those are vendor products, not part of the protocol.

A recommended vendor-attestation shape is on the roadmap (post-v1). Until then, any vendor attestation that includes the registration's `claimHash` + a pointer to the `.ots` proof is interoperable with the verifier — readers will use the registration's own commitment, not the vendor's wrapper, for ground truth.

## Can I compare two registered scripts for similarity?

**Yes, but only with both writers' consent.** The architecture is split into two layers:

- **Public claim** (always emitted): commits the Merkle roots + counts of your script's scene tree and paragraph tree. Reveals nothing about the actual content of any scene or paragraph.
- **Comparison disclosure bundle** (opt-in sidecar): contains the per-scene + per-paragraph content hashes + word counts. Generated locally when you register, kept private by default. You publish it ONLY when you want to enable comparison.

Workflow:

```bash
# 1. You decide to enable comparison for your own script. The CLI prints the
#    irrevocability warning FIRST and prompts for "I UNDERSTAND" — nothing is
#    written until you confirm. Add --yes-i-understand to skip the prompt in
#    scripts. Input may be the screenplay, the manifest, or the private bundle.
screenreg disclose-comparison my-screenplay.fountain
# → after confirmation: writes my-screenplay.fountain.comparison-bundle.json

# 2. The other writer does the same with their script.

# 3. Anyone with both bundles runs:
screenreg similarity mine.comparison-bundle.json theirs.comparison-bundle.json
# → reports set Jaccard + multiset Jaccard + longest-common-run + longest-common-subsequence
#   + coverage-by-words for paragraph layer (typically the most legible number for a court).
#
# Add --envelope-a / --envelope-b to additionally verify each bundle's external
# binding (that its tree roots match the on-chain claim) — recommended when a
# bundle comes from a third party.
```

If either writer never runs `disclose-comparison`, no comparison is possible. This is by design — see the next question.

## Doesn't publishing my registration let anyone test "do you have this scene?" against my script?

**No — that's exactly the attack the bundle architecture exists to prevent.**

The original draft of the spec put `sceneContentHashes` + `paragraphContentHashes` directly in the public claim. A reviewer caught it pre-launch: that would have turned every registered script into a fingerprint-queryable database. Anyone holding a hash could test it against the entire corpus without the writer's consent (the "membership oracle attack").

The fix: per-leaf hashes were moved out of the claim and into the opt-in comparison disclosure bundle. The claim now commits only the Merkle ROOT — sufficient for tamper-evidence + selective single-scene disclosure proofs (Section 03), but not for fingerprint-style membership queries.

If you never run `disclose-comparison`, no one can ask "does your script contain this scene?" against your registration. They can ask "does this exact normalized byte sequence match your registered script?" (the verify command) — but that requires them to already possess the bytes, so it's not a fishing query.

## Irrevocability — what does that mean for my comparison bundle?

Once you publish a bundle, anyone in the world can compare any future bundle against yours, forever. You CANNOT unpublish. The CLI prints an explicit warning before `disclose-comparison` writes a public-path file.

Publish only when comparison is the actual goal (you're alleging or defending against an idea-theft claim, you're proving a draft lineage, etc.). If you only want a registration for "I had it on this date," skip the disclosure step entirely — the registration is fully valid without it.

## How do I contribute?

See [`CONTRIBUTING.md`](../CONTRIBUTING.md). All contributions are accepted under the Developer Certificate of Origin (DCO) — sign your commits with `git commit -s`. License is MIT for code, CC-BY 4.0 for spec, and CC0 for test vectors.

## Who is behind this?

The Screenplay Registry is an open standard maintained by initial contributors. The spec, the commitment-bearing URN namespace, and the verification semantics are intentionally designed to outlive any single steward. As external integrators adopt the protocol, governance will transition to a stewards council with rotating chair (Phase 2 of the governance roadmap in the README).

The point is: the PROTOCOL is the thing. Anyone can build on it. Existing proofs verify forever via the OpenTimestamps Bitcoin anchor regardless of who maintains the reference implementation.
