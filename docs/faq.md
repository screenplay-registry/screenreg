# FAQ

---

## How do I actually register a screenplay?

Two options, equivalent in evidentiary weight:

**Browser (recommended for one-off registrations).** Drag your screenplay — a `.pdf`, `.fountain`, or plain text — into [screenplayregistry.org/create/](https://screenplayregistry.org/create/). The page reads and hashes it locally and gives back a single `.screenreg` file (plus a shareable proof-only version). No account, no install, no upload.

**CLI (for batch / scripted use).** Install once (`git clone` + `npm install`), then run `./bin/screenreg.mjs register draft.fountain`. One `draft.screenreg` appears next to the script — your screenplay and the proof in a single file. (Add `--loose` if you'd rather have the separate `manifest.json` + `.ots`.) It is not published to npm yet; the examples below abbreviate `./bin/screenreg.mjs` as `screenreg`, so alias it in your clone if you like.

Verification is the same in either path and takes one file: drag-drop the `.screenreg` at [screenplayregistry.org/verify/](https://screenplayregistry.org/verify/), or run `screenreg verify draft.screenreg`. (A proof-only `.evidence.screenreg` verifies the date; add the screenplay — `screenreg verify draft.evidence.screenreg draft.fountain` — to also confirm the contents. The loose 3-file form `screenreg verify <file> <manifest> <ots>` still works for integrators.)

---

## I have a PDF, not a Fountain file. Can I register that?

Yes, in v0.2 the CLI can extract a PDF to Fountain text:

```bash
screenreg extract draft.pdf > draft.fountain   # extracts FD-convention text PDFs
# REVIEW draft.fountain — the extractor is heuristic and can mis-classify
# edge cases like dual dialogue side-by-side or unusual layouts. Edit as needed.
screenreg register draft.fountain --source-pdf draft.pdf
```

`--source-pdf` records the source-PDF SHA-256 + the extracted-Fountain SHA-256 + the extractor's name and version in `evidenceBundle.bundleExtensions.sourceExtractor`. An archival verifier can re-run that same extractor on the asserted PDF and confirm it reproduces the registered Fountain — a reproducibility check that links the PDF to the registered text.

The browser `/create/` page detects PDF drops and surfaces the CLI command. Browser-native PDF extraction is on the roadmap; it needs a browser-compatible PDF parser that won't bloat the page beyond the privacy-first design goals.

PDFs the reference extractor cannot handle (scanned image-only, password-encrypted, multi-column shooting drafts) reject with a typed exit code so you know which alternate path to take.

---

## Is this a substitute for the US Copyright Office?

**No.** The Copyright Office gives you federal-court statutory damages + attorney's fees in an infringement suit. This protocol gives you cryptographic evidence that complements that. For maximum protection, register with the Copyright Office AND create a protocol proof. See [`comparison.md`](comparison.md) for details.

## Is this a substitute for WGA registration?

**Not exactly.** WGA registration's main value is credit arbitration if your project gets made. The protocol does NOT carry that guild-internal weight. WGA is also faster (instant) and cheaper for members (~$10; ~$20-25 non-member), but expires every 5 years and uploads the file. Use WGA for credit arbitration; use this protocol for everything else.

## What does "Bitcoin-anchored" mean in plain English?

When you register, a 32-byte commitment — a nonce-blinded hash of your claim hash (the SHA-256 of your canonicalized claim), so the calendar never sees the claim hash itself — goes through a public OpenTimestamps "calendar" server. The calendar batches thousands of these commitments from different people into one cryptographic tree, and puts only the tree's root into a Bitcoin transaction. Bitcoin's distributed ledger then records that root permanently. Anyone with your `.ots` proof file can later check that your claim hash (via that blinded commitment) was part of the tree committed in that Bitcoin block — proving your claim existed by the block's timestamp.

You never see Bitcoin, and you never pay any fee. The calendar operators pay the Bitcoin transaction fee themselves as a public-good service (the per-fingerprint marginal cost is fractions of a cent).

## Doesn't Bitcoin use a lot of energy?

Yes. But the marginal energy cost of YOUR registration is essentially zero — the same Bitcoin transaction that anchors your registration also anchors thousands of other unrelated fingerprints. You're not commissioning a new transaction; you're sharing one that would happen anyway.

If you object to Bitcoin for environmental reasons, the protocol's `evidenceBundle` is extensible — an optional Ethereum-mainnet anchor (post-merge proof-of-stake, ~99% less energy) is specified as a secondary, additive witness. It is never a priority source — Bitcoin stays the sole time + priority anchor — and old v1 proofs remain valid; a new proof can carry both.

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

Then your proof loses its anchor — Bitcoin block headers wouldn't be verifiable. This is a multi-decade tail risk. By the time it's a realistic threat, the protocol will have additional parallel anchors (an optional Ethereum-mainnet anchor, Sigstore-style logs, etc.) — additive, not replacements, and never a priority source — so you can have a single registration that anchors to MULTIPLE chains. As long as ONE survives, the proof verifies.

## What can someone who has my proof actually see?

It depends which file you hand them — and that's exactly why there are two.

**The proof-only file (`.evidence.screenreg`)** — the one meant for sharing — reveals almost nothing about your script. Someone who holds it can see:

- two fingerprints (the content hash and the claim hash) — one-way SHA-256 hashes that cannot be reversed into your text;
- structural counts: how many scenes and how many paragraphs (e.g. "226 scenes"), plus the Merkle-tree *roots* (single hashes — not the per-scene contents);
- the date your fingerprint was timestamped (once it's Bitcoin-anchored);
- your AI-training preference, if you set one;
- a pseudonymous Ed25519 public key, if you chose to sign the registration (a key, not your name);
- a pointer to an earlier registration, if you filed this one as a revision.

It does **not** reveal your screenplay's text, title, or author. There is no plaintext title or author field anywhere in a registration — so a proof-only file is safe to post publicly or hand to a studio: it proves "a document with this fingerprint existed by this date," and nothing more.

**The full file (`.screenreg`)** — your private keep-copy — additionally embeds the screenplay text itself, so anyone you give it to can read the whole script. Keep this one; share only the `.evidence` version.

**Encrypted title/author:** if you turned on "keep the title and author private," those are stored as AES-256-GCM ciphertext. They are present in the file but unreadable without your password — verification never displays them (the field *names*, "title"/"author", are visible; the values are not).

**Can someone test "does your script contain this exact scene?" against a proof?** No — not from a proof alone. A registration commits only the tree *roots*, never the per-scene leaves, so there is nothing to query. That kind of comparison is possible only if you deliberately opt in by publishing a comparison bundle — see "Doesn't publishing my registration let anyone test…" below, and [the threat model](threat-model.md).

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

Verification will fail. The hash will differ. You should register a NEW version (which produces a new `.screenreg`). It's normal to have multiple registrations over a script's lifetime.

The `diagnose` mode will show you the transforms applied to the candidate file and the hash difference, but it cannot tell you EXACTLY which bytes changed — the protocol only stores the hash of the registered version, not the bytes.

## What if a court doesn't recognize cryptographic timestamps?

US courts have increasingly accepted blockchain timestamps as evidence (Vermont's blockchain rules, Federal Rules of Evidence Rule 902 self-authenticating data). Italy's Law 12/2019 gives blockchain timestamps eIDAS-equivalent legal effect. The EU's eIDAS 2 (effective Dec 2026) introduces Qualified Electronic Ledgers, and OTS-style Bitcoin anchoring is positioned to qualify.

This protocol's evidentiary value will continue to grow as adoption + legal precedent accumulate. For TODAY: pair with Copyright Office registration for the strongest legal posture.

## Why isn't there a hosted version?

There can be — any operator may offer a "hosted convenience tier" with extras like email notifications when proofs upgrade, bulk registration, mobile apps, a searchable registry listing (specified in [spec 10](../spec/v1/10-registry-index.md), not yet built), or the optional on-chain certificate (the secondary Ethereum-mainnet anchor specified in [spec 09](../spec/v1/09-onchain-anchor.md), not yet deployed). The PROTOCOL is always free and runnable yourself, and every one of those extras is optional and orthogonal to the free Bitcoin timestamp — none of them is a time or priority source, and none is required to verify a proof.

The deliberate choice to NOT have a single hosted version is what makes the protocol survive its operators — by design, you never need anyone's server to verify your proof.

## Is this a cryptocurrency thing? Do I need a wallet?

**No, not for the default free path.** You don't need a wallet, a token, an ETH balance, or any crypto experience to register and verify. The protocol uses Bitcoin only as a timestamp medium — you never see Bitcoin, never interact with it, never pay any fee. The "blockchain" part is invisible plumbing.

The one place crypto would become visible is the OPTIONAL on-chain certificate (a secondary Ethereum-mainnet anchor that is specified but not yet live). As designed it would be gasless: you sign an EIP-712 message and a relayer submits it and pays the gas, so you would never need to FUND a wallet. It is opt-in, would never be required, and would never affect the free Bitcoin timestamp.

## What's the difference between this and C2PA Content Credentials?

[C2PA](https://c2pa.org) is the broader industry coalition (Adobe, Microsoft, Sony, BBC, Google, OpenAI, Reuters, etc.) for content provenance, mostly in images and video. It defines a manifest format for embedded provenance + edit history with signed assertions.

The Screenplay Registry is COMPLEMENTARY:
- **C2PA covers images / video / audio / PDFs** — first-class asset types.
- **Screenplay Registry covers screenplay text** — a first-class asset type C2PA hasn't claimed.

Long-term, we expect to emit a C2PA sidecar from registrations so screenplays in PDF form can carry both kinds of provenance. v1 does not ship that; v2+ may.

## What about an optional on-chain certificate for a registration?

The core protocol does NOT require any on-chain code, and the free Bitcoin timestamp ships none. The time/priority weight of a registration lives entirely in the local manifest + Bitcoin OpenTimestamps anchor; nothing on-chain is needed to register or verify.

Separately, an OPTIONAL on-chain certificate is specified but not yet live: an Ethereum-mainnet `ScreenplayLedger` event recording the same opaque `claimHash`, plus an optional transferable product NFT. It is an opt-in, additive tier — the Solidity contracts are not yet deployed and require a security audit and legal review before any mainnet launch — designed so that it is:

- **never a priority or time source** — Bitcoin remains the sole time + priority anchor, and a missing, failed, or unreachable on-chain check never invalidates an otherwise Bitcoin-valid proof;
- **never part of the v1 commitment** — no on-chain field is hashed into `claimHash`, and the on-chain plaintext is user-chosen `title`/`name` labels only (the script fingerprint is never published);
- **content-neutral** — any abuse-control at the relayer is admission / rate-limit / fee / proof-of-work, never a content filter;
- **not an authorship proof and not a Copyright-Office replacement** — the product NFT confers no rights; transferring it moves a collectible, not rights.

Any on-chain or off-chain attestation that includes the registration's `claimHash` + a pointer to the `.ots` proof is interoperable with the verifier — readers use the registration's own commitment, not any wrapper, for ground truth.

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
# binding (that its tree roots match the committed claim) — recommended when a
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
