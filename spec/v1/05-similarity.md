# Screenplay Registry Protocol v1.0
## Section 05 — Similarity Commitment Layer (Merkle roots in `committedClaim`)

**Status**: COMMITMENT-BEARING. The `sceneTreeRoot` + `sceneCount` + `paragraphTreeRoot` + `paragraphCount` fields are part of `committedClaim` whenever the optional scene tree and/or paragraph tree is present. Once registered, the values are locked.

**Important**: this section defines only what the public claim COMMITS. The per-scene + per-paragraph content hashes used for similarity comparison are NOT in the committed claim — they live in an OPT-IN comparison disclosure bundle defined in [Section 06](./06-comparison-bundle.md).

---

### 1. Purpose

Enable two registrations to be compared for **exact scene-content reuse** — but only when both registrants CONSENT to comparison. The architecture is split into:

- **Commitment (this section)**: the claim commits the Merkle roots + counts of the scene tree and paragraph tree. Public. Immutable. Reveals nothing about scene content.
- **Disclosure (Section 06)**: the registrant CHOOSES to publish a comparison bundle containing the per-leaf hashes + word counts. Opt-in. Irrevocable once published. Required for similarity scoring.

Properties of the resulting similarity workflow:
- **Cryptographically verifiable** — anyone with both bundles can compute the score independently and arrive at the same answer
- **Consent-bound** — comparison requires both registrants to publish bundles. Neither party can be compared against without their participation.
- **Position-independent (set/multiset layers)** — moving a scene between drafts does NOT drop the similarity score
- **Order-sensitive (sequence layer)** — verbatim-block copying surfaces in longest-common-run / longest-common-subsequence metrics
- **Honest** — the score measures EXACT byte reuse after normalization, NOT narrative or semantic similarity

The use cases:
- **Draft revision tracking**: "v3 of my script is 91% the same as v1 — only 4 scenes changed."
- **AI-training defense**: "this AI-generated screenplay shares 67% of its paragraph hashes with my registered work."
- **Idea-theft / lookalike claims**: "the released movie contains 84% of the scenes I registered 18 months earlier — here is the cryptographic proof."
- **Cross-tool re-registration**: "I exported from Final Draft in 2026 and from Highland in 2027 — even though byte hashes differ, my paragraph tree overlaps 96%."

### 2. Committed fields

When `committedClaim.sceneTreeProfile` is present, the claim MUST also contain `sceneTreeRoot` and `sceneCount`:

```jsonc
"committedClaim": {
  ...
  "sceneTreeProfile": "screenplay-registration-merkle/v1",
  "sceneTreeRoot":    "sha256:abc...",
  "sceneCount":       47
  // NOTE: sceneContentHashes is NOT here — see Section 06.
}
```

When `committedClaim.paragraphTreeProfile` is present, the claim MUST also contain `paragraphTreeRoot` and `paragraphCount`:

```jsonc
"committedClaim": {
  ...
  "paragraphTreeProfile": "screenplay-registration-paragraph-merkle/v1",
  "paragraphTreeRoot":    "sha256:def...",
  "paragraphCount":       312
  // NOTE: paragraphContentHashes is NOT here — see Section 06.
}
```

Either tree (or both, or neither) may be present. The paragraph tree is robust to global rename + adversarial scene-heading edits — only paragraphs containing the renamed term change.

#### 2.1 What the roots commit

The Merkle root is computed per the position-bound, domain-separated construction in [Section 03](./03-scene-tree.md) (scenes) and Section 03's analogous paragraph tree (domain tags `0x10` / `0x11` / `0x12`).

The root is sufficient to:
- Detect any post-registration tampering of the scene or paragraph sequence
- Support **selective-disclosure proofs**: reveal one leaf + Merkle path, prove inclusion without revealing siblings (Section 03 §4)

The root is NOT sufficient to:
- Enable cross-claim similarity comparison — that requires the leaves, which only the disclosure bundle exposes (Section 06)

### 3. Similarity computation: see Section 06

All comparison metrics — set Jaccard, multiset Jaccard, longest common run, longest common subsequence, coverage-by-words — operate on `ComparisonBundle` objects, NOT directly on `committedClaim` objects. See [Section 06 §4](./06-comparison-bundle.md) for the formulas and reporting obligations.

A `committedClaim` alone is not enough to compute similarity. Both registrants must publish bundles for any cross-claim comparison to be possible. This is a deliberate consent boundary.

### 4. Verifier obligations (for the commitment layer)

A claim verifier MUST:

1. Confirm `sceneTreeProfile` is the exact locked constant when present
2. Confirm `sceneTreeRoot` matches the format `sha256:<64-lowercase-hex>`
3. Confirm `sceneCount` is a non-negative integer matching the tree's leaf count
4. Apply the analogous rules to `paragraphTree*` when present
5. Reject any claim that has a partial scene-tree triple (e.g. root without profile)

A claim verifier MUST NOT:

- Compute similarity from a claim alone (use bundles per Section 06)
- Treat absence of the scene tree or paragraph tree as a soft error — registrations without trees CANNOT be similarity-compared, and the verifier must say so
- Claim that the score measures narrative, plot, or character similarity

### 5. Threat model

#### 5.1 Membership oracle (resolved in v1)

**Original design flaw, caught during pre-launch review**: publishing `sceneContentHashes` and `paragraphContentHashes` directly in the public claim would have turned every registration into a fingerprint-queryable database. An adversary holding a single scene hash could test "does any registered script contain THIS scene?" against the entire corpus without the writer's consent.

**Mitigation**: per-leaf hashes are removed from the committed claim. They live only in opt-in comparison disclosure bundles (Section 06) that the writer publishes ONLY when they choose to compare against another registrant. The claim commits only the Merkle root, which leaks `sceneCount` and `paragraphCount` (both already disclosed) but no per-leaf signal.

#### 5.2 Adversarial dilution

An attacker registers a "diluted" script containing the target's scenes plus many trivial added scenes, hoping to make the set-Jaccard score against the target look low (because the union grows).

**Mitigation (Section 06)**: the report MUST include coverage values + multiset + sequence metrics alongside Jaccard. If A has 5 scenes and B has 100 scenes that include all 5 of A's, set-Jaccard is 5% but A's coverage in B is 100% — the asymmetry exposes the attack. Likewise, longest-common-run catches "I copied the whole third act and added unrelated padding."

#### 5.3 Adversarial modification

An attacker changes one byte per scene (e.g., adds a trailing space, swaps one character), defeating exact-content matching while preserving narrative similarity.

**Mitigation**: this is NOT what similarity scoring detects. Document explicitly: "exact scene-content match after normalization." If you suspect "obfuscated plagiarism," similarity scoring is the wrong tool. (v2 may add MinHash / LSH for fuzzy similarity.)

#### 5.4 Replay / impersonation

A third party cannot "claim" another writer's content hashes because:

- The hashes are deterministically computable from the script (anyone with the script can recompute)
- The REGISTRATION binds the Merkle root to the registrant's Bitcoin timestamp via OpenTimestamps
- A stolen bundle still points back to the original registration's manifest + anchor, not the impersonator's
- The optional `registrant` block (Section 06) binds an Ed25519 signature over the claim body, providing per-registration identity attestation

### 6. Backward compatibility

This section's contract changed BEFORE v1 launch (the field moved from `committedClaim` to an opt-in bundle in Section 06). No pre-launch registrations exist on Bitcoin yet, so the migration is purely a spec edit — no compatibility shim is required.

If a future point release re-introduces per-leaf material into the claim, it MUST do so behind an explicit opt-in field with a separate URN, NOT silently.

### 7. Future work (NOT in v1)

Out of scope for v1:

- **MinHash / LSH**: approximate / fuzzy similarity for cross-tool comparisons where bytes differ but content is "the same"
- **Sentence-level commitment trees**: finer-grained robustness to local edits
- **Semantic similarity**: comparing meaning, not bytes (would require LLMs and is out of scope for this protocol entirely)
- **Lossy normalization profiles**: `screenplay-registration-norm/v2-fountain` for cosmetic-difference-tolerant comparisons
- **Partial bundles**: reveal SOME leaves with Merkle proofs (e.g. "scenes 3, 5, 17 only") for surgical disclosure. v1 bundles reveal ALL leaves. See Section 06 §7.

All of these are additive: they can ship in v2+ without invalidating any v1 commitments.

### 8. Compliance statement

An implementation claims compliance with this section if and only if:

1. When generating a registration with a scene tree, it commits `sceneTreeProfile` + `sceneTreeRoot` + `sceneCount` and OMITS `sceneContentHashes` from the claim
2. When generating a registration with a paragraph tree, it commits `paragraphTreeProfile` + `paragraphTreeRoot` + `paragraphCount` and OMITS `paragraphContentHashes` from the claim
3. When the user requests similarity comparison, it directs them to generate a comparison disclosure bundle per Section 06 — it does NOT compute similarity from claims alone
4. It does NOT claim the score (when computed against bundles) measures narrative, semantic, or legal similarity

### 9. Prior art

Similarity / plagiarism detection has a long history. Related work:

- **MOSS** (Measure of Software Similarity, Stanford) — winnowing + fingerprint matching for source code plagiarism. Closest in spirit to this design but operates on tokens, not pre-committed hashes.
- **JPlag** — structural plagiarism detection for code.
- **Turnitin** — commercial document fingerprint matching against a corpus.
- **simhash / MinHash / LSH** — approximate similarity for near-duplicates (Google web pages, Stack Overflow questions).
- **Certificate Transparency** — uses Merkle trees for tamper-evidence, similar shape but different purpose (inclusion proofs, not similarity).
- **DKIM / public-key crypto opt-in disclosure** — the consent-bound disclosure pattern echoes how DKIM separates the always-public domain signature from the opt-in body-hash check.

What is novel about this design:

- **Two-tier visibility**: the commitment is public + universal; the comparison surface is private + opt-in. Standard plagiarism tools collapse these into one always-public fingerprint database.
- **Pre-committed Merkle roots**: the comparison surface is cryptographically tied to a specific Bitcoin-anchored registration. A bundle cannot be retroactively forged.
- **Permissionless**: no third-party comparison service required. Two registrants can compare directly with no intermediary.

---

**End of Section 05.**
