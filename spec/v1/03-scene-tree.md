# Screenplay Registry Protocol v1.0
## Section 03 — Scene-Level Merkle Tree (`screenplay-registration-merkle/v1`)

**Profile identifier**: `screenplay-registration-merkle/v1`
**Status**: COMMITMENT-BEARING. The profile identifier is embedded in `committedClaim.sceneTreeProfile` when the optional scene tree is present, and is therefore hashed into the on-chain commitment. The rules defined in this document MUST NEVER change.

---

### 1. Purpose

Enable selective disclosure: prove that a specific scene was part of a registered screenplay
WITHOUT revealing the contents of any other scene. The scene tree is OPTIONAL — if present, its
root is committed via `committedClaim.sceneTreeRoot`; if absent, the script is registered as an
opaque blob via `contentHash` only.

### 2. Scene detection

Scenes are detected in the NORMALIZED bytes (output of Section 01) by scanning for scene
headings on lines that begin with one of these prefixes (case-insensitive on the prefix only):

- `INT.`
- `INT/EXT.`
- `EXT.`
- `EST.`
- `I/E.`
- `E/I.`

A scene heading line matches if it starts at byte position 0 OR follows a `LF` (`0x0A`), and the
prefix appears at the start of the line.

A scene runs from the byte position of its scene heading line (inclusive) up to but excluding
the byte position of the NEXT scene heading line, OR to end-of-file if no further heading exists.

**Pre-amble content** (any bytes before the first scene heading — title pages, notes, etc.) is
NOT a scene leaf in v1. It contributes to the whole-script `contentHash` via Section 01 but is
not selectively disclosable in v1. Future profiles (`screenplay-registration-merkle/v2`) MAY add a
"preamble" leaf type; v1 does not.

**Edge cases**:
- A file with NO scene headings has zero scenes. The tree is empty (root = `SHA-256(0x02)` per §3.4).
  Implementations MAY omit the scene tree entirely in this case.
- A file with ONE scene has ONE leaf and the leaf IS the root: `depth = 0`, `paddedLeafCount = 1`,
  no parent computation, no padding. The Merkle root equals `leafHash(scene_0)`. Selective-disclosure
  proofs for `sceneCount == 1` carry zero sibling hashes (`siblingHashes.length === 0`); the verifier's
  expected depth is also 0. The single-scene corpus vector at
  `spec/v1/testvectors/scene-tree/002-single-scene-int/` locks this semantic.
- `INT.MOON` (no space after the dot) does NOT match — the prefix MUST be followed by a space
  or hyphen or end-of-line.

### 3. Leaf and tree construction

#### 3.1. Per-scene leaf hash (two-stage chain with domain separation)

The leaf hash is computed in TWO stages. First the position-INDEPENDENT content hash:

```
contentHash := SHA-256(
    UTF-8("screenplay-registration-scene-content/v1")    // profile bytes
 || sceneBytes                                            // variable
)
```

Then the position-BOUND leaf hash, which incorporates the content hash:

```
leafHash := SHA-256(
    0x00                                              // domain tag: leaf
 || UTF-8("screenplay-registration-merkle/v1")        // tree profile bytes
 || uint32_BE(sceneIndex)                             // 4 bytes
 || uint64_BE(byteStart)                              // 8 bytes
 || uint64_BE(byteEnd)                                // 8 bytes
 || contentHash                                       // 32 bytes (NOT raw sceneBytes)
)
```

The two-stage chain (`bytes → contentHash → leafHash → ... → root`) is load-bearing for
comparison-bundle binding (Section 06): a verifier given `(sceneIndex, byteStart, byteEnd,
contentHash)` can recompute `leafHash` WITHOUT access to `sceneBytes` and confirm it reduces
to the committed root. This means an opt-in comparison disclosure bundle's
`sceneContentHashes` are cryptographically bound to the on-chain commitment via the leaf
preimage, even though the bundle does not expose `sceneBytes`.

The domain tag `0x00` distinguishes leaves from internal nodes. Combined with the tree profile
identifier + scene metadata + content hash (itself domain-separated by
`"screenplay-registration-scene-content/v1"`), this prevents the second-preimage attack where
an adversary constructs a candidate "scene" whose hash equals the hash of two real scenes'
parent node, AND prevents cross-layer hash reuse (a scene content hash can never collide with
a paragraph content hash or a Merkle leaf hash).

Selective-disclosure proof verification (Section 03 §4) reveals `sceneBytes`, recomputes
`contentHash`, then `leafHash`, then walks the Merkle path to root — all steps deterministic
from the revealed scene.

#### 3.2. Parent hash (with domain separation)

```
parentHash := SHA-256(
    0x01                                           // domain tag: parent
 || leftChildHash                                  // 32 bytes
 || rightChildHash                                 // 32 bytes
)
```

#### 3.3. Tree shape

The tree is a complete binary tree, leaves sorted by `sceneIndex` (ascending). If the leaf
count `n` is not a power of 2, leaves are padded to the next power of 2 using the padding
sentinel below (§3.4).

The root is built bottom-up by pairing adjacent leaves and recursively hashing parents until
a single root remains.

#### 3.4. Padding sentinel

For any padding slot (when `n` < next power of 2):

```
paddingHash := SHA-256(0x02)
            = 0xdbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986
```

The padding sentinel has its own domain tag (`0x02`), distinguishing it from both leaves
and parents. It is a precomputed constant: implementations MAY hardcode it for performance.

#### 3.5. sceneCount commits the tree size

`committedClaim.sceneCount` records the NUMBER OF REAL SCENES detected (i.e. the unpadded
leaf count). This is commitment-bearing per Section 02. It prevents a class of attack where
an adversary provides a smaller tree and claims fewer scenes existed than were actually
registered.

A verifier checking a selective-disclosure proof MUST:
1. Reconstruct the expected tree dimensions from `sceneCount` (calculate next power of 2).
2. Verify the proof's sibling-hash path is exactly that depth.
3. Reject proofs whose dimensions do not match the committed `sceneCount`.

#### 3.6. Paragraph tree variant (`screenplay-registration-paragraph-merkle/v1`)

A second Merkle tree commits the document's paragraph structure (Section 05 §2). The construction is byte-for-byte parallel to the scene tree above with three substitutions:

| Construct | Scene tree | Paragraph tree |
|---|---|---|
| Tree profile | `screenplay-registration-merkle/v1` | `screenplay-registration-paragraph-merkle/v1` |
| Content profile | `screenplay-registration-scene-content/v1` | `screenplay-registration-paragraph-content/v1` |
| Leaf domain tag | `0x00` | `0x10` |
| Parent domain tag | `0x01` | `0x11` |
| Padding domain tag | `0x02` | `0x12` |
| Count field | `sceneCount` | `paragraphCount` |

Disjoint domain tags + disjoint profile strings ensure a scene-tree leaf can NEVER collide with a paragraph-tree leaf (or parent, or padding), even when the underlying bytes happen to overlap. This is the structural defense against cross-tree second-preimage substitution.

Per-paragraph leaf hash:

```
contentHash := SHA-256(
    UTF-8("screenplay-registration-paragraph-content/v1")
 || paragraphBytes
)

leafHash := SHA-256(
    0x10
 || UTF-8("screenplay-registration-paragraph-merkle/v1")
 || uint32_BE(paragraphIndex)
 || uint64_BE(byteStart)
 || uint64_BE(byteEnd)
 || contentHash
)
```

Paragraph parent + padding hashes follow the same domain-separation pattern (`SHA-256(0x11 || left || right)` and `SHA-256(0x12)` respectively). The same tree shape rules (§3.3) and `paragraphCount` size commitment (§3.5 applied to `paragraphCount`) apply.

Paragraph boundaries are defined as maximal runs of non-blank lines, delimited by one or more blank lines (where a blank line is a single `\n` after normalization). Leading and trailing blank lines in the file are skipped. The definition derives only from blank-line structure, not from Fountain semantic elements, so it works on any normalized text screenplay input.

### 4. Selective-disclosure proof format

To prove that scene `i` was part of a registered tree with root `R` and committed `sceneCount`:

```jsonc
{
  "sceneTreeProfile": "screenplay-registration-merkle/v1",
  "sceneCount": 47,
  "sceneIndex": 32,
  "byteRange": { "start": 12345, "end": 18900 },
  "sceneBytes": "<base64 of normalized scene bytes>",
  "siblingHashes": [
    "sha256:...",       // sibling at level 0 (sibling of the leaf)
    "sha256:...",       // sibling at level 1
    "..."               // up to ceil(log2(nextPow2(sceneCount))) entries
  ]
}
```

To verify:

1. Decode `sceneBytes` from base64.
2. Recompute the leaf hash per §3.1 using the proof's `sceneTreeProfile`, `sceneIndex`,
   `byteRange`, and decoded `sceneBytes`.
3. Walk up the tree using `siblingHashes`. At each level:
   - If the current node's index at that level is even, pair as `parent = SHA-256(0x01 || self || sibling)`.
   - If odd, pair as `parent = SHA-256(0x01 || sibling || self)`.
4. After all siblings are consumed, the accumulator MUST equal the committed `sceneTreeRoot`.
5. The depth of the proof (number of sibling hashes) MUST equal `ceil(log2(nextPow2(sceneCount)))`.
   Mismatches indicate truncation or extension attacks.

### 5. Threat model

This Merkle construction defends against:

- **Second-preimage attack**: Without domain separation, an adversary could construct an
  artificial "scene" whose `SHA-256(sceneBytes) == SHA-256(left || right)` of two legitimate
  scenes, forging a path through the tree. With `0x00`/`0x01`/`0x02` domain tags, the input
  spaces are disjoint and no collision can promote a leaf-shaped value to a parent-shaped one
  (or vice versa).
- **Truncation attack**: Without committing `sceneCount`, an attacker could claim a smaller
  tree than registered (e.g. dropping the last scene). The committed count detects this.
- **Reorder attack**: Without binding `sceneIndex` into the leaf, an attacker could swap two
  scenes' positions. Including `sceneIndex` in the leaf preimage prevents this.
- **Byte-range substitution**: Without binding `byteRange`, an attacker could present the
  same `sceneBytes` as a different scene. Including `byteStart`/`byteEnd` prevents this.

This Merkle construction does NOT defend against (these are by design):
- An owner who registers a SECOND tree with reordered scenes after the fact — that's a new
  registration with a new commitment.
- Selective non-disclosure: the protocol permits proving inclusion but not non-inclusion.

### 6. Compliance statement

An implementation claims compliance with `screenplay-registration-merkle/v1` if and only if:

1. It detects scenes per §2 byte-identically with the test corpus.
2. It computes leaf hashes per §3.1 with the exact byte layout described.
3. It computes parent hashes per §3.2 with `0x01` domain tag.
4. It pads with the `0x02`-sentinel per §3.4.
5. It rejects selective-disclosure proofs that fail any of the verification steps in §4.

---

**End of Section 03.**

References:
- [Certificate Transparency RFC 6962 §2.1](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1) — the canonical reference for domain-separated Merkle trees on the internet
