# Screenplay Registry Protocol v1.0
## Section 11 — `.screenreg` container (`urn:screenplay-registration-bundle:v1`)

**Container profile identifier**: `urn:screenplay-registration-bundle:v1`

**Tier**: packaging / convenience. This section defines a single-file ON-DISK PACKAGING
FORMAT that bundles the artifacts a registration already produces into one file. **Nothing in
this section is commitment-bearing.** No field defined here is hashed into `claimHash`, the
container bytes are never themselves a commitment, and wrapping (or unwrapping) an envelope
in a `.screenreg` cannot change the bytes of any existing v1 artifact. A verifier that ignores
this section entirely — operating on the loose `envelope` + `.ots` files — reaches an identical
verdict. The container is a delivery vehicle, not a protocol surface.

---

### 1. Purpose

A registration produces three loose artifacts today: the envelope (`*.manifest.json`), the
OpenTimestamps proof (`*.proof.ots`), and — optionally — an identity key. Asking a writer to
keep track of, and a verifier to re-supply, several files is the dominant source of friction.

The `.screenreg` container collapses these into **one human-handleable file** in two clearly
distinguished variants:

- **`<name>.screenreg`** — the **full** bundle. Self-contained: it embeds the screenplay text
  that was hashed, so the holder can verify *and open* the commitment (prove the bytes) from
  this one file, forever, with no other input. This is the writer's archival copy. *Keep it.*
- **`<name>.evidence.screenreg`** — the **evidence** bundle. Proof-only: the envelope and the
  timestamp proof, **with no screenplay text**. It verifies that *a document with a given
  fingerprint existed by a given date* (and, if signed, by whom) while revealing nothing about
  the content. *Safe to hand to anyone.*

The two variants differ by exactly one thing: whether the source text is present. Everything
else is identical. The container is forward-compatible by construction (§6): readers resolve
entries by ROLE and ignore unknown entries, so future evidence types (additional anchors,
registry records) ride along without a format break.

### 2. Physical format

A `.screenreg` file is a **ZIP archive** using the **store method only** (compression method
`0`, no DEFLATE). Store-only is mandatory for three reasons:

1. **Determinism.** DEFLATE output is not byte-identical across implementations (Node `zlib`
   vs. the browser `CompressionStream`); store-only is byte-deterministic, so the same inputs
   produce the same `.screenreg` on every runtime.
2. **Inspectability.** Any `unzip`, Finder, or Explorer opens it; the contents are plain files.
3. **Sufficiency.** A screenplay as text is ~150–300 KB; compression buys nothing meaningful.

To make the archive reproducible, a producer MUST:

- emit entries in a fixed canonical order (§3, descriptor first, README last);
- set every entry's modification time to `0` and date to the fixed DOS epoch `1980-01-01`
  (date field `0x0021`); a constant timestamp is what makes the output reproducible, and a valid
  date avoids the warnings some tools emit for an all-zero date;
- use version-needed-to-extract `20`, general-purpose bit flag `0`, and no extra fields;
- write standard local-file-header + central-directory + end-of-central-directory records with
  a correct CRC-32 per entry (CRC-32 is the standard ZIP IEEE polynomial; it is an integrity
  check, not a cryptographic function, and carries no security weight here).

A reader MUST accept any well-formed ZIP for forward tolerance, but the reference reader only
needs to inflate store entries; an entry whose method is not `0` MAY be rejected by a v1 reader.

### 3. Logical layout

Canonical entry order within the archive:

```
<name>.screenreg            (full bundle)        |  <name>.evidence.screenreg  (evidence bundle)
├── screenreg.json          container descriptor ├── screenreg.json
├── envelope.json           the v1 envelope      ├── envelope.json
├── proof.ots               OpenTimestamps proof ├── proof.ots
├── script.fountain         the hashed text      │   (no source text)
└── README.txt              human guide          └── README.txt
```

| Entry           | Role          | Full | Evidence | Notes |
|-----------------|---------------|:----:|:--------:|-------|
| `screenreg.json`| `descriptor`  |  ✓   |    ✓     | Container manifest (§4). Always first. |
| `envelope.json` | `envelope`    |  ✓   |    ✓     | Byte-faithful v1 envelope (Section 02), except the OTS `proofRef` is rewritten to the in-archive proof name (`proofRef` lives in the unhashed `evidenceBundle`, so `claimHash` is invariant). |
| `proof.ots`     | `ots-proof`   |  ✓   |    ✓     | The OpenTimestamps proof bytes. Absent only if the envelope carries no OTS proof. |
| `script.fountain`| `source-text`|  ✓   |    ✗     | The exact text whose normalized form was hashed to `contentHash`. **Defines the variant**: present ⇒ full, absent ⇒ evidence. |
| `README.txt`    | `readme`      |  ✓   |    ✓     | Plain-English description; ignored by readers. Always last. |
| *(future)*      | *(new roles)* |  —   |    —     | e.g. `eth-anchor`, `registry-record`, `source-pdf`. Additive (§6). |

The source text is stored under the role name `source-text` regardless of the writer's original
filename. It is named `script.fountain` for the common case; the descriptor's role map (§4) is
authoritative, not the filename.

### 4. Container descriptor (`screenreg.json`)

```jsonc
{
  "format": "urn:screenplay-registration-bundle:v1",
  "bundleType": "full",                  // "full" | "evidence"
  "contents": {                          // role → in-archive path (present roles only)
    "descriptor": "screenreg.json",
    "envelope": "envelope.json",
    "otsProof": "proof.ots",
    "sourceText": "script.fountain"      // omitted in an evidence bundle
  },
  "entries": [                           // every non-descriptor entry, sorted by path (code-unit order)
    { "path": "README.txt",      "role": "readme",      "bytes": 980,    "sha256": "<hex>" },
    { "path": "envelope.json",   "role": "envelope",    "bytes": 1234,   "sha256": "<hex>" },
    { "path": "proof.ots",       "role": "ots-proof",   "bytes": 412,    "sha256": "<hex>" },
    { "path": "script.fountain", "role": "source-text", "bytes": 158022, "sha256": "<hex>" }
  ]
}
```

`entries[].sha256` is a per-file checksum manifest for **corruption detection**, not a security
claim — the descriptor is unsigned. The cryptographic chain of trust runs entirely through
`envelope.json` → `contentHash`/`claimHash` → the OTS proof, exactly as for the loose files.
The descriptor is written with stable key order and `entries` sorted by `path` in code-unit
order (not locale-aware, which would vary by environment), so it is byte-deterministic.
`bundleType` MUST agree with the presence of the `source-text` role: a `full` bundle declares a
`sourceText`, an `evidence` bundle does not. Every path named in `contents` other than the
descriptor itself MUST appear in `entries` (so it is digest-checked); a reader rejects a
descriptor that points at content it does not also list. Combined with the per-entry digest
check (§5), this means a `full` bundle that fails to actually carry its source text cannot read
as intact.

### 5. Verification

Given a `.screenreg`, a verifier:

1. Reads `screenreg.json`; confirms `format` is recognized and `entries[].sha256` match (else
   the archive is corrupt).
2. Loads `envelope.json` and validates it against Section 02 (`validateEnvelope`).
3. Resolves the OTS proof by the `otsProof` role and verifies it against `committedClaimHash`
   per the OpenTimestamps verification path (existence + time). **This step needs no text.**
4. **If a `source-text` entry is present (full bundle):** normalizes it under
   `screenplay-registration-norm/v1-strict`, hashes it, and confirms it equals the envelope's
   `contentHash` — *opening* the commitment (proving the bytes). An evidence bundle stops at
   step 3 and reports "existence + time verified; source not included."

This mirrors the two-question model: steps 1–3 answer *"did this fingerprint exist by date T?"*
(verifiable from an evidence bundle alone, reveals nothing); step 4 answers *"is that
fingerprint this script?"* and is only possible — and only necessary — when the writer chooses
to include or reveal the text.

### 6. Forward compatibility

- **Resolve by role, not filename.** Readers use `contents`/`entries[].role`; filenames are
  cosmetic. A reader encountering an unknown `role` MUST ignore that entry, not fail.
- **Additive evidence.** New witnesses (an `ethereum-anchor` proof per Section 09, a registry
  record per Section 10, a future ZK proof) attach inside `envelope.json`'s `evidenceBundle`
  — which is never hashed — and/or as new container entries with new roles. A v1 `.screenreg`
  can gain such evidence later and still verify its original Bitcoin proof, because `claimHash`
  is fixed at registration and the additions sit in unhashed surfaces.
- **No speculative slots.** A bundle carries only the roles present at creation. The format is
  open; the contents are minimal.

### 7. Source provenance (optional, in the unhashed evidence bundle)

When the source text was extracted from another format (e.g. a PDF), the *extracted text* — not
the source bytes — is what is hashed (see Section 08). To make the extraction auditable without
making it commitment-bearing, a producer MAY record extraction provenance under
`evidenceBundle.bundleExtensions.sourceProvenance`:

```jsonc
"sourceProvenance": {
  "sourceFormat": "pdf",
  "sourceDigest": "sha256:<hex of the original file>",      // optional breadcrumb
  "extractor": {
    "name": "screenreg-pdf-extractor",
    "version": "1.0.0",
    "commit": "<git commit hash>",                          // exact, immutable pin
    "artifactSha256": "sha256:<hex of the extractor source/bundle>"  // self-verifying pin
  }
}
```

This block is **not hashed** (it lives in `bundleExtensions`) and is **not** required for
verification — steps 1–4 of §5 never run an extractor. It exists so that an auditor who doubts
the *faithfulness* of the extraction can fetch exactly that extractor and re-run it against the
original file to confirm it reproduces the embedded `source-text`. The proof of existence and
time stands without it.

### 8. Identity keys

A private identity key (`*.private-key.pem`) is **never** placed in a `.screenreg`. Bundling a
secret with a file meant to be shared is a footgun. The optional Ed25519 *public* key and
signature already live inside `committedClaim.registrant`; that is sufficient for a verifier to
confirm who signed the claim. Private keys remain a separate, writer-held artifact.
