# Screenplay Registry Protocol v1.0
## Section 08 — PDF extraction (input tool, not a commitment surface)

**Tier**: input / convenience. This section defines how a PDF becomes the text that a
registration commits to. **Nothing in this section is commitment-bearing.** No PDF byte is ever
hashed, no extractor output is frozen by the protocol, and changing or replacing an extractor
cannot alter any existing v1 artifact. A verifier never runs an extractor.

---

### 1. The premise: PDF is a rendering of text, not the text

`screenplay-registration-norm/v1-strict` (Section 01) consumes UTF-8 text. A PDF is a rendering
layer over text — the same logical screenplay can be encoded countless ways (font subsetting,
embedded resources, xref reordering, many permitted text encodings), so canonicalizing PDF bytes
is intractable and pointless. The protocol therefore treats a PDF as **just another input
source** that is converted to text by an extractor. **The extracted text is what gets normalized,
hashed into `contentHash`, and embedded in the `.screenreg`** (Section 11). The PDF itself is
never the committed artifact.

### 2. Extraction is a pluggable input tool

An extractor maps PDF bytes → screenplay text. It is a tool the writer runs *before* committing,
not a part of the protocol's trust path. Consequences:

- **Two extractors that produce the same text produce the same `contentHash`.** Two that disagree
  produce different hashes — so the writer **reviews the extracted text before registering**, and
  any disagreement is surfaced before commitment, never after.
- **The writer reviews (and may edit) the extracted text.** What they see is exactly what is
  fingerprinted and embedded. This human checkpoint is what makes a non-deterministic or
  evolving extractor safe.
- **Extractors may differ across surfaces and over time.** The reference CLI extractor and the
  in-browser extractor need not agree byte-for-byte, and either may be improved or replaced. This
  affects only *future* registrations; every existing `.screenreg` keeps verifying, because it
  carries its own frozen text (Section 11 §5).

Reference + current extractors (informative, not normative):
- **CLI reference** — `src/extractors/reference/` (Final Draft-convention text PDFs).
- **Browser** — pdf.js, self-hosted, run entirely client-side; the PDF never leaves the browser.
- **Future** — a first-party pure-TS extractor may replace the above with no effect on prior proofs.

### 3. Verification never extracts

Because the committed artifact is the text (embedded in the full `.screenreg`), verification is:
re-normalize the embedded text under v1-strict, SHA-256 it, compare to `contentHash`, and check
the anchor. **No PDF and no extractor are involved at verify time** — verification is pure
SHA-256, in any tool, forever.

### 4. Extraction provenance (optional, in the unhashed evidence bundle)

So that an extraction can be *audited* without being commitment-bearing, a producer MAY record
which extractor produced the text under `evidenceBundle.bundleExtensions.sourceProvenance` (see
Section 11 §7): `sourceFormat`, an optional `sourceDigest` of the original PDF, and an `extractor`
identity (`name`, `version`, `commit`, `artifactSha256`). This block is never hashed and is not
required for verification; it exists only so an auditor who doubts the faithfulness of an
extraction can fetch exactly that extractor and re-run it against the original PDF.

### 5. Out of scope

- **Scanned / image-only PDFs** (no text layer) are rejected — there is no text to commit.
- **OCR** is out of scope for the reference and browser extractors.
- A PDF that needs predefined CMaps or non-embedded fonts the extractor lacks may extract
  incompletely; the review step (the writer sees the text) is the safeguard, and such inputs can
  fall back to a different extractor or to pasting the screenplay as text.
