/**
 * Pluggable PDF → Fountain extractor contract.
 *
 * Architectural premise: `screenplay-registration-norm/v1-strict` is the
 * commitment-bearing normalization profile and only consumes valid UTF-8.
 * PDF is not a screenplay format; it is a rendering layer over one.
 * Rather than introduce a new commitment profile that would attempt to
 * canonicalize PDF bytes (an intractable problem given font subsetting,
 * embedded resources, xref table reordering, and the many permitted
 * encodings of the same logical text), screenreg treats PDF as just
 * another input source that gets converted to canonical Fountain text by
 * a pluggable extractor. The Fountain output is what gets hashed.
 *
 * Consequences:
 *   - There is no `screenreg-norm/v2-pdf` profile and there will not be one.
 *   - Two extractors that produce the same Fountain output produce the same
 *     content hash. Two extractors that disagree produce different hashes;
 *     the writer reviews the extracted Fountain before registering so the
 *     disagreement is surfaced before commitment, not after.
 *   - The reference extractor handles Final Draft-convention text PDFs;
 *     anything else (scanned, encrypted, multi-column shooting drafts,
 *     bilingual layouts) is rejected with a specific error code so the
 *     caller can choose a different extractor or fall back to manual
 *     Fountain entry.
 *
 * Operators ship their own extractors by exporting a default value
 * conforming to PdfExtractor. The reference implementation in
 * `src/extractors/reference/` handles FD-convention text PDFs; non-FD
 * dialects (OCR, multi-column shooting drafts, bilingual layouts) are
 * out-of-scope for the reference and require an operator-specific
 * extractor that satisfies the same contract.
 */

export interface PdfExtractor {
  /** Stable identifier recorded in the envelope evidence bundle. */
  readonly name: string

  /** Semantic version of this extractor implementation. */
  readonly version: string

  /**
   * Extract a Fountain-text representation of `pdfBytes`.
   *
   * MUST return Fountain that is valid input to v1-strict normalization
   * (UTF-8, well-formed, no embedded NUL bytes — though embedded NULs are
   * not a hard requirement of UTF-8 they are a hard requirement of
   * fountain.io's whitespace conventions).
   *
   * MUST be deterministic for a given `(pdfBytes, options)` pair within
   * a given extractor version. Non-determinism would mean two writers with
   * the same input PDF could produce different content hashes — defeats
   * the whole point of a cryptographic timestamp.
   *
   * MUST NOT write to disk, the network, or any global state. The browser
   * /create/ page calls this directly in-process; any side effect would
   * surface as a "your script was uploaded" privacy regression.
   *
   * MUST throw `ExtractorError` on every failure path with a specific
   * code. Silent partial output produces silent verification failures
   * months later.
   */
  extract(pdfBytes: Uint8Array, options?: ExtractorOptions): Promise<ExtractorResult>
}

export interface ExtractorOptions {
  /** Document font hint; reference extractor uses this to disambiguate
   * Courier-like fixed-width layouts from proportional-font layouts. */
  fontHint?: 'courier' | 'courier-prime' | 'auto'
  /** Expected page margins in inches; reference extractor uses these for
   * column detection. Defaults to FD convention (1.5L, 1.0R/T/B). */
  marginsHint?: { left?: number; top?: number; right?: number; bottom?: number }
  /** Strip page numbers from extracted output. Default true. */
  stripPageNumbers?: boolean
  /** Strip scene numbers from extracted output. Default true; flip to
   * false when registering a production draft that carries scene-number
   * provenance. */
  stripSceneNumbers?: boolean
}

export interface ExtractorResult {
  /** Fountain text suitable for direct input to v1-strict normalization. */
  fountain: string
  /** Diagnostic info per page — informational; not committed. */
  diagnostics: PageDiagnostic[]
  /** Confidence score in [0, 1]. Below 0.85 the caller MUST surface the
   * extracted text to the writer for review before committing. */
  confidence: number
}

export interface PageDiagnostic {
  page: number
  unrecognizedRegions: number
  warnings: string[]
}

export class ExtractorError extends Error {
  constructor(
    public readonly code: ExtractorErrorCode,
    message: string,
    public readonly context?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'ExtractorError'
  }
}

export type ExtractorErrorCode =
  /** PDF has no text layer (scanned image). OCR-equipped operators may
   *  ship an extractor that handles this; the reference does not. */
  | 'EXTRACT_NO_TEXT_LAYER'
  /** PDF is password-protected. */
  | 'EXTRACT_ENCRYPTED'
  /** PDF layout doesn't match the reference extractor's heuristics
   *  (multi-column production draft, scanned-form, non-FD layout). */
  | 'EXTRACT_UNSUPPORTED_LAYOUT'
  /** PDF bytes are not a valid PDF. */
  | 'EXTRACT_CORRUPTED'
  /** Reference extractor produced text but with too many low-confidence
   *  regions to trust without manual review. */
  | 'EXTRACT_AMBIGUOUS_BLOCKS'
  /** Optional pdf2json dependency was not installed. */
  | 'EXTRACT_DEPENDENCY_MISSING'
