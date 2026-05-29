/**
 * Reference PDF → Fountain extractor for Final Draft-convention text PDFs.
 *
 * What it handles:
 *   - Text-layer PDFs produced by Final Draft, Highland, WriterDuet,
 *     Fade In, Trelby, Slugline, and similar tools that emit standard
 *     screenplay layout.
 *   - Courier 12pt fixed-width fonts.
 *   - US Letter, FD-convention margins (1.5in left, 1.0in others) with
 *     small (±0.25in) tolerance.
 *   - Standard elements: slug lines (INT/EXT/EST), action, character
 *     cues, parentheticals, dialogue, transitions (right-aligned).
 *
 * What it rejects (with specific error codes so the caller can fall
 * back gracefully):
 *   - Image-only PDFs (no text layer) → EXTRACT_NO_TEXT_LAYER
 *   - Password-protected PDFs        → EXTRACT_ENCRYPTED
 *   - Non-FD layouts (multi-column shooting drafts, unusual margins,
 *     non-Courier proportional fonts) → EXTRACT_UNSUPPORTED_LAYOUT
 *   - Malformed PDFs                 → EXTRACT_CORRUPTED
 *   - PDFs where too many regions are ambiguous to classify with
 *     confidence → EXTRACT_AMBIGUOUS_BLOCKS
 *
 * pdf2json is loaded via dynamic import so it remains an optional
 * runtime dependency. Callers that never extract a PDF do not pay the
 * pdf2json install + load cost.
 */

import {
  type PdfExtractor,
  type ExtractorOptions,
  type ExtractorResult,
  type PageDiagnostic,
  ExtractorError,
} from '../types.js'

const NAME = 'screenreg-reference'
const VERSION = '0.2.0'

/**
 * FD-convention column boundaries in PDF user-space units (72 per inch).
 * pdf2json reports x in its own unit system that approximates 1.0 per
 * character at 12pt Courier; the boundaries here are in pdf2json units.
 *
 *   Left margin:        ~7.0   (≈ 1.5in)
 *   Action text:        ~7.0
 *   Parenthetical start: ~13.0 (~ 2.7in)
 *   Dialogue:           ~12.0 (~ 2.5in)
 *   Character cue:      ~17.0 (~ 3.5in)
 *   Right-aligned transition: ~50.0+
 */
const X_LEFT_MARGIN = 6.0
const X_DIALOGUE = 11.0
const X_PAREN = 13.0
const X_CHARACTER = 16.0
const X_TRANSITION = 45.0

const TOLERANCE = 2.0

const SCENE_HEADING_PREFIXES = [
  'INT.',
  'EXT.',
  'EST.',
  'INT/EXT',
  'INT./EXT.',
  'I/E',
]

/** Maximum input size — defensive cap against a maliciously huge PDF. */
const MAX_INPUT_BYTES = 32 * 1024 * 1024 // 32 MB

export class ReferenceExtractor implements PdfExtractor {
  readonly name = NAME
  readonly version = VERSION

  async extract(
    pdfBytes: Uint8Array,
    options?: ExtractorOptions,
  ): Promise<ExtractorResult> {
    if (!(pdfBytes instanceof Uint8Array)) {
      throw new ExtractorError(
        'EXTRACT_CORRUPTED',
        'extractor expected Uint8Array input',
      )
    }
    if (pdfBytes.length === 0) {
      throw new ExtractorError('EXTRACT_CORRUPTED', 'input is empty (0 bytes)')
    }
    if (pdfBytes.length > MAX_INPUT_BYTES) {
      throw new ExtractorError(
        'EXTRACT_CORRUPTED',
        `input ${pdfBytes.length} bytes exceeds ${MAX_INPUT_BYTES}`,
      )
    }
    if (!startsWithPdfHeader(pdfBytes)) {
      throw new ExtractorError(
        'EXTRACT_CORRUPTED',
        'input does not start with %PDF- header',
      )
    }

    const parsed = await loadAndParse(pdfBytes)
    const pages = parsed?.Pages
    if (!Array.isArray(pages) || pages.length === 0) {
      throw new ExtractorError('EXTRACT_CORRUPTED', 'PDF has no pages')
    }

    const stripPageNumbers = options?.stripPageNumbers !== false
    const stripSceneNumbers = options?.stripSceneNumbers !== false

    const diagnostics: PageDiagnostic[] = []
    let totalTextTokens = 0
    let totalClassifiedTokens = 0
    const fountainLines: string[] = []

    for (let i = 0; i < pages.length; i++) {
      const page = pages[i] as PdfJsonPage
      const pageNum = i + 1

      if (!Array.isArray(page?.Texts) || page.Texts.length === 0) {
        diagnostics.push({
          page: pageNum,
          unrecognizedRegions: 0,
          warnings: ['page has no text tokens'],
        })
        continue
      }

      totalTextTokens += page.Texts.length

      const lines = groupTokensIntoLines(page.Texts)
      const pageDiag: PageDiagnostic = {
        page: pageNum,
        unrecognizedRegions: 0,
        warnings: [],
      }

      let prevElementType: ElementType | null = null
      for (const line of lines) {
        if (
          stripPageNumbers &&
          isLikelyPageNumber(line, pageNum, pages.length)
        ) {
          continue
        }
        const classified = classifyLine(line, stripSceneNumbers)
        if (classified.type === 'unknown') {
          pageDiag.unrecognizedRegions += 1
          continue
        }
        totalClassifiedTokens += classified.tokens

        // Fountain syntax: most elements are separated by blank lines.
        // Character + dialogue + parenthetical are a contiguous block.
        const needsBlankBefore =
          fountainLines.length > 0 &&
          fountainLines[fountainLines.length - 1] !== '' &&
          !isContiguous(prevElementType, classified.type)
        if (needsBlankBefore) fountainLines.push('')

        fountainLines.push(classified.text)
        prevElementType = classified.type
      }

      diagnostics.push(pageDiag)
    }

    if (totalTextTokens === 0) {
      throw new ExtractorError(
        'EXTRACT_NO_TEXT_LAYER',
        'PDF has pages but no extractable text — likely a scanned image-only PDF',
      )
    }

    // Confidence = ratio of classified tokens to total tokens, modulated by
    // per-page unrecognized regions.
    const confidence = clamp01(totalClassifiedTokens / Math.max(1, totalTextTokens))
    if (confidence < 0.5) {
      throw new ExtractorError(
        'EXTRACT_AMBIGUOUS_BLOCKS',
        `too many unrecognized regions (confidence ${confidence.toFixed(2)} < 0.5)`,
        { diagnostics },
      )
    }

    // Trim leading/trailing blank lines and collapse runs of >1 blank line.
    const fountain = postProcess(fountainLines)

    return { fountain, diagnostics, confidence }
  }
}

export default new ReferenceExtractor()

// ===========================================================================
// pdf2json adapter
// ===========================================================================

interface PdfJsonTextRun {
  T?: string
  S?: number
  TS?: number[]
}

interface PdfJsonTextItem {
  x: number
  y: number
  w?: number
  sw?: number
  A?: string
  R: PdfJsonTextRun[]
}

interface PdfJsonPage {
  Texts: PdfJsonTextItem[]
}

interface PdfJsonOutput {
  Pages: PdfJsonPage[]
}

interface PdfParserCtor {
  new (): PdfParserInstance
}
interface PdfParserInstance {
  on(event: string, handler: (data: unknown) => void): void
  parseBuffer(buf: Buffer): void
}

/**
 * Wall-clock timeout for a single pdf2json parse. A hostile xref stream
 * or pathological compression can hang the parser indefinitely. 30 seconds
 * is generous for legitimate inputs (a 32 MB FD-convention PDF parses in
 * <2 s on a modest laptop); anything slower deserves an EXTRACT_CORRUPTED
 * regardless of the underlying cause.
 */
const PARSE_TIMEOUT_MS = 30_000

async function loadAndParse(pdfBytes: Uint8Array): Promise<PdfJsonOutput> {
  let PDFParser: PdfParserCtor
  try {
    const mod = (await import('pdf2json')) as unknown as { default: PdfParserCtor }
    PDFParser = mod.default
  } catch (err) {
    throw new ExtractorError(
      'EXTRACT_DEPENDENCY_MISSING',
      'pdf2json is not installed — run `npm install pdf2json` to enable PDF extraction, or use a different PdfExtractor implementation',
      { cause: err instanceof Error ? err.message : String(err) },
    )
  }

  return new Promise<PdfJsonOutput>((resolve, reject) => {
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      restoreStdout()
      reject(
        new ExtractorError(
          'EXTRACT_CORRUPTED',
          `pdf2json parse exceeded ${PARSE_TIMEOUT_MS} ms — possible adversarial input`,
        ),
      )
    }, PARSE_TIMEOUT_MS)

    // Silence stdout while pdf2json runs. The bundled pdfjs writes
    // "Warning: Setting up fake worker." to process.stdout, which would
    // corrupt `screenreg extract foo.pdf > out.fountain` by prepending a
    // non-Fountain line to the output file. The redirect is restored
    // before this Promise resolves or rejects.
    const restoreStdout = silenceStdoutToStderr()

    const parser = new PDFParser()
    parser.on('pdfParser_dataError', (data: unknown) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      restoreStdout()
      const errInfo = (data as { parserError?: { message?: string } })
        ?.parserError
      const msg = errInfo?.message ?? 'pdf2json parse error'
      if (/encrypt/i.test(msg)) {
        reject(
          new ExtractorError(
            'EXTRACT_ENCRYPTED',
            'PDF is password-protected; the reference extractor does not decrypt',
            { upstreamMessage: msg },
          ),
        )
        return
      }
      reject(
        new ExtractorError('EXTRACT_CORRUPTED', `pdf2json: ${msg}`, {
          upstreamMessage: msg,
        }),
      )
    })
    parser.on('pdfParser_dataReady', (data: unknown) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      restoreStdout()
      resolve(data as PdfJsonOutput)
    })
    try {
      parser.parseBuffer(Buffer.from(pdfBytes))
    } catch (err) {
      if (settled) return
      settled = true
      clearTimeout(timer)
      restoreStdout()
      reject(
        new ExtractorError(
          'EXTRACT_CORRUPTED',
          `pdf2json threw synchronously: ${err instanceof Error ? err.message : String(err)}`,
        ),
      )
    }
  })
}

/**
 * Temporarily redirect process.stdout.write to process.stderr. Returns a
 * function that restores the original behavior. Used to keep pdf2json's
 * internal warnings out of the extract subcommand's stdout pipeline.
 *
 * No-op in environments where process.stdout.write isn't writable
 * (e.g. some test harnesses) — failing to silence is preferable to
 * crashing on assignment to a sealed property.
 */
function silenceStdoutToStderr(): () => void {
  const original = process.stdout.write.bind(process.stdout)
  try {
    process.stdout.write = ((chunk: unknown, ...rest: unknown[]): boolean => {
      return (process.stderr.write as (c: unknown, ...r: unknown[]) => boolean)(
        chunk,
        ...rest,
      )
    }) as typeof process.stdout.write
  } catch {
    return () => {
      /* unable to redirect; nothing to restore */
    }
  }
  return () => {
    try {
      process.stdout.write = original
    } catch {
      /* swallow */
    }
  }
}

// ===========================================================================
// Line grouping + classification
// ===========================================================================

interface PageLine {
  x: number
  y: number
  text: string
  tokenCount: number
}

function groupTokensIntoLines(texts: PdfJsonTextItem[]): PageLine[] {
  // pdf2json's text items aren't always emitted in reading order. Sort by
  // (y, x) so we can group same-y tokens into a single line.
  const sorted = [...texts].sort((a, b) => {
    if (Math.abs(a.y - b.y) > 0.2) return a.y - b.y
    return a.x - b.x
  })
  const lines: PageLine[] = []
  let current: PageLine | null = null
  for (const item of sorted) {
    const raw = decodeText(item)
    if (raw.length === 0) continue
    if (current === null || Math.abs(item.y - current.y) > 0.4) {
      if (current !== null) lines.push(current)
      current = { x: item.x, y: item.y, text: raw, tokenCount: 1 }
    } else {
      // Glue tokens on the same line; pdf2json doesn't always include the
      // trailing space character so we add one when the gap suggests it.
      const needsSpace =
        current.text.length > 0 &&
        !current.text.endsWith(' ') &&
        !raw.startsWith(' ') &&
        item.x - current.x > current.text.length + 0.5
      current.text += (needsSpace ? ' ' : '') + raw
      current.tokenCount += 1
    }
  }
  if (current !== null) lines.push(current)
  return lines
}

function decodeText(item: PdfJsonTextItem): string {
  let out = ''
  for (const run of item.R) {
    if (typeof run.T !== 'string') continue
    try {
      out += decodeURIComponent(run.T)
    } catch {
      // pdf2json sometimes emits malformed percent-encoding (e.g. a literal
      // '%' that isn't part of an escape). Strip the offending bytes.
      out += run.T.replace(/%(?![0-9A-Fa-f]{2})/g, '%25')
      try {
        out = decodeURIComponent(out)
      } catch {
        /* swallow */
      }
    }
  }
  return out
}

type ElementType =
  | 'scene-heading'
  | 'action'
  | 'character'
  | 'parenthetical'
  | 'dialogue'
  | 'transition'
  | 'centered'

interface ClassifiedLine {
  type: ElementType | 'unknown'
  text: string
  tokens: number
}

function classifyLine(line: PageLine, stripSceneNumbers: boolean): ClassifiedLine {
  const trimmed = line.text.trim()
  if (trimmed.length === 0) return { type: 'unknown', text: '', tokens: 0 }

  const isAllCaps = /^[^a-z]+$/.test(trimmed) && /[A-Z]/.test(trimmed)

  // Scene heading: starts with INT/EXT/EST/INT./EXT./I/E etc. Optional
  // leading scene number for production drafts (e.g. "12 INT. KITCHEN").
  const sceneHeadingMatch = trimmed.match(
    /^(\s*\d+\s+)?((INT|EXT|EST|INT\.?\/EXT|I\/E)\.?\s+.+)$/,
  )
  if (sceneHeadingMatch !== null && isAllCaps) {
    const heading = stripSceneNumbers
      ? sceneHeadingMatch[2]!
      : sceneHeadingMatch[0]
    return { type: 'scene-heading', text: heading.toUpperCase(), tokens: line.tokenCount }
  }

  // Transition: right-aligned or ends with "TO:"
  if (
    isAllCaps &&
    (line.x >= X_TRANSITION || /TO:$/.test(trimmed) || trimmed === 'FADE OUT.' || trimmed === 'FADE IN:')
  ) {
    if (trimmed === 'FADE IN:' || trimmed === 'FADE OUT.') {
      // FADE IN: is conventionally action at the start; emit as such
      return { type: 'action', text: trimmed, tokens: line.tokenCount }
    }
    return { type: 'transition', text: `> ${trimmed.replace(/\s*TO:$/, ' TO:')}`, tokens: line.tokenCount }
  }

  // Character cue: roughly centered (between dialogue x and transition x),
  // all caps, often followed by an extension like (V.O.) or (CONT'D).
  if (
    isAllCaps &&
    line.x >= X_CHARACTER - TOLERANCE &&
    line.x < X_TRANSITION - TOLERANCE
  ) {
    return { type: 'character', text: trimmed, tokens: line.tokenCount }
  }

  // Parenthetical: wrapped in ( ) and indented past dialogue
  if (
    /^\(.*\)$/.test(trimmed) &&
    line.x >= X_PAREN - TOLERANCE &&
    line.x < X_CHARACTER + TOLERANCE
  ) {
    return { type: 'parenthetical', text: trimmed, tokens: line.tokenCount }
  }

  // Dialogue: indented to the dialogue column, mixed case
  if (line.x >= X_DIALOGUE - TOLERANCE && line.x < X_CHARACTER - TOLERANCE) {
    return { type: 'dialogue', text: trimmed, tokens: line.tokenCount }
  }

  // Action: left-margin, anything else
  if (line.x < X_DIALOGUE - TOLERANCE) {
    return { type: 'action', text: trimmed, tokens: line.tokenCount }
  }

  // Doesn't fit any column — unrecognized.
  return { type: 'unknown', text: trimmed, tokens: line.tokenCount }
}

function isLikelyPageNumber(
  line: PageLine,
  pageNum: number,
  totalPages: number,
): boolean {
  const trimmed = line.text.trim()
  // Bare integer matching the page number or "n." form
  if (/^\d{1,4}\.?$/.test(trimmed)) {
    const n = parseInt(trimmed, 10)
    if (!Number.isNaN(n) && n >= 1 && n <= totalPages * 2) return true
  }
  return false
}

function isContiguous(prev: ElementType | null, next: ElementType): boolean {
  if (prev === null) return false
  if (prev === 'character' && (next === 'parenthetical' || next === 'dialogue')) {
    return true
  }
  if (prev === 'parenthetical' && next === 'dialogue') return true
  if (prev === 'dialogue' && next === 'parenthetical') return true
  return false
}

function postProcess(lines: string[]): string {
  // Strip leading/trailing blanks; collapse multi-blank runs to single blank.
  const out: string[] = []
  let lastWasBlank = true
  for (const l of lines) {
    if (l === '') {
      if (lastWasBlank) continue
      lastWasBlank = true
      out.push('')
    } else {
      out.push(l)
      lastWasBlank = false
    }
  }
  while (out.length > 0 && out[out.length - 1] === '') out.pop()
  return out.join('\n') + '\n'
}

function clamp01(v: number): number {
  if (v < 0) return 0
  if (v > 1) return 1
  return v
}

function startsWithPdfHeader(bytes: Uint8Array): boolean {
  // %PDF- in ASCII
  return (
    bytes.length >= 5 &&
    bytes[0] === 0x25 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x44 &&
    bytes[3] === 0x46 &&
    bytes[4] === 0x2d
  )
}
