/**
 * Generate the canonical normalization test corpus.
 *
 * Outputs to /spec/v1/testvectors/normalization/.
 * Each vector is a (input.bin, expected.bin, hash.txt, transforms.json, description.md) quintuple.
 *
 * IMPORTANT: this script uses the REFERENCE IMPLEMENTATION to compute the expected outputs.
 * That is acceptable for corpus generation because:
 *  (a) the implementation is itself authoritative per §1 of the spec, and
 *  (b) any independent implementation can verify the committed corpus matches its own outputs.
 *
 * Re-running this script SHOULD produce byte-identical files (modulo file system metadata).
 *
 * Usage: npx tsx scripts/generate-normalization-corpus.ts
 */

import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync, readdirSync, readFileSync, unlinkSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalize, contentHashOfNormalized, type TransformRecord } from '../src/normalize/v1-strict.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CORPUS_DIR = join(__dirname, '..', 'spec', 'v1', 'testvectors', 'normalization')

interface Vector {
  /** Three-digit zero-padded id, used in filename prefix. */
  id: string
  /** Kebab-case short name, used in filename. */
  name: string
  /** Human-readable description of what this vector tests. */
  description: string
  /** Input bytes. */
  input: Buffer
  /** Expected outcome. If 'normalize', compute outputs; if 'reject', expect invalid-utf8 error. */
  expectation: 'normalize' | 'reject-invalid-utf8'
  /** For 'reject' vectors only: the expected error detail's substring. */
  rejectDetailSubstring?: string
}

// ---------------------------------------------------------------------------
// Helpers for building inputs
// ---------------------------------------------------------------------------

const utf8 = (s: string): Buffer => Buffer.from(s, 'utf8')
const BOM = Buffer.from([0xef, 0xbb, 0xbf])
const concat = (...parts: Buffer[]): Buffer => Buffer.concat(parts)

// ---------------------------------------------------------------------------
// The vectors
// ---------------------------------------------------------------------------

const vectors: Vector[] = [
  // ---- Empty / trivial inputs ----
  {
    id: '001',
    name: 'empty',
    description: 'Empty input → empty output → SHA-256 of empty string.',
    input: Buffer.alloc(0),
    expectation: 'normalize',
  },
  {
    id: '002',
    name: 'single-lf',
    description: 'Input is a single LF byte (0x0A). Output unchanged.',
    input: Buffer.from([0x0a]),
    expectation: 'normalize',
  },
  {
    id: '003',
    name: 'single-cr',
    description: 'Input is a single CR byte (0x0D). Output should be LF (0x0A).',
    input: Buffer.from([0x0d]),
    expectation: 'normalize',
  },
  {
    id: '004',
    name: 'ascii-no-newline',
    description: 'Pure ASCII with no trailing newline. Output identical to input.',
    input: utf8('Hello, world.'),
    expectation: 'normalize',
  },
  {
    id: '005',
    name: 'ascii-with-lf',
    description: 'ASCII line ending in LF. Output identical to input.',
    input: utf8('Hello\n'),
    expectation: 'normalize',
  },

  // ---- BOM handling ----
  {
    id: '010',
    name: 'bom-only',
    description: 'Input is exactly the UTF-8 BOM. Output is empty after stripping.',
    input: BOM,
    expectation: 'normalize',
  },
  {
    id: '011',
    name: 'bom-then-ascii',
    description: 'BOM + ASCII. BOM stripped; ASCII preserved.',
    input: concat(BOM, utf8('Hello')),
    expectation: 'normalize',
  },
  {
    id: '012',
    name: 'embedded-bom-preserved',
    description:
      'BOM in the middle of the file is the zero-width no-break space U+FEFF and MUST be preserved (only the LEADING BOM is stripped).',
    input: utf8('Hello\u{FEFF}world'),
    expectation: 'normalize',
  },

  // ---- Line ending normalization ----
  {
    id: '020',
    name: 'crlf-to-lf',
    description: 'CRLF becomes LF.',
    input: utf8('line one\r\nline two\r\n'),
    expectation: 'normalize',
  },
  {
    id: '021',
    name: 'lone-cr-to-lf',
    description: 'Lone CR (not followed by LF) becomes LF.',
    input: utf8('classic-mac\rstyle\r'),
    expectation: 'normalize',
  },
  {
    id: '022',
    name: 'mixed-line-endings',
    description: 'Mix of CRLF, LF, lone CR. All CR sequences become LF.',
    input: Buffer.concat([
      utf8('a'),
      Buffer.from([0x0d, 0x0a]),
      utf8('b'),
      Buffer.from([0x0a]),
      utf8('c'),
      Buffer.from([0x0d]),
      utf8('d'),
    ]),
    expectation: 'normalize',
  },
  {
    id: '023',
    name: 'only-cr-bytes',
    description: 'Input is exactly three CR bytes. Output should be three LF bytes.',
    input: Buffer.from([0x0d, 0x0d, 0x0d]),
    expectation: 'normalize',
  },

  // ---- NFC normalization ----
  {
    id: '030',
    name: 'already-nfc',
    description: 'Text already in NFC. Output identical to input.',
    input: utf8('café'),
    expectation: 'normalize',
  },
  {
    id: '031',
    name: 'nfd-to-nfc-acute',
    description: 'NFD form U+0065 U+0301 (e + combining acute) → NFC U+00E9 (é).',
    input: utf8('café'),
    expectation: 'normalize',
  },
  {
    id: '032',
    name: 'nfd-multiple-diacritics',
    description: 'Multiple NFD sequences compose to their NFC equivalents.',
    input: utf8('Président à ç Ñ ö'),
    expectation: 'normalize',
  },
  {
    id: '033',
    name: 'nfc-non-composable',
    description:
      'NFD sequence that has no precomposed form. NFC leaves it as-is (no information loss).',
    input: utf8('a̖b'), // a + combining grave-below; no precomposed form
    expectation: 'normalize',
  },

  // ---- Hidden/invisible characters PRESERVED ----
  {
    id: '040',
    name: 'zwsp-preserved',
    description: 'Zero-width space (U+200B) is preserved — removing it would mask tampering.',
    input: utf8('word​word'),
    expectation: 'normalize',
  },
  {
    id: '041',
    name: 'zwj-zwnj-preserved',
    description: 'Zero-width joiner (U+200D) and non-joiner (U+200C) preserved.',
    input: utf8('a‍bc‌d'),
    expectation: 'normalize',
  },
  {
    id: '042',
    name: 'nbsp-preserved',
    description: 'Non-breaking space (U+00A0) preserved.',
    input: utf8('hello world'),
    expectation: 'normalize',
  },
  {
    id: '043',
    name: 'rtl-ltr-overrides-preserved',
    description: 'Bidi override characters preserved (security-sensitive but stripping is worse).',
    input: utf8('a‮evil‬normal'),
    expectation: 'normalize',
  },
  {
    id: '044',
    name: 'homoglyphs-preserved',
    description: 'Visually identical Latin and Cyrillic letters preserved as distinct codepoints.',
    input: utf8('Latin-a:a Cyrillic-a:а Greek-alpha:α'),
    expectation: 'normalize',
  },

  // ---- Whitespace PRESERVED ----
  {
    id: '050',
    name: 'trailing-spaces-preserved',
    description: 'Trailing spaces on lines preserved (Fountain semantics).',
    input: utf8('action with trailing spaces   \nnext line\n'),
    expectation: 'normalize',
  },
  {
    id: '051',
    name: 'tabs-preserved',
    description: 'Tab characters preserved (no conversion to spaces).',
    input: utf8('col1\tcol2\tcol3\n'),
    expectation: 'normalize',
  },
  {
    id: '052',
    name: 'blank-lines-preserved',
    description: 'Empty lines and their counts preserved (Fountain delimiter semantics).',
    input: utf8('para1\n\n\n\npara2 separated by 3 blank lines\n'),
    expectation: 'normalize',
  },
  {
    id: '053',
    name: 'final-newline-present',
    description: 'A file ending in LF produces a hash that includes that LF.',
    input: utf8('line\n'),
    expectation: 'normalize',
  },
  {
    id: '054',
    name: 'final-newline-absent',
    description: 'A file NOT ending in LF produces a DIFFERENT hash than one that does.',
    input: utf8('line'),
    expectation: 'normalize',
  },

  // ---- Fountain-like content ----
  {
    id: '060',
    name: 'fountain-scene-heading',
    description: 'Fountain INT./EXT. scene heading; ASCII only, no transforms needed.',
    input: utf8('INT. CAFE - DAY\n\nA bustling cafe.\n'),
    expectation: 'normalize',
  },
  {
    id: '061',
    name: 'fountain-dialogue',
    description: 'Fountain character + dialogue with smart quotes (already NFC).',
    input: utf8('SARAH\n“I am the storyteller,” she said.\n'),
    expectation: 'normalize',
  },
  {
    id: '062',
    name: 'fountain-with-crlf',
    description: 'Fountain content saved by a Windows tool (CRLF line endings).',
    input: Buffer.from('INT. ROOM - NIGHT\r\n\r\nAction.\r\n', 'utf8'),
    expectation: 'normalize',
  },
  {
    id: '063',
    name: 'fountain-with-bom-and-crlf',
    description: 'Fountain content saved by Windows Notepad (BOM + CRLF).',
    input: concat(BOM, Buffer.from('INT. ROOM - NIGHT\r\n\r\nAction.\r\n', 'utf8')),
    expectation: 'normalize',
  },

  // ---- Combined adversarial cases ----
  {
    id: '070',
    name: 'combined-bom-crlf-nfd',
    description: 'BOM + CRLF + NFD all at once — exercises all transforms.',
    input: concat(BOM, Buffer.from('café\r\nnaivë \r\n', 'utf8')),
    expectation: 'normalize',
  },
  {
    id: '071',
    name: 'unicode-supplementary',
    description: 'Supplementary plane characters (emoji) preserved correctly.',
    input: utf8('Writing: \u{1F4DC} Bitcoin: \u{20BF}\n'),
    expectation: 'normalize',
  },

  // ---- Large input ----
  {
    id: '080',
    name: 'large-1mb',
    description: '~1 MB of repeated ASCII content. Performance + correctness sanity check.',
    input: Buffer.from('A'.repeat(1024 * 1024) + '\n', 'utf8'),
    expectation: 'normalize',
  },

  // ---- Invalid UTF-8 — MUST REJECT ----
  {
    id: '090',
    name: 'invalid-overlong-null',
    description:
      'Overlong encoding of U+0000 as 0xC0 0x80 — rejected per RFC 3629 strict.',
    input: Buffer.from([0xc0, 0x80]),
    expectation: 'reject-invalid-utf8',
    rejectDetailSubstring: 'offset 0',
  },
  {
    id: '091',
    name: 'invalid-lone-continuation',
    description: 'Lone continuation byte 0x80 with no leading byte.',
    input: Buffer.from([0x80]),
    expectation: 'reject-invalid-utf8',
    rejectDetailSubstring: 'offset 0',
  },
  {
    id: '092',
    name: 'invalid-truncated-multibyte',
    description: '3-byte sequence indicator 0xE0 with only 1 continuation byte.',
    input: Buffer.from([0xe0, 0xa0]),
    expectation: 'reject-invalid-utf8',
  },
  {
    id: '093',
    name: 'invalid-surrogate',
    description: 'Encoded high surrogate U+D800 (0xED 0xA0 0x80) — rejected.',
    input: Buffer.from([0xed, 0xa0, 0x80]),
    expectation: 'reject-invalid-utf8',
  },
  {
    id: '094',
    name: 'invalid-codepoint-too-large',
    description: 'Encoded codepoint U+110000 (0xF4 0x90 0x80 0x80) > U+10FFFF — rejected.',
    input: Buffer.from([0xf4, 0x90, 0x80, 0x80]),
    expectation: 'reject-invalid-utf8',
  },
  {
    id: '095',
    name: 'invalid-5byte-attempt',
    description: '5-byte sequence indicator (0xF8) is not valid in UTF-8.',
    input: Buffer.from([0xf8, 0x88, 0x80, 0x80, 0x80]),
    expectation: 'reject-invalid-utf8',
  },
  {
    id: '096',
    name: 'invalid-stray-c1',
    description: 'Stray leading byte 0xC1 (would always produce overlong).',
    input: Buffer.from([0xc1, 0x80]),
    expectation: 'reject-invalid-utf8',
  },
]

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

function writeVectorFile(path: string, content: Buffer | string): void {
  const buf = typeof content === 'string' ? Buffer.from(content, 'utf8') : content
  writeFileSync(path, buf)
}

function generate(): void {
  mkdirSync(CORPUS_DIR, { recursive: true })

  // Clear out any old vector files to avoid stale leftovers from prior runs
  const existing = readdirSync(CORPUS_DIR).filter(
    (f) =>
      f.endsWith('.input.bin') ||
      f.endsWith('.expected.bin') ||
      f.endsWith('.hash.txt') ||
      f.endsWith('.transforms.json') ||
      f.endsWith('.description.md') ||
      f.endsWith('.reject.json'),
  )
  for (const f of existing) {
    try {
      unlinkSync(join(CORPUS_DIR, f))
    } catch {
      // ignore
    }
  }

  const indexEntries: Array<{ id: string; name: string; description: string; kind: string }> = []
  const allFileDigests: string[] = []

  for (const v of vectors) {
    const prefix = `${v.id}-${v.name}`

    // input.bin (always)
    const inputPath = join(CORPUS_DIR, `${prefix}.input.bin`)
    writeVectorFile(inputPath, v.input)

    // description.md (always)
    writeVectorFile(
      join(CORPUS_DIR, `${prefix}.description.md`),
      `# Vector ${v.id} — ${v.name}\n\n${v.description}\n`,
    )

    if (v.expectation === 'normalize') {
      const result = normalize(v.input)
      if (!result.ok) {
        throw new Error(
          `Vector ${v.id} (${v.name}) was expected to normalize but failed: ${result.detail}`,
        )
      }
      writeVectorFile(join(CORPUS_DIR, `${prefix}.expected.bin`), result.normalized)
      writeVectorFile(
        join(CORPUS_DIR, `${prefix}.hash.txt`),
        contentHashOfNormalized(result.normalized) + '\n',
      )
      writeVectorFile(
        join(CORPUS_DIR, `${prefix}.transforms.json`),
        JSON.stringify(result.transforms satisfies TransformRecord[], null, 2) + '\n',
      )
      indexEntries.push({
        id: v.id,
        name: v.name,
        description: v.description,
        kind: 'normalize',
      })
    } else {
      const result = normalize(v.input)
      if (result.ok) {
        throw new Error(
          `Vector ${v.id} (${v.name}) was expected to reject as invalid UTF-8 but normalized successfully.`,
        )
      }
      writeVectorFile(
        join(CORPUS_DIR, `${prefix}.reject.json`),
        JSON.stringify(
          {
            reason: result.reason,
            detail: result.detail,
            ...(v.rejectDetailSubstring ? { expectedDetailSubstring: v.rejectDetailSubstring } : {}),
          },
          null,
          2,
        ) + '\n',
      )
      indexEntries.push({
        id: v.id,
        name: v.name,
        description: v.description,
        kind: 'reject-invalid-utf8',
      })
    }
  }

  // Write the manifest index for easy discovery
  writeVectorFile(
    join(CORPUS_DIR, 'INDEX.json'),
    JSON.stringify(
      {
        profileId: 'screenplay-registration-norm/v1-strict',
        vectorCount: vectors.length,
        vectors: indexEntries,
      },
      null,
      2,
    ) + '\n',
  )

  // Compute corpus digest = SHA-256 of sorted concatenation of (filename || SHA-256(content))
  const files = readdirSync(CORPUS_DIR).filter((f) => f !== 'CORPUS_DIGEST.txt' && f !== 'INDEX.json').sort()
  const corpusHash = createHash('sha256')
  for (const f of files) {
    const path = join(CORPUS_DIR, f)
    const content = readFileSync(path)
    const fileDigest = createHash('sha256').update(content).digest('hex')
    corpusHash.update(f)
    corpusHash.update(':')
    corpusHash.update(fileDigest)
    corpusHash.update('\n')
    allFileDigests.push(`${f} ${fileDigest}`)
  }
  writeVectorFile(
    join(CORPUS_DIR, 'CORPUS_DIGEST.txt'),
    corpusHash.digest('hex') + '\n',
  )
  writeVectorFile(
    join(CORPUS_DIR, 'CORPUS_FILE_DIGESTS.txt'),
    allFileDigests.join('\n') + '\n',
  )

  console.log(`Generated ${vectors.length} test vectors in ${CORPUS_DIR}`)
}

generate()
