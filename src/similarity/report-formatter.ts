/**
 * Human-readable formatter for ComparisonReport.
 *
 * Kept separate from src/similarity/jaccard.ts (the metric math) so:
 *   - Library consumers building their own UI (web verifier, integrator app)
 *     can import only the metric layer without pulling in the CLI's text shape.
 *   - The "what we display to a court / journalist" copy lives in one place
 *     where compliance reviewers can audit phrasing without grep-ing through
 *     the math module.
 *   - The legal caveat at the bottom ("EXACT normalized-byte content reuse,
 *     NOT narrative / semantic / legal similarity") is contract-bearing per
 *     spec §06 §5 — pulling it out makes it visible as a single block.
 */

import type { ComparisonReport } from './jaccard.js'

export interface FormatComparisonReportOptions {
  /** Display label for bundle A (default 'A'). */
  labelA?: string
  /** Display label for bundle B (default 'B'). */
  labelB?: string
}

export function formatComparisonReport(
  report: ComparisonReport,
  options: FormatComparisonReportOptions = {},
): string {
  const a = options.labelA ?? 'A'
  const b = options.labelB ?? 'B'
  const lines: string[] = []
  if (report.exactWholeScriptMatch) {
    lines.push(`★ EXACT MATCH — ${a} and ${b} are the same registration (same claim hash).`)
    lines.push(``)
  }
  if (report.scenes) {
    appendSceneSection(lines, report.scenes, a, b)
  }
  if (report.paragraphs) {
    appendParagraphSection(lines, report.paragraphs, a, b)
  }
  lines.push(...LEGAL_CAVEAT_LINES)
  return lines.join('\n')
}

const LEGAL_CAVEAT_LINES = [
  `(Measures EXACT normalized-byte content reuse. Does NOT measure narrative,`,
  ` semantic, or legal similarity. HIGH scores are strong evidence of content`,
  ` reuse. LOW scores are NOT proof of difference — could be cosmetic byte`,
  ` differences (cross-tool exports), single-character edits, or adversarial`,
  ` obfuscation that exact matching does not catch.)`,
] as const

function pct(n: number): string {
  return (n * 100).toFixed(1) + '%'
}

function appendSceneSection(
  lines: string[],
  scenes: NonNullable<ComparisonReport['scenes']>,
  a: string,
  b: string,
): void {
  lines.push(`SCENE-LEVEL`)
  lines.push(`  ${a}: ${scenes.set.countA} scenes (distinct)`)
  lines.push(`  ${b}: ${scenes.set.countB} scenes (distinct)`)
  lines.push(
    `  Shared (set):       ${scenes.set.shared}    Jaccard ${pct(scenes.set.jaccard)}`,
  )
  lines.push(
    `  Coverage:           ${pct(scenes.set.coverageAInB)} of ${a}'s scenes appear in ${b}; ${pct(scenes.set.coverageBInA)} of ${b}'s scenes appear in ${a}`,
  )
  lines.push(
    `  Multiset Jaccard:   ${pct(scenes.multiset.multisetJaccard)} (${scenes.multiset.multisetSharedCount} / ${scenes.multiset.multisetUnionCount} — counts repeats)`,
  )
  lines.push(
    `  Longest run:        ${scenes.sequence.longestCommonRun} consecutive scenes (${pct(scenes.sequence.longestCommonRunFraction)} of shorter)`,
  )
  lines.push(
    `  Longest subseq:     ${scenes.sequence.longestCommonSubsequence} scenes (${pct(scenes.sequence.longestCommonSubsequenceFraction)} of shorter)`,
  )
  lines.push(``)
}

function appendParagraphSection(
  lines: string[],
  paragraphs: NonNullable<ComparisonReport['paragraphs']>,
  a: string,
  b: string,
): void {
  lines.push(`PARAGRAPH-LEVEL  (robust to global rename + adversarial scene-heading changes)`)
  lines.push(`  ${a}: ${paragraphs.set.countA} paragraphs (distinct)`)
  lines.push(`  ${b}: ${paragraphs.set.countB} paragraphs (distinct)`)
  lines.push(
    `  Shared (set):       ${paragraphs.set.shared}    Jaccard ${pct(paragraphs.set.jaccard)}`,
  )
  lines.push(
    `  Coverage:           ${pct(paragraphs.set.coverageAInB)} of ${a}'s paragraphs in ${b}; ${pct(paragraphs.set.coverageBInA)} of ${b}'s paragraphs in ${a}`,
  )
  lines.push(
    `  Multiset Jaccard:   ${pct(paragraphs.multiset.multisetJaccard)} (${paragraphs.multiset.multisetSharedCount} / ${paragraphs.multiset.multisetUnionCount})`,
  )
  lines.push(
    `  Longest run:        ${paragraphs.sequence.longestCommonRun} consecutive paragraphs (${pct(paragraphs.sequence.longestCommonRunFraction)} of shorter)`,
  )
  if (paragraphs.coverageByWords) {
    const cw = paragraphs.coverageByWords
    lines.push(``)
    lines.push(`  COVERAGE BY WORDS  ← typically the most legible single number`)
    lines.push(
      `    ${a}: ${cw.totalWordsA} total words; ${cw.sharedWordsInA} in matched paragraphs (${pct(cw.coverageAInB)})`,
    )
    lines.push(
      `    ${b}: ${cw.totalWordsB} total words; ${cw.sharedWordsInB} in matched paragraphs (${pct(cw.coverageBInA)})`,
    )
  }
  lines.push(``)
}
