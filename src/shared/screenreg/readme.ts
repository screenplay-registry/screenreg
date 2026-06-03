/**
 * Generates the human-readable README.txt embedded in every `.screenreg`.
 *
 * Deterministic: no timestamps, no environment detail — the same bundle inputs always produce
 * the same README bytes (required for reproducible containers). The README is purely
 * descriptive; readers ignore it.
 */

import type { BundleType } from './types.js'

export interface ReadmeInput {
  bundleType: BundleType
  /** The canonical "sha256:<hex>" commitment, shown so a human can eyeball-match it. */
  claimHash: string
}

export function buildReadme(input: ReadmeInput): string {
  const full = input.bundleType === 'full'
  const lines: string[] = [
    'THE SCREENPLAY REGISTRY — proof bundle',
    '======================================',
    '',
    'This is a .screenreg file: a dated, cryptographically verifiable proof that a',
    'screenplay draft existed at a point in time, anchored to the Bitcoin blockchain',
    'via OpenTimestamps. It is an ordinary ZIP archive — you can open it with any',
    'unzip tool to inspect the files inside.',
    '',
    `Commitment (claimHash): ${input.claimHash}`,
    '',
    full
      ? [
          'BUNDLE TYPE: full (self-contained)',
          '',
          'This bundle includes the screenplay text that was fingerprinted, so it can be',
          'verified completely on its own — now or in decades. Keep it somewhere safe.',
          'Because it contains your script, share it only with people you intend to show',
          'the script to. To prove the date WITHOUT revealing the script, create an',
          'evidence bundle (the .evidence.screenreg file) instead.',
        ].join('\n')
      : [
          'BUNDLE TYPE: evidence (proof-only)',
          '',
          'This bundle does NOT contain the screenplay. It proves that a document with the',
          'fingerprint above existed by a certain date (and, if signed, by whom) while',
          'revealing nothing about the contents. It is safe to hand to anyone. To later',
          'prove that the fingerprint is a specific screenplay, supply that screenplay',
          'alongside this bundle when verifying.',
        ].join('\n'),
    '',
    'CONTENTS',
    '--------',
    '  screenreg.json   description of this bundle (format, contents, checksums)',
    '  envelope.json    the registration record: the committed claim + evidence',
    '  proof.ots        the OpenTimestamps proof (Bitcoin time anchor)',
    ...(full ? ['  script.fountain  the screenplay text that was fingerprinted'] : []),
    '  README.txt       this file',
    '',
    'HOW TO VERIFY',
    '-------------',
    '  In a browser:  https://screenplayregistry.org/verify/  (drop this file)',
    '  On the command line:',
    '    git clone https://github.com/screenplay-registry/screenreg',
    '    screenreg verify <this-file>.screenreg',
    '',
    'Verification runs entirely on your own machine. Nothing is uploaded. Existing',
    'proofs verify against Bitcoin forever, with no server and no company required.',
    '',
    'Specification: https://github.com/screenplay-registry/screenreg/tree/main/spec/v1',
    '',
  ]
  return lines.join('\n')
}
