#!/usr/bin/env node
/**
 * Copy non-TypeScript runtime assets into dist/ after `tsc`. tsc emits only the
 * compiled .js/.d.ts, so the OpenTimestamps Python helper — which the compiled
 * `dist/anchors/ots-submit.js` resolves relative to its own location — must be
 * copied alongside it, or `bin/screenreg.mjs` (which runs dist) cannot stamp.
 */
import { copyFileSync, mkdirSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

const assets = [['src/anchors/python/ots_stamp_digest.py', 'dist/anchors/python/ots_stamp_digest.py']]

for (const [from, to] of assets) {
  const src = join(repoRoot, from)
  const dest = join(repoRoot, to)
  if (!existsSync(src)) {
    process.stderr.write(`copy-dist-assets: missing source ${from}\n`)
    process.exit(1)
  }
  mkdirSync(dirname(dest), { recursive: true })
  copyFileSync(src, dest)
}
