#!/usr/bin/env node
/**
 * Thin shim that runs the compiled dist/cli/main.js. If dist is missing
 * (fresh clone, post-npm-install), build it once on first use.
 *
 * The tsx fallback path was removed: pdf2json (the optional PDF extractor
 * dependency) embeds Mozilla's pdfjs, whose module-loading sequence fails
 * under tsx's on-the-fly transpilation — the parser throws
 * "Command token too long: 128" on every input. The compiled-dist path
 * works for the same inputs, so we standardize on it and auto-build
 * once instead of carrying two broken paths.
 */
import { existsSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(__dirname, '..')
const distMain = join(repoRoot, 'dist', 'cli', 'main.js')

if (!existsSync(distMain)) {
  process.stderr.write(
    `screenreg: building dist (first-time setup; will take ~2-3 seconds)…\n`,
  )
  // Redirect npm's stdout to OUR stderr so the build output never lands in
  // the user's `screenreg extract draft.pdf > out.fountain` redirection.
  const build = spawnSync('npm', ['run', 'build'], {
    cwd: repoRoot,
    stdio: ['ignore', 2, 'inherit'],
  })
  if (build.status !== 0) {
    process.stderr.write(
      `screenreg: build failed (exit ${build.status}). Run \`npm install && npm run build\` from ${repoRoot} manually.\n`,
    )
    process.exit(build.status ?? 1)
  }
}

await import(distMain)
