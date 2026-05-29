#!/usr/bin/env node
/**
 * Copies verifier-web/{index.html,verifier.js} → landing/verify/ so a single
 * Cloudflare Pages project serves both /create/ and /verify/ from one site.
 *
 * Cloudflare Pages' publish directory is `landing/`. The verifier source lives
 * at `verifier-web/` (separate from `landing/` because /verify/ is a strictly
 * read-only tool with no shared state). This script is run as part of the
 * deploy build so the published tree contains landing/verify/.
 *
 * landing/verify/ is .gitignored — it is a build artifact.
 */

import { copyFile, mkdir, stat } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..')
const src = resolve(repoRoot, 'verifier-web')
const dst = resolve(repoRoot, 'landing', 'verify')

const FILES = ['index.html', 'verifier.js']

async function exists(path) {
  try {
    await stat(path)
    return true
  } catch {
    return false
  }
}

async function main() {
  for (const name of FILES) {
    const srcPath = resolve(src, name)
    if (!(await exists(srcPath))) {
      process.stderr.write(`build-landing-verify: missing source ${srcPath}\n`)
      process.exit(1)
    }
  }
  await mkdir(dst, { recursive: true })
  for (const name of FILES) {
    const srcPath = resolve(src, name)
    const dstPath = resolve(dst, name)
    await copyFile(srcPath, dstPath)
    process.stderr.write(`build-landing-verify: ${srcPath} -> ${dstPath}\n`)
  }
}

main().catch((err) => {
  process.stderr.write(`build-landing-verify: ${err?.stack ?? err}\n`)
  process.exit(1)
})
