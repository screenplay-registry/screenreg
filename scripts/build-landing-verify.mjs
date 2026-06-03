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

import { copyFile, mkdir, stat, readdir } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..')
const src = resolve(repoRoot, 'verifier-web')
const dst = resolve(repoRoot, 'landing', 'verify')

const FILES = ['index.html', 'verifier.js']

// The verifier imports the .screenreg container reader to unpack a dropped bundle. Those compiled
// modules are produced by build:browser under landing/create/lib (build:landing runs it first);
// copy the subset the verifier needs — the screenreg module and its only runtime dependency,
// crypto.js — preserving the relative layout so `../crypto.js` resolves from lib/screenreg/.
const LIB_SRC = resolve(repoRoot, 'landing', 'create', 'lib')
const LIB_DST = resolve(dst, 'lib')

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
  await copyVerifierLib()
}

async function copyVerifierLib() {
  const cryptoSrc = resolve(LIB_SRC, 'crypto.js')
  const screenregSrc = resolve(LIB_SRC, 'screenreg')
  if (!(await exists(cryptoSrc)) || !(await exists(screenregSrc))) {
    process.stderr.write(
      `build-landing-verify: missing compiled lib at ${LIB_SRC} — run build:browser first ` +
        `(build:landing does this for you)\n`,
    )
    process.exit(1)
  }
  await mkdir(resolve(LIB_DST, 'screenreg'), { recursive: true })
  await copyFile(cryptoSrc, resolve(LIB_DST, 'crypto.js'))
  for (const name of await readdir(screenregSrc)) {
    if (!name.endsWith('.js')) continue // compiled modules only (no .map / .d.ts if ever emitted)
    await copyFile(resolve(screenregSrc, name), resolve(LIB_DST, 'screenreg', name))
  }
  process.stderr.write(`build-landing-verify: ${LIB_SRC}/{crypto.js,screenreg/} -> ${LIB_DST}/\n`)
}

main().catch((err) => {
  process.stderr.write(`build-landing-verify: ${err?.stack ?? err}\n`)
  process.exit(1)
})
