#!/usr/bin/env node
/**
 * Vendors the pdf.js runtime into the published /create/ tree so PDF extraction runs entirely
 * from our own origin (no third-party CDN, CSP `script-src 'self'` + `worker-src 'self'`).
 *
 * Copies the minified ESM main + worker from the pdfjs-dist dependency into
 * landing/create/lib/pdfjs/. Run as part of build:landing (after build:browser, which creates
 * landing/create/lib). landing/create/lib is .gitignored — these are build artifacts, regenerated
 * on deploy from the pinned pdfjs-dist version in package.json.
 *
 * pdf.js is used ONLY as a browser input tool (PDF -> text); the extracted text is what gets
 * hashed and embedded, so the parser is fully swappable with no effect on any existing proof.
 */

import { copyFile, mkdir, stat } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..')
const distBuild = resolve(repoRoot, 'node_modules', 'pdfjs-dist', 'build')
const dst = resolve(repoRoot, 'landing', 'create', 'lib', 'pdfjs')

// The minified ESM build: smaller payload, lazy-loaded only when a PDF is dropped.
const FILES = ['pdf.min.mjs', 'pdf.worker.min.mjs']

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
    if (!(await exists(resolve(distBuild, name)))) {
      process.stderr.write(
        `vendor-pdfjs: missing ${resolve(distBuild, name)} — run \`npm install\` first ` +
          `(pdfjs-dist is a dependency)\n`,
      )
      process.exit(1)
    }
  }
  await mkdir(dst, { recursive: true })
  for (const name of FILES) {
    await copyFile(resolve(distBuild, name), resolve(dst, name))
    process.stderr.write(`vendor-pdfjs: ${name} -> ${resolve(dst, name)}\n`)
  }
}

main().catch((err) => {
  process.stderr.write(`vendor-pdfjs: ${err?.stack ?? err}\n`)
  process.exit(1)
})
