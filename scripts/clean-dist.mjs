#!/usr/bin/env node
/**
 * Remove dist/ before a fresh `tsc` build. tsc is incremental and never deletes
 * the compiled output of a source file that was itself deleted — so a stale
 * artifact (e.g. a removed module) would otherwise linger in dist/ and, because
 * dist/ is in package.json `files`, get published. Clean first so the published
 * tarball reflects exactly the current source.
 */
import { rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const dist = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist')
rmSync(dist, { recursive: true, force: true })
