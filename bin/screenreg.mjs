#!/usr/bin/env node
// Thin shim that runs the TS CLI via tsx (dev convenience) or the compiled
// dist/cli/main.js if tsx isn't available. After `npm run build`, the compiled
// path is faster.
import { existsSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(__dirname, '..')
const distMain = join(repoRoot, 'dist', 'cli', 'main.js')
const srcMain = join(repoRoot, 'src', 'cli', 'main.ts')

if (existsSync(distMain)) {
  await import(distMain)
} else {
  // Dev mode: run via tsx
  const result = spawnSync('npx', ['tsx', srcMain, ...process.argv.slice(2)], { stdio: 'inherit' })
  process.exit(result.status ?? 1)
}
