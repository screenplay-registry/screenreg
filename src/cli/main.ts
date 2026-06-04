/**
 * The Screenplay Registry — CLI entry point.
 *
 * Subcommands:
 *   register <file>            — normalize, build claim, stamp via OTS, emit one .screenreg (--evidence adds a shareable twin; --loose for separate files)
 *   verify <file.screenreg> | <file> <env> <ots>  — binary OK/FAILED verification
 *   diagnose <file> [env] [ots] — honest transform analysis (mode matrix per spec §6)
 *   finalize <ots|.screenreg> — fold in the Bitcoin attestation once confirmed (alias: upgrade)
 *   normalize <file>           — debug: print normalized bytes + hash
 *   claim <file>               — debug: build committedClaim + print claimHash
 *   scene-prove <file> <env> <sceneIndex>  — generate selective-disclosure proof
 *   scene-verify <root> <sceneContent-base64> <proof-json>
 *   decrypt-field <env> <fieldName>  — prompts for password, decrypts and prints field
 */

import { readFileSync, writeFileSync, existsSync, readSync, openSync, writeSync, closeSync, fchmodSync, lstatSync, unlinkSync, mkdirSync } from 'node:fs'
import { basename, dirname, join, resolve, sep } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createInterface } from 'node:readline'
import { normalize, contentHash, contentHashOfNormalized } from '../normalize/v1-strict.js'
import { buildCommittedClaim, buildEnvelope, checkEnvelopeConsistency } from '../envelope/build.js'
import { validateEnvelope } from '../envelope/validate.js'
import { computeClaimHash, computeClaimHashBytes } from '../envelope/claim-hash.js'
import {
  detectScenes,
  buildSceneTree,
  buildSceneProof,
  verifySceneProof,
  detectParagraphsWithPositions,
  buildParagraphTree,
  PROFILE_ID as MERKLE_PROFILE,
} from '../merkle/scene-tree.js'
import { compareBundles, formatComparisonReport } from '../similarity/jaccard.js'
import {
  buildComparisonBundle,
  type ComparisonBundle,
  verifyBundleAgainstClaim,
} from '../similarity/comparison-bundle.js'
import {
  generateKeypair,
  loadPrivateKey,
  signChallenge,
  signRegistration,
  verifySignature,
  verifyRegistrationSignature,
} from '../identity/ed25519-signing.js'
import { timelockEncrypt, timelockDecrypt } from '../timelock/drand.js'
import { submitOts } from '../anchors/ots-submit.js'
import { verifyOtsAgainstFileDigest, parseOts } from '../anchors/ots-verify.js'
import { finalizeProof, type FinalizeOptions } from '../shared/finalize/index.js'
import {
  buildScreenreg,
  buildEvidenceScreenreg,
  readScreenreg,
  unzipStore,
  ScreenregError,
  ENTRY_DESCRIPTOR,
  type BuildBundleInput,
} from '../shared/screenreg/index.js'
import type { Envelope as SharedEnvelope } from '../shared/envelope/types.js'
import { BANNER } from './banner.js'
import { startSpinner, formatDuration, countdownSleep } from './progress.js'
import { verifyAttestationsWithSources, type BitcoinHeaderSource, type SpvOutcome } from '../anchors/bitcoin-spv.js'
import { makeBitcoinRpcSource, makeExplorerSource, type ExplorerName } from '../anchors/bitcoin-header-sources.js'
import {
  buildEncryptedFieldsBlock,
  decryptFieldsBlock,
  type EncryptedFieldsBlock,
} from '../encrypt/fields.js'
import type { Envelope, EthereumAnchorProof, EvidenceProof } from '../envelope/types.js'
import { CANONICAL_CHAIN_ID, ETHEREUM_ANCHOR_EVIDENCE_PROFILE } from '../anchors/eth/constants.js'
import {
  verifyEthAnchor,
  type EthAnchorResult,
  type EthLog,
  type EthLogProvider,
} from '../anchors/eth/verify-eth-anchor.js'
import {
  buildRegistryRecord,
  validateRegistryRecord,
  type RegistryRecord,
} from '../registry/record.js'
import {
  verifyIndexSnapshot,
  type LoadOtsProof,
  type RegistrySnapshot,
} from '../registry/verify-index.js'
import { resolvePriority, type PriorityContender } from '../registry/priority.js'

const CLI_NAME = 'screenreg' // The Screenplay Registry

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function die(msg: string, code = 1): never {
  process.stderr.write(`${CLI_NAME}: ${msg}\n`)
  process.exit(code)
}

/**
 * Write sensitive content (private keys, private comparison bundles) with
 * defensive file-system hygiene:
 *
 *   1. Refuse to follow a symlink at the target path (lstat check). Without
 *      this, an attacker who controls the directory could symlink the target
 *      to a sensitive file they want overwritten.
 *   2. Open with O_CREAT|O_EXCL|O_WRONLY ('wx') — fail if the file already
 *      exists. Combined with the lstat check this prevents TOCTOU between
 *      "does this exist?" and "open it for write."
 *   3. Set 0o600 mode at create time via openSync's mode arg, then double-
 *      enforce with fchmodSync after write (some umask configurations
 *      override the create-time mode; the explicit fchmod is the belt to
 *      the suspenders).
 *   4. Restrictive umask isn't enough on its own — relying on the user's
 *      umask is hostile to anyone whose umask is 022.
 *
 * Use this for: Ed25519 private-key PEMs, the private comparison-disclosure
 * bundle (which contains membership-oracle material), and anywhere else a
 * file's permissions are part of the security contract.
 */
function writeSensitiveFileExclusive(path: string, content: string | Buffer): void {
  // Reject pre-existing symlink targeting elsewhere
  if (existsSync(path)) {
    try {
      const st = lstatSync(path)
      if (st.isSymbolicLink()) {
        die(`refusing to follow symlink at sensitive output path: ${path}`)
      }
    } catch {
      // existsSync said yes but lstat fails — pathological race; abort.
      die(`unable to stat sensitive output path: ${path}`)
    }
    // Pre-existing regular file at target — refuse so we never silently
    // overwrite (the caller can unlink explicitly if intentional).
    die(`refusing to overwrite existing file at sensitive output path: ${path}`)
  }
  const O_CREAT = 0o100
  const O_EXCL = 0o200
  const O_WRONLY = 0o1
  let fd: number
  try {
    // O_CREAT | O_EXCL | O_WRONLY — exclusive create, fail on race
    fd = openSync(path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
  } catch (err) {
    die(`failed to exclusively create ${path}: ${err instanceof Error ? err.message : String(err)}`)
  }
  try {
    const buf = typeof content === 'string' ? Buffer.from(content, 'utf8') : content
    writeSync(fd, buf, 0, buf.length, 0)
    // Belt + suspenders: force 0o600 even if umask interfered with create mode.
    fchmodSync(fd, 0o600)
  } catch (err) {
    // Cleanup on failure: try to remove the partial file
    try {
      closeSync(fd)
    } catch {
      // ignore
    }
    try {
      unlinkSync(path)
    } catch {
      // ignore
    }
    die(`failed to write ${path}: ${err instanceof Error ? err.message : String(err)}`)
  }
  closeSync(fd)
}

function getEnvelopeOutputPath(inputFile: string): string {
  const base = basename(inputFile)
  return join(dirname(inputFile), `${base}.manifest.json`)
}

function getOtsOutputPath(inputFile: string): string {
  const base = basename(inputFile)
  return join(dirname(inputFile), `${base}.proof.ots`)
}

function getScreenregOutputPath(inputFile: string): string {
  const base = basename(inputFile).replace(/\.(fountain|txt)$/i, '')
  return join(dirname(inputFile), `${base}.screenreg`)
}

function getEvidenceScreenregOutputPath(inputFile: string): string {
  const base = basename(inputFile).replace(/\.(fountain|txt)$/i, '')
  return join(dirname(inputFile), `${base}.evidence.screenreg`)
}

/**
 * Hard cap on envelope/bundle JSON inputs. Legitimate v1 envelopes are <10 KB
 * even with full scene+paragraph trees in committed roots + a registrant block
 * + a few timelock fields. Comparison disclosure bundles can be larger because
 * they carry per-leaf hash arrays, but a screenplay with >50,000 paragraphs is
 * already adversarial. 16 MiB is generous for any legitimate v1 input and
 * stops the obvious DoS where an attacker submits a 4 GB JSON blob.
 */
const MAX_JSON_INPUT_BYTES = 16 * 1024 * 1024

function readJsonFileBounded<T>(path: string, label: string): T {
  if (!existsSync(path)) die(`${label} file not found: ${path}`)
  // Use lstat to also reject symlinks pointed at sensitive files — readFileSync
  // would follow them. For verify-only inputs the symlink isn't a security
  // issue per se (we don't write back), but it's a smell worth surfacing.
  const st = lstatSync(path)
  if (st.size > MAX_JSON_INPUT_BYTES) {
    die(`${label} file too large: ${st.size} bytes (max ${MAX_JSON_INPUT_BYTES})`)
  }
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as T
  } catch (e: any) {
    die(`failed to parse ${label} JSON: ${e?.message ?? e}`)
  }
}

function readEnvelope(path: string): Envelope {
  return readJsonFileBounded<Envelope>(path, 'envelope')
}

/**
 * Resolve a proof reference that MUST live beside a base file, with hard
 * path-traversal containment. A registry snapshot names its `.ots` proofs by
 * a snapshot-relative `proofRef`; a hostile snapshot could try to point that
 * reference at an arbitrary file (`/etc/shadow`, `../../secret.key`) or hide a
 * traversal behind a symlink. The contract here is deliberately narrow:
 *
 *   1. `proofRef` MUST be a bare relative path — absolute paths are rejected.
 *   2. After resolution it MUST stay strictly inside `baseDir` — any `..` that
 *      escapes (even via an internal segment) is rejected.
 *   3. Neither the resolved target nor any path segment may be a symlink —
 *      checked with `lstatSync`, never `statSync`, so a symlink pointing
 *      outside `baseDir` cannot smuggle the read past the containment check.
 *
 * Returns the absolute, contained path. Throws (never returns a path) on any
 * violation so the caller fails closed.
 */
function resolveSiblingProof(baseDir: string, proofRef: string): string {
  if (typeof proofRef !== 'string' || proofRef.length === 0) {
    throw new Error('proofRef must be a non-empty string')
  }
  // Reject absolute references outright (POSIX `/...` and Windows `C:\...`/UNC).
  if (proofRef.startsWith('/') || proofRef.startsWith('\\') || /^[A-Za-z]:[\\/]/.test(proofRef)) {
    throw new Error(`proofRef must be relative, got absolute path: ${proofRef}`)
  }
  const base = resolve(baseDir)
  const target = resolve(base, proofRef)
  // Containment: the resolved target must be `base` itself or a descendant.
  // The trailing separator on the prefix stops `/base-evil` matching `/base`.
  if (target !== base && !target.startsWith(base + sep)) {
    throw new Error(`proofRef escapes the snapshot directory: ${proofRef}`)
  }
  // Walk every path segment from base down to the target and reject any symlink.
  // Resolving first then re-checking with lstat closes the gap where a symlink
  // segment would otherwise let `target` land outside `base`.
  let cursor = base
  const rel = target.slice(base.length).split(sep).filter((s) => s.length > 0)
  for (const segment of rel) {
    cursor = join(cursor, segment)
    let st
    try {
      st = lstatSync(cursor)
    } catch {
      throw new Error(`proofRef does not resolve to an existing file: ${proofRef}`)
    }
    if (st.isSymbolicLink()) {
      throw new Error(`proofRef path contains a symlink (rejected): ${proofRef}`)
    }
  }
  return target
}

/**
 * Hard cap on screenplay-input file size. A finished feature screenplay is
 * ~100-150 pages = ~250-400 KB normalized. Multi-act mini-series scripts top
 * out around 1-2 MB. 32 MiB is well above any legitimate screenplay and blocks
 * the obvious OOM-DoS where an attacker hands a writing-app integrator a
 * multi-gigabyte "screenplay" to register.
 */
const MAX_SCREENPLAY_INPUT_BYTES = 32 * 1024 * 1024

/**
 * Heuristic password-entropy warning for the encryption flow.
 *
 * v1 uses PBKDF2-HMAC-SHA256 at 600,000 iterations — CPU-hard but NOT memory-
 * hard (per threat-model.md "Adversaries this protocol does NOT defend
 * against" #4). Stolen manifests allow GPU/ASIC-accelerated offline guessing
 * at 10⁶–10⁸ candidates/sec; a weak password is genuinely at risk.
 *
 * This is a heuristic, not a policy — we don't block weak passwords (some
 * users have legitimate reasons for short passwords, and a strict policy
 * pushes people to write them down). Instead, surface the risk so the user
 * can make an informed choice.
 *
 * Triggers warning if ANY of: length < 12, all lowercase letters, present
 * in a small common-password list. Each trigger explains specifically why.
 */
function warnIfWeakPassword(password: string): void {
  const concerns: string[] = []
  if (password.length < 12) {
    concerns.push(`only ${password.length} characters (< 12 — a 12-char random password is ~80 bits entropy; below that, GPU offline guessing becomes practical)`)
  }
  if (/^[a-z]+$/.test(password)) {
    concerns.push('only lowercase letters (no digits, uppercase, or symbols → much lower entropy per char)')
  }
  const trivial = new Set(['password', 'hunter2', '12345678', 'letmein', 'qwerty', 'screenplay'])
  if (trivial.has(password.toLowerCase())) {
    concerns.push('appears in the trivial-password list (cracked instantly)')
  }
  if (concerns.length > 0) {
    process.stderr.write(`⚠  Weak password warning:\n`)
    for (const c of concerns) process.stderr.write(`     • ${c}\n`)
    process.stderr.write(
      `   v1 KDF (PBKDF2-HMAC-SHA256 @ 600k iter) is NOT memory-hard. For\n` +
        `   maximum offline-attack resistance, use a passphrase of ≥4 random\n` +
        `   dictionary words OR a password manager-generated random string\n` +
        `   ≥16 chars with mixed case + digits + symbols. v2 will migrate to\n` +
        `   Argon2id (memory-hard).\n`,
    )
  }
}

function readScreenplayBounded(path: string): Buffer {
  if (!existsSync(path)) die(`input file not found: ${path}`)
  const st = lstatSync(path)
  if (st.size > MAX_SCREENPLAY_INPUT_BYTES) {
    die(`input screenplay too large: ${st.size} bytes (max ${MAX_SCREENPLAY_INPUT_BYTES})`)
  }
  return readFileSync(path)
}

/**
 * Read a password with priority: file > env > prompt.
 *
 *   1. SCREENREG_PASSWORD_FILE  — preferred. Path to a file containing the
 *      password as its first line. Recommended for scripts/CI (the file
 *      contents are not visible in `ps`, shell history, or environment dumps).
 *   2. SCREENREG_PASSWORD       — env var. Convenient but LEAKS via process
 *      environment dumps (`/proc/$pid/environ`, `ps eww` on some platforms).
 *      We warn once on stderr when this path is taken.
 *   3. Interactive prompt       — best for human use; doesn't touch argv or env.
 *      v0.x note: this CLI does not yet disable TTY echo while reading the
 *      password (Node lacks first-class support without a native module). Use
 *      SCREENREG_PASSWORD_FILE for unattended workflows; assume stdin echo is
 *      visible to anyone watching the terminal.
 *
 * Anti-pattern: passing the password as a `--password` CLI argument. The argv
 * is visible to every process on the host via `ps`. We accept `--password`
 * for backwards-compat but warn loudly when used.
 */
async function readPassword(prompt: string): Promise<string> {
  const passwordFile = process.env.SCREENREG_PASSWORD_FILE
  if (passwordFile && passwordFile.length > 0) {
    if (!existsSync(passwordFile)) die(`SCREENREG_PASSWORD_FILE not found: ${passwordFile}`)
    const contents = readFileSync(passwordFile, 'utf8')
    return contents.split('\n')[0] ?? ''
  }
  if (process.env.SCREENREG_PASSWORD) {
    process.stderr.write(
      `⚠  Reading password from SCREENREG_PASSWORD env var. Note: process environment\n` +
        `   variables can leak via /proc/<pid>/environ, ps eww, or container introspection.\n` +
        `   For unattended workflows prefer SCREENREG_PASSWORD_FILE=<path>.\n`,
    )
    return process.env.SCREENREG_PASSWORD
  }
  process.stderr.write(prompt)
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: false })
  try {
    for await (const line of rl) return line
    return ''
  } finally {
    rl.close()
  }
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

interface RegisterOptions {
  inputFile: string
  encryptTitle?: string
  encryptAuthor?: string
  trainingMining?: 'allowed' | 'notAllowed' | 'constrained'
  noSceneTree?: boolean
  mock?: boolean
  /** Emit the loose manifest + .ots (+ .pem) instead of a single .screenreg (integrator path). */
  loose?: boolean
  /**
   * Additionally emit a proof-only `.evidence.screenreg` (no screenplay) next to the
   * full bundle, mirroring the browser's keep-file + shareable-file pair. Default mode only.
   */
  evidence?: boolean
  envelopeOut?: string
  otsOut?: string
  password?: string
  /** Generate an Ed25519 keypair + write the public key into committedClaim.registrantPublicKey */
  identity?: boolean
  /** Path to write the PEM-encoded private key (used with --identity) */
  identityKeyOut?: string
  /** Parent registration's claim hash (for revision lineage) */
  previousClaimHash?: string
  /**
   * Path to the source PDF this Fountain was extracted from. When set, the
   * envelope records `evidenceBundle.bundleExtensions.sourceExtractor` so an
   * archival verifier can prove the registered text came from the asserted
   * PDF (by hashing the PDF and matching against the recorded sha256).
   */
  sourcePdf?: string
}

async function cmdRegister(opts: RegisterOptions): Promise<void> {
  // Validate flag combinations BEFORE any stamping, key generation, or sidecar
  // writes — a rejected invocation must never leave a private key or comparison
  // bundle on disk. --evidence (the proof-only twin of the single-file default)
  // is meaningless alongside the loose separate-files output.
  const looseMode = !!opts.loose || opts.envelopeOut !== undefined || opts.otsOut !== undefined
  if (opts.evidence && looseMode) {
    die('register: --evidence emits a proof-only .screenreg and is incompatible with --loose / --envelope-out / --ots-out')
  }

  const raw = readScreenplayBounded(opts.inputFile)
  const normResult = normalize(raw)
  if (!normResult.ok) die(`normalization failed: ${normResult.detail}`)
  const cHash = contentHashOfNormalized(normResult.normalized)

  // Build scene + paragraph trees. We commit only the ROOTS in the claim; the
  // leaves are saved separately to a private comparison-disclosure bundle that
  // the writer can optionally publish later. This avoids the membership-oracle
  // attack of publishing the full leaf array in the public claim.
  let sceneTreeBuilt: ReturnType<typeof buildSceneTree> | undefined
  let scenesDetected: ReturnType<typeof detectScenes> | undefined
  let paragraphTreeBuilt: ReturnType<typeof buildParagraphTree> | undefined
  let paragraphsDetected: ReturnType<typeof detectParagraphsWithPositions> | undefined
  if (!opts.noSceneTree) {
    scenesDetected = detectScenes(normResult.normalized)
    if (scenesDetected.length > 0) {
      sceneTreeBuilt = buildSceneTree(scenesDetected)
    }
    paragraphsDetected = detectParagraphsWithPositions(normResult.normalized)
    if (paragraphsDetected.length > 0) {
      paragraphTreeBuilt = buildParagraphTree(paragraphsDetected)
    }
  }

  let encryptedFields: EncryptedFieldsBlock | undefined
  if (opts.encryptTitle !== undefined || opts.encryptAuthor !== undefined) {
    const password = opts.password ?? (await readPassword('Encryption password: '))
    if (!password) die('encryption requested but no password provided')
    warnIfWeakPassword(password)
    const plaintextFields: Record<string, string> = {}
    if (opts.encryptTitle !== undefined) plaintextFields.title = opts.encryptTitle
    if (opts.encryptAuthor !== undefined) plaintextFields.author = opts.encryptAuthor
    encryptedFields = buildEncryptedFieldsBlock({
      password,
      claimVersion: 'urn:screenplay-registration-claim:v1',
      plaintextFields,
    })
  }

  // Identity binding: generate fresh keypair if requested. The signature is
  // computed AFTER the rest of the claim is built (over the claim body
  // canonical-JSON-hash) then inserted as the `registrant` field. Two-phase
  // signing per spec §06.
  let keypair: ReturnType<typeof generateKeypair> | undefined
  if (opts.identity) {
    keypair = generateKeypair()
    const keyOutPath = opts.identityKeyOut ?? `${opts.inputFile}.private-key.pem`
    writeSensitiveFileExclusive(keyOutPath, keypair.privateKeyPem)
    process.stderr.write(`  Identity key written to ${keyOutPath} (0600, exclusive create — keep it safe!)\n`)
  }

  // Phase 1: build claim body (without registrant)
  const claimBody = buildCommittedClaim({
    contentHash: cHash,
    ...(sceneTreeBuilt !== undefined
      ? { sceneTree: { root: sceneTreeBuilt.root, count: sceneTreeBuilt.sceneCount } }
      : {}),
    ...(paragraphTreeBuilt !== undefined
      ? {
          paragraphTree: {
            root: paragraphTreeBuilt.root,
            count: paragraphTreeBuilt.paragraphCount,
          },
        }
      : {}),
    ...(opts.previousClaimHash !== undefined
      ? { previousRegistration: { claimHash: opts.previousClaimHash } }
      : {}),
    ...(encryptedFields !== undefined ? { encryptedFields } : {}),
    ...(opts.trainingMining !== undefined
      ? { preferences: { trainingMining: opts.trainingMining } }
      : {}),
  })

  // Phase 2: if identity requested, sign the claim body and add the registrant block.
  // The signature is computed over the body's canonical-JSON-digest; the resulting
  // registrant block is then added to the claim, so the FINAL claim hash (OTS-anchored)
  // is computed over the claim INCLUDING the signature.
  let claim = claimBody
  if (keypair) {
    const privateKey = loadPrivateKey(keypair.privateKeyPem)
    const registrantBlock = signRegistration(claimBody, privateKey, keypair.publicKeyEncoded)
    claim = { ...claimBody, registrant: registrantBlock }
  }

  const claimHashBytes = computeClaimHashBytes(claim)
  const claimHash = `sha256:${claimHashBytes.toString('hex')}`

  // quietLabel preserves the pre-spinner behavior: this line was always printed,
  // including under a pipe, so keep it byte-identical for non-interactive callers.
  const stopStamp = startSpinner('Stamping claim hash via OpenTimestamps...', { quietLabel: true })
  const stampResult = await submitOts({ digest: claimHashBytes, mock: !!opts.mock })
  stopStamp()
  if (!stampResult.ok) {
    die(`OTS submission failed: ${stampResult.reason}${stampResult.stderr ? '\n' + stampResult.stderr : ''}`)
  }

  const otsOutputPath = opts.otsOut ?? getOtsOutputPath(opts.inputFile)

  // Save the private comparison-disclosure data (the leaves) to a sidecar file.
  // This file is NEVER part of the public registration; the writer keeps it
  // privately and can opt to publish it via `screenreg disclose-comparison`
  // when a dispute or comparison is needed.
  if (sceneTreeBuilt || paragraphTreeBuilt) {
    const bundle = buildComparisonBundle({
      claimHash,
      ...(sceneTreeBuilt && scenesDetected
        ? { scenes: { tree: sceneTreeBuilt, scenes: scenesDetected } }
        : {}),
      ...(paragraphTreeBuilt && paragraphsDetected
        ? { paragraphs: { tree: paragraphTreeBuilt, paragraphs: paragraphsDetected } }
        : {}),
    })
    const bundlePath = `${opts.inputFile}.comparison-bundle.private.json`
    // Sensitive: contains per-leaf hashes (membership-oracle material if leaked).
    // 0600 + exclusive create. If a stale bundle exists at the path, refuse +
    // require explicit cleanup — silent overwrite would mask whether the user
    // accidentally re-ran register on top of an existing registration.
    writeSensitiveFileExclusive(bundlePath, JSON.stringify(bundle, null, 2) + '\n')
    process.stderr.write(`  Private comparison bundle: ${bundlePath} (0600, exclusive create — KEEP PRIVATE)\n`)
  }

  // If the writer registered a Fountain that was extracted from a PDF, record
  // the source-PDF provenance in evidenceBundle.bundleExtensions so an
  // archival verifier can prove the Fountain was derived from the asserted
  // PDF. The sourceExtractor block captures the extractor identity, the SHA-256
  // of the PDF bytes, and the SHA-256 of the extracted Fountain bytes; a
  // verifier reproduces the extraction and checks both hashes.
  const bundleExtensions: Record<string, unknown> = {}
  if (opts.sourcePdf !== undefined) {
    let pdfBytes: Buffer
    try {
      pdfBytes = readFileSync(opts.sourcePdf)
    } catch (err) {
      die(
        `--source-pdf: cannot read ${opts.sourcePdf}: ${err instanceof Error ? err.message : String(err)}`,
      )
    }
    const { createHash } = await import('node:crypto')
    const pdfDigest = 'sha256:' + createHash('sha256').update(pdfBytes).digest('hex')
    const fountainDigest = cHash
    const { ReferenceExtractor } = await import('../extractors/reference/index.js')
    const extractor = new ReferenceExtractor()
    bundleExtensions.sourceExtractor = {
      name: extractor.name,
      version: extractor.version,
      sourcePdfSha256: pdfDigest,
      extractedFountainSha256: fountainDigest,
      sourcePdfFilename: basename(opts.sourcePdf),
    }
  }

  const envelope = buildEnvelope(claim, {
    proofs: [
      {
        type: 'opentimestamps',
        claimHash,
        proofRef: basename(otsOutputPath),
        submittedAt: new Date().toISOString(),
      },
    ],
    bundleExtensions,
  })

  // Output. By default, emit a single self-contained .screenreg (full bundle, embedding the
  // source). Integrators who pass --loose / --envelope-out / --ots-out get the loose manifest +
  // .ots instead. The private .pem (if --identity) and comparison bundle are always separate
  // sidecars — a private key and membership-oracle leaves never belong in a one-file deliverable.
  process.stderr.write(`\n✓ Registration complete.\n`)
  process.stderr.write(`  Claim hash: ${claimHash}\n`)
  if (looseMode) {
    writeFileSync(otsOutputPath, stampResult.otsBytes)
    const envelopeOutputPath = opts.envelopeOut ?? getEnvelopeOutputPath(opts.inputFile)
    writeFileSync(envelopeOutputPath, JSON.stringify(envelope, null, 2) + '\n')
    process.stderr.write(`  Envelope:   ${envelopeOutputPath}\n`)
    process.stderr.write(`  OTS proof:  ${otsOutputPath}\n`)
  } else {
    const bundlePath = getScreenregOutputPath(opts.inputFile)
    let bundle: Uint8Array
    try {
      bundle = await buildScreenreg({
        envelope: envelope as unknown as SharedEnvelope,
        otsBytes: stampResult.otsBytes,
        sourceText: new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength),
      })
    } catch (err) {
      die(`register: could not assemble .screenreg: ${err instanceof ScreenregError ? err.message : String(err)}`)
    }
    writeFileSync(bundlePath, bundle)
    process.stderr.write(`  Bundle:     ${bundlePath} (${bundle.length} bytes — your screenplay + proof in one file)\n`)
    if (opts.evidence) {
      // The shareable proof-only twin: same claim + proof, no screenplay text. Mirrors the
      // browser handing the user both a keep-file and a send-file.
      let evidenceBundle: Uint8Array
      try {
        evidenceBundle = await buildEvidenceScreenreg({
          envelope: envelope as unknown as SharedEnvelope,
          otsBytes: stampResult.otsBytes,
        })
      } catch (err) {
        die(`register: could not assemble the evidence .screenreg: ${err instanceof ScreenregError ? err.message : String(err)}`)
      }
      const evidencePath = getEvidenceScreenregOutputPath(opts.inputFile)
      writeFileSync(evidencePath, evidenceBundle)
      process.stderr.write(`  Shareable:  ${evidencePath} (${evidenceBundle.length} bytes — proof only, no screenplay; safe to send)\n`)
    }
  }
  if (opts.mock) {
    process.stderr.write(`  (Mock mode — proof is a placeholder, not anchored to Bitcoin.)\n`)
  } else {
    const finalizeArg = looseMode ? otsOutputPath : getScreenregOutputPath(opts.inputFile)
    process.stderr.write(`  Bitcoin confirmation typically takes 1-6 hours. Run \`${CLI_NAME} finalize ${finalizeArg}\` later.\n`)
  }
}

interface VerifyOptions {
  inputFile: string
  envelopePath: string
  otsPath: string
  verbose?: boolean
  /**
   * When true, verify exits with status 2 if the .ots proof is not yet
   * Bitcoin-anchored (still pending calendar attestations OR has no
   * attestations at all). Default false — pending proofs still exit 0
   * with the headline warning. Useful for CI / scripted contexts that
   * MUST gate on independent Bitcoin verifiability.
   */
  requireBitcoinAnchor?: boolean
  /**
   * Optional Ethereum JSON-RPC endpoint. When set AND the envelope carries an
   * `ethereum-anchor` proof, verify runs a topics-only on-chain check and prints
   * the result as INFORMATIONAL. The Ethereum anchor is a secondary witness: its
   * result NEVER changes the Bitcoin OK/FAILED verdict or the exit status.
   */
  ethRpc?: string
  /** Confirmations required for the Ethereum anchor to count as final. */
  ethMinConfirmations?: number
  /** Bitcoin block-header sources for SPV; tried in order (node first, explorer fallback). */
  headerSources?: BitcoinHeaderSource[]
}

/** The subset of verify options the optional Ethereum-anchor report reads. */
interface EthAnchorReportOptions {
  ethRpc?: string
  ethMinConfirmations?: number
}

/**
 * Inputs to the shared verification core. `raw` is the screenplay bytes used to
 * re-derive the contentHash + scene/paragraph Merkle trees; when it is
 * undefined, verification runs DATE-ONLY — the OTS proof and the envelope's
 * internal consistency are checked, but the screenplay contents are NOT. That
 * matches verifying a proof-only `.evidence.screenreg` (or a `.screenreg`
 * supplied without its screenplay): the date is proven, the contents are not.
 */
interface VerifyCoreInputs {
  raw?: Buffer
  envelope: Envelope
  otsBytes: Uint8Array | Buffer
  /** Path shown in the "verify the Bitcoin header yourself" hint. */
  otsHintPath: string
  /** True when otsHintPath is a `.screenreg` (the hint tells the user to unpack first). */
  otsHintIsBundle?: boolean
  requireBitcoinAnchor?: boolean
  ethRpc?: string
  ethMinConfirmations?: number
  verbose?: boolean
  /** Bitcoin block-header sources for SPV; tried in order (node first, explorer fallback). */
  headerSources?: BitcoinHeaderSource[]
}

interface VerifyBundleOptions {
  bundlePath: string
  /** Optional external screenplay, used to confirm contents when the bundle is proof-only. */
  scriptPath?: string
  requireBitcoinAnchor?: boolean
  ethRpc?: string
  ethMinConfirmations?: number
  verbose?: boolean
  headerSources?: BitcoinHeaderSource[]
}

/**
 * Shared verification core for both the loose 3-file path (`cmdVerify`) and the
 * single-file `.screenreg` path (`cmdVerifyBundle`). When `inputs.raw` is
 * present the screenplay contents are re-derived and checked; when it is absent
 * the run is date-only (envelope consistency + OTS proof, contents NOT checked).
 */
async function verifyCore(inputs: VerifyCoreInputs): Promise<void> {
  const { envelope } = inputs
  const otsBytes = Buffer.from(inputs.otsBytes)
  const contentsChecked = inputs.raw !== undefined

  // 0. Validate envelope shape against the v1 schema BEFORE any cryptographic
  // work. If the envelope is malformed by shape (wrong locked values, partial
  // all-or-none triples, junk preference enum, malformed registrant block),
  // recomputing the hash gives a value but the value is meaningless — the
  // verifier must reject. Per spec/v1/02-envelope.md verifier obligations.
  const shape = validateEnvelope(envelope)
  if (!shape.ok) {
    process.stdout.write(`✗ FAILED — envelope does not conform to v1 schema\n`)
    for (const e of shape.errors) {
      process.stdout.write(`  • ${e}\n`)
    }
    process.exit(2)
  }

  // 1–2b. Re-derive contentHash + Merkle trees from the screenplay. Skipped
  // entirely for a date-only run (proof-only bundle, no screenplay supplied).
  let recomputedContentHash: string | undefined
  if (inputs.raw !== undefined) {
    const normResult = normalize(inputs.raw)
    if (!normResult.ok) {
      process.stdout.write(`✗ FAILED — the screenplay is not valid UTF-8\n`)
      if (inputs.verbose) process.stdout.write(`  ${normResult.detail}\n`)
      process.exit(2)
    }
    recomputedContentHash = contentHashOfNormalized(normResult.normalized)
    if (recomputedContentHash !== envelope.committedClaim.contentHash) {
      process.stdout.write(
        `✗ FAILED — content hash mismatch\n` +
          `  Screenplay hashes to: ${recomputedContentHash}\n` +
          `  Record expects:       ${envelope.committedClaim.contentHash}\n` +
          `  (Use \`${CLI_NAME} diagnose\` for detailed transform analysis.)\n`,
      )
      process.exit(2)
    }

    // Recompute scene tree (if committed)
    if (envelope.committedClaim.sceneTreeRoot !== undefined) {
      const scenes = detectScenes(normResult.normalized)
      if (scenes.length !== envelope.committedClaim.sceneCount) {
        process.stdout.write(
          `✗ FAILED — scene count mismatch\n` +
            `  Screenplay has:  ${scenes.length} scenes\n` +
            `  Record expects:  ${envelope.committedClaim.sceneCount} scenes\n`,
        )
        process.exit(2)
      }
      const tree = buildSceneTree(scenes)
      if (tree.root !== envelope.committedClaim.sceneTreeRoot) {
        process.stdout.write(
          `✗ FAILED — scene tree root mismatch\n` +
            `  Screenplay computes: ${tree.root}\n` +
            `  Record expects:      ${envelope.committedClaim.sceneTreeRoot}\n`,
        )
        process.exit(2)
      }
    }

    // Recompute paragraph tree (if committed). Per spec §05 §4, the verifier
    // applies the same recomputation rules as for the scene tree.
    if (envelope.committedClaim.paragraphTreeRoot !== undefined) {
      const paragraphs = detectParagraphsWithPositions(normResult.normalized)
      if (paragraphs.length !== envelope.committedClaim.paragraphCount) {
        process.stdout.write(
          `✗ FAILED — paragraph count mismatch\n` +
            `  Screenplay has:  ${paragraphs.length} paragraphs\n` +
            `  Record expects:  ${envelope.committedClaim.paragraphCount} paragraphs\n`,
        )
        process.exit(2)
      }
      const ptree = buildParagraphTree(paragraphs)
      if (ptree.root !== envelope.committedClaim.paragraphTreeRoot) {
        process.stdout.write(
          `✗ FAILED — paragraph tree root mismatch\n` +
            `  Screenplay computes: ${ptree.root}\n` +
            `  Record expects:      ${envelope.committedClaim.paragraphTreeRoot}\n`,
        )
        process.exit(2)
      }
    }
  }

  // 3. Recompute claimHash + check envelope consistency
  const recomputedClaimHash = computeClaimHash(envelope.committedClaim)
  const consistency = checkEnvelopeConsistency(envelope, recomputedClaimHash)
  if (!consistency.ok) {
    process.stdout.write(`✗ FAILED — envelope consistency error\n  ${consistency.detail}\n`)
    process.exit(2)
  }

  // 4. Verify .ots
  const otsResult = verifyOtsAgainstFileDigest({
    otsBytes,
    expectedFileDigest: Buffer.from(recomputedClaimHash.slice('sha256:'.length), 'hex'),
  })
  if (!otsResult.ok) {
    process.stdout.write(`✗ FAILED — .ots verification error\n  ${otsResult.reason}\n`)
    process.exit(2)
  }

  // 4b. Optional SPV: confirm the attested merkle root against real Bitcoin block
  // headers (a local node and/or public explorers). A genuine MISMATCH means the
  // proof claims an attestation the block does not bear — that is a hard failure.
  // An unreachable source degrades to informational (never fail a valid proof on
  // a network hiccup), like a pending proof or an unreachable ETH RPC.
  let spv: SpvOutcome | undefined
  if (inputs.headerSources && inputs.headerSources.length > 0 && otsResult.bitcoinAttestations.length > 0) {
    const stopSpv = startSpinner('Verifying the merkle root against Bitcoin block headers…')
    try {
      spv = await verifyAttestationsWithSources(otsResult.bitcoinAttestations, inputs.headerSources)
    } finally {
      stopSpv()
    }
    if (spv.status === 'mismatch') {
      process.stdout.write(
        `✗ FAILED — the proof does NOT match Bitcoin\n` +
          `  ${spv.reason}\n` +
          `  The .ots proof claims a Bitcoin attestation that the real block does not bear; it is invalid.\n`,
      )
      process.exit(2)
    }
  }

  // 5. Optional Ethereum-anchor check (INFORMATIONAL). The envelope is otherwise
  // Bitcoin-valid here; the ETH anchor is a secondary witness and its result
  // never changes the verdict below or the exit status. We compute it once and
  // print it on every success/pending/no-attestation path. The verifier is
  // passed the INDEPENDENTLY-RECOMPUTED claimHash (never proof.claimHash) for
  // both the topic filter and the comparison.
  const printEth = await prepareEthAnchorReport(envelope, recomputedClaimHash, inputs)

  // The contents line tells the reader whether the screenplay was actually
  // checked. A proof-only verification proves the DATE of a claim hash, not that
  // any particular screenplay matches it — say so plainly.
  const contentLine = contentsChecked
    ? `  Content hash:  ${recomputedContentHash}\n`
    : `  Content hash:  ${envelope.committedClaim.contentHash}  (from the record — screenplay not provided, so contents were NOT checked)\n`
  const claimLine = `  Claim hash:    ${recomputedClaimHash}\n`
  // Surface encrypted fields (title/author) when present: the field NAMES are
  // non-secret, the values stay ciphertext. So verify announces they exist and
  // are unlockable, without ever displaying them.
  const ef = envelope.committedClaim.encryptedFields
  // Field names are registrant-controlled; strip control chars + cap length so a
  // crafted .screenreg can't inject newlines/ANSI into the terminal output.
  // eslint-disable-next-line no-control-regex
  const safeName = (s: string): string => s.replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 64)
  const encLine =
    ef && ef.fields.length > 0
      ? `  Encrypted:     ${ef.fields.map((f) => safeName(f.name)).join(', ')} 🔒 present as ciphertext — unlock with your password (\`${CLI_NAME} decrypt-field\`)\n`
      : ''
  const dateOnlyTag = contentsChecked ? '' : ', DATE ONLY'
  // Alternative external block-header check, for when no in-process source was
  // supplied: a bare .ots verifies directly; a bundle must be unpacked first so
  // upstream `ots verify` has a .ots to read.
  const upstreamHint = inputs.otsHintIsBundle
    ? `        run \`${CLI_NAME} unpack ${inputs.otsHintPath} --out-dir out\` then upstream\n` +
      `        \`ots verify out/proof.ots\` against the opentimestamps-client.\n`
    : `        run upstream \`ots verify ${inputs.otsHintPath}\` against the opentimestamps-client.\n`

  // Status headline distinguishes Bitcoin-attestation-present vs pending vs
  // no-attestations, and contents-verified vs date-only. A casual reader who
  // stops at the first line MUST get the right impression of verification
  // strength.
  //
  // When --bitcoin-rpc/--explorer is supplied, this verifier fetches the real
  // block header and confirms the attested merkle root (step 4b); a mismatch
  // already exited above. Without a source it checks only the OTS proof
  // structure and says so, pointing the user at the in-process flags or upstream
  // `ots verify` for true block-header verification.
  if (otsResult.bitcoinAnchored) {
    process.stdout.write(
      contentsChecked
        ? `✓ VERIFIED — claim hash matches and a Bitcoin attestation is present in the .ots proof.\n`
        : `✓ VERIFIED (DATE ONLY) — a Bitcoin attestation is present for this claim hash. The\n` +
            `  screenplay contents were NOT checked; supply the screenplay to confirm them.\n`,
    )
    process.stdout.write(contentLine)
    process.stdout.write(claimLine)
    process.stdout.write(encLine)
    if (spv?.status === 'confirmed') {
      // Strongest result: the attested merkle root matches the real block header.
      for (const c of spv.confirmations) {
        const trust = c.trustless ? 'trustless — your own node' : `trusting ${c.sourceLabel}`
        process.stdout.write(
          `  Bitcoin block ${c.blockHeight}: merkle root CONFIRMED against the block header via ${c.sourceLabel} (${trust}).\n`,
        )
      }
    } else if (spv?.status === 'unreachable') {
      process.stdout.write(
        `  Bitcoin attestation: block heights ${otsResult.bitcoinBlockHeights.join(', ')} (parsed from .ots structure)\n` +
          `  NOTE: could not reach a block-header source to confirm the merkle root —\n` +
          `        ${spv.reason}.\n` +
          `        The structure-only result stands; retry with a reachable --bitcoin-rpc/--explorer.\n`,
      )
    } else {
      process.stdout.write(
        `  Bitcoin attestation: block heights ${otsResult.bitcoinBlockHeights.join(', ')} (parsed from .ots structure)\n` +
          `  NOTE: only the OTS proof structure was checked. To confirm the merkle root against\n` +
          `        real Bitcoin block headers, re-run with --bitcoin-rpc <url> (your own node,\n` +
          `        trustless) or --explorer mempool|blockstream. For an external check instead,\n` +
          upstreamHint,
      )
    }
    printEth()
    process.exit(0)
  }
  if (otsResult.pendingCalendarUrls.length > 0) {
    process.stdout.write(
      `⚠ VERIFIED (PENDING${dateOnlyTag}) — ${contentsChecked ? 'claim hash matches, but ' : ''}the .ots proof has NOT YET been confirmed on Bitcoin.\n`,
    )
    if (!contentsChecked) {
      process.stdout.write(`  (Screenplay contents were NOT checked; supply the screenplay to confirm them.)\n`)
    }
    process.stdout.write(contentLine)
    process.stdout.write(claimLine)
    process.stdout.write(encLine)
    process.stdout.write(
      `  Bitcoin block: PENDING — proof references calendars: ${otsResult.pendingCalendarUrls.join(', ')}\n` +
        `                 Run \`${CLI_NAME} finalize <ots|.screenreg>\` after ~1-6 hours to fold the\n` +
        `                 calendar attestation into a Bitcoin block proof.\n`,
    )
    process.stdout.write(
      `  Until upgraded, this proof depends on the calendar operator(s) above. It is NOT\n` +
        `  yet independently verifiable against Bitcoin block headers alone.\n`,
    )
    printEth()
    if (inputs.requireBitcoinAnchor) {
      process.stdout.write(`\n✗ FAILED — --require-bitcoin-anchor was set but the proof is still pending.\n`)
      process.exit(2)
    }
    process.exit(0)
  }
  process.stdout.write(
    `⚠ VERIFIED (NO ATTESTATIONS${dateOnlyTag}) — ${contentsChecked ? 'claim hash matches, but ' : ''}the .ots proof carries no\n` +
      `  attestations (placeholder / malformed?). The registration cannot be timestamp-verified\n` +
      `  against any external authority in its current state.\n`,
  )
  if (!contentsChecked) {
    process.stdout.write(`  (Screenplay contents were NOT checked; supply the screenplay to confirm them.)\n`)
  }
  process.stdout.write(contentLine)
  process.stdout.write(claimLine)
  process.stdout.write(encLine)
  printEth()
  if (inputs.requireBitcoinAnchor) {
    process.stdout.write(`\n✗ FAILED — --require-bitcoin-anchor was set but the proof has no attestations.\n`)
    process.exit(2)
  }
  process.exit(0)
}

/** Loose 3-file verification: screenplay + envelope.json + proof.ots. */
async function cmdVerify(opts: VerifyOptions): Promise<void> {
  const raw = readScreenplayBounded(opts.inputFile)
  const envelope = readEnvelope(opts.envelopePath)
  const otsBytes = readFileSync(opts.otsPath)
  await verifyCore({
    raw,
    envelope,
    otsBytes,
    otsHintPath: opts.otsPath,
    ...(opts.requireBitcoinAnchor !== undefined ? { requireBitcoinAnchor: opts.requireBitcoinAnchor } : {}),
    ...(opts.ethRpc !== undefined ? { ethRpc: opts.ethRpc } : {}),
    ...(opts.ethMinConfirmations !== undefined ? { ethMinConfirmations: opts.ethMinConfirmations } : {}),
    ...(opts.verbose !== undefined ? { verbose: opts.verbose } : {}),
    ...(opts.headerSources !== undefined ? { headerSources: opts.headerSources } : {}),
  })
}

/**
 * Single-file verification: `screenreg verify <file.screenreg>`. The same
 * verified read path the browser `/verify/` page uses — integrity-check the
 * container, then run the shared core. A FULL bundle carries the screenplay, so
 * contents are confirmed from the embedded source; a proof-only bundle is
 * date-only unless the user also supplies the screenplay as a second argument.
 */
async function cmdVerifyBundle(opts: VerifyBundleOptions): Promise<void> {
  const bundleBytes = readBytesOrDie(opts.bundlePath, 'verify: cannot read')
  let parsed: Awaited<ReturnType<typeof readScreenreg>>
  try {
    parsed = await readScreenreg(bundleBytes)
  } catch (err) {
    die(`verify: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (!parsed.integrity.ok) {
    process.stdout.write(`✗ FAILED — the .screenreg failed its integrity check\n`)
    for (const issue of parsed.integrity.issues) process.stdout.write(`  • ${issue}\n`)
    process.exit(2)
  }
  if (!parsed.otsBytes) die(`verify: ${opts.bundlePath} contains no OpenTimestamps proof to verify`)

  // Choose the screenplay source for the contents check. An EXPLICITLY supplied
  // screenplay is always the one verified — it answers "does THIS file match the
  // registration?" and must never be silently ignored (ignoring it would let a
  // non-matching file appear to pass). Otherwise a full bundle confirms contents
  // from its embedded source; a proof-only bundle with no screenplay is date-only.
  let raw: Buffer | undefined
  if (opts.scriptPath) {
    raw = readScreenplayBounded(opts.scriptPath)
  } else if (parsed.sourceText) {
    raw = Buffer.from(parsed.sourceText)
  }

  await verifyCore({
    ...(raw !== undefined ? { raw } : {}),
    envelope: parsed.envelope,
    otsBytes: parsed.otsBytes,
    otsHintPath: opts.bundlePath,
    otsHintIsBundle: true,
    ...(opts.requireBitcoinAnchor !== undefined ? { requireBitcoinAnchor: opts.requireBitcoinAnchor } : {}),
    ...(opts.ethRpc !== undefined ? { ethRpc: opts.ethRpc } : {}),
    ...(opts.ethMinConfirmations !== undefined ? { ethMinConfirmations: opts.ethMinConfirmations } : {}),
    ...(opts.verbose !== undefined ? { verbose: opts.verbose } : {}),
    ...(opts.headerSources !== undefined ? { headerSources: opts.headerSources } : {}),
  })
}

/**
 * Prepare the optional Ethereum-anchor report for `verify`. Runs the topics-only
 * on-chain check (when `--eth-rpc` is set and the envelope carries an
 * `ethereum-anchor` proof) and returns a closure that PRINTS the result. The
 * check is INFORMATIONAL: any RPC failure degrades to `unverified` inside the
 * verifier, the result is never allowed to change the Bitcoin verdict, and the
 * recomputed envelope claimHash (not `proof.claimHash`) is the expected value.
 * Returns a no-op closure when there is nothing to report.
 */
async function prepareEthAnchorReport(
  envelope: Envelope,
  recomputedClaimHash: string,
  opts: EthAnchorReportOptions,
): Promise<() => void> {
  if (opts.ethRpc === undefined) return () => {}
  const ethProof = envelope.evidenceBundle.proofs.find(
    (p): p is EthereumAnchorProof => p.type === 'ethereum-anchor',
  )
  if (ethProof === undefined) {
    return () => {
      process.stdout.write(
        `  Ethereum anchor: none in envelope (--eth-rpc supplied but no ethereum-anchor proof).\n`,
      )
    }
  }
  const provider = makeJsonRpcProvider(opts.ethRpc)
  const minConfirmations = opts.ethMinConfirmations ?? 12
  let result: EthAnchorResult
  try {
    result = await verifyEthAnchor(ethProof, recomputedClaimHash, provider, { minConfirmations })
  } catch {
    // Defense-in-depth: the verifier already catches provider errors, but a
    // construction/abort error must still never fail an otherwise Bitcoin-valid
    // proof. Degrade to an informational unverified line.
    result = { status: 'unverified', reason: 'rpc-error' }
  }
  return () => printEthAnchorResult(result, ethProof.registrant, ethProof.blockNumber)
}

interface DiagnoseOptions {
  inputFile: string
  envelopePath?: string
  otsPath?: string
}

function cmdDiagnose(opts: DiagnoseOptions): void {
  const raw = readScreenplayBounded(opts.inputFile)
  process.stdout.write(`Diagnose: ${opts.inputFile}\n`)
  process.stdout.write(`  Bytes (raw):       ${raw.length}\n`)

  const normResult = normalize(raw)
  if (!normResult.ok) {
    process.stdout.write(`  Status:            INVALID UTF-8\n  Detail:            ${normResult.detail}\n`)
    return
  }
  process.stdout.write(`  Bytes (normalized): ${normResult.normalized.length}\n`)

  if (normResult.transforms.length === 0) {
    process.stdout.write(`  Transforms:        (none — input already canonical)\n`)
  } else {
    process.stdout.write(`  Transforms applied:\n`)
    for (const t of normResult.transforms) {
      process.stdout.write(`    ✓ ${t.kind} (count: ${t.count})\n`)
    }
  }
  const cHash = contentHashOfNormalized(normResult.normalized)
  process.stdout.write(`  Content hash:      ${cHash}\n`)

  if (!opts.envelopePath) {
    process.stdout.write(
      `\n  (No envelope provided. To compare against a registered claim, run with the manifest.)\n`,
    )
    return
  }

  const envelope = readEnvelope(opts.envelopePath)
  process.stdout.write(`\n  Envelope:          ${opts.envelopePath}\n`)
  process.stdout.write(`  Manifest expects:  ${envelope.committedClaim.contentHash}\n`)
  if (cHash === envelope.committedClaim.contentHash) {
    process.stdout.write(`  Content hash:      ✓ MATCH\n`)
  } else {
    process.stdout.write(`  Content hash:      ✗ MISMATCH\n`)
    process.stdout.write(`\n  Probable causes:\n`)
    process.stdout.write(`    - File has been edited since registration\n`)
    process.stdout.write(`    - File saved by different tool with different invisible defaults\n`)
    process.stdout.write(`    - Hidden characters added/removed (zero-width space, BOM, etc.)\n`)
    process.stdout.write(`    - Wrong manifest paired with this file\n`)
    process.stdout.write(`\n  NOTE: The protocol stores ONLY the hash of the registered file, not its bytes.\n`)
    process.stdout.write(`        We cannot tell you WHICH bytes differ — only that the hashes diverge.\n`)
  }

  if (!opts.otsPath) return

  // Validate manifest/proof pair first per spec §6 mode matrix
  const otsBytes = readFileSync(opts.otsPath)
  const recomputedClaimHash = computeClaimHash(envelope.committedClaim)
  const consistency = checkEnvelopeConsistency(envelope, recomputedClaimHash)
  if (!consistency.ok) {
    process.stdout.write(`\n  Envelope consistency: ✗ FAILED — ${consistency.detail}\n`)
    process.stdout.write(`  (Manifest/proof pair invalid; ignoring file-mismatch diagnosis above.)\n`)
    return
  }
  const otsResult = verifyOtsAgainstFileDigest({
    otsBytes,
    expectedFileDigest: Buffer.from(recomputedClaimHash.slice('sha256:'.length), 'hex'),
  })
  if (!otsResult.ok) {
    process.stdout.write(`\n  OTS proof:         ✗ INVALID — ${otsResult.reason}\n`)
  } else if (otsResult.bitcoinAnchored) {
    process.stdout.write(`\n  OTS proof:         ✓ Bitcoin-anchored (block heights: ${otsResult.bitcoinBlockHeights.join(', ')})\n`)
  } else {
    process.stdout.write(`\n  OTS proof:         PENDING (no Bitcoin attestation yet)\n`)
  }
}

interface FinalizeCliOptions {
  otsPath: string
  /** Where to write the upgraded proof; defaults to overwriting the input in place. */
  outPath?: string
  /** Per-calendar request timeout in milliseconds. */
  timeoutMs?: number
  /** Keep polling until the proof confirms on Bitcoin, with a live countdown. */
  watch?: boolean
  /** Seconds between polls in watch mode (default 600 ≈ one Bitcoin block). */
  intervalSeconds?: number
  /** In watch mode, give up (exit 3) after this many pending checks. 0 = unlimited. */
  maxChecks?: number
}

/**
 * Finalize a pending proof: fold in the Bitcoin attestation once the calendars
 * have it. Clean-room TypeScript via the shared `finalizeProof` engine — no
 * Python, no `ots` binary. The same engine powers the browser `/create/` page,
 * so the CLI and the browser finalize identically.
 *
 * Exit codes: 0 = confirmed (proof upgraded and written), 3 = still pending
 * (no Bitcoin attestation yet; safe to re-run later), 1 = error. With `--watch`
 * the command does not exit on pending — it re-polls with a live countdown until
 * the proof confirms (0), an error occurs (1), or `--max-checks` is reached (3).
 */
async function cmdFinalize(opts: FinalizeCliOptions): Promise<void> {
  // Accept either a bare .ots proof or a .screenreg bundle (unpack → finalize → repack in place).
  const isBundle = opts.otsPath.endsWith('.screenreg')
  let otsBytes: Uint8Array
  let parsedBundle: Awaited<ReturnType<typeof readScreenreg>> | null = null
  if (isBundle) {
    const bundleBytes = readBytesOrDie(opts.otsPath, 'finalize: cannot read')
    try {
      parsedBundle = await readScreenreg(bundleBytes)
    } catch (err) {
      die(`finalize: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (!parsedBundle.otsBytes) die(`finalize: ${opts.otsPath} contains no OpenTimestamps proof to finalize`)
    // VERIFY the bundle before upgrading + repacking it. Otherwise a valid-CRC tampered bundle
    // (integrity.ok=false) could be finalized and rewritten with fresh descriptor digests,
    // laundering the corruption. Check the descriptor digests, the envelope shape, the
    // claim→committedClaimHash binding, the embedded source (full bundles), and that the OTS proof
    // actually anchors this claim — refusing to finalize anything that doesn't fully bind.
    if (!parsedBundle.integrity.ok) {
      die(`finalize: ${opts.otsPath} failed its integrity check (${parsedBundle.integrity.issues.join('; ')}) — refusing to finalize a corrupt bundle`)
    }
    const ev = validateEnvelope(parsedBundle.envelope)
    if (!ev.ok) die(`finalize: ${opts.otsPath} contains an invalid envelope:\n  - ${ev.errors.join('\n  - ')}`)
    const recomputedClaimHash = computeClaimHash(
      parsedBundle.envelope.committedClaim as unknown as Parameters<typeof computeClaimHash>[0],
    )
    if (recomputedClaimHash !== parsedBundle.envelope.evidenceBundle.committedClaimHash) {
      die(`finalize: envelope tampering — recomputed claim hash does not match the stored committedClaimHash`)
    }
    if (parsedBundle.sourceText) {
      const norm = normalize(Buffer.from(parsedBundle.sourceText))
      if (!norm.ok) die(`finalize: the embedded screenplay is not valid UTF-8 (${norm.detail})`)
      if (contentHashOfNormalized(norm.normalized) !== parsedBundle.envelope.committedClaim.contentHash) {
        die(`finalize: the embedded screenplay does not match the committed contentHash — refusing to finalize a tampered bundle`)
      }
    }
    // The embedded OTS proof must actually anchor this claim hash.
    const otsCheck = verifyOtsAgainstFileDigest({
      otsBytes: Buffer.from(parsedBundle.otsBytes),
      expectedFileDigest: Buffer.from(recomputedClaimHash.slice('sha256:'.length), 'hex'),
    })
    if (!otsCheck.ok) {
      die(`finalize: the embedded proof does not anchor this claim — refusing to finalize (${otsCheck.reason})`)
    }
    otsBytes = parsedBundle.otsBytes
  } else {
    try {
      otsBytes = new Uint8Array(readFileSync(opts.otsPath))
    } catch (err) {
      die(`finalize: cannot read ${opts.otsPath}: ${err instanceof Error ? err.message : String(err)}`)
    }
  }
  const finalizeOpts: FinalizeOptions = { otsBytes }
  if (opts.timeoutMs !== undefined) finalizeOpts.timeoutMs = opts.timeoutMs

  const intervalSeconds = opts.intervalSeconds ?? 600
  const startMs = Date.now()
  let checks = 0
  for (;;) {
    checks++
    const stopPoll = startSpinner('Checking the OpenTimestamps calendars for a Bitcoin block…')
    const result = await finalizeProof(finalizeOpts)
    stopPoll()

    if (result.status === 'error') {
      die(`finalize: ${result.reason ?? 'could not parse the .ots proof'}`)
    }

    if (result.status === 'confirmed') {
      const outPath = opts.outPath ?? opts.otsPath
      if (isBundle && parsedBundle) {
        // Fold the upgraded proof back into the one file (full bundle if it carries the source
        // text, evidence bundle otherwise). claimHash is unchanged — only the unhashed proof bytes.
        let rebuilt: Uint8Array
        try {
          rebuilt = parsedBundle.sourceText
            ? await buildScreenreg({ envelope: parsedBundle.envelope, otsBytes: result.otsBytes, sourceText: parsedBundle.sourceText })
            : await buildEvidenceScreenreg({ envelope: parsedBundle.envelope, otsBytes: result.otsBytes })
        } catch (err) {
          die(`finalize: could not repack the .screenreg: ${err instanceof ScreenregError ? err.message : String(err)}`)
        }
        writeFileSync(outPath, Buffer.from(rebuilt))
      } else {
        writeFileSync(outPath, Buffer.from(result.otsBytes))
      }
      const plural = result.bitcoinBlockHeights.length > 1 ? 's' : ''
      const waited = opts.watch ? ` after ${formatDuration((Date.now() - startMs) / 1000)}` : ''
      process.stderr.write(
        `✓  Confirmed on Bitcoin${waited} (block height${plural}: ${result.bitcoinBlockHeights.join(', ')}).\n` +
          `   Wrote the finalized ${isBundle ? '.screenreg' : 'proof'} to ${outPath}. It now verifies against\n` +
          `   Bitcoin block headers alone — no calendar or server required.\n`,
      )
      process.exit(0)
    }

    // status === 'pending'
    if (!opts.watch) {
      // The --watch hint is an interactive affordance only; keep non-TTY (piped/CI)
      // output byte-identical to the pre-watch behavior.
      const watchHint = process.stderr.isTTY ? ' (or pass --watch to wait here)' : ''
      process.stderr.write(
        `⧗  Still pending — the Bitcoin confirmation is not available yet.\n` +
          `   This is normal in the first ~1-6 hours after registration. The proof is\n` +
          `   already valid as a pending calendar attestation; re-run \`${CLI_NAME} finalize\`\n` +
          `   later to fold in the Bitcoin block${watchHint}.\n`,
      )
      if (result.pendingCalendars.length > 0) {
        process.stderr.write(`   Pending calendars: ${result.pendingCalendars.join(', ')}\n`)
      }
      process.exit(3)
    }

    if (opts.maxChecks && checks >= opts.maxChecks) {
      process.stderr.write(
        `⧗  Still pending after ${checks} check${checks > 1 ? 's' : ''} (${formatDuration((Date.now() - startMs) / 1000)}). Giving up for now;\n` +
          `   the proof is unchanged on disk — re-run \`${CLI_NAME} finalize --watch\` later.\n`,
      )
      process.exit(3)
    }

    await countdownSleep(intervalSeconds, (Date.now() - startMs) / 1000)
  }
}

function cmdNormalize(inputFile: string): void {
  const raw = readScreenplayBounded(inputFile)
  const result = normalize(raw)
  if (!result.ok) {
    process.stderr.write(`error: ${result.detail}\n`)
    process.exit(2)
  }
  const hash = contentHashOfNormalized(result.normalized)
  process.stderr.write(`Content hash: ${hash}\n`)
  process.stderr.write(`Normalized bytes (${result.normalized.length}):\n`)
  process.stdout.write(result.normalized)
}

function cmdClaim(inputFile: string): void {
  const raw = readScreenplayBounded(inputFile)
  const ch = contentHash(raw)
  if (ch === null) die('input is not valid UTF-8')
  const claim = buildCommittedClaim({ contentHash: ch! })
  const claimHash = computeClaimHash(claim)
  const out = { committedClaim: claim, claimHash }
  process.stdout.write(JSON.stringify(out, null, 2) + '\n')
}

function cmdSceneProve(inputFile: string, envelopePath: string, sceneIndex: number): void {
  const raw = readScreenplayBounded(inputFile)
  const norm = normalize(raw)
  if (!norm.ok) die('not valid UTF-8')
  const scenes = detectScenes(norm.normalized)
  if (sceneIndex < 0 || sceneIndex >= scenes.length) {
    die(`sceneIndex ${sceneIndex} out of range [0, ${scenes.length})`)
  }
  const tree = buildSceneTree(scenes)
  const envelope = readEnvelope(envelopePath)
  if (envelope.committedClaim.sceneTreeRoot !== tree.root) {
    die(`tree root mismatch (envelope: ${envelope.committedClaim.sceneTreeRoot}, computed: ${tree.root})`)
  }
  const proof = buildSceneProof(tree, sceneIndex, scenes[sceneIndex]!)
  process.stdout.write(JSON.stringify(proof, null, 2) + '\n')
}

function cmdSceneVerify(root: string, sceneContentBase64: string, proofJson: string): void {
  const proof = JSON.parse(readFileSync(proofJson, 'utf8'))
  // Use the proof's stored sceneBytes if matches the override, else override
  const result = verifySceneProof({
    expectedRoot: root,
    expectedSceneCount: proof.sceneCount,
    expectedProfile: MERKLE_PROFILE,
    proof: { ...proof, sceneBytes: sceneContentBase64 || proof.sceneBytes },
  })
  if (result.ok) {
    process.stdout.write('✓ scene proof verifies\n')
    process.exit(0)
  } else {
    process.stdout.write(`✗ scene proof FAILED: ${result.detail}\n`)
    process.exit(2)
  }
}

function cmdSimilarity(
  bundleAPath: string,
  bundleBPath: string,
  opts: { envelopeAPath?: string; envelopeBPath?: string },
): void {
  const bundleA = readJsonFileBounded<ComparisonBundle>(bundleAPath, 'bundle A')
  const bundleB = readJsonFileBounded<ComparisonBundle>(bundleBPath, 'bundle B')

  // External binding: when envelope paths are supplied, verify each bundle
  // binds to its specific committed claim. Without this, two bundles whose
  // SELF-binding is valid could still be FABRICATED — any party can construct
  // a fresh bundle (with internally-consistent leaf hashes that reduce to a
  // root) that doesn't correspond to any real Bitcoin-anchored claim. The
  // comparison report would be mathematically correct over fabricated data.
  //
  // Loud warning when either envelope is missing — the report is still
  // produced (for the "I'm comparing my own drafts" case where I trust
  // both inputs) but the caller MUST be aware that envelope-less comparison
  // is trust-the-other-party, not trust-the-protocol.
  if (!opts.envelopeAPath || !opts.envelopeBPath) {
    process.stderr.write(
      `⚠  UNBOUND COMPARISON — running similarity WITHOUT external binding to a claim.\n` +
        `   The report below is mathematically correct over whatever leaf+content hashes\n` +
        `   the bundles supply, but DOES NOT prove either bundle came from a real\n` +
        `   Bitcoin-anchored claim. Any party can fabricate self-consistent bundles.\n` +
        `   For binding-verified comparison (recommended when a bundle comes from a\n` +
        `   third party), pass --envelope-a PATH AND --envelope-b PATH.\n\n`,
    )
  }
  if (opts.envelopeAPath) {
    const envA = readEnvelope(opts.envelopeAPath)
    const bindA = verifyBundleAgainstClaim(bundleA, envA.committedClaim)
    if (!bindA.ok) die(`bundle A does not bind to envelope A: ${bindA.reason}`)
  }
  if (opts.envelopeBPath) {
    const envB = readEnvelope(opts.envelopeBPath)
    const bindB = verifyBundleAgainstClaim(bundleB, envB.committedClaim)
    if (!bindB.ok) die(`bundle B does not bind to envelope B: ${bindB.reason}`)
  }

  const result = compareBundles(bundleA, bundleB)
  if (!result.ok) {
    process.stdout.write(`✗ comparison unavailable: ${result.reason}\n`)
    process.exit(2)
  }
  process.stdout.write(
    formatComparisonReport(result.report, {
      labelA: basename(bundleAPath),
      labelB: basename(bundleBPath),
    }) + '\n',
  )
}

/**
 * Disclose a comparison bundle for publication.
 *
 * Spec §06 §6: the CLI MUST display the irrevocability warning BEFORE writing
 * the public file (so a user who Ctrl-C's after seeing it has not already
 * leaked). Confirmation requires the literal token "I UNDERSTAND" — typed
 * accidents like "yes" or hitting Enter do nothing.
 *
 * Argument shape per spec §06 §9:
 *   screenreg disclose-comparison <input>
 *     where <input> is one of:
 *       - the original screenplay file (we derive the .comparison-bundle.private.json)
 *       - the manifest path (.manifest.json) — same derivation
 *       - the private bundle path directly (.comparison-bundle.private.json)
 *
 * Optional second arg overrides the auto-derived public output path.
 */
function cmdDiscloseComparison(
  inputPath: string,
  publicOutPathOverride: string | undefined,
  opts: { yesIUnderstand?: boolean },
): void {
  // Resolve the private bundle path
  const privateBundlePath = resolvePrivateBundlePath(inputPath)
  if (!existsSync(privateBundlePath)) {
    die(
      `private bundle not found: ${privateBundlePath}\n` +
        `  (Was the original \`${CLI_NAME} register\` run? Bundles only exist when there is a scene or paragraph tree.)`,
    )
  }
  // Default public output: strip ".private" from the private bundle path.
  const publicOutPath =
    publicOutPathOverride ?? privateBundlePath.replace(/\.private\.json$/, '.json')
  if (publicOutPath === privateBundlePath) {
    die(`refusing to overwrite the private bundle in place: ${privateBundlePath}`)
  }

  // Warn FIRST. If the user Ctrl-C's at the prompt, nothing has been written.
  process.stdout.write(
    `\n⚠  IRREVOCABLE PUBLIC DISCLOSURE — read before continuing.\n\n` +
      `  Publishing a comparison bundle reveals all per-scene + per-paragraph\n` +
      `  content hashes for this registration. Once published, anyone can:\n` +
      `    • compare any other bundle to yours, forever\n` +
      `    • test whether a candidate paragraph appears in your script\n` +
      `      (the membership oracle that the architecture lets you opt INTO)\n\n` +
      `  You CANNOT unpublish. Bundles SHOULD be published only when\n` +
      `  comparison is the actual goal (alleging or defending against an\n` +
      `  idea-theft claim, proving a draft lineage, etc.). If you only want\n` +
      `  to prove your script existed on a date, your registration is\n` +
      `  already complete WITHOUT this step.\n\n` +
      `  Private bundle:  ${privateBundlePath}\n` +
      `  Public output:   ${publicOutPath}\n\n`,
  )

  if (!opts.yesIUnderstand) {
    process.stdout.write(`  To proceed, re-run with the literal phrase:\n`)
    process.stdout.write(
      `    ${CLI_NAME} disclose-comparison ${inputPath}${publicOutPathOverride ? ' ' + publicOutPathOverride : ''} --yes-i-understand\n\n`,
    )
    // Only offer interactive confirmation when stdin is a TTY. In CI / scripted
    // contexts stdin is typically piped or closed, and prompting would silently
    // accept '' as the answer (rejecting safely) but still confuse the operator.
    if (!process.stdin.isTTY) {
      process.stdout.write(`  (stdin is not a TTY — re-run with --yes-i-understand to confirm.)\n`)
      process.exit(1)
    }
    process.stdout.write(`  Or interactively, type "I UNDERSTAND" (case-sensitive) then Enter: `)
    const answer = readLineSync().trim()
    if (answer !== 'I UNDERSTAND') {
      process.stdout.write(`\nAborted — no file was written.\n`)
      process.exit(1)
    }
  }

  // Now safe to read + write.
  const bundle = readJsonFileBounded<ComparisonBundle>(privateBundlePath, 'private bundle')
  writeFileSync(publicOutPath, JSON.stringify(bundle, null, 2) + '\n')
  process.stdout.write(`\n✓ Comparison bundle written to ${publicOutPath}.\n`)
  process.stdout.write(`  This file is now safe (and IRREVOCABLE) to publish.\n`)
}

/**
 * Map a user-provided <input> to the path of its private comparison bundle.
 * Accepts the original screenplay, its manifest, or the private bundle path itself.
 */
function resolvePrivateBundlePath(inputPath: string): string {
  if (inputPath.endsWith('.comparison-bundle.private.json')) return inputPath
  if (inputPath.endsWith('.manifest.json')) {
    return inputPath.replace(/\.manifest\.json$/, '.comparison-bundle.private.json')
  }
  return `${inputPath}.comparison-bundle.private.json`
}

/**
 * Synchronously read one line from stdin. Returns '' on EOF.
 * Used for the disclose-comparison confirmation prompt.
 */
function readLineSync(): string {
  // Synchronous one-byte-at-a-time read from stdin until LF or EOF. Used for
  // the disclose-comparison confirmation prompt; we block the entire process
  // until the user answers, hence no readline/async wrapper.
  //
  // If stdin is closed or unreadable (e.g. piped input that ended, EBADF
  // from a non-interactive shell), readSync throws. Treat that as a "no
  // answer" — return '' so the caller's strict `=== 'I UNDERSTAND'` check
  // fails cleanly without a stack trace.
  let buf = ''
  const chunk = Buffer.alloc(1)
  const fd = 0 // stdin
  while (true) {
    let n: number
    try {
      n = readSync(fd, chunk, 0, 1, null)
    } catch {
      return buf
    }
    if (n === 0) break
    const ch = chunk.toString('utf8')
    if (ch === '\n') break
    buf += ch
  }
  return buf
}

function cmdSignChallenge(claimHash: string, challengeHex: string, privateKeyPath: string): void {
  if (!existsSync(privateKeyPath)) die(`private key file not found: ${privateKeyPath}`)
  const pem = readFileSync(privateKeyPath, 'utf8')
  const privateKey = loadPrivateKey(pem)
  const challenge = Buffer.from(challengeHex, 'hex')
  const signature = signChallenge(claimHash, challenge, privateKey)
  process.stdout.write(signature.toString('hex') + '\n')
}

function cmdVerifySignature(
  envelopePath: string,
  challengeHex: string,
  signatureHex: string,
): void {
  const envelope = readEnvelope(envelopePath)
  const registrant = envelope.committedClaim.registrant
  if (!registrant) die('envelope has no registrant block')
  const pubkey = registrant.publicKey
  const claimHash = computeClaimHash(envelope.committedClaim)
  const challenge = Buffer.from(challengeHex, 'hex')
  const signature = Buffer.from(signatureHex, 'hex')
  const ok = verifySignature({ claimHash, challenge, publicKeyEncoded: pubkey, signature })
  if (ok) {
    process.stdout.write(`✓ signature valid — registrant of ${claimHash} is the holder of ${pubkey}\n`)
    process.exit(0)
  } else {
    process.stdout.write(`✗ signature INVALID\n`)
    process.exit(2)
  }
}

function cmdVerifyRegistration(envelopePath: string): void {
  const envelope = readEnvelope(envelopePath)
  const result = verifyRegistrationSignature(envelope.committedClaim)
  if (result.ok) {
    process.stdout.write(`✓ registration-time signature valid\n`)
    process.stdout.write(`  Registrant: ${envelope.committedClaim.registrant!.publicKey}\n`)
    process.stdout.write(`  Signed body digest: ${envelope.committedClaim.registrant!.signedDigest}\n`)
    process.exit(0)
  } else {
    process.stdout.write(`✗ registration-time signature INVALID: ${result.reason}\n`)
    process.exit(2)
  }
}

async function cmdTimelockEncrypt(
  envelopePath: string,
  fieldName: string,
  unlockAtIso: string,
  plaintext: string,
  opts: { outPath?: string; iUnderstandMustRestamp?: boolean },
): Promise<void> {
  const envelope = readEnvelope(envelopePath)
  const unlockAt = new Date(unlockAtIso)
  if (isNaN(unlockAt.getTime())) die(`unparseable unlockAt: ${unlockAtIso}`)

  // SAFETY: timelock-encrypt mutates committedClaim, which changes the claim
  // hash. If we wrote back to the input envelope path, the on-disk OTS proof
  // (which anchors the OLD claim hash) would no longer match the on-disk
  // envelope — a broken pair that fails `screenreg verify` on its happy path.
  //
  // Requirements to proceed:
  //   1. --out PATH (a DIFFERENT file than the input) — never overwrite the input
  //      envelope. The output is a fresh, unanchored envelope.
  //   2. --i-understand-must-restamp — explicit acknowledgement that the output
  //      envelope has NO valid OTS proof and MUST be re-stamped before it can
  //      verify against Bitcoin.
  //
  // For new registrations, the better flow is to set timelock fields at register
  // time (planned for v0.2 register --timelock-field flag). For adding a timelock
  // to an EXISTING registration, the right pattern is a new registration that
  // sets `previousRegistration.claimHash` to the prior anchor — the old anchor
  // stays valid; the new one chains.
  if (!opts.outPath) {
    die(
      `timelock-encrypt: --out PATH is REQUIRED.\n` +
        `  This command changes the claim hash, which invalidates the existing OTS\n` +
        `  proof. Write to a NEW envelope file (never overwrite the input).\n` +
        `  Then re-stamp the new envelope via OTS, OR include a previousRegistration\n` +
        `  pointer to chain off the original anchor.`,
    )
  }
  if (resolve(opts.outPath) === resolve(envelopePath)) {
    die(
      `timelock-encrypt: --out (${opts.outPath}) must be a DIFFERENT file than the input envelope (${envelopePath}).`,
    )
  }
  if (!opts.iUnderstandMustRestamp) {
    die(
      `timelock-encrypt: --i-understand-must-restamp REQUIRED.\n` +
        `  Adding a timelock field changes the committed claim hash. The output\n` +
        `  envelope at ${opts.outPath} will have NO valid OTS proof until you re-stamp.\n` +
        `  Pass --i-understand-must-restamp to confirm and proceed.`,
    )
  }

  process.stderr.write(`Encrypting "${fieldName}" with unlock at ${unlockAt.toISOString()}...\n`)
  const field = await timelockEncrypt({
    name: fieldName,
    plaintext: Buffer.from(plaintext, 'utf8'),
    unlockAt,
  })
  const existing = envelope.committedClaim.timelockFields ?? []
  envelope.committedClaim.timelockFields = [...existing, field]
  const newClaimHash = computeClaimHash(envelope.committedClaim)
  envelope.evidenceBundle.committedClaimHash = newClaimHash
  // CRITICAL: clear any existing proofs from the evidenceBundle. They anchor
  // the OLD claim hash and would silently mislead anyone running `verify`.
  // (Writing the unmodified proofs array would produce a structurally invalid
  // envelope where evidenceBundle.committedClaimHash differs from every
  // proof.claimHash — checkEnvelopeConsistency catches it, but only after
  // bytes are on disk. Strip preemptively.)
  envelope.evidenceBundle.proofs = []
  writeFileSync(opts.outPath, JSON.stringify(envelope, null, 2) + '\n')
  process.stderr.write(`✓ timelock field "${fieldName}" added → ${opts.outPath}\n`)
  process.stderr.write(`  Unlock at:   ${field.unlockAt}\n`)
  process.stderr.write(`  Drand round: ${field.unlockAtRound}\n`)
  process.stderr.write(`  NEW claim hash: ${newClaimHash}\n`)
  process.stderr.write(
    `\n  ⚠  The new envelope has NO Bitcoin anchor. Next step: either\n` +
      `     (a) submit the new claim hash to OTS (re-stamp), OR\n` +
      `     (b) treat this as a draft and discard if you don't proceed.\n` +
      `  The original envelope at ${envelopePath} (and its .ots proof) is UNCHANGED.\n`,
  )
}

async function cmdTimelockDecrypt(envelopePath: string, fieldName: string): Promise<void> {
  const envelope = readEnvelope(envelopePath)
  const fields = envelope.committedClaim.timelockFields ?? []
  const field = fields.find((f) => f.name === fieldName)
  if (!field) die(`timelock field "${fieldName}" not found in envelope`)
  process.stderr.write(`Fetching Drand round ${field.unlockAtRound} from ${field.drandChainHash}...\n`)
  const result = await timelockDecrypt({ field })
  if (!result.ok) {
    process.stdout.write(`✗ ${result.reason}: ${result.detail}\n`)
    process.exit(2)
  }
  process.stdout.write(result.plaintext.toString('utf8'))
  if (process.stdout.isTTY) process.stdout.write('\n')
}

function cmdGenerateIdentity(outPath: string): void {
  const kp = generateKeypair()
  writeSensitiveFileExclusive(outPath, kp.privateKeyPem)
  process.stdout.write(`Private key written to ${outPath} (0600, exclusive create)\n`)
  process.stdout.write(`Public key (paste into committedClaim.registrant.publicKey): ${kp.publicKeyEncoded}\n`)
}

async function cmdDecryptField(envelopePath: string, fieldName: string): Promise<void> {
  const envelope = readEnvelope(envelopePath)
  if (!envelope.committedClaim.encryptedFields) {
    die('envelope has no encryptedFields block')
  }
  const password = await readPassword(`Password for ${fieldName}: `)
  const result = decryptFieldsBlock({
    password,
    claimVersion: envelope.committedClaim.claimVersion,
    block: envelope.committedClaim.encryptedFields,
  })
  if (!result.ok) {
    die(`decryption failed: ${result.failures.map((f) => `${f.name}=${f.reason}`).join(', ')}`)
  }
  const value = result.plaintexts[fieldName]
  if (!value) die(`field "${fieldName}" not found in encryptedFields`)
  process.stdout.write(value.toString('utf8'))
  if (process.stdout.isTTY) process.stdout.write('\n')
}

// ---------------------------------------------------------------------------
// Optional Ethereum-mainnet anchor (secondary, additive witness — NEVER a
// priority/time source; Bitcoin via OpenTimestamps stays the sole anchor).
// ---------------------------------------------------------------------------

interface AttachEthAnchorOptions {
  envelopePath: string
  contract: string
  registrant: string
  txHash: string
  logIndex: number
  blockNumber: number
  chainId: number
  outPath: string | undefined
}

/**
 * Attach an `ethereum-anchor` evidence proof to an existing envelope and write a
 * NEW envelope (never mutating in place — the original + its `.ots` stay valid).
 *
 * The proof is bound to the envelope's INDEPENDENTLY-RECOMPUTED `claimHash`, not
 * to any value the caller supplies, so an attached anchor can only ever witness
 * the same 32-byte commitment. The combined envelope is then re-validated against
 * the v1 schema: the strict `ethereum-anchor` validator runs at this integration
 * boundary, so a malformed coordinate (or a forbidden `contentHash`) fails here
 * rather than silently shipping. The anchor is additive — it changes no committed
 * bytes and is never hashed into the claim.
 */
function cmdAttachEthAnchor(opts: AttachEthAnchorOptions): void {
  const envelope = readEnvelope(opts.envelopePath)

  // Bind to the recomputed envelope claimHash — never trust a caller-supplied one.
  const claimHash = computeClaimHash(envelope.committedClaim)
  const consistency = checkEnvelopeConsistency(envelope, claimHash)
  if (!consistency.ok) {
    die(`attach-eth-anchor: source envelope is inconsistent — ${consistency.detail}`)
  }

  const proof: EthereumAnchorProof = {
    type: 'ethereum-anchor',
    profile: ETHEREUM_ANCHOR_EVIDENCE_PROFILE,
    claimHash,
    chainId: opts.chainId,
    contract: opts.contract,
    registrant: opts.registrant,
    txHash: opts.txHash,
    logIndex: opts.logIndex,
    blockNumber: opts.blockNumber,
  }

  const updated: Envelope = {
    ...envelope,
    evidenceBundle: {
      ...envelope.evidenceBundle,
      proofs: [...envelope.evidenceBundle.proofs, proof],
    },
  }

  // Re-validate the combined envelope. The strict ethereum-anchor branch runs at
  // this boundary; a bad address/hash/logIndex (or a contentHash anywhere on the
  // proof) is rejected here before anything is written.
  const shape = validateEnvelope(updated)
  if (!shape.ok) {
    process.stderr.write(`${CLI_NAME}: attach-eth-anchor: resulting envelope is invalid\n`)
    for (const e of shape.errors) process.stderr.write(`  • ${e}\n`)
    process.exit(2)
  }

  const outPath = opts.outPath ?? defaultAnchoredEnvelopePath(opts.envelopePath)
  if (resolve(outPath) === resolve(opts.envelopePath)) {
    die('attach-eth-anchor: --out must differ from the source envelope (never overwrites in place)')
  }
  writeFileSync(outPath, JSON.stringify(updated, null, 2) + '\n')

  process.stderr.write(`\n✓ Ethereum anchor attached (additive — claim hash unchanged).\n`)
  process.stderr.write(`  Claim hash:  ${claimHash}\n`)
  process.stderr.write(`  Contract:    ${opts.contract}\n`)
  process.stderr.write(`  Registrant:  ${opts.registrant}\n`)
  process.stderr.write(`  Tx / log:    ${opts.txHash} #${opts.logIndex} (block ${opts.blockNumber})\n`)
  process.stderr.write(`  New envelope: ${outPath}\n`)
  process.stderr.write(
    `  NOTE: the Ethereum anchor is a SECONDARY witness. It is never a priority or\n` +
      `        time source — Bitcoin (via OpenTimestamps) remains the sole anchor.\n` +
      `        Verify it on-chain with: ${CLI_NAME} verify <file> <env> <ots> --eth-rpc <url>\n`,
  )
}

function defaultAnchoredEnvelopePath(envelopePath: string): string {
  const dir = dirname(envelopePath)
  const base = basename(envelopePath)
  const stem = base.endsWith('.json') ? base.slice(0, -'.json'.length) : base
  return join(dir, `${stem}.eth-anchored.json`)
}

/**
 * A minimal JSON-RPC `EthLogProvider` over a single endpoint URL, used only by
 * the CLI's optional `--eth-rpc` path. It speaks the three read methods the
 * topics-only verifier needs (`eth_chainId`, `eth_getLogs`, `eth_blockNumber`)
 * and DELIBERATELY exposes no calldata/receipt method — the verifier reads event
 * topics and never recovers a signature off-chain.
 *
 * Any network/JSON error surfaces as a thrown error; the verifier catches it and
 * degrades to `unverified`, so a flaky RPC never flips a Bitcoin verdict.
 */
function makeJsonRpcProvider(rpcUrl: string): EthLogProvider {
  let nextId = 1
  async function rpc<T>(method: string, params: unknown[]): Promise<T> {
    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
    })
    if (!res.ok) throw new Error(`RPC ${method} HTTP ${res.status}`)
    const json = (await res.json()) as { result?: unknown; error?: { message?: string } }
    if (json.error) throw new Error(`RPC ${method}: ${json.error.message ?? 'error'}`)
    return json.result as T
  }
  return {
    async getChainId(): Promise<number> {
      return Number.parseInt(await rpc<string>('eth_chainId', []), 16)
    },
    async getBlockNumber(): Promise<number> {
      return Number.parseInt(await rpc<string>('eth_blockNumber', []), 16)
    },
    async getLogs(filter): Promise<EthLog[]> {
      const toHexBlock = (n: number | undefined): string | undefined =>
        n === undefined ? undefined : '0x' + n.toString(16)
      const rawLogs = await rpc<
        {
          address: string
          topics: string[]
          blockNumber: string
          transactionHash: string
          logIndex: string
        }[]
      >('eth_getLogs', [
        {
          address: filter.address,
          topics: filter.topics,
          ...(filter.fromBlock !== undefined ? { fromBlock: toHexBlock(filter.fromBlock) } : {}),
          ...(filter.toBlock !== undefined ? { toBlock: toHexBlock(filter.toBlock) } : {}),
        },
      ])
      return rawLogs.map((l) => ({
        address: l.address,
        topics: l.topics,
        blockNumber: Number.parseInt(l.blockNumber, 16),
        transactionHash: l.transactionHash,
        logIndex: Number.parseInt(l.logIndex, 16),
      }))
    },
  }
}

/**
 * Print the result of an on-chain `ethereum-anchor` check as INFORMATIONAL.
 * NEVER changes a Bitcoin verdict or this process's exit status — the ETH anchor
 * is a secondary witness. The deterministic status taxonomy is surfaced verbatim
 * so a script can grep it without inferring success from the Bitcoin result.
 */
function printEthAnchorResult(result: EthAnchorResult, registrant: string, blockNumber: number): void {
  switch (result.status) {
    case 'verified':
      process.stdout.write(
        `  Ethereum anchor: VERIFIED — also anchored on Ethereum mainnet at block ${result.blockNumber} ` +
          `by ${registrant} (${result.confirmations} confirmations). Informational; not a priority source.\n`,
      )
      break
    case 'not-found':
      process.stdout.write(
        `  Ethereum anchor: NOT-FOUND — RPC reachable but no Registered log matched the proof's ` +
          `txHash + logIndex at block ${blockNumber}. (Bitcoin verdict unaffected.)\n`,
      )
      break
    case 'unverified':
      process.stdout.write(
        `  Ethereum anchor: UNVERIFIED (${result.reason}) — could not confirm on-chain ` +
          `(RPC issue, insufficient confirmations, or a reserved batched anchor). (Bitcoin verdict unaffected.)\n`,
      )
      break
    case 'rejected':
      process.stdout.write(
        `  Ethereum anchor: REJECTED (${result.reason}) — on-chain data contradicts the proof. ` +
          `This does NOT change the Bitcoin verdict; the ETH anchor is a secondary witness only.\n`,
      )
      break
  }
}

// ---------------------------------------------------------------------------
// Registry index: build / search / verify + Bitcoin-only priority lookup.
//
// The registry index is a SIGNED, MIRRORABLE discovery convenience — NOT a
// tamper-proof log. In v1 it gives ZERO cryptographic protection against an
// operator that censors, withholds, or equivocates; per-record truth is each
// record's own `.ots` verified against Bitcoin. Priority/dispute resolution uses
// the Bitcoin block height ONLY, and only when an injected attestation verifier
// has confirmed header inclusion. See spec/v1/10-registry-index.md.
// ---------------------------------------------------------------------------

interface RegistryBuildOptions {
  envelopePath: string
  proofRef: string | undefined
  title: string | undefined
  authorPubkey: string | undefined
  authorName: string | undefined
  registeredAt: string | undefined
  outPath: string | undefined
}

/**
 * Build a registry-index record from an envelope. The record carries the opaque
 * `claimHash` (recomputed from the envelope, never trusted from a field), optional
 * public labels, and the anchor coordinates needed to re-verify the record
 * independently. The script `contentHash` is FORBIDDEN at any depth — the
 * validator rejects it so the index can never become a membership oracle.
 */
function cmdRegistryBuild(opts: RegistryBuildOptions): void {
  const envelope = readEnvelope(opts.envelopePath)
  const claimHash = computeClaimHash(envelope.committedClaim)
  const consistency = checkEnvelopeConsistency(envelope, claimHash)
  if (!consistency.ok) {
    die(`registry-build: source envelope is inconsistent — ${consistency.detail}`)
  }

  // Pull the OTS proofRef from the envelope's opentimestamps proof unless the
  // caller overrides it. The record's truth is this `.ots` against Bitcoin.
  const otsProof = envelope.evidenceBundle.proofs.find(
    (p): p is EvidenceProof & { proofRef: string } =>
      p.type === 'opentimestamps' && typeof (p as { proofRef?: unknown }).proofRef === 'string',
  )
  const proofRef = opts.proofRef ?? otsProof?.proofRef
  if (proofRef === undefined) {
    die(
      'registry-build: no OpenTimestamps proofRef found in the envelope; supply one with --proof-ref <file>',
    )
  }

  // Optionally surface an Ethereum anchor's coordinates (secondary witness only).
  const ethProof = envelope.evidenceBundle.proofs.find(
    (p): p is EthereumAnchorProof => p.type === 'ethereum-anchor',
  )

  const record = buildRegistryRecord({
    claimHash,
    ...(opts.title !== undefined ? { title: opts.title } : {}),
    ...(opts.authorPubkey !== undefined
      ? {
          author: {
            pubkey: opts.authorPubkey,
            ...(opts.authorName !== undefined ? { name: opts.authorName } : {}),
          },
        }
      : {}),
    ...(opts.registeredAt !== undefined ? { registeredAt: opts.registeredAt } : {}),
    anchors: {
      opentimestamps: { proofRef },
      ...(ethProof !== undefined
        ? {
            ethereum: {
              chainId: ethProof.chainId,
              contract: ethProof.contract,
              txHash: ethProof.txHash,
              logIndex: ethProof.logIndex,
              blockNumber: ethProof.blockNumber,
            },
          }
        : {}),
    },
  })

  const validation = validateRegistryRecord(record)
  if (!validation.ok) {
    process.stderr.write(`${CLI_NAME}: registry-build: built an invalid record\n`)
    for (const e of validation.errors) process.stderr.write(`  • ${e}\n`)
    process.exit(2)
  }

  const json = JSON.stringify(record, null, 2) + '\n'
  if (opts.outPath !== undefined) {
    writeFileSync(opts.outPath, json)
    process.stderr.write(`✓ Registry record written to ${opts.outPath}\n`)
    process.stderr.write(`  Claim hash:  ${claimHash}\n`)
    process.stderr.write(`  OTS proof:   ${proofRef}\n`)
  } else {
    process.stdout.write(json)
  }
}

/** Read a registry snapshot (`{ records: [...] }`) and validate every record. */
function readRegistrySnapshot(snapshotPath: string): { snapshot: RegistrySnapshot; dir: string } {
  const raw = readJsonFileBounded<unknown>(snapshotPath, 'snapshot')
  if (typeof raw !== 'object' || raw === null || !Array.isArray((raw as { records?: unknown }).records)) {
    die('snapshot must be a JSON object with a "records" array')
  }
  const records = (raw as { records: unknown[] }).records
  const validated: RegistryRecord[] = []
  records.forEach((rec, i) => {
    const v = validateRegistryRecord(rec)
    if (!v.ok) {
      process.stderr.write(`${CLI_NAME}: snapshot record[${i}] is invalid:\n`)
      for (const e of v.errors) process.stderr.write(`  • ${e}\n`)
      process.exit(2)
    }
    validated.push(rec as RegistryRecord)
  })
  return { snapshot: { records: validated }, dir: dirname(resolve(snapshotPath)) }
}

interface RegistrySearchOptions {
  snapshotPath: string
  claimHash: string | undefined
  title: string | undefined
  author: string | undefined
}

/**
 * Search a registry snapshot by claimHash, public title, or public author
 * (pubkey or name), printing matching records. Search is over PUBLIC labels only
 * — the script `contentHash` is never in a record, so the index is not a
 * membership oracle for the work itself.
 */
function cmdRegistrySearch(opts: RegistrySearchOptions): void {
  const { snapshot } = readRegistrySnapshot(opts.snapshotPath)
  const needleHash = opts.claimHash?.toLowerCase()
  const needleTitle = opts.title?.toLowerCase()
  const needleAuthor = opts.author?.toLowerCase()

  const matches = snapshot.records.filter((r) => {
    if (needleHash !== undefined && r.claimHash.toLowerCase() !== needleHash) return false
    if (needleTitle !== undefined && !(r.title ?? '').toLowerCase().includes(needleTitle)) return false
    if (needleAuthor !== undefined) {
      const pubkey = (r.author?.pubkey ?? '').toLowerCase()
      const name = (r.author?.name ?? '').toLowerCase()
      if (!pubkey.includes(needleAuthor) && !name.includes(needleAuthor)) return false
    }
    return true
  })

  if (matches.length === 0) {
    process.stderr.write('No matching records.\n')
    process.exit(1)
  }
  process.stdout.write(JSON.stringify({ matches }, null, 2) + '\n')
  process.stderr.write(`${matches.length} match${matches.length === 1 ? '' : 'es'}.\n`)
}

/**
 * Build the CLI's path-traversal-guarded `loadOtsProof` resolver. Every record's
 * `proofRef` is resolved ONLY relative to the snapshot directory; absolute paths,
 * `..` traversal, and symlinks are rejected (fail closed). Returns `undefined`
 * when a proof file is absent so a missing proof is reported, not fatal.
 */
function makeSnapshotOtsLoader(snapshotDir: string): LoadOtsProof {
  return (record: RegistryRecord, proofRef: string): Buffer | undefined => {
    let resolved: string
    try {
      resolved = resolveSiblingProof(snapshotDir, proofRef)
    } catch (e) {
      // A rejected proofRef (traversal/symlink/absolute) is surfaced as an error
      // by re-throwing — verifyIndexSnapshot turns it into an ok:false record.
      throw new Error(
        `record ${record.claimHash}: ${e instanceof Error ? e.message : String(e)}`,
      )
    }
    if (!existsSync(resolved)) return undefined
    const st = lstatSync(resolved)
    if (st.size > MAX_JSON_INPUT_BYTES) {
      throw new Error(`record ${record.claimHash}: .ots proof too large: ${st.size} bytes`)
    }
    return readFileSync(resolved)
  }
}

interface VerifyRegistryOptions {
  snapshotPath: string
  minConfirmations: number
}

/**
 * Verify every record in a registry snapshot by re-checking its `.ots` against
 * Bitcoin (per-record only — there is NO snapshot-root step; that is deferred
 * with the CT-style transparency-log target). Without an injected Bitcoin-
 * attestation verifier, every height is OTS-CLAIMED (header-unverified) and
 * CANNOT rank; this command refuses to print a priority ranking in that case.
 */
async function cmdVerifyRegistry(opts: VerifyRegistryOptions): Promise<void> {
  const { snapshot, dir } = readRegistrySnapshot(opts.snapshotPath)
  const loadOtsProof = makeSnapshotOtsLoader(dir)

  // No Bitcoin-attestation oracle is wired in the CLI: this verifier confirms
  // structural `.ots` validity (file-digest match + parsed heights) but NOT
  // Bitcoin-header inclusion. Every height is therefore OTS-CLAIMED.
  const result = await verifyIndexSnapshot(snapshot, {
    loadOtsProof,
    minConfirmations: opts.minConfirmations,
  })

  process.stdout.write(
    `Registry snapshot verification — per-record .ots only.\n` +
      `The index is signed/mirrorable, NOT a tamper-proof log: it offers ZERO\n` +
      `cryptographic protection against operator censorship or equivocation. Each\n` +
      `record's truth is its own .ots against Bitcoin.\n\n`,
  )

  let okCount = 0
  let failCount = 0
  for (const rec of result.records) {
    if (rec.ok) {
      okCount++
      const heights = rec.bitcoinHeights
        .map((h) => `${h.height} [${h.finality === 'bitcoin-final' ? 'Bitcoin-final' : 'OTS-CLAIMED, NOT Bitcoin-final'}]`)
        .join(', ')
      process.stdout.write(
        `  ✓ ${rec.claimHash}\n` +
          `      structural .ots OK; heights: ${heights.length > 0 ? heights : '(none — pending)'}\n`,
      )
    } else {
      failCount++
      process.stdout.write(`  ✗ ${rec.claimHash}\n      ${rec.reason}\n`)
    }
  }

  // Priority is Bitcoin-only and requires Bitcoin-final heights. Without an
  // attestation oracle (none in the CLI), all heights are OTS-claimed and the
  // contest is undetermined — refuse to print a ranking rather than fake one.
  const contenders: PriorityContender[] = result.records.map((r) => ({
    claimHash: r.claimHash,
    result: r,
  }))
  const priority = resolvePriority(contenders)
  process.stdout.write(`\nPriority / dispute resolution (Bitcoin block height ONLY):\n`)
  printPriorityOutcome(priority)

  process.stdout.write(`\n${okCount} verified, ${failCount} failed.\n`)
  if (failCount > 0) process.exit(2)
  process.exit(0)
}

interface RegistryPriorityOptions {
  snapshotPath: string
  minConfirmations: number
  claimHashes: string[]
}

/**
 * Bitcoin-only priority / dispute lookup across a snapshot (optionally narrowed
 * to a set of contender claimHashes). Ranks by EARLIEST Bitcoin block height;
 * same block ⇒ tie; ETH anchors never rank; `registeredAt` is ignored. Because
 * the CLI wires no Bitcoin-attestation oracle, all heights are OTS-CLAIMED and
 * the contest resolves `undetermined` — proving earliest anchored commitment
 * requires header-verified heights, which this surface honestly refuses to fake.
 */
async function cmdRegistryPriority(opts: RegistryPriorityOptions): Promise<void> {
  const { snapshot, dir } = readRegistrySnapshot(opts.snapshotPath)
  const loadOtsProof = makeSnapshotOtsLoader(dir)
  const result = await verifyIndexSnapshot(snapshot, {
    loadOtsProof,
    minConfirmations: opts.minConfirmations,
  })

  let recs = result.records
  if (opts.claimHashes.length > 0) {
    const wanted = new Set(opts.claimHashes.map((h) => h.toLowerCase()))
    recs = recs.filter((r) => wanted.has(r.claimHash.toLowerCase()))
  }

  const contenders: PriorityContender[] = recs.map((r) => ({ claimHash: r.claimHash, result: r }))
  const priority = resolvePriority(contenders)
  process.stdout.write(
    `Priority / dispute resolution — Bitcoin block height ONLY (proves earliest\n` +
      `anchored commitment, NOT authorship or originality):\n`,
  )
  printPriorityOutcome(priority)
  process.exit(0)
}

function printPriorityOutcome(priority: ReturnType<typeof resolvePriority>): void {
  switch (priority.outcome) {
    case 'winner':
      process.stdout.write(
        `  WINNER — ${priority.claimHash} at Bitcoin block ${priority.bitcoinHeight}.\n`,
      )
      break
    case 'tie':
      process.stdout.write(
        `  TIE — at Bitcoin block ${priority.bitcoinHeight} (no sub-block ordering):\n` +
          priority.claimHashes.map((h) => `      ${h}\n`).join(''),
      )
      break
    case 'undetermined':
      process.stdout.write(`  UNDETERMINED — ${priority.reason}.\n`)
      if (priority.reason === 'heights-not-bitcoin-final') {
        process.stdout.write(
          `      All candidate heights are OTS-CLAIMED, not Bitcoin-final. Ranking requires\n` +
            `      an attestation verifier that confirms Bitcoin-header inclusion; this CLI\n` +
            `      wires none, so it refuses to assert a priority winner.\n`,
        )
      }
      break
  }
}

// ---------------------------------------------------------------------------
// Argv parsing
// ---------------------------------------------------------------------------

function printUsage(): void {
  process.stderr.write(BANNER + '\n')
  process.stderr.write(`Usage:
  ${CLI_NAME} register <file> [--encrypt-title TITLE] [--encrypt-author AUTHOR]
                       [--training-mining allowed|notAllowed|constrained]
                       [--no-scene-tree] [--mock] [--password PASSWORD]
                       [--evidence] [--loose] [--envelope-out PATH] [--ots-out PATH]
                       [--identity] [--identity-key-out PATH]
                       [--previous-claim-hash sha256:...]
                       Default: writes ONE self-contained <file>.screenreg (your
                       screenplay + the proof in a single file). --evidence also
                       writes a proof-only <file>.evidence.screenreg (no screenplay)
                       for sharing. --loose (or --envelope-out/--ots-out) emits the
                       separate manifest + .ots instead, for integrators. --identity
                       always writes the private key as a separate .pem (never in a bundle).
  ${CLI_NAME} verify <file.screenreg> [screenplay]
  ${CLI_NAME} verify <file> <envelope> <ots>
                       [--require-bitcoin-anchor] [--bitcoin-rpc URL] [--bitcoin-rpc-cookie PATH]
                       [--explorer mempool|blockstream] [--eth-rpc URL] [--eth-min-confirmations N]
                       Verify a single .screenreg (contents confirmed from the
                       embedded screenplay; a proof-only bundle verifies the date,
                       add the screenplay to also confirm contents) — or the loose
                       3-file artifacts. The flags below apply to both forms.
                       Default: pending proofs still exit 0 with a warning headline.
                       --require-bitcoin-anchor: exit 2 unless the proof has been
                       upgraded to a Bitcoin block attestation (use in CI / scripts
                       that must gate on independent Bitcoin verifiability).
                       --bitcoin-rpc URL: confirm the attested merkle root against
                       real block headers from your own Bitcoin Core node (TRUSTLESS;
                       a pruned node works, no wallet). Auth via --bitcoin-rpc-cookie
                       <.cookie path> or rpcuser:rpcpassword in the URL; URL/cookie
                       also read from BITCOIN_RPC_URL / BITCOIN_RPC_COOKIE. A merkle-
                       root MISMATCH fails (exit 2); an unreachable node is
                       informational. --explorer mempool|blockstream: same check via
                       a public explorer (TRUSTED third party), usable as a fallback.
                       --eth-rpc URL: if the envelope carries an ethereum-anchor
                       proof, also check it on-chain (topics-only) and print the
                       result as INFORMATIONAL. The Ethereum anchor is a secondary
                       witness — its result NEVER changes the Bitcoin verdict or the
                       exit status; an unreachable RPC degrades to "unverified".
                       --eth-min-confirmations N: confirmations required for the
                       Ethereum anchor to count as final (default 12).
  ${CLI_NAME} diagnose <file> [envelope] [ots]
  ${CLI_NAME} similarity <bundleA> <bundleB> [--envelope-a PATH] [--envelope-b PATH]
  ${CLI_NAME} disclose-comparison <input> [public-out.json] [--yes-i-understand]
                       <input> may be: the screenplay, its .manifest.json, or the
                       .comparison-bundle.private.json directly. Default public-out
                       is derived by stripping ".private" from the bundle filename.
  ${CLI_NAME} sign-challenge <claim-hash> <challenge-hex> <private-key.pem>
  ${CLI_NAME} verify-signature <envelope> <challenge-hex> <signature-hex>
  ${CLI_NAME} verify-registration <envelope>
  ${CLI_NAME} attach-eth-anchor <envelope> --contract 0x… --registrant 0x…
                       --tx-hash 0x… --log-index N --block-number N
                       [--chain-id N] [--out PATH]
                       Attaches an OPTIONAL Ethereum-mainnet anchor (a secondary,
                       additive witness) to a NEW envelope; the original + its .ots
                       stay valid. The proof is bound to the envelope's recomputed
                       claimHash and re-validated against the v1 schema. The anchor
                       is NEVER a priority or time source — Bitcoin stays the sole
                       anchor. Default --chain-id is mainnet (1); --out defaults to
                       <envelope>.eth-anchored.json (never overwrites in place).
  ${CLI_NAME} registry-build <envelope> [--proof-ref FILE] [--title TITLE]
                       [--author-pubkey ed25519:…] [--author-name NAME]
                       [--registered-at ISO] [--out PATH]
                       Builds an off-chain registry-index record (discovery
                       convenience) from an envelope. claimHash is recomputed from
                       the envelope; the script contentHash is FORBIDDEN. --proof-ref
                       defaults to the envelope's opentimestamps proofRef. Writes to
                       stdout unless --out is given.
  ${CLI_NAME} registry-search <snapshot.json> [--claim-hash sha256:…]
                       [--title SUBSTR] [--author SUBSTR]
                       Searches a snapshot ({"records":[…]}) by PUBLIC labels only.
  ${CLI_NAME} verify-registry <snapshot.json> [--min-confirmations N]
                       Re-verifies every record's .ots against Bitcoin (per-record
                       only — no snapshot-root step). The index is signed/mirrorable,
                       NOT a tamper-proof log. Without an attestation verifier (the
                       CLI wires none) heights are OTS-CLAIMED, NOT Bitcoin-final, so
                       it REFUSES to assert a priority ranking.
  ${CLI_NAME} registry-priority <snapshot.json> [--claim-hash sha256:…]…
                       [--min-confirmations N]
                       Bitcoin-only priority / dispute lookup. Ranks by earliest
                       Bitcoin block height (same block ⇒ tie); ETH never ranks;
                       registeredAt is ignored. Proves earliest anchored commitment,
                       NOT authorship. Undetermined when heights are not Bitcoin-final.
  ${CLI_NAME} timelock-encrypt <envelope> <fieldName> <unlockAt-ISO> <plaintext>
                       --out PATH --i-understand-must-restamp
                       Adds a timelock field to a NEW envelope file (--out PATH; never
                       overwrites the input). The new envelope has NO valid OTS proof;
                       you MUST re-stamp (or chain via previousRegistration) before
                       it verifies. The original envelope + .ots stay untouched.
  ${CLI_NAME} timelock-decrypt <envelope> <fieldName>
  ${CLI_NAME} generate-identity <output-private-key.pem>
  ${CLI_NAME} finalize <ots|.screenreg> [--out PATH] [--timeout-ms N]   (alias: upgrade)
                       [--watch [--interval SECONDS] [--max-checks N]]
                       Folds the Bitcoin attestation into a pending proof once the
                       calendars have it (typically 1-6 h after registration). Accepts a
                       bare .ots OR a .screenreg (unpacks, upgrades, repacks in place).
                       Writes in place (or to --out), via the clean-room TS engine — no
                       Python. Exit: 0 confirmed, 3 still pending, 1 error.
                       --watch: keep polling with a live countdown until the proof
                       confirms (--interval between checks, default 600s; --max-checks
                       gives up with exit 3 after N pending checks).
  ${CLI_NAME} normalize <file>
  ${CLI_NAME} claim <file>
  ${CLI_NAME} scene-prove <file> <envelope> <sceneIndex>
  ${CLI_NAME} scene-verify <root> <sceneContent-base64> <proof.json>
  ${CLI_NAME} decrypt-field <envelope> <fieldName>
  ${CLI_NAME} extract <input.pdf> [--out PATH] [--preserve-page-numbers]
                       [--preserve-scene-numbers]
                       Extracts a PDF to Fountain text via the reference
                       extractor. Writes to stdout by default; --out PATH
                       writes to a file (with a confidence summary on
                       stderr). Recommended flow: extract, manually review
                       the .fountain output, then register that file.

  ${CLI_NAME} pack <envelope.manifest.json> [--source FILE] [--ots FILE]
                       [--evidence] [--out FILE.screenreg]
                       Bundles a registration into one .screenreg file. With
                       --source, the bundle is self-contained (embeds the
                       screenplay text); without it (or with --evidence), it
                       is proof-only. The .ots defaults to the proof the
                       envelope references. claimHash is never changed.
  ${CLI_NAME} unpack <file.screenreg> [--out-dir DIR]            (alias: open)
                       Verifies a .screenreg (checks every entry's digest) and
                       prints what it contains. With --out-dir, also extracts
                       the files. Exits non-zero if integrity fails.
`)
}

interface ExtractOptions {
  outPath: string | undefined
  stripPageNumbers: boolean
  stripSceneNumbers: boolean
}

async function cmdExtract(inputFile: string, opts: ExtractOptions): Promise<void> {
  // The reference extractor is loaded lazily so users who never extract a
  // PDF never pay the pdf2json install / load cost. ExtractorError surfaces
  // typed failure codes; this CLI maps each code to a stable exit status so
  // shell scripts can react to the specific rejection reason.
  let extractorModule
  try {
    extractorModule = await import('../extractors/reference/index.js')
  } catch (err) {
    die(
      `extract: failed to load reference extractor: ${err instanceof Error ? err.message : String(err)}`,
    )
  }
  const extractor = extractorModule.default

  let pdfBytes: Uint8Array
  try {
    const buf = readFileSync(inputFile)
    pdfBytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  } catch (err) {
    die(`extract: cannot read ${inputFile}: ${err instanceof Error ? err.message : String(err)}`)
  }

  try {
    const result = await extractor.extract(pdfBytes, {
      stripPageNumbers: opts.stripPageNumbers,
      stripSceneNumbers: opts.stripSceneNumbers,
    })
    const outBytes = Buffer.from(result.fountain, 'utf8')
    if (opts.outPath !== undefined) {
      writeFileSync(opts.outPath, outBytes)
      process.stderr.write(
        `✓ extracted ${outBytes.length} bytes (confidence ${result.confidence.toFixed(2)}) → ${opts.outPath}\n`,
      )
      if (result.confidence < 0.85) {
        process.stderr.write(
          `⚠  confidence ${result.confidence.toFixed(2)} < 0.85 — review the extracted Fountain before registering.\n`,
        )
      }
    } else {
      process.stdout.write(outBytes)
      // No success line on stderr in stdout mode; the user's pipeline will
      // see Fountain on stdout and any warnings on stderr.
      if (result.confidence < 0.85) {
        process.stderr.write(
          `⚠  confidence ${result.confidence.toFixed(2)} < 0.85 — review the extracted Fountain before registering.\n`,
        )
      }
    }
  } catch (err) {
    if (err instanceof Error && 'code' in err) {
      const code = (err as { code: unknown }).code
      // Map typed extractor codes to stable exit statuses for scripts.
      const exitByCode: Record<string, number> = {
        EXTRACT_NO_TEXT_LAYER: 10,
        EXTRACT_ENCRYPTED: 11,
        EXTRACT_UNSUPPORTED_LAYOUT: 12,
        EXTRACT_CORRUPTED: 13,
        EXTRACT_AMBIGUOUS_BLOCKS: 14,
        EXTRACT_DEPENDENCY_MISSING: 15,
      }
      const exit = typeof code === 'string' ? exitByCode[code] ?? 2 : 2
      process.stderr.write(
        `extract failed [${typeof code === 'string' ? code : 'UNKNOWN'}]: ${err.message}\n`,
      )
      if (code === 'EXTRACT_DEPENDENCY_MISSING') {
        process.stderr.write(
          `\nTo install: npm install pdf2json\n` +
            `Or use a different PdfExtractor implementation.\n`,
        )
      }
      process.exit(exit)
    }
    die(`extract failed: ${err instanceof Error ? err.message : String(err)}`)
  }
}

// ---------------------------------------------------------------------------
// pack / unpack — the single-file `.screenreg` container (spec §11)
// ---------------------------------------------------------------------------

function readBytesOrDie(path: string, ctx: string): Uint8Array {
  try {
    const buf = readFileSync(path)
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  } catch (err) {
    die(`${ctx} ${path}: ${err instanceof Error ? err.message : String(err)}`)
  }
}

interface PackOptions {
  envelopePath: string
  sourcePath?: string
  otsPath?: string
  outPath?: string
  evidence: boolean
}

/**
 * Zip a registration's loose artifacts into one `.screenreg`. Packs an already-built envelope
 * (plus its OpenTimestamps proof, and — for a full bundle — the source text). The container is
 * not commitment-bearing; this never recomputes or alters `claimHash`.
 */
async function cmdPack(opts: PackOptions): Promise<void> {
  if (opts.evidence && opts.sourcePath !== undefined) {
    die('pack: --evidence and --source are mutually exclusive (an evidence bundle carries no source text)')
  }

  let envelope: SharedEnvelope
  try {
    envelope = JSON.parse(readFileSync(opts.envelopePath, 'utf8')) as SharedEnvelope
  } catch (err) {
    die(`pack: cannot read envelope ${opts.envelopePath}: ${err instanceof Error ? err.message : String(err)}`)
  }
  const validation = validateEnvelope(envelope)
  if (!validation.ok) {
    die(`pack: invalid envelope:\n  - ${validation.errors.join('\n  - ')}`)
  }

  // Resolve the OTS proof bytes: explicit --ots wins; otherwise the proof the envelope references
  // (proofRef), looked up next to the envelope. basename() on the ref keeps the lookup local.
  let otsBytes: Uint8Array | undefined
  const otsProof = envelope.evidenceBundle.proofs.find(
    (p) => (p as { type?: string }).type === 'opentimestamps',
  ) as { proofRef?: string } | undefined
  if (opts.otsPath !== undefined) {
    otsBytes = readBytesOrDie(opts.otsPath, 'pack: cannot read --ots')
  } else if (otsProof) {
    if (!otsProof.proofRef) die('pack: the envelope OTS proof has no proofRef; pass --ots <file.ots>')
    const otsResolved = join(dirname(opts.envelopePath), basename(otsProof.proofRef))
    if (!existsSync(otsResolved)) {
      die(`pack: cannot find the OTS proof "${otsProof.proofRef}" beside the envelope; pass --ots <file.ots>`)
    }
    otsBytes = readBytesOrDie(otsResolved, 'pack: cannot read OTS proof')
  }

  const wantFull = !opts.evidence && opts.sourcePath !== undefined
  const input: BuildBundleInput = { envelope }
  if (otsBytes) input.otsBytes = otsBytes
  if (wantFull) {
    const sourceBytes = readBytesOrDie(opts.sourcePath!, 'pack: cannot read --source')
    // Refuse to pack a source that does not hash to the committed contentHash — that would build
    // a "full" bundle which fails verification, the worst kind of silent footgun.
    const ch = contentHash(Buffer.from(sourceBytes))
    if (ch !== envelope.committedClaim.contentHash) {
      die(
        `pack: --source does not match the envelope's contentHash\n` +
          `      source: ${ch ?? '(not valid UTF-8)'}\n` +
          `      claim:  ${envelope.committedClaim.contentHash}\n` +
          `      (a full bundle with a mismatched source would fail verification)`,
      )
    }
    input.sourceText = sourceBytes
  }

  let bundle: Uint8Array
  try {
    bundle = wantFull ? await buildScreenreg(input) : await buildEvidenceScreenreg(input)
  } catch (err) {
    if (err instanceof ScreenregError) die(`pack: ${err.message}`)
    throw err
  }

  const base = opts.envelopePath.endsWith('.manifest.json')
    ? opts.envelopePath.slice(0, -'.manifest.json'.length)
    : opts.envelopePath.replace(/\.[^./]+$/, '')
  const outPath = opts.outPath ?? `${base}${wantFull ? '' : '.evidence'}.screenreg`
  // Refuse to write THROUGH a pre-existing symlink: writeFileSync follows it, so a link named
  // like the output but pointing at the envelope (or any other file) would silently clobber the
  // target. lstat does not follow, so this catches both live and dangling links.
  let outLstat
  try {
    outLstat = lstatSync(outPath)
  } catch {
    outLstat = undefined // nothing there yet — fine
  }
  if (outLstat?.isSymbolicLink()) {
    die(`pack: refusing to write through the existing symlink ${outPath}`)
  }
  // Never write the bundle directly over one of its own inputs either.
  const resolvedOut = resolve(outPath)
  for (const [label, p] of [
    ['envelope', opts.envelopePath],
    ['--source', opts.sourcePath],
    ['--ots', opts.otsPath],
  ] as const) {
    if (p !== undefined && resolve(p) === resolvedOut) {
      die(`pack: --out would overwrite the ${label} input (${p})`)
    }
  }
  try {
    writeFileSync(outPath, bundle)
  } catch (err) {
    die(`pack: cannot write ${outPath}: ${err instanceof Error ? err.message : String(err)}`)
  }
  process.stderr.write(
    `✓ packed ${wantFull ? 'full' : 'evidence'} bundle (${bundle.length} bytes) → ${outPath}\n` +
      `  claimHash: ${envelope.evidenceBundle.committedClaimHash}\n` +
      (wantFull
        ? '  (self-contained — includes the screenplay text)\n'
        : '  (proof-only — no screenplay text; safe to share)\n'),
  )
}

interface UnpackOptions {
  bundlePath: string
  outDir?: string
}

/**
 * Open a `.screenreg`: verify it (the read path folds in each entry's SHA-256), report what it
 * contains, and optionally extract the files. Exits non-zero if integrity fails.
 */
async function cmdUnpack(opts: UnpackOptions): Promise<void> {
  const bytes = readBytesOrDie(opts.bundlePath, 'unpack: cannot read')
  let parsed: Awaited<ReturnType<typeof readScreenreg>>
  try {
    parsed = await readScreenreg(bytes)
  } catch (err) {
    die(`unpack: ${err instanceof Error ? err.message : String(err)}`)
  }

  // Validate the embedded envelope before dereferencing it: a digest-valid bundle can still carry
  // a malformed envelope, and that must surface as a clear error, not a raw property-access crash.
  const ev = validateEnvelope(parsed.envelope)
  if (!ev.ok) {
    die(`unpack: ${opts.bundlePath} contains an invalid envelope:\n  - ${ev.errors.join('\n  - ')}`)
  }

  const d = parsed.descriptor
  process.stderr.write(
    `${opts.bundlePath}: ${d.bundleType} bundle\n` +
      `  claimHash: ${parsed.envelope.evidenceBundle.committedClaimHash}\n` +
      `  contents:  ${d.entries.map((e) => e.path).join(', ')}\n` +
      `  integrity: ${parsed.integrity.ok ? 'OK — all declared digests match' : 'FAILED'}\n`,
  )

  // Integrity gates extraction: never write files out of a bundle whose declared digests do not
  // match. Report the failures and stop before touching the filesystem.
  if (!parsed.integrity.ok) {
    for (const issue of parsed.integrity.issues) process.stderr.write(`    ✗ ${issue}\n`)
    process.exit(1)
  }

  if (opts.outDir !== undefined) {
    // Extract ONLY the descriptor-declared (hence digest-verified) entries, plus the descriptor
    // itself — never arbitrary physical ZIP members. This blocks a hostile bundle that appends an
    // undeclared "../envelope.json" which basename-flattening would otherwise map onto a real file.
    const map = new Map<string, Uint8Array>()
    for (const e of unzipStore(bytes)) map.set(e.name, e.bytes)
    const declaredPaths = [ENTRY_DESCRIPTOR, ...d.entries.map((e) => e.path)]

    // Preflight: resolve safe basenames and detect unsafe names / collisions BEFORE creating the
    // directory or writing anything, so a malformed bundle never leaves a partial extraction.
    const toWrite = new Map<string, Uint8Array>() // basename → bytes
    for (const path of declaredPaths) {
      const data = map.get(path)
      if (!data) continue // declared entries were proven present by readScreenreg; defensive
      // Flatten to the basename to neutralize any "../" traversal in a crafted name.
      const safe = basename(path)
      if (!safe || safe === '.' || safe === '..') {
        die(`unpack: refusing to extract an entry with an unsafe name (${JSON.stringify(path)})`)
      }
      if (toWrite.has(safe)) {
        die(`unpack: refusing to extract — two entries collide on the name "${safe}"`)
      }
      toWrite.set(safe, data)
    }

    try {
      mkdirSync(opts.outDir, { recursive: true })
    } catch (err) {
      die(`unpack: cannot create ${opts.outDir}: ${err instanceof Error ? err.message : String(err)}`)
    }
    for (const [safe, data] of toWrite) writeFileSync(join(opts.outDir, safe), data)
    process.stderr.write(`✓ extracted ${toWrite.size} file${toWrite.size === 1 ? '' : 's'} → ${opts.outDir}/\n`)
  }
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2)
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    printUsage()
    process.exit(argv.length === 0 ? 1 : 0)
  }

  const cmd = argv[0]!
  const rest = argv.slice(1)

  switch (cmd) {
    case 'register': {
      const opts: RegisterOptions = { inputFile: '' }
      const requireArg = (flag: string, val: string | undefined): string => {
        if (val === undefined) die(`${flag} requires an argument`)
        return val
      }
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--encrypt-title') opts.encryptTitle = requireArg(a, rest[++i])
        else if (a === '--encrypt-author') opts.encryptAuthor = requireArg(a, rest[++i])
        else if (a === '--training-mining') {
          const raw = requireArg(a, rest[++i])
          if (raw !== 'allowed' && raw !== 'notAllowed' && raw !== 'constrained') {
            die(`--training-mining: expected one of allowed|notAllowed|constrained, got ${JSON.stringify(raw)}`)
          }
          opts.trainingMining = raw
        } else if (a === '--no-scene-tree') opts.noSceneTree = true
        else if (a === '--mock') opts.mock = true
        else if (a === '--loose') opts.loose = true
        else if (a === '--evidence') opts.evidence = true
        else if (a === '--password') {
          opts.password = requireArg(a, rest[++i])
          process.stderr.write(
            `⚠  --password on the CLI exposes the password via process argv (visible to\n` +
              `   other users via \`ps\`). Use SCREENREG_PASSWORD_FILE=<path> or omit\n` +
              `   --password to be prompted.\n`,
          )
        }
        else if (a === '--envelope-out') opts.envelopeOut = requireArg(a, rest[++i])
        else if (a === '--ots-out') opts.otsOut = requireArg(a, rest[++i])
        else if (a === '--identity') opts.identity = true
        else if (a === '--identity-key-out') opts.identityKeyOut = requireArg(a, rest[++i])
        else if (a === '--previous-claim-hash') opts.previousClaimHash = requireArg(a, rest[++i])
        else if (a === '--source-pdf') opts.sourcePdf = requireArg(a, rest[++i])
        else if (!opts.inputFile) opts.inputFile = a
        else die(`unexpected positional argument: ${a}`)
      }
      if (!opts.inputFile) die('register: missing input file')
      await cmdRegister(opts)
      return
    }
    case 'similarity': {
      const positional: string[] = []
      let envelopeAPath: string | undefined
      let envelopeBPath: string | undefined
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--envelope-a') envelopeAPath = rest[++i]
        else if (a === '--envelope-b') envelopeBPath = rest[++i]
        else positional.push(a)
      }
      if (positional.length < 2) die('similarity: need <bundleA> <bundleB>')
      const simOpts: { envelopeAPath?: string; envelopeBPath?: string } = {}
      if (envelopeAPath !== undefined) simOpts.envelopeAPath = envelopeAPath
      if (envelopeBPath !== undefined) simOpts.envelopeBPath = envelopeBPath
      cmdSimilarity(positional[0]!, positional[1]!, simOpts)
      return
    }
    case 'disclose-comparison': {
      const positional: string[] = []
      let yesIUnderstand = false
      for (const a of rest) {
        if (a === '--yes-i-understand' || a === '-y') yesIUnderstand = true
        else positional.push(a)
      }
      if (positional.length < 1) die('disclose-comparison: need <input> [public-out.json]')
      cmdDiscloseComparison(positional[0]!, positional[1], { yesIUnderstand })
      return
    }
    case 'sign-challenge':
      if (rest.length < 3) die('sign-challenge: need <claim-hash> <challenge-hex> <private-key.pem>')
      cmdSignChallenge(rest[0]!, rest[1]!, rest[2]!)
      return
    case 'verify-signature':
      if (rest.length < 3) die('verify-signature: need <envelope> <challenge-hex> <signature-hex>')
      cmdVerifySignature(rest[0]!, rest[1]!, rest[2]!)
      return
    case 'verify-registration':
      if (rest.length < 1) die('verify-registration: need <envelope>')
      cmdVerifyRegistration(rest[0]!)
      return
    case 'timelock-encrypt': {
      const positional: string[] = []
      let outPath: string | undefined
      let iUnderstandMustRestamp = false
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--out') outPath = rest[++i]
        else if (a === '--i-understand-must-restamp') iUnderstandMustRestamp = true
        else positional.push(a)
      }
      if (positional.length < 4)
        die('timelock-encrypt: need <envelope> <fieldName> <unlockAt-ISO> <plaintext> --out PATH --i-understand-must-restamp')
      const encOpts: { outPath?: string; iUnderstandMustRestamp?: boolean } = {}
      if (outPath !== undefined) encOpts.outPath = outPath
      if (iUnderstandMustRestamp) encOpts.iUnderstandMustRestamp = true
      await cmdTimelockEncrypt(positional[0]!, positional[1]!, positional[2]!, positional[3]!, encOpts)
      return
    }
    case 'timelock-decrypt':
      if (rest.length < 2) die('timelock-decrypt: need <envelope> <fieldName>')
      await cmdTimelockDecrypt(rest[0]!, rest[1]!)
      return
    case 'generate-identity':
      if (rest.length < 1) die('generate-identity: need <output-private-key.pem>')
      cmdGenerateIdentity(rest[0]!)
      return
    case 'verify': {
      const positional: string[] = []
      let requireBitcoinAnchor = false
      let ethRpc: string | undefined
      let ethMinConfirmations: number | undefined
      let bitcoinRpc: string | undefined
      let bitcoinRpcCookie: string | undefined
      let explorer: ExplorerName | undefined
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--require-bitcoin-anchor') requireBitcoinAnchor = true
        else if (a === '--eth-rpc') {
          if (rest[i + 1] === undefined) die('--eth-rpc requires a URL argument')
          ethRpc = rest[++i]
        } else if (a === '--eth-min-confirmations') {
          if (rest[i + 1] === undefined) die('--eth-min-confirmations requires an argument')
          const n = Number.parseInt(rest[++i]!, 10)
          if (!Number.isInteger(n) || n < 1) die('--eth-min-confirmations must be a positive integer')
          ethMinConfirmations = n
        } else if (a === '--bitcoin-rpc') {
          if (rest[i + 1] === undefined) die('--bitcoin-rpc requires a URL argument')
          bitcoinRpc = rest[++i]
        } else if (a === '--bitcoin-rpc-cookie') {
          if (rest[i + 1] === undefined) die('--bitcoin-rpc-cookie requires a path argument')
          bitcoinRpcCookie = rest[++i]
        } else if (a === '--explorer') {
          const v = rest[++i]
          if (v !== 'mempool' && v !== 'blockstream') die('--explorer must be mempool or blockstream')
          explorer = v
        } else positional.push(a)
      }

      // Build the SPV header sources, tried in order: a local node first (trustless),
      // then a public explorer as fallback. URL/cookie also fall back to env vars.
      const headerSources: BitcoinHeaderSource[] = []
      const rpcUrl = bitcoinRpc ?? process.env.BITCOIN_RPC_URL
      const rpcCookie = bitcoinRpcCookie ?? process.env.BITCOIN_RPC_COOKIE
      if (rpcUrl) {
        try {
          headerSources.push(makeBitcoinRpcSource({ url: rpcUrl, ...(rpcCookie ? { cookiePath: rpcCookie } : {}) }))
        } catch (err) {
          die(`verify: ${err instanceof Error ? err.message : String(err)}`)
        }
      } else if (bitcoinRpcCookie !== undefined) {
        die('verify: --bitcoin-rpc-cookie requires --bitcoin-rpc (or BITCOIN_RPC_URL)')
      }
      if (explorer) headerSources.push(makeExplorerSource(explorer))

      const first = positional[0]
      if (first === undefined) {
        die('verify: need <file.screenreg>, or <file> <envelope> <ots> for loose artifacts')
      }
      // Single-file path: `verify <file.screenreg> [screenplay]`. The bundle is
      // the same artifact the browser /verify/ page accepts.
      if (first.endsWith('.screenreg')) {
        await cmdVerifyBundle({
          bundlePath: first,
          ...(positional[1] !== undefined ? { scriptPath: positional[1] } : {}),
          requireBitcoinAnchor,
          ...(ethRpc !== undefined ? { ethRpc } : {}),
          ...(ethMinConfirmations !== undefined ? { ethMinConfirmations } : {}),
          ...(headerSources.length > 0 ? { headerSources } : {}),
        })
        return
      }
      if (positional.length < 3) {
        die('verify: need <file.screenreg>, or <file> <envelope> <ots> for loose artifacts')
      }
      await cmdVerify({
        inputFile: positional[0]!,
        envelopePath: positional[1]!,
        otsPath: positional[2]!,
        requireBitcoinAnchor,
        ...(ethRpc !== undefined ? { ethRpc } : {}),
        ...(ethMinConfirmations !== undefined ? { ethMinConfirmations } : {}),
        ...(headerSources.length > 0 ? { headerSources } : {}),
      })
      return
    }
    case 'attach-eth-anchor': {
      const positional: string[] = []
      let contract: string | undefined
      let registrant: string | undefined
      let txHash: string | undefined
      let logIndex: number | undefined
      let blockNumber: number | undefined
      let chainId = CANONICAL_CHAIN_ID as number
      let outPath: string | undefined
      const reqInt = (flag: string, val: string | undefined): number => {
        if (val === undefined) die(`${flag} requires an integer argument`)
        const n = Number.parseInt(val, 10)
        if (!Number.isInteger(n) || n < 0) die(`${flag} must be a non-negative integer`)
        return n
      }
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--contract') contract = rest[++i]
        else if (a === '--registrant') registrant = rest[++i]
        else if (a === '--tx-hash') txHash = rest[++i]
        else if (a === '--log-index') logIndex = reqInt(a, rest[++i])
        else if (a === '--block-number') blockNumber = reqInt(a, rest[++i])
        else if (a === '--chain-id') chainId = reqInt(a, rest[++i])
        else if (a === '--out') outPath = rest[++i]
        else positional.push(a)
      }
      if (positional.length < 1) die('attach-eth-anchor: need <envelope>')
      if (contract === undefined) die('attach-eth-anchor: --contract <0x…> required')
      if (registrant === undefined) die('attach-eth-anchor: --registrant <0x…> required')
      if (txHash === undefined) die('attach-eth-anchor: --tx-hash <0x…> required')
      if (logIndex === undefined) die('attach-eth-anchor: --log-index <n> required')
      if (blockNumber === undefined) die('attach-eth-anchor: --block-number <n> required')
      cmdAttachEthAnchor({
        envelopePath: positional[0]!,
        contract,
        registrant,
        txHash,
        logIndex,
        blockNumber,
        chainId,
        outPath,
      })
      return
    }
    case 'registry-build': {
      const positional: string[] = []
      let proofRef: string | undefined
      let title: string | undefined
      let authorPubkey: string | undefined
      let authorName: string | undefined
      let registeredAt: string | undefined
      let outPath: string | undefined
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--proof-ref') proofRef = rest[++i]
        else if (a === '--title') title = rest[++i]
        else if (a === '--author-pubkey') authorPubkey = rest[++i]
        else if (a === '--author-name') authorName = rest[++i]
        else if (a === '--registered-at') registeredAt = rest[++i]
        else if (a === '--out') outPath = rest[++i]
        else positional.push(a)
      }
      if (positional.length < 1) die('registry-build: need <envelope>')
      cmdRegistryBuild({
        envelopePath: positional[0]!,
        proofRef,
        title,
        authorPubkey,
        authorName,
        registeredAt,
        outPath,
      })
      return
    }
    case 'registry-search': {
      const positional: string[] = []
      let claimHash: string | undefined
      let title: string | undefined
      let author: string | undefined
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--claim-hash') claimHash = rest[++i]
        else if (a === '--title') title = rest[++i]
        else if (a === '--author') author = rest[++i]
        else positional.push(a)
      }
      if (positional.length < 1) die('registry-search: need <snapshot.json>')
      if (claimHash === undefined && title === undefined && author === undefined) {
        die('registry-search: supply at least one of --claim-hash / --title / --author')
      }
      cmdRegistrySearch({ snapshotPath: positional[0]!, claimHash, title, author })
      return
    }
    case 'verify-registry': {
      const positional: string[] = []
      let minConfirmations = 6
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--min-confirmations') {
          const n = Number.parseInt(rest[++i] ?? '', 10)
          if (!Number.isInteger(n) || n < 1) die('--min-confirmations must be a positive integer')
          minConfirmations = n
        } else positional.push(a)
      }
      if (positional.length < 1) die('verify-registry: need <snapshot.json>')
      await cmdVerifyRegistry({ snapshotPath: positional[0]!, minConfirmations })
      return
    }
    case 'registry-priority': {
      const positional: string[] = []
      const claimHashes: string[] = []
      let minConfirmations = 6
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--claim-hash') {
          const v = rest[++i]
          if (v === undefined) die('--claim-hash requires an argument')
          claimHashes.push(v)
        } else if (a === '--min-confirmations') {
          const n = Number.parseInt(rest[++i] ?? '', 10)
          if (!Number.isInteger(n) || n < 1) die('--min-confirmations must be a positive integer')
          minConfirmations = n
        } else positional.push(a)
      }
      if (positional.length < 1) die('registry-priority: need <snapshot.json>')
      await cmdRegistryPriority({ snapshotPath: positional[0]!, minConfirmations, claimHashes })
      return
    }
    case 'diagnose': {
      if (rest.length < 1) die('diagnose: need <file>')
      const opts: DiagnoseOptions = { inputFile: rest[0]! }
      if (rest[1] !== undefined) opts.envelopePath = rest[1]
      if (rest[2] !== undefined) opts.otsPath = rest[2]
      cmdDiagnose(opts)
      return
    }
    case 'finalize':
    case 'upgrade': {
      const positional: string[] = []
      let outPath: string | undefined
      let timeoutMs: number | undefined
      let watch = false
      let intervalSeconds: number | undefined
      let maxChecks: number | undefined
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--out' || a === '-o') {
          if (rest[i + 1] === undefined) die('--out requires an argument')
          outPath = rest[++i]
        } else if (a === '--timeout-ms') {
          const v = rest[++i]
          if (v === undefined) die('--timeout-ms requires an argument')
          const n = Number(v)
          if (!Number.isInteger(n) || n <= 0) die(`--timeout-ms: expected a positive integer, got ${JSON.stringify(v)}`)
          timeoutMs = n
        } else if (a === '--watch' || a === '-w') {
          watch = true
        } else if (a === '--interval') {
          const v = rest[++i]
          if (v === undefined) die('--interval requires an argument (seconds)')
          const n = Number(v)
          if (!Number.isInteger(n) || n < 1) die(`--interval: expected a positive integer of seconds, got ${JSON.stringify(v)}`)
          intervalSeconds = n
        } else if (a === '--max-checks') {
          const v = rest[++i]
          if (v === undefined) die('--max-checks requires an argument')
          const n = Number(v)
          if (!Number.isInteger(n) || n < 1) die(`--max-checks: expected a positive integer, got ${JSON.stringify(v)}`)
          maxChecks = n
        } else if (!a.startsWith('-')) {
          positional.push(a)
        } else {
          die(`${cmd}: unexpected argument: ${a}`)
        }
      }
      if (positional.length < 1) die(`${cmd}: need <ots>`)
      if (positional.length > 1) die(`${cmd}: too many arguments — pass one <ots> path (use --out for a different output path)`)
      if ((intervalSeconds !== undefined || maxChecks !== undefined) && !watch) {
        die(`${cmd}: --interval / --max-checks only apply with --watch`)
      }
      const fo: FinalizeCliOptions = { otsPath: positional[0]! }
      if (outPath !== undefined) fo.outPath = outPath
      if (timeoutMs !== undefined) fo.timeoutMs = timeoutMs
      if (watch) fo.watch = true
      if (intervalSeconds !== undefined) fo.intervalSeconds = intervalSeconds
      if (maxChecks !== undefined) fo.maxChecks = maxChecks
      await cmdFinalize(fo)
      return
    }
    case 'normalize':
      if (rest.length < 1) die('normalize: need <file>')
      cmdNormalize(rest[0]!)
      return
    case 'claim':
      if (rest.length < 1) die('claim: need <file>')
      cmdClaim(rest[0]!)
      return
    case 'scene-prove':
      if (rest.length < 3) die('scene-prove: need <file> <envelope> <sceneIndex>')
      cmdSceneProve(rest[0]!, rest[1]!, parseInt(rest[2]!, 10))
      return
    case 'scene-verify':
      if (rest.length < 3) die('scene-verify: need <root> <sceneContent-base64> <proof.json>')
      cmdSceneVerify(rest[0]!, rest[1]!, rest[2]!)
      return
    case 'decrypt-field':
      if (rest.length < 2) die('decrypt-field: need <envelope> <fieldName>')
      await cmdDecryptField(rest[0]!, rest[1]!)
      return
    case 'extract': {
      const positional: string[] = []
      let outPath: string | undefined
      let stripPageNumbers = true
      let stripSceneNumbers = true
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--out' || a === '-o') {
          if (rest[i + 1] === undefined) die('--out requires an argument')
          outPath = rest[++i]
        } else if (a === '--preserve-page-numbers') {
          stripPageNumbers = false
        } else if (a === '--preserve-scene-numbers') {
          stripSceneNumbers = false
        } else {
          positional.push(a)
        }
      }
      if (positional.length < 1) {
        die(
          'extract: need <input.pdf> [--out <file.fountain>]\n' +
            '         (no --out → writes Fountain to stdout)',
        )
      }
      await cmdExtract(positional[0]!, {
        outPath,
        stripPageNumbers,
        stripSceneNumbers,
      })
      return
    }
    case 'pack': {
      const positional: string[] = []
      let sourcePath: string | undefined
      let otsPath: string | undefined
      let outPath: string | undefined
      let evidence = false
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--source' || a === '-s') {
          if (rest[i + 1] === undefined) die('--source requires an argument')
          sourcePath = rest[++i]
        } else if (a === '--ots') {
          if (rest[i + 1] === undefined) die('--ots requires an argument')
          otsPath = rest[++i]
        } else if (a === '--out' || a === '-o') {
          if (rest[i + 1] === undefined) die('--out requires an argument')
          outPath = rest[++i]
        } else if (a === '--evidence') {
          evidence = true
        } else if (!a.startsWith('-')) {
          positional.push(a)
        } else {
          die(`pack: unexpected argument: ${a}`)
        }
      }
      if (positional.length < 1) {
        die(
          'pack: need <envelope.manifest.json> [--source <file>] [--ots <file>] [--evidence] [--out <file.screenreg>]\n' +
            '      --source <file>  embed the screenplay text (full bundle); omit for a proof-only bundle\n' +
            '      --ots <file>     OpenTimestamps proof (default: the proof the envelope references)',
        )
      }
      if (positional.length > 1) die('pack: too many arguments — pass one envelope path')
      const po: PackOptions = { envelopePath: positional[0]!, evidence }
      if (sourcePath !== undefined) po.sourcePath = sourcePath
      if (otsPath !== undefined) po.otsPath = otsPath
      if (outPath !== undefined) po.outPath = outPath
      await cmdPack(po)
      return
    }
    case 'unpack':
    case 'open': {
      const positional: string[] = []
      let outDir: string | undefined
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]!
        if (a === '--out-dir' || a === '-d') {
          if (rest[i + 1] === undefined) die('--out-dir requires an argument')
          outDir = rest[++i]
        } else if (!a.startsWith('-')) {
          positional.push(a)
        } else {
          die(`${cmd}: unexpected argument: ${a}`)
        }
      }
      if (positional.length < 1) die(`${cmd}: need <file.screenreg> [--out-dir <dir>]`)
      if (positional.length > 1) die(`${cmd}: too many arguments — pass one .screenreg path`)
      const uo: UnpackOptions = { bundlePath: positional[0]! }
      if (outDir !== undefined) uo.outDir = outDir
      await cmdUnpack(uo)
      return
    }
    default:
      printUsage()
      die(`unknown command: ${cmd}`, 1)
  }
}

main().catch((e) => die(e?.message ?? String(e)))
