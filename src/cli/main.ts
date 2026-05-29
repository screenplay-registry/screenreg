/**
 * The Screenplay Registry — CLI entry point.
 *
 * Subcommands:
 *   register <file>            — normalize, build claim, stamp via OTS, emit envelope + .ots
 *   verify <file> <env> <ots>  — binary OK/FAILED verification
 *   diagnose <file> [env] [ots] — honest transform analysis (mode matrix per spec §6)
 *   upgrade <ots>              — block until Bitcoin-confirmed (subprocess to `ots upgrade`)
 *   normalize <file>           — debug: print normalized bytes + hash
 *   claim <file>               — debug: build committedClaim + print claimHash
 *   scene-prove <file> <env> <sceneIndex>  — generate selective-disclosure proof
 *   scene-verify <root> <sceneContent-base64> <proof-json>
 *   decrypt-field <env> <fieldName>  — prompts for password, decrypts and prints field
 */

import { readFileSync, writeFileSync, existsSync, readSync, openSync, writeSync, closeSync, fchmodSync, lstatSync, unlinkSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
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
import {
  buildEncryptedFieldsBlock,
  decryptFieldsBlock,
  type EncryptedFieldsBlock,
} from '../encrypt/fields.js'
import type { Envelope } from '../envelope/types.js'

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

  process.stderr.write(`Stamping claim hash via OpenTimestamps...\n`)
  const stampResult = await submitOts({ digest: claimHashBytes, mock: !!opts.mock })
  if (!stampResult.ok) {
    die(`OTS submission failed: ${stampResult.reason}${stampResult.stderr ? '\n' + stampResult.stderr : ''}`)
  }

  const otsOutputPath = opts.otsOut ?? getOtsOutputPath(opts.inputFile)
  writeFileSync(otsOutputPath, stampResult.otsBytes)

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

  const envelopeOutputPath = opts.envelopeOut ?? getEnvelopeOutputPath(opts.inputFile)
  writeFileSync(envelopeOutputPath, JSON.stringify(envelope, null, 2) + '\n')

  process.stderr.write(`\n✓ Registration complete.\n`)
  process.stderr.write(`  Claim hash: ${claimHash}\n`)
  process.stderr.write(`  Envelope:   ${envelopeOutputPath}\n`)
  process.stderr.write(`  OTS proof:  ${otsOutputPath}\n`)
  if (opts.mock) {
    process.stderr.write(`  (Mock mode — proof is a placeholder, not anchored to Bitcoin.)\n`)
  } else {
    process.stderr.write(`  Bitcoin confirmation typically takes 1-6 hours. Run \`${CLI_NAME} upgrade ${otsOutputPath}\` later.\n`)
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
}

function cmdVerify(opts: VerifyOptions): void {
  const raw = readScreenplayBounded(opts.inputFile)
  const envelope = readEnvelope(opts.envelopePath)
  const otsBytes = readFileSync(opts.otsPath)

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

  // 1. Normalize + recompute contentHash
  const normResult = normalize(raw)
  if (!normResult.ok) {
    process.stdout.write(`✗ FAILED — ${opts.inputFile} is not valid UTF-8\n`)
    if (opts.verbose) process.stdout.write(`  ${normResult.detail}\n`)
    process.exit(2)
  }
  const recomputedContentHash = contentHashOfNormalized(normResult.normalized)
  if (recomputedContentHash !== envelope.committedClaim.contentHash) {
    process.stdout.write(
      `✗ FAILED — content hash mismatch\n` +
        `  File hashes to:  ${recomputedContentHash}\n` +
        `  Manifest expects: ${envelope.committedClaim.contentHash}\n` +
        `  (Use \`${CLI_NAME} diagnose\` for detailed transform analysis.)\n`,
    )
    process.exit(2)
  }

  // 2. Recompute scene tree (if committed)
  if (envelope.committedClaim.sceneTreeRoot !== undefined) {
    const scenes = detectScenes(normResult.normalized)
    if (scenes.length !== envelope.committedClaim.sceneCount) {
      process.stdout.write(
        `✗ FAILED — scene count mismatch\n` +
          `  File has:        ${scenes.length} scenes\n` +
          `  Manifest expects: ${envelope.committedClaim.sceneCount} scenes\n`,
      )
      process.exit(2)
    }
    const tree = buildSceneTree(scenes)
    if (tree.root !== envelope.committedClaim.sceneTreeRoot) {
      process.stdout.write(
        `✗ FAILED — scene tree root mismatch\n` +
          `  File computes:   ${tree.root}\n` +
          `  Manifest expects: ${envelope.committedClaim.sceneTreeRoot}\n`,
      )
      process.exit(2)
    }
  }

  // 2b. Recompute paragraph tree (if committed). Per spec §05 §4, the verifier
  // applies the same recomputation rules as for the scene tree.
  if (envelope.committedClaim.paragraphTreeRoot !== undefined) {
    const paragraphs = detectParagraphsWithPositions(normResult.normalized)
    if (paragraphs.length !== envelope.committedClaim.paragraphCount) {
      process.stdout.write(
        `✗ FAILED — paragraph count mismatch\n` +
          `  File has:        ${paragraphs.length} paragraphs\n` +
          `  Manifest expects: ${envelope.committedClaim.paragraphCount} paragraphs\n`,
      )
      process.exit(2)
    }
    const ptree = buildParagraphTree(paragraphs)
    if (ptree.root !== envelope.committedClaim.paragraphTreeRoot) {
      process.stdout.write(
        `✗ FAILED — paragraph tree root mismatch\n` +
          `  File computes:   ${ptree.root}\n` +
          `  Manifest expects: ${envelope.committedClaim.paragraphTreeRoot}\n`,
      )
      process.exit(2)
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

  // Status headline distinguishes Bitcoin-attestation-present vs pending vs
  // no-attestations. A casual reader who stops at the first line MUST get the
  // right impression of verification strength.
  //
  // IMPORTANT: this verifier parses the OTS proof structure and CONFIRMS that
  // a Bitcoin block-header attestation is referenced. It does NOT independently
  // fetch + verify the Bitcoin block headers themselves (full SPV ships in v0.2
  // per the README roadmap). So the headline says "Bitcoin attestation present"
  // — accurate to what we actually verified — and points the user at upstream
  // `ots verify` for true block-header verification.
  if (otsResult.bitcoinAnchored) {
    process.stdout.write(
      `✓ VERIFIED — claim hash matches and a Bitcoin attestation is present in the .ots proof.\n`,
    )
    process.stdout.write(`  Content hash:  ${recomputedContentHash}\n`)
    process.stdout.write(`  Claim hash:    ${recomputedClaimHash}\n`)
    process.stdout.write(
      `  Bitcoin attestation: block heights ${otsResult.bitcoinBlockHeights.join(', ')} (parsed from .ots structure)\n` +
        `  NOTE: this verifier does NOT fetch + verify Bitcoin block headers in v0.x —\n` +
        `        only the OTS proof structure was checked. For independent block-header\n` +
        `        verification, run upstream \`ots verify ${opts.otsPath}\` against the\n` +
        `        opentimestamps-client. Full in-process SPV ships in v0.2.\n`,
    )
    process.exit(0)
  }
  if (otsResult.pendingCalendarUrls.length > 0) {
    process.stdout.write(
      `⚠ VERIFIED (PENDING) — claim hash matches, but the .ots proof has NOT YET been confirmed on Bitcoin.\n`,
    )
    process.stdout.write(`  Content hash:  ${recomputedContentHash}\n`)
    process.stdout.write(`  Claim hash:    ${recomputedClaimHash}\n`)
    process.stdout.write(
      `  Bitcoin block: PENDING — proof references calendars: ${otsResult.pendingCalendarUrls.join(', ')}\n` +
        `                 Run \`${CLI_NAME} upgrade <ots>\` after ~1-6 hours to fold the calendar\n` +
        `                 attestation into a Bitcoin block proof.\n`,
    )
    process.stdout.write(
      `  Until upgraded, this proof depends on the calendar operator(s) above. It is NOT\n` +
        `  yet independently verifiable against Bitcoin block headers alone.\n`,
    )
    if (opts.requireBitcoinAnchor) {
      process.stdout.write(`\n✗ FAILED — --require-bitcoin-anchor was set but the proof is still pending.\n`)
      process.exit(2)
    }
    process.exit(0)
  }
  process.stdout.write(
    `⚠ VERIFIED (NO ATTESTATIONS) — claim hash matches, but the .ots proof carries no\n` +
      `  attestations (placeholder / malformed?). The registration cannot be timestamp-verified\n` +
      `  against any external authority in its current state.\n`,
  )
  process.stdout.write(`  Content hash:  ${recomputedContentHash}\n`)
  process.stdout.write(`  Claim hash:    ${recomputedClaimHash}\n`)
  if (opts.requireBitcoinAnchor) {
    process.stdout.write(`\n✗ FAILED — --require-bitcoin-anchor was set but the proof has no attestations.\n`)
    process.exit(2)
  }
  process.exit(0)
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

function cmdUpgrade(otsPath: string): void {
  // Use the upstream `ots upgrade` CLI which works correctly on a file.
  //
  // SECURITY: do NOT search for `.venv/bin/ots` relative to the .ots file's
  // directory — that path is attacker-influenced (anyone who can hand a user
  // an .ots file in a directory they control could plant a malicious binary
  // there and trigger arbitrary code execution).
  //
  // Preference order, all rooted in the INVOCATION cwd (not the file path):
  //   1. SCREENREG_OTS_BIN env var (explicit operator override, absolute path
  //      recommended; warn if not absolute)
  //   2. ${cwd}/.venv/bin/ots — matches the README's recommended setup of
  //      `python3 -m venv .venv && .venv/bin/pip install opentimestamps-client`
  //      run from the project root
  //   3. system `ots` on PATH
  const otsBinary = resolveOtsBinary()
  // SECURITY: POSIX `--` separator forces the downstream `ots` binary to treat
  // `otsPath` as a positional argument, even if the path begins with `-`. Without
  // this, an attacker who can hand a user an `.ots`-like file at a path like
  // `--evil-flag` would have it parsed as an option by the upstream tool —
  // argument injection (distinct from shell injection: spawnSync without a shell
  // is safe from shell metachars but NOT from CLI flag injection).
  const result = spawnSync(otsBinary, ['upgrade', '--', otsPath], { encoding: 'utf8' })
  if (result.error || result.status !== 0) {
    die(
      `\`${otsBinary} upgrade\` failed: ${result.error?.message ?? result.stderr ?? 'unknown error'}\n` +
        `Install the upstream client: pip install opentimestamps-client`,
    )
  }
  process.stderr.write(result.stdout)
  process.stderr.write(result.stderr)
}

function resolveOtsBinary(): string {
  const explicit = process.env.SCREENREG_OTS_BIN
  if (explicit && explicit.length > 0) {
    if (!explicit.startsWith('/')) {
      process.stderr.write(
        `⚠  SCREENREG_OTS_BIN should be an absolute path; got ${JSON.stringify(explicit)}\n`,
      )
    }
    return explicit
  }
  const cwdVenvOts = join(process.cwd(), '.venv', 'bin', 'ots')
  if (existsSync(cwdVenvOts)) return cwdVenvOts
  return 'ots'
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
// Argv parsing
// ---------------------------------------------------------------------------

function printUsage(): void {
  process.stderr.write(`Usage:
  ${CLI_NAME} register <file> [--encrypt-title TITLE] [--encrypt-author AUTHOR]
                       [--training-mining allowed|notAllowed|constrained]
                       [--no-scene-tree] [--mock] [--password PASSWORD]
                       [--envelope-out PATH] [--ots-out PATH]
                       [--identity] [--identity-key-out PATH]
                       [--previous-claim-hash sha256:...]
  ${CLI_NAME} verify <file> <envelope> <ots> [--require-bitcoin-anchor]
                       Default: pending proofs still exit 0 with a warning headline.
                       --require-bitcoin-anchor: exit 2 unless the proof has been
                       upgraded to a Bitcoin block attestation (use in CI / scripts
                       that must gate on independent Bitcoin verifiability).
  ${CLI_NAME} diagnose <file> [envelope] [ots]
  ${CLI_NAME} similarity <bundleA> <bundleB> [--envelope-a PATH] [--envelope-b PATH]
  ${CLI_NAME} disclose-comparison <input> [public-out.json] [--yes-i-understand]
                       <input> may be: the screenplay, its .manifest.json, or the
                       .comparison-bundle.private.json directly. Default public-out
                       is derived by stripping ".private" from the bundle filename.
  ${CLI_NAME} sign-challenge <claim-hash> <challenge-hex> <private-key.pem>
  ${CLI_NAME} verify-signature <envelope> <challenge-hex> <signature-hex>
  ${CLI_NAME} verify-registration <envelope>
  ${CLI_NAME} timelock-encrypt <envelope> <fieldName> <unlockAt-ISO> <plaintext>
                       --out PATH --i-understand-must-restamp
                       Adds a timelock field to a NEW envelope file (--out PATH; never
                       overwrites the input). The new envelope has NO valid OTS proof;
                       you MUST re-stamp (or chain via previousRegistration) before
                       it verifies. The original envelope + .ots stay untouched.
  ${CLI_NAME} timelock-decrypt <envelope> <fieldName>
  ${CLI_NAME} generate-identity <output-private-key.pem>
  ${CLI_NAME} upgrade <ots>
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
      for (const a of rest) {
        if (a === '--require-bitcoin-anchor') requireBitcoinAnchor = true
        else positional.push(a)
      }
      if (positional.length < 3) die('verify: need <file> <envelope> <ots>')
      cmdVerify({
        inputFile: positional[0]!,
        envelopePath: positional[1]!,
        otsPath: positional[2]!,
        requireBitcoinAnchor,
      })
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
    case 'upgrade':
      if (rest.length < 1) die('upgrade: need <ots>')
      cmdUpgrade(rest[0]!)
      return
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
    default:
      printUsage()
      die(`unknown command: ${cmd}`, 1)
  }
}

main().catch((e) => die(e?.message ?? String(e)))
