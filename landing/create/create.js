/**
 * Browser glue for /create/.
 *
 * Drives the drag-drop flow against the shared cross-runtime modules at ./lib/.
 * No frameworks, no bundler, no analytics; ES modules straight from the
 * compiled output.
 */

import { normalize, contentHashOfNormalized, PROFILE_ID as NORM_PROFILE_ID } from './lib/normalize/v1-strict.js'
import { buildCommittedClaim, buildEnvelope } from './lib/envelope/build.js'
import { computeClaimHash, computeClaimHashBytes } from './lib/envelope/claim-hash.js'
import { buildOtsBytes, isValidTimestampSubtree } from './lib/anchors/ots-build.js'
import {
  generateKeypair as identityGenerateKeypair,
  signRegistration as identitySignRegistration,
  exportPrivateKeyPem as identityExportPrivateKeyPem,
} from './lib/identity/ed25519-signing.js'
import { buildEncryptedFieldsBlock } from './lib/encrypt/fields.js'
import { CLAIM_VERSION } from './lib/envelope/types.js'
import { detectScenes, buildSceneTree } from './lib/merkle/scene-tree.js'

const CALENDARS = [
  'https://a.pool.opentimestamps.org',
  'https://alice.btc.calendar.opentimestamps.org',
  'https://bob.btc.calendar.opentimestamps.org',
  'https://finney.calendar.eternitywall.com',
]

const MIN_CALENDARS_REQUIRED = 2
const PER_CALENDAR_TIMEOUT_MS = 15_000

const MAX_FILE_BYTES = 8 * 1024 * 1024

const els = {
  drop: document.getElementById('dropZone'),
  fileInput: document.getElementById('fileInput'),
  fileName: document.getElementById('fileName'),
  computeBtn: document.getElementById('computeBtn'),
  stepsRoot: document.getElementById('stepsRoot'),
  calendarList: document.getElementById('calendarList'),
  downloads: document.getElementById('downloads'),
  downloadManifest: document.getElementById('downloadManifest'),
  downloadProof: document.getElementById('downloadProof'),
  downloadIdentityKey: document.getElementById('downloadIdentityKey'),
  optIdentity: document.getElementById('optIdentity'),
  optEncrypt: document.getElementById('optEncrypt'),
  optSceneTree: document.getElementById('optSceneTree'),
  encryptInputs: document.getElementById('encryptInputs'),
  encTitle: document.getElementById('encTitle'),
  encAuthor: document.getElementById('encAuthor'),
  encPassword: document.getElementById('encPassword'),
  encPassword2: document.getElementById('encPassword2'),
}

let selectedFile = null
let lastObjectUrls = []

function revokeStaleObjectUrls() {
  for (const u of lastObjectUrls) URL.revokeObjectURL(u)
  lastObjectUrls = []
}

function setStep(stepId, state, detail) {
  const el = els.stepsRoot.querySelector(`.step[data-step="${stepId}"]`)
  if (!el) return
  el.classList.remove('active', 'done', 'err')
  if (state) el.classList.add(state)
  const detailEl = el.querySelector('[data-detail]')
  if (detail !== undefined) {
    detailEl.classList.remove('muted', 'err')
    if (state === 'err') detailEl.classList.add('err')
    detailEl.textContent = detail
  }
}

function setCalendarRow(url, badge, label, reason) {
  let row = els.calendarList.querySelector(`li[data-url="${url}"]`)
  if (!row) {
    row = document.createElement('li')
    row.dataset.url = url
    els.calendarList.appendChild(row)
  }
  row.innerHTML = ''
  const badgeEl = document.createElement('span')
  badgeEl.className = `badge ${badge}`
  badgeEl.textContent = label
  const urlEl = document.createElement('span')
  urlEl.textContent = url
  row.appendChild(badgeEl)
  row.appendChild(urlEl)
  if (reason) {
    const reasonEl = document.createElement('div')
    reasonEl.style.fontSize = '12px'
    reasonEl.style.marginLeft = '64px'
    reasonEl.style.color = badge === 'err' ? 'var(--err)' : 'var(--muted)'
    reasonEl.textContent = reason
    row.appendChild(reasonEl)
  }
}

async function readFileBytes(file) {
  // file.size has already been validated by onFile() — this just streams the bytes.
  return new Promise((resolve, reject) => {
    const fr = new FileReader()
    fr.onload = () => resolve(new Uint8Array(fr.result))
    fr.onerror = () => reject(fr.error || new Error('FileReader error'))
    fr.readAsArrayBuffer(file)
  })
}

async function submitToCalendar(url, digestBytes) {
  // text/plain keeps the request inside the CORS "simple request" set — no
  // preflight required. All four public OTS calendars return
  // access-control-allow-origin: *.
  const ctrl = new AbortController()
  const timeoutId = setTimeout(() => ctrl.abort(new Error('timeout')), PER_CALENDAR_TIMEOUT_MS)
  try {
    const resp = await fetch(`${url}/digest`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: digestBytes,
      mode: 'cors',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: ctrl.signal,
    })
    if (!resp.ok) {
      return { url, ok: false, error: `HTTP ${resp.status}` }
    }
    const ctype = resp.headers.get('content-type') || ''
    if (ctype && !/octet-stream|opentimestamps/i.test(ctype)) {
      return { url, ok: false, error: `unexpected content-type ${ctype}` }
    }
    const buf = await resp.arrayBuffer()
    const bytes = new Uint8Array(buf)
    if (!isValidTimestampSubtree(bytes)) {
      return { url, ok: false, error: `response is not a valid OTS Timestamp sub-tree (${bytes.length} bytes)` }
    }
    return { url, ok: true, bytes }
  } catch (err) {
    const reason = err && err.name === 'AbortError'
      ? `timed out after ${PER_CALENDAR_TIMEOUT_MS / 1000}s`
      : err && err.message
        ? err.message
        : String(err)
    return { url, ok: false, error: reason }
  } finally {
    clearTimeout(timeoutId)
  }
}

async function run() {
  // Snapshot the file at run-start so a second selection in the middle of the
  // async pipeline (drop, file-input change) cannot mint a proof that points
  // at the wrong filename in the manifest's proofRef / download names.
  const fileForThisRun = selectedFile
  if (!fileForThisRun) return
  els.computeBtn.disabled = true
  els.drop.style.pointerEvents = 'none'
  els.fileInput.disabled = true
  els.stepsRoot.hidden = false
  els.downloads.hidden = true
  els.calendarList.innerHTML = ''
  revokeStaleObjectUrls()

  try {
    // Step 1 — normalize (file.size guard was applied at onFile; this is the byte read)
    setStep('normalize', 'active', 'reading bytes…')
    const inputBytes = await readFileBytes(fileForThisRun)
    if (inputBytes.length === 0) throw new Error('file is empty (0 bytes)')
    if (inputBytes.length > MAX_FILE_BYTES) {
      throw new Error(`file is too large (${inputBytes.length} bytes > ${MAX_FILE_BYTES} max)`)
    }
    const norm = normalize(inputBytes)
    if (!norm.ok) {
      throw new Error(`normalization rejected this file: ${norm.detail}. v1-strict requires well-formed UTF-8.`)
    }
    setStep('normalize', 'done', `${norm.normalized.length} canonical bytes; ${norm.transforms.length} transform(s) applied`)

    // Step 2 — content hash
    setStep('content-hash', 'active', 'hashing…')
    const contentHash = await contentHashOfNormalized(norm.normalized)
    setStep('content-hash', 'done', contentHash)

    // Step 3 — build committed claim (with optional identity / encryption / scene tree)
    setStep('claim', 'active', 'assembling…')
    const claimInput = { contentHash }
    // Collect human-readable claim-step annotations as the optional features
    // are processed (sceneCount=N, sceneTree=skipped, encryptedFields=...,
    // registrant=ed25519). Surfaced verbatim in the "claim" step's done line.
    const claimAnnotations = []
    // Scene-tree Merkle root (Section 03). Commits per-scene leaf hashes
    // without revealing scene contents; later enables selective scene
    // disclosure proofs.
    if (els.optSceneTree.checked) {
      setStep('claim', 'active', 'detecting scenes + building Merkle tree…')
      const scenes = detectScenes(norm.normalized)
      if (scenes.length > 0) {
        const tree = await buildSceneTree(scenes)
        claimInput.sceneTree = { root: tree.root, count: tree.sceneCount }
      } else {
        // Zero scenes detected (preamble-only or non-screenplay text). The
        // claim omits sceneTree entirely so its absence is commitment-bearing
        // per spec §3.5. Surface this to the writer so they understand the
        // option they enabled was effectively a no-op for this input.
        claimAnnotations.push('sceneTree=skipped (no INT./EXT./EST. headings detected)')
      }
    }
    // Encrypted-fields block is built BEFORE the registrant signature so the
    // signature commits to the (ciphertext, IV, tag) bytes too — tampering
    // with any of those after registration would invalidate the signature.
    if (els.optEncrypt.checked) {
      const fields = {}
      if (els.encTitle.value.trim() !== '') fields.title = els.encTitle.value
      if (els.encAuthor.value.trim() !== '') fields.author = els.encAuthor.value
      if (Object.keys(fields).length === 0) {
        throw new Error('encrypted fields enabled but no title or author provided')
      }
      if (els.encPassword.value !== els.encPassword2.value) {
        throw new Error('encryption passwords do not match')
      }
      if (els.encPassword.value.length < 8) {
        throw new Error('encryption password must be at least 8 characters')
      }
      setStep('claim', 'active', `deriving master key (PBKDF2 600,000 iterations)…`)
      claimInput.encryptedFields = await buildEncryptedFieldsBlock({
        password: els.encPassword.value,
        claimVersion: CLAIM_VERSION,
        fields,
      })
    }
    let claim = buildCommittedClaim(claimInput)
    let identityPemForDownload = null
    if (els.optIdentity.checked) {
      setStep('claim', 'active', 'generating Ed25519 keypair…')
      const kp = await identityGenerateKeypair()
      setStep('claim', 'active', 'signing claim body…')
      const registrant = await identitySignRegistration(claim, kp.privateKey, kp.publicKeyEncoded)
      claim = { ...claim, registrant }
      identityPemForDownload = await identityExportPrivateKeyPem(kp.privateKey)
    }
    if (claimInput.sceneTree) claimAnnotations.push(`sceneCount=${claimInput.sceneTree.count}`)
    if (els.optEncrypt.checked) claimAnnotations.push('encryptedFields=aes-256-gcm')
    if (els.optIdentity.checked) claimAnnotations.push('registrant=ed25519')
    setStep(
      'claim',
      'done',
      `profile=${NORM_PROFILE_ID}; canonicalization=rfc8785${claimAnnotations.length > 0 ? '; ' + claimAnnotations.join('; ') : ''}`,
    )

    // Step 4 — claim hash (computed over the FINAL claim, with registrant if set)
    setStep('claim-hash', 'active', 'hashing canonical bytes…')
    const claimHash = await computeClaimHash(claim)
    const claimHashBytes = await computeClaimHashBytes(claim)
    setStep('claim-hash', 'done', claimHash)

    // Step 5 — submit to calendars
    setStep('calendars', 'active', `submitting to ${CALENDARS.length} calendars in parallel (${PER_CALENDAR_TIMEOUT_MS / 1000}s timeout each)…`)
    for (const url of CALENDARS) setCalendarRow(url, 'pending', 'pending')
    // allSettled never throws and never hangs because each fetch has its own
    // AbortController-backed timeout. Per-row UI updates happen as each
    // promise resolves.
    const submissions = await Promise.allSettled(
      CALENDARS.map(async (url) => {
        const r = await submitToCalendar(url, claimHashBytes)
        if (r.ok) {
          setCalendarRow(url, 'ok', `${r.bytes.length}B`)
        } else {
          setCalendarRow(url, 'err', 'failed', r.error)
        }
        return r
      }),
    )
    const settled = submissions.map((s) => s.status === 'fulfilled' ? s.value : { ok: false, error: 'unexpected' })
    const successful = settled.filter((r) => r.ok)
    if (successful.length < MIN_CALENDARS_REQUIRED) {
      throw new Error(
        `Only ${successful.length} of ${CALENDARS.length} calendars accepted the digest (need ≥${MIN_CALENDARS_REQUIRED}). Try again in a minute, or fall back to the screenreg CLI.`,
      )
    }
    setStep(
      'calendars',
      'done',
      `${successful.length} of ${CALENDARS.length} calendars accepted the digest`,
    )

    // Step 6 — assemble .ots
    setStep('ots', 'active', 'building proof bytes…')
    const otsBytes = buildOtsBytes({
      fileDigest: claimHashBytes,
      calendarTimestamps: successful.map((r) => r.bytes),
    })
    setStep('ots', 'done', `${otsBytes.length} bytes`)

    // Build the envelope manifest — derive names from the snapshotted file,
    // not the mutable global selectedFile, so a mid-flight reselection cannot
    // mismatch downloaded names with the actual proof's contentHash subject.
    const envelope = await buildEnvelope(claim, {
      proofs: [
        {
          type: 'opentimestamps',
          claimHash,
          proofRef: deriveProofRef(fileForThisRun.name),
          submittedAt: new Date().toISOString(),
        },
      ],
    })

    const manifestJson = JSON.stringify(envelope, null, 2)
    const manifestBlob = new Blob([manifestJson], { type: 'application/json' })
    const otsBlob = new Blob([otsBytes], { type: 'application/vnd.opentimestamps.v1' })

    const manifestUrl = URL.createObjectURL(manifestBlob)
    const otsUrl = URL.createObjectURL(otsBlob)
    lastObjectUrls.push(manifestUrl, otsUrl)

    els.downloadManifest.href = manifestUrl
    els.downloadManifest.download = deriveManifestName(fileForThisRun.name)
    els.downloadProof.href = otsUrl
    els.downloadProof.download = deriveProofName(fileForThisRun.name)
    if (identityPemForDownload !== null) {
      const pemBlob = new Blob([identityPemForDownload], { type: 'application/x-pem-file' })
      const pemUrl = URL.createObjectURL(pemBlob)
      lastObjectUrls.push(pemUrl)
      els.downloadIdentityKey.href = pemUrl
      els.downloadIdentityKey.download = deriveIdentityKeyName(fileForThisRun.name)
      els.downloadIdentityKey.hidden = false
    } else {
      els.downloadIdentityKey.hidden = true
      els.downloadIdentityKey.removeAttribute('href')
    }
    els.downloads.hidden = false
  } catch (err) {
    const steps = els.stepsRoot.querySelectorAll('.step')
    let marked = false
    for (const s of steps) {
      if (s.classList.contains('active')) {
        s.classList.remove('active')
        s.classList.add('err')
        const detail = s.querySelector('[data-detail]')
        detail.classList.remove('muted')
        detail.classList.add('err')
        detail.textContent = err && err.message ? err.message : String(err)
        marked = true
        break
      }
    }
    if (!marked) {
      // Shouldn't happen — defensive fallback
      console.error('[create] unhandled error', err)
    }
  } finally {
    els.computeBtn.disabled = false
    els.drop.style.pointerEvents = ''
    els.fileInput.disabled = false
    // Clear the AES password inputs whether compute succeeded or failed.
    // The password is gone from the page's JS memory once buildEncryptedFieldsBlock
    // returns, but the <input> still holds its DOM value — a writer who leaves
    // the tab open keeps the password recoverable via DevTools / extensions.
    // This also forces re-entry on a second run, which is the right discipline
    // for a destructive password (no recovery path).
    els.encPassword.value = ''
    els.encPassword2.value = ''
  }
}

function deriveManifestName(filename) {
  return filename.replace(/\.(fountain|txt)$/i, '') + '.manifest.json'
}
function deriveProofName(filename) {
  return filename.replace(/\.(fountain|txt)$/i, '') + '.proof.ots'
}
function deriveIdentityKeyName(filename) {
  return filename.replace(/\.(fountain|txt)$/i, '') + '.identity.pem'
}
function deriveProofRef(filename) {
  return deriveProofName(filename)
}

// ---- Wire up DOM events ----

els.drop.addEventListener('dragover', (e) => {
  e.preventDefault()
  els.drop.classList.add('hover')
})
els.drop.addEventListener('dragleave', () => els.drop.classList.remove('hover'))
els.drop.addEventListener('drop', (e) => {
  e.preventDefault()
  els.drop.classList.remove('hover')
  // ANY new drop invalidates previous proof artifacts and clears state
  // before doing any validation — failure paths must not leave stale state.
  resetSelectionState()
  // Reject directory drops, text-only drops, multi-item drops with non-file kinds.
  if (e.dataTransfer && e.dataTransfer.items && e.dataTransfer.items.length > 0) {
    const item = e.dataTransfer.items[0]
    if (item.kind !== 'file') {
      els.fileName.textContent = 'Drop a file, not a directory or text.'
      return
    }
  }
  const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]
  if (f) onFile(f)
})
els.fileInput.addEventListener('change', (e) => {
  resetSelectionState()
  const f = e.target.files && e.target.files[0]
  if (f) onFile(f)
})

function resetSelectionState() {
  // Centralized state cleanup. Called on every new file selection (success
  // OR failure) and every drop event before validation. Ensures stale proof
  // downloads, prior compute steps, and prior Blob URLs never survive a new
  // selection.
  selectedFile = null
  els.computeBtn.disabled = true
  els.stepsRoot.hidden = true
  els.downloads.hidden = true
  els.calendarList.innerHTML = ''
  revokeStaleObjectUrls()
}

function onFile(f) {
  // PDF detection — reject in the browser, surface the CLI path. Doing the
  // detection at file-select time (not after FileReader runs) avoids loading
  // potentially large PDFs into memory before refusing them. v1-strict's
  // UTF-8 validator would reject the bytes anyway, but the error message
  // "Invalid UTF-8 byte sequence detected at offset 0" wouldn't tell the
  // writer to use the CLI.
  if (/\.pdf$/i.test(f.name) || f.type === 'application/pdf') {
    // shellQuote escapes filenames containing whitespace, quotes, or
    // metacharacters so the displayed command is safe to copy-paste.
    const quotedIn = shellQuote(f.name)
    const quotedOut = shellQuote(deriveBaseName(f.name) + '.fountain')
    els.fileName.innerHTML =
      `<strong>${escapeText(f.name)}</strong> is a PDF.<br>` +
      `Browser-native PDF extraction is not yet available. ` +
      `Run the CLI:<br>` +
      `<code style="display:block;margin:8px 0;padding:8px 12px;background:var(--code-bg);font-size:13px;">` +
      `screenreg extract ${escapeText(quotedIn)} &gt; ${escapeText(quotedOut)}` +
      `</code>` +
      `Then drop the resulting <span class="mono">.fountain</span> file here.`
    return
  }
  // Pre-flight size check BEFORE allowing FileReader to read multi-GB inputs.
  if (f.size === 0) {
    els.fileName.textContent = `${f.name} · empty file (0 bytes) — choose a non-empty file.`
    return
  }
  if (f.size > MAX_FILE_BYTES) {
    els.fileName.textContent = `${f.name} · ${f.size.toLocaleString()} bytes exceeds ${MAX_FILE_BYTES.toLocaleString()} byte limit.`
    return
  }
  // Soft extension warning (don't reject — v1-strict accepts any UTF-8 input).
  const looksFountain = /\.(fountain|txt)$/i.test(f.name)
  const extNote = looksFountain ? '' : ' · note: not a .fountain extension'
  selectedFile = f
  els.fileName.textContent = `${f.name} · ${f.size.toLocaleString()} bytes${extNote}`
  els.computeBtn.disabled = false
}

function escapeText(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : c === '"' ? '&quot;' : '&#39;',
  )
}
function deriveBaseName(filename) {
  return filename.replace(/\.pdf$/i, '')
}
/**
 * POSIX-shell-quote a filename. Uses single quotes and escapes any embedded
 * single quote as '\''. Safe for all printable characters; non-printable
 * bytes are still passed through (filenames typically can't contain control
 * bytes, but the quoting itself prevents shell metacharacter interpretation).
 */
function shellQuote(s) {
  const str = String(s)
  if (/^[A-Za-z0-9_./-]+$/.test(str)) return str // safe as-is
  return `'${str.replace(/'/g, `'\\''`)}'`
}

els.computeBtn.addEventListener('click', () => {
  void run()
})

// Show/hide the encrypted-fields input block in sync with the checkbox.
els.optEncrypt.addEventListener('change', () => {
  els.encryptInputs.hidden = !els.optEncrypt.checked
})
