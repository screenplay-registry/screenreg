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
import { submitDigestToCalendars } from './lib/anchors/ots-submit.js'
import { buildEncryptedFieldsBlock } from './lib/encrypt/fields.js'
import { CLAIM_VERSION } from './lib/envelope/types.js'
import { detectScenes, buildSceneTree } from './lib/merkle/scene-tree.js'
import { finalizeProof, encodePendingHandle, decodePendingHandle } from './lib/finalize/index.js'
import { buildScreenreg, buildEvidenceScreenreg } from './lib/screenreg/index.js'

const CALENDARS = [
  'https://a.pool.opentimestamps.org',
  'https://alice.btc.calendar.opentimestamps.org',
  'https://bob.btc.calendar.opentimestamps.org',
  'https://finney.calendar.eternitywall.com',
]

const MIN_CALENDARS_REQUIRED = 2
const PER_CALENDAR_TIMEOUT_MS = 15_000

const MAX_FILE_BYTES = 8 * 1024 * 1024
// A source PDF is larger than the text it yields (fonts, layout, images). Cap the PDF we will
// parse to bound pdf.js memory; the EXTRACTED TEXT is still subject to MAX_FILE_BYTES in run().
const MAX_PDF_BYTES = 30 * 1024 * 1024
// Page cap bounds extraction wall-clock on a pathological PDF (a feature script is ~90–200 pages).
const MAX_PDF_PAGES = 3000

const els = {
  drop: document.getElementById('dropZone'),
  fileInput: document.getElementById('fileInput'),
  fileName: document.getElementById('fileName'),
  computeBtn: document.getElementById('computeBtn'),
  inputArea: document.getElementById('inputArea'),
  topBar: document.getElementById('topBar'),
  topBarFill: document.getElementById('topBarFill'),
  startOver: document.getElementById('startOver'),
  ghostTimer: document.getElementById('ghostTimer'),
  stepsRoot: document.getElementById('stepsRoot'),
  calendarList: document.getElementById('calendarList'),
  downloads: document.getElementById('downloads'),
  bundleWarn: document.getElementById('bundleWarn'),
  indivFiles: document.getElementById('indivFiles'),
  downloadBundle: document.getElementById('downloadBundle'),
  downloadEvidence: document.getElementById('downloadEvidence'),
  downloadManifest: document.getElementById('downloadManifest'),
  downloadProof: document.getElementById('downloadProof'),
  optEncrypt: document.getElementById('optEncrypt'),
  encryptInputs: document.getElementById('encryptInputs'),
  encTitle: document.getElementById('encTitle'),
  encAuthor: document.getElementById('encAuthor'),
  encPassword: document.getElementById('encPassword'),
  encPassword2: document.getElementById('encPassword2'),
  ghost: document.getElementById('ghost'),
  ghostCard: document.getElementById('ghostCard'),
  ghostHeadline: document.getElementById('ghostHeadline'),
  ghostDetail: document.getElementById('ghostDetail'),
  ghostCheck: document.getElementById('ghostCheck'),
  ghostResume: document.getElementById('ghostResume'),
  ghostCopy: document.getElementById('ghostCopy'),
  downloadFinal: document.getElementById('downloadFinal'),
  pendingList: document.getElementById('pendingList'),
  pendingItems: document.getElementById('pendingItems'),
}

let selectedFile = null
// When a PDF is extracted + the writer confirms the text, this holds the bytes to register
// (the reviewed/edited text), so run() uses it instead of reading selectedFile.
let extractedSource = null
let pdfjsLib = null
// Bumped on every new selection. A long-running async PDF extraction captures the token at start
// and aborts all UI/state writes if it no longer matches — so a superseded PDF can't overwrite a
// newer selection or become the registered source.
let selectionToken = 0
let lastObjectUrls = []
// Finalize ghost-loader state. `activeFinalize` is the proof currently shown in
// the card; `pollTimer` is its background re-check timer (cleared on reset).
let activeFinalize = null
let pollTimer = null
// Settling-timer state: when the proof was created (for elapsed), when the next auto-check fires
// (for the countdown), and the 1s tick interval.
let ghostTimerInterval = null
let ghostStartMs = 0
let ghostNextCheckMs = 0
const PENDING_STORE_KEY = 'screenreg.pending.v1'
const POLL_INTERVAL_MS = 60_000

function fmtDuration(ms) {
  const s = Math.max(0, Math.floor(ms / 1000))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${sec}s` : `${sec}s`
}
function startGhostTimer(createdAtIso) {
  const parsed = createdAtIso ? Date.parse(createdAtIso) : NaN
  ghostStartMs = Number.isFinite(parsed) ? parsed : Date.now()
  els.ghostTimer.hidden = false
  tickGhostTimer()
  if (ghostTimerInterval) clearInterval(ghostTimerInterval)
  ghostTimerInterval = setInterval(tickGhostTimer, 1000)
}
function stopGhostTimer() {
  if (ghostTimerInterval) {
    clearInterval(ghostTimerInterval)
    ghostTimerInterval = null
  }
  if (els.ghostTimer) els.ghostTimer.hidden = true
}
function tickGhostTimer() {
  const elapsed = Date.now() - ghostStartMs
  const nextIn = ghostNextCheckMs ? Math.max(0, ghostNextCheckMs - Date.now()) : 0
  // All interpolated values are numbers/our own strings — safe for innerHTML.
  els.ghostTimer.innerHTML =
    `<span class="big">Elapsed: ${fmtDuration(elapsed)}</span> · usually confirms within 1–6 hours` +
    (nextIn > 0 ? ` · next check in ${Math.ceil(nextIn / 1000)}s` : ' · checking…')
}

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
  // Advance the fixed top progress bar as steps move through the pipeline.
  const i = STEP_ORDER.indexOf(stepId)
  if (i >= 0) {
    if (state === 'err') els.topBar.classList.add('err')
    else if (state === 'done') setTopBar(((i + 1) / STEP_ORDER.length) * 100)
    else if (state === 'active') setTopBar((i / STEP_ORDER.length) * 100)
  }
}

const STEP_ORDER = ['normalize', 'content-hash', 'claim', 'claim-hash', 'calendars', 'ots', 'bundle']

function setTopBar(pct) {
  els.topBar.classList.add('on')
  els.topBarFill.style.width = Math.max(0, Math.min(100, pct)) + '%'
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

async function run() {
  // Snapshot the file at run-start so a second selection in the middle of the
  // async pipeline (drop, file-input change) cannot mint a proof that points
  // at the wrong filename in the manifest's proofRef / download names.
  // The source is either a dropped text file, or the reviewed text extracted from a dropped PDF.
  const fileForThisRun = selectedFile
  const extractedForThisRun = extractedSource && extractedSource.bytes ? extractedSource : null
  if (!fileForThisRun && !extractedForThisRun) return
  // Web Crypto (SHA-256) is only exposed in a secure context — HTTPS, or http://localhost. On an
  // insecure origin `crypto.subtle` is undefined; fail fast with a clear reason instead of a
  // cryptic "Cannot read properties of undefined (reading 'digest')" mid-pipeline.
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    els.stepsRoot.hidden = false
    setStep(
      'normalize',
      'err',
      'A secure (HTTPS) connection is required to create a proof in your browser. Please reload over HTTPS.',
    )
    return
  }
  const sourceName = extractedForThisRun ? extractedForThisRun.name : fileForThisRun.name
  els.computeBtn.disabled = true
  els.drop.style.pointerEvents = 'none'
  els.fileInput.disabled = true
  // Dynamic run UI: the input form gives way to the progress view + a top progress bar.
  els.inputArea.hidden = true
  els.startOver.hidden = false
  els.topBar.classList.remove('err')
  setTopBar(4)
  els.stepsRoot.hidden = false
  els.downloads.hidden = true
  els.calendarList.innerHTML = ''
  revokeStaleObjectUrls()

  try {
    // Step 1 — normalize (size guard was applied at onFile; this is the byte read)
    setStep('normalize', 'active', 'reading bytes…')
    const inputBytes = extractedForThisRun ? extractedForThisRun.bytes : await readFileBytes(fileForThisRun)
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
    // Scene-tree Merkle root (Section 03) — always built on the website. Commits per-scene leaf
    // hashes without revealing scene contents; later enables selective scene-disclosure proofs.
    {
      setStep('claim', 'active', 'detecting scenes + building Merkle tree…')
      const scenes = detectScenes(norm.normalized)
      if (scenes.length > 0) {
        const tree = await buildSceneTree(scenes)
        claimInput.sceneTree = { root: tree.root, count: tree.sceneCount }
      } else {
        // Zero scenes detected (preamble-only or non-screenplay text). The claim omits sceneTree
        // entirely, so its absence is itself commitment-bearing per spec §3.5.
        claimAnnotations.push('sceneTree=skipped (no INT./EXT./EST. headings detected)')
      }
    }
    // "Keep the title and author private" — optional encrypted fields (AES-256-GCM).
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
    // Identity signing (Ed25519) is a CLI-only feature: it produces a private key, and burying a
    // key in a browser-downloaded file is a footgun for the mass audience. The browser never signs.
    const claim = buildCommittedClaim(claimInput)
    if (claimInput.sceneTree) claimAnnotations.push(`sceneCount=${claimInput.sceneTree.count}`)
    if (els.optEncrypt.checked) claimAnnotations.push('title/author kept private (aes-256-gcm)')
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

    // Outward-facing naming. When "keep title & author private" is on, EVERYTHING a recipient
    // could see is derived from a neutral claimHash serial, never the (possibly title-bearing)
    // filename: the envelope's proofRef, the loose manifest/proof download names, the shareable
    // bundle name, and the resume label. The full keep-safe bundle is the writer's private copy
    // and keeps the real name. (claimHash is final here — the claim never changes after this.)
    const keepPrivate = els.optEncrypt.checked
    const shareSerial = 'screenreg-' + claimHash.replace(/^sha256:/, '').slice(0, 12)
    const outName = keepPrivate ? shareSerial : sourceName

    // Step 5 — submit to calendars (shared engine; the CLI uses the same one).
    setStep('calendars', 'active', `submitting to ${CALENDARS.length} calendars in parallel (${PER_CALENDAR_TIMEOUT_MS / 1000}s timeout each)…`)
    for (const url of CALENDARS) setCalendarRow(url, 'pending', 'pending')
    // Each calendar has its own AbortController-backed timeout, so this never
    // hangs; onResult drives the per-row UI as each resolves.
    const sub = await submitDigestToCalendars({
      fileDigest: claimHashBytes,
      calendars: CALENDARS,
      minCalendars: MIN_CALENDARS_REQUIRED,
      timeoutMs: PER_CALENDAR_TIMEOUT_MS,
      onResult: (r) => {
        if (r.ok) setCalendarRow(r.url, 'ok', `${r.bytes.length}B`)
        else setCalendarRow(r.url, 'err', 'failed', r.error)
      },
    })
    const successful = sub.results.filter((r) => r.ok)
    if (!sub.ok) {
      const reason = sub.reason.charAt(0).toUpperCase() + sub.reason.slice(1)
      throw new Error(`${reason}. Try again in a minute, or fall back to the screenreg CLI.`)
    }
    setStep(
      'calendars',
      'done',
      `${successful.length} of ${CALENDARS.length} calendars accepted the digest`,
    )

    // Step 6 — assemble .ots (the shared engine already assembled it)
    setStep('ots', 'active', 'building proof bytes…')
    const otsBytes = sub.otsBytes
    setStep('ots', 'done', `${otsBytes.length} bytes`)

    // Build the envelope manifest — derive names from the snapshotted file,
    // not the mutable global selectedFile, so a mid-flight reselection cannot
    // mismatch downloaded names with the actual proof's contentHash subject.
    const envelope = await buildEnvelope(claim, {
      proofs: [
        {
          type: 'opentimestamps',
          claimHash,
          proofRef: deriveProofRef(outName),
          submittedAt: new Date().toISOString(),
        },
      ],
    })

    // Loose individual files first: they are deterministic and never blocked on bundling, so the
    // writer's proof is in hand regardless of what follows. The .screenreg is assembled after, in
    // its own guarded step — if it ever fails, these remain usable.
    const manifestJson = JSON.stringify(envelope, null, 2)
    const manifestBlob = new Blob([manifestJson], { type: 'application/json' })
    const otsBlob = new Blob([otsBytes], { type: 'application/vnd.opentimestamps.v1' })
    const manifestUrl = URL.createObjectURL(manifestBlob)
    const otsUrl = URL.createObjectURL(otsBlob)
    lastObjectUrls.push(manifestUrl, otsUrl)
    els.downloadManifest.href = manifestUrl
    els.downloadManifest.download = deriveManifestName(outName)
    els.downloadProof.href = otsUrl
    els.downloadProof.download = deriveProofName(outName)

    // The single-file .screenreg is the primary artifact: a full bundle that embeds the
    // screenplay (self-contained verification) and an evidence bundle that omits it (shareable
    // without revealing the script). Both wrap the SAME envelope + proof; bundling is not
    // commitment-bearing and never changes claimHash. inputBytes is the exact source whose
    // normalization produced contentHash, so it is what the full bundle embeds.
    setStep('bundle', 'active', 'packaging the screenplay + proof into one file…')
    els.bundleWarn.hidden = true
    try {
      const fullBundle = await buildScreenreg({ envelope, otsBytes, sourceText: inputBytes })
      const evidenceBundleBytes = await buildEvidenceScreenreg({ envelope, otsBytes })
      const bundleUrl = URL.createObjectURL(new Blob([fullBundle], { type: 'application/zip' }))
      const evidenceUrl = URL.createObjectURL(new Blob([evidenceBundleBytes], { type: 'application/zip' }))
      lastObjectUrls.push(bundleUrl, evidenceUrl)
      // The full keep-safe bundle (writer's private copy) keeps the real name; the shareable
      // evidence bundle uses the neutral serial when keep-private is on (outName).
      els.downloadBundle.href = bundleUrl
      els.downloadBundle.download = deriveBundleName(sourceName)
      els.downloadBundle.hidden = false
      els.downloadEvidence.href = evidenceUrl
      els.downloadEvidence.download = deriveEvidenceName(outName)
      els.downloadEvidence.hidden = false
      setStep('bundle', 'done', `${fullBundle.length} B full · ${evidenceBundleBytes.length} B shareable`)
    } catch (e) {
      // Bundling is deterministic over in-memory bytes, so this should not happen for a valid
      // envelope; if it does, keep the loose files usable and say so plainly instead of failing.
      console.error('[create] .screenreg assembly failed; loose files remain available', e)
      setStep('bundle', 'err', e && e.message ? e.message : String(e))
      els.downloadBundle.hidden = true
      els.downloadEvidence.hidden = true
      els.bundleWarn.textContent =
        'Your browser could not assemble the one-file .screenreg, but your proof is ready as the individual files below — download all of them and keep them together.'
      els.bundleWarn.hidden = false
      if (els.indivFiles) els.indivFiles.open = true
    }
    els.downloads.hidden = false

    // Stand up the serverless finalize ghost-loader: build a resumable token,
    // remember it in this browser, put it in the address bar so it survives a
    // tab close, and start checking for the Bitcoin confirmation. This is a pure
    // convenience layer over the two files just downloaded — if anything here
    // throws, the proof is already safely in hand.
    try {
      // The label rides in the resume token + the on-page dashboard, and the "copy a link" link is
      // shareable — so it uses outName (the neutral serial when keep-private is on).
      const title = outName
      const createdAt = new Date().toISOString()
      const token = encodePendingHandle({ v: 1, claimHash, ots: otsBytes, title, createdAt })
      setResumeHash(token)
      upsertPendingRecord({ claimHash, title, token, status: 'pending' })
      // Pass the envelope + source through (active run only — never in the resume token, which
      // stays small and script-free) so the confirmed download can be a finalized .screenreg.
      showGhostPending(otsBytes, claimHash, title, true, { envelope, sourceBytes: inputBytes }, createdAt)
    } catch (e) {
      console.error('[create] ghost-loader setup failed (non-fatal)', e)
    }
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

function deriveBundleName(filename) {
  return filename.replace(/\.(fountain|txt)$/i, '') + '.screenreg'
}
function deriveEvidenceName(filename) {
  return filename.replace(/\.(fountain|txt)$/i, '') + '.evidence.screenreg'
}
function deriveManifestName(filename) {
  return filename.replace(/\.(fountain|txt)$/i, '') + '.manifest.json'
}
function deriveProofName(filename) {
  return filename.replace(/\.(fountain|txt)$/i, '') + '.proof.ots'
}
function deriveProofRef(filename) {
  return deriveProofName(filename)
}

// ---- Finalize ghost-loader (serverless, resumable) ----

function loadPendingStore() {
  try {
    const raw = localStorage.getItem(PENDING_STORE_KEY)
    const arr = raw ? JSON.parse(raw) : []
    return Array.isArray(arr) ? arr : []
  } catch {
    return []
  }
}

function savePendingStore(arr) {
  try {
    localStorage.setItem(PENDING_STORE_KEY, JSON.stringify(arr.slice(0, 50)))
  } catch {
    // localStorage may be disabled (private mode / quota). The dashboard is a
    // convenience; the address-bar resume link and downloaded files still work.
  }
}

function upsertPendingRecord(entry) {
  const arr = loadPendingStore().filter((e) => e.claimHash !== entry.claimHash)
  arr.unshift(entry)
  savePendingStore(arr)
  renderPendingList()
}

function markPendingConfirmed(claimHash, heights) {
  const arr = loadPendingStore().map((e) =>
    e.claimHash === claimHash ? { ...e, status: 'confirmed', bitcoin: heights } : e,
  )
  savePendingStore(arr)
  renderPendingList()
}

function renderPendingList() {
  const arr = loadPendingStore()
  els.pendingItems.innerHTML = ''
  if (arr.length === 0) {
    els.pendingList.hidden = true
    return
  }
  for (const e of arr) {
    const li = document.createElement('li')
    const title = document.createElement('span')
    title.className = 'ph-title'
    title.textContent = e.title || String(e.claimHash || '').slice(0, 28) + '…'
    const status = document.createElement('span')
    if (e.status === 'confirmed') {
      status.className = 'ph-status confirmed'
      status.textContent = '✓ on Bitcoin'
    } else {
      status.className = 'ph-status'
      const a = document.createElement('a')
      a.textContent = 'check / resume →'
      a.href = '#p=' + e.token
      status.appendChild(a)
    }
    li.appendChild(title)
    li.appendChild(status)
    els.pendingItems.appendChild(li)
  }
  els.pendingList.hidden = false
}

/** Put the resume token in the address bar so the link survives a tab close. */
function setResumeHash(token) {
  try {
    const url = new URL(window.location.href)
    url.hash = 'p=' + token
    window.history.replaceState(null, '', url.toString())
  } catch {
    // history API unavailable — the dashboard + downloaded files are the fallback.
  }
}

// `knownValid` is true only for a proof this page just built. For a proof
// resumed from a #p= link we have NOT yet parsed it, so we show a neutral
// "checking" headline and let the first finalize check prove it's real (or
// surface an error) — never claim "valid now" for an unverified token.
function showGhostPending(otsBytes, claimHash, title, knownValid, extras, createdAt) {
  // `extras` ({ envelope, sourceBytes }) is present only for a proof built in THIS tab, enabling
  // a finalized .screenreg on confirmation. A resumed proof (from a #p= link) has neither, so its
  // confirmed download falls back to the upgraded .ots.
  activeFinalize = { otsBytes, claimHash, title, extras: extras || null }
  startGhostTimer(createdAt)
  els.ghostCard.classList.remove('confirmed', 'error')
  if (knownValid) {
    setPendingValidCopy()
  } else {
    els.ghostHeadline.textContent = 'Checking your proof…'
    els.ghostDetail.textContent =
      'Reading the proof from your link and asking the calendars whether Bitcoin has confirmed it yet.'
  }
  els.downloadFinal.hidden = true
  els.ghostCheck.hidden = false
  els.ghostCheck.disabled = false
  els.ghostCheck.textContent = 'Check now'
  els.ghostResume.hidden = false
  els.ghost.hidden = false
  scheduleFinalizeCheck(0)
}

function setPendingValidCopy() {
  els.ghostCard.classList.remove('confirmed', 'error')
  els.ghostHeadline.textContent = 'Registered — finalizing on Bitcoin…'
  els.ghostDetail.textContent =
    'Your proof is valid as a pending calendar attestation. The Bitcoin ' +
    'confirmation usually lands within 1–6 hours — you can safely close this tab and come back.'
}

function showGhostError(message) {
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = null }
  stopGhostTimer()
  activeFinalize = null
  els.ghostCard.classList.remove('confirmed')
  els.ghostCard.classList.add('error')
  els.ghostHeadline.textContent = 'Couldn’t read this proof'
  els.ghostDetail.textContent = message
  els.ghostCheck.hidden = true
  els.ghostResume.hidden = true
  els.downloadFinal.hidden = true
  els.ghost.hidden = false
}

function scheduleFinalizeCheck(delayMs) {
  if (pollTimer) clearTimeout(pollTimer)
  ghostNextCheckMs = Date.now() + delayMs // drives the "next check in Ns" countdown
  pollTimer = setTimeout(runFinalizeCheck, delayMs)
}

async function runFinalizeCheck() {
  if (!activeFinalize) return
  const { otsBytes, claimHash, title } = activeFinalize
  els.ghostCheck.disabled = true
  els.ghostCheck.textContent = 'Checking…'
  let result
  try {
    result = await finalizeProof({ otsBytes })
  } catch {
    result = { status: 'pending' }
  }
  // The user may have started a different proof while this check was in flight.
  if (!activeFinalize || activeFinalize.claimHash !== claimHash) return
  if (result.status === 'confirmed') {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null }
    await showGhostConfirmed(result.otsBytes, result.bitcoinBlockHeights || [], title, activeFinalize.extras, claimHash)
    markPendingConfirmed(claimHash, result.bitcoinBlockHeights || [])
  } else if (result.status === 'error') {
    // The bytes are not a proof we can parse (e.g. a hand-crafted resume link).
    // Fail safe: stop polling and say so, rather than claim "valid" forever.
    showGhostError(
      'This link does not contain a proof we can read. If you have your screenplay, ' +
      'manifest, and .ots files, verify them on the verify page instead.',
    )
  } else {
    // pending — the engine parsed the proof, so it IS a valid pending attestation.
    setPendingValidCopy()
    els.ghostCheck.disabled = false
    els.ghostCheck.textContent = 'Check now'
    scheduleFinalizeCheck(POLL_INTERVAL_MS)
  }
}

async function showGhostConfirmed(upgradedOts, heights, title, extras, expectedClaimHash) {
  // Build the download artifact BEFORE mutating any UI, so a proof the user replaced mid-await
  // never publishes a stale confirmation over the new one. Prefer a finalized .screenreg (the
  // upgraded proof folded back into the one-file bundle) when this tab still holds the envelope +
  // source; on a resumed proof we only have the .ots, which is itself a complete Bitcoin proof.
  let blob
  let downloadName
  let rebuilt = false
  if (extras && extras.envelope && extras.sourceBytes) {
    try {
      const finalizedBundle = await buildScreenreg({
        envelope: extras.envelope,
        otsBytes: upgradedOts,
        sourceText: extras.sourceBytes,
      })
      blob = new Blob([finalizedBundle], { type: 'application/zip' })
      downloadName = title ? deriveBundleName(title) : 'proof.screenreg'
      rebuilt = true
    } catch (e) {
      console.error('[create] could not rebuild finalized .screenreg; falling back to .ots', e)
    }
  }
  if (!rebuilt) {
    blob = new Blob([upgradedOts], { type: 'application/vnd.opentimestamps.v1' })
    downloadName = title ? deriveProofName(title) : 'proof.ots'
  }

  // The active proof may have been replaced while buildScreenreg was awaited — do not paint a
  // confirmation (or publish a download) over a different proof.
  if (!activeFinalize || activeFinalize.claimHash !== expectedClaimHash) return

  stopGhostTimer()
  els.ghostCard.classList.add('confirmed')
  els.ghostHeadline.textContent = '✓ Confirmed on Bitcoin'
  els.ghostCheck.hidden = true
  els.ghostResume.hidden = true
  els.ghostDetail.textContent =
    (heights.length ? `Anchored at Bitcoin block ${heights.join(', ')}. ` : '') +
    (rebuilt
      ? 'Download the finalized .screenreg below — it now verifies against Bitcoin block headers alone, with no calendar or server.'
      : 'Your proof is now self-contained — it verifies against Bitcoin block headers alone, with no calendar or server.')
  const url = URL.createObjectURL(blob)
  lastObjectUrls.push(url)
  els.downloadFinal.href = url
  els.downloadFinal.download = downloadName
  els.downloadFinal.hidden = false
  els.ghost.hidden = false
}

/** Resume a finalize from a `#p=<token>` link (bookmarked or from the dashboard). */
function resumeFromHash() {
  const m = /^#p=([A-Za-z0-9_-]+)$/.exec(window.location.hash || '')
  if (!m) return
  let handle
  try {
    handle = decodePendingHandle(m[1])
  } catch {
    return // not a valid resume token — ignore
  }
  showGhostPending(handle.ots, handle.claimHash, handle.title || '', false, undefined, handle.createdAt) // resumed → prove it before claiming valid
}

els.ghostCheck.addEventListener('click', () => {
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = null }
  runFinalizeCheck()
})
els.ghostCopy.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(window.location.href)
    els.ghostCopy.textContent = 'Copied ✓'
    setTimeout(() => { els.ghostCopy.textContent = 'Copy a link to finish later' }, 1600)
  } catch {
    // clipboard blocked — the link is already in the address bar.
  }
})
window.addEventListener('hashchange', resumeFromHash)

// On load: show any locally-remembered pending proofs, and resume a finalize if
// the URL carries a #p=<token> (a bookmarked "finish later" link).
renderPendingList()
resumeFromHash()

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
els.startOver.addEventListener('click', () => {
  resetSelectionState()
  els.fileName.textContent = ''
})

function resetSelectionState() {
  // Centralized state cleanup. Called on every new file selection (success
  // OR failure) and every drop event before validation. Ensures stale proof
  // downloads, prior compute steps, and prior Blob URLs never survive a new
  // selection.
  selectedFile = null
  extractedSource = null
  selectionToken++ // invalidate any in-flight PDF extraction from a prior selection
  els.computeBtn.disabled = true
  els.stepsRoot.hidden = true
  els.downloads.hidden = true
  els.calendarList.innerHTML = ''
  // Restore the input form + reset the dynamic run UI.
  els.inputArea.hidden = false
  els.startOver.hidden = true
  els.topBar.classList.remove('on', 'err')
  els.topBarFill.style.width = '0%'
  // Tear down any prior ghost-loader so a fresh registration starts clean. The
  // local "pending proofs" dashboard persists; only the active card is cleared.
  els.ghost.hidden = true
  activeFinalize = null
  stopGhostTimer()
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = null }
  revokeStaleObjectUrls()
}

function onFile(f) {
  // A PDF is routed to in-browser extraction (handlePdf) instead of the text path: it is read by
  // pdf.js into text the writer reviews, and that text — not the PDF bytes — is what gets hashed.
  if (/\.pdf$/i.test(f.name) || f.type === 'application/pdf') {
    handlePdf(f)
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

// ---- PDF extraction (pdf.js, lazy-loaded from our own origin only when a PDF is dropped) ----
// pdf.js is an INPUT TOOL: it turns a PDF into text. The extracted text — reviewed and editable
// by the writer below — is what gets normalized, hashed, and embedded in the .screenreg. The
// parser is never part of verification, so it can be swapped (for our own, later) with no effect
// on any existing proof.

async function loadPdfjs() {
  if (pdfjsLib) return pdfjsLib
  const lib = await import('./lib/pdfjs/pdf.min.mjs')
  lib.GlobalWorkerOptions.workerSrc = new URL('./lib/pdfjs/pdf.worker.min.mjs', import.meta.url).href
  pdfjsLib = lib
  return lib
}

async function extractPdfText(bytes, isCancelled) {
  const pdfjs = await loadPdfjs()
  // pdf.js detaches the ArrayBuffer it is handed; pass a copy so the caller's bytes survive.
  const data = bytes.slice()
  const loadingTask = pdfjs.getDocument({ data, isEvalSupported: false, useSystemFonts: false })
  const doc = await loadingTask.promise
  const pages = doc.numPages
  if (pages > MAX_PDF_PAGES) {
    await doc.destroy()
    throw new Error(`the PDF has ${pages.toLocaleString()} pages (max ${MAX_PDF_PAGES.toLocaleString()})`)
  }
  // Collect chunks (not repeated string concat) and track length so a pathological PDF that would
  // expand into huge text is aborted mid-extraction, before it can freeze or balloon the tab. The
  // char-count cap is a generous proxy that bounds memory; useExtractedText() does the exact byte check.
  const chunks = []
  let len = 0
  let items = 0
  try {
    for (let p = 1; p <= pages; p++) {
      // Stop promptly (and free the parser) if a newer selection superseded this extraction, so a
      // hostile/huge PDF can't keep parsing in the background.
      if (isCancelled && isCancelled()) throw new Error('superseded')
      const page = await doc.getPage(p)
      const tc = await page.getTextContent()
      for (const it of tc.items) {
        if (typeof it.str !== 'string') continue
        chunks.push(it.str)
        len += it.str.length
        if (it.hasEOL) {
          chunks.push('\n') // pdf.js marks line ends; trust them for line reconstruction
          len += 1
        }
        items++
        if (len > MAX_FILE_BYTES) {
          throw new Error(`the extracted text exceeds the ${MAX_FILE_BYTES.toLocaleString()}-byte limit`)
        }
      }
      chunks.push('\n') // page break
      len += 1
      page.cleanup()
    }
  } finally {
    await doc.destroy()
  }
  const text = chunks.join('').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').replace(/^\s+|\s+$/g, '') + '\n'
  return { text, items, pages }
}

async function handlePdf(f) {
  const myToken = selectionToken // abort if a newer selection supersedes this one mid-extraction
  if (f.size === 0) {
    els.fileName.textContent = `${f.name} · empty file (0 bytes) — choose a non-empty PDF.`
    return
  }
  if (f.size > MAX_PDF_BYTES) {
    els.fileName.textContent = `${f.name} · ${f.size.toLocaleString()} bytes exceeds the ${MAX_PDF_BYTES.toLocaleString()} byte PDF limit.`
    return
  }
  els.fileName.innerHTML = `<strong>${escapeText(f.name)}</strong> · reading the PDF in your browser…`
  let result
  try {
    const bytes = new Uint8Array(await f.arrayBuffer())
    if (myToken !== selectionToken) return // superseded by a newer selection
    result = await extractPdfText(bytes, () => myToken !== selectionToken)
  } catch (e) {
    if (myToken !== selectionToken) return
    els.fileName.innerHTML =
      `<strong>${escapeText(f.name)}</strong> · could not read this PDF (${escapeText(e && e.message ? e.message : String(e))}).<br>` +
      `If it is a scanned or image-only PDF, there is no text to extract — paste the screenplay as plain text instead.`
    return
  }
  if (myToken !== selectionToken) return // superseded while extracting
  if (!result.text || result.text.trim().length === 0 || result.items === 0) {
    els.fileName.innerHTML =
      `<strong>${escapeText(f.name)}</strong> · no selectable text found — this looks like a scanned or image-only PDF.<br>` +
      `Use a text-based PDF, or paste the screenplay as plain text.`
    return
  }
  useExtractedText(f.name, result)
}

// No review textarea — the extracted text is committed as-is and goes straight to ready-to-
// register. (The full .screenreg embeds the exact text, so the writer can always inspect what was
// fingerprinted later; a per-page proofread of a feature script up front is not actionable.)
function useExtractedText(name, result) {
  const bytes = new TextEncoder().encode(result.text)
  if (bytes.length > MAX_FILE_BYTES) {
    els.fileName.innerHTML = `<strong>${escapeText(name)}</strong> · the extracted text is ${bytes.length.toLocaleString()} bytes, over the ${MAX_FILE_BYTES.toLocaleString()} byte limit.`
    return
  }
  extractedSource = { name: deriveBaseName(name) + '.fountain', bytes }
  selectedFile = null
  els.fileName.innerHTML = `<strong>${escapeText(name)}</strong> · extracted ${result.pages} page${result.pages === 1 ? '' : 's'} (${bytes.length.toLocaleString()} bytes) — ready to register.`
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
