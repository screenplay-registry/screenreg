/**
 * Public types for the "finalize" layer.
 *
 * Registration is two-phase by nature: submitting a claim hash to the
 * OpenTimestamps calendars returns a *pending* proof in about a minute, but the
 * Bitcoin confirmation that makes the proof self-contained only lands once the
 * calendar's aggregation batch is mined and buried (typically 1–6 hours later).
 * "Finalize" is the act of folding that Bitcoin attestation into the `.ots` —
 * the OpenTimestamps "upgrade" operation.
 *
 * Nothing here touches a commitment-bearing byte: the `.ots` lives in the
 * envelope's `evidenceBundle`, which is never hashed into the `claimHash`.
 * Upgrading a proof strengthens the evidence; it cannot change what was claimed.
 *
 * These types are the stable surface an integrator, the CLI, and the browser
 * pages all share. Keep them runtime-agnostic (`Uint8Array`, no `Buffer`).
 */

/**
 * Outcome of a finalize attempt against the calendars.
 *  - `confirmed` — a Bitcoin attestation is now available and was folded in; the
 *    returned proof verifies against Bitcoin block headers alone, forever.
 *  - `pending`   — the calendars do not yet have a Bitcoin attestation for this
 *    commitment (the batch has not been mined/buried yet). Try again later; the
 *    input proof is still valid as a pending calendar attestation in the meantime.
 *  - `error`     — the proof could not be parsed, or every calendar was
 *    unreachable. Never a reason to distrust an already-held pending proof.
 */
export type FinalizeStatus = 'confirmed' | 'pending' | 'error'

export interface FinalizeResult {
  status: FinalizeStatus
  /**
   * The proof bytes. On `confirmed`, this is the upgraded, Bitcoin-anchored
   * proof. On `pending`/`error`, it is the input proof returned unchanged so a
   * caller can always write back a single value without branching.
   */
  otsBytes: Uint8Array
  /** Bitcoin block heights folded in. Empty unless `status === 'confirmed'`. */
  bitcoinBlockHeights: number[]
  /** Calendar URLs that are still pending (no Bitcoin attestation available yet). */
  pendingCalendars: string[]
  /** Human-readable detail; present when `status === 'error'`. */
  reason?: string
}

/**
 * A lifecycle event emitted at well-defined moments during finalize. This is
 * the seam a notification provider hooks into (see `FinalizeNotifier`): the core
 * emits events, a provider decides whether to email / webhook / push. The core
 * never knows about email addresses or delivery channels.
 *
 * `claimHash` is the `sha256:<hex>` of the committed claim — the same public
 * value the calendars and Bitcoin already hold. It is safe to log or transmit;
 * it reveals nothing about the screenplay.
 */
export type FinalizeEvent =
  | { type: 'pending'; claimHash: string; pendingCalendars: string[] }
  | { type: 'confirmed'; claimHash: string; bitcoinBlockHeights: number[]; otsBytes: Uint8Array }
  | { type: 'error'; claimHash: string; reason: string }

/**
 * The resumable handle: everything needed to re-check and finalize a pending
 * proof later, with no server and no account. Encoded (see `handle.ts`) into a
 * URL-fragment-safe token so a writer can bookmark a link and come back — even
 * on another device — and finish the Bitcoin anchoring in one click.
 *
 * Privacy: the handle carries the pending `.ots` and the public `claimHash`,
 * NEVER the screenplay. When carried in a URL fragment (`/create/#p=<token>`)
 * the value is not sent to any server by the browser.
 */
export interface PendingHandleV1 {
  v: 1
  /** `sha256:<hex>` of the committed claim — public; already on the calendars. */
  claimHash: string
  /** The pending `.ots` proof bytes (the resumable payload). */
  ots: Uint8Array
  /** Optional user-facing label, for a local "your pending proofs" list. */
  title?: string
  /** Optional ISO-8601 creation time. Supplied by the caller; never read from a clock here. */
  createdAt?: string
}
