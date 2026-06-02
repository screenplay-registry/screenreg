/**
 * The pluggable notification seam.
 *
 * The base protocol is serverless: a writer finalizes a proof by coming back to
 * the page (or re-running the CLI) once Bitcoin has confirmed. That covers
 * "come back and it's ready." It deliberately does NOT cover "tell me when it's
 * ready" — a push notification to a closed tab needs a server, and the core
 * ships none.
 *
 * An operator who wants that proactive step (email me / webhook my backend /
 * push to my app when the proof confirms) implements `FinalizeNotifier` and
 * passes it to a finalize run. The core calls `notify` at well-defined moments
 * and hands over only the public `claimHash` (and, on confirmation, the upgraded
 * proof bytes). It never sees an email address, a subscriber list, or a delivery
 * channel — those belong entirely to the provider. This keeps every delivery
 * system (SMTP, SES, Resend, Postmark, a webhook, a job queue, a mobile push
 * service) a drop-in behind the same one-method contract, and keeps the core
 * free of any mail dependency.
 *
 * The interface is intentionally minimal so it is trivial to insert: one method,
 * sync or async, and a thrown error from a notifier is the caller's concern, not
 * the finalize engine's (a failed notification must never invalidate a proof).
 */

import type { FinalizeEvent } from './types.js'

export interface FinalizeNotifier {
  /**
   * Called once per finalize outcome. May be async; the caller decides whether
   * to await it. Implementations should treat this as best-effort delivery and
   * must not assume exactly-once semantics — a writer may finalize the same
   * proof from several devices.
   */
  notify(event: FinalizeEvent): void | Promise<void>
}

/**
 * The default notifier: does nothing. Used everywhere the serverless path runs
 * (the browser, a plain CLI invocation) so the engine can always call
 * `notifier.notify(...)` without a null check. Swap it for a real provider only
 * where proactive delivery is wanted.
 */
export class NoopNotifier implements FinalizeNotifier {
  notify(): void {
    /* intentionally empty — the serverless path needs no delivery channel */
  }
}
