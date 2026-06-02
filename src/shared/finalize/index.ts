/**
 * Public surface of the finalize layer.
 *
 * Import from this module root only. The deeper file paths are implementation
 * detail and may change; this curated set is the stable contract for the CLI,
 * the browser pages, and external integrators.
 */

export type {
  FinalizeStatus,
  FinalizeResult,
  FinalizeEvent,
  PendingHandleV1,
} from './types.js'

export { type FinalizeNotifier, NoopNotifier } from './notifier.js'

export { encodePendingHandle, decodePendingHandle } from './handle.js'

export { finalizeProof, type FinalizeOptions } from './finalize.js'
