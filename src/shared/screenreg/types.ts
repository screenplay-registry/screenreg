/**
 * Types and locked identifiers for the `.screenreg` container (Section 11).
 *
 * The container is a packaging format, not a commitment surface: nothing here is hashed into
 * `claimHash`. The format identifier is stable so readers can recognize and version the wrapper.
 */

export const BUNDLE_FORMAT = 'urn:screenplay-registration-bundle:v1' as const

/** Canonical in-archive paths. Filenames are cosmetic — readers resolve by ROLE (see below). */
export const ENTRY_DESCRIPTOR = 'screenreg.json' as const
export const ENTRY_ENVELOPE = 'envelope.json' as const
export const ENTRY_OTS_PROOF = 'proof.ots' as const
export const ENTRY_SOURCE_TEXT = 'script.fountain' as const
export const ENTRY_README = 'README.txt' as const

export type BundleType = 'full' | 'evidence'

/** Role keys are the authoritative way to locate entries; new roles are additive (Section 11 §6). */
export type EntryRole = 'descriptor' | 'envelope' | 'ots-proof' | 'source-text' | 'readme' | string

export interface DescriptorEntry {
  path: string
  role: EntryRole
  bytes: number
  /** "sha256:<lowercase-hex>" of the entry bytes — corruption check, not a security claim. */
  sha256: string
}

export interface ScreenregDescriptor {
  format: typeof BUNDLE_FORMAT
  bundleType: BundleType
  /** Role → in-archive path, for the roles actually present. */
  contents: {
    descriptor: string
    envelope: string
    otsProof?: string
    sourceText?: string
    readme?: string
  }
  /** Every non-descriptor entry, sorted by path. */
  entries: DescriptorEntry[]
}
