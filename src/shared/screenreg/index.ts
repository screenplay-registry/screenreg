/**
 * Public surface of the `.screenreg` container layer (Section 11).
 *
 * Import from this module root only; deeper paths are implementation detail. This is the stable
 * contract for the CLI, the browser pages, and external integrators. The container packages an
 * already-built v1 envelope; it is not commitment-bearing and never alters `claimHash`.
 */

export {
  buildScreenreg,
  buildEvidenceScreenreg,
  readScreenreg,
  verifyEntryDigests,
  ScreenregError,
  type BuildBundleInput,
  type ParsedBundle,
} from './container.js'

export {
  BUNDLE_FORMAT,
  ENTRY_DESCRIPTOR,
  type BundleType,
  type EntryRole,
  type DescriptorEntry,
  type ScreenregDescriptor,
} from './types.js'

export { buildReadme, type ReadmeInput } from './readme.js'

export { zipStore, unzipStore, crc32, ZipError, type ZipEntry } from './zip.js'
