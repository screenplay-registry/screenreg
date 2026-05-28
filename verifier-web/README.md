# Browser Verifier

Single-page static verifier for The Screenplay Registry v1.

## Run locally

```bash
# Any static-file HTTP server works:
cd verifier-web
python3 -m http.server 8000
# then open http://localhost:8000
```

## What it does

- Drag in a `.fountain`, `.manifest.json`, and `.proof.ots`
- Re-normalizes the script per `screenplay-registration-norm/v1-strict` (browser-native)
- Recomputes `contentHash` via Web Crypto API SHA-256
- Recomputes `claimHash` via RFC 8785 canonicalization (clean-room JS)
- Parses the `.ots` proof binary and confirms `file_digest === claimHash`
- Extracts attestation summary (Bitcoin block heights / pending calendar URLs)

## What it does NOT do (deferred)

- Re-execute the OTS timestamp tree's hash operations to verify
  `file_digest → ops → tip → calendar/Bitcoin attestation` is consistent.
  The Node CLI does this; the browser verifier extracts the asserted block
  height and trusts the calendar's claim that the file_digest leads to it.
- Verify the Bitcoin block hash at the asserted height against the canonical
  Bitcoin chain. NEITHER the CLI nor this browser verifier performs full
  SPV / block-header verification in v0.x — both check OTS proof structure
  and report the asserted block height + calendar attestations. For true
  independent block-header verification, run upstream `ots verify` against
  the opentimestamps-client (it queries Bitcoin Core or a public Bitcoin
  node). Full in-process SPV with bundled checkpoints + public-explorer
  fallback ships in v0.2 per the README roadmap.
- Verify the scene-tree Merkle root.
- Decrypt encrypted manifest fields.

For OTS structure + claim-hash verification, run `screenreg verify` from the CLI.
For Bitcoin-anchor cryptographic verification, run `ots verify` from the
upstream opentimestamps-client.

## Privacy

- Files are read via `FileReader` and processed in-memory.
- ZERO network requests are made by the verification path.
- Open DevTools → Network tab to confirm.
- The page itself is a static HTML + a single `.js` file; serve it from
  any CDN or open it from local filesystem.
