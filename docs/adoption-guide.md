# Adoption Guide (for integrators)

If you build a writing tool — Final Draft, Highland, Fade In, Sudowrite, a web editor, a self-hosted markdown writer — this guide tells you how to integrate The Screenplay Registry registration as a button in your tool.

---

## Why integrate

Writers want one-click registration without leaving their writing environment. The CLI works for power users; tool integration is what makes it ambient — same UX shape as "Save As PDF" or "Export to Final Draft."

For your users, the benefit is: their script gets a free Bitcoin timestamp (and, if you set it, an AI-training preference signal) embedded in your save flow.

For you, the benefit is a standards-based registration flow with no per-registration fee and no custody of user scripts.

## Integration paths

### Path A: browser handoff (least integration; ~30 min)

Add a "Register on screenplayregistry.org" menu item that:
1. Exports the current document to a temporary `.fountain` file.
2. Opens the user's default browser to `https://screenplayregistry.org/create/`.
3. Surfaces a short note prompting them to drag the temp file into the page.

The page handles the hash, calendar fan-out, and proof assembly entirely client-side; your tool never sees the resulting `.screenreg` (the user downloads it from the page). Use this when you want zero registration logic in your binary and no dependency on the screenreg codebase.

### Path B: shell out to the CLI (simplest in-process flow)

Spawn `screenreg register <file>` from your tool's "Register" menu. Parse stdout/stderr for the result. By default it produces one self-contained `<file>.screenreg`; a tool that prefers the separate `.manifest.json` + `.proof.ots` to file in a registrations subdirectory should pass `--loose` (or `--envelope-out`/`--ots-out` for explicit paths). (In these examples `screenreg` is the cloned `./bin/screenreg.mjs` — it is not published to npm yet, so resolve the path or alias it in your tool.)

This works in any tool that can spawn a subprocess. Total integration effort: ~1 hour.

If the user is registering a PDF screenplay (Final Draft export, archived PDF, etc.), use the two-step PDF flow:

```bash
screenreg extract draft.pdf > draft.fountain    # surfaces output for user review
# (host tool's UX should let the user inspect/edit draft.fountain here)
screenreg register draft.fountain --source-pdf draft.pdf
#   → envelope.evidenceBundle.bundleExtensions.sourceExtractor records
#     extractor name+version + sourcePdfSha256 + extractedFountainSha256
```

```bash
screenreg register screenplay.fountain --envelope-out registrations/v1.manifest.json --ots-out registrations/v1.proof.ots
```

Optional flags:
- `--encrypt-title "..." --encrypt-author "..."` — for owner-key encrypted metadata
- `--training-mining notAllowed` — set the AI-training preference
- `--no-scene-tree` — skip the scene Merkle tree if you don't want selective disclosure

### Path C: import the TypeScript SDK (for JS/TS tools)

For tools built in Node / Electron / browser (the package is not yet published to npm — vendor it from a clone or a git dependency for now):

```typescript
// All public exports come from the package root. The package's `exports` map
// resolves "screenreg" to a curated index re-exporting every stable symbol.
// Subpath imports (`/normalize`, `/envelope`, etc.) are NOT supported in v1 —
// reaching into deeper paths breaks across versions.
import {
  normalize,
  contentHashOfNormalized,
  buildCommittedClaim,
  buildEnvelope,
  computeClaimHashBytes,
  detectScenes,
  buildSceneTree,
  submitOts,
} from 'screenreg'

async function registerScreenplay(fountainBytes: Buffer): Promise<{ envelope: any; otsBytes: Buffer }> {
  const norm = normalize(fountainBytes)
  if (!norm.ok) throw new Error(norm.detail)

  const contentHash = contentHashOfNormalized(norm.normalized)
  const scenes = detectScenes(norm.normalized)
  const sceneTree = scenes.length > 0 ? buildSceneTree(scenes) : undefined

  const claim = buildCommittedClaim({
    contentHash,
    ...(sceneTree ? { sceneTree: { root: sceneTree.root, count: sceneTree.sceneCount } } : {}),
  })

  const claimHashBytes = computeClaimHashBytes(claim)
  const stampResult = await submitOts({ digest: claimHashBytes })
  if (!stampResult.ok) throw new Error(stampResult.reason)

  const envelope = buildEnvelope(claim, {
    proofs: [{
      type: 'opentimestamps',
      claimHash: `sha256:${claimHashBytes.toString('hex')}`,
      proofRef: 'screenplay.proof.ots',
    }],
  })

  return { envelope, otsBytes: stampResult.otsBytes }
}
```

The SDK is pure TypeScript with no native dependencies and no Python: normalize/canonicalize/merkle/encrypt are zero-dep, and the OTS calendar submit + verification use only `globalThis.fetch` and Web Crypto (Node ≥20 or any evergreen browser).

### Path D: shell out to the CLI from a worker (for SaaS)

If your tool is server-rendered SaaS:
- Spawn `screenreg register` from a worker job
- Store the resulting `.screenreg` in the user's project storage (or pass `--loose` for separate `manifest.json` + `.ots` files)
- Surface a "Registered ✓" indicator in the UI with a button to download the `.screenreg`

This is the recommended pattern for any SaaS writing tool that wants to register on the user's behalf.

## What to surface in your UI

Required:
- A **Register** button (not auto-register — writers should make this an intentional act)
- A confirmation showing the **content hash** and **claim hash** (for power-user transparency)
- A clear note that this **does not replace Copyright Office registration** (link to [`comparison.md`](comparison.md))

Recommended:
- An **AI-training preference** toggle (allowed / notAllowed / constrained) with the C2PA convention explained briefly
- A **Verify** button that loads the user's `.screenreg` (or, in `--loose` setups, the manifest + .ots) and confirms the current file matches
- A **Diagnose** button for when Verify fails — explains the transforms applied to the current file

Optional but valuable:
- A **timeline** view showing all registered versions of a script over time
- A **scene-disclosure** flow letting writers generate selective-disclosure proofs for specific scenes
- An **encrypted-fields** toggle for writers who want to keep title/author private

## What NOT to do

1. **Don't upload the screenplay to your servers.** The whole privacy promise is that the script stays on the writer's machine. Doing your own copy or having a "we'll back it up for you" feature breaks the model.
2. **Don't add free credits or rate limits that imply your-org has special access.** The protocol is the protocol; vendor convenience tiers should be transparent.
3. **Don't claim "court-grade" or "WGA-replacement" in marketing copy.** Both are misleading. Use language like "cryptographically verifiable" and "may be useful as evidence" — same language we use in [`threat-model.md`](threat-model.md).
4. **Don't reinvent the spec.** If you find yourself needing a new field, normalize profile, or proof type, open a PR. Forking the spec creates incompatibility that hurts everyone.
5. **Don't market the optional on-chain certificate or NFT as authorship proof.** If you wrap a registration in the optional Ethereum-mainnet anchor or a product NFT, that record proves a specific claim hash was written on-chain — it does NOT prove authorship and is NOT a Copyright-Office replacement. The on-chain anchor is never a time or priority source (Bitcoin is), it is never required, and any relayer or registry-intake gating you add MUST be content-neutral (admission, rate limits, an optional small fee, or light proof-of-work) — never a filter on a script's content. The user-chosen `title`/`name` written on-chain are public and permanent; surface that to the user before they sign.

## What we expect from integrators

If you integrate, we'd love to:
- Add you to the README's "Adopters" section
- Cross-link to your docs from the protocol's docs
- Get your feedback on what spec ambiguities you ran into (early integrators have outsized influence on v2)

There is no fee or paperwork. The license is MIT for code and CC-BY for the spec. Integrators can adopt it directly and ask to be listed after launch.

## Reference integrations

- **(your tool here)** — be the first listed integrator

## Questions

Open an issue at [github.com/screenplay-registry/screenreg](https://github.com/screenplay-registry/screenreg), or email `protocol@screenplayregistry.org`.
