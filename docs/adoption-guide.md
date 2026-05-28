# Adoption Guide (for integrators)

If you build a writing tool — Final Draft, Highland, Fade In, Sudowrite, a web editor, a self-hosted markdown writer — this guide tells you how to integrate The Screenplay Registry registration as a button in your tool.

---

## Why integrate

Writers want one-click registration without leaving their writing environment. The CLI works for power users; tool integration is what makes it ambient — same UX shape as "Save As PDF" or "Export to Final Draft."

For your users, the benefit is: their script gets a free, Bitcoin-anchored timestamp and an AI-training preference signal embedded in your save flow.

For you, the benefit is a standards-based registration flow with no per-registration fee and no custody of user scripts.

## Integration paths

### Path A: shell out to the CLI (simplest)

Spawn `screenreg register <file>` from your tool's "Register" menu. Parse stdout/stderr for the result. Drop the produced `.manifest.json` + `.proof.ots` in a registrations subdirectory next to the script.

This works in any tool that can spawn a subprocess. Total integration effort: ~1 hour.

```bash
screenreg register screenplay.fountain --envelope-out registrations/v1.manifest.json --ots-out registrations/v1.proof.ots
```

Optional flags:
- `--encrypt-title "..." --encrypt-author "..."` — for owner-key encrypted metadata
- `--training-mining notAllowed` — set the AI-training preference
- `--no-scene-tree` — skip the scene Merkle tree if you don't want selective disclosure

### Path B: import the TypeScript SDK (for JS/TS tools)

For tools built in Node / Electron / browser:

```typescript
// All public exports come from the package root. The package's `exports` map
// resolves "@screenplay-registry/cli" to a curated index re-exporting every
// stable symbol. Subpath imports (`/normalize`, `/envelope`, etc.) are NOT
// supported in v1 — reaching into deeper paths breaks across versions.
import {
  normalize,
  contentHashOfNormalized,
  buildCommittedClaim,
  buildEnvelope,
  computeClaimHashBytes,
  detectScenes,
  buildSceneTree,
  submitOts,
} from '@screenplay-registry/cli'

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

The SDK is pure TypeScript (zero deps for normalize/canonicalize/merkle/encrypt; the OTS submit path subprocesses a Python helper, which requires `opentimestamps` installed on the system).

### Path C: shell out to the CLI from a worker (for SaaS)

If your tool is server-rendered SaaS:
- Spawn `screenreg register` from a worker job
- Store the resulting `manifest.json` + `.ots` files in the user's project storage
- Surface a "Registered ✓" indicator in the UI with a button to download both files

This is the recommended pattern for any SaaS writing tool that wants to register on the user's behalf.

## What to surface in your UI

Required:
- A **Register** button (not auto-register — writers should make this an intentional act)
- A confirmation showing the **content hash** and **claim hash** (for power-user transparency)
- A clear note that this **does not replace Copyright Office registration** (link to [`comparison.md`](comparison.md))

Recommended:
- An **AI-training preference** toggle (allowed / notAllowed / constrained) with the C2PA convention explained briefly
- A **Verify** button that loads the user's manifest + .ots and confirms the current file matches
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

## What we expect from integrators

If you integrate, we'd love to:
- Add you to the README's "Adopters" section
- Cross-link to your docs from the protocol's docs
- Get your feedback on what spec ambiguities you ran into (early integrators have outsized influence on v2)

There is no fee or paperwork. The license is MIT for code and CC-BY for the spec. Integrators can adopt it directly and ask to be listed after launch.

## Reference integrations

- **(your tool here)** — be the first listed integrator

## Questions

Open an issue at [github.com/the-screenplay-registry/protocol](https://github.com/the-screenplay-registry/protocol) (link forthcoming — currently in private development).
