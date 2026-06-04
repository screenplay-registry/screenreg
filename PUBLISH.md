# Publishing `screenreg` to npm

The package is configured to publish as the unscoped name **`screenreg`** (so users run
`npm i -g screenreg` / `npx screenreg`). Verification and registration need only Node ≥20 — no Python,
no native build step on the consumer's machine.

## One-time setup

- **npm account** with two-factor auth enabled. The package `author` is `Rufus Xavier
  <protocol@screenplayregistry.org>`; publish from an account consistent with the project's stewardship.
- **Reserve the brand names** (squatting insurance), even though the CLI publishes unscoped:
  - the org/scope **`screenplay-registry`** → <https://www.npmjs.com/org/create> (gives `@screenplay-registry/*`)
  - optionally the unscoped name **`screenplay-registry`** as a placeholder.
- `npm login`.

## Publish

```bash
npm publish
```

That's it. The lifecycle hooks make it safe:

- `prepublishOnly` runs `npm run check` (typecheck + full test suite) — a broken build can't be published.
- `prepack` runs `npm run build` (cleans `dist/` then `tsc`) — the tarball always reflects current source.
- `publishConfig.access` is `public`.

Sanity-check what will ship without publishing:

```bash
npm pack --dry-run     # review the file list; confirm no Python, no source-only files, dist present
```

### Recommended: signed provenance

Publish from CI (GitHub Actions) with provenance, so npm records a verifiable link from the tarball to
the source commit + workflow — fitting for a verifiability-focused project:

```yaml
# .github/workflows/publish.yml (sketch)
permissions: { id-token: write, contents: read }
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with: { node-version: 20, registry-url: 'https://registry.npmjs.org' }
  - run: npm ci
  - run: npm publish --provenance
    env: { NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }} }
```

Local `npm publish` works too, just without the provenance attestation.

## After publishing

- Verify from a clean directory: `npx screenreg@latest verify some.screenreg` (no repo, no Python).
- Update the docs that currently say "not yet published to npm" (README quick-start, `docs/adoption-guide.md`
  Path C) to `npm i -g screenreg` / `npx screenreg`.
- Bump `version` in `package.json` per change (semver; start at 0.x to signal pre-1.0). The public SDK
  surface is `src/index.ts` only — keep those exports stable across minors.

## Identity

Keep the project's identity discipline: author/committer = `Rufus Xavier
<protocol@screenplayregistry.org>`; no AI-assistant or third-party attribution anywhere in the package
or its metadata.
