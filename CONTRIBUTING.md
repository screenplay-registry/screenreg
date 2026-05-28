# Contributing to The Screenplay Registry

Thanks for considering a contribution. This project ships under the **Developer Certificate of Origin (DCO)** model — every commit must include a `Signed-off-by` line.

```bash
git commit -s -m "your commit message"
```

This is a lightweight alternative to a CLA: by signing off, you affirm the [DCO 1.1](https://developercertificate.org/) terms (you have the right to submit the work under the project's license).

## What's in scope

- Bug fixes in the reference TS implementation
- New adversarial test vectors that catch real-world failure modes
- Documentation improvements (especially the threat model, FAQ, comparison)
- Integration guides for new writing tools
- Translations of user-facing documentation

## What needs design discussion first (open an issue before writing code)

- Changes to the canonical normalization rules — these are commitment-bearing, so changes mean a new profile (`screenplay-registration-norm/v2-*`)
- New profile types (`screenplay-registration-merkle/v2`, `screenplay-registration-claim:v2`)
- New evidence-bundle proof types (EAS, Sigstore-style, ZK property proofs)
- New cryptographic primitives (KDF parameters, AEAD scheme, padding scheme)

For these, the COMMITMENT shape itself is sacred — backward compatibility for existing v1 proofs is non-negotiable.

## What's out of scope

- Custom cryptography that isn't widely-reviewed
- Closed-source dependencies
- Telemetry / analytics in any code path

## Development workflow

```bash
# 1. Clone
git clone https://github.com/screenplay-registry/screenreg.git
cd screenreg

# 2. Install dependencies
npm install
python3 -m venv .venv && .venv/bin/pip install opentimestamps opentimestamps-client

# 3. Run tests
npm test           # vitest, all
npm run typecheck  # tsc --noEmit

# 4. Regenerate test corpora (if you modified normalization/canonicalize/Merkle/encryption)
npx tsx scripts/generate-normalization-corpus.ts
npx tsx scripts/generate-envelope-corpus.ts
npx tsx scripts/generate-scene-tree-corpus.ts

# 5. Try the CLI end-to-end
./bin/screenreg.mjs register /tmp/my-screenplay.fountain --mock
```

## Pull request guidelines

- Small, focused PRs are easier to review.
- Include test vectors for any new behavior.
- Update the relevant spec section in `/spec/v1/` if your change affects committed semantics.
- Sign your commits (`git commit -s`).
- Reference any related issues.

## Code style

- TypeScript strict mode (already configured in `tsconfig.json`).
- Avoid dependencies in `/src/normalize/`, `/src/envelope/`, `/src/merkle/` — these are the commitment-bearing modules and must remain pure-TS / Node-builtin only.
- `/src/anchors/` is allowed to subprocess Python (the helper script); a future v1.1 may replace it with a clean-room TS calendar submitter.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — email `security@screenplayregistry.org`. **Do NOT open a public GitHub issue** for security-sensitive findings (cryptographic bugs, key-disclosure paths, forgery / replay / membership-oracle attacks, etc.).

## License

By contributing, you agree your contributions are licensed under:
- **MIT** for code
- **CC-BY 4.0** for spec
- **CC0** for test vectors

This is the same license the project ships under. No other licenses are accepted.
