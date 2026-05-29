# `/landing/` — the screenplayregistry.org static site

What's deployed:

- `index.html` — the marketing landing page (editorial RFC aesthetic, browser-first CTAs).
- `create/` — the browser-native register page. Drag a `.fountain` file, get back a `manifest.json` + `proof.ots`. Script content never leaves the tab; only the 32-byte SHA-256 claim hash goes to the OpenTimestamps public calendars.
- `create/lib/` — compiled cross-runtime ES modules from `src/shared/`. Regenerate with `npm run build:browser` from the repo root.
- `_headers` — Cloudflare Pages security headers (CSP, HSTS, no-referrer, Permissions-Policy locking down sensors, COOP/CORP, X-Frame-Options DENY).

## Deploy on Cloudflare Pages

1. Connect the GitHub repo (`screenplay-registry/screenreg`).
2. Build command: `npm install && npm run build:landing`.
3. Build output directory: `landing/`.
4. Production branch: `main`.
5. Bind the apex `screenplayregistry.org` and `www.` to the Pages project.
6. Verify the deployed `_headers` is applied — `curl -I https://screenplayregistry.org/create/` should show every header in this file, and `curl -I https://screenplayregistry.org/verify/` should return 200.

### What `build:landing` does

`npm run build:landing` runs two steps from the repo root:

- `build:browser` — compiles `src/shared/` to `landing/create/lib/` (the cross-runtime ES modules the browser register page imports).
- `build:verify` — copies `verifier-web/index.html` and `verifier-web/verifier.js` into `landing/verify/`. `landing/verify/` is .gitignored; it is a build artifact regenerated on every deploy from `verifier-web/` (the source of truth for the read-only verifier).

The published `landing/` tree contains every file Cloudflare Pages should serve. No symlinks, no sibling Pages projects, no Worker routing.

## CSP tradeoff: `style-src 'unsafe-inline'`

Every page currently uses a single inline `<style>` block to keep load fast and dependency-free. The CSP allows `'unsafe-inline'` for styles only — `script-src` is still strict `'self'`, blocking inline + eval. Inline styles cannot exfiltrate data (no JS execution, no `fetch`), so the marginal risk is low. The future-tight path is to move every `<style>` into a sibling `.css` and switch to `style-src 'self'`; this is tracked as a polish task and not load-bearing for v0.2.

## Adding a new outbound endpoint

The `/create/` CSP `connect-src` allowlist is the **only** place the page can make outbound HTTPS requests. Any new OTS calendar URL must be added there, OR the page must be redeployed with the allowlist extended. Without an entry, `fetch()` is refused by the browser at the CSP layer — defense-in-depth against an attacker who manages to exfiltrate the page's contents to a hostile host.

## Privacy posture

- No analytics. No third-party scripts. No third-party fonts (system serif + system monospace).
- `Referrer-Policy: no-referrer` strips referrer headers on every outbound calendar POST.
- `Permissions-Policy` blocks every sensor / payment / clipboard API the page never uses.
- `Strict-Transport-Security` preload-eligible (2-year max-age, `includeSubDomains; preload`).

This is the operational complement to the protocol's "script never leaves your machine" promise — the page itself cannot be repurposed to phone home.
