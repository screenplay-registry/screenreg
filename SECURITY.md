# Security Policy

The Screenplay Registry handles cryptographic commitments that may be referenced as legal evidence. We take security reports seriously and respond promptly.

## Reporting a vulnerability

**Email**: `security@screenplayregistry.org`

Include in your report:
- A description of the vulnerability
- Steps to reproduce (proof-of-concept if possible)
- Affected component (CLI, spec, reference implementation, web verifier)
- Affected version(s)
- Your suggested severity (your best estimate; we'll triage)

**Please do NOT** open a public GitHub issue for vulnerabilities. Public disclosure before a fix is published puts existing users at risk.

## What we consider in scope

- Cryptographic flaws in the protocol spec or reference implementation
- Vulnerabilities in the CLI that affect a writer's local environment (RCE, key disclosure, privilege escalation)
- Bypasses of the protocol's stated guarantees (forgery, replay, membership-oracle leaks, false-binding attacks)
- Supply-chain compromise of the published reference implementation or its dependencies
- Issues that allow an attacker to produce a verifying registration for content they don't possess

## What we consider out of scope

- Issues in the upstream OpenTimestamps protocol or calendar operators (report those upstream)
- Bitcoin protocol vulnerabilities (out of our control)
- Drand network vulnerabilities (out of our control)
- DoS via mass automated registration through public calendars (by design; absorbed by calendar operators)
- Weak-password attacks against `encryptedFields` (a writer choosing a weak password is a documented threat-model gap, not a vulnerability — see `docs/threat-model.md`)

## Response timeline

- **Within 72 hours**: acknowledgement of receipt
- **Within 14 days**: initial triage + severity classification
- **Within 90 days**: fix released for confirmed vulnerabilities (faster for critical issues)

We follow coordinated disclosure: we'll work with you on a timeline that lets us ship a fix before the issue becomes public.

## Past audits

The protocol has been audited via adversarial review (multiple independent LLM-based audits running structured threat-model prompts) prior to v0.1.0 release. The audit trail is visible in the repository's git history. Formal third-party audit is on the post-launch roadmap.

## Supported versions

| Version | Supported |
|---|---|
| v0.1.x | ✓ Active |
| v0.0.x (pre-launch wip) | ✗ Not supported |

When v0.2 ships, v0.1 enters a 6-month security-fix-only window before being deprecated.
