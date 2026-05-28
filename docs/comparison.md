# Comparison: The Screenplay Registry vs the alternatives

How this protocol compares to existing options for proving a screenplay existed by a specific date.

**TL;DR**: If you want federal-court statutory damages, register with the US Copyright Office. If you want guild-internal credit arbitration, register with the WGA. If you want a free, privacy-first, AI-aware, cryptographically verifiable timestamp that complements (not replaces) the above, use this protocol. **The best strategy combines them.**

---

## At-a-glance

| Property | The Screenplay Registry | US Copyright Office | WGA West/East | Bare OpenTimestamps | OriginStamp / Bernstein |
|---|---|---|---|---|---|
| **Cost per registration** | $0 | $45 | $10-25 | $0 | $20+/yr subscription |
| **Term** | Forever | Life + 70 years | 5 years (renewable) | Forever | Subscription-bound |
| **Processing time** | Seconds (calendar) + 1-6 hrs (Bitcoin) | ~4 months | Instant | Seconds + 1-6 hrs | Seconds |
| **What is uploaded?** | NOTHING (only a hash) | The full file | The full file | NOTHING | Hash only (some plans upload) |
| **Privacy of content** | Total — stays on your machine | Stored in gov registry | Stored on WGA server | Total | Vendor-dependent |
| **Selective scene disclosure** | YES (Merkle tree) | No | No | No | No |
| **Encrypted manifest fields** | YES (AES-256-GCM, owner-key) | No | No | N/A | Vendor-dependent |
| **AI-training opt-out signal** | YES (C2PA convention) | No | No | No | Some pilots |
| **Federal-court statutory damages** | Not directly | YES (post-registration) | No | No | No |
| **Guild credit arbitration weight** | No | No | YES (WGA-internal) | No | No |
| **Cryptographic verifiability** | YES (mathematical) | No (database lookup only) | No (file retrieval) | YES | YES (if anchored) |
| **Survives provider shutdown** | YES (forever, Bitcoin) | YES (US government) | Depends on WGA | YES (forever, Bitcoin) | NO (vendor-bound) |
| **Open source** | YES (MIT + CC-BY) | N/A | No | YES | No |
| **Tool integration** | Designed for it | Manual upload | Manual upload | CLI-only | Vendor APIs |
| **Survives a brand rename** | YES (URN-based namespace) | N/A | Tied to WGA org | YES | NO |

---

## US Copyright Office

**Use it.** This is the only thing that gives you federal-court statutory damages + attorney's fees in an infringement suit. As of 2026, fees are $45 for a single-author screenplay; a proposed 43% increase is under comment.

Processing time per the [Copyright Office's published status page](https://www.copyright.gov/help/status.html) is "up to four months" for electronic filings, with average processing typically lower; the published 90th-percentile horizon is the main planning friction. You upload the actual file; it gets stored in the government registry.

This protocol does NOT replace Copyright Office registration. It provides cryptographic evidence that COMPLEMENTS the Copyright Office's evidentiary record. Use both.

**Citations / resources**:
- Copyright Office processing times: https://www.copyright.gov/registration/docs/processing-times-faqs.pdf
- Fee schedule: https://www.copyright.gov/about/fees.html
- "Poor man's copyright" myth (explicitly debunked): https://copyrightalliance.org/faqs/poor-mans-copyright/

## WGA West / East registration

**Use it for credit arbitration.** WGA registration is the relevant document if a project gets made and there's a dispute over who deserves "Written by" credit. Cost: $10 (member) or $20-25 (non-member). Term: 5 years, renewable.

The WGA itself says explicitly that Registry registration "does not make comparisons of registration deposits, bestow any statutory protections, or give legal advice." It is NOT a substitute for Copyright Office registration in an infringement suit. Multiple entertainment lawyers (Zerner Law, Prescene, Lawyers Rock) have written that writers commonly over-rely on WGA registration as legal protection when it offers very little of that.

This protocol's value over WGA: free, no upload, no 5-year expiry, mathematical verifiability, selective scene disclosure, AI-training signal.

**Citations / resources**:
- WGA Registry: https://www.wgawregistry.org/
- WGA FAQ + protection disclaimer: https://www.wgawregistry.org/regfaqs.aspx
- Zerner Law: "It's Time for the Writers Guild to Shut Down the WGA Registry" (a sharp critique): https://www.zernerlaw.com/blog/its-time-for-the-writers-guild-to-shut-down-the-wga-registry/

## Bare OpenTimestamps (without this protocol)

You can use OpenTimestamps directly on any file:

```bash
ots stamp my-screenplay.fountain
```

This produces a `.ots` file that proves your screenplay's exact bytes existed by a Bitcoin block timestamp. Free, decentralized, verifiable forever.

This protocol's value over bare OTS:
- **Canonical normalization** so verifications survive minor formatting changes (BOM stripping, CRLF→LF, NFC) — same logical script always hashes the same way (within a profile)
- **Manifest envelope** with metadata (title, author, optional encryption)
- **Scene-level Merkle tree** for selective disclosure
- **Forward-compatibility** via the `committedClaim`/`evidenceBundle` split — future anchors (EAS-on-Base, etc.) attach without breaking v1 proofs
- **Honest verifier UX** with diagnose mode that explains hash failures in plain English
- **Standard preference field for AI-training opt-out**

If your use case is "I just want a Bitcoin timestamp on these bytes", bare OTS is sufficient. If your use case is "I'm a screenwriter who wants the full provenance story", this protocol provides the surface area you actually need.

## OriginStamp / Bernstein / Stampd

Commercial blockchain timestamping services. Each has features this protocol doesn't (enterprise audit reporting, court-prepared certificates, custodial signing keys for large orgs). They typically cost $20+/yr in subscription fees and tie your records to their continued operation.

This protocol's value over commercial services:
- **Free** (forever, no subscription)
- **Open source** (you can fork it, run your own infrastructure, never be vendor-locked)
- **Survives provider shutdown** — Bitcoin proofs verify against block headers; no calendar OR foundation is required for verification
- **Screenwriter-specific** (scene tree, normalization for Fountain files, AI signal)

If you need a commercial provider's enterprise features (notary-certified PDFs, court-ready bundles, custodial key management), use them. This protocol is designed for the long tail of individual writers who don't need or want a subscription.

## Defunct blockchain registries (cautionary tales)

Several blockchain registration projects died in 2018-2020 because they tied user proofs to the company's continued operation:

- **Ascribe** (2013-2018): grew to 13,500 users / 31,900 works; founders pivoted to Ocean Protocol; site dormant.
- **Stampery** (Spanish): co-founders moved on; no activity since 2018.
- **ProvenDB**, **Bitproof**, **Tierion**: similar trajectories.

The lesson: **a registration service that disappears takes your evidence with it** unless the underlying primitive is independent of the service. OpenTimestamps is structured so that ANY accumulated `.ots` proof verifies forever via Bitcoin, regardless of whether ANY calendar operator still exists. This protocol inherits that property by design.

## Combined strategy (recommended)

For a serious screenwriter, the strongest combination is:

1. **The Screenplay Registry registration** — immediate, free, privacy-first, AI-aware. Use at every significant draft revision. Back up the manifest + .ots files.
2. **WGA registration** at major milestones (sale, option, optioning) — for guild-internal credit disputes if the project gets made.
3. **US Copyright Office registration** before any public distribution — for federal-court teeth on infringement.

The protocol is the cheap, fast, frequent layer. WGA + Copyright Office are the slower, more specialized layers. They serve different purposes; none of them substitute for the others.
