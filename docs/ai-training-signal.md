# The AI-Training Opt-Out Signal

A registered claim MAY include a preference field declaring the writer's wishes about AI training. This document explains what the signal IS, what it ISN'T, and how it fits into the broader landscape.

---

## What the signal is

A field in `committedClaim.preferences` named `trainingMining` (locked at v1 against the [CAWG training-data-mining assertion](https://cawg.io/training-and-data-mining/1.0) — originally part of the C2PA 1.x spec, now maintained by the Creator Assertions Working Group adjacent to C2PA. See [Note on field syntax](#note-on-field-syntax) below).

Allowed values (per the C2PA convention):
- `allowed` — owner explicitly permits AI training on this work
- `notAllowed` — owner explicitly forbids AI training on this work
- `constrained` — owner permits some uses but not others; details out of scope for v1

The field's PRESENCE and VALUE are part of the on-chain commitment. Once registered, the signal cannot be modified without invalidating the proof.

## Why C2PA convention

Reusing the C2PA training/mining assertion shape means the signal is honored from day 1 by every system that already speaks C2PA:
- **Adobe Firefly** — respects the preference in image training; expected to extend to text in time
- **Spawning's HaveIBeenTrained registry** — aggregates opt-outs across formats
- **Future LLM providers** — many have committed to honoring C2PA preferences as the spec matures

By using the same field name + value enumeration, we plug into existing honoring infrastructure rather than building a parallel registry that no one consults.

## What the signal is NOT

1. **It is NOT enforcement.** This is the most important sentence in this document.
   The protocol does not contain code that prevents anyone from scraping your script. It does not encrypt your file from AI crawlers. It does not legally compel anyone to honor your preference.
2. **It is NOT a license.** A license grants or revokes rights. The signal expresses INTENT but does not transfer or restrict IP rights — your copyright already does that. The signal is a separate, narrower mechanism for declaring training-mining preferences.
3. **It is NOT retroactive.** If an AI company scraped your work BEFORE you registered, your registration cannot remove your data from their training set. The signal is forward-looking.
4. **It is NOT a guarantee of detection.** If a company trains on your work in violation of your signal, you may have no way to detect it. (Some research projects watermark or fingerprint training data, but those are external to this protocol.)

## What the signal IS useful for

1. **Evidence in litigation.** "I publicly declared on $DATE that I did not consent to AI training on this work. The defendant scraped it on $LATER_DATE in defiance of that declaration." This is exactly the kind of evidence that prevailed (in part) in *Bartz v. Anthropic* — the court ruled training on legally-acquired books was fair use, but pirated copies in the training set remained actionable. A public, dated opt-out signal strengthens the "they should have known" argument.
2. **Coordinating with honoring systems.** As more LLM providers commit to honoring C2PA training-mining preferences, having your signal in a machine-readable, cryptographically-anchored format makes it discoverable by those systems.
3. **Cultural pressure on holdouts.** A growing public registry of opt-outs raises the reputational cost of training on opted-out works. This is soft power, not hard enforcement, but it's not nothing — see how SBOMs (software bills of materials) went from "weird academic thing" to "industry-standard expectation" over five years.
4. **Court of public opinion.** When a model is shown to have trained on opted-out works, public discourse can hold the trainer accountable in ways the legal system is too slow to.

## What the signal is NOT a substitute for

- **Your copyright.** Copyright in the US arises automatically on fixation (per Berne Convention). The signal does not replace, supplement, or interpret your copyright.
- **US Copyright Office registration.** For statutory damages in an infringement suit, you still need Copyright Office registration. See [`threat-model.md`](threat-model.md).
- **`robots.txt`.** The signal is the same SHAPE of declaration as a `robots.txt` directive — a public, machine-readable wish. It does not replace the existing web mechanisms; it complements them.
- **A DRM scheme.** This is not DRM. The protocol does not encrypt, fingerprint, or otherwise restrict the script. It just records your stated wish.

## How to USE the signal effectively

If you want maximum effect:

1. **Set the signal at registration time.** Use `--training-mining notAllowed` when running `screenreg register`.
2. **Make it discoverable.** Publish your manifest publicly (e.g., on your portfolio site) so honoring systems can find it.
3. **Use it consistently across works.** A scattered signal is weaker than a uniform one.
4. **Combine with platform-level opt-outs.** Use Spawning's HaveIBeenTrained registry, set your tools' built-in preferences (Adobe Content Authenticity preferences, etc.).
5. **Don't overstate.** When citing the signal in a complaint or public statement, describe it as "a public, machine-readable preference declaration honored by [list of systems] and recommended by C2PA." Don't call it a "license" or "binding restriction."

## Note on field syntax

The v1 JSON shape is LOCKED:

```jsonc
"preferences": {
  "trainingMining": "notAllowed"   // or "allowed" or "constrained"
}
```

The enum is closed at v1 (`additionalProperties: false`, no other preference fields, no other enum values). Unknown values MUST be rejected by verifiers. Forward-compat additions land via a new `schemaId` in v2+, NOT silent enum growth — see `spec/v1/envelope.schema.json` `Preferences` definition + `spec/v1/02-envelope.md` §3.2.

This shape is a SIMPLIFICATION over the CAWG training-data-mining assertion's full nested structure (which has a richer value object including `entries` arrays per training data type). The protocol may translate to CAWG's full form when emitting a C2PA/CAWG sidecar (post-v1). The originating C2PA 1.x assertion was migrated to CAWG when C2PA 2.x narrowed core scope; the enum values (`allowed` / `notAllowed` / `constrained`) carry forward unchanged.
