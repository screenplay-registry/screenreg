# Screenplay Registry Protocol v1.0
## Section 10 — Off-chain registry index (`urn:screenplay-registration-registry-record:v1`)

**Registry-record identifier**: `urn:screenplay-registration-registry-record:v1`

**Tier**: secondary / additive / off-chain. This section defines an OPTIONAL public registry
index — a searchable directory of registrations — and the per-record verification and priority
rules over it. Nothing in this section is commitment-bearing: no field defined here is hashed
into `claimHash`, and no behavior here can change the bytes of any existing v1 artifact. The
index is a discovery convenience layered over the frozen v1 commitment surface; it adds nothing
to and removes nothing from what a registration proves.

---

### 1. Purpose

The free Bitcoin timestamp answers "this commitment existed by block N." The registry index
turns a pile of independent timestamps into something a writer (or an adjudicator) can search:
look up a `claimHash`, a public title, or a public author label, and find the registration plus
the anchors needed to RE-VERIFY it without trusting the operator.

The index is a directory, not an authority. Its records point AT the cryptographic truth (each
record's own `.ots` against Bitcoin); they are not themselves the truth.

### 2. The registry record

A registry record is an off-chain JSON object conforming to
`spec/v1/registry-record.schema.json`. It is NOT a `committedClaim` field and is never hashed.

```jsonc
{
  "registryRecordVersion": "urn:screenplay-registration-registry-record:v1",
  "claimHash": "sha256:<lowercase-hex>",       // primary + join key everywhere
  "title": "THE LAST REWRITE",                 // OPTIONAL public, searchable label
  "author": {
    "pubkey": "ed25519:<base64>",              // the registrant's public key
    "name": "Jane Roe"                         // OPTIONAL chosen label; blank by default
  },
  "registeredAt": "2026-05-29T12:00:00Z",      // INFORMATIONAL ONLY; see §2.2
  "anchors": {
    "opentimestamps": { "proofRef": "the-last-rewrite.ots", "bitcoinBlock": 875432 },
    "ethereum": {                              // OPTIONAL; Section 09; never a priority source
      "chainId": 1, "contract": "0x..", "txHash": "0x..", "logIndex": 2, "blockNumber": 21345678
    }
  }
}
```

#### 2.1. `contentHash` is forbidden

The script `contentHash` (the whole-work fingerprint) MUST NOT appear in a registry record at
the top level OR nested anywhere within it. A public, searchable column of script fingerprints
would turn the index into a MEMBERSHIP ORACLE: anyone holding a candidate script could test
whether it had been registered, defeating the privacy of a bare-claim timestamp. A holder looks
up their own registration by their own `claimHash` (recomputable from their envelope), never by
a published `contentHash`. A validator MUST REJECT (not ignore) a record carrying a `contentHash`
at any depth.

#### 2.2. `registeredAt` is informational only

`registeredAt` is an operator-supplied wall-clock label. It is NEVER used for priority, tie
resolution, or any verification decision. The only trustworthy time is the Bitcoin block height
derived from the record's own `.ots` (§4). Ranking on an operator timestamp would let an
operator forge priority; this is forbidden.

#### 2.3. Privacy

`title` and `author` labels are PUBLIC by default but reversible (delistable) — they are
self-published, user-CHOSEN labels (`name` is blank by default), not auto-extracted PII. A
writer wanting only a private timestamp registers free against Bitcoin WITHOUT a listing. Even
`claimHash` is, for a bare claim, recomputable by a script-holder, so a listing is itself a
public membership statement (that is the point of a registry); the protocol simply never hands
out the stronger `contentHash` fingerprint (§2.1).

### 3. Tamper-evidence — honest framing

**The MVP index is a SIGNED, MIRRORABLE dataset, NOT a tamper-proof log.** It provides ZERO
cryptographic protection against an operator that censors, withholds, delays, reorders, or
equivocates (serves split views to different clients). An OTS-stamped snapshot root would prove
inclusion in ONE snapshot; it would NOT prove append-only behavior, non-removal, or the absence
of equivocation. "Signed dataset + root" is not a transparency log.

The protection that DOES hold is per-record and operator-independent: **each record's truth is
its own `.ots` verified against Bitcoin** (§4), which any party can check without trusting the
operator. Treat the index as a discovery convenience and assume the operator MAY equivocate.

**Target (roadmap, not shipped):** a CT-style transparency log — signed tree heads, append-only
consistency proofs, per-record inclusion proofs, public checkpoints with gossip and mirrors, and
client monitoring. Only then is "nothing was altered or removed" cryptographically meaningful
(and only for monitoring clients). Until that exists, this section says so plainly.

#### 3.1. Validity vs spam — different things; content-neutral

A valid OTS proof gates VALIDITY (a record references a real Bitcoin-anchored registration); it
is NOT an anti-spam cost (OTS is free and permissionless). Spam resistance is a SEPARATE,
operator-layer, CONTENT-NEUTRAL mechanism — account / verified-email / API-key admission plus
per-account rate limits, an optional small fee, or light proof-of-work for anonymous intake.
These gate volume and submitter identity, never content, so they stay compatible with
anti-censorship. The base protocol remains free.

### 4. Per-record verification

A registry verifier re-checks each record independently. There is NO snapshot-root step in v1
(§7). For each record:

1. **Recompute the expected file digest** = the record's `claimHash` as raw 32 bytes (strip the
   `sha256:` label; decode the 64 hex chars). This is the digest the `.ots` must assert.
2. **Load the `.ots`** referenced by `anchors.opentimestamps.proofRef`. The reference is
   resolved ONLY relative to the snapshot's own directory; absolute paths, parent-directory
   (`..`) traversal, and symlinks MUST be rejected at load time. A missing or unloadable proof
   yields a per-record failure, never a crash.
3. **Verify structural `.ots` validity** — the proof parses cleanly and its file digest equals
   the expected digest. This is the "signed/mirrorable, NOT a tamper-proof log" guarantee. It
   does NOT by itself assert Bitcoin finality.
4. **Bitcoin-finality split.** A height parsed from the `.ots` attestation is, on its own, only
   an OTS-CLAIMED height — the reference verifier reads heights from the attestation WITHOUT a
   Bitcoin-header inclusion check, so an OTS-claimed height is not proof that the block at
   height N contains the timestamp's Merkle root. A height becomes `bitcoin-final` ONLY when an
   injected attestation verifier confirms header inclusion AND at least `minConfirmations`
   confirmations against the chain tip. Without such a verifier, EVERY height stays
   `ots-claimed` and the snapshot MUST NOT resolve priority (§5).

The verifier reports per record: structural validity, the list of `(height, finality)` pairs,
and any pending calendar URLs. ETH anchors (if present) are corroborating only and are verified
by Section 09's topics-only path; they never affect this section's outcome.

### 5. Priority and dispute resolution — Bitcoin only

Priority proves EARLIEST ANCHORED COMMITMENT, not authorship or originality. Per-scene overlap
still requires the opt-in comparison bundle (Section 06); the public index reveals no
`contentHash`, so identical content is NOT trivially detectable from the index.

- **Priority = the earliest Bitcoin block height, and nothing else.** The record whose
  `claimHash` is confirmed in the EARLIER Bitcoin block wins.
- **Same block ⇒ a tie.** There is no sub-block ordering.
- **Ethereum anchors are NEVER a priority source.** ETH ranks nothing and can never flip a
  Bitcoin-derived outcome.
- **`registeredAt` is ignored** (§2.2).
- **A height that is not Bitcoin-final cannot rank.** If any verified contender carries only
  OTS-claimed (header-unverified) heights, the contest is UNDETERMINED — an unverified `.ots`
  height could name any block, so ranking on it would be dishonest.

### 6. `ethereum` anchor — corroboration only

The optional `anchors.ethereum` coordinates point at a Section 09 `Registered` log. They are
verified, if at all, by the Section 09 topics-only verifier and are purely corroborating: a
missing, failed, unreachable, or `unverified` Ethereum check NEVER fails an otherwise
Bitcoin-valid record, and ETH is NEVER a priority/time source. A `batch` anchor (Section 09 §6)
is RESERVED and `unverified` in v1; the registry makes no Merkle-path claim for it.

### 7. Deferred follow-ups

- **Snapshot-Merkle root + transparency log.** A real, verifiable snapshot root requires a NEW
  named, domain-tagged Merkle profile — with its own wire schema, leaf ordering, duplicate
  handling, and conformance vectors — consistent with the project's rule that every Merkle tree
  is a named, domain-tagged profile. This is NOT defined or built at v1; it belongs with the
  CT-style transparency-log target (§3). Until then the index is a discovery convenience whose
  per-record truth is each record's own `.ots` against Bitcoin.
- **Batch receipts.** The Section 09 `batch` mode is RESERVED; no batch wire format exists in v1.
- **Commit-reveal title.** A private-but-anchored listing (publish `titleHash`, reveal only in a
  dispute) is a future addition.

### 8. Versioning rule

The registry-record URN (`urn:screenplay-registration-registry-record:v1`) and the record shape
above are LOCKED at v1. Any change to the record shape, the priority rule, or the finality model
requires a new record URN under a new schema — old records continue to verify under v1 rules.

---

**End of Section 10.**

References:
- Section 02 — Envelope (`urn:screenplay-registration-envelope:v1`), §4.2 verifier consistency.
- Section 06 — Comparison disclosure bundle.
- Section 09 — Optional Ethereum on-chain anchor.
- [Certificate Transparency (RFC 6962)](https://www.rfc-editor.org/rfc/rfc6962) — the CT-style
  transparency-log target referenced in §3.
- [OpenTimestamps](https://opentimestamps.org/) — the Bitcoin time anchor each record re-verifies against.
