# Screenplay Registry Protocol v1.0
## Section 07 — Time-locked Encrypted Fields (capability-flagged)

**Status**: OPTIONAL, CAPABILITY-FLAGGED. Implementations that do NOT support timelock MAY verify all other commitment-bearing fields of a manifest, but MUST NOT claim full v1 conformance for manifests containing a non-empty `committedClaim.timelockFields` array.

---

### 1. Purpose

Allow a registrant to encrypt specific fields of their registration such that decryption is **not possible until a deterministic future moment** — without trusting any third party to hold the key.

Use cases:

- **Embargo / NDA workflows**: lock the title + logline until pitch date; the registration is anchored TODAY, but no one (including the writer) can decrypt those fields until the embargo lifts.
- **Vesting commitments**: prove you wrote a specific work by date X but withhold the work itself until date Y.
- **Sealed-envelope arbitration**: lock disputed fields until a hearing date; both parties commit before the hearing, neither can change after.

The commitment (`claimHash` → Bitcoin) is created NOW. The fields decrypt LATER. No vault, no escrow, no human in the loop.

### 2. Drand League of Entropy

This section uses the [Drand](https://drand.love) League of Entropy threshold-BLS network and the [`tlock`](https://github.com/drand/tlock) scheme. Drand publishes deterministic signatures at fixed round intervals; an encryption against round R cannot be decrypted until that round's signature is published.

v1 uses the **quicknet** chain:

| Property | Value |
|---|---|
| Chain hash | `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971` |
| Period | 3 seconds |
| Genesis | 2023-08-23 18:29:27 UTC (unix `1692803367`) |
| Underlying curve | BLS12-381 (Drand quicknet upstream) |
| Scheme identifier (this protocol) | `tlock-bls12-381-quicknet` |
| Public key | The quicknet group public key (verifiable against the chain hash) |

A `unlockAt` unix timestamp deterministically maps to a Drand round. Drand
round `N` happens at `genesis + N * period`, so to get the first round at or
after `unlockAt`:

```
unlockAtRound := ceil((unlockAt - genesis) / period)
```

(Boundary case: when `unlockAt = genesis + k*period` for integer `k > 0`, this
returns round `k` — that round's signature is what enables decryption AT the
specified time exactly.)

### 3. The `timelockFields` array

When present in `committedClaim`, `timelockFields` is a non-empty array of objects with this shape:

```jsonc
{
  "timelockFields": [
    {
      "name": "title",                                 // unencrypted field label
      "ciphertext": "<base64 tlock ciphertext>",
      "unlockAtRound": 12345678,                       // Drand round at which decryption becomes possible
      "unlockAt": "2027-01-01T00:00:00Z",             // informational; derived from round + chain genesis/period
      "drandChainHash": "52db9ba70e0cc0f6e...",       // commits which Drand chain to fetch from
      "drandPublicKey": "<hex of group pubkey>",     // for offline verification
      "scheme": "tlock-bls12-381-quicknet"            // encryption scheme identifier
    }
  ]
}
```

Field-by-field rules:

- `name` — UTF-8 label, ≥ 1 character. Field NAMES are NOT encrypted (presence + length leak per design).
- `ciphertext` — base64 of the tlock-encrypted ciphertext. The plaintext is the raw UTF-8 bytes of the locked value (no padding, no canonicalization).
- `unlockAtRound` — positive integer Drand round number. Decryption is mathematically impossible before this round is signed.
- `unlockAt` — ISO-8601 UTC timestamp. INFORMATIONAL ONLY — derived from `unlockAtRound + chain genesis + period`. Verifiers MUST trust the round, not the timestamp.
- `drandChainHash` — 64-hex-char chain identifier. Commits which Drand network to consult. v1 quicknet hash MUST be used unless a future chain is locked in a later spec revision.
- `drandPublicKey` — hex-encoded chain group public key. Required so an offline verifier can validate Drand beacons without trusting any specific Drand operator.
- `scheme` — identifier of the encryption scheme. v1 quicknet = `tlock-bls12-381-quicknet` (BLS12-381 pairing, tlock library, Drand quicknet chain). Verifiers MUST reject manifests whose `scheme` does not match the scheme they support — a mismatch indicates the field was encrypted under a different protocol than the verifier can decrypt.

### 4. Decryption procedure

A verifier with access to a Drand beacon at round ≥ `unlockAtRound`:

1. Fetch the Drand beacon for `unlockAtRound` from any Drand HTTP relay (or a self-hosted Drand client).
2. Verify the beacon signature against `drandPublicKey` (the standard Drand verification).
3. Use the beacon signature as the decryption key per the `scheme` (tlock).
4. Decrypt `ciphertext` to recover the plaintext field bytes.

Before `unlockAtRound`, decryption is computationally infeasible under the BLS hardness assumption.

### 5. Commitment semantics

The entire `timelockFields` array IS part of `committedClaim` and IS in the canonical-JSON hash. This means:

- The CIPHERTEXTS are committed to Bitcoin at registration time — they cannot be substituted after the fact.
- The `unlockAtRound` per field is committed — a registrant cannot retroactively shorten the embargo.
- The `drandChainHash` + `drandPublicKey` are committed — a registrant cannot point at a malicious sibling chain after registration.

What is NOT committed: the plaintext (by design; decryption happens later).

### 6. Capability conformance

A v1 implementation MAY skip timelock support. Such an implementation:

- MUST recompute `claimHash` over the full `committedClaim` including `timelockFields` (the bytes are hashed regardless of semantic support).
- MUST verify the OTS anchor against that hash normally.
- MUST surface a warning that timelock fields are present but cannot be decrypted by this implementation.
- MUST NOT claim full v1 conformance for that manifest.
- MAY claim "v1-core conformance" or equivalent if it implements every other commitment-bearing section.

A fully-conformant v1 implementation MUST support decryption of timelock fields once `unlockAtRound` has passed AND a Drand beacon is available.

### 7. Threat model

#### 7.1 Drand network failure

If Drand quicknet ceases producing beacons before `unlockAtRound`, decryption becomes impossible. Mitigations: (a) writers SHOULD pick reasonable unlock horizons (months to ~2 years); (b) Drand is a federated network with multiple independent operators — a single operator failure does not stop beacon production; (c) future revisions of this section may support multi-chain timelock so a registration can be decrypted from any of several chains.

#### 7.2 Adversarial early decryption

The BLS hardness assumption guarantees decryption is infeasible before round signing. If BLS hardness assumptions are broken (a multi-decade tail risk), early decryption becomes possible. Same threat horizon as the other crypto primitives in this protocol.

#### 7.3 Pre-decryption substitution

Someone with the timelock ciphertext cannot substitute a different plaintext, because the ciphertext itself is committed in `claimHash`. The committed bytes are what they are; only the verifier's ability to read them changes over time.

#### 7.4 Field-presence leakage

`timelockFields` field NAMES are committed and visible. A verifier learns "there is a locked field called `title`" before decryption. Writers who want presence-private fields MUST NOT use the `timelockFields` mechanism for those — combine with the `encryptedFields` mechanism (Section 04) for the presence-private cases.

### 8. Compliance statement

An implementation claims full v1 conformance for this section if and only if:

1. It can serialize `timelockFields` per §3 with byte-identical canonical form against the test vectors.
2. It hashes `timelockFields` into `claimHash` per Section 02 §5.
3. It can decrypt a field whose `unlockAtRound` has passed, given a Drand beacon, against the declared `drandChainHash` + `drandPublicKey`.
4. It refuses to decrypt before `unlockAtRound`.
5. It surfaces a clear "still locked" status for fields whose round has not yet arrived.

---

**End of Section 07.**
