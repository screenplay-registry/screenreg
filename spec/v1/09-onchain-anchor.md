# Screenplay Registry Protocol v1.0
## Section 09 — Optional Ethereum on-chain anchor (`ethereum-anchor` evidence)

**Evidence profile identifier**: `urn:screenplay-registration-evidence-ethereum-anchor:v1`

**Tier**: secondary / additive. This section defines an OPTIONAL evidence proof type and
pins the on-chain interface it refers to. The on-chain CONTRACT itself is reserved ("coming
soon"): the interface is frozen here, the deployed implementation is deferred. Nothing in
this section is commitment-bearing — no field defined here is hashed into `claimHash`, and
no behavior here can change the bytes of any existing v1 artifact.

---

### 1. Purpose

Provide a SECOND, independent witness to the same 32-byte commitment — the `claimHash` —
recorded on the Ethereum mainnet ledger, in addition to the Bitcoin time anchor from
OpenTimestamps.

The Ethereum anchor is **never** a time or priority source. Bitcoin (via OpenTimestamps)
remains the sole time + priority anchor (Section 02 §4.2 rule 4; Section 10). A missing,
failed, or unreachable Ethereum check MUST NEVER fail an otherwise Bitcoin-valid proof. An
Ethereum anchor adds a corroborating, human-discoverable record; it removes nothing and
ranks nothing.

The `contentHash` (the script fingerprint) is NEVER published on-chain or in any index. The
on-chain record commits only to the opaque `claimHash` plus user-chosen labels.

### 2. The `ethereum-anchor` evidence proof type

An Ethereum anchor appears as an entry in `evidenceBundle.proofs[]` (Section 02 §4). Like
every proof entry, it is UNTRUSTED metadata and is NOT part of the committed claim.

```jsonc
{
  "type": "ethereum-anchor",
  "profile": "urn:screenplay-registration-evidence-ethereum-anchor:v1",  // OPTIONAL; if present, MUST equal this
  "claimHash": "sha256:<lowercase-hex>",  // MUST equal the envelope claimHash (Section 02 §4.2 rule 3)
  "chainId": 1,                            // Ethereum mainnet
  "contract": "0x<40 hex>",                // the ScreenplayLedger address
  "registrant": "0x<40 hex>",              // the address recovered on-chain from the EIP-712 signature
  "txHash": "0x<64 hex>",
  "logIndex": 2,
  "blockNumber": 21345678,
  "batch": { "batchId": "..", "merkleRoot": "0x..", "path": ["0x.."] }   // OPTIONAL, RESERVED — see §6
}
```

**Required fields** (a verifier processing a named `ethereum-anchor` proof MUST require all of):
`type`, `claimHash`, `chainId`, `contract`, `registrant`, `txHash`, `logIndex`, `blockNumber`.

**Field rules:**

| Field | Rule |
|---|---|
| `type` | `"ethereum-anchor"` |
| `profile` | OPTIONAL. If present, MUST equal `urn:screenplay-registration-evidence-ethereum-anchor:v1`; a wrong value is rejected. |
| `claimHash` | `sha256:<lowercase-hex>`; MUST equal the verifier's independently recomputed envelope `claimHash`. |
| `chainId` | integer ≥ 1. A v1 verifier pins mainnet (`1`); see §3.1. |
| `contract` | `^0x[0-9a-fA-F]{40}$` — the `ScreenplayLedger` address. |
| `registrant` | `^0x[0-9a-fA-F]{40}$` — the address recovered on-chain from the EIP-712 signature (NOT `msg.sender`). |
| `txHash` | `^0x[0-9a-fA-F]{64}$` |
| `logIndex` | integer ≥ 0 — disambiguates the exact log within the transaction. |
| `blockNumber` | integer ≥ 0 |
| `batch` | OPTIONAL, RESERVED in v1 (§6). |

**`contentHash` is forbidden** on an `ethereum-anchor` proof — at the top level OR nested
anywhere within it (including under `batch`). Publishing a script fingerprint alongside an
on-chain record would turn the public ledger into a membership oracle for the work. A verifier
MUST REJECT (not ignore) an `ethereum-anchor` proof carrying a `contentHash` at any depth.

**Unknown-type tolerance is unaffected.** This strictness applies ONLY to proofs whose `type`
is exactly `"ethereum-anchor"`. Proofs of any other or unknown `type` remain tolerated and
reported as UNVERIFIED per Section 02 §4.2; they are never rejected for being unknown.

### 3. Pinned on-chain interface

The off-chain proof above references an on-chain record produced by the `ScreenplayLedger`
contract. The contract's wire surface is pinned here so the off-chain verifier, the spec, and
the (reserved) Solidity implementation agree byte-for-byte. The reference TypeScript constants
mirror this section verbatim in `src/anchors/eth/constants.ts`.

#### 3.1. Chain

The canonical chain is **Ethereum mainnet** (`chainId = 1`), not an L2. Rationale: the trust
roots are Bitcoin and Ethereum mainnet — there is no single-company sequencer in the trust
path. A v1 verifier treats a proof as a candidate only when `chainId === 1`.

#### 3.2. The event IS the ledger

The canonical on-chain artifact is the EVENT, not contract storage. The contract's only
persistent state is `nonces[registrant]` (replay protection). There is NO `claimHash → data`
storage mapping: a single-valued mapping could not hold duplicate registrations (which are
allowed), and priority is Bitcoin-only, so on-chain queryable state is unnecessary. Logs are
cheap and remain self-describing via `eth_getLogs`.

```solidity
event Registered(
    bytes32 indexed claimHash,
    address indexed registrant,
    uint256 blockTime,
    string title,
    string name
);
```

- `claimHash` and `registrant` are INDEXED (filterable topics).
- `blockTime`, `title`, `name` are DATA.
- The log's `topic[0]` is `keccak256("Registered(bytes32,address,uint256,string,string)")`
  = `0xd2447c3a89a5ee056ff41d62d513b054faa56c17b9074ead1e0b964a43dcd1e9`.

The indexed `claimHash` topic is the envelope `claimHash` with the `sha256:` prefix stripped,
encoded as a `bytes32` (`0x` + 64 lowercase hex). The indexed `registrant` topic is the
20-byte address left-padded to 32 bytes (the low 20 bytes are the address).

#### 3.3. Gasless registration (EIP-712)

The user signs an EIP-712 message; any relayer may submit it and pay the gas; the contract
records the address RECOVERED from the signature as `registrant` (never `msg.sender`).

EIP-712 domain:

```jsonc
{
  "name": "ScreenplayLedger",
  "version": "1",
  "chainId": <actual chain id>,     // 1 for mainnet; never hard-coded into the digest helper
  "verifyingContract": "0x<contract address>"
}
```

`REGISTER_TYPEHASH` is the `keccak256` of the exact struct type string (field order and types
are part of the typehash and locked):

```
Register(bytes32 claimHash,string title,string name,address registrant,uint256 nonce)
```

`REGISTER_TYPEHASH`
= `keccak256("Register(bytes32 claimHash,string title,string name,address registrant,uint256 nonce)")`
= `0x906391fe7c2de371bd901d51d6f0e0075e07208ff18c5198838bd34ffd9477a5`.

The consent preview shown to a user before any mainnet write MUST render EXACTLY the fields
that are signed — `{claimHash, title, name, registrant, nonce, chainId, verifyingContract}` —
so a relayer/UI mismatch cannot defeat the consent ceremony.

#### 3.4. Caps

The contract enforces a hard byte-LENGTH cap only — `bytes(title).length <= 128` and
`bytes(name).length <= 64`. There is NO on-chain UTF-8 or control-character validation (an
expensive gas trap, and pointless since the strings only reach logs, never EVM state logic).
UTF-8 / control-character sanitization is a relayer + display-layer concern. The cap is a
content-neutral capacity limit (anti-abuse), not a content filter.

#### 3.5. Strict nonce; no `claimHash` uniqueness

`registerWithSig` requires `nonce == nonces[registrant]` and increments on success, so an
intercepted signature can never be replayed. There is NO uniqueness check on `claimHash`:
duplicates are allowed because Bitcoin OTS is the sole priority source, so on-chain front-
running proves and blocks nothing.

### 4. Off-chain verification rule (topics-only)

An ETH-aware verifier reads the `Registered` log via `eth_getLogs` and compares its indexed
topics + transaction coordinates against the proof:

1. Independently recompute the envelope `claimHash` (Section 02 §4.2 rule 1) and use THAT for
   the topic filter and all comparisons — never trust `proof.claimHash` alone.
2. Filter by the contract address and the indexed topics
   (`[topic0, claimHashTopic, registrantTopic]`).
3. Select the EXACT log by `txHash` AND `logIndex` — never "first match" (no on-chain
   uniqueness means many logs may share a `claimHash` topic).
4. Confirm the decoded indexed `claimHash` topic equals the recomputed `claimHash`, the
   decoded indexed `registrant` topic equals `proof.registrant` (case-insensitive, padding
   stripped), and the proof's `contract` / `chainId` / coordinates match.
5. Require finality — N confirmations; a receipt is not final.

**EIP-712 signature recovery is performed ONLY by the on-chain contract, NEVER re-run
off-chain.** The off-chain verifier reads indexed topics; it never fetches calldata and never
recovers a signature. Recovery off-chain would re-introduce signature-malleability and
encoding-mismatch surfaces that the on-chain `ecrecover` already settled.

An Ethereum-anchor result is informational ("also anchored on Ethereum mainnet at block N by
`registrant`"). It is NEVER a priority source and NEVER flips a Bitcoin verdict.

### 5. Contract status — reserved (Tier-2, coming soon)

The `ScreenplayLedger` contract is **immutable and ownerless** by design: non-upgradeable, no
proxy / `delegatecall`-to-mutable, no privileged callable function (no owner / pause / mint /
fee / withdraw / `baseURI` / upgrade / `selfdestruct`). Immutability is the guarantee.

The interface above is FROZEN; the deployed implementation is DEFERRED. Because the contract is
immutable, a bug is NOT fixed by "deploy v2 in place." The honest recovery policy is that the
v1 ledger may be **ABANDONED, not patched**: new registrations move to a new address and the
off-chain index points forward. Integrators MUST NOT hardcode permanence assumptions about any
single deployed address. A separate, optional product NFT (transferable ERC-721; confers no
rights; not an authorship proof) MAY reference a ledger entry by `claimHash` and is likewise
out of the commitment surface.

On-chain plaintext is content-neutral and permanent: the exposed `title`/`name` are user-chosen
labels (name blank by default) over a pseudonymous key, accepted as an anti-censorship surface
that cannot be deleted. A pen name can still be correlated/deanonymized over time. The free
Bitcoin-only path remains the default and needs no wallet, gas, or account.

### 6. `batch` — reserved / unverified in v1

The optional `batch` field is RESERVED in v1. No batch event, method, or inclusion-path format
is defined here. Batching is a cheaper hash-only RECEIPT mode (the proof would carry a
`batchId` + Merkle root + inclusion path) and is NOT self-describing: a batched anchor emits no
per-claim `Registered` event, so `eth_getLogs(claimHash)` finds nothing and `title`/`name` are
never on-chain. A v1 off-chain verifier therefore makes NO Merkle-path claim for a batched
anchor and reports it as UNVERIFIED. The self-describing tier MUST be UNBATCHED. A future spec
section defines the batch receipt mode under a new named, domain-tagged Merkle profile with its
own wire schema and conformance vectors.

### 7. Versioning rule

The evidence profile URN (`urn:screenplay-registration-evidence-ethereum-anchor:v1`), the
`Registered` event ABI, the EIP-712 domain `name`/`version`, and `REGISTER_TYPEHASH` are LOCKED
at v1. Any change to the event signature, the struct type string, the domain name/version, or
the byte caps requires a new profile URN under a new schema — old proofs continue to verify
under v1 rules.

---

**End of Section 09.**

References:
- [EIP-712 — Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [EIP-55 — Mixed-case checksum address encoding](https://eips.ethereum.org/EIPS/eip-55)
- Section 02 — Envelope (`urn:screenplay-registration-envelope:v1`)
- Section 10 — Registry index (when shipped)
