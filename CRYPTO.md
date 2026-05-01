# **Paranoid (NOID) — Cryptographic Primitive Specification (Locked)**

## **Goal**

Design a **proof-native, post-quantum, signatureless PoW blockchain** based on transparent STARKs (no trusted setup), with:

* Non-interactive transactions (Fiat–Shamir only)
* Deterministic proofs (no external randomness)
* Fast sync for light clients
* Recursion-ready primitives and formats

---

# **0. Design Principles**

* No elliptic curves, no pairings, no trusted setup
* All authorization = STARK proof validity
* Deterministic cryptography (no entropy sources outside FS)
* Strict domain separation for every primitive
* Canonical encoding everywhere (no ambiguity tolerated)
* Recursion compatibility is preserved by design

---

# **1. Field**

* Primary field: **GF(2^128)** (binary tower, `Block128`)

### Rationale

* Native to additive NTT and Poseidon2b
* SIMD-efficient
* No dependency on large integer modular arithmetic

### Constraint Note

Range constraints are non-native in binary fields. If needed, introduce auxiliary lookup/range systems — without changing the hash field.

---

# **2. Permutation**

* Primitive: Poseidon2b
* State width: `t = 4`, rate = 2, capacity = 2
* S-box: x⁷
* Rounds: 8 full + 58 partial

### Security Targets

| Property                      | Security               |
| ----------------------------- | ---------------------- |
| Collision (classical)         | ~2¹²⁸                  |
| Preimage (classical)          | ~2¹²⁸ (capacity bound) |
| Preimage (quantum)            | ~2¹²⁸                  |
| Collision (quantum practical) | ~2¹²⁸                  |

---

# **3. Domain Separation**

## 3.1 Method

Each sponge-mode construction initializes capacity words:

```text
state[2] = (LABEL << 64)    // high 64 bits of the 128-bit capacity word
state[3] = LABEL            // low 64 bits of the next 128-bit capacity word
```

`LABEL` is the 8-byte ASCII constant interpreted as a big-endian `u64`.

## 3.2 Rule

* Every primitive MUST use a unique domain label (see §11)
* No reuse across constructions
* No implicit domains

---

# **4. Canonical Encoding (MANDATORY)**

All inputs to hash functions MUST follow:

* Fixed-width encoding
* Little-endian for integers
* No variable-length ambiguity
* No implicit padding

### Block128 encoding

* 16 bytes, little-endian

### Digest encoding (locked)

* 32 bytes interpreted as two `Block128` words:
  * `bytes[0..16]`  → `Block128[0]` (high half of the digest)
  * `bytes[16..32]` → `Block128[1]` (low half of the digest)
* This rule is identical in every construction that accepts a digest as input.

### ZERO_DIGEST (locked)

```text
ZERO_DIGEST = [0u8; 32]
```

Identical across all contexts (sparse-tree padding, tx-body leaf padding, etc.).

### Leaf canonicalization (locked)

* For tx-body Merkle input, leaves are **already** canonical 32-byte values.
* **No implicit per-leaf hashing.**
* Scalar leaves (`fee`) are canonicalized as `le_bytes_u128(scalar) || [0u8; 16]`.

---

# **5. Core Primitives**

---

## **5.1 `compress(a, b) → 32 bytes`** — TWO-PERMUTATION SPONGE

### Use

Merkle inner nodes for every Poseidon2b-backed Merkle tree (state tree, nullifier tree, tx-body tree). FRI Merkle trees use Blake3 (§9).

### Construction (locked)

```text
// a, b : [u8; 32]   (digests, encoded per §4)
// COMPRESS_hi, COMPRESS_lo : capacity IV words derived from LABEL = "COMPRESS"

state = [a0, a1, COMPRESS_hi, COMPRESS_lo]
permute(state)

state[0] ^= b0
state[1] ^= b1
permute(state)

return state[0] || state[1]
```

### Notes

* Two permutations per inner node (mandatory).
* Domain is carried in the capacity IV before any data is absorbed — no ad-hoc mixing.
* Uniform security model across all primitives (capacity-IV sponge everywhere).

---

## **5.2 `hash_leaf(fields[]) → 32 bytes`**

* Sponge, IV = `LEAF____`
* Absorb all fields
* Standard padding
* Output: 32 bytes

---

## **5.3 `hash_commitment(...) → 32 bytes`**

```text
H_COMMIT(value, owner_hi, owner_lo, blinding, asset_tag)
```

* IV = `COMMIT__`
* `value` absorbed as `Block128::from(value_u128)`
* `owner` absorbed as two halves (`owner_hi`, `owner_lo`) — preserves full 256-bit binding
* `blinding` : 128-bit random
* `asset_tag` : `Block128::ZERO` for native asset; reserved for multi-asset

### Properties

* Binding: collision resistance
* Hiding: via blinding randomness

---

## **5.4 `hash_nullifier(...) → 32 bytes`** — VERSIONED

```text
NULLIFIER_VERSION = Block128::from(1u128)

H_NULL(
  spend_secret_hi,
  spend_secret_lo,
  commitment_hi,
  commitment_lo,
  NULLIFIER_VERSION
)
```

* IV = `NULLIFIE`
* Version MUST be part of the hash input.
* Future scheme rotation: increment (2, 3, …). Cross-version collisions impossible.

### Properties

* Unique per spend
* Unlinkable without secret

---

## **5.5 `hash_auth_tag(spend_secret, tx_body_hash) → 32 bytes`**

```text
H_AUTH(spend_secret_hi, spend_secret_lo, tx_body_hi, tx_body_lo)
```

* IV = `AUTHTAG_`
* Binds the STARK proof to this tx body.

---

## **5.6 `derive_address(...)` — STEALTH-ADDRESS MODEL**

The salt model is **payer-chosen, public salt**, carried in the transaction output.

### Address

```text
address = H_ADDR(master_secret_hi, master_secret_lo, salt_hi, salt_lo)
```

* IV = `ADDRESS_`
* `salt` : 128-bit public value, chosen by the payer, included in the output.

### Spend secret

```text
spend_secret = H_ADDRSPND(master_secret_hi, master_secret_lo, salt_hi, salt_lo)
```

* IV = `ADDRSPND`
* The spend secret is recoverable by the recipient from `(master_secret, salt)`; `salt` is part of the output, `master_secret` never leaves the wallet.

### Properties

* Unlinkability across payments to the same logical wallet (salt differs per payment).
* No deterministic address clustering.
* Addresses are per-output; no on-chain "account".

### Notes

* `master_secret` is a private 256-bit value (two `Block128` halves), stored encrypted at rest in the wallet.
* `salt` encoded as 128 bits. Protocol convention: if extended to 256 bits later, both halves feed both IVs.

---

## **5.7 `hash_tx_body(...)` — MERKLE + FINAL WRAP**

### Step 1 — Build Merkle tree over canonical 32-byte leaves

Leaves (in order):

1. `prev_state_root`                   (32 bytes, passthrough)
2. `fee_leaf = le_bytes_u128(fee) || [0u8; 16]`
3. input commitments                   (32 bytes each, passthrough)
4. output commitments                  (32 bytes each, passthrough)

Pad with `ZERO_DIGEST` to the next power of two (minimum 2).

### Step 2 — Reduce with `compress` (§5.1)

```text
root = MerkleReduce(compress, leaves)
```

### Step 3 — Final wrap (single permutation, locked)

```text
state = [root_hi, root_lo, TXBODY_hi, TXBODY_lo]
permute(state)
tx_body_hash = state[0] || state[1]
```

* IV = `TXBODY__`
* Single permutation (no re-absorb, no padding — input is exactly one rate block).
* Provides explicit TXBODY domain separation on top of the COMPRESS-domain Merkle tree.

---

## **5.8 Fiat–Shamir**

* Sponge channel, IV = `FSCHALNG`
* Deterministic transcript; challenges squeezed after padding flush.

---

## **5.9 `derive_view_key(master_secret) → 32 bytes`** — OBSERVABILITY

```text
view_key = H_VIEW(master_secret_hi, master_secret_lo)
```

* IV = `VIEWKEY_`
* Wallet-wide (one view key per wallet, not per address).
* **Strictly separated from `ADDRSPND`**: sharing `view_key` never leaks `spend_secret` — the two use disjoint IVs and the sponge is preimage-resistant.

### Capability of a view-key holder

* Can detect all incoming payments to the wallet by recomputing `hash_scan_tag` (§5.10) for each output in a block.
* Cannot spend. Cannot derive `spend_secret`. Cannot create valid `auth_tag`.
* Revoking view access requires rotating the master secret (i.e., a new wallet).

### Use cases

* Exchanges / custodians tracking deposits.
* Block explorers that a user voluntarily grants read access to.
* Light wallets syncing without downloading the full note set.

---

## **5.10 `hash_scan_tag(view_key, salt) → 32 bytes`** — OBSERVABILITY

Every on-chain output carries `(commitment, salt, scan_tag)` where

```text
scan_tag = H_TAG(view_key_hi, view_key_lo, salt, 0)
```

* IV = `SCANTAG_`
* `salt` is the same 128-bit public salt used in §5.6 address derivation.
* The trailing `0` field pads the salt absorb to a rate boundary and matches `derive_address` / `derive_spend_secret` in shape.

### Scanning algorithm (pseudocode)

```text
for each output (commitment, salt, scan_tag) in the new block:
    expected = hash_scan_tag(my_view_key, salt)
    if constant_time_eq(expected, scan_tag):
        this output is mine
        spend_secret = derive_spend_secret(master_secret, salt)   # spender only
```

### Cost

* **One Poseidon2b sponge per output per scanner**, no state, no secrets beyond the view key. ~microseconds per output at current benchmarks.

### Privacy

* A non-holder of `view_key` sees `scan_tag` as a uniformly random 32-byte string — the sponge is indistinguishable without the key.
* Scan tags do not link a recipient across outputs (same view key, different salts → different tags).

---

# **6. Merkle Trees**

* Binary
* Inner node: `compress` (§5.1)
* Leaves: `hash_leaf` (§5.2) for field-element payloads; passthrough 32-byte digests where the leaf is already a digest (tx body)

### Sparse trees (locked)

* Fixed depth (per tree, see §6.1)
* Precomputed zero subtree roots:

```text
Z[0] = hash_leaf(&[])
Z[i] = compress(Z[i-1], Z[i-1])
```

### 6.1 Depths

| Tree                              | Depth |
| --------------------------------- | ----- |
| State tree (coin commitments)     | 32    |
| Nullifier tree                    | 32    |
| Note tree (wallet-local, off-chain) | grows |

---

# **7. Transaction Model**

### Structure

* Max: 4 inputs / 8 outputs
* Dummy slots allowed (zero commitment; `valid=false` witness bit; contributes 0 to balance; no nullifier insert).

### Output schema (observable, per §5.10)

Each on-chain output is the triple:

```text
output = (
  commitment : 32 bytes,   // §5.3, binds value/owner/blinding/asset_tag
  salt       : 16 bytes,   // §5.6, public, payer-chosen
  scan_tag   : 32 bytes    // §5.10, computed from recipient's view_key + salt
)
```

`salt` and `scan_tag` are covered by `tx_body_hash` — see §7.1.

### 7.1 Tx-body coverage of salt + scan_tag (binding extension)

To prevent a relay from rewriting `(salt, scan_tag)` while leaving `commitment` untouched, the tx-body Merkle leaves for outputs are the 2-to-1 compression of `(commitment, compress(salt_leaf, scan_tag))`, where `salt_leaf = le_bytes(salt) || [0u8; 16]`. Inputs remain passthrough commitments.

Concretely, per output the leaf absorbed into the tx-body Merkle is:

```text
output_leaf = compress(commitment, compress(salt_leaf, scan_tag))
```

This keeps the tx-body Merkle shape (32-byte leaves reduced by `compress`) while binding the full observable output tuple. `hash_tx_body`'s implementation (`noid_poseidon2b::primitives::hash_tx_body`) currently takes only commitments; the signature extension lands in a follow-up alongside the `noid_tx` crate so this spec bump is not a breaking change to the present library.

### Constraints

* Balance: `Σ inputs = Σ outputs + fee`
* Range: 64-bit values enforced in-circuit (bit decomposition)

### Public Inputs

1. `prev_state_root`
2. `new_state_root`
3. `nullifier_root`
4. `tx_body_hash`
5. `fee`

---

# **8. Proof-of-Work**

## **8.1 Block Hash**

```text
H_BLOCK(
  prev_block_hash,
  state_root,
  tx_root,
  timestamp,
  miner_address,
  nonce,
  proof_transcript_hash
)
```

IV = `BLOCKHDR`.

## **8.2 Mining Rules**

* Proof MUST be deterministic from seed
* Only entropy source: `nonce`
* Allowed variation: transaction ordering, batch composition
* Forbidden: re-randomizing the proof to re-roll the block hash

## **8.3 Useful-Work Property**

Every mining attempt produces a valid state-transition STARK; there is no wasted work.

---

# **9. FRI Parameters**

* Rate: 4
* Queries: 96
* Soundness: ~192-bit conservative bound

### Hash Tiering

| Layer                              | Hash       |
| ---------------------------------- | ---------- |
| FRI Merkle (native verifier)       | Blake3     |
| UTXO primitives / transcript       | Poseidon2b |

---

# **9a. Binius-style Packing (DA / bandwidth)**

Witnesses that are semantically defined over a subfield of GF(2^128) are
committed in their **packed** representation rather than via one Block128 per
cell. Two packings are standardized:

| Witness domain | Cells per Block128 | Payload shrink |
| -------------- | ------------------ | --------------- |
| GF(2)     (bit)     | 128              | 128x          |
| GF(2^8)   (byte)    | 16               | 16x           |

The packing layout is canonical:

* Bit `i` of a bit-witness sits at bit `i mod 128` of packed word `i / 128`.
* Byte `i` of a byte-witness sits at byte `i mod 16` of packed word `i / 16`.

Commitments are produced by the unchanged FRI PCS on the packed vector, so
soundness is inherited verbatim. The DA block carries the packed Block128
words only; full nodes reconstruct the expanded witness locally before
verification.

### Scope bound (today)

* `noid_binius::PackedCommit` supports raw, byte-packed, and bit-packed
  commitments and openings *of the packed MLE*.
* Reducing a bit- / byte-level claim "bit_mle(ẑ, r_z) = v" to a packed MLE
  opening uses the Binius ring-switching sumcheck. That protocol is **not**
  shipped in this revision — it is deferred until its soundness argument and
  transcript layout are fully pinned. AIRs that need bit-level evaluation
  claims currently enforce bit-decomposition in-circuit on the packed MLE.

### Non-breaking

Existing commitments (Block128-per-cell) remain valid; `commit_raw` is
identical to the previous FRI commit.

---

# **10. Recursion Readiness**

* Deterministic verifier
* Fixed public-input layout
* No dependency on non-recursive assumptions
* Future `cumulative_block_proof` is a STARK over "I know prev cumulative + block proof that verify"

---

# **11. Domain Tags**

All tags are exactly 8 ASCII bytes.

| Label      | Purpose                           |
| ---------- | --------------------------------- |
| `LEAF____` | leaf hashing                      |
| `COMMIT__` | output / coin commitments         |
| `NULLIFIE` | nullifiers                        |
| `AUTHTAG_` | auth binding                      |
| `ADDRESS_` | stealth address derivation        |
| `ADDRSPND` | spend-secret derivation           |
| `TXBODY__` | tx-body final wrap                |
| `BLOCKHDR` | block header hash                 |
| `FSCHALNG` | Fiat-Shamir channel               |
| `COMPRESS` | Merkle inner compression          |
| `VIEWKEY_` | wallet view-key derivation        |
| `SCANTAG_` | per-output public scan tag        |

---

# **12. Non-Goals**

* No signatures (ever)
* No trusted setup
* No pairing-based systems
* No SHA-family for binding logic

---

# **13. Observability Scope (added)**

The view-key / scan-tag pair lives in CRYPTO.md because it defines on-chain output shape. Other observability concerns — finality rule, reorg limit, RPC surface, DoS model — are **deliberately not pinned here**. They depend on empirical block-time data and adversarial benchmarks that don't yet exist, and premature numbers in the crypto spec would either be wrong or foreclose changes. Those specs track separately as `CONSENSUS.md` and `NETWORK.md` once testnet produces the data.

What this spec guarantees for integrators:

1. **Output format is forward-stable.** `(commitment, salt, scan_tag)` is what a block explorer or exchange parses today and the same tuple ships in every future minor version.
2. **View-key scanning is universal.** No version negotiation needed — a view key issued on day 1 keeps working.
3. **View-key holders can never spend.** `VIEWKEY_` and `ADDRSPND` are disjoint IVs over the sponge; there is no "upgrade path" from a view key to a spend key.

---

# **Final Decisions (locked)**

| Topic                | Decision                                          |
| -------------------- | ------------------------------------------------- |
| `compress`           | Two-permutation sponge, IV = `COMPRESS`           |
| `hash_nullifier`     | Version = `1` mandatory input                     |
| `derive_address`     | Stealth-address: `(master_secret, salt)`, public salt |
| `hash_tx_body`       | Merkle(compress) + final wrap permutation, IV = `TXBODY__` |
| View key             | `H_VIEW(master_secret)`, IV = `VIEWKEY_`, non-spending |
| Scan tag             | `H_TAG(view_key, salt)`, IV = `SCANTAG_`, on every output |
| Output schema        | `(commitment, salt, scan_tag)` — locked            |
| Digest encoding      | `bytes[0..16] → Block128[0]`, `bytes[16..32] → Block128[1]` |
| `ZERO_DIGEST`        | `[0u8; 32]` everywhere                            |

This spec is suitable as a **production cryptographic specification base** for the Paranoid blockchain.
