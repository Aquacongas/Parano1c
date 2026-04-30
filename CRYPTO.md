# Paranoid (NOID) — Cryptographic Primitive Specification (v0.1)

Status: **draft**, pinned before commitment-format-sensitive code (Merkle compression, UTXO primitives, PoW) is written.
Scope: hashing, commitments, nullifiers, addresses, transaction binding, PoW, recursion-readiness.
Non-scope (v1): recursive STARKs / IVC (design for, do not build).

---

## 0. Design goals, restated

- Paranoid, post-quantum ready.
- **No elliptic curves, no pairings, no trusted setup.**
- **Signatureless.** The STARK proof is the only spend authorization.
- **Non-interactive transactions** (MUST). All randomness from Fiat-Shamir.
- Fast and lightweight per block. Proof-native PoW.
- Recursion-ready: primitive formats and public-input layouts must not foreclose future IVC.

## 1. Field

- **Primary field**: `GF(2^128)` binary tower (`Block128`).
- **Rationale**: native to our Poseidon2b + FRI stack, hash/NTT are cheap, no CLMUL dependency outside what we already have.
- **Open issue (non-blocking v1)**: integer range / balance constraints arithmetize less naturally in GF(2^128) than in a prime field. If those costs become painful inside the circuit we will introduce a companion small-prime sub-structure for range tables only. We will NOT change the hash field.

## 2. Permutation

- **Primitive**: Poseidon2b, state width `t = 4`, rate `r = 2`, capacity `c = 2`.
- **Rounds**: 8 full + 58 partial, x^7 S-box. (As implemented.)
- **Target security** (256-bit output, 256-bit capacity):
  - Classical collision: ~2^128 (birthday / sponge c/2 bound).
  - Classical preimage: ~2^256 (capped by sponge c/2 = 2^128 in the generic model).
  - Quantum preimage (Grover): ~2^128.
  - Quantum collision: ~2^85 under the BHT model (requires exponential qRAM; widely considered unrealistic), and ~2^128 under parallel-Rho which remains the best practical quantum collision attack. We therefore target ~85–128-bit PQ collision resistance depending on the adversary model.

## 3. Domain separation

- **Placement**: capacity-IV style. Each construction initializes `state[2]`, `state[3]` with a domain-tag constant derived from a 64-bit ASCII label. `state[0]`, `state[1]` hold the rate.
- **Tag derivation**: `tag_i = Block128::from(LABEL_u64 << 64 | i)` for `i ∈ {0,1}` producing the two capacity words. Labels are distinct 8-byte ASCII strings — see §11.
- **Never** reuse the same permutation with the same IV for two different constructions.

## 4. Primitives

Every primitive below is built from the same Poseidon2b permutation, distinguished only by IV and input layout.

### 4.1 `compress(a, b) -> [u8; 32]`

- **Use**: inner Merkle nodes. The hot path — called ~`2N` times per tree of `N` leaves.
- **Construction (truncated fixed-width permutation)**:
  ```
  state = [a0, a1, b0, b1]       // a, b each 32 bytes = 2 Block128 words
  permute_mut(&mut state)
  return (state[0] || state[1])
  ```
- **No padding, no IV.** Safe because the input width is fixed (128 bytes → 64 bytes). Inner-node domain is distinct from every other construction because every other construction either uses sponge-mode (padding marker) or a capacity IV, so no collision across uses.
- **Cost**: 1 permutation per call.

### 4.2 `hash_leaf(fields: &[Block128]) -> [u8; 32]`

- **Use**: leaves of the state / note / nullifier Merkle trees.
- **Construction**: sponge with capacity IV = `LEAF`. Absorb all field elements, standard pad, squeeze 32 bytes.
- **Cost**: `ceil(len/2) + 1` permutations. Called once per leaf, not hot.

### 4.3 `hash_commitment(value, owner, blinding, asset_tag) -> [u8; 32]`

- **Use**: coin / output commitment. Same primitive for both.
- **Input**: 4 `Block128` (value as LE-128 integer; owner as 128-bit address; blinding as 128-bit random; asset_tag = `Block128::ZERO` for native asset in v1, reserved for multi-asset).
- **Construction**: sponge with IV = `COMMIT__`. Absorb the 4 fields, pad, squeeze 32 bytes.
- **Binding**: hash-binding (hiding under preimage-resistance, binding under collision-resistance; blinding is the randomness).

### 4.4 `hash_nullifier(spend_secret, coin_commitment) -> [u8; 32]`

- **Use**: spend nullifier. Revealed on spend; uniqueness is checked against the nullifier-set Merkle root.
- **Input**: 2 `Block128` from `spend_secret` + 2 `Block128` from `coin_commitment` digest → 4 fields.
- **Construction**: sponge with IV = `NULLIFIE`. Absorb 4 fields, pad, squeeze 32 bytes.
- **Security**: un-linkability = preimage-resistance of the hash over the secret. Uniqueness = collision-resistance.

### 4.5 `hash_auth_tag(spend_secret, tx_body_hash) -> [u8; 32]`

- **Use**: binds the STARK proof to this specific tx body; prevents replay with different outputs.
- **Input**: `spend_secret` (2 fields) + `tx_body_hash` (2 fields) → 4 fields.
- **Construction**: sponge with IV = `AUTHTAG_`.
- **Public input** of the STARK includes the auth tag; the circuit verifies it in-circuit.

### 4.6 `derive_address(master_secret, account_index) -> [u8; 32]`

- **Use**: address = `H_ADDRESS(master_secret, account_index)`. Flat derivation, no hierarchy in v1.
- **Input**: `master_secret` (2 fields) + `account_index` (1 field, little-endian u128) → 3 fields.
- **Construction**: sponge with IV = `ADDRESS_`.
- **Spend key**: per address, the spend secret is `H_ADDRESS_SPEND(master_secret, account_index)` with IV = `ADDRSPND`. The address is public; the spend secret is private and never leaves the wallet.

### 4.7 `hash_tx_body(prev_state_root, inputs, outputs, fee) -> [u8; 32]`

- **Use**: canonical tx identifier; input to `hash_auth_tag`; hashed into the Fiat-Shamir transcript.
- **Construction**: binary Merkle tree over 32-byte canonical leaf encodings, reduced by [`compress`]. No per-leaf sponge.
- **Leaf encoding (all 32 bytes, little-endian)**:
  1. `prev_state_root` — passthrough (already 32 bytes).
  2. `fee_leaf = le_bytes_u128(fee) || [0u8; 16]`.
  3. Each `input_commitment` — passthrough.
  4. Each `output_commitment` — passthrough.
- **Padding**: pad the leaf list to the next power of two (min 2) with `ZERO_DIGEST = [0u8; 32]`.
- **Reduction**: while `len > 1`, `next[i] = compress(level[2i], level[2i+1])`.
- **Rationale for no per-leaf hash**: every payload is already a 256-bit cryptographic digest or a canonically encoded scalar; an extra sponge per leaf would add cost without adding domain separation (the fixed tree shape and the `COMPRESS_` IV already provide it).
- **Why Merkle and not a sponge**: lets the circuit expose a logarithmic auth path if the prover wants to commit to a specific input without revealing all siblings. Keeps the door open.
- **Breaking change vs. v0**: v0 hashed each leaf with `hash_leaf` before the Merkle reduction. v1 removes the leaf sponge. Digests are not compatible. KATs updated.

### 4.8 `fiat_shamir_challenge(transcript) -> Block128`

- **Use**: verifier challenges inside the STARK (sumcheck, FRI query positions).
- **Construction**: existing `Poseidon2bChannel` with IV = `FSCHALNG`. Already implemented; add the IV on the next breaking change.

## 5. Merkle tree

- **Arity**: binary.
- **Leaf rule**: `leaf = hash_leaf(field_elements_of_payload)`. Always.
- **Inner rule**: `parent = compress(left, right)`. Always. Position-independent; the path bit lives in the witness.
- **Empty subtree handling**: sparse, with precomputed zero-subtree roots `Z[0], Z[1], ..., Z[DEPTH]`, `Z[0] = hash_leaf(&[])`, `Z[k] = compress(Z[k-1], Z[k-1])`.
- **Depth**:
  - State tree (coin commitments): **32** (4B leaves).
  - Nullifier tree: **32**, sparse-by-construction.
  - Note tree (per-wallet, off-chain index): wallet-local, depth grows.
- **Rationale for uniform depth**: one circuit arithmetization for inclusion proofs.

## 6. Transaction format (v1)

- **Weight classes**: one circuit with max width **4 inputs / 8 outputs**, padded with dummy slots. Dummy = zeroed commitment + "valid = false" witness bit; circuit enforces that dummies contribute zero to balance and do not touch the nullifier set.
- **Fee**: explicit. Balance constraint: `Σ input_values = Σ output_values + fee`.
- **Range**: each `value` range-checked to 64 bits in-circuit via bit decomposition.
- **Public inputs of the STARK**:
  1. `prev_state_root`
  2. `new_state_root`
  3. `nullifier_insertions_root` (Merkle root of the nullifiers added by this tx)
  4. `tx_body_hash`
  5. `fee`
- **Auth tags** are in the witness (per-input), verified against the spend-secret + `tx_body_hash` inside the circuit.

## 7. Proof-of-Work

### 7.1 Block hash

`block_hash = H_BLOCKHDR(prev_block_hash, state_root, tx_batch_root, timestamp, miner_address, nonce, proof_transcript_hash)`

where `proof_transcript_hash` is the Fiat-Shamir seed of the aggregated block proof.

### 7.2 Mining

- Miners produce an aggregated STARK (`block_proof`) over the batch of transactions plus the state-transition correctness proof.
- **Nonce is the only grinding surface.** The Fiat-Shamir transcript is seeded with `(prev_block_hash, state_root, tx_batch_root, timestamp, miner_address, nonce)`. Given those, the proof is deterministic.
- Difficulty target applies to `block_hash`.
- A miner attempting to vary tx ordering or drop a tx changes `tx_batch_root` → new seed → fresh proof, which is a valid (but costlier) grind strategy. That is acceptable and is the honest "usable work" property.
- **Not acceptable**: re-proving the same logical block with fresh FRI randomness to re-roll the hash. This is prevented by making the proof deterministic given the seed (no external randomness source).

### 7.3 Useful-work property

Every mining attempt produces a verifiable STARK of a valid state transition. There is no wasted SHA grinding; the work done is exactly the work required to validate the block.

## 8. Recursion-readiness (not shipped in v1)

- Public-input layout of the block proof is fixed and self-describing.
- The verifier is deterministic and pure: given `(public_inputs, proof_bytes)` it returns accept/reject with no hidden state.
- No construction in this spec assumes a non-recursive verifier. A future `cumulative_block_proof_{N+1}` can be a STARK over the statement:
  > "I know `prev_cumulative_proof_N` and `block_proof_{N+1}` such that both verify against the declared public inputs."
- Binary-tower STARK recursion is an open research area; we expect to prototype it in a separate track once v1 is stable.

## 9. Storage (local node)

- **Primary store**: `sled` (pure-Rust, embedded, zero-config) for chain state, note set, nullifier bloom + exact table, wallet data.
- **Chain history**: append-only log; full node retains all blocks. Light node keeps only the latest block header + proof.
- **Wallet secrets**: master secret encrypted at rest (Argon2id KDF from user passphrase → XChaCha20-Poly1305).
- **Genesis**: CLI command `paranoid genesis --to <address> --count N --value V` writes `N` initial commitments into the state tree, publishes the genesis state root.

## 10. Open issues (tracked, not blocking compress v1)

- **In-circuit range check encoding** for 64-bit values over GF(2^128): bit-decomposition vs. lookup-based (if/when a lookup argument is added).
- **Recursion field choice**: if binary-tower recursion turns out too expensive to arithmetize, we may split: block proofs in GF(2^128), cumulative proofs in a prime field, with a translation layer. Deferred.
- **Difficulty adjustment algorithm**: not part of crypto spec; tracked separately in consensus spec.

## 11. Domain-tag registry

All tags are exactly 8 ASCII bytes. `state[2] = Block128::from((LABEL_u64 as u128) << 64)`, `state[3] = Block128::from(LABEL_u64 as u128)` (distinct high/low halves prevent a cheap cancellation).

| Label      | Use                                   |
|------------|---------------------------------------|
| `LEAF____` | leaf hashing of arbitrary field sets  |
| `COMMIT__` | coin / output commitment              |
| `NULLIFIE` | spend nullifier                       |
| `AUTHTAG_` | per-input authorization tag           |
| `ADDRESS_` | address derivation                    |
| `ADDRSPND` | spend secret derivation               |
| `TXBODY__` | tx body hashing                       |
| `BLOCKHDR` | block header hash / PoW target domain |
| `FSCHALNG` | Fiat-Shamir challenge channel         |

`compress` uses **no IV** and carries no label (fixed-width truncated permutation — see §4.1).

## 12. Non-changes (explicit)

- No Schnorr / EdDSA / Lamport / XMSS. Ever.
- No Groth16 / Plonk / anything pairing-based.
- No SHA-2/SHA-3 as primary hash. (Allowed outside cryptographic binding — e.g. logging, debug dumps.)
- No wallet format or auth flow that depends on an online service.
