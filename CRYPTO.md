# Paranoid (NOID) — Cryptographic Primitive Specification

**Scope.** This document pins the cryptographic primitives and
transcript contracts consumed by the Paranoid transparent UTXO STARK.
Protocol-level engineering stages (AIR composition, node runtime, IVC
fast-sync) live in `ROADMAP.md`; anything labelled here as "not
shipped" tracks against a specific ROADMAP stage.

**Source of truth alignment.** Paranoid is a **transparent** UTXO chain
(see ROADMAP header): no view keys, no scan tags, no nullifiers, no
blinding, no stealth addresses, no multi-asset. Ownership is enforced
by `H_ADDR(secret) == owner` inside `TxValidityAir`, replay by
`H_AUTH(secret, tx_body_hash) == tag`, and double-spend by linearly
zeroing the consumed slot in `state_delta` over a FRI-committed state.
Any primitive from earlier revisions that required shielded outputs has
been removed from this spec.

---

## 0. Design Principles

- Binary-tower field GF(2^128); no elliptic curves, no pairings, no
  trusted setup.
- Authorization = STARK validity (signatureless).
- Deterministic transcripts — Fiat–Shamir is the only randomness source.
- Strict domain separation via capacity-IV sponges (§3).
- Canonical encoding everywhere (§4).
- Recursion-ready: fixed public-input layout, deterministic verifier.

---

## 1. Field

Primary field: **GF(2^128)** (binary tower, `Block128` in `noid_core`).

- Native to additive NTT and Poseidon2b.
- SIMD-efficient (AVX2 PCLMULQDQ in `noid_core::packed`).
- Range constraints are non-native and must be discharged by an AIR
  gate (see ROADMAP §3b-2 `RangeGateAir`).

---

## 2. Permutation — Poseidon2b (locked)

- State width `t = 4`, rate `= 2`, capacity `= 2`.
- S-box `x^7`.
- Rounds: `8` full + `58` partial (+ `8` full) — matches
  `noid_poseidon2b/src/native/permutation.rs`.

Security targets (conservative):

| Property                      | Bound     |
| ----------------------------- | --------- |
| Collision (classical)         | ~2^128    |
| Preimage (classical)          | ~2^128    |
| Preimage (quantum)            | ~2^128    |
| Collision (quantum practical) | ~2^128    |

---

## 3. Domain Separation

### 3.1 Method

Every sponge-mode construction seeds its capacity words from an 8-byte
ASCII label (big-endian `u64`):

```text
state[2] = (LABEL_hi << 64)   // high half of first capacity word
state[3] = LABEL_lo           // low half
```

(Matches `noid_poseidon2b/src/native/domain.rs`.)

### 3.2 Rule

- Every primitive uses a unique domain label (§11).
- No reuse across constructions.
- No implicit domains.

---

## 4. Canonical Encoding (mandatory)

- Integers: fixed-width little-endian.
- No variable-length inputs.
- No implicit padding.

### Block128 encoding

16 bytes, little-endian.

### Digest encoding (locked)

32 bytes interpreted as two `Block128` words:

```text
bytes[0..16]  -> Block128[0]   // high half of digest
bytes[16..32] -> Block128[1]   // low half
```

Identical in every construction that accepts a digest as input.

### ZERO_DIGEST

```text
ZERO_DIGEST = [0u8; 32]
```

Identical across all contexts (padding, passthrough, default leaves).

### Leaf canonicalization

- Tx-body Merkle leaves are already canonical 32-byte values — no
  implicit per-leaf hashing.
- Scalar leaves (`fee`) are canonicalized as
  `le_bytes_u128(scalar) || [0u8; 16]`.

---

## 5. Core Primitives

### 5.1 `compress(a, b) -> 32 bytes` — two-permutation sponge

**Use.** Inner nodes of every Poseidon2b-backed Merkle tree. FRI Merkle
trees use Blake3 (§9).

```text
// a, b : [u8; 32]  encoded per §4
// COMPRESS_hi, COMPRESS_lo derived from LABEL = "COMPRESS"

state = [a0, a1, COMPRESS_hi, COMPRESS_lo]
permute(state)

state[0] ^= b0
state[1] ^= b1
permute(state)

return state[0] || state[1]
```

(Matches `noid_poseidon2b/src/native/compression.rs`.)

### 5.2 `hash_leaf(fields[]) -> 32 bytes`

- Sponge, IV = `LEAF____`.
- Absorb all fields with standard sponge padding.
- Output: 32 bytes.

### 5.3 `H_ADDR(secret_hi, secret_lo) -> 32 bytes`

- IV = `ADDRESS_`.
- Binds an output to an owner. `owner == H_ADDR(secret)` is enforced
  inside `TxValidityAir` by the Stage 3c `HAddrAir` gate.
- No salt, no stealth derivation: Paranoid is transparent.

### 5.4 `H_AUTH(secret_hi, secret_lo, tx_body_hi, tx_body_lo) -> 32 bytes`

- IV = `AUTHTAG_`.
- Binds the STARK proof to this `tx_body_hash`, preventing proof
  replay against a different tx body.

### 5.5 `H_LEAF(value, owner_hi, owner_lo) -> 32 bytes` — UTXO leaf

- IV = `LEAF____` (sponge layout per §5.2).
- `value` absorbed as `Block128::from(value_u128)`.
- `owner` absorbed as two halves.
- The resulting 32-byte digest is the canonical "UTXO leaf" that gets
  committed to the FRI-state (§7).

### 5.6 `hash_tx_body(body) -> TxBodyHash` — fixed-depth Merkle + wrap

Depth **4**, 16 leaves (chain constant `TXBODY_DEPTH = 4`). Leaf order:

1. `prev_state_root`                     (32 bytes, passthrough)
2. `new_state_root`                      (32 bytes, passthrough)
3. `fee_leaf = le_bytes_u128(fee) || [0u8; 16]`
4. `input_commitment[0..MAX_INPUTS=4]`   (32 bytes each, passthrough)
5. `output_commitment[0..MAX_OUTPUTS=8]` (32 bytes each, passthrough)
6. Pad to 16 leaves with `ZERO_DIGEST`.

Reduce with `compress` (§5.1):

```text
root = MerkleReduce(compress, leaves)
```

Final wrap (single permutation, one rate block, no padding):

```text
state = [root_hi, root_lo, TXBODY_hi, TXBODY_lo]
permute(state)
tx_body_hash = state[0] || state[1]
```

IV = `TXBODY__`. Provides explicit TXBODY domain separation on top of
the `COMPRESS`-domain Merkle tree.

### 5.7 Fiat–Shamir channel

- Sponge, IV = `FSCHALNG`.
- Deterministic transcript, challenges squeezed after padding flush.
- Absorb-before-squeeze discipline strictly enforced
  (`noid_fri::channel`, `noid_core::transcript`).

---

## 6. State commitment — FRI over UTXO slots

Paranoid does **not** use a sparse Merkle state tree. State is
committed as three `Block128` multilinear extensions over
`2^LOG_SLOTS = 2^24` UTXO slots (see `noid_chain::fri_state`).

### 6.1 Columns

| Column     | Contents                                                 |
| ---------- | -------------------------------------------------------- |
| `value`    | Slot value (`u64` embedded in `Block128`); `0` if empty. |
| `owner_hi` | High half of `owner` per §5.3.                           |
| `owner_lo` | Low half.                                                |

Each column is FRI-committed independently. A zeroed slot = dummy /
empty UTXO (consumed or unused).

### 6.2 Root binding

```text
state_root = blake3(
    "PARANOID/FRISTATE/v1"
    || le_bytes_u64(log_slots)
    || r_value
    || r_owner_hi
    || r_owner_lo
)
```

where `r_*` are the per-column FRI roots. Blake3 is the cross-column
wrapper only; column-internal Merkle commitments and query-phase leaves
use the FRI-layer hash (§9).

### 6.3 Delta application

A tx produces a `state_delta` — a sparse list of `(slot, new_value,
new_owner)` triples. Double-spend is prevented by the AIR enforcing
that every consumed input slot is linearly zeroed in `state_delta`
before being repopulated (if at all). The resulting
`new_state_root` is a public input of the proof (§7.2).

### 6.4 Tx-body Merkle (separate)

Fixed depth `TXBODY_DEPTH = 4` Poseidon2b tree, layout per §5.6.
`BLOCK_MAX_TXS = 1024` transactions per block; an outer block-level
tx-tree composition lives in `noid_chain::block`.

---

## 7. Transaction model

### 7.1 Structure

- `MAX_INPUTS = 4`, `MAX_OUTPUTS = 8`.
- Dummy slots allowed: zero commitment, `valid = false` witness bit,
  contributes `0` to balance, no state write.
- Single native asset; there is no `asset_tag` column.
- Outputs carry `(value, owner)` only — no salt, no scan tag, no
  blinding. The on-wire output commitment is `H_LEAF(value, owner)`.

### 7.2 Public inputs (locked)

```text
PublicInputs = (
    prev_state_root : [u8; 32],
    new_state_root  : [u8; 32],
    tx_body_hash    : [u8; 32],
    fee             : u64,
)
```

Exactly four fields. The STARK layer (`noid_stark::prove_air` /
`verify_air`) absorbs this tuple first into the FS channel before any
column roots.

### 7.3 Constraints enforced inside `TxValidityAir`

- **Ownership**: for every valid input, `H_ADDR(secret) == owner`.
- **Replay**: for every valid input, `H_AUTH(secret, tx_body_hash) ==
  auth_tag`.
- **Balance**: `Σ inputs.value == Σ outputs.value + fee` over `u64`
  with honest overflow handling (Stage 3b-3 `BalanceGateAir`).
- **Range**: every declared `value` lies in `[0, 2^64)` (Stage 3b-2
  `RangeGateAir`).
- **State transition**: each input slot opens against
  `prev_state_root`; `new_state_root` equals the opened-and-updated
  MLE root.
- **Tx-body binding**: the leaves committed by §5.6 match the
  per-input / per-output commitments surfaced in the witness.

---

## 8. Proof-of-Work — not in scope

PoW / mining / block-hash binding is **not pinned in this revision**.
ROADMAP Stages 3b → 5 cover the per-tx STARK, the node runtime, and
IVC fast-sync; a separate `CONSENSUS.md` will pin `H_BLOCK`, timestamp
policy, and nonce rules once empirical block-time data exists. Until
then, any mention of "block header hash" in this document is a
placeholder; do not rely on it for implementation.

---

## 9. FRI parameters (locked)

- Rate: `4` (`LOG_RATE = 2`).
- Queries: `96` (release default).
- Soundness: ~192-bit conservative bound.
- `TAU = 7`; `padded_log_len(log_rows) >= TAU + 1 = 8` is enforced by
  the STARK layer whenever any column declares `shifted_columns`.

### Hash tiering

| Layer                        | Hash       |
| ---------------------------- | ---------- |
| FRI Merkle (native verifier) | Blake3     |
| UTXO primitives / transcript | Poseidon2b |

### Binius-style packing — scope

`noid_binius::PackedCommit` ships raw, byte-packed, and bit-packed
commitments / openings of the *packed* MLE. Reducing a bit- or
byte-level AIR claim to a packed MLE opening via Binius ring-switching
sumcheck is **not shipped** (deferred until its transcript layout is
pinned). Today, AIRs that need bit-level reads enforce bit-
decomposition in-circuit on the packed MLE (ROADMAP §3b-2 is the
canonical example).

---

## 10. Recursion readiness

- Deterministic verifier.
- Fixed public-input layout (§7.2).
- No non-recursive assumptions.
- `noid_ivc::fold_block` composes `(cum_proof, block_proof) ->
  cum_proof'` using the same transcript contracts pinned here
  (ROADMAP Stage 5).

---

## 11. Domain Tags (locked)

All tags are exactly 8 ASCII bytes.

| Label      | Purpose                                        |
| ---------- | ---------------------------------------------- |
| `LEAF____` | leaf / UTXO-leaf hashing                       |
| `AUTHTAG_` | auth-tag binding                               |
| `ADDRESS_` | address derivation                             |
| `TXBODY__` | tx-body final wrap                             |
| `FSCHALNG` | Fiat–Shamir channel                            |
| `COMPRESS` | Merkle inner compression (Poseidon2b)          |
| `LADDERFS` | Ladder-FRI batched-open sub-channel (§12a)     |

Labels retired in this revision (removed outputs ⇒ removed domains):
`COMMIT__`, `NULLIFIE`, `ADDRSPND`, `VIEWKEY_`, `SCANTAG_`, `BLOCKHDR`.
Do not reintroduce these tags without a ROADMAP entry.

---

## 12. STARK / FRI transcript layout (pinned)

This section is the canonical contract between `noid_stark`,
`noid_fri`, and any future verifier reimplementation. All ordering
below is enforced by `noid_stark::prove_air` / `verify_air` and the
FS channel (§5.7).

### 12.0 Parent-channel ordering (`prove_air`)

1. Absorb `PublicInputs` in the fixed order of §7.2.
2. Absorb every column's FRI Merkle root in column-index order.
3. Run the zero-check sumcheck: per round, observe
   `[p(0), p(1), …, p(d+1)]` (where `d` is the max constraint degree,
   ROADMAP §3b-0), squeeze round challenge `r_i`. The final opening
   point is the **reversed** challenge vector `r ∈ F^{log_rows}`.
4. For each shifted column slot `(slot, col_id)`, open the base column
   through the Ladder-FRI sub-channel (§12a).
5. Open the `n_cols` base columns at `r` via the RLC-batched protocol
   (§12b).
6. Emit `StarkProof { zero_check_rounds, shift_partials, shift_proofs,
   base_openings, base_batched_proof }`.

The VSHIFT ladder separator (opening-point tag) is
`0xFFFF_0000_0000_0000 | slot`; the Ladder-FRI sub-channel separator is
`0xFFFE_0000_0000_0000 | slot` (§12a.4). These two tags **must**
remain distinct — see §12a rationale.

### 12a Ladder-FRI batched opening (shipped, Stage 3b-0.4)

Collapses the `n + 1`-point ladder (`n = log_len`) per shifted column
into a **single** FRI opening of the base column at a freshly sampled
random point `r'`, with a short product-sumcheck binding the batched
claim.

#### 12a.1 Inputs at this point in the transcript

- Parent channel has already absorbed PI, all column roots, and the
  zero-check sumcheck.
- VSHIFT ladder partials `v_k = C(P_k)` for `k = 0, …, n` are
  produced by the prover; `P_k` are deterministic from `r`.

#### 12a.2 Per shifted column `(slot, col_id)`

1. **Seed sub-channel.** Clone parent channel; absorb
   `LADDERFS_TAG = 0xFFFE_0000_0000_0000 | slot`, then `col_id` as
   `Block128`, then `v_0, …, v_n`.
2. **Squeeze batching scalar `γ`** (one field element).
3. **Target.** `T = Σ_{k=0}^{n} γ^k · v_k`; computed locally by both
   parties.
4. **Weight polynomial.**
   `W(x) = Σ_k γ^k · eq(P_k, x)` on `{0,1}^n`. Then
   `Σ_{x ∈ {0,1}^n} C(x) · W(x) = Σ_k γ^k · v_k = T`.
5. **Batched sumcheck.** Prove `Σ_x C(x)·W(x) = T` in `n` rounds,
   degree-2 per round (three evaluations at `X ∈ {0,1,2}`); verifier
   checks `p(0) + p(1) == claim`, folds `claim ← p(r'_i)`, LSB-first.
6. **Final.** The terminal claim equals `C(r') · W(r')`; `W(r')` is
   computable by both parties from `(γ, r, r')`. Prover opens `C(r')`
   with one FRI evaluation proof; verifier checks
   `C(r') · W(r') == terminal_claim`.

The zero-check terminal equation continues to use the ladder partials
`v_k` and the closed-form `C'(r) = Σ_k w_k(r) · v_k` — steps 5–6 only
attest that the `v_k` are *consistent with* the committed `C`.

#### 12a.3 Soundness

With `Δ_k = v_k - C(P_k)` and `p_Δ(γ) = Σ_k γ^k · Δ_k`:

- `Pr_γ[T = T*] ≤ n / |F| = n / 2^128` (Schwartz–Zippel).
- Degree-2 `n`-round sumcheck error ≤ `2n / |F|` (LFKN over GF(2^128)).
- Base FRI error inherited from §9.

Union bound: `ε_ladder ≤ 3n / |F| ≤ 48 / 2^128` — negligible.

#### 12a.4 Canonical sub-channel order

Per slot `(slot, col_id)`:

1. absorb `0xFFFE_0000_0000_0000 | slot`;
2. absorb `col_id as Block128`;
3. absorb `v_0, v_1, …, v_n`;
4. squeeze `γ`;
5. for `i = 0, …, n-1`: observe `[p(0), p(1), p(2)]`, squeeze `r'_i`;
6. observe the single `C(r')` FRI opening (internal FRI FS is handled
   by `noid_fri::prover::prove`).

The `0xFFFE_…` / `0xFFFF_…` split is mandatory: the old per-ladder-
point FRI openings remain reachable in historical proof blobs, and
tag reuse would risk replay-style FS collisions if a pre-3b-0.4 proof
were ever resubmitted through the new verifier.

#### 12a.5 Cost (`prod`, `log_len = 16`, `n_shifted = 5`)

| Metric                         | Before (3b-0.3) | After (3b-0.4) |
| ------------------------------ | --------------- | -------------- |
| FRI openings per shifted col   | `n + 1 = 17`    | `1`            |
| Extra sumcheck rounds per col  | 0               | `n = 16`, d=2  |
| Proof size (ladder block)      | ~ 11.2 MB       | ~ 0.6 MB       |
| Verifier ladder share          | ~ 78 %          | < 15 %         |

### 12b RLC-batched column opening (shipped, Stage 3b-0.5 / 0.5.1)

Collapses the `n_cols` independent base-column FRI openings at the
common zero-check point `r` into a single FRI opening of the random
linear combination of the columns. Commit cost is unchanged; only the
opening and verifier query-phase FRI work drops.

#### 12b.1 Transcript steps

1. **Per-column openings.** Prover sends `e_i = MLE_i(r)` for
   `i = 0, …, n_cols - 1`; both sides absorb them in column-index
   order.
2. **Squeeze `α`** (single field element); derive `λ_i = α^i`
   (Horner RLC). Horner is chosen over `n_cols` independent squeezes
   for FS economy and still gives `n_cols / |F|` soundness, which is
   negligible for `|F| = 2^128`, `n_cols ≤ 256`.
3. **Derive batched claim / codeword.**
   `e_batch = Σ_i λ_i · e_i` (both sides compute).
   `C_batch  = Σ_i λ_i · C_i`  (prover only, pointwise sum of RS-
   encoded codewords; every column uses the same NTT plan at `log_len`,
   so `C_batch` is a valid codeword of the same RS code).
4. **Open `C_batch` at `r`.** Run `noid_fri::prover::prove` against
   `C_batch` as MLE evals, `r` as the opening point, `e_batch` as the
   claim. There is **no** dedicated Merkle tree over `C_batch`: query-
   phase openings are answered out of the per-column Merkle trees, and
   the batched symbol pair is recomputed by the verifier (3b-0.5.1).
5. **Query phase.** For each FRI query index `q`:
   - For every column `i`, prover ships the symbol pair
     `(s_{i,0}, s_{i,1})` with its Merkle path against the column-`i`
     commitment (unchanged from 3b-0.4).
   - Verifier checks each path; then computes
     `(s_0^batch, s_1^batch) = (Σ_i λ_i · s_{i,0}, Σ_i λ_i · s_{i,1})`
     and feeds this pair into the existing FRI fold-consistency check.

Nothing else in the FRI-internal transcript changes (oracle commits,
folding sumcheck round polynomials, challenge ordering).

#### 12b.2 Soundness

- **Wrong batched claim.** If `δ_i = e_i - MLE_i(r)` is non-zero for
  some `i`, then `MLE_batch(r) - e_batch` is a non-zero degree-
  `(n_cols - 1)` polynomial in `α`; Schwartz–Zippel gives
  `Pr ≤ (n_cols - 1) / 2^128`.
- **Query-phase forgery.** Per-column Merkle paths remain the sole
  symbol authenticators; RLC is only applied after all paths validate.
  Binding inherited from column commitments unchanged.

Total extra loss: `≤ n_cols / 2^128`. FRI fold-consistency and query-
count arguments are inherited verbatim from `noid_fri::verifier`.

#### 12b.3 Canonical order (parent channel, after zero-check)

1. observe `e_0, …, e_{n_cols - 1}`;
2. squeeze `α`;
3. observe the batched FRI proof in the order emitted by
   `noid_fri::prover::prove` (FRI oracle roots, sumcheck round
   oracles, folding challenges, final codeword, query answers).

Step 2 **must** happen after every `e_i` is absorbed and before any
FRI-internal transcript begins, so that `α` is pinned before the
prover has any influence on `C_batch`.

#### 12b.4 What does not change

- Per-column Merkle commitments (roots, depths, leaf layout).
- VSHIFT ladder sub-channel (§12a) — still tagged `0xFFFE_…` per slot.
- Zero-check sumcheck.
- FRI-internal transcript contract (`EvalProof` layout, query count).

Only the number of base-column `EvalProof`s drops from `n_cols` to `1`;
per-query symbol-pair block grows by `n_cols` (per-column paths
against existing per-column roots).

#### 12b.5 Cost (`prod`, `log_len = 16`, `n_cols = 8`)

| Metric                        | Before (3b-0.4) | After (3b-0.5.1) |
| ----------------------------- | --------------- | ---------------- |
| Base `EvalProof` count        | `n_cols = 8`    | `1`              |
| FRI oracle roots              | `n_cols · n`    | `n`              |
| FRI folding sumcheck rounds   | `n_cols · n`    | `n`              |
| Query-phase Merkle paths      | `n_cols · q`    | `n_cols · q`     |
| Per-column openings `e_i`     | implicit        | `n_cols` elems   |

Measured on `prod`: verify 98.7 ms (−29 % vs 3b-0.4), proof 1.12 MB
(−57 %), prove 2.15 s (−3.6 %). See ROADMAP §3b-0.5 / 0.5.1.

### 12c Interaction between §12a and §12b

Out of scope for 3b-0.5. The ladder sub-channel opens the base column
at a *different* point `r'` per shifted column, so RLC-batching ladder
openings would require choosing a shared `r'` across shifted columns
— possible, but a distinct protocol change, not on the critical path.

---

## 13. Non-goals (locked)

- No signatures.
- No trusted setup.
- No pairing-based systems.
- No SHA-family hashes inside binding logic.
- No shielded outputs (no blinding, scan tags, nullifiers, view keys,
  stealth addresses).
- No multi-asset (single native asset only; no `asset_tag` column).
- No on-chain observability primitives beyond the transparent tuple
  `(value, owner)` per output.

---

## Final Decisions (locked)

| Topic                 | Decision                                                        |
| --------------------- | --------------------------------------------------------------- |
| `compress`            | Two-permutation sponge, IV = `COMPRESS`                         |
| UTXO leaf             | `H_LEAF(value, owner_hi, owner_lo)`, IV = `LEAF____`            |
| Ownership             | `H_ADDR(secret)`, IV = `ADDRESS_`, in-AIR equality              |
| Replay guard          | `H_AUTH(secret, tx_body_hash)`, IV = `AUTHTAG_`, in-AIR         |
| `hash_tx_body`        | Depth-4 Merkle (`compress`) + wrap permutation, IV = `TXBODY__` |
| State commitment      | 3-column FRI MLE over `2^24` slots, Blake3 cross-column root    |
| Public inputs         | `(prev_state_root, new_state_root, tx_body_hash, fee)`          |
| Ladder-FRI separator  | `0xFFFE_0000_0000_0000 \| slot` (see §12a.4)                    |
| VSHIFT opening tag    | `0xFFFF_0000_0000_0000 \| slot`                                 |
| Digest encoding       | `bytes[0..16] -> Block128[0]`, `bytes[16..32] -> Block128[1]`   |
| `ZERO_DIGEST`         | `[0u8; 32]` everywhere                                          |
| FRI release defaults  | rate = 4, queries = 96, TAU = 7                                 |
| Chain constants       | `BLOCK_MAX_TXS = 1024`, `TXBODY_DEPTH = 4`                      |

Anything not in this table or in §12 is either (a) still specified
above as aspirational with an explicit "not shipped" tag, or (b) out
of scope per §13 / ROADMAP.
