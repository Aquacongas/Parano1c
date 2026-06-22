# PARANOID: Cryptography Specification

## Abstract

This document specifies Paranoid's transparent validity proof stack. All constructions operate over the binary tower field GF(2^128). The proof system composes four protocols: Poseidon2b (algebraic hash), FROST-GKR (hash computation proof), FRI-Binius (polynomial commitment), and recursive STARK (chain accumulation).

System soundness: **~120 bits** (bottleneck: FROST-GKR unified sumcheck at 345/2^128).

---

## 1. Binary Tower Field GF(2^128)

### 1.1 Construction

The tower is built via iterated quadratic extensions:

```
F_1   = GF(2)
F_8   = F_1[X] / (X^2 + X + τ_1)     — repeated 3 times from bit to byte
F_16  = F_8[X] / (X^2 + X + τ_8)
F_32  = F_16[X] / (X^2 + X + τ_16)
F_64  = F_32[X] / (X^2 + X + τ_32)
F_128 = F_64[X] / (X^2 + X + τ_64)
```

Each `τ_K` is a fixed element in `F_K` chosen so the quotient is irreducible. Elements are stored as little-endian byte arrays. Addition is XOR. Multiplication uses recursive Karatsuba:

```
(a + bX)(c + dX) = ac + ((a+b)(c+d) + ac + bd)X + bd·τ    (mod X^2 + X + τ)
```

Implementation: `noid_core/src/tower/`, types `Bit`, `Block8`, `Block16`, `Block32`, `Block64`, `Block128`.

### 1.2 Frobenius Endomorphism

**Theorem 1 (Frobenius).** In any field of characteristic 2, squaring is GF(2)-linear:

```
(a + b)^2 = a^2 + b^2        (no cross term: 2ab = 0)
```

In the binary tower, this means `sq: x ↦ x^2` is a bitwise permutation of the coefficient representation — computable in O(1) without any multiplication.

**Corollary.** The S-box `σ(x) = x^7` decomposes as:

```
x^7 = x · x^2 · x^4
```

where `x^2` and `x^4` are free (linear maps). Cost: **3 multiplications** in GF(2^128).

This is the key insight enabling FROST-GKR: the S-box is provable at degree 7 directly, without auxiliary decomposition columns.

### 1.3 Inversion

Multiplicative inversion uses the norm-based algorithm for tower fields. For `a = a_lo + a_hi·X`:

```
norm = a_lo^2 + a_lo·a_hi + a_hi^2·τ
inv_norm = norm^(-1)    (recursive call to lower tower level)
a^(-1) = (a_lo + a_hi)·inv_norm + a_hi·inv_norm·X
```

Base case: `GF(2)` inversion is identity (1^-1 = 1). Constant-time (no branching on secret data).

Implementation: `noid_core/src/tower/block128.rs::invert()`.

---

## 2. Poseidon2b Hash Function

### 2.1 Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Field | GF(2^128) | Native to proof system |
| State width | t = 4 | 512-bit internal state |
| Rate | 2 elements (256 bits) | Efficiency vs. security |
| Capacity | 2 elements (256 bits) | 128-bit security margin |
| S-box | x^7 | Minimum multiplicative degree for security in char-2 |
| Full rounds | 8 (4 initial + 4 final) | Per Poseidon2 security analysis |
| Partial rounds | 58 | Security margin for algebraic attacks |
| Total rounds | 66 | |
| MDS matrix (full) | 4×4 with coefficients from {1, 3, 4, 5, 6, 7} | Maximum branch number |
| MDS matrix (partial) | Sparse 4×4 | Reduced cost in partial rounds |

Implementation: `noid_poseidon2b/src/native/permutation.rs`.

### 2.2 Permutation Algorithm

```
permute(state: [F; 4]):
    state ← MDS_FULL(state)
    for round in 0..66:
        if round < 4 or round >= 62:               // full round
            state[i] += RC[round][i]  for all i
            state[i] ← state[i]^7    for all i      // S-box on all lanes
            state ← MDS_FULL(state)
        else:                                        // partial round
            state[0] += RC[round][0]
            state[0] ← state[0]^7                    // S-box on lane 0 only
            state ← MDS_PARTIAL(state)
```

### 2.3 Compression Function

```
compress(a: [u8; 32], b: [u8; 32]) → [u8; 32]:
    state = [a_lo, a_hi, IV_COMPRESS_HI, IV_COMPRESS_LO]
    state ← permute(state)
    state[0] ^= b_lo;  state[1] ^= b_hi
    state ← permute(state)
    return state[0] || state[1]
```

Domain separation via capacity IVs: `TAG_COMPRESS`, `TAG_ADDR`, `TAG_AUTH`, `TAG_LEAF`.

Implementation: `noid_poseidon2b/src/native/compression.rs`.

### 2.4 Security

**Assumption A1 (Collision resistance).** No PPT adversary finds distinct `(a, b) ≠ (a', b')` with `compress(a, b) = compress(a', b')`. Security: 128 bits (256-bit capacity, t/2 sponge bound).

**Assumption A2 (Preimage resistance).** No PPT adversary inverts `compress`. Security: 128 bits. This assumption underlies the privacy of `spend_secret` (§5.4).

---

## 3. FROST-GKR Kill-Shot Protocol

### 3.1 Overview

FROST-GKR (Frobenius Reduction Over Shifted Tables) proves batched Poseidon2b permutations via a single unified degree-7 sumcheck. It replaces 472 degree-2 sumchecks with 2 sumchecks (unified + shift), achieving 141× fewer Fiat-Shamir rounds.

Standard instances:
- **Spine:** 59 permutation slots, 15-variable hypercube (2^15 = 32,768 cells)
- **Auth:** 20 permutation slots, 14-variable hypercube (2^14 = 16,384 cells)

`Sweep25x2` reuses the same construction with a wider auth surface: 125 auth permutation slots for up to 25 live inputs, plus a distinct sweep tx-body spine layout.

### 3.2 MLE Layout

The unified hypercube encodes all permutation slots contiguously:

```
x = slot_bits:6 || round_bits:7 || elem_bits:2     (spine, 15 vars)
x = slot_bits:5 || round_bits:7 || elem_bits:2     (auth, 14 vars)
```

Three column MLEs:
- `state(x)`: permutation state after MDS application
- `s_in(x)`: S-box input (state + round constant)
- `s_out(x)`: S-box output

Implementation: `noid_gkr/src/spine_mle.rs`, `noid_gkr/src/auth_mle_v2.rs`.

### 3.3 Constraint System

Three constraint families over the unified MLE:

**C1 (S-box identity, degree 7):**
```
σ(x) · (s_out(x) - s_in(x)^7) + (1 - σ(x)) · (s_out(x) - s_in(x)) = 0
```
where `σ(x)` is the active-lane selector (1 for full rounds on all lanes, 1 for partial rounds on lane 0, 0 otherwise).

**C1' (Round constant, degree 2):**
```
σ(x) · (s_in(x) - state(x) - RC(x)) = 0
```

**C2 (MDS transition, degree 4 in shifted basis):**
```
state(inc(x)) - MDS(s_out(x)) = 0
```

The function `inc(x)` increments the round-bits portion of x. It is degree-7 in the bits of x. To avoid evaluating at a non-linear point during the sumcheck, the protocol uses a **Change of Variable**.

### 3.4 Change of Variable

Define `y = inc(x)`. The unified sumcheck runs over y with pre-materialized shifted tables:

```
state_inc[i] = state[inc_map[i]]
s_in_dec[i]  = s_in[dec_map[i]]
s_out_dec[i] = s_out[dec_map[i]]
```

All constraints become degree-9 in y (7 from `s_in^7` × 1 from eq × 1 from selector).

### 3.5 Unified Sumcheck

The main sumcheck proves:

```
Σ_y  U(y) · [C1(dec(y)) + ρ·C1'(dec(y)) + ρ²·C2(y)] = 0
```

where `U(y) = eq(β, dec(y)) · δ(dec(y))` is the weight function (challenges `ρ, β, δ` squeezed from the Fiat-Shamir channel before round polynomials are committed).

Round polynomial degree: 9 (10 coefficients per round). Number of rounds: 15 (spine) or 14 (auth).

Implementation: `noid_gkr/src/spine_unified.rs`, `noid_gkr/src/auth_unified_v2.rs`.

**Theorem 2 (Unified Sumcheck Soundness).** Under Assumption A4 (Schwartz-Zippel over GF(2^128)), if any permutation slot's witness violates any constraint at any hypercube point, the unified sumcheck rejects with probability ≥ 1 − 135/2^128 (spine).

*Proof.* Let the honest combined polynomial be `P(y) = U(y)·[C1 + ρ·C1' + ρ²·C2]`.

Step 1: If constraint C_i is violated at some point, the combined polynomial `C1 + ρ·C1' + ρ²·C2` is nonzero at that point with probability ≥ 1 − 2/2^128 over (ρ, ρ²) (Schwartz-Zippel on a degree-2 polynomial in ρ).

Step 2: Given a nonzero combined polynomial, the sumcheck detects it. Per round, the prover commits a round polynomial `rp_i` before the challenge `r_i` is drawn. If `rp_i` differs from the honest polynomial `q_i`, then `rp_i - q_i` is nonzero of degree ≤ 9. By A4, `Pr[r_i is a root] ≤ 9/2^128`.

Step 3: Over 15 rounds, the detection failure probability is at most `15 × 9/2^128 = 135/2^128` by union bound.

The union bound is valid because each round's failure event depends only on the current round polynomial being wrong, and the challenge is drawn fresh after commitment (Fiat-Shamir under ROM, Assumption A3). □

### 3.6 Flat-Basis Accumulation

The unified sumcheck operates entirely in the **flat (polynomial) basis** — the standard representation modulo `x^128 + x^7 + x^2 + x + 1` (GCM polynomial). All 23 MLE tables are converted from tower to flat basis once before the sumcheck loop begins:

```
tables_flat[i] = tower_to_flat(tables_tower[i])    for i in 0..23
```

In flat basis, field multiplication reduces to carry-less polynomial multiplication (`PCLMULQDQ` on x86_64), which completes in 5–8 ns versus 80–100 ns for recursive tower Karatsuba. The fold operation (contracting one variable via `f'(x) = f(x|_{x_j=0}) + r_j · (f(x|_{x_j=1}) - f(x|_{x_j=0}))`) is basis-agnostic since it is GF(2)-linear: XOR and scalar-mul commute with the basis isomorphism.

Only the final claims are converted back to tower basis for absorption into the Fiat-Shamir channel:

```
claim_tower = flat_to_tower(claim_flat)
channel.absorb(claim_tower)
```

**Lemma 1 (Basis Isomorphism).** The map `φ: tower → flat` defined by the 128×128 binary matrix `TOWER_TO_FLAT` is a GF(2)-algebra isomorphism. For all `a, b ∈ GF(2^128)`:

```
φ(a + b) = φ(a) + φ(b)         (linearity — immediate from matrix-over-GF(2) application)
φ(a · b) = φ(a) ·_GCM φ(b)    (ring homomorphism — verified exhaustively on generators)
```

*Proof.* Both representations define the same abstract field GF(2^128). The tower uses nested quadratic extensions; the flat basis uses a single degree-128 irreducible over GF(2). Any two GF(2^128) representations are isomorphic via a unique GF(2)-linear map. The matrix `TOWER_TO_FLAT` is this map, precomputed and hardcoded (128 rows × 128 bits). Invertibility: `FLAT_TO_TOWER = TOWER_TO_FLAT^{-1}` exists because the matrix has full rank (verified at compile time). The ring homomorphism property follows from uniqueness of the field structure. □

Implementation: `noid_core/src/hardware.rs` (matrices, `clmul_gcm`, PCLMULQDQ intrinsics).

### 3.7 Polynomial Coefficient Accumulation

Instead of evaluating the degree-9 integrand at 10 interpolation points {0, 1, ..., 9} per hypercube cell, the prover expresses the round polynomial directly in monomial form and accumulates 10 coefficients via XOR:

```
For each cell c in the current half-hypercube:
    P_c(τ) = Σ_{k=0}^{9} a_k(c) · τ^k       // degree-9 polynomial in folding variable τ
    acc[k] ^= a_k(c)                           // XOR-accumulate monomial coefficients
```

The coefficient `a_k(c)` is built from sub-polynomials in τ:

1. **S-box contribution:** `(s_in_0 + τ·s_in_1)^7` — degree 7 in τ, computed via `pow7_poly_t` using 6 flat-basis CLMULs
2. **Selector weight:** `U(c, τ) = eq_partial · (u_0 + τ·u_1)` — degree 1 in τ
3. **MDS constraint:** degree 1 in τ from `state_inc(c, τ)`
4. **Product:** weight × constraint = degree 1 × degree 8 = degree 9 (10 monomial coefficients)

The dominant cost is `pow7_poly_t` over 32 element-lanes in partial-round cells (14 CLMULs/lane × 32 lanes = 448 CLMULs per cell). Total per spine round: 32,768 cells × ~15 CLMULs/cell ≈ 490K CLMULs at 5–8 ns each ≈ 2.5–4 ms.

This eliminates:
- Multi-point evaluation at 10 points (10× redundant computation)
- Lagrange interpolation to recover coefficients (O(d²) overhead)
- Non-trivial rounding from evaluation-form to coefficient-form

The resulting round polynomial coefficients are absorbed directly into the Fiat-Shamir channel.

Implementation: `noid_gkr/src/spine_unified.rs::compute_round_polynomial_flat()`.

### 3.8 Fiat-Shamir Security: Round Reduction

The Kill-Shot reduces the Fiat-Shamir transcript from **4,248 rounds** in a naive per-permutation decomposition to **30 rounds** (spine), tightening the grinding/collision attack surface:

**Naive per-permutation decomposition:**
```
59 slots × 8 sumchecks/slot × 9 rounds/sumcheck = 4,248 FS rounds
```

Each round requires: absorb round polynomial → squeeze challenge. An attacker performing a grinding attack (choosing transcript prefixes to bias challenges) gets 4,248 injection points. Under the ROM (Assumption A3), the best attack advantage scales linearly with the number of rounds that can be targeted.

**Kill-Shot approach:**
```
1 unified sumcheck × 15 rounds + 1 shift gadget × 15 rounds = 30 FS rounds
```

The attack surface reduction factor is 4,248/30 = **141×**. In the random oracle model, an adversary making Q hash queries and targeting T rounds achieves advantage at most `Q·T/2^128` (standard FS extraction bound). Reducing T from 4,248 to 30 tightens this by 141× without changing the field size.

Additionally, fewer rounds means:
- Smaller proof size (30 round polynomials instead of 4,248)
- Fewer hash invocations for the verifier (direct speedup)
- Reduced transcript length minimizes multi-target collision opportunities

### 3.9 Shift Gadget

After the unified sumcheck completes at point `r'`, we have claims on shifted columns (e.g., `state_inc(r')`). The Shift Gadget proves:

```
state_inc(r') = Σ_x eq(r', inc(x)) · state(x)
```

Since `inc(x)` is degree-7 in x, `eq(r', inc(x))` is degree-7, and multiplied by the multilinear `state(x)` gives a degree-8 sumcheck.

- Rounds: 15 (spine) or 14 (auth)
- Round polynomial degree: 8
- Operates on a single column MLE (efficient)
- Output: reduces to a single point opening `state(r'')`

**Theorem 3 (Shift Gadget Soundness).** Soundness error ≤ 15 × 8/2^128 = 120/2^128 (spine).

*Proof.* Same argument as Theorem 2, applied to the degree-8 round polynomial over 15 rounds. □

### 3.10 Batch-Eval Reductions

After unified + shift, claims exist on three columns at various points:

| Column | Claims |
|--------|--------|
| `state` | `state(r')`, `state(r'')` |
| `s_in` | `s_in(r'')` |
| `s_out` | `s_out(r'')` |

Each column is reduced via `batch_eval` (random linear combination + degree-2 sumcheck) to a single `(r_B, v_B)` pair:

1. Draw challenge `γ` from channel
2. Combine M claims: `target = Σ_k γ^k · v_k`
3. Run degree-2 sumcheck: `target = Σ_x eq(r_B, x) · f(x)` where `r_B = (r_k₁ ⊕ ... ⊕ r_k_M)` (randomized)

The `state` column's `(r_B, v_B)` is committed via FRI (boundary MLE). The `s_in` and `s_out` values are discharged by native verifier computation.

Implementation: `noid_gkr/src/batch_eval.rs`.

**Theorem 4 (Batch-Eval Soundness).** Three columns × 15-round degree-2 sumcheck: 3 × 15 × 2/2^128 = 90/2^128.

### 3.11 Total GKR Soundness

```
ε_GKR = ε_unified + ε_shift + ε_batch
      = 135/2^128 + 120/2^128 + 90/2^128
      = 345/2^128
      ≈ 2^{-120}
```

### 3.12 Performance Comparison

| Metric | Naive degree-2 decomposition | Kill-Shot | Improvement |
|--------|--------------------------------|-----------|-------------|
| Sumchecks (spine) | 472 (8/slot × 59) | 2 (unified + shift) | 236× |
| FS rounds (spine) | 4,248 | 30 | 141× |
| Proof size (spine) | >280 KB | ~5.4 KB | >50× |
| Soundness error | 12,744/2^128 | 345/2^128 | 37× better |
| Prover time | 1.63 s | 154 ms | 10.5× |
| Verifier time | 1.06 s | 69 ms | 15.3× |

Implementation: `noid_gkr/src/spine_killshot.rs`, `noid_gkr/src/auth_killshot.rs`.

---

## 4. FRI-Binius Polynomial Commitment Scheme

### 4.1 Protocol Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Code rate ρ | 1/4 (LOG_RATE = 2) | Standard STARK rate |
| Queries Q | 64 (COMPACT_NUM_QUERIES) | 128-bit proximity soundness |
| τ (tensor) | 8 (COMPACT_TAU) | 256 upper partial evaluations |
| Merkle hash | Poseidon2b compress | Proof-friendly (same field) |
| Cap depth | 5 (MERKLE_CAP_DEPTH) | 32 cap leaves |

### 4.2 Commit Phase

Given polynomial `f` with `2^n` evaluations on the Boolean hypercube:

1. Encode via Reed-Solomon: `codeword = RS_encode(f)` → `4 × 2^n` symbols
2. Build Merkle tree over codeword (Poseidon2b compress)
3. Return `FriCommitment { root, log_len: n }`

### 4.3 Prove Phase (Opening at Point z)

1. **Split eval_point:** `z = (z_right, z_left)` where `|z_right| = n - τ`, `|z_left| = τ`
2. **Upper partial evaluations:** For each `b ∈ {0,1}^τ`, compute `up[b] = Σ_x eq(z_right, x) · f(b || x)`
3. **Tensor batching:** Draw challenge α, compute `batched = Σ_b eq(α, b) · up[b]`
4. **Sumcheck (right variables):** Prove `batched = Σ_x eq(z_right, x) · f_α(x)` where `f_α` is the α-weighted folded polynomial
5. **FRI folding rounds:** For each of `n - τ` rounds:
   - Encode current evals, commit Merkle root, absorb
   - Squeeze fold challenge, fold polynomial (halving size)
6. **Query phase:** Draw Q = 64 query indices, extract symbol pairs + Merkle paths
7. **Return** `CompactEvalProof`

### 4.4 Verify Phase

1. Verify upper partials: `Σ_b eq(z_left, b) · up[b] == claimed_eval`
2. Tensor batch: recompute α-weighted combination
3. Per-round: verify sumcheck polynomials (degree-1), absorb roots, squeeze challenges
4. **Batched Merkle verification:** For all Q queries simultaneously, reconstruct paths layer-by-layer
5. **Final codeword check:** Verify fold-consistency at each query position

### 4.5 Batched Merkle Proofs

The compact FRI uses deduplicated Merkle paths. Instead of Q independent paths (which share many siblings), the `BatchedMerkleProof` stores only unique siblings per layer. Space saving: ~40%.

Implementation: `noid_fri_binius/src/compact_fri.rs`.

**Theorem 5 (FRI Proximity Soundness).** For an adversarial prover whose committed codeword is at relative Hamming distance δ ≥ 1 − ρ = 3/4 from the Reed-Solomon code, the verifier accepts with probability at most:

```
ε_FRI ≤ ρ^Q = (1/4)^64 = 2^{-128}
```

*Proof.* After all folding rounds, the final codeword comparison fails at any query position that is in the error set (density ≥ δ ≥ 3/4). A single uniformly random query catches the adversary with probability ≥ δ ≥ 3/4, so it passes with probability ≤ 1/4. For Q = 64 independent queries: ε_FRI ≤ (1/4)^64 = 2^{-128}. The proximity gap theorem [BBHR18] ensures that FRI folding preserves the distance property through each round with overwhelming probability over the fold challenges. □

### 4.6 Interleaved Commitment (Block-Level)

For N same-shape transactions inside one block bucket, all trace columns are committed under one interleaved Merkle cap. A bucket multipoint sumcheck reduces the bucket's N terminal claims to one row point. A column-axis terminal-compression sumcheck then reduces the resulting linear form to one source-bound mixed FRI opening of the flattened row×column MLE. Standard and `Sweep25x2` transactions use separate non-empty buckets because their AIR shapes differ; the canonical `BlockProof` binds all non-empty bucket proofs together with common NativeDelta pre/post `SegmentMleOpening`s.

Implementation: `noid_fri_binius/src/interleaved_commit.rs`, `noid_fri_binius/src/mixed_open.rs`, `noid_block/src/lib.rs`.

---

## 5. STARK Protocol

### 5.1 AIR Framework

An Algebraic Intermediate Representation (AIR) defines:
- `n_cols`: number of trace columns
- `constraints()`: list of gates, each a polynomial over column evaluations
- `public_columns()`: columns whose values are verifier-known (not from proof)

The STARK proves: all constraints vanish on the trace (evaluation domain = Boolean hypercube of size 2^log_rows).

### 5.2 Zero-Check Protocol

The zero-check reduces constraint verification to a single evaluation:

1. Compose all gate constraints into `B(x) = Σ_j β^j · gate_j(columns(x))`
2. Prove `Σ_x eq(z, x) · B(x) = 0` via sumcheck (z is Fiat-Shamir challenge)
3. At the terminal point r, verify `B(r) = 0` using column openings

Soundness per zero-check: `n_rounds × d_max / 2^128` where `d_max` = maximum constraint degree + 1.

### 5.3 Verification Flow

```
verify_air_interleaved(proof, air):
    1. Absorb Merkle cap (column commitment)
    2. check_public_columns: verify MLE evaluations of verifier-owned columns
    3. Absorb extra_transcript (GKR proof bytes for binding)
    4. Squeeze zero-check point z
    5. Verify zero-check sumcheck rounds
    6. At terminal point r: verify constraint composition B(r) = 0
    7. Verify column openings via FRI (compact or full)
```

Implementation: `noid_stark/src/interleaved.rs`.

### 5.4 Public Column Enforcement

Public columns are deterministic functions of the AIR's static data (not from the proof). The verifier computes their MLE evaluations independently and asserts equality with the opened values. This is how GKR outputs (tx_body_hash, Address, AuthTag) are pinned:

```
if base_openings[pc.col] != MLE(pc.values, r_point) {
    return Err(ConstraintViolated)
}
```

This check is deterministic (ε = 0), not probabilistic.

---

## 6. Recursive STARK

### 6.1 RecursiveBlockAir

| Parameter | Value |
|-----------|-------|
| Rows | 256 (2^8) |
| Columns | 10 |
| Max degree | 4 |
| n_rounds (FRI) | 0 |

**Constraints:**

1. **ClaimInCheckGate**: `claim_in + p0 + p1 = 0`
   - Rows 0–10: primary block bucket multipoint sumcheck (11 variables)
   - Rows 11–21: secondary block bucket multipoint sumcheck (all-zero for single-shape blocks)
   - Rows 22–32: previous recursive proof sumcheck

2. **FoldCheckGate**: `claim_out + Lagrange([p0,p1,p2], r) = 0`
   - Rows 0–10: primary block bucket degree-2 multipoint sumcheck
   - Rows 11–21: secondary block bucket degree-2 multipoint sumcheck
   - Rows 22–32: previous recursive proof degree-2 sumcheck
   - `p0,p1,p2` are the round polynomial evaluations at `X = 0,1,2`; `r` is the real Fiat-Shamir challenge replayed from the bucket/recursive transcript.

3. **State-root pins** (row 33): `COL_P0 = sr_hi`, `COL_P1 = sr_lo`
   - Values from externally-verified block header (verifier-hardcoded)

### 6.2 Tensor PCS at n_rounds = 0

With `LOG_ROWS = 8` and `COMPACT_TAU = 8`, the FRI right-hand variables are empty (`n_rounds = 0`). The query loop never executes. The sole verification is the tensor check:

```
derived = Σ_i eq(eval_point, i) · upper_partial_evals[i]
assert derived == eval
```

**Theorem 6 (Tensor PCS Completeness at n=0).** A multilinear polynomial over 2^8 variables is uniquely determined by its 256 Boolean-hypercube evaluations. The tensor check is an exact evaluation, not an approximate proximity test.

*Proof.* A multilinear polynomial `f(x_1,...,x_8)` has exactly 2^8 = 256 coefficients in the multilinear basis `{Π x_i^{b_i} : b ∈ {0,1}^8}`. Its evaluation table on {0,1}^8 uniquely determines all coefficients (the multilinear extension is unique). Therefore `f(z) = Σ_i eq(z, i) · f(i)` is the exact evaluation at any point z. No proximity gap exists; no FRI queries are needed. □

**Theorem 7 (RecursiveBlockAir Soundness).** Under A3, A4, the recursive AIR STARK has soundness:

```
ε_rec ≤ (d_max + n_cols + 1) / 2^128 = (4 + 10 + 1) / 2^128 = 15/2^128 ≪ 2^{-120}
```

*Proof.* See Security Model §9.2 for the full three-condition proof (public column determinism, witness constraint via Schwartz-Zippel, opening consistency via multipoint sumcheck). □

### 6.3 Chain Accumulator

```
ChainAccumulator:
    extend(block_hash, claim_bytes, new_state_root):
        inner      = compress(block_hash, claim_bytes)
        chain_hash = compress(prev_chain_hash, inner)
```

The accumulator folds each block into the chain hash via two Poseidon2b compressions. The `chain_claim` is the canonical block proof claim folded into recursive history; for bucketized proofs it is derived from the canonical block proof transcript hash. The separate `block_initial_claim` remains the bucket-local multipoint sumcheck target checked by `RecursiveBlockAir`. `block_hash` binds the PoW header, including `proof_transcript_hash`.

Implementation: `noid_recursive/src/accumulator.rs`.

---

## 7. Proof Sizes

Measured medians on the reference 2023 Intel Core i7-1365U laptop:

| Component | Size / time | Notes |
|-----------|-------------|-------|
| Standard4x8 wallet bundle (4-in/8-out) | 235.79 KB; prove 89.41 ms; verify 24.60 ms | Logic proof = 234.08 KB = 151.50 KB STARK + 82.58 KB AuthGKR |
| Sweep25x2 wallet bundle (25-in/2-out) | 214.94 KB; prove 372.33 ms; verify 111.54 ms | Logic proof = 210.28 KB = 96.19 KB STARK + 114.09 KB AuthGKR |
| Standard-only full block, 10 txs | 2.24 MB proof + 828.17 KB Auth sidecar; prove 2.37 s; verify 542.39 ms | Production proof-native path: bucket proof + NativeDelta pre/post state openings |
| Standard-only full block, 20 txs | 2.85 MB proof + 1.62 MB Auth sidecar; prove 3.95 s; verify 960.62 ms | Same path |
| Standard-only full block, 100 txs | 7.62 MB proof + 8.11 MB Auth sidecar; prove 14.26 s; verify 4.10 s | Same path |
| Sweep-only full block, 10 txs | 2.70 MB proof + 1.11 MB Auth sidecar; prove 3.97 s; verify 1.06 s | Wallet pre-proving excluded from block prove time |
| RecursiveProof | ~38 KB encoded; verify ~5 ms | 256-row `RecursiveBlockAir`; current `recursive_hotspots` run measured 37.91–38.34 KB encoded |

---

## 8. Soundness Budget

| Component | Formula | ε | Bits |
|-----------|---------|---|------|
| GKR unified sumcheck (spine) | 15 × 9 / 2^128 | 135/2^128 | ~120 |
| GKR shift gadget | 15 × 8 / 2^128 | 120/2^128 | ~120 |
| GKR batch-eval (3 cols) | 3 × 15 × 2 / 2^128 | 90/2^128 | ~121 |
| TxLogicAir zero-check | 11 × 5 / 2^128 | 55/2^128 | ~122 |
| NativeDelta state identity, per dirty segment | 3 × eff_log / 2^128, eff_log ≤ 16 | ≤48/2^128 | ~122 |
| RecursiveBlockAir zero-check | 8 × 4 / 2^128 | 32/2^128 | ~123 |
| FRI PCS (64 queries, ρ=1/4) | (1/4)^64 | 2^{-128} | 128 |
| Poseidon2b collision | — | 2^{-128} | 128 |
| **Block aggregate** | union bound over active checks and dirty segments | see `docs/security.md` | target ≥120-bit for accepted production caps |

**Theorem 8 (System Soundness).** Under assumptions A1–A5, no PPT adversary can produce a block proof accepted by an honest verifier for a block containing an invalid transaction except with the union-bound probability over the verified wallet proofs, bucket proofs, NativeDelta segment identities, source-bound FRI openings, recursive AIR check, and Poseidon2b collision events.

*Proof.* Each sumcheck or random-point identity term is bounded by Schwartz-Zippel (A4) using its degree and round count. Each source-bound FRI opening contributes the code-rate query bound (A5). Poseidon2b commitments contribute the collision term (A2). Fiat-Shamir domain separation (A3) makes every challenge pseudorandom for the already-bound transcript prefix. See `docs/security.md` for the exact production acceptance predicates and block-level aggregate analysis. □

---

## 9. Fiat-Shamir Transcript

### 9.1 Channel

A single `Poseidon2bChannel` spans the entire proof (GKR + STARK + FRI). Operations:
- `absorb(data)`: feed bytes into the sponge state
- `squeeze() → Block128`: extract a field element challenge

The channel uses Poseidon2b in sponge mode (rate-2, capacity-2).

### 9.2 Transcript Ordering (Per-Transaction)

```
1. Spine Kill-Shot:
   absorb(claimed_tx_body_hash)
   squeeze → ρ (RLC combination)
   squeeze → β, γ (weight function)
   for round in 0..15: absorb(round_poly), squeeze(r_i)
   absorb(final_scalars × 12)
   squeeze → δ (shift)
   for round in 0..15: absorb(shift_poly), squeeze(s_i)
   absorb(shift_finals × 3)
   squeeze → γ_batch
   3× batch_eval rounds

2. Auth Kill-Shot:
   absorb(tx_body_hash, expected_address[], expected_auth_tag[])
   [same unified + shift + batch pattern, 14 rounds]

3. STARK:
   absorb(column_merkle_cap)
   absorb(spine_ks_bytes || auth_ks_bytes)    ← GKR binding point
   squeeze → z (zero-check point)
   zero-check rounds
   FRI opening
```

**Critical invariant:** `extra_transcript` (step 3, second absorb) binds GKR proofs to the STARK. Any byte-level modification forks all downstream challenges.

### 9.3 No Forked Channels

No module in the system constructs a parallel channel. The boundary-MLE FRI opening uses a fresh `noid_fri::Channel` whose output bytes are re-absorbed into the shared channel via the extras hook.

---

## 10. Cryptographic Assumptions

| ID | Assumption | Security | Used in |
|----|-----------|----------|---------|
| A1 | Poseidon2b collision resistance | 128 bits | Merkle trees, state root, accumulator |
| A2 | Poseidon2b preimage resistance | 128 bits | Privacy of spend_secret |
| A3 | Blake3 random oracle model | 256 bits | Fiat-Shamir, PoW |
| A4 | Schwartz-Zippel over GF(2^128) | d/2^128 per eval | All sumchecks |
| A5 | FRI proximity (Q=64, ρ=1/4) | 128 bits | Polynomial commitments |

---

## 11. Parameter Reference

| Identifier | Value | Source |
|-----------|-------|--------|
| `COMPACT_TAU` | 8 | `noid_fri_binius/src/compact_fri.rs` |
| `COMPACT_NUM_QUERIES` | 64 | `noid_fri_binius/src/compact_fri.rs` |
| `LOG_RATE` | 2 (ρ = 1/4) | `noid_fri/src/code.rs` |
| `MERKLE_CAP_DEPTH` | 5 | `noid_fri_binius/src/lib.rs` |
| `N_SPINE_SLOTS` | 59 | `noid_gkr/src/spine_sumcheck.rs` |
| `N_AUTH_SLOTS` | 20 | `noid_gkr/src/auth_circuit.rs` |
| `N_SPINE_UNIFIED_VARS` | 15 | `noid_gkr/src/spine_mle.rs` |
| `N_AUTH_UNIFIED_VARS` | 14 | `noid_gkr/src/auth_mle_v2.rs` |
| `SPINE_UNIFIED_ROUND_DEGREE` | 9 | `noid_gkr/src/spine_unified.rs` |
| `LOG_ROWS` (Recursive) | 8 | `noid_recursive/src/air.rs` |
| `POSEIDON2B_FULL_ROUNDS` | 8 | `noid_poseidon2b/src/native/permutation.rs` |
| `POSEIDON2B_PARTIAL_ROUNDS` | 58 | `noid_poseidon2b/src/native/permutation.rs` |
| `POSEIDON2B_WIDTH` | 4 | `noid_poseidon2b/src/native/permutation.rs` |

---

## 12. Implementation Map

| Function | File | Role |
|----------|------|------|
| `permute_mut` | `noid_poseidon2b/src/native/permutation.rs` | Poseidon2b permutation |
| `compress` | `noid_poseidon2b/src/native/compression.rs` | Two-to-one hash |
| `prove_spine_killshot` | `noid_gkr/src/spine_killshot.rs` | FROST-GKR Spine orchestrator |
| `prove_auth_killshot` | `noid_gkr/src/auth_killshot.rs` | FROST-GKR Auth orchestrator |
| `prove_spine_unified` | `noid_gkr/src/spine_unified.rs` | Degree-9 unified sumcheck |
| `compute_round_polynomial_flat` | `noid_gkr/src/spine_unified.rs` | Monomial coefficient accumulation |
| `prove_spine_shift` | `noid_gkr/src/spine_shift.rs` | Shift Gadget |
| `prove_batch_eval` | `noid_gkr/src/batch_eval.rs` | RLC + degree-2 reduction |
| `prove_single_d` | `noid_core/src/sumcheck/prove.rs` | Generic sumcheck prover |
| `verify_with_channel` | `noid_core/src/sumcheck/verify.rs` | Generic sumcheck verifier |
| `tower_to_flat_u128` | `noid_core/src/hardware.rs` | Tower → flat basis conversion |
| `flat_to_tower_u128` | `noid_core/src/hardware.rs` | Flat → tower basis conversion |
| `clmul_gcm` | `noid_core/src/hardware.rs` | PCLMULQDQ carry-less multiply |
| `commit` / `prove` | `noid_fri/src/prover.rs` | FRI commit + open |
| `verify` | `noid_fri/src/verifier.rs` | FRI verifier |
| `compact_fri_prove` | `noid_fri_binius/src/compact_fri.rs` | Compact FRI (production) |
| `compact_fri_verify` | `noid_fri_binius/src/compact_fri.rs` | Compact FRI verifier |
| `commit_interleaved` | `noid_fri_binius/src/interleaved_commit.rs` | Block-level joint commitment |
| `verify_mixed_opening` | `noid_fri_binius/src/mixed_open.rs` | Per-bucket FRI mixed opening for N same-shape txs |
| `verify_air_interleaved` | `noid_stark/src/interleaved.rs` | STARK verifier |
| `RecursiveBlockAir` | `noid_recursive/src/air.rs` | 256-row recursive AIR |
| `ChainAccumulator::extend` | `noid_recursive/src/accumulator.rs` | Chain hash fold |
| `verify_recursive_step` | `noid_recursive/src/verify.rs` | Recursive verifier |

---

## 13. Related Work

| System | Field | Hash Proof Strategy | Key Difference |
|--------|-------|-------------------|----------------|
| **Binius** [DP24] | GF(2^128) tower | Generic sumcheck over multilinears | No hash-specific optimization; degree-2 decomposition via auxiliary columns |
| **Lasso / Jolt** [STW24] | Prime fields | Lookup arguments for non-arithmetic ops | R1CS-derived; lookup tables scale with gate fan-in |
| **Libra / Virgo** [XZZ+19] | Prime fields | GKR with linear-time prover | Per-layer sumchecks; no cross-layer unification |
| **Plonky3** [Pol24] | Goldilocks / BabyBear | AIR + FRI over small prime fields | No binary tower; requires extension field for soundness |
| **FROST-GKR** (this work) | GF(2^128) tower | Unified degree-7 sumcheck over shifted tables | Single sumcheck replaces O(N·R) per-round decomposition; flat-basis CLMUL hardware acceleration |

**Key distinctions:**

1. **vs. Binius:** Binius operates in the same binary tower but proves hash computations via generic multilinear constraint systems requiring degree-2 decomposition (auxiliary columns for x^7). FROST-GKR eliminates decomposition by handling degree 7 natively in a single unified sumcheck, removing 470+ intermediate sumchecks.

2. **vs. Lasso/Jolt:** These systems use lookup arguments over prime fields to handle non-arithmetic operations (bitwise ops, comparisons). FROST-GKR operates natively in GF(2^128) where XOR is free (addition) and the S-box x^7 is directly provable without lookups.

3. **vs. Libra/Virgo:** These use GKR protocol layering where each circuit layer requires its own sumcheck. FROST-GKR unifies all 59 permutation slots × 66 rounds into a single hypercube, eliminating inter-layer reduction overhead.

4. **Flat-basis acceleration:** No prior system exploits the tower-to-GCM-polynomial basis isomorphism for hardware-accelerated prover arithmetic via PCLMULQDQ. This provides a 10–16× speedup on commodity x86_64 hardware (5–8 ns/mul vs 80–100 ns tower Karatsuba).

---

*Formal security proofs: [Security Model](security.md). System integration: [Protocol](protocol.md).*
