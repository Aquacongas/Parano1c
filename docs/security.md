# Paranoid protocol security specification

Scope: wallet transaction proofs, block aggregation, state binding, recursive chain proof, source-bound FRI-Binius openings, state-retention policy, and network/RPC/mempool resource caps.

This document defines the security model, assumptions, algebraic claims, proof obligations, implementation correspondence, and test coverage for Paranoid validators. Every theorem below is conditional on the stated cryptographic assumptions and on validators executing the referenced verifier code.

---

## 1. Protocol overview

Paranoid is a transparent proof-native UTXO/state chain over the binary tower field

```text
F = GF(2^128).
```

The validator proof stack uses:

- Poseidon2b over `GF(2^128)` for application hashes and Fiat-Shamir transcript hashing;
- FROST-GKR / KillShot for Poseidon2b execution traces;
- STARK/AIR proofs over the same field for transaction logic, block buckets, and recursion;
- NativeDelta state-transition verification with source-bound pre/post segment MLE openings;
- FRI-Binius mixed openings with source-bound compact FRI round-0 oracles;
- proof-native block validation: a user-transaction block is accepted only if the canonical `BlockProof` verifies and the proven state delta is committed atomically.

The source/oracle binding relation for mixed openings is:

```text
committed encoded source columns
  -> γ-reduced source code symbols
  -> additive-NTT high TensorFold
  -> Code(H)
  -> Code(H * eq_right)
  == compact FRI round-0 oracle.
```

The verifier acceptance predicate requires the compact FRI round-0 oracle to be query-bound to the committed encoded source columns through a Merkle source root and additive-NTT TensorFold checks.

The node enforces shared wire and memory caps before expensive decode, allocation, verification, mempool insertion, orphan retention, or snapshot collection. The consensus transaction cap is:

```text
BLOCK_TIME    = 15 seconds
BLOCK_MAX_TXS = 256
```

Implementation anchors:

```text
noid_fri_binius/src/interleaved_commit.rs
noid_fri_binius/src/mixed_open.rs
noid_fri_binius/src/compact_fri.rs
noid_block/src/validate.rs
noid_chain/src/consensus/params.rs
noid_chain/src/consensus/wire_limits.rs
```

---

## 2. Threat model

### 2.1 Adversarial capabilities

The adversary may:

1. Construct arbitrary wallet proofs, block proofs, auth sidecars, block bodies, mempool messages, RPC requests, P2P announcements, snapshot manifests, and snapshot segments.
2. Choose malformed proof transcripts, malformed Merkle proofs, malformed FRI query symbols, malformed source-binding data, malformed secondary mixed-opening claims, and malformed block state claims.
3. Control miners/provers attempting to generate blocks that spend unavailable slots, mint unauthorized outputs, alter fees, alter public inputs, replay or reorder claims, or bind a proof to a different state root.
4. Attempt memory/CPU denial-of-service by sending oversized hex/RPC inputs, oversized P2P payloads, oversized block proofs/sidecars, many mempool transactions, many orphan blocks, or large snapshot manifests/segments.
5. Observe all public wire data, block proofs, recursive proofs, headers, transaction bodies, and public Auth sidecars.

### 2.2 Assumptions outside this document

The adversary is assumed not to break the cryptographic assumptions in Section 4. The document does not claim protection against:

- compromise of a wallet process while `spend_secret` is resident in wallet-local memory;
- implementation defects outside the referenced verifier paths;
- undefined behavior or compiler/hardware faults;
- economic attacks not represented in the consensus/proof validity predicates;
- denial-of-service below configured resource caps, such as many valid-but-expensive proofs within policy.

---

## 3. Security objectives

### 3.1 Wallet-secret confinement

`spend_secret` is a wallet-local witness. The public protocol exposes one-way outputs only:

```text
owner    = H_ADDR(spend_secret)
auth_tag = H_AUTH(spend_secret, tx_body_hash)
```

The secret is not part of:

- serialized wallet bundles;
- transaction wire payloads;
- block proofs or block auth sidecars;
- public Fiat-Shamir transcript inputs;
- committed AIR/PCS source columns sent to miners/full nodes;
- raw helper tables sent outside wallet-local proving memory.

Implementation anchors:

```text
noid_tx/src/wire.rs              TxInput::encode_public
noid_tx/src/intent.rs            spend_secret_absent_from_wire
noid_gkr/src/auth_killshot.rs    absorb_public_boundary
noid_gkr/src/auth_circuit.rs     AuthPublicInputs
```

Implementation tests:

```text
cargo test -p noid_tx --release
spend_secret_absent_from_wire
```

### 3.2 Transparent proof assumptions

The validator proof stack does not use curve-based or trusted-setup primitives. In particular, the security argument does not rely on:

```text
KZG, IPA, Pedersen commitments, signatures, elliptic-curve discrete log, pairings, or trusted setup.
```

The proof stack is binary-tower-native and transparent: FRI, GKR/KillShot, Merkle/hash commitments, and Fiat-Shamir over public transcripts.

### 3.3 Source binding for mixed openings

The mixed-opening acceptance predicate requires the compact FRI round-0 oracle to be derived from the committed source columns. For every accepted mixed opening, the returned primary opening vector is bound to the committed columns at the claimed point, up to the soundness terms stated in Theorem 1.

### 3.4 Block-state safety

For every accepted user-transaction block:

1. transaction bodies define the canonical public claims;
2. wallet proofs and bucket proofs verify against those claims;
3. the verifier reconstructs the ordered dirty-segment claim set from transaction bodies and the parent state view;
4. for each dirty segment, the pre/post opening segment IDs equal the verifier-reconstructed segment ID;
5. the Fiat-Shamir state-delta evaluation point is derived from the parent state root, child state root, segment ID, segment order, transaction count, and segment size;
6. the native random-point state-delta identity holds for value, owner-high, and owner-low lanes;
7. the pre/post lane openings are source-bound mixed openings and are Merkle-bound to the parent and child global state roots at the same segment index;
8. the header binds the block proof and public sidecar;
9. the atomic storage commit applies exactly the verified state delta.

### 3.5 Bounded untrusted input handling

Untrusted inputs must be bounded before expensive decode/allocation/verification. The shared cap constants are in `noid_chain/src/consensus/wire_limits.rs` and are enforced across RPC, P2P, mempool, block validation, orphan retention, and snapshot collection.

---

## 4. Cryptographic assumptions and notation

### 4.1 Assumptions

| ID | Assumption | Security target |
| --- | --- | ---: |
| A1 | Poseidon2b collision resistance over `GF(2^128)` for application and transcript hashes | 128 bits |
| A2 | Poseidon2b preimage resistance for `Address` / `AuthTag` | 128 bits |
| A3 | Poseidon2b Fiat-Shamir channels (`Poseidon2bChannel` and `noid_fri::Channel`) are modeled as random-oracle outputs after absorb-before-squeeze; Blake3 is not used for Fiat-Shamir | 128 bits |
| A4 | Schwartz-Zippel over `GF(2^128)`: a nonzero degree-`d` polynomial vanishes at a random point with probability at most `d / 2^128` | algebraic |
| A5 | Compact FRI at rate `1/4` with 64 validator queries satisfies the standard FRI proximity bound for the configured folding/query schedule; `(1/4)^64` is only the query-rate intuition, not a standalone proof | 128-bit target |
| A6 | Blake3 collision resistance where explicitly used outside Fiat-Shamir; source-binding Merkle trees use full 256-bit Blake3 outputs, giving a 128-bit collision-security target | 128 bits |

Validator compact FRI query count:

```text
COMPACT_NUM_QUERIES = 64    // release builds
```

Release validator builds use the query count above. Debug/test builds may use smaller constants and are not security-parameter configurations.

Implementation anchor:

```text
noid_fri_binius/src/compact_fri.rs
```

### 4.2 Notation

```text
F              = GF(2^128)
|F|            = 2^128
Code(v)        = additive-NTT Reed-Solomon-style codeword of message table v
eq_r(x)        = multilinear equality polynomial at point r
γ, β, ρ        = Fiat-Shamir challenges sampled after the values they bind
Hash collision = collision in Poseidon2b or the relevant Merkle hash
```

For vectors over characteristic 2, `+` denotes field addition, which is XOR at the bit level after basis representation.

---

## 5. Source-bound mixed opening

### 5.1 Statement proved by the validator verifier

Let the committed source columns be multilinear functions

```text
col_i : {0,1}^n -> F,      i = 0..m-1.
```

Vector-mode mixed openings are admitted only for

```text
m <= MAX_MIXED_OPEN_VECTOR_COLS = 256.
```

Wider linear terminal relations must be reduced to a scalar terminal before reaching this verifier surface; the block bucket terminal relation uses `commitment.n_cols = 1` after flattening.

The prover returns a vector

```text
v = (v_0, ..., v_{m-1})
```

claimed to equal

```text
(col_0(r), ..., col_{m-1}(r))
```

at primary point `r ∈ F^n`.

The verifier absorbs `v` before sampling `γ` and checks a compact FRI proof for

```text
C(r) = Σ_{i=0}^{m-1} γ^i * v_i,
```

where the committed source polynomial is

```text
C_src(x) = Σ_{i=0}^{m-1} γ^i * col_i(x).
```

The source-binding layer enforces that the compact FRI round-0 oracle is derived from `C_src`.

Implementation anchors:

```text
noid_fri_binius/src/mixed_open.rs       prove_mixed_opening, verify_mixed_opening
noid_fri_binius/src/compact_fri.rs      compact_fri_prove_with_query_hook, compact_fri_verify_with_query_hook
noid_fri_binius/src/interleaved_commit.rs
```

### 5.2 Source commitment

`InterleavedCommitment` contains the compact Merkle cap and an additional source root inside `cap.hashes`:

```text
[32 compact cap hashes..., source_root]
```

The source root commits to encoded columns:

```text
encoded_cols[col][code_index]
```

using a full-output Blake3-based Merkle tree (`SourceHash = [u8; 32]`). Each source leaf is a high-variable pair for all columns with this exact byte-level preimage:

```text
source_leaf = BLAKE3(
    "PARANOID/INTERLEAVED-SOURCE-HIGH-PAIR-LEAF/256/v2"
 || u64_le(log_rows)
 || u64_le(n_cols)
 || u64_le(leaf_index)
 || u128_le(col_0[pos0]) || u128_le(col_0[pos1])
 || ...
 || u128_le(col_{m-1}[pos0]) || u128_le(col_{m-1}[pos1])
)
```

where

```text
(pos0, pos1) = source_leaf_positions(log_rows, leaf_index).
```

Internal source-binding Merkle compression is full-output Blake3 over two 32-byte child hashes:

```text
node = BLAKE3(
    "PARANOID/SOURCE-BINDING-MERKLE-256/v2"
 || left[32]
 || right[32]
)
```

Intermediate folded-layer roots use the same Merkle internal-node tag and a distinct folded-layer leaf tag. This is intentional safe reuse: source leaves and folded-layer leaves are role-separated by their leaf tags and byte preimages, while each folded root is also absorbed as a `VectorCommitment { root, depth }` before query sampling.

For a folded layer with `layer_log = log_rows - 1 - layer_idx`, each folded leaf is:

```text
folded_leaf = BLAKE3(
    "PARANOID/MIXED-SOURCE-HIGH-FOLD-LEAF/256/v2"
 || u64_le(layer_log)
 || u64_le(leaf_index)
 || u128_le(s0)
 || u128_le(s1)
)
```

and the folded root is the Merkle root over `folded_leaf` values using the `SOURCE-BINDING-MERKLE-256/v2` internal compression above.

The batched Merkle verifier:

- accepts duplicate requested leaves only if the provided leaf hashes are identical;
- rejects insufficient siblings;
- rejects unused siblings;
- reconstructs the root in deterministic parent order.

Implementation anchors:

```text
noid_fri_binius/src/interleaved_commit.rs
  InterleavedCommitment
  InterleavedProverState::encoded_cols
  SourceMerkleTree
  SourceHash
  source_leaf_hash
  source_leaf_positions
  verify_source_batched_merkle_proof
```

### 5.3 Transcript order

The transcript order is the source of Fiat-Shamir binding. The verifier mirrors the prover:

```text
1. absorb MIXED_OPEN_TAG
2. absorb all returned opening values v and secondary claim values
3. squeeze γ
4. compute C(r) = Σ_i γ^i * v_i
5. compact FRI absorbs primary point, claimed C(r), sumcheck messages, FRI roots, final codeword
6. source-binding hook absorbs tag, H evaluations, and TensorFold roots
7. squeeze shared compact-FRI query indices
8. verify compact FRI queries
9. verify source Merkle/TensorFold queries for the same query indices
```

The crucial ordering is that source-binding commitments are absorbed before query indices are sampled. Therefore the prover cannot adapt source-binding data after seeing the FRI queries.

Implementation anchors:

```text
noid_fri_binius/src/mixed_open.rs
  MIXED_OPEN_TAG
  MIXED_SOURCE_BINDING_TAG
  prove_source_binding
  verify_source_binding

noid_fri_binius/src/compact_fri.rs
  compact_fri_prove_with_query_hook
  compact_fri_verify_with_query_hook
```

### 5.4 Algebraic construction

Let

```text
n         = log_rows
tau       = min(COMPACT_TAU, n)
n_low     = n - tau
(r_low, r_high) = r.split_at(n_low)
```

Compact FRI upper partials are:

```text
U[u] = C_src(u, r_low),            u ∈ {0,1}^tau
C_src(r) = Σ_u eq_{r_high}(u) * U[u].
```

After tensor challenge `β ∈ F^tau`, define:

```text
H[j] = Σ_u eq_β(u) * C_src(u, j),  j ∈ {0,1}^{n_low}
g[j] = H[j] * eq_{r_low}(j).
```

The compact FRI round-0 oracle must be:

```text
Code(g) = Code(H * eq_{r_low}).
```

The proof carries `H` explicitly for the supported verifier shapes. The verifier computes `Code(H)` and `Code(H * eq_{r_low})`, checks that the latter root equals the compact FRI round-0 root, and verifies that queried `Code(H)` symbols are obtained from authenticated source columns through TensorFold.

Implementation anchor:

```text
noid_fri_binius/src/mixed_open.rs
  SourceBindingProof::h_evals
  verify_source_binding
```

### 5.5 Correct additive-NTT TensorFold

For one additive-NTT high-variable pair, write the message-domain values as `(u, v)` and the corresponding code-domain pair as `(even, odd)`. The additive NTT butterfly is:

```text
forward:
  even = u + v
  odd  = even * b + v

inverse:
  v = odd + even * b
  u = even + v
```

The MLE high-variable fold at challenge `r` is:

```text
fold_mle(u, v; r) = u + r * (u + v).
```

Substituting the inverse butterfly gives the transported code-domain operation:

```text
fold_mle(u, v; r)
  = (even + (odd + even*b)) + r*even
  = odd + even*(b + 1 + r).
```

Therefore the high-variable TensorFold used by the verifier is:

```text
TensorFoldHigh(even, odd; b, r) = odd + even * (b + 1 + r).
```

This is distinct from `Code::fold_code`, which is the FRI proximity/quotient fold and does not express the source MLE fold. Using `Code::fold_code` for source binding would not prove that the final oracle encodes the claimed source-derived scalar.

Implementation anchor:

```text
noid_fri_binius/src/mixed_open.rs
  tensor_high_fold_pair
```

Implementation tests:

```text
cargo test --release -p noid_fri_binius --lib mixed_open::tests -- --nocapture

Tests include:
  high TensorFold matches Code::new_parallel on random vectors
  source Code high TensorFold layers match the additive-NTT rebuild path
```

### 5.6 Verifier query checks

For each shared compact-FRI query, the source-binding verifier checks:

1. derive the source high-pair leaf index from the query index;
2. authenticate the corresponding source symbols against `source_root`;
3. reduce all source columns with the same `γ`:

   ```text
   (c0, c1) = Σ_i γ^i * (col_i_code[pos0], col_i_code[pos1]);
   ```

4. apply `TensorFoldHigh` over high variables using `β`;
5. authenticate intermediate high-fold layer pairs against their folded roots when present;
6. compare the final carried value to the verifier-computed `Code(H)` symbol;
7. require the compact FRI round-0 root to equal `root(Code(H * eq_{r_low}))`;
8. run ordinary compact FRI verification for proximity.

The hot linear-combination path is implemented in flat/GCM basis using carry-less multiplication helpers:

```text
compute_horner_weights_flat
source pair reduction: reduce_source_pair_flat
batched claim:       compute_batched_claim_flat
```

Implementation anchors:

```text
noid_fri_binius/src/mixed_open.rs
  compute_horner_weights_flat
  reduce_source_pair_flat
  compute_batched_claim_flat
  verify_source_binding
```

### 5.7 Theorem 1: primary vector source binding

**Claim.** Consider an accepting call to `verify_mixed_opening` with commitment `Com(col_0, ..., col_{m-1})`, primary point `r`, and returned primary vector `v`. The verifier first enforces `m <= MAX_MIXED_OPEN_VECTOR_COLS = 256`. Under assumptions A3-A6,

```text
Pr[accept ∧ v != (col_0(r), ..., col_{m-1}(r))]
  ≤ ε_hash
   + ε_tensor_query
   + ε_FRI
   + (m - 1) / 2^128
   + ε_FS
  ≤ ε_hash + ε_tensor_query + ε_FRI + 255/2^128 + ε_FS.
```

The algebraic vector-randomization term therefore satisfies

```text
255 / 2^128 < 2^-120.
```

For rate `1/4` and 64 compact-FRI queries,

```text
ε_FRI ≈ 2^-128.
```

The TensorFold query term is also targeted at the 128-bit level because the same 64 query positions are sampled after all source-binding roots/messages have been absorbed.

**Proof sketch.** Let the true committed evaluation vector be

```text
a = (col_0(r), ..., col_{m-1}(r)).
```

If `v != a`, then

```text
D(γ) = Σ_i γ^i * (v_i - a_i)
```

is a nonzero polynomial in `γ` of degree at most `m-1`, except in the degenerate case where all coefficients are zero, which is exactly `v = a`. Since `γ` is sampled after `v` is absorbed,

```text
Pr[D(γ) = 0] ≤ (m - 1) / |F| = (m - 1) / 2^128.
```

Condition on `D(γ) != 0`. Then the claimed compact-FRI scalar

```text
Σ_i γ^i * v_i
```

is not equal to the source-derived value

```text
C_src(r) = Σ_i γ^i * col_i(r).
```

For the verifier to accept anyway, at least one of the following must occur:

1. a Merkle/hash collision allows source symbols inconsistent with `source_root`;
2. TensorFold query checks fail to catch an inconsistent `Code(H)` relation;
3. compact FRI accepts an invalid low-degree/proximity claim or invalid round-0 oracle relation;
4. Fiat-Shamir challenges are predicted or biased despite absorb-before-squeeze ordering.

Union-bounding these events gives the stated bound.

Implementation anchors:

```text
noid_fri_binius/src/mixed_open.rs
  MAX_MIXED_OPEN_VECTOR_COLS
  verify_mixed_opening
```

Implementation tests:

```text
cargo test --release -p noid_fri_binius --lib mixed_open::tests -- --nocapture

Tests include:
  vector_mode_rejects_columns_above_120_bit_cap
  A/A' attack: commit to one source matrix and attempt to open from another
  valid round-0 source-binding path passes
  tampered round-0 FRI root rejects
  tampered source H rejects
  source_root_upper_half_mutation_rejects
  source_sibling_upper_half_mutation_rejects
  folded_root_upper_half_mutation_rejects
  one-column direct source expansion passes and tampering rejects
```

### 5.8 Secondary mixed-opening claims

`MixedOpeningProof.all_openings` serializes primary openings followed by secondary claim values. The `verify_mixed_opening` function:

- verifies secondary claim shape and dimensions;
- verifies that serialized secondary values equal the caller-supplied secondary values;
- transcript-binds secondary values before `γ` is sampled.

The theorem above covers the primary opening vector. A verifier component that supplies nonempty secondary claims must also verify an external relation reducing those secondary claims to the primary vector or to another already-checked terminal relation. Block/STARK callers perform this composition before relying on secondary values.

Implementation anchors:

```text
noid_fri_binius/src/mixed_open.rs       EvalClaim, verify_mixed_opening
noid_stark/src/interleaved.rs
noid_block/src/lib.rs
```

---

## 6. FROST-GKR / KillShot soundness

FROST-GKR proves Poseidon2b execution traces over `GF(2^128)`. The relevant binary-tower property is that Frobenius squaring is linear, so the Poseidon2b S-box can be represented as:

```text
x^7 = x * x^2 * x^4.
```

This gives a native degree-7 S-box relation. With equality-polynomial and selector factors, the unified sumcheck round polynomial has degree 9.

For the unified relation:

```text
Σ_y U(y) * [C1(dec(y)) + ρ*C1'(dec(y)) + ρ^2*C2(y)] = 0,
```

where:

```text
C1  = S-box relation, degree 7
C1' = round-constant relation, degree 2
C2  = MDS transition relation after change of variables
```

If any of the three batched constraint families is nonzero, random batching by `ρ` fails with probability at most:

```text
3 / 2^128.
```

For 15 rounds of degree-9 sumcheck, the Schwartz-Zippel bound is:

```text
15 * 9 / 2^128.
```

Thus the unified relation error is bounded by:

```text
ε_unified ≤ (3 + 15*9) / 2^128 = 138 / 2^128.
```

The Auth/Spine proof includes additional shift and batch-evaluation reductions. The conservative per-subproof bound used by this audit is:

```text
ε_GKR ≤ 348 / 2^128 ≈ 2^-120.
```

Implementation anchors:

```text
noid_gkr/src/spine_killshot.rs
noid_gkr/src/auth_killshot.rs
noid_gkr/src/auth_killshot_sweep.rs
noid_gkr/SPEC.md
```

Implementation tests:

```text
cargo test -p noid_gkr --release

Tests include:
  auth_mle_opening_roundtrip
  auth_mle_opening_rejects_wrong_value
  auth_mle_multi_opening_roundtrip
  auth_mle_multi_opening_rejects_wrong_value
```

---

## 7. Transaction logic and wallet proof boundary

Wallet proofs are stateless with respect to live chain state. They prove ownership and internal transaction consistency. Live-slot availability is checked at block/state-binding level.

Public transaction inputs contain:

```text
slot_index, value, owner, auth_tag, valid
```

They do not contain `spend_secret`. Nullifiers are public transaction-body hashes rather than hashes of wallet secrets.

For sweep transactions, secret-bearing Auth witness slices are not part of the public logic wire shape. The public proof surface contains source-bound proof artifacts, not raw AuthGKR witness tables.

Implementation anchors:

```text
noid_tx/src/wire.rs
noid_tx/src/intent.rs
noid_stark/tests/sweep_logic_proof.rs
```

Implementation tests:

```text
cargo test -p noid_tx --release
cargo test -p noid_stark --release

Tests include:
  spend_secret_absent_from_wire
  sweep_auth_slices_are_not_part_of_logic_wire_shape
  sweep_logic_proves_and_verifies_25_live_inputs
```

---

## 8. Block aggregation and state transition

### 8.1 Block validation pipeline

The validation path for a user-transaction block is:

```text
Block + BlockProof + BlockAuthSidecar
  -> cheap consensus/header/resource checks
  -> reconstruct public inputs from TxBody
  -> reconstruct ordered per-segment state-delta claims from TxBody and pre-state
  -> verify canonical BlockProof
  -> verify pre/post source-bound segment MLE openings
  -> apply_state_delta
  -> atomic MDBX commit
```

Implementation anchors:

```text
noid_block/src/validate.rs              validate_block_from_network, validate_block_full
noid_chain/src/storage/mdbx_context.rs  MdbxChainContext::apply_next_block
noid_chain/src/block.rs                 apply_state_delta
```

### 8.2 Bucket aggregation

Standard and sweep transactions are aggregated in shape-specific buckets. For each nonempty bucket, the verifier checks:

1. bucket transaction coverage and order;
2. canonical public inputs reconstructed from `TxBody`;
3. wallet logic proof / AuthGKR / SpineGKR outputs;
4. bucket algebraic terminal relation;
5. source-bound FRI-Binius mixed opening.

Block bucket terminal compression flattens row×column MLE data into one committed column:

```text
flat[row + (col << log_len)] = original_bucket_col[col][row]
commitment.n_cols            = 1
commitment.log_rows          = log_len + log_cols
```

A column-axis sumcheck reduces the terminal linear functional

```text
S = Σ_col coeff[col] * value_col(r_block)
```

to one flattened opening at

```text
flat_point = (r_block, r_col),
```

with terminal equality

```text
coeff(r_col) * flat(flat_point) = column_final_claim.
```

This removes the large `all_openings` vector from block bucket terminal checks while keeping the same mixed-opening machinery and source-bound compact FRI.

Implementation anchors:

```text
noid_block/src/lib.rs
  build_flattened_bucket_column
  bucket_terminal_coefficients
  prove_bucket_linear_terminal_opening
  verify_bucket_linear_terminal_opening
```

Implementation tests:

```text
cargo test -p noid_block --release

Tests include:
  sweep_bucket_rejects_auth_capsule_pcs_value_tampering
  sweep_bucket_rejects_mixed_opening_tampering
```

### 8.3 Canonical transaction-to-state bridge

For every non-coinbase transaction, the verifier reconstructs from the canonical `TxBody`:

```text
tx_body_hash
claims_commitment
fee
live input/output counts
shape id
activation/deactivation bits
slot/value/owner/action claims
```

`validate_public_inputs_for_tx` rejects if bucket public inputs disagree with this canonical reconstruction.

The verifier constructs NativeDelta segment claims from the sequential public state view:

```text
read(slot) = overlay[slot] if changed earlier in the block
             else pre_state.slot(slot).
```

For a live input:

```text
read(inp.slot_index) = (Block128(inp.value), inp.owner_hi, inp.owner_lo).
```

For a live output before applying same-transaction updates:

```text
read(out.slot_index) = EMPTY.
```

Only after these equalities hold are segment claims admitted to the state-delta verifier. The verifier does not substitute state-opened owner/value data into a transaction's claim list; the claim list is determined by the transaction body.

Implementation anchors:

```text
noid_block/src/validate.rs    NativeDelta claim reconstruction and state precondition checks
noid_block/src/lib.rs         NativeDelta MLE opening verification, SegmentMleOpening
```

### 8.4 Segment identity and native state-delta binding

For one dirty segment `s`, let the verifier-reconstructed ordered claim list be

```text
Q_s = (q_0, ..., q_{t-1}).
```

Each claim contains:

```text
local_slot, value, owner_hi, owner_lo, is_spend, is_mint.
```

The verifier reconstructs the set of dirty segment IDs from the canonical block body and the pre-state overlay. Iteration is in strictly increasing segment order. For the `k`-th segment, the proof must contain pre/post openings whose segment identity equals the verifier-reconstructed segment:

```text
pre_state_openings[k].seg_id  = s
post_state_openings[k].seg_id = s.
```

The evaluation point and RLC challenge are not prover supplied. They are derived as

```text
(r_s, γ_s) = FS(
    DOMAIN_TAG_STATE_DELTA_EVAL,
    PROTOCOL_VERSION_Q,
    prev_state_root,
    new_state_root,
    s,
    k,
    n_tx,
    eff_log
).
```

The verifier requires both serialized openings to use `r_s`:

```text
pre_state_openings[k].eval_point  = r_s
post_state_openings[k].eval_point = r_s.
```

For each lane `ℓ ∈ {value, owner_hi, owner_lo}`, define the verifier-computed delta polynomial

```text
D_ℓ(x) = Σ_{q ∈ Q_s} eq_x(q.local_slot) * delta_ℓ(q),
```

where a spend contributes the removed value/owner tuple and a mint contributes the inserted value/owner tuple. The native state-delta acceptance equation is

```text
new_opening_ℓ = prev_opening_ℓ + D_ℓ(r_s).
```

Because `F` has characteristic 2, the `+` operator is the algebraic XOR delta. If a fixed claimed three-lane segment transition differs from the verifier-reconstructed transition, then for at least one lane the difference is a nonzero multilinear polynomial in `r_s` of individual degree at most one and total degree at most `eff_log`; by Schwartz-Zippel,

```text
Pr[wrong complete segment delta passes native point check] ≤ eff_log / 2^128.
```

The aggregate budget below uses the more conservative lane-union term `3 * eff_log / 2^128`, matching the implementation surface where value, owner-high, and owner-low lanes are checked independently at the same transcript-derived point.

The pre/post lane values used in the equation are themselves accepted only if all of the following hold:

```text
verify_mixed_opening(pre.commitment,  r_s, ..., pre.opening)  = pre.lane_values
verify_mixed_opening(post.commitment, r_s, ..., post.opening) = post.lane_values
cap_to_seg_root_with_depth(pre.commitment.cap,  eff_log) = pre.seg_root
cap_to_seg_root_with_depth(post.commitment.cap, eff_log) = post.seg_root
MerkleRoot(pre.seg_root,  index=s, siblings=pre.merkle_siblings)  = prev_state_root
MerkleRoot(post.seg_root, index=s, siblings=post.merkle_siblings) = new_state_root
```

Thus the segment identifier is bound three times: by verifier-reconstructed ordering, by Fiat-Shamir derivation of `r_s`, and by the Merkle leaf index used to connect each segment root to the global state root.

Implementation anchors:

```text
noid_block/src/validate.rs
  NativeDelta claim reconstruction and state precondition checks

noid_block/src/lib.rs
  NativeDelta MLE opening verification
  SegmentMleOpening

noid_block/src/channel.rs
  state_binding_eval_point_and_gamma

noid_chain/src/fri_state.rs
  merkle_root_from_leaf
```

Implementation tests:

```text
cargo test -p noid_block --release

Tests include:
  common_state_binding_rejects_cross_shape_double_spend
  native_state_delta_rejects_wrong_post_lane_before_opening_verify
  native_state_delta_rejects_tampered_segment_id_before_opening_verify
```

### 8.5 Header/proof/sidecar binding

For user-transaction blocks, the header binds the canonical proof and public Auth sidecar:

```text
block.header.proof_transcript_hash = block_recursive_claim_hash(BlockProof)
block.header.witness_root          = block_auth_sidecar_root(block, sidecar)
proof.meta.prev_block_state_root   = parent.state_root
proof.meta.new_state_root          = block.header.state_root
```

`validate_block_from_network` checks proof, sidecar, and combined size caps before proof deserialization, then checks the header/proof/sidecar bindings before accepting the proof result.

Coinbase-only blocks are the only no-user-proof exception. They contain no user slot claims and use the canonical stub/header path plus deterministic coinbase delta.

### 8.6 Theorem 2: accepted block implies a valid state transition

**Claim.** For a user-transaction block accepted by `validate_block_from_network` and committed by `MdbxChainContext::apply_next_block`, either the committed state transition equals the verifier-reconstructed transaction claims applied to the parent state, or one of the following events occurs:

```text
- a transaction/bucket proof verifies falsely;
- a source-bound mixed opening verifies falsely;
- a native state-delta identity or pre/post segment MLE opening verifies falsely;
- a header/proof/sidecar binding hash collides;
- the atomic storage layer violates its commit semantics.
```

**Proof sketch.** The verifier reconstructs public transaction claims from `TxBody`, not from prover-chosen state openings. Bucket proofs bind wallet logic outputs and terminal algebraic claims to these public inputs. For every dirty segment, the verifier checks the native random-point state-delta equation and binds its pre/post lane values to source-bound segment MLE openings under `prev_state_root` and `new_state_root`. The block proof metadata binds the parent state root and new state root, and the header binds the proof transcript and public sidecar. Therefore any accepted block whose committed delta differs from the reconstructed delta must break at least one of those checked relations or the underlying storage commit assumption.

---

## 9. Recursive chain proof

`RecursiveBlockAir` accumulates block-level claims and pins the previous state root from the externally verified header. The chain accumulator folds:

```text
inner       = compress(block_hash, canonical_chain_claim)
chain_hash  = compress(prev_chain_hash, inner)
```

A forged recursive transition must either:

```text
- satisfy an invalid recursive AIR zero-check;
- mismatch the externally verified header/proof transcript claim;
- collide the accumulator hash.
```

Using the zero-check degree budget, the conservative bound is:

```text
ε_recursive ≤ 32 / 2^128 + 2^-128 ≈ 2^-123.
```

Implementation anchors:

```text
noid_recursive/src/air.rs
noid_recursive/src/accumulator.rs
noid_recursive/src/verify.rs
```

---

## 10. Storage retention and state sync

The storage layer separates consensus-verifiable history from raw payload retention. Accepted user blocks are proof-verified before commit; the header chain and recursive proof carry the accumulated state transition claim after raw block bodies and proofs leave the retained body window.

### 10.1 Retention policy

```text
headers:               retained without historical pruning
recursive proof:       retained as latest/single entry plus covered height
retained block bodies: FINALITY_DEPTH = 18
block proofs:          retained until min(finality cutoff, recursive proof height) passes them
block auth sidecars:   FINALITY_DEPTH = 18
undo logs:             FINALITY_DEPTH = 18
nullifiers / tx idx:   ANCHOR_DEPTH = 144
```

Relevant consensus constants:

```text
FINALITY_DEPTH = 18
ANCHOR_DEPTH   = 144
```

At `BLOCK_TIME = 15s`, the anchor window is approximately 36 minutes under nominal timing. `ANCHOR_DEPTH` bounds nullifier and transaction-index retention for the valid transaction anchor window. MDBX pruning removes public Auth sidecars at finality, but removes `BlockProof` bytes only after the block is both finalized and covered by the stored recursive proof height; this avoids racing the background recursive updater.

### 10.2 Snapshot manifest acceptance predicate

A snapshot manifest contains:

```text
tip_height, tip_hash, log_slots, eff_log,
segment_ids[0..k), segment_roots[0..k),
recent_headers, nullifier_blocks.
```

Let

```text
N = 2^(log_slots - eff_log)
EncodedSegmentLen(e) = 5 + 2^e · 3 · 16 bytes
```

where `5` bytes encode `(effective_log_seg: u8, n_elems: u32)` and the three state lanes are `(value, owner_hi, owner_lo) ∈ F^3` per slot. The manifest is eligible for segment download only if all of the following predicates hold:

```text
len(segment_ids) = len(segment_roots)
0 <= segment_ids[j] < N for every j
segment_ids are strictly increasing
len(segment_ids) <= min(N, MAX_SNAPSHOT_MANIFEST_SEGMENTS)
EncodedSegmentLen(eff_log) <= MAX_SEGMENT_BYTES
```

The sparse segment-root table defines leaves

```text
L_i = segment_roots[j]                 if segment_ids[j] = i
    = ZeroSegmentRoot(eff_log)         otherwise,
```

and the reconstructed snapshot state root is

```text
SparseRoot(log_slots, eff_log, segment_ids, segment_roots)
  = MerkleRoot(L_0, ..., L_{N-1}).
```

For `N = 1`, the sparse root is the single leaf. For `N > 1`, internal nodes use the same Poseidon2b compression tree as the segmented state root.

The node accepts the manifest only if recursive/header verification anchors the snapshot tip and

```text
SparseRoot(log_slots, eff_log, segment_ids, segment_roots)
  = tip_header.state_root
full_block_hash(tip_header) = tip_hash.
```

Thus every downloadable segment ID is paired with a segment root before any segment payload is trusted.

### 10.3 Segment response acceptance predicate

For each segment response, before insertion into the collected snapshot set, the node requires:

```text
response.segment_id is pending and appears in authenticated segment_ids
number of outstanding segment requests <= MAX_INFLIGHT_SEGMENTS
len(response.data) = EncodedSegmentLen(response.eff_log)
len(response.data) <= MAX_SEGMENT_BYTES
response.eff_log = manifest.eff_log
decode_segment(response.data) succeeds with exact length and n = 2^eff_log
encoded_eff_log = response.eff_log
compute_segment_root(decoded_columns) = segment_roots[index(response.segment_id)]
```

Only decoded `SegmentColumns` satisfying this predicate are retained for snapshot application. Raw bytes that fail any predicate are discarded. Snapshot byte volume is therefore determined by the authenticated populated segment set and exact canonical segment encoding; it is not restricted by a fixed total-byte protocol cap. For the production segment size `eff_log = 16`,

```text
EncodedSegmentLen(16) = 5 + 65,536 · 48 = 3,145,733 bytes.
```

Network in-flight payload exposure is bounded by

```text
MAX_INFLIGHT_SEGMENTS * MAX_SEGMENT_BYTES = 64 MiB.
```

Snapshot application receives only decoded segment columns whose FRI segment root matches the manifest root table, and the manifest root table reconstructs the snapshot tip state root.


Implementation anchors:

```text
noid_p2p/src/protocol.rs                 GetStateManifestResponse, GetStateSegmentResponse
noid_p2p/src/network.rs                  manifest/segment server caps
noid_node/src/main.rs                    manifest selection, recursive/header anchoring, segment checks
noid_chain/src/segmented_state.rs        sparse_state_root_from_segment_roots
noid_chain/src/storage/serial.rs         decode_segment, encoded_segment_len_for_eff_log
noid_chain/src/storage/mdbx_context.rs   apply_state_snapshot
```

Implementation tests:

```text
cargo test -p noid_chain sparse_manifest_root_matches_segmented_state_root -- --nocapture
cargo test -p noid_chain encoded_segment_size -- --nocapture
```

---

## 11. Wire, memory, and decode caps

### 11.1 Cap values

Caps are centralized in:

```text
noid_chain/src/consensus/wire_limits.rs
```

They are resource-safety parameters, not cryptographic soundness parameters.

```text
TX / wallet:
  MAX_TX_INTENT_BYTES_GLOBAL          = 512 KiB
  MAX_STANDARD_TX_INTENT_BYTES        = 384 KiB
  MAX_SWEEP_TX_INTENT_BYTES           = 384 KiB

Mempool:
  MAX_MEMPOOL_TXS                     = 1024
  MAX_MEMPOOL_BYTES                   = 384 MiB
  MAX_MEMPOOL_SYNC_TXS                = 128
  MAX_MEMPOOL_SYNC_BYTES              = 16 MiB

Block / proof payloads:
  MAX_BLOCK_BYTES                     = 1 MiB
  MAX_BLOCK_PROOF_BYTES               = 32 MiB
  MAX_BLOCK_AUTH_SIDECAR_BYTES        = 32 MiB
  MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES  = 48 MiB

P2P:
  GOSSIP_MAX_TRANSMIT_BYTES           = 2 MiB
  INLINE_BLOCK_GOSSIP_THRESHOLD       = 1 MiB
  MAX_RECURSIVE_PROOF_BYTES           = 64 KiB
  MAX_HEADER_BYTES                    = 512 B
  MAX_SEGMENT_BYTES                   = 8 MiB

Snapshot sync:
  MAX_SNAPSHOT_MANIFEST_SEGMENTS      = 65,536
  MAX_INFLIGHT_SEGMENTS               = 8

Orphans:
  MAX_ORPHAN_POOL                     = 36
  MAX_ORPHAN_POOL_BYTES               = 128 MiB

RPC:
  MAX_RPC_RECEIPT_BYTES               = 128 KiB
  MAX_RPC_SALT_BYTES                  = 256 B
```

Consensus block limits:

```text
BLOCK_MAX_TXS = 256
BLOCK_TIME    = 15 seconds
```

Block construction policy may choose fewer transactions than the consensus maximum. Validators accept blocks that satisfy the consensus cap and all proof/resource checks.

The combined proof+sidecar cap is a worst-case validity and denial-of-service ceiling, not a target average payload. At the cap,

```text
48 MiB / 15 s = 3.2 MiB/s ≈ 25.6 Mbit/s.
```

This is a pull-serving capacity bound for maximum-size blocks. Gossipsub propagation is separately bounded:

```text
INLINE_BLOCK_GOSSIP_THRESHOLD = 1 MiB
GOSSIP_MAX_TRANSMIT_BYTES     = 2 MiB.
```

Blocks above the inline threshold are propagated as compact header announcements and fetched by request/response.

### 11.2 Enforcement correspondence

| Surface | Enforcement |
| --- | --- |
| RPC hex input | `noid_rpc/src/server.rs` checks maximum hex characters before `hex::decode` for tx intent, block, block proof, auth sidecar, receipt, and salt. |
| Mempool admission | `noid_mempool/src/pool.rs` checks global and shape-specific transaction caps before body-hash recomputation and LogicProof verification and checks total retained bytes before final insertion. |
| Core mempool byte accounting | `noid_chain/src/mempool.rs::total_intent_bytes`. |
| P2P transaction gossip | `noid_p2p/src/network.rs` and `noid_node/src/main.rs` use the shared transaction intent cap before decode. |
| P2P inline/pulled blocks | Block body, proof, sidecar, and combined proof+sidecar caps are checked before forwarding to node validation. |
| Block validation | `noid_block/src/validate.rs::validate_block_from_network` checks proof and sidecar caps before `bincode::deserialize`. |
| Mempool sync | Server and client truncate by transaction count and total bytes. |
| Orphan pool | `noid_node/src/main.rs` evicts by count and retained bytes. |
| Snapshot sync | Manifest `segment_ids`/`segment_roots` shape, sparse-root equality to the tip header state root, segment byte caps, exact decode, per-segment `eff_log`, and per-segment FRI root equality are checked before collection/apply. |
| Gossipsub | Large blocks use compact announce + pull; only small inline payloads are gossiped. |

### 11.3 Theorem 3: bounded pre-verification resource exposure

**Claim.** For the surfaces listed in Section 11.2, an unauthenticated peer or RPC caller cannot force the node to decode, allocate, store, or verify a payload above the corresponding cap before the cap check is applied.

**Proof sketch.** The shared constants in `wire_limits.rs` are imported by RPC, P2P, mempool, node, and block validation paths. The relevant checks occur on byte length or hex-character length before expensive operations: `hex::decode`, `bincode::deserialize`, proof verification, mempool insertion, orphan retention, or snapshot segment collection. Snapshot sync additionally authenticates the manifest segment-root table against the snapshot tip state root and checks each segment root before inserting decoded columns into the collected snapshot set. The tests in `wire_limits.rs` assert ordering relationships among caps, saturating combined proof+sidecar arithmetic, and shape-specific transaction cap consistency.

Implementation tests:

```text
cargo test -p noid_chain wire_limits --release

Tests:
  production_wire_caps_are_ordered
  proof_sidecar_combined_cap_is_saturating
  tx_shape_caps_are_below_global_cap
```

### 11.4 Measured margin

Benchmark observations:

```text
Standard4x8 wallet bundle: ~288–291 KiB
Sweep25x2 wallet bundle:   ~284–285 KiB

Current largest `block_scaling` row, 100 standard-shape tx fixture mix:
  full block proof:       10.75 MiB
  public Auth sidecar:    11.80 MiB
  proof + sidecar total:  22.55 MiB
```

These measurements fit under configured caps:

```text
tx intent cap by shape: 384 KiB
block proof cap:        32 MiB
proof+sidecar cap:      48 MiB
```

The measurements are not cryptographic assumptions. They show that the measured proof sizes fit inside the configured resource envelope.

---

## 12. Aggregate soundness budget

The main algebraic and hash-based terms are:

| Component | Bound | Approximate bits |
| --- | ---: | ---: |
| FROST-GKR unified relation | `138 / 2^128` | ~120 |
| FROST-GKR full subproof including shift/batch-eval reductions | `348 / 2^128` | ~120 |
| Transaction AIR zero-check | `55 / 2^128` | ~122 |
| Native state-delta point check | exact fixed-vector term `eff_log / 2^128`; conservative budget `3 * eff_log / 2^128` per dirty segment, plus source-bound pre/post opening terms | ~122 per segment for `eff_log = 16` |
| Recursive block AIR zero-check | `32 / 2^128` | ~123 |
| Source-bound mixed opening vector random linear combination | `(m - 1) / 2^128` plus source/FRI terms, with `m <= 256` | at least ~120 |
| Tensor/source query binding | targeted around `2^-128` | 128 |
| Compact FRI proximity | standard FRI bound for configured parameters, target `2^-128` | 128 |
| Poseidon2b / full-output Blake3 source-Merkle collision | `2^-128` target | 128 |
| `spend_secret` one-wayness through public hashes | `2^-128` target | 128 |

For one accepted block, let:

```text
N_gkr   = number of accepted FROST-GKR/KillShot subproofs
N_txair = number of accepted transaction/bucket AIR subclaims
N_mix   = number of accepted source-bound mixed openings
D_seg   = number of dirty state segments
```

A conservative block-level union bound has the form

```text
ε_block
  ≤ N_gkr   * ε_GKR
   + N_txair * ε_txair
   + N_mix   * (ε_hash + ε_tensor_query + ε_FRI + 255/2^128 + ε_FS)
   + D_seg   * (3*eff_log)/2^128
   + ε_recursive
   + ε_header_sidecar_hash.
```

The vector random-linear-combination term uses `255/2^128` because `verify_mixed_opening` rejects vector-mode commitments with `m > 256`. A repeated subclaim with at least 120-bit security remains above a 100-bit composed threshold for fewer than `2^20` repetitions. The consensus transaction cap, proof-byte caps, segment ID domain, and verifier shapes keep the number of repeated subclaims far below that threshold for a valid block.

The union bound does not require independent subprotocol transcripts. It requires that every prover message which a challenge must bind is absorbed before that challenge is sampled. The verifier code follows this absorb-before-squeeze discipline in STARK, GKR, compact FRI, and source-binding hooks.

---

## 13. Validation matrix

The following commands validate the referenced verifier and resource-cap code:

```text
cargo fmt --check
cargo check -p noid_chain -p noid_mempool -p noid_p2p -p noid_rpc -p noid_node -p noid_block
cargo test -p noid_chain --release
cargo test -p noid_block --release
cargo test -p noid_node --release
cargo test -p noid_mempool -p noid_p2p -p noid_rpc --release
cargo test --release -p noid_fri_binius --lib mixed_open::tests -- --nocapture
```

### 13.1 Source-bound mixed opening

Command:

```text
cargo test --release -p noid_fri_binius --lib mixed_open::tests -- --nocapture
```

Coverage includes:

| Property | Test reference |
| --- | --- |
| Honest source-bound opening verifies | valid round-0 source-binding path passes |
| Opening from a different committed source is rejected | A/A' attack test |
| Correct additive-NTT high TensorFold | high TensorFold matches `Code::new_parallel` |
| TensorFold layers match additive-NTT rebuild path | source-code high TensorFold layer test |
| Tampered compact-FRI round-0 root rejects | round-0 FRI root tamper test |
| Tampered `H` table rejects | source `H` tamper test |
| Upper half of `source_root` is authenticated | `source_root_upper_half_mutation_rejects` |
| Upper half of source Merkle siblings is authenticated | `source_sibling_upper_half_mutation_rejects` |
| Upper half of folded-layer roots is authenticated | `folded_root_upper_half_mutation_rejects` |
| One-column direct source expansion is sound | direct expansion pass/tamper test |
| Flat/GCM source-pair reduction equals batched code symbols | source-pair reduction test |
| Vector mode rejects widths exceeding the 120-bit cap | `vector_mode_rejects_columns_above_120_bit_cap` |

### 13.2 Wallet/auth boundary

Commands:

```text
cargo test -p noid_gkr --release
cargo test -p noid_tx --release
cargo test -p noid_stark --release
```

Coverage includes:

| Property | Test reference |
| --- | --- |
| `spend_secret` absent from serialized wire bytes | `spend_secret_absent_from_wire` |
| Auth PCS opening accepts honest value | `auth_mle_opening_roundtrip` |
| Auth PCS opening rejects wrong value | `auth_mle_opening_rejects_wrong_value` |
| Auth PCS multi-opening accepts honest values | `auth_mle_multi_opening_roundtrip` |
| Auth PCS multi-opening rejects wrong value | `auth_mle_multi_opening_rejects_wrong_value` |
| Sweep Auth slices are not part of public logic wire shape | `sweep_auth_slices_are_not_part_of_logic_wire_shape` |
| Sweep proof verifies with 25 live inputs | `sweep_logic_proves_and_verifies_25_live_inputs` |

### 13.3 Block aggregation and state binding

Command:

```text
cargo test -p noid_block --release
```

Coverage includes:

| Property | Test reference |
| --- | --- |
| Auth capsule PCS value tamper rejects | `sweep_bucket_rejects_auth_capsule_pcs_value_tampering` |
| Bucket mixed-opening tamper rejects | `sweep_bucket_rejects_mixed_opening_tampering` |
| Cross-shape double-spend rejects | `common_state_binding_rejects_cross_shape_double_spend` |
| Wrong post-state lane rejects before opening verify | `native_state_delta_rejects_wrong_post_lane_before_opening_verify` |
| Tampered segment ID rejects before opening verify | `native_state_delta_rejects_tampered_segment_id_before_opening_verify` |

### 13.4 Snapshot state sync

Command:

```text
cargo test -p noid_chain sparse_manifest_root_matches_segmented_state_root -- --nocapture
cargo test -p noid_chain encoded_segment_size -- --nocapture
```

Coverage includes:

| Property | Test reference |
| --- | --- |
| Sparse manifest root matches segmented state root | `sparse_manifest_root_matches_segmented_state_root` |
| Canonical encoded segment length respects the per-segment cap and full `u16` manifest namespace | `encoded_segment_size_matches_snapshot_caps` |
| Invalid/overflowing effective segment logs reject | `encoded_segment_size_rejects_impossible_logs` |

### 13.5 Resource caps

Commands:

```text
cargo test -p noid_chain wire_limits --release
cargo check -p noid_chain -p noid_mempool -p noid_p2p -p noid_rpc -p noid_node -p noid_block
```

Coverage includes:

| Property | Test reference |
| --- | --- |
| cap ordering is internally consistent | `production_wire_caps_are_ordered` |
| proof+sidecar cap uses saturating arithmetic | `proof_sidecar_combined_cap_is_saturating` |
| shape-specific tx caps do not exceed global cap | `tx_shape_caps_are_below_global_cap` |

### 13.6 End-to-end and performance gates

Representative commands:

```text
cargo bench --bench alice_sends_bob
NOID_PROVE_BLOCK_PROFILE=0 NOID_HOTSPOT_STANDARD_TX=100 NOID_HOTSPOT_SWEEP_TX=0 \
  cargo bench -p bench_prover --bench block_hotspots
```

These benches are used for operational sizing and performance-drift detection. They are not a substitute for the algebraic soundness tests above.

---

## 14. Security rationale for excluded constructions

Several constructions are outside the protocol because they do not establish the required source/oracle binding theorem under the project's transparency constraints.

### 14.1 Root/cap-only Fiat-Shamir absorption

Absorbing an additional root or cap into the transcript does not prove that compact FRI query symbols are derived from the committed source columns. Without query-level authentication, the prover can choose a standalone oracle consistent with the scalar FRI statement but inconsistent with the committed matrix.

### 14.2 Standalone compact FRI over a prover-chosen oracle

A standalone compact FRI proof can show that some oracle is close to a low-degree codeword and evaluates to a claimed scalar. It does not by itself prove that the oracle is the codeword of the committed source columns. The verifier therefore binds compact FRI round 0 to source-authenticated TensorFold checks.

### 14.3 FRI proximity fold as source TensorFold

`Code::fold_code` is the FRI proximity fold. It is not the additive-NTT transport of a message-domain MLE fold. The correct source TensorFold is:

```text
TensorFoldHigh(even, odd; b, r) = odd + even * (b + 1 + r).
```

### 14.4 Path-only column folding

A proof that reveals only one carried child and one sibling per column-fold layer does not bind the final folded value to all committed source columns. A malicious prover can make one sampled path locally consistent while choosing off-path folded-layer subtrees arbitrarily. The acceptance probability is then governed by path-hit probability rather than a 128-bit algebraic soundness term.

### 14.5 Curve-based or trusted-setup commitments

The proof stack remains transparent and binary-tower-native. Adding KZG/IPA/Pedersen/signature assumptions would change the trust model and is not part of the security argument.

---

## 15. Primary code index

| Area | Files |
| --- | --- |
| Source-bound mixed opening | `noid_fri_binius/src/interleaved_commit.rs`, `noid_fri_binius/src/mixed_open.rs`, `noid_fri_binius/src/compact_fri.rs` |
| FROST-GKR / KillShot | `noid_gkr/src/spine_killshot.rs`, `noid_gkr/src/auth_killshot.rs`, `noid_gkr/src/auth_killshot_sweep.rs`, `noid_gkr/SPEC.md` |
| STARK verifier and interleaved openings | `noid_stark/src/interleaved.rs` |
| Wallet wire format | `noid_tx/src/wire.rs`, `noid_tx/src/intent.rs` |
| Block proof / bucket aggregation | `noid_block/src/lib.rs` |
| Block validation / state bridge | `noid_block/src/validate.rs`, `noid_block/src/lib.rs`, `noid_block/src/channel.rs`, `noid_chain/src/fri_state.rs` |
| Recursive proof | `noid_recursive/src/air.rs`, `noid_recursive/src/accumulator.rs`, `noid_recursive/src/verify.rs` |
| Chain storage / retention | `noid_chain/src/storage/mdbx_store.rs`, `noid_chain/src/storage/mdbx_context.rs` |
| Wire/resource caps | `noid_chain/src/consensus/wire_limits.rs`, `noid_rpc/src/server.rs`, `noid_p2p/src/network.rs`, `noid_mempool/src/pool.rs`, `noid_node/src/main.rs` |
| Consensus parameters | `noid_chain/src/consensus/params.rs` |

This document specifies the protocol review surface: verifier code, cryptographic parameters, resource caps, and retention rules.
