# S1 / B2-G source-binding audit note

Status: **production path implemented; security-doc merge pending**.

This note is the detailed source material for the future rewrite of `docs/security.md` around the B2/G mixed-opening PCS fix. It is intentionally narrower than the full system security document: it records the bug, the implemented protocol, the equations, proof sketch, code references, tests, measured size impact, and remaining optimization/security-documentation tasks.

The implementation is in the existing production FRI-Binius path. There is no standalone Matrix/PASO/checkpoint backend and no curve/KZG/IPA/Pedersen dependency.

---

## 1. Bug closed

Old `mixed_open` accepted a proof of the form:

```text
exists low-degree C such that C(r) = Σ_i γ^i · v_i
```

where `v_i` were prover-supplied openings. What the system needs for production callers is:

```text
C(x) = Σ_i γ^i · committed_col_i(x)
```

for the columns committed by the `InterleavedCommitment` used by the verifier.

Attack shape:

```text
commit A
build all_openings and compact FRI oracle from A'
verify against Com(A)
```

This was possible because compact FRI's round-0 oracle was not authenticated back to the committed encoded source columns. Absorbing more caps/roots into Fiat-Shamir is not sufficient: the verifier must see query-level authentication from the FRI oracle boundary back to the source commitment.

Regression gate now active:

```text
noid_fri_binius/src/mixed_open.rs
  commit_to_a_open_from_a_prime_must_reject_after_s1_fix
```

---

## 2. Production invariant

For a production caller that uses `verify_mixed_opening` as intended:

```text
verify_mixed_opening(Com(cols), primary_point, secondary_claims, proof) accepts
```

implies, except with the stated soundness error, that the returned primary openings are the committed MLE values:

```text
returned[i] = committed_col_i(primary_point)
```

The standalone `mixed_open` source-binding theorem is about the **primary point**. `secondary_claims` are checked for shape/value hygiene inside `mixed_open` and are transcript-bound before `γ`, but their polynomial relation to other evaluation points is supplied by the caller's outer multipoint/slice reduction. Security documentation must not claim that `verify_mixed_opening` alone proves arbitrary secondary point openings.

Mandatory caller invariant:

```text
Any secondary_claim passed to mixed_open must already be tied to the primary-point
opening vector by the caller's algebraic multipoint/terminal protocol.
```

Current production callers satisfy this pattern:

- STARK/interleaved slice claims: `noid_stark/src/interleaved.rs`
- block bucket terminal compression: `noid_block/src/lib.rs`
- state segment openings: no secondary claims
- Auth PCS openings: no secondary claims

---

## 3. Implemented source commitment

Code:

```text
noid_fri_binius/src/interleaved_commit.rs
```

`InterleavedCommitment.cap.hashes` now contains:

```text
[legacy 32 segment cap hashes..., source_root]
```

where `source_root` is a 128-bit Blake3-truncated Merkle root, stored as a 32-byte `HashOutput` with the high 16 bytes zeroed.

Prover state now keeps the encoded source columns:

```rust
pub struct InterleavedProverState<'a> {
    pub raw_cols: Vec<&'a [Block128]>,
    pub log_rows: usize,
    pub n_cols: usize,
    pub encoded_cols: Vec<Vec<Block128>>, // encoded_cols[col][code_index]
    pub source_tree: ShortMerkleTree,
}
```

Source leaf layout:

```text
leaf(log_rows, n_cols, leaf_index) =
  H("PARANOID/INTERLEAVED-SOURCE-HIGH-PAIR-LEAF/128/v1"
    || log_rows || n_cols || leaf_index
    || col_0[pos0] || col_0[pos1]
    || ...
    || col_{n_cols-1}[pos0] || col_{n_cols-1}[pos1])
```

where:

```text
(pos0, pos1) = source_leaf_positions(log_rows, leaf_index)
pos1 = pos0 + 2^(log_rows - 1) within the same additive-NTT coset
```

Merkle compression domain:

```text
"PARANOID/SOURCE-BINDING-MERKLE-128/v1"
```

Security assumption for this source tree is 128-bit collision resistance for truncated Blake3 outputs. This matches the rest of the system's 128-bit target but must be listed explicitly in the final security assumptions.

---

## 4. Mixed-opening protocol after S1

Code:

```text
noid_fri_binius/src/mixed_open.rs
noid_fri_binius/src/compact_fri.rs
```

Proof structs:

```rust
pub struct MixedOpeningProof {
    pub all_openings: Vec<Block128>,
    pub fri_proof: CompactEvalProof,
    pub source_proof: SourceBindingProof,
}

pub struct SourceBindingProof {
    pub h_evals: Vec<Block128>,
    pub folded_roots: Vec<ShortHash>,
    pub source_symbols: Vec<Block128>,
    pub source_merkle_batch: ShortBatchedMerkleProof,
    pub folded_queried_symbols: Vec<Vec<(Block128, Block128)>>,
    pub folded_merkle_batch: Vec<ShortBatchedMerkleProof>,
}
```

The compact FRI API gained query hooks:

```rust
compact_fri_prove_with_query_hook(..., before_queries)
compact_fri_verify_with_query_hook(..., before_queries)
```

The hook runs after compact FRI has absorbed its round roots and final codeword but before query indices are sampled. Source-binding roots/data are therefore part of the same query transcript.

---

## 5. Transcript order

For a caller that already absorbed `commitment.cap`:

```text
1. absorb MIXED_OPEN_TAG
2. absorb all_openings
3. squeeze γ
4. compact FRI:
   4.1 absorb primary_point
   4.2 absorb C(primary_point)
   4.3 squeeze tensor batching point β
   4.4 absorb per-round sumcheck oracle coefficients
   4.5 absorb per-round fri_roots and squeeze FRI fold challenges
   4.6 absorb final_codeword
5. source-binding hook:
   5.1 absorb MIXED_SOURCE_BINDING_TAG
   5.2 absorb h_evals
   5.3 absorb folded_roots as vector commitments
6. squeeze shared query indices
7. verify compact FRI Merkle/query checks
8. verify source Merkle/query/TensorFold checks using the same query indices
```

Relevant code:

```text
mixed_open.rs: prove_mixed_opening / verify_mixed_opening
compact_fri.rs: compact_fri_prove_with_query_hook / compact_fri_verify_with_query_hook
```

---

## 6. Algebraic equations

Let:

```text
F = GF(2^128)
N = 2^log_rows
cols_i: {0,1}^log_rows -> F
γ <- F after all_openings are absorbed
C(x) = Σ_i γ^i · cols_i(x)
```

The primary batched scalar checked by compact FRI is:

```text
C(primary_point) = Σ_i γ^i · all_openings[i]
```

### 6.1 Compact FRI tensor split

Compact FRI uses:

```text
tau = min(COMPACT_TAU, log_rows)
n_rounds = log_rows - tau
(primary_low, primary_high) = primary_point.split_at(n_rounds)
```

It computes upper partials:

```text
U[u] = C(u, primary_low),  u ∈ {0,1}^tau
C(primary_point) = Σ_u eq_{primary_high}(u) · U[u]
```

Then it samples the tensor batching point:

```text
β ∈ F^tau
```

and defines:

```text
H[j] = Σ_u eq_β(u) · C(u, j),  j ∈ {0,1}^{n_rounds}
g[j] = H[j] · eq_{primary_low}(j)
```

Compact FRI round 0 is the codeword:

```text
Code(g)
```

S1 binding requires this oracle to be derived from the committed source columns, not chosen standalone by the prover.

### 6.2 Source pair reduction

For each transcript-derived source query, the prover reveals a high-variable pair from every encoded committed column:

```text
(col_i_code[pos0], col_i_code[pos1]) for i = 0..n_cols-1
```

Verifier authenticates these symbols against `source_root`, then reduces them with the same `γ`:

```text
(c0, c1) = Σ_i γ^i · (col_i_code[pos0], col_i_code[pos1])
```

Implementation uses flat/GCM-basis CLMUL helpers for the hot loop:

```text
compute_horner_weights_flat
reduce_source_pair_flat
compute_batched_claim_flat
```

Code:

```text
noid_fri_binius/src/mixed_open.rs
```

### 6.3 Correct high-variable TensorFold

The source-binding fold is **not** `Code::fold_code`. `Code::fold_code` is the FRI quotient/proximity fold. Source binding needs the message-domain MLE fold transported through the additive NTT.

For additive-NTT pair symbols `(even, odd)` and coset-local basis element `b`:

```text
forward:
  even = u + v
  odd  = even · b + v

inverse:
  v = odd + even · b
  u = even + v
```

The MLE fold at challenge `r` is:

```text
fold_mle(u, v; r) = u + r · (u + v)
```

Transported to code symbols:

```text
TensorFoldHigh(even, odd; b, r)
  = odd + even · (b + 1 + r)
```

Implementation:

```rust
fn tensor_high_fold_pair(r, layer_log, leaf_index, s0, s1) -> Block128 {
    let coset = leaf_index >> (layer_log - 1);
    let basis_idx = coset + layer_log - 1;
    let basis = Block128::from(1u128 << basis_idx);
    s1 + (basis + Block128::ONE + r) * s0
}
```

Mandatory invariant test:

```text
TensorFoldHigh(Code(B), β) == Code(fold_highest_mle_eq(B, β))
```

Implemented as:

```text
noid_fri_binius/src/mixed_open.rs
  high_tensor_fold_matches_code_new_parallel
```

### 6.4 Binding to compact FRI round 0

The prover reveals `h_evals = H` directly for current production shapes. The verifier checks:

```text
H(primary_low) == compact_fri.initial_sumcheck_claim
```

Then it computes:

```text
g = H * eq_{primary_low}
root(Code(g)) == compact_fri.fri_roots[0]
```

Code:

```text
assert_source_h_matches_compact
```

For `n_rounds == 0`, the verifier checks the final codeword directly instead of `fri_roots[0]`.

Current production-size reason for direct `H` reveal:

```text
|H| = 2^(log_rows - tau)
```

The current code comments note common shapes around:

```text
block/Auth:    |H| = 8
state segment: |H| = 256
```

This is much cheaper than introducing a second low PCS for these paths.

---

## 7. Verifier checks

For each shared query index:

1. derive the source high-pair leaf index;
2. authenticate source leaf symbols against `source_root`;
3. compute the `γ`-reduced source pair `(c0, c1)`;
4. apply the first high TensorFold with `β[tau-1]`;
5. for every intermediate high-fold layer:
   - authenticate the layer pair against `folded_roots[layer]`;
   - check the carried symbol equals the previous fold output;
   - apply the next high TensorFold;
6. after all high folds, check the result equals `Code(H)` at the derived queried index;
7. independently check `Code(H * eq_right)` root equals compact FRI round-0 root;
8. run normal compact FRI query/fold/final-codeword checks.

This creates the required bridge:

```text
committed encoded source columns
  -> γ-reduced source code symbols
  -> high TensorFold under β
  -> Code(H)
  -> Code(H * eq_right)
  == compact FRI round-0 oracle
```

---

## 8. Proof sketch

Assumptions:

```text
A1. Short source Merkle and high-fold Merkle roots are binding up to ε_hash_128.
A2. Fiat-Shamir challenges are random-oracle samples after all bound data is absorbed.
A3. Compact FRI with COMPACT_NUM_QUERIES = 64 has proximity error ε_FRI.
A4. The additive-NTT TensorFold formula above is correct for Code::new_parallel.
A5. Schwartz-Zippel over GF(2^128).
```

The adversary can try three broad strategies.

### 8.1 Wrong primary opening vector

Let the true committed primary vector be:

```text
a_i = committed_col_i(primary_point)
```

and the proof vector be `v_i`. If any `v_i != a_i`, then:

```text
D(γ) = Σ_i γ^i · (v_i - a_i)
```

is a nonzero polynomial in `γ` of degree `< n_cols`, except for the degenerate case where the vector difference is all zero. Since `γ` is sampled after `all_openings` are absorbed:

```text
Pr[D(γ) = 0] <= (n_cols - 1) / 2^128
```

Conditioned on `D(γ) != 0`, compact FRI would need to prove a value different from the committed source-derived `C(primary_point)`, which is caught by the source-bound FRI relation except with the errors below.

### 8.2 Standalone FRI oracle from A'

If the prover builds `fri_roots[0]` from `A'` while the verifier commitment is `Com(A)`, then either:

- some source leaf authentication against `source_root(A)` fails;
- some TensorFold carried-symbol check fails;
- `Code(H * eq_right)` root differs from `fri_roots[0]`;
- or a Merkle collision / query-soundness failure occurs.

The active regression test `commit_to_a_open_from_a_prime_must_reject_after_s1_fix` exercises this exact attack shape.

### 8.3 Wrong H / wrong TensorFold layer

If revealed `H` is not the high-variable TensorFold of committed `C`, then `Code(H)` differs from the honest folded codeword. Because `Code::new_parallel` is a rate-1/4 code in this path, a nonzero message difference has codeword distance at least `1 - 1/4 = 3/4` under the standard RS-code distance assumption used by compact FRI. With `Q = 64` shared queries, the probability of missing all bad positions is bounded by:

```text
(1/4)^64 = 2^-128
```

up to Fiat-Shamir and hash-collision terms. The exact final security document should express this as the same code-distance/query bound used for compact FRI, rather than as a new independent assumption if it can be folded into A5.

### 8.4 Resulting primary-opening bound

For primary openings:

```text
Pr[accept && ∃i: returned[i] != committed_col_i(primary_point)]
  <= ε_hash_128
   + ε_tensor_query
   + ε_FRI
   + (n_cols - 1) / 2^128
   + ε_FS
```

With the current 64-query, rate-1/4 model:

```text
ε_tensor_query ≈ 2^-128
ε_FRI          ≈ 2^-128
```

The final `docs/security.md` should state the concrete union bound for each caller shape using its maximum `n_cols`.

---

## 9. Secondary-claim composition note

`MixedOpeningProof.all_openings` contains:

```text
primary openings for committed columns at primary_point
followed by secondary claim values
```

The verifier enforces:

```text
secondary_claim.col_index in range
secondary_claim.eval_point dimension matches
all_openings[n_cols + j] == secondary_claim.value
```

Those values are absorbed before `γ`, so they cannot be changed without changing the transcript. However, the source-binding FRI polynomial is built from the primary opening vector only:

```text
batched_claim = Σ_i γ^i · all_openings[i] for i < n_cols
```

Therefore security of secondary claims is caller-composed. In current STARK/interleaved code, the algebraic verifier returns a terminal identity that uses the same primary opening vector and the slice-claim values before calling `verify_mixed_opening`.

Code:

```text
noid_stark/src/interleaved.rs
  verify_air_interleaved
  verify_algebraic_inner
```

Audit rule:

```text
Do not introduce a production caller that passes nonempty secondary_claims
unless another checked relation reduces those claims to the primary-point vector.
```

---

## 10. Production integrations and optimizations already done

### 10.1 AuthGKR PCS source binding without raw slices

Code:

```text
noid_gkr/src/auth_pcs.rs
noid_gkr/src/auth_killshot.rs
noid_gkr/src/auth_killshot_sweep.rs
```

Auth capsules commit/open the three private AuthGKR MLE columns:

```text
state, s_in, s_out
```

with one `AuthMleMultiOpeningProof`, backed by source-bound `MixedOpeningProof`. Raw AuthGKR slices/tables are not serialized to network/block paths. Owned columns are zeroized on drop.

Tests:

```text
noid_gkr/src/auth_pcs.rs
  auth_mle_opening_roundtrip
  auth_mle_opening_rejects_wrong_value
  auth_mle_multi_opening_roundtrip
  auth_mle_multi_opening_rejects_wrong_value
```

### 10.2 Public AIR columns omitted from PCS/source binding

Code:

```text
noid_stark/src/interleaved.rs
```

Public columns remain in algebraic transcript/opening checks, but are not committed in the PCS source-binding surface. Verifier recomputes public column openings from `Air::public_columns()` at the terminal point.

Key functions:

```text
public_column_flags
public_openings_at_point
committed_air_indices_from_public_flags
verify_air_interleaved
```

Security condition:

```text
A column may be omitted from PCS only if it is verifier-derived as PublicColumn.
```

### 10.3 Sweep deterministic balance columns public-pinned

Code:

```text
noid_air/src/airs/bit_adder.rs
noid_air/src/airs/balance_gate.rs
noid_air/src/composition/sweep_logic.rs
noid_stark/tests/sweep_logic_proof.rs
```

Sweep deterministic balance selectors/operands/sum/carry/body payload columns are pinned as `PublicColumn`s. The test currently fixes the important shape invariant:

```text
SweepTxLogicAir public columns = 481
Sweep STARK committed columns = 1
```

Tests:

```text
sweep_auth_slices_are_not_part_of_logic_wire_shape
sweep_logic_proves_and_verifies_5_live_inputs
sweep_logic_proves_and_verifies_21_live_inputs
sweep_logic_proves_and_verifies_25_live_inputs
```

### 10.4 Block bucket terminal compression

Code:

```text
noid_block/src/lib.rs
```

Standard and sweep block buckets now flatten row×column MLE data into one committed column:

```text
flat[row + (col << log_len)] = original_bucket_col[col][row]
commitment.n_cols = 1
commitment.log_rows = log_len + log_cols
```

The bucket terminal linear form is reduced by a column-axis sumcheck:

```text
S = Σ_col coeff[col] · value_col(r_block)
```

Verifier receives column-sumcheck rounds, derives `r_col`, evaluates the coefficient table with `evaluate_flat_with_scratch`, and opens one flattened MLE point:

```text
flat_point = (r_block, r_col)
verify coeff(r_col) · flat(flat_point) == column_final_claim
```

This avoids serializing/source-binding a huge vector of bucket column openings in the common case.

Key functions:

```text
build_flattened_bucket_column
bucket_terminal_coefficients
prove_bucket_linear_terminal_opening
verify_bucket_linear_terminal_opening
```

### 10.5 Compact Merkle serialization cleanup

Code:

```text
noid_fri_binius/src/compact_fri.rs
noid_fri_binius/src/interleaved_commit.rs
```

`BatchedMerkleProof` and `ShortBatchedMerkleProof` serialize only sibling streams:

```rust
pub struct BatchedMerkleProof { pub siblings: Vec<HashOutput> }
pub struct ShortBatchedMerkleProof { pub siblings: Vec<ShortHash> }
```

Depth and query indices are verifier-derived from shape/transcript. Verifiers reject unused siblings.

### 10.6 NTT basis bug fixed

Code:

```text
noid_core/src/ntt.rs
```

A prior path silently skipped transforms when the basis was one short. The fix derives missing canonical basis elements instead of returning without a transform. This matters for source-binding tests because TensorFold correctness depends on the real `AdditiveNTT` layout.

### 10.7 Genesis/state root updated

Code:

```text
noid_chain/src/consensus/genesis.rs
noid_chain/src/fri_state.rs
```

Because the commitment cap now includes `source_root`, state segment roots and genesis changed.

Current constants:

```text
GENESIS_STATE_ROOT =
  6e7eb71415b4beea7239aca409ed0a80
  6b3b21d2f2b53f9638ff2f48cbcdbd34

GENESIS_NONCE = 15_108_031
```

Tests:

```text
genesis_state_root_matches_computed
genesis_nonce_satisfies_pow
```

---

## 11. Test checklist currently represented in code

Source-binding core:

```text
cargo test -p noid_fri_binius --release

source_pair_reduction_matches_batched_code_symbols
high_tensor_fold_matches_code_new_parallel
valid_secondary_claim_hygiene_passes
secondary_claim_value_mismatch_rejects_before_fri
secondary_claim_column_out_of_range_rejects_before_fri
secondary_claim_eval_point_dimension_mismatch_rejects_before_fri
commit_to_a_open_from_a_prime_must_reject_after_s1_fix
```

Auth PCS:

```text
cargo test -p noid_gkr --release

auth_mle_opening_roundtrip
auth_mle_opening_rejects_wrong_value
auth_mle_multi_opening_roundtrip
auth_mle_multi_opening_rejects_wrong_value
```

Sweep/wallet public-column and secret-surface guards:

```text
cargo test -p noid_stark --release
cargo test -p noid_block --release

sweep_auth_slices_are_not_part_of_logic_wire_shape
sweep_logic_proves_and_verifies_5_live_inputs
sweep_logic_proves_and_verifies_21_live_inputs
sweep_logic_proves_and_verifies_25_live_inputs
mixed_block_proof_does_not_serialize_spend_secret_bytes
sweep_bucket_rejects_auth_capsule_pcs_value_tampering
sweep_bucket_rejects_mixed_opening_tampering
sweep_bucket_rejects_aggregation_opening_tampering
common_state_binding_rejects_cross_shape_double_spend
native_state_delta_rejects_wrong_post_lane_before_opening_verify
standalone_state_binding_proves_and_verifies_for_sweep_only_path
```

Consensus/genesis:

```text
cargo test -p noid_chain --release

genesis_state_root_matches_computed
genesis_nonce_satisfies_pow
```

---

## 12. Bench snapshots recorded during this batch

Reproduce:

```sh
cargo bench --bench alice_sends_bob
cargo bench --bench block_scaling
```

Raw S1 source binding before size mitigations was not acceptable:

```text
Standard4x8 wallet bundle: ~310 KB
Sweep25x2 wallet bundle:   ~1.17 MB
100 standard block proof:  ~27.26 MB
```

After production mitigations in this branch:

```text
Standard4x8 wallet bundle: ~235–236 KB
  STARK:                   ~151–152 KB
  AuthGKR:                 ~82.6 KB

Sweep25x2 wallet bundle:   ~214–216 KB
  STARK:                   ~96–97 KB
  AuthGKR:                 ~113–115 KB
```

Block scaling snapshot:

```text
10 standard tx block proof:  ~1.89 MB
  standard bucket:           ~1.25 MB
  state binding:             ~655.64 KB

20 standard tx block proof:  ~3.18 MB
  standard bucket:           ~2.33 MB
  state binding:             ~875.91 KB

100 standard tx block proof: ~14.15 MB
  standard bucket:           ~10.52 MB
  state binding:             ~3.63 MB
```

Interpretation:

- S1 is now cryptographically bound but still expensive.
- Wallet sizes are back to a practical class after public-column and sweep reductions.
- 100-tx block proofs remain too large for a comfortable mainnet target.
- Dominant remaining standard-block cost is per-tx AuthGKR PCS/source-bound capsule duplication.

---

## 13. Remaining work before final `docs/security.md`

### 13.1 Full validation rerun

Run before final handoff:

```sh
cargo fmt --check
cargo test -p noid_fri --release
cargo test -p noid_fri_binius --release
cargo test -p noid_air --release
cargo test -p noid_gkr --release
cargo test -p noid_stark --release
cargo test -p noid_chain --release
cargo test -p noid_block --release
cargo test -p noid_recursive -p noid_mempool -p noid_node --release
cargo bench --bench alice_sends_bob
cargo bench --bench block_scaling
./scripts/live_multinode_scenarios.py
```

### 13.2 Proof-size / DoS caps

Need explicit production limits for:

```text
max wallet tx proof bytes
max block proof bytes
max bucket proof bytes
max tx count by shape
max P2P/RPC chunk size/count
```

Enforce in:

```text
mempool admission
block production
block validation
P2P/RPC decode
```

### 13.3 Remaining big-size wins

Likely highest-value production options:

1. Auth proof sidecar / DA dedup for block propagation and canonical block proof bytes.
2. Paired pre/post state mixed opening to reduce duplicated state binding openings.
3. Auth PCS prover-state reuse to avoid rebuilding `interleaved_commit` in `open_auth_mle_columns_committed`.
4. A deeper Auth protocol redesign that commits only `state` if it can be proven sound without reintroducing private witness surfaces.

Do not introduce standalone experimental PCS backends to solve these.

---

## 14. Rejected alternatives

Rejected for production S1:

```text
- root/cap-only Fiat-Shamir absorption;
- standalone compact_fri over prover-chosen oracle as the fix;
- Code::fold_code as source TensorFold;
- lowering COMPACT_NUM_QUERIES;
- curves / KZG / IPA / Pedersen / signatures;
- Matrix/PASO/checkpoint/backend zoo outside the production path;
- raw Auth witness/slices in block/network path;
- moving wallet secrets or secret-bearing witness tables to miner/full node.
```

`Code::fold_code` is especially important: it is correct for compact FRI proximity folding, but wrong for the source-binding TensorFold relation.
