# noid_block — Stage G: Block Folding (Deferred-Opening)

Status: design freeze (production). This is the binding spec for Stage G
of `ROADMAP2.md` Part II. Stage H (recursive chain) will replay every
algebraic step defined here in-circuit; deviations from this document
in code must come with an updated revision here.

## 1. Goal

Aggregate N validated per-tx witnesses into one `BlockProof` of bounded
size (≈55 KB) and bounded verifier cost (≈700 ms native at N=1000),
while preserving the soundness profile of the per-tx engine (128-bit).

The block proof does **not** carry N copies of the FRI mixed opening.
It carries:

1. One interleaved Merkle cap covering all columns of all transactions
   in the block.
2. N per-tx Spine/Auth Kill-Shot proofs (unchanged from Part I).
3. N per-tx **algebraic** STARK transcripts (zero-check + per-tx
   multipoint, no FRI).
4. One **block-level multipoint sumcheck** that fuses every per-tx
   `(r''_k, claim_k)` pair into a single `(r_block, claim_block)`.
5. One **single** FRI-Binius mixed opening of the block-wide
   interleaved commitment at `r_block`.

The verifier is native (no recursion yet) and forms the algebraic
substrate that Stage H will embed into an AIR.

## 2. Notation

- `N` = number of transactions in the block (1 ≤ N ≤ 1024).
- `log_N` = `ceil(log2(N))`, `N_pow := 1 << log_N` (rounded up).
- `log_rows = 13` = base log-length of all columns (matches per-tx).
- `n_air_k` = number of AIR columns in tx_k (currently constant 297;
  the design tolerates per-tx variation only via padding).
- `n_slice = 6` = boundary-slice columns appended per tx
  (4 Spine + 2 Auth, identical for every tx).
- `n_per_tx = n_air_k + n_slice` (= 303 today).
- `BLOCK_COLS` = the flat ordered list of all per-tx columns, total
  `N * n_per_tx` columns of length `2^log_rows` each.

## 3. Wire structure

```
BlockProof {
    meta:                BlockPublicMeta,         // see §4
    commitment:          InterleavedCommitment,   // one cap, n_cols = N*n_per_tx
    tx_pis:              Vec<PublicInputs>,       // length N, ordered
    tx_spine_proofs:     Vec<SpineProofKillShot>, // length N
    tx_auth_proofs:      Vec<AuthProofKillShot>,  // length N
    tx_algebraic:        Vec<AlgebraicStarkProof>,// length N (see §5)
    block_multipoint_rounds: Vec<RoundPoly>,      // degree-2 sumcheck, see §6
    mixed_opening:       MixedOpeningProof,       // ONE FRI, primary = r_block
}
```

`BlockPublicMeta`:

```
BlockPublicMeta {
    prev_block_state_root: [u8; 32],     // root before tx_0
    n_tx:                  u32,           // == tx_pis.len()
    n_air_per_tx:          u32,           // for shape validation
    n_slice_per_tx:        u32,           // == 6
    log_rows:              u32,           // == 13
    log_n:                 u32,           // == ceil(log2(N))
}
```

The block header binding (`proof_transcript_hash`) is computed by
`noid_chain::block::proof_transcript_hash` over the canonical encoding
of `BlockProof.transcript_seed()` — defined as the concatenation of the
cap bytes, every per-tx PI, and the squeezed `(z_k, r_k, r''_k,
r_block)` summary. This pins the proof bytes into consensus without
re-running FRI.

## 4. Public inputs and state continuity

For every adjacent pair `(tx_{k-1}, tx_k)`:

```
tx_pi[k].prev_state_root == tx_pi[k-1].new_state_root
```

and for `k = 0`:

```
tx_pi[0].prev_state_root == meta.prev_block_state_root
```

These are equality checks on the public inputs themselves; soundness is
trivial (the prover gains nothing by lying — the chain layer rejects
the block).

## 5. Per-tx algebraic STARK proof

`AlgebraicStarkProof` is `InterleavedStarkProof` minus
`commitment` and `mixed_opening`:

```
AlgebraicStarkProof {
    log_rows:               usize,
    base_openings:          Vec<Block128>,       // n_air_k entries, at r_point_k
    zero_check_rounds:      Vec<RoundPoly>,      // log_rows rounds
    shift_partials:         Vec<Vec<Block128>>,  // ladders for shifted cols
    multipoint_rounds:      Vec<RoundPoly>,      // log_rows degree-2 rounds
    slice_claimed_values:   Vec<Block128>,       // n_slice entries
    // Derived from transcript; not stored separately:
    //   r_point_k  = zero-check challenges (highest-var-first reversed)
    //   r_pp_k     = multipoint challenges
    //   primary point inside BLOCK_COLS: r_pp_global_k (see §6)
}
```

Two new public functions in `noid_stark::interleaved`:

```rust
pub fn prove_air_interleaved_algebraic<A: Air + ?Sized>(
    air: &A,
    padded_columns: &[Vec<Block128>],
    pi: &PublicInputs,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
    log_len: usize,
    channel: &mut Channel,           // shared block-wide channel
) -> (AlgebraicStarkProof, /*r_pp_k*/ Vec<Block128>, /*claim_k*/ Block128);

pub fn verify_air_interleaved_algebraic<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: &AlgebraicStarkProof,
    extra_transcript: &[Block128],
    slice_claims: &[SliceClaim],
    channel: &mut Channel,
) -> Result<(/*r_pp_k*/ Vec<Block128>, /*claim_k*/ Block128), VerifyError>;
```

Invariants enforced by these functions:

1. Same transcript order as Part I `prove_air_interleaved` up to (but
   not including) the `prove_mixed_opening` call.
2. The returned `claim_k` equals
   `Σ_i λ_k_i · m_k_i(r_pp_k)` — the multipoint terminal claim that
   the verifier of the per-tx path checks against the FRI opening
   reconstruction. Here we instead carry it to §6.
3. The `Channel` is left in a state that has absorbed everything
   through the end of the per-tx multipoint sumcheck; the caller is
   responsible for the next absorb (block-level RLC scalar squeeze).

The existing `prove_air_interleaved` is rewritten as:

```rust
fn prove_air_interleaved(...) -> InterleavedStarkProof {
    let (commitment, state) = prepare_or_reuse_commit(...);
    let mut channel = build_channel_with(commitment.cap, ...);
    let (alg, r_pp, _claim) = prove_air_interleaved_algebraic(..., &mut channel);
    let mixed = prove_mixed_opening(&state, &r_pp, secondary, ..., &mut channel, ...);
    InterleavedStarkProof { commitment, ..alg, mixed_opening: mixed }
}
```

Byte-identical TxProof, line-for-line same Fiat-Shamir order. Part I
test suite must keep passing without changes.

## 6. Block-level multipoint sumcheck

After all N algebraic per-tx proofs are recorded, the block channel
holds (in order) the cap, then for each k = 0..N-1:

- per-tx PI,
- spine/auth extras (`(r_spine_k, v_spine_k, r_auth_k, v_auth_k)`),
- zero-check rounds + base_openings,
- shift partials + slice_claimed_values,
- multipoint rounds.

We then enter the block-level reduction.

### 6.1 Geometry: global primary point

The block-wide interleaved commitment is over a polynomial of
`log_rows` variables. Per-tx primary points `r_pp_k` are `log_rows`
elements long. We do **not** widen the commitment to
`log_rows + log_N`; instead we treat the N column groups as N separate
sub-commitments to the same interleaved tree and combine their claims
by a **column-RLC**, not by row-stacking.

Concretely, for tx_k define the `n_per_tx`-wide vector of column
openings at `r_pp_k`:

```
M_k[i] := MLE(BLOCK_COLS[k*n_per_tx + i])(r_pp_k)
```

and the per-tx batched terminal claim (already verified inside
§5's algebraic path, by reconstructing it from `m_k` against
`final_claim_k = claim_k`):

```
claim_k = Σ_i λ_k[i] · M_k[i]
```

where `λ_k` are the standard per-tx Horner weights derived from the
per-tx `β_k` (already in §5). The block-level multipoint must verify
that the prover-supplied `M_k[i]` are consistent with the global
commitment, batched into ONE FRI opening.

### 6.2 Sumcheck statement

Absorb:

```
channel.observe_field_elem(BLOCK_MULTIPOINT_TAG);
channel.observe_field_elems(&flat([M_k[0..n_per_tx] for k in 0..N]));
let mu = channel.get_random_point();    // λ across tx
```

Build per-tx weights `mu^k`. The block-level statement is:

```
T_block := Σ_k mu^k · claim_k
         = Σ_k mu^k · Σ_i λ_k[i] · M_k[i]
```

Define for the sumcheck:

- pairs_a[k] = `mu^k · eq_ind(r_pp_k, x)`        (length 2^log_rows)
- pairs_b[k] = column-RLC `Σ_i λ_k[i] · BLOCK_COLS[k*n_per_tx + i]`
                                                 (length 2^log_rows)

The sumcheck over `H(x) = Σ_k pairs_a[k](x) · pairs_b[k](x)` reduces
to `T_block` on the hypercube, and yields `(r_block, h_block)` after
`log_rows` degree-2 rounds (reuses existing
`multipoint_batch::prove_multipoint_sumcheck`).

### 6.3 Terminal closure

Define the **block-batched polynomial** over BLOCK_COLS at `r_block`:

```
F(x) := Σ_{k,i} (mu^k · λ_k[i]) · BLOCK_COLS[k*n_per_tx + i](x)
```

The terminal claim from §6.2 satisfies

```
h_block == Σ_k pairs_a[k](r_block) · pairs_b[k](r_block)
       == Σ_k mu^k · eq_ind(r_pp_k, r_block) · Σ_i λ_k[i] · M_k[i](r_block)
```

The mixed FRI opening (next step) provides `M_k[i](r_block)` for every
column. The verifier reconstructs `h_block` from these openings and the
known scalars and checks equality.

### 6.4 Single FRI

One call to `prove_mixed_opening` with:

- `primary_point = r_block`
- `state = block-wide InterleavedProverState`
- `secondary_claims = []` (everything is at r_block now)

The mixed opening returns `all_openings` of length `N * n_per_tx` —
exactly the `M_k[i](r_block)` values. Note: these are evaluations at
`r_block`, **not** at the per-tx points `r_pp_k`. The mapping between
M_k[i] supplied to §6.2 sumcheck (as transcript observation) and these
new evaluations is enforced solely by the sumcheck terminal: any
mismatch fails §6.3's equality.

## 7. Soundness

| Step | Failure probability |
|---|---|
| Per-tx GKR Kill-Shots | 2^-128 each (Schwartz–Zippel) |
| Per-tx zero-check | 2^-128 |
| Per-tx multipoint | 2^-128 |
| State continuity | 0 (equality on public data) |
| Block-level λ-RLC | (N-1)/2^128 ≤ 2^-118 for N ≤ 2^10 |
| Block-level multipoint sumcheck | 2^-127 (degree-2, log_rows rounds) |
| Mixed FRI (γ-RLC + compact-FRI) | (n_block-1)/2^128 + 2^-128 |
| **Total per-block** | ≤ (N · n_per_tx + 3) / 2^128 ≈ 2^-110 at N=1024 |

For N ≤ 1024, n_per_tx ≤ 303: total margin > 110 bits — well above any
practical attack budget.

## 8. Performance budget (N=1000)

| Stage | Sequential | 8-core target |
|---|---|---|
| Build N traces | 700 ms × N (if reused from mempool: ≈0) | — |
| One interleaved_commit (N·n_per_tx cols × 2^13 rows) | ≈4.0 s | ≈600 ms |
| N × (spine + auth) GKR Kill-Shots | ≈100 ms × N | ≈12.5 s … (mempool-cached) |
| N × algebraic STARK | ≈20 ms × N | ≈2.5 s |
| Block multipoint sumcheck (log_rows=13, N pairs) | ≈200 ms | ≈40 ms |
| Single mixed FRI | ≈500 ms | ≈80 ms |
| **Total cold block prove** | (mempool-cached GKR) ≈3.5 s | ≈800 ms |

In production every tx arriving from mempool already carries a cached
Spine/Auth Kill-Shot (computed at submission time). The block prover
re-uses those bytes and only runs Steps {commit, algebraic-STARK,
block-multipoint, FRI}. Verify is single-threaded ≈ 600 ms at N=1000
(dominated by the N algebraic replays and the one FRI verify).

## 9. Non-goals (Stage G)

- No in-circuit verification. That is Stage H.
- No mempool conflict-resolution rules.
- No reduction of GKR Kill-Shot bytes (5.4 KB + 5.1 KB per tx remain).
  These dominate block size at large N; Stage K may compress them by
  λ-folding across tx, but it is **not** in this stage's scope.
  Therefore practical BlockProof size at N=1000 is dominated by the
  N×(spine+auth) GKR bytes (≈10 MB) — Stage G achieves the ≈55 KB
  goal **only** for the STARK + FRI portion. The recursive chain
  (Stage H) compresses the historical chain to ≈55 KB; per-block
  pre-recursion size is unconstrained.

## 10. Test matrix (Stage G acceptance)

| Test | Asserts |
|---|---|
| `block_one_tx_roundtrip` | BlockProof(N=1) verifies; state matches |
| `block_three_tx_roundtrip` | Happy path, chained roots |
| `block_rejects_broken_continuity` | tampered `tx_pi[1].prev_state_root` |
| `block_rejects_tampered_M_k` | M_k[i] post-prove flip → block-multipoint fails |
| `block_rejects_tampered_r_pp_k` | per-tx algebraic verify fails |
| `block_rejects_swapped_tx_order` | continuity fails OR FRI fails |
| `tx_proof_unchanged_after_refactor` | Byte-identical TxProof in Part I tests |
