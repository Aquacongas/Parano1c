# PARANOID — ROADMAP

From current implementation state to public testnet.

---

## Current State (Baseline)

The cryptographic engine is complete and tested:

```
noid_core         GF(2^128) tower, CLMUL/AVX2, MLE, sumcheck, NTT, transcript.
noid_poseidon2b   Poseidon2b native + AIR (perm, sponge, domain tags, compress).
noid_fri          Generic FRI (foundational dep: Channel, Blake3, NTT, code).
noid_fri_binius   Production PCS: interleaved commit, compact FRI, mixed opening.
noid_binius       Bit/byte packing for DA bandwidth reduction.
noid_gkr          Kill-Shot GKR: Spine (59-slot), Auth (20-slot), Merkle (32-slot).
noid_air          AIRs + gates + compositions. Production: TxLogicAir (Stage S).
noid_stark        STARK engine: prove_logic / verify_logic (Split GKR, Stage S).
noid_tx           TxBody, TxIntent, PublicInputs, C_claimed, wire serialization.
noid_chain        State (FriState), block header, blocks, DA packing, nullifier set.
noid_block        Block aggregation via deferred-opening (prove_block / verify_block).
bench_prover      Performance harness.
```

**Phase 1 (Stage S) — DONE:**
- Stateless architecture: TxLogicAir (no state columns), prove_logic / verify_logic.
- Epoch anchor replaces prev_state_root in tx_body_hash.
- C_claimed bridge (claims commitment) linking LogicProof to BlockStateBinding.
- BlockStateBinding native verification (noid_chain).
- NullifierSet rolling window.
- TxIntent wire format (spend_secret stripped from network payload).

**Phase 1.5 (Stage Q) — DONE:**
- Per-tx algebraic STARK fully parallelised (`rayon::par_iter`, Q.2b/Q.2c/Q.5).
- Per-tx independent Fiat-Shamir channels (`per_tx_algebraic_channel`, Q.1).
- Fixed columns zero-copy shared via `FixedColumns` (Q.2a).
- Merkle transcript reduction in Stage 6 (`merkle_reduce`, Q.4a).
- Parallel verifier: auth Kill-Shot + algebraic STARK all `into_par_iter()` (Q.5).
- Dedicated state-binding channel per segment (`state_binding_channel`, Q.4).

Performance (per-tx, Stage Q, implementation complete — benchmark pending re-measure):
- LogicProof (wallet): ~102 ms
- Block prove (100 tx, 8 cores): target <8 s (was ~43 s sequential)
- verify_block (100 tx, 8 cores): target <4 s (was ~15 s sequential)

What exists: proof math, state machine, block aggregation, wire formats,
  stateless wallet proof (LogicProof), block-level state binding.
What does NOT exist: networking, mempool, RPC, wallet CLI, mining,
  difficulty adjustment, consensus validation, node binary.

---

## Phase 1 — Stateless Architecture (Stage S) — **DONE**

**Goal:** Separate wallet-side logic proof from full-node-side state binding.
Light Node (wallet) proves only math (balance, auth, body).
Full Node proves state (Merkle openings, BlockStateBinding) and assembles BlockProof.
External Miner receives 248-byte block template header and brute-forces nonce.

### S.1 Epoch Anchor — ✅ DONE

Replace `prev_state_root` with `epoch_anchor` in tx body hash.

- `noid_tx::TxBody.epoch_anchor: Digest` ✅
- `hash_tx_body()` takes `epoch_anchor` as first arg ✅
- `ANCHOR_DEPTH = 6` defined in `noid_tx::types` ✅
- `SpineInputs` in `noid_gkr` updated ✅
- Wire format bumped (version history removed — no network yet) ✅

### S.2 Claims Commitment (C_claimed) — ✅ DONE

Wallet commits to claimed slot values without proving state.

- `compute_claims_commitment(inputs, outputs) -> Digest` in `noid_tx::claims` ✅
- Poseidon2b sponge under `TAG_CLAIMS` over `(slot_index, value, owner_hi, owner_lo)` ✅
- `claims_commitment: Digest` in `PublicInputs` ✅
- LogicProof absorbs C_claimed into Fiat-Shamir channel ✅
- Tamper any slot value → proof fails ✅ (tested)

### S.3 TxLogicAir — ✅ DONE

Pure-logic AIR (no FriStateOpen, no state columns).

- `noid_air::composition::tx_logic::TxLogicAir` ✅
- Contains: balance_gate, range_gate, tx_body_spine pin, selector gates ✅
- Does NOT contain: FriStateOpenAir, FriStateCombinerComposite ✅
- Note: `log_rows` stays at 13 (same as SPINE_LOG_ROWS); reducing to
  10-11 deferred — spine boundary pins require log_rows=13.

### S.4 LogicProof Pipeline — ✅ DONE

`prove_logic` / `verify_logic` in `noid_stark`.

- **Split GKR:** wallet proves AuthGKR only (needs spend_secret).
  SpineGKR is deferred to block-prover who has public SpineInputs. ✅
- `prove_logic(LogicWitness) -> LogicProof` ✅
- `verify_logic(air, pi, spine_inputs, auth_public, proof) -> Result<()>` ✅
- Auth/Spine bridge enforced: `auth_public.tx_body_hash == pi.tx_body_hash`,
  `expected_address[i] == spine_inputs.input_leaves[i][2..3]` ✅
- End-to-end roundtrip tested ✅

### S.5 BlockStateBinding — ✅ DONE

Block-level state binding (native, non-circuit).

- `noid_chain::state_binding::BlockStateBinding` ✅
- Opens all input/output slots, verifies pre-conditions ✅
- C_claimed bridge: recomputes from opened slots, checks equality ✅
- `BlockStateBindingAir` in `noid_air::airs::block_state_binding` ✅
- Integrated into `prove_block` via `StateBindingBlockWitness` ✅

### S.6 Integrated BlockProof — ✅ DONE

LogicProofs + BlockStateBinding aggregated in `prove_block`.

- `prove_block(prev_state_root, witnesses, state_binding)` ✅
- Full Node: verifies auth Kill-Shots → unified block spine Kill-Shot →
  algebraic STARK per tx → multipoint sumcheck → single FRI opening ✅
- State continuity: prev_block_state_root tracked in `BlockPublicMeta` ✅
- `noid_block::full_node::prove_block_full` for full-node use ✅

### S.7 Nullifier Set — ✅ DONE

- `noid_chain::nullifier::NullifierSet` ✅
- Rolling window of ANCHOR_DEPTH=6 blocks of tx_body_hashes ✅
- O(1) lookup, O(1) amortised insertion ✅
- Pruning on oldest block exit ✅

### S.8 TxIntent Wire Format — ✅ DONE

- `noid_tx::intent::TxIntent` ✅
- `encode()` uses `encode_public()` — spend_secret stripped from wire ✅
- `decode()` uses `decode_public()` — spend_secret → zero on received side ✅
- `spend_secret_absent_from_wire` test verifies bytes do not contain secret ✅
- Version byte removed (no network yet, no backward compat needed) ✅

---

```markdown
## Phase 1.5 — Parallel Per-Tx Algebraic STARK (Stage Q) — ✅ **DONE**

**Goal:** Reduce `prove_block` from ~43s to <8s at 100 tx (8 cores) by parallelizing
the per-tx algebraic STARK phase.

**Status:** All sub-tasks Q.1–Q.5 implemented. Benchmarks pending re-run on target hardware.

**Baseline (Stage S, before Q):**
- 100-tx block prove: ~43 s (sequential Stage 5)
- 100-tx block verify: ~15 s (sequential Stage 2b)
- Per-tx amortised prove: ~434 ms

### Problem Statement

Stage 5 of `prove_block` (`noid_block/src/lib.rs`) runs per-tx algebraic STARKs
sequentially on a shared Fiat-Shamir channel. Each tx takes ~615ms. For N=100:
`100 * 615ms = 61.5s` — exceeds the 60s block time.

The sequential channel works by chaining: challenge for tx[k+1] depends on proof[k].
This prevents parallel execution.

Furthermore, the underlying data structures (`Vec<Vec<Block128>>` for traces) cause 
severe allocation churn, cache misses, and memory duplication at scale, which will 
block scaling to 1024 tx even if parallelism is achieved.

### Solution: Independent Per-Tx Channels + Memory Topology

Replace the sequential block channel in Stage 5 with independent per-tx channels, each
deterministically seeded from `(prev_state_root, commitment_cap, tx_index)`.

Simultaneously, refactor the witness layout to eliminate per-tx duplication of fixed 
columns and prevent memory bandwidth collapse during parallel execution.

**Security argument:** After Stage 3 (interleaved commit), the Merkle cap cryptographically
binds ALL witness columns. The prover cannot change the witness after commit.
Zero-check challenges derived from `seed_k = H(state_root || cap || k)` are:
- Unpredictable before commit (cap depends on columns)
- Deterministic after commit (same seed → same challenges)
- Bound to the specific transaction (tx_index prevents cross-tx confusion)

This is non-adaptive soundness for committed witnesses — equivalent in strength to
adaptive (sequential) soundness because the witness is immutable post-commit.

Stage 6 (block-level multipoint sumcheck) remains sequential and provides the global
binding across all per-tx results. FRI opening (Stage 7) is unchanged.

### What Does NOT Change

- Privacy: `spend_secret` stays on wallet. `auth_gkr_channel()` is already independent.
- Auth GKR: Self-seeded, not affected.
- Unified Block SpineGKR: Seeded from `(cap)`, not affected.
- Block-level multipoint sumcheck (Stage 6): Remains sequential, binds all openings.
- FRI mixed opening (Stage 7): Unchanged.
- Verifier logic: Same as prover — uses `seed(state_root, cap, k)` per tx.
- Proof format: `BlockProof` struct unchanged (same fields, same sizes).
- Soundness level: 128-bit (Schwartz-Zippel over GF(2^128), challenges from cap).

### Performance Projection

| Metric (100 tx) | Before | After Q.2-Q.4 (8c) | After Q.5 (8c) | After Q.5 (16c) |
|-----------------|--------|---------------------|----------------|-----------------|
| prove_block     | 61.5s  | ~8s                 | ~8s            | ~4s             |
| verify_block    | 16.3s  | 16.3s               | ~3.6s          | ~2.7s           |
| proof size      | 2.02 MB| 2.02 MB             | 2.02 MB        | 2.02 MB         |

### Implementation Plan

#### Q.1 Per-Tx Channel Factory ✅ DONE

Create a deterministic channel constructor for per-tx algebraic STARKs.

- Add `fn per_tx_algebraic_channel(prev_state_root, cap, tx_index) -> Channel` to `noid_block`
- Full domain-separated seed sequence:
  1. `observe(DOMAIN_TAG_TX_ALGEBRAIC)` — fixed 128-bit constant, unique to this sub-protocol
  2. `observe(PROTOCOL_VERSION)` — `Block128::from(1u128)`, bumped on protocol changes
  3. `observe(state_root_hi)`, `observe(state_root_lo)` — block context binding
  4. `absorb_cap(cap)` — commitment binding (all columns)
  5. `observe(Block128::from(tx_index as u128))` — per-tx uniqueness
- Constants in `noid_block/src/lib.rs`:
  - `DOMAIN_TAG_TX_ALGEBRAIC: u128 = 0x5458_414C_4745_4252_4149_4332_3032_3600`
  - `PROTOCOL_VERSION_Q: u128 = 1`
- Stage 5b (BlockStateBindingAir) uses `tx_index = n_tx` as its domain separator
- **Done when:** factory produces deterministic channel; same inputs → same output; different tx_index → different challenges

#### Q.2a Trace Layout Separation ✅ DONE

Refactor the monolithic trace representation before parallelizing execution.

- **Problem:** Current implementation stores execution traces as `Vec<Vec<Block128>>`, mixing fixed columns (selectors, masks) and witness/runtime columns. This causes redundant duplication of fixed columns per tx, poor cache locality, and memory bandwidth collapse during parallel proving.
- **Required Refactor:** Replace monolithic trace with split storage:
  ```rust
  pub struct Trace {
      pub fixed_cols: Arc<Vec<Vec<Block128>>>, // Immutable, shared across all txs
      pub witness_cols: Vec<Vec<Block128>>,     // Tx-local, mutable
  }
  ```
  Alternative equivalent representation (e.g., `TraceView` with slices) is acceptable provided fixed columns are immutable/shared and witness columns are tx-local.
- **API Changes:** `noid_stark` AIR evaluator must accept split trace; `noid_air` composition evaluators must distinguish fixed/witness domains; `noid_block` Stage 5 must pass witness-only slices into per-tx workers.
- **Execution Rule:** Per-tx proving workers MUST only clone/access `witness_cols`. Fixed columns MUST be shared through `Arc`. No per-thread duplication allowed.
- **Done when:** Fixed columns are physically separated; Stage 5 parallel proving allocates O(witness) memory per tx; Algebraic evaluator works without rebuilding merged traces.

#### Q.2b Witness Generation Parallelization ✅ DONE

Parallelize the witness construction phase itself, not just the algebraic prover.

- **Problem:** Current roadmap only parallelizes algebraic proving. Witness assembly (`build_witness`) is still sequential, leaving a large CPU bottleneck before proving begins.
- **Required Change:** Replace sequential witness construction with `rayon` parallelism:
  ```rust
  let witness_bundle: Vec<_> = txs.par_iter()
      .map(build_tx_witness)
      .collect();
  ```
  This includes selector evaluation, boundary row construction, AIR witness expansion, and composition preprocessing.
- **Constraints:** Witness workers MUST NOT mutate shared transcript state. All per-tx preprocessing must be deterministic and isolated. Shared read-only state is allowed via `Arc<T>`.
- **Done when:** Witness construction scales linearly with core count; Stage 5 no longer has a sequential preprocessing bottleneck; 100 tx witness generation fits within sub-second budget on 8 cores.

#### Q.2c Parallelize prove_block Stage 5 ✅ DONE

Replace the sequential algebraic proving loop with `rayon::par_iter`, operating on the separated traces from Q.2a/Q.2b.

```rust
// BEFORE (sequential, shared channel, monolithic trace):
for (k, w) in witnesses.iter().enumerate() {
    let (alg, r_pp, claim, lambdas) = prove_air_interleaved_algebraic(
        ..., &mut block_channel,
    );
}

// AFTER (parallel, per-tx channels, separated traces):
let tx_results: Vec<_> = (0..n_tx).into_par_iter().map(|k| {
    let mut ch = per_tx_algebraic_channel(&prev_state_root, cap, k);
    // Access only witness_cols locally; fixed_cols via Arc
    let (alg, r_pp, claim, lambdas) = prove_air_interleaved_algebraic(
        ..., &mut ch,
    );
    (alg, r_pp, claim, lambdas)
}).collect();
```

- Move `build_auth_slice_claims` inside the parallel closure (it's per-tx, no shared state)
- Collect results into `tx_algebraic`, `tx_r_pp`, `tx_claims`, `tx_lambdas` vectors
- **Done when:** `prove_block` produces valid proof with parallel Stage 5

#### Q.3 Update verify_block Stage 2b ✅ DONE

Mirror the prover change in the verifier.

```rust
// BEFORE (sequential, shared channel):
for k in 0..n_tx {
    let (r_pp_k, final_claim_k) = verify_air_interleaved_algebraic(
        ..., &mut block_channel,
    )?;
}

// AFTER (per-tx channels, still sequential for now):
for k in 0..n_tx {
    let mut ch = per_tx_algebraic_channel(&meta.prev_block_state_root, cap, k);
    let (r_pp_k, final_claim_k) = verify_air_interleaved_algebraic(
        ..., &mut ch,
    )?;
}
```

Note: Verifier loop can remain sequential (correctness first, parallel verify is Q.5).
The critical change is using `per_tx_algebraic_channel` instead of shared `block_channel`.

- **Done when:** `verify_block` accepts proofs generated by parallel prover

#### Q.4 Reconnect Block Channel for Stage 6 ✅ DONE

After per-tx algebraic STARKs complete (parallel), Stage 6 (multipoint sumcheck) still
needs a deterministic shared channel for the block-level reduction.

- Block channel for Stage 6 is seeded from: `(prev_state_root, cap, BLOCK_MULTIPOINT_TAG)`
- Fix: create fresh block channel AFTER Stage 5, seed with `(state_root, cap, MULTIPOINT_TAG)`.
- Stage 5b (BlockStateBindingAir) also gets its own channel: `per_tx_algebraic_channel(..., n_tx)`

#### Q.4a Segmented Transcript Absorption ✅ DONE

Refactor Stage 6 transcript absorption to prevent serialization walls and support streaming.

- **Problem:** Absorbing all `block_col_openings` linearly (`for x in openings { channel.observe(x) }`) creates huge sequential transcript bandwidth, poor cache locality, and future recursion bottlenecks.
- **Required Change:** Replace linear opening absorption with Merkle reduction.
  Instead of absorbing every field element, compute per-entity (per-tx or per-segment) digests in parallel:
  ```rust
  // Parallel digest computation
  let digests: Vec<Digest> = (0..n_tx).into_par_iter().map(|k| {
      H(tx_index || k || openings_k || lambdas_k || reductions_k || metadata_k)
  }).collect();
  // Sequential absorption of reduced data
  let root = merkle_reduce(&digests);
  channel.absorb(root);
  ```
- **Security Requirement:** The per-entity digest MUST commit to `tx_index` (or `segment_id`), opening positions, lambda reductions, and local evaluation claims to prevent reordering attacks, cross-segment replay, and transcript ambiguity.
- **Benefits:** Unlocks streaming verification, segmented recursion, lower transcript memory pressure, and GPU batching compatibility.
- **Done when:** Stage 6 no longer linearly absorbs every field element; entity digests are used as transcript units; Multipoint reduction remains sound; Verifier reconstructs identical segmented transcript.

#### Q.5 Parallel Verifier ✅ DONE

Parallelize verify_block Stage 2b.

The per-tx verification loop does 4 things per tx, ALL of which become independent
after Q.3:

1. `verify_auth_killshot` — already self-seeded via `auth_gkr_channel()` (no shared state)
2. Auth/Spine bridge checks — pure field comparisons (no channel)
3. Slice reconstruction — pure MLE math (no channel)
4. `verify_air_interleaved_algebraic` — after Q.3, uses `per_tx_algebraic_channel(cap, k)`

Implementation:

```rust
// BEFORE (sequential):
for k in 0..n_tx {
    let auth_reductions = verify_auth_killshot(..., &mut auth_gkr_channel())?;
    // ... bridge checks, slice reconstruction ...
    let (r_pp_k, claim_k) = verify_air_interleaved_algebraic(
        ..., &mut block_channel)?;
    tx_r_pp.push(r_pp_k);
    tx_final_claims.push(claim_k);
}

// AFTER (parallel):
let tx_results: Vec<Result<(Vec<Block128>, Block128), VerifyBlockError>> =
    (0..n_tx).into_par_iter().map(|k| {
        // Auth Kill-Shot (self-seeded, independent)
        let auth_reductions = {
            let mut ch = auth_gkr_channel();
            verify_auth_killshot(&proof.tx_auth_proofs[k], &auth_circuit,
                &auth_public_list[k], &mut ch)
                .ok_or(VerifyBlockError::AuthKillShot(k))?
        };
        // Bridge checks...
        // Slice reconstruction...
        // Algebraic STARK (per-tx channel, independent)
        let mut ch = per_tx_algebraic_channel(&meta.prev_block_state_root, cap, k);
        let (r_pp_k, claim_k) = verify_air_interleaved_algebraic(
            airs[k], pi, alg, &extras, &slice_claims, &mut ch)
            .map_err(|e| VerifyBlockError::AlgebraicStark(k, e))?;
        Ok((r_pp_k, claim_k))
    }).collect();
// Unpack results, propagate first error.
```

What remains sequential after Q.5:
- Block SpineGKR Kill-Shot verification (one call, ~3ms)
- Stage 6: Block multipoint sumcheck verification (cheap, O(log_len * n_participants))
- Stage 7: FRI mixed opening verification (one call, ~15ms for 64 queries)

These three are fast and inherently sequential (global binding).

Timing breakdown (100 tx, current):
- Per-tx auth Kill-Shot verify: ~45ms each → 4.5s total sequential
- Per-tx algebraic STARK verify: ~100ms each → 10s total sequential
- Stages 6+7: ~1.8s (already fast)
- Total: ~16.3s

After parallelization (8 cores):
- Per-tx (auth + algebraic): max(100 tx / 8) * 145ms = ~1.8s
- Stages 6+7: ~1.8s (unchanged)
- Total: ~3.6s

After parallelization (16 cores):
- Per-tx: max(100 tx / 16) * 145ms = ~0.9s
- Stages 6+7: ~1.8s
- Total: ~2.7s

- **Done when:** `verify_block` runs in <4s for 100 tx on 8 cores

#### Q.6 Update Benchmarks

- Update `bench_prover/benches/block_scaling.rs` to reflect new timing
- Update `bench_prover/benches/stark_report.rs` pipeline description
- Verify: 100-tx block prove < 10s on 8 cores
- **Done when:** benchmarks confirm target performance

### Q.7 AIR Versioning & Proof Compatibility

Goal: Define protocol evolution rules for AIR systems.

Topics to Design
- AIR version identifiers
- Proof format compatibility
- Recursive verifier upgrade policy
- Constraint deprecation semantics
- Hardfork boundaries
- Mixed-version block handling

Dependency

Required before:
- Phase 7 recursion

### Q.8 Deterministic Parallel Execution

Goal: Guarantee identical proofs across parallel execution environments.

Topics to Design
- Stable reduction ordering
- Deterministic rayon scheduling assumptions
- Parallel hash consistency
- Floating nondeterminism avoidance
- Thread-local transcript isolation
- Parallel memory visibility rules

Blocks:
- Distributed proving
- External prover implementations

### Files Modified

| File | Change |
|------|--------|
| `noid_air` (composition/airs) | Trace layout split (fixed vs witness), API changes |
| `noid_stark` (interleaved/logic) | Accept split trace, distinguish fixed/witness domains |
| `noid_block/src/lib.rs` | `per_tx_algebraic_channel()`, parallel Stage 5 (Q.2c), fresh Stage 6 channel, Merkle transcript reduction (Q.4a) |
| `noid_block/src/lib.rs` | verify_block: per-tx channels in Stage 2b |
| `noid_block/src/full_node.rs` | Update `prove_block_full`/`verify_block_full` if affected |
| `noid_block/tests/stage_g_roundtrip.rs` | Update test to use new protocol |
| `bench_prover/benches/block_scaling.rs` | Update notes, verify performance |
| `bench_prover/benches/stark_report.rs` | Update architecture description |

### Soundness Proof Sketch

1. **Commitment binding:** `cap = MerkleRoot(NTT(all_columns))`. After commit, prover
   cannot alter any column without changing cap. cap is collision-resistant (Blake3, 128-bit).

2. **Challenge derivation:** `z_k = H(state_root || cap || k || "TX_ALG")`. Since cap
   encodes all columns, and H is a random oracle (Poseidon2b sponge), z_k is uniformly
   random from prover's perspective at commit time.

3. **Zero-check soundness:** If AIR polynomial P != 0 on the evaluation domain, then
   `sum_x eq(z_k, x) * P(x) = 0` with probability at most `degree / |F|` = negligible.
   The proof is a standard sum-check argument; only requires z_k to be random with
   respect to the committed polynomial — which it is (derived from cap).

4. **Cross-tx binding:** Stage 6 multipoint sumcheck verifies that ALL per-tx opening
   claims `M_k[i](r_pp_k)` are consistent with the committed columns. A cheating prover
   must fool Stage 6 which uses a fresh challenge `mu` derived from ALL openings.

5. **Reordering attack:** tx_index `k` is absorbed into the seed. Reordering transactions
   changes seeds, changes challenges, invalidates proofs. Verifier reconstructs same seeds
   from proof metadata → reordering detected.

6. **No new assumptions:** Same field (GF(2^128)), same hash (Poseidon2b), same PCS
   (FRI-Binius). Only change: sequential Fiat-Shamir → parallel Fiat-Shamir with
   commitment-derived seeds. This is a standard technique used in Plonky2, Boojum,
   and other production systems.

### Risk Analysis

Three potential risks were identified and analyzed against the codebase:

#### Risk 1: Cross-Tx Algebraic Coupling (Correlation Attacks)

**Concern:** If per-tx polynomials share structure (e.g., `P_total = sum P_k` or shared
composition batching), simultaneous challenge knowledge might enable coordinated cheating.

**Verdict: SAFE.** Verified in code (`noid_stark/src/interleaved.rs:125-296`): each per-tx
algebraic STARK operates exclusively on `preps[k].columns`. There is:
- No shared polynomial across tx within Stage 5
- No cross-tx composition batching
- No shared `alpha` or `beta` between different tx proofs
- `betas` and `z` are sampled per-tx from own channel

The only cross-tx coupling is in Stage 6 (block multipoint sumcheck), which uses a FRESH
channel seeded AFTER all per-tx results are committed. This is the global binding layer.

#### Risk 2: Self-Referential Cap (FS Soundness)

**Concern:** `r_k = H(cap, k)` where prover controls `cap` indirectly via witness choice.
Could prover iteratively choose witness to get favorable challenges?

**Verdict: SAFE.** Verified in code (`noid_block/src/lib.rs:315`): `interleaved_commit()`
finalizes the Merkle cap ONCE from the NTT of ALL columns. After commit:
- Columns are immutable (stored in `prover_state`)
- Cap is a Blake3 Merkle root — collision-resistant
- No partial cap computation; no witness modification after cap

This is standard commit-then-challenge Fiat-Shamir. Prover would need to break Blake3
collision resistance to find witness that produces a favorable cap — computationally
infeasible at 128-bit security.

#### Risk 3: Domain Separation / Entropy Collapse

**Concern:** Bare `H(cap, k)` is insufficient. Future protocol upgrades, cross-stage
channel reuse, or transcript collisions could cause soundness issues.

**Mitigation:** Q.1 specifies full domain separation in channel seed:

```
per_tx_algebraic_channel(prev_state_root, cap, tx_index):
    ch = Channel::new()
    ch.observe(DOMAIN_TAG_TX_ALGEBRAIC)    // fixed 128-bit constant
    ch.observe(PROTOCOL_VERSION)           // versioned protocol binding
    ch.observe(state_root_hi)              // block context
    ch.observe(state_root_lo)
    absorb_cap(ch, cap)                    // commitment binding
    ch.observe(Block128::from(tx_index))   // per-tx uniqueness
    return ch
```

Where:
- `DOMAIN_TAG_TX_ALGEBRAIC = 0x5458_414C_4745_4252_4149_4332_3032_3600` ("TXALGEBR AIC2026")
- `PROTOCOL_VERSION = Block128::from(1u128)` (bumped on protocol changes)

This ensures:
- No collision with SpineGKR channel (uses Poseidon2bChannel, different type)
- No collision with Stage 6 channel (uses BLOCK_MULTIPOINT_TAG)
- No collision with existing `prove_logic` STARK (different domain tag)
- Protocol version prevents cross-version transcript reuse
- Future stages cannot accidentally reuse the same channel state

### Formal Proof Obligation

The protocol change requires proving:

1. **Commitment binding:** `cap = Blake3_Merkle(NTT(columns))` is binding —
   prover cannot open committed columns to different values.

2. **No post-challenge witness adaptation:** All columns are fixed at commit time
   (Stage 3, line 315). Per-tx challenges derived from cap + tx_index cannot influence
   witness because witness is already committed.

3. **Stage 6 global binding:** Block-level multipoint sumcheck (Stage 6) verifies that
   `M_k[i](r_pp_k) == block_col_openings[k*n + i]` for ALL tx. Challenge `mu` is derived
   from ALL openings simultaneously. A prover faking any single tx would need to
   fool Stage 6 which has full visibility over all claims.

4. **No cross-instance adaptive dependency:** Per-tx STARK[k] produces `(r_pp_k, claim_k)`
   using only: (a) committed columns of tx k, (b) challenges from channel_k. Since
   channel_k = H(state_root, cap, k), and cap commits ALL columns, knowledge of channel_j
   (for j != k) provides no advantage — the prover already knew both channels at commit time.

5. **Reordering resistance:** tx_index is absorbed into the seed. Permuting transactions
   changes all per-tx channels, invalidates all proofs. Verifier deterministically
   reconstructs seeds from proof order.

### Dependency

- Requires: Phase 1 complete (Stage S — Split GKR, privacy fix, all current code)
- Blocks: Nothing (this is a prover optimization, proof format unchanged)
- Enables: 100-tx blocks within 60s budget, path to 1024-tx blocks with SIMD (Stage K)

### Implementation Stages

#### Stage 1: Per-Tx Channel Factory (Q.1) — 1 day

**Files:** `noid_block/src/channel.rs` (new)

**Goal:** Create deterministic per-tx Fiat-Shamir channels with full domain separation.

**Implementation:**
```rust
// Domain separation constants
pub const DOMAIN_TAG_TX_ALGEBRAIC: u128 = 0x5458_414C_4745_4252_4149_4332_3032_3600;
pub const DOMAIN_TAG_STATE_BINDING: u128 = 0x5354_4154_4542_494E_4449_4E47_3230_3236;
pub const DOMAIN_TAG_BLOCK_MULTIPOINT: u128 = 0x424C_4F43_4B4D_554C_5449_504F_494E_5400;
pub const PROTOCOL_VERSION_Q: u128 = 1;

// Per-tx channel factory
pub fn per_tx_algebraic_channel(
    prev_state_root: &[u8; 32],
    cap: &MerkleCap,
    tx_index: u32,
) -> Channel;

// State binding channel (uses tx_index = n_tx)
pub fn state_binding_channel(
    prev_state_root: &[u8; 32],
    cap: &MerkleCap,
    n_tx: u32,
) -> Channel;

// Block multipoint channel (Stage 6)
pub fn block_multipoint_channel(
    prev_state_root: &[u8; 32],
    cap: &MerkleCap,
) -> Channel;
```

**Tests:**
- `deterministic_channel`: same inputs → same challenges
- `different_tx_index`: different tx_index → different challenges
- `domain_separation`: algebraic vs multipoint vs state_binding → different channels
- `protocol_version`: different version → different challenges

**Done when:** Factory produces deterministic channels; same inputs → same output; different tx_index → different challenges; domain separation verified.

---

#### Stage 2: Trace Layout Separation (Q.2a) + Critical Memory Fixes — 5 days

**Files:** `noid_air/src/lib.rs`, `noid_air/src/composition/tx_logic.rs`, `noid_stark/src/lib.rs`, `noid_stark/src/interleaved.rs`, `noid_core/src/mle/evaluate.rs`, `noid_fri_binius/src/mixed_open.rs`

**Goal:** Split trace into fixed/witness columns, eliminate critical memory copies.

**2.1 Column Classification Trait**

Add to `noid_air/src/lib.rs`:
```rust
pub trait Air {
    // ... existing methods ...
    
    /// Indices of columns that are fixed (identical across all valid traces).
    /// Fixed columns are shared across all transactions via Arc.
    fn fixed_columns(&self) -> Vec<usize> { vec![] }
}
```

For TxLogicAir (81 columns):
- Fixed (selectors, masks): columns 0..8
- Per-tx public: columns 78..80 (tx_body_hash), column 80 (TxvLiveMask)
- Witness: columns 8..78 (balance, range, carry chains)

**2.2 FixedColumns Structure**

```rust
#[derive(Clone)]
pub struct FixedColumns {
    pub tower: Vec<Vec<Block128>>,   // tower basis (constraint eval)
    pub flat: Vec<Vec<u128>>,        // flat basis (zero-check)
    pub col_indices: Vec<usize>,     // original Trace column indices
    pub log_len: usize,
}
```

**2.3 Zero-Copy Padding**

Replace `pad_column` with `pad_column_cow`:
```rust
pub fn pad_column_cow(column: &[Block128], target_log: usize) -> Cow<[Block128]> {
    let target = 1usize << target_log;
    if column.len() == target {
        return Cow::Borrowed(column);  // NO ALLOC
    }
    // ... allocate and pad ...
}
```

**2.4 Split Trace View**

```rust
pub struct SplitTraceView<'a> {
    pub fixed: &'a FixedColumns,
    pub witness: &'a [Vec<Block128>],
    pub witness_flat: &'a [Vec<u128>],
    pub log_rows: usize,
}
```

**2.5 Fix M1: sumcheck_cols Cloning (752 MB savings)**

In `noid_stark/src/interleaved.rs:150-153`:
```rust
// BEFORE: clones all columns
let mut sumcheck_cols: Vec<Vec<Block128>> = Vec::with_capacity(...);
sumcheck_cols.extend_from_slice(&padded_columns[..n_air_cols]);

// AFTER: uses references
let mut sumcheck_refs: Vec<&[Block128]> = Vec::with_capacity(...);
for col in &padded_columns[..n_air_cols] {
    sumcheck_refs.push(col.as_slice());
}
```

Update `prove_zero_check` signature to accept `&[&[Block128]]`.

**2.6 Fix M2: evaluate_slice Thread-Local Scratch (800 MB savings)**

Add to `noid_core/src/mle/evaluate.rs`:
```rust
pub fn evaluate_slice_with_scratch<F: TowerField>(
    evals: &[F],
    point: &[F],
    scratch: &mut Vec<F>,
) -> F;
```

In `noid_fri_binius/src/mixed_open.rs`:
```rust
thread_local! {
    static EVAL_SCRATCH: RefCell<Vec<Block128>> = RefCell::new(Vec::new());
}

let primary_openings: Vec<Block128> = prover_state.raw_cols
    .par_iter()
    .map(|col| {
        EVAL_SCRATCH.with(|s| {
            evaluate_slice_with_scratch(col, &r_pp, &mut s.borrow_mut())
        })
    })
    .collect();
```

**Done when:**
- FixedColumns built once per AIR, shared via Arc
- Fixed columns pre-converted to flat basis
- prove_zero_check_split accepts split trace
- sumcheck_cols uses references (M1 fixed)
- evaluate_slice uses thread-local scratch (M2 fixed)
- pad_column_cow zero-copy for same-size columns (M4 fixed)

---

#### Stage 3: Witness Generation Parallelization (Q.2b) — 3 days

**Files:** `noid_block/src/lib.rs`, `noid_block/src/full_node.rs`, `noid_air/src/airs/tx_body_spine.rs`, `noid_gkr/src/block_spine.rs`

**Goal:** Parallelize all sequential witness construction bottlenecks.

**3.1 Parallel Stage 2 Prep Loop**

In `noid_block/src/lib.rs`:
```rust
// BEFORE: sequential
for w in witnesses.iter() {
    let spine_states = reconstruct_slot_states(...);
    // ... pad columns ...
}

// AFTER: parallel
let prep_results: Vec<_> = witnesses.par_iter().map(|w| {
    let spine_states = reconstruct_slot_states(...);
    // ... pad columns ...
    (spine_states, columns, auth_slices)
}).collect();
```

Note: `reconstruct_slot_states` internally sequential (hash chain), but **between tx** — independent.

**3.2 Parallel BlockSpineMle::build (S3)**

In `noid_gkr/src/block_spine.rs`:
```rust
// BEFORE: sequential loop over 5900 slots
for (slot, state_in) in slot_state_ins.iter().enumerate() {
    let witness = evaluate_permutation(*state_in);
    mle.populate_slot(slot, &witness);
}

// AFTER: parallel (embarrassingly parallel, disjoint memory)
slot_state_ins.par_iter().enumerate().for_each(|(slot, state_in)| {
    let witness = evaluate_permutation(*state_in);
    mle.populate_slot(slot, &witness);
});
```

**Speedup:** 5900 perms / 8 cores = ~738 per core. Near-linear scaling.

**3.3 Parallel build_balance_trace_parts (S5)**

In `noid_air/src/airs/balance_gate.rs`:
```rust
let block_traces: Vec<_> = per_block.par_iter()
    .map(|block| BitAdderAir::build_trace(block))
    .collect();
```

**3.4 Parallel verify_logic in full_node (S6)**

In `noid_block/src/full_node.rs`:
```rust
let verify_results: Vec<_> = (0..n_tx).into_par_iter()
    .map(|k| verify_logic(...))
    .collect();
```

**Done when:**
- Stage 2 prep loop parallel
- BlockSpineMle::build parallel
- build_balance_trace_parts parallel
- verify_logic in full_node parallel
- No shared mutable state between threads

---

#### Stage 4: Fix Critical Memory Copies — 2 days

**Files:** `noid_gkr/src/block_spine.rs`, `noid_fri_binius/src/interleaved_commit.rs`, `noid_stark/src/interleaved.rs`

**4.1 Fix M3: BlockSpineMle mmap Optimization**

For 100 tx: 4 × 2^22 × 16 bytes = 256 MB. Use mmap for lazy zero-fill:
```rust
fn alloc_zeroed_mle(n_cells: usize) -> Vec<Block128> {
    #[cfg(target_os = "linux")]
    {
        let size = n_cells * std::mem::size_of::<Block128>();
        let ptr = unsafe {
            libc::mmap(ptr::null_mut(), size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        if ptr != libc::MAP_FAILED {
            return unsafe { Vec::from_raw_parts(ptr as *mut Block128, n_cells, n_cells) };
        }
    }
    vec![Block128::ZERO; n_cells]  // fallback
}
```

**4.2 Fix M5: Remove encoded_cols Dead Field**

In `noid_fri_binius/src/interleaved_commit.rs`:
```rust
pub struct InterleavedProverState<'a> {
    // REMOVED: pub encoded_cols: Vec<Vec<Block128>>,
    pub raw_cols: Vec<&'a [Block128]>,
    pub log_rows: usize,
    pub n_cols: usize,
}
```

**4.3 Fix M6: Verifier Proof Clone**

In `noid_stark/src/interleaved.rs`:
```rust
// BEFORE: clones entire AlgebraicStarkProof
let alg = AlgebraicStarkProof {
    base_openings: proof.base_openings.clone(),
    // ...
};

// AFTER: restructure to borrow directly
fn verify_algebraic_from_interleaved<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: &InterleavedStarkProof,  // borrow directly
    // ...
) -> Result<AlgebraicVerifyOut, VerifyError>
```

**Done when:**
- BlockSpineMle allocation optimized (M3)
- encoded_cols removed (M5)
- Verifier borrows proof directly (M6)

---

#### Stage 5: Parallel Stage 5 (Q.2c) — 1 day

**Files:** `noid_block/src/lib.rs`

**Goal:** Parallelize per-tx algebraic STARK proofs.

```rust
let tx_results: Vec<_> = (0..n_tx)
    .into_par_iter()
    .map(|k| {
        let mut ch = per_tx_algebraic_channel(
            &prev_block_state_root, cap, k as u32,
        );
        
        let slice_claims = build_auth_slice_claims(...);
        
        let (alg, r_pp_k, claim_k, lambdas_k) = prove_air_interleaved_algebraic_split(
            w.air, &fixed_cols, &prep.witness_columns,
            w.pi, &auth_res.extras_transcript,
            &slice_claims, log_len, &mut ch,
        );
        
        (alg, r_pp_k, claim_k, lambdas_k)
    })
    .collect();
```

**Done when:**
- Stage 5 uses rayon::par_iter
- Each tx uses independent per_tx_algebraic_channel
- build_auth_slice_claims inside parallel closure
- prove_block produces valid proof

---

#### Stage 6: Update Verifier (Q.3, Q.5) — 1 day

**Files:** `noid_block/src/lib.rs`

**Goal:** Mirror prover changes in verifier, parallelize verification.

```rust
let tx_verify_results: Vec<Result<_, VerifyBlockError>> = (0..n_tx)
    .into_par_iter()
    .map(|k| {
        // Auth Kill-Shot (self-seeded)
        let auth_reductions = {
            let mut ch = auth_gkr_channel();
            verify_auth_killshot(...)?
        };
        
        // Bridge checks, slice reconstruction
        
        // Algebraic STARK (per-tx channel)
        let mut ch = per_tx_algebraic_channel(
            &meta.prev_block_state_root, cap, k as u32,
        );
        let (r_pp_k, claim_k) = verify_air_interleaved_algebraic(...)?;
        
        Ok((r_pp_k, claim_k))
    })
    .collect();
```

**Done when:**
- verify_block uses per-tx channels
- verify_block parallelizes Stage 2b
- Accepts proofs from parallel prover

---

#### Stage 7: Reconnect Block Channel (Q.4) — 0.5 day

**Files:** `noid_block/src/lib.rs`

**Goal:** Create fresh channels for Stage 5b and Stage 6.

```rust
// Stage 5b: State binding
if let Some(sb) = state_binding {
    let mut sb_ch = state_binding_channel(
        &prev_block_state_root, cap, n_tx as u32,
    );
    // ...
}

// Stage 6: Block multipoint
let mut block_channel = block_multipoint_channel(
    &prev_block_state_root, cap,
);
block_channel.observe_field_elem(Block128::from(BLOCK_MULTIPOINT_TAG));
block_channel.observe_field_elems(&block_col_openings);
```

**Done when:**
- Stage 5b uses state_binding_channel
- Stage 6 uses fresh block_multipoint_channel
- No shared channel state between Stage 5 and Stage 6

---

#### Stage 8: Segmented Transcript Absorption (Q.4a) — 4 days

**Files:** `noid_block/src/lib.rs`, `noid_block/src/transcript.rs` (new)

**Goal:** Replace linear transcript absorption with Merkle reduction.

**8.1 Per-Entity Digest Construction**

```rust
pub fn compute_tx_transcript_digest(
    tx_index: u32,
    r_pp: &[Block128],
    openings: &[Block128],
    lambdas: &[Block128],
    final_claim: Block128,
) -> [u8; 32] {
    let mut sponge = Poseidon2bSponge::new();
    sponge.absorb(Block128::from(tx_index as u128));
    sponge.absorb_slice(r_pp);
    sponge.absorb_slice(openings);
    sponge.absorb_slice(lambdas);
    sponge.absorb(final_claim);
    sponge.squeeze_digest()
}
```

**8.2 Merkle Reduction**

```rust
pub fn merkle_reduce(digests: &[[u8; 32]]) -> [u8; 32] {
    let n = digests.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(digests);
    layer.resize(n, [0u8; 32]);
    
    while layer.len() > 1 {
        layer = layer.par_chunks(2)
            .map(|pair| compress(&pair[0], &pair[1]))
            .collect();
    }
    layer[0]
}
```

**8.3 Update Stage 6 Transcript**

```rust
// BEFORE: linear absorption
block_channel.observe_field_elems(&block_col_openings);

// AFTER: Merkle reduction
let tx_digests: Vec<[u8; 32]> = (0..n_tx).into_par_iter().map(|k| {
    compute_tx_transcript_digest(k as u32, &tx_r_pp[k], ...)
}).collect();

let transcript_root = merkle_reduce(&all_digests);
let [root_hi, root_lo] = hash_to_fields(&transcript_root);
block_channel.observe_field_elem(root_hi);
block_channel.observe_field_elem(root_lo);
```

**Security Requirements:**
- Per-entity digest MUST commit to tx_index (prevents reordering)
- MUST commit to opening positions (prevents cross-segment replay)
- MUST commit to lambda reductions (prevents transcript ambiguity)
- MUST commit to evaluation claims (prevents claim substitution)

**Done when:**
- Stage 6 no longer linearly absorbs every field element
- Entity digests used as transcript units
- Multipoint reduction remains sound
- Verifier reconstructs identical segmented transcript

---

#### Stage 9: Parallel Verifier (Q.5) — 1 day

Already covered in Stage 6. Additional:

**9.1 Parallel State Binding Verification**

```rust
if has_state_binding {
    let mut sb_ch = state_binding_channel(...);
    let (r_pp_sb, _) = verify_air_interleaved_algebraic(...)?;
}
```

**What remains sequential:**
- Block SpineGKR Kill-Shot verification (~3ms)
- Stage 6: Block multipoint sumcheck (cheap)
- Stage 7: FRI mixed opening (~15ms)

**Done when:** verify_block <4s for 100 tx on 8 cores.

---

#### Stage 10: Benchmarks & Validation (Q.6) — 2 days

**Files:** `bench_prover/benches/block_scaling.rs`, `noid_block/tests/`

**10.1 Performance Benchmarks**

```rust
fn bench_block_prove(c: &mut Criterion) {
    for n_tx in [10, 50, 100, 200, 500] {
        group.bench_with_input(BenchmarkId::new("parallel", n_tx), &n_tx, |b, &n| {
            let (witnesses, state_binding) = setup_block(n);
            b.iter(|| prove_block([0; 32], &witnesses, Some(&state_binding)));
        });
    }
}
```

**10.2 Determinism Tests**

```rust
#[test]
fn sequential_vs_parallel_equivalence() {
    let proof_seq = prove_block_sequential(...);
    let proof_par = prove_block(...);
    verify_block(&airs, &proof_par, ...).unwrap();
}
```

**10.3 Memory Profiling**

```rust
#[test]
fn memory_peak_under_2gb() {
    let peak = measure_peak_memory(|| prove_block(...));
    assert!(peak < 2 * 1024 * 1024 * 1024);
}
```

**Validation Checklist:**
- [ ] prove_block <15s on 8 cores (100 tx)
- [ ] verify_block <5s on 8 cores (100 tx)
- [ ] Memory peak <2 GB (100 tx)
- [ ] Sequential vs parallel proof equivalence
- [ ] Cross-platform determinism (CI: x86_64, ARM)
- [ ] No regression in existing tests

**Done when:** All benchmarks confirm targets, all validation tests pass.

---

#### Stage 11: Deterministic Parallel Execution (Q.8) — 2 days

**11.1 Stable Reduction Ordering**

```rust
// INVARIANT: All parallel reductions use indexed par_iter (0..n)
// with .collect() to guarantee deterministic ordering.
```

**11.2 Thread-Local Transcript Isolation**

Each rayon worker gets its own Channel instance. No shared mutable transcript state.

**11.3 Parallel Hash Consistency**

- Blake3: deterministic across threads
- Poseidon2b: deterministic (pure arithmetic)
- No floating-point anywhere (GF(2^128) only)

**11.4 Cross-Run Determinism Test**

```rust
#[test]
fn deterministic_across_runs() {
    let proof1 = prove_block(...);
    let proof2 = prove_block(...);
    assert_eq!(format!("{:?}", proof1), format!("{:?}", proof2));
}
```

**Done when:**
- Stable reduction ordering documented and enforced
- Thread-local transcript isolation verified
- Cross-run determinism test passes
- No floating-point in any hot path

---

### Appendix A: Architectural Invariants

**A.1 Streaming-First Invariant**

```
No protocol stage may require full materialization
of all block openings simultaneously in RAM.
```

**A.2 Column Lifetime Ownership Model**

```
fixed columns:       global immutable (Arc<FixedColumns>)
witness columns:     per-tx ephemeral (Vec<Vec<Block128>>)
opening reductions:  stage-local ephemeral (dropped after Stage 6)
recursive replay:    streaming-only (Phase 7)
```

**A.3 Pre-Allocation Over Arena**

From Plonky2/Boojum reference analysis: **neither uses bumpalo**. Both use:
- Pre-allocated `Vec::with_capacity`
- Aligned allocation (`allocate_with_alignment_of::<F, P>()`)
- Rayon chunked parallelism

**Decision for Paranoid:** Pre-allocation + `pad_column_cow` (zero-copy for fixed) instead of bumpalo. Simpler, safer, same result.

---

### Implementation Timeline

| Stage | Task | Days | Cumulative | Dependencies |
|-------|------|------|------------|-------------|
| 1 | Per-Tx Channel Factory (Q.1) | 1 | 1 | — |
| 2 | Trace Layout Separation (Q.2a) + M1/M2/M4 | 5 | 6 | — |
| 3 | Witness Generation Parallelization (Q.2b) | 3 | 9 | — |
| 4 | Fix Critical Copies (M3/M5/M6) | 2 | 11 | Stage 2 |
| 5 | Parallel Stage 5 (Q.2c) | 1 | 12 | Stage 1, 2 |
| 6 | Update Verifier (Q.3, Q.5) | 1 | 13 | Stage 1, 5 |
| 7 | Reconnect Block Channel (Q.4) | 0.5 | 13.5 | Stage 1 |
| 8 | Segmented Transcript (Q.4a) | 4 | 17.5 | Stage 7 |
| 9 | Parallel Verifier (Q.5) | 1 | 18.5 | Stage 6, 8 |
| 10 | Benchmarks & Validation (Q.6) | 2 | 20.5 | All |
| 11 | Deterministic Parallel (Q.8) | 2 | 22.5 | Stage 5, 9 |

**Critical path:** 1 → 2 → 5 → 6 → 8 → 9 → 10

---

### Performance Projection

| Metric | Before | After Stage 5 | After Stage 8 | After All |
|--------|--------|--------------|--------------|-----------|
| prove_block (100 tx, 8c) | 43s | ~12s | ~10s | **~8s** |
| verify_block (100 tx, 8c) | 15s | ~5s | ~4s | **~3.5s** |
| Memory peak (100 tx) | ~3 GB | ~1.5 GB | ~1.2 GB | **<1 GB** |
| Proof size | 2.02 MB | 2.02 MB | 2.02 MB | 2.02 MB |

**Breakdown (after all stages, 100 tx, 8 cores):**

```
prove_block: ~8s
├── Stage 2 (prep): ~0.3s (parallel, fixed shared)
├── Stage 2b (BlockSpineMle): ~0.5s (parallel 5900 perms)
├── Stage 3 (commit): ~3s (parallel Blake3, unchanged)
├── Stage 4 (GKR): ~0.5s (spine sequential + auth parallel)
├── Stage 5 (algebraic): ~2.5s (100/8 × 200ms, per-tx channels)
├── Stage 5b (state binding): ~0.2s
├── Stage 6 (block multipoint): ~0.5s (Merkle reduction)
└── Stage 7 (FRI): ~0.5s
```

---

### Risk Register

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| Split trace API breaks existing callers | Medium | High | Incremental: add `_split` variants, don't replace |
| Q.4a Merkle reduction changes proof format | High | Medium | Proof format unchanged (same BlockProof struct), only transcript internals change |
| Parallel determinism failure | Low | Critical | Indexed par_iter + collect; determinism tests |
| BlockSpineMle parallel write conflicts | None | — | Disjoint memory regions (pack_index_dyn guarantees) |
| reconstruct_slot_states can't parallelize | Known | Medium | Accept sequential; it's ~2s of 43s total |

---

### What We Do NOT Do (Justified Defer)

| Item | Reason for Defer |
|------|-----------------|
| `#[repr(align(64))]` for Block128 | Audit showed: AVX2 uses unaligned loads, CLMUL register-only. 64-byte alignment would break pack_slice. |
| Column chunking (64-256KB) | Columns already 128KB (log_rows=13). Needed at log_rows≥16 (Phase 3). |
| NUMA-awareness | 250 MB fits in L3. Needed at 1024 tx (Phase 8). |
| KillShot batch scheduler | KillShot self-contained. Batch scheduling — Phase 7 concern. |
| Streaming witness | Segmented state doesn't exist. YAGNI until Phase 3. |
| Bumpalo arena | References (Plonky2, Boojum) do NOT use arena. Pre-allocation + Cow better. |

---

## Phase 3 — Segmented State & Merkle Kill-Shot (Stage F)

**Goal:** Scale state beyond 2^16 slots per monolithic FRI by splitting it into fixed-size independently committed segments. 

**CRITICAL DEPENDENCY:** This phase MUST be completed before Recursion (Phase 7). Recursion commits the state format into the circuit. If we do Recursion before Segmented State, we will hardcode the monolithic FRI format and have to rewrite the recursive STARK later.

**Architectural Philosophy — INCREMENTAL UPGRADE & MEMORY TOPOLOGY:**
We do not rewrite `noid_chain` from scratch. We abstract storage via a `StateBackend` trait (Ref: Reth `revm` database traits), replace the monolithic `FriState` with `SegmentedFriState`, and inject the segment Merkle path into `BlockStateBindingAir` via GKR instead of AIR trace rows. 
Memory discipline is a first-class concern: zero-copy views, opening deduplication, and virtualized empty segments are mandatory to prevent bandwidth collapse at scale.

**Performance target:** Reduce per-block state commitment from O(2^log_slots) to O(K * 2^16) where K is the number of dirty (modified) segments. Target <50ms for state root update in a typical 100-tx block.

### F.0 Crate Structure & Trait Architecture (Zero-Copy Mandate)
Abstract state storage to prepare for disk backend and enable segment-level loading.
- `noid_chain/src/storage/mod.rs` — `StateBackend` trait.
- `noid_chain/src/segmented_state.rs` — `SegmentedFriState` replacing `FriState`.
- **Reference:** Reth `crates/storage/db` and `crates/revm/database` trait patterns.

**MANDATORY Trait Definition (Patch 3):**
The `StateBackend` trait MUST include a strict contract for column loading that prevents full-state materialization and supports future MDBX mmap:
```rust
pub trait StateBackend {
    fn get_slot(&self, segment_id: u32, local_idx: u32) -> SlotValue;
    fn set_slot(&mut self, segment_id: u32, local_idx: u32, val: SlotValue);
    fn load_segment_columns(&self, segment_id: u32) -> SegmentColumns;
    fn flush(&mut self);
}

pub struct SegmentColumns {
    pub value: Vec<Block128>,
    pub owner_hi: Vec<Block128>,
    pub owner_lo: Vec<Block128>,
}
```
*Future K.3 requirement:* `MdbxBackend` MUST return zero-copy mmap slices (`SegmentView<'txn> -> &[Block128]`), NOT `Vec<Block128>`, to avoid `memcpy` bandwidth collapse.

- **Done when:** `StateBackend` trait compiles with strict loading semantics; existing code compiles against it (using RAM backend).

### F.1 RAM Backend, Zero-Constants & Virtual Zero Segments
- `noid_chain/src/storage/memory.rs` — `RamBackend`: `Vec<Block128>` per segment.
- `noid_chain/src/constants.rs` — Pre-compute `ZERO_SUBTREE_ROOT[k]`, `ZERO_SEGMENT_ROOT`, `ZERO_SEGTREE_NODE[d]` for empty subtrees/segments.
- **F.1b Virtual Zero Segment:** Empty segments MUST NOT materialize columns. `load_segment_columns` for empty segments must return a static immutable slice `&[Block128]` (or a `SegmentColumns` struct backed by static `ZERO_COLUMN`) without allocation.
- **Done when:** Backend implements full trait; zero-constants match Poseidon2b hashes; empty segments result in zero allocation.

### F.2 Segmented FRI Commitment (Per-Segment)
Split state into `2^(log_slots - 16)` segments of `2^16` slots (3 columns: value, owner_hi, owner_lo).
- Each segment is independently FRI-committed via `noid_fri_binius`.
- `SegmentedFriState` holds a cache of `seg_roots: Vec<Digest>`.
- **Done when:** `state_root` computed from segmented FRI matches the monolithic FRI at `log_slots=16` (unit test parity).

### F.3 Segment Merkle Tree (Global state_root)
Implement the global state_root as a Poseidon2b Merkle tree over segment roots.
- Domain tag: `TAG_SEGMENTTREE`.
- Depth of the segment tree = `log_slots - 16` (8 at genesis, 16 at max scale).
- Cache all internal nodes: `tree_cache: Vec<Vec<Digest>>` (max 4 MB at `log_slots=32`).
- **Reference:** Standard binary Merkle tree patterns (e.g., winterfell Merkle tree, but with Poseidon2b).
- **Done when:** `state_root` updates correctly on segment root change; empty state produces correct zero root.

### F.4 Dirty Tracking & Block Production Pipeline
The core performance optimization. During block production, only modified segments are recomputed.
- Maintain a `DirtySegments: HashSet<u16>` during tx execution.
- On `apply_block`: Mark dirty -> Load dirty columns -> Mutate -> Recompute FRI root -> Update Merkle tree.
- **F.4b Opening Coalescer:** Before Stage 6, deduplicate FRI query openings. Use `HashMap<(segment_id, query_pos), SharedOpening>` to collapse `1024 × Q` openings into `dirty_segments × Q`. Prevents redundant Merkle path proofs and bandwidth waste.
- **Done when:** Block production state update takes <50ms for 100 txs; clean segments are never touched; duplicate openings are collapsed.

### F.5 Integrate Existing Merkle Kill-Shot GKR (Segment Paths)
Prove the segment Merkle path (up to 16 levels) in-circuit WITHOUT materializing Poseidon2b in the STARK AIR trace.
- **CRITICAL:** The `noid_gkr` crate ALREADY contains a fully implemented and tested Merkle Kill-Shot (`merkle_circuit`, `merkle_killshot`). You MUST reuse the existing `prove_merkle_killshot` / `verify_merkle_killshot` API and `MerklePathInputs` structure. Do NOT reimplement.
- When building `MerklePathInputs`, `leaf` is the `seg_root`, `expected_root` is the global `state_root`, `siblings` are the path elements, and `active_depth` is the current segment tree depth.
- **F.5b Merkle Sibling Cache:** Add `HashMap<(segment_id, tree_level), Digest>` to batch Merkle paths. Prevents recomputing shared siblings for adjacent segment leaves in Kill-Shot.
- **Done when:** Existing Kill-Shot is successfully integrated into `BlockStateBindingAir`; proof size increases by ≤3%; shared siblings are cached.

### F.6 BlockStateBinding Refactor (FRI + Merkle Path)
Update `BlockStateBindingAir` and `prove_block_state_binding` for the two-tier state.
- For each touched slot: 1) FRI Opening against `seg_root`, 2) Merkle Path to `state_root` via the integrated Kill-Shot.
- Batch multiple slots in the same segment (share Merkle path and use coalesced openings from F.4b).
- **Done when:** BlockStateBinding proves/verifies with segmented state; BlockProof size increases by ≤3%.

### F.7 Automatic Expansion under Segmentation
Handle `log_slots += 1` (Spec §15.3).
- `num_segments` doubles. New upper half is all-zero segments (using `ZERO_SEGMENT_ROOT`). One Poseidon2b compression.
- **Done when:** Expansion triggers correctly; node applies expansion block without re-hashing state.


---

## Phase 7 — Recursive Chain (Stage H) — ✅ **DONE**

**Goal:** O(1) historical verification. A new node downloads ONE ~6.5 KB proof and verifies the entire chain from genesis in ~5 ms.

**Achieved:** True O(1) — constant-size proof regardless of chain length. No archive nodes. No O(N) sync.

**Result:** `RecursiveBlockProof` = 6.5 KB, `verify_tip` = ~5 ms, `prove_recursive_step` overhead = ~30 ms/block.

**Dependency:** Required Phase 1.5 (parallel BlockProof) and Phase 3 (Segmented State — to lock state_root format). Both done before Phase 7.

### Implementation Summary

All H.1–H.7 are implemented. H.8/H.9 are deferred (not needed for initial mainnet).

#### H.1 Chain Accumulator ✅ DONE
`noid_recursive::accumulator`: `ChainAccumulator { height, state_root, chain_hash }`, `genesis_accumulator`. Rolling Poseidon2b chain hash: `chain_hash_{n} = compress(chain_hash_{n-1}, H_BLOCK(header_n))`. Binds every block header (including `proof_transcript_hash`) into a 32-byte commitment. Security: per-tx FS challenges are bound through `proof_transcript_hash → H_BLOCK → chain_hash`.

#### H.2 Algebraic-Replay Witness ✅ DONE
`noid_recursive::witness::BlockReplayWitness::from_parts(...)`. Extracts `block_multipoint_rounds`, `compact_fri`, `block_col_openings` from `BlockProof` without re-importing `noid_block` (avoids cyclic dep). Used by `prove_recursive_step`.

#### H.3 Fiat-Shamir Sponge AIR ✅ DONE (via STARKPack insight)
Instead of a Sponge AIR, used compact FRI `COMPACT_TAU=8` with `log_rows=8` → `n_rounds=0` → **zero Merkle paths in FRI**. The recursive STARK's FRI collapses to pure tensor decomposition. No in-circuit hash verification needed.

#### H.4 Algebraic-Replay AIR ✅ DONE
`noid_recursive::air::RecursiveBlockAir` (8 columns, 256 rows, log_rows=8):
- Constraints 0–1: multipoint sumcheck fold consistency for block_n and rec_{n-1}: `claim_out == p0 + r*(p0+p1)` (degree-2, FoldCheckGate via SelectorGate).
- Constraints 2–3: state root pin at ACC_ROW (WeightedLinearGate).
- Selectors declared as PublicColumns (no witness overhead).

#### H.5 RecursiveBlockAir ✅ DONE
`prove_recursive_step(witness, header, prev_acc, prev_rec)` → `RecursiveBlockProof`. Uses STARKPack: all algebraic data packed into ONE `InterleavedStarkProof`. Result: **6.5 KB constant-size** proof per block.

#### H.6 Poseidon2b in compact FRI ✅ DONE (enabling change Phase A)
Compact FRI round trees changed Blake3 → Poseidon2b (`noid_stark`, `noid_block`). With COMPACT_TAU=8 and log_rows=8, n_rounds=0 → no Merkle paths at all. Obsoletes the need for a dedicated Poseidon2b Kill-Shot for FRI.

#### H.7 Tip Verifier ✅ DONE
`noid_recursive::verify::verify_tip(rec_proof, rec_air, tip_prev_state_root, tip_height, genesis_acc)`: O(1), ~5 ms. Verifies the recursive STARK + accumulator consistency. Integrated into `noid_block::full_node::verify_block_full` via `Option<RecVerifyInputs>`.

#### H.8/H.9 Deferred
Witness streaming and aggregation topology are not needed for initial operation. Single-block recursive step RAM is O(1) in chain length (only current block data materialized).

### Key metrics (measured)

| Metric | Value |
|---|---|
| `RecursiveBlockProof` size | **6.5 KB** (constant) |
| `verify_tip` time | **~5 ms** (O(1)) |
| `prove_recursive_step` overhead | **~30 ms/block** |
| New node sync download | **6.5 KB** (constant) |
| compact FRI rounds in rec proof | **0** (n_rounds = 0) |
| Test coverage | E2E test in `noid_block/tests/phase7_recursive_e2e.rs` |

---

## Phase 2 — Consensus & State Machine (Stage P)

**Goal:** Implement ALL block validity rules, state transitions, fork choice, and chain reorg logic so nodes can reach deterministic consensus.

**Architectural Philosophy — BORROW, DON'T INVENT:**
Consensus code is a minefield. We adapt battle-tested patterns from production Rust clients. A new `noid_consensus` crate contains pure functions and trait bounds. `noid_chain` implements these traits.

**Consensus with Recursion:** Because Phase 7 is done, consensus validation now supports **two paths**:
1. **Full Block Validation:** For block producers. Validates raw BlockProofs.
2. **O(1) Tip Validation:** For syncing nodes and Light Nodes. Validates RecursiveProofs against the ChainAccumulator.

### P.0 Crate Structure & Trait Architecture
Create `noid_consensus` crate with strict separation of concerns (Reference: Reth `crates/consensus`).
- Pure logic (no IO, no networking, no storage).
- Provider traits (`HeaderProvider`, `NullifierProvider`, `StateProvider`) (Reference: Substrate `sp-consensus`).
- `ConsensusError` enum covering all 16 invariants.

### P.1 Consensus Parameters (`params.rs`)
ALL constants in one place. Every constant MUST have a doc comment referencing SPECIFICATION.md.
- Time, Limits, State, Rewards, PoW parameters.
- **Done when:** All constants match SPECIFICATION.md.

### P.2 ASERT Difficulty Adjustment (`difficulty.rs`)
**Reference:** Grin `consensus/src/target.rs` & Bitcoin Cash ASERT.
- Fixed-point 256-bit arithmetic. NO FLOATS.
- **Done when:** Matches reference vectors, deterministic across architectures.

### P.3 PoW Validation (`pow.rs`)
- `Blake3(header_bytes) < difficulty_target` (256-bit LE).
- **Done when:** Rejects invalid nonces and wrong targets.

### P.4 Timestamp Rules (`timestamps.rs`)
- Median-time-past over 11 blocks + future drift cap.
- **Done when:** Rejects backward timestamps and far-future blocks.

### P.5 Header Chain Validation (`header.rs`)
**Reference:** Reth `consensus/validation.rs`.
- `prev_header_hash`, height, `log_slots`, epoch boundaries.
- **Done when:** All header fields validated.

### P.6 Block Reward Schedule & Coinbase (`reward.rs`)
- **Security Fix P.7.3:** `coinbase_credit == reward + sum(fees)`.
- **Done when:** Blocks with inflated coinbase are rejected.

### P.7 Block Limits (`limits.rs`)
- `BLOCK_MAX_TXS`, `BLOCK_MAX_DA_SIZE`, coinbase structure.
- **Done when:** Overlimits blocks rejected.

### P.8 Per-Tx Consensus Checks (`checks.rs`)
**Reference:** Zcash `zcash_consensus` rules.
- **Security Fix P.7.1:** `epoch_anchor` freshness.
- **Security Fix P.7.2:** `tx_body_hash` consistency.
- Nullifiers, slot conflicts, state checks.
- **Done when:** All 8 checks enforced; security fixes active.

### P.9 DA Payload Verification (`da.rs`)
- `da_root` matching (block-withholding protection).
- **Done when:** Tampered DA payload rejected.

### P.10 State Transition Rules (`state_trans.rs`)
- `active_slot_count` delta, `alloc_counter` increment, expansion trigger.
- **Done when:** State accounting matches Spec §15.

### P.11 Fork Choice + Finality (`fork_choice.rs`)
**Reference:** Reth `consensus/forkchoice.rs`.
- Heaviest chain rule. 18-block finality.
- **Done when:** Reorg beyond finality rejected; heaviest chain wins.

### P.12 Full Block Validation Pipeline (`block.rs`)
**Reference:** Reth `consensus/validation.rs`.
- Orchestrates all 16 invariants (cheapest first).
- **Done when:** ALL 16 invariants enforced.

### P.13 Reorg Logic (`reorg.rs`)
**Reference:** Grin `chain/chain.rs`.
- Unwind to common ancestor, apply fork, return txs to mempool.
- **Done when:** Handles 1-3 block reorgs gracefully.

### P.14 Chain State Machine (`noid_chain` update)
**Reference:** Substrate `sc-client-api`.
- Apply validated blocks, maintain ring buffer, nullifiers, state counters.
- **Done when:** Deterministic state evolution from genesis.

### P.15 Genesis (`genesis.rs`)
- Hardcoded initial distribution. Identical state_root on any node.
- **Done when:** Byte-identical genesis state.

### P.16 Check Verification (`checks.rs`)
- Offline payment receipts (LogicProof + InclusionReceipt).
- **Done when:** Eternal proof of payment verified.

### P.17 — Fee Market & Resource Accounting

Goal: Price prover work, DA bandwidth, state growth, and mempool occupancy to prevent asymmetric resource exhaustion attacks.

**Topics to Design**

Fee dimensions:
- algebraic proving cost
- DA byte cost
- state growth cost
- recursive accumulation cost

Tx pricing model:
- fixed vs dynamic fee market
- congestion adjustment
- proof-size weighting

Spam resistance:
- mempool occupancy pricing
- low-fee eviction policy
- recursive prover saturation attacks

State rent / slot lifecycle:
- permanent slot allocation economics
- dormant slot handling
- expansion incentives

Miner / prover incentives:
- reward split between ordering and proving
- external miner compatibility

Dependency

Requires:

Phase 1.5 performance model
Phase 3 segmented state
Phase 7 recursion timings

### P.17b Economic Attack Surface

Goal: Analyze adversarial economics of proving and state growth.

Topics to Design
- Prover centralization pressure
- ASIC asymmetry
- Recursive proving monopolization
- DA flooding economics
- State expansion griefing
- Fee market manipulation
- Empty block incentives

Blocks:
- Mainnet economics
- Token issuance finalization

### P.18 — Failure & Recovery Semantics

Goal: Define deterministic node behavior under partial failure, proof lag, corrupted state snapshots, recursive backlog, and interrupted block application.

**Topics to Design**
- Recursive prover lag handling:
    - whether blocks may propagate before recursive folding completes
    - max allowed recursion backlog
    - fallback validation mode
- Snapshot integrity:
    - snapshot hash commitments
    - partial snapshot corruption handling
    - resumable state sync
- Crash consistency:
    - atomic MDBX commit semantics
    - interrupted block application rollback
    - accumulator/state_root consistency guarantees
- DA pruning race conditions:
    - minimum retention window
    - snapshot-vs-DA dependency ordering
    - late sync guarantees
- Recovery invariants:
    - node restart must never produce divergent state_root
    - accumulator/state DB/header DB must roll forward atomically

**Dependency**

Requires:

Phase 2 (consensus rules)
Phase 4.2 (MDBX storage)

Blocks:

Production deployment
Public testnet reliability

### P.18b Recursive Failure Domains

Goal: Define deterministic behavior under recursive pipeline failure.

Topics to Design
- Recursive backlog thresholds
- Accumulator corruption handling
- Recursive prover crash recovery
- Fallback block validation mode
- Recursive desync recovery
- Delayed recursive finalization semantics

Dependency

Requires:
- Phase 7 recursion

### P.19 Canonical Serialization Rules

Goal: Ensure byte-identical encoding across all architectures.

Topics to Design
- Endianness policy
- Canonical integer encoding
- Digest serialization
- Transcript byte encoding
- Network framing rules
- Snapshot encoding
- Deterministic hashing order

Blocks:
- Networking
- Snapshots
- External integrations

---

## Phase 4 — Node Infrastructure (Stage N)

**Goal:** Working Full Node binary — validates, assembles blocks, mines, serves wallet requests, syncs O(1).

**Architectural Philosophy — NO ARCHIVE NODES:**
Because Recursion (Phase 7) is complete, we do NOT implement historical block download from genesis. All nodes sync by verifying a RecursiveProof and downloading a state snapshot. DA payload is pruned immediately after block application. History does not exist in the network. Borrow architectural patterns from Reth (services), libp2p (networking), and Bitcoin Core (mining/sync).

### N.1 Node Binary Skeleton & Async Runtime
Create `noid-node` binary crate. 
- **Reference:** Reth `bin/reth` and `crates/node-builder`.
- Async runtime (Tokio). CLI arguments via `clap`. Modular service architecture.
- **Done when:** Binary starts, loads genesis, initializes Tokio tasks, shuts down cleanly.

### N.2 Block Storage (MDBX)
- **Reference:** Reth `crates/storage/db` (MDBX wrapper).
- Persist headers, ChainAccumulator, state, recent blocks. Prune DA payload.
- **Done when:** Node can store/retrieve 1000 blocks; state survives process restart.

### N.3 Mempool
- **Reference:** Reth `crates/transaction-pool`.
- UTXO slot conflict tracking (`spent_slots`, `minted_slots`), fee priority, eviction.
- **Done when:** Accepts valid, rejects invalid, handles conflicts, evicts expired.

### N.4 Block Assembly Pipeline
- Select txs -> `prove_block` -> `extend_accumulator` (Phase 7) -> construct header.
- **Done when:** Produces valid candidate block + recursive proof from mempool txs.

### N.5 Built-in Miner
- **Reference:** Bitcoin Core miner logic.
- Multi-threaded Blake3 nonce search. Interrupt on new P2P block.
- **Done when:** Finds valid nonce, Full Node assembles and propagates.

### N.6 Block Template API
- **Reference:** Bitcoin Core `getblocktemplate` & Stratum V2.
- Push 248-byte header to external miners. Empty-block fallback.
- **Done when:** External mock miner solves nonce, Full Node accepts and propagates.

### N.7 RPC API
- **Reference:** Reth RPC (`jsonrpsee`).
- Wallet endpoints: `get_slot`, `get_epoch_anchor`, `submit_tx_intent`.
- Explorer endpoints: `get_block`, `get_header`, `get_chain_info`.
- **Done when:** External client can query state and submit transactions.

### N.8 P2P Networking (libp2p)
- **Reference:** `rust-libp2p` (Substrate/Filecoin standard).
- Gossipsub for `NewBlock` (header + RecursiveProof) and `NewTxIntent`.
- Kademlia for DHT. Noise for encryption.
- **Done when:** Two Full Nodes gossip transactions and sync a chain of 10 blocks.

### N.9 O(1) Chain Sync (State Sync)
**CRITICAL:** No history download from genesis.
- **Reference:** Mina Protocol state sync.
- Request `TipHeader + RecursiveProof + StateSnapshot` from peers.
- Verify RecursiveProof against TipHeader (~300ms).
- If valid, accept StateSnapshot. Apply recent blocks to catch up to absolute tip.
- **Done when:** Fresh Full Node syncs from peer to tip in <1 minute without archive nodes.

### N.11 Data Availability Retention Policy

Goal: Define deterministic DA retention and pruning semantics.

Topics to Design
- Minimum DA retention window
- Snapshot dependency guarantees
- DA pruning schedule
- Late sync recovery rules
- Temporary archival semantics
- DA replay protection

Blocks:
- Public testnet
- Production deployment

### N.10 Snapshot Format & State Sync Semantics

Goal: Define deterministic, authenticated, resumable state snapshot synchronization.

Topics to Design
Snapshot serialization format
Segment-wise snapshot hashing
Snapshot chunking and resume
Snapshot authentication against recursive accumulator
Incremental catch-up after snapshot load
Compatibility across protocol versions
Snapshot pruning policy
Security Requirements
Snapshot must deterministically reconstruct identical state_root
Partial corruption must be detectable
Snapshot replay attacks must be impossible
Dependency

Requires:

Phase 3 segmented state
Phase 7 recursive accumulator

### N.10b Snapshot Commitment Format

Goal: Define authenticated snapshot transport and verification.

Topics to Design
- Snapshot chunk commitments
- Segment authentication
- Incremental snapshot verification
- Resumable sync proofs
- Snapshot replay prevention
- Version compatibility

Dependency

Requires:
- Segmented state
- Recursive accumulator

---

## Phase 5 — Wallet Core (Stage W)

**Goal:** Wallet logic shared by Full Node (built-in) and Light Node (standalone CLI).

### W.1 Key Management
- Generate SpendSecret, derive Address. Encrypted keystore (`argon2 + chacha20-poly1305`).
- **Done when:** Generate, export, import keys.

### W.2 Slot Tracking
- Full Node mode: scan own state directly. Light Node mode: subscribe via RPC.
- **Done when:** Balance updates on new blocks in both modes.

### W.3 Transaction Construction
- Coin selection, TxBody, C_claimed.
- **Done when:** Produces valid TxBody from wallet state.

### W.4 LogicProof Generation
- Build witness -> `prove_logic()` (~300-400ms) -> TxIntent.
- **Done when:** Locally generated TxIntent verifies.

### W.5 Submit & Confirm
- Full Node: inject directly. Light Node: submit via RPC.
- **Done when:** End-to-end send from wallet A to wallet B.

### W.6 Light Node CLI Binary
- `noid-light` binary. O(1) sync via RecursiveProof.
- Commands: `balance`, `send`, `receive`, `history`.
- **Done when:** Light Node sends coins to Full Node and vice versa.

---

## Phase 6 — Integration & Testnet (Stage T)

**Goal:** Multi-node network running real consensus with O(1) sync.

### T.1 Multi-Node Test Harness
- Spawn 3-5 nodes locally. Verify O(1) sync and block propagation.
- **Done when:** 3 nodes agree on 50-block chain.

### T.2 Adversarial Testing
- Invalid PoW/Proofs, double-spends, forks, timestamp manipulation.
- **Done when:** All attack vectors handled.

### T.3 Performance Validation
- Block time ~60s. Prove <10s. Verify <3s. O(1) sync <300ms.
- **Done when:** Sustained block production for 1 hour.

### T.4 Reorg Handling
- Fork resolution. Revert mempool.
- **Done when:** Handles 1-3 block reorgs gracefully.

### T.5 Public Testnet Launch
- Docker image, seed nodes, faucet, explorer.
- **Done when:** External parties can run nodes and send transactions.

### T.6 Audit Preparation & Formalization

Goal: Prepare the protocol for external cryptographic and consensus audits.

Topics to Design
- Formal invariant registry
- Cryptographic assumption registry
- Proof obligation index
- Reproducible benchmark suite
- Deterministic test vectors
- Consensus failure taxonomy

Dependency

Requires:
- Consensus complete
- Recursive pipeline complete

---

## Phase 8 — Optimizations (Stage K)

### K.1 Reduced Inner Queries
- NUM_QUERIES=16 for block-internal proofs.

### K.2 Parallel Recursive Prover
- Partition trace across 8 cores.

### K.3 MDBX Storage Backend
- `MdbxBackend` for large states (log_slots > 26).

### K.4 Proof Compression
- Delta-encode FRI paths.

---

## Phase 9 — GUI Wallet (Stage G)

**Goal:** Desktop application (Tauri/egui). Light or Full mode.

### G.1 GUI Framework
### G.2 Mode Selection
### G.3 Wallet UI
### G.4 Full Node Controls

---

## Dependency Graph

```
Phase 1 (Stateless) — DONE
    │
    ▼
Phase 1.5 (Parallel STARK)
    │
    ▼
Phase 3 (Segmented State) ─── MUST lock state format before recursion
    │
    ▼
Phase 7 (Recursive Chain) ─── O(1) sync foundation, no archive nodes
    │
    ▼
Phase 2 (Consensus) ────────── Uses RecursiveProofs for fast validation
    │
    ▼
Phase 4 (Node) ─────────────── No O(N) sync, pure O(1) State Sync
    │
    ▼
Phase 5 (Wallet) ───────────── Uses O(1) sync
    │
    ▼
Phase 6 (Testnet)

Phase 8 (Optimizations) — Post-testnet
Phase 9 (GUI) — Post-testnet
```

Critical path: **S → Q → F → H → P → N → T**.

---

## Design Invariants (Non-Negotiable)

1. **No trusted setup.** No elliptic curves. Post-quantum.
2. **Single algebraic universe.** Everything is GF(2^128) — from tx to recursion.
3. **Proof-native.** Network does not execute code. It verifies mathematics.
4. **Transparent.** All values on-chain. No zero-knowledge.
5. **PoW for ordering only.** Blake3 determines canonical chain. Proofs determine validity.
6. **Light Nodes prove logic, Full Nodes prove state.** External miners only provide PoW ordering.
7. **O(1) history.** Recursive chain compresses unbounded history into one proof.
8. **128-bit security.** Every component: FRI, GKR, Fiat-Shamir, PoW hash.
9. **Deterministic consensus.** Byte-identical state_root across all honest nodes.
10. **Fixed-slot UTXO.** No hash-map, no dynamic structures. Slots addressed by index.

---

## Proof Architecture (Current: Stage S, Target: Stage Q)

### Current (Stage S — implemented)
```
  LogicProof generation (200-300ms, runs on any node with wallet)
  ┌──────────────────────────────────────────┐
  │  AuthGKR Kill-Shot (20 perms, 14-var)    │
  │  STARK + FRI-Binius over TxLogicAir      │
  │  Output: LogicProof (~36 KB)             │
  │                                          │
  │  SpineGKR is NOT in LogicProof.          │
  │  tx_body_hash is native-computed and     │
  │  pinned via PublicColumn in STARK trace. │
  │  GKR proof of correctness is deferred    │
  │  to block-prover (below).                │
  │                                          │
  │  Runs on: Full Node (built-in wallet)    │
  │           Light Node (standalone wallet)  │
  └──────────────────────────────────────────┘
           │ TxIntent (to own mempool or via RPC)
           ▼
  Full Node — Block Assembly (current: ~43s sequential)
  ┌──────────────────────────────────────────┐
  │  Collect TxIntents from mempool          │
  │  Verify N LogicProofs                    │
  │  Unified block SpineGKR Kill-Shot        │
  │    (N×59 perms, public SpineInputs only) │
  │  Build BlockStateBinding                 │
  │    - FRI state openings (gamma-RLC)      │
  │    - Segment Merkle paths                │
  │    - MerkleGKR Kill-Shot (32-slot, 14v)  │
  │    - Bridge check (C_claimed match)      │
  │  Per-tx algebraic STARKs (SEQUENTIAL —   │
  │    shared block channel, ~43s at 100 tx) │
  │  Block-level multipoint sumcheck         │
  │  Single FRI-Binius opening               │
  │  Output: BlockProof ~2 MB (100 tx)       │
  └──────────────────────────────────────────┘
           │ PoW (built-in miner OR Block Template API)
           ▼
```

### Target (After Stage Q — parallel per-tx STARK)
```

  LogicProof generation: unchanged from Stage S (~200-300ms, ~36 KB)

  Full Node — Block Assembly (target: <8s CPU on 8 cores for 100 tx)
  ┌──────────────────────────────────────────┐
  │  Collect TxIntents from mempool          │
  │  Verify N LogicProofs                    │
  │  Unified block SpineGKR Kill-Shot        │
  │  Build BlockStateBinding                 │
  │  Parallel per-tx algebraic STARKs        │
  │    - Independent channels: H(root,cap,k) │
  │    - N zero-checks on N cores (rayon)    │
  │  Block-level multipoint sumcheck         │
  │  Single FRI-Binius opening               │
  │  Output: BlockProof ~2 MB (100 tx)       │
  └──────────────────────────────────────────┘
           │ PoW (built-in miner OR Block Template API)
           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Built-in miner          │  External Miner (3rd party)      │
  │  - Multi-thread Blake3   │  - Receives 248-byte header      │
  │  - Same process          │  - GPU/ASIC/pool                 │
  │  - Config: mining=on     │  - Returns valid nonce           │
  │                          │  - Cannot modify block content   │
  └─────────────────────────────────────────────────────────────┘
           │ Valid nonce found
           ▼
  Full Node — Propagation
  ┌──────────────────────────────────────────┐
  │  Attach nonce → complete block           │
  │  Propagate to P2P network                │
  │  Other Full Nodes validate + apply       │
  └──────────────────────────────────────────┘
           │ Block (P2P)
           ▼
  Recursive Accumulator (per-block, ~3-5s, Phase 7)
  ┌──────────────────────────────────────────┐
  │  Algebraic replay of BlockProof verify   │
  │  Fiat-Shamir sponge in-circuit           │
  │  FS Kill-Shot (300 perms, 18-var)        │
  │  Deferred-FRI Merkle commitment          │
  │  State continuity gate                   │
  │  Output: RecursiveProof (~55 KB)         │
  └──────────────────────────────────────────┘
           │
           ▼
  Tip Verification (Light Node or any verifier, ~230ms, O(1))
  ┌──────────────────────────────────────────┐
  │  Verify RecursiveProof (STARK)           │
  │  Check deferred Merkle at tip            │
  │  Result: entire history correct           │
  └──────────────────────────────────────────┘
```
---

## Soundness Summary

| Component | Security | Mechanism |
|---|---|---|
| FRI-Binius | 128-bit | 64 queries x 2-bit rate |
| Blake3 Merkle | 128-bit | collision resistance |
| Gamma batching | 128-bit | Horner RLC over GF(2^128) |
| SpineGKR | 128-bit | Schwartz-Zippel, 15-var |
| AuthGKR | 128-bit | Schwartz-Zippel, 14-var |
| MerkleGKR | 128-bit | Schwartz-Zippel, 14-var |
| Batch-eval | 128-bit | degree-2 sumcheck + RLC |
| Fiat-Shamir | collision-resistant | Poseidon2b sponge |
| Parallel per-tx STARK | 128-bit | non-adaptive: cap-derived seeds, committed witness |
| PoW | ordering-only | Blake3 + ASERT DAA |
| Recursion | 128-bit | native field (no foreign-field penalty) |

No trusted setup. No elliptic curves. Post-quantum.

### Appendix A — Transcript & Fiat-Shamir Architecture

Goal: Formalize all transcript domains, challenge derivation rules, domain separation constants, and transcript binding invariants.

Topics to Specify
Global transcript hierarchy
Per-stage domain separation
Recursive transcript replay rules
Commitment-before-challenge invariants
Segment transcript reduction semantics
Query ordering rules
Versioning strategy
Cross-protocol collision prevention
Required Outputs
Complete transcript state machine
Domain tag registry
Formal challenge derivation specification
Recursive replay compatibility rules
Dependency

Required before:

Phase 7 recursion


### Appendix A.1 — Transcript State Machine

Goal: Freeze the global Fiat-Shamir architecture before recursion.

Topics to Design
- Transcript ownership rules
- Absorb/squeeze ordering invariants
- Transcript serialization format
- Cross-stage domain separation
- Recursive replay transcript semantics
- Streaming transcript reduction
- Version migration policy

Blocks:
- Phase 7 recursion
