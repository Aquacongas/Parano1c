# PARANOID — ROADMAP

From current implementation state to public testnet.

---

## Current State (Baseline)

The cryptographic engine is complete and tested:

```
noid_core         GF(2^128) tower, CLMUL/AVX2, MLE, sumcheck, NTT, transcript.
noid_poseidon2b   Poseidon2b native + AIR (perm, sponge, domain tags, compress).
noid_fri          Generic FRI (legacy, used by IVC).
noid_fri_binius   Production PCS: interleaved commit, compact FRI, mixed opening.
noid_binius       Bit/byte packing for DA bandwidth reduction.
noid_gkr          Kill-Shot GKR: Spine (59-slot), Auth (20-slot), Merkle (32-slot).
noid_air          AIRs + gates + compositions. Production: tx_validity_with_spine.
noid_stark        STARK engine: prove_tx / verify_tx (Spine→Auth→STARK).
noid_ivc          Linear folding accumulator.
noid_tx           TxBody, PublicInputs, wire serialization.
noid_chain        State (FriState), block header, blocks, DA packing, wire encoding.
noid_block        Block aggregation via deferred-opening (prove_block / verify_block).
bench_prover      Performance harness.
```

Performance (per-tx, 8 thread, measured):
- Prove: 725 ms | Verify: 145 ms | Size: 55.5 KB

What exists: proof math, state machine, block aggregation, IVC, wire formats.
What does NOT exist: networking, mempool, RPC, wallet CLI, mining, difficulty adjustment, consensus validation, node binary.

---

## Phase 1 — Stateless Architecture (Stage S)

**Goal:** Separate wallet-side logic proof from full-node-side state binding.
Light Node (wallet) proves only math (balance, auth, body).
Full Node proves state (Merkle openings, BlockStateBinding) and assembles BlockProof.
External Miner receives 248-byte block template header and brute-forces nonce.

### S.1 Epoch Anchor

Replace `prev_state_root` with `epoch_anchor` in tx body hash.

- Change `noid_tx::TxBody.prev_state_root` → `epoch_anchor: Digest`
- Change `hash_tx_body()` first arg to `epoch_anchor`
- Define `ANCHOR_DEPTH = 6`; `epoch_anchor = H_BLOCK(header[height - 6])`
- Update `SpineInputs` in `noid_gkr`
- Update all downstream tests
- **Done when:** Spine GKR roundtrip passes with epoch_anchor

### S.2 Claims Commitment (C_claimed)

Wallet commits to claimed slot values without proving state.

- `compute_claims_commitment(inputs, outputs) -> Digest` in `noid_tx`
- Poseidon2b sponge over `(slot_index, value, owner_hi, owner_lo)` for each claim
- Add `claims_commitment: Digest` to `PublicInputs`
- LogicProof absorbs C_claimed into channel
- **Done when:** tamper any slot value → proof fails

### S.3 TxLogicAir

Extract pure-logic AIR (no FriStateOpen, no Merkle).

- Create `noid_air::composition::tx_logic` module
- Contains: balance_gate, range_gate, tx_body_spine pin, selector gates
- Does NOT contain: FriStateOpenAir, FriStateCombinerComposite
- Reduced `log_rows` (10-11 instead of 13)
- **Done when:** `air.check(trace)` passes for balance/range/auth/spine

### S.4 LogicProof Pipeline

New `prove_logic` / `verify_logic` in `noid_stark`.

- `prove_logic(LogicWitness) -> LogicProof`
- LogicWitness: TxLogicAir trace, SpineInputs (epoch_anchor), AuthInputs, C_claimed
- Same pipeline: SpineGKR → AuthGKR → STARK over TxLogicAir
- `verify_logic(proof, pi) -> Result<()>`
- **Done when:** end-to-end roundtrip with verify_logic

### S.5 BlockStateBindingAir

Block-level state opening AIR.

- Reuse FriStateOpenAir pattern at block scope
- All slots from all N txs (up to 12K)
- gamma-RLC accumulator batches openings into one FRI claim
- Bridge: opened slot values must match each tx's C_claimed
- Proves pre-state (inputs exist, outputs empty) and post-state (inputs zeroed, outputs filled)
- **Done when:** 3-tx block roundtrip, tamper detection on bridge

### S.6 Integrated BlockProof

Combine LogicProofs + BlockStateBinding.

- Modify `prove_block()` to accept `Vec<LogicProof>` + full state
- Full Node: verify LogicProofs → build BlockStateBinding → aggregate via deferred-opening
- State continuity: prev_block_state_root → apply all txs → new_block_state_root
- After BlockProof ready: form header, push to external miner via Block Template API
- **Done when:** 3-tx block roundtrip; each component tamper-tested

### S.7 Nullifier Set

Anti-double-inclusion rolling window.

- `NullifierSet` in `noid_chain::ChainState`
- Window = ANCHOR_DEPTH blocks of tx_body_hashes
- Reject at mempool if duplicate within window
- Prune on oldest block exit
- **Done when:** double-inclusion rejected at validation

### S.8 TxIntent Wire Format

Network payload for stateless transactions.

- `TxIntent { tx_body, logic_proof, claims_commitment, claimed_slots }`
- Wire serialization in `noid_tx::wire`
- No prev/new state_root in per-tx wire
- **Done when:** serialize/deserialize roundtrip

---

## Phase 1.5 — Parallel Per-Tx Algebraic STARK (Stage Q)

**Goal:** Reduce `prove_block` from 61s to ~8s at 100 tx (8 cores) by parallelizing
the per-tx algebraic STARK phase. Currently the main bottleneck preventing 100-tx blocks
from fitting within the 60-second block time budget.

### Problem Statement

Stage 5 of `prove_block` (`noid_block/src/lib.rs:416-439`) runs per-tx algebraic STARKs
sequentially on a shared Fiat-Shamir channel. Each tx takes ~615ms. For N=100:
`100 * 615ms = 61.5s` — exceeds the 60s block time.

The sequential channel works by chaining: challenge for tx[k+1] depends on proof[k].
This prevents parallel execution.

### Solution: Independent Per-Tx Channels

Replace the sequential block channel in Stage 5 with independent per-tx channels, each
deterministically seeded from `(prev_state_root, commitment_cap, tx_index)`.

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

#### Q.1 Per-Tx Channel Factory

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

#### Q.2 Parallelize prove_block Stage 5

Replace the sequential loop with `rayon::par_iter`.

```rust
// BEFORE (sequential, shared channel):
for (k, w) in witnesses.iter().enumerate() {
    let (alg, r_pp, claim, lambdas) = prove_air_interleaved_algebraic(
        ..., &mut block_channel,
    );
}

// AFTER (parallel, per-tx channels):
let tx_results: Vec<_> = (0..n_tx).into_par_iter().map(|k| {
    let mut ch = per_tx_algebraic_channel(&prev_state_root, cap, k);
    let (alg, r_pp, claim, lambdas) = prove_air_interleaved_algebraic(
        ..., &mut ch,
    );
    (alg, r_pp, claim, lambdas)
}).collect();
```

- Move `build_auth_slice_claims` inside the parallel closure (it's per-tx, no shared state)
- Collect results into `tx_algebraic`, `tx_r_pp`, `tx_claims`, `tx_lambdas` vectors
- **Done when:** `prove_block` produces valid proof with parallel Stage 5

#### Q.3 Update verify_block Stage 2b

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

#### Q.4 Reconnect Block Channel for Stage 6

After per-tx algebraic STARKs complete (parallel), Stage 6 (multipoint sumcheck) still
needs a deterministic shared channel for the block-level reduction.

- Block channel for Stage 6 is seeded from: `(prev_state_root, cap, BLOCK_MULTIPOINT_TAG)`
- It absorbs `block_col_openings` (all per-tx openings concatenated) and derives `mu`, `beta_block`
- This is already the current design — just ensure the block channel is NOT polluted by
  per-tx STARK data (it currently is because per-tx STARKs absorbed into it)
- Fix: create fresh block channel AFTER Stage 5, seed with `(state_root, cap, MULTIPOINT_TAG)`,
  absorb all `block_col_openings`, proceed to multipoint sumcheck

Stage 5b (BlockStateBindingAir) also gets its own channel: `per_tx_algebraic_channel(..., n_tx)`
(uses tx_index = n_tx as the "state binding slot").

- **Done when:** Stage 6 multipoint sumcheck produces valid block-level reduction

#### Q.5 Parallel Verifier

Parallelize verify_block Stage 2b (`noid_block/src/lib.rs:785-842`).

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

### Files Modified

| File | Change |
|------|--------|
| `noid_block/src/lib.rs` | `per_tx_algebraic_channel()`, parallel Stage 5, fresh Stage 6 channel |
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
- No collision with per-tx STARK in standalone `prove_tx` (different domain tag)
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
   changes all per-tx channels, invalidating all proofs. Verifier deterministically
   reconstructs seeds from proof order.

### Dependency

- Requires: Phase 1 complete (Stage S — Split GKR, privacy fix, all current code)
- Blocks: Nothing (this is a prover optimization, proof format unchanged)
- Enables: 100-tx blocks within 60s budget, path to 1024-tx blocks with SIMD (Stage K)

---

## Phase 2 — Consensus & PoW (Stage P)

**Goal:** Implement block validity rules so nodes can reach consensus.

### P.1 ASERT Difficulty Adjustment

- `noid_chain::difficulty` module
- `compute_target(anchor_header, current_height, current_timestamp) -> [u8; 32]`
- ASERT formula: `target = anchor_target * 2^((elapsed - ideal) / halflife)`
- Fixed-point 256-bit arithmetic (no floats, deterministic)
- EPOCH_LENGTH = 6, HALFLIFE = 360s, BLOCK_TIME = 60s
- GENESIS_TARGET = 2^240
- Anchor updates at each epoch boundary
- **Done when:** matches reference vectors, edge cases (negative exponent, overflow)

### P.2 PoW Validation

- `validate_pow(header: &BlockHeader) -> bool`
- `Blake3(header.to_bytes()) < header.difficulty_target` (LE comparison)
- `validate_difficulty(header, prev_epoch_anchor) -> bool` (ASERT check)
- **Done when:** rejects invalid nonces and wrong targets

### P.3 Timestamp Rules

- Median-time-past: `header.timestamp > median(last 11 timestamps)`
- Future limit: `header.timestamp <= now + MAX_FUTURE_DRIFT` (120s)
- **Done when:** rejects backward timestamps and far-future blocks

### P.4 Block Validation Pipeline

Full consensus validation combining all rules.

- `validate_block(block, chain_state) -> Result<(), ConsensusError>`
- Checks (in order): PoW valid, difficulty correct, timestamp valid, height sequential, prev_hash matches, tx_root matches, state_root matches, BlockProof verifies, nullifier clean, slot allocations valid
- All 16 invariants from Spec §16
- **Done when:** invalid blocks rejected for each rule independently

### P.5 Chain State Machine

- `ChainState::apply_validated_block(block) -> Result<ChainState>`
- Updates: state_root, active_slot_count, alloc_counter, log_slots, tip header
- Stores epoch anchors for ASERT
- Stores last 11 timestamps for median-time-past
- **Done when:** deterministic state evolution from genesis through 100 blocks

### P.6 Genesis

- `genesis() -> (Block, ChainState)` — hardcoded initial distribution
- All slots EMPTY except protocol alloc
- GENESIS_TARGET, height=0, timestamp=protocol-defined
- **Done when:** two independent nodes produce identical genesis state_root

### P.7 Security fixes (carried from Phase 1 audit)

These three items were identified during the Phase 1/1.5 security audit
and require the chain infrastructure built in Phase 2 to implement.
TODOs are already present in the relevant source files.

#### P.7.1 — epoch_anchor freshness validation (Security #5)

- **File:** `noid_chain/src/state_binding.rs` (TODO comment in `BlockStateBinding::build`)
- **Problem:** `TxIntent.tx_body.epoch_anchor` is absorbed into `tx_body_hash`
  and bound into the Fiat–Shamir transcript, but no node verifies that the
  anchor equals `hash_block_header(chain[height - ANCHOR_DEPTH])`.
  Without this check the fork-binding and TTL properties of the epoch anchor
  are not enforced at the consensus layer.
- **Fix:** In `noid_chain::mempool::admit_tx` (to be created in P.4/P.5),
  after decoding `TxIntent`, assert:
  ```rust
  body.epoch_anchor == chain_state.header_at(height - ANCHOR_DEPTH).hash()
  ```
  Reject with `MempoolError::AnchorStale` if the chain has no block at that
  depth or if the hash does not match.
- **Requires:** header ring in `ChainState` (P.5), mempool module (Phase 4).
- **Done when:** a tx with a wrong epoch_anchor is rejected by mempool admission.

#### P.7.2 — tx_body_hash consistency check on mempool admission (Security #6)

- **File:** `noid_tx/src/intent.rs` (TODO comment on `TxIntent`)
- **Problem:** `TxIntent` carries `tx_body_hash` as a wire field alongside
  `tx_body`. Neither `decode` nor `from_bytes` verifies that
  `hash_tx_body(tx_body) == tx_body_hash`. A malformed or adversarial intent
  could carry mismatched body and hash; the LogicProof would bind to the
  hash, not to the actual body fields.
- **Fix:** In `noid_chain::mempool::admit_tx`, after deserialising:
  ```rust
  let recomputed = hash_tx_body(&body.epoch_anchor, body.fee,
                                &body.inputs, &body.outputs, body.is_coinbase);
  if recomputed != intent.tx_body_hash {
      return Err(MempoolError::TxBodyHashMismatch);
  }
  ```
- **Requires:** mempool module (Phase 4).
- **Done when:** intent with tampered `tx_body_hash` field is rejected.

#### P.7.3 — coinbase_credit == block_reward(height) + Σ fees (Security #7)

- **File:** `noid_chain/src/block.rs` (TODO comment in `apply_block`)
- **Problem:** The per-tx STARK proves `Σ outputs == coinbase_credit` for
  coinbase txs, but the VALUE of `coinbase_credit` is unconstrained by
  consensus. A miner can currently mint an arbitrary amount.
- **Fix:** In `apply_block` (or the new `validate_block`), for the coinbase tx:
  1. Confirm exactly one coinbase tx exists at index 0.
  2. Compute `expected_credit = block_reward(height) + Σ pi.fee` for all
     non-coinbase txs (fees taken from `PublicInputs.fee`).
  3. Reject if `coinbase_pi.coinbase_credit != expected_credit`.
- **Requires:** `block_reward(height)` schedule in SPECIFICATION.md and a
  reward function in `noid_chain`; `PublicInputs` available from BlockProof.
  Add `CoinbaseCreditMismatch` to `BlockApplyError`.
- **Done when:** block with inflated coinbase is rejected; test mines a valid
  block at height 1 and confirms the reward matches the schedule.

---

## Phase 3 — Segmented State (Stage F)

**Goal:** Scale state beyond 2^16 slots per FRI.

### F.1 StateBackend Trait

- `trait StateBackend { get_slot, set_slot, load_segment, flush, segment_root }`
- Separates storage from logic
- **Done when:** FriState refactored to use trait

### F.2 RAM Backend

- `RamBackend`: Vec<Block128> per segment
- Implements full trait
- Default for testnet
- **Done when:** existing tests pass through backend abstraction

### F.3 Segmented FriState

- Split state into 2^16-slot segments
- Per-segment independent FRI commitment
- `state_root = Poseidon2b_Merkle(segment_roots)`
- TAG_SEGMENTTREE domain tag
- Zero-subtree optimization for empty segments
- **Done when:** state_root matches monolithic FRI at log_slots=16

### F.4 Segment Merkle Path in BlockStateBinding

- BlockStateBinding proves segment Merkle path (up to 16 levels)
- Merkle Kill-Shot GKR for in-circuit verification (~8 KB per path)
- **Done when:** block proves/verifies with segmented state + Merkle path

### F.5 Automatic Expansion

- Trigger: avg_occupancy > 0.90 over 7-day finalized window
- Action: append zero-subtree, increment log_slots
- One Poseidon2b compression per expansion
- **Done when:** expansion triggers correctly in multi-block test

---

## Phase 4 — Node Infrastructure (Stage N)

**Goal:** Working Full Node binary — validates, assembles blocks, mines, serves wallet requests.

### Node Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  FULL NODE (all-in-one: state + wallet + miner + API)           │
│                                                                 │
│  State layer:                                                   │
│    - Full segmented state (~768 MB+)                            │
│    - Block storage, mempool, nullifier set                      │
│    - Slot ownership tracking (built-in wallet)                  │
│                                                                 │
│  Block assembly:                                                │
│    - Validates incoming TxIntents (LogicProof check, ~3ms)      │
│    - Builds BlockStateBinding + BlockProof (1-3s CPU)           │
│    - Constructs 248-byte header                                 │
│                                                                 │
│  Mining:                                                        │
│    - Built-in multi-threaded Blake3 nonce search                │
│    - OR: serves Block Template API to external miners           │
│                                                                 │
│  Wallet:                                                        │
│    - Key management, slot tracking, balance                     │
│    - Builds LogicProof locally (~300-400ms)                     │
│    - Sends transactions (no RPC needed, direct mempool)         │
│                                                                 │
│  API server:                                                    │
│    - RPC for Light Nodes + explorers                            │
│    - Block Template API for external miners (solo/pool)         │
│                                                                 │
│  P2P:                                                           │
│    - Propagates blocks + TxIntents                              │
│    - Syncs chain from peers                                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  LIGHT NODE (wallet-only, connects to Full Node via RPC)        │
│                                                                 │
│  - Stores: keys, headers, receipts (minimal disk)               │
│  - Proves: LogicProof (~300-400ms, offline)                     │
│  - Queries: Full Node for slot hints + epoch_anchor             │
│  - Submits: TxIntent via RPC                                    │
│  - Verifies: chain tip via recursive proof (O(1), ~230ms)       │
│  - No state, no mining, no block assembly                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  EXTERNAL MINER (3rd party, solo or pool)                       │
│                                                                 │
│  - Input: 248-byte BlockHeader via Block Template API           │
│  - Operation: brute-force Blake3(header) < difficulty_target    │
│  - Output: valid 128-bit nonce                                  │
│  - Cannot: see transactions, modify coinbase, steal blocks      │
│  - Use case: GPU farms, ASICs, mining pools                     │
└─────────────────────────────────────────────────────────────────┘
```

### N.1 Node Binary Skeleton

- `noid-node` binary crate
- Config: data_dir, listen_addr, rpc_addr, template_api_addr, mining (on/off)
- Async runtime (tokio)
- State persistence (load/save ChainState)
- **Done when:** starts, loads genesis, shuts down cleanly

### N.2 Block Storage

- On-disk block index (height → header + proof location)
- Pruning: keep last N full blocks, headers-only beyond
- **Done when:** store/retrieve 1000 blocks

### N.3 Mempool

- `Mempool` struct: accepts TxIntents, validates LogicProof + epoch_anchor + nullifier
- Priority by fee/byte
- Eviction policy (size cap, TTL)
- Conflict detection (same input slot)
- **Done when:** accepts valid, rejects invalid, handles conflicts

### N.4 Block Assembly

- Select txs from mempool (max N, max bytes)
- Generate BlockStateBinding for selected set
- Produce BlockProof via `prove_block()` (1-3s CPU)
- Construct header (state_root, tx_root, da_root, difficulty_target, timestamp)
- Coinbase locked in da_root → header → BlockProof (withholding protection)
- **Done when:** produces valid block from mempool txs

### N.5 Built-in Miner

- Multi-threaded Blake3 nonce search (divide 128-bit space across cores)
- Interrupt on new block arrival from P2P
- Enabled via config flag
- **Done when:** finds valid nonce, Full Node assembles and propagates block

### N.6 Block Template API

- Minimal protocol: Full Node pushes 248-byte header to connected external miners
- External miner returns `(header_hash, nonce)` on solution
- Full Node validates PoW, assembles complete block, propagates
- Supports: multiple concurrent miners, work update on new txs/blocks
- Empty-block fallback: push empty template immediately, full template after assembly
- **Done when:** external miner process solves nonce, Full Node accepts and propagates

### N.7 RPC API

- JSON-RPC over HTTP
- Wallet-facing: `get_slot(idx)`, `get_epoch_anchor()`, `submit_tx_intent(TxIntent)`, `get_chain_info()`, `query_free_slots(count)`
- Explorer-facing: `get_block(height)`, `get_header(height)`, `get_tx(hash)`
- **Done when:** Light Node can query state and submit transactions

### N.8 P2P Networking

- libp2p or custom TCP protocol
- Message types: `NewBlock`, `NewTxIntent`, `GetBlock`, `GetHeaders`
- Peer discovery (static seeds + gossip)
- Block propagation (flood with seen-filter)
- TxIntent relay (mempool sharing)
- **Done when:** two Full Nodes sync a chain of 10 blocks

### N.9 Chain Sync

- Header-first sync (download headers, validate PoW + timestamps)
- Block download (request bodies for validated headers)
- State reconstruction (apply blocks from genesis)
- Fast-sync (future: download tip state + recursive proof)
- **Done when:** fresh Full Node syncs from peer to tip

---

## Phase 5 — Wallet Core (Stage W)

**Goal:** Wallet logic shared by both Full Node (built-in) and Light Node (standalone CLI).

### W.1 Key Management

- Generate SpendSecret, derive Address
- Encrypted keystore (argon2 + chacha20-poly1305)
- Shared library: `noid_wallet` crate (used by both node modes)
- **Done when:** generate, export, import keys

### W.2 Slot Tracking

- Track owned slots (slot_index, value, owner)
- Full Node mode: scan own state directly
- Light Node mode: subscribe to new block headers via RPC, detect incoming
- Mark spent slots
- **Done when:** balance updates on new blocks in both modes

### W.3 Transaction Construction

- Select inputs (coin selection: largest-first or random)
- Choose output slots: Full Node queries own state, Light Node queries via RPC
- Build TxBody, compute tx_body_hash, C_claimed
- **Done when:** produces valid TxBody from wallet state

### W.4 LogicProof Generation

- Build full witness (SpineInputs, AuthInputs, TxLogicAir trace)
- Call `prove_logic()` (~300-400ms)
- Package as TxIntent
- **Done when:** locally generated TxIntent verifies

### W.5 Submit & Confirm

- Full Node mode: inject directly into own mempool
- Light Node mode: submit TxIntent via RPC
- Poll for inclusion (watch blocks for tx_body_hash in tx_root)
- **Done when:** end-to-end send from wallet A to wallet B (both modes)

### W.6 Light Node CLI Binary

- `noid-light` binary crate (or `noid-node --light` flag)
- Connects to Full Node via RPC
- Stores: keys + headers + receipts only
- Commands: `balance`, `send <address> <amount>`, `receive`, `history`
- **Done when:** Light Node sends coins to Full Node and vice versa

---

## Phase 6 — Integration & Testnet (Stage T)

**Goal:** Multi-node network running real consensus.

### T.1 Multi-Node Test Harness

- Spawn 3-5 nodes locally (different ports)
- Seed peers, verify they sync
- One miner, others validate
- **Done when:** 3 nodes agree on 50-block chain

### T.2 Adversarial Testing

- Invalid PoW → rejected
- Invalid BlockProof → rejected
- Double-spend attempt → rejected
- Fork resolution (longest valid chain)
- Timestamp manipulation → rejected
- **Done when:** all attack vectors handled

### T.3 Performance Validation

- Block time targeting ~60s at genesis difficulty
- prove_block() < 10s for 100 txs (Phase 1.5: parallel per-tx STARK)
- prove_block() < 3s for 100 txs (Phase 8: + SIMD zero-check)
- verify_block() < 3s for 100 txs (Phase 1.5 Q.5: parallel verifier)
- P2P propagation < 2s
- **Done when:** sustained block production for 1 hour

### T.4 Reorg Handling

- Detect competing chains
- Switch to longest valid chain
- Revert mempool (return txs from orphaned blocks)
- **Done when:** handles 1-3 block reorgs gracefully

### T.5 Public Testnet Launch

- Docker image for node
- 3+ seed nodes on cloud (separate regions)
- Faucet (genesis allocation or low-difficulty coinbase)
- Block explorer (minimal: height, txs, difficulty, timestamps)
- Public RPC endpoint
- Wallet binary release
- **Done when:** external parties can run nodes and send transactions

---

## Phase 7 — Recursive Chain (Stage H)

**Goal:** O(1) historical verification. New node verifies entire history with one proof.

### H.1 Chain Accumulator

- `noid_recursive` crate
- `ChainAccumulator { acc: Digest, height, last_state_root }`
- `block_fri_digest(BlockProof) -> Digest`: canonical hash of FRI Merkle data
- `extend_chain(prev, block_proof) -> ChainAccumulator`: verify + fold `acc' = compress(acc, block_fri_digest)`
- `genesis_accumulator(initial_state_root) -> ChainAccumulator`
- **Done when:** 3-block chain accumulation + tamper detection

### H.2 Algebraic-Replay Witness

- Deterministic transcript-trace producer
- Takes BlockProof → emits field-element witness for recursive AIR
- Covers: sumcheck round polys, composition values, Fiat-Shamir squeezes
- **Done when:** witness generation deterministic and bit-identical across runs

### H.3 Fiat-Shamir Sponge AIR

- Composable AIR wrapping Poseidon2b absorb/squeeze
- Public-input bindings + transcript continuity
- Reused for ~300 in-circuit perms
- **Done when:** sponge AIR passes `check()` for arbitrary transcript

### H.4 Algebraic-Replay AIR

- Sumcheck round consistency constraints
- Composition terminal equation
- ~8K field muls over GF(2^128)
- **Done when:** replays full block verify algebraically

### H.5 RecursiveBlockAir

- Composes H.3 sponge + H.4 algebraic
- Deferred-Merkle accumulator gate: `acc' == compress(acc, fri_digest)`
- State-continuity gate: `prev_root == state_root_n`
- Proven with FRI-Binius PCS
- **Done when:** recursive proof of one-block verify

### H.6 Kill-Shot for In-Circuit Poseidon2b

- 300 FS perms → one unified degree-7 sumcheck over 18-var MLE
- Reduces circuit from ~2^18 to ~2^15 rows
- Expected recursive prove: ~3-5s
- **Done when:** recursive prove with Kill-Shot < 5s

### H.7 Tip Verifier

- `verify_tip(recursive_proof, tip_acc, tip_block_proof) -> Result<()>`
- Verifies recursive STARK + native FRI on tip + accumulator match
- O(1) regardless of chain length
- **Done when:** fresh node verifies 100-block chain in <300ms

---

## Phase 8 — Optimizations (Stage K)

### K.1 Reduced Inner Queries

- NUM_QUERIES=16 for block-internal proofs (nested inside recursive proof)
- Reduces Fiat-Shamir perms and proof size
- **Done when:** block prove time drops ~30%

### K.2 Parallel Recursive Prover

- Partition trace across 8 cores for commit + NTT phases
- **Done when:** recursive prove < 2s on 8-core

### K.3 MDBX Storage Backend

- `MdbxBackend` implementing StateBackend trait
- Memory-mapped, crash-safe copy-on-write
- Mandatory at log_slots > 26 (~4M+ slots)
- **Done when:** node runs with disk storage, survives crash

### K.4 Proof Compression

- Strip redundant data from block proofs for relay
- Delta-encode FRI paths within same Merkle tree
- **Done when:** BlockProof wire size < 100 KB for 100-tx blocks

---

## Phase 9 — GUI Wallet (Stage G)

**Goal:** Desktop application. User opens it, chooses Light or Full mode.

### G.1 GUI Framework

- Tauri or native Rust GUI (egui/iced)
- Cross-platform: Linux, macOS, Windows
- Embeds `noid_wallet` crate + node core
- **Done when:** window opens, mode selection screen renders

### G.2 Mode Selection

- Launch screen: "Light Node" or "Full Node"
- Light mode: connects to configured Full Node RPC, wallet-only
- Full mode: starts embedded Full Node (state, mining, P2P, everything)
- Config persistence between sessions
- **Done when:** both modes launch successfully from GUI

### G.3 Wallet UI

- Balance display, transaction history
- Send: address input, amount, fee selector, prove + submit
- Receive: show own address, QR code
- Slot viewer (own slots with values)
- LogicProof generation progress bar (~300-400ms)
- **Done when:** full send/receive cycle through GUI

### G.4 Full Node Controls (Full mode only)

- Mining toggle (on/off), hashrate display
- Mempool viewer (pending txs, fees)
- Chain status (height, difficulty, peers, sync progress)
- Block Template API status (connected external miners)
- **Done when:** user can monitor and control Full Node from GUI

---

## Dependency Graph

```
Phase 1 (Stateless)
    S.1 → S.2 → S.3 → S.4
                        S.5 → S.6
    S.7 (parallel to S.1-S.6)
    S.8 (after S.6)

Phase 1.5 (Parallel STARK) [after Phase 1, before Phase 4]
    Q.1 → Q.2 → Q.3 → Q.4 → Q.6
    Q.5 (optional, after Q.4)

Phase 2 (Consensus)
    P.1 → P.2 → P.4
    P.3 → P.4
    P.4 → P.5
    P.5 → P.6

Phase 3 (Segmented) [can start after S.6]
    F.1 → F.2 → F.3 → F.4
    F.5 (after F.3)

Phase 4 (Node) [can start after P.6]
    N.1 → N.2 → N.3 → N.4 → N.5 (built-in miner)
    N.6 (template API, parallel to N.5)
    N.7 (RPC, parallel to N.3+)
    N.8 → N.9

Phase 5 (Wallet) [W.1-W.5 start with N.1, W.6 after N.7]
    W.1 → W.2 → W.3 → W.4 → W.5 (built into Full Node)
    W.6 (Light Node CLI, after N.7)

Phase 6 (Integration) [requires N.9 + W.6]
    T.1 → T.2 → T.3 → T.4 → T.5

Phase 7 (Recursive) [can start after T.1, ship after T.5]
    H.1 → H.2 → H.3 → H.4 → H.5 → H.6 → H.7

Phase 8 (Optimizations) [incremental, any time after T.5]
    K.1, K.2, K.3, K.4 — independent

Phase 9 (GUI) [after T.5]
    G.1 → G.2 → G.3 → G.4
```

Critical path to testnet: **S → Q → P → N/W → T** (Phases 1-1.5-2-4/5-6).
Phase 1.5 is on the critical path — without it, block assembly exceeds 60s at 100 tx.
Phases 3 (Segmented) and 7 (Recursive) are parallel tracks — valuable but not blocking testnet.
Phase 9 (GUI) comes after testnet launch.

---

## Timeline Estimates

| Phase | Duration | Cumulative | Notes |
|-------|----------|------------|-------|
| Phase 1 (Stateless) | 4-6 weeks | 4-6 wk | Pure Rust, no external deps |
| Phase 1.5 (Parallel STARK) | 3-5 days | 5-7 wk | Critical path; unlocks 100-tx blocks |
| Phase 2 (Consensus) | 2-3 weeks | 7-10 wk | Deterministic math + tests |
| Phase 3 (Segmented) | 3-4 weeks | parallel | Can overlap with Phase 4 |
| Phase 4 (Node) | 6-8 weeks | 13-18 wk | Networking is the long pole |
| Phase 5 (Wallet) | 2-3 weeks | 15-21 wk | Built into Full Node + Light CLI |
| Phase 6 (Testnet) | 3-4 weeks | 18-25 wk | Integration + hardening |
| Phase 7 (Recursive) | 8-12 weeks | post-testnet | Research-grade; ships as upgrade |
| Phase 8 (Optimizations) | ongoing | post-testnet | Incremental improvements |
| Phase 9 (GUI) | 4-6 weeks | post-testnet | Desktop app, last priority |

**Testnet ETA: ~5-6 months from start of Phase 1.**

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

## Proof Architecture (Target State)

```
  LogicProof generation (~300-400ms, runs on any node with wallet)
  ┌──────────────────────────────────────────┐
  │  SpineGKR Kill-Shot (59 perms, 15-var)   │
  │  AuthGKR Kill-Shot (20 perms, 14-var)    │
  │  STARK + FRI-Binius over TxLogicAir      │
  │  Output: LogicProof (~50-55 KB)          │
  │                                          │
  │  Runs on: Full Node (built-in wallet)    │
  │           Light Node (standalone wallet)  │
  └──────────────────────────────────────────┘
           │ TxIntent (to own mempool or via RPC)
           ▼
  Full Node — Block Assembly (~8s CPU on 8 cores for 100 tx)
  ┌──────────────────────────────────────────┐
  │  Collect TxIntents from mempool          │
  │  Verify N LogicProofs                    │
  │  Build BlockStateBinding                 │
  │    - FRI state openings (gamma-RLC)      │
  │    - Segment Merkle paths                │
  │    - MerkleGKR Kill-Shot (32-slot, 14v)  │
  │    - Bridge check (C_claimed match)      │
  │  Parallel per-tx algebraic STARKs        │
  │    - Independent channels: H(root,cap,k) │
  │    - N zero-checks on N cores (rayon)    │
  │  Block-level multipoint sumcheck         │
  │  Single FRI-Binius opening               │
  │  Output: BlockProof + 248-byte header    │
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
