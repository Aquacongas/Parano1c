# PARANOID — ROADMAP2

PARANOID — Transparent Slot-Based UTXO Validity Engine
A STARK-Based Validity Engine for Transparent UTXO Chains

---

## Part I. Current Engine (Production)

The per-transaction proof engine is complete and operational. A single transaction is proved and verified end-to-end with a 50-60 KB proof.

### I.1 What the engine proves (per transaction)

Given `(prev_state_root, tx_body, new_state_root)` and a witness:

1. `tx_body` is well-formed (4 in / 8 out max, `is_coinbase` consistent).
2. Each input exists in pre-state at its claimed slot (`fri_state_open`).
3. Each input's owner is derived from a secret, and the auth tag binds the secret to this specific tx body. Proven by **AuthGKR Kill-Shot** (20-slot unified sumcheck).
4. Each output target is empty in pre-state (`is_mint => pre = 0`).
5. Each input is zeroed in post-state.
6. Each output is materialized in post-state.
7. Balance: `sum(inputs) == sum(outputs) + fee`. Range gates on all u64.
8. Body commitment: `tx_body_hash` proven by **SpineGKR Kill-Shot** (59-perm unified sumcheck). Pinned as PublicColumn in AIR.
9. Activation/deactivation bookkeeping (public columns).

### I.2 Proof architecture

```
  SpineGKR Kill-Shot (59 Poseidon2b perms, degree-7 sumcheck, 15-var MLE)
       |
       v
  AuthGKR Kill-Shot (20 auth sponges, degree-7 sumcheck, 14-var MLE)
       |
       v
  STARK + FRI-Binius (297 cols x 2^13 rows, interleaved Blake3 Merkle,
                      TAU=8, 64 queries, batched paths, mixed opening)
       |
       v
  TxProof: ~50-60 KB, verify <10 ms
```

Single Fiat-Shamir transcript (Poseidon2bChannel) binds all layers. GKR boundary MLEs committed as ExtraColumns. Kill-Shot bytes in extra_transcript.

### I.3 Soundness

| Component | Security | Mechanism |
|---|---|---|
| FRI-Binius | 128-bit | 64 queries x 2-bit rate |
| Blake3 Merkle | 128-bit | collision resistance |
| Gamma batching | 128-bit | Horner RLC over GF(2^128) |
| SpineGKR | 128-bit | Schwartz-Zippel, 15-var |
| AuthGKR | 128-bit | Schwartz-Zippel, 14-var |
| Batch-eval | 128-bit | degree-2 sumcheck + RLC |
| Fiat-Shamir | collision-resistant | Poseidon2b sponge |

No trusted setup. No elliptic curves. Post-quantum.

### I.4 Modules

```
noid_core         GF(2^128) tower, packed ops (CLMUL/AVX2), MLE, sumcheck, NTT, transcript.
noid_poseidon2b   Poseidon2b native + AIR (perm, sponge, domain tags, compression).
noid_fri          Generic FRI (legacy, used by noid_ivc primitive).
noid_fri_binius   Production PCS: interleaved commit, compact FRI, mixed opening. ~41 KB.
noid_binius       Bit/byte packing for DA bandwidth reduction.
noid_gkr          Kill-Shot GKR: spine (59-slot) + auth (20-slot), unified sumcheck,
                  shift argument, batch-eval, circuit/layers/mle_layout.
noid_air          AIRs + gates + compositions. Production: tx_validity_with_spine.
noid_stark        STARK engine: prove_tx / verify_tx (SpineKS -> AuthKS -> STARK).
noid_ivc          Linear folding accumulator (primitive, single-column).
noid_tx           TxBody, PublicInputs, wire serialization.
noid_chain        State layer: ChainState, FriState, blocks, genesis. No proof dependency.
bench_prover      Performance harness.
```

### I.5 Performance

Bench: `cargo bench --bench alice_sends_bob` (1 cold + 5 warm per scenario).

| Metric | 2in/4out (standard) | 4in/8out (max capacity) |
|---|---|---|
| Prove (median) | 725 ms | 749 ms |
| Prove (best) | 709 ms | 728 ms |
| Verify (median) | 145 ms | 150 ms |
| Verify (best) | 143 ms | 144 ms |
| Proof size | 55.62 KB | 55.52 KB |
| — STARK | 45.09 KB (81%) | 44.99 KB (81%) |
| — SpineGKR | 5.44 KB (10%) | 5.44 KB (10%) |
| — AuthGKR | 5.09 KB (9%) | 5.09 KB (9%) |

---

## Part II. Phase 3 — Recursive Chain-of-Proofs

### II.1 Goal

```
  A new node downloads one proof (~55 KB) + block header.
  Verifies in ~200-400 ms (single STARK verify of recursive circuit).
  Gains cryptographic certainty over the entire history from genesis.
  No archive. No replay. No re-execution. O(1).
```

### II.2 Key advantage: native recursion

The entire stack (STARK, FRI-Binius, GKR, Poseidon2b) operates over GF(2^128). The BlockProof verifier is also arithmetic over GF(2^128). Therefore the verifier is expressible as an AIR over the same field with zero foreign-field emulation.

This is impossible in:
- Nova/HyperNova (requires curves, not post-quantum, foreign field)
- Groth16 (trusted setup, BN254 != GF(2^128))
- Halo2 (cycle-of-curves, not post-quantum)

Here: a single algebraic universe from transaction to recursion.

### II.3 Verifier cost analysis (basis for architecture decisions)

Measured: the current `verify_tx` performs:

| Component | Poseidon2b perms | Field muls | Notes |
|---|---|---|---|
| FRI query phase (Merkle) | ~3,100 | ~2,000 | 64 queries x 6 rounds x ~8 depth |
| Fiat-Shamir channel | ~300 | — | absorb/squeeze for sumcheck + GKR |
| STARK zero-check (13 rounds, deg 8) | — | ~3,000 | composition eval dominates |
| STARK multipoint sumcheck | — | ~400 | 13 rounds, deg 2 |
| SpineGKR Kill-Shot | — | ~1,100 | 75 sumcheck rounds total |
| AuthGKR Kill-Shot | — | ~1,200 | 70 sumcheck rounds total |
| **TOTAL** | **~3,400** | **~8,000** | |

Key insight: **90% of hashing is FRI Merkle verification.** The algebraic portion
(sumcheck + GKR + composition) is ~8K field muls over GF(2^128) — trivial in-circuit.
Putting 3,400 Poseidon2b perms in-circuit costs ~2^19 rows. This is the bottleneck.

### II.4 Architecture: Deferred-FRI Split Recursion

Primary strategy: **do NOT put FRI Merkle verification in the recursive circuit.**
Instead, split the verifier into algebraic (cheap, in-circuit) and hash-heavy (deferred).

```
  ┌─────────────────────────────────────────────────────────────────┐
  │  LEVEL 1: Block Folding (Deferred Opening)                       │
  │                                                                  │
  │  Input:   N TxProofs within a single block                       │
  │  Output:  One BlockProof (~55 KB)                                │
  │                                                                  │
  │  Method:  Accumulate evaluation claims via random linear          │
  │           combination + single FRI opening at end                 │
  └──────────────────────────────┬──────────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  LEVEL 2: Recursive Chain (Deferred-FRI)                         │
  │                                                                  │
  │  In-circuit (cheap):                                             │
  │    - Replay sumcheck / zero-check / GKR algebraically            │
  │    - Derive FRI query indices from Fiat-Shamir                   │
  │    - Commit expected (leaf, root, path) tuples into a running    │
  │      Poseidon2b hash (single chain-hash, NOT full Merkle check)  │
  │    - Verify state continuity                                     │
  │                                                                  │
  │  Deferred (carried forward):                                     │
  │    - Accumulated Merkle-binding commitment                       │
  │    - Resolved at tip: one native FRI Merkle check                │
  │                                                                  │
  │  Output:  BlockProof_{n+1} (same format, ~55 KB)                 │
  └─────────────────────────────────────────────────────────────────┘
```

**Why this works:** The in-circuit part only needs ~300-500 Poseidon2b perms
(Fiat-Shamir channel + commitment chain) plus ~8K field muls. This yields a
circuit of ~2^15-16 rows instead of 2^19.

**Tip verification (end user):**
1. Verify the recursive STARK proof (~150ms, standard verify).
2. Check the deferred Merkle commitment against the tip block's FRI data (~80ms).
3. Total: ~230ms. O(1) regardless of chain length.

### II.5 Level 1: Block Folding (Deferred Opening)

**Problem:** N transactions = N separate FRI openings = N*50KB = enormous block.

**Solution:** Do not open FRI per transaction. Instead:

```
  For each tx_k (k = 1..N):
    1. Absorb PublicInputs_k into the block transcript.
    2. Check new_root_{k-1} == prev_root_k (continuity).
    3. Replay STARK sumcheck/zero-check algebraically.
    4. Replay GKR Kill-Shot algebraically.
    5. Do NOT open FRI — accumulate evaluation claim.
    6. Derive alpha_k from transcript.
    7. y_acc += alpha_k * claimed_value_k.

  After all N tx:
    8. One FRI-Binius opening for the entire batch.
    9. Package as BlockProof.
```

**Soundness:** Schwartz-Zippel: sum(alpha_k * error_k) = 0 for random alpha_k.
Probability of forgery <= N/2^128.

**Size:** ~55 KB (single FRI opening dominates). Independent of N.

**Performance (derived from bench: prove=725ms, verify=145ms per tx):**
- Accumulation per tx: ~0.01ms (absorb + field mul + squeeze). N=1000: ~10ms.
- Single FRI prove at end: ~500ms (dominates current prove time).
- **Block prove total (N=1000): ~0.5-1s.**
- Block verify (native): N * transcript_replay (~0.5ms/tx) + FRI verify (~80ms). N=1000: ~600ms.

### II.6 Level 2: Recursive Chain (Deferred-FRI)

**Principle:** BlockProof_{n+1} proves algebraic validity of BlockProof_n in-circuit
while deferring the expensive FRI Merkle checks to a running commitment.

**What the recursive circuit computes:**

1. **Algebraic replay** (~8K field muls, ~2^14 rows):
   - Zero-check sumcheck: 13 rounds, verify round polynomials.
   - Multipoint-batch sumcheck: 13 rounds, deg 2.
   - SpineGKR: unified sumcheck (15 rounds, deg 9) + shift + batch-eval.
   - AuthGKR: unified sumcheck (14 rounds, deg 9) + shift + batch-eval.
   - Composition terminal equation: evaluate AIR constraints at claimed openings.

2. **Fiat-Shamir replay** (~300 Poseidon2b perms):
   - Absorb all prover messages (commitments, round polys).
   - Squeeze all challenges (must match what the original prover used).
   - Derive FRI query indices.

3. **Deferred Merkle commitment** (~20 Poseidon2b perms):
   - From FRI data in BlockProof_n, extract expected (leaf, path, root) tuples.
   - Chain-hash them into a single 128-bit running accumulator:
     `acc_{n+1} = H(acc_n || query_data_n)`.
   - This pins ALL historical Merkle data without checking paths in-circuit.

4. **State continuity** (trivial):
   - `state_root_n == prev_root` of first tx in block n+1.

**Recursive circuit size:**
- Fiat-Shamir: ~300 perms x 66 rounds x ~10 constraints = ~200K constraints -> 2^18 rows.
- After Kill-Shot (Stage K.1): 300 perms -> one deg-7 sumcheck over 18-var MLE -> **~2^15 rows**.
- Algebraic replay: ~8K muls -> ~2^13 rows.
- **Total (with Kill-Shot): ~2^16 rows.**

**Performance estimates:**
- Recursive prove: ~3-8s (2^16-row STARK, 297+ columns, 8-core parallel).
- Recursive verify (end user): ~150-200ms (STARK verify) + ~80ms (tip Merkle check) = **~230ms**.
- Proof size: ~55-60 KB.

### II.7 Deferred-FRI soundness argument

The deferred Merkle commitment provides binding:

1. At block n, the prover includes FRI leaf/path data in BlockProof_n.
2. The recursive circuit computes `acc_{n+1} = H(acc_n || merkle_data_n)`.
3. The tip verifier receives `acc_tip` and the tip block's raw Merkle data.
4. Verifier checks: native Merkle verification of tip data, and that `acc_tip`
   matches the hash chain over all historical blocks.

**Why an adversary cannot cheat:**
- Changing any historical Merkle data changes `acc_tip` (preimage resistance).
- The algebraic checks (sumcheck, GKR, composition) are verified in full in-circuit.
- Only the Merkle binding is deferred — the polynomial evaluation claims are
  committed via Fiat-Shamir (which IS replayed in-circuit).

**Security:** 128-bit (Poseidon2b preimage + Schwartz-Zippel + FRI proximity).
No degradation with chain length — each step uses independent randomness.

### II.8 Bootstrap

```
  Block 0 (genesis):  Trivial proof "state = genesis". acc_0 = H(genesis).
  Block 1:            Proves: algebraic validity of BlockProof_0 + txs of block 1.
                      Carries: acc_1 = H(acc_0 || merkle_data_0).
  Block n:            Proves: algebraic validity of BlockProof_{n-1} + txs of block n.
                      Carries: acc_n = H(acc_{n-1} || merkle_data_{n-1}).
```

**Invariant:** verify(BlockProof_h, acc_h, tip_merkle_data) => entire history correct.

### II.9 Implementation plan

**Stage G — Block Accumulator (Deferred Folding)**

Prerequisite: working TxProof (DONE). No changes to existing crates.

- G.1. `BlockAccumulator` struct in `noid_ivc`: accepts TxProof bundles, accumulates
       evaluation claims via random-linear-combination over transcript.
- G.2. State-continuity enforcement: assert `new_root_{k-1} == prev_root_k` during
       accumulation (abort on mismatch).
- G.3. Single batched FRI-Binius opening at end: call `prove_mixed_opening` once
       for the accumulated claim.
- G.4. `BlockProof` struct + `prove_block` / `verify_block` API in `noid_stark`.
- G.5. Test: 100-tx block -> ~55 KB proof, native verify <700ms.
- G.6. Bench: 1000-tx block -> prove <1s on 8-core.

**Stage H — Deferred-FRI Recursive Circuit**

Prerequisite: Stage G (BlockProof exists).

- H.1. `RecursiveVerifierAir`: AIR that replays algebraic verifier (~8K field muls).
       Pure arithmetic over GF(2^128), no hashing except Fiat-Shamir.
- H.2. In-circuit Fiat-Shamir: Poseidon2b sponge AIR (~300 perms).
       Reuse existing `poseidon_perm` AIR rows, scaled to 300 slots.
- H.3. Deferred Merkle accumulator: in-circuit `acc_{n+1} = H(acc_n || data_n)`.
       ~20 extra Poseidon2b perms (compress query_data blob).
- H.4. State-continuity gate: `prev_root == state_root_n` equality in AIR.
- H.5. Compose into single `RecursiveBlockAir`. Prove with existing FRI-Binius PCS.
- H.6. Tip verifier: standalone function that checks recursive STARK proof +
       native Merkle verification of tip block's FRI data + acc chain.
- H.7. End-to-end test: 5-block chain, verify tip only, confirm O(1).

**Stage K — Optimizations (apply incrementally)**

- K.1. **Kill-Shot for in-circuit Poseidon2b** (primary optimization).
       300 Fiat-Shamir perms -> one unified deg-7 sumcheck over 18-var MLE.
       Reduces circuit from ~2^18 to ~2^15 rows. Expected prove: ~3-5s.
- K.2. **Reduced inner queries**: use NUM_QUERIES=16 for block-internal proofs
       (32-bit standalone, but nested inside full-security recursive proof).
       Reduces Fiat-Shamir perms further (fewer query indices to derive).
- K.3. **Parallel recursive prover**: partition recursive trace across 8 cores
       for commit + NTT phases.
- K.4. **Incrementality**: only re-prove the recursive verifier + new txs;
       reuse committed columns from previous block where unchanged.
- K.5. Target after all optimizations: **recursive prove <3s, verify <200ms.**

### II.10 Risks and mitigations

| Risk | Mitigation |
|---|---|
| Fiat-Shamir replay circuit still large (~2^18) | K.1: Kill-Shot compresses to ~2^15 |
| Deferred Merkle accumulator soundness subtle | H.6: formal argument + test with adversarial prover |
| Recursive prove >10s before K.1 | Acceptable for first version; K.1 is incremental |
| Tip verifier requires raw Merkle data (~55KB) | Already carried in BlockProof; no extra bandwidth |
| Proof size growth with wider recursive trace | Same FRI params; trace wider but log_rows smaller |

### II.11 Future exploration: FRI-less accumulation

A more radical approach (post-implementation research):

Instead of deferring FRI Merkle checks to the tip, eliminate FRI entirely from the
recursive loop. Each block produces an "evaluation claim" (polynomial P opens to y at z).
A running accumulator collects claims via random-linear-combination. Only a periodic
"squash" step (every M blocks) actually proves the accumulated claims with one FRI opening.

**Tradeoffs:**
- Pro: recursive circuit becomes purely algebraic (no Poseidon2b at all). ~2^13 rows.
       Prove time <1s. Verify <150ms.
- Con: accumulator state grows linearly until squash. Squash step expensive (~10-30s).
       Requires careful soundness argument for unbounded accumulation.
- Con: tip verifier must wait for next squash or carry accumulator state (larger proof).

**Verdict:** Worth investigating after Stages G/H/K are complete and benchmarked.
The deferred-FRI approach (II.4-II.6) is the pragmatic first step; FRI-less accumulation
is an asymptotic improvement that may or may not be needed depending on real performance.

---

## Part III. Non-goals

- Mempool policy, fee market, PoW, difficulty, reorg, finality, gossip.
- Block-assembler logic beyond test driver.
- New hash primitive.
- DA layer implementation (chain concern, not proof engine).
- Wallet UX, slot-hint service.

---

## Part IV. Coverage matrix

| Spec section | Status |
|---|---|
| S0 state model (3-col FRI, zero-subtree) | DONE |
| S2 Address = H_ADDR(secret) | DONE (AuthGKR Kill-Shot) |
| S3 tx body + body hash | DONE (SpineGKR Kill-Shot) |
| S4 ownership + state correctness | DONE |
| S5 public inputs | DONE |
| S12 coinbase | DONE |
| S15.1 is_mint => pre=0 | DONE |
| Proof size ~55 KB | DONE (55.5 KB measured) |
| Verify ~145 ms (per tx) | DONE (145 ms measured) |
| Block = aggregated proof | PRIMITIVE (noid_ivc linear fold) -> Stage G |
| Recursive chain O(1) | DESIGNED -> Stage J |
