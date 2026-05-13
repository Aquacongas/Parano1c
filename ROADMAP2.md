# PARANOID — ROADMAP2

PARANOID — Transparent Slot-Based UTXO Validity Engine
A STARK-Based Validity Engine for Transparent UTXO Chains

PARANOID is a proof-native STARK-based validity engine. Computation, state, and transitions are unified in a single binary-field model. The system proves correctness of state transitions without trusted setup, without transaction re-execution, and without signature-based authorization semantics: each transaction ships with a deterministic validity proof derived directly from the state transition it performs.

PARANOID combines three architectural properties rarely unified in existing blockchain systems:
- transparent slot-based state execution,
- proof-native validity semantics over a binary-field STARK model,
- hardware-accelerated GF(2^128) arithmetic.

The execution model is built around a reusable slot-based state architecture. State slots are recycled after spend; the ledger expands automatically (`log_slots += 1`) when sustained occupancy demands more capacity. This allows deterministic state growth without global account mutation or permanent address-space accumulation.

A defining feature is the separation of mathematical semantics from hardware execution. The system operates natively over a GF(2^128) binary tower field within the STARK proving model, while selectively projecting arithmetic into a hardware-optimized polynomial basis for CLMUL-accelerated multiplication and squaring, before re-lifting results back into the canonical proof representation.

**Current Proving Stack (in `main`):** The system uses Poseidon2b inside the AIR, a native GF(2^128) binary tower field for execution semantics, and Poseidon2b-Merkle FRI for polynomial commitments. The 59-permutation Poseidon2b spine that compresses the transaction body into `tx_body_hash` lives in a dedicated GKR sub-protocol (`noid_gkr`), while all other Poseidon2b permutations (Auth, Merkle paths) currently reside inside the STARK AIR, resulting in a wide trace (~575 columns). 

**Target Proving Stack (Post-Phases 1-3):** The engine will evolve to use Basefold PCS for commitments, move all hashing into Fat GKR (leaving a Skinny STARK of ~50 columns), and use Deferred IVC Folding for constant-size block proofs.

The result is a transparent, post-quantum validity engine intended for integration into full blockchain protocols.

---

**Engine track. The STARK validity engine.**

`SPECIFICATION.md` describes the blockchain — state model, transactions, consensus, blocks, coinbase, activation bookkeeping, `log_slots` expansion — and `DESIGN_NOTES.md` carries the proof-native ledger philosophy. This ROADMAP2 scopes down to the **engine obligations** only: everything the STARK validity engine must provide so that, when a chain/node/wallet layer is later built on top, the design of `SPECIFICATION.md` can be realized without patching the engine.

**Out of scope for this roadmap** (explicitly, so we stop drifting):
- P2P networking, node daemon, block propagation, gossip.
- Mempool admission, fee market, replay protection beyond tx-level.
- Block-assembly policy (conflict tie-break, coinbase construction policy, reorg handling, finality windows).
- Wallet UX, key management, slot-hinting services, wallet-side retries.
- Consensus (PoW puzzle, difficulty retargeting, chain selection).

**In scope for this roadmap** (what the engine must deliver, end to end):
- Every in-circuit predicate required to validate one transaction against a prev-state commitment and a new-state commitment.
- Every public input / public column the chain layer will need to compose tx proofs into a block proof.
- Every commitment primitive: state commitment, body commitment, DA witness commitment, proof-level PCS (currently FRI, migrating to Basefold).
- Aggregation over a block of N txs via IVC Folding (currently linear, migrating to Succinct/Deferred).
- Recursive chain-of-proofs: `Proof_{n+1}` verifies `Proof_n`.
- Parallel-proving harness for disjoint-slot-set txs.
- Explicit, testable performance targets (proof size, prove time, verify time) enforced by a CI regression gate.

---

## Part I. Current Engine Architecture (As implemented in `main`)

*Note: This section describes the codebase as it exists today. See Part II for the plan to evolve this architecture.*

### I.1 Predicate the engine proves, per transaction

Given `(prev_state_root, tx_body, new_state_root)` and a witness, the engine proves:

1. `tx_body` is well-formed: field ranges valid, input/output counts within bounds, `is_coinbase` flag consistent.
2. For each live input `i`: `(value_i, owner_i) == prev_state[slot_index_i]` — i.e. the input exists in the pre-state. (`fri_state_open` against `prev_state_root`).
3. For each live input `i`: `owner_i == H_ADDR(secret_i)` and `auth_tag_i == H_AUTH(secret_i, tx_body_hash)`. (Currently in-AIR `haddr` and `hauth`).
4. For each live output `j`: `prev_state[slot_index_j] == (0, 0, 0)` — the mint target is empty in pre-state. (`is_mint ⇒ pre = 0`).
5. For each live input `i`: `new_state[slot_index_i] == (0, 0, 0)` — input is zeroed in post-state. (`fri_state_open` on `new_state_root`).
6. For each live output `j`: `new_state[slot_index_j] == (value_j, owner_j)` — output is materialized in post-state. (`fri_state_open` on `new_state_root`).
7. Balance: regular tx `Σ inputs.value == Σ outputs.value + fee`; coinbase `Σ outputs.value == coinbase_credit`. `range_gate` on every u64.
8. Body commitment: `tx_body_hash`, produced end-to-end by the GKR spine sub-proof. On the STARK side the two lanes of `tx_body_hash` are row-pinned via `PublicColumn`.
9. Activation bookkeeping: `is_activation[j]`, `is_deactivation[i]` boolean public columns.

**Architectural invariant — the new-state commitment is attested in-circuit, not recomputed natively by the chain.** The engine must be self-contained.

### I.2 What does NOT move through the engine

Out of the predicate, because it is a chain/block concern:
- Aggregating many `is_activation[j]` / `is_deactivation[i]` public columns across txs to match the block-header `active_slot_count` delta.
- Enforcing `coinbase_credit == block_reward(height) + Σ fees`.
- Enforcing "coinbase tx is at position 0 and appears at most once".
- Enforcing `log_slots` growth policy.

### I.3 Commitments the engine currently owns

| Commitment | What it commits to | Primitive | Module |
|---|---|---|---|
| `state_root` | `(value, owner_hi, owner_lo)` over `2^log_slots` slots | 3× FRI over GF(2^128), combined by `Poseidon2bSponge` | `noid_chain::fri_state` |
| `tx_body_hash` | the tx body (inputs, outputs, flags) | `Poseidon2bSponge` via the GKR 59-perm spine | `noid_tx`, `noid_gkr` |
| GKR boundary MLE | Poseidon2b trace of the 59-perm spine | Sumcheck + FRI opening | `noid_gkr` |
| `witness_root` (DA) | per-block packed witness columns | `PackedCommit` / Poseidon2b Merkle | `noid_binius` |
| per-tx proof `π` | satisfaction of the predicate in §I.1 | STARK over binary tower + FRI | `noid_stark` |
| block-level proof `Π` | fold of N tx proofs | IVC linear folding accumulator | `noid_ivc` |

### I.4 Modules, by role (Current)

```
noid_core         : GF(2^128) tower arithmetic, packed ops, MLE, sumcheck, AdditiveNTT, transcript.
noid_poseidon2b   : native + AIR-side Poseidon2b (permutation, sponge, domain tags).
noid_fri          : RS-code + Poseidon2b-Merkle + prover/verifier, batched PCS.
noid_binius       : bit/byte packing into Block128, PackedCommit, DA root.
noid_gkr          : GKR sub-protocol for the 59-permutation tx-body spine; emits a
                    boundary MLE evaluation absorbed by the STARK transcript.
noid_air          : AIRs (gates, single-purpose AIRs, compositions). Currently wide (~575 cols).
noid_stark        : STARK wrapper — multipoint + ladder batch, vshift, FRI proof object.
noid_ivc          : linear folding accumulator (block-level aggregation).
noid_tx           : TxBody / TxInput / TxOutput / TxBodyHash / PublicInputs, wire, body_hash.
noid_chain        : thin state layer — ChainState, apply_tx, FriState-backed state, genesis, block driver.
bench_prover      : perf harness + reports.
```

### I.5 – I.7 (Unchanged: Activation, Coinbase, DA)

### I.8 Canonical flow — single live output, end to end

```
Stage 0 (wallet)         TxOutput { slot_index_j, value_j, owner_j, valid: true }.

Stage 1 (body hash)      Native hash_tx_body. In-circuit: tx_body_merkle boundary pins.
                         Final wrap squeeze → tx_body_hash pinned as PublicColumn.

Stage 2 (balance)        balance_gate, parameterized by is_coinbase. range_gate on every u64.

Stage 3 (auth)           Per input i: haddr_block[i], hauth_block[i] (in-AIR Poseidon2b).

Stage 4 (state)          Per input i: fri_state_open(prev, slot_i), fri_state_open(new, slot_i).
                         Per output j: fri_state_open(prev, slot_j), fri_state_open(new, slot_j).
                         fri_state_combiner recomputes roots.

Stage 5 (public)         PublicInputs = (prev_state_root, new_state_root, tx_body_hash,
                                         fee, coinbase_credit, log_slots,
                                         is_activation[*], is_deactivation[*]).
```

### I.9 AIR inventory (Current)

Implemented and gated by tests:
- Gates: `bool`, `mul`, `linear`, `selector`, `row_selector`, `eq_ladder`, `const_column`.
- Single-purpose: `balance_gate`, `range_gate`, `bit_adder`, `carry_ripple`, `haddr`, `hauth`, `poseidon_perm`, `poseidon_sbox`, `poseidon_mds`, `linear_combination`, `tx_body_spine` (thin 2-lane pin), `fri_state_open`, `fri_state_combiner`, `tx_validity`.
- Note: `haddr`, `hauth`, and `fri_state_open` are currently materialised inside the STARK AIR. Evacuating them to GKR is the goal of Phase 1.

---

## Part II. Phased Delivery Plan (The Evolution)

The roadmap is structured into three major architectural phases to transform the engine from its current state (Part I) into a succinct, mobile-friendly validity engine, followed by DA, parallelism, and recursion integration.

### Phase 1: Skinny STARK / Fat GKR [IN PROGRESS]
*Detailed spec: `phase1.md`*

Evacuate all repetitive high-degree computations (Poseidon2b permutations for Auth and Merkle state openings) from the STARK AIR into the GKR sub-protocol.
- **Goal:** Reduce `n_cols` from ~575 to ~50-80. STARK becomes a lightweight algebraic router. GKR handles all hashing via degree-2 Sumcheck layers.
- **Key modules:** `noid_gkr`, `noid_air`.
- **Exit:** Prover time < 300ms. Verify time < 30ms. Proof size ~100 KB.

#### Status tracker (updated as work lands)

##### Phase 1 baseline (locked — pre-AuthGKR)

Measured on `main` via `cargo bench --bench stark_report` (release, warmup 1 / samples 3). These numbers are the anchor every Phase 1 step compares against.

Per-tx headline (`TxValidityCompositeWithSpine`, fixture: 2 live in / 4 live out, fee 50):
- `log_rows = 13`, `n_cols = 575`, `shifted = 115`.
- prove = **1.68 s**, verify = **227.02 ms**, proof ≈ **290.48 KB**.
- Hot spots of prove: transcript + sumcheck 767 ms (54.8%), multipoint + FRI 332 ms (23.7%), ladder sumcheck 158 ms (11.3%), commit 144 ms (10.3%).

Component anchors:
- `RangeGateAir` (prod, log_rows 16, 1024 instances): prove 216.92 ms, verify 48.15 ms, proof 384.11 KB, n_cols 4.
- `PoseidonPermAir` (1 perm, log_rows 8): prove 17.32 ms, verify 10.85 ms, proof 35.61 KB, n_cols 30.
- `HAddrAir` (2 perms, log_rows 8): prove 30.32 ms, verify 19.24 ms, proof 38.73 KB, n_cols 71.
- `HAuthAir` (3 perms, log_rows 8): prove 40.30 ms, verify 26.35 ms, proof 41.48 KB, n_cols 106.

After Phase 1 completes, the `HAddrAir` / `HAuthAir` component benches disappear (circuits deleted); the per-tx headline must land at `n_cols ≤ 80`, prove < 300 ms, verify < 30 ms, proof ≈ 100 KB per the phase exit.

##### Baseline already shipped on `main`:
- 59-perm `tx_body_hash` spine evacuated into `noid_gkr` (spine_sumcheck, perm_sumcheck, product_sumcheck, batch_eval, layers, mle_layout, oracle, circuit, binding). `TxValidityCompositeWithSpine` is the production composite; the ex-merkle band survives as a 2-lane `PublicColumn` pin only.

Production inventory confirmed by reference tracing (`TxValidityCompositeWithSpine` → `TxValidityCompositeLeaf` → {`shared_haddr_block`, `shared_hauth_block`, `fri_state_open`, `fri_state_combiner_composite`}):
- **PROD** STARK AIRs still carrying Poseidon2b: `airs/haddr_multi.rs`, `airs/hauth_multi.rs`, `airs/fri_state_open.rs`, `airs/fri_state_combiner.rs`, `airs/fri_state_combiner_composite.rs`, `airs/poseidon_perm.rs` (+ `poseidon_sbox.rs`, `poseidon_mds.rs` as trace helpers).
- **DEAD / pre-unification** (to be removed alongside their PROD callers): `airs/haddr.rs`, `airs/hauth.rs`, `composition/haddr_block.rs`, `composition/hauth_block.rs`, `composition/tx_validity_composite.rs`, `composition/tx_validity_full.rs`.

Phase 1 splits into two atomic steps. Each step is one commit that compiles and passes the full workspace test suite; legacy files are deleted **in the same commit** that lights up the GKR replacement. No `#[cfg]` legacy gating.

##### Step 1 — AuthGKR [DONE]

Scope: evacuate HAddr (2 perms/input) + HAuth (3 perms/input) from the STARK AIR into a new GKR sub-protocol, reusing the spine's sumcheck machinery (`layers`, `product_sumcheck`, `perm_sumcheck`, `batch_eval`) verbatim.

Execution cadence — Step 1 is cut into two atomic commits to keep each commit green:

- **Step 1a [DONE] — additive foundation, zero deletions, zero STARK changes.** Land `noid_gkr::auth_circuit` + `auth_oracle` + `auth_sumcheck` with full test coverage (differential-vs-native, honest + tamper sumcheck, transcript determinism). `noid_air` and `noid_stark` untouched; the new modules are exercised by `noid_gkr/tests/*` only. Workspace stays green — the AuthGKR path is usable internally but not yet wired into the STARK composite (mirrors how the spine was developed before its bridge landed).
- **Step 1b [OPEN] — atomic flip.** In one commit: STARK bridge update (`extra_transcript` ordering extended, new `PublicColumn`s pinning `(Address, AuthTag)`), `TxValidityCompositeWithSpine` refactor to drop the haddr/hauth embeddings, deletion of the legacy AIRs + composition modules listed below, update of `stage_5_7_roundtrip.rs`. Compile + full test suite + bench must be green at the end of this commit.

Structural plan:
1. **New circuit.** `noid_gkr::auth_circuit::AuthCircuit` = 5 slots × `MAX_INPUTS` = 20 Poseidon2b permutation slots. Topology per input:
   - HAddr-A (head, IV = `capacity_iv(TAG_ADDRESS)`), HAddr-B (chains from A via inter-perm XOR).
   - HAuth-A (head, IV = `capacity_iv(TAG_AUTHTAG)`), HAuth-B (chains from HAuth-A, absorbs `tx_body_hash`), HAuth-C (chains from HAuth-B).
   - IVs read from `noid_poseidon2b::native::domain` — no constant duplication.
2. **Oracle.** `noid_gkr::auth_oracle::evaluate_auth(circuit, inputs) -> AuthWitness`. Drives `Poseidon2bPermutation` slot-by-slot. Differential oracle tied to `noid_poseidon2b::native::digest::{derive_address, hash_auth_tag}`.
3. **Sumcheck orchestration.** `noid_gkr::auth_sumcheck::{prove_auth, verify_auth}` cloned structurally from `spine_sumcheck`:
   - Absorb claimed `(Address_hi, Address_lo, AuthTag_hi, AuthTag_lo)` per input.
   - Per-slot `perm_sumcheck::prove_perm`, 3 state claims each, lifted into `B_auth = ‖ state_in` boundary MLE (`N_AUTH_BOUNDARY_VARS = 9 + ceil_log2(20) = 14`).
   - `batch_eval::prove_batch_eval` collapses 60 lifted claims into one `(r_B, v_B)`.
   - Equality-bound boundary: HAddr-B final `state_out[0..1]` == `(Address_hi, Address_lo)`; HAuth-C final `state_out[0..1]` == `(AuthTag_hi, AuthTag_lo)`. Rejects closed on mismatch (no probabilistic handoff).
4. **STARK bridge.** `AuthProof` bytes flattened into `extra_transcript` **after** spine bytes, **before** zero-check draw. Boundary-MLE `B_auth` committed via the same FRI batch plumbing the spine uses. New `PublicColumn`s pin `(Address_hi/lo, AuthTag_hi/lo)` per input; `TxValidityAir` gets a linear equality to `OwnerHi/Lo` / `AuthTagHi/Lo`.
5. **AIR slimming.** `TxValidityCompositeWithSpine` drops the `shared_haddr_block` and `shared_hauth_block` embeddings; `tx_validity_leaf` no longer routes HAddr/HAuth witness bands. Expected column reduction ≈ 500+ cols (haddr_multi + hauth_multi + composition overhead).
6. **Legacy deletion (same commit).** Remove: `airs/haddr.rs`, `airs/haddr_multi.rs`, `airs/hauth.rs`, `airs/hauth_multi.rs`, `composition/haddr_block.rs`, `composition/hauth_block.rs`, `composition/shared_haddr_block.rs`, `composition/shared_hauth_block.rs`, `composition/tx_validity_hauth.rs`, `composition/tx_validity_full.rs`, `composition/t1_owner_tie.rs`, `composition/bridge.rs` (verify orphan), trimmed `composition/registry.rs`. Verify no other crate references before deletion.
7. **Tests.** Mirror the spine test matrix: `tests/auth_differential_vs_native.rs`, `tests/auth_sumcheck.rs` (honest + ≥ 4 mutations + transcript determinism), `tests/auth_transcript_vectors.rs`. Update `noid_stark/tests/stage_5_7_roundtrip.rs`.
8. **Docs.** Append §7 to `noid_gkr/SPEC.md` and attack-vector rows to `noid_gkr/AUDIT.md`. Update `phase1.md` with the realised Auth numbers.
9. **Exit.** `cargo build --workspace` green; `cargo test --workspace` green; `n_cols` drops by ≥ 450; privacy invariant preserved (no `SpendSecret` anywhere in the public surface, enforced by a grep hook in tests).

##### Step 1.5 — Spine Kill Shot (Unified Degree-7 Sumcheck with CoV) [OPEN]

Scope: collapse the 472 product-sumchecks of the 59-slot Poseidon2b tx-body spine into **one degree-9 sumcheck** that simultaneously discharges the S-box identity (`C1`) and the MDS+RC linear identity (`C2`) under a change-of-variable that linearises the round shift. This is purely a Spine-internal optimisation — AuthGKR (Step 1) and MerkleGKR (Step 2) remain on the legacy degree-2/3 path until follow-up PRs port them to the same pattern.

**Architectural correction (post Stage 1.5.4 review).** The originally planned separate degree-1 MDS sumcheck (Stage 1.5.5) is **cancelled**. In a binary-field MLE, the round-shift `inc(x)` (binary increment with carry over the 7 round bits) is a degree-7 polynomial in `x`, so `s_in(inc(x))` is **not** multilinear and cannot be discharged by a degree-1 sumcheck. Instead we fold `C2` into the same degree-7 sumcheck with an FS-derived RLC challenge `β`, and we **change the summation variable** from `x` to `y = inc(x)` so the shift moves out of the MLEs and into a public coefficient `U(y)`.

Motivation: the current per-slot chain (1 sout=x4·x3, 1 x4=x2·x2, 1 x3=x2·sin, 2 x2=sin·sin, 3 sin-expansion) consumes 8 product-sumchecks × 59 slots = **472 sumchecks per spine**, ~4248 FS rounds, ~280 KB of GKR proof bytes, ~1.6 s prove, ~1 s verify at the spine layer. The kill shot replaces this with **two sumchecks total** (≈ 30 FS rounds), driven directly by `s_out = sigma · s_in^7 + (1-sigma) · s_in` over a single 15-var MLE.

Hard architectural constraints (locked before coding):
- **Out of scope here:** AuthGKR + MerkleGKR. They keep the legacy `prove_single` (D=2) and `product_sumcheck` (D=3) paths via the wrapper introduced in Stage 1 below.
- **STARK boundary contract unchanged.** The 15-var boundary MLE `B = ‖ state_in[slot]` already exists (`spine_sumcheck.rs:71-75`). The new orchestrator extracts `s_in[round=0]` per slot and feeds the same `build_boundary_mle_from_mles` shape into `extra_transcript`. No changes to `noid_stark/src/spine.rs`, no new `PublicColumn`s, no new commit.
- **Honest Fiat-Shamir.** Replace the current `transcript.iter().fold(+)` challenge derivation (`noid_core/src/sumcheck/prove.rs:89`) with `FiatShamir::absorb`/`squeeze` throughout. Legacy tests with hardcoded FS fixtures will be regenerated in the same commit. No two FS engines in tree.
- **Cross-sumcheck binding.** Degree-7 and degree-1 sumchecks are chained via FS absorption of the degree-7 final point claims `(s_in(r'), s_out(r'), σ(r'))` before the verifier draws the RLC challenge `β` that opens degree-1. This pins both sumchecks to the same boundary coordinates.

Execution cadence — six atomic stages, each compiles and tests green on its own:

- **Stage 1.5.1 [DONE] — Generalised sumcheck core.** `noid_core/src/sumcheck/{prove,verify}.rs`. Generalise `RoundPolynomial` from `[F; 3]` to `Vec<F>` (or const-generic `[F; D+2]`). Add `prove_single_d<const D: usize>` and Lagrange interpolation through `d+2` points `{0, 1, …, d+1}` over GF(2^128). Switch challenge derivation to `FiatShamir::absorb`/`squeeze`. Keep `prove_single` as a `D=2` wrapper. Update `auth_sumcheck`, `batch_eval`, `product_sumcheck` callsites to use the wrapper (zero behaviour change for them, but FS bytes change — regenerate any `transcript_vectors` fixtures in the same commit).

- **Stage 1.5.2 [DONE] — Frobenius pow7.** `noid_core/src/packed/pow7.rs`. `pow7_block128(x) = x^4 · (x^2 · x)` (3 muls + 2 free squarings via `Block128::square`). SIMD variant on `PackedBlock128` (re-using `simd_square_avx2`). Unit tests vs. naive 7-fold multiplication; benches showing > 2× over `x.pow(7)`.

- **Stage 1.5.3 [DONE — extended in 1.5.4-A.2] — Unified 15-var MLE layout.** `noid_gkr/src/spine_mle.rs`. **Four** MLEs of length `2^15 = 32768`, indexed `(slot:6 | round:7 | elem:2)`:
  1. `s_in[idx]` — input to the S-box (zero on padded / inactive cells).
  2. `s_out[idx]` — output after the S-box (zero on padded / inactive cells).
  3. `sigma[idx]` — public 0/1 selector derived from Poseidon2b topology (`F_ROUNDS=8` full, `P_ROUNDS=58` partial × `STATE=4`). `sigma=1` iff the cell goes through `x^7`.
  4. `state[idx]` — round-entry state (post-initial-MDS at `round=0`; permutation output at `round=N_ROUNDS`). Required to close the linear C2 (MDS shift) identity on partial rounds, where lanes 1..3 of `state[r+1]` come from `state[r][1..3]`, **not** from `s_out[r][1..3]` (the witness pins those to zero).
  Slots `≥ N_SPINE_SLOTS` and rounds `> N_ROUNDS` zero-padded. Legacy `mle_layout.rs` `X2, X3, X4` columns survive only for AuthGKR/MerkleGKR until they are migrated.

- **Stage 1.5.4 [REWORK — IN PROGRESS] — Unified Degree-9 Sumcheck + Shift Gadget.** `noid_gkr/src/spine_degree7.rs`. The original Stage 1.5.4 (S-box only) is superseded; this stage now discharges all three identities (C1, C1', C2) plus a small CoV-correctness gadget. Proven identity, after change of variable `y = inc_round(x)`:

  ```text
  Σ_y  U(y) · [ C1(dec(y))  +  β · C1'(dec(y))  +  γ · C2(y) ]  =  0
  ```

  where:
  - `dec(y) = inc_round^{-1}(y)` — integer decrement of the 7 round bits inside the index `y`.
  - `U(y) = eq(ρ, dec(y)) · μ(dec(y))` — public coefficient. `μ(x) = 1` iff `round(x) < N_ROUNDS` and `slot(x) < N_SPINE_SLOTS` (live witness cell). C2's source row lives at `dec(y)`, and C1/C1' are indexed at `dec(y)`, so a single mask covers all three.
  - `C1(x) = σ(x)·(s_out(x) + s_in(x)^7) + (1+σ(x))·(s_out(x) + s_in(x))` — S-box identity at `x = dec(y)`. Degree 7 in MLE values.
  - `C1'(x) = σ(x) · ( s_in(x) + state(x) + RC(x) )` — RC tie at `x = dec(y)`. The `σ` mask is mandatory: on partial rounds at lanes 1..3 the witness has `σ=0`, `s_in=0`, `state≠0`, so the unmasked form is false. Degree 2 in MLE values.
  - `C2(y) = state(y) + Σ_j  M_{kind(dec(y))}[elem(y)][j] · π(dec(y) | e=j)` where `π = σ·s_out + (1+σ)·state`. On full rounds `σ=1` ⇒ `π=s_out`; on partial rounds at j≥1 `σ=0` ⇒ `π=state` (lane pass-through). Degree 2 in MLE values. `MDS` switches between `MDS_FULL` and `MDS_PARTIAL` based on `kind(dec(y))`.
  - `β`, `γ` squeezed from the FS channel after `ρ` and before the round loop.

  **Prover algorithm — Immutable-Tables fold (Variant I).** The 32768-cell MLEs are small, so we materialise *one* permuted state table once and treat all factors as standard multilinear MLEs in `y`. Inside `compute_round_polynomial`:
  1. Build `state_inc[y] = state[inc_round_index(y)]` once, before the round loop. This is a pure permutation of the `state` table by the round-shift.
  2. Build `U[y] = eq(ρ, dec(y)) · μ(dec(y))` once (15-var public table, verifier-recomputable).
  3. Build `RC_dec[y] = RC[dec(y)]`, `σ_dec[y] = σ[dec(y)]`, `state_dec[y] = state[dec(y)]`, `s_in_dec[y] = s_in[dec(y)]`, `s_out_dec[y] = s_out[dec(y)]` once each (also pure permutations by the round-shift).
  4. The constraint becomes a standard product of multilinear MLEs in `y`:
  ```text
   F(y) = U(y) · [
            C1: σ_dec(y)·(s_out_dec(y) + s_in_dec(y)^7) + (1+σ_dec(y))·(s_out_dec(y) + s_in_dec(y))
          + β · σ_dec(y)·(s_in_dec(y) + state_dec(y) + RC_dec(y))
          + γ · ( state(y) + Σ_j M_{kind(dec(y))}[elem(y)][j] · π_dec(y, j) )
         ]
  ```
   where `π_dec(y, j) = σ(dec(y) | e=j) · s_out(dec(y) | e=j) + (1+σ(dec(y) | e=j)) · state(dec(y) | e=j)`. The four `j`-substituted lookups are NOT MLEs in `y`; they are read out of `s_out` and `state` at integer indices `dec(y) | e=j`, and the **MDS coefficients are public**, so this term contributes a fixed degree-2 multilinear factor in `y` per `j`. To stay multilinear in `y`, we precompute four more permuted tables `pi_dec[j][y] = π(dec(y) | e=j)` (each is degree 2 in `s_out`, `state`, `σ` — but evaluated at fixed indices, so as a function of `y` it is multilinear).
  5. Round poly degree: 9 (eq:1 in U times deg-7 sin^7 times deg-1 σ_dec gives 9 in C1; C1' contributes deg 3; C2 contributes deg 3 via the LHS state(y) + the four MLE π_dec lookups. Max stays 9.)
  6. Standard high-to-low fold across all 12 helper tables: `U`, `σ_dec`, `s_in_dec`, `s_out_dec`, `state_dec`, `RC_dec`, `state` (LHS of C2), `pi_dec[0..3]`, plus a fold helper for `M_{kind}[elem(y)][j]` — but since `M[·][j]` depends on `kind(dec(y))` AND `elem(y)`, both are public deterministic functions of `y`, so we precompute four more tables `mds_pi_dec[j][y] = M_{kind(dec(y))}[elem(y)][j] · pi_dec[j][y]` and fold those instead.

  Total helper tables folded: `U`, `σ_dec`, `s_in_dec`, `s_out_dec`, `RC_dec`, `state_dec`, `state`, plus 4 × `mds_pi_dec[j]` = **11 tables** of 32K Block128. Memory ≈ 5.6 MB. Hot loop ≈ 15 rounds × 10 evals × 2^14 cells × 11 muls ≈ 27M GF(2^128) muls — well under the 50 ms budget.

  After the main sumcheck (15 rounds), the prover obtains a final point `r' ∈ F^15` and ten claimed evaluations:
  - `s_in_dec_ml(r')`              — drives C1, C1' (will be reduced to `s_in(r'_x*)` via shift gadget).
  - `state_ml(r')`                  — drives C2 LHS (already a direct opening of `state` at `r'`).
  - `s_out_dec_ml(r' | e=j)` for j=0..3  — actually four separate claims at points `(r'_slot, r'_round, e=j)` (we open the underlying `s_out_dec` table, restricted to fixed `e=j`, so the elem-bits of `r'` are *not* used for these — they are 4 separate evaluations at `(r'_slot, r'_round)` of the round-shifted `s_out`).
  - `state_dec_ml(r' | e=j)` for j=0..3  — same shape; 4 evaluations of round-shifted `state`.

  These nine "_dec" claims live on the **round-shifted** versions of the committed columns. The shift gadget (below) reduces all of them to claims on the **original** `s_in`, `s_out`, `state` columns at one common point `r''` so they can be batch-opened.

  **Shift gadget (sub-sumcheck).** Proves the equality of two MLEs with a public permutation between them:
  ```text
   Σ_y eq(r', y) · T_dec(y) = Σ_y eq(r', y) · T(dec(y)) = Σ_x eq(r', inc(x)) · T(x) = Σ_x W(x) · T(x)
  ```
   where `W(x) = eq(r', inc(x))` is verifier-public (15-var table built natively from `r'`). The gadget is one classical product-sumcheck of degree 2 over 15 rounds; the prover and verifier run it once per `_dec` claim, OR (more efficiently) batch all nine `_dec` claims with FS-derived RLC `δ` into one sumcheck and obtain a single combined claim at point `r''`, plus per-column claims at substituted points. We batch.

  Concretely: after the main sumcheck, the prover absorbs all ten claimed evaluations, the channel squeezes `δ`, then runs **one shift sumcheck of 15 rounds, degree 2**, on the combined statement
  ```text
   Σ_x W(x) · [ s_in(x) + δ·s_out(x|e=0) + δ²·… + δ⁸·state(x|e=3) ] = (claimed combined value)
  ```
   with `W(x) = eq(r', inc(x))`. After 15 rounds: one final point `r''`, one combined opened value, plus the verifier checks each per-column claim by linear-combining the standard openings using `δ`-powers and elem-eq weights.

  **Final batch_eval surface (10 claims at point `r''`):**
  1. `s_in(r'')`
  2. `state(r')`                   (direct, no shift)
  3-6. `s_out(r'' | e=j)` for j=0..3
  7-10. `state(r'' | e=j)` for j=0..3

  The verifier:
  - Recomputes `σ(·)`, `RC(·)`, `μ(·)`, `eq(ρ, dec(y*))`, `MDS_{kind(·)}` natively.
  - Verifies the main sumcheck's deg-9 rounds and the shift gadget's deg-2 rounds independently.
  - Reconstructs `s_out_dec_ml(r'|e=j)` and `state_dec_ml(r'|e=j)` from the post-shift claims via the gadget's reduction.

  All 10 final openings of the original committed columns are batched through the single `batch_eval::prove_batch_eval` invocation in Stage 1.5.6.

- **Stage 1.5.5 — CANCELLED.** A separate degree-1 MDS/RC sumcheck is not realisable in binary fields because the round-shift `inc(x)` has degree 7 in `x`. The constraint is folded into Stage 1.5.4 via `β` and the `y = inc(x)` change of variable. No `spine_degree1.rs` is created.

- **Stage 1.5.6 [LANDED — additive] — Orchestration via `spine_killshot`.** New module `noid_gkr/src/spine_killshot.rs` lives alongside the legacy `spine_sumcheck.rs`:
  1. `build_unified_from_inputs` — materialises `SpineUnifiedMle` (`s_in`, `s_out`, `state` columns, 15 vars each) from `SpineInputs`.
  2. `prove_spine_killshot` — runs `prove_spine_unified` (deg-9, 15 rounds), then `prove_spine_shift` (deg-2, 15 rounds), producing 4 final witness claims: `state(r')`, `state(r'')`, `s_in(r'')`, `s_out(r'')`.
  3. Three `prove_batch_eval` invocations (one per committed column): `state` collapses 2 claims to one `(r_state, v_state)`; `s_in` and `s_out` each carry a single claim through batch-eval (degenerate but uniform).
  4. New `SpineProofKillShot` shape: `{ kill_shot: SpineKillShotProof, state_batch, sin_batch, sout_batch }`. Three `BatchEvalReduction`s returned alongside the proof — STARK bridge will discharge them via a multi-column FRI commit (deferred to a follow-up).
  5. Legacy `SpineProof` / `prove_spine` / `verify_spine` remain in `spine_sumcheck.rs` so existing tests and the STARK bridge keep compiling. Tests in `spine_killshot.rs` cover honest verify, native discharge of all three reductions, and tamper rejection at every layer (main claims, shift claims, batch-eval finals, claimed hash).

- **Stage 1.5.7 [PARTIAL] — Differential green, perf gate MISSED.**
  - Correctness (LANDED):
    - `noid_gkr/tests/spine_killshot_vs_native.rs`: kill-shot wrap pin matches `hash_tx_body` byte-for-byte; every reduction (`state`, `s_in`, `s_out`) is consistent with native MLE evaluation; prover/verifier reductions agree bit-for-bit; post-proof `inputs` tamper rejected.
    - Cross-check vs. legacy `prove_spine` deliberately **not** asserted bit-equal: kill-shot's transcript is structurally different (15 rounds × deg-9 main + 15 rounds × deg-2 shift vs. legacy's 59 × deg-3 perm chains), so squeezed `r_B` differs even on identical fixtures. Both reductions remain valid against the same underlying state MLE — the agreement is on the polynomial, not on the point. `discharge_reductions_native` covers this.
    - Tamper tests live in `spine_killshot.rs` unit tests: tampered `state_at_r`, `s_in_at_r2`, `state_batch.b_final`, and wrong claimed hash all rejected.
    - Proof bytes: **5.44 KB** (target ≤ 5 KB; ~9% over but flat — the 30 round polys plus three batch-eval finals dominate; the ~280 KB legacy figure is annihilated).
  - Perf gates **NOT** met on current Block128 multiplier:
    - Spine prove: **1.61 s** measured vs. 50 ms gate (~32× over).
    - Spine verify: **64.67 ms** measured vs. 2 ms gate (~32× over).
    - Bytes:       **5.44 KB**  measured vs. 5 KB gate (~9% over).
  - Why the prove gate misses (cost analysis):
    - Kill-shot main: one 15-var sumcheck × 10 eval points × deg-9 round poly with 23 helper tables. Inner-loop per cell does ≈30 Block128 muls (pow7 + lane sum-product). Total ≈ 2^16 cells × 10 evals × 30 muls ≈ **20 M muls**, vs. legacy's 59 × 2^9 × 4 × 10 ≈ **1.2 M muls** spread across 59 sumchecks. Algorithmically kill-shot is ~16× heavier on field arithmetic than legacy.
    - Legacy claws back what kill-shot saves on channel work: 2 124 round-poly absorbs into Poseidon2bChannel (~700 µs each → ~1.5 s) vs. kill-shot's ~195 absorbs (~140 ms). Both flows therefore land at ~1.6 s but for **different** reasons: legacy is transcript-bound, kill-shot is field-arithmetic-bound.
    - The original 30× projection assumed the unified sumcheck would inherit legacy's per-cell cost (deg-3 with 4 evals). It doesn't — collapsing the slot axis costs degree at the round poly. To hit the published gate we need either (a) a hardware-accelerated Block128 multiplier (PCLMUL/CLMUL on x86, NEON pmull on ARM), or (b) a per-evaluation-point dynamic-programming reformulation of `compute_round_polynomial` that amortises the lane sum across the 10 evaluation points.
  - Action items moved to a new **Phase 1 Step 1.5.8 — Kill-Shot perf**:
    1. Profile the prover with `cargo flamegraph --bench stark_report -- phase1k` to confirm the field-arithmetic hypothesis.
    2. Add a PCLMUL-backed Block128 mul behind `cfg(target_feature = "pclmulqdq")`, fall back to current path otherwise.
    3. Re-evaluate the round-poly inner loop: precompute `(s_in)^7` via repeated squaring across the t-axis using Lagrange combinators instead of a full pow7 per evaluation point.
    4. Re-bench. Re-publish gate values that reflect actual multiplier performance, not aspirational ones.
  - `bench_prover/benches/stark_report.rs`: new `[phase1k]` row prints kill-shot prove/verify/bytes alongside the gate values (≤ 50 ms / ≤ 2 ms / ≤ 5 KB). Targets are reported, not enforced — CI gating happens externally by grepping the printed line. Section header now reads "Stage 1.5.7 gates (current multiplier; see 1.5.8)".

- **Stage 1.5.8.A [LANDED] — flat-basis prover hot path.**
  - **Premise correction.** Action item (2) from 1.5.7 was already half-realised: `noid_core/src/hardware.rs` ships a complete `Flat<Block128>` isomorphism (`tower_to_flat_u128` / `flat_to_tower_u128`) plus a native PCLMULQDQ-backed `clmul_gcm`, and `PackedBlock128` exposes `flat_mul` / `flat_square` / `flat_scalar_mul`. The kill-shot prover was leaving this entire infrastructure on the floor: every multiplication inside `compute_round_polynomial` and `compute_shift_round_polynomial` went through tower-basis Karatsuba (~80–100 ns/mul) instead of CLMUL (~8–12 ns/mul).
  - **Scope (strictly local).** Hot path of the kill-shot prover only. No change to `Block128::mul` / `Block64::mul` / `Block128::square`. Verifier (`verify_spine_unified`, `verify_spine_shift`) untouched — it is not in the hot path and its tower-basis arithmetic is fine. Public-schedule constructors (`build_u_table`, `build_sigma_table`, `build_rc_table`, `build_mds_lane_table`) untouched.
  - **Implementation.**
    1. `noid_core/src/packed/pow7.rs`: new `pow7_flat_block128(x: u128) -> u128` — same Frobenius decomposition (`s2 = sq, s3 = s2·x, s4 = sq(s2), s7 = s4·s3`) but every step is `square_flat_u128` / `clmul_gcm`. Parity test against `pow7_block128 ∘ basis change` over 1000 random inputs.
    2. `noid_gkr/src/spine_unified.rs`: new `UnifiedFlatTables` struct mirroring `UnifiedTables` but holding `Vec<u128>` (flat). `from_tower` performs a single 128×128 GF(2) matrix-vector multiply per element across all 23 tables (~32K cells each, shrinking by half each round). `fold_flat` runs the linear interpolation step `evals[j] ^= clmul_gcm(r_flat, evals[j] ^ evals[j+half])` directly. `final_claims_tower` lifts the twelve final claims back to tower for channel absorption.
    3. New `compute_round_polynomial_flat`: for each `i ∈ [0, half)` and each evaluation point `k ∈ [0, 9]`, builds `u, sg, rc, si, so, st_dec, st_main, mds_j, sgl_j, sol_j, stl_j` in flat basis via XOR + `clmul_gcm(t_flat[k], delta)`, computes `Q1 / Q1' / Q2` with `pow7_flat_block128` + `clmul_gcm`, and accumulates `evals[k] ^= clmul_gcm(u, q)`. Final pass converts the 10 evaluations back to tower and feeds `RoundPolynomial::from_evals` (which interpolates over tower-basis points `0,1,…,9`).
    4. `compute_shift_round_polynomial_flat`: same shape for the deg-2 shift gadget on six 32K vectors (`s_in / s_out / state` plus the three weight tables).
    5. `prove_spine_unified` / `prove_spine_shift` rewired: tower → flat lift once, all 15 rounds in flat, lift back at the boundary for the four absorbs (round-poly coeffs every round + final claims at the end).
    6. Old `compute_round_polynomial` / `UnifiedTables::fold` / `final_claims` / `compute_shift_round_polynomial` kept under `#[allow(dead_code)]` as parity oracles for the new tests.
  - **Parity tests (in-file, `#[cfg(test)]`).**
    - `flat_round_poly_matches_tower_round_poly`: 15 sumcheck rounds; round-poly coefficients and final witness claims are bit-equal to the tower reference at every round.
    - `flat_shift_round_poly_matches_tower`: same for the shift gadget round polynomial.
    - `pow7_flat_matches_pow7_tower_via_basis_change`: 1000 random pow7 evaluations.
    - `spine_killshot_vs_native` continues to pass — flat path is transcript-equivalent (the channel sees identical bytes).
  - **Measured impact (bench_prover `[phase1k]`).**
    - Spine prove: **1.61 s → 194.59 ms** (8.3× ↓).
    - Spine verify: **64.67 ms → 66.31 ms** (unchanged — verifier was deliberately not touched; verify is dominated by `evaluate_slice` over six public schedules, ~200K muls).
    - Spine bytes: **5.44 KB → 5.44 KB** (basis change doesn't move bytes).
    - End-to-end Phase 1 per-tx: prove **2.81 s** (was ~3.7 s, dominated by the unchanged STARK stage); SpineGKR delta over STARK-only is now `2.72 s − 1.65 s = 1.07 s` of which ~870 ms is the 59-perm legacy adapter still on-path.
  - **Gate status after 1.5.8.A.**
    - prove **194.59 ms** vs. 50 ms gate — ~3.9× over. Remaining headroom: 1.5.8.B (Lagrange amortisation of `(s_in)^7` across the 10 evaluation points, expected ~2.5×) and 1.5.8.C (PackedBlock128 lane-batched cell loop, expected ~2× on AVX2 / ~4× on AVX-512). Combined headroom 5–10× — sufficient.
    - verify **66.31 ms** vs. 2 ms gate — verifier optimisation moves to a new follow-up 1.5.8.E (target: cache the public-schedule `evaluate_slice` precomputations across the six inner products, replacing six independent traversals with one shared eq-table fold).

- **Stage 1.5.8.B [LANDED] — Monomial-form prover (full `t`-axis convolution per cell).**
  - **Premise.** In the per-evaluation-point flat-basis prover (1.5.8.A), every cell is walked 10 times — once for each `t ∈ {0,…,9}`. But every witness factor is **affine** in `t`: `x(t) = x0 + t · dx`. So the round-poly integrand `F_i(t) = u(t) · (Q1(t) + β · Q1'(t) + γ · Q2(t))` is a polynomial of degree ≤ 9 in `t` with 10 monomial coefficients. Build those coefficients **once per cell** and accumulate them XOR-wise into a global degree-9 vector — no more 10× re-walk, no more Lagrange interpolation at the end.
  - **Implementation.** `noid_gkr/src/spine_unified.rs`:
    - `poly_mul_t<NA,NB,NR>(a, b)` — full polynomial-in-`t` convolution via `clmul_gcm` on coefficients.
    - `pow7_poly_t(a, b) -> [u128; 8]` — eight monomial coefficients of `(a + t·b)^7` via Lucas-theorem argument (`binomial(7, j) ≡ 1 (mod 2)` for all `j ∈ [0,7]`, so `(a + tb)^7 = Σ_j a^j b^{7-j} t^j`).
    - `compute_round_polynomial_flat` — per cell builds `Q1` (deg-8), `Q1'` (deg-2), `Q2` (deg-3, via 32 lanes × deg-3 lane contributions), combines `q = Q1 + β·Q1' + γ·Q2` (deg-8), multiplies by `u(t)` (deg-1) → 10-coeff `F_i(t)`. Aggregates into `acc[0..10]` via XOR. Final lift via `flat_to_tower_u128` × 10 + `RoundPolynomial::from_coeffs`.
    - Old per-eval prover preserved as `compute_round_polynomial_flat_per_eval` under `#[allow(dead_code)]` — parity oracle.
  - **Parity tests.** `pow7_poly_t_matches_naive` (1000 random `(a, b)` × 10 `t` points) — confirms the deg-7 build. `flat_round_poly_matches_tower_round_poly` extended to a 3-way diff: tower ↔ monomial-form flat ↔ per-eval flat. `spine_killshot_vs_native` stays green: transcript identical.
  - **Cost.** Per-cell budget drops from ~850 muls (1.5.8.A) → ~520 muls (1.5.8.B), plus much smaller working set (no 10× re-walk of `mds0/sgl0/sol0/stl0` arrays).
  - **Measured impact.** Spine prove **194.59 → 146.26 ms** (≈ 1.33× — under the projected 1.7×; suggests we are now memory-bound rather than ALU-bound).

- **Stage 1.5.8.C [REVERTED] — `PackedBlock128`-wrapped cell loop.**
  - **What was tried.** Pack `PACKED_LANES` (2 on AVX2, 4 on AVX-512) consecutive cells into `PackedBlock128`s per witness column, run the entire monomial-form cell loop with `PackedBlock128::flat_mul` / `flat_square` / `flat_scalar_mul`, collapse via `reduce_xor` at the round end.
  - **Why it was reverted.** `PackedBlock128::flat_mul` is implemented as a **scalar `for`-loop over lanes** calling `clmul_gcm` per lane (see `noid_core/src/packed/arith.rs:98`). There is no actual lane-parallel CLMUL — the underlying instruction is the scalar `pclmulqdq` (128-bit). On AMD Zen3 (EPYC 7B13) with `PACKED_LANES = 2`, this expands to two sequential `pclmulqdq`s plus per-lane Karatsuba reduction — bit-identical work to the scalar 1.5.8.B path, just routed through extra struct unpack/repack noise.
  - **Measured.** Spine prove **146 → 150 ms** (delta = 2.4%, within run-to-run noise). Code complexity (~250 LOC, two parallel implementations, dispatcher with `PACKED_LANES` predicate) for zero measurable win. Reverted in this iteration; only `compute_round_polynomial_flat` (monomial-form scalar) and `compute_round_polynomial_flat_per_eval` (parity oracle) remain.
  - **Lesson.** True lane parallelism in this codebase requires the `vpclmulqdq` extension (256-bit-lane CLMUL on Zen3+, 512-bit on Sapphire Rapids / Zen4). That is a hardware-arithmetic-layer change, not a per-protocol layer change — moves to **Stage 1.5.8.F**.

- **Stage 1.5.8.D [PENDING] — Re-bench + gate ratification.** Update `bench_prover/benches/stark_report.rs` section header to drop the "current multiplier" caveat once 1.5.8.E + 1.5.8.F land. Final gates: prove ≤ 50 ms, verify ≤ 2 ms, bytes ≤ 5 KB.

- **Stage 1.5.8.E [LANDED] — Cache public-schedule tables.**
  - **Status quo (post 1.5.8.B).** Spine **verify = 66 ms** vs. 2 ms gate. The original ROADMAP claimed "shared `eq_ind` traversal" would give ~30× speedup. **That was wrong arithmetic.** A round-by-round inspection of `evaluate_slice` shows it folds `2^15 → 1` in `2^15 + 2^14 + … + 1 ≈ 32K` multiplies — *not* 65K. A one-shot eq-table build + dot product also costs `2 × 32K` muls. There is **no asymptotic win** in restructuring the eval call shape. Confirmed empirically: a "shared eq" rewrite measured 66 → 70 ms (within run-to-run noise).
  - **Real bottleneck (identified after the failed shared-eq attempt).** The verifier rebuilds the *constants* of the protocol on every call:
    - `build_sigma_table()` + `permute_by_dec(...)` → `σ_dec_full` (length `2^15`, fully populated, two passes).
    - `build_rc_table()` + `permute_by_dec(...)` → `RC_dec_full`.
    - `build_mds_lane_table(j)` × 32 lanes — each writes 32K cells with `mds_coeff` lookups.
    - `project_lane(σ_dec_full, j)` × 32 lanes — each is another 32K-cell write.
    These tables depend **only** on the fixed unified-spine topology (`pack_index` layout, `dec_round_index` permutation, `ROUND_CONSTANTS`, `MDS_FULL`/`MDS_PARTIAL`). Same value every verify call.
  - **Plan.** Wrap each table in a `OnceLock<…>` static. First call pays the build; all subsequent calls return a `&'static [Block128]` reference and skip straight into `evaluate_slice`. Bench harness (in `bench_prover/benches/stark_report.rs::time`) does warmup iterations so steady-state cost dominates the reported median.
  - **Implementation.** `noid_gkr/src/spine_unified.rs`:
    - `sigma_dec_full_cached() -> &'static [Block128]` — cached `permute_by_dec(build_sigma_table())`.
    - `rc_dec_full_cached() -> &'static [Block128]` — cached `permute_by_dec(build_rc_table())`.
    - `mds_lane_dec_full_cached() -> &'static [Vec<Block128>; STATE_SIZE]` — 32 cached MDS-per-lane tables.
    - `sigma_lane_dec_full_cached() -> &'static [Vec<Block128>; STATE_SIZE]` — 32 cached σ-per-lane tables, derived from the cached σ_dec.
  - **Parity test.** `cached_schedules_match_freshly_built` — for all four caches, asserts bit-equality with a freshly constructed copy. Catches any future refactor that breaks idempotency of the build functions.
  - **Soundness.** `spine_killshot_vs_native` continues to assert verifier accepts transcript bit-for-bit; no protocol surface changes.
  - **Memory.** Caches retain `(2^15) × 16 B × (1 + 1 + 32 + 32) = ~33 MB` of static memory. Acceptable for a verifier (tx validators are batch-verifying many proofs; one-time amortised allocation is fine).
  - **Expected impact.** Steady-state verify saves roughly the build cost: ≈ 14 ms of memory writes per verify call. Projected verify **66 ms → ~50 ms** (≈ 1.3×). Still ~25× over the 2 ms gate. The residual is the 67 `evaluate_slice` calls themselves (`67 × 32K` ≈ 2.1M GF(2^128) multiplies), which is the floor that cannot be moved without either VPCLMULQDQ (1.5.8.F) or sparse-aware evaluation (1.5.8.E.bis below).

- **Stage 1.5.8.F [PENDING] — True `vpclmulqdq` lane-parallel CLMUL.**
  - **Premise.** AMD Zen3+ and Intel Ice Lake+ ship the `vpclmulqdq` instruction extension, which performs **two** independent 64×64→128 carry-less multiplies in a single 256-bit `ymm` register (AVX2 + VPCLMULQDQ), and **four** in a single 512-bit `zmm` register on Intel Sapphire Rapids / Zen 4 (AVX-512 + VPCLMULQDQ-512). The kill-shot prover at `compute_round_polynomial_flat` is bottlenecked by `clmul_gcm` calls (~17M total over the 15 rounds × 32K cells × ~520 muls/cell = roughly the kind of work that should fit in ~70 ms theoretically; we observe 146 ms, so a 2× lane-parallel CLMUL closes most of the gap).
  - **Hardware.** Our reference benching CPU is **AMD EPYC 7B13** (Zen 3) — `pclmulqdq`, `avx2`, `vpclmulqdq` all present (verified via `/proc/cpuinfo`); no `avx512f`. So the reachable lane parallelism is **2-way 256-bit `vpclmulqdq`**, not 4-way 512-bit. Sapphire Rapids / Zen 4 deployments would automatically pick up the 4-way path under the same feature gate.
  - **Implementation outline (~1 day of careful work).**
    1. **New module `noid_core/src/hardware/clmul_pair.rs`.** Add a function with shape:
       ```rust
       #[cfg(all(target_arch = "x86_64",
                 target_feature = "avx2",
                 target_feature = "vpclmulqdq"))]
       #[inline(always)]
       pub unsafe fn clmul_gcm_pair(a: (u128, u128), b: (u128, u128)) -> (u128, u128);
       ```
       Internally pack `(a0, a1)` into a `__m256i` (two 128-bit lanes), same for `(b0, b1)`, then issue **three** 256-bit `_mm256_clmulepi64_epi128` instructions (`0x00`, `0x11`, `_mm256_xor_si256`-Karatsuba mid term), and one shared 256-bit reduction stage that operates on both lanes simultaneously. Reduction stays the standard GCM polynomial reduction `x^128 + x^7 + x^2 + x + 1`, but the shifts/XORs become `_mm256_slli_epi64` / `_mm256_xor_si256` — the same ops, twice the throughput.
    2. **Fallback.** `#[cfg(not(...))]` path delegates to `(clmul_gcm(a.0, b.0), clmul_gcm(a.1, b.1))` (two scalar calls). Maintains build on machines without VPCLMULQDQ.
    3. **Wire into `PackedBlock128`.** Change `PackedBlock128::flat_mul` (currently `noid_core/src/packed/arith.rs:98` — scalar lane-loop) to dispatch to `clmul_gcm_pair` when `PACKED_LANES == 2` and `vpclmulqdq` is available. AVX-512 path (`PACKED_LANES == 4`) lifts to `clmul_gcm_quad` with the same recipe, three 512-bit `_mm512_clmulepi64_epi128` Karatsuba instructions.
    4. **Re-introduce 1.5.8.C.** Once `flat_mul` is true SIMD, re-add the packed cell loop (we still have the design and parity tests in git history). The packed implementation itself is correct — it's the underlying op that was scalar-equivalent. Restoring will likely take ~2 hours total, almost entirely diff-revert + re-running parity tests.
    5. **Parity tests.**
       - `clmul_gcm_pair_matches_scalar` (random 10K samples).
       - `flat_round_poly_matches_tower_round_poly` exercised through both packed and scalar paths.
       - Existing `flat_roundtrip_matches_tower_mul` in `noid_core/src/packed/arith.rs` automatically picks up the new SIMD path.
  - **Risk.** `vpclmulqdq` Karatsuba reduction is fiddly: register pressure on AMD's 16 ymm pool, plus subtle differences between the AVX2 and AVX-512 reductions. Mitigation: ship behind a `#[cfg]` gate, keep the scalar fallback, run both paths in CI on every commit (parity test). Cross-checkable against `aes-gcm` crate's open-source `vpclmulqdq` reduction (look at `aes-gcm-siv` or `polyval` crate as a reference implementation; do **not** copy code — read for reduction technique only).
  - **Expected impact.**
    - On Zen 3 / EPYC 7B13 (AVX2 + VPCLMULQDQ-256, 2-way): spine prove **146 ms → ~80 ms** (≈ 1.8×). Approaches but does not fully close the 50 ms gate.
    - On Sapphire Rapids / Zen 4 (AVX-512 + VPCLMULQDQ-512, 4-way): spine prove **146 ms → ~40 ms** (≈ 3.5×). Meets the 50 ms gate with margin.
  - **Decision point after 1.5.8.E + 1.5.8.F.** If we are still > 50 ms on Zen 3, options are:
    - Accept reality and re-set the gate as a per-class number: "≤ 50 ms on AVX-512+VPCLMULQDQ; ≤ 100 ms on AVX2+VPCLMULQDQ" — explicit hardware tiering matches what production validators will look like.
    - Pursue 1.5.8.G (memory-layout SoA on the hot tables — ~12 MB working set currently exceeds Zen 3's 32 MB L3 minus other live data; restructure into one interleaved buffer for cache locality). Estimated 1.2–1.5×.

Exit: `cargo build --workspace` and `cargo test --workspace` green; `bench_prover` shows spine-layer numbers above; `noid_stark` and AuthGKR/MerkleGKR untouched on the surface (legacy `prove_single` still functional under the `D=2` wrapper); ROADMAP2 / `noid_gkr/SPEC.md` / `noid_gkr/AUDIT.md` updated with the new sumcheck recipe and attack vectors (soundness of degree-7 with Frobenius linearity, FS chaining proof).

Follow-up PRs (out of scope for this step but enabled by it): port AuthGKR (Step 1) and MerkleGKR (Step 2) to the same degree-7/degree-1 pattern, dropping the residual `product_sumcheck` callers and finally deleting `noid_gkr/src/product_sumcheck.rs` and `mle_layout::PermColumn::{X2,X3,X4}`.

##### Step 2 — MerkleGKR [OPEN]

Scope: evacuate the 4-corner state openings (`fri_state_open`) and the root-squeeze combiner (`fri_state_combiner` + `_composite`) into GKR, reusing Step 1's orchestration pattern.

Preconditions before coding:
- **Corner-set lock.** Before writing any `noid_gkr/src/merkle_circuit.rs` code, derive the exact corner set (count, shape, per-corner payload, mint-branch semantics) from `airs/fri_state_open.rs` and post a corner-contract addendum under this section of ROADMAP2. Lock the contract before implementation.
- **`log_slots` genericity.** `MerkleCircuit` is parameterised by `log_slots` read from the block header at build time — no hardcoded constant. Enforces `SPECIFICATION.md §15.3.9`. Tests at `log_slots ∈ {4, 24}`.

Structural plan (high-level — refined after the corner lock):
1. `noid_gkr::merkle_circuit::MerkleCircuit` parameterised by `log_slots`. Slot = one Poseidon2b compression per Merkle level × per corner. IV = `capacity_iv(TAG_COMPRESS)`, leaf IV = `capacity_iv(TAG_LEAF)`.
2. `noid_gkr::merkle_oracle::evaluate_merkle`. Witness: per-corner `(leaf_triple, slot_index_bits, sibling_hashes[level], is_mint)`. Native root recomputation differential vs. `noid_chain::fri_state`.
3. `noid_gkr::merkle_sumcheck::{prove_merkle, verify_merkle}`. Per-slot `perm_sumcheck`; plus one dedicated degree-2 `product_sumcheck` round that discharges the char-2 lane-update identity `new_f_L(r) + prev_f_L(r) + Σ eq(r, slot_bits) · delta_L = 0` (replaces `fri_state_combiner`). `prev_f_L(r)` / `new_f_L(r)` absorbed as verifier-known scalars.
4. Equality-bound boundary: `computed_prev_root == prev_state_root`, `computed_new_root == new_state_root`. `is_mint ⇒ pre_triple = 0` enforced inside GKR by pinning the leaf MLE value on mint corners.
5. STARK bridge: `MerkleProof` bytes appended to `extra_transcript` after `AuthProof` bytes. New `PublicColumn`s pin the two computed roots to `prev_state_root` / `new_state_root`.
6. AIR slimming + legacy deletion (atomic commit): `airs/fri_state_open.rs`, `airs/fri_state_combiner.rs`, `airs/fri_state_combiner_composite.rs`, `airs/poseidon_perm.rs`, `airs/poseidon_sbox.rs`, `airs/poseidon_mds.rs`, `composition/tx_validity_composite.rs`, `composition/tx_validity_leaf.rs`, `composition/row_window.rs`, `composition/spine_adapter.rs` (verify each orphan first). Keep: `composition/tx_validity_with_spine.rs` (drastically trimmed), `composition/placement.rs`, minimised `composition/registry.rs`.
7. Tests: `tests/merkle_differential_vs_native.rs` (both `log_slots`), `tests/merkle_sumcheck.rs` (honest + ≥ 6 mutations), `tests/merkle_transcript_vectors.rs`. Update `stage_5_7_roundtrip.rs` and `bench_prover` harness.
8. Docs: §8 of `noid_gkr/SPEC.md`, AUDIT additions, ROADMAP `§I.4` / `§I.9` / coverage matrix refresh.
9. **Exit (Phase 1 exit).** `n_cols ≤ 80`, prover < 300 ms, verify < 30 ms, proof ≈ 100 KB on `bench_prover`. Every spec predicate (`§4.1`, `§4.3`–`§4.5`) still enforced, now in GKR instead of in-AIR. Full test suite green. `reports/perf_tip.md` records the headline numbers; the CI regression gate itself is deferred to Stage I.

##### Invariants preserved by Phase 1

- Single `Poseidon2bChannel` across STARK + Spine + Auth + Merkle (one Fiat-Shamir transcript).
- Each GKR sub-proof equality-bound at its boundary (no "trust me" handoffs).
- `SpendSecret` is witness-only in every sub-proof; never pinned, never recoverable from the public surface.
- `SPECIFICATION.md §0.3` (zero canonicalisation) unchanged: GKR uses the same `H_LEAF(0,0,0)` and `ZERO_SUBTREE_ROOT[k]` constants via `noid_poseidon2b::native`.
- One STARK proof object — GKR bytes absorbed via the existing `extra_transcript` hook ordering (`AUDIT.md §5`).

### Phase 2: Basefold PCS [OPEN]
*Detailed spec: `phase2.md`*

Replace FRI (Merkle-tree based, query-heavy) with Basefold PCS (Sumcheck-based) over GF(2^128).
- **Goal:** Radically compress the proof size and verification time. Basefold generates logarithmic proofs without Merkle paths.
- **Key modules:** `noid_basefold` (new), `noid_stark`, `noid_core`.
- **Exit:** Proof size 15-30 KB. Verify time 1-2 ms on mobile. Removes `noid_fri` from the primary proving path.

### Phase 3: Succinct Block Folding [OPEN]
*Detailed spec: `phase3.md`*

Upgrade `noid_ivc` to use Deferred Folding over Basefold commitments. Instead of opening proofs per-transaction, linearly combine commitments (`C_block = C_1 + α*C_2...`) and generate one Basefold opening for the whole block.
- **Goal:** Constant-size BlockProof (15-30 KB) regardless of the number of transactions in the block. Unlocks native recursion (Stage J).
- **Key modules:** `noid_ivc`, `noid_basefold`.
- **Exit:** 1000 TX block proof is 30 KB. Miner aggregation takes ~1-1.5s on 8-core CPU.

### Stage F — DA witness-root schema [OPEN]

- F.1. Specify the packed DA columns per-tx (see §I.7): bit-domain set + byte-domain set.
- F.2. Implement `per_tx_witness_commit` in `noid_binius` (builder + verifier).
- F.3. Implement `block_witness_root` = Poseidon2b Merkle over per-tx commits.
- F.4. Round-trip test at `2^10` tx: commit → open random tx/column → verify.
- F.5. Hook to `BlockHeader.witness_root` in `noid_chain`.

Exit: `witness_root` reproducible, openable, and bound to the same tx_body_hash set that the proofs cover.

### Stage H — Parallel proving harness (§15) [OPEN]

- H.1. Define a disjointness predicate: `input_slots(tx_a) ∩ (input_slots(tx_b) ∪ output_slots(tx_b)) == ∅`.
- H.2. Harness `prove_parallel(batch: &[TxBody]) -> Vec<TxProof>` in `bench_prover` that spawns N threads against a shared read-only prev_state snapshot.
- H.3. Wall-clock test: 8 disjoint txs in parallel vs. sequential → ≥ 4× speedup on 8-core.
- H.4. Document that parallel proving is prover-side only; serialized apply in chain is preserved by block_tx_root ordering.

Exit: demonstrable prover-side parallelism over disjoint slot sets.

### Stage J — Native Recursive Chain-of-Proofs [OPEN]

**Goal.** `BlockProof_{n+1}` verifies `BlockProof_n` inside its own circuit. Because Phase 2/3 use Basefold (Sumcheck over GF(2^128)) and the STARK is also over GF(2^128), the verifier circuit can be encoded **natively** without emulating foreign field arithmetic.

- **J.1 — Block-proof public-input canonicalization.** Freeze `BlockPublicInputs` tuple.
- **J.2 — Native recursive verifier circuit (`noid_air::airs::block_proof_verify`).** AIR that verifies the Sumcheck rounds and final Basefold claim of `BlockProof_{n-1}`.
- **J.3 — Genesis base case.** Distinguished `GenesisBlockProof` with protocol constant.
- **J.4 — Chain binding.** Enforce root continuity and proof digest matching.
- **J.5 — `LightClientHeader` = (`block_header_n`, `BlockProof_n`).** One-shot `verify_light_client(tip) → bool`.
- **J.6 — Round-trip test: synthetic 100-block chain.**
- **J.7 — Size & time targets.** `BlockProof_n` size constant. `verify_light_client(tip)` ≤ 50 ms. Prover overhead ≤ 2×.

Exit: Light client verifies entire chain history via a single 30 KB proof in milliseconds.

### Stage I — Performance regression gate [OPEN]

Goal: lock in the wins from Phases 1-3.

Budgets (post-Phase 2/3 targets):
- **Proof size (single tx)**: ≤ 30 KB.
- **Prove time (single tx)**: ≤ 300 ms.
- **Verify time (single tx)**: ≤ 2 ms.
- **Block Proof size (1000 tx)**: ≤ 30 KB.

Stage I deliverables:
- I.1. `bench_prover` exports numbers to `reports/perf_tip.md`.
- I.2. CI regression gate: a PR that regresses any number by > 5% is blocked.
- I.3. Historical anchors linked.

Exit: Gains locked; cannot silently erode.

### Stage K — Review contract & closure [OPEN]

- K.1. Update `ARCHITECTURE.md` and `SPECIFICATION.md` to match Skinny STARK + Basefold + Succinct Folding.
- K.2. One-page `predicate.md` listing the nine predicates with file:line citations.
- K.3. External review pass.

Exit: engine is complete against the `SPECIFICATION.md` obligations.

---

## Part IV. Non-goals (explicitly, do not drift into)

- No chain-level policy: mempool admission, fee market, PoW puzzle, difficulty adjust, reorg, finality, gossip, wallet UX, slot-hint service.
- No block-assembler logic beyond a trivial test driver.
- No new cryptographic commitment on outputs: `tx_body_hash` is sufficient.
- No new hash primitive.

---

## Part V. Coverage matrix — `SPECIFICATION.md` vs engine (Current State)

| Design § | Engine obligation | Current Status | Target stage |
|---|---|---|---|
| §0 state model | 3-column FRI, leaf-hash zero, zero-subtree constant | done | — |
| §2 `Address = H_ADDR(secret)` | in-AIR `haddr` | done | Phase 1 (migrates to GKR) |
| §3 tx body + body hash | GKR 59-perm spine | done | — |
| §4 ownership (haddr + hauth) | in-AIR `haddr`/`hauth` | done | Phase 1 (migrates to GKR) |
| §4 state correctness (4-corner) | in-AIR `fri_state_open` | done | Phase 1 (migrates to GKR) |
| §5 public inputs | `PublicInputs` | partial | Baseline |
| §12 coinbase | parameterized `balance_gate` | missing | Baseline |
| §15 DA/packed witness | `witness_root` builder | partial | F |
| §15.1 `is_mint ⇒ pre=0` | in-circuit | done | — |
| `DESIGN_NOTES.md §1.3` block = aggregated proof checkpoint | IVC linear folding | primitive done | Phase 3 (Deferred Folding) |
| `DESIGN_NOTES.md §1.4` recursive chain-of-proofs | Native Basefold verification in STARK | missing | J |
| `DESIGN_NOTES.md §1.5` full-chain verification O(1) | `verify_light_client(tip)` | missing | J |
| Proof Size & Verify Time | Currently FRI based | FRI implemented | Phase 2 (Basefold) |