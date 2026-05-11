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