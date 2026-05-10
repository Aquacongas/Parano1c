# PARANOID — ROADMAP2

PARANOID — Transparent Slot-Based UTXO Validity Engine
A STARK-Based Validity Engine for Transparent UTXO Chains

PARANOID is a proof-native STARK-based validity engine. Computation,
state, and transitions are unified in a single binary-field model.
The system proves correctness of state transitions without trusted
setup, without transaction re-execution, and without signature-based
authorization semantics: each transaction ships with a deterministic
validity proof derived directly from the state transition it
performs.

PARANOID combines three architectural properties rarely unified in
existing blockchain systems:

- transparent slot-based state execution,
- proof-native validity semantics over a binary-field STARK model,
- hardware-accelerated GF(2^128) arithmetic.

The execution model is built around a reusable slot-based state
architecture. State slots are recycled after spend; the ledger
expands automatically (`log_slots += 1`) when sustained occupancy
demands more capacity. This allows deterministic state growth
without global account mutation or permanent address-space
accumulation.

A defining feature is the separation of mathematical semantics from
hardware execution. The system operates natively over a GF(2^128)
binary tower field within the STARK proving model, while selectively
projecting arithmetic into a hardware-optimized polynomial basis
for CLMUL-accelerated multiplication and squaring, before re-lifting
results back into the canonical proof representation.

The proving system uses Poseidon2b inside the AIR, a native
GF(2^128) binary tower field for execution semantics, and
Poseidon2b-Merkle FRI commitments. The 59-permutation Poseidon2b
spine that compresses the transaction body into `tx_body_hash` lives
in a dedicated GKR sub-protocol (`noid_gkr`) rather than inside the
STARK trace.

The result is a transparent, post-quantum validity engine intended
for integration into full blockchain protocols.

---

**Engine track. The STARK validity engine.**

`SPECIFICATION.md` describes the blockchain — state model,
transactions, consensus, blocks, coinbase, activation bookkeeping,
`log_slots` expansion — and `DESIGN_NOTES.md` carries the
proof-native ledger philosophy. This ROADMAP2 scopes down to the
**engine obligations** only: everything the STARK validity engine
must provide so that, when a chain/node/wallet layer is later built
on top, the design of `SPECIFICATION.md` can be realized without
patching the engine.

**Out of scope for this roadmap** (explicitly, so we stop drifting):
- P2P networking, node daemon, block propagation, gossip.
- Mempool admission, fee market, replay protection beyond tx-level.
- Block-assembly policy (conflict tie-break, coinbase construction
  policy, reorg handling, finality windows).
- Wallet UX, key management, slot-hinting services, wallet-side retries.
- Consensus (PoW puzzle, difficulty retargeting, chain selection).

**In scope for this roadmap** (what the engine must deliver, end to end):
- Every in-circuit predicate required to validate one transaction
  against a prev-state commitment and a new-state commitment.
- Every public input / public column the chain layer will need to
  compose tx proofs into a block proof.
- Every commitment primitive: state commitment, body commitment,
  DA witness commitment, proof-level FRI.
- Aggregation over a block of N txs via IVC folding.
- Recursive chain-of-proofs: `Proof_{n+1}` verifies `Proof_n`.
- Parallel-proving harness for disjoint-slot-set txs.
- A production-shape performance baseline taken on the full
  post-E predicate, followed by a dedicated optimization pass
  before any aggregation layer (F/G/H) multiplies costs forward.
- Explicit, testable performance targets (proof size, prove time,
  verify time) enforced by a CI regression gate.

---

## Part I. Engine target architecture

### I.1 Predicate the engine proves, per transaction

Given `(prev_state_root, tx_body, new_state_root)` and a witness,
the engine proves:

1. `tx_body` is well-formed: field ranges valid, input/output
   counts within bounds, `is_coinbase` flag consistent.
2. For each live input `i`: `(value_i, owner_i) == prev_state[slot_index_i]`
   — i.e. the input exists in the pre-state. (`fri_state_open`
   against `prev_state_root`.)
3. For each live input `i`: `owner_i == H_ADDR(secret_i)` and
   `auth_tag_i == H_AUTH(secret_i, tx_body_hash)`.
4. For each live output `j`: `prev_state[slot_index_j] == (0, 0, 0)`
   — the mint target is empty in pre-state. (`is_mint ⇒ pre = 0`,
   via an extra `fri_state_open` on `prev_state_root`.)
5. For each live input `i`: `new_state[slot_index_i] == (0, 0, 0)`
   — input is zeroed in post-state. (`fri_state_open` on `new_state_root`.)
6. For each live output `j`: `new_state[slot_index_j] == (value_j, owner_j)`
   — output is materialized in post-state. (`fri_state_open` on
   `new_state_root`.)
7. Balance: regular tx `Σ inputs.value == Σ outputs.value + fee`;
   coinbase `Σ outputs.value == coinbase_credit`. `range_gate` on
   every u64.
8. Body commitment: `tx_body_hash == Poseidon2bSponge(TAG_TXBODY, is_coinbase ∥ n_in ∥ n_out ∥ inputs ∥ outputs)`,
   produced end-to-end by the GKR spine sub-proof (`noid_gkr`) over
   the 59-permutation Poseidon2b chain. On the STARK side the two
   lanes of `tx_body_hash` are row-pinned via `PublicColumn` through
   `tx_body_merkle_boundary` / `tx_body_spine`; the STARK transcript
   absorbs GKR's boundary MLE so that the pinned cell equals the
   spine's wrap output.
9. Activation bookkeeping: `is_activation[j]`, `is_deactivation[i]`
   boolean public columns (§I.5).

**Architectural invariant — the new-state commitment is attested
in-circuit, not recomputed natively by the chain.** This is what
`SPECIFICATION.md §4` ("resulting root = new_root") means when
read strictly. This requires two `fri_state_open` calls
per slot touched against `new_state_root`, on top of the prev-state
openings in 2 and 4 — roughly doubling state-opening work per tx
vs. a prev-side-only circuit. The alternative ("chain recomputes
natively, engine only proves prev-side") is rejected: it would make
the engine's guarantee weaker than `SPECIFICATION.md §4` promises,
and would force the chain layer into non-trivial cryptographic
responsibility. The engine must be self-contained.

### I.2 What does NOT move through the engine

Out of the predicate, because it is a chain/block concern:
- Aggregating many `is_activation[j]` / `is_deactivation[i]` public
  columns across txs to match the block-header `active_slot_count` delta.
- Enforcing `coinbase_credit == block_reward(height) + Σ fees`.
- Enforcing "coinbase tx is at position 0 and appears at most once".
- Enforcing `log_slots` growth policy (`avg_occupancy > 0.90 ⇒ +1`).

The engine **supplies the public-input channels** (`coinbase_credit`,
`log_slots`, activation columns) so the chain layer can enforce
those rules. The engine does **not** itself apply the rules.

### I.3 Commitments the engine owns

| Commitment | What it commits to | Primitive | Module |
|---|---|---|---|
| `state_root` | `(value, owner_hi, owner_lo)` over `2^log_slots` slots | 3× FRI over GF(2^128), combined by `Poseidon2bSponge(TAG_FRISTATE, log_slots ∥ r_val ∥ r_owner_hi ∥ r_owner_lo)` | `noid_chain::fri_state`, `noid_air::airs::fri_state_combiner_composite` |
| `tx_body_hash` | the tx body (inputs, outputs, flags) | `Poseidon2bSponge(TAG_TXBODY, …)` via the GKR 59-perm spine; STARK exposes the scalar via 2-lane `PublicColumn` pins | `noid_tx::body_hash`, `noid_gkr`, `noid_air::airs::{tx_body_spine, tx_body_merkle_boundary}` |
| GKR spine boundary MLE | Poseidon2b trace of the 59-permutation spine (reduced to a boundary evaluation `v_B` at random point `r_B`) | sumcheck + FRI opening, absorbed into the STARK transcript as `extra_transcript` | `noid_gkr` |
| `witness_root` (DA) | per-block packed witness columns (bit/byte domain) | `PackedCommit` over FRI, Poseidon2b Merkle | `noid_binius` |
| per-tx proof `π` | satisfaction of the predicate in §I.1 | STARK over binary tower + FRI (Poseidon2b Merkle) | `noid_stark` |
| block-level proof `Π` | fold of N tx proofs | IVC linear folding accumulator | `noid_ivc` |
| chain tip proof `Π*` | recursive cover `Π_n verifies Π_{n-1}` | IVC decider replayed in-circuit | `noid_air::airs::block_proof_verify` (Stage J) |

### I.4 Modules, by role

```
noid_core         : GF(2^128) tower arithmetic, packed ops, MLE, sumcheck, AdditiveNTT, transcript.
noid_poseidon2b   : native + AIR-side Poseidon2b (permutation, sponge, domain tags).
noid_fri          : RS-code + Poseidon2b-Merkle + prover/verifier, batched PCS.
noid_binius       : bit/byte packing into Block128, PackedCommit over FRI, DA root.
noid_gkr          : GKR sub-protocol for the 59-permutation tx-body spine; emits a
                    boundary MLE evaluation (`r_B`, `v_B`) absorbed by the STARK transcript.
noid_air          : AIRs (gates, single-purpose AIRs, compositions).
noid_stark        : STARK wrapper — multipoint + ladder batch, vshift, proof object.
noid_ivc          : linear folding accumulator (block-level aggregation).
noid_tx           : TxBody / TxInput / TxOutput / TxBodyHash / PublicInputs, wire, body_hash.
noid_chain        : thin state layer — ChainState, apply_tx, FriState-backed state, genesis, block driver.
bench_prover      : perf harness + reports.
```

`noid_chain` is the only module at the boundary between engine and
"future chain layer". It stays minimal: state container, deterministic
`apply_tx` reducer for local testing, genesis construction, block
driver for tests. No mempool, no PoW, no difficulty, no networking.

### I.5 Activation accounting + `log_slots` versioning

Per `SPECIFICATION.md §15.3`. Engine exposes, as public columns of `tx_validity`:
- `is_activation[j] = (pre_value_j == 0) ∧ (post_value_j ≠ 0)` for each output slot.
- `is_deactivation[i] = (pre_value_i ≠ 0) ∧ (post_value_i == 0)` for each input slot.

Constrained to booleans. Derived from the four `fri_state_open`
claims (§I.1 predicates 2, 4, 5, 6), so no extra witness is required.

`log_slots` is a circuit constant per block, sourced from the block
header at proof time, absorbed into the Fiat-Shamir transcript. AIR
widths (`fri_state_open` bit-decomposition, eq-table size, state
FRI length) are parameterized by it. No hardcoded `LOG_SLOTS=24`.

### I.6 Coinbase (§12)

Per-tx, engine-only view (block-level policy is out of scope):
- `TxBody.is_coinbase: bool`. Absorbed into `tx_body_hash` (prepended
  before `n_in ∥ n_out`).
- When `is_coinbase=1`: `n_inputs=0`, `hauth`/`haddr` constraints
  vacuous (all `InputValid[i]=0`).
- `balance_gate` parameterized:
  `(1 − is_coinbase)·(Σin − Σout − fee) + is_coinbase·(Σout − coinbase_credit) == 0`.
- `coinbase_credit: u64` — new field of `PublicInputs`, zero when
  `is_coinbase=0`, range-checked.
- `fee` is still in `TxBody`; for coinbase `fee == 0` is constrained
  in-circuit.

Whether a block contains the correct coinbase (position, count,
credit matches reward+fees) is a chain concern.

### I.7 DA / witness commitment

`BlockHeader.witness_root` in the design is fed by engine. Per-tx,
the engine emits a packed DA payload containing the data the chain
layer needs to verify tx admissibility without re-running the prover:
- bit-domain columns: `InputValid[i]`, `OutputValid[j]`, `is_coinbase`,
  `is_activation[*]`, `is_deactivation[*]`.
- byte-domain columns: `slot_index` (per input and per output),
  `value`, `fee`.
- Poseidon2b Merkle-hash over `PackedCommit` outputs per column.

Exact schema is fixed at Stage F. No per-tx field in DA that is not
already committed through `tx_body_hash`, to avoid a second
commitment drift problem.

### I.8 Canonical flow — single live output, end to end

```
Stage 0 (wallet)         TxOutput { slot_index_j, value_j, owner_j, valid: true }.
                         Wallet chose slot_index_j using a node hint (non-authoritative).
                         Native allocator (§15.1) re-derives the choice deterministically:
                         free_slots.pop_min() if non-empty, else splitmix64 probe.

Stage 1 (body hash)      Native hash_tx_body absorbs is_coinbase, n_in, n_out,
                         then each input, then each output (including slot_index_j).
                         In-circuit: tx_body_merkle AIR's pins.output_leaf_absorb[j]
                         derived from body.outputs[j] (4 lanes: slot_index,
                         value, owner_hi, owner_lo). Pinned as PublicColumn.
                         Final wrap squeeze → tx_body_hash pinned as PublicColumn.

Stage 2 (balance)        balance_gate, parameterized by is_coinbase.
                         range_gate on every u64.

Stage 3 (auth)           Per input i: haddr_block[i], hauth_block[i] (gated by InputValid[i]).

Stage 4 (state)          Per input i:   fri_state_open(prev, slot_i) == (v_i, oh_i, ol_i)
                                         fri_state_open(new,  slot_i) == (0,    0,    0)
                         Per output j:  fri_state_open(prev, slot_j) == (0,    0,    0)
                                         fri_state_open(new,  slot_j) == (v_j, oh_j, ol_j)
                         is_activation[j], is_deactivation[i] derived booleans.
                         fri_state_combiner recomputes prev_state_root and new_state_root.

Stage 5 (public)         PublicInputs = (prev_state_root, new_state_root, tx_body_hash,
                                         fee, coinbase_credit, log_slots,
                                         is_activation[*], is_deactivation[*]).
```

### I.9 AIR inventory (current)

Implemented and gated by tests:
- Gates: `bool`, `mul`, `linear`, `selector`, `row_selector`,
  `eq_ladder`, `const_column`.
- Single-purpose: `balance_gate`,
  `range_gate`, `bit_adder`, `carry_ripple`, `haddr`, `hauth`,
  `poseidon_perm`, `poseidon_sbox`, `poseidon_mds`, `linear_combination`,
  `tx_body_spine`, `tx_body_merkle/*`, `tx_body_merkle_boundary`
  (thin two-lane `tx_body_hash` pin under the GKR-spine path),
  `fri_state_open`
  (input-side at `N=MAX_INPUTS` plus output-side at `N=MAX_OUTPUTS`
  via `FriStateOpenLayout`),
  `fri_state_combiner`, `fri_state_combiner_composite`, `tx_validity`.
- Compositions: `bridge`, `placement`, `registry`, `row_window`,
  `t1_owner_tie`, `spine_adapter`, `tx_validity_composite`,
  `tx_validity_hauth`, `tx_validity_with_spine`, `tx_validity_full`,
  `haddr_block`, `hauth_block`, `tx_validity_leaf`
  (four-corner state openings wired; `is_activation` / `is_deactivation`
  public columns emitted).

Note: the 59-permutation Poseidon2b spine that produces `tx_body_hash`
is **no longer** materialised inside any STARK AIR. It lives in
`noid_gkr` as the production — and only — path; the former in-AIR
spine has been retired from the default build surface. The STARK
side carries only the two `tx_body_hash` lanes, row-pinned by
`tx_body_merkle_boundary` / `tx_body_spine` `PublicColumn`s, with
the GKR boundary claim absorbed into the STARK transcript
(`extra_transcript`). See `ARCHITECTURE.md §4.2` and
`noid_gkr/SPEC.md` for the binding contract.

### I.10 Graphical picture

```
                                PUBLIC INPUTS
     ┌────────────────────────────────────────────────────────────┐
     │ prev_state_root  new_state_root  tx_body_hash              │
     │ fee  coinbase_credit  log_slots                            │
     │ is_activation[*]  is_deactivation[*]                       │
     └───────▲─────────▲────────▲─────────▲──────────▲────────────┘
             │         │        │         │          │
     ┌───────┴──┐ ┌────┴─────┐ ┌┴────────┐│ ┌────────┴────────┐
     │ combiner │ │ combiner │ │ merkle  ││ │  derived bools  │
     │  (prev)  │ │  (new)   │ │ body    ││ │  from 4 opens   │
     └───▲──────┘ └────▲─────┘ └▲────────┘│ └─────────────────┘
         │             │        │         │
   ┌─────┴──┐    ┌─────┴──┐     │         │
   │ open   │×M  │ open   │×N   │         │
   │ prev   │    │ new    │     │         │
   └────────┘    └────────┘     │         │
                                │         │
                                │  ┌──────┴──────┐       ┌─────────────┐
                                │  │ balance_gate │←─────│ range_gate  │
                                │  │ (coinbase    │      └─────────────┘
                                │  │  branch)     │
                                │  └──────────────┘
                                │
                                │  ┌──────────────┐  ┌──────────────┐
                                │  │ haddr_block  │  │ hauth_block  │
                                │  │   × M        │  │   × M        │
                                │  └──────────────┘  └──────────────┘
                                │        (bound to tx_body_hash)
                                │
                                │   tx_body_hash pin is fed by
                                │   `noid_gkr` (59-perm spine);
                                │   the STARK transcript absorbs
                                │   the GKR boundary MLE claim.
```

## Part II. Stage plan

### Stage Eopt (Eπ) — Performance baseline & optimization pass [OPEN — runs immediately after E]

**Why here, not at Stage I.** After Stage E, the engine encodes the
**full production predicate** of §I.1 — four-corner state openings,
coinbase mux, activation columns, `log_slots` as circuit constant.
This is the first moment when `bench_prover/benches/stark_report.rs`
reports **production-shaped** numbers (single-tx proof with the real
AIR inventory, not a reduced diagnostic harness). Optimizing earlier
tunes the wrong shape; optimizing later means Stages F/G/H inherit
unoptimized primitives. Do it now.

Stage I stays at its current slot as the **regression gate** and
published budgets. Eπ produces the baseline those budgets are
measured against; Stage I protects the gains.

Out of scope for Eπ: touching §I.1 predicates, commitment shapes,
public-input schemas. This is a pure perf stage — same circuit,
faster prover and smaller proof.

> **Rationale for running this before F/G/H.** Stage F wraps the DA
> commitment around `PackedCommit`/FRI primitives from `noid_binius`
> and `noid_fri`; Stage G folds per-tx proofs through
> `noid_ivc::Accumulator`; Stage H parallelizes the per-tx prover.
> All three are **multipliers** on the single-tx primitive cost.
> A 2× win at Eπ is a 2× win across the entire block workload
> automatically. A 2× win found later after F/G/H land requires
> re-benchmarking every aggregation shape to confirm it carries through.

### Stage F — DA witness-root schema [OPEN]

- F.1. Specify the packed DA columns per-tx (see §I.7): bit-domain
  set + byte-domain set.
- F.2. Implement `per_tx_witness_commit` in `noid_binius` (builder
  + verifier).
- F.3. Implement `block_witness_root` = Poseidon2b Merkle over per-tx
  commits.
- F.4. Round-trip test at `2^10` tx: commit → open random tx/column
  → verify.
- F.5. Hook to `BlockHeader.witness_root` in `noid_chain`.

Exit: `witness_root` reproducible, openable, and bound to the same
tx_body_hash set that the proofs cover.

### Stage G — Block-level proof aggregation via IVC [OPEN — primitive exists]

Status. `noid_ivc::Accumulator` with `fold_step_prove` and `decide`
is implemented and tested in isolation. What's missing is wiring:
folding actual per-tx `StarkProof` objects (not toy single-column
AIRs) into a typed `BlockProof`.

- G.1. Define `BlockProof = IVCAccumulator` folded over per-tx
  STARK proofs. `fold_step_prove` per tx.
- G.2. `decide` reproduces transcript, verifies every tx FRI-opening,
  checks `y_acc == Σ α_k · y_k`.
- G.3. Wire block-level public inputs: aggregated `prev_state_root_block`,
  `new_state_root_block`, `active_slot_count_delta` (sum of per-tx
  activation columns), `coinbase_credit_total`, `block_tx_root` =
  Merkle of `tx_body_hash` list.
- G.4. Benchmark: aggregated proof size as function of
  `N = tx_per_block` ∈ {1, 8, 64, 512}.

Exit: one verifiable `BlockProof` per block, size sublinear in N
(target: log N + constant).

### Stage H — Parallel proving harness (§15) [OPEN]

- H.1. Define a disjointness predicate:
  `input_slots(tx_a) ∩ (input_slots(tx_b) ∪ output_slots(tx_b)) == ∅`
  for all pairs in a parallel batch.
- H.2. Harness `prove_parallel(batch: &[TxBody]) -> Vec<TxProof>`
  in `bench_prover` that spawns N threads, each proving one tx
  against a **shared read-only prev_state snapshot**.
- H.3. Wall-clock test: 8 disjoint txs in parallel vs. sequential
  → ≥ 4× speedup on 8-core. Not an absolute guarantee (scheduler
  noise allowed), but a regression test.
- H.4. Document that parallel proving is prover-side only; serialized
  apply in chain is preserved by G.3's `block_tx_root` ordering.

Exit: demonstrable prover-side parallelism over disjoint slot sets.

### Stage I — Performance regression gate [OPEN]

Goal: lock in the wins from Eπ and protect block-level numbers from
Stage G. Eπ produced the **baseline and optimized single-tx numbers**;
Stage I turns them into a CI-enforced budget and extends coverage
to the block-aggregation shape.

Budgets (single-tx numbers are the Eπ.10 result; block numbers
require Stage G to have landed for G.4 to report them):

- **Proof size (single tx)**: ≤ 64 KiB on realistic body (4 inputs,
  4 outputs).
- **Proof size (block, N=64 via IVC)**: ≤ 96 KiB.
- **Prove time (single tx)**: ≤ 400 ms on one modern core.
- **Verify time (single tx)**: ≤ 8 ms.
- **Verify time (block, N=64)**: ≤ 32 ms.
- **Peak prover memory (single tx)**: ≤ 512 MiB.

Stage I deliverables:
- I.1. `bench_prover` exports these six numbers to `reports/perf_tip.md`
  on every tagged revision. Source report: `stark_report.rs`.
- I.2. CI regression gate: a PR that regresses any number by > 5%
  vs. the tip in `reports/perf_tip.md` is blocked.
- I.3. Link `reports/perf_baseline_postE.md` and
  `reports/perf_postE_optimized.md` as historical anchors in
  `reports/README.md` so regressions are explicable.

Exit: six numbers recorded, green, gated; Eπ gains cannot silently
erode.

### Stage J — Recursive chain-of-proofs (§15.4 claims 4, 5, 10) [OPEN]

**Goal.** `BlockProof_{n+1}` verifies `BlockProof_n` inside its own
circuit, so that a fresh light client needs exactly one proof — the
tip — to verify the entire chain from genesis. This is the single
largest cryptographic-capability step beyond Stage G, and the one
that turns the engine from "per-block aggregation" into a true
proof-native ledger.

Prerequisite: Stage G landed. Without G.3's stable public-input
schema there is nothing well-typed to chain.

- **J.1 — Block-proof public-input canonicalization.** Freeze the
  tuple `BlockPublicInputs = (prev_block_state_root, new_block_state_root,
  prev_block_proof_digest, active_slot_count, log_slots, block_tx_root, witness_root)`.
  Every field must be a fixed-width digest or `u64`; no
  variable-length payloads. `prev_block_proof_digest` is a Poseidon2b
  commitment to `BlockProof_{n-1}`'s serialized bytes.
- **J.2 — Recursive verifier circuit (`noid_air::airs::block_proof_verify`).**
  AIR that re-executes `noid_ivc::Accumulator::decide` on
  `BlockProof_{n-1}`. Inputs: claimed `prev_block_proof_digest` +
  the prior accumulator's public tuple. Constraint: the transcript
  replay reproduces the verifier's final acceptance. Same pattern
  as `fri_state_open` but for the IVC decider, not a FRI opening.
- **J.3 — Genesis base case.** A distinguished `GenesisBlockProof`
  whose `prev_block_proof_digest` is a protocol constant
  `GENESIS_PROOF_DIGEST` (Poseidon2b of a fixed sentinel). Base AIR
  accepts this constant unconditionally; inductive AIR requires real
  decider replay. One boolean selector separates the two cases.
- **J.4 — Chain binding.** Inside `block_proof_verify`, enforce
  `BlockPublicInputs_n.new_block_state_root == BlockPublicInputs_{n+1}.prev_block_state_root`
  and `Poseidon2b(BlockProof_n.bytes) == BlockPublicInputs_{n+1}.prev_block_proof_digest`.
  This is what makes the chain recursive — breaking it is what a
  forger would need to do.
- **J.5 — `LightClientHeader` = (`block_header_n`, `BlockProof_n`).**
  Reusable type. One-shot `verify_light_client(tip) → bool` routine
  in `noid_chain` that runs the recursive decider on `BlockProof_n`
  and returns `true` iff the whole chain from genesis to `n` is valid.
  Target verify time: within 2–3× of a single `BlockProof.decide()`,
  i.e. still O(1) in chain length.
- **J.6 — Round-trip test: synthetic 100-block chain.** Build a chain
  where each `ChainState` is advanced by a realistic block, each
  `BlockProof` folds one tx, and each `BlockProof` in turn recursively
  verifies the previous. A fresh client decodes only the tip and
  accepts. Separately confirm that tampering with block 50's
  `new_state_root` causes `verify_light_client(tip_100)` to reject.
- **J.7 — Size & time targets.**
  * `BlockProof_n` size independent of `n` (constant within noise).
  * `verify_light_client(tip)` ≤ 50 ms on one modern core at N=100.
  * Prover overhead per block due to J.2 recursion: ≤ 2× the
    non-recursive Stage G baseline.
- **J.8 — Non-finality oracle.** A recursive proof does NOT by itself
  decide which of two competing chains is canonical — that's PoW's
  job. Document that J validates "this is a valid history", not
  "this is THE history"; finality still comes from §11.

Exit: a light client running only a genesis constant +
`verify_light_client(tip)` correctly accepts a valid 100-block chain
and rejects any single-bit tampering. §15.4 claims 4, 5, 10 become
implemented facts, not just framing. Claim 3 (block = aggregated
proof checkpoint) graduates from Stage G's single-block result to
a cross-block invariant.

### Stage K — Review contract & closure [OPEN]

- K.1. Update `ARCHITECTURE.md §4` narrative and
  `SPECIFICATION.md §4` public-input schema to match the final AIR
  inventory (including the GKR-spine split and the
  `tx_body_merkle_boundary` pin path).
- K.2. One-page `noid_stark/docs/predicate.md` listing the nine
  predicates of §I.1 with file:line citations, plus §15.4 philosophy
  claims → file:line implementation citations.
- K.3. External review pass on the predicate list, state-transition
  completeness, the coinbase mux, and the recursive chain binding
  (Stage J).

Exit: engine is complete against the `SPECIFICATION.md` obligations
(§0–§17) plus the `DESIGN_NOTES.md` recursive-chain claims.

---

## Part IV. Non-goals (explicit, do not drift into)

- No chain-level policy: mempool admission, fee market, PoW puzzle,
  difficulty adjust, reorg, finality, gossip, wallet UX, slot-hint
  service.
- No block-assembler logic beyond a trivial test driver: tie-break,
  coinbase position/count, expansion trigger → future chain layer.
- No new cryptographic commitment on outputs: `tx_body_hash` via
  `tx_body_merkle` is sufficient.
- No new hash primitive.
- No new FRI parameters.
- No changes to `noid_ivc`, `noid_binius`, `noid_fri`, `noid_core`
  beyond what Stages F/G/H/J require at their wire boundaries.

---

## Part V. Coverage matrix — `SPECIFICATION.md` vs engine

Reading: "engine contract" is what the engine must provide; everything
else is out of scope by Part IV. Status reflects the code at ROADMAP tip.

| Design § | Engine obligation | Status | Target stage |
|---|---|---|---|
| §0 state model, zero canonicalization | 3-column FRI, leaf-hash zero, zero-subtree constant | done | — |
| §0 `state_root = Poseidon2bSponge(TAG_FRISTATE, log_slots ∥ 3 roots)` | `fri_state_combiner_composite` | done | — |
| §1 genesis | `FriState::from_slots` | done | — |
| §2 `Address = H_ADDR(secret)` | `haddr` AIR | done | — |
| §3 tx body + body hash | `TxBody`, `hash_tx_body`, GKR spine (`noid_gkr`) with STARK-side `tx_body_merkle_boundary` / `tx_body_spine` pins | done (GKR-spine production path; 4-lane leaf path kept by boundary pins) | E.1 |
| §4 ownership (haddr + hauth) | per-input composition, gated by `InputValid` | done | — |
| §4 balance | `balance_gate` (regular only today) | partial | E.5 |
| §4 range | `range_gate` | done | — |
| §4 state correctness — prev-input opens | `fri_state_open` on prev | done | — |
| §4 state correctness — prev-output `is_mint ⇒ pre=0` | `fri_state_open` on prev, is_mint selector already exists | missing (wiring only) | E.2 |
| §4 state correctness — new-input opens `== 0` | `fri_state_open` on new | missing | E.3 |
| §4 state correctness — new-output opens `== (v,o)` | `fri_state_open` on new | missing | E.3 |
| §5 public inputs | `PublicInputs` has (prev_root, new_root, tx_body_hash, fee, n_in, n_out) | partial (needs coinbase_credit, log_slots, activation cols) | E.4–E.6 |
| §6–§8 mempool / block driver / apply_block | `noid_chain::block` skeleton done; policy layer | **OUT OF SCOPE** (policy) | — |
| §9–§11 observer, replay semantics | nothing from engine | — | — |
| §12 coinbase | `is_coinbase` flag, parameterized `balance_gate`, `coinbase_credit` public input | missing | E.5 |
| §13 dust floor | in-circuit `v == 0 ∨ v ≥ MIN_VALUE` | optional | E.7 |
| §14 wallet retry | wallet | **OUT** | — |
| §15 parallel prove | harness over disjoint slot sets | missing | H |
| §15 DA/packed witness | `witness_root` builder | partial (primitives exist, no per-tx schema) | F |
| §15.1 slot allocator (free_slots min-heap primary + splitmix64 random probe fallback; active_slot_count; alloc_counter) | `noid_chain::ChainState` | done (native) | — |
| §15.1 `is_mint ⇒ pre=0` | in-circuit | missing (wiring only) | E.2 |
| §15.1 wallet-chosen `slot_index` verified by native allocator (pre=0) | `noid_chain::insert_output` | missing (TxOutput needs slot_index field) | E.1 |
| §15.2 tie-break | chain | **OUT** | — |
| §15.3 activation / deactivation public columns | `tx_validity` | missing | E.4 |
| §15.3 `log_slots` as AIR constant + FS-absorbed | AIR builder param | missing | E.6 |
| §15.3 `ZERO_SUBTREE_ROOT[k]` table | constant table | missing | E.6 |
| §15.3 occupancy / expansion trigger | chain | **OUT** | — |
| `SPECIFICATION.md §4` / §17 tx = self-contained state transition proof (4-corner) | `noid_stark::StarkProof` + E.2/E.3 | partial (1/4 corners done) | E.2, E.3 |
| `DESIGN_NOTES.md §1.3` block = aggregated recursive proof checkpoint | `noid_ivc::Accumulator` + block wiring | primitive done, wiring missing | G |
| `DESIGN_NOTES.md §1.4` recursive chain-of-proofs (`Proof_{n+1}` verifies `Proof_n`) | `noid_air::airs::block_proof_verify` | missing | J |
| `DESIGN_NOTES.md §1.5` / §1.10 full-chain verification O(1) via light client | `verify_light_client(tip)` | missing | J.5 |
| `DESIGN_NOTES.md §1.13` / §1.14 mempool, PoW, miner-as-aggregator claims | consensus layer | **OUT** | — |
| `DESIGN_NOTES.md §2`–§4 UX / verdict | docs | — | — |
| (engine deliverable) HLeaf output duplication | removed; `tamper_output_leaf_absorb_pin_rejects` gated | **done** | B [done] |
| (engine deliverable) post-E perf baseline & optimization | `stark_report.rs` on production-shape predicate | missing | Eπ |
| (engine deliverable) block-level proof aggregation | IVC fold over N tx proofs | primitive done, integration missing | G |
| (engine deliverable) perf regression gate | concrete targets + CI check | missing | I |

---

## Part VI. Review contract

Before any stage is marked complete:

1. Every test that must REJECT actually REJECTS (assertion-flip
   sanity: flipping it makes the test red).
2. `cargo test --all` green on the stage tip.
3. `cargo build --all` green on the stage tip.
4. No new public column, constraint, bridge, or commitment is
   introduced without a sentence in this file describing its
   binding role.
5. §I.1 (the nine predicates), §I.8 (canonical flow), and §V
   (coverage matrix) still match the code one-for-one. If any row
   is stale, fix it in the same change.
6. `bench_prover` numbers (Stage I) either improve or stay within
   the regression budget.
