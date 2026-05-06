# PARANOID — Transparent Slot-Based UTXO Validity Engine

### A STARK-Based Validity Engine for Transparent UTXO Chains

PARANOID is a STARK-based execution and validity engine for transparent UTXO ledgers. It proves correctness of state transitions without trusted setup, without transaction re-execution, and without cryptographic opacity (no view keys, no commitment blinding, no scan tags, no nullifiers).

Poseidon2b is used inside the AIR. The native field is GF(2^128) binary tower. FRI commitments use Blake3.

The system defines a validity kernel intended for integration into a full blockchain protocol.

---

## Chain constants (locked)

`BLOCK_MAX_TXS = 1024`,
`TXBODY_DEPTH = 4` (fixed 16-leaf Poseidon2b tree),
`STATE_LOG_SLOTS = 24`.

---

## North star

One objective: **a transparent UTXO validity engine whose per-transaction correctness is proven by a single STARK over `TxValidityAir`**, verified against a fixed public-input tuple:

```
PublicInputs = (prev_state_root, new_state_root, tx_body_hash, fee)
```

This validity proof is designed to be composable across blocks via IVC for fast synchronization. Every engineering stage exists to make this execution kernel efficient, sound, and deployment-ready for integration into a full blockchain protocol.

!IMPORTANT! read GENERAL_DESIGN.md to understand our goal more detailed.

---

## Per-tx permutation budget (entire hash-cost of validity)

| Sub-circuit                                  | Poseidon2b perms                     |
| -------------------------------------------- | ------------------------------------ |
| Ownership `H_ADDR` (4 inputs)                | 4                                    |
| Auth `H_AUTH` (4 inputs)                     | 4                                    |
| UTXO leaf `H_LEAF(value, owner)` (8 outputs) | 8                                    |
| Tx-body Merkle depth 4 + wrap                | 31 (59 AIR instances under Option α) |
| FRI-state opening                            | 0 (sumcheck — no hash)               |

Targets: prove 1–2 s on a 12-core AVX2 box, verify ≈ 20 ms, proof 50–100 KB per tx; block-level IVC sync of 100 blocks in seconds.

---

## Non-negotiables

This is execution-core cryptographic code. No optimisation is allowed to:

1. **Weaken or disable `Air::check`.** A malformed witness must be rejected in **every** release build. `Air::check` is not gated under `debug_assert`, not feature-flagged, and is not an "unchecked fast path" in production. `prove_air_unchecked*` exists solely for soundness tests that simulate a malicious prover and is marked `#[doc(hidden)]`.

3. **Drop native checks on the grounds that the cryptographic layer would catch it anyway.** The native pre-check and the cryptographic layer are two independent defences; both must hold the invariant.

Priority ranking for every design call, in order: **security → soundness margin → prover speed → proof size → prover memory → code size**. When two stages offer the same soundness guarantee, prefer the one that reuses an existing primitive (public columns, echo columns, ladder-merge sumcheck) over the one that widens the trace.

---

## Current architecture (what is actually shipped)

### Field, hash, FRI

- **Field.** GF(2^128) binary tower, represented as `Block128`.
  Packed-SIMD widths `PACKED_LANES ∈ {1, 2, 4}` auto-selected between
  AVX-512 / AVX2 / scalar; CLMUL via x86_64 PCLMUL when available.
- **Flat basis (GCM polynomial).** `Flat<Block128>` is the dedicated
  flat-basis type; tower↔flat conversion is a pair of nibble lookup
  tables; reduction is modulo `x^128 + x^7 + x^2 + x + 1`. Every hot
  multiplication on the prover path runs through `clmul_gcm`.
- **Hash.** Poseidon2b, `t = 4`, `F_ROUNDS = 8`, `P_ROUNDS = 58`,
  `N_ROUNDS = 66`, S-box `x^7`. Native reference in
  `noid_poseidon2b::native::permutation`; every AIR that arithmetises
  Poseidon verifies its witness against `Poseidon2bPermutation::permute_mut`
  before any STARK-layer test.
- **FRI.** Blake3 Merkle commitments, `NUM_QUERIES = 96`,
  `LOG_RATE = 2`, `TAU = 7`. Parallel additive-NTT `commit_fast`.

### Commitments — state and tx body

- **State commit (`noid_chain::fri_state`).** Three `Block128` columns
  (`value`, `owner_hi`, `owner_lo`) over `2^STATE_LOG_SLOTS = 2^24`
  slots, each with an independent FRI Merkle commitment. The state
  root is

  ```
  Poseidon2bSponge(TAG_FRISTATE, log_slots || r_value || r_hi || r_lo)
  ```

  Deterministic-empty, deterministic-update, spend-restore round-trip,
  and batched-equals-sequential all covered by tests; per-slot
  `open` / `verify_opening` shipped with tamper tests.

- **Tx-body commit.** `noid_poseidon2b::primitives::hash_tx_body` is a
  fixed depth-4 Poseidon2b binary tree over 16 leaves, canonical order

  ```
  L0  = prev_state_root
  L1  = fee_leaf(fee)
  L2..L5   = hash_input_leaf(slot_index, value, owner) × 4
  L6..L13  = hash_output_leaf(value, owner) × 8
  L14, L15 = zero padding
  ```

  Final wrap: one Poseidon2b permutation seeded with the
  `TAG_TXBODY` capacity IV over `(root_hi, root_lo)`.

### Tx / chain types

`noid_tx` ships the transparent rewrite: `hash_utxo_leaf`,
`derive_address`, `hash_auth_tag`, newtype wrappers (`Address`,
`Commitment`, `AuthTag`, `TxBodyHash`, `SpendSecret`) for domain-
separated digests, plus the tx body / wire format.

`noid_chain` provides the block header, state, FRI-state wiring, and
DA wire format. A `Node` runtime that uses the STARK end-to-end does
not yet exist — that is Stage 7 below.

### STARK engine (`noid_stark`)

The engine supports arbitrary `log_rows ≥ TAU+1 = 8` AIRs with
cross-row reads, ladder-batched rotation openings, and
RLC-batched base-column openings. Shipped sub-AIRs run at their
own fixed sizes (`POSEIDON_PERM_LOG_ROWS = 8`,
`TXBODY_MERKLE_LOG_ROWS = 13`, `FRI_STATE_COMBINER_LOG_ROWS = 9`,
`FRI_STATE_OPEN_LOG_ROWS = 3`, `BALANCE_MIN_LOG_ROWS = 8`). The
single stitched `[L]` composite's `log_rows` is derived from the
Stage 5 stitch, not hardcoded.

- **Frame + constraints.** `EvalFrame { local, next }`,
  `Constraint::shifted_columns()`, cyclic `Air::check` wrap-around.
- **Ladder-FRI.** Every `n+1` ladder
  openings per shifted column collapse to one FRI opening.
- **Base-column RLC batching.** A single FRI opening over an
  RLC of base-column MLEs. Merkle authentication inherits from
  per-column roots plus the per-round FRI-fold oracle roots.
- **Ladder Merge.** Every per-slot product sumcheck
  folds directly into the multipoint sumcheck as `η_s · W_s(x)`
  pairs; one merged degree-2 sumcheck closes all base openings and
  every shifted-column ladder at a shared `r''`, followed by one
  RLC-batched FRI opening.
- **Flat-basis zero-check.** `CompiledGates` is a single SoA
  (`betas_flat`, `col_indices`, `next_indices`, `max_local_arity`,
  `max_next_arity`). Constraints expose
  `Constraint::evaluate_flat(FlatEvalFrame)`; all multiplication uses
  `clmul_gcm`. Tower↔flat conversion runs only at boundaries
  (witness ingress, final claim). This is the only zero-check path —
  the tower-basis prover has been removed; no runtime switch exists.
- **Fiat-Shamir transcript.** `Channel` driven by `Poseidon2bSponge`,
  with byte-tag domain separation on every absorb.

Latest prod bench for the big sub-circuit:
`[K] TxBodyMerkleAir` (`log_rows = 13`, 59 instances): prove ≈ 1.37 s,
ts+sc ≈ 323 ms. Verify and proof-size tracked by `stark_report.rs`.

### AIR library (`noid_air`)

**Algebraic gate primitives.** `BoolGate`, `WeightedLinearGate`,
`WeightedLinearGateShifted` (off-by-one cross-row linear),
`SelectorGate`, `MulGate`, `SquareGate`.

**Public-column machinery.** `PublicColumn` (verifier re-evaluates the
programme MLE at the sumcheck terminal point `r_point`), plus the
helper family in `noid_air::gates::{row_selector, const_column}`:
`emit_public_cell`, `emit_column_eq_at_row`,
`emit_column_eq_at_next_row`, `emit_multi_row_selector`,
`emit_rows_must_be_zero`, `row_indicator_programme`,
`multi_row_indicator_programme`.

**Shipped AIRs.**

- **Bit / range / balance — non-Poseidon half of `TxValidityAir`.**
  `CarryRippleAir`, `BitAdderAir`, `RangeGateAir`, `BalanceGateAir`
  (Variant 3 — dual chain of `bit_adder` blocks with cross-block
  carry-bridge gates, fee folded into the B chain, asymmetric-width
  tail equality), plus `TxValidityAir::new_3b4` and its skeleton /
  balance-selector-pinned variants. Skeleton `InputValid` /
  `OutputValid` masks are pinned to zero on every non-input /
  non-output row via multi-hot `PublicColumn`s. The 22 balance-block
  `is_input` / `is_reset` programmes are pinned too.
- **Poseidon interior.** `PoseidonPermAir` (30-column lane, 66-round
  trace) with the full `emit_perm_all` 29-gate set. `HAddrAir`,
  `HAuthAir`, `HLeafAir` stack 2–3 permutation blocks side-by-side and
  share the row axis at `log_rows = 8`.
- **Poseidon programme binding.** `emit_perm_public_columns_at` and
  `emit_perm_public_columns_row_major_at` pin `is_full`, `is_round`,
  and `rc[0..4]` on every permutation block. Padding-row RC tamper
  tests cover the MLE re-evaluation path end-to-end.
- **Option α boundary ties (sponges).** `HAddrAir`, `HAuthAir`,
  `HLeafAir` each ship a single constructor that installs every
  boundary tie via Option α (private pre-MDS witness columns
  `pre_s[0..4]`): capacity-IV pins on public IV lanes, absorb XOR on
  secret lanes via MDS-linked witness cells (never publicly pinned),
  inter-permutation carries via `WeightedLinearGateShifted`, and the
  output squeeze pinned to the declared public hash. Privacy
  invariant: `SpendSecret` never appears in any `PublicColumn`.
- **`TxBodyMerkleAir` — the 59-instance stack.** Lays out the
  depth-4 tx-body tree plus wrap as 59 permutation instances in
  post-order:

  ```
  input leaves  (L2..L5)    × 3 perms = 12
  output leaves (L6..L13)   × 2 perms = 16
  internal compress × 2 perms × 15   = 30
  wrap                               =  1
  ```

  Row budget `59 × 128 = 7552` live rows, padded to `2^13 = 8192`
  (`TXBODY_MERKLE_LOG_ROWS = 13`). Head rows carry four pre-MDS
  witness lanes `pre_s[0..4]`; a row-0 MDS binding gate ties
  `s[lane]@row_0 = MDS_FULL(pre_s[..])[lane]`, so cross-instance dst
  pins land on the **pre-MDS** lanes (sponge-input *before* MDS,
  matching native `absorb_pair`).

  Cross-instance carries flow through **echo columns** — committed
  witness columns held constant across a live interval by a
  selector-gated degree-1 transition gate `echo[r+1] − echo[r] = 0`
  (multi-hot `hold_mask`). One echo column pins one source cell and
  multiple downstream dst cells on disjoint rows. An
  interval-graph greedy colouring runs once at
  `TxBodyMerkleAir::new()` to minimise `n_echo` across the fixed
  post-order layout.

  Four shipped echo-tie families:
  - E.1 — left-child digest fan-out for level-1 compresses.
  - E.4.a — capacity continuation between perms of the same sponge.
  - E.4.b — compress rate absorb.
  - E.4.c — leaf rate absorb with the shared-payload optimisation
    (`N_LEAF_RATE_PAYLOAD_COLS = 2`: 16 leaf non-head instances share
    two physical payload columns via row-gated absorbs, instead of a
    pair per instance). The three-term XOR
    `pre_s_next[lane] + echo_prev_out[lane] + payload[lane] = 0`
    fires per instance, but `payload[lane]` is **not yet** pinned to
    the tx-body value / owner / tag columns. Closing that pin is
    Stage 1.

### IVC (`noid_ivc`)

Linear folding over GF(2^128): additions are XOR and therefore free,
so folded MLEs stay additive with no quadratic cross term and no
per-step re-commitment. Shipped surface: `Accumulator`,
`fold_step_prove`, `decide`. First cut is single-column; multi-column
AIRs fold column-by-column with independent sub-accumulators. Fold,
decide, forged-`y_acc` rejection, forged-opening rejection, empty-
decide-rejection tests all green.

### Binius packing (`noid_binius`)

`pack_bits` (128× into one `Block128`) and `pack_bytes` (16×), wired
as a DA optimisation for the bit-domain columns
(`InputValid` / `OutputValid` / skeleton masks). Column domain tags
`ColumnDomain ∈ {Bit, Byte, Block128}` route packing automatically.

### Benches (`bench_prover`)

`stark_report.rs` reports prove / verify / proof-size buckets for the
Poseidon sponge AIRs, `TxBodyMerkleAir`, and the current skeleton of
`TxValidityAir`. Numbers above are from there, on `prod` config.

### What soundness holds today

- Per-AIR soundness for every shipped circuit: `HAddrAir`,
  `HAuthAir`, `HLeafAir`, `PoseidonPermAir`, `TxBodyMerkleAir`,
  `TxBodySpineComposite`, `BalanceGateAir`, `RangeGateAir`,
  `BitAdderAir`, `CarryRippleAir`, `TxValidityAir` (skeleton),
  `FriStateOpenAir`, `FriStateCombinerAir`,
  `FriStateCombinerComposite`.
- State commitment: `combine_roots` (native Poseidon2b sponge over
  `log_slots ‖ r_val ‖ r_hi ‖ r_lo` under `TAG_FRISTATE`) is
  bit-identical to the in-circuit `FriStateCombinerAir` digest
  (fixed-point test `combine_roots_matches_stage_4c3_combiner_air`).
- FRI opening soundness: `noid_fri::prove`/`verify` with
  `NUM_QUERIES = 96`, `LOG_RATE = 2`, `TAU = 7`.
- IVC linear fold soundness: `fold_three_decide_ok` +
  forged-`y_acc` / forged-opening rejection.
- Privacy: `SpendSecret` never appears in any `PublicColumn`;
  absorb XORs land on secret pre-MDS lanes (Option α).

### What is trusted today (the gaps the plan closes)

- **Cross-AIR semantic ties.** Every sub-circuit is
  internally sound but not yet tied to its siblings. For example,
  nothing today forces `HAddrAir.output_squeeze` to equal the
  `owner` column cell opened by `FriStateOpenAir` for the same
  input `i`, nor `HAuthAir.output_squeeze` to equal the tx auth
  tag, nor `HLeafAir.output` to equal the `TxBodyMerkleAir`
  output-leaf payload. Closed by **Stage 5**.
- **`PublicInputs` surface.** `PublicInputs = (prev_state_root,
  new_state_root, tx_body_hash, fee)` exists as a type, but is not
  wired as the verifier's single input surface. The four scalars
  are still reached via disjoint per-AIR pins. Closed by
  **Stage 6**.
- **End-to-end prover driver.** No single entry point today
  produces `(PublicInputs, StarkProof)` from a `Tx` and verifies
  it against `PublicInputs` alone. `bench_prover` drives each
  sub-AIR separately. Closed by **Stage 7** (`[L]` bench).
- **IVC block-fold shape.** `noid_ivc` ships single-column linear
  fold. Block-level fold needs per-column composition + a decided
  header layout (`cum_proof_ref`, `witness_root`, etc.) that
  cannot be safely locked before IVC economics are known. Closed
  by **Stage 7.5** (feasibility spike) → **Stage 9**
  (production).
- **Node runtime.** No `submit_tx` / `apply_block` driver exists.
  Closed by **Stage 8** (*minimal* runtime only; product-layer
  policy like mempool TTL, peer rate limits, fridge resource caps
  is deferred to Stage 9+).


---

# Plan

## Guiding principles for remaining stages

1. **One north-star metric per stage.** Each stage ships with a
   single measurable acceptance that advances `(prove time, proof
   size, verify time, PI surface)`. Feature accretion without a
   measurable delta is out of scope.
2. **PCS properties stay at the PCS layer.** Any arrow whose
   soundness can be discharged through "same `FriCommitment` →
   same MLE opening" is closed outside the AIR, never through
   extra committed trace columns. This is what killed the
   original Stage 4c.3.c chunk-ii.
3. **Bench before optimising.** Structural work (Stage 5, 6) is
   non-negotiable. Micro-optimisation (column fusion, gate
   compression) waits for the `[L]` baseline.
4. **Engine before product.** Mempool policy, TTL, per-peer rate
   limits, fridge resource envelopes — all deferred until the
   proving economics are measured. A slow prover makes every ops
   question about it irrelevant.
5. **IVC shape decided early, IVC production late.** The header
   format depends on the fold shape; the fold shape depends on
   one feasibility spike. Do the spike right after `[L]` so
   Stage 8 node runtime locks its header against the real shape,
   not a guess.

---

## Stage 5 — Semantic cross-AIR binding layer

Turns every shipped sub-AIR from "internally honest" into "honest
*about the same tx*". The machinery is the same
`emit_column_eq_at_row` / `emit_multi_row_selector` family already
used inside single AIRs — the novelty is that the two sides of
the equality live in different sub-AIRs' column spaces.

Three semantic ties:

- **T1 — Input ownership.** For each tx input `i`:
  `HAddrAir<i>.output_squeeze == FriStateOpenAir.owner[i]`
  (two 128-bit halves: `owner_hi`, `owner_lo`).
- **T2 — Input authorisation.** For each tx input `i`:
  `HAuthAir<i>.output_squeeze == tx.auth_tag[i]`. The second
  absorb of `HAuthAir<i>` is tied to `tx_body_hash` — but only
  **once**, as an internal equality between the Merkle wrap
  output column and the `HAuthAir` second-absorb column. Do **not**
  introduce `tx_body_hash` as a separate public pin per HAuth
  instance; Stage 6 pins it exactly once.
- **T3 — Output commitment.** For each tx output `j`:
  `HLeafAir<j>.output_squeeze == TxBodyMerkleAir.output_leaf_input[j]`.

### Mechanism

A new `SemanticBindingComposite` stitches the relevant sub-AIRs
into one composite trace with disjoint column blocks (same
shape as `FriStateCombinerComposite`). Cross-block ties are
emitted as `SelectorGate(row_indicator, WeightedLinearGate([(lhs,
1), (rhs, 1)], 0))` — zero new gate primitives, zero new witness
columns (the equality is between existing trace cells), one
shared row indicator per tie family (already shipped).

### Why this can't live as extra PIs

The temptation is to just expose both sides of each tie as
separate public inputs and let the verifier check equality
natively. Rejected: it doubles the PI surface without any
soundness gain (the verifier already sees one side of every
tie as part of the tx body); moves work from prover-side (free)
to verifier-side (paid); and the PI surface is the user-facing
contract we're trying to freeze in Stage 6.

### Acceptance

Per-tie forgery matrix: for each of T1×N_INPUTS + T2×N_INPUTS +
T3×N_OUTPUTS ties, flipping exactly one byte on either side of
the equality causes composite `check` to reject.

---

## Stage 6 — Single `PublicInputs` surface

`PublicInputs = (prev_state_root, new_state_root, tx_body_hash,
fee)` becomes the **only** verifier-visible surface. Each scalar
pinned exactly once; all other AIR-internal consumers reach it
through Stage 5 equality ties.

Four pins:

- **`prev_state_root`** → `FriStateCombinerComposite.prev_digest`
  (pinned as `expected_prev_state_root_fields`; the landing path
  for Stage 4c.3.c).
- **`new_state_root`** → `FriStateCombinerComposite.new_digest`
  (pinned as `expected_new_state_root_fields`).
- **`tx_body_hash`** → `TxBodyMerkleAir`'s wrap output (reuses
  the Stage 1 O2 tie — *verify* this pin is reused, do not
  re-introduce it). Every `HAuthAir<i>` second-absorb cell reaches
  `tx_body_hash` via the Stage 5 T2 tie, **not** a fresh PI pin.
- **`fee`** → `BalanceGateAir`'s B-chain tail operand, lifted
  from a witness cell to a PI-bound operand.

### Acceptance

(a) Mutating any of the four PI scalars without a matching trace
rebuild causes `verify_air` to reject. (b) The verifier signature
is a single function `verify(&PublicInputs, &StarkProof) -> bool`
— no other reachable verifier input exists. (c) The four pins
are each emitted exactly once (asserted at composite construction
time).

### Why Stage 6 must come before Stage 7

`[L]` measures the production prover/verifier shape. If the PI
surface still has per-AIR pins it isn't measuring the shape that
ships, it's measuring a draft.

---

## Stage 7 — End-to-end tx proof bench `[L]`

One bench block proving **one realistic** transaction (4 in / 8
out, non-zero fee, valid H_ADDR / H_AUTH / H_LEAF / TxBodyMerkle
/ FriStateOpen / FriStateCombiner across ≈ 47 Poseidon perms +
three FRI state openings) through the Stage 5 + 6 composite.

Emit: `prove_wallclock`, `verify_wallclock`, `proof_size`, and
the prover bucket breakdown (`commit / ts+sc / base FRI /
ladder`). Report in `bench_prover::stark_report` as the `[L]`
workflow.

### `log_rows` is not fixed in advance

`log_rows` is derived from the post-Stage-5-stitch column /
row budget of the unified composite. Bench at the minimum
satisfying `log_rows` and sweep `log_rows ∈ {min, min+1, min+2}`
to characterise blowup sensitivity. Do **not** hardcode
`log_rows = 16`.

### North-star gate

`[L]` is the first moment we see end-to-end numbers on the ship
path. Every later-stage decision (IVC recursion shape, bench
targets, optional optimisations) keys off this measurement.

### Post-bench optimisation candidate — `FriStateOpenAir` `col_gp_*` fusion

Only evaluated **after** the `[L]` baseline. Details preserved
as before: single degree-3 shifted recurrence
`acc_next = acc + γ^i · eq_tail · pre_lane` per lane, fused
into `evaluate_flat` via two `clmul_gcm` calls + one XOR.
Removes `col_gp_value`, `col_gp_owner_hi`, `col_gp_owner_lo`
(−3 committed FRI columns × `N_INPUTS` rows of commit cost) at
the cost of one extra CLMUL per row inside the quotient path.
Decision gate: keep iff
`prove_wallclock_new ≤ baseline ∧ proof_size_new ≤ baseline`.

---

## Stage 7.5 — IVC feasibility spike

**Scope.** One fold step:
`fold(prev_cum_proof, tx_proof_from_[L]) -> cum_proof'`, run
through `decide`. No block assembly, no multi-column composition
layer, no chain driver. Just: can the linear fold absorb a real
`[L]` proof in acceptable time with recognisable proof-size
economics, and what does the folded accumulator shape imply for
`BlockHeader`?

**Why before Stage 8.** The block-header layout (specifically
`cum_proof_ref`, `witness_root`, and whether
`proof_transcript_hash` is the absorption target for the next
fold) is decided here. Locking the header before the spike is
the classic "node writes headers that Stage 9 must migrate"
trap the previous roadmap walked into.

**Deliverable.** A one-page report: fold wallclock, folded-proof
size, decide wallclock, header-field implications. No new
public API; the spike may be thrown away. The point is the
measurement and the header shape it forces.

**Acceptance.** Report committed to `reports/ivc_spike.md`;
`BlockHeader` definition reviewed against the report's
implications and updated (or explicitly frozen, with rationale)
before Stage 8 starts.

---

## Stage 8 — Minimal node runtime

Smallest thing that ties `[L]` proofs to chain state:

```rust
pub struct Node {
    pub state: FriState,
    pub head: BlockHeader,
    pub mempool: Vec<(Tx, StarkProof)>,
}
impl Node {
    pub fn genesis(initial: Vec<SlotValue>) -> Self;
    pub fn submit_tx(&self, tx: Tx) -> Result<StarkProof, TxBuildError>;
    pub fn verify_tx(&self, tx: &Tx, proof: &StarkProof) -> bool;
    pub fn apply_tx(&mut self, tx: &Tx, proof: &StarkProof) -> Result<(), ApplyError>;
    pub fn assemble_block(&mut self) -> Block;
    pub fn apply_block(&mut self, block: &Block) -> Result<(), ApplyError>;
}
```

Contract:

- `submit_tx` builds the witness trace via the Stage-5 composite
  and runs `noid_stark::prove_air` against Stage 6's
  `PublicInputs`.
- `verify_tx` is exactly `verify_air(pi, &proof)` — nothing
  else.
- `apply_tx` assumes `verify_tx` already passed; applies the
  delta; asserts the post-apply `state.root()` matches
  `new_state_root` from the tx's `PublicInputs`.
- `apply_block` is `apply_tx` in a loop, plus the header-root
  consistency check.
- **Coinbase / block reward.** Genesis via `Node::genesis`;
  per-block reward via an `is_coinbase` selector inside
  `TxValidityAir` flipping the balance identity to
  `sum(outputs) = block_reward + fee_pool` with zero inputs.
  One extra selector column, no new AIR, no new sub-circuit.

### Explicitly **not** in Stage 8

The following are **Stage 9+** (post-mainnet-bench ops layer) and
must not bleed into Stage 8:

- per-peer rate limiting on `submit_tx`;
- `pending_mint_slots` reservation map with TTL;
- `MAX_RESERVATIONS` / LRU eviction / graceful degradation;
- "fridge-class" 512 MB RAM / single-core envelope;
- hint RPC beyond raw bitmap.

These are product-layer decisions that can only be tuned once
the Stage 7/7.5 economics are known. Adding them now is
premature product engineering.

### Acceptance

E2E integration test in `noid_chain`:
`genesis → alice_sends_bob → bob_spends → verify_balances`. Depends
on Stage 6 (real verifier surface) and Stage 7.5 (decided
`BlockHeader` shape).

---

## Stage 9 — Production runtime + IVC fast-sync + mainnet bench

1. **`noid_chain::sync::fold_block(cum_proof, block_proof) ->
   cum_proof'`** via `noid_ivc`, built on the per-column
   composition layer informed by Stage 7.5.
2. **Mempool / ops hardening** (deferred from Stage 8):
   `pending_mint_slots` soft-reservation map, TTL, LRU eviction,
   per-peer rate limiting, graceful degradation, snapshot-bound
   hints. Resource envelope tuned against measured proof and
   mempool costs, not against a hypothesised fridge constraint.
3. **Mainnet workflow section in `stark_report.rs`:**
   - `empty_block`
   - `single_tx_alice_to_bob` (1 in / 1 out)
   - `max_tx` (4 in / 8 out, depth-24 FRI openings, value
     saturates 64 bits)
   - `full_block` (N × `max_tx`, N tuned to target block proof
     time)
   - `end_to_end` (genesis → Alice→Bob → balance check)
   - `ivc_sync_100_blocks`
4. Target hardware: 12-core AVX2. Report in `reports/mainnet.md`.

Targets:

| Metric | Value |
|---|---|
| Prove time / tx | 1–4 s (12-core AVX2) |
| Proof size / tx | 50–100 KB |
| Verify time / tx | ~20 ms |
| IVC sync 100 blocks | seconds |

---

## Stage 9+ — post-mainnet exploration (not scheduled)

Ideas captured here are **not on the critical path** and must not
influence Stage 1–9 decisions. They exist so that, once the
mainnet bench numbers are in, we can evaluate drop-in upgrades
against concrete measurements rather than rediscovering the
design space from scratch.

### 9+.A Sparse Merkle Complement allocator (zk-native slot picker)

**Motivation.** The locked slot-selection model ("UTXO
slot-selection model") relies on an off-chain occupancy bitmap
hint and lex tie-break for mint-slot collisions. It is correct
and zero proof-footprint, but it assumes wallets can cheaply
refresh the hint. Under adversarial or highly-contended load the
retry rate could climb, and the bitmap-hint surface is a natural
DoS amplifier.

**Idea.** Replace the hint with a publicly-committed
`freed_slots_root` — a Sparse Merkle tree whose members are the
slot indices currently known to be empty. Maintained per-block
by the miner (single-writer, so no contention in principle).

Wallet path:
  1. Read the latest `freed_slots_root` (published in the
     block header alongside `new_state_root`).
  2. Pick any member slot.
  3. Add a `MembershipProof { slot, merkle_path }` to the mint
     witness. AIR verifies `slot ∈ freed_slots_root` in-circuit
     via the existing Poseidon2b Merkle primitive (reuses
     `HAuthAir` / `TxBodyMerkleAir` infrastructure; no new
     sponge).
  4. Miner, on inclusion, removes `slot` from
     `freed_slots_root` and mints it (standard spend/mint delta
     against `state_root`).

**Properties.**
- **No contention by construction.** `freed_slots_root` has a
  single writer per block (the miner); two wallets picking the
  same slot simply see one tx included and the other rejected
  at block-assembly, identical to today — but with zero retry
  needed because the **next** `freed_slots_root` already
  reflects the assignment.
- **Privacy preserved.** `slot_index` is not derived from
  recipient or tx content; it's just a member of a public set.
- **Self-contained proof.** Wallet needs only the latest public
  `freed_slots_root`; no peer-node occupancy query.
- **Proof cost.** +1 Merkle path of depth `STATE_LOG_SLOTS = 24`
  per mint ≈ 24 Poseidon2b compressions. Marginal vs. the
  existing `FriStateOpenAir` opening (~0.5 % wallclock, <1 KB
  proof).
- **Header surface.** `BlockHeader` grows by one 32-byte root.

**Rejected alternatives (kept here so we don't re-debate them).**
- Hash-derived addressing (`slot = H(tx_id, i)` +
  probe sequence): regresses privacy (slot correlates with
  recipient / tx id), only *hides* coordination into the probe
  oracle, and still needs an occupancy hint for the probe to
  terminate. Not an improvement.
- Miner-assigned indices broadcast as part of block building:
  breaks self-contained wallet proofs (wallet must re-prove
  after inclusion), incompatible with the Stage 4b.2
  opening-against-`prev_state_root` design.
- Full on-chain bitmap: 2 MB of state per block, defeats the
  point of a succinct state commitment.

**Migration shape (if accepted post-Stage 9).**
1. Add `freed_slots_root` to `BlockHeader`; initialise at
   genesis as the full `2^24` empty set.
2. Extend `TxValidityAir` / `FriStateOpenAir` with a
   membership-proof selector gated by `is_mint`.
3. Update `noid_chain::Node::apply_block` to delete minted
   slots and insert freshly-spent slots into
   `freed_slots_root` atomically.
4. Wallet RPC replaces the bitmap-hint endpoint with a
   thin `freed_slots_root` + path oracle (nodes keep the
   Sparse Merkle structure; wallets fetch paths on demand).

**Decision gate.** Revisit after Stage 9 mainnet benches
publish `retry_rate` and `hint_refresh_latency` under realistic
load. If retry rate < 1 % and latency < 1 s, stay with the
bitmap-hint model. If either threshold is breached, this
upgrade is the drop-in.

### 9+.B Other speculative threads

- **Lookup-argument migration for Poseidon S-box.** Evaluate
  against a post-Stage 7 bench of per-perm witness cost; only
  worth it if the S-box table dominates the FRI commitment
  bucket.
- **Column-domain-aware FRI packing.** The `ColumnDomain` tag
  already distinguishes `Bit`-packable from `Block128` columns;
  a future FRI layer could exploit this to pack bit columns
  128× on the DA path. Mentioned but not scheduled.
- **Recursive proof compression at the IVC boundary.** If
  Stage 9 IVC fast-sync throughput bottlenecks on proof size,
  wrapping the fold in a SNARK-over-STARK recursion is the
  next knob. Dependent on upstream recursion tooling maturing.

These are **notes, not commitments.**

---

## Out of scope (explicit)

- Networking / p2p / gossip
- Wallet GUI, HD wallet derivation
- Fee market / mempool prioritisation
- snark-friendly address encoding / bech32-alike
- Stateless-client proofs beyond what IVC sync already gives
- Multi-asset support (`asset_tag` is removed — single native asset
  only)

This document is the source of truth.
