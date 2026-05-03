# Paranoid — Transparent UTXO STARK (mainnet design)

Design direction: Bitcoin-style transparent UTXO with Poseidon2b in AIR,
binary-tower GF(2^128) field, FRI over Blake3. No trusted setup. No view
keys, no blinding, no scan tags, no nullifiers. State is FRI-committed
instead of Sparse-Merkle-committed.

Chain constants (locked): `BLOCK_MAX_TXS = 1024`, `TXBODY_DEPTH = 4`
(fixed 16-leaf Poseidon2b tree).

---

## North star — what all of this is for

The whole project is one objective: **a transparent UTXO blockchain whose
per-tx validity proof is a single STARK over `TxValidityAir`**, verified
with a fixed public input tuple

```
PublicInputs = (prev_state_root, new_state_root, tx_body_hash, fee)
```

and folded block-by-block via IVC for fast sync. Every engineering
stage below exists to make that one proof cheap, sound, and honest.

The critical path to that proof, in order:

1. **Primitives + tx/state types** (Stage 1) — done.
2. **FRI-committed state** (Stage 2) — done.
3. **STARK engine for `log_rows = 16` AIRs with cross-row reads and
   multi-column batched openings** (Stage 3b-0) — done.
4. **Non-Poseidon gate library: bool, linear, range, balance** (Stage 3b)
   — **current focus**. Without range+balance there is no honest tx.
5. **Poseidon gate library: H_ADDR, H_AUTH, H_LEAF, TxBodyMerkle**
   (Stage 3c).
6. **Compose everything into `TxValidityAir`** (Stage 3d).
7. **Node runtime with real tx flow** (Stage 4).
8. **IVC fast-sync and mainnet benches** (Stage 5).

Anything outside this list is a side-quest and has to justify its
existence against the critical path.

---

## 0. Architecture

| Layer | Choice |
|---|---|
| Field | GF(2^128), binary tower, Block128 |
| Hash | Poseidon2b (t=4, x^7, F=8, P=58, R=66) |
| FRI Merkle | Blake3 |
| State commit | FRI-committed MLE over 2^24 UTXO slots |
| Tx-body commit | Sparse Merkle depth 4 (16 leaves) |
| Ownership | `H_ADDR(secret) = owner` in AIR (signatureless) |
| Replay guard | `H_AUTH(secret, tx_body_hash) = tag` in AIR |
| Double-spend | linearly zero the consumed slot in `state_delta` |
| Sync | IVC-folded cumulative block proof (`noid_ivc`) |

### 0.1 Permutation budget (per tx)

| Sub-circuit | Count |
|---|---|
| Ownership H_ADDR (4 inputs) | 4 |
| Auth H_AUTH (4 inputs) | 4 |
| UTXO leaf H_LEAF(value, owner) (8 outputs) | 8 |
| Tx-body Merkle depth 4 + wrap | 31 |
| FRI-state opening | 0 (sumcheck, no hash) |
| **Total per tx** | **~47** |

---

## Stage 1 — Primitives cleanup [DONE]

Transparent rewrite of `noid_poseidon2b::primitives` + `noid_tx`.
`hash_utxo_leaf`, `derive_address`, `hash_auth_tag`, newtype wrappers
(`Address`, `Commitment`, `AuthTag`, `TxBodyHash`, `SpendSecret`).
FRI release defaults: `NUM_QUERIES = 96`, `LOG_RATE = 2`, `TAU = 7`.
16-leaf tx-body layout at depth 4.

## Stage 2 — FRI state commitment [DONE]

`noid_chain::fri_state`: three `Block128` columns (`value`, `owner_hi`,
`owner_lo`) over `2^24` slots, each with its own FRI Merkle commitment.
`root = blake3("PARANOID/FRISTATE/v1" || log_slots || r_value || r_hi
|| r_lo)`. Deterministic, monotonic writes, spend-restore round-trip,
batched-vs-sequential equivalence all green. Opening APIs consumed by
the §FriStateOpen sub-circuit in Stage 3d.

## Stage 3b-0 — STARK engine infrastructure [DONE]

Everything needed for `log_rows = 16` AIRs with cross-row reads,
ladder-batched rotation opening, and RLC-batched base-column opening.
This is the platform on which Stage 3b/3c/3d gates sit.

Journal of finished substages:

- **3b-0.1** — `EvalFrame { local, next }`, `Constraint::shifted_columns()`,
  cyclic `Air::check` wrap-around.
- **3b-0.2** — VSHIFT sumcheck gadget (`noid_stark::vshift`): closed-form
  `C'(r)` reconstruction from an `n+1`-point ladder of MLE-openings,
  wired into `prove_air` / `verify_air`. Invariant: `log_rows ==
  padded_log_len(log_rows)` when any shifted column is declared.
- **3b-0.3** — `CarryRippleAir`: first rotation-consuming gate, five
  bit-domain columns, six constraints, benchmark driver for 3b-0.4/0.5.
- **3b-0.4** — Ladder-FRI batching via product-sumcheck (CRYPTO.md §12a,
  Candidate A): all `n+1` ladder openings per shifted column collapse
  to one FRI opening. On `prod` (log_rows=16, n_shifted=5):
  verify 402 → 140 ms (−65 %), proof 14.5 → 2.61 MB (−82 %), prove 2.17 → 2.07 s.
- **3b-0.5 / 3b-0.5.1** — RLC-batched base-column opening (CRYPTO.md §12b)
  with `C_batch` Merkle build eliminated via caller-owned commitment
  absorption. Authentication inherits from per-column roots + per-round
  FRI-fold oracle roots. On `prod`: verify 98.7 ms (−29 % vs 3b-0.4),
  proof 1.12 MB (−57 %), prove 2.15 s (−3.6 %).
- **3b-0.6 — Ladder Merge (CRYPTO.md §12c').** Collapses every per-slot
  §12a product sumcheck directly into the §12c multipoint sumcheck as
  `η_s · W_s(x)` pairs with `W_s(x) = Σ_k γ_s^k · eq(P_{s,k}, x)`. One
  merged degree-2 sumcheck closes all base openings and every shifted-
  column ladder at a shared `r''`, followed by a single RLC-batched FRI
  opening. Each slot contributes one extra `(A, B)` pair instead of a
  full `log_len`-round sumcheck and a dedicated FRI opening. Wire format
  drops `ladder_batch_rounds` and `ladder_batch_openings`. The
  `0xFFFE_…|slot` tag survives as the sub-channel tag absorbed with each
  slot's ladder partials (see §12c'.3). Expected impact per projection:
  Balance per-tx prove ~157 → ~65 ms, verify ~115 → ~30 ms; `ladder`
  bucket collapses to the weight-table fill and closed-form `W_s(r'')`
  reconstruction. Measured numbers land after the next `stark_report`
  run.

Post-3b-0.5.1 prover bucket breakdown on `prod` (pre-Ladder-Merge):

| Bucket   | prove share | verify share |
|----------|-------------|--------------|
| commit   | 64.2 %      | —            |
| ts + sc  | 14.3 %      | 5.5 %        |
| base FRI | 2.8 %       | 44.6 %       |
| ladder   | 18.7 %      | 49.9 %       |

The remaining prove-time gap to the original −15 % Stage-3b-0.5 target
sits in the commit bucket. Moving it needs a **packed-leaf Merkle
redesign** (`n_cols` values per leaf, same number of leaves, fewer
hashes overall). Tracked as **Stage 3b-0-LATE** below, gated on tx-AIR
numbers — not a prerequisite for the critical path.

---

# Critical path (current)

## Stage 3b — non-Poseidon gate library

This is where `TxValidityAir` starts being real. Every gate here is a
prerequisite for either range-checking tx amounts or enforcing the
conservation law `Σ inputs = Σ outputs + fee`.

Principle: **each gate ships as a standalone `*Air` first** with its
own `cargo test -p noid_air` coverage (positive + forgery) and a
micro-bench. Only after the standalone proof round-trips cleanly does
the gate get composed into `TxValidityAir`. Rationale: when a composite
AIR fails, you want to bisect against known-good building blocks, not
debug five interacting gates at once. `CarryRippleAir` already sets
this pattern.

### 3b-1 — BoolGate + WeightedLinearGate consolidation [DONE]

**Goal.** Clean, reusable bool and linear-combination primitives on
the post-3b-0 bus (ladder + RLC-batched opening). Partial coverage
exists today (`BoolGate` in `noid_air`, ad-hoc XOR-linear sums inside
`CarryRippleAir` / `LinearCombinationAir`); consolidate into first-class
gates with tests.

- `BoolGate { col }`: `x · (x + 1) == 0`. Already shipped — promote to
  `noid_air::gates::bool`, export, pin negative tests.
- `WeightedLinearGate { coeffs: Vec<(usize, Block128)>, const_term }`:
  `Σ cᵢ · colᵢ + c₀ == 0`, local-only. Generic replacement for the
  ad-hoc `sum + a + b + carry == 0` gate in `CarryRippleAir`.
- `SelectorGate { sel, inner }`: multiplies any gate by a boolean
  selector column. Needed by balance gate (tx can have fewer than
  `MAX_INPUTS` valid inputs) and by boundary suppression.

**Deliverable.** `noid_air::gates` module with the three gates and
their negative tests. `CarryRippleAir` migrated onto them (no new
tests, just refactor, shows they subsume the ad-hoc forms).

**Size.** ~300 LOC + ~200 LOC tests. 1 day.

### 3b-2 — RangeGateAir (standalone) [DONE]

Proves `x ∈ [0, 2^64)` for `x: u64` via bit-decomposition. Rotation gate,
so it rides the same VSHIFT + ladder-FRI bus as `CarryRippleAir`.

**Columns (4).**

- `bit` (`Bit` domain) — LSB-first bit decomposition of the value.
- `acc` (`Block128`) — running accumulator `Σ bit[j] · weight[j]`.
- `is_reset` (`Bit`) — marks row 0 of each instance.
- `weight` (`Block128`) — per-row GF(2^128) weight, reinitialised to
  `ONE` at every reset row and doubled (multiplied by `x`) on every
  non-reset transition. At bit position `i` within an instance the
  cell equals the field monomial `x^i`; for `i < 128` this matches the
  integer `1 << i` bitwise, which is more than enough for `u64`.

**Constraints (6).**

1. `bool(bit)` — per-row boolean.
2. `bool(is_reset)` — per-row boolean.
3. `acc_init` — `is_reset · (acc + bit · weight) == 0` (forces `acc = bit`
   at reset rows, since `weight == 1` there).
4. `acc_recurrence` — `(1 + is_reset_next) · (next(acc) + acc + next(bit) · next(weight)) == 0`.
5. `weight_init` — `is_reset · (weight + 1) == 0`.
6. `weight_recurrence` — `(1 + is_reset_next) · (next(weight) + weight · 2) == 0`.

Two shifted columns (`acc`, `weight` — plus `is_reset`, `bit` reads via
`next()`); `n_shifted = 4` before ladder-batching, reduced to the usual
one-sumcheck-per-column by Stage 3b-0.4.

Binding `acc` at the last row of each instance to an externally-claimed
public value is deferred to the §3b-4 composition step (would need a
`ConstColumnGate` or public-input row).

**Tower-basis caveat.** `Block128` is GF(2^128) in tower basis, so the
`weight_{i+1} = weight_i · 2` recurrence produces tower-field powers
rather than integer `1 << i`. `acc` at the final row is therefore a
faithful linear encoding of the bit vector but NOT the integer
embedding of `x`. For range-checking alone this is sound (bool pins
each `bit_i ∈ {0,1}` and the recurrence is injective). Integer-embedding
of `acc` is deferred to §3b-4 via a `ConstColumnGate` that pins
`weight[i] = Block128::from(1u128 << i)` explicitly. §3b-3 BalanceGate
sidesteps the issue by building the integer adder directly on the bit
columns (no dependency on `acc`).

**Standalone acceptance — shipped.**

- `range_gate_native_check_accepts_valid` — `noid_air` unit test.
- `range_gate_*_rejects_*` — five negative cases in `noid_air::airs::range_gate`.
- `range_gate_*` STARK integration tests live in `noid_stark` (same
  pattern as CarryRipple): honest round-trip, bit flip, non-bit,
  acc tamper, weight tamper, missing-reset, acc-at-last-row sanity.

**Bench.** `[D] RangeGateAir` block in
`bench_prover/benches/stark_report.rs`, bucket layout `small/mid/prod`
= `log_rows ∈ {8, 12, 16}`. Prod row = 1024 parallel u64 checks.

### 3b-3 — BalanceGateAir (standalone)

**Goal.** Enforce `Σ inputs.value = Σ outputs.value + fee` over `u64`
with honest overflow handling.

**Status (2026-05-02).** Design chosen: *Variant 3 — dual chain of
`BitAdderAir` blocks with cross-block carry-bridge linear gates and a
final bitwise-equality check between `A = Σ inputs` (4 operands, width
≤ 66) and `B = Σ outputs + fee` (9 operands, width ≤ 68)*. Fee is
folded into the B chain (not the A chain) so the enforced equation
directly matches the UTXO conservation goal `Σ inputs = Σ outputs + fee`.

Rejected alternatives and why (see session log):

- *D — bit-serial multi-operand adder with multi-bit carry in one
  chain*: not expressible in char-2 because `Block128::from(2)` is a
  tower-basis monomial shift, not an integer doubling. `D_i = sum_i +
  2·carry_{i+1}` has no gloss into char-2 polynomial constraints.
- *D' — Wallace tree inline within one row*: correct, but equivalent
  prover cost to Variant 3 (same number of char-2 multiplications
  across the trace), and much heavier wiring code.
- *A' — 12 sequential bit_adder blocks with plain column aliasing*:
  simple but ~25 cols and still needs cross-block wiring; no better
  than Variant 3 on any axis.

**Design (Variant 3).** Two parallel chains of width-growing
`BitAdderAir` instances, each block reusing the §3b-3a gate family
with a **parametric column layout** so multiple instances coexist in
one composite trace:

- Chain A (`Σ inputs`, 4 operands, balanced binary tree):
  - `A0 = i0 + i1` (width 64 → 65)
  - `A1 = i2 + i3` (width 64 → 65)
  - `A2 = A0 + A1` (width 65 → 66)
- Chain B (`Σ outputs + fee`, 9 operands): 7-block output tree plus a
  fee-tail block, final width ≤ 68.
  - `B00..B03`, `B10,B11`, `B20` — binary tree over 8 outputs (result ≤ 67)
  - `B21 = B20 + fee` (width 67 → 68)
- Cross-block bridge: `WeightedLinearGate` equating `sum` column of
  block k with `a` column of block k+1 (same row range, different
  column slot). Final carry-out bit of block k becomes the top bit of
  block k+1's `a` input via one more bridge gate.
- Final equality between the 66-bit A tail and the ≤ 68-bit B tail:
  (1) bits 0..64: `A2.sum ≡ B21.sum` on A2's active input rows,
  (2) bit 65: `A2.carry ≡ B21.sum` at the A2 is_input transition,
  (3) bit 66: `B21.sum ≡ 0` at the B20 is_input transition,
  (4) bit 67: `B21.carry ≡ 0` at the B21 is_input transition.
  Gates (3) and (4) together catch the `Σ outputs + fee ≥ 2^66` overflow attack.

**Plan (3 commits).**

1. **3b-3.1 — `bit_adder` gates parametric layout [DONE].**
   Refactor `FaSumGate`, `BitAdderCarryInitGate`,
   `BitAdderCarryNextGate`, `PadZeroGate` to accept explicit column
   offsets via constructors (default constructors keep the legacy
   `BIT_ADDER_COL_*` layout intact, so `BitAdderAir` is unchanged).
   Adds one unit test that the same gate family works correctly at a
   shifted column offset. Prerequisite for 3b-3.2.
2. **3b-3.2 — `BalanceGateAir` standalone [DONE].**
   Shipped in `noid_air::airs::balance_gate`. 11 parametric `bit_adder`
   blocks at contiguous 6-column offsets (`BALANCE_N_COLS = 66`), cross-
   block bridges (`BalanceBridgeBitsGate`, `BalanceBridgeCarryGate`),
   and asymmetric-width tail equality (`BalanceFinalSumGate`,
   `BalanceFinalCarryGate`, two `BalanceZeroAtTransitionGate`s).
   Width layout: A0,A1=64; A2=65; B0x=64; B1x=65; B20=66; B21=67. A
   tail value (≤ 66 bits) lives on `A2.sum[0..64] ‖ A2.carry[65]`;
   B tail value (≤ 68 bits) lives on `B21.sum[0..66] ‖ B21.carry[67]`.
   The two high bits of the B tail (`B21.sum[66]`, `B21.carry[67]`) are
   pinned to zero for a balanced tx, catching `Σ outputs + fee ≥ 2^66`
   overflow. Fee is added to the B chain (not the A chain) so the
   enforced equation matches `Σ inputs = Σ outputs + fee` directly.
   Trace builder maps primary tx `(inputs[4], outputs[8], fee)` onto
   block-0 operand pairs, with all other hypercube instances zero-filled
   (zeros trivially satisfy every bit_adder + bridge constraint). Native
   `air.check` acceptance tests cover: honest balanced tx (8 random
   seeds), 13 single-operand tampers, bridge tamper, A2/B21 final sum
   flip, `(2^64-1)*4 + fee=4 ≥ 2^66` overflow path, and B-chain top-bit
   overflow. `log_rows = BALANCE_MIN_LOG_ROWS = 8` default (two 128-row
   instances — STARK floor).
3. **3b-3.3 — STARK integration + bench [DONE].**
   `BalanceGateAir` wired through `prove_air`/`verify_air`; shifted-
   column set computed by the default `Air` trait (one `carry` per block
   plus the bridge `next`-reads on operand, carry, `is_input`, B21.sum
   and B21.carry columns). Integration tests in `noid_stark::tests`
   mirror the `RangeGateAir` + `BitAdderAir` patterns:
   `balance_gate_stark_honest_tx_accepted` (log_rows ∈ {8, 10}),
   `balance_gate_stark_unbalanced_rejected` (B21.b fee flip),
   `balance_gate_stark_bridge_tamper_rejected` (A0 → A2 bridge cell
   flip), `balance_gate_stark_b_chain_overflow_rejected` (2^65 vs 2^66
   mismatch via `prove_air_unchecked`), and
   `balance_gate_stark_ladder_tampering_rejected` (FRI partial flip).
   Bench block `[E] BalanceGateAir` in
   `bench_prover/benches/stark_report.rs` with `BALANCE_SHAPES =
   [("small", 8), ("mid", 12), ("prod", 16)]` — same log_rows axis as
   CarryRipple/Range so the three AIRs are comparable (128 rows/instance
   × 66 cols for Balance vs 64 rows/instance × 5 or 4 cols for
   CarryRipple/Range). Prover/verifier buckets + estimated proof size
   reported in the same format as §3b-0 / §3b-2.

**Standalone acceptance (3b-3.2).**

- `balance_gate_accepts_balanced_tx` — random `(inputs, outputs, fee)`
  with `Σ in = Σ out + fee`, proof verifies.
- `balance_gate_rejects_unbalanced` — perturb any of the 13 values,
  verifier rejects.
- `balance_gate_rejects_overflow` — set inputs to values that
  individually pass range but whose sum overflows `u67`, caught by the
  top-carry assertion.

**Bench.** Same three-config bench as §3b-2.

**Size.** ~350 LOC + ~250 LOC tests for 3b-3.2, plus this commit's
~80 LOC refactor + 2 tests.

### 3b-4 — Composition into `TxValidityAir` (non-Poseidon half) [DONE]

Compose `BoolGate` + `WeightedLinearGate` + `SelectorGate` + §Range +
§Balance into the first real `TxValidityAir` subset: all non-Poseidon
gates wired, all Poseidon sub-circuits stubbed with free variables.
Proves nothing crypto-meaningful yet, but ensures the composite-AIR
column layout is nailed down before §3c doubles the column count.

**Shipped.** `TxValidityAir::new_3b4(log_rows)` composes the Stage 3a
skeleton BoolGates (cols 0..10) with `BalanceGateAir` embedded at
`TX_VALIDITY_BALANCE_COL_OFFSET = 10` (cols 10..76). `BitAdder`
blocks inside `BalanceGateAir` already `BoolGate` every operand bit,
so the Range sub-circuit is inlined rather than instanced separately
— Range remains available as a standalone AIR for non-balance
bit-decomposition callers. Trace builder
`TxValidityAir::build_trace_3b4` concatenates the zero-padded 3a
witness columns with `build_balance_columns(inputs, outputs, fee,
log_rows)`.

**Acceptance.** `noid_stark::tx_validity_3b4_tests` runs end-to-end
`prove_air` → `verify_air` on a 1-in / 1-out honest tx and three
forgery variants (unbalanced outputs, tampered skeleton selector,
tampered balance-region column); standalone 3b-1/-2/-3 gate tests
unchanged and green.

**Soundness caveats, deferred to §3d.** (1) Witness `value` column is
not yet bound to balance operands — needs `ConstColumnGate` +
`WeightedLinearGate` cross-region bridge. (2) Poseidon inputs are
still free. (3) Skeleton selectors are not bound to the `valid` flag.

---

## Stage 3c — Poseidon gate library

Gates for `H_ADDR`, `H_AUTH`, `H_LEAF`, `TxBodyMerkle`. Each shipped
as a standalone `*Air` with forgery coverage before composition, same
pattern as §3b.

**Native reference locked.** `noid_poseidon2b::native::permutation`:
`t=4`, `F_ROUNDS=8`, `P_ROUNDS=58`, `N_ROUNDS=66`, `x^7` S-box over
`Block128` (GF(2^128) in tower basis). Every AIR in §3c verifies its
own trace against `Poseidon2bPermutation::permute_mut` before STARK
integration, so arithmetization bugs are localized before the zero-check
bus gets involved.

### 3c-1 — `PoseidonPermAir` (standalone permutation)

**Goal.** One Poseidon2b permutation as a standalone AIR. All four
downstream AIRs (`HAddr`, `HAuth`, `HLeaf`, `TxBodyMerkle`) consume
this as an embedded block, same pattern as `BalanceGateAir` embedding
parametric `BitAdderAir` blocks.

**Row layout.** One row per round step, 66 rounds total. Per row:

- 4 state columns `s[0..4]` (Block128, post-MDS output of the previous
  round, input to this round's RC addition).
- 4 sbox-input columns `sin[0..4]` where `sin[i] = s[i] + RC[i][r]`.
  For partial rounds lanes 1..4 are unused (set to zero by the round-
  type selector).
- 3 sbox-chain aux columns per lane — `x2[i] = sin[i]²`,
  `x4[i] = x2[i]²`, `x3[i] = x2[i] · sin[i]` — matching the native
  chain in `noid_poseidon2b::native::permutation::sbox_x7`. For full
  rounds we need the chain on every lane, so allocate `3 × 4 = 12`
  aux columns total. Partial rounds zero out lanes 1..3.
- 4 sbox-output columns `sout[0..4]`, each pinned by
  `sout[i] = x4[i] · x3[i]` (the final `x⁷ = x⁴·x³` multiplication).
- 1 round index / selector programme column (pinned via
  `ConstColumnGate` in §3d; for standalone 3c-1 it is a witness column
  with `is_full` / `is_partial` bool selectors derived from it).

**Constraints.**

- `SquareGate { out: x2[i], a: sin[i] }` — `x² = x·x`.
- `SquareGate { out: x4[i], a: x2[i] }` — `x⁴ = (x²)²`.
- `MulGate { out: x3[i], a: x2[i], b: sin[i] }` — `x³ = x²·x`.
- `MulGate { out: sout[i], a: x4[i], b: x3[i] }` — `x⁷ = x⁴·x³`.
  Four lanes each for full rounds; partial-round selector forces
  lanes 1..3 aux/output columns to zero.
- `RcBindGate { sin[i] = s[i] + RC[i][r] }` — a `WeightedLinearGate`
  whose constant term is the per-row RC (pinned by programme column
  in §3d, hard-coded in standalone 3c-1).
- `MdsFullGate` / `MdsPartialGate` — `next(s[i]) = Σ M[i][j] · sout[j]`,
  encoded as two `WeightedLinearGate`s with a `next`-read on `s` and
  gated by `is_full` vs `is_partial`.
- Boundary: first row ties `s[..]` to the permutation input (via
  `ConstColumnGate` in §3d; standalone test embeds input in trace).
- Boundary: last row exposes permutation output as the public value.

**Prerequisites** (standalone gate library commits before the AIR):

1. **3c-1.1 — `MulGate` / `SquareGate` primitives.** Promote from
   ad-hoc to first-class gates in `noid_air::gates`. Degree-2 gates,
   local-only. `MulGate::new(out, a, b)` asserts `out = a · b`;
   `SquareGate::new(out, a)` asserts `out = a · a`. Positive + forgery
   unit tests, no STARK yet.
2. **3c-1.2 — `SboxX7Gate` composite.** 3-row helper that bundles the
   four (square, mul, square, mul) chain gates for one lane. Tested
   against native `sbox_x7`.
3. **3c-1.3 — `MdsFullGate` / `MdsPartialGate`.** Thin wrappers over
   `WeightedLinearGate` with a `next`-read on `s`, constants = MDS row.
4. **3c-1.4 — `PoseidonPermAir::new(log_rows)` + `build_trace`.**
   _Landed._ Done in sub-steps 4a–4e:
   - 4a (done): 30-column witness layout + `build_perm_trace` +
     `extract_perm_output`, exact match against native `permute_mut`.
   - 4b (done): `emit_perm_sbox_chain` — 16 degree-2 gates (4 per lane).
   - 4c (done): `emit_perm_rc_binding` — 4 RC XOR gates (lane-0 gated by
     `is_round`, lanes 1..3 gated by `is_full`) + `BoolGate`(is_full) +
     `BoolGate`(is_round). Introduced `POSEIDON_COL_RC`,
     `POSEIDON_COL_IS_ROUND` selector columns (still trusted-input;
     §3d's `ConstColumnGate` will pin them to the literal programme).
   - 4d (done): `emit_perm_mds_blend` — 4 degree-3 `PermMdsBlendGate`s
     combining full/partial MDS arms via `is_full` and `is_round`.
   - 4e (done): `emit_perm_partial_sbox_kill` — 3 degree-2 gates forcing
     `sin[1..3] = 0` on non-full rows.
   - `emit_perm_all` aggregator ships the full 29-gate set; native
     acceptance + forgery matrix already wired.
5. **3c-1.5 (done) — STARK integration.** `prove_air`/`verify_air`
   round-trip at `log_rows = POSEIDON_PERM_LOG_ROWS` (= 8, STARK floor).
   8 forgery tests (sout / rc / partial-row sin kill / `is_full` bool /
   `is_round` bool / x2 / s_next) wired as `poseidon_perm_stark_tests`.
6. **3c-1.6 (done) — Bench block `[G] PoseidonPermAir`** in
   `bench_prover/benches/stark_report.rs`.

**Debt carried forward from 3c-1.4.** See §3d — `rc[..]`, `is_full`,
`is_round` still trusted-input; padding containment deferred.

**Size estimate.** ~400 LOC + ~300 LOC tests. Gates: ~150 LOC. AIR:
~250 LOC. Entirely mechanical once the gate primitives land.

### 3c-2 — `HAddrAir` (2-field sponge, `derive_address`)

Witness and constrain `H_ADDR = Poseidon2b(TAG_ADDRESS, secret_hi, secret_lo)`
as implemented by `noid_poseidon2b::primitives::derive_address`.

**Native behaviour to match** (`Poseidon2bSponge::with_iv` +
`absorb_pair` + `finalize`):

1. Initialize `state = [0, 0, IV_hi, IV_lo]` with
   `(IV_hi, IV_lo) = capacity_iv(TAG_ADDRESS)`.
2. **Absorb permutation.** XOR `(secret_hi, secret_lo)` into
   `state[0..2]` (rate), permute. This is one full Poseidon2b
   permutation via `PoseidonPermAir` (§3c-1).
3. **Padding permutation.** XOR the padding block
   `(0x80…0x00, 0x00…0x01)` as two `Block128` field elements into
   `state[0..2]`, permute. Second full Poseidon2b permutation.
4. Output digest bytes `state[0] || state[1]`.

So `HAddrAir` embeds **two** `PoseidonPermAir` instances back-to-back,
not one — matching the native code, not the original one-liner.

**Sub-steps** (mirrors §3c-1 cadence):

1. **3c-2.1 (done) — Layout + honest trace builder.** Two 30-column
   permutation blocks stacked side-by-side (60 cols, 256 rows), with
   `PermLayout::at(base)` parameterizing the Poseidon emitters so the
   same constraint logic applies to both blocks.
   `build_haddr_trace(secret)` seeds block A at row 0 with
   `[secret_hi, secret_lo, IV_hi, IV_lo]` (where `(IV_hi, IV_lo) =
   capacity_iv(TAG_ADDRESS)`), runs `write_perm_trace_at`, XORs the
   padding block `(0x80, 0x01<<120)` into the rate of the post-perm-A
   state, and runs a second `write_perm_trace_at` on block B. The
   native tests verify the extracted output bytes match both
   `Poseidon2bSponge::with_iv + absorb_pair + finalize` and
   `primitives::derive_address(SpendSecret)`.
2. **3c-2.2 — Capacity-IV binding (deferred to §3d).** Needs a
   `RowSelectorGate` + `ConstColumnGate` primitive that the current
   row-local constraint system lacks. Without it, `state[2],
   state[3]` at block-A row 0 are trusted-input, same treatment as
   `rc` / `is_full` / `is_round` in 3c-1. Captured in the §3d debt
   block below.
3. **3c-2.3..6 — Boundary gates (deferred to §3d).** Absorb XOR,
   inter-permutation carry (rate: XOR with padding block; capacity:
   straight equality), and output squeeze pinning all need the same
   `RowSelectorGate` + `ConstColumnGate` primitive. Landing them here
   would also benefit `PoseidonPermAir` by closing the §3c-1 debts
   (`rc` / `is_full` / `is_round` trusted-input); the primitive is a
   shared dependency. §3d schedules this as a single bundle.
4. **3c-2.7 (partial) — Native acceptance + forgery matrix.** Honest
   trace passes (two native tests vs `Poseidon2bSponge::finalize` and
   `primitives::derive_address`); four forgery tests cover perm-A
   S-box / perm-A MDS / perm-B RC / perm-B partial-row sin. Boundary
   forgeries (IV, absorb XOR, inter-perm carry, output squeeze) gain
   gate coverage once §3d's boundary primitives land.
5. **3c-2.8 — STARK round-trip** at `log_rows = POSEIDON_PERM_LOG_ROWS
   = 8` (single-block rows; both perm blocks share the row axis).
6. **3c-2.9 — Bench block `[H] HAddrAir`** in `stark_report.rs`.

**Boundary-primitive note.** The §3c-1 and §3c-2 interior gates land
clean, but every "boundary tie" in this codebase (IV at row 0, absorb
XOR at row 0, inter-perm carry between blocks, output squeeze at row
`N_ROUNDS`, round-constant programme, `is_full` / `is_round` schedule)
all require the same missing primitive: a row-index-aware selector
(`RowSelectorGate` or a `ConstColumnGate` that reads a synthesized
row-index column). §3d tracks the whole bundle as one work item —
landing it unblocks 3c-1's trusted-input debts AND 3c-2's boundary
gates AND the §3d skeleton-selector pinning all at once.

### 3c-3 — `HAuthAir` (4-field sponge, `hash_auth_tag`) — interior shipped

Three permutations back-to-back, matching
`Poseidon2bSponge::with_iv(TAG_AUTHTAG) + absorb_pair(secret) +
absorb_pair(tx_body_hash) + finalize()`:

1. **Perm A.** XOR `(secret_hi, secret_lo)` into rate; permute.
2. **Perm B.** XOR `(tx_body_hi, tx_body_lo)` into rate; permute.
3. **Perm C (padding flush).** XOR `(0x80, 0x01<<120)` into rate;
   permute. Output = `state[0..2]`.

`HAuthAir` lays out three perm blocks at column bases `0`, `30`, `60`
(90 cols total), sharing the row axis at `log_rows = 8`. Interior
constraints: `3 × emit_perm_all_at = 87` gates. Boundary ties (IV,
each absorb XOR, two inter-perm carries, output squeeze) are
trusted-input, deferred to §3d under the same `RowSelectorGate` /
`ConstColumnGate` bundle as §3c-1 and §3c-2.

Ships: trace builder, native equivalence test vs
`primitives::hash_auth_tag`, interior forgery matrix (perm-A sout,
perm-B MDS, perm-C partial sin-kill, perm-C rc), STARK round-trip
(4 tests), and bench block `[I] HAuthAir` in `stark_report.rs`.

### 3c-4 — `HLeafAir` (4-field `hash_leaf`) — interior shipped

Mirrors `primitives::hash_leaf(&[f0, f1, f2, f3])` under `TAG_LEAF`:
`absorb_pair(f0, f1)` + `absorb_pair(f2, f3)` + padding flush = 3
permutations. Structurally identical to `HAuthAir`; only the capacity
IV differs. 90 cols, `log_rows = 8`, 87 interior gates.

Used by `hash_input_leaf(slot, value, owner)` which feeds the tx-body
Merkle tree leaves. Verified in tests by a direct vector equality
against `hash_input_leaf` (slot=42, value=1_234_567, owner=0..31).

Ships: trace builder, two native equivalence tests (`hash_leaf` and
`hash_input_leaf`), interior forgery matrix (perm-A sout, perm-B MDS,
perm-C partial sin-kill, perm-C rc on full-round row), STARK
round-trip (4 tests), and bench block `[J] HLeafAir` in
`stark_report.rs`. Boundary ties deferred to §3d.

### 3c-5 — `TxBodyMerkleAir` (depth-4 tree + wrap)

4 inputs + 8 outputs = 12 leaves → pad to 16 → depth-4 binary tree =
15 internal `compress` calls (two permutations each) → one final
`compress(tx_body_hash, wrap_tag)`. Total: 12 × 3 + 15 × 2 + 2 = 68
permutations per tx. At ~30 ms/permutation (first bench est.) that is
~2 s/tx in prover cost — will need §3b-0-style ladder batching, but
that is already in place on the bus.

Targets and exact constraint counts written up when §3c-1 closes and
we know the per-permutation prover cost at `log_rows = 16`.

---

## Stage 3d — `TxValidityAir` (full composition)

Fold §3c gates into the §3b-4 skeleton + add `ConstColumnGate` for
verifier-side public-input binding (`is_reset`, `is_final`, bit-position
programme columns, etc.). First honest `TxValidityAir` end-to-end.

**Debt carried forward from §3b-4** (known soundness caveats,
expected — 3b-4 is the "non-Poseidon half" of TxValidity):

- Witness **value column** is not yet bound to the balance operands.
  §3d must cross-link the `v_in`/`v_out` columns the balance sub-AIR
  reads against the tx-body value payload (via `ConstColumnGate` or
  an explicit copy gate).
- Poseidon **inputs** are free-floating: the `PoseidonPermAir` initial
  `s[..]` state is unconstrained at row 0. §3d must pin it to the
  sponge capacity IV + the bound absorb payload (address hash, auth
  hash, leaf inputs per §3c-2/3/4).
- §3b-4 **skeleton selectors** (`is_reset`, `is_final`, row-programme
  flags) are witness columns with only a `BoolGate`; §3d must pin them
  to the literal programme via `ConstColumnGate` so the prover cannot
  shift the row schedule.

**Debt carried forward from §3c-1** (Poseidon permutation):

- `rc[0..4]`, `is_full`, `is_round` columns in `PoseidonPermAir` are
  currently _trusted public input_: `build_perm_trace` populates them
  from `ROUND_CONSTANTS` / `is_full_round`, but no gate asserts the
  binding. §3d must add `ConstColumnGate`s that pin
  - `rc[lane][r] == ROUND_CONSTANTS[lane][r]` for `r ∈ 0..N_ROUNDS`,
    `rc[lane][r] == 0` otherwise,
  - `is_full[r] == 1` iff `r ∈ full-round set`,
  - `is_round[r] == 1` iff `r < N_ROUNDS`.
  Without these, a malicious prover can swap rounds or zero selectors
  to bypass round-constant binding / the MDS blend.
- Padding rows outside `0..N_ROUNDS` on Poseidon columns are
  unconstrained beyond selector gating. When §3d co-locates Poseidon
  with other AIRs, ensure no cross-contamination (likely a `pad_zero`
  selector on `s[..]` past the output row).
- §3c-1.5/1.6 shipped (8-test STARK forgery matrix at
  `POSEIDON_PERM_LOG_ROWS = 8`; `[G] PoseidonPermAir` bench block
  landed at ~25 ms prove / ~13 ms verify / ~35 KB proof on the floor).

**Debt carried forward from §3c-2** (`HAddrAir`, two-permutation
sponge):

- **Capacity-IV binding.** Block-A row 0 must be pinned:
  `state[2]@A_row0 == IV_hi(TAG_ADDRESS)`,
  `state[3]@A_row0 == IV_lo(TAG_ADDRESS)`. Currently trusted-input.
- **Absorb XOR at row 0.** Block-A row 0's `state[0..1]` must equal
  the public-input `(secret_hi, secret_lo)`. Currently trusted.
- **Inter-permutation carry.** Block-B row 0 must equal block-A's
  row-`N_ROUNDS` state XOR'd with the fixed padding word on the rate
  lanes, straight-copied on the capacity lanes:
  - `B.s[0]@row0 = A.s[0]@row_N + 0x80`
  - `B.s[1]@row0 = A.s[1]@row_N + (0x01 << 120)`
  - `B.s[2]@row0 = A.s[2]@row_N`
  - `B.s[3]@row0 = A.s[3]@row_N`
  Currently trusted.
- **Output squeeze binding.** `B.s[0]@row_N`, `B.s[1]@row_N` must
  equal the public `addr_hi`, `addr_lo`. Currently trusted.

All four bullets share the same missing primitive:
`RowSelectorGate` / `ConstColumnGate`. Landing it closes §3c-1's
trusted-input list simultaneously.

**Debt carried forward from §3c-3…5** (sponges + merkle): to be
enumerated when those sub-stages land; at minimum each sponge will
need capacity-IV binding and rate-XOR-absorb gates wired in §3d.

**Acceptance.** `cargo test -p noid_air` green on the negative-test
matrix for every sub-circuit; `[A] TxValidityAir` block in
`bench_prover/benches/stark_report.rs` is promoted from the Stage 3a
skeleton (log_rows=4, bool-only) to the full composition
(log_rows=16), with honest prove/verify/proof-size numbers.

---

## Stage 4 — Node runtime (`noid_chain::Node`)

```rust
pub struct Node {
    pub state: FriState,
    pub head: BlockHeader,
    pub mempool: Vec<(Tx, Proof)>,
}
impl Node {
    pub fn genesis(initial: Vec<SlotValue>) -> Self;
    pub fn submit_tx(&self, tx: Tx) -> Result<(Tx, Proof), TxBuildError>;
    pub fn assemble_block(&mut self) -> Block;
    pub fn apply_block(&mut self, block: &Block) -> Result<(), ApplyError>;
}
```

- `submit_tx` builds the witness trace via `TxValidityAir::build_trace`
  and runs `noid_stark::prove_air`.
- `apply_block` iterates txs: `verify_air` → `state.apply_delta` →
  assert resulting root == `block.header.new_state_root`.

**Acceptance**: E2E test `genesis → alice_sends_bob → bob_spends → verify_balances`.

---

## Stage 5 — IVC fast-sync + mainnet benches

1. `noid_chain::sync::fold_block(cum_proof, block_proof) -> cum_proof'`
   via `noid_ivc`.
2. New `[E] mainnet workflow` section in `bench_prover/benches/stark_report.rs`:
   - `empty_block`
   - `single_tx_alice_to_bob` (1 in / 1 out)
   - `max_tx` (4 in / 8 out, depth-24 FRI openings, value saturates 64
     bits)
   - `full_block` (N × max_tx, N tuned to target block proof time)
   - `end_to_end` (genesis → Alice→Bob → check balances)
   - `ivc_sync_100_blocks`
3. Target hardware: 32-core AVX2. Report in `reports/mainnet.md`.

**Targets (reality-check)**

| Metric | Value |
|---|---|
| Prove time / tx | 1–4 s (32-core AVX2) |
| Proof size / tx | 50–100 KB |
| Verify time / tx | ~20 ms |
| IVC sync 100 blocks | seconds |

---

## Stage 3b-0-LATE (deferred) — packed-leaf Merkle redesign

Not on the critical path. Only executed if the tx-AIR bench at the end
of Stage 3d shows commit > 55 % of prove wallclock *and* prove
wallclock > 3 s on `prod` (32-core AVX2). Mechanism: `n_cols` field
elements per Merkle leaf → same leaf count, ~`n_cols`× fewer
Poseidon compressions. Expected prove delta on today's
CarryRipple `prod`: ~ −25 % of commit bucket = ~ −16 % of wallclock.

Soundness: unchanged — the opened leaf is still a single hashed commitment
to an `n_cols`-tuple of field values, the RLC-batched opening (§12b)
already treats columns independently inside the FRI fold.

---

## Out of scope (explicit)

- Networking / p2p / gossip
- Wallet GUI, HD wallet derivation
- Fee-market / mempool prioritization
- Snark-friendly address encoding / bech32-alike
- Stateless client proofs beyond what IVC-sync already gives
- Multi-asset support (`asset_tag` is removed; single native asset only)

This document is the source of truth. `upgrade.md` is deleted and must
not be reintroduced.
