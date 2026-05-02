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

Post-3b-0.5.1 prover bucket breakdown on `prod`:

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

### 3b-2 — RangeGateAir (standalone) [NEXT]

**Goal.** Prove `x ∈ [0, 2^w)` for `x: Block128` that encodes a `u64`
(or `u128`) value. This is the gate that VSHIFT was built for.

**Design.** Bit-decomposition with carry. For a value `x: u64`:

```
columns: bit[0..64], acc[0..64]
bit[i] ∈ {0,1}                         -- BoolGate per bit column
acc[0]   = bit[0]                      -- seed (at reset row)
acc[i+1] = acc[i] + bit[i+1] · 2^(i+1) -- linear recurrence, uses next()
acc[w-1] = x                           -- boundary equality to the opened value
```

In GF(2^128) the constants `2^i` are field elements (`Block128::from(1u128 << i)`)
and the recurrence is a `WeightedLinearGate` with one rotated read per
row. The cross-row read is exactly what `VSHIFT` authenticates.

Per-instance width `w = 64`; `log_rows = 16` packs `1024` independent
range checks per trace (one per tx value: 4 inputs × value + 8 outputs
× value + 1 fee = 13 checks per tx; trace handles up to ~78 tx worth,
more than enough for `TxValidityAir`). `is_reset` column marks the
row-0-of-each-instance boundary, analogously to `CarryRippleAir`.

**Constraints.**

1. `bool(bit)` — per-row boolean.
2. `acc_recurrence` — `is_reset · (acc − bit) + (1 + is_reset) · (acc − (prev(acc) + bit · 2^pos)) == 0`,
   where `pos` is a constant column of bit positions within the instance.
3. `acc_final` — at `is_final` rows, `acc == x_public` where `x_public`
   is the claimed range-checked value surfaced through a public column.

**Standalone acceptance (`cargo test -p noid_air`).**

- `range_gate_accepts_valid_u64` — random `x < 2^64`, proof verifies.
- `range_gate_rejects_out_of_range` — set `bit[i]` pattern to encode a
  value ≥ 2^64, verifier rejects.
- `range_gate_rejects_non_bool` — flip one `bit[i]` to a non-bit field
  value, caught by `BoolGate`.
- `range_gate_rejects_tampered_acc` — mutate one `acc[i]`, caught by
  `acc_recurrence` through `next()`-read.
- `range_gate_rejects_mismatched_public_value` — honest bits, wrong
  claimed `x`, caught by `acc_final`.

**Bench.** New `[D]` block in `bench_prover/benches/stark_report.rs` at
`log_rows ∈ {8, 12, 16}`, mirroring the CarryRipple `small/mid/prod`
bucket layout that currently sits under `[B]`. Target on `prod`
(`log_rows = 16`): prove < 2.5 s, verify < 150 ms, proof < 1.5 MB.

**Size.** ~400 LOC in `noid_air` + ~300 LOC tests + ~100 LOC bench.
2–3 days.

### 3b-3 — BalanceGateAir (standalone)

**Goal.** Enforce `Σ inputs.value = Σ outputs.value + fee` over `u64`
with honest overflow handling.

**Design.** With 4 inputs and 8 outputs of `u64` each, the sum fits in
`u67`. Approach: reuse the carry-ripple machinery on a wider adder
laid out over the hypercube. The 13 values are already bit-decomposed
by §3b-2; balance is then a fixed sum over those bit columns, checked
via one composite carry-ripple that consumes `input_bits − output_bits
− fee_bits` and asserts the top `u67` result is zero.

Concretely:

- Re-use `RangeGateAir`'s `bit` column layout; add two small columns
  `sign` (`+1` for inputs / fee, `−1` for outputs → in char-2 this is
  just column-remapping, documented in the gate comment) and
  `balance_carry`.
- Add one `WeightedLinearGate` enforcing bitwise sum-of-signed-bits +
  carry.
- Add one `bool(balance_carry)` + one `acc_final` (final carry-out
  must be 0 → perfect balance).

**Standalone acceptance.**

- `balance_gate_accepts_balanced_tx` — random `(inputs, outputs, fee)`
  with `Σ in = Σ out + fee`, proof verifies.
- `balance_gate_rejects_unbalanced` — perturb any of the 13 values,
  verifier rejects.
- `balance_gate_rejects_overflow` — set inputs to values that
  individually pass range but whose sum overflows `u67`, caught by the
  top-carry assertion.

**Bench.** Same three-config bench as §3b-2.

**Size.** ~200 LOC + ~200 LOC tests (small because it rides on §3b-2).
1–2 days.

### 3b-4 — Composition into `TxValidityAir` (non-Poseidon half)

Compose `BoolGate` + `WeightedLinearGate` + `SelectorGate` + §Range +
§Balance into the first real `TxValidityAir` subset: all non-Poseidon
gates wired, all Poseidon sub-circuits stubbed with free variables.
Proves nothing crypto-meaningful yet, but ensures the composite-AIR
column layout is nailed down before §3c doubles the column count.

**Acceptance.** End-to-end `prove_air` → `verify_air` on a single
synthetic tx (1 in / 1 out, correct balance, bit-decompositions
honest); standalone gate tests all remain green.

---

## Stage 3c — Poseidon gate library

Gates for `H_ADDR`, `H_AUTH`, `H_LEAF`, `TxBodyMerkle`. Each shipped
as a standalone `*Air` with forgery coverage before composition, same
pattern as §3b.

- **3c-1** `PoseidonInstanceBuilder` + RC/Sbox/MDS gates as first-class
  primitives on the post-3b-0 bus.
- **3c-2** `HAddrAir` — 2-field sponge, standalone tests.
- **3c-3** `HAuthAir` — 4-field sponge.
- **3c-4** `HLeafAir` — 3-absorb UTXO leaf hash.
- **3c-5** `TxBodyMerkleAir` — depth-4 tree + wrap.

Targets and exact constraint counts written up when §3b-4 closes and
we know the remaining column budget at `log_rows = 16`.

---

## Stage 3d — `TxValidityAir` (full composition)

Fold §3c gates into the §3b-4 skeleton + add `ConstColumnGate` for
verifier-side public-input binding (`is_reset`, `is_final`, bit-position
programme columns, etc.). First honest `TxValidityAir` end-to-end.

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
