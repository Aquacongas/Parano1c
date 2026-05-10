# GKR Spine — Implementation Specification

This document describes what the `noid_gkr` crate **is** and how it
integrates with the STARK, as the code currently stands. It is a
specification, not a plan: every section reflects the shipped
implementation. Cross-references are to paths inside this workspace.

The goals of the original integration track (cut the 59-permutation
tx-body Poseidon2b spine out of the STARK trace, prove it with a GKR
sub-protocol, keep STARK as the single root proof) are achieved.

---

## 1. What GKR proves

The cut is at the tx-body Poseidon2b Merkle spine. The spine is a
deterministic layered circuit that consumes tx-body public data and
emits a single 2-lane digest — `tx_body_hash` — that the STARK binds
through `TxBodyMerkleBoundaryPins::tx_body_hash`.

**Inputs (boundary of the cut)** — `SpineInputs`,
`noid_gkr/src/circuit.rs:59-75`:

| Field | Shape | Role |
|---|---|---|
| `prev_state_root` | `[Block128; 2]` | Tree leaf L0 |
| `fee_leaf` | `[Block128; 2]` | Tree leaf L1 (encoding of `fee`) |
| `input_leaves` | `[[Block128; 4]; 4]` | Tree leaves L2..L5; each `[slot, value, owner_hi, owner_lo]` |
| `output_leaves` | `[[Block128; 4]; 8]` | Tree leaves L6..L13 |
| `is_coinbase_leaf` | `[Block128; 2]` | Tree leaf L14 |
| `pad_leaf` | `[Block128; 2]` | Tree leaf L15 (currently `[0, 0]`) |

**Output of the cut** — two lanes of the wrap permutation's
`state_out`, read as `tx_body_hash`.

**Topology** — post-order layout of
`noid_air::airs::tx_body_merkle::layout::build_instance_layout()`:
`N_INSTANCES = 59` permutation slots = 4 input leaves × 3 perms + 8
output leaves × 2 perms + 15 compress nodes × 2 perms + 1 wrap. The
topology is *read* from `noid_air` — it is never duplicated inside
`noid_gkr`. See `circuit.rs:16-20, 88`.

Slot classification carried on each `SlotDescriptor`
(`circuit.rs:29-53`):
`role` (from `InstanceRole`), `capacity_iv` (from
`noid_poseidon2b::native::domain::capacity_iv` for `TAG_LEAF` /
`TAG_OUTLEAF` / `TAG_COMPRESS` / `TAG_TXBODY`), `is_head`,
`prev_output_src`, `left_child`, `right_child`.

---

## 2. Crate layout (`noid_gkr`)

Eight modules, all public (`noid_gkr/src/lib.rs:14-43`):

| Module | Purpose |
|---|---|
| `circuit.rs` | Static 59-slot topology (`SpineCircuit`, `SpineInputs`, `SlotDescriptor`) read from the canonical `noid_air` layout. |
| `oracle.rs` | Reference execution: `evaluate_spine(circuit, inputs) -> SpineWitness`. Drives `noid_poseidon2b::native::permutation::Poseidon2bPermutation` slot-by-slot; produces `tx_body_hash`. |
| `layers.rs` | G1a layered witness for one permutation. `evaluate_permutation(state_in) -> PermLayerWitness` with columns `state / sin / x2 / x3 / x4 / sout` across 67 rows × 4 lanes. Column semantics match `noid_air::airs::poseidon_perm` exactly. |
| `mle_layout.rs` | Multilinear extension packing. `N_PERM_VARS = 9`, `N_PERM_CELLS = 512 = 2^9`. Index convention `(row << 2) | lane`. |
| `product_sumcheck.rs` | G1b.α primitive. Reduces `Σ_x eq(r, x) · A(x) · B(x) = claim` to `(A(r'), B(r'))`. Round polynomial degree 3; four coefficients per round. |
| `perm_sumcheck.rs` | G1b.β per-slot reduction. Eight `ProductProof`s per slot (five for the S-box chain `x² → x⁴ → x³ → sout`, three for sin-expansion). Reduces a claim on `sout(r)` to three claims on `state(rs_i)`. |
| `batch_eval.rs` | γ₂ primitive. Collapses `M` MLE point-value pairs into one `(r_B, v_B)` via RLC + degree-2 sumcheck (three coefficients per round). |
| `spine_sumcheck.rs` | Full spine orchestration. `prove_spine / verify_spine`. Walks the 59 slots in post-order, batches all `59 × 3 = 177` per-slot state claims into one boundary reduction. |
| `binding.rs` | Pure contract: `BindingCut { boundary_inputs, claimed_output }` names the cut in code. Used by tests and audit tooling. |

---

## 3. Layered arithmetisation

Each Poseidon2b permutation has 66 rounds: 4 full head + 58 partial +
4 full tail (`AUDIT.md:33-35`). The round update is
`state' = MDS · SBox(state + RC)` where `SBox(x) = x⁷`.

`layers::evaluate_permutation` decomposes the S-box into four
**degree-2** multiplications:

| Identity | Layer |
|---|---|
| `x2 = sin · sin` | degree 2 |
| `x4 = x2 · x2` | degree 2 |
| `x3 = x2 · sin` | degree 2 |
| `sout = x4 · x3` | degree 2 |

Partial rounds kill the S-box on lanes 1..3 (enforced identically to
`poseidon_perm.rs`; covered by
`noid_gkr/tests/layered_witness.rs::partial_round_sbox_kill`). Round
constants (`ROUND_CONSTANTS`), MDS_FULL, and MDS_PARTIAL are re-exported
from `noid_poseidon2b::native::permutation` with **no duplicated
copies** anywhere in the workspace (AUDIT.md:29-32).

MLE packing is `(row << 2) | lane` across 9 variables
(`mle_layout.rs:N_PERM_VARS = 9`); inactive rows zero-padded.

---

## 4. Sumcheck protocol

### 4.1 Per-slot (`perm_sumcheck`)

A `PermProof` for one slot contains eight `ProductProof`s. The chain,
in order the prover emits and the verifier consumes them, is:

1. `sout = x4 · x3` at random `r₀` → `(x4(r₁), x3(r₁))`
2. `x4 = x2 · x2` at `r₁` → `(x2(r₂), x2(r₂))`
3. `x3 = x2 · sin` at `r₁` → `(x2(r₃), sin(r₃))`
4. `x2 = sin · sin` at `r₂` → `(sin(r₄), sin(r₄))`
5. `x2 = sin · sin` at `r₃` → `(sin(r₅), sin(r₅))`

followed by three **sin-expansion** sumchecks that reduce
`sin(ρ) = Σ_x eq(ρ, x) · active(x) · (state(x) + rc(x))` to a claim
`(state(ρ'), B(ρ'))`. This is the γ₁ contract from AUDIT.md:56-60:
`verify_perm` does **not** reconstruct `state_mle` natively. It returns
three `PermStateClaim { point: [Block128; 9], value: Block128 }`
claims; those are carried upward and discharged by the spine layer.

Round polynomial degree is 3 (four evals per round); the verifier
checks the telescope identity `evals[0] + evals[1] == prev_claim` at
every round and the final identity `claim == eq(r, r') · a · b`
(AUDIT.md:42-44). `active` and `rc` MLEs are rebuilt from the
Poseidon2b round schedule via `build_active_mle` / `build_rc_mle`.

### 4.2 Full spine (`spine_sumcheck`)

`spine_sumcheck.rs:175-214` — `prove_spine`:

1. Absorb `claimed_tx_body_hash` (two lanes) into the shared channel
   (`spine_sumcheck.rs:189`).
2. Natively reconstruct each slot's `(state_in, state_out)` via
   `reconstruct_slot_states` (which delegates to `oracle::evaluate_spine`).
3. For each slot `s ∈ 0..59` in post-order: call `prove_perm` on
   `state_in`. Collect the three `PermStateClaim`s per slot.
4. **Lift** each per-slot claim to the concatenated boundary MLE `B`
   via `lift_claim(s, per_slot)` — the point becomes
   `per_slot.point ‖ slot_bits(s)` (inner 9 vars first, slot 6 vars on
   top), matching the layout `(s << N_PERM_VARS) | inner_idx`
   (`spine_sumcheck.rs:129-143`).
5. Batch all `59 · 3 = 177` lifted claims via `prove_batch_eval` into
   one `(r_B, v_B)` reduction on `B` of `N_BOUNDARY_VARS = 15`
   variables and `N_BOUNDARY_CELLS = 2^15 = 32768` cells.

`verify_spine` (`spine_sumcheck.rs:221-260`) mirrors the absorb order
exactly, runs `verify_perm` on each slot against the same natively
reconstructed `state_in`, batches via `verify_batch_eval`, and
**cross-checks** `wrap.state_out[0..1] == claimed_tx_body_hash`
(`spine_sumcheck.rs:253-257`). All three gates (per-slot reject,
boundary batch reject, wrap mismatch) fail the proof closed.

### 4.3 Soundness profile

- Product sumcheck: degree-3 round polynomial over `GF(2^128)` with
  Fiat-Shamir challenges drawn from the Poseidon2b channel. Soundness
  error per round is `3 / |F|` where `|F| = 2^128`.
- Batch-eval sumcheck: degree-2; per-round error `2 / |F|`.
- Per-slot: 8 products × ~9 rounds + 3 expansions × ~9 rounds ≈ 99
  rounds at error `3 / 2^128` each; per-slot error ≤ `3 · 99 / 2^128`.
- Full spine: 59 slots × per-slot error + boundary batch of 15 rounds
  at `2 / 2^128`. Total soundness error is dominated by the RLC + wrap
  pin and stays at roughly `O(60·100 / 2^128) ≪ 2^−100`.
- The wrap-digest pin itself is not probabilistic: it is an **equality
  check** against `claimed_tx_body_hash`, which is the same cell the
  STARK AIR pins through `PublicColumn`. Any disagreement rejects
  deterministically.

---

## 5. STARK ⇄ GKR binding

### 5.1 Single transcript

Everything runs under one `Poseidon2bChannel`
(`noid_poseidon2b/src/channel.rs`) — the same channel the outer STARK
uses. No parallel or forked channel exists inside any of
`spine_sumcheck`, `perm_sumcheck`, or `product_sumcheck`
(AUDIT.md:69-73, 115-119).

The only side-channel is the boundary-MLE FRI opening, which uses a
fresh `noid_fri::Channel` whose transcript bytes are then re-absorbed
into the shared Poseidon2b channel via the extras hook, so the STARK
still sees every byte (AUDIT.md:117-119).

**Absorb order** (`AUDIT.md:120-123`):

1. `claimed_tx_body_hash` — two lanes.
2. Per-slot sumcheck proofs (for each of 59 slots, eight products +
   three expansions).
3. RLC challenges for the boundary batch.
4. Boundary-MLE commitment root.
5. `r_B` drawn; boundary opening emitted.

Any reordering invalidates the locked transcript vectors
(`noid_gkr/tests/transcript_vectors.rs`).

### 5.2 Extras hook into the STARK

The flattened GKR proof — every `ProductProof`'s round evals, each
slot's `(a_final, b_final)` pair, the boundary commitment root, and the
opening bytes — is fed into the STARK's `extra_transcript` hook
**between column-root absorption and the zero-check point draw**
(AUDIT.md:98-106). That ordering is load-bearing: any byte-level tamper
in the spine proof forks `z`, `β_j`, `γ_s`, the multipoint β, and every
FRI query on the STARK side. The STARK thus inherits the soundness of
the GKR sub-protocol through transcript fork.

### 5.3 The 2-lane output pin

Both sides bind the same cell:

- **GKR side**: `spine_sumcheck.rs:253-257` rejects if
  `wrap.state_out[0..1] != claimed_tx_body_hash`.
- **STARK side**: `TxBodyMerkleBoundaryPins::tx_body_hash` is pinned
  row-wide as a `PublicColumn` on the two retained merkle-band lanes
  (`noid_air/src/airs/tx_body_spine.rs:341-348, 449-464`).

There is no cell outside this 2-lane surface where the spine
communicates with the STARK. The AIR now carries only those two
lanes — zero-filled except for the row-wide pins — of what used to be
the 192-column merkle band.

### 5.4 Boundary commitment

The concatenated boundary MLE `B = ‖₅₉ state_in` of 2^15 cells is
committed via FRI in the STARK (`AUDIT.md:94-97`). Its root is
absorbed into the spine channel **before** `r_B` is drawn; any
tamper on the commitment root forks `r_B` and the `(r_B, v_B)` opening
fails.

The slot-index bits are the **high-order** vars and the within-slot
bits are the **low-order** vars (`spine_sumcheck.rs:95-143`). This
convention must match on both sides; the unit test
`spine_sumcheck.rs::unit::compute_tx_body_hash_matches_oracle` pins it.

---

## 6. End-to-end workflow

### 6.1 Prove

```
                  +----------------------------+
 SpineInputs ---> | oracle::evaluate_spine     | --> SpineWitness
                  +----------------------------+           |
                                                           v
                                             tx_body_hash = wrap.state_out[0..1]
                                                           |
                                                           v
                          +-------------------------------------------+
 shared channel   <-----> | spine_sumcheck::prove_spine               |
 (Poseidon2b)             |   absorb(claimed_tx_body_hash)            |
                          |   for slot in 0..59:                      |
                          |     perm_sumcheck::prove_perm             |
                          |       (8 product sumchecks)               |
                          |     lift 3 claims → boundary MLE          |
                          |   batch_eval::prove_batch_eval            |
                          |   return (SpineProof, (r_B, v_B))         |
                          +-------------------------------------------+
                                                           |
                                                           v
                          +-------------------------------------------+
                          | STARK prover (noid_stark)                 |
                          |   commit columns                          |
                          |   absorb column roots                     |
                          |   extra_transcript = spine_proof_bytes    |
                          |   draw zero-check point                   |
                          |   ...FRI on all columns + boundary MLE    |
                          |   open (r_B, v_B) on boundary MLE         |
                          +-------------------------------------------+
```

### 6.2 Verify

```
                          +-------------------------------------------+
 shared channel   <-----> | spine_sumcheck::verify_spine              |
 (Poseidon2b)             |   absorb(claimed_tx_body_hash)            |
                          |   reconstruct_slot_states (native)        |
                          |   for slot in 0..59:                      |
                          |     perm_sumcheck::verify_perm            |
                          |   batch_eval::verify_batch_eval           |
                          |   assert wrap.state_out == hash           |
                          |   return Some((r_B, v_B)) or None         |
                          +-------------------------------------------+
                                                           |
                                                           v
                          +-------------------------------------------+
                          | STARK verifier (noid_stark)               |
                          |   mirror column-root absorption           |
                          |   extra_transcript = spine_proof_bytes    |
                          |   mirror zero-check draw                  |
                          |   FRI-open (r_B, v_B) on boundary MLE     |
                          |   verify PublicColumn pin on              |
                          |     TxBodyMerkleBoundaryPins::tx_body_hash|
                          +-------------------------------------------+
```

### 6.3 Failure modes

| Attack | Detected by |
|---|---|
| Wrong `claimed_tx_body_hash` | Wrap-digest equality (`spine_sumcheck.rs:255`); STARK `PublicColumn` pin mismatch |
| Tamper on any `state_in` lane | Native reconstruction diverges; boundary MLE evaluation at `r_B` disagrees; FRI opening fails |
| Tamper on slot ordering | Slot index bits in `lift_claim` change; boundary cell at `r_B` wrong |
| Wrong IV for a slot role | Native reconstruction produces wrong `state_in`; boundary cell wrong |
| Product-sumcheck round-poly tamper | Telescope identity fails on the flipped round |
| MDS or round-constant swap | `perm_sumcheck::verify_perm` fails at the slot's final identity |
| GKR proof-byte tamper | STARK transcript fork: `z`, `β_j`, multipoint β, FRI queries all move |
| Boundary commitment root tamper | `r_B` forks; opening check fails |

---

## 7. Test coverage

`noid_gkr/tests/` (cross-referenced in AUDIT.md §Test coverage matrix):

| File | What it locks |
|---|---|
| `differential_vs_native.rs` | Oracle ≡ `primitives::hash_tx_body` on canonical and mutated fixtures; coinbase flag propagation; wrap role uses `TAG_TXBODY`; slot count = 59 |
| `layered_witness.rs` | MDS schedule, S-box decomposition, partial-round kill, round-kind vector |
| `mle_layout.rs` | Hypercube round-trip, packing determinism |
| `product_sumcheck.rs` | Honest path + three mutations + transcript determinism |
| `perm_sumcheck.rs` | Honest + four mutations + transcript determinism |
| `spine_sumcheck.rs` | Honest + three+ mutations + transcript determinism |
| `spine_uses_layers.rs` | Layered evaluator produces the same `state_out` as `permute_mut` across the full spine |
| `fuzz_spine.rs` | `GKR_FUZZ_ITERS` random fixtures (default 1024, raise via env for CI) |
| `transcript_vectors.rs` | Five fixtures × (byte-determinism across runs, pairwise-distinct fingerprints, constant `byte_len`) |

The STARK-level integration is locked by:

- `noid_air/tests/tx_body_hash_air_matches_native.rs` — three-way
  lock: native Poseidon2b oracle ≡ GKR reconstruction ≡ in-circuit
  `tx_body_hash`.
- `noid_air/tests/input_binding_end_to_end.rs`,
  `output_binding_end_to_end.rs` — the leaf-side PublicColumn pins
  still close through the GKR path.
- `noid_stark/tests/stage_5_7_roundtrip.rs` — full composite prove /
  verify through `TxValidityCompositeWithSpine`.

---

## 8. Safety summary

The GKR spine integration holds the ground rules established at the
start of the track:

1. **Single root proof**: STARK remains the root; GKR is a sub-protocol
   whose bytes are absorbed into the STARK transcript via the extras
   hook, before the zero-check draw. There is one proof object.
2. **`tx_body_hash` is the binding cell**: both paths must agree on
   the same two lanes; the STARK `PublicColumn` pin is the
   authoritative surface.
3. **Equality-bound boundary**: wrap output is equality-checked, not
   reconstructed inside the sumcheck. No "trust me" handoff exists.
4. **One Fiat-Shamir transcript**: no forked `Poseidon2bChannel`
   inside any sumcheck module; boundary-MLE opening's fresh FRI
   channel is fully covered by the extras-hook absorption.
5. **Differential coverage**: `hash_tx_body` native oracle, GKR
   reconstruction, and in-circuit output are triple-locked across the
   test suite.
6. **No dead paths left**: the old AIR-spine has been removed from
   production builds, benchmarks, and the STARK test matrix; what
   remains of `tx_body_merkle` is the shared layout scaffolding
   needed by GKR and the two-lane PublicColumn pin.

There are no known soundness holes. Every attack vector in the
failure-modes table above is caught by at least one of: per-slot
sumcheck rejection, boundary-MLE opening rejection, wrap-digest
equality, STARK `PublicColumn` mismatch, or STARK transcript fork. The
audit document (`noid_gkr/AUDIT.md`) enumerates the review hooks; the
test matrix locks every one of them.
