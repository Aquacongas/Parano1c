# GKR Sub-Protocol — Implementation Specification (FROST-GKR / Kill-Shot)

This document describes what the `noid_gkr` crate **is** and how it
integrates with the STARK, as the code currently stands. It is a
specification, not a plan: every section reflects the shipped
implementation. Cross-references are to paths inside this workspace.

The production protocol is **FROST-GKR** (Frobenius Reduction Over
Shifted Tables), internally dubbed **Kill-Shot**. It proves both
the 59-permutation tx-body spine and the 20-slot auth circuit via
unified degree-7 sumchecks + shift arguments, replacing the former
per-slot PermProof chain entirely.

---

## 1. What GKR proves

Two sub-circuits, both using the Kill-Shot protocol:

### 1.1 Spine (tx-body Merkle hash)

The cut is at the tx-body Poseidon2b Merkle spine. The spine is a
deterministic circuit that consumes tx-body public data and emits a
single 2-lane digest — `tx_body_hash` — that the STARK binds through
`TxBodyMerkleBoundaryPins::tx_body_hash`.

**Inputs** — `SpineInputs`, `noid_gkr/src/circuit.rs`:

| Field | Shape | Role |
|---|---|---|
| `prev_state_root` | `[Block128; 2]` | Tree leaf L0 |
| `fee_leaf` | `[Block128; 2]` | Tree leaf L1 (encoding of `fee`) |
| `input_leaves` | `[[Block128; 4]; 4]` | Tree leaves L2..L5 |
| `output_leaves` | `[[Block128; 4]; 8]` | Tree leaves L6..L13 |
| `is_coinbase_leaf` | `[Block128; 2]` | Tree leaf L14 |
| `pad_leaf` | `[Block128; 2]` | Tree leaf L15 (currently `[0, 0]`) |

**Output** — two lanes of the wrap permutation's `state_out`, read
as `tx_body_hash`.

**Topology** — `N_INSTANCES = 59` permutation slots = 4 input
leaves + 8 output leaves + 15 compress nodes + 1 wrap. Read from
`noid_air::airs::tx_body_merkle::layout::build_instance_layout()`.

### 1.2 Auth (HAddr + HAuth per input)

The auth circuit proves ownership authentication for up to 4
inputs. Each input requires 5 Poseidon2b sponges (HAddr + HAuth
chain), yielding 20 slots total.

**Inputs** — `AuthInputs`, `noid_gkr/src/auth_circuit.rs`:

| Field | Shape | Role |
|---|---|---|
| `spend_secret` | `[Block128; 4]` | Per-input secret (witness only) |
| `tx_body_hash` | `[Block128; 2]` | Binds auth to the tx body |
| `expected_address` | `[[Block128; 2]; 4]` | Expected Address digest |
| `expected_auth_tag` | `[[Block128; 2]; 4]` | Expected AuthTag digest |

**Output** — per-input `(Address, AuthTag)` pairs, equality-checked
against the expected values.

**Privacy invariant**: `spend_secret` is never absorbed into the
transcript. Only public inputs seed the channel.

---

## 2. Crate layout (`noid_gkr`)

### 2.1 Kill-Shot modules (production path)

| Module | Purpose |
|---|---|
| `circuit.rs` | Static 59-slot spine topology (`SpineCircuit`, `SpineInputs`, `SlotDescriptor`). |
| `auth_circuit.rs` | Static 20-slot auth topology (`AuthCircuit`, `AuthInputs`). |
| `oracle.rs` | Spine reference execution: `evaluate_spine(circuit, inputs) -> SpineWitness`. |
| `auth_oracle.rs` | Auth reference execution. |
| `layers.rs` | Layered witness for one permutation: columns `state / sin / sout` across 67 rows x 4 lanes. |
| `mle_layout.rs` | MLE packing. `N_PERM_VARS = 9`, cells = 512 per slot. |
| `spine_mle.rs` | Spine-wide MLE construction: 15-var unified hypercube (`state`, `s_in`, `s_out` columns). |
| `auth_mle_v2.rs` | Auth-wide MLE construction: 14-var unified hypercube. |
| `spine_unified.rs` | Unified degree-7 sumcheck over all 59 spine slots. |
| `spine_degree7.rs` | Degree-7 round polynomial evaluator (Frobenius-based). |
| `auth_unified_v2.rs` | Unified degree-7 sumcheck over all 20 auth slots. |
| `spine_shift.rs` | Shift Gadget for spine: proves `state(x) == s_in(x XOR 1)`. |
| `auth_shift.rs` | Shift Gadget for auth. |
| `spine_killshot.rs` | Kill-Shot orchestrator (spine): unified + shift + 3x batch-eval -> `SpineProofKillShot`. |
| `auth_killshot.rs` | Kill-Shot orchestrator (auth): unified + shift + 3x batch-eval -> `AuthProofKillShot`. |
| `batch_eval.rs` | Gamma-2 primitive: RLC + degree-2 sumcheck collapses M claims into `(r_B, v_B)`. |
| `binding.rs` | Pure contract: `BindingCut` names the STARK-GKR cut in code. |

### 2.2 Legacy modules (retained for tests / reference)

| Module | Purpose |
|---|---|
| `product_sumcheck.rs` | Degree-3 product sumcheck primitive (used by batch-eval). |
| `perm_sumcheck.rs` | Former per-slot PermProof chain. Retained for differential testing; NOT used in production. |
| `spine_sumcheck.rs` | Former 59-slot orchestrator. NOT used in production (`prove_tx` calls Kill-Shot). |
| `auth_sumcheck.rs` | Former auth orchestrator. NOT used in production. |

---

## 3. FROST-GKR protocol (Kill-Shot)

### 3.1 Key insight: Frobenius eliminates degree-2 decomposition

In GF(2^128), squaring is a linear operation (Frobenius
endomorphism). Computing `x^7 = x * x^2 * x^4` requires only 3
multiplications and 2 free linear squarings. This makes the degree-7
S-box constraint directly provable without decomposing into four
degree-2 layers.

The legacy approach required per-slot: 5 product sumchecks (for
`x2 = sin*sin`, `x4 = x2*x2`, `x3 = x2*sin`, `sout = x4*x3`) + 3
sin-expansion sumchecks = 8 sumchecks per slot x 59 slots = 472
sumchecks total (4,248 FS rounds).

Kill-Shot: 1 unified sumcheck (15 rounds) + 1 shift (15 rounds) = 30
FS rounds total. Over 140x reduction.

### 3.2 MLE layout

The unified hypercube for the spine uses 15 variables:
`x = slot:6 || round:7 || elem:2`. Three column MLEs are maintained:

- `state(x)` — the permutation state after MDS application
- `s_in(x)` — the S-box input (state + round constant)
- `s_out(x)` — the S-box output

For auth: 14 variables (fewer slots, same round/elem structure).

### 3.3 Constraints

The Kill-Shot proves three families of constraints over the unified
MLE:

1. **S-box (degree 7)**: `active(x) * (s_out(x) - s_in(x)^7) +
   (1 - active(x)) * (s_out(x) - s_in(x)) = 0`

2. **Round constant**: `s_in(x) - state(x) - RC(x) = 0`

3. **MDS transition (shift)**: `state(inc(x)) - MDS(s_out(x)) = 0`

Constraint 3 involves `inc(x)` which is degree-7 in the bits of x.
Rather than evaluate at a non-linear point, the protocol uses a
**Change of Variable**: run the sumcheck over `y = inc(x)` with
shifted tables, then prove consistency via the Shift Gadget.

### 3.4 Unified sumcheck

The main sumcheck proves:

```
  sum_y U(y) * [C1(dec(y)) + rho * C1'(dec(y)) + rho^2 * C2(y)] = 0
```

where `U(y) = eq(beta, dec(y)) * delta(dec(y))` is the weight
function. All constraints are evaluated using shifted/materialized
tables. The degree over `y` is 7 (from `s_in^7`), yielding a round
polynomial of degree at most 9 with 10 coefficients per round.

With 15 variables (spine) or 14 variables (auth), this is **one**
sumcheck of 15 or 14 rounds.

### 3.5 Shift Gadget

After the unified sumcheck, we have claims on shifted tables (e.g.,
`state_inc(r')`). We must prove these equal the original MLE at the
shifted point: `state_inc(r') = sum_x eq(r', inc(x)) * state(x)`.

Since `inc(x)` is degree-7 in x, `eq(r', inc(x))` is degree-7. The
Shift Gadget is a sumcheck of degree 8 over 15 (or 14) rounds. It
operates on a single MLE (not 23 tables), so it is cheap.

It reduces the shifted claim to a single point opening `state(r'')`.

### 3.6 Batch-eval reductions

After unified + shift, we have claims on three columns at various
points:

```
  column     claims
  --------   --------
  state      state(r'), state(r'')
  s_in       s_in(r'')
  s_out      s_out(r'')
```

Each column is reduced via `batch_eval` (RLC + degree-2 sumcheck) to
a single `(r_B, v_B)` pair. The `state` column's `(r_B, v_B)` is
the one committed by the STARK boundary MLE and opened via FRI.

### 3.7 Transcript order

**Spine** (`spine_killshot.rs`):
1. Absorb `claimed_tx_body_hash`.
2. Absorb spine inputs header.
3. Run unified sumcheck (squeezes rho, beta, gamma; 15 round polys;
   12 final witness scalars).
4. Run shift (squeezes delta; 15 round polys; 3 final scalars).
5. `batch_eval` on `state` with claims `(r', state_at_r)` and
   `(r'', state_at_r2)`.
6. `batch_eval` on `s_in` with claim `(r'', s_in_at_r2)`.
7. `batch_eval` on `s_out` with claim `(r'', s_out_at_r2)`.

**Auth** (`auth_killshot.rs`):
1. Absorb `tx_body_hash`.
2. For each `i in 0..4`: absorb `expected_address[i]` then
   `expected_auth_tag[i]`.
3. Run unified sumcheck (14 round polys).
4. Run shift (14 round polys).
5. `batch_eval` on `state` with claims `(r', state_at_r)`,
   `(r'', state_at_r2)`, plus per-input `(Address, AuthTag)` output
   pin claims.
6. `batch_eval` on `s_in`.
7. `batch_eval` on `s_out`.

---

## 4. Soundness profile

- Unified sumcheck: degree-9 round polynomial over GF(2^128). Per-
  round error <= 9 / 2^128. Over 15 rounds: 135 / 2^128.
- Shift Gadget: degree-2 round polynomial. Per-round error <=
  2 / 2^128. Over 15 rounds: 30 / 2^128.
- Batch-eval: degree-2, 15 rounds each, 3 columns: 90 / 2^128.
- Total soundness error per sub-proof: ~ 255 / 2^128 ~ 2^-120.
- The wrap-digest pin and auth output pins are deterministic equality
  checks, not probabilistic.

Combined system soundness (all components):
- FRI proximity: 128 bits (64 queries x 2 bits, rate 1/4).
- Poseidon2b collision resistance: 128 bits (256-bit capacity).
- Overall system: ~120 bits (bottleneck = sumcheck error).

Compared to the legacy protocol (4,248 rounds x 3/2^128 ~= 12,744 /
2^128), Kill-Shot has **lower total soundness error** because it uses
far fewer rounds despite higher per-round degree.

---

## 5. STARK <-> GKR binding

### 5.1 Single transcript

Everything runs under one `Poseidon2bChannel`. No parallel or forked
channel exists inside any Kill-Shot module. The boundary-MLE FRI
opening uses a fresh `noid_fri::Channel` whose bytes are re-absorbed
into the shared channel via the extras hook.

**Absorb order** (in `noid_stark::prove_tx`):
1. Spine Kill-Shot proof bytes (via `extra_transcript`).
2. Auth Kill-Shot proof bytes (via `extra_transcript`).
3. Both land between column-root absorption and the zero-check draw.

Any byte-level tamper forks the STARK challenges (`z`, `beta_j`,
multipoint beta, FRI queries).

### 5.2 Extras hook

The flattened `SpineProofKillShot` + `AuthProofKillShot` bytes are fed
into the STARK's `extra_transcript` hook between column-root
absorption and the zero-check point draw. Ordering: spine first, auth
second.

### 5.3 The 2-lane output pin (spine)

- **GKR side**: `spine_killshot.rs` rejects if wrap's `state_out[0..1]
  != claimed_tx_body_hash`.
- **STARK side**: `TxBodyMerkleBoundaryPins::tx_body_hash` is pinned
  row-wide as a `PublicColumn`.

### 5.4 Auth output pins

- **GKR side**: `auth_killshot.rs` verifies `state_out` at the HAddr
  and HAuth final slots match `expected_address[i]` and
  `expected_auth_tag[i]` via additional `EvalClaim`s on the `state`
  column at boolean hypercube points.
- **STARK side**: These values flow into `TxValidityCols` pins.

### 5.5 Boundary commitment

The spine boundary MLE `B = state` (2^15 cells, 15-var) is committed
via FRI. Its root is absorbed into the spine channel before `r_B` is
drawn. The auth boundary MLE (2^14 cells, 14-var) follows the same
pattern.

---

## 6. End-to-end workflow

### 6.1 Prove (`noid_stark::prove_tx`)

```
 SpineInputs + AuthInputs
         |
         v
 +-------------------------------------------+
 | oracle::evaluate_spine -> SpineWitness    |
 | auth_oracle::evaluate_auth -> AuthWitness |
 +-------------------------------------------+
         |
         v
 +----------------------------------------------------+
 | spine_killshot::prove_spine_killshot               |
 |   absorb(claimed_tx_body_hash)                    |
 |   build unified MLE (state, s_in, s_out)          |
 |   prove_spine_unified (1 sumcheck, 15 rounds)     |
 |   prove_spine_shift (1 sumcheck, 15 rounds)       |
 |   3x prove_batch_eval (state, s_in, s_out)        |
 |   assert wrap.state_out[0..1] == tx_body_hash     |
 |   -> (SpineProofKillShot, (r_B, v_B))             |
 +----------------------------------------------------+
         |
         v
 +----------------------------------------------------+
 | auth_killshot::prove_auth_killshot                 |
 |   absorb(tx_body_hash, expected_address/auth_tag) |
 |   build unified MLE (14-var)                      |
 |   prove_auth_unified (1 sumcheck, 14 rounds)      |
 |   prove_auth_shift (1 sumcheck, 14 rounds)        |
 |   3x prove_batch_eval + output pin claims         |
 |   -> (AuthProofKillShot, (r_B, v_B))              |
 +----------------------------------------------------+
         |
         v
 +----------------------------------------------------+
 | STARK prover (noid_stark)                         |
 |   commit columns                                  |
 |   absorb column roots                             |
 |   extra_transcript = spine_ks_bytes || auth_ks_bytes|
 |   draw zero-check point                           |
 |   FRI on all columns + boundary MLEs              |
 |   open (r_B, v_B) for spine and auth boundaries   |
 +----------------------------------------------------+
```

### 6.2 Verify (`noid_stark::verify_tx`)

```
 +----------------------------------------------------+
 | spine_killshot::verify_spine_killshot              |
 |   absorb(claimed_tx_body_hash)                    |
 |   verify unified sumcheck (15 rounds)             |
 |   verify shift (15 rounds)                        |
 |   3x verify_batch_eval                            |
 |   assert wrap output == tx_body_hash              |
 |   -> Some((r_B, v_B)) or None                     |
 +----------------------------------------------------+
         |
         v
 +----------------------------------------------------+
 | auth_killshot::verify_auth_killshot                |
 |   absorb(tx_body_hash, expected_address/auth_tag) |
 |   verify unified sumcheck (14 rounds)             |
 |   verify shift (14 rounds)                        |
 |   3x verify_batch_eval + output pin checks        |
 |   -> Some((r_B, v_B)) or None                     |
 +----------------------------------------------------+
         |
         v
 +----------------------------------------------------+
 | STARK verifier (noid_stark)                       |
 |   mirror column-root absorption                   |
 |   extra_transcript = ks_bytes                     |
 |   mirror zero-check draw                          |
 |   FRI-open (r_B, v_B) for both boundaries         |
 |   verify PublicColumn pins                        |
 +----------------------------------------------------+
```

### 6.3 Failure modes

| Attack | Detected by |
|---|---|
| Wrong `claimed_tx_body_hash` | Wrap-digest equality; STARK `PublicColumn` pin mismatch |
| Tampered `state_in` lane | Boundary MLE evaluation at `r_B` disagrees; FRI opening fails |
| Wrong slot ordering | Slot bits in MLE layout change; boundary cell wrong |
| Wrong IV for a slot role | Produces wrong `state_in`; boundary cell wrong |
| Unified sumcheck round-poly tamper | Degree check or claim sum fails |
| Shift Gadget tamper | Shifted claim != original MLE claim |
| Auth secret tamper | Output pins (Address, AuthTag) won't match expected |
| GKR proof-byte tamper | STARK transcript fork: z, beta, gamma, FRI queries all move |
| Boundary commitment root tamper | `r_B` forks; opening check fails |

---

## 7. Performance

| Metric | Legacy (degree-2) | Kill-Shot | Improvement |
|---|---|---|---|
| FS rounds (spine) | 4,248 | 30 | 141x |
| Proof size (spine) | > 280 KB | ~5.4 KB | > 50x |
| Prover time | 1.63 s | 154 ms | 10.5x |
| Verifier time | 1.06 s | 69 ms | 15.3x |

Auth Kill-Shot follows the same pattern at reduced scale (20 slots,
14-var MLE).

---

## 8. Test coverage

`noid_gkr/tests/`:

| File | What it locks |
|---|---|
| `spine_killshot_vs_native.rs` | Kill-Shot spine proof/verify matches oracle; mutation rejection |
| `auth_killshot_vs_native.rs` | Kill-Shot auth proof/verify matches oracle; privacy invariant |
| `differential_vs_native.rs` | Oracle == `hash_tx_body` native; coinbase flag; wrap role; slot count = 59 |
| `layered_witness.rs` | MDS schedule, S-box, partial-round kill, round-kind vector |
| `mle_layout.rs` | Hypercube round-trip, packing determinism |
| `product_sumcheck.rs` | Honest + mutations + transcript determinism |
| `perm_sumcheck.rs` | Legacy per-slot (retained for differential reference) |
| `spine_sumcheck.rs` | Legacy orchestrator (retained for differential reference) |
| `spine_uses_layers.rs` | Layered evaluator = permute_mut on full spine |
| `fuzz_spine.rs` | N random fixtures (default 1024, `GKR_FUZZ_ITERS`) |
| `transcript_vectors.rs` | 5 fixtures x byte-determinism + distinct fingerprints |

STARK integration:
- `noid_air/tests/tx_body_hash_air_matches_native.rs` — three-way lock
- `noid_air/tests/input_binding_end_to_end.rs`,
  `output_binding_end_to_end.rs` — leaf-side PublicColumn pins
- `noid_stark/tests/stage_5_7_roundtrip.rs` — full composite prove /
  verify with Kill-Shot path

---

## 9. Safety summary

1. **Single root proof**: STARK remains the root; Kill-Shot proofs are
   absorbed into the STARK transcript via extras hook. One proof object.
2. **`tx_body_hash` is the binding cell** (spine): both paths agree on
   the same two lanes; the STARK `PublicColumn` pin is authoritative.
3. **Auth outputs are equality-bound**: Address and AuthTag at output
   slots are pinned via `EvalClaim`s on the state boundary.
4. **One Fiat-Shamir transcript**: no forked channel inside any module.
5. **Differential coverage**: native oracle, GKR reconstruction, and
   in-circuit output are triple-locked across the test suite.
6. **No dead paths in production**: `prove_tx` / `verify_tx` call
   exclusively `prove_spine_killshot` / `verify_spine_killshot` and
   `prove_auth_killshot` / `verify_auth_killshot`. The legacy per-slot
   modules are retained only for reference testing.
7. **Privacy**: `spend_secret` never enters the transcript. Only public
   boundary values (expected_address, expected_auth_tag) are absorbed.
