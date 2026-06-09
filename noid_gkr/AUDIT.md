# `noid_gkr` audit checklist (FROST-GKR / Kill-Shot)

This document covers the soundness-critical surface of the GKR
sub-protocol (Kill-Shot) and its bridge into the STARK. Every bullet
is either load-bearing — meaning a bug here breaks soundness silently
— or a review hook for the next person to re-verify.

## Scope

The GKR track proves:

1. **Spine**: 59 Poseidon2b permutations computing `tx_body_hash`
   from public tx-body payload.
2. **Auth**: 20 Poseidon2b sponges (4 inputs x 5 sponges) computing
   `(Address, AuthTag)` per input from `spend_secret` + `tx_body_hash`.

Both use the Kill-Shot protocol: a single unified degree-7 sumcheck +
a Shift Gadget + 3x batch-eval reductions. This is the sole
production path.

## Non-goals

- The Kill-Shot does NOT prove the in-AIR linear constraints
  (balance_gate, range_gate, fri_state_open, tx_validity). Those stay
  in the STARK trace.
- Privacy: `spend_secret` is witness-only and never enters the Fiat-
  Shamir transcript. Only public expected outputs are absorbed.

---

## Unified degree-7 sumcheck

### Frobenius-based S-box evaluation

1. In GF(2^128), `sq(x) = x^2` is F2-linear. Computing `x^7 =
   x * x^2 * x^4` needs 3 multiplications + 2 free squarings.
   Review must verify that `spine_degree7.rs` does NOT use any
   intermediate `x2/x3/x4` columns — it evaluates `s_in^7` directly.
2. The round polynomial has degree 9 (7 from `s_in^7` * eq * weight
   contributions). Each round ships 10 coefficients. Review must
   verify that no round emits fewer than 10 values.
3. The `active` selector distinguishes full S-box rounds from partial
   rounds (only lane 0 active in internal rounds). A mis-configured
   selector would silently accept wrong state for lanes 1..3 in
   partial rounds.

### Change of Variable (CoV)

1. The MDS constraint `state(inc(x)) = MDS(s_out(x))` involves
   `inc(x)` which is degree-7 in x. Instead of evaluating at a
   non-linear point in the hot loop, the unified sumcheck runs over
   `y = inc(x)` with pre-materialized shifted tables (`state_inc`,
   `s_in_dec`, `s_out_dec`, `active_dec`).
2. Review must confirm that `state_inc[i] = state[inc_map[i]]` where
   `inc_map` is the increment-by-one map over the round bits only
   (not slot or element bits).

### RLC combination

1. Three constraint families (S-box, RC, MDS) are combined via
   powers of `rho` squeezed from the channel. Review must confirm
   `rho` is drawn BEFORE any round polynomial coefficients are
   absorbed.
2. The weight `U(y) = eq(beta, dec(y)) * delta(dec(y))` includes the
   eq polynomial for random combination across the hypercube. `beta`
   is drawn after `rho`.

---

## Shift Gadget

1. After the unified sumcheck, we have claims on shifted tables (e.g.,
   `state_inc(r')`). The Shift Gadget proves:
   `state_inc(r') = sum_x eq(r', inc(x)) * state(x)`
2. `eq(r', inc(x))` has degree 7 in x. Multiplied by the multilinear
   `state(x)`, this is a degree-8 sumcheck over 15 (or 14) rounds.
3. The Shift Gadget operates on a SINGLE column MLE, not all 23
   tables. This is what makes it cheap.
4. It reduces the shifted claim to a single point opening `state(r'')`.
   Review must confirm `r''` is the randomness vector produced by the
   shift sumcheck rounds.

---

## Batch-eval reductions

1. After unified + shift, claims exist on 3 columns at multiple
   points:
   - `state`: `state(r')` and `state(r'')`
   - `s_in`: `s_in(r'')`
   - `s_out`: `s_out(r'')`
   (For auth: additional `EvalClaim`s from output pins on `state`.)
2. Each column is reduced via `batch_eval` (RLC + degree-2 sumcheck)
   to one `(r_B, v_B)`. Review must confirm the RLC challenge `gamma`
   is drawn from the channel BEFORE the batch-eval sumcheck runs.
3. The `state` column's `(r_B, v_B)` is committed by the STARK
   boundary MLE and opened via FRI. The `s_in` and `s_out` reductions
   are discharged natively by the verifier against the materialized
   MLEs.

---

## Binding bridge (STARK <-> GKR)

### Output ties

1. **Spine**: wrap output lanes == `TxBodyMerkleBoundaryPins::
   tx_body_hash`. The AIR pins both lanes row-wide via `PublicColumn`.
2. **Auth**: per-input `(Address, AuthTag)` output claims are included
   as additional `EvalClaim`s on the `state` column at boolean
   hypercube points. These flow into `TxValidityCols`.

### Boundary commitment

1. `StarkProofWithSpine::boundary_commitment` is a `FriCommitment`
   over the spine `state` MLE (2^15 cells). Its root is absorbed into
   the GKR channel BEFORE `r_B` is drawn. Tamper on the root forks
   `r_B` and the `(r_B, v_B)` opening fails.
2. Auth boundary follows the same pattern (2^14 cells).

### Extras hook

1. `SpineProofKillShot` bytes + `AuthProofKillShot` bytes are fed into
   the STARK's `extra_transcript` between column-root absorption and
   the zero-check point draw (spine first, auth second).
2. Any byte-level tamper forks `z`, `beta_j`, `gamma_s`, multipoint
   beta, and every FRI query on the STARK side.
3. Audit must verify: extras land AFTER column roots and BEFORE the
   zero-check draw. Never elsewhere.

### Public surface

The public-column slot for `tx_body_hash` is the same under all
configurations. Cross-fixture tests (`stage_5_7_roundtrip.rs`,
`tx_body_hash_air_matches_native.rs`, `input_binding_end_to_end.rs`,
`output_binding_end_to_end.rs`) must produce byte-equal values.

---

## Transcript canonicity

1. Single `Poseidon2bChannel` across STARK + both Kill-Shot proofs. No
   parallel channel is constructed inside `spine_killshot`,
   `auth_killshot`, `spine_unified`, `auth_unified_v2`, or
   `spine_shift` / `auth_shift`.
2. The boundary-open call uses a fresh `noid_fri::Channel` — the only
   exception. It lives entirely under the extras digest so the STARK
   still sees every byte.
3. Absorb ordering is fixed and load-bearing:
   - Spine: `tx_body_hash` -> `rho` -> `beta` -> unified round polys
     -> final scalars -> `delta` -> shift round polys -> shift final
     -> `gamma` -> batch-eval rounds -> boundary root -> `r_B` ->
     opening.
   - Auth: `tx_body_hash` -> expected outputs -> same unified/shift/
     batch pattern.
4. Any re-ordering invalidates transcript vectors; regression is caught
   by the integration tests in `spine_killshot_vs_native.rs` and
   `auth_killshot_vs_native.rs`.

---

## Re-ordering / role-confusion attacks

1. Swapping two slots in the spine changes the MLE layout and produces
   wrong boundary values. `SpineCircuit::build` is a compile-time
   constant; review must grep for any runtime mutation of slot order.
2. Feeding the wrong IV for a slot's role (e.g., `TAG_LEAF` for a
   compress slot) produces wrong `state_in`. The boundary MLE disagrees
   at `r_B`; opening fails.
3. Feeding wrong tx-body payload at a leaf produces wrong wrap output;
   the `tx_body_hash` pin breaks.
4. Auth: swapping inputs or providing wrong `spend_secret` produces
   wrong `(Address, AuthTag)`; the output pin `EvalClaim`s reject.

---

## Privacy audit (auth)

1. `spend_secret` values are used ONLY to build the auth witness MLEs
   (`state`, `s_in`, `s_out`). They are NEVER absorbed into the
   channel.
2. Only `tx_body_hash`, `expected_address[i]`, and
   `expected_auth_tag[i]` seed the transcript before sumcheck
   challenges are drawn.
3. The proof reveals only the sumcheck round polynomials and final
   scalar evaluations — these are randomized by the challenges and do
   not leak the secret input.
4. Review must confirm: no code path in `auth_killshot.rs` or
   `auth_unified_v2.rs` calls `channel.absorb()` on any `spend_secret`
   value.

---

## Test coverage matrix

| area | file | covers |
|---|---|
| Kill-Shot spine | `tests/spine_killshot_vs_native.rs` | honest proof/verify, mutations, transcript match |
| Kill-Shot auth | `tests/auth_killshot_vs_native.rs` | honest proof/verify, privacy invariant, output pin check |
| Kill-Shot Merkle | `tests/merkle_killshot_vs_native.rs` | honest proof/verify, depth 1/8/16, root/sibling tamper |
| layer witness | `tests/layered_witness.rs` | MDS schedule, S-box, partial-round kill |
| MLE packing | `tests/mle_layout.rs` | hypercube roundtrip, packing determinism |
| G0 differential | `tests/differential_vs_native.rs` | oracle = native hash, coinbase, wrap role |
| cross-check | `tests/spine_uses_layers.rs` | layered evaluator = permute_mut on full spine |
| fuzz | `tests/fuzz_spine.rs` | N random fixtures (default 1024) |

STARK integration:
- `noid_stark/tests/stage_5_7_roundtrip.rs` — full prove/verify with
  Kill-Shot path
- `noid_air/tests/tx_body_hash_air_matches_native.rs` — three-way lock
- `noid_air/tests/input_binding_end_to_end.rs`,
  `output_binding_end_to_end.rs` — leaf-side PublicColumn pins

---

## Summary of Kill-Shot vs legacy

| Dimension | Legacy (per-slot PermProof) | Kill-Shot |
|---|---|---|
| Sumchecks (spine) | 472 (8 per slot x 59) | 2 (unified + shift) |
| FS rounds (spine) | 4,248 | 30 |
| Proof size (spine) | > 280 KB | ~5.4 KB |
| Degree per round | 3 (degree-2 product) | 9 (degree-7 S-box) |
| S-box decomposition | 4 layers (x2, x3, x4, sout) | Direct via Frobenius |
| Witness columns | 6 per slot (state/sin/x2/x3/x4/sout) | 3 unified (state/s_in/s_out) |
| Production status | RETIRED (test-only) | SOLE production path |
