# `noid_gkr` audit checklist

This document covers the soundness-critical surface of the GKR spine
sub-protocol and its bridge into the STARK. Every bullet is either
load-bearing — meaning a bug here breaks soundness silently — or a
review hook for the next person to re-verify.

## Scope and non-goals

The GKR track proves the 59 Poseidon2b permutations that compute
`tx_body_hash` from public tx-body payload. It does **not** prove the
HAuth / HAddr sponges; those stay in the STARK AIR because they touch
witness secrets.

The sub-protocol is the sole production path: there is no
`gkr-spine` cargo feature, and the former AIR-side 59-perm proving
block has been retired from the default STARK trace. The only
merkle-band cells surviving inside the STARK are the two `tx_body_hash`
lanes pinned via `PublicColumn`; everything else the merkle band used
to commit is now proven by this crate. The full workspace test-suite
exercises exactly this single path.

## Layer MLE derivations

1. The per-perm layered witness is produced by
   `layers::evaluate_permutation`. Every column (`state`, `sin`, `x2`,
   `x3`, `x4`, `sout`) is recorded per lane per round. 66 rounds, 4
   lanes, packed into `2^N_PERM_VARS` cells. Inactive rows zero-padded.
2. The S-box is decomposed into four degree-2 sub-layers:
   `x2 = sin·sin`, `x4 = x2·x2`, `x3 = x2·sin`, `sout = x4·x3`. This
   matches `poseidon_perm.rs` in `noid_air`. A mis-decomposition would
   silently accept wrong state values.
3. Round-constant and MDS coefficients are re-exported from
   `noid_poseidon2b::native::permutation`. **No duplication** — review
   must confirm there is no second copy of `ROUND_CONSTANTS`, `MDS_FULL`,
   or `MDS_PARTIAL` elsewhere in the workspace.
4. Partial-round schedule: 4 full at head, 58 partial in middle, 4 full
   at tail. S-box kill on lanes 1..3 during partial rounds. Covered by
   `tests/layered_witness.rs::partial_round_sbox_kill`.

## Sumcheck primitive (`product_sumcheck`)

1. Round polynomial degree = 3 (product `eq · A · B`). Each round
   ships four evaluations at `X ∈ {0,1,2,3}` (`RoundEvals::evals`, four
   `Block128`s). Audit should verify that no round emits fewer than
   four evaluations (a degree-drop would skip a check). Lagrange
   evaluation at the challenge uses `lagrange_at_0_1_2_3`.
2. Final identity: `claim = eq(r, r') · a · b`. The verifier must
   evaluate `eq` at the randomness derived across all rounds; any
   off-by-one on `r'` length breaks soundness.
3. Transcript determinism locked by
   `tests/product_sumcheck.rs::transcript_determinism`. Two identical
   invocations produce byte-equal proofs.
4. Mutation coverage: bumping the claim, flipping a middle round-poly
   coefficient, and running on a wrong claim point all reject.

## Per-perm chained reduction (`perm_sumcheck`)

1. Libra-style chaining. Each product gate is unplugged via
   `product_sumcheck`. Linear gates are rewritten in place; only the
   `eq` / `rc` MLEs get absorbed.
2. γ₁ contract: `verify_perm` **does not** reconstruct
   `state_mle` natively. Instead it returns three
   `(rs_i, state_val_i)` claims on the per-slot `state`-column MLE.
   These are discharged against the boundary commitment in γ₃, not
   inside `verify_perm`.
3. γ₄ contract: no raw `state_in` absorption. The whole boundary is
   bound through `(r_B, v_B)` — see the binding bridge section below.
4. Mutation coverage: flipping `state_out`, a middle-witness cell, a
   round-constant, or swapping `MDS_FULL`/`MDS_PARTIAL` on a partial
   round — all reject. See `tests/perm_sumcheck.rs`.

## Spine batching (`spine_sumcheck`)

1. RLC challenges are squeezed from the shared `Poseidon2bChannel`
   between `absorb_hash(output)` and the first outer sumcheck round.
   **Never** from a forked channel. Audit should grep for any
   `Poseidon2bChannel::new` inside `spine_sumcheck.rs`; there should be
   exactly one entry point.
2. The boundary MLE `B = ‖₅₉ state_i` concatenates every slot's
   `state_in` into `2^N_BOUNDARY_VARS` cells. Slot index bits are the
   high-order vars; within-slot bits are low-order. Any permutation of
   this convention between prover and verifier silently breaks the
   claim lift in `lift_claim`.
3. γ₂ reduces 177 per-slot claims to one `(r_B, v_B)`. The outer
   sumcheck's final check is `claim = Σ α_i · eq(lifted_i, r_B) · v_B`
   with `α_i` derived from the RLC challenges. Review must confirm the
   `α_i` ordering in `verify_spine_claims` matches the one in
   `prove_spine`.
4. Mutation coverage in `tests/spine_sumcheck.rs`: tampering with any
   `state_in` lane, the wrap output, a slot index, or the boundary
   value must reject.

## Binding bridge (STARK ⇄ GKR)

1. **Output tie**: the wrap output lanes equal the scalar at
   `TxBodyMerkleBoundaryPins::tx_body_hash`. The AIR side pins both
   lanes row-wide via `PublicColumn`. Any disagreement forks the public
   input and breaks both proofs.
2. **Boundary commitment**: `StarkProofWithSpine::boundary_commitment`
   is a `FriCommitment` over `B`. Its root is absorbed into the GKR
   channel **before** `r_B` is drawn. Any tamper on the commitment root
   forks `r_B` and the `(r_B, v_B)` opening fails.
3. **Extras hook**: `spine_proof_transcript` flattens every
   `ProductProof`'s round evaluations, the `(a_final, b_final)` pair
   for each slot, the boundary commitment root, and the opening bytes.
   This flattened vector is fed into the STARK's `extra_transcript`
   between column-root absorption and the zero-check point draw. Any
   byte-level tamper in the spine proof forks `z`, `β_j`, γ_s, the
   multipoint β, and every FRI query. Audit should verify the ordering
   constraint in `prove_air_unchecked_with_extra`: extras land after
   column roots and before the zero-check draw, never elsewhere.
4. **Public surface**: the public-column slot for `tx_body_hash` is
   the same under both feature configs. Cross-feature fixture tests
   (`stage_5_7_roundtrip.rs`, `tx_body_hash_air_matches_native.rs`,
   `input_binding_end_to_end.rs`, `output_binding_end_to_end.rs`) must
   produce byte-equal `tx_body_hash` across both paths.

## Transcript canonicity

1. Single `Poseidon2bChannel` across STARK + GKR. No parallel channel
   is constructed inside `spine_sumcheck`, `perm_sumcheck`, or
   `product_sumcheck`. The boundary-open call uses a fresh
   `noid_fri::Channel` — that is the only exception, and it lives
   entirely under the extras digest so the STARK still sees every byte.
2. Absorb ordering is fixed: output lanes → RLC challenges → outer
   sumcheck rounds → per-slot perm sumcheck proofs → boundary
   commitment root → `r_B` → opening. Any re-ordering changes proofs
   and invalidates the locked test vectors.

## Re-ordering / role-confusion attacks

1. Swapping two slots in the spine changes the slot index bits used in
   `lift_claim`. `SpineCircuit::build` is a compile-time constant;
   review must grep for any runtime mutation of the slot order.
2. Feeding the wrong IV for a slot's role (e.g. `TAG_LEAF` for a
   compress slot) produces a wrong `state_in` for that slot. The
   boundary MLE sees the wrong value; the opening at `r_B` fails.
3. Feeding the wrong tx-body payload at a leaf slot produces a wrong
   digest at the wrap output; the output pin on `tx_body_hash` breaks.

## Test coverage matrix

| area | file | covers |
|---|---|---|
| layer witness | `tests/layered_witness.rs` | MDS schedule, S-box decomposition, partial-round kill, round-kind vector |
| MLE packing | `tests/mle_layout.rs` | hypercube roundtrip, packing determinism |
| primitive | `tests/product_sumcheck.rs` | honest + 3 mutations + transcript determinism |
| per-perm | `tests/perm_sumcheck.rs` | honest + 4 mutations + transcript determinism |
| spine | `tests/spine_sumcheck.rs` | honest + 3+ mutations + transcript determinism |
| G0 differential | `tests/differential_vs_native.rs` | oracle = native, coinbase flag, wrap role |
| cross-check | `tests/spine_uses_layers.rs` | layered evaluator = permute_mut on full spine |
| fuzz | `tests/fuzz_spine.rs` | N random fixtures (default 1024, `GKR_FUZZ_ITERS` env raises to 10 000) |
| transcript vectors | `tests/transcript_vectors.rs` | 5 fixtures × (byte-determinism across runs, pairwise-distinct fingerprints, constant `byte_len`) |
