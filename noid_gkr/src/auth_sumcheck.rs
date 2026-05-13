// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Step 1a — auth sumcheck: prove/verify the 20-slot per-input
//! HAddr/HAuth sponge stack in one transcript.
//!
//! Structurally a clone of [`crate::spine_sumcheck`], swapping the
//! 59-slot tx-body circuit for the 20-slot [`AuthCircuit`]. The
//! per-slot permutation sumcheck ([`crate::perm_sumcheck`]) and the
//! batch-eval boundary collapse ([`crate::batch_eval`]) are reused
//! verbatim — they are fully generic in the number of slots.
//!
//! ## Transcript order
//!
//! Both sides absorb, in this order:
//!
//! 1. `tx_body_hash` (2 lanes) — shared with the STARK side via the
//!    existing tx-body-hash pin.
//! 2. For `i ∈ 0..N_AUTH_INPUTS`: `expected_address[i]` (2 lanes) then
//!    `expected_auth_tag[i]` (2 lanes). These are the verifier's
//!    public boundary pins; absorbing them before any per-slot round
//!    folds every public claim into the sumcheck's random challenges.
//! 3. For each slot in post-order: invoke `prove_perm` / `verify_perm`
//!    on the reconstructed `state_in`.
//! 4. A single γ₂-style batch-eval sumcheck over the 20-slot
//!    concatenated boundary MLE collapses `20 × 3` per-slot `state`
//!    MLE claims into one `(r_B, v_B)`.
//!
//! ## Step-1a scope
//!
//! This file lands the internal auth-GKR scaffold only. The verifier
//! here accepts the full [`AuthInputs`] (including `spend_secret`) so
//! it can reconstruct each slot's `state_in`, exactly like
//! `verify_spine` today. The **production** verifier cannot be given
//! `spend_secret` — Step 1b wires this stack into the STARK transcript
//! and uses the γ₂ batching to deliver the head-slot `v₀` claims from
//! the outer boundary commitment, at which point `state_in` drops out
//! of the verifier's argument list. For now the secret stays a
//! function argument only; it never touches the Fiat–Shamir state.
//!
//! ## Boundary equality pins
//!
//! On accept, the verifier additionally cross-checks
//!
//!   - `slots[haddr_output_slot(i)].state_out[0..1] == expected_address[i]`
//!   - `slots[hauth_output_slot(i)].state_out[0..1] == expected_auth_tag[i]`
//!
//! for every `i`. Any mismatch rejects deterministically.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::STATE_SIZE;
use rayon::prelude::*;

use crate::auth_circuit::{AuthCircuit, AuthInputs, N_AUTH_INPUTS, N_AUTH_SLOTS};
use crate::auth_oracle::evaluate_auth;
use crate::batch_eval::{
    prove_batch_eval, verify_batch_eval, BatchEvalProof, BatchEvalReduction, EvalClaim,
};
use crate::layers::evaluate_permutation;
use crate::mle_layout::{PermMle, N_PERM_CELLS, N_PERM_VARS};
use crate::perm_sumcheck::{prove_perm_with_mle, verify_perm, PermProof, PermStateClaim};

/// Smallest power of two ≥ `N_AUTH_SLOTS`, used for zero-padding.
pub const N_AUTH_SLOTS_PADDED: usize = 32;

/// Slot-index variables. `log2(32) = 5`.
pub const N_AUTH_SLOT_VARS: usize = 5;

/// Column-selector variable: `c=0` addresses the `state` half of the
/// concatenated boundary MLE, `c=1` addresses the `sout` half.
pub const N_AUTH_COL_VARS: usize = 1;

/// Total variables in the concatenated auth-boundary MLE:
/// `N_PERM_VARS + N_AUTH_SLOT_VARS + N_AUTH_COL_VARS = 9 + 5 + 1 = 15`.
/// Variable order in `EvalClaim.point` is
/// `[per_perm_vars(9), slot_bits(5), c(1)]` (lowest first), which
/// matches the flat index `(c << 14) | (s << 9) | perm_idx`.
pub const N_AUTH_BOUNDARY_VARS: usize = N_PERM_VARS + N_AUTH_SLOT_VARS + N_AUTH_COL_VARS;

/// `2^N_AUTH_BOUNDARY_VARS` cells.
pub const N_AUTH_BOUNDARY_CELLS: usize = 1 << N_AUTH_BOUNDARY_VARS;

const _: () = assert!(N_AUTH_SLOTS_PADDED >= N_AUTH_SLOTS);
const _: () = assert!(N_AUTH_SLOTS_PADDED.is_power_of_two());

/// One proof object covering all 20 auth slots plus the batching
/// sumcheck on the concatenated boundary MLE.
///
/// γ₂-lift: `slot_v0[s] = sout_mle_s(r0_s)` is supplied by the prover.
/// A lying prover cannot forge these: every `slot_v0[s]` becomes a
/// claim inside the batch-eval sumcheck against the committed
/// boundary MLE `B`, and the reduction `(r_B, v_B)` is discharged
/// against the same `B`. Tampering therefore forks the sumcheck or
/// fails the final opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProof {
    pub slots: Vec<PermProof>,
    pub slot_v0: Vec<Block128>,
    pub boundary: BatchEvalProof,
}

impl AuthProof {
    pub fn byte_len(&self) -> usize {
        self.slots.iter().map(|p| p.byte_len()).sum::<usize>()
            + self.slot_v0.len() * core::mem::size_of::<Block128>()
            + self.boundary.byte_len()
    }
}

/// Build the concatenated auth-boundary MLE of length
/// `N_AUTH_BOUNDARY_CELLS = 2^15`. Slot `s ∈ 0..N_AUTH_SLOTS` occupies
/// indices `(s << N_PERM_VARS) .. ((s+1) << N_PERM_VARS)` within each
/// of the two columns (`state` at `c=0` half, `sout` at `c=1` half).
/// Padded slots are zero.
pub fn build_auth_boundary_mle(
    slot_states: &[([Block128; STATE_SIZE], [Block128; STATE_SIZE])],
) -> Vec<Block128> {
    debug_assert_eq!(slot_states.len(), N_AUTH_SLOTS);
    let mut b = vec![Block128::ZERO; N_AUTH_BOUNDARY_CELLS];
    let half = 1usize << (N_PERM_VARS + N_AUTH_SLOT_VARS);
    for (s, (state_in, _)) in slot_states.iter().enumerate() {
        let witness = evaluate_permutation(*state_in);
        let mle = PermMle::from_witness(&witness);
        debug_assert_eq!(mle.state.len(), N_PERM_CELLS);
        debug_assert_eq!(mle.sout.len(), N_PERM_CELLS);
        let offset = s << N_PERM_VARS;
        b[offset..offset + N_PERM_CELLS].copy_from_slice(&mle.state);
        b[half + offset..half + offset + N_PERM_CELLS].copy_from_slice(&mle.sout);
    }
    b
}

/// Prover-side fast path: use already-built [`PermMle`]s to assemble
/// the auth boundary MLE without re-running `evaluate_permutation` or
/// re-packing witness columns.
fn assemble_auth_boundary_mle(mles: &[PermMle]) -> Vec<Block128> {
    debug_assert_eq!(mles.len(), N_AUTH_SLOTS);
    let mut b = vec![Block128::ZERO; N_AUTH_BOUNDARY_CELLS];
    let half = 1usize << (N_PERM_VARS + N_AUTH_SLOT_VARS);
    for (s, m) in mles.iter().enumerate() {
        debug_assert_eq!(m.state.len(), N_PERM_CELLS);
        debug_assert_eq!(m.sout.len(), N_PERM_CELLS);
        let offset = s << N_PERM_VARS;
        b[offset..offset + N_PERM_CELLS].copy_from_slice(&m.state);
        b[half + offset..half + offset + N_PERM_CELLS].copy_from_slice(&m.sout);
    }
    b
}

fn slot_index_to_bits(s: usize) -> Vec<Block128> {
    let mut out = Vec::with_capacity(N_AUTH_SLOT_VARS);
    for i in 0..N_AUTH_SLOT_VARS {
        out.push(if (s >> i) & 1 == 1 {
            Block128::ONE
        } else {
            Block128::ZERO
        });
    }
    out
}

/// Lift a per-slot `state`-MLE claim to a boundary claim in the
/// `c=0` (state) half.
fn lift_state_claim(s: usize, per_slot: &PermStateClaim) -> EvalClaim {
    debug_assert_eq!(per_slot.point.len(), N_PERM_VARS);
    let mut point = Vec::with_capacity(N_AUTH_BOUNDARY_VARS);
    point.extend_from_slice(&per_slot.point);
    point.extend_from_slice(&slot_index_to_bits(s));
    point.push(Block128::ZERO); // c = 0 (state)
    EvalClaim {
        point,
        value: per_slot.value,
    }
}

/// Lift a per-slot `sout(r0) = v0` claim to a boundary claim in the
/// `c=1` (sout) half.
fn lift_sout_claim(s: usize, r0: &[Block128], v0: Block128) -> EvalClaim {
    debug_assert_eq!(r0.len(), N_PERM_VARS);
    let mut point = Vec::with_capacity(N_AUTH_BOUNDARY_VARS);
    point.extend_from_slice(r0);
    point.extend_from_slice(&slot_index_to_bits(s));
    point.push(Block128::ONE); // c = 1 (sout)
    EvalClaim { point, value: v0 }
}

/// Two output-digest lanes (high, low) per pin site.
pub const AUTH_PIN_LANES: usize = 2;

/// Flat index of a slot's output-digest lane inside the concatenated
/// auth-boundary MLE. The output digest lives in `state[N_ROUNDS]`
/// (not `sout`), so the cell sits in the `c = 0` half of the boundary.
/// Per-perm layout is `(row << 2) | lane`; slots stack every
/// `2^N_PERM_VARS` cells within the half.
#[inline]
pub fn auth_boundary_output_cell(slot: usize, lane: usize) -> usize {
    debug_assert!(slot < N_AUTH_SLOTS);
    debug_assert!(lane < AUTH_PIN_LANES);
    use noid_poseidon2b::native::permutation::N_ROUNDS;
    let perm_idx = (N_ROUNDS << 2) | lane;
    (slot << N_PERM_VARS) | perm_idx
}

/// Hypercube coordinates of a flat boundary cell — the shape an
/// `EvalClaim.point` needs for a single-cell opening of the committed
/// boundary polynomial.
pub fn point_for_auth_boundary_cell(cell: usize) -> Vec<Block128> {
    debug_assert!(cell < N_AUTH_BOUNDARY_CELLS);
    let mut out = Vec::with_capacity(N_AUTH_BOUNDARY_VARS);
    for i in 0..N_AUTH_BOUNDARY_VARS {
        out.push(if (cell >> i) & 1 == 1 {
            Block128::ONE
        } else {
            Block128::ZERO
        });
    }
    out
}

/// A single public pin: the committed boundary polynomial must
/// evaluate to `value` at the hypercube point corresponding to `cell`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthOutputPin {
    pub cell: usize,
    pub value: Block128,
}

/// Full pin set the AuthGKR boundary enforces publicly:
/// `2 * AUTH_PIN_LANES * N_AUTH_INPUTS` pins — two digests per input
/// (Address, AuthTag), two lanes each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthBoundaryPins {
    pub address: Vec<[AuthOutputPin; AUTH_PIN_LANES]>,
    pub auth_tag: Vec<[AuthOutputPin; AUTH_PIN_LANES]>,
}

impl AuthBoundaryPins {
    /// Build the pin set from public `AuthInputs`. Touches nothing
    /// secret — every value here is also exposed to the verifier.
    pub fn from_public_inputs(inputs: &AuthInputs) -> Self {
        let mut address = Vec::with_capacity(N_AUTH_INPUTS);
        let mut auth_tag = Vec::with_capacity(N_AUTH_INPUTS);
        for i in 0..N_AUTH_INPUTS {
            let addr_slot = AuthCircuit::haddr_output_slot(i);
            let tag_slot = AuthCircuit::hauth_output_slot(i);
            address.push([
                AuthOutputPin {
                    cell: auth_boundary_output_cell(addr_slot, 0),
                    value: inputs.expected_address[i][0],
                },
                AuthOutputPin {
                    cell: auth_boundary_output_cell(addr_slot, 1),
                    value: inputs.expected_address[i][1],
                },
            ]);
            auth_tag.push([
                AuthOutputPin {
                    cell: auth_boundary_output_cell(tag_slot, 0),
                    value: inputs.expected_auth_tag[i][0],
                },
                AuthOutputPin {
                    cell: auth_boundary_output_cell(tag_slot, 1),
                    value: inputs.expected_auth_tag[i][1],
                },
            ]);
        }
        Self { address, auth_tag }
    }

    /// Flatten the pin set into `EvalClaim`s over the committed
    /// boundary polynomial. Order is fixed (Address inputs 0..N, then
    /// AuthTag inputs 0..N, two lanes each) so prover and verifier
    /// inject byte-identical streams into `batch_eval`.
    pub fn as_eval_claims(&self) -> Vec<EvalClaim> {
        let mut out = Vec::with_capacity(AUTH_PIN_LANES * (self.address.len() + self.auth_tag.len()));
        for per_input in self.address.iter().chain(self.auth_tag.iter()) {
            for pin in per_input {
                out.push(EvalClaim {
                    point: point_for_auth_boundary_cell(pin.cell),
                    value: pin.value,
                });
            }
        }
        out
    }
}

#[inline]
fn absorb_pair<T: FiatShamir<Block128>>(channel: &mut T, pair: &[Block128; 2]) {
    channel.absorb(pair[0]);
    channel.absorb(pair[1]);
}

/// Absorb the public boundary into the channel, in a fixed order shared
/// by prover and verifier. Never absorbs `spend_secret`.
fn absorb_public_boundary<T: FiatShamir<Block128>>(channel: &mut T, inputs: &AuthInputs) {
    absorb_pair(channel, &inputs.tx_body_hash);
    for i in 0..N_AUTH_INPUTS {
        absorb_pair(channel, &inputs.expected_address[i]);
        absorb_pair(channel, &inputs.expected_auth_tag[i]);
    }
}

/// Rebuild every auth slot's `(state_in, state_out)` natively via
/// [`evaluate_auth`].
pub fn reconstruct_auth_slot_states(
    circuit: &AuthCircuit,
    inputs: &AuthInputs,
) -> Vec<([Block128; STATE_SIZE], [Block128; STATE_SIZE])> {
    let w = evaluate_auth(circuit, inputs);
    w.slots.into_iter().map(|s| (s.state_in, s.state_out)).collect()
}

/// Honest prover. Fails a debug-assertion if the claimed
/// `expected_address`/`expected_auth_tag` disagrees with the natively
/// computed boundary (i.e. the prover is trying to prove a lie).
pub fn prove_auth<T: FiatShamir<Block128>>(
    circuit: &AuthCircuit,
    inputs: &AuthInputs,
    channel: &mut T,
) -> (AuthProof, BatchEvalReduction) {
    let witness = evaluate_auth(circuit, inputs);
    for i in 0..N_AUTH_INPUTS {
        debug_assert_eq!(
            witness.derived_address[i], inputs.expected_address[i],
            "prover asked to prove a mismatching Address at input {i}",
        );
        debug_assert_eq!(
            witness.derived_auth_tag[i], inputs.expected_auth_tag[i],
            "prover asked to prove a mismatching AuthTag at input {i}",
        );
    }

    absorb_public_boundary(channel, inputs);

    let states: Vec<_> = witness
        .slots
        .iter()
        .map(|s| (s.state_in, s.state_out))
        .collect();

    // Build each slot's layered witness MLE once; reuse it for both
    // the per-slot permutation sumcheck and the boundary assembly.
    // Independent across slots — run in parallel.
    let mles: Vec<PermMle> = states
        .par_iter()
        .map(|(state_in, _)| PermMle::from_witness(&evaluate_permutation(*state_in)))
        .collect();

    let mut slot_proofs = Vec::with_capacity(states.len());
    let mut slot_v0 = Vec::with_capacity(states.len());
    // 4 claims per slot: 1 sout (bootstraps the chain) + 3 state (fall
    // out of the sin-expansion sumchecks).
    let mut batched: Vec<EvalClaim> = Vec::with_capacity(states.len() * 4);
    for (s, mle) in mles.iter().enumerate() {
        let (p, r0, v0, slot_claims) = prove_perm_with_mle(mle, channel);
        slot_proofs.push(p);
        slot_v0.push(v0);
        batched.push(lift_sout_claim(s, &r0, v0));
        for c in &slot_claims {
            batched.push(lift_state_claim(s, c));
        }
    }

    // Pass 4b: lift every public `expected_*` digest lane into the
    // batch-eval as an additional claim against the committed boundary.
    // A lying prover cannot forge these — the reduction point `r_B`
    // becomes an RLC of every claim (sout + state + pins), and the
    // final opening discharges `B(r_B) = v_B` against the same bytes
    // that seeded the FS channel via the FRI commitment.
    let pins = AuthBoundaryPins::from_public_inputs(inputs);
    batched.extend(pins.as_eval_claims());

    let boundary_mle = assemble_auth_boundary_mle(&mles);
    let (boundary, reduction) = prove_batch_eval(&boundary_mle, &batched, channel);

    (
        AuthProof {
            slots: slot_proofs,
            slot_v0,
            boundary,
        },
        reduction,
    )
}

/// Verifier. Returns `Some(reduction)` iff every per-slot sumcheck
/// accepts AND every public digest pin opens against the committed
/// boundary.
///
/// γ₂-lift (Pass 2): the verifier no longer reconstructs `sout_mle`
/// from `state_in` to bootstrap each per-slot chain — the
/// prover-supplied `proof.slot_v0[s]` is submitted as `v0 = sout(r0)`
/// and simultaneously registered as a claim in the outer batch-eval.
/// A lying `slot_v0[s]` either forks the per-slot sumcheck or fails
/// the final boundary opening.
///
/// Pin-lift (Pass 4b): the `expected_address` / `expected_auth_tag`
/// lanes are no longer cross-checked against a natively reconstructed
/// witness. Each pin is instead injected as an `EvalClaim` against
/// the committed boundary polynomial at the corresponding output-row
/// hypercube point. The batch-eval reduction's random-linear
/// combination therefore entangles pin consistency with the per-slot
/// sumcheck, and the final STARK mixed-close opening at `(r_B, v_B)`
/// discharges both in a single FRI verification. `spend_secret` is
/// not touched anywhere on the verifier side.
pub fn verify_auth<T: FiatShamir<Block128>>(
    proof: &AuthProof,
    circuit: &AuthCircuit,
    inputs: &AuthInputs,
    channel: &mut T,
) -> Option<BatchEvalReduction> {
    if proof.slots.len() != circuit.slots.len() {
        return None;
    }
    if circuit.slots.len() != N_AUTH_SLOTS {
        return None;
    }
    if proof.slot_v0.len() != N_AUTH_SLOTS {
        return None;
    }

    absorb_public_boundary(channel, inputs);

    // γ₂: walk every slot's per-perm sumcheck using the prover-supplied
    // `v0`. We capture `r0` via the provider closure so we can lift
    // `sout(r0) = v0` into the outer boundary batching below.
    let mut batched: Vec<EvalClaim> = Vec::with_capacity(N_AUTH_SLOTS * 4);
    for (s, slot_proof) in proof.slots.iter().enumerate() {
        let v0 = proof.slot_v0[s];
        let mut captured_r0: Option<Vec<Block128>> = None;
        let r0_slot = &mut captured_r0;
        let claims = verify_perm(slot_proof, channel, |r0| {
            *r0_slot = Some(r0.to_vec());
            v0
        })?;
        let r0 = captured_r0.expect("v0 provider always sets r0");
        batched.push(lift_sout_claim(s, &r0, v0));
        for c in &claims {
            batched.push(lift_state_claim(s, c));
        }
    }

    // Pass 4b: lift the public `expected_*` digest lanes into the
    // batch-eval as claims against the committed boundary, in the same
    // order the prover injected them.
    let pins = AuthBoundaryPins::from_public_inputs(inputs);
    batched.extend(pins.as_eval_claims());

    let reduction =
        verify_batch_eval(&proof.boundary, &batched, N_AUTH_BOUNDARY_VARS, channel)?;

    // `circuit` is still accepted (keeps the API stable for Pass 4c),
    // but nothing inside verify_auth depends on it any more — the
    // committed-boundary opening is the sole enforcement of the pins.
    let _ = circuit;

    Some(reduction)
}

/// Native discharge of the batch-eval reduction against the
/// reconstructed auth-boundary MLE. Test-harness helper, analogous to
/// [`crate::spine_sumcheck::discharge_boundary_native`].
pub fn discharge_auth_boundary_native(
    circuit: &AuthCircuit,
    inputs: &AuthInputs,
    reduction: &BatchEvalReduction,
) -> bool {
    let states = reconstruct_auth_slot_states(circuit, inputs);
    let boundary_mle = build_auth_boundary_mle(&states);
    noid_core::mle::evaluate::evaluate_slice(&boundary_mle, &reduction.point) == reduction.value
}

/// Convenience: compute the honest `(expected_address, expected_auth_tag)`
/// boundary from `spend_secret` + `tx_body_hash` without building any
/// proof. Callers use this to populate `AuthInputs` before entering the
/// transcript.
pub fn compute_auth_boundary(
    circuit: &AuthCircuit,
    spend_secret: [[Block128; 2]; N_AUTH_INPUTS],
    tx_body_hash: [Block128; 2],
) -> ([[Block128; 2]; N_AUTH_INPUTS], [[Block128; 2]; N_AUTH_INPUTS]) {
    let probe = AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address: [[Block128::ZERO; 2]; N_AUTH_INPUTS],
        expected_auth_tag: [[Block128::ZERO; 2]; N_AUTH_INPUTS],
    };
    let w = evaluate_auth(circuit, &probe);
    (w.derived_address, w.derived_auth_tag)
}
