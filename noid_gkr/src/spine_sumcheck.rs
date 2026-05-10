// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G2 — spine sumcheck: prove/verify the full 59-slot Poseidon2b
//! tx-body spine in one transcript.
//!
//! Architecture
//! ------------
//!
//! Prover and verifier both walk the spine slot-by-slot in post-order.
//! For each slot they deterministically reconstruct `state_in` from
//! `SpineInputs` plus the previous slots' (already verified) outputs,
//! using the native oracle helpers. They then invoke the G1b.β
//! permutation sumcheck on that slot — which further reduces a claim
//! on the slot's `sout`-MLE to claims on its `state`-MLE that the
//! verifier cross-checks against the honestly reconstructed witness.
//!
//! At the very end the verifier takes the wrap slot's `state_out[0..1]`
//! (again reconstructed natively) and cross-checks it against the
//! public `claimed_tx_body_hash` injected into the channel at the top
//! of the protocol. Byte-equality on this pin is the `BindingCut`
//! contract expressed in code.
//!
//! What this stage does NOT yet do
//! -------------------------------
//!
//! - It does not batch per-slot sumchecks into a single outer sumcheck
//!   over a random linear combination of per-slot claims. Each slot
//!   runs its G1b.β chain independently. Batching is a
//!   proof-size / verifier-time optimisation scheduled for a follow-up
//!   pass on top of this correctness floor.
//! - The verifier still reconstructs the per-slot state MLE natively
//!   from the boundary inputs. G3 replaces that reconstruction with a
//!   STARK multipoint opening on a small committed boundary MLE.
//!
//! Transcript order (must be mirrored by both sides)
//! -------------------------------------------------
//!
//! 1. Absorb `claimed_tx_body_hash` (two lanes).
//! 2. Absorb the capacity-IV-typed spine inputs header: `prev_state_root`,
//!    `fee_leaf`, `is_coinbase_leaf`, `pad_leaf`, all input-leaf
//!    payloads, all output-leaf payloads. The order is deterministic so
//!    both sides walk it identically.
//! 3. For each slot in post-order: invoke `prove_perm` / `verify_perm`
//!    on the slot's reconstructed `state_in` using the shared channel.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use crate::batch_eval::{
    prove_batch_eval, verify_batch_eval, BatchEvalProof, BatchEvalReduction, EvalClaim,
};
use crate::circuit::{SpineCircuit, SpineInputs};
use crate::layers::evaluate_permutation;
use crate::mle_layout::{PermMle, N_PERM_CELLS, N_PERM_VARS};
use crate::perm_sumcheck::{prove_perm, verify_perm, PermProof, PermStateClaim};

/// Number of slots in the tx-body spine.
pub const N_SPINE_SLOTS: usize = 59;

/// Smallest power of two ≥ `N_SPINE_SLOTS`, used for zero-padding so
/// the concatenated boundary MLE lives on a hypercube.
pub const N_SPINE_SLOTS_PADDED: usize = 64;

/// Extra variable count to index slots. `log2(64) = 6`.
pub const N_SLOT_VARS: usize = 6;

/// Total variables in the concatenated boundary MLE:
/// `log2(N_SPINE_SLOTS_PADDED) + N_PERM_VARS = 6 + 9 = 15`.
pub const N_BOUNDARY_VARS: usize = N_SLOT_VARS + N_PERM_VARS;

/// `2^N_BOUNDARY_VARS` cells — the padded size of the boundary MLE.
pub const N_BOUNDARY_CELLS: usize = 1 << N_BOUNDARY_VARS;

/// One proof object covering all 59 slots plus the γ₂ boundary
/// batching sumcheck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpineProof {
    pub slots: Vec<PermProof>,
    /// γ₂: the single outer sumcheck that collapses all `N_SPINE_SLOTS
    /// × 3` per-slot `state` MLE claims into one `(r_B, v_B)` on the
    /// concatenated boundary MLE `B = ‖ state_i`.
    pub boundary: BatchEvalProof,
}

impl SpineProof {
    /// Sum of all per-slot `PermProof` sizes plus the γ₂ boundary
    /// `BatchEvalProof`, in raw field-element bytes.
    pub fn byte_len(&self) -> usize {
        self.slots.iter().map(|p| p.byte_len()).sum::<usize>() + self.boundary.byte_len()
    }
}

/// Build the concatenated boundary MLE `B` of length
/// `N_BOUNDARY_CELLS = 2^15`. Slot `s ∈ 0..N_SPINE_SLOTS` occupies
/// indices `(s << N_PERM_VARS) .. ((s+1) << N_PERM_VARS)`; padded
/// slots are zero.
pub fn build_boundary_mle(
    slot_states: &[([Block128; STATE_SIZE], [Block128; STATE_SIZE])],
) -> Vec<Block128> {
    debug_assert_eq!(slot_states.len(), N_SPINE_SLOTS);
    let mut b = vec![Block128::ZERO; N_BOUNDARY_CELLS];
    for (s, (state_in, _)) in slot_states.iter().enumerate() {
        let witness = evaluate_permutation(*state_in);
        let state_mle = PermMle::from_witness(&witness).state;
        debug_assert_eq!(state_mle.len(), N_PERM_CELLS);
        let offset = s << N_PERM_VARS;
        b[offset..offset + N_PERM_CELLS].copy_from_slice(&state_mle);
    }
    b
}

/// Encode the slot index `s ∈ 0..N_SPINE_SLOTS_PADDED` as an
/// `N_SLOT_VARS`-bit point in variable order (LSB first) using
/// Block128::ZERO / Block128::ONE.
fn slot_index_to_bits(s: usize) -> Vec<Block128> {
    let mut out = Vec::with_capacity(N_SLOT_VARS);
    for i in 0..N_SLOT_VARS {
        out.push(if (s >> i) & 1 == 1 {
            Block128::ONE
        } else {
            Block128::ZERO
        });
    }
    out
}

/// Lift a per-slot claim `(rs, v)` on slot `s`'s state MLE into a
/// claim `(point, v)` on the concatenated boundary MLE `B`, where
/// `point = rs ‖ slot_bits(s)` (inner vars first, slot vars on top —
/// matching the `(s << N_PERM_VARS) | inner_idx` layout and the
/// highest-var-first fold convention).
fn lift_claim(s: usize, per_slot: &PermStateClaim) -> EvalClaim {
    debug_assert_eq!(per_slot.point.len(), N_PERM_VARS);
    let mut point = Vec::with_capacity(N_BOUNDARY_VARS);
    point.extend_from_slice(&per_slot.point);
    point.extend_from_slice(&slot_index_to_bits(s));
    EvalClaim {
        point,
        value: per_slot.value,
    }
}

// γ₄: `absorb_inputs` deleted. The entire boundary (concatenation of
// every slot's `state_in`) is bound through the `(r_B, v_B)` claim
// which the caller discharges against the boundary MLE commitment.
// Redundant raw-input absorption was a γ₂-era belt-and-braces; keeping
// it post-γ₃b would just make two paths disagree on what "the spine
// channel looks like" when we later audit for transcript canonicity.

fn absorb_hash<T: FiatShamir<Block128>>(channel: &mut T, hash: &[Block128; 2]) {
    channel.absorb(hash[0]);
    channel.absorb(hash[1]);
}

/// Rebuild every slot's `(state_in, state_out)` natively. Matches
/// `oracle::evaluate_spine` but returns the intermediate witness
/// directly so both prover and verifier can drive their sumchecks off
/// it.
pub fn reconstruct_slot_states(
    circuit: &SpineCircuit,
    inputs: &SpineInputs,
) -> Vec<([Block128; STATE_SIZE], [Block128; STATE_SIZE])> {
    use crate::oracle::evaluate_spine;
    let w = evaluate_spine(circuit, inputs);
    w.slots
        .into_iter()
        .map(|s| (s.state_in, s.state_out))
        .collect()
}

/// Honest prover. Fails a debug-assertion if
/// `claimed_tx_body_hash != evaluate_spine(circuit, inputs).tx_body_hash`.
pub fn prove_spine<T: FiatShamir<Block128>>(
    circuit: &SpineCircuit,
    inputs: &SpineInputs,
    claimed_tx_body_hash: [Block128; 2],
    channel: &mut T,
) -> (SpineProof, BatchEvalReduction) {
    let states = reconstruct_slot_states(circuit, inputs);
    let wrap = states.last().expect("spine must have at least one slot");
    debug_assert_eq!(
        [wrap.1[0], wrap.1[1]],
        claimed_tx_body_hash,
        "prover asked to claim a tx_body_hash inconsistent with its own inputs",
    );

    absorb_hash(channel, &claimed_tx_body_hash);

    let mut slot_proofs = Vec::with_capacity(states.len());
    let mut batched: Vec<EvalClaim> = Vec::with_capacity(states.len() * 3);
    for (s, (state_in, _state_out)) in states.iter().enumerate() {
        let (p, _v0, slot_claims) = prove_perm(*state_in, channel);
        slot_proofs.push(p);
        for c in &slot_claims {
            batched.push(lift_claim(s, c));
        }
    }

    // γ₂: collapse all 59·3 per-slot claims into one `(r_B, v_B)` on
    // the concatenated boundary MLE `B`. The returned reduction is
    // what γ₃a discharges via a FRI opening on the boundary column.
    let boundary_mle = build_boundary_mle(&states);
    let (boundary, reduction) = prove_batch_eval(&boundary_mle, &batched, channel);

    (
        SpineProof {
            slots: slot_proofs,
            boundary,
        },
        reduction,
    )
}

/// Verifier. Returns `Some(reduction)` iff every slot's permutation
/// sumcheck accepts AND the wrap-slot output equals
/// `claimed_tx_body_hash`. The caller is responsible for discharging
/// `reduction.value == B(reduction.point)` against a commitment to the
/// boundary MLE `B` (γ₃a swaps the native discharge for a FRI opening).
pub fn verify_spine<T: FiatShamir<Block128>>(
    proof: &SpineProof,
    circuit: &SpineCircuit,
    inputs: &SpineInputs,
    claimed_tx_body_hash: [Block128; 2],
    channel: &mut T,
) -> Option<BatchEvalReduction> {
    if proof.slots.len() != circuit.slots.len() {
        return None;
    }
    if circuit.slots.len() != N_SPINE_SLOTS {
        return None;
    }

    absorb_hash(channel, &claimed_tx_body_hash);

    let states = reconstruct_slot_states(circuit, inputs);
    let mut batched: Vec<EvalClaim> = Vec::with_capacity(states.len() * 3);
    for (s, ((state_in, _state_out), slot_proof)) in
        states.iter().zip(proof.slots.iter()).enumerate()
    {
        let claims = verify_perm(slot_proof, *state_in, channel)?;
        for c in &claims {
            batched.push(lift_claim(s, c));
        }
    }

    // γ₂: run the boundary batching sumcheck. We return the reduction
    // `(r_B, v_B)` so the caller can discharge it with either a native
    // evaluation (γ₂ test harness) or a FRI opening (γ₃a).
    let reduction = verify_batch_eval(&proof.boundary, &batched, N_BOUNDARY_VARS, channel)?;

    let wrap = states.last()?;
    let wrap_digest = [wrap.1[0], wrap.1[1]];
    if wrap_digest != claimed_tx_body_hash {
        return None;
    }

    Some(reduction)
}

/// Discharge a `BatchEvalReduction` against the natively-reconstructed
/// boundary MLE. Used by γ₂-only call sites (tests and anything that
/// doesn't carry a FRI commitment for `B`). γ₃a callers replace this
/// with `noid_fri::verify`.
pub fn discharge_boundary_native(
    circuit: &SpineCircuit,
    inputs: &SpineInputs,
    reduction: &BatchEvalReduction,
) -> bool {
    let states = reconstruct_slot_states(circuit, inputs);
    let boundary_mle = build_boundary_mle(&states);
    noid_core::mle::evaluate::evaluate_slice(&boundary_mle, &reduction.point) == reduction.value
}

/// Convenience: reconstruct the wrap digest from `SpineInputs` without
/// building any proof. Useful for callers that need to compute the
/// claimed hash before opening a transcript.
pub fn compute_tx_body_hash(circuit: &SpineCircuit, inputs: &SpineInputs) -> [Block128; 2] {
    let states = reconstruct_slot_states(circuit, inputs);
    let wrap = states.last().expect("spine must have at least one slot");
    [wrap.1[0], wrap.1[1]]
}

#[cfg(test)]
mod unit {
    use super::*;
    use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

    #[test]
    fn compute_tx_body_hash_matches_oracle() {
        use crate::oracle::evaluate_spine;
        let circuit = SpineCircuit::build();
        let inputs = SpineInputs {
            prev_state_root: [Block128::from(11u128), Block128::from(22u128)],
            fee_leaf: [Block128::from(33u128), Block128::from(44u128)],
            input_leaves: [[Block128::from(1u128); 4]; 4],
            output_leaves: [[Block128::from(2u128); 4]; 8],
            is_coinbase_leaf: [Block128::from(55u128), Block128::from(66u128)],
            pad_leaf: [Block128::from(0u128), Block128::from(0u128)],
        };
        let from_spine = compute_tx_body_hash(&circuit, &inputs);
        let from_oracle = evaluate_spine(&circuit, &inputs).tx_body_hash;
        assert_eq!(from_spine, from_oracle);

        // And the final lane we'd permute natively is consistent.
        let wrap = reconstruct_slot_states(&circuit, &inputs).pop().unwrap();
        let mut s = wrap.0;
        Poseidon2bPermutation.permute_mut(&mut s);
        assert_eq!([s[0], s[1]], from_spine);
    }
}
