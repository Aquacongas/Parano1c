// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 1.5.6 — Kill-Shot orchestration.
//!
//! Top-level entry point that replaces the legacy 59 × per-slot
//! `prove_perm` chain with a single
//! `prove_spine_unified` + `prove_spine_shift` pair, then collapses the
//! four resulting witness claims into three column-level batch-eval
//! reductions:
//!
//! ```text
//!         column           claims at points
//!     ────────────  ─────────────────────────────────
//!     state           state(r')   state(r'')          ← `state_at_r`, `state_at_r2`
//!     s_in            s_in(r'')                       ← `s_in_at_r2`
//!     s_out           s_out(r'')                      ← `s_out_at_r2`
//! ```
//!
//! Each column is a 15-variable MLE over the unified hypercube (same
//! bit layout as the legacy boundary MLE for the `state` column, so
//! existing FRI commitments to `B = state` continue to work
//! unchanged). The three columns share the same hypercube topology.
//!
//! `s_in` and `s_out` MLEs are built once from the slot witnesses and
//! reduced via `batch_eval` like the existing `state` boundary; this
//! crate does not yet emit a 3-column FRI commitment — that is wired
//! by the STARK bridge in a follow-up task. For now both `s_in` /
//! `s_out` reductions are discharged natively by the verifier.
//!
//! Transcript order
//! ----------------
//! 1. Absorb `claimed_tx_body_hash`.
//! 2. Absorb the spine inputs header (same as legacy spine).
//! 3. Run `prove_spine_unified` (squeezes ρ, β, γ; 15 round polys; 12
//!    final witness scalars).
//! 4. Run `prove_spine_shift` (squeezes δ; 15 round polys; 3 final
//!    witness scalars).
//! 5. Run `prove_batch_eval` on `state` with claims `(r', state_at_r)`
//!    and `(r'', state_at_r2)`.
//! 6. Run `prove_batch_eval` on `s_in` with claim `(r'', s_in_at_r2)`.
//! 7. Run `prove_batch_eval` on `s_out` with claim `(r'', s_out_at_r2)`.
//!
//! Each step's transcript-side effects are encapsulated by the
//! sub-prover; both prover and verifier share one `Poseidon2bChannel`.

use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_poseidon2b::native::permutation::STATE_SIZE;

use crate::batch_eval::{
    prove_batch_eval, verify_batch_eval, BatchEvalProof, BatchEvalReduction, EvalClaim,
};
use crate::circuit::{SpineCircuit, SpineInputs};
use crate::spine_mle::{build_unified_mle, SpineUnifiedMle, N_SPINE_UNIFIED_VARS};
use crate::spine_sumcheck::{
    compute_tx_body_hash, reconstruct_slot_states, N_SPINE_SLOTS,
};
use crate::spine_unified::{
    prove_spine_shift, prove_spine_unified, verify_spine_shift, verify_spine_unified,
    SpineKillShotProof,
};

/// Composite proof for a tx-body spine in the Kill-Shot flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpineProofKillShot {
    pub kill_shot: SpineKillShotProof,
    /// Discharges `state(r')` and `state(r'')` against the committed
    /// `state` MLE.
    pub state_batch: BatchEvalProof,
    /// Discharges `s_in(r'')` against the committed `s_in` MLE.
    pub sin_batch: BatchEvalProof,
    /// Discharges `s_out(r'')` against the committed `s_out` MLE.
    pub sout_batch: BatchEvalProof,
}

impl SpineProofKillShot {
    /// Total raw field-element byte size of every sumcheck round poly
    /// plus the three batch finals. Excludes the unified/shift witness
    /// scalars (which are part of `kill_shot`).
    pub fn byte_len(&self) -> usize {
        let main_polys = self.kill_shot.main.round_polys.len() * 10 * 16;
        let shift_polys = self.kill_shot.shift.round_polys.len() * 3 * 16;
        let main_finals = 12 * 16; // 12 witness claims emitted by main.
        let shift_finals = 3 * 16; // 3 witness claims emitted by shift.
        main_polys
            + shift_polys
            + main_finals
            + shift_finals
            + self.state_batch.byte_len()
            + self.sin_batch.byte_len()
            + self.sout_batch.byte_len()
    }
}

/// Reduction outputs delivered to the FRI / STARK bridge. Each
/// `BatchEvalReduction` carries `(point, value)` — the column
/// commitment must open to `value` at `point`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpineKillShotReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

fn absorb_hash<T: FiatShamir<Block128>>(channel: &mut T, hash: &[Block128; 2]) {
    channel.absorb(hash[0]);
    channel.absorb(hash[1]);
}

/// Materialise the unified MLE bundle from pre-computed slot states.
/// Avoids redundant `reconstruct_slot_states` when the caller already
/// has them (e.g. `prove_tx` which needs them for `build_boundary_mle`).
pub fn build_unified_from_states(
    states: &[([Block128; STATE_SIZE], [Block128; STATE_SIZE])],
) -> SpineUnifiedMle {
    debug_assert_eq!(states.len(), N_SPINE_SLOTS);
    let state_ins: Vec<[Block128; STATE_SIZE]> =
        states.iter().map(|(s_in, _)| *s_in).collect();
    let (mle, _witnesses) = build_unified_mle(&state_ins);
    mle
}

/// Materialise the unified MLE bundle from `SpineInputs`. Native
/// path; both prover (full witness) and verifier (test harness) use
/// it. In production the verifier never reconstructs this — the FRI
/// commitments answer all opening queries.
pub fn build_unified_from_inputs(
    circuit: &SpineCircuit,
    inputs: &SpineInputs,
) -> SpineUnifiedMle {
    let states = reconstruct_slot_states(circuit, inputs);
    build_unified_from_states(&states)
}

/// Honest prover.
pub fn prove_spine_killshot<T: FiatShamir<Block128>>(
    circuit: &SpineCircuit,
    inputs: &SpineInputs,
    claimed_tx_body_hash: [Block128; 2],
    channel: &mut T,
) -> (SpineProofKillShot, SpineKillShotReductions) {
    let actual = compute_tx_body_hash(circuit, inputs);
    debug_assert_eq!(
        actual, claimed_tx_body_hash,
        "prover asked to claim a tx_body_hash inconsistent with its own inputs",
    );
    let states = reconstruct_slot_states(circuit, inputs);
    prove_spine_killshot_with_states(&states, claimed_tx_body_hash, channel)
}

/// Honest prover — variant that accepts pre-computed slot states,
/// avoiding redundant `reconstruct_slot_states` when the caller
/// already has them (e.g. `prove_tx`).
pub fn prove_spine_killshot_with_states<T: FiatShamir<Block128>>(
    states: &[([Block128; STATE_SIZE], [Block128; STATE_SIZE])],
    claimed_tx_body_hash: [Block128; 2],
    channel: &mut T,
) -> (SpineProofKillShot, SpineKillShotReductions) {
    absorb_hash(channel, &claimed_tx_body_hash);

    let mle = build_unified_from_states(states);

    // (1) Main unified sumcheck.
    let (main, r_prime) = prove_spine_unified(&mle, channel);
    // (2) Shift gadget.
    let (shift, r_double_prime) = prove_spine_shift(&mle, &r_prime, channel);

    // (3) state column batch: 2 claims at r' and r''.
    let state_claims = vec![
        EvalClaim {
            point: r_prime.clone(),
            value: main.state_at_r,
        },
        EvalClaim {
            point: r_double_prime.clone(),
            value: shift.state_at_r2,
        },
    ];
    let (state_batch, state_red) = prove_batch_eval(&mle.state, &state_claims, channel);

    // (4) s_in column batch: 1 claim at r''.
    let sin_claims = vec![EvalClaim {
        point: r_double_prime.clone(),
        value: shift.s_in_at_r2,
    }];
    let (sin_batch, sin_red) = prove_batch_eval(&mle.s_in, &sin_claims, channel);

    // (5) s_out column batch: 1 claim at r''.
    let sout_claims = vec![EvalClaim {
        point: r_double_prime,
        value: shift.s_out_at_r2,
    }];
    let (sout_batch, sout_red) = prove_batch_eval(&mle.s_out, &sout_claims, channel);

    let proof = SpineProofKillShot {
        kill_shot: SpineKillShotProof { main, shift },
        state_batch,
        sin_batch,
        sout_batch,
    };
    let reductions = SpineKillShotReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    };
    (proof, reductions)
}

/// Verifier.
pub fn verify_spine_killshot<T: FiatShamir<Block128>>(
    proof: &SpineProofKillShot,
    circuit: &SpineCircuit,
    inputs: &SpineInputs,
    claimed_tx_body_hash: [Block128; 2],
    channel: &mut T,
) -> Option<SpineKillShotReductions> {
    if circuit.slots.len() != N_SPINE_SLOTS {
        return None;
    }

    // Wrap-digest pin: bind the claimed hash to the natively
    // reconstructed wrap output, exactly like the legacy verifier.
    let actual = compute_tx_body_hash(circuit, inputs);
    if actual != claimed_tx_body_hash {
        return None;
    }

    absorb_hash(channel, &claimed_tx_body_hash);

    let main_red = verify_spine_unified(&proof.kill_shot.main, channel)?;
    let shift_red = verify_spine_shift(&proof.kill_shot.shift, &main_red, channel)?;

    let state_claims = vec![
        EvalClaim {
            point: main_red.r_prime.clone(),
            value: main_red.state_at_r,
        },
        EvalClaim {
            point: shift_red.r_double_prime.clone(),
            value: shift_red.state_at_r2,
        },
    ];
    let state_red =
        verify_batch_eval(&proof.state_batch, &state_claims, N_SPINE_UNIFIED_VARS, channel)?;

    let sin_claims = vec![EvalClaim {
        point: shift_red.r_double_prime.clone(),
        value: shift_red.s_in_at_r2,
    }];
    let sin_red =
        verify_batch_eval(&proof.sin_batch, &sin_claims, N_SPINE_UNIFIED_VARS, channel)?;

    let sout_claims = vec![EvalClaim {
        point: shift_red.r_double_prime,
        value: shift_red.s_out_at_r2,
    }];
    let sout_red =
        verify_batch_eval(&proof.sout_batch, &sout_claims, N_SPINE_UNIFIED_VARS, channel)?;

    Some(SpineKillShotReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

/// Discharge all three reductions against the natively reconstructed
/// MLE bundle. Used by tests and by callers that don't yet carry
/// 3-column FRI commitments. Returns `true` iff every reduction
/// matches the native evaluation.
pub fn discharge_reductions_native(
    circuit: &SpineCircuit,
    inputs: &SpineInputs,
    reductions: &SpineKillShotReductions,
) -> bool {
    use noid_core::mle::evaluate::evaluate_slice;
    let mle = build_unified_from_inputs(circuit, inputs);
    evaluate_slice(&mle.state, &reductions.state.point) == reductions.state.value
        && evaluate_slice(&mle.s_in, &reductions.sin.point) == reductions.sin.value
        && evaluate_slice(&mle.s_out, &reductions.sout.point) == reductions.sout.value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::SpineCircuit;
    use noid_core::TowerField;
    use noid_poseidon2b::channel::Poseidon2bChannel;

    fn fixture_inputs() -> SpineInputs {
        SpineInputs {
            prev_state_root: [Block128::from(11u128), Block128::from(22u128)],
            fee_leaf: [Block128::from(33u128), Block128::from(44u128)],
            input_leaves: [[Block128::from(1u128); 4]; 4],
            output_leaves: [[Block128::from(2u128); 4]; 8],
            is_coinbase_leaf: [Block128::from(55u128), Block128::from(66u128)],
            pad_leaf: [Block128::from(0u128), Block128::from(0u128)],
        }
    }

    #[test]
    fn killshot_round_trip_native_discharge() {
        let circuit = SpineCircuit::build();
        let inputs = fixture_inputs();
        let claimed = compute_tx_body_hash(&circuit, &inputs);

        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) =
            prove_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);

        let mut ch_v = Poseidon2bChannel::new();
        let v_red = verify_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v)
            .expect("verifier accepts honest proof");

        assert_eq!(v_red, reductions);
        assert!(discharge_reductions_native(&circuit, &inputs, &v_red));
    }

    #[test]
    fn killshot_rejects_tampered_state_at_r() {
        let circuit = SpineCircuit::build();
        let inputs = fixture_inputs();
        let claimed = compute_tx_body_hash(&circuit, &inputs);

        let mut ch_p = Poseidon2bChannel::new();
        let (mut proof, _) = prove_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);
        proof.kill_shot.main.state_at_r += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v).is_none());
    }

    #[test]
    fn killshot_rejects_tampered_shift_claim() {
        let circuit = SpineCircuit::build();
        let inputs = fixture_inputs();
        let claimed = compute_tx_body_hash(&circuit, &inputs);

        let mut ch_p = Poseidon2bChannel::new();
        let (mut proof, _) = prove_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);
        proof.kill_shot.shift.s_in_at_r2 += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v).is_none());
    }

    #[test]
    fn killshot_rejects_tampered_state_batch() {
        let circuit = SpineCircuit::build();
        let inputs = fixture_inputs();
        let claimed = compute_tx_body_hash(&circuit, &inputs);

        let mut ch_p = Poseidon2bChannel::new();
        let (mut proof, _) = prove_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);
        proof.state_batch.b_final += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v).is_none());
    }

    #[test]
    fn killshot_rejects_wrong_claimed_hash() {
        let circuit = SpineCircuit::build();
        let inputs = fixture_inputs();
        let bad = [Block128::from(0xDEADu64), Block128::from(0xBEEFu64)];

        let mut ch_v = Poseidon2bChannel::new();
        // Build an honest proof under a real claimed hash.
        let real = compute_tx_body_hash(&circuit, &inputs);
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) = prove_spine_killshot(&circuit, &inputs, real, &mut ch_p);

        // The verifier asks for `bad` — should reject before even
        // walking the sumchecks.
        assert!(verify_spine_killshot(&proof, &circuit, &inputs, bad, &mut ch_v).is_none());
    }
}
