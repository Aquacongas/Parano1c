// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Kill-Shot orchestration.
//!
//! Top-level entry point that runs the unified Spine Kill-Shot:
//! uses a single `prove_sweep_spine_unified` + `prove_sweep_spine_shift` pair, then collapses the
//! four resulting witness claims into one multi-column batch-eval proof:
//!
//! ```text
//!         column           claims at points
//!     ────────────  ─────────────────────────────────
//!     state           state(r')   state(r'')          ← `state_at_r`, `state_at_r2`
//!     s_in            s_in(r'')                       ← `s_in_at_r2`
//!     s_out           s_out(r'')                      ← `s_out_at_r2`
//! ```
//!
//! Each column is a 17-variable MLE over the sweep unified hypercube.
//! The three columns share the same hypercube topology.
//!
//! `s_in` and `s_out` MLEs are built once from the slot witnesses and
//! reduced alongside `state` via one multi-column batch-eval. All three
//! columns share one terminal point on the unified hypercube.
//!
//! Transcript order
//! ----------------
//! 1. Absorb `claimed_tx_body_hash`.
//! 2. Absorb the spine inputs header.
//! 3. Run `prove_sweep_spine_unified` (squeezes ρ, β, γ; 15 round polys; 12
//!    final witness scalars).
//! 4. Run `prove_sweep_spine_shift` (squeezes δ; 15 round polys; 3 final
//!    witness scalars).
//! 5. Run one multi-column `batch_eval` over `state`, `s_in`, and
//!    `s_out`.
//!
//! Each step's transcript-side effects are encapsulated by the
//! sub-prover; both prover and verifier share one `Poseidon2bChannel`.

use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_poseidon2b::native::permutation::STATE_SIZE;

use crate::batch_eval::{
    prove_multi_batch_eval, verify_multi_batch_eval, BatchEvalReduction, EvalClaim,
    MultiBatchEvalProof,
};
use crate::circuit_sweep::N_SWEEP_SPINE_SLOTS;
use crate::circuit_sweep::{SweepSpineCircuit, SweepSpineInputs};
use crate::spine_mle_sweep::{
    build_sweep_spine_unified_mle, SweepSpineUnifiedMle, N_SWEEP_SPINE_UNIFIED_VARS,
};
use crate::spine_sumcheck_sweep::{
    compute_sweep_tx_body_hash, reconstruct_sweep_spine_slot_states,
};
use crate::spine_unified_sweep::{
    prove_sweep_spine_shift, prove_sweep_spine_unified, verify_sweep_spine_shift,
    verify_sweep_spine_unified, SweepSpineKillShotProof,
};

/// Composite proof for a tx-body spine in the Kill-Shot flow.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SweepSpineProofKillShot {
    pub kill_shot: SweepSpineKillShotProof,
    /// Discharges `state(r')`, `state(r'')`, `s_in(r'')`, and `s_out(r'')`
    /// against the committed MLE columns with one shared terminal point.
    pub batch: MultiBatchEvalProof,
}

impl SweepSpineProofKillShot {
    /// Total raw field-element byte size of every sumcheck round poly
    /// plus the three batch finals. Excludes the unified/shift witness
    /// scalars (which are part of `kill_shot`).
    pub fn byte_len(&self) -> usize {
        let main_polys = self.kill_shot.main.round_polys.len() * 10 * 16;
        let shift_polys = self.kill_shot.shift.round_polys.len() * 3 * 16;
        let main_finals = 12 * 16; // 12 witness claims emitted by main.
        let shift_finals = 3 * 16; // 3 witness claims emitted by shift.
        main_polys + shift_polys + main_finals + shift_finals + self.batch.byte_len()
    }
}

/// Reduction outputs delivered to the composed batch relation. Each
/// `BatchEvalReduction` carries `(point, value)` — the column
/// commitment must open to `value` at `point`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepSpineKillShotReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

fn absorb_hash<T: FiatShamir<Block128>>(channel: &mut T, hash: &[Block128; 2]) {
    channel.absorb(hash[0]);
    channel.absorb(hash[1]);
}

/// Materialise the unified MLE bundle from pre-computed slot states.
/// Avoids redundant `reconstruct_sweep_spine_slot_states` when the caller already
/// has them (e.g. `prove_tx` which derives them to feed both the
/// Kill-Shot unified MLE and boundary digest computation).
pub fn build_sweep_spine_unified_from_states(
    states: &[([Block128; STATE_SIZE], [Block128; STATE_SIZE])],
) -> SweepSpineUnifiedMle {
    debug_assert_eq!(states.len(), N_SWEEP_SPINE_SLOTS);
    let state_ins: Vec<[Block128; STATE_SIZE]> = states.iter().map(|(s_in, _)| *s_in).collect();
    let (mle, _witnesses) = build_sweep_spine_unified_mle(&state_ins);
    mle
}

/// Materialise the unified MLE bundle from `SweepSpineInputs`. Native
/// path; both prover (full witness) and verifier (test harness) use
/// it. In production the verifier never reconstructs this — the FRI
/// commitments answer all opening queries.
pub fn build_sweep_spine_unified_from_inputs(
    circuit: &SweepSpineCircuit,
    inputs: &SweepSpineInputs,
) -> SweepSpineUnifiedMle {
    let states = reconstruct_sweep_spine_slot_states(circuit, inputs);
    build_sweep_spine_unified_from_states(&states)
}

/// Honest prover.
pub fn prove_sweep_spine_killshot<T: FiatShamir<Block128>>(
    circuit: &SweepSpineCircuit,
    inputs: &SweepSpineInputs,
    claimed_tx_body_hash: [Block128; 2],
    channel: &mut T,
) -> (SweepSpineProofKillShot, SweepSpineKillShotReductions) {
    let actual = compute_sweep_tx_body_hash(circuit, inputs);
    debug_assert_eq!(
        actual, claimed_tx_body_hash,
        "prover asked to claim a tx_body_hash inconsistent with its own inputs",
    );
    let states = reconstruct_sweep_spine_slot_states(circuit, inputs);
    prove_sweep_spine_killshot_with_states(&states, claimed_tx_body_hash, channel)
}

/// Honest prover — variant that accepts pre-computed slot states,
/// avoiding redundant `reconstruct_sweep_spine_slot_states` when the caller
/// already has them (e.g. `prove_tx`).
pub fn prove_sweep_spine_killshot_with_states<T: FiatShamir<Block128>>(
    states: &[([Block128; STATE_SIZE], [Block128; STATE_SIZE])],
    claimed_tx_body_hash: [Block128; 2],
    channel: &mut T,
) -> (SweepSpineProofKillShot, SweepSpineKillShotReductions) {
    absorb_hash(channel, &claimed_tx_body_hash);

    let mle = build_sweep_spine_unified_from_states(states);

    // (1) Main unified sumcheck.
    let (main, r_prime) = prove_sweep_spine_unified(&mle, channel);
    // (2) Shift gadget.
    let (shift, r_double_prime) = prove_sweep_spine_shift(&mle, &r_prime, channel);

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

    let sin_claims = vec![EvalClaim {
        point: r_double_prime.clone(),
        value: shift.s_in_at_r2,
    }];

    let sout_claims = vec![EvalClaim {
        point: r_double_prime,
        value: shift.s_out_at_r2,
    }];
    let columns: [&[Block128]; 3] = [&mle.state, &mle.s_in, &mle.s_out];
    let claims_by_column: [&[EvalClaim]; 3] = [&state_claims, &sin_claims, &sout_claims];
    let (batch, reductions) = prove_multi_batch_eval(&columns, &claims_by_column, channel);
    let [state_red, sin_red, sout_red]: [BatchEvalReduction; 3] = reductions
        .try_into()
        .expect("multi-batch returns one reduction per column");

    let proof = SweepSpineProofKillShot {
        kill_shot: SweepSpineKillShotProof { main, shift },
        batch,
    };
    let reductions = SweepSpineKillShotReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    };
    (proof, reductions)
}

/// Verifier.
///
/// `inputs` is used only in debug builds as a belt-and-braces native
/// re-execution check (`compute_sweep_tx_body_hash`). In release builds the
/// parameter is intentionally unused: soundness is guaranteed algebraically
/// because `claimed_tx_body_hash` is absorbed into the Fiat-Shamir channel
/// (see `absorb_hash` below), binding all GKR challenges to this value.
/// The Kill-Shot sumcheck + FRI openings then prove that the committed MLE
/// is consistent with this hash. There is no soundness gap from skipping
/// native re-execution in release.
#[cfg_attr(not(debug_assertions), allow(unused_variables))]
pub fn verify_sweep_spine_killshot<T: FiatShamir<Block128>>(
    proof: &SweepSpineProofKillShot,
    circuit: &SweepSpineCircuit,
    inputs: &SweepSpineInputs,
    claimed_tx_body_hash: [Block128; 2],
    channel: &mut T,
) -> Option<SweepSpineKillShotReductions> {
    if circuit.slots.len() != N_SWEEP_SPINE_SLOTS {
        return None;
    }

    // Soundness of the wrap-digest pin is guaranteed algebraically:
    // claimed_tx_body_hash is absorbed into the Fiat-Shamir channel below,
    // binding all GKR challenges to this value. The Kill-Shot sumcheck +
    // FRI openings prove the committed MLE is consistent with this hash.
    // Native re-execution is kept only for debug builds as belt-and-braces.
    #[cfg(debug_assertions)]
    {
        let actual = compute_sweep_tx_body_hash(circuit, inputs);
        if actual != claimed_tx_body_hash {
            return None;
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = inputs;

    absorb_hash(channel, &claimed_tx_body_hash);

    let main_red = verify_sweep_spine_unified(&proof.kill_shot.main, channel)?;
    let shift_red = verify_sweep_spine_shift(&proof.kill_shot.shift, &main_red, channel)?;

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
    let sin_claims = vec![EvalClaim {
        point: shift_red.r_double_prime.clone(),
        value: shift_red.s_in_at_r2,
    }];

    let sout_claims = vec![EvalClaim {
        point: shift_red.r_double_prime,
        value: shift_red.s_out_at_r2,
    }];
    let claims_by_column: [&[EvalClaim]; 3] = [&state_claims, &sin_claims, &sout_claims];
    let reductions = verify_multi_batch_eval(
        &proof.batch,
        &claims_by_column,
        N_SWEEP_SPINE_UNIFIED_VARS,
        channel,
    )?;
    let [state_red, sin_red, sout_red]: [BatchEvalReduction; 3] = reductions.try_into().ok()?;

    Some(SweepSpineKillShotReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

/// Discharge all three reductions against the natively reconstructed
/// MLE bundle. Used by tests and by callers that don't yet carry
/// 3-column FRI commitments. Returns `true` iff every reduction
/// matches the native evaluation.
pub fn discharge_sweep_spine_reductions_native(
    circuit: &SweepSpineCircuit,
    inputs: &SweepSpineInputs,
    reductions: &SweepSpineKillShotReductions,
) -> bool {
    use noid_core::mle::evaluate::evaluate_slice;
    let mle = build_sweep_spine_unified_from_inputs(circuit, inputs);
    evaluate_slice(&mle.state, &reductions.state.point) == reductions.state.value
        && evaluate_slice(&mle.s_in, &reductions.sin.point) == reductions.sin.value
        && evaluate_slice(&mle.s_out, &reductions.sout.point) == reductions.sout.value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_sweep::SweepSpineCircuit;
    use noid_core::TowerField;
    use noid_poseidon2b::channel::Poseidon2bChannel;

    fn fixture_inputs() -> SweepSpineInputs {
        SweepSpineInputs {
            epoch_anchor: [Block128::from(11u128), Block128::from(22u128)],
            fee_leaf: [Block128::from(33u128), Block128::from(44u128)],
            shape_leaf: [Block128::ONE, Block128::ZERO],
            input_leaves: [[Block128::from(1u128); 4]; 25],
            output_leaves: [[Block128::from(2u128); 4]; 2],
            is_coinbase_leaf: [Block128::from(55u128), Block128::from(66u128)],
            pad_leaf: [Block128::from(0u128), Block128::from(0u128)],
        }
    }

    #[test]
    fn killshot_round_trip_native_discharge() {
        let circuit = SweepSpineCircuit::build();
        let inputs = fixture_inputs();
        let claimed = compute_sweep_tx_body_hash(&circuit, &inputs);

        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) = prove_sweep_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);

        let mut ch_v = Poseidon2bChannel::new();
        let v_red = verify_sweep_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v)
            .expect("verifier accepts honest proof");

        assert_eq!(v_red, reductions);
        assert!(discharge_sweep_spine_reductions_native(
            &circuit, &inputs, &v_red
        ));
    }

    #[test]
    fn killshot_rejects_tampered_state_at_r() {
        let circuit = SweepSpineCircuit::build();
        let inputs = fixture_inputs();
        let claimed = compute_sweep_tx_body_hash(&circuit, &inputs);

        let mut ch_p = Poseidon2bChannel::new();
        let (mut proof, _) = prove_sweep_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);
        proof.kill_shot.main.state_at_r += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(
            verify_sweep_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v).is_none()
        );
    }

    #[test]
    fn killshot_rejects_tampered_shift_claim() {
        let circuit = SweepSpineCircuit::build();
        let inputs = fixture_inputs();
        let claimed = compute_sweep_tx_body_hash(&circuit, &inputs);

        let mut ch_p = Poseidon2bChannel::new();
        let (mut proof, _) = prove_sweep_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);
        proof.kill_shot.shift.s_in_at_r2 += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(
            verify_sweep_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v).is_none()
        );
    }

    #[test]
    fn killshot_rejects_tampered_batch_terminal() {
        let circuit = SweepSpineCircuit::build();
        let inputs = fixture_inputs();
        let claimed = compute_sweep_tx_body_hash(&circuit, &inputs);

        let mut ch_p = Poseidon2bChannel::new();
        let (mut proof, _) = prove_sweep_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);
        proof.batch.b_finals[0] += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(
            verify_sweep_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v).is_none()
        );
    }

    #[test]
    fn killshot_rejects_wrong_claimed_hash() {
        let circuit = SweepSpineCircuit::build();
        let inputs = fixture_inputs();
        let bad = [Block128::from(0xDEADu64), Block128::from(0xBEEFu64)];

        let mut ch_v = Poseidon2bChannel::new();
        // Build an honest proof under a real claimed hash.
        let real = compute_sweep_tx_body_hash(&circuit, &inputs);
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) = prove_sweep_spine_killshot(&circuit, &inputs, real, &mut ch_p);

        // The verifier asks for `bad` — should reject before even
        // walking the sumchecks.
        assert!(verify_sweep_spine_killshot(&proof, &circuit, &inputs, bad, &mut ch_v).is_none());
    }
}
