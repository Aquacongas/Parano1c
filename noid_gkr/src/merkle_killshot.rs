// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Merkle path Kill-Shot orchestrator.
//!
//! Proves that a Merkle path of up to 16 Poseidon2b compressions chains
//! a leaf digest to the expected root. Uses the same unified sumcheck +
//! shift + batch-eval architecture as Spine and Auth Kill-Shots.
//!
//! Transcript order:
//! 1. Absorb `expected_root`.
//! 2. Absorb `leaf`.
//! 3. For each level: absorb `siblings[level]`.
//! 4. Absorb `active_depth` as a scalar.
//! 5. Unified sumcheck (14 rounds).
//! 6. Shift gadget (14 rounds).
//! 7. Batch-eval on `state` (root pin + sumcheck claims).
//! 8. Batch-eval on `s_in`.
//! 9. Batch-eval on `s_out`.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

use crate::auth_unified_v2::{
    AuthKillShotProof, AuthShiftReduction, AuthUnifiedReduction,
};
use crate::batch_eval::{
    prove_batch_eval, verify_batch_eval, BatchEvalProof, BatchEvalReduction, EvalClaim,
};
use crate::merkle_circuit::{MerkleCircuit, MerklePathInputs, MAX_MERKLE_DEPTH, N_MERKLE_SLOTS};
use crate::merkle_mle::{
    build_merkle_unified_mle, MerkleUnifiedMle, N_MERKLE_UNIFIED_VARS,
};
use crate::merkle_oracle::evaluate_merkle;
use crate::merkle_unified::{
    prove_merkle_shift, prove_merkle_unified, verify_merkle_shift, verify_merkle_unified,
};

/// Number of output lanes pinned (root = 2 lanes).
pub const MERKLE_PIN_LANES: usize = 2;

/// Composite proof for a Merkle path Kill-Shot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProofKillShot {
    pub kill_shot: AuthKillShotProof,
    pub state_batch: BatchEvalProof,
    pub sin_batch: BatchEvalProof,
    pub sout_batch: BatchEvalProof,
}

impl MerkleProofKillShot {
    pub fn byte_len(&self) -> usize {
        let main_polys = self.kill_shot.main.round_polys.len() * 10 * 16;
        let shift_polys = self.kill_shot.shift.round_polys.len() * 3 * 16;
        let main_finals = 12 * 16;
        let shift_finals = 3 * 16;
        main_polys
            + shift_polys
            + main_finals
            + shift_finals
            + self.state_batch.byte_len()
            + self.sin_batch.byte_len()
            + self.sout_batch.byte_len()
    }
}

/// Reductions delivered to the FRI / STARK bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleKillShotReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

#[inline]
fn absorb_pair<T: FiatShamir<Block128>>(channel: &mut T, pair: &[Block128; 2]) {
    channel.absorb(pair[0]);
    channel.absorb(pair[1]);
}

fn absorb_public_boundary<T: FiatShamir<Block128>>(channel: &mut T, inputs: &MerklePathInputs) {
    absorb_pair(channel, &inputs.expected_root);
    absorb_pair(channel, &inputs.leaf);
    for level in 0..MAX_MERKLE_DEPTH {
        absorb_pair(channel, &inputs.siblings[level]);
    }
    channel.absorb(Block128::from(inputs.active_depth as u128));
}

/// Hypercube point for `state[(slot, N_ROUNDS, lane)]`.
fn state_output_point(slot: usize, lane: usize) -> Vec<Block128> {
    debug_assert!(slot < N_MERKLE_SLOTS);
    debug_assert!(lane < MERKLE_PIN_LANES);
    let cell = MerkleUnifiedMle::index(slot, N_ROUNDS, lane);
    (0..N_MERKLE_UNIFIED_VARS)
        .map(|b| {
            if (cell >> b) & 1 == 1 {
                Block128::ONE
            } else {
                Block128::ZERO
            }
        })
        .collect()
}

/// Build pin claims for the root output.
fn root_pin_claims(inputs: &MerklePathInputs) -> Vec<EvalClaim> {
    if inputs.active_depth == 0 {
        return vec![];
    }
    let root_slot = MerkleCircuit::output_slot(inputs.active_depth - 1);
    (0..MERKLE_PIN_LANES)
        .map(|lane| EvalClaim {
            point: state_output_point(root_slot, lane),
            value: inputs.expected_root[lane],
        })
        .collect()
}

/// Build the Merkle unified MLE from inputs.
pub fn build_merkle_unified_from_inputs(
    circuit: &MerkleCircuit,
    inputs: &MerklePathInputs,
) -> MerkleUnifiedMle {
    let live_slots = MerkleCircuit::live_slots(inputs.active_depth);
    let w = evaluate_merkle(circuit, inputs);
    let state_ins: Vec<[Block128; STATE_SIZE]> = w.slots[..live_slots]
        .iter()
        .map(|s| s.state_in)
        .collect();
    let (mle, _) = build_merkle_unified_mle(&state_ins, live_slots);
    mle
}

/// Honest prover.
pub fn prove_merkle_killshot<T: FiatShamir<Block128>>(
    circuit: &MerkleCircuit,
    inputs: &MerklePathInputs,
    channel: &mut T,
) -> (MerkleProofKillShot, MerkleKillShotReductions) {
    assert!(inputs.active_depth > 0 && inputs.active_depth <= MAX_MERKLE_DEPTH);
    let live_slots = MerkleCircuit::live_slots(inputs.active_depth);

    let witness = evaluate_merkle(circuit, inputs);
    debug_assert_eq!(
        witness.derived_root, inputs.expected_root,
        "prover asked to prove a mismatching root"
    );

    absorb_public_boundary(channel, inputs);

    let state_ins: Vec<[Block128; STATE_SIZE]> = witness.slots[..live_slots]
        .iter()
        .map(|s| s.state_in)
        .collect();
    let (mle, _) = build_merkle_unified_mle(&state_ins, live_slots);

    let (main, r_prime) = prove_merkle_unified(&mle, live_slots, channel);
    let (shift, r_double_prime) = prove_merkle_shift(&mle, &r_prime, channel);

    let mut state_claims = vec![
        EvalClaim {
            point: r_prime.clone(),
            value: main.state_at_r,
        },
        EvalClaim {
            point: r_double_prime.clone(),
            value: shift.state_at_r2,
        },
    ];
    state_claims.extend(root_pin_claims(inputs));
    let (state_batch, state_red) = prove_batch_eval(&mle.state, &state_claims, channel);

    let sin_claims = vec![EvalClaim {
        point: r_double_prime.clone(),
        value: shift.s_in_at_r2,
    }];
    let (sin_batch, sin_red) = prove_batch_eval(&mle.s_in, &sin_claims, channel);

    let sout_claims = vec![EvalClaim {
        point: r_double_prime,
        value: shift.s_out_at_r2,
    }];
    let (sout_batch, sout_red) = prove_batch_eval(&mle.s_out, &sout_claims, channel);

    let proof = MerkleProofKillShot {
        kill_shot: AuthKillShotProof { main, shift },
        state_batch,
        sin_batch,
        sout_batch,
    };
    let reductions = MerkleKillShotReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    };
    (proof, reductions)
}

/// Verifier.
pub fn verify_merkle_killshot<T: FiatShamir<Block128>>(
    proof: &MerkleProofKillShot,
    inputs: &MerklePathInputs,
    channel: &mut T,
) -> Option<MerkleKillShotReductions> {
    if inputs.active_depth == 0 || inputs.active_depth > MAX_MERKLE_DEPTH {
        return None;
    }

    let live_slots = MerkleCircuit::live_slots(inputs.active_depth);

    absorb_public_boundary(channel, inputs);

    let main_red: AuthUnifiedReduction =
        verify_merkle_unified(&proof.kill_shot.main, live_slots, channel)?;
    let shift_red: AuthShiftReduction =
        verify_merkle_shift(&proof.kill_shot.shift, &main_red, channel)?;

    let mut state_claims = vec![
        EvalClaim {
            point: main_red.r_prime.clone(),
            value: main_red.state_at_r,
        },
        EvalClaim {
            point: shift_red.r_double_prime.clone(),
            value: shift_red.state_at_r2,
        },
    ];
    state_claims.extend(root_pin_claims(inputs));
    let state_red = verify_batch_eval(
        &proof.state_batch,
        &state_claims,
        N_MERKLE_UNIFIED_VARS,
        channel,
    )?;

    let sin_claims = vec![EvalClaim {
        point: shift_red.r_double_prime.clone(),
        value: shift_red.s_in_at_r2,
    }];
    let sin_red = verify_batch_eval(&proof.sin_batch, &sin_claims, N_MERKLE_UNIFIED_VARS, channel)?;

    let sout_claims = vec![EvalClaim {
        point: shift_red.r_double_prime,
        value: shift_red.s_out_at_r2,
    }];
    let sout_red = verify_batch_eval(
        &proof.sout_batch,
        &sout_claims,
        N_MERKLE_UNIFIED_VARS,
        channel,
    )?;

    Some(MerkleKillShotReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

/// Discharge reductions against natively reconstructed MLE (test harness).
pub fn discharge_merkle_reductions_native(
    circuit: &MerkleCircuit,
    inputs: &MerklePathInputs,
    reductions: &MerkleKillShotReductions,
) -> bool {
    use noid_core::mle::evaluate::evaluate_slice;
    let mle = build_merkle_unified_from_inputs(circuit, inputs);
    evaluate_slice(&mle.state, &reductions.state.point) == reductions.state.value
        && evaluate_slice(&mle.s_in, &reductions.sin.point) == reductions.sin.value
        && evaluate_slice(&mle.s_out, &reductions.sout.point) == reductions.sout.value
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::channel::Poseidon2bChannel;
    use noid_poseidon2b::native::compress;

    fn digest_to_fields(d: &[u8; 32]) -> [Block128; 2] {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a.copy_from_slice(&d[..16]);
        b.copy_from_slice(&d[16..]);
        [
            Block128::from(u128::from_le_bytes(a)),
            Block128::from(u128::from_le_bytes(b)),
        ]
    }

    fn fixture_inputs(depth: usize) -> MerklePathInputs {
        let leaf = [0x42u8; 32];
        let mut current = leaf;
        let mut siblings_raw = [[0u8; 32]; MAX_MERKLE_DEPTH];
        for i in 0..depth {
            siblings_raw[i] = [(i as u8).wrapping_add(0xA0); 32];
            current = compress(&current, &siblings_raw[i]);
        }
        let mut siblings = [[Block128::ZERO; 2]; MAX_MERKLE_DEPTH];
        for i in 0..depth {
            siblings[i] = digest_to_fields(&siblings_raw[i]);
        }
        MerklePathInputs {
            leaf: digest_to_fields(&leaf),
            siblings,
            expected_root: digest_to_fields(&current),
            active_depth: depth,
        }
    }

    #[test]
    fn merkle_killshot_round_trip_depth_8() {
        let circuit = MerkleCircuit::build();
        let inputs = fixture_inputs(8);

        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) = prove_merkle_killshot(&circuit, &inputs, &mut ch_p);

        let mut ch_v = Poseidon2bChannel::new();
        let v_red = verify_merkle_killshot(&proof, &inputs, &mut ch_v)
            .expect("verifier accepts honest proof");

        assert_eq!(v_red, reductions);
        assert!(discharge_merkle_reductions_native(&circuit, &inputs, &v_red));
    }

    #[test]
    fn merkle_killshot_round_trip_depth_16() {
        let circuit = MerkleCircuit::build();
        let inputs = fixture_inputs(16);

        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) = prove_merkle_killshot(&circuit, &inputs, &mut ch_p);

        let mut ch_v = Poseidon2bChannel::new();
        let v_red = verify_merkle_killshot(&proof, &inputs, &mut ch_v)
            .expect("verifier accepts honest proof");

        assert_eq!(v_red, reductions);
        assert!(discharge_merkle_reductions_native(&circuit, &inputs, &v_red));
    }

    #[test]
    fn merkle_killshot_rejects_tampered_root() {
        let circuit = MerkleCircuit::build();
        let inputs = fixture_inputs(8);

        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) = prove_merkle_killshot(&circuit, &inputs, &mut ch_p);

        let mut bad_inputs = inputs.clone();
        bad_inputs.expected_root[0] += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_merkle_killshot(&proof, &bad_inputs, &mut ch_v).is_none());
    }

    #[test]
    fn merkle_killshot_rejects_tampered_state_batch() {
        let circuit = MerkleCircuit::build();
        let inputs = fixture_inputs(4);

        let mut ch_p = Poseidon2bChannel::new();
        let (mut proof, _) = prove_merkle_killshot(&circuit, &inputs, &mut ch_p);
        proof.state_batch.b_final += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_merkle_killshot(&proof, &inputs, &mut ch_v).is_none());
    }

    #[test]
    fn proof_size_is_compact() {
        let circuit = MerkleCircuit::build();
        let inputs = fixture_inputs(8);

        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) = prove_merkle_killshot(&circuit, &inputs, &mut ch_p);

        let size = proof.byte_len();
        assert!(size < 8000, "proof should be < 8 KB, got {size}");
    }
}
