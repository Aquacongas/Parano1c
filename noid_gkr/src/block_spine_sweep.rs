// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Sweep25x2 block-level SpineGKR.
//!
//! This module is the Sweep25x2 analogue of `block_spine`: one block-level
//! Kill-Shot over `N x 142` sweep tx-body spine slots. It intentionally exposes
//! a dedicated public API instead of reusing the Standard4x8 `BlockSpineProof`
//! type, while reusing the same low-level dynamic block-spine sumcheck machinery.

use noid_core::mle::evaluate::evaluate_slice;
use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

use crate::batch_eval::{
    prove_batch_eval, verify_batch_eval, BatchEvalProof, BatchEvalReduction, EvalClaim,
};
use crate::block_spine::{
    prove_block_spine_shift, prove_block_spine_unified, verify_block_spine_shift,
    verify_block_spine_unified, BlockSpineKillShotProof, BlockSpineMle, BlockSpineReductions,
    BlockSpineUnifiedReduction,
};
use crate::circuit_sweep::{SweepSpineCircuit, SweepSpineInputs, N_SWEEP_SPINE_SLOTS};
use crate::layers::{evaluate_permutation, RoundKind};
use crate::spine_mle_sweep::{N_SWEEP_SPINE_ELEM_VARS, N_SWEEP_SPINE_ROUND_VARS};
use crate::spine_sumcheck_sweep::reconstruct_sweep_spine_slot_states;

const ELEM_BITS: usize = N_SWEEP_SPINE_ELEM_VARS;
const ROUND_BITS: usize = N_SWEEP_SPINE_ROUND_VARS;
const ROUND_LIMIT: usize = 1 << ROUND_BITS;

const _: () = assert!(STATE_SIZE == 4);
const _: () = assert!(N_ROUNDS <= ROUND_LIMIT);

/// Compute the number of slot variables needed for `total_live_slots`.
fn slot_vars_for(total_live_slots: usize) -> usize {
    assert!(total_live_slots > 0);
    let bits = (usize::BITS - (total_live_slots - 1).leading_zeros()) as usize;
    bits.max(1)
}

/// Total number of MLE variables for a given number of live sweep slots.
fn num_vars_for(total_live_slots: usize) -> usize {
    slot_vars_for(total_live_slots) + ROUND_BITS + ELEM_BITS
}

#[inline]
fn pack_index_dyn(slot: usize, round: usize, elem: usize) -> usize {
    (slot << (ROUND_BITS + ELEM_BITS)) | (round << ELEM_BITS) | elem
}

fn build_block_spine_mle_from_state_ins(
    n_instances: usize,
    slot_state_ins: &[[Block128; STATE_SIZE]],
) -> BlockSpineMle {
    let total_live = n_instances * N_SWEEP_SPINE_SLOTS;
    assert_eq!(slot_state_ins.len(), total_live);
    let num_vars = num_vars_for(total_live);
    let n_cells = 1usize << num_vars;

    let mut mle = BlockSpineMle {
        s_in: vec![Block128::ZERO; n_cells],
        s_out: vec![Block128::ZERO; n_cells],
        sigma: vec![Block128::ZERO; n_cells],
        state: vec![Block128::ZERO; n_cells],
        num_vars,
        live_slots: total_live,
    };

    use rayon::prelude::*;
    let witnesses: Vec<_> = slot_state_ins
        .par_iter()
        .map(|&state_in| evaluate_permutation(state_in))
        .collect();

    for (slot, witness) in witnesses.iter().enumerate() {
        for r in 0..N_ROUNDS {
            let active_mask = match witness.kind[r] {
                RoundKind::Full => [true; STATE_SIZE],
                RoundKind::Partial => {
                    let mut m = [false; STATE_SIZE];
                    m[0] = true;
                    m
                }
            };
            for (elem, active) in active_mask.iter().enumerate().take(STATE_SIZE) {
                let idx = pack_index_dyn(slot, r, elem);
                mle.s_in[idx] = witness.sin[r][elem];
                mle.s_out[idx] = witness.sout[r][elem];
                mle.sigma[idx] = if *active {
                    Block128::ONE
                } else {
                    Block128::ZERO
                };
            }
        }
        debug_assert_eq!(witness.state.len(), N_ROUNDS + 1);
        for r in 0..=N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = pack_index_dyn(slot, r, elem);
                mle.state[idx] = witness.state[r][elem];
            }
        }
    }

    mle
}

/// Dynamically-sized unified MLE for an `N x 142` sweep block spine.
#[derive(Debug, Clone)]
pub struct SweepBlockSpineMle {
    pub inner: BlockSpineMle,
    pub n_instances: usize,
}

impl SweepBlockSpineMle {
    /// Build the sweep block-spine MLE from canonical sweep spine inputs.
    pub fn build(inputs: &[SweepSpineInputs]) -> Self {
        let circuit = SweepSpineCircuit::build();
        let mut state_ins = Vec::with_capacity(inputs.len() * N_SWEEP_SPINE_SLOTS);
        for input in inputs {
            let states = reconstruct_sweep_spine_slot_states(&circuit, input);
            debug_assert_eq!(states.len(), N_SWEEP_SPINE_SLOTS);
            state_ins.extend(states.iter().map(|(s_in, _)| *s_in));
        }
        Self::build_from_state_ins(inputs.len(), &state_ins)
    }

    /// Build from already reconstructed slot state inputs. Useful for tests and
    /// future block prover integration that already has the canonical slot states.
    pub fn build_from_state_ins(
        n_instances: usize,
        slot_state_ins: &[[Block128; STATE_SIZE]],
    ) -> Self {
        Self {
            inner: build_block_spine_mle_from_state_ins(n_instances, slot_state_ins),
            n_instances,
        }
    }
}

/// Complete proof for the Sweep25x2 unified block spine.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SweepBlockSpineProof {
    pub kill_shot: BlockSpineKillShotProof,
    pub state_batch: BatchEvalProof,
    pub sin_batch: BatchEvalProof,
    pub sout_batch: BatchEvalProof,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl SweepBlockSpineProof {
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

/// Reductions delivered to the future sweep bucket FRI/STARK bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepBlockSpineReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

impl From<BlockSpineReductions> for SweepBlockSpineReductions {
    fn from(value: BlockSpineReductions) -> Self {
        Self {
            state: value.state,
            sin: value.sin,
            sout: value.sout,
        }
    }
}

fn absorb_tx_body_hashes<T: FiatShamir<Block128>>(
    tx_body_hashes: &[[Block128; 2]],
    channel: &mut T,
) {
    for hash in tx_body_hashes {
        channel.absorb(hash[0]);
        channel.absorb(hash[1]);
    }
}

/// Prove one Sweep25x2 block-level spine Kill-Shot over `n_instances * 142` slots.
pub fn prove_sweep_block_spine_killshot<T: FiatShamir<Block128>>(
    n_instances: usize,
    mle: &SweepBlockSpineMle,
    tx_body_hashes: &[[Block128; 2]],
    channel: &mut T,
) -> (SweepBlockSpineProof, SweepBlockSpineReductions) {
    assert_eq!(mle.n_instances, n_instances);
    assert_eq!(tx_body_hashes.len(), n_instances);
    let live_slots = n_instances * N_SWEEP_SPINE_SLOTS;
    let num_vars = num_vars_for(live_slots);
    assert_eq!(mle.inner.live_slots, live_slots);
    assert_eq!(mle.inner.num_vars, num_vars);

    absorb_tx_body_hashes(tx_body_hashes, channel);

    let (main, r_prime) = prove_block_spine_unified(&mle.inner, channel);
    let main_red = BlockSpineUnifiedReduction {
        r_prime: r_prime.clone(),
        s_in_dec_at_r: main.s_in_dec_at_r,
        s_out_dec_at_r: main.s_out_dec_at_r,
        state_dec_at_r: main.state_dec_at_r,
        state_at_r: main.state_at_r,
        s_out_lane_dec_at_r: main.s_out_lane_dec_at_r,
        state_lane_dec_at_r: main.state_lane_dec_at_r,
        beta: Block128::ZERO,
        gamma: Block128::ZERO,
    };

    let (shift, r_double_prime) = prove_block_spine_shift(&mle.inner, &r_prime, &main_red, channel);

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
    let (state_batch, state_red) = prove_batch_eval(&mle.inner.state, &state_claims, channel);

    let sin_claims = vec![EvalClaim {
        point: r_double_prime.clone(),
        value: shift.s_in_at_r2,
    }];
    let (sin_batch, sin_red) = prove_batch_eval(&mle.inner.s_in, &sin_claims, channel);

    let sout_claims = vec![EvalClaim {
        point: r_double_prime,
        value: shift.s_out_at_r2,
    }];
    let (sout_batch, sout_red) = prove_batch_eval(&mle.inner.s_out, &sout_claims, channel);

    let proof = SweepBlockSpineProof {
        kill_shot: BlockSpineKillShotProof { main, shift },
        state_batch,
        sin_batch,
        sout_batch,
        num_vars,
        live_slots,
    };
    let reductions = SweepBlockSpineReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    };
    (proof, reductions)
}

/// Verify one Sweep25x2 block-level spine Kill-Shot over `n_instances * 142` slots.
pub fn verify_sweep_block_spine_killshot<T: FiatShamir<Block128>>(
    proof: &SweepBlockSpineProof,
    n_instances: usize,
    tx_body_hashes: &[[Block128; 2]],
    channel: &mut T,
) -> Option<SweepBlockSpineReductions> {
    let expected_live = n_instances * N_SWEEP_SPINE_SLOTS;
    if proof.live_slots != expected_live {
        return None;
    }
    let expected_num_vars = num_vars_for(expected_live);
    if proof.num_vars != expected_num_vars || tx_body_hashes.len() != n_instances {
        return None;
    }

    absorb_tx_body_hashes(tx_body_hashes, channel);

    let main_red = verify_block_spine_unified(
        &proof.kill_shot.main,
        proof.num_vars,
        proof.live_slots,
        channel,
    )?;
    let shift_red =
        verify_block_spine_shift(&proof.kill_shot.shift, &main_red, proof.num_vars, channel)?;

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
    let state_red = verify_batch_eval(&proof.state_batch, &state_claims, proof.num_vars, channel)?;

    let sin_claims = vec![EvalClaim {
        point: shift_red.r_double_prime.clone(),
        value: shift_red.s_in_at_r2,
    }];
    let sin_red = verify_batch_eval(&proof.sin_batch, &sin_claims, proof.num_vars, channel)?;

    let sout_claims = vec![EvalClaim {
        point: shift_red.r_double_prime,
        value: shift_red.s_out_at_r2,
    }];
    let sout_red = verify_batch_eval(&proof.sout_batch, &sout_claims, proof.num_vars, channel)?;

    Some(SweepBlockSpineReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

/// Discharge reductions against a natively reconstructed sweep block-spine MLE.
/// Test helper and future integration sanity check.
pub fn discharge_sweep_block_spine_reductions_native(
    inputs: &[SweepSpineInputs],
    reductions: &SweepBlockSpineReductions,
) -> bool {
    let mle = SweepBlockSpineMle::build(inputs);
    evaluate_slice(&mle.inner.state, &reductions.state.point) == reductions.state.value
        && evaluate_slice(&mle.inner.s_in, &reductions.sin.point) == reductions.sin.value
        && evaluate_slice(&mle.inner.s_out, &reductions.sout.point) == reductions.sout.value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_block_spine_num_vars() {
        assert_eq!(slot_vars_for(N_SWEEP_SPINE_SLOTS), 8);
        assert_eq!(num_vars_for(N_SWEEP_SPINE_SLOTS), 17);
        assert_eq!(slot_vars_for(2 * N_SWEEP_SPINE_SLOTS), 9);
        assert_eq!(num_vars_for(2 * N_SWEEP_SPINE_SLOTS), 18);
    }
}
