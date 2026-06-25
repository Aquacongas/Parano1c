// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Batched exact composite state-root KillShot.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_EXSTROT};
use noid_poseidon2b::native::permutation::{Poseidon2bPermutation, MDS_FULL, N_ROUNDS, STATE_SIZE};

use crate::batch_eval::{
    prove_linear_eval_prebound, prove_multi_batch_eval, verify_linear_eval_prebound,
    verify_multi_batch_eval, BatchEvalReduction, EvalClaim, LinearEvalClaim, LinearEvalProof,
    LinearEvalTerm, MultiBatchEvalProof,
};
use crate::block_spine::{
    block_spine_state_point, prove_block_spine_shift, prove_block_spine_unified,
    verify_block_spine_shift, verify_block_spine_unified, BlockSpineKillShotProof, BlockSpineMle,
    BlockSpineUnifiedReduction,
};

const STATE_ROOT_LINEAR_RELATION_TAG: u128 = 0x4558_5354_524F_5401; // "EXSTROT"+1
const STATE_ROOT_PERMS: usize = 3;
const STATE_ROOT_PIN_LANES: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeStateRootInputs {
    pub log_slots: u32,
    pub utxo_root: [Block128; 2],
    pub guard_root: [Block128; 2],
    pub expected_state_root: [Block128; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedStateRootProofKillShot {
    pub kill_shot: BlockSpineKillShotProof,
    pub chain: LinearEvalProof,
    pub batch: MultiBatchEvalProof,
    pub n_roots: usize,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl BatchedStateRootProofKillShot {
    pub fn byte_len(&self) -> usize {
        let main_polys = self.kill_shot.main.round_polys.len() * 10 * 16;
        let shift_polys = self.kill_shot.shift.round_polys.len() * 3 * 16;
        let main_finals = 12 * 16;
        let shift_finals = 3 * 16;
        main_polys
            + shift_polys
            + main_finals
            + shift_finals
            + self.chain.byte_len()
            + self.batch.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchedStateRootReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

fn pad_after_one_field() -> Block128 {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x80;
    bytes[15] = 0x01;
    Block128::from(u128::from_le_bytes(bytes))
}

fn rate_blocks(input: &CompositeStateRootInputs) -> [[Block128; 2]; STATE_ROOT_PERMS] {
    [
        [Block128::from(input.log_slots), input.utxo_root[0]],
        [input.utxo_root[1], input.guard_root[0]],
        [input.guard_root[1], pad_after_one_field()],
    ]
}

fn absorb_public_root<T: FiatShamir<Block128>>(channel: &mut T, input: &CompositeStateRootInputs) {
    channel.absorb(Block128::from(input.log_slots));
    channel.absorb(input.utxo_root[0]);
    channel.absorb(input.utxo_root[1]);
    channel.absorb(input.guard_root[0]);
    channel.absorb(input.guard_root[1]);
    channel.absorb(input.expected_state_root[0]);
    channel.absorb(input.expected_state_root[1]);
}

fn absorb_public_batch<T: FiatShamir<Block128>>(
    channel: &mut T,
    inputs: &[CompositeStateRootInputs],
) {
    channel.absorb(Block128::from(inputs.len() as u128));
    channel.absorb(Block128::from(TAG_EXSTROT.as_u64() as u128));
    for input in inputs {
        absorb_public_root(channel, input);
    }
}

fn evaluate_state_root(input: &CompositeStateRootInputs) -> Option<Vec<[Block128; STATE_SIZE]>> {
    let [iv_hi, iv_lo] = capacity_iv(TAG_EXSTROT);
    let perm = Poseidon2bPermutation;
    let mut state = [Block128::ZERO, Block128::ZERO, iv_hi, iv_lo];
    let mut ins = Vec::with_capacity(STATE_ROOT_PERMS);
    for block in rate_blocks(input) {
        state[0] += block[0];
        state[1] += block[1];
        ins.push(state);
        perm.permute_mut(&mut state);
    }
    if [state[0], state[1]] != input.expected_state_root {
        return None;
    }
    Some(ins)
}

fn state_claim(num_vars: usize, slot: usize, round: usize, lane: usize) -> LinearEvalTerm {
    LinearEvalTerm {
        point: block_spine_state_point(num_vars, slot, round, lane),
        coeff: Block128::ONE,
    }
}

fn weighted_state_claim(
    num_vars: usize,
    slot: usize,
    round: usize,
    lane: usize,
    coeff: Block128,
) -> LinearEvalTerm {
    LinearEvalTerm {
        point: block_spine_state_point(num_vars, slot, round, lane),
        coeff,
    }
}

#[inline]
fn mds_coeff(row: usize, col: usize) -> Block128 {
    Block128::from(MDS_FULL[row][col])
}

fn mds_constant(row: usize, inputs: &[(usize, Block128)]) -> Block128 {
    inputs
        .iter()
        .map(|&(col, value)| mds_coeff(row, col) * value)
        .fold(Block128::ZERO, |a, b| a + b)
}

fn chain_claims_at_offset(
    input: &CompositeStateRootInputs,
    slot_offset: usize,
    num_vars: usize,
) -> Vec<LinearEvalClaim> {
    let [iv_hi, iv_lo] = capacity_iv(TAG_EXSTROT);
    let blocks = rate_blocks(input);
    let mut claims = Vec::with_capacity(STATE_ROOT_PERMS * STATE_SIZE + STATE_ROOT_PIN_LANES);
    for (block_idx, block) in blocks.iter().copied().enumerate() {
        let slot = slot_offset + block_idx;
        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_claim(num_vars, slot, 0, lane)];
            let value = if block_idx == 0 {
                mds_constant(
                    lane,
                    &[(0, block[0]), (1, block[1]), (2, iv_hi), (3, iv_lo)],
                )
            } else {
                let prev = slot - 1;
                for src_lane in 0..STATE_SIZE {
                    terms.push(weighted_state_claim(
                        num_vars,
                        prev,
                        N_ROUNDS,
                        src_lane,
                        mds_coeff(lane, src_lane),
                    ));
                }
                mds_constant(lane, &[(0, block[0]), (1, block[1])])
            };
            claims.push(LinearEvalClaim { terms, value });
        }
    }

    let last_slot = slot_offset + STATE_ROOT_PERMS - 1;
    for lane in 0..STATE_ROOT_PIN_LANES {
        claims.push(LinearEvalClaim {
            terms: vec![state_claim(num_vars, last_slot, N_ROUNDS, lane)],
            value: input.expected_state_root[lane],
        });
    }
    claims
}

pub fn prove_batched_state_root_killshot<T: FiatShamir<Block128>>(
    inputs: &[CompositeStateRootInputs],
    channel: &mut T,
) -> (BatchedStateRootProofKillShot, BatchedStateRootReductions) {
    assert!(!inputs.is_empty());

    let mut slot_state_ins = Vec::with_capacity(inputs.len() * STATE_ROOT_PERMS);
    for input in inputs {
        let slots = evaluate_state_root(input).expect("prover asked to prove wrong state root");
        slot_state_ins.extend(slots);
    }

    absorb_public_batch(channel, inputs);

    let mle = BlockSpineMle::build_from_slot_state_ins(&slot_state_ins);
    let (main, r_prime) = prove_block_spine_unified(&mle, channel);
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
    let (shift, r_double_prime) = prove_block_spine_shift(&mle, &r_prime, &main_red, channel);

    let mut chain_claims = Vec::new();
    for (idx, input) in inputs.iter().enumerate() {
        chain_claims.extend(chain_claims_at_offset(
            input,
            idx * STATE_ROOT_PERMS,
            mle.num_vars,
        ));
    }
    let (chain, chain_red) = prove_linear_eval_prebound(
        &mle.state,
        &chain_claims,
        STATE_ROOT_LINEAR_RELATION_TAG,
        channel,
    );

    let state_claims = vec![
        EvalClaim {
            point: r_prime,
            value: main.state_at_r,
        },
        EvalClaim {
            point: r_double_prime.clone(),
            value: shift.state_at_r2,
        },
        EvalClaim {
            point: chain_red.point,
            value: chain_red.value,
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

    let proof = BatchedStateRootProofKillShot {
        kill_shot: BlockSpineKillShotProof { main, shift },
        chain,
        batch,
        n_roots: inputs.len(),
        num_vars: mle.num_vars,
        live_slots: mle.live_slots,
    };
    let reductions = BatchedStateRootReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    };
    (proof, reductions)
}

pub fn verify_batched_state_root_killshot<T: FiatShamir<Block128>>(
    proof: &BatchedStateRootProofKillShot,
    inputs: &[CompositeStateRootInputs],
    channel: &mut T,
) -> Option<BatchedStateRootReductions> {
    if inputs.is_empty()
        || proof.n_roots != inputs.len()
        || proof.live_slots != inputs.len() * STATE_ROOT_PERMS
    {
        return None;
    }
    let expected_num_vars = crate::block_spine::num_vars_for(proof.live_slots);
    if proof.num_vars != expected_num_vars {
        return None;
    }

    absorb_public_batch(channel, inputs);

    let main_red = verify_block_spine_unified(
        &proof.kill_shot.main,
        proof.num_vars,
        proof.live_slots,
        channel,
    )?;
    let shift_red =
        verify_block_spine_shift(&proof.kill_shot.shift, &main_red, proof.num_vars, channel)?;

    let mut chain_claims = Vec::new();
    for (idx, input) in inputs.iter().enumerate() {
        chain_claims.extend(chain_claims_at_offset(
            input,
            idx * STATE_ROOT_PERMS,
            proof.num_vars,
        ));
    }
    let chain_red = verify_linear_eval_prebound(
        &proof.chain,
        &chain_claims,
        proof.num_vars,
        STATE_ROOT_LINEAR_RELATION_TAG,
        channel,
    )?;

    let state_claims = vec![
        EvalClaim {
            point: main_red.r_prime,
            value: main_red.state_at_r,
        },
        EvalClaim {
            point: shift_red.r_double_prime.clone(),
            value: shift_red.state_at_r2,
        },
        EvalClaim {
            point: chain_red.point,
            value: chain_red.value,
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
    let reductions =
        verify_multi_batch_eval(&proof.batch, &claims_by_column, proof.num_vars, channel)?;
    let [state_red, sin_red, sout_red]: [BatchEvalReduction; 3] = reductions.try_into().ok()?;

    Some(BatchedStateRootReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

pub fn discharge_batched_state_root_reductions_native(
    inputs: &[CompositeStateRootInputs],
    reductions: &BatchedStateRootReductions,
) -> bool {
    if inputs.is_empty() {
        return false;
    }
    let mut slot_state_ins = Vec::with_capacity(inputs.len() * STATE_ROOT_PERMS);
    for input in inputs {
        let Some(slots) = evaluate_state_root(input) else {
            return false;
        };
        slot_state_ins.extend(slots);
    }
    crate::block_spine::discharge_block_spine_batch_reductions_from_slot_state_ins_native(
        &slot_state_ins,
        &reductions.state,
        &reductions.sin,
        &reductions.sout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::channel::Poseidon2bChannel;
    use noid_poseidon2b::native::compression::Poseidon2bSponge;

    fn fields_from_digest(hash: [u8; 32]) -> [Block128; 2] {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        lo.copy_from_slice(&hash[..16]);
        hi.copy_from_slice(&hash[16..]);
        [
            Block128::from(u128::from_le_bytes(lo)),
            Block128::from(u128::from_le_bytes(hi)),
        ]
    }

    fn input(seed: u128) -> CompositeStateRootInputs {
        let log_slots = 24 + (seed as u32 & 1);
        let utxo_root = [Block128::from(seed + 1), Block128::from(seed + 2)];
        let guard_root = [Block128::from(seed + 3), Block128::from(seed + 4)];
        let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_EXSTROT));
        s.absorb_pair(Block128::from(log_slots), utxo_root[0]);
        s.absorb_pair(utxo_root[1], guard_root[0]);
        s.absorb(guard_root[1]);
        CompositeStateRootInputs {
            log_slots,
            utxo_root,
            guard_root,
            expected_state_root: fields_from_digest(s.finalize()),
        }
    }

    #[test]
    fn batched_state_root_roundtrip() {
        let inputs = vec![input(1), input(2), input(3)];
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) = prove_batched_state_root_killshot(&inputs, &mut ch_p);

        let mut ch_v = Poseidon2bChannel::new();
        let verified = verify_batched_state_root_killshot(&proof, &inputs, &mut ch_v)
            .expect("state root proof verifies");
        assert_eq!(verified, reductions);
    }

    #[test]
    fn batched_state_root_rejects_tamper() {
        let inputs = vec![input(9)];
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) = prove_batched_state_root_killshot(&inputs, &mut ch_p);
        let mut bad = inputs.clone();
        bad[0].expected_state_root[1] += Block128::ONE;
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_batched_state_root_killshot(&proof, &bad, &mut ch_v).is_none());
    }
}
