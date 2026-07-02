// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Batched ReuseGuard bucket hash KillShot.
//!
//! Proves the canonical `RGDBUCK_` sponge schedule for empty and occupied
//! guard buckets. The Merkle path over bucket hashes is proved separately under
//! `RGDNODE`; this module binds the bucket contents to the leaf digest.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_RGDBUCK};
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

const GUARD_BUCKET_LINEAR_RELATION_TAG: u128 = 0x5247_4442_5543_4B01; // "RGDBUCK"+1
const GUARD_BUCKET_PIN_LANES: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GuardBucketHashInputs {
    pub occupied: bool,
    pub absolute_height: u64,
    pub spent_slots: Vec<u32>,
    pub expected_hash: [Block128; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BatchedGuardBucketProofKillShot {
    pub kill_shot: BlockSpineKillShotProof,
    pub chain: LinearEvalProof,
    pub batch: MultiBatchEvalProof,
    pub n_buckets: usize,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl BatchedGuardBucketProofKillShot {
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
pub struct BatchedGuardBucketReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

fn absorb_public_bucket<T: FiatShamir<Block128>>(channel: &mut T, input: &GuardBucketHashInputs) {
    channel.absorb(Block128::from(input.occupied as u128));
    channel.absorb(Block128::from(input.absolute_height));
    channel.absorb(Block128::from(input.spent_slots.len() as u128));
    for &slot in &input.spent_slots {
        channel.absorb(Block128::from(slot));
    }
    channel.absorb(input.expected_hash[0]);
    channel.absorb(input.expected_hash[1]);
}

fn absorb_public_batch<T: FiatShamir<Block128>>(channel: &mut T, inputs: &[GuardBucketHashInputs]) {
    channel.absorb(Block128::from(inputs.len() as u128));
    channel.absorb(Block128::from(TAG_RGDBUCK.as_u64() as u128));
    for input in inputs {
        absorb_public_bucket(channel, input);
    }
}

fn pad_after_one_field() -> Block128 {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x80;
    bytes[15] = 0x01;
    Block128::from(u128::from_le_bytes(bytes))
}

fn pad_empty_block() -> [Block128; 2] {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo[0] = 0x80;
    hi[15] = 0x01;
    [
        Block128::from(u128::from_le_bytes(lo)),
        Block128::from(u128::from_le_bytes(hi)),
    ]
}

fn inputs_are_canonical(input: &GuardBucketHashInputs) -> bool {
    if !input.occupied {
        return input.absolute_height == 0 && input.spent_slots.is_empty();
    }
    !input.spent_slots.is_empty() && input.spent_slots.windows(2).all(|w| w[0] < w[1])
}

fn bucket_blocks(input: &GuardBucketHashInputs) -> Option<Vec<[Block128; 2]>> {
    if !inputs_are_canonical(input) {
        return None;
    }
    if !input.occupied {
        return Some(vec![[Block128::ZERO, pad_after_one_field()]]);
    }

    let mut blocks = vec![[Block128::from(1u8), Block128::from(input.absolute_height)]];
    let mut fields = Vec::with_capacity(input.spent_slots.len() + 1);
    fields.push(Block128::from(input.spent_slots.len() as u64));
    fields.extend(input.spent_slots.iter().map(|&slot| Block128::from(slot)));
    let mut chunks = fields.chunks_exact(2);
    for pair in &mut chunks {
        blocks.push([pair[0], pair[1]]);
    }
    let rem = chunks.remainder();
    if rem.is_empty() {
        blocks.push(pad_empty_block());
    } else {
        blocks.push([rem[0], pad_after_one_field()]);
    }
    Some(blocks)
}

fn evaluate_bucket(input: &GuardBucketHashInputs) -> Option<Vec<[Block128; STATE_SIZE]>> {
    let blocks = bucket_blocks(input)?;
    let [iv_hi, iv_lo] = capacity_iv(TAG_RGDBUCK);
    let perm = Poseidon2bPermutation;
    let mut state = [Block128::ZERO, Block128::ZERO, iv_hi, iv_lo];
    let mut ins = Vec::with_capacity(blocks.len());
    for block in blocks {
        state[0] += block[0];
        state[1] += block[1];
        ins.push(state);
        perm.permute_mut(&mut state);
    }
    if [state[0], state[1]] != input.expected_hash {
        return None;
    }
    Some(ins)
}

fn live_slots_for(inputs: &[GuardBucketHashInputs]) -> Option<usize> {
    inputs
        .iter()
        .map(|input| bucket_blocks(input).map(|blocks| blocks.len()))
        .try_fold(0usize, |acc, len| len.map(|len| acc + len))
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
    input: &GuardBucketHashInputs,
    slot_offset: usize,
    num_vars: usize,
) -> Option<Vec<LinearEvalClaim>> {
    let blocks = bucket_blocks(input)?;
    let [iv_hi, iv_lo] = capacity_iv(TAG_RGDBUCK);
    let mut claims = Vec::with_capacity(blocks.len() * STATE_SIZE + GUARD_BUCKET_PIN_LANES);
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

    let last_slot = slot_offset + blocks.len() - 1;
    for lane in 0..GUARD_BUCKET_PIN_LANES {
        claims.push(LinearEvalClaim {
            terms: vec![state_claim(num_vars, last_slot, N_ROUNDS, lane)],
            value: input.expected_hash[lane],
        });
    }
    Some(claims)
}

pub fn prove_batched_guard_bucket_killshot<T: FiatShamir<Block128>>(
    inputs: &[GuardBucketHashInputs],
    channel: &mut T,
) -> (
    BatchedGuardBucketProofKillShot,
    BatchedGuardBucketReductions,
) {
    assert!(!inputs.is_empty());
    assert!(inputs.iter().all(inputs_are_canonical));

    let live_slots = live_slots_for(inputs).expect("canonical inputs have blocks");
    let mut slot_state_ins = Vec::with_capacity(live_slots);
    for input in inputs {
        let slots = evaluate_bucket(input).expect("prover asked to prove wrong bucket hash");
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
    let mut slot_offset = 0usize;
    for input in inputs {
        chain_claims.extend(
            chain_claims_at_offset(input, slot_offset, mle.num_vars)
                .expect("canonical inputs have chain claims"),
        );
        slot_offset += bucket_blocks(input).expect("canonical bucket").len();
    }
    let (chain, chain_red) = prove_linear_eval_prebound(
        &mle.state,
        &chain_claims,
        GUARD_BUCKET_LINEAR_RELATION_TAG,
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

    let proof = BatchedGuardBucketProofKillShot {
        kill_shot: BlockSpineKillShotProof { main, shift },
        chain,
        batch,
        n_buckets: inputs.len(),
        num_vars: mle.num_vars,
        live_slots: mle.live_slots,
    };
    let reductions = BatchedGuardBucketReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    };
    (proof, reductions)
}

pub fn verify_batched_guard_bucket_killshot<T: FiatShamir<Block128>>(
    proof: &BatchedGuardBucketProofKillShot,
    inputs: &[GuardBucketHashInputs],
    channel: &mut T,
) -> Option<BatchedGuardBucketReductions> {
    if inputs.is_empty()
        || proof.n_buckets != inputs.len()
        || !inputs.iter().all(inputs_are_canonical)
        || proof.live_slots != live_slots_for(inputs)?
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
    let mut slot_offset = 0usize;
    for input in inputs {
        chain_claims.extend(chain_claims_at_offset(input, slot_offset, proof.num_vars)?);
        slot_offset += bucket_blocks(input)?.len();
    }
    let chain_red = verify_linear_eval_prebound(
        &proof.chain,
        &chain_claims,
        proof.num_vars,
        GUARD_BUCKET_LINEAR_RELATION_TAG,
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

    Some(BatchedGuardBucketReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

pub fn discharge_batched_guard_bucket_reductions_native(
    inputs: &[GuardBucketHashInputs],
    reductions: &BatchedGuardBucketReductions,
) -> bool {
    if inputs.is_empty() || !inputs.iter().all(inputs_are_canonical) {
        return false;
    }
    let Some(live_slots) = live_slots_for(inputs) else {
        return false;
    };
    let mut slot_state_ins = Vec::with_capacity(live_slots);
    for input in inputs {
        let Some(slots) = evaluate_bucket(input) else {
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

    fn native_hash(input: &GuardBucketHashInputs) -> [Block128; 2] {
        let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_RGDBUCK));
        if input.occupied {
            s.absorb_pair(Block128::from(1u8), Block128::from(input.absolute_height));
            s.absorb(Block128::from(input.spent_slots.len() as u64));
            for &slot in &input.spent_slots {
                s.absorb(Block128::from(slot));
            }
        } else {
            s.absorb(Block128::ZERO);
        }
        fields_from_digest(s.finalize())
    }

    fn empty() -> GuardBucketHashInputs {
        let mut input = GuardBucketHashInputs {
            occupied: false,
            absolute_height: 0,
            spent_slots: vec![],
            expected_hash: [Block128::ZERO; 2],
        };
        input.expected_hash = native_hash(&input);
        input
    }

    fn occupied(height: u64, slots: &[u32]) -> GuardBucketHashInputs {
        let mut input = GuardBucketHashInputs {
            occupied: true,
            absolute_height: height,
            spent_slots: slots.to_vec(),
            expected_hash: [Block128::ZERO; 2],
        };
        input.expected_hash = native_hash(&input);
        input
    }

    #[test]
    fn batched_guard_bucket_roundtrip_empty_and_occupied() {
        let inputs = vec![empty(), occupied(10, &[2, 5, 13]), occupied(266, &[1])];
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) = prove_batched_guard_bucket_killshot(&inputs, &mut ch_p);

        let mut ch_v = Poseidon2bChannel::new();
        let verified = verify_batched_guard_bucket_killshot(&proof, &inputs, &mut ch_v)
            .expect("guard bucket proof verifies");
        assert_eq!(verified, reductions);
    }

    #[test]
    fn batched_guard_bucket_rejects_noncanonical_or_hash_tamper() {
        let inputs = vec![occupied(10, &[2, 5])];
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) = prove_batched_guard_bucket_killshot(&inputs, &mut ch_p);

        let mut bad = inputs.clone();
        bad[0].expected_hash[0] += Block128::ONE;
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_batched_guard_bucket_killshot(&proof, &bad, &mut ch_v).is_none());

        let noncanonical = vec![GuardBucketHashInputs {
            occupied: true,
            absolute_height: 10,
            spent_slots: vec![5, 2],
            expected_hash: [Block128::ZERO; 2],
        }];
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_batched_guard_bucket_killshot(&proof, &noncanonical, &mut ch_v).is_none());
    }
}
