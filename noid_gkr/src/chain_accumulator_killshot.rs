// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Batched rolling chain-accumulator KillShot.
//!
//! This proves the Poseidon2b-heavy accumulator relation used by recursive
//! history:
//!
//! ```text
//! inner_i = COMPRESS(block_id_i, chain_claim_i)
//! acc_i   = COMPRESS(acc_{i-1}, inner_i)
//! ```
//!
//! The public statement is only `(start_acc, block_ids, claims, end_acc)`.
//! Intermediate accumulator values are witness state and are linked by the
//! linear chain constraints below.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_COMPRESS};
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

// Public: the in-circuit trace transliteration (`noid_recursive::acceptance::trace`)
// replays the chain relation from these same definitions; change both together.
pub const CHAIN_ACC_LINEAR_RELATION_TAG: u128 = 0x4348_4149_4E41_4301; // "CHAINAC"+1
pub const CHAIN_ACC_PERMS_PER_ITEM: usize = 4;
pub const CHAIN_ACC_PIN_LANES: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAccumulatorItem {
    pub block_id: [Block128; 2],
    pub chain_claim: [Block128; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainAccumulatorBatchInputs {
    pub start_chain_hash: [Block128; 2],
    pub items: Vec<ChainAccumulatorItem>,
    pub expected_chain_hash: [Block128; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainAccumulatorProofKillShot {
    pub kill_shot: BlockSpineKillShotProof,
    pub chain: LinearEvalProof,
    pub batch: MultiBatchEvalProof,
    pub n_items: usize,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl ChainAccumulatorProofKillShot {
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
pub struct ChainAccumulatorReductions {
    pub state: BatchEvalReduction,
    pub sin: BatchEvalReduction,
    pub sout: BatchEvalReduction,
}

fn absorb_digest_fields<T: FiatShamir<Block128>>(channel: &mut T, fields: [Block128; 2]) {
    channel.absorb(fields[0]);
    channel.absorb(fields[1]);
}

fn absorb_public_batch<T: FiatShamir<Block128>>(
    channel: &mut T,
    inputs: &ChainAccumulatorBatchInputs,
) {
    channel.absorb(Block128::from(inputs.items.len() as u128));
    channel.absorb(Block128::from(TAG_COMPRESS.as_u64() as u128));
    absorb_digest_fields(channel, inputs.start_chain_hash);
    absorb_digest_fields(channel, inputs.expected_chain_hash);
    for item in &inputs.items {
        absorb_digest_fields(channel, item.block_id);
        absorb_digest_fields(channel, item.chain_claim);
    }
}

fn zero_chain_accumulator_item() -> ChainAccumulatorItem {
    ChainAccumulatorItem {
        block_id: [Block128::ZERO; 2],
        chain_claim: [Block128::ZERO; 2],
    }
}

fn absorb_public_batch_padded<T: FiatShamir<Block128>>(
    channel: &mut T,
    inputs: &ChainAccumulatorBatchInputs,
    padded_items: usize,
) {
    channel.absorb(Block128::from(inputs.items.len() as u128));
    channel.absorb(Block128::from(padded_items as u128));
    channel.absorb(Block128::from(TAG_COMPRESS.as_u64() as u128));
    absorb_digest_fields(channel, inputs.start_chain_hash);
    absorb_digest_fields(channel, inputs.expected_chain_hash);
    let zero = zero_chain_accumulator_item();
    for idx in 0..padded_items {
        let item = inputs.items.get(idx).unwrap_or(&zero);
        absorb_digest_fields(channel, item.block_id);
        absorb_digest_fields(channel, item.chain_claim);
    }
}

fn evaluate_chain_accumulator(
    inputs: &ChainAccumulatorBatchInputs,
) -> Option<Vec<[Block128; STATE_SIZE]>> {
    if inputs.items.is_empty() {
        return None;
    }
    let [iv_hi, iv_lo] = capacity_iv(TAG_COMPRESS);
    let perm = Poseidon2bPermutation;
    let mut chain_hash = inputs.start_chain_hash;
    let mut slot_state_ins = Vec::with_capacity(inputs.items.len() * CHAIN_ACC_PERMS_PER_ITEM);

    for item in &inputs.items {
        let mut inner = [item.block_id[0], item.block_id[1], iv_hi, iv_lo];
        slot_state_ins.push(inner);
        perm.permute_mut(&mut inner);
        inner[0] += item.chain_claim[0];
        inner[1] += item.chain_claim[1];
        slot_state_ins.push(inner);
        perm.permute_mut(&mut inner);
        let inner_digest = [inner[0], inner[1]];

        let mut outer = [chain_hash[0], chain_hash[1], iv_hi, iv_lo];
        slot_state_ins.push(outer);
        perm.permute_mut(&mut outer);
        outer[0] += inner_digest[0];
        outer[1] += inner_digest[1];
        slot_state_ins.push(outer);
        perm.permute_mut(&mut outer);
        chain_hash = [outer[0], outer[1]];
    }

    if chain_hash != inputs.expected_chain_hash {
        return None;
    }
    Some(slot_state_ins)
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

fn push_prev_terms(
    terms: &mut Vec<LinearEvalTerm>,
    num_vars: usize,
    prev_slot: usize,
    row: usize,
    lanes: impl IntoIterator<Item = usize>,
) {
    for src_lane in lanes {
        terms.push(weighted_state_claim(
            num_vars,
            prev_slot,
            N_ROUNDS,
            src_lane,
            mds_coeff(row, src_lane),
        ));
    }
}

fn chain_claims(inputs: &ChainAccumulatorBatchInputs, num_vars: usize) -> Vec<LinearEvalClaim> {
    let [iv_hi, iv_lo] = capacity_iv(TAG_COMPRESS);
    let mut claims = Vec::with_capacity(
        inputs.items.len() * CHAIN_ACC_PERMS_PER_ITEM * STATE_SIZE + CHAIN_ACC_PIN_LANES,
    );

    for (idx, item) in inputs.items.iter().enumerate() {
        let base = idx * CHAIN_ACC_PERMS_PER_ITEM;

        for lane in 0..STATE_SIZE {
            claims.push(LinearEvalClaim {
                terms: vec![state_claim(num_vars, base, 0, lane)],
                value: mds_constant(
                    lane,
                    &[
                        (0, item.block_id[0]),
                        (1, item.block_id[1]),
                        (2, iv_hi),
                        (3, iv_lo),
                    ],
                ),
            });
        }

        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_claim(num_vars, base + 1, 0, lane)];
            push_prev_terms(&mut terms, num_vars, base, lane, 0..STATE_SIZE);
            claims.push(LinearEvalClaim {
                terms,
                value: mds_constant(lane, &[(0, item.chain_claim[0]), (1, item.chain_claim[1])]),
            });
        }

        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_claim(num_vars, base + 2, 0, lane)];
            let value = if idx == 0 {
                mds_constant(
                    lane,
                    &[
                        (0, inputs.start_chain_hash[0]),
                        (1, inputs.start_chain_hash[1]),
                        (2, iv_hi),
                        (3, iv_lo),
                    ],
                )
            } else {
                push_prev_terms(&mut terms, num_vars, base - 1, lane, [0usize, 1usize]);
                mds_constant(lane, &[(2, iv_hi), (3, iv_lo)])
            };
            claims.push(LinearEvalClaim { terms, value });
        }

        for lane in 0..STATE_SIZE {
            let mut terms = vec![state_claim(num_vars, base + 3, 0, lane)];
            push_prev_terms(&mut terms, num_vars, base + 2, lane, 0..STATE_SIZE);
            push_prev_terms(&mut terms, num_vars, base + 1, lane, [0usize, 1usize]);
            claims.push(LinearEvalClaim {
                terms,
                value: Block128::ZERO,
            });
        }
    }

    let last_slot = inputs.items.len() * CHAIN_ACC_PERMS_PER_ITEM - 1;
    for lane in 0..CHAIN_ACC_PIN_LANES {
        claims.push(LinearEvalClaim {
            terms: vec![state_claim(num_vars, last_slot, N_ROUNDS, lane)],
            value: inputs.expected_chain_hash[lane],
        });
    }

    claims
}

fn zero_state_claim(num_vars: usize, slot: usize, round: usize, lane: usize) -> LinearEvalTerm {
    weighted_state_claim(num_vars, slot, round, lane, Block128::ZERO)
}

fn push_zero_prev_terms(
    terms: &mut Vec<LinearEvalTerm>,
    num_vars: usize,
    prev_slot: usize,
    lanes: impl IntoIterator<Item = usize>,
) {
    for src_lane in lanes {
        terms.push(weighted_state_claim(
            num_vars,
            prev_slot,
            N_ROUNDS,
            src_lane,
            Block128::ZERO,
        ));
    }
}

fn zero_chain_item_claims(item_idx: usize, num_vars: usize) -> Vec<LinearEvalClaim> {
    let base = item_idx * CHAIN_ACC_PERMS_PER_ITEM;
    let mut claims = Vec::with_capacity(CHAIN_ACC_PERMS_PER_ITEM * STATE_SIZE);

    for lane in 0..STATE_SIZE {
        claims.push(LinearEvalClaim {
            terms: vec![zero_state_claim(num_vars, base, 0, lane)],
            value: Block128::ZERO,
        });
    }

    for lane in 0..STATE_SIZE {
        let mut terms = vec![zero_state_claim(num_vars, base + 1, 0, lane)];
        push_zero_prev_terms(&mut terms, num_vars, base, 0..STATE_SIZE);
        claims.push(LinearEvalClaim {
            terms,
            value: Block128::ZERO,
        });
    }

    for lane in 0..STATE_SIZE {
        let mut terms = vec![zero_state_claim(num_vars, base + 2, 0, lane)];
        if item_idx > 0 {
            push_zero_prev_terms(&mut terms, num_vars, base - 1, [0usize, 1usize]);
        }
        claims.push(LinearEvalClaim {
            terms,
            value: Block128::ZERO,
        });
    }

    for lane in 0..STATE_SIZE {
        let mut terms = vec![zero_state_claim(num_vars, base + 3, 0, lane)];
        push_zero_prev_terms(&mut terms, num_vars, base + 2, 0..STATE_SIZE);
        push_zero_prev_terms(&mut terms, num_vars, base + 1, [0usize, 1usize]);
        claims.push(LinearEvalClaim {
            terms,
            value: Block128::ZERO,
        });
    }

    claims
}

fn chain_claims_padded(
    inputs: &ChainAccumulatorBatchInputs,
    padded_items: usize,
    num_vars: usize,
) -> Vec<LinearEvalClaim> {
    let mut claims = chain_claims(inputs, num_vars);
    if inputs.items.len() < padded_items {
        claims.reserve((padded_items - inputs.items.len()) * CHAIN_ACC_PERMS_PER_ITEM * STATE_SIZE);
        for item_idx in inputs.items.len()..padded_items {
            claims.extend(zero_chain_item_claims(item_idx, num_vars));
        }
    }
    claims
}

pub fn prove_chain_accumulator_killshot<T: FiatShamir<Block128>>(
    inputs: &ChainAccumulatorBatchInputs,
    channel: &mut T,
) -> (ChainAccumulatorProofKillShot, ChainAccumulatorReductions) {
    prove_chain_accumulator_killshot_with_shape(inputs, inputs.items.len(), false, channel)
}

pub fn prove_chain_accumulator_killshot_padded<T: FiatShamir<Block128>>(
    inputs: &ChainAccumulatorBatchInputs,
    padded_items: usize,
    channel: &mut T,
) -> (ChainAccumulatorProofKillShot, ChainAccumulatorReductions) {
    prove_chain_accumulator_killshot_with_shape(inputs, padded_items, true, channel)
}

fn prove_chain_accumulator_killshot_with_shape<T: FiatShamir<Block128>>(
    inputs: &ChainAccumulatorBatchInputs,
    padded_items: usize,
    pad_public_transcript: bool,
    channel: &mut T,
) -> (ChainAccumulatorProofKillShot, ChainAccumulatorReductions) {
    let slot_state_ins =
        evaluate_chain_accumulator(inputs).expect("prover asked to prove wrong chain accumulator");
    assert!(inputs.items.len() <= padded_items);
    let padded_live_slots = padded_items * CHAIN_ACC_PERMS_PER_ITEM;

    if pad_public_transcript {
        absorb_public_batch_padded(channel, inputs, padded_items);
    } else {
        absorb_public_batch(channel, inputs);
    }

    let mle = BlockSpineMle::build_from_slot_state_ins_padded(&slot_state_ins, padded_live_slots);
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

    let chain_claims = if pad_public_transcript {
        chain_claims_padded(inputs, padded_items, mle.num_vars)
    } else {
        chain_claims(inputs, mle.num_vars)
    };
    let (chain, chain_red) = prove_linear_eval_prebound(
        &mle.state,
        &chain_claims,
        CHAIN_ACC_LINEAR_RELATION_TAG,
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

    let proof = ChainAccumulatorProofKillShot {
        kill_shot: BlockSpineKillShotProof { main, shift },
        chain,
        batch,
        n_items: inputs.items.len(),
        num_vars: mle.num_vars,
        live_slots: mle.live_slots,
    };
    let reductions = ChainAccumulatorReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    };
    (proof, reductions)
}

pub fn verify_chain_accumulator_killshot<T: FiatShamir<Block128>>(
    proof: &ChainAccumulatorProofKillShot,
    inputs: &ChainAccumulatorBatchInputs,
    channel: &mut T,
) -> Option<ChainAccumulatorReductions> {
    verify_chain_accumulator_killshot_with_shape(proof, inputs, inputs.items.len(), false, channel)
}

pub fn verify_chain_accumulator_killshot_padded<T: FiatShamir<Block128>>(
    proof: &ChainAccumulatorProofKillShot,
    inputs: &ChainAccumulatorBatchInputs,
    padded_items: usize,
    channel: &mut T,
) -> Option<ChainAccumulatorReductions> {
    verify_chain_accumulator_killshot_with_shape(proof, inputs, padded_items, true, channel)
}

fn verify_chain_accumulator_killshot_with_shape<T: FiatShamir<Block128>>(
    proof: &ChainAccumulatorProofKillShot,
    inputs: &ChainAccumulatorBatchInputs,
    padded_items: usize,
    pad_public_transcript: bool,
    channel: &mut T,
) -> Option<ChainAccumulatorReductions> {
    if inputs.items.is_empty()
        || proof.n_items != inputs.items.len()
        || inputs.items.len() > padded_items
        || proof.live_slots != padded_items * CHAIN_ACC_PERMS_PER_ITEM
    {
        return None;
    }
    let expected_num_vars = crate::block_spine::num_vars_for(proof.live_slots);
    if proof.num_vars != expected_num_vars {
        return None;
    }

    if pad_public_transcript {
        absorb_public_batch_padded(channel, inputs, padded_items);
    } else {
        absorb_public_batch(channel, inputs);
    }

    let main_red = verify_block_spine_unified(
        &proof.kill_shot.main,
        proof.num_vars,
        proof.live_slots,
        channel,
    )?;
    let shift_red =
        verify_block_spine_shift(&proof.kill_shot.shift, &main_red, proof.num_vars, channel)?;

    let chain_claims = if pad_public_transcript {
        chain_claims_padded(inputs, padded_items, proof.num_vars)
    } else {
        chain_claims(inputs, proof.num_vars)
    };
    let chain_red = verify_linear_eval_prebound(
        &proof.chain,
        &chain_claims,
        proof.num_vars,
        CHAIN_ACC_LINEAR_RELATION_TAG,
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

    Some(ChainAccumulatorReductions {
        state: state_red,
        sin: sin_red,
        sout: sout_red,
    })
}

pub fn discharge_chain_accumulator_reductions_native(
    inputs: &ChainAccumulatorBatchInputs,
    reductions: &ChainAccumulatorReductions,
) -> bool {
    discharge_chain_accumulator_reductions_native_padded(inputs, reductions, inputs.items.len())
}

pub fn discharge_chain_accumulator_reductions_native_padded(
    inputs: &ChainAccumulatorBatchInputs,
    reductions: &ChainAccumulatorReductions,
    padded_items: usize,
) -> bool {
    let Some(slot_state_ins) = evaluate_chain_accumulator(inputs) else {
        return false;
    };
    let padded_live_slots = padded_items * CHAIN_ACC_PERMS_PER_ITEM;
    if slot_state_ins.len() > padded_live_slots {
        return false;
    }
    let mut slot_state_ins = slot_state_ins;
    slot_state_ins.resize(padded_live_slots, [Block128::ZERO; STATE_SIZE]);
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
    use noid_core::TowerField;
    use noid_poseidon2b::channel::Poseidon2bChannel;
    use noid_poseidon2b::native::compress;

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

    fn digest_from_fields(fields: [Block128; 2]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&fields[0].to_u128().to_le_bytes());
        out[16..].copy_from_slice(&fields[1].to_u128().to_le_bytes());
        out
    }

    fn claim_bytes(claim: [Block128; 2]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&claim[0].to_u128().to_le_bytes());
        out[16..].copy_from_slice(&claim[1].to_u128().to_le_bytes());
        out
    }

    fn inputs(n: usize) -> ChainAccumulatorBatchInputs {
        let start_chain_hash = fields_from_digest([0xA1; 32]);
        let mut chain = digest_from_fields(start_chain_hash);
        let mut items = Vec::with_capacity(n);
        for i in 0..n {
            let block_id = [i as u8 + 1; 32];
            let claim = [
                Block128::from(0xCAFE_0000_u128 + i as u128),
                Block128::from(0xF00D_0000_u128 + i as u128),
            ];
            let inner = compress(&block_id, &claim_bytes(claim));
            chain = compress(&chain, &inner);
            items.push(ChainAccumulatorItem {
                block_id: fields_from_digest(block_id),
                chain_claim: claim,
            });
        }
        ChainAccumulatorBatchInputs {
            start_chain_hash,
            items,
            expected_chain_hash: fields_from_digest(chain),
        }
    }

    #[test]
    fn chain_accumulator_roundtrip() {
        let inputs = inputs(4);
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) = prove_chain_accumulator_killshot(&inputs, &mut ch_p);

        let mut ch_v = Poseidon2bChannel::new();
        let verified = verify_chain_accumulator_killshot(&proof, &inputs, &mut ch_v)
            .expect("chain accumulator proof verifies");
        assert_eq!(verified, reductions);
    }

    #[test]
    fn chain_accumulator_padded_roundtrip_size_constant_and_rejects_small_shape() {
        let padded_items = 4;
        let mut expected_len = None;

        for n in [1usize, 3, padded_items] {
            let inputs = inputs(n);
            let mut ch_p = Poseidon2bChannel::new();
            let (proof, reductions) =
                prove_chain_accumulator_killshot_padded(&inputs, padded_items, &mut ch_p);
            assert_eq!(proof.n_items, n);
            assert_eq!(proof.live_slots, padded_items * CHAIN_ACC_PERMS_PER_ITEM);

            let mut ch_v = Poseidon2bChannel::new();
            let verified =
                verify_chain_accumulator_killshot_padded(&proof, &inputs, padded_items, &mut ch_v)
                    .expect("padded chain accumulator proof verifies");
            assert_eq!(verified, reductions);
            assert!(discharge_chain_accumulator_reductions_native_padded(
                &inputs,
                &verified,
                padded_items,
            ));

            if let Some(expected_len) = expected_len {
                assert_eq!(proof.byte_len(), expected_len);
            } else {
                expected_len = Some(proof.byte_len());
            }

            if n < padded_items {
                let mut ch_small = Poseidon2bChannel::new();
                assert!(verify_chain_accumulator_killshot_padded(
                    &proof,
                    &inputs,
                    n,
                    &mut ch_small
                )
                .is_none());
            }
        }

        let inputs = inputs(1);
        let mut ch_p = Poseidon2bChannel::new();
        let (small_shape_proof, _) = prove_chain_accumulator_killshot(&inputs, &mut ch_p);
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_chain_accumulator_killshot_padded(
            &small_shape_proof,
            &inputs,
            padded_items,
            &mut ch_v,
        )
        .is_none());
    }

    #[test]
    fn chain_accumulator_rejects_tamper() {
        let inputs = inputs(3);
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) = prove_chain_accumulator_killshot(&inputs, &mut ch_p);

        let mut bad = inputs.clone();
        bad.expected_chain_hash[0] += Block128::ONE;
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_chain_accumulator_killshot(&proof, &bad, &mut ch_v).is_none());
    }
}
