// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Batched ReuseGuard bucket-update hash KillShot.
//!
//! Proves one block's guard bucket update as three sponge chains whose
//! schedule depends only on the block's shape class:
//!
//! 1. the OLD bucket leaf — the fixed four-field `RGDBUCK_` sponge over
//!    `(occupied, absolute_height, slots_digest)`. The old bucket's spent
//!    list stays behind its nested digest, so replaying this chain never
//!    grows with historical bucket contents;
//! 2. the NEW bucket leaf — the same fixed leaf sponge;
//! 3. the NEW bucket's spent-slot list — the `RGDSLOT_` sponge over
//!    `(len, slots...)`, laid out over `padded_spent_len` (the class's
//!    spend capacity) MLE slots. Chain positions past the real list carry
//!    zero-coefficient claims and zero permutation slots, and the final
//!    digest pins select the last live chain position through boundary
//!    indicators, so the claim structure is a pure function of the class.
//!
//! The Merkle path over bucket leaves is proved separately under `RGDNODE`;
//! this module binds bucket contents to the leaf digests.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_RGDBUCK, TAG_RGDSLOT};
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

pub const GUARD_BUCKET_LINEAR_RELATION_TAG: u128 = 0x5247_4442_5543_4B01; // "RGDBUCK"+1
pub const GUARD_BUCKET_PIN_LANES: usize = 2;
/// MLE slots of one fixed-form bucket leaf chain.
pub const GUARD_LEAF_CHAIN_SLOTS: usize = 3;

/// One guard bucket leaf statement: the fixed four-field leaf sponge
/// preimage plus its expected digest. Empty buckets carry all-zero
/// height/digest with `occupied = false`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GuardLeafHashInputs {
    pub occupied: bool,
    pub absolute_height: u64,
    pub slots_digest: [Block128; 2],
    pub expected_hash: [Block128; 2],
}

/// The full per-block guard update statement: old and new leaves plus the
/// new bucket's spent-slot list. The list's digest is `new_leaf.slots_digest`
/// (bound by the slots chain); `padded_spent_len` is the shape class's spend
/// capacity and fixes the killshot schedule.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GuardBucketUpdateInputs {
    pub old_leaf: GuardLeafHashInputs,
    pub new_leaf: GuardLeafHashInputs,
    pub spent_slots: Vec<u32>,
    pub padded_spent_len: usize,
}

/// Chain length (MLE slots) of the spent-slot sponge for a list of `len`
/// entries: `len + 1` absorbed fields in two-lane blocks plus the padding
/// tail block.
#[inline]
pub const fn guard_slots_chain_len(len: usize) -> usize {
    (len + 1) / 2 + 1
}

/// Total MLE slots of the class-shaped guard update killshot.
#[inline]
pub const fn guard_update_live_slots(padded_spent_len: usize) -> usize {
    2 * GUARD_LEAF_CHAIN_SLOTS + guard_slots_chain_len(padded_spent_len)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BatchedGuardBucketProofKillShot {
    pub kill_shot: BlockSpineKillShotProof,
    pub chain: LinearEvalProof,
    pub batch: MultiBatchEvalProof,
    pub padded_spent_len: usize,
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

fn absorb_public_leaf<T: FiatShamir<Block128>>(channel: &mut T, leaf: &GuardLeafHashInputs) {
    channel.absorb(Block128::from(leaf.occupied as u128));
    channel.absorb(Block128::from(leaf.absolute_height));
    channel.absorb(leaf.slots_digest[0]);
    channel.absorb(leaf.slots_digest[1]);
    channel.absorb(leaf.expected_hash[0]);
    channel.absorb(leaf.expected_hash[1]);
}

fn absorb_public_batch<T: FiatShamir<Block128>>(channel: &mut T, inputs: &GuardBucketUpdateInputs) {
    channel.absorb(Block128::from(TAG_RGDBUCK.as_u64() as u128));
    channel.absorb(Block128::from(inputs.padded_spent_len as u128));
    absorb_public_leaf(channel, &inputs.old_leaf);
    absorb_public_leaf(channel, &inputs.new_leaf);
    // The slot vector absorbs at its padded width so the schedule is a
    // class constant; the live length disambiguates the zero fill.
    channel.absorb(Block128::from(inputs.spent_slots.len() as u128));
    for q in 0..inputs.padded_spent_len {
        let slot = inputs.spent_slots.get(q).copied().unwrap_or(0);
        channel.absorb(Block128::from(slot));
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

fn inputs_are_canonical(inputs: &GuardBucketUpdateInputs) -> bool {
    let old_ok = if inputs.old_leaf.occupied {
        true
    } else {
        inputs.old_leaf.absolute_height == 0
            && inputs.old_leaf.slots_digest == [Block128::ZERO; 2]
    };
    old_ok
        && inputs.new_leaf.occupied
        && !inputs.spent_slots.is_empty()
        && inputs.spent_slots.windows(2).all(|w| w[0] < w[1])
        && inputs.spent_slots.len() <= inputs.padded_spent_len
}

/// The fixed three-block leaf chain: `(occupied, height)`, the digest pair,
/// then the sponge padding block.
fn leaf_blocks(leaf: &GuardLeafHashInputs) -> [[Block128; 2]; GUARD_LEAF_CHAIN_SLOTS] {
    [
        [
            Block128::from(leaf.occupied as u128),
            Block128::from(leaf.absolute_height),
        ],
        leaf.slots_digest,
        pad_empty_block(),
    ]
}

/// Absorbed-field stream of the spent-slot sponge at position `q`, over the
/// class-padded position range. Positions past the live stream return the
/// padding constants at the two boundary offsets and zero beyond — exactly
/// the values the selector algebra in the trace twin reconstructs.
fn slots_field_at(spent_slots: &[u32], q: usize) -> Block128 {
    let len = spent_slots.len();
    if q == 0 {
        Block128::from(len as u64)
    } else if q <= len {
        Block128::from(spent_slots[q - 1])
    } else if q == len + 1 {
        if q % 2 == 0 {
            pad_empty_block()[0]
        } else {
            pad_after_one_field()
        }
    } else if q == len + 2 && q % 2 == 1 {
        pad_empty_block()[1]
    } else {
        Block128::ZERO
    }
}

/// The spent-slot chain blocks over the padded schedule: `chain_len(len)`
/// live blocks followed by all-zero ghost blocks up to the class capacity.
fn slots_blocks_padded(spent_slots: &[u32], padded_spent_len: usize) -> Vec<[Block128; 2]> {
    (0..guard_slots_chain_len(padded_spent_len))
        .map(|p| [slots_field_at(spent_slots, 2 * p), slots_field_at(spent_slots, 2 * p + 1)])
        .collect()
}

fn evaluate_chain(
    blocks: &[[Block128; 2]],
    live_blocks: usize,
    iv: [Block128; 2],
    expected: Option<[Block128; 2]>,
) -> Option<Vec<[Block128; STATE_SIZE]>> {
    let [iv_hi, iv_lo] = iv;
    let perm = Poseidon2bPermutation;
    let mut state = [Block128::ZERO, Block128::ZERO, iv_hi, iv_lo];
    let mut ins = Vec::with_capacity(blocks.len());
    for (idx, block) in blocks.iter().enumerate() {
        if idx < live_blocks {
            state[0] += block[0];
            state[1] += block[1];
            ins.push(state);
            perm.permute_mut(&mut state);
            if idx + 1 == live_blocks {
                if let Some(expected) = expected {
                    if [state[0], state[1]] != expected {
                        return None;
                    }
                }
            }
        } else {
            // Ghost chain position: an isolated zero-input permutation slot.
            ins.push([Block128::ZERO; STATE_SIZE]);
        }
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

/// Claims of one fixed-length leaf chain (head, chained blocks, digest pins).
fn leaf_chain_claims(
    leaf: &GuardLeafHashInputs,
    slot_offset: usize,
    num_vars: usize,
) -> Vec<LinearEvalClaim> {
    let blocks = leaf_blocks(leaf);
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
            value: leaf.expected_hash[lane],
        });
    }
    claims
}

/// Field-position liveness of the spent-slot stream: `h(q) = [q <= len]`,
/// with `h(0) = 1` (the length field is always absorbed). Chain-block
/// liveness and the last-block boundary indicators are derived from it:
/// block `p` is live iff `h(2p - 1)`, and the boundary at block `p` is
/// `h(2p - 1) + h(2p + 1)` (char-2 difference of a monotone sequence).
#[inline]
fn slots_h(len: usize, q: isize) -> Block128 {
    if q <= len as isize {
        Block128::ONE
    } else {
        Block128::ZERO
    }
}

/// Claims of the class-padded spent-slot chain. Every coefficient is the
/// class-fixed term structure scaled by the liveness/boundary indicators,
/// so ghost positions carry zero-coefficient claims and the digest pins
/// select the last live block — the claim layout is a pure function of
/// `padded_spent_len`.
fn slots_chain_claims(
    spent_slots: &[u32],
    digest: [Block128; 2],
    padded_spent_len: usize,
    slot_offset: usize,
    num_vars: usize,
) -> Vec<LinearEvalClaim> {
    let len = spent_slots.len();
    let chain_len = guard_slots_chain_len(padded_spent_len);
    let [iv_hi, iv_lo] = capacity_iv(TAG_RGDSLOT);
    let mut claims = Vec::with_capacity(chain_len * STATE_SIZE + GUARD_BUCKET_PIN_LANES);

    for p in 0..chain_len {
        let slot = slot_offset + p;
        let block = [
            slots_field_at(spent_slots, 2 * p),
            slots_field_at(spent_slots, 2 * p + 1),
        ];
        let live = if p == 0 {
            Block128::ONE
        } else {
            slots_h(len, 2 * p as isize - 1)
        };
        for lane in 0..STATE_SIZE {
            let mut terms = vec![weighted_state_claim(num_vars, slot, 0, lane, live)];
            let value = if p == 0 {
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
                        live * mds_coeff(lane, src_lane),
                    ));
                }
                live * mds_constant(lane, &[(0, block[0]), (1, block[1])])
            };
            claims.push(LinearEvalClaim { terms, value });
        }
    }

    for lane in 0..GUARD_BUCKET_PIN_LANES {
        let terms = (0..chain_len)
            .map(|p| {
                let boundary =
                    slots_h(len, 2 * p as isize - 1) + slots_h(len, 2 * p as isize + 1);
                weighted_state_claim(num_vars, slot_offset + p, N_ROUNDS, lane, boundary)
            })
            .collect();
        claims.push(LinearEvalClaim {
            terms,
            value: digest[lane],
        });
    }
    claims
}

fn guard_update_chain_claims(
    inputs: &GuardBucketUpdateInputs,
    num_vars: usize,
) -> Vec<LinearEvalClaim> {
    let mut claims = leaf_chain_claims(&inputs.old_leaf, 0, num_vars);
    claims.extend(leaf_chain_claims(
        &inputs.new_leaf,
        GUARD_LEAF_CHAIN_SLOTS,
        num_vars,
    ));
    claims.extend(slots_chain_claims(
        &inputs.spent_slots,
        inputs.new_leaf.slots_digest,
        inputs.padded_spent_len,
        2 * GUARD_LEAF_CHAIN_SLOTS,
        num_vars,
    ));
    claims
}

pub fn prove_batched_guard_bucket_killshot<T: FiatShamir<Block128>>(
    inputs: &GuardBucketUpdateInputs,
    channel: &mut T,
) -> (
    BatchedGuardBucketProofKillShot,
    BatchedGuardBucketReductions,
) {
    assert!(inputs_are_canonical(inputs), "non-canonical guard update");

    let live_slots = guard_update_live_slots(inputs.padded_spent_len);
    let mut slot_state_ins = Vec::with_capacity(live_slots);
    let leaf_iv = capacity_iv(TAG_RGDBUCK);
    for leaf in [&inputs.old_leaf, &inputs.new_leaf] {
        let blocks = leaf_blocks(leaf);
        let slots = evaluate_chain(
            &blocks,
            blocks.len(),
            leaf_iv,
            Some(leaf.expected_hash),
        )
        .expect("prover asked to prove wrong guard leaf hash");
        slot_state_ins.extend(slots);
    }
    let slots_blocks = slots_blocks_padded(&inputs.spent_slots, inputs.padded_spent_len);
    let slots = evaluate_chain(
        &slots_blocks,
        guard_slots_chain_len(inputs.spent_slots.len()),
        capacity_iv(TAG_RGDSLOT),
        Some(inputs.new_leaf.slots_digest),
    )
    .expect("prover asked to prove wrong spent-slot digest");
    slot_state_ins.extend(slots);
    debug_assert_eq!(slot_state_ins.len(), live_slots);

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

    let chain_claims = guard_update_chain_claims(inputs, mle.num_vars);
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
        padded_spent_len: inputs.padded_spent_len,
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
    inputs: &GuardBucketUpdateInputs,
    channel: &mut T,
) -> Option<BatchedGuardBucketReductions> {
    if !inputs_are_canonical(inputs)
        || proof.padded_spent_len != inputs.padded_spent_len
        || proof.live_slots != guard_update_live_slots(inputs.padded_spent_len)
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

    let chain_claims = guard_update_chain_claims(inputs, proof.num_vars);
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
    inputs: &GuardBucketUpdateInputs,
    reductions: &BatchedGuardBucketReductions,
) -> bool {
    if !inputs_are_canonical(inputs) {
        return false;
    }
    let mut slot_state_ins = Vec::with_capacity(guard_update_live_slots(inputs.padded_spent_len));
    let leaf_iv = capacity_iv(TAG_RGDBUCK);
    for leaf in [&inputs.old_leaf, &inputs.new_leaf] {
        let blocks = leaf_blocks(leaf);
        let Some(slots) =
            evaluate_chain(&blocks, blocks.len(), leaf_iv, Some(leaf.expected_hash))
        else {
            return false;
        };
        slot_state_ins.extend(slots);
    }
    let slots_blocks = slots_blocks_padded(&inputs.spent_slots, inputs.padded_spent_len);
    let Some(slots) = evaluate_chain(
        &slots_blocks,
        guard_slots_chain_len(inputs.spent_slots.len()),
        capacity_iv(TAG_RGDSLOT),
        Some(inputs.new_leaf.slots_digest),
    ) else {
        return false;
    };
    slot_state_ins.extend(slots);
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

    fn native_slots_digest(slots: &[u32]) -> [Block128; 2] {
        let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_RGDSLOT));
        s.absorb(Block128::from(slots.len() as u64));
        for &slot in slots {
            s.absorb(Block128::from(slot));
        }
        fields_from_digest(s.finalize())
    }

    fn native_leaf_hash(
        occupied: bool,
        height: u64,
        digest: [Block128; 2],
    ) -> [Block128; 2] {
        let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_RGDBUCK));
        s.absorb_pair(Block128::from(occupied as u128), Block128::from(height));
        s.absorb_pair(digest[0], digest[1]);
        fields_from_digest(s.finalize())
    }

    fn empty_leaf() -> GuardLeafHashInputs {
        let digest = [Block128::ZERO; 2];
        GuardLeafHashInputs {
            occupied: false,
            absolute_height: 0,
            slots_digest: digest,
            expected_hash: native_leaf_hash(false, 0, digest),
        }
    }

    fn occupied_leaf(height: u64, slots: &[u32]) -> GuardLeafHashInputs {
        let digest = native_slots_digest(slots);
        GuardLeafHashInputs {
            occupied: true,
            absolute_height: height,
            slots_digest: digest,
            expected_hash: native_leaf_hash(true, height, digest),
        }
    }

    fn update(old: GuardLeafHashInputs, height: u64, slots: &[u32], capacity: usize) -> GuardBucketUpdateInputs {
        GuardBucketUpdateInputs {
            old_leaf: old,
            new_leaf: occupied_leaf(height, slots),
            spent_slots: slots.to_vec(),
            padded_spent_len: capacity,
        }
    }

    #[test]
    fn guard_update_roundtrip_empty_and_occupied_old() {
        for (inputs, label) in [
            (update(empty_leaf(), 266, &[2, 5, 13], 8), "empty old"),
            (
                update(occupied_leaf(10, &[7, 9, 11, 20, 33]), 266, &[1], 8),
                "occupied old",
            ),
            (
                update(empty_leaf(), 266, &[1, 2, 3, 4, 5, 6, 7, 8], 8),
                "full capacity",
            ),
        ] {
            let mut ch_p = Poseidon2bChannel::new();
            let (proof, reductions) = prove_batched_guard_bucket_killshot(&inputs, &mut ch_p);
            let mut ch_v = Poseidon2bChannel::new();
            let verified = verify_batched_guard_bucket_killshot(&proof, &inputs, &mut ch_v)
                .unwrap_or_else(|| panic!("guard update proof verifies ({label})"));
            assert_eq!(verified, reductions, "{label}");
            assert!(
                discharge_batched_guard_bucket_reductions_native(&inputs, &reductions),
                "{label}"
            );
        }
    }

    #[test]
    fn guard_update_same_class_shapes_match_across_lengths() {
        // Two updates in one class (capacity 8) with different live spend
        // counts must produce the same schedule (live_slots / num_vars) and
        // the same claim layout (claim count and per-claim term counts).
        let a = update(empty_leaf(), 266, &[2], 8);
        let b = update(occupied_leaf(9, &[3, 4, 5]), 266, &[1, 2, 3, 4, 5, 6, 7], 8);
        assert_eq!(
            guard_update_live_slots(a.padded_spent_len),
            guard_update_live_slots(b.padded_spent_len)
        );
        let ca = guard_update_chain_claims(&a, 6);
        let cb = guard_update_chain_claims(&b, 6);
        assert_eq!(ca.len(), cb.len());
        for (x, y) in ca.iter().zip(cb.iter()) {
            assert_eq!(x.terms.len(), y.terms.len());
        }
    }

    #[test]
    fn guard_update_rejects_noncanonical_or_hash_tamper() {
        let inputs = update(empty_leaf(), 10, &[2, 5], 8);
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _) = prove_batched_guard_bucket_killshot(&inputs, &mut ch_p);

        let mut bad = inputs.clone();
        bad.new_leaf.expected_hash[0] += Block128::ONE;
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_batched_guard_bucket_killshot(&proof, &bad, &mut ch_v).is_none());

        let mut bad = inputs.clone();
        bad.new_leaf.slots_digest[1] += Block128::ONE;
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_batched_guard_bucket_killshot(&proof, &bad, &mut ch_v).is_none());

        let mut bad = inputs.clone();
        bad.old_leaf.absolute_height = 3; // non-canonical: empty leaf with height
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_batched_guard_bucket_killshot(&proof, &bad, &mut ch_v).is_none());

        let mut bad = inputs.clone();
        bad.spent_slots = vec![5, 2];
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_batched_guard_bucket_killshot(&proof, &bad, &mut ch_v).is_none());

        let mut bad = inputs;
        bad.padded_spent_len = 16;
        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_batched_guard_bucket_killshot(&proof, &bad, &mut ch_v).is_none());
    }
}
