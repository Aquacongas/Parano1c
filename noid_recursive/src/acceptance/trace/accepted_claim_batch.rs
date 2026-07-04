// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The accepted-claim batch CLAIM PART in the trace.
//!
//! Trace twin of the claim part of
//! `accepted_batch::verify_accepted_claim_batch_with_header_trace`: the
//! rolling `ChainAccumulator::extend` fold over `(block_id, chain_claim,
//! state_root, height)` per block, ending in the `end_accumulator` equality
//! that `verify_accepted_block_batch_components` checks on its output.
//!
//! The header part (`verify_header_integer_trace` — PoW/ASERT/MTP/chainwork
//! and the start-consensus equalities) is deliberately NOT replayed: header
//! consensus does not belong in the O(1) history proof. A fresh peer
//! verifies headers natively; the binding slot pins the same accumulator
//! lanes to the snapshot-decider anchors.
//!
//! `ChainAccumulator::extend` is two `compress` calls; `compress` is the
//! fixed two-permutation schedule (`compression.rs`): `[a0, a1, IV]` →
//! permute → rate += b → permute. The 32-byte digests travel as two lanes
//! (`Digest::as_fields` layout — the same φ-mapped lane convention as every
//! other slot).

use noid_core::Block128;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_COMPRESS};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use super::{
    alloc_block, const_block, pin_eq, poseidon2b_permute, FieldR1csBuilder, LinExpr,
};
use crate::accumulator::ChainAccumulator;

/// Digest as two little-endian u128 lanes (the `digest_to_fields`
/// convention).
pub fn digest_lanes(d: &[u8; 32]) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(d[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(d[16..].try_into().unwrap())),
    ]
}

/// Trace twin of `compress(a, b)` over lane expressions (2 permutations).
pub fn compress_trace(
    b: &mut FieldR1csBuilder,
    a_lanes: &[LinExpr; 2],
    b_lanes: &[LinExpr; 2],
) -> [LinExpr; 2] {
    let [iv_hi, iv_lo] = capacity_iv(TAG_COMPRESS);
    let state: [LinExpr; STATE_SIZE] = [
        a_lanes[0].clone(),
        a_lanes[1].clone(),
        const_block(iv_hi),
        const_block(iv_lo),
    ];
    let mut state = poseidon2b_permute(b, state);
    state[0] = state[0].add(&b_lanes[0]);
    state[1] = state[1].add(&b_lanes[1]);
    let state = poseidon2b_permute(b, state);
    [state[0].clone(), state[1].clone()]
}

/// One accumulator step's statement wires.
pub struct ClaimBatchStepWires {
    pub block_id: [LinExpr; 2],
    pub chain_claim: [LinExpr; 2],
    pub state_root: [LinExpr; 2],
    pub height: LinExpr,
}

/// Accumulator boundary wires (start/end).
pub struct AccumulatorWires {
    pub height: LinExpr,
    pub state_root: [LinExpr; 2],
    pub chain_hash: [LinExpr; 2],
}

impl AccumulatorWires {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &ChainAccumulator) -> Self {
        Self {
            height: alloc_block(b, Block128::from(native.height)),
            state_root: {
                let lanes = digest_lanes(&native.state_root);
                std::array::from_fn(|i| alloc_block(b, lanes[i]))
            },
            chain_hash: {
                let lanes = digest_lanes(&native.chain_hash);
                std::array::from_fn(|i| alloc_block(b, lanes[i]))
            },
        }
    }
}

/// Trace twin of the claim-part fold: `acc = acc.extend(state_root,
/// block_id, height, chain_claim)` per block, then the component's
/// `accepted_claim_batch.accumulator == end_accumulator` check as pins
/// (chain hash, final state root, final height).
///
/// Returns the per-step statement wires for the [B] bindings (they must be
/// shared with the checkpoint slot's chain-accumulator items and the
/// certificate statements at final proof assembly).
pub fn build_accepted_claim_batch_claim_slot(
    b: &mut FieldR1csBuilder,
    start: &AccumulatorWires,
    steps: &[ClaimBatchStepWires],
    end: &AccumulatorWires,
) {
    assert!(!steps.is_empty());

    let mut chain_hash = start.chain_hash.clone();
    for step in steps {
        // extend: inner = compress(block_id, claim_bytes);
        //         chain_hash = compress(chain_hash, inner).
        let inner = compress_trace(b, &step.block_id, &step.chain_claim);
        chain_hash = compress_trace(b, &chain_hash, &inner);
    }

    let last = steps.last().unwrap();
    pin_eq(b, &chain_hash[0], &end.chain_hash[0]);
    pin_eq(b, &chain_hash[1], &end.chain_hash[1]);
    pin_eq(b, &last.state_root[0], &end.state_root[0]);
    pin_eq(b, &last.state_root[1], &end.state_root[1]);
    pin_eq(b, &last.height, &end.height);
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::TowerField;

    fn wires_from(
        b: &mut FieldR1csBuilder,
        start: &ChainAccumulator,
        blocks: &[([u8; 32], [Block128; 2], [u8; 32], u64)],
        end: &ChainAccumulator,
    ) -> (AccumulatorWires, Vec<ClaimBatchStepWires>, AccumulatorWires) {
        let start_w = AccumulatorWires::alloc(b, start);
        let steps = blocks
            .iter()
            .map(|(block_id, claim, state_root, height)| {
                let id_lanes = digest_lanes(block_id);
                let root_lanes = digest_lanes(state_root);
                ClaimBatchStepWires {
                    block_id: std::array::from_fn(|i| alloc_block(b, id_lanes[i])),
                    chain_claim: std::array::from_fn(|i| alloc_block(b, claim[i])),
                    state_root: std::array::from_fn(|i| alloc_block(b, root_lanes[i])),
                    height: alloc_block(b, Block128::from(*height)),
                }
            })
            .collect();
        let end_w = AccumulatorWires::alloc(b, end);
        (start_w, steps, end_w)
    }

    fn fixture(n: usize) -> (
        ChainAccumulator,
        Vec<([u8; 32], [Block128; 2], [u8; 32], u64)>,
        ChainAccumulator,
    ) {
        let start = ChainAccumulator {
            height: 5,
            state_root: [9u8; 32],
            chain_hash: [3u8; 32],
        };
        let mut acc = start.clone();
        let mut blocks = Vec::new();
        for i in 0..n as u64 {
            let block_id = [10 + i as u8; 32];
            let claim = [Block128::from(100 + i as u128), Block128::from(200 + i as u128)];
            let state_root = [40 + i as u8; 32];
            let height = start.height + 1 + i;
            acc = acc.extend(state_root, block_id, height, claim);
            blocks.push((block_id, claim, state_root, height));
        }
        (start, blocks, acc)
    }

    /// Positive: the fold matches `ChainAccumulator::extend` and the end
    /// pins hold; a swapped claim breaks the trace exactly as the native
    /// component's accumulator equality breaks.
    #[test]
    fn claim_batch_fold_positive_and_tamper() {
        let (start, blocks, end) = fixture(2);

        let mut b = FieldR1csBuilder::new();
        let (start_w, steps, end_w) = wires_from(&mut b, &start, &blocks, &end);
        build_accepted_claim_batch_claim_slot(&mut b, &start_w, &steps, &end_w);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest claim-batch fold unsatisfiable");
        eprintln!(
            "claim-batch fold slot (2 blocks): {} useful rows (k_log = {})",
            r1cs.useful_rows, r1cs.k_log
        );

        // Every statement lane, mutated one at a time → unsat.
        for target in 0..(blocks.len() * 7 + 5 + 5) {
            let mut bad_blocks = blocks.clone();
            let mut bad_start = start.clone();
            let mut bad_end = end.clone();
            let per_block = 7usize;
            if target < blocks.len() * per_block {
                let (i, k) = (target / per_block, target % per_block);
                let blk = &mut bad_blocks[i];
                match k {
                    0 => blk.0[0] ^= 1,
                    1 => blk.0[17] ^= 1,
                    2 => blk.1[0] += Block128::ONE,
                    3 => blk.1[1] += Block128::ONE,
                    // state_root / height only matter for the LAST block's
                    // end pins — mutate the last block for those.
                    4 if i + 1 == blocks.len() => blk.2[0] ^= 1,
                    5 if i + 1 == blocks.len() => blk.2[17] ^= 1,
                    6 if i + 1 == blocks.len() => blk.3 ^= 1,
                    _ => continue,
                }
            } else if target < blocks.len() * per_block + 5 {
                match target - blocks.len() * per_block {
                    0 => bad_start.chain_hash[0] ^= 1,
                    1 => bad_start.chain_hash[17] ^= 1,
                    // start height/state_root are [B]-layer publics — not
                    // pinned by the claim fold itself.
                    _ => continue,
                }
            } else {
                match target - blocks.len() * per_block - 5 {
                    0 => bad_end.chain_hash[0] ^= 1,
                    1 => bad_end.chain_hash[17] ^= 1,
                    2 => bad_end.state_root[0] ^= 1,
                    3 => bad_end.state_root[17] ^= 1,
                    4 => bad_end.height ^= 1,
                    _ => continue,
                }
            }

            let mut b = FieldR1csBuilder::new();
            let (start_w, steps, end_w) = wires_from(&mut b, &bad_start, &bad_blocks, &bad_end);
            build_accepted_claim_batch_claim_slot(&mut b, &start_w, &steps, &end_w);
            let (r1cs, z) = b.build();
            assert!(
                !r1cs.satisfies(&z),
                "claim-batch mutant {target} produced a satisfiable trace"
            );
        }
    }

    /// The fold agrees with `ChainAccumulator::extend` lane-for-lane on a
    /// longer chain (5 blocks).
    #[test]
    fn claim_batch_fold_matches_native_chain() {
        let (start, blocks, end) = fixture(5);
        let mut b = FieldR1csBuilder::new();
        let (start_w, steps, end_w) = wires_from(&mut b, &start, &blocks, &end);
        build_accepted_claim_batch_claim_slot(&mut b, &start_w, &steps, &end_w);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
    }
}
