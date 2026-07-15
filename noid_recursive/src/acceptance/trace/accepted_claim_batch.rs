// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Direct ten-lane chain-accumulator transition in the acceptance trace.
//!
//! There is no rolling chain hash and no accepted-claim digest fold. One
//! block proof exposes the parent boundary and proves that the header is its
//! exact child. The child header supplies the new tip, state, depth and
//! counters directly; the transaction-epoch anchor changes to the child id
//! exactly when the constrained child height is divisible by 144.

use noid_core::Block128;
use noid_poseidon2b::native::domain::{capacity_iv, DomainTag, TAG_COMPRESS};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use super::tx_epoch::constrain_tx_epoch_boundary;
use super::{
    alloc_block, const_block, flat_const, mul, pin_eq, pin_zero, poseidon2b_permute,
    range_check_bits, FieldR1csBuilder, LinExpr, Wire, F128,
};
use crate::accumulator::{ChainAccumulator, CHAIN_ACCUMULATOR_LANES};

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
    compress_with_tag_trace(b, TAG_COMPRESS, a_lanes, b_lanes)
}

/// Trace twin of `compress_with_tag(tag, a, b)`.
pub fn compress_with_tag_trace(
    b: &mut FieldR1csBuilder,
    tag: DomainTag,
    a_lanes: &[LinExpr; 2],
    b_lanes: &[LinExpr; 2],
) -> [LinExpr; 2] {
    let [iv_hi, iv_lo] = capacity_iv(tag);
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

/// The child-header values consumed by the direct transition.
pub struct DirectChildWires {
    pub block_id: [LinExpr; 2],
    pub prev_block_hash: [LinExpr; 2],
    pub state_root: [LinExpr; 2],
    pub height: LinExpr,
    pub log_slots: LinExpr,
    pub active_slot_count: LinExpr,
    pub alloc_counter: LinExpr,
}

/// Accumulator boundary wires (start/end).
pub struct AccumulatorWires {
    pub height: LinExpr,
    pub tip_block_id: [LinExpr; 2],
    pub state_root: [LinExpr; 2],
    pub log_slots: LinExpr,
    pub active_slot_count: LinExpr,
    pub alloc_counter: LinExpr,
    pub epoch_anchor_id: [LinExpr; 2],
}

impl AccumulatorWires {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &ChainAccumulator) -> Self {
        let lanes = native.to_lanes().map(|lane| alloc_block(b, lane));
        Self::from_ordered_lanes(lanes)
    }

    /// Build named wires from the consensus-significant lane order.
    pub fn from_ordered_lanes(lanes: [LinExpr; CHAIN_ACCUMULATOR_LANES]) -> Self {
        Self {
            height: lanes[0].clone(),
            tip_block_id: [lanes[1].clone(), lanes[2].clone()],
            state_root: [lanes[3].clone(), lanes[4].clone()],
            log_slots: lanes[5].clone(),
            active_slot_count: lanes[6].clone(),
            alloc_counter: lanes[7].clone(),
            epoch_anchor_id: [lanes[8].clone(), lanes[9].clone()],
        }
    }

    /// Return the exact lane order used by block/link public IO.
    pub fn ordered_lanes(&self) -> [LinExpr; CHAIN_ACCUMULATOR_LANES] {
        [
            self.height.clone(),
            self.tip_block_id[0].clone(),
            self.tip_block_id[1].clone(),
            self.state_root[0].clone(),
            self.state_root[1].clone(),
            self.log_slots.clone(),
            self.active_slot_count.clone(),
            self.alloc_counter.clone(),
            self.epoch_anchor_id[0].clone(),
            self.epoch_anchor_id[1].clone(),
        ]
    }
}

/// Range-check every scalar accumulator lane and return the height and
/// height bits for the exact successor relation.
fn range_check_boundary_scalars(
    b: &mut FieldR1csBuilder,
    boundary: &AccumulatorWires,
) -> Vec<Wire> {
    let height_bits = range_check_bits(b, &boundary.height, 64);
    let _ = range_check_bits(b, &boundary.log_slots, 32);
    let _ = range_check_bits(b, &boundary.active_slot_count, 64);
    let _ = range_check_bits(b, &boundary.alloc_counter, 64);
    height_bits
}

/// Pin `child = parent + 1` as an exact u64 integer relation.
fn pin_u64_successor(b: &mut FieldR1csBuilder, parent_bits: &[Wire], child: &LinExpr) {
    const N: usize = 64;
    assert_eq!(parent_bits.len(), N);
    let mut carry = LinExpr::constant(F128::ONE);
    let mut reconstructed = LinExpr::zero();
    for (i, &bit) in parent_bits.iter().enumerate() {
        let parent_bit = LinExpr::from_wire(bit);
        let child_bit = parent_bit.add(&carry);
        reconstructed = reconstructed.add(&child_bit.scale(flat_const(1u128 << i)));
        carry = mul(b, &parent_bit, &carry);
    }
    pin_zero(b, &carry);
    pin_eq(b, child, &reconstructed);
}

/// Prove one direct child transition between ten-lane boundaries.
pub fn build_direct_accumulator_transition_slot(
    b: &mut FieldR1csBuilder,
    start: &AccumulatorWires,
    child: &DirectChildWires,
    end: &AccumulatorWires,
) {
    let start_height_bits = range_check_boundary_scalars(b, start);
    let _ = range_check_boundary_scalars(b, end);

    for lane in 0..2 {
        pin_eq(b, &child.prev_block_hash[lane], &start.tip_block_id[lane]);
    }
    pin_u64_successor(b, &start_height_bits, &child.height);

    pin_eq(b, &child.height, &end.height);
    for lane in 0..2 {
        pin_eq(b, &child.block_id[lane], &end.tip_block_id[lane]);
        pin_eq(b, &child.state_root[lane], &end.state_root[lane]);
    }
    pin_eq(b, &child.log_slots, &end.log_slots);
    pin_eq(b, &child.active_slot_count, &end.active_slot_count);
    pin_eq(b, &child.alloc_counter, &end.alloc_counter);

    // `boundary` is derived from the constrained child height, never supplied
    // independently by the prover.
    let epoch = constrain_tx_epoch_boundary(b, &child.height);
    for lane in 0..2 {
        let delta = start.epoch_anchor_id[lane].add(&child.block_id[lane]);
        let selected = start.epoch_anchor_id[lane].add(&mul(b, &epoch.boundary, &delta));
        pin_eq(b, &selected, &end.epoch_anchor_id[lane]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::TowerField;
    use noid_poseidon2b::native::{compress_with_tag, domain::TAG_TXROOT};

    #[derive(Clone)]
    struct NativeChild {
        block_id: [u8; 32],
        prev_block_hash: [u8; 32],
        state_root: [u8; 32],
        height: u64,
        log_slots: u32,
        active_slot_count: u64,
        alloc_counter: u64,
    }

    fn fixture(parent_height: u64) -> (ChainAccumulator, NativeChild, ChainAccumulator) {
        let start = ChainAccumulator {
            height: parent_height,
            tip_block_id: [0x11; 32],
            state_root: [0x22; 32],
            log_slots: 24,
            active_slot_count: 17,
            alloc_counter: 29,
            epoch_anchor_id: [0x33; 32],
        };
        let child = NativeChild {
            block_id: [0x44; 32],
            prev_block_hash: start.tip_block_id,
            state_root: [0x55; 32],
            height: parent_height + 1,
            log_slots: 25,
            active_slot_count: 19,
            alloc_counter: 31,
        };
        let end = ChainAccumulator {
            height: child.height,
            tip_block_id: child.block_id,
            state_root: child.state_root,
            log_slots: child.log_slots,
            active_slot_count: child.active_slot_count,
            alloc_counter: child.alloc_counter,
            epoch_anchor_id: if child.height % 144 == 0 {
                child.block_id
            } else {
                start.epoch_anchor_id
            },
        };
        (start, child, end)
    }

    fn alloc_child(b: &mut FieldR1csBuilder, child: &NativeChild) -> DirectChildWires {
        let block_id = digest_lanes(&child.block_id);
        let prev = digest_lanes(&child.prev_block_hash);
        let state = digest_lanes(&child.state_root);
        DirectChildWires {
            block_id: block_id.map(|lane| alloc_block(b, lane)),
            prev_block_hash: prev.map(|lane| alloc_block(b, lane)),
            state_root: state.map(|lane| alloc_block(b, lane)),
            height: alloc_block(b, Block128::from(child.height)),
            log_slots: alloc_block(b, Block128::from(child.log_slots)),
            active_slot_count: alloc_block(b, Block128::from(child.active_slot_count)),
            alloc_counter: alloc_block(b, Block128::from(child.alloc_counter)),
        }
    }

    fn satisfies(start: &ChainAccumulator, child: &NativeChild, end: &ChainAccumulator) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b = FieldR1csBuilder::new();
            let start = AccumulatorWires::alloc(&mut b, start);
            let child = alloc_child(&mut b, child);
            let end = AccumulatorWires::alloc(&mut b, end);
            build_direct_accumulator_transition_slot(&mut b, &start, &child, &end);
            let (r1cs, witness) = b.build();
            r1cs.satisfies(&witness)
        }))
        .unwrap_or(false)
    }

    fn mutate_accumulator_lane(acc: &ChainAccumulator, lane: usize) -> ChainAccumulator {
        let mut lanes = acc.to_lanes();
        lanes[lane] += Block128::ONE;
        ChainAccumulator::from_lanes(lanes).unwrap()
    }

    #[test]
    fn tagged_compression_trace_matches_tx_root_wrapper() {
        let left = [0x31u8; 32];
        let right = [0x72u8; 32];
        let expected = digest_lanes(&compress_with_tag(TAG_TXROOT, &left, &right));

        let mut b = FieldR1csBuilder::new();
        let left_w = digest_lanes(&left).map(|lane| alloc_block(&mut b, lane));
        let right_w = digest_lanes(&right).map(|lane| alloc_block(&mut b, lane));
        let actual = compress_with_tag_trace(&mut b, TAG_TXROOT, &left_w, &right_w);
        for lane in 0..2 {
            let expected_w = alloc_block(&mut b, expected[lane]);
            pin_eq(&mut b, &actual[lane], &expected_w);
        }
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
    }

    #[test]
    fn exact_epoch_edges_143_to_144_and_144_to_145() {
        for parent_height in [143, 144] {
            let (start, child, end) = fixture(parent_height);
            assert!(satisfies(&start, &child, &end));
            let expected = if child.height == 144 {
                child.block_id
            } else {
                start.epoch_anchor_id
            };
            assert_eq!(end.epoch_anchor_id, expected);
        }
    }

    #[test]
    fn direct_transition_rejects_every_end_lane_mutation() {
        for parent_height in [143, 144] {
            let (start, child, end) = fixture(parent_height);
            for lane in 0..CHAIN_ACCUMULATOR_LANES {
                let bad_end = mutate_accumulator_lane(&end, lane);
                assert!(
                    !satisfies(&start, &child, &bad_end),
                    "end lane {lane} accepted at parent height {parent_height}"
                );
            }
        }
    }

    #[test]
    fn direct_transition_rejects_parent_link_height_and_epoch_mutations() {
        let (start, child, end) = fixture(143);
        for lane in [0usize, 1, 2] {
            let bad_start = mutate_accumulator_lane(&start, lane);
            assert!(!satisfies(&bad_start, &child, &end), "start lane {lane}");
        }

        // At 143→144 the old epoch is intentionally overwritten, so its
        // lanes are dead for that one transition. They are continuity-critical
        // again on the following non-boundary step.
        let (start, child, end) = fixture(144);
        for lane in [8usize, 9] {
            let bad_start = mutate_accumulator_lane(&start, lane);
            assert!(!satisfies(&bad_start, &child, &end), "start lane {lane}");
        }
    }

    #[test]
    fn direct_transition_rejects_every_child_projection_mutation() {
        let (start, child, end) = fixture(143);
        for target in 0..10 {
            let mut bad = child.clone();
            match target {
                0 => bad.block_id[0] ^= 1,
                1 => bad.block_id[17] ^= 1,
                2 => bad.prev_block_hash[0] ^= 1,
                3 => bad.prev_block_hash[17] ^= 1,
                4 => bad.state_root[0] ^= 1,
                5 => bad.state_root[17] ^= 1,
                6 => bad.height ^= 1,
                7 => bad.log_slots ^= 1,
                8 => bad.active_slot_count ^= 1,
                9 => bad.alloc_counter ^= 1,
                _ => unreachable!(),
            }
            assert!(!satisfies(&start, &bad, &end), "child target {target}");
        }
    }

    #[test]
    fn boundary_scalar_ranges_reject_oversized_field_lanes() {
        for (lane, value) in [
            (5usize, u32::MAX as u128 + 1),
            (6usize, u64::MAX as u128 + 1),
            (7usize, u64::MAX as u128 + 1),
        ] {
            let accepted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut b = FieldR1csBuilder::new();
                let mut native = fixture(143).0.to_lanes();
                native[lane] = Block128::from(value);
                let wires = native.map(|value| alloc_block(&mut b, value));
                let boundary = AccumulatorWires::from_ordered_lanes(wires);
                let _ = range_check_boundary_scalars(&mut b, &boundary);
                let (r1cs, witness) = b.build();
                r1cs.satisfies(&witness)
            }))
            .unwrap_or(false);
            assert!(!accepted, "oversized boundary lane {lane} was accepted");
        }
    }
}
