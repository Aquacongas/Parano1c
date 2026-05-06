// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 4c.3.a — `FriStateCombinerAir` scaffold: layout constants and
//! sponge trace builder.
//!
//! Meta-root identity (per side), matching
//! [`noid_chain::fri_state::combine_roots`]:
//!
//! ```text
//! state_root = Poseidon2bSponge::with_iv(capacity_iv(TAG_FRISTATE))
//!                 .update(log_slots_block)   // 32 bytes: u32 LE + 28 zeros
//!                 .update(root_value)        // 32 bytes
//!                 .update(root_owner_hi)     // 32 bytes
//!                 .update(root_owner_lo)     // 32 bytes
//!                 .finalize()                // final padded permutation
//! ```
//!
//! The preimage is always exactly `4 × 32 = 128` bytes, so `finalize`
//! runs `fill_padding` over an **empty** buffer — one extra rate-absorb
//! with `[0x80, 0, …, 0, 0x01]` (= lane0 `0x80`, lane1 `1 << 120`) and
//! one last permutation. Five permutations total per side.
//!
//! # Row programme (5 permutations, row-major, `SLOT = 128` rows each)
//!
//! | rows      | perm | role                                          |
//! |-----------|------|-----------------------------------------------|
//! | 0..128    | 0    | seed `[0, 0, IV_hi, IV_lo]` + XOR `log_slots` |
//! | 128..256  | 1    | + XOR `root_value`                            |
//! | 256..384  | 2    | + XOR `root_owner_hi`                         |
//! | 384..512  | 3    | + XOR `root_owner_lo`                         |
//! | 512..640  | 4    | + XOR `pad_block` (finalize)                  |
//! | 640..1024 | —    | padding                                       |
//!
//! Digest = state[0..2] at row `512 + N_ROUNDS` (output row of perm 4).
//!
//! # Column layout (scaffold, single side, 30 committed columns)
//!
//! Columns `0..30` carry the five Poseidon permutation instances
//! row-major via [`write_perm_trace_at_offset`]. Rate-lane bookkeeping
//! (`pre_s` columns, head-row indicators, XOR-absorb witness gates,
//! expected-digest `PublicColumn` pins) lands in Stage 4c.3.b alongside
//! the constraint set. The scaffold keeps the surface area tight so
//! 4c.3.b can drop the constraint layer in without layout churn.

use crate::airs::poseidon_perm::{
    write_perm_trace_at_offset, PermLayout, DEFAULT_PERM_LAYOUT, POSEIDON_PERM_N_COLS,
};
use noid_core::{Block128, CanonicalSerialize, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_FRISTATE};
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

/// Bytes absorbed into the combiner preimage.
pub const FRI_STATE_COMBINER_PREIMAGE_BYTES: usize = 4 * 32;

/// Rate-block absorb count before finalize (one block per 32-byte
/// preimage chunk).
pub const FRI_STATE_COMBINER_N_ABSORB_BLOCKS: usize = 4;

/// Poseidon2b permutations per side: four absorb rounds + one padded
/// finalize.
pub const FRI_STATE_COMBINER_N_PERMS_PER_SIDE: usize =
    FRI_STATE_COMBINER_N_ABSORB_BLOCKS + 1;

/// Rows allotted to each permutation instance — identical stride to the
/// `TxBodyMerkleAir` stack so the row-major Poseidon helpers apply
/// verbatim.
pub const FRI_STATE_COMBINER_SLOT_ROWS: usize = 128;
pub const FRI_STATE_COMBINER_SLOT_LOG_ROWS: usize = 7;

/// Total trace height for one side: 5 × 128 = 640 live rows, rounded up
/// to the nearest power of two (1024 = 2^10).
pub const FRI_STATE_COMBINER_LOG_ROWS: usize = 10;
pub const FRI_STATE_COMBINER_N_ROWS: usize = 1 << FRI_STATE_COMBINER_LOG_ROWS;

/// Scaffold column count (single side, Poseidon permutation block only).
/// Grows in 4c.3.b with `pre_s`, head indicators, IV programme, and
/// absorb-payload witness columns.
pub const FRI_STATE_COMBINER_SCAFFOLD_N_COLS: usize = POSEIDON_PERM_N_COLS;

/// Finalize-padding rate-lane 0: `fill_padding` on an empty 32-byte
/// buffer places `PADDING_START = 0x80` at byte 0.
pub const FRI_STATE_COMBINER_PAD_LANE_0: u128 = 0x80u128;

/// Finalize-padding rate-lane 1: `fill_padding` places
/// `PADDING_END = 0x01` at byte 31, i.e. byte 15 of the upper 16-byte
/// rate slice.
pub const FRI_STATE_COMBINER_PAD_LANE_1: u128 = 1u128 << 120;

/// Row offset of instance `id ∈ 0..5` inside a side trace.
#[inline]
pub const fn combiner_instance_row_offset(id: usize) -> usize {
    id * FRI_STATE_COMBINER_SLOT_ROWS
}

/// Row within a side trace where instance `id`'s output state lives
/// (state at row `slot_base + N_ROUNDS`, matching `PoseidonPermAir`).
#[inline]
pub const fn combiner_instance_output_row(id: usize) -> usize {
    combiner_instance_row_offset(id) + N_ROUNDS
}

/// Per-side preimage fed into the sponge. Bytes agree with
/// `combine_roots` in `noid_chain::fri_state`:
/// - lane 0 of block 0 carries `log_slots` as a little-endian u128
///   (top bits zero; the native code writes `u32::to_le_bytes` then
///   zero-pads to 32 bytes);
/// - lane 1 of block 0 is zero;
/// - blocks 1..4 carry `(r_val, r_owner_hi, r_owner_lo)` bytes split
///   into little-endian 16-byte lanes.
#[derive(Debug, Clone, Copy)]
pub struct FriStateCombinerPreimage {
    pub log_slots: u32,
    pub r_val: [u8; 32],
    pub r_owner_hi: [u8; 32],
    pub r_owner_lo: [u8; 32],
}

impl FriStateCombinerPreimage {
    /// Decompose the preimage into four 32-byte rate blocks in sponge
    /// absorption order.
    pub fn rate_blocks(&self) -> [[u8; 32]; FRI_STATE_COMBINER_N_ABSORB_BLOCKS] {
        let mut block0 = [0u8; 32];
        block0[..4].copy_from_slice(&self.log_slots.to_le_bytes());
        [block0, self.r_val, self.r_owner_hi, self.r_owner_lo]
    }
}

/// Split a 32-byte rate block into its two little-endian 16-byte lanes,
/// matching `Poseidon2bSponge::permute_buffer` (see
/// `noid_poseidon2b/src/native/compression.rs:125-133`).
#[inline]
pub fn rate_block_to_lanes(block: &[u8; 32]) -> [Block128; 2] {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&block[..16]);
    hi.copy_from_slice(&block[16..]);
    [
        Block128::from(u128::from_le_bytes(lo)),
        Block128::from(u128::from_le_bytes(hi)),
    ]
}

/// Compute the pre-MDS seed state for each of the 5 permutations in one
/// side's sponge run. The seed for perm 0 is
/// `[0, 0, IV_hi, IV_lo] XOR block0_lanes` — the capacity IV is
/// installed before any absorb. Seeds for perms 1..4 are
/// `prev_output XOR next_block_lanes` on the two rate lanes. Perm 4's
/// seed XORs the finalize-padding block.
pub fn combiner_pre_seeds(
    preimage: &FriStateCombinerPreimage,
) -> [[Block128; STATE_SIZE]; FRI_STATE_COMBINER_N_PERMS_PER_SIDE] {
    let [iv_hi, iv_lo] = capacity_iv(TAG_FRISTATE);
    let blocks = preimage.rate_blocks();

    let mut seeds = [[Block128::ZERO; STATE_SIZE]; FRI_STATE_COMBINER_N_PERMS_PER_SIDE];

    // Perm 0: fresh capacity-IV state absorbs block 0.
    let [b0_lo, b0_hi] = rate_block_to_lanes(&blocks[0]);
    seeds[0] = [b0_lo, b0_hi, iv_hi, iv_lo];

    // Run the native sponge to obtain the post-perm state for 0..3,
    // which feeds the next perm's seed after XOR-ing the next block's
    // rate lanes. Finalize-padding block lives at index 4.
    use noid_poseidon2b::native::permutation::Poseidon2bPermutation;
    let perm = Poseidon2bPermutation;
    let mut state = seeds[0];
    for i in 1..FRI_STATE_COMBINER_N_PERMS_PER_SIDE {
        let mut next_state = state;
        perm.permute_mut(&mut next_state);

        let block = if i < FRI_STATE_COMBINER_N_ABSORB_BLOCKS {
            blocks[i]
        } else {
            // Finalize: fill_padding on empty buffer.
            let mut pad = [0u8; 32];
            pad[0] = 0x80;
            pad[31] = 0x01;
            pad
        };
        let [lo, hi] = rate_block_to_lanes(&block);
        next_state[0] = next_state[0] + lo;
        next_state[1] = next_state[1] + hi;
        seeds[i] = next_state;
        state = next_state;
    }

    seeds
}

/// Build a single-side combiner trace: five Poseidon2b permutations
/// stacked row-major, 30 committed columns, 1024 rows. The digest
/// (two little-endian 16-byte halves) can be read at
/// `(cols[POSEIDON_COL_S + lane][combiner_instance_output_row(4)]) for lane in 0..2`.
///
/// Stage 4c.3.a produces the trace only; the constraint set, `pre_s`
/// plumbing, and `PublicColumn` pins on the expected digest ship in
/// 4c.3.b. The round-trip test against `combine_roots` in this file is
/// the stand-in correctness check until then.
pub fn build_combiner_side_trace(
    preimage: &FriStateCombinerPreimage,
) -> Vec<Vec<Block128>> {
    let mut cols: Vec<Vec<Block128>> = (0..FRI_STATE_COMBINER_SCAFFOLD_N_COLS)
        .map(|_| vec![Block128::ZERO; FRI_STATE_COMBINER_N_ROWS])
        .collect();

    let seeds = combiner_pre_seeds(preimage);
    for (i, seed) in seeds.iter().enumerate() {
        write_perm_trace_at_offset(
            &mut cols,
            DEFAULT_PERM_LAYOUT,
            *seed,
            combiner_instance_row_offset(i),
        );
    }

    cols
}

/// Read the 32-byte digest from a side trace: state[0..2] at perm 4's
/// output row, serialised little-endian lane-first.
pub fn extract_combiner_digest(
    cols: &[Vec<Block128>],
    layout: PermLayout,
) -> [u8; 32] {
    let row = combiner_instance_output_row(FRI_STATE_COMBINER_N_PERMS_PER_SIDE - 1);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&cols[layout.s + 0][row].to_bytes());
    out[16..].copy_from_slice(&cols[layout.s + 1][row].to_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::native::Poseidon2bSponge;

    /// Native reference: bit-identical to
    /// `noid_chain::fri_state::combine_roots`. Kept inline to avoid a
    /// circular crate dependency (`noid_chain` depends on `noid_air`).
    fn native_combine_roots(
        log_slots: u32,
        r_val: &[u8; 32],
        r_hi: &[u8; 32],
        r_lo: &[u8; 32],
    ) -> [u8; 32] {
        let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_FRISTATE));
        let mut depth = [0u8; 32];
        depth[..4].copy_from_slice(&log_slots.to_le_bytes());
        sponge.update(&depth);
        sponge.update(r_val);
        sponge.update(r_hi);
        sponge.update(r_lo);
        sponge.finalize()
    }

    fn mk_preimage(seed: u8) -> FriStateCombinerPreimage {
        let mut r_val = [0u8; 32];
        let mut r_hi = [0u8; 32];
        let mut r_lo = [0u8; 32];
        for i in 0..32 {
            r_val[i] = seed ^ (i as u8);
            r_hi[i] = seed.wrapping_add(0x11) ^ (i as u8).wrapping_mul(3);
            r_lo[i] = seed.wrapping_add(0x22) ^ (i as u8).wrapping_mul(5);
        }
        FriStateCombinerPreimage {
            log_slots: 24,
            r_val,
            r_owner_hi: r_hi,
            r_owner_lo: r_lo,
        }
    }

    #[test]
    fn row_and_column_budget_match_constants() {
        let pre = mk_preimage(0x7A);
        let cols = build_combiner_side_trace(&pre);
        assert_eq!(cols.len(), FRI_STATE_COMBINER_SCAFFOLD_N_COLS);
        for c in &cols {
            assert_eq!(c.len(), FRI_STATE_COMBINER_N_ROWS);
        }
        assert_eq!(
            FRI_STATE_COMBINER_N_PERMS_PER_SIDE * FRI_STATE_COMBINER_SLOT_ROWS,
            640,
        );
        assert!(
            FRI_STATE_COMBINER_N_PERMS_PER_SIDE * FRI_STATE_COMBINER_SLOT_ROWS
                <= FRI_STATE_COMBINER_N_ROWS,
        );
    }

    #[test]
    fn rate_block_decomposition_matches_preimage() {
        let pre = mk_preimage(0x01);
        let blocks = pre.rate_blocks();
        // Block 0: first 4 bytes carry log_slots LE, rest zero.
        let mut expected0 = [0u8; 32];
        expected0[..4].copy_from_slice(&24u32.to_le_bytes());
        assert_eq!(blocks[0], expected0);
        assert_eq!(blocks[1], pre.r_val);
        assert_eq!(blocks[2], pre.r_owner_hi);
        assert_eq!(blocks[3], pre.r_owner_lo);
    }

    #[test]
    fn pad_block_lanes_match_native_finalize() {
        // Sanity: fill_padding on empty 32-byte buffer yields 0x80 at
        // byte 0 and 0x01 at byte 31 — lane 0 = 0x80, lane 1 = 1 << 120.
        let mut pad = [0u8; 32];
        pad[0] = 0x80;
        pad[31] = 0x01;
        let [lo, hi] = rate_block_to_lanes(&pad);
        assert_eq!(lo, Block128::from(FRI_STATE_COMBINER_PAD_LANE_0));
        assert_eq!(hi, Block128::from(FRI_STATE_COMBINER_PAD_LANE_1));
    }

    #[test]
    fn trace_digest_matches_combine_roots() {
        // Round-trip: the trace digest must agree bit-for-bit with
        // `noid_chain::fri_state::combine_roots`, the on-chain meta-root
        // function 4c.3 is arithmetising.
        for seed in [0x01u8, 0x5A, 0xA5, 0xFE] {
            let pre = mk_preimage(seed);
            let cols = build_combiner_side_trace(&pre);
            let trace_digest = extract_combiner_digest(&cols, DEFAULT_PERM_LAYOUT);
            let expected =
                native_combine_roots(pre.log_slots, &pre.r_val, &pre.r_owner_hi, &pre.r_owner_lo);
            assert_eq!(trace_digest, expected, "seed {seed:#04x}");
        }
    }

    #[test]
    fn pre_seeds_install_capacity_iv_on_perm_0() {
        // Perm 0's pre-MDS seed carries the fresh capacity IV in lanes
        // 2..3 (plus the block-0 absorb in lanes 0..1). Non-zero IV by
        // construction — `capacity_iv` asserts that.
        let pre = mk_preimage(0);
        let seeds = combiner_pre_seeds(&pre);
        let [iv_hi, iv_lo] = capacity_iv(TAG_FRISTATE);
        assert_eq!(seeds[0][2], iv_hi);
        assert_eq!(seeds[0][3], iv_lo);
    }

    #[test]
    fn pre_seeds_chain_rate_absorbs() {
        // For perms 1..N, the pre-MDS seed equals the prior perm's
        // post-permutation state with the next rate block XOR'd into
        // lanes 0..1. This invariant is what 4c.3.b's inter-perm
        // absorb gate will enforce directly on the trace.
        use noid_poseidon2b::native::permutation::Poseidon2bPermutation;
        let pre = mk_preimage(0xCC);
        let seeds = combiner_pre_seeds(&pre);
        let blocks = pre.rate_blocks();

        let perm = Poseidon2bPermutation;
        for i in 1..FRI_STATE_COMBINER_N_PERMS_PER_SIDE {
            let mut post_prev = seeds[i - 1];
            perm.permute_mut(&mut post_prev);

            let block = if i < FRI_STATE_COMBINER_N_ABSORB_BLOCKS {
                blocks[i]
            } else {
                let mut pad = [0u8; 32];
                pad[0] = 0x80;
                pad[31] = 0x01;
                pad
            };
            let [lo, hi] = rate_block_to_lanes(&block);
            assert_eq!(seeds[i][0], post_prev[0] + lo, "perm {i} lane 0");
            assert_eq!(seeds[i][1], post_prev[1] + hi, "perm {i} lane 1");
            assert_eq!(seeds[i][2], post_prev[2], "perm {i} lane 2 (capacity)");
            assert_eq!(seeds[i][3], post_prev[3], "perm {i} lane 3 (capacity)");
        }
    }
}
