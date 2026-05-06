// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 4c.3 — `FriStateCombinerAir`: Poseidon2b meta-root combiner for
//! one side (prev or new) of the state-root identity.
//!
//! # Identity
//!
//! Per side, matching [`noid_chain::fri_state::combine_roots`]:
//!
//! ```text
//! state_root = Poseidon2bSponge::with_iv(capacity_iv(TAG_FRISTATE))
//!                 .update(log_slots_block)  // 32 bytes: u32 LE + 28 zeros
//!                 .update(root_value)       // 32 bytes
//!                 .update(root_owner_hi)    // 32 bytes
//!                 .update(root_owner_lo)    // 32 bytes
//!                 .finalize()               // final padded permutation
//! ```
//!
//! The preimage is exactly `4 × 32 = 128` bytes, so `finalize` triggers
//! one extra rate-absorb on an empty buffer (`fill_padding` →
//! `[0x80, 0, …, 0, 0x01]` = lane 0 `0x80`, lane 1 `1 << 120`) plus one
//! last permutation — **five** Poseidon2b permutations per side.
//!
//! # Column layout
//!
//! Five Poseidon permutation blocks stacked **back-to-back** at stride
//! `SLOT = N_ROUNDS + 1 = 67` rows (same pattern as `HAddrAir`'s block-A /
//! block-B chain, just generalised to five blocks). Perm `i` occupies
//! rows `67 * i ..= 67 * i + N_ROUNDS`.
//!
//! | range      | semantics                                          |
//! |------------|----------------------------------------------------|
//! | 0..30      | row-major Poseidon permutation trace (5 instances) |
//! | 30..50     | `pre_s_block_i[0..4]` for `i ∈ 0..5` (4 lanes each)|
//! | 50         | `ind_perm_0_row_0` — hot at row 0                  |
//! | 51..55     | `ind_prev_out_i` for `i ∈ 1..5` — hot at perm (i-1)'s output row |
//! | 55         | `ind_digest` — hot at perm 4's output row          |
//!
//! `pre_s_block_0` is populated at row 0 (perm 0's own row-0 pre-MDS
//! seed, carrying `[block_0_lane_0, block_0_lane_1, IV_hi, IV_lo]`).
//!
//! For `i ∈ 1..5` the `pre_s_block_i` witness lives at row
//! `SLOT * i - 1` — i.e. the prior perm's output row. That shared row
//! is what lets one `WeightedLinearGateShifted` bridge the MDS-i binding
//! (local-row `pre_s_i[j]` + next-row `s[lane]` cross-row equation) and
//! one `WeightedLinearGate` carry the absorb-XOR on the same indicator.
//!
//! # Boundary ties (per side)
//!
//! 1. **Perm 0 IV + block-0 absorb (row 0).** Four pins on
//!    `pre_s_block_0[0..4]@0` via `SelectorGate(ind_perm_0_row_0, ...)`:
//!    lanes 0..2 pinned to `block_0_lanes`, lanes 2..4 pinned to
//!    `capacity_iv(TAG_FRISTATE)`.
//! 2. **Perm 0 MDS binding (row 0).** Local gate
//!    `s[lane]@0 + Σ MDS_FULL[lane][j] · pre_s_block_0[j]@0 == 0`, gated
//!    by `ind_perm_0_row_0`.
//! 3. **Inter-perm absorb XOR (i ∈ 1..5, row `SLOT * i - 1`).** Local
//!    gate on the shared row
//!    `s[lane]@row + pre_s_block_i[lane]@row + block_i_absorb_lane == 0`
//!    with `block_i_absorb_lane ∈ {0, 0}` on capacity lanes (2,3) and the
//!    little-endian 16-byte lane of absorb block `i` on rate lanes (0,1).
//!    Gated by `ind_prev_out_i`. Binds `pre_s_i` to the prior perm's
//!    final state XOR the absorb payload.
//! 4. **Perm i MDS binding (i ∈ 1..5, shifted row `SLOT * i - 1` →
//!    `SLOT * i`).** Shifted gate
//!    `next(s[lane]) + Σ MDS_FULL[lane][j] · pre_s_block_i[j]@row == 0`,
//!    gated by `ind_prev_out_i`. This transports the post-MDS state to
//!    perm `i`'s row 0 and prevents any malicious prover from
//!    substituting an arbitrary seed.
//! 5. **Digest squeeze (row `SLOT * 5 - 1`).** Pin `s[0..2]` via
//!    `SelectorGate(ind_digest, ...)` to `expected_state_root_fields`.
//!
//! All five absorb blocks (log_slots / r_val / r_hi / r_lo / finalize
//! padding) are pinned to the AIR at construction time as gate constants,
//! which is what binds the native
//! `combine_roots(log_slots, r_val, r_owner_hi, r_owner_lo)` identity to
//! the arithmetisation: any trace whose absorb payloads deviate from the
//! declared inputs, or whose digest deviates from the declared
//! `expected_state_root`, is rejected.

use crate::airs::poseidon_perm::{
    is_full_round, write_perm_trace_at_offset, PermLayout, DEFAULT_PERM_LAYOUT,
    POSEIDON_PERM_N_COLS,
};
use crate::gates::row_selector::row_indicator_programme;
use crate::gates::{PublicColumn, SelectorGate, WeightedLinearGate, WeightedLinearGateShifted};
use crate::{Air, Constraint, Trace};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_FRISTATE};
use noid_poseidon2b::native::permutation::{
    MDS_FULL, N_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};

// ---------------------------------------------------------------------------
// Sponge shape
// ---------------------------------------------------------------------------

/// Bytes absorbed into the combiner preimage.
pub const FRI_STATE_COMBINER_PREIMAGE_BYTES: usize = 4 * 32;

/// Rate-block absorb count before finalize.
pub const FRI_STATE_COMBINER_N_ABSORB_BLOCKS: usize = 4;

/// Poseidon2b permutations per side: four absorb rounds + one padded
/// finalize.
pub const FRI_STATE_COMBINER_N_PERMS_PER_SIDE: usize =
    FRI_STATE_COMBINER_N_ABSORB_BLOCKS + 1;

/// Rows per permutation slot. Perms sit back-to-back at stride
/// `N_ROUNDS + 1`, mirroring the two-perm chain in `HAddrAir`. Each
/// slot holds the `N_ROUNDS` transition rows plus one trailing post-MDS
/// output row.
pub const FRI_STATE_COMBINER_SLOT_ROWS: usize = N_ROUNDS + 1;

/// Total trace height per side: `5 * 67 = 335` live rows rounded up to
/// the next power of two (`512 = 2^9`).
pub const FRI_STATE_COMBINER_LOG_ROWS: usize = 9;
pub const FRI_STATE_COMBINER_N_ROWS: usize = 1 << FRI_STATE_COMBINER_LOG_ROWS;

/// Finalize-padding rate lanes. `fill_padding` on an empty 32-byte
/// buffer places `0x80` at byte 0 (→ lane 0) and `0x01` at byte 31
/// (→ lane 1 upper bit).
pub const FRI_STATE_COMBINER_PAD_LANE_0: u128 = 0x80u128;
pub const FRI_STATE_COMBINER_PAD_LANE_1: u128 = 1u128 << 120;

// ---------------------------------------------------------------------------
// Column layout
// ---------------------------------------------------------------------------

/// Base of the Poseidon permutation block (shared across all 5
/// instances via row-major stacking).
pub const COMBINER_PERM_BASE: usize = 0;

/// Base of the `pre_s` witness block for permutation `i`. Each instance
/// gets its own 4-lane pre-MDS seed block laid out back-to-back.
pub const COMBINER_PRE_S_BASE: usize = POSEIDON_PERM_N_COLS;

/// Total number of `pre_s` columns across the 5 perms (4 lanes each).
pub const COMBINER_PRE_S_N_COLS: usize =
    STATE_SIZE * FRI_STATE_COMBINER_N_PERMS_PER_SIDE;

/// Indicator column hot on perm 0's row 0 (IV + block-0 absorb pin +
/// perm 0 MDS binding).
pub const COMBINER_IND_PERM_0_ROW_0: usize = COMBINER_PRE_S_BASE + COMBINER_PRE_S_N_COLS;

/// Base of the 4 "prior perm output row" indicator columns, one per
/// `i ∈ 1..5`. Each hot on row `SLOT * i - 1`.
pub const COMBINER_IND_PREV_OUT_BASE: usize = COMBINER_IND_PERM_0_ROW_0 + 1;

/// Indicator column hot on the digest squeeze row (perm 4's output row).
pub const COMBINER_IND_DIGEST: usize =
    COMBINER_IND_PREV_OUT_BASE + (FRI_STATE_COMBINER_N_PERMS_PER_SIDE - 1);

/// Total committed column count for the full AIR (witness + public).
pub const FRI_STATE_COMBINER_N_COLS: usize = COMBINER_IND_DIGEST + 1;

/// Scaffold-only column width (Poseidon permutation block alone).
/// Retained for callers that still want the pre-4c.3.b trace shape.
pub const FRI_STATE_COMBINER_SCAFFOLD_N_COLS: usize = POSEIDON_PERM_N_COLS;

/// Permutation layout reused by every instance via row-major offsetting.
pub const COMBINER_PERM_LAYOUT: PermLayout = DEFAULT_PERM_LAYOUT;

/// Column base of `pre_s_block_i` for permutation `i`.
#[inline]
pub const fn combiner_pre_s_base(perm_idx: usize) -> usize {
    COMBINER_PRE_S_BASE + STATE_SIZE * perm_idx
}

/// Row offset where permutation `i`'s interior trace starts.
#[inline]
pub const fn combiner_instance_row_offset(perm_idx: usize) -> usize {
    perm_idx * FRI_STATE_COMBINER_SLOT_ROWS
}

/// Row at which permutation `i`'s post-MDS output state lives.
#[inline]
pub const fn combiner_instance_output_row(perm_idx: usize) -> usize {
    combiner_instance_row_offset(perm_idx) + N_ROUNDS
}

/// Row at which `pre_s_block_i` is populated. Perm 0's seed lives on
/// its own row 0; for `i ≥ 1` the seed rides on the prior perm's output
/// row so one shifted gate bridges the MDS binding to perm `i`'s
/// row 0.
#[inline]
pub const fn combiner_pre_s_row(perm_idx: usize) -> usize {
    if perm_idx == 0 {
        0
    } else {
        combiner_instance_output_row(perm_idx - 1)
    }
}

/// Column of the "prior perm output row" indicator for perm `i ∈ 1..5`.
#[inline]
pub const fn combiner_ind_prev_out(perm_idx: usize) -> usize {
    assert!(perm_idx >= 1 && perm_idx < FRI_STATE_COMBINER_N_PERMS_PER_SIDE);
    COMBINER_IND_PREV_OUT_BASE + (perm_idx - 1)
}

/// Row where the side's digest is read: perm 4's output row.
#[inline]
pub const fn combiner_digest_row() -> usize {
    combiner_instance_output_row(FRI_STATE_COMBINER_N_PERMS_PER_SIDE - 1)
}

// ---------------------------------------------------------------------------
// Preimage
// ---------------------------------------------------------------------------

/// Per-side preimage fed into the sponge, byte-compatible with
/// `combine_roots` in `noid_chain::fri_state`:
/// - block 0 carries `log_slots as u32 LE` in bytes 0..4 and zero
///   elsewhere;
/// - blocks 1..4 carry `(r_val, r_owner_hi, r_owner_lo)`.
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
/// matching `Poseidon2bSponge::permute_buffer`.
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

/// Finalize-padding block: `[0x80, 0, …, 0, 0x01]`.
#[inline]
fn finalize_pad_block() -> [u8; 32] {
    let mut pad = [0u8; 32];
    pad[0] = 0x80;
    pad[31] = 0x01;
    pad
}

/// Build all five rate blocks (4 absorbed + 1 finalize-padding) per side
/// together with their lane-split representation.
fn all_absorb_lanes(
    preimage: &FriStateCombinerPreimage,
) -> [[Block128; 2]; FRI_STATE_COMBINER_N_PERMS_PER_SIDE] {
    let blocks = preimage.rate_blocks();
    let mut out = [[Block128::ZERO; 2]; FRI_STATE_COMBINER_N_PERMS_PER_SIDE];
    for (i, block) in blocks.iter().enumerate() {
        out[i] = rate_block_to_lanes(block);
    }
    out[FRI_STATE_COMBINER_N_PERMS_PER_SIDE - 1] = rate_block_to_lanes(&finalize_pad_block());
    out
}

/// Compute the pre-MDS seed for each of the 5 permutations in the
/// sponge run. Seed 0 is `[b0_lo, b0_hi, IV_hi, IV_lo]`; seeds 1..4 are
/// `prev_output + block_i_lanes` on rate lanes (0..2) and
/// `prev_output` on capacity lanes (2..4).
pub fn combiner_pre_seeds(
    preimage: &FriStateCombinerPreimage,
) -> [[Block128; STATE_SIZE]; FRI_STATE_COMBINER_N_PERMS_PER_SIDE] {
    use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

    let [iv_hi, iv_lo] = capacity_iv(TAG_FRISTATE);
    let absorb = all_absorb_lanes(preimage);

    let mut seeds = [[Block128::ZERO; STATE_SIZE]; FRI_STATE_COMBINER_N_PERMS_PER_SIDE];
    seeds[0] = [absorb[0][0], absorb[0][1], iv_hi, iv_lo];

    let perm = Poseidon2bPermutation;
    let mut state = seeds[0];
    for i in 1..FRI_STATE_COMBINER_N_PERMS_PER_SIDE {
        let mut next_state = state;
        perm.permute_mut(&mut next_state);
        next_state[0] = next_state[0] + absorb[i][0];
        next_state[1] = next_state[1] + absorb[i][1];
        seeds[i] = next_state;
        state = next_state;
    }
    seeds
}

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

/// Build an honest witness trace for one side's sponge run. Produces
/// the full `FRI_STATE_COMBINER_N_COLS`-wide trace with `pre_s` and
/// indicator tails populated.
pub fn build_combiner_side_trace(
    preimage: &FriStateCombinerPreimage,
) -> Vec<Vec<Block128>> {
    let mut cols: Vec<Vec<Block128>> = (0..FRI_STATE_COMBINER_N_COLS)
        .map(|_| vec![Block128::ZERO; FRI_STATE_COMBINER_N_ROWS])
        .collect();

    let seeds = combiner_pre_seeds(preimage);
    for (i, seed) in seeds.iter().enumerate() {
        let row_offset = combiner_instance_row_offset(i);
        write_perm_trace_at_offset(&mut cols, COMBINER_PERM_LAYOUT, *seed, row_offset);

        let pre_s_row = combiner_pre_s_row(i);
        for lane in 0..STATE_SIZE {
            cols[combiner_pre_s_base(i) + lane][pre_s_row] = seed[lane];
        }
    }

    cols[COMBINER_IND_PERM_0_ROW_0][0] = Block128::ONE;
    for i in 1..FRI_STATE_COMBINER_N_PERMS_PER_SIDE {
        let row = combiner_instance_output_row(i - 1);
        cols[combiner_ind_prev_out(i)][row] = Block128::ONE;
    }
    cols[COMBINER_IND_DIGEST][combiner_digest_row()] = Block128::ONE;

    cols
}

/// Read the 32-byte digest from a side trace: state[0..2] at perm 4's
/// output row, serialised little-endian lane-first.
pub fn extract_combiner_digest(
    cols: &[Vec<Block128>],
    layout: PermLayout,
) -> [u8; 32] {
    use noid_core::CanonicalSerialize;
    let row = combiner_digest_row();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&cols[layout.s + 0][row].to_bytes());
    out[16..].copy_from_slice(&cols[layout.s + 1][row].to_bytes());
    out
}

/// Extract `(digest_hi, digest_lo)` as field elements — the form used
/// for pinning to `expected_state_root`.
pub fn extract_combiner_digest_fields(
    cols: &[Vec<Block128>],
    layout: PermLayout,
) -> [Block128; 2] {
    let row = combiner_digest_row();
    [cols[layout.s][row], cols[layout.s + 1][row]]
}

// ---------------------------------------------------------------------------
// Public-column programmes for the 5 stacked perm blocks
// ---------------------------------------------------------------------------

fn combiner_is_full_values() -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; FRI_STATE_COMBINER_N_ROWS];
    for i in 0..FRI_STATE_COMBINER_N_PERMS_PER_SIDE {
        let base = combiner_instance_row_offset(i);
        for r in 0..N_ROUNDS {
            if is_full_round(r) {
                out[base + r] = Block128::ONE;
            }
        }
    }
    out
}

fn combiner_is_round_values() -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; FRI_STATE_COMBINER_N_ROWS];
    for i in 0..FRI_STATE_COMBINER_N_PERMS_PER_SIDE {
        let base = combiner_instance_row_offset(i);
        for r in 0..N_ROUNDS {
            out[base + r] = Block128::ONE;
        }
    }
    out
}

fn combiner_rc_values(lane: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; FRI_STATE_COMBINER_N_ROWS];
    for i in 0..FRI_STATE_COMBINER_N_PERMS_PER_SIDE {
        let base = combiner_instance_row_offset(i);
        for r in 0..N_ROUNDS {
            out[base + r] = Block128::from(ROUND_CONSTANTS[lane][r]);
        }
    }
    out
}

fn emit_combiner_perm_publics(layout: PermLayout) -> Vec<PublicColumn> {
    let mut out = Vec::with_capacity(STATE_SIZE + 2);
    out.push(PublicColumn::new(layout.is_full, combiner_is_full_values()));
    out.push(PublicColumn::new(layout.is_round, combiner_is_round_values()));
    for lane in 0..STATE_SIZE {
        out.push(PublicColumn::new(layout.rc + lane, combiner_rc_values(lane)));
    }
    out
}

// ---------------------------------------------------------------------------
// Constraint emission
// ---------------------------------------------------------------------------

fn mds_full_row_terms(lane: usize, pre_s_base: usize) -> Vec<(usize, Block128)> {
    (0..STATE_SIZE)
        .map(|j| (pre_s_base + j, Block128::from(MDS_FULL[lane][j])))
        .collect()
}

/// Build the full combiner constraint set and public-column declarations.
///
/// `expected_state_root_fields = [digest_hi, digest_lo]` — the verifier-
/// known 32-byte state-root half-fields. `preimage` carries the four
/// 32-byte absorb blocks (`log_slots`-padded, `r_val`, `r_owner_hi`,
/// `r_owner_lo`). Every absorbed payload byte is pinned as public input,
/// so the AIR's statement agrees bit-for-bit with
/// `combine_roots(log_slots, r_val, r_owner_hi, r_owner_lo) ==
/// expected_state_root`.
pub fn emit_fri_state_combiner(
    preimage: &FriStateCombinerPreimage,
    expected_state_root_fields: [Block128; 2],
) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
    let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
    let mut public_columns: Vec<PublicColumn> = Vec::new();

    // (A) Poseidon interior for all 5 perms (row-major public programmes).
    constraints.extend(crate::airs::emit_perm_all_at(COMBINER_PERM_LAYOUT));
    public_columns.extend(emit_combiner_perm_publics(COMBINER_PERM_LAYOUT));

    // (B) Row indicators.
    public_columns.push(PublicColumn::new(
        COMBINER_IND_PERM_0_ROW_0,
        row_indicator_programme(0, FRI_STATE_COMBINER_N_ROWS),
    ));
    for i in 1..FRI_STATE_COMBINER_N_PERMS_PER_SIDE {
        public_columns.push(PublicColumn::new(
            combiner_ind_prev_out(i),
            row_indicator_programme(
                combiner_instance_output_row(i - 1),
                FRI_STATE_COMBINER_N_ROWS,
            ),
        ));
    }
    public_columns.push(PublicColumn::new(
        COMBINER_IND_DIGEST,
        row_indicator_programme(combiner_digest_row(), FRI_STATE_COMBINER_N_ROWS),
    ));

    let [iv_hi, iv_lo] = capacity_iv(TAG_FRISTATE);
    let absorb = all_absorb_lanes(preimage);

    // (C) Perm 0 IV + block-0 absorb pin on pre_s_block_0@row 0.
    let pre_s_0 = combiner_pre_s_base(0);
    let block_0 = absorb[0];
    for (lane, v) in [(0usize, block_0[0]), (1, block_0[1]), (2, iv_hi), (3, iv_lo)] {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![(pre_s_0 + lane, Block128::ONE)],
            v,
        ));
        constraints.push(Box::new(SelectorGate::new(COMBINER_IND_PERM_0_ROW_0, inner)));
    }

    // (D) Perm 0 MDS binding at row 0: `s[lane]@0 + Σ MDS · pre_s_0[j]@0 == 0`.
    for lane in 0..STATE_SIZE {
        let mut terms = vec![(COMBINER_PERM_LAYOUT.s + lane, Block128::ONE)];
        terms.extend(mds_full_row_terms(lane, pre_s_0));
        let inner: Box<dyn Constraint> =
            Box::new(WeightedLinearGate::new(terms, Block128::ZERO));
        constraints.push(Box::new(SelectorGate::new(COMBINER_IND_PERM_0_ROW_0, inner)));
    }

    // (E) Inter-perm absorb XOR + (F) Perm-i MDS binding for i ∈ 1..5.
    // Both fire on the same row `SLOT * i - 1` (prior perm's output row)
    // and share the indicator `ind_prev_out_i`.
    //
    //   (E) `s[lane]@row + pre_s_i[lane]@row + block_i_absorb_lane == 0`
    //       (rate lanes 0..2 carry the absorb constant; capacity lanes 2..4
    //        have zero constant — pass-through).
    //   (F) `next(s[lane])@row + Σ MDS · pre_s_i[j]@row == 0`
    //       (shifted; `next` reaches perm i's row-0 post-MDS state).
    for i in 1..FRI_STATE_COMBINER_N_PERMS_PER_SIDE {
        let ind = combiner_ind_prev_out(i);
        let pre_s_i = combiner_pre_s_base(i);
        let absorb_i = absorb[i];

        // (E) absorb XOR
        for lane in 0..STATE_SIZE {
            let constant = if lane < 2 { absorb_i[lane] } else { Block128::ZERO };
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
                vec![
                    (COMBINER_PERM_LAYOUT.s + lane, Block128::ONE),
                    (pre_s_i + lane, Block128::ONE),
                ],
                constant,
            ));
            constraints.push(Box::new(SelectorGate::new(ind, inner)));
        }

        // (F) MDS-i shifted binding
        for lane in 0..STATE_SIZE {
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new(
                mds_full_row_terms(lane, pre_s_i),
                vec![(COMBINER_PERM_LAYOUT.s + lane, Block128::ONE)],
                Block128::ZERO,
            ));
            constraints.push(Box::new(SelectorGate::new(ind, inner)));
        }
    }

    // (G) Digest squeeze: pin s[0..2]@combiner_digest_row() to
    //     expected_state_root_fields.
    for (lane, expected) in expected_state_root_fields.iter().enumerate() {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![(COMBINER_PERM_LAYOUT.s + lane, Block128::ONE)],
            *expected,
        ));
        constraints.push(Box::new(SelectorGate::new(COMBINER_IND_DIGEST, inner)));
    }

    (constraints, public_columns)
}

// ---------------------------------------------------------------------------
// FriStateCombinerAir
// ---------------------------------------------------------------------------

/// One-side meta-root combiner AIR. Constructed with the public
/// preimage + expected 32-byte digest, the AIR exposes a
/// constraint/public-column pair that verifies the sponge identity on
/// any honest trace produced by [`build_combiner_side_trace`].
pub struct FriStateCombinerAir {
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl FriStateCombinerAir {
    pub fn new(
        preimage: &FriStateCombinerPreimage,
        expected_state_root_fields: [Block128; 2],
    ) -> Self {
        let (constraints, public_columns) =
            emit_fri_state_combiner(preimage, expected_state_root_fields);
        Self {
            constraints,
            public_columns,
        }
    }

    pub fn build_trace(preimage: &FriStateCombinerPreimage) -> Trace {
        Trace::new(build_combiner_side_trace(preimage))
    }
}

impl Air for FriStateCombinerAir {
    fn n_columns(&self) -> usize {
        FRI_STATE_COMBINER_N_COLS
    }
    fn log_rows(&self) -> usize {
        FRI_STATE_COMBINER_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
    fn public_columns(&self) -> &[PublicColumn] {
        &self.public_columns
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    fn expected_fields_for(pre: &FriStateCombinerPreimage) -> [Block128; 2] {
        let cols = build_combiner_side_trace(pre);
        extract_combiner_digest_fields(&cols, COMBINER_PERM_LAYOUT)
    }

    // ---- Round-trip: trace digest ≡ native combine_roots -----------------

    #[test]
    fn trace_digest_matches_native_combine_roots() {
        for seed in [0x01u8, 0x5A, 0xA5, 0xFE] {
            let pre = mk_preimage(seed);
            let cols = build_combiner_side_trace(&pre);
            let trace_digest = extract_combiner_digest(&cols, COMBINER_PERM_LAYOUT);
            let expected = native_combine_roots(
                pre.log_slots,
                &pre.r_val,
                &pre.r_owner_hi,
                &pre.r_owner_lo,
            );
            assert_eq!(trace_digest, expected, "seed {seed:#04x}");
        }
    }

    #[test]
    fn row_and_column_budget_match_constants() {
        let pre = mk_preimage(0x7A);
        let cols = build_combiner_side_trace(&pre);
        assert_eq!(cols.len(), FRI_STATE_COMBINER_N_COLS);
        for c in &cols {
            assert_eq!(c.len(), FRI_STATE_COMBINER_N_ROWS);
        }
        assert!(
            FRI_STATE_COMBINER_N_PERMS_PER_SIDE * FRI_STATE_COMBINER_SLOT_ROWS
                <= FRI_STATE_COMBINER_N_ROWS,
        );
    }

    #[test]
    fn rate_block_decomposition_matches_preimage() {
        let pre = mk_preimage(0x01);
        let blocks = pre.rate_blocks();
        let mut expected0 = [0u8; 32];
        expected0[..4].copy_from_slice(&24u32.to_le_bytes());
        assert_eq!(blocks[0], expected0);
        assert_eq!(blocks[1], pre.r_val);
        assert_eq!(blocks[2], pre.r_owner_hi);
        assert_eq!(blocks[3], pre.r_owner_lo);
    }

    #[test]
    fn pad_block_lanes_match_native_finalize() {
        let pad = finalize_pad_block();
        let [lo, hi] = rate_block_to_lanes(&pad);
        assert_eq!(lo, Block128::from(FRI_STATE_COMBINER_PAD_LANE_0));
        assert_eq!(hi, Block128::from(FRI_STATE_COMBINER_PAD_LANE_1));
    }

    // ---- AIR.check on honest trace --------------------------------------

    #[test]
    fn air_accepts_honest_trace() {
        for seed in [0x01u8, 0x42, 0xFF] {
            let pre = mk_preimage(seed);
            let expected = expected_fields_for(&pre);
            let air = FriStateCombinerAir::new(&pre, expected);
            let trace = FriStateCombinerAir::build_trace(&pre);
            assert!(air.check(&trace), "seed {seed:#04x}");
        }
    }

    // ---- Tamper rejections ----------------------------------------------

    #[test]
    fn air_rejects_wrong_digest_pin() {
        let pre = mk_preimage(0x33);
        let correct = expected_fields_for(&pre);
        let bad = [correct[0] + Block128::ONE, correct[1]];
        let air = FriStateCombinerAir::new(&pre, bad);
        let trace = FriStateCombinerAir::build_trace(&pre);
        assert!(!air.check(&trace));
    }

    #[test]
    fn air_rejects_tampered_pre_s_iv_lane() {
        let pre = mk_preimage(0x77);
        let expected = expected_fields_for(&pre);
        let air = FriStateCombinerAir::new(&pre, expected);
        let mut cols = build_combiner_side_trace(&pre);
        cols[combiner_pre_s_base(0) + 2][0] =
            cols[combiner_pre_s_base(0) + 2][0] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_tampered_absorb_lane() {
        let pre = mk_preimage(0xAA);
        let expected = expected_fields_for(&pre);
        let air = FriStateCombinerAir::new(&pre, expected);
        let mut cols = build_combiner_side_trace(&pre);
        // Flip block-0 rate-lane-0 absorb (pre_s_0[0]@row 0). This
        // contradicts the public-input absorb pin.
        cols[combiner_pre_s_base(0) + 0][0] =
            cols[combiner_pre_s_base(0) + 0][0] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_tampered_perm_interior() {
        let pre = mk_preimage(0xC3);
        let expected = expected_fields_for(&pre);
        let air = FriStateCombinerAir::new(&pre, expected);
        let mut cols = build_combiner_side_trace(&pre);
        // Flip a cell inside perm 2's S-box chain.
        use crate::airs::poseidon_perm::POSEIDON_COL_SOUT;
        let row = combiner_instance_row_offset(2) + 5;
        cols[POSEIDON_COL_SOUT + 1][row] =
            cols[POSEIDON_COL_SOUT + 1][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_tampered_digest_cell() {
        // Flip the s[0] digest cell so it no longer matches the
        // declared expected_state_root fields.
        let pre = mk_preimage(0x01);
        let expected = expected_fields_for(&pre);
        let air = FriStateCombinerAir::new(&pre, expected);
        let mut cols = build_combiner_side_trace(&pre);
        let row = combiner_digest_row();
        cols[COMBINER_PERM_LAYOUT.s + 0][row] =
            cols[COMBINER_PERM_LAYOUT.s + 0][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn pre_seeds_install_capacity_iv_on_perm_0() {
        let pre = mk_preimage(0);
        let seeds = combiner_pre_seeds(&pre);
        let [iv_hi, iv_lo] = capacity_iv(TAG_FRISTATE);
        assert_eq!(seeds[0][2], iv_hi);
        assert_eq!(seeds[0][3], iv_lo);
    }

    // ---- Soundness: inter-perm absorb / MDS binding closes the tie 1..5 --
    //
    // Each test isolates a single prover deviation on the i ∈ 1..5
    // handoff (absorb XOR on rate lanes, capacity-lane pass-through,
    // shifted MDS binding, free mid-sponge seed) and asserts the AIR
    // rejects it. Collectively these cover the gap previously flagged
    // in §4c.3.b.

    #[test]
    fn air_rejects_tampered_pre_s_mid_sponge_rate_lane() {
        // Flip pre_s_2[0] on its live row (perm 1's output row). The
        // MDS-2 shifted binding no longer matches perm 2's row-0 state.
        let pre = mk_preimage(0x11);
        let expected = expected_fields_for(&pre);
        let air = FriStateCombinerAir::new(&pre, expected);
        let mut cols = build_combiner_side_trace(&pre);
        let row = combiner_pre_s_row(2);
        cols[combiner_pre_s_base(2)][row] =
            cols[combiner_pre_s_base(2)][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_tampered_pre_s_mid_sponge_capacity_lane() {
        // Flip pre_s_3[2] (a capacity lane) — absorb XOR gate enforces
        // pass-through, so this is caught by the capacity-lane absorb
        // gate (constant = 0).
        let pre = mk_preimage(0x22);
        let expected = expected_fields_for(&pre);
        let air = FriStateCombinerAir::new(&pre, expected);
        let mut cols = build_combiner_side_trace(&pre);
        let row = combiner_pre_s_row(3);
        cols[combiner_pre_s_base(3) + 2][row] =
            cols[combiner_pre_s_base(3) + 2][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_forged_mid_sponge_run() {
        // Classic attack the gap used to allow: replace perm 2's entire
        // run (seed + interior) with an honest permutation seeded from
        // a forged `pre_s_2`. The absorb-XOR gate at the perm 1 output
        // row rejects because the forged pre_s_2 no longer equals
        // prev_s + absorb_block_2.
        use noid_poseidon2b::native::permutation::Poseidon2bPermutation;
        let pre = mk_preimage(0x33);
        let expected = expected_fields_for(&pre);
        let air = FriStateCombinerAir::new(&pre, expected);
        let mut cols = build_combiner_side_trace(&pre);

        // Replace perm 2 pre-MDS seed with an arbitrary value, run it
        // honestly, and splice the resulting trace in. Subsequent perms
        // 3 and 4 keep the old trace rows — so the digest won't match,
        // but the local soundness tie we care about (absorb-XOR at
        // perm 1's output row) is what catches the forgery first.
        let forged_seed = [
            Block128::from(0xDEAD_BEEF_u128),
            Block128::from(0xCAFE_BABE_u128),
            Block128::from(0x1234_5678_u128),
            Block128::from(0xFEDC_BA98_u128),
        ];
        let row = combiner_pre_s_row(2);
        for lane in 0..STATE_SIZE {
            cols[combiner_pre_s_base(2) + lane][row] = forged_seed[lane];
        }
        // Rewrite perm 2's interior from the forged seed so MDS-2 is
        // locally satisfied (this is the soundness attack we want to
        // catch on the absorb-XOR tie, not the MDS tie).
        write_perm_trace_at_offset(
            &mut cols,
            COMBINER_PERM_LAYOUT,
            forged_seed,
            combiner_instance_row_offset(2),
        );
        let _ = Poseidon2bPermutation; // silences unused-import if refactored later

        assert!(!air.check(&Trace::new(cols)));
    }
}
