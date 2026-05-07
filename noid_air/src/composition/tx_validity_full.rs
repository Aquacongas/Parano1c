// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.4 — [`TxValidityCompositeFull`].
//!
//! Extends the 5.3 [`super::tx_validity_composite::TxValidityCompositeSkeleton`]
//! with `FRI_STATE_OPEN_N_INPUTS` `HAddrAir` instances, one per tx input, each
//! embedded via [`super::haddr_block`] and tied to the corresponding
//! FriStateOpen owner-lane cell via a T1 bridge pair.
//!
//! The skeleton already binds the state-root sponges (A) and the
//! lane-opening consistency (B). This file adds block (C):
//!
//! ```text
//!   C_i  (for i in 0..FRI_STATE_OPEN_N_INPUTS)
//!     HAddr sub-AIR(i):   s_B[0..2]@OUTPUT_ROW  ==  derive_address(secret_i)
//!     T1 bridges:
//!       s_B[0]@OUTPUT_ROW  ==  FriStateOpen.owner_hi[row = i]
//!       s_B[1]@OUTPUT_ROW  ==  FriStateOpen.owner_lo[row = i]
//! ```
//!
//! Per-input column budget for block C_i: `HADDR_N_COLS` (sub-AIR) + 1
//! (window indicator) + 2 × 4 (two T1 lane bridges) = `HADDR_N_COLS + 9`.
//! Four inputs → 4 × `(HADDR_N_COLS + 9)` extra outer columns.

use crate::airs::fri_state_combiner::FRI_STATE_COMBINER_LOG_ROWS;
use crate::airs::fri_state_combiner_composite::{
    FriStateCombinerComposite, COMBINER_COMPOSITE_LOG_ROWS, COMBINER_COMPOSITE_N_COLS,
};
use crate::airs::fri_state_open::{
    FriStateOpenAir, FriStateOpenWitness, COL_OWNER_HI, COL_OWNER_LO,
    FRI_STATE_OPEN_LOG_ROWS, FRI_STATE_OPEN_N_INPUTS, FRI_STATE_OPEN_N_ROWS,
    FRI_STATE_OPEN_WITNESS_COLS,
};
use crate::airs::haddr::{HADDR_LOG_ROWS, HADDR_N_COLS};
use crate::composition::haddr_block::{
    emit_haddr_block, write_haddr_block_trace, HAddrBlockColumns, HAddrBlockParams,
    HAddrBlockT1Targets,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWrapper, WrapPolicy,
};
use crate::composition::t1_owner_tie::T1LaneColumnBudget;
use crate::composition::tx_validity_composite::{
    SKEL_COMBINER_COL_OFFSET, SKEL_OPEN_COL_OFFSET, SKEL_OPEN_WINDOW_INDICATOR_COL,
    TX_VALIDITY_SKELETON_LOG_ROWS, TX_VALIDITY_SKELETON_N_COLS,
};
use crate::gates::const_column::PublicColumn;
use crate::{Air, CompositeAir, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::{Block128, TowerField};

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Outer log-rows: inherited from the 5.3 skeleton (512 rows). HAddr's
/// 256-row footprint fits comfortably inside a 512-row outer trace.
pub const TX_VALIDITY_FULL_LOG_ROWS: usize = TX_VALIDITY_SKELETON_LOG_ROWS;

/// Compile-time height sanity.
const _: () = {
    assert!(HADDR_LOG_ROWS <= TX_VALIDITY_FULL_LOG_ROWS);
    assert!(FRI_STATE_OPEN_LOG_ROWS <= TX_VALIDITY_FULL_LOG_ROWS);
    assert!(FRI_STATE_COMBINER_LOG_ROWS == COMBINER_COMPOSITE_LOG_ROWS);
};

/// Extra columns per embedded HAddr block: sub-AIR columns + window
/// indicator + 4 bridge/indicator cols × 2 lanes.
pub const HADDR_BLOCK_OUTER_COLS: usize = HADDR_N_COLS + 1 + 8;

/// Outer col offset of the first HAddr block.
pub const FULL_HADDR_BLOCKS_BASE: usize = TX_VALIDITY_SKELETON_N_COLS;

/// Total outer column count.
pub const TX_VALIDITY_FULL_N_COLS: usize =
    FULL_HADDR_BLOCKS_BASE + FRI_STATE_OPEN_N_INPUTS * HADDR_BLOCK_OUTER_COLS;

/// Per-input HAddr block column base.
pub const fn full_haddr_block_base(input: usize) -> usize {
    FULL_HADDR_BLOCKS_BASE + input * HADDR_BLOCK_OUTER_COLS
}

// Each HAddr block's internal sub-layout (relative to its base):
const REL_HADDR_SUBAIR_COL: usize = 0; // [0, HADDR_N_COLS)
const REL_WINDOW_INDICATOR_COL: usize = HADDR_N_COLS;
const REL_T1_HI_BRIDGE_COL: usize = HADDR_N_COLS + 1;
const REL_T1_HI_SRC_IND_COL: usize = HADDR_N_COLS + 2;
const REL_T1_HI_DST_IND_COL: usize = HADDR_N_COLS + 3;
const REL_T1_HI_TRANS_IND_COL: usize = HADDR_N_COLS + 4;
const REL_T1_LO_BRIDGE_COL: usize = HADDR_N_COLS + 5;
const REL_T1_LO_SRC_IND_COL: usize = HADDR_N_COLS + 6;
const REL_T1_LO_DST_IND_COL: usize = HADDR_N_COLS + 7;
const REL_T1_LO_TRANS_IND_COL: usize = HADDR_N_COLS + 8;

fn haddr_block_params_for(input: usize, outer_n_cols: usize) -> HAddrBlockParams {
    let base = full_haddr_block_base(input);
    HAddrBlockParams {
        cols: HAddrBlockColumns {
            col_offset: base + REL_HADDR_SUBAIR_COL,
            window_indicator_col: base + REL_WINDOW_INDICATOR_COL,
            t1_hi_budget: T1LaneColumnBudget {
                bridge_col: base + REL_T1_HI_BRIDGE_COL,
                src_indicator_col: base + REL_T1_HI_SRC_IND_COL,
                dst_indicator_col: base + REL_T1_HI_DST_IND_COL,
                transition_indicator_col: base + REL_T1_HI_TRANS_IND_COL,
            },
            t1_lo_budget: T1LaneColumnBudget {
                bridge_col: base + REL_T1_LO_BRIDGE_COL,
                src_indicator_col: base + REL_T1_LO_SRC_IND_COL,
                dst_indicator_col: base + REL_T1_LO_DST_IND_COL,
                transition_indicator_col: base + REL_T1_LO_TRANS_IND_COL,
            },
        },
        row_window_start: 0,
        outer_n_cols,
        outer_log_rows: TX_VALIDITY_FULL_LOG_ROWS,
        t1_targets: HAddrBlockT1Targets {
            // FriStateOpen owner-lane cells: row = input index, cols =
            // SKEL_OPEN_COL_OFFSET + {COL_OWNER_HI, COL_OWNER_LO}.
            owner_hi_dst_col: SKEL_OPEN_COL_OFFSET + COL_OWNER_HI,
            owner_hi_dst_row: input,
            owner_lo_dst_col: SKEL_OPEN_COL_OFFSET + COL_OWNER_LO,
            owner_lo_dst_row: input,
        },
    }
}

// ---------------------------------------------------------------------------
// Column-shift adapter (local copy of the skeleton's; kept private)
// ---------------------------------------------------------------------------

struct ShiftedColumnsConstraint {
    inner: Box<dyn Constraint>,
    shifted_cols: Vec<usize>,
    shifted_next: Vec<usize>,
}

impl ShiftedColumnsConstraint {
    fn new(inner: Box<dyn Constraint>, offset: usize, inner_n_cols: usize) -> Self {
        for &c in inner.columns() {
            assert!(c < inner_n_cols);
        }
        for &c in inner.shifted_columns() {
            assert!(c < inner_n_cols);
        }
        let shifted_cols = inner.columns().iter().map(|&c| c + offset).collect();
        let shifted_next = inner.shifted_columns().iter().map(|&c| c + offset).collect();
        Self {
            inner,
            shifted_cols,
            shifted_next,
        }
    }
}

impl Constraint for ShiftedColumnsConstraint {
    fn degree(&self) -> usize {
        self.inner.degree()
    }
    fn columns(&self) -> &[usize] {
        &self.shifted_cols
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted_next
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        self.inner.evaluate(frame)
    }
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        self.inner.evaluate_flat(frame)
    }
}

fn shift_public_column(pc: PublicColumn, offset: usize) -> PublicColumn {
    PublicColumn::new(pc.col + offset, pc.values)
}

// ---------------------------------------------------------------------------
// Full composite
// ---------------------------------------------------------------------------

/// Stage 5.4 full composite: combiner + FriStateOpen + N_INPUTS × HAddr
/// (each tied to an owner lane via T1 bridges).
pub struct TxValidityCompositeFull {
    pub air: CompositeAir,
    combiner: FriStateCombinerComposite,
    open_witness: FriStateOpenWitness,
    open_public_columns: Vec<PublicColumn>,
    /// Per-input spend secrets (hi, lo). One set per `FriStateOpenClaim`
    /// entry; inactive / mint / dummy inputs still need a placeholder
    /// secret — the HAddr sub-AIR runs unconditionally on every block.
    secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
}

impl TxValidityCompositeFull {
    /// Build the full composite.
    pub fn new(
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
        secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    ) -> Self {
        let outer_n_cols = TX_VALIDITY_FULL_N_COLS;
        let outer_log_rows = TX_VALIDITY_FULL_LOG_ROWS;

        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // Block A — combiner, plain column shift (no row window).
        let (combiner_constraints, combiner_publics) = clone_combiner_parts(&combiner);
        for c in combiner_constraints {
            constraints.push(Box::new(ShiftedColumnsConstraint::new(
                c,
                SKEL_COMBINER_COL_OFFSET,
                COMBINER_COMPOSITE_N_COLS,
            )));
        }
        for pc in combiner_publics {
            public_columns.push(shift_public_column(pc, SKEL_COMBINER_COL_OFFSET));
        }

        // Block B — FriStateOpen via RowWindowWrapper.
        let (open_n_cols, open_constraints, open_publics) = open_air.into_parts();
        assert_eq!(open_n_cols, FRI_STATE_OPEN_WITNESS_COLS);
        let inner_view = InnerAirView {
            inner_n_cols: open_n_cols,
            inner_log_rows: FRI_STATE_OPEN_LOG_ROWS,
            constraints: open_constraints,
            public_columns: open_publics.clone(),
            requires_true_cyclic_wrap: false,
        };
        let open_params = RowWindowParams {
            col_offset: SKEL_OPEN_COL_OFFSET,
            outer_n_cols,
            outer_log_rows,
            row_window_start: 0,
            row_window_end: FRI_STATE_OPEN_N_ROWS,
            window_indicator_col: SKEL_OPEN_WINDOW_INDICATOR_COL,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: Vec::new(),
        };
        let open_wiring = RowWindowWrapper::wrap(inner_view, open_params);
        constraints.extend(open_wiring.constraints);
        public_columns.extend(open_wiring.public_columns);

        // Block C — FRI_STATE_OPEN_N_INPUTS × HAddr, each tied via T1 to
        // the corresponding FriStateOpen owner lane row.
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let params = haddr_block_params_for(input, outer_n_cols);
            let wiring = emit_haddr_block(params);
            constraints.extend(wiring.constraints);
            public_columns.extend(wiring.public_columns);
        }

        let air = CompositeAir::from_parts_with_publics(
            outer_log_rows,
            outer_n_cols,
            constraints,
            public_columns,
        );

        Self {
            air,
            combiner,
            open_witness,
            open_public_columns: open_publics,
            secrets,
        }
    }

    /// Build an honest outer trace.
    pub fn build_trace(&self) -> Trace {
        let outer_n_rows = 1usize << TX_VALIDITY_FULL_LOG_ROWS;
        let mut cols: Vec<Vec<Block128>> = (0..TX_VALIDITY_FULL_N_COLS)
            .map(|_| vec![Block128::ZERO; outer_n_rows])
            .collect();

        // Combiner columns on rows 0..combiner_n_rows.
        let combiner_trace = self.combiner.build_trace();
        let combiner_cols = combiner_trace.columns;
        assert_eq!(combiner_cols.len(), COMBINER_COMPOSITE_N_COLS);
        for (i, src) in combiner_cols.into_iter().enumerate() {
            cols[SKEL_COMBINER_COL_OFFSET + i] = src;
        }

        // Open columns on rows 0..FRI_STATE_OPEN_N_ROWS.
        let open_inner =
            build_open_inner_cols(&self.open_witness, &self.open_public_columns);
        assert_eq!(open_inner.len(), FRI_STATE_OPEN_WITNESS_COLS);
        for (i, src) in open_inner.into_iter().enumerate() {
            let dst = &mut cols[SKEL_OPEN_COL_OFFSET + i];
            for (r, v) in src.into_iter().enumerate() {
                dst[r] = v;
            }
        }

        // HAddr blocks + T1 bridges. Write each block's sub-trace; the
        // helper plants the owner-lane destination cell (= native HAddr
        // squeeze) back into the FriStateOpen column band we just wrote.
        // This overwrite is deliberate: the honest FriStateOpen owner-
        // lane value is exactly `derive_address(secret)` hi/lo, so the
        // witness stays internally consistent.
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let params = haddr_block_params_for(input, TX_VALIDITY_FULL_N_COLS);
            let _ = write_haddr_block_trace(&mut cols, params, self.secrets[input]);
        }

        // Final pass: overwrite every public column with its programme.
        // Mirrors the skeleton's build_trace — `Air::check` enforces
        // trace == programme on every declared public column.
        for pc in self.air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }

        Trace::new(cols)
    }

    pub fn air(&self) -> &CompositeAir {
        &self.air
    }

    pub fn secrets(&self) -> &[[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] {
        &self.secrets
    }
}

// ---------------------------------------------------------------------------
// Helpers (ported from the skeleton; see `tx_validity_composite.rs`)
// ---------------------------------------------------------------------------

fn clone_combiner_parts(
    c: &FriStateCombinerComposite,
) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
    use crate::airs::fri_state_combiner::{
        build_combiner_side_trace, extract_combiner_digest_fields, COMBINER_PERM_LAYOUT,
    };
    let prev = *c.prev_preimage();
    let new = *c.new_preimage();
    let prev_fields =
        extract_combiner_digest_fields(&build_combiner_side_trace(&prev), COMBINER_PERM_LAYOUT);
    let new_fields =
        extract_combiner_digest_fields(&build_combiner_side_trace(&new), COMBINER_PERM_LAYOUT);
    FriStateCombinerComposite::new(prev, prev_fields, new, new_fields).into_parts()
}

fn build_open_inner_cols(
    witness: &FriStateOpenWitness,
    publics: &[PublicColumn],
) -> Vec<Vec<Block128>> {
    let mut cols = witness.build_columns(FRI_STATE_OPEN_WITNESS_COLS);
    for pc in publics {
        cols[pc.col] = pc.values.clone();
    }
    cols
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::fri_state_combiner::{
        build_combiner_side_trace, extract_combiner_digest_fields, FriStateCombinerPreimage,
        COMBINER_PERM_LAYOUT,
    };
    use crate::airs::fri_state_open::FriStateOpenClaim;
    use crate::airs::haddr::{HADDR_LAYOUT_B, HADDR_OUTPUT_ROW};
    use noid_core::{CanonicalSerialize, TowerField};

    fn mk_combiner_preimage(seed: u8) -> FriStateCombinerPreimage {
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

    fn mk_secret(seed: u128) -> [Block128; 2] {
        [
            Block128::from(seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(seed.wrapping_mul(0xBF58476D1CE4E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    fn addr_for_secret(secret: [Block128; 2]) -> [Block128; 2] {
        // Compute via the HAddr trace builder — canonical source of
        // truth for the witness-visible address lanes.
        let cols = crate::airs::haddr::build_haddr_trace(secret);
        crate::airs::haddr::extract_haddr_output(&cols)
    }

    fn mk_eval_point() -> [Block128; 4] {
        let mut r = [Block128::ZERO; 4];
        for (i, slot) in r.iter_mut().enumerate() {
            *slot = Block128::from(0x100u128 + (i as u128) * 0x11);
        }
        r
    }

    fn mk_gamma() -> Block128 {
        Block128::from(0xB16B_00B5_0000_BEEFu128)
    }

    fn build_full() -> TxValidityCompositeFull {
        let prev_preimage = mk_combiner_preimage(0x5A);
        let new_preimage = mk_combiner_preimage(0xA5);
        let prev_trace = build_combiner_side_trace(&prev_preimage);
        let new_trace = build_combiner_side_trace(&new_preimage);
        let prev_fields = extract_combiner_digest_fields(&prev_trace, COMBINER_PERM_LAYOUT);
        let new_fields = extract_combiner_digest_fields(&new_trace, COMBINER_PERM_LAYOUT);
        let combiner = FriStateCombinerComposite::new(
            prev_preimage,
            prev_fields,
            new_preimage,
            new_fields,
        );

        // Per-input secrets; spend claims get honest HAddr-derived
        // owners, dummy inputs still receive a placeholder secret so
        // the HAddr sub-AIR has a well-defined trace.
        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            mk_secret(11),
            mk_secret(22),
            mk_secret(33),
            mk_secret(44),
        ];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            addr_for_secret(secrets[0]),
            addr_for_secret(secrets[1]),
            addr_for_secret(secrets[2]),
            addr_for_secret(secrets[3]),
        ];

        // Two active spend claims whose owner cells match their
        // HAddr-derived addresses; two dummy (empty) claims pin the
        // owner lanes to zero. Dummy rows still get HAddr blocks
        // tied — the T1 bridge forces the owner cells to zero, so the
        // corresponding HAddr block's squeeze must ALSO be zero. To
        // satisfy that without forging a preimage, we plant real
        // HAddr-derived addresses in `FriStateOpenClaim`'s owner_hi /
        // owner_lo fields for EVERY row (including "dummy" rows).
        // Dummy rows stay `live = false` via `is_spend = false &&
        // is_mint = false`, so the accumulator gates ignore their
        // pre-values, but the column cells themselves are still pinned
        // by the T1 bridge to HAddr's squeeze.
        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            spend_with_owner(11, 0, addrs[0]),
            spend_with_owner(22, 3, addrs[1]),
            empty_with_owner(addrs[2]),
            empty_with_owner(addrs[3]),
        ];
        let base = FriStateOpenWitness::from_claims(claims)
            .with_eval_point(mk_eval_point())
            .with_gamma(mk_gamma());
        let prev_lane_openings = [
            Block128::from(0xA5A5_1234_5678_9ABC_u128),
            Block128::from(0xDEAD_BEEF_CAFE_F00D_u128),
            Block128::from(0x1357_9BDF_2468_ACE0_u128),
        ];
        let new_lane_openings = base.expected_new_lane_openings(prev_lane_openings);
        let open_witness = base.with_lane_openings(prev_lane_openings, new_lane_openings);
        let open_air = FriStateOpenAir::new(
            &claims,
            open_witness.prev_lane_openings,
            open_witness.new_lane_openings,
            mk_eval_point(),
            mk_gamma(),
            open_witness.expected_batched_claims(),
        );

        TxValidityCompositeFull::new(combiner, open_air, open_witness, secrets)
    }

    fn spend_with_owner(seed: u128, slot: u32, owner: [Block128; 2]) -> FriStateOpenClaim {
        let v = Block128::from(seed);
        FriStateOpenClaim {
            slot_index: slot,
            value: v,
            owner_hi: owner[0],
            owner_lo: owner[1],
            delta_value: v,
            delta_owner_hi: owner[0],
            delta_owner_lo: owner[1],
            is_spend: true,
            is_mint: false,
        }
    }

    fn empty_with_owner(owner: [Block128; 2]) -> FriStateOpenClaim {
        FriStateOpenClaim {
            slot_index: 0,
            value: Block128::ZERO,
            owner_hi: owner[0],
            owner_lo: owner[1],
            delta_value: Block128::ZERO,
            delta_owner_hi: Block128::ZERO,
            delta_owner_lo: Block128::ZERO,
            is_spend: false,
            is_mint: false,
        }
    }

    #[test]
    fn layout_constants_agree() {
        assert_eq!(
            TX_VALIDITY_FULL_N_COLS,
            TX_VALIDITY_SKELETON_N_COLS
                + FRI_STATE_OPEN_N_INPUTS * HADDR_BLOCK_OUTER_COLS
        );
        assert_eq!(TX_VALIDITY_FULL_LOG_ROWS, TX_VALIDITY_SKELETON_LOG_ROWS);
        // Each block's relative layout is exactly HADDR_N_COLS + 9.
        assert_eq!(HADDR_BLOCK_OUTER_COLS, HADDR_N_COLS + 9);
    }

    #[test]
    fn honest_trace_accepts() {
        let comp = build_full();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
    }

    #[test]
    fn haddr_squeeze_matches_native_address_per_input() {
        use noid_poseidon2b::primitives::{derive_address, SpendSecret};
        let comp = build_full();
        let cols = comp.build_trace().columns;
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let base = full_haddr_block_base(input);
            let hi_col = base + HADDR_LAYOUT_B.s;
            let lo_col = base + HADDR_LAYOUT_B.s + 1;
            let row = HADDR_OUTPUT_ROW;
            let addr_hi = cols[hi_col][row];
            let addr_lo = cols[lo_col][row];

            let sec = comp.secrets()[input];
            let hi_bytes = sec[0].to_bytes();
            let lo_bytes = sec[1].to_bytes();
            let mut sec_bytes = [0u8; 32];
            sec_bytes[..16].copy_from_slice(&hi_bytes[..16]);
            sec_bytes[16..].copy_from_slice(&lo_bytes[..16]);
            let native = derive_address(&SpendSecret(sec_bytes));
            let ah = addr_hi.to_bytes();
            let al = addr_lo.to_bytes();
            let mut out = [0u8; 32];
            out[..16].copy_from_slice(&ah[..16]);
            out[16..].copy_from_slice(&al[..16]);
            assert_eq!(out, native.0, "input {input}");

            // The matching FriStateOpen owner lane cell mirrors the
            // HAddr squeeze (that's the T1 bridge contract).
            assert_eq!(cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][input], addr_hi);
            assert_eq!(cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_LO][input], addr_lo);
        }
    }

    #[test]
    fn open_owner_hi_tamper_rejects_via_t1() {
        let comp = build_full();
        let mut cols = comp.build_trace().columns;
        cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][0] =
            cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][0] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn open_owner_lo_tamper_rejects_via_t1() {
        let comp = build_full();
        let mut cols = comp.build_trace().columns;
        cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_LO][2] =
            cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_LO][2] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_squeeze_tamper_rejects_via_t1() {
        let comp = build_full();
        let mut cols = comp.build_trace().columns;
        // Tamper input 1's HAddr squeeze hi. The sub-AIR constraints
        // reject this directly (the permutation gates wouldn't be
        // satisfied), but even if they didn't, the T1 bridge catches
        // the src mismatch.
        let base = full_haddr_block_base(1);
        let col = base + HADDR_LAYOUT_B.s;
        cols[col][HADDR_OUTPUT_ROW] = cols[col][HADDR_OUTPUT_ROW] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_interior_tamper_rejects() {
        let comp = build_full();
        let mut cols = comp.build_trace().columns;
        // Tamper an interior sbox-output cell in input 2's HAddr block.
        let base = full_haddr_block_base(2);
        use crate::airs::haddr::HADDR_LAYOUT_A;
        let col = base + HADDR_LAYOUT_A.sout + 2;
        cols[col][5] = cols[col][5] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn combiner_tamper_rejects() {
        let comp = build_full();
        let mut cols = comp.build_trace().columns;
        let reg = crate::composition::registry::CombinerCompositeCols::new();
        let row = crate::airs::fri_state_combiner::combiner_digest_row();
        cols[reg.prev_digest_hi][row] = cols[reg.prev_digest_hi][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }
}
