// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.3 — [`TxValidityComposite`] skeleton.
//!
//! First cut of the unified per-tx composite. The skeleton embeds the
//! two sub-AIRs whose column budgets are small enough to stitch without
//! waiting on the rest of Stage 5: `FriStateCombinerComposite` (the
//! prev/new state-root sponge) and `FriStateOpenAir` (per-input
//! lane-opening consistency). No Stage 5 ties yet; this cut exists
//! purely to pin down the embedding contract end-to-end.
//!
//! # Layout
//!
//! Outer shape: `log_rows = COMBINER_COMPOSITE_LOG_ROWS = 9`
//! (512 rows). `FriStateCombinerComposite` uses every row of its own
//! trace, so its embedding is a plain column shift — no row window.
//! `FriStateOpenAir` lives on rows `[0, 8)` via `RowWindowWrapper`
//! (MaskOff policy, inner `requires_true_cyclic_wrap == false`).
//!
//! | block | source AIR                    | col span                                                    | rows       |
//! |-------|-------------------------------|-------------------------------------------------------------|------------|
//! | A     | `FriStateCombinerComposite`   | `[0, COMBINER_COMPOSITE_N_COLS)`                            | full 0..512 |
//! | B     | `FriStateOpenAir`             | `[COMBINER_COMPOSITE_N_COLS, + FRI_STATE_OPEN_WITNESS_COLS)`| 0..8       |
//! | B.ind | window indicator for B         | 1 col                                                       | full       |
//!
//! Row silencing for B: multi-hot `PublicColumn` ONE on rows 0..8 and
//! ZERO elsewhere, gated onto every inner B constraint via
//! `SelectorGate`. B's own `PublicColumn` programmes (row indicators,
//! step indicator) are lifted by `RowWindowWrapper`: inner values on
//! rows 0..8, zero elsewhere.
//!
//! # What this does *not* do
//!
//! - No Stage 5 ties: T1 (`HAddr.owner ↔ FriStateOpen.owner`) et al.
//!   land in Stage 5.4+.
//! - No Stage 6 `PublicInputs` surface: the combiner's
//!   `expected_{prev,new}_state_root_fields` are still inner pins.
//! - No `TxBodyMerkleAir` / `HAddr` / `HAuth` / `HLeaf` — those widen
//!   the column budget and require `log_rows = 13`, deferred to
//!   later substages.

use crate::airs::fri_state_combiner::FRI_STATE_COMBINER_LOG_ROWS;
use crate::airs::fri_state_combiner_composite::{
    FriStateCombinerComposite, COMBINER_COMPOSITE_LOG_ROWS, COMBINER_COMPOSITE_N_COLS,
};
use crate::airs::fri_state_open::{
    FriStateOpenAir, FriStateOpenWitness, FRI_STATE_OPEN_LOG_ROWS, FRI_STATE_OPEN_N_ROWS,
    FRI_STATE_OPEN_WITNESS_COLS,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWrapper, WrapPolicy,
};
use crate::gates::const_column::PublicColumn;
use crate::{Air, CompositeAir, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::{Block128, TowerField};

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Outer `log_rows` of the skeleton. Pinned at the combiner composite's
/// height; Stage 5.4+ bumps this to 13 once `TxBodyMerkleAir` enters.
pub const TX_VALIDITY_SKELETON_LOG_ROWS: usize = COMBINER_COMPOSITE_LOG_ROWS;

/// Column offset of the combiner sub-composite.
pub const SKEL_COMBINER_COL_OFFSET: usize = 0;

/// Column offset of the FRI-state-open block.
pub const SKEL_OPEN_COL_OFFSET: usize = COMBINER_COMPOSITE_N_COLS;

/// Column reserved for the FRI-state-open window indicator.
pub const SKEL_OPEN_WINDOW_INDICATOR_COL: usize =
    SKEL_OPEN_COL_OFFSET + FRI_STATE_OPEN_WITNESS_COLS;

/// Total outer column count.
pub const TX_VALIDITY_SKELETON_N_COLS: usize = SKEL_OPEN_WINDOW_INDICATOR_COL + 1;

// Compile-time sanity on the height assumption: the Open sub-AIR fits
// in the combiner height.
const _: () = {
    assert!(FRI_STATE_OPEN_LOG_ROWS <= COMBINER_COMPOSITE_LOG_ROWS);
    assert!(FRI_STATE_COMBINER_LOG_ROWS == COMBINER_COMPOSITE_LOG_ROWS);
};

// ---------------------------------------------------------------------------
// Column-shift adapter (local; not re-exported)
// ---------------------------------------------------------------------------

/// Plain column-offset adapter for a sub-AIR whose row shape matches
/// the outer `log_rows` (i.e. no row-window wrapping needed). The Stage 5
/// `RowWindowWrapper` would work here too, but it'd burn an indicator
/// column on an always-on selector — wasteful.
struct ShiftedColumnsConstraint {
    inner: Box<dyn Constraint>,
    shifted_cols: Vec<usize>,
    shifted_next: Vec<usize>,
}

impl ShiftedColumnsConstraint {
    fn new(inner: Box<dyn Constraint>, offset: usize, inner_n_cols: usize) -> Self {
        for &c in inner.columns() {
            assert!(
                c < inner_n_cols,
                "TxValidityComposite skeleton: inner local col {c} out of inner range [0, {inner_n_cols})"
            );
        }
        for &c in inner.shifted_columns() {
            assert!(
                c < inner_n_cols,
                "TxValidityComposite skeleton: inner shifted col {c} out of inner range [0, {inner_n_cols})"
            );
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

// ---------------------------------------------------------------------------
// Skeleton composite
// ---------------------------------------------------------------------------

/// Configured skeleton bundle: the embedded composite AIR plus the
/// witnesses needed to rebuild its honest trace.
pub struct TxValidityCompositeSkeleton {
    pub air: CompositeAir,
    combiner: FriStateCombinerComposite,
    open_witness: FriStateOpenWitness,
    open_public_columns: Vec<PublicColumn>,
}

impl TxValidityCompositeSkeleton {
    /// Build the skeleton from already-constructed sub-AIR inputs.
    ///
    /// Caller supplies:
    /// - combiner preimages + expected root field pins (identical to
    ///   `FriStateCombinerComposite::new` inputs);
    /// - open claims, lane openings, eval point, gamma, expected
    ///   batched claims (identical to `FriStateOpenAir::new` inputs);
    /// - `open_witness` matching those open inputs, used by
    ///   [`Self::build_trace`] to populate the FRI-state-open columns.
    pub fn new(
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
    ) -> Self {
        let outer_n_cols = TX_VALIDITY_SKELETON_N_COLS;
        let outer_log_rows = TX_VALIDITY_SKELETON_LOG_ROWS;

        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // Block A: combiner, plain column shift (no row window).
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

        // Block B: open, RowWindowWrapper at rows [0, FRI_STATE_OPEN_N_ROWS).
        let (open_n_cols, open_constraints, open_publics) = open_air.into_parts();
        assert_eq!(open_n_cols, FRI_STATE_OPEN_WITNESS_COLS);
        let inner_view = InnerAirView {
            inner_n_cols: open_n_cols,
            inner_log_rows: FRI_STATE_OPEN_LOG_ROWS,
            constraints: open_constraints,
            public_columns: open_publics.clone(),
            requires_true_cyclic_wrap: false,
        };
        let params = RowWindowParams {
            col_offset: SKEL_OPEN_COL_OFFSET,
            outer_n_cols,
            outer_log_rows,
            row_window_start: 0,
            row_window_end: FRI_STATE_OPEN_N_ROWS,
            window_indicator_col: SKEL_OPEN_WINDOW_INDICATOR_COL,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: Vec::new(),
        };
        let open_wiring = RowWindowWrapper::wrap(inner_view, params);
        constraints.extend(open_wiring.constraints);
        public_columns.extend(open_wiring.public_columns);

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
        }
    }

    /// Build an honest outer trace by composing each sub-AIR's honest
    /// sub-trace into its assigned column block.
    pub fn build_trace(&self) -> Trace {
        let outer_n_rows = 1usize << TX_VALIDITY_SKELETON_LOG_ROWS;
        let mut cols: Vec<Vec<Block128>> =
            (0..TX_VALIDITY_SKELETON_N_COLS).map(|_| vec![Block128::ZERO; outer_n_rows]).collect();

        // --- Combiner side -------------------------------------------------
        let combiner_trace = self.combiner.build_trace();
        let combiner_cols = combiner_trace.columns;
        assert_eq!(combiner_cols.len(), COMBINER_COMPOSITE_N_COLS);
        for (i, src) in combiner_cols.into_iter().enumerate() {
            assert_eq!(src.len(), outer_n_rows);
            cols[SKEL_COMBINER_COL_OFFSET + i] = src;
        }

        // --- Open side -----------------------------------------------------
        // Build the inner-rows-wide open trace, then embed at rows
        // [0, FRI_STATE_OPEN_N_ROWS) in the outer trace. Outer rows beyond
        // the window stay at ZERO for Open-owned columns; the Open AIR's
        // constraints are silenced on those rows by the window selector.
        let inner_cols =
            build_open_inner_cols(&self.open_witness, &self.open_public_columns);
        assert_eq!(inner_cols.len(), FRI_STATE_OPEN_WITNESS_COLS);
        for (i, src) in inner_cols.into_iter().enumerate() {
            assert_eq!(src.len(), FRI_STATE_OPEN_N_ROWS);
            let dst = &mut cols[SKEL_OPEN_COL_OFFSET + i];
            for (r, v) in src.into_iter().enumerate() {
                dst[r] = v;
            }
        }

        // --- Overwrite every public column with its programme ------------
        // The composite owns programmes for: combiner-side inner publics
        // (shifted), the Open window indicator, and Open's inner publics
        // (row-wise lifted from inner to outer). `Air::check` will
        // enforce trace == programme, so writing them here guarantees
        // the honest trace matches on the nose.
        for pc in self.air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }

        Trace::new(cols)
    }

    pub fn air(&self) -> &CompositeAir {
        &self.air
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Clone the combiner composite's wiring parts by reconstructing from
/// its preserved preimages + pinned digest fields. The composite itself
/// does not expose a `Clone` for `Box<dyn Constraint>`, so we rebuild
/// from scratch — cheap (one construction per composite build).
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

fn shift_public_column(pc: PublicColumn, offset: usize) -> PublicColumn {
    PublicColumn::new(pc.col + offset, pc.values)
}

/// Rebuild the FRI-state-open inner witness columns for the skeleton's
/// row window. Mirrors `FriStateOpenAir::build_trace` but uses the
/// already-captured public-column programmes from the owning
/// `FriStateOpenAir` (avoiding a second construction).
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
    use crate::airs::fri_state_combiner::FriStateCombinerPreimage;
    use crate::airs::fri_state_combiner_composite::{
        COMBINER_COMPOSITE_NEW_OFFSET, COMBINER_COMPOSITE_PREV_OFFSET,
    };
    use crate::airs::fri_state_open::{
        FriStateOpenClaim, COL_OWNER_HI, COL_OWNER_LO, COL_VALUE, FRI_STATE_OPEN_N_INPUTS,
    };

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

    fn mk_spend_claim(seed: u128, slot: u32) -> FriStateOpenClaim {
        let v = Block128::from(seed);
        let hi = Block128::from(seed.wrapping_mul(3) + 1);
        let lo = Block128::from(seed.wrapping_mul(7) + 2);
        FriStateOpenClaim {
            slot_index: slot,
            value: v,
            owner_hi: hi,
            owner_lo: lo,
            delta_value: v,
            delta_owner_hi: hi,
            delta_owner_lo: lo,
            is_spend: true,
            is_mint: false,
        }
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

    fn build_skeleton() -> TxValidityCompositeSkeleton {
        let prev_preimage = mk_combiner_preimage(0x5A);
        let new_preimage = mk_combiner_preimage(0xA5);

        // Expected root fields derived from honest combiner traces.
        let prev_trace = crate::airs::fri_state_combiner::build_combiner_side_trace(&prev_preimage);
        let new_trace = crate::airs::fri_state_combiner::build_combiner_side_trace(&new_preimage);
        let prev_fields = crate::airs::fri_state_combiner::extract_combiner_digest_fields(
            &prev_trace,
            crate::airs::fri_state_combiner::COMBINER_PERM_LAYOUT,
        );
        let new_fields = crate::airs::fri_state_combiner::extract_combiner_digest_fields(
            &new_trace,
            crate::airs::fri_state_combiner::COMBINER_PERM_LAYOUT,
        );
        let combiner = FriStateCombinerComposite::new(
            prev_preimage,
            prev_fields,
            new_preimage,
            new_fields,
        );

        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = [
            mk_spend_claim(11, 0),
            mk_spend_claim(22, 3),
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
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

        TxValidityCompositeSkeleton::new(combiner, open_air, open_witness)
    }

    #[test]
    fn layout_constants_agree() {
        assert_eq!(SKEL_COMBINER_COL_OFFSET, 0);
        assert_eq!(SKEL_OPEN_COL_OFFSET, COMBINER_COMPOSITE_N_COLS);
        assert_eq!(
            TX_VALIDITY_SKELETON_N_COLS,
            COMBINER_COMPOSITE_N_COLS + FRI_STATE_OPEN_WITNESS_COLS + 1
        );
        assert_eq!(TX_VALIDITY_SKELETON_LOG_ROWS, 9);
        let _ = COMBINER_COMPOSITE_PREV_OFFSET;
        let _ = COMBINER_COMPOSITE_NEW_OFFSET;
    }

    #[test]
    fn honest_trace_accepts() {
        let skel = build_skeleton();
        let trace = skel.build_trace();
        assert!(skel.air().check(&trace));
    }

    #[test]
    fn combiner_side_tamper_rejects() {
        let skel = build_skeleton();
        let mut cols = skel.build_trace().columns;
        // Flip the prev-side digest-hi cell one byte.
        let reg = crate::composition::registry::CombinerCompositeCols::new();
        let row = crate::airs::fri_state_combiner::combiner_digest_row();
        cols[reg.prev_digest_hi][row] = cols[reg.prev_digest_hi][row] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!skel.air().check(&trace));
    }

    #[test]
    fn open_value_tamper_rejects() {
        let skel = build_skeleton();
        let mut cols = skel.build_trace().columns;
        let col = SKEL_OPEN_COL_OFFSET + COL_VALUE;
        cols[col][0] = cols[col][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!skel.air().check(&trace));
    }

    #[test]
    fn open_owner_hi_tamper_rejects() {
        let skel = build_skeleton();
        let mut cols = skel.build_trace().columns;
        let col = SKEL_OPEN_COL_OFFSET + COL_OWNER_HI;
        cols[col][1] = cols[col][1] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!skel.air().check(&trace));
    }

    #[test]
    fn open_owner_lo_tamper_rejects() {
        let skel = build_skeleton();
        let mut cols = skel.build_trace().columns;
        let col = SKEL_OPEN_COL_OFFSET + COL_OWNER_LO;
        cols[col][0] = cols[col][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!skel.air().check(&trace));
    }

    #[test]
    fn outside_window_edit_is_accepted() {
        // Edit an Open-owned column outside the window (row >= 8).
        // Stage 5.2 MaskOff policy silences inner Open constraints
        // there, so this must NOT reject.
        let skel = build_skeleton();
        let mut cols = skel.build_trace().columns;
        let col = SKEL_OPEN_COL_OFFSET + COL_VALUE;
        cols[col][FRI_STATE_OPEN_N_ROWS] = Block128::from(0xDEAD_u128);
        let trace = Trace::new(cols);
        assert!(skel.air().check(&trace));
    }
}
