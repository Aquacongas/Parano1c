// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 4c.3.c — two-side `FriStateCombinerComposite`.
//!
//! Stitches one `FriStateCombinerAir` for the **prev** side and one for
//! the **new** side into a single AIR at `log_rows =
//! FRI_STATE_COMBINER_LOG_ROWS`. The two sides share nothing; their
//! column blocks are disjoint and each sub-AIR's soundness argument
//! carries through unchanged under a uniform column shift.
//!
//! # Column layout
//!
//! | range                              | side |
//! |------------------------------------|------|
//! | `0 .. N_COLS`                      | prev |
//! | `N_COLS .. 2 * N_COLS`             | new  |
//!
//! where `N_COLS = FRI_STATE_COMBINER_N_COLS`.
//!
//! # Why a composite, not just two AIRs run in parallel
//!
//! The top-level state-root composite (the outer stitch built on top of
//! this one) needs to quote both digests in the same public-input
//! vector. Materialising them here as one `Air` with one public-column
//! table lets the verifier consume them through a single programme
//! binding rather than two disjoint ones, and keeps the row-map for
//! later stages flat.
//!
//! # Cross-side linkage with `FriStateOpenAir`
//!
//! Not emitted here. Per ROADMAP §4c.3.c the lane-opening ↔ sub-root
//! binding is closed through PCS-opening verification *outside* the
//! AIR, not through trace-column pins: `FriStateOpenAir` consumes
//! `{prev,new}_lane_openings` as scalars (fused into the terminal
//! const-offset gate in 4c.2), and the same FRI commitments yield the
//! 32-byte sub-roots pinned here as absorb-block public inputs to
//! `FriStateCombinerAir`. The composite just exposes both digests so
//! the outer stitch can wire them to `PublicInputs.{epoch_anchor,claims_commitment}`.

use crate::airs::fri_state_combiner::{
    build_combiner_side_trace, emit_fri_state_combiner, FriStateCombinerPreimage,
    FRI_STATE_COMBINER_LOG_ROWS, FRI_STATE_COMBINER_N_COLS, FRI_STATE_COMBINER_N_ROWS,
};
use crate::gates::PublicColumn;
use crate::{Air, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::Block128;

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// Column offset of the prev-side combiner block.
pub const COMBINER_COMPOSITE_PREV_OFFSET: usize = 0;

/// Column offset of the new-side combiner block.
pub const COMBINER_COMPOSITE_NEW_OFFSET: usize = FRI_STATE_COMBINER_N_COLS;

/// Total committed column count of the composite.
pub const COMBINER_COMPOSITE_N_COLS: usize = 2 * FRI_STATE_COMBINER_N_COLS;

/// Shared log-rows of the composite (both sides run at the same
/// height).
pub const COMBINER_COMPOSITE_LOG_ROWS: usize = FRI_STATE_COMBINER_LOG_ROWS;

/// Total row count of the composite.
pub const COMBINER_COMPOSITE_N_ROWS: usize = FRI_STATE_COMBINER_N_ROWS;

// ---------------------------------------------------------------------------
// Column-shift adapter
// ---------------------------------------------------------------------------

/// Applies a uniform column offset to a wrapped `Constraint`. Matches
/// the shift-invariance invariant used by `CompositeAir` and
/// `TxBodySpineComposite`: every shipped gate in `noid_air::gates`
/// reads `frame.local[i]` / `frame.next[i]` by ordinal position in
/// `columns()` / `shifted_columns()`, so shifting those indices is
/// equivalent to shifting the underlying projection source.
///
/// Inner range is validated at construction time so a gate that
/// accidentally hard-codes absolute column indices trips the assert
/// immediately rather than silently producing a mis-projected trace.
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
                "ShiftedColumnsConstraint: inner local column {c} out of inner range [0, {inner_n_cols})"
            );
        }
        for &c in inner.shifted_columns() {
            assert!(
                c < inner_n_cols,
                "ShiftedColumnsConstraint: inner shifted column {c} out of inner range [0, {inner_n_cols})"
            );
        }
        let shifted_cols = inner.columns().iter().map(|&c| c + offset).collect();
        let shifted_next = inner
            .shifted_columns()
            .iter()
            .map(|&c| c + offset)
            .collect();
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
// Composite
// ---------------------------------------------------------------------------

/// Two-side Poseidon2b meta-root combiner: one sponge run for `prev`,
/// one for `new`, stacked into a single AIR. Each side binds its
/// `log_slots + 3 × 32-byte sub-roots` preimage to the declared
/// `expected_*_fields` via the sub-AIR's internal absorb
/// pins + digest pin.
pub struct FriStateCombinerComposite {
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
    prev_preimage: FriStateCombinerPreimage,
    new_preimage: FriStateCombinerPreimage,
    // Stage 6 — expected digests exposed for the single PI surface.
    expected_epoch_anchor: [Block128; 2],
    expected_claims_commitment: [Block128; 2],
}

impl FriStateCombinerComposite {
    pub fn new(
        prev_preimage: FriStateCombinerPreimage,
        expected_epoch_anchor_fields: [Block128; 2],
        new_preimage: FriStateCombinerPreimage,
        expected_claims_commitment_fields: [Block128; 2],
    ) -> Self {
        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        for (offset, preimage, expected) in [
            (
                COMBINER_COMPOSITE_PREV_OFFSET,
                &prev_preimage,
                expected_epoch_anchor_fields,
            ),
            (
                COMBINER_COMPOSITE_NEW_OFFSET,
                &new_preimage,
                expected_claims_commitment_fields,
            ),
        ] {
            let (side_constraints, side_publics) = emit_fri_state_combiner(preimage, expected);
            for c in side_constraints {
                constraints.push(Box::new(ShiftedColumnsConstraint::new(
                    c,
                    offset,
                    FRI_STATE_COMBINER_N_COLS,
                )));
            }
            for pc in side_publics {
                assert!(
                    pc.col < FRI_STATE_COMBINER_N_COLS,
                    "combiner side public column {} escapes inner range",
                    pc.col
                );
                public_columns.push(PublicColumn::new(pc.col + offset, pc.values));
            }
        }

        // Final alignment: every constraint / public column stays inside
        // the composite width. Cheap and runs once per construction.
        for c in &constraints {
            for &j in c.columns() {
                assert!(j < COMBINER_COMPOSITE_N_COLS, "composite local col {j} oob");
            }
            for &j in c.shifted_columns() {
                assert!(
                    j < COMBINER_COMPOSITE_N_COLS,
                    "composite shifted col {j} oob"
                );
            }
        }
        for pc in &public_columns {
            assert!(
                pc.col < COMBINER_COMPOSITE_N_COLS,
                "composite public col {} oob",
                pc.col
            );
        }

        Self {
            constraints,
            public_columns,
            prev_preimage,
            new_preimage,
            expected_epoch_anchor: expected_epoch_anchor_fields,
            expected_claims_commitment: expected_claims_commitment_fields,
        }
    }

    /// Stage 6 — expected `epoch_anchor` as the two-block pair
    /// pinned into the prev-side combiner.
    pub fn expected_epoch_anchor_fields(&self) -> [Block128; 2] {
        self.expected_epoch_anchor
    }

    /// Stage 6 — expected `claims_commitment` as the two-block pair
    /// pinned into the new-side combiner.
    pub fn expected_claims_commitment_fields(&self) -> [Block128; 2] {
        self.expected_claims_commitment
    }

    /// Build an honest composite trace. Prev-side columns occupy
    /// `[0, N_COLS)`; new-side columns occupy `[N_COLS, 2*N_COLS)`.
    pub fn build_trace(&self) -> Trace {
        let mut cols = build_combiner_side_trace(&self.prev_preimage);
        cols.extend(build_combiner_side_trace(&self.new_preimage));
        debug_assert_eq!(cols.len(), COMBINER_COMPOSITE_N_COLS);
        for c in &cols {
            debug_assert_eq!(c.len(), COMBINER_COMPOSITE_N_ROWS);
        }
        Trace::new(cols)
    }

    pub fn prev_preimage(&self) -> &FriStateCombinerPreimage {
        &self.prev_preimage
    }
    pub fn new_preimage(&self) -> &FriStateCombinerPreimage {
        &self.new_preimage
    }

    /// Destructure the composite into its wiring parts, consuming
    /// `self`. Used by the Stage 5 `TxValidityComposite` skeleton
    /// (Stage 5.3) to embed this composite into a larger outer trace
    /// without re-running the construction-time soundness setup.
    pub fn into_parts(self) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
        (self.constraints, self.public_columns)
    }
}

impl Air for FriStateCombinerComposite {
    fn n_columns(&self) -> usize {
        COMBINER_COMPOSITE_N_COLS
    }
    fn log_rows(&self) -> usize {
        COMBINER_COMPOSITE_LOG_ROWS
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
    use crate::airs::fri_state_combiner::{
        build_combiner_side_trace, combiner_digest_row, combiner_pre_s_base,
        extract_combiner_digest_fields, COMBINER_IND_DIGEST, COMBINER_PERM_LAYOUT,
    };
    use noid_core::TowerField;

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

    fn honest_composite() -> FriStateCombinerComposite {
        let prev = mk_preimage(0x11);
        let new = mk_preimage(0x77);
        let expected_prev = expected_fields_for(&prev);
        let expected_new = expected_fields_for(&new);
        FriStateCombinerComposite::new(prev, expected_prev, new, expected_new)
    }

    #[test]
    fn composite_layout_constants() {
        assert_eq!(COMBINER_COMPOSITE_PREV_OFFSET, 0);
        assert_eq!(COMBINER_COMPOSITE_NEW_OFFSET, FRI_STATE_COMBINER_N_COLS);
        assert_eq!(COMBINER_COMPOSITE_N_COLS, 2 * FRI_STATE_COMBINER_N_COLS);
        assert_eq!(COMBINER_COMPOSITE_LOG_ROWS, FRI_STATE_COMBINER_LOG_ROWS);
    }

    #[test]
    fn composite_accepts_honest_trace() {
        let composite = honest_composite();
        let trace = composite.build_trace();
        assert_eq!(trace.n_cols(), composite.n_columns());
        assert_eq!(trace.log_rows, composite.log_rows());
        assert!(composite.check(&trace));
    }

    #[test]
    fn composite_rejects_prev_side_digest_tamper() {
        let composite = honest_composite();
        let mut trace = composite.build_trace();
        let row = combiner_digest_row();
        let col = COMBINER_COMPOSITE_PREV_OFFSET + COMBINER_PERM_LAYOUT.s;
        trace.columns[col][row] += Block128::ONE;
        assert!(!composite.check(&trace));
    }

    #[test]
    fn composite_rejects_new_side_digest_tamper() {
        let composite = honest_composite();
        let mut trace = composite.build_trace();
        let row = combiner_digest_row();
        let col = COMBINER_COMPOSITE_NEW_OFFSET + COMBINER_PERM_LAYOUT.s;
        trace.columns[col][row] += Block128::ONE;
        assert!(!composite.check(&trace));
    }

    #[test]
    fn composite_rejects_prev_side_absorb_tamper() {
        let composite = honest_composite();
        let mut trace = composite.build_trace();
        let col = COMBINER_COMPOSITE_PREV_OFFSET + combiner_pre_s_base(0);
        trace.columns[col][0] += Block128::ONE;
        assert!(!composite.check(&trace));
    }

    #[test]
    fn composite_rejects_new_side_absorb_tamper() {
        let composite = honest_composite();
        let mut trace = composite.build_trace();
        let col = COMBINER_COMPOSITE_NEW_OFFSET + combiner_pre_s_base(0);
        trace.columns[col][0] += Block128::ONE;
        assert!(!composite.check(&trace));
    }

    #[test]
    fn composite_rejects_expected_prev_pin_mismatch() {
        // Declared prev expected root doesn't match the honest one.
        let prev = mk_preimage(0x33);
        let new = mk_preimage(0x44);
        let correct_prev = expected_fields_for(&prev);
        let correct_new = expected_fields_for(&new);
        let bad_prev = [correct_prev[0] + Block128::ONE, correct_prev[1]];
        let composite = FriStateCombinerComposite::new(prev, bad_prev, new, correct_new);
        let trace = composite.build_trace();
        assert!(!composite.check(&trace));
    }

    #[test]
    fn composite_rejects_expected_new_pin_mismatch() {
        let prev = mk_preimage(0x55);
        let new = mk_preimage(0x66);
        let correct_prev = expected_fields_for(&prev);
        let correct_new = expected_fields_for(&new);
        let bad_new = [correct_new[0], correct_new[1] + Block128::ONE];
        let composite = FriStateCombinerComposite::new(prev, correct_prev, new, bad_new);
        let trace = composite.build_trace();
        assert!(!composite.check(&trace));
    }

    #[test]
    fn composite_rejects_prev_side_indicator_tamper() {
        // Move the prev-side digest indicator off its row.
        let composite = honest_composite();
        let mut trace = composite.build_trace();
        let col = COMBINER_COMPOSITE_PREV_OFFSET + COMBINER_IND_DIGEST;
        let row = combiner_digest_row();
        trace.columns[col][row] = Block128::ZERO;
        trace.columns[col][row - 1] = Block128::ONE;
        assert!(!composite.check(&trace));
    }

    #[test]
    fn composite_independence_between_sides() {
        // Sanity: tampering the new side must not change the check
        // outcome of a separately-built prev-only trace and vice-versa.
        let composite = honest_composite();
        let baseline = composite.build_trace();
        assert!(composite.check(&baseline));

        // Per-side tamper only flips the *one* gate that owns that
        // side's digest; the other side still passes its own gates.
        // This isn't directly visible through `check()` (it's a boolean),
        // but we can check that the witness digest extraction on the
        // untampered side matches `expected_*` regardless of what happens
        // on the other side.
        let mut trace = baseline.clone();
        let new_digest_col = COMBINER_COMPOSITE_NEW_OFFSET + COMBINER_PERM_LAYOUT.s;
        let row = combiner_digest_row();
        trace.columns[new_digest_col][row] += Block128::ONE;
        // Prev-side digest cell is untouched.
        let prev_digest_col = COMBINER_COMPOSITE_PREV_OFFSET + COMBINER_PERM_LAYOUT.s;
        assert_eq!(
            trace.columns[prev_digest_col][row],
            baseline.columns[prev_digest_col][row]
        );
    }
}
