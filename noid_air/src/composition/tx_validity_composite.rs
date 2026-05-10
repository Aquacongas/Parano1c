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
//! - No `TxBodyMerkleAir` / `HAddr` / `HAuth` — those widen
//!   the column budget and require `log_rows = 13`, deferred to
//!   later substages.

use crate::airs::fri_state_combiner::FRI_STATE_COMBINER_LOG_ROWS;
use crate::airs::fri_state_combiner_composite::{
    FriStateCombinerComposite, COMBINER_COMPOSITE_LOG_ROWS, COMBINER_COMPOSITE_N_COLS,
};
use crate::airs::fri_state_open::{
    FriStateOpenAir, FriStateOpenWitness, FRI_STATE_OPEN_LOG_ROWS,
    FRI_STATE_OPEN_N_ROWS, FRI_STATE_OPEN_OUTPUT_LAYOUT, FRI_STATE_OPEN_WITNESS_COLS,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWrapper, WrapPolicy,
};
use crate::gates::const_column::PublicColumn;
use crate::{Air, CompositeAir, Constraint, Trace};
use noid_core::{Block128, TowerField};

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Outer `log_rows` of the skeleton. OP-1.δ.0 raised this from 9 to
/// 10 so downstream composites (`Full`, `HAuth`) have enough rows to
/// host a 4-input `HAddrMultiAir` (whose `min_log_rows(4) = 10`).
/// The combiner sub-composite has `inner_log_rows = 9` and is now
/// wrapped via `RowWindowWrapper(MaskOff)` — its constraints are
/// silenced on rows `[512, 1024)`. The leaf / with-spine composites
/// lift further to `log_rows = 13`; they consume the same skeleton
/// wiring under a larger outer row count.
pub const TX_VALIDITY_SKELETON_LOG_ROWS: usize = COMBINER_COMPOSITE_LOG_ROWS + 1;

/// Column offset of the combiner sub-composite.
pub const SKEL_COMBINER_COL_OFFSET: usize = 0;

/// OP-1.δ.0 — column reserved for the combiner's window indicator.
/// The combiner occupies `inner_log_rows = 9 < TX_VALIDITY_SKELETON_LOG_ROWS`,
/// so it is embedded via `RowWindowWrapper(MaskOff)` rather than a plain
/// column shift.
pub const SKEL_COMBINER_WINDOW_INDICATOR_COL: usize = COMBINER_COMPOSITE_N_COLS;

/// Column offset of the FRI-state-open block.
pub const SKEL_OPEN_COL_OFFSET: usize = SKEL_COMBINER_WINDOW_INDICATOR_COL + 1;

/// Column reserved for the FRI-state-open window indicator.
pub const SKEL_OPEN_WINDOW_INDICATOR_COL: usize =
    SKEL_OPEN_COL_OFFSET + FRI_STATE_OPEN_WITNESS_COLS;

/// E.2.b: column width of the output-side `FriStateOpenAir` instance,
/// sized for `MAX_OUTPUTS = 8`. `FriStateOpenLayout::witness_cols`
/// grows with `n_inputs`, so this differs from the input-side width.
pub const SKEL_OUT_OPEN_WITNESS_COLS: usize = FRI_STATE_OPEN_OUTPUT_LAYOUT.witness_cols();

/// E.2.b: column offset of the output-side FRI-state-open block.
/// Sits immediately after the input-side open block's window-indicator
/// column so downstream composites' `FULL_HADDR_BLOCKS_BASE =
/// TX_VALIDITY_SKELETON_N_COLS` still picks up the next free slot.
pub const SKEL_OUT_OPEN_COL_OFFSET: usize = SKEL_OPEN_WINDOW_INDICATOR_COL + 1;

/// E.2.b: window indicator column for the output-side open block.
pub const SKEL_OUT_OPEN_WINDOW_INDICATOR_COL: usize =
    SKEL_OUT_OPEN_COL_OFFSET + SKEL_OUT_OPEN_WITNESS_COLS;

/// Total outer column count.
pub const TX_VALIDITY_SKELETON_N_COLS: usize = SKEL_OUT_OPEN_WINDOW_INDICATOR_COL + 1;

// Compile-time sanity on the height assumption: the Open sub-AIR fits
// in the combiner height.
const _: () = {
    assert!(FRI_STATE_OPEN_LOG_ROWS <= COMBINER_COMPOSITE_LOG_ROWS);
    assert!(FRI_STATE_COMBINER_LOG_ROWS == COMBINER_COMPOSITE_LOG_ROWS);
};

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
    out_open_witness: FriStateOpenWitness,
    out_open_public_columns: Vec<PublicColumn>,
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
        out_open_air: FriStateOpenAir,
        out_open_witness: FriStateOpenWitness,
    ) -> Self {
        let outer_n_cols = TX_VALIDITY_SKELETON_N_COLS;
        let outer_log_rows = TX_VALIDITY_SKELETON_LOG_ROWS;

        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // Block A: combiner via RowWindowWrapper(MaskOff). Its
        // inner_log_rows = 9 < TX_VALIDITY_SKELETON_LOG_ROWS = 10; its
        // constraints are silenced on rows [512, outer).
        let (combiner_constraints, combiner_publics) = clone_combiner_parts(&combiner);
        let combiner_view = InnerAirView {
            inner_n_cols: COMBINER_COMPOSITE_N_COLS,
            inner_log_rows: COMBINER_COMPOSITE_LOG_ROWS,
            constraints: combiner_constraints,
            public_columns: combiner_publics,
            requires_true_cyclic_wrap: false,
        };
        let combiner_params = RowWindowParams {
            col_offset: SKEL_COMBINER_COL_OFFSET,
            outer_n_cols,
            outer_log_rows,
            row_window_start: 0,
            row_window_end: 1usize << COMBINER_COMPOSITE_LOG_ROWS,
            window_indicator_col: SKEL_COMBINER_WINDOW_INDICATOR_COL,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: Vec::new(),
        };
        let combiner_wiring = RowWindowWrapper::wrap(combiner_view, combiner_params);
        constraints.extend(combiner_wiring.constraints);
        public_columns.extend(combiner_wiring.public_columns);

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

        // Block B.out (E.2.b): output-side FriStateOpenAir. Shape =
        // FRI_STATE_OPEN_OUTPUT_LAYOUT (n_inputs = MAX_OUTPUTS = 8),
        // embedded on rows [0, 8) via RowWindowWrapper(MaskOff),
        // sharing the combiner's outer log_rows. E.2.b.comp-1 reserves
        // the columns and wires constraints honestly; per-output
        // slot-index bridge to TxValidityCol::SlotIndex lands in a
        // later substage.
        let (out_open_wiring, out_open_publics) =
            emit_output_open_wiring(out_open_air, outer_n_cols, outer_log_rows);
        constraints.extend(out_open_wiring.constraints);
        public_columns.extend(out_open_wiring.public_columns);
        // NOTE: the skeleton intentionally does not emit comp-4
        // slot-index bridge pins — it accepts caller-constructed
        // `out_open_air` instances of arbitrary origin (EMPTY in
        // `build_skeleton`, body-derived in
        // `out_open_body_derived_honest_trace_accepts`). Comp-4 pins
        // live in Leaf / Full / HAuth where the source is encoded in
        // the composite type.

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
            out_open_witness,
            out_open_public_columns: out_open_publics,
        }
    }

    /// Build an honest outer trace by composing each sub-AIR's honest
    /// sub-trace into its assigned column block.
    pub fn build_trace(&self) -> Trace {
        let outer_n_rows = 1usize << TX_VALIDITY_SKELETON_LOG_ROWS;
        let mut cols: Vec<Vec<Block128>> =
            (0..TX_VALIDITY_SKELETON_N_COLS).map(|_| vec![Block128::ZERO; outer_n_rows]).collect();

        // --- Combiner side -------------------------------------------------
        // Combiner inner trace has `1 << COMBINER_COMPOSITE_LOG_ROWS`
        // rows; copy those into rows `[0, inner_n_rows)` of the outer
        // trace. Outer rows beyond the window stay at ZERO — the
        // combiner's constraints are silenced there by MaskOff.
        let combiner_inner_n_rows = 1usize << COMBINER_COMPOSITE_LOG_ROWS;
        let combiner_trace = self.combiner.build_trace();
        let combiner_cols = combiner_trace.columns;
        assert_eq!(combiner_cols.len(), COMBINER_COMPOSITE_N_COLS);
        for (i, src) in combiner_cols.into_iter().enumerate() {
            assert_eq!(src.len(), combiner_inner_n_rows);
            let dst = &mut cols[SKEL_COMBINER_COL_OFFSET + i];
            for (r, v) in src.into_iter().enumerate() {
                dst[r] = v;
            }
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

        // --- Output-side open (E.2.b) -----------------------------------
        write_output_open_trace(
            &mut cols,
            &self.out_open_witness,
            &self.out_open_public_columns,
        );

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

/// Rebuild the FRI-state-open inner witness columns for the skeleton's
/// row window. Mirrors `FriStateOpenAir::build_trace` but uses the
/// already-captured public-column programmes from the owning
/// `FriStateOpenAir` (avoiding a second construction).
fn build_open_inner_cols(
    witness: &FriStateOpenWitness,
    publics: &[PublicColumn],
) -> Vec<Vec<Block128>> {
    build_open_inner_cols_sized(witness, publics, FRI_STATE_OPEN_WITNESS_COLS)
}

fn build_open_inner_cols_sized(
    witness: &FriStateOpenWitness,
    publics: &[PublicColumn],
    n_cols: usize,
) -> Vec<Vec<Block128>> {
    let mut cols = witness.build_columns(n_cols);
    for pc in publics {
        cols[pc.col] = pc.values.clone();
    }
    cols
}

/// E.2.b: shared helper — wrap a configured output-side
/// `FriStateOpenAir` into an outer composite via `RowWindowWrapper`,
/// reusing the skeleton's `SKEL_OUT_OPEN_*` offsets. Used from both
/// the skeleton and downstream composites (`Full`, `HAuth`, `Leaf`,
/// `WithSpine`) so the output-side wiring is authored exactly once.
pub(crate) fn emit_output_open_wiring(
    out_open_air: FriStateOpenAir,
    outer_n_cols: usize,
    outer_log_rows: usize,
) -> (crate::composition::row_window::RowWindowWiring, Vec<PublicColumn>) {
    let out_layout = out_open_air.layout();
    assert_eq!(out_layout, FRI_STATE_OPEN_OUTPUT_LAYOUT);
    let (out_open_n_cols, out_open_constraints, out_open_publics) = out_open_air.into_parts();
    assert_eq!(out_open_n_cols, SKEL_OUT_OPEN_WITNESS_COLS);
    let inner_view = InnerAirView {
        inner_n_cols: out_open_n_cols,
        inner_log_rows: out_layout.log_rows,
        constraints: out_open_constraints,
        public_columns: out_open_publics.clone(),
        requires_true_cyclic_wrap: false,
    };
    let params = RowWindowParams {
        col_offset: SKEL_OUT_OPEN_COL_OFFSET,
        outer_n_cols,
        outer_log_rows,
        row_window_start: 0,
        row_window_end: out_layout.n_rows(),
        window_indicator_col: SKEL_OUT_OPEN_WINDOW_INDICATOR_COL,
        policy: WrapPolicy::MaskOff,
        terminator_pin_cols: Vec::new(),
    };
    let wiring = RowWindowWrapper::wrap(inner_view, params);
    (wiring, out_open_publics)
}

/// E.2.b: write an output-side honest sub-trace into the outer column
/// block starting at `SKEL_OUT_OPEN_COL_OFFSET`. Paired with
/// `emit_output_open_wiring`.
pub(crate) fn write_output_open_trace(
    cols: &mut [Vec<Block128>],
    witness: &FriStateOpenWitness,
    publics: &[PublicColumn],
) {
    let inner =
        build_open_inner_cols_sized(witness, publics, SKEL_OUT_OPEN_WITNESS_COLS);
    let out_n_rows = witness.layout.n_rows();
    for (i, src) in inner.into_iter().enumerate() {
        assert_eq!(src.len(), out_n_rows);
        let dst = &mut cols[SKEL_OUT_OPEN_COL_OFFSET + i];
        for (r, v) in src.into_iter().enumerate() {
            dst[r] = v;
        }
    }
}

/// E.2.b: convenience wrapper — build the all-EMPTY output-side witness
/// on the fly and write its honest sub-trace into `cols`. Used by
/// composites (`Full`, `HAuth`, `Leaf`, `WithSpine`) that don't need
/// to retain the witness between `new` and `build_trace` because every
/// call recreates the same deterministic all-zero witness.
pub(crate) fn write_empty_output_open_trace(cols: &mut [Vec<Block128>]) {
    // We need the publics the AIR would own. `build_empty_output_side`
    // returns them via the air; we extract them by building a fresh
    // instance once per trace. Cheap because the inner construction is
    // O(witness_cols) work only.
    let (air, witness) = build_empty_output_side();
    let (_, _, publics) = air.into_parts();
    write_output_open_trace(cols, &witness, &publics);
}

/// E.2.b.comp-3: how the output-side `FriStateOpenAir` block is
/// populated in downstream composites (`Leaf`, `WithSpine`).
///
/// `Empty` keeps the deterministic all-EMPTY witness (the 3c path);
/// `FromBody` binds each live `TxOutput` as a mint claim whose
/// `slot_index / value / owner` lanes flow through the γ-RLC
/// accumulator together with the honest prev-side lane openings. See
/// `build_output_side_from_body`.
#[derive(Debug, Clone)]
pub enum OutputSideSource {
    Empty,
    FromBody {
        outputs: Vec<noid_tx::TxOutput>,
        prev_lane_openings: [Block128; 3],
    },
}

impl Default for OutputSideSource {
    fn default() -> Self {
        Self::Empty
    }
}

/// E.2.b.comp-3: dispatch `build_empty_output_side` vs
/// `build_output_side_from_body` from a [`OutputSideSource`]. The
/// `eval_point` / `gamma` inputs are forwarded verbatim; callers pass
/// the same values the input-side open witness was built against so
/// both instances share the transcript-derived challenges.
pub fn build_output_side_from_source(
    source: &OutputSideSource,
    eval_point: [Block128; crate::airs::fri_state_open::FRI_STATE_OPEN_LOG_SLOTS],
    gamma: Block128,
) -> (FriStateOpenAir, FriStateOpenWitness) {
    match source {
        OutputSideSource::Empty => build_empty_output_side(),
        OutputSideSource::FromBody { outputs, prev_lane_openings } => {
            build_output_side_from_body(outputs, eval_point, gamma, *prev_lane_openings)
        }
    }
}

/// E.2.b.comp-3: write the output-side honest sub-trace from a
/// [`OutputSideSource`] + transcript challenges. Paired with
/// `emit_output_open_wiring(build_output_side_from_source(...).0, …)`
/// at composite construction time.
pub(crate) fn write_output_open_trace_from_source(
    cols: &mut [Vec<Block128>],
    source: &OutputSideSource,
    eval_point: [Block128; crate::airs::fri_state_open::FRI_STATE_OPEN_LOG_SLOTS],
    gamma: Block128,
) {
    let (air, witness) = build_output_side_from_source(source, eval_point, gamma);
    let (_, _, publics) = air.into_parts();
    write_output_open_trace(cols, &witness, &publics);
}

/// E.2.b.comp-4 — slot-index bridge. Pin each output-side
/// `col_idx_bit(k)` column's rows `[0, MAX_OUTPUTS)` to the `k`-th bit
/// of the declared `TxOutput.slot_index`. Rows past `MAX_OUTPUTS`
/// pin to zero (matching the silenced-window init).
///
/// Why: on the output side every claim is a mint ⇒ `opened_pre_lane =
/// is_spend · lane = 0` ⇒ `gp_lane = 0`, so the γ-RLC accumulator
/// terminus is identically `[0, 0, 0]` regardless of the slot-index
/// bits. Without an explicit pin, an adversary could mutate the bits
/// in the trace freely. Pinning each bit column directly from the
/// declared `outputs[j].slot_index` closes the gap; the spine's
/// `TxValidityCol::SlotIndex[MAX_INPUTS + j]` is independently pinned
/// to the same declared value (via
/// `emit_txv_tx_body_public_columns`), so the two pins agree row-wise
/// and the bridge closes transitively: tampering either side fails
/// against its own public-column pin.
///
/// `Empty` source emits `[0; outer_n_rows]` programmes for every bit
/// column, matching the all-EMPTY witness.
pub(crate) fn emit_out_open_slot_index_publics(
    source: &OutputSideSource,
    outer_n_rows: usize,
) -> Vec<PublicColumn> {
    use crate::airs::fri_state_open::FRI_STATE_OPEN_LOG_SLOTS;
    let layout = FRI_STATE_OPEN_OUTPUT_LAYOUT;
    let n_inputs = layout.n_inputs;
    // Decide declared slot index per output row. Empty → every row 0.
    let slot_indices: Vec<u32> = match source {
        OutputSideSource::Empty => vec![0; n_inputs],
        OutputSideSource::FromBody { outputs, .. } => (0..n_inputs)
            .map(|j| {
                let out = outputs
                    .get(j)
                    .copied()
                    .unwrap_or_else(noid_tx::TxOutput::dummy);
                if out.valid { out.slot_index } else { 0 }
            })
            .collect(),
    };
    let mut publics = Vec::with_capacity(FRI_STATE_OPEN_LOG_SLOTS);
    for k in 0..FRI_STATE_OPEN_LOG_SLOTS {
        let outer_col = SKEL_OUT_OPEN_COL_OFFSET + layout.col_idx_bit(k);
        let mut programme = vec![Block128::ZERO; outer_n_rows];
        for (j, &slot) in slot_indices.iter().enumerate() {
            let bit = ((slot >> k) & 1) as u128;
            programme[j] = Block128::from(bit);
        }
        publics.push(PublicColumn::new(outer_col, programme));
    }
    publics
}

/// E.2.b: build an honest, all-EMPTY output-side `FriStateOpenAir`
/// instance together with its matching witness. Every slot claim is
/// `FriStateOpenClaim::EMPTY` (dummy, neither spend nor mint) so the
/// γ-batched accumulator terminus collapses to zero and the four-corner
/// update identity holds trivially (prev + new == 0 in char 2). Later
/// substages replace this with a `TxBody.outputs`-derived witness plus
/// a slot-index bridge to `TxValidityCol::SlotIndex[MAX_INPUTS..]`.
pub fn build_empty_output_side()
-> (FriStateOpenAir, FriStateOpenWitness) {
    use crate::airs::fri_state_open::FriStateOpenClaim;
    let layout = FRI_STATE_OPEN_OUTPUT_LAYOUT;
    let claims: Vec<FriStateOpenClaim> =
        vec![FriStateOpenClaim::EMPTY; layout.n_inputs];
    let eval_point = [Block128::ZERO; crate::airs::fri_state_open::FRI_STATE_OPEN_LOG_SLOTS];
    let gamma = Block128::ZERO;
    let prev_lane_openings = [Block128::ZERO; 3];
    let new_lane_openings = [Block128::ZERO; 3];
    let expected_batched_claims = [Block128::ZERO; 3];
    let witness = FriStateOpenWitness::from_claims_with_layout(claims.clone(), layout)
        .with_eval_point(eval_point)
        .with_gamma(gamma)
        .with_lane_openings(prev_lane_openings, new_lane_openings);
    let air = FriStateOpenAir::new_with_layout(
        &claims,
        prev_lane_openings,
        new_lane_openings,
        eval_point,
        gamma,
        expected_batched_claims,
        layout,
    );
    (air, witness)
}

// ---------------------------------------------------------------------
// E.3.a — new-state opener builder primitives.
//
// Four-corner state-transition proof shape (GENERAL_DESIGN §4):
//
//   prev-side  inputs   opens to  (value_i, owner_i)   — spend pre-state
//   prev-side  outputs  opens to  (0, 0, 0)            — mint pre-state  (E.2.b done)
//   new-side   inputs   opens to  (0, 0, 0)            — spend post-state (E.3)
//   new-side   outputs  opens to  (value_j, owner_j)   — mint post-state  (E.3)
//
// E.3.a is the pure-plumbing slice: builder primitives + source
// enums, no new AIR instances wired into composites yet. E.3.b will
// reserve column bands and instantiate two more `FriStateOpenAir`
// blocks per leaf. Constructed here so E.3.b's diff is a wiring
// change only.
// ---------------------------------------------------------------------

// OP-1.φ.1b: the E.3.a/E.3.b new-state opener dispatchers and
// `NewStateInputSource` / `NewStateOutputSource` variants have been
// removed together with the opener bands. If a future composite needs
// to re-introduce a new-state opener, add the enum + dispatchers back
// alongside a dedicated column band (do NOT reuse the leaf-band layout
// slot — there isn't one any more).

/// E.2.b.comp-2: build the output-side `FriStateOpenAir` + witness
/// from a `TxBody`. Each `TxOutput` with `valid == true` becomes a
/// mint claim (`is_mint=1`, `is_spend=0`) carrying its declared
/// `slot_index`, `value`, and owner lanes; each dummy / inactive
/// output becomes `FriStateOpenClaim::EMPTY`.
///
/// Honest semantics for mints: `opened_pre_lane = is_spend · lane
/// = 0` on every row (mints contribute nothing to the γ-RLC), so
/// `expected_batched_claims = [0, 0, 0]`. The four-corner MLE
/// update identity terminus carries
/// `delta_acc_lane[N-1] = Σ_j eq(r, slot_j) · value_j` on the
/// output block; we bind it to `prev_lane + new_lane` by
/// computing the honest `new_lane = prev_lane + delta_acc`.
/// `prev_lane_openings` are an external input (the verifier-known
/// FRI openings of `prev_state` at `r` — binding the output-side
/// `is_mint ⇒ pre_slot = 0` to the real prev-state.
pub fn build_output_side_from_body(
    outputs: &[noid_tx::TxOutput],
    eval_point: [Block128; crate::airs::fri_state_open::FRI_STATE_OPEN_LOG_SLOTS],
    gamma: Block128,
    prev_lane_openings: [Block128; 3],
) -> (FriStateOpenAir, FriStateOpenWitness) {
    use crate::airs::fri_state_open::FriStateOpenClaim;
    use noid_poseidon2b::primitives::Address;
    let layout = FRI_STATE_OPEN_OUTPUT_LAYOUT;
    let mut claims: Vec<FriStateOpenClaim> =
        vec![FriStateOpenClaim::EMPTY; layout.n_inputs];
    for (j, slot) in claims.iter_mut().enumerate() {
        let out = outputs.get(j).copied().unwrap_or_else(noid_tx::TxOutput::dummy);
        if !out.valid {
            continue;
        }
        let addr: Address = out.owner;
        let [owner_hi, owner_lo] = addr.as_fields();
        let value = Block128::from(out.value as u128);
        *slot = FriStateOpenClaim {
            slot_index: out.slot_index,
            value,
            owner_hi,
            owner_lo,
            delta_value: value,
            delta_owner_hi: owner_hi,
            delta_owner_lo: owner_lo,
            is_spend: false,
            is_mint: true,
        };
    }
    let base = FriStateOpenWitness::from_claims_with_layout(claims.clone(), layout)
        .with_eval_point(eval_point)
        .with_gamma(gamma);
    let new_lane_openings = base.expected_new_lane_openings(prev_lane_openings);
    let witness = base.with_lane_openings(prev_lane_openings, new_lane_openings);
    let expected_batched_claims = witness.expected_batched_claims();
    let air = FriStateOpenAir::new_with_layout(
        &claims,
        prev_lane_openings,
        new_lane_openings,
        eval_point,
        gamma,
        expected_batched_claims,
        layout,
    );
    (air, witness)
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

        let (out_open_air, out_open_witness) = build_empty_output_side();
        TxValidityCompositeSkeleton::new(
            combiner,
            open_air,
            open_witness,
            out_open_air,
            out_open_witness,
        )
    }

    #[test]
    fn layout_constants_agree() {
        assert_eq!(SKEL_COMBINER_COL_OFFSET, 0);
        assert_eq!(SKEL_COMBINER_WINDOW_INDICATOR_COL, COMBINER_COMPOSITE_N_COLS);
        assert_eq!(SKEL_OPEN_COL_OFFSET, COMBINER_COMPOSITE_N_COLS + 1);
        assert_eq!(
            SKEL_OUT_OPEN_COL_OFFSET,
            COMBINER_COMPOSITE_N_COLS + 1 + FRI_STATE_OPEN_WITNESS_COLS + 1
        );
        assert_eq!(
            TX_VALIDITY_SKELETON_N_COLS,
            COMBINER_COMPOSITE_N_COLS
                + 1
                + FRI_STATE_OPEN_WITNESS_COLS
                + 1
                + SKEL_OUT_OPEN_WITNESS_COLS
                + 1
        );
        // Output-side is strictly wider than input-side (more rows → more
        // row-indicator columns) and lives at a strictly later offset.
        assert!(SKEL_OUT_OPEN_WITNESS_COLS > FRI_STATE_OPEN_WITNESS_COLS);
        assert!(SKEL_OUT_OPEN_COL_OFFSET > SKEL_OPEN_COL_OFFSET);
        assert_eq!(TX_VALIDITY_SKELETON_LOG_ROWS, 10);
        let _ = COMBINER_COMPOSITE_PREV_OFFSET;
        let _ = COMBINER_COMPOSITE_NEW_OFFSET;
    }

    #[test]
    fn out_open_honest_trace_accepts() {
        // E.2.b.comp-1: the all-EMPTY output-side block must not fail
        // the skeleton's honest-trace check. This exercises the fact
        // that the new constraints are wired, the new PublicColumns
        // match their programmes, and the window indicator drives
        // row-silencing consistently.
        let skel = build_skeleton();
        let trace = skel.build_trace();
        assert!(skel.air().check(&trace));
    }

    #[test]
    fn out_open_value_tamper_rejects() {
        // Flipping col_value on an in-window row of the output
        // block must be caught — boundary `claim_pins` unconditionally
        // pin `col_value[row]` to the (zero) EMPTY-claim value via
        // `SelectorGate(row_indicator(row), …)`. Guarantees the new
        // instance is actually constrained, not just allocated.
        use crate::airs::fri_state_open::{FriStateOpenLayout, COL_VALUE};
        let skel = build_skeleton();
        let mut cols = skel.build_trace().columns;
        let _layout: FriStateOpenLayout = FRI_STATE_OPEN_OUTPUT_LAYOUT;
        let col = SKEL_OUT_OPEN_COL_OFFSET + COL_VALUE;
        cols[col][0] = cols[col][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!skel.air().check(&trace));
    }

    #[test]
    fn out_open_body_derived_honest_trace_accepts() {
        // E.2.b.comp-2: feed `build_output_side_from_body` with a
        // realistic 2-live-output `TxBody` and verify the resulting
        // out-open block embeds cleanly. Exercises the honest
        // construction path end-to-end (claims + eval_point + gamma
        // + honest prev/new lane openings).
        use noid_poseidon2b::primitives::Address;
        use noid_tx::TxOutput;

        let outputs = vec![
            TxOutput {
                slot_index: 7,
                value: 42,
                owner: Address([0x11u8; 32]),
                valid: true,
            },
            TxOutput {
                slot_index: 13,
                value: 99,
                owner: Address([0x22u8; 32]),
                valid: true,
            },
        ];
        let eval_point = [
            Block128::from(0xCAFEu128),
            Block128::from(0xBABEu128),
            Block128::from(0xF00Du128),
            Block128::from(0xBEEFu128),
        ];
        let gamma = Block128::from(0xABCD_1234_5678_9ABCu128);
        let prev_lane_openings = [Block128::ZERO; 3];
        let (out_air, out_witness) = build_output_side_from_body(
            &outputs,
            eval_point,
            gamma,
            prev_lane_openings,
        );

        // Re-use the skeleton builder but swap the output-side pair.
        let prev_preimage = mk_combiner_preimage(0x5A);
        let new_preimage = mk_combiner_preimage(0xA5);
        let prev_fields = crate::airs::fri_state_combiner::extract_combiner_digest_fields(
            &crate::airs::fri_state_combiner::build_combiner_side_trace(&prev_preimage),
            crate::airs::fri_state_combiner::COMBINER_PERM_LAYOUT,
        );
        let new_fields = crate::airs::fri_state_combiner::extract_combiner_digest_fields(
            &crate::airs::fri_state_combiner::build_combiner_side_trace(&new_preimage),
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
        let prev_ins = [
            Block128::from(0xA5A5_1234_5678_9ABC_u128),
            Block128::from(0xDEAD_BEEF_CAFE_F00D_u128),
            Block128::from(0x1357_9BDF_2468_ACE0_u128),
        ];
        let new_ins = base.expected_new_lane_openings(prev_ins);
        let open_witness = base.with_lane_openings(prev_ins, new_ins);
        let open_air = FriStateOpenAir::new(
            &claims,
            open_witness.prev_lane_openings,
            open_witness.new_lane_openings,
            mk_eval_point(),
            mk_gamma(),
            open_witness.expected_batched_claims(),
        );
        let skel = TxValidityCompositeSkeleton::new(
            combiner,
            open_air,
            open_witness,
            out_air,
            out_witness,
        );
        let trace = skel.build_trace();
        assert!(skel.air().check(&trace));
    }

    #[test]
    fn out_open_outside_window_edit_is_accepted() {
        // Analogue of `outside_window_edit_is_accepted` for the
        // output-side block. `col_value` rows beyond the output window
        // are silenced by `MaskOff`.
        use crate::airs::fri_state_open::{FriStateOpenLayout, COL_VALUE};
        let skel = build_skeleton();
        let mut cols = skel.build_trace().columns;
        let layout: FriStateOpenLayout = FRI_STATE_OPEN_OUTPUT_LAYOUT;
        let col = SKEL_OUT_OPEN_COL_OFFSET + COL_VALUE;
        let out_n_rows = layout.n_rows();
        cols[col][out_n_rows] = Block128::from(0xDEAD_u128);
        let trace = Trace::new(cols);
        assert!(skel.air().check(&trace));
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
