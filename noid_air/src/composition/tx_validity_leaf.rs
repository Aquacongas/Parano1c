// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! [`TxValidityCompositeLeaf`].
//!
//! Authentication-free leaf. Address and auth-tag derivation live
//! entirely in the external `AuthGKR` proof; this composite stacks
//! only the combiner, the prev/output FriStateOpen blocks, and the
//! E.4/E.5 public columns. Outer log-rows are `13` so the composite
//! embeds inside [`super::tx_validity_with_spine::TxValidityCompositeWithSpine`]
//! without a row-count mismatch.

use crate::airs::fri_state_combiner::FRI_STATE_COMBINER_LOG_ROWS;
use crate::airs::fri_state_combiner_composite::{
    FriStateCombinerComposite, COMBINER_COMPOSITE_LOG_ROWS, COMBINER_COMPOSITE_N_COLS,
};
use crate::airs::fri_state_open::{
    FriStateOpenAir, FriStateOpenLayout, FriStateOpenWitness, FRI_STATE_OPEN_LOG_ROWS,
    FRI_STATE_OPEN_N_ROWS, FRI_STATE_OPEN_OUTPUT_LAYOUT, FRI_STATE_OPEN_WITNESS_COLS,
};
use crate::composition::row_window::{InnerAirView, RowWindowParams, RowWindowWrapper, WrapPolicy};
use crate::composition::tx_validity_composite::{
    OutputSideSource, SKEL_COMBINER_COL_OFFSET, SKEL_OPEN_COL_OFFSET,
    SKEL_OPEN_WINDOW_INDICATOR_COL, TX_VALIDITY_SKELETON_N_COLS,
};
use crate::gates::const_column::PublicColumn;
use crate::{Air, CompositeAir, Constraint, Trace};
use noid_core::{Block128, TowerField};

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Outer log-rows = 13, matching
/// `TxValidityCompositeWithSpine`'s `SPINE_LOG_ROWS = 13` so the leaf
/// composite can be embedded without an outer-row-count mismatch.
/// Every embedded sub-AIR is wrapped under [`WrapPolicy::MaskOff`]
/// (combiner via [`RowWindowWrapper`], open / haddr / hauth via the
/// existing block helpers) so its constraints stay scoped to its
/// original window. Trace cells outside the windows are zero-padded.
pub const TX_VALIDITY_LEAF_LOG_ROWS: usize = 13;

/// Compile-time height sanity.
const _: () = {
    assert!(FRI_STATE_OPEN_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(COMBINER_COMPOSITE_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(FRI_STATE_COMBINER_LOG_ROWS == COMBINER_COMPOSITE_LOG_ROWS);
};

/// Outer column reserved for the combiner block's window indicator.
/// The combiner is wrapped via [`RowWindowWrapper`] under
/// `WrapPolicy::MaskOff` so its row-9-scoped constraints are silenced
/// past row `2^COMBINER_COMPOSITE_LOG_ROWS = 512` on the
/// 8192-row outer trace.
pub const SKEL_COMBINER_WINDOW_INDICATOR_COL: usize = TX_VALIDITY_SKELETON_N_COLS;

// ---------------------------------------------------------------------
// E.4 — Activation / deactivation public columns.
//
// Two boolean public columns exposed on the leaf composite. Semantics
// (GENERAL_DESIGN §15.3):
//
//   is_deactivation[i]  ==  (pre_value[i] != 0) AND (post_value[i] == 0)
//   is_activation[j]    ==  (pre_value[j] == 0) AND (post_value[j] != 0)
//
// With the four-corner openings (E.2/E.3) in place the booleans are
// fully determined by the prev-side opener's per-input / per-output
// `is_spend` / `is_mint` selector columns: a live spend on the
// prev-side input opener is exactly a deactivation row, and a live
// mint on the prev-side output opener is exactly an activation row.
//
// The columns expose the per-row booleans verbatim (programme on row
// `i` == `is_spend[i]` for deactivation; row `j` == `is_mint[j]` for
// activation; zero on every other row). Consistency is bound
// in-circuit via linear-equality constraints between each exposed
// column and the corresponding opener-band selector column.
// ---------------------------------------------------------------------

/// E.4 — outer column carrying the derived `is_deactivation[i]` boolean
/// programme. One column, `MAX_INPUTS = FRI_STATE_OPEN_N_INPUTS`
/// significant rows (one bit per live input on rows `[0, 4)`); zero
/// elsewhere.
pub const SKEL_IS_DEACTIVATION_COL: usize = SKEL_COMBINER_WINDOW_INDICATOR_COL + 1;
/// E.4 — outer column carrying the derived `is_activation[j]` boolean
/// programme. One column, `MAX_OUTPUTS = FRI_STATE_OPEN_N_OUTPUTS`
/// significant rows (one bit per live output on rows `[0, 8)`); zero
/// elsewhere.
pub const SKEL_IS_ACTIVATION_COL: usize = SKEL_IS_DEACTIVATION_COL + 1;

// ---------------------------------------------------------------------
// E.5 — Coinbase marker.
//
// `is_coinbase ∈ {0,1}` tx-level scalar (GENERAL_DESIGN §15.4). Exposed
// on the leaf as a single `PublicColumn` whose programme is the constant
// `is_coinbase` on every row. At the leaf level we bind the structural
// rule `is_coinbase = 1 ⇒ n_inputs = 0` by the gate
//     row_indicator_i · is_coinbase · col_is_spend = 0     ∀ i ∈ [0, MAX_INPUTS).
// Live-spend rows carry `col_is_spend = 1`; on a coinbase tx every such
// row is silenced (row_indicator = 0) so the identity holds, and any
// prover that tries to activate a spend on a coinbase tx is rejected.
//
// The complementary rules `is_coinbase = 1 ⇒ fee = 0` and the balance
// block mux live at the WithSpine composite (balance columns reside on
// the spine side of the composite), handled in E.5.d.
// ---------------------------------------------------------------------

/// E.5 — outer column carrying the `is_coinbase` public scalar as a
/// row-constant programme (`is_coinbase` on every row).
pub const SKEL_IS_COINBASE_COL: usize = SKEL_IS_ACTIVATION_COL + 1;

/// Total outer column count.
pub const TX_VALIDITY_LEAF_N_COLS: usize = SKEL_IS_COINBASE_COL + 1;

// ---------------------------------------------------------------------------
// Construction options
// ---------------------------------------------------------------------------

/// Optional construction-time tweaks for [`TxValidityCompositeLeaf`].
/// `Default` applies no overrides (canonical wiring).
#[derive(Debug, Clone, Default)]
pub struct LeafConstructionOptions {
    /// E.2.b.comp-3: how the output-side `FriStateOpenAir` block is
    /// populated. `Empty` (default) keeps the deterministic all-EMPTY
    /// witness; `FromBody` binds the `TxOutput` list as mint claims
    /// routed through the γ-RLC accumulator with the supplied
    /// `prev_lane_openings` (the verifier-known FRI openings of
    /// `prev_state` at the output-side eval point).
    pub output_side: OutputSideSource,
    /// E.5: tx-level coinbase marker. `false` (default) is the normal
    /// non-coinbase path; `true` activates the structural rule
    /// `is_coinbase = 1 ⇒ n_inputs = 0` — every live-spend row must be
    /// silenced on the input opener.
    pub is_coinbase: bool,
}

// ---------------------------------------------------------------------------
// Composite
// ---------------------------------------------------------------------------

/// Leaf composite: combiner + input-side FriStateOpen + output-side
/// FriStateOpen + the E.4/E.5 public-column tie block. Address and
/// auth-tag derivation live entirely in the external `AuthGKR` proof,
/// so the leaf carries no spend-secret witness.
pub struct TxValidityCompositeLeaf {
    pub air: CompositeAir,
    combiner: FriStateCombinerComposite,
    open_witness: FriStateOpenWitness,
    open_public_columns: Vec<PublicColumn>,
    /// E.2.b.comp-3: output-side witness source. Captured so
    /// `build_trace` can rebuild the honest sub-trace without requiring
    /// callers to hand it in again.
    output_side: OutputSideSource,
    /// E.2.b.comp-3: transcript-derived eval-point / gamma forwarded
    /// to the output-side construction. Input- and output-side
    /// instances share these challenges (the FRI-side transcript is a
    /// single stream), so we re-use the input-side witness's values.
    output_side_eval_point: [Block128; crate::airs::fri_state_open::FRI_STATE_OPEN_LOG_SLOTS],
    output_side_gamma: Block128,
}

impl TxValidityCompositeLeaf {
    pub fn new(
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
    ) -> Self {
        Self::new_with_options(
            combiner,
            open_air,
            open_witness,
            LeafConstructionOptions::default(),
        )
    }

    /// Construct a [`TxValidityCompositeLeaf`] with caller-controlled
    /// option overrides. See [`LeafConstructionOptions`].
    pub fn new_with_options(
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
        options: LeafConstructionOptions,
    ) -> Self {
        let outer_n_cols = TX_VALIDITY_LEAF_N_COLS;
        let outer_log_rows = TX_VALIDITY_LEAF_LOG_ROWS;
        let outer_n_rows = 1usize << outer_log_rows;

        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // Block A — combiner. Wrapped via `RowWindowWrapper` under
        // `MaskOff` because the combiner's `inner_log_rows = 9` is
        // smaller than the lifted `outer_log_rows = 13`. The combiner
        // doesn't use load-bearing cyclic wrap, so MaskOff is legal.
        // Its window indicator sits at `SKEL_COMBINER_WINDOW_INDICATOR_COL`.
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

        // Capture the open witness's eval_point/gamma before consuming
        // `open_air`: input-side and output-side share these challenges.
        let output_side_eval_point = open_witness.eval_point;
        let output_side_gamma = open_witness.gamma;

        // Block B — FriStateOpen.
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

        // Block B.out (E.2.b.comp-3) — output-side FriStateOpenAir.
        // Source is `options.output_side`: either all-EMPTY or
        // body-derived mint claims.
        let (out_open_air, _) =
            crate::composition::tx_validity_composite::build_output_side_from_source(
                &options.output_side,
                output_side_eval_point,
                output_side_gamma,
            );
        let (out_open_wiring, _) =
            crate::composition::tx_validity_composite::emit_output_open_wiring(
                out_open_air,
                outer_n_cols,
                outer_log_rows,
            );
        constraints.extend(out_open_wiring.constraints);
        public_columns.extend(out_open_wiring.public_columns);

        // E.2.b.comp-4: slot-index bridge — pin each output-side
        // `col_idx_bit(k)` row `j` to bit `k` of `outputs[j].slot_index`.
        // Necessary because mint claims collapse the γ-RLC terminus to
        // zero, leaving the bit columns otherwise unconstrained on the
        // output side.
        public_columns.extend(
            crate::composition::tx_validity_composite::emit_out_open_slot_index_publics(
                &options.output_side,
                outer_n_rows,
            ),
        );

        // OP-1.φ.1b: the E.3.b new-state opener bands have been
        // removed. On the honest WithSpine path both sides were
        // all-empty, so the γ-RLC terminuses were identically zero and
        // the opener AIR evaluated to a tautology — ~94 columns and
        // two full `FriStateOpenAir` constraint blocks of dead weight.
        // If a future composite wants to bind `new_state_root` at
        // per-claim slot indices, add a fresh opener band after the
        // leaf-band (non-breaking layout extension).

        // Block E.4 — activation / deactivation public columns.
        //
        // The prev-side input opener's `col_is_spend` column lives on
        // rows `[0, FRI_STATE_OPEN_N_INPUTS)`; its value on row `i`
        // equals `1` iff input `i` was a live spend (= deactivation).
        // The prev-side output opener's `col_is_mint` column lives on
        // rows `[0, FRI_STATE_OPEN_N_OUTPUTS)`; value on row `j` equals
        // `1` iff output `j` was a live mint (= activation).
        //
        // Expose each as a `PublicColumn` and pin equality to the
        // opener-side selector via a `WeightedLinearGate`, gated on
        // the relevant row indicator so the tie only fires on opener
        // rows. Outside those rows the public column is zero and the
        // opener-side selector is zero (silenced by window MaskOff),
        // so the identity holds trivially.
        use crate::gates::linear::WeightedLinearGate;
        use crate::gates::selector::SelectorGate;

        let in_layout = FriStateOpenLayout::DEFAULT;
        let out_layout = FRI_STATE_OPEN_OUTPUT_LAYOUT;

        // Programmes: derived directly from the prev-side sources. On
        // the honest path these coincide with `col_is_spend` /
        // `col_is_mint` of the respective openers.
        let is_deact_programme: Vec<Block128> = {
            let mut p = vec![Block128::ZERO; outer_n_rows];
            // Prev-input opener claims live on rows [0, in_layout.n_inputs). The
            // input-side opener is built from the leaf's canonical
            // `open_witness` → `claims`. We stash those claims on the
            // witness; read them back here.
            for (row, claim) in open_witness.claims.iter().enumerate() {
                if row >= in_layout.n_inputs {
                    break;
                }
                p[row] = if claim.is_spend {
                    Block128::ONE
                } else {
                    Block128::ZERO
                };
            }
            p
        };
        let is_act_programme: Vec<Block128> = {
            let mut p = vec![Block128::ZERO; outer_n_rows];
            // Output activation booleans follow the prev-side output
            // opener's `is_mint` flags — one-to-one with `options.output_side`.
            if let OutputSideSource::FromBody { outputs, .. } = &options.output_side {
                for (j, out) in outputs.iter().enumerate() {
                    if j >= out_layout.n_inputs {
                        break;
                    }
                    p[j] = if out.valid {
                        Block128::ONE
                    } else {
                        Block128::ZERO
                    };
                }
            }
            p
        };
        public_columns.push(PublicColumn::new(
            SKEL_IS_DEACTIVATION_COL,
            is_deact_programme,
        ));
        public_columns.push(PublicColumn::new(SKEL_IS_ACTIVATION_COL, is_act_programme));

        // Binding: for every opener row, the public column equals the
        // opener's selector column. The prev-side input opener's
        // `col_is_spend` sits at outer column
        // `SKEL_OPEN_COL_OFFSET + in_layout.col_is_spend()` (the leaf
        // wraps the input opener at `SKEL_OPEN_COL_OFFSET`); the
        // prev-side output opener's `col_is_mint` sits at
        // `SKEL_OUT_OPEN_COL_OFFSET + out_layout.col_is_mint()`.
        //
        // Each tie is a degree-1 linear identity
        // `pub - sel == 0` gated on the opener's single-hot row
        // indicator.
        let in_is_spend_col = SKEL_OPEN_COL_OFFSET + in_layout.col_is_spend();
        for i in 0..in_layout.n_inputs {
            let row_ind = SKEL_OPEN_COL_OFFSET + in_layout.col_row_indicator(i);
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
                vec![
                    (SKEL_IS_DEACTIVATION_COL, Block128::ONE),
                    (in_is_spend_col, Block128::ONE),
                ],
                Block128::ZERO,
            ));
            constraints.push(Box::new(SelectorGate::new(row_ind, inner)));
        }
        let out_is_mint_col = crate::composition::tx_validity_composite::SKEL_OUT_OPEN_COL_OFFSET
            + out_layout.col_is_mint();
        for j in 0..out_layout.n_inputs {
            let row_ind = crate::composition::tx_validity_composite::SKEL_OUT_OPEN_COL_OFFSET
                + out_layout.col_row_indicator(j);
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
                vec![
                    (SKEL_IS_ACTIVATION_COL, Block128::ONE),
                    (out_is_mint_col, Block128::ONE),
                ],
                Block128::ZERO,
            ));
            constraints.push(Box::new(SelectorGate::new(row_ind, inner)));
        }

        // Block E.5 — coinbase scalar + structural `n_inputs = 0` tie.
        //
        // Publish `is_coinbase` as a row-constant `PublicColumn`. The
        // scalar enters the pinned-publics surface exactly once; every
        // downstream reader (the WithSpine `fee = 0` tie / balance mux)
        // reads from the same column.
        //
        // Structural rule per input `i ∈ [0, MAX_INPUTS)`:
        //     row_indicator_i · is_coinbase · col_is_spend == 0.
        // Honest: `is_coinbase = 1` ⇒ every spend must be silenced ⇒
        // `col_is_spend = 0` on live rows (enforced by the opener's
        // window mask and by the prover's choice of claims); dummy rows
        // have `row_indicator = 0`. Tamper: flipping `col_is_spend` on
        // input `i` of a coinbase tx activates a live-spend row, makes
        // `row_indicator_i = 1` (single-hot) and `is_coinbase = 1`, so
        // the product is `1 · 1 · 1 = 1` ≠ 0 → reject.
        let is_coinbase_val = if options.is_coinbase {
            Block128::ONE
        } else {
            Block128::ZERO
        };
        public_columns.push(PublicColumn::new(
            SKEL_IS_COINBASE_COL,
            vec![is_coinbase_val; outer_n_rows],
        ));

        // Per-input structural tie: `is_coinbase · col_is_spend == 0`,
        // gated on the opener's single-hot row indicator. Expressed
        // via a bespoke two-column product gate (degree 2); wrapped
        // in a `SelectorGate` (degree 3 total) so it only fires on
        // the target opener row.
        struct CoinbaseNoSpendGate {
            cols: [usize; 2],
        }
        impl Constraint for CoinbaseNoSpendGate {
            fn degree(&self) -> usize {
                2
            }
            fn columns(&self) -> &[usize] {
                &self.cols
            }
            fn evaluate(&self, frame: crate::EvalFrame) -> Block128 {
                frame.local[0] * frame.local[1]
            }
            fn evaluate_flat(&self, frame: crate::FlatEvalFrame) -> u128 {
                noid_core::hardware::clmul_gcm(frame.local[0], frame.local[1])
            }
        }

        for i in 0..in_layout.n_inputs {
            let row_ind = SKEL_OPEN_COL_OFFSET + in_layout.col_row_indicator(i);
            let inner: Box<dyn Constraint> = Box::new(CoinbaseNoSpendGate {
                cols: [SKEL_IS_COINBASE_COL, in_is_spend_col],
            });
            constraints.push(Box::new(SelectorGate::new(row_ind, inner)));
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
            output_side: options.output_side,
            output_side_eval_point,
            output_side_gamma,
        }
    }

    /// Build an honest outer trace.
    pub fn build_trace(&self) -> Trace {
        let outer_n_rows = 1usize << TX_VALIDITY_LEAF_LOG_ROWS;
        let mut cols: Vec<Vec<Block128>> = (0..TX_VALIDITY_LEAF_N_COLS)
            .map(|_| vec![Block128::ZERO; outer_n_rows])
            .collect();
        write_leaf_block_traces(
            &mut cols,
            &self.combiner,
            &self.open_witness,
            &self.open_public_columns,
            TX_VALIDITY_LEAF_N_COLS,
            TX_VALIDITY_LEAF_LOG_ROWS,
            &self.output_side,
            self.output_side_eval_point,
            self.output_side_gamma,
        );

        // Final pass: overwrite every public column with its programme.
        for pc in self.air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }

        Trace::new(cols)
    }

    /// Decompose the composite into `(air, combiner, open_witness,
    /// open_public_columns)`. Used to embed a fully-built leaf composite
    /// inside [`super::tx_validity_with_spine::TxValidityCompositeWithSpine`]
    /// without re-instantiating its sub-AIRs.
    pub fn into_parts(
        self,
    ) -> (
        CompositeAir,
        FriStateCombinerComposite,
        FriStateOpenWitness,
        Vec<PublicColumn>,
    ) {
        (
            self.air,
            self.combiner,
            self.open_witness,
            self.open_public_columns,
        )
    }

    pub fn air(&self) -> &CompositeAir {
        &self.air
    }
}

// ---------------------------------------------------------------------------
// Helpers
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

/// Stitch the leaf-band sub-traces (combiner + input/output `FriStateOpen`)
/// into `cols`. Caller pre-allocates `cols` with
/// `outer_n_cols >= TX_VALIDITY_LEAF_N_COLS` columns and
/// `2^outer_log_rows` rows. Public-column overwrites are NOT performed
/// here — caller does the final pass against its own composite air.
///
/// [`super::tx_validity_with_spine::TxValidityCompositeWithSpine::build_trace`]
/// calls this
/// to populate the embedded leaf-band before the spine block.
#[allow(clippy::too_many_arguments)]
pub fn write_leaf_block_traces(
    cols: &mut [Vec<Block128>],
    combiner: &FriStateCombinerComposite,
    open_witness: &FriStateOpenWitness,
    open_public_columns: &[PublicColumn],
    outer_n_cols: usize,
    outer_log_rows: usize,
    output_side: &OutputSideSource,
    output_side_eval_point: [Block128; crate::airs::fri_state_open::FRI_STATE_OPEN_LOG_SLOTS],
    output_side_gamma: Block128,
) {
    assert_eq!(outer_log_rows, TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(outer_n_cols >= TX_VALIDITY_LEAF_N_COLS);

    // Combiner. Sub-trace is 512 rows; copy element-wise into the
    // leading prefix; trailing rows are zero (combiner constraints
    // are masked off by the `RowWindowWrapper` window indicator).
    let combiner_trace = combiner.build_trace();
    let combiner_cols = combiner_trace.columns;
    assert_eq!(combiner_cols.len(), COMBINER_COMPOSITE_N_COLS);
    for (i, src) in combiner_cols.into_iter().enumerate() {
        let dst = &mut cols[SKEL_COMBINER_COL_OFFSET + i];
        for (r, v) in src.into_iter().enumerate() {
            dst[r] = v;
        }
    }

    // FriStateOpen.
    let open_inner = build_open_inner_cols(open_witness, open_public_columns);
    assert_eq!(open_inner.len(), FRI_STATE_OPEN_WITNESS_COLS);
    for (i, src) in open_inner.into_iter().enumerate() {
        let dst = &mut cols[SKEL_OPEN_COL_OFFSET + i];
        for (r, v) in src.into_iter().enumerate() {
            dst[r] = v;
        }
    }

    // E.2.b.comp-3: output-side open columns. Source-driven — either
    // all-EMPTY or body-derived, must match the source passed at
    // composite construction time.
    crate::composition::tx_validity_composite::write_output_open_trace_from_source(
        cols,
        output_side,
        output_side_eval_point,
        output_side_gamma,
    );
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
    use crate::airs::fri_state_open::{FriStateOpenClaim, FRI_STATE_OPEN_N_INPUTS};

    /// Deterministic pseudo-address for opener fixtures. Address values
    /// enter the leaf only through the `FriStateOpenClaim.owner_*`
    /// fields; the AIR does not constrain them to be secret-derived.
    /// (Address/auth-tag derivation lives in the external AuthGKR proof.)
    fn mk_addr(seed: u128) -> [Block128; 2] {
        [
            Block128::from(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
            Block128::from(seed.wrapping_mul(0xBF58_476D_1CE4_E5B9)),
        ]
    }

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

    fn build() -> TxValidityCompositeLeaf {
        let prev_preimage = mk_combiner_preimage(0x5A);
        let new_preimage = mk_combiner_preimage(0xA5);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);

        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] =
            [mk_addr(11), mk_addr(22), mk_addr(33), mk_addr(44)];

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

        TxValidityCompositeLeaf::new(combiner, open_air, open_witness)
    }

    #[test]
    fn layout_constants_agree() {
        // OP-1.φ.1b: E.3.b new-state opener bands removed. E.4's
        // booleans follow the combiner window indicator directly.
        assert_eq!(
            SKEL_COMBINER_WINDOW_INDICATOR_COL,
            TX_VALIDITY_SKELETON_N_COLS
        );
        assert_eq!(
            SKEL_IS_DEACTIVATION_COL,
            SKEL_COMBINER_WINDOW_INDICATOR_COL + 1
        );
        assert_eq!(SKEL_IS_ACTIVATION_COL, SKEL_IS_DEACTIVATION_COL + 1);
        // E.5 appends the `is_coinbase` public column.
        assert_eq!(SKEL_IS_COINBASE_COL, SKEL_IS_ACTIVATION_COL + 1);
        assert_eq!(SKEL_IS_COINBASE_COL, TX_VALIDITY_LEAF_N_COLS - 1);
        assert_eq!(TX_VALIDITY_LEAF_LOG_ROWS, 13);
        const { assert!(TX_VALIDITY_LEAF_LOG_ROWS >= COMBINER_COMPOSITE_LOG_ROWS) };
    }

    #[test]
    fn honest_trace_accepts() {
        let comp = build();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
    }

    // ---- E.4: activation / deactivation public columns ------------------

    /// Build a leaf with the prev-state witness from [`build`] plus a
    /// body-derived `OutputSideSource::FromBody` so live outputs (=
    /// activations) are non-empty. Two live spends (rows 0, 1) drive
    /// `is_deactivation`; two live mints (rows 0, 1) drive `is_activation`.
    fn build_with_activation_sources() -> TxValidityCompositeLeaf {
        use noid_poseidon2b::primitives::Address;
        use noid_tx::TxOutput;
        let prev_preimage = mk_combiner_preimage(0x5A);
        let new_preimage = mk_combiner_preimage(0xA5);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);

        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] =
            [mk_addr(11), mk_addr(22), mk_addr(33), mk_addr(44)];
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
        let outputs = vec![
            TxOutput {
                slot_index: 5,
                value: 7,
                owner: Address([0x33u8; 32]),
                valid: true,
            },
            TxOutput {
                slot_index: 9,
                value: 11,
                owner: Address([0x44u8; 32]),
                valid: true,
            },
        ];
        TxValidityCompositeLeaf::new_with_options(
            combiner,
            open_air,
            open_witness,
            LeafConstructionOptions {
                output_side: OutputSideSource::FromBody {
                    outputs,
                    prev_lane_openings: [Block128::ZERO; 3],
                },
                ..LeafConstructionOptions::default()
            },
        )
    }

    #[test]
    fn e4_activation_deactivation_programmes_match_sources() {
        // Honest acceptance plus structural check: the derived
        // `is_deactivation` / `is_activation` public columns carry the
        // expected booleans on live opener rows.
        let comp = build_with_activation_sources();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
        // Rows 0,1 are live spends / live mints; rows 2,3 and beyond
        // are dummy / silenced.
        assert_eq!(trace.columns[SKEL_IS_DEACTIVATION_COL][0], Block128::ONE);
        assert_eq!(trace.columns[SKEL_IS_DEACTIVATION_COL][1], Block128::ONE);
        assert_eq!(trace.columns[SKEL_IS_DEACTIVATION_COL][2], Block128::ZERO);
        assert_eq!(trace.columns[SKEL_IS_DEACTIVATION_COL][3], Block128::ZERO);
        assert_eq!(trace.columns[SKEL_IS_ACTIVATION_COL][0], Block128::ONE);
        assert_eq!(trace.columns[SKEL_IS_ACTIVATION_COL][1], Block128::ONE);
        for j in 2..FRI_STATE_OPEN_OUTPUT_LAYOUT.n_inputs {
            assert_eq!(trace.columns[SKEL_IS_ACTIVATION_COL][j], Block128::ZERO);
        }
    }

    #[test]
    fn e4_is_deactivation_tamper_rejects() {
        // Flipping `is_deactivation[i]` on a live spend row (0 or 1)
        // breaks the linear equality tie to the input opener's
        // `col_is_spend`. Flipping on a dummy row (2 or 3) breaks the
        // tie too (both sides are zero on honest; flip pushes one to
        // one).
        let comp = build_with_activation_sources();
        for row in 0..FRI_STATE_OPEN_N_INPUTS {
            let mut cols = comp.build_trace().columns;
            cols[SKEL_IS_DEACTIVATION_COL][row] += Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "E.4: is_deactivation[{row}] tamper must REJECT",
            );
        }
    }

    #[test]
    fn e4_is_activation_tamper_rejects() {
        let comp = build_with_activation_sources();
        for row in 0..FRI_STATE_OPEN_OUTPUT_LAYOUT.n_inputs {
            let mut cols = comp.build_trace().columns;
            cols[SKEL_IS_ACTIVATION_COL][row] += Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "E.4: is_activation[{row}] tamper must REJECT",
            );
        }
    }

    // ---- E.5: coinbase marker + n_inputs=0 structural tie --------------

    /// Build a leaf with `is_coinbase = true` and no live spends
    /// (every input claim is EMPTY). Mirrors the shape needed for a
    /// coinbase tx at the leaf level: output-side can still carry live
    /// mints (the block's reward is an activation).
    fn build_coinbase_leaf(has_spends: bool) -> TxValidityCompositeLeaf {
        let prev_preimage = mk_combiner_preimage(0x5A);
        let new_preimage = mk_combiner_preimage(0xA5);
        let prev_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&prev_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let new_fields = extract_combiner_digest_fields(
            &build_combiner_side_trace(&new_preimage),
            COMBINER_PERM_LAYOUT,
        );
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);

        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] =
            [mk_addr(11), mk_addr(22), mk_addr(33), mk_addr(44)];
        let claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] = if has_spends {
            [
                spend_with_owner(11, 0, addrs[0]),
                empty_with_owner(addrs[1]),
                empty_with_owner(addrs[2]),
                empty_with_owner(addrs[3]),
            ]
        } else {
            [
                empty_with_owner(addrs[0]),
                empty_with_owner(addrs[1]),
                empty_with_owner(addrs[2]),
                empty_with_owner(addrs[3]),
            ]
        };
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

        TxValidityCompositeLeaf::new_with_options(
            combiner,
            open_air,
            open_witness,
            LeafConstructionOptions {
                is_coinbase: true,
                ..LeafConstructionOptions::default()
            },
        )
    }

    #[test]
    fn e5_non_coinbase_honest_still_accepts() {
        // Default path (is_coinbase = false, live spends allowed) must
        // still accept. Regression guard on the standard `build()` shape
        // once the E.5 public column and structural gates are live.
        let comp = build();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
        // `is_coinbase` column is row-constant zero on the default path.
        for row in 0..(1usize << TX_VALIDITY_LEAF_LOG_ROWS) {
            assert_eq!(trace.columns[SKEL_IS_COINBASE_COL][row], Block128::ZERO);
        }
    }

    #[test]
    fn e5_coinbase_without_spends_accepts() {
        let comp = build_coinbase_leaf(false);
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
        // is_coinbase pin: every row must carry ONE.
        for row in 0..(1usize << TX_VALIDITY_LEAF_LOG_ROWS) {
            assert_eq!(trace.columns[SKEL_IS_COINBASE_COL][row], Block128::ONE);
        }
    }

    #[test]
    fn e5_coinbase_with_live_spend_rejects() {
        // `has_spends = true` activates `col_is_spend = 1` on input 0's
        // opener row 0. The public-column pin on is_coinbase keeps its
        // programme at ONE, so the structural gate
        // `row_ind_0 · is_coinbase · col_is_spend` fires at
        // `1 · 1 · 1 = 1 ≠ 0` → reject.
        let comp = build_coinbase_leaf(true);
        let trace = comp.build_trace();
        assert!(!comp.air().check(&trace));
    }

    #[test]
    fn e5_is_coinbase_public_column_tamper_rejects() {
        // Honest non-coinbase trace: is_coinbase pinned to ZERO. Flip
        // the programme at any row → programme mismatch ⇒ reject.
        let comp = build();
        for row in [0usize, 1, 5, 100, 1 << 12] {
            let mut cols = comp.build_trace().columns;
            cols[SKEL_IS_COINBASE_COL][row] += Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "E.5: is_coinbase row {row} tamper must REJECT",
            );
        }
    }
}
