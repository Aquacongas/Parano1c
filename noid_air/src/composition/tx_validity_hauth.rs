// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! [`TxValidityCompositeHAuth`].
//!
//! Extends [`super::tx_validity_full::TxValidityCompositeFull`]
//! with a single [`SharedHAuthBlock`][super::shared_hauth_block] covering all
//! `FRI_STATE_OPEN_N_INPUTS` inputs. Two bridge families run per input:
//!
//! - **T2a** — per-input auth-tag tie. `(tag_hi, tag_lo)` squeezed from
//!   the shared [`HAuthMultiAir`] at
//!   `hauth_multi_row_output(i)` is bridged to a pair of outer dst
//!   cells (one pair per input) pinned as a `PublicColumn` programme
//!   carrying the declared auth tag. In the spine-embedded composite
//!   the dst is re-pointed at `TxValidityCol::AuthTagHi/Lo @ row i`
//!   via [`T2aDstOverride`].
//!
//! - **T2b** — shared `tx_body_hash` anchor. The HAuth multi-AIR now
//!   carries `tx_body_col[0..2]` witness columns pinned constant
//!   across rows; a single T2b bridge ties `tx_body_col[0..2]@row 0`
//!   to a shared dst cell pair. The default dst is pinned to the
//!   declared `tx_body_hash` via a `PublicColumn` programme; in the
//!   spine composite the dst is re-pointed at `TxBodyMerkleAir`'s
//!   wrap-output cells via [`T2bDstOverride`], which is the single
//!   canonical `tx_body_hash` origin per audit § 1 / § 6.2.
//!
//! OP-1.δ.3 — single shared T2b tie. The HAuth multi-AIR now carries
//! `tx_body_col[0..2]` witness columns bound to a single canonical
//! `tx_body_hash` origin (row 0 of the shared band), instead of baking
//! `tx_body_hash` as a compile-time AIR constant. This lets a single
//! T2b bridge close the binding for all inputs, dropping per-input
//! T2b slots (bridge + dst). Column savings vs. δ.2 for
//! `FRI_STATE_OPEN_N_INPUTS = 4`: was `4·16 + 4·2 = 72` T2b outer
//! cols; now `8 + 2 = 10` shared T2b cols plus 2 new AIR cols —
//! `-72 + 10 + 2 = -60`.
//!
//! # Layout
//!
//! All new columns append to the right of the full composite:
//!
//! ```text
//!   [0, TX_VALIDITY_FULL_N_COLS)                          — inherited
//!   [FULL_HAUTH_BLOCK_BASE, +SHARED_HAUTH_MULTI_N_COLS)   — HAuthMultiAir slab
//!   FULL_HAUTH_WINDOW_INDICATOR_COL                       — window indicator
//!   [FULL_HAUTH_T2A_BASE, +8·N_INPUTS)                    — per-input T2a bridges
//!   [FULL_HAUTH_T2B_BASE, +8)                             — shared T2b bridge
//!   [AUTH_TAG_DST_BASE, +2·N_INPUTS)                      — per-input T2a dsts
//!   [TX_BODY_DST_BASE,  +2)                               — shared T2b dst pair
//! ```

use crate::airs::fri_state_combiner::FRI_STATE_COMBINER_LOG_ROWS;
use crate::airs::fri_state_combiner_composite::{
    FriStateCombinerComposite, COMBINER_COMPOSITE_LOG_ROWS, COMBINER_COMPOSITE_N_COLS,
};
use crate::airs::fri_state_open::{
    FriStateOpenAir, FriStateOpenWitness,
    FRI_STATE_OPEN_LOG_ROWS, FRI_STATE_OPEN_N_INPUTS, FRI_STATE_OPEN_N_ROWS,
    FRI_STATE_OPEN_WITNESS_COLS,
};
use crate::airs::haddr::HADDR_LOG_ROWS;
use crate::airs::hauth::HAUTH_LOG_ROWS;
use crate::airs::hauth_multi::{
    hauth_multi_min_log_rows, hauth_multi_n_cols,
    hauth_multi_row_output, HAUTH_MULTI_LAYOUT_C, HAUTH_MULTI_TX_BODY_BASE,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWrapper, WrapPolicy,
};
use crate::composition::shared_hauth_block::{
    emit_shared_hauth_block, shared_hauth_outer_overhead_cols, write_shared_hauth_block_trace,
    SharedHAuthBlockParams, SharedHAuthInputBudget, SharedHAuthInputTargets,
    SharedHAuthTxBodyBinding,
};
use crate::composition::t1_owner_tie::LaneBridgeBudget;
use crate::composition::tx_validity_composite::{
    SKEL_COMBINER_COL_OFFSET, SKEL_COMBINER_WINDOW_INDICATOR_COL, SKEL_OPEN_COL_OFFSET,
    SKEL_OPEN_WINDOW_INDICATOR_COL,
};
use crate::composition::tx_validity_full::{
    emit_full_shared_haddr, write_full_shared_haddr_trace, TX_VALIDITY_FULL_LOG_ROWS,
    TX_VALIDITY_FULL_N_COLS,
};
use crate::gates::const_column::PublicColumn;
use crate::{Air, CompositeAir, Constraint, Trace};
use noid_core::{Block128, TowerField};

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Outer log-rows: inherited from the full composite.
pub const TX_VALIDITY_HAUTH_LOG_ROWS: usize = TX_VALIDITY_FULL_LOG_ROWS;

/// Column count of the shared `HAuthMultiAir` slab.
pub const SHARED_HAUTH_MULTI_N_COLS: usize = hauth_multi_n_cols(FRI_STATE_OPEN_N_INPUTS);

/// Inner log-rows of the shared `HAuthMultiAir`.
pub const SHARED_HAUTH_MULTI_LOG_ROWS: usize =
    hauth_multi_min_log_rows(FRI_STATE_OPEN_N_INPUTS);

/// Compile-time height sanity.
const _: () = {
    assert!(HAUTH_LOG_ROWS <= TX_VALIDITY_HAUTH_LOG_ROWS);
    assert!(HADDR_LOG_ROWS <= TX_VALIDITY_HAUTH_LOG_ROWS);
    assert!(FRI_STATE_OPEN_LOG_ROWS <= TX_VALIDITY_HAUTH_LOG_ROWS);
    assert!(SHARED_HAUTH_MULTI_LOG_ROWS <= TX_VALIDITY_HAUTH_LOG_ROWS);
    assert!(FRI_STATE_COMBINER_LOG_ROWS == COMBINER_COMPOSITE_LOG_ROWS);
};

/// Outer column offset of the shared HAuth slab.
pub const FULL_HAUTH_BLOCK_BASE: usize = TX_VALIDITY_FULL_N_COLS;

/// Outer column of the shared-HAuth window indicator.
pub const FULL_HAUTH_WINDOW_INDICATOR_COL: usize =
    FULL_HAUTH_BLOCK_BASE + SHARED_HAUTH_MULTI_N_COLS;

/// Outer column offset of the per-input T2a bridge slab
/// (8 cols/input: T2a hi + T2a lo, 4 cols each).
pub const FULL_HAUTH_T2A_BASE: usize = FULL_HAUTH_WINDOW_INDICATOR_COL + 1;

/// Outer column offset of the shared T2b bridge slab (8 cols total:
/// T2b hi + T2b lo, 4 cols each).
pub const FULL_HAUTH_T2B_BASE: usize =
    FULL_HAUTH_T2A_BASE + 8 * FRI_STATE_OPEN_N_INPUTS;

/// Outer columns consumed by the shared-HAuth block (multi-AIR slab +
/// window indicator + per-input T2a bridges + shared T2b bridges).
pub const SHARED_HAUTH_OUTER_COLS: usize =
    SHARED_HAUTH_MULTI_N_COLS + shared_hauth_outer_overhead_cols(FRI_STATE_OPEN_N_INPUTS);

/// Per-input T2a destination column base. Each input reserves two
/// columns (auth_tag_hi, auth_tag_lo). Destinations are pinned via
/// `PublicColumn` programmes carrying the declared auth tag.
pub const AUTH_TAG_DST_BASE: usize =
    FULL_HAUTH_BLOCK_BASE + SHARED_HAUTH_OUTER_COLS;

/// Shared T2b destination column base: a single `(tx_body_hi,
/// tx_body_lo)` pair bound to the canonical tx-body-hash origin.
pub const TX_BODY_DST_BASE: usize = AUTH_TAG_DST_BASE + 2 * FRI_STATE_OPEN_N_INPUTS;

/// Total outer column count.
pub const TX_VALIDITY_HAUTH_N_COLS: usize = TX_BODY_DST_BASE + 2;

/// Per-input auth-tag dst columns `(hi, lo)`.
pub const fn auth_tag_dst_cols(input: usize) -> (usize, usize) {
    let base = AUTH_TAG_DST_BASE + 2 * input;
    (base, base + 1)
}

/// Shared tx-body-hash dst columns `(hi, lo)`.
pub const fn tx_body_dst_cols() -> (usize, usize) {
    (TX_BODY_DST_BASE, TX_BODY_DST_BASE + 1)
}

// Per-input auth-tag dst rows (preserved from legacy — each input gets
// its own row per lane, well clear of the multi-AIR band on every
// shared-slab column).
pub const fn auth_tag_hi_dst_row(input: usize) -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 2 + 8 * input
}
pub const fn auth_tag_lo_dst_row(input: usize) -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 4 + 8 * input
}

/// Shared T2b tx-body dst rows (well clear of all per-input rows).
pub const fn tx_body_hi_dst_row() -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 6 + 8 * FRI_STATE_OPEN_N_INPUTS
}
pub const fn tx_body_lo_dst_row() -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 8 + 8 * FRI_STATE_OPEN_N_INPUTS
}

/// Outer column of any input's squeezed auth-tag hi lane inside the
/// shared HAuth slab. Row = [`full_hauth_squeeze_row`]`(i)`.
pub const fn full_hauth_squeeze_hi_col() -> usize {
    FULL_HAUTH_BLOCK_BASE + HAUTH_MULTI_LAYOUT_C.s
}

/// Outer column of any input's squeezed auth-tag lo lane.
pub const fn full_hauth_squeeze_lo_col() -> usize {
    FULL_HAUTH_BLOCK_BASE + HAUTH_MULTI_LAYOUT_C.s + 1
}

/// Outer row of input `i`'s squeezed auth tag inside the shared HAuth
/// slab (the multi-AIR's per-input output row).
pub fn full_hauth_squeeze_row(input: usize) -> usize {
    hauth_multi_row_output(input)
}

/// Outer column of the shared `tx_body_col` hi lane (row 0 carries
/// `tx_body_hash[0]`; enforced constant across rows by a shifted-XOR
/// gate inside [`crate::airs::hauth_multi::HAuthMultiAir`]).
pub const fn full_hauth_tx_body_hi_col() -> usize {
    FULL_HAUTH_BLOCK_BASE + HAUTH_MULTI_TX_BODY_BASE
}

/// Outer column of the shared `tx_body_col` lo lane.
pub const fn full_hauth_tx_body_lo_col() -> usize {
    FULL_HAUTH_BLOCK_BASE + HAUTH_MULTI_TX_BODY_BASE + 1
}

/// Per-input T2a bridge column bases `(t2a_hi, t2a_lo)`. Each lane
/// owns a 4-col sub-budget (bridge + src/dst/transition indicators).
pub const fn full_hauth_t2a_bases(input: usize) -> (usize, usize) {
    let base = FULL_HAUTH_T2A_BASE + 8 * input;
    (base, base + 4)
}

/// Shared T2b bridge column bases `(t2b_hi, t2b_lo)`.
pub const fn full_hauth_t2b_bases() -> (usize, usize) {
    (FULL_HAUTH_T2B_BASE, FULL_HAUTH_T2B_BASE + 4)
}

// ---------------------------------------------------------------------------
// Override types (also re-exported from `tx_validity_leaf`).
// ---------------------------------------------------------------------------

/// Per-input T2a dst override. When supplied via
/// [`FullSharedHAuthOptions::t2a_dst_override`] the HAuth bridge dst
/// cells are routed at these `(col, row)` pairs instead of the
/// canonical `auth_tag_dst_cols / auth_tag_*_dst_row`, AND the per-
/// input `PublicColumn` programme pinning the dst to the declared auth
/// tag is **omitted** by the caller. Used to retarget T2a dsts at
/// spine `TxValidityCol::AuthTagHi/Lo[i]` cells.
#[derive(Debug, Clone, Copy)]
pub struct T2aDstOverride {
    pub hi_col: usize,
    pub hi_row: usize,
    pub lo_col: usize,
    pub lo_row: usize,
}

/// Shared T2b dst override. When supplied, the single T2b bridge
/// binding `tx_body_col[0..2]@row 0` is routed at this `(col, row)`
/// pair instead of the canonical `tx_body_dst_cols / tx_body_*_dst_row`.
/// The caller is also responsible for omitting the dst-pinning
/// `PublicColumn` programme carrying the declared `tx_body_hash`.
/// Used to retarget T2b at `TxBodyMerkleAir`'s wrap-output cells.
#[derive(Debug, Clone, Copy)]
pub struct T2bDstOverride {
    pub hi_col: usize,
    pub hi_row: usize,
    pub lo_col: usize,
    pub lo_row: usize,
}

/// Optional overrides for [`emit_full_shared_hauth`] /
/// [`write_full_shared_hauth_trace`]. `Default` = canonical wiring.
#[derive(Debug, Clone, Default)]
pub struct FullSharedHAuthOptions {
    pub t2a_dst_override: Option<[T2aDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
    pub t2b_dst_override: Option<T2bDstOverride>,
}

// ---------------------------------------------------------------------------
// Shared HAuth emitter / trace writer.
// ---------------------------------------------------------------------------

fn shared_hauth_params(
    outer_n_cols: usize,
    outer_log_rows: usize,
    tx_body_hash: [Block128; 2],
    opts: &FullSharedHAuthOptions,
) -> SharedHAuthBlockParams {
    let mut inputs = Vec::with_capacity(FRI_STATE_OPEN_N_INPUTS);
    for i in 0..FRI_STATE_OPEN_N_INPUTS {
        let (t2a_hi, t2a_lo) = full_hauth_t2a_bases(i);
        let budget = SharedHAuthInputBudget {
            t2a_hi_budget: LaneBridgeBudget {
                bridge_col: t2a_hi,
                src_indicator_col: t2a_hi + 1,
                dst_indicator_col: t2a_hi + 2,
                transition_indicator_col: t2a_hi + 3,
            },
            t2a_lo_budget: LaneBridgeBudget {
                bridge_col: t2a_lo,
                src_indicator_col: t2a_lo + 1,
                dst_indicator_col: t2a_lo + 2,
                transition_indicator_col: t2a_lo + 3,
            },
        };
        let (default_tag_hi_col, default_tag_lo_col) = auth_tag_dst_cols(i);
        let (tag_hi_col, tag_hi_row, tag_lo_col, tag_lo_row) = match opts.t2a_dst_override {
            Some(arr) => {
                let o = arr[i];
                (o.hi_col, o.hi_row, o.lo_col, o.lo_row)
            }
            None => (
                default_tag_hi_col,
                auth_tag_hi_dst_row(i),
                default_tag_lo_col,
                auth_tag_lo_dst_row(i),
            ),
        };
        let targets = SharedHAuthInputTargets {
            auth_tag_hi_dst_col: tag_hi_col,
            auth_tag_hi_dst_row: tag_hi_row,
            auth_tag_lo_dst_col: tag_lo_col,
            auth_tag_lo_dst_row: tag_lo_row,
        };
        inputs.push((budget, targets));
    }

    let (t2b_hi_base, t2b_lo_base) = full_hauth_t2b_bases();
    let (default_txb_hi_col, default_txb_lo_col) = tx_body_dst_cols();
    let (txb_hi_col, txb_hi_row, txb_lo_col, txb_lo_row) = match opts.t2b_dst_override {
        Some(o) => (o.hi_col, o.hi_row, o.lo_col, o.lo_row),
        None => (
            default_txb_hi_col,
            tx_body_hi_dst_row(),
            default_txb_lo_col,
            tx_body_lo_dst_row(),
        ),
    };
    let tx_body_binding = SharedHAuthTxBodyBinding {
        hi_budget: LaneBridgeBudget {
            bridge_col: t2b_hi_base,
            src_indicator_col: t2b_hi_base + 1,
            dst_indicator_col: t2b_hi_base + 2,
            transition_indicator_col: t2b_hi_base + 3,
        },
        lo_budget: LaneBridgeBudget {
            bridge_col: t2b_lo_base,
            src_indicator_col: t2b_lo_base + 1,
            dst_indicator_col: t2b_lo_base + 2,
            transition_indicator_col: t2b_lo_base + 3,
        },
        hi_dst_col: txb_hi_col,
        hi_dst_row: txb_hi_row,
        lo_dst_col: txb_lo_col,
        lo_dst_row: txb_lo_row,
    };

    SharedHAuthBlockParams {
        n_inputs: FRI_STATE_OPEN_N_INPUTS,
        col_offset: FULL_HAUTH_BLOCK_BASE,
        window_indicator_col: FULL_HAUTH_WINDOW_INDICATOR_COL,
        row_window_start: 0,
        outer_n_cols,
        outer_log_rows,
        tx_body_hash,
        inputs,
        tx_body_binding,
    }
}

/// Shared entry-point: emit the shared-HAuth block wiring into the
/// enclosing composite.
pub fn emit_full_shared_hauth(
    outer_n_cols: usize,
    outer_log_rows: usize,
    tx_body_hash: [Block128; 2],
    opts: &FullSharedHAuthOptions,
) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
    let wiring = emit_shared_hauth_block(shared_hauth_params(
        outer_n_cols,
        outer_log_rows,
        tx_body_hash,
        opts,
    ));
    (wiring.constraints, wiring.public_columns)
}

/// Honest-trace writer for the shared-HAauth block.
pub fn write_full_shared_hauth_trace(
    cols: &mut [Vec<Block128>],
    outer_n_cols: usize,
    outer_log_rows: usize,
    secrets: &[[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    tx_body_hash: [Block128; 2],
    opts: &FullSharedHAuthOptions,
) {
    let params = shared_hauth_params(outer_n_cols, outer_log_rows, tx_body_hash, opts);
    let _ = write_shared_hauth_block_trace(cols, &params, secrets);
}

// ---------------------------------------------------------------------------
// Composite
// ---------------------------------------------------------------------------

/// HAuth composite: combiner + FriStateOpen + shared HAddr (T1) +
/// shared HAuth (T2a per-input + T2b per-input).
pub struct TxValidityCompositeHAuth {
    pub air: CompositeAir,
    combiner: FriStateCombinerComposite,
    open_witness: FriStateOpenWitness,
    open_public_columns: Vec<PublicColumn>,
    secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    tx_body_hash: [Block128; 2],
    auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
}

impl TxValidityCompositeHAuth {
    pub fn new(
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
        secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
        tx_body_hash: [Block128; 2],
        auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    ) -> Self {
        let outer_n_cols = TX_VALIDITY_HAUTH_N_COLS;
        let outer_log_rows = TX_VALIDITY_HAUTH_LOG_ROWS;
        let outer_n_rows = 1usize << outer_log_rows;

        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // Block A — combiner via RowWindowWrapper(MaskOff).
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

        // Block B.out (E.2.b) — output-side FriStateOpenAir (all-EMPTY).
        let (out_open_air, _) =
            crate::composition::tx_validity_composite::build_empty_output_side();
        let (out_open_wiring, _) =
            crate::composition::tx_validity_composite::emit_output_open_wiring(
                out_open_air,
                outer_n_cols,
                outer_log_rows,
            );
        constraints.extend(out_open_wiring.constraints);
        public_columns.extend(out_open_wiring.public_columns);

        // E.2.b.comp-4: slot-index bridge pins (all-zero programmes
        // for the all-EMPTY output source used here).
        public_columns.extend(
            crate::composition::tx_validity_composite::emit_out_open_slot_index_publics(
                &crate::composition::tx_validity_composite::OutputSideSource::Empty,
                1usize << outer_log_rows,
            ),
        );

        // Block C — shared HAddr (OP-1.δ.1).
        let (haddr_constraints, haddr_publics) =
            emit_full_shared_haddr(outer_n_cols, outer_log_rows);
        constraints.extend(haddr_constraints);
        public_columns.extend(haddr_publics);

        // Block D — shared HAuth (OP-1.δ.2).
        let (hauth_constraints, hauth_publics) = emit_full_shared_hauth(
            outer_n_cols,
            outer_log_rows,
            tx_body_hash,
            &FullSharedHAuthOptions::default(),
        );
        constraints.extend(hauth_constraints);
        public_columns.extend(hauth_publics);

        // Pin per-input T2a destinations to declared auth tags.
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let (hi_col, lo_col) = auth_tag_dst_cols(input);
            public_columns.push(PublicColumn::new(
                hi_col,
                pinned_row_programme(auth_tag_hi_dst_row(input), auth_tags[input][0], outer_n_rows),
            ));
            public_columns.push(PublicColumn::new(
                lo_col,
                pinned_row_programme(auth_tag_lo_dst_row(input), auth_tags[input][1], outer_n_rows),
            ));
        }

        // Pin the shared T2b dst to the declared tx_body_hash.
        let (txb_hi_col, txb_lo_col) = tx_body_dst_cols();
        public_columns.push(PublicColumn::new(
            txb_hi_col,
            pinned_row_programme(tx_body_hi_dst_row(), tx_body_hash[0], outer_n_rows),
        ));
        public_columns.push(PublicColumn::new(
            txb_lo_col,
            pinned_row_programme(tx_body_lo_dst_row(), tx_body_hash[1], outer_n_rows),
        ));

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
            tx_body_hash,
            auth_tags,
        }
    }

    /// Build an honest outer trace.
    pub fn build_trace(&self) -> Trace {
        let outer_n_rows = 1usize << TX_VALIDITY_HAUTH_LOG_ROWS;
        let mut cols: Vec<Vec<Block128>> = (0..TX_VALIDITY_HAUTH_N_COLS)
            .map(|_| vec![Block128::ZERO; outer_n_rows])
            .collect();

        // Combiner — inner rows [0, 2^9); beyond silenced.
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

        // FriStateOpen.
        let open_inner =
            build_open_inner_cols(&self.open_witness, &self.open_public_columns);
        assert_eq!(open_inner.len(), FRI_STATE_OPEN_WITNESS_COLS);
        for (i, src) in open_inner.into_iter().enumerate() {
            let dst = &mut cols[SKEL_OPEN_COL_OFFSET + i];
            for (r, v) in src.into_iter().enumerate() {
                dst[r] = v;
            }
        }

        // E.2.b: output-side open columns (all-EMPTY honest witness).
        crate::composition::tx_validity_composite::write_empty_output_open_trace(&mut cols);

        // Shared HAddr block (OP-1.δ.1).
        let _ = write_full_shared_haddr_trace(
            &mut cols,
            TX_VALIDITY_HAUTH_N_COLS,
            TX_VALIDITY_HAUTH_LOG_ROWS,
            &self.secrets,
        );

        // Shared HAuth block (OP-1.δ.2).
        write_full_shared_hauth_trace(
            &mut cols,
            TX_VALIDITY_HAUTH_N_COLS,
            TX_VALIDITY_HAUTH_LOG_ROWS,
            &self.secrets,
            self.tx_body_hash,
            &FullSharedHAuthOptions::default(),
        );

        // Final pass: overwrite every public column with its programme.
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

    pub fn tx_body_hash(&self) -> [Block128; 2] {
        self.tx_body_hash
    }

    pub fn auth_tags(&self) -> &[[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] {
        &self.auth_tags
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pinned_row_programme(row: usize, value: Block128, total_rows: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; total_rows];
    out[row] = value;
    out
}

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

/// Native auth-tag computation for a given `(secret, tx_body_hash)`.
pub fn native_auth_tag(
    secret: [Block128; 2],
    tx_body_hash: [Block128; 2],
) -> [Block128; 2] {
    use crate::airs::hauth::{build_hauth_trace, extract_hauth_output};
    extract_hauth_output(&build_hauth_trace(secret, tx_body_hash))
}

/// Native address computation — test helper.
pub fn native_address(secret: [Block128; 2]) -> [Block128; 2] {
    use crate::airs::haddr::{build_haddr_trace, extract_haddr_output};
    extract_haddr_output(&build_haddr_trace(secret))
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
    use crate::airs::fri_state_open::{FriStateOpenClaim, COL_OWNER_HI};
    use crate::airs::hauth_multi::HAUTH_MULTI_LAYOUT_A;

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

    fn build() -> TxValidityCompositeHAuth {
        let prev_preimage = mk_combiner_preimage(0x5A);
        let new_preimage = mk_combiner_preimage(0xA5);
        let prev_fields =
            extract_combiner_digest_fields(&build_combiner_side_trace(&prev_preimage), COMBINER_PERM_LAYOUT);
        let new_fields =
            extract_combiner_digest_fields(&build_combiner_side_trace(&new_preimage), COMBINER_PERM_LAYOUT);
        let combiner =
            FriStateCombinerComposite::new(prev_preimage, prev_fields, new_preimage, new_fields);

        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            mk_secret(11),
            mk_secret(22),
            mk_secret(33),
            mk_secret(44),
        ];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]),
            native_address(secrets[1]),
            native_address(secrets[2]),
            native_address(secrets[3]),
        ];

        let tx_body_hash: [Block128; 2] = [
            Block128::from(0x1111_2222_3333_4444_u128),
            Block128::from(0x5555_6666_7777_8888_u128),
        ];

        let auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_auth_tag(secrets[0], tx_body_hash),
            native_auth_tag(secrets[1], tx_body_hash),
            native_auth_tag(secrets[2], tx_body_hash),
            native_auth_tag(secrets[3], tx_body_hash),
        ];

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

        TxValidityCompositeHAuth::new(
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
        )
    }

    #[test]
    fn layout_constants_agree() {
        assert_eq!(
            TX_VALIDITY_HAUTH_N_COLS,
            TX_VALIDITY_FULL_N_COLS
                + SHARED_HAUTH_OUTER_COLS
                + 2 * FRI_STATE_OPEN_N_INPUTS // per-input T2a dsts
                + 2                            // shared T2b dst pair
        );
        assert_eq!(
            SHARED_HAUTH_OUTER_COLS,
            SHARED_HAUTH_MULTI_N_COLS + 1 + 8 * FRI_STATE_OPEN_N_INPUTS + 8
        );
        assert_eq!(TX_VALIDITY_HAUTH_LOG_ROWS, TX_VALIDITY_FULL_LOG_ROWS);
    }

    #[test]
    fn honest_trace_accepts() {
        let comp = build();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
    }

    #[test]
    fn hauth_squeeze_matches_declared_tag_per_input() {
        let comp = build();
        let cols = comp.build_trace().columns;
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let hi = cols[full_hauth_squeeze_hi_col()][full_hauth_squeeze_row(input)];
            let lo = cols[full_hauth_squeeze_lo_col()][full_hauth_squeeze_row(input)];
            assert_eq!(hi, comp.auth_tags()[input][0]);
            assert_eq!(lo, comp.auth_tags()[input][1]);
        }
    }

    #[test]
    fn t2a_hi_declared_tag_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (hi_col, _lo_col) = auth_tag_dst_cols(0);
        cols[hi_col][auth_tag_hi_dst_row(0)] =
            cols[hi_col][auth_tag_hi_dst_row(0)] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t2a_lo_declared_tag_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (_hi_col, lo_col) = auth_tag_dst_cols(2);
        cols[lo_col][auth_tag_lo_dst_row(2)] =
            cols[lo_col][auth_tag_lo_dst_row(2)] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t2b_tx_body_hi_dst_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (hi_col, _) = tx_body_dst_cols();
        let row = tx_body_hi_dst_row();
        cols[hi_col][row] = cols[hi_col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t2b_tx_body_lo_dst_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (_, lo_col) = tx_body_dst_cols();
        let row = tx_body_lo_dst_row();
        cols[lo_col][row] = cols[lo_col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t2b_tx_body_col_tamper_rejects() {
        // Tamper the shared tx_body_col itself at a non-bridge row:
        // the shifted-XOR constant gate should reject.
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let col = full_hauth_tx_body_hi_col();
        let row = (1usize << TX_VALIDITY_HAUTH_LOG_ROWS) - 3;
        cols[col][row] = cols[col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_interior_tamper_rejects() {
        // Tamper an interior cell of the shared multi-AIR slab inside
        // input 1's row band.
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let col = FULL_HAUTH_BLOCK_BASE + HAUTH_MULTI_LAYOUT_A.sout + 2;
        let row = full_hauth_squeeze_row(1).saturating_sub(5).max(1);
        cols[col][row] = cols[col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_squeeze_cell_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let col = full_hauth_squeeze_hi_col();
        let row = full_hauth_squeeze_row(2);
        cols[col][row] = cols[col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t1_still_active_owner_tamper_rejects() {
        // T1 ties must still fire.
        let comp = build();
        let mut cols = comp.build_trace().columns;
        cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][0] =
            cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][0] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }
}
