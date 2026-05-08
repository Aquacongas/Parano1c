// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! [`TxValidityCompositeLeaf`].
//!
//! Inherits the [`super::tx_validity_hauth::TxValidityCompositeHAuth`]
//! layout verbatim at `TX_VALIDITY_LEAF_LOG_ROWS = 13` so the composite
//! can be embedded inside
//! [`super::tx_validity_with_spine::TxValidityCompositeWithSpine`]
//! without an outer-row-count mismatch. Output commitments are pinned
//! by `TxBodyMerkleAir`'s `o1_payload_programme` on the Merkle side of
//! the composite.

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
use crate::airs::hauth::{HAUTH_LOG_ROWS, HAUTH_N_COLS};
use crate::composition::haddr_block::{
    emit_haddr_block, write_haddr_block_trace, HAddrBlockColumns, HAddrBlockParams,
    HAddrBlockT1Targets,
};
use crate::composition::hauth_block::{
    emit_hauth_block, write_hauth_block_trace, HAuthBlockColumns, HAuthBlockParams,
    HAuthBlockTargets,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWrapper, WrapPolicy,
};
use crate::composition::t1_owner_tie::{LaneBridgeBudget, T1LaneColumnBudget};
use crate::composition::tx_validity_composite::{
    NewStateInputSource, NewStateOutputSource, OutputSideSource, SKEL_COMBINER_COL_OFFSET,
    SKEL_OPEN_COL_OFFSET, SKEL_OPEN_WINDOW_INDICATOR_COL,
};
use crate::composition::tx_validity_full::full_haddr_block_base;
use crate::composition::tx_validity_hauth::{
    full_hauth_block_base, TX_VALIDITY_HAUTH_N_COLS,
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
    assert!(HAUTH_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(HADDR_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(FRI_STATE_OPEN_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(COMBINER_COMPOSITE_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(FRI_STATE_COMBINER_LOG_ROWS == COMBINER_COMPOSITE_LOG_ROWS);
};

/// Outer column reserved for the combiner block's window indicator.
/// The combiner is wrapped via [`RowWindowWrapper`] under
/// `WrapPolicy::MaskOff` so its row-9-scoped constraints are silenced
/// past row `2^COMBINER_COMPOSITE_LOG_ROWS = 512` on the
/// 8192-row outer trace.
pub const SKEL_COMBINER_WINDOW_INDICATOR_COL: usize = TX_VALIDITY_HAUTH_N_COLS;

// ---------------------------------------------------------------------
// E.3.b — new-state opener bands.
//
// Two more `FriStateOpenAir` blocks live past the combiner window
// indicator. Layouts match the prev-state side:
// - new-state input opener uses `FriStateOpenLayout::DEFAULT`
//   (`MAX_INPUTS = 4` rows, same witness width as the prev-state
//   input opener).
// - new-state output opener uses `FRI_STATE_OPEN_OUTPUT_LAYOUT`
//   (`MAX_OUTPUTS = 8` rows, same witness width as the prev-state
//   output opener).
// ---------------------------------------------------------------------

use crate::airs::fri_state_open::{FriStateOpenLayout, FRI_STATE_OPEN_OUTPUT_LAYOUT};

/// E.3.b — witness width of the new-state input opener block (DEFAULT
/// layout = 4 live inputs).
pub const NEW_IN_OPEN_WITNESS_COLS: usize = FriStateOpenLayout::DEFAULT.witness_cols();
/// E.3.b — witness width of the new-state output opener block
/// (OUTPUT layout = 8 live outputs).
pub const NEW_OUT_OPEN_WITNESS_COLS: usize =
    FRI_STATE_OPEN_OUTPUT_LAYOUT.witness_cols();

/// E.3.b — new-state input opener band.
pub const SKEL_NEW_IN_OPEN_COL_OFFSET: usize = SKEL_COMBINER_WINDOW_INDICATOR_COL + 1;
pub const SKEL_NEW_IN_OPEN_WINDOW_INDICATOR_COL: usize =
    SKEL_NEW_IN_OPEN_COL_OFFSET + NEW_IN_OPEN_WITNESS_COLS;

/// E.3.b — new-state output opener band.
pub const SKEL_NEW_OUT_OPEN_COL_OFFSET: usize =
    SKEL_NEW_IN_OPEN_WINDOW_INDICATOR_COL + 1;
pub const SKEL_NEW_OUT_OPEN_WINDOW_INDICATOR_COL: usize =
    SKEL_NEW_OUT_OPEN_COL_OFFSET + NEW_OUT_OPEN_WITNESS_COLS;

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
pub const SKEL_IS_DEACTIVATION_COL: usize = SKEL_NEW_OUT_OPEN_WINDOW_INDICATOR_COL + 1;
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
// Wiring helpers (mirrored — inputs unchanged)
// ---------------------------------------------------------------------------

const REL_HAUTH_SUBAIR_COL: usize = 0;
const REL_HAUTH_WINDOW_INDICATOR_COL: usize = HAUTH_N_COLS;
const REL_T2A_HI_BRIDGE: usize = HAUTH_N_COLS + 1;
const REL_T2A_HI_SRC: usize = HAUTH_N_COLS + 2;
const REL_T2A_HI_DST_IND: usize = HAUTH_N_COLS + 3;
const REL_T2A_HI_TRANS: usize = HAUTH_N_COLS + 4;
const REL_T2A_LO_BRIDGE: usize = HAUTH_N_COLS + 5;
const REL_T2A_LO_SRC: usize = HAUTH_N_COLS + 6;
const REL_T2A_LO_DST_IND: usize = HAUTH_N_COLS + 7;
const REL_T2A_LO_TRANS: usize = HAUTH_N_COLS + 8;
const REL_T2B_HI_BRIDGE: usize = HAUTH_N_COLS + 9;
const REL_T2B_HI_SRC: usize = HAUTH_N_COLS + 10;
const REL_T2B_HI_DST_IND: usize = HAUTH_N_COLS + 11;
const REL_T2B_HI_TRANS: usize = HAUTH_N_COLS + 12;
const REL_T2B_LO_BRIDGE: usize = HAUTH_N_COLS + 13;
const REL_T2B_LO_SRC: usize = HAUTH_N_COLS + 14;
const REL_T2B_LO_DST_IND: usize = HAUTH_N_COLS + 15;
const REL_T2B_LO_TRANS: usize = HAUTH_N_COLS + 16;

const fn auth_tag_hi_dst_row(input: usize) -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 2 + 8 * input
}
const fn auth_tag_lo_dst_row(input: usize) -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 4 + 8 * input
}
const fn pre_s_b_hi_dst_row(input: usize) -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 6 + 8 * input
}
const fn pre_s_b_lo_dst_row(input: usize) -> usize {
    crate::airs::hauth::HAUTH_N_ROWS + 8 + 8 * input
}

/// Per-input T2a dst override. When supplied via
/// [`LeafConstructionOptions::t2a_dst_override`] the HAuth block's
/// hi/lo auth-tag bridge dst cells are routed at these `(col, row)`
/// pairs instead of the canonical `auth_tag_dst_cols /
/// auth_tag_*_dst_row`, AND the per-input `PublicColumn` programme
/// that pins the dst to the declared auth tag is **omitted**. Used
/// used to retarget T2a dsts at spine
/// `TxValidityCol::AuthTagHi/Lo[i]` cells.
#[derive(Debug, Clone, Copy)]
pub struct T2aDstOverride {
    pub hi_col: usize,
    pub hi_row: usize,
    pub lo_col: usize,
    pub lo_row: usize,
}

/// Per-input T2b dst override. When supplied via
/// [`LeafConstructionOptions::t2b_dst_override`] the HAuth block's
/// hi/lo `pre_s_b` (== `tx_body_hash`) bridge dst cells are routed at
/// these `(col, row)` pairs instead of the canonical
/// `pre_s_b_dst_cols / pre_s_b_*_dst_row`. The leaf composite
/// emits no `PublicColumn` programmes for T2b dsts (they are unpinned
/// — see `tx_validity_hauth.rs:427`), so unlike T2a the override
/// only re-routes the bridge dst cells. Used to point all per-input
/// T2b dsts at the spine's single canonical wrap-output cell carrying
/// `tx_body_hash`.
#[derive(Debug, Clone, Copy)]
pub struct T2bDstOverride {
    pub hi_col: usize,
    pub hi_row: usize,
    pub lo_col: usize,
    pub lo_row: usize,
}

/// Optional construction-time tweaks for [`TxValidityCompositeLeaf`].
/// `Default` applies no overrides (canonical wiring).
#[derive(Debug, Clone, Default)]
pub struct LeafConstructionOptions {
    /// When `Some`, override every HAuth block's bridge dst cells
    /// (auth-tag hi/lo) and skip the T2a PI-pin emission. Caller
    /// must guarantee each override cell lies inside the outer
    /// composite and (in honest traces) carries the corresponding
    /// `native_auth_tag(secrets[i], tx_body_hash)`.
    pub t2a_dst_override: Option<[T2aDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
    /// When `Some`, override every HAuth block's `pre_s_b` (==
    /// `tx_body_hash`) bridge dst cells. Caller must guarantee each
    /// override cell lies inside the outer composite and (in honest
    /// traces) carries `tx_body_hash[lane]`. No PI-pin gating is
    /// needed since the leaf composite emits no T2b programmes.
    pub t2b_dst_override: Option<[T2bDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
    /// E.2.b.comp-3: how the output-side `FriStateOpenAir` block is
    /// populated. `Empty` (default) keeps the deterministic all-EMPTY
    /// witness; `FromBody` binds the `TxOutput` list as mint claims
    /// routed through the γ-RLC accumulator with the supplied
    /// `prev_lane_openings` (the verifier-known FRI openings of
    /// `prev_state` at the output-side eval point).
    pub output_side: OutputSideSource,
    /// E.3.a: how the new-state input-side `FriStateOpenAir` block is
    /// populated. `Empty` (default) is pure plumbing — no block is
    /// wired in Leaf until E.3.b reserves a column band. The field is
    /// captured so downstream composites can thread a body-derived
    /// source once wiring lands.
    pub new_input_side: NewStateInputSource,
    /// E.3.a: how the new-state output-side `FriStateOpenAir` block is
    /// populated. Same rationale as `new_input_side`.
    pub new_output_side: NewStateOutputSource,
    /// E.5: tx-level coinbase marker. `false` (default) is the normal
    /// non-coinbase path; `true` activates the structural rule
    /// `is_coinbase = 1 ⇒ n_inputs = 0` — every live-spend row must be
    /// silenced on the input opener.
    pub is_coinbase: bool,
}

fn hauth_block_params_for(
    input: usize,
    outer_n_cols: usize,
    tx_body_hash: [Block128; 2],
    t2a_override: Option<T2aDstOverride>,
    t2b_override: Option<T2bDstOverride>,
) -> HAuthBlockParams {
    let base = full_hauth_block_base(input);
    let (default_tag_hi_col, default_tag_lo_col) =
        crate::composition::tx_validity_hauth::auth_tag_dst_cols(input);
    let (tag_hi_col, tag_hi_row, tag_lo_col, tag_lo_row) = match t2a_override {
        Some(o) => (o.hi_col, o.hi_row, o.lo_col, o.lo_row),
        None => (
            default_tag_hi_col,
            auth_tag_hi_dst_row(input),
            default_tag_lo_col,
            auth_tag_lo_dst_row(input),
        ),
    };
    let (default_pre_hi_col, default_pre_lo_col) =
        crate::composition::tx_validity_hauth::pre_s_b_dst_cols(input);
    let (pre_hi_col, pre_hi_row, pre_lo_col, pre_lo_row) = match t2b_override {
        Some(o) => (o.hi_col, o.hi_row, o.lo_col, o.lo_row),
        None => (
            default_pre_hi_col,
            pre_s_b_hi_dst_row(input),
            default_pre_lo_col,
            pre_s_b_lo_dst_row(input),
        ),
    };
    HAuthBlockParams {
        cols: HAuthBlockColumns {
            col_offset: base + REL_HAUTH_SUBAIR_COL,
            window_indicator_col: base + REL_HAUTH_WINDOW_INDICATOR_COL,
            t2a_hi_budget: LaneBridgeBudget {
                bridge_col: base + REL_T2A_HI_BRIDGE,
                src_indicator_col: base + REL_T2A_HI_SRC,
                dst_indicator_col: base + REL_T2A_HI_DST_IND,
                transition_indicator_col: base + REL_T2A_HI_TRANS,
            },
            t2a_lo_budget: LaneBridgeBudget {
                bridge_col: base + REL_T2A_LO_BRIDGE,
                src_indicator_col: base + REL_T2A_LO_SRC,
                dst_indicator_col: base + REL_T2A_LO_DST_IND,
                transition_indicator_col: base + REL_T2A_LO_TRANS,
            },
            t2b_hi_budget: LaneBridgeBudget {
                bridge_col: base + REL_T2B_HI_BRIDGE,
                src_indicator_col: base + REL_T2B_HI_SRC,
                dst_indicator_col: base + REL_T2B_HI_DST_IND,
                transition_indicator_col: base + REL_T2B_HI_TRANS,
            },
            t2b_lo_budget: LaneBridgeBudget {
                bridge_col: base + REL_T2B_LO_BRIDGE,
                src_indicator_col: base + REL_T2B_LO_SRC,
                dst_indicator_col: base + REL_T2B_LO_DST_IND,
                transition_indicator_col: base + REL_T2B_LO_TRANS,
            },
        },
        row_window_start: 0,
        outer_n_cols,
        outer_log_rows: TX_VALIDITY_LEAF_LOG_ROWS,
        tx_body_hash,
        targets: HAuthBlockTargets {
            auth_tag_hi_dst_col: tag_hi_col,
            auth_tag_hi_dst_row: tag_hi_row,
            auth_tag_lo_dst_col: tag_lo_col,
            auth_tag_lo_dst_row: tag_lo_row,
            tx_body_hi_dst_col: pre_hi_col,
            tx_body_hi_dst_row: pre_hi_row,
            tx_body_lo_dst_col: pre_lo_col,
            tx_body_lo_dst_row: pre_lo_row,
        },
    }
}

fn haddr_block_params_for(input: usize, outer_n_cols: usize) -> HAddrBlockParams {
    let base = full_haddr_block_base(input);
    const REL_HADDR_SUBAIR_COL: usize = 0;
    const REL_WINDOW_INDICATOR_COL: usize = HADDR_N_COLS;
    const REL_T1_HI_BRIDGE_COL: usize = HADDR_N_COLS + 1;
    const REL_T1_HI_SRC_IND_COL: usize = HADDR_N_COLS + 2;
    const REL_T1_HI_DST_IND_COL: usize = HADDR_N_COLS + 3;
    const REL_T1_HI_TRANS_IND_COL: usize = HADDR_N_COLS + 4;
    const REL_T1_LO_BRIDGE_COL: usize = HADDR_N_COLS + 5;
    const REL_T1_LO_SRC_IND_COL: usize = HADDR_N_COLS + 6;
    const REL_T1_LO_DST_IND_COL: usize = HADDR_N_COLS + 7;
    const REL_T1_LO_TRANS_IND_COL: usize = HADDR_N_COLS + 8;
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
        outer_log_rows: TX_VALIDITY_LEAF_LOG_ROWS,
        t1_targets: HAddrBlockT1Targets {
            owner_hi_dst_col: SKEL_OPEN_COL_OFFSET + COL_OWNER_HI,
            owner_hi_dst_row: input,
            owner_lo_dst_col: SKEL_OPEN_COL_OFFSET + COL_OWNER_LO,
            owner_lo_dst_row: input,
        },
    }
}

// ---------------------------------------------------------------------------
// Composite
// ---------------------------------------------------------------------------

/// Leaf composite: combiner + FriStateOpen + N_INPUTS × HAddr (T1)
/// + N_INPUTS × HAuth (T2a per-input + T2b per-input).
pub struct TxValidityCompositeLeaf {
    pub air: CompositeAir,
    combiner: FriStateCombinerComposite,
    open_witness: FriStateOpenWitness,
    open_public_columns: Vec<PublicColumn>,
    secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    tx_body_hash: [Block128; 2],
    auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    /// Optional per-input T2a dst override. When `Some`, the
    /// HAuth bridge dst cells are routed at these `(col, row)` pairs
    /// and the T2a PI-pin loop is skipped at construction.
    t2a_dst_override: Option<[T2aDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
    /// Optional per-input T2b (`pre_s_b == tx_body_hash`) dst override.
    /// When `Some`, the HAuth `pre_s_b` bridge dst cells are
    /// routed at these `(col, row)` pairs.
    t2b_dst_override: Option<[T2bDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
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
    /// E.3.b — new-state input opener source, captured so
    /// `build_trace` can re-derive the honest sub-trace.
    new_input_side: NewStateInputSource,
    /// E.3.b — new-state output opener source, captured for `build_trace`.
    new_output_side: NewStateOutputSource,
}

impl TxValidityCompositeLeaf {
    pub fn new(
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
        secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
        tx_body_hash: [Block128; 2],
        auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    ) -> Self {
        Self::new_with_options(
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
            LeafConstructionOptions::default(),
        )
    }

    /// Construct a [`TxValidityCompositeLeaf`] with caller-controlled
    /// option overrides. See [`LeafConstructionOptions`].
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_options(
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
        secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
        tx_body_hash: [Block128; 2],
        auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
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

        // Block B.new_in (E.3.b) — new-state input-side FriStateOpenAir.
        // Opens `new_state_root` at every live input's `slot_index`;
        // honest pre = post = 0 on live spends ⇒ `opened_pre_lane = 0`
        // ⇒ γ-RLC terminus collapses to zero. Slot-index bits are
        // pinned via the comp-4-analogue bridge below.
        let (new_in_air, _) =
            crate::composition::tx_validity_composite::build_new_input_side_from_source(
                &options.new_input_side,
                output_side_eval_point,
                output_side_gamma,
            );
        let new_in_layout = new_in_air.layout();
        assert_eq!(new_in_layout, crate::airs::fri_state_open::FriStateOpenLayout::DEFAULT);
        let (new_in_wiring, _) =
            crate::composition::tx_validity_composite::emit_open_wiring_at(
                new_in_air,
                SKEL_NEW_IN_OPEN_COL_OFFSET,
                SKEL_NEW_IN_OPEN_WINDOW_INDICATOR_COL,
                outer_n_cols,
                outer_log_rows,
            );
        constraints.extend(new_in_wiring.constraints);
        public_columns.extend(new_in_wiring.public_columns);

        // E.3.b — new-state input slot-index bridge. Per-row pin to
        // bit `k` of `inputs[i].slot_index` (live rows) / zero (dummy).
        let new_in_slot_indices: Vec<u32> = match &options.new_input_side {
            NewStateInputSource::Empty => vec![0; new_in_layout.n_inputs],
            NewStateInputSource::FromBody { inputs, .. } => (0..new_in_layout.n_inputs)
                .map(|i| {
                    let inp = inputs
                        .get(i)
                        .copied()
                        .unwrap_or_else(noid_tx::TxInput::dummy);
                    if inp.valid { inp.slot_index } else { 0 }
                })
                .collect(),
        };
        public_columns.extend(
            crate::composition::tx_validity_composite::emit_slot_index_publics_at(
                &new_in_slot_indices,
                SKEL_NEW_IN_OPEN_COL_OFFSET,
                new_in_layout,
                outer_n_rows,
            ),
        );

        // Block B.new_out (E.3.b) — new-state output-side
        // FriStateOpenAir. Opens `new_state_root` at every live
        // output's `slot_index`; honest post = `(value, owner)`,
        // "delta" on re-execution = 0 (see builder docs). Slot-index
        // bits pinned below.
        let (new_out_air, _) =
            crate::composition::tx_validity_composite::build_new_output_side_from_source(
                &options.new_output_side,
                output_side_eval_point,
                output_side_gamma,
            );
        let new_out_layout = new_out_air.layout();
        assert_eq!(new_out_layout, FRI_STATE_OPEN_OUTPUT_LAYOUT);
        let (new_out_wiring, _) =
            crate::composition::tx_validity_composite::emit_open_wiring_at(
                new_out_air,
                SKEL_NEW_OUT_OPEN_COL_OFFSET,
                SKEL_NEW_OUT_OPEN_WINDOW_INDICATOR_COL,
                outer_n_cols,
                outer_log_rows,
            );
        constraints.extend(new_out_wiring.constraints);
        public_columns.extend(new_out_wiring.public_columns);

        let new_out_slot_indices: Vec<u32> = match &options.new_output_side {
            NewStateOutputSource::Empty => vec![0; new_out_layout.n_inputs],
            NewStateOutputSource::FromBody { outputs, .. } => (0..new_out_layout.n_inputs)
                .map(|j| {
                    let out = outputs
                        .get(j)
                        .copied()
                        .unwrap_or_else(noid_tx::TxOutput::dummy);
                    if out.valid { out.slot_index } else { 0 }
                })
                .collect(),
        };
        public_columns.extend(
            crate::composition::tx_validity_composite::emit_slot_index_publics_at(
                &new_out_slot_indices,
                SKEL_NEW_OUT_OPEN_COL_OFFSET,
                new_out_layout,
                outer_n_rows,
            ),
        );

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
                if row >= in_layout.n_inputs { break; }
                p[row] = if claim.is_spend { Block128::ONE } else { Block128::ZERO };
            }
            p
        };
        let is_act_programme: Vec<Block128> = {
            let mut p = vec![Block128::ZERO; outer_n_rows];
            // Output activation booleans follow the prev-side output
            // opener's `is_mint` flags — one-to-one with `options.output_side`.
            if let OutputSideSource::FromBody { outputs, .. } = &options.output_side {
                for (j, out) in outputs.iter().enumerate() {
                    if j >= out_layout.n_inputs { break; }
                    p[j] = if out.valid { Block128::ONE } else { Block128::ZERO };
                }
            }
            p
        };
        public_columns.push(PublicColumn::new(SKEL_IS_DEACTIVATION_COL, is_deact_programme));
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
        let out_is_mint_col =
            crate::composition::tx_validity_composite::SKEL_OUT_OPEN_COL_OFFSET
                + out_layout.col_is_mint();
        for j in 0..out_layout.n_inputs {
            let row_ind =
                crate::composition::tx_validity_composite::SKEL_OUT_OPEN_COL_OFFSET
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
        let is_coinbase_val = if options.is_coinbase { Block128::ONE } else { Block128::ZERO };
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
            fn degree(&self) -> usize { 2 }
            fn columns(&self) -> &[usize] { &self.cols }
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

        // Block C — HAddr × N_INPUTS + T1.
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let params = haddr_block_params_for(input, outer_n_cols);
            let wiring = emit_haddr_block(params);
            constraints.extend(wiring.constraints);
            public_columns.extend(wiring.public_columns);
        }

        // Block D — HAuth × N_INPUTS + T2a/T2b.
        for input in 0..FRI_STATE_OPEN_N_INPUTS {
            let t2a_override = options.t2a_dst_override.map(|arr| arr[input]);
            let t2b_override = options.t2b_dst_override.map(|arr| arr[input]);
            let params = hauth_block_params_for(
                input,
                outer_n_cols,
                tx_body_hash,
                t2a_override,
                t2b_override,
            );
            let wiring = emit_hauth_block(params);
            constraints.extend(wiring.constraints);
            public_columns.extend(wiring.public_columns);
        }

        // Pin per-input T2a destinations to declared auth tags —
        // skipped when the caller supplied a `t2a_dst_override` (PR
        // B.6: the override cell is expected to carry the correct
        // value via the spine's `TxValidityCol::AuthTagHi/Lo` cells).
        if options.t2a_dst_override.is_none() {
            for input in 0..FRI_STATE_OPEN_N_INPUTS {
                let (hi_col, lo_col) =
                    crate::composition::tx_validity_hauth::auth_tag_dst_cols(input);
                public_columns.push(PublicColumn::new(
                    hi_col,
                    pinned_row_programme(
                        auth_tag_hi_dst_row(input),
                        auth_tags[input][0],
                        outer_n_rows,
                    ),
                ));
                public_columns.push(PublicColumn::new(
                    lo_col,
                    pinned_row_programme(
                        auth_tag_lo_dst_row(input),
                        auth_tags[input][1],
                        outer_n_rows,
                    ),
                ));
            }
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
            tx_body_hash,
            auth_tags,
            t2a_dst_override: options.t2a_dst_override,
            t2b_dst_override: options.t2b_dst_override,
            output_side: options.output_side,
            output_side_eval_point,
            output_side_gamma,
            new_input_side: options.new_input_side,
            new_output_side: options.new_output_side,
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
            &self.secrets,
            self.tx_body_hash,
            TX_VALIDITY_LEAF_N_COLS,
            TX_VALIDITY_LEAF_LOG_ROWS,
            self.t2a_dst_override,
            self.t2b_dst_override,
            &self.output_side,
            self.output_side_eval_point,
            self.output_side_gamma,
            &self.new_input_side,
            &self.new_output_side,
        );

        // Final pass: overwrite every public column with its programme.
        for pc in self.air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }

        Trace::new(cols)
    }

    /// Decompose the composite into `(air, combiner, open_witness,
    /// open_public_columns, secrets, tx_body_hash, auth_tags)`. Used
    /// to embed a fully-built leaf composite inside
    /// [`super::tx_validity_with_spine::TxValidityCompositeWithSpine`]
    /// without re-instantiating its sub-AIRs.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        CompositeAir,
        FriStateCombinerComposite,
        FriStateOpenWitness,
        Vec<PublicColumn>,
        [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
        [Block128; 2],
        [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    ) {
        (
            self.air,
            self.combiner,
            self.open_witness,
            self.open_public_columns,
            self.secrets,
            self.tx_body_hash,
            self.auth_tags,
        )
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

/// Stitch the leaf-band sub-traces (combiner, open, haddr×N_INPUTS,
/// hauth×N_INPUTS) into `cols`. Caller pre-allocates `cols` with
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
    secrets: &[[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    tx_body_hash: [Block128; 2],
    outer_n_cols: usize,
    outer_log_rows: usize,
    t2a_dst_override: Option<[T2aDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
    t2b_dst_override: Option<[T2bDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
    output_side: &OutputSideSource,
    output_side_eval_point: [Block128; crate::airs::fri_state_open::FRI_STATE_OPEN_LOG_SLOTS],
    output_side_gamma: Block128,
    new_input_side: &NewStateInputSource,
    new_output_side: &NewStateOutputSource,
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

    // E.3.b — new-state input-side open columns.
    {
        let (air, witness) =
            crate::composition::tx_validity_composite::build_new_input_side_from_source(
                new_input_side,
                output_side_eval_point,
                output_side_gamma,
            );
        let (_, _, publics) = air.into_parts();
        crate::composition::tx_validity_composite::write_open_trace_at(
            cols,
            &witness,
            &publics,
            SKEL_NEW_IN_OPEN_COL_OFFSET,
        );
    }

    // E.3.b — new-state output-side open columns.
    {
        let (air, witness) =
            crate::composition::tx_validity_composite::build_new_output_side_from_source(
                new_output_side,
                output_side_eval_point,
                output_side_gamma,
            );
        let (_, _, publics) = air.into_parts();
        crate::composition::tx_validity_composite::write_open_trace_at(
            cols,
            &witness,
            &publics,
            SKEL_NEW_OUT_OPEN_COL_OFFSET,
        );
    }

    // HAddr blocks.
    for input in 0..FRI_STATE_OPEN_N_INPUTS {
        let params = haddr_block_params_for(input, outer_n_cols);
        let _ = write_haddr_block_trace(cols, params, secrets[input]);
    }

    // HAuth blocks.
    for input in 0..FRI_STATE_OPEN_N_INPUTS {
        let t2a_override = t2a_dst_override.map(|arr| arr[input]);
        let t2b_override = t2b_dst_override.map(|arr| arr[input]);
        let params = hauth_block_params_for(
            input,
            outer_n_cols,
            tx_body_hash,
            t2a_override,
            t2b_override,
        );
        let _ = write_hauth_block_trace(cols, params, secrets[input]);
    }
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
    use crate::composition::tx_validity_hauth::{native_address, native_auth_tag};

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
        let combiner = FriStateCombinerComposite::new(
            prev_preimage,
            prev_fields,
            new_preimage,
            new_fields,
        );

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

        TxValidityCompositeLeaf::new(
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
        // Combiner indicator is the last column *before* the two E.3.b
        // new-state opener bands.
        assert_eq!(SKEL_COMBINER_WINDOW_INDICATOR_COL, TX_VALIDITY_HAUTH_N_COLS);
        assert_eq!(SKEL_NEW_IN_OPEN_COL_OFFSET, TX_VALIDITY_HAUTH_N_COLS + 1);
        // E.4 appends two public columns at the end of the leaf band.
        assert_eq!(SKEL_IS_DEACTIVATION_COL, SKEL_NEW_OUT_OPEN_WINDOW_INDICATOR_COL + 1);
        assert_eq!(SKEL_IS_ACTIVATION_COL, SKEL_IS_DEACTIVATION_COL + 1);
        // E.5 appends the `is_coinbase` public column.
        assert_eq!(SKEL_IS_COINBASE_COL, SKEL_IS_ACTIVATION_COL + 1);
        assert_eq!(SKEL_IS_COINBASE_COL, TX_VALIDITY_LEAF_N_COLS - 1);
        assert_eq!(TX_VALIDITY_LEAF_LOG_ROWS, 13);
        assert!(TX_VALIDITY_LEAF_LOG_ROWS >= COMBINER_COMPOSITE_LOG_ROWS);
    }

    #[test]
    fn honest_trace_accepts() {
        let comp = build();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
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

    #[test]
    fn t2a_still_active_auth_tag_tamper_rejects() {
        // T2a ties must still fire.
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (hi_col, _) = crate::composition::tx_validity_hauth::auth_tag_dst_cols(1);
        cols[hi_col][auth_tag_hi_dst_row(1)] =
            cols[hi_col][auth_tag_hi_dst_row(1)] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    // ---- E.3.b: new-state opener blocks ---------------------------------

    /// Build a leaf with the prev-state witness from [`build`] plus
    /// body-derived new-state input / output sources (2 live inputs,
    /// 2 live outputs). Uses fresh combiner preimages so
    /// `build_trace` is re-derived from scratch.
    fn build_with_new_state_body() -> TxValidityCompositeLeaf {
        use noid_poseidon2b::primitives::Address;
        use noid_tx::{TxInput, TxOutput};
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
        let combiner = FriStateCombinerComposite::new(
            prev_preimage, prev_fields, new_preimage, new_fields,
        );

        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            mk_secret(11), mk_secret(22), mk_secret(33), mk_secret(44),
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

        // Body-derived new-state sources. Inputs/outputs are contrived
        // — the E.3.b bridges pin `slot_index` bits per row; the AIR
        // itself re-executes against `new_state_root` lane openings of
        // all zeros (the builders accept arbitrary `new_lane_openings`
        // and compute honest terminuses against them).
        let new_inputs = vec![
            TxInput { slot_index: 0, valid: true, ..TxInput::dummy() },
            TxInput { slot_index: 3, valid: true, ..TxInput::dummy() },
        ];
        let new_outputs = vec![
            TxOutput { slot_index: 5, value: 7, owner: Address([0x33u8; 32]), valid: true },
            TxOutput { slot_index: 9, value: 11, owner: Address([0x44u8; 32]), valid: true },
        ];

        TxValidityCompositeLeaf::new_with_options(
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
            LeafConstructionOptions {
                new_input_side: NewStateInputSource::FromBody {
                    inputs: new_inputs,
                    new_lane_openings: [Block128::ZERO; 3],
                },
                new_output_side: NewStateOutputSource::FromBody {
                    outputs: new_outputs,
                    new_lane_openings: [Block128::ZERO; 3],
                },
                ..LeafConstructionOptions::default()
            },
        )
    }

    #[test]
    fn e3b_honest_new_state_body_derived_accepts() {
        let comp = build_with_new_state_body();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
    }

    #[test]
    fn e3b_new_in_slot_index_bit_tamper_rejects() {
        use crate::airs::fri_state_open::FriStateOpenLayout;
        let layout = FriStateOpenLayout::DEFAULT;
        let comp = build_with_new_state_body();
        let base_trace = comp.build_trace();
        for row in 0..2 {
            for k in 0..layout.log_slots {
                let mut cols = base_trace.columns.clone();
                let col = SKEL_NEW_IN_OPEN_COL_OFFSET + layout.col_idx_bit(k);
                cols[col][row] = cols[col][row] + Block128::ONE;
                assert!(
                    !comp.air().check(&Trace::new(cols)),
                    "E.3.b: new-in slot_index bit ({row}, {k}) tamper must REJECT",
                );
            }
        }
    }

    #[test]
    fn e3b_new_out_slot_index_bit_tamper_rejects() {
        let layout = FRI_STATE_OPEN_OUTPUT_LAYOUT;
        let comp = build_with_new_state_body();
        let base_trace = comp.build_trace();
        for row in 0..2 {
            for k in 0..layout.log_slots {
                let mut cols = base_trace.columns.clone();
                let col = SKEL_NEW_OUT_OPEN_COL_OFFSET + layout.col_idx_bit(k);
                cols[col][row] = cols[col][row] + Block128::ONE;
                assert!(
                    !comp.air().check(&Trace::new(cols)),
                    "E.3.b: new-out slot_index bit ({row}, {k}) tamper must REJECT",
                );
            }
        }
    }

    #[test]
    fn e3b_new_out_value_tamper_rejects() {
        use crate::airs::fri_state_open::COL_VALUE;
        let comp = build_with_new_state_body();
        let mut cols = comp.build_trace().columns;
        let col = SKEL_NEW_OUT_OPEN_COL_OFFSET + COL_VALUE;
        // Row 0 is a live-mint row carrying value=7.
        cols[col][0] = cols[col][0] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn e3b_empty_default_still_accepts() {
        // All-EMPTY new-state sources (the WithSpine path) must not
        // break the honest-trace check.
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
        let combiner = FriStateCombinerComposite::new(
            prev_preimage, prev_fields, new_preimage, new_fields,
        );

        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            mk_secret(11), mk_secret(22), mk_secret(33), mk_secret(44),
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
        let outputs = vec![
            TxOutput { slot_index: 5, value: 7, owner: Address([0x33u8; 32]), valid: true },
            TxOutput { slot_index: 9, value: 11, owner: Address([0x44u8; 32]), valid: true },
        ];
        TxValidityCompositeLeaf::new_with_options(
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
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
            cols[SKEL_IS_DEACTIVATION_COL][row] =
                cols[SKEL_IS_DEACTIVATION_COL][row] + Block128::ONE;
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
            cols[SKEL_IS_ACTIVATION_COL][row] =
                cols[SKEL_IS_ACTIVATION_COL][row] + Block128::ONE;
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
        let combiner = FriStateCombinerComposite::new(
            prev_preimage, prev_fields, new_preimage, new_fields,
        );

        let secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            mk_secret(11), mk_secret(22), mk_secret(33), mk_secret(44),
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
            secrets,
            tx_body_hash,
            auth_tags,
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
            cols[SKEL_IS_COINBASE_COL][row] =
                cols[SKEL_IS_COINBASE_COL][row] + Block128::ONE;
            assert!(
                !comp.air().check(&Trace::new(cols)),
                "E.5: is_coinbase row {row} tamper must REJECT",
            );
        }
    }
}
