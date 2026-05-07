// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.6 — [`TxValidityCompositeLeaf`].
//!
//! Extends the 5.5 [`super::tx_validity_hauth::TxValidityCompositeHAuth`]
//! with `N_OUTPUTS` `HLeafAir` instances, one per tx output. Each HLeaf
//! block is embedded via [`super::hleaf_block`] and wired through one
//! bridge family:
//!
//! - **T3** — per-output leaf-hash tie. The squeezed
//!   `(leaf_hi, leaf_lo) = s_C[0..2]@HLEAF_OUTPUT_ROW` is bridged to a
//!   pair of outer destination cells (one pair per output) carrying the
//!   declared output leaf hash. The destinations are pinned as
//!   `PublicColumn` programmes, so the overall contract is
//!   `HLeaf.squeeze[j] == declared_leaf_hash[j]` with the bridge
//!   mediating the cross-row equality. Stage 5.7 re-points the
//!   destinations at `TxBodyMerkleAir`'s E.4.c rate-absorb payload
//!   columns inside the embedded `TxBodySpineComposite`; the bridge
//!   contract is unchanged. This closes audit §1 / §6.1 — at 5.6 the
//!   bind is to declared leaf hashes; at 5.7 it is to the Merkle
//!   absorbed payload.
//!
//! # Layout (on top of 5.5)
//!
//! All new columns append to the right of the 5.5 composite:
//!
//! ```text
//!   [0, TX_VALIDITY_HAUTH_N_COLS)              — inherited from 5.5
//!   [LEAF_BLOCKS_BASE, +N_OUTPUTS·HLEAF_BLOCK_OUTER_COLS)  — HLeaf blocks
//!   [LEAF_HASH_DST_BASE, +2·N_OUTPUTS)         — per-output T3 dsts
//! ```
//!
//! Each HLeaf block's 2 lane bridges carry 4 outer cols each (bridge +
//! 3 indicators); the block width is
//! `HLEAF_N_COLS + 1 (window) + 2·4 (bridges) = HLEAF_N_COLS + 9`.
//!
//! Outer log-rows: 13 (Stage 5.7 PR B.2 lift). Combiner is wrapped
//! via [`RowWindowWrapper`] under `MaskOff`; HLeaf / HAuth / HAddr /
//! FriStateOpen retain their existing `MaskOff` wrappers. Cells
//! outside each sub-AIR's window are zero-padded.

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
use crate::airs::hleaf::{HLEAF_LOG_ROWS, HLEAF_N_COLS};
use crate::composition::haddr_block::{
    emit_haddr_block, write_haddr_block_trace, HAddrBlockColumns, HAddrBlockParams,
    HAddrBlockT1Targets,
};
use crate::composition::hauth_block::{
    emit_hauth_block, write_hauth_block_trace, HAuthBlockColumns, HAuthBlockParams,
    HAuthBlockTargets,
};
use crate::composition::hleaf_block::{
    emit_hleaf_block, write_hleaf_block_trace, HLeafBlockColumns, HLeafBlockParams,
    HLeafBlockTargets,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWrapper, WrapPolicy,
};
use crate::composition::t1_owner_tie::{LaneBridgeBudget, T1LaneColumnBudget};
use crate::composition::tx_validity_composite::{
    SKEL_COMBINER_COL_OFFSET, SKEL_OPEN_COL_OFFSET, SKEL_OPEN_WINDOW_INDICATOR_COL,
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

/// Stage 5.6 output count. Matches the roadmap target `N_OUTPUTS = 8`.
pub const N_OUTPUTS: usize = 8;

/// Outer log-rows. Stage 5.7 PR B.2 lifts from
/// `TX_VALIDITY_HAUTH_LOG_ROWS = 9` to `13` so the leaf composite can
/// be embedded inside `TxValidityCompositeWithSpine` (fixed at
/// `SPINE_LOG_ROWS = 13`) without an outer-row-count mismatch. Every
/// embedded sub-AIR is wrapped under [`WrapPolicy::MaskOff`] (combiner
/// via [`RowWindowWrapper`], open / haddr / hauth / hleaf via the
/// existing block helpers) so its constraints stay scoped to its
/// original window. Trace cells outside the windows are zero-padded.
pub const TX_VALIDITY_LEAF_LOG_ROWS: usize = 13;

/// Compile-time height sanity.
const _: () = {
    assert!(HAUTH_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(HADDR_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(HLEAF_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(FRI_STATE_OPEN_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(COMBINER_COMPOSITE_LOG_ROWS <= TX_VALIDITY_LEAF_LOG_ROWS);
    assert!(FRI_STATE_COMBINER_LOG_ROWS == COMBINER_COMPOSITE_LOG_ROWS);
};

/// Per-HLeaf-block extra outer columns: sub-AIR + window indicator +
/// 2 lane bridges × 4 cols each.
pub const HLEAF_BLOCK_OUTER_COLS: usize = HLEAF_N_COLS + 1 + 8;

/// Outer col offset of the first HLeaf block (right after the 5.5
/// column band).
pub const LEAF_BLOCKS_BASE: usize = TX_VALIDITY_HAUTH_N_COLS;

/// Per-output T3 destination column base. Each output reserves two
/// columns (leaf_hi, leaf_lo). Destinations are pinned via
/// `PublicColumn` programmes carrying the declared output leaf hash.
pub const LEAF_HASH_DST_BASE: usize =
    LEAF_BLOCKS_BASE + N_OUTPUTS * HLEAF_BLOCK_OUTER_COLS;

/// Per-output T3 destination band end. The combiner window indicator
/// (added by Stage 5.7 PR B.2) sits past it.
const LEAF_HASH_DST_BAND_END: usize = LEAF_HASH_DST_BASE + 2 * N_OUTPUTS;

/// Outer column reserved for the combiner block's window indicator.
/// Stage 5.7 PR B.2 wraps the combiner via [`RowWindowWrapper`] under
/// `WrapPolicy::MaskOff` so its row-9-scoped constraints are silenced
/// past row `2^COMBINER_COMPOSITE_LOG_ROWS = 512` on the lifted
/// 8192-row outer trace.
pub const SKEL_COMBINER_WINDOW_INDICATOR_COL: usize = LEAF_HASH_DST_BAND_END;

/// Total outer column count.
pub const TX_VALIDITY_LEAF_N_COLS: usize = SKEL_COMBINER_WINDOW_INDICATOR_COL + 1;

/// Per-output HLeaf block column base.
pub const fn leaf_block_base(output: usize) -> usize {
    LEAF_BLOCKS_BASE + output * HLEAF_BLOCK_OUTER_COLS
}

/// Per-output leaf-hash dst columns `(hi, lo)`.
pub const fn leaf_hash_dst_cols(output: usize) -> (usize, usize) {
    let base = LEAF_HASH_DST_BASE + 2 * output;
    (base, base + 1)
}

// HLeaf block internal sub-layout (relative to its base):
const REL_HLEAF_SUBAIR_COL: usize = 0;
const REL_HLEAF_WINDOW_INDICATOR_COL: usize = HLEAF_N_COLS;
const REL_T3_HI_BRIDGE: usize = HLEAF_N_COLS + 1;
const REL_T3_HI_SRC: usize = HLEAF_N_COLS + 2;
const REL_T3_HI_DST_IND: usize = HLEAF_N_COLS + 3;
const REL_T3_HI_TRANS: usize = HLEAF_N_COLS + 4;
const REL_T3_LO_BRIDGE: usize = HLEAF_N_COLS + 5;
const REL_T3_LO_SRC: usize = HLEAF_N_COLS + 6;
const REL_T3_LO_DST_IND: usize = HLEAF_N_COLS + 7;
const REL_T3_LO_TRANS: usize = HLEAF_N_COLS + 8;

// Per-output leaf dst rows. Each block gets its own row per lane,
// distinct from the HLeaf window [0, HLEAF_N_ROWS).
const fn leaf_hi_dst_row(output: usize) -> usize {
    crate::airs::hleaf::HLEAF_N_ROWS + 2 + 4 * output
}
const fn leaf_lo_dst_row(output: usize) -> usize {
    crate::airs::hleaf::HLEAF_N_ROWS + 4 + 4 * output
}

/// Per-output T3 dst override. When supplied via
/// [`LeafConstructionOptions::t3_dst_override`] the HLeaf block's
/// hi/lo bridge dst cells are routed at these `(col, row)` pairs
/// instead of the canonical `leaf_hash_dst_cols / leaf_*_dst_row`,
/// AND the per-output `PublicColumn` programme that pins the dst to
/// the declared leaf hash is **omitted**. Used by Stage 5.7 PR B.4 to
/// retarget T3 dsts at spine `OutputLeafPermA` rate-payload cells.
#[derive(Debug, Clone, Copy)]
pub struct T3DstOverride {
    pub hi_col: usize,
    pub hi_row: usize,
    pub lo_col: usize,
    pub lo_row: usize,
}

/// Per-input T2a dst override. When supplied via
/// [`LeafConstructionOptions::t2a_dst_override`] the HAuth block's
/// hi/lo auth-tag bridge dst cells are routed at these `(col, row)`
/// pairs instead of the canonical `auth_tag_dst_cols /
/// auth_tag_*_dst_row`, AND the per-input `PublicColumn` programme
/// that pins the dst to the declared auth tag is **omitted**. Used
/// by Stage 5.7 PR B.6 to retarget T2a dsts at spine
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
/// `pre_s_b_dst_cols / pre_s_b_*_dst_row`. The 5.5/5.6 leaf composite
/// emits no `PublicColumn` programmes for T2b dsts (they are unpinned
/// — see `tx_validity_hauth.rs:427`), so unlike T2a/T3 the override
/// only re-routes the bridge dst cells. Used by Stage 5.7 PR B.7 to
/// point all per-input T2b dsts at the spine's single canonical
/// wrap-output cell carrying `tx_body_hash`.
#[derive(Debug, Clone, Copy)]
pub struct T2bDstOverride {
    pub hi_col: usize,
    pub hi_row: usize,
    pub lo_col: usize,
    pub lo_row: usize,
}

/// Optional construction-time tweaks for [`TxValidityCompositeLeaf`].
/// `Default` reproduces 5.6 behavior bit-identically.
#[derive(Debug, Clone, Default)]
pub struct LeafConstructionOptions {
    /// When `Some`, override every HLeaf block's bridge dst cells and
    /// skip the T3 PI-pin emission. Caller must guarantee each
    /// override cell lies inside the outer composite and (in honest
    /// traces) carries the corresponding leaf hash.
    pub t3_dst_override: Option<[T3DstOverride; N_OUTPUTS]>,
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
}

fn hleaf_block_params_for(
    output: usize,
    outer_n_cols: usize,
    fields: [Block128; 4],
    override_cell: Option<T3DstOverride>,
) -> HLeafBlockParams {
    let base = leaf_block_base(output);
    let (default_hi_col, default_lo_col) = leaf_hash_dst_cols(output);
    let (hi_col, hi_row, lo_col, lo_row) = match override_cell {
        Some(o) => (o.hi_col, o.hi_row, o.lo_col, o.lo_row),
        None => (
            default_hi_col,
            leaf_hi_dst_row(output),
            default_lo_col,
            leaf_lo_dst_row(output),
        ),
    };
    HLeafBlockParams {
        cols: HLeafBlockColumns {
            col_offset: base + REL_HLEAF_SUBAIR_COL,
            window_indicator_col: base + REL_HLEAF_WINDOW_INDICATOR_COL,
            t3_hi_budget: LaneBridgeBudget {
                bridge_col: base + REL_T3_HI_BRIDGE,
                src_indicator_col: base + REL_T3_HI_SRC,
                dst_indicator_col: base + REL_T3_HI_DST_IND,
                transition_indicator_col: base + REL_T3_HI_TRANS,
            },
            t3_lo_budget: LaneBridgeBudget {
                bridge_col: base + REL_T3_LO_BRIDGE,
                src_indicator_col: base + REL_T3_LO_SRC,
                dst_indicator_col: base + REL_T3_LO_DST_IND,
                transition_indicator_col: base + REL_T3_LO_TRANS,
            },
        },
        row_window_start: 0,
        outer_n_cols,
        outer_log_rows: TX_VALIDITY_LEAF_LOG_ROWS,
        fields,
        targets: HLeafBlockTargets {
            leaf_hi_dst_col: hi_col,
            leaf_hi_dst_row: hi_row,
            leaf_lo_dst_col: lo_col,
            leaf_lo_dst_row: lo_row,
        },
    }
}

// ---------------------------------------------------------------------------
// 5.5 wiring helpers (mirrored — inputs unchanged)
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

/// Stage 5.6 composite: combiner + FriStateOpen + N_INPUTS × HAddr (T1)
/// + N_INPUTS × HAuth (T2a per-input + T2b per-input) + N_OUTPUTS ×
/// HLeaf (T3 per-output).
pub struct TxValidityCompositeLeaf {
    pub air: CompositeAir,
    combiner: FriStateCombinerComposite,
    open_witness: FriStateOpenWitness,
    open_public_columns: Vec<PublicColumn>,
    secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    tx_body_hash: [Block128; 2],
    auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    /// Per-output public field tuples `[slot, value, owner_hi, owner_lo]`.
    output_fields: [[Block128; 4]; N_OUTPUTS],
    /// Per-output declared leaf hash `(hi, lo)`. Pinned on per-output T3
    /// destinations.
    output_leaf_hashes: [[Block128; 2]; N_OUTPUTS],
    /// Optional per-output T3 dst override (PR B.4). When `Some`, the
    /// HLeaf bridge dst cells are routed at these `(col, row)` pairs
    /// and the T3 PI-pin loop is skipped at construction.
    t3_dst_override: Option<[T3DstOverride; N_OUTPUTS]>,
    /// Optional per-input T2a dst override (PR B.6). When `Some`, the
    /// HAuth bridge dst cells are routed at these `(col, row)` pairs
    /// and the T2a PI-pin loop is skipped at construction.
    t2a_dst_override: Option<[T2aDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
    /// Optional per-input T2b (`pre_s_b == tx_body_hash`) dst override
    /// (PR B.7). When `Some`, the HAuth `pre_s_b` bridge dst cells are
    /// routed at these `(col, row)` pairs.
    t2b_dst_override: Option<[T2bDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
}

impl TxValidityCompositeLeaf {
    pub fn new(
        combiner: FriStateCombinerComposite,
        open_air: FriStateOpenAir,
        open_witness: FriStateOpenWitness,
        secrets: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
        tx_body_hash: [Block128; 2],
        auth_tags: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
        output_fields: [[Block128; 4]; N_OUTPUTS],
        output_leaf_hashes: [[Block128; 2]; N_OUTPUTS],
    ) -> Self {
        Self::new_with_options(
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
            output_fields,
            output_leaf_hashes,
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
        output_fields: [[Block128; 4]; N_OUTPUTS],
        output_leaf_hashes: [[Block128; 2]; N_OUTPUTS],
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

        // Block E — HLeaf × N_OUTPUTS + T3.
        for output in 0..N_OUTPUTS {
            let override_cell = options.t3_dst_override.map(|arr| arr[output]);
            let params = hleaf_block_params_for(
                output,
                outer_n_cols,
                output_fields[output],
                override_cell,
            );
            let wiring = emit_hleaf_block(params);
            constraints.extend(wiring.constraints);
            public_columns.extend(wiring.public_columns);
        }

        // Pin per-output T3 destinations to declared leaf hashes —
        // skipped when the caller supplied a `t3_dst_override` (the
        // override cell is expected to carry the correct value via
        // some other mechanism, typically the spine's
        // `OutputLeafPermA` absorb chain).
        if options.t3_dst_override.is_none() {
            for output in 0..N_OUTPUTS {
                let (hi_col, lo_col) = leaf_hash_dst_cols(output);
                public_columns.push(PublicColumn::new(
                    hi_col,
                    pinned_row_programme(
                        leaf_hi_dst_row(output),
                        output_leaf_hashes[output][0],
                        outer_n_rows,
                    ),
                ));
                public_columns.push(PublicColumn::new(
                    lo_col,
                    pinned_row_programme(
                        leaf_lo_dst_row(output),
                        output_leaf_hashes[output][1],
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
            output_fields,
            output_leaf_hashes,
            t3_dst_override: options.t3_dst_override,
            t2a_dst_override: options.t2a_dst_override,
            t2b_dst_override: options.t2b_dst_override,
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
            &self.output_fields,
            TX_VALIDITY_LEAF_N_COLS,
            TX_VALIDITY_LEAF_LOG_ROWS,
            self.t3_dst_override,
            self.t2a_dst_override,
            self.t2b_dst_override,
        );

        // Final pass: overwrite every public column with its programme.
        for pc in self.air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }

        Trace::new(cols)
    }

    /// Decompose the composite into `(air, combiner, open_witness,
    /// open_public_columns, secrets, tx_body_hash, auth_tags,
    /// output_fields, output_leaf_hashes)`. Used by Stage 5.7 PR B.3
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
        [[Block128; 4]; N_OUTPUTS],
        [[Block128; 2]; N_OUTPUTS],
    ) {
        (
            self.air,
            self.combiner,
            self.open_witness,
            self.open_public_columns,
            self.secrets,
            self.tx_body_hash,
            self.auth_tags,
            self.output_fields,
            self.output_leaf_hashes,
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

    pub fn output_fields(&self) -> &[[Block128; 4]; N_OUTPUTS] {
        &self.output_fields
    }

    pub fn output_leaf_hashes(&self) -> &[[Block128; 2]; N_OUTPUTS] {
        &self.output_leaf_hashes
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
/// hauth×N_INPUTS, hleaf×N_OUTPUTS) into `cols`. Caller pre-allocates
/// `cols` with `outer_n_cols >= TX_VALIDITY_LEAF_N_COLS` columns and
/// `2^outer_log_rows` rows. Public-column overwrites are NOT performed
/// here — caller does the final pass against its own composite air.
///
/// Stage 5.7 PR B.3 calls this from
/// [`super::tx_validity_with_spine::TxValidityCompositeWithSpine::build_trace`]
/// to populate the embedded leaf-band before the spine block.
#[allow(clippy::too_many_arguments)]
pub fn write_leaf_block_traces(
    cols: &mut [Vec<Block128>],
    combiner: &FriStateCombinerComposite,
    open_witness: &FriStateOpenWitness,
    open_public_columns: &[PublicColumn],
    secrets: &[[Block128; 2]; FRI_STATE_OPEN_N_INPUTS],
    tx_body_hash: [Block128; 2],
    output_fields: &[[Block128; 4]; N_OUTPUTS],
    outer_n_cols: usize,
    outer_log_rows: usize,
    t3_dst_override: Option<[T3DstOverride; N_OUTPUTS]>,
    t2a_dst_override: Option<[T2aDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
    t2b_dst_override: Option<[T2bDstOverride; FRI_STATE_OPEN_N_INPUTS]>,
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

    // HLeaf blocks.
    for output in 0..N_OUTPUTS {
        let override_cell = t3_dst_override.map(|arr| arr[output]);
        let params = hleaf_block_params_for(
            output,
            outer_n_cols,
            output_fields[output],
            override_cell,
        );
        let _ = write_hleaf_block_trace(cols, params);
    }
}

/// Native leaf-hash computation for a given `[slot, value, owner_hi, owner_lo]`.
pub fn native_output_leaf_hash(fields: [Block128; 4]) -> [Block128; 2] {
    use crate::airs::hleaf::{build_hleaf_trace, extract_hleaf_output};
    extract_hleaf_output(&build_hleaf_trace(fields))
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
    use crate::airs::hleaf::{HLEAF_LAYOUT_C, HLEAF_OUTPUT_ROW};
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

    fn mk_output_fields(seed: u128) -> [Block128; 4] {
        let s = seed.wrapping_mul(0xD6E8FEB86659FD93);
        [
            Block128::from(s ^ 0x1111_1111_1111_1111),
            Block128::from(s.wrapping_add(1) ^ 0x2222_2222_2222_2222),
            Block128::from(s.wrapping_add(2) ^ 0x3333_3333_3333_3333),
            Block128::from(s.wrapping_add(3) ^ 0x4444_4444_4444_4444),
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

        let mut output_fields: [[Block128; 4]; N_OUTPUTS] = [[Block128::ZERO; 4]; N_OUTPUTS];
        let mut output_leaf_hashes: [[Block128; 2]; N_OUTPUTS] = [[Block128::ZERO; 2]; N_OUTPUTS];
        for j in 0..N_OUTPUTS {
            output_fields[j] = mk_output_fields(0x100u128 + j as u128);
            output_leaf_hashes[j] = native_output_leaf_hash(output_fields[j]);
        }

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
            output_fields,
            output_leaf_hashes,
        )
    }

    #[test]
    fn layout_constants_agree() {
        assert_eq!(
            TX_VALIDITY_LEAF_N_COLS,
            TX_VALIDITY_HAUTH_N_COLS
                + N_OUTPUTS * HLEAF_BLOCK_OUTER_COLS
                + 2 * N_OUTPUTS
                + 1
        );
        assert_eq!(
            SKEL_COMBINER_WINDOW_INDICATOR_COL,
            TX_VALIDITY_LEAF_N_COLS - 1
        );
        assert_eq!(HLEAF_BLOCK_OUTER_COLS, HLEAF_N_COLS + 9);
        assert_eq!(TX_VALIDITY_LEAF_LOG_ROWS, 13);
        assert!(TX_VALIDITY_LEAF_LOG_ROWS >= COMBINER_COMPOSITE_LOG_ROWS);
        assert_eq!(N_OUTPUTS, 8);
    }

    #[test]
    fn honest_trace_accepts() {
        let comp = build();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
    }

    #[test]
    fn hleaf_squeeze_matches_declared_hash_per_output() {
        let comp = build();
        let cols = comp.build_trace().columns;
        for output in 0..N_OUTPUTS {
            let base = leaf_block_base(output);
            let hi_col = base + HLEAF_LAYOUT_C.s;
            let lo_col = base + HLEAF_LAYOUT_C.s + 1;
            assert_eq!(
                cols[hi_col][HLEAF_OUTPUT_ROW],
                comp.output_leaf_hashes()[output][0]
            );
            assert_eq!(
                cols[lo_col][HLEAF_OUTPUT_ROW],
                comp.output_leaf_hashes()[output][1]
            );
        }
    }

    #[test]
    fn t3_hi_declared_hash_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (hi_col, _) = leaf_hash_dst_cols(0);
        let row = leaf_hi_dst_row(0);
        cols[hi_col][row] = cols[hi_col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t3_lo_declared_hash_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (_, lo_col) = leaf_hash_dst_cols(5);
        let row = leaf_lo_dst_row(5);
        cols[lo_col][row] = cols[lo_col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_interior_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let base = leaf_block_base(2);
        use crate::airs::hleaf::HLEAF_LAYOUT_A;
        let col = base + HLEAF_LAYOUT_A.sout + 2;
        cols[col][5] = cols[col][5] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_squeeze_cell_tamper_rejects() {
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let base = leaf_block_base(4);
        let col = base + HLEAF_LAYOUT_C.s;
        cols[col][HLEAF_OUTPUT_ROW] = cols[col][HLEAF_OUTPUT_ROW] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn per_output_t3_dsts_are_disjoint() {
        use std::collections::HashSet;
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        for output in 0..N_OUTPUTS {
            let (hi_col, lo_col) = leaf_hash_dst_cols(output);
            assert!(seen.insert((hi_col, leaf_hi_dst_row(output))));
            assert!(seen.insert((lo_col, leaf_lo_dst_row(output))));
        }
    }

    /// Build a leaf composite with `t3_dst_override = Some(...)` whose
    /// cells coincide with the canonical default T3 dsts. Skips the
    /// T3 PI-pin emission. Used by PR B.4 unit tests to validate the
    /// override hook end-to-end without coupling to a spine.
    fn build_with_default_override() -> TxValidityCompositeLeaf {
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
            mk_secret(11), mk_secret(22), mk_secret(33), mk_secret(44),
        ];
        let addrs: [[Block128; 2]; FRI_STATE_OPEN_N_INPUTS] = [
            native_address(secrets[0]), native_address(secrets[1]),
            native_address(secrets[2]), native_address(secrets[3]),
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
        let mut output_fields: [[Block128; 4]; N_OUTPUTS] = [[Block128::ZERO; 4]; N_OUTPUTS];
        let mut output_leaf_hashes: [[Block128; 2]; N_OUTPUTS] =
            [[Block128::ZERO; 2]; N_OUTPUTS];
        for j in 0..N_OUTPUTS {
            output_fields[j] = mk_output_fields(0x100u128 + j as u128);
            output_leaf_hashes[j] = native_output_leaf_hash(output_fields[j]);
        }
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

        let mut t3 = [T3DstOverride { hi_col: 0, hi_row: 0, lo_col: 0, lo_row: 0 }; N_OUTPUTS];
        for j in 0..N_OUTPUTS {
            let (hi_col, lo_col) = leaf_hash_dst_cols(j);
            t3[j] = T3DstOverride {
                hi_col,
                hi_row: leaf_hi_dst_row(j),
                lo_col,
                lo_row: leaf_lo_dst_row(j),
            };
        }

        TxValidityCompositeLeaf::new_with_options(
            combiner,
            open_air,
            open_witness,
            secrets,
            tx_body_hash,
            auth_tags,
            output_fields,
            output_leaf_hashes,
            LeafConstructionOptions {
                t3_dst_override: Some(t3),
                t2a_dst_override: None,
                t2b_dst_override: None,
            },
        )
    }

    #[test]
    fn override_with_default_cells_accepts_honest() {
        let comp = build_with_default_override();
        let trace = comp.build_trace();
        assert!(comp.air().check(&trace));
    }

    #[test]
    fn override_t3_dst_tamper_rejects_via_bridge() {
        // With the override path the per-output T3 PI-pin is omitted —
        // tampering the dst cell breaks the bridge `cell == squeeze`
        // tie (no longer the PI programme), but still rejects.
        let comp = build_with_default_override();
        let mut cols = comp.build_trace().columns;
        let (hi_col, _) = leaf_hash_dst_cols(3);
        let row = leaf_hi_dst_row(3);
        cols[hi_col][row] = cols[hi_col][row] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t1_still_active_owner_tamper_rejects() {
        // Stage 5.4 T1 ties must still fire in the 5.6 composite.
        let comp = build();
        let mut cols = comp.build_trace().columns;
        cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][0] =
            cols[SKEL_OPEN_COL_OFFSET + COL_OWNER_HI][0] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }

    #[test]
    fn t2a_still_active_auth_tag_tamper_rejects() {
        // Stage 5.5 T2a ties must still fire in the 5.6 composite.
        let comp = build();
        let mut cols = comp.build_trace().columns;
        let (hi_col, _) = crate::composition::tx_validity_hauth::auth_tag_dst_cols(1);
        cols[hi_col][auth_tag_hi_dst_row(1)] =
            cols[hi_col][auth_tag_hi_dst_row(1)] + Block128::ONE;
        assert!(!comp.air().check(&Trace::new(cols)));
    }
}
