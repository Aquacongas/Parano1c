// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Column-layout registries for sub-AIRs participating in the Stage 5
//! [`TxValidityComposite`]. Each registry is a typed facade over
//! existing `pub const` column offsets — no layout changes, just a
//! stable API surface for bridge destinations and composite adapters.
//!
//! The registries exist so that Stage 5 wiring (bridges, row windows,
//! cross-AIR equality ties) can address specific `(col, row)` cells
//! without hard-coding offsets at the call site. If a sub-AIR later
//! reshuffles its columns, only its registry accessor changes.

pub mod bridge;
pub mod placement;
pub mod shared_haddr_block;
pub mod shared_hauth_block;
pub mod registry;
pub mod row_window;
pub mod spine_adapter;
pub mod t1_owner_tie;
pub mod tx_validity_composite;
pub mod tx_validity_full;
pub mod tx_validity_hauth;
pub mod tx_validity_leaf;
pub mod tx_validity_with_spine;

pub use bridge::{
    emit_cross_row_eq, write_bridge_column, BridgeHold, BridgeParams, BridgeWiring,
};
pub use placement::{validate_placements, CompositePlacement, PlacementError};
pub use registry::{
    CombinerCompositeCols, FriStateOpenCols, HAddrCols, HAuthCols,
    TxBodyMerkleCols, TxValidityCols,
};
pub use spine_adapter::{SpineEmbeddingLayout, SpineLayoutError};
pub use row_window::{
    InnerAirView, RowWindowParams, RowWindowWiring, RowWindowWrapper, TerminatorPinCols,
    WrapPolicy,
};
pub use t1_owner_tie::{
    emit_t1_input, emit_t1_lane, write_t1_lane_bridge, LaneBridgeBudget, LaneBridgeTie,
    T1InputWiring, T1LaneColumnBudget, T1LaneTie,
};
pub use shared_haddr_block::{
    emit_shared_haddr_block, shared_haddr_outer_overhead_cols, write_shared_haddr_block_trace,
    SharedHAddrBlockParams, SharedHAddrBlockWiring, SharedHAddrInputBudget,
    SharedHAddrInputTargets,
};
pub use shared_hauth_block::{
    emit_shared_hauth_block, shared_hauth_outer_overhead_cols, write_shared_hauth_block_trace,
    InputCells as SharedHAuthInputWiringCells, SharedHAuthBlockParams, SharedHAuthBlockWiring,
    SharedHAuthInputBudget, SharedHAuthInputCells, SharedHAuthInputTargets,
    SharedHAuthTxBodyBinding, TxBodyCells as SharedHAuthTxBodyCells,
};
pub use tx_validity_full::{
    emit_full_shared_haddr, full_haddr_squeeze_hi_col, full_haddr_squeeze_lo_col,
    full_haddr_squeeze_row, full_haddr_t1_bases, write_full_shared_haddr_trace,
    TxValidityCompositeFull, FULL_HADDR_BLOCKS_BASE, FULL_HADDR_T1_BASE,
    FULL_HADDR_WINDOW_INDICATOR_COL, SHARED_HADDR_MULTI_LOG_ROWS, SHARED_HADDR_MULTI_N_COLS,
    SHARED_HADDR_OUTER_COLS, TX_VALIDITY_FULL_LOG_ROWS, TX_VALIDITY_FULL_N_COLS,
};
pub use tx_validity_hauth::{
    auth_tag_dst_cols, auth_tag_hi_dst_row, auth_tag_lo_dst_row, emit_full_shared_hauth,
    full_hauth_squeeze_hi_col, full_hauth_squeeze_lo_col, full_hauth_squeeze_row,
    full_hauth_t2a_bases, full_hauth_t2b_bases, full_hauth_tx_body_hi_col,
    full_hauth_tx_body_lo_col, native_address, native_auth_tag, tx_body_dst_cols,
    tx_body_hi_dst_row, tx_body_lo_dst_row, write_full_shared_hauth_trace,
    FullSharedHAuthOptions, T2aDstOverride, T2bDstOverride, TxValidityCompositeHAuth,
    AUTH_TAG_DST_BASE, FULL_HAUTH_BLOCK_BASE, FULL_HAUTH_T2A_BASE, FULL_HAUTH_T2B_BASE,
    FULL_HAUTH_WINDOW_INDICATOR_COL, SHARED_HAUTH_MULTI_LOG_ROWS,
    SHARED_HAUTH_MULTI_N_COLS, SHARED_HAUTH_OUTER_COLS, TX_BODY_DST_BASE,
    TX_VALIDITY_HAUTH_LOG_ROWS, TX_VALIDITY_HAUTH_N_COLS,
};
pub use tx_validity_leaf::{
    TxValidityCompositeLeaf, TX_VALIDITY_LEAF_LOG_ROWS, TX_VALIDITY_LEAF_N_COLS,
};
pub use tx_validity_with_spine::{
    build_stage_5_7_honest_fixture, coinbase_credit_bit_col, tx_validity_with_spine_n_cols,
    TxValidityCompositeWithSpine, WithSpineOptions, LEAF_BAND_RESERVED, SPINE_BLOCK_OUTER_BASE,
    TX_VALIDITY_WITH_SPINE_LOG_ROWS,
};
