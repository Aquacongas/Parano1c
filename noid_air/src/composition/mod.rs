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
pub mod haddr_block;
pub mod hauth_block;
pub mod hleaf_block;
pub mod placement;
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
    CombinerCompositeCols, FriStateOpenCols, HAddrCols, HAuthCols, HLeafCols,
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
pub use haddr_block::{
    emit_haddr_block, write_haddr_block_trace, HAddrBlockColumns, HAddrBlockParams,
    HAddrBlockT1Targets, HAddrBlockWiring,
};
pub use hauth_block::{
    emit_hauth_block, write_hauth_block_trace, HAuthBlockColumns, HAuthBlockParams,
    HAuthBlockTargets, HAuthBlockTraceCells, HAuthBlockWiring,
};
pub use tx_validity_full::{
    full_haddr_block_base, TxValidityCompositeFull, HADDR_BLOCK_OUTER_COLS,
    TX_VALIDITY_FULL_LOG_ROWS, TX_VALIDITY_FULL_N_COLS,
};
pub use tx_validity_hauth::{
    auth_tag_dst_cols, full_hauth_block_base, native_address, native_auth_tag,
    pre_s_b_dst_cols, TxValidityCompositeHAuth, AUTH_TAG_DST_BASE,
    FULL_HAUTH_BLOCKS_BASE, HAUTH_BLOCK_OUTER_COLS, PRE_S_B_DST_BASE,
    TX_VALIDITY_HAUTH_LOG_ROWS, TX_VALIDITY_HAUTH_N_COLS,
};
pub use hleaf_block::{
    emit_hleaf_block, write_hleaf_block_trace, HLeafBlockColumns, HLeafBlockParams,
    HLeafBlockTargets, HLeafBlockTraceCells, HLeafBlockWiring,
};
pub use tx_validity_leaf::{
    leaf_block_base, leaf_hash_dst_cols, native_output_leaf_hash, TxValidityCompositeLeaf,
    HLEAF_BLOCK_OUTER_COLS, LEAF_BLOCKS_BASE, LEAF_HASH_DST_BASE, N_OUTPUTS,
    TX_VALIDITY_LEAF_LOG_ROWS, TX_VALIDITY_LEAF_N_COLS,
};
pub use tx_validity_with_spine::{
    tx_validity_with_spine_n_cols, TxValidityCompositeWithSpine, LEAF_BAND_RESERVED,
    SPINE_BLOCK_OUTER_BASE, TX_VALIDITY_WITH_SPINE_LOG_ROWS,
};
