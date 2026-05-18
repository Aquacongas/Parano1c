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
pub mod registry;
pub mod row_window;
pub mod spine_adapter;
pub mod tx_validity_composite;
pub mod tx_validity_leaf;
pub mod tx_validity_with_spine;

pub use bridge::{emit_cross_row_eq, write_bridge_column, BridgeHold, BridgeParams, BridgeWiring};
pub use registry::{CombinerCompositeCols, FriStateOpenCols, TxBodyMerkleCols, TxValidityCols};
pub use row_window::{
    InnerAirView, RowWindowParams, RowWindowWiring, RowWindowWrapper, TerminatorPinCols, WrapPolicy,
};
pub use spine_adapter::{SpineEmbeddingLayout, SpineLayoutError};
pub use tx_validity_leaf::{
    TxValidityCompositeLeaf, TX_VALIDITY_LEAF_LOG_ROWS, TX_VALIDITY_LEAF_N_COLS,
};
pub use tx_validity_with_spine::{
    build_stage_5_7_honest_fixture, coinbase_credit_bit_col, tx_validity_with_spine_n_cols,
    TxValidityCompositeWithSpine, WithSpineOptions, LEAF_BAND_RESERVED, SPINE_BLOCK_OUTER_BASE,
    TX_VALIDITY_WITH_SPINE_LOG_ROWS,
};
