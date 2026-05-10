// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3c-5 / 3d-0.9 — `TxBodyMerkleAir`.
//!
//! `air.rs` keeps the 3c-5 interior-only AIR (68 stacked Poseidon2b
//! permutations, §3d-0.4 programme binding). The 3d-0.9 full-boundary
//! rebuild lives in `layout.rs` + `echo.rs` and is plugged back into
//! `air.rs` in later sub-stages (3d-0.9.D onwards). Splitting into a
//! folder module now keeps subsequent diffs focused on the new code
//! without churning the existing 370-line file.

pub mod air;
pub mod echo;
pub mod layout;

pub use air::{
    build_tx_body_merkle_trace, build_tx_body_merkle_trace_with_boundary_pins,
    build_tx_body_merkle_typed_trace, emit_tx_body_merkle_constraints,
    emit_tx_body_merkle_boundary_pin_gates,
    emit_tx_body_merkle_constraints_with_boundary_pins,
    emit_tx_body_merkle_public_columns,
    emit_tx_body_merkle_public_columns_with_boundary_pins, extract_instance_output,
    instance_row_offset, leaf_rate_absorb_instance_ids, leaf_rate_payload_col,
    tx_body_merkle_column_domains, tx_body_merkle_column_domains_with_boundary_pins,
    TxBodyMerkleAir, TxBodyMerkleBoundaryPins, N_LEAF_RATE_PAYLOAD_COLS, N_ROUNDS,
    TXBODY_MERKLE_LAYOUT, TXBODY_MERKLE_LOG_ROWS, TXBODY_MERKLE_N_COLS,
    TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS, TXBODY_MERKLE_N_PERMS, TXBODY_MERKLE_N_ROWS,
    TXBODY_MERKLE_PRE_S_BASE, TXBODY_MERKLE_SLOT_LOG_ROWS, TXBODY_MERKLE_SLOT_ROWS,
};
pub use layout::{build_instance_layout, InstanceMeta, InstanceRole};
