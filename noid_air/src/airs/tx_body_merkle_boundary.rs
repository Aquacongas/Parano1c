// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G3.α — `TxBodyMerkleBoundaryAir`.
//!
//! Thin replacement for `TxBodyMerkleAir` under the GKR-spine path. The
//! 59-slot permutation witness lives outside the STARK; the only thing
//! the STARK still needs is the `tx_body_hash` public cell, plus enough
//! shape to slot into the existing composite at `log_rows = 13`.
//!
//! Surface
//! -------
//!
//! - Two columns (`tx_body_hash[0]`, `tx_body_hash[1]`).
//! - Every row of each column is pinned (via `PublicColumn`) to the
//!   respective scalar. This matches the contract
//!   `TxBodyMerkleBoundaryPins::tx_body_hash` exposes today: the
//!   verifier-known pin is the single source of truth.
//! - No row-local constraints.
//! - `log_rows = TXBODY_MERKLE_LOG_ROWS` so the composite embedding
//!   keeps its existing row geometry and cross-AIR ties don't move.
//!
//! What this stage does NOT do
//! ---------------------------
//!
//! - It does not wire itself into `TxValidityCompositeWithSpine`.
//!   Swapping the thick `TxBodyMerkleAir` block for this thin one
//!   requires threading the GKR binding through the STARK transcript
//!   (Stage G3.β) plus updating every consumer that reads the thick
//!   block's internal columns. This module only freezes the contract.
//! - It does not check that `tx_body_hash` is the *correct* wrap
//!   output. That binding is GKR's job; this AIR only asserts that the
//!   public cell equals whatever scalar the composite supplies as the
//!   pin. G3.β connects the GKR output claim to this pin.

use noid_core::Block128;

use crate::gates::const_column::PublicColumn;
use crate::{Air, ColumnDomain, Constraint, Trace};

use super::tx_body_merkle::TXBODY_MERKLE_LOG_ROWS;

/// Number of columns in the thin boundary AIR: lane 0 + lane 1.
pub const TX_BODY_MERKLE_BOUNDARY_N_COLS: usize = 2;

/// `log_rows`, inherited from the thick spine AIR so composites can
/// swap the two without rewiring row geometry.
pub const TX_BODY_MERKLE_BOUNDARY_LOG_ROWS: usize = TXBODY_MERKLE_LOG_ROWS;

/// Column index carrying `tx_body_hash[0]` on every row.
pub const TX_BODY_MERKLE_BOUNDARY_COL_LANE0: usize = 0;
/// Column index carrying `tx_body_hash[1]` on every row.
pub const TX_BODY_MERKLE_BOUNDARY_COL_LANE1: usize = 1;

/// Thin AIR exposing only the `tx_body_hash` public pin. See module
/// docs.
pub struct TxBodyMerkleBoundaryAir {
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
    tx_body_hash: [Block128; 2],
}

impl TxBodyMerkleBoundaryAir {
    /// Build an AIR whose public cells pin every row of columns 0 and 1
    /// to `tx_body_hash[0]` and `tx_body_hash[1]` respectively.
    pub fn new(tx_body_hash: [Block128; 2]) -> Self {
        let total_rows = 1usize << TX_BODY_MERKLE_BOUNDARY_LOG_ROWS;
        let lane0 = vec![tx_body_hash[0]; total_rows];
        let lane1 = vec![tx_body_hash[1]; total_rows];
        let public_columns = vec![
            PublicColumn::new(TX_BODY_MERKLE_BOUNDARY_COL_LANE0, lane0),
            PublicColumn::new(TX_BODY_MERKLE_BOUNDARY_COL_LANE1, lane1),
        ];
        Self {
            constraints: Vec::new(),
            public_columns,
            tx_body_hash,
        }
    }

    /// Build the honest trace: every row carries `tx_body_hash`.
    pub fn build_trace(&self) -> Trace {
        let total_rows = 1usize << TX_BODY_MERKLE_BOUNDARY_LOG_ROWS;
        let lane0 = vec![self.tx_body_hash[0]; total_rows];
        let lane1 = vec![self.tx_body_hash[1]; total_rows];
        Trace::new_with_domains(
            vec![lane0, lane1],
            vec![ColumnDomain::Block128, ColumnDomain::Block128],
        )
    }

    /// Expose the pinned `tx_body_hash` scalar.
    pub fn tx_body_hash(&self) -> [Block128; 2] {
        self.tx_body_hash
    }

    /// Consume the AIR and surrender its constraint / public-column
    /// vectors for embedding in a larger composite (mirrors the
    /// `into_parts` helpers on neighbouring AIRs).
    pub fn into_parts(self) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
        (self.constraints, self.public_columns)
    }
}

impl Air for TxBodyMerkleBoundaryAir {
    fn n_columns(&self) -> usize {
        TX_BODY_MERKLE_BOUNDARY_N_COLS
    }
    fn log_rows(&self) -> usize {
        TX_BODY_MERKLE_BOUNDARY_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
    fn public_columns(&self) -> &[PublicColumn] {
        &self.public_columns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::TowerField;

    fn demo_hash() -> [Block128; 2] {
        [Block128::from(0xABCDEF_u128), Block128::from(0x123456_u128)]
    }

    #[test]
    fn shape_is_two_columns_log_rows_13() {
        let air = TxBodyMerkleBoundaryAir::new(demo_hash());
        assert_eq!(air.n_columns(), 2);
        assert_eq!(air.log_rows(), 13);
        assert_eq!(air.constraints().len(), 0);
        assert_eq!(air.public_columns().len(), 2);
        for pc in air.public_columns() {
            assert_eq!(pc.values.len(), 1 << TX_BODY_MERKLE_BOUNDARY_LOG_ROWS);
        }
    }

    #[test]
    fn honest_trace_accepts() {
        let air = TxBodyMerkleBoundaryAir::new(demo_hash());
        let trace = air.build_trace();
        assert!(air.check(&trace), "honest boundary trace must accept");
    }

    #[test]
    fn tampered_lane0_row_rejects() {
        let air = TxBodyMerkleBoundaryAir::new(demo_hash());
        let mut trace = air.build_trace();
        // Pick a mid-range row that's not obviously boundary-adjacent.
        let row = 4321;
        trace.columns[TX_BODY_MERKLE_BOUNDARY_COL_LANE0][row] += Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_lane1_last_row_rejects() {
        let air = TxBodyMerkleBoundaryAir::new(demo_hash());
        let mut trace = air.build_trace();
        let last = (1 << TX_BODY_MERKLE_BOUNDARY_LOG_ROWS) - 1;
        trace.columns[TX_BODY_MERKLE_BOUNDARY_COL_LANE1][last] += Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn swapping_hash_scalar_changes_pin() {
        let air_a = TxBodyMerkleBoundaryAir::new([Block128::from(1u128), Block128::from(2u128)]);
        let air_b = TxBodyMerkleBoundaryAir::new([Block128::from(3u128), Block128::from(4u128)]);

        let trace_a = air_a.build_trace();
        let trace_b = air_b.build_trace();

        assert!(air_a.check(&trace_a));
        assert!(air_b.check(&trace_b));
        // Cross-checking must fail: the pins are different scalars.
        assert!(!air_a.check(&trace_b));
        assert!(!air_b.check(&trace_a));
    }

    #[test]
    fn zero_hash_is_representable() {
        // Empty / pre-init state must still construct cleanly.
        let air = TxBodyMerkleBoundaryAir::new([Block128::ZERO; 2]);
        let trace = air.build_trace();
        assert!(air.check(&trace));
    }

    #[test]
    fn width_is_minimal() {
        // Regression guard: if this ever grows past 2 columns, the
        // G3.β embedder must be updated to allocate a matching column
        // band in the composite.
        assert_eq!(TX_BODY_MERKLE_BOUNDARY_N_COLS, 2);
    }
}
