// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `TxValidityAir` — Stage 3a witness skeleton for the transparent
//! transaction circuit. Carries every raw field the Stage 3b/3c/3d
//! gates will read but algebraically enforces only that the two
//! selector columns are boolean.

use crate::gates::BoolGate;
use crate::{Air, ColumnDomain, Constraint, Trace};
use noid_core::{Block128, TowerField};
use noid_tx::{TxBody, MAX_INPUTS, MAX_OUTPUTS};

/// Number of slots in a transaction trace: MAX_INPUTS input rows followed
/// by MAX_OUTPUTS output rows, padded up to `2^TX_VALIDITY_LOG_ROWS`.
pub const TX_VALIDITY_SLOTS: usize = MAX_INPUTS + MAX_OUTPUTS;
pub const TX_VALIDITY_LOG_ROWS: usize = 4;
pub const TX_VALIDITY_ROWS: usize = 1 << TX_VALIDITY_LOG_ROWS;

/// Column layout for the Stage 3a transaction-validity witness trace.
///
/// All columns have length `TX_VALIDITY_ROWS = 16`. Rows `0..MAX_INPUTS`
/// hold per-input witness fields; rows `MAX_INPUTS..MAX_INPUTS+MAX_OUTPUTS`
/// hold per-output fields; remaining rows are zero-padded. Input-only
/// columns are zero on every output or padding row, and vice versa.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxValidityCol {
    /// Bit selector: `1` on rows that carry a real (`valid=true`) input.
    InputValid = 0,
    /// Bit selector: `1` on rows that carry a real output.
    OutputValid = 1,
    /// `TxInput.slot_index` as a field element (zero on non-input rows).
    SlotIndex = 2,
    /// `value` (u64 → Block128). Set on both input and output rows.
    Value = 3,
    /// Owner address high half (two 128-bit halves).
    OwnerHi = 4,
    /// Owner address low half.
    OwnerLo = 5,
    /// Spend-secret high half (input rows only).
    SpendSecretHi = 6,
    /// Spend-secret low half (input rows only).
    SpendSecretLo = 7,
    /// Auth-tag high half (input rows only).
    AuthTagHi = 8,
    /// Auth-tag low half (input rows only).
    AuthTagLo = 9,
}

pub const TX_VALIDITY_N_COLS: usize = 10;

impl TxValidityCol {
    #[inline]
    pub const fn index(self) -> usize {
        self as usize
    }
}

pub struct TxValidityAir {
    constraints: Vec<Box<dyn Constraint>>,
}

impl Default for TxValidityAir {
    fn default() -> Self {
        Self::new()
    }
}

impl TxValidityAir {
    /// Build the Stage 3a AIR: boolean constraints on the two selector
    /// columns. Further algebraic gates (Poseidon, balance, tx-body
    /// Merkle, FRI-state openings) land in Stage 3b/3c/3d.
    pub fn new() -> Self {
        let constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(TxValidityCol::InputValid.index())),
            Box::new(BoolGate::new(TxValidityCol::OutputValid.index())),
        ];
        Self { constraints }
    }

    /// Build the raw witness trace from a `TxBody`. Column order is fixed
    /// by [`TxValidityCol`]. Missing / dummy inputs and outputs contribute
    /// zero rows; selector bits are zero on those rows so higher-level
    /// gates (added in later substages) can use them as row masks.
    pub fn build_trace(body: &TxBody) -> Trace {
        let n_rows = TX_VALIDITY_ROWS;
        let mut cols: Vec<Vec<Block128>> =
            (0..TX_VALIDITY_N_COLS).map(|_| vec![Block128::ZERO; n_rows]).collect();

        let write_owner = |cols: &mut [Vec<Block128>], row: usize, owner: &[Block128; 2]| {
            cols[TxValidityCol::OwnerHi.index()][row] = owner[0];
            cols[TxValidityCol::OwnerLo.index()][row] = owner[1];
        };

        for (i, input) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
            if !input.valid {
                continue;
            }
            let row = i;
            cols[TxValidityCol::InputValid.index()][row] = Block128::ONE;
            cols[TxValidityCol::SlotIndex.index()][row] =
                Block128::from(input.slot_index as u128);
            cols[TxValidityCol::Value.index()][row] = Block128::from(input.value as u128);
            write_owner(&mut cols, row, &input.owner.as_fields());
            let secret = input.spend_secret.as_fields();
            cols[TxValidityCol::SpendSecretHi.index()][row] = secret[0];
            cols[TxValidityCol::SpendSecretLo.index()][row] = secret[1];
            let tag = input.auth_tag.as_fields();
            cols[TxValidityCol::AuthTagHi.index()][row] = tag[0];
            cols[TxValidityCol::AuthTagLo.index()][row] = tag[1];
        }

        for (i, output) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
            if !output.valid {
                continue;
            }
            let row = MAX_INPUTS + i;
            cols[TxValidityCol::OutputValid.index()][row] = Block128::ONE;
            cols[TxValidityCol::Value.index()][row] = Block128::from(output.value as u128);
            write_owner(&mut cols, row, &output.owner.as_fields());
        }

        let mut domains = vec![ColumnDomain::Block128; TX_VALIDITY_N_COLS];
        domains[TxValidityCol::InputValid.index()] = ColumnDomain::Bit;
        domains[TxValidityCol::OutputValid.index()] = ColumnDomain::Bit;
        Trace::new_with_domains(cols, domains)
    }
}

impl Air for TxValidityAir {
    fn n_columns(&self) -> usize {
        TX_VALIDITY_N_COLS
    }
    fn log_rows(&self) -> usize {
        TX_VALIDITY_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};
    use noid_tx::{TxInput, TxOutput};

    fn mk_input(seed: u8) -> TxInput {
        TxInput {
            slot_index: seed as u32,
            value: (seed as u64) * 11,
            owner: Address([seed; 32]),
            spend_secret: SpendSecret([seed ^ 0xAA; 32]),
            auth_tag: AuthTag([seed ^ 0x55; 32]),
            valid: true,
        }
    }

    fn mk_output(seed: u8) -> TxOutput {
        TxOutput {
            value: (seed as u64) * 7,
            owner: Address([seed; 32]),
            valid: true,
        }
    }

    fn mk_body() -> TxBody {
        TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![mk_input(1), TxInput::dummy(), TxInput::dummy(), TxInput::dummy()],
            outputs: vec![
                mk_output(2),
                mk_output(3),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
        }
    }

    #[test]
    fn validity_air_native_check() {
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_body());
        assert!(air.check(&trace));
    }

    #[test]
    fn validity_air_trace_shape() {
        let trace = TxValidityAir::build_trace(&mk_body());
        assert_eq!(trace.n_cols(), TX_VALIDITY_N_COLS);
        assert_eq!(trace.n_rows(), TX_VALIDITY_ROWS);
        assert_eq!(trace.log_rows, TX_VALIDITY_LOG_ROWS);
        assert_eq!(
            trace.domain(TxValidityCol::InputValid.index()),
            ColumnDomain::Bit
        );
        assert_eq!(
            trace.domain(TxValidityCol::OutputValid.index()),
            ColumnDomain::Bit
        );
    }

    #[test]
    fn validity_air_rows_match_body_fields() {
        let body = mk_body();
        let trace = TxValidityAir::build_trace(&body);
        let input_valid = &trace.columns[TxValidityCol::InputValid.index()];
        assert_eq!(input_valid[0], Block128::ONE);
        for row in 1..TX_VALIDITY_ROWS {
            assert_eq!(input_valid[row], Block128::ZERO);
        }

        let output_valid = &trace.columns[TxValidityCol::OutputValid.index()];
        assert_eq!(output_valid[MAX_INPUTS], Block128::ONE);
        assert_eq!(output_valid[MAX_INPUTS + 1], Block128::ONE);
        for row in [0usize, MAX_INPUTS + 2, MAX_INPUTS + MAX_OUTPUTS] {
            assert_eq!(output_valid[row], Block128::ZERO);
        }

        let value = &trace.columns[TxValidityCol::Value.index()];
        assert_eq!(value[0], Block128::from(body.inputs[0].value as u128));
        assert_eq!(
            value[MAX_INPUTS],
            Block128::from(body.outputs[0].value as u128)
        );

        let slot = &trace.columns[TxValidityCol::SlotIndex.index()];
        assert_eq!(slot[0], Block128::from(body.inputs[0].slot_index as u128));
        for row in MAX_INPUTS..TX_VALIDITY_ROWS {
            assert_eq!(slot[row], Block128::ZERO, "slot index leaked onto output/pad row");
        }

        let auth_hi = &trace.columns[TxValidityCol::AuthTagHi.index()];
        let auth_lo = &trace.columns[TxValidityCol::AuthTagLo.index()];
        let [expected_hi, expected_lo] = body.inputs[0].auth_tag.as_fields();
        assert_eq!(auth_hi[0], expected_hi);
        assert_eq!(auth_lo[0], expected_lo);
        for row in MAX_INPUTS..TX_VALIDITY_ROWS {
            assert_eq!(auth_hi[row], Block128::ZERO);
            assert_eq!(auth_lo[row], Block128::ZERO);
        }
    }

    #[test]
    fn validity_air_rejects_non_bool_input_selector() {
        let air = TxValidityAir::new();
        let mut trace = TxValidityAir::build_trace(&mk_body());
        trace.columns[TxValidityCol::InputValid.index()][3] = Block128::from(5u128);
        assert!(!air.check(&trace));
    }

    #[test]
    fn validity_air_rejects_non_bool_output_selector() {
        let air = TxValidityAir::new();
        let mut trace = TxValidityAir::build_trace(&mk_body());
        trace.columns[TxValidityCol::OutputValid.index()][MAX_INPUTS + 4] =
            Block128::from(7u128);
        assert!(!air.check(&trace));
    }

    #[test]
    fn validity_air_accepts_empty_body() {
        let air = TxValidityAir::new();
        let empty = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![],
        };
        let trace = TxValidityAir::build_trace(&empty);
        assert!(air.check(&trace));
        for col in &trace.columns {
            assert!(col.iter().all(|v| *v == Block128::ZERO));
        }
    }

    #[test]
    fn validity_air_dummy_inputs_keep_selector_zero() {
        let air = TxValidityAir::new();
        let body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![TxInput::dummy(); MAX_INPUTS],
            outputs: vec![TxOutput::dummy(); MAX_OUTPUTS],
        };
        let trace = TxValidityAir::build_trace(&body);
        assert!(air.check(&trace));
        let input_valid = &trace.columns[TxValidityCol::InputValid.index()];
        let output_valid = &trace.columns[TxValidityCol::OutputValid.index()];
        assert!(input_valid.iter().all(|v| *v == Block128::ZERO));
        assert!(output_valid.iter().all(|v| *v == Block128::ZERO));
    }
}
