// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `TxValidityAir` — transaction-validity AIR.
//!
//! Two entry points coexist in this module:
//!
//! * [`TxValidityAir::new`] — Stage-3a witness skeleton (10 witness
//!   columns, two [`BoolGate`] constraints, `log_rows = 4`). Kept as a
//!   smoke-test target for the commit path and as a regression baseline
//!   for the Stage-3a bench row. No balance, no range, no tx algebra.
//!
//! * [`TxValidityAir::new_3b4`] — Stage-3b-4 composition: witness
//!   skeleton + [`BalanceGateAir`] embedded at a column offset. Enforces
//!   the UTXO conservation law `Σ inputs = Σ outputs + fee` with every
//!   balance operand bit-decomposed inside the balance circuit. Bit
//!   ranges of every operand are pinned by the per-bit [`BoolGate`]
//!   constraints that the `bit_adder` blocks already carry (each of the
//!   four input u64s, eight output u64s, and the fee appears as the
//!   low-bits of a `bit_adder.a` or `.b` column), so there is no
//!   separate [`super::range_gate::RangeGateAir`] instance on the 3b-4
//!   composite — the range check is inlined in the balance witness.
//!
//! ## Layout of the 3b-4 trace
//!
//! Columns `0..TX_VALIDITY_N_COLS` carry the Stage-3a witness fields
//! (selectors, value, owner, spend-secret, auth-tag). Columns
//! `TX_VALIDITY_N_COLS..(TX_VALIDITY_N_COLS + BALANCE_N_COLS)` hold the
//! `BalanceGateAir` columns in the standard balance block order (see
//! `balance_gate.rs`).
//!
//! Witness rows `0..MAX_INPUTS` carry per-input fields on their home
//! columns; rows `MAX_INPUTS..MAX_INPUTS+MAX_OUTPUTS` hold per-output
//! fields. Beyond row `MAX_INPUTS + MAX_OUTPUTS = 12` the witness region
//! is zero-filled. The balance block region uses the standard 128-row
//! per-instance layout demanded by [`super::BitAdderAir`]; instance 0
//! carries the real tx and any remaining instances are zero-padded.
//!
//! ## Soundness caveats — what 3b-4 still does *not* bind
//!
//! 3b-4 is the first real non-Poseidon composition; the full binding
//! of the balance operands to the public `TxBody` u64 fields was
//! originally scoped for Stage 3d via an in-circuit weighted
//! accumulator. Stage 3d-0.10.5 replaces that plan with a cheaper
//! public-input pin — each of the 13 primary operand columns
//! (`i0..i3`, `o0..o7`, `fee`) is declared as a `PublicColumn` whose
//! 64-row programme encodes the bit decomposition of the
//! verifier-known u64, exposed through
//! [`Self::new_3b4_with_value_pins`]. Remaining caveats:
//!
//! 1. (Closed by §3d-0.10.5.) The `Value` witness column is *not*
//!    directly wired to the balance operands — that column is derived
//!    from the same public `TxBody`, so a secondary intra-trace tie is
//!    redundant once the balance operands are themselves pinned public.
//! 2. Poseidon-derived fields (`OwnerHi/Lo`, `SpendSecretHi/Lo`,
//!    `AuthTagHi/Lo`) are free variables: no constraint relates them
//!    yet. That is the job of Stage 3c.
//! 3. The `InputValid` / `OutputValid` selectors are only pinned to the
//!    `{0, 1}` domain; their correspondence to the `valid` flag of each
//!    `TxInput` / `TxOutput` is trace-side only. Stage 3d adds the
//!    per-row selector-consistency gate.

use crate::airs::balance_gate::{
    build_balance_columns, emit_balance_constraints, emit_balance_selector_public_columns,
    emit_balance_value_public_columns,
};
use crate::airs::{BALANCE_MIN_LOG_ROWS, BALANCE_N_COLS};
use crate::gates::{
    emit_rows_must_be_zero, multi_row_indicator_programme, BoolGate, PublicColumn,
};
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

/// Column offset of the balance circuit inside the Stage-3b-4 composite
/// trace. Balance columns occupy
/// `[TX_VALIDITY_BALANCE_COL_OFFSET .. TX_VALIDITY_BALANCE_COL_OFFSET + BALANCE_N_COLS)`.
pub const TX_VALIDITY_BALANCE_COL_OFFSET: usize = TX_VALIDITY_N_COLS;

/// Total column count of the Stage-3b-4 composite trace.
pub const TX_VALIDITY_3B4_N_COLS: usize = TX_VALIDITY_N_COLS + BALANCE_N_COLS;

/// §3d-0.10 skeleton-selector pinning reserves two additional indicator
/// columns at the end of the composite trace. One carries the forbidden
/// row mask for `InputValid` (must-be-zero on rows
/// `MAX_INPUTS..2^log_rows`); the other carries the forbidden row mask
/// for `OutputValid` (must-be-zero on rows
/// `0..MAX_INPUTS ∪ MAX_INPUTS+MAX_OUTPUTS..2^log_rows`).
pub const TX_VALIDITY_INPUT_VALID_MASK_COL: usize = TX_VALIDITY_3B4_N_COLS;
pub const TX_VALIDITY_OUTPUT_VALID_MASK_COL: usize = TX_VALIDITY_3B4_N_COLS + 1;
pub const TX_VALIDITY_3B4_PINNED_N_COLS: usize = TX_VALIDITY_3B4_N_COLS + 2;

/// Stage-3b-4 default `log_rows`. Picked to satisfy both the balance
/// floor (`BALANCE_MIN_LOG_ROWS = 8`, one 128-row instance × 2) and
/// the TAU+1 = 8 rotation-AIR floor. Room for the witness region
/// (`MAX_INPUTS + MAX_OUTPUTS = 12` rows) is trivial at 256 rows.
pub const TX_VALIDITY_3B4_LOG_ROWS: usize = BALANCE_MIN_LOG_ROWS;

impl TxValidityCol {
    #[inline]
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Which composition level the AIR was built at. Stage 3a is the
/// selectors-only skeleton; Stage 3b-4 is the witness + balance
/// composition described at module level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxValidityStage {
    Skeleton3a,
    Composite3b4,
}

pub struct TxValidityAir {
    stage: TxValidityStage,
    log_rows: usize,
    n_cols: usize,
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl Default for TxValidityAir {
    fn default() -> Self {
        Self::new()
    }
}

impl TxValidityAir {
    /// Build the Stage-3a AIR: boolean constraints on the two selector
    /// columns, 10 witness columns, `log_rows = 4`. No balance, no
    /// range, no tx algebra.
    pub fn new() -> Self {
        let constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(TxValidityCol::InputValid.index())),
            Box::new(BoolGate::new(TxValidityCol::OutputValid.index())),
        ];
        Self {
            stage: TxValidityStage::Skeleton3a,
            log_rows: TX_VALIDITY_LOG_ROWS,
            n_cols: TX_VALIDITY_N_COLS,
            constraints,
            public_columns: Vec::new(),
        }
    }

    /// Build the Stage-3b-4 composite AIR: 10 witness columns +
    /// `BALANCE_N_COLS` balance columns, with the full balance-circuit
    /// constraint set emitted at the balance column offset plus the
    /// two skeleton selector `BoolGate`s. `log_rows` must satisfy the
    /// balance and STARK floors (`>= BALANCE_MIN_LOG_ROWS = 8`).
    pub fn new_3b4(log_rows: usize) -> Self {
        assert!(
            log_rows >= BALANCE_MIN_LOG_ROWS,
            "TxValidityAir::new_3b4 requires log_rows >= {BALANCE_MIN_LOG_ROWS}"
        );
        let mut constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(TxValidityCol::InputValid.index())),
            Box::new(BoolGate::new(TxValidityCol::OutputValid.index())),
        ];
        constraints.extend(emit_balance_constraints(TX_VALIDITY_BALANCE_COL_OFFSET));
        Self {
            stage: TxValidityStage::Composite3b4,
            log_rows,
            n_cols: TX_VALIDITY_3B4_N_COLS,
            constraints,
            public_columns: Vec::new(),
        }
    }

    /// §3d-0.10 — composite AIR with the 22 balance-block selector
    /// programmes pinned at the composite's `TX_VALIDITY_BALANCE_COL_OFFSET`.
    /// Constraint set is unchanged relative to [`Self::new_3b4`]; only
    /// the `public_columns` list grows. Honest witnesses verify; any
    /// row-level tamper to a balance `is_reset` / `is_input` cell is
    /// caught by `Air::check` and, post-STARK, by the verifier's
    /// `check_public_columns` MLE re-eval.
    pub fn new_3b4_with_balance_selector_pins(log_rows: usize) -> Self {
        let mut air = Self::new_3b4(log_rows);
        air.public_columns =
            emit_balance_selector_public_columns(TX_VALIDITY_BALANCE_COL_OFFSET, log_rows);
        air
    }

    /// §3d-0.10.5 — composite AIR with the 22 balance-selector pins
    /// AND the 13 primary-operand value pins. Closes the §3b-4 debt
    /// item that the balance circuit operands were witness-free
    /// variables unrelated to the public `TxBody` u64 fields: each
    /// of the 4 input values, 8 output values, and fee is now pinned
    /// to its home `bit_adder.a` / `.b` column via a `PublicColumn`
    /// carrying the 64-bit-decomposition programme of the public u64.
    ///
    /// Programmes depend on `(balance_inputs, balance_outputs, balance_fee)`,
    /// so they must be supplied at AIR construction time (mirroring the
    /// verifier-known public-input contract). An honest prover that
    /// produces the matching trace via [`Self::build_trace_3b4`] with
    /// the same triple verifies; any prover that populates the balance
    /// region with different operand bits is rejected by the value
    /// pins without touching the in-circuit constraint set.
    pub fn new_3b4_with_value_pins(
        log_rows: usize,
        balance_inputs: [u64; 4],
        balance_outputs: [u64; 8],
        balance_fee: u64,
    ) -> Self {
        let mut air = Self::new_3b4(log_rows);
        let mut publics = emit_balance_selector_public_columns(
            TX_VALIDITY_BALANCE_COL_OFFSET,
            log_rows,
        );
        publics.extend(emit_balance_value_public_columns(
            TX_VALIDITY_BALANCE_COL_OFFSET,
            log_rows,
            balance_inputs,
            balance_outputs,
            balance_fee,
        ));
        air.public_columns = publics;
        air
    }

    /// §3d-0.10 skeleton-selector bullet — composite AIR with
    /// - the 22 balance-block selector programmes pinned, AND
    /// - the `InputValid` / `OutputValid` row-domain masks pinned via
    ///   the §3d-0.5.1 `emit_rows_must_be_zero` primitive:
    ///   * `InputValid == 0` on rows `MAX_INPUTS..2^log_rows` (input
    ///     selector can't fire on output / padding rows).
    ///   * `OutputValid == 0` on rows
    ///     `0..MAX_INPUTS ∪ MAX_INPUTS+MAX_OUTPUTS..2^log_rows`
    ///     (output selector can't fire on input / padding rows).
    ///
    /// The `{0,1}` bool constraint already fires on every row via
    /// [`Self::new_3b4`]; the row-domain pin additionally forbids
    /// writing `1` outside the tx's legitimate slot window. Requires
    /// the two extra indicator columns
    /// [`TX_VALIDITY_INPUT_VALID_MASK_COL`] and
    /// [`TX_VALIDITY_OUTPUT_VALID_MASK_COL`], so `n_columns` grows
    /// from `TX_VALIDITY_3B4_N_COLS` to
    /// [`TX_VALIDITY_3B4_PINNED_N_COLS`]. Use
    /// [`Self::build_trace_3b4_with_skeleton_pins`] to materialise
    /// the matching trace.
    pub fn new_3b4_with_skeleton_selector_pins(log_rows: usize) -> Self {
        assert!(
            log_rows >= BALANCE_MIN_LOG_ROWS,
            "TxValidityAir::new_3b4_with_skeleton_selector_pins requires log_rows >= {BALANCE_MIN_LOG_ROWS}"
        );
        let n_rows = 1usize << log_rows;

        let mut constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(TxValidityCol::InputValid.index())),
            Box::new(BoolGate::new(TxValidityCol::OutputValid.index())),
        ];
        constraints.extend(emit_balance_constraints(TX_VALIDITY_BALANCE_COL_OFFSET));

        let mut public_columns =
            emit_balance_selector_public_columns(TX_VALIDITY_BALANCE_COL_OFFSET, log_rows);

        // InputValid forbidden rows: MAX_INPUTS..n_rows.
        let input_forbidden: Vec<usize> = (MAX_INPUTS..n_rows).collect();
        let (pc_in, g_in) = emit_rows_must_be_zero(
            TX_VALIDITY_INPUT_VALID_MASK_COL,
            &input_forbidden,
            n_rows,
            TxValidityCol::InputValid.index(),
        );
        public_columns.push(pc_in);
        constraints.push(g_in);

        // OutputValid forbidden rows: 0..MAX_INPUTS ∪ MAX_INPUTS+MAX_OUTPUTS..n_rows.
        let mut output_forbidden: Vec<usize> = (0..MAX_INPUTS).collect();
        output_forbidden.extend((MAX_INPUTS + MAX_OUTPUTS)..n_rows);
        let (pc_out, g_out) = emit_rows_must_be_zero(
            TX_VALIDITY_OUTPUT_VALID_MASK_COL,
            &output_forbidden,
            n_rows,
            TxValidityCol::OutputValid.index(),
        );
        public_columns.push(pc_out);
        constraints.push(g_out);

        Self {
            stage: TxValidityStage::Composite3b4,
            log_rows,
            n_cols: TX_VALIDITY_3B4_PINNED_N_COLS,
            constraints,
            public_columns,
        }
    }

    /// Trace builder matching [`Self::new_3b4_with_skeleton_selector_pins`].
    /// Same as [`Self::build_trace_3b4`] plus two appended indicator
    /// columns carrying the two forbidden-row masks. Indicator columns
    /// are `Block128::ONE` on forbidden rows and `Block128::ZERO`
    /// elsewhere — the honest programmes are public knowledge (no
    /// witness dependence). Tagged as `ColumnDomain::Bit`.
    pub fn build_trace_3b4_with_skeleton_pins(
        body: &TxBody,
        balance_inputs: [u64; 4],
        balance_outputs: [u64; 8],
        balance_fee: u64,
        log_rows: usize,
    ) -> Trace {
        let trace =
            Self::build_trace_3b4(body, balance_inputs, balance_outputs, balance_fee, log_rows);
        let n_rows = 1usize << log_rows;
        let mut cols = trace.columns;
        let mut domains = trace.domains;

        let input_forbidden: Vec<usize> = (MAX_INPUTS..n_rows).collect();
        let mut output_forbidden: Vec<usize> = (0..MAX_INPUTS).collect();
        output_forbidden.extend((MAX_INPUTS + MAX_OUTPUTS)..n_rows);

        cols.push(multi_row_indicator_programme(&input_forbidden, n_rows));
        cols.push(multi_row_indicator_programme(&output_forbidden, n_rows));
        domains.push(ColumnDomain::Bit);
        domains.push(ColumnDomain::Bit);
        Trace::new_with_domains(cols, domains)
    }

    /// Build the Stage-3a witness trace from a `TxBody`. Column order
    /// is fixed by [`TxValidityCol`]; 10 columns × 16 rows.
    pub fn build_trace(body: &TxBody) -> Trace {
        let (cols, domains) = build_witness_columns(body, TX_VALIDITY_LOG_ROWS);
        Trace::new_with_domains(cols, domains)
    }

    /// Build the Stage-3b-4 composite witness trace from a `TxBody`
    /// and the balance-circuit view of the same tx. Columns
    /// `0..TX_VALIDITY_N_COLS` carry the Stage-3a witness fields at
    /// `log_rows` rows each (same semantics as [`Self::build_trace`],
    /// zero-padded beyond `TX_VALIDITY_SLOTS`); columns
    /// `TX_VALIDITY_N_COLS..` carry the balance trace built from
    /// `(balance_inputs, balance_outputs, balance_fee)`. `log_rows`
    /// must match [`Self::log_rows`] of the AIR.
    ///
    /// The balance-view tuple is supplied explicitly instead of being
    /// derived from `body` because `TxBody::fee` is a `u128` (chain
    /// constant) and the balance circuit wants `u64`; promoting or
    /// truncating that silently would hide bugs. Stage 3d narrows this
    /// to a single `(body, log_rows)` entry once the fee type is
    /// finalised.
    pub fn build_trace_3b4(
        body: &TxBody,
        balance_inputs: [u64; 4],
        balance_outputs: [u64; 8],
        balance_fee: u64,
        log_rows: usize,
    ) -> Trace {
        assert!(
            log_rows >= BALANCE_MIN_LOG_ROWS,
            "Stage-3b-4 trace requires log_rows >= {BALANCE_MIN_LOG_ROWS}"
        );
        let (mut cols, mut domains) = build_witness_columns(body, log_rows);
        let (balance_cols, balance_domains) =
            build_balance_columns(balance_inputs, balance_outputs, balance_fee, log_rows);
        cols.extend(balance_cols.into_iter());
        domains.extend(balance_domains.into_iter());
        Trace::new_with_domains(cols, domains)
    }

    /// Which composition stage this AIR was built at.
    pub fn is_composite_3b4(&self) -> bool {
        self.stage == TxValidityStage::Composite3b4
    }
}

fn build_witness_columns(
    body: &TxBody,
    log_rows: usize,
) -> (Vec<Vec<Block128>>, Vec<ColumnDomain>) {
    let n_rows = 1usize << log_rows;
    assert!(
        n_rows >= TX_VALIDITY_SLOTS,
        "log_rows = {log_rows} too small for {TX_VALIDITY_SLOTS} witness rows"
    );
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
    (cols, domains)
}

impl TxValidityAir {
    /// Move out the constraint list and public-column list.
    /// Used by higher-level composites (e.g. `TxBodySpineComposite`)
    /// that need to shift the column indices and re-wrap.
    pub fn into_parts(self) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
        (self.constraints, self.public_columns)
    }
}

impl Air for TxValidityAir {
    fn n_columns(&self) -> usize {
        self.n_cols
    }
    fn log_rows(&self) -> usize {
        self.log_rows
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

    // --------------------------------------------------------------------
    // Stage 3b-4 composite
    // --------------------------------------------------------------------

    fn mk_body_balanced_1in1out(in_val: u64, out_val: u64, fee: u64) -> TxBody {
        assert_eq!(in_val, out_val + fee, "mk_body must be balanced");
        TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: fee as u128,
            inputs: vec![
                TxInput {
                    slot_index: 0,
                    value: in_val,
                    owner: Address([0x11; 32]),
                    spend_secret: SpendSecret([0x22; 32]),
                    auth_tag: AuthTag([0x33; 32]),
                    valid: true,
                },
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                TxOutput {
                    value: out_val,
                    owner: Address([0x44; 32]),
                    valid: true,
                },
                TxOutput::dummy(),
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
    fn validity_3b4_shape() {
        let air = TxValidityAir::new_3b4(TX_VALIDITY_3B4_LOG_ROWS);
        assert_eq!(air.n_columns(), TX_VALIDITY_3B4_N_COLS);
        assert_eq!(air.log_rows(), TX_VALIDITY_3B4_LOG_ROWS);
        assert!(air.is_composite_3b4());
        // Skeleton 2 BoolGates + 11-block balance + bridges + tail gates.
        assert!(air.constraints().len() > 2);
    }

    #[test]
    fn validity_3b4_accepts_balanced_tx() {
        let air = TxValidityAir::new_3b4(TX_VALIDITY_3B4_LOG_ROWS);
        let body = mk_body_balanced_1in1out(1000, 995, 5);
        let ins = [1000u64, 0, 0, 0];
        let outs = [995u64, 0, 0, 0, 0, 0, 0, 0];
        let trace = TxValidityAir::build_trace_3b4(
            &body,
            ins,
            outs,
            5,
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        assert_eq!(trace.n_cols(), TX_VALIDITY_3B4_N_COLS);
        assert!(air.check(&trace));
    }

    #[test]
    fn validity_3b4_rejects_unbalanced_tx() {
        let air = TxValidityAir::new_3b4(TX_VALIDITY_3B4_LOG_ROWS);
        let body = mk_body_balanced_1in1out(1000, 995, 5);
        // Witness says balanced but balance circuit carries an
        // unbalanced tuple — the composite AIR must reject.
        let ins = [1000u64, 0, 0, 0];
        let outs = [994u64, 0, 0, 0, 0, 0, 0, 0];
        let trace = TxValidityAir::build_trace_3b4(
            &body,
            ins,
            outs,
            5,
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        assert!(!air.check(&trace));
    }

    #[test]
    fn validity_3b4_rejects_tampered_witness_selector() {
        let air = TxValidityAir::new_3b4(TX_VALIDITY_3B4_LOG_ROWS);
        let body = mk_body_balanced_1in1out(1234, 1234, 0);
        let ins = [1234u64, 0, 0, 0];
        let outs = [1234u64, 0, 0, 0, 0, 0, 0, 0];
        let mut trace = TxValidityAir::build_trace_3b4(
            &body,
            ins,
            outs,
            0,
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        // Break the InputValid selector `{0,1}` bool constraint.
        trace.columns[TxValidityCol::InputValid.index()][7] = Block128::from(3u128);
        assert!(!air.check(&trace));
    }

    // --------------------------------------------------------------------
    // Stage 3d-0.10 — balance-selector programme pinning (composite)
    // --------------------------------------------------------------------

    #[test]
    fn validity_3b4_with_balance_selector_pins_shape() {
        let air =
            TxValidityAir::new_3b4_with_balance_selector_pins(TX_VALIDITY_3B4_LOG_ROWS);
        assert_eq!(air.n_columns(), TX_VALIDITY_3B4_N_COLS);
        // 22 = 2 selector programmes × 11 balance blocks.
        assert_eq!(air.public_columns().len(), 22);
        // All pinned columns live inside the balance region.
        for pc in air.public_columns() {
            assert!(pc.col >= TX_VALIDITY_BALANCE_COL_OFFSET);
            assert!(pc.col < TX_VALIDITY_BALANCE_COL_OFFSET + BALANCE_N_COLS);
        }
    }

    #[test]
    fn validity_3b4_with_balance_selector_pins_accepts_honest_tx() {
        let air =
            TxValidityAir::new_3b4_with_balance_selector_pins(TX_VALIDITY_3B4_LOG_ROWS);
        let body = mk_body_balanced_1in1out(777, 770, 7);
        let ins = [777u64, 0, 0, 0];
        let outs = [770u64, 0, 0, 0, 0, 0, 0, 0];
        let trace =
            TxValidityAir::build_trace_3b4(&body, ins, outs, 7, TX_VALIDITY_3B4_LOG_ROWS);
        assert!(air.check(&trace));
    }

    #[test]
    fn validity_3b4_with_balance_selector_pins_rejects_selector_tamper() {
        use crate::airs::bit_adder::{BIT_ADDER_COL_IS_INPUT, BIT_ADDER_N_COLS};
        let air =
            TxValidityAir::new_3b4_with_balance_selector_pins(TX_VALIDITY_3B4_LOG_ROWS);
        let body = mk_body_balanced_1in1out(1000, 1000, 0);
        let ins = [1000u64, 0, 0, 0];
        let outs = [1000u64, 0, 0, 0, 0, 0, 0, 0];
        let mut trace =
            TxValidityAir::build_trace_3b4(&body, ins, outs, 0, TX_VALIDITY_3B4_LOG_ROWS);
        // Flip is_input of the first balance block (A0) on a padding
        // row of instance 0. Without the selector pin the FA gates stay
        // silent (no active data there); the `PublicColumn` check is
        // what fires.
        let col = TX_VALIDITY_BALANCE_COL_OFFSET
            + 0 * BIT_ADDER_N_COLS
            + BIT_ADDER_COL_IS_INPUT;
        trace.columns[col][100] = Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn validity_3b4_rejects_tampered_balance_column() {
        let air = TxValidityAir::new_3b4(TX_VALIDITY_3B4_LOG_ROWS);
        let body = mk_body_balanced_1in1out(1000, 995, 5);
        let ins = [1000u64, 0, 0, 0];
        let outs = [995u64, 0, 0, 0, 0, 0, 0, 0];
        let mut trace = TxValidityAir::build_trace_3b4(
            &body,
            ins,
            outs,
            5,
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        // Flip a bit of the A0.a column at row 0 (an active input
        // bit) — the balance circuit must catch it.
        let col = TX_VALIDITY_BALANCE_COL_OFFSET; // A0.a is col 0 of balance
        trace.columns[col][0] += Block128::ONE;
        assert!(!air.check(&trace));
    }

    // --------------------------------------------------------------------
    // Stage 3d-0.10 — skeleton-selector row-domain pins (3d-0.5.1 primitive)
    // --------------------------------------------------------------------

    #[test]
    fn validity_3b4_with_skeleton_pins_shape() {
        let air = TxValidityAir::new_3b4_with_skeleton_selector_pins(
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        assert_eq!(air.n_columns(), TX_VALIDITY_3B4_PINNED_N_COLS);
        // 22 balance selector publics + 2 skeleton-mask publics.
        assert_eq!(air.public_columns().len(), 24);
        // Mask columns live at the end of the composite.
        let mask_cols: Vec<usize> = air
            .public_columns()
            .iter()
            .map(|pc| pc.col)
            .filter(|&c| c >= TX_VALIDITY_3B4_N_COLS)
            .collect();
        assert_eq!(mask_cols.len(), 2);
        assert!(mask_cols.contains(&TX_VALIDITY_INPUT_VALID_MASK_COL));
        assert!(mask_cols.contains(&TX_VALIDITY_OUTPUT_VALID_MASK_COL));
    }

    #[test]
    fn validity_3b4_with_skeleton_pins_accepts_honest_tx() {
        let air = TxValidityAir::new_3b4_with_skeleton_selector_pins(
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        let body = mk_body_balanced_1in1out(500, 500, 0);
        let ins = [500u64, 0, 0, 0];
        let outs = [500u64, 0, 0, 0, 0, 0, 0, 0];
        let trace = TxValidityAir::build_trace_3b4_with_skeleton_pins(
            &body,
            ins,
            outs,
            0,
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        assert!(air.check(&trace));
    }

    #[test]
    fn validity_3b4_with_skeleton_pins_rejects_input_valid_on_output_row() {
        // Adversary: try to set InputValid = 1 on an output row
        // (MAX_INPUTS). The bool constraint accepts (still {0,1}), but
        // the row-domain pin rejects.
        let air = TxValidityAir::new_3b4_with_skeleton_selector_pins(
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        let body = mk_body_balanced_1in1out(99, 99, 0);
        let ins = [99u64, 0, 0, 0];
        let outs = [99u64, 0, 0, 0, 0, 0, 0, 0];
        let mut trace = TxValidityAir::build_trace_3b4_with_skeleton_pins(
            &body,
            ins,
            outs,
            0,
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        trace.columns[TxValidityCol::InputValid.index()][MAX_INPUTS] = Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn validity_3b4_with_skeleton_pins_rejects_output_valid_on_input_row() {
        let air = TxValidityAir::new_3b4_with_skeleton_selector_pins(
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        let body = mk_body_balanced_1in1out(99, 99, 0);
        let ins = [99u64, 0, 0, 0];
        let outs = [99u64, 0, 0, 0, 0, 0, 0, 0];
        let mut trace = TxValidityAir::build_trace_3b4_with_skeleton_pins(
            &body,
            ins,
            outs,
            0,
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        trace.columns[TxValidityCol::OutputValid.index()][0] = Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn validity_3b4_with_skeleton_pins_rejects_selector_on_pad_row() {
        // Both selectors must be zero on rows beyond the slot window.
        // Pad row = MAX_INPUTS + MAX_OUTPUTS.
        let air = TxValidityAir::new_3b4_with_skeleton_selector_pins(
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        let body = mk_body_balanced_1in1out(77, 77, 0);
        let ins = [77u64, 0, 0, 0];
        let outs = [77u64, 0, 0, 0, 0, 0, 0, 0];
        let mut trace = TxValidityAir::build_trace_3b4_with_skeleton_pins(
            &body,
            ins,
            outs,
            0,
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        let pad_row = MAX_INPUTS + MAX_OUTPUTS;
        trace.columns[TxValidityCol::OutputValid.index()][pad_row] = Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn validity_3b4_with_skeleton_pins_rejects_tampered_mask() {
        let air = TxValidityAir::new_3b4_with_skeleton_selector_pins(
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        let body = mk_body_balanced_1in1out(123, 123, 0);
        let ins = [123u64, 0, 0, 0];
        let outs = [123u64, 0, 0, 0, 0, 0, 0, 0];
        let mut trace = TxValidityAir::build_trace_3b4_with_skeleton_pins(
            &body,
            ins,
            outs,
            0,
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        // Flip the InputValid mask on a legitimate input row (0) —
        // programme says ZERO, tamper ONE.
        trace.columns[TX_VALIDITY_INPUT_VALID_MASK_COL][0] = Block128::ONE;
        assert!(!air.check(&trace));
    }

    // --------------------------------------------------------------------
    // Stage 3d-0.10.5 — primary-operand value pins on the composite
    // --------------------------------------------------------------------

    #[test]
    fn validity_3b4_with_value_pins_shape() {
        let ins = [777u64, 0, 0, 0];
        let outs = [770u64, 0, 0, 0, 0, 0, 0, 0];
        let air = TxValidityAir::new_3b4_with_value_pins(
            TX_VALIDITY_3B4_LOG_ROWS,
            ins,
            outs,
            7,
        );
        assert_eq!(air.n_columns(), TX_VALIDITY_3B4_N_COLS);
        // 22 selector + 13 value = 35.
        assert_eq!(air.public_columns().len(), 22 + 13);
        // All pinned columns live inside the balance region.
        for pc in air.public_columns() {
            assert!(pc.col >= TX_VALIDITY_BALANCE_COL_OFFSET);
            assert!(pc.col < TX_VALIDITY_BALANCE_COL_OFFSET + BALANCE_N_COLS);
        }
    }

    #[test]
    fn validity_3b4_with_value_pins_accepts_honest_tx() {
        let body = mk_body_balanced_1in1out(777, 770, 7);
        let ins = [777u64, 0, 0, 0];
        let outs = [770u64, 0, 0, 0, 0, 0, 0, 0];
        let air = TxValidityAir::new_3b4_with_value_pins(
            TX_VALIDITY_3B4_LOG_ROWS,
            ins,
            outs,
            7,
        );
        let trace =
            TxValidityAir::build_trace_3b4(&body, ins, outs, 7, TX_VALIDITY_3B4_LOG_ROWS);
        assert!(air.check(&trace));
    }

    #[test]
    fn validity_3b4_with_value_pins_rejects_operand_swap() {
        // AIR expects (777, 770, 7); prover submits a different but
        // internally-balanced tuple (500, 495, 5). Balance gates accept
        // either (both balanced), but the value pins commit to the
        // (777, 770, 7) bit decomposition and must reject.
        let body = mk_body_balanced_1in1out(500, 495, 5);
        let pinned_ins = [777u64, 0, 0, 0];
        let pinned_outs = [770u64, 0, 0, 0, 0, 0, 0, 0];
        let air = TxValidityAir::new_3b4_with_value_pins(
            TX_VALIDITY_3B4_LOG_ROWS,
            pinned_ins,
            pinned_outs,
            7,
        );
        let trace = TxValidityAir::build_trace_3b4(
            &body,
            [500u64, 0, 0, 0],
            [495u64, 0, 0, 0, 0, 0, 0, 0],
            5,
            TX_VALIDITY_3B4_LOG_ROWS,
        );
        assert!(!air.check(&trace));
    }

    #[test]
    fn validity_3b4_with_value_pins_rejects_fee_tamper() {
        use crate::airs::bit_adder::{BIT_ADDER_COL_B, BIT_ADDER_N_COLS};
        let body = mk_body_balanced_1in1out(1000, 993, 7);
        let ins = [1000u64, 0, 0, 0];
        let outs = [993u64, 0, 0, 0, 0, 0, 0, 0];
        let air = TxValidityAir::new_3b4_with_value_pins(
            TX_VALIDITY_3B4_LOG_ROWS,
            ins,
            outs,
            7,
        );
        let mut trace =
            TxValidityAir::build_trace_3b4(&body, ins, outs, 7, TX_VALIDITY_3B4_LOG_ROWS);
        // Flip bit 0 of the fee column (BLK_B21 is block ordinal 10).
        let col =
            TX_VALIDITY_BALANCE_COL_OFFSET + 10 * BIT_ADDER_N_COLS + BIT_ADDER_COL_B;
        trace.columns[col][0] += Block128::ONE;
        assert!(!air.check(&trace));
    }
}
