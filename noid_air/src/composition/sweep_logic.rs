// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Body-bound transaction logic AIR for the `Sweep25x2` shape.
//!
//! The legacy sweep wallet path used the standalone `Sweep25x2BalanceGateAir`,
//! whose `public_columns()` were empty. `SweepTxLogicAir` is the replacement
//! production-facing AIR for sweep transaction logic: it reuses the 25-input /
//! 2-output sweep balance constraints, but pins body-derived values and the
//! canonical `tx_body_hash` through `PublicColumn`s.

use crate::airs::{
    build_sweep_balance_trace_parts, emit_sweep_balance_constraints,
    emit_sweep_balance_deterministic_operand_public_columns,
    emit_sweep_balance_selector_public_columns, emit_sweep_balance_sum_carry_public_columns,
    emit_sweep_balance_value_public_columns, BALANCE_MIN_LOG_ROWS, SWEEP_BALANCE_INPUTS,
    SWEEP_BALANCE_N_COLS, SWEEP_BALANCE_OUTPUTS,
};
use crate::{Air, ColumnDomain, Constraint, PublicColumn, Trace};
use noid_core::{Block128, TowerField};
use noid_tx::{hash_tx_body_for_shape, TxBody, TxShape};

/// Sweep logic traces use the same base length as the Standard4x8 logic path so
/// wallet/block aggregation can share the same padded column length.
pub const SWEEP_TX_LOGIC_LOG_ROWS: usize = crate::airs::SPINE_LOG_ROWS;

/// Extra public payload columns appended after the sweep balance columns.
pub const SWEEP_TX_LOGIC_HASH_COLS: usize = 2;
pub const SWEEP_TX_LOGIC_INPUT_MASK_COLS: usize = SWEEP_BALANCE_INPUTS;
pub const SWEEP_TX_LOGIC_OUTPUT_MASK_COLS: usize = SWEEP_BALANCE_OUTPUTS;
pub const SWEEP_TX_LOGIC_INPUT_SLOT_COLS: usize = SWEEP_BALANCE_INPUTS;
pub const SWEEP_TX_LOGIC_OUTPUT_SLOT_COLS: usize = SWEEP_BALANCE_OUTPUTS;
pub const SWEEP_TX_LOGIC_INPUT_OWNER_COLS: usize = 2 * SWEEP_BALANCE_INPUTS;
pub const SWEEP_TX_LOGIC_OUTPUT_OWNER_COLS: usize = 2 * SWEEP_BALANCE_OUTPUTS;
pub const SWEEP_TX_LOGIC_PAYLOAD_COLS: usize = SWEEP_TX_LOGIC_HASH_COLS
    + SWEEP_TX_LOGIC_INPUT_MASK_COLS
    + SWEEP_TX_LOGIC_OUTPUT_MASK_COLS
    + SWEEP_TX_LOGIC_INPUT_SLOT_COLS
    + SWEEP_TX_LOGIC_OUTPUT_SLOT_COLS
    + SWEEP_TX_LOGIC_INPUT_OWNER_COLS
    + SWEEP_TX_LOGIC_OUTPUT_OWNER_COLS;
pub const SWEEP_TX_LOGIC_HASH_COL_OFFSET: usize = SWEEP_BALANCE_N_COLS;
pub const SWEEP_TX_LOGIC_N_COLS: usize = SWEEP_BALANCE_N_COLS + SWEEP_TX_LOGIC_PAYLOAD_COLS;

#[derive(Clone)]
pub struct SweepTxLogicWitness {
    pub body: TxBody,
    pub balance_inputs: [u64; SWEEP_BALANCE_INPUTS],
    pub balance_outputs: [u64; SWEEP_BALANCE_OUTPUTS],
    pub balance_fee: u64,
    pub tx_body_hash_lanes: [Block128; 2],
    pub input_valid_masks: [Block128; SWEEP_BALANCE_INPUTS],
    pub output_valid_masks: [Block128; SWEEP_BALANCE_OUTPUTS],
    pub input_slot_indices: [Block128; SWEEP_BALANCE_INPUTS],
    pub output_slot_indices: [Block128; SWEEP_BALANCE_OUTPUTS],
    pub input_owner_lanes: [[Block128; 2]; SWEEP_BALANCE_INPUTS],
    pub output_owner_lanes: [[Block128; 2]; SWEEP_BALANCE_OUTPUTS],
}

/// Body-bound sweep transaction logic AIR.
pub struct SweepTxLogicAir {
    log_rows: usize,
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
    tx_body_hash_lanes: [Block128; 2],
}

impl SweepTxLogicAir {
    pub fn new(witness: &SweepTxLogicWitness) -> Self {
        let log_rows = SWEEP_TX_LOGIC_LOG_ROWS;
        assert!(
            log_rows >= BALANCE_MIN_LOG_ROWS,
            "SweepTxLogicAir needs log_rows >= {BALANCE_MIN_LOG_ROWS}"
        );
        let mut public_columns = emit_sweep_balance_selector_public_columns(0, log_rows);
        public_columns.extend(emit_sweep_balance_value_public_columns(
            0,
            log_rows,
            witness.balance_inputs,
            witness.balance_outputs,
            witness.balance_fee,
        ));
        public_columns.extend(emit_sweep_balance_deterministic_operand_public_columns(
            0,
            log_rows,
            witness.balance_inputs,
            witness.balance_outputs,
            witness.balance_fee,
        ));
        public_columns.extend(emit_sweep_balance_sum_carry_public_columns(
            0,
            log_rows,
            witness.balance_inputs,
            witness.balance_outputs,
            witness.balance_fee,
        ));
        append_body_public_columns(&mut public_columns, witness, 1usize << log_rows);

        Self {
            log_rows,
            constraints: emit_sweep_balance_constraints(0),
            public_columns,
            tx_body_hash_lanes: witness.tx_body_hash_lanes,
        }
    }

    pub fn new_from_body(body: &TxBody) -> Self {
        let witness = sweep_logic_witness_from_body(body);
        Self::new(&witness)
    }

    pub fn build_trace(&self, witness: &SweepTxLogicWitness) -> Trace {
        let (mut cols, mut domains) = build_sweep_balance_trace_parts(
            self.log_rows,
            witness.balance_inputs,
            witness.balance_outputs,
            witness.balance_fee,
        );
        let n_rows = 1usize << self.log_rows;
        append_body_payload_columns(&mut cols, &mut domains, witness, n_rows);
        Trace::new_with_domains(cols, domains)
    }

    pub fn tx_body_hash_lanes(&self) -> [Block128; 2] {
        self.tx_body_hash_lanes
    }
}

impl Air for SweepTxLogicAir {
    fn n_columns(&self) -> usize {
        SWEEP_TX_LOGIC_N_COLS
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

    fn column_domains(&self) -> Vec<ColumnDomain> {
        let mut domains = vec![ColumnDomain::Block128; SWEEP_BALANCE_N_COLS];
        domains.extend(vec![ColumnDomain::Block128; SWEEP_TX_LOGIC_PAYLOAD_COLS]);
        domains
    }
}

fn push_constant_payload_column(
    cols: &mut Vec<Vec<Block128>>,
    domains: &mut Vec<ColumnDomain>,
    value: Block128,
    n_rows: usize,
) {
    cols.push(vec![value; n_rows]);
    domains.push(ColumnDomain::Block128);
}

fn append_body_payload_columns(
    cols: &mut Vec<Vec<Block128>>,
    domains: &mut Vec<ColumnDomain>,
    witness: &SweepTxLogicWitness,
    n_rows: usize,
) {
    for value in witness.tx_body_hash_lanes {
        push_constant_payload_column(cols, domains, value, n_rows);
    }
    for value in witness.input_valid_masks {
        push_constant_payload_column(cols, domains, value, n_rows);
    }
    for value in witness.output_valid_masks {
        push_constant_payload_column(cols, domains, value, n_rows);
    }
    for value in witness.input_slot_indices {
        push_constant_payload_column(cols, domains, value, n_rows);
    }
    for value in witness.output_slot_indices {
        push_constant_payload_column(cols, domains, value, n_rows);
    }
    for lanes in witness.input_owner_lanes {
        push_constant_payload_column(cols, domains, lanes[0], n_rows);
        push_constant_payload_column(cols, domains, lanes[1], n_rows);
    }
    for lanes in witness.output_owner_lanes {
        push_constant_payload_column(cols, domains, lanes[0], n_rows);
        push_constant_payload_column(cols, domains, lanes[1], n_rows);
    }
    debug_assert_eq!(cols.len(), SWEEP_TX_LOGIC_N_COLS);
}

fn push_constant_public_column(
    public_columns: &mut Vec<PublicColumn>,
    next_col: &mut usize,
    value: Block128,
    n_rows: usize,
) {
    public_columns.push(PublicColumn::new(*next_col, vec![value; n_rows]));
    *next_col += 1;
}

fn append_body_public_columns(
    public_columns: &mut Vec<PublicColumn>,
    witness: &SweepTxLogicWitness,
    n_rows: usize,
) {
    let mut next_col = SWEEP_TX_LOGIC_HASH_COL_OFFSET;
    for value in witness.tx_body_hash_lanes {
        push_constant_public_column(public_columns, &mut next_col, value, n_rows);
    }
    for value in witness.input_valid_masks {
        push_constant_public_column(public_columns, &mut next_col, value, n_rows);
    }
    for value in witness.output_valid_masks {
        push_constant_public_column(public_columns, &mut next_col, value, n_rows);
    }
    for value in witness.input_slot_indices {
        push_constant_public_column(public_columns, &mut next_col, value, n_rows);
    }
    for value in witness.output_slot_indices {
        push_constant_public_column(public_columns, &mut next_col, value, n_rows);
    }
    for lanes in witness.input_owner_lanes {
        push_constant_public_column(public_columns, &mut next_col, lanes[0], n_rows);
        push_constant_public_column(public_columns, &mut next_col, lanes[1], n_rows);
    }
    for lanes in witness.output_owner_lanes {
        push_constant_public_column(public_columns, &mut next_col, lanes[0], n_rows);
        push_constant_public_column(public_columns, &mut next_col, lanes[1], n_rows);
    }
    debug_assert_eq!(next_col, SWEEP_TX_LOGIC_N_COLS);
}

pub fn sweep_logic_witness_from_body(body: &TxBody) -> SweepTxLogicWitness {
    assert_eq!(
        body.shape,
        TxShape::Sweep25x2,
        "unsupported tx body shape for SweepTxLogicAir"
    );
    assert!(
        !body.is_coinbase,
        "SweepTxLogicAir does not support coinbase transactions"
    );
    assert!(
        body.inputs.len() <= SWEEP_BALANCE_INPUTS,
        "inputs exceed Sweep25x2 input capacity"
    );
    assert!(
        body.outputs.len() <= SWEEP_BALANCE_OUTPUTS,
        "outputs exceed Sweep25x2 output capacity"
    );
    assert!(
        body.fee <= u64::MAX as u128,
        "TxBody.fee ({}) exceeds u64::MAX — sweep logic circuit cannot represent it",
        body.fee,
    );

    let mut balance_inputs = [0u64; SWEEP_BALANCE_INPUTS];
    let mut input_valid_masks = [Block128::ZERO; SWEEP_BALANCE_INPUTS];
    let mut input_slot_indices = [Block128::ZERO; SWEEP_BALANCE_INPUTS];
    let mut input_owner_lanes = [[Block128::ZERO; 2]; SWEEP_BALANCE_INPUTS];
    for i in 0..SWEEP_BALANCE_INPUTS {
        let inp = body
            .inputs
            .get(i)
            .cloned()
            .unwrap_or_else(noid_tx::TxInput::dummy);
        if inp.valid {
            balance_inputs[i] = inp.value;
            input_valid_masks[i] = Block128::ONE;
        }
        input_slot_indices[i] = Block128::from(inp.slot_index as u128);
        input_owner_lanes[i] = inp.owner.as_fields();
    }

    let mut balance_outputs = [0u64; SWEEP_BALANCE_OUTPUTS];
    let mut output_valid_masks = [Block128::ZERO; SWEEP_BALANCE_OUTPUTS];
    let mut output_slot_indices = [Block128::ZERO; SWEEP_BALANCE_OUTPUTS];
    let mut output_owner_lanes = [[Block128::ZERO; 2]; SWEEP_BALANCE_OUTPUTS];
    for i in 0..SWEEP_BALANCE_OUTPUTS {
        let out = body
            .outputs
            .get(i)
            .copied()
            .unwrap_or_else(noid_tx::TxOutput::dummy);
        if out.valid {
            balance_outputs[i] = out.value;
            output_valid_masks[i] = Block128::ONE;
        }
        output_slot_indices[i] = Block128::from(out.slot_index as u128);
        output_owner_lanes[i] = out.owner.as_fields();
    }

    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );

    SweepTxLogicWitness {
        body: body.clone(),
        balance_inputs,
        balance_outputs,
        balance_fee: body.fee as u64,
        tx_body_hash_lanes: tx_body_hash.as_fields(),
        input_valid_masks,
        output_valid_masks,
        input_slot_indices,
        output_slot_indices,
        input_owner_lanes,
        output_owner_lanes,
    }
}

pub fn sweep_logic_air_and_trace_from_body(body: &TxBody) -> (SweepTxLogicAir, Trace) {
    let witness = sweep_logic_witness_from_body(body);
    let air = SweepTxLogicAir::new(&witness);
    let trace = air.build_trace(&witness);
    (air, trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Air;
    use noid_core::TowerField;
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};
    use noid_tx::{TxInput, TxOutput};

    fn mk_input(i: usize) -> TxInput {
        TxInput {
            slot_index: 1_000 + i as u32,
            value: 10_000 + i as u64,
            owner: Address([i as u8; 32]),
            spend_secret: SpendSecret([0xA0 ^ i as u8; 32]),
            auth_tag: AuthTag([0x55 ^ i as u8; 32]),
            valid: true,
        }
    }

    fn mk_sweep_body() -> TxBody {
        let inputs: Vec<TxInput> = (0..SWEEP_BALANCE_INPUTS).map(mk_input).collect();
        let total: u64 = inputs.iter().map(|i| i.value).sum();
        let fee = 777u64;
        let spendable = total - fee;
        TxBody {
            shape: TxShape::Sweep25x2,
            epoch_anchor: [0x5A; 32],
            fee: fee as u128,
            inputs,
            outputs: vec![
                TxOutput {
                    slot_index: 50_000,
                    value: spendable / 2,
                    owner: Address([0xA1; 32]),
                    valid: true,
                },
                TxOutput {
                    slot_index: 50_001,
                    value: spendable - spendable / 2,
                    owner: Address([0xA2; 32]),
                    valid: true,
                },
            ],
            is_coinbase: false,
        }
    }

    #[test]
    fn sweep_tx_logic_air_has_body_public_columns() {
        let body = mk_sweep_body();
        let witness = sweep_logic_witness_from_body(&body);
        let air = SweepTxLogicAir::new(&witness);
        let trace = air.build_trace(&witness);

        assert!(air.check(&trace));
        assert_eq!(air.n_columns(), SWEEP_TX_LOGIC_N_COLS);
        assert!(air.public_columns().len() > 0);
        assert_eq!(
            air.public_columns().len(),
            4 * crate::airs::SWEEP_BALANCE_N_BLOCKS
                + (2 * crate::airs::SWEEP_BALANCE_N_BLOCKS
                    - SWEEP_BALANCE_INPUTS
                    - SWEEP_BALANCE_OUTPUTS
                    - 1
                    - 1)
                + SWEEP_BALANCE_INPUTS
                + SWEEP_BALANCE_OUTPUTS
                + 1
                + SWEEP_TX_LOGIC_PAYLOAD_COLS
        );
    }

    #[test]
    fn sweep_tx_logic_rejects_input_value_tamper() {
        let body = mk_sweep_body();
        let witness = sweep_logic_witness_from_body(&body);
        let air = SweepTxLogicAir::new(&witness);
        let mut malicious = witness.clone();
        malicious.balance_inputs[0] = malicious.balance_inputs[0].saturating_add(1);
        malicious.balance_outputs[0] = malicious.balance_outputs[0].saturating_add(1);
        let trace = air.build_trace(&malicious);
        assert!(!air.check(&trace));
    }

    #[test]
    fn sweep_tx_logic_rejects_output_value_tamper() {
        let body = mk_sweep_body();
        let witness = sweep_logic_witness_from_body(&body);
        let air = SweepTxLogicAir::new(&witness);
        let mut malicious = witness.clone();
        malicious.balance_outputs[1] = malicious.balance_outputs[1].saturating_add(1);
        malicious.balance_inputs[1] = malicious.balance_inputs[1].saturating_add(1);
        let trace = air.build_trace(&malicious);
        assert!(!air.check(&trace));
    }

    #[test]
    fn sweep_tx_logic_rejects_fee_tamper() {
        let body = mk_sweep_body();
        let witness = sweep_logic_witness_from_body(&body);
        let air = SweepTxLogicAir::new(&witness);
        let mut malicious = witness.clone();
        malicious.balance_fee = malicious.balance_fee.saturating_add(1);
        malicious.balance_inputs[2] = malicious.balance_inputs[2].saturating_add(1);
        let trace = air.build_trace(&malicious);
        assert!(!air.check(&trace));
    }

    #[test]
    fn sweep_tx_logic_rejects_hash_lane_tamper() {
        let body = mk_sweep_body();
        let witness = sweep_logic_witness_from_body(&body);
        let air = SweepTxLogicAir::new(&witness);
        let mut malicious = witness.clone();
        malicious.tx_body_hash_lanes[0] += Block128::ONE;
        let trace = air.build_trace(&malicious);
        assert!(!air.check(&trace));
    }

    #[test]
    fn sweep_tx_logic_rejects_balanced_trace_for_different_body() {
        let body = mk_sweep_body();
        let witness = sweep_logic_witness_from_body(&body);
        let air = SweepTxLogicAir::new(&witness);

        let mut other = body.clone();
        other.inputs[0].value += 1;
        other.outputs[0].value += 1;
        let other_witness = sweep_logic_witness_from_body(&other);
        let other_trace = air.build_trace(&other_witness);

        assert!(!air.check(&other_trace));
        let other_air = SweepTxLogicAir::new(&other_witness);
        assert!(other_air.check(&other_trace));
    }

    #[test]
    fn sweep_tx_logic_pins_invalid_inputs_to_zero() {
        let mut body = mk_sweep_body();
        let removed_value = body.inputs[5].value;
        body.inputs[5].valid = false;
        body.inputs[5].value = 99_999;
        body.outputs[0].value = body.outputs[0].value.saturating_sub(removed_value);
        let witness = sweep_logic_witness_from_body(&body);
        assert_eq!(witness.balance_inputs[5], 0);
        let air = SweepTxLogicAir::new(&witness);
        let trace = air.build_trace(&witness);
        assert!(air.check(&trace));

        let mut malicious = witness.clone();
        malicious.balance_inputs[5] = 99_999;
        let bad_trace = air.build_trace(&malicious);
        assert!(!air.check(&bad_trace));
    }
}
