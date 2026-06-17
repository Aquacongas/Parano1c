// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Concrete `Air` implementations.

pub mod balance_gate;
pub mod bit_adder;
pub mod block_state_binding;
pub mod carry_ripple;
pub mod linear_combination;
pub mod poseidon_mds;
pub mod poseidon_perm;
pub mod poseidon_sbox;
pub mod range_gate;
pub mod tx_body_merkle;
pub mod tx_body_spine;

pub use balance_gate::{
    build_balance_columns, build_sweep_balance_trace_parts, emit_balance_constraints,
    emit_balance_selector_public_columns, emit_sweep_balance_constraints, BalanceGateAir,
    Sweep25x2BalanceGateAir, BALANCE_MIN_LOG_ROWS, BALANCE_N_BLOCKS, BALANCE_N_COLS,
    SWEEP_BALANCE_INPUTS, SWEEP_BALANCE_LEAVES, SWEEP_BALANCE_N_BLOCKS, SWEEP_BALANCE_N_COLS,
    SWEEP_BALANCE_OUTPUTS, SWEEP_BALANCE_TREE_BLOCKS,
};
pub use bit_adder::{
    bit_adder_is_input_programme, bit_adder_is_reset_programme, bit_adder_operand_programme,
    emit_block_constraints, BitAdderAir, BitAdderCarryInitGate, BitAdderCarryNextGate, FaSumGate,
    PadZeroGate, BIT_ADDER_COL_A, BIT_ADDER_COL_B, BIT_ADDER_COL_CARRY, BIT_ADDER_COL_IS_INPUT,
    BIT_ADDER_COL_IS_RESET, BIT_ADDER_COL_SUM, BIT_ADDER_LOG_WORD_BITS, BIT_ADDER_MAX_WIDTH,
    BIT_ADDER_N_COLS, BIT_ADDER_WORD_BITS,
};
pub use block_state_binding::{
    BlockStateBindingAir, BlockStateBindingClaim, BlockStateBindingLayout,
    BlockStateBindingWitness, BLOCK_STATE_BINDING_LOG_ROWS, BLOCK_STATE_BINDING_LOG_SLOTS,
    BLOCK_STATE_BINDING_MAX_SLOTS, BLOCK_STATE_BINDING_N_ROWS,
};
pub use carry_ripple::{
    CarryInitGate, CarryNextGate, CarryRippleAir, CARRY_RIPPLE_COL_A, CARRY_RIPPLE_COL_B,
    CARRY_RIPPLE_COL_CARRY, CARRY_RIPPLE_COL_IS_RESET, CARRY_RIPPLE_COL_SUM,
    CARRY_RIPPLE_LOG_WORD_BITS, CARRY_RIPPLE_N_COLS, CARRY_RIPPLE_WORD_BITS,
};
pub use linear_combination::LinearCombinationAir;
// poseidon_mds internals are used only within poseidon_perm; no public re-export needed.
pub use poseidon_perm::{
    build_perm_trace, emit_perm_all, emit_perm_public_columns, extract_perm_output, is_full_round,
    POSEIDON_COL_IS_FULL, POSEIDON_COL_IS_ROUND, POSEIDON_COL_RC, POSEIDON_COL_S, POSEIDON_COL_SIN,
    POSEIDON_COL_SOUT, POSEIDON_COL_X2, POSEIDON_COL_X3, POSEIDON_COL_X4, POSEIDON_N_ACTIVE_ROWS,
    POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS, POSEIDON_PERM_N_ROWS,
};
// poseidon_sbox is an internal building block for poseidon_perm; no public re-export.
pub use range_gate::{
    RangeGateAir, RANGE_GATE_COL_ACC, RANGE_GATE_COL_BIT, RANGE_GATE_COL_IS_RESET,
    RANGE_GATE_COL_WEIGHT, RANGE_GATE_LOG_WORD_BITS, RANGE_GATE_N_COLS, RANGE_GATE_WORD_BITS,
};
pub use tx_body_merkle::{
    build_instance_layout, instance_row_offset, InstanceMeta, InstanceRole,
    TxBodyMerkleBoundaryPins, TXBODY_MERKLE_LAYOUT, TXBODY_MERKLE_N_PERMS, TXBODY_MERKLE_SLOT_ROWS,
};
pub use tx_body_spine::{
    emit_txv_tx_body_public_columns, merkle_band_width, spine_n_cols, txv_live_mask_col,
    txv_live_mask_programme, TxBodySpineComposite, SPINE_LOG_ROWS, TXV_COL_OFFSET, TXV_LIVE_ROWS,
    TX_BODY_MERKLE_COL_OFFSET,
};
