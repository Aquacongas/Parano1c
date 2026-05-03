// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Concrete `Air` implementations: transaction validity skeleton,
//! carry-ripple adder, u64 range check, linear-combination test rig.

pub mod balance_gate;
pub mod bit_adder;
pub mod carry_ripple;
pub mod haddr;
pub mod hauth;
pub mod hleaf;
pub mod linear_combination;
pub mod poseidon_mds;
pub mod poseidon_perm;
pub mod poseidon_sbox;
pub mod range_gate;
pub mod tx_validity;

pub use balance_gate::{
    build_balance_columns, build_balance_trace_parts, emit_balance_constraints,
    BalanceBridgeBitsGate, BalanceBridgeCarryGate, BalanceFinalCarryGate, BalanceFinalSumGate,
    BalanceGateAir, BalanceZeroAtTransitionGate, BALANCE_MIN_LOG_ROWS, BALANCE_N_BLOCKS,
    BALANCE_N_COLS,
};
pub use bit_adder::{
    emit_block_constraints, BitAdderAir, BitAdderCarryInitGate, BitAdderCarryNextGate,
    BitAdderLayout, FaSumGate, PadZeroGate, BIT_ADDER_COL_A, BIT_ADDER_COL_B, BIT_ADDER_COL_CARRY,
    BIT_ADDER_COL_IS_INPUT, BIT_ADDER_COL_IS_RESET, BIT_ADDER_COL_SUM, BIT_ADDER_LOG_WORD_BITS,
    BIT_ADDER_MAX_WIDTH, BIT_ADDER_N_COLS, BIT_ADDER_WORD_BITS,
};
pub use haddr::{
    build_haddr_trace, emit_haddr_constraints, extract_haddr_output, HAddrAir, HADDR_LAYOUT_A,
    HADDR_LAYOUT_B, HADDR_LOG_ROWS, HADDR_N_COLS, HADDR_N_ROWS, HADDR_PAD_0, HADDR_PAD_1,
    HADDR_PERM_A_BASE, HADDR_PERM_B_BASE,
};
pub use hauth::{
    build_hauth_trace, emit_hauth_constraints, extract_hauth_output, HAuthAir, HAUTH_LAYOUT_A,
    HAUTH_LAYOUT_B, HAUTH_LAYOUT_C, HAUTH_LOG_ROWS, HAUTH_N_COLS, HAUTH_N_ROWS, HAUTH_PERM_A_BASE,
    HAUTH_PERM_B_BASE, HAUTH_PERM_C_BASE,
};
pub use hleaf::{
    build_hleaf_trace, emit_hleaf_constraints, extract_hleaf_output, HLeafAir, HLEAF_LAYOUT_A,
    HLEAF_LAYOUT_B, HLEAF_LAYOUT_C, HLEAF_LOG_ROWS, HLEAF_N_COLS, HLEAF_N_ROWS, HLEAF_PERM_A_BASE,
    HLEAF_PERM_B_BASE, HLEAF_PERM_C_BASE,
};
pub use carry_ripple::{
    CarryInitGate, CarryNextGate, CarryRippleAir, CARRY_RIPPLE_COL_A, CARRY_RIPPLE_COL_B,
    CARRY_RIPPLE_COL_CARRY, CARRY_RIPPLE_COL_IS_RESET, CARRY_RIPPLE_COL_SUM,
    CARRY_RIPPLE_LOG_WORD_BITS, CARRY_RIPPLE_N_COLS, CARRY_RIPPLE_WORD_BITS,
};
pub use linear_combination::LinearCombinationAir;
pub use poseidon_mds::{
    apply_mds_row, emit_mds_row_constraints, MdsKind, MdsLayout, MdsRowGate,
};
pub use poseidon_perm::{
    build_perm_trace, emit_perm_all, emit_perm_all_at, emit_perm_mds_blend,
    emit_perm_mds_blend_at, emit_perm_partial_sbox_kill, emit_perm_partial_sbox_kill_at,
    emit_perm_rc_binding, emit_perm_rc_binding_at, emit_perm_sbox_chain, emit_perm_sbox_chain_at,
    extract_perm_output, is_full_round, write_perm_trace_at, PartialSboxKillGate, PermLayout,
    PermMdsBlendGate, PoseidonPermColumns, DEFAULT_PERM_LAYOUT, POSEIDON_COL_IS_FULL,
    POSEIDON_COL_IS_ROUND, POSEIDON_COL_RC, POSEIDON_COL_S, POSEIDON_COL_SIN, POSEIDON_COL_SOUT,
    POSEIDON_COL_X2, POSEIDON_COL_X3, POSEIDON_COL_X4, POSEIDON_N_ACTIVE_ROWS,
    POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS, POSEIDON_PERM_N_ROWS,
};
pub use poseidon_sbox::{
    build_sbox_x7_columns, emit_sbox_x7_constraints, SboxX7Layout, SBOX_X7_N_COLS,
};
pub use range_gate::{
    AccInitGate, AccNextGate, RangeGateAir, WeightInitGate, WeightNextGate, RANGE_GATE_COL_ACC,
    RANGE_GATE_COL_BIT, RANGE_GATE_COL_IS_RESET, RANGE_GATE_COL_WEIGHT, RANGE_GATE_LOG_WORD_BITS,
    RANGE_GATE_N_COLS, RANGE_GATE_WORD_BITS,
};
pub use tx_validity::{
    TxValidityAir, TxValidityCol, TX_VALIDITY_3B4_LOG_ROWS, TX_VALIDITY_3B4_N_COLS,
    TX_VALIDITY_BALANCE_COL_OFFSET, TX_VALIDITY_LOG_ROWS, TX_VALIDITY_N_COLS, TX_VALIDITY_ROWS,
    TX_VALIDITY_SLOTS,
};
