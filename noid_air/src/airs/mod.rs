// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Concrete `Air` implementations: transaction validity skeleton,
//! carry-ripple adder, u64 range check, linear-combination test rig.

pub mod balance_gate;
pub mod bit_adder;
pub mod carry_ripple;
pub mod fri_state_open;
pub mod haddr;
pub mod hauth;
pub mod hleaf;
pub mod linear_combination;
pub mod tx_body_merkle;
pub mod tx_body_spine;
pub mod poseidon_mds;
pub mod poseidon_perm;
pub mod poseidon_sbox;
pub mod range_gate;
pub mod tx_validity;

pub use balance_gate::{
    build_balance_columns, build_balance_trace_parts, emit_balance_constraints,
    emit_balance_selector_public_columns, emit_balance_value_public_columns,
    BalanceBridgeBitsGate, BalanceBridgeCarryGate, BalanceFinalCarryGate, BalanceFinalSumGate,
    BalanceGateAir, BalanceZeroAtTransitionGate, BALANCE_MIN_LOG_ROWS, BALANCE_N_BLOCKS,
    BALANCE_N_COLS,
};
pub use bit_adder::{
    bit_adder_is_input_programme, bit_adder_is_reset_programme, bit_adder_operand_programme,
    emit_block_constraints,
    BitAdderAir, BitAdderCarryInitGate, BitAdderCarryNextGate, BitAdderLayout, FaSumGate,
    PadZeroGate, BIT_ADDER_COL_A, BIT_ADDER_COL_B, BIT_ADDER_COL_CARRY, BIT_ADDER_COL_IS_INPUT,
    BIT_ADDER_COL_IS_RESET, BIT_ADDER_COL_SUM, BIT_ADDER_LOG_WORD_BITS, BIT_ADDER_MAX_WIDTH,
    BIT_ADDER_N_COLS, BIT_ADDER_WORD_BITS,
};
pub use fri_state_open::{
    col_delta_owner_hi, col_delta_owner_lo, col_delta_value, col_eval_point, col_is_mint,
    col_is_spend, col_live_mask, col_new_state_root_hi, col_new_state_root_lo,
    col_opened_pre_owner_hi, col_opened_pre_owner_lo, col_opened_pre_value,
    col_proof_round_digest,
    FriStateOpenAir, FriStateOpenClaim, FriStateOpenWitness, COL_IDX_BIT_BASE, COL_OWNER_HI,
    COL_OWNER_LO, COL_VALUE, FRI_STATE_OPEN_LOG_ROWS, FRI_STATE_OPEN_LOG_SLOTS,
    FRI_STATE_OPEN_N_INPUTS, FRI_STATE_OPEN_N_ROWS, FRI_STATE_OPEN_WITNESS_COLS,
};
pub use haddr::{
    build_haddr_trace, emit_haddr, extract_haddr_output, HAddrAir, HADDR_B_SEED_ROW,
    HADDR_IND_ROW_0, HADDR_IND_ROW_N_ROUNDS, HADDR_IND_ROW_OUTPUT, HADDR_LAYOUT_A, HADDR_LAYOUT_B,
    HADDR_LOG_ROWS, HADDR_N_COLS, HADDR_N_ROWS, HADDR_OUTPUT_ROW, HADDR_PAD_0, HADDR_PAD_1,
    HADDR_PERM_A_BASE, HADDR_PERM_B_BASE, HADDR_PRE_S_A_BASE, HADDR_PRE_S_B_BASE,
};
pub use hauth::{
    build_hauth_trace, emit_hauth, extract_hauth_output, HAuthAir, HAUTH_B_SEED_ROW,
    HAUTH_C_SEED_ROW, HAUTH_IND_ROW_0, HAUTH_IND_ROW_2N_PLUS_1, HAUTH_IND_ROW_N_ROUNDS,
    HAUTH_IND_ROW_OUTPUT, HAUTH_LAYOUT_A, HAUTH_LAYOUT_B, HAUTH_LAYOUT_C, HAUTH_LOG_ROWS,
    HAUTH_N_COLS, HAUTH_N_ROWS, HAUTH_OUTPUT_ROW, HAUTH_PERM_A_BASE, HAUTH_PERM_B_BASE,
    HAUTH_PERM_C_BASE, HAUTH_PRE_S_A_BASE, HAUTH_PRE_S_B_BASE, HAUTH_PRE_S_C_BASE,
};
pub use hleaf::{
    build_hleaf_trace, emit_hleaf, extract_hleaf_output, HLeafAir, HLEAF_B_SEED_ROW,
    HLEAF_C_SEED_ROW, HLEAF_IND_ROW_0, HLEAF_IND_ROW_2N_PLUS_1, HLEAF_IND_ROW_N_ROUNDS,
    HLEAF_IND_ROW_OUTPUT, HLEAF_LAYOUT_A, HLEAF_LAYOUT_B, HLEAF_LAYOUT_C, HLEAF_LOG_ROWS,
    HLEAF_N_COLS, HLEAF_N_ROWS, HLEAF_OUTPUT_ROW, HLEAF_PERM_A_BASE, HLEAF_PERM_B_BASE,
    HLEAF_PERM_C_BASE, HLEAF_PRE_S_A_BASE, HLEAF_PRE_S_B_BASE, HLEAF_PRE_S_C_BASE,
};
pub use tx_body_merkle::{
    build_instance_layout, build_tx_body_merkle_trace,
    build_tx_body_merkle_trace_with_boundary_pins, build_tx_body_merkle_typed_trace,
    emit_tx_body_merkle_constraints, emit_tx_body_merkle_constraints_with_boundary_pins,
    emit_tx_body_merkle_public_columns, emit_tx_body_merkle_public_columns_with_boundary_pins,
    extract_instance_output, instance_row_offset, leaf_rate_absorb_instance_ids,
    leaf_rate_payload_col, tx_body_merkle_column_domains, TxBodyMerkleAir,
    TxBodyMerkleBoundaryPins, N_LEAF_RATE_PAYLOAD_COLS, TXBODY_MERKLE_LAYOUT,
    TXBODY_MERKLE_LOG_ROWS, TXBODY_MERKLE_N_COLS, TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS,
    TXBODY_MERKLE_N_PERMS, TXBODY_MERKLE_N_ROWS, TXBODY_MERKLE_PRE_S_BASE,
    TXBODY_MERKLE_SLOT_LOG_ROWS, TXBODY_MERKLE_SLOT_ROWS,
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
    emit_perm_public_columns, emit_perm_public_columns_at, emit_perm_public_columns_row_major_at,
    emit_perm_rc_binding, emit_perm_rc_binding_at, emit_perm_sbox_chain, emit_perm_sbox_chain_at,
    extract_perm_output, is_full_round, perm_is_full_values, perm_is_full_values_row_major,
    perm_is_round_values, perm_is_round_values_row_major, perm_rc_values,
    perm_rc_values_row_major, write_perm_trace_at, write_perm_trace_at_offset,
    PartialSboxKillGate, PermLayout,
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
    TX_VALIDITY_3B4_PINNED_N_COLS, TX_VALIDITY_BALANCE_COL_OFFSET,
    TX_VALIDITY_INPUT_VALID_MASK_COL, TX_VALIDITY_LOG_ROWS, TX_VALIDITY_N_COLS,
    TX_VALIDITY_OUTPUT_VALID_MASK_COL, TX_VALIDITY_ROWS, TX_VALIDITY_SLOTS,
};
pub use tx_body_spine::{
    emit_txv_tx_body_public_columns, spine_n_cols, txv_live_mask_col, txv_live_mask_programme,
    TxBodySpineComposite, SPINE_LOG_ROWS, TXV_COL_OFFSET, TXV_LIVE_ROWS,
    TX_BODY_MERKLE_COL_OFFSET,
};
