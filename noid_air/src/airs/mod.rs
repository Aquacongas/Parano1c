// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Concrete `Air` implementations: transaction validity skeleton,
//! carry-ripple adder, linear-combination test rig.

pub mod carry_ripple;
pub mod linear_combination;
pub mod tx_validity;

pub use carry_ripple::{
    CarryInitGate, CarryNextGate, CarryRippleAir, CARRY_RIPPLE_COL_A, CARRY_RIPPLE_COL_B,
    CARRY_RIPPLE_COL_CARRY, CARRY_RIPPLE_COL_IS_RESET, CARRY_RIPPLE_COL_SUM,
    CARRY_RIPPLE_LOG_WORD_BITS, CARRY_RIPPLE_N_COLS, CARRY_RIPPLE_WORD_BITS,
};
pub use linear_combination::LinearCombinationAir;
pub use tx_validity::{
    TxValidityAir, TxValidityCol, TX_VALIDITY_LOG_ROWS, TX_VALIDITY_N_COLS, TX_VALIDITY_ROWS,
    TX_VALIDITY_SLOTS,
};
