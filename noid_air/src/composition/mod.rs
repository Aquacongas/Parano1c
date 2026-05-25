// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

pub mod tx_logic;

pub use tx_logic::{
    boundary_pins_from_body, witness_from_body, TxLogicAir, TxLogicWitness, TX_LOGIC_LOG_ROWS,
    TX_LOGIC_N_COLS,
};
