// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Reusable AIR gates: boolean, weighted-linear, selector — the
//! core primitives the rest of the gate library (range, balance, Poseidon)
//! is built from.

pub mod bool;
pub mod const_column;
pub mod eq_ladder;
pub mod linear;
pub mod mul;
pub mod row_selector;
pub mod selector;

pub use bool::BoolGate;
pub use const_column::PublicColumn;
pub use eq_ladder::EqLadderStepGate;
pub use linear::{WeightedLinearGate, WeightedLinearGateShifted};
pub use mul::{MulGate, SquareGate, TripleProductGate};
pub use row_selector::{
    emit_column_eq_at_next_row, emit_column_eq_at_row, emit_multi_row_selector, emit_public_cell,
    emit_row_selector, emit_rows_must_be_zero, multi_row_indicator_programme,
    row_indicator_programme,
};
pub use selector::SelectorGate;
