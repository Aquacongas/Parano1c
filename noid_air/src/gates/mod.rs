// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Reusable AIR gates: boolean, weighted-linear, selector. These are
//! the Stage 3b-1 primitives the rest of the gate library (range,
//! balance, Poseidon) is built from.

pub mod bool;
pub mod linear;
pub mod selector;

pub use bool::BoolGate;
pub use linear::WeightedLinearGate;
pub use selector::SelectorGate;
