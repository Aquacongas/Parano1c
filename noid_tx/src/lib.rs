// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Transparent transaction layer for Paranoid.
//!
//! Defines the on-wire shape of a transaction — inputs, outputs, body
//! roots, auth tags — and the canonical body hash that binds all of it.
//! Paranoid is a transparent UTXO chain: values and owner addresses are
//! on-chain, spends are authorized by signatureless `AuthTag`s.

pub mod body_hash;
pub mod claims;
pub mod intent;
pub mod public;
pub mod types;
pub mod wire;

pub use body_hash::hash_tx_body;
pub use claims::compute_claims_commitment;
pub use intent::{ClaimedSlot, TxIntent};
pub use public::{PublicInputs, MAX_LOG_SLOTS, MIN_LOG_SLOTS};
pub use types::{Transaction, TxBody, TxInput, TxOutput, ANCHOR_DEPTH, MAX_INPUTS, MAX_OUTPUTS};
pub use wire::{
    WireError, PUBLIC_INPUTS_WIRE_SIZE, TX_BODY_VERSION, TX_INPUT_PUBLIC_WIRE_SIZE,
    TX_INPUT_WIRE_SIZE, TX_OUTPUT_WIRE_SIZE,
};
