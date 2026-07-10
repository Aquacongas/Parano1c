// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transparent transaction layer for Paranoid.
//!
//! Defines the on-wire shape of a transaction — inputs, outputs, body
//! roots, auth tags — and the canonical body hash that binds all of it.
//! Paranoid is a transparent UTXO chain: values and owner addresses are
//! on-chain, spends are authorized by signatureless owner proofs.

pub mod body_hash;
pub mod claims;
pub mod intent;
pub mod owner_auth;
pub mod public;
pub mod public_logic;
pub mod types;
pub mod wire;

pub use body_hash::{hash_tx_body, hash_tx_body_for_shape, validity_bits_for_shape};
pub use claims::compute_claims_commitment;
pub use intent::TxIntent;
pub use owner_auth::{canonical_owner_auth, CanonicalOwnerAuth, OwnerAuthError};
pub use public::{PublicInputs, MAX_LOG_SLOTS, MIN_LOG_SLOTS};
pub use public_logic::{
    validate_body_semantics_no_hash, validate_public_tx_logic, PublicLogicError,
    PublicLogicFacts,
};
pub use types::{
    pack_amount_creation_id, unpack_amount_creation_id, Transaction, TxBody, TxInput, TxOutput,
    TxShape, ANCHOR_DEPTH, MAX_INPUTS, MAX_OUTPUTS,
};
pub use wire::{
    WireError, PUBLIC_INPUTS_WIRE_SIZE, TX_INPUT_PUBLIC_WIRE_SIZE, TX_INPUT_WIRE_SIZE,
    TX_OUTPUT_WIRE_SIZE,
};
