// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Transaction layer for Paranoid.
//!
//! Defines the on-wire shape of a transaction — inputs, outputs, body
//! roots, auth tags — and the canonical body hash that binds all of it.
//! Cross-reference: `CRYPTO.md` §7 (transaction model) and §7.1 (tx-body
//! coverage of salt + scan_tag).
//!
//! The hash in this crate supersedes the commitment-only
//! `noid_poseidon2b::primitives::hash_tx_body` for full transactions:
//! outputs feed the Merkle as `compress(commitment, compress(salt_leaf,
//! scan_tag))` so a relay cannot rewrite the `(salt, scan_tag)` pair
//! without invalidating the body hash.

pub mod body_hash;
pub mod public;
pub mod types;

pub use body_hash::hash_tx_body;
pub use public::PublicInputs;
pub use types::{Transaction, TxBody, TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS};
