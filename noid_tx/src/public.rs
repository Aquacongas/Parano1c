// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Public-input layout for the transaction STARK. CRYPTO.md §7.
//!
//! Order is locked: `(prev_state_root, new_state_root, nullifier_root,
//! tx_body_hash, fee)`. Recursion and verifier consume this tuple
//! verbatim.

use noid_poseidon2b::primitives::{Digest, TxBodyHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicInputs {
    pub prev_state_root: Digest,
    pub new_state_root: Digest,
    pub nullifier_root: Digest,
    pub tx_body_hash: TxBodyHash,
    pub fee: u128,
}
