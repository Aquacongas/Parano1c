// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid. All rights reserved.

//! Poseidon2b over GF(2^128): native permutation, sponge, typed
//! UTXO-layer primitives, and hasher trait.

pub mod batch;
pub mod channel;
pub mod hasher;
pub mod hasher_impl;
pub mod native;
pub mod primitives;

pub use channel::Poseidon2bChannel;
pub use hasher::*;
pub use native::*;
pub use primitives::{
    derive_address, derive_spend_secret, hash_auth_tag, hash_commitment, hash_leaf, hash_nullifier,
    hash_tx_body, Address, AuthTag, Commitment, Digest, MasterSecret, Nullifier, SpendSecret,
    TxBodyHash,
};

/// Bulk import surface for UTXO-layer callers.
pub mod prelude {
    pub use crate::native::{
        capacity_iv, compress, DomainTag, Poseidon2bSponge, TAG_ADDRESS, TAG_ADDRSPND, TAG_AUTHTAG,
        TAG_BLOCKHDR, TAG_COMMIT, TAG_FSCHALNG, TAG_LEAF, TAG_NULLIFIER, TAG_TXBODY,
    };
    pub use crate::primitives::{
        derive_address, derive_spend_secret, hash_auth_tag, hash_commitment, hash_leaf,
        hash_nullifier, hash_tx_body, Address, AuthTag, Commitment, Digest, MasterSecret,
        Nullifier, SpendSecret, TxBodyHash,
    };
    pub use crate::Poseidon2bChannel;
}
