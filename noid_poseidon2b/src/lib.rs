// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Poseidon2b over GF(2^128): native permutation, sponge, typed
//! UTXO-layer primitives, and hasher trait.

pub mod batch;
pub(crate) mod batch_avx2;
pub mod channel;
pub mod hasher;
pub mod hasher_impl;
pub mod native;
pub mod primitives;

pub use channel::Poseidon2bChannel;
pub use hasher::*;
pub use native::*;
pub use primitives::{
    derive_address, hash_input_leaf_packed, hash_leaf, hash_output_leaf, hash_output_leaf_packed,
    hash_tx_body_carrier, hash_utxo_leaf, is_coinbase_leaf, Address, Commitment, Digest,
    SpendSecret, TxBodyHash,
};

/// Bulk import surface for UTXO-layer callers.
pub mod prelude {
    pub use crate::native::{
        capacity_iv, compress, poseidon2b_hash_byte_slices, poseidon2b_hash_bytes, DomainTag,
        Poseidon2bSponge, TAG_ACCBLK, TAG_ADDRFIX, TAG_BLOCKHDR, TAG_COMMIT, TAG_COMPRESS,
        TAG_FSCHALNG, TAG_LEAF, TAG_POWHDR, TAG_TXBODY, TAG_TXROOT,
    };
    pub use crate::primitives::{
        derive_address, hash_input_leaf_packed, hash_leaf, hash_output_leaf,
        hash_output_leaf_packed, hash_tx_body_carrier, hash_utxo_leaf, Address, Commitment, Digest,
        SpendSecret, TxBodyHash,
    };
    pub use crate::Poseidon2bChannel;
}
