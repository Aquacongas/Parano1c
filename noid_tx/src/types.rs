// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Transaction data types. See `CRYPTO.md` §7.

use noid_core::Block128;
use noid_poseidon2b::primitives::{AuthTag, Commitment, Digest, Nullifier, ScanTag, TxBodyHash};

/// Maximum input slots per transaction. Dummy slots (`valid = false`) are
/// padded up to this bound. CRYPTO.md §7.
pub const MAX_INPUTS: usize = 4;

/// Maximum output slots per transaction. CRYPTO.md §7.
pub const MAX_OUTPUTS: usize = 8;

/// A spending input. Dummy slots carry `valid = false`, a zero
/// commitment, and a zero nullifier; they contribute 0 to balance and
/// are not inserted into the nullifier tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxInput {
    pub commitment: Commitment,
    pub nullifier: Nullifier,
    pub valid: bool,
}

impl TxInput {
    pub const fn dummy() -> Self {
        Self {
            commitment: Commitment([0u8; 32]),
            nullifier: Nullifier([0u8; 32]),
            valid: false,
        }
    }
}

/// An on-chain output triple `(commitment, salt, scan_tag)`. CRYPTO.md
/// §5.10 and §7. `salt` is the payer-chosen public salt used both by
/// §5.6 address derivation and §5.10 scan-tag derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxOutput {
    pub commitment: Commitment,
    pub salt: Block128,
    pub scan_tag: ScanTag,
    pub valid: bool,
}

impl TxOutput {
    pub const fn dummy() -> Self {
        Self {
            commitment: Commitment([0u8; 32]),
            salt: Block128(0),
            scan_tag: ScanTag([0u8; 32]),
            valid: false,
        }
    }
}

/// Canonical transaction body. Fields are exactly those covered by the
/// body hash plus the state-root triple exposed as public inputs.
#[derive(Debug, Clone)]
pub struct TxBody {
    pub prev_state_root: Digest,
    pub new_state_root: Digest,
    pub nullifier_root: Digest,
    pub fee: u128,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

/// A full transaction: body plus per-input auth tags binding each spend
/// secret to `tx_body_hash`. CRYPTO.md §5.5.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub body: TxBody,
    pub tx_body_hash: TxBodyHash,
    pub auth_tags: Vec<AuthTag>,
}
