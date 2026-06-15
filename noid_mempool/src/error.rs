// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Error types for the async mempool.

use noid_chain::consensus::ConsensusError;
use noid_poseidon2b::primitives::TxBodyHash;
use thiserror::Error;

/// Error returned by [`AsyncMempool::submit`].
#[derive(Debug, Error)]
pub enum SubmitError {
    /// Transaction already in the pool (idempotent — not a hard error).
    #[error("already admitted: {0:?}")]
    AlreadyAdmitted(TxBodyHash),

    /// Native consensus check failed (fee, anchor, nullifier, slot).
    #[error("consensus: {0}")]
    Consensus(#[from] ConsensusError),

    /// Pool is at capacity.
    #[error("mempool full (capacity {capacity})")]
    Full { capacity: usize },

    /// Malformed TxIntent wire format.
    #[error("malformed intent: {0}")]
    MalformedIntent(String),

    /// Non-coinbase transactions must carry a wallet logic proof.
    #[error("missing logic proof for non-coinbase transaction")]
    MissingProof,

    /// Logic proof bytes exceed the mempool wire/admission cap.
    #[error("logic proof too large: {actual} bytes (max {max})")]
    ProofTooLarge { actual: usize, max: usize },

    /// ZK logic proof verification failed.
    #[error("invalid logic proof: {0}")]
    InvalidProof(String),

    /// Internal error (lock poisoned, channel closed, etc).
    #[error("internal: {0}")]
    Internal(String),
}

impl SubmitError {
    /// Returns `true` if this error is a soft rejection (no evidence of malice).
    /// Soft rejections can be retried after the on-chain state changes.
    pub fn is_soft(&self) -> bool {
        matches!(
            self,
            SubmitError::AlreadyAdmitted(_)
                | SubmitError::Full { .. }
                | SubmitError::Consensus(ConsensusError::SlotConflict)
        )
    }
}
