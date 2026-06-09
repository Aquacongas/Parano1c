// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Consensus logic — pure, I/O-free validation functions.
//!
//! This module contains every consensus rule for Paranoid. All functions
//! are deterministic and produce identical results on any architecture.
//! No networking, no disk I/O, no mutable global state.
//!
//! # Modules
//!
//! - [`params`]         — All consensus constants (single source of truth).
//! - [`emission`]       — Block reward schedule (halves per state expansion).
//! - [`difficulty`]     — ASERT difficulty adjustment (no floats).
//! - [`pow`]            — Blake3 PoW over `header_core` (parallel-provable).
//! - [`timestamps`]     — Median-time-past and future-drift rules.
//! - [`receipt`]        — ParanoidReceipt generation and verification.
//! - [`header`]         — Per-block header validation rules.
//! - [`checks`]         — Slot-conflict and tx-consensus validation.
//! - [`mempool_checks`] — Full tx validation for mempool admission.
//! - [`allocator`]      — Slot hint generation (splitmix64, zone-based).
//! - [`fork_choice`]    — Cumulative-chainwork fork choice rule.
//! - [`reorg`]          — Chain reorganisation within finality window.
//! - [`template`]       — Block template assembly for the miner.
//! - [`validation`]     — Full block consensus + state application.
//! - [`ordering`]       — Canonical tx ordering policy for block assembly.
//! - [`conflict`]       — Slot-conflict resolution between competing txs.
//! - [`da_prune`]       — Undo-log build/prune for chain reorg support.
//! - [`genesis`]        — Genesis block / state root derivation.
//! - [`network`]        — Network-kind parameters and per-network constants.

pub mod checks;
pub mod conflict;
pub mod da_prune;
pub mod mempool_checks;
pub mod network;
pub mod ordering;
pub mod reorg;
pub mod template;
pub mod validation;

pub mod allocator;
pub mod difficulty;
pub mod emission;
pub mod fork_choice;
pub mod genesis;
pub mod header;
pub mod params;
pub mod pow;
pub mod receipt;
pub mod timestamps;

// Convenient re-exports.
pub use allocator::{deduplicate_hints, generate_slot_hints, splitmix64};
pub use checks::{validate_block_slot_conflicts, validate_tx_consensus};
pub use conflict::resolve_slot_conflicts;
pub use da_prune::{build_undo_log, prune_undo_logs, revert_block, BlockUndoLog};
pub use difficulty::{add_work, block_work, le256_lt, next_target, work_gt};
pub use emission::{
    block_reward, format_noid, max_coinbase_value, max_coinbase_value_from_fee_sum, total_fees,
};
pub use fork_choice::{choose_chain, choose_chain_by_work, reorg_allowed, ChainChoice};
pub use genesis::{find_genesis_nonce, genesis_header, genesis_state_root, GENESIS_TIMESTAMP};
pub use header::{epoch_anchor_height, is_anchor_height_valid, is_final, validate_header};
pub use mempool_checks::validate_tx_for_mempool;
pub use network::{NetworkConfig, NetworkKind};
pub use ordering::order_block_txs;
pub use params::*;
pub use params::{min_fee, FEE_PER_OUTPUT, MIN_FEE_BASE};
pub use pow::{full_block_hash, header_core_bytes, search_pow, validate_pow, BlockHash};
pub use receipt::{
    generate_receipt, tx_root, verify_against_header, verify_merkle_inclusion, ParanoidReceipt,
    ReceiptVerifyResult, TxSummary,
};
pub use reorg::{apply_reorg, find_common_ancestor, ReorgError, ReorgResult};
pub use template::{build_block_template, BlockTemplate, TemplateBuildError};
pub use timestamps::{median_time_past, median_u64, validate_timestamp};
pub use validation::{validate_block_checks, validate_block_consensus, AnchorInfo};

/// Consensus validation errors — one variant per block invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// §16.1 — PoW hash ≥ difficulty target.
    InvalidPoW,
    /// §16.2 — `prev_block_hash` does not match canonical parent.
    BadParentHash,
    /// §16.3 — `height != parent.height + 1`.
    BadHeight,
    /// §16.4 — `difficulty_target` differs from ASERT expectation.
    BadDifficultyTarget,
    /// §16.5 — Timestamp violates MTP or future-drift rules.
    BadTimestamp,
    /// §16.6 — `proof_transcript_hash` is zero (block has no ZK proof).
    MissingProof,
    /// §16.7 — `log_slots < parent.log_slots` (slots must be monotone).
    BadLogSlots,
    /// §16.8 — Block contains more than `BLOCK_MAX_TXS` transactions.
    TooManyTxs,
    /// §16.9 — `tx_root` does not match the computed Merkle root.
    BadTxRoot,
    /// §16.10 — Nullifier collision (double-spend attempt).
    NullifierCollision,
    /// §16.11 — Two transactions claim the same output slot.
    SlotConflict,
    /// §16.12 — `epoch_anchor` outside valid `[height-7, height-1]` window.
    BadEpochAnchor,
    /// §16.13 — `tx_body_hash` in `PublicInputs` ≠ `hash(tx.body)`.
    BadTxBodyHash,
    /// §16.14 — LogicProof verification failed.
    InvalidLogicProof { tx_index: usize },
    /// §16.15 — Coinbase value exceeds `block_reward + sum(fees)`.
    InflatedCoinbase,
    /// Fee exceeds u64::MAX (values are 64-bit in this protocol).
    BadFee,
    /// P.16 — transaction fee is below the node's minimum relay fee.
    /// Non-consensus (local policy); enforced at mempool admission only.
    BelowMinFee { required: u64, actual: u64 },
    /// §15.3.6 — `log_slots` must expand exactly when occupancy ≥ 75 %,
    /// and must not expand when occupancy < 75 %.
    BadLogSlotsExpansion,
    /// §16.16 — `state_root` does not match post-block state.
    BadStateRoot,
    /// Block carries user transactions with the development stub proof marker [1u8;32].
    /// User-tx blocks must reference a real ZK transcript digest.
    StubProof,
    /// Generic shape / length mismatch.
    ShapeMismatch(String),
}

impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLogicProof { tx_index } => {
                write!(f, "InvalidLogicProof at tx_index={tx_index}")
            }
            Self::BadFee => write!(f, "BadFee"),
            Self::BadLogSlotsExpansion => write!(f, "BadLogSlotsExpansion"),
            Self::ShapeMismatch(msg) => write!(f, "ShapeMismatch: {msg}"),
            Self::BelowMinFee { required, actual } => {
                write!(f, "BelowMinFee: required={required} actual={actual}")
            }
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for ConsensusError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_error_display() {
        let e = ConsensusError::InvalidLogicProof { tx_index: 3 };
        assert!(e.to_string().contains("3"));
        let e2 = ConsensusError::InvalidPoW;
        assert!(e2.to_string().contains("InvalidPoW"));
    }
}
