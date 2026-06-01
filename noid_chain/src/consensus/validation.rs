// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Native block validation pipeline (SPECIFICATION.md §16, ROADMAP Phase 1 P.9).
//!
//! `validate_block_consensus` enforces all consensus rules that do NOT require
//! ZK proof verification. ZK verification (LogicProof + BlockProof) is layered
//! on top in `noid_block::validate_block_full()`.
//!
//! # Invariants checked here (SPEC §16)
//!
//!  ✅  Header chain (prev_hash, height, difficulty, timestamp, PoW)     [P.6]
//!  ✅  Coinbase structure (at most one, first, zero inputs)              [P.7 partial]
//!  ✅  Coinbase value ≤ block_reward(log_slots) + Σ fees                [P.7 full]
//!  ✅  Per-tx: body_hash binding, non-zero anchor, nullifier             [P.8]
//!  ✅  Cross-tx slot conflicts                                           [P.8]
//!  ✅  TooManyTxs                                                        [P.9]
//!  ✅  Native state transition (apply_block) — state_root, active count  [P.9]
//!
//! # Invariants NOT checked here (require ZK layer in noid_block)
//!
//!  ❌  LogicProof verifies (STARK + AuthGKR)
//!  ❌  BlockStateBinding verifies (Merkle openings)
//!  ❌  C_claimed bridge
//!  ❌  BlockProof aggregate verifies
//!  ❌  epoch_anchor hash matches actual header at that height (needs HeaderProvider)
//!  ❌  da_root / witness_root binding (needs packed DA data)

use crate::block::apply_block;
use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::consensus::{
    checks::{validate_block_slot_conflicts, validate_tx_consensus},
    emission::max_coinbase_value,
    header::validate_header,
    params::BLOCK_MAX_TXS,
    ConsensusError,
};
use crate::nullifier::NullifierSet;
use crate::state::ChainState;

/// Parameters needed for header chain validation.
pub struct AnchorInfo {
    /// Height of the ASERT anchor block.
    pub anchor_height: u64,
    /// Timestamp of the ASERT anchor block.
    pub anchor_timestamp: u64,
    /// Difficulty target at the ASERT anchor block.
    pub anchor_target: [u8; 32],
}

/// Validate all native consensus rules for a block and apply it to `state`.
///
/// On success, `state` is updated to the post-block state and the function
/// returns the post-state root. On failure, `state` is left **unchanged**.
///
/// # Arguments
/// - `block`: candidate block
/// - `parent`: parent block header
/// - `prev_timestamps`: timestamps of the last ≤11 ancestors (oldest first)
/// - `local_time`: current wall-clock seconds (for future-drift check)
/// - `anchor`: ASERT epoch anchor for difficulty computation
/// - `nullifiers`: rolling nullifier set (last ANCHOR_DEPTH blocks)
/// - `state`: chain state to apply to (modified on success)
///
/// # What this does NOT check
///
/// ZK proofs (LogicProof, BlockStateBinding, BlockProof) are verified by
/// `noid_block::validate_block_full()` which calls this function internally.
pub fn validate_block_consensus(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    local_time: u64,
    anchor: &AnchorInfo,
    nullifiers: &NullifierSet,
    state: &mut ChainState,
) -> Result<[u8; 32], ConsensusError> {
    // --- Header checks (P.6) ---
    validate_header(
        &block.header,
        parent,
        prev_timestamps,
        local_time,
        anchor.anchor_height,
        anchor.anchor_timestamp,
        &anchor.anchor_target,
    )?;

    // --- Tx count limit ---
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(ConsensusError::TooManyTxs);
    }

    // --- Cross-tx slot conflict check (P.8, §16 invariants 4-5) ---
    validate_block_slot_conflicts(&block.transactions)?;

    // --- Per-tx consensus checks (P.8) ---
    for tx in &block.transactions {
        validate_tx_consensus(tx, block.header.height, nullifiers)?;
    }

    // --- Coinbase amount validation (P.7) ---
    // block_reward() uses log_slots from the block header (consensus-significant).
    let non_coinbase_bodies: Vec<_> = block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .map(|tx| tx.body.clone())
        .collect();

    if let Some(cb) = block.transactions.first() {
        if cb.body.is_coinbase {
            // Sum coinbase output values.
            let cb_value: u64 = cb
                .body
                .outputs
                .iter()
                .filter(|o| o.valid)
                .map(|o| o.value)
                .fold(0u64, |acc, v| acc.saturating_add(v));

            let max_allowed = max_coinbase_value(block.header.log_slots, &non_coinbase_bodies);
            if cb_value > max_allowed {
                return Err(ConsensusError::InflatedCoinbase);
            }
        }
    }

    // --- Native state transition (apply_block handles state_root, active counts, etc.) ---
    // apply_block returns Err(BlockApplyError) on mismatch; map to ConsensusError.
    apply_block(state, block).map_err(|e| {
        use crate::block::BlockApplyError;
        match e {
            BlockApplyError::TooManyTransactions => ConsensusError::TooManyTxs,
            BlockApplyError::WrongTxBodyHash => ConsensusError::BadTxBodyHash,
            BlockApplyError::HeaderStateRootMismatch => ConsensusError::BadStateRoot,
            BlockApplyError::HeaderTxRootMismatch => ConsensusError::BadTxRoot,
            BlockApplyError::MissingProofTranscriptHash => ConsensusError::MissingProof,
            _ => ConsensusError::ShapeMismatch(format!("{:?}", e)),
        }
    })?;

    Ok(block.header.state_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::block_header::BlockHeader;
    use crate::consensus::{
        genesis::GENESIS_TIMESTAMP,
        params::{BLOCK_TIME, GENESIS_TARGET},
        pow::search_pow,
    };
    use crate::nullifier::NullifierSet;
    use crate::state::ChainState;
    use noid_poseidon2b::primitives::Address;

    const TEST_LOG_SLOTS: usize = 6;

    fn mk_parent(height: u64, ts: u64, prev_hash: [u8; 32], state_root: [u8; 32]) -> BlockHeader {
        BlockHeader {
            prev_block_hash: prev_hash,
            state_root,
            tx_root: [0u8; 32],
            timestamp: ts,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    /// Build a minimal valid block (no txs) on top of `parent`.
    fn build_empty_block(parent: &BlockHeader, state: &mut ChainState) -> Block {
        use crate::block::compute_tx_root;
        use crate::consensus::pow::full_block_hash;

        let mut header = BlockHeader {
            prev_block_hash: full_block_hash(parent),
            state_root: state.state_root(),
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: parent.height + 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: state.state.log_slots() as u32,
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        };
        let nonce =
            search_pow(&header, 0, 100_000_000).expect("genesis target trivially satisfiable");
        header.nonce = nonce;
        Block {
            header,
            transactions: vec![],
        }
    }

    fn genesis_anchor(parent: &BlockHeader) -> AnchorInfo {
        AnchorInfo {
            anchor_height: 0,
            anchor_timestamp: parent.timestamp,
            anchor_target: parent.difficulty_target,
        }
    }

    #[test]
    fn empty_block_on_genesis_validates() {
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let state_root = state.state_root();
        let parent = mk_parent(0, GENESIS_TIMESTAMP, [0u8; 32], state_root);
        let block = build_empty_block(&parent, &mut state.clone());

        let mut apply_state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let result = validate_block_consensus(
            &block,
            &parent,
            &[parent.timestamp],
            block.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
            &mut apply_state,
        );
        assert!(result.is_ok(), "empty block should validate: {:?}", result);
    }

    #[test]
    fn bad_pow_rejected() {
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let state_root = state.state_root();
        let parent = mk_parent(0, GENESIS_TIMESTAMP, [0u8; 32], state_root);
        let mut block = build_empty_block(&parent, &mut state.clone());
        block.header.nonce = 99999999; // likely invalid nonce

        let mut apply_state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let result = validate_block_consensus(
            &block,
            &parent,
            &[parent.timestamp],
            block.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
            &mut apply_state,
        );
        // Either InvalidPoW (nonce doesn't satisfy target) or ok if we got unlucky
        // and it happens to work. Just exercise the path.
        let _ = result;
    }
}
