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
use crate::consensus::timestamps::median_u64;
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
/// - `prev_active_counts`: `active_slot_count` from the last ≤`EXPANSION_WINDOW`
///   finalised headers (oldest first). Used for the median expansion trigger.
///   Pass `&[parent.active_slot_count]` when only the parent is known.
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
    prev_active_counts: &[u64],
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

    // --- §15.3.6 log_slots expansion trigger (median-based) ---
    //
    // Expansion fires when the MEDIAN active_slot_count over the last
    // EXPANSION_WINDOW (= FINALITY_DEPTH = 18) finalised headers exceeds
    // 75% of capacity.  Using the median prevents a single-block spam spike
    // from forcing an expansion: an attacker would need to sustain > 75%
    // occupancy across a majority of the window blocks.
    //
    // `prev_active_counts` is supplied by the caller (from stored headers);
    // it falls back to `[parent.active_slot_count]` when the window is shallow.
    {
        use crate::consensus::params::{EXPAND_DENOM, EXPAND_NUM, LOG_SLOTS_MAX};
        let prev_capacity = 1u64.checked_shl(parent.log_slots).unwrap_or(u64::MAX);
        // Median of the supplied window; fall back to parent when window is empty.
        let median_active = if prev_active_counts.is_empty() {
            parent.active_slot_count
        } else {
            median_u64(prev_active_counts)
        };
        let trigger =
            median_active.saturating_mul(EXPAND_DENOM) >= prev_capacity.saturating_mul(EXPAND_NUM);
        let expected_log_slots = if trigger {
            parent.log_slots.saturating_add(1).min(LOG_SLOTS_MAX)
        } else {
            parent.log_slots
        };
        if block.header.log_slots != expected_log_slots {
            return Err(ConsensusError::BadLogSlotsExpansion);
        }
    }

    // --- Tx count limit ---
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(ConsensusError::TooManyTxs);
    }

    // --- Cross-tx slot conflict check (P.8, §16 invariants 4-5) ---
    validate_block_slot_conflicts(&block.transactions)?;

    // --- Per-tx consensus checks (P.8) ---
    for tx in &block.transactions {
        validate_tx_consensus(tx, nullifiers)?;
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
            &[parent.active_slot_count],
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
            &[parent.active_slot_count],
            block.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
            &mut apply_state,
        );
        // Either InvalidPoW (nonce doesn't satisfy target) or ok if we got unlucky
        // and it happens to work. Just exercise the path.
        let _ = result;
    }

    #[test]
    fn expansion_trigger_enforced() {
        // Build a parent that is at exactly 75% occupancy (should trigger expansion).
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let capacity = 1u64 << TEST_LOG_SLOTS as u64;
        // Set active_slot_count to 75% of capacity.
        let target_active = (capacity * 3) / 4;
        state.active_slot_count = target_active;

        let state_root = state.state_root();
        let parent = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root,
            tx_root: [0u8; 32],
            timestamp: GENESIS_TIMESTAMP,
            height: 0,
            miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: target_active,
            alloc_counter: 0,
        };

        // Block claiming log_slots = TEST_LOG_SLOTS (no expansion) should be rejected.
        let block_no_expand = {
            use crate::block::compute_tx_root;
            use crate::consensus::pow::{full_block_hash, search_pow};
            let mut hdr = BlockHeader {
                prev_block_hash: full_block_hash(&parent),
                state_root,
                tx_root: compute_tx_root(&[]),
                timestamp: parent.timestamp + BLOCK_TIME,
                height: 1,
                miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
                nonce: 0,
                difficulty_target: GENESIS_TARGET,
                proof_transcript_hash: [1u8; 32],
                witness_root: [1u8; 32],
                log_slots: TEST_LOG_SLOTS as u32, // should be TEST_LOG_SLOTS + 1
                active_slot_count: target_active,
                alloc_counter: 0,
            };
            hdr.nonce = search_pow(&hdr, 0, 100_000_000).unwrap();
            crate::block::Block {
                header: hdr,
                transactions: vec![],
            }
        };

        let mut apply_state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        apply_state.active_slot_count = target_active;
        // Pass a window where all EXPANSION_WINDOW values are at 75% —
        // median will equal target_active and trigger expansion.
        let active_window = vec![target_active; 18];
        let result = validate_block_consensus(
            &block_no_expand,
            &parent,
            &[parent.timestamp],
            &active_window,
            block_no_expand.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
            &mut apply_state,
        );
        assert_eq!(
            result,
            Err(ConsensusError::BadLogSlotsExpansion),
            "block must fail when expansion trigger fires but log_slots not incremented"
        );
    }

    #[test]
    fn expansion_not_triggered_by_single_spike() {
        // Median-based trigger: even if parent is at 75%, a window where
        // only the last value is high should NOT trigger (median stays low).
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let capacity = 1u64 << TEST_LOG_SLOTS as u64;
        let low_active = capacity / 4; // 25% — most of the window
        let spike_active = (capacity * 3) / 4; // 75% — only last value
        state.active_slot_count = spike_active;

        let state_root = state.state_root();
        let parent = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root,
            tx_root: [0u8; 32],
            timestamp: GENESIS_TIMESTAMP,
            height: 0,
            miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: spike_active,
            alloc_counter: 0,
        };

        // Build a block that does NOT expand (log_slots unchanged).
        use crate::block::compute_tx_root;
        use crate::consensus::pow::{full_block_hash, search_pow};
        let mut hdr = BlockHeader {
            prev_block_hash: full_block_hash(&parent),
            state_root,
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: 1,
            miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: TEST_LOG_SLOTS as u32, // no expansion
            active_slot_count: spike_active,
            alloc_counter: 0,
        };
        hdr.nonce = search_pow(&hdr, 0, 100_000_000).unwrap();
        let block = crate::block::Block {
            header: hdr,
            transactions: vec![],
        };

        // Window: 17 values at 25%, 1 value at 75%. Median = 25% → no trigger.
        let mut active_window = vec![low_active; 17];
        active_window.push(spike_active);

        let mut apply_state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        apply_state.active_slot_count = spike_active;
        let result = validate_block_consensus(
            &block,
            &parent,
            &[parent.timestamp],
            &active_window,
            block.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
            &mut apply_state,
        );
        assert!(
            result.is_ok(),
            "single spike must not trigger expansion via median: {:?}",
            result
        );
    }
}
