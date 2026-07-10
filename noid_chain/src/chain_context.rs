// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `ChainContext` — the unified chain state required to validate and apply blocks.
//!
//! A full node needs more than just the current UTXO state to validate a new block:
//! it needs recent block headers (for timestamp MTP and ASERT anchor), undo logs
//! (for reorg), and the running tip info.
//!
//! `ChainContext` bundles all of this into one struct. It is the RAM/in-memory
//! chain context used by tests and non-live utilities. The live full node uses
//! `MdbxChainContext::apply_next_block`, which verifies minimal block proofs before
//! committing the proven state delta to durable storage.
//!
//! # Scope
//!
//! This context intentionally does not verify `BlockProof`. Do not use it as the
//! full-node production block acceptance path.

use std::collections::HashMap;

use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::consensus::{
    da_prune::{build_undo_log, prune_undo_logs, BlockUndoLog},
    epoch_anchor::{tx_epoch_anchor_height_for_child, validate_block_epoch_anchors},
    genesis::genesis_header,
    header::asert_anchor_height,
    params::{EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS},
    pow::block_id,
    validation::{validate_block_consensus, AnchorInfo},
    ConsensusError,
};
use crate::state::ChainState;

/// In-memory chain context for tests and non-live utilities.
///
/// All fields are derived deterministically from the block history. Live full
/// nodes use the MDBX-backed proof-native context instead.
pub struct ChainContext {
    /// All block headers ever seen, indexed by height. Never pruned.
    /// 212 bytes × N blocks (≈ 1.1 GB after 10 years at 1 block/min).
    pub headers: HashMap<u64, BlockHeader>,

    /// Current exact UTXO chain state.
    pub state: ChainState,

    /// Compact undo logs for the last `UNDO_RETENTION_DEPTH` blocks.
    /// Enables state revert during reorg without replaying from genesis.
    pub undo_logs: HashMap<u64, BlockUndoLog>,

    /// Height of the current chain tip.
    pub tip_height: u64,

    /// `H_BLOCK` hash of the current tip header.
    pub tip_hash: [u8; 32],
}

/// PoW target that is trivially satisfiable for any nonce.
/// Used exclusively in tests — any 256-bit PoW digest is < `[0xFF; 32]`.
#[cfg(test)]
pub(crate) const TEST_TARGET: [u8; 32] = [0xFF; 32];

impl ChainContext {
    /// Initialise a fresh chain context from the genesis block.
    ///
    /// This is the only valid starting state for a new node.
    /// The genesis block is applied via the hardcoded genesis header
    /// (no BlockProof required for genesis).
    pub fn init_from_genesis() -> Self {
        let genesis = genesis_header();
        let state = ChainState::new();

        let mut headers = HashMap::new();
        let genesis_hash = block_id(&genesis);
        headers.insert(0u64, genesis);

        // Genesis: no txs and no undo log.
        Self {
            headers,
            state,
            undo_logs: HashMap::new(),
            tip_height: 0,
            tip_hash: genesis_hash,
        }
    }

    /// Return the header at `height`, if known.
    pub fn header(&self, height: u64) -> Option<&BlockHeader> {
        self.headers.get(&height)
    }

    /// Return the tip header.
    pub fn tip_header(&self) -> &BlockHeader {
        self.headers
            .get(&self.tip_height)
            .expect("tip header must always be present")
    }

    /// Collect the last `MEDIAN_TIME_BLOCKS` timestamps for MTP calculation.
    ///
    /// Returns at most `MEDIAN_TIME_BLOCKS` timestamps, oldest first.
    pub fn prev_timestamps(&self) -> Vec<u64> {
        let tip = self.tip_height;
        let start = tip.saturating_sub(MEDIAN_TIME_BLOCKS as u64 - 1);
        (start..=tip)
            .filter_map(|h| self.headers.get(&h).map(|hdr| hdr.timestamp))
            .collect()
    }

    /// Collect the last `EXPANSION_WINDOW` `active_slot_count` values for the
    /// median expansion trigger. Returns oldest-first.
    pub fn prev_active_counts(&self) -> Vec<u64> {
        let tip = self.tip_height;
        let start = tip.saturating_sub(EXPANSION_WINDOW.saturating_sub(1));
        (start..=tip)
            .filter_map(|h| self.headers.get(&h).map(|hdr| hdr.active_slot_count))
            .collect()
    }

    /// Build the ASERT `AnchorInfo` for the next block's difficulty calculation.
    ///
    /// The anchor is the header at the most recent epoch boundary.
    pub fn anchor_info(&self) -> AnchorInfo {
        let anchor_height = asert_anchor_height(self.tip_height);
        let anchor_header = self
            .headers
            .get(&anchor_height)
            .unwrap_or_else(|| self.tip_header());
        AnchorInfo {
            anchor_height,
            anchor_timestamp: anchor_header.timestamp,
            anchor_target: anchor_header.difficulty_target,
        }
    }

    /// Validate and apply the next block on top of the current tip using the
    /// sequential consensus interpreter.
    ///
    /// This is not the live full-node production path; it does not verify a
    /// `BlockProof`.
    ///
    /// On success:
    /// - `state` is updated to the post-block UTXO state
    /// - the block's header is stored in `headers`
    /// - a new undo log is appended
    /// - old undo logs (> UNDO_RETENTION_DEPTH blocks old) are pruned
    /// - `tip_height` and `tip_hash` are updated
    ///
    /// On failure, the context is left **unchanged**.
    ///
    /// Note: BlockProof verification is NOT performed here.
    pub fn apply_next_block(
        &mut self,
        block: &Block,
        local_time: u64,
    ) -> Result<[u8; 32], ConsensusError> {
        let parent = *self.tip_header();
        let prev_timestamps = self.prev_timestamps();
        let prev_active_counts = self.prev_active_counts();
        let anchor = self.anchor_info();
        let tx_anchor_height = tx_epoch_anchor_height_for_child(block.header.height);
        let tx_anchor_header = self
            .headers
            .get(&tx_anchor_height)
            .ok_or(ConsensusError::BadEpochAnchor)?;
        validate_block_epoch_anchors(block, block_id(tx_anchor_header), block_id(&parent))?;

        // Build undo log BEFORE applying (captures pre-state).
        let undo = build_undo_log(&self.state, block);

        // Run the sequential consensus interpreter (no proof verification).
        // On success, self.state is updated to the post-block state.
        // On failure, self.state is left unchanged.
        let new_state_root = validate_block_consensus(
            block,
            &parent,
            &prev_timestamps,
            &prev_active_counts,
            local_time,
            &anchor,
            &mut self.state,
        )?;

        // All checks passed — update context.
        let block_hash = block_id(&block.header);

        // Store header (forever).
        self.headers.insert(block.header.height, block.header);

        // Store undo log keyed by height; prune old ones beyond UNDO_RETENTION_DEPTH.
        self.undo_logs.insert(block.header.height, undo);
        prune_undo_logs(&mut self.undo_logs, block.header.height);

        // Advance tip.
        self.tip_height = block.header.height;
        self.tip_hash = block_hash;

        Ok(new_state_root)
    }

    /// Number of headers stored (= tip_height + 1 for a linear chain).
    pub fn header_count(&self) -> usize {
        self.headers.len()
    }

    /// Test-only: initialise a chain from a fake genesis with a trivially-satisfiable
    /// PoW target (`[0xFF; 32]`) and a small exact-state domain. Any nonce
    /// satisfies this target, so all subsequent blocks can use `nonce = 0`.
    /// ASERT with perfect `BLOCK_TIME` timing always returns the same easy
    /// target, while the `2^8` state keeps coinbase/finality/reorg tests from
    /// paying the production `2^24` exact-root cost per block.
    #[cfg(test)]
    pub fn init_from_easy_genesis() -> Self {
        const TEST_LOG_SLOTS: usize = 8;

        let mut genesis = crate::consensus::genesis::genesis_header();
        genesis.difficulty_target = TEST_TARGET;
        // nonce = 0 trivially satisfies TEST_TARGET (any digest < 0xFF..FF).
        genesis.nonce = 0;

        let mut state = crate::state::ChainState::with_log_slots(TEST_LOG_SLOTS);
        genesis.log_slots = TEST_LOG_SLOTS as u32;
        genesis.state_root = state.state_root();
        genesis.active_slot_count = 0;
        genesis.alloc_counter = 0;
        let mut headers = std::collections::HashMap::new();
        let genesis_hash = crate::consensus::pow::block_id(&genesis);
        headers.insert(0u64, genesis);

        Self {
            headers,
            state,
            undo_logs: std::collections::HashMap::new(),
            tip_height: 0,
            tip_hash: genesis_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::consensus::{
        genesis::GENESIS_TIMESTAMP,
        params::{BLOCK_TIME, EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS, UNDO_RETENTION_DEPTH},
        pow::block_id,
        template::build_block_template,
    };
    // Easy target for test blocks: any digest satisfies hash < 0xFF..FF.
    // ASERT with perfect BLOCK_TIME timing returns this same target for every
    // subsequent block, so all chained test blocks can use nonce = 0.
    use crate::chain_context::TEST_TARGET;
    use noid_poseidon2b::primitives::Address;

    fn build_coinbase_block_on(ctx: &mut ChainContext) -> Block {
        let parent = *ctx.tip_header();
        let template = build_block_template(
            &parent,
            &ctx.state,
            &ctx.prev_active_counts(),
            vec![],
            Address([0u8; 32]),
            parent.timestamp + BLOCK_TIME,
            TEST_TARGET,
        )
        .expect("canonical coinbase-only child template");
        Block {
            header: template.clone().into_header(0),
            transactions: template.all_txs(),
        }
    }

    #[test]
    fn init_from_genesis_is_valid() {
        let ctx = ChainContext::init_from_genesis();
        assert_eq!(ctx.tip_height, 0);
        assert_eq!(ctx.header_count(), 1);
        assert_eq!(ctx.undo_logs.len(), 0);
        // Tip hash must equal block_id(genesis_header()).
        let genesis = genesis_header();
        assert_eq!(ctx.tip_hash, block_id(&genesis));
    }

    #[test]
    fn apply_next_block_advances_tip() {
        let mut ctx = ChainContext::init_from_easy_genesis();
        let block = build_coinbase_block_on(&mut ctx);
        let ts = block.header.timestamp + 1;
        let result = ctx.apply_next_block(&block, ts);
        assert!(result.is_ok(), "first block should apply: {:?}", result);
        assert_eq!(ctx.tip_height, 1);
        assert_eq!(ctx.header_count(), 2);
    }

    #[test]
    fn three_consecutive_blocks_apply() {
        let mut ctx = ChainContext::init_from_easy_genesis();
        for expected_height in 1..=3u64 {
            let block = build_coinbase_block_on(&mut ctx);
            let ts = block.header.timestamp + 1;
            ctx.apply_next_block(&block, ts)
                .unwrap_or_else(|e| panic!("block {} should apply: {:?}", expected_height, e));
            assert_eq!(ctx.tip_height, expected_height);
        }
        assert_eq!(ctx.header_count(), 4); // genesis + 3
    }

    #[test]
    fn undo_logs_pruned_after_retention() {
        let mut ctx = ChainContext::init_from_easy_genesis();
        // Apply UNDO_RETENTION_DEPTH + 2 blocks.
        for _ in 0..(UNDO_RETENTION_DEPTH + 2) {
            let block = build_coinbase_block_on(&mut ctx);
            let ts = block.header.timestamp + 1;
            ctx.apply_next_block(&block, ts).expect("apply");
        }
        // Undo logs should cover at most UNDO_RETENTION_DEPTH blocks.
        assert!(
            ctx.undo_logs.len() <= UNDO_RETENTION_DEPTH as usize,
            "undo logs exceeded retention: {} > {}",
            ctx.undo_logs.len(),
            UNDO_RETENTION_DEPTH
        );
    }

    #[test]
    fn bad_parent_hash_rejected() {
        let mut ctx = ChainContext::init_from_easy_genesis();
        let mut block = build_coinbase_block_on(&mut ctx);
        block.header.prev_block_hash = [0xAB; 32]; // wrong
                                                   // TEST_TARGET: nonce = 0 always satisfies the target after tampering.
        block.header.nonce = 0;
        let result = ctx.apply_next_block(&block, block.header.timestamp + 1);
        assert_eq!(result, Err(ConsensusError::BadParentHash));
    }

    #[test]
    fn prev_timestamps_covers_up_to_11_headers() {
        let mut ctx = ChainContext::init_from_easy_genesis();
        for _ in 0..15 {
            let block = build_coinbase_block_on(&mut ctx);
            let ts = block.header.timestamp + 1;
            ctx.apply_next_block(&block, ts).expect("apply");
        }
        let ts = ctx.prev_timestamps();
        assert!(
            ts.len() <= MEDIAN_TIME_BLOCKS,
            "at most {} timestamps",
            MEDIAN_TIME_BLOCKS
        );
        assert!(!ts.is_empty());
    }

    #[test]
    fn prev_active_counts_covers_exact_expansion_window() {
        let mut ctx = ChainContext::init_from_easy_genesis();
        for _ in 0..(EXPANSION_WINDOW + 4) {
            let block = build_coinbase_block_on(&mut ctx);
            let ts = block.header.timestamp + 1;
            ctx.apply_next_block(&block, ts).expect("apply");
        }
        let active = ctx.prev_active_counts();
        assert_eq!(active.len(), EXPANSION_WINDOW as usize);
        assert!(!active.is_empty());
    }

    /// Ensure GENESIS_TIMESTAMP is a reasonable value (sanity check on the constant).
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn genesis_timestamp_sanity() {
        assert!(GENESIS_TIMESTAMP > 1_700_000_000);
    }
}
