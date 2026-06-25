// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `BlockChainContext` — extends `ChainContext` with a local history cache.
//!
//! `ChainContext` (in `noid_chain`) is an in-memory, non-live utility context.
//! `BlockChainContext` wraps it and adds:
//!
//! - `local_history_cache: Option<LocalHistoryCache>` — local finalized-history accumulator cache.
//! - `update_local_history_cache_with_claim(chain_claim)` — advances the cache by one block.
//! - `init_from_genesis()` — initialises both consensus state and the genesis cache.
//!
//! The live full node does not use this wrapper as its block acceptance path; it
//! uses `MdbxChainContext::apply_next_block` with full `BlockProof` validation.
//!
//! # Dependency note
//!
//! `noid_chain` cannot depend on `noid_recursive` (would be circular).
//! `BlockChainContext` lives in `noid_block` which depends on both.

use noid_chain::block::Block;
use noid_chain::consensus::ConsensusError;
use noid_chain::ChainContext;
use noid_core::Block128;
use noid_recursive::prove::{
    accepted_block_claim_witness, advance_local_history_cache, init_genesis_history_cache,
    LocalHistoryCache,
};

#[derive(Debug)]
pub enum ReplayWitnessError {
    /// Local history cache has not been bootstrapped before a non-genesis update.
    MissingPreviousLocalHistoryCache,
}

/// Full chain context: consensus state + local finalized-history cache.
///
/// The two components can advance at different rates:
/// - Consensus state advances synchronously on each `apply_block_consensus` call.
/// - Local cache advances asynchronously via `update_local_history_cache`.
///
/// Local cache is never required for consensus validity and is not public
/// snapshot authority. Missing or lagging cache state does not affect block
/// validation.
pub struct BlockChainContext {
    /// Native consensus chain state (headers, UTXO state, ReuseGuard, undo logs).
    pub consensus: ChainContext,
    /// Current local finalized-history cache.
    pub local_history_cache: Option<LocalHistoryCache>,
}

impl BlockChainContext {
    /// Initialise from genesis: build `ChainContext` plus genesis local cache.
    ///
    /// The genesis local cache is produced synchronously here.
    ///
    /// If the genesis local cache should be deferred, use
    /// `init_from_genesis_no_cache()` and call `bootstrap_local_history_cache()` later.
    pub fn init_from_genesis() -> Self {
        let consensus = ChainContext::init_from_genesis();
        let local_history_cache = Some(init_genesis_history_cache());
        Self {
            consensus,
            local_history_cache,
        }
    }

    /// Initialise from genesis without producing local history cache.
    ///
    /// The node starts without cache state. Call `bootstrap_local_history_cache()`
    /// when ready to start local finalized-history caching.
    pub fn init_from_genesis_no_cache() -> Self {
        Self {
            consensus: ChainContext::init_from_genesis(),
            local_history_cache: None,
        }
    }

    /// Generate the genesis local cache entry.
    pub fn bootstrap_local_history_cache(&mut self) {
        self.local_history_cache = Some(init_genesis_history_cache());
    }

    // -----------------------------------------------------------------------
    // In-memory block application (non-live utility)
    // -----------------------------------------------------------------------

    /// Apply the next block through the in-memory sequential interpreter.
    ///
    /// This is not the live full-node production path and does not verify the
    /// block's BlockProof. Live nodes use MDBX proof-native application.
    ///
    /// Does not update local history cache. Call
    /// `update_local_history_cache_with_claim` after this if the utility
    /// context should maintain its cache.
    pub fn apply_block_consensus(
        &mut self,
        block: &Block,
        local_time: u64,
    ) -> Result<[u8; 32], ConsensusError> {
        self.consensus.apply_next_block(block, local_time)
    }

    // -----------------------------------------------------------------------
    // Local history cache update
    // -----------------------------------------------------------------------

    /// Advance local finalized-history cache by one step.
    ///
    /// MUST be called after this utility context has advanced its in-memory tip
    /// so that `self.consensus.tip_header()` reflects the newly applied block.
    ///
    /// Returns a reference to the new local cache object.
    ///
    /// This is not public O(1) authority.
    pub fn update_local_history_cache_with_claim(
        &mut self,
        chain_claim: [Block128; 2],
    ) -> Result<&LocalHistoryCache, ReplayWitnessError> {
        let witness = accepted_block_claim_witness(chain_claim);
        let prev = self
            .local_history_cache
            .as_ref()
            .ok_or(ReplayWitnessError::MissingPreviousLocalHistoryCache)?;
        let prev_acc = prev.acc.clone();
        let header = *self.consensus.tip_header();
        let next = advance_local_history_cache(&witness, &header, &prev_acc, Some(prev));
        self.local_history_cache = Some(next);
        Ok(self.local_history_cache.as_ref().expect("just stored"))
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Current tip height.
    pub fn tip_height(&self) -> u64 {
        self.consensus.tip_height
    }

    /// Current tip block hash.
    pub fn tip_hash(&self) -> [u8; 32] {
        self.consensus.tip_hash
    }

    /// Local cache lag: how many blocks behind the consensus tip cache is.
    pub fn local_history_cache_lag(&self) -> u64 {
        match &self.local_history_cache {
            Some(p) => self.consensus.tip_height.saturating_sub(p.block_height),
            None => self.consensus.tip_height + 1,
        }
    }

    /// True if local cache is close to the tip.
    pub fn local_history_cache_current(&self) -> bool {
        self.local_history_cache_lag() <= 3
    }

    /// True if syncing nodes should fall back to native verification
    /// (local cache > FINALITY_DEPTH blocks behind).
    pub fn local_history_cache_too_stale(&self) -> bool {
        use noid_chain::consensus::params::FINALITY_DEPTH;
        self.local_history_cache_lag() > FINALITY_DEPTH
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::genesis::genesis_state_root;
    use noid_chain::hash_block_header;
    use noid_recursive::accumulator::genesis_accumulator;

    #[test]
    fn init_no_cache_starts_degraded() {
        let ctx = BlockChainContext::init_from_genesis_no_cache();
        assert!(ctx.local_history_cache.is_none());
        // Lag = tip_height + 1 = 0 + 1 = 1 block behind.
        assert_eq!(ctx.local_history_cache_lag(), 1);
    }

    #[test]
    fn local_history_cache_lag_zero_after_genesis_init() {
        let ctx = BlockChainContext::init_from_genesis();
        assert_eq!(ctx.local_history_cache_lag(), 0);
        assert!(ctx.local_history_cache_current());
    }

    #[test]
    fn genesis_local_history_cache_accumulator_is_correct() {
        let ctx = BlockChainContext::init_from_genesis();
        let cache = ctx.local_history_cache.as_ref().unwrap();

        use noid_chain::consensus::genesis::genesis_header;
        let genesis = genesis_header();
        let genesis_hash = hash_block_header(&genesis);
        let expected_acc = genesis_accumulator(genesis_state_root(), genesis_hash);

        assert_eq!(cache.block_height, 0);
        assert_eq!(
            cache.acc.chain_hash, expected_acc.chain_hash,
            "local history cache accumulator must match genesis_accumulator"
        );
        assert_eq!(cache.acc.state_root, genesis.state_root);
    }

    #[test]
    fn apply_block_consensus_increments_tip() {
        use noid_chain::block::{compute_tx_root, Block};
        use noid_chain::block_header::BlockHeader;
        use noid_chain::consensus::{
            params::{BLOCK_TIME, GENESIS_TARGET},
            pow::block_id,
        };
        use noid_poseidon2b::primitives::Address;
        use rayon::prelude::*;

        let mut ctx = BlockChainContext::init_from_genesis_no_cache();

        // Build a trivial empty block.
        let parent = *ctx.consensus.tip_header();
        let new_root = ctx.consensus.state.state_root();

        let mut header = BlockHeader {
            prev_block_hash: block_id(&parent),
            state_root: new_root,
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            log_slots: parent.log_slots,
            active_slot_count: 0,
            alloc_counter: 0,
        };

        // GENESIS_TARGET keeps this test in the same easy mining class as
        // genesis on the current Poseidon2b miner.
        {
            use noid_chain::consensus::pow::search_pow;
            let chunk = 10_000_000u128;
            header.nonce = (0u64..300)
                .into_par_iter()
                .find_map_any(|i| search_pow(&header, i as u128 * chunk, chunk))
                .expect("mine: no nonce found in 3 B attempts");
        }

        let block = Block {
            header,
            transactions: vec![],
        };

        let result = ctx.apply_block_consensus(&block, block.header.timestamp + 1);
        assert!(result.is_ok(), "empty block should apply: {:?}", result);
        assert_eq!(ctx.tip_height(), 1);
        // No local cache at all; lag = tip_height + 1 = 2.
        assert_eq!(ctx.local_history_cache_lag(), 2);
    }
}
