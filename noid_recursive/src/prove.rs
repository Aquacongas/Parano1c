// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Local finalized-history cache accumulator.
//!
//! This object is deliberately not a trustless snapshot authority. It is a
//! deterministic host-side cache of the rolling history accumulator: each
//! finalized block contributes its semantic block id, post-state root, and
//! canonical accepted-block claim.

use crate::accumulator::ChainAccumulator;
use noid_chain::BlockHeader;
use noid_core::{Block128, TowerField};

/// Minimal witness for one accepted block in the local history cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedBlockClaimWitness {
    pub chain_claim: [Block128; 2],
}

/// Local cache object after a finalized block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalHistoryCache {
    /// Rolling chain accumulator after this block.
    pub acc: ChainAccumulator,
    /// Block height covered by `acc`.
    pub block_height: u64,
    /// Canonical accepted-block claim folded into this step.
    pub chain_claim: [Block128; 2],
}

impl LocalHistoryCache {
    /// Approximate serialised byte length.
    pub fn byte_len(&self) -> usize {
        8 + 32 + 32 + 32
    }
}

/// Extend the local finalized-history cache by one block.
pub fn advance_local_history_cache(
    witness: &AcceptedBlockClaimWitness,
    block_header: &BlockHeader,
    prev_acc: &ChainAccumulator,
    _prev_cache: Option<&LocalHistoryCache>,
) -> LocalHistoryCache {
    let block_hash = noid_chain::hash_block_header(block_header);
    let acc = prev_acc.extend(
        block_header.state_root,
        block_hash,
        block_header.height,
        witness.chain_claim,
    );
    LocalHistoryCache {
        acc,
        block_height: block_header.height,
        chain_claim: witness.chain_claim,
    }
}

/// Produce the local cache entry for genesis.
pub fn init_genesis_history_cache() -> LocalHistoryCache {
    use noid_chain::consensus::genesis::genesis_header;

    let genesis = genesis_header();
    let pre_genesis_acc = ChainAccumulator {
        height: 0,
        state_root: [0u8; 32],
        chain_hash: [0u8; 32],
    };
    advance_local_history_cache(
        &accepted_block_claim_witness([Block128::ZERO; 2]),
        &genesis,
        &pre_genesis_acc,
        None,
    )
}

/// Empty witness for genesis and coinbase-only blocks with no detached proof.
pub fn empty_accepted_block_witness() -> AcceptedBlockClaimWitness {
    accepted_block_claim_witness([Block128::ZERO; 2])
}

/// Wrap a canonical accepted-block claim for local history-cache folding.
pub fn accepted_block_claim_witness(chain_claim: [Block128; 2]) -> AcceptedBlockClaimWitness {
    AcceptedBlockClaimWitness { chain_claim }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::genesis_accumulator;
    use noid_chain::consensus::genesis::{genesis_header, genesis_state_root};
    use noid_chain::hash_block_header;

    #[test]
    fn genesis_local_history_cache_has_correct_accumulator() {
        let cache = init_genesis_history_cache();

        let genesis = genesis_header();
        let genesis_hash = hash_block_header(&genesis);
        let expected_acc = genesis_accumulator(genesis_state_root(), genesis_hash);

        assert_eq!(cache.block_height, 0, "genesis cache must be at height 0");
        assert_eq!(cache.acc.chain_hash, expected_acc.chain_hash);
        assert_eq!(cache.acc.state_root, genesis.state_root);
        assert_eq!(cache.chain_claim, [Block128::ZERO; 2]);
    }

    #[test]
    fn accepted_block_claim_witness_sets_only_chain_claim() {
        let claim = [Block128::from(0x1234_u128), Block128::from(0x5678_u128)];
        let witness = accepted_block_claim_witness(claim);
        assert_eq!(witness.chain_claim, claim);
    }
}
