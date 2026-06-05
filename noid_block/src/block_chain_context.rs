// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `BlockChainContext` — extends `ChainContext` with recursive proof tracking.
//!
//! `ChainContext` (in `noid_chain`) handles all native consensus state.
//! `BlockChainContext` wraps it and adds:
//!
//! - `recursive_proof: Option<RecursiveBlockProof>` — the current O(1) chain proof.
//! - `update_recursive_proof(block_proof)` — advances the recursive proof by one block.
//! - `init_from_genesis()` — initialises both consensus state and genesis recursive proof.
//!
//! The recursive proof is updated **asynchronously** relative to block application:
//! call `apply_block_consensus` (or `apply_block_full`) to advance consensus state,
//! then call `update_recursive_proof` with the block's `BlockProof` when ready.
//!
//! # Dependency note
//!
//! `noid_chain` cannot depend on `noid_recursive` (would be circular).
//! `BlockChainContext` lives in `noid_block` which depends on both.

use noid_chain::block::Block;
use noid_chain::consensus::ConsensusError;
use noid_chain::ChainContext;
use noid_recursive::{
    accumulator::genesis_accumulator,
    prove::{prove_genesis_recursive, prove_recursive_step, RecursiveBlockProof},
    witness::BlockReplayWitness,
};

use crate::BlockProof;

/// Full chain context: consensus state + recursive proof.
///
/// The two components can advance at different rates:
/// - Consensus state advances synchronously on each `apply_block_consensus` call.
/// - Recursive proof advances asynchronously via `update_recursive_proof`.
///
/// The recursive proof is never required for consensus validity — it exists
/// only for O(1) light-client sync. Missing or lagging recursive proof does
/// not affect block validation.
pub struct BlockChainContext {
    /// Native consensus chain state (headers, nullifiers, UTXO state, undo logs).
    pub consensus: ChainContext,
    /// Current recursive chain proof. `None` only if prove_genesis_recursive
    /// failed or was skipped; this should be treated as DEGRADED mode (P.19).
    pub recursive_proof: Option<RecursiveBlockProof>,
}

impl BlockChainContext {
    /// Initialise from genesis: build `ChainContext` + genesis recursive proof.
    ///
    /// The genesis recursive proof is produced synchronously here (~2s on first call).
    /// Subsequent recursive steps are much cheaper (~0.5s) since they only cover
    /// one block each.
    ///
    /// If the genesis recursive proof should be deferred (e.g. for fast startup),
    /// use `init_from_genesis_no_proof()` and call `bootstrap_recursive_proof()` later.
    pub fn init_from_genesis() -> Self {
        let consensus = ChainContext::init_from_genesis();
        let recursive_proof = Some(prove_genesis_recursive());
        Self {
            consensus,
            recursive_proof,
        }
    }

    /// Initialise from genesis WITHOUT producing the recursive proof.
    ///
    /// The node starts in DEGRADED recursive mode. Call `bootstrap_recursive_proof()`
    /// when ready to start the recursive chain.
    pub fn init_from_genesis_no_proof() -> Self {
        Self {
            consensus: ChainContext::init_from_genesis(),
            recursive_proof: None,
        }
    }

    /// Generate the genesis recursive proof (used after `init_from_genesis_no_proof`).
    pub fn bootstrap_recursive_proof(&mut self) {
        self.recursive_proof = Some(prove_genesis_recursive());
    }

    // -----------------------------------------------------------------------
    // Block application (consensus only)
    // -----------------------------------------------------------------------

    /// Apply the next block using native consensus validation only (no ZK).
    ///
    /// Does NOT verify the block's ZK proof. For full ZK validation, use
    /// `noid_block::validate_block_full` before calling this.
    ///
    /// Does NOT update the recursive proof. Call `update_recursive_proof`
    /// after this to advance the recursive chain.
    pub fn apply_block_consensus(
        &mut self,
        block: &Block,
        local_time: u64,
    ) -> Result<[u8; 32], ConsensusError> {
        self.consensus.apply_next_block(block, local_time)
    }

    // -----------------------------------------------------------------------
    // Recursive proof update
    // -----------------------------------------------------------------------

    /// Extract `BlockReplayWitness` from a `BlockProof` and advance the
    /// recursive chain proof by one step.
    ///
    /// MUST be called after `apply_block_consensus` (or `apply_block_full`)
    /// so that `self.consensus.tip_header()` reflects the newly applied block.
    ///
    /// Returns a reference to the new recursive proof.
    pub fn update_recursive_proof(&mut self, block_proof: &BlockProof) -> &RecursiveBlockProof {
        let witness = extract_replay_witness(block_proof);
        let header = self.consensus.tip_header().clone();

        // prev_acc: the accumulator BEFORE this block (from the previous recursive proof).
        // If there's no previous proof yet (shouldn't happen after genesis init),
        // fall back to the pre-genesis zero accumulator.
        let prev_acc = match &self.recursive_proof {
            Some(prev) => prev.acc.clone(),
            None => {
                // Reconstruct what the accumulator should be at the parent block.
                // This path only happens in DEGRADED mode (recursive proof was skipped).
                // Use genesis_accumulator for the parent of block 1, zero for earlier.
                use noid_chain::consensus::genesis::{genesis_header, genesis_state_root};
                use noid_chain::hash_block_header;
                if header.height <= 1 {
                    let g = genesis_header();
                    genesis_accumulator(genesis_state_root(), hash_block_header(&g))
                } else {
                    // Cannot safely reconstruct — return without updating.
                    // Caller must bootstrap from a known-good recursive proof.
                    return self
                        .recursive_proof
                        .as_ref()
                        .expect("recursive_proof must exist after bootstrap");
                }
            }
        };

        let prev_ref = self.recursive_proof.as_ref();
        let new_proof = prove_recursive_step(&witness, &header, &prev_acc, prev_ref);
        self.recursive_proof = Some(new_proof);
        self.recursive_proof.as_ref().unwrap()
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

    /// Recursive proof lag: how many blocks behind the consensus tip is the
    /// recursive proof. 0 = fully caught up (NORMAL mode).
    pub fn recursive_lag(&self) -> u64 {
        match &self.recursive_proof {
            Some(p) => self.consensus.tip_height.saturating_sub(p.block_height),
            None => self.consensus.tip_height + 1,
        }
    }

    /// True if in NORMAL mode (recursive proof ≤ 3 blocks behind).
    pub fn recursive_normal(&self) -> bool {
        self.recursive_lag() <= 3
    }

    /// True if light clients should fall back to native verification
    /// (recursive proof > FINALITY_DEPTH blocks behind).
    pub fn recursive_fallback(&self) -> bool {
        use noid_chain::consensus::params::FINALITY_DEPTH;
        self.recursive_lag() > FINALITY_DEPTH
    }
}

// ---------------------------------------------------------------------------
// BlockProof → BlockReplayWitness extraction
// ---------------------------------------------------------------------------

/// Extract the `BlockReplayWitness` from a `BlockProof`.
///
/// This is the inverse of the prover's assembly step. The witness contains
/// all algebraic data needed by the recursive prover, extracted from the
/// already-proven block proof.
pub fn extract_replay_witness(proof: &BlockProof) -> BlockReplayWitness {
    BlockReplayWitness::from_parts(
        proof.commitment.cap.clone(),
        proof.state_binding_algebraics.clone(),
        proof.block_col_openings.clone(),
        proof.block_multipoint_rounds.clone(),
        proof.mixed_opening.fri_proof.clone(),
        proof.mixed_opening.all_openings.clone(),
    )
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
    fn init_no_proof_starts_degraded() {
        let ctx = BlockChainContext::init_from_genesis_no_proof();
        assert!(ctx.recursive_proof.is_none());
        // Lag = tip_height + 1 = 0 + 1 = 1 block behind.
        assert_eq!(ctx.recursive_lag(), 1);
    }

    #[test]
    fn recursive_lag_zero_after_genesis_init() {
        // This test is fast because prove_genesis_recursive uses compact FRI
        // with 0 FRI rounds (LOG_ROWS=8, COMPACT_TAU=8 → n_rounds=0).
        let ctx = BlockChainContext::init_from_genesis();
        // After init, recursive proof is at height 0 = tip_height.
        assert_eq!(ctx.recursive_lag(), 0);
        assert!(ctx.recursive_normal());
    }

    #[test]
    fn genesis_recursive_proof_accumulator_is_correct() {
        let ctx = BlockChainContext::init_from_genesis();
        let proof = ctx.recursive_proof.as_ref().unwrap();

        use noid_chain::consensus::genesis::genesis_header;
        let genesis = genesis_header();
        let genesis_hash = hash_block_header(&genesis);
        let expected_acc = genesis_accumulator(genesis_state_root(), genesis_hash);

        assert_eq!(proof.block_height, 0);
        assert_eq!(
            proof.acc.chain_hash, expected_acc.chain_hash,
            "recursive proof accumulator must match genesis_accumulator"
        );
        assert_eq!(proof.acc.state_root, genesis.state_root);
    }

    #[test]
    fn apply_block_consensus_increments_tip() {
        use noid_chain::block::{compute_tx_root, Block};
        use noid_chain::block_header::BlockHeader;
        use noid_chain::consensus::{
            params::{BLOCK_TIME, GENESIS_TARGET},
            pow::full_block_hash,
        };
        use noid_poseidon2b::primitives::Address;
        use rayon::prelude::*;

        let mut ctx = BlockChainContext::init_from_genesis_no_proof();

        // Build a trivial empty block.
        let parent = ctx.consensus.tip_header().clone();
        let new_root = ctx.consensus.state.state_root();

        let mut header = BlockHeader {
            prev_block_hash: full_block_hash(&parent),
            state_root: new_root,
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: parent.log_slots,
            active_slot_count: 0,
            alloc_counter: 0,
        };

        // GENESIS_TARGET = 2^228 requires avg 2^28 ≈ 268 M hash attempts.
        // This is the only PoW-mining test in this binary, so rayon gets
        // full use of all CPU cores without contention from other tests.
        // Expected wall time: ~1 s on a multi-core machine.
        {
            use noid_chain::consensus::pow::search_pow;
            let chunk = 10_000_000u128;
            header.nonce = (0u64..300)
                .into_par_iter()
                .find_map_any(|i| search_pow(&header, i as u128 * chunk, chunk))
                .expect("mine: no nonce found in 3 B attempts (GENESIS_TARGET=2^228)");
        }

        let block = Block {
            header,
            transactions: vec![],
        };

        let result = ctx.apply_block_consensus(&block, block.header.timestamp + 1);
        assert!(result.is_ok(), "empty block should apply: {:?}", result);
        assert_eq!(ctx.tip_height(), 1);
        // No recursive proof at all (init_from_genesis_no_proof); lag = tip_height + 1 = 2.
        assert_eq!(ctx.recursive_lag(), 2);
    }
}
