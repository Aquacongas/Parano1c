// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Rolling chain accumulator proven by each recursive step.

use noid_chain::fri_state::StateRoot;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::primitives::Digest;

/// Rolling accumulator for the recursive chain proof.
///
/// Each block extends this by one step; `verify_tip` checks
/// that the accumulator reaches the expected genesis state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainAccumulator {
    /// Block height (number of blocks applied since genesis).
    pub height: u64,
    /// State root after all blocks up to `height` are applied.
    pub state_root: StateRoot,
    /// Rolling Poseidon2b chain hash:
    ///
    ///   chain_hash_0 = compress(ZERO, compress(H_BLOCK(genesis), claim_bytes_0))
    ///   chain_hash_n = compress(chain_hash_{n-1}, compress(H_BLOCK(header_n), claim_bytes_n))
    ///
    /// where `claim_bytes_n` = `block_initial_claim` zero-padded to 32 bytes.
    ///
    /// Binding both `H_BLOCK` (which includes `proof_transcript_hash`) and
    /// `block_initial_claim` into a single 32-byte commitment prevents a forger
    /// from substituting a null-witness `block_initial_claim = ZERO` for a block
    /// that has a real ZK proof: the resulting `chain_hash` would diverge from
    /// the value computed by honest nodes, making the forgery detectable.
    pub chain_hash: Digest,
}

impl ChainAccumulator {
    /// Extend the accumulator by one block.
    ///
    /// # Parameters
    ///
    /// - `block_hash`          = `hash_block_header(&header)` (embeds `proof_transcript_hash`)
    /// - `block_initial_claim` = multipoint sumcheck target from the block's STARK proof.
    ///                           `Block128::ZERO` for coinbase-only / genesis blocks.
    pub fn extend(
        &self,
        new_state_root: StateRoot,
        block_hash: Digest,
        new_height: u64,
        block_initial_claim: Block128,
    ) -> Self {
        use noid_poseidon2b::native::compress;
        // Encode claim as 32 bytes (LE u128, zero-padded).
        let mut claim_bytes = [0u8; 32];
        claim_bytes[..16].copy_from_slice(&block_initial_claim.to_u128().to_le_bytes());
        // chain_hash = compress(prev, compress(H_BLOCK, claim))
        let inner = compress(&block_hash, &claim_bytes);
        let chain_hash = compress(&self.chain_hash, &inner);
        Self {
            height: new_height,
            state_root: new_state_root,
            chain_hash,
        }
    }
}

/// Build the genesis accumulator for a given genesis state root and genesis
/// block hash.
///
/// Genesis uses a null witness so `block_initial_claim = ZERO`.
/// Formula: `compress(ZERO, compress(genesis_block_hash, [0;32]))`
/// — identical to calling `pre_genesis.extend(state_root, block_hash, 0, ZERO)`
/// on an all-zero pre-genesis accumulator.
pub fn genesis_accumulator(
    genesis_state_root: StateRoot,
    genesis_block_hash: Digest,
) -> ChainAccumulator {
    let pre_genesis = ChainAccumulator {
        height: 0,
        state_root: [0u8; 32],
        chain_hash: [0u8; 32],
    };
    // Genesis block has no ZK proof — block_initial_claim is ZERO.
    pre_genesis.extend(genesis_state_root, genesis_block_hash, 0, Block128::ZERO)
}
