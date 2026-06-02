// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Rolling chain accumulator proven by each recursive step.

use noid_chain::fri_state::StateRoot;
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
    ///   chain_hash_0 = compress(ZERO_DIGEST, H_BLOCK(genesis_header))
    ///   chain_hash_n = compress(chain_hash_{n-1}, H_BLOCK(header_n))
    ///
    /// Binds every block header (including `proof_transcript_hash`) into
    /// a single 32-byte commitment, providing per-tx FS security without
    /// needing in-circuit FS derivation.
    pub chain_hash: Digest,
}

impl ChainAccumulator {
    /// Extend the accumulator by one block.
    ///
    /// `block_hash` = `hash_block_header(&header)` (the canonical `H_BLOCK`
    /// digest, which embeds `proof_transcript_hash` for soundness).
    pub fn extend(&self, new_state_root: StateRoot, block_hash: Digest, new_height: u64) -> Self {
        use noid_poseidon2b::native::compress;
        let chain_hash = compress(&self.chain_hash, &block_hash);
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
/// Uses `compress(ZERO_DIGEST, genesis_block_hash)` so the chain hash is
/// domain-separated from any mid-chain accumulator value.
pub fn genesis_accumulator(
    genesis_state_root: StateRoot,
    genesis_block_hash: Digest,
) -> ChainAccumulator {
    use noid_poseidon2b::native::compress;
    let zero: Digest = [0u8; 32];
    let chain_hash = compress(&zero, &genesis_block_hash);
    ChainAccumulator {
        height: 0,
        state_root: genesis_state_root,
        chain_hash,
    }
}
