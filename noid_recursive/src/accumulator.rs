// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

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
    /// where `claim_bytes_n` = canonical 32-byte `chain_claim`.
    ///
    /// Binding both the semantic block id and the canonical chain claim into a
    /// single 32-byte commitment prevents a forger from substituting a different
    /// local claim for a covered block: the resulting `chain_hash` would diverge
    /// from the value computed by honest nodes, making the mismatch detectable.
    pub chain_hash: Digest,
    /// Active slot count after all blocks up to `height` are applied — the
    /// consensus-continuity counter the chain rules carry across blocks
    /// (each block pins its start counter to its claim's PARENT counter and
    /// its end counter to its header's child counter; the boundary equality
    /// start == prev.end closes the chain).
    pub active_slot_count: u64,
    /// Allocation counter after all blocks up to `height` are applied —
    /// same continuity discipline as `active_slot_count`.
    pub alloc_counter: u64,
}

impl ChainAccumulator {
    /// Extend the accumulator by one block.
    ///
    /// # Parameters
    ///
    /// - `block_hash`  = `hash_block_header(&header)` semantic block id.
    /// - `chain_claim` = canonical 32-byte block claim folded into recursive
    ///   history. `[Block128::ZERO; 2]` for genesis.
    /// - `active_slot_count` / `alloc_counter` = the block header's child
    ///   consensus counters.
    #[allow(clippy::too_many_arguments)]
    pub fn extend(
        &self,
        new_state_root: StateRoot,
        block_hash: Digest,
        new_height: u64,
        chain_claim: [Block128; 2],
        active_slot_count: u64,
        alloc_counter: u64,
    ) -> Self {
        use noid_poseidon2b::native::compress;
        // Encode claim as 32 bytes (two LE u128 lanes).
        let mut claim_bytes = [0u8; 32];
        claim_bytes[..16].copy_from_slice(&chain_claim[0].to_u128().to_le_bytes());
        claim_bytes[16..].copy_from_slice(&chain_claim[1].to_u128().to_le_bytes());
        // chain_hash = compress(prev, compress(H_BLOCK, claim))
        let inner = compress(&block_hash, &claim_bytes);
        let chain_hash = compress(&self.chain_hash, &inner);
        Self {
            height: new_height,
            state_root: new_state_root,
            chain_hash,
            active_slot_count,
            alloc_counter,
        }
    }
}

/// Build the genesis accumulator for a given genesis state root and genesis
/// block hash.
///
/// Genesis uses a null witness so `chain_claim = [ZERO; 2]`.
/// Formula: `compress(ZERO, compress(genesis_block_hash, [0;32]))`
/// — identical to calling `pre_genesis.extend(state_root, block_hash, 0,
/// [ZERO; 2])` on an all-zero pre-genesis accumulator.
pub fn genesis_accumulator(
    genesis_state_root: StateRoot,
    genesis_block_hash: Digest,
) -> ChainAccumulator {
    let pre_genesis = ChainAccumulator {
        height: 0,
        state_root: [0u8; 32],
        chain_hash: [0u8; 32],
        active_slot_count: 0,
        alloc_counter: 0,
    };
    // Genesis block has no BlockProof (and mints nothing: zero counters).
    pre_genesis.extend(
        genesis_state_root,
        genesis_block_hash,
        0,
        [Block128::ZERO; 2],
        0,
        0,
    )
}
