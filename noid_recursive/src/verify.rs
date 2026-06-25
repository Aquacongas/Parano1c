// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Verification helpers for the local finalized-history cache.
//!
//! These helpers check deterministic accumulator consistency only. They do not
//! make snapshots trustless; public snapshot sync must remain disabled until the
//! recursive verifier proves the full accepted-block batch relation.

use crate::accumulator::ChainAccumulator;
use crate::prove::LocalHistoryCache;

#[derive(Debug)]
pub enum RecVerifyError {
    /// The new accumulator's state root does not match the block header.
    NewStateRootMismatch,
    /// The chain hash does not match the expected value.
    ChainHashMismatch,
    /// Height is not monotonically increasing by 1.
    HeightMismatch,
    /// Accumulator mismatch between local cache and tip context.
    TipAccumulatorMismatch,
    /// Caller attempted to use the local cache as public snapshot authority.
    PublicSnapshotAuthorityDisabled,
}

/// Check one locally-produced cache object against retained header roots.
pub fn verify_local_history_cache_step(
    cache: &LocalHistoryCache,
    _acc_prev_state_root: &[u8; 32],
    expected_new_state_root: &[u8; 32],
) -> Result<(), RecVerifyError> {
    if cache.acc.state_root != *expected_new_state_root {
        return Err(RecVerifyError::NewStateRootMismatch);
    }
    if cache.block_height != cache.acc.height {
        return Err(RecVerifyError::HeightMismatch);
    }
    Ok(())
}

/// Verify the local cache against a local tip context.
pub fn verify_tip(
    cache: &LocalHistoryCache,
    tip_prev_state_root: &[u8; 32],
    tip_height: u64,
    _genesis_acc: &ChainAccumulator,
    expected_chain_hash: Option<&[u8; 32]>,
) -> Result<(), RecVerifyError> {
    if cache.acc.state_root != *tip_prev_state_root {
        return Err(RecVerifyError::TipAccumulatorMismatch);
    }
    if tip_height != cache.acc.height + 1 {
        return Err(RecVerifyError::HeightMismatch);
    }
    if let Some(expected) = expected_chain_hash {
        if cache.acc.chain_hash != *expected {
            return Err(RecVerifyError::ChainHashMismatch);
        }
    }
    Ok(())
}

/// Public arbitrary-peer snapshot proofs are disabled until the full recursive
/// accepted-block verifier exists.
pub fn reject_public_snapshot_authority() -> Result<(), RecVerifyError> {
    Err(RecVerifyError::PublicSnapshotAuthorityDisabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::genesis_accumulator;
    use noid_core::Block128;

    #[test]
    fn verify_error_types_are_debug() {
        let _ = format!("{:?}", RecVerifyError::ChainHashMismatch);
        let _ = format!("{:?}", RecVerifyError::PublicSnapshotAuthorityDisabled);
    }

    #[test]
    fn chain_hash_compress_matches_accumulator() {
        use noid_poseidon2b::native::compress;

        let genesis = genesis_accumulator([0x11u8; 32], [0x22u8; 32]);
        let block_hash = [0x33u8; 32];
        let claim = [
            Block128::from(0xDEAD_BEEFu128),
            Block128::from(0xFACE_FEEDu128),
        ];
        let extended = genesis.extend([0x44u8; 32], block_hash, 1, claim);
        let mut claim_bytes = [0u8; 32];
        claim_bytes[..16].copy_from_slice(&claim[0].to_u128().to_le_bytes());
        claim_bytes[16..].copy_from_slice(&claim[1].to_u128().to_le_bytes());
        let expected = compress(&genesis.chain_hash, &compress(&block_hash, &claim_bytes));
        assert_eq!(extended.chain_hash, expected);
    }
}
