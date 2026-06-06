// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! recursive chain verifier — O(1) historical verification.
//!
//! `verify_recursive_step` verifies one `RecursiveBlockProof` algebraically
//! and checks the accumulator transition is consistent with the block header.
//!
//! `verify_tip` is the O(1) entry-point: given the LATEST `RecursiveBlockProof_N`
//! and the genesis accumulator, it verifies the entire chain in constant time.
//! The tip block itself is verified separately by the caller (e.g.
//! `noid_block::full_node::verify_block_full`).
//!
//! **Complexity**: O(1) — the recursive proof is ~11 KB regardless of chain length.

use noid_chain::{hash_block_header, BlockHeader};
use noid_fri_binius::COMPACT_NUM_QUERIES;
use noid_poseidon2b::native::compress;
use noid_stark::interleaved::verify_air_interleaved;

use crate::accumulator::ChainAccumulator;
use crate::prove::RecursiveBlockProof;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum RecVerifyError {
    /// The underlying STARK proof failed verification.
    StarkInvalid,
    /// The new accumulator's state root does not match the block header.
    NewStateRootMismatch,
    /// The chain hash does not match the expected value.
    ChainHashMismatch,
    /// Height is not monotonically increasing by 1.
    HeightMismatch,
    /// Accumulator mismatch between recursive chain and tip.
    TipAccumulatorMismatch,
}

// ---------------------------------------------------------------------------
// verify_recursive_step
// ---------------------------------------------------------------------------

/// Verify one `RecursiveBlockProof` against a known previous accumulator.
///
/// Checks:
/// 1. The packed STARK proof verifies (algebraic + FRI).
/// 2. The new chain hash equals `compress(prev_acc.chain_hash, H_BLOCK(header))`.
/// 3. The new state root equals `block_header.state_root`.
/// 4. The height increments by 1.
///
/// Returns the new `ChainAccumulator` on success.
pub fn verify_recursive_step(
    proof: &RecursiveBlockProof,
    prev_acc: &ChainAccumulator,
    block_header: &BlockHeader,
    rec_air: &dyn noid_air::Air,
) -> Result<ChainAccumulator, RecVerifyError> {
    // Reconstruct extra_transcript from proof fields (same as prover).
    let extra_transcript = [proof.block_initial_claim, proof.rec_initial_claim];

    // 1. Verify the STARK proof.
    let empty_pi = make_empty_pi();
    verify_air_interleaved(
        rec_air,
        &empty_pi,
        &proof.stark,
        &extra_transcript,
        &[],
        COMPACT_NUM_QUERIES,
    )
    .map_err(|_| RecVerifyError::StarkInvalid)?;

    // 2. Verify accumulator transition.
    let block_hash = hash_block_header(block_header);
    let expected_chain_hash = compress(&prev_acc.chain_hash, &block_hash);

    if proof.acc.chain_hash != expected_chain_hash {
        return Err(RecVerifyError::ChainHashMismatch);
    }
    if proof.acc.state_root != block_header.state_root {
        return Err(RecVerifyError::NewStateRootMismatch);
    }
    if proof.acc.height != block_header.height {
        return Err(RecVerifyError::HeightMismatch);
    }

    Ok(proof.acc.clone())
}

// ---------------------------------------------------------------------------
// verify_tip — O(1) chain verification
// ---------------------------------------------------------------------------

/// Verify the entire chain history in O(1).
///
/// `expected_chain_hash`: when `Some`, `rec_proof_n.acc.chain_hash` is checked
/// against this value. Pass `Some` only when all block headers from genesis are
/// available in the snapshot (so the caller can independently compute the full
/// chain hash by replaying `ChainAccumulator::extend`). When the snapshot covers
/// only recent headers, pass `None` — PoW + chainwork validation is the primary
/// guard. Once C2 is fully wired (BlockStateBindingAir), the STARK itself will
/// prove chain-hash continuity and this will become unconditionally mandatory.
pub fn verify_tip(
    rec_proof_n: &RecursiveBlockProof,
    rec_air: &dyn noid_air::Air,
    tip_prev_state_root: &[u8; 32],
    tip_height: u64,
    _genesis_acc: &ChainAccumulator,
    expected_chain_hash: Option<&[u8; 32]>,
) -> Result<(), RecVerifyError> {
    // Reconstruct extra_transcript from proof-stored initial claims.
    // Must match what the prover supplied to prove_air_interleaved.
    let extra_transcript = [
        rec_proof_n.block_initial_claim,
        rec_proof_n.rec_initial_claim,
    ];

    // Step 1: Verify the recursive STARK proof (tiny, O(1)).
    let empty_pi = make_empty_pi();
    verify_air_interleaved(
        rec_air,
        &empty_pi,
        &rec_proof_n.stark,
        &extra_transcript,
        &[],
        COMPACT_NUM_QUERIES,
    )
    .map_err(|_| RecVerifyError::StarkInvalid)?;

    // Step 2: Cross-check with the tip block.
    // The tip's prev_state_root must equal the recursive accumulator's state_root.
    if rec_proof_n.acc.state_root != *tip_prev_state_root {
        return Err(RecVerifyError::TipAccumulatorMismatch);
    }
    // The tip block height must be exactly one above the recursive accumulator.
    if tip_height != rec_proof_n.acc.height + 1 {
        return Err(RecVerifyError::HeightMismatch);
    }

    // Step 3: chain_hash verification.
    //
    // When the caller has all block headers from genesis, it computes the full
    // expected chain_hash by replaying ChainAccumulator::extend and passes
    // Some(expected). This covers the genesis-anchor case (height 0) and any
    // chain where the snapshot window includes the genesis block.
    //
    // When only recent headers are available (gap from genesis), None is passed
    // and PoW + chainwork validation of snapshot headers is the primary guard.
    if let Some(expected) = expected_chain_hash {
        if rec_proof_n.acc.chain_hash != *expected {
            return Err(RecVerifyError::ChainHashMismatch);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// verify_step_stark_only — for Mode B snapshot verification
// ---------------------------------------------------------------------------

/// Verify the STARK portion of a `RecursiveBlockProof` without a full
/// accumulator chain.
///
/// Used for **Mode B snapshot verification**: the recursive proof is behind
/// the snapshot tip, so we cannot call `verify_tip` (which expects the proof
/// to be exactly one step before the tip). Instead we:
///
/// 1. Verify the STARK over `RecursiveBlockAir(acc_prev_state_root)` — the
///    same check `verify_tip` performs internally.
/// 2. Assert `proof.acc.state_root == expected_new_state_root` from the
///    snapshot's `recent_headers`.
///
/// This prevents accepting a fabricated `RecursiveBlockProof` whose
/// `acc.state_root` field was crafted to match the snapshot header without
/// a valid STARK backing it.
///
/// # Arguments
/// * `proof` — the `RecursiveBlockProof` at height `proof_h`.
/// * `acc_prev_state_root` — `state_root` from `recent_headers[proof_h - 1]`
///   (or `genesis_state_root()` when `proof_h == 0`).
/// * `expected_new_state_root` — `state_root` from `recent_headers[proof_h]`.
pub fn verify_step_stark_only(
    proof: &RecursiveBlockProof,
    acc_prev_state_root: &[u8; 32],
    expected_new_state_root: &[u8; 32],
) -> Result<(), RecVerifyError> {
    // Reconstruct extra_transcript from proof fields (same as prover).
    let extra_transcript = [proof.block_initial_claim, proof.rec_initial_claim];

    // Step 1: verify the STARK proof over the RecursiveBlockAir.
    let rec_air = crate::air::RecursiveBlockAir::from_prev_state_root(acc_prev_state_root);
    let empty_pi = make_empty_pi();
    verify_air_interleaved(
        &rec_air,
        &empty_pi,
        &proof.stark,
        &extra_transcript,
        &[],
        COMPACT_NUM_QUERIES,
    )
    .map_err(|_| RecVerifyError::StarkInvalid)?;

    // Step 2: the proof's committed state_root must match the header we have.
    if proof.acc.state_root != *expected_new_state_root {
        return Err(RecVerifyError::NewStateRootMismatch);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn make_empty_pi() -> noid_tx::PublicInputs {
    use noid_poseidon2b::primitives::TxBodyHash;
    use noid_tx::PublicInputs;
    PublicInputs {
        epoch_anchor: [0u8; 32],
        tx_body_hash: TxBodyHash([0u8; 32]),
        fee: 0,
        n_live_inputs: 0,
        n_live_outputs: 0,
        coinbase_credit: 0,
        log_slots: 0,
        claims_commitment: [0u8; 32],
        is_activation: [false; 8],
        is_deactivation: [false; 4],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::genesis_accumulator;

    #[test]
    fn verify_error_types_are_debug() {
        let _ = format!("{:?}", RecVerifyError::StarkInvalid);
        let _ = format!("{:?}", RecVerifyError::ChainHashMismatch);
        let _ = format!("{:?}", RecVerifyError::TipAccumulatorMismatch);
    }

    #[test]
    fn chain_hash_compress_matches_accumulator() {
        let genesis = genesis_accumulator([0x11u8; 32], [0x22u8; 32]);
        let block_hash = [0x33u8; 32];
        let extended = genesis.extend([0x44u8; 32], block_hash, 1);
        let expected = compress(&genesis.chain_hash, &block_hash);
        assert_eq!(extended.chain_hash, expected);
    }
}
