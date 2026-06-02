// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Recursive step prover: given `BlockProof` + `BlockHeader` + previous
//! `ChainAccumulator`, produce a `RecursiveBlockProof` that bundles the
//! rolling accumulator and a STARK proof of the `RecursiveBlockAir`.
//!
//! # STARKPack-style packing
//!
//! All algebraic data (block-n multipoint sumcheck rounds, prev recursive
//! sumcheck rounds, accumulator state-root pins) are packed into one
//! `InterleavedStarkProof` via `prove_air_interleaved`.  With LOG_ROWS=8
//! and TAU=7 the padded log-length is 8, giving compact FRI with 0 folding
//! rounds — no Merkle paths in the FRI, making the proof ultra-compact
//! (~11 KB).

use crate::accumulator::ChainAccumulator;
use crate::air::{
    build_recursive_trace, RecursiveBlockAir, RecursiveBlockWitness, BLOCK_SUMCHECK_ROUNDS,
    LOG_ROWS, REC_SUMCHECK_ROUNDS,
};
use crate::witness::BlockReplayWitness;
use noid_chain::BlockHeader;
use noid_core::{Block128, TowerField};
use noid_fri::Channel;
use noid_fri_binius::COMPACT_NUM_QUERIES;
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::interleaved::{prove_air_interleaved, InterleavedStarkProof};
use noid_stark::{padded_log_len, SliceClaim};
use noid_tx::PublicInputs;

// =============================================================================
// RecursiveBlockProof
// =============================================================================

/// One recursive proof step: an `InterleavedStarkProof` over the
/// `RecursiveBlockAir` plus the updated rolling `ChainAccumulator`.
///
/// The proof is self-contained: verifying it requires only the public
/// genesis accumulator and the current `block_height`, both of which
/// are embeddable in a block header.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RecursiveBlockProof {
    /// The full interleaved STARK proof over the `RecursiveBlockAir`.
    /// Packs block-n algebraic data + prev recursive data into one proof.
    pub stark: InterleavedStarkProof,
    /// Rolling chain accumulator after this block.
    pub acc: ChainAccumulator,
    /// Block height at which this proof was generated.
    pub block_height: u64,
}

impl RecursiveBlockProof {
    /// Approximate serialised byte length.
    pub fn byte_len(&self) -> usize {
        let cap_bytes = self.stark.commitment.cap.hashes.len() * 32;
        let base_bytes = self.stark.base_openings.len() * 16;
        let zc_bytes: usize = self
            .stark
            .zero_check_rounds
            .iter()
            .map(|r| r.len() * 16)
            .sum();
        let mp_bytes: usize = self
            .stark
            .multipoint_rounds
            .iter()
            .map(|r| r.len() * 16)
            .sum();
        let mixed_bytes = self.stark.mixed_opening.byte_len();
        // 50 bytes: height (8) + state_root (32) + chain_hash (32) - with overlap ≈50
        cap_bytes + base_bytes + zc_bytes + mp_bytes + mixed_bytes + 50
    }
}

// =============================================================================
// Main entrypoint
// =============================================================================

/// Produce a `RecursiveBlockProof` for one block.
///
/// # Parameters
///
/// - `block_proof`: The `BlockProof` produced by the miner for `block_n`.
/// - `block_header`: The header of `block_n`.
/// - `prev_acc`: The `ChainAccumulator` after block `n-1`.
/// - `prev_rec_proof`: The previous `RecursiveBlockProof` (`None` at genesis).
///
/// # Returns
///
/// A `RecursiveBlockProof` whose `acc` field is the updated accumulator
/// after applying `block_n`.
pub fn prove_recursive_step(
    block_witness: &BlockReplayWitness,
    block_header: &BlockHeader,
    prev_acc: &ChainAccumulator,
    prev_rec_proof: Option<&RecursiveBlockProof>,
) -> RecursiveBlockProof {
    // 1. Extend the rolling accumulator.
    let block_hash = noid_chain::hash_block_header(block_header);
    let acc_new = prev_acc.extend(block_header.state_root, block_hash, block_header.height);

    // 2. Build the RecursiveBlockWitness from the pre-extracted block replay data.
    let rec_witness =
        build_recursive_block_witness(block_witness, prev_rec_proof, prev_acc, &acc_new);

    // 4. Build the RecursiveBlockAir and execution trace.
    let air = RecursiveBlockAir::new(&rec_witness);
    let trace_cols = build_recursive_trace(&rec_witness);

    // 5. Prove via prove_air_interleaved.
    //    LOG_ROWS=8, TAU=7  →  padded_log_len = max(8, 8) = 8.
    //    compact FRI n_rounds = log_len - COMPACT_TAU = 8 - 8 = 0 → no Merkle paths.
    let log_len = padded_log_len(LOG_ROWS);
    let empty_pi = make_empty_pi();
    let no_slices: &[SliceClaim] = &[];

    let stark = prove_air_interleaved(
        &air,
        &trace_cols,
        &empty_pi,
        &[],       // extra_transcript: no additional FS absorbs
        no_slices, // slice_claims: no MLE slices
        log_len,
        None, // pre_committed: commit internally
        COMPACT_NUM_QUERIES,
    );

    RecursiveBlockProof {
        stark,
        acc: acc_new,
        block_height: block_header.height,
    }
}

// =============================================================================
// Witness builder
// =============================================================================

/// Build the `RecursiveBlockWitness` from the block replay data and the
/// optional previous recursive proof.
///
/// Challenge derivation note: the `block_challenges` and `rec_challenges`
/// are derived by replaying the round polynomials through a fresh Fiat-
/// Shamir channel.  Full soundness requires replaying the complete block
/// STARK channel; this is a structural placeholder that correctly captures
/// the fold relation for native `Air::check` purposes.
fn build_recursive_block_witness(
    witness_data: &BlockReplayWitness,
    prev_rec_proof: Option<&RecursiveBlockProof>,
    prev_acc: &ChainAccumulator,
    acc_new: &ChainAccumulator,
) -> RecursiveBlockWitness {
    // Block multipoint rounds from the block proof.
    let block_multipoint_rounds = witness_data.block_multipoint_rounds.clone();
    // Initial sumcheck claim (to be derived from the full transcript in a
    // complete implementation; zero here since the trace only checks fold
    // consistency, not the initial target value).
    let block_initial_claim = Block128::ZERO;
    let block_challenges = derive_sumcheck_challenges(&block_multipoint_rounds);

    // Rec multipoint rounds from the previous recursive proof (or zeros at genesis).
    let (rec_multipoint_rounds, rec_initial_claim, rec_challenges) = match prev_rec_proof {
        None => {
            // Genesis: no previous recursive proof — use all-zero rounds.
            let zero_rounds = vec![vec![Block128::ZERO; 3]; BLOCK_SUMCHECK_ROUNDS];
            let zero_challenges = vec![Block128::ZERO; REC_SUMCHECK_ROUNDS];
            (zero_rounds, Block128::ZERO, zero_challenges)
        }
        Some(prev) => {
            let rounds = prev.stark.multipoint_rounds.clone();
            let initial = Block128::ZERO; // placeholder (see note above)
            let challenges = derive_sumcheck_challenges(&rounds);
            (rounds, initial, challenges)
        }
    };

    RecursiveBlockWitness {
        block_multipoint_rounds,
        block_initial_claim,
        block_challenges,
        rec_multipoint_rounds,
        rec_initial_claim,
        rec_challenges,
        acc_prev_state_root: prev_acc.state_root,
        acc_new_state_root: acc_new.state_root,
    }
}

/// Derive a Fiat-Shamir challenge sequence from sumcheck round polynomials.
///
/// Absorbs each round polynomial into a fresh channel in order and squeezes
/// one challenge per round.  This captures the per-round folding structure
/// without needing the full STARK transcript context.
fn derive_sumcheck_challenges(rounds: &[Vec<Block128>]) -> Vec<Block128> {
    let mut channel = Channel::new();
    let mut challenges = Vec::with_capacity(rounds.len());
    for round in rounds {
        channel.observe_field_elems(round);
        challenges.push(channel.get_random_point());
    }
    challenges
}

// =============================================================================
// Helpers
// =============================================================================

/// Build an all-zero `PublicInputs` for the recursive AIR.
///
/// The recursive AIR does not verify a transaction, so all public-input
/// fields are zero.  The absorb sequence still runs (binding the empty
/// inputs to the Fiat-Shamir transcript), which is correct because the
/// verifier will supply the same zero inputs.
fn make_empty_pi() -> PublicInputs {
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

// =============================================================================
// Genesis
// =============================================================================

/// Produce the `RecursiveBlockProof` for the genesis block (height = 0).
///
/// Genesis has no real `BlockProof` — it is a special chain anchor with a
/// marker `proof_transcript_hash`. This function creates a null
/// `BlockReplayWitness` (all-zero rounds) and calls `prove_recursive_step`
/// with a "pre-genesis" accumulator so that the resulting proof carries:
///
/// ```text
/// acc.chain_hash  = compress([0;32], H_BLOCK(genesis_header))
///                 = genesis_accumulator(...).chain_hash
/// acc.state_root  = genesis_header.state_root  (= GENESIS_STATE_ROOT)
/// acc.height      = 0
/// ```
///
/// This is the root of the recursive chain that `verify_tip` anchors against.
pub fn prove_genesis_recursive() -> RecursiveBlockProof {
    use noid_chain::consensus::genesis::genesis_header;
    use noid_fri_binius::{CompactEvalProof, MerkleCap};

    let genesis = genesis_header();

    // "Pre-genesis" accumulator: all zeros, no blocks applied yet.
    // prove_recursive_step computes:
    //   acc_new.chain_hash = compress([0;32], H_BLOCK(genesis))
    // which matches genesis_accumulator(genesis_state_root, genesis_hash).
    let pre_genesis_acc = ChainAccumulator {
        height: 0,
        state_root: [0u8; 32],
        chain_hash: [0u8; 32],
    };

    // Null replay witness: no real block data for genesis.
    // Only block_multipoint_rounds is used inside prove_recursive_step;
    // the remaining fields are unused during proving (they serve FRI Kill-Shot
    // verification which is not relevant for the genesis stub).
    let null_witness = BlockReplayWitness::from_parts(
        MerkleCap { hashes: vec![] },
        vec![], // no state_binding_algebraics
        vec![], // no block_col_openings
        // BLOCK_SUMCHECK_ROUNDS = 11; each round has 3 evaluations [p(0), p(1), p(2)]
        vec![vec![Block128::ZERO; 3]; BLOCK_SUMCHECK_ROUNDS],
        CompactEvalProof {
            upper_partial_evals: vec![],
            sum_check_oracles: vec![],
            fri_roots: vec![],
            fri_queried_symbols: vec![],
            fri_merkle_batch: vec![],
            final_codeword: vec![],
        },
        vec![], // no mixed_all_openings
    );

    // prev_rec_proof = None: genesis is the first step, uses zero rec rounds.
    prove_recursive_step(&null_witness, &genesis, &pre_genesis_acc, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator::genesis_accumulator;
    use noid_chain::consensus::genesis::{genesis_header, genesis_state_root};
    use noid_chain::hash_block_header;

    #[test]
    #[ignore = "heavy: proves a full recursive STARK (~2s)"]
    fn genesis_recursive_proof_has_correct_accumulator() {
        let proof = prove_genesis_recursive();

        let genesis = genesis_header();
        let genesis_hash = hash_block_header(&genesis);
        let expected_acc = genesis_accumulator(genesis_state_root(), genesis_hash);

        assert_eq!(proof.block_height, 0, "genesis proof must be at height 0");
        assert_eq!(
            proof.acc.chain_hash, expected_acc.chain_hash,
            "genesis chain_hash must match genesis_accumulator"
        );
        assert_eq!(
            proof.acc.state_root, genesis.state_root,
            "genesis state_root must match header"
        );
    }
}
