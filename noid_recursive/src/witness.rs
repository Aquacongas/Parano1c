// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Algebraic replay witness for recursive proofs.
//!
//! `BlockReplayWitness` holds everything needed for in-circuit algebraic
//! verification — zero-check transcripts, multipoint sumcheck rounds,
//! column openings — but explicitly excludes FRI Merkle paths.
//!
//! The witness is extracted from a `BlockProof` by the caller (in
//! `noid_block`).  `noid_recursive` itself never imports `noid_block`
//! to avoid a cyclic dependency.

use noid_core::Block128;
use noid_fri_binius::compact_fri::CompactEvalProof;
use noid_fri_binius::MerkleCap;
use noid_stark::interleaved::AlgebraicStarkProof;

/// All data from a `BlockProof` needed for algebraic in-circuit verification.
///
/// Excludes FRI Merkle paths — those are extracted via
/// `extract_fri_query_inputs` and flow into the `FriMerkleKillShot`.
///
/// Constructed by the caller (e.g. `noid_block::full_node`) via
/// `BlockReplayWitness::from_block_proof_parts(...)`, keeping `noid_recursive`
/// free of a direct `noid_block` dependency.
#[derive(Debug, Clone)]
pub struct BlockReplayWitness {
    /// The interleaved commitment cap (opaque hash bytes, public input to
    /// the recursive circuit).  Treated as raw bytes — the recursive circuit
    /// does not verify cap generation (security via `chain_hash`).
    pub cap: MerkleCap,
    /// Algebraic STARK transcripts for state-binding AIRs (one per touched
    /// segment).  Empty when there is no state transition.
    pub state_binding_algebraics: Vec<AlgebraicStarkProof>,
    /// Column evaluations at the per-tx terminal points `r''_k`
    /// (flat layout across all transactions and block-spine slices).
    pub block_col_openings: Vec<Block128>,
    /// Block-level degree-2 multipoint sumcheck round polynomials.
    pub block_multipoint_rounds: Vec<Vec<Block128>>,
    /// The compact FRI proof embedded in the mixed opening.
    /// Fed to `extract_fri_query_inputs` for the FRI Merkle Kill-Shot.
    pub compact_fri: CompactEvalProof,
    /// Per-column evaluations at `r_block` plus secondary claim values.
    pub mixed_all_openings: Vec<Block128>,
    /// Initial claim for the block-level multipoint sumcheck
    /// (= `block_target` from `prove_block`). ZERO for null/genesis witnesses.
    /// Passed into the recursive STARK via `extra_transcript` to bind the
    /// fold-check to the real value rather than the placeholder ZERO.
    pub block_initial_claim: Block128,
}

impl BlockReplayWitness {
    /// Construct from the raw fields extracted from a `BlockProof`.
    ///
    /// This constructor exists so that the `noid_block` crate can build
    /// a `BlockReplayWitness` without `noid_recursive` needing to import
    /// `noid_block::BlockProof` (which would create a cyclic dependency).
    pub fn from_parts(
        cap: MerkleCap,
        state_binding_algebraics: Vec<AlgebraicStarkProof>,
        block_col_openings: Vec<Block128>,
        block_multipoint_rounds: Vec<Vec<Block128>>,
        compact_fri: CompactEvalProof,
        mixed_all_openings: Vec<Block128>,
        block_initial_claim: Block128,
    ) -> Self {
        Self {
            cap,
            state_binding_algebraics,
            block_col_openings,
            block_multipoint_rounds,
            compact_fri,
            mixed_all_openings,
            block_initial_claim,
        }
    }
}

/// Convenience alias used in integration code.
pub fn extract_block_replay_witness_parts(
    cap: MerkleCap,
    state_binding_algebraics: Vec<AlgebraicStarkProof>,
    block_col_openings: Vec<Block128>,
    block_multipoint_rounds: Vec<Vec<Block128>>,
    compact_fri: CompactEvalProof,
    mixed_all_openings: Vec<Block128>,
    block_initial_claim: Block128,
) -> BlockReplayWitness {
    BlockReplayWitness::from_parts(
        cap,
        state_binding_algebraics,
        block_col_openings,
        block_multipoint_rounds,
        compact_fri,
        mixed_all_openings,
        block_initial_claim,
    )
}
