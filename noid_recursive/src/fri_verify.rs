// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! FRI query data extraction for the recursive Merkle Kill-Shot.
//!
//! The compact FRI uses a `BatchedMerkleProof` that deduplicates shared
//! ancestors across all queries in a round, storing only the unique
//! sibling hashes needed to reconstruct every path bottom-up.
//!
//! `extract_fri_query_inputs` lifts the per-round raw batch data and
//! queried symbols out of a `CompactEvalProof` into typed structs.
//! Constructing individual `MerklePathInputs` for `prove_merkle_killshot`
//! requires a `CryptographicHasher` to compute leaf hashes and parent
//! nodes — that expansion lives in the prove module (coming next).

use noid_core::Block128;
use noid_fri_binius::compact_fri::{BatchedMerkleProof, CompactEvalProof};

/// Per-FRI-round query inputs for the Merkle Kill-Shot.
///
/// Stores the raw batched proof and queried symbols for one round.
/// `depth` = tree depth = `n_rounds + LOG_RATE - 1 - round` where
/// `LOG_RATE = 2`.
///
/// To feed `prove_merkle_killshot`, expand each `(batch, queried_symbols)`
/// pair into `Vec<MerklePathInputs>` using a hasher — see the `prove`
/// module for `expand_to_merkle_path_inputs`.
#[derive(Debug, Clone)]
pub struct FriRoundQueryInputs {
    /// FRI round index (0 = first folding round).
    pub round: usize,
    /// Merkle root of this round's codeword tree.
    pub root: [u8; 32],
    /// Tree depth: number of layers from leaf to root (exclusive of root).
    /// Equals `n_rounds + LOG_RATE - 1 - round`.
    pub depth: usize,
    /// Queried symbol pairs `(s0, s1)` for each query, in the same order
    /// as `batch.query_indices`.
    pub queried_symbols: Vec<(Block128, Block128)>,
    /// Compressed Merkle authentication for all queries in this round.
    ///
    /// Contains deduplicated sibling hashes in bottom-up, left-to-right
    /// order.  Verification (and path expansion) is performed by
    /// `verify_batched_merkle_proof` in `noid_fri_binius::compact_fri`.
    pub batch: BatchedMerkleProof,
}

impl FriRoundQueryInputs {
    /// Upper-bound on Poseidon2b compressions contributed by this round.
    ///
    /// Equals `depth * n_queries`; the true count may be lower because
    /// the batch deduplicates shared ancestors (reducing the number of
    /// actual compress calls in `prove_merkle_killshot`).
    pub fn max_compressions(&self) -> usize {
        self.depth * self.queried_symbols.len()
    }
}

/// All FRI round query inputs extracted from one `CompactEvalProof`.
#[derive(Debug, Clone)]
pub struct FriQueryInputs {
    /// One entry per compact-FRI round (typically 5 rounds for log_len=13,
    /// COMPACT_TAU=8).
    pub rounds: Vec<FriRoundQueryInputs>,
    /// Sum of `depth * n_queries` across all rounds — an upper bound on
    /// the total Poseidon2b compressions the Kill-Shot must prove.
    pub total_compressions: usize,
}

/// Extract FRI Merkle query data from a `CompactEvalProof`.
///
/// The returned `FriQueryInputs` captures everything needed to later call
/// `prove_merkle_killshot` (one Kill-Shot per round, or batched).
/// Leaf hash computation and per-query path reconstruction are deferred to
/// the prove module because they require a `CryptographicHasher`.
pub fn extract_fri_query_inputs(proof: &CompactEvalProof) -> FriQueryInputs {
    let n_rounds = proof.fri_roots.len();
    // LOG_RATE = 2 (rate-4 code).  Round depth formula from compact_fri:
    //   depth_r = n_rounds + LOG_RATE - 1 - r
    const LOG_RATE: usize = 2;

    let mut rounds = Vec::with_capacity(n_rounds);
    let mut total_compressions = 0usize;

    for round in 0..n_rounds {
        let root = proof.fri_roots[round];
        let batch = proof.fri_merkle_batch[round].clone();
        let queried_symbols = proof.fri_queried_symbols[round].clone();

        // Compute tree depth for this round.
        let depth = if n_rounds + LOG_RATE > round + 1 {
            n_rounds + LOG_RATE - 1 - round
        } else {
            0
        };

        total_compressions += depth * queried_symbols.len();

        rounds.push(FriRoundQueryInputs {
            round,
            root,
            depth,
            queried_symbols,
            batch,
        });
    }

    FriQueryInputs {
        rounds,
        total_compressions,
    }
}
