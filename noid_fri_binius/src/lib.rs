// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! FRI-Binius Polynomial Commitment Scheme for the Paranoid STARK.
//!
//! Optimized interleaved commitment + compact FRI opening:
//! - Single Merkle cap for ALL columns (binding commitment)
//! - Arithmetic hasher backend for field-friendly commitments
//! - Compact FRI with TAU=8, 64 queries, batched Merkle proofs
//! - Mixed-point opening via gamma-batched polynomial
//!
//! # Proof Size Budget (log_len=13, 297 columns)
//!
//! | Component | Size |
//! |-----------|------|
//! | upper_partial_evals (256) | 4.0 KB |
//! | sumcheck oracles (5 rounds) | 0.2 KB |
//! | FRI roots (5) | 0.2 KB |
//! | queried symbols (64*5) | 10.2 KB |
//! | batched Merkle paths | ~22 KB |
//! | final codeword | 0.1 KB |
//! | column openings (297) | 4.7 KB |
//! | **Total FRI-Binius opening** | **~41 KB** |
//!
//! # Soundness
//!
//! | Component | Security |
//! |-----------|----------|
//! | Merkle cap backend | 128-bit collision target |
//! | Gamma batching | (n-1)/2^128 (Horner RLC) |
//! | Compact FRI | 128-bit under the RS capacity CONJECTURE; provable ~64-bit (Johnson) / ~43-bit (unique decoding) |
//!
//! The FRI query phase is the weakest provable link of the whole proof
//! chain: only the capacity-conjecture figure reaches the 128-bit target,
//! and raising the provable floor by query count alone (~148 queries for
//! 128-bit Johnson) would roughly double the opening bytes.

pub mod capsule;
pub mod compact_fri;
pub mod encode_kernel;
pub mod interleaved_commit;
pub mod mixed_open;

pub use capsule::{
    absorb_capsule_commitment, capsule_commit, capsule_open, capsule_queries_from_seeds,
    capsule_query_bit_location, capsule_query_seed_count, capsule_verify, CapsuleCommitment,
    CapsuleOpeningProof, CapsuleProverState, CAPSULE_CAP_DEPTH, CAPSULE_GRIND_BITS,
    CAPSULE_LOG_RATE, CAPSULE_NUM_QUERIES, CAPSULE_QUERY_SEED_BITS, CAPSULE_TAU, CAPSULE_WIDE_LOG,
};
pub use compact_fri::{CompactEvalProof, COMPACT_NUM_QUERIES, COMPACT_TAU};
pub use interleaved_commit::{
    absorb_cap, interleaved_commit, interleaved_commit_arithmetic, CommitmentHashBackend,
    InterleavedCommitment, InterleavedProverState, MerkleCap,
};
pub use mixed_open::{
    prove_mixed_opening, verify_mixed_opening, EvalClaim, MixedOpeningProof, SourceBindingProof,
};

/// Top levels of Merkle tree stored in the cap commitment.
/// 2^5 = 32 hash nodes at cap level.
pub const MERKLE_CAP_DEPTH: usize = 5;
