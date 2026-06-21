// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! FRI-Binius Polynomial Commitment Scheme for the Paranoid STARK.
//!
//! Optimized interleaved commitment + compact FRI opening:
//! - Single Blake3 Merkle cap for ALL columns (binding commitment)
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
//! | Blake3 cap | 128-bit collision |
//! | Gamma batching | (n-1)/2^128 (Horner RLC) |
//! | Compact FRI | 64 queries * 2 bits = 128-bit proven |

pub mod batched_open;
pub mod compact_fri;
pub mod interleaved_commit;
pub mod mixed_open;
pub mod verify;

pub use batched_open::{prove_batched_opening, BatchedOpeningProof};
pub use compact_fri::{CompactEvalProof, COMPACT_NUM_QUERIES, COMPACT_TAU};
pub use interleaved_commit::{
    absorb_cap, interleaved_commit, InterleavedCommitment, InterleavedProverState, MerkleCap,
};
pub use mixed_open::{
    prove_mixed_opening, verify_mixed_opening, EvalClaim, MixedOpeningProof, SourceBindingProof,
};
pub use verify::verify_batched_opening;

/// Top levels of Merkle tree stored in the cap commitment.
/// 2^5 = 32 hash nodes at cap level.
pub const MERKLE_CAP_DEPTH: usize = 5;
