// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # noid_miner — Block Production Engine
//!
//! Implements the parallel PoW + block-certificate generation pipeline.
//!
//! ## Pipeline
//!
//! ```text
//!  ┌────────────────────────────────────────────────────────────┐
//!  │                   Block Production Loop                    │
//!  │                                                            │
//!  │  1. Build template (txs from mempool + coinbase)           │
//!  │     ├─ Empty block template first (no block proof)         │
//!  │     └─ User-tx template with exact state certificate       │
//!  │                                                            │
//!  │  2. Parallel execution:                                    │
//!  │     ┌──────────────────┐   ┌──────────────────────────┐   │
//!  │     │  PoW Search      │   │  Certificate assembly    │   │
//!  │     │  Poseidon2b POW  │   │  proof + auth sidecar    │   │
//!  │     │  < target        │   │                          │   │
//!  │     └───────┬──────────┘   └──────────┬───────────────┘   │
//!  │             │                         │                   │
//!  │             └──────────┬──────────────┘                   │
//!  │                        │ both complete                    │
//!  │                        ▼                                  │
//!  │  3. Seal: semantic header + detached witness bytes        │
//!  │  4. Broadcast via P2P                                     │
//!  └────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security property
//!
//! `state_root` (derived from all txs + miner_address via coinbase output) is
//! in the fixed Poseidon2b PoW header schedule. An external miner CANNOT change
//! the coinbase without regenerating the block certificate — the miner only
//! brute-forces the nonce.

mod memory_governor;
pub mod miner;
pub mod pow;
mod recursive_class_registry_store;
pub mod recursive_matrix_store;
pub mod recursive_prover;
pub mod selected_history_verifier;
pub mod template;

pub use miner::{BlockAppliedHook, BlockMiner, MinerConfig, MinerEvent};
pub use pow::{search_pow_parallel, PowSolution};
pub use recursive_class_registry_store::{
    LoadedSelectedRecursiveClassRegistry, LocalSelectedRecursiveClassRegistryError,
    LocalSelectedRecursiveClassRegistryStore,
};
pub use recursive_matrix_store::{
    selected_recursive_matrix_relative_path, LoadedSelectedRecursiveMatrixView,
    LocalSelectedRecursiveMatrixError, LocalSelectedRecursiveMatrixSource,
    SelectedRecursiveMatrixArtifactIdentity, MAX_SELECTED_RECURSIVE_MATRIX_ARTIFACT_BYTES,
};
pub use recursive_prover::{
    begin_selected_history_proof_session, prove_selected_recursive_block,
    prove_selected_recursive_link, selected_recursive_tier, LoadedSelectedRecursiveMatrix,
    SelectedHistoryProofSession, SelectedRecursiveBlockClasses, SelectedRecursiveBlockJob,
    SelectedRecursiveBlockProof, SelectedRecursiveLinkClasses, SelectedRecursiveLinkJob,
    SelectedRecursiveLinkPredecessor, SelectedRecursiveLinkProof, SelectedRecursiveMatrixKind,
    SelectedRecursiveMatrixRequest, SelectedRecursiveMatrixSource, SelectedRecursiveProverError,
    SelectedRecursiveTier,
};
pub use selected_history_verifier::{
    begin_selected_history_terminal_verification_session,
    verify_selected_history_terminal_governed, SelectedHistoryTerminalVerificationSession,
    SelectedHistoryTerminalVerifierError,
};
pub use template::{BlockTemplate, TemplateBuilder, TemplateRefreshTrigger};

pub type ProvedBlockParts = (Vec<u8>, Vec<u8>);

/// Public wrapper around the internal `run_prove_block` function.
/// Used by the RPC `getBlockTemplate` to generate a fully-proved block
/// for external miners that need complete block bytes and detached proof data.
pub fn run_prove_block_for_rpc(
    tmpl: &BlockTemplate,
    prev_state_root: [u8; 32],
) -> Result<ProvedBlockParts, String> {
    miner::run_prove_block(tmpl, prev_state_root)
}
