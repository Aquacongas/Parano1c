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

#[cfg(unix)]
mod anchored_artifact_fs;
mod cpu_budget;
mod embedded_recursive_artifacts;
pub mod miner;
pub mod pow;
mod recursive_class_registry_store;
pub mod recursive_matrix_store;
pub mod recursive_prover;
pub mod selected_history_verifier;
pub mod template;
mod topology_gate;

pub use cpu_budget::{
    configure_process_cpu_budget, configured_process_cpu_budget, install_process_proof_cpu,
    install_selected_history_cpu, plan_process_cpu_budget, ProcessCpuBudgetError,
    ProcessCpuBudgetMode, ProcessCpuBudgetPlan, SelectedHistoryCpuStage,
};
pub use embedded_recursive_artifacts::{
    EmbeddedSelectedRecursiveArtifactError, EmbeddedSelectedRecursiveArtifacts,
    EmbeddedSelectedRecursiveClassRegistrySource, EmbeddedSelectedRecursiveMatrixEvaluator,
    EmbeddedSelectedRecursiveMatrixSource, EmbeddedSelectedRecursiveRetention,
    EMBEDDED_SELECTED_RECURSIVE_LEAF_COUNT,
};
pub use miner::{BlockAppliedHook, BlockMiner, MinerConfig, MinerEvent};
pub use pow::{search_pow_parallel, PowSolution};
pub use recursive_class_registry_store::{
    LoadedSelectedRecursiveClassRegistry, LoadedSelectedRecursiveTerminalRegistry,
    LocalSelectedRecursiveClassRegistryError, LocalSelectedRecursiveClassRegistryStore,
    PinnedSelectedRecursiveClassRegistrySource,
};
pub use recursive_matrix_store::{
    selected_recursive_matrix_relative_path, LoadedSelectedRecursiveMatrixEvaluator,
    LoadedSelectedRecursiveMatrixView, LocalSelectedRecursiveMatrixError,
    LocalSelectedRecursiveMatrixSource, SelectedRecursiveMatrixArtifactIdentity,
    MAX_SELECTED_RECURSIVE_MATRIX_ARTIFACT_BYTES,
};
pub use recursive_prover::{
    begin_selected_history_prewarm_session, begin_selected_history_proof_session,
    prove_selected_recursive_block, prove_selected_recursive_link, selected_recursive_tier,
    LoadedSelectedRecursiveMatrix, SelectedHistoryPrewarmSession, SelectedHistoryProofSession,
    SelectedRecursiveBlockClasses, SelectedRecursiveBlockJob, SelectedRecursiveBlockProof,
    SelectedRecursiveLinkClasses, SelectedRecursiveLinkJob, SelectedRecursiveLinkPredecessor,
    SelectedRecursiveLinkProof, SelectedRecursiveMatrixKind, SelectedRecursiveMatrixRequest,
    SelectedRecursiveMatrixSource, SelectedRecursiveProverError, SelectedRecursiveTier,
};
pub use selected_history_verifier::{
    begin_selected_history_terminal_compact_verification_session,
    begin_selected_history_terminal_verification_session,
    verify_selected_history_terminal_embedded_governed, verify_selected_history_terminal_governed,
    verify_selected_history_terminal_pinned_governed, SelectedHistoryTerminalVerificationSession,
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
    // Extminer mode has no `BlockMiner` owner to enter the common pool on its
    // behalf. Keep RPC certificate assembly inside the same fixed proof CPU
    // budget as the selected-history A/B/C lanes instead of activating the
    // independent global Rayon pool from `spawn_blocking`.
    install_process_proof_cpu(|| miner::run_prove_block(tmpl, prev_state_root))
        .map_err(|error| error.to_string())?
}
