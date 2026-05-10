// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G0 — scaffolding for the GKR acceleration of the tx-body
//! Merkle Poseidon2b spine. See `gkr.md` for the full plan.
//!
//! At G0 this crate is **only** a typed description of the spine
//! circuit plus a reference oracle that re-executes the 59-permutation
//! stack through the native `noid_poseidon2b` implementation. No
//! sumcheck, no prover, no verifier yet. Its purpose is to pin down
//! the topology and the I/O boundary so later stages have a single
//! source of truth.

pub mod batch_eval;
pub mod binding;
pub mod circuit;
pub mod layers;
pub mod mle_layout;
pub mod oracle;
pub mod perm_sumcheck;
pub mod product_sumcheck;
pub mod spine_sumcheck;

pub use batch_eval::{
    prove_batch_eval, verify_batch_eval, BatchEvalProof, BatchEvalReduction, BatchEvalRound,
    EvalClaim,
};
pub use binding::BindingCut;
pub use circuit::{SlotDescriptor, SpineCircuit, SpineInputs};
pub use layers::{evaluate_permutation, round_kind, PermLayerWitness, RoundKind};
pub use mle_layout::{pack_column, PermColumn, PermMle, N_PERM_CELLS, N_PERM_VARS};
pub use oracle::{evaluate_spine, SpineWitness};
pub use perm_sumcheck::{
    build_active_mle, build_rc_mle, prove_perm, verify_perm, PermProof, PermStateClaim,
    N_STATE_CLAIMS_PER_SLOT,
};
pub use product_sumcheck::{
    compute_product_claim, prove_product, verify_product, ProductProof, RoundEvals,
};
pub use spine_sumcheck::{
    build_boundary_mle, compute_tx_body_hash, discharge_boundary_native, prove_spine,
    reconstruct_slot_states, verify_spine, SpineProof, N_BOUNDARY_CELLS, N_BOUNDARY_VARS,
};
