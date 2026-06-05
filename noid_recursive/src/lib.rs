// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Recursive chain proofs for O(1) historical verification.
//!
//! Core components:
//! - `ChainAccumulator`: rolling hash commitment to the entire chain history.
//! - `RecursiveBlockProof`: ~11 KB constant-size proof covering all blocks.
//! - `prove_recursive_step`: build one recursive proof step.
//! - `verify_tip`: verify the entire chain in O(1) ≈ 5 ms.

pub mod accumulator;
pub mod air;
pub mod fri_verify;
pub mod prove;
pub mod verify;
pub mod witness;

pub use accumulator::{genesis_accumulator, ChainAccumulator};
pub use air::{
    build_recursive_trace, RecursiveBlockAir, RecursiveBlockWitness, LOG_ROWS, N_COLS, N_ROWS,
};
pub use fri_verify::{extract_fri_query_inputs, FriQueryInputs};
pub use prove::{
    null_block_replay_witness, prove_genesis_recursive, prove_recursive_step, RecursiveBlockProof,
};
pub use verify::{verify_recursive_step, verify_step_stark_only, verify_tip, RecVerifyError};
pub use witness::{extract_block_replay_witness_parts, BlockReplayWitness};
