// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Binding contract between the Kill-Shot GKR sub-proof
//! and the outer STARK's `TxBodyMerkleBoundaryPins`.
//!
//! This module names, in code, the exact cut the GKR proof claims and
//! the exact cell the STARK equality-binds. If this contract is ever
//! weakened, the `(prev_root, tx) → new_root` invariant is at risk;
//! the checklist in `gkr.md §0 rule 3` is the guard.

use crate::circuit::{SpineCircuit, SpineInputs};
use crate::oracle::{evaluate_spine, SpineWitness};
use noid_core::Block128;

/// The single cell bound by `TxBodyMerkleBoundaryPins::tx_body_hash`
/// in `noid_air::airs::tx_body_merkle::air`. Both the classical AIR
/// path and the GKR path must equal this cell, or the overall STARK
/// rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxBodyHashCell {
    pub lanes: [Block128; 2],
}

/// Description of the GKR ↔ STARK cut.
///
/// - `boundary_inputs` is the small MLE the GKR verifier reduces to
///   after its sumcheck. These values are either (a) already committed
///   by the STARK as public cells (leaf payloads, epoch_anchor,
///   fee, is_coinbase), or (b) deterministic constants (capacity IVs,
///   pad leaf). There is no new committed trace data introduced.
/// - `claimed_output` is the GKR prover's claim about `tx_body_hash`.
///   It is compared, lane-by-lane, against `TxBodyHashCell` in the
///   STARK AIR.
#[derive(Debug, Clone)]
pub struct BindingCut {
    pub boundary_inputs: SpineInputs,
    pub claimed_output: TxBodyHashCell,
}

impl BindingCut {
    /// Build a cut for a given `SpineInputs` by running the reference
    /// oracle; the returned `claimed_output` is what any honest GKR
    /// prover must produce.
    pub fn honest(circuit: &SpineCircuit, inputs: SpineInputs) -> (Self, SpineWitness) {
        let witness = evaluate_spine(circuit, &inputs);
        let cut = Self {
            boundary_inputs: inputs,
            claimed_output: TxBodyHashCell {
                lanes: witness.tx_body_hash,
            },
        };
        (cut, witness)
    }

    /// Extract the two field lanes the STARK's boundary pin will read.
    #[inline]
    pub fn output_lanes(&self) -> [Block128; 2] {
        self.claimed_output.lanes
    }
}
