// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Public-input layout for the LogicProof STARK (stateless).
//!
//! Order is locked:
//! `(epoch_anchor, tx_body_hash, fee, n_live_inputs,
//!   n_live_outputs, coinbase_credit, log_slots,
//!   claims_commitment)`.
//!
//! State roots (prev/new) are NOT part of per-tx public inputs.
//! They live at block level in BlockStateBinding.

use noid_poseidon2b::primitives::{Digest, TxBodyHash};

use crate::types::{MAX_INPUTS, MAX_OUTPUTS};

/// Minimum accepted `log_slots` in `PublicInputs`. Mainnet launches
/// at this depth; any smaller is a test-only configuration.
pub const MIN_LOG_SLOTS: u32 = 24;
/// Maximum accepted `log_slots` in `PublicInputs`. Upper bound of the
/// expansion trigger per `GENERAL_DESIGN §15.3`.
pub const MAX_LOG_SLOTS: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicInputs {
    /// Hash of block header at `height - ANCHOR_DEPTH`. Replaces
    /// prev_state_root; provides fork-binding without state coupling.
    pub epoch_anchor: Digest,
    pub tx_body_hash: TxBodyHash,
    pub fee: u128,
    pub n_live_inputs: u8,
    pub n_live_outputs: u8,
    /// Stage E.5.f₁ — coinbase credit. Zero for non-coinbase.
    pub coinbase_credit: u64,
    /// Slot-space depth `k ∈ [MIN_LOG_SLOTS, MAX_LOG_SLOTS]` from block
    /// header. Absorbed into STARK transcript to bind circuit sizing.
    pub log_slots: u32,
    /// Binding commitment to all claimed slot values (inputs + outputs).
    /// Bridges LogicProof to BlockStateBinding: the miner opens the
    /// same slots and verifies equality.
    pub claims_commitment: Digest,
    /// Per-output activation booleans.
    pub is_activation: [bool; MAX_OUTPUTS],
    /// Per-input deactivation booleans.
    pub is_deactivation: [bool; MAX_INPUTS],
}
