// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Public-input layout for the transaction STARK.
//!
//! Order is locked:
//! `(prev_state_root, new_state_root, tx_body_hash, fee, n_live_inputs,
//!   n_live_outputs, coinbase_credit, log_slots)`.
//!
//! `n_live_inputs` / `n_live_outputs` count how many of the fixed-capacity
//! `MAX_INPUTS` / `MAX_OUTPUTS` hash-stack slots carry a real UTXO; the
//! remainder are dummies the prover pads with.
//!
//! `coinbase_credit` (Stage E.5.f₁) is the mint credit for a coinbase tx;
//! zero for regular transactions. Range-checked as `u64` under the
//! coinbase branch of `balance_gate`.
//!
//! `log_slots` (Stage E.6) is the header-committed circuit constant that
//! sets the depth of the slot-space Merkle structure (`2^log_slots`
//! UTXO slots). Mainnet starts at `24` and may grow to at most `32`
//! via the expansion trigger in `GENERAL_DESIGN §15.3`. Absorbed into
//! the STARK transcript so any disagreement between prover and
//! verifier forks the Fiat-Shamir channel.

use noid_poseidon2b::primitives::{Digest, TxBodyHash};

use crate::types::{MAX_INPUTS, MAX_OUTPUTS};

/// Minimum accepted `log_slots` in `PublicInputs`. Mainnet launches
/// at this depth; any smaller is a test-only configuration.
pub const MIN_LOG_SLOTS: u32 = 24;
/// Maximum accepted `log_slots` in `PublicInputs`. Upper bound of the
/// expansion trigger per `GENERAL_DESIGN §15.3`.
pub const MAX_LOG_SLOTS: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicInputs {
    pub prev_state_root: Digest,
    pub new_state_root: Digest,
    pub tx_body_hash: TxBodyHash,
    pub fee: u128,
    pub n_live_inputs: u8,
    pub n_live_outputs: u8,
    /// Stage E.5.f₁ — coinbase credit. Zero for non-coinbase. When the
    /// body's `is_coinbase = 1` the balance AIR enforces
    /// `Σ outputs == coinbase_credit`; when `is_coinbase = 0` the AIR
    /// enforces `coinbase_credit == 0` and the standard UTXO
    /// conservation law.
    pub coinbase_credit: u64,
    /// Stage E.6 — slot-space depth `k ∈ [MIN_LOG_SLOTS, MAX_LOG_SLOTS]`
    /// sourced from the block header. Absorbed into the STARK
    /// transcript before the column roots so the Fiat-Shamir channel
    /// is bound to the circuit sizing declared by the block.
    pub log_slots: u32,
    /// Stage E.4 — per-output activation booleans. `is_activation[j]`
    /// is `true` iff output `j` was a live mint:
    /// `(pre_value == 0) ∧ (post_value != 0)`. Dummy/silenced output
    /// slots carry `false`. In-circuit the same boolean programme is
    /// pinned as `SKEL_IS_ACTIVATION_COL` and tied to the prev-side
    /// output opener's `col_is_mint` selector. Summed across a block
    /// to feed the `active_delta` term in `GENERAL_DESIGN §15.3`.
    pub is_activation: [bool; MAX_OUTPUTS],
    /// Stage E.4 — per-input deactivation booleans. `is_deactivation[i]`
    /// is `true` iff input `i` was a live spend:
    /// `(pre_value != 0) ∧ (post_value == 0)`. Dummy slots carry
    /// `false`. Pinned in-circuit as `SKEL_IS_DEACTIVATION_COL`, tied
    /// to the prev-side input opener's `col_is_spend` selector.
    pub is_deactivation: [bool; MAX_INPUTS],
}
