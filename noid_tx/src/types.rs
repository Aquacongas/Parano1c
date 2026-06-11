// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transparent transaction data types.
//!
//! Paranoid is a transparent UTXO chain: inputs carry raw `(value,
//! owner, spend_secret, auth_tag, slot_index)` so the STARK AIR can
//! enforce ownership (`owner = H_ADDR(spend_secret)`), replay
//! protection (`auth_tag = H_AUTH(spend_secret, tx_body_hash)`), range
//! and balance, and state-tree opening directly against the witness.
//! Outputs carry raw `(value, owner)`; the commitment leaf is derived
//! deterministically via `hash_utxo_leaf` both natively and in-circuit.

use noid_poseidon2b::primitives::{Address, AuthTag, Commitment, Digest, SpendSecret, TxBodyHash};

/// Maximum input slots per transaction. Dummy slots (`valid = false`)
/// pad up to this bound so the AIR has a fixed-shape witness trace.
pub const MAX_INPUTS: usize = 4;

/// Maximum output slots per transaction.
pub const MAX_OUTPUTS: usize = 8;

/// A spending input. Dummy slots carry `valid = false`, `value = 0`,
/// zero owner/secret/auth_tag and `slot_index = 0`; they contribute 0
/// to balance and the AIR skips their constraints via a selector.
///
/// SECURITY: `Debug` is intentionally NOT derived — the struct contains
/// `spend_secret` which must never appear in logs or panic output.
#[derive(Clone, PartialEq, Eq)]
pub struct TxInput {
    /// Index of the spent UTXO inside the chain state vector
    /// (`FriState` slot).
    pub slot_index: u32,
    /// Transparent value (LE u64).
    pub value: u64,
    /// 256-bit owner address. Must equal `H_ADDR(spend_secret)`.
    pub owner: Address,
    /// Preimage of `owner`. Never on-chain in cleartext — lives only
    /// in the witness trace.
    pub spend_secret: SpendSecret,
    /// Replay-protection tag: `H_AUTH(spend_secret, tx_body_hash)`.
    pub auth_tag: AuthTag,
    pub valid: bool,
}

impl TxInput {
    pub const fn dummy() -> Self {
        Self {
            slot_index: 0,
            value: 0,
            owner: Address([0u8; 32]),
            spend_secret: SpendSecret([0u8; 32]),
            auth_tag: AuthTag([0u8; 32]),
            valid: false,
        }
    }

    /// Commitment leaf for this input: `hash_utxo_leaf(value, owner)`.
    /// Must equal the current `FriState` entry at `slot_index` for a
    /// valid spend.
    pub fn commitment(&self) -> Commitment {
        noid_poseidon2b::primitives::hash_utxo_leaf(self.value as u128, &self.owner)
    }
}

/// A fresh transparent UTXO. All fields are public on-chain; any node
/// can recompute the leaf via `hash_utxo_leaf` (which binds `(value,
/// owner)`). The `slot_index` picks which `FriState` cell the chain
/// allocator must occupy with this output; the AIR proves in-circuit
/// that the prev-state cell at that slot was `(0,0,0)` (proved by `BlockStateBindingAir`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxOutput {
    /// Index of the `FriState` slot this output activates. Must be
    /// free (prev-state `(0,0,0)`).
    pub slot_index: u32,
    /// Transparent value (LE u64).
    pub value: u64,
    /// 256-bit owner address.
    pub owner: Address,
    pub valid: bool,
}

impl TxOutput {
    pub const fn dummy() -> Self {
        Self {
            slot_index: 0,
            value: 0,
            owner: Address([0u8; 32]),
            valid: false,
        }
    }

    pub fn commitment(&self) -> Commitment {
        noid_poseidon2b::primitives::hash_utxo_leaf(self.value as u128, &self.owner)
    }
}

/// Canonical transaction body. Covers the fields bound by the body
/// hash. State roots are NOT part of per-tx data (they live at block
/// level in BlockStateBinding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBody {
    /// Hash of block header at `height - ANCHOR_DEPTH`. Provides
    /// anti-replay across forks and natural TTL (~6 minutes).
    pub epoch_anchor: Digest,
    pub fee: u128,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    /// Coinbase marker. When `true`, the engine
    /// relaxes the UTXO conservation law (`Σin − Σout − fee == 0`) and
    /// replaces it with `Σout == coinbase_credit`; also requires
    /// `fee == 0 ∧ n_live_inputs == 0`. Chain-layer policy enforces
    /// `coinbase_credit == block_reward(height) + Σ fees`; engine only
    /// proves per-tx arithmetic.
    pub is_coinbase: bool,
}

/// Epoch anchor validity window in blocks.
/// A transaction's `epoch_anchor` must reference a block within the last
/// `ANCHOR_DEPTH` blocks. Larger values allow txs to survive slow-block periods
/// (e.g. 144 blocks × 30 min/block = 3 days of validity during a difficulty spike).
/// Nullifier set window = ANCHOR_DEPTH (prevents replay within validity window).
pub const ANCHOR_DEPTH: u64 = 144;

impl TxBody {
    /// Number of real spend inputs (`valid = true`).
    #[inline]
    pub fn valid_input_count(&self) -> usize {
        self.inputs.iter().filter(|i| i.valid).count()
    }
}

/// A full transaction: body plus the canonical body hash. Per-input
/// auth tags live inside each `TxInput.auth_tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub body: TxBody,
    pub tx_body_hash: TxBodyHash,
}

impl Transaction {
    /// Collect auth tags for the valid inputs, in order.
    pub fn valid_auth_tags(&self) -> Vec<AuthTag> {
        self.body
            .inputs
            .iter()
            .filter(|i| i.valid)
            .map(|i| i.auth_tag)
            .collect()
    }
}

/// Custom Debug for TxInput: spend_secret is redacted to prevent
/// accidental exposure in logs, panic output, or test diagnostics.
impl std::fmt::Debug for TxInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxInput")
            .field("slot_index", &self.slot_index)
            .field("value", &self.value)
            .field("owner", &self.owner)
            .field("spend_secret", &"[REDACTED]")
            .field("auth_tag", &self.auth_tag)
            .field("valid", &self.valid)
            .finish()
    }
}
