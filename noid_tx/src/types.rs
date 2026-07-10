// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Transparent transaction data types.
//!
//! Paranoid is a transparent UTXO chain: public inputs carry raw
//! `(value, owner, slot_index)` and outputs carry raw `(value, owner)`.
//! `TxInput::spend_secret` is a local wallet/prover witness field only; public
//! network serialization omits it and carries an authorization proof instead.
//! The proof layer enforces ownership (`owner = H_ADDR(spend_secret)`), public
//! range/balance predicates, and exact state membership against that witness.

use noid_core::Block128;
use noid_poseidon2b::primitives::{Address, Commitment, Digest, SpendSecret, TxBodyHash};

/// Pack the transparent amount and alloc-counter incarnation into the single
/// existing value field used by state and transaction hash schedules.
///
/// The amount occupies the low 64 bits and `creation_id` the high 64 bits, so
/// `creation_id = 0` is byte-identical to the historical amount-only lane.
#[inline]
pub const fn pack_amount_creation_id(amount: u64, creation_id: u64) -> Block128 {
    Block128(((creation_id as u128) << 64) | amount as u128)
}

/// Inverse of [`pack_amount_creation_id`], returning `(amount, creation_id)`.
#[inline]
pub const fn unpack_amount_creation_id(packed: Block128) -> (u64, u64) {
    (packed.0 as u64, (packed.0 >> 64) as u64)
}

/// Transaction proof/body shape.
///
/// The launch protocol supports the fast standard wallet shape. Larger shapes
/// are represented explicitly so wallet/RPC/mempool plumbing can dispatch by
/// shape without changing the standard proof layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum TxShape {
    /// Fast default transaction shape: up to 4 inputs and 8 outputs.
    Standard4x8 = 0,
    /// Large-payment/sweep shape: up to 25 inputs and 2 outputs.
    Sweep25x2 = 1,
}

impl TxShape {
    pub const fn id(self) -> u8 {
        self as u8
    }

    pub const fn max_inputs(self) -> usize {
        match self {
            Self::Standard4x8 => 4,
            Self::Sweep25x2 => 25,
        }
    }

    pub const fn max_outputs(self) -> usize {
        match self {
            Self::Standard4x8 => 8,
            Self::Sweep25x2 => 2,
        }
    }

    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Standard4x8),
            1 => Some(Self::Sweep25x2),
            _ => None,
        }
    }

    /// Whether the current wallet/mempool proof stack can prove/verify this shape.
    #[inline]
    pub const fn proof_supported(self) -> bool {
        matches!(self, Self::Standard4x8 | Self::Sweep25x2)
    }
}

/// Maximum input slots for the currently-supported standard transaction proof.
/// Dummy slots (`valid = false`) pad up to this bound so the proof relation has
/// a fixed-shape witness trace.
pub const MAX_INPUTS: usize = 4;

/// Maximum output slots for the currently-supported standard transaction proof.
pub const MAX_OUTPUTS: usize = 8;

/// A spending input. Dummy slots carry `valid = false`, `value = 0`,
/// zero owner/secret and `slot_index = 0`; they contribute 0 to balance
/// and the proof layer skips their constraints via a selector.
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
    /// Alloc-counter incarnation assigned when this UTXO was created.
    /// Prevents a stale opening from spending a later UTXO that reused the
    /// same physical slot.
    pub creation_id: u64,
    /// 256-bit owner address. Must equal `H_ADDR(spend_secret)`.
    pub owner: Address,
    /// Preimage of `owner`. Never on-chain in cleartext — lives only
    /// in the witness trace.
    pub spend_secret: SpendSecret,
    pub valid: bool,
}

impl TxInput {
    pub const fn dummy() -> Self {
        Self {
            slot_index: 0,
            value: 0,
            creation_id: 0,
            owner: Address([0u8; 32]),
            spend_secret: SpendSecret([0u8; 32]),
            valid: false,
        }
    }

    /// Commitment leaf for this input:
    /// `hash_utxo_leaf(pack(value, creation_id), owner)`.
    /// Must equal the current `FriState` entry at `slot_index` for a
    /// valid spend.
    pub fn commitment(&self) -> Commitment {
        noid_poseidon2b::primitives::hash_utxo_leaf(
            pack_amount_creation_id(self.value, self.creation_id).0,
            &self.owner,
        )
    }
}

/// A fresh transparent UTXO. All fields are public on-chain; any node
/// can recompute the leaf via `hash_utxo_leaf` (which binds `(value,
/// owner)`). The `slot_index` picks which `FriState` cell the chain
/// allocator must occupy with this output; the block-level exact state
/// transition proof authenticates that the previous cell was empty.
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

    /// State-leaf commitment after the block allocator assigns this output's
    /// incarnation. Outputs intentionally do not choose their own ID.
    pub fn commitment_with_creation_id(&self, creation_id: u64) -> Commitment {
        noid_poseidon2b::primitives::hash_utxo_leaf(
            pack_amount_creation_id(self.value, creation_id).0,
            &self.owner,
        )
    }
}

/// Canonical transaction body. Covers the fields bound by the body
/// hash. State roots are NOT part of per-tx data; they are bound at block
/// level by the exact state transition proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBody {
    /// Fixed proof/body shape for this transaction.
    pub shape: TxShape,
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
pub const ANCHOR_DEPTH: u64 = 144;

impl TxBody {
    /// Construct a standard 4-input/8-output transaction body.
    pub fn standard(
        epoch_anchor: Digest,
        fee: u128,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        is_coinbase: bool,
    ) -> Self {
        Self {
            shape: TxShape::Standard4x8,
            epoch_anchor,
            fee,
            inputs,
            outputs,
            is_coinbase,
        }
    }

    #[inline]
    pub fn max_inputs(&self) -> usize {
        self.shape.max_inputs()
    }

    #[inline]
    pub fn max_outputs(&self) -> usize {
        self.shape.max_outputs()
    }

    /// Number of real spend inputs (`valid = true`).
    #[inline]
    pub fn valid_input_count(&self) -> usize {
        self.inputs.iter().filter(|i| i.valid).count()
    }
}

/// A full transaction: body plus the canonical body hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub body: TxBody,
    pub tx_body_hash: TxBodyHash,
}

/// Custom Debug for TxInput: spend_secret is redacted to prevent
/// accidental exposure in logs, panic output, or test diagnostics.
impl std::fmt::Debug for TxInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxInput")
            .field("slot_index", &self.slot_index)
            .field("value", &self.value)
            .field("creation_id", &self.creation_id)
            .field("owner", &self.owner)
            .field("spend_secret", &"[REDACTED]")
            .field("valid", &self.valid)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_creation_id_packing_roundtrips_and_zero_id_uses_low_lane() {
        for (amount, creation_id) in [
            (0, 0),
            (u64::MAX, 0),
            (0, u64::MAX),
            (0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210),
        ] {
            let packed = pack_amount_creation_id(amount, creation_id);
            assert_eq!(unpack_amount_creation_id(packed), (amount, creation_id));
        }
        assert_eq!(
            pack_amount_creation_id(0xA55A, 0),
            Block128::from(0xA55Au128)
        );

        let output = TxOutput {
            slot_index: 3,
            value: 77,
            owner: Address([0x5A; 32]),
            valid: true,
        };
        assert_eq!(
            output.commitment_with_creation_id(0),
            noid_poseidon2b::primitives::hash_utxo_leaf(77, &output.owner)
        );
        assert_ne!(
            output.commitment_with_creation_id(0),
            output.commitment_with_creation_id(1)
        );
    }
}
