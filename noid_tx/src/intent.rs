// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! TxIntent: the network payload for stateless transactions.
//!
//! A TxIntent carries everything a full node needs to validate and
//! include a transaction without re-executing it:
//! - The transaction body (epoch_anchor, fee, inputs, outputs)
//! - The opaque wallet authorization bytes (AuthGKR Kill-Shot)
//! - The claims commitment (C_claimed)
//! - The list of claimed slots with their values
//!
//! Neither `prev_state_root` nor `new_state_root` appear — state
//! binding is performed at block level by the miner.

use noid_poseidon2b::primitives::{Digest, TxBodyHash};

use crate::types::TxBody;

/// A single claimed slot entry in the TxIntent payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimedSlot {
    pub slot_index: u32,
    pub value: u64,
    pub owner_hi: [u8; 16],
    pub owner_lo: [u8; 16],
}

/// Network payload for a stateless transaction. Full nodes verify
/// the wallet authorization, check the epoch_anchor window, verify claimed
/// slots against native state, and admit to mempool.
///
/// # tx_body_hash consistency
///
/// `TxIntent` carries `tx_body_hash` alongside `tx_body` on the wire.
/// The mempool verifier recomputes `hash_tx_body(tx_body)` and rejects
/// any TxIntent where the hash field doesn't match the body.
/// See `noid_mempool::pool::submit`.
#[derive(Debug, Clone, PartialEq)]
pub struct TxIntent {
    pub tx_body: TxBody,
    pub tx_body_hash: TxBodyHash,
    pub claims_commitment: Digest,
    pub claimed_slots: Vec<ClaimedSlot>,
    /// Opaque serialized WalletAuthorizationBundle (AuthGKR only).
    /// Wire format is defined by the proof system; we carry raw bytes.
    pub authorization_bytes: Vec<u8>,
}

impl TxIntent {
    /// Derive claimed slots from the tx body's inputs and outputs.
    pub fn claimed_slots_from_body(body: &TxBody) -> Vec<ClaimedSlot> {
        let mut slots = Vec::with_capacity(body.inputs.len() + body.outputs.len());
        for inp in body.inputs.iter().filter(|i| i.valid) {
            slots.push(ClaimedSlot {
                slot_index: inp.slot_index,
                value: inp.value,
                owner_hi: inp.owner.0[..16].try_into().unwrap(),
                owner_lo: inp.owner.0[16..].try_into().unwrap(),
            });
        }
        for out in body.outputs.iter().filter(|o| o.valid) {
            slots.push(ClaimedSlot {
                slot_index: out.slot_index,
                value: out.value,
                owner_hi: out.owner.0[..16].try_into().unwrap(),
                owner_lo: out.owner.0[16..].try_into().unwrap(),
            });
        }
        slots
    }
}

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

use crate::wire::WireError;

impl ClaimedSlot {
    pub const WIRE_SIZE: usize = 4 + 8 + 16 + 16; // 44 bytes

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.slot_index.to_le_bytes());
        buf.extend_from_slice(&self.value.to_le_bytes());
        buf.extend_from_slice(&self.owner_hi);
        buf.extend_from_slice(&self.owner_lo);
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        if src.len() < Self::WIRE_SIZE {
            return Err(WireError::Truncated);
        }
        let slot_index = u32::from_le_bytes(src[..4].try_into().unwrap());
        let value = u64::from_le_bytes(src[4..12].try_into().unwrap());
        let mut owner_hi = [0u8; 16];
        owner_hi.copy_from_slice(&src[12..28]);
        let mut owner_lo = [0u8; 16];
        owner_lo.copy_from_slice(&src[28..44]);
        *src = &src[44..];
        Ok(Self {
            slot_index,
            value,
            owner_hi,
            owner_lo,
        })
    }
}

impl TxIntent {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        // Network wire: encode TxBody WITHOUT spend_secret in inputs.
        self.tx_body.encode_public(buf);
        buf.extend_from_slice(&self.tx_body_hash.0);
        buf.extend_from_slice(&self.claims_commitment);
        // claimed_slots
        let n_slots = self.claimed_slots.len() as u32;
        buf.extend_from_slice(&n_slots.to_le_bytes());
        for s in &self.claimed_slots {
            s.encode(buf);
        }
        // authorization_bytes (length-prefixed)
        let proof_len = self.authorization_bytes.len() as u32;
        buf.extend_from_slice(&proof_len.to_le_bytes());
        buf.extend_from_slice(&self.authorization_bytes);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        if src.is_empty() {
            return Err(WireError::Truncated);
        }

        // Network wire: decode TxBody WITHOUT spend_secret (spend_secret → zero).
        let tx_body = TxBody::decode_public(src)?;

        if src.len() < 32 {
            return Err(WireError::Truncated);
        }
        let mut tx_body_hash = [0u8; 32];
        tx_body_hash.copy_from_slice(&src[..32]);
        *src = &src[32..];

        if src.len() < 32 {
            return Err(WireError::Truncated);
        }
        let mut claims_commitment = [0u8; 32];
        claims_commitment.copy_from_slice(&src[..32]);
        *src = &src[32..];

        if src.len() < 4 {
            return Err(WireError::Truncated);
        }
        let n_slots = u32::from_le_bytes(src[..4].try_into().unwrap()) as usize;
        *src = &src[4..];
        if n_slots > tx_body.shape.max_claimed_slots() {
            return Err(WireError::CountTooLarge);
        }
        let mut claimed_slots = Vec::with_capacity(n_slots);
        for _ in 0..n_slots {
            claimed_slots.push(ClaimedSlot::decode(src)?);
        }

        if src.len() < 4 {
            return Err(WireError::Truncated);
        }
        let proof_len = u32::from_le_bytes(src[..4].try_into().unwrap()) as usize;
        *src = &src[4..];
        if src.len() < proof_len {
            return Err(WireError::Truncated);
        }
        let authorization_bytes = src[..proof_len].to_vec();
        *src = &src[proof_len..];

        Ok(Self {
            tx_body,
            tx_body_hash: TxBodyHash(tx_body_hash),
            claims_commitment,
            claimed_slots,
            authorization_bytes,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut src = bytes;
        let out = Self::decode(&mut src)?;
        if !src.is_empty() {
            return Err(WireError::TrailingBytes);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TxInput, TxOutput};
    use noid_poseidon2b::primitives::{Address, SpendSecret};

    fn mk_body() -> TxBody {
        TxBody::standard(
            [0xAA; 32],
            100,
            vec![TxInput {
                slot_index: 42,
                value: 1000,
                owner: Address([0x11; 32]),
                spend_secret: SpendSecret([0x22; 32]),
                valid: true,
            }],
            vec![TxOutput {
                slot_index: 99,
                value: 900,
                owner: Address([0x44; 32]),
                valid: true,
            }],
            false,
        )
    }

    fn mk_sweep_body() -> TxBody {
        TxBody {
            shape: crate::types::TxShape::Sweep25x2,
            epoch_anchor: [0xAB; 32],
            fee: 250,
            inputs: (0..5)
                .map(|i| TxInput {
                    slot_index: i,
                    value: 100 + i as u64,
                    owner: Address([0x20 + i as u8; 32]),
                    spend_secret: SpendSecret([0x40 + i as u8; 32]),
                    valid: true,
                })
                .collect(),
            outputs: vec![
                TxOutput {
                    slot_index: 100,
                    value: 400,
                    owner: Address([0x88; 32]),
                    valid: true,
                },
                TxOutput {
                    slot_index: 101,
                    value: 75,
                    owner: Address([0x99; 32]),
                    valid: true,
                },
            ],
            is_coinbase: false,
        }
    }

    #[test]
    fn roundtrip() {
        let body = mk_body();
        let intent = TxIntent {
            tx_body: body,
            tx_body_hash: TxBodyHash([0xBB; 32]),
            claims_commitment: [0xCC; 32],
            claimed_slots: vec![
                ClaimedSlot {
                    slot_index: 42,
                    value: 1000,
                    owner_hi: [0x11; 16],
                    owner_lo: [0x11; 16],
                },
                ClaimedSlot {
                    slot_index: 99,
                    value: 900,
                    owner_hi: [0x44; 16],
                    owner_lo: [0x44; 16],
                },
            ],
            authorization_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = intent.to_bytes();
        let back = TxIntent::from_bytes(&bytes).unwrap();

        // spend_secret is stripped on network wire — decoded value is zero.
        // All other fields must round-trip exactly.
        let mut expected_body = intent.tx_body.clone();
        for inp in expected_body.inputs.iter_mut() {
            inp.spend_secret = SpendSecret([0u8; 32]);
        }
        assert_eq!(back.tx_body, expected_body);
        assert_eq!(back.tx_body_hash, intent.tx_body_hash);
        assert_eq!(back.claims_commitment, intent.claims_commitment);
        assert_eq!(back.claimed_slots, intent.claimed_slots);
        assert_eq!(back.authorization_bytes, intent.authorization_bytes);
    }

    #[test]
    fn sweep_roundtrip() {
        let body = mk_sweep_body();
        let claimed_slots = TxIntent::claimed_slots_from_body(&body);
        let intent = TxIntent {
            tx_body: body,
            tx_body_hash: TxBodyHash([0xBC; 32]),
            claims_commitment: [0xCD; 32],
            claimed_slots,
            authorization_bytes: vec![1, 2, 3],
        };
        let bytes = intent.to_bytes();
        let back = TxIntent::from_bytes(&bytes).unwrap();
        assert_eq!(back.tx_body.shape, crate::types::TxShape::Sweep25x2);
        assert_eq!(back.tx_body.inputs.len(), 5);
        assert_eq!(back.tx_body.outputs.len(), 2);
        assert_eq!(back.claimed_slots.len(), 7);
        assert!(back
            .tx_body
            .inputs
            .iter()
            .all(|inp| inp.spend_secret == SpendSecret([0u8; 32])));
    }

    /// Verify spend_secret is NOT present in the serialized bytes.
    #[test]
    fn spend_secret_absent_from_wire() {
        let body = mk_body();
        let secret = body.inputs[0].spend_secret.0;
        let intent = TxIntent {
            tx_body: body,
            tx_body_hash: TxBodyHash([0xBB; 32]),
            claims_commitment: [0xCC; 32],
            claimed_slots: vec![],
            authorization_bytes: vec![],
        };
        let bytes = intent.to_bytes();
        // The raw secret bytes must not appear anywhere in the wire payload.
        let found = bytes.windows(32).any(|w| w == secret);
        assert!(!found, "spend_secret leaked into TxIntent wire bytes");
    }

    #[test]
    fn rejects_trailing_bytes() {
        let intent = TxIntent {
            tx_body: mk_body(),
            tx_body_hash: TxBodyHash([0; 32]),
            claims_commitment: [0; 32],
            claimed_slots: vec![],
            authorization_bytes: vec![],
        };
        let mut bytes = intent.to_bytes();
        bytes.push(0xFF);
        assert_eq!(TxIntent::from_bytes(&bytes), Err(WireError::TrailingBytes));
    }

    #[test]
    fn claimed_slots_from_body_works() {
        let body = mk_body();
        let slots = TxIntent::claimed_slots_from_body(&body);
        assert_eq!(slots.len(), 2); // 1 live input + 1 live output
        assert_eq!(slots[0].slot_index, 42);
        assert_eq!(slots[0].value, 1000);
        assert_eq!(slots[1].slot_index, 99);
        assert_eq!(slots[1].value, 900);
    }
}
