// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! TxIntent: the network payload for stateless transactions.
//!
//! A TxIntent carries everything a full node needs to validate and
//! include a transaction without re-executing it:
//! - The transaction body (epoch_anchor, fee, inputs, outputs)
//! - The opaque wallet authorization bytes (AuthGKR Kill-Shot)
//!
//! Slot claims and their commitment are derived from the hash-bound body by
//! validators. Carrying a second copy here would add a malleable representation
//! and, for outputs, an incarnation that does not exist until block inclusion.
//!
//! Neither `prev_state_root` nor `new_state_root` appear — state
//! binding is performed at block level by the miner.

use noid_poseidon2b::primitives::TxBodyHash;

use crate::types::TxBody;

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
    /// Opaque serialized WalletAuthorizationBundle (AuthGKR only).
    /// Wire format is defined by the proof system; we carry raw bytes.
    pub authorization_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Wire encoding
// ---------------------------------------------------------------------------

use crate::wire::WireError;

/// Incompatible intent epoch for the packed-incarnation/minimal-intent format.
/// Chosen outside the valid transaction-shape byte range so older decoders
/// reject new intents immediately instead of reinterpreting shifted fields.
pub const TX_INTENT_WIRE_VERSION: u8 = 0xA2;

impl TxIntent {
    /// Construct a public intent from a body and detached authorization proof.
    ///
    /// The transitional per-input secret field is canonicalized to zero before
    /// the body enters the public object. The canonical txid is derived here;
    /// callers cannot supply an independent hash.
    pub fn new(mut tx_body: TxBody, authorization_bytes: Vec<u8>) -> Self {
        tx_body.clear_transitional_spend_secrets();
        let tx_body_hash = tx_body.txid();
        Self {
            tx_body,
            tx_body_hash,
            authorization_bytes,
        }
    }

    /// Canonical transaction id derived from the intent body.
    ///
    /// The transitional `tx_body_hash` field remains wire-visible until the
    /// fixed Tx8x2 cutover, but this accessor never trusts that duplicate.
    #[inline]
    pub fn txid(&self) -> TxBodyHash {
        self.tx_body.txid()
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(TX_INTENT_WIRE_VERSION);
        self.tx_body.encode(buf);
        buf.extend_from_slice(&self.tx_body_hash.0);
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
        let Some((&version, tail)) = src.split_first() else {
            return Err(WireError::Truncated);
        };
        if version != TX_INTENT_WIRE_VERSION {
            return Err(WireError::UnsupportedVersion);
        }
        *src = tail;

        let tx_body = TxBody::decode(src)?;

        if src.len() < 32 {
            return Err(WireError::Truncated);
        }
        let mut tx_body_hash = [0u8; 32];
        tx_body_hash.copy_from_slice(&src[..32]);
        *src = &src[32..];

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
                creation_id: 7,
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
                    creation_id: i as u64 + 1,
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
        assert_eq!(back.authorization_bytes, intent.authorization_bytes);
    }

    #[test]
    fn sweep_roundtrip() {
        let body = mk_sweep_body();
        let intent = TxIntent {
            tx_body: body,
            tx_body_hash: TxBodyHash([0xBC; 32]),
            authorization_bytes: vec![1, 2, 3],
        };
        let bytes = intent.to_bytes();
        let back = TxIntent::from_bytes(&bytes).unwrap();
        assert_eq!(back.tx_body.shape, crate::types::TxShape::Sweep25x2);
        assert_eq!(back.tx_body.inputs.len(), 5);
        assert_eq!(back.tx_body.outputs.len(), 2);
        assert!(
            back.tx_body
                .inputs
                .iter()
                .all(|inp| inp.spend_secret == SpendSecret([0u8; 32]))
        );
    }

    /// Verify spend_secret is NOT present in the serialized bytes.
    #[test]
    fn spend_secret_absent_from_wire() {
        let body = mk_body();
        let secret = body.inputs[0].spend_secret.0;
        let intent = TxIntent {
            tx_body: body,
            tx_body_hash: TxBodyHash([0xBB; 32]),
            authorization_bytes: vec![],
        };
        let bytes = intent.to_bytes();
        // The raw secret bytes must not appear anywhere in the wire payload.
        let found = bytes.windows(32).any(|w| w == secret);
        assert!(!found, "spend_secret leaked into TxIntent wire bytes");
    }

    #[test]
    fn constructor_canonicalizes_secret_and_wire_is_secret_invariant() {
        let body = mk_body();
        let mut same_public_body = body.clone();
        same_public_body.inputs[0].spend_secret = SpendSecret([0xD9; 32]);

        let intent = TxIntent::new(body, vec![1, 2, 3]);
        let same_public_intent = TxIntent::new(same_public_body, vec![1, 2, 3]);

        assert_eq!(
            intent.tx_body.inputs[0].spend_secret,
            SpendSecret([0u8; 32])
        );
        assert_eq!(intent.tx_body_hash, intent.tx_body.txid());
        assert_eq!(intent.txid(), intent.tx_body_hash);
        assert_eq!(intent.to_bytes(), same_public_intent.to_bytes());

        let mut stale = intent;
        stale.tx_body_hash = TxBodyHash([0xFE; 32]);
        assert_ne!(stale.tx_body_hash, stale.txid());
        assert_eq!(stale.txid(), stale.tx_body.txid());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let intent = TxIntent {
            tx_body: mk_body(),
            tx_body_hash: TxBodyHash([0; 32]),
            authorization_bytes: vec![],
        };
        let mut bytes = intent.to_bytes();
        bytes.push(0xFF);
        assert_eq!(TxIntent::from_bytes(&bytes), Err(WireError::TrailingBytes));
    }

    #[test]
    fn rejects_missing_format_marker() {
        let intent = TxIntent {
            tx_body: mk_body(),
            tx_body_hash: TxBodyHash([0; 32]),
            authorization_bytes: vec![],
        };
        let mut bytes = intent.to_bytes();
        bytes.remove(0);
        assert_eq!(
            TxIntent::from_bytes(&bytes),
            Err(WireError::UnsupportedVersion)
        );
    }
}
