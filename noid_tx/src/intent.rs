// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Secret-free user transaction intent: one Tx8x2 body plus its detached
//! owner-authorization proof.

use noid_poseidon2b::primitives::TxBodyHash;

use crate::{wire::WireError, TxBody, TX_BODY_WIRE_SIZE};

/// Fixed construction marker. It is not a negotiable version.
pub const TX_INTENT_MARKER: u8 = 0xA2;
pub const MAX_TX_AUTHORIZATION_BYTES: usize = 256 * 1024;
pub const TX_INTENT_FIXED_OVERHEAD: usize = 1 + TX_BODY_WIRE_SIZE + 4;
pub const MAX_TX_INTENT_BYTES: usize = TX_INTENT_FIXED_OVERHEAD + MAX_TX_AUTHORIZATION_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIntent {
    pub tx_body: TxBody,
    pub authorization_bytes: Vec<u8>,
}

impl TxIntent {
    pub fn new(tx_body: TxBody, authorization_bytes: Vec<u8>) -> Self {
        assert!(!tx_body.is_coinbase, "coinbase is not a TxIntent");
        assert!(
            authorization_bytes.len() <= MAX_TX_AUTHORIZATION_BYTES,
            "authorization exceeds canonical intent cap"
        );
        assert!(
            tx_body.validate_canonical().is_ok(),
            "non-canonical intent body"
        );
        Self {
            tx_body,
            authorization_bytes,
        }
    }

    #[inline]
    pub fn txid(&self) -> TxBodyHash {
        self.tx_body.txid()
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        assert!(!self.tx_body.is_coinbase, "coinbase is not a TxIntent");
        assert!(self.authorization_bytes.len() <= MAX_TX_AUTHORIZATION_BYTES);
        buf.push(TX_INTENT_MARKER);
        self.tx_body.encode(buf);
        buf.extend_from_slice(&(self.authorization_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.authorization_bytes);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(TX_INTENT_FIXED_OVERHEAD + self.authorization_bytes.len());
        self.encode(&mut bytes);
        bytes
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let (&marker, tail) = src.split_first().ok_or(WireError::Truncated)?;
        if marker != TX_INTENT_MARKER {
            return Err(WireError::BadMarker);
        }
        *src = tail;
        let tx_body = TxBody::decode(src)?;
        if tx_body.is_coinbase {
            return Err(WireError::CoinbaseIntent);
        }
        if src.len() < 4 {
            return Err(WireError::Truncated);
        }
        let auth_len = u32::from_le_bytes(src[..4].try_into().unwrap()) as usize;
        *src = &src[4..];
        if auth_len > MAX_TX_AUTHORIZATION_BYTES {
            return Err(WireError::AuthorizationTooLarge);
        }
        if src.len() < auth_len {
            return Err(WireError::Truncated);
        }
        let authorization_bytes = src[..auth_len].to_vec();
        *src = &src[auth_len..];
        Ok(Self {
            tx_body,
            authorization_bytes,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_TX_INTENT_BYTES {
            return Err(WireError::AuthorizationTooLarge);
        }
        let mut src = bytes;
        let intent = Self::decode(&mut src)?;
        if !src.is_empty() {
            return Err(WireError::TrailingBytes);
        }
        Ok(intent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{output_bitmap_bit, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};
    use noid_poseidon2b::primitives::Address;

    fn body() -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 1,
            amount: 10,
            creation_id: 2,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 2,
            amount: 9,
            owner: Address([4u8; 32]),
        };
        TxBody {
            epoch_anchor: [3u8; 32],
            fee: 1,
            input_owner: Address([5u8; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    #[test]
    fn exact_roundtrip_has_no_duplicate_txid() {
        let intent = TxIntent::new(body(), vec![1, 2, 3]);
        let bytes = intent.to_bytes();
        assert_eq!(bytes.len(), TX_INTENT_FIXED_OVERHEAD + 3);
        assert_eq!(bytes[0], TX_INTENT_MARKER);
        assert_eq!(TxIntent::from_bytes(&bytes), Ok(intent));
    }

    #[test]
    fn wrong_marker_trailing_and_oversize_reject() {
        let intent = TxIntent::new(body(), vec![]);
        let mut bytes = intent.to_bytes();
        bytes[0] ^= 1;
        assert_eq!(TxIntent::from_bytes(&bytes), Err(WireError::BadMarker));

        let mut bytes = intent.to_bytes();
        bytes.push(0);
        assert_eq!(TxIntent::from_bytes(&bytes), Err(WireError::TrailingBytes));

        let mut bytes = intent.to_bytes();
        let len_offset = 1 + TX_BODY_WIRE_SIZE;
        bytes[len_offset..len_offset + 4]
            .copy_from_slice(&((MAX_TX_AUTHORIZATION_BYTES as u32) + 1).to_le_bytes());
        assert_eq!(
            TxIntent::from_bytes(&bytes),
            Err(WireError::AuthorizationTooLarge)
        );
    }
}
