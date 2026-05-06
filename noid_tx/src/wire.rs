// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Canonical wire encoding for transparent transaction types.
//!
//! Fixed-width, little-endian. Counts on variable-length vectors
//! (`inputs`, `outputs`) are explicit `u32`s, each bounded by its
//! spec-level maximum. Every 32-byte digest is a passthrough byte copy;
//! `value` is 8 LE bytes; `slot_index` is 4 LE bytes.

use noid_poseidon2b::primitives::{Address, AuthTag, Digest, SpendSecret, TxBodyHash};

use crate::public::PublicInputs;
use crate::types::{Transaction, TxBody, TxInput, TxOutput};

/// Encoding / decoding errors surfaced to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    CountTooLarge,
    ShapeMismatch,
    InvalidBool,
    TrailingBytes,
    UnknownVersion,
}

#[inline]
fn put_digest(buf: &mut Vec<u8>, d: &Digest) {
    buf.extend_from_slice(d);
}
#[inline]
fn put_u128(buf: &mut Vec<u8>, v: u128) {
    buf.extend_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_bool(buf: &mut Vec<u8>, v: bool) {
    buf.push(if v { 1u8 } else { 0u8 });
}

#[inline]
fn take<'a>(src: &mut &'a [u8], n: usize) -> Result<&'a [u8], WireError> {
    if src.len() < n {
        return Err(WireError::Truncated);
    }
    let (head, tail) = src.split_at(n);
    *src = tail;
    Ok(head)
}
#[inline]
fn take_digest(src: &mut &[u8]) -> Result<Digest, WireError> {
    let bytes = take(src, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
#[inline]
fn take_u128(src: &mut &[u8]) -> Result<u128, WireError> {
    let bytes = take(src, 16)?;
    Ok(u128::from_le_bytes(bytes.try_into().unwrap()))
}
#[inline]
fn take_u64(src: &mut &[u8]) -> Result<u64, WireError> {
    let bytes = take(src, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}
#[inline]
fn take_u32(src: &mut &[u8]) -> Result<u32, WireError> {
    let bytes = take(src, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}
#[inline]
fn take_bool(src: &mut &[u8]) -> Result<bool, WireError> {
    let b = take(src, 1)?[0];
    match b {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WireError::InvalidBool),
    }
}

// ---------------------------------------------------------------------------
// TxInput
//   slot_index (4) + value (8) + owner (32) + spend_secret (32)
//   + auth_tag (32) + valid (1) = 109 bytes
// ---------------------------------------------------------------------------

pub const TX_INPUT_WIRE_SIZE: usize = 4 + 8 + 32 + 32 + 32 + 1;

impl TxInput {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.slot_index);
        put_u64(buf, self.value);
        put_digest(buf, &self.owner.0);
        put_digest(buf, &self.spend_secret.0);
        put_digest(buf, &self.auth_tag.0);
        put_bool(buf, self.valid);
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let slot_index = take_u32(src)?;
        let value = take_u64(src)?;
        let owner = Address(take_digest(src)?);
        let spend_secret = SpendSecret(take_digest(src)?);
        let auth_tag = AuthTag(take_digest(src)?);
        let valid = take_bool(src)?;
        Ok(Self {
            slot_index,
            value,
            owner,
            spend_secret,
            auth_tag,
            valid,
        })
    }
}

// ---------------------------------------------------------------------------
// TxOutput : value (8) + owner (32) + valid (1) = 41 bytes
// ---------------------------------------------------------------------------

pub const TX_OUTPUT_WIRE_SIZE: usize = 8 + 32 + 1;

impl TxOutput {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u64(buf, self.value);
        put_digest(buf, &self.owner.0);
        put_bool(buf, self.valid);
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let value = take_u64(src)?;
        let owner = Address(take_digest(src)?);
        let valid = take_bool(src)?;
        Ok(Self {
            value,
            owner,
            valid,
        })
    }
}

// ---------------------------------------------------------------------------
// TxBody
// ---------------------------------------------------------------------------

pub const TX_BODY_VERSION: u8 = 1;

impl TxBody {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        assert!(
            self.inputs.len() <= crate::types::MAX_INPUTS,
            "inputs exceed MAX_INPUTS"
        );
        assert!(
            self.outputs.len() <= crate::types::MAX_OUTPUTS,
            "outputs exceed MAX_OUTPUTS"
        );

        buf.push(TX_BODY_VERSION);
        put_digest(buf, &self.prev_state_root);
        put_digest(buf, &self.new_state_root);
        put_u128(buf, self.fee);
        put_u32(buf, self.inputs.len() as u32);
        for i in &self.inputs {
            i.encode(buf);
        }
        put_u32(buf, self.outputs.len() as u32);
        for o in &self.outputs {
            o.encode(buf);
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + 2 * 32
                + 16
                + 4
                + self.inputs.len() * TX_INPUT_WIRE_SIZE
                + 4
                + self.outputs.len() * TX_OUTPUT_WIRE_SIZE,
        );
        self.encode(&mut buf);
        buf
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let v = take(src, 1)?[0];
        if v != TX_BODY_VERSION {
            return Err(WireError::UnknownVersion);
        }
        let prev_state_root = take_digest(src)?;
        let new_state_root = take_digest(src)?;
        let fee = take_u128(src)?;

        let n_in = take_u32(src)? as usize;
        if n_in > crate::types::MAX_INPUTS {
            return Err(WireError::CountTooLarge);
        }
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            inputs.push(TxInput::decode(src)?);
        }

        let n_out = take_u32(src)? as usize;
        if n_out > crate::types::MAX_OUTPUTS {
            return Err(WireError::CountTooLarge);
        }
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            outputs.push(TxOutput::decode(src)?);
        }

        Ok(Self {
            prev_state_root,
            new_state_root,
            fee,
            inputs,
            outputs,
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

// ---------------------------------------------------------------------------
// Transaction : body + tx_body_hash. Auth tags travel inside TxInput.
// ---------------------------------------------------------------------------

impl Transaction {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.body.encode(buf);
        put_digest(buf, &self.tx_body_hash.0);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let body = TxBody::decode(src)?;
        let tx_body_hash = TxBodyHash(take_digest(src)?);
        Ok(Self { body, tx_body_hash })
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

// ---------------------------------------------------------------------------
// PublicInputs : prev_root (32) + new_root (32) + tx_body_hash (32) + fee (16)
// ---------------------------------------------------------------------------

pub const PUBLIC_INPUTS_WIRE_SIZE: usize = 3 * 32 + 16;

impl PublicInputs {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_digest(buf, &self.prev_state_root);
        put_digest(buf, &self.new_state_root);
        put_digest(buf, &self.tx_body_hash.0);
        put_u128(buf, self.fee);
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_INPUTS_WIRE_SIZE] {
        let mut out = [0u8; PUBLIC_INPUTS_WIRE_SIZE];
        let mut i = 0;
        out[i..i + 32].copy_from_slice(&self.prev_state_root);
        i += 32;
        out[i..i + 32].copy_from_slice(&self.new_state_root);
        i += 32;
        out[i..i + 32].copy_from_slice(&self.tx_body_hash.0);
        i += 32;
        out[i..i + 16].copy_from_slice(&self.fee.to_le_bytes());
        out
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let prev_state_root = take_digest(src)?;
        let new_state_root = take_digest(src)?;
        let tx_body_hash = TxBodyHash(take_digest(src)?);
        let fee = take_u128(src)?;
        Ok(Self {
            prev_state_root,
            new_state_root,
            tx_body_hash,
            fee,
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
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};

    fn mk_output(seed: u8) -> TxOutput {
        TxOutput {
            value: (seed as u64) * 7,
            owner: Address([seed; 32]),
            valid: true,
        }
    }

    fn mk_input(seed: u8) -> TxInput {
        TxInput {
            slot_index: seed as u32,
            value: (seed as u64) * 11,
            owner: Address([seed; 32]),
            spend_secret: SpendSecret([seed ^ 0xAA; 32]),
            auth_tag: AuthTag([seed ^ 0x55; 32]),
            valid: true,
        }
    }

    #[test]
    fn tx_input_roundtrip() {
        let i = mk_input(5);
        let mut buf = Vec::new();
        i.encode(&mut buf);
        assert_eq!(buf.len(), TX_INPUT_WIRE_SIZE);
        let mut src: &[u8] = &buf;
        let back = TxInput::decode(&mut src).unwrap();
        assert!(src.is_empty());
        assert_eq!(back, i);
    }

    #[test]
    fn tx_output_roundtrip() {
        let o = mk_output(7);
        let mut buf = Vec::new();
        o.encode(&mut buf);
        assert_eq!(buf.len(), TX_OUTPUT_WIRE_SIZE);
        let mut src: &[u8] = &buf;
        let back = TxOutput::decode(&mut src).unwrap();
        assert!(src.is_empty());
        assert_eq!(back, o);
    }

    #[test]
    fn tx_body_roundtrip() {
        let body = TxBody {
            prev_state_root: [0x11u8; 32],
            new_state_root: [0x22u8; 32],
            fee: 42u128,
            inputs: vec![mk_input(1), mk_input(2), TxInput::dummy()],
            outputs: vec![mk_output(1), mk_output(2), TxOutput::dummy()],
        };
        let bytes = body.to_bytes();
        let back = TxBody::from_bytes(&bytes).unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn tx_body_rejects_too_many_inputs() {
        let mut buf = Vec::new();
        buf.push(TX_BODY_VERSION);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 16]);
        put_u32(&mut buf, (crate::types::MAX_INPUTS + 1) as u32);
        assert_eq!(TxBody::from_bytes(&buf), Err(WireError::CountTooLarge));
    }

    #[test]
    fn tx_body_rejects_trailing_bytes() {
        let body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![],
        };
        let mut bytes = body.to_bytes();
        bytes.push(0xFF);
        assert_eq!(TxBody::from_bytes(&bytes), Err(WireError::TrailingBytes));
    }

    #[test]
    fn tx_body_rejects_wrong_version() {
        let body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![],
        };
        let mut bytes = body.to_bytes();
        bytes[0] = 0xFF;
        assert_eq!(TxBody::from_bytes(&bytes), Err(WireError::UnknownVersion));
    }

    #[test]
    fn transaction_roundtrip() {
        let body = TxBody {
            prev_state_root: [0xAAu8; 32],
            new_state_root: [0xBBu8; 32],
            fee: 7,
            inputs: vec![mk_input(3)],
            outputs: vec![mk_output(4)],
        };
        let tx = Transaction {
            tx_body_hash: TxBodyHash([0x99u8; 32]),
            body,
        };
        let bytes = tx.to_bytes();
        let back = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(back.tx_body_hash, tx.tx_body_hash);
        assert_eq!(back.body, tx.body);
    }

    #[test]
    fn public_inputs_roundtrip() {
        let p = PublicInputs {
            prev_state_root: [1u8; 32],
            new_state_root: [2u8; 32],
            tx_body_hash: TxBodyHash([4u8; 32]),
            fee: 0xFEED_FACE_CAFE_BEEFu128,
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), PUBLIC_INPUTS_WIRE_SIZE);
        let back = PublicInputs::from_bytes(&bytes).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn truncated_decode_errors_cleanly() {
        let body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![mk_input(1)],
            outputs: vec![],
        };
        let bytes = body.to_bytes();
        for cut in 0..bytes.len() {
            let res = TxBody::from_bytes(&bytes[..cut]);
            assert!(res.is_err(), "expected error at cut={}", cut);
        }
    }

    #[test]
    #[should_panic(expected = "inputs exceed MAX_INPUTS")]
    fn tx_body_encode_panics_when_inputs_exceed_bound() {
        let body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![TxInput::dummy(); crate::types::MAX_INPUTS + 1],
            outputs: vec![],
        };
        let mut buf = Vec::new();
        body.encode(&mut buf);
    }

    #[test]
    #[should_panic(expected = "outputs exceed MAX_OUTPUTS")]
    fn tx_body_encode_panics_when_outputs_exceed_bound() {
        let body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![TxOutput::dummy(); crate::types::MAX_OUTPUTS + 1],
        };
        let mut buf = Vec::new();
        body.encode(&mut buf);
    }
}
