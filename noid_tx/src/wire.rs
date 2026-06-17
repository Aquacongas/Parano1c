// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical wire encoding for transparent transaction types.
//!
//! Fixed-width, little-endian. Counts on variable-length vectors
//! (`inputs`, `outputs`) are explicit `u32`s, each bounded by its
//! spec-level maximum. Every 32-byte digest is a passthrough byte copy;
//! `value` is 8 LE bytes; `slot_index` is 4 LE bytes.

use noid_poseidon2b::primitives::{Address, AuthTag, Digest, SpendSecret, TxBodyHash};

use crate::public::PublicInputs;
use crate::types::{Transaction, TxBody, TxInput, TxOutput, TxShape};

/// Encoding / decoding errors surfaced to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    CountTooLarge,
    /// fee field exceeds u64::MAX — cannot be represented in the
    /// balance circuit (which uses 64-bit operands).
    FeeTooLarge,
    ShapeMismatch,
    InvalidBool,
    InvalidShape,
    UnsupportedShape,
    TrailingBytes,
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
fn put_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
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
#[inline]
fn take_u8(src: &mut &[u8]) -> Result<u8, WireError> {
    Ok(take(src, 1)?[0])
}

#[inline]
fn take_shape(src: &mut &[u8]) -> Result<TxShape, WireError> {
    TxShape::from_id(take_u8(src)?).ok_or(WireError::InvalidShape)
}

// ---------------------------------------------------------------------------
// TxInput
//
// Two wire formats:
//
//   FULL  (local wallet storage only — NEVER sent over the network):
//     slot_index (4) + value (8) + owner (32) + spend_secret (32)
//     + auth_tag (32) + valid (1) = 109 bytes
//
//   PUBLIC (network wire format — spend_secret omitted):
//     slot_index (4) + value (8) + owner (32) + auth_tag (32) + valid (1) = 77 bytes
//
// The full format is used internally by the wallet to persist its own
// transaction records. The public format is what goes into TxIntent and
// is broadcast to the mempool. Full nodes never need spend_secret —
// they only read (slot_index, value, owner) for state binding and
// (auth_tag) is already committed via the LogicProof.
// ---------------------------------------------------------------------------

/// Wire size of the FULL local format (includes spend_secret).
pub const TX_INPUT_WIRE_SIZE: usize = 4 + 8 + 32 + 32 + 32 + 1;

/// Wire size of the PUBLIC network format (spend_secret omitted).
pub const TX_INPUT_PUBLIC_WIRE_SIZE: usize = 4 + 8 + 32 + 32 + 1;

impl TxInput {
    /// Encode with spend_secret included. **Local wallet storage only.**
    /// MUST NOT be used for network payloads.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.slot_index);
        put_u64(buf, self.value);
        put_digest(buf, &self.owner.0);
        put_digest(buf, &self.spend_secret.0);
        put_digest(buf, &self.auth_tag.0);
        put_bool(buf, self.valid);
    }

    /// Encode WITHOUT spend_secret. Used in `TxBody::encode_public` and
    /// `TxIntent`. Safe to broadcast over the network.
    pub fn encode_public(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.slot_index);
        put_u64(buf, self.value);
        put_digest(buf, &self.owner.0);
        put_digest(buf, &self.auth_tag.0);
        put_bool(buf, self.valid);
    }

    /// Decode full format (includes spend_secret). Local storage only.
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

    /// Decode public network format (spend_secret absent → zeroed).
    pub fn decode_public(src: &mut &[u8]) -> Result<Self, WireError> {
        let slot_index = take_u32(src)?;
        let value = take_u64(src)?;
        let owner = Address(take_digest(src)?);
        let auth_tag = AuthTag(take_digest(src)?);
        let valid = take_bool(src)?;
        Ok(Self {
            slot_index,
            value,
            owner,
            spend_secret: SpendSecret([0u8; 32]),
            auth_tag,
            valid,
        })
    }
}

// ---------------------------------------------------------------------------
// TxOutput : slot_index (4) + value (8) + owner (32) + valid (1) = 45 bytes
// ---------------------------------------------------------------------------

pub const TX_OUTPUT_WIRE_SIZE: usize = 4 + 8 + 32 + 1;

impl TxOutput {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_u32(buf, self.slot_index);
        put_u64(buf, self.value);
        put_digest(buf, &self.owner.0);
        put_bool(buf, self.valid);
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let slot_index = take_u32(src)?;
        let value = take_u64(src)?;
        let owner = Address(take_digest(src)?);
        let valid = take_bool(src)?;
        Ok(Self {
            slot_index,
            value,
            owner,
            valid,
        })
    }
}

// ---------------------------------------------------------------------------
// TxBody
// ---------------------------------------------------------------------------

impl TxBody {
    /// Encode with spend_secret in each input. **Local wallet storage only.**
    /// MUST NOT be used for network payloads — use `encode_public` instead.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        assert!(
            self.inputs.len() <= self.shape.max_inputs(),
            "inputs exceed shape max"
        );
        assert!(
            self.outputs.len() <= self.shape.max_outputs(),
            "outputs exceed shape max"
        );
        assert!(
            self.fee <= u64::MAX as u128,
            "fee ({}) exceeds u64::MAX — balance circuit cannot represent it",
            self.fee,
        );

        put_u8(buf, self.shape.id());
        put_digest(buf, &self.epoch_anchor);
        put_u128(buf, self.fee);
        put_u32(buf, self.inputs.len() as u32);
        for i in &self.inputs {
            i.encode(buf);
        }
        put_u32(buf, self.outputs.len() as u32);
        for o in &self.outputs {
            o.encode(buf);
        }
        put_bool(buf, self.is_coinbase);
    }

    /// Encode WITHOUT spend_secret in inputs. This is the network wire format
    /// used inside `TxIntent`. Safe to broadcast to full nodes.
    pub fn encode_public(&self, buf: &mut Vec<u8>) {
        assert!(
            self.inputs.len() <= self.shape.max_inputs(),
            "inputs exceed shape max"
        );
        assert!(
            self.outputs.len() <= self.shape.max_outputs(),
            "outputs exceed shape max"
        );
        assert!(
            self.fee <= u64::MAX as u128,
            "fee ({}) exceeds u64::MAX — balance circuit cannot represent it",
            self.fee,
        );

        put_u8(buf, self.shape.id());
        put_digest(buf, &self.epoch_anchor);
        put_u128(buf, self.fee);
        put_u32(buf, self.inputs.len() as u32);
        for i in &self.inputs {
            i.encode_public(buf);
        }
        put_u32(buf, self.outputs.len() as u32);
        for o in &self.outputs {
            o.encode(buf);
        }
        put_bool(buf, self.is_coinbase);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + 32
                + 16
                + 4
                + self.inputs.len() * TX_INPUT_WIRE_SIZE
                + 4
                + self.outputs.len() * TX_OUTPUT_WIRE_SIZE
                + 1,
        );
        self.encode(&mut buf);
        buf
    }

    /// Decode full format (includes spend_secret). Local storage only.
    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let shape = take_shape(src)?;
        let epoch_anchor = take_digest(src)?;
        let fee = take_u128(src)?;
        if fee > u64::MAX as u128 {
            return Err(WireError::FeeTooLarge);
        }

        let n_in = take_u32(src)? as usize;
        if n_in > shape.max_inputs() {
            return Err(WireError::CountTooLarge);
        }
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            inputs.push(TxInput::decode(src)?);
        }

        let n_out = take_u32(src)? as usize;
        if n_out > shape.max_outputs() {
            return Err(WireError::CountTooLarge);
        }
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            outputs.push(TxOutput::decode(src)?);
        }

        let is_coinbase = take_bool(src)?;

        Ok(Self {
            shape,
            epoch_anchor,
            fee,
            inputs,
            outputs,
            is_coinbase,
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

    /// Decode public network format (spend_secret absent in inputs → zeroed).
    pub fn decode_public(src: &mut &[u8]) -> Result<Self, WireError> {
        let shape = take_shape(src)?;
        let epoch_anchor = take_digest(src)?;
        let fee = take_u128(src)?;
        if fee > u64::MAX as u128 {
            return Err(WireError::FeeTooLarge);
        }

        let n_in = take_u32(src)? as usize;
        if n_in > shape.max_inputs() {
            return Err(WireError::CountTooLarge);
        }
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            inputs.push(TxInput::decode_public(src)?);
        }

        let n_out = take_u32(src)? as usize;
        if n_out > shape.max_outputs() {
            return Err(WireError::CountTooLarge);
        }
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            outputs.push(TxOutput::decode(src)?);
        }

        let is_coinbase = take_bool(src)?;

        Ok(Self {
            shape,
            epoch_anchor,
            fee,
            inputs,
            outputs,
            is_coinbase,
        })
    }

    pub fn from_bytes_public(bytes: &[u8]) -> Result<Self, WireError> {
        let mut src = bytes;
        let out = Self::decode_public(&mut src)?;
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
// PublicInputs : epoch_anchor (32) + tx_body_hash (32) + shape_id (1)
//              + fee (16) + n_live_inputs (1) + n_live_outputs (1)
//              + coinbase_credit (8) + log_slots (4)
//              + claims_commitment (32)
//              + is_activation[MAX_OUTPUTS] (MAX_OUTPUTS bytes, 0/1)
//              + is_deactivation[MAX_INPUTS] (MAX_INPUTS bytes, 0/1)
// ---------------------------------------------------------------------------

pub const PUBLIC_INPUTS_WIRE_SIZE: usize =
    3 * 32 + 1 + 16 + 1 + 1 + 8 + 4 + crate::types::MAX_OUTPUTS + crate::types::MAX_INPUTS;

impl PublicInputs {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_digest(buf, &self.epoch_anchor);
        put_digest(buf, &self.tx_body_hash.0);
        put_u8(buf, self.shape_id);
        put_u128(buf, self.fee);
        buf.push(self.n_live_inputs);
        buf.push(self.n_live_outputs);
        put_u64(buf, self.coinbase_credit);
        put_u32(buf, self.log_slots);
        put_digest(buf, &self.claims_commitment);
        for b in &self.is_activation {
            put_bool(buf, *b);
        }
        for b in &self.is_deactivation {
            put_bool(buf, *b);
        }
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_INPUTS_WIRE_SIZE] {
        let mut out = [0u8; PUBLIC_INPUTS_WIRE_SIZE];
        let mut i = 0;
        out[i..i + 32].copy_from_slice(&self.epoch_anchor);
        i += 32;
        out[i..i + 32].copy_from_slice(&self.tx_body_hash.0);
        i += 32;
        out[i] = self.shape_id;
        i += 1;
        out[i..i + 16].copy_from_slice(&self.fee.to_le_bytes());
        i += 16;
        out[i] = self.n_live_inputs;
        i += 1;
        out[i] = self.n_live_outputs;
        i += 1;
        out[i..i + 8].copy_from_slice(&self.coinbase_credit.to_le_bytes());
        i += 8;
        out[i..i + 4].copy_from_slice(&self.log_slots.to_le_bytes());
        i += 4;
        out[i..i + 32].copy_from_slice(&self.claims_commitment);
        i += 32;
        for b in &self.is_activation {
            out[i] = if *b { 1 } else { 0 };
            i += 1;
        }
        for b in &self.is_deactivation {
            out[i] = if *b { 1 } else { 0 };
            i += 1;
        }
        out
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let epoch_anchor = take_digest(src)?;
        let tx_body_hash = TxBodyHash(take_digest(src)?);
        let shape_id = take_u8(src)?;
        if TxShape::from_id(shape_id).is_none() {
            return Err(WireError::InvalidShape);
        }
        let fee = take_u128(src)?;
        let n_live_inputs = take(src, 1)?[0];
        let n_live_outputs = take(src, 1)?[0];
        if (n_live_inputs as usize) > crate::types::MAX_INPUTS
            || (n_live_outputs as usize) > crate::types::MAX_OUTPUTS
        {
            return Err(WireError::CountTooLarge);
        }
        let coinbase_credit = take_u64(src)?;
        let log_slots = take_u32(src)?;
        if !(crate::public::MIN_LOG_SLOTS..=crate::public::MAX_LOG_SLOTS).contains(&log_slots) {
            return Err(WireError::ShapeMismatch);
        }
        let claims_commitment = take_digest(src)?;
        let mut is_activation = [false; crate::types::MAX_OUTPUTS];
        for slot in is_activation.iter_mut() {
            *slot = take_bool(src)?;
        }
        let mut is_deactivation = [false; crate::types::MAX_INPUTS];
        for slot in is_deactivation.iter_mut() {
            *slot = take_bool(src)?;
        }
        Ok(Self {
            epoch_anchor,
            tx_body_hash,
            shape_id,
            fee,
            n_live_inputs,
            n_live_outputs,
            coinbase_credit,
            log_slots,
            claims_commitment,
            is_activation,
            is_deactivation,
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
            slot_index: (seed as u32).wrapping_mul(3),
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
        let body = TxBody::standard(
            [0x11u8; 32],
            42u128,
            vec![mk_input(1), mk_input(2), TxInput::dummy()],
            vec![mk_output(1), mk_output(2), TxOutput::dummy()],
            false,
        );
        let bytes = body.to_bytes();
        let back = TxBody::from_bytes(&bytes).unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn tx_body_coinbase_roundtrip() {
        let body = TxBody::standard([0u8; 32], 0, vec![], vec![mk_output(1)], true);
        let bytes = body.to_bytes();
        let back = TxBody::from_bytes(&bytes).unwrap();
        assert_eq!(back, body);
        assert!(back.is_coinbase);
    }

    #[test]
    fn tx_body_is_coinbase_byte_is_bound() {
        let body = TxBody::standard([0u8; 32], 0, vec![], vec![], false);
        let mut bytes = body.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] = 1;
        let back = TxBody::from_bytes(&bytes).unwrap();
        assert!(back.is_coinbase);
        bytes[last] = 0x42;
        assert_eq!(TxBody::from_bytes(&bytes), Err(WireError::InvalidBool));
    }

    #[test]
    fn tx_body_rejects_invalid_shape_id() {
        let bytes = [0xFFu8];
        assert_eq!(TxBody::from_bytes(&bytes), Err(WireError::InvalidShape));
    }

    #[test]
    fn tx_body_sweep25x2_roundtrip() {
        let body = TxBody {
            shape: TxShape::Sweep25x2,
            epoch_anchor: [0x22u8; 32],
            fee: 123,
            inputs: (0..25).map(|i| mk_input(i as u8 + 1)).collect(),
            outputs: vec![mk_output(1), mk_output(2)],
            is_coinbase: false,
        };
        let bytes = body.to_bytes();
        let back = TxBody::from_bytes(&bytes).unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn tx_body_rejects_too_many_inputs() {
        let mut buf = Vec::new();
        put_u8(&mut buf, TxShape::Standard4x8.id());
        buf.extend_from_slice(&[0u8; 32]); // epoch_anchor
        buf.extend_from_slice(&[0u8; 16]); // fee
        put_u32(&mut buf, (TxShape::Standard4x8.max_inputs() + 1) as u32);
        assert_eq!(TxBody::from_bytes(&buf), Err(WireError::CountTooLarge));
    }

    #[test]
    fn tx_body_rejects_too_many_sweep_outputs() {
        let mut buf = Vec::new();
        put_u8(&mut buf, TxShape::Sweep25x2.id());
        buf.extend_from_slice(&[0u8; 32]); // epoch_anchor
        buf.extend_from_slice(&[0u8; 16]); // fee
        put_u32(&mut buf, 0u32); // n_inputs
        put_u32(&mut buf, (TxShape::Sweep25x2.max_outputs() + 1) as u32);
        assert_eq!(TxBody::from_bytes(&buf), Err(WireError::CountTooLarge));
    }

    #[test]
    fn tx_body_rejects_fee_too_large() {
        // fee = u64::MAX + 1 = 2^64 must be rejected because the balance
        // circuit uses 64-bit operands; u128 fee above this range cannot
        // be faithfully represented.
        let mut buf = Vec::new();
        put_u8(&mut buf, TxShape::Standard4x8.id());
        buf.extend_from_slice(&[0u8; 32]); // epoch_anchor
                                           // fee = u64::MAX + 1 as little-endian u128
        let fee_too_large: u128 = u64::MAX as u128 + 1;
        buf.extend_from_slice(&fee_too_large.to_le_bytes());
        // rest can be truncated — error should fire on fee
        put_u32(&mut buf, 0u32); // n_inputs = 0
        put_u32(&mut buf, 0u32); // n_outputs = 0
        buf.push(0u8); // is_coinbase = false
        assert_eq!(TxBody::from_bytes(&buf), Err(WireError::FeeTooLarge));
    }

    #[test]
    fn tx_body_rejects_trailing_bytes() {
        let body = TxBody::standard([0u8; 32], 0, vec![], vec![], false);
        let mut bytes = body.to_bytes();
        bytes.push(0xFF);
        assert_eq!(TxBody::from_bytes(&bytes), Err(WireError::TrailingBytes));
    }

    #[test]
    fn transaction_roundtrip() {
        let body = TxBody::standard(
            [0xAAu8; 32],
            7,
            vec![mk_input(3)],
            vec![mk_output(4)],
            false,
        );
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
        let mut is_act = [false; crate::types::MAX_OUTPUTS];
        is_act[0] = true;
        is_act[3] = true;
        let mut is_deact = [false; crate::types::MAX_INPUTS];
        is_deact[1] = true;
        let p = PublicInputs {
            epoch_anchor: [1u8; 32],
            tx_body_hash: TxBodyHash([4u8; 32]),
            shape_id: TxShape::Standard4x8.id(),
            fee: 0xFEED_FACE_CAFE_BEEFu128,
            n_live_inputs: 2,
            n_live_outputs: 4,
            coinbase_credit: 0xDEAD_BEEF_1234_5678,
            log_slots: 24,
            claims_commitment: [0xCCu8; 32],
            is_activation: is_act,
            is_deactivation: is_deact,
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), PUBLIC_INPUTS_WIRE_SIZE);
        let back = PublicInputs::from_bytes(&bytes).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn public_inputs_rejects_invalid_shape_id() {
        let mut p = PublicInputs {
            epoch_anchor: [0u8; 32],
            tx_body_hash: TxBodyHash([0u8; 32]),
            shape_id: TxShape::Standard4x8.id(),
            fee: 0,
            n_live_inputs: 0,
            n_live_outputs: 0,
            coinbase_credit: 0,
            log_slots: 24,
            claims_commitment: [0u8; 32],
            is_activation: [false; crate::types::MAX_OUTPUTS],
            is_deactivation: [false; crate::types::MAX_INPUTS],
        };
        p.shape_id = 0xFF;
        assert_eq!(
            PublicInputs::from_bytes(&p.to_bytes()),
            Err(WireError::InvalidShape)
        );
    }

    #[test]
    fn public_inputs_rejects_live_count_over_max() {
        let good = PublicInputs {
            epoch_anchor: [0u8; 32],
            tx_body_hash: TxBodyHash([0u8; 32]),
            shape_id: TxShape::Standard4x8.id(),
            fee: 0,
            n_live_inputs: 0,
            n_live_outputs: 0,
            coinbase_credit: 0,
            log_slots: 24,
            claims_commitment: [0u8; 32],
            is_activation: [false; crate::types::MAX_OUTPUTS],
            is_deactivation: [false; crate::types::MAX_INPUTS],
        };
        // Layout: epoch_anchor(32) + tx_body_hash(32) + shape_id(1) + fee(16) + n_live_in(1) + n_live_out(1) ...
        let n_in_off = 32 + 32 + 1 + 16; // offset of n_live_inputs
        let n_out_off = n_in_off + 1; // offset of n_live_outputs
        let mut bytes = good.to_bytes();
        bytes[n_in_off] = (crate::types::MAX_INPUTS + 1) as u8;
        assert_eq!(
            PublicInputs::from_bytes(&bytes),
            Err(WireError::CountTooLarge)
        );
        let mut bytes = good.to_bytes();
        bytes[n_out_off] = (crate::types::MAX_OUTPUTS + 1) as u8;
        assert_eq!(
            PublicInputs::from_bytes(&bytes),
            Err(WireError::CountTooLarge)
        );
    }

    #[test]
    fn truncated_decode_errors_cleanly() {
        let body = TxBody::standard([0u8; 32], 0, vec![mk_input(1)], vec![], false);
        let bytes = body.to_bytes();
        for cut in 0..bytes.len() {
            let res = TxBody::from_bytes(&bytes[..cut]);
            assert!(res.is_err(), "expected error at cut={}", cut);
        }
    }

    #[test]
    #[should_panic(expected = "inputs exceed shape max")]
    fn tx_body_encode_panics_when_inputs_exceed_bound() {
        let body = TxBody::standard(
            [0u8; 32],
            0,
            vec![TxInput::dummy(); crate::types::MAX_INPUTS + 1],
            vec![],
            false,
        );
        let mut buf = Vec::new();
        body.encode(&mut buf);
    }

    #[test]
    #[should_panic(expected = "outputs exceed shape max")]
    fn tx_body_encode_panics_when_outputs_exceed_bound() {
        let body = TxBody::standard(
            [0u8; 32],
            0,
            vec![],
            vec![TxOutput::dummy(); crate::types::MAX_OUTPUTS + 1],
            false,
        );
        let mut buf = Vec::new();
        body.encode(&mut buf);
    }
}
