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

/// Wire-format version. Bumped:
/// - `1 → 2` at Stage E.1: `TxOutput.slot_index: u32`.
/// - `2 → 3` at Stage E.5.f₁: `TxBody.is_coinbase: bool`.
pub const TX_BODY_VERSION: u8 = 3;

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
        put_bool(buf, self.is_coinbase);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + 2 * 32
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

        let is_coinbase = take_bool(src)?;

        Ok(Self {
            prev_state_root,
            new_state_root,
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
//              + n_live_inputs (1) + n_live_outputs (1)
//              + coinbase_credit (8) + log_slots (4)
//              + is_activation[MAX_OUTPUTS] (MAX_OUTPUTS bytes, 0/1)
//              + is_deactivation[MAX_INPUTS] (MAX_INPUTS bytes, 0/1)
//              = 142 + MAX_OUTPUTS + MAX_INPUTS bytes
// ---------------------------------------------------------------------------

pub const PUBLIC_INPUTS_WIRE_SIZE: usize =
    3 * 32 + 16 + 1 + 1 + 8 + 4 + crate::types::MAX_OUTPUTS + crate::types::MAX_INPUTS;

impl PublicInputs {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_digest(buf, &self.prev_state_root);
        put_digest(buf, &self.new_state_root);
        put_digest(buf, &self.tx_body_hash.0);
        put_u128(buf, self.fee);
        buf.push(self.n_live_inputs);
        buf.push(self.n_live_outputs);
        put_u64(buf, self.coinbase_credit);
        put_u32(buf, self.log_slots);
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
        out[i..i + 32].copy_from_slice(&self.prev_state_root);
        i += 32;
        out[i..i + 32].copy_from_slice(&self.new_state_root);
        i += 32;
        out[i..i + 32].copy_from_slice(&self.tx_body_hash.0);
        i += 32;
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
        let prev_state_root = take_digest(src)?;
        let new_state_root = take_digest(src)?;
        let tx_body_hash = TxBodyHash(take_digest(src)?);
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
        if log_slots < crate::public::MIN_LOG_SLOTS
            || log_slots > crate::public::MAX_LOG_SLOTS
        {
            return Err(WireError::ShapeMismatch);
        }
        let mut is_activation = [false; crate::types::MAX_OUTPUTS];
        for slot in is_activation.iter_mut() {
            *slot = take_bool(src)?;
        }
        let mut is_deactivation = [false; crate::types::MAX_INPUTS];
        for slot in is_deactivation.iter_mut() {
            *slot = take_bool(src)?;
        }
        Ok(Self {
            prev_state_root,
            new_state_root,
            tx_body_hash,
            fee,
            n_live_inputs,
            n_live_outputs,
            coinbase_credit,
            log_slots,
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
        let body = TxBody {
            prev_state_root: [0x11u8; 32],
            new_state_root: [0x22u8; 32],
            fee: 42u128,
            inputs: vec![mk_input(1), mk_input(2), TxInput::dummy()],
            outputs: vec![mk_output(1), mk_output(2), TxOutput::dummy()],
            is_coinbase: false,
        };
        let bytes = body.to_bytes();
        let back = TxBody::from_bytes(&bytes).unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn tx_body_coinbase_roundtrip() {
        let body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [1u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![mk_output(1)],
            is_coinbase: true,
        };
        let bytes = body.to_bytes();
        let back = TxBody::from_bytes(&bytes).unwrap();
        assert_eq!(back, body);
        assert!(back.is_coinbase);
    }

    #[test]
    fn tx_body_is_coinbase_byte_is_bound() {
        let body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![],
            is_coinbase: false,
        };
        let mut bytes = body.to_bytes();
        // Last byte is is_coinbase; flipping it must be observable.
        let last = bytes.len() - 1;
        bytes[last] = 1;
        let back = TxBody::from_bytes(&bytes).unwrap();
        assert!(back.is_coinbase);
        // Invalid bool byte rejects.
        bytes[last] = 0x42;
        assert_eq!(TxBody::from_bytes(&bytes), Err(WireError::InvalidBool));
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
            is_coinbase: false,
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
            is_coinbase: false,
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
            is_coinbase: false,
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
        let mut is_act = [false; crate::types::MAX_OUTPUTS];
        is_act[0] = true;
        is_act[3] = true;
        let mut is_deact = [false; crate::types::MAX_INPUTS];
        is_deact[1] = true;
        let p = PublicInputs {
            prev_state_root: [1u8; 32],
            new_state_root: [2u8; 32],
            tx_body_hash: TxBodyHash([4u8; 32]),
            fee: 0xFEED_FACE_CAFE_BEEFu128,
            n_live_inputs: 2,
            n_live_outputs: 4,
            coinbase_credit: 0xDEAD_BEEF_1234_5678,
            log_slots: 24,
            is_activation: is_act,
            is_deactivation: is_deact,
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), PUBLIC_INPUTS_WIRE_SIZE);
        let back = PublicInputs::from_bytes(&bytes).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn public_inputs_rejects_live_count_over_max() {
        let good = PublicInputs {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            tx_body_hash: TxBodyHash([0u8; 32]),
            fee: 0,
            n_live_inputs: 0,
            n_live_outputs: 0,
            coinbase_credit: 0,
            log_slots: 24,
            is_activation: [false; crate::types::MAX_OUTPUTS],
            is_deactivation: [false; crate::types::MAX_INPUTS],
        };
        // Trailing layout is `... n_live_in (1) n_live_out (1) credit (8) log_slots (4)
        // is_activation[MAX_OUTPUTS] is_deactivation[MAX_INPUTS]`.
        // Offsets measured from the end (`size - tail_bytes`).
        let tail = crate::types::MAX_OUTPUTS + crate::types::MAX_INPUTS + 4 + 8;
        let n_in_off = PUBLIC_INPUTS_WIRE_SIZE - tail - 1 - 1;
        let n_out_off = PUBLIC_INPUTS_WIRE_SIZE - tail - 1;
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
        let body = TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![mk_input(1)],
            outputs: vec![],
            is_coinbase: false,
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
            is_coinbase: false,
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
            is_coinbase: false,
        };
        let mut buf = Vec::new();
        body.encode(&mut buf);
    }
}
