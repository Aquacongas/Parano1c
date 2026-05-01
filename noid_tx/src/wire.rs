// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Canonical wire encoding for transaction types.
//!
//! Fixed-width, little-endian. Counts on variable-length vectors
//! (`inputs`, `outputs`, `auth_tags`) are explicit `u32`s, each bounded
//! by its spec-level maximum (§7). Every 32-byte digest is a passthrough
//! byte copy; every 128-bit scalar is 16 LE bytes.
//!
//! The encoding is designed to be consumed byte-for-byte — no
//! length-prefix ambiguity, no hidden padding, no hidden branches.

use noid_core::Block128;
use noid_poseidon2b::primitives::{AuthTag, Commitment, Digest, Nullifier, ScanTag, TxBodyHash};

use crate::public::PublicInputs;
use crate::types::{Transaction, TxBody, TxInput, TxOutput};

/// Encoding / decoding errors surfaced to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Buffer ended before the type was fully parsed.
    Truncated,
    /// A count field exceeds the hard protocol bound (e.g. > MAX_INPUTS).
    CountTooLarge,
    /// Cross-field shape mismatch (e.g. auth_tags count vs. valid inputs).
    ShapeMismatch,
    /// The `valid` byte decoded to a value other than 0 or 1.
    InvalidBool,
    /// Trailing bytes after a top-level decode.
    TrailingBytes,
    /// Wire version byte does not match this build.
    UnknownVersion,
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

#[inline]
fn put_digest(buf: &mut Vec<u8>, d: &Digest) {
    buf.extend_from_slice(d);
}

#[inline]
fn put_u128(buf: &mut Vec<u8>, v: u128) {
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
// ---------------------------------------------------------------------------

pub const TX_INPUT_WIRE_SIZE: usize = 32 + 32 + 1;

impl TxInput {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_digest(buf, &self.commitment.0);
        put_digest(buf, &self.nullifier.0);
        put_bool(buf, self.valid);
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let commitment = Commitment(take_digest(src)?);
        let nullifier = Nullifier(take_digest(src)?);
        let valid = take_bool(src)?;
        Ok(Self {
            commitment,
            nullifier,
            valid,
        })
    }
}

// ---------------------------------------------------------------------------
// TxOutput
// ---------------------------------------------------------------------------

pub const TX_OUTPUT_WIRE_SIZE: usize = 32 + 16 + 32 + 1;

impl TxOutput {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_digest(buf, &self.commitment.0);
        put_u128(buf, self.salt.to_u128());
        put_digest(buf, &self.scan_tag.0);
        put_bool(buf, self.valid);
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let commitment = Commitment(take_digest(src)?);
        let salt = Block128::from(take_u128(src)?);
        let scan_tag = ScanTag(take_digest(src)?);
        let valid = take_bool(src)?;
        Ok(Self {
            commitment,
            salt,
            scan_tag,
            valid,
        })
    }
}

// ---------------------------------------------------------------------------
// TxBody
// ---------------------------------------------------------------------------

/// Wire layout (version=1):
/// ```text
/// u8   version = 1
/// [32] prev_state_root
/// [32] new_state_root
/// [32] nullifier_root
/// u128 fee
/// u32  n_inputs  (<= MAX_INPUTS)
/// TxInput[n_inputs]
/// u32  n_outputs (<= MAX_OUTPUTS)
/// TxOutput[n_outputs]
/// ```
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
        put_digest(buf, &self.nullifier_root);
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
            1 + 3 * 32
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
        let nullifier_root = take_digest(src)?;
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
            nullifier_root,
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
// Transaction
// ---------------------------------------------------------------------------

impl Transaction {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        assert!(
            self.auth_tags.len() <= crate::types::MAX_INPUTS,
            "auth_tags exceed MAX_INPUTS"
        );
        assert!(
            self.has_canonical_auth_tag_count(),
            "auth_tags count must equal number of valid inputs"
        );

        self.body.encode(buf);
        put_digest(buf, &self.tx_body_hash.0);
        put_u32(buf, self.auth_tags.len() as u32);
        for t in &self.auth_tags {
            put_digest(buf, &t.0);
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let body = TxBody::decode(src)?;
        let tx_body_hash = TxBodyHash(take_digest(src)?);
        let n = take_u32(src)? as usize;
        if n > crate::types::MAX_INPUTS {
            return Err(WireError::CountTooLarge);
        }
        let mut auth_tags = Vec::with_capacity(n);
        for _ in 0..n {
            auth_tags.push(AuthTag(take_digest(src)?));
        }
        let tx = Self {
            body,
            tx_body_hash,
            auth_tags,
        };
        if !tx.has_canonical_auth_tag_count() {
            return Err(WireError::ShapeMismatch);
        }
        Ok(tx)
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
// PublicInputs
// ---------------------------------------------------------------------------

pub const PUBLIC_INPUTS_WIRE_SIZE: usize = 4 * 32 + 16;

impl PublicInputs {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_digest(buf, &self.prev_state_root);
        put_digest(buf, &self.new_state_root);
        put_digest(buf, &self.nullifier_root);
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
        out[i..i + 32].copy_from_slice(&self.nullifier_root);
        i += 32;
        out[i..i + 32].copy_from_slice(&self.tx_body_hash.0);
        i += 32;
        out[i..i + 16].copy_from_slice(&self.fee.to_le_bytes());
        out
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let prev_state_root = take_digest(src)?;
        let new_state_root = take_digest(src)?;
        let nullifier_root = take_digest(src)?;
        let tx_body_hash = TxBodyHash(take_digest(src)?);
        let fee = take_u128(src)?;
        Ok(Self {
            prev_state_root,
            new_state_root,
            nullifier_root,
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
    use noid_core::TowerField;
    use noid_poseidon2b::primitives::{
        derive_view_key, hash_commitment, hash_scan_tag, Address, MasterSecret,
    };

    fn mk_output(seed: u8, salt: u128) -> TxOutput {
        let addr = Address([seed; 32]);
        let c = hash_commitment(
            seed as u128,
            &addr,
            Block128::from(seed as u128),
            Block128::ZERO,
        );
        let vk = derive_view_key(&MasterSecret([seed; 32]));
        let salt = Block128::from(salt);
        TxOutput {
            commitment: c,
            salt,
            scan_tag: hash_scan_tag(&vk, salt),
            valid: true,
        }
    }

    fn mk_input(seed: u8) -> TxInput {
        let addr = Address([seed; 32]);
        let c = hash_commitment(
            seed as u128,
            &addr,
            Block128::from(seed as u128),
            Block128::ZERO,
        );
        TxInput {
            commitment: c,
            nullifier: Nullifier([seed; 32]),
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
        let o = mk_output(7, 0xDEAD_BEEFu128);
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
            nullifier_root: [0x33u8; 32],
            fee: 42u128,
            inputs: vec![mk_input(1), mk_input(2), TxInput::dummy()],
            outputs: vec![mk_output(1, 10), mk_output(2, 20), TxOutput::dummy()],
        };
        let bytes = body.to_bytes();
        let back = TxBody::from_bytes(&bytes).unwrap();
        assert_eq!(back.prev_state_root, body.prev_state_root);
        assert_eq!(back.new_state_root, body.new_state_root);
        assert_eq!(back.nullifier_root, body.nullifier_root);
        assert_eq!(back.fee, body.fee);
        assert_eq!(back.inputs, body.inputs);
        assert_eq!(back.outputs, body.outputs);
    }

    #[test]
    fn tx_body_rejects_too_many_inputs() {
        let mut buf = Vec::new();
        buf.push(TX_BODY_VERSION);
        buf.extend_from_slice(&[0u8; 32]);
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
            nullifier_root: [0u8; 32],
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
            nullifier_root: [0u8; 32],
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
            nullifier_root: [0xCCu8; 32],
            fee: 7,
            inputs: vec![mk_input(3)],
            outputs: vec![mk_output(4, 99)],
        };
        let tx = Transaction {
            tx_body_hash: TxBodyHash([0x99u8; 32]),
            auth_tags: vec![AuthTag([0x12u8; 32])],
            body,
        };
        let bytes = tx.to_bytes();
        let back = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(back.tx_body_hash, tx.tx_body_hash);
        assert_eq!(back.auth_tags, tx.auth_tags);
    }

    #[test]
    fn public_inputs_roundtrip() {
        let p = PublicInputs {
            prev_state_root: [1u8; 32],
            new_state_root: [2u8; 32],
            nullifier_root: [3u8; 32],
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
            nullifier_root: [0u8; 32],
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
            nullifier_root: [0u8; 32],
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
            nullifier_root: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![TxOutput::dummy(); crate::types::MAX_OUTPUTS + 1],
        };
        let mut buf = Vec::new();
        body.encode(&mut buf);
    }

    #[test]
    #[should_panic(expected = "auth_tags exceed MAX_INPUTS")]
    fn transaction_encode_panics_when_auth_tags_exceed_bound() {
        let tx = Transaction {
            body: TxBody {
                prev_state_root: [0u8; 32],
                new_state_root: [0u8; 32],
                nullifier_root: [0u8; 32],
                fee: 0,
                inputs: vec![],
                outputs: vec![],
            },
            tx_body_hash: TxBodyHash([0u8; 32]),
            auth_tags: vec![AuthTag([0u8; 32]); crate::types::MAX_INPUTS + 1],
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf);
    }

    #[test]
    #[should_panic(expected = "auth_tags count must equal number of valid inputs")]
    fn transaction_encode_panics_when_auth_tags_count_mismatches_valid_inputs() {
        let tx = Transaction {
            body: TxBody {
                prev_state_root: [0u8; 32],
                new_state_root: [0u8; 32],
                nullifier_root: [0u8; 32],
                fee: 0,
                inputs: vec![mk_input(1)],
                outputs: vec![],
            },
            tx_body_hash: TxBodyHash([0u8; 32]),
            auth_tags: vec![],
        };
        let mut buf = Vec::new();
        tx.encode(&mut buf);
    }

    #[test]
    fn transaction_decode_rejects_auth_tag_shape_mismatch() {
        let body = TxBody {
            prev_state_root: [0xAAu8; 32],
            new_state_root: [0xBBu8; 32],
            nullifier_root: [0xCCu8; 32],
            fee: 7,
            inputs: vec![mk_input(3)],
            outputs: vec![mk_output(4, 99)],
        };

        let mut bytes = body.to_bytes();
        bytes.extend_from_slice(&[0x99u8; 32]); // tx_body_hash
        put_u32(&mut bytes, 0); // zero auth tags, but one valid input

        assert_eq!(Transaction::from_bytes(&bytes), Err(WireError::ShapeMismatch));
    }
}
