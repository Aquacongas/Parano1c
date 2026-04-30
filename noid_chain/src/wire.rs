// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Canonical wire encoding for chain-level types.
//!
//! Same rules as `noid_tx::wire`: fixed-width little-endian, no hidden
//! padding, errors on truncation / trailing bytes / unknown version.

use noid_poseidon2b::primitives::Address;
use noid_tx::wire::WireError;

use crate::block_header::BlockHeader;

#[inline]
fn put_digest(buf: &mut Vec<u8>, d: &[u8; 32]) {
    buf.extend_from_slice(d);
}

#[inline]
fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
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
fn take_digest(src: &mut &[u8]) -> Result<[u8; 32], WireError> {
    let bytes = take(src, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[inline]
fn take_u64(src: &mut &[u8]) -> Result<u64, WireError> {
    let bytes = take(src, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

/// Wire size of a [`BlockHeader`]: 5 digests + timestamp + nonce.
pub const BLOCK_HEADER_WIRE_SIZE: usize = 5 * 32 + 8 + 8;

impl BlockHeader {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        put_digest(buf, &self.prev_block_hash);
        put_digest(buf, &self.state_root);
        put_digest(buf, &self.tx_root);
        put_u64(buf, self.timestamp);
        put_digest(buf, self.miner_address.as_bytes());
        put_u64(buf, self.nonce);
        put_digest(buf, &self.proof_transcript_hash);
    }

    pub fn to_bytes(&self) -> [u8; BLOCK_HEADER_WIRE_SIZE] {
        let mut buf = Vec::with_capacity(BLOCK_HEADER_WIRE_SIZE);
        self.encode(&mut buf);
        let mut out = [0u8; BLOCK_HEADER_WIRE_SIZE];
        out.copy_from_slice(&buf);
        out
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let prev_block_hash = take_digest(src)?;
        let state_root = take_digest(src)?;
        let tx_root = take_digest(src)?;
        let timestamp = take_u64(src)?;
        let miner_address = Address(take_digest(src)?);
        let nonce = take_u64(src)?;
        let proof_transcript_hash = take_digest(src)?;
        Ok(Self {
            prev_block_hash,
            state_root,
            tx_root,
            timestamp,
            miner_address,
            nonce,
            proof_transcript_hash,
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

    fn hdr() -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0x11u8; 32],
            state_root: [0x22u8; 32],
            tx_root: [0x33u8; 32],
            timestamp: 1_700_000_000,
            miner_address: Address([0x44u8; 32]),
            nonce: 0xDEAD_BEEFu64,
            proof_transcript_hash: [0x55u8; 32],
        }
    }

    #[test]
    fn block_header_roundtrip() {
        let h = hdr();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), BLOCK_HEADER_WIRE_SIZE);
        let back = BlockHeader::from_bytes(&bytes).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn header_truncation_errors_cleanly() {
        let h = hdr();
        let bytes = h.to_bytes();
        for cut in 0..bytes.len() {
            assert!(BlockHeader::from_bytes(&bytes[..cut]).is_err());
        }
    }

    #[test]
    fn header_rejects_trailing_bytes() {
        let h = hdr();
        let mut v = h.to_bytes().to_vec();
        v.push(0);
        assert_eq!(BlockHeader::from_bytes(&v), Err(WireError::TrailingBytes));
    }
}
