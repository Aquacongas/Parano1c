// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Block-header hash. CRYPTO.md §8.1.
//!
//! `H_BLOCK(prev_block_hash, state_root, tx_root, timestamp,
//! miner_address, nonce, proof_transcript_hash)` with capacity IV =
//! `BLOCKHDR`. Each field is absorbed as a canonical little-endian
//! sequence of `Block128` words: 32-byte digests as two halves (same
//! rule as every other primitive, §4), scalars (`timestamp`, `nonce`)
//! as a single `Block128` word.
//!
//! The field order is locked. Any future extension appends new fields
//! behind a fresh domain tag, never reorders.

use noid_core::Block128;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_BLOCKHDR};
use noid_poseidon2b::primitives::{Address, Digest};

/// Canonical block header. Mirrors the seven fields of `H_BLOCK`.
///
/// `timestamp` is seconds since Unix epoch; `nonce` is the PoW nonce.
/// Both are absorbed as 128-bit field elements (zero-extended), which
/// matches the binary-tower convention used for every other scalar in
/// the spec (fee, value, salt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub prev_block_hash: Digest,
    pub state_root: Digest,
    pub tx_root: Digest,
    pub timestamp: u64,
    pub miner_address: Address,
    pub nonce: u64,
    pub proof_transcript_hash: Digest,
}

/// Compute `H_BLOCK` per CRYPTO.md §8.1.
pub fn hash_block_header(hdr: &BlockHeader) -> Digest {
    let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_BLOCKHDR));

    absorb_digest(&mut s, &hdr.prev_block_hash);
    absorb_digest(&mut s, &hdr.state_root);
    absorb_digest(&mut s, &hdr.tx_root);
    s.absorb(Block128::from(hdr.timestamp as u128));
    absorb_digest(&mut s, hdr.miner_address.as_bytes());
    s.absorb(Block128::from(hdr.nonce as u128));
    absorb_digest(&mut s, &hdr.proof_transcript_hash);

    s.finalize()
}

#[inline]
fn absorb_digest(s: &mut Poseidon2bSponge, d: &Digest) {
    let hi = Block128::from(u128::from_le_bytes(d[..16].try_into().unwrap()));
    let lo = Block128::from(u128::from_le_bytes(d[16..].try_into().unwrap()));
    s.absorb_pair(hi, lo);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_fixture() -> BlockHeader {
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
    fn determinism() {
        let h = header_fixture();
        assert_eq!(hash_block_header(&h), hash_block_header(&h));
    }

    #[test]
    fn each_field_affects_hash() {
        let base = header_fixture();
        let baseline = hash_block_header(&base);

        let mut h = base;
        h.prev_block_hash = [0xAAu8; 32];
        assert_ne!(hash_block_header(&h), baseline);

        let mut h = base;
        h.state_root = [0xAAu8; 32];
        assert_ne!(hash_block_header(&h), baseline);

        let mut h = base;
        h.tx_root = [0xAAu8; 32];
        assert_ne!(hash_block_header(&h), baseline);

        let mut h = base;
        h.timestamp += 1;
        assert_ne!(hash_block_header(&h), baseline);

        let mut h = base;
        h.miner_address = Address([0xAAu8; 32]);
        assert_ne!(hash_block_header(&h), baseline);

        let mut h = base;
        h.nonce ^= 1;
        assert_ne!(hash_block_header(&h), baseline);

        let mut h = base;
        h.proof_transcript_hash = [0xAAu8; 32];
        assert_ne!(hash_block_header(&h), baseline);
    }

    #[test]
    fn domain_disjoint_from_txbody() {
        // Feeding the same seven-word rate schedule into the TXBODY wrap
        // would produce a different digest — the IV is the only thing
        // that differs between the two constructions with matching
        // input shapes, so this is the minimal cross-domain check.
        use noid_poseidon2b::native::domain::{capacity_iv, TAG_TXBODY};

        let h = header_fixture();
        let block_digest = hash_block_header(&h);

        let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_TXBODY));
        absorb_digest(&mut s, &h.prev_block_hash);
        absorb_digest(&mut s, &h.state_root);
        absorb_digest(&mut s, &h.tx_root);
        s.absorb(Block128::from(h.timestamp as u128));
        absorb_digest(&mut s, h.miner_address.as_bytes());
        s.absorb(Block128::from(h.nonce as u128));
        absorb_digest(&mut s, &h.proof_transcript_hash);
        let txbody_flavor = s.finalize();

        assert_ne!(block_digest, txbody_flavor);
    }
}
