// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Block-header hash. SPECIFICATION.md §0.4 / §8.
//!
//! `H_BLOCK` absorbs all consensus-significant header fields in the order
//! declared below, using capacity IV = `BLOCKHDR`. Each 32-byte digest is
//! absorbed as two `Block128` halves (hi then lo, little-endian). Scalar
//! integers are absorbed as a single `Block128` word (zero-extended).
//!
//! **Field order is locked. Future fields MUST be appended at the end**,
//! never reordered. Consensus nodes reject any header whose byte count
//! does not equal `BLOCK_HEADER_WIRE_SIZE`.

use noid_core::Block128;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_BLOCKHDR};
use noid_poseidon2b::primitives::{Address, Digest};

/// Canonical block header. All fields are consensus-significant.
///
/// Byte layout (see `BLOCK_HEADER_WIRE_SIZE` in `wire.rs`):
///
/// ```text
///   prev_block_hash       [32B]  hash of previous header
///   state_root            [32B]  Poseidon2b Merkle over segment FRI roots
///   tx_root               [32B]  COMPRESS Merkle of tx_body_hashes
///   timestamp             [8B]   seconds since Unix epoch (LE u64)
///   height                [8B]   block height (LE u64)
///   miner_address         [32B]  coinbase recipient address
///   nonce                 [16B]  128-bit Blake3 PoW nonce (LE u128)
///   difficulty_target     [32B]  256-bit ASERT target
///   proof_transcript_hash [32B]  Fiat-Shamir transcript digest of BlockProof
///   witness_root          [32B]  Binius-packed DA payload root
///   log_slots             [4B]   current slot-space depth (LE u32)
///   active_slot_count     [8B]   live UTXO count after this block (LE u64)
///   alloc_counter         [8B]   monotonic PRNG seed after this block (LE u64)
/// ```
///
/// Total: 276 bytes (see `BLOCK_HEADER_WIRE_SIZE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub prev_block_hash: Digest,
    /// Global state root — Poseidon2b Merkle root over per-segment FRI roots
    /// (SPECIFICATION.md §19). For a single-segment state (`log_slots ≤ 16`)
    /// this degenerates to the single segment's FRI combined root.
    pub state_root: Digest,
    /// COMPRESS-domain Merkle root of all `tx_body_hash`es in block order.
    pub tx_root: Digest,
    pub timestamp: u64,
    pub height: u64,
    pub miner_address: Address,
    /// 128-bit PoW nonce. Provides effectively unlimited search space.
    pub nonce: u128,
    /// 256-bit ASERT difficulty target (LE). Block valid iff
    /// `Blake3(header_bytes) < difficulty_target`.
    pub difficulty_target: [u8; 32],
    /// Poseidon2b digest of the `BlockProof` Fiat-Shamir transcript.
    /// Non-zero field required by `apply_block`.
    pub proof_transcript_hash: Digest,
    /// Binius-packed DA witness root (`noid_chain::da::packed_witness_root`).
    /// Binds the 128×/16× packed bytes into consensus.
    pub witness_root: Digest,
    /// Slot-space depth: `log₂(num_slots)`. Lives in [24, 32] on mainnet;
    /// may be smaller in test mode. Replicated in every Fiat-Shamir
    /// transcript (SPECIFICATION.md §15.3.9).
    pub log_slots: u32,
    /// Number of live (non-empty) slots after all transactions in this block
    /// are applied. Drives the §15.3.6 expansion trigger. MUST equal
    /// `ChainState::active_slot_count` after `apply_block`.
    pub active_slot_count: u64,
    /// Monotonic PRNG seed: incremented on every successful mint.
    /// MUST equal `ChainState::alloc_counter` after `apply_block`.
    pub alloc_counter: u64,
}

/// Compute `H_BLOCK` — the Poseidon2b hash of the canonical header.
///
/// Used as `epoch_anchor` in transactions (`H_BLOCK(header[height - 6])`)
/// and for chain linking (`prev_block_hash`).
pub fn hash_block_header(hdr: &BlockHeader) -> Digest {
    let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_BLOCKHDR));

    absorb_digest(&mut s, &hdr.prev_block_hash);
    absorb_digest(&mut s, &hdr.state_root);
    absorb_digest(&mut s, &hdr.tx_root);
    s.absorb(Block128::from(hdr.timestamp as u128));
    s.absorb(Block128::from(hdr.height as u128));
    absorb_digest(&mut s, hdr.miner_address.as_bytes());
    s.absorb(Block128::from(hdr.nonce));
    absorb_digest(&mut s, &hdr.difficulty_target);
    absorb_digest(&mut s, &hdr.proof_transcript_hash);
    absorb_digest(&mut s, &hdr.witness_root);
    s.absorb(Block128::from(hdr.log_slots as u128));
    s.absorb(Block128::from(hdr.active_slot_count as u128));
    s.absorb(Block128::from(hdr.alloc_counter as u128));

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
            height: 100,
            miner_address: Address([0x44u8; 32]),
            nonce: 0xDEAD_BEEF_CAFE_BABEu128,
            difficulty_target: [0x77u8; 32],
            proof_transcript_hash: [0x55u8; 32],
            witness_root: [0x66u8; 32],
            log_slots: 24,
            active_slot_count: 12_345,
            alloc_counter: 99_999,
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

        macro_rules! check {
            ($field:ident, $val:expr) => {{
                let mut h = base;
                h.$field = $val;
                assert_ne!(
                    hash_block_header(&h),
                    baseline,
                    "field {} did not affect hash",
                    stringify!($field)
                );
            }};
        }

        check!(prev_block_hash, [0xAAu8; 32]);
        check!(state_root, [0xAAu8; 32]);
        check!(tx_root, [0xAAu8; 32]);
        check!(timestamp, base.timestamp + 1);
        check!(height, base.height + 1);
        check!(miner_address, Address([0xAAu8; 32]));
        check!(nonce, base.nonce ^ 1);
        check!(difficulty_target, [0xAAu8; 32]);
        check!(proof_transcript_hash, [0xAAu8; 32]);
        check!(witness_root, [0xAAu8; 32]);
        check!(log_slots, base.log_slots + 1);
        check!(active_slot_count, base.active_slot_count + 1);
        check!(alloc_counter, base.alloc_counter + 1);
    }

    #[test]
    fn domain_disjoint_from_txbody() {
        use noid_poseidon2b::native::domain::{capacity_iv, TAG_TXBODY};

        let h = header_fixture();
        let block_digest = hash_block_header(&h);

        // Build the same absorb schedule under a different IV.
        let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_TXBODY));
        absorb_digest(&mut s, &h.prev_block_hash);
        absorb_digest(&mut s, &h.state_root);
        absorb_digest(&mut s, &h.tx_root);
        s.absorb(Block128::from(h.timestamp as u128));
        s.absorb(Block128::from(h.height as u128));
        absorb_digest(&mut s, h.miner_address.as_bytes());
        s.absorb(Block128::from(h.nonce));
        absorb_digest(&mut s, &h.difficulty_target);
        absorb_digest(&mut s, &h.proof_transcript_hash);
        absorb_digest(&mut s, &h.witness_root);
        s.absorb(Block128::from(h.log_slots as u128));
        s.absorb(Block128::from(h.active_slot_count as u128));
        s.absorb(Block128::from(h.alloc_counter as u128));
        let txbody_flavor = s.finalize();

        assert_ne!(block_digest, txbody_flavor);
    }
}
