// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Capacity-IV domain separation tags for Poseidon2b constructions.
//!
//! See `CRYPTO.md` §3 and §11. Every sponge-mode construction initializes
//! `state[2]`, `state[3]` from an 8-byte ASCII label: the high capacity
//! word holds `LABEL_u64 << 64`, the low holds `LABEL_u64`. Distinct
//! halves prevent trivial cancellation.

use noid_core::Block128;

/// An 8-byte ASCII domain-separation label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainTag(pub [u8; 8]);

impl DomainTag {
    pub const fn new(label: &[u8; 8]) -> Self {
        let mut i = 0;
        while i < 8 {
            assert!(label[i] < 128, "domain tag must be ASCII");
            i += 1;
        }
        Self(*label)
    }

    #[inline]
    pub const fn as_u64(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }
}

/// Derive the two capacity-IV words `(state[2], state[3])` from a tag.
#[inline]
pub fn capacity_iv(tag: DomainTag) -> [Block128; 2] {
    let label = tag.as_u64() as u128;
    let high = Block128::from(label << 64);
    let low = Block128::from(label);
    [high, low]
}

pub const TAG_LEAF: DomainTag = DomainTag::new(b"LEAF____");
pub const TAG_COMMIT: DomainTag = DomainTag::new(b"COMMIT__");
pub const TAG_AUTHTAG: DomainTag = DomainTag::new(b"AUTHTAG_");
pub const TAG_ADDRESS: DomainTag = DomainTag::new(b"ADDRESS_");
pub const TAG_TXBODY: DomainTag = DomainTag::new(b"TXBODY__");
pub const TAG_BLOCKHDR: DomainTag = DomainTag::new(b"BLOCKHDR");
pub const TAG_FSCHALNG: DomainTag = DomainTag::new(b"FSCHALNG");
pub const TAG_COMPRESS: DomainTag = DomainTag::new(b"COMPRESS");
pub const TAG_DAWTNSS: DomainTag = DomainTag::new(b"DAWTNSS_");
pub const TAG_FRISTATE: DomainTag = DomainTag::new(b"FRISTATE");
/// Segment-level Merkle tree: Poseidon2b binary tree over per-segment
/// FRI roots. The root is the global `state_root` when `num_segments > 1`.
pub const TAG_SEGMENTTREE: DomainTag = DomainTag::new(b"SEGTREE_");
/// Fixed-length 4-field output-leaf sponge: `[slot, value, owner_hi,
/// owner_lo]` absorbed as two rate blocks with no padding flush
/// (total: 2 permutations). Symmetric twin of the AIR's
/// `OutputLeafPermA + OutputLeafPermB` schedule in
/// `noid_air::airs::tx_body_merkle`. Distinct from `TAG_LEAF` so the
/// no-pad 4-field output-leaf construction cannot collide with the
/// pad-flushed variable-length `hash_leaf` under the same IV.
pub const TAG_OUTLEAF: DomainTag = DomainTag::new(b"OUTLEAF_");
/// Claims commitment: Poseidon2b sponge over all claimed slot data
/// (inputs + outputs). Bridges WalletAuthorizationBundle to BlockStateBinding.
pub const TAG_CLAIMS: DomainTag = DomainTag::new(b"CLAIMS__");

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::TowerField;

    #[test]
    fn all_tags_distinct() {
        let tags = [
            TAG_LEAF,
            TAG_COMMIT,
            TAG_AUTHTAG,
            TAG_ADDRESS,
            TAG_TXBODY,
            TAG_BLOCKHDR,
            TAG_FSCHALNG,
            TAG_COMPRESS,
            TAG_DAWTNSS,
            TAG_FRISTATE,
            TAG_SEGMENTTREE,
            TAG_OUTLEAF,
            TAG_CLAIMS,
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j]);
            }
        }
    }

    #[test]
    fn iv_nonzero_and_split() {
        let [hi, lo] = capacity_iv(TAG_LEAF);
        assert_ne!(hi, Block128::ZERO);
        assert_ne!(lo, Block128::ZERO);
        assert_ne!(hi, lo);
    }
}
