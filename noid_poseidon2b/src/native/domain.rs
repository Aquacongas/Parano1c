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

/// [`capacity_iv`] mapped into the **flat (GCM) basis** — IV words for
/// constructions whose state lives in the flat basis end to end
/// (`compress_flat_feed_forward_with_tag`, `Poseidon2bFlatSponge`).
#[inline]
pub fn capacity_iv_flat(tag: DomainTag) -> [u128; 2] {
    let [high, low] = capacity_iv(tag);
    [
        noid_core::hardware::tower_to_flat_u128(high.0),
        noid_core::hardware::tower_to_flat_u128(low.0),
    ]
}

pub const TAG_LEAF: DomainTag = DomainTag::new(b"LEAF____");
pub const TAG_COMMIT: DomainTag = DomainTag::new(b"COMMIT__");
pub const TAG_ADDRFIX: DomainTag = DomainTag::new(b"ADDRFIX_");
pub const TAG_TXBODY: DomainTag = DomainTag::new(b"TXBODY__");
pub const TAG_BLOCKHDR: DomainTag = DomainTag::new(b"BLOCKHDR");
/// Proof-of-work header digest. Distinct from `BLOCKHDR`: the same semantic
/// header has separate chain-link and mining-difficulty hash domains.
pub const TAG_POWHDR: DomainTag = DomainTag::new(b"POWHDR__");
/// Byte-oriented Fiat-Shamir challenger (`FsChallenger`: op headers +
/// length-prefixed byte absorbs).
pub const TAG_FSCHALNG: DomainTag = DomainTag::new(b"FSCHALNG");
/// Lane-oriented Fiat-Shamir challenger for the proof-core transcripts
/// (`FsLaneChallenger` and its in-trace twin). Distinct from the other
/// Fiat-Shamir families so no transcript state can be replayed across
/// challenger constructions that absorb different framings.
pub const TAG_LANECHAL: DomainTag = DomainTag::new(b"LANECHAL");
/// Killshot Fiat-Shamir channel (`Poseidon2bChannel`, the bare rate-2
/// duplex every GKR verifier runs on) and its replays.
pub const TAG_KSCHANNL: DomainTag = DomainTag::new(b"KSCHANNL");
/// Wallet-capsule FRI transcript (`noid_fri::Channel`) and its replays.
pub const TAG_FRICHANL: DomainTag = DomainTag::new(b"FRICHANL");
pub const TAG_COMPRESS: DomainTag = DomainTag::new(b"COMPRESS");
pub const TAG_DAWTNSS: DomainTag = DomainTag::new(b"DAWTNSS_");
pub const TAG_FRISTATE: DomainTag = DomainTag::new(b"FRISTATE");
/// Segment-level Merkle tree: Poseidon2b binary tree over per-segment
/// FRI roots. The root is the global `state_root` when `num_segments > 1`.
pub const TAG_SEGMENTTREE: DomainTag = DomainTag::new(b"SEGTREE_");
/// Fixed-length 4-field output-leaf sponge: `[slot, value, owner_hi,
/// owner_lo]` absorbed as two rate blocks with no padding flush
/// (total: 2 permutations). Symmetric twin of the canonical tx-body
/// GKR `OutputLeafPermA + OutputLeafPermB` schedule. Distinct from `TAG_LEAF` so the
/// no-pad 4-field output-leaf construction cannot collide with the
/// pad-flushed variable-length `hash_leaf` under the same IV.
pub const TAG_OUTLEAF: DomainTag = DomainTag::new(b"OUTLEAF_");
/// Claims commitment: Poseidon2b sponge over all claimed slot data
/// (inputs + outputs). Bridges WalletAuthorizationBundle to exact state proof.
pub const TAG_CLAIMS: DomainTag = DomainTag::new(b"CLAIMS__");
/// Exact UTXO state slot leaf: `PARANOID/EXACT-STATE-SLOT/256/v1`.
pub const TAG_EXSTSLT: DomainTag = DomainTag::new(b"EXSTSLT_");
/// Exact UTXO state binary Merkle node: `PARANOID/EXACT-STATE-NODE/256/v1`.
pub const TAG_EXSTNOD: DomainTag = DomainTag::new(b"EXSTNOD_");
/// Composite exact state root: `PARANOID/EXACT-STATE-ROOT/256/v1`.
pub const TAG_EXSTROT: DomainTag = DomainTag::new(b"EXSTROT_");
/// ReuseGuard canonical bucket: `PARANOID/REUSE-GUARD-BUCKET/256/v1`.
pub const TAG_RGDBUCK: DomainTag = DomainTag::new(b"RGDBUCK_");
/// ReuseGuard spent-slot list digest (the inner hash nested inside a
/// bucket leaf): `PARANOID/REUSE-GUARD-SLOTS/256/v1`.
pub const TAG_RGDSLOT: DomainTag = DomainTag::new(b"RGDSLOT_");
/// ReuseGuard fixed-depth Merkle node: `PARANOID/REUSE-GUARD-NODE/256/v1`.
pub const TAG_RGDNODE: DomainTag = DomainTag::new(b"RGDNODE_");
/// Accepted-block claim field transcript for recursive chain accumulation.
pub const TAG_ACCBLK: DomainTag = DomainTag::new(b"ACCBLK__");
/// Header projection item for public history anchoring.
pub const TAG_HDRPROJ: DomainTag = DomainTag::new(b"HDRPROJ_");
/// Rolling header-chain anchor over canonical header projections.
pub const TAG_HDRANCH: DomainTag = DomainTag::new(b"HDRANCH_");
/// Accepted history/state transition digest for O(1) state sync.
pub const TAG_HISTTRN: DomainTag = DomainTag::new(b"HISTTRN_");
/// Accepted history/state claim digest for O(1) state sync.
pub const TAG_HISTCLM: DomainTag = DomainTag::new(b"HISTCLM_");
/// Constant public history proof envelope digest for O(1) state sync.
pub const TAG_HISTPRF: DomainTag = DomainTag::new(b"HISTPRF_");
/// Variable-length byte hashing with an explicit absorbed domain string.
pub const TAG_BYTEHASH: DomainTag = DomainTag::new(b"BYTEHASH");

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::TowerField;

    #[test]
    fn all_tags_distinct() {
        let tags = [
            TAG_LEAF,
            TAG_COMMIT,
            TAG_ADDRFIX,
            TAG_TXBODY,
            TAG_BLOCKHDR,
            TAG_POWHDR,
            TAG_FSCHALNG,
            TAG_LANECHAL,
            TAG_KSCHANNL,
            TAG_FRICHANL,
            TAG_COMPRESS,
            TAG_DAWTNSS,
            TAG_FRISTATE,
            TAG_SEGMENTTREE,
            TAG_OUTLEAF,
            TAG_CLAIMS,
            TAG_EXSTSLT,
            TAG_EXSTNOD,
            TAG_EXSTROT,
            TAG_RGDBUCK,
            TAG_RGDSLOT,
            TAG_RGDNODE,
            TAG_ACCBLK,
            TAG_HDRPROJ,
            TAG_HDRANCH,
            TAG_HISTTRN,
            TAG_HISTCLM,
            TAG_HISTPRF,
            TAG_BYTEHASH,
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
