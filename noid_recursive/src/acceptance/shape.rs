// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical block shape classes for the sole Tx8x2 transaction form.
//!
//! Performance measurements live in `bench_prover` and are never protocol
//! constants. This module contains only current proof-shape identity.

use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

/// One block shape class: a canonical user-transaction-count tier.
///
/// Every proof-facing per-block structure is padded to this tier. The fixed
/// one-owner authorization statement has one geometry in every class; the
/// tier selects transaction, spend, universal-tree, and touched-slot capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShapeClass {
    pub tier: usize,
}

impl ShapeClass {
    /// The class holding `user_txs`, or `None` above the consensus maximum.
    pub fn for_count(user_txs: usize) -> Option<Self> {
        Some(Self {
            tier: noid_chain::consensus::params::user_tx_class_tier(user_txs)?,
        })
    }

    /// Class live-input capacity used by spend-facing structures.
    pub fn spend_capacity(self) -> usize {
        noid_chain::consensus::params::block_class_spend_capacity(self.tier)
    }

    /// Authorization slots are power-of-two padded; B255 therefore carries
    /// one canonical dead authorization slot.
    pub fn authorization_capacity(self) -> usize {
        self.tier.next_power_of_two()
    }

    /// Exact-state touched capacity: spends, at most two creations per user
    /// transaction, and the mandatory coinbase creation.
    pub fn touched_capacity(self) -> usize {
        self.spend_capacity() + self.tier * noid_tx::TX_OUTPUTS + 1
    }

    /// Domain-separated identity of the class key and current structural
    /// parameters. This is not an R1CS statement digest.
    pub fn shape_digest(self) -> [u8; 32] {
        let fields = [
            self.tier,
            self.spend_capacity(),
            self.authorization_capacity(),
            self.touched_capacity(),
            noid_tx::TX_INPUTS,
            noid_tx::TX_OUTPUTS,
            noid_tx::body_hash::BODY_HASH_LEAVES,
            noid_gkr::N_SPINE_SLOTS,
            noid_chain::tx_tree::TX_TREE_DEPTH,
        ];
        let mut encoded = Vec::with_capacity(fields.len() * 8);
        for field in fields {
            encoded.extend_from_slice(&(field as u64).to_le_bytes());
        }
        poseidon2b_hash_byte_slices(SHAPE_CLASS_DOMAIN, &[&encoded])
    }
}

/// Every current class in canonical ladder order: B8, B32, B64, B255.
pub fn enumerate_shape_classes() -> impl Iterator<Item = ShapeClass> {
    noid_chain::consensus::params::USER_TX_CLASS_TIERS
        .into_iter()
        .map(|tier| ShapeClass { tier })
}

const SHAPE_CLASS_DOMAIN: &[u8] = b"NOID-TX8X2-SHAPE-CLASS-V2";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_table_is_finite_and_injective() {
        let classes: Vec<_> = enumerate_shape_classes().collect();
        assert_eq!(
            classes.iter().map(|class| class.tier).collect::<Vec<_>>(),
            [8, 32, 64, 255]
        );
        let digests: std::collections::HashSet<_> = classes
            .iter()
            .copied()
            .map(ShapeClass::shape_digest)
            .collect();
        assert_eq!(digests.len(), classes.len());

        assert_eq!(ShapeClass::for_count(9).unwrap().tier, 32);
        assert!(ShapeClass::for_count(256).is_none());
        assert_eq!(
            ShapeClass::for_count(255).unwrap().spend_capacity(),
            noid_chain::consensus::params::BLOCK_MAX_LIVE_INPUTS
        );
        assert_eq!(
            ShapeClass::for_count(255).unwrap().authorization_capacity(),
            256
        );
        assert_eq!(
            ShapeClass::for_count(255).unwrap().touched_capacity(),
            1_531
        );
        assert_eq!(noid_tx::body_hash::BODY_HASH_LEAVES, 16);
        assert_eq!(noid_gkr::N_SPINE_SLOTS, 31);
    }
}
