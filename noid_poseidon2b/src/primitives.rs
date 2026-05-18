// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Typed cryptographic primitives for the transparent UTXO layer.
//!
//! Paranoid is a transparent, Bitcoin-style chain: every UTXO discloses
//! value and owner address on-chain. Authorization is still signatureless
//! — a spend is authorized by a Poseidon2b-based `AuthTag` that binds an
//! `Address`-preimage `spend_secret` to the `TxBodyHash`. All privacy
//! primitives (stealth addresses, view keys, scan tags, commitment
//! blinding, nullifiers) have been removed.
//!
//! Every primitive is a thin wrapper over a Poseidon2b sponge seeded
//! with a capacity IV derived from a domain tag (CRYPTO.md §3). Newtype
//! wrappers prevent cross-domain digest mix-ups at the type level.

use noid_core::Block128;

use crate::batch::compress_batch_interleaved_into;
use crate::native::compression::Poseidon2bSponge;
use crate::native::domain::{
    capacity_iv, DomainTag, TAG_ADDRESS, TAG_AUTHTAG, TAG_COMMIT, TAG_LEAF, TAG_OUTLEAF, TAG_TXBODY,
};
use crate::native::permutation::Poseidon2bPermutation;
use noid_core::CanonicalSerialize;

/// Generic 32-byte Poseidon2b digest.
pub type Digest = [u8; 32];

macro_rules! newtype_digest {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            #[inline]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            #[inline]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
            /// Interpret the 32-byte digest as two little-endian
            /// `Block128` words.
            #[inline]
            pub fn as_fields(&self) -> [Block128; 2] {
                let mut a = [0u8; 16];
                let mut b = [0u8; 16];
                a.copy_from_slice(&self.0[..16]);
                b.copy_from_slice(&self.0[16..]);
                [
                    Block128::from(u128::from_le_bytes(a)),
                    Block128::from(u128::from_le_bytes(b)),
                ]
            }
        }
    };
}

newtype_digest!(
    /// A 256-bit transparent wallet address. Derived from a 256-bit
    /// `spend_secret` via `H_ADDR = Poseidon2b(ADDRESS_, secret)`.
    Address
);
newtype_digest!(
    /// A coin / UTXO leaf digest binding `(value, owner)`. The leaf is
    /// also the payload stored in the on-chain state tree.
    Commitment
);
newtype_digest!(
    /// Per-input authorization tag binding `spend_secret` to the
    /// `TxBodyHash`.
    AuthTag
);
newtype_digest!(
    /// Canonical transaction-body hash.
    TxBodyHash
);
newtype_digest!(
    /// The 256-bit wallet spend secret. Preimage of `Address`. Stored
    /// encrypted at rest.
    SpendSecret
);

#[inline]
fn sponge(tag: DomainTag) -> Poseidon2bSponge {
    Poseidon2bSponge::with_iv(capacity_iv(tag))
}

#[inline]
fn absorb_fields(s: &mut Poseidon2bSponge, fields: &[Block128]) {
    let mut iter = fields.chunks_exact(2);
    for pair in iter.by_ref() {
        s.absorb_pair(pair[0], pair[1]);
    }
    for rem in iter.remainder() {
        s.absorb(*rem);
    }
}

/// Hash a list of field elements as a Merkle-tree leaf payload.
/// Sponge-mode, capacity IV = `LEAF____`.
pub fn hash_leaf(fields: &[Block128]) -> Digest {
    let mut s = sponge(TAG_LEAF);
    absorb_fields(&mut s, fields);
    s.finalize()
}

/// Transparent UTXO leaf. Binds `(value, owner)` with IV `COMMIT__`.
/// Three field inputs: `value` (little-endian u128) and the two 128-bit
/// halves of the 256-bit owner address.
pub fn hash_utxo_leaf(value: u128, owner: &Address) -> Commitment {
    let [owner_hi, owner_lo] = owner.as_fields();
    let mut s = sponge(TAG_COMMIT);
    s.absorb(Block128::from(value));
    s.absorb(owner_hi);
    s.absorb(owner_lo);
    Commitment(s.finalize())
}

/// Derive a transparent address from a 256-bit spend secret.
/// `H_ADDR = Poseidon2b(ADDRESS_, secret_hi, secret_lo)`.
pub fn derive_address(secret: &SpendSecret) -> Address {
    let mut s = sponge(TAG_ADDRESS);
    let [a, b] = secret.as_fields();
    s.absorb_pair(a, b);
    Address(s.finalize())
}

/// Per-input authorization tag binding the spend secret to the
/// transaction body hash. The STARK proves a spender's knowledge of
/// `spend_secret` and of a matching `auth_tag`.
pub fn hash_auth_tag(spend_secret: &SpendSecret, tx_body_hash: &TxBodyHash) -> AuthTag {
    let mut s = sponge(TAG_AUTHTAG);
    let [a, b] = spend_secret.as_fields();
    let [c, d] = tx_body_hash.as_fields();
    s.absorb_pair(a, b);
    s.absorb_pair(c, d);
    AuthTag(s.finalize())
}

/// Shape of the tx-body Merkle tree, locked to keep the AIR
/// `§TxBodyMerkle` sub-circuit at a fixed depth. Changing these breaks
/// every downstream component; they are intentionally constants.
pub const TXBODY_INPUTS: usize = 4;
pub const TXBODY_OUTPUTS: usize = 8;
pub const TXBODY_LEAVES: usize = 16;
pub const TXBODY_DEPTH: usize = 4;

/// Per-input leaf of the tx-body Merkle tree. Binds the slot index to
/// the UTXO being spent. Sponge-mode 4-field absorb under IV `LEAF____`:
/// `hash_leaf([slot_index, value, owner_hi, owner_lo])`.
pub fn hash_input_leaf(slot_index: u32, value: u64, owner: &Address) -> Digest {
    let [owner_hi, owner_lo] = owner.as_fields();
    hash_leaf(&[
        Block128::from(slot_index as u128),
        Block128::from(value as u128),
        owner_hi,
        owner_lo,
    ])
}

/// Per-output leaf of the tx-body Merkle tree.
///
/// Fixed-length 4-field sponge under IV `OUTLEAF_`:
/// `[slot_index, value, owner_hi, owner_lo]` absorbed as two rate
/// blocks and squeezed **without a padding flush** (2 permutations
/// total). This matches the AIR's two-instance output-leaf schedule
/// (`OutputLeafPermA + OutputLeafPermB`) in
/// `noid_air::airs::tx_body_merkle` byte-for-byte.
///
/// Domain separation vs. [`hash_leaf`] — which uses `TAG_LEAF` and a
/// padding-flush — comes from the distinct `TAG_OUTLEAF` capacity IV,
/// not from shape; the no-pad construction cannot be reached through
/// the padded API under any tag.
pub fn hash_output_leaf(slot_index: u32, value: u64, owner: &Address) -> Digest {
    let [owner_hi, owner_lo] = owner.as_fields();
    let mut s = sponge(TAG_OUTLEAF);
    s.absorb_pair(
        Block128::from(slot_index as u128),
        Block128::from(value as u128),
    );
    s.absorb_pair(owner_hi, owner_lo);
    s.finalize_no_pad()
}

/// 32-byte fee leaf: `fee_le_bytes_u128 || [0u8; 16]`.
#[inline]
pub fn fee_leaf(fee: u128) -> Digest {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&fee.to_le_bytes());
    out
}

/// E.5.f₂ — encode `is_coinbase` into the L14 tx-body Merkle leaf as a
/// bit-wide digest: `L14 = [is_coinbase as u8, 0, …, 0]`.
///
/// Zero-preserving: `is_coinbase=false` leaves the leaf at the all-zero
/// digest used by every pre-E.5 body hash, so this change is a pure
/// extension of the digest surface. The corresponding AIR pin lives at
/// `TxBodyMerkleBoundaryPins.is_coinbase_leaf` and is tied to
/// `SKEL_IS_COINBASE_COL` in f₃.
#[inline]
pub fn is_coinbase_leaf(is_coinbase: bool) -> Digest {
    let mut out = [0u8; 32];
    out[0] = is_coinbase as u8;
    out
}

/// Canonical transaction-body hash.
///
/// Fixed 16-leaf, depth-4 Merkle tree over 32-byte canonical leaves,
/// reduced with [`compress`](crate::native::compress) and wrapped with
/// a single `TXBODY__` permutation. Layout:
///
/// ```text
/// L0         = prev_state_root
/// L1         = fee_leaf(fee)
/// L2..L5     = input_leaves[0..4]        // hash_input_leaf
/// L6..L13    = output_leaves[0..8]       // hash_output_leaf
/// L14        = is_coinbase_leaf(is_coinbase)  // E.5.f₂
/// L15        = [0u8; 32]                 // pad
/// ```
///
/// Callers (`noid_tx::body_hash::hash_tx_body`) fill padding with the
/// zero digest for dummy slots so the shape is constant across every
/// transaction.
pub fn hash_tx_body(
    prev_state_root: &Digest,
    fee: u128,
    input_leaves: &[Digest; TXBODY_INPUTS],
    output_leaves: &[Digest; TXBODY_OUTPUTS],
    is_coinbase: bool,
) -> TxBodyHash {
    let mut leaves: [Digest; TXBODY_LEAVES] = [[0u8; 32]; TXBODY_LEAVES];
    leaves[0] = *prev_state_root;
    leaves[1] = fee_leaf(fee);
    leaves[2..2 + TXBODY_INPUTS].copy_from_slice(input_leaves);
    leaves[2 + TXBODY_INPUTS..2 + TXBODY_INPUTS + TXBODY_OUTPUTS].copy_from_slice(output_leaves);
    leaves[14] = is_coinbase_leaf(is_coinbase);
    // L15 already zero.

    // Depth-4 reduction, serial: 16 → 8 → 4 → 2 → 1. The batch-parallel
    // path is overkill for a fixed 16-leaf tree.
    let mut level: Vec<Digest> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = vec![[0u8; 32]; level.len() / 2];
        compress_batch_interleaved_into(&level, &mut next);
        level = next;
    }

    // Final wrap: single permutation with capacity IV = `TXBODY__`.
    let root = level[0];
    let r0 = Block128::from(u128::from_le_bytes(root[..16].try_into().unwrap()));
    let r1 = Block128::from(u128::from_le_bytes(root[16..].try_into().unwrap()));
    let [iv_hi, iv_lo] = capacity_iv(TAG_TXBODY);
    let mut state = [r0, r1, iv_hi, iv_lo];
    Poseidon2bPermutation.permute_mut(&mut state);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&state[0].to_bytes());
    out[16..].copy_from_slice(&state[1].to_bytes());
    TxBodyHash(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::needless_range_loop)]
    use super::*;

    const SS: SpendSecret = SpendSecret([7u8; 32]);

    fn pad_inputs(leaves: Vec<Digest>) -> [Digest; TXBODY_INPUTS] {
        let mut out = [[0u8; 32]; TXBODY_INPUTS];
        for (i, d) in leaves.into_iter().enumerate() {
            out[i] = d;
        }
        out
    }
    fn pad_outputs(leaves: Vec<Digest>) -> [Digest; TXBODY_OUTPUTS] {
        let mut out = [[0u8; 32]; TXBODY_OUTPUTS];
        for (i, d) in leaves.into_iter().enumerate() {
            out[i] = d;
        }
        out
    }

    #[test]
    fn determinism_all_primitives() {
        let addr = derive_address(&SS);
        assert_eq!(addr, derive_address(&SS));

        let c = hash_utxo_leaf(100, &addr);
        assert_eq!(c, hash_utxo_leaf(100, &addr));

        let ins = pad_inputs(vec![hash_input_leaf(5, 100, &addr)]);
        let outs = pad_outputs(vec![c.0]);
        let tb = hash_tx_body(&[1u8; 32], 3, &ins, &outs, false);
        assert_eq!(tb, hash_tx_body(&[1u8; 32], 3, &ins, &outs, false));

        let t = hash_auth_tag(&SS, &tb);
        assert_eq!(t, hash_auth_tag(&SS, &tb));
    }

    #[test]
    fn cross_domain_no_collision() {
        let a = Block128::from(1u128);
        let b = Block128::from(2u128);
        let c = Block128::from(3u128);
        let d = Block128::from(4u128);

        let mut leaf = sponge(TAG_LEAF);
        leaf.absorb_pair(a, b);
        leaf.absorb_pair(c, d);
        let d_leaf = leaf.finalize();

        let mut commit = sponge(TAG_COMMIT);
        commit.absorb_pair(a, b);
        commit.absorb_pair(c, d);
        let d_commit = commit.finalize();

        let mut auth = sponge(TAG_AUTHTAG);
        auth.absorb_pair(a, b);
        auth.absorb_pair(c, d);
        let d_auth = auth.finalize();

        let mut addr = sponge(TAG_ADDRESS);
        addr.absorb_pair(a, b);
        addr.absorb_pair(c, d);
        let d_addr = addr.finalize();

        let all = [d_leaf, d_commit, d_auth, d_addr];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    #[test]
    fn tx_body_sensitive_to_ordering_and_fee() {
        let a1 = Address([1u8; 32]);
        let a2 = Address([2u8; 32]);
        let in1 = hash_input_leaf(0, 1, &a1);
        let in2 = hash_input_leaf(0, 2, &a2);
        let c1 = hash_utxo_leaf(1, &a1).0;
        let c2 = hash_utxo_leaf(2, &a2).0;

        let ins_ab = pad_inputs(vec![in1]);
        let ins_ba = pad_inputs(vec![in2]);
        let outs_ab = pad_outputs(vec![c2]);
        let outs_ba = pad_outputs(vec![c1]);

        let h_a = hash_tx_body(&[0u8; 32], 10, &ins_ab, &outs_ab, false);
        let h_b = hash_tx_body(&[0u8; 32], 10, &ins_ba, &outs_ba, false);
        let h_c = hash_tx_body(&[0u8; 32], 11, &ins_ab, &outs_ab, false);
        assert_ne!(h_a, h_b);
        assert_ne!(h_a, h_c);
    }

    fn txbody_wrap(root: [u8; 32]) -> [u8; 32] {
        let r0 = Block128::from(u128::from_le_bytes(root[..16].try_into().unwrap()));
        let r1 = Block128::from(u128::from_le_bytes(root[16..].try_into().unwrap()));
        let [hi, lo] = capacity_iv(TAG_TXBODY);
        let mut state = [r0, r1, hi, lo];
        Poseidon2bPermutation.permute_mut(&mut state);
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&state[0].to_bytes());
        out[16..].copy_from_slice(&state[1].to_bytes());
        out
    }

    #[test]
    fn tx_body_matches_reference_construction() {
        use crate::native::compress;

        let prev = [0xAAu8; 32];
        let fee = 0x1234_5678u128;

        // Fully-empty tx: 16 leaves = [prev, fee_leaf, 14 × zero].
        let mut leaves: [Digest; TXBODY_LEAVES] = [[0u8; 32]; TXBODY_LEAVES];
        leaves[0] = prev;
        leaves[1] = fee_leaf(fee);

        // Depth-4 compress.
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            let mut next = vec![[0u8; 32]; level.len() / 2];
            for (i, pair) in level.chunks_exact(2).enumerate() {
                next[i] = compress(&pair[0], &pair[1]);
            }
            level = next;
        }
        let expected = txbody_wrap(level[0]);

        let got = hash_tx_body(
            &prev,
            fee,
            &[[0u8; 32]; TXBODY_INPUTS],
            &[[0u8; 32]; TXBODY_OUTPUTS],
            false,
        );
        assert_eq!(got.0, expected);
    }

    #[test]
    fn tx_body_depth_always_four() {
        // Empty tx, 1-in/1-out, and 4-in/8-out must all produce
        // different but equally deep hashes.
        let a = Address([9u8; 32]);
        let ins_empty = [[0u8; 32]; TXBODY_INPUTS];
        let outs_empty = [[0u8; 32]; TXBODY_OUTPUTS];

        let mut ins_one = ins_empty;
        ins_one[0] = hash_input_leaf(1, 100, &a);
        let mut outs_one = outs_empty;
        outs_one[0] = hash_output_leaf(0, 50, &a);

        let mut ins_full = ins_empty;
        for i in 0..TXBODY_INPUTS {
            ins_full[i] = hash_input_leaf(i as u32, 10 + i as u64, &a);
        }
        let mut outs_full = outs_empty;
        for i in 0..TXBODY_OUTPUTS {
            outs_full[i] = hash_output_leaf(i as u32, 5 + i as u64, &a);
        }

        let h_empty = hash_tx_body(&[0u8; 32], 0, &ins_empty, &outs_empty, false);
        let h_one = hash_tx_body(&[0u8; 32], 0, &ins_one, &outs_one, false);
        let h_full = hash_tx_body(&[0u8; 32], 0, &ins_full, &outs_full, false);
        assert_ne!(h_empty, h_one);
        assert_ne!(h_empty, h_full);
        assert_ne!(h_one, h_full);
    }

    #[test]
    fn is_coinbase_flips_tx_body_hash() {
        // E.5.f₂: body hash must be sensitive to the is_coinbase flag;
        // the L14 leaf separates the coinbase branch from regular txs.
        let prev = [0u8; 32];
        let ins = [[0u8; 32]; TXBODY_INPUTS];
        let outs = [[0u8; 32]; TXBODY_OUTPUTS];
        let h_regular = hash_tx_body(&prev, 0, &ins, &outs, false);
        let h_coinbase = hash_tx_body(&prev, 0, &ins, &outs, true);
        assert_ne!(h_regular, h_coinbase);
    }

    #[test]
    fn is_coinbase_leaf_zero_preserving() {
        assert_eq!(is_coinbase_leaf(false), [0u8; 32]);
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(is_coinbase_leaf(true), expected);
    }

    #[test]
    fn address_changes_per_secret() {
        let s1 = SpendSecret([1u8; 32]);
        let s2 = SpendSecret([2u8; 32]);
        assert_ne!(derive_address(&s1), derive_address(&s2));
    }
}
