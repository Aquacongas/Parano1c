// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Typed cryptographic primitives for the UTXO layer.
//!
//! Every primitive is a thin wrapper over a Poseidon2b sponge seeded
//! with a capacity IV derived from a domain tag (see CRYPTO.md §3, §4,
//! §11). Newtype wrappers prevent cross-domain digest mix-ups at the
//! type level.
//!
//! Cross-reference with CRYPTO.md:
//! - §4.1 `compress` — re-exported from `native`
//! - §4.2 `hash_leaf`       — [`hash_leaf`]
//! - §4.3 `hash_commitment` — [`hash_commitment`]
//! - §4.4 `hash_nullifier`  — [`hash_nullifier`]
//! - §4.5 `hash_auth_tag`   — [`hash_auth_tag`]
//! - §4.6 `derive_address` / `derive_spend_secret` —
//!   [`derive_address`], [`derive_spend_secret`]
//! - §4.7 `hash_tx_body`    — [`hash_tx_body`]

use noid_core::Block128;
use rayon::prelude::*;

use crate::batch::compress_batch_interleaved_into;
use crate::native::compression::Poseidon2bSponge;
use crate::native::domain::{
    capacity_iv, DomainTag, TAG_ADDRESS, TAG_ADDRSPND, TAG_AUTHTAG, TAG_COMMIT, TAG_LEAF,
    TAG_NULLIFIER, TAG_SCANTAG, TAG_TXBODY, TAG_VIEWKEY,
};
use crate::native::permutation::Poseidon2bPermutation;
use noid_core::{CanonicalSerialize, TowerField};

/// Nullifier scheme version (CRYPTO.md §5.4). Absorbed as the final field
/// input to `hash_nullifier`. Increment to rotate the scheme; cross-version
/// collisions are impossible because the version is inside the sponge.
pub const NULLIFIER_VERSION: u128 = 1;

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
            /// `Block128` words. Used by primitives that take a digest
            /// back in as field input.
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
    /// A 256-bit flat-derived address. See CRYPTO.md §4.6.
    Address
);
newtype_digest!(
    /// A coin / output commitment. See CRYPTO.md §4.3.
    Commitment
);
newtype_digest!(
    /// A spend nullifier. See CRYPTO.md §4.4.
    Nullifier
);
newtype_digest!(
    /// A per-input authorization tag. See CRYPTO.md §4.5.
    AuthTag
);
newtype_digest!(
    /// A canonical transaction-body hash. See CRYPTO.md §4.7.
    TxBodyHash
);
newtype_digest!(
    /// A spend secret derived from the master secret. See CRYPTO.md §4.6.
    SpendSecret
);
newtype_digest!(
    /// The wallet master secret (stored encrypted at rest).
    MasterSecret
);
newtype_digest!(
    /// Wallet view key. Reveals incoming payments when shared; never
    /// grants spend authority. See CRYPTO.md §5.9.
    ViewKey
);
newtype_digest!(
    /// Per-output public scan tag. Lets a holder of the matching view key
    /// detect their outputs in O(1) per block scan. See CRYPTO.md §5.10.
    ScanTag
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
/// CRYPTO.md §4.2. Sponge-mode, capacity IV = `LEAF____`.
pub fn hash_leaf(fields: &[Block128]) -> Digest {
    let mut s = sponge(TAG_LEAF);
    absorb_fields(&mut s, fields);
    s.finalize()
}

/// Coin / output commitment. CRYPTO.md §4.3. Five field inputs:
/// `value` (little-endian u128), `owner` (full 256-bit address,
/// absorbed as two `Block128` halves), `blinding`, `asset_tag`
/// (`Block128::ZERO` for native asset, reserved for multi-asset).
///
/// Absorbing both halves of the address preserves the full 256-bit
/// collision resistance of the sponge capacity — a single 128-bit
/// address slot would cap commitment binding at ~2^64 work.
pub fn hash_commitment(
    value: u128,
    owner: &Address,
    blinding: Block128,
    asset_tag: Block128,
) -> Commitment {
    let [owner_hi, owner_lo] = owner.as_fields();
    let mut s = sponge(TAG_COMMIT);
    s.absorb(Block128::from(value));
    s.absorb(owner_hi);
    s.absorb(owner_lo);
    s.absorb(blinding);
    s.absorb(asset_tag);
    Commitment(s.finalize())
}

/// Spend nullifier. CRYPTO.md §5.4. Absorbs the spend secret, the coin
/// commitment, and the scheme [`NULLIFIER_VERSION`] as the final field so
/// future versions cannot collide with v1 outputs.
pub fn hash_nullifier(spend_secret: &SpendSecret, coin_commitment: &Commitment) -> Nullifier {
    let mut s = sponge(TAG_NULLIFIER);
    let [a, b] = spend_secret.as_fields();
    let [c, d] = coin_commitment.as_fields();
    s.absorb_pair(a, b);
    s.absorb_pair(c, d);
    s.absorb(Block128::from(NULLIFIER_VERSION));
    Nullifier(s.finalize())
}

/// Per-input authorization tag binding the STARK proof to this tx
/// body. CRYPTO.md §4.5.
pub fn hash_auth_tag(spend_secret: &SpendSecret, tx_body_hash: &TxBodyHash) -> AuthTag {
    let mut s = sponge(TAG_AUTHTAG);
    let [a, b] = spend_secret.as_fields();
    let [c, d] = tx_body_hash.as_fields();
    s.absorb_pair(a, b);
    s.absorb_pair(c, d);
    AuthTag(s.finalize())
}

/// Derive a stealth address from the wallet master secret and a
/// payer-chosen public salt. CRYPTO.md §5.6.
///
/// Each output on-chain includes its own salt; recipients recover
/// `spend_secret` from `(master_secret, salt)`. Distinct salts produce
/// unlinkable addresses for the same logical wallet.
pub fn derive_address(master_secret: &MasterSecret, salt: Block128) -> Address {
    let mut s = sponge(TAG_ADDRESS);
    let [a, b] = master_secret.as_fields();
    s.absorb_pair(a, b);
    // Salt is a 128-bit public value. Absorb as a single rate slot plus a
    // zero companion so the schedule matches `derive_spend_secret` exactly.
    s.absorb_pair(salt, Block128::ZERO);
    Address(s.finalize())
}

/// Derive the spend secret for a stealth address. CRYPTO.md §5.6.
pub fn derive_spend_secret(master_secret: &MasterSecret, salt: Block128) -> SpendSecret {
    let mut s = sponge(TAG_ADDRSPND);
    let [a, b] = master_secret.as_fields();
    s.absorb_pair(a, b);
    s.absorb_pair(salt, Block128::ZERO);
    SpendSecret(s.finalize())
}

/// Derive the wallet view key from the master secret. CRYPTO.md §5.9.
///
/// Sharing the view key reveals incoming payments (via `hash_scan_tag`) but
/// does NOT grant spend authority — the spend path uses `ADDRSPND`, which
/// is a disjoint IV. The view key is wallet-wide (not per-output), which is
/// what makes third-party scanning cheap.
pub fn derive_view_key(master_secret: &MasterSecret) -> ViewKey {
    let mut s = sponge(TAG_VIEWKEY);
    let [a, b] = master_secret.as_fields();
    s.absorb_pair(a, b);
    ViewKey(s.finalize())
}

/// Compute the public scan tag for an output. CRYPTO.md §5.10.
///
/// Each output carries `(salt, scan_tag)` on-chain. A scanner holding the
/// matching view key recomputes `hash_scan_tag(view_key, salt)` for every
/// output and compares — a single Poseidon2b sponge per output, no secret
/// state. Non-holders cannot distinguish outputs because the view key is
/// preimage-protected by the sponge.
///
/// The `SCANTAG_` IV is disjoint from `ADDRESS_` / `ADDRSPND` / `VIEWKEY_`,
/// so a view-key holder cannot grind cross-domain collisions.
pub fn hash_scan_tag(view_key: &ViewKey, salt: Block128) -> ScanTag {
    let mut s = sponge(TAG_SCANTAG);
    let [a, b] = view_key.as_fields();
    s.absorb_pair(a, b);
    s.absorb_pair(salt, Block128::ZERO);
    ScanTag(s.finalize())
}

/// Canonical transaction-body hash. CRYPTO.md §4.7.
///
/// Builds a binary Merkle tree over 32-byte canonical leaf encodings
/// and reduces it with [`compress`]. No per-leaf sponge — every payload
/// is already a digest or a canonically padded scalar. The leaf order is
/// `[prev_state_root, fee_leaf, input_commitments..., output_commitments...]`
/// padded to the next power of two with the zero digest.
///
/// `fee_leaf` is `le_bytes_u128(fee) || [0u8; 16]`.
pub fn hash_tx_body(
    prev_state_root: &Digest,
    fee: u128,
    input_commitments: &[Commitment],
    output_commitments: &[Commitment],
) -> TxBodyHash {
    let n = 2 + input_commitments.len() + output_commitments.len();
    let target = n.next_power_of_two().max(2);

    let mut leaves: Vec<Digest> = Vec::with_capacity(target);
    leaves.push(*prev_state_root);

    let mut fee_leaf = [0u8; 32];
    fee_leaf[..16].copy_from_slice(&fee.to_le_bytes());
    leaves.push(fee_leaf);

    for c in input_commitments {
        leaves.push(c.0);
    }
    for c in output_commitments {
        leaves.push(c.0);
    }
    leaves.resize(target, [0u8; 32]);

    // Merkle up. Each level feeds `compress_batch_interleaved_into`
    // (SIMD-packed across PACKED_LANES). Above a threshold, split the
    // layer across rayon threads; each chunk still calls the batch
    // routine, so we compose SIMD × threads.
    const PAR_COMPRESS_THRESHOLD: usize = 64;
    let mut level = leaves;
    while level.len() > 1 {
        let out_len = level.len() / 2;
        let mut next = vec![[0u8; 32]; out_len];

        if level.len() >= PAR_COMPRESS_THRESHOLD {
            // Chunk by pairs of leaves (each pair produces one output);
            // use a big chunk so each thread gets enough work to amortize
            // rayon overhead and still fill the SIMD lanes.
            let pairs_per_chunk = (out_len / rayon::current_num_threads()).max(32);
            next.par_chunks_mut(pairs_per_chunk)
                .enumerate()
                .for_each(|(ci, out_chunk)| {
                    let start = ci * pairs_per_chunk;
                    let in_slice = &level[2 * start..2 * (start + out_chunk.len())];
                    compress_batch_interleaved_into(in_slice, out_chunk);
                });
        } else {
            compress_batch_interleaved_into(&level, &mut next);
        }

        level = next;
    }

    // Final wrap — CRYPTO.md §5.7 step 3. Single permutation with
    // capacity IV = `TXBODY__`. Provides explicit domain separation over
    // the COMPRESS-domain Merkle tree.
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
    use super::*;
    use noid_core::TowerField;

    const MS: MasterSecret = MasterSecret([7u8; 32]);

    #[test]
    fn determinism_all_primitives() {
        let addr = derive_address(&MS, Block128::from(0u128));
        assert_eq!(addr, derive_address(&MS, Block128::from(0u128)));

        let spend = derive_spend_secret(&MS, Block128::from(0u128));
        assert_eq!(spend, derive_spend_secret(&MS, Block128::from(0u128)));

        let c = hash_commitment(100, &addr, Block128::from(9u8), Block128::ZERO);
        assert_eq!(
            c,
            hash_commitment(100, &addr, Block128::from(9u8), Block128::ZERO)
        );

        let n = hash_nullifier(&spend, &c);
        assert_eq!(n, hash_nullifier(&spend, &c));

        let tb = hash_tx_body(&[1u8; 32], 3, &[c], &[c]);
        assert_eq!(tb, hash_tx_body(&[1u8; 32], 3, &[c], &[c]));

        let t = hash_auth_tag(&spend, &tb);
        assert_eq!(t, hash_auth_tag(&spend, &tb));
    }

    #[test]
    fn address_and_spend_secret_are_different_domains() {
        let addr = derive_address(&MS, Block128::from(0u128));
        let spend = derive_spend_secret(&MS, Block128::from(0u128));
        assert_ne!(addr.as_bytes(), spend.as_bytes());
    }

    #[test]
    fn cross_domain_no_collision() {
        // Same sponge-mode inputs through four different IVs must
        // produce four distinct digests.
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

        let mut nullif = sponge(TAG_NULLIFIER);
        nullif.absorb_pair(a, b);
        nullif.absorb_pair(c, d);
        let d_nullif = nullif.finalize();

        let mut auth = sponge(TAG_AUTHTAG);
        auth.absorb_pair(a, b);
        auth.absorb_pair(c, d);
        let d_auth = auth.finalize();

        let all = [d_leaf, d_commit, d_nullif, d_auth];
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
        let c1 = hash_commitment(1, &a1, Block128::from(1u8), Block128::ZERO);
        let c2 = hash_commitment(2, &a2, Block128::from(2u8), Block128::ZERO);

        let h_a = hash_tx_body(&[0u8; 32], 10, &[c1], &[c2]);
        let h_b = hash_tx_body(&[0u8; 32], 10, &[c2], &[c1]);
        let h_c = hash_tx_body(&[0u8; 32], 11, &[c1], &[c2]);
        assert_ne!(h_a, h_b);
        assert_ne!(h_a, h_c);
    }

    fn txbody_wrap(root: [u8; 32]) -> [u8; 32] {
        use crate::native::domain::{capacity_iv, TAG_TXBODY};
        use crate::native::permutation::Poseidon2bPermutation;
        use noid_core::CanonicalSerialize;

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
        // Zero I/O → exactly 2 leaves. tree root = compress(prev, fee_leaf),
        // then the TXBODY final wrap.
        use crate::native::compress;

        let prev = [0xAAu8; 32];
        let fee = 0x1234_5678u128;
        let mut fee_leaf = [0u8; 32];
        fee_leaf[..16].copy_from_slice(&fee.to_le_bytes());

        let root = compress(&prev, &fee_leaf);
        let expected = txbody_wrap(root);
        let got = hash_tx_body(&prev, fee, &[], &[]);
        assert_eq!(got.0, expected);
    }

    #[test]
    fn tx_body_pads_with_zero_digest() {
        // 3 leaves → padded to 4 with ZERO_DIGEST, then TXBODY wrap.
        use crate::native::compress;

        let prev = [0x11u8; 32];
        let fee = 7u128;
        let addr = Address([1u8; 32]);
        let c = hash_commitment(5, &addr, Block128::from(2u8), Block128::ZERO);

        let mut fee_leaf = [0u8; 32];
        fee_leaf[..16].copy_from_slice(&fee.to_le_bytes());
        let left = compress(&prev, &fee_leaf);
        let right = compress(&c.0, &[0u8; 32]);
        let root = compress(&left, &right);
        let expected = txbody_wrap(root);

        let got = hash_tx_body(&prev, fee, &[c], &[]);
        assert_eq!(got.0, expected);
    }

    #[test]
    fn view_key_independent_of_spend_secret() {
        let ms = MasterSecret([9u8; 32]);
        let vk = derive_view_key(&ms);
        let sp = derive_spend_secret(&ms, Block128::from(0u128));
        // Distinct IVs over overlapping inputs must land on distinct digests.
        assert_ne!(vk.as_bytes(), sp.as_bytes());
    }

    #[test]
    fn scan_tag_detectable_with_view_key_only() {
        let ms = MasterSecret([9u8; 32]);
        let vk = derive_view_key(&ms);
        let salt = Block128::from(0x1234_5678u128);

        // A sender knowing the recipient's view key (e.g., a payment URI
        // exposed out-of-band) can compute the scan tag and attach it.
        let tag_sender = hash_scan_tag(&vk, salt);

        // The recipient's scanner recomputes from the same view_key and
        // matches — no secrets leaked.
        let tag_scanner = hash_scan_tag(&vk, salt);
        assert_eq!(tag_sender, tag_scanner);

        // A different view key produces a different tag for the same salt.
        let other_vk = derive_view_key(&MasterSecret([10u8; 32]));
        assert_ne!(hash_scan_tag(&other_vk, salt), tag_scanner);
    }

    #[test]
    fn scan_tag_changes_per_salt() {
        let ms = MasterSecret([9u8; 32]);
        let vk = derive_view_key(&ms);
        let t1 = hash_scan_tag(&vk, Block128::from(1u128));
        let t2 = hash_scan_tag(&vk, Block128::from(2u128));
        assert_ne!(t1, t2);
    }

    #[test]
    fn view_key_domain_disjoint_from_scan_tag() {
        // Protects against an attacker who sees a view-key-derived digest
        // trying to reuse it as a scan tag or vice versa.
        let ms = MasterSecret([11u8; 32]);
        let vk = derive_view_key(&ms);
        let salt = Block128::from(7u128);
        let st = hash_scan_tag(&vk, salt);
        assert_ne!(vk.as_bytes(), st.as_bytes());
    }

    #[test]
    fn nullifier_unlinkable_per_secret() {
        let addr = Address([1u8; 32]);
        let c = hash_commitment(42, &addr, Block128::from(123u8), Block128::ZERO);
        let salt = Block128::from(0u128);
        let s1 = derive_spend_secret(&MasterSecret([1u8; 32]), salt);
        let s2 = derive_spend_secret(&MasterSecret([2u8; 32]), salt);
        assert_ne!(hash_nullifier(&s1, &c), hash_nullifier(&s2, &c));
    }
}
