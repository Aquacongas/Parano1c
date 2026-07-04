// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Batch Poseidon2b permutation using packed arithmetic.
//!
//! Processes P independent permutations simultaneously by:
//! 1. Loading P state vectors into packed representation
//! 2. Applying linear operations (round constants, MDS) in packed form
//! 3. Applying S-box per lane (squarings are packed, muls are per-lane)

// Many loops in this module iterate by explicit index because they touch
// multiple parallel buffers (state/input/round-constants/MDS rows) or use
// the index arithmetically. Rewriting them as iterator chains hurts
// readability without changing generated code.
#![allow(clippy::needless_range_loop)]

use crate::native::compression::Poseidon2bSponge;
use crate::native::domain::{capacity_iv, DomainTag, TAG_COMPRESS};
use crate::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};
use noid_core::hardware::tower_to_flat_u128;
use noid_core::packed::{PackedBlock128, PACKED_LANES};
use noid_core::Block128;
use std::sync::OnceLock;

/// Number of independent Block128 lanes used by the packed Poseidon2b kernels
/// in this build.
pub const POSEIDON2B_BATCH_LANES: usize = PACKED_LANES;

/// Padding constants for Poseidon2b sponge finalization.
const PAD0: u128 = u128::from_le_bytes([0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const PAD1: u128 = u128::from_le_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);

/// Hash pairs of field elements using packed permutations.
///
/// When `PACKED_LANES > 1` and the input is large enough, processes
/// multiple hashes simultaneously. Falls back to scalar hashing for
/// small inputs or scalar builds.
pub fn hash_pair_batch(a: &[Block128], b: &[Block128]) -> Vec<[u8; 32]> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    let mut out = vec![[0u8; 32]; n];

    let scalar = |i: usize| scalar_hash_pair(a[i], b[i]);

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            out[i] = scalar(i);
        }
        return out;
    }

    let chunks = n / PACKED_LANES;
    let _rem = n % PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        for lane in 0..PACKED_LANES {
            states[0] = states[0].set_lane(lane, a[off + lane]);
            states[1] = states[1].set_lane(lane, b[off + lane]);
        }

        // Fixed-width compression: one permutation on [a, b, 0, 0].
        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        out[i] = scalar(i);
    }

    out
}

/// Hash adjacent pairs of field elements from a single interleaved slice.
///
/// `pairs` has even length: `[a0, b0, a1, b1, ...]`. Output `out[i]` is the
/// `hash_pair(a_i, b_i)` digest. Skips the two-Vec split that
/// `hash_pair_batch` callers would otherwise have to do on an interleaved
/// input.
pub fn hash_pair_batch_interleaved_into(pairs: &[Block128], out: &mut [[u8; 32]]) {
    assert_eq!(
        pairs.len() & 1,
        0,
        "hash_pair_batch_interleaved expects even length"
    );
    let n = pairs.len() / 2;
    assert_eq!(out.len(), n, "output length must match pair count");

    let scalar = |i: usize, out: &mut [[u8; 32]]| {
        out[i] = scalar_hash_pair(pairs[2 * i], pairs[2 * i + 1]);
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            scalar(i, out);
        }
        return;
    }

    let chunks = n / PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        for lane in 0..PACKED_LANES {
            states[0] = states[0].set_lane(lane, pairs[2 * (off + lane)]);
            states[1] = states[1].set_lane(lane, pairs[2 * (off + lane) + 1]);
        }

        // Fixed-width compression: one permutation on [a, b, 0, 0].
        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        scalar(i, out);
    }
}

/// Scalar fixed-width `(Block128, Block128) → [u8; 32]` compression.
/// Matches `CryptographicHasher::hash_pair` — one Poseidon2b permutation.
fn scalar_hash_pair(a: Block128, b: Block128) -> [u8; 32] {
    use crate::native::permutation::Poseidon2bPermutation;
    use noid_core::{CanonicalSerialize, TowerField};
    let mut state = [a, b, Block128::ZERO, Block128::ZERO];
    Poseidon2bPermutation.permute_mut(&mut state);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&state[0].to_bytes());
    out[16..].copy_from_slice(&state[1].to_bytes());
    out
}

/// Hash concatenations of 32-byte digests using packed permutations.
///
/// Matches the exact scalar output of `Poseidon2bSponge::hash_concatenation`.
pub fn hash_concatenation_batch(a: &[[u8; 32]], b: &[[u8; 32]]) -> Vec<[u8; 32]> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    let mut out = vec![[0u8; 32]; n];

    let scalar = |i: usize| {
        let mut sponge = Poseidon2bSponge::new();
        sponge.update(&a[i]);
        sponge.update(&b[i]);
        sponge.finalize()
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            out[i] = scalar(i);
        }
        return out;
    }

    let chunks = n / PACKED_LANES;
    let _rem = n % PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        // Load a into rate (states start at zero, so set = XOR)
        for lane in 0..PACKED_LANES {
            let a0 = Block128::from(u128::from_le_bytes(
                a[off + lane][0..16].try_into().unwrap(),
            ));
            let a1 = Block128::from(u128::from_le_bytes(
                a[off + lane][16..32].try_into().unwrap(),
            ));
            states[0] = states[0].set_lane(lane, a0);
            states[1] = states[1].set_lane(lane, a1);
        }

        // update(a) -> permute
        packed_poseidon2b_permute(&mut states);

        // XOR b into rate
        let mut pb0 = PackedBlock128::ZERO;
        let mut pb1 = PackedBlock128::ZERO;
        for lane in 0..PACKED_LANES {
            let b0 = Block128::from(u128::from_le_bytes(
                b[off + lane][0..16].try_into().unwrap(),
            ));
            let b1 = Block128::from(u128::from_le_bytes(
                b[off + lane][16..32].try_into().unwrap(),
            ));
            pb0 = pb0.set_lane(lane, b0);
            pb1 = pb1.set_lane(lane, b1);
        }
        states[0] = states[0].xor(pb0);
        states[1] = states[1].xor(pb1);

        packed_poseidon2b_permute(&mut states);

        // finalize padding
        states[0] = states[0].xor(PackedBlock128::broadcast(Block128::from(PAD0)));
        states[1] = states[1].xor(PackedBlock128::broadcast(Block128::from(PAD1)));
        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        out[i] = scalar(i);
    }

    out
}

/// Hash interleaved pairs of 32-byte digests using packed permutations.
///
/// `pairs` must have even length and contain `[a0, b0, a1, b1, ...]`.
/// Matches the exact scalar output of `Poseidon2bSponge::hash_concatenation`.
pub fn hash_concatenation_batch_interleaved(pairs: &[[u8; 32]]) -> Vec<[u8; 32]> {
    assert_eq!(
        pairs.len() & 1,
        0,
        "Interleaved pairs must have even length"
    );
    let n = pairs.len() / 2;
    let mut out = vec![[0u8; 32]; n];

    let scalar = |i: usize| {
        let mut sponge = Poseidon2bSponge::new();
        sponge.update(&pairs[2 * i]);
        sponge.update(&pairs[2 * i + 1]);
        sponge.finalize()
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            out[i] = scalar(i);
        }
        return out;
    }

    let chunks = n / PACKED_LANES;
    let _rem = n % PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        // Load a into rate (states start at zero)
        for lane in 0..PACKED_LANES {
            let a0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][0..16].try_into().unwrap(),
            ));
            let a1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][16..32].try_into().unwrap(),
            ));
            states[0] = states[0].set_lane(lane, a0);
            states[1] = states[1].set_lane(lane, a1);
        }

        packed_poseidon2b_permute(&mut states);

        // XOR b into rate
        let mut pb0 = PackedBlock128::ZERO;
        let mut pb1 = PackedBlock128::ZERO;
        for lane in 0..PACKED_LANES {
            let b0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][0..16].try_into().unwrap(),
            ));
            let b1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][16..32].try_into().unwrap(),
            ));
            pb0 = pb0.set_lane(lane, b0);
            pb1 = pb1.set_lane(lane, b1);
        }
        states[0] = states[0].xor(pb0);
        states[1] = states[1].xor(pb1);

        packed_poseidon2b_permute(&mut states);

        // finalize padding
        states[0] = states[0].xor(PackedBlock128::broadcast(Block128::from(PAD0)));
        states[1] = states[1].xor(PackedBlock128::broadcast(Block128::from(PAD1)));
        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        out[i] = scalar(i);
    }

    out
}

/// Batched 2-to-1 compression of interleaved 32-byte digest pairs.
///
/// Matches `native::compress` exactly: two Poseidon2b permutations per
/// pair with capacity IV = `COMPRESS` absorbed before `a`, then `b` XORed
/// into the rate between permutations (CRYPTO.md §5.1).
pub fn compress_batch_interleaved_into(pairs: &[[u8; 32]], out: &mut [[u8; 32]]) {
    compress_batch_interleaved_with_tag_into(TAG_COMPRESS, pairs, out);
}

/// Batched 2-to-1 compression of interleaved 32-byte digest pairs under a
/// caller-selected capacity tag.
///
/// Matches `native::compress_with_tag(tag, left, right)` exactly.
pub fn compress_batch_interleaved_with_tag_into(
    tag: DomainTag,
    pairs: &[[u8; 32]],
    out: &mut [[u8; 32]],
) {
    assert_eq!(
        pairs.len() & 1,
        0,
        "Interleaved pairs must have even length"
    );
    let n = pairs.len() / 2;
    assert_eq!(out.len(), n, "Output length must match pair count");

    let scalar = |i: usize, out: &mut [[u8; 32]]| {
        out[i] = crate::native::compress_with_tag(tag, &pairs[2 * i], &pairs[2 * i + 1]);
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            scalar(i, out);
        }
        return;
    }

    let [iv_hi, iv_lo] = capacity_iv(tag);
    let chunks = n / PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        // state = [a0, a1, IV_hi, IV_lo]
        states[2] = PackedBlock128::broadcast(iv_hi);
        states[3] = PackedBlock128::broadcast(iv_lo);
        for lane in 0..PACKED_LANES {
            let a0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][0..16].try_into().unwrap(),
            ));
            let a1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][16..32].try_into().unwrap(),
            ));
            states[0] = states[0].set_lane(lane, a0);
            states[1] = states[1].set_lane(lane, a1);
        }

        packed_poseidon2b_permute(&mut states);

        // XOR b into rate.
        let mut pb0 = PackedBlock128::ZERO;
        let mut pb1 = PackedBlock128::ZERO;
        for lane in 0..PACKED_LANES {
            let b0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][0..16].try_into().unwrap(),
            ));
            let b1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][16..32].try_into().unwrap(),
            ));
            pb0 = pb0.set_lane(lane, b0);
            pb1 = pb1.set_lane(lane, b1);
        }
        states[0] = states[0].xor(pb0);
        states[1] = states[1].xor(pb1);

        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        scalar(i, out);
    }
}

/// Like `hash_concatenation_batch_interleaved` but writes into a caller-provided
/// output slice. Skips the Vec allocation per layer.
pub fn hash_concatenation_batch_interleaved_into(pairs: &[[u8; 32]], out: &mut [[u8; 32]]) {
    assert_eq!(
        pairs.len() & 1,
        0,
        "Interleaved pairs must have even length"
    );
    let n = pairs.len() / 2;
    assert_eq!(out.len(), n, "Output length must match pair count");

    let scalar = |i: usize, out: &mut [[u8; 32]]| {
        let mut sponge = Poseidon2bSponge::new();
        sponge.update(&pairs[2 * i]);
        sponge.update(&pairs[2 * i + 1]);
        out[i] = sponge.finalize();
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            scalar(i, out);
        }
        return;
    }

    let chunks = n / PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        for lane in 0..PACKED_LANES {
            let a0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][0..16].try_into().unwrap(),
            ));
            let a1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane)][16..32].try_into().unwrap(),
            ));
            states[0] = states[0].set_lane(lane, a0);
            states[1] = states[1].set_lane(lane, a1);
        }

        packed_poseidon2b_permute(&mut states);

        let mut pb0 = PackedBlock128::ZERO;
        let mut pb1 = PackedBlock128::ZERO;
        for lane in 0..PACKED_LANES {
            let b0 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][0..16].try_into().unwrap(),
            ));
            let b1 = Block128::from(u128::from_le_bytes(
                pairs[2 * (off + lane) + 1][16..32].try_into().unwrap(),
            ));
            pb0 = pb0.set_lane(lane, b0);
            pb1 = pb1.set_lane(lane, b1);
        }
        states[0] = states[0].xor(pb0);
        states[1] = states[1].xor(pb1);

        packed_poseidon2b_permute(&mut states);

        states[0] = states[0].xor(PackedBlock128::broadcast(Block128::from(PAD0)));
        states[1] = states[1].xor(PackedBlock128::broadcast(Block128::from(PAD1)));
        packed_poseidon2b_permute(&mut states);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        scalar(i, out);
    }
}

/// Precomputed flat-basis round constants and MDS matrices.
///
/// XOR is identical in tower and flat bases (both linear over GF(2)), and
/// scalar multiplication in flat basis is just CLMUL. Converting the
/// Poseidon2b constants once at program start lets the batch permutation
/// stay in flat basis for the entire schedule.
struct FlatTables {
    rc: [[u128; N_ROUNDS]; STATE_SIZE],
    mds_full: [[u128; STATE_SIZE]; STATE_SIZE],
    mds_partial: [[u128; STATE_SIZE]; STATE_SIZE],
    // Sparsity masks: `is_one[i][j] = true` when MDS[i][j] == tower 0x1.
    // In that case multiplication is the identity and the CLMUL can be
    // replaced with a bare XOR of the input.
    mds_full_is_one: [[bool; STATE_SIZE]; STATE_SIZE],
    mds_partial_is_one: [[bool; STATE_SIZE]; STATE_SIZE],
}

fn flat_tables() -> &'static FlatTables {
    static TABLES: OnceLock<FlatTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut rc = [[0u128; N_ROUNDS]; STATE_SIZE];
        for i in 0..STATE_SIZE {
            for r in 0..N_ROUNDS {
                rc[i][r] = tower_to_flat_u128(ROUND_CONSTANTS[i][r]);
            }
        }
        let mut mds_full = [[0u128; STATE_SIZE]; STATE_SIZE];
        let mut mds_partial = [[0u128; STATE_SIZE]; STATE_SIZE];
        let mut mds_full_is_one = [[false; STATE_SIZE]; STATE_SIZE];
        let mut mds_partial_is_one = [[false; STATE_SIZE]; STATE_SIZE];
        for i in 0..STATE_SIZE {
            for j in 0..STATE_SIZE {
                mds_full[i][j] = tower_to_flat_u128(MDS_FULL[i][j]);
                mds_partial[i][j] = tower_to_flat_u128(MDS_PARTIAL[i][j]);
                mds_full_is_one[i][j] = MDS_FULL[i][j] == 1;
                mds_partial_is_one[i][j] = MDS_PARTIAL[i][j] == 1;
            }
        }
        FlatTables {
            rc,
            mds_full,
            mds_partial,
            mds_full_is_one,
            mds_partial_is_one,
        }
    })
}

/// Apply PackedBlock128 Poseidon2b permutation to P states simultaneously.
///
/// Runs the entire schedule in flat basis: a single tower→flat pass at the
/// start and flat→tower pass at the end replaces what was previously 3
/// basis conversions per CLMUL (hundreds per permutation).
pub fn packed_poseidon2b_permute(states: &mut [PackedBlock128; STATE_SIZE]) {
    // Convert state to flat basis once.
    for i in 0..STATE_SIZE {
        states[i] = states[i].to_flat();
    }
    packed_poseidon2b_permute_flat(states);
    // Convert back to tower basis.
    for i in 0..STATE_SIZE {
        states[i] = states[i].to_tower();
    }
}

/// Packed permutation acting on states whose lanes already carry **flat
/// (GCM) basis** bit patterns — the batched twin of
/// `native::permutation::permute_flat_u128`, with no boundary conversion.
pub fn packed_poseidon2b_permute_flat(states: &mut [PackedBlock128; STATE_SIZE]) {
    let tables = flat_tables();

    // Initial MDS_FULL multiplication (flat basis).
    packed_apply_mds_full_flat(states, tables);

    for r in 0..N_ROUNDS {
        let is_full = !((F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&r));

        // 1. Add round constants (linear — XOR works in flat basis).
        if is_full {
            for i in 0..STATE_SIZE {
                let rc_flat = tables.rc[i][r];
                states[i] = states[i].xor(PackedBlock128::broadcast(Block128::from(rc_flat)));
            }
        } else {
            let rc_flat = tables.rc[0][r];
            states[0] = states[0].xor(PackedBlock128::broadcast(Block128::from(rc_flat)));
        }

        // 2. Apply S-box x → x^7 in flat basis (no round trips).
        let active_count = if is_full { STATE_SIZE } else { 1 };
        for i in 0..active_count {
            states[i] = packed_sbox_x7_flat(states[i]);
        }

        // 3. Apply MDS (flat basis).
        if is_full {
            packed_apply_mds_full_flat(states, tables);
        } else {
            packed_apply_mds_partial_flat(states, tables);
        }
    }
}

/// Batched flat-basis 1-permutation feed-forward compression of interleaved
/// 32-byte digest pairs. Matches
/// `native::compress_flat_feed_forward_with_tag(tag, left, right)` exactly.
pub fn compress_flat_ff_batch_interleaved_with_tag_into(
    tag: DomainTag,
    pairs: &[[u8; 32]],
    out: &mut [[u8; 32]],
) {
    assert_eq!(
        pairs.len() & 1,
        0,
        "Interleaved pairs must have even length"
    );
    let n = pairs.len() / 2;
    assert_eq!(out.len(), n, "Output length must match pair count");

    let scalar = |i: usize, out: &mut [[u8; 32]]| {
        out[i] = crate::native::compression::compress_flat_feed_forward_with_tag(
            tag,
            &pairs[2 * i],
            &pairs[2 * i + 1],
        );
    };

    if PACKED_LANES == 1 || n < PACKED_LANES {
        for i in 0..n {
            scalar(i, out);
        }
        return;
    }

    let [iv_hi, iv_lo] = crate::native::domain::capacity_iv_flat(tag);
    let chunks = n / PACKED_LANES;

    for chunk in 0..chunks {
        let mut states = [PackedBlock128::ZERO; STATE_SIZE];
        let off = chunk * PACKED_LANES;

        // state = [a0, a1, b0 ^ IV_hi, b1 ^ IV_lo] (all lanes flat bit
        // patterns; Block128 is used as a plain 128-bit container here).
        let mut a0s = PackedBlock128::ZERO;
        let mut a1s = PackedBlock128::ZERO;
        for lane in 0..PACKED_LANES {
            let a = &pairs[2 * (off + lane)];
            let b = &pairs[2 * (off + lane) + 1];
            let a0 = u128::from_le_bytes(a[0..16].try_into().unwrap());
            let a1 = u128::from_le_bytes(a[16..32].try_into().unwrap());
            let b0 = u128::from_le_bytes(b[0..16].try_into().unwrap());
            let b1 = u128::from_le_bytes(b[16..32].try_into().unwrap());
            a0s = a0s.set_lane(lane, Block128::from(a0));
            a1s = a1s.set_lane(lane, Block128::from(a1));
            states[0] = states[0].set_lane(lane, Block128::from(a0));
            states[1] = states[1].set_lane(lane, Block128::from(a1));
            states[2] = states[2].set_lane(lane, Block128::from(b0 ^ iv_hi));
            states[3] = states[3].set_lane(lane, Block128::from(b1 ^ iv_lo));
        }

        packed_poseidon2b_permute_flat(&mut states);

        // Feed-forward of the left input on the truncated lanes.
        states[0] = states[0].xor(a0s);
        states[1] = states[1].xor(a1s);

        for lane in 0..PACKED_LANES {
            let s0 = states[0].get_lane(lane);
            let s1 = states[1].get_lane(lane);
            out[off + lane][..16].copy_from_slice(&s0.to_u128().to_le_bytes());
            out[off + lane][16..].copy_from_slice(&s1.to_u128().to_le_bytes());
        }
    }

    let rem_off = chunks * PACKED_LANES;
    for i in rem_off..n {
        scalar(i, out);
    }
}

/// Packed S-box x → x^7 entirely in flat basis.
///
/// x^2, x^4 use `flat_square` (CLMUL-free bit spread + reduction); the
/// two multiplications use raw CLMUL with no basis conversion.
#[inline(always)]
fn packed_sbox_x7_flat(x: PackedBlock128) -> PackedBlock128 {
    let x2 = x.flat_square();
    let x4 = x2.flat_square();
    let x6 = x.flat_mul(x2);
    x6.flat_mul(x4)
}

#[inline(always)]
fn packed_apply_mds_full_flat(state: &mut [PackedBlock128; STATE_SIZE], tables: &FlatTables) {
    let input = *state;
    for i in 0..STATE_SIZE {
        let mut out = PackedBlock128::ZERO;
        for j in 0..STATE_SIZE {
            // Skip CLMUL when the MDS entry is 1 (identity); XOR the lane
            // directly. On GF(2^128) over flat basis, `a * 1 = a`.
            if tables.mds_full_is_one[i][j] {
                out = out.xor(input[j]);
            } else {
                out = out.xor(input[j].flat_scalar_mul(tables.mds_full[i][j]));
            }
        }
        state[i] = out;
    }
}

#[inline(always)]
fn packed_apply_mds_partial_flat(state: &mut [PackedBlock128; STATE_SIZE], tables: &FlatTables) {
    let input = *state;
    for i in 0..STATE_SIZE {
        let mut out = PackedBlock128::ZERO;
        for j in 0..STATE_SIZE {
            if tables.mds_partial_is_one[i][j] {
                out = out.xor(input[j]);
            } else {
                out = out.xor(input[j].flat_scalar_mul(tables.mds_partial[i][j]));
            }
        }
        state[i] = out;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::CryptographicHasher;
    use crate::native::compression::Poseidon2bSponge;
    use noid_core::TowerField;
    use rand::Rng;

    #[test]
    fn test_hash_pair_batch_matches_scalar() {
        let mut rng = rand::thread_rng();
        let n = 256;
        let a: Vec<Block128> = (0..n).map(|_| Block128::from(rng.gen::<u128>())).collect();
        let b: Vec<Block128> = (0..n).map(|_| Block128::from(rng.gen::<u128>())).collect();

        let sponge = Poseidon2bSponge::new();
        let expected: Vec<[u8; 32]> = (0..n).map(|i| sponge.hash_pair(&a[i], &b[i])).collect();

        let got = hash_pair_batch(&a, &b);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_hash_concatenation_batch_matches_scalar() {
        let mut rng = rand::thread_rng();
        let n = 256;
        let a: Vec<[u8; 32]> = (0..n).map(|_| rng.gen()).collect();
        let b: Vec<[u8; 32]> = (0..n).map(|_| rng.gen()).collect();

        let sponge = Poseidon2bSponge::new();
        let expected: Vec<[u8; 32]> = (0..n)
            .map(|i| sponge.hash_concatenation(&a[i], &b[i]))
            .collect();

        let got = hash_concatenation_batch(&a, &b);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_hash_pair_batch_small_input() {
        let sponge = Poseidon2bSponge::new();
        let a = vec![Block128::ONE, Block128::ZERO];
        let b = vec![Block128::ZERO, Block128::ONE];
        let expected = vec![
            sponge.hash_pair(&Block128::ONE, &Block128::ZERO),
            sponge.hash_pair(&Block128::ZERO, &Block128::ONE),
        ];
        let got = hash_pair_batch(&a, &b);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_hash_concatenation_batch_small_input() {
        let sponge = Poseidon2bSponge::new();
        let a = vec![[1u8; 32], [2u8; 32]];
        let b = vec![[3u8; 32], [4u8; 32]];
        let expected = vec![
            sponge.hash_concatenation(&a[0], &b[0]),
            sponge.hash_concatenation(&a[1], &b[1]),
        ];
        let got = hash_concatenation_batch(&a, &b);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_hash_concatenation_batch_interleaved_matches_scalar() {
        let mut rng = rand::thread_rng();
        let n = 256;
        let a: Vec<[u8; 32]> = (0..n).map(|_| rng.gen()).collect();
        let b: Vec<[u8; 32]> = (0..n).map(|_| rng.gen()).collect();

        let sponge = Poseidon2bSponge::new();
        let expected: Vec<[u8; 32]> = (0..n)
            .map(|i| sponge.hash_concatenation(&a[i], &b[i]))
            .collect();

        let mut interleaved = Vec::with_capacity(n * 2);
        for i in 0..n {
            interleaved.push(a[i]);
            interleaved.push(b[i]);
        }
        let got = hash_concatenation_batch_interleaved(&interleaved);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_hash_concatenation_batch_interleaved_small_input() {
        let sponge = Poseidon2bSponge::new();
        let interleaved = vec![[1u8; 32], [3u8; 32], [2u8; 32], [4u8; 32]];
        let expected = vec![
            sponge.hash_concatenation(&interleaved[0], &interleaved[1]),
            sponge.hash_concatenation(&interleaved[2], &interleaved[3]),
        ];
        let got = hash_concatenation_batch_interleaved(&interleaved);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_compress_batch_interleaved_with_tag_matches_scalar() {
        use crate::native::DomainTag;

        let mut rng = rand::thread_rng();
        let tag = DomainTag::new(b"BTCHTST_");
        let n = 257;
        let mut interleaved = Vec::with_capacity(n * 2);
        for _ in 0..(n * 2) {
            interleaved.push(rng.gen::<[u8; 32]>());
        }

        let mut got = vec![[0u8; 32]; n];
        compress_batch_interleaved_with_tag_into(tag, &interleaved, &mut got);
        let expected: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                crate::native::compress_with_tag(tag, &interleaved[2 * i], &interleaved[2 * i + 1])
            })
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn test_compress_flat_ff_batch_matches_scalar() {
        use crate::native::DomainTag;

        let mut rng = rand::thread_rng();
        let tag = DomainTag::new(b"FFTBTST_");
        // 257 exercises both the packed chunks and the scalar remainder.
        let n = 257;
        let mut interleaved = Vec::with_capacity(n * 2);
        for _ in 0..(n * 2) {
            interleaved.push(rng.gen::<[u8; 32]>());
        }

        let mut got = vec![[0u8; 32]; n];
        compress_flat_ff_batch_interleaved_with_tag_into(tag, &interleaved, &mut got);
        let expected: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                crate::native::compress_flat_feed_forward_with_tag(
                    tag,
                    &interleaved[2 * i],
                    &interleaved[2 * i + 1],
                )
            })
            .collect();
        assert_eq!(got, expected);
    }
}
