// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Register-domain Poseidon2b permutation kernel for AVX2 + VPCLMULQDQ.
//!
//! The generic packed round loop bounces every intermediate through
//! `PackedBlock128`'s `[u128; 2]` representation, forcing constant
//! vector↔general-register transitions between the CLMUL multiplies and the
//! XOR gluing. This kernel instead keeps the whole 66-round schedule in
//! `__m256i` locals: states load once at the absorb boundary and store once
//! at the squeeze boundary. It also processes several INDEPENDENT state
//! groups per call — one permutation is a serial multiply chain, so a lone
//! group leaves the carry-less-multiply unit idle waiting on latency;
//! interleaved groups convert the batch kernels from latency-bound to
//! throughput-bound.
//!
//! Bit-identical to `native::permutation::permute_flat_u128` per lane.

#![cfg(all(target_arch = "x86_64", not(target_feature = "avx512f")))]

use core::arch::x86_64::*;

use crate::native::permutation::{F_ROUNDS, N_ROUNDS, P_ROUNDS, STATE_SIZE};
use noid_core::packed::clmul_avx2::{mul_gcm_x2, square_gcm_clmul_x2};
use noid_core::packed::PackedBlock128;

/// Flat-basis round constants / MDS entries, as produced by the batch
/// module's `FlatTables` (already tower→flat converted).
pub(crate) struct VecTables {
    pub rc: [[u128; N_ROUNDS]; STATE_SIZE],
    pub mds_full: [[u128; STATE_SIZE]; STATE_SIZE],
    pub mds_full_is_one: [[bool; STATE_SIZE]; STATE_SIZE],
    /// Diagonal of the partial-round matrix (its off-diagonal entries are
    /// all 1, checked at table build time).
    pub mds_partial_diag: [u128; STATE_SIZE],
}

#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
unsafe fn bcast(c: u128) -> __m256i {
    _mm256_broadcastsi128_si256(core::mem::transmute::<u128, __m128i>(c))
}

#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
unsafe fn sbox_x7(x: __m256i) -> __m256i {
    let x2 = square_gcm_clmul_x2(x);
    let x4 = square_gcm_clmul_x2(x2);
    let x6 = mul_gcm_x2(x, x2);
    mul_gcm_x2(x6, x4)
}

/// Full-round MDS: generic 4×4 with the is-one entries as bare XORs.
#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
unsafe fn mds_full(s: &mut [__m256i; STATE_SIZE], t: &VecTables) {
    let input = *s;
    for i in 0..STATE_SIZE {
        let mut acc = _mm256_setzero_si256();
        for j in 0..STATE_SIZE {
            if t.mds_full_is_one[i][j] {
                acc = _mm256_xor_si256(acc, input[j]);
            } else {
                acc = _mm256_xor_si256(acc, mul_gcm_x2(input[j], bcast(t.mds_full[i][j])));
            }
        }
        s[i] = acc;
    }
}

/// Partial-round MDS: diagonal entries `c_i`, all off-diagonals 1, so
/// `out_i = c_i·s_i + (S + s_i)` with `S` the XOR of the whole state —
/// 4 multiplies and one shared sum instead of a dense row pass.
#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
unsafe fn mds_partial(s: &mut [__m256i; STATE_SIZE], t: &VecTables) {
    let sum = _mm256_xor_si256(_mm256_xor_si256(s[0], s[1]), _mm256_xor_si256(s[2], s[3]));
    for i in 0..STATE_SIZE {
        let diag = mul_gcm_x2(s[i], bcast(t.mds_partial_diag[i]));
        s[i] = _mm256_xor_si256(diag, _mm256_xor_si256(sum, s[i]));
    }
}

/// The full Poseidon2b schedule over `G` independent state groups held in
/// `__m256i` registers (each group = PACKED_LANES independent permutations).
#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
unsafe fn permute_groups<const G: usize>(st: &mut [[__m256i; STATE_SIZE]; G], t: &VecTables) {
    for g in 0..G {
        mds_full(&mut st[g], t);
    }
    for r in 0..N_ROUNDS {
        let is_full = !((F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&r));
        if is_full {
            for g in 0..G {
                for i in 0..STATE_SIZE {
                    let x = _mm256_xor_si256(st[g][i], bcast(t.rc[i][r]));
                    st[g][i] = sbox_x7(x);
                }
            }
            for g in 0..G {
                mds_full(&mut st[g], t);
            }
        } else {
            let rc0 = bcast(t.rc[0][r]);
            for g in 0..G {
                st[g][0] = sbox_x7(_mm256_xor_si256(st[g][0], rc0));
            }
            for g in 0..G {
                mds_partial(&mut st[g], t);
            }
        }
    }
}

#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
unsafe fn load_group(s: &[PackedBlock128; STATE_SIZE]) -> [__m256i; STATE_SIZE] {
    std::array::from_fn(|i| _mm256_loadu_si256(&s[i] as *const PackedBlock128 as *const __m256i))
}

#[inline]
#[target_feature(enable = "avx2,vpclmulqdq")]
unsafe fn store_group(v: &[__m256i; STATE_SIZE], s: &mut [PackedBlock128; STATE_SIZE]) {
    for i in 0..STATE_SIZE {
        _mm256_storeu_si256(&mut s[i] as *mut PackedBlock128 as *mut __m256i, v[i]);
    }
}

/// Permute `states.len()` independent packed groups: G-wide register-domain
/// chunks first, then a single-group pass over the remainder.
///
/// # Safety
/// The CPU must support AVX2 and VPCLMULQDQ — callers gate on
/// `is_x86_feature_detected!` (or a statically-enabled build).
#[target_feature(enable = "avx2,vpclmulqdq")]
pub(crate) unsafe fn permute_flat_groups(
    states: &mut [[PackedBlock128; STATE_SIZE]],
    t: &VecTables,
) {
    /// Groups per register-domain chunk. 4 groups × 4 state words = 16 ymm
    /// values plus multiply temporaries: the working set spills a little,
    /// but the interleaving keeps the CLMUL port saturated, which measures
    /// faster than any narrower arrangement.
    const G: usize = 4;
    unsafe {
        let mut chunks = states.chunks_exact_mut(G);
        for chunk in &mut chunks {
            let mut regs: [[__m256i; STATE_SIZE]; G] =
                std::array::from_fn(|g| load_group(&chunk[g]));
            permute_groups(&mut regs, t);
            for g in 0..G {
                store_group(&regs[g], &mut chunk[g]);
            }
        }
        for s in chunks.into_remainder() {
            let mut regs = [load_group(s)];
            permute_groups(&mut regs, t);
            store_group(&regs[0], s);
        }
    }
}

/// Single-group register-domain permutation (the `packed_poseidon2b_permute_flat`
/// fast path).
///
/// # Safety
/// See [`permute_flat_groups`].
#[target_feature(enable = "avx2,vpclmulqdq")]
pub(crate) unsafe fn permute_flat_one(states: &mut [PackedBlock128; STATE_SIZE], t: &VecTables) {
    unsafe {
        let mut regs = [load_group(states)];
        permute_groups(&mut regs, t);
        store_group(&regs[0], states);
    }
}

/// One SCALAR permutation through the register-domain kernel: the state
/// rides the low 128-bit lane of each register; the high lane computes
/// garbage that never crosses lanes (every kernel op is per-128-bit-lane).
/// Still ~2.5× faster than the general-register scalar path — the CLMUL
/// products and the reduction stay in the vector domain.
///
/// # Safety
/// See [`permute_flat_groups`].
#[target_feature(enable = "avx2,vpclmulqdq")]
pub(crate) unsafe fn permute_flat_single_u128(flat: &mut [u128; STATE_SIZE], t: &VecTables) {
    unsafe {
        let mut regs: [[__m256i; STATE_SIZE]; 1] = [std::array::from_fn(|i| {
            _mm256_zextsi128_si256(_mm_loadu_si128(&flat[i] as *const u128 as *const __m128i))
        })];
        permute_groups(&mut regs, t);
        for i in 0..STATE_SIZE {
            _mm_storeu_si128(
                &mut flat[i] as *mut u128 as *mut __m128i,
                _mm256_castsi256_si128(regs[0][i]),
            );
        }
    }
}
