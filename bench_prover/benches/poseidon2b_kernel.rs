// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Poseidon2b permutation-kernel microbench — the P6 gate.
//!
//! The m=24 link prove is hash-bound (commit + open ≈ 96% of prove time),
//! and every hash rides one of two kernels:
//!   - `permute_flat_u128` — the sequential scalar permutation (transcript
//!     duplex chains, FS challengers);
//!   - `packed_poseidon2b_permute_flat` — the PACKED_LANES-wide batch
//!     permutation behind the PCS Merkle leaf sponges and the
//!     feed-forward compress layers.
//!
//! Reports single-threaded ns/permutation and derived M perms/s for both,
//! plus the two production batch entry points (leaf sponge at the PCS leaf
//! width, feed-forward compress) in hashes/s. Run before/after any kernel
//! change; the P6 acceptance is the packed-path factor.

use std::hint::black_box;
use std::time::Instant;

use noid_poseidon2b::batch::{
    compress_flat_ff_batch_interleaved_with_tag_into, leaf_sponge_flat_batch_with_iv_into,
    packed_poseidon2b_permute_flat, POSEIDON2B_BATCH_LANES,
};
use noid_poseidon2b::native::domain::{capacity_iv_flat, DomainTag};
use noid_poseidon2b::native::permutation::{permute_flat_u128, STATE_SIZE};
use noid_core::packed::PackedBlock128;
use noid_core::Block128;

fn splitmix(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn rand_u128(s: &mut u64) -> u128 {
    ((splitmix(s) as u128) << 64) | splitmix(s) as u128
}

fn main() {
    let mut seed = 0xC0FFEE_u64;

    // --- scalar permute_flat_u128: chained (latency-bound, the transcript
    // shape) ---
    let mut state = [rand_u128(&mut seed); STATE_SIZE];
    let n = 200_000u32;
    // Warmup.
    for _ in 0..20_000 {
        permute_flat_u128(&mut state);
    }
    let t = Instant::now();
    for _ in 0..n {
        permute_flat_u128(&mut state);
    }
    let dt = t.elapsed();
    black_box(state);
    let ns = dt.as_nanos() as f64 / n as f64;
    println!(
        "scalar  permute_flat_u128 (chained):   {:8.1} ns/perm  ({:.2} M perms/s)",
        ns,
        1e3 / ns
    );

    // --- packed permutation: chained packed states (the batch kernels run
    // long dependent chains per lane group) ---
    let mut pstates: [PackedBlock128; STATE_SIZE] = std::array::from_fn(|_| {
        PackedBlock128::from_array(std::array::from_fn(|_| Block128::from(rand_u128(&mut seed))))
    });
    for _ in 0..20_000 {
        packed_poseidon2b_permute_flat(&mut pstates);
    }
    let t = Instant::now();
    for _ in 0..n {
        packed_poseidon2b_permute_flat(&mut pstates);
    }
    let dt = t.elapsed();
    black_box(pstates);
    let ns = dt.as_nanos() as f64 / n as f64;
    let lanes = POSEIDON2B_BATCH_LANES as f64;
    println!(
        "packed  permute_flat ({} lanes):        {:8.1} ns/call  ({:8.1} ns/perm, {:.2} M perms/s)",
        POSEIDON2B_BATCH_LANES,
        ns,
        ns / lanes,
        lanes * 1e3 / ns
    );

    // --- production batch entry points ---
    // Feed-forward compress: one permutation per hash; the Merkle inner
    // layers. 2^16 pairs per pass.
    let n_pairs = 1usize << 16;
    let tag = DomainTag::new(b"P6BENCH_");
    let mut pairs = vec![[0u8; 32]; 2 * n_pairs];
    for p in pairs.iter_mut() {
        let lo = rand_u128(&mut seed).to_le_bytes();
        let hi = rand_u128(&mut seed).to_le_bytes();
        p[..16].copy_from_slice(&lo);
        p[16..].copy_from_slice(&hi);
    }
    let mut out = vec![[0u8; 32]; n_pairs];
    compress_flat_ff_batch_interleaved_with_tag_into(tag, &pairs, &mut out); // warm
    let reps = 20u32;
    let t = Instant::now();
    for _ in 0..reps {
        compress_flat_ff_batch_interleaved_with_tag_into(tag, black_box(&pairs), &mut out);
    }
    let dt = t.elapsed();
    black_box(&out);
    let per = dt.as_nanos() as f64 / (reps as f64 * n_pairs as f64);
    println!(
        "batch   compress_flat_ff (2^16 pairs): {:8.1} ns/hash  ({:.2} M hashes/s)",
        per,
        1e3 / per
    );

    // Leaf sponge at a PCS-like leaf width: 512-byte leaves (16 rate blocks),
    // padded mode.
    let leaf_size = 512usize;
    let n_leaves = 1usize << 13;
    let mut data = vec![0u8; n_leaves * leaf_size];
    for chunk in data.chunks_exact_mut(8) {
        chunk.copy_from_slice(&splitmix(&mut seed).to_le_bytes());
    }
    let iv = capacity_iv_flat(tag);
    let mut lout = vec![[0u8; 32]; n_leaves];
    leaf_sponge_flat_batch_with_iv_into(iv, true, &data, leaf_size, &mut lout); // warm
    let t = Instant::now();
    for _ in 0..reps {
        leaf_sponge_flat_batch_with_iv_into(iv, true, black_box(&data), leaf_size, &mut lout);
    }
    let dt = t.elapsed();
    black_box(&lout);
    let per_leaf = dt.as_nanos() as f64 / (reps as f64 * n_leaves as f64);
    let perms_per_leaf = (leaf_size / 32 + 1) as f64;
    println!(
        "batch   leaf_sponge 512B (2^13 leaves): {:7.1} ns/leaf  ({:.1} ns/perm, {:.2} M perms/s)",
        per_leaf,
        per_leaf / perms_per_leaf,
        perms_per_leaf * 1e3 / per_leaf
    );
}
