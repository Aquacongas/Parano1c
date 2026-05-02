// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid. All rights reserved.

//! Criterion micro-benchmarks for the performance-critical primitives.
//!
//! Every benchmark exercises the production-optimized code:
//!   - Packed field arithmetic (SIMD lanes)
//!   - Parallel sumcheck proving
//!   - Parallel NTT
//!   - Parallel Merkle tree construction
//!   - End-to-end FRI commit + prove (parallel NTT + parallel Merkle + packed MLE)
//!   - Compression primitives (compress vs. sponge hash_concatenation)
//!   - UTXO primitives (CRYPTO.md §4)
//!
//! When to use this vs. other benches:
//!   - `release_report`  — one-shot overview across every layer with a
//!     branded table. Start here for a first look.
//!   - `bench_prover`    — (this bench) criterion statistical runner for
//!     micro-benchmarks; use to compare two commits
//!     of the same primitive with confidence
//!     intervals and HTML reports.
//!   - `air_bench`       — focused AIR / STARK / IVC sweeps.
//!   - `binius_packing`  — focused Binius packing breakdown.
//!
//! Run:  cargo bench --bench bench_prover

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use noid_core::ntt::forward_ntt_parallel;
use noid_core::packed::PackedBlock128;
use noid_core::sumcheck::prove::prove_single_packed;
use noid_core::{AdditiveNTT, Block128, TowerField};

use noid_fri::channel::Channel;
use noid_fri::code::LOG_RATE;
use noid_fri::merkle::MerkleTree;
use noid_fri::prover::{commit, prove};

use noid_poseidon2b::native::compression::Poseidon2bSponge;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

// ---------------------------------------------------------------------------
// Field Arithmetic (Packed ONLY)
// ---------------------------------------------------------------------------

fn bench_field_arithmetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_arithmetic_packed");

    let a = Block128::from(0xDEADBEEFCAFE1234u128);
    let b = Block128::from(0x1337133713371337u128);

    let pa = PackedBlock128::broadcast(a);
    let pb = PackedBlock128::broadcast(b);

    group.bench_function("packed128_mul", |bencher| {
        bencher.iter(|| black_box(pa).packed_mul(black_box(pb)));
    });

    group.bench_function("packed128_square", |bencher| {
        bencher.iter(|| black_box(pa).square());
    });

    group.bench_function("packed128_xor", |bencher| {
        bencher.iter(|| black_box(pa).xor(black_box(pb)));
    });

    group.bench_function("packed128_scalar_mul", |bencher| {
        bencher.iter(|| black_box(pa).scalar_mul(black_box(b)));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Sumcheck (Packed + Parallel ONLY)
// ---------------------------------------------------------------------------

fn bench_sumcheck(c: &mut Criterion) {
    let mut group = c.benchmark_group("sumcheck_packed");
    group.sample_size(10);

    for log_size in [16, 20] {
        let n = 1usize << log_size;
        let poly: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128)).collect();
        let claimed_sum = poly.iter().fold(Block128::ZERO, |acc, &x| acc + x);

        group.bench_with_input(
            BenchmarkId::new("prove_packed", log_size),
            &log_size,
            |bencher, _| {
                bencher.iter(|| {
                    let mut transcript = Vec::new();
                    prove_single_packed(&poly, claimed_sum, &mut transcript)
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// NTT (Parallel ONLY)
// ---------------------------------------------------------------------------

fn bench_ntt(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_parallel");
    group.sample_size(10);

    for log_size in [16, 20] {
        let n = 1usize << log_size;
        let data: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128)).collect();
        let basis: Vec<Block128> = (0..log_size).map(|i| Block128::from(1u128 << i)).collect();

        group.bench_with_input(
            BenchmarkId::new("forward_ntt_parallel", log_size),
            &log_size,
            |bencher, _| {
                bencher.iter(|| forward_ntt_parallel(&data, &basis));
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Merkle Tree (Parallel ONLY)
// ---------------------------------------------------------------------------

fn bench_merkle(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_parallel");
    group.sample_size(10);

    let hasher = Poseidon2bSponge::new();

    for log_size in [12, 16] {
        let n = 1usize << log_size;
        let leaves: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                let mut buf = [0u8; 32];
                let i_bytes = i.to_le_bytes();
                buf[0..i_bytes.len()].copy_from_slice(&i_bytes);
                buf[16..16 + i_bytes.len()].copy_from_slice(&i_bytes);
                buf
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("build_parallel", log_size),
            &log_size,
            |bencher, _| {
                bencher.iter_batched(
                    || leaves.clone(),
                    |leaves| MerkleTree::new_parallel(leaves, &hasher),
                    criterion::BatchSize::LargeInput,
                );
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Compression primitives (2-to-1 compress vs sponge hash_concatenation)
// ---------------------------------------------------------------------------

fn bench_compress(c: &mut Criterion) {
    use noid_poseidon2b::batch::{
        compress_batch_interleaved_into, hash_concatenation_batch_interleaved_into,
    };

    let mut group = c.benchmark_group("compress_vs_hash_concat");
    group.sample_size(10);

    for log_n in [12usize, 14, 16] {
        let n = 1usize << log_n;
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let pairs: Vec<[u8; 32]> = (0..n * 2).map(|_| rng.gen()).collect();
        let mut out = vec![[0u8; 32]; n];

        group.bench_with_input(
            BenchmarkId::new("compress_batch", log_n),
            &log_n,
            |bencher, _| {
                bencher.iter(|| {
                    compress_batch_interleaved_into(black_box(&pairs), black_box(&mut out));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("hash_concat_batch", log_n),
            &log_n,
            |bencher, _| {
                bencher.iter(|| {
                    hash_concatenation_batch_interleaved_into(
                        black_box(&pairs),
                        black_box(&mut out),
                    );
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// UTXO primitives (CRYPTO.md §4)
// ---------------------------------------------------------------------------

fn bench_utxo_primitives(c: &mut Criterion) {
    use noid_poseidon2b::primitives::{
        derive_address, hash_auth_tag, hash_tx_body, hash_utxo_leaf, Commitment, SpendSecret,
    };

    let mut group = c.benchmark_group("utxo_primitives");
    group.sample_size(20);

    let mut rng = StdRng::seed_from_u64(0x0000_7E57_AB1E_7E57);
    let spend = SpendSecret(rng.gen());
    let addr = derive_address(&spend);
    let commitment = hash_utxo_leaf(1_000, &addr);

    group.bench_function("derive_address", |b| {
        b.iter(|| derive_address(black_box(&spend)))
    });
    group.bench_function("hash_utxo_leaf", |b| {
        b.iter(|| hash_utxo_leaf(black_box(1_000), black_box(&addr)))
    });

    let prev = [0u8; 32];
    let body_small = hash_tx_body(&prev, 5, &[commitment], &[commitment]);
    group.bench_function("hash_auth_tag", |b| {
        b.iter(|| hash_auth_tag(black_box(&spend), black_box(&body_small)))
    });

    // Larger sizes (128, 512) run into the hundreds of ms per iter; drop
    // the sample count for the whole group so wall time stays bounded.
    group.sample_size(10);
    for &n_io in &[2usize, 8, 32, 128, 512] {
        let ins: Vec<Commitment> = (0..n_io).map(|_| commitment).collect();
        let outs: Vec<Commitment> = (0..n_io).map(|_| commitment).collect();
        group.bench_with_input(BenchmarkId::new("hash_tx_body", n_io), &n_io, |b, _| {
            b.iter(|| {
                hash_tx_body(
                    black_box(&prev),
                    black_box(5),
                    black_box(&ins),
                    black_box(&outs),
                )
            })
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// End to End (Fully optimized FRI)
// ---------------------------------------------------------------------------

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end_optimized");
    group.sample_size(50);

    let log_len = 16usize;
    let n = 1usize << log_len;
    let mut rng = StdRng::seed_from_u64(0xBEAD_C0DE_DEAD_BEEF);
    let evals: Vec<Block128> = (0..n).map(|_| Block128::from(rng.gen::<u128>())).collect();
    let eval_point: Vec<Block128> = (0..log_len)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();

    let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    group.bench_function("fri_commit_and_prove_optimized", |bencher| {
        bencher.iter(|| {
            let (commitment, _tree, _code) = commit(&evals, &ntt, &hasher);
            let mut prover_channel = Channel::new();
            prover_channel.observe_fri_commitment(&commitment);
            let _proof = prove(
                &evals,
                &eval_point,
                &ntt,
                &mut prover_channel,
                &hasher,
            );
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_field_arithmetic,
    bench_sumcheck,
    bench_ntt,
    bench_merkle,
    bench_compress,
    bench_utxo_primitives,
    bench_end_to_end,
);
criterion_main!(benches);
