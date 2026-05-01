// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid. All rights reserved.

//! Binius-style packing benchmark — focused view of DA / bandwidth
//! savings with full proof-size accounting.
//!
//! Compares raw Block128 commits against bit- and byte-packed commits of
//! the *same logical witness*, and — unlike `release_report` — also
//! itemizes the actual serialized FRI eval-proof size per mode. Use this
//! when you want to verify that the 128x / 16x savings really do carry
//! through to the proof bytes, not just the committed payload.
//!
//! When to use this vs. other benches:
//!   - `release_report`  — one-shot overview; packing is one row in a
//!     multi-section report. Start here.
//!   - `binius_packing`  — (this bench) drill-down on packing overhead,
//!     including FRI proof-size deltas per mode.
//!   - `bench_prover`    — criterion micro-benchmarks of the primitives
//!     underneath packing (field ops, NTT, Merkle).
//!
//! Run:  cargo bench --bench binius_packing

use std::time::{Duration, Instant};

use noid_core::{AdditiveNTT, Block128};
use noid_fri::channel::Channel;
use noid_fri::code::LOG_RATE;
use noid_poseidon2b::native::compression::Poseidon2bSponge;

use noid_binius::{pack_bits, pack_bytes, PackedCommit};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const WARMUP: usize = 1;
const SAMPLES: usize = 3;

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn time<F: FnMut()>(mut f: F) -> Duration {
    for _ in 0..WARMUP {
        f();
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t = Instant::now();
        f();
        samples.push(t.elapsed());
    }
    median(samples)
}

fn fmt_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1_000.0;
    if ms >= 1.0 {
        format!("{:>8.2} ms", ms)
    } else {
        format!("{:>8.2} us", ms * 1_000.0)
    }
}

fn fmt_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:>8.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:>8.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:>8} B ", bytes)
    }
}

fn main() {
    println!();
    println!("  BINIUS-STYLE PACKING  --  DA / bandwidth savings");
    println!();
    println!("  Committing the *same logical witness* three ways:");
    println!("    1. raw   : one Block128 per cell (the status quo)");
    println!("    2. bytes : 16 GF(2^8) cells packed per Block128");
    println!("    3. bits  : 128 GF(2)  cells packed per Block128");
    println!();
    println!("  Size columns are the committed vector payload only — the");
    println!("  FRI commitment root + opening proof are unchanged.");
    println!();

    let mut rng = StdRng::seed_from_u64(0xB1_B1_05_1A);

    // Logical witness length (cells). We pick one that produces at least 128
    // packed Block128 words in the bit case so FRI is comfortable.
    // 2^20 cells -> 1M cells -> bit-packed = 8192 words, byte-packed = 65536, raw = 1048576.
    let log_cells = 20;
    let n_cells = 1usize << log_cells;

    let bits: Vec<u8> = (0..n_cells).map(|_| rng.gen::<bool>() as u8).collect();
    let bytes: Vec<u8> = (0..n_cells).map(|_| rng.gen::<u8>()).collect();
    let blocks: Vec<Block128> = (0..n_cells)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();

    let bits_packed = pack_bits(&bits);
    let bytes_packed = pack_bytes(&bytes);

    let log_bits = bits_packed.len().trailing_zeros() as usize;
    let log_bytes = bytes_packed.len().trailing_zeros() as usize;
    let log_raw = blocks.len().trailing_zeros() as usize;

    let hasher = Poseidon2bSponge::new();
    let ntt_raw = AdditiveNTT::<Block128>::new(log_raw + LOG_RATE);
    let ntt_bytes = AdditiveNTT::<Block128>::new(log_bytes + LOG_RATE);
    let ntt_bits = AdditiveNTT::<Block128>::new(log_bits + LOG_RATE);

    println!(
        "  +{:-<90}+",
        ""
    );
    println!(
        "  | {:<10} | {:>10} | {:>12} | {:>10} | {:>12} | {:>12} | {:>10} |",
        "mode", "log_packed", "payload", "shrink", "commit", "open", "proof(KB)"
    );
    println!(
        "  +{:-<90}+",
        ""
    );

    // --- RAW ---
    let commit_raw_t = time(|| {
        let _ = PackedCommit::commit_raw(blocks.clone(), &ntt_raw, &hasher);
    });
    let committed = PackedCommit::commit_raw(blocks.clone(), &ntt_raw, &hasher);
    let point_raw: Vec<Block128> = (0..log_raw)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();
    let open_raw_t = time(|| {
        let mut ch = Channel::new();
        let _ = committed.open(&point_raw, &ntt_raw, &mut ch, &hasher);
    });
    let mut ch = Channel::new();
    let proof_raw = committed.open(&point_raw, &ntt_raw, &mut ch, &hasher);
    let proof_raw_bytes = proof_raw.final_codeword.len() * 16
        + proof_raw.sum_check_oracles.iter().map(|u| u.coeffs.len() * 16).sum::<usize>()
        + proof_raw.fri_oracles.len() * 40
        + proof_raw.upper_partial_evals.len() * 16
        + proof_raw.fri_queried_symbols.iter().map(|r| r.len() * 32).sum::<usize>()
        + proof_raw.fri_merkle_paths.iter().map(|r| r.iter().map(|p| p.len() * 32).sum::<usize>()).sum::<usize>();

    println!(
        "  | {:<10} | {:>10} | {:>12} | {:>10} | {:>12} | {:>12} | {:>10.1} |",
        "raw 128-b",
        log_raw,
        fmt_size(committed.serialized_size()),
        "1x",
        fmt_ms(commit_raw_t),
        fmt_ms(open_raw_t),
        proof_raw_bytes as f64 / 1024.0
    );

    // --- BYTES ---
    let commit_bytes_t = time(|| {
        let _ = PackedCommit::commit_bytes(bytes_packed.clone(), &ntt_bytes, &hasher);
    });
    let committed = PackedCommit::commit_bytes(bytes_packed.clone(), &ntt_bytes, &hasher);
    let point_b: Vec<Block128> = (0..log_bytes)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();
    let open_bytes_t = time(|| {
        let mut ch = Channel::new();
        let _ = committed.open(&point_b, &ntt_bytes, &mut ch, &hasher);
    });
    let mut ch = Channel::new();
    let proof_b = committed.open(&point_b, &ntt_bytes, &mut ch, &hasher);
    let proof_b_bytes = proof_b.final_codeword.len() * 16
        + proof_b.sum_check_oracles.iter().map(|u| u.coeffs.len() * 16).sum::<usize>()
        + proof_b.fri_oracles.len() * 40
        + proof_b.upper_partial_evals.len() * 16
        + proof_b.fri_queried_symbols.iter().map(|r| r.len() * 32).sum::<usize>()
        + proof_b.fri_merkle_paths.iter().map(|r| r.iter().map(|p| p.len() * 32).sum::<usize>()).sum::<usize>();

    println!(
        "  | {:<10} | {:>10} | {:>12} | {:>10} | {:>12} | {:>12} | {:>10.1} |",
        "bytes x16",
        log_bytes,
        fmt_size(committed.serialized_size()),
        "16x",
        fmt_ms(commit_bytes_t),
        fmt_ms(open_bytes_t),
        proof_b_bytes as f64 / 1024.0
    );

    // --- BITS ---
    let commit_bits_t = time(|| {
        let _ = PackedCommit::commit_bits(bits_packed.clone(), &ntt_bits, &hasher);
    });
    let committed = PackedCommit::commit_bits(bits_packed.clone(), &ntt_bits, &hasher);
    let point_bi: Vec<Block128> = (0..log_bits)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();
    let open_bits_t = time(|| {
        let mut ch = Channel::new();
        let _ = committed.open(&point_bi, &ntt_bits, &mut ch, &hasher);
    });
    let mut ch = Channel::new();
    let proof_bi = committed.open(&point_bi, &ntt_bits, &mut ch, &hasher);
    let proof_bi_bytes = proof_bi.final_codeword.len() * 16
        + proof_bi.sum_check_oracles.iter().map(|u| u.coeffs.len() * 16).sum::<usize>()
        + proof_bi.fri_oracles.len() * 40
        + proof_bi.upper_partial_evals.len() * 16
        + proof_bi.fri_queried_symbols.iter().map(|r| r.len() * 32).sum::<usize>()
        + proof_bi.fri_merkle_paths.iter().map(|r| r.iter().map(|p| p.len() * 32).sum::<usize>()).sum::<usize>();

    println!(
        "  | {:<10} | {:>10} | {:>12} | {:>10} | {:>12} | {:>12} | {:>10.1} |",
        "bits  x128",
        log_bits,
        fmt_size(committed.serialized_size()),
        "128x",
        fmt_ms(commit_bits_t),
        fmt_ms(open_bits_t),
        proof_bi_bytes as f64 / 1024.0
    );

    println!(
        "  +{:-<90}+",
        ""
    );
    println!();
    println!("  notes:");
    println!("    * 'payload' is the committed vector on the wire (DA cost).");
    println!("    * 'shrink' is vs. the raw Block128-per-cell baseline.");
    println!("    * commit / open / proof are on the *packed* vector;");
    println!("      smaller packed vector => smaller everything.");
    println!();
}
