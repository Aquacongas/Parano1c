// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Poseidon2b PoW mining benchmark.
//!
//!   cargo bench -p bench_prover --bench poseidon_pow_mining

use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use noid_chain::consensus::genesis::genesis_header;
use noid_chain::consensus::pow::{pow_header_fields, PowNonceBatchHasher};
use noid_core::packed::PACKED_LANES;
use rayon::prelude::*;

const DIGEST_BATCH: usize = 256;

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default)
}

fn fmt_rate(hashes: u64, elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64().max(1e-9);
    let hps = hashes as f64 / seconds;
    if hps >= 1_000_000.0 {
        format!("{:.2} MH/s", hps / 1_000_000.0)
    } else if hps >= 1_000.0 {
        format!("{:.2} KH/s", hps / 1_000.0)
    } else {
        format!("{hps:.2} H/s")
    }
}

fn expected_seconds(avg_attempts_pow2: u32, hps: f64) -> f64 {
    2f64.powi(avg_attempts_pow2 as i32) / hps.max(1.0)
}

fn xor_digest(lhs: &mut [u8; 32], rhs: [u8; 32]) {
    for (lhs, rhs) in lhs.iter_mut().zip(rhs) {
        *lhs ^= rhs;
    }
}

fn main() {
    let seq_attempts = env_u64("NOID_POSEIDON_POW_SEQ", 20_000);
    let par_attempts = env_u64("NOID_POSEIDON_POW_PAR", 200_000);

    let header = genesis_header();
    let seq_fields = pow_header_fields(&header);

    println!();
    println!("  =====================================================================");
    println!("  PARANOID Poseidon2b PoW Mining Benchmark");
    println!("  =====================================================================");
    println!("  Measures production H_POSEIDON_POW(header fields with patched nonce).");
    println!("  Override: NOID_POSEIDON_POW_SEQ=20000 NOID_POSEIDON_POW_PAR=200000");
    println!();

    let start = Instant::now();
    let mut sink = [0u8; 32];
    let mut seq_digests = [[0u8; 32]; DIGEST_BATCH];
    let mut seq_hasher = PowNonceBatchHasher::new(&seq_fields);
    let mut nonce = 0u64;
    while nonce < seq_attempts {
        let n = (seq_attempts - nonce).min(DIGEST_BATCH as u64) as usize;
        seq_hasher.hash_into(nonce as u128, &mut seq_digests[..n]);
        for digest in &seq_digests[..n] {
            xor_digest(&mut sink, *digest);
        }
        nonce += n as u64;
    }
    let seq_elapsed = start.elapsed();

    let fields = pow_header_fields(&header);
    let par_done = AtomicU64::new(0);
    let start = Instant::now();
    let threads = rayon::current_num_threads() as u64;
    let per_thread = par_attempts.div_ceil(threads);
    let par_sink = (0..rayon::current_num_threads())
        .into_par_iter()
        .map(|thread| {
            let local = fields;
            let mut hasher = PowNonceBatchHasher::new(&local);
            let mut local_sink = [0u8; 32];
            let start_nonce = thread as u64 * per_thread;
            let end_nonce = (start_nonce + per_thread).min(par_attempts);
            let mut nonce = start_nonce;
            let mut digests = [[0u8; 32]; DIGEST_BATCH];
            while nonce < end_nonce {
                let n = (end_nonce - nonce).min(DIGEST_BATCH as u64) as usize;
                hasher.hash_into(nonce as u128, &mut digests[..n]);
                for digest in &digests[..n] {
                    xor_digest(&mut local_sink, *digest);
                }
                par_done.fetch_add(n as u64, Ordering::Relaxed);
                nonce += n as u64;
            }
            local_sink
        })
        .reduce(
            || [0u8; 32],
            |mut acc, value| {
                xor_digest(&mut acc, value);
                acc
            },
        );
    let par_elapsed = start.elapsed();

    let par_hps = par_done.load(Ordering::Relaxed) as f64 / par_elapsed.as_secs_f64().max(1e-9);

    println!("  sequential attempts:      {seq_attempts}");
    println!(
        "  sequential time:          {:.3} s",
        seq_elapsed.as_secs_f64()
    );
    println!(
        "  sequential rate:          {}",
        fmt_rate(seq_attempts, seq_elapsed)
    );
    println!(
        "  parallel attempts:        {}",
        par_done.load(Ordering::Relaxed)
    );
    println!(
        "  parallel time:            {:.3} s",
        par_elapsed.as_secs_f64()
    );
    println!(
        "  parallel rate:            {}",
        fmt_rate(par_done.load(Ordering::Relaxed), par_elapsed)
    );
    println!(
        "  threads:                  {}",
        rayon::current_num_threads()
    );
    println!(
        "  CPU backend:              {}",
        noid_core::cpu::selected_backend()
    );
    println!("  logical packed lanes:     {PACKED_LANES}");
    println!(
        "  checksum:                 {}{}",
        hex::encode(sink),
        hex::encode(par_sink)
    );
    println!();
    println!("  Expected average solve time by target exponent:");
    for exponent in [237u32, 238, 239, 240, 241, 242] {
        let attempts_pow2 = 256 - exponent;
        println!(
            "    target 2^{exponent:<3} -> 2^{attempts_pow2:<2} attempts -> {:.2} s @ measured parallel",
            expected_seconds(attempts_pow2, par_hps)
        );
    }
    println!("  ---------------------------------------------------------------------");
    println!("  Reproduce: cargo bench -p bench_prover --bench poseidon_pow_mining");
    println!();
}
