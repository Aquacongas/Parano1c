// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid. All rights reserved.

//! Paranoid release report — one branded, screenshot-ready dump of every
//! number a reviewer, an integrator, or a competing team is likely to ask
//! about. If you only run one benchmark in this repo, run this one.
//!
//!   cargo bench --bench release_report
//!
//! What this prints, in order:
//!
//!   1. Environment block (arch, SIMD tier, threads, build profile).
//!   2. Protocol parameters (field, hash, FRI rate / queries / TAU, NTT).
//!   3. FRI prover scaling table across `log_n ∈ {14, 16, 18, 20}`:
//!      NTT, Merkle, commit, prove, verify, proof size.
//!   4. Sumcheck + prove-throughput summary (cells/s).
//!   5. Binius packing table: same logical witness committed raw
//!      (1x / 128-bit cells), byte-packed (16x), bit-packed (128x) — the
//!      DA / bandwidth headline.
//!   6. STARK end-to-end table on `LinearCombinationAir`: real AIR
//!      commit + zero-check sumcheck + per-column FRI opening.
//!   7. DA witness-root throughput: Poseidon2b over the packed DA blob
//!      (this is what every full node recomputes against the block header).
//!   8. IVC fold / decide numbers on a realistic column batch.
//!
//! Every data point is a wall-clock median over a small number of samples.
//! `prove`/`verify` timings exclude compile-time constants and are
//! end-to-end; no pre-computation is hoisted out.
//!
//! Companion benches (use these for deeper dives, not first-look numbers):
//!   - `cargo bench --bench bench_prover`    — criterion micro-benchmarks
//!     (packed-field ops, NTT, Merkle, UTXO primitives).
//!   - `cargo bench --bench air_bench`       — focused AIR/STARK/IVC perf.
//!   - `cargo bench --bench binius_packing`  — focused packing-savings
//!     breakdown with proof-size deltas.

use std::time::{Duration, Instant};

use noid_core::ntt::forward_ntt_parallel;
use noid_core::packed::PACKED_LANES;
use noid_core::sumcheck::prove::prove_single_packed;
use noid_core::{AdditiveNTT, Block128, TowerField};

use noid_fri::channel::Channel;
use noid_fri::code::{LOG_RATE, RATE};
use noid_fri::hasher::Blake3Hasher;
use noid_fri::merkle::{compute_leaf_hashes, MerkleTree};
use noid_fri::prover::{commit, prove};
use noid_fri::verifier::verify;
use noid_fri::{NUM_QUERIES, TAU};

use noid_air::{ColumnDomain, LinearCombinationAir, Trace};
use noid_binius::{pack_bits, pack_bytes, PackedCommit};
use noid_chain::{packed_witness_root, trace_witness_root};
use noid_ivc::{decide, fold_step_prove, Accumulator};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::{padded_log_len, prove_air, verify_air};
use noid_tx::PublicInputs;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Trace sizes (log2) shown in the main FRI scaling table.
const LOG_TRACES: &[usize] = &[14, 16, 18, 20];

/// STARK table sweeps. `(log_rows, n_cols)`.
const STARK_SHAPES: &[(usize, usize)] = &[(10, 3), (12, 3), (14, 3), (14, 6)];

/// IVC sweep. `(log_rows, steps)`.
const IVC_SHAPES: &[(usize, usize)] = &[(10, 8), (12, 16), (14, 16)];

/// `log_cells` used for the Binius packing table. One value keeps the
/// table compact; anyone who wants a sweep runs `binius_packing`.
const PACKING_LOG_CELLS: usize = 20;

/// Warmup + sample counts for each data point.
const WARMUP: usize = 1;
const SAMPLES: usize = 3;

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------

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
    if ms >= 1_000.0 {
        format!("{:>9.2} s ", ms / 1_000.0)
    } else if ms >= 1.0 {
        format!("{:>9.2} ms", ms)
    } else {
        format!("{:>9.2} us", ms * 1_000.0)
    }
}

fn fmt_kb(bytes: usize) -> String {
    let kb = bytes as f64 / 1024.0;
    if kb >= 1024.0 {
        format!("{:>8.2} MB", kb / 1024.0)
    } else {
        format!("{:>8.2} KB", kb)
    }
}

fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:>9.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:>9.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:>9} B ", bytes)
    }
}

fn fmt_count(n: usize) -> String {
    const KI: f64 = 1024.0;
    const MI: f64 = 1024.0 * 1024.0;
    let nf = n as f64;
    if nf >= MI {
        format!("{:.0}M", nf / MI)
    } else if nf >= KI {
        format!("{:.0}K", nf / KI)
    } else {
        format!("{}", n)
    }
}

fn fmt_bytes_per_s(bytes_per_s: f64) -> String {
    const KI: f64 = 1024.0;
    const MI: f64 = 1024.0 * 1024.0;
    const GI: f64 = 1024.0 * 1024.0 * 1024.0;
    if bytes_per_s >= GI {
        format!("{:>8.2} GiB/s", bytes_per_s / GI)
    } else if bytes_per_s >= MI {
        format!("{:>8.2} MiB/s", bytes_per_s / MI)
    } else if bytes_per_s >= KI {
        format!("{:>8.2} KiB/s", bytes_per_s / KI)
    } else {
        format!("{:>8.2}  B/s ", bytes_per_s)
    }
}

// ---------------------------------------------------------------------------
// Environment detection
// ---------------------------------------------------------------------------

fn detect_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    }
}

fn detect_simd() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512f") {
            return "AVX-512";
        }
        if is_x86_feature_detected!("avx2") {
            return "AVX2";
        }
        if is_x86_feature_detected!("pclmulqdq") {
            return "SSE+CLMUL";
        }
        "scalar"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "NEON+PMULL"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "scalar"
    }
}

// ---------------------------------------------------------------------------
// Proof-size estimator (FRI eval proof)
// ---------------------------------------------------------------------------

fn estimate_proof_bytes(log_len: usize) -> usize {
    let tau = TAU.min(log_len);
    let n_rounds = log_len.saturating_sub(tau);

    let upper = (1usize << tau) * 16;
    let sum_check = n_rounds * 3 * 16;
    let fri_roots = n_rounds * 32;
    let queried = n_rounds * NUM_QUERIES * 2 * 16;

    let mut paths = 0usize;
    for r in 0..n_rounds {
        let depth = (log_len + LOG_RATE).saturating_sub(1 + r);
        paths += NUM_QUERIES * depth * 32;
    }

    let final_cw = RATE * 16;
    upper + sum_check + fri_roots + queried + paths + final_cw
}

// ---------------------------------------------------------------------------
// FRI prover scaling row
// ---------------------------------------------------------------------------

struct FriRow {
    log_len: usize,
    ntt_ms: Duration,
    merkle_ms: Duration,
    commit_ms: Duration,
    prove_ms: Duration,
    verify_ms: Duration,
    sumcheck_ms: Duration,
    proof_bytes: usize,
    throughput_cells_per_s: f64,
}

fn bench_fri_row(log_len: usize, hasher: &Blake3Hasher) -> FriRow {
    let n = 1usize << log_len;
    let mut rng = StdRng::seed_from_u64(0xBEAD_C0DE_DEAD_BEEF ^ log_len as u64);

    let evals: Vec<Block128> = (0..n).map(|_| Block128::from(rng.gen::<u128>())).collect();
    let eval_point: Vec<Block128> = (0..log_len)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();

    let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);
    let code_len = n * RATE;
    let mut expanded: Vec<Block128> = Vec::with_capacity(code_len);
    expanded.extend_from_slice(&evals);
    expanded.resize(code_len, Block128::ZERO);
    let expanded_basis: Vec<Block128> = (0..log_len + LOG_RATE)
        .map(|i| Block128::from(1u128 << i))
        .collect();
    let ntt_ms = time(|| {
        let _ = forward_ntt_parallel(&expanded, &expanded_basis);
    });

    let leaves_raw: Vec<Block128> = (0..code_len)
        .map(|i| Block128::from((i as u128).wrapping_mul(0x9E3779B97F4A7C15)))
        .collect();
    let merkle_ms = time(|| {
        let leaf_hashes = compute_leaf_hashes(&leaves_raw, hasher);
        let _ = MerkleTree::new_parallel(leaf_hashes, hasher);
    });

    let sumcheck_poly: Vec<Block128> = evals.clone();
    let claimed_sum = sumcheck_poly.iter().fold(Block128::ZERO, |a, b| a + *b);
    let sumcheck_ms = time(|| {
        let mut t = Vec::new();
        prove_single_packed(&sumcheck_poly, claimed_sum, &mut t);
    });

    let commit_ms = time(|| {
        let _ = commit(&evals, &ntt, hasher);
    });
    let (commitment, _tree, _code) = commit(&evals, &ntt, hasher);

    let prove_ms = time(|| {
        let mut ch = Channel::new();
        let _ = prove(&commitment, &evals, &eval_point, &ntt, &mut ch, hasher);
    });
    let mut ch = Channel::new();
    let proof = prove(&commitment, &evals, &eval_point, &ntt, &mut ch, hasher);

    let claimed_eval = noid_core::mle::evaluate::evaluate_slice(&evals, &eval_point);
    let verify_ms = time(|| {
        let mut ch = Channel::new();
        let _ = verify(
            &commitment,
            &eval_point,
            claimed_eval,
            proof.clone(),
            &ntt,
            &mut ch,
            hasher,
        );
    });

    let proof_bytes = estimate_proof_bytes(log_len);
    let throughput = n as f64 / prove_ms.as_secs_f64();

    FriRow {
        log_len,
        ntt_ms,
        merkle_ms,
        commit_ms,
        prove_ms,
        verify_ms,
        sumcheck_ms,
        proof_bytes,
        throughput_cells_per_s: throughput,
    }
}

// ---------------------------------------------------------------------------
// Binius packing row
// ---------------------------------------------------------------------------

struct PackRow {
    label: &'static str,
    log_packed: usize,
    packed_bytes: usize,
    shrink: &'static str,
    commit_ms: Duration,
    open_ms: Duration,
}

fn bench_packing_rows(log_cells: usize, hasher: &Blake3Hasher) -> Vec<PackRow> {
    let n_cells = 1usize << log_cells;
    let mut rng = StdRng::seed_from_u64(0xB1_B1_05_1A);

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

    let ntt_raw = AdditiveNTT::<Block128>::new(log_raw + LOG_RATE);
    let ntt_bytes = AdditiveNTT::<Block128>::new(log_bytes + LOG_RATE);
    let ntt_bits = AdditiveNTT::<Block128>::new(log_bits + LOG_RATE);

    let mut out = Vec::with_capacity(3);

    // raw
    let commit_raw_t = time(|| {
        let _ = PackedCommit::commit_raw(blocks.clone(), &ntt_raw, hasher);
    });
    let committed = PackedCommit::commit_raw(blocks.clone(), &ntt_raw, hasher);
    let point: Vec<Block128> = (0..log_raw)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();
    let open_raw_t = time(|| {
        let mut ch = Channel::new();
        let _ = committed.open(&point, &ntt_raw, &mut ch, hasher);
    });
    out.push(PackRow {
        label: "raw  1x (Block128)",
        log_packed: log_raw,
        packed_bytes: committed.serialized_size(),
        shrink: "1x",
        commit_ms: commit_raw_t,
        open_ms: open_raw_t,
    });

    // bytes
    let commit_bytes_t = time(|| {
        let _ = PackedCommit::commit_bytes(bytes_packed.clone(), &ntt_bytes, hasher);
    });
    let committed = PackedCommit::commit_bytes(bytes_packed.clone(), &ntt_bytes, hasher);
    let point: Vec<Block128> = (0..log_bytes)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();
    let open_bytes_t = time(|| {
        let mut ch = Channel::new();
        let _ = committed.open(&point, &ntt_bytes, &mut ch, hasher);
    });
    out.push(PackRow {
        label: "bytes 16x (GF(2^8))",
        log_packed: log_bytes,
        packed_bytes: committed.serialized_size(),
        shrink: "16x",
        commit_ms: commit_bytes_t,
        open_ms: open_bytes_t,
    });

    // bits
    let commit_bits_t = time(|| {
        let _ = PackedCommit::commit_bits(bits_packed.clone(), &ntt_bits, hasher);
    });
    let committed = PackedCommit::commit_bits(bits_packed.clone(), &ntt_bits, hasher);
    let point: Vec<Block128> = (0..log_bits)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();
    let open_bits_t = time(|| {
        let mut ch = Channel::new();
        let _ = committed.open(&point, &ntt_bits, &mut ch, hasher);
    });
    out.push(PackRow {
        label: "bits 128x (GF(2))",
        log_packed: log_bits,
        packed_bytes: committed.serialized_size(),
        shrink: "128x",
        commit_ms: commit_bits_t,
        open_ms: open_bits_t,
    });

    out
}

// ---------------------------------------------------------------------------
// STARK row (AIR + STARK wrapper, end-to-end)
// ---------------------------------------------------------------------------

struct StarkRow {
    log_rows: usize,
    n_cols: usize,
    prove_ms: Duration,
    verify_ms: Duration,
}

fn mk_pi() -> PublicInputs {
    PublicInputs {
        prev_state_root: [0x11; 32],
        new_state_root: [0x22; 32],
        nullifier_root: [0x33; 32],
        tx_body_hash: TxBodyHash([0x44; 32]),
        fee: 7,
    }
}

fn mk_linear_trace(log_rows: usize, n_cols: usize) -> Trace {
    let n = 1usize << log_rows;
    let mut cols: Vec<Vec<Block128>> = (0..n_cols - 1)
        .map(|c| {
            (0..n)
                .map(|i| Block128::from((i as u128).wrapping_mul(c as u128 + 1) ^ 0xABCD))
                .collect()
        })
        .collect();
    let mut last = vec![Block128::ZERO; n];
    for c in &cols {
        for i in 0..n {
            last[i] += c[i];
        }
    }
    cols.push(last);
    Trace::new(cols)
}

fn bench_stark_row(log_rows: usize, n_cols: usize) -> StarkRow {
    let air = LinearCombinationAir::new(n_cols, log_rows);
    let trace = mk_linear_trace(log_rows, n_cols);
    let pi = mk_pi();
    let prove_ms = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    let proof = prove_air(&air, &trace, &pi).unwrap();
    let verify_ms = time(|| {
        verify_air(&air, &pi, &proof).unwrap();
    });
    StarkRow {
        log_rows,
        n_cols,
        prove_ms,
        verify_ms,
    }
}

// ---------------------------------------------------------------------------
// DA witness-root row
// ---------------------------------------------------------------------------

struct DaRow {
    log_rows: usize,
    packed_bytes: usize,
    hash_ms: Duration,
    bytes_per_s: f64,
}

fn bench_witness_root(log_rows: usize) -> DaRow {
    use noid_chain::{pack_trace, PackedWitness};

    let n = 1usize << log_rows;
    let mut rng = StdRng::seed_from_u64(0xDAD0_DAD0_0000_0000 ^ log_rows as u64);

    // Realistic mixed trace: bits + bytes + raw.
    let bit_col: Vec<Block128> = (0..n)
        .map(|_| {
            if rng.gen::<bool>() {
                Block128::ONE
            } else {
                Block128::ZERO
            }
        })
        .collect();
    let byte_col: Vec<Block128> = (0..n)
        .map(|_| Block128::from(rng.gen::<u8>() as u128))
        .collect();
    let block_col: Vec<Block128> = (0..n)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();

    let trace = Trace::new_with_domains(
        vec![bit_col, byte_col, block_col],
        vec![ColumnDomain::Bit, ColumnDomain::Byte, ColumnDomain::Block128],
    );
    let pw: PackedWitness = pack_trace(&trace);
    let packed_bytes: usize = pw.columns.iter().map(|c| c.payload.len()).sum();

    let hash_ms = time(|| {
        let _ = packed_witness_root(&pw);
    });
    // Sanity: also time the convenience shortcut, but only use the primary
    // number for the table.
    let _ = trace_witness_root(&trace);

    let bytes_per_s = packed_bytes as f64 / hash_ms.as_secs_f64();
    DaRow {
        log_rows,
        packed_bytes,
        hash_ms,
        bytes_per_s,
    }
}

// ---------------------------------------------------------------------------
// IVC row
// ---------------------------------------------------------------------------

struct IvcRow {
    log_rows: usize,
    steps: usize,
    fold_ms: Duration,
    decide_ms: Duration,
}

fn bench_ivc_row(log_rows: usize, steps: usize) -> IvcRow {
    let log_len = padded_log_len(log_rows);
    let z: Vec<Block128> = (0..log_len)
        .map(|i| Block128::from(0xC0DEu128 << (i % 32)))
        .collect();
    let cols: Vec<Vec<Block128>> = (0..steps)
        .map(|s| {
            (0..1 << log_len)
                .map(|i| Block128::from((s as u128).wrapping_mul(i as u128 + 7)))
                .collect()
        })
        .collect();
    let fold_ms = time(|| {
        let mut acc = Accumulator::new(log_len, z.clone());
        for c in &cols {
            fold_step_prove(&mut acc, c);
        }
    });
    let mut acc = Accumulator::new(log_len, z);
    for c in &cols {
        fold_step_prove(&mut acc, c);
    }
    let decide_ms = time(|| {
        decide(&acc).unwrap();
    });
    IvcRow {
        log_rows,
        steps,
        fold_ms,
        decide_ms,
    }
}

// ---------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------

const BANNER: &str = r#"
   ____   _    ____      _    _   _  ___ ___ ____
  |  _ \ / \  |  _ \    / \  | \ | |/ _ \_ _|  _ \
  | |_) / _ \ | |_) |  / _ \ |  \| | | | | || | | |
  |  __/ ___ \|  _ <  / ___ \| |\  | |_| | || |_| |
  |_| /_/   \_\_| \_\/_/   \_\_| \_|\___/___|____/

  PARANOID  --  RELEASE REPORT
  FRI + Blake3 (merkle) + Poseidon2b (transcript) + Binius packing
"#;

fn print_banner() {
    println!("{}", BANNER);
    println!(
        "  Wall-clock medians over {} samples ({} warmup); single process, multi-threaded.",
        SAMPLES, WARMUP
    );
    println!();
}

fn print_environment() {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!("  +------------------------- ENVIRONMENT -------------------------+");
    println!("  | {:<18} {:<42} |", "arch:", detect_arch());
    println!("  | {:<18} {:<42} |", "simd:", detect_simd());
    println!("  | {:<18} {:<42} |", "os:", std::env::consts::OS);
    println!("  | {:<18} {:<42} |", "threads (rayon):", threads);
    println!(
        "  | {:<18} {:<42} |",
        "packed lanes:",
        PACKED_LANES.to_string()
    );
    println!(
        "  | {:<18} {:<42} |",
        "profile:",
        if cfg!(debug_assertions) {
            "debug (!)"
        } else {
            "release"
        }
    );
    println!("  +---------------------------------------------------------------+");
    println!();
}

fn print_params() {
    println!("  +------------------------- PARAMETERS --------------------------+");
    println!("  | {:<28} {:<32} |", "field:", "GF(2^128) binary tower");
    println!("  | {:<28} {:<32} |", "merkle hash:", "Blake3 (fast tier)");
    println!(
        "  | {:<28} {:<32} |",
        "transcript hash:", "Poseidon2b (t=4, recursion tier)"
    );
    println!("  | {:<28} {:<32} |", "PCS:", "FRI (DEEP-FRI style)");
    println!(
        "  | {:<28} {:<32} |",
        "code rate (RATE):",
        format!("{} (log2 = {})", RATE, LOG_RATE)
    );
    println!(
        "  | {:<28} {:<32} |",
        "num FRI queries:",
        NUM_QUERIES.to_string()
    );
    println!(
        "  | {:<28} {:<32} |",
        "TAU (batched vars):",
        TAU.to_string()
    );
    println!("  | {:<28} {:<32} |", "NTT:", "additive (Lin-Chung-Han)");
    println!(
        "  | {:<28} {:<32} |",
        "Binius packing:", "bit 128x / byte 16x / raw 1x"
    );
    println!("  +---------------------------------------------------------------+");
    println!();
}

fn print_fri_table(rows: &[FriRow]) {
    println!("  +-------------------------------------------- FRI PROVER (SINGLE COLUMN) ---------------------------------------+");
    println!(
        "  | {:>7} | {:>7} | {:>12} | {:>12} | {:>12} | {:>12} | {:>12} | {:>11} |",
        "log_n", "trace", "ntt", "merkle", "commit", "prove", "verify", "proof"
    );
    println!("  |---------+---------+--------------+--------------+--------------+--------------+--------------+-------------|");
    for r in rows {
        println!(
            "  | {:>7} | {:>7} | {:>12} | {:>12} | {:>12} | {:>12} | {:>12} | {:>11} |",
            r.log_len,
            fmt_count(1 << r.log_len),
            fmt_ms(r.ntt_ms),
            fmt_ms(r.merkle_ms),
            fmt_ms(r.commit_ms),
            fmt_ms(r.prove_ms),
            fmt_ms(r.verify_ms),
            fmt_kb(r.proof_bytes),
        );
    }
    println!("  +---------------------------------------------------------------------------------------------------------------+");
    println!();

    println!("  +------------------------- PROVER THROUGHPUT -------------------------+");
    println!(
        "  | {:>7} | {:>12} | {:>28} |",
        "log_n", "sumcheck", "prove throughput"
    );
    println!("  |---------+--------------+------------------------------|");
    for r in rows {
        let cells_s = r.throughput_cells_per_s;
        let label = if cells_s >= 1e6 {
            format!("{:>12.2} Mcells/s", cells_s / 1e6)
        } else {
            format!("{:>12.2} Kcells/s", cells_s / 1e3)
        };
        println!(
            "  | {:>7} | {:>12} | {:>28} |",
            r.log_len,
            fmt_ms(r.sumcheck_ms),
            label,
        );
    }
    println!("  +---------------------------------------------------------------------+");
    println!();
}

fn print_packing_table(log_cells: usize, rows: &[PackRow]) {
    println!(
        "  +--------------------- BINIUS PACKING  (log_cells = {:>2}) ---------------------+",
        log_cells
    );
    println!(
        "  | {:<20} | {:>8} | {:>11} | {:>7} | {:>12} | {:>12} |",
        "mode", "log_pkd", "payload", "shrink", "commit", "open"
    );
    println!("  |----------------------+----------+-------------+---------+--------------+--------------|");
    for r in rows {
        println!(
            "  | {:<20} | {:>8} | {:>11} | {:>7} | {:>12} | {:>12} |",
            r.label,
            r.log_packed,
            fmt_bytes(r.packed_bytes),
            r.shrink,
            fmt_ms(r.commit_ms),
            fmt_ms(r.open_ms),
        );
    }
    println!("  +-----------------------------------------------------------------------------+");
    println!();
}

fn print_stark_table(rows: &[StarkRow]) {
    println!("  +---------- STARK END-TO-END (LinearCombinationAir, zero-check) ----------+");
    println!(
        "  | {:>8} | {:>8} | {:>7} | {:>14} | {:>14} |",
        "log_rows", "rows", "n_cols", "prove", "verify"
    );
    println!("  |----------+----------+---------+----------------+----------------|");
    for r in rows {
        println!(
            "  | {:>8} | {:>8} | {:>7} | {:>14} | {:>14} |",
            r.log_rows,
            fmt_count(1 << r.log_rows),
            r.n_cols,
            fmt_ms(r.prove_ms),
            fmt_ms(r.verify_ms),
        );
    }
    println!("  +-------------------------------------------------------------------------+");
    println!();
}

fn print_da_table(rows: &[DaRow]) {
    println!("  +---------------- DA WITNESS-ROOT  (Blake3 over packed blob) -----------------+");
    println!(
        "  | {:>8} | {:>12} | {:>14} | {:>22} |",
        "log_rows", "packed blob", "hash", "throughput"
    );
    println!("  |----------+--------------+----------------+------------------------|");
    for r in rows {
        println!(
            "  | {:>8} | {:>12} | {:>14} | {:>22} |",
            r.log_rows,
            fmt_bytes(r.packed_bytes),
            fmt_ms(r.hash_ms),
            fmt_bytes_per_s(r.bytes_per_s),
        );
    }
    println!("  +-----------------------------------------------------------------------------+");
    println!();
}

fn print_ivc_table(rows: &[IvcRow]) {
    println!("  +------------------------------ IVC ------------------------------+");
    println!(
        "  | {:>8} | {:>6} | {:>14} | {:>14} |",
        "log_rows", "steps", "fold (total)", "decide"
    );
    println!("  |----------+--------+----------------+----------------|");
    for r in rows {
        println!(
            "  | {:>8} | {:>6} | {:>14} | {:>14} |",
            r.log_rows,
            r.steps,
            fmt_ms(r.fold_ms),
            fmt_ms(r.decide_ms),
        );
    }
    println!("  +-----------------------------------------------------------------+");
    println!();
}

fn print_footer() {
    println!("  column definitions:");
    println!("    trace   = 2^log_n multilinear evaluations committed (KiB/MiB, binary)");
    println!("    ntt     = parallel additive NTT over the rate-expanded domain (size n*RATE)");
    println!("    merkle  = leaf hashing + Blake3 Merkle tree build over RS-encoded leaves");
    println!("    commit  = full commit() = NTT + leaf hash + Merkle tree (end-to-end)");
    println!("    prove   = end-to-end evaluation proof (commit excluded)");
    println!("    verify  = end-to-end verification on the prover's proof");
    println!("    proof   = estimated serialized FRI eval-proof size");
    println!();
    println!("  notes:");
    println!("    * 'sumcheck' is a standalone micro-benchmark on a trace-sized");
    println!("      polynomial; the sumcheck embedded in `prove` runs on a");
    println!("      2^(log_n - TAU) polynomial and so is faster than the row above.");
    println!("    * Binius packing: 'payload' is the on-wire committed vector only");
    println!("      (DA cost). Commitment root + FRI proof sizes are unchanged.");
    println!("    * STARK uses the Block128-expanded trace; Binius packing affects");
    println!("      DA and the on-header witness_root, not proof soundness.");
    println!("    * DA witness-root throughput scales with the packed blob: bit");
    println!("      columns contribute 128x less bytes than raw.");
    println!();
    println!("  companion benches (deeper dives):");
    println!("    cargo bench --bench bench_prover    (criterion micro-benchmarks)");
    println!("    cargo bench --bench air_bench       (focused AIR + STARK + IVC)");
    println!("    cargo bench --bench binius_packing  (packing savings + proof sizes)");
    println!();
    println!("  reproduce: cargo bench --bench release_report");
    println!();
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

fn main() {
    print_banner();
    print_environment();
    print_params();

    let hasher = Blake3Hasher::new();

    eprintln!("  [1/5] FRI prover scaling ...");
    let mut fri_rows = Vec::with_capacity(LOG_TRACES.len());
    for &log_len in LOG_TRACES {
        eprintln!("        log_n = {} ...", log_len);
        fri_rows.push(bench_fri_row(log_len, &hasher));
    }

    eprintln!("  [2/5] Binius packing savings ...");
    let pack_rows = bench_packing_rows(PACKING_LOG_CELLS, &hasher);

    eprintln!("  [3/5] STARK end-to-end ...");
    let mut stark_rows = Vec::with_capacity(STARK_SHAPES.len());
    for &(lr, nc) in STARK_SHAPES {
        eprintln!("        log_rows = {}, n_cols = {} ...", lr, nc);
        stark_rows.push(bench_stark_row(lr, nc));
    }

    eprintln!("  [4/5] DA witness-root ...");
    let mut da_rows = Vec::with_capacity(3);
    for &lr in &[14usize, 16, 18] {
        eprintln!("        log_rows = {} ...", lr);
        da_rows.push(bench_witness_root(lr));
    }

    eprintln!("  [5/5] IVC fold / decide ...");
    let mut ivc_rows = Vec::with_capacity(IVC_SHAPES.len());
    for &(lr, s) in IVC_SHAPES {
        eprintln!("        log_rows = {}, steps = {} ...", lr, s);
        ivc_rows.push(bench_ivc_row(lr, s));
    }
    eprintln!();

    print_fri_table(&fri_rows);
    print_packing_table(PACKING_LOG_CELLS, &pack_rows);
    print_stark_table(&stark_rows);
    print_da_table(&da_rows);
    print_ivc_table(&ivc_rows);
    print_footer();
}
