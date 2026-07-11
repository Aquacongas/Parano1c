// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production PCS commit/open roofline for the B255 feasibility gate.
//!
//! Here `m` is the logical FieldR1cs domain: the committed witness contains
//! `2^m` F128 elements.  The PCS bit-domain parameter is therefore `m + 7`,
//! exactly as in `field_prover::prove_field`.
//!
//! The default deliberately runs only m22.  Run every roadmap domain in a
//! fresh process (so Linux `VmHWM` is attributable to one case):
//!
//! ```text
//! NOID_PCS_ROOFLINE_DOMAINS=22 cargo bench -p bench_prover --bench pcs_roofline
//! NOID_PCS_ROOFLINE_DOMAINS=23 cargo bench -p bench_prover --bench pcs_roofline
//! NOID_PCS_ROOFLINE_DOMAINS=24 cargo bench -p bench_prover --bench pcs_roofline
//! ```
//!
//! A comma-separated sweep is supported for convenience, but its `VmHWM` is
//! process-cumulative. `pcs::commit`'s production NTT/Merkle phase split is
//! enabled automatically via `NOIDH_COMMIT_TIMING=1`.

use std::env;
use std::mem::size_of;
use std::process::Command;
use std::time::{Duration, Instant};

use bench_prover::{fmt_bytes, fmt_ms};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::field::F128;
use noid_ivc_prover::pcs::{self, PcsParams, QuirkyDirectClaim, QuirkyDirectClaimRef};
use noid_ivc_prover::proof::bind_statement_field_parts;
use noid_ivc_prover::zerocheck::multilinear::lagrange_weights_naive;
use rayon::prelude::*;

const DOMAIN: &[u8] = b"pcs-roofline-field-v0";
const STATEMENT_DIGEST: [u8; 32] = [0x52; 32];
const K_SKIP: usize = 6;
const LOG_INV_RATE: usize = 2;
const LOG_BATCH_SIZE: usize = 5;
const DEFAULT_LOGICAL_M: usize = 22;
const MIN_LOGICAL_M: usize = 22;
const MAX_LOGICAL_M: usize = 24;
const BLOCK_TIME_BUDGET: Duration = Duration::from_secs(15);

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn deterministic_f128(stream: u64, index: usize) -> F128 {
    let index = index as u64;
    let lo = splitmix64(stream ^ index.wrapping_mul(0xd6e8_feb8_6659_fd93));
    let hi = splitmix64(stream.rotate_left(29) ^ index.wrapping_mul(0xa076_1d64_78bd_642f));
    F128::new(lo, hi)
}

fn deterministic_witness(logical_m: usize) -> Vec<F128> {
    let stream = 0x5043_5352_4f4f_4600 ^ logical_m as u64;
    (0..(1usize << logical_m))
        .into_par_iter()
        .map(|index| deterministic_f128(stream, index))
        .collect()
}

fn deterministic_claim_point(logical_m: usize) -> (F128, Vec<F128>) {
    assert!(logical_m >= K_SKIP);
    let stream = 0x4f50_454e_504f_494e ^ logical_m as u64;
    let z_skip = deterministic_f128(stream, 0);
    let x_rest = (0..(logical_m - K_SKIP))
        .map(|index| deterministic_f128(stream ^ 0x9e37_79b9, index + 1))
        .collect();
    (z_skip, x_rest)
}

/// Evaluate the production quirky point without charging the value derivation
/// to PCS-open. The real prover receives this value from the preceding PIOP.
fn quirky_eval(witness: &[F128], logical_m: usize, z_skip: F128, x_rest: &[F128]) -> F128 {
    assert_eq!(witness.len(), 1usize << logical_m);
    assert_eq!(x_rest.len() + K_SKIP, logical_m);

    let lagrange = lagrange_weights_naive(K_SKIP, z_skip);
    let block = 1usize << K_SKIP;
    let mut folded: Vec<F128> = witness
        .par_chunks_exact(block)
        .map(|values| {
            values
                .iter()
                .zip(lagrange.iter())
                .fold(F128::ZERO, |acc, (&value, &weight)| acc + value * weight)
        })
        .collect();

    for &point in x_rest {
        let one_plus_point = F128::ONE + point;
        let mut next = vec![F128::ZERO; folded.len() / 2];
        next.par_iter_mut().enumerate().for_each(|(index, out)| {
            *out = folded[2 * index] * one_plus_point + folded[2 * index + 1] * point;
        });
        folded = next;
    }

    assert_eq!(folded.len(), 1);
    folded[0]
}

fn requested_domains() -> Vec<usize> {
    let raw =
        env::var("NOID_PCS_ROOFLINE_DOMAINS").unwrap_or_else(|_| DEFAULT_LOGICAL_M.to_string());
    let mut domains = Vec::new();
    for part in raw.split(',') {
        let logical_m = part
            .trim()
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("invalid logical domain in {raw:?}"));
        assert!(
            (MIN_LOGICAL_M..=MAX_LOGICAL_M).contains(&logical_m),
            "roadmap roofline domains are m22, m23, and m24"
        );
        if !domains.contains(&logical_m) {
            domains.push(logical_m);
        }
    }
    assert!(
        !domains.is_empty(),
        "at least one roofline domain is required"
    );
    domains
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.replace('\n', "; "))
}

fn proc_value(path: &str, key: &str) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then(|| value.trim().to_string())
    })
}

fn physical_ram_bytes() -> Option<u64> {
    let value = proc_value("/proc/meminfo", "MemTotal")?;
    let kib = value.split_whitespace().next()?.parse::<u64>().ok()?;
    Some(kib << 10)
}

fn cgroup_memory_limit() -> Option<u64> {
    for path in [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ] {
        let Ok(raw) = std::fs::read_to_string(path) else {
            continue;
        };
        let raw = raw.trim();
        if raw != "max" {
            if let Ok(bytes) = raw.parse() {
                return Some(bytes);
            }
        }
    }
    None
}

fn fmt_u64_bytes(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if bytes as f64 >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB)
    } else {
        format!("{:.2} MiB", bytes as f64 / MIB)
    }
}

fn git_revision() -> String {
    let revision = command_output("git", &["rev-parse", "--short=12", "HEAD"])
        .unwrap_or_else(|| "unavailable".into());
    let dirty = Command::new("git")
        .args(["diff", "--quiet", "--ignore-submodules", "HEAD", "--"])
        .status()
        .ok()
        .is_some_and(|status| !status.success());
    format!("{revision}{}", if dirty { " (dirty)" } else { "" })
}

fn print_manifest(domains: &[usize]) {
    let cpu = proc_value("/proc/cpuinfo", "model name")
        .or_else(|| command_output("sysctl", &["-n", "machdep.cpu.brand_string"]))
        .unwrap_or_else(|| "unavailable".into());
    let affinity = proc_value("/proc/self/status", "Cpus_allowed_list")
        .unwrap_or_else(|| "unavailable".into());
    let rustc = command_output(
        env::var("RUSTC").as_deref().unwrap_or("rustc"),
        &["--version", "--verbose"],
    )
    .unwrap_or_else(|| "unavailable".into());
    let host_parallelism = std::thread::available_parallelism()
        .map(|value| value.get().to_string())
        .unwrap_or_else(|_| "unavailable".into());
    let ram = physical_ram_bytes()
        .map(fmt_u64_bytes)
        .or_else(|| {
            command_output("sysctl", &["-n", "hw.memsize"])
                .and_then(|raw| raw.parse::<u64>().ok())
                .map(fmt_u64_bytes)
        })
        .unwrap_or_else(|| "unavailable".into());
    let cgroup = cgroup_memory_limit()
        .map(fmt_u64_bytes)
        .unwrap_or_else(|| "unlimited/unavailable".into());

    println!("== Production PCS roofline manifest ==");
    println!("  revision        : {}", git_revision());
    println!("  CPU             : {cpu}");
    println!("  physical RAM    : {ram}");
    println!("  cgroup RAM cap  : {cgroup}");
    println!("  host parallelism: {host_parallelism}");
    println!("  CPU affinity    : {affinity}");
    println!("  rayon threads   : {}", rayon::current_num_threads());
    println!("  rustc           : {rustc}");
    println!(
        "  target/profile  : {}-{} / {}",
        env::consts::ARCH,
        env::consts::OS,
        if cfg!(debug_assertions) {
            "debug (use cargo bench for roofline data)"
        } else {
            "bench/release"
        }
    );
    println!(
        "  RUSTFLAGS       : {}",
        env::var("RUSTFLAGS").unwrap_or_else(|_| "<unset>".into())
    );
    println!("  logical domains : {domains:?} (2^m F128 elements)");
    println!("  PCS params      : log_inv_rate={LOG_INV_RATE}, log_batch_size={LOG_BATCH_SIZE}");
    println!("  dataset         : deterministic SplitMix64 witness + one k_skip={K_SKIP} quirky-direct claim");
    println!("  cache state     : fresh process recommended; OS page cache is not flushed");
    println!("  RSS method      : Linux /proc/self/status VmRSS + process-cumulative VmHWM");
    println!("  commit split    : production NOIDH_COMMIT_TIMING NTT/Merkle timers");
    println!();
}

fn print_rss(label: &str, snapshot: Option<MemSnapshot>) {
    match snapshot {
        Some(snapshot) => println!(
            "  RSS {label:<12}: {:>9.1} MiB current, {:>9.1} MiB process HWM",
            snapshot.rss_mb(),
            snapshot.hwm_mb(),
        ),
        None => println!("  RSS {label:<12}: unavailable"),
    }
}

fn rate_gib(bytes: usize, elapsed: Duration) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0) / elapsed.as_secs_f64()
}

fn run_case(logical_m: usize) {
    let params = PcsParams {
        m: logical_m + pcs::LOG_PACKING,
        log_inv_rate: LOG_INV_RATE,
        log_batch_size: LOG_BATCH_SIZE,
        profile: Default::default(),
    };
    let witness_elements = 1usize << logical_m;
    let witness_bytes = witness_elements * size_of::<F128>();

    println!("== logical m{logical_m} / PCS bit-domain m{} ==", params.m);
    println!(
        "  shape           : 2^{logical_m} F128 witness, 2^{} codeword F128, 2^{} Merkle leaves",
        params.codeword_len_f128().trailing_zeros(),
        params.n_leaves().trailing_zeros(),
    );
    println!(
        "  FRI             : log_dim={}, arities={:?}, queries={}",
        params.log_dim(),
        params.fri_arities(),
        pcs::default_fri_queries(params.log_inv_rate),
    );
    println!("  witness bytes   : {}", fmt_bytes(witness_bytes));
    println!(
        "  codeword bytes  : {}",
        fmt_bytes(params.codeword_len_f128() * size_of::<F128>())
    );
    print_rss("baseline", current_mem_snapshot());

    let started = Instant::now();
    let witness = deterministic_witness(logical_m);
    let witness_time = started.elapsed();
    let (z_skip, x_rest) = deterministic_claim_point(logical_m);
    let started = Instant::now();
    let claim_value = quirky_eval(&witness, logical_m, z_skip, &x_rest);
    let claim_time = started.elapsed();
    print_rss("claim setup", current_mem_snapshot());

    let started = Instant::now();
    let (commitment, prover_data) = pcs::commit(&witness, &params);
    let commit_time = started.elapsed();
    let commit_rss = current_mem_snapshot();

    let claim = QuirkyDirectClaim {
        z_skip,
        k_skip: K_SKIP,
        x_rest,
        value: claim_value,
    };
    let mut prover_challenger = FsLaneChallenger::new(DOMAIN);
    bind_statement_field_parts(&mut prover_challenger, &STATEMENT_DIGEST, &commitment);
    let started = Instant::now();
    let opening = pcs::open_batch_quirky_direct(
        &witness,
        &prover_data,
        &commitment,
        std::slice::from_ref(&claim),
        &mut prover_challenger,
    );
    let open_time = started.elapsed();
    let open_rss = current_mem_snapshot();

    let claim_ref = QuirkyDirectClaimRef {
        z_skip: claim.z_skip,
        k_skip: claim.k_skip,
        x_rest: &claim.x_rest,
        value: claim.value,
    };
    let mut verifier_challenger = FsLaneChallenger::new(DOMAIN);
    bind_statement_field_parts(&mut verifier_challenger, &STATEMENT_DIGEST, &commitment);
    let started = Instant::now();
    pcs::verify_opening_batch_quirky_direct(
        &commitment,
        std::slice::from_ref(&claim_ref),
        &opening,
        &mut verifier_challenger,
    )
    .unwrap_or_else(|error| panic!("honest m{logical_m} PCS opening rejected: {error:?}"));
    let verify_time = started.elapsed();
    let verify_rss = current_mem_snapshot();

    let commitment_bytes = bincode::serialize(&commitment)
        .expect("PCS commitment serializes")
        .len();
    let opening_bytes = bincode::serialize(&opening)
        .expect("PCS opening serializes")
        .len();
    let retained_bytes = prover_data.codeword.len() * size_of::<F128>()
        + prover_data.merkle_tree.len() * size_of_val(&prover_data.merkle_tree[0]);
    let pcs_floor = commit_time + open_time;

    println!("  witness build   : {}", fmt_ms(witness_time));
    println!(
        "  claim eval      : {} (setup only; excluded from PCS-open)",
        fmt_ms(claim_time)
    );
    println!(
        "  PCS commit      : {} ({:.2} GiB/s input, {:.2} GiB/s encoded)",
        fmt_ms(commit_time),
        rate_gib(witness_bytes, commit_time),
        rate_gib(params.codeword_len_f128() * size_of::<F128>(), commit_time),
    );
    println!("  PCS open (one)  : {}", fmt_ms(open_time));
    println!("  PCS verify      : {}", fmt_ms(verify_time));
    println!(
        "  PCS floor       : {} (commit + one open)",
        fmt_ms(pcs_floor)
    );
    println!(
        "  15 s necessary : {} (PCS floor only; not a full-proof SLA result)",
        if pcs_floor <= BLOCK_TIME_BUDGET {
            "WITHIN"
        } else {
            "EXCEEDS"
        }
    );
    println!("  commitment wire : {}", fmt_bytes(commitment_bytes));
    println!("  opening wire    : {}", fmt_bytes(opening_bytes));
    println!(
        "  retained PCS    : {} (codeword + initial Merkle tree)",
        fmt_bytes(retained_bytes)
    );
    print_rss("post-commit", commit_rss);
    print_rss("post-open", open_rss);
    print_rss("post-verify", verify_rss);
    if let Some(snapshot) = verify_rss {
        println!(
            "  8 GiB necessary: {} (process HWM; PCS-only)",
            if snapshot.hwm_kib <= 8 * 1024 * 1024 {
                "WITHIN"
            } else {
                "EXCEEDS"
            }
        );
    }
    println!();

    drop(opening);
    drop(prover_data);
    drop(commitment);
    drop(claim);
    drop(witness);
    noid_ivc_prover::scratch::clear();
}

fn main() {
    // Read by pcs::commit; set before rayon or any other worker thread starts.
    if env::var_os("NOIDH_COMMIT_TIMING").is_none() {
        env::set_var("NOIDH_COMMIT_TIMING", "1");
    }
    noid_ivc_prover::init_perf_thread_pool();

    let domains = requested_domains();
    print_manifest(&domains);
    for logical_m in domains {
        run_case(logical_m);
    }
}
