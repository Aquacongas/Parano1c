// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::env;
use std::hint::black_box;
use std::process::Command;
use std::time::{Duration, Instant};

use noid_core::Block128;
use noid_gkr::{
    compute_tx_body_hash, discharge_boundary_native, discharge_reductions_native, prove_spine,
    prove_spine_killshot, verify_spine, verify_spine_killshot, SpineCircuit, SpineInputs,
};
use noid_poseidon2b::channel::Poseidon2bChannel;

const PINNED_REVISION: &str = "8e514ff4eb59e7925992e8274c4f10214d7c6b9f";
const ARTIFACT_URL: &str = "https://github.com/ignotusnemo/parano1d/tree/main/research/frost_gkr";
const LEGACY_CONSTRAINT_ROUNDS: usize = 4_248;
const KILL_SHOT_CONSTRAINT_ROUNDS: usize = 30;
const LEGACY_TOTAL_SUMCHECK_ROUNDS: usize = 4_263;
const KILL_SHOT_TOTAL_SUMCHECK_ROUNDS: usize = 75;
const LEGACY_EXPECTED_BYTES: usize = 287_712;
const KILL_SHOT_EXPECTED_BYTES: usize = 5_568;

#[derive(Clone, Copy)]
struct Config {
    warmups: usize,
    samples: usize,
}

#[derive(Clone)]
struct Statistics {
    median_ms: f64,
    p95_ms: f64,
    mean_ms: f64,
    stddev_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

fn parse_config() -> Config {
    let mut config = Config {
        warmups: 3,
        samples: 20,
    };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--warmups" => {
                config.warmups = args
                    .next()
                    .expect("--warmups requires an integer")
                    .parse()
                    .expect("invalid --warmups value");
            }
            "--samples" => {
                config.samples = args
                    .next()
                    .expect("--samples requires an integer")
                    .parse()
                    .expect("invalid --samples value");
            }
            "-h" | "--help" => {
                println!("Usage: frost-gkr-bench [--warmups N] [--samples N]");
                std::process::exit(0);
            }
            _ => panic!("unknown argument: {arg}"),
        }
    }
    assert!(config.samples > 0, "--samples must be positive");
    config
}

fn fixture_inputs() -> SpineInputs {
    SpineInputs {
        prev_state_root: [Block128::from(11u128), Block128::from(22u128)],
        fee_leaf: [Block128::from(33u128), Block128::from(44u128)],
        input_leaves: [[Block128::from(1u128); 4]; 4],
        output_leaves: [[Block128::from(2u128); 4]; 8],
        is_coinbase_leaf: [Block128::from(55u128), Block128::from(66u128)],
        pad_leaf: [Block128::from(0u128), Block128::from(0u128)],
    }
}

fn timed<F, T>(f: &mut F) -> Duration
where
    F: FnMut() -> T,
{
    let start = Instant::now();
    let output = black_box(f());
    let elapsed = start.elapsed();
    black_box(&output);
    drop(output);
    elapsed
}

fn measure_single<F, T>(warmups: usize, samples: usize, mut f: F) -> Statistics
where
    F: FnMut() -> T,
{
    for _ in 0..warmups {
        let _ = timed(&mut f);
    }
    let mut durations = Vec::with_capacity(samples);
    for _ in 0..samples {
        durations.push(timed(&mut f));
    }
    statistics(&durations)
}

fn measure_pair<FL, TL, FK, TK>(
    warmups: usize,
    samples: usize,
    mut legacy: FL,
    mut kill_shot: FK,
) -> (Statistics, Statistics)
where
    FL: FnMut() -> TL,
    FK: FnMut() -> TK,
{
    for i in 0..warmups {
        if i % 2 == 0 {
            let _ = timed(&mut legacy);
            let _ = timed(&mut kill_shot);
        } else {
            let _ = timed(&mut kill_shot);
            let _ = timed(&mut legacy);
        }
    }

    let mut legacy_durations = Vec::with_capacity(samples);
    let mut kill_shot_durations = Vec::with_capacity(samples);
    for i in 0..samples {
        if i % 2 == 0 {
            legacy_durations.push(timed(&mut legacy));
            kill_shot_durations.push(timed(&mut kill_shot));
        } else {
            kill_shot_durations.push(timed(&mut kill_shot));
            legacy_durations.push(timed(&mut legacy));
        }
    }

    (
        statistics(&legacy_durations),
        statistics(&kill_shot_durations),
    )
}

fn statistics(durations: &[Duration]) -> Statistics {
    let mut values: Vec<f64> = durations
        .iter()
        .map(|duration| duration.as_secs_f64() * 1_000.0)
        .collect();
    values.sort_by(f64::total_cmp);

    let len = values.len();
    let median_ms = if len % 2 == 0 {
        (values[len / 2 - 1] + values[len / 2]) / 2.0
    } else {
        values[len / 2]
    };
    let p95_index = ((len as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(len - 1);
    let mean_ms = values.iter().sum::<f64>() / len as f64;
    let variance = if len > 1 {
        values
            .iter()
            .map(|value| {
                let delta = value - mean_ms;
                delta * delta
            })
            .sum::<f64>()
            / (len - 1) as f64
    } else {
        0.0
    };

    Statistics {
        median_ms,
        p95_ms: values[p95_index],
        mean_ms,
        stddev_ms: variance.sqrt(),
        min_ms: values[0],
        max_ms: values[len - 1],
    }
}

fn command_output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn cpu_info_value(key: &str) -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                let (candidate, value) = line.split_once(':')?;
                (candidate.trim() == key).then(|| value.trim().to_owned())
            })
        })
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn enabled_isa() -> String {
    let flags = cpu_info_value("flags");
    ["pclmulqdq", "avx2", "avx512f", "gfni", "vpclmulqdq"]
        .into_iter()
        .filter(|feature| flags.split_whitespace().any(|flag| flag == *feature))
        .collect::<Vec<_>>()
        .join(", ")
}

fn physical_core_count() -> String {
    let cores = command_output("lscpu", &["--parse=CORE"])
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<BTreeSet<_>>()
        .len();
    if cores == 0 {
        "unavailable".to_owned()
    } else {
        cores.to_string()
    }
}

fn read_system_value(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unavailable".to_owned())
}

fn print_timing_row(label: &str, statistics: &Statistics) {
    println!(
        "| {label} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} |",
        statistics.median_ms,
        statistics.p95_ms,
        statistics.mean_ms,
        statistics.stddev_ms,
        statistics.min_ms,
        statistics.max_ms,
    );
}

fn main() {
    let config = parse_config();
    let actual_revision = command_output("git", &["rev-parse", "HEAD"]);
    assert_eq!(
        actual_revision, PINNED_REVISION,
        "benchmark must run at the pinned comparison revision"
    );

    let circuit = SpineCircuit::build();
    let inputs = fixture_inputs();
    let claimed = compute_tx_body_hash(&circuit, &inputs);

    // Correctness gate before measurement.
    let mut legacy_prover_channel = Poseidon2bChannel::new();
    let (legacy_proof, legacy_prover_reduction) =
        prove_spine(&circuit, &inputs, claimed, &mut legacy_prover_channel);
    let mut legacy_verifier_channel = Poseidon2bChannel::new();
    let legacy_verifier_reduction = verify_spine(
        &legacy_proof,
        &circuit,
        &inputs,
        claimed,
        &mut legacy_verifier_channel,
    )
    .expect("legacy verifier rejected its honest proof");
    assert_eq!(legacy_prover_reduction, legacy_verifier_reduction);
    assert!(discharge_boundary_native(
        &circuit,
        &inputs,
        &legacy_verifier_reduction
    ));

    let mut kill_shot_prover_channel = Poseidon2bChannel::new();
    let (kill_shot_proof, kill_shot_prover_reductions) =
        prove_spine_killshot(&circuit, &inputs, claimed, &mut kill_shot_prover_channel);
    let mut kill_shot_verifier_channel = Poseidon2bChannel::new();
    let kill_shot_verifier_reductions = verify_spine_killshot(
        &kill_shot_proof,
        &circuit,
        &inputs,
        claimed,
        &mut kill_shot_verifier_channel,
    )
    .expect("Kill-Shot verifier rejected its honest proof");
    assert_eq!(kill_shot_prover_reductions, kill_shot_verifier_reductions);
    assert!(discharge_reductions_native(
        &circuit,
        &inputs,
        &kill_shot_verifier_reductions
    ));

    let legacy_bytes = legacy_proof.byte_len();
    let kill_shot_bytes = kill_shot_proof.byte_len();
    assert_eq!(legacy_bytes, LEGACY_EXPECTED_BYTES);
    assert_eq!(kill_shot_bytes, KILL_SHOT_EXPECTED_BYTES);

    let shared_hash = measure_single(config.warmups, config.samples, || {
        compute_tx_body_hash(black_box(&circuit), black_box(&inputs))
    });

    let (legacy_prover, kill_shot_prover) = measure_pair(
        config.warmups,
        config.samples,
        || {
            let mut channel = Poseidon2bChannel::new();
            let (proof, reduction) = prove_spine(&circuit, &inputs, claimed, &mut channel);
            (proof.byte_len(), reduction.point.len())
        },
        || {
            let mut channel = Poseidon2bChannel::new();
            let (proof, reductions) =
                prove_spine_killshot(&circuit, &inputs, claimed, &mut channel);
            (
                proof.byte_len(),
                reductions.state.point.len()
                    + reductions.sin.point.len()
                    + reductions.sout.point.len(),
            )
        },
    );

    let (legacy_verifier, kill_shot_verifier) = measure_pair(
        config.warmups,
        config.samples,
        || {
            let mut channel = Poseidon2bChannel::new();
            verify_spine(
                black_box(&legacy_proof),
                &circuit,
                &inputs,
                claimed,
                &mut channel,
            )
            .expect("legacy verifier failed during timing")
        },
        || {
            let mut channel = Poseidon2bChannel::new();
            verify_spine_killshot(
                black_box(&kill_shot_proof),
                &circuit,
                &inputs,
                claimed,
                &mut channel,
            )
            .expect("Kill-Shot verifier failed during timing")
        },
    );

    let (legacy_discharge, kill_shot_discharge) = measure_pair(
        config.warmups,
        config.samples,
        || {
            assert!(discharge_boundary_native(
                &circuit,
                &inputs,
                black_box(&legacy_verifier_reduction)
            ));
        },
        || {
            assert!(discharge_reductions_native(
                &circuit,
                &inputs,
                black_box(&kill_shot_verifier_reductions)
            ));
        },
    );

    let (legacy_full_verifier, kill_shot_full_verifier) = measure_pair(
        config.warmups,
        config.samples,
        || {
            let mut channel = Poseidon2bChannel::new();
            let reduction = verify_spine(
                black_box(&legacy_proof),
                &circuit,
                &inputs,
                claimed,
                &mut channel,
            )
            .expect("legacy verifier failed during combined timing");
            assert!(discharge_boundary_native(&circuit, &inputs, &reduction));
        },
        || {
            let mut channel = Poseidon2bChannel::new();
            let reductions = verify_spine_killshot(
                black_box(&kill_shot_proof),
                &circuit,
                &inputs,
                claimed,
                &mut channel,
            )
            .expect("Kill-Shot verifier failed during combined timing");
            assert!(discharge_reductions_native(&circuit, &inputs, &reductions));
        },
    );

    let generated = command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]);
    let logical_threads = std::thread::available_parallelism()
        .map(|count| count.get().to_string())
        .unwrap_or_else(|_| "unavailable".to_owned());
    let rayon_threads = env::var("RAYON_NUM_THREADS")
        .unwrap_or_else(|_| format!("default ({logical_threads} logical threads available)"));
    let rustflags = env::var("RUSTFLAGS").unwrap_or_else(|_| "not set".to_owned());

    println!("# FROST-GKR benchmark result");
    println!();
    println!("- Generated (UTC): `{generated}`");
    println!("- Implementation revision: `{actual_revision}`");
    println!("- Artifact: <{ARTIFACT_URL}>");
    println!("- Profile: `cargo run --release --locked`");
    println!("- Warmups: `{}` per operation", config.warmups);
    println!("- Samples: `{}` per operation", config.samples);
    println!("- CPU: `{}`", cpu_info_value("model name"));
    println!(
        "- CPU topology: `{}` physical cores, `{logical_threads}` logical threads",
        physical_core_count()
    );
    println!("- Relevant ISA: `{}`", enabled_isa());
    println!(
        "- CPU governor: `{}`",
        read_system_value("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    );
    let no_turbo = read_system_value("/sys/devices/system/cpu/intel_pstate/no_turbo");
    let turbo = match no_turbo.as_str() {
        "0" => "enabled",
        "1" => "disabled",
        _ => "unavailable",
    };
    println!("- Turbo: `{turbo}`");
    println!("- Rayon threads: `{rayon_threads}`");
    println!("- OS/kernel: `{}`", command_output("uname", &["-srmo"]));
    println!("- Rust: `{}`", command_output("rustc", &["--version"]));
    println!("- Cargo: `{}`", command_output("cargo", &["--version"]));
    println!("- Repository rustflags: `-C target-cpu=native`");
    println!("- Additional `RUSTFLAGS`: `{rustflags}`");
    println!();
    println!("## Timings");
    println!();
    println!("All values are milliseconds. p95 uses the nearest-rank estimator; standard deviation is the sample standard deviation.");
    println!();
    println!("| Operation | Median | p95 | Mean | Std. dev. | Min | Max |");
    println!("|---|---:|---:|---:|---:|---:|---:|");
    print_timing_row("Shared tx-body hash computation", &shared_hash);
    print_timing_row("Legacy prover", &legacy_prover);
    print_timing_row("Kill-Shot prover", &kill_shot_prover);
    print_timing_row("Legacy protocol verifier", &legacy_verifier);
    print_timing_row("Kill-Shot protocol verifier", &kill_shot_verifier);
    print_timing_row("Legacy native terminal discharge", &legacy_discharge);
    print_timing_row("Kill-Shot native terminal discharge", &kill_shot_discharge);
    print_timing_row("Legacy verifier + native discharge", &legacy_full_verifier);
    print_timing_row(
        "Kill-Shot verifier + native discharge",
        &kill_shot_full_verifier,
    );
    println!();
    println!(
        "Median prover speedup: `{:.2}x`",
        legacy_prover.median_ms / kill_shot_prover.median_ms
    );
    println!(
        "Median protocol-verifier speedup: `{:.2}x`",
        legacy_verifier.median_ms / kill_shot_verifier.median_ms
    );
    println!(
        "Median verifier-plus-discharge speedup: `{:.2}x`",
        legacy_full_verifier.median_ms / kill_shot_full_verifier.median_ms
    );
    println!();
    println!("## Algebraic proof accounting");
    println!();
    println!("| Metric | Legacy product-chain GKR | Kill-Shot | Reduction |");
    println!("|---|---:|---:|---:|");
    println!("| Constraint sumcheck rounds | {LEGACY_CONSTRAINT_ROUNDS} | {KILL_SHOT_CONSTRAINT_ROUNDS} | {:.2}x |", LEGACY_CONSTRAINT_ROUNDS as f64 / KILL_SHOT_CONSTRAINT_ROUNDS as f64);
    println!("| Total sumcheck rounds, including terminal batching | {LEGACY_TOTAL_SUMCHECK_ROUNDS} | {KILL_SHOT_TOTAL_SUMCHECK_ROUNDS} | {:.2}x |", LEGACY_TOTAL_SUMCHECK_ROUNDS as f64 / KILL_SHOT_TOTAL_SUMCHECK_ROUNDS as f64);
    println!(
        "| Raw algebraic proof bytes | {legacy_bytes} | {kill_shot_bytes} | {:.2}x |",
        legacy_bytes as f64 / kill_shot_bytes as f64
    );
    println!(
        "| Raw algebraic proof KiB | {:.5} | {:.5} | {:.2}x |",
        legacy_bytes as f64 / 1024.0,
        kill_shot_bytes as f64 / 1024.0,
        legacy_bytes as f64 / kill_shot_bytes as f64
    );
    println!();
    println!("The proof-byte rows count raw field elements in the preserved algebraic proof objects. They exclude serialization framing, PCS/FRI openings, and Merkle authentication paths.");
}
