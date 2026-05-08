// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Paranoid STARK report — **Transparent UTXO Validity Engine**.
//!
//!   cargo bench --bench stark_report
//!
//! # Scope (Stage Eopt baseline)
//!
//! This report is the performance surface for Stage Eopt. It measures
//! the **per-tx client prover path** — `TxValidityCompositeWithSpine`
//! — under its verifier-visible `PublicInputs` surface, plus the small
//! set of component AIRs that dominate its prove-bucket profile:
//!
//!   - `TxValidityCompositeWithSpine` — headline: full per-tx composite
//!     (balance, range, H_ADDR, H_AUTH, tx-body Merkle spine, FRI state
//!     opening, combiner).
//!   - `TxBodyMerkleAir`  — 59 Poseidon2b permutations hashing the
//!     tx body into `tx_body_hash`. Largest hash-chain component.
//!   - `PoseidonPermAir`  — one Poseidon2b permutation in isolation
//!     (micro-baseline for Merkle, HAddr, HAuth scaling).
//!   - `HAddrAir`         — 2-field sponge, derive_address (2 perms).
//!   - `HAuthAir`         — 4-field sponge, hash_auth_tag (3 perms).
//!   - `RangeGateAir`     — u64 bit-decomposition sweep; raw engine
//!                          scaling harness.
//!
//! All other pre-Eopt benches (LinearCombination scaling harness,
//! CarryRipple sweep, standalone BalanceGate / TxValidity halves,
//! TxBodySpineComposite subset, interior-only TxBodyMerkle regression
//! baseline) have been retired: they were either subsumed by the full
//! composite or not actionable for optimisation work.

use std::time::{Duration, Instant};

use noid_air::{
    build_perm_trace, emit_perm_all, Air, CompositeAir, HAddrAir, HAuthAir, RangeGateAir, Trace,
    TxBodyMerkleAir, TxBodyMerkleBoundaryPins, HADDR_LOG_ROWS, HADDR_N_COLS, HAUTH_LOG_ROWS,
    HAUTH_N_COLS, POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS, TXBODY_MERKLE_LOG_ROWS,
    TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS, TXBODY_MERKLE_N_PERMS,
};
use noid_core::{Block128, TowerField};
use noid_fri::code::{LOG_RATE, RATE};
use noid_fri::{NUM_QUERIES, TAU};
use noid_stark::{
    padded_log_len, prove_air, prove_air_timed, verify_air_timed, ProveTimings, StarkProof,
    VerifyTimings,
};
use noid_tx::{PublicInputs, MAX_INPUTS, MAX_OUTPUTS};

use noid_poseidon2b::primitives::TxBodyHash;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// RangeGateAir sweep — raw engine scaling harness over a single-column
/// bit-decomposition AIR. `small / mid / prod` mirror the three
/// production-relevant log_rows so prove-bucket percentages remain
/// comparable as the trace grows.
const RANGE_SHAPES: &[(&str, usize)] = &[("small", 8), ("mid", 12), ("prod", 16)];

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
    let mut xs = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t = Instant::now();
        f();
        xs.push(t.elapsed());
    }
    median(xs)
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

fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:>9.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:>9.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:>9} B ", bytes)
    }
}

fn percent(part: Duration, whole: Duration) -> f64 {
    if whole.is_zero() {
        0.0
    } else {
        100.0 * part.as_secs_f64() / whole.as_secs_f64()
    }
}

// ---------------------------------------------------------------------------
// Proof-size estimator
// ---------------------------------------------------------------------------

fn fri_opening_bytes(log_len: usize) -> usize {
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

fn estimate_stark_proof_bytes(
    proof: &StarkProof,
    log_len: usize,
    n_cols: usize,
    n_shifted: usize,
) -> usize {
    let per_opening = fri_opening_bytes(log_len);
    let column_roots = n_cols * 32;
    let base_openings = n_cols * 16;
    let multipoint_openings = n_cols * 16;
    let sumcheck = proof
        .zero_check_rounds
        .iter()
        .map(|r| r.len() * 16)
        .sum::<usize>();
    let shift_partials = n_shifted * (log_len + 1) * 16;
    let multipoint_rounds = proof
        .multipoint_rounds
        .iter()
        .map(|r| r.len() * 16)
        .sum::<usize>();
    let multipoint_fri = per_opening + 32 + multipoint_rounds + multipoint_openings;
    column_roots + base_openings + sumcheck + shift_partials + multipoint_fri
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn mk_pi() -> PublicInputs {
    PublicInputs {
        prev_state_root: [0x11; 32],
        new_state_root: [0x22; 32],
        tx_body_hash: TxBodyHash([0x44; 32]),
        fee: 7,
        n_live_inputs: 0,
        n_live_outputs: 0,
        coinbase_credit: 0,
        log_slots: 24,
        is_activation: [false; MAX_OUTPUTS],
        is_deactivation: [false; MAX_INPUTS],
    }
}

fn splitmix(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn random_u64s(n: usize, mut seed: u64) -> Vec<u64> {
    (0..n).map(|_| splitmix(&mut seed)).collect()
}

// ---------------------------------------------------------------------------
// Sample-collection helpers for bucketed prove/verify
// ---------------------------------------------------------------------------

fn collect_prove_buckets<A: Air>(
    air: &A,
    trace: &Trace,
    pi: &PublicInputs,
    samples: usize,
) -> ProveTimings {
    for _ in 0..WARMUP {
        let _ = prove_air_timed(air, trace, pi).unwrap();
    }
    let mut xs: Vec<ProveTimings> = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (_p, t) = prove_air_timed(air, trace, pi).unwrap();
        xs.push(t);
    }
    xs.sort_by_key(|t| t.total());
    xs[xs.len() / 2]
}

fn collect_verify_buckets<A: Air>(
    air: &A,
    pi: &PublicInputs,
    proof: &StarkProof,
    samples: usize,
) -> VerifyTimings {
    for _ in 0..WARMUP {
        let (r, _) = verify_air_timed(air, pi, proof);
        r.unwrap();
    }
    let mut xs: Vec<VerifyTimings> = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (r, t) = verify_air_timed(air, pi, proof);
        r.unwrap();
        xs.push(t);
    }
    xs.sort_by_key(|t| t.total());
    xs[xs.len() / 2]
}

// ---------------------------------------------------------------------------
// Common row / metrics struct used for every AIR
// ---------------------------------------------------------------------------

struct AirRow {
    label: String,
    log_rows: usize,
    n_cols: usize,
    n_shifted: usize,
    extra: Option<String>,
    prove_total: Duration,
    prove_buckets: ProveTimings,
    verify: VerifyTimings,
    proof_bytes: usize,
}

fn bench_air<A: Air, F>(
    label: &str,
    extra: Option<String>,
    air: A,
    trace: Trace,
    samples: usize,
    check_msg: F,
) -> AirRow
where
    F: FnOnce() -> String,
{
    bench_air_with_pi(label, extra, air, trace, mk_pi(), samples, check_msg)
}

fn bench_air_with_pi<A: Air, F>(
    label: &str,
    extra: Option<String>,
    air: A,
    trace: Trace,
    pi: PublicInputs,
    samples: usize,
    check_msg: F,
) -> AirRow
where
    F: FnOnce() -> String,
{
    assert!(air.check(&trace), "{}", check_msg());

    let prove_total = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    let prove_buckets = collect_prove_buckets(&air, &trace, &pi, samples);

    let proof = prove_air(&air, &trace, &pi).unwrap();
    let verify = collect_verify_buckets(&air, &pi, &proof, samples);

    let log_len = padded_log_len(air.log_rows());
    let n_shifted = air.shifted_column_indices().len();
    let proof_bytes = estimate_stark_proof_bytes(&proof, log_len, air.n_columns(), n_shifted);

    AirRow {
        label: label.to_string(),
        log_rows: air.log_rows(),
        n_cols: air.n_columns(),
        n_shifted,
        extra,
        prove_total,
        prove_buckets,
        verify,
        proof_bytes,
    }
}

fn print_row(tag: &str, r: &AirRow) {
    println!("  [{tag}] {}", r.label);
    println!("  +--------------------------------------------------------------------------+");
    let extra_line = r
        .extra
        .as_deref()
        .map(|s| format!("  {s}"))
        .unwrap_or_default();
    println!(
        "  | log_rows={:>3}  n_cols={:>4}  shifted={:>2}  prove={}  verify={} |",
        r.log_rows,
        r.n_cols,
        r.n_shifted,
        fmt_ms(r.prove_total),
        fmt_ms(r.verify.total()),
    );
    println!(
        "  | proof(estimated)={}                                               |",
        fmt_bytes(r.proof_bytes)
    );
    println!("  +--------------------------------------------------------------------------+");
    if !extra_line.is_empty() {
        println!("{extra_line}");
    }
    let ptot = r.prove_buckets.total();
    println!(
        "    prove  commit {} ({:>5.1}%) | ts+sc {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
        fmt_ms(r.prove_buckets.commit),
        percent(r.prove_buckets.commit, ptot),
        fmt_ms(r.prove_buckets.transcript_sumcheck),
        percent(r.prove_buckets.transcript_sumcheck, ptot),
        fmt_ms(r.prove_buckets.ladder_sumcheck),
        percent(r.prove_buckets.ladder_sumcheck, ptot),
        fmt_ms(r.prove_buckets.multipoint_fri),
        percent(r.prove_buckets.multipoint_fri, ptot),
    );
    let mpt = r.prove_buckets.multipoint_fri;
    println!(
        "      mp-sub setup+pairs {} ({:>5.1}%) | mp-sumcheck {} ({:>5.1}%) | batched-FRI {} ({:>5.1}%)",
        fmt_ms(r.prove_buckets.mp_setup_pairs),
        percent(r.prove_buckets.mp_setup_pairs, mpt),
        fmt_ms(r.prove_buckets.mp_sumcheck),
        percent(r.prove_buckets.mp_sumcheck, mpt),
        fmt_ms(r.prove_buckets.mp_fri),
        percent(r.prove_buckets.mp_fri, mpt),
    );
    let vtot = r.verify.total();
    println!(
        "    verify ts+sc  {} ({:>5.1}%) | comp  {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
        fmt_ms(r.verify.transcript_sumcheck),
        percent(r.verify.transcript_sumcheck, vtot),
        fmt_ms(r.verify.composition),
        percent(r.verify.composition, vtot),
        fmt_ms(r.verify.ladder_sumcheck),
        percent(r.verify.ladder_sumcheck, vtot),
        fmt_ms(r.verify.multipoint_fri),
        percent(r.verify.multipoint_fri, vtot),
    );
    println!();
}

// ---------------------------------------------------------------------------
// RangeGateAir — raw engine scaling harness
// ---------------------------------------------------------------------------

fn bench_range(label: &'static str, log_rows: usize) -> AirRow {
    let air = RangeGateAir::new(log_rows);
    let n = air.n_instances();
    let values = random_u64s(n, 0xBEEF_CAFE ^ log_rows as u64);
    let trace = air.build_trace(&values);
    bench_air(
        &format!("RangeGateAir (u64 bit-decomp, {label})"),
        Some(format!("    instances: {n}")),
        air,
        trace,
        SAMPLES,
        || format!("RangeGateAir native check failed at log_rows={log_rows}"),
    )
}

// ---------------------------------------------------------------------------
// Poseidon2b primitives — Perm / HAddr / HAuth
// ---------------------------------------------------------------------------

fn bench_poseidon_perm() -> AirRow {
    let air = CompositeAir::from_parts(
        POSEIDON_PERM_LOG_ROWS,
        POSEIDON_PERM_N_COLS,
        emit_perm_all(),
    );
    let cols = build_perm_trace([
        Block128::from(0xDECAF_CAFE_BABEu128 ^ 0xA5A5_A5A5_A5A5_A5A5),
        Block128::from(0xDECAF_CAFE_BABFu128 ^ 0x5A5A_5A5A_5A5A_5A5A),
        Block128::from(0xDECAF_CAFE_BAC0u128 ^ 0xFFFF_0000_FFFF_0000),
        Block128::from(0xDECAF_CAFE_BAC1u128 ^ 0x0F0F_F0F0_0F0F_F0F0),
    ]);
    let trace = Trace::new(cols);
    let row = bench_air(
        "PoseidonPermAir (Poseidon2b permutation, 66 rounds)",
        Some("    one permutation per proof (hash hot path)".to_string()),
        air,
        trace,
        SAMPLES,
        || "PoseidonPermAir native check failed".to_string(),
    );
    assert_eq!(row.n_cols, POSEIDON_PERM_N_COLS);
    assert_eq!(row.log_rows, POSEIDON_PERM_LOG_ROWS);
    row
}

fn bench_haddr() -> AirRow {
    use noid_air::{build_haddr_trace, extract_haddr_output};
    let secret = [
        Block128::from(0xDECAF_CAFE_BABEu128 ^ 0xA5A5_A5A5_A5A5_A5A5),
        Block128::from(0xDECAF_CAFE_BABFu128 ^ 0x5A5A_5A5A_5A5A_5A5A),
    ];
    let expected = extract_haddr_output(&build_haddr_trace(secret));
    let air = HAddrAir::new(expected);
    let trace = air.build_trace(secret);
    let row = bench_air(
        "HAddrAir (2-field sponge, derive_address, 2 perms)",
        Some("    secret is witness-only; all boundary ties closed".to_string()),
        air,
        trace,
        SAMPLES,
        || "HAddrAir native check failed".to_string(),
    );
    assert_eq!(row.n_cols, HADDR_N_COLS);
    assert_eq!(row.log_rows, HADDR_LOG_ROWS);
    row
}

fn bench_hauth() -> AirRow {
    use noid_air::{build_hauth_trace, extract_hauth_output};
    let secret = [
        Block128::from(0xA07_5EED_DEAD_BEEFu128),
        Block128::from(0xFACE_FEED_CAFE_F00Du128),
    ];
    let txbody = [
        Block128::from(0x5C0FF_B0D_F00D_FACEu128),
        Block128::from(0xBEEF_DEAD_BABE_CAFEu128),
    ];
    let expected = extract_hauth_output(&build_hauth_trace(secret, txbody));
    let air = HAuthAir::new(txbody, expected);
    let trace = air.build_trace(secret, txbody);
    let row = bench_air(
        "HAuthAir (4-field sponge, hash_auth_tag, 3 perms)",
        Some("    interior-only; capacity IV pinned via PublicColumn".to_string()),
        air,
        trace,
        SAMPLES,
        || "HAuthAir native check failed".to_string(),
    );
    assert_eq!(row.n_cols, HAUTH_N_COLS);
    assert_eq!(row.log_rows, HAUTH_LOG_ROWS);
    row
}

// ---------------------------------------------------------------------------
// TxBodyMerkleAir — boundary-pinned (production path)
// ---------------------------------------------------------------------------

fn bench_tx_body_merkle() -> AirRow {
    // Run the permutation chain once with a placeholder pin set and
    // read back the wrap output, so the O2 pin is self-consistent
    // with the honest trace.
    let inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]> =
        Box::new([[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS]);
    let placeholder = TxBodyMerkleBoundaryPins::default();
    let seed_cols = noid_air::build_tx_body_merkle_trace_with_boundary_pins(&inputs, &placeholder);
    let layout = noid_air::build_instance_layout();
    // Wrap instance id 58.
    let wrap_out_row = layout[58].slot_base_row + 66; // N_ROUNDS = 66
    let s_base = noid_air::TXBODY_MERKLE_LAYOUT.s;
    let pins = TxBodyMerkleBoundaryPins {
        tx_body_hash: [seed_cols[s_base][wrap_out_row], seed_cols[s_base + 1][wrap_out_row]],
        ..TxBodyMerkleBoundaryPins::default()
    };

    let air = TxBodyMerkleAir::new_with_boundary_pins(pins);
    let trace_cols = noid_air::build_tx_body_merkle_trace_with_boundary_pins(&inputs, &pins);
    let domains = noid_air::airs::tx_body_merkle::tx_body_merkle_column_domains_with_boundary_pins();
    let trace = Trace::new_with_domains(trace_cols, domains);

    let row = bench_air(
        "TxBodyMerkleAir (tx-body spine: 59 Poseidon2b perms + boundary pins)",
        Some("    per-perm: {prove, verify, proof} / 59".to_string()),
        air,
        trace,
        SAMPLES.min(3),
        || "TxBodyMerkleAir native check failed".to_string(),
    );
    assert_eq!(row.log_rows, TXBODY_MERKLE_LOG_ROWS);
    assert_eq!(row.n_cols, *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS);
    row
}

// ---------------------------------------------------------------------------
// Per-tx prover path — TxValidityCompositeWithSpine (headline)
//
// Full unified composite proving balance, range, H_ADDR, H_AUTH,
// the tx-body Merkle spine, and the FRI state opening / combiner
// under the verifier-visible PublicInputs surface
// (prev_state_root, new_state_root, tx_body_hash, fee, coinbase_credit,
// log_slots, is_activation[*], is_deactivation[*]).
// ---------------------------------------------------------------------------

fn bench_per_tx_composite() -> AirRow {
    use noid_air::composition::tx_validity_with_spine::fixture;

    let comp = fixture::build_honest_realistic();
    let pi = comp.public_inputs();
    comp.assert_public_inputs_consistent(&pi);

    let trace = comp.build_trace();
    let air = comp.air;

    bench_air_with_pi(
        "TxValidityCompositeWithSpine (full per-tx prover path, PublicInputs-bound)",
        Some("    fixture: 2 live in / 4 live out, fee 50, balance 150 = 100 + 50".to_string()),
        air,
        trace,
        pi,
        SAMPLES.min(3),
        || "TxValidityCompositeWithSpine native check failed".to_string(),
    )
}

// ---------------------------------------------------------------------------
// Banner / footer
// ---------------------------------------------------------------------------

const BANNER: &str = r#"
   ____   _    ____      _    _   _  ___ ___ ____
  |  _ \ / \  |  _ \    / \  | \ | |/ _ \_ _|  _ \
  | |_) / _ \ | |_) |  / _ \ |  \| | | | | || | | |
  |  __/ ___ \|  _ <  / ___ \| |\  | |_| | || |_| |
  |_| /_/   \_\_| \_\/_/   \_\_| \_|\___/___|____/

  PARANOID  --  Transparent UTXO Validity Engine (STARK-based)
  Binius-style STARK over GF(2^128). Per-tx client-side proof.
"#;

fn print_banner() {
    println!("{}", BANNER);
    println!(
        "  Wall-clock medians, release profile. Warmup: {} / Samples: {}.",
        WARMUP, SAMPLES
    );
    println!();
    println!("  Sections:");
    println!("    Engine scaling              (RangeGate sweep)");
    println!("    Poseidon2b hashes           (Perm / HAddr / HAuth)");
    println!("    Transaction-body Merkle     (TxBodyMerkle, boundary-pinned)");
    println!("    Per-tx prover path          (TxValidityCompositeWithSpine, headline)");
    println!();
}

fn print_section(title: &str) {
    println!("==========================================================================");
    println!("  {title}");
    println!("==========================================================================");
    println!();
}

fn print_footer(prod: &AirRow) {
    print_section("Summary");
    println!(
        "  Per-tx prover path:  prove={}  verify={}  proof≈{}",
        fmt_ms(prod.prove_total),
        fmt_ms(prod.verify.total()),
        fmt_bytes(prod.proof_bytes),
    );
    println!("  composite log_rows = {}  |  n_cols = {}", prod.log_rows, prod.n_cols);
    println!();
    println!("  Optimisation targets (by share of prove wall-clock):");
    let p = &prod.prove_buckets;
    let mut buckets = [
        ("commit          ", p.commit),
        ("transcript + sc ", p.transcript_sumcheck),
        ("ladder sumcheck ", p.ladder_sumcheck),
        ("multipoint + FRI", p.multipoint_fri),
    ];
    buckets.sort_by(|a, b| b.1.cmp(&a.1));
    let total = p.total();
    for (name, dur) in &buckets {
        println!(
            "    {name}  {:>10}  ({:>5.1}%)",
            fmt_ms(*dur),
            percent(*dur, total)
        );
    }
    println!();
    println!("  Reproduce: cargo bench --bench stark_report");
    println!();
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

fn main() {
    print_banner();

    eprintln!("  engine scaling ...");
    let mut range_rows = Vec::with_capacity(RANGE_SHAPES.len());
    for (label, log_rows) in RANGE_SHAPES {
        eprintln!("        range  ({label}, log_rows={log_rows}) ...");
        range_rows.push(bench_range(label, *log_rows));
    }

    eprintln!("  Poseidon2b ...");
    let perm_row = bench_poseidon_perm();
    let haddr_row = bench_haddr();
    let hauth_row = bench_hauth();

    eprintln!("  tx body merkle ...");
    let merkle_prod = bench_tx_body_merkle();

    eprintln!("  per-tx prover path ...");
    let l_row = bench_per_tx_composite();
    eprintln!();

    print_section("Engine scaling");
    for r in &range_rows {
        print_row("range    ", r);
    }

    print_section("Poseidon2b hashes");
    print_row("perm     ", &perm_row);
    print_row("haddr    ", &haddr_row);
    print_row("hauth    ", &hauth_row);

    print_section("Transaction-body Merkle");
    print_row("boundary ", &merkle_prod);

    print_section("Per-tx prover path (full PublicInputs surface)");
    print_row("per-tx   ", &l_row);

    print_footer(&l_row);
}
