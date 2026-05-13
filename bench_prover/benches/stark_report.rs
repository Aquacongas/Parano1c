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
//! set of component AIRs that dominate its prove-bucket profile.
//!
//! The tx-body Poseidon spine and the per-input H_ADDR / H_AUTH
//! sponges no longer run inside the STARK — GKR owns the 59-perm
//! tx-body spine and the 20-perm AuthGKR (4 inputs × 5 slots), and the
//! STARK keeps only the two `tx_body_hash` lanes plus the boundary MLE
//! openings. The headline here measures the **full Phase 1 production
//! path** for a single transaction: STARK + SpineGKR + AuthGKR, all
//! stapled through one shared FRI boundary commitment and the
//! `(r_B, v_B)` reduction per sub-protocol absorbed into the STARK's
//! extras-transcript hook.
//!
//!   - `TxValidityCompositeWithSpine` — headline: full per-tx composite
//!     (balance, range, FRI state opening, combiner) wired through
//!     **both** GKR sub-protocols (SpineGKR + AuthGKR). The bench
//!     reports STARK-only baseline, STARK+SpineGKR, STARK+AuthGKR,
//!     their GKR deltas, and the full production total.
//!   - `PoseidonPermAir`  — one Poseidon2b permutation in isolation
//!     (micro-baseline for residual Poseidon scaling).
//!   - `RangeGateAir`     — u64 bit-decomposition sweep; raw engine
//!                          scaling harness.

use std::time::{Duration, Instant};

use noid_air::{
    build_perm_trace, emit_perm_all, Air, CompositeAir, RangeGateAir, Trace,
    POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS,
};
use noid_core::{Block128, TowerField};
use noid_fri::code::{LOG_RATE, RATE};
use noid_fri::{NUM_QUERIES, TAU};
use noid_gkr::{
    compute_auth_boundary, compute_tx_body_hash, prove_spine_killshot, verify_spine_killshot,
    AuthCircuit, AuthInputs, SpineCircuit, SpineInputs, SpineProofKillShot, N_AUTH_INPUTS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_stark::auth::{prove_air_with_auth, verify_air_with_auth, StarkProofWithAuth};
use noid_stark::spine::{prove_air_with_spine, verify_air_with_spine, StarkProofWithSpine};
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
// Poseidon2b primitives — Perm (HAddr / HAuth evacuated to GKR)
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

// ---------------------------------------------------------------------------
// Per-tx prover path — TxValidityCompositeWithSpine + SpineGKR + AuthGKR
//
// Full Phase 1/1 production path for a single transaction:
//   STARK   : balance, range, boundary pins, FRI state opening, combiner
//   SpineGKR: 59-perm tx-body spine Merkle (evacuated from AIR)
//   AuthGKR : 4 × 5 Poseidon2b sponge slots (H_ADDR + H_AUTH per input)
//
// All three are stapled through the shared FRI boundary commitment
// channel + the `(r_B, v_B)` reduction absorbed into the STARK's
// extras-transcript hook. We measure three buckets so the Phase 1/1 GKR
// win is visible:
//
//   - STARK-only              : baseline `prove_air` / `verify_air`
//   - STARK + SpineGKR        : `prove_air_with_spine` + verify
//   - STARK + AuthGKR         : `prove_air_with_auth`  + verify
//
// GKR-only deltas are derived by subtraction (with-GKR − baseline).
// ---------------------------------------------------------------------------

struct CompositePhase1Row {
    log_rows: usize,
    n_cols: usize,
    n_shifted: usize,

    // STARK-only baseline.
    prove_stark: Duration,
    verify_stark: Duration,
    stark_proof_bytes: usize,

    // STARK + SpineGKR.
    prove_with_spine: Duration,
    verify_with_spine: Duration,

    // STARK + AuthGKR.
    prove_with_auth: Duration,
    verify_with_auth: Duration,
}

fn spine_inputs_from_composite(
    comp: &noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine,
) -> SpineInputs {
    let pins = comp.boundary_pins();
    SpineInputs {
        prev_state_root: pins.prev_state_root,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    }
}

fn auth_inputs_from_composite(
    comp: &noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine,
) -> AuthInputs {
    let circuit = AuthCircuit::build();
    let spend_secret: [[Block128; 2]; N_AUTH_INPUTS] = [
        [Block128::from(0xA1u128), Block128::from(0xA2u128)],
        [Block128::from(0xB1u128), Block128::from(0xB2u128)],
        [Block128::from(0xC1u128), Block128::from(0xC2u128)],
        [Block128::from(0xD1u128), Block128::from(0xD2u128)],
    ];
    let tx_body_hash = comp.tx_body_hash_fields();
    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&circuit, spend_secret, tx_body_hash);
    AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    }
}

fn bench_per_tx_composite_phase1() -> CompositePhase1Row {
    use noid_air::composition::tx_validity_with_spine::fixture;

    let comp = fixture::build_honest_realistic();
    let pi = comp.public_inputs();
    comp.assert_public_inputs_consistent(&pi);

    let trace = comp.build_trace();
    let spine_inputs = spine_inputs_from_composite(&comp);
    let auth_inputs = auth_inputs_from_composite(&comp);
    let air = comp.air();

    assert!(
        air.check(&trace),
        "TxValidityCompositeWithSpine native check failed"
    );

    // STARK-only baseline.
    let prove_stark = time(|| {
        let _ = prove_air(air, &trace, &pi).unwrap();
    });
    let stark_proof = prove_air(air, &trace, &pi).unwrap();
    let verify_buckets = collect_verify_buckets(air, &pi, &stark_proof, SAMPLES);
    let verify_stark = verify_buckets.total();

    let log_len = padded_log_len(air.log_rows());
    let n_shifted = air.shifted_column_indices().len();
    let stark_proof_bytes =
        estimate_stark_proof_bytes(&stark_proof, log_len, air.n_columns(), n_shifted);

    // STARK + SpineGKR.
    let prove_with_spine = time(|| {
        let _: StarkProofWithSpine =
            prove_air_with_spine(air, &trace, &pi, &spine_inputs).unwrap();
    });
    let with_spine_proof =
        prove_air_with_spine(air, &trace, &pi, &spine_inputs).unwrap();
    let verify_with_spine = time(|| {
        verify_air_with_spine(air, &pi, &spine_inputs, &with_spine_proof)
            .expect("verify spine");
    });

    // STARK + AuthGKR.
    let prove_with_auth = time(|| {
        let _: StarkProofWithAuth =
            prove_air_with_auth(air, &trace, &pi, &auth_inputs).unwrap();
    });
    let with_auth_proof =
        prove_air_with_auth(air, &trace, &pi, &auth_inputs).unwrap();
    let verify_with_auth = time(|| {
        verify_air_with_auth(air, &pi, &auth_inputs, &with_auth_proof)
            .expect("verify auth");
    });

    let log_rows = air.log_rows();
    let n_cols = air.n_columns();
    CompositePhase1Row {
        log_rows,
        n_cols,
        n_shifted,
        prove_stark,
        verify_stark,
        stark_proof_bytes,
        prove_with_spine,
        verify_with_spine,
        prove_with_auth,
        verify_with_auth,
    }
}

// ---------------------------------------------------------------------------
// Kill-Shot spine — standalone bench (pure GKR, no STARK bridge yet).
//
// Stage 1.5.7 gates:
//   - Spine prove  ≤  50 ms
//   - Spine verify ≤   2 ms
//   - Spine bytes  ≤  5 KB
//
// Targets are reported beside the measured values so a regression is
// visible at a glance. We don't `panic!` on miss: cold dev hardware
// is slower than CI; call sites that need a hard gate should grep
// the printed line and fail externally.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct KillShotRow {
    prove: Duration,
    verify: Duration,
    bytes: usize,
}

fn bench_spine_killshot(
    comp: &noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine,
) -> KillShotRow {
    let circuit = SpineCircuit::build();
    let inputs = spine_inputs_from_composite(comp);
    let claimed = compute_tx_body_hash(&circuit, &inputs);

    let prove = time(|| {
        let mut ch = Poseidon2bChannel::new();
        let _: (SpineProofKillShot, _) =
            prove_spine_killshot(&circuit, &inputs, claimed, &mut ch);
    });

    let mut ch_p = Poseidon2bChannel::new();
    let (proof, _) = prove_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);
    let bytes = proof.byte_len();

    let verify = time(|| {
        let mut ch_v = Poseidon2bChannel::new();
        let _ = verify_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v)
            .expect("kill-shot verify");
    });

    KillShotRow {
        prove,
        verify,
        bytes,
    }
}

fn print_killshot_row(r: &KillShotRow) {
    println!("  [phase1k] SpineGKR Kill-Shot — pure GKR (no STARK bridge yet)");
    println!("  +------------------------------------------------------------------------------+");
    println!(
        "    Spine prove  {}   gate ≤   50 ms",
        fmt_ms(r.prove),
    );
    println!(
        "    Spine verify {}   gate ≤    2 ms",
        fmt_ms(r.verify),
    );
    println!(
        "    Spine bytes  {}     gate ≤    5 KB",
        fmt_bytes(r.bytes),
    );
    println!();
}

fn print_phase1_row(r: &CompositePhase1Row) {
    println!("  [phase1 ] TxValidityCompositeWithSpine + SpineGKR + AuthGKR (full per-tx production path)");
    println!("  +------------------------------------------------------------------------------+");
    println!(
        "  | log_rows={:>3}  n_cols={:>4}  shifted={:>2}  STARK proof(estimated)={} |",
        r.log_rows,
        r.n_cols,
        r.n_shifted,
        fmt_bytes(r.stark_proof_bytes),
    );
    println!("  |   fixture: 2 live in / 4 live out, fee 50, balance 150 = 100 + 50           |");
    println!("  +------------------------------------------------------------------------------+");

    let spine_prove_delta = r.prove_with_spine.saturating_sub(r.prove_stark);
    let auth_prove_delta = r.prove_with_auth.saturating_sub(r.prove_stark);
    let spine_verify_delta = r.verify_with_spine.saturating_sub(r.verify_stark);
    let auth_verify_delta = r.verify_with_auth.saturating_sub(r.verify_stark);
    // Full production path total: STARK is shared between the two
    // with-GKR runs — it's paid once. GKR-only deltas add linearly.
    let prove_full = r.prove_stark + spine_prove_delta + auth_prove_delta;
    let verify_full = r.verify_stark + spine_verify_delta + auth_verify_delta;

    println!(
        "    STARK only         prove {}  verify {}",
        fmt_ms(r.prove_stark),
        fmt_ms(r.verify_stark),
    );
    println!(
        "    STARK + SpineGKR   prove {}  verify {}   (spine delta: prove {} / verify {})",
        fmt_ms(r.prove_with_spine),
        fmt_ms(r.verify_with_spine),
        fmt_ms(spine_prove_delta),
        fmt_ms(spine_verify_delta),
    );
    println!(
        "    STARK + AuthGKR    prove {}  verify {}   (auth  delta: prove {} / verify {})",
        fmt_ms(r.prove_with_auth),
        fmt_ms(r.verify_with_auth),
        fmt_ms(auth_prove_delta),
        fmt_ms(auth_verify_delta),
    );
    println!(
        "    Phase 1/1 TOTAL      prove {}  verify {}   (STARK + SpineGKR + AuthGKR)",
        fmt_ms(prove_full),
        fmt_ms(verify_full),
    );
    println!();
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
    println!("    Poseidon2b hashes           (Perm)");
    println!("    Per-tx prover path          (STARK + SpineGKR + AuthGKR, Phase 1/1)");
    println!();
}

fn print_section(title: &str) {
    println!("==========================================================================");
    println!("  {title}");
    println!("==========================================================================");
    println!();
}

fn print_footer(prod: &CompositePhase1Row) {
    print_section("Summary");

    let spine_prove_delta = prod.prove_with_spine.saturating_sub(prod.prove_stark);
    let auth_prove_delta = prod.prove_with_auth.saturating_sub(prod.prove_stark);
    let spine_verify_delta = prod.verify_with_spine.saturating_sub(prod.verify_stark);
    let auth_verify_delta = prod.verify_with_auth.saturating_sub(prod.verify_stark);
    let prove_full = prod.prove_stark + spine_prove_delta + auth_prove_delta;
    let verify_full = prod.verify_stark + spine_verify_delta + auth_verify_delta;

    println!(
        "  Phase 1/1 per-tx prover (full production path):  prove={}  verify={}",
        fmt_ms(prove_full),
        fmt_ms(verify_full),
    );
    println!(
        "    STARK proper           prove={}  verify={}  proof(STARK only)≈{}",
        fmt_ms(prod.prove_stark),
        fmt_ms(prod.verify_stark),
        fmt_bytes(prod.stark_proof_bytes),
    );
    println!(
        "    SpineGKR (59 perms)    prove={}  verify={}",
        fmt_ms(spine_prove_delta),
        fmt_ms(spine_verify_delta),
    );
    println!(
        "    AuthGKR  (4×5 perms)   prove={}  verify={}",
        fmt_ms(auth_prove_delta),
        fmt_ms(auth_verify_delta),
    );
    println!(
        "  composite log_rows = {}  |  n_cols = {}",
        prod.log_rows, prod.n_cols
    );
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

    eprintln!("  per-tx prover path (STARK + SpineGKR + AuthGKR) ...");
    let l_row = bench_per_tx_composite_phase1();

    eprintln!("  spine kill-shot (pure GKR) ...");
    let killshot_row = {
        use noid_air::composition::tx_validity_with_spine::fixture;
        let comp = fixture::build_honest_realistic();
        bench_spine_killshot(&comp)
    };
    eprintln!();

    print_section("Engine scaling");
    for r in &range_rows {
        print_row("range    ", r);
    }

    print_section("Poseidon2b hashes");
    print_row("perm     ", &perm_row);

    print_section("Per-tx prover path ( Phase 1/1 production path)");
    print_phase1_row(&l_row);

    print_section("SpineGKR Kill-Shot (pure GKR, Stage 1.5.7 gates; current multiplier — see 1.5.8)");
    print_killshot_row(&killshot_row);

    print_footer(&l_row);
}
