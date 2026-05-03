// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Paranoid STARK report — roadmap tracker.
//!
//!   cargo bench --bench stark_report
//!
//! Unlike `release_report` (which is a stable hardware-floor dump of
//! primitives), this report grows alongside the roadmap. It measures
//! every `*Air` that has actually landed in `noid_air::airs`, on trace
//! sizes that are relevant to the Stage 3b/3c/3d critical path.
//!
//! Current coverage (maps to ROADMAP.md):
//!
//!   [A] TxValidityAir            — Stage 3a witness skeleton.
//!                                  log_rows = 4 (padded to the STARK
//!                                  engine's minimum), 10 columns, two
//!                                  boolean selectors. Zero algebraic
//!                                  content beyond bool — this number is
//!                                  a *shape baseline*, not a speed claim.
//!
//!   [B] CarryRippleAir           — Stage 3b-0.3/0.4/0.5 rotation-consuming
//!                                  AIR. 5 columns, 64-bit ripple adder,
//!                                  one shifted column. `small/mid/prod`
//!                                  buckets drive the ladder FRI tuning.
//!
//!   [D] RangeGateAir             — Stage 3b-2 u64 range check via
//!                                  bit-decomposition + GF(2^128) weight
//!                                  ladder. 4 columns, 6 constraints,
//!                                  two shifted columns. `small/mid/prod`
//!                                  mirrors the CarryRipple buckets.
//!
//!   [G] PoseidonPermAir          — Stage 3c-1 Poseidon2b permutation.
//!                                  30 columns, 29 selector-gated
//!                                  constraints (S-box chain / RC binding
//!                                  / MDS blend / partial-round sin kill),
//!                                  one shifted column (MDS blend).
//!                                  `log_rows = POSEIDON_PERM_LOG_ROWS`
//!                                  (= 8, STARK floor). One permutation
//!                                  instance per proof — the hash hot
//!                                  path is one permutation per leaf.
//!
//!   [F] TxValidityAir (3b-4)     — Stage 3b-4 composite: witness
//!                                  skeleton + BalanceGate embedded at
//!                                  column offset 10. Non-Poseidon half
//!                                  of the transaction-validity AIR.
//!                                  `log_rows = TX_VALIDITY_3B4_LOG_ROWS`
//!                                  (= balance floor, 8), 76 columns.
//!
//!   [E] BalanceGateAir           — Stage 3b-3 UTXO conservation law
//!                                  (`Σ inputs = Σ outputs + fee`). 11
//!                                  parametric `bit_adder` blocks over
//!                                  66 columns, cross-block carry bridges
//!                                  + asymmetric-width tail comparison.
//!                                  One shifted column per block (11),
//!                                  128 rows per instance, `small/mid/prod`
//!                                  mirrors the CarryRipple/Range buckets.
//!
//!   [C] LinearCombinationAir     — scaling harness (synthetic constraint
//!                                  `last = sum of others`). Not a real
//!                                  gate; included to expose how the
//!                                  STARK engine scales in `n_cols` and
//!                                  `log_rows` independent of AIR
//!                                  algebra. Marked as such in the output.
//!
//! As §3c (Poseidon gates), §3d (TxValidityAir full composition) land,
//! each one gets a new block here. `[C]` will be removed once enough
//! real gates exist to span the `n_cols` / `log_rows` space honestly.
//!
//! For each AIR this report prints wall-clock prove, verify, and proof
//! size (via `estimate_proof_bytes`, not serialisation).
//!
//! Companion: `cargo bench --bench release_report`.

use std::time::{Duration, Instant};

use noid_air::{
    build_perm_trace, emit_perm_all, Air, BalanceGateAir, CarryRippleAir, CompositeAir,
    LinearCombinationAir, RangeGateAir, Trace, TxValidityAir, BIT_ADDER_LOG_WORD_BITS,
    POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS, TX_VALIDITY_3B4_LOG_ROWS, TX_VALIDITY_3B4_N_COLS,
    TX_VALIDITY_LOG_ROWS, TX_VALIDITY_N_COLS,
};
use noid_core::{Block128, TowerField};
use noid_fri::code::{LOG_RATE, RATE};
use noid_fri::{NUM_QUERIES, TAU};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::{
    padded_log_len, prove_air, prove_air_timed, verify_air, verify_air_timed, ProveTimings,
    StarkProof, VerifyTimings,
};
use noid_tx::{PublicInputs, TxBody, TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS};

use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// CarryRippleAir sweep (Stage 3b-0.3 / 0.4 / 0.5 buckets).
const CARRY_SHAPES: &[(&str, usize)] = &[("small", 8), ("mid", 12), ("prod", 16)];

/// RangeGateAir sweep (Stage 3b-2) — same bucket layout as CarryRipple
/// so numbers can be compared apples-to-apples (both AIRs have 64 rows
/// per instance, one bit-domain per row).
const RANGE_SHAPES: &[(&str, usize)] = &[("small", 8), ("mid", 12), ("prod", 16)];

/// BalanceGateAir — the ONLY shape we care about in a UTXO /
/// bitcoin-like model: one transaction per proving session.
///
/// The chain has no smart contracts — no approve/swap, no multicall,
/// no bundled user intents. A wallet signs exactly one tx and proves
/// exactly one tx before broadcasting; the mempool carries
/// (tx, proof) pairs; block builders aggregate N per-tx proofs via
/// IVC / folding in §3e (`noid_ivc`), not via flat batching.
///
/// So there is only one meaningful number to measure here: per-tx
/// client-side prove latency at the STARK floor (TAU=7 ⇒ log_rows ≥ 8).
/// Each tx instance occupies 128 rows × 66 cols; log_rows=8 ⇒ 2 tx
/// instance slots (1 active + zero-pad).
///
/// Deliberately NOT measured:
/// - Flat multi-tx batches (log_rows ≥ 10): not a product scenario in
///   a UTXO chain. Block builders fold, not flat-batch.
/// - IVC / folding aggregation: separate workload with its own cost
///   model; lands in `ivc_report.rs` when §3e is ready.
/// - General scaling-with-size behaviour: already covered by the
///   CarryRipple and Range sweeps, which use clean per-instance
///   matrices better suited for scaling studies.
///
/// If you ever need a one-off stress run, call
/// `bench_balance("stress", N)` manually.
const BALANCE_SHAPES: &[(&str, usize)] = &[("per_tx", 8)];

/// LinearCombinationAir scaling harness. Kept small (`log_rows ≤ 14`) so
/// the report stays under ~2 minutes; bigger sweeps belong in ad-hoc runs.
const LINCOMB_SHAPES: &[(usize, usize)] = &[(10, 3), (12, 3), (14, 3), (14, 6)];

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

fn percent(part: Duration, whole: Duration) -> f64 {
    if whole.is_zero() {
        0.0
    } else {
        100.0 * part.as_secs_f64() / whole.as_secs_f64()
    }
}

// ---------------------------------------------------------------------------
// Proof-size estimator (matches the one used in `release_report` + `carry_ripple`)
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
// Fixture builders
// ---------------------------------------------------------------------------

fn mk_pi() -> PublicInputs {
    PublicInputs {
        prev_state_root: [0x11; 32],
        new_state_root: [0x22; 32],
        tx_body_hash: TxBodyHash([0x44; 32]),
        fee: 7,
    }
}

fn splitmix(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn random_adders(n: usize, mut seed: u64) -> Vec<(u64, u64)> {
    (0..n)
        .map(|_| {
            let a = splitmix(&mut seed);
            let b = splitmix(&mut seed);
            (a, b)
        })
        .collect()
}

fn mk_tx_body() -> TxBody {
    let inputs = (0..MAX_INPUTS)
        .map(|i| TxInput {
            slot_index: i as u32,
            value: 100 + i as u64,
            owner: Address([i as u8; 32]),
            spend_secret: SpendSecret([(i ^ 0xAA) as u8; 32]),
            auth_tag: AuthTag([(i ^ 0x55) as u8; 32]),
            valid: true,
        })
        .collect();
    let outputs = (0..MAX_OUTPUTS)
        .map(|i| TxOutput {
            value: 50 + i as u64,
            owner: Address([(0x30 | i) as u8; 32]),
            valid: true,
        })
        .collect();
    TxBody {
        prev_state_root: [0x11; 32],
        new_state_root: [0x22; 32],
        fee: 7,
        inputs,
        outputs,
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

// ---------------------------------------------------------------------------
// [A] TxValidityAir — Stage 3a
// ---------------------------------------------------------------------------

struct TxValidityRow {
    log_rows: usize,
    n_cols: usize,
    build_ms: Duration,
    prove_ms: Duration,
    verify_ms: Duration,
    proof_bytes: usize,
}

fn bench_tx_validity() -> TxValidityRow {
    let air = TxValidityAir::new();
    let body = mk_tx_body();
    let build_ms = time(|| {
        let _ = TxValidityAir::build_trace(&body);
    });
    let trace = TxValidityAir::build_trace(&body);
    assert!(air.check(&trace), "TxValidityAir native check failed");
    let pi = mk_pi();

    let prove_ms = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    let proof = prove_air(&air, &trace, &pi).unwrap();
    let verify_ms = time(|| {
        verify_air(&air, &pi, &proof).unwrap();
    });

    let log_len = padded_log_len(air.log_rows());
    let n_shifted = air
        .constraints()
        .iter()
        .flat_map(|c| c.shifted_columns().iter().copied())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let proof_bytes = estimate_stark_proof_bytes(&proof, log_len, air.n_columns(), n_shifted);

    TxValidityRow {
        log_rows: air.log_rows(),
        n_cols: air.n_columns(),
        build_ms,
        prove_ms,
        verify_ms,
        proof_bytes,
    }
}

// ---------------------------------------------------------------------------
// [B] CarryRippleAir — Stage 3b-0.3/0.4/0.5
// ---------------------------------------------------------------------------

struct CarryRow {
    label: &'static str,
    log_rows: usize,
    n_instances: usize,
    prove_total: Duration,
    prove_buckets: ProveTimings,
    verify: VerifyTimings,
    proof_bytes: usize,
}

fn bench_carry(label: &'static str, log_rows: usize) -> CarryRow {
    let air = CarryRippleAir::new(log_rows);
    let n_instances = air.n_instances();
    let adders = random_adders(n_instances, 0xA5A5_0000 ^ log_rows as u64);
    let trace = air.build_trace(&adders);
    assert!(air.check(&trace), "CarryRippleAir native check failed at log_rows={log_rows}");
    let pi = mk_pi();

    let prove_total = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    for _ in 0..WARMUP {
        let _ = prove_air_timed(&air, &trace, &pi).unwrap();
    }
    let mut prove_samples: Vec<ProveTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (_p, t) = prove_air_timed(&air, &trace, &pi).unwrap();
        prove_samples.push(t);
    }
    prove_samples.sort_by_key(|t| t.total());
    let prove_buckets = prove_samples[prove_samples.len() / 2];
    let proof = prove_air(&air, &trace, &pi).unwrap();

    let mut verify_samples: Vec<VerifyTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..WARMUP {
        let (r, _) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
    }
    for _ in 0..SAMPLES {
        let (r, t) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
        verify_samples.push(t);
    }
    verify_samples.sort_by_key(|t| t.total());
    let verify = verify_samples[verify_samples.len() / 2];

    let log_len = padded_log_len(log_rows);
    let n_shifted = air.shifted_column_indices().len();
    let proof_bytes = estimate_stark_proof_bytes(&proof, log_len, air.n_columns(), n_shifted);

    CarryRow {
        label,
        log_rows,
        n_instances,
        prove_total,
        prove_buckets,
        verify,
        proof_bytes,
    }
}

// ---------------------------------------------------------------------------
// [D] RangeGateAir — Stage 3b-2
// ---------------------------------------------------------------------------

struct RangeRow {
    label: &'static str,
    log_rows: usize,
    n_instances: usize,
    prove_total: Duration,
    prove_buckets: ProveTimings,
    verify: VerifyTimings,
    proof_bytes: usize,
}

fn random_u64s(n: usize, mut seed: u64) -> Vec<u64> {
    (0..n).map(|_| splitmix(&mut seed)).collect()
}

fn bench_range(label: &'static str, log_rows: usize) -> RangeRow {
    let air = RangeGateAir::new(log_rows);
    let n_instances = air.n_instances();
    let values = random_u64s(n_instances, 0xBEEF_CAFE ^ log_rows as u64);
    let trace = air.build_trace(&values);
    assert!(air.check(&trace), "RangeGateAir native check failed at log_rows={log_rows}");
    let pi = mk_pi();

    let prove_total = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    for _ in 0..WARMUP {
        let _ = prove_air_timed(&air, &trace, &pi).unwrap();
    }
    let mut prove_samples: Vec<ProveTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (_p, t) = prove_air_timed(&air, &trace, &pi).unwrap();
        prove_samples.push(t);
    }
    prove_samples.sort_by_key(|t| t.total());
    let prove_buckets = prove_samples[prove_samples.len() / 2];
    let proof = prove_air(&air, &trace, &pi).unwrap();

    let mut verify_samples: Vec<VerifyTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..WARMUP {
        let (r, _) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
    }
    for _ in 0..SAMPLES {
        let (r, t) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
        verify_samples.push(t);
    }
    verify_samples.sort_by_key(|t| t.total());
    let verify = verify_samples[verify_samples.len() / 2];

    let log_len = padded_log_len(log_rows);
    let n_shifted = air.shifted_column_indices().len();
    let proof_bytes = estimate_stark_proof_bytes(&proof, log_len, air.n_columns(), n_shifted);

    RangeRow {
        label,
        log_rows,
        n_instances,
        prove_total,
        prove_buckets,
        verify,
        proof_bytes,
    }
}

// ---------------------------------------------------------------------------
// [E] BalanceGateAir — Stage 3b-3
// ---------------------------------------------------------------------------

struct BalanceRow {
    label: &'static str,
    log_rows: usize,
    n_instances: usize,
    prove_total: Duration,
    prove_buckets: ProveTimings,
    verify: VerifyTimings,
    proof_bytes: usize,
}

/// Deterministic balanced (inputs, outputs, fee) tuple with
/// `Σ in = Σ out + fee`. Mirrors the `balanced_tuple` helper used by
/// `balance_gate`'s own tests.
fn balanced_tuple_bench(seed: u64) -> ([u64; 4], [u64; 8], u64) {
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
    let mut next = || -> u64 {
        s = s
            .wrapping_mul(0x5851F42D4C957F2D)
            .wrapping_add(0x14057B7EF767814F);
        s >> 32
    };
    let inputs = [
        next() & 0x0FFF_FFFF_FFFF_FFFF,
        next() & 0x0FFF_FFFF_FFFF_FFFF,
        next() & 0x0FFF_FFFF_FFFF_FFFF,
        next() & 0x0FFF_FFFF_FFFF_FFFF,
    ];
    let fee = next() & 0xFFFF;
    let total: u128 = inputs.iter().map(|&x| x as u128).sum::<u128>() - fee as u128;
    let mut remaining = total;
    let mut outs = [0u64; 8];
    for i in 0..7 {
        let take_mask = next() as u128;
        let take = take_mask % (remaining / (8 - i) as u128 + 1);
        outs[i] = take as u64;
        remaining -= take;
    }
    outs[7] = remaining as u64;
    (inputs, outs, fee)
}

fn bench_balance(label: &'static str, log_rows: usize) -> BalanceRow {
    let air = BalanceGateAir::new(log_rows);
    let n_instances = air.n_instances();
    let (ins, outs, fee) = balanced_tuple_bench(0xBA1A_0000 ^ log_rows as u64);
    let trace = air.build_trace(ins, outs, fee);
    assert!(
        air.check(&trace),
        "BalanceGateAir native check failed at log_rows={log_rows}"
    );
    let pi = mk_pi();

    let prove_total = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    for _ in 0..WARMUP {
        let _ = prove_air_timed(&air, &trace, &pi).unwrap();
    }
    let mut prove_samples: Vec<ProveTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (_p, t) = prove_air_timed(&air, &trace, &pi).unwrap();
        prove_samples.push(t);
    }
    prove_samples.sort_by_key(|t| t.total());
    let prove_buckets = prove_samples[prove_samples.len() / 2];
    let proof = prove_air(&air, &trace, &pi).unwrap();

    let mut verify_samples: Vec<VerifyTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..WARMUP {
        let (r, _) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
    }
    for _ in 0..SAMPLES {
        let (r, t) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
        verify_samples.push(t);
    }
    verify_samples.sort_by_key(|t| t.total());
    let verify = verify_samples[verify_samples.len() / 2];

    let log_len = padded_log_len(log_rows);
    let n_shifted = air.shifted_column_indices().len();
    let proof_bytes = estimate_stark_proof_bytes(&proof, log_len, air.n_columns(), n_shifted);

    BalanceRow {
        label,
        log_rows,
        n_instances,
        prove_total,
        prove_buckets,
        verify,
        proof_bytes,
    }
}

// ---------------------------------------------------------------------------
// [F] TxValidityAir (Stage 3b-4) — skeleton + balance composition
// ---------------------------------------------------------------------------

struct TxValidity3b4Row {
    log_rows: usize,
    n_cols: usize,
    n_instances: usize,
    prove_total: Duration,
    prove_buckets: ProveTimings,
    verify: VerifyTimings,
    proof_bytes: usize,
}

fn mk_tx_body_balanced_1in1out(in_val: u64, out_val: u64, fee: u64) -> TxBody {
    assert_eq!(in_val, out_val + fee);
    let mut inputs = vec![TxInput::dummy(); MAX_INPUTS];
    inputs[0] = TxInput {
        slot_index: 0,
        value: in_val,
        owner: Address([0x11; 32]),
        spend_secret: SpendSecret([0x22; 32]),
        auth_tag: AuthTag([0x33; 32]),
        valid: true,
    };
    let mut outputs = vec![TxOutput::dummy(); MAX_OUTPUTS];
    outputs[0] = TxOutput {
        value: out_val,
        owner: Address([0x44; 32]),
        valid: true,
    };
    TxBody {
        prev_state_root: [0x11; 32],
        new_state_root: [0x22; 32],
        fee: fee as u128,
        inputs,
        outputs,
    }
}

fn bench_tx_validity_3b4(log_rows: usize) -> TxValidity3b4Row {
    let air = TxValidityAir::new_3b4(log_rows);
    let body = mk_tx_body_balanced_1in1out(1000, 995, 5);
    let ins = [1000u64, 0, 0, 0];
    let outs = [995u64, 0, 0, 0, 0, 0, 0, 0];
    let trace = TxValidityAir::build_trace_3b4(&body, ins, outs, 5, log_rows);
    assert!(
        air.check(&trace),
        "TxValidityAir 3b-4 native check failed at log_rows={log_rows}"
    );
    let pi = mk_pi();

    let prove_total = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    for _ in 0..WARMUP {
        let _ = prove_air_timed(&air, &trace, &pi).unwrap();
    }
    let mut prove_samples: Vec<ProveTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (_p, t) = prove_air_timed(&air, &trace, &pi).unwrap();
        prove_samples.push(t);
    }
    prove_samples.sort_by_key(|t| t.total());
    let prove_buckets = prove_samples[prove_samples.len() / 2];
    let proof = prove_air(&air, &trace, &pi).unwrap();

    let mut verify_samples: Vec<VerifyTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..WARMUP {
        let (r, _) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
    }
    for _ in 0..SAMPLES {
        let (r, t) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
        verify_samples.push(t);
    }
    verify_samples.sort_by_key(|t| t.total());
    let verify = verify_samples[verify_samples.len() / 2];

    let log_len = padded_log_len(log_rows);
    let n_shifted = air.shifted_column_indices().len();
    let proof_bytes = estimate_stark_proof_bytes(&proof, log_len, air.n_columns(), n_shifted);

    let n_instances = 1usize << (log_rows - BIT_ADDER_LOG_WORD_BITS);

    TxValidity3b4Row {
        log_rows,
        n_cols: air.n_columns(),
        n_instances,
        prove_total,
        prove_buckets,
        verify,
        proof_bytes,
    }
}

fn print_tx_validity_3b4(r: &TxValidity3b4Row) {
    println!("  [F] TxValidityAir (Stage 3b-4 — skeleton + BalanceGate composition)");
    println!("  +--------------------------------------------------------------------------+");
    println!(
        "  | log_rows={:>2}  n_cols={:>3}  bal_inst={:>2}  prove={}  verify={} |",
        r.log_rows,
        r.n_cols,
        r.n_instances,
        fmt_ms(r.prove_total),
        fmt_ms(r.verify.total()),
    );
    println!(
        "  | proof(estimated)={}                                                |",
        fmt_bytes(r.proof_bytes)
    );
    println!("  +--------------------------------------------------------------------------+");
    println!();
    println!("  prover buckets (commit / ts+sc / ladder-sc / multipoint+FRI):");
    let total = r.prove_buckets.total();
    println!(
        "    3b-4  commit {} ({:>5.1}%) | ts+sc {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
        fmt_ms(r.prove_buckets.commit),
        percent(r.prove_buckets.commit, total),
        fmt_ms(r.prove_buckets.transcript_sumcheck),
        percent(r.prove_buckets.transcript_sumcheck, total),
        fmt_ms(r.prove_buckets.ladder_sumcheck),
        percent(r.prove_buckets.ladder_sumcheck, total),
        fmt_ms(r.prove_buckets.multipoint_fri),
        percent(r.prove_buckets.multipoint_fri, total),
    );
    println!();
    println!("  verifier buckets (ts+sc / composition / ladder-sc / multipoint+FRI):");
    let vtotal = r.verify.total();
    println!(
        "    3b-4  ts+sc  {} ({:>5.1}%) | comp  {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
        fmt_ms(r.verify.transcript_sumcheck),
        percent(r.verify.transcript_sumcheck, vtotal),
        fmt_ms(r.verify.composition),
        percent(r.verify.composition, vtotal),
        fmt_ms(r.verify.ladder_sumcheck),
        percent(r.verify.ladder_sumcheck, vtotal),
        fmt_ms(r.verify.multipoint_fri),
        percent(r.verify.multipoint_fri, vtotal),
    );
    println!();
    println!("  Note: non-Poseidon half of TxValidity — skeleton bool selectors plus full");
    println!("  BalanceGate (Σ inputs = Σ outputs + fee). Value binding to balance operands");
    println!("  and Poseidon gates land in §3c/§3d.");
    println!();
    assert_eq!(r.n_cols, TX_VALIDITY_3B4_N_COLS);
}

// ---------------------------------------------------------------------------
// [G] PoseidonPermAir — Stage 3c-1
// ---------------------------------------------------------------------------

struct PoseidonRow {
    log_rows: usize,
    n_cols: usize,
    prove_total: Duration,
    prove_buckets: ProveTimings,
    verify: VerifyTimings,
    proof_bytes: usize,
}

fn mk_perm_input(seed: u128) -> [Block128; 4] {
    let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
    [
        Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
        Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        Block128::from(s.wrapping_add(2) ^ 0xFFFF_0000_FFFF_0000),
        Block128::from(s.wrapping_add(3) ^ 0x0F0F_F0F0_0F0F_F0F0),
    ]
}

fn bench_poseidon_perm() -> PoseidonRow {
    let air = CompositeAir::from_parts(POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS, emit_perm_all());
    let cols = build_perm_trace(mk_perm_input(0xDECAF_CAFE_BABE));
    let trace = Trace::new(cols);
    assert!(air.check(&trace), "PoseidonPermAir native check failed");
    let pi = mk_pi();

    let prove_total = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    for _ in 0..WARMUP {
        let _ = prove_air_timed(&air, &trace, &pi).unwrap();
    }
    let mut prove_samples: Vec<ProveTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (_p, t) = prove_air_timed(&air, &trace, &pi).unwrap();
        prove_samples.push(t);
    }
    prove_samples.sort_by_key(|t| t.total());
    let prove_buckets = prove_samples[prove_samples.len() / 2];
    let proof = prove_air(&air, &trace, &pi).unwrap();

    let mut verify_samples: Vec<VerifyTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..WARMUP {
        let (r, _) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
    }
    for _ in 0..SAMPLES {
        let (r, t) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
        verify_samples.push(t);
    }
    verify_samples.sort_by_key(|t| t.total());
    let verify = verify_samples[verify_samples.len() / 2];

    let log_len = padded_log_len(POSEIDON_PERM_LOG_ROWS);
    let n_shifted = air.shifted_column_indices().len();
    let proof_bytes = estimate_stark_proof_bytes(&proof, log_len, air.n_columns(), n_shifted);

    PoseidonRow {
        log_rows: POSEIDON_PERM_LOG_ROWS,
        n_cols: air.n_columns(),
        prove_total,
        prove_buckets,
        verify,
        proof_bytes,
    }
}

fn print_poseidon_perm(r: &PoseidonRow) {
    println!("  [G] PoseidonPermAir  (Stage 3c-1 — Poseidon2b permutation, 66 rounds)");
    println!("  +--------------------------------------------------------------------------+");
    println!(
        "  | log_rows={:>2}  n_cols={:>3}  prove={}  verify={}            |",
        r.log_rows,
        r.n_cols,
        fmt_ms(r.prove_total),
        fmt_ms(r.verify.total()),
    );
    println!(
        "  | proof(estimated)={}                                                |",
        fmt_bytes(r.proof_bytes)
    );
    println!("  +--------------------------------------------------------------------------+");
    println!();
    println!("  prover buckets (commit / ts+sc / ladder-sc / multipoint+FRI):");
    let total = r.prove_buckets.total();
    println!(
        "    3c-1  commit {} ({:>5.1}%) | ts+sc {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
        fmt_ms(r.prove_buckets.commit),
        percent(r.prove_buckets.commit, total),
        fmt_ms(r.prove_buckets.transcript_sumcheck),
        percent(r.prove_buckets.transcript_sumcheck, total),
        fmt_ms(r.prove_buckets.ladder_sumcheck),
        percent(r.prove_buckets.ladder_sumcheck, total),
        fmt_ms(r.prove_buckets.multipoint_fri),
        percent(r.prove_buckets.multipoint_fri, total),
    );
    println!();
    println!("  verifier buckets (ts+sc / composition / ladder-sc / multipoint+FRI):");
    let vtotal = r.verify.total();
    println!(
        "    3c-1  ts+sc  {} ({:>5.1}%) | comp  {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
        fmt_ms(r.verify.transcript_sumcheck),
        percent(r.verify.transcript_sumcheck, vtotal),
        fmt_ms(r.verify.composition),
        percent(r.verify.composition, vtotal),
        fmt_ms(r.verify.ladder_sumcheck),
        percent(r.verify.ladder_sumcheck, vtotal),
        fmt_ms(r.verify.multipoint_fri),
        percent(r.verify.multipoint_fri, vtotal),
    );
    println!();
    println!("  Note: 29 selector-gated constraints — S-box chain (16), RC binding (6),");
    println!("  MDS blend (4, full+partial fused via is_full selector), partial-round");
    println!("  sin kill (3). `rc`, `is_full`, `is_round` are trusted input columns; §3d");
    println!("  will pin them via ConstColumnGate.");
    println!();
    assert_eq!(r.n_cols, POSEIDON_PERM_N_COLS);
    assert_eq!(r.log_rows, POSEIDON_PERM_LOG_ROWS);
}

// ---------------------------------------------------------------------------
// [C] LinearCombinationAir — synthetic scaling harness
// ---------------------------------------------------------------------------

struct LinearRow {
    log_rows: usize,
    n_cols: usize,
    prove_ms: Duration,
    verify_ms: Duration,
    proof_bytes: usize,
}

fn bench_linear(log_rows: usize, n_cols: usize) -> LinearRow {
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
    let log_len = padded_log_len(log_rows);
    let proof_bytes = estimate_stark_proof_bytes(&proof, log_len, n_cols, 0);
    LinearRow {
        log_rows,
        n_cols,
        prove_ms,
        verify_ms,
        proof_bytes,
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

  PARANOID  --  STARK REPORT (roadmap tracker)
  TxValidity (3a) + CarryRipple (3b-0) + Range (3b-2) + Balance (3b-3) + TxValidity3b4 (3b-4) + PoseidonPerm (3c-1) + LinearCombination
"#;

fn print_banner() {
    println!("{}", BANNER);
    println!(
        "  Wall-clock medians over {} samples ({} warmup); release profile.",
        SAMPLES, WARMUP
    );
    println!();
}

fn print_tx_validity(r: &TxValidityRow) {
    println!("  [A] TxValidityAir  (Stage 3a — witness skeleton, bool-only gates)");
    println!("  +---------------------------------------------------------------------+");
    println!(
        "  | log_rows={:>2}  n_cols={:>2}  build_trace={}  prove={}  verify={} |",
        r.log_rows,
        r.n_cols,
        fmt_ms(r.build_ms),
        fmt_ms(r.prove_ms),
        fmt_ms(r.verify_ms),
    );
    println!(
        "  | proof(estimated)={}                                         |",
        fmt_bytes(r.proof_bytes)
    );
    println!("  +---------------------------------------------------------------------+");
    println!("  Note: this AIR is a Stage 3a witness skeleton — only InputValid,");
    println!("  OutputValid are constrained (bool). Real tx validity lands once");
    println!("  Stage 3b Range + Balance + Stage 3c Poseidon gates are composed in.");
    println!();
    assert_eq!(r.log_rows, TX_VALIDITY_LOG_ROWS);
    assert_eq!(r.n_cols, TX_VALIDITY_N_COLS);
}

fn print_carry_table(rows: &[CarryRow]) {
    println!("  [B] CarryRippleAir  (Stage 3b-0 — rotation-consuming gate, ladder FRI)");
    println!("  +--------------------------------------------------------------------------+");
    println!(
        "  | {:>5} | {:>8} | {:>8} | {:>12} | {:>12} | {:>12} |",
        "label", "log_rows", "adders", "prove", "verify (tot)", "proof"
    );
    println!(
        "  |-------+----------+----------+--------------+--------------+--------------|"
    );
    for r in rows {
        println!(
            "  | {:>5} | {:>8} | {:>8} | {:>12} | {:>12} | {:>12} |",
            r.label,
            r.log_rows,
            r.n_instances,
            fmt_ms(r.prove_total),
            fmt_ms(r.verify.total()),
            fmt_bytes(r.proof_bytes),
        );
    }
    println!("  +--------------------------------------------------------------------------+");
    println!();

    println!("  prover buckets (commit / ts+sc / ladder-sc / multipoint+FRI):");
    for r in rows {
        let total = r.prove_buckets.total();
        println!(
            "    {:>5}  commit {} ({:>5.1}%) | ts+sc {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
            r.label,
            fmt_ms(r.prove_buckets.commit),
            percent(r.prove_buckets.commit, total),
            fmt_ms(r.prove_buckets.transcript_sumcheck),
            percent(r.prove_buckets.transcript_sumcheck, total),
            fmt_ms(r.prove_buckets.ladder_sumcheck),
            percent(r.prove_buckets.ladder_sumcheck, total),
            fmt_ms(r.prove_buckets.multipoint_fri),
            percent(r.prove_buckets.multipoint_fri, total),
        );
    }
    println!();

    println!("  verifier buckets (ts+sc / composition / ladder-sc / multipoint+FRI):");
    for r in rows {
        let total = r.verify.total();
        println!(
            "    {:>5}  ts+sc  {} ({:>5.1}%) | comp  {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
            r.label,
            fmt_ms(r.verify.transcript_sumcheck),
            percent(r.verify.transcript_sumcheck, total),
            fmt_ms(r.verify.composition),
            percent(r.verify.composition, total),
            fmt_ms(r.verify.ladder_sumcheck),
            percent(r.verify.ladder_sumcheck, total),
            fmt_ms(r.verify.multipoint_fri),
            percent(r.verify.multipoint_fri, total),
        );
    }
    println!();
}

fn print_range_table(rows: &[RangeRow]) {
    println!("  [D] RangeGateAir  (Stage 3b-2 — u64 bit-decomposition range check)");
    println!("  +--------------------------------------------------------------------------+");
    println!(
        "  | {:>5} | {:>8} | {:>8} | {:>12} | {:>12} | {:>12} |",
        "label", "log_rows", "values", "prove", "verify (tot)", "proof"
    );
    println!(
        "  |-------+----------+----------+--------------+--------------+--------------|"
    );
    for r in rows {
        println!(
            "  | {:>5} | {:>8} | {:>8} | {:>12} | {:>12} | {:>12} |",
            r.label,
            r.log_rows,
            r.n_instances,
            fmt_ms(r.prove_total),
            fmt_ms(r.verify.total()),
            fmt_bytes(r.proof_bytes),
        );
    }
    println!("  +--------------------------------------------------------------------------+");
    println!();

    println!("  prover buckets (commit / ts+sc / ladder-sc / multipoint+FRI):");
    for r in rows {
        let total = r.prove_buckets.total();
        println!(
            "    {:>5}  commit {} ({:>5.1}%) | ts+sc {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
            r.label,
            fmt_ms(r.prove_buckets.commit),
            percent(r.prove_buckets.commit, total),
            fmt_ms(r.prove_buckets.transcript_sumcheck),
            percent(r.prove_buckets.transcript_sumcheck, total),
            fmt_ms(r.prove_buckets.ladder_sumcheck),
            percent(r.prove_buckets.ladder_sumcheck, total),
            fmt_ms(r.prove_buckets.multipoint_fri),
            percent(r.prove_buckets.multipoint_fri, total),
        );
    }
    println!();

    println!("  verifier buckets (ts+sc / composition / ladder-sc / multipoint+FRI):");
    for r in rows {
        let total = r.verify.total();
        println!(
            "    {:>5}  ts+sc  {} ({:>5.1}%) | comp  {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
            r.label,
            fmt_ms(r.verify.transcript_sumcheck),
            percent(r.verify.transcript_sumcheck, total),
            fmt_ms(r.verify.composition),
            percent(r.verify.composition, total),
            fmt_ms(r.verify.ladder_sumcheck),
            percent(r.verify.ladder_sumcheck, total),
            fmt_ms(r.verify.multipoint_fri),
            percent(r.verify.multipoint_fri, total),
        );
    }
    println!();
}

fn print_balance_table(rows: &[BalanceRow]) {
    println!("  [E] BalanceGateAir  (Stage 3b-3 — UTXO conservation law, 4-in / 8-out / fee)");
    println!("  +--------------------------------------------------------------------------+");
    println!(
        "  | {:>5} | {:>8} | {:>8} | {:>12} | {:>12} | {:>12} |",
        "label", "log_rows", "tx inst", "prove", "verify (tot)", "proof"
    );
    println!(
        "  |-------+----------+----------+--------------+--------------+--------------|"
    );
    for r in rows {
        println!(
            "  | {:>5} | {:>8} | {:>8} | {:>12} | {:>12} | {:>12} |",
            r.label,
            r.log_rows,
            r.n_instances,
            fmt_ms(r.prove_total),
            fmt_ms(r.verify.total()),
            fmt_bytes(r.proof_bytes),
        );
    }
    println!("  +--------------------------------------------------------------------------+");
    println!();

    println!("  prover buckets (commit / ts+sc / ladder-sc / multipoint+FRI):");
    for r in rows {
        let total = r.prove_buckets.total();
        println!(
            "    {:>5}  commit {} ({:>5.1}%) | ts+sc {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
            r.label,
            fmt_ms(r.prove_buckets.commit),
            percent(r.prove_buckets.commit, total),
            fmt_ms(r.prove_buckets.transcript_sumcheck),
            percent(r.prove_buckets.transcript_sumcheck, total),
            fmt_ms(r.prove_buckets.ladder_sumcheck),
            percent(r.prove_buckets.ladder_sumcheck, total),
            fmt_ms(r.prove_buckets.multipoint_fri),
            percent(r.prove_buckets.multipoint_fri, total),
        );
    }
    println!();

    println!("  verifier buckets (ts+sc / composition / ladder-sc / multipoint+FRI):");
    for r in rows {
        let total = r.verify.total();
        println!(
            "    {:>5}  ts+sc  {} ({:>5.1}%) | comp  {} ({:>5.1}%) | ladsc {} ({:>5.1}%) | mp+fri {} ({:>5.1}%)",
            r.label,
            fmt_ms(r.verify.transcript_sumcheck),
            percent(r.verify.transcript_sumcheck, total),
            fmt_ms(r.verify.composition),
            percent(r.verify.composition, total),
            fmt_ms(r.verify.ladder_sumcheck),
            percent(r.verify.ladder_sumcheck, total),
            fmt_ms(r.verify.multipoint_fri),
            percent(r.verify.multipoint_fri, total),
        );
    }
    println!();
}

fn print_linear_table(rows: &[LinearRow]) {
    println!("  [C] LinearCombinationAir  (SYNTHETIC scaling harness, NOT a real gate)");
    println!("  +-------------------------------------------------------------------+");
    println!(
        "  | {:>8} | {:>7} | {:>8} | {:>12} | {:>12} | {:>12} |",
        "log_rows", "n_cols", "rows", "prove", "verify", "proof"
    );
    println!(
        "  |----------+---------+----------+--------------+--------------+--------------|"
    );
    for r in rows {
        println!(
            "  | {:>8} | {:>7} | {:>8} | {:>12} | {:>12} | {:>12} |",
            r.log_rows,
            r.n_cols,
            fmt_count(1 << r.log_rows),
            fmt_ms(r.prove_ms),
            fmt_ms(r.verify_ms),
            fmt_bytes(r.proof_bytes),
        );
    }
    println!("  +-------------------------------------------------------------------+");
    println!("  Note: constraint is 'last column = sum of others' — no real algebra.");
    println!("  Purpose: expose engine scaling in (log_rows, n_cols). Gets deleted");
    println!("  from this report once real §3b-2/3b-3/§3c AIRs populate the grid.");
    println!();
}

fn print_footer() {
    println!("  roadmap checkpoint (see ROADMAP.md):");
    println!("    [A] TxValidityAir  (Stage 3a)               shipped (skeleton)");
    println!("    [B] CarryRippleAir (Stage 3b-0.3..0.5)      shipped");
    println!("    [D] RangeGateAir   (Stage 3b-2)             shipped");
    println!("    [E] BalanceGateAir (Stage 3b-3)             shipped");
    println!("    [F] TxValidityAir  (Stage 3b-4 — non-Pos)   shipped");
    println!("    [G] PoseidonPermAir (Stage 3c-1)            shipped");
    println!("    [ ] HAddrAir / HAuthAir / HLeafAir / TxBodyMerkleAir (Stage 3c-2..5)  NEXT");
    println!("    [ ] TxValidityAir  (Stage 3d — full)        planned");
    println!();
    println!("  reproduce: cargo bench --bench stark_report");
    println!();
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

fn main() {
    print_banner();

    eprintln!("  [A] TxValidityAir (Stage 3a) ...");
    let tx_row = bench_tx_validity();

    eprintln!("  [B] CarryRippleAir ...");
    let mut carry_rows = Vec::with_capacity(CARRY_SHAPES.len());
    for (label, log_rows) in CARRY_SHAPES {
        eprintln!("        {} (log_rows = {}) ...", label, log_rows);
        carry_rows.push(bench_carry(label, *log_rows));
    }

    eprintln!("  [D] RangeGateAir ...");
    let mut range_rows = Vec::with_capacity(RANGE_SHAPES.len());
    for (label, log_rows) in RANGE_SHAPES {
        eprintln!("        {} (log_rows = {}) ...", label, log_rows);
        range_rows.push(bench_range(label, *log_rows));
    }

    eprintln!("  [E] BalanceGateAir ...");
    let mut balance_rows = Vec::with_capacity(BALANCE_SHAPES.len());
    for (label, log_rows) in BALANCE_SHAPES {
        eprintln!("        {} (log_rows = {}) ...", label, log_rows);
        balance_rows.push(bench_balance(label, *log_rows));
    }

    eprintln!("  [F] TxValidityAir (Stage 3b-4) ...");
    let tx3b4_row = bench_tx_validity_3b4(TX_VALIDITY_3B4_LOG_ROWS);

    eprintln!("  [G] PoseidonPermAir (Stage 3c-1) ...");
    let poseidon_row = bench_poseidon_perm();

    eprintln!("  [C] LinearCombinationAir (scaling harness) ...");
    let mut lin_rows = Vec::with_capacity(LINCOMB_SHAPES.len());
    for &(lr, nc) in LINCOMB_SHAPES {
        eprintln!("        log_rows = {}, n_cols = {} ...", lr, nc);
        lin_rows.push(bench_linear(lr, nc));
    }
    eprintln!();

    print_tx_validity(&tx_row);
    print_carry_table(&carry_rows);
    print_range_table(&range_rows);
    print_balance_table(&balance_rows);
    print_tx_validity_3b4(&tx3b4_row);
    print_poseidon_perm(&poseidon_row);
    print_linear_table(&lin_rows);
    print_footer();
}
