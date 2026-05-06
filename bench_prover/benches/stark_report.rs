// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Paranoid STARK report — **Transparent UTXO Validity Engine**.
//!
//!   cargo bench --bench stark_report
//!
//! # What this is
//!
//! Paranoid is a transparent (no encrypted values, no shielded pools)
//! UTXO chain whose state transitions are proven correct by a
//! client-side STARK. Every wallet transaction produces one STARK
//! proof before it is broadcast to the mempool; block builders
//! aggregate per-tx proofs via IVC (separate workload, not covered
//! here).
//!
//! The proof system is a Binius-style STARK over the GF(2^128) tower
//! field, implemented end-to-end in this repository (no external zk
//! dependencies). The AIRs below encode one UTXO transition:
//!
//!   - `BalanceGateAir`      — Σ inputs = Σ outputs + fee (bit-adder
//!                             composition over GF(2^128)).
//!   - `RangeGateAir`        — u64 range check via bit-decomposition.
//!   - `PoseidonPermAir`     — Poseidon2b permutation over GF(2^128).
//!   - `HAddrAir`            — 2-field sponge: derive_address.
//!   - `HAuthAir`            — 4-field sponge: hash_auth_tag.
//!   - `HLeafAir`            — 4-field sponge: hash_input_leaf /
//!                             hash_utxo_leaf.
//!   - `TxBodyMerkleAir`     — tx-body Merkle spine: 59 stacked
//!                             Poseidon2b permutations hashing
//!                             `(prev_state_root, fee, 4 inputs,
//!                             8 outputs)` into `tx_body_hash`.
//!   - `TxValidityAir`       — non-Poseidon half of the transition:
//!                             witness skeleton, selector discipline,
//!                             embedded BalanceGate, value-operand
//!                             public-column pins.
//!   - `TxBodySpineComposite` — end-to-end transition AIR: TxValidity
//!                              and TxBodyMerkle stitched with cross-AIR
//!                              payload ties (production prover path).
//!
//! # What this report measures
//!
//! For each AIR: wall-clock median prove time, verify time, and
//! estimated proof size (via `estimate_proof_bytes`, not the
//! serialiser). Prover and verifier wall-clock are bucketed by phase
//! (commit / transcript+sumcheck / ladder-sumcheck / multipoint+FRI)
//! so optimisation work has a direct target.
//!
//! The critical number is `[P] TxBodySpineComposite` — the actual
//! per-tx client prover path. Everything above it is a component
//! bench kept for regression coverage and optimisation guidance.
//!
//! # What this report is not
//!
//! - Not a batched-proof benchmark. The chain has no flat batching;
//!   aggregation is IVC-folded.
//! - Not a circuit sizing study. Gate counts and witness widths are
//!   printed but not swept.
//! - Not a hardware-floor microbench. See `release_report` for
//!   Poseidon / FRI primitives in isolation.
//!
//! Companion: `cargo bench --bench release_report`.

use std::time::{Duration, Instant};

use noid_air::{
    build_perm_trace, emit_perm_all, Air, BalanceGateAir, CarryRippleAir, CompositeAir, HAddrAir,
    HAuthAir, HLeafAir, LinearCombinationAir, RangeGateAir, Trace, TxBodyMerkleAir,
    TxBodyMerkleBoundaryPins, TxBodySpineComposite, TxValidityAir,
    BIT_ADDER_LOG_WORD_BITS, HADDR_LOG_ROWS, HADDR_N_COLS, HAUTH_LOG_ROWS, HAUTH_N_COLS,
    HLEAF_LOG_ROWS, HLEAF_N_COLS, POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS,
    SPINE_LOG_ROWS, TXBODY_MERKLE_LOG_ROWS, TXBODY_MERKLE_N_COLS,
    TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS, TXBODY_MERKLE_N_PERMS, TX_VALIDITY_3B4_LOG_ROWS,
    TX_VALIDITY_3B4_N_COLS,
};
use noid_core::{Block128, TowerField};
use noid_fri::code::{LOG_RATE, RATE};
use noid_fri::{NUM_QUERIES, TAU};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::{
    padded_log_len, prove_air, prove_air_timed, verify_air_timed, ProveTimings,
    StarkProof, VerifyTimings,
};
use noid_tx::{PublicInputs, TxBody, TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS};

use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// CarryRippleAir sweep — exposes STARK engine scaling for a
/// single-column algebra (one 64-bit ripple adder per instance).
const CARRY_SHAPES: &[(&str, usize)] = &[("small", 8), ("mid", 12), ("prod", 16)];

/// RangeGateAir sweep — same bucket layout as CarryRipple so the two
/// numbers are directly comparable (both are 64 rows per instance).
const RANGE_SHAPES: &[(&str, usize)] = &[("small", 8), ("mid", 12), ("prod", 16)];

/// BalanceGateAir: one transaction per proof. The chain has no flat
/// multi-tx batching — the wallet signs one tx, proves one tx, then
/// broadcasts. Block builders fold per-tx proofs via IVC, not by
/// re-proving a wider batch.
///
/// `per_tx` at `log_rows = 8` is the STARK floor (TAU = 7 ⇒ log_rows ≥ 8).
/// One active instance + zero-padded slots.
const BALANCE_SHAPES: &[(&str, usize)] = &[("per_tx", 8)];

/// LinearCombinationAir scaling harness — synthetic constraint used
/// to expose raw engine scaling independent of AIR algebra.
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

fn random_u64s(n: usize, mut seed: u64) -> Vec<u64> {
    (0..n).map(|_| splitmix(&mut seed)).collect()
}

fn mk_tx_body_1in1out(in_val: u64, out_val: u64, fee: u64) -> TxBody {
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
    assert!(air.check(&trace), "{}", check_msg());
    let pi = mk_pi();

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
// [A] Primitive scaling — CarryRipple / Range / LinearCombination
// ---------------------------------------------------------------------------

fn bench_carry(label: &'static str, log_rows: usize) -> AirRow {
    let air = CarryRippleAir::new(log_rows);
    let n = air.n_instances();
    let adders = random_adders(n, 0xA5A5_0000 ^ log_rows as u64);
    let trace = air.build_trace(&adders);
    bench_air(
        &format!("CarryRippleAir (64-bit ripple, {label})"),
        Some(format!("    instances: {n}")),
        air,
        trace,
        SAMPLES,
        || format!("CarryRippleAir native check failed at log_rows={log_rows}"),
    )
}

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

fn bench_linear(log_rows: usize, n_cols: usize) -> AirRow {
    let air = LinearCombinationAir::new(n_cols, log_rows);
    let trace = mk_linear_trace(log_rows, n_cols);
    bench_air(
        &format!(
            "LinearCombinationAir (scaling harness, {} rows × {} cols)",
            fmt_count(1 << log_rows),
            n_cols
        ),
        None,
        air,
        trace,
        SAMPLES,
        || "LinearCombinationAir native check failed".to_string(),
    )
}

// ---------------------------------------------------------------------------
// [B] BalanceGateAir — per-tx
// ---------------------------------------------------------------------------

fn balanced_tuple(seed: u64) -> ([u64; 4], [u64; 8], u64) {
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

fn bench_balance(label: &'static str, log_rows: usize) -> AirRow {
    let air = BalanceGateAir::new(log_rows);
    let n = air.n_instances();
    let (ins, outs, fee) = balanced_tuple(0xBA1A_0000 ^ log_rows as u64);
    let trace = air.build_trace(ins, outs, fee);
    bench_air(
        &format!("BalanceGateAir (UTXO conservation, {label})"),
        Some(format!("    tx slots: {n}  |  4 inputs / 8 outputs / fee")),
        air,
        trace,
        SAMPLES,
        || format!("BalanceGateAir native check failed at log_rows={log_rows}"),
    )
}

// ---------------------------------------------------------------------------
// [C] Poseidon2b primitives — Perm / HAddr / HAuth / HLeaf
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

fn bench_hleaf() -> AirRow {
    use noid_air::{build_hleaf_trace, extract_hleaf_output};
    let fields = [
        Block128::from(0x1EAF_5EED_DEAD_BEEFu128),
        Block128::from(0xFACE_FEED_CAFE_F00Du128),
        Block128::from(0x5C0FF_B0D_F00D_FACEu128),
        Block128::from(0xBEEF_DEAD_BABE_CAFEu128),
    ];
    let expected = extract_hleaf_output(&build_hleaf_trace(fields));
    let air = HLeafAir::new(fields, expected);
    let trace = air.build_trace(fields);
    let row = bench_air(
        "HLeafAir (4-field sponge, hash_input_leaf, 3 perms)",
        Some("    interior-only; TAG_LEAF capacity IV pinned".to_string()),
        air,
        trace,
        SAMPLES,
        || "HLeafAir native check failed".to_string(),
    );
    assert_eq!(row.n_cols, HLEAF_N_COLS);
    assert_eq!(row.log_rows, HLEAF_LOG_ROWS);
    row
}

// ---------------------------------------------------------------------------
// [D] Transaction validity — TxValidityAir (non-Poseidon half)
// ---------------------------------------------------------------------------

fn bench_tx_validity() -> AirRow {
    let air = TxValidityAir::new_3b4(TX_VALIDITY_3B4_LOG_ROWS);
    let body = mk_tx_body_1in1out(1000, 995, 5);
    let ins = [1000u64, 0, 0, 0];
    let outs = [995u64, 0, 0, 0, 0, 0, 0, 0];
    let trace = TxValidityAir::build_trace_3b4(&body, ins, outs, 5, TX_VALIDITY_3B4_LOG_ROWS);
    let n_tx = 1usize << (TX_VALIDITY_3B4_LOG_ROWS - BIT_ADDER_LOG_WORD_BITS);
    let row = bench_air(
        "TxValidityAir (non-Poseidon half: skeleton + BalanceGate)",
        Some(format!(
            "    tx slots: {n_tx}  |  embedded BalanceGate at col offset 10",
        )),
        air,
        trace,
        SAMPLES,
        || "TxValidityAir native check failed".to_string(),
    );
    assert_eq!(row.n_cols, TX_VALIDITY_3B4_N_COLS);
    row
}

// ---------------------------------------------------------------------------
// [E] TxBodyMerkleAir — prod path (with boundary pins)
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
        Some(format!(
            "    per-perm: {{prove, verify, proof}} / 59",
        )),
        air,
        trace,
        SAMPLES.min(3),
        || "TxBodyMerkleAir native check failed".to_string(),
    );
    assert_eq!(row.log_rows, TXBODY_MERKLE_LOG_ROWS);
    assert_eq!(row.n_cols, *TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS);
    row
}

fn bench_tx_body_merkle_legacy() -> AirRow {
    let air = TxBodyMerkleAir::new();
    let mut inputs = [[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS];
    for k in 0..TXBODY_MERKLE_N_PERMS {
        let s = (k as u128 + 1).wrapping_mul(0x9E3779B97F4A7C15);
        inputs[k] = [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
            Block128::from(s.wrapping_add(2) ^ 0xFFFF_0000_FFFF_0000),
            Block128::from(s.wrapping_add(3) ^ 0x0F0F_F0F0_0F0F_F0F0),
        ];
    }
    let trace = air.build_trace(&inputs);
    let row = bench_air(
        "TxBodyMerkleAir (interior-only, no boundary pins — regression baseline)",
        None,
        air,
        trace,
        SAMPLES.min(3),
        || "TxBodyMerkleAir (interior) native check failed".to_string(),
    );
    assert_eq!(row.n_cols, *TXBODY_MERKLE_N_COLS);
    row
}

// ---------------------------------------------------------------------------
// [P] TxBodySpineComposite — full per-tx prover path
// ---------------------------------------------------------------------------

fn bench_spine_composite() -> AirRow {
    // Derive consistent pins by running the honest permutation chain
    // against a zero input set and reading back `tx_body_hash`.
    let inputs: Box<[[Block128; 4]; TXBODY_MERKLE_N_PERMS]> =
        Box::new([[Block128::ZERO; 4]; TXBODY_MERKLE_N_PERMS]);
    let placeholder = TxBodyMerkleBoundaryPins::default();
    let seed_cols = noid_air::build_tx_body_merkle_trace_with_boundary_pins(&inputs, &placeholder);
    let layout = noid_air::build_instance_layout();
    let wrap_out_row = layout[58].slot_base_row + 66;
    let s_base = noid_air::TXBODY_MERKLE_LAYOUT.s;
    let pins = TxBodyMerkleBoundaryPins {
        tx_body_hash: [seed_cols[s_base][wrap_out_row], seed_cols[s_base + 1][wrap_out_row]],
        ..TxBodyMerkleBoundaryPins::default()
    };

    let spine = TxBodySpineComposite::new(pins);
    let body = TxBody {
        prev_state_root: [0u8; 32],
        new_state_root: [0u8; 32],
        fee: 0,
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    let trace = spine.build_trace(&body, [0u64; 4], [0u64; 8], 0u64, &inputs);

    let row = bench_air(
        "TxBodySpineComposite (PROD: TxValidity + TxBodyMerkle + cross-AIR ties)",
        Some(
            "    this is the per-tx client prover path"
                .to_string(),
        ),
        spine,
        trace,
        SAMPLES.min(3),
        || "TxBodySpineComposite native check failed".to_string(),
    );
    assert_eq!(row.log_rows, SPINE_LOG_ROWS);
    row
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
    println!("    [A] Engine scaling primitives   (CarryRipple / Range / LinearCombination)");
    println!("    [B] Balance gate                (BalanceGate, per-tx)");
    println!("    [C] Poseidon2b hashes           (Perm / HAddr / HAuth / HLeaf)");
    println!("    [D] Transaction validity        (TxValidity, non-Poseidon half)");
    println!("    [E] Transaction-body Merkle     (TxBodyMerkle, with boundary pins)");
    println!("    [P] PROD per-tx prover path     (TxBodySpineComposite)");
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
        "  PROD per-tx prover:  prove={}  verify={}  proof≈{}",
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

    // ---- Run all benches (eprintln progress so long sweeps are visible) ----
    eprintln!("  [A] primitive scaling ...");
    let mut carry_rows = Vec::with_capacity(CARRY_SHAPES.len());
    for (label, log_rows) in CARRY_SHAPES {
        eprintln!("        carry  ({label}, log_rows={log_rows}) ...");
        carry_rows.push(bench_carry(label, *log_rows));
    }
    let mut range_rows = Vec::with_capacity(RANGE_SHAPES.len());
    for (label, log_rows) in RANGE_SHAPES {
        eprintln!("        range  ({label}, log_rows={log_rows}) ...");
        range_rows.push(bench_range(label, *log_rows));
    }
    let mut lin_rows = Vec::with_capacity(LINCOMB_SHAPES.len());
    for &(lr, nc) in LINCOMB_SHAPES {
        eprintln!("        lincomb  (log_rows={lr}, n_cols={nc}) ...");
        lin_rows.push(bench_linear(lr, nc));
    }

    eprintln!("  [B] balance gate ...");
    let mut bal_rows = Vec::with_capacity(BALANCE_SHAPES.len());
    for (label, log_rows) in BALANCE_SHAPES {
        eprintln!("        balance  ({label}, log_rows={log_rows}) ...");
        bal_rows.push(bench_balance(label, *log_rows));
    }

    eprintln!("  [C] Poseidon2b ...");
    let perm_row = bench_poseidon_perm();
    let haddr_row = bench_haddr();
    let hauth_row = bench_hauth();
    let hleaf_row = bench_hleaf();

    eprintln!("  [D] tx validity ...");
    let txv_row = bench_tx_validity();

    eprintln!("  [E] tx body merkle ...");
    let merkle_legacy = bench_tx_body_merkle_legacy();
    let merkle_prod = bench_tx_body_merkle();

    eprintln!("  [P] spine composite (prod) ...");
    let spine_row = bench_spine_composite();
    eprintln!();

    // ---- Render ----
    print_section("[A] Engine scaling primitives");
    for r in &carry_rows { print_row("A.carry  ", r); }
    for r in &range_rows { print_row("A.range  ", r); }
    for r in &lin_rows   { print_row("A.lincomb", r); }

    print_section("[B] Balance gate");
    for r in &bal_rows   { print_row("B.bal    ", r); }

    print_section("[C] Poseidon2b hashes");
    print_row("C.perm   ", &perm_row);
    print_row("C.haddr  ", &haddr_row);
    print_row("C.hauth  ", &hauth_row);
    print_row("C.hleaf  ", &hleaf_row);

    print_section("[D] Transaction validity");
    print_row("D.txv    ", &txv_row);

    print_section("[E] Transaction-body Merkle");
    print_row("E.legacy ", &merkle_legacy);
    print_row("E.prod   ", &merkle_prod);

    print_section("[P] PROD — per-tx prover path");
    print_row("P.spine  ", &spine_row);

    print_footer(&spine_row);
}
