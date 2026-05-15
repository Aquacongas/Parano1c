// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Paranoid STARK report — **Transparent UTXO Validity Engine**.
//!
//!   cargo bench --bench stark_report
//!
//! Measures the per-tx client prover path: full `prove_tx` / `verify_tx`
//! production pipeline with component breakdown for optimization.

use std::time::{Duration, Instant};

use noid_air::{
    build_perm_trace, emit_perm_all, Air, CompositeAir, RangeGateAir, Trace,
    POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS,
};
use noid_core::mle::evaluate::evaluate_slice;
use noid_core::mle::split::split_mle_into_slices;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::code::{LOG_RATE, RATE};
use noid_fri::prover::commit_fast;
use noid_fri::{NUM_QUERIES, TAU};
use noid_gkr::{
    build_auth_unified_from_inputs, build_boundary_mle, compute_auth_boundary,
    compute_tx_body_hash, prove_auth_killshot, prove_spine_killshot,
    reconstruct_slot_states, verify_auth_killshot, verify_spine_killshot, AuthCircuit,
    AuthInputs, AuthProofKillShot, SpineCircuit, SpineInputs, SpineProofKillShot,
    N_AUTH_INPUTS, N_AUTH_UNIFIED_VARS, N_BOUNDARY_VARS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_stark::{
    pad_column, padded_log_len, prove_air, prove_air_timed, prove_air_with_slices,
    verify_air_timed, verify_air_with_slices, ProveTimings, SliceClaim, StarkProof,
    VerifyTimings,
};
use noid_tx::{PublicInputs, MAX_INPUTS, MAX_OUTPUTS};
use noid_stark::prove_tx::{prove_tx, verify_tx, TxWitness};

use noid_poseidon2b::primitives::TxBodyHash;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

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
// Component AIR metrics (engine scaling / Poseidon perm)
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
// Poseidon2b — single permutation micro-baseline
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
// Production: prove_tx / verify_tx — with full component breakdown
//
// prove_tx orchestrates three components in a single transcript:
//   1. SpineGKR Kill-Shot  — 59 Poseidon2b perms, tx-body Merkle spine
//   2. AuthGKR Kill-Shot   — 4 inputs x 5 perms (H_ADDR + H_AUTH)
//   3. STARK               — balance, range, FRI state, boundary bridges
//
// The bench isolates each component so time/size attribution is precise.
// ---------------------------------------------------------------------------

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
    use noid_air::composition::tx_validity_with_spine::fixture::mk_secret;

    let circuit = AuthCircuit::build();
    let pi = comp.public_inputs();
    let n_live = pi.n_live_inputs as usize;
    let all_secrets = [mk_secret(0xA1), mk_secret(0xB2), mk_secret(0xC3), mk_secret(0xD4)];
    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for i in 0..n_live {
        spend_secret[i] = all_secrets[i];
    }
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

struct ProdRow {
    // End-to-end totals
    prove: Duration,
    verify: Duration,
    proof_bytes: usize,
    // Trace parameters
    log_rows: usize,
    n_cols: usize,
    n_shifted: usize,
    // Proof size per component
    spine_proof_bytes: usize,
    auth_proof_bytes: usize,
    stark_proof_bytes: usize,
    // SpineGKR Kill-Shot (isolated)
    spine_prove: Duration,
    spine_verify: Duration,
    // AuthGKR Kill-Shot (isolated)
    auth_prove: Duration,
    auth_verify: Duration,
    // STARK (isolated, with bucket breakdown)
    stark_prove: Duration,
    stark_verify: Duration,
    stark_prove_buckets: ProveTimings,
    stark_verify_buckets: VerifyTimings,
}

fn bench_production() -> ProdRow {
    use noid_air::composition::tx_validity_with_spine::fixture;

    let comp = fixture::build_honest_realistic();
    let pi = comp.public_inputs();
    comp.assert_public_inputs_consistent(&pi);
    let trace = comp.build_trace();
    let air = comp.air();
    let spine_inputs = spine_inputs_from_composite(&comp);
    let auth_inputs = auth_inputs_from_composite(&comp);

    assert!(air.check(&trace), "production fixture native check failed");

    // -----------------------------------------------------------------------
    // End-to-end: prove_tx / verify_tx
    // -----------------------------------------------------------------------
    let witness = TxWitness {
        air,
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_inputs: &auth_inputs,
    };

    let prove = time(|| {
        let w = TxWitness {
            air,
            trace: &trace,
            pi: &pi,
            spine_inputs: &spine_inputs,
            auth_inputs: &auth_inputs,
        };
        let _ = prove_tx(&w).expect("prove_tx");
    });

    let tx_proof = prove_tx(&witness).expect("prove_tx for verify");
    let proof_bytes = tx_proof.estimated_byte_len();
    let spine_proof_bytes = tx_proof.spine.byte_len();
    let auth_proof_bytes = tx_proof.auth.byte_len();
    let stark_proof_bytes = proof_bytes - spine_proof_bytes - auth_proof_bytes;

    let verify = time(|| {
        verify_tx(air, &pi, &spine_inputs, &auth_inputs, &tx_proof)
            .expect("verify_tx");
    });

    // -----------------------------------------------------------------------
    // Isolated: SpineGKR Kill-Shot
    //   59 Poseidon2b permutations, hypercube dim=15, cells=32768
    //   Computes: tx_body_hash = Merkle(leaves) via GKR sumcheck
    // -----------------------------------------------------------------------
    let spine_circuit = SpineCircuit::build();
    let claimed = compute_tx_body_hash(&spine_circuit, &spine_inputs);

    let spine_prove = time(|| {
        let mut ch = Poseidon2bChannel::new();
        let _: (SpineProofKillShot, _) =
            prove_spine_killshot(&spine_circuit, &spine_inputs, claimed, &mut ch);
    });

    let mut ch_p = Poseidon2bChannel::new();
    let (spine_proof, _) = prove_spine_killshot(&spine_circuit, &spine_inputs, claimed, &mut ch_p);

    let spine_verify = time(|| {
        let mut ch_v = Poseidon2bChannel::new();
        let _ = verify_spine_killshot(&spine_proof, &spine_circuit, &spine_inputs, claimed, &mut ch_v)
            .expect("spine kill-shot verify");
    });

    // -----------------------------------------------------------------------
    // Isolated: AuthGKR Kill-Shot
    //   4 inputs x 5 perms = 20 Poseidon2b permutations
    //   Hypercube dim=14, cells=16384
    //   Per input: H_ADDR(secret) -> address, H_AUTH(secret, tx_body_hash) -> auth_tag
    // -----------------------------------------------------------------------
    let auth_circuit = AuthCircuit::build();

    let auth_prove = time(|| {
        let mut ch = Poseidon2bChannel::new();
        let _: (AuthProofKillShot, _) = prove_auth_killshot(&auth_circuit, &auth_inputs, &mut ch);
    });

    let mut ch_a = Poseidon2bChannel::new();
    let (auth_proof_standalone, _) = prove_auth_killshot(&auth_circuit, &auth_inputs, &mut ch_a);

    let auth_verify = time(|| {
        let mut ch_v = Poseidon2bChannel::new();
        let _ = verify_auth_killshot(&auth_proof_standalone, &auth_circuit, &auth_inputs, &mut ch_v)
            .expect("auth kill-shot verify");
    });

    // -----------------------------------------------------------------------
    // Isolated: STARK with slice columns (production 297-col path)
    //   log_rows=13, 291 AIR columns + 6 boundary slices = 297 total
    //   Proves: BalanceGate (UTXO conservation), RangeGate (u64 decomp),
    //           FriStateCombiner, FriStateOpen (input/output),
    //           TxBodyHash boundary pins, coinbase gate,
    //           + 6 slice column openings at GKR reduction points
    // -----------------------------------------------------------------------
    let log_len = padded_log_len(air.log_rows());
    let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);

    // Build slice columns (mirrors prove_tx Stage 1)
    let spine_states = reconstruct_slot_states(&spine_circuit, &spine_inputs);
    let spine_boundary_mle = build_boundary_mle(&spine_states);
    let spine_slices = split_mle_into_slices(&spine_boundary_mle, N_BOUNDARY_VARS, log_len);
    let auth_unified_mle = build_auth_unified_from_inputs(&auth_circuit, &auth_inputs);
    let auth_slices = split_mle_into_slices(&auth_unified_mle.state, N_AUTH_UNIFIED_VARS, log_len);

    let n_air_cols = trace.columns.len();
    let n_boundary_slices = spine_slices.len() + auth_slices.len();

    let mut all_columns: Vec<Vec<Block128>> = Vec::with_capacity(n_air_cols + n_boundary_slices);
    for col in &trace.columns {
        all_columns.push(pad_column(col, log_len));
    }
    for s in &spine_slices {
        all_columns.push(s.clone());
    }
    for s in &auth_slices {
        all_columns.push(s.clone());
    }

    let commitments: Vec<_> = {
        use rayon::prelude::*;
        all_columns
            .par_iter()
            .map(|col| commit_fast(col, &ntt))
            .collect()
    };

    // Build slice claims (mirrors prove_tx Stage 4)
    let spine_r_low: Vec<Block128> = (0..log_len)
        .map(|b| Block128::from(((b * 7 + 3) % 128) as u128))
        .collect();
    let auth_r_low: Vec<Block128> = (0..log_len)
        .map(|b| Block128::from(((b * 11 + 5) % 128) as u128))
        .collect();
    let spine_slice_values: Vec<Block128> = spine_slices
        .iter()
        .map(|s| evaluate_slice(s, &spine_r_low))
        .collect();
    let auth_slice_values: Vec<Block128> = auth_slices
        .iter()
        .map(|s| evaluate_slice(s, &auth_r_low))
        .collect();

    let mut slice_claims: Vec<SliceClaim> = Vec::with_capacity(n_boundary_slices);
    for (i, &val) in spine_slice_values.iter().enumerate() {
        slice_claims.push(SliceClaim {
            col_index: n_air_cols + i,
            eval_point: spine_r_low.clone(),
            value: val,
        });
    }
    for (i, &val) in auth_slice_values.iter().enumerate() {
        slice_claims.push(SliceClaim {
            col_index: n_air_cols + spine_slices.len() + i,
            eval_point: auth_r_low.clone(),
            value: val,
        });
    }

    // Measure STARK with slices (total time, including commit)
    let stark_prove = time(|| {
        let ntt_inner = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);
        let commits: Vec<_> = {
            use rayon::prelude::*;
            all_columns
                .par_iter()
                .map(|col| commit_fast(col, &ntt_inner))
                .collect()
        };
        let _ = prove_air_with_slices(
            air, &all_columns, &commits, &pi, &[], &slice_claims, log_len,
        );
    });
    let stark_proof = prove_air_with_slices(
        air, &all_columns, &commitments, &pi, &[], &slice_claims, log_len,
    );

    let stark_verify = time(|| {
        verify_air_with_slices(air, &pi, &stark_proof, &[], &slice_claims)
            .expect("STARK verify with slices");
    });

    // Bucket breakdown (approximation via 291-col timed path)
    let stark_prove_buckets = collect_prove_buckets(air, &trace, &pi, SAMPLES);
    let stark_verify_buckets = collect_verify_buckets(air, &pi, &{
        prove_air(air, &trace, &pi).unwrap()
    }, SAMPLES);

    let n_shifted = air.shifted_column_indices().len();

    ProdRow {
        prove,
        verify,
        proof_bytes,
        log_rows: air.log_rows(),
        n_cols: n_air_cols + n_boundary_slices,
        n_shifted,
        spine_proof_bytes,
        auth_proof_bytes,
        stark_proof_bytes,
        spine_prove,
        spine_verify,
        auth_prove,
        auth_verify,
        stark_prove,
        stark_verify,
        stark_prove_buckets,
        stark_verify_buckets,
    }
}

fn print_prod_row(r: &ProdRow) {
    // --- Headline: end-to-end totals ---
    println!("  prove_tx / verify_tx  (single-transcript orchestrator)");
    println!("  +------------------------------------------------------------------------------+");
    println!(
        "  | trace: log_rows={:>3}  columns={:>4}  shifted={:>2}                              |",
        r.log_rows, r.n_cols, r.n_shifted,
    );
    println!(
        "  | fixture: 2 live inputs, 4 live outputs, fee=50, balance=150                   |",
    );
    println!("  +------------------------------------------------------------------------------+");
    println!();
    println!("    TOTAL prove      {}    (end-to-end prove_tx)", fmt_ms(r.prove));
    println!("    TOTAL verify     {}    (end-to-end verify_tx)", fmt_ms(r.verify));
    println!("    TOTAL proof      {}    (wire size)", fmt_bytes(r.proof_bytes));
    println!();
    println!("    Targets:  prove < 300 ms  |  verify < 30 ms  |  proof < 250 KB");
    println!();

    // --- Component breakdown ---
    let sum_prove = r.stark_prove + r.spine_prove + r.auth_prove;
    let sum_verify = r.stark_verify + r.spine_verify + r.auth_verify;
    let sum_bytes = r.stark_proof_bytes + r.spine_proof_bytes + r.auth_proof_bytes;

    println!("  ============================================================================");
    println!("  Component breakdown (isolated measurements, sum -> end-to-end)");
    println!("  ============================================================================");
    println!();

    // --- STARK ---
    println!("  [1] STARK — Binius-style over GF(2^128), production 297-col path");
    println!("      Constraints: BalanceGate (UTXO conservation), RangeGate (u64 bit-decomp),");
    println!("                   FriStateCombiner, FriStateOpen (in/out), TxBodyHash pins,");
    println!("                   coinbase gate, activation/deactivation selectors,");
    println!("                   + 6 boundary-slice columns (4 spine + 2 auth)");
    println!(
        "      Parameters:  log_rows={}  columns={}  shifted={}",
        r.log_rows, r.n_cols, r.n_shifted,
    );
    println!();
    println!(
        "      prove     {}  ({:>5.1}% of sum)",
        fmt_ms(r.stark_prove),
        percent(r.stark_prove, sum_prove),
    );
    println!(
        "      verify    {}  ({:>5.1}% of sum)",
        fmt_ms(r.stark_verify),
        percent(r.stark_verify, sum_verify),
    );
    println!(
        "      size      {}  ({:>5.1}% of sum)",
        fmt_bytes(r.stark_proof_bytes),
        100.0 * r.stark_proof_bytes as f64 / sum_bytes as f64,
    );
    println!();

    // STARK prover buckets (291-col approximation for sub-bucket breakdown)
    let ptot = r.stark_prove_buckets.total();
    println!("      prover buckets (approx, 291-col breakdown):");
    println!(
        "        commit (Merkle)        {}  ({:>5.1}%)",
        fmt_ms(r.stark_prove_buckets.commit),
        percent(r.stark_prove_buckets.commit, ptot),
    );
    println!(
        "        zero-check sumcheck    {}  ({:>5.1}%)",
        fmt_ms(r.stark_prove_buckets.transcript_sumcheck),
        percent(r.stark_prove_buckets.transcript_sumcheck, ptot),
    );
    println!(
        "        shift ladder sumcheck  {}  ({:>5.1}%)",
        fmt_ms(r.stark_prove_buckets.ladder_sumcheck),
        percent(r.stark_prove_buckets.ladder_sumcheck, ptot),
    );
    println!(
        "        multipoint + FRI       {}  ({:>5.1}%)",
        fmt_ms(r.stark_prove_buckets.multipoint_fri),
        percent(r.stark_prove_buckets.multipoint_fri, ptot),
    );
    let mpt = r.stark_prove_buckets.multipoint_fri;
    println!("          multipoint sub-buckets:");
    println!(
        "            setup + pairs      {}  ({:>5.1}% of mp)",
        fmt_ms(r.stark_prove_buckets.mp_setup_pairs),
        percent(r.stark_prove_buckets.mp_setup_pairs, mpt),
    );
    println!(
        "            mp sumcheck        {}  ({:>5.1}% of mp)",
        fmt_ms(r.stark_prove_buckets.mp_sumcheck),
        percent(r.stark_prove_buckets.mp_sumcheck, mpt),
    );
    println!(
        "            batched FRI        {}  ({:>5.1}% of mp)",
        fmt_ms(r.stark_prove_buckets.mp_fri),
        percent(r.stark_prove_buckets.mp_fri, mpt),
    );
    println!();

    // STARK verifier buckets
    let vtot = r.stark_verify_buckets.total();
    println!("      verifier buckets (approx, 291-col breakdown):");
    println!(
        "        transcript sumcheck    {}  ({:>5.1}%)",
        fmt_ms(r.stark_verify_buckets.transcript_sumcheck),
        percent(r.stark_verify_buckets.transcript_sumcheck, vtot),
    );
    println!(
        "        composition check      {}  ({:>5.1}%)",
        fmt_ms(r.stark_verify_buckets.composition),
        percent(r.stark_verify_buckets.composition, vtot),
    );
    println!(
        "        shift ladder sumcheck  {}  ({:>5.1}%)",
        fmt_ms(r.stark_verify_buckets.ladder_sumcheck),
        percent(r.stark_verify_buckets.ladder_sumcheck, vtot),
    );
    println!(
        "        multipoint + FRI       {}  ({:>5.1}%)",
        fmt_ms(r.stark_verify_buckets.multipoint_fri),
        percent(r.stark_verify_buckets.multipoint_fri, vtot),
    );
    println!();

    // --- SpineGKR Kill-Shot ---
    println!("  [2] SpineGKR Kill-Shot — tx-body Merkle spine via GKR");
    println!("      Circuit: 59 Poseidon2b permutations (66 rounds each)");
    println!("      Hypercube: dim=15, cells=32768, layout=[elem:2|round:7|slot:6]");
    println!("      Proves: tx_body_hash = Poseidon2b-Merkle(input_leaves, output_leaves, fee, ...)");
    println!("      Protocol: unified sumcheck -> shift gadget -> 3x batch_eval reductions");
    println!();
    println!(
        "      prove     {}  ({:>5.1}% of sum)",
        fmt_ms(r.spine_prove),
        percent(r.spine_prove, sum_prove),
    );
    println!(
        "      verify    {}  ({:>5.1}% of sum)",
        fmt_ms(r.spine_verify),
        percent(r.spine_verify, sum_verify),
    );
    println!(
        "      size      {}  ({:>5.1}% of sum)",
        fmt_bytes(r.spine_proof_bytes),
        100.0 * r.spine_proof_bytes as f64 / sum_bytes as f64,
    );
    println!();

    // --- AuthGKR Kill-Shot ---
    println!("  [3] AuthGKR Kill-Shot — spend authorization via GKR");
    println!("      Circuit: {} inputs x 5 perms = {} Poseidon2b permutations (66 rounds each)", N_AUTH_INPUTS, N_AUTH_INPUTS * 5);
    println!("      Hypercube: dim=14, cells=16384, layout=[elem:2|round:7|slot:5]");
    println!("      Per input: H_ADDR(secret)->address, H_AUTH(secret,tx_body_hash)->auth_tag");
    println!("      Protocol: unified sumcheck -> shift gadget -> 3x batch_eval reductions");
    println!();
    println!(
        "      prove     {}  ({:>5.1}% of sum)",
        fmt_ms(r.auth_prove),
        percent(r.auth_prove, sum_prove),
    );
    println!(
        "      verify    {}  ({:>5.1}% of sum)",
        fmt_ms(r.auth_verify),
        percent(r.auth_verify, sum_verify),
    );
    println!(
        "      size      {}  ({:>5.1}% of sum)",
        fmt_bytes(r.auth_proof_bytes),
        100.0 * r.auth_proof_bytes as f64 / sum_bytes as f64,
    );
    println!();

    // --- Sum check ---
    println!("  ----------------------------------------------------------------------------");
    println!(
        "  SUM (isolated)   prove {}   verify {}   size {}",
        fmt_ms(sum_prove),
        fmt_ms(sum_verify),
        fmt_bytes(sum_bytes),
    );
    println!(
        "  END-TO-END       prove {}   verify {}   size {}",
        fmt_ms(r.prove),
        fmt_ms(r.verify),
        fmt_bytes(r.proof_bytes),
    );
    let overhead_prove = r.prove.saturating_sub(sum_prove);
    let overhead_verify = r.verify.saturating_sub(sum_verify);
    println!(
        "  OVERHEAD         prove {}   verify {}   (transcript glue, boundary commits)",
        fmt_ms(overhead_prove),
        fmt_ms(overhead_verify),
    );
    println!();
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

const BANNER: &str = r#"
   ____   _    ____      _    _   _  ___ ___ ____
  |  _ \ / \  |  _ \    / \  | \ | |/ _ \_ _|  _ \
  | |_) / _ \ | |_) |  / _ \ |  \| | | | | || | | |
  |  __/ ___ \|  _ <  / ___ \| |\  | |_| | || |_| |
  |_| /_/   \_\_| \_\/_/   \_\_| \_|\___/___|____/

  PARANOID  --  Transparent UTXO Validity Engine
  Binius-style STARK over GF(2^128) + GKR Kill-Shot. Per-tx client-side proof.
"#;

fn print_banner() {
    println!("{}", BANNER);
    println!(
        "  Wall-clock medians, release profile. Warmup: {} / Samples: {}.",
        WARMUP, SAMPLES
    );
    println!();
}

fn print_section(title: &str) {
    println!("==========================================================================");
    println!("  {title}");
    println!("==========================================================================");
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

    eprintln!("  Poseidon2b perm ...");
    let perm_row = bench_poseidon_perm();

    eprintln!("  production prove_tx / verify_tx (+ component breakdown) ...");
    let prod_row = bench_production();
    eprintln!();

    print_section("Engine scaling (RangeGateAir — u64 bit-decomposition)");
    for r in &range_rows {
        print_row("range", r);
    }

    print_section("Poseidon2b single-permutation (66 rounds, micro-baseline)");
    print_row("perm ", &perm_row);

    print_section("PRODUCTION: prove_tx / verify_tx (per-tx mainnet path)");
    print_prod_row(&prod_row);

    println!("  Reproduce: cargo bench --bench stark_report");
    println!();
}
