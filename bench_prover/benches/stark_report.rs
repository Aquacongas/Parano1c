// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::manual_memcpy)]

//! Paranoid STARK report — **Transparent UTXO Validity Engine**.
//!
//!   cargo bench --bench stark_report
//!
//! Measures the per-tx client prover path: full `prove_tx` / `verify_tx`
//! production pipeline with component breakdown for optimization.

use std::time::{Duration, Instant};

use noid_air::{Air, Trace};
use noid_core::mle::evaluate::evaluate_slice;
use noid_core::mle::split::split_mle_into_slices;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::code::LOG_RATE;
use noid_gkr::{
    build_auth_unified_from_inputs, build_boundary_mle, compute_auth_boundary,
    compute_tx_body_hash, prove_auth_killshot, prove_spine_killshot, reconstruct_slot_states,
    verify_auth_killshot, verify_spine_killshot, AuthCircuit, AuthInputs, AuthProofKillShot,
    SpineCircuit, SpineInputs, SpineProofKillShot, N_AUTH_INPUTS, N_AUTH_UNIFIED_VARS,
    N_BOUNDARY_VARS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_stark::interleaved::{prove_air_interleaved, verify_air_interleaved};
use noid_stark::prove_tx::{prove_tx, verify_tx, TxWitness};
use noid_stark::{
    pad_column, padded_log_len, prove_air_timed, verify_air_timed, ProveTimings, VerifyTimings,
};
use noid_tx::PublicInputs;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

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
// Fixtures
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
    let all_secrets = [
        mk_secret(0xA1),
        mk_secret(0xB2),
        mk_secret(0xC3),
        mk_secret(0xD4),
    ];
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

struct ProdRow {
    prove: Duration,
    verify: Duration,
    proof_bytes: usize,
    log_rows: usize,
    n_cols: usize,
    n_shifted: usize,
    spine_proof_bytes: usize,
    auth_proof_bytes: usize,
    stark_proof_bytes: usize,
    spine_prove: Duration,
    spine_verify: Duration,
    auth_prove: Duration,
    auth_verify: Duration,
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
        verify_tx(air, &pi, &spine_inputs, &auth_inputs, &tx_proof).expect("verify_tx");
    });

    // -----------------------------------------------------------------------
    // Isolated: SpineGKR Kill-Shot
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
        let _ = verify_spine_killshot(
            &spine_proof,
            &spine_circuit,
            &spine_inputs,
            claimed,
            &mut ch_v,
        )
        .expect("spine kill-shot verify");
    });

    // -----------------------------------------------------------------------
    // Isolated: AuthGKR Kill-Shot
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
        let _ = verify_auth_killshot(
            &auth_proof_standalone,
            &auth_circuit,
            &auth_inputs,
            &mut ch_v,
        )
        .expect("auth kill-shot verify");
    });

    // -----------------------------------------------------------------------
    // Isolated: STARK (interleaved path, production 297-col)
    // -----------------------------------------------------------------------
    let log_len = padded_log_len(air.log_rows());
    let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);

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

    let col_refs: Vec<&[Block128]> = all_columns.iter().map(|c| c.as_slice()).collect();
    let (pre_commitment, pre_state) = noid_fri_binius::interleaved_commit(
        &col_refs,
        &ntt,
        &noid_fri::hasher::Blake3Hasher::new(),
    );

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

    let mut slice_claims = Vec::with_capacity(n_boundary_slices);
    for (i, &val) in spine_slice_values.iter().enumerate() {
        slice_claims.push(noid_stark::SliceClaim {
            col_index: n_air_cols + i,
            eval_point: spine_r_low.clone(),
            value: val,
        });
    }
    for (i, &val) in auth_slice_values.iter().enumerate() {
        slice_claims.push(noid_stark::SliceClaim {
            col_index: n_air_cols + spine_slices.len() + i,
            eval_point: auth_r_low.clone(),
            value: val,
        });
    }

    // Fake extras transcript for isolated STARK measurement
    let extras_transcript: Vec<Block128> = (0..30)
        .map(|i| Block128::from((i * 13 + 7) as u128))
        .collect();

    let stark_prove = time(|| {
        let _ = prove_air_interleaved(
            air,
            &all_columns,
            &pi,
            &extras_transcript,
            &slice_claims,
            log_len,
            None,
        );
    });

    let stark_proof = {
        prove_air_interleaved(
            air,
            &all_columns,
            &pi,
            &extras_transcript,
            &slice_claims,
            log_len,
            Some((pre_commitment, pre_state)),
        )
    };

    let stark_verify = time(|| {
        verify_air_interleaved(air, &pi, &stark_proof, &extras_transcript, &slice_claims)
            .expect("STARK interleaved verify");
    });

    // Bucket breakdown (approximation via 291-col timed path)
    let stark_prove_buckets = collect_prove_buckets(air, &trace, &pi, SAMPLES);
    let stark_verify_buckets = collect_verify_buckets(
        air,
        &pi,
        &{
            let _ = prove_air_timed(air, &trace, &pi).unwrap();
            prove_air_timed(air, &trace, &pi).unwrap().0
        },
        SAMPLES,
    );

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
    proof: &noid_stark::StarkProof,
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

fn print_prod_row(r: &ProdRow) {
    println!("  prove_tx / verify_tx  (single-transcript orchestrator)");
    println!("  +------------------------------------------------------------------------------+");
    println!(
        "  | trace: log_rows={:>3}  columns={:>4}  shifted={:>2}                              |",
        r.log_rows, r.n_cols, r.n_shifted,
    );
    println!("  | fixture: 2 live inputs, 4 live outputs, fee=50, balance=150                   |",);
    println!("  +------------------------------------------------------------------------------+");
    println!();
    println!(
        "    TOTAL prove      {}    (end-to-end prove_tx)",
        fmt_ms(r.prove)
    );
    println!(
        "    TOTAL verify     {}    (end-to-end verify_tx)",
        fmt_ms(r.verify)
    );
    println!(
        "    TOTAL proof      {}    (wire size)",
        fmt_bytes(r.proof_bytes)
    );
    println!();
    println!("    Targets:  prove < 500 ms  |  verify < 50 ms  |  proof < 60 KB");
    println!();

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
    println!(
        "      Proves: tx_body_hash = Poseidon2b-Merkle(input_leaves, output_leaves, fee, ...)"
    );
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
    println!(
        "      Circuit: {} inputs x 5 perms = {} Poseidon2b permutations (66 rounds each)",
        N_AUTH_INPUTS,
        N_AUTH_INPUTS * 5
    );
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

    eprintln!("  production prove_tx / verify_tx (+ component breakdown) ...");
    let prod_row = bench_production();
    eprintln!();

    print_section("PRODUCTION: prove_tx / verify_tx (per-tx mainnet path)");
    print_prod_row(&prod_row);

    println!("  Reproduce: cargo bench --bench stark_report");
    println!();
}
