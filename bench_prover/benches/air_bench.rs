// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! End-to-end AIR + STARK + IVC benchmark.
//!
//! Reports wall-clock timings for:
//!
//!   - TxValidityAir prove / verify (one tx)
//!   - LinearCombinationAir prove / verify at several trace sizes
//!   - IVC fold_step_prove + decide over a batch of folded columns
//!
//! Run with:  cargo bench --bench air_bench

use std::time::{Duration, Instant};

use noid_air::{Air, LinearCombinationAir, Trace, TxValidityAir};
use noid_core::{Block128, TowerField};
use noid_ivc::{decide, fold_step_prove, Accumulator};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::{padded_log_len, prove_air, verify_air};
use noid_tx::{PublicInputs, TxBody, TxInput, TxOutput};

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

const SAMPLES: usize = 5;
const WARMUP: usize = 1;

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

fn fmt(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1_000.0;
    if ms >= 1_000.0 {
        format!("{:>9.2} s ", ms / 1_000.0)
    } else if ms >= 1.0 {
        format!("{:>9.2} ms", ms)
    } else {
        format!("{:>9.2} us", ms * 1_000.0)
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn mk_pi() -> PublicInputs {
    PublicInputs {
        prev_state_root: [0x11; 32],
        new_state_root: [0x22; 32],
        nullifier_root: [0x33; 32],
        tx_body_hash: TxBodyHash([0x44; 32]),
        fee: 7,
    }
}

fn mk_body() -> TxBody {
    TxBody {
        prev_state_root: [0u8; 32],
        new_state_root: [0u8; 32],
        nullifier_root: [0u8; 32],
        fee: 0,
        inputs: vec![TxInput::dummy(), TxInput::dummy()],
        outputs: vec![TxOutput::dummy(), TxOutput::dummy()],
    }
}

fn mk_linear_trace(log_rows: usize, n_cols: usize) -> Trace {
    let n = 1 << log_rows;
    let mut cols: Vec<Vec<Block128>> = (0..n_cols - 1)
        .map(|c| {
            (0..n)
                .map(|i| Block128::from((i as u128).wrapping_mul(c as u128 + 1) ^ 0xABCD))
                .collect()
        })
        .collect();
    // Last column cancels the rest so the XOR-linear gate is satisfied.
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
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_tx_validity() {
    let air = TxValidityAir::new();
    let trace = TxValidityAir::build_trace(&mk_body());
    let pi = mk_pi();
    let prove_ms = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    let proof = prove_air(&air, &trace, &pi).unwrap();
    let verify_ms = time(|| {
        verify_air(&air, &pi, &proof).unwrap();
    });
    println!(
        "  TxValidityAir (1 col, log_rows=4):   prove {}   verify {}",
        fmt(prove_ms),
        fmt(verify_ms)
    );
}

fn bench_linear_air(log_rows: usize, n_cols: usize) {
    let air = LinearCombinationAir::new(n_cols, log_rows);
    let trace = mk_linear_trace(log_rows, n_cols);
    assert!(air.check(&trace));
    let pi = mk_pi();
    let prove_ms = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    let proof = prove_air(&air, &trace, &pi).unwrap();
    let verify_ms = time(|| {
        verify_air(&air, &pi, &proof).unwrap();
    });
    println!(
        "  LinearAir (n_cols={}, log_rows={:>2}): prove {}   verify {}",
        n_cols,
        log_rows,
        fmt(prove_ms),
        fmt(verify_ms)
    );
}

fn bench_ivc(log_rows: usize, steps: usize) {
    let log_len = padded_log_len(log_rows);
    let z: Vec<Block128> = (0..log_len)
        .map(|i| Block128::from(0xC0DEu128 << i))
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
    println!(
        "  IVC (log_rows={:>2}, steps={:>3}):       fold {}   decide {}",
        log_rows,
        steps,
        fmt(fold_ms),
        fmt(decide_ms)
    );
}

fn main() {
    println!();
    println!("  PARANOID -- AIR + STARK + IVC benchmarks");
    println!();
    bench_tx_validity();
    println!();
    for (log_rows, n_cols) in [(4usize, 3usize), (8, 3), (12, 3), (14, 4)] {
        bench_linear_air(log_rows, n_cols);
    }
    println!();
    for (log_rows, steps) in [(8usize, 4usize), (10, 8), (12, 16)] {
        bench_ivc(log_rows, steps);
    }
    println!();
}
