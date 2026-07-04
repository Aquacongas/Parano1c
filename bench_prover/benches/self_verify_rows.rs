// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Row-count measurement for the recursion slot: how many FieldR1cs
//! constraints does the in-trace FieldR1cs verifier replay
//! (`trace::self_verify::verify_field_trace`) cost, as a function of the
//! verified instance size and the PCS code rate?
//!
//! The verified instance is a synthetic satisfiable FieldR1cs shaped like a
//! verifier-replay trace (1–4 nonzeros per matrix row, strictly
//! lower-triangular). Reported per case:
//! - the [R] trace row count and its per-phase split (statement+zerocheck /
//!   lincheck / PCS),
//! - the nonzero 64×64 block count of the verified matrices (the lincheck
//!   bilinear replay pays ~2 muls per block),
//! - native prove/verify wall times for context.
//!
//! Rerun after any change to the FieldR1cs verifier or the trace gadgets.

use std::time::Instant;

use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::field_r1cs::synthetic_satisfiable;
use noid_ivc_prover::field_prover::prove_field;
use noid_ivc_prover::pcs::{self, PcsParams};
use noid_ivc_prover::verifier::verify_field;
use noid_ivc_prover::field_circuit::FsChannelTrace;
use noid_recursive::acceptance::trace::self_verify::{
    alloc_flat_digest, verify_field_trace, FieldR1csProofTrace,
};
use noid_recursive::acceptance::trace::FieldR1csBuilder;

const DOMAIN: &[u8] = b"self-verify-rows-bench-v0";

fn main() {
    noid_ivc_prover::init_perf_thread_pool();
    println!(
        "== [R] row-count measurement — rayon threads: {} ==\n",
        rayon::current_num_threads()
    );

    // (m, log_inv_rate, log_batch_size). m is the verified instance's
    // witness log-size; production π traces sit at m ≈ 20–25 (tx-count
    // dependent until the folding layer lands). The query counts are
    // 148 @ rate 1/4, 121 @ 1/8, 110 @ 1/16, 105 @ 1/32.
    for &(m, lir, lb) in &[
        (14usize, 2usize, 2usize),
        (16, 2, 5),
        (16, 4, 5),
        (18, 4, 5),
        (20, 4, 5),
        (20, 5, 2),
    ] {
        let (r1cs, z) = synthetic_satisfiable(m, m, 0x5EED ^ (m as u64) ^ ((lir as u64) << 8));
        let params = PcsParams {
            m: m + pcs::LOG_PACKING,
            log_inv_rate: lir,
            log_batch_size: lb,
            profile: Default::default(),
        };

        let t = Instant::now();
        let mut ch = FsLaneChallenger::new(DOMAIN);
        let (proof, commitment, _claim) = prove_field(&r1cs, &z, &params, &mut ch);
        let prove_ms = t.elapsed().as_secs_f64() * 1e3;

        let t = Instant::now();
        let mut ch = FsLaneChallenger::new(DOMAIN);
        verify_field(&r1cs, &commitment, &proof, &mut ch).expect("native verify");
        let verify_ms = t.elapsed().as_secs_f64() * 1e3;

        // Nonzero 64×64 block count of the verified matrices (lincheck cost
        // driver in-trace).
        let block_count = {
            use std::collections::BTreeSet;
            let mut blocks: BTreeSet<(usize, usize)> = BTreeSet::new();
            for rows in [&r1cs.a_0.rows, &r1cs.b_0.rows] {
                for (r, row) in rows.iter().enumerate() {
                    for &(c, _) in row {
                        blocks.insert((r >> r1cs.k_skip, (c as usize) >> r1cs.k_skip));
                    }
                }
            }
            blocks.len()
        };

        let t = Instant::now();
        let mut b = FieldR1csBuilder::new();
        let mut tch = FsChannelTrace::new(&mut b, DOMAIN);
        let root = alloc_flat_digest(&mut b, &commitment.root);
        let proof_e = FieldR1csProofTrace::alloc(&mut b, &proof, &r1cs, &params);
        let rows_before = b.num_wires();
        let _ = verify_field_trace(&mut b, &mut tch, &r1cs, &params, &root, &proof_e);
        let rows_total = b.num_wires();
        let build_ms = t.elapsed().as_secs_f64() * 1e3;

        println!(
            "m=2^{m} lir={lir} lb={lb} (queries {q}): [R] rows = {rows_total} \
             (proof wires {pw}, verifier rows {vr}) — 2^{log:.1}",
            q = pcs::default_fri_queries(lir),
            pw = rows_before,
            vr = rows_total - rows_before,
            log = (rows_total as f64).log2(),
        );
        println!(
            "    verified-matrix nnz blocks = {block_count}; native prove {prove_ms:.0} ms, \
             native verify {verify_ms:.1} ms, trace build {build_ms:.0} ms\n"
        );
    }
}
