// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Row-count measurement for the recursion slot: how many FieldR1cs
//! constraints does the in-trace FieldR1cs verifier replay
//! (`trace::self_verify::verify_field_trace`) cost, as a function of the
//! verified instance size and the PCS code rate?
//!
//! Two families of verified instances:
//! - **Poseidon2b permutation chains** built with `FieldR1csBuilder` — the
//!   representative shape: real verifier-replay traces are builder-produced
//!   and have the same strong wire locality, so their 64×64 matrix block
//!   count (the lincheck bilinear replay pays ~2 rows per block) is small.
//! - **Synthetic instances** (`synthetic_satisfiable`) — an adversarial
//!   locality bound: columns are uniformly random over earlier wires, so
//!   nearly every nonzero lands in its own block.
//!
//! Reported per case: the [R] trace row count and the proof-wire /
//! verifier-row split, the verified-matrix block count, native prove and
//! verify wall times, and the trace build time.
//!
//! Rerun after any change to the FieldR1cs verifier or the trace gadgets.

use std::time::Instant;

use bench_prover::poseidon_chain_field_instance;
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::field_circuit::FsChannelTrace;
use noid_ivc_prover::field_r1cs::{synthetic_satisfiable, FieldR1cs};
use noid_ivc_prover::field_prover::prove_field;
use noid_ivc_prover::pcs::{self, PcsParams};
use noid_ivc_prover::verifier::verify_field;
use noid_ivc_prover::field::F128;
use noid_recursive::acceptance::trace::self_verify::{
    alloc_flat_digest, verify_field_trace, FieldR1csProofTrace,
};
use noid_recursive::acceptance::trace::FieldR1csBuilder;

const DOMAIN: &[u8] = b"self-verify-rows-bench-v0";

fn measure(label: &str, r1cs: &FieldR1cs, z: &[F128], lir: usize, lb: usize) {
    let m = r1cs.m;
    let params = PcsParams {
        m: m + pcs::LOG_PACKING,
        log_inv_rate: lir,
        log_batch_size: lb,
        profile: Default::default(),
    };

    let t = Instant::now();
    let mut ch = FsLaneChallenger::new(DOMAIN);
    let (proof, commitment, _claim) = prove_field(r1cs, z, &params, &mut ch);
    let prove_ms = t.elapsed().as_secs_f64() * 1e3;

    let t = Instant::now();
    let mut ch = FsLaneChallenger::new(DOMAIN);
    verify_field(r1cs, &commitment, &proof, &mut ch).expect("native verify");
    let verify_ms = t.elapsed().as_secs_f64() * 1e3;

    // Nonzero 64×64 block count of the verified matrices (lincheck cost
    // driver in-trace: ~2 rows per block).
    let block_count = {
        use std::collections::BTreeSet;
        let mut blocks: BTreeSet<(usize, usize)> = BTreeSet::new();
        for m in [&r1cs.a_0, &r1cs.b_0] {
            for r in 0..m.num_rows {
                for (c, _) in m.row(r) {
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
    let proof_e = FieldR1csProofTrace::alloc(&mut b, &proof, r1cs, &params);
    let rows_before = b.num_wires();
    let _ = verify_field_trace(&mut b, &mut tch, r1cs, &params, &root, &proof_e);
    let rows_total = b.num_wires();
    let build_ms = t.elapsed().as_secs_f64() * 1e3;

    println!(
        "{label}: m=2^{m} lir={lir} lb={lb} (queries {q}) → [R] rows = {rows_total} (2^{log:.1})",
        q = pcs::default_fri_queries(lir),
        log = (rows_total as f64).log2(),
    );
    println!(
        "    proof wires {pw}, verifier rows {vr}; verified-matrix nnz blocks = {block_count}",
        pw = rows_before,
        vr = rows_total - rows_before,
    );
    println!(
        "    native prove {prove_ms:.0} ms, native verify {verify_ms:.1} ms, trace build {build_ms:.0} ms\n"
    );
}

fn main() {
    noid_ivc_prover::init_perf_thread_pool();
    println!(
        "== [R] row-count measurement — rayon threads: {} ==\n",
        rayon::current_num_threads()
    );

    // Poseidon chains: ~2^17 and ~2^19 rows (the second is the shape class
    // of a small production trace; the real π sits at 2^20+ until folding).
    for &(chain, lir, lb) in &[
        (364usize, 2usize, 2usize), // 364·360+5 ≈ 2^17
        (1456, 2, 5),               // ≈ 2^19
        (1456, 4, 5),
        (1456, 5, 5),
    ] {
        let (r1cs, z) = poseidon_chain_field_instance(chain);
        measure("poseidon-chain", &r1cs, &z, lir, lb);
    }

    // Synthetic adversarial-locality instances (block count ≈ nnz).
    for &(m, lir, lb) in &[(14usize, 2usize, 2usize), (16, 2, 5)] {
        let (r1cs, z) = synthetic_satisfiable(m, m, 0x5EED ^ (m as u64));
        measure("synthetic", &r1cs, &z, lir, lb);
    }
}
