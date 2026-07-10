// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Wallet-PCS region-discharge LAYOUT PROBE: exact wire/claim costs of the
//! plural discharge at the TEST parameters the heavy gates run (`nq = 2`)
//! versus the PRODUCTION parameters the link must ship
//! (`nq = CAPSULE_NUM_QUERIES` — every capsule query authenticated on both
//! trees; anything less leaves unauthenticated openings a fake-history
//! prover can forge).
//!
//! Measures REAL builds at k = 1 / 2 / 4 obligations and fits the exact cost
//! model (committed walk columns + per-tx pins are LINEAR in k; the three
//! walk twins add one round per domain doubling — LOGARITHMIC), then
//! extrapolates the wallet-discharge share of the link trace to the class
//! tiers up to the attack tier (255 std -> k = 256 power-of-two obligation
//! padding). The fit is validated against the measured k = 4 point before
//! any extrapolated number is printed.
//!
//! Run explicitly (release; the production k = 4 build is a multi-million
//! wire trace):
//! ```text
//! cargo test -p noid_recursive --release --test region_4f_layout_probe -- --ignored --nocapture
//! ```

use noid_core::Block128;
use noid_fri_binius::capsule::{CAPSULE_NUM_QUERIES, CAPSULE_TAU};
use noid_gkr::auth_pcs::{commit_auth_mle_column, open_auth_mle_committed, AuthMleOpeningProof};
use noid_gkr::batch_eval::BatchEvalReduction;

use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};

use noid_recursive::acceptance::trace::owner_auth::PendingAuthPcsObligation;
use noid_recursive::acceptance::trace::region_source_binding::{
    discharge_auth_pcs_obligations_via_region, RegionDischargeParams,
};
use noid_recursive::acceptance::trace::{alloc_block, alloc_blocks, BatchEvalReductionTrace};

/// The real wallet auth-MLE width (`AUTH_PCS_BASE_LOG`): Tx8x2 transactions commit
/// a 2^9 column, so the capsule shape here IS the production shape.
const WALLET_NUM_VARS: usize = 9;

/// Allocate one raw-flat digest lane pair (the capsule cap lanes carry the
/// raw flat digest halves under the flat→tower absorb convention).
fn alloc_digest_raw(b: &mut FieldR1csBuilder, d: &[u8; 32]) -> [LinExpr; 2] {
    use noid_ivc_core::field::F128;
    let lo = u128::from_le_bytes(d[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(d[16..].try_into().unwrap());
    let lane = |v: u128| F128 {
        lo: v as u64,
        hi: (v >> 64) as u64,
    };
    [
        LinExpr::from_wire(b.alloc_f128(lane(lo))),
        LinExpr::from_wire(b.alloc_f128(lane(hi))),
    ]
}

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn f128_block(&mut self) -> Block128 {
        Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
    }
}

/// A REAL capsule opening (commit + open + native verify all run) over a
/// random wallet-shaped column; only the column contents are synthetic.
fn capsule_fixture(seed: u64) -> (Vec<Block128>, BatchEvalReduction, AuthMleOpeningProof) {
    use noid_core::mle::evaluate::evaluate_slice;
    let mut rng = Rng(seed);
    let column: Vec<Block128> = (0..(1usize << WALLET_NUM_VARS))
        .map(|_| rng.f128_block())
        .collect();
    let point: Vec<Block128> = (0..WALLET_NUM_VARS).map(|_| rng.f128_block()).collect();
    let value = evaluate_slice(&column, &point);
    let reduction = BatchEvalReduction {
        point: point.clone(),
        value,
    };
    let mut committed = commit_auth_mle_column(&column, WALLET_NUM_VARS);
    let proof = open_auth_mle_committed(&mut committed, WALLET_NUM_VARS, &reduction);
    (point, reduction, proof)
}

struct Measured {
    wires: usize,
    claims: usize,
    max_arity: usize,
}

/// One plural discharge at `k` obligations under `params`; returns the exact
/// builder wire count and claim count the discharge produced.
fn measure(k: usize, params: RegionDischargeParams) -> Measured {
    let mut b = FieldR1csBuilder::new();
    let fixtures: Vec<_> = (0..k)
        .map(|i| capsule_fixture(0xA55E_C0DE + i as u64))
        .collect();
    let mut obligations = Vec::with_capacity(k);
    let mut natives = Vec::with_capacity(k);
    for (point, red, proof) in &fixtures {
        let cap_lanes: Vec<[LinExpr; 2]> = proof
            .commitment
            .cap
            .hashes
            .iter()
            .map(|h| alloc_digest_raw(&mut b, h))
            .collect();
        let point_w = alloc_blocks(&mut b, point);
        let value_w = alloc_block(&mut b, red.value);
        obligations.push(PendingAuthPcsObligation {
            commitment_cap_lanes: cap_lanes,
            num_vars: WALLET_NUM_VARS,
            reduction: BatchEvalReductionTrace {
                point: point_w,
                value: value_w,
            },
        });
        natives.push(proof.clone());
    }
    let before = b.num_wires();
    let claims = discharge_auth_pcs_obligations_via_region(
        &mut b,
        &obligations,
        &natives,
        params,
        None,
        None,
        None,
        None,
    );
    let max_arity = claims.iter().map(|c| c.point.len()).max().unwrap();
    Measured {
        wires: b.num_wires() - before,
        claims: claims.len(),
        max_arity,
    }
}

/// Fit `wires(k) = w(1) + s·(k−1) + t·log2(k)` on k = 1/2/4 (s = linear
/// column+pin slope per tx, t = the walk-twin bump per domain doubling),
/// validate on the measured k = 4 point, extrapolate to the tier ks.
fn fit_and_report(label: &str, ms: &[Measured]) {
    let (w1, w2, w4) = (ms[0].wires as i64, ms[1].wires as i64, ms[2].wires as i64);
    let d1 = w2 - w1;
    let d2 = w4 - w2;
    let s = d2 - d1; // per-tx linear slope
    let t = 2 * d1 - d2; // per-doubling twin bump
    let predict = |k: i64, log2k: i64| w1 + s * (k - 1) + t * log2k;
    let check4 = predict(4, 2);
    println!(
        "[{label}] fit: linear slope s = {s} wires/tx, twin bump t = {t} wires/doubling \
         (k=4 check: predicted {check4}, measured {w4})"
    );
    let c1 = ms[0].claims as i64;
    let c2 = ms[1].claims as i64;
    let cs = c2 - c1; // claims per tx
    println!(
        "[{label}] claims: {} @k=1, +{cs}/tx (k=4 check: predicted {}, measured {}), \
         max_arity {}",
        c1,
        c1 + 3 * cs,
        ms[2].claims,
        ms[2].max_arity
    );
    for (tier, k) in [(16usize, 16i64), (255usize, 256i64)] {
        let log2k = k.trailing_zeros() as i64;
        let w = predict(k, log2k);
        let c = c1 + (k - 1) * cs;
        println!(
            "[{label}] tier {tier:>3} (k = {k}): wallet-discharge ≈ {:>11} wires, \
             ≈ {:>6} claims",
            w, c
        );
    }
}

#[test]
#[ignore = "layout probe (multi-million-wire builds at the production point); run explicitly"]
fn region_4f_layout_probe() {
    let test_params = RegionDischargeParams { nq: 2 };
    let prod_params = RegionDischargeParams {
        nq: CAPSULE_NUM_QUERIES,
    };
    println!(
        "[probe] wallet num_vars = {WALLET_NUM_VARS}, tau = {CAPSULE_TAU}; TEST params: nq = {}; \
         PRODUCTION params: nq = {} (all queries, both trees)",
        test_params.nq, prod_params.nq
    );

    for (label, params) in [("test-nq2", test_params), ("PROD-nq-full", prod_params)] {
        let mut ms = Vec::new();
        for k in [1usize, 2, 4] {
            let t0 = std::time::Instant::now();
            let m = measure(k, params);
            println!(
                "[{label}] k = {k}: {} wires, {} claims (max_arity {}) in {:.1?}",
                m.wires,
                m.claims,
                m.max_arity,
                t0.elapsed()
            );
            ms.push(m);
        }
        fit_and_report(label, &ms);
    }
}
