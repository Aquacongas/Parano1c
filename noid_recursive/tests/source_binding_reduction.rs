//! The wallet-capsule source-binding reduction, validated natively in the
//! flat (GCM) `F128` basis the region carries.
//!
//! The native check `codeword = Code(H·eq_right)` (tower basis) is replayed
//! in the region as: pin `codeword~(z)` (from the tree's CODE claims) to
//! `Σ_i K_i(z)·eq(right,i)·H[i]` via ONE `prove_weighted_sum` over the
//! committed `H`, plus the H-claim `H~(right) = initial_sumcheck_claim`. The
//! encode kernel `K_i(z)` is closed form; the flat kernel reproduces the MLE
//! of the φ-mapped tower codeword because φ = `tower_to_flat` is a field
//! isomorphism.
//!
//! This test constructs a real tower codeword with `Code::new_parallel`,
//! maps it to flat, and drives the flat kernel + `verify_weighted_sum` end
//! to end — the native reference the in-region trace twin will shadow.

use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::code::{Code, LOG_RATE};
use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::encode_kernel::{
    encode_mle_via_kernel, eq_at, source_weight_at,
};
use noid_ivc_core::deep_chain::relations::{prove_weighted_sum, verify_weighted_sum};
use noid_ivc_core::deep_chain::schedule::flat_of_tower_u128;
use noid_ivc_core::field::F128;
use noid_ivc_core::lincheck::build_eq_table;

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn block(&mut self) -> Block128 {
        Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
    }
    fn f128(&mut self) -> F128 {
        F128 {
            lo: self.next_u64(),
            hi: self.next_u64(),
        }
    }
}

/// φ = tower→flat of a tower `Block128` into the region's flat `F128`.
fn phi(b: Block128) -> F128 {
    flat_of_tower_u128(b.0)
}

fn mle_eval(vals: &[F128], z: &[F128]) -> F128 {
    let eq = build_eq_table(z);
    let mut acc = F128::ZERO;
    for (v, e) in vals.iter().zip(eq.iter()) {
        acc += *v * *e;
    }
    acc
}

/// The flat encode kernel reproduces the MLE of the φ-mapped REAL tower
/// codeword at a native flat point — the field-iso identity the whole
/// source binding rests on, cross-checked against `Code::new_parallel`.
#[test]
fn flat_kernel_matches_phi_of_real_codeword() {
    let mut rng = Rng(0x50FA);
    for n_rounds in [1usize, 2, 3, 5, 7] {
        let ntt = AdditiveNTT::<Block128>::new(n_rounds + LOG_RATE);
        let g_tower: Vec<Block128> = (0..(1usize << n_rounds)).map(|_| rng.block()).collect();
        let codeword_tower = Code::new_parallel(&g_tower, &ntt);

        let g_flat: Vec<F128> = g_tower.iter().map(|&b| phi(b)).collect();
        let codeword_flat: Vec<F128> = codeword_tower.encoding.iter().map(|&b| phi(b)).collect();

        // A native flat z (NOT φ of a tower point) — the identity holds for
        // all flat z because φ is a field iso.
        let z: Vec<F128> = (0..n_rounds + 2).map(|_| rng.f128()).collect();
        assert_eq!(
            encode_mle_via_kernel(&g_flat, &z, n_rounds),
            mle_eval(&codeword_flat, &z),
            "flat kernel != phi(real codeword) MLE at n_rounds={n_rounds}"
        );
    }
}

/// The full reduction: given the real tower codeword of `H·eq_right`, the
/// flat weighted-sum discharge reduces `codeword~(z)` to a plain `H` opening
/// (weight `K_i(z)·eq(right,i)`), and the H-claim reduces `H~(right)` to the
/// same column — both honest, and a corrupted target is rejected.
#[test]
fn source_binding_reduces_to_h_openings() {
    let mut rng = Rng(0xB1AD);
    let n_rounds = 6usize;
    let ntt = AdditiveNTT::<Block128>::new(n_rounds + LOG_RATE);

    // Tower construction (the native capsule basis), then φ to flat.
    let h_tower: Vec<Block128> = (0..(1usize << n_rounds)).map(|_| rng.block()).collect();
    let right_tower: Vec<Block128> = (0..n_rounds).map(|_| rng.block()).collect();
    let eq_right_tower = {
        // eq(right, i) over the tower basis.
        let mut t = vec![Block128::ONE; 1usize << n_rounds];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut e = Block128::ONE;
            for (l, &r) in right_tower.iter().enumerate() {
                let bit = (i >> l) & 1 == 1;
                e = e * if bit { r } else { Block128::ONE + r };
            }
            *slot = e;
        }
        t
    };
    let g_tower: Vec<Block128> = h_tower
        .iter()
        .zip(eq_right_tower.iter())
        .map(|(&h, &e)| h * e)
        .collect();
    let codeword_tower = Code::new_parallel(&g_tower, &ntt);

    // Flat views.
    let h_flat: Vec<F128> = h_tower.iter().map(|&b| phi(b)).collect();
    let right_flat: Vec<F128> = right_tower.iter().map(|&b| phi(b)).collect();
    let codeword_flat: Vec<F128> = codeword_tower.encoding.iter().map(|&b| phi(b)).collect();

    // ---- Encode binding: codeword~(z) = Σ_i K_i(z)·eq(right,i)·H[i].
    let z: Vec<F128> = (0..n_rounds + 2).map(|_| rng.f128()).collect();
    let target = mle_eval(&codeword_flat, &z);
    // Materialized weights for the prover.
    let weights: Vec<F128> = (0..(1usize << n_rounds))
        .map(|i| {
            let x: Vec<F128> = (0..n_rounds)
                .map(|l| {
                    if (i >> l) & 1 == 1 {
                        F128::ONE
                    } else {
                        F128::ZERO
                    }
                })
                .collect();
            source_weight_at(&z, &right_flat, &x, n_rounds)
        })
        .collect();
    // Sanity: the materialized weighted sum equals the codeword MLE.
    let direct: F128 = weights
        .iter()
        .zip(h_flat.iter())
        .map(|(&w, &h)| w * h)
        .fold(F128::ZERO, |a, b| a + b);
    assert_eq!(direct, target, "weighted H sum != codeword MLE");

    let mut ch_p = FsLaneChallenger::new(b"source-binding");
    let (proof, point_p) = prove_weighted_sum(&h_flat, &weights, target, &mut ch_p);
    let mut ch_v = FsLaneChallenger::new(b"source-binding");
    let point_v = verify_weighted_sum(
        n_rounds,
        |pt: &[F128]| source_weight_at(&z, &right_flat, pt, n_rounds),
        target,
        &proof,
        &mut ch_v,
    )
    .expect("encode binding discharge");
    assert_eq!(point_p, point_v);
    assert_eq!(mle_eval(&h_flat, &point_v), proof.final_value, "H opening");

    // A tampered target is rejected.
    let mut ch = FsLaneChallenger::new(b"source-binding");
    assert!(verify_weighted_sum(
        n_rounds,
        |pt: &[F128]| source_weight_at(&z, &right_flat, pt, n_rounds),
        target + F128::ONE,
        &proof,
        &mut ch,
    )
    .is_err());

    // ---- H-claim: H~(right) = initial_sumcheck_claim (weight eq(right,·)).
    let claim = mle_eval(&h_flat, &right_flat);
    let eq_weights = build_eq_table(&right_flat);
    let mut ch_p = FsLaneChallenger::new(b"h-claim");
    let (h_proof, _) = prove_weighted_sum(&h_flat, &eq_weights, claim, &mut ch_p);
    let mut ch_v = FsLaneChallenger::new(b"h-claim");
    let h_point = verify_weighted_sum(
        n_rounds,
        |pt: &[F128]| eq_at(&right_flat, pt),
        claim,
        &h_proof,
        &mut ch_v,
    )
    .expect("H-claim discharge");
    assert_eq!(mle_eval(&h_flat, &h_point), h_proof.final_value, "H-claim opening");

    // Lockstep sanity across both channels.
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128());
}
