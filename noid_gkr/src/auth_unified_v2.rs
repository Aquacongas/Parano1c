// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 2.3 — AuthGKR unified Kill-Shot sumcheck driver, retargeted on
//! the 14-variable hypercube.
//!
//! Forked from `spine_unified.rs` (Stages 1.5.4-B / 1.5.4-C / 1.5.8.A /
//! 1.5.8.B). The protocol shape is identical:
//!
//!   * 14-round main sumcheck of degree 9 (C1 + β·C1' + γ·C2)
//!   * 14-round shift gadget of degree 2 (reduces 11 `_dec` claims to
//!     three direct openings on the original `s_in`, `s_out`, `state`
//!     columns)
//!
//! Differences from Spine:
//!
//!   * `N_AUTH_UNIFIED_VARS = 14` vs. `N_SPINE_UNIFIED_VARS = 15`
//!   * Slot field width 5 bits (instead of 6); cell count `2^14 = 16K`.
//!   * Public schedules pulled from cached `auth_shift::auth_*_table()`
//!     getters — no per-proof rebuild.
//!   * Live-slot count fixed at `N_AUTH_LIVE_SLOTS = 20`.

use noid_core::hardware::{
    clmul_gcm, flat_to_tower_u128, square_flat_u128, tower_to_flat_u128,
};
use noid_core::mle::eq::eq_ind;
use noid_core::mle::evaluate::{evaluate_flat, evaluate_preflat, evaluate_slice};
use noid_core::packed::pow7::pow7_block128;
use noid_core::sumcheck::RoundPolynomial;
use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use crate::auth_mle_v2::{
    AuthUnifiedMle, N_AUTH_ELEM_VARS, N_AUTH_ROUND_VARS, N_AUTH_SLOT_BITS,
    N_AUTH_UNIFIED_CELLS, N_AUTH_UNIFIED_VARS,
};
use crate::auth_shift::{
    auth_build_u_table, auth_mds_lane_tables, auth_mds_lane_tables_flat, auth_permute_by_dec,
    auth_project_lane, auth_rc_dec_table_flat, auth_rc_table, auth_sigma_dec_lane_tables_flat,
    auth_sigma_dec_table_flat, auth_sigma_table,
};

const ELEM_LO: usize = 0;
const ELEM_HI: usize = ELEM_LO + N_AUTH_ELEM_VARS;
const ROUND_LO: usize = ELEM_HI;
const ROUND_HI: usize = ROUND_LO + N_AUTH_ROUND_VARS;
const SLOT_LO: usize = ROUND_HI;
const SLOT_HI: usize = SLOT_LO + N_AUTH_SLOT_BITS;

/// Per-variable degree of the main round polynomial.
pub const AUTH_UNIFIED_ROUND_DEGREE: usize = 9;

/// Per-variable degree of the shift-gadget round polynomial.
pub const AUTH_SHIFT_ROUND_DEGREE: usize = 2;

/// Number of witness-derived claims emitted by the main sumcheck.
pub const N_AUTH_UNIFIED_WITNESS_CLAIMS: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUnifiedProof {
    pub round_polys: Vec<RoundPolynomial<Block128>>,
    pub s_in_dec_at_r: Block128,
    pub s_out_dec_at_r: Block128,
    pub state_dec_at_r: Block128,
    pub state_at_r: Block128,
    pub s_out_lane_dec_at_r: [Block128; STATE_SIZE],
    pub state_lane_dec_at_r: [Block128; STATE_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUnifiedReduction {
    pub r_prime: Vec<Block128>,
    pub s_in_dec_at_r: Block128,
    pub s_out_dec_at_r: Block128,
    pub state_dec_at_r: Block128,
    pub state_at_r: Block128,
    pub s_out_lane_dec_at_r: [Block128; STATE_SIZE],
    pub state_lane_dec_at_r: [Block128; STATE_SIZE],
    pub beta: Block128,
    pub gamma: Block128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthShiftProof {
    pub round_polys: Vec<RoundPolynomial<Block128>>,
    pub s_in_at_r2: Block128,
    pub s_out_at_r2: Block128,
    pub state_at_r2: Block128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthShiftReduction {
    pub r_double_prime: Vec<Block128>,
    pub s_in_at_r2: Block128,
    pub s_out_at_r2: Block128,
    pub state_at_r2: Block128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKillShotProof {
    pub main: AuthUnifiedProof,
    pub shift: AuthShiftProof,
}

// ---------------------------------------------------------------------------
// Main sumcheck
// ---------------------------------------------------------------------------

pub fn prove_auth_unified<T: FiatShamir<Block128>>(
    mle: &AuthUnifiedMle,
    channel: &mut T,
) -> (AuthUnifiedProof, Vec<Block128>) {
    assert_eq!(mle.s_in.len(), N_AUTH_UNIFIED_CELLS);
    assert_eq!(mle.s_out.len(), N_AUTH_UNIFIED_CELLS);
    assert_eq!(mle.sigma.len(), N_AUTH_UNIFIED_CELLS);
    assert_eq!(mle.state.len(), N_AUTH_UNIFIED_CELLS);

    let rho: Vec<Block128> = (0..N_AUTH_UNIFIED_VARS)
        .map(|_| channel.squeeze())
        .collect();
    let beta = channel.squeeze();
    let gamma = channel.squeeze();

    let tabs = build_unified_tables(mle, &rho);
    let mut tabs = UnifiedFlatTables::from_tower(tabs);
    let beta_flat = tower_to_flat_u128(beta.to_u128());
    let gamma_flat = tower_to_flat_u128(gamma.to_u128());

    let mut round_polys = Vec::with_capacity(N_AUTH_UNIFIED_VARS);
    let mut r_prime = vec![Block128::ZERO; N_AUTH_UNIFIED_VARS];

    for round in 0..N_AUTH_UNIFIED_VARS {
        let poly = compute_round_polynomial_flat(&tabs, beta_flat, gamma_flat);
        for &c in &poly.coeffs {
            channel.absorb(c);
        }
        let challenge = channel.squeeze();
        let challenge_flat = tower_to_flat_u128(challenge.to_u128());
        tabs.fold_flat(challenge_flat);
        r_prime[N_AUTH_UNIFIED_VARS - 1 - round] = challenge;
        round_polys.push(poly);
    }

    let final_claims = tabs.final_claims_tower();
    channel.absorb(final_claims.s_in_dec);
    channel.absorb(final_claims.s_out_dec);
    channel.absorb(final_claims.state_dec);
    channel.absorb(final_claims.state);
    for v in &final_claims.s_out_lane_dec {
        channel.absorb(*v);
    }
    for v in &final_claims.state_lane_dec {
        channel.absorb(*v);
    }

    let proof = AuthUnifiedProof {
        round_polys,
        s_in_dec_at_r: final_claims.s_in_dec,
        s_out_dec_at_r: final_claims.s_out_dec,
        state_dec_at_r: final_claims.state_dec,
        state_at_r: final_claims.state,
        s_out_lane_dec_at_r: final_claims.s_out_lane_dec,
        state_lane_dec_at_r: final_claims.state_lane_dec,
    };
    (proof, r_prime)
}

pub fn verify_auth_unified<T: FiatShamir<Block128>>(
    proof: &AuthUnifiedProof,
    channel: &mut T,
) -> Option<AuthUnifiedReduction> {
    if proof.round_polys.len() != N_AUTH_UNIFIED_VARS {
        return None;
    }
    for p in &proof.round_polys {
        if p.degree() > AUTH_UNIFIED_ROUND_DEGREE {
            return None;
        }
    }

    let rho: Vec<Block128> = (0..N_AUTH_UNIFIED_VARS)
        .map(|_| channel.squeeze())
        .collect();
    let beta = channel.squeeze();
    let gamma = channel.squeeze();

    let mut expected = Block128::ZERO;
    let mut r_prime = vec![Block128::ZERO; N_AUTH_UNIFIED_VARS];

    for (round, poly) in proof.round_polys.iter().enumerate() {
        let s = poly.evaluate(Block128::ZERO) + poly.evaluate(Block128::ONE);
        if s != expected {
            return None;
        }
        for &c in &poly.coeffs {
            channel.absorb(c);
        }
        let challenge = channel.squeeze();
        expected = poly.evaluate(challenge);
        r_prime[N_AUTH_UNIFIED_VARS - 1 - round] = challenge;
    }

    let u_at_r = evaluate_flat(&auth_build_u_table(&rho), &r_prime);
    let sigma_dec_at_r = evaluate_preflat(auth_sigma_dec_table_flat(), &r_prime);
    let rc_dec_at_r = evaluate_preflat(auth_rc_dec_table_flat(), &r_prime);
    let mut mds_lane_dec_at_r = [Block128::ZERO; STATE_SIZE];
    let mut sigma_lane_dec_at_r = [Block128::ZERO; STATE_SIZE];
    let mds_lane_flat = auth_mds_lane_tables_flat();
    let sigma_lane_flat = auth_sigma_dec_lane_tables_flat();
    for j in 0..STATE_SIZE {
        mds_lane_dec_at_r[j] = evaluate_preflat(&mds_lane_flat[j], &r_prime);
        sigma_lane_dec_at_r[j] = evaluate_preflat(&sigma_lane_flat[j], &r_prime);
    }

    let q_c1 = sigma_dec_at_r * pow7_block128(proof.s_in_dec_at_r)
        + proof.s_out_dec_at_r
        + proof.s_in_dec_at_r
        + sigma_dec_at_r * proof.s_in_dec_at_r;
    let q_c1p = sigma_dec_at_r * (proof.s_in_dec_at_r + proof.state_dec_at_r + rc_dec_at_r);
    let mut c2_sum = proof.state_at_r;
    for j in 0..STATE_SIZE {
        let pi_j = sigma_lane_dec_at_r[j] * proof.s_out_lane_dec_at_r[j]
            + (Block128::ONE + sigma_lane_dec_at_r[j]) * proof.state_lane_dec_at_r[j];
        c2_sum += mds_lane_dec_at_r[j] * pi_j;
    }
    let q_at_r = q_c1 + beta * q_c1p + gamma * c2_sum;

    if expected != u_at_r * q_at_r {
        return None;
    }

    channel.absorb(proof.s_in_dec_at_r);
    channel.absorb(proof.s_out_dec_at_r);
    channel.absorb(proof.state_dec_at_r);
    channel.absorb(proof.state_at_r);
    for v in &proof.s_out_lane_dec_at_r {
        channel.absorb(*v);
    }
    for v in &proof.state_lane_dec_at_r {
        channel.absorb(*v);
    }

    Some(AuthUnifiedReduction {
        r_prime,
        s_in_dec_at_r: proof.s_in_dec_at_r,
        s_out_dec_at_r: proof.s_out_dec_at_r,
        state_dec_at_r: proof.state_dec_at_r,
        state_at_r: proof.state_at_r,
        s_out_lane_dec_at_r: proof.s_out_lane_dec_at_r,
        state_lane_dec_at_r: proof.state_lane_dec_at_r,
        beta,
        gamma,
    })
}

// ---------------------------------------------------------------------------
// Internal helper-table bundle.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct UnifiedTables {
    u: Vec<Block128>,
    sigma_dec: Vec<Block128>,
    rc_dec: Vec<Block128>,
    mds_lane_dec: [Vec<Block128>; STATE_SIZE],
    sigma_lane_dec: [Vec<Block128>; STATE_SIZE],
    s_in_dec: Vec<Block128>,
    s_out_dec: Vec<Block128>,
    state_dec: Vec<Block128>,
    state: Vec<Block128>,
    s_out_lane_dec: [Vec<Block128>; STATE_SIZE],
    state_lane_dec: [Vec<Block128>; STATE_SIZE],
}

struct UnifiedFinalClaims {
    s_in_dec: Block128,
    s_out_dec: Block128,
    state_dec: Block128,
    state: Block128,
    s_out_lane_dec: [Block128; STATE_SIZE],
    state_lane_dec: [Block128; STATE_SIZE],
}

fn build_unified_tables(mle: &AuthUnifiedMle, rho: &[Block128]) -> UnifiedTables {
    let sigma_full = auth_sigma_table().to_vec();
    let sigma_dec = auth_permute_by_dec(&sigma_full);
    let rc_dec = auth_permute_by_dec(auth_rc_table());
    let s_in_dec = auth_permute_by_dec(&mle.s_in);
    let s_out_dec = auth_permute_by_dec(&mle.s_out);
    let state_dec = auth_permute_by_dec(&mle.state);

    let mds_lane_dec: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|j| auth_mds_lane_tables()[j].clone());
    let sigma_lane_dec: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|j| auth_project_lane(&sigma_dec, j));
    let s_out_lane_dec: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|j| auth_project_lane(&s_out_dec, j));
    let state_lane_dec: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|j| auth_project_lane(&state_dec, j));

    UnifiedTables {
        u: auth_build_u_table(rho),
        sigma_dec,
        rc_dec,
        mds_lane_dec,
        sigma_lane_dec,
        s_in_dec,
        s_out_dec,
        state_dec,
        state: mle.state.clone(),
        s_out_lane_dec,
        state_lane_dec,
    }
}

// ---------------------------------------------------------------------------
// Flat-basis prover hot path.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct UnifiedFlatTables {
    u: Vec<u128>,
    sigma_dec: Vec<u128>,
    rc_dec: Vec<u128>,
    mds_lane_dec: [Vec<u128>; STATE_SIZE],
    sigma_lane_dec: [Vec<u128>; STATE_SIZE],
    s_in_dec: Vec<u128>,
    s_out_dec: Vec<u128>,
    state_dec: Vec<u128>,
    state: Vec<u128>,
    s_out_lane_dec: [Vec<u128>; STATE_SIZE],
    state_lane_dec: [Vec<u128>; STATE_SIZE],
}

#[inline]
fn vec_tower_to_flat(v: Vec<Block128>) -> Vec<u128> {
    v.into_iter().map(|b| tower_to_flat_u128(b.to_u128())).collect()
}

impl UnifiedFlatTables {
    fn from_tower(t: UnifiedTables) -> Self {
        UnifiedFlatTables {
            u: vec_tower_to_flat(t.u),
            sigma_dec: vec_tower_to_flat(t.sigma_dec),
            rc_dec: vec_tower_to_flat(t.rc_dec),
            mds_lane_dec: t.mds_lane_dec.map(vec_tower_to_flat),
            sigma_lane_dec: t.sigma_lane_dec.map(vec_tower_to_flat),
            s_in_dec: vec_tower_to_flat(t.s_in_dec),
            s_out_dec: vec_tower_to_flat(t.s_out_dec),
            state_dec: vec_tower_to_flat(t.state_dec),
            state: vec_tower_to_flat(t.state),
            s_out_lane_dec: t.s_out_lane_dec.map(vec_tower_to_flat),
            state_lane_dec: t.state_lane_dec.map(vec_tower_to_flat),
        }
    }

    fn fold_flat(&mut self, r_flat: u128) {
        fold_highest_var_inplace_flat(&mut self.u, r_flat);
        fold_highest_var_inplace_flat(&mut self.sigma_dec, r_flat);
        fold_highest_var_inplace_flat(&mut self.rc_dec, r_flat);
        fold_highest_var_inplace_flat(&mut self.s_in_dec, r_flat);
        fold_highest_var_inplace_flat(&mut self.s_out_dec, r_flat);
        fold_highest_var_inplace_flat(&mut self.state_dec, r_flat);
        fold_highest_var_inplace_flat(&mut self.state, r_flat);
        for j in 0..STATE_SIZE {
            fold_highest_var_inplace_flat(&mut self.mds_lane_dec[j], r_flat);
            fold_highest_var_inplace_flat(&mut self.sigma_lane_dec[j], r_flat);
            fold_highest_var_inplace_flat(&mut self.s_out_lane_dec[j], r_flat);
            fold_highest_var_inplace_flat(&mut self.state_lane_dec[j], r_flat);
        }
    }

    fn final_claims_tower(&self) -> UnifiedFinalClaims {
        debug_assert_eq!(self.u.len(), 1);
        let f = |x: u128| Block128::from(flat_to_tower_u128(x));
        UnifiedFinalClaims {
            s_in_dec: f(self.s_in_dec[0]),
            s_out_dec: f(self.s_out_dec[0]),
            state_dec: f(self.state_dec[0]),
            state: f(self.state[0]),
            s_out_lane_dec: std::array::from_fn(|j| f(self.s_out_lane_dec[j][0])),
            state_lane_dec: std::array::from_fn(|j| f(self.state_lane_dec[j][0])),
        }
    }
}

#[inline(always)]
fn fold_highest_var_inplace_flat(evals: &mut Vec<u128>, r_flat: u128) {
    let half = evals.len() / 2;
    debug_assert!(half > 0);
    for j in 0..half {
        let delta = evals[j] ^ evals[j + half];
        evals[j] ^= clmul_gcm(r_flat, delta);
    }
    evals.truncate(half);
}

#[inline(always)]
fn poly_mul_t<const NA: usize, const NB: usize, const NR: usize>(
    a: &[u128; NA],
    b: &[u128; NB],
) -> [u128; NR] {
    debug_assert_eq!(NR, NA + NB - 1);
    let mut out = [0u128; NR];
    for i in 0..NA {
        for j in 0..NB {
            out[i + j] ^= clmul_gcm(a[i], b[j]);
        }
    }
    out
}

#[inline(always)]
fn poly_scalar_mul_t<const N: usize>(p: &[u128; N], s: u128) -> [u128; N] {
    let mut out = [0u128; N];
    for k in 0..N {
        out[k] = clmul_gcm(s, p[k]);
    }
    out
}

#[inline(always)]
fn pow7_poly_t(a: u128, b: u128) -> [u128; 8] {
    let a2 = square_flat_u128(a);
    let a3 = clmul_gcm(a2, a);
    let a4 = square_flat_u128(a2);
    let a5 = clmul_gcm(a4, a);
    let a6 = clmul_gcm(a4, a2);
    let a7 = clmul_gcm(a4, a3);

    let b2 = square_flat_u128(b);
    let b3 = clmul_gcm(b2, b);
    let b4 = square_flat_u128(b2);
    let b5 = clmul_gcm(b4, b);
    let b6 = clmul_gcm(b4, b2);
    let b7 = clmul_gcm(b4, b3);

    [
        a7,
        clmul_gcm(a6, b),
        clmul_gcm(a5, b2),
        clmul_gcm(a4, b3),
        clmul_gcm(a3, b4),
        clmul_gcm(a2, b5),
        clmul_gcm(a, b6),
        b7,
    ]
}

fn compute_round_polynomial_flat(
    tabs: &UnifiedFlatTables,
    beta_flat: u128,
    gamma_flat: u128,
) -> RoundPolynomial<Block128> {
    let half = tabs.u.len() / 2;
    let mut acc = [0u128; AUTH_UNIFIED_ROUND_DEGREE + 1];
    const ONE_FLAT: u128 = 1u128;

    for i in 0..half {
        let u_p: [u128; 2] = [tabs.u[i], tabs.u[i] ^ tabs.u[i + half]];
        let sg_p: [u128; 2] = [tabs.sigma_dec[i], tabs.sigma_dec[i] ^ tabs.sigma_dec[i + half]];
        let rc_p: [u128; 2] = [tabs.rc_dec[i], tabs.rc_dec[i] ^ tabs.rc_dec[i + half]];
        let si_p: [u128; 2] = [tabs.s_in_dec[i], tabs.s_in_dec[i] ^ tabs.s_in_dec[i + half]];
        let so_p: [u128; 2] = [tabs.s_out_dec[i], tabs.s_out_dec[i] ^ tabs.s_out_dec[i + half]];
        let st_p: [u128; 2] = [tabs.state_dec[i], tabs.state_dec[i] ^ tabs.state_dec[i + half]];
        let stmain_p: [u128; 2] = [tabs.state[i], tabs.state[i] ^ tabs.state[i + half]];

        let si7_p: [u128; 8] = pow7_poly_t(si_p[0], si_p[1]);
        let sg_si7_p: [u128; 9] = poly_mul_t::<2, 8, 9>(&sg_p, &si7_p);
        let sg_si_p: [u128; 3] = poly_mul_t::<2, 2, 3>(&sg_p, &si_p);
        let mut q1_p = [0u128; 9];
        q1_p.copy_from_slice(&sg_si7_p);
        q1_p[0] ^= so_p[0] ^ si_p[0] ^ sg_si_p[0];
        q1_p[1] ^= so_p[1] ^ si_p[1] ^ sg_si_p[1];
        q1_p[2] ^= sg_si_p[2];

        let inner_p: [u128; 2] = [
            si_p[0] ^ st_p[0] ^ rc_p[0],
            si_p[1] ^ st_p[1] ^ rc_p[1],
        ];
        let q1p_p: [u128; 3] = poly_mul_t::<2, 2, 3>(&sg_p, &inner_p);

        let mut q2_p = [0u128; 4];
        q2_p[0] ^= stmain_p[0];
        q2_p[1] ^= stmain_p[1];
        for j in 0..STATE_SIZE {
            let m_p: [u128; 2] = [
                tabs.mds_lane_dec[j][i],
                tabs.mds_lane_dec[j][i] ^ tabs.mds_lane_dec[j][i + half],
            ];
            let sgl_p: [u128; 2] = [
                tabs.sigma_lane_dec[j][i],
                tabs.sigma_lane_dec[j][i] ^ tabs.sigma_lane_dec[j][i + half],
            ];
            let sol_p: [u128; 2] = [
                tabs.s_out_lane_dec[j][i],
                tabs.s_out_lane_dec[j][i] ^ tabs.s_out_lane_dec[j][i + half],
            ];
            let stl_p: [u128; 2] = [
                tabs.state_lane_dec[j][i],
                tabs.state_lane_dec[j][i] ^ tabs.state_lane_dec[j][i + half],
            ];
            let one_plus_sgl_p: [u128; 2] = [ONE_FLAT ^ sgl_p[0], sgl_p[1]];

            let sgl_sol_p: [u128; 3] = poly_mul_t::<2, 2, 3>(&sgl_p, &sol_p);
            let onep_stl_p: [u128; 3] = poly_mul_t::<2, 2, 3>(&one_plus_sgl_p, &stl_p);
            let pi_p: [u128; 3] = [
                sgl_sol_p[0] ^ onep_stl_p[0],
                sgl_sol_p[1] ^ onep_stl_p[1],
                sgl_sol_p[2] ^ onep_stl_p[2],
            ];
            let m_pi_p: [u128; 4] = poly_mul_t::<2, 3, 4>(&m_p, &pi_p);
            for k in 0..4 {
                q2_p[k] ^= m_pi_p[k];
            }
        }

        let beta_q1p_p: [u128; 3] = poly_scalar_mul_t::<3>(&q1p_p, beta_flat);
        let gamma_q2_p: [u128; 4] = poly_scalar_mul_t::<4>(&q2_p, gamma_flat);
        let mut q_p = [0u128; 9];
        q_p.copy_from_slice(&q1_p);
        for k in 0..3 {
            q_p[k] ^= beta_q1p_p[k];
        }
        for k in 0..4 {
            q_p[k] ^= gamma_q2_p[k];
        }

        let f_p: [u128; 10] = poly_mul_t::<2, 9, 10>(&u_p, &q_p);
        for k in 0..=AUTH_UNIFIED_ROUND_DEGREE {
            acc[k] ^= f_p[k];
        }
    }

    let coeffs_tower: Vec<Block128> = acc
        .iter()
        .map(|&c| Block128::from(flat_to_tower_u128(c)))
        .collect();
    RoundPolynomial::from_coeffs(coeffs_tower)
}

// ---------------------------------------------------------------------------
// Shift gadget
// ---------------------------------------------------------------------------

pub fn prove_auth_shift<T: FiatShamir<Block128>>(
    mle: &AuthUnifiedMle,
    main_red_r_prime: &[Block128],
    channel: &mut T,
) -> (AuthShiftProof, Vec<Block128>) {
    assert_eq!(main_red_r_prime.len(), N_AUTH_UNIFIED_VARS);
    let delta = channel.squeeze();
    let weights = build_combined_weights(main_red_r_prime, delta);

    let mut s_in = vec_tower_to_flat(mle.s_in.clone());
    let mut s_out = vec_tower_to_flat(mle.s_out.clone());
    let mut state = vec_tower_to_flat(mle.state.clone());
    let mut w_sin = vec_tower_to_flat(weights.w_sin);
    let mut w_sout = vec_tower_to_flat(weights.w_sout);
    let mut w_state = vec_tower_to_flat(weights.w_state);

    let mut round_polys = Vec::with_capacity(N_AUTH_UNIFIED_VARS);
    let mut r_double_prime = vec![Block128::ZERO; N_AUTH_UNIFIED_VARS];
    for round in 0..N_AUTH_UNIFIED_VARS {
        let poly = compute_shift_round_polynomial_flat(
            &s_in, &s_out, &state, &w_sin, &w_sout, &w_state,
        );
        for &c in &poly.coeffs {
            channel.absorb(c);
        }
        let r = channel.squeeze();
        let r_flat = tower_to_flat_u128(r.to_u128());
        fold_highest_var_inplace_flat(&mut s_in, r_flat);
        fold_highest_var_inplace_flat(&mut s_out, r_flat);
        fold_highest_var_inplace_flat(&mut state, r_flat);
        fold_highest_var_inplace_flat(&mut w_sin, r_flat);
        fold_highest_var_inplace_flat(&mut w_sout, r_flat);
        fold_highest_var_inplace_flat(&mut w_state, r_flat);
        r_double_prime[N_AUTH_UNIFIED_VARS - 1 - round] = r;
        round_polys.push(poly);
    }

    let s_in_at_r2 = Block128::from(flat_to_tower_u128(s_in[0]));
    let s_out_at_r2 = Block128::from(flat_to_tower_u128(s_out[0]));
    let state_at_r2 = Block128::from(flat_to_tower_u128(state[0]));
    channel.absorb(s_in_at_r2);
    channel.absorb(s_out_at_r2);
    channel.absorb(state_at_r2);

    (
        AuthShiftProof {
            round_polys,
            s_in_at_r2,
            s_out_at_r2,
            state_at_r2,
        },
        r_double_prime,
    )
}

pub fn verify_auth_shift<T: FiatShamir<Block128>>(
    proof: &AuthShiftProof,
    main_red: &AuthUnifiedReduction,
    channel: &mut T,
) -> Option<AuthShiftReduction> {
    if proof.round_polys.len() != N_AUTH_UNIFIED_VARS {
        return None;
    }
    for p in &proof.round_polys {
        if p.degree() > AUTH_SHIFT_ROUND_DEGREE {
            return None;
        }
    }
    let delta = channel.squeeze();
    let target = combined_target(main_red, delta);

    let mut expected = target;
    let mut r_double_prime = vec![Block128::ZERO; N_AUTH_UNIFIED_VARS];
    for (round, poly) in proof.round_polys.iter().enumerate() {
        let s = poly.evaluate(Block128::ZERO) + poly.evaluate(Block128::ONE);
        if s != expected {
            return None;
        }
        for &c in &poly.coeffs {
            channel.absorb(c);
        }
        let r = channel.squeeze();
        expected = poly.evaluate(r);
        r_double_prime[N_AUTH_UNIFIED_VARS - 1 - round] = r;
    }

    let w = combined_weights_at_point(&main_red.r_prime, delta, &r_double_prime);
    let claimed = w.w_sin * proof.s_in_at_r2
        + w.w_sout * proof.s_out_at_r2
        + w.w_state * proof.state_at_r2;
    if expected != claimed {
        return None;
    }

    channel.absorb(proof.s_in_at_r2);
    channel.absorb(proof.s_out_at_r2);
    channel.absorb(proof.state_at_r2);

    Some(AuthShiftReduction {
        r_double_prime,
        s_in_at_r2: proof.s_in_at_r2,
        s_out_at_r2: proof.s_out_at_r2,
        state_at_r2: proof.state_at_r2,
    })
}

struct CombinedWeights {
    w_sin: Vec<Block128>,
    w_sout: Vec<Block128>,
    w_state: Vec<Block128>,
}

struct WeightsAtPoint {
    w_sin: Block128,
    w_sout: Block128,
    w_state: Block128,
}

fn build_combined_weights(r_prime: &[Block128], delta: Block128) -> CombinedWeights {
    let r_slot = &r_prime[SLOT_LO..SLOT_HI];
    let r_round = &r_prime[ROUND_LO..ROUND_HI];
    let r_elem = &r_prime[ELEM_LO..ELEM_HI];

    let mut w_dec = vec![Block128::ZERO; N_AUTH_UNIFIED_CELLS];
    let mut w_lane: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![Block128::ZERO; N_AUTH_UNIFIED_CELLS]);

    let n_slots = 1usize << N_AUTH_SLOT_BITS;
    let n_rounds = 1usize << N_AUTH_ROUND_VARS;
    let n_elems = 1usize << N_AUTH_ELEM_VARS;

    let eq_slot_tab = boolean_tensor(r_slot);
    let eq_elem_tab = boolean_tensor(r_elem);

    let mut eq_round_at_inc = vec![Block128::ZERO; n_rounds];
    let eq_round_tab = boolean_tensor(r_round);
    for round_x in 0..n_rounds {
        let inc = (round_x + 1) & (n_rounds - 1);
        eq_round_at_inc[round_x] = eq_round_tab[inc];
    }

    for slot in 0..n_slots {
        let es = eq_slot_tab[slot];
        for round_x in 0..n_rounds {
            let er = eq_round_at_inc[round_x];
            let es_er = es * er;
            for elem in 0..n_elems {
                let idx = (slot << SLOT_LO) | (round_x << ROUND_LO) | (elem << ELEM_LO);
                let ee = eq_elem_tab[elem];
                w_dec[idx] = es_er * ee;
                w_lane[elem][idx] = es_er;
            }
        }
    }

    let d0 = Block128::ONE;
    let d1 = delta;
    let d2 = d1 * delta;
    let d3 = d2 * delta;
    let d4 = d3 * delta;
    let d5 = d4 * delta;
    let d6 = d5 * delta;
    let d7 = d6 * delta;
    let d8 = d7 * delta;
    let d9 = d8 * delta;
    let d10 = d9 * delta;

    let lane_sout = [d3, d4, d5, d6];
    let lane_state = [d7, d8, d9, d10];

    let mut w_sin = vec![Block128::ZERO; N_AUTH_UNIFIED_CELLS];
    let mut w_sout = vec![Block128::ZERO; N_AUTH_UNIFIED_CELLS];
    let mut w_state = vec![Block128::ZERO; N_AUTH_UNIFIED_CELLS];

    for x in 0..N_AUTH_UNIFIED_CELLS {
        let dec = w_dec[x];
        w_sin[x] = d0 * dec;
        w_sout[x] = d1 * dec;
        w_state[x] = d2 * dec;
        let elem = x & ((1 << N_AUTH_ELEM_VARS) - 1);
        w_sout[x] += lane_sout[elem] * w_lane[elem][x];
        w_state[x] += lane_state[elem] * w_lane[elem][x];
    }

    CombinedWeights {
        w_sin,
        w_sout,
        w_state,
    }
}

fn combined_target(red: &AuthUnifiedReduction, delta: Block128) -> Block128 {
    let d0 = Block128::ONE;
    let d1 = delta;
    let d2 = d1 * delta;
    let mut acc = d0 * red.s_in_dec_at_r + d1 * red.s_out_dec_at_r + d2 * red.state_dec_at_r;
    let mut p = d2 * delta;
    for j in 0..STATE_SIZE {
        acc += p * red.s_out_lane_dec_at_r[j];
        p *= delta;
    }
    for j in 0..STATE_SIZE {
        acc += p * red.state_lane_dec_at_r[j];
        p *= delta;
    }
    acc
}

fn combined_weights_at_point(
    r_prime: &[Block128],
    delta: Block128,
    r2: &[Block128],
) -> WeightsAtPoint {
    let rp_slot = &r_prime[SLOT_LO..SLOT_HI];
    let rp_round = &r_prime[ROUND_LO..ROUND_HI];
    let rp_elem = &r_prime[ELEM_LO..ELEM_HI];
    let r2_slot = &r2[SLOT_LO..SLOT_HI];
    let r2_round = &r2[ROUND_LO..ROUND_HI];
    let r2_elem = &r2[ELEM_LO..ELEM_HI];

    let eq_slot = eq_ind(rp_slot, r2_slot);
    let eq_elem = eq_ind(rp_elem, r2_elem);

    let n_rounds = 1usize << N_AUTH_ROUND_VARS;
    let eq_rp_round_tab = boolean_tensor(rp_round);
    let mut tab = vec![Block128::ZERO; n_rounds];
    for round_x in 0..n_rounds {
        let inc = (round_x + 1) & (n_rounds - 1);
        tab[round_x] = eq_rp_round_tab[inc];
    }
    let g_round = evaluate_slice(&tab, r2_round);

    let mut ind_j_at_r2 = [Block128::ZERO; STATE_SIZE];
    for (j, slot) in ind_j_at_r2.iter_mut().enumerate() {
        let mut acc = Block128::ONE;
        for (b, &r) in r2_elem.iter().enumerate() {
            if (j >> b) & 1 == 1 {
                acc *= r;
            } else {
                acc *= Block128::ONE + r;
            }
        }
        *slot = acc;
    }

    let w_dec_r2 = eq_slot * g_round * eq_elem;
    let lane_base = eq_slot * g_round;

    let d0 = Block128::ONE;
    let d1 = delta;
    let d2 = d1 * delta;
    let mut p = d2;
    let mut lane_sout = [Block128::ZERO; STATE_SIZE];
    for slot in lane_sout.iter_mut() {
        p *= delta;
        *slot = p;
    }
    let mut lane_state = [Block128::ZERO; STATE_SIZE];
    for slot in lane_state.iter_mut() {
        p *= delta;
        *slot = p;
    }

    let w_sin = d0 * w_dec_r2;
    let mut w_sout = d1 * w_dec_r2;
    let mut w_state = d2 * w_dec_r2;
    for j in 0..STATE_SIZE {
        let lane_w = lane_base * ind_j_at_r2[j];
        w_sout += lane_sout[j] * lane_w;
        w_state += lane_state[j] * lane_w;
    }

    WeightsAtPoint {
        w_sin,
        w_sout,
        w_state,
    }
}

fn boolean_tensor(point: &[Block128]) -> Vec<Block128> {
    use noid_core::mle::eq::eq_ind_partial_eval;
    eq_ind_partial_eval::<Block128>(point)
}

fn compute_shift_round_polynomial_flat(
    s_in: &[u128],
    s_out: &[u128],
    state: &[u128],
    w_sin: &[u128],
    w_sout: &[u128],
    w_state: &[u128],
) -> RoundPolynomial<Block128> {
    let half = s_in.len() / 2;
    let mut evals = [0u128; AUTH_SHIFT_ROUND_DEGREE + 1];
    let t_flat: [u128; AUTH_SHIFT_ROUND_DEGREE + 1] =
        std::array::from_fn(|k| tower_to_flat_u128(k as u128));

    for i in 0..half {
        let (sin0, sin1) = (s_in[i], s_in[i + half]);
        let (sout0, sout1) = (s_out[i], s_out[i + half]);
        let (st0, st1) = (state[i], state[i + half]);
        let (wsin0, wsin1) = (w_sin[i], w_sin[i + half]);
        let (wsout0, wsout1) = (w_sout[i], w_sout[i + half]);
        let (wst0, wst1) = (w_state[i], w_state[i + half]);

        let dsin = sin0 ^ sin1;
        let dsout = sout0 ^ sout1;
        let dst = st0 ^ st1;
        let dwsin = wsin0 ^ wsin1;
        let dwsout = wsout0 ^ wsout1;
        let dwst = wst0 ^ wst1;

        for k in 0..=AUTH_SHIFT_ROUND_DEGREE {
            let t = t_flat[k];
            let sin = sin0 ^ clmul_gcm(t, dsin);
            let sout = sout0 ^ clmul_gcm(t, dsout);
            let st = st0 ^ clmul_gcm(t, dst);
            let wsin = wsin0 ^ clmul_gcm(t, dwsin);
            let wsout = wsout0 ^ clmul_gcm(t, dwsout);
            let wst = wst0 ^ clmul_gcm(t, dwst);
            evals[k] ^=
                clmul_gcm(wsin, sin) ^ clmul_gcm(wsout, sout) ^ clmul_gcm(wst, st);
        }
    }

    let evals_tower: [Block128; AUTH_SHIFT_ROUND_DEGREE + 1] =
        std::array::from_fn(|k| Block128::from(flat_to_tower_u128(evals[k])));
    RoundPolynomial::from_evals(&evals_tower)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_mle_v2::{build_auth_unified_mle_v2, N_AUTH_LIVE_SLOTS};
    use noid_poseidon2b::channel::Poseidon2bChannel;

    fn random_state(seed: u128) -> [Block128; STATE_SIZE] {
        let mut s = seed.wrapping_add(0xC0FFEE);
        std::array::from_fn(|_| {
            s = s.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(0xDEAD_BEEF);
            Block128::from(s)
        })
    }

    fn random_mle(seed: u128) -> AuthUnifiedMle {
        let state_ins: Vec<_> = (0..N_AUTH_LIVE_SLOTS)
            .map(|i| random_state(i as u128 + seed))
            .collect();
        let (mle, _) = build_auth_unified_mle_v2(&state_ins);
        mle
    }

    #[test]
    fn round_degree_constants() {
        assert_eq!(AUTH_UNIFIED_ROUND_DEGREE, 9);
        assert_eq!(AUTH_SHIFT_ROUND_DEGREE, 2);
    }

    #[test]
    fn honest_main_verifies() {
        let mle = random_mle(17);

        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _r_prime) = prove_auth_unified(&mle, &mut ch_p);
        assert_eq!(proof.round_polys.len(), N_AUTH_UNIFIED_VARS);

        let mut ch_v = Poseidon2bChannel::new();
        let red = verify_auth_unified(&proof, &mut ch_v).expect("verify must accept");
        assert_eq!(red.r_prime.len(), N_AUTH_UNIFIED_VARS);
        assert_eq!(ch_p.squeeze(), ch_v.squeeze());
    }

    #[test]
    fn final_main_claims_match_native_evaluations() {
        let mle = random_mle(91);

        let mut ch_p = Poseidon2bChannel::new();
        let (proof, _r_prime) = prove_auth_unified(&mle, &mut ch_p);

        let mut ch_v = Poseidon2bChannel::new();
        let red = verify_auth_unified(&proof, &mut ch_v).unwrap();

        assert_eq!(evaluate_slice(&mle.state, &red.r_prime), red.state_at_r);
        assert_eq!(
            evaluate_slice(&auth_permute_by_dec(&mle.s_in), &red.r_prime),
            red.s_in_dec_at_r
        );
        assert_eq!(
            evaluate_slice(&auth_permute_by_dec(&mle.s_out), &red.r_prime),
            red.s_out_dec_at_r
        );
        assert_eq!(
            evaluate_slice(&auth_permute_by_dec(&mle.state), &red.r_prime),
            red.state_dec_at_r
        );

        let s_out_dec_full = auth_permute_by_dec(&mle.s_out);
        let state_dec_full = auth_permute_by_dec(&mle.state);
        for j in 0..STATE_SIZE {
            assert_eq!(
                evaluate_slice(&auth_project_lane(&s_out_dec_full, j), &red.r_prime),
                red.s_out_lane_dec_at_r[j],
                "s_out lane {j}"
            );
            assert_eq!(
                evaluate_slice(&auth_project_lane(&state_dec_full, j), &red.r_prime),
                red.state_lane_dec_at_r[j],
                "state lane {j}"
            );
        }
    }

    #[test]
    fn tampered_state_claim_is_rejected() {
        let mle = random_mle(5);

        let mut ch_p = Poseidon2bChannel::new();
        let (mut proof, _r_prime) = prove_auth_unified(&mle, &mut ch_p);
        proof.state_at_r += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_auth_unified(&proof, &mut ch_v).is_none());
    }

    #[test]
    fn tampered_round_poly_is_rejected() {
        let mle = random_mle(31);

        let mut ch_p = Poseidon2bChannel::new();
        let (mut proof, _r_prime) = prove_auth_unified(&mle, &mut ch_p);
        proof.round_polys[7].coeffs[0] += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_auth_unified(&proof, &mut ch_v).is_none());
    }

    fn run_full_pipeline(seed: u128) -> (AuthUnifiedMle, AuthKillShotProof) {
        let mle = random_mle(seed);
        let mut ch = Poseidon2bChannel::new();
        let (main, r_prime) = prove_auth_unified(&mle, &mut ch);
        let (shift, _r2) = prove_auth_shift(&mle, &r_prime, &mut ch);
        (mle, AuthKillShotProof { main, shift })
    }

    #[test]
    fn shift_gadget_round_count_and_degree() {
        let (_, proof) = run_full_pipeline(101);
        assert_eq!(proof.shift.round_polys.len(), N_AUTH_UNIFIED_VARS);
        for p in &proof.shift.round_polys {
            assert!(p.degree() <= AUTH_SHIFT_ROUND_DEGREE);
        }
    }

    #[test]
    fn shift_gadget_verifies_end_to_end() {
        let (_, proof) = run_full_pipeline(102);

        let mut ch = Poseidon2bChannel::new();
        let main_red = verify_auth_unified(&proof.main, &mut ch).expect("main verify");
        let shift_red = verify_auth_shift(&proof.shift, &main_red, &mut ch)
            .expect("shift verify");
        assert_eq!(shift_red.r_double_prime.len(), N_AUTH_UNIFIED_VARS);
    }

    #[test]
    fn shift_final_claims_match_native_evaluations() {
        let (mle, proof) = run_full_pipeline(103);

        let mut ch = Poseidon2bChannel::new();
        let main_red = verify_auth_unified(&proof.main, &mut ch).unwrap();
        let shift_red = verify_auth_shift(&proof.shift, &main_red, &mut ch).unwrap();

        assert_eq!(
            evaluate_slice(&mle.s_in, &shift_red.r_double_prime),
            shift_red.s_in_at_r2
        );
        assert_eq!(
            evaluate_slice(&mle.s_out, &shift_red.r_double_prime),
            shift_red.s_out_at_r2
        );
        assert_eq!(
            evaluate_slice(&mle.state, &shift_red.r_double_prime),
            shift_red.state_at_r2
        );
    }

    #[test]
    fn shift_tampered_final_claim_is_rejected() {
        let (_, mut proof) = run_full_pipeline(104);
        proof.shift.s_in_at_r2 += Block128::ONE;

        let mut ch = Poseidon2bChannel::new();
        let main_red = verify_auth_unified(&proof.main, &mut ch).unwrap();
        assert!(verify_auth_shift(&proof.shift, &main_red, &mut ch).is_none());
    }

    #[test]
    fn shift_combined_target_matches_first_round_sum() {
        let (mle, _) = run_full_pipeline(106);

        let mut ch = Poseidon2bChannel::new();
        let (main, r_prime) = prove_auth_unified(&mle, &mut ch);
        let (shift, _r2) = prove_auth_shift(&mle, &r_prime, &mut ch);

        let mut ch_v = Poseidon2bChannel::new();
        let main_red = verify_auth_unified(&main, &mut ch_v).unwrap();
        let delta = ch_v.squeeze();
        let target = combined_target(&main_red, delta);
        let first = &shift.round_polys[0];
        assert_eq!(first.evaluate(Block128::ZERO) + first.evaluate(Block128::ONE), target);
    }
}
