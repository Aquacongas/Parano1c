// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The owner-auth killshot in the trace (direct replay per tx; the separate
//! auth-FS-transcript killshot is deliberately NOT replayed — the direct
//! replay is ~3.9x cheaper than verifying that killshot).
//!
//! Trace twins of `noid_gkr::owner_auth::verify_owner_auth_killshot`'s GKR
//! layers, challenges included: the public-boundary and commitment absorbs,
//! `verify_owner_auth_unified`, `verify_owner_auth_shift`,
//! `verify_owner_auth_boundary` (both weighted-state sumchecks) and the
//! single-column `verify_batch_eval` closure.
//!
//! ## The wallet-PCS obligation
//!
//! The final native check — `verify_auth_mle_opening` (the wallet PCS: a
//! `noid_fri_binius` compact-FRI mixed opening on its own `noid_fri::Channel`)
//! — is intentionally split out: [`verify_owner_auth_killshot_trace`] returns
//! a [`PendingAuthPcsObligation`] carrying exactly the inputs of the native
//! check (commitment wires + the reduced `(point, value)` claim), and
//! `super::auth_pcs::discharge_auth_pcs_obligation` replays that opening.
//! An assembled proof MUST NOT be considered complete while any obligation
//! is undischarged.

use noid_core::{Block128, TowerField};
use noid_gkr::owner_auth::{
    owner_auth_sigma_at, OwnerAuthKillShotProof, OwnerAuthLayout, OwnerAuthProofKillShot,
    OwnerAuthPublicInputs, OWNER_AUTH_BOUNDARY_DOMAIN_TAG, OWNER_AUTH_ELEM_VARS,
    OWNER_AUTH_GKR_DOMAIN_TAG, OWNER_AUTH_LIVE_SLOTS, OWNER_AUTH_NUM_VARS, OWNER_AUTH_PADDED_SLOTS,
    OWNER_AUTH_PIN_LANES, OWNER_AUTH_ROUND_VARS, OWNER_AUTH_SLOT_BITS,
    OWNER_AUTH_STATE_ROUND_DEGREE,
};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRFIX};
use noid_poseidon2b::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};

use super::batch_eval::{
    squeeze_alphas_trace, verify_batch_eval_trace, BatchEvalProofTrace, BatchEvalRoundTrace,
    EvalClaimTrace,
};
use super::block_spine::spine_point_index;
use super::{
    alloc_block, eq_ind_partial_eval_trace, eq_ind_trace, evaluate_slice_trace, flat_of, mul,
    pin_zero, BatchEvalReductionTrace, BooleanPointEqCache, FieldR1csBuilder, LinExpr,
    RawChannelTrace, RoundPolyTrace,
};

const ELEM_BITS: usize = OWNER_AUTH_ELEM_VARS; // 2 (same packing as block spine)
const ROUND_BITS: usize = OWNER_AUTH_ROUND_VARS; // 7
const ROUND_LIMIT: usize = 1 << ROUND_BITS;

fn owner_mds_coeff(round: usize, i: usize, j: usize) -> Block128 {
    let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
    let raw = if is_partial {
        MDS_PARTIAL[i][j]
    } else {
        MDS_FULL[i][j]
    };
    Block128::from(raw)
}

// ---------------------------------------------------------------------------
// Statement / proof wire types
// ---------------------------------------------------------------------------

/// Trace twin of the minimal `OwnerAuthPublicInputs`. The exact layout is
/// fixed metadata; only the transaction-body hash and sole owner address are
/// statement wires.
///
/// Statement-binding obligations (the block assembly must pin these wires
/// to values derived from the transaction statement): `tx_body_hash`,
/// every live address pair. Ghost address pairs are fixed zeros derived from
/// the layout rather than proof-carried statement data.
pub struct OwnerAuthPublicInputsTrace {
    pub layout: OwnerAuthLayout,
    pub tx_body_hash: [LinExpr; 2],
    pub expected_address: [LinExpr; 2],
    /// Slot-liveness selectors derived as constants from the exact layout.
    pub slot_live: Vec<LinExpr>,
}

impl OwnerAuthPublicInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &OwnerAuthPublicInputs) -> Self {
        let layout = native.layout;
        assert_eq!(layout, OwnerAuthLayout::FIXED);
        let expected_address = std::array::from_fn(|i| alloc_block(b, native.expected_address[i]));

        // The layout is fixed metadata, so live-vs-ghost selectors are
        // constants rather than malleable witness fields.
        let slot_live = vec![super::const_block(Block128::ONE)];

        Self {
            layout,
            tx_body_hash: std::array::from_fn(|i| alloc_block(b, native.tx_body_hash[i])),
            expected_address,
            slot_live,
        }
    }
}

/// Trace twin of `OwnerAuthProofKillShot`'s GKR part plus the commitment
/// lanes (the PCS opening body is replayed separately by
/// `super::auth_pcs::discharge_auth_pcs_obligation` — module docs).
pub struct OwnerAuthProofTrace {
    pub main_round_polys: Vec<RoundPolyTrace>,
    pub main_state_at_r: LinExpr,
    pub main_state_lane_dec_at_r: [LinExpr; STATE_SIZE],
    pub shift_round_polys: Vec<BatchEvalRoundTrace>,
    pub shift_state_at_r2: LinExpr,
    pub boundary_round_polys: Vec<BatchEvalRoundTrace>,
    pub boundary_state_at_r: LinExpr,
    pub batch: BatchEvalProofTrace,
    /// Commitment cap hash lanes (2 per 32-byte hash), absorbed into the
    /// killshot channel and consumed by the pending PCS obligation.
    pub commitment_cap_lanes: Vec<[LinExpr; 2]>,
    pub commitment_log_rows: usize,
}

impl OwnerAuthProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &OwnerAuthProofKillShot,
        _layout: OwnerAuthLayout,
    ) -> Self {
        let OwnerAuthKillShotProof { main, shift } = &native.kill_shot;
        assert_eq!(
            main.round_polys.len(),
            OWNER_AUTH_NUM_VARS,
            "proof off shape"
        );
        assert_eq!(
            shift.round_polys.len(),
            OWNER_AUTH_NUM_VARS,
            "proof off shape"
        );
        assert_eq!(
            native.boundary.round_polys.len(),
            OWNER_AUTH_NUM_VARS,
            "proof off shape"
        );
        // Native rejects a wrong log_rows — shape-assert here (it is
        // absorbed as a constant below).
        assert_eq!(
            native.pcs.commitment.log_rows, OWNER_AUTH_NUM_VARS,
            "proof off shape"
        );
        Self {
            main_round_polys: main
                .round_polys
                .iter()
                .map(|p| RoundPolyTrace::alloc(b, p, OWNER_AUTH_STATE_ROUND_DEGREE))
                .collect(),
            main_state_at_r: alloc_block(b, main.state_at_r),
            main_state_lane_dec_at_r: std::array::from_fn(|i| {
                alloc_block(b, main.state_lane_dec_at_r[i])
            }),
            shift_round_polys: shift
                .round_polys
                .iter()
                .map(|r| BatchEvalRoundTrace::alloc(b, r))
                .collect(),
            shift_state_at_r2: alloc_block(b, shift.state_at_r2),
            boundary_round_polys: native
                .boundary
                .round_polys
                .iter()
                .map(|r| BatchEvalRoundTrace::alloc(b, r))
                .collect(),
            boundary_state_at_r: alloc_block(b, native.boundary.state_at_r),
            batch: BatchEvalProofTrace::alloc(b, &native.batch, OWNER_AUTH_NUM_VARS),
            // Capsule digests are FLAT-basis lanes absorbed flat→tower by
            // the native channel, so each wire's flat value IS the raw
            // digest half (== the region tree column cell).
            commitment_cap_lanes: native
                .pcs
                .commitment
                .cap
                .hashes
                .iter()
                .map(|h| {
                    use noid_core::hardware::flat_to_tower_u128;
                    let lo = flat_to_tower_u128(u128::from_le_bytes(h[..16].try_into().unwrap()));
                    let hi = flat_to_tower_u128(u128::from_le_bytes(h[16..].try_into().unwrap()));
                    [
                        alloc_block(b, Block128::from(lo)),
                        alloc_block(b, Block128::from(hi)),
                    ]
                })
                .collect(),
            commitment_log_rows: native.pcs.commitment.log_rows,
        }
    }
}

/// What remains of the owner-auth slot once the GKR layers are replayed:
/// the wallet-PCS opening claim, discharged by
/// `super::auth_pcs::discharge_auth_pcs_obligation` (module docs).
pub struct PendingAuthPcsObligation {
    pub commitment_cap_lanes: Vec<[LinExpr; 2]>,
    pub num_vars: usize,
    pub reduction: BatchEvalReductionTrace,
}

// ---------------------------------------------------------------------------
// Absorbs
// ---------------------------------------------------------------------------

/// Trace twin of `absorb_owner_public_boundary`. Class parameters absorb as
/// constants; only the hash and address content absorbs as wires.
fn absorb_owner_public_boundary_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    inputs: &OwnerAuthPublicInputsTrace,
) {
    ch.absorb_const_tower(b, 1);
    ch.absorb_const_tower(b, OWNER_AUTH_LIVE_SLOTS as u128);
    ch.absorb_const_tower(b, OWNER_AUTH_SLOT_BITS as u128);
    ch.absorb_const_tower(b, OWNER_AUTH_NUM_VARS as u128);
    ch.absorb_const_tower(b, OWNER_AUTH_PADDED_SLOTS as u128);
    ch.absorb(b, &inputs.tx_body_hash[0]);
    ch.absorb(b, &inputs.tx_body_hash[1]);
    ch.absorb(b, &inputs.expected_address[0]);
    ch.absorb(b, &inputs.expected_address[1]);
}

/// Trace twin of `auth_pcs::absorb_auth_mle_commitment`.
fn absorb_auth_mle_commitment_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &OwnerAuthProofTrace,
) {
    const AUTH_PCS_COMMIT_TAG: u128 = 0xA07D_6B12_C011_17ED_u128;
    ch.absorb_const_tower(b, AUTH_PCS_COMMIT_TAG);
    ch.absorb_const_tower(b, proof.commitment_log_rows as u128);
    ch.absorb_const_tower(b, proof.commitment_cap_lanes.len() as u128);
    for lanes in &proof.commitment_cap_lanes {
        ch.absorb(b, &lanes[0]);
        ch.absorb(b, &lanes[1]);
    }
}

// ---------------------------------------------------------------------------
// Unified sumcheck
// ---------------------------------------------------------------------------

pub(crate) struct OwnerUnifiedReductionTrace {
    pub(crate) r_prime: Vec<LinExpr>,
    pub(crate) state_at_r: LinExpr,
    pub(crate) state_lane_dec_at_r: [LinExpr; STATE_SIZE],
}

/// Factored final evaluations for `verify_owner_auth_unified`: the public
/// lane-dec tables are constants over the (slot, round, elem) product
/// structure, so their values at r' are affine in the eq tensors; the
/// rho-dependent `u` table factors exactly like the block spine's
/// (`fast_eval_block_schedules`). Values are identical to the native
/// full-table `evaluate_flat`/`evaluate_preflat` calls.
///
/// Channel-independent (challenges are parameters), so the region-layer
/// discharge ([`super::region_source_binding::discharge_owner_auth_killshots_via_region`])
/// reuses it verbatim while sourcing `rho`/`r_prime` from the walk-C carry
/// cells instead of an inline transcript.
pub(crate) fn owner_unified_final_evals(
    b: &mut FieldR1csBuilder,
    slot_live: &[LinExpr],
    rho: &[LinExpr],
    r_prime: &[LinExpr],
) -> (
    LinExpr,
    [LinExpr; STATE_SIZE],
    [LinExpr; STATE_SIZE],
    [LinExpr; STATE_SIZE],
) {
    let r_elem = &r_prime[..ELEM_BITS];
    let r_round = &r_prime[ELEM_BITS..ELEM_BITS + ROUND_BITS];
    let r_slot = &r_prime[ELEM_BITS + ROUND_BITS..];
    let rho_elem = &rho[..ELEM_BITS];
    let rho_round = &rho[ELEM_BITS..ELEM_BITS + ROUND_BITS];
    let rho_slot = &rho[ELEM_BITS + ROUND_BITS..];

    let eq_elem = eq_ind_partial_eval_trace(b, r_elem);
    let eq_round_r = eq_ind_partial_eval_trace(b, r_round);
    let eq_r_slot = eq_ind_partial_eval_trace(b, r_slot);
    let eq_rho_elem = eq_ind_partial_eval_trace(b, rho_elem);
    let eq_rho_round = eq_ind_partial_eval_trace(b, rho_round);
    let eq_rho_slot = eq_ind_partial_eval_trace(b, rho_slot);

    // Live-slot projection of the schedule tables: natively a sum over the
    // first `live_slots` eq terms; here every padded slot contributes
    // through its liveness selector so the term set is class-fixed.
    debug_assert_eq!(slot_live.len(), eq_r_slot.len());
    let mut live_sum_r = LinExpr::zero();
    for (g, e) in slot_live.iter().zip(eq_r_slot.iter()) {
        live_sum_r = live_sum_r.add(&mul(b, g, e));
    }

    // Inner sums over (round, elem) with constant schedule values.
    let mut mds_inner: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    let mut sigma_round_sum: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    let mut rc_round_sum: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());

    for round in 1..ROUND_LIMIT.min(N_ROUNDS + 1) {
        let eq_r = &eq_round_r[round];
        let prev = round - 1;
        for elem in 0..STATE_SIZE {
            let eq_re = mul(b, eq_r, &eq_elem[elem]);
            // mds_lane_dec[j][y] = mds_coeff(prev, elem(y), j).
            for (j, inner) in mds_inner.iter_mut().enumerate().take(STATE_SIZE) {
                *inner = inner.add(&eq_re.scale(flat_of(owner_mds_coeff(prev, elem, j))));
            }
        }
        // sigma/rc lane tables ignore elem(y) (row-projected): Σ_e eq_e = 1.
        let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&prev);
        for j in 0..STATE_SIZE {
            if owner_auth_sigma_at(prev, j) == Block128::ONE {
                sigma_round_sum[j] = sigma_round_sum[j].add(eq_r);
            }
            if !is_partial || j == 0 {
                rc_round_sum[j] = rc_round_sum[j]
                    .add(&eq_r.scale(flat_of(Block128::from(ROUND_CONSTANTS[j][prev]))));
            }
        }
    }

    let mds_lane_at_r: [LinExpr; STATE_SIZE] =
        std::array::from_fn(|j| mul(b, &live_sum_r, &mds_inner[j]));
    let sigma_lane_at_r: [LinExpr; STATE_SIZE] =
        std::array::from_fn(|j| mul(b, &live_sum_r, &sigma_round_sum[j]));
    let rc_lane_at_r: [LinExpr; STATE_SIZE] =
        std::array::from_fn(|j| mul(b, &live_sum_r, &rc_round_sum[j]));

    // u(y) = eq(rho, dec(y)) · mu(dec(y)) — factors into slot/round/elem;
    // the slot factor is live-projected through the same selectors.
    let mut u_slot_factor = LinExpr::zero();
    for s in 0..eq_r_slot.len() {
        let pair = mul(b, &eq_rho_slot[s], &eq_r_slot[s]);
        u_slot_factor = u_slot_factor.add(&mul(b, &slot_live[s], &pair));
    }
    let mut u_round_factor = LinExpr::zero();
    for r in 1..ROUND_LIMIT.min(N_ROUNDS + 1) {
        u_round_factor = u_round_factor.add(&mul(b, &eq_rho_round[r - 1], &eq_round_r[r]));
    }
    let mut u_elem_factor = LinExpr::zero();
    for e in 0..STATE_SIZE {
        u_elem_factor = u_elem_factor.add(&mul(b, &eq_rho_elem[e], &eq_elem[e]));
    }
    let u_sr = mul(b, &u_slot_factor, &u_round_factor);
    let u_at_r = mul(b, &u_sr, &u_elem_factor);

    (u_at_r, mds_lane_at_r, sigma_lane_at_r, rc_lane_at_r)
}

/// Trace twin of `verify_owner_auth_unified`.
fn verify_owner_auth_unified_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &OwnerAuthProofTrace,
    layout: OwnerAuthLayout,
    slot_live: &[LinExpr],
) -> OwnerUnifiedReductionTrace {
    let _ = layout;
    assert_eq!(proof.main_round_polys.len(), OWNER_AUTH_NUM_VARS);

    let rho: Vec<LinExpr> = ch.squeeze_n(b, OWNER_AUTH_NUM_VARS);

    let mut expected = LinExpr::zero();
    let mut r_prime: Vec<Option<LinExpr>> = vec![None; OWNER_AUTH_NUM_VARS];
    for (round, poly) in proof.main_round_polys.iter().enumerate() {
        // The linear coefficient comes from the running claim, so the
        // per-round sum check holds by construction (no pin).
        poly.absorb_coeffs(b, ch);
        let challenge = ch.squeeze(b);
        expected = poly.evaluate_reconstructed(b, &expected, &challenge);
        r_prime[OWNER_AUTH_NUM_VARS - 1 - round] = Some(challenge);
    }
    let r_prime: Vec<LinExpr> = r_prime.into_iter().map(Option::unwrap).collect();

    let (u_at_r, mds_lane, sigma_lane, rc_lane) =
        owner_unified_final_evals(b, slot_live, &rho, &r_prime);

    let mut q_at_r = proof.main_state_at_r.clone();
    for j in 0..STATE_SIZE {
        let x_j = proof.main_state_lane_dec_at_r[j].add(&rc_lane[j]);
        let x_j_pow7 = b.pow7(&x_j);
        let pi_j = mul(b, &sigma_lane[j], &x_j_pow7).add(&mul(
            b,
            &sigma_lane[j].add_const(super::F128::ONE),
            &proof.main_state_lane_dec_at_r[j],
        ));
        q_at_r = q_at_r.add(&mul(b, &mds_lane[j], &pi_j));
    }
    let rhs = mul(b, &u_at_r, &q_at_r);
    pin_zero(b, &expected.add(&rhs));

    ch.absorb(b, &proof.main_state_at_r);
    for v in &proof.main_state_lane_dec_at_r {
        ch.absorb(b, v);
    }

    OwnerUnifiedReductionTrace {
        r_prime,
        state_at_r: proof.main_state_at_r.clone(),
        state_lane_dec_at_r: proof.main_state_lane_dec_at_r.clone(),
    }
}

// ---------------------------------------------------------------------------
// Weighted-state sumchecks (shift + boundary)
// ---------------------------------------------------------------------------

/// Shared rounds of `verify_weighted_state_sumcheck` (checks + transcript);
/// the caller supplies W(r) per its weight structure and closes the pin.
fn weighted_state_rounds_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    round_polys: &[BatchEvalRoundTrace],
    target: LinExpr,
) -> (Vec<LinExpr>, LinExpr) {
    let mut expected = target;
    let mut r = Vec::with_capacity(round_polys.len());
    for poly in round_polys {
        poly.absorb_evals(b, ch);
        let challenge = ch.squeeze(b);
        expected = poly.evaluate(b, &expected.clone(), &challenge);
        r.push(challenge);
    }
    r.reverse();
    (r, expected)
}

/// Trace twin of `owner_combined_target`. Channel-independent (reused by the
/// region-layer discharge with `delta` from the walk-C carry cells).
pub(crate) fn owner_combined_target_trace(
    b: &mut FieldR1csBuilder,
    red: &OwnerUnifiedReductionTrace,
    delta: &LinExpr,
) -> LinExpr {
    let d1 = delta.clone();
    let d2 = mul(b, &d1, delta);
    let d3 = mul(b, &d2, delta);
    let d4 = mul(b, &d3, delta);
    let lane = [d1, d2, d3, d4];
    let mut acc = red.state_at_r.clone();
    for j in 0..STATE_SIZE {
        acc = acc.add(&mul(b, &lane[j], &red.state_lane_dec_at_r[j]));
    }
    acc
}

/// W(r'') of the shift weights (`build_owner_combined_weights` evaluated at
/// r'' — the factored form of the block spine's combined-weight evaluation,
/// state column only). Channel-independent (reused by the region-layer
/// discharge with `delta`/`r2` from the walk-C carry cells).
pub(crate) fn owner_shift_weights_at_point(
    b: &mut FieldR1csBuilder,
    layout: OwnerAuthLayout,
    r_prime: &[LinExpr],
    delta: &LinExpr,
    r2: &[LinExpr],
) -> LinExpr {
    let rp_elem = &r_prime[..ELEM_BITS];
    let rp_round = &r_prime[ELEM_BITS..ELEM_BITS + ROUND_BITS];
    let _ = layout;
    let rp_slot = &r_prime[ELEM_BITS + ROUND_BITS..OWNER_AUTH_NUM_VARS];
    let r2_elem = &r2[..ELEM_BITS];
    let r2_round = &r2[ELEM_BITS..ELEM_BITS + ROUND_BITS];
    let r2_slot = &r2[ELEM_BITS + ROUND_BITS..OWNER_AUTH_NUM_VARS];

    let eq_slot = if rp_slot.is_empty() {
        LinExpr::constant(super::F128::ONE)
    } else {
        eq_ind_trace(b, rp_slot, r2_slot)
    };
    let eq_elem = eq_ind_trace(b, rp_elem, r2_elem);
    let eq_round = eq_ind_trace(b, rp_round, r2_round);

    // g_round: eq(rp_round, inc(·)) evaluated at r2_round.
    let eq_rp_round_tab = eq_ind_partial_eval_trace(b, rp_round);
    let mut tab: Vec<LinExpr> = vec![LinExpr::zero(); ROUND_LIMIT];
    for (round_x, slot) in tab.iter_mut().enumerate().take(ROUND_LIMIT) {
        let inc = (round_x + 1) & (ROUND_LIMIT - 1);
        *slot = eq_rp_round_tab[inc].clone();
    }
    let g_round = evaluate_slice_trace(b, &tab, r2_round);
    let ind_j_at_r2 = eq_ind_partial_eval_trace(b, r2_elem);

    let d1 = delta.clone();
    let d2 = mul(b, &d1, delta);
    let d3 = mul(b, &d2, delta);
    let d4 = mul(b, &d3, delta);
    let lane_state = [d1, d2, d3, d4];

    // w_direct + Σ_j lane_j · eq_slot·g_round·ind_j.
    let eq_sr = mul(b, &eq_slot, &eq_round);
    let w_direct = mul(b, &eq_sr, &eq_elem);
    let es_er = mul(b, &eq_slot, &g_round);
    let mut acc = w_direct;
    for j in 0..STATE_SIZE {
        let lane_w = mul(b, &es_er, &ind_j_at_r2[j]);
        acc = acc.add(&mul(b, &lane_state[j], &lane_w));
    }
    acc
}

/// Trace twin of `verify_owner_auth_shift`.
fn verify_owner_auth_shift_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &OwnerAuthProofTrace,
    layout: OwnerAuthLayout,
    main_red: &OwnerUnifiedReductionTrace,
) -> (Vec<LinExpr>, LinExpr) {
    assert_eq!(proof.shift_round_polys.len(), OWNER_AUTH_NUM_VARS);
    let delta = ch.squeeze(b);
    let target = owner_combined_target_trace(b, main_red, &delta);
    let (r_double_prime, expected) =
        weighted_state_rounds_trace(b, ch, &proof.shift_round_polys, target);
    let w_at_r =
        owner_shift_weights_at_point(b, layout, &main_red.r_prime, &delta, &r_double_prime);
    let rhs = mul(b, &w_at_r, &proof.shift_state_at_r2);
    pin_zero(b, &expected.add(&rhs));
    ch.absorb(b, &proof.shift_state_at_r2);
    (r_double_prime, proof.shift_state_at_r2.clone())
}

/// One boundary constraint: an α-batched public linear relation over the
/// spine cells (`terms`) equal to a witness-dependent right-hand side
/// (`constant`). Channel-independent; shared by the inline twin and the
/// region-layer discharge.
pub(crate) struct ConstraintTrace {
    pub(crate) terms: Vec<(usize, Block128)>,
    pub(crate) constant: LinExpr,
}

/// Rebuild the boundary constraints (from `owner_auth_boundary_constraints`)
/// over every PADDED slot: per owner, the two capacity-IV pre pins through the
/// inverse MDS and the two address output pins.
///
/// Term structure is slot-uniform; ghost slots differ only in the right-hand
/// side, which the liveness selector zeroes: capacity-IV constants become
/// `g_s · iv` (affine in the selector, no rows), address constants
/// `g_s · address_wire` (one multiplication each). The constraint count and
/// every term coefficient are functions of the class alone. Channel-independent
/// so both the inline `verify_owner_auth_boundary_trace` and the region-layer
/// discharge rebuild identical constraints.
pub(crate) fn owner_boundary_constraints(
    b: &mut FieldR1csBuilder,
    inputs: &OwnerAuthPublicInputsTrace,
    layout: OwnerAuthLayout,
) -> Vec<ConstraintTrace> {
    let inv = mds_full_inverse_flat();
    let iv_addr = capacity_iv(TAG_ADDRFIX);
    let _ = (b, layout);
    let mut constraints: Vec<ConstraintTrace> = Vec::with_capacity(4);
    let base = 0;
    for (pre_lane, iv_lane) in [(2usize, iv_addr[0]), (3usize, iv_addr[1])] {
        let terms = (0..STATE_SIZE)
            .map(|post_lane| {
                (
                    spine_point_index(OWNER_AUTH_NUM_VARS, base, 0, post_lane),
                    inv[pre_lane][post_lane],
                )
            })
            .collect();
        constraints.push(ConstraintTrace {
            terms,
            constant: LinExpr::constant(flat_of(iv_lane)),
        });
    }
    for lane in 0..OWNER_AUTH_PIN_LANES {
        constraints.push(ConstraintTrace {
            terms: vec![(
                spine_point_index(OWNER_AUTH_NUM_VARS, base, N_ROUNDS, lane),
                Block128::ONE,
            )],
            constant: inputs.expected_address[lane].clone(),
        });
    }
    constraints
}

/// The α-batched boundary target `Σ_c α_c · constant_c` (`α_0 = 1` folds free).
/// Channel-independent; shared by the inline twin and the region discharge.
pub(crate) fn owner_boundary_target(
    b: &mut FieldR1csBuilder,
    constraints: &[ConstraintTrace],
    alphas: &[LinExpr],
) -> LinExpr {
    let mut target = constraints[0].constant.clone();
    for (c, a) in constraints.iter().zip(alphas.iter()).skip(1) {
        target = target.add(&mul(b, a, &c.constant));
    }
    target
}

/// The boundary weight `W(point) = Σ_c α_c · Σ_terms coeff · eq_cell(point)`.
/// Channel-independent; shared by the inline twin and the region discharge.
pub(crate) fn owner_boundary_w(
    b: &mut FieldR1csBuilder,
    constraints: &[ConstraintTrace],
    alphas: &[LinExpr],
    point: &[LinExpr],
) -> LinExpr {
    let mut eq_cache = BooleanPointEqCache::new(point);
    let mut w_at = LinExpr::zero();
    for (c, a) in constraints.iter().zip(alphas.iter()) {
        let mut inner = LinExpr::zero();
        for &(cell, coeff) in &c.terms {
            let eq = eq_cache.eq_at_index(b, cell);
            inner = inner.add(&eq.scale(flat_of(coeff)));
        }
        if a.is_const() && a.constant == super::F128::ONE {
            w_at = w_at.add(&inner);
        } else {
            w_at = w_at.add(&mul(b, a, &inner));
        }
    }
    w_at
}

/// Trace twin of `verify_owner_auth_boundary` (constraints from
/// `owner_auth_boundary_constraints`: per owner, the two capacity-IV pre
/// pins through the inverse MDS and the two address output pins).
fn verify_owner_auth_boundary_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &OwnerAuthProofTrace,
    layout: OwnerAuthLayout,
    inputs: &OwnerAuthPublicInputsTrace,
) -> (Vec<LinExpr>, LinExpr) {
    assert_eq!(proof.boundary_round_polys.len(), OWNER_AUTH_NUM_VARS);

    let constraints = owner_boundary_constraints(b, inputs, layout);

    ch.absorb_const_tower(b, OWNER_AUTH_BOUNDARY_DOMAIN_TAG);
    ch.absorb_const_tower(b, constraints.len() as u128);
    let alphas = squeeze_alphas_trace(b, ch, constraints.len());

    let target = owner_boundary_target(b, &constraints, &alphas);

    let (point, expected) = weighted_state_rounds_trace(b, ch, &proof.boundary_round_polys, target);

    let w_at = owner_boundary_w(b, &constraints, &alphas, &point);
    let rhs = mul(b, &w_at, &proof.boundary_state_at_r);
    pin_zero(b, &expected.add(&rhs));
    ch.absorb(b, &proof.boundary_state_at_r);
    (point, proof.boundary_state_at_r.clone())
}

/// Trace twin of `owner_auth::mds_full_inverse` (a build-time constant).
fn mds_full_inverse_flat() -> [[Block128; STATE_SIZE]; STATE_SIZE] {
    let mut aug = [[Block128::ZERO; STATE_SIZE * 2]; STATE_SIZE];
    for row in 0..STATE_SIZE {
        for col in 0..STATE_SIZE {
            aug[row][col] = Block128::from(MDS_FULL[row][col]);
        }
        aug[row][STATE_SIZE + row] = Block128::ONE;
    }
    // Gauss-Jordan over GF(2^128).
    for col in 0..STATE_SIZE {
        let pivot = (col..STATE_SIZE)
            .find(|&r| aug[r][col] != Block128::ZERO)
            .expect("MDS_FULL is invertible");
        aug.swap(col, pivot);
        let inv = aug[col][col].invert();
        for c in 0..STATE_SIZE * 2 {
            aug[col][c] *= inv;
        }
        for r in 0..STATE_SIZE {
            if r == col || aug[r][col] == Block128::ZERO {
                continue;
            }
            let factor = aug[r][col];
            for c in 0..STATE_SIZE * 2 {
                let sub = factor * aug[col][c];
                aug[r][c] += sub;
            }
        }
    }
    std::array::from_fn(|r| std::array::from_fn(|c| aug[r][STATE_SIZE + c]))
}

// ---------------------------------------------------------------------------
// Killshot assembly
// ---------------------------------------------------------------------------

/// Trace twin of `verify_owner_auth_killshot` up to (excluding) the wallet
/// PCS check — see the module docs for the pending obligation.
/// `ch` must already carry the `OWNER_AUTH_GKR_DOMAIN_TAG` absorb
/// (`init_owner_auth_gkr_channel`), which `build_owner_auth_slot` does.
pub fn verify_owner_auth_killshot_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &OwnerAuthProofTrace,
    inputs: &OwnerAuthPublicInputsTrace,
) -> PendingAuthPcsObligation {
    let layout = inputs.layout;

    absorb_owner_public_boundary_trace(b, ch, inputs);
    absorb_auth_mle_commitment_trace(b, ch, proof);

    let main_red = verify_owner_auth_unified_trace(b, ch, proof, layout, &inputs.slot_live);
    let (r_double_prime, state_at_r2) =
        verify_owner_auth_shift_trace(b, ch, proof, layout, &main_red);
    let (boundary_point, boundary_state_at_r) =
        verify_owner_auth_boundary_trace(b, ch, proof, layout, inputs);

    let state_claims = vec![
        EvalClaimTrace {
            point: main_red.r_prime.clone(),
            value: main_red.state_at_r.clone(),
        },
        EvalClaimTrace {
            point: r_double_prime,
            value: state_at_r2,
        },
        EvalClaimTrace {
            point: boundary_point,
            value: boundary_state_at_r,
        },
    ];
    let red = verify_batch_eval_trace(b, ch, &proof.batch, &state_claims, OWNER_AUTH_NUM_VARS);

    PendingAuthPcsObligation {
        commitment_cap_lanes: proof.commitment_cap_lanes.clone(),
        num_vars: OWNER_AUTH_NUM_VARS,
        reduction: red,
    }
}

/// Full owner-auth [K] slot from native objects: fresh channel with the GKR
/// domain tag (`owner_auth_gkr_channel`), statement + proof alloc, verifier
/// replay. Returns the statement wires (for the [B] bindings — tx_body_hash
/// must share wires with the spine slot) and the pending PCS obligation.
pub fn build_owner_auth_slot(
    b: &mut FieldR1csBuilder,
    proof: &OwnerAuthProofKillShot,
    inputs: &OwnerAuthPublicInputs,
) -> (OwnerAuthPublicInputsTrace, PendingAuthPcsObligation) {
    let inputs_t = OwnerAuthPublicInputsTrace::alloc(b, inputs);
    let proof_t = OwnerAuthProofTrace::alloc(b, proof, inputs.layout);
    let mut ch = RawChannelTrace::new();
    ch.absorb_const_tower(b, OWNER_AUTH_GKR_DOMAIN_TAG);
    let obligation = verify_owner_auth_killshot_trace(b, &mut ch, &proof_t, &inputs_t);
    (inputs_t, obligation)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::test_support::assert_expr_is;
    use super::*;
    use noid_gkr::owner_auth::{
        compute_owner_auth_boundary, owner_auth_gkr_channel, prove_owner_auth_killshot,
        verify_owner_auth_killshot_with_claims, OwnerAuthInputs,
    };

    fn fixture(seed: u128) -> (OwnerAuthInputs, OwnerAuthPublicInputs) {
        let circuit = noid_gkr::owner_auth::OwnerAuthCircuit::build();
        let spend_secret = [Block128::from(seed + 1000), Block128::from(seed + 2000)];
        let tx_body_hash = [Block128::from(seed + 7), Block128::from(seed + 8)];
        let expected_address = compute_owner_auth_boundary(&circuit, spend_secret, tx_body_hash);
        let public = OwnerAuthPublicInputs::new(tx_body_hash, expected_address);
        let inputs = OwnerAuthInputs::from_parts(&public, spend_secret);
        (inputs, public)
    }

    /// Production fixed-matrix gate: distinct one-owner statements (different
    /// secrets, hashes and addresses) produce byte-identical matrices.
    #[test]
    fn fixed_matrix_within_class() {
        let digest = |seed: u128| {
            let circuit = noid_gkr::owner_auth::OwnerAuthCircuit::build();
            let spend_secret = [Block128::from(seed + 1000), Block128::from(seed + 2000)];
            let tx_body_hash = [Block128::from(seed + 7), Block128::from(seed + 8)];
            let expected_address =
                compute_owner_auth_boundary(&circuit, spend_secret, tx_body_hash);
            let public = OwnerAuthPublicInputs::new(tx_body_hash, expected_address);
            let inputs = OwnerAuthInputs::from_parts(&public, spend_secret);
            let proof = prove(&inputs);
            let mut b = FieldR1csBuilder::new();
            let _ = build_owner_auth_slot(&mut b, &proof, &public);
            let (r1cs, _z) = b.build();
            r1cs.statement_digest()
        };
        assert_eq!(
            digest(11),
            digest(999),
            "owner-auth slot matrix must depend only on the shape class"
        );
    }

    fn prove(inputs: &OwnerAuthInputs) -> OwnerAuthProofKillShot {
        let circuit = noid_gkr::owner_auth::OwnerAuthCircuit::build();
        let mut ch = owner_auth_gkr_channel();
        let (proof, _) = prove_owner_auth_killshot(&circuit, inputs, &mut ch);
        proof
    }

    fn native_gkr_accepts(proof: &OwnerAuthProofKillShot, public: &OwnerAuthPublicInputs) -> bool {
        let circuit = noid_gkr::owner_auth::OwnerAuthCircuit::build();
        let mut ch = owner_auth_gkr_channel();
        verify_owner_auth_killshot_with_claims(proof, &circuit, public, &mut ch).is_some()
    }

    fn trace_accepts(proof: &OwnerAuthProofKillShot, public: &OwnerAuthPublicInputs) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b = FieldR1csBuilder::new();
            let _ = build_owner_auth_slot(&mut b, proof, public);
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        }))
        .unwrap_or(false)
    }

    /// Positive lockstep: the trace's reduced claim equals the native
    /// verifier's, and the built system is satisfiable.
    #[test]
    fn owner_auth_trace_positive_lockstep() {
        let (inputs, public) = fixture(51);
        let proof = prove(&inputs);

        let circuit = noid_gkr::owner_auth::OwnerAuthCircuit::build();
        let mut ch = owner_auth_gkr_channel();
        let claims = verify_owner_auth_killshot_with_claims(&proof, &circuit, &public, &mut ch)
            .expect("native accepts the honest proof");

        let mut b = FieldR1csBuilder::new();
        let (_, obligation) = build_owner_auth_slot(&mut b, &proof, &public);
        for (e, v) in obligation
            .reduction
            .point
            .iter()
            .zip(claims.state.point.iter())
        {
            assert_expr_is(&b, e, *v, "owner-auth terminal point");
        }
        assert_expr_is(
            &b,
            &obligation.reduction.value,
            claims.state.value,
            "owner-auth terminal value",
        );
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest owner-auth trace unsat");
    }

    fn visit_gkr_proof_fields(p: &mut OwnerAuthProofKillShot, f: &mut dyn FnMut(&mut Block128)) {
        for rp in &mut p.kill_shot.main.round_polys {
            for c in &mut rp.coeffs_no_linear {
                f(c);
            }
        }
        f(&mut p.kill_shot.main.state_at_r);
        for v in &mut p.kill_shot.main.state_lane_dec_at_r {
            f(v);
        }
        for r in &mut p.kill_shot.shift.round_polys {
            for e in &mut r.evals_at_1_2 {
                f(e);
            }
        }
        f(&mut p.kill_shot.shift.state_at_r2);
        for r in &mut p.boundary.round_polys {
            for e in &mut r.evals_at_1_2 {
                f(e);
            }
        }
        f(&mut p.boundary.state_at_r);
        for r in &mut p.batch.rounds {
            for e in &mut r.evals_at_1_2 {
                f(e);
            }
        }
        f(&mut p.batch.b_final);
    }

    /// Replay-completeness auto-mutator over every GKR-layer proof field
    /// (the `pcs` opening body has its own mutator in `auth_pcs.rs`).
    #[test]
    fn owner_auth_gkr_proof_mutator_kills_all() {
        let (inputs, public) = fixture(90);
        let proof = prove(&inputs);
        let mut n_fields = 0usize;
        {
            let mut c = proof.clone();
            visit_gkr_proof_fields(&mut c, &mut |_| n_fields += 1);
        }
        let stride: usize = std::env::var("NOID_TRACE_MUTATE_STRIDE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let mut survivors = Vec::new();
        for target in (0..n_fields).step_by(stride) {
            let mut bad = proof.clone();
            let mut i = 0usize;
            visit_gkr_proof_fields(&mut bad, &mut |v| {
                if i == target {
                    *v += Block128::ONE;
                }
                i += 1;
            });
            assert!(
                !native_gkr_accepts(&bad, &public),
                "native accepted GKR mutant {target}"
            );
            if trace_accepts(&bad, &public) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving owner-auth GKR mutants: {survivors:?} of {n_fields}"
        );
    }

    /// Statement mutator: tx hash lanes and expected addresses.
    #[test]
    fn owner_auth_statement_mutator_kills_all() {
        let (inputs, public) = fixture(130);
        let proof = prove(&inputs);
        let mut survivors = Vec::new();
        for target in 0..4 {
            let mut bad = public.clone();
            if target < 2 {
                bad.tx_body_hash[target] += Block128::ONE;
            } else {
                bad.expected_address[target - 2] += Block128::ONE;
            }
            assert!(
                !native_gkr_accepts(&proof, &bad),
                "native accepted statement mutant {target}"
            );
            if trace_accepts(&proof, &bad) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving owner-auth statement mutants: {survivors:?}"
        );
    }

    /// Cross-test "trace ⇔ native (GKR layers)" on randomized cases.
    #[test]
    fn owner_auth_native_trace_equivalence() {
        let cases: usize = std::env::var("NOID_TRACE_CROSS_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let mut seed = 0x0A0E_4A07u128;
        let mut next = |m: u128| {
            seed = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            (seed >> 16) % m
        };
        let (inputs, public) = fixture(170);
        let proof = prove(&inputs);
        let mut n_fields = 0usize;
        {
            let mut c = proof.clone();
            visit_gkr_proof_fields(&mut c, &mut |_| n_fields += 1);
        }
        for case in 0..cases {
            let case_proof = if case % 2 == 0 {
                proof.clone()
            } else {
                let target = next(n_fields as u128) as usize;
                let mut bad = proof.clone();
                let mut i = 0usize;
                visit_gkr_proof_fields(&mut bad, &mut |v| {
                    if i == target {
                        *v += Block128::ONE;
                    }
                    i += 1;
                });
                bad
            };
            assert_eq!(
                native_gkr_accepts(&case_proof, &public),
                trace_accepts(&case_proof, &public),
                "native/trace divergence on case {case}"
            );
        }
    }
}
