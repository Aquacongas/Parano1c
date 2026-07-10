//! The [G] region layer: class-fixed chain schedules that map every bulk
//! per-transaction verifier obligation (transcript channels, Merkle path
//! and tree hashing) onto witness-region columns verified by the
//! deep-chain walk + column relations.
//!
//! This module hosts the SCHEDULE EXTRACTORS: transliterations of the
//! native verifiers' transcript/hash usage into
//! [`noid_ivc_core::deep_chain::schedule`] op lists plus the witness data
//! streams that populate the region columns. Extractors are line-by-line
//! shadows of the native code they mirror (the wallet-capsule PCS
//! verifier here); any change to the native absorb/squeeze order changes
//! the extractor in the same commit, and integration gates hold the pair
//! in lockstep by comparing post-verification channel states.
//!
//! Basis convention: transcript lanes are tower-basis byte patterns
//! (`Block128`); region columns are flat-basis `F128`. The two sides
//! agree because lane XOR commutes with the basis change and the
//! deep-chain walk replays the same permutation on flat values.

use noid_core::Block128;
use noid_fri_binius::capsule::{CAPSULE_CAP_DEPTH, CAPSULE_NUM_QUERIES, CAPSULE_TAU};
use noid_gkr::auth_pcs::AuthMleOpeningProof;
use noid_gkr::owner_auth::{
    OwnerAuthLayout, OwnerAuthProofKillShot, OwnerAuthPublicInputs, OWNER_AUTH_BOUNDARY_DOMAIN_TAG,
    OWNER_AUTH_GKR_DOMAIN_TAG, OWNER_AUTH_LIVE_SLOTS, OWNER_AUTH_NUM_VARS, OWNER_AUTH_PADDED_SLOTS,
    OWNER_AUTH_SLOT_BITS, OWNER_AUTH_STATE_ROUND_DEGREE,
};
use noid_ivc_core::deep_chain::schedule::{flat_of_tower_u128, TranscriptOp};
use noid_ivc_core::field::F128;

/// A compiled channel schedule: the class-fixed op list plus the witness
/// lane values of one concrete proof (tower for native channel replay,
/// flat for the region columns).
pub struct ChannelSchedule {
    pub ops: Vec<TranscriptOp>,
    pub data_tower: Vec<Block128>,
    pub data_flat: Vec<F128>,
}

impl ChannelSchedule {
    fn new() -> Self {
        Self {
            ops: Vec::new(),
            data_tower: Vec::new(),
            data_flat: Vec::new(),
        }
    }

    fn absorb_lanes(&mut self, lanes: Vec<Option<u128>>) {
        self.ops.push(TranscriptOp::Absorb(lanes));
    }

    fn data_lane(&mut self, v: Block128) -> Option<u128> {
        self.data_tower.push(v);
        self.data_flat.push(flat_of_tower_u128(v.0));
        None
    }

    /// Two data lanes of one 32-byte capsule tree digest. Capsule digests
    /// are FLAT-basis lanes and the native channels absorb them converted
    /// flat→tower (the absorbed element IS the digest lane), so the flat
    /// data stream carries the raw digest halves — equal to the tree
    /// column cells, with no per-digest basis bridge in-trace.
    fn hash_lanes(&mut self, h: &[u8; 32]) -> [Option<u128>; 2] {
        use noid_core::hardware::flat_to_tower_u128;
        let lo = u128::from_le_bytes(h[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(h[16..].try_into().unwrap());
        let a = Block128::from(flat_to_tower_u128(lo));
        let b = Block128::from(flat_to_tower_u128(hi));
        [self.data_lane(a), self.data_lane(b)]
    }
}

/// Domain tags mirrored from `noid_fri_binius::capsule` (private there:
/// `absorb_capsule_commitment`'s commit tag and the opening tag). A change
/// to a native constant changes these in the same commit; the differential
/// gate catches any divergence.
pub(crate) const CAPSULE_COMMIT_TAG: u128 = 0xCA95_C0DE_C011_1701;
pub(crate) const CAPSULE_OPEN_TAG: u128 = 0xCA95_01E0_0AE4_1102;

/// The wallet-capsule PCS channel schedule (`verify_auth_mle_opening`'s
/// transcript): `Channel::new()` + `capsule_verify` over one committed
/// column.
///
/// Mirrors, in order: the commitment absorb (commit tag, `log_rows`, cap
/// length, cap hash lanes); the claim absorb (opening tag, value, point,
/// the 256 upper partial evals); the τ = 8 beta draws; the mid-layer root
/// absorb; the `h` table absorb; the grind nonce absorb + the ground
/// squeeze (its low [`noid_fri_binius::capsule::CAPSULE_GRIND_BITS`] bits
/// are zero — enforced by the discharge, not the schedule); the query
/// draw over `nv + CAPSULE_LOG_RATE` bits. Domain tags, `log_rows` and
/// the cap length are protocol constants of the shape class; everything
/// else is witness data.
pub fn capsule_pcs_channel_schedule(
    proof: &AuthMleOpeningProof,
    num_vars: usize,
    reduction_point: &[Block128],
) -> ChannelSchedule {
    let commitment = &proof.commitment;
    let opening = &proof.opening;
    assert_eq!(commitment.log_rows, num_vars);
    assert_eq!(reduction_point.len(), num_vars);
    assert!(num_vars > CAPSULE_TAU, "capsule column below the tau fold");
    let low_len = 1usize << (num_vars - CAPSULE_TAU);
    assert_eq!(opening.upper_partial_evals.len(), 1usize << CAPSULE_TAU);
    assert_eq!(opening.h_evals.len(), low_len);
    assert_eq!(commitment.cap.hashes.len(), 1usize << CAPSULE_CAP_DEPTH);

    let mut s = ChannelSchedule::new();

    // absorb_capsule_commitment: tag, shape constants, cap hash lanes.
    let mut lanes = vec![
        Some(CAPSULE_COMMIT_TAG),
        Some(commitment.log_rows as u128),
        Some(commitment.cap.hashes.len() as u128),
    ];
    for h in &commitment.cap.hashes {
        lanes.extend(s.hash_lanes(h));
    }
    s.absorb_lanes(lanes);

    // The claim: opening tag, value, point, upper partial evals; then the
    // τ beta draws.
    let mut lanes = Vec::with_capacity(2 + num_vars + opening.upper_partial_evals.len());
    lanes.push(Some(CAPSULE_OPEN_TAG));
    lanes.push(s.data_lane(opening.value));
    for &v in reduction_point {
        lanes.push(s.data_lane(v));
    }
    for &v in &opening.upper_partial_evals {
        lanes.push(s.data_lane(v));
    }
    s.absorb_lanes(lanes);
    s.ops.push(TranscriptOp::Squeeze(CAPSULE_TAU));

    // Mid-layer root, then the h table.
    let mid_lanes = s.hash_lanes(&opening.mid_root).to_vec();
    s.absorb_lanes(mid_lanes);
    let mut lanes = Vec::with_capacity(opening.h_evals.len());
    for &v in &opening.h_evals {
        lanes.push(s.data_lane(v));
    }
    s.absorb_lanes(lanes);

    // Grind: nonce absorb + the ground squeeze, then the query draw.
    let nonce_lane = s.data_lane(Block128::from(opening.grind_nonce as u128));
    s.absorb_lanes(vec![nonce_lane]);
    s.ops.push(TranscriptOp::Squeeze(1));
    s.ops.push(TranscriptOp::Squeeze(CAPSULE_NUM_QUERIES));

    s
}

/// Domain tag mirrored from `noid_gkr::auth_pcs::absorb_auth_mle_commitment`
/// (private there). A change to the native constant changes this in the same
/// commit; the differential gate catches any divergence.
const AUTH_PCS_COMMIT_TAG: u128 = 0xA07D_6B12_C011_17ED;

/// The owner-authorization killshot channel schedule (the KSCHANNL
/// `Poseidon2bChannel` transcript of `verify_owner_auth_killshot`, up to but
/// NOT including the PCS opening — that runs on a separate FRICHANL channel
/// modeled by [`capsule_pcs_channel_schedule`]).
///
/// Mirrors, in order (`owner_auth::verify_owner_auth_killshot_with_claims`):
/// the channel init domain tag; the owner public boundary (layout scalars,
/// tx-body hash, per-slot addresses); the auth
/// MLE commitment absorb; the unified state sumcheck (`rho`, per-round
/// degree-10 oracle absorb + fold, `state_at_r` + lane decomposition); the
/// shift sumcheck (`delta`, per-round 2-eval absorb + fold, `state_at_r2`);
/// the boundary sumcheck (domain tag, constraint count, one α draw, per-round
/// absorb + fold, `state_at_r`); the batch-eval reduction (3 claim
/// length/value binds, one α draw, per-round absorb + fold).
///
/// Class-fixity: the exact layout scalars, all domain tags, the commitment
/// scalars and constraint count are Const. Addresses, cap hashes, all
/// round-poly coefficients and reduced state values are witness data.
pub fn owner_auth_channel_schedule(
    proof: &OwnerAuthProofKillShot,
    inputs: &OwnerAuthPublicInputs,
) -> ChannelSchedule {
    let layout = inputs.layout;
    assert_eq!(layout, OwnerAuthLayout::FIXED);
    let num_vars = OWNER_AUTH_NUM_VARS;
    // Class-shape assertions: the schedule (op structure) is a function of
    // these counts alone.
    assert_eq!(proof.kill_shot.main.round_polys.len(), num_vars);
    for p in &proof.kill_shot.main.round_polys {
        assert_eq!(p.coeffs_no_linear.len(), OWNER_AUTH_STATE_ROUND_DEGREE);
    }
    assert_eq!(proof.kill_shot.shift.round_polys.len(), num_vars);
    for r in &proof.kill_shot.shift.round_polys {
        assert_eq!(r.evals_at_1_2.len(), 2);
    }
    assert_eq!(proof.boundary.round_polys.len(), num_vars);
    assert_eq!(proof.batch.rounds.len(), num_vars);

    let mut s = ChannelSchedule::new();

    // Step 0/1: channel init domain tag + owner public boundary. Modeled from
    // the raw IV, so the init absorb is the first op (the region replays the
    // whole channel from `capacity_iv(TAG_KSCHANNL)`).
    let mut lanes: Vec<Option<u128>> = vec![
        Some(OWNER_AUTH_GKR_DOMAIN_TAG),
        Some(1),
        Some(OWNER_AUTH_LIVE_SLOTS as u128),
        Some(OWNER_AUTH_SLOT_BITS as u128),
        Some(num_vars as u128),
        Some(OWNER_AUTH_PADDED_SLOTS as u128),
    ];
    lanes.push(s.data_lane(inputs.tx_body_hash[0]));
    lanes.push(s.data_lane(inputs.tx_body_hash[1]));
    lanes.push(s.data_lane(inputs.expected_address[0]));
    lanes.push(s.data_lane(inputs.expected_address[1]));

    // Step 2: auth MLE commitment absorb (tag, log_rows, cap length, cap
    // hash lanes — the capsule commitment carries no other shape fields).
    let commitment = &proof.pcs.commitment;
    lanes.push(Some(AUTH_PCS_COMMIT_TAG));
    lanes.push(Some(commitment.log_rows as u128));
    lanes.push(Some(commitment.cap.hashes.len() as u128));
    for h in &commitment.cap.hashes {
        lanes.extend(s.hash_lanes(h));
    }
    s.absorb_lanes(lanes);

    // Step 3: unified state sumcheck. rho, then per round: absorb the
    // degree-10 oracle coefficients, squeeze the fold challenge.
    s.ops.push(TranscriptOp::Squeeze(num_vars));
    for p in &proof.kill_shot.main.round_polys {
        let round_lanes: Vec<Option<u128>> =
            p.coeffs_no_linear.iter().map(|&c| s.data_lane(c)).collect();
        s.absorb_lanes(round_lanes);
        s.ops.push(TranscriptOp::Squeeze(1));
    }
    let mut lanes = vec![s.data_lane(proof.kill_shot.main.state_at_r)];
    for v in &proof.kill_shot.main.state_lane_dec_at_r {
        lanes.push(s.data_lane(*v));
    }
    s.absorb_lanes(lanes);

    // Step 4: shift sumcheck. delta, per round: 2 evals + fold, state_at_r2.
    s.ops.push(TranscriptOp::Squeeze(1));
    for r in &proof.kill_shot.shift.round_polys {
        let round_lanes: Vec<Option<u128>> =
            r.evals_at_1_2.iter().map(|&e| s.data_lane(e)).collect();
        s.absorb_lanes(round_lanes);
        s.ops.push(TranscriptOp::Squeeze(1));
    }
    let lane = s.data_lane(proof.kill_shot.shift.state_at_r2);
    s.absorb_lanes(vec![lane]);

    // Step 5: boundary sumcheck. domain tag + constraint count, the RLC
    // level draws (`rlc_levels(m)` squeezes — 1 at every transaction class),
    // per round: 2 evals + fold, state_at_r.
    let constraints_len = 4;
    s.absorb_lanes(vec![
        Some(OWNER_AUTH_BOUNDARY_DOMAIN_TAG),
        Some(constraints_len as u128),
    ]);
    s.ops
        .push(TranscriptOp::Squeeze(noid_gkr::batch_eval::rlc_levels(
            constraints_len,
        )));
    for r in &proof.boundary.round_polys {
        let round_lanes: Vec<Option<u128>> =
            r.evals_at_1_2.iter().map(|&e| s.data_lane(e)).collect();
        s.absorb_lanes(round_lanes);
        s.ops.push(TranscriptOp::Squeeze(1));
    }
    let lane = s.data_lane(proof.boundary.state_at_r);
    s.absorb_lanes(vec![lane]);

    // Step 6: batch-eval reduction over the 3 state claims (main/shift/
    // boundary). absorb_claims binds each claim's point LENGTH (num_vars,
    // Const) and VALUE (data); one RLC draw (`rlc_levels(3) = 1`); per
    // round: 2 evals + fold.
    let claim_values = [
        proof.kill_shot.main.state_at_r,
        proof.kill_shot.shift.state_at_r2,
        proof.boundary.state_at_r,
    ];
    let mut lanes = Vec::with_capacity(6);
    for &value in &claim_values {
        lanes.push(Some(num_vars as u128));
        lanes.push(s.data_lane(value));
    }
    s.absorb_lanes(lanes);
    s.ops.push(TranscriptOp::Squeeze(1));
    for r in &proof.batch.rounds {
        let round_lanes: Vec<Option<u128>> =
            r.evals_at_1_2.iter().map(|&e| s.data_lane(e)).collect();
        s.absorb_lanes(round_lanes);
        s.ops.push(TranscriptOp::Squeeze(1));
    }

    s
}
