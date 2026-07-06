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
use noid_fri_binius::compact_fri::compute_round_depth;
use noid_fri_binius::mixed_open::{
    high_pair_tree_depth, use_direct_source_expansion, MIXED_OPEN_TAG, MIXED_SOURCE_BINDING_TAG,
};
use noid_fri_binius::COMPACT_TAU;
use noid_gkr::auth_pcs::AuthMleOpeningProof;
use noid_gkr::owner_auth::{
    OwnerAuthProofKillShot, OwnerAuthPublicInputs, OWNER_AUTH_BOUNDARY_DOMAIN_TAG,
    OWNER_AUTH_GKR_DOMAIN_TAG, OWNER_AUTH_INPUT_PAD_SENTINEL, OWNER_AUTH_STATE_ROUND_DEGREE,
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

    fn hash_lanes(&mut self, h: &[u8; 32]) -> [Option<u128>; 2] {
        let a = Block128::from(u128::from_le_bytes(h[..16].try_into().unwrap()));
        let b = Block128::from(u128::from_le_bytes(h[16..].try_into().unwrap()));
        [self.data_lane(a), self.data_lane(b)]
    }
}

/// The wallet-capsule PCS channel schedule (`verify_auth_mle_opening`'s
/// transcript): `Channel::new()` + `absorb_cap` + `verify_mixed_opening`
/// over one committed column (`n_cols = 1`, no secondary claims).
///
/// Mirrors, in order: the cap absorb; the mixed-opening tag + openings +
/// γ draw; compact FRI's statement absorb (`eval_point`, batched claim),
/// τ tensor-batching draws, per-round sumcheck/root/depth absorbs and
/// fold draws, final-codeword absorb; the source-binding commitments
/// (tag, H table, high-fold roots+depths) and its query draw; compact
/// FRI's query draw. Tree depths and domain tags are protocol constants
/// of the shape class; everything else is witness data.
pub fn capsule_pcs_channel_schedule(
    proof: &AuthMleOpeningProof,
    num_vars: usize,
    reduction_point: &[Block128],
    num_queries: usize,
) -> ChannelSchedule {
    let commitment = &proof.commitment;
    let opening = &proof.opening;
    assert_eq!(commitment.log_rows, num_vars);
    assert_eq!(commitment.n_cols, 1);
    assert_eq!(reduction_point.len(), num_vars);
    let tau = COMPACT_TAU.min(num_vars);
    let n_rounds = num_vars - tau;
    assert_eq!(opening.fri_proof.sum_check_oracles.len(), n_rounds);
    assert_eq!(opening.fri_proof.fri_roots.len(), n_rounds);
    assert!(
        !use_direct_source_expansion(1, tau, num_vars),
        "capsule shapes use the folded source-binding path"
    );
    assert_eq!(
        opening.source_proof.folded_roots.len(),
        tau.saturating_sub(1)
    );
    assert_eq!(opening.all_openings.len(), 1);

    let mut s = ChannelSchedule::new();

    // absorb_cap: every cap hash as two 16-byte lanes.
    let mut cap_lanes = Vec::with_capacity(commitment.cap.hashes.len() * 2);
    for h in &commitment.cap.hashes {
        cap_lanes.extend(s.hash_lanes(h));
    }
    s.absorb_lanes(cap_lanes);

    // Mixed-opening tag + all openings, then γ.
    let mut lanes = vec![Some(MIXED_OPEN_TAG as u128)];
    for &v in &opening.all_openings {
        lanes.push(s.data_lane(v));
    }
    s.absorb_lanes(lanes);
    s.ops.push(TranscriptOp::Squeeze(1));

    // Compact FRI statement: eval_point then the batched claim (γ-Horner
    // with weights 1, γ, … — one column, so the claim IS the opening).
    let mut lanes = Vec::with_capacity(num_vars + 1);
    for &v in reduction_point {
        lanes.push(s.data_lane(v));
    }
    lanes.push(s.data_lane(opening.all_openings[0]));
    s.absorb_lanes(lanes);
    s.ops.push(TranscriptOp::Squeeze(tau));

    // Per-round: sumcheck oracle pair, round root, depth constant; fold
    // challenge.
    for round in 0..n_rounds {
        let [c0, c1] = opening.fri_proof.sum_check_oracles[round];
        let mut lanes = vec![s.data_lane(c0), s.data_lane(c1)];
        lanes.extend(s.hash_lanes(&opening.fri_proof.fri_roots[round]));
        lanes.push(Some(compute_round_depth(n_rounds, round) as u128));
        s.absorb_lanes(lanes);
        s.ops.push(TranscriptOp::Squeeze(1));
    }

    // Final codeword.
    let mut lanes = Vec::with_capacity(opening.fri_proof.final_codeword.len());
    for &v in &opening.fri_proof.final_codeword {
        lanes.push(s.data_lane(v));
    }
    s.absorb_lanes(lanes);

    // Source binding commitments: tag, H table, folded roots + depths.
    let mut lanes = vec![Some(MIXED_SOURCE_BINDING_TAG)];
    for &v in &opening.source_proof.h_evals {
        lanes.push(s.data_lane(v));
    }
    for (i, root) in opening.source_proof.folded_roots.iter().enumerate() {
        let layer_log = num_vars - 1 - i;
        lanes.extend(s.hash_lanes(root));
        lanes.push(Some(high_pair_tree_depth(layer_log) as u128));
    }
    s.absorb_lanes(lanes);

    // Source-binding query draw, then compact FRI's own query draw. Both
    // clamp the query count to the domain size (`gen_compact_queries`);
    // the compact-FRI domain `2^(n_rounds + LOG_RATE)` is small at wallet
    // shapes.
    let source_queries = num_queries.min(1usize << (num_vars + noid_fri::code::LOG_RATE));
    let fri_queries = num_queries.min(1usize << (n_rounds + noid_fri::code::LOG_RATE));
    s.ops.push(TranscriptOp::Squeeze(source_queries));
    s.ops.push(TranscriptOp::Squeeze(fri_queries));

    s
}

/// Domain tag mirrored from `noid_gkr::auth_pcs::absorb_auth_mle_commitment`
/// (private there). A change to the native constant changes this in the same
/// commit; the differential gate catches any divergence.
const AUTH_PCS_COMMIT_TAG: u128 = 0xA07D_6B12_C011_17ED;

/// Absorb one per-input statement vector, padded to `padded_len`: the live
/// length, then the live values, then the pad sentinel for each remaining
/// slot. The live length and the boundary between live values and sentinels
/// VARY within a shape class (different live-input counts), so every entry is
/// a witness-data lane; only the total count (`1 + padded_len`) is class-fixed.
fn push_padded_input_vector(
    s: &mut ChannelSchedule,
    lanes: &mut Vec<Option<u128>>,
    values: impl ExactSizeIterator<Item = u128>,
    padded_len: usize,
) {
    let live_len = values.len();
    lanes.push(s.data_lane(Block128::from(live_len as u128)));
    for v in values {
        lanes.push(s.data_lane(Block128::from(v)));
    }
    for _ in live_len..padded_len {
        lanes.push(s.data_lane(Block128::from(OWNER_AUTH_INPUT_PAD_SENTINEL)));
    }
}

/// The owner-authorization killshot channel schedule (the KSCHANNL
/// `Poseidon2bChannel` transcript of `verify_owner_auth_killshot`, up to but
/// NOT including the PCS opening — that runs on a separate FRICHANL channel
/// modeled by [`capsule_pcs_channel_schedule`]).
///
/// Mirrors, in order (`owner_auth::verify_owner_auth_killshot_with_claims`):
/// the channel init domain tag; the owner public boundary (layout scalars,
/// tx-body hash, three padded input vectors, per-slot addresses); the auth
/// MLE commitment absorb; the unified state sumcheck (`rho`, per-round
/// degree-10 oracle absorb + fold, `state_at_r` + lane decomposition); the
/// shift sumcheck (`delta`, per-round 2-eval absorb + fold, `state_at_r2`);
/// the boundary sumcheck (domain tag, constraint count, one α draw, per-round
/// absorb + fold, `state_at_r`); the batch-eval reduction (3 claim
/// length/value binds, one α draw, per-round absorb + fold).
///
/// Class-fixity: `slot_bits`, `num_vars`, `padded_slots`, `padded_input_len`,
/// all domain tags, the commitment scalars and constraint count are Const
/// (fixed by the shape class); `owner_count`, `live_slots`, the vector
/// live-lengths / values / sentinels, addresses, cap hashes, all round-poly
/// coefficients and reduced state values are witness data (they vary within a
/// class — 3 vs 4 owners share a class). This matches the in-trace owner-auth
/// verifier's witness/constant split.
pub fn owner_auth_channel_schedule(
    proof: &OwnerAuthProofKillShot,
    inputs: &OwnerAuthPublicInputs,
) -> ChannelSchedule {
    let layout = inputs.layout;
    let num_vars = layout.num_vars;
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
        s.data_lane(Block128::from(layout.owner_count as u128)),
        s.data_lane(Block128::from(layout.live_slots as u128)),
        Some(layout.slot_bits as u128),
        Some(num_vars as u128),
        Some(layout.padded_slots as u128),
    ];
    lanes.push(s.data_lane(inputs.tx_body_hash[0]));
    lanes.push(s.data_lane(inputs.tx_body_hash[1]));
    lanes.push(Some(inputs.padded_input_len as u128));
    push_padded_input_vector(
        &mut s,
        &mut lanes,
        inputs.live_input_positions.iter().map(|&p| p as u128),
        inputs.padded_input_len,
    );
    push_padded_input_vector(
        &mut s,
        &mut lanes,
        inputs.live_slot_indices.iter().map(|&x| x as u128),
        inputs.padded_input_len,
    );
    push_padded_input_vector(
        &mut s,
        &mut lanes,
        inputs.input_to_group.iter().map(|&g| g as u128),
        inputs.padded_input_len,
    );
    // Addresses for every padded slot (ghost slots >= owner_count as zero
    // pairs, selected by liveness in the region).
    for slot in 0..layout.padded_slots {
        let pair = inputs
            .expected_address
            .get(slot)
            .copied()
            .unwrap_or([Block128::from(0u128); 2]);
        lanes.push(s.data_lane(pair[0]));
        lanes.push(s.data_lane(pair[1]));
    }

    // Step 2: auth MLE commitment absorb.
    let commitment = &proof.pcs.commitment;
    lanes.push(Some(AUTH_PCS_COMMIT_TAG));
    lanes.push(Some(commitment.log_rows as u128));
    lanes.push(Some(commitment.n_cols as u128));
    lanes.push(Some(commitment.hash_backend.as_u128()));
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

    // Step 5: boundary sumcheck. domain tag + constraint count, one alpha
    // draw (squeeze_alphas m>0 => 1 squeeze), per round: 2 evals + fold,
    // state_at_r.
    let constraints_len = layout.padded_slots * 4;
    s.absorb_lanes(vec![
        Some(OWNER_AUTH_BOUNDARY_DOMAIN_TAG),
        Some(constraints_len as u128),
    ]);
    s.ops.push(TranscriptOp::Squeeze(1));
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
    // Const) and VALUE (data); one alpha draw; per round: 2 evals + fold.
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
