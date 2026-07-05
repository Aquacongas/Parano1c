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
