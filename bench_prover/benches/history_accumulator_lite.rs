// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bench-only history/state accumulator kernel.
//!
//! This benchmark feeds real `AcceptedStateTransitionClaim` rows derived from
//! accepted no-user block transitions. It measures history/state folding only.

use std::env;
use std::time::Duration;

use bench_prover::{fmt_bytes, fmt_ms, time_once};
use noid_block::{
    accepted_state_transition_chain_claim, derive_no_user_tx_validation_artifacts,
    AcceptedStateTransitionClaim,
};
use noid_chain::consensus::params::{BLOCK_TIME, GENESIS_TARGET};
use noid_chain::consensus::template::build_block_template;
use noid_chain::header_anchor::{
    compute_header_chain_anchor, extend_header_chain_anchor, header_projection_digest,
    HeaderChainAnchor,
};
use noid_chain::state::ChainState;
use noid_chain::{add_work, block_work, Block, BlockHeader};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_core::{
    hardware::{clmul_gcm, flat_to_tower_u128, tower_to_flat_u128},
    transcript::FiatShamir,
    Block128, TowerField,
};
use noid_gkr::{
    discharge_fixed_field_hash_reductions_native, prove_fixed_field_hash_killshot,
    verify_fixed_field_hash_killshot, FixedFieldHashInputs, FixedFieldHashParams,
    HISTORY_CLAIM_FIELDS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::TAG_HISTPRF;
use noid_poseidon2b::primitives::{Address, Digest};
use noid_recursive::{
    accepted_block_claim_witness_from_fields, advance_local_history_cache,
    advance_local_history_recursive_chunk_head_cache, advance_local_history_recursive_head_cache,
    build_history_arc_pcd_recursive_step_statement, build_history_pcd_step_statement_native,
    discharge_fiat_shamir_transcript_batch_reductions_native, discharge_history_step_native,
    history_arc_pcd_accumulator_digest, history_arc_pcd_accumulator_hash_fields,
    history_arc_pcd_chunk_step_verifier_traces,
    history_arc_pcd_recursive_chunk_step_verifier_traces, history_pcd_step_statement_digest,
    history_pcd_step_statement_hash_fields, history_proof_digest, history_tagged_pair_hash_fields,
    init_local_history_cache_from_anchor, init_local_history_recursive_chunk_head_cache,
    init_local_history_recursive_head_cache, prove_history_arc_pcd_chunk_step_native,
    prove_history_arc_pcd_chunk_step_verifier_transcript_batch_native,
    prove_history_arc_pcd_from_recursive_chunk_head_cache,
    prove_history_arc_pcd_from_recursive_head_cache, prove_history_arc_pcd_one_step,
    prove_history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_native,
    prove_history_arc_pcd_recursive_step_native, prove_history_arc_pcd_step_native,
    prove_history_from_local_cache, prove_history_native, prove_history_step_native,
    verify_fiat_shamir_transcript_batch_killshot, verify_history_arc_pcd_chunk_step_proof_native,
    verify_history_arc_pcd_recursive_chain_head_shape_native,
    verify_history_arc_pcd_recursive_chunk_chain_head_shape_native,
    verify_history_arc_pcd_recursive_step_proof_native, verify_history_arc_pcd_step_proof_native,
    verify_history_proof_native, verify_history_proof_untrusted, verify_history_step_native,
    ChainAccumulator, HistoryAccumulationState, HistoryArcPcdAccumulator,
    HistoryArcPcdOneStepProof, HistoryProof, HistoryProofWitness, HistoryTransitionWitnessItem,
    LocalHistoryCache, LocalHistoryRecursiveChunkHeadCache, LocalHistoryRecursiveHeadCache,
    HISTORY_ACCUMULATION_STATE_HASH_FIELDS, HISTORY_ARC_PCD_ACCUMULATOR_FIELDS,
    HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS, HISTORY_ARC_PCD_CHUNK_MAX_STEPS,
    HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS, HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_FIELDS,
    HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS, HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_FIELDS,
    HISTORY_PCD_STEP_HASH_FIELDS, HISTORY_PCD_STEP_STATEMENT_FIELDS, HISTORY_PROOF_VERSION,
    HISTORY_TAGGED_PAIR_HASH_FIELDS,
};

const DEFAULT_NS: &[usize] = &[1, 18];
const DEFAULT_SAMPLES: usize = 9;
const DEFAULT_LOG_SLOTS: usize = 16;

#[derive(Debug, Clone)]
struct HistoryFixture {
    claims: Vec<AcceptedStateTransitionClaim>,
    headers: Vec<BlockHeader>,
    header_projection_digests: Vec<Digest>,
    start_anchor: HeaderChainAnchor,
    end_anchor: HeaderChainAnchor,
    start_accumulator: ChainAccumulator,
    claim_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
struct AccumResult {
    digest: Block128,
    beta: Block128,
    absorbed_fields: usize,
}

trait FieldSink {
    fn absorb(&mut self, value: Block128);

    #[inline]
    fn absorb_usize(&mut self, value: usize) {
        self.absorb(Block128::from(value as u128));
    }

    fn absorb_hash(&mut self, hash: &Digest) {
        let lo = Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap()));
        let hi = Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap()));
        self.absorb(lo);
        self.absorb(hi);
    }
}

struct ClmulRlc {
    acc_flat: u128,
    power_flat: u128,
    beta_flat: u128,
    absorbed_fields: usize,
}

impl ClmulRlc {
    fn new(beta: Block128) -> Self {
        Self {
            acc_flat: 0,
            power_flat: tower_to_flat_u128(Block128::ONE.to_u128()),
            beta_flat: tower_to_flat_u128(beta.to_u128()),
            absorbed_fields: 0,
        }
    }

    fn digest(&self) -> Block128 {
        Block128::from(flat_to_tower_u128(self.acc_flat))
    }
}

impl FieldSink for ClmulRlc {
    #[inline]
    fn absorb(&mut self, value: Block128) {
        self.acc_flat ^= clmul_gcm(self.power_flat, tower_to_flat_u128(value.to_u128()));
        self.power_flat = clmul_gcm(self.power_flat, self.beta_flat);
        self.absorbed_fields += 1;
    }
}

fn env_usize_list(name: &str, default: &[usize]) -> Vec<usize> {
    let Ok(value) = env::var(name) else {
        return default.to_vec();
    };
    let parsed = value
        .split(',')
        .filter_map(|part| part.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .collect::<Vec<_>>();
    if parsed.is_empty() {
        default.to_vec()
    } else {
        parsed
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default)
}

fn fmt_mem(snapshot: Option<MemSnapshot>) -> String {
    match snapshot {
        Some(snapshot) => format!("{:>7.1}M", snapshot.hwm_mb()),
        None => "      n/a".to_string(),
    }
}

fn parent_header(state: &mut ChainState) -> BlockHeader {
    BlockHeader {
        prev_block_hash: [0u8; 32],
        state_root: state.state_root(),
        tx_root: noid_chain::compute_tx_root(&[]),
        timestamp: 1_767_225_600,
        height: 0,
        miner_address: Address([0x44; 32]),
        nonce: 0,
        difficulty_target: GENESIS_TARGET,
        log_slots: state.state.log_slots() as u32,
        active_slot_count: state.active_slot_count,
        alloc_counter: state.alloc_counter,
    }
}

fn build_fixture(n: usize, log_slots: usize) -> HistoryFixture {
    let mut state = ChainState::with_log_slots(log_slots);
    let mut parent = parent_header(&mut state);
    let start_anchor =
        compute_header_chain_anchor(std::iter::once(&parent), [0u8; 32]).expect("start anchor");
    let start_accumulator = ChainAccumulator {
        height: start_anchor.height,
        state_root: start_anchor.state_root,
        chain_hash: [0u8; 32],
    };
    let mut headers = vec![parent];
    let mut accepted_headers = Vec::with_capacity(n);
    let mut claims = Vec::with_capacity(n);
    let mut projection_digests = Vec::with_capacity(n);

    for i in 0..n {
        let template = build_block_template(
            &parent,
            &state,
            &[parent.active_slot_count],
            vec![],
            Address([(0x55u8).wrapping_add((i & 0x3f) as u8); 32]),
            parent.timestamp + BLOCK_TIME,
            GENESIS_TARGET,
        )
        .expect("history bench template");
        let block = Block {
            header: template.clone().into_header(0),
            transactions: template.all_txs(),
        };
        let artifacts =
            derive_no_user_tx_validation_artifacts(&block, &parent, &state).expect("artifacts");
        let claim = AcceptedStateTransitionClaim::from_accepted_block(&block, &parent, &artifacts)
            .expect("history claim");

        state
            .apply_verified_exact_transition(
                artifacts.verified_transition.log_slots(),
                artifacts.verified_transition.child_utxo_root(),
                artifacts.verified_transition.child_guard_root(),
                artifacts.verified_transition.slot_updates(),
                artifacts.verified_transition.guard_bucket_update().cloned(),
                artifacts.verified_transition.active_slot_count(),
                artifacts.verified_transition.alloc_counter(),
            )
            .expect("apply verified transition");
        projection_digests.push(header_projection_digest(&block.header, &claim.block_id));
        parent = block.header;
        headers.push(parent);
        accepted_headers.push(parent);
        claims.push(claim);
    }

    let end_anchor = compute_header_chain_anchor(headers.iter(), [0u8; 32]).expect("end anchor");
    let claim_bytes = claims
        .iter()
        .map(|claim| bincode::serialized_size(claim).unwrap_or(0) as usize)
        .sum();

    HistoryFixture {
        claims,
        headers: accepted_headers,
        header_projection_digests: projection_digests,
        start_anchor,
        end_anchor,
        start_accumulator,
        claim_bytes,
    }
}

fn history_witness(fixture: &HistoryFixture) -> HistoryProofWitness {
    let items = fixture
        .headers
        .iter()
        .zip(fixture.claims.iter())
        .map(|(header, claim)| HistoryTransitionWitnessItem {
            header: header.clone(),
            block_id: claim.block_id,
            parent_state_root: claim.parent_state_root,
            child_state_root: claim.child_state_root,
            claim_fields: claim.fields(),
            chain_claim: accepted_state_transition_chain_claim(claim),
            claim_digest: claim.claim_digest,
        })
        .collect();
    HistoryProofWitness { items }
}

fn prove_fixture_history(fixture: &HistoryFixture) -> HistoryProof {
    let witness = history_witness(fixture);
    prove_history_native(
        fixture.start_anchor.clone(),
        fixture.end_anchor.clone(),
        fixture.start_accumulator.clone(),
        &witness,
    )
    .expect("history proof")
}

fn recursive_step_inputs(
    fixture: &HistoryFixture,
) -> (
    noid_recursive::HistoryArcPcdRecursiveStepStatement,
    HistoryArcPcdAccumulator,
    HistoryArcPcdAccumulator,
    Digest,
) {
    assert!(
        fixture.headers.len() >= 2,
        "recursive step bench needs two sequential blocks"
    );
    let witness = history_witness(fixture);
    let first_chainwork = add_work(
        &fixture.start_anchor.cumulative_chainwork,
        &block_work(&fixture.headers[0].difficulty_target),
    );
    let first_end_anchor =
        extend_header_chain_anchor(&fixture.start_anchor, &fixture.headers[0], first_chainwork)
            .expect("first block anchor");
    let first_witness = HistoryProofWitness {
        items: vec![witness.items[0].clone()],
    };
    let first_proof = prove_history_arc_pcd_one_step(
        fixture.start_anchor.clone(),
        first_end_anchor,
        fixture.start_accumulator.clone(),
        &first_witness,
    )
    .expect("first one-step proof");
    let previous_state = HistoryAccumulationState {
        version: HISTORY_PROOF_VERSION,
        height: first_proof.end_anchor.height,
        block_id: first_proof.end_anchor.block_id,
        projection_root: first_proof.end_anchor.projection_root,
        accumulator: first_proof.end_accumulator.clone(),
        folded_witness_root: first_proof.folded_witness_root,
        step_count: first_proof.step_count,
    };
    let previous_proof_digest = history_proof_digest(&first_proof);
    let previous_accumulator = first_proof.decider.pcd_accumulator.clone();
    let (step, reductions) = prove_history_step_native(
        &previous_state.accumulator,
        previous_state.block_id,
        previous_state.projection_root,
        &witness.items[1],
    )
    .expect("second step proof");
    let pcd_step = build_history_pcd_step_statement_native(&previous_state, &step, &reductions)
        .expect("second PCD step");
    let (_, arc_step) = prove_history_arc_pcd_step_native(&previous_accumulator, &pcd_step)
        .expect("second ARC/PCD step");
    let one_step = HistoryArcPcdOneStepProof { step, arc_step };
    let (statement, _, next_accumulator, next_proof_digest) =
        build_history_arc_pcd_recursive_step_statement(
            previous_proof_digest,
            &previous_accumulator,
            &previous_state,
            &one_step,
        )
        .expect("recursive step statement");
    (
        statement,
        previous_accumulator,
        next_accumulator,
        next_proof_digest,
    )
}

fn build_fixture_cache(fixture: &HistoryFixture) -> LocalHistoryCache {
    let mut cache = init_local_history_cache_from_anchor(
        fixture.start_anchor.clone(),
        fixture.start_accumulator.clone(),
    )
    .expect("start local history cache");
    for (header, claim) in fixture.headers.iter().zip(fixture.claims.iter()) {
        let witness =
            accepted_block_claim_witness_from_fields(claim.fields()).expect("claim witness");
        cache = advance_local_history_cache(&cache, &witness, header, [0u8; 32])
            .expect("advance local history cache");
    }
    cache
}

fn build_fixture_recursive_head_cache(fixture: &HistoryFixture) -> LocalHistoryRecursiveHeadCache {
    let base = init_local_history_cache_from_anchor(
        fixture.start_anchor.clone(),
        fixture.start_accumulator.clone(),
    )
    .expect("start local history cache");
    let mut cache =
        init_local_history_recursive_head_cache(base).expect("start recursive-head cache");
    for (header, claim) in fixture.headers.iter().zip(fixture.claims.iter()) {
        let witness =
            accepted_block_claim_witness_from_fields(claim.fields()).expect("claim witness");
        cache = advance_local_history_recursive_head_cache(&cache, &witness, header, [0u8; 32])
            .expect("advance recursive-head cache");
    }
    cache
}

fn build_fixture_recursive_chunk_head_cache(
    fixture: &HistoryFixture,
) -> LocalHistoryRecursiveChunkHeadCache {
    let base = init_local_history_cache_from_anchor(
        fixture.start_anchor.clone(),
        fixture.start_accumulator.clone(),
    )
    .expect("start local history cache");
    let mut cache =
        init_local_history_recursive_chunk_head_cache(base).expect("start recursive chunk cache");
    for (headers, claims) in fixture
        .headers
        .chunks(HISTORY_ARC_PCD_CHUNK_MAX_STEPS)
        .zip(fixture.claims.chunks(HISTORY_ARC_PCD_CHUNK_MAX_STEPS))
    {
        let witnesses = claims
            .iter()
            .map(|claim| accepted_block_claim_witness_from_fields(claim.fields()))
            .collect::<Result<Vec<_>, _>>()
            .expect("claim witnesses");
        let chainworks = vec![[0u8; 32]; headers.len()];
        cache = advance_local_history_recursive_chunk_head_cache(
            &cache,
            &witnesses,
            headers,
            &chainworks,
        )
        .expect("advance recursive chunk cache");
    }
    cache
}

fn challenge_beta(fixture: &HistoryFixture) -> Block128 {
    let mut channel = Poseidon2bChannel::new();
    absorb_anchor_to_channel(&mut channel, &fixture.start_anchor);
    absorb_anchor_to_channel(&mut channel, &fixture.end_anchor);
    for claim in &fixture.claims {
        let [lo, hi] = accepted_state_transition_chain_claim(claim);
        channel.absorb(lo);
        channel.absorb(hi);
    }
    channel.squeeze()
}

fn absorb_anchor_to_channel(channel: &mut Poseidon2bChannel, anchor: &HeaderChainAnchor) {
    channel.absorb(Block128::from(anchor.height as u128));
    absorb_hash_to_channel(channel, &anchor.block_id);
    absorb_hash_to_channel(channel, &anchor.state_root);
    absorb_hash_to_channel(channel, &anchor.tx_root);
    absorb_hash_to_channel(channel, &anchor.cumulative_chainwork);
    absorb_hash_to_channel(channel, &anchor.projection_root);
}

fn absorb_hash_to_channel(channel: &mut Poseidon2bChannel, hash: &Digest) {
    let [lo, hi] = digest_to_fields(hash);
    channel.absorb(lo);
    channel.absorb(hi);
}

fn digest_to_fields(hash: &Digest) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap())),
    ]
}

fn fixed_hash_input(fields: &[Block128], digest: &Digest) -> FixedFieldHashInputs {
    FixedFieldHashInputs {
        fields: fields.to_vec(),
        expected_digest: digest_to_fields(digest),
    }
}

fn absorb_anchor<S: FieldSink>(sink: &mut S, anchor: &HeaderChainAnchor) {
    sink.absorb(Block128::from(anchor.height as u128));
    sink.absorb_hash(&anchor.block_id);
    sink.absorb_hash(&anchor.state_root);
    sink.absorb_hash(&anchor.tx_root);
    sink.absorb_hash(&anchor.cumulative_chainwork);
    sink.absorb_hash(&anchor.projection_root);
}

fn absorb_fixture<S: FieldSink>(sink: &mut S, fixture: &HistoryFixture) {
    sink.absorb_usize(fixture.claims.len());
    absorb_anchor(sink, &fixture.start_anchor);
    absorb_anchor(sink, &fixture.end_anchor);
    for digest in &fixture.header_projection_digests {
        sink.absorb_hash(digest);
    }
    for claim in &fixture.claims {
        let chain_claim = accepted_state_transition_chain_claim(claim);
        sink.absorb(chain_claim[0]);
        sink.absorb(chain_claim[1]);
        for field in claim.fields() {
            sink.absorb(field);
        }
    }
}

fn accumulate_fixture(fixture: &HistoryFixture) -> AccumResult {
    let beta = challenge_beta(fixture);
    let mut sink = ClmulRlc::new(beta);
    absorb_fixture(&mut sink, fixture);
    AccumResult {
        digest: sink.digest(),
        beta,
        absorbed_fields: sink.absorbed_fields,
    }
}

fn median(mut xs: Vec<Duration>) -> Duration {
    xs.sort();
    xs[xs.len() / 2]
}

fn bench_accum(fixture: &HistoryFixture, samples: usize) -> (Duration, AccumResult) {
    let mut times = Vec::with_capacity(samples);
    let mut last = accumulate_fixture(fixture);
    for _ in 0..samples {
        let (elapsed, result) = time_once(|| accumulate_fixture(fixture));
        std::hint::black_box(result.digest);
        std::hint::black_box(result.beta);
        times.push(elapsed);
        last = result;
    }
    (median(times), last)
}

fn main() {
    let ns = env_usize_list("NOID_HISTORY_ACCUM_NS", DEFAULT_NS);
    let samples = env_usize("NOID_HISTORY_ACCUM_SAMPLES", DEFAULT_SAMPLES);
    let log_slots = env_usize("NOID_HISTORY_ACCUM_LOG_SLOTS", DEFAULT_LOG_SLOTS);

    println!("history_accumulator_lite");
    println!("  backend: Block128 + Poseidon2b transcript + CLMUL RLC");
    println!("  rows: header projections + AcceptedStateTransitionClaim + chain claims");
    println!("  history_claim_fields={HISTORY_CLAIM_FIELDS}");
    println!(
        "  accum_state_hash_fields={HISTORY_ACCUMULATION_STATE_HASH_FIELDS} pcd_step_fields={HISTORY_PCD_STEP_STATEMENT_FIELDS} pcd_step_hash_fields={HISTORY_PCD_STEP_HASH_FIELDS} arc_pcd_accum_fields={HISTORY_ARC_PCD_ACCUMULATOR_FIELDS} arc_pcd_accum_hash_fields={HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS} arc_recursive_step_fields={HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS} arc_recursive_step_hash_fields={HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_FIELDS} arc_recursive_chunk_step_fields={HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS} arc_recursive_chunk_step_hash_fields={HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_FIELDS} tagged_pair_hash_fields={HISTORY_TAGGED_PAIR_HASH_FIELDS}"
    );
    println!("  log_slots={log_slots} samples={samples}");

    let recursive_source_fixture = build_fixture(2, log_slots);
    let mut public_proof_bytes: Option<usize> = None;
    let mut cache_proof_bytes: Option<usize> = None;
    let mut decider_statement_bytes: Option<usize> = None;
    let mut decider_proof_bytes: Option<usize> = None;
    let mut decider_hash_proof_bytes: Option<usize> = None;
    let mut local_cache_bytes: Option<usize> = None;
    let mut arc_pcd_accumulator_bytes: Option<usize> = None;
    let mut arc_one_step_proof_bytes: Option<usize> = None;
    let mut pcd_step_statement_bytes: Option<usize> = None;
    let mut arc_pcd_step_proof_bytes: Option<usize> = None;
    let mut arc_pcd_chunk_step_proof_bytes: Option<usize> = None;
    let mut arc_pcd_chunk_step_transcript_proof_bytes: Option<usize> = None;
    let mut arc_pcd_recursive_step_statement_bytes: Option<usize> = None;
    let mut arc_pcd_recursive_step_proof_bytes: Option<usize> = None;
    let mut arc_pcd_recursive_chunk_step_transcript_proof_bytes: Option<usize> = None;
    let mut arc_pcd_recursive_chain_head_bytes: Option<usize> = None;
    let mut arc_pcd_recursive_chunk_chain_head_bytes: Option<usize> = None;
    let mut recursive_head_cache_bytes: Option<usize> = None;
    let mut recursive_chunk_head_cache_bytes: Option<usize> = None;
    let mut recursive_head_history_proof_bytes: Option<usize> = None;
    let mut recursive_chunk_head_history_proof_bytes: Option<usize> = None;
    let mut pcd_step_hash_proof_bytes: Option<usize> = None;
    let mut arc_accumulator_hash_proof_bytes: Option<usize> = None;
    let mut tagged_pair_hash_proof_bytes: Option<usize> = None;
    let pcd_step_hash_params =
        FixedFieldHashParams::with_default_relation_tag(TAG_HISTPRF, HISTORY_PCD_STEP_HASH_FIELDS)
            .expect("PCD step hash params");
    let arc_accumulator_hash_params = FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS,
    )
    .expect("ARC accumulator hash params");
    let tagged_pair_hash_params = FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        HISTORY_TAGGED_PAIR_HASH_FIELDS,
    )
    .expect("tagged pair hash params");

    for n in ns {
        let mem_before = current_mem_snapshot();
        let (build_time, fixture) = time_once(|| build_fixture(n, log_slots));
        let mem_after_build = current_mem_snapshot();
        let (proof_time, proof) = time_once(|| prove_fixture_history(&fixture));
        let (cache_fold_time, cache) = time_once(|| build_fixture_cache(&fixture));
        let (cache_proof_time, cache_proof) =
            time_once(|| prove_history_from_local_cache(&cache).expect("cache proof"));
        assert_eq!(
            cache_proof, proof,
            "cache proof must match witness-built native proof"
        );
        let decider_statement = noid_recursive::history_decider_statement(&proof);
        let accum_state = HistoryAccumulationState {
            version: HISTORY_PROOF_VERSION,
            height: proof.end_accumulator.height,
            block_id: fixture.end_anchor.block_id,
            projection_root: fixture.end_anchor.projection_root,
            accumulator: proof.end_accumulator.clone(),
            folded_witness_root: proof.folded_witness_root,
            step_count: fixture.claims.len() as u64,
        };
        let (verify_time, _) = time_once(|| {
            verify_history_proof_native(&proof, &fixture.start_anchor, &fixture.end_anchor)
                .expect("verify history proof")
        });
        let step_witness = history_witness(&fixture);
        let recursive_fixture = if fixture.headers.len() >= 2 {
            &fixture
        } else {
            &recursive_source_fixture
        };
        let (
            recursive_statement,
            recursive_previous_acc,
            recursive_next_acc,
            recursive_next_digest,
        ) = recursive_step_inputs(recursive_fixture);
        let (arc_recursive_step_prove_time, (verified_next_digest, arc_recursive_step_proof)) =
            time_once(|| {
                prove_history_arc_pcd_recursive_step_native(
                    &recursive_statement,
                    &recursive_previous_acc,
                    &recursive_next_acc,
                )
                .expect("prove recursive ARC/PCD step")
            });
        assert_eq!(verified_next_digest, recursive_next_digest);
        let (arc_recursive_step_verify_time, verified_recursive_digest) = time_once(|| {
            verify_history_arc_pcd_recursive_step_proof_native(
                &recursive_statement,
                &recursive_previous_acc,
                &recursive_next_acc,
                &arc_recursive_step_proof,
            )
            .expect("verify recursive ARC/PCD step")
        });
        assert_eq!(verified_recursive_digest, recursive_next_digest);
        let first_chainwork = add_work(
            &fixture.start_anchor.cumulative_chainwork,
            &block_work(&fixture.headers[0].difficulty_target),
        );
        let first_end_anchor =
            extend_header_chain_anchor(&fixture.start_anchor, &fixture.headers[0], first_chainwork)
                .expect("first block anchor");
        let one_step_witness = HistoryProofWitness {
            items: vec![step_witness.items[0].clone()],
        };
        let (arc_one_step_prove_time, arc_one_step_proof) = time_once(|| {
            prove_history_arc_pcd_one_step(
                fixture.start_anchor.clone(),
                first_end_anchor.clone(),
                fixture.start_accumulator.clone(),
                &one_step_witness,
            )
            .expect("prove one-step ARC/PCD proof")
        });
        let (arc_one_step_verify_time, _) = time_once(|| {
            verify_history_proof_untrusted(
                &arc_one_step_proof,
                &fixture.start_anchor,
                &first_end_anchor,
            )
            .expect("verify one-step ARC/PCD proof")
        });
        let chain_head_start_state = HistoryAccumulationState::from_anchor(
            &fixture.start_anchor,
            fixture.start_accumulator.clone(),
        )
        .expect("chain-head start state");
        let (arc_chain_head_worker_time, recursive_head_cache) =
            time_once(|| build_fixture_recursive_head_cache(&fixture));
        assert_eq!(recursive_head_cache.base, cache);
        assert_eq!(
            recursive_head_cache.base.accumulation_state.accumulator,
            proof.end_accumulator
        );
        assert_eq!(
            recursive_head_cache.base.arc_pcd_accumulator,
            proof.decider.pcd_accumulator
        );
        let (arc_chain_head_serve_time, arc_chain_head) = time_once(|| {
            recursive_head_cache
                .recursive_head
                .as_ref()
                .expect("recursive chain head")
                .clone()
        });
        let (arc_chain_head_verify_time, chain_head_digest) = time_once(|| {
            verify_history_arc_pcd_recursive_chain_head_shape_native(
                &chain_head_start_state,
                &recursive_head_cache.base.arc_pcd_accumulator,
                &arc_chain_head,
            )
            .expect("verify recursive ARC/PCD chain-head shape")
        });
        assert_eq!(chain_head_digest, arc_chain_head.final_proof_digest);
        let (arc_chain_head_proof_time, arc_chain_head_history_proof) = time_once(|| {
            prove_history_arc_pcd_from_recursive_head_cache(&recursive_head_cache)
                .expect("recursive-head HistoryProof")
        });
        let (arc_chain_head_proof_verify_time, _) = time_once(|| {
            verify_history_proof_native(
                &arc_chain_head_history_proof,
                &fixture.start_anchor,
                &fixture.end_anchor,
            )
            .expect("verify staged recursive-head HistoryProof")
        });
        let (arc_chain_head_untrusted_time, untrusted_result) = time_once(|| {
            verify_history_proof_untrusted(
                &arc_chain_head_history_proof,
                &fixture.start_anchor,
                &fixture.end_anchor,
            )
        });
        assert_eq!(
            untrusted_result,
            Err(noid_recursive::HistoryProofError::BackendVerifierMissing)
        );
        let (arc_chunk_chain_head_worker_time, recursive_chunk_head_cache) =
            time_once(|| build_fixture_recursive_chunk_head_cache(&fixture));
        assert_eq!(recursive_chunk_head_cache.base, cache);
        assert_eq!(
            recursive_chunk_head_cache
                .base
                .accumulation_state
                .accumulator,
            proof.end_accumulator
        );
        assert_eq!(
            recursive_chunk_head_cache.base.arc_pcd_accumulator,
            proof.decider.pcd_accumulator
        );
        let (arc_chunk_chain_head_serve_time, arc_chunk_chain_head) = time_once(|| {
            recursive_chunk_head_cache
                .recursive_head
                .as_ref()
                .expect("recursive chunk chain head")
                .clone()
        });
        let (arc_chunk_chain_head_verify_time, chunk_chain_head_digest) = time_once(|| {
            verify_history_arc_pcd_recursive_chunk_chain_head_shape_native(
                &chain_head_start_state,
                &recursive_chunk_head_cache.base.arc_pcd_accumulator,
                &arc_chunk_chain_head,
            )
            .expect("verify recursive ARC/PCD chunk chain-head shape")
        });
        assert_eq!(
            chunk_chain_head_digest,
            arc_chunk_chain_head.final_proof_digest
        );
        let (
            arc_recursive_chunk_step_transcript_trace_time,
            arc_recursive_chunk_step_transcript_traces,
        ) = time_once(|| {
            history_arc_pcd_recursive_chunk_step_verifier_traces(
                &arc_chunk_chain_head.final_chunk_statement,
                &arc_chunk_chain_head.previous_accumulator,
                &recursive_chunk_head_cache.base.arc_pcd_accumulator,
                &arc_chunk_chain_head.final_chunk_proof,
            )
            .expect("recursive ARC/PCD chunk-step verifier traces")
        });
        let (
            arc_recursive_chunk_step_transcript_prove_time,
            (
                arc_recursive_chunk_step_transcript_proof,
                arc_recursive_chunk_step_transcript_reductions,
            ),
        ) = time_once(|| {
            prove_history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_native(
                &arc_chunk_chain_head.final_chunk_statement,
                &arc_chunk_chain_head.previous_accumulator,
                &recursive_chunk_head_cache.base.arc_pcd_accumulator,
                &arc_chunk_chain_head.final_chunk_proof,
            )
            .expect("prove recursive ARC/PCD chunk-step verifier transcript")
        });
        let (
            arc_recursive_chunk_step_transcript_verify_time,
            arc_recursive_chunk_step_transcript_verified,
        ) = time_once(|| {
            let mut channel = Poseidon2bChannel::new();
            verify_fiat_shamir_transcript_batch_killshot(
                &arc_recursive_chunk_step_transcript_traces,
                &arc_recursive_chunk_step_transcript_proof,
                &mut channel,
            )
            .expect("verify recursive ARC/PCD chunk-step verifier transcript")
        });
        assert_eq!(
            arc_recursive_chunk_step_transcript_verified,
            arc_recursive_chunk_step_transcript_reductions
        );
        let (arc_recursive_chunk_step_transcript_discharge_time, _) = time_once(|| {
            assert!(discharge_fiat_shamir_transcript_batch_reductions_native(
                &arc_recursive_chunk_step_transcript_traces,
                &arc_recursive_chunk_step_transcript_verified,
            ));
        });
        let (arc_chunk_chain_head_proof_time, arc_chunk_chain_head_history_proof) =
            time_once(|| {
                prove_history_arc_pcd_from_recursive_chunk_head_cache(&recursive_chunk_head_cache)
                    .expect("recursive chunk-head HistoryProof")
            });
        let (arc_chunk_chain_head_proof_verify_time, _) = time_once(|| {
            verify_history_proof_native(
                &arc_chunk_chain_head_history_proof,
                &fixture.start_anchor,
                &fixture.end_anchor,
            )
            .expect("verify staged recursive chunk-head HistoryProof")
        });
        let (arc_chunk_chain_head_untrusted_time, chunk_untrusted_result) = time_once(|| {
            verify_history_proof_untrusted(
                &arc_chunk_chain_head_history_proof,
                &fixture.start_anchor,
                &fixture.end_anchor,
            )
        });
        assert_eq!(
            chunk_untrusted_result,
            Err(noid_recursive::HistoryProofError::BackendVerifierMissing)
        );
        let (step_prove_time, (step_proof, step_reductions)) = time_once(|| {
            prove_history_step_native(
                &fixture.start_accumulator,
                fixture.start_anchor.block_id,
                fixture.start_anchor.projection_root,
                &step_witness.items[0],
            )
            .expect("prove history step")
        });
        let (step_verify_time, verified_step_reductions) =
            time_once(|| verify_history_step_native(&step_proof).expect("verify history step"));
        assert_eq!(verified_step_reductions, step_reductions);
        let (step_discharge_time, _) = time_once(|| {
            discharge_history_step_native(&step_proof, &verified_step_reductions)
                .expect("discharge history step")
        });
        let start_state = HistoryAccumulationState::from_anchor(
            &fixture.start_anchor,
            fixture.start_accumulator.clone(),
        )
        .expect("start accumulation state");
        let (pcd_step_time, pcd_step_statement) = time_once(|| {
            build_history_pcd_step_statement_native(
                &start_state,
                &step_proof,
                &verified_step_reductions,
            )
            .expect("PCD step statement")
        });
        let arc_start = HistoryArcPcdAccumulator::from_start_state(&start_state)
            .expect("start ARC/PCD accumulator");
        let (arc_step_prove_time, (arc_next, arc_step_proof)) = time_once(|| {
            prove_history_arc_pcd_step_native(&arc_start, &pcd_step_statement)
                .expect("prove ARC/PCD step")
        });
        let (arc_step_verify_time, _) = time_once(|| {
            verify_history_arc_pcd_step_proof_native(
                &arc_start,
                &pcd_step_statement,
                &arc_next,
                &arc_step_proof,
            )
            .expect("verify ARC/PCD step")
        });
        let chunk_live = step_witness
            .items
            .len()
            .min(HISTORY_ARC_PCD_CHUNK_MAX_STEPS);
        let chunk_items = &step_witness.items[..chunk_live];
        let (arc_chunk_step_prove_time, (chunk_next_state, chunk_next_acc, arc_chunk_step_proof)) =
            time_once(|| {
                prove_history_arc_pcd_chunk_step_native(&arc_start, &start_state, chunk_items)
                    .expect("prove ARC/PCD chunk step")
            });
        let (arc_chunk_step_verify_time, (verified_chunk_state, verified_chunk_acc)) =
            time_once(|| {
                verify_history_arc_pcd_chunk_step_proof_native(
                    &arc_start,
                    &start_state,
                    chunk_items,
                    &arc_chunk_step_proof,
                )
                .expect("verify ARC/PCD chunk step")
            });
        assert_eq!(verified_chunk_state, chunk_next_state);
        assert_eq!(verified_chunk_acc, chunk_next_acc);
        let (arc_chunk_step_transcript_trace_time, arc_chunk_step_transcript_traces) =
            time_once(|| {
                history_arc_pcd_chunk_step_verifier_traces(
                    &arc_start,
                    &start_state,
                    chunk_items,
                    &arc_chunk_step_proof,
                )
                .expect("ARC/PCD chunk verifier traces")
            });
        let (
            arc_chunk_step_transcript_prove_time,
            (arc_chunk_step_transcript_proof, arc_chunk_step_transcript_reductions),
        ) = time_once(|| {
            prove_history_arc_pcd_chunk_step_verifier_transcript_batch_native(
                &arc_start,
                &start_state,
                chunk_items,
                &arc_chunk_step_proof,
            )
            .expect("prove ARC/PCD chunk verifier transcript")
        });
        let (arc_chunk_step_transcript_verify_time, arc_chunk_step_transcript_verified) =
            time_once(|| {
                let mut channel = Poseidon2bChannel::new();
                verify_fiat_shamir_transcript_batch_killshot(
                    &arc_chunk_step_transcript_traces,
                    &arc_chunk_step_transcript_proof,
                    &mut channel,
                )
                .expect("verify ARC/PCD chunk verifier transcript")
            });
        assert_eq!(
            arc_chunk_step_transcript_verified,
            arc_chunk_step_transcript_reductions
        );
        let (arc_chunk_step_transcript_discharge_time, _) = time_once(|| {
            assert!(discharge_fiat_shamir_transcript_batch_reductions_native(
                &arc_chunk_step_transcript_traces,
                &arc_chunk_step_transcript_verified,
            ));
        });
        let pcd_step_digest = history_pcd_step_statement_digest(&pcd_step_statement);
        let pcd_step_hash_fields = history_pcd_step_statement_hash_fields(&pcd_step_statement);
        let pcd_step_hash_input = fixed_hash_input(&pcd_step_hash_fields, &pcd_step_digest);
        let (pcd_hash_prove_time, (pcd_hash_proof, pcd_hash_reductions)) = time_once(|| {
            let mut channel = Poseidon2bChannel::new();
            prove_fixed_field_hash_killshot(
                pcd_step_hash_params,
                std::slice::from_ref(&pcd_step_hash_input),
                &mut channel,
            )
        });
        let (pcd_hash_verify_time, verified_pcd_hash_reductions) = time_once(|| {
            let mut channel = Poseidon2bChannel::new();
            verify_fixed_field_hash_killshot(
                pcd_step_hash_params,
                &pcd_hash_proof,
                std::slice::from_ref(&pcd_step_hash_input),
                &mut channel,
            )
            .expect("verify PCD step hash")
        });
        assert_eq!(verified_pcd_hash_reductions, pcd_hash_reductions);
        let (pcd_hash_discharge_time, _) = time_once(|| {
            assert!(discharge_fixed_field_hash_reductions_native(
                pcd_step_hash_params,
                std::slice::from_ref(&pcd_step_hash_input),
                &verified_pcd_hash_reductions,
            ));
        });
        let arc_accumulator_digest =
            history_arc_pcd_accumulator_digest(&proof.decider.pcd_accumulator);
        let arc_accumulator_hash_fields =
            history_arc_pcd_accumulator_hash_fields(&proof.decider.pcd_accumulator);
        let arc_accumulator_hash_input =
            fixed_hash_input(&arc_accumulator_hash_fields, &arc_accumulator_digest);
        let (arc_hash_prove_time, (arc_hash_proof, arc_hash_reductions)) = time_once(|| {
            let mut channel = Poseidon2bChannel::new();
            prove_fixed_field_hash_killshot(
                arc_accumulator_hash_params,
                std::slice::from_ref(&arc_accumulator_hash_input),
                &mut channel,
            )
        });
        let (arc_hash_verify_time, verified_arc_hash_reductions) = time_once(|| {
            let mut channel = Poseidon2bChannel::new();
            verify_fixed_field_hash_killshot(
                arc_accumulator_hash_params,
                &arc_hash_proof,
                std::slice::from_ref(&arc_accumulator_hash_input),
                &mut channel,
            )
            .expect("verify ARC accumulator hash")
        });
        assert_eq!(verified_arc_hash_reductions, arc_hash_reductions);
        let (arc_hash_discharge_time, _) = time_once(|| {
            assert!(discharge_fixed_field_hash_reductions_native(
                arc_accumulator_hash_params,
                std::slice::from_ref(&arc_accumulator_hash_input),
                &verified_arc_hash_reductions,
            ));
        });
        let tagged_pair_hash_fields = history_tagged_pair_hash_fields(
            0x4849_5354_5043_5331u128,
            &proof.decider.pcd_accumulator.pcd_root,
            &proof.decider.pcd_accumulator.transcript_digest,
        );
        let tagged_pair_hash_input =
            fixed_hash_input(&tagged_pair_hash_fields, &proof.decider.pcs_commitment);
        let (pair_hash_prove_time, (pair_hash_proof, pair_hash_reductions)) = time_once(|| {
            let mut channel = Poseidon2bChannel::new();
            prove_fixed_field_hash_killshot(
                tagged_pair_hash_params,
                std::slice::from_ref(&tagged_pair_hash_input),
                &mut channel,
            )
        });
        let (pair_hash_verify_time, verified_pair_hash_reductions) = time_once(|| {
            let mut channel = Poseidon2bChannel::new();
            verify_fixed_field_hash_killshot(
                tagged_pair_hash_params,
                &pair_hash_proof,
                std::slice::from_ref(&tagged_pair_hash_input),
                &mut channel,
            )
            .expect("verify tagged pair hash")
        });
        assert_eq!(verified_pair_hash_reductions, pair_hash_reductions);
        let (pair_hash_discharge_time, _) = time_once(|| {
            assert!(discharge_fixed_field_hash_reductions_native(
                tagged_pair_hash_params,
                std::slice::from_ref(&tagged_pair_hash_input),
                &verified_pair_hash_reductions,
            ));
        });
        let (accum_time, accum) = bench_accum(&fixture, samples);
        let fields_per_block = accum.absorbed_fields as f64 / n.max(1) as f64;
        let proof_bytes = proof.byte_len();
        if let Some(expected) = public_proof_bytes {
            assert_eq!(
                proof_bytes, expected,
                "public HistoryProof byte_len must be constant across benchmark sizes"
            );
        } else {
            public_proof_bytes = Some(proof_bytes);
        }
        let cache_proof_len = cache_proof.byte_len();
        if let Some(expected) = cache_proof_bytes {
            assert_eq!(
                cache_proof_len, expected,
                "cache-built HistoryProof byte_len must be constant across benchmark sizes"
            );
        } else {
            cache_proof_bytes = Some(cache_proof_len);
        }
        let cache_bytes = cache.byte_len();
        if let Some(expected) = local_cache_bytes {
            assert_eq!(
                cache_bytes, expected,
                "LocalHistoryCache byte_len must be constant across benchmark sizes"
            );
        } else {
            local_cache_bytes = Some(cache_bytes);
        }
        let statement_bytes = decider_statement.byte_len();
        if let Some(expected) = decider_statement_bytes {
            assert_eq!(
                statement_bytes, expected,
                "HistoryDeciderStatement byte_len must be constant across benchmark sizes"
            );
        } else {
            decider_statement_bytes = Some(statement_bytes);
        }
        let decider_bytes = proof.decider.byte_len();
        if let Some(expected) = decider_proof_bytes {
            assert_eq!(
                decider_bytes, expected,
                "HistoryDeciderProof byte_len must be constant across benchmark sizes"
            );
        } else {
            decider_proof_bytes = Some(decider_bytes);
        }
        let decider_hash_bytes = proof
            .decider
            .hash_proofs
            .as_ref()
            .expect("decider hash proofs")
            .byte_len();
        if let Some(expected) = decider_hash_proof_bytes {
            assert_eq!(
                decider_hash_bytes, expected,
                "HistoryDeciderHashProofs byte_len must be constant across benchmark sizes"
            );
        } else {
            decider_hash_proof_bytes = Some(decider_hash_bytes);
        }
        let arc_pcd_bytes = proof.decider.pcd_accumulator.byte_len();
        if let Some(expected) = arc_pcd_accumulator_bytes {
            assert_eq!(
                arc_pcd_bytes, expected,
                "HistoryArcPcdAccumulator byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_pcd_accumulator_bytes = Some(arc_pcd_bytes);
        }
        let arc_one_step_bytes = arc_one_step_proof.byte_len();
        if let Some(expected) = arc_one_step_proof_bytes {
            assert_eq!(
                arc_one_step_bytes, expected,
                "one-step ArcPcdV1 HistoryProof byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_one_step_proof_bytes = Some(arc_one_step_bytes);
        }
        let pcd_step_bytes = pcd_step_statement.byte_len();
        if let Some(expected) = pcd_step_statement_bytes {
            assert_eq!(
                pcd_step_bytes, expected,
                "HistoryPcdStepStatement byte_len must be constant across benchmark sizes"
            );
        } else {
            pcd_step_statement_bytes = Some(pcd_step_bytes);
        }
        let arc_step_bytes = arc_step_proof.byte_len();
        if let Some(expected) = arc_pcd_step_proof_bytes {
            assert_eq!(
                arc_step_bytes, expected,
                "HistoryArcPcdStepProof byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_pcd_step_proof_bytes = Some(arc_step_bytes);
        }
        let arc_chunk_step_bytes = arc_chunk_step_proof.byte_len();
        if let Some(expected) = arc_pcd_chunk_step_proof_bytes {
            assert_eq!(
                arc_chunk_step_bytes, expected,
                "HistoryArcPcdChunkStepProof byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_pcd_chunk_step_proof_bytes = Some(arc_chunk_step_bytes);
        }
        let arc_chunk_step_transcript_bytes = arc_chunk_step_transcript_proof.byte_len();
        if let Some(expected) = arc_pcd_chunk_step_transcript_proof_bytes {
            assert_eq!(
                arc_chunk_step_transcript_bytes, expected,
                "chunk verifier transcript proof byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_pcd_chunk_step_transcript_proof_bytes = Some(arc_chunk_step_transcript_bytes);
        }
        let arc_recursive_statement_bytes = recursive_statement.byte_len();
        if let Some(expected) = arc_pcd_recursive_step_statement_bytes {
            assert_eq!(
                arc_recursive_statement_bytes, expected,
                "HistoryArcPcdRecursiveStepStatement byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_pcd_recursive_step_statement_bytes = Some(arc_recursive_statement_bytes);
        }
        let arc_recursive_step_bytes = arc_recursive_step_proof.byte_len();
        if let Some(expected) = arc_pcd_recursive_step_proof_bytes {
            assert_eq!(
                arc_recursive_step_bytes, expected,
                "HistoryArcPcdRecursiveStepProof byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_pcd_recursive_step_proof_bytes = Some(arc_recursive_step_bytes);
        }
        let arc_recursive_chunk_step_transcript_bytes =
            arc_recursive_chunk_step_transcript_proof.byte_len();
        if let Some(expected) = arc_pcd_recursive_chunk_step_transcript_proof_bytes {
            assert_eq!(
                arc_recursive_chunk_step_transcript_bytes, expected,
                "recursive chunk-step verifier transcript proof byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_pcd_recursive_chunk_step_transcript_proof_bytes =
                Some(arc_recursive_chunk_step_transcript_bytes);
        }
        let arc_chain_head_bytes = arc_chain_head.byte_len();
        if let Some(expected) = arc_pcd_recursive_chain_head_bytes {
            assert_eq!(
                arc_chain_head_bytes, expected,
                "HistoryArcPcdRecursiveChainHead byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_pcd_recursive_chain_head_bytes = Some(arc_chain_head_bytes);
        }
        let arc_chunk_chain_head_bytes = arc_chunk_chain_head.byte_len();
        if let Some(expected) = arc_pcd_recursive_chunk_chain_head_bytes {
            assert_eq!(
                arc_chunk_chain_head_bytes, expected,
                "HistoryArcPcdRecursiveChunkChainHead byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_pcd_recursive_chunk_chain_head_bytes = Some(arc_chunk_chain_head_bytes);
        }
        let recursive_cache_bytes = recursive_head_cache.byte_len();
        if let Some(expected) = recursive_head_cache_bytes {
            assert_eq!(
                recursive_cache_bytes, expected,
                "LocalHistoryRecursiveHeadCache byte_len must be constant across benchmark sizes"
            );
        } else {
            recursive_head_cache_bytes = Some(recursive_cache_bytes);
        }
        let recursive_chunk_cache_bytes = recursive_chunk_head_cache.byte_len();
        if let Some(expected) = recursive_chunk_head_cache_bytes {
            assert_eq!(
                recursive_chunk_cache_bytes, expected,
                "LocalHistoryRecursiveChunkHeadCache byte_len must be constant across benchmark sizes"
            );
        } else {
            recursive_chunk_head_cache_bytes = Some(recursive_chunk_cache_bytes);
        }
        let recursive_history_proof_bytes = arc_chain_head_history_proof.byte_len();
        if let Some(expected) = recursive_head_history_proof_bytes {
            assert_eq!(
                recursive_history_proof_bytes, expected,
                "recursive-head ArcPcdV1 HistoryProof byte_len must be constant across benchmark sizes"
            );
        } else {
            recursive_head_history_proof_bytes = Some(recursive_history_proof_bytes);
        }
        let recursive_chunk_history_proof_bytes = arc_chunk_chain_head_history_proof.byte_len();
        if let Some(expected) = recursive_chunk_head_history_proof_bytes {
            assert_eq!(
                recursive_chunk_history_proof_bytes, expected,
                "recursive chunk-head ArcPcdV1 HistoryProof byte_len must be constant across benchmark sizes"
            );
        } else {
            recursive_chunk_head_history_proof_bytes = Some(recursive_chunk_history_proof_bytes);
        }
        let pcd_hash_bytes = pcd_hash_proof.byte_len();
        if let Some(expected) = pcd_step_hash_proof_bytes {
            assert_eq!(
                pcd_hash_bytes, expected,
                "PCD step hash proof byte_len must be constant across benchmark sizes"
            );
        } else {
            pcd_step_hash_proof_bytes = Some(pcd_hash_bytes);
        }
        let arc_hash_bytes = arc_hash_proof.byte_len();
        if let Some(expected) = arc_accumulator_hash_proof_bytes {
            assert_eq!(
                arc_hash_bytes, expected,
                "ARC accumulator hash proof byte_len must be constant across benchmark sizes"
            );
        } else {
            arc_accumulator_hash_proof_bytes = Some(arc_hash_bytes);
        }
        let pair_hash_bytes = pair_hash_proof.byte_len();
        if let Some(expected) = tagged_pair_hash_proof_bytes {
            assert_eq!(
                pair_hash_bytes, expected,
                "tagged pair hash proof byte_len must be constant across benchmark sizes"
            );
        } else {
            tagged_pair_hash_proof_bytes = Some(pair_hash_bytes);
        }

        println!("  n={n}");
        println!(
            "    build_fixture={} claims={} mem_hwm_before={} mem_hwm_after={}",
            fmt_ms(build_time),
            fmt_bytes(fixture.claim_bytes),
            fmt_mem(mem_before),
            fmt_mem(mem_after_build)
        );
        println!(
            "    public_proof={} cache_proof={} local_cache={} decider_statement={} decider_proof={} decider_hash_proofs={} arc_pcd_accum={} accum_state={} fold_envelope={} cache_fold={} cache_proof_time={} verify_envelope={}",
            fmt_bytes(proof_bytes),
            fmt_bytes(cache_proof_len),
            fmt_bytes(cache_bytes),
            fmt_bytes(statement_bytes),
            fmt_bytes(decider_bytes),
            fmt_bytes(decider_hash_bytes),
            fmt_bytes(arc_pcd_bytes),
            fmt_bytes(accum_state.byte_len()),
            fmt_ms(proof_time),
            fmt_ms(cache_fold_time),
            fmt_ms(cache_proof_time),
            fmt_ms(verify_time)
        );
        println!(
            "    step_proof={} prove={} verify={} discharge_native={} pcd_step_statement={} pcd_step_build={}",
            fmt_bytes(step_proof.byte_len()),
            fmt_ms(step_prove_time),
            fmt_ms(step_verify_time),
            fmt_ms(step_discharge_time),
            fmt_bytes(pcd_step_bytes),
            fmt_ms(pcd_step_time)
        );
        println!(
            "    arc_pcd_one_step_proof={} prove={} verify_untrusted={}",
            fmt_bytes(arc_one_step_bytes),
            fmt_ms(arc_one_step_prove_time),
            fmt_ms(arc_one_step_verify_time)
        );
        println!(
            "    arc_pcd_step_proof={} prove={} verify={}",
            fmt_bytes(arc_step_bytes),
            fmt_ms(arc_step_prove_time),
            fmt_ms(arc_step_verify_time)
        );
        println!(
            "    arc_pcd_chunk18_step_proof={} live={} prove={} verify={}",
            fmt_bytes(arc_chunk_step_bytes),
            chunk_live,
            fmt_ms(arc_chunk_step_prove_time),
            fmt_ms(arc_chunk_step_verify_time)
        );
        println!(
            "    arc_pcd_chunk18_verifier_transcript_proof={} traces={} ops={} perms={} trace_build={} prove={} verify={} discharge_native={}",
            fmt_bytes(arc_chunk_step_transcript_bytes),
            arc_chunk_step_transcript_proof.n_traces,
            arc_chunk_step_transcript_proof.n_ops,
            arc_chunk_step_transcript_proof.n_permutations,
            fmt_ms(arc_chunk_step_transcript_trace_time),
            fmt_ms(arc_chunk_step_transcript_prove_time),
            fmt_ms(arc_chunk_step_transcript_verify_time),
            fmt_ms(arc_chunk_step_transcript_discharge_time)
        );
        println!(
            "    arc_pcd_recursive_step_statement={} arc_pcd_recursive_step_proof={} prove={} verify={}",
            fmt_bytes(arc_recursive_statement_bytes),
            fmt_bytes(arc_recursive_step_bytes),
            fmt_ms(arc_recursive_step_prove_time),
            fmt_ms(arc_recursive_step_verify_time)
        );
        println!(
            "    arc_pcd_recursive_chain_head={} recursive_head_cache={} worker_fold={} serve_head={} verify_shape={}",
            fmt_bytes(arc_chain_head_bytes),
            fmt_bytes(recursive_cache_bytes),
            fmt_ms(arc_chain_head_worker_time),
            fmt_ms(arc_chain_head_serve_time),
            fmt_ms(arc_chain_head_verify_time)
        );
        println!(
            "    arc_pcd_recursive_chunk_chain_head={} recursive_chunk_head_cache={} chunk_count={} worker_fold={} serve_head={} verify_shape={}",
            fmt_bytes(arc_chunk_chain_head_bytes),
            fmt_bytes(recursive_chunk_cache_bytes),
            arc_chunk_chain_head.chunk_count,
            fmt_ms(arc_chunk_chain_head_worker_time),
            fmt_ms(arc_chunk_chain_head_serve_time),
            fmt_ms(arc_chunk_chain_head_verify_time)
        );
        println!(
            "    arc_pcd_recursive_chunk_step_verifier_transcript_proof={} traces={} ops={} perms={} trace_build={} prove={} verify={} discharge_native={}",
            fmt_bytes(arc_recursive_chunk_step_transcript_bytes),
            arc_recursive_chunk_step_transcript_proof.n_traces,
            arc_recursive_chunk_step_transcript_proof.n_ops,
            arc_recursive_chunk_step_transcript_proof.n_permutations,
            fmt_ms(arc_recursive_chunk_step_transcript_trace_time),
            fmt_ms(arc_recursive_chunk_step_transcript_prove_time),
            fmt_ms(arc_recursive_chunk_step_transcript_verify_time),
            fmt_ms(arc_recursive_chunk_step_transcript_discharge_time)
        );
        println!(
            "    arc_pcd_recursive_chunk_history_proof={} build_from_cache={} verify_native={} verify_untrusted_fail_closed={}",
            fmt_bytes(recursive_chunk_history_proof_bytes),
            fmt_ms(arc_chunk_chain_head_proof_time),
            fmt_ms(arc_chunk_chain_head_proof_verify_time),
            fmt_ms(arc_chunk_chain_head_untrusted_time)
        );
        println!(
            "    arc_pcd_recursive_history_proof={} build_from_cache={} verify_native={} verify_untrusted_fail_closed={}",
            fmt_bytes(recursive_history_proof_bytes),
            fmt_ms(arc_chain_head_proof_time),
            fmt_ms(arc_chain_head_proof_verify_time),
            fmt_ms(arc_chain_head_untrusted_time)
        );
        println!(
            "    fixed_hash_pcd_step proof={} prove={} verify={} discharge_native={}",
            fmt_bytes(pcd_hash_bytes),
            fmt_ms(pcd_hash_prove_time),
            fmt_ms(pcd_hash_verify_time),
            fmt_ms(pcd_hash_discharge_time)
        );
        println!(
            "    fixed_hash_arc_accum proof={} prove={} verify={} discharge_native={}",
            fmt_bytes(arc_hash_bytes),
            fmt_ms(arc_hash_prove_time),
            fmt_ms(arc_hash_verify_time),
            fmt_ms(arc_hash_discharge_time)
        );
        println!(
            "    fixed_hash_tagged_pair proof={} prove={} verify={} discharge_native={}",
            fmt_bytes(pair_hash_bytes),
            fmt_ms(pair_hash_prove_time),
            fmt_ms(pair_hash_verify_time),
            fmt_ms(pair_hash_discharge_time)
        );
        println!(
            "    core_accum={} absorbed_fields={} fields/block={:.1}",
            fmt_ms(accum_time),
            accum.absorbed_fields,
            fields_per_block
        );
        println!(
            "    digest={:032x} beta={:032x} pcd_step={}",
            accum.digest.to_u128(),
            accum.beta.to_u128(),
            hex32(&pcd_step_digest)
        );
    }
}

fn hex32(digest: &Digest) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").expect("write to string");
    }
    out
}
