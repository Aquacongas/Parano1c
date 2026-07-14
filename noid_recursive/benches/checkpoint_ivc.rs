// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Checkpoint IVC chunk-core benchmark for the production O(1) history path.
//!
//! This measures `noid_recursive::checkpoint_ivc_backend`, not the removed
//! history workbench. The current relation is the fixed 16-slot
//! checkpoint/certificate/claim continuity core with public receipt projection
//! pins. The remaining final layer must prove accepted-claim digest and
//! recursive-head validity, not replay tx-shaped component lists inside history
//! aggregation.

use std::env;
use std::hint::black_box;
use std::time::{Duration, Instant};

use noid_chain::consensus::difficulty::{add_work, block_work};
use noid_chain::consensus::params::{BLOCK_TIME, MAX_TARGET};
use noid_chain::consensus::{genesis_header, GENESIS_TIMESTAMP};
use noid_chain::header_anchor::HeaderChainAnchor;
use noid_core::Block128;
use noid_poseidon2b::primitives::{Address, Digest};
use noid_recursive::{
    accepted_block_certificate_batch_statement, accepted_block_certificate_receipt,
    accepted_block_receipt_projection_handle, accepted_claim_batch_digest,
    advance_history_checkpoint_head_native, genesis_accumulator,
    history_checkpoint_head_from_boundary,
    prove_accepted_block_certificate_receipt_projection_proof,
    prove_history_checkpoint_ivc_chunk_receipt_handle_core,
    verify_history_checkpoint_ivc_chunk_core, AcceptedBlockCertificateBatchStatement,
    AcceptedBlockCertificateReceipt, AcceptedBlockCertificateStatement,
    AcceptedBlockReceiptProjectionHandle, AcceptedClaimBatchOutput, AcceptedClaimBatchWitness,
    HeaderWitness, HistoryCheckpointBatchSummary, HistoryCheckpointStepStatement,
    RecursiveConsensusState, HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS,
    HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC, HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES,
    HISTORY_CHECKPOINT_IVC_PCS_LOG_BATCH_SIZE, HISTORY_CHECKPOINT_IVC_PCS_LOG_INV_RATE,
};

const DEFAULT_SAMPLES: usize = 3;

#[derive(Clone)]
struct ChunkFixture {
    statement: HistoryCheckpointStepStatement,
    certificate_batch_statement: AcceptedBlockCertificateBatchStatement,
    certificate_receipt_projection_handles: Vec<AcceptedBlockReceiptProjectionHandle>,
    certificate_receipts: Vec<AcceptedBlockCertificateReceipt>,
    accepted_claim_witness: AcceptedClaimBatchWitness,
    accepted_claim_output: AcceptedClaimBatchOutput,
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default)
}

fn time_once<T>(f: impl FnOnce() -> T) -> (Duration, T) {
    let start = Instant::now();
    let out = f();
    (start.elapsed(), out)
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

fn fmt_ms(duration: Duration) -> String {
    if duration.as_secs() > 0 {
        format!("{:>8.2} s ", duration.as_secs_f64())
    } else {
        format!("{:>8.2} ms", duration.as_secs_f64() * 1000.0)
    }
}

fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:>8.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:>8.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes:>8} B  ")
    }
}

fn prove_fixture(fixture: &ChunkFixture) -> noid_recursive::HistoryCheckpointIvcChunkCoreProof {
    prove_history_checkpoint_ivc_chunk_receipt_handle_core(
        &fixture.statement,
        &fixture.certificate_batch_statement,
        &fixture.certificate_receipt_projection_handles,
        &fixture.certificate_receipts,
        &fixture.accepted_claim_witness,
        &fixture.accepted_claim_output,
    )
    .expect("checkpoint IVC chunk-core proves")
}

fn verify_fixture(
    fixture: &ChunkFixture,
    proof: &noid_recursive::HistoryCheckpointIvcChunkCoreProof,
) {
    verify_history_checkpoint_ivc_chunk_core(
        &fixture.statement,
        &fixture.certificate_batch_statement,
        proof,
    )
    .expect("checkpoint IVC chunk-core verifies");
}

fn bench(samples: usize, fixture: &ChunkFixture) {
    let proof = prove_fixture(fixture);
    verify_fixture(fixture, &proof);

    let mut prove_times = Vec::with_capacity(samples);
    let mut verify_times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (prove_time, proof) = time_once(|| prove_fixture(fixture));
        prove_times.push(prove_time);
        let (verify_time, ()) = time_once(|| verify_fixture(fixture, &proof));
        verify_times.push(verify_time);
        black_box(proof);
    }

    let prove = median(prove_times);
    let verify = median(verify_times);
    let proof_bytes = proof.byte_len();
    let core_proof_wire_bytes = proof.core_proof.len();
    let core_proof_actual_bytes = proof.core_proof_len as usize;
    let handle_bytes = bincode::serialized_size(&proof.certificate_receipt_projection_handles)
        .expect("certificate receipt projection handles serialize") as usize;
    let receipt_bytes = bincode::serialized_size(&proof.certificate_receipts)
        .expect("certificate receipts serialize") as usize;
    let accepted_claim_digest_fields_bytes =
        bincode::serialized_size(&proof.accepted_claim_digest_hash_fields)
            .expect("accepted-claim digest fields serialize") as usize;

    println!("  chunk_len={}", proof.chunk_len);
    println!("  relation={}", proof.relation);
    println!("  proof_bytes={}", fmt_bytes(proof_bytes));
    println!(
        "  certificate_receipt_projection_handles={}",
        fmt_bytes(handle_bytes)
    );
    println!("  certificate_receipts={}", fmt_bytes(receipt_bytes));
    println!(
        "  accepted_claim_digest_fields={}",
        fmt_bytes(accepted_claim_digest_fields_bytes)
    );
    println!("  core_proof_wire={}", fmt_bytes(core_proof_wire_bytes));
    println!("  core_proof_actual={}", fmt_bytes(core_proof_actual_bytes));
    println!("  prove_median={}", fmt_ms(prove));
    println!("  verify_median={}", fmt_ms(verify));
    println!(
        "  per_block_prove_median={:>8.2} ms",
        prove.as_secs_f64() * 1000.0 / proof.chunk_len as f64
    );
}

fn main() {
    let samples = env_usize("NOID_RECURSIVE_CHECKPOINT_IVC_SAMPLES", DEFAULT_SAMPLES);
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let (fixture_time, fixture) = time_once(chunk_fixture);

    println!("noid_recursive checkpoint_ivc");
    println!("  backend=checkpoint_ivc_backend");
    println!("  proof_core=Poseidon2b BaseFold/R1CS");
    println!("  pcs_log_inv_rate={HISTORY_CHECKPOINT_IVC_PCS_LOG_INV_RATE}");
    println!("  pcs_log_batch_size={HISTORY_CHECKPOINT_IVC_PCS_LOG_BATCH_SIZE}");
    println!(
        "  chunk_core_wire_bytes={}",
        fmt_bytes(HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES)
    );
    println!(
        "  chunk_capacity={}",
        HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS
    );
    println!("  tx_count_dependent=false");
    println!("  full_component_ivc=false");
    println!("  fixture_includes_certificate_handle_issuance=true");
    println!("  samples={samples}");
    println!("  fixture_build={}", fmt_ms(fixture_time));

    bench(samples, &fixture);
}

fn chunk_fixture() -> ChunkFixture {
    let chunk_capacity = HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize;
    let start_header = genesis_header();
    let mut consensus = RecursiveConsensusState::from_header(
        &start_header,
        block_work(&start_header.difficulty_target),
        0,
        start_header.timestamp,
        start_header.difficulty_target,
        &[start_header.timestamp],
        &[start_header.active_slot_count],
    );
    let start_consensus = consensus.clone();
    let start_accumulator = genesis_accumulator();
    let start_anchor = anchor_from_consensus(&start_consensus, start_header.tx_root);

    let mut accumulator = start_accumulator.clone();
    let mut previous_block_id = start_consensus.block_id;
    let mut headers = Vec::with_capacity(chunk_capacity);
    let mut claims = Vec::with_capacity(chunk_capacity);
    let mut certificate_statements = Vec::with_capacity(chunk_capacity);
    for index in 0..chunk_capacity {
        let height = accumulator.height + 1;
        let state_seed = (index as u8).wrapping_add(2);
        let header = test_header(previous_block_id, [state_seed; 32], height);
        let header_witness = HeaderWitness::from_header(&header);
        let accepted_block_claim_digest = digest_with_seed(0x80 | index as u8);
        let claim = digest_to_fields(accepted_block_claim_digest);
        let certificate = AcceptedBlockCertificateStatement {
            height,
            block_id: header_witness.block_id,
            parent_block_id: previous_block_id,
            parent_state_root: accumulator.state_root,
            child_state_root: header.state_root,
            tx_root: header.tx_root,
            block_body_digest: digest_with_seed(0x20 | index as u8),
            block_proof_digest: digest_with_seed(0x30 | index as u8),
            auth_sidecar_digest: digest_with_seed(0x40 | index as u8),
            accepted_block_claim_digest,
            accepted_state_transition_claim_digest: digest_with_seed(0x50 | index as u8),
            exact_transition_digest: digest_with_seed(0x60 | index as u8),
            tx_count: index as u32,
            user_tx_count: index as u32,
            live_input_count: 0,
            live_output_count: 0,
            state_frontier_node_count: 0,
            touched_slot_count: 0,
            action_count: 0,
            block_body_len: 0,
            block_proof_len: 0,
            auth_sidecar_len: 0,
        };
        consensus.height = height;
        consensus.block_id = header_witness.block_id;
        consensus.state_root = header.state_root;
        consensus.cumulative_chainwork = add_work(
            &consensus.cumulative_chainwork,
            &block_work(&header.difficulty_target),
        );
        consensus.log_slots = header.log_slots;
        consensus.active_slot_count = header.active_slot_count;
        consensus.alloc_counter = header.alloc_counter;

        accumulator = accumulator
            .advance(&header)
            .expect("header advances accumulator");
        previous_block_id = header_witness.block_id;
        headers.push(header_witness);
        claims.push(claim);
        certificate_statements.push(certificate);
    }

    let accepted_claim_witness = AcceptedClaimBatchWitness {
        headers,
        accepted_block_claims: claims,
    };
    let accepted_claim_output = AcceptedClaimBatchOutput {
        consensus_state: consensus.clone(),
        accumulator: accumulator.clone(),
    };
    let accepted_claim_batch_digest =
        accepted_claim_batch_digest(&accepted_claim_witness, &accepted_claim_output)
            .expect("accepted claim digest");
    let certificate_batch_statement = accepted_block_certificate_batch_statement(
        &certificate_statements,
        &accepted_claim_witness.accepted_block_claims,
        accepted_claim_batch_digest,
    )
    .expect("certificate batch");
    let mut certificate_receipts = Vec::with_capacity(chunk_capacity);
    let mut certificate_receipt_projection_handles = Vec::with_capacity(chunk_capacity);
    for certificate_statement in &certificate_statements {
        certificate_receipts.push(accepted_block_certificate_receipt(certificate_statement));
        let certificate_proof =
            prove_accepted_block_certificate_receipt_projection_proof(certificate_statement)
                .expect("certificate handle proof builds");
        certificate_receipt_projection_handles.push(
            accepted_block_receipt_projection_handle(&certificate_proof)
                .expect("certificate receipt projection handle builds"),
        );
    }
    let end_anchor = anchor_from_consensus(
        &accepted_claim_output.consensus_state,
        accepted_claim_witness
            .headers
            .last()
            .expect("chunk has last header")
            .header
            .tx_root,
    );
    let previous_head =
        history_checkpoint_head_from_boundary(&start_anchor, &start_accumulator, &start_consensus)
            .expect("previous head");
    let batch_summary = HistoryCheckpointBatchSummary {
        batch_len: chunk_capacity as u32,
        start_anchor,
        end_anchor,
        start_accumulator,
        end_accumulator: accepted_claim_output.accumulator.clone(),
        start_consensus,
        end_consensus: accepted_claim_output.consensus_state.clone(),
        accepted_claim_batch_digest,
    };
    let next_head =
        advance_history_checkpoint_head_native(&previous_head, &batch_summary).expect("next head");
    let statement = HistoryCheckpointStepStatement {
        previous_head,
        batch_summary,
        next_head,
    };
    assert_eq!(
        statement.next_head.engine_id,
        HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC
    );

    ChunkFixture {
        statement,
        certificate_batch_statement,
        certificate_receipt_projection_handles,
        certificate_receipts,
        accepted_claim_witness,
        accepted_claim_output,
    }
}

fn test_header(
    prev_block_hash: Digest,
    state_root: Digest,
    height: u64,
) -> noid_chain::BlockHeader {
    noid_chain::BlockHeader {
        attested_coverage: 0,
        prev_block_hash,
        state_root,
        tx_root: digest_with_seed(0x10 | (height as u8)),
        timestamp: GENESIS_TIMESTAMP + height * BLOCK_TIME,
        height,
        miner_address: Address([0x44; 32]),
        nonce: height as u128,
        difficulty_target: MAX_TARGET,
        log_slots: 24,
        active_slot_count: height,
        alloc_counter: height,
    }
}

fn anchor_from_consensus(
    consensus: &RecursiveConsensusState,
    tx_root: Digest,
) -> HeaderChainAnchor {
    HeaderChainAnchor {
        height: consensus.height,
        block_id: consensus.block_id,
        state_root: consensus.state_root,
        tx_root,
        miner_address: Address([0x44; 32]),
        log_slots: consensus.log_slots,
        active_slot_count: consensus.active_slot_count,
        alloc_counter: consensus.alloc_counter,
        cumulative_chainwork: consensus.cumulative_chainwork,
    }
}

fn digest_to_fields(hash: Digest) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap())),
    ]
}

fn digest_with_seed(seed: u8) -> Digest {
    [seed; 32]
}
