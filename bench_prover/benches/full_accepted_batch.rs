// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Full `AcceptBlock` batch benchmark for the receipt issuance boundary.
//!
//! This benchmark measures the tx-dependent block-validation work that issues
//! fixed accepted-block certificates before the checkpoint task folds receipts.
//! It intentionally uses retained semantic blocks and detached witnesses, not
//! pre-trusted local history claims.

use std::env;
use std::io::Write;

use bench_prover::{fmt_bytes, fmt_ms, median, time_once};
use noid_block::{
    accepted_block_certificate_batch_statement_digest, accepted_claim_batch_digest,
    build_exact_state_transition_proof, history_checkpoint_batch_summary_from_full_accepted_output,
    prove_history_checkpoint_step_proof_from_verified_full_accepted_output,
    prove_retained_full_accepted_block_batch_proof,
    verify_history_checkpoint_step_proof_with_verified_full_accepted_output,
    verify_retained_full_accepted_block_batch_proof, BlockAuthSidecar, BlockProof,
    FullAcceptedBlockBatchItem, FullAcceptedBlockBatchWitness,
};
use noid_chain::block::{compute_tx_root, Block};
use noid_chain::consensus::difficulty::{block_work, next_target};
use noid_chain::consensus::fees::required_fee_for_tx_body;
use noid_chain::consensus::params::{BLOCK_TIME, MAX_TARGET};
use noid_chain::consensus::pow::{search_pow, validate_pow};
use noid_chain::fri_state::SlotValue;
use noid_chain::header_anchor::compute_header_chain_anchor;
use noid_chain::state::ChainState;
use noid_chain::{apply_tx, build_exact_action_surface, hash_block_header, BlockHeader};
use noid_core::Block128;
use noid_gkr::{
    owner_auth_gkr_channel, owner_auth_inputs_from_body_and_live_secrets,
    prove_owner_auth_killshot, OwnerAuthCircuit,
};
use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret};
use noid_recursive::{
    advance_history_checkpoint_head_native, history_checkpoint_head_from_boundary,
    prove_accepted_claim_batch_digest, verify_accepted_claim_batch_digest,
    verify_history_checkpoint_step_proof_checkpoint,
    verify_history_checkpoint_step_statement_native, verify_pow_header_witness_batch_native,
    ChainAccumulator, HeaderWitness, HistoryCheckpointIvcChunkCoreProof,
    HistoryCheckpointStepBackendProof, HistoryCheckpointStepStatement, RecursiveConsensusState,
};
use noid_tx::{hash_tx_body_for_shape, Transaction, TxBody, TxInput, TxOutput, TxShape};
use rayon::prelude::*;

const RETAINED_WINDOW_BLOCKS: usize = 18;
const CHECKPOINT_BATCH_TARGET_BLOCKS: usize = 16;
const BENCH_POW_SEARCH_RANGE: u128 = 100_000_000;
const BENCH_POW_CHUNK_SIZE: u128 = 65_536;
const PREMINED_COINBASE_ONLY_NONCES: [u128; CHECKPOINT_BATCH_TARGET_BLOCKS] = [
    69_582, 579_360, 737_824, 268_145, 15_749, 43_373, 199_577, 600_086, 425_466, 310_248, 166_011,
    1_355_852, 479_822, 418_510, 220_161, 95_998,
];
const PREMINED_USER_BLOCK_NONCE: u128 = 87_803;
const PREMINED_USER_THEN_COINBASE_TAIL_NONCES: [u128; CHECKPOINT_BATCH_TARGET_BLOCKS - 1] = [
    124_329, 1_886_009, 159_414, 531_286, 230_280, 689_257, 156_834, 582_378, 691_435, 566_052,
    420_051, 94_211, 93_651, 134_834, 366_524,
];

type FullBatchFixture = (
    RecursiveConsensusState,
    ChainAccumulator,
    BlockHeader,
    ChainState,
    FullAcceptedBlockBatchWitness,
);

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            let value = value.trim();
            !(value == "0" || value.eq_ignore_ascii_case("false"))
        })
        .unwrap_or(default)
}

fn parent_header(state: &mut ChainState) -> BlockHeader {
    BlockHeader {
        prev_block_hash: [0u8; 32],
        state_root: state.state_root(),
        tx_root: compute_tx_root(&[]),
        timestamp: 1_767_225_600,
        height: 0,
        miner_address: Address([0x11; 32]),
        nonce: 0,
        difficulty_target: MAX_TARGET,
        log_slots: state.state.log_slots() as u32,
        active_slot_count: state.active_slot_count,
        alloc_counter: state.alloc_counter,
    }
}

fn start_tuple(parent: &BlockHeader) -> (RecursiveConsensusState, ChainAccumulator) {
    let start_consensus = RecursiveConsensusState::from_header(
        parent,
        block_work(&parent.difficulty_target),
        0,
        parent.timestamp,
        parent.difficulty_target,
        &[parent.timestamp],
        &[parent.active_slot_count],
    );
    let start_accumulator = ChainAccumulator {
        height: parent.height,
        state_root: parent.state_root,
        chain_hash: [0u8; 32],
    };
    (start_consensus, start_accumulator)
}

fn bench_pow_nonce(header: &BlockHeader) -> u128 {
    if let Some(nonce) = search_pow(header, 0, 1) {
        return nonce;
    }
    let worker_chunks = rayon::current_num_threads().max(1) as u128;
    let mut base = 1u128;
    while base < BENCH_POW_SEARCH_RANGE {
        let remaining = BENCH_POW_SEARCH_RANGE.saturating_sub(base);
        let chunks = remaining.div_ceil(BENCH_POW_CHUNK_SIZE).min(worker_chunks);
        if let Some(nonce) = (0..chunks).into_par_iter().find_map_any(|chunk| {
            let start = base.saturating_add(chunk.saturating_mul(BENCH_POW_CHUNK_SIZE));
            let remaining = BENCH_POW_SEARCH_RANGE.saturating_sub(start);
            let range = remaining.min(BENCH_POW_CHUNK_SIZE);
            search_pow(header, start, range)
        }) {
            return nonce;
        }
        base = base.saturating_add(chunks.saturating_mul(BENCH_POW_CHUNK_SIZE));
    }
    panic!("bench target mines")
}

fn empty_child(
    parent: &BlockHeader,
    state: &ChainState,
    rolling_consensus: &RecursiveConsensusState,
    premined_nonce: Option<u128>,
) -> Block {
    let timestamp = parent.timestamp + BLOCK_TIME;
    let difficulty_target = next_target(
        rolling_consensus.asert_anchor_height,
        rolling_consensus.asert_anchor_timestamp,
        &rolling_consensus.asert_anchor_target,
        parent.height + 1,
        timestamp,
    );
    let mut header = BlockHeader {
        prev_block_hash: hash_block_header(parent),
        state_root: state.cached_state_root(),
        tx_root: compute_tx_root(&[]),
        timestamp,
        height: parent.height + 1,
        miner_address: Address([0x22; 32]),
        nonce: 0,
        difficulty_target,
        log_slots: parent.log_slots,
        active_slot_count: parent.active_slot_count,
        alloc_counter: parent.alloc_counter,
    };
    if let Some(nonce) = premined_nonce {
        header.nonce = nonce;
        validate_pow(&header).expect("premined bench nonce is valid");
    } else {
        header.nonce = bench_pow_nonce(&header);
    }
    Block {
        header,
        transactions: vec![],
    }
}

fn coinbase_only_batch(
    n: usize,
) -> (
    RecursiveConsensusState,
    ChainAccumulator,
    BlockHeader,
    ChainState,
    FullAcceptedBlockBatchWitness,
) {
    let mut start_state = ChainState::with_log_slots(8);
    let mut parent = parent_header(&mut start_state);
    let start_parent = parent.clone();
    let (start_consensus, start_accumulator) = start_tuple(&start_parent);
    let mut items = Vec::with_capacity(n);
    let mut rolling_consensus = start_consensus.clone();
    let progress = env_bool("NOID_FULL_ACCEPTED_BATCH_PROGRESS", false);
    for index in 0..n {
        let premined_nonce = PREMINED_COINBASE_ONLY_NONCES.get(index).copied();
        let (block_time, block) =
            time_once(|| empty_child(&parent, &start_state, &rolling_consensus, premined_nonce));
        if progress {
            println!(
                "    fixture block={}/{} height={} nonce={} build={}",
                index + 1,
                n,
                block.header.height,
                block.header.nonce,
                fmt_ms(block_time)
            );
            let _ = std::io::stdout().flush();
        }
        rolling_consensus = verify_pow_header_witness_batch_native(
            &rolling_consensus,
            &[HeaderWitness::from_header(&block.header)],
        )
        .expect("bench header advances consensus");
        parent = block.header.clone();
        items.push(FullAcceptedBlockBatchItem {
            block,
            block_proof_bytes: vec![],
            block_auth_sidecar_bytes: vec![],
        });
    }
    (
        start_consensus,
        start_accumulator,
        start_parent,
        start_state,
        FullAcceptedBlockBatchWitness { items },
    )
}

fn spend_secret(seed: u8) -> SpendSecret {
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_mul(19).wrapping_add(i as u8);
    }
    SpendSecret(bytes)
}

fn tx_from_body(body: TxBody) -> Transaction {
    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );
    Transaction { body, tx_body_hash }
}

fn auth_proof_for_body(body: &TxBody) -> noid_gkr::OwnerAuthProofKillShot {
    let live_secrets: Vec<_> = body
        .inputs
        .iter()
        .filter(|input| input.valid)
        .map(|input| input.spend_secret.clone())
        .collect();
    let auth_inputs = owner_auth_inputs_from_body_and_live_secrets(body, &live_secrets)
        .expect("bench auth inputs");
    let circuit = OwnerAuthCircuit::build(auth_inputs.layout);
    let mut channel = owner_auth_gkr_channel();
    prove_owner_auth_killshot(&circuit, &auth_inputs, &mut channel).0
}

fn one_user_block_item() -> (
    RecursiveConsensusState,
    ChainAccumulator,
    BlockHeader,
    ChainState,
    FullAcceptedBlockBatchItem,
    ChainState,
) {
    let secret = spend_secret(7);
    let owner = derive_address(&secret);
    let mut start_state = ChainState::with_log_slots(4);
    let input_value = 10_000u64;
    let pre_slot = SlotValue {
        value: Block128::from(input_value as u128),
        owner_hi: owner.as_fields()[0],
        owner_lo: owner.as_fields()[1],
    };
    start_state.state.set_slot(2, pre_slot).unwrap();
    start_state.rebuild_exact_utxo_root_loaded().unwrap();
    start_state.active_slot_count = 1;
    start_state.alloc_counter = 2;

    let parent = parent_header(&mut start_state);
    let (start_consensus, start_accumulator) = start_tuple(&parent);

    let mut body = TxBody {
        shape: TxShape::Standard4x8,
        epoch_anchor: [0x42; 32],
        fee: 0,
        inputs: vec![TxInput {
            slot_index: 2,
            value: input_value,
            owner,
            spend_secret: secret,
            valid: true,
        }],
        outputs: vec![TxOutput {
            slot_index: 5,
            value: input_value,
            owner,
            valid: true,
        }],
        is_coinbase: false,
    };
    let required_fee = required_fee_for_tx_body(&body, parent.active_slot_count, parent.log_slots);
    body.fee = required_fee as u128;
    body.outputs[0].value = input_value.saturating_sub(required_fee);
    let tx = tx_from_body(body.clone());
    let txs = vec![tx.clone()];

    let parent_cache = {
        let mut tmp = start_state.clone();
        tmp.exact_sparse_cache().unwrap()
    };
    let claims = vec![noid_tx::compute_claims_commitment(
        &body.inputs,
        &body.outputs,
    )];
    let surface = build_exact_action_surface(&start_state.state, &[body.clone()], &claims)
        .expect("exact action surface");
    let state_transition = build_exact_state_transition_proof(
        &parent_cache,
        &surface,
        &start_state.reuse_guard,
        parent.height + 1,
    )
    .expect("exact proof");

    let mut child_state = start_state.clone();
    apply_tx(&mut child_state, &body).expect("native tx apply");
    let mut child_guard = start_state.reuse_guard.clone();
    child_guard
        .apply_spends(parent.height + 1, &surface.spent_slots)
        .expect("guard spend apply");
    child_state.reuse_guard = child_guard;
    let child_state_root = child_state.cached_state_root();
    let timestamp = parent.timestamp + BLOCK_TIME;
    let mut header = BlockHeader {
        prev_block_hash: hash_block_header(&parent),
        state_root: child_state_root,
        tx_root: compute_tx_root(&txs),
        timestamp,
        height: parent.height + 1,
        miner_address: Address([0x22; 32]),
        nonce: 0,
        difficulty_target: next_target(
            start_consensus.asert_anchor_height,
            start_consensus.asert_anchor_timestamp,
            &start_consensus.asert_anchor_target,
            parent.height + 1,
            timestamp,
        ),
        log_slots: parent.log_slots,
        active_slot_count: child_state.active_slot_count,
        alloc_counter: child_state.alloc_counter,
    };
    let progress = env_bool("NOID_FULL_ACCEPTED_BATCH_PROGRESS", false);
    let (pow_time, ()) = time_once(|| {
        header.nonce = PREMINED_USER_BLOCK_NONCE;
        validate_pow(&header).expect("premined user-block bench nonce is valid");
    });
    if progress {
        println!(
            "    fixture user_block height={} nonce={} pow={}",
            header.height,
            header.nonce,
            fmt_ms(pow_time)
        );
        let _ = std::io::stdout().flush();
    }
    let block = Block {
        header,
        transactions: txs,
    };
    let block_proof = BlockProof::minimal(
        parent.state_root,
        block.header.state_root,
        1,
        state_transition,
    );
    let auth_sidecar = BlockAuthSidecar {
        tx_auth: vec![auth_proof_for_body(&body)],
    };
    let item = FullAcceptedBlockBatchItem {
        block,
        block_proof_bytes: bincode::serialize(&block_proof).unwrap(),
        block_auth_sidecar_bytes: bincode::serialize(&auth_sidecar).unwrap(),
    };

    (
        start_consensus,
        start_accumulator,
        parent,
        start_state,
        item,
        child_state,
    )
}

fn one_user_block_batch() -> FullBatchFixture {
    let (start_consensus, start_accumulator, parent, start_state, item, _) = one_user_block_item();
    (
        start_consensus,
        start_accumulator,
        parent,
        start_state,
        FullAcceptedBlockBatchWitness { items: vec![item] },
    )
}

fn user_then_coinbase_batch(n: usize) -> FullBatchFixture {
    assert!(n > 0, "mixed bench needs at least the user block");
    let (start_consensus, start_accumulator, start_parent, start_state, first_item, tail_state) =
        one_user_block_item();
    let progress = env_bool("NOID_FULL_ACCEPTED_BATCH_PROGRESS", false);
    let mut items = Vec::with_capacity(n);
    let mut parent = first_item.block.header.clone();
    let mut rolling_consensus = verify_pow_header_witness_batch_native(
        &start_consensus,
        &[HeaderWitness::from_header(&parent)],
    )
    .expect("bench user header advances consensus");
    items.push(first_item);

    for tail_index in 0..n.saturating_sub(1) {
        let premined_nonce = PREMINED_USER_THEN_COINBASE_TAIL_NONCES
            .get(tail_index)
            .copied();
        let (block_time, block) =
            time_once(|| empty_child(&parent, &tail_state, &rolling_consensus, premined_nonce));
        if progress {
            println!(
                "    fixture mixed_tail block={}/{} height={} nonce={} build={}",
                tail_index + 2,
                n,
                block.header.height,
                block.header.nonce,
                fmt_ms(block_time)
            );
            let _ = std::io::stdout().flush();
        }
        rolling_consensus = verify_pow_header_witness_batch_native(
            &rolling_consensus,
            &[HeaderWitness::from_header(&block.header)],
        )
        .expect("bench tail header advances consensus");
        parent = block.header.clone();
        items.push(FullAcceptedBlockBatchItem {
            block,
            block_proof_bytes: vec![],
            block_auth_sidecar_bytes: vec![],
        });
    }

    (
        start_consensus,
        start_accumulator,
        start_parent,
        start_state,
        FullAcceptedBlockBatchWitness { items },
    )
}

fn bench_case<F>(label: &str, build_fixture: F, samples: usize)
where
    F: FnOnce() -> FullBatchFixture,
{
    println!("  case={label}");
    let (build_time, fixture) = time_once(build_fixture);
    let (start_consensus, start_accumulator, parent, state, witness) = fixture;
    let (prove_time, (out, proof)) = time_once(|| {
        prove_retained_full_accepted_block_batch_proof(
            &start_consensus,
            &start_accumulator,
            &parent,
            &state,
            &witness,
        )
        .expect("full accepted batch proves")
    });
    let mut verify_times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (elapsed, verified) = time_once(|| {
            verify_retained_full_accepted_block_batch_proof(
                &start_consensus,
                &start_accumulator,
                &parent,
                &state,
                &witness,
                &proof,
            )
            .expect("full accepted batch verifies")
        });
        assert_eq!(verified.accepted_claim_batch, out.accepted_claim_batch);
        verify_times.push(elapsed);
    }
    let verify_time = median(verify_times);
    let accepted_claim_batch_digest = accepted_claim_batch_digest(&out);
    let (accepted_claim_digest_proof_time, accepted_claim_digest_proof) = time_once(|| {
        prove_accepted_claim_batch_digest(
            &out.proof_components.accepted_claim_witness,
            &out.accepted_claim_batch,
        )
        .expect("accepted-claim batch digest proof builds")
    });
    let (accepted_claim_digest_verify_time, ()) = time_once(|| {
        verify_accepted_claim_batch_digest(
            &out.proof_components.accepted_claim_witness,
            &out.accepted_claim_batch,
            &accepted_claim_digest_proof,
        )
        .expect("accepted-claim batch digest proof verifies")
    });
    let start_anchor = compute_header_chain_anchor(
        std::iter::once(&parent),
        start_consensus.cumulative_chainwork,
    )
    .expect("start anchor computes");
    let summary = history_checkpoint_batch_summary_from_full_accepted_output(
        &start_anchor,
        &start_consensus,
        &start_accumulator,
        &out,
        accepted_claim_batch_digest,
    )
    .expect("checkpoint summary builds");
    let previous_head = history_checkpoint_head_from_boundary(
        &summary.start_anchor,
        &summary.start_accumulator,
        &summary.start_consensus,
    )
    .expect("previous checkpoint head builds");
    let next_head = advance_history_checkpoint_head_native(&previous_head, &summary)
        .expect("next checkpoint head builds");
    let step_statement = HistoryCheckpointStepStatement {
        previous_head,
        batch_summary: summary,
        next_head,
    };
    verify_history_checkpoint_step_statement_native(&step_statement)
        .expect("checkpoint step statement verifies");
    let (step_proof_time, (step_proof, certificate_batch_statement)) = time_once(|| {
        prove_history_checkpoint_step_proof_from_verified_full_accepted_output(
            &step_statement,
            &out,
        )
        .expect("checkpoint step proof builds from already verified accepted output")
    });
    assert_eq!(
        certificate_batch_statement.batch_len,
        step_statement.batch_summary.batch_len
    );
    assert_eq!(
        certificate_batch_statement.accepted_claim_batch_digest,
        step_statement.batch_summary.accepted_claim_batch_digest
    );
    let certificate_batch_statement_digest =
        accepted_block_certificate_batch_statement_digest(&certificate_batch_statement);
    assert_ne!(certificate_batch_statement_digest, [0u8; 32]);
    let (step_private_verify_time, ()) = time_once(|| {
        verify_history_checkpoint_step_proof_with_verified_full_accepted_output(
            &step_statement,
            &certificate_batch_statement,
            &out,
            &step_proof,
        )
        .expect("checkpoint step already verified accepted output verifies")
    });
    let (step_verify_time, step_verify_result) = time_once(|| {
        verify_history_checkpoint_step_proof_checkpoint(
            &step_statement,
            &certificate_batch_statement,
            &step_proof,
        )
    });
    step_verify_result.expect("checkpoint step public checkpoint path verifies");
    println!(
        "    blocks={} claims={} build_fixture={} prove={} verify={} proof={} end_height={} start_height={} suffix_budget={}",
        witness.items.len(),
        out.proof_components
            .accepted_claim_witness
            .accepted_block_claims
            .len(),
        fmt_ms(build_time),
        fmt_ms(prove_time),
        fmt_ms(verify_time),
        fmt_bytes(proof.byte_len(&out.proof_components)),
        out.accepted_claim_batch.consensus_state.height,
        start_consensus.height,
        RETAINED_WINDOW_BLOCKS.saturating_sub(CHECKPOINT_BATCH_TARGET_BLOCKS)
    );
    println!(
        "    checkpoint_step statement={} next_head={} accepted_claim_batch_bound=true",
        fmt_bytes(step_statement.byte_len()),
        fmt_bytes(step_statement.next_head.byte_len())
    );
    println!(
        "    accepted_claim_batch digest_proof={} prove={} verify={} fixed_slots={}",
        fmt_bytes(accepted_claim_digest_proof.byte_len()),
        fmt_ms(accepted_claim_digest_proof_time),
        fmt_ms(accepted_claim_digest_verify_time),
        CHECKPOINT_BATCH_TARGET_BLOCKS
    );
    println!(
        "    checkpoint_step proof={} prove={} private_verify={} public_verify={}",
        fmt_bytes(step_proof.byte_len()),
        fmt_ms(step_proof_time),
        fmt_ms(step_private_verify_time),
        fmt_ms(step_verify_time)
    );
    let step_backend: HistoryCheckpointStepBackendProof =
        bincode::deserialize(&step_proof.backend_proof).expect("checkpoint step backend decodes");
    println!(
        "    checkpoint_step_parts backend={} step_digest={} cert_digest={} claim_digest={} chunk_core={}",
        fmt_bytes(step_backend.byte_len()),
        fmt_bytes(step_backend.step_statement_digest_proof.byte_len()),
        fmt_bytes(step_backend.certificate_batch_digest_proof.byte_len()),
        fmt_bytes(
            step_backend
                .accepted_claim_batch_digest_proof
                .as_ref()
                .map_or(0, |proof| proof.byte_len())
        ),
        fmt_bytes(
            step_backend
                .checkpoint_ivc_chunk_core_proof
                .as_ref()
                .map_or(0, |proof| proof.byte_len())
        )
    );
    if let Some(chunk_core) = &step_backend.checkpoint_ivc_chunk_core_proof {
        print_chunk_core_part(chunk_core);
    }
    println!(
        "    certificate_batch statement={} fixed_slots={} digest_bound=true",
        fmt_bytes(certificate_batch_statement.byte_len()),
        CHECKPOINT_BATCH_TARGET_BLOCKS
    );
    let certificate_proof_bytes: usize = out
        .proof_components
        .accepted_block_certificate_proofs
        .iter()
        .map(|proof| proof.byte_len())
        .sum();
    let certificate_handle_bytes = bincode::serialized_size(
        &out.proof_components
            .accepted_block_receipt_projection_handles,
    )
    .expect("certificate receipt projection handles serialize")
        as usize;
    let certificate_receipt_bytes =
        bincode::serialized_size(&out.proof_components.accepted_block_certificate_receipts)
            .expect("certificate receipts serialize") as usize;
    println!(
        "    certificate_sidecars proofs={} handles={} receipts={} fixed_history_inputs=true",
        fmt_bytes(certificate_proof_bytes),
        fmt_bytes(certificate_handle_bytes),
        fmt_bytes(certificate_receipt_bytes)
    );
    println!(
        "    components claim_hashes={} exact_state={} auth_traces={} standard_spines={} sweep_spines={} tx_root_paths={}",
        out.proof_components.accepted_claim_hash_inputs.len(),
        proof.exact_state.len(),
        proof.authorization_transcripts.len(),
        usize::from(proof.tx_body_standard.is_some()),
        usize::from(proof.tx_body_sweep.is_some()),
        out.proof_components.tx_root_inputs.len()
    );
}

fn print_chunk_core_part(chunk_core: &HistoryCheckpointIvcChunkCoreProof) {
    let handle_bytes = bincode::serialized_size(&chunk_core.certificate_receipt_projection_handles)
        .expect("certificate receipt projection handles serialize") as usize;
    let receipt_bytes = bincode::serialized_size(&chunk_core.certificate_receipts)
        .expect("certificate receipts serialize") as usize;
    let accepted_claim_digest_fields_bytes =
        bincode::serialized_size(&chunk_core.accepted_claim_digest_hash_fields)
            .expect("accepted-claim digest fields serialize") as usize;
    println!(
        "    checkpoint_chunk_core cert_handles={} receipts={} claim_digest_fields={} wire={} actual={} tx_count_dependent=false",
        fmt_bytes(handle_bytes),
        fmt_bytes(receipt_bytes),
        fmt_bytes(accepted_claim_digest_fields_bytes),
        fmt_bytes(chunk_core.core_proof.len()),
        fmt_bytes(chunk_core.core_proof_len as usize)
    );
}

fn main() {
    let samples = env_usize("NOID_FULL_ACCEPTED_BATCH_SAMPLES", 3);
    let no_user_blocks = env_usize("NOID_FULL_ACCEPTED_BATCH_BLOCKS", 1);
    println!("full_accepted_batch");
    println!("  relation=full-retained-AcceptBlock-batch");
    println!("  role=receipt_issuance_boundary");
    println!("  history_aggregation=false");
    println!("  retained_window_blocks={RETAINED_WINDOW_BLOCKS}");
    println!("  checkpoint_batch_target_blocks={CHECKPOINT_BATCH_TARGET_BLOCKS}");
    println!("  selected_no_user_blocks={no_user_blocks}");
    println!("  samples={samples}");
    println!("  public_o1_final=false");
    println!("  purpose=measure block-validation receipt issuance before fixed history folding");

    bench_case(
        "coinbase_only",
        || coinbase_only_batch(no_user_blocks),
        samples,
    );
    bench_case("user_block_1", one_user_block_batch, samples);
    bench_case(
        "user_then_coinbase_16",
        || user_then_coinbase_batch(CHECKPOINT_BATCH_TARGET_BLOCKS),
        samples,
    );
}
