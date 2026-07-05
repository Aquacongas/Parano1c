// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Tier-1 shape statistics for the acceptance-proof trace.
//!
//! Replays every killshot verifier that `verify_accepted_block_batch_components`
//! runs for a real accepted block, with a counting Fiat-Shamir channel wrapped
//! around the production `Poseidon2bChannel`. Prints, per component:
//! absorb/squeeze op counts, exact Poseidon2b permutation counts, and proof
//! sizes — the measured inputs behind the shape constants of
//! `noid_recursive::acceptance::shape` (the empirical cost model of the
//! acceptance-proof trace).
//!
//! This tool is measurement-only: it must not diverge from the call structure
//! of `block_certificate_backend.rs` / `checkpoint.rs`. When those change,
//! change this file in the same commit.

use std::io::Write;
use std::time::Duration;

use bench_prover::{fmt_bytes, fmt_ms, time_once};
use noid_block::validate::validate_block_authorizations_with_output;
use noid_block::{
    accept_block_timeless_with_artifacts, build_exact_state_transition_proof,
    prove_retained_full_accepted_block_batch_proof, verify_full_accepted_block_batch_native,
    verify_retained_full_accepted_block_batch_proof, BlockAuthSidecar, BlockProof,
    FullAcceptedBlockBatchItem, FullAcceptedBlockBatchProofComponents,
    FullAcceptedBlockBatchWitness, OwnerAuthAuthorizationVerifier,
    RetainedFullAcceptedBlockBatchProof,
};
use noid_chain::block::{compute_tx_root, Block};
use noid_chain::consensus::difficulty::{block_work, next_target};
use noid_chain::consensus::fees::required_fee_for_tx_body;
use noid_chain::consensus::params::{BLOCK_TIME, MAX_TARGET};
use noid_chain::consensus::pow::{search_pow, validate_pow};
use noid_chain::consensus::validation::{validate_block_checks_timeless, AnchorInfo};
use noid_chain::fri_state::SlotValue;
use noid_chain::state::ChainState;
use noid_chain::{apply_tx, build_exact_action_surface, hash_block_header, BlockHeader};
use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_gkr::{
    init_owner_auth_gkr_channel, owner_auth_gkr_channel, owner_auth_inputs_from_body_and_live_secrets,
    prove_owner_auth_killshot, verify_accepted_claim_hash_killshot, verify_batched_guard_bucket_killshot,
    verify_batched_merkle_killshot, verify_batched_slot_leaf_killshot,
    verify_batched_state_root_killshot, verify_block_spine_killshot,
    verify_chain_accumulator_killshot_padded, verify_header_hash_killshot_padded,
    verify_owner_auth_killshot, verify_sweep_block_spine_killshot, MerkleCircuit, OwnerAuthCircuit,
    MAX_MERKLE_DEPTH,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::{TAG_EXSTNOD, TAG_RGDNODE};
use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret};
use noid_recursive::{
    chain_accumulator_proof_inputs,
    header_hash_proof_inputs, prove_accepted_block_certificate_receipt_projection_proof,
    verify_pow_header_witness_batch_native,
    ChainAccumulator, HeaderWitness, RecursiveConsensusState,
};
use noid_tx::{
    hash_tx_body_for_shape, validate_public_tx_logic, Transaction, TxBody, TxInput, TxOutput,
    TxShape,
};
use rayon::prelude::*;

// Constraint cost of one Poseidon2b permutation in the F128 arithmetic trace
// (linear layers live in the F128-coefficient matrices for free):
// 90 S-boxes x 4 multiplications.
const PERM_TRACE_CONSTRAINTS: usize = 360;
const PREMINED_COINBASE_NONCE: u128 = 69_582;
const PREMINED_USER_BLOCK_NONCE: u128 = 87_803;
const BENCH_POW_SEARCH_RANGE: u128 = 100_000_000;
const BENCH_POW_CHUNK_SIZE: u128 = 65_536;

// ---------------------------------------------------------------------------
// Counting Fiat-Shamir channel.
//
// Delegates absorb/squeeze to the production `Poseidon2bChannel` (so every
// verifier sees the exact production challenge stream) while mirroring the
// sponge state machine (t=4, rate=2, buffered absorbs, pending squeeze lane)
// to count permutations exactly:
//   absorb: buffer one element; the second buffered element costs 1 permutation
//   squeeze: served from the pending lane for free every second call;
//            otherwise flush (1 permutation if an odd absorb is buffered)
//            plus 1 squeeze permutation
// ---------------------------------------------------------------------------

struct CountingChannel {
    inner: Poseidon2bChannel,
    absorbs: u64,
    squeezes: u64,
    perms: u64,
    buffered: u8,
    pending: bool,
}

impl CountingChannel {
    fn new() -> Self {
        Self {
            inner: Poseidon2bChannel::new(),
            absorbs: 0,
            squeezes: 0,
            perms: 0,
            buffered: 0,
            pending: false,
        }
    }

    fn stats(&self) -> FsStats {
        FsStats {
            absorbs: self.absorbs,
            squeezes: self.squeezes,
            perms: self.perms,
        }
    }
}

impl FiatShamir<Block128> for CountingChannel {
    fn absorb(&mut self, elem: Block128) {
        self.inner.absorb(elem);
        self.absorbs += 1;
        self.pending = false;
        self.buffered += 1;
        if self.buffered == 2 {
            self.perms += 1;
            self.buffered = 0;
        }
    }

    fn squeeze(&mut self) -> Block128 {
        let out = self.inner.squeeze();
        self.squeezes += 1;
        if self.pending {
            self.pending = false;
        } else {
            if self.buffered > 0 {
                self.perms += 1;
                self.buffered = 0;
            }
            self.perms += 1;
            self.pending = true;
        }
        out
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct FsStats {
    absorbs: u64,
    squeezes: u64,
    perms: u64,
}

impl FsStats {
    fn add(&mut self, other: FsStats) {
        self.absorbs += other.absorbs;
        self.squeezes += other.squeezes;
        self.perms += other.perms;
    }
}

struct Row {
    name: String,
    stats: FsStats,
    proof_bytes: usize,
    note: String,
}

// ---------------------------------------------------------------------------
// Fixtures (copied from full_accepted_batch.rs so both stay runnable
// independently; premined nonces keep PoW instant).
// ---------------------------------------------------------------------------

type FullBatchFixture = (
    RecursiveConsensusState,
    ChainAccumulator,
    BlockHeader,
    ChainState,
    FullAcceptedBlockBatchWitness,
);

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

fn coinbase_only_batch() -> FullBatchFixture {
    let mut start_state = ChainState::with_log_slots(8);
    let parent = parent_header(&mut start_state);
    let (start_consensus, start_accumulator) = start_tuple(&parent);
    let block = empty_child(
        &parent,
        &start_state,
        &start_consensus,
        Some(PREMINED_COINBASE_NONCE),
    );
    verify_pow_header_witness_batch_native(
        &start_consensus,
        &[HeaderWitness::from_header(&block.header)],
    )
    .expect("bench header advances consensus");
    let items = vec![FullAcceptedBlockBatchItem {
        block,
        block_proof_bytes: vec![],
        block_auth_sidecar_bytes: vec![],
    }];
    (
        start_consensus,
        start_accumulator,
        parent,
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

/// A single block with `n` independent Standard4x8 user transactions.
/// `n == 1` reproduces the `one_user_block` fixture of full_accepted_batch.rs
/// (premined nonce); larger `n` searches PoW (cheap at bench difficulty).
fn user_txs_block_batch(n: usize) -> FullBatchFixture {
    assert!(n >= 1);
    let log_slots = if n <= 1 {
        4
    } else {
        // 2 reserved slots + one interleaved in/out slot pair per tx; grow the
        // state for large blocks (255 txs -> log_slots 9).
        ((usize::BITS - (2 * n + 1).leading_zeros()) as usize).max(8)
    };
    let mut start_state = ChainState::with_log_slots(log_slots);
    let input_value = 10_000u64;

    let secrets: Vec<SpendSecret> = (0..n)
        .map(|i| spend_secret(7u8.wrapping_add(i as u8)))
        .collect();
    let owners: Vec<Address> = secrets.iter().map(derive_address).collect();
    let input_slot = |i: usize| 2 + 2 * i;
    let output_slot = |i: usize| 3 + 2 * i;
    for i in 0..n {
        let pre_slot = SlotValue {
            value: Block128::from(input_value as u128),
            owner_hi: owners[i].as_fields()[0],
            owner_lo: owners[i].as_fields()[1],
        };
        start_state
            .state
            .set_slot(input_slot(i) as u32, pre_slot)
            .unwrap();
    }
    // n == 1 keeps the exact legacy layout (input slot 2, output slot 5,
    // alloc_counter 2) so the premined nonce stays valid.
    let legacy_single = n == 1;
    start_state.rebuild_exact_utxo_root_loaded().unwrap();
    start_state.active_slot_count = n as u64;
    start_state.alloc_counter = if legacy_single {
        2
    } else {
        (input_slot(n - 1) + 1) as u64
    };

    let parent = parent_header(&mut start_state);
    let (start_consensus, start_accumulator) = start_tuple(&parent);

    let mut bodies = Vec::with_capacity(n);
    for i in 0..n {
        let out_slot = if legacy_single { 5 } else { output_slot(i) };
        let mut body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0x42; 32],
            fee: 0,
            inputs: vec![TxInput {
                slot_index: input_slot(i) as u32,
                value: input_value,
                owner: owners[i],
                spend_secret: secrets[i].clone(),
                valid: true,
            }],
            outputs: vec![TxOutput {
                slot_index: out_slot as u32,
                value: input_value,
                owner: owners[i],
                valid: true,
            }],
            is_coinbase: false,
        };
        let required_fee =
            required_fee_for_tx_body(&body, parent.active_slot_count, parent.log_slots);
        body.fee = required_fee as u128;
        body.outputs[0].value = input_value.saturating_sub(required_fee);
        bodies.push(body);
    }
    let txs: Vec<Transaction> = bodies.iter().cloned().map(tx_from_body).collect();

    let parent_cache = {
        let mut tmp = start_state.clone();
        tmp.exact_sparse_cache().unwrap()
    };
    let claims: Vec<_> = bodies
        .iter()
        .map(|body| noid_tx::compute_claims_commitment(&body.inputs, &body.outputs))
        .collect();
    let surface = build_exact_action_surface(&start_state.state, &bodies, &claims)
        .expect("exact action surface");
    let state_transition = build_exact_state_transition_proof(
        &parent_cache,
        &surface,
        &start_state.reuse_guard,
        parent.height + 1,
    )
    .expect("exact proof");

    let mut child_state = start_state.clone();
    for body in &bodies {
        apply_tx(&mut child_state, body).expect("native tx apply");
    }
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
    if legacy_single {
        header.nonce = PREMINED_USER_BLOCK_NONCE;
        validate_pow(&header).expect("premined user-block bench nonce is valid");
    } else {
        header.nonce = bench_pow_nonce(&header);
    }
    let block = Block {
        header,
        transactions: txs,
    };
    let block_proof = BlockProof::minimal(
        parent.state_root,
        block.header.state_root,
        n as u32,
        state_transition,
    );
    let auth_sidecar = BlockAuthSidecar {
        tx_auth: bodies.iter().map(auth_proof_for_body).collect(),
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
        FullAcceptedBlockBatchWitness { items: vec![item] },
    )
}

fn sweep_spend_secret(tx_index: usize, input_index: usize) -> SpendSecret {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x53; // 'S'weep domain byte, distinct from spend_secret()
    bytes[1..9].copy_from_slice(&(tx_index as u64).to_le_bytes());
    bytes[9..17].copy_from_slice(&(input_index as u64).to_le_bytes());
    for i in 17..32 {
        bytes[i] = (tx_index as u8)
            .wrapping_mul(31)
            .wrapping_add(input_index as u8)
            .wrapping_add(i as u8);
    }
    SpendSecret(bytes)
}

/// A single block with `n` independent full Sweep25x2 user transactions
/// (25 live inputs with a distinct owner each / 2 outputs — the heaviest
/// per-tx authorization shape; the sweep-heavy adversarial case).
fn sweep_txs_block_batch(n: usize) -> FullBatchFixture {
    assert!(n >= 1);
    const SWEEP_INPUTS: usize = 25;
    const SWEEP_OUTPUTS: usize = 2;
    const SLOTS_PER_TX: usize = SWEEP_INPUTS + SWEEP_OUTPUTS;
    let highest_slot = 2 + n * SLOTS_PER_TX - 1;
    let log_slots = ((usize::BITS - highest_slot.leading_zeros()) as usize).max(8);
    let mut start_state = ChainState::with_log_slots(log_slots);
    let input_value = 10_000u64;

    let in_slot = |tx: usize, k: usize| 2 + tx * SLOTS_PER_TX + k;
    let out_slot = |tx: usize, k: usize| 2 + tx * SLOTS_PER_TX + SWEEP_INPUTS + k;

    let secrets: Vec<Vec<SpendSecret>> = (0..n)
        .map(|tx| (0..SWEEP_INPUTS).map(|k| sweep_spend_secret(tx, k)).collect())
        .collect();
    for tx in 0..n {
        for k in 0..SWEEP_INPUTS {
            let owner = derive_address(&secrets[tx][k]);
            let pre_slot = SlotValue {
                value: Block128::from(input_value as u128),
                owner_hi: owner.as_fields()[0],
                owner_lo: owner.as_fields()[1],
            };
            start_state
                .state
                .set_slot(in_slot(tx, k) as u32, pre_slot)
                .unwrap();
        }
    }
    start_state.rebuild_exact_utxo_root_loaded().unwrap();
    start_state.active_slot_count = (n * SWEEP_INPUTS) as u64;
    start_state.alloc_counter = (2 + n * SLOTS_PER_TX) as u64;

    let parent = parent_header(&mut start_state);
    let (start_consensus, start_accumulator) = start_tuple(&parent);

    let mut bodies = Vec::with_capacity(n);
    for tx in 0..n {
        let inputs: Vec<TxInput> = (0..SWEEP_INPUTS)
            .map(|k| TxInput {
                slot_index: in_slot(tx, k) as u32,
                value: input_value,
                owner: derive_address(&secrets[tx][k]),
                spend_secret: secrets[tx][k].clone(),
                valid: true,
            })
            .collect();
        let total_in = input_value * SWEEP_INPUTS as u64;
        let mut body = TxBody {
            shape: TxShape::Sweep25x2,
            epoch_anchor: [0x42; 32],
            fee: 0,
            inputs,
            outputs: vec![
                TxOutput {
                    slot_index: out_slot(tx, 0) as u32,
                    value: total_in / 2,
                    owner: derive_address(&secrets[tx][0]),
                    valid: true,
                },
                TxOutput {
                    slot_index: out_slot(tx, 1) as u32,
                    value: total_in - total_in / 2,
                    owner: derive_address(&secrets[tx][1]),
                    valid: true,
                },
            ],
            is_coinbase: false,
        };
        let required_fee =
            required_fee_for_tx_body(&body, parent.active_slot_count, parent.log_slots);
        body.fee = required_fee as u128;
        let spendable = total_in - required_fee;
        body.outputs[0].value = spendable / 2;
        body.outputs[1].value = spendable - spendable / 2;
        bodies.push(body);
    }
    let txs: Vec<Transaction> = bodies.iter().cloned().map(tx_from_body).collect();

    let parent_cache = {
        let mut tmp = start_state.clone();
        tmp.exact_sparse_cache().unwrap()
    };
    let claims: Vec<_> = bodies
        .iter()
        .map(|body| noid_tx::compute_claims_commitment(&body.inputs, &body.outputs))
        .collect();
    let surface = build_exact_action_surface(&start_state.state, &bodies, &claims)
        .expect("exact action surface");
    let state_transition = build_exact_state_transition_proof(
        &parent_cache,
        &surface,
        &start_state.reuse_guard,
        parent.height + 1,
    )
    .expect("exact proof");

    let mut child_state = start_state.clone();
    for body in &bodies {
        apply_tx(&mut child_state, body).expect("native tx apply");
    }
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
    header.nonce = bench_pow_nonce(&header);
    let block = Block {
        header,
        transactions: txs,
    };
    let block_proof = BlockProof::minimal(
        parent.state_root,
        block.header.state_root,
        n as u32,
        state_transition,
    );
    let auth_sidecar = BlockAuthSidecar {
        tx_auth: bodies.iter().map(auth_proof_for_body).collect(),
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
        FullAcceptedBlockBatchWitness { items: vec![item] },
    )
}

// ---------------------------------------------------------------------------
// Component replay with counting channels. Mirrors the call structure of
// noid_recursive::block_certificate_backend / checkpoint.
// ---------------------------------------------------------------------------

fn replay_components(
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &FullAcceptedBlockBatchProofComponents,
    proof: &RetainedFullAcceptedBlockBatchProof,
) -> Vec<Row> {
    let mut rows = Vec::new();

    {
        let mut ch = CountingChannel::new();
        let ok = verify_accepted_claim_hash_killshot(
            &proof.accepted_claim_hash,
            &components.component_inputs.accepted_claim_hash_inputs,
            &mut ch,
        )
        .is_some();
        assert!(ok, "accepted_claim_hash verifier rejected");
        rows.push(Row {
            name: "accepted_claim_hash".into(),
            stats: ch.stats(),
            proof_bytes: proof.accepted_claim_hash.byte_len(),
            note: format!("claims={}", components.component_inputs.accepted_claim_hash_inputs.len()),
        });
    }

    if let Some(tx_body_proof) = proof.tx_body_standard.as_ref() {
        let mut ch = CountingChannel::new();
        let ok = verify_block_spine_killshot(
            tx_body_proof,
            components.component_inputs.tx_body_standard_inputs.len(),
            &components.component_inputs.tx_body_standard_hashes,
            &mut ch,
        )
        .is_some();
        assert!(ok, "standard tx-body spine verifier rejected");
        rows.push(Row {
            name: "tx_body_standard_spine".into(),
            stats: ch.stats(),
            proof_bytes: tx_body_proof.byte_len(),
            note: format!("txs={}", components.component_inputs.tx_body_standard_inputs.len()),
        });
    }

    if let Some(sweep_proof) = proof.tx_body_sweep.as_ref() {
        let mut ch = CountingChannel::new();
        let ok = verify_sweep_block_spine_killshot(
            sweep_proof,
            components.component_inputs.tx_body_sweep_inputs.len(),
            &components.component_inputs.tx_body_sweep_hashes,
            &mut ch,
        )
        .is_some();
        assert!(ok, "sweep tx-body spine verifier rejected");
        rows.push(Row {
            name: "tx_body_sweep_spine".into(),
            stats: ch.stats(),
            proof_bytes: sweep_proof.byte_len(),
            note: format!("sweeps={}", components.component_inputs.tx_body_sweep_inputs.len()),
        });
    }

    if let Some(tx_root_proof) = proof.tx_root.as_ref() {
        let circuit = MerkleCircuit::build();
        let mut ch = CountingChannel::new();
        let ok = verify_batched_merkle_killshot(
            &circuit,
            tx_root_proof,
            &components.component_inputs.tx_root_inputs,
            &mut ch,
        )
        .is_some();
        assert!(ok, "tx-root merkle verifier rejected");
        rows.push(Row {
            name: "tx_root_merkle".into(),
            stats: ch.stats(),
            proof_bytes: tx_root_proof.byte_len(&components.component_inputs.tx_root_inputs),
            note: format!(
                "paths={} max_depth={}",
                components.component_inputs.tx_root_inputs.len(),
                MAX_MERKLE_DEPTH
            ),
        });
    }

    for (index, (input, witness)) in components
        .component_inputs.authorization_inputs
        .iter()
        .zip(components.component_inputs.authorization_witnesses.iter())
        .enumerate()
    {
        let circuit = OwnerAuthCircuit::build(input.public.layout);
        let mut ch = CountingChannel::new();
        init_owner_auth_gkr_channel(&mut ch);
        let ok = verify_owner_auth_killshot(witness, &circuit, &input.public, &mut ch).is_some();
        assert!(ok, "owner-auth verifier rejected (tx {index})");
        rows.push(Row {
            name: format!("owner_auth[{index}]"),
            stats: ch.stats(),
            proof_bytes: 0,
            note: format!("tx_index={}", input.tx_index),
        });
    }

    {
        let witness = &components.component_inputs.accepted_claim_witness;
        let padded_blocks = witness.headers.len();
        let header_inputs = header_hash_proof_inputs(&witness.headers);
        let chain_inputs =
            chain_accumulator_proof_inputs(start_accumulator, witness, end_accumulator);

        let mut ch = CountingChannel::new();
        let ok = verify_header_hash_killshot_padded(
            &proof.checkpoint_poseidon.header_hash,
            &header_inputs,
            padded_blocks,
            &mut ch,
        )
        .is_some();
        assert!(ok, "checkpoint header-hash verifier rejected");
        rows.push(Row {
            name: "checkpoint_header_hash".into(),
            stats: ch.stats(),
            proof_bytes: proof.checkpoint_poseidon.header_hash.byte_len(),
            note: format!("blocks={padded_blocks}"),
        });

        let mut ch = CountingChannel::new();
        let ok = verify_chain_accumulator_killshot_padded(
            &proof.checkpoint_poseidon.chain_accumulator,
            &chain_inputs,
            padded_blocks,
            &mut ch,
        )
        .is_some();
        assert!(ok, "checkpoint chain-accumulator verifier rejected");
        rows.push(Row {
            name: "checkpoint_chain_accumulator".into(),
            stats: ch.stats(),
            proof_bytes: proof.checkpoint_poseidon.chain_accumulator.byte_len(),
            note: format!("blocks={padded_blocks}"),
        });
    }

    for (index, (inputs, es_proof)) in components
        .component_inputs.exact_state_killshot_inputs
        .iter()
        .zip(proof.exact_state.iter())
        .enumerate()
    {
        {
            let mut ch = CountingChannel::new();
            let ok =
                verify_batched_slot_leaf_killshot(&es_proof.slot_leaves, &inputs.slot_leaves, &mut ch)
                    .is_some();
            assert!(ok, "slot-leaf verifier rejected (block {index})");
            rows.push(Row {
                name: format!("exact_state[{index}].slot_leaves"),
                stats: ch.stats(),
                proof_bytes: es_proof.slot_leaves.byte_len(),
                note: format!("leaves={}", inputs.slot_leaves.len()),
            });
        }
        {
            let circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
            let mut ch = CountingChannel::new();
            let ok = verify_batched_merkle_killshot(
                &circuit,
                &es_proof.state_paths,
                &inputs.state_paths,
                &mut ch,
            )
            .is_some();
            assert!(ok, "state-path merkle verifier rejected (block {index})");
            rows.push(Row {
                name: format!("exact_state[{index}].state_paths"),
                stats: ch.stats(),
                proof_bytes: es_proof.state_paths.byte_len(&inputs.state_paths),
                note: format!("paths={}", inputs.state_paths.len()),
            });
        }
        if let (Some(bucket_inputs), Some(bucket_proof)) =
            (&inputs.guard_buckets, &es_proof.guard_buckets)
        {
            let mut ch = CountingChannel::new();
            let ok =
                verify_batched_guard_bucket_killshot(bucket_proof, bucket_inputs, &mut ch).is_some();
            assert!(ok, "guard-bucket verifier rejected (block {index})");
            rows.push(Row {
                name: format!("exact_state[{index}].guard_buckets"),
                stats: ch.stats(),
                proof_bytes: bucket_proof.byte_len(),
                note: format!("spends={}", bucket_inputs.spent_slots.len()),
            });
        }
        if let (Some(path_inputs), Some(path_proof)) = (&inputs.guard_paths, &es_proof.guard_paths) {
            let circuit = MerkleCircuit::build_with_tag(TAG_RGDNODE);
            let mut ch = CountingChannel::new();
            let ok =
                verify_batched_merkle_killshot(&circuit, path_proof, path_inputs, &mut ch).is_some();
            assert!(ok, "guard-path merkle verifier rejected (block {index})");
            rows.push(Row {
                name: format!("exact_state[{index}].guard_paths"),
                stats: ch.stats(),
                proof_bytes: path_proof.byte_len(path_inputs),
                note: format!("paths={}", path_inputs.len()),
            });
        }
        {
            let mut ch = CountingChannel::new();
            let ok = verify_batched_state_root_killshot(
                &es_proof.state_roots,
                &inputs.state_roots,
                &mut ch,
            )
            .is_some();
            assert!(ok, "state-root verifier rejected (block {index})");
            rows.push(Row {
                name: format!("exact_state[{index}].state_roots"),
                stats: ch.stats(),
                proof_bytes: es_proof.state_roots.byte_len(),
                note: format!("roots={}", inputs.state_roots.len()),
            });
        }
    }

    rows
}

fn print_rows(label: &str, rows: &[Row]) -> FsStats {
    println!("\n  [K] killshot verifier transcripts — {label}");
    println!(
        "    {:<34} {:>8} {:>8} {:>7} {:>10}  note",
        "component", "absorbs", "squeezes", "perms", "proof"
    );
    let mut total = FsStats::default();
    let mut total_bytes = 0usize;
    for row in rows {
        total.add(row.stats);
        total_bytes += row.proof_bytes;
        println!(
            "    {:<34} {:>8} {:>8} {:>7} {:>10}  {}",
            row.name,
            row.stats.absorbs,
            row.stats.squeezes,
            row.stats.perms,
            fmt_bytes(row.proof_bytes),
            row.note
        );
    }
    println!(
        "    {:<34} {:>8} {:>8} {:>7} {:>10}",
        "TOTAL",
        total.absorbs,
        total.squeezes,
        total.perms,
        fmt_bytes(total_bytes)
    );
    total
}

fn print_data_volumes(components: &FullAcceptedBlockBatchProofComponents) {
    let trace_ops: usize = components
        .component_inputs.authorization_traces
        .iter()
        .map(|trace| trace.transcript.len())
        .sum();
    let exact_state_bytes: usize = bincode::serialized_size(&components.component_inputs.exact_state_killshot_inputs)
        .expect("exact-state inputs serialize") as usize;
    let spine_bytes: usize = bincode::serialized_size(&components.component_inputs.tx_body_standard_inputs)
        .expect("spine inputs serialize") as usize
        + bincode::serialized_size(&components.component_inputs.tx_body_sweep_inputs)
            .expect("sweep inputs serialize") as usize;
    println!("  [D] discharge data volumes (per block batch)");
    println!(
        "    accepted_claims={} std_txs={} sweep_txs={} tx_root_paths={} auth_witnesses={} auth_trace_ops={}",
        components.component_inputs.accepted_claim_hash_inputs.len(),
        components.component_inputs.tx_body_standard_inputs.len(),
        components.component_inputs.tx_body_sweep_inputs.len(),
        components.component_inputs.tx_root_inputs.len(),
        components.component_inputs.authorization_witnesses.len(),
        trace_ops,
    );
    for (index, es) in components.component_inputs.exact_state_killshot_inputs.iter().enumerate() {
        println!(
            "    exact_state[{index}]: slot_leaves={} state_paths={} guard_buckets={} guard_paths={} state_roots={}",
            es.slot_leaves.len(),
            es.state_paths.len(),
            es.guard_buckets.as_ref().map_or(0, |u| u.spent_slots.len()),
            es.guard_paths.as_ref().map_or(0, Vec::len),
            es.state_roots.len(),
        );
    }
    println!(
        "    serialized: exact_state_inputs={} spine_inputs={}  (~F128 elems: {})",
        fmt_bytes(exact_state_bytes),
        fmt_bytes(spine_bytes),
        (exact_state_bytes + spine_bytes) / 16,
    );
}

// ---------------------------------------------------------------------------
// Coarse replay-phase probe: times the public pieces of the
// AcceptBlock replay on the same fixture to rank where the replay half of
// native_verify goes. This is subtraction-based ranking, not a call-structure
// shadow: `exact+apply+decode` is accept minus the measured pieces and covers
// proof/sidecar decode, exact surface build, exact-state verify and apply.
// ---------------------------------------------------------------------------

fn profile_replay_phases(
    start_consensus: &RecursiveConsensusState,
    start_parent: &BlockHeader,
    start_state: &ChainState,
    witness: &FullAcceptedBlockBatchWitness,
    components: &FullAcceptedBlockBatchProofComponents,
    native_replay_time: Duration,
) {
    assert_eq!(
        witness.items.len(),
        1,
        "replay phase probe expects single-block fixtures"
    );
    let item = &witness.items[0];
    let prev_timestamps = start_consensus.timestamps().to_vec();
    let prev_active_counts = start_consensus.active_counts().to_vec();
    let anchor = AnchorInfo {
        anchor_height: start_consensus.asert_anchor_height,
        anchor_timestamp: start_consensus.asert_anchor_timestamp,
        anchor_target: start_consensus.asert_anchor_target,
    };

    let (state_clone_time, probe_state) = time_once(|| start_state.clone());
    drop(probe_state);
    let (accept_time, _) = time_once(|| {
        let mut state = start_state.clone();
        accept_block_timeless_with_artifacts(
            &item.block,
            &item.block_proof_bytes,
            &item.block_auth_sidecar_bytes,
            start_parent,
            &prev_timestamps,
            &prev_active_counts,
            &anchor,
            &mut state,
        )
        .expect("replay phase probe: accept replays")
    });
    let (checks_time, _) = time_once(|| {
        validate_block_checks_timeless(
            &item.block,
            start_parent,
            &prev_timestamps,
            &prev_active_counts,
            &anchor,
        )
        .expect("replay phase probe: consensus checks pass")
    });
    let (tx_root_time, _) = time_once(|| compute_tx_root(&item.block.transactions));
    let (public_logic_time, _) = time_once(|| {
        for tx in item
            .block
            .transactions
            .iter()
            .filter(|tx| !tx.body.is_coinbase)
        {
            validate_public_tx_logic(&tx.body).expect("replay phase probe: public tx logic passes");
        }
    });
    let auth_time = if item.block_auth_sidecar_bytes.is_empty() {
        Duration::ZERO
    } else {
        let sidecar: BlockAuthSidecar = bincode::deserialize(&item.block_auth_sidecar_bytes)
            .expect("replay phase probe: sidecar decodes");
        let (auth_time, _) = time_once(|| {
            validate_block_authorizations_with_output(
                &item.block,
                &sidecar,
                &OwnerAuthAuthorizationVerifier,
            )
            .expect("replay phase probe: authorization batch verifies")
        });
        auth_time
    };
    let (cert_prove_time, _) = time_once(|| {
        for statement in &components
            .component_inputs
            .accepted_block_certificate_statements
        {
            prove_accepted_block_certificate_receipt_projection_proof(statement)
                .expect("replay phase probe: certificate projection proves");
        }
    });

    let rest = accept_time
        .saturating_sub(state_clone_time)
        .saturating_sub(checks_time)
        .saturating_sub(tx_root_time)
        .saturating_sub(public_logic_time)
        .saturating_sub(auth_time);
    let batch_extras = native_replay_time.saturating_sub(accept_time);
    println!("  replay phase probe (single block):");
    println!(
        "    accept={} [state_clone={} checks={} tx_root={} public_logic={} auth={} exact+apply+decode={}]",
        fmt_ms(accept_time),
        fmt_ms(state_clone_time),
        fmt_ms(checks_time),
        fmt_ms(tx_root_time),
        fmt_ms(public_logic_time),
        fmt_ms(auth_time),
        fmt_ms(rest),
    );
    println!(
        "    batch_extras={} (claims/receipts/certificates/claim-batch; cert_prove alone={})",
        fmt_ms(batch_extras),
        fmt_ms(cert_prove_time),
    );
}

// ---------------------------------------------------------------------------
// Component-leaf probe: times the dominant killshot leaves
// of `verify_accepted_block_batch_components` in isolation. The component
// verify runs these on a parallel join tree, so its wall time is bounded from
// below by the slowest single leaf; this probe identifies that leaf.
// ---------------------------------------------------------------------------

fn profile_component_leaves(
    components: &FullAcceptedBlockBatchProofComponents,
    proof: &RetainedFullAcceptedBlockBatchProof,
) {
    let (owner_auth_total, _) = time_once(|| {
        for (input, witness) in components
            .component_inputs
            .authorization_inputs
            .iter()
            .zip(components.component_inputs.authorization_witnesses.iter())
        {
            let circuit = OwnerAuthCircuit::build(input.public.layout);
            let mut ch = owner_auth_gkr_channel();
            verify_owner_auth_killshot(witness, &circuit, &input.public, &mut ch)
                .expect("component leaf probe: owner auth verifies");
        }
    });

    let mut state_paths_total = Duration::ZERO;
    for (inputs, es_proof) in components
        .component_inputs
        .exact_state_killshot_inputs
        .iter()
        .zip(proof.exact_state.iter())
    {
        let circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
        let mut ch = Poseidon2bChannel::new();
        let (path_time, _) = time_once(|| {
            verify_batched_merkle_killshot(&circuit, &es_proof.state_paths, &inputs.state_paths, &mut ch)
                .expect("component leaf probe: state-path merkle verifies")
        });
        state_paths_total += path_time;
    }

    println!(
        "  component leaf probe: owner_auth_seq_total={} (txs={}) state_paths={}",
        fmt_ms(owner_auth_total),
        components.component_inputs.authorization_inputs.len(),
        fmt_ms(state_paths_total),
    );
}

fn run_case(label: &str, fixture: FullBatchFixture) {
    println!("\n=== case: {label} ===");
    let (start_consensus, start_accumulator, start_parent, start_state, witness) = fixture;

    let (prove_time, proved) = time_once(|| {
        prove_retained_full_accepted_block_batch_proof(
            &start_consensus,
            &start_accumulator,
            &start_parent,
            &start_state,
            &witness,
        )
        .expect("retained batch proves")
    });
    let (output, proof) = proved;
    let components = &output.proof_components;
    let end_accumulator = output.accepted_claim_batch.accumulator.clone();

    let (verify_time, verified) = time_once(|| {
        verify_retained_full_accepted_block_batch_proof(
            &start_consensus,
            &start_accumulator,
            &start_parent,
            &start_state,
            &witness,
            &proof,
        )
        .is_ok()
    });
    assert!(verified, "production verify_retained path rejected the fixture");

    // Phase split of the full verify: native AcceptBlock replay vs killshot
    // component verification.
    let (native_replay_time, _) = time_once(|| {
        verify_full_accepted_block_batch_native(
            &start_consensus,
            &start_accumulator,
            &start_parent,
            &start_state,
            &witness,
        )
        .expect("native replay verifies")
    });
    let (components_time, components_ok) = time_once(|| {
        noid_recursive::block_certificate_backend::verify_accepted_block_batch_components(
            &start_consensus,
            &start_accumulator,
            &end_accumulator,
            &components.component_inputs,
            &proof,
        )
        .is_ok()
    });
    assert!(components_ok, "component verify rejected the fixture");

    println!(
        "  blocks={} prove={} native_verify={} (replay={} + components={}) retained_proof={}",
        witness.items.len(),
        fmt_ms(prove_time),
        fmt_ms(verify_time),
        fmt_ms(native_replay_time),
        fmt_ms(components_time),
        fmt_bytes(proof.byte_len(&components.component_inputs)),
    );

    profile_replay_phases(
        &start_consensus,
        &start_parent,
        &start_state,
        &witness,
        components,
        native_replay_time,
    );
    profile_component_leaves(components, &proof);

    let rows = replay_components(&start_accumulator, &end_accumulator, components, &proof);
    let total = print_rows(label, &rows);
    print_data_volumes(components);

    let fs_constraints = total.perms as usize * PERM_TRACE_CONSTRAINTS;
    let algebra_lo = total.absorbs as usize;
    let algebra_hi = 2 * total.absorbs as usize;
    println!("  [K] F128-trace estimate (option A, perm={PERM_TRACE_CONSTRAINTS}):");
    println!(
        "    fs = {} perms x {} = {} constraints; round algebra ~ [{}, {}]; [K] total ~ [{}, {}] (~2^{:.1})",
        total.perms,
        PERM_TRACE_CONSTRAINTS,
        fs_constraints,
        algebra_lo,
        algebra_hi,
        fs_constraints + algebra_lo,
        fs_constraints + algebra_hi,
        ((fs_constraints + algebra_hi) as f64).log2(),
    );
    let _ = std::io::stdout().flush();
}

fn main() {
    println!("tier1_shape_stats — verifier-replay shape statistics");
    println!("counts are exact production-transcript replays; estimates use the F128-trace cost model");
    // NOID_SHAPE_CASE=<substring> runs only matching cases (iteration aid).
    let case_filter = std::env::var("NOID_SHAPE_CASE").ok();
    let wants = |label: &str| {
        case_filter
            .as_deref()
            .is_none_or(|filter| label.contains(filter))
    };
    if wants("coinbase_only_1_block") {
        run_case("coinbase_only_1_block", coinbase_only_batch());
    }
    if wants("user_txs_1") {
        run_case("user_txs_1", user_txs_block_batch(1));
    }
    if wants("user_txs_4") {
        run_case("user_txs_4", user_txs_block_batch(4));
    }
    if wants("user_txs_16") {
        run_case("user_txs_16", user_txs_block_batch(16));
    }
    if wants("sweep_txs_1") {
        run_case("sweep_txs_1", sweep_txs_block_batch(1));
    }
    if wants("sweep_txs_4") {
        run_case("sweep_txs_4", sweep_txs_block_batch(4));
    }
    // Consensus max-shape case (255 standard txs): minutes of runtime, so it
    // only runs when explicitly requested.
    if std::env::var_os("NOID_SHAPE_MAX_STD").is_some() && wants("user_txs_255") {
        run_case("user_txs_255", user_txs_block_batch(255));
    }
}
