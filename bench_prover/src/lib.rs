// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared benchmark fixtures for the final Tx8x2 transaction path.
//!
//! There is one transaction form, one owner per transaction, and one wallet
//! authorization geometry. Benchmark secrets stay outside canonical bodies;
//! transaction ids are always derived through [`TxBody::txid`].

use std::time::{Duration, Instant};

use noid_block::{
    build_exact_state_transition_proof, verify_exact_state_transition, BlockAuthSidecar,
    BlockProof, ExactStateTransitionInputs,
};
use noid_chain::exact_state_hash::slot_leaf_hash;
use noid_chain::sparse_merkle::reconstruct_root;
use noid_chain::state::ChainState;
use noid_chain::{Block, BlockHeader, SlotValue};
use noid_core::Block128;
use noid_gkr::zk_authorization::ZkAuthorizationProof;
use noid_gkr::{
    prove_wallet_authorization, verify_wallet_authorization_proof, OwnerAuthWitness,
    WalletAuthorizationBundle,
};
use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret, TxBodyHash};
use noid_tx::{output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

pub const BENCH_LOG_SLOTS: u32 = 24;
pub const B255_EIGHT_INPUT_TXS: usize = 85;
pub const B255_TWO_INPUT_TXS: usize = 170;

#[derive(Clone)]
pub struct BenchScenario {
    pub label: &'static str,
    pub desc: String,
    pub body: TxBody,
    /// Public deterministic fixture seed used to recreate a fresh, consuming
    /// wallet-local proving authority for each benchmark sample.  Keeping the
    /// seed instead of a `SpendSecret` preserves the production type's
    /// non-cloneable/non-exposing contract.
    pub spend_secret_seed: u128,
}

impl BenchScenario {
    pub fn spend_secret(&self) -> SpendSecret {
        mk_secret(self.spend_secret_seed)
    }
}

#[derive(Clone)]
pub struct MinimalTxFixture {
    pub scenario: BenchScenario,
    pub auth_proof: ZkAuthorizationProof,
}

pub struct WalletBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof: ZkAuthorizationProof,
}

pub struct FullBlockProofBench {
    pub state_seed_time: Duration,
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof_bytes: usize,
    pub auth_sidecar_bytes: usize,
    pub state_transition_bytes: usize,
    pub proof: BlockProof,
    pub auth_sidecar: BlockAuthSidecar,
    pub start_accumulator: noid_recursive::ChainAccumulator,
    pub end_accumulator: noid_recursive::ChainAccumulator,
}

/// One consensus-accepted user-bearing block and every object needed to feed
/// the production recursive block-slot assembly.
pub struct AcceptedSingleBlockFixture {
    pub start_consensus: noid_recursive::RecursiveConsensusState,
    pub start_accumulator: noid_recursive::ChainAccumulator,
    pub parent: BlockHeader,
    pub pre_state: ChainState,
    pub witness: noid_block::FullAcceptedBlockBatchWitness,
    pub output: noid_block::FullAcceptedBlockBatchOutput,
    pub component_proof: noid_block::RetainedFullAcceptedBlockBatchProof,
}

/// A fully replayed accepted block with all production component statements,
/// but without the expensive retained component proof. This split keeps the
/// B255 truth fixture independent from the m22+ prover roofline measurement.
pub struct AcceptedNativeBlockFixture {
    pub start_consensus: noid_recursive::RecursiveConsensusState,
    pub start_accumulator: noid_recursive::ChainAccumulator,
    pub parent: BlockHeader,
    pub pre_state: ChainState,
    pub witness: noid_block::FullAcceptedBlockBatchWitness,
    pub output: noid_block::FullAcceptedBlockBatchOutput,
}

struct AcceptedBlockSeed {
    start_consensus: noid_recursive::RecursiveConsensusState,
    start_accumulator: noid_recursive::ChainAccumulator,
    parent: BlockHeader,
    pre_state: ChainState,
    witness: noid_block::FullAcceptedBlockBatchWitness,
}

pub fn fmt_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1_000.0;
    if ms >= 1_000.0 {
        format!("{:>8.2} s ", ms / 1_000.0)
    } else {
        format!("{:>8.2} ms", ms)
    }
}

pub fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:>8.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:>8.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:>8} B ", bytes)
    }
}

pub fn median(mut xs: Vec<Duration>) -> Duration {
    xs.sort();
    xs[xs.len() / 2]
}

pub fn time_once<F, R>(f: F) -> (Duration, R)
where
    F: FnOnce() -> R,
{
    let started = Instant::now();
    let value = f();
    (started.elapsed(), value)
}

pub fn time_median<F>(samples: usize, mut f: F) -> Duration
where
    F: FnMut(),
{
    assert!(samples > 0);
    let mut timings = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        f();
        timings.push(started.elapsed());
    }
    median(timings)
}

/// Representative FieldR1cs shape used by field-prover microbenchmarks.
pub fn poseidon_chain_field_instance(
    chain: usize,
) -> (
    noid_ivc_prover::field_r1cs::FieldR1cs,
    Vec<noid_ivc_prover::field::F128>,
) {
    use noid_ivc_prover::field_circuit::{flat_const, poseidon2b_permute, LinExpr};
    use noid_poseidon2b::native::permutation::{Poseidon2bPermutation, STATE_SIZE};
    use noid_recursive::acceptance::trace::FieldR1csBuilder;

    let seed: [Block128; STATE_SIZE] =
        std::array::from_fn(|i| Block128(0x1234_5678_9abc_def0 + i as u128));
    let mut expected = seed;
    for _ in 0..chain {
        Poseidon2bPermutation.permute_mut(&mut expected);
    }
    let mut builder = FieldR1csBuilder::new();
    let mut state: [LinExpr; STATE_SIZE] =
        std::array::from_fn(|i| LinExpr::from_wire(builder.alloc_f128(flat_const(seed[i].0))));
    for _ in 0..chain {
        state = poseidon2b_permute(&mut builder, state);
    }
    for lane in &state {
        let value = lane.eval(builder.values());
        builder.pin_f128(lane, value);
    }
    builder.build()
}

pub fn mk_secret(seed: u128) -> SpendSecret {
    let lo = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_A5A5_A5A5_A5A5;
    let hi = seed.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A;
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&lo.to_le_bytes());
    bytes[16..].copy_from_slice(&hi.to_le_bytes());
    SpendSecret::from_bytes(bytes)
}

/// Build one canonical Tx8x2 scenario with `1..=8` live inputs and `1..=2`
/// live outputs. All inputs share the address derived from one secret.
pub fn tx8x2_scenario(
    label: &'static str,
    n_inputs: usize,
    n_outputs: usize,
    slot_base: u32,
    seed: u128,
) -> BenchScenario {
    assert!((1..=TX_INPUTS).contains(&n_inputs));
    assert!((1..=TX_OUTPUTS).contains(&n_outputs));

    let spend_secret = mk_secret(seed);
    let input_owner = derive_address(&spend_secret);
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    let mut input_sum = 0u64;
    let mut validity_bitmap = 0u16;
    for (index, input) in inputs.iter_mut().enumerate().take(n_inputs) {
        let amount = 100_000 + (n_inputs - index) as u64 * 10_000;
        input_sum = input_sum.checked_add(amount).expect("bench input sum");
        *input = TxInput {
            slot_index: slot_base + index as u32,
            amount,
            creation_id: 0,
        };
        validity_bitmap |= 1 << index;
    }

    let fee = 5_000 + (n_inputs + n_outputs) as u64 * 500;
    let spendable = input_sum.checked_sub(fee).expect("bench fee fits inputs");
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    let mut remaining = spendable;
    for (index, output) in outputs.iter_mut().enumerate().take(n_outputs) {
        let amount = if index + 1 == n_outputs {
            remaining
        } else {
            spendable / n_outputs as u64
        };
        remaining -= amount;
        *output = TxOutput {
            slot_index: slot_base + 1_000 + index as u32,
            amount,
            owner: derive_address(&mk_secret(seed + 0x10_000 + index as u128)),
        };
        validity_bitmap |= output_bitmap_bit(index);
    }

    let body = TxBody {
        epoch_anchor: [0xAA; 32],
        fee,
        input_owner,
        inputs,
        outputs,
        validity_bitmap,
        is_coinbase: false,
    };
    body.validate_canonical()
        .expect("canonical Tx8x2 benchmark body");

    BenchScenario {
        label,
        desc: format!("Tx8x2: {n_inputs} inputs / {n_outputs} outputs"),
        body,
        spend_secret_seed: seed,
    }
}

/// Build the legal saturation body set for one proof-class tier.
///
/// B8/B32/B64 use eight inputs per body.  B255 uses the canonical consensus
/// saturation distribution `85 * 8 + 170 * 2 = 1020` and a depth-24
/// maximally dispersed touched set spanning all 256 state segments.
pub fn legal_block_scenarios(
    label: &'static str,
    user_txs: usize,
    seed_base: u128,
) -> Vec<BenchScenario> {
    assert!(
        noid_chain::consensus::params::USER_TX_CLASS_TIERS.contains(&user_txs),
        "fixture count must be a canonical proof tier"
    );
    if user_txs == noid_chain::consensus::params::BLOCK_MAX_USER_TXS {
        return b255_saturation_scenarios(label, seed_base);
    }
    (0..user_txs)
        .map(|index| {
            tx8x2_scenario(
                label,
                TX_INPUTS,
                TX_OUTPUTS,
                (index * 2_048) as u32,
                seed_base + index as u128,
            )
        })
        .collect()
}

/// Legal 255-real saturation foundation for the feasibility fixture.
///
/// The returned bodies have 1020 distinct, non-zero creation-id inputs, 510
/// outputs, varied owners, sparse high input bitmap positions, and 1530 unique
/// user-action slots. Together with the benchmark coinbase output they attain
/// the depth-24, 256-segment canonical frontier maximum.
pub fn b255_saturation_scenarios(label: &'static str, seed_base: u128) -> Vec<BenchScenario> {
    const INPUT_PAIRS: [[usize; 2]; 8] = [
        [0, 7],
        [1, 6],
        [2, 5],
        [3, 4],
        [0, 5],
        [1, 7],
        [2, 6],
        [3, 7],
    ];

    let coinbase_slot = (1u32 << BENCH_LOG_SLOTS) - 1;
    let mut all_touched = maximally_dispersed_b255_touched_slots();
    let coinbase_pos = all_touched
        .iter()
        .position(|slot| *slot == coinbase_slot)
        .expect("dispersed set reserves the canonical benchmark coinbase slot");
    all_touched.swap_remove(coinbase_pos);
    assert_eq!(
        all_touched.len(),
        noid_chain::consensus::params::BLOCK_MAX_USER_ACTIONS
    );

    let mut slot_cursor = 0usize;
    let mut next_creation_id = 1u64;
    let mut scenarios = Vec::with_capacity(noid_chain::consensus::params::BLOCK_MAX_USER_TXS);
    for tx_index in 0..noid_chain::consensus::params::BLOCK_MAX_USER_TXS {
        let n_inputs = if tx_index < B255_EIGHT_INPUT_TXS {
            TX_INPUTS
        } else {
            2
        };
        let input_positions: Vec<_> = if n_inputs == TX_INPUTS {
            (0..TX_INPUTS).collect()
        } else {
            INPUT_PAIRS[(tx_index - B255_EIGHT_INPUT_TXS) % INPUT_PAIRS.len()].to_vec()
        };
        let input_slots = &all_touched[slot_cursor..slot_cursor + n_inputs];
        slot_cursor += n_inputs;
        let output_slots: [u32; TX_OUTPUTS] = all_touched[slot_cursor..slot_cursor + TX_OUTPUTS]
            .try_into()
            .expect("two output slots");
        slot_cursor += TX_OUTPUTS;

        scenarios.push(tx8x2_scenario_with_layout(
            label,
            &input_positions,
            input_slots,
            output_slots,
            next_creation_id,
            seed_base + tx_index as u128,
        ));
        next_creation_id += n_inputs as u64;
    }

    assert_eq!(slot_cursor, all_touched.len());
    assert_eq!(next_creation_id - 1, 1_020);
    assert_eq!(scenarios.len(), 255);
    scenarios
}

fn maximally_dispersed_b255_touched_slots() -> Vec<u32> {
    let mut slots = Vec::with_capacity(noid_chain::consensus::params::BLOCK_MAX_ACTIONS);
    for segment_rank in 0..noid_chain::consensus::params::BLOCK_MAX_DISTINCT_SEGMENTS {
        // All 256 production segments are present. Bit reversal keeps the
        // fixture prefix dispersed too, which is useful while inspecting it.
        let segment = (segment_rank as u32).reverse_bits() >> 24;
        let local_count = if segment_rank < 251 { 6 } else { 5 };
        for local_rank in 0..local_count {
            let mut local = (local_rank as u32).reverse_bits() >> 16;
            if segment == 0 || segment == u8::MAX as u32 {
                // Preserve maximum dispersion while making the canonical
                // benchmark coinbase slot one member of the set. Mirroring
                // segment zero also places 65_535 next to segment one's
                // 65_536, so the truth fixture exercises adjacent (but still
                // distinct) spend/mint slots across a segment boundary.
                local ^= u16::MAX as u32;
            }
            slots.push((segment << noid_chain::consensus::params::LOG_SEGMENT_SIZE) | local);
        }
    }
    assert_eq!(
        slots.len(),
        noid_chain::consensus::params::BLOCK_MAX_ACTIONS
    );
    slots
}

fn tx8x2_scenario_with_layout(
    label: &'static str,
    input_positions: &[usize],
    input_slots: &[u32],
    output_slots: [u32; TX_OUTPUTS],
    first_creation_id: u64,
    seed: u128,
) -> BenchScenario {
    assert_eq!(input_positions.len(), input_slots.len());
    assert!((1..=TX_INPUTS).contains(&input_slots.len()));

    let spend_secret = mk_secret(seed);
    let input_owner = derive_address(&spend_secret);
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    let mut validity_bitmap = 0u16;
    let mut input_sum = 0u64;
    for (logical_index, (&position, &slot_index)) in
        input_positions.iter().zip(input_slots.iter()).enumerate()
    {
        assert!(position < TX_INPUTS);
        assert_eq!(inputs[position], TxInput::dummy());
        let amount = 1_000_000 + (logical_index as u64 + 1) * 10_000 + seed as u64 % 997;
        input_sum = input_sum.checked_add(amount).expect("saturation input sum");
        inputs[position] = TxInput {
            slot_index,
            amount,
            creation_id: first_creation_id + logical_index as u64,
        };
        validity_bitmap |= 1 << position;
    }

    let fee = noid_chain::consensus::fees::fee_breakdown(
        input_slots.len() as u64,
        TX_OUTPUTS as u64,
        noid_chain::consensus::params::BLOCK_MAX_LIVE_INPUTS as u64,
        BENCH_LOG_SLOTS,
    )
    .required_total;
    let spendable = input_sum
        .checked_sub(fee)
        .expect("saturation fee fits inputs");
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    let first_output = spendable / 2;
    outputs[0] = TxOutput {
        slot_index: output_slots[0],
        amount: first_output,
        owner: derive_address(&mk_secret(seed + 0x10_000)),
    };
    outputs[1] = TxOutput {
        slot_index: output_slots[1],
        amount: spendable - first_output,
        owner: derive_address(&mk_secret(seed + 0x20_000)),
    };
    validity_bitmap |= output_bitmap_bit(0) | output_bitmap_bit(1);

    let body = TxBody {
        epoch_anchor: [0xAA; 32],
        fee,
        input_owner,
        inputs,
        outputs,
        validity_bitmap,
        is_coinbase: false,
    };
    body.validate_canonical()
        .expect("canonical B255 saturation body");
    BenchScenario {
        label,
        desc: format!(
            "B255 saturation Tx8x2: {} inputs / {} outputs",
            input_slots.len(),
            TX_OUTPUTS
        ),
        body,
        spend_secret_seed: seed,
    }
}

pub fn state_shrinking_scenario(
    label: &'static str,
    n_inputs: usize,
    slot_base: u32,
    seed: u128,
) -> BenchScenario {
    let mut scenario = tx8x2_scenario(label, n_inputs, 1, slot_base, seed);
    scenario.desc = format!("Tx8x2 state shrink: {n_inputs} inputs / 1 output");
    scenario
}

pub fn minimal_tx_fixture(scenario: BenchScenario) -> MinimalTxFixture {
    let spend_secret = scenario.spend_secret();
    let proof = prove_wallet_authorization(&scenario.body, OwnerAuthWitness::new(spend_secret))
        .expect("selected witness-hiding authorization")
        .proof;
    MinimalTxFixture {
        scenario,
        auth_proof: proof,
    }
}

pub fn prove_wallet(fixture: &MinimalTxFixture, samples: usize) -> WalletBench {
    let prove_time = time_median(samples, || {
        prove_wallet_authorization(
            &fixture.scenario.body,
            OwnerAuthWitness::new(fixture.scenario.spend_secret()),
        )
        .expect("prove selected wallet authorization");
    });
    let proof = prove_wallet_authorization(
        &fixture.scenario.body,
        OwnerAuthWitness::new(fixture.scenario.spend_secret()),
    )
    .expect("prove selected wallet authorization")
    .proof;
    let verify_time = time_median(samples, || {
        verify_wallet_authorization_proof(&fixture.scenario.body, &proof)
            .expect("verify selected wallet authorization");
    });
    WalletBench {
        prove_time,
        verify_time,
        proof,
    }
}

pub fn authorization_size(proof: &ZkAuthorizationProof) -> usize {
    proof
        .to_bytes()
        .expect("encode selected authorization")
        .len()
}

pub fn wallet_bundle_size(proof: &ZkAuthorizationProof) -> usize {
    WalletAuthorizationBundle {
        proof: proof.clone(),
    }
    .to_bytes()
    .expect("encode selected wallet bundle")
    .len()
}

pub fn live_counts(body: &TxBody) -> (usize, usize) {
    (body.live_input_count(), body.live_output_count())
}

pub fn block_tx_hash_body(body: &TxBody) -> TxBodyHash {
    body.txid()
}

fn seed_state_for_bodies(bodies: &[TxBody]) -> ChainState {
    let slots: Vec<_> = bodies
        .iter()
        .flat_map(|body| {
            body.live_inputs().map(|(_, input)| {
                (
                    input.slot_index,
                    SlotValue::with_owner_fields(
                        input.amount,
                        input.creation_id,
                        body.input_owner.as_fields(),
                    ),
                )
            })
        })
        .collect();
    let alloc_counter = bodies
        .iter()
        .flat_map(TxBody::live_inputs)
        .map(|(_, input)| input.creation_id)
        .max()
        .unwrap_or(0);
    ChainState::from_sparse_utxos(BENCH_LOG_SLOTS as usize, &slots, alloc_counter)
        .expect("bench input slots form a valid sparse UTXO state")
}

fn bench_coinbase_body() -> TxBody {
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    outputs[0] = TxOutput {
        slot_index: (1u32 << BENCH_LOG_SLOTS) - 1,
        amount: 0,
        owner: Address([0xCB; 32]),
    };
    TxBody {
        epoch_anchor: [0u8; 32],
        fee: 0,
        input_owner: Address([0u8; 32]),
        inputs: [TxInput::dummy(); TX_INPUTS],
        outputs,
        validity_bitmap: output_bitmap_bit(0),
        is_coinbase: true,
    }
}

fn mine_benchmark_header(header: &BlockHeader) -> u128 {
    const CHUNK: u128 = 2_000_000;
    let mut start_nonce = 0u128;
    loop {
        if let Some(nonce) = noid_chain::consensus::pow::search_pow(header, start_nonce, CHUNK) {
            return nonce;
        }
        start_nonce = start_nonce
            .checked_add(CHUNK)
            .expect("benchmark PoW nonce space exhausted");
    }
}

/// Deterministic batched PoW search for multi-block heavy fixtures. Each batch
/// exhausts adjacent nonce ranges in parallel and returns the minimum hit, so
/// the result does not depend on Rayon scheduling.
fn mine_benchmark_header_parallel(header: &BlockHeader) -> u128 {
    use rayon::prelude::*;

    const CHUNK: u128 = 65_536;
    let lanes = rayon::current_num_threads().max(1);
    let batch_width = CHUNK
        .checked_mul(lanes as u128)
        .expect("benchmark PoW batch width");
    let mut batch_start = 0u128;
    loop {
        let hit = (0..lanes)
            .into_par_iter()
            .filter_map(|lane| {
                let start = batch_start.checked_add(CHUNK * lane as u128)?;
                noid_chain::consensus::pow::search_pow(header, start, CHUNK)
            })
            .min();
        if let Some(nonce) = hit {
            return nonce;
        }
        batch_start = batch_start
            .checked_add(batch_width)
            .expect("benchmark PoW nonce space exhausted");
    }
}

fn bench_block_from_parts(
    coinbase_body: TxBody,
    user_bodies: &[TxBody],
    proof: &BlockProof,
    pre_state: &ChainState,
) -> Block {
    let mut transactions = Vec::with_capacity(user_bodies.len() + 1);
    transactions.push(Transaction::new(coinbase_body));
    transactions.extend(user_bodies.iter().cloned().map(Transaction::new));
    let active_inputs: u64 = user_bodies
        .iter()
        .map(|body| body.live_input_count() as u64)
        .sum();
    let active_outputs: u64 = transactions
        .iter()
        .map(|tx| tx.body.live_output_count() as u64)
        .sum();
    let active_slot_count = pre_state
        .active_slot_count
        .checked_sub(active_inputs)
        .and_then(|count| count.checked_add(active_outputs))
        .expect("benchmark active counter transition");
    let alloc_counter = pre_state
        .alloc_counter
        .checked_add(active_outputs)
        .expect("benchmark allocation counter transition");
    let tx_root = noid_chain::compute_tx_root(&transactions);
    Block {
        header: BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: proof.meta.new_state_root,
            tx_root,
            timestamp: 2,
            height: 1,
            miner_address: Address([0xCB; 32]),
            nonce: 0,
            difficulty_target: [0xFF; 32],
            log_slots: BENCH_LOG_SLOTS,
            active_slot_count,
            alloc_counter,
        },
        transactions,
    }
}

fn prove_full_block_from_fixtures(
    pre_state: ChainState,
    user_bodies: Vec<TxBody>,
    tx_auth: Vec<ZkAuthorizationProof>,
) -> (
    BlockProof,
    Block,
    BlockAuthSidecar,
    ChainState,
    noid_recursive::ChainAccumulator,
    noid_recursive::ChainAccumulator,
) {
    assert_eq!(user_bodies.len(), tx_auth.len());
    let prev_state_root = pre_state.cached_state_root();
    let coinbase_body = bench_coinbase_body();
    let all_bodies: Vec<_> = std::iter::once(coinbase_body.clone())
        .chain(user_bodies.iter().cloned())
        .collect();
    let commitments: Vec<_> = all_bodies.iter().map(TxBody::claims_commitment).collect();
    let exact_surface = noid_chain::build_exact_action_surface(
        &pre_state.state,
        &all_bodies,
        &commitments,
        pre_state.alloc_counter,
    )
    .expect("build Tx8x2 exact action surface");
    let exact_cache = pre_state
        .state
        .exact_sparse_cache()
        .expect("build benchmark sparse cache");
    let exact_state_transition = build_exact_state_transition_proof(&exact_cache, &exact_surface)
        .expect("build exact state proof");
    let new_leaf_hashes: Vec<_> = exact_surface
        .new_slots
        .iter()
        .map(|&slot| slot_leaf_hash(slot))
        .collect();
    let new_state_root = reconstruct_root(
        &exact_surface.touched_indices,
        &new_leaf_hashes,
        &exact_state_transition.slot_siblings,
        BENCH_LOG_SLOTS,
    )
    .expect("child state root from multiproof frontier");
    let auth_sidecar = BlockAuthSidecar { tx_auth };
    let proof = BlockProof::minimal(
        prev_state_root,
        new_state_root,
        user_bodies.len() as u32,
        exact_state_transition,
    );
    let block = bench_block_from_parts(coinbase_body, &user_bodies, &proof, &pre_state);
    let start_accumulator = noid_recursive::ChainAccumulator {
        height: block.header.height - 1,
        tip_block_id: block.header.prev_block_hash,
        state_root: prev_state_root,
        log_slots: pre_state.state.log_slots() as u32,
        active_slot_count: pre_state.active_slot_count,
        alloc_counter: pre_state.alloc_counter,
        epoch_anchor_id: user_bodies
            .first()
            .map_or(block.header.prev_block_hash, |body| body.epoch_anchor),
    };
    assert_eq!(
        block.transactions[0].body.epoch_anchor, start_accumulator.tip_block_id,
        "coinbase epoch anchor is the parent tip"
    );
    assert!(user_bodies
        .iter()
        .all(|body| body.epoch_anchor == start_accumulator.epoch_anchor_id));
    let end_accumulator = start_accumulator
        .advance(&block.header)
        .expect("benchmark block advances the direct ten-lane accumulator");
    (
        proof,
        block,
        auth_sidecar,
        pre_state,
        start_accumulator,
        end_accumulator,
    )
}

/// Build a complete accepted user-bearing block from a locally valid synthetic
/// parent header. The parent itself is a valid PoW/header child of genesis; its
/// exact state is seeded with the users' real input UTXOs.
///
/// Coinbase deliberately occupies the final depth-24 slot. The B255 saturation
/// scenarios reserve that slot, so their accepted block retains the attainable
/// 20,420-sibling maximum rather than allowing template slot heuristics to
/// change the truth fixture's frontier geometry.
fn accepted_user_block_seed(mut scenarios: Vec<BenchScenario>) -> AcceptedBlockSeed {
    assert!(
        (1..=noid_chain::consensus::params::BLOCK_MAX_USER_TXS).contains(&scenarios.len()),
        "accepted fixture needs 1..=255 real user transactions"
    );
    let pre_bodies: Vec<_> = scenarios
        .iter()
        .map(|scenario| scenario.body.clone())
        .collect();
    let pre_state = seed_state_for_bodies(&pre_bodies);
    let pre_leaves: Vec<_> = pre_bodies
        .iter()
        .flat_map(|body| {
            body.live_inputs().map(|(_, input)| {
                let slot = SlotValue::with_owner_fields(
                    input.amount,
                    input.creation_id,
                    body.input_owner.as_fields(),
                );
                (input.slot_index, slot_leaf_hash(slot))
            })
        })
        .collect();
    let exact_cache =
        noid_chain::sparse_merkle::SparseMerkleCache::from_leaves(BENCH_LOG_SLOTS, &pre_leaves)
            .expect("accepted fixture sparse cache from real UTXOs");
    assert_eq!(exact_cache.root(), pre_state.cached_state_root());
    let genesis = noid_chain::consensus::genesis_header();
    let genesis_id = noid_chain::hash_block_header(&genesis);
    let parent_timestamp = genesis.timestamp + noid_chain::consensus::params::BLOCK_TIME;
    let parent_target = noid_chain::consensus::difficulty::next_target(
        0,
        genesis.timestamp,
        &genesis.difficulty_target,
        1,
        parent_timestamp,
    );
    let mut parent = BlockHeader {
        prev_block_hash: genesis_id,
        state_root: pre_state.cached_state_root(),
        tx_root: [0u8; 32],
        timestamp: parent_timestamp,
        height: 1,
        miner_address: Address([0xA1; 32]),
        nonce: 0,
        difficulty_target: parent_target,
        log_slots: BENCH_LOG_SLOTS,
        active_slot_count: pre_state.active_slot_count,
        alloc_counter: pre_state.alloc_counter,
    };
    parent.nonce = mine_benchmark_header(&parent);
    let parent_id = noid_chain::hash_block_header(&parent);

    // Height one is still in genesis' transaction epoch. Recompute the exact
    // consensus fee against this parent and preserve each scenario's output
    // slots/owners while rebalancing its live amount lanes.
    for scenario in &mut scenarios {
        scenario.body.epoch_anchor = genesis_id;
        let required_fee = noid_chain::consensus::fees::required_fee_for_tx_body(
            &scenario.body,
            parent.active_slot_count,
            parent.log_slots,
        );
        let input_sum: u64 = scenario
            .body
            .live_inputs()
            .map(|(_, input)| input.amount)
            .sum();
        let spendable = input_sum
            .checked_sub(required_fee)
            .expect("fixture fee fits inputs");
        scenario.body.fee = required_fee;
        let live_outputs: Vec<_> = (0..TX_OUTPUTS)
            .filter(|&index| scenario.body.output_is_live(index))
            .collect();
        assert!(!live_outputs.is_empty(), "accepted user needs an output");
        let mut remaining = spendable;
        for (rank, &index) in live_outputs.iter().enumerate() {
            let amount = if rank + 1 == live_outputs.len() {
                remaining
            } else {
                spendable / live_outputs.len() as u64
            };
            remaining -= amount;
            scenario.body.outputs[index].amount = amount;
        }
        scenario
            .body
            .validate_canonical()
            .expect("accepted fixture canonical body");
    }
    let tx_auth: Vec<_> = scenarios
        .iter()
        .cloned()
        .map(minimal_tx_fixture)
        .map(|fixture| fixture.auth_proof)
        .collect();
    let user_bodies: Vec<_> = scenarios
        .into_iter()
        .map(|scenario| scenario.body)
        .collect();

    let genesis_work = noid_chain::consensus::block_work(&genesis.difficulty_target);
    let parent_work = noid_chain::consensus::add_work(
        &genesis_work,
        &noid_chain::consensus::block_work(&parent.difficulty_target),
    );
    let start_consensus = noid_recursive::RecursiveConsensusState::from_header(
        &parent,
        parent_work,
        0,
        genesis.timestamp,
        genesis.difficulty_target,
        &[genesis.timestamp, parent.timestamp],
        &[genesis.active_slot_count, parent.active_slot_count],
    );
    let start_accumulator = noid_recursive::ChainAccumulator {
        height: parent.height,
        tip_block_id: parent_id,
        state_root: parent.state_root,
        log_slots: parent.log_slots,
        active_slot_count: parent.active_slot_count,
        alloc_counter: parent.alloc_counter,
        epoch_anchor_id: genesis_id,
    };
    let child_timestamp = parent.timestamp + noid_chain::consensus::params::BLOCK_TIME;
    let child_target = noid_chain::consensus::difficulty::next_target(
        start_consensus.asert_anchor_height,
        start_consensus.asert_anchor_timestamp,
        &start_consensus.asert_anchor_target,
        parent.height + 1,
        child_timestamp,
    );
    let miner_address = Address([0xB2; 32]);
    let mut coinbase = bench_coinbase_body();
    coinbase.epoch_anchor = parent_id;
    coinbase.outputs[0].owner = miner_address;
    let claimable_fee_sum: u128 = user_bodies
        .iter()
        .map(|body| {
            u128::from(noid_chain::consensus::fees::claimable_fee_for_tx_body(
                body,
                parent.active_slot_count,
                parent.log_slots,
            ))
        })
        .sum();
    coinbase.outputs[0].amount = (u128::from(noid_chain::consensus::emission::block_reward(
        BENCH_LOG_SLOTS,
    )) + claimable_fee_sum)
        .min(u128::from(u64::MAX)) as u64;
    let mut transactions = Vec::with_capacity(user_bodies.len() + 1);
    transactions.push(Transaction::new(coinbase));
    transactions.extend(user_bodies.iter().cloned().map(Transaction::new));

    let all_bodies: Vec<_> = transactions
        .iter()
        .map(|transaction| transaction.body.clone())
        .collect();
    let commitments: Vec<_> = all_bodies.iter().map(TxBody::claims_commitment).collect();
    let surface = noid_chain::build_exact_action_surface(
        &pre_state.state,
        &all_bodies,
        &commitments,
        pre_state.alloc_counter,
    )
    .expect("accepted fixture exact action surface");
    let state_transition = build_exact_state_transition_proof(&exact_cache, &surface)
        .expect("accepted fixture structural frontier");
    let child_leaves: Vec<_> = surface
        .new_slots
        .iter()
        .copied()
        .map(slot_leaf_hash)
        .collect();
    let child_root = reconstruct_root(
        &surface.touched_indices,
        &child_leaves,
        &state_transition.slot_siblings,
        BENCH_LOG_SLOTS,
    )
    .expect("accepted fixture child root");
    let child_active_slot_count = parent
        .active_slot_count
        .checked_sub(u64::from(surface.spends))
        .and_then(|count| count.checked_add(u64::from(surface.mints)))
        .expect("accepted fixture active counter");
    let child_alloc_counter = parent
        .alloc_counter
        .checked_add(u64::from(surface.mints))
        .expect("accepted fixture allocator counter");
    let mut child_header = BlockHeader {
        prev_block_hash: parent_id,
        state_root: child_root,
        tx_root: noid_chain::compute_tx_root(&transactions),
        timestamp: child_timestamp,
        height: parent.height + 1,
        miner_address,
        nonce: 0,
        difficulty_target: child_target,
        log_slots: BENCH_LOG_SLOTS,
        active_slot_count: child_active_slot_count,
        alloc_counter: child_alloc_counter,
    };
    child_header.nonce = mine_benchmark_header(&child_header);
    let block = Block {
        header: child_header,
        transactions,
    };
    noid_chain::consensus::validate_block_checks_timeless(
        &block,
        &parent,
        &[genesis.timestamp, parent.timestamp],
        &[genesis.active_slot_count, parent.active_slot_count],
        &noid_chain::consensus::AnchorInfo {
            anchor_height: 0,
            anchor_timestamp: genesis.timestamp,
            anchor_target: genesis.difficulty_target,
        },
    )
    .expect("accepted fixture native consensus checks");
    let block_proof = BlockProof::minimal(
        pre_state.cached_state_root(),
        child_root,
        user_bodies.len() as u32,
        state_transition,
    );
    let sidecar = BlockAuthSidecar { tx_auth };
    let witness = noid_block::FullAcceptedBlockBatchWitness {
        items: vec![noid_block::FullAcceptedBlockBatchItem {
            block,
            block_proof_bytes: bincode::serialize(&block_proof)
                .expect("accepted fixture block proof bytes"),
            block_auth_sidecar_bytes: sidecar
                .to_bytes()
                .expect("accepted fixture auth sidecar bytes"),
        }],
    };
    AcceptedBlockSeed {
        start_consensus,
        start_accumulator,
        parent,
        pre_state,
        witness,
    }
}

/// Replay an accepted user-bearing block and derive every production component
/// statement without crossing into the retained component prover.
pub fn accepted_user_block_fixture(scenarios: Vec<BenchScenario>) -> AcceptedNativeBlockFixture {
    let seed = accepted_user_block_seed(scenarios);
    let output = noid_block::verify_full_accepted_block_batch_native(
        &seed.start_consensus,
        &seed.start_accumulator,
        &seed.parent,
        &seed.pre_state,
        &seed.witness,
    )
    .expect("accepted fixture native replay");
    AcceptedNativeBlockFixture {
        start_consensus: seed.start_consensus,
        start_accumulator: seed.start_accumulator,
        parent: seed.parent,
        pre_state: seed.pre_state,
        witness: seed.witness,
        output,
    }
}

/// Build the retained production component proof for an accepted user block.
/// Keep B255 calls opt-in: this crosses the m22+ proof roofline by design.
pub fn accepted_proved_user_block_fixture(
    scenarios: Vec<BenchScenario>,
) -> AcceptedSingleBlockFixture {
    let seed = accepted_user_block_seed(scenarios);
    let (output, component_proof) = noid_block::prove_retained_full_accepted_block_batch_proof(
        &seed.start_consensus,
        &seed.start_accumulator,
        &seed.parent,
        &seed.pre_state,
        &seed.witness,
    )
    .expect("accepted fixture component proof");
    AcceptedSingleBlockFixture {
        start_consensus: seed.start_consensus,
        start_accumulator: seed.start_accumulator,
        parent: seed.parent,
        pre_state: seed.pre_state,
        witness: seed.witness,
        output,
        component_proof,
    }
}

/// Small production-path smoke fixture.
pub fn accepted_single_user_fixture(seed: u128) -> AcceptedSingleBlockFixture {
    accepted_proved_user_block_fixture(vec![tx8x2_scenario(
        "accepted-single-user",
        2,
        2,
        4_096,
        seed,
    )])
}

/// Two consecutive canonical coinbase-only children of the real genesis
/// boundary, each replayed and proved as its own retained single-block batch.
///
/// This is the smallest honest fixture for the recursive block -> link -> tip
/// vertical: the first link can use the canonical blockless bootstrap
/// accumulator, while the second link exercises an ordinary predecessor replay.
/// Both blocks belong to B8 (`user_tx_class_tier(0) == Some(8)`) and therefore
/// share one production block matrix after capacity padding.
pub fn accepted_two_coinbase_chain_fixture() -> [AcceptedSingleBlockFixture; 2] {
    let genesis = noid_chain::consensus::genesis_header();
    let mut state = ChainState::with_log_slots(genesis.log_slots as usize);
    assert_eq!(
        state.cached_state_root(),
        genesis.state_root,
        "canonical empty state must match the genesis header"
    );

    let genesis_work = noid_chain::consensus::block_work(&genesis.difficulty_target);
    let mut consensus = noid_recursive::RecursiveConsensusState::from_header(
        &genesis,
        genesis_work,
        0,
        genesis.timestamp,
        genesis.difficulty_target,
        &[genesis.timestamp],
        &[genesis.active_slot_count],
    );
    let mut accumulator = noid_recursive::genesis_accumulator();
    let mut parent = genesis;
    let mut fixtures = Vec::with_capacity(2);

    for index in 0..2usize {
        let timestamp = parent
            .timestamp
            .checked_add(noid_chain::consensus::params::BLOCK_TIME)
            .expect("coinbase-chain timestamp");
        let target = noid_chain::consensus::next_target(
            consensus.asert_anchor_height,
            consensus.asert_anchor_timestamp,
            &consensus.asert_anchor_target,
            parent.height + 1,
            timestamp,
        );
        let template = noid_chain::consensus::build_block_template(
            &parent,
            &state,
            consensus.active_counts(),
            Vec::new(),
            Address([0xC0 + index as u8; 32]),
            timestamp,
            target,
        )
        .expect("canonical coinbase-only template");
        let transactions = template.all_txs();
        let mut header = template.into_header(0);
        header.nonce = mine_benchmark_header(&header);
        let block = Block {
            header: header.clone(),
            transactions,
        };
        let witness = noid_block::FullAcceptedBlockBatchWitness {
            items: vec![noid_block::FullAcceptedBlockBatchItem {
                block,
                // Coinbase-only acceptance has no detached block proof or
                // authorization sidecar. The retained replay derives its exact
                // structural component statements directly.
                block_proof_bytes: Vec::new(),
                block_auth_sidecar_bytes: Vec::new(),
            }],
        };
        let (output, component_proof) = noid_block::prove_retained_full_accepted_block_batch_proof(
            &consensus,
            &accumulator,
            &parent,
            &state,
            &witness,
        )
        .expect("canonical coinbase-only retained component proof");
        assert_eq!(component_proof.exact_state.len(), 1);

        let next_consensus = output.accepted_claim_batch.consensus_state.clone();
        let next_accumulator = output.accepted_claim_batch.accumulator.clone();
        let next_state = output.end_state.clone();
        fixtures.push(AcceptedSingleBlockFixture {
            start_consensus: consensus,
            start_accumulator: accumulator,
            parent,
            pre_state: state,
            witness,
            output,
            component_proof,
        });

        consensus = next_consensus;
        accumulator = next_accumulator;
        state = next_state;
        parent = header;
    }

    fixtures
        .try_into()
        .unwrap_or_else(|_| unreachable!("exactly two fixtures were built"))
}

#[derive(Clone)]
struct TrackedSpendable {
    slot_index: u32,
    spend_secret_seed: u128,
}

impl TrackedSpendable {
    fn spend_secret(&self) -> SpendSecret {
        mk_secret(self.spend_secret_seed)
    }
}

fn four_tier_chain_start(
    seed: u128,
) -> (
    noid_recursive::RecursiveConsensusState,
    noid_recursive::ChainAccumulator,
    BlockHeader,
    ChainState,
    Vec<TrackedSpendable>,
) {
    const INITIAL_UTXO_COUNT: usize = 8;
    const INITIAL_AMOUNT: u64 = 1_000_000_000;

    let mut spendables = Vec::with_capacity(INITIAL_UTXO_COUNT);
    let mut slots = Vec::with_capacity(INITIAL_UTXO_COUNT);
    for index in 0..INITIAL_UTXO_COUNT {
        let spend_secret_seed = seed.wrapping_add(0x1000_0000).wrapping_add(index as u128);
        let spend_secret = mk_secret(spend_secret_seed);
        let slot_index = 0x0001_0000 + (index as u32) * 0x0001_0000;
        let creation_id = index as u64 + 1;
        slots.push((
            slot_index,
            SlotValue::with_owner_fields(
                INITIAL_AMOUNT,
                creation_id,
                derive_address(&spend_secret).as_fields(),
            ),
        ));
        spendables.push(TrackedSpendable {
            slot_index,
            spend_secret_seed,
        });
    }
    let state =
        ChainState::from_sparse_utxos(BENCH_LOG_SLOTS as usize, &slots, INITIAL_UTXO_COUNT as u64)
            .expect("four-tier fixture synthetic parent state");

    let genesis = noid_chain::consensus::genesis_header();
    let genesis_id = noid_chain::hash_block_header(&genesis);
    let parent_timestamp = genesis
        .timestamp
        .checked_add(noid_chain::consensus::params::BLOCK_TIME)
        .expect("four-tier parent timestamp");
    let parent_target = noid_chain::consensus::next_target(
        0,
        genesis.timestamp,
        &genesis.difficulty_target,
        1,
        parent_timestamp,
    );
    let mut parent = BlockHeader {
        prev_block_hash: genesis_id,
        state_root: state.cached_state_root(),
        tx_root: [0u8; 32],
        timestamp: parent_timestamp,
        height: 1,
        miner_address: Address([0xD0; 32]),
        nonce: 0,
        difficulty_target: parent_target,
        log_slots: BENCH_LOG_SLOTS,
        active_slot_count: state.active_slot_count,
        alloc_counter: state.alloc_counter,
    };
    parent.nonce = mine_benchmark_header_parallel(&parent);
    let parent_id = noid_chain::hash_block_header(&parent);
    let genesis_work = noid_chain::consensus::block_work(&genesis.difficulty_target);
    let parent_work = noid_chain::consensus::add_work(
        &genesis_work,
        &noid_chain::consensus::block_work(&parent.difficulty_target),
    );
    let consensus = noid_recursive::RecursiveConsensusState::from_header(
        &parent,
        parent_work,
        0,
        genesis.timestamp,
        genesis.difficulty_target,
        &[genesis.timestamp, parent.timestamp],
        &[genesis.active_slot_count, parent.active_slot_count],
    );
    let accumulator = noid_recursive::ChainAccumulator {
        height: parent.height,
        tip_block_id: parent_id,
        state_root: parent.state_root,
        log_slots: parent.log_slots,
        active_slot_count: parent.active_slot_count,
        alloc_counter: parent.alloc_counter,
        epoch_anchor_id: genesis_id,
    };
    (consensus, accumulator, parent, state, spendables)
}

fn canonical_ladder_chain_start() -> (
    noid_recursive::RecursiveConsensusState,
    noid_recursive::ChainAccumulator,
    BlockHeader,
    ChainState,
    Vec<TrackedSpendable>,
) {
    let genesis = noid_chain::consensus::genesis_header();
    let state = ChainState::with_log_slots(genesis.log_slots as usize);
    assert_eq!(state.cached_state_root(), genesis.state_root);
    let consensus = noid_recursive::RecursiveConsensusState::from_header(
        &genesis,
        noid_chain::consensus::block_work(&genesis.difficulty_target),
        0,
        genesis.timestamp,
        genesis.difficulty_target,
        &[genesis.timestamp],
        &[genesis.active_slot_count],
    );
    let accumulator = noid_recursive::genesis_accumulator();
    assert_eq!(
        accumulator.tip_block_id,
        noid_chain::hash_block_header(&genesis)
    );
    assert_eq!(accumulator.state_root, state.cached_state_root());
    (consensus, accumulator, genesis, state, Vec::new())
}

fn sequential_chain_user_scenario(
    source: &TrackedSpendable,
    pre_state: &ChainState,
    epoch_anchor: [u8; 32],
    output_slots: [u32; TX_OUTPUTS],
    output_secret_seeds: [u128; TX_OUTPUTS],
) -> BenchScenario {
    let input_slot = pre_state.state.slot(source.slot_index);
    assert!(!input_slot.is_empty(), "tracked fixture UTXO must be live");
    let source_secret = source.spend_secret();
    let input_owner = derive_address(&source_secret);
    assert_eq!(
        input_slot,
        SlotValue::with_owner_fields(
            input_slot.amount(),
            input_slot.creation_id(),
            input_owner.as_fields(),
        ),
        "tracked fixture secret must own the selected UTXO"
    );

    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    inputs[0] = TxInput {
        slot_index: source.slot_index,
        amount: input_slot.amount(),
        creation_id: input_slot.creation_id(),
    };
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    for index in 0..TX_OUTPUTS {
        outputs[index] = TxOutput {
            slot_index: output_slots[index],
            amount: 1,
            owner: derive_address(&mk_secret(output_secret_seeds[index])),
        };
    }
    let mut body = TxBody {
        epoch_anchor,
        fee: 0,
        input_owner,
        inputs,
        outputs,
        validity_bitmap: 1 | output_bitmap_bit(0) | output_bitmap_bit(1),
        is_coinbase: false,
    };
    let required_fee = noid_chain::consensus::fees::required_fee_for_tx_body(
        &body,
        pre_state.active_slot_count,
        pre_state.state.log_slots() as u32,
    );
    let spendable = input_slot
        .amount()
        .checked_sub(required_fee)
        .expect("four-tier fixture input covers the exact consensus fee");
    body.fee = required_fee;
    body.outputs[0].amount = spendable / 2;
    body.outputs[1].amount = spendable - body.outputs[0].amount;
    body.validate_canonical()
        .expect("four-tier fixture canonical one-input/two-output body");
    BenchScenario {
        label: "accepted-four-tier-chain",
        desc: "continuous tier-ladder Tx8x2: 1 input / 2 outputs".to_owned(),
        body,
        spend_secret_seed: source.spend_secret_seed,
    }
}

fn accepted_sequential_chain_fixture(
    seed: u128,
    user_counts: &[usize],
    expected_tiers: &[usize],
    start: (
        noid_recursive::RecursiveConsensusState,
        noid_recursive::ChainAccumulator,
        BlockHeader,
        ChainState,
        Vec<TrackedSpendable>,
    ),
) -> Vec<AcceptedSingleBlockFixture> {
    assert_eq!(user_counts.len(), expected_tiers.len());
    let (mut consensus, mut accumulator, mut parent, mut state, mut spendables) = start;
    let mut fixtures = Vec::with_capacity(user_counts.len());
    let mut output_slot_cursor = 0x0080_0000u32;

    for (block_index, &user_count) in user_counts.iter().enumerate() {
        assert!(
            spendables.len() >= user_count,
            "preceding accepted outputs must fund the next proof tier"
        );
        assert_eq!(
            noid_chain::consensus::params::user_tx_class_tier(user_count),
            Some(expected_tiers[block_index])
        );

        let mut scenarios = Vec::with_capacity(user_count);
        let mut next_user_spendables = Vec::with_capacity(user_count * TX_OUTPUTS);
        for (tx_index, source) in spendables.iter().take(user_count).enumerate() {
            let mut output_slots = [0u32; TX_OUTPUTS];
            for output_slot in &mut output_slots {
                while state.state.slot(output_slot_cursor) != SlotValue::EMPTY {
                    output_slot_cursor = output_slot_cursor
                        .checked_add(1)
                        .expect("four-tier fixture output slot space");
                }
                *output_slot = output_slot_cursor;
                output_slot_cursor = output_slot_cursor
                    .checked_add(1)
                    .expect("four-tier fixture output slot space");
            }
            let output_secret_seeds = std::array::from_fn(|output_index| {
                seed.wrapping_add(0x2000_0000)
                    .wrapping_add((block_index as u128) << 20)
                    .wrapping_add((tx_index as u128) << 4)
                    .wrapping_add(output_index as u128)
            });
            scenarios.push(sequential_chain_user_scenario(
                source,
                &state,
                accumulator.epoch_anchor_id,
                output_slots,
                output_secret_seeds,
            ));
            next_user_spendables.extend((0..TX_OUTPUTS).map(|output_index| TrackedSpendable {
                slot_index: output_slots[output_index],
                spend_secret_seed: output_secret_seeds[output_index],
            }));
        }

        let timestamp = parent
            .timestamp
            .checked_add(noid_chain::consensus::params::BLOCK_TIME)
            .expect("four-tier child timestamp");
        let target = noid_chain::consensus::next_target(
            consensus.asert_anchor_height,
            consensus.asert_anchor_timestamp,
            &consensus.asert_anchor_target,
            parent.height + 1,
            timestamp,
        );
        let miner_secret_seed = seed
            .wrapping_add(0x3000_0000)
            .wrapping_add(block_index as u128);
        let miner_secret = mk_secret(miner_secret_seed);
        let template = noid_chain::consensus::build_block_template(
            &parent,
            &state,
            consensus.active_counts(),
            scenarios
                .iter()
                .map(|scenario| Transaction::new(scenario.body.clone()))
                .collect(),
            derive_address(&miner_secret),
            timestamp,
            target,
        )
        .expect("four-tier canonical block template");
        assert_eq!(
            template.txs.len(),
            user_count,
            "canonical template must retain every tier transaction"
        );

        let transactions = template.all_txs();
        let (block_proof_bytes, block_auth_sidecar_bytes) = if user_count == 0 {
            (Vec::new(), Vec::new())
        } else {
            let tx_auth = template
                .txs
                .iter()
                .map(|transaction| {
                    let scenario = scenarios
                        .iter()
                        .find(|scenario| scenario.body.txid() == transaction.txid())
                        .expect("template transaction maps to its tracked authority")
                        .clone();
                    minimal_tx_fixture(scenario).auth_proof
                })
                .collect();
            let all_bodies: Vec<_> = transactions
                .iter()
                .map(|transaction| transaction.body.clone())
                .collect();
            let commitments: Vec<_> = all_bodies.iter().map(TxBody::claims_commitment).collect();
            let exact_surface = noid_chain::build_exact_action_surface(
                &state.state,
                &all_bodies,
                &commitments,
                state.alloc_counter,
            )
            .expect("sequential fixture exact action surface");
            let exact_cache = state
                .state
                .exact_sparse_cache()
                .expect("sequential fixture sparse pre-state cache");
            let exact_state_transition =
                build_exact_state_transition_proof(&exact_cache, &exact_surface)
                    .expect("sequential fixture exact state transition proof");
            let new_leaf_hashes: Vec<_> = exact_surface
                .new_slots
                .iter()
                .copied()
                .map(slot_leaf_hash)
                .collect();
            let child_root = reconstruct_root(
                &exact_surface.touched_indices,
                &new_leaf_hashes,
                &exact_state_transition.slot_siblings,
                template.log_slots,
            )
            .expect("sequential fixture reconstructed child root");
            assert_eq!(child_root, template.state_root);
            let block_proof = BlockProof::minimal(
                state.cached_state_root(),
                child_root,
                user_count as u32,
                exact_state_transition,
            );
            let sidecar = BlockAuthSidecar { tx_auth };
            (
                bincode::serialize(&block_proof)
                    .expect("sequential fixture detached block proof bytes"),
                sidecar
                    .to_bytes()
                    .expect("sequential fixture authorization sidecar bytes"),
            )
        };
        let mut header = template.to_pow_header(0);
        header.nonce = mine_benchmark_header_parallel(&header);
        let block = Block {
            header: header.clone(),
            transactions,
        };
        let witness = noid_block::FullAcceptedBlockBatchWitness {
            items: vec![noid_block::FullAcceptedBlockBatchItem {
                block,
                block_proof_bytes,
                block_auth_sidecar_bytes,
            }],
        };
        let (output, component_proof) = noid_block::prove_retained_full_accepted_block_batch_proof(
            &consensus,
            &accumulator,
            &parent,
            &state,
            &witness,
        )
        .expect("four-tier retained component proof");
        assert_eq!(component_proof.exact_state.len(), 1);
        noid_recursive::block_certificate_backend::verify_accepted_block_batch_components(
            &consensus,
            &accumulator,
            &output.accepted_claim_batch.accumulator,
            &output.proof_components.component_inputs,
            &component_proof,
        )
        .expect("four-tier structural retained component verification");

        let next_consensus = output.accepted_claim_batch.consensus_state.clone();
        let next_accumulator = output.accepted_claim_batch.accumulator.clone();
        let next_state = output.end_state.clone();
        assert_eq!(
            next_accumulator.tip_block_id,
            noid_chain::hash_block_header(&header)
        );
        assert_eq!(next_accumulator.state_root, next_state.cached_state_root());

        let coinbase_output = &witness.items[0].block.transactions[0].body.outputs[0];
        // Tracking is fixture-only bookkeeping.  Sources not selected by this
        // block remain live in the consensus state and must remain available
        // to a later downward/skip class transition.  Keep them first so the
        // next block deterministically spends the oldest tracked UTXOs, then
        // append this block's coinbase and new user outputs.
        let mut next_spendables =
            Vec::with_capacity(spendables.len() - user_count + 1 + next_user_spendables.len());
        next_spendables.extend(spendables.iter().skip(user_count).cloned());
        next_spendables.push(TrackedSpendable {
            slot_index: coinbase_output.slot_index,
            spend_secret_seed: miner_secret_seed,
        });
        next_spendables.extend(next_user_spendables);
        for tracked in &next_spendables {
            let slot = next_state.state.slot(tracked.slot_index);
            let tracked_secret = tracked.spend_secret();
            assert_eq!(
                slot,
                SlotValue::with_owner_fields(
                    slot.amount(),
                    slot.creation_id(),
                    derive_address(&tracked_secret).as_fields(),
                ),
                "accepted end state must retain each tracked output authority"
            );
        }

        fixtures.push(AcceptedSingleBlockFixture {
            start_consensus: consensus,
            start_accumulator: accumulator,
            parent,
            pre_state: state,
            witness,
            output,
            component_proof,
        });
        consensus = next_consensus;
        accumulator = next_accumulator;
        parent = header;
        state = next_state;
        spendables = next_spendables;
    }

    fixtures
}

/// Four consecutive accepted and retained-proof-backed user blocks selecting
/// the complete production proof ladder B8 -> B32 -> B64 -> B255.
///
/// The live user counts are `[8, 17, 33, 65]`. Every user spends one output of
/// the preceding state and creates two outputs; the preceding coinbase is also
/// tracked, which supplies the seventeenth input at the first tier boundary.
/// Amounts and creation IDs are always read back from the actual preceding
/// `end_state`, never predicted by the fixture.
pub fn accepted_four_tier_chain_fixture(seed: u128) -> [AcceptedSingleBlockFixture; 4] {
    const USER_COUNTS: [usize; 4] = [8, 17, 33, 65];
    const EXPECTED_TIERS: [usize; 4] = [8, 32, 64, 255];

    accepted_sequential_chain_fixture(
        seed,
        &USER_COUNTS,
        &EXPECTED_TIERS,
        four_tier_chain_start(seed),
    )
    .try_into()
    .unwrap_or_else(|_| unreachable!("exactly four tier fixtures were built"))
}

/// Honest canonical-genesis ladder fixture. The first item is a coinbase-only
/// child of the real genesis boundary. Tracking that miner output and every
/// later user output gives the tracked-pool recurrence
/// `1 -> 3 -> 7 -> 15 -> 24 -> 42 -> 76 -> 142`, leaving unspent accepted
/// outputs available for later downward and skipped class transitions.
pub fn accepted_canonical_ladder_chain_fixture(seed: u128) -> [AcceptedSingleBlockFixture; 8] {
    const USER_COUNTS: [usize; 8] = [0, 1, 3, 7, 8, 17, 33, 65];
    const EXPECTED_TIERS: [usize; 8] = [8, 8, 8, 8, 8, 32, 64, 255];

    accepted_sequential_chain_fixture(
        seed,
        &USER_COUNTS,
        &EXPECTED_TIERS,
        canonical_ladder_chain_start(),
    )
    .try_into()
    .unwrap_or_else(|_| unreachable!("exactly eight canonical ladder fixtures were built"))
}

/// Honest canonical-genesis ladder extended through the saturated Stage-5
/// maximum.  After first entering B255 at 65 user transactions, the chain
/// remains continuous through 131 and finally all 255 production user slots.
/// Retaining unspent accepted sources gives pool sizes `142 -> 274 -> 530`,
/// so both saturated steps are funded entirely by live UTXOs in the direct
/// predecessor state.
pub fn accepted_canonical_saturated_ladder_chain_fixture(
    seed: u128,
) -> [AcceptedSingleBlockFixture; 10] {
    const USER_COUNTS: [usize; 10] = [0, 1, 3, 7, 8, 17, 33, 65, 131, 255];
    const EXPECTED_TIERS: [usize; 10] = [8, 8, 8, 8, 8, 32, 64, 255, 255, 255];

    accepted_sequential_chain_fixture(
        seed,
        &USER_COUNTS,
        &EXPECTED_TIERS,
        canonical_ladder_chain_start(),
    )
    .try_into()
    .unwrap_or_else(|_| unreachable!("exactly ten saturated ladder fixtures were built"))
}

/// Honest arbitrary-class-transition fixture after the complete 255-user
/// Stage-5 saturation point.
///
/// The final suffix selects `B8, B255, B32, B64`, exercising the representative
/// transitions `B255 -> B8` (full downward), `B8 -> B255` (full skipped
/// upward), `B255 -> B32` (skipped downward), and `B32 -> B64` (ordinary
/// upward) without resetting consensus, state, accumulator, or tracked UTXOs.
pub fn accepted_canonical_ladder_transition_chain_fixture(
    seed: u128,
) -> [AcceptedSingleBlockFixture; 14] {
    const USER_COUNTS: [usize; 14] = [0, 1, 3, 7, 8, 17, 33, 65, 131, 255, 8, 65, 17, 33];
    const EXPECTED_TIERS: [usize; 14] = [8, 8, 8, 8, 8, 32, 64, 255, 255, 255, 8, 255, 32, 64];

    accepted_sequential_chain_fixture(
        seed,
        &USER_COUNTS,
        &EXPECTED_TIERS,
        canonical_ladder_chain_start(),
    )
    .try_into()
    .unwrap_or_else(|_| unreachable!("exactly fourteen transition fixtures were built"))
}

/// Complete 255-real Stage-3 truth fixture.
pub fn accepted_b255_truth_fixture(seed: u128) -> AcceptedNativeBlockFixture {
    accepted_user_block_fixture(b255_saturation_scenarios("accepted-b255-truth", seed))
}

/// Opt-in retained component proof over the complete B255 truth fixture.
pub fn accepted_b255_proved_truth_fixture(seed: u128) -> AcceptedSingleBlockFixture {
    accepted_proved_user_block_fixture(b255_saturation_scenarios(
        "accepted-b255-proved-truth",
        seed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashSet};

    /// This fixture produces four retained component proofs (including B255
    /// class selection) and is intentionally opt-in for ordinary unit runs.
    #[test]
    #[ignore = "heavy continuous B8/B32/B64/B255 retained-proof fixture"]
    fn accepted_four_tier_chain_is_continuous_and_structural() {
        const EXPECTED_COUNTS: [usize; 4] = [8, 17, 33, 65];
        const EXPECTED_TIERS: [usize; 4] = [8, 32, 64, 255];

        let fixtures = accepted_four_tier_chain_fixture(0x4C41_4444_4552);
        for (index, fixture) in fixtures.iter().enumerate() {
            let block = &fixture.witness.items[0].block;
            let user_count = block.transactions.len() - 1;
            assert_eq!(user_count, EXPECTED_COUNTS[index]);
            assert_eq!(
                noid_chain::consensus::params::user_tx_class_tier(user_count),
                Some(EXPECTED_TIERS[index])
            );
            assert_eq!(
                block.header.prev_block_hash,
                noid_chain::hash_block_header(&fixture.parent)
            );
            assert_eq!(block.header.height, fixture.parent.height + 1);
            assert_eq!(fixture.start_accumulator.height, fixture.parent.height);
            assert_eq!(
                fixture.start_accumulator.tip_block_id,
                noid_chain::hash_block_header(&fixture.parent)
            );
            assert_eq!(
                fixture.start_accumulator.state_root,
                fixture.pre_state.cached_state_root()
            );
            assert_eq!(
                fixture
                    .output
                    .proof_components
                    .component_inputs
                    .exact_state_structural_inputs
                    .len(),
                1
            );

            if index == 0 {
                continue;
            }
            let previous = &fixtures[index - 1];
            let previous_block = &previous.witness.items[0].block;
            assert_eq!(fixture.parent, previous_block.header);
            assert_eq!(
                fixture.start_consensus,
                previous.output.accepted_claim_batch.consensus_state
            );
            assert_eq!(
                fixture.start_accumulator,
                previous.output.accepted_claim_batch.accumulator
            );
            assert_eq!(
                fixture.pre_state.cached_state_root(),
                previous.output.end_state.cached_state_root()
            );
            assert_eq!(
                fixture.pre_state.active_slot_count,
                previous.output.end_state.active_slot_count
            );
            assert_eq!(
                fixture.pre_state.alloc_counter,
                previous.output.end_state.alloc_counter
            );
            for transaction in &previous_block.transactions {
                for (_, input) in transaction.body.live_inputs() {
                    assert_eq!(
                        fixture.pre_state.state.slot(input.slot_index),
                        previous.output.end_state.state.slot(input.slot_index)
                    );
                }
                for (_, output) in transaction.body.live_outputs() {
                    assert_eq!(
                        fixture.pre_state.state.slot(output.slot_index),
                        previous.output.end_state.state.slot(output.slot_index)
                    );
                }
            }
        }
    }

    #[test]
    #[ignore = "heavy canonical-genesis eight-block retained-proof ladder"]
    fn accepted_canonical_ladder_chain_has_direct_boundaries_and_structural_state() {
        const EXPECTED_COUNTS: [usize; 8] = [0, 1, 3, 7, 8, 17, 33, 65];
        const EXPECTED_TIERS: [usize; 8] = [8, 8, 8, 8, 8, 32, 64, 255];

        let fixtures = accepted_canonical_ladder_chain_fixture(0xC4A0_1CA1_1ADD_E2);
        let genesis = noid_chain::consensus::genesis_header();
        assert_eq!(fixtures[0].parent, genesis);
        assert_eq!(
            fixtures[0].start_accumulator,
            noid_recursive::genesis_accumulator()
        );
        assert_eq!(
            fixtures[0].start_consensus.block_id,
            noid_chain::hash_block_header(&genesis)
        );
        assert_eq!(
            fixtures[0].pre_state.cached_state_root(),
            genesis.state_root
        );

        for (index, fixture) in fixtures.iter().enumerate() {
            let block = &fixture.witness.items[0].block;
            let user_count = block.transactions.len() - 1;
            assert_eq!(user_count, EXPECTED_COUNTS[index]);
            assert_eq!(
                noid_chain::consensus::params::user_tx_class_tier(user_count),
                Some(EXPECTED_TIERS[index])
            );
            assert_eq!(
                block.header.prev_block_hash,
                noid_chain::hash_block_header(&fixture.parent)
            );
            assert_eq!(block.header.height, fixture.parent.height + 1);
            assert_eq!(
                fixture
                    .output
                    .proof_components
                    .component_inputs
                    .exact_state_structural_inputs
                    .len(),
                1
            );

            if index == 0 {
                assert!(fixture.witness.items[0].block_proof_bytes.is_empty());
                assert!(fixture.witness.items[0].block_auth_sidecar_bytes.is_empty());
                continue;
            }
            let previous = &fixtures[index - 1];
            assert_eq!(fixture.parent, previous.witness.items[0].block.header);
            assert_eq!(
                fixture.start_consensus,
                previous.output.accepted_claim_batch.consensus_state
            );
            assert_eq!(
                fixture.start_accumulator,
                previous.output.accepted_claim_batch.accumulator
            );
            assert_eq!(
                fixture.pre_state.cached_state_root(),
                previous.output.end_state.cached_state_root()
            );
            assert_eq!(
                fixture.pre_state.active_slot_count,
                previous.output.end_state.active_slot_count
            );
            assert_eq!(
                fixture.pre_state.alloc_counter,
                previous.output.end_state.alloc_counter
            );
        }
    }

    #[test]
    #[ignore = "heavy canonical-genesis ten-block saturated retained-proof ladder"]
    fn accepted_canonical_saturated_ladder_reaches_b255_with_direct_boundaries() {
        const EXPECTED_COUNTS: [usize; 10] = [0, 1, 3, 7, 8, 17, 33, 65, 131, 255];
        const EXPECTED_TIERS: [usize; 10] = [8, 8, 8, 8, 8, 32, 64, 255, 255, 255];

        let fixtures = accepted_canonical_saturated_ladder_chain_fixture(0xC4A0_5A7A_2A7E_D255);
        let genesis = noid_chain::consensus::genesis_header();
        assert_eq!(fixtures[0].parent, genesis);
        assert_eq!(
            fixtures[0].start_accumulator,
            noid_recursive::genesis_accumulator()
        );
        assert_eq!(
            fixtures[0].start_consensus.block_id,
            noid_chain::hash_block_header(&genesis)
        );
        assert_eq!(
            fixtures[0].pre_state.cached_state_root(),
            genesis.state_root
        );

        for (index, fixture) in fixtures.iter().enumerate() {
            let block = &fixture.witness.items[0].block;
            let user_count = block.transactions.len() - 1;
            assert_eq!(user_count, EXPECTED_COUNTS[index]);
            assert_eq!(
                noid_chain::consensus::params::user_tx_class_tier(user_count),
                Some(EXPECTED_TIERS[index])
            );
            assert_eq!(
                block.header.prev_block_hash,
                noid_chain::hash_block_header(&fixture.parent)
            );
            assert_eq!(block.header.height, fixture.parent.height + 1);
            assert_eq!(fixture.start_accumulator.height, fixture.parent.height);
            assert_eq!(
                fixture.start_accumulator.tip_block_id,
                noid_chain::hash_block_header(&fixture.parent)
            );
            assert_eq!(
                fixture.start_accumulator.state_root,
                fixture.pre_state.cached_state_root()
            );
            assert_eq!(
                fixture.output.accepted_claim_batch.accumulator.tip_block_id,
                noid_chain::hash_block_header(&block.header)
            );
            assert_eq!(
                fixture.output.accepted_claim_batch.accumulator.state_root,
                fixture.output.end_state.cached_state_root()
            );
            assert_eq!(
                fixture.output.accepted_claim_batch.accumulator.state_root,
                block.header.state_root
            );
            assert_eq!(fixture.component_proof.exact_state.len(), 1);
            assert_eq!(
                fixture
                    .output
                    .proof_components
                    .component_inputs
                    .exact_state_structural_inputs
                    .len(),
                1
            );

            if user_count == 0 {
                assert!(fixture.witness.items[0].block_proof_bytes.is_empty());
                assert!(fixture.witness.items[0].block_auth_sidecar_bytes.is_empty());
            } else {
                let proof: BlockProof =
                    bincode::deserialize(&fixture.witness.items[0].block_proof_bytes)
                        .expect("decode saturated-ladder detached BlockProof");
                assert_eq!(proof.meta.n_tx, user_count as u32);
                assert_eq!(
                    proof.meta.prev_block_state_root,
                    fixture.pre_state.cached_state_root()
                );
                assert_eq!(proof.meta.new_state_root, block.header.state_root);
            }

            if index == 0 {
                continue;
            }
            let previous = &fixtures[index - 1];
            assert_eq!(fixture.parent, previous.witness.items[0].block.header);
            assert_eq!(
                fixture.start_consensus,
                previous.output.accepted_claim_batch.consensus_state
            );
            assert_eq!(
                fixture.start_accumulator,
                previous.output.accepted_claim_batch.accumulator
            );
            assert_eq!(
                fixture.pre_state.cached_state_root(),
                previous.output.end_state.cached_state_root()
            );
            assert_eq!(
                fixture.pre_state.active_slot_count,
                previous.output.end_state.active_slot_count
            );
            assert_eq!(
                fixture.pre_state.alloc_counter,
                previous.output.end_state.alloc_counter
            );
        }

        let final_fixture = fixtures.last().expect("saturated ladder tip");
        let final_proof: BlockProof =
            bincode::deserialize(&final_fixture.witness.items[0].block_proof_bytes)
                .expect("decode final saturated detached BlockProof");
        assert_eq!(final_proof.meta.n_tx, 255);
        assert_eq!(
            final_proof.meta.prev_block_state_root,
            final_fixture.pre_state.cached_state_root()
        );
        assert_eq!(
            final_proof.meta.new_state_root,
            final_fixture.witness.items[0].block.header.state_root
        );
    }

    #[test]
    #[ignore = "heavy canonical saturated ladder plus real class-transition suffix"]
    fn accepted_canonical_transition_suffix_is_continuous_and_structural() {
        const EXPECTED_COUNTS: [usize; 14] = [0, 1, 3, 7, 8, 17, 33, 65, 131, 255, 8, 65, 17, 33];
        const EXPECTED_TIERS: [usize; 14] = [8, 8, 8, 8, 8, 32, 64, 255, 255, 255, 8, 255, 32, 64];

        let fixtures = accepted_canonical_ladder_transition_chain_fixture(0xC4A0_7A4A_5171_0A55);
        assert_eq!(fixtures[0].parent, noid_chain::consensus::genesis_header());
        assert_eq!(
            fixtures[0].start_accumulator,
            noid_recursive::genesis_accumulator()
        );
        for (index, fixture) in fixtures.iter().enumerate() {
            let block = &fixture.witness.items[0].block;
            let user_count = block.transactions.len() - 1;
            assert_eq!(user_count, EXPECTED_COUNTS[index]);
            assert_eq!(
                noid_chain::consensus::params::user_tx_class_tier(user_count),
                Some(EXPECTED_TIERS[index])
            );
            assert_eq!(
                block.header.prev_block_hash,
                noid_chain::hash_block_header(&fixture.parent)
            );
            assert_eq!(fixture.component_proof.exact_state.len(), 1);
            assert_eq!(
                fixture
                    .output
                    .proof_components
                    .component_inputs
                    .exact_state_structural_inputs
                    .len(),
                1
            );
            if index > 0 {
                let previous = &fixtures[index - 1];
                assert_eq!(fixture.parent, previous.witness.items[0].block.header);
                assert_eq!(
                    fixture.start_accumulator,
                    previous.output.accepted_claim_batch.accumulator
                );
                assert_eq!(
                    fixture.pre_state.cached_state_root(),
                    previous.output.end_state.cached_state_root()
                );
            }
        }
        assert_eq!(
            &EXPECTED_TIERS[9..],
            &[255, 8, 255, 32, 64],
            "real suffix covers downward, skipped-up, skipped-down, and upward transitions",
        );
    }

    #[test]
    fn b255_saturation_fixture_hits_caps_and_depth24_frontier_maximum() {
        let scenarios = b255_saturation_scenarios("b255-saturation", 0xB255_0000);
        let coinbase = bench_coinbase_body();
        let mut transactions = Vec::with_capacity(256);
        transactions.push(Transaction::new(coinbase));
        transactions.extend(
            scenarios
                .iter()
                .map(|scenario| Transaction::new(scenario.body.clone())),
        );
        let tx_root = noid_chain::compute_tx_root(&transactions);
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [0u8; 32],
                tx_root,
                timestamp: 2,
                height: 1,
                miner_address: Address([0xCB; 32]),
                nonce: 0,
                difficulty_target: [0xFF; 32],
                log_slots: BENCH_LOG_SLOTS,
                active_slot_count: 0,
                alloc_counter: 0,
            },
            transactions,
        };
        let resources = noid_chain::consensus::validate_block_resource_preflight(&block)
            .expect("saturation fixture passes raw consensus caps");
        assert_eq!(resources.user_tx_count, 255);
        assert_eq!(resources.live_input_count, 1_020);
        assert_eq!(resources.output_count, 511);
        assert_eq!(resources.action_count, 1_531);
        assert_eq!(resources.touched_slot_count, 1_531);
        assert_eq!(resources.distinct_segment_count, 256);
        assert_eq!(resources.state_frontier_node_count, 20_420);

        let input_counts: Vec<_> = scenarios
            .iter()
            .map(|scenario| scenario.body.live_input_count())
            .collect();
        assert_eq!(
            input_counts.iter().filter(|&&count| count == 8).count(),
            B255_EIGHT_INPUT_TXS
        );
        assert_eq!(
            input_counts.iter().filter(|&&count| count == 2).count(),
            B255_TWO_INPUT_TXS
        );
        assert!(scenarios[B255_EIGHT_INPUT_TXS..]
            .iter()
            .any(|scenario| scenario.body.input_is_live(7)));
        assert_eq!(
            scenarios
                .iter()
                .map(|scenario| scenario.body.input_owner)
                .collect::<HashSet<_>>()
                .len(),
            255
        );

        let creation_ids: BTreeSet<_> = scenarios
            .iter()
            .flat_map(|scenario| scenario.body.live_inputs())
            .map(|(_, input)| input.creation_id)
            .collect();
        assert_eq!(creation_ids.len(), 1_020);
        assert_eq!(creation_ids.first(), Some(&1));
        assert_eq!(creation_ids.last(), Some(&1_020));

        let input_slots: HashSet<_> = scenarios
            .iter()
            .flat_map(|scenario| scenario.body.live_inputs())
            .map(|(_, input)| input.slot_index)
            .collect();
        let output_slots: HashSet<_> = scenarios
            .iter()
            .flat_map(|scenario| scenario.body.live_outputs())
            .map(|(_, output)| output.slot_index)
            .collect();
        assert!(input_slots.contains(&65_535));
        assert!(output_slots.contains(&65_536));

        assert!(scenarios.iter().all(|scenario| {
            noid_gkr::owner_auth_public_from_body(&scenario.body)
                .is_ok_and(|public| public.layout == noid_gkr::OwnerAuthLayout::FIXED)
        }));

        let mut touched: Vec<_> = block
            .transactions
            .iter()
            .flat_map(|tx| {
                tx.body
                    .live_inputs()
                    .map(|(_, input)| input.slot_index)
                    .chain(tx.body.live_outputs().map(|(_, output)| output.slot_index))
            })
            .collect();
        touched.sort_unstable();
        let maximum = noid_chain::sparse_merkle::maximum_sibling_count_with_segment_cap(
            touched.len(),
            BENCH_LOG_SLOTS,
            noid_chain::consensus::params::LOG_SEGMENT_SIZE,
            noid_chain::consensus::params::BLOCK_MAX_DISTINCT_SEGMENTS,
        );
        assert_eq!(maximum, 20_420);
        assert_eq!(
            noid_chain::sparse_merkle::expected_sibling_count(&touched, BENCH_LOG_SLOTS).unwrap(),
            maximum
        );
    }

    /// The truth replay materializes all 256 exact-state segments and is kept
    /// out of the default unit suite. It intentionally stops before the m22+
    /// retained component prover; that roofline has its own benchmark gate.
    #[test]
    #[ignore = "large B255 native accepted-block truth fixture"]
    fn accepted_b255_truth_fixture_binds_every_production_statement() {
        let fixture = accepted_b255_truth_fixture(0xB255_ACCE_57ED);
        let block = &fixture.witness.items[0].block;
        let resources = noid_chain::consensus::validate_block_resource_preflight(block)
            .expect("accepted B255 resource preflight");
        assert_eq!(
            (
                resources.user_tx_count,
                resources.live_input_count,
                resources.output_count,
                resources.action_count,
                resources.touched_slot_count,
                resources.distinct_segment_count,
                resources.state_frontier_node_count,
            ),
            (255, 1_020, 511, 1_531, 1_531, 256, 20_420)
        );

        let proof: BlockProof = bincode::deserialize(&fixture.witness.items[0].block_proof_bytes)
            .expect("decode B255 exact proof");
        assert_eq!(proof.meta.n_tx, 255);
        assert_eq!(proof.meta.prev_block_state_root, fixture.parent.state_root);
        assert_eq!(proof.meta.new_state_root, block.header.state_root);
        assert_eq!(proof.state_transition.slot_siblings.len(), 20_420);
        assert_eq!(
            block.header.tx_root,
            noid_chain::compute_tx_root(&block.transactions)
        );

        let users = &block.transactions[1..];
        assert_eq!(users.len(), 255);
        assert_eq!(
            users
                .iter()
                .map(|tx| tx.body.input_owner)
                .collect::<HashSet<_>>()
                .len(),
            255
        );
        assert!(users.iter().any(|tx| tx.body.input_is_live(7)));

        let mut input_creation_ids = BTreeSet::new();
        let mut input_slots = HashSet::new();
        let mut output_slots = HashSet::new();
        let mut output_owners = HashSet::new();
        for tx in users {
            for (_, input) in tx.body.live_inputs() {
                assert!(input_creation_ids.insert(input.creation_id));
                assert!(input_slots.insert(input.slot_index));
                assert_eq!(
                    fixture.pre_state.state.slot(input.slot_index),
                    SlotValue::with_owner_fields(
                        input.amount,
                        input.creation_id,
                        tx.body.input_owner.as_fields(),
                    )
                );
                assert!(fixture
                    .output
                    .end_state
                    .state
                    .slot(input.slot_index)
                    .is_empty());
            }
            for (_, output) in tx.body.live_outputs() {
                assert!(output_slots.insert(output.slot_index));
                assert!(output_owners.insert(output.owner));
            }
        }
        assert_eq!(input_creation_ids.len(), 1_020);
        assert_eq!(input_creation_ids.first(), Some(&1));
        assert_eq!(input_creation_ids.last(), Some(&1_020));
        assert!(input_slots.contains(&65_535));
        assert!(output_slots.contains(&65_536));
        assert_eq!(output_owners.len(), 510);

        let mut next_creation_id = fixture.start_accumulator.alloc_counter;
        for tx in &block.transactions {
            for (_, output) in tx.body.live_outputs() {
                next_creation_id += 1;
                let minted = fixture.output.end_state.state.slot(output.slot_index);
                assert_eq!(minted.amount(), output.amount);
                assert_eq!(minted.creation_id(), next_creation_id);
                assert_eq!([minted.owner_hi, minted.owner_lo], output.owner.as_fields());
            }
        }
        assert_eq!(next_creation_id, 1_531);
        assert_eq!(fixture.output.end_state.active_slot_count, 511);
        assert_eq!(fixture.output.end_state.alloc_counter, 1_531);
        assert_eq!(
            fixture.output.end_state.cached_state_root(),
            block.header.state_root
        );

        let component = &fixture.output.proof_components.component_inputs;
        assert_eq!(component.tx_body_inputs.len(), 256);
        assert_eq!(component.tx_body_hashes.len(), 256);
        assert_eq!(component.tx_root_inputs.len(), 256);
        assert!(component
            .tx_root_inputs
            .iter()
            .all(|input| input.active_depth == noid_chain::tx_tree::TX_TREE_DEPTH));
        assert!(
            component.tx_root_inputs[255].directions[..noid_chain::tx_tree::TX_TREE_DEPTH]
                .iter()
                .all(|direction| *direction)
        );
        for (body, hash) in block
            .transactions
            .iter()
            .map(|tx| &tx.body)
            .zip(component.tx_body_hashes.iter())
        {
            assert_eq!(*hash, body.txid().as_fields());
        }
        assert_eq!(component.authorization_inputs.len(), 255);
        assert_eq!(component.authorization_totals.user_tx_count, 255);
        assert_eq!(component.authorization_totals.live_input_count_total, 1_020);
        for (index, authorization) in component.authorization_inputs.iter().enumerate() {
            let body = &block.transactions[index + 1].body;
            assert_eq!(authorization.block_index, 0);
            assert_eq!(authorization.tx_index, index + 1);
            assert_eq!(
                authorization.public.layout,
                noid_gkr::OwnerAuthLayout::FIXED
            );
            assert_eq!(authorization.tx_body_hash, body.txid().as_fields());
            assert_eq!(
                authorization.public.tx_body_hash,
                authorization.tx_body_hash
            );
            assert_eq!(
                authorization.public.expected_address,
                body.input_owner.as_fields()
            );
            assert_eq!(
                usize::from(authorization.live_input_count),
                body.live_input_count()
            );
        }
        assert_eq!(component.exact_state_structural_inputs.len(), 1);
        assert_eq!(
            component.exact_state_structural_inputs[0]
                .old_slot_leaves
                .len(),
            1_531
        );
        assert_eq!(
            component.exact_state_structural_inputs[0]
                .new_slot_leaves
                .len(),
            1_531
        );

        let expected_end = fixture
            .start_accumulator
            .advance(&block.header)
            .expect("B255 direct accumulator transition");
        assert_eq!(
            expected_end,
            fixture.output.accepted_claim_batch.accumulator
        );
    }
}

pub fn bench_full_block_proof_minimal(fixtures: &[MinimalTxFixture]) -> FullBlockProofBench {
    let user_bodies: Vec<_> = fixtures
        .iter()
        .map(|fixture| fixture.scenario.body.clone())
        .collect();
    let tx_auth: Vec<_> = fixtures
        .iter()
        .map(|fixture| fixture.auth_proof.clone())
        .collect();
    let (state_seed_time, pre_state) = time_once(|| seed_state_for_bodies(&user_bodies));
    let (prove_time, (proof, block, auth_sidecar, pre_state, start_accumulator, end_accumulator)) =
        time_once(move || prove_full_block_from_fixtures(pre_state, user_bodies, tx_auth));
    let (verify_time, ()) = time_once(|| {
        noid_block::validate_block_authorizations(
            &block,
            &auth_sidecar,
            &noid_block::OwnerAuthAuthorizationVerifier,
        )
        .expect("verify block authorizations");

        let exact_bodies: Vec<_> = block
            .transactions
            .iter()
            .map(|tx| tx.body.clone())
            .collect();
        let commitments: Vec<_> = exact_bodies.iter().map(TxBody::claims_commitment).collect();
        let exact_surface = noid_chain::build_exact_action_surface(
            &pre_state.state,
            &exact_bodies,
            &commitments,
            pre_state.alloc_counter,
        )
        .expect("rebuild exact state surface");
        let inputs = ExactStateTransitionInputs {
            parent_state_root: proof.meta.prev_block_state_root,
            parent_log_slots: pre_state.state.log_slots() as u32,
            child_state_root: block.header.state_root,
            child_log_slots: block.header.log_slots,
            parent_active_slot_count: pre_state.active_slot_count,
            parent_alloc_counter: pre_state.alloc_counter,
        };
        verify_exact_state_transition(&inputs, &exact_surface, &proof.state_transition)
            .expect("verify exact state transition");
    });
    FullBlockProofBench {
        state_seed_time,
        prove_time,
        verify_time,
        proof_bytes: proof.byte_len(),
        auth_sidecar_bytes: auth_sidecar.byte_len(),
        state_transition_bytes: proof.state_transition.byte_len(),
        proof,
        auth_sidecar,
        start_accumulator,
        end_accumulator,
    }
}
