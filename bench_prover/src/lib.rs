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
use noid_gkr::{
    owner_auth_gkr_channel, owner_auth_trace_inputs_from_body_and_secret,
    prove_owner_auth_killshot, spine_inputs_from_body, verify_owner_auth_killshot,
    OwnerAuthCircuit, OwnerAuthInputs, OwnerAuthProofKillShot, OwnerAuthPublicInputs, SpineInputs,
    WalletAuthorizationBundle,
};
use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret, TxBodyHash};
use noid_tx::{output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

pub const BENCH_LOG_SLOTS: u32 = 24;

#[derive(Clone)]
pub struct BenchScenario {
    pub label: &'static str,
    pub desc: String,
    pub body: TxBody,
    /// Wallet-local proving authority. It is never serialized into `body`.
    pub spend_secret: SpendSecret,
}

pub struct TxFixture {
    pub scenario: BenchScenario,
    pub spine_inputs: SpineInputs,
    pub auth_inputs: OwnerAuthInputs,
    pub auth_public: OwnerAuthPublicInputs,
    pub auth_proof: OwnerAuthProofKillShot,
}

#[derive(Clone)]
pub struct MinimalTxFixture {
    pub scenario: BenchScenario,
    pub auth_proof: OwnerAuthProofKillShot,
}

pub struct WalletBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof: OwnerAuthProofKillShot,
}

pub struct FullBlockProofBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof_bytes: usize,
    pub auth_sidecar_bytes: usize,
    pub state_transition_bytes: usize,
    pub proof: BlockProof,
    pub auth_sidecar: BlockAuthSidecar,
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
    SpendSecret(bytes)
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
        spend_secret,
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

pub fn tx_fixture(scenario: BenchScenario) -> TxFixture {
    scenario
        .body
        .validate_canonical()
        .expect("Tx8x2 fixture public logic");
    let auth_inputs =
        owner_auth_trace_inputs_from_body_and_secret(&scenario.body, &scenario.spend_secret)
            .expect("fixed one-owner inputs");
    let auth_public = auth_inputs.to_public();
    let circuit = OwnerAuthCircuit::build();
    let mut channel = owner_auth_gkr_channel();
    let (auth_proof, _) = prove_owner_auth_killshot(&circuit, &auth_inputs, &mut channel);
    let spine_inputs = spine_inputs_from_body(&scenario.body);
    TxFixture {
        scenario,
        spine_inputs,
        auth_inputs,
        auth_public,
        auth_proof,
    }
}

pub fn minimal_tx_fixture(scenario: BenchScenario) -> MinimalTxFixture {
    let fixture = tx_fixture(scenario);
    MinimalTxFixture {
        scenario: fixture.scenario,
        auth_proof: fixture.auth_proof,
    }
}

pub fn prove_wallet(fixture: &TxFixture, samples: usize) -> WalletBench {
    let circuit = OwnerAuthCircuit::build();
    let prove_time = time_median(samples, || {
        let mut channel = owner_auth_gkr_channel();
        let _ = prove_owner_auth_killshot(&circuit, &fixture.auth_inputs, &mut channel);
    });
    let mut channel = owner_auth_gkr_channel();
    let (proof, _) = prove_owner_auth_killshot(&circuit, &fixture.auth_inputs, &mut channel);
    let verify_time = time_median(samples, || {
        let mut channel = owner_auth_gkr_channel();
        verify_owner_auth_killshot(&proof, &circuit, &fixture.auth_public, &mut channel)
            .expect("verify fixed owner authorization");
    });
    WalletBench {
        prove_time,
        verify_time,
        proof,
    }
}

pub fn authorization_size(proof: &OwnerAuthProofKillShot) -> usize {
    proof.byte_len()
}

pub fn wallet_bundle_size(proof: &OwnerAuthProofKillShot) -> usize {
    WalletAuthorizationBundle {
        proof: proof.clone(),
    }
    .to_bytes()
    .expect("serialize fixed authorization")
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
    ChainState::from_sparse_utxos(BENCH_LOG_SLOTS as usize, &slots, 0)
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

fn bench_block_from_parts(
    coinbase_body: TxBody,
    user_bodies: &[TxBody],
    proof: &BlockProof,
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
            active_slot_count: active_outputs,
            alloc_counter: active_outputs + active_inputs.saturating_sub(active_inputs),
        },
        transactions,
    }
}

fn prove_full_block_from_fixtures(
    pre_state: ChainState,
    user_bodies: Vec<TxBody>,
    tx_auth: Vec<OwnerAuthProofKillShot>,
) -> (BlockProof, Block, BlockAuthSidecar, ChainState) {
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
    let block = bench_block_from_parts(coinbase_body, &user_bodies, &proof);
    (proof, block, auth_sidecar, pre_state)
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
    let pre_state = seed_state_for_bodies(&user_bodies);
    let (prove_time, (proof, block, auth_sidecar, pre_state)) =
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
        prove_time,
        verify_time,
        proof_bytes: proof.byte_len(),
        auth_sidecar_bytes: auth_sidecar.byte_len(),
        state_transition_bytes: proof.state_transition.byte_len(),
        proof,
        auth_sidecar,
    }
}
