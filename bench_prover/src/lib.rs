// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Shared benchmark fixtures for production standard/sweep proof paths.
//!
//! These helpers intentionally build real transaction bodies, real wallet logic
//! proofs, real auth slices, and real block-bucket witnesses. They are used by
//! `alice_sends_bob`, `block_scaling`, and `stark_report` so benchmark numbers
//! stay comparable across reports.

use std::time::{Duration, Instant};

use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_air::Air;
use noid_block::{
    assemble_sweep_bucket_proof, block_recursive_claim_hash, build_tx_witness,
    extract_replay_witness, prove_block_with_total_tx_count, verify_sweep_bucket_aggregation,
    BlockProof, BlockPublicMeta, OwnedSweepTxWitness, OwnedTxWitness, TxBlockWitness,
    BLOCK_BASE_LOG,
};
use noid_core::mle::split::split_mle_into_slices;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    auth_gkr_channel, build_auth_unified_from_inputs, compute_auth_boundary, prove_auth_killshot,
    AuthCircuit, AuthInputs, AuthProofKillShot, AuthPublicInputs, SpineInputs, N_AUTH_INPUTS,
    N_AUTH_UNIFIED_VARS,
};
use noid_poseidon2b::primitives::{
    derive_address, hash_auth_tag, Address, AuthTag, SpendSecret, TxBodyHash,
};
use noid_stark::prove_logic::{prove_logic, verify_logic, LogicProof, LogicWitness};
use noid_stark::prove_logic_sweep::{
    build_sweep_auth_slices, prove_sweep_logic, sweep_logic_witness_parts_from_body,
    sweep_spine_inputs_from_body, verify_sweep_logic, SweepLogicProof, SweepLogicWitness,
};
use noid_stark::{SweepWalletProofBundle, WalletProofBundle};
use noid_tx::{
    compute_claims_commitment, hash_tx_body_for_shape, PublicInputs, Transaction, TxBody, TxInput,
    TxOutput, TxShape, MAX_INPUTS, MAX_OUTPUTS,
};

pub const BENCH_LOG_SLOTS: u32 = 24;
pub const BENCH_PREV_STATE_ROOT: [u8; 32] = [0x11; 32];
pub const BENCH_NEW_STATE_ROOT: [u8; 32] = [0x22; 32];

#[derive(Debug, Clone, Copy)]
pub enum BenchShape {
    Standard,
    Sweep,
}

#[derive(Clone)]
pub struct BenchScenario {
    pub label: &'static str,
    pub desc: String,
    pub body: TxBody,
    pub shape: BenchShape,
}

pub struct StandardFixture {
    pub scenario: BenchScenario,
    pub air: TxLogicAir,
    pub trace: noid_air::Trace,
    pub pi: PublicInputs,
    pub spine_inputs: SpineInputs,
    pub auth_inputs: AuthInputs,
    pub auth_public: AuthPublicInputs,
    pub auth_proof: AuthProofKillShot,
    pub auth_slices: Vec<Vec<Block128>>,
}

pub struct SweepFixture {
    pub scenario: BenchScenario,
    pub air: noid_air::airs::Sweep25x2BalanceGateAir,
    pub trace: noid_air::Trace,
    pub pi: PublicInputs,
    pub auth_inputs: noid_gkr::SweepAuthInputs,
    pub auth_public: noid_gkr::SweepAuthPublicInputs,
    pub auth_slices: Vec<Vec<Block128>>,
    pub spine_inputs: noid_gkr::SweepSpineInputs,
}

pub struct StandardWalletBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof: LogicProof,
}

pub struct SweepWalletBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof: SweepLogicProof,
}

pub struct StandardBlockBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof_bytes: usize,
    pub standard_bucket_bytes: usize,
    pub per_tx_algebraic_bytes: usize,
    pub unified_spine_bytes: usize,
}

pub struct SweepBucketBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub bucket_bytes: usize,
    pub per_tx_algebraic_bytes: usize,
}

pub struct RecursiveStepBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof_bytes: usize,
    pub block_proof_bytes: usize,
    pub standard_bucket_bytes: usize,
    pub sweep_bucket_bytes: usize,
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
    let t = Instant::now();
    let r = f();
    (t.elapsed(), r)
}

pub fn time_median<F>(samples: usize, mut f: F) -> Duration
where
    F: FnMut(),
{
    let mut xs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let t = Instant::now();
        f();
        xs.push(t.elapsed());
    }
    median(xs)
}

pub fn mk_secret(seed: u128) -> SpendSecret {
    let lo = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_A5A5_A5A5_A5A5;
    let hi = seed.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A;
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&lo.to_le_bytes());
    bytes[16..].copy_from_slice(&hi.to_le_bytes());
    SpendSecret(bytes)
}

fn secret_fields(secret: &SpendSecret) -> [Block128; 2] {
    secret.as_fields()
}

fn standard_secrets(seed_base: u128) -> [SpendSecret; N_AUTH_INPUTS] {
    std::array::from_fn(|i| mk_secret(seed_base + i as u128 * 0x101))
}

fn sweep_secrets(seed_base: u128) -> Vec<SpendSecret> {
    (0..TxShape::Sweep25x2.max_inputs())
        .map(|i| mk_secret(seed_base + i as u128 * 0x101))
        .collect()
}

pub fn standard_scenario(
    label: &'static str,
    n_inputs: usize,
    n_outputs: usize,
    slot_base: u32,
    seed_base: u128,
) -> BenchScenario {
    assert!((1..=TxShape::Standard4x8.max_inputs()).contains(&n_inputs));
    assert!((1..=TxShape::Standard4x8.max_outputs()).contains(&n_outputs));
    let secrets = standard_secrets(seed_base);
    let mut inputs = Vec::with_capacity(MAX_INPUTS);
    let mut total_in = 0u64;
    for (i, secret) in secrets.iter().enumerate().take(n_inputs) {
        let value = 100_000 + (n_inputs - i) as u64 * 10_000;
        total_in += value;
        inputs.push(TxInput {
            slot_index: slot_base + i as u32,
            value,
            owner: derive_address(secret),
            spend_secret: secret.clone(),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        });
    }
    while inputs.len() < MAX_INPUTS {
        inputs.push(TxInput::dummy());
    }

    let fee = 5_000u128 + (n_inputs + n_outputs) as u128 * 500;
    let spendable = total_in - fee as u64;
    let mut outputs = Vec::with_capacity(MAX_OUTPUTS);
    let mut remaining = spendable;
    for j in 0..n_outputs {
        let value = if j + 1 == n_outputs {
            remaining
        } else {
            spendable / n_outputs as u64
        };
        remaining = remaining.saturating_sub(value);
        let owner = derive_address(&mk_secret(seed_base + 0x10_000 + j as u128));
        outputs.push(TxOutput {
            slot_index: slot_base + 1_000 + j as u32,
            value,
            owner,
            valid: true,
        });
    }
    while outputs.len() < MAX_OUTPUTS {
        outputs.push(TxOutput::dummy());
    }

    let mut body = TxBody {
        shape: TxShape::Standard4x8,
        epoch_anchor: [0xAA; 32],
        fee,
        inputs,
        outputs,
        is_coinbase: false,
    };
    let tx_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );
    for input in body.inputs.iter_mut().filter(|i| i.valid) {
        input.auth_tag = hash_auth_tag(&input.spend_secret, &tx_hash);
    }

    BenchScenario {
        label,
        desc: format!("Standard4x8: {n_inputs} inputs / {n_outputs} outputs"),
        body,
        shape: BenchShape::Standard,
    }
}

pub fn sweep_scenario(
    label: &'static str,
    n_inputs: usize,
    slot_base: u32,
    seed_base: u128,
) -> BenchScenario {
    assert!((5..=TxShape::Sweep25x2.max_inputs()).contains(&n_inputs));
    let secrets = sweep_secrets(seed_base);
    let mut inputs = Vec::with_capacity(n_inputs);
    let mut total_in = 0u64;
    for (i, secret) in secrets.iter().enumerate().take(n_inputs) {
        let value = 50_000_000 + (n_inputs - i) as u64 * 1_000;
        total_in += value;
        inputs.push(TxInput {
            slot_index: slot_base + i as u32,
            value,
            owner: derive_address(secret),
            spend_secret: secret.clone(),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        });
    }

    let fee = 18_500u128 + n_inputs as u128 * 250;
    let spendable = total_in - fee as u64;
    let outputs = vec![
        TxOutput {
            slot_index: slot_base + 50_000,
            value: spendable / 2,
            owner: derive_address(&mk_secret(seed_base + 0x20_000)),
            valid: true,
        },
        TxOutput {
            slot_index: slot_base + 50_001,
            value: spendable - spendable / 2,
            owner: derive_address(&mk_secret(seed_base + 0x20_001)),
            valid: true,
        },
    ];

    let mut body = TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor: [0xBB; 32],
        fee,
        inputs,
        outputs,
        is_coinbase: false,
    };
    let tx_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );
    for input in body.inputs.iter_mut().filter(|i| i.valid) {
        input.auth_tag = hash_auth_tag(&input.spend_secret, &tx_hash);
    }

    BenchScenario {
        label,
        desc: format!("Sweep25x2: {n_inputs} inputs / 2 outputs"),
        body,
        shape: BenchShape::Sweep,
    }
}

pub fn consolidation_scenario(
    label: &'static str,
    n_inputs: usize,
    slot_base: u32,
) -> BenchScenario {
    assert!((5..=TxShape::Sweep25x2.max_inputs()).contains(&n_inputs));
    let mut scenario = sweep_scenario(label, n_inputs, slot_base, 0xC0_000 + slot_base as u128);
    scenario.desc = format!("Sweep25x2 consolidation: {n_inputs} inputs / 1 output");
    let total_in: u64 = scenario
        .body
        .inputs
        .iter()
        .filter(|i| i.valid)
        .map(|i| i.value)
        .sum();
    let fee = scenario.body.fee as u64;
    scenario.body.outputs = vec![TxOutput {
        slot_index: slot_base + 60_000,
        value: total_in - fee,
        owner: derive_address(&mk_secret(0xC0FFEE + slot_base as u128)),
        valid: true,
    }];
    let tx_hash = hash_tx_body_for_shape(
        scenario.body.shape,
        &scenario.body.epoch_anchor,
        scenario.body.fee,
        &scenario.body.inputs,
        &scenario.body.outputs,
        scenario.body.is_coinbase,
    );
    for input in scenario.body.inputs.iter_mut().filter(|i| i.valid) {
        input.auth_tag = hash_auth_tag(&input.spend_secret, &tx_hash);
    }
    scenario
}

pub fn standard_fixture(scenario: BenchScenario) -> StandardFixture {
    assert_eq!(scenario.body.shape, TxShape::Standard4x8);
    let body = &scenario.body;
    let pins = boundary_pins_from_body(body);
    let air = TxLogicAir::new(pins);
    let trace = air.build_trace(&witness_from_body(body));
    assert!(air.check(&trace), "standard trace rejected by AIR");

    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for (i, input) in body.inputs.iter().filter(|i| i.valid).enumerate() {
        spend_secret[i] = secret_fields(&input.spend_secret);
    }
    let circuit = AuthCircuit::build();
    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&circuit, spend_secret, pins.tx_body_hash);
    let auth_inputs = AuthInputs {
        spend_secret,
        tx_body_hash: pins.tx_body_hash,
        expected_address,
        expected_auth_tag,
    };
    let auth_public = auth_inputs.to_public();
    let mut ch = auth_gkr_channel();
    let (auth_proof, _) = prove_auth_killshot(&circuit, &auth_inputs, &mut ch);
    let auth_mle = build_auth_unified_from_inputs(&circuit, &auth_inputs);
    let auth_slices = split_mle_into_slices(&auth_mle.state, N_AUTH_UNIFIED_VARS, BLOCK_BASE_LOG);

    let pi = public_inputs_for_body(body);
    let spine_inputs = SpineInputs {
        epoch_anchor: pins.epoch_anchor,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    };

    StandardFixture {
        scenario,
        air,
        trace,
        pi,
        spine_inputs,
        auth_inputs,
        auth_public,
        auth_proof,
        auth_slices,
    }
}

pub fn sweep_fixture(scenario: BenchScenario) -> SweepFixture {
    assert_eq!(scenario.body.shape, TxShape::Sweep25x2);
    let (air, trace, auth_inputs, spine_inputs) =
        sweep_logic_witness_parts_from_body(&scenario.body);
    assert!(air.check(&trace), "sweep trace rejected by AIR");
    let auth_public = auth_inputs.to_public();
    let auth_slices = build_sweep_auth_slices(&auth_inputs);
    let pi = public_inputs_for_body(&scenario.body);
    SweepFixture {
        scenario,
        air,
        trace,
        pi,
        auth_inputs,
        auth_public,
        auth_slices,
        spine_inputs,
    }
}

pub fn public_inputs_for_body(body: &TxBody) -> PublicInputs {
    let mut is_activation = [false; MAX_OUTPUTS];
    let mut is_deactivation = [false; MAX_INPUTS];
    if body.shape == TxShape::Standard4x8 {
        for (j, output) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
            is_activation[j] = output.valid;
        }
        for (i, input) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
            is_deactivation[i] = input.valid;
        }
    }
    PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash: hash_tx_body_for_shape(
            body.shape,
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        ),
        shape_id: body.shape.id(),
        fee: body.fee,
        n_live_inputs: body.inputs.iter().filter(|i| i.valid).count() as u8,
        n_live_outputs: body.outputs.iter().filter(|o| o.valid).count() as u8,
        coinbase_credit: 0,
        log_slots: BENCH_LOG_SLOTS,
        claims_commitment: compute_claims_commitment(&body.inputs, &body.outputs),
        is_activation,
        is_deactivation,
    }
}

pub fn tx_from_body(body: TxBody) -> Transaction {
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

pub fn prove_standard_wallet(f: &StandardFixture, samples: usize) -> StandardWalletBench {
    let witness = LogicWitness {
        air: &f.air,
        trace: &f.trace,
        pi: &f.pi,
        auth_inputs: &f.auth_inputs,
    };
    let prove_time = time_median(samples, || {
        let _ = prove_logic(&witness).expect("prove standard logic");
    });
    let proof = prove_logic(&witness).expect("prove standard logic");
    let verify_time = time_median(samples, || {
        verify_logic(&f.air, &f.pi, &f.spine_inputs, &f.auth_public, &proof)
            .expect("verify standard logic");
    });
    StandardWalletBench {
        prove_time,
        verify_time,
        proof,
    }
}

pub fn prove_sweep_wallet(f: &SweepFixture, samples: usize) -> SweepWalletBench {
    let witness = SweepLogicWitness {
        air: &f.air,
        trace: &f.trace,
        pi: &f.pi,
        auth_inputs: &f.auth_inputs,
        spine_inputs: &f.spine_inputs,
    };
    let prove_time = time_median(samples, || {
        let _ = prove_sweep_logic(&witness).expect("prove sweep logic");
    });
    let proof = prove_sweep_logic(&witness).expect("prove sweep logic");
    let verify_time = time_median(samples, || {
        verify_sweep_logic(&f.air, &f.pi, &f.spine_inputs, &f.auth_public, &proof)
            .expect("verify sweep logic");
    });
    SweepWalletBench {
        prove_time,
        verify_time,
        proof,
    }
}

pub fn standard_bundle(f: &StandardFixture, proof: LogicProof) -> WalletProofBundle {
    WalletProofBundle::Standard4x8(noid_stark::StandardWalletProofBundle {
        logic_proof: proof,
        auth_slices: f.auth_slices.clone(),
        auth_public: f.auth_public,
    })
}

pub fn sweep_bundle(f: &SweepFixture, proof: SweepLogicProof) -> WalletProofBundle {
    WalletProofBundle::Sweep25x2(SweepWalletProofBundle {
        logic_proof: proof,
        auth_slices: f.auth_slices.clone(),
        auth_public: f.auth_public,
    })
}

pub fn standard_block_witness<'a>(idx: u32, f: &'a StandardFixture) -> TxBlockWitness<'a> {
    TxBlockWitness {
        block_tx_index: idx,
        air: &f.air as &dyn Air,
        trace: &f.trace,
        pi: &f.pi,
        spine_inputs: &f.spine_inputs,
        auth_public: &f.auth_public,
        auth_proof: &f.auth_proof,
        auth_slices: &f.auth_slices,
    }
}

pub fn owned_sweep_witness(
    idx: u32,
    f: &SweepFixture,
    proof: SweepLogicProof,
) -> OwnedSweepTxWitness {
    let bundle = sweep_bundle(f, proof);
    match build_tx_witness(idx, &f.scenario.body, &bundle, BENCH_LOG_SLOTS) {
        OwnedTxWitness::Sweep25x2(w) => w,
        OwnedTxWitness::Standard4x8(_) => panic!("expected sweep witness"),
    }
}

pub fn bench_standard_block(fixtures: &[StandardFixture]) -> StandardBlockBench {
    bench_standard_block_with_total(fixtures, fixtures.len() as u32)
}

pub fn standard_block_proof_with_total(
    fixtures: &[StandardFixture],
    total_non_coinbase_tx: u32,
) -> (Duration, BlockProof) {
    let witnesses: Vec<_> = fixtures
        .iter()
        .enumerate()
        .map(|(i, f)| standard_block_witness(1 + i as u32, f))
        .collect();
    time_once(|| {
        prove_block_with_total_tx_count(
            BENCH_PREV_STATE_ROOT,
            BENCH_NEW_STATE_ROOT,
            &witnesses,
            &[],
            total_non_coinbase_tx,
        )
        .expect("prove standard block")
    })
}

pub fn bench_standard_block_with_total(
    fixtures: &[StandardFixture],
    total_non_coinbase_tx: u32,
) -> StandardBlockBench {
    let (prove_time, proof) = standard_block_proof_with_total(fixtures, total_non_coinbase_tx);
    let standard_bucket = proof.standard_bucket.as_ref().expect("standard bucket");
    let standard_bucket_bytes = standard_bucket.byte_len();
    let per_tx_algebraic_bytes = standard_bucket
        .tx_algebraic
        .first()
        .map_or(0, |a| a.byte_len());
    let unified_spine_bytes = standard_bucket.block_spine_proof.byte_len();

    let spine_inputs_list: Vec<_> = fixtures.iter().map(|f| f.spine_inputs.clone()).collect();
    let auth_public_list: Vec<_> = fixtures.iter().map(|f| f.auth_public).collect();
    let air_refs: Vec<&dyn Air> = fixtures.iter().map(|f| &f.air as &dyn Air).collect();
    let (verify_time, _) = time_once(|| {
        noid_block::verify_block(
            &air_refs,
            &proof,
            &spine_inputs_list,
            &auth_public_list,
            &[],
        )
        .expect("verify standard block")
    });

    StandardBlockBench {
        prove_time,
        verify_time,
        proof_bytes: proof.byte_len(),
        standard_bucket_bytes,
        per_tx_algebraic_bytes,
        unified_spine_bytes,
    }
}

pub fn sweep_bucket_proof(
    witnesses: &[OwnedSweepTxWitness],
) -> (Duration, noid_block::SweepBucketProof) {
    time_once(|| {
        assemble_sweep_bucket_proof(BENCH_PREV_STATE_ROOT, witnesses)
            .expect("assemble sweep bucket")
            .expect("non-empty sweep bucket")
    })
}

pub fn sweep_only_block_proof(witnesses: &[OwnedSweepTxWitness]) -> (Duration, BlockProof) {
    let (prove_time, bucket) = sweep_bucket_proof(witnesses);
    let meta = BlockPublicMeta {
        prev_block_state_root: BENCH_PREV_STATE_ROOT,
        new_state_root: BENCH_NEW_STATE_ROOT,
        n_tx: witnesses.len() as u32,
        n_air_per_tx: bucket.meta.n_air_per_tx,
        n_auth_slices_per_tx: bucket.meta.n_boundary_slices_per_tx,
        log_rows: bucket.meta.log_rows,
        n_block_spine_slices: bucket.meta.n_block_spine_slices,
        n_state_bindings: 0,
        state_binding_n_cols: 0,
        state_binding_log_rows: 0,
    };
    (
        prove_time,
        BlockProof {
            meta,
            standard_bucket: None,
            sweep_bucket: Some(bucket),
            state_binding_algebraics: vec![],
            state_binding_starks: vec![],
            pre_state_openings: vec![],
            post_state_openings: vec![],
        },
    )
}

pub fn mixed_block_proof(
    standard_fixtures: &[StandardFixture],
    sweep_witnesses: &[OwnedSweepTxWitness],
) -> (Duration, BlockProof) {
    assert!(
        sweep_witnesses
            .first()
            .map_or(true, |w| w.block_tx_index > standard_fixtures.len() as u32),
        "mixed sweep witnesses must be indexed after the standard bucket"
    );
    let total_non_coinbase_tx = (standard_fixtures.len() + sweep_witnesses.len()) as u32;
    let (standard_time, mut proof) =
        standard_block_proof_with_total(standard_fixtures, total_non_coinbase_tx);
    let (sweep_time, bucket) = sweep_bucket_proof(sweep_witnesses);
    proof.sweep_bucket = Some(bucket);
    (standard_time + sweep_time, proof)
}

pub fn bench_sweep_bucket(witnesses: &[OwnedSweepTxWitness]) -> SweepBucketBench {
    let (prove_time, bucket) = sweep_bucket_proof(witnesses);
    let airs: Vec<&dyn Air> = witnesses.iter().map(|w| &w.air as &dyn Air).collect();
    let (verify_time, _) = time_once(|| {
        verify_sweep_bucket_aggregation(&BENCH_PREV_STATE_ROOT, &airs, &bucket)
            .expect("verify sweep bucket aggregation")
    });
    let per_tx_algebraic_bytes = bucket.tx_algebraic.first().map_or(0, |a| a.byte_len());
    SweepBucketBench {
        prove_time,
        verify_time,
        bucket_bytes: bucket.byte_len(),
        per_tx_algebraic_bytes,
    }
}

fn recursive_bench_header(
    proof: &BlockProof,
    prev_header: &noid_chain::BlockHeader,
    height: u64,
) -> noid_chain::BlockHeader {
    noid_chain::BlockHeader {
        prev_block_hash: noid_chain::hash_block_header(prev_header),
        state_root: proof.meta.new_state_root,
        tx_root: [0u8; 32],
        timestamp: prev_header.timestamp + 1,
        height,
        miner_address: Address([0u8; 32]),
        nonce: 0,
        difficulty_target: [0xFFu8; 32],
        proof_transcript_hash: block_recursive_claim_hash(proof),
        witness_root: [0u8; 32],
        log_slots: BENCH_LOG_SLOTS,
        active_slot_count: proof.meta.n_tx as u64,
        alloc_counter: 0,
    }
}

fn primed_recursive_state() -> (noid_chain::BlockHeader, noid_recursive::RecursiveBlockProof) {
    let pre_acc = noid_recursive::genesis_accumulator(BENCH_PREV_STATE_ROOT, [0u8; 32]);
    let header = noid_chain::BlockHeader {
        prev_block_hash: [0u8; 32],
        state_root: BENCH_PREV_STATE_ROOT,
        tx_root: [0u8; 32],
        timestamp: 1,
        height: 0,
        miner_address: Address([0u8; 32]),
        nonce: 0,
        difficulty_target: [0xFFu8; 32],
        proof_transcript_hash: [1u8; 32],
        witness_root: [0u8; 32],
        log_slots: BENCH_LOG_SLOTS,
        active_slot_count: 0,
        alloc_counter: 0,
    };
    let proof = noid_recursive::prove_recursive_step(
        &noid_recursive::null_block_replay_witness(),
        &header,
        &pre_acc,
        None,
    );
    (header, proof)
}

pub fn bench_recursive_step(proof: &BlockProof) -> RecursiveStepBench {
    let (prev_header, prev_rec_proof) = primed_recursive_state();
    let prev_acc = prev_rec_proof.acc.clone();
    let header = recursive_bench_header(proof, &prev_header, prev_acc.height + 1);
    let block_witness = extract_replay_witness(proof).expect("extract recursive replay witness");

    let (prove_time, rec_proof) = time_once(|| {
        noid_recursive::prove_recursive_step(
            &block_witness,
            &header,
            &prev_acc,
            Some(&prev_rec_proof),
        )
    });
    let rec_air = noid_recursive::RecursiveBlockAir::from_prev_state_root(&prev_acc.state_root);
    let (verify_time, _) = time_once(|| {
        noid_recursive::verify_recursive_step(&rec_proof, &prev_acc, &header, &rec_air)
            .expect("verify recursive step")
    });

    RecursiveStepBench {
        prove_time,
        verify_time,
        proof_bytes: rec_proof.byte_len(),
        block_proof_bytes: proof.byte_len(),
        standard_bucket_bytes: proof
            .standard_bucket
            .as_ref()
            .map_or(0, noid_block::StandardBucketProof::byte_len),
        sweep_bucket_bytes: proof
            .sweep_bucket
            .as_ref()
            .map_or(0, noid_block::SweepBucketProof::byte_len),
    }
}

pub fn proof_size_standard(proof: &LogicProof) -> (usize, usize, usize) {
    let total = proof.estimated_byte_len();
    let auth = proof.auth.byte_len();
    let stark = total - auth;
    (total, stark, auth)
}

pub fn proof_size_sweep(proof: &SweepLogicProof) -> (usize, usize, usize, usize) {
    let total = proof.estimated_byte_len();
    let auth = proof.auth.byte_len();
    let spine = proof.spine.byte_len();
    let stark = total - auth - spine;
    (total, stark, auth, spine)
}

pub fn live_counts(body: &TxBody) -> (usize, usize) {
    (
        body.inputs.iter().filter(|i| i.valid).count(),
        body.outputs.iter().filter(|o| o.valid).count(),
    )
}

pub fn block_tx_hash_body(body: &TxBody) -> TxBodyHash {
    hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    )
}

pub fn canonical_sweep_spine_inputs(body: &TxBody) -> noid_gkr::SweepSpineInputs {
    sweep_spine_inputs_from_body(body)
}
