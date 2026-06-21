// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Shared benchmark fixtures for production standard/sweep proof paths.
//!
//! These helpers intentionally build real transaction bodies, real wallet logic
//! proofs, self-contained auth capsules, and real block-bucket witnesses. They are used by
//! `alice_sends_bob`, `block_scaling`, and `stark_report` so benchmark numbers
//! stay comparable across reports.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_air::composition::SweepTxLogicAir;
use noid_air::Air;
use noid_block::{
    assemble_sweep_bucket_proof, block_auth_sidecar_root, block_recursive_claim_hash,
    build_block_auth_sidecar, build_state_bindings_from_binding, build_tx_witness,
    extract_replay_witness, prove_block_with_total_tx_count, prove_state_bindings_standalone,
    split_auth_sidecar_for_buckets, verify_state_bindings_standalone,
    verify_sweep_bucket_aggregation, verify_sweep_bucket_from_block, BlockAuthSidecar, BlockProof,
    BlockPublicMeta, OwnedSweepTxWitness, OwnedTxWitness, TxBlockWitness,
};
use noid_chain::segmented_state::SegmentColumns;
use noid_chain::state::ChainState;
use noid_chain::state_binding::BlockStateBinding;
use noid_chain::{Block, BlockHeader, SlotValue};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_core::{Block128, TowerField};
use noid_gkr::{
    auth_gkr_channel, compute_auth_boundary, prove_auth_killshot, AuthCircuit, AuthInputs,
    AuthProofKillShot, AuthPublicInputs, SpineInputs, N_AUTH_INPUTS,
};
use noid_poseidon2b::primitives::{
    derive_address, hash_auth_tag, Address, AuthTag, SpendSecret, TxBodyHash,
};
use noid_stark::prove_logic::{prove_logic, verify_logic, LogicProof, LogicWitness};
use noid_stark::prove_logic_sweep::{
    prove_sweep_logic, sweep_logic_witness_parts_from_body, sweep_spine_inputs_from_body,
    verify_sweep_logic, SweepLogicProof, SweepLogicWitness,
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
}

pub struct SweepFixture {
    pub scenario: BenchScenario,
    pub air: SweepTxLogicAir,
    pub trace: noid_air::Trace,
    pub pi: PublicInputs,
    pub auth_inputs: noid_gkr::SweepAuthInputs,
    pub auth_public: noid_gkr::SweepAuthPublicInputs,
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
    /// Verifies bucket aggregation only. Use `FullBlockProofBench` for production
    /// block-proof verification including state binding.
    pub aggregation_verify_time: Duration,
    pub bucket_bytes: usize,
    pub block_spine_bytes: usize,
    pub tx_auth_proofs_bytes: usize,
    pub per_tx_auth_proof_bytes: usize,
    pub per_tx_algebraic_bytes: usize,
}

pub struct FullBlockProofBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof_bytes: usize,
    /// Public AuthGKR sidecar bytes bound by block.header.witness_root.
    pub auth_sidecar_bytes: usize,
    pub standard_bucket_bytes: usize,
    pub sweep_bucket_bytes: usize,
    pub state_binding_bytes: usize,
    /// Full production `BlockProof` produced by the benchmark path. Reports reuse
    /// this for recursive measurements so they bind the same state-binding and
    /// mixed-bucket proof bytes that block validation measured.
    pub proof: BlockProof,
    pub auth_sidecar: BlockAuthSidecar,
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

#[derive(Debug)]
struct BenchFullBlockPhaseTiming {
    name: &'static str,
    elapsed: Duration,
    mem: Option<MemSnapshot>,
    delta_rss_mb: Option<f64>,
}

#[derive(Debug)]
struct BenchFullBlockProfiler {
    enabled: bool,
    started: Instant,
    last: Instant,
    start_mem: Option<MemSnapshot>,
    last_mem: Option<MemSnapshot>,
    phases: Vec<BenchFullBlockPhaseTiming>,
}

impl BenchFullBlockProfiler {
    fn new() -> Self {
        let now = Instant::now();
        let enabled = std::env::var("NOID_PROVE_BLOCK_PROFILE")
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        let start_mem = if enabled {
            current_mem_snapshot()
        } else {
            None
        };
        Self {
            enabled,
            started: now,
            last: now,
            start_mem,
            last_mem: start_mem,
            phases: Vec::with_capacity(12),
        }
    }

    fn phase(&mut self, name: &'static str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let mem = current_mem_snapshot();
        let delta_rss_mb = match (mem, self.last_mem) {
            (Some(current), Some(previous)) => Some(current.delta_rss_mb(previous)),
            _ => None,
        };
        self.phases.push(BenchFullBlockPhaseTiming {
            name,
            elapsed: now.duration_since(self.last),
            mem,
            delta_rss_mb,
        });
        self.last = now;
        if mem.is_some() {
            self.last_mem = mem;
        }
    }

    fn finish(
        self,
        n_standard: usize,
        n_sweep: usize,
        n_sweep_witnesses: usize,
        n_state_bindings: usize,
        has_standard_bucket: bool,
        has_sweep_bucket: bool,
    ) {
        if !self.enabled {
            return;
        }
        let total = self.started.elapsed();
        let final_mem = current_mem_snapshot().or(self.last_mem);
        let summary = self
            .phases
            .iter()
            .map(|p| format!("{}={:.3}ms", p.name, p.elapsed.as_secs_f64() * 1_000.0))
            .collect::<Vec<_>>()
            .join(", ");
        for phase in &self.phases {
            eprintln!(
                "bench_full_block_profile phase n_standard={} n_sweep={} n_sweep_witnesses={} n_state_bindings={} phase={} elapsed_ms={:.3}{}",
                n_standard,
                n_sweep,
                n_sweep_witnesses,
                n_state_bindings,
                phase.name,
                phase.elapsed.as_secs_f64() * 1_000.0,
                profile_mem_fields(phase.mem, phase.delta_rss_mb)
            );
        }
        eprintln!(
            "bench_full_block_profile summary n_standard={} n_sweep={} n_sweep_witnesses={} n_state_bindings={} has_standard_bucket={} has_sweep_bucket={} total_ms={:.3} phases={}{}",
            n_standard,
            n_sweep,
            n_sweep_witnesses,
            n_state_bindings,
            has_standard_bucket,
            has_sweep_bucket,
            total.as_secs_f64() * 1_000.0,
            summary,
            profile_total_mem_fields(self.start_mem, final_mem)
        );
    }
}

fn profile_mem_fields(mem: Option<MemSnapshot>, delta_rss_mb: Option<f64>) -> String {
    let Some(mem) = mem else {
        return String::new();
    };
    match delta_rss_mb {
        Some(delta) => format!(
            " rss_mb={:.1} hwm_mb={:.1} delta_rss_mb={:+.1}",
            mem.rss_mb(),
            mem.hwm_mb(),
            delta
        ),
        None => format!(" rss_mb={:.1} hwm_mb={:.1}", mem.rss_mb(), mem.hwm_mb()),
    }
}

fn profile_total_mem_fields(
    start_mem: Option<MemSnapshot>,
    final_mem: Option<MemSnapshot>,
) -> String {
    let Some(final_mem) = final_mem else {
        return String::new();
    };
    match start_mem {
        Some(start_mem) => format!(
            " rss_mb={:.1} hwm_mb={:.1} delta_rss_mb={:+.1}",
            final_mem.rss_mb(),
            final_mem.hwm_mb(),
            final_mem.delta_rss_mb(start_mem)
        ),
        None => format!(
            " rss_mb={:.1} hwm_mb={:.1}",
            final_mem.rss_mb(),
            final_mem.hwm_mb()
        ),
    }
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
    }
}

pub fn sweep_fixture(scenario: BenchScenario) -> SweepFixture {
    assert_eq!(scenario.body.shape, TxShape::Sweep25x2);
    let (air, trace, auth_inputs, spine_inputs) =
        sweep_logic_witness_parts_from_body(&scenario.body);
    assert!(air.check(&trace), "sweep trace rejected by AIR");
    let auth_public = auth_inputs.to_public();
    let pi = public_inputs_for_body(&scenario.body);
    SweepFixture {
        scenario,
        air,
        trace,
        pi,
        auth_inputs,
        auth_public,
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

fn seed_state_for_bodies(bodies: &[TxBody]) -> ChainState {
    let mut state = ChainState::with_log_slots(BENCH_LOG_SLOTS as usize);
    let mut deltas = Vec::new();
    for input in bodies
        .iter()
        .flat_map(|body| body.inputs.iter().filter(|i| i.valid))
    {
        let [owner_hi, owner_lo] = input.owner.as_fields();
        deltas.push((
            input.slot_index,
            SlotValue {
                value: Block128::from(input.value as u128),
                owner_hi,
                owner_lo,
            },
        ));
        state.active_slot_count += 1;
    }
    state
        .state
        .apply_delta(&deltas)
        .expect("bench input slots in range");
    state
}

fn pre_segments_for_bodies(
    state: &ChainState,
    bodies: &[TxBody],
    coinbase_body: &TxBody,
) -> HashMap<u16, SegmentColumns> {
    let eff_log = state.state.effective_log_segment_size();
    let seg_size = 1usize << eff_log;
    let mut pre_segs = HashMap::new();
    for slot in bodies
        .iter()
        .chain(std::iter::once(coinbase_body))
        .flat_map(|body| {
            body.inputs
                .iter()
                .filter(|i| i.valid)
                .map(|i| i.slot_index)
                .chain(
                    body.outputs
                        .iter()
                        .filter(|o| o.valid)
                        .map(|o| o.slot_index),
                )
        })
    {
        let seg_id = (slot >> eff_log) as u16;
        pre_segs.entry(seg_id).or_insert_with(|| {
            state
                .state
                .try_get_segment_columns(seg_id)
                .cloned()
                .unwrap_or_else(|| SegmentColumns::new_zero(seg_size))
        });
    }
    pre_segs
}

fn bench_coinbase_body() -> TxBody {
    TxBody::standard(
        [0u8; 32],
        0,
        vec![],
        vec![TxOutput {
            slot_index: (1u32 << BENCH_LOG_SLOTS) - 1,
            value: 0,
            owner: Address([0xCB; 32]),
            valid: true,
        }],
        true,
    )
}

fn patch_binding_with_coinbase_root_and_siblings(
    binding: &mut BlockStateBinding,
    pre_state: &noid_chain::segmented_state::SegmentedFriState,
    mut post_state: noid_chain::segmented_state::SegmentedFriState,
    user_bodies: &[TxBody],
    coinbase_body: &TxBody,
) {
    for out in coinbase_body.outputs.iter().filter(|o| o.valid) {
        let [owner_hi, owner_lo] = out.owner.as_fields();
        post_state
            .set_slot(
                out.slot_index,
                SlotValue {
                    value: Block128::from(out.value as u128),
                    owner_hi,
                    owner_lo,
                },
            )
            .expect("bench coinbase slot in range");
    }

    // Mirrors noid_chain::consensus::template: root() flushes the post-state
    // Merkle tree before collecting per-segment siblings.
    binding.new_state_root = post_state.root();
    binding.tree_depth = post_state.tree_depth();
    if binding.tree_depth == 0 {
        return;
    }

    let eff_log = pre_state.effective_log_segment_size();
    let mut segs = HashSet::new();
    for body in user_bodies {
        for input in body.inputs.iter().filter(|i| i.valid) {
            segs.insert((input.slot_index >> eff_log) as u16);
        }
        for output in body.outputs.iter().filter(|o| o.valid) {
            segs.insert((output.slot_index >> eff_log) as u16);
        }
    }
    for output in coinbase_body.outputs.iter().filter(|o| o.valid) {
        segs.insert((output.slot_index >> eff_log) as u16);
    }

    for seg_id in segs {
        binding
            .pre_seg_siblings
            .insert(seg_id, pre_state.merkle_siblings(seg_id));
        binding
            .post_seg_siblings
            .insert(seg_id, post_state.merkle_siblings(seg_id));
    }
}

fn bench_block_from_parts(
    coinbase_body: TxBody,
    user_bodies: &[TxBody],
    proof: &BlockProof,
    auth_sidecar: &BlockAuthSidecar,
) -> Block {
    let coinbase = tx_from_body(coinbase_body);
    let mut transactions = Vec::with_capacity(user_bodies.len() + 1);
    transactions.push(coinbase);
    transactions.extend(user_bodies.iter().cloned().map(tx_from_body));
    let active_inputs = user_bodies
        .iter()
        .flat_map(|b| b.inputs.iter())
        .filter(|i| i.valid)
        .count() as u64;
    let active_outputs = user_bodies
        .iter()
        .flat_map(|b| b.outputs.iter())
        .filter(|o| o.valid)
        .count() as u64;
    let coinbase_outputs = transactions[0]
        .body
        .outputs
        .iter()
        .filter(|o| o.valid)
        .count() as u64;
    let proof_hash = block_recursive_claim_hash(proof);
    let mut block = Block {
        header: BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: proof.meta.new_state_root,
            tx_root: noid_chain::compute_tx_root(&transactions),
            timestamp: 2,
            height: 1,
            miner_address: Address([0xCB; 32]),
            nonce: 0,
            difficulty_target: [0xFF; 32],
            proof_transcript_hash: proof_hash,
            witness_root: [0u8; 32],
            log_slots: BENCH_LOG_SLOTS,
            active_slot_count: active_outputs + coinbase_outputs,
            alloc_counter: active_outputs
                + coinbase_outputs
                + active_inputs.saturating_sub(active_inputs),
        },
        transactions,
    };
    block.header.witness_root =
        block_auth_sidecar_root(&block, auth_sidecar).expect("bench sidecar root");
    block
}

fn prove_full_block_proof_once(
    standard_fixtures: &[StandardFixture],
    sweep_fixtures: &[SweepFixture],
    sweep_witnesses: &[OwnedSweepTxWitness],
) -> (BlockProof, Block, BlockAuthSidecar, ChainState) {
    let mut profiler = BenchFullBlockProfiler::new();
    let mut user_bodies: Vec<TxBody> = standard_fixtures
        .iter()
        .map(|f| f.scenario.body.clone())
        .collect();
    user_bodies.extend(sweep_fixtures.iter().map(|f| f.scenario.body.clone()));
    assert_eq!(sweep_fixtures.len(), sweep_witnesses.len());
    profiler.phase("body_clone");

    let mut pre_state = seed_state_for_bodies(&user_bodies);
    let prev_state_root = pre_state.state_root();
    let coinbase_body = bench_coinbase_body();
    let commitments: Vec<_> = user_bodies
        .iter()
        .map(|body| compute_claims_commitment(&body.inputs, &body.outputs))
        .collect();
    profiler.phase("seed_state_and_commitments");

    let mut binding_state = pre_state.state.clone();
    let mut binding = BlockStateBinding::build(&mut binding_state, &user_bodies, &commitments)
        .expect("build bench state binding");
    profiler.phase("state_binding_build");
    patch_binding_with_coinbase_root_and_siblings(
        &mut binding,
        &pre_state.state,
        binding_state,
        &user_bodies,
        &coinbase_body,
    );
    let pre_segs = pre_segments_for_bodies(&pre_state, &user_bodies, &coinbase_body);
    let owned_bindings = build_state_bindings_from_binding(
        &binding,
        &user_bodies,
        Some(&coinbase_body),
        &pre_segs,
        prev_state_root,
        user_bodies.len() as u32,
        BENCH_LOG_SLOTS,
    );
    let state_bindings: Vec<_> = owned_bindings.iter().map(|b| b.as_witness()).collect();
    profiler.phase("state_binding_witnesses");

    let standard_witnesses: Vec<_> = standard_fixtures
        .iter()
        .enumerate()
        .map(|(i, f)| standard_block_witness(1 + i as u32, f))
        .collect();
    let auth_sidecar =
        build_block_auth_sidecar(&standard_witnesses, sweep_witnesses).expect("bench auth sidecar");
    profiler.phase("standard_witnesses");

    let sweep_bucket = assemble_sweep_bucket_proof(prev_state_root, sweep_witnesses)
        .expect("assemble sweep bucket")
        .filter(|_| !sweep_witnesses.is_empty());
    profiler.phase("sweep_bucket_prove");

    let mut proof = if standard_witnesses.is_empty() {
        let (state_binding_starks, pre_state_openings, post_state_openings) =
            prove_state_bindings_standalone(&state_bindings);
        let bucket = sweep_bucket.expect("sweep-only block needs sweep bucket");
        BlockProof {
            meta: BlockPublicMeta {
                prev_block_state_root: prev_state_root,
                new_state_root: binding.new_state_root,
                n_tx: user_bodies.len() as u32,
                n_air_per_tx: 0,
                n_auth_slices_per_tx: 0,
                log_rows: noid_air::airs::tx_body_spine::SPINE_LOG_ROWS as u32,
                n_block_spine_slices: 0,
                n_state_bindings: state_bindings.len() as u32,
                state_binding_n_cols: 0,
                state_binding_log_rows: 0,
            },
            standard_bucket: None,
            sweep_bucket: Some(bucket),
            state_binding_algebraics: vec![],
            state_binding_starks,
            pre_state_openings,
            post_state_openings,
        }
    } else {
        let mut proof = prove_block_with_total_tx_count(
            prev_state_root,
            binding.new_state_root,
            &standard_witnesses,
            &state_bindings,
            user_bodies.len() as u32,
        )
        .expect("prove full standard/mixed block");
        proof.sweep_bucket = sweep_bucket;
        proof
    };
    profiler.phase("core_proof");

    let block = bench_block_from_parts(coinbase_body, &user_bodies, &proof, &auth_sidecar);
    proof.meta.new_state_root = block.header.state_root;
    profiler.phase("block_assembly");
    profiler.finish(
        standard_fixtures.len(),
        sweep_fixtures.len(),
        sweep_witnesses.len(),
        state_bindings.len(),
        proof.standard_bucket.is_some(),
        proof.sweep_bucket.is_some(),
    );
    (proof, block, auth_sidecar, pre_state)
}

pub fn bench_full_block_proof(
    standard_fixtures: &[StandardFixture],
    sweep_fixtures: &[SweepFixture],
    sweep_witnesses: &[OwnedSweepTxWitness],
) -> FullBlockProofBench {
    let (prove_time, (proof, block, auth_sidecar, pre_state)) = time_once(|| {
        prove_full_block_proof_once(standard_fixtures, sweep_fixtures, sweep_witnesses)
    });
    let (verify_time, _) = time_once(|| {
        noid_block::validate_block_auth_sidecar_root(&block, &auth_sidecar)
            .expect("auth sidecar root");
        let (standard_auth_proofs, sweep_auth_proofs) =
            split_auth_sidecar_for_buckets(&block, &proof, &auth_sidecar)
                .expect("split auth sidecar");
        if proof.sweep_bucket.is_some() {
            verify_sweep_bucket_from_block(&block, &proof, &sweep_auth_proofs)
                .expect("verify sweep bucket from block");
        }
        let sb_airs = noid_block::build_state_binding_airs(&block, &proof, &pre_state.state)
            .expect("build verifier state binding AIRs");
        let sb_refs: Vec<&noid_air::airs::block_state_binding::BlockStateBindingAir> =
            sb_airs.iter().collect();
        if proof.standard_bucket.is_some() {
            let spine = noid_block::build_spine_inputs_list(&block);
            let auth = noid_block::build_auth_public_list(&block, &proof);
            let tx_airs = noid_block::build_tx_airs(&block);
            let air_refs: Vec<&dyn Air> = tx_airs.iter().map(|a| a as &dyn Air).collect();
            noid_block::verify_block(
                &air_refs,
                &proof,
                &spine,
                &auth,
                &standard_auth_proofs,
                &sb_refs,
            )
            .expect("verify full standard/mixed block proof");
        } else {
            verify_state_bindings_standalone(&proof, &sb_refs)
                .expect("verify sweep-only standalone state binding");
        }
    });
    let state_binding_bytes = proof
        .state_binding_starks
        .iter()
        .map(|p| p.byte_len())
        .sum::<usize>()
        + proof
            .state_binding_algebraics
            .iter()
            .map(|p| p.byte_len())
            .sum::<usize>()
        + proof
            .pre_state_openings
            .iter()
            .map(|p| p.byte_len())
            .sum::<usize>()
        + proof
            .post_state_openings
            .iter()
            .map(|p| p.byte_len())
            .sum::<usize>();
    let proof_bytes = proof.byte_len();
    let auth_sidecar_bytes = auth_sidecar.byte_len();
    let standard_bucket_bytes = proof
        .standard_bucket
        .as_ref()
        .map_or(0, noid_block::StandardBucketProof::byte_len);
    let sweep_bucket_bytes = proof
        .sweep_bucket
        .as_ref()
        .map_or(0, noid_block::SweepBucketProof::byte_len);
    FullBlockProofBench {
        prove_time,
        verify_time,
        proof_bytes,
        auth_sidecar_bytes,
        standard_bucket_bytes,
        sweep_bucket_bytes,
        state_binding_bytes,
        proof,
        auth_sidecar,
    }
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
        auth_public: f.auth_public,
    })
}

pub fn sweep_bundle(f: &SweepFixture, proof: SweepLogicProof) -> WalletProofBundle {
    WalletProofBundle::Sweep25x2(SweepWalletProofBundle {
        logic_proof: proof,
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
    let auth_proofs: Vec<_> = fixtures.iter().map(|f| f.auth_proof.clone()).collect();
    let air_refs: Vec<&dyn Air> = fixtures.iter().map(|f| &f.air as &dyn Air).collect();
    let (verify_time, _) = time_once(|| {
        noid_block::verify_block(
            &air_refs,
            &proof,
            &spine_inputs_list,
            &auth_public_list,
            &auth_proofs,
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
    let auth_public: Vec<_> = witnesses.iter().map(|w| w.auth_public).collect();
    let auth_proofs: Vec<_> = witnesses.iter().map(|w| w.auth_proof.clone()).collect();
    let spine_inputs: Vec<_> = witnesses.iter().map(|w| w.spine_inputs.clone()).collect();
    let (aggregation_verify_time, _) = time_once(|| {
        verify_sweep_bucket_aggregation(
            &BENCH_PREV_STATE_ROOT,
            &airs,
            &bucket,
            &auth_public,
            &auth_proofs,
            &spine_inputs,
        )
        .expect("verify sweep bucket aggregation")
    });
    let per_tx_algebraic_bytes = bucket.tx_algebraic.first().map_or(0, |a| a.byte_len());
    let block_spine_bytes = bucket.block_spine_proof.byte_len();
    let tx_auth_proofs_bytes: usize = auth_proofs.iter().map(|p| p.byte_len()).sum();
    let per_tx_auth_proof_bytes = auth_proofs.first().map_or(0, |p| p.byte_len());
    SweepBucketBench {
        prove_time,
        aggregation_verify_time,
        bucket_bytes: bucket.byte_len(),
        block_spine_bytes,
        tx_auth_proofs_bytes,
        per_tx_auth_proof_bytes,
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
    let wallet_spine = 0;
    let stark = total - auth;
    (total, stark, auth, wallet_spine)
}

pub fn standard_wallet_bundle_size(f: &StandardFixture, proof: &LogicProof) -> usize {
    standard_bundle(f, proof.clone()).to_bytes().len()
}

pub fn sweep_wallet_bundle_size(f: &SweepFixture, proof: &SweepLogicProof) -> usize {
    sweep_bundle(f, proof.clone()).to_bytes().len()
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
