// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Shared benchmark fixtures for production transaction proof-shape paths.
//!
//! These helpers intentionally build real transaction bodies, self-contained
//! authorization capsules, and minimal production block proofs.
//! They are used by `alice_sends_bob`, `block_scaling`, and `block_hotspots`
//! so benchmark numbers stay comparable across reports.

use std::time::{Duration, Instant};

use noid_block::{
    build_exact_state_transition_proof, verify_exact_state_transition, BlockAuthSidecar,
    BlockProof, ExactStateTransitionInputs,
};
use noid_chain::exact_state_hash::slot_leaf_hash;
use noid_chain::sparse_merkle::reconstruct_root;
use noid_chain::state::ChainState;
use noid_chain::{Block, BlockHeader, SlotValue};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_core::Block128;
use noid_gkr::{
    owner_auth_gkr_channel, owner_auth_inputs_from_body_and_live_secrets,
    prove_owner_auth_killshot, spine_inputs_from_body, sweep_spine_inputs_from_body,
    verify_owner_auth_killshot, OwnerAuthCircuit, OwnerAuthInputs, OwnerAuthProofKillShot,
    OwnerAuthPublicInputs, SpineInputs, WalletAuthorizationBundle,
};
use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret, TxBodyHash};
use noid_tx::{
    compute_claims_commitment, hash_tx_body_for_shape, PublicInputs, Transaction, TxBody, TxInput,
    TxOutput, TxShape, MAX_INPUTS, MAX_OUTPUTS,
};

pub const BENCH_LOG_SLOTS: u32 = 24;
pub const BENCH_PREV_STATE_ROOT: [u8; 32] = [0x11; 32];

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
    pub pi: PublicInputs,
    pub spine_inputs: SpineInputs,
    pub auth_inputs: OwnerAuthInputs,
    pub auth_public: OwnerAuthPublicInputs,
    pub auth_proof: OwnerAuthProofKillShot,
}

pub struct SweepFixture {
    pub scenario: BenchScenario,
    pub pi: PublicInputs,
    pub auth_inputs: OwnerAuthInputs,
    pub auth_public: OwnerAuthPublicInputs,
    pub spine_inputs: noid_gkr::SweepSpineInputs,
}

#[derive(Clone)]
pub struct MinimalTxFixture {
    pub scenario: BenchScenario,
    pub auth_proof: OwnerAuthProofKillShot,
}

pub struct StandardWalletBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof: OwnerAuthProofKillShot,
}

pub struct SweepWalletBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof: OwnerAuthProofKillShot,
}

pub struct FullBlockProofBench {
    pub prove_time: Duration,
    pub verify_time: Duration,
    pub proof_bytes: usize,
    /// Public authorization sidecar bytes carried as detached validation witness.
    pub auth_sidecar_bytes: usize,
    pub state_transition_bytes: usize,
    /// Minimal production `BlockProof` produced by the benchmark path.
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

/// A builder-produced Poseidon2b chain circuit of `chain` permutations —
/// the representative FieldR1cs instance shape: real verifier-replay traces
/// are builder-produced single-block (`m = k_log`) circuits dominated by
/// Poseidon2b permutation gadgets, with the same coefficient density
/// (~20 nnz/row across A+B) and strong wire locality. Synthetic multi-block
/// instances understate both, so throughput gates must run on this shape.
pub fn poseidon_chain_field_instance(
    chain: usize,
) -> (
    noid_ivc_prover::field_r1cs::FieldR1cs,
    Vec<noid_ivc_prover::field::F128>,
) {
    use noid_ivc_prover::field_circuit::{LinExpr, flat_const, poseidon2b_permute};
    use noid_poseidon2b::native::permutation::{Poseidon2bPermutation, STATE_SIZE};
    use noid_recursive::acceptance::trace::FieldR1csBuilder;

    let seed: [Block128; STATE_SIZE] =
        std::array::from_fn(|i| Block128(0x1234_5678_9abc_def0 + i as u128));
    let mut expected = seed;
    for _ in 0..chain {
        Poseidon2bPermutation.permute_mut(&mut expected);
    }
    let mut b = FieldR1csBuilder::new();
    let mut state: [LinExpr; STATE_SIZE] =
        std::array::from_fn(|i| LinExpr::from_wire(b.alloc_f128(flat_const(seed[i].0))));
    for _ in 0..chain {
        state = poseidon2b_permute(&mut b, state);
    }
    for lane in state.iter() {
        let v = lane.eval(b.values());
        b.pin_f128(lane, v);
    }
    b.build()
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
        let enabled = profile_env_enabled("NOID_BENCH_FULL_BLOCK_PROFILE")
            || profile_env_enabled("NOID_PROVE_BLOCK_PROFILE");
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

    fn finish(self, n_standard: usize, n_sweep: usize, n_sweep_witnesses: usize) {
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
                "bench_full_block_profile phase n_standard={} n_sweep={} n_sweep_witnesses={} phase={} elapsed_ms={:.3}{}",
                n_standard,
                n_sweep,
                n_sweep_witnesses,
                phase.name,
                phase.elapsed.as_secs_f64() * 1_000.0,
                profile_mem_fields(phase.mem, phase.delta_rss_mb)
            );
        }
        eprintln!(
            "bench_full_block_profile summary n_standard={} n_sweep={} n_sweep_witnesses={} total_ms={:.3} phases={}{}",
            n_standard,
            n_sweep,
            n_sweep_witnesses,
            total.as_secs_f64() * 1_000.0,
            summary,
            profile_total_mem_fields(self.start_mem, final_mem)
        );
    }
}

fn profile_env_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
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

fn standard_secrets(seed_base: u128) -> [SpendSecret; MAX_INPUTS] {
    // One owner per tx (consensus rule): every live input shares the
    // tx's single address, so all input slots carry the SAME secret.
    std::array::from_fn(|_| mk_secret(seed_base))
}

fn sweep_secrets(seed_base: u128) -> Vec<SpendSecret> {
    // One owner per tx (consensus rule): one secret for every input slot.
    (0..TxShape::Sweep25x2.max_inputs())
        .map(|_| mk_secret(seed_base))
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
            creation_id: 0,
            owner: derive_address(secret),
            spend_secret: secret.clone(),
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

    let body = TxBody {
        shape: TxShape::Standard4x8,
        epoch_anchor: [0xAA; 32],
        fee,
        inputs,
        outputs,
        is_coinbase: false,
    };

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
            creation_id: 0,
            owner: derive_address(secret),
            spend_secret: secret.clone(),
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

    let body = TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor: [0xBB; 32],
        fee,
        inputs,
        outputs,
        is_coinbase: false,
    };

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
    scenario
}

pub fn standard_fixture(scenario: BenchScenario) -> StandardFixture {
    assert_eq!(scenario.body.shape, TxShape::Standard4x8);
    let body = &scenario.body;
    noid_tx::validate_public_tx_logic(body).expect("standard public logic");

    let live_secrets: Vec<_> = body
        .inputs
        .iter()
        .filter(|i| i.valid)
        .map(|input| input.spend_secret.clone())
        .collect();
    let auth_inputs = owner_auth_inputs_from_body_and_live_secrets(body, &live_secrets)
        .expect("standard owner auth inputs from bench body");
    let auth_public = auth_inputs.to_public();
    let circuit = OwnerAuthCircuit::build(auth_inputs.layout);
    let mut ch = owner_auth_gkr_channel();
    let (auth_proof, _) = prove_owner_auth_killshot(&circuit, &auth_inputs, &mut ch);

    let pi = public_inputs_for_body(body);
    let spine_inputs = spine_inputs_from_body(body).expect("standard spine statement");

    StandardFixture {
        scenario,
        pi,
        spine_inputs,
        auth_inputs,
        auth_public,
        auth_proof,
    }
}

pub fn sweep_fixture(scenario: BenchScenario) -> SweepFixture {
    assert_eq!(scenario.body.shape, TxShape::Sweep25x2);
    noid_tx::validate_public_tx_logic(&scenario.body).expect("sweep public logic");
    let live_secrets: Vec<_> = scenario
        .body
        .inputs
        .iter()
        .filter(|i| i.valid)
        .map(|input| input.spend_secret.clone())
        .collect();
    let auth_inputs = owner_auth_inputs_from_body_and_live_secrets(&scenario.body, &live_secrets)
        .expect("sweep owner auth inputs from bench body");
    let spine_inputs =
        sweep_spine_inputs_from_body(&scenario.body).expect("sweep spine inputs from bench body");
    let auth_public = auth_inputs.to_public();
    let pi = public_inputs_for_body(&scenario.body);
    SweepFixture {
        scenario,
        pi,
        auth_inputs,
        auth_public,
        spine_inputs,
    }
}

pub fn minimal_tx_fixture(scenario: BenchScenario) -> MinimalTxFixture {
    let body = &scenario.body;
    let live_secrets: Vec<_> = body
        .inputs
        .iter()
        .filter(|i| i.valid)
        .map(|input| input.spend_secret.clone())
        .collect();
    let auth_inputs = owner_auth_inputs_from_body_and_live_secrets(body, &live_secrets)
        .expect("owner auth inputs from bench body");
    let circuit = OwnerAuthCircuit::build(auth_inputs.layout);
    let mut ch = owner_auth_gkr_channel();
    let (auth_proof, _) = prove_owner_auth_killshot(&circuit, &auth_inputs, &mut ch);
    MinimalTxFixture {
        scenario,
        auth_proof,
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
    let mut slots = Vec::new();
    for input in bodies
        .iter()
        .flat_map(|body| body.inputs.iter().filter(|i| i.valid))
    {
        slots.push((
            input.slot_index,
            SlotValue::with_owner_fields(
                input.value,
                input.creation_id,
                input.owner.as_fields(),
            ),
        ));
    }
    // These benchmark fixtures intentionally use creation_id=0 inputs
    // and model a zero-counter parent.
    ChainState::from_sparse_utxos(BENCH_LOG_SLOTS as usize, &slots, 0)
        .expect("bench input slots form a valid sparse UTXO state")
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

fn bench_block_from_parts(
    coinbase_body: TxBody,
    user_bodies: &[TxBody],
    proof: &BlockProof,
) -> Block {
    let profile = profile_env_enabled("NOID_BENCH_FULL_BLOCK_PROFILE")
        || profile_env_enabled("NOID_PROVE_BLOCK_PROFILE");
    let assembly_started = Instant::now();
    let mut last = assembly_started;
    let mut phase = |name: &'static str| {
        if profile {
            let now = Instant::now();
            eprintln!(
                "bench_block_assembly_profile phase={} elapsed_ms={:.3}",
                name,
                now.duration_since(last).as_secs_f64() * 1_000.0
            );
            last = now;
        }
    };

    let coinbase = tx_from_body(coinbase_body);
    let mut transactions = Vec::with_capacity(user_bodies.len() + 1);
    transactions.push(coinbase);
    transactions.extend(user_bodies.iter().cloned().map(tx_from_body));
    phase("tx_hashes");
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
    phase("counts");
    let tx_root = noid_chain::compute_tx_root(&transactions);
    phase("tx_root");
    let block = Block {
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
            active_slot_count: active_outputs + coinbase_outputs,
            alloc_counter: active_outputs
                + coinbase_outputs
                + active_inputs.saturating_sub(active_inputs),
        },
        transactions,
    };
    phase("block_struct");
    if profile {
        eprintln!(
            "bench_block_assembly_profile summary total_ms={:.3}",
            assembly_started.elapsed().as_secs_f64() * 1_000.0
        );
    }
    block
}

fn prove_full_block_from_bodies_and_auth(
    pre_state: ChainState,
    user_bodies: Vec<TxBody>,
    tx_auth: Vec<OwnerAuthProofKillShot>,
    n_standard: usize,
    n_sweep: usize,
    n_sweep_witnesses: usize,
) -> (BlockProof, Block, BlockAuthSidecar, ChainState) {
    assert_eq!(user_bodies.len(), tx_auth.len());
    let mut profiler = BenchFullBlockProfiler::new();
    // The parent root is a cached read: a live miner takes it from the
    // parent header, and the seeded fixture state arrives with its cache
    // built (`state_root()` would rebuild the whole sparse cache).
    let prev_state_root = pre_state.cached_state_root();
    let coinbase_body = bench_coinbase_body();
    profiler.phase("prev_root_and_coinbase");

    let all_state_bodies: Vec<_> = std::iter::once(coinbase_body.clone())
        .chain(user_bodies.iter().cloned())
        .collect();
    let all_state_commitments: Vec<_> = all_state_bodies
        .iter()
        .map(|body| compute_claims_commitment(&body.inputs, &body.outputs))
        .collect();
    profiler.phase("state_claim_commitments");
    let exact_surface = noid_chain::build_exact_action_surface(
        &pre_state.state,
        &all_state_bodies,
        &all_state_commitments,
        pre_state.alloc_counter,
    )
    .expect("build bench exact state surface");
    profiler.phase("exact_action_surface");
    let exact_cache = pre_state
        .state
        .exact_sparse_cache()
        .expect("build bench exact sparse cache");
    profiler.phase("exact_sparse_cache");
    let exact_state_transition = build_exact_state_transition_proof(&exact_cache, &exact_surface)
        .expect("build bench exact state proof");
    profiler.phase("exact_transition_proof");
    // Child roots from the multiproof frontier — O(touched · depth), the
    // same reconstruction the verifier runs. Cloning the whole sparse
    // cache and re-setting every touched leaf measures cache-maintenance
    // work, not block-proving work.
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
    .expect("bench child state root from multiproof frontier");
    profiler.phase("child_root_reconstruct");

    let auth_sidecar = BlockAuthSidecar { tx_auth };
    profiler.phase("auth_sidecar");

    let mut proof = BlockProof::minimal(
        prev_state_root,
        new_state_root,
        user_bodies.len() as u32,
        exact_state_transition.clone(),
    );
    profiler.phase("core_proof");

    let block = bench_block_from_parts(coinbase_body, &user_bodies, &proof);
    proof.meta.new_state_root = block.header.state_root;
    profiler.phase("block_assembly");
    profiler.finish(n_standard, n_sweep, n_sweep_witnesses);
    (proof, block, auth_sidecar, pre_state)
}

pub fn bench_full_block_proof_minimal(fixtures: &[MinimalTxFixture]) -> FullBlockProofBench {
    let (n_standard, n_sweep) =
        fixtures
            .iter()
            .fold(
                (0usize, 0usize),
                |(standard, sweep), fixture| match fixture.scenario.body.shape {
                    TxShape::Standard4x8 => (standard + 1, sweep),
                    TxShape::Sweep25x2 => (standard, sweep + 1),
                },
            );
    // Fixture prep is untimed: body/auth clones and the seeded parent
    // state are bench inputs — a live miner starts from the state it
    // already holds in memory, so seeding one is not block-time work.
    let user_bodies = fixtures
        .iter()
        .map(|f| f.scenario.body.clone())
        .collect::<Vec<_>>();
    let tx_auth = fixtures
        .iter()
        .map(|f| f.auth_proof.clone())
        .collect::<Vec<_>>();
    let pre_state = seed_state_for_bodies(&user_bodies);
    let (prove_time, (proof, block, auth_sidecar, pre_state)) = time_once(move || {
        prove_full_block_from_bodies_and_auth(
            pre_state,
            user_bodies,
            tx_auth,
            n_standard,
            n_sweep,
            n_sweep,
        )
    });
    let (verify_time, _) = time_once(|| {
        noid_block::validate_block_authorizations(
            &block,
            &auth_sidecar,
            &noid_block::OwnerAuthAuthorizationVerifier,
        )
        .expect("verify block authorizations");

        let exact_bodies: Vec<TxBody> = block
            .transactions
            .iter()
            .map(|tx| tx.body.clone())
            .collect();
        let exact_commitments: Vec<_> = exact_bodies
            .iter()
            .map(|body| compute_claims_commitment(&body.inputs, &body.outputs))
            .collect();
        let exact_surface = noid_chain::build_exact_action_surface(
            &pre_state.state,
            &exact_bodies,
            &exact_commitments,
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
    let state_transition_bytes = proof.state_transition.byte_len();
    let proof_bytes = proof.byte_len();
    let auth_sidecar_bytes = auth_sidecar.byte_len();
    FullBlockProofBench {
        prove_time,
        verify_time,
        proof_bytes,
        auth_sidecar_bytes,
        state_transition_bytes,
        proof,
        auth_sidecar,
    }
}

pub fn prove_standard_wallet(f: &StandardFixture, samples: usize) -> StandardWalletBench {
    let circuit = OwnerAuthCircuit::build(f.auth_inputs.layout);
    let prove_time = time_median(samples, || {
        let mut ch = owner_auth_gkr_channel();
        let _ = prove_owner_auth_killshot(&circuit, &f.auth_inputs, &mut ch);
    });
    let mut ch = owner_auth_gkr_channel();
    let (proof, _) = prove_owner_auth_killshot(&circuit, &f.auth_inputs, &mut ch);
    let verify_time = time_median(samples, || {
        let mut ch = owner_auth_gkr_channel();
        verify_owner_auth_killshot(&proof, &circuit, &f.auth_public, &mut ch)
            .expect("verify standard authorization");
    });
    StandardWalletBench {
        prove_time,
        verify_time,
        proof,
    }
}

pub fn prove_sweep_wallet(f: &SweepFixture, samples: usize) -> SweepWalletBench {
    let circuit = OwnerAuthCircuit::build(f.auth_inputs.layout);
    let prove_time = time_median(samples, || {
        let mut ch = owner_auth_gkr_channel();
        let _ = prove_owner_auth_killshot(&circuit, &f.auth_inputs, &mut ch);
    });
    let mut ch = owner_auth_gkr_channel();
    let (proof, _) = prove_owner_auth_killshot(&circuit, &f.auth_inputs, &mut ch);
    let verify_time = time_median(samples, || {
        let mut ch = owner_auth_gkr_channel();
        verify_owner_auth_killshot(&proof, &circuit, &f.auth_public, &mut ch)
            .expect("verify sweep authorization");
    });
    SweepWalletBench {
        prove_time,
        verify_time,
        proof,
    }
}

pub fn prove_sweep_wallet_once(f: &SweepFixture) -> OwnerAuthProofKillShot {
    let circuit = OwnerAuthCircuit::build(f.auth_inputs.layout);
    let mut ch = owner_auth_gkr_channel();
    let (proof, _) = prove_owner_auth_killshot(&circuit, &f.auth_inputs, &mut ch);
    proof
}

pub fn standard_bundle(
    _f: &StandardFixture,
    proof: OwnerAuthProofKillShot,
) -> WalletAuthorizationBundle {
    WalletAuthorizationBundle { proof }
}

pub fn sweep_bundle(_f: &SweepFixture, proof: OwnerAuthProofKillShot) -> WalletAuthorizationBundle {
    WalletAuthorizationBundle { proof }
}

pub fn authorization_size(proof: &OwnerAuthProofKillShot) -> usize {
    proof.byte_len()
}

pub fn standard_wallet_bundle_size(f: &StandardFixture, proof: &OwnerAuthProofKillShot) -> usize {
    standard_bundle(f, proof.clone())
        .to_bytes()
        .expect("serialize standard authorization")
        .len()
}

pub fn sweep_wallet_bundle_size(f: &SweepFixture, proof: &OwnerAuthProofKillShot) -> usize {
    sweep_bundle(f, proof.clone())
        .to_bytes()
        .expect("serialize sweep authorization")
        .len()
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
    sweep_spine_inputs_from_body(body).expect("canonical sweep spine inputs")
}
