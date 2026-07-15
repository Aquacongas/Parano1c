// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared benchmark fixtures for the canonical Tx8x2 and Field-R1CS paths.
//!
//! The `HistoryStep` pack generator builds its own one-shot freezing inputs.

use std::time::{Duration, Instant};

use noid_core::Block128;
use noid_gkr::zk_authorization::ZkAuthorizationProof;
use noid_gkr::{
    prove_wallet_authorization, verify_wallet_authorization_proof, OwnerAuthWitness,
    WalletAuthorizationBundle,
};
use noid_poseidon2b::primitives::{derive_address, SpendSecret, TxBodyHash};
use noid_tx::{output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

pub const BENCH_LOG_SLOTS: u32 = 24;
pub const B255_EIGHT_INPUT_TXS: usize = 85;
pub const B255_TWO_INPUT_TXS: usize = 170;

#[derive(Clone)]
pub struct BenchScenario {
    pub label: &'static str,
    pub desc: String,
    pub body: TxBody,
    /// Public deterministic seed used to recreate a fresh, consuming wallet
    /// proving authority for each sample.
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

pub fn fmt_ms(duration: Duration) -> String {
    let milliseconds = duration.as_secs_f64() * 1_000.0;
    if milliseconds >= 1_000.0 {
        format!("{:>8.2} s ", milliseconds / 1_000.0)
    } else {
        format!("{:>8.2} ms", milliseconds)
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

pub fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

pub fn time_once<F, R>(operation: F) -> (Duration, R)
where
    F: FnOnce() -> R,
{
    let started = Instant::now();
    let value = operation();
    (started.elapsed(), value)
}

pub fn time_median<F>(samples: usize, mut operation: F) -> Duration
where
    F: FnMut(),
{
    assert!(samples > 0);
    let mut timings = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        operation();
        timings.push(started.elapsed());
    }
    median(timings)
}

/// Representative Field-R1CS shape used by prover microbenchmarks.
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
        std::array::from_fn(|index| Block128(0x1234_5678_9abc_def0 + index as u128));
    let mut expected = seed;
    for _ in 0..chain {
        Poseidon2bPermutation.permute_mut(&mut expected);
    }
    let mut builder = FieldR1csBuilder::new();
    let mut state: [LinExpr; STATE_SIZE] = std::array::from_fn(|index| {
        LinExpr::from_wire(builder.alloc_f128(flat_const(seed[index].0)))
    });
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
    let low = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_A5A5_A5A5_A5A5;
    let high = seed.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A;
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&low.to_le_bytes());
    bytes[16..].copy_from_slice(&high.to_le_bytes());
    SpendSecret::from_bytes(bytes)
}

/// Build one canonical Tx8x2 scenario with `1..=8` live inputs and `1..=2`
/// live outputs. All inputs share the address derived from one secret.
pub fn tx8x2_scenario(
    label: &'static str,
    input_count: usize,
    output_count: usize,
    slot_base: u32,
    seed: u128,
) -> BenchScenario {
    assert!((1..=TX_INPUTS).contains(&input_count));
    assert!((1..=TX_OUTPUTS).contains(&output_count));

    let spend_secret = mk_secret(seed);
    let input_owner = derive_address(&spend_secret);
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    let mut input_sum = 0u64;
    let mut validity_bitmap = 0u16;
    for (index, input) in inputs.iter_mut().enumerate().take(input_count) {
        let amount = 100_000 + (input_count - index) as u64 * 10_000;
        input_sum = input_sum.checked_add(amount).expect("benchmark input sum");
        *input = TxInput {
            slot_index: slot_base + index as u32,
            amount,
            creation_id: 0,
        };
        validity_bitmap |= 1 << index;
    }

    let fee = 5_000 + (input_count + output_count) as u64 * 500;
    let spendable = input_sum
        .checked_sub(fee)
        .expect("benchmark fee fits inputs");
    let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
    let mut remaining = spendable;
    for (index, output) in outputs.iter_mut().enumerate().take(output_count) {
        let amount = if index + 1 == output_count {
            remaining
        } else {
            spendable / output_count as u64
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
    body.validate_canonical().expect("canonical Tx8x2 fixture");
    BenchScenario {
        label,
        desc: format!("Tx8x2: {input_count} inputs / {output_count} outputs"),
        body,
        spend_secret_seed: seed,
    }
}

/// Build the legal saturation body set for one HistoryStep current tier.
pub fn legal_block_scenarios(
    label: &'static str,
    user_txs: usize,
    seed_base: u128,
) -> Vec<BenchScenario> {
    assert!(noid_chain::consensus::params::USER_TX_CLASS_TIERS.contains(&user_txs));
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

/// Legal 255-user saturation foundation with the consensus maximum 1020
/// inputs and 510 outputs spread across all depth-24 state segments.
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
    let mut touched = maximally_dispersed_b255_touched_slots();
    let coinbase_position = touched
        .iter()
        .position(|slot| *slot == coinbase_slot)
        .expect("fixture reserves the coinbase slot");
    touched.swap_remove(coinbase_position);

    let mut cursor = 0usize;
    let mut next_creation_id = 1u64;
    let mut scenarios = Vec::with_capacity(255);
    for tx_index in 0..255 {
        let input_count = if tx_index < B255_EIGHT_INPUT_TXS {
            TX_INPUTS
        } else {
            2
        };
        let positions: Vec<_> = if input_count == TX_INPUTS {
            (0..TX_INPUTS).collect()
        } else {
            INPUT_PAIRS[(tx_index - B255_EIGHT_INPUT_TXS) % INPUT_PAIRS.len()].to_vec()
        };
        let input_slots = &touched[cursor..cursor + input_count];
        cursor += input_count;
        let output_slots: [u32; TX_OUTPUTS] = touched[cursor..cursor + TX_OUTPUTS]
            .try_into()
            .expect("two output slots");
        cursor += TX_OUTPUTS;
        scenarios.push(tx8x2_scenario_with_layout(
            label,
            &positions,
            input_slots,
            output_slots,
            next_creation_id,
            seed_base + tx_index as u128,
        ));
        next_creation_id += input_count as u64;
    }
    assert_eq!(cursor, touched.len());
    assert_eq!(next_creation_id - 1, 1_020);
    scenarios
}

fn maximally_dispersed_b255_touched_slots() -> Vec<u32> {
    let mut slots = Vec::with_capacity(noid_chain::consensus::params::BLOCK_MAX_ACTIONS);
    for segment_rank in 0..noid_chain::consensus::params::BLOCK_MAX_DISTINCT_SEGMENTS {
        let segment = (segment_rank as u32).reverse_bits() >> 24;
        let local_count = if segment_rank < 251 { 6 } else { 5 };
        for local_rank in 0..local_count {
            let mut local = (local_rank as u32).reverse_bits() >> 16;
            if segment == 0 || segment == u8::MAX as u32 {
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
    let spend_secret = mk_secret(seed);
    let input_owner = derive_address(&spend_secret);
    let mut inputs = [TxInput::dummy(); TX_INPUTS];
    let mut validity_bitmap = 0u16;
    let mut input_sum = 0u64;
    for (logical_index, (&position, &slot_index)) in
        input_positions.iter().zip(input_slots).enumerate()
    {
        let amount = 1_000_000 + (logical_index as u64 + 1) * 10_000 + seed as u64 % 997;
        input_sum = input_sum.checked_add(amount).expect("fixture input sum");
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
    let spendable = input_sum.checked_sub(fee).expect("fixture fee fits inputs");
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
    body.validate_canonical().expect("canonical B255 fixture");
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
    input_count: usize,
    slot_base: u32,
    seed: u128,
) -> BenchScenario {
    let mut scenario = tx8x2_scenario(label, input_count, 1, slot_base, seed);
    scenario.desc = format!("Tx8x2 state shrink: {input_count} inputs / 1 output");
    scenario
}

pub fn minimal_tx_fixture(scenario: BenchScenario) -> MinimalTxFixture {
    let proof = prove_wallet_authorization(
        &scenario.body,
        OwnerAuthWitness::new(scenario.spend_secret()),
    )
    .expect("wallet authorization fixture")
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
        .expect("prove wallet authorization");
    });
    let proof = prove_wallet_authorization(
        &fixture.scenario.body,
        OwnerAuthWitness::new(fixture.scenario.spend_secret()),
    )
    .expect("prove wallet authorization")
    .proof;
    let verify_time = time_median(samples, || {
        verify_wallet_authorization_proof(&fixture.scenario.body, &proof)
            .expect("verify wallet authorization");
    });
    WalletBench {
        prove_time,
        verify_time,
        proof,
    }
}

pub fn authorization_size(proof: &ZkAuthorizationProof) -> usize {
    proof.to_bytes().expect("encode authorization proof").len()
}

pub fn wallet_bundle_size(proof: &ZkAuthorizationProof) -> usize {
    WalletAuthorizationBundle {
        proof: proof.clone(),
    }
    .to_bytes()
    .expect("encode wallet bundle")
    .len()
}

pub fn live_counts(body: &TxBody) -> (usize, usize) {
    (body.live_input_count(), body.live_output_count())
}

pub fn block_tx_hash_body(body: &TxBody) -> TxBodyHash {
    body.txid()
}

/// Native user counts used by the release freezer's honest backbone.
///
/// The first ten blocks remain in B8 while growing a pool large enough for
/// every fork. The final three blocks establish exact B32, B64 and B255
/// parent boundaries. Every block starts at canonical genesis ancestry and is
/// mined, checked and materialized through the production state transition.
pub const HISTORY_STEP_FREEZER_BACKBONE_USER_COUNTS: [usize; 13] =
    [0, 1, 3, 7, 8, 8, 8, 8, 8, 8, 17, 33, 65];

/// One honest current-block member for each fixed HistoryStep tier.
pub const HISTORY_STEP_FREEZER_FORK_USER_COUNTS: [usize; 4] = [8, 17, 33, 65];

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

#[derive(Clone)]
struct HistoryStepFixtureCheckpoint {
    parent_header: noid_chain::BlockHeader,
    tx_epoch_anchor_header: noid_chain::BlockHeader,
    parent_state: noid_chain::state::ChainState,
    start_accumulator: noid_recursive::ChainAccumulator,
    previous_timestamps: Vec<u64>,
    previous_active_counts: Vec<u64>,
    asert_anchor: noid_chain::consensus::AnchorInfo,
    spendables: Vec<TrackedSpendable>,
    output_slot_cursor: u32,
}

/// A mined, fully prepared release-freezer witness for one HistoryStep input.
///
/// The start/end accumulators are owned beside the one-shot witness so the
/// freezer can consume the input immediately without retaining borrowed
/// chain state or reconstructing any boundary.
pub struct PreparedHistoryStepTierFixture<const TIER: usize> {
    witness: noid_block::PreparedHistoryStepInputWitness<TIER>,
    nonce: u128,
    start_accumulator: noid_recursive::ChainAccumulator,
    end_accumulator: noid_recursive::ChainAccumulator,
}

impl<const TIER: usize> PreparedHistoryStepTierFixture<TIER> {
    pub fn nonce(&self) -> u128 {
        self.nonce
    }

    pub fn start_accumulator(&self) -> &noid_recursive::ChainAccumulator {
        &self.start_accumulator
    }

    pub fn end_accumulator(&self) -> &noid_recursive::ChainAccumulator {
        &self.end_accumulator
    }

    pub fn into_parts(
        self,
    ) -> (
        noid_block::PreparedHistoryStepInputWitness<TIER>,
        u128,
        noid_recursive::ChainAccumulator,
        noid_recursive::ChainAccumulator,
    ) {
        (
            self.witness,
            self.nonce,
            self.start_accumulator,
            self.end_accumulator,
        )
    }

    fn into_history_step_input(
        self,
    ) -> Result<noid_recursive::HistoryStepBlockInput<TIER>, String> {
        let (witness, nonce, start, end) = self.into_parts();
        witness
            .finish(nonce, &start, &end)
            .map(|(_, input)| input)
            .map_err(|error| format!("finish honest B{TIER} HistoryStep witness: {error}"))
    }
}

/// Heterogeneous streaming item used while the freezer proves the backbone.
pub enum PreparedHistoryStepBackboneInput {
    B8(PreparedHistoryStepTierFixture<8>),
    B32(PreparedHistoryStepTierFixture<32>),
    B64(PreparedHistoryStepTierFixture<64>),
    B255(PreparedHistoryStepTierFixture<255>),
}

/// One backbone item and the parent-tier checkpoint established after it.
pub struct HonestHistoryStepBackboneStep {
    pub input: PreparedHistoryStepBackboneInput,
    pub capture_parent_slot: Option<usize>,
}

struct BuiltFixtureChild<const TIER: usize> {
    prepared: PreparedHistoryStepTierFixture<TIER>,
    sealed_block: noid_chain::Block,
    next_spendables: Vec<TrackedSpendable>,
    next_output_slot_cursor: u32,
}

/// Deterministic, resettable source of real release-freezer witnesses.
///
/// A pass first streams the canonical-genesis backbone. Once all four parent
/// checkpoints exist, each class method forks a real child from the exact
/// checkpoint selected by `class_id.parent_slot()`. Only the currently
/// requested witness is materialized.
pub struct HonestHistoryStepFixtureProvider {
    seed: u128,
    ghost: noid_recursive::PreparedHistoryStepGhostAuthorization,
    authorization_proofs:
        std::cell::RefCell<std::collections::HashMap<TxBodyHash, ZkAuthorizationProof>>,
    mined_nonces: std::cell::RefCell<std::collections::HashMap<[u8; 32], u128>>,
    backbone_index: usize,
    live: HistoryStepFixtureCheckpoint,
    checkpoints: [Option<HistoryStepFixtureCheckpoint>; 4],
}

impl HonestHistoryStepFixtureProvider {
    pub fn new(seed: u128) -> Result<Self, String> {
        let ghost = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
            .map_err(|error| format!("prove canonical ghost authorization: {error}"))?;
        let ghost = noid_recursive::prepare_history_step_ghost_authorization(ghost)
            .map_err(|error| format!("prepare canonical ghost authorization: {error}"))?;
        let live = genesis_fixture_checkpoint();
        Ok(Self {
            seed,
            ghost,
            authorization_proofs: std::cell::RefCell::new(std::collections::HashMap::new()),
            mined_nonces: std::cell::RefCell::new(std::collections::HashMap::new()),
            backbone_index: 0,
            live,
            checkpoints: std::array::from_fn(|_| None),
        })
    }

    /// Start a fresh deterministic freezer pass at the canonical genesis
    /// boundary. This drops all previous state checkpoints and witnesses.
    pub fn reset_backbone(&mut self) {
        self.backbone_index = 0;
        self.live = genesis_fixture_checkpoint();
        self.checkpoints = std::array::from_fn(|_| None);
    }

    pub fn next_backbone(
        &mut self,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<Option<HonestHistoryStepBackboneStep>, String> {
        if self.backbone_index == HISTORY_STEP_FREEZER_BACKBONE_USER_COUNTS.len() {
            return Ok(None);
        }
        if &self.live.start_accumulator != expected_start {
            return Err("freezer backbone start does not match the honest native boundary".into());
        }

        let step = self.backbone_index;
        let user_count = HISTORY_STEP_FREEZER_BACKBONE_USER_COUNTS[step];
        let capture_parent_slot = match step {
            9 => Some(0),
            10 => Some(1),
            11 => Some(2),
            12 => Some(3),
            _ => None,
        };
        let input = match noid_chain::consensus::params::user_tx_class_tier(user_count) {
            Some(8) => self
                .build_child::<8>(user_count, step as u128)?
                .map_into(&mut self.live)?,
            Some(32) => self
                .build_child::<32>(user_count, step as u128)?
                .map_into(&mut self.live)?,
            Some(64) => self
                .build_child::<64>(user_count, step as u128)?
                .map_into(&mut self.live)?,
            Some(255) => self
                .build_child::<255>(user_count, step as u128)?
                .map_into(&mut self.live)?,
            _ => return Err("backbone user count does not select a canonical tier".into()),
        };

        self.backbone_index += 1;
        if let Some(parent_slot) = capture_parent_slot {
            self.checkpoints[parent_slot] = Some(self.live.clone());
        }
        Ok(Some(HonestHistoryStepBackboneStep {
            input,
            capture_parent_slot,
        }))
    }

    pub fn b8(
        &self,
        class_id: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<PreparedHistoryStepTierFixture<8>, String> {
        self.fork::<8>(
            class_id,
            expected_start,
            HISTORY_STEP_FREEZER_FORK_USER_COUNTS[0],
        )
    }

    pub fn b32(
        &self,
        class_id: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<PreparedHistoryStepTierFixture<32>, String> {
        self.fork::<32>(
            class_id,
            expected_start,
            HISTORY_STEP_FREEZER_FORK_USER_COUNTS[1],
        )
    }

    pub fn b64(
        &self,
        class_id: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<PreparedHistoryStepTierFixture<64>, String> {
        self.fork::<64>(
            class_id,
            expected_start,
            HISTORY_STEP_FREEZER_FORK_USER_COUNTS[2],
        )
    }

    pub fn b255(
        &self,
        class_id: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<PreparedHistoryStepTierFixture<255>, String> {
        self.fork::<255>(
            class_id,
            expected_start,
            HISTORY_STEP_FREEZER_FORK_USER_COUNTS[3],
        )
    }

    pub fn parent_accumulator(
        &self,
        parent_slot: usize,
    ) -> Option<&noid_recursive::ChainAccumulator> {
        self.checkpoints
            .get(parent_slot)?
            .as_ref()
            .map(|checkpoint| &checkpoint.start_accumulator)
    }

    fn fork<const TIER: usize>(
        &self,
        class_id: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
        user_count: usize,
    ) -> Result<PreparedHistoryStepTierFixture<TIER>, String> {
        if class_id.current_tier() != TIER {
            return Err(format!(
                "class {} selects B{}, not requested B{TIER}",
                class_id.index(),
                class_id.current_tier(),
            ));
        }
        let checkpoint = self.checkpoints[class_id.parent_slot()]
            .as_ref()
            .ok_or_else(|| format!("parent checkpoint {} is not built", class_id.parent_slot()))?;
        if &checkpoint.start_accumulator != expected_start {
            return Err(format!(
                "class {} start does not match parent checkpoint {}",
                class_id.index(),
                class_id.parent_slot(),
            ));
        }
        self.build_child_from::<TIER>(checkpoint, user_count, 0x1000 + class_id.index() as u128)
            .map(|child| child.prepared)
    }

    fn build_child<const TIER: usize>(
        &self,
        user_count: usize,
        nonce_domain: u128,
    ) -> Result<BuiltFixtureChild<TIER>, String> {
        self.build_child_from::<TIER>(&self.live, user_count, nonce_domain)
    }

    fn build_child_from<const TIER: usize>(
        &self,
        checkpoint: &HistoryStepFixtureCheckpoint,
        user_count: usize,
        nonce_domain: u128,
    ) -> Result<BuiltFixtureChild<TIER>, String> {
        if noid_chain::consensus::params::user_tx_class_tier(user_count) != Some(TIER) {
            return Err(format!("{user_count} users do not select B{TIER}"));
        }
        let (candidates, authorities, next_user_spendables, next_output_slot_cursor) =
            child_user_transactions(checkpoint, user_count, self.seed, nonce_domain)?;
        let timestamp = checkpoint
            .parent_header
            .timestamp
            .checked_add(noid_chain::consensus::params::BLOCK_TIME)
            .ok_or_else(|| "fixture timestamp overflow".to_owned())?;
        let target = noid_chain::consensus::next_target(
            checkpoint.asert_anchor.anchor_height,
            checkpoint.asert_anchor.anchor_timestamp,
            &checkpoint.asert_anchor.anchor_target,
            checkpoint.parent_header.height + 1,
            timestamp,
        );
        let miner_seed = self
            .seed
            .wrapping_add(0x3000_0000)
            .wrapping_add(nonce_domain << 12)
            .wrapping_add(checkpoint.parent_header.height as u128);
        let template = noid_chain::consensus::build_block_template(
            &checkpoint.parent_header,
            &checkpoint.parent_state,
            &checkpoint.previous_active_counts,
            candidates,
            derive_address(&mk_secret(miner_seed)),
            timestamp,
            target,
        )
        .map_err(|error| format!("build honest B{TIER} template: {error:?}"))?;
        if template.txs.len() != user_count {
            return Err(format!(
                "honest B{TIER} template retained {} of {user_count} users",
                template.txs.len(),
            ));
        }
        let authorization_proofs = template
            .txs
            .iter()
            .map(|transaction| -> Result<ZkAuthorizationProof, String> {
                let seed = authorities
                    .iter()
                    .find_map(|(txid, seed)| (txid == &transaction.txid()).then_some(*seed))
                    .ok_or_else(|| "ordered template lost its wallet authority".to_owned())?;
                let cached_proof = {
                    self.authorization_proofs
                        .borrow()
                        .get(&transaction.txid())
                        .cloned()
                };
                if let Some(proof) = cached_proof {
                    return Ok(proof);
                }
                let proof = prove_wallet_authorization(
                    &transaction.body,
                    OwnerAuthWitness::new(mk_secret(seed)),
                )
                .map(|bundle| bundle.proof)
                .map_err(|error| format!("prove honest wallet authorization: {error}"))?;
                self.authorization_proofs
                    .borrow_mut()
                    .insert(transaction.txid(), proof.clone());
                Ok(proof)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let block = template.into_block(0);
        let nonce_key = noid_chain::hash_block_header(&block.header);
        let cached_nonce = { self.mined_nonces.borrow().get(&nonce_key).copied() };
        let nonce = if let Some(nonce) = cached_nonce {
            nonce
        } else {
            let nonce = mine_history_step_fixture_header(&block.header);
            self.mined_nonces.borrow_mut().insert(nonce_key, nonce);
            nonce
        };
        let mut sealed_block = block.clone();
        sealed_block.header.nonce = nonce;
        let end_accumulator = checkpoint
            .start_accumulator
            .advance(&sealed_block.header)
            .map_err(|error| format!("advance honest B{TIER} accumulator: {error:?}"))?;
        let context = noid_block::HistoryStepPreparationContext {
            parent_header: &checkpoint.parent_header,
            tx_epoch_anchor_header: &checkpoint.tx_epoch_anchor_header,
            parent_state: &checkpoint.parent_state,
            start_accumulator: &checkpoint.start_accumulator,
            previous_timestamps: &checkpoint.previous_timestamps,
            previous_active_counts: &checkpoint.previous_active_counts,
            asert_anchor: &checkpoint.asert_anchor,
            local_time: timestamp,
        };
        let witness = noid_block::prepare_history_step_input_witness::<TIER>(
            block,
            context,
            authorization_proofs,
            &self.ghost,
        )
        .map_err(|error| format!("prepare honest B{TIER} HistoryStep: {error}"))?;

        let mut next_spendables = Vec::with_capacity(
            checkpoint.spendables.len() - user_count + 1 + next_user_spendables.len(),
        );
        next_spendables.extend(checkpoint.spendables.iter().skip(user_count).cloned());
        let coinbase_slot = sealed_block.transactions[0]
            .body
            .live_outputs()
            .next()
            .ok_or_else(|| "honest coinbase has no live output".to_owned())?
            .1
            .slot_index;
        next_spendables.push(TrackedSpendable {
            slot_index: coinbase_slot,
            spend_secret_seed: miner_seed,
        });
        next_spendables.extend(next_user_spendables);

        Ok(BuiltFixtureChild {
            prepared: PreparedHistoryStepTierFixture {
                witness,
                nonce,
                start_accumulator: checkpoint.start_accumulator.clone(),
                end_accumulator,
            },
            sealed_block,
            next_spendables,
            next_output_slot_cursor,
        })
    }
}

impl noid_recursive::HistoryStepFreezeInputProvider for HonestHistoryStepFixtureProvider {
    type Error = String;

    fn reset_backbone(&mut self) -> Result<(), Self::Error> {
        HonestHistoryStepFixtureProvider::reset_backbone(self);
        Ok(())
    }

    fn next_backbone(
        &mut self,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<Option<noid_recursive::HistoryStepFreezeInput>, Self::Error> {
        HonestHistoryStepFixtureProvider::next_backbone(self, expected_start)?
            .map(|step| match step.input {
                PreparedHistoryStepBackboneInput::B8(input) => input
                    .into_history_step_input()
                    .map(noid_recursive::HistoryStepFreezeInput::B8),
                PreparedHistoryStepBackboneInput::B32(input) => input
                    .into_history_step_input()
                    .map(noid_recursive::HistoryStepFreezeInput::B32),
                PreparedHistoryStepBackboneInput::B64(input) => input
                    .into_history_step_input()
                    .map(noid_recursive::HistoryStepFreezeInput::B64),
                PreparedHistoryStepBackboneInput::B255(input) => input
                    .into_history_step_input()
                    .map(noid_recursive::HistoryStepFreezeInput::B255),
            })
            .transpose()
    }

    fn b8(
        &mut self,
        class: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<noid_recursive::HistoryStepBlockInput<8>, Self::Error> {
        HonestHistoryStepFixtureProvider::b8(self, class, expected_start)?.into_history_step_input()
    }

    fn b32(
        &mut self,
        class: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<noid_recursive::HistoryStepBlockInput<32>, Self::Error> {
        HonestHistoryStepFixtureProvider::b32(self, class, expected_start)?
            .into_history_step_input()
    }

    fn b64(
        &mut self,
        class: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<noid_recursive::HistoryStepBlockInput<64>, Self::Error> {
        HonestHistoryStepFixtureProvider::b64(self, class, expected_start)?
            .into_history_step_input()
    }

    fn b255(
        &mut self,
        class: noid_recursive::CanonicalHistoryStepClassId,
        expected_start: &noid_recursive::ChainAccumulator,
    ) -> Result<noid_recursive::HistoryStepBlockInput<255>, Self::Error> {
        HonestHistoryStepFixtureProvider::b255(self, class, expected_start)?
            .into_history_step_input()
    }
}

trait AdvanceHonestBackbone {
    fn map_into(
        self,
        live: &mut HistoryStepFixtureCheckpoint,
    ) -> Result<PreparedHistoryStepBackboneInput, String>;
}

macro_rules! impl_advance_honest_backbone {
    ($tier:literal, $variant:ident) => {
        impl AdvanceHonestBackbone for BuiltFixtureChild<$tier> {
            fn map_into(
                self,
                live: &mut HistoryStepFixtureCheckpoint,
            ) -> Result<PreparedHistoryStepBackboneInput, String> {
                let Self {
                    prepared,
                    sealed_block,
                    next_spendables,
                    next_output_slot_cursor,
                } = self;
                noid_chain::consensus::validate_block_checks(
                    &sealed_block,
                    &live.parent_header,
                    &live.previous_timestamps,
                    &live.previous_active_counts,
                    sealed_block.header.timestamp,
                    &live.asert_anchor,
                )
                .map_err(|error| format!("validate honest B{} backbone: {error}", $tier))?;
                noid_chain::materialize_accepted_block_state(&mut live.parent_state, &sealed_block)
                    .map_err(|error| {
                        format!("materialize honest B{} backbone: {error:?}", $tier)
                    })?;
                if live.parent_state.cached_state_root() != sealed_block.header.state_root {
                    return Err(format!("honest B{} state root did not materialize", $tier));
                }
                live.previous_timestamps.push(sealed_block.header.timestamp);
                live.previous_active_counts
                    .push(sealed_block.header.active_slot_count);
                live.start_accumulator = prepared.end_accumulator.clone();
                live.parent_header = sealed_block.header;
                live.spendables = next_spendables;
                live.output_slot_cursor = next_output_slot_cursor;
                Ok(PreparedHistoryStepBackboneInput::$variant(prepared))
            }
        }
    };
}

impl_advance_honest_backbone!(8, B8);
impl_advance_honest_backbone!(32, B32);
impl_advance_honest_backbone!(64, B64);
impl_advance_honest_backbone!(255, B255);

fn genesis_fixture_checkpoint() -> HistoryStepFixtureCheckpoint {
    let genesis = noid_chain::consensus::genesis_header();
    let state = noid_chain::state::ChainState::with_log_slots(genesis.log_slots as usize);
    assert_eq!(state.cached_state_root(), genesis.state_root);
    HistoryStepFixtureCheckpoint {
        parent_header: genesis,
        tx_epoch_anchor_header: genesis,
        parent_state: state,
        start_accumulator: noid_recursive::genesis_accumulator(),
        previous_timestamps: vec![genesis.timestamp],
        previous_active_counts: vec![genesis.active_slot_count],
        asert_anchor: noid_chain::consensus::AnchorInfo {
            anchor_height: genesis.height,
            anchor_timestamp: genesis.timestamp,
            anchor_target: genesis.difficulty_target,
        },
        spendables: Vec::new(),
        output_slot_cursor: 1 << (BENCH_LOG_SLOTS - 1),
    }
}

fn child_user_transactions(
    checkpoint: &HistoryStepFixtureCheckpoint,
    user_count: usize,
    seed: u128,
    nonce_domain: u128,
) -> Result<
    (
        Vec<Transaction>,
        Vec<(TxBodyHash, u128)>,
        Vec<TrackedSpendable>,
        u32,
    ),
    String,
> {
    if checkpoint.spendables.len() < user_count {
        return Err(format!(
            "honest parent has {} spendables, needs {user_count}",
            checkpoint.spendables.len(),
        ));
    }
    let mut output_slot_cursor = checkpoint.output_slot_cursor;
    let mut reserved = std::collections::BTreeSet::new();
    let mut transactions = Vec::with_capacity(user_count);
    let mut authorities = Vec::with_capacity(user_count);
    let mut next_spendables = Vec::with_capacity(user_count * TX_OUTPUTS);

    for (tx_index, source) in checkpoint.spendables.iter().take(user_count).enumerate() {
        let slot = checkpoint.parent_state.state.slot(source.slot_index);
        if slot.is_empty() {
            return Err("tracked honest input is not live".into());
        }
        let spend_secret = source.spend_secret();
        let owner = derive_address(&spend_secret);
        if [slot.owner_hi, slot.owner_lo] != owner.as_fields() {
            return Err("tracked honest input owner does not match its wallet secret".into());
        }
        let mut output_slots = [0u32; TX_OUTPUTS];
        for output_slot in &mut output_slots {
            while checkpoint.parent_state.state.slot(output_slot_cursor)
                != noid_chain::SlotValue::EMPTY
                || reserved.contains(&output_slot_cursor)
            {
                output_slot_cursor = output_slot_cursor
                    .checked_add(1)
                    .ok_or_else(|| "honest fixture output slot overflow".to_owned())?;
            }
            *output_slot = output_slot_cursor;
            reserved.insert(output_slot_cursor);
            output_slot_cursor = output_slot_cursor
                .checked_add(1)
                .ok_or_else(|| "honest fixture output slot overflow".to_owned())?;
        }
        let output_seeds: [u128; TX_OUTPUTS] = std::array::from_fn(|output_index| {
            seed.wrapping_add(0x2000_0000)
                .wrapping_add(nonce_domain << 20)
                .wrapping_add((tx_index as u128) << 4)
                .wrapping_add(output_index as u128)
        });
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: source.slot_index,
            amount: slot.amount(),
            creation_id: slot.creation_id(),
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        for index in 0..TX_OUTPUTS {
            outputs[index] = TxOutput {
                slot_index: output_slots[index],
                amount: 1,
                owner: derive_address(&mk_secret(output_seeds[index])),
            };
        }
        let mut body = TxBody {
            epoch_anchor: checkpoint.start_accumulator.epoch_anchor_id,
            fee: 0,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | output_bitmap_bit(1),
            is_coinbase: false,
        };
        body.fee = noid_chain::consensus::fees::required_fee_for_tx_body(
            &body,
            checkpoint.parent_state.active_slot_count,
            checkpoint.parent_header.log_slots,
        );
        let spendable = slot
            .amount()
            .checked_sub(body.fee)
            .ok_or_else(|| "honest input does not cover the consensus fee".to_owned())?;
        body.outputs[0].amount = spendable / 2;
        body.outputs[1].amount = spendable - body.outputs[0].amount;
        body.validate_canonical()
            .map_err(|error| format!("honest Tx8x2 body: {error}"))?;
        let txid = body.txid();
        authorities.push((txid, source.spend_secret_seed));
        transactions.push(Transaction::new(body));
        next_spendables.extend((0..TX_OUTPUTS).map(|index| TrackedSpendable {
            slot_index: output_slots[index],
            spend_secret_seed: output_seeds[index],
        }));
    }
    Ok((
        transactions,
        authorities,
        next_spendables,
        output_slot_cursor,
    ))
}

fn mine_history_step_fixture_header(header: &noid_chain::BlockHeader) -> u128 {
    use rayon::prelude::*;

    const NONCES_PER_LANE: u128 = 65_536;
    let lanes = rayon::current_num_threads().max(1);
    let batch_width = NONCES_PER_LANE * lanes as u128;
    let mut batch_start = 0u128;
    loop {
        if let Some(nonce) = (0..lanes)
            .into_par_iter()
            .filter_map(|lane| {
                noid_chain::consensus::pow::search_pow(
                    header,
                    batch_start + NONCES_PER_LANE * lane as u128,
                    NONCES_PER_LANE,
                )
            })
            .min()
        {
            return nonce;
        }
        batch_start = batch_start
            .checked_add(batch_width)
            .expect("fixture PoW nonce space exhausted");
    }
}

#[cfg(test)]
mod honest_history_step_fixture_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    const KNOWN_C00_PREFIX_PASSED: &str = "focused known-c00 prefix passed";

    struct KnownC00CutoffProvider {
        inner: HonestHistoryStepFixtureProvider,
        resets: usize,
        backbone_calls_per_reset: Vec<usize>,
    }

    impl noid_recursive::HistoryStepFreezeInputProvider for KnownC00CutoffProvider {
        type Error = String;

        fn reset_backbone(&mut self) -> Result<(), Self::Error> {
            self.resets += 1;
            // Resets 1-2 derive the provisional direct VKs, 3 assembles the
            // provisional c00, 4 assembles c00 with its integrated direct VK,
            // and 5 must consume the now-known c00 before discovering c04.
            // Stop only when that complete pass has succeeded.
            if self.resets == 6 {
                return Err(KNOWN_C00_PREFIX_PASSED.to_owned());
            }
            self.inner.reset_backbone();
            self.backbone_calls_per_reset.push(0);
            Ok(())
        }

        fn next_backbone(
            &mut self,
            expected_start: &noid_recursive::ChainAccumulator,
        ) -> Result<Option<noid_recursive::HistoryStepFreezeInput>, Self::Error> {
            *self
                .backbone_calls_per_reset
                .last_mut()
                .expect("next_backbone follows reset_backbone") += 1;
            noid_recursive::HistoryStepFreezeInputProvider::next_backbone(
                &mut self.inner,
                expected_start,
            )
        }

        fn b8(
            &mut self,
            class: noid_recursive::CanonicalHistoryStepClassId,
            expected_start: &noid_recursive::ChainAccumulator,
        ) -> Result<noid_recursive::HistoryStepBlockInput<8>, Self::Error> {
            noid_recursive::HistoryStepFreezeInputProvider::b8(
                &mut self.inner,
                class,
                expected_start,
            )
        }

        fn b32(
            &mut self,
            class: noid_recursive::CanonicalHistoryStepClassId,
            expected_start: &noid_recursive::ChainAccumulator,
        ) -> Result<noid_recursive::HistoryStepBlockInput<32>, Self::Error> {
            noid_recursive::HistoryStepFreezeInputProvider::b32(
                &mut self.inner,
                class,
                expected_start,
            )
        }

        fn b64(
            &mut self,
            class: noid_recursive::CanonicalHistoryStepClassId,
            expected_start: &noid_recursive::ChainAccumulator,
        ) -> Result<noid_recursive::HistoryStepBlockInput<64>, Self::Error> {
            noid_recursive::HistoryStepFreezeInputProvider::b64(
                &mut self.inner,
                class,
                expected_start,
            )
        }

        fn b255(
            &mut self,
            class: noid_recursive::CanonicalHistoryStepClassId,
            expected_start: &noid_recursive::ChainAccumulator,
        ) -> Result<noid_recursive::HistoryStepBlockInput<255>, Self::Error> {
            noid_recursive::HistoryStepFreezeInputProvider::b255(
                &mut self.inner,
                class,
                expected_start,
            )
        }
    }

    #[derive(Default)]
    struct RetainedBootstrapMatrices {
        matrices: Mutex<Vec<Option<std::sync::Arc<noid_ivc_core::field_r1cs::FieldR1cs>>>>,
        installs: AtomicUsize,
        loads: AtomicUsize,
    }

    impl noid_recursive::HistoryStepMatrixSource for RetainedBootstrapMatrices {
        fn load(
            &self,
            class: noid_recursive::CanonicalHistoryStepClassId,
        ) -> Result<
            noid_recursive::HistoryStepMatrixLease,
            noid_recursive::HistoryStepMatrixSourceError,
        > {
            self.loads.fetch_add(1, Ordering::Relaxed);
            self.matrices
                .lock()
                .map_err(|_| noid_recursive::HistoryStepMatrixSourceError)?
                .get(class.index())
                .and_then(Clone::clone)
                .map(noid_recursive::HistoryStepMatrixLease::Resident)
                .ok_or(noid_recursive::HistoryStepMatrixSourceError)
        }
    }

    impl noid_recursive::HistoryStepFreezeMatrixStore for RetainedBootstrapMatrices {
        type Error = String;

        fn install(
            &self,
            class: noid_recursive::CanonicalHistoryStepClassId,
            matrix: noid_ivc_core::field_r1cs::FieldR1cs,
        ) -> Result<(), Self::Error> {
            let mut matrices = self
                .matrices
                .lock()
                .map_err(|_| "bootstrap matrix lock is poisoned".to_owned())?;
            if matrices.is_empty() {
                matrices.resize_with(noid_recursive::HISTORY_STEP_CLASS_COUNT, || None);
            }
            matrices[class.index()] = Some(std::sync::Arc::new(matrix));
            self.installs.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct SharedRetainedBootstrapMatrices(std::sync::Arc<RetainedBootstrapMatrices>);

    impl noid_recursive::HistoryStepMatrixSource for SharedRetainedBootstrapMatrices {
        fn load(
            &self,
            class: noid_recursive::CanonicalHistoryStepClassId,
        ) -> Result<
            noid_recursive::HistoryStepMatrixLease,
            noid_recursive::HistoryStepMatrixSourceError,
        > {
            noid_recursive::HistoryStepMatrixSource::load(self.0.as_ref(), class)
        }
    }

    fn derive_focused_provisional_parts(
        provider: &mut HonestHistoryStepFixtureProvider,
    ) -> Result<noid_recursive::HistoryStepRuntimeParts, String> {
        provider.reset_backbone();
        let mut expected = noid_recursive::genesis_accumulator();
        let mut vks: [Option<noid_recursive::region_sidecar::BlockRegionSidecarVk>; 4] =
            std::array::from_fn(|_| None);

        while vks.iter().any(Option::is_none) {
            let step = provider
                .next_backbone(&expected)?
                .ok_or_else(|| "focused VK derivation exhausted the backbone".to_owned())?;
            macro_rules! derive_vk {
                ($fixture:expr, $slot:expr) => {{
                    let input = $fixture.into_history_step_input()?;
                    expected = input.end_accumulator().clone();
                    if vks[$slot].is_none() {
                        vks[$slot] = Some(
                            noid_recursive::derive_history_step_direct_block_vk(input).map_err(
                                |error| {
                                    format!(
                                        "derive focused B{} VK: {error}",
                                        [8, 32, 64, 255][$slot]
                                    )
                                },
                            )?,
                        );
                    }
                }};
            }
            match step.input {
                PreparedHistoryStepBackboneInput::B8(fixture) => derive_vk!(fixture, 0),
                PreparedHistoryStepBackboneInput::B32(fixture) => derive_vk!(fixture, 1),
                PreparedHistoryStepBackboneInput::B64(fixture) => derive_vk!(fixture, 2),
                PreparedHistoryStepBackboneInput::B255(fixture) => derive_vk!(fixture, 3),
            }
        }

        noid_recursive::derive_history_step_runtime_parts(
            vks.map(|vk| vk.expect("all focused direct VKs were derived")),
        )
        .map_err(|error| format!("derive focused runtime parts: {error}"))
    }

    fn focused_runtime(
        digests: [[u8; 32]; noid_recursive::HISTORY_STEP_CLASS_COUNT],
        parts: &noid_recursive::HistoryStepRuntimeParts,
        store: &std::sync::Arc<RetainedBootstrapMatrices>,
    ) -> Result<noid_recursive::HistoryStepRuntime, String> {
        let bank = noid_recursive::pin_history_step_class_bank(digests, parts)
            .map_err(|error| format!("pin focused bank: {error}"))?;
        noid_recursive::HistoryStepRuntime::new(
            bank,
            Box::new(SharedRetainedBootstrapMatrices(std::sync::Arc::clone(
                store,
            ))),
            parts.clone(),
        )
        .map_err(|error| format!("construct focused runtime: {error}"))
    }

    fn next_focused_b8(
        provider: &mut HonestHistoryStepFixtureProvider,
        expected: &noid_recursive::ChainAccumulator,
    ) -> Result<(noid_chain::Block, noid_recursive::HistoryStepBlockInput<8>), String> {
        let step = provider
            .next_backbone(expected)?
            .ok_or_else(|| "focused B8 backbone step is missing".to_owned())?;
        let PreparedHistoryStepBackboneInput::B8(fixture) = step.input else {
            return Err("focused backbone step does not select B8".to_owned());
        };
        let (witness, nonce, start, end) = fixture.into_parts();
        witness
            .finish(nonce, &start, &end)
            .map_err(|error| format!("finish focused B8 input: {error}"))
    }

    fn next_focused_b32(
        provider: &mut HonestHistoryStepFixtureProvider,
        expected: &noid_recursive::ChainAccumulator,
    ) -> Result<(noid_chain::Block, noid_recursive::HistoryStepBlockInput<32>), String> {
        let step = provider
            .next_backbone(expected)?
            .ok_or_else(|| "focused B32 backbone step is missing".to_owned())?;
        let PreparedHistoryStepBackboneInput::B32(fixture) = step.input else {
            return Err("focused backbone step does not select B32".to_owned());
        };
        let (witness, nonce, start, end) = fixture.into_parts();
        witness
            .finish(nonce, &start, &end)
            .map_err(|error| format!("finish focused B32 input: {error}"))
    }

    fn replace_focused_direct_vk(
        parts: &noid_recursive::HistoryStepRuntimeParts,
        slot: usize,
        vk: noid_recursive::region_sidecar::BlockRegionSidecarVk,
    ) -> noid_recursive::HistoryStepRuntimeParts {
        let mut direct_vks = parts.direct_block_vks().clone();
        direct_vks[slot] = vk;
        noid_recursive::HistoryStepRuntimeParts::new(
            parts.parent_recursion_vk().clone(),
            direct_vks,
            parts.parent_transcripts().clone(),
        )
        .expect("focused direct VK replacement remains canonical")
    }

    fn prove_focused_b8_checkpoint(
        runtime: &noid_recursive::HistoryStepRuntime,
        provider: &mut HonestHistoryStepFixtureProvider,
    ) -> noid_recursive::HistoryStepTerminal {
        provider.reset_backbone();
        let mut expected = noid_recursive::genesis_accumulator();
        let mut parent = None;
        for _ in 0..10 {
            let (_, input) = next_focused_b8(provider, &expected).unwrap();
            let terminal = noid_recursive::prove_history_step(runtime, parent.as_ref(), input)
                .expect("prove focused B8 backbone step");
            expected = terminal.accumulator().clone();
            parent = Some(terminal);
        }
        parent.expect("focused B8 checkpoint exists")
    }

    fn prove_focused_b32_checkpoint(
        runtime: &noid_recursive::HistoryStepRuntime,
        provider: &mut HonestHistoryStepFixtureProvider,
    ) -> noid_recursive::HistoryStepTerminal {
        let b8 = prove_focused_b8_checkpoint(runtime, provider);
        let (_, input) = next_focused_b32(provider, b8.accumulator()).unwrap();
        noid_recursive::prove_history_step(runtime, Some(&b8), input)
            .expect("prove focused B32 checkpoint")
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FocusedBlockVkRoleGeometry {
        role: &'static str,
        row_count: usize,
        slice_starts: Vec<usize>,
        slice_lengths: Vec<usize>,
    }

    fn focused_block_vk_geometry(
        vk: &noid_recursive::region_sidecar::BlockRegionSidecarVk,
    ) -> Vec<FocusedBlockVkRoleGeometry> {
        macro_rules! role {
            ($name:literal, $child:expr) => {{
                let child = $child;
                FocusedBlockVkRoleGeometry {
                    role: $name,
                    row_count: 1usize << child.w_log(),
                    slice_starts: child.slices().iter().map(|slice| slice.start()).collect(),
                    slice_lengths: child.slices().iter().map(|slice| slice.len()).collect(),
                }
            }};
        }
        vec![
            role!("wallet_a", vk.wallet_a()),
            role!("meta_a", vk.meta_a()),
            role!("wallet_b", vk.wallet_b()),
            role!("meta_b", vk.meta_b()),
            role!("owner_c", vk.owner_c()),
            role!("main_c", vk.main_c()),
        ]
    }

    #[test]
    fn freezer_transaction_counts_select_the_declared_tiers() {
        let backbone_tiers = HISTORY_STEP_FREEZER_BACKBONE_USER_COUNTS
            .map(|count| noid_chain::consensus::params::user_tx_class_tier(count).unwrap());
        assert_eq!(backbone_tiers, [8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 32, 64, 255]);
        let fork_tiers = HISTORY_STEP_FREEZER_FORK_USER_COUNTS
            .map(|count| noid_chain::consensus::params::user_tx_class_tier(count).unwrap());
        assert_eq!(fork_tiers, [8, 32, 64, 255]);
    }

    #[test]
    #[ignore = "runs real wallet proving and production PoW"]
    fn first_backbone_step_is_exact_genesis_child() {
        let mut provider = HonestHistoryStepFixtureProvider::new(0x4849_5354_4550).unwrap();
        let genesis = noid_recursive::genesis_accumulator();
        let step = provider.next_backbone(&genesis).unwrap().unwrap();
        assert!(step.capture_parent_slot.is_none());
        let PreparedHistoryStepBackboneInput::B8(prepared) = step.input else {
            panic!("height one must select B8");
        };
        let (witness, nonce, start, end) = prepared.into_parts();
        let (block, _) = witness.finish(nonce, &start, &end).unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.header.prev_block_hash, genesis.tip_block_id);
    }

    #[test]
    #[ignore = "runs the honest provisional -> integrated -> known-c00 freezer prefix"]
    fn known_c00_proves_after_exact_direct_vk_replacement() {
        noid_ivc_prover::init_perf_thread_pool();
        let mut provider = KnownC00CutoffProvider {
            inner: HonestHistoryStepFixtureProvider::new(0x4849_5354_4550_5f56_31).unwrap(),
            resets: 0,
            backbone_calls_per_reset: Vec::new(),
        };
        let store = std::sync::Arc::new(RetainedBootstrapMatrices::default());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            noid_recursive::freeze_history_step_bank(&mut provider, std::sync::Arc::clone(&store))
        }));
        let result = result.unwrap_or_else(|payload| {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic");
            panic!(
                "known-c00 freezer panicked after resets={} backbone_calls={:?} installs={} loads={}: {message}",
                provider.resets,
                provider.backbone_calls_per_reset,
                store.installs.load(Ordering::Relaxed),
                store.loads.load(Ordering::Relaxed),
            )
        });
        match result {
            Err(noid_recursive::HistoryStepFreezeError::Provider(message)) => {
                assert_eq!(message, KNOWN_C00_PREFIX_PASSED);
                assert_eq!(provider.resets, 6);
                assert_eq!(provider.backbone_calls_per_reset, [13, 0, 1, 1, 11]);
                assert_eq!(store.installs.load(Ordering::Relaxed), 3);
                assert!(store.loads.load(Ordering::Relaxed) > 0);
            }
            Err(error) => panic!(
                "known-c00 prefix failed after resets={} backbone_calls={:?} installs={} loads={}: {error}",
                provider.resets,
                provider.backbone_calls_per_reset,
                store.installs.load(Ordering::Relaxed),
                store.loads.load(Ordering::Relaxed),
            ),
            Ok(_) => panic!("focused known-c00 freezer did not stop at its exact cutoff"),
        }
    }

    #[test]
    #[ignore = "runs honest VK derivation and a production c00 proof"]
    fn fresh_known_c00_terminal_verifies_before_recursive_consumption() {
        noid_ivc_prover::init_perf_thread_pool();
        let mut provider = HonestHistoryStepFixtureProvider::new(0x4849_5354_4550_5f56_31).unwrap();
        let provisional_parts = derive_focused_provisional_parts(&mut provider).unwrap();
        let store = std::sync::Arc::new(RetainedBootstrapMatrices::default());
        let zero_digests = [[0u8; 32]; noid_recursive::HISTORY_STEP_CLASS_COUNT];
        let provisional_runtime =
            focused_runtime(zero_digests, &provisional_parts, &store).unwrap();

        provider.reset_backbone();
        let genesis = noid_recursive::genesis_accumulator();
        let (_, provisional_input) = next_focused_b8(&mut provider, &genesis).unwrap();
        let provisional =
            noid_recursive::acceptance::history_step::assemble_frozen_history_step_base(
                &provisional_runtime,
                provisional_input,
            )
            .unwrap();
        let integrated_b8_vk = provisional.direct_block_vk().clone();
        drop(provisional);

        let mut integrated_vks = provisional_parts.direct_block_vks().clone();
        integrated_vks[0] = integrated_b8_vk;
        let integrated_parts = noid_recursive::HistoryStepRuntimeParts::new(
            provisional_parts.parent_recursion_vk().clone(),
            integrated_vks,
            provisional_parts.parent_transcripts().clone(),
        )
        .unwrap();
        let integrated_runtime = focused_runtime(zero_digests, &integrated_parts, &store).unwrap();

        provider.reset_backbone();
        let (_, integrated_input) = next_focused_b8(&mut provider, &genesis).unwrap();
        let integrated =
            noid_recursive::acceptance::history_step::assemble_frozen_history_step_base(
                &integrated_runtime,
                integrated_input,
            )
            .unwrap();
        assert_eq!(
            integrated.direct_block_vk(),
            &integrated_parts.direct_block_vks()[0]
        );
        let c00 = noid_recursive::CanonicalHistoryStepClassId::from_index(0).unwrap();
        let integrated_digest = integrated.matrix().structural_statement_digest();
        noid_recursive::HistoryStepFreezeMatrixStore::install(
            store.as_ref(),
            c00,
            integrated.into_matrix(),
        )
        .unwrap();

        let mut known_digests = zero_digests;
        known_digests[c00.index()] = integrated_digest;
        let known_runtime = focused_runtime(known_digests, &integrated_parts, &store).unwrap();
        provider.reset_backbone();
        let (base_block, base_input) = next_focused_b8(&mut provider, &genesis).unwrap();
        let terminal =
            noid_recursive::prove_history_step(&known_runtime, None, base_input).unwrap();
        let accepted = noid_recursive::verify_history_step_terminal(
            &known_runtime,
            &terminal,
            &base_block.header,
            &noid_chain::consensus::genesis_header(),
        )
        .unwrap();
        assert_eq!(accepted.height(), 1);
        assert_eq!(accepted.block_id(), terminal.block_id());
        assert_eq!(accepted.class_id(), c00);

        let (_, recursive_input) = next_focused_b8(&mut provider, terminal.accumulator()).unwrap();
        let recursive = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            noid_recursive::prove_history_step(&known_runtime, Some(&terminal), recursive_input)
        }));
        match recursive {
            Ok(Ok(next)) => assert_eq!(next.height(), 2),
            Ok(Err(error)) => panic!(
                "fresh c00 passed full native verification before recursive consumption failed: {error}"
            ),
            Err(payload) => {
                let message = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string panic");
                panic!(
                    "fresh c00 passed full native verification before recursive consumption panicked: {message}"
                );
            }
        }
    }

    #[test]
    #[ignore = "runs the honest frozen B8/B32 prefix and first fork class c01"]
    fn first_b8_from_b32_fork_reuses_the_frozen_b8_direct_vk() {
        noid_ivc_prover::init_perf_thread_pool();
        let mut provider = HonestHistoryStepFixtureProvider::new(0x4849_5354_4550_5f56_31).unwrap();
        let provisional_parts = derive_focused_provisional_parts(&mut provider).unwrap();
        let store = std::sync::Arc::new(RetainedBootstrapMatrices::default());
        let mut digests = [[0u8; 32]; noid_recursive::HISTORY_STEP_CLASS_COUNT];

        // Freeze c00 and its exact B8 direct VK.
        let provisional_runtime = focused_runtime(digests, &provisional_parts, &store).unwrap();
        provider.reset_backbone();
        let genesis = noid_recursive::genesis_accumulator();
        let (_, provisional_b8_input) = next_focused_b8(&mut provider, &genesis).unwrap();
        let provisional_c00 =
            noid_recursive::acceptance::history_step::assemble_frozen_history_step_base(
                &provisional_runtime,
                provisional_b8_input,
            )
            .unwrap();
        let b8_parts = replace_focused_direct_vk(
            &provisional_parts,
            0,
            provisional_c00.direct_block_vk().clone(),
        );
        drop(provisional_c00);

        let b8_runtime = focused_runtime(digests, &b8_parts, &store).unwrap();
        provider.reset_backbone();
        let (_, frozen_b8_input) = next_focused_b8(&mut provider, &genesis).unwrap();
        let frozen_c00 =
            noid_recursive::acceptance::history_step::assemble_frozen_history_step_base(
                &b8_runtime,
                frozen_b8_input,
            )
            .unwrap();
        assert_eq!(
            frozen_c00.direct_block_vk(),
            &b8_parts.direct_block_vks()[0]
        );
        let c00 = noid_recursive::CanonicalHistoryStepClassId::from_index(0).unwrap();
        digests[c00.index()] = frozen_c00.matrix().structural_statement_digest();
        noid_recursive::HistoryStepFreezeMatrixStore::install(
            store.as_ref(),
            c00,
            frozen_c00.into_matrix(),
        )
        .unwrap();

        // Freeze c04 and its exact B32 direct VK using the real ten-block B8
        // checkpoint. Reprove that checkpoint after replacing B32 because the
        // terminal authenticates the complete bank.
        let c00_runtime = focused_runtime(digests, &b8_parts, &store).unwrap();
        let first_b8_checkpoint = prove_focused_b8_checkpoint(&c00_runtime, &mut provider);
        let (_, provisional_b32_input) =
            next_focused_b32(&mut provider, first_b8_checkpoint.accumulator()).unwrap();
        let provisional_c04 =
            noid_recursive::acceptance::history_step::assemble_frozen_history_step_recursive(
                &c00_runtime,
                noid_recursive::acceptance::history_step::HistoryStepParent::new(
                    &c00_runtime,
                    &first_b8_checkpoint,
                )
                .unwrap(),
                provisional_b32_input,
            )
            .unwrap();
        let b8_b32_parts =
            replace_focused_direct_vk(&b8_parts, 1, provisional_c04.direct_block_vk().clone());
        drop(provisional_c04);

        let integrated_c00_runtime = focused_runtime(digests, &b8_b32_parts, &store).unwrap();
        let frozen_b8_checkpoint =
            prove_focused_b8_checkpoint(&integrated_c00_runtime, &mut provider);
        let (_, frozen_b32_input) =
            next_focused_b32(&mut provider, frozen_b8_checkpoint.accumulator()).unwrap();
        let frozen_c04 =
            noid_recursive::acceptance::history_step::assemble_frozen_history_step_recursive(
                &integrated_c00_runtime,
                noid_recursive::acceptance::history_step::HistoryStepParent::new(
                    &integrated_c00_runtime,
                    &frozen_b8_checkpoint,
                )
                .unwrap(),
                frozen_b32_input,
            )
            .unwrap();
        assert_eq!(
            frozen_c04.direct_block_vk(),
            &b8_b32_parts.direct_block_vks()[1]
        );
        let c04 = noid_recursive::CanonicalHistoryStepClassId::from_index(4).unwrap();
        digests[c04.index()] = frozen_c04.matrix().structural_statement_digest();
        noid_recursive::HistoryStepFreezeMatrixStore::install(
            store.as_ref(),
            c04,
            frozen_c04.into_matrix(),
        )
        .unwrap();

        // Candidate class 1 is the first non-backbone fork: current B8 over
        // the honest B32 checkpoint. Its direct relation must reuse the sole
        // frozen B8 VK byte-for-byte, independent of parent geometry.
        let frozen_runtime = focused_runtime(digests, &b8_b32_parts, &store).unwrap();
        let b32_checkpoint = prove_focused_b32_checkpoint(&frozen_runtime, &mut provider);
        let c01 = noid_recursive::CanonicalHistoryStepClassId::from_index(1).unwrap();
        assert_eq!((c01.current_tier(), c01.parent_tier()), (8, 32));
        let fork_input = provider
            .b8(c01, b32_checkpoint.accumulator())
            .unwrap()
            .into_history_step_input()
            .unwrap();
        let candidate_c01 =
            noid_recursive::acceptance::history_step::assemble_frozen_history_step_recursive(
                &frozen_runtime,
                noid_recursive::acceptance::history_step::HistoryStepParent::new(
                    &frozen_runtime,
                    &b32_checkpoint,
                )
                .unwrap(),
                fork_input,
            )
            .unwrap();
        assert_eq!(candidate_c01.class_id(), c01);

        let expected = focused_block_vk_geometry(&b8_b32_parts.direct_block_vks()[0]);
        let actual = focused_block_vk_geometry(candidate_c01.direct_block_vk());
        for (expected_role, actual_role) in expected.iter().zip(&actual) {
            eprintln!(
                "[focused-c01-vk] class=c01 current=B8 parent=B32 role={} expected_rows={} actual_rows={} expected_starts={:?} actual_starts={:?}",
                expected_role.role,
                expected_role.row_count,
                actual_role.row_count,
                expected_role.slice_starts,
                actual_role.slice_starts,
            );
        }
        assert_eq!(
            actual, expected,
            "c01 current B8 / parent B32 relocated the frozen B8 direct VK"
        );
    }
}
