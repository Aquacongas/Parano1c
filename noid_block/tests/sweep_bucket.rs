// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Sweep25x2 block-bucket binding tests.
//!
//! These tests exercise the redesigned Sweep25x2 bucket layer: per-tx
//! SweepAuth proofs and body-bound `SweepTxLogicAir` algebraics are aggregated
//! with one block-side `SweepBlockSpineProof` and bound to concrete block
//! transaction indices.

use noid_air::airs::block_state_binding::BlockStateBindingClaim;
use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_air::Air;
use noid_block::{
    assemble_sweep_bucket_proof, block_recursive_claim_hash, build_state_binding_airs,
    build_state_bindings_from_binding, build_tx_witness, extract_replay_witness,
    prove_block_with_total_tx_count, prove_state_bindings_standalone,
    validate_block_bucket_tx_indices, validate_block_proof_transcript_hash,
    verify_state_bindings_standalone, verify_sweep_bucket_from_block, BlockProof, BlockPublicMeta,
    OwnedTxWitness, TxBlockWitness, VerifyBlockError,
};
use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::params::GENESIS_TARGET;
use noid_chain::segmented_state::SegmentColumns;
use noid_chain::state::ChainState;
use noid_chain::state_binding::{BlockStateBinding, StateBindingError};
use noid_chain::{build_state_delta_witness, SlotValue, StateDeltaActionKind, StateDeltaWitness};
use noid_core::{Block128, TowerField};
use noid_gkr::{
    auth_gkr_channel, compute_auth_boundary, prove_auth_killshot, AuthCircuit, AuthInputs,
    AuthProofKillShot, AuthPublicInputs, SpineInputs, N_AUTH_INPUTS,
};
use noid_poseidon2b::primitives::{
    derive_address, hash_auth_tag, Address, AuthTag, SpendSecret, TxBodyHash,
};
use noid_recursive::{
    accumulator::genesis_accumulator, air::RecursiveBlockAir, prove::prove_recursive_step,
    verify::verify_recursive_step,
};
use noid_stark::prove_logic_sweep::{
    prove_sweep_logic, sweep_logic_witness_parts_from_body, SweepLogicWitness,
};
use noid_stark::{SweepWalletProofBundle, WalletProofBundle};
use noid_tx::{
    compute_claims_commitment, hash_tx_body_for_shape, PublicInputs, Transaction, TxBody, TxInput,
    TxOutput, TxShape, MAX_INPUTS, MAX_OUTPUTS,
};
use std::collections::HashMap;

const TEST_LOG_SLOTS: u32 = 24;

fn mk_secret(seed: u8) -> SpendSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_mul(19).wrapping_add(i as u8).wrapping_add(7);
    }
    SpendSecret(bytes)
}

fn mk_sweep_mint_body() -> TxBody {
    TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor: [0x5A; 32],
        fee: 0,
        inputs: vec![],
        outputs: vec![TxOutput {
            slot_index: 7,
            value: 12_345,
            owner: Address([0xA1; 32]),
            valid: true,
        }],
        is_coinbase: false,
    }
}

fn mk_sweep_body(n_live_inputs: usize) -> TxBody {
    assert!(n_live_inputs <= TxShape::Sweep25x2.max_inputs());
    let mut inputs = Vec::with_capacity(n_live_inputs);
    for i in 0..n_live_inputs {
        let secret = mk_secret(i as u8 + 1);
        let owner = derive_address(&secret);
        inputs.push(TxInput {
            slot_index: 1_000 + i as u32,
            value: 10_000 + i as u64,
            owner,
            spend_secret: secret,
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        });
    }

    let total: u64 = inputs.iter().map(|i| i.value).sum();
    let fee = 777u64;
    let spendable = total - fee;

    let mut body = TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor: [0x5A; 32],
        fee: fee as u128,
        inputs,
        outputs: vec![
            TxOutput {
                slot_index: 50_000,
                value: spendable / 2,
                owner: Address([0xA1; 32]),
                valid: true,
            },
            TxOutput {
                slot_index: 50_001,
                value: spendable - spendable / 2,
                owner: Address([0xA2; 32]),
                valid: true,
            },
        ],
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
    for input in &mut body.inputs {
        input.auth_tag = hash_auth_tag(&input.spend_secret, &tx_hash);
    }

    body
}

fn public_inputs_for_body(body: &TxBody) -> PublicInputs {
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
        log_slots: TEST_LOG_SLOTS,
        claims_commitment: compute_claims_commitment(&body.inputs, &body.outputs),
        is_activation: [false; MAX_OUTPUTS],
        is_deactivation: [false; MAX_INPUTS],
    }
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

fn seed_slot(state: &mut ChainState, slot_index: u32, value: u64, owner: Address) {
    let [owner_hi, owner_lo] = owner.as_fields();
    state
        .state
        .set_slot(
            slot_index,
            SlotValue {
                value: Block128::from(value as u128),
                owner_hi,
                owner_lo,
            },
        )
        .expect("test slot in range");
    state.active_slot_count += 1;
}

fn pre_segments_for_state(
    state: &ChainState,
    slot_indices: &[u32],
) -> HashMap<u16, SegmentColumns> {
    let eff_log = state.state.effective_log_segment_size();
    let seg_size = 1usize << eff_log;
    let mut pre_segs = HashMap::new();
    for slot in slot_indices {
        let seg_id = (*slot >> eff_log) as u16;
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

fn patch_binding_new_root_with_coinbase(
    binding: &mut BlockStateBinding,
    mut post_state: noid_chain::segmented_state::SegmentedFriState,
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
            .expect("coinbase slot in range");
    }
    binding.new_state_root = post_state.root();
}

fn sorted_claim_pairs(
    mut pairs: Vec<(u16, BlockStateBindingClaim)>,
) -> Vec<(u16, BlockStateBindingClaim)> {
    pairs.sort_by_key(|(seg_id, claim)| {
        (
            *seg_id,
            claim.slot_index,
            claim.is_mint,
            claim.is_spend,
            claim.value.to_u128(),
            claim.owner_hi.to_u128(),
            claim.owner_lo.to_u128(),
            claim.delta_value.to_u128(),
            claim.delta_owner_hi.to_u128(),
            claim.delta_owner_lo.to_u128(),
        )
    });
    pairs
}

fn owned_state_binding_claim_pairs(
    owned: &[noid_block::OwnedStateBindingWitness],
) -> Vec<(u16, BlockStateBindingClaim)> {
    sorted_claim_pairs(
        owned
            .iter()
            .flat_map(|binding| {
                binding
                    .claims
                    .iter()
                    .copied()
                    .map(|claim| (binding.seg_id, claim))
            })
            .collect(),
    )
}

fn state_delta_claim_pairs(
    delta: &StateDeltaWitness,
    coinbase_body: Option<&TxBody>,
    log_slots: u32,
) -> Vec<(u16, BlockStateBindingClaim)> {
    let eff_log =
        (log_slots as usize).min(noid_chain::consensus::params::LOG_SEGMENT_SIZE as usize);
    let seg_mask = (1u32 << eff_log) - 1;
    let mut pairs = Vec::new();

    if let Some(coinbase) = coinbase_body {
        for output in coinbase.outputs.iter().filter(|output| output.valid) {
            let seg_id = (output.slot_index >> eff_log) as u16;
            let local = output.slot_index & seg_mask;
            let [owner_hi, owner_lo] = output.owner.as_fields();
            pairs.push((
                seg_id,
                BlockStateBindingClaim::mint(
                    local,
                    Block128::from(output.value as u128),
                    owner_hi,
                    owner_lo,
                ),
            ));
        }
    }

    for action in &delta.actions {
        let seg_id = (action.slot_index >> eff_log) as u16;
        let local = action.slot_index & seg_mask;
        let claim = match action.kind {
            StateDeltaActionKind::Spend => BlockStateBindingClaim::spend(
                local,
                action.pre.value,
                action.pre.owner_hi,
                action.pre.owner_lo,
            ),
            StateDeltaActionKind::Mint => BlockStateBindingClaim::mint(
                local,
                action.post.value,
                action.post.owner_hi,
                action.post.owner_lo,
            ),
        };
        pairs.push((seg_id, claim));
    }

    sorted_claim_pairs(pairs)
}

fn coinbase_tx() -> Transaction {
    tx_from_body(TxBody {
        shape: TxShape::Standard4x8,
        epoch_anchor: [0u8; 32],
        fee: 0,
        inputs: vec![],
        outputs: vec![TxOutput {
            slot_index: 42,
            value: 5000,
            owner: Address([0xC0; 32]),
            valid: true,
        }],
        is_coinbase: true,
    })
}

fn block_with_user_tx(user_tx: Transaction) -> Block {
    Block {
        header: BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            timestamp: 1,
            height: 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [0u8; 32],
            witness_root: [0u8; 32],
            log_slots: TEST_LOG_SLOTS,
            active_slot_count: 0,
            alloc_counter: 0,
        },
        transactions: vec![coinbase_tx(), user_tx],
    }
}

#[allow(dead_code)]
fn block_with_standard_and_sweep_tx(standard_tx: Transaction, sweep_tx: Transaction) -> Block {
    let mut block = block_with_user_tx(standard_tx);
    block.transactions.push(sweep_tx);
    block
}

#[allow(dead_code)]
fn mk_standard_secret(seed: u128) -> [Block128; 2] {
    [
        Block128::from(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_A5A5_A5A5_A5A5),
        Block128::from(seed.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A),
    ]
}

#[allow(dead_code)]
fn fields_to_bytes(f: [Block128; 2]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&f[0].to_u128().to_le_bytes());
    out[16..].copy_from_slice(&f[1].to_u128().to_le_bytes());
    out
}

#[allow(dead_code)]
struct StandardFixture {
    body: TxBody,
    air: TxLogicAir,
    trace: noid_air::Trace,
    pi: PublicInputs,
    spine_inputs: SpineInputs,
    auth_public: AuthPublicInputs,
    auth_proof: AuthProofKillShot,
}

#[allow(dead_code)]
fn standard_fixture() -> StandardFixture {
    standard_fixture_with_params(0xA1, 0, 10, 0xAA)
}

#[allow(dead_code)]
fn standard_fixture_with_params(
    seed_base: u128,
    input_slot_base: u32,
    output_slot_base: u32,
    epoch: u8,
) -> StandardFixture {
    let secrets = [
        mk_standard_secret(seed_base),
        mk_standard_secret(seed_base.wrapping_add(0x11)),
    ];
    let addrs: Vec<_> = secrets
        .iter()
        .map(|s| derive_address(&SpendSecret(fields_to_bytes(*s))))
        .collect();

    let mut inputs = vec![
        TxInput {
            slot_index: input_slot_base,
            value: 100,
            owner: addrs[0],
            spend_secret: SpendSecret(fields_to_bytes(secrets[0])),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        },
        TxInput {
            slot_index: input_slot_base + 1,
            value: 50,
            owner: addrs[1],
            spend_secret: SpendSecret(fields_to_bytes(secrets[1])),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        },
    ];
    while inputs.len() < MAX_INPUTS {
        inputs.push(TxInput::dummy());
    }

    let mut outputs = vec![
        TxOutput {
            slot_index: output_slot_base,
            value: 80,
            owner: addrs[0],
            valid: true,
        },
        TxOutput {
            slot_index: output_slot_base + 1,
            value: 60,
            owner: addrs[1],
            valid: true,
        },
    ];
    while outputs.len() < MAX_OUTPUTS {
        outputs.push(TxOutput::dummy());
    }

    let mut body = TxBody {
        shape: TxShape::Standard4x8,
        epoch_anchor: [epoch; 32],
        fee: 10,
        inputs,
        outputs,
        is_coinbase: false,
    };

    let pins = boundary_pins_from_body(&body);
    for i in 0..2 {
        body.inputs[i].auth_tag = hash_auth_tag(
            &SpendSecret(fields_to_bytes(secrets[i])),
            &TxBodyHash(fields_to_bytes(pins.tx_body_hash)),
        );
    }

    let pins = boundary_pins_from_body(&body);
    let air = TxLogicAir::new(pins);
    let trace = air.build_trace(&witness_from_body(&body));
    let mut is_activation = [false; MAX_OUTPUTS];
    for (j, output) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
        is_activation[j] = output.valid;
    }
    let mut is_deactivation = [false; MAX_INPUTS];
    for (i, input) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
        is_deactivation[i] = input.valid;
    }
    let pi = PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash: TxBodyHash(fields_to_bytes(pins.tx_body_hash)),
        shape_id: body.shape.id(),
        fee: body.fee,
        n_live_inputs: body.inputs.iter().filter(|i| i.valid).count() as u8,
        n_live_outputs: body.outputs.iter().filter(|o| o.valid).count() as u8,
        coinbase_credit: 0,
        log_slots: TEST_LOG_SLOTS,
        claims_commitment: compute_claims_commitment(&body.inputs, &body.outputs),
        is_activation,
        is_deactivation,
    };
    let spine_inputs = SpineInputs {
        epoch_anchor: pins.epoch_anchor,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    };

    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for (dst, src) in spend_secret.iter_mut().zip(secrets.iter()) {
        *dst = *src;
    }
    let circuit = AuthCircuit::build();
    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&circuit, spend_secret, pi.tx_body_hash.as_fields());
    let auth_inputs = AuthInputs {
        spend_secret,
        tx_body_hash: pi.tx_body_hash.as_fields(),
        expected_address,
        expected_auth_tag,
    };
    let mut ch = auth_gkr_channel();
    let (auth_proof, _) = prove_auth_killshot(&circuit, &auth_inputs, &mut ch);

    StandardFixture {
        body,
        air,
        trace,
        pi,
        spine_inputs,
        auth_public: auth_inputs.to_public(),
        auth_proof,
    }
}

fn prove_sweep_bundle(body: &TxBody) -> WalletProofBundle {
    let pi = public_inputs_for_body(body);
    let (air, trace, auth_inputs, _) = sweep_logic_witness_parts_from_body(body);
    assert!(air.check(&trace));
    let witness = SweepLogicWitness {
        air: &air,
        trace: &trace,
        pi: &pi,
        auth_inputs: &auth_inputs,
    };
    let logic_proof = prove_sweep_logic(&witness).expect("prove sweep logic");
    WalletProofBundle::Sweep25x2(SweepWalletProofBundle {
        logic_proof,
        auth_public: auth_inputs.to_public(),
    })
}

fn empty_bucketized_proof(n_tx: u32) -> BlockProof {
    BlockProof {
        meta: BlockPublicMeta {
            prev_block_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            n_tx,
            n_air_per_tx: 0,
            n_auth_slices_per_tx: 0,
            log_rows: noid_air::airs::tx_body_spine::SPINE_LOG_ROWS as u32,
            n_block_spine_slices: 0,
            n_state_bindings: 0,
            state_binding_n_cols: 0,
            state_binding_log_rows: 0,
        },
        standard_bucket: None,
        sweep_bucket: None,
        state_binding_algebraics: vec![],
        state_binding_starks: vec![],
        pre_state_openings: vec![],
        post_state_openings: vec![],
    }
}

fn sweep_bucket_proof_for_body(body: TxBody) -> (Block, BlockProof) {
    let bundle = prove_sweep_bundle(&body);
    let block = block_with_user_tx(tx_from_body(body));
    let owned = noid_block::build_block_witnesses(&block.transactions, &[bundle], TEST_LOG_SLOTS);
    let sweep_witnesses: Vec<_> = owned
        .into_iter()
        .map(|w| match w {
            OwnedTxWitness::Sweep25x2(w) => w,
            OwnedTxWitness::Standard4x8(_) => panic!("expected sweep witness"),
        })
        .collect();
    assert_eq!(sweep_witnesses[0].block_tx_index, 1);

    let sweep_bucket = assemble_sweep_bucket_proof([0u8; 32], &sweep_witnesses)
        .expect("assemble sweep bucket")
        .expect("non-empty sweep bucket");

    let proof = BlockProof {
        meta: BlockPublicMeta {
            prev_block_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            n_tx: 1,
            n_air_per_tx: 0,
            n_auth_slices_per_tx: 0,
            log_rows: noid_air::airs::tx_body_spine::SPINE_LOG_ROWS as u32,
            n_block_spine_slices: 0,
            n_state_bindings: 0,
            state_binding_n_cols: 0,
            state_binding_log_rows: 0,
        },
        standard_bucket: None,
        sweep_bucket: Some(sweep_bucket),
        state_binding_algebraics: vec![],
        state_binding_starks: vec![],
        pre_state_openings: vec![],
        post_state_openings: vec![],
    };
    (block, proof)
}

#[allow(dead_code)]
fn block_with_user_txs(mut user_txs: Vec<Transaction>) -> Block {
    assert!(
        !user_txs.is_empty(),
        "test block needs at least one user tx"
    );
    let first = user_txs.remove(0);
    let mut block = block_with_user_tx(first);
    block.transactions.extend(user_txs);
    block
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[allow(dead_code)]
fn mixed_block_proof() -> (Block, BlockProof) {
    mixed_block_proof_with_counts(1, 1)
}

#[allow(dead_code)]
fn mixed_block_proof_with_counts(n_standard: usize, n_sweep: usize) -> (Block, BlockProof) {
    assert!(n_standard > 0, "mixed test needs at least one standard tx");
    assert!(n_sweep > 0, "mixed test needs at least one sweep tx");

    let standards: Vec<_> = (0..n_standard)
        .map(|i| {
            standard_fixture_with_params(
                0xA1 + (i as u128) * 0x20,
                (i as u32) * 10,
                100 + (i as u32) * 10,
                0xAAu8.wrapping_add(i as u8),
            )
        })
        .collect();
    let sweep_bodies: Vec<_> = (0..n_sweep).map(|i| mk_sweep_body(5 + i)).collect();

    let mut txs = Vec::with_capacity(n_standard + n_sweep);
    txs.extend(standards.iter().map(|s| tx_from_body(s.body.clone())));
    txs.extend(sweep_bodies.iter().cloned().map(tx_from_body));
    let block = block_with_user_txs(txs);

    let standard_witnesses: Vec<_> = standards
        .iter()
        .enumerate()
        .map(|(i, standard)| TxBlockWitness {
            block_tx_index: 1 + i as u32,
            air: &standard.air as &dyn Air,
            trace: &standard.trace,
            pi: &standard.pi,
            spine_inputs: &standard.spine_inputs,
            auth_public: &standard.auth_public,
            auth_proof: &standard.auth_proof,
        })
        .collect();
    let mut proof = prove_block_with_total_tx_count(
        [0u8; 32],
        [0u8; 32],
        &standard_witnesses,
        &[],
        (n_standard + n_sweep) as u32,
    )
    .expect("prove standard bucket for mixed block");

    let sweep_bundles: Vec<_> = sweep_bodies.iter().map(prove_sweep_bundle).collect();
    let sweep_witnesses: Vec<_> = sweep_bodies
        .iter()
        .zip(sweep_bundles.iter())
        .enumerate()
        .map(|(i, (body, bundle))| {
            match build_tx_witness(
                1 + n_standard as u32 + i as u32,
                body,
                bundle,
                TEST_LOG_SLOTS,
            ) {
                OwnedTxWitness::Sweep25x2(w) => w,
                OwnedTxWitness::Standard4x8(_) => panic!("expected sweep witness"),
            }
        })
        .collect();
    proof.sweep_bucket = Some(
        assemble_sweep_bucket_proof([0u8; 32], &sweep_witnesses)
            .expect("assemble sweep bucket")
            .expect("non-empty sweep bucket"),
    );

    (block, proof)
}

#[test]
fn canonical_recursive_claim_hash_is_deterministic_and_binds_meta() {
    let proof = empty_bucketized_proof(0);
    assert_eq!(
        block_recursive_claim_hash(&proof),
        block_recursive_claim_hash(&proof)
    );

    let mut tampered = proof.clone();
    tampered.meta.n_tx = 1;
    assert_ne!(
        block_recursive_claim_hash(&proof),
        block_recursive_claim_hash(&tampered)
    );
}

#[test]
fn proof_transcript_hash_mismatch_rejects() {
    let mut block = block_with_user_tx(tx_from_body(mk_sweep_mint_body()));
    let proof = empty_bucketized_proof(1);

    block.header.proof_transcript_hash = [0u8; 32];
    assert!(validate_block_proof_transcript_hash(&block, &proof).is_err());

    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);
    validate_block_proof_transcript_hash(&block, &proof).expect("matching hash accepts");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_assembles_and_verifies_from_owned_witness() {
    let (block, proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    validate_block_bucket_tx_indices(&block, &proof).expect("bucket coverage");
    verify_sweep_bucket_from_block(&block, &proof).expect("sweep bucket verifies");

    let bucket = proof.sweep_bucket.as_ref().expect("sweep bucket");
    assert_eq!(bucket.meta.shape, TxShape::Sweep25x2);
    assert_eq!(bucket.meta.tx_indices, vec![1]);
    assert_eq!(bucket.tx_pis[0].shape_id, TxShape::Sweep25x2.id());
    assert_eq!(bucket.tx_auth_proofs.len(), 1);
    assert_eq!(bucket.meta.n_boundary_slices_per_tx, 0);
    assert_eq!(bucket.commitment.n_cols, bucket.block_col_openings.len());
    assert!(
        bucket.commitment.n_cols
            < bucket.meta.n_air_per_tx as usize + bucket.meta.n_block_spine_slices as usize,
        "public AIR columns should be verifier-derived, not committed"
    );
    assert!(bucket.byte_len() > 0);

    let canonical_hash = block_recursive_claim_hash(&proof);
    let mut tampered = proof.clone();
    tampered.sweep_bucket.as_mut().unwrap().meta.tx_indices[0] = 2;
    assert_ne!(canonical_hash, block_recursive_claim_hash(&tampered));
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_index_and_shape_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof.sweep_bucket.as_mut().unwrap().meta.tx_indices[0] = 0;
    assert!(validate_block_bucket_tx_indices(&block, &proof).is_err());

    proof.sweep_bucket.as_mut().unwrap().meta.tx_indices[0] = 1;
    proof.sweep_bucket.as_mut().unwrap().tx_pis[0].shape_id = TxShape::Standard4x8.id();
    assert!(validate_block_bucket_tx_indices(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_spine_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    let bucket = proof.sweep_bucket.as_mut().unwrap();
    bucket.spine_inputs[0].output_leaves[0][0] += Block128::ONE;

    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_missing_auth_proof() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof.sweep_bucket.as_mut().unwrap().tx_auth_proofs.pop();
    assert!(validate_block_bucket_tx_indices(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_auth_capsule_pcs_value_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof.sweep_bucket.as_mut().unwrap().tx_auth_proofs[0]
        .pcs
        .opening
        .all_openings[0] += Block128::ONE;
    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_aggregation_opening_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof.sweep_bucket.as_mut().unwrap().block_col_openings[0] += Block128::ONE;
    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    let err = verify_sweep_bucket_from_block(&block, &proof).expect_err("tampered opening rejects");
    assert!(
        matches!(err, VerifyBlockError::AlgebraicTerminal(0)),
        "unexpected error: {err:?}"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_block_initial_claim_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof.sweep_bucket.as_mut().unwrap().block_initial_claim += Block128::ONE;
    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_block_multipoint_challenge_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof
        .sweep_bucket
        .as_mut()
        .unwrap()
        .block_multipoint_challenges[0] += Block128::ONE;
    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_recursive_claim_hash_binds_new_sweep_auth_proof_field() {
    let (mut block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);
    validate_block_proof_transcript_hash(&block, &proof).expect("honest transcript hash");

    let canonical_hash = block.header.proof_transcript_hash;
    proof.sweep_bucket.as_mut().unwrap().tx_auth_proofs[0]
        .batch
        .b_finals[0] += Block128::ONE;

    assert_ne!(canonical_hash, block_recursive_claim_hash(&proof));
    assert!(
        validate_block_proof_transcript_hash(&block, &proof).is_err(),
        "header transcript hash must bind per-tx sweep auth proofs"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_recursive_claim_hash_binds_block_spine_proof_field() {
    let (mut block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);
    validate_block_proof_transcript_hash(&block, &proof).expect("honest transcript hash");

    let canonical_hash = block.header.proof_transcript_hash;
    proof
        .sweep_bucket
        .as_mut()
        .unwrap()
        .block_spine_proof
        .state_batch
        .b_final += Block128::ONE;

    assert_ne!(canonical_hash, block_recursive_claim_hash(&proof));
    assert!(
        validate_block_proof_transcript_hash(&block, &proof).is_err(),
        "header transcript hash must bind the sweep block-spine proof"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_recursive_claim_hash_binds_committed_spine_columns() {
    let (mut block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);
    validate_block_proof_transcript_hash(&block, &proof).expect("honest transcript hash");

    let canonical_hash = block.header.proof_transcript_hash;
    proof.sweep_bucket.as_mut().unwrap().commitment.cap.hashes[0][0] ^= 0x01;

    assert_ne!(canonical_hash, block_recursive_claim_hash(&proof));
    assert!(
        validate_block_proof_transcript_hash(&block, &proof).is_err(),
        "header transcript hash must bind sweep bucket committed columns"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_only_replay_witness_zeroes_unused_secondary_lane() {
    let (_block, proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));
    let witness = extract_replay_witness(&proof).expect("sweep-only replay witness");

    assert_eq!(witness.block_secondary_initial_claim, Block128::ZERO);
    assert!(witness
        .block_secondary_multipoint_rounds
        .iter()
        .flatten()
        .all(|v| *v == Block128::ZERO));
    assert!(witness
        .block_secondary_multipoint_challenges
        .iter()
        .all(|v| *v == Block128::ZERO));
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_mixed_opening_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof
        .sweep_bucket
        .as_mut()
        .unwrap()
        .mixed_opening
        .all_openings[0] += Block128::ONE;
    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_only_replay_witness_extracts_and_recursive_step_verifies() {
    let (mut block, proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);

    let witness = extract_replay_witness(&proof).expect("sweep-only replay witness");
    let sweep_bucket = proof.sweep_bucket.as_ref().expect("sweep bucket");
    assert_eq!(
        witness.block_initial_claim,
        sweep_bucket.block_initial_claim
    );
    assert_eq!(
        witness.chain_claim,
        noid_block::block_recursive_claim_field(&proof)
    );
    assert_eq!(
        witness.block_multipoint_rounds,
        sweep_bucket.block_multipoint_rounds
    );

    let prev_acc = genesis_accumulator([0u8; 32], [0u8; 32]);
    let rec_proof = prove_recursive_step(&witness, &block.header, &prev_acc, None);
    let rec_air = RecursiveBlockAir::from_prev_state_root(&prev_acc.state_root);
    verify_recursive_step(&rec_proof, &prev_acc, &block.header, &rec_air)
        .expect("sweep-only recursive step verifies");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_block_proof_does_not_serialize_spend_secret_bytes() {
    let (block, proof) = mixed_block_proof();
    let raw_secrets: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .flat_map(|tx| tx.body.inputs.iter())
        .filter(|input| input.valid)
        .map(|input| input.spend_secret.0)
        .collect();
    assert!(!raw_secrets.is_empty(), "test must contain spend secrets");

    let proof_bytes = bincode::serialize(&proof).expect("serialize block proof");
    for raw_secret in raw_secrets {
        assert!(
            !contains_subslice(&proof_bytes, &raw_secret),
            "block proof must not contain raw spend_secret bytes"
        );
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_replay_witness_extracts_secondary_lane_and_recursive_step_verifies() {
    let (mut block, proof) = mixed_block_proof();
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);

    validate_block_bucket_tx_indices(&block, &proof).expect("mixed bucket coverage");
    verify_sweep_bucket_from_block(&block, &proof).expect("mixed sweep bucket verifies");
    validate_block_proof_transcript_hash(&block, &proof).expect("mixed header transcript hash");

    let standard_bucket = proof.standard_bucket.as_ref().expect("standard bucket");
    let sweep_bucket = proof.sweep_bucket.as_ref().expect("sweep bucket");
    let witness = extract_replay_witness(&proof).expect("mixed replay witness");

    assert_eq!(
        witness.block_initial_claim,
        standard_bucket.block_initial_claim
    );
    assert_eq!(
        witness.block_multipoint_rounds,
        standard_bucket.block_multipoint_rounds
    );
    assert_eq!(
        witness.block_multipoint_challenges,
        standard_bucket.block_multipoint_challenges
    );
    assert_eq!(
        witness.block_secondary_initial_claim,
        sweep_bucket.block_initial_claim
    );
    assert_eq!(
        witness.block_secondary_multipoint_rounds,
        sweep_bucket.block_multipoint_rounds
    );
    assert_eq!(
        witness.block_secondary_multipoint_challenges,
        sweep_bucket.block_multipoint_challenges
    );
    assert_eq!(
        witness.chain_claim,
        noid_block::block_recursive_claim_field(&proof)
    );

    let prev_acc = genesis_accumulator([0u8; 32], [0u8; 32]);
    let rec_proof = prove_recursive_step(&witness, &block.header, &prev_acc, None);
    let rec_air = RecursiveBlockAir::from_prev_state_root(&prev_acc.state_root);
    verify_recursive_step(&rec_proof, &prev_acc, &block.header, &rec_air)
        .expect("mixed recursive step verifies");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_many_standard_one_sweep_replay_witness_verifies() {
    let (mut block, proof) = mixed_block_proof_with_counts(2, 1);
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);

    validate_block_bucket_tx_indices(&block, &proof).expect("mixed coverage");
    verify_sweep_bucket_from_block(&block, &proof).expect("mixed sweep bucket verifies");
    validate_block_proof_transcript_hash(&block, &proof).expect("mixed transcript hash");

    let standard_bucket = proof.standard_bucket.as_ref().expect("standard bucket");
    let sweep_bucket = proof.sweep_bucket.as_ref().expect("sweep bucket");
    assert_eq!(standard_bucket.meta.tx_indices, vec![1, 2]);
    assert_eq!(sweep_bucket.meta.tx_indices, vec![3]);

    let witness = extract_replay_witness(&proof).expect("mixed replay witness");
    assert_eq!(
        witness.block_multipoint_rounds,
        standard_bucket.block_multipoint_rounds
    );
    assert_eq!(
        witness.block_secondary_multipoint_rounds,
        sweep_bucket.block_multipoint_rounds
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_one_standard_many_sweep_replay_witness_verifies() {
    let (mut block, proof) = mixed_block_proof_with_counts(1, 2);
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);

    validate_block_bucket_tx_indices(&block, &proof).expect("mixed coverage");
    verify_sweep_bucket_from_block(&block, &proof).expect("mixed sweep bucket verifies");
    validate_block_proof_transcript_hash(&block, &proof).expect("mixed transcript hash");

    let standard_bucket = proof.standard_bucket.as_ref().expect("standard bucket");
    let sweep_bucket = proof.sweep_bucket.as_ref().expect("sweep bucket");
    assert_eq!(standard_bucket.meta.tx_indices, vec![1]);
    assert_eq!(sweep_bucket.meta.tx_indices, vec![2, 3]);

    let witness = extract_replay_witness(&proof).expect("mixed replay witness");
    assert_eq!(
        witness.block_multipoint_rounds,
        standard_bucket.block_multipoint_rounds
    );
    assert_eq!(
        witness.block_secondary_multipoint_rounds,
        sweep_bucket.block_multipoint_rounds
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_block_rejects_duplicate_and_missing_bucket_indices() {
    let (block, proof) = mixed_block_proof();
    validate_block_bucket_tx_indices(&block, &proof).expect("honest mixed coverage");

    let mut duplicate = proof.clone();
    duplicate.sweep_bucket.as_mut().unwrap().meta.tx_indices = vec![1];
    assert!(
        validate_block_bucket_tx_indices(&block, &duplicate).is_err(),
        "duplicate standard/sweep index must reject"
    );

    let mut missing = proof;
    missing
        .sweep_bucket
        .as_mut()
        .unwrap()
        .meta
        .tx_indices
        .clear();
    missing.sweep_bucket.as_mut().unwrap().tx_pis.clear();
    missing.sweep_bucket.as_mut().unwrap().auth_public.clear();
    missing
        .sweep_bucket
        .as_mut()
        .unwrap()
        .tx_auth_proofs
        .clear();
    missing.sweep_bucket.as_mut().unwrap().spine_inputs.clear();
    assert!(
        validate_block_bucket_tx_indices(&block, &missing).is_err(),
        "missing sweep tx index must reject"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_block_rejects_cross_shape_bucket_indices() {
    let (block, proof) = mixed_block_proof();
    validate_block_bucket_tx_indices(&block, &proof).expect("honest mixed coverage");

    let mut sweep_in_standard = proof.clone();
    sweep_in_standard
        .standard_bucket
        .as_mut()
        .unwrap()
        .meta
        .tx_indices = vec![2];
    assert!(
        validate_block_bucket_tx_indices(&block, &sweep_in_standard).is_err(),
        "sweep tx claimed by standard bucket must reject"
    );

    let mut standard_in_sweep = proof;
    standard_in_sweep
        .sweep_bucket
        .as_mut()
        .unwrap()
        .meta
        .tx_indices = vec![1];
    assert!(
        validate_block_bucket_tx_indices(&block, &standard_in_sweep).is_err(),
        "standard tx claimed by sweep bucket must reject"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_bucket_order_tampering_rejects() {
    let (block, mut proof) = mixed_block_proof_with_counts(2, 1);
    validate_block_bucket_tx_indices(&block, &proof).expect("honest mixed coverage");

    proof
        .standard_bucket
        .as_mut()
        .unwrap()
        .meta
        .tx_indices
        .swap(0, 1);
    assert!(
        validate_block_bucket_tx_indices(&block, &proof).is_err(),
        "non-canonical bucket tx order must reject"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_block_rejects_swapped_sweep_bucket_after_validation() {
    let (block, mut proof) = mixed_block_proof();
    validate_block_bucket_tx_indices(&block, &proof).expect("honest mixed coverage");

    let (_other_block, other_sweep_only_proof) = sweep_bucket_proof_for_body(mk_sweep_body(6));
    let mut swapped_bucket = other_sweep_only_proof
        .sweep_bucket
        .expect("alternate sweep bucket");
    swapped_bucket.meta.tx_indices = vec![2];
    proof.sweep_bucket = Some(swapped_bucket);

    assert!(
        validate_block_bucket_tx_indices(&block, &proof).is_err(),
        "a valid sweep bucket for another tx body must not bind to the mixed block"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_header_transcript_rejects_state_meta_tamper() {
    let (mut block, mut proof) = mixed_block_proof();
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);
    validate_block_proof_transcript_hash(&block, &proof).expect("honest transcript hash");

    let canonical_hash = block.header.proof_transcript_hash;
    proof.meta.new_state_root[0] ^= 0x01;

    assert_ne!(canonical_hash, block_recursive_claim_hash(&proof));
    assert!(
        validate_block_proof_transcript_hash(&block, &proof).is_err(),
        "header proof_transcript_hash must bind mixed proof state metadata"
    );
}

#[test]
fn sweep_only_state_binding_witness_includes_coinbase_claims() {
    let body = mk_sweep_mint_body();
    let coinbase = coinbase_tx().body;
    let commitment = compute_claims_commitment(&body.inputs, &body.outputs);

    let mut state = ChainState::with_log_slots(6);
    let prev_state_root = state.state_root();
    let mut binding_state = state.state.clone();
    let mut binding = BlockStateBinding::build(&mut binding_state, &[body.clone()], &[commitment])
        .expect("build sweep-only binding");
    patch_binding_new_root_with_coinbase(&mut binding, binding_state, &coinbase);

    let pre_segs = pre_segments_for_state(&state, &[7, 42]);
    let owned = build_state_bindings_from_binding(
        &binding,
        &[body.clone()],
        Some(&coinbase),
        &pre_segs,
        prev_state_root,
        1,
        6,
    );

    let mut delta_state = state.state.clone();
    let delta = build_state_delta_witness(&mut delta_state, &[body], &[commitment])
        .expect("build native state-delta witness");
    assert_eq!(
        owned_state_binding_claim_pairs(&owned),
        state_delta_claim_pairs(&delta, Some(&coinbase), 6),
        "current BlockStateBindingAir claims must match native state-delta actions"
    );

    assert_eq!(owned.len(), 1, "test fixture touches one segment");
    let claims = &owned[0].claims;
    assert_eq!(claims.len(), 2, "sweep mint plus coinbase mint");
    assert!(claims
        .iter()
        .any(|c| c.is_mint && c.slot_index == 7 && c.value == Block128::from(12_345u128)));
    assert!(claims
        .iter()
        .any(|c| c.is_mint && c.slot_index == 42 && c.value == Block128::from(5_000u128)));
}

#[test]
fn mixed_state_binding_witness_is_common_across_standard_sweep_and_coinbase() {
    let standard = standard_fixture();
    let sweep_owner = Address([0x51; 32]);
    let sweep_body = TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor: [0x5A; 32],
        fee: 100,
        inputs: vec![TxInput {
            slot_index: 3,
            value: 1_000,
            owner: sweep_owner,
            spend_secret: SpendSecret([0x51; 32]),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        }],
        outputs: vec![TxOutput {
            slot_index: 12,
            value: 900,
            owner: Address([0x52; 32]),
            valid: true,
        }],
        is_coinbase: false,
    };
    let coinbase = coinbase_tx().body;

    let mut state = ChainState::with_log_slots(6);
    for input in standard.body.inputs.iter().filter(|i| i.valid) {
        seed_slot(&mut state, input.slot_index, input.value, input.owner);
    }
    seed_slot(&mut state, 3, 1_000, sweep_owner);
    let prev_state_root = state.state_root();

    let bodies = vec![standard.body.clone(), sweep_body.clone()];
    let commitments = vec![
        compute_claims_commitment(&standard.body.inputs, &standard.body.outputs),
        compute_claims_commitment(&sweep_body.inputs, &sweep_body.outputs),
    ];
    let mut binding_state = state.state.clone();
    let mut binding = BlockStateBinding::build(&mut binding_state, &bodies, &commitments)
        .expect("build mixed binding");
    patch_binding_new_root_with_coinbase(&mut binding, binding_state, &coinbase);

    let pre_segs = pre_segments_for_state(&state, &[0, 1, 3, 10, 11, 12, 42]);
    let owned = build_state_bindings_from_binding(
        &binding,
        &bodies,
        Some(&coinbase),
        &pre_segs,
        prev_state_root,
        bodies.len() as u32,
        6,
    );

    let mut delta_state = state.state.clone();
    let delta = build_state_delta_witness(&mut delta_state, &bodies, &commitments)
        .expect("build native state-delta witness");
    assert_eq!(
        owned_state_binding_claim_pairs(&owned),
        state_delta_claim_pairs(&delta, Some(&coinbase), 6),
        "mixed standard/sweep state-binding claims must match native state-delta actions"
    );

    assert_eq!(owned.len(), 1, "test fixture touches one segment");
    let claims = &owned[0].claims;
    assert_eq!(
        claims.iter().filter(|c| c.is_spend).count(),
        3,
        "two standard spends plus one sweep spend"
    );
    assert_eq!(
        claims.iter().filter(|c| c.is_mint).count(),
        4,
        "two standard mints plus one sweep mint plus coinbase mint"
    );
    for slot in [0, 1, 3] {
        assert!(
            claims.iter().any(|c| c.is_spend && c.slot_index == slot),
            "missing spend claim for slot {slot}"
        );
    }
    for slot in [10, 11, 12, 42] {
        assert!(
            claims.iter().any(|c| c.is_mint && c.slot_index == slot),
            "missing mint claim for slot {slot}"
        );
    }
}

#[test]
fn state_delta_claim_equivalence_allows_prefix_overlay_spend() {
    let alice = Address([0xA3; 32]);
    let bob = Address([0xB4; 32]);
    let tx0 = TxBody {
        shape: TxShape::Standard4x8,
        epoch_anchor: [0x41; 32],
        fee: 0,
        inputs: vec![],
        outputs: vec![TxOutput {
            slot_index: 10,
            value: 123,
            owner: alice,
            valid: true,
        }],
        is_coinbase: false,
    };
    let tx1 = TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor: [0x42; 32],
        fee: 0,
        inputs: vec![TxInput {
            slot_index: 10,
            value: 123,
            owner: alice,
            spend_secret: SpendSecret([0xA3; 32]),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        }],
        outputs: vec![TxOutput {
            slot_index: 70_000,
            value: 100,
            owner: bob,
            valid: true,
        }],
        is_coinbase: false,
    };
    let bodies = vec![tx0, tx1];
    let commitments: Vec<_> = bodies
        .iter()
        .map(|body| compute_claims_commitment(&body.inputs, &body.outputs))
        .collect();

    let mut state = ChainState::with_log_slots(18);
    let prev_state_root = state.state_root();

    let mut binding_state = state.state.clone();
    let binding = BlockStateBinding::build(&mut binding_state, &bodies, &commitments)
        .expect("current binding accepts prefix-overlay spend");

    let mut delta_state = state.state.clone();
    let delta = build_state_delta_witness(&mut delta_state, &bodies, &commitments)
        .expect("native delta accepts prefix-overlay spend");
    assert_eq!(binding.new_state_root, delta.post_state_root);

    let pre_segs = pre_segments_for_state(&state, &[10, 70_000]);
    let owned = build_state_bindings_from_binding(
        &binding,
        &bodies,
        None,
        &pre_segs,
        prev_state_root,
        bodies.len() as u32,
        18,
    );

    assert_eq!(
        owned_state_binding_claim_pairs(&owned),
        state_delta_claim_pairs(&delta, None, 18),
        "prefix-overlay mints/spends across segments must map to the same BSB claims"
    );
    assert!(
        owned.iter().any(|binding| binding.seg_id == 0),
        "mint-then-spend slot should live in segment 0"
    );
    assert!(
        owned.iter().any(|binding| binding.seg_id == 1),
        "70_000 output should live in segment 1 for log_slots=18"
    );
}

#[test]
fn common_state_binding_rejects_cross_shape_double_spend() {
    let standard = standard_fixture();
    let shared = standard
        .body
        .inputs
        .iter()
        .find(|i| i.valid)
        .expect("standard fixture input")
        .clone();
    let sweep_body = TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor: [0x5A; 32],
        fee: 0,
        inputs: vec![TxInput {
            slot_index: shared.slot_index,
            value: shared.value,
            owner: shared.owner,
            spend_secret: shared.spend_secret,
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        }],
        outputs: vec![],
        is_coinbase: false,
    };

    let mut state = ChainState::with_log_slots(6);
    seed_slot(&mut state, shared.slot_index, shared.value, shared.owner);
    for input in standard.body.inputs.iter().filter(|i| i.valid) {
        if input.slot_index != shared.slot_index {
            seed_slot(&mut state, input.slot_index, input.value, input.owner);
        }
    }

    let bodies = vec![standard.body.clone(), sweep_body.clone()];
    let commitments = vec![
        compute_claims_commitment(&standard.body.inputs, &standard.body.outputs),
        compute_claims_commitment(&sweep_body.inputs, &sweep_body.outputs),
    ];
    let err = BlockStateBinding::build(&mut state.state, &bodies, &commitments)
        .expect_err("second cross-shape spend must see the slot already spent");

    assert_eq!(
        err,
        StateBindingError::InputMismatch {
            tx_index: 1,
            input_index: 0
        }
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "release-only state-delta native identity regression"
)]
fn native_state_delta_rejects_wrong_post_lane_before_opening_verify() {
    let standard = standard_fixture_with_params(0xD1, 0, 10, 0x44);
    let body = standard.body.clone();
    let block = block_with_user_tx(tx_from_body(body.clone()));
    let commitment = compute_claims_commitment(&body.inputs, &body.outputs);

    let mut state = ChainState::with_log_slots(6);
    seed_slot(&mut state, 0, body.inputs[0].value, body.inputs[0].owner);
    seed_slot(&mut state, 1, body.inputs[1].value, body.inputs[1].owner);
    let prev_state_root = state.state_root();

    let tx_witness = TxBlockWitness {
        block_tx_index: 1,
        air: &standard.air as &dyn Air,
        trace: &standard.trace,
        pi: &standard.pi,
        spine_inputs: &standard.spine_inputs,
        auth_public: &standard.auth_public,
        auth_proof: &standard.auth_proof,
    };
    let mut proof =
        prove_block_with_total_tx_count(prev_state_root, [0u8; 32], &[tx_witness], &[], 1)
            .expect("prove standard bucket");

    let mut state_for_binding = state.state.clone();
    let mut binding =
        BlockStateBinding::build(&mut state_for_binding, &[body.clone()], &[commitment])
            .expect("build binding");
    patch_binding_new_root_with_coinbase(
        &mut binding,
        state_for_binding,
        &block.transactions[0].body,
    );

    let pre_segs = pre_segments_for_state(&state, &[0, 1, 10, 11, 42]);
    let owned = build_state_bindings_from_binding(
        &binding,
        &[body],
        Some(&block.transactions[0].body),
        &pre_segs,
        prev_state_root,
        1,
        6,
    );
    let witnesses: Vec<_> = owned.iter().map(|b| b.as_witness()).collect();
    let (_starks, pre_openings, post_openings) = prove_state_bindings_standalone(&witnesses);

    proof.meta.new_state_root = binding.new_state_root;
    proof.meta.n_state_bindings = witnesses.len() as u32;
    proof.meta.state_binding_n_cols = 0;
    proof.meta.state_binding_log_rows = 0;
    proof.pre_state_openings = pre_openings;
    proof.post_state_openings = post_openings;

    let mut bad = proof;
    bad.post_state_openings[0].lane_values[0] += Block128::ONE;

    let err = match build_state_binding_airs(&block, &bad, &state.state) {
        Ok(_) => panic!("wrong post lane must fail native state-delta identity"),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        noid_block::VerifyBlockError::StateMleOpeningFailed(0)
    ));
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "release-only state-binding proof regression"
)]
fn standalone_state_binding_proves_and_verifies_for_sweep_only_path() {
    let body = mk_sweep_mint_body();
    let commitment = compute_claims_commitment(&body.inputs, &body.outputs);

    let mut state = ChainState::with_log_slots(6);
    let prev_state_root = state.state_root();
    let mut state_for_binding = state.state.clone();
    let binding = BlockStateBinding::build(&mut state_for_binding, &[body.clone()], &[commitment])
        .expect("build binding");

    let mut pre_segs = HashMap::new();
    pre_segs.insert(0u16, SegmentColumns::new_zero(64));
    let owned = build_state_bindings_from_binding(
        &binding,
        &[body],
        None,
        &pre_segs,
        prev_state_root,
        1,
        6,
    );
    let witnesses: Vec<_> = owned.iter().map(|b| b.as_witness()).collect();
    let (starks, pre_openings, post_openings) = prove_state_bindings_standalone(&witnesses);

    let proof = BlockProof {
        meta: BlockPublicMeta {
            prev_block_state_root: prev_state_root,
            new_state_root: binding.new_state_root,
            n_tx: 1,
            n_air_per_tx: 0,
            n_auth_slices_per_tx: 0,
            log_rows: noid_air::airs::tx_body_spine::SPINE_LOG_ROWS as u32,
            n_block_spine_slices: 0,
            n_state_bindings: witnesses.len() as u32,
            state_binding_n_cols: 0,
            state_binding_log_rows: 0,
        },
        standard_bucket: None,
        sweep_bucket: None,
        state_binding_algebraics: vec![],
        state_binding_starks: starks,
        pre_state_openings: pre_openings,
        post_state_openings: post_openings,
    };
    let air_refs: Vec<_> = owned.iter().map(|b| &b.air).collect();
    verify_state_bindings_standalone(&proof, &air_refs).expect("standalone state binding verifies");
}
