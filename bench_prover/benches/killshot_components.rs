// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! KillShot/FROST component benchmark for the O(1) recursion redesign.
//!
//!   cargo bench -p bench_prover --bench killshot_components
//!
//! This measures existing Poseidon2b-heavy KillShot components in isolation.
//! It is not public O(1) authority by itself; authority comes only after the
//! components are composed into the checkpoint/history proof.

use std::env;
use std::time::Duration;

use bench_prover::{
    fmt_bytes, fmt_ms, standard_fixture, standard_scenario, sweep_fixture, sweep_scenario,
    time_once, tx_from_body,
};
use noid_block::{
    prove_exact_state_killshot, verify_exact_state_killshot, ExactStateKillShotInputs,
};
use noid_chain::consensus::params::MAX_TARGET;
use noid_chain::exact_state_hash::{composite_state_root, slot_leaf_hash};
use noid_chain::fri_state::SlotValue;
use noid_chain::reuse_guard::{guard_bucket_hash, GuardBucket};
use noid_core::{Block128, TowerField};
use noid_gkr::OwnerAuthProofKillShot;
use noid_gkr::{
    compute_merkle_root, compute_sweep_tx_body_hash, compute_tx_body_hash,
    discharge_block_spine_reductions_native, discharge_sweep_block_spine_reductions_native,
    owner_auth_gkr_channel, prove_batched_guard_bucket_killshot, prove_batched_merkle_killshot,
    prove_batched_slot_leaf_killshot, prove_batched_state_root_killshot,
    prove_block_spine_killshot, prove_chain_accumulator_killshot, prove_header_hash_killshot,
    prove_owner_auth_killshot, prove_sweep_block_spine_killshot, reconstruct_slot_states,
    verify_batched_guard_bucket_killshot, verify_batched_merkle_killshot,
    verify_batched_slot_leaf_killshot, verify_batched_state_root_killshot,
    verify_block_spine_killshot, verify_chain_accumulator_killshot, verify_header_hash_killshot,
    verify_owner_auth_killshot, verify_sweep_block_spine_killshot, BlockSpineMle,
    ChainAccumulatorBatchInputs, ChainAccumulatorItem, CompositeStateRootInputs,
    GuardBucketHashInputs, HeaderHashInputs, MerkleCircuit, MerklePathInputs, SlotLeafInputs,
    SpineCircuit, SpineInputs, SweepBlockSpineMle, SweepSpineCircuit, MAX_MERKLE_DEPTH,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::compress;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{
    capacity_iv, TAG_BLOCKHDR, TAG_COMPRESS, TAG_EXSTNOD, TAG_POWHDR, TAG_RGDNODE,
};
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_poseidon2b::primitives::Address;
use noid_recursive::{
    prove_checkpoint_poseidon, prove_fiat_shamir_transcript_batch_killshot,
    verify_authorization_batch_native_with_traces, verify_checkpoint_poseidon,
    verify_fiat_shamir_transcript_batch_killshot, AcceptedClaimBatchWitness, ChainAccumulator,
    HeaderWitness, FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH,
};
use rayon::prelude::*;

const DEFAULT_STANDARD_NS: &[usize] = &[1, 4, 16, 32];
const DEFAULT_SWEEP_NS: &[usize] = &[1, 4, 8];
const DEFAULT_MERKLE_MANY: usize = 32;
const DEFAULT_AUTH_VERIFY_N: usize = 255;
const DEFAULT_AUTH_TRACE_N: usize = 16;
const DEFAULT_STATE_COMPONENT_N: usize = 64;
const DEFAULT_CHAIN_ACC_N: usize = 32;
const DEFAULT_HEADER_HASH_N: usize = 32;

fn env_usize_list(name: &str, default: &[usize]) -> Vec<usize> {
    let Ok(value) = env::var(name) else {
        return default.to_vec();
    };
    let parsed: Vec<usize> = value
        .split(',')
        .filter_map(|part| part.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .collect();
    if parsed.is_empty() {
        default.to_vec()
    } else {
        parsed
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn print_metric(label: &str, value: Duration) {
    println!("    {label:<26} {}", fmt_ms(value));
}

fn print_size(label: &str, bytes: usize) {
    println!("    {label:<26} {}", fmt_bytes(bytes));
}

fn owner_auth_size_breakdown(proof: &OwnerAuthProofKillShot) -> (usize, usize, usize, usize) {
    let main_polys: usize = proof
        .kill_shot
        .main
        .round_polys
        .iter()
        .map(|p| p.coeffs.len() * 16)
        .sum();
    let shift_polys: usize = proof
        .kill_shot
        .shift
        .round_polys
        .iter()
        .map(|p| p.evals.len() * 16)
        .sum();
    let boundary_polys: usize = proof
        .boundary
        .round_polys
        .iter()
        .map(|p| p.evals.len() * 16)
        .sum();
    let frost = main_polys + shift_polys + boundary_polys + (1 + STATE_SIZE) * 16 + 16 + 16;
    (
        frost,
        proof.batch.byte_len(),
        proof.pcs.byte_len(),
        proof.byte_len(),
    )
}

fn print_owner_auth_breakdown(proof: &OwnerAuthProofKillShot) {
    let (frost, batch, pcs, total) = owner_auth_size_breakdown(proof);
    print_size("proof logical", total);
    print_size("  FROST/GKR", frost);
    print_size("  batch eval", batch);
    print_size("  PCS opening", pcs);
}

fn field_pair(seed: u128) -> [Block128; 2] {
    [
        Block128::from(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
        Block128::from(seed ^ 0xD1B5_4A32_D192_ED03),
    ]
}

fn digest_to_fields(hash: [u8; 32]) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap())),
    ]
}

fn digest_from_fields(fields: [Block128; 2]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&fields[0].to_u128().to_le_bytes());
    out[16..].copy_from_slice(&fields[1].to_u128().to_le_bytes());
    out
}

fn claim_bytes(claim: [Block128; 2]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&claim[0].to_u128().to_le_bytes());
    out[16..].copy_from_slice(&claim[1].to_u128().to_le_bytes());
    out
}

fn chain_accumulator_inputs(n: usize) -> ChainAccumulatorBatchInputs {
    let start_chain_hash = digest_to_fields([0xA1; 32]);
    let mut chain = digest_from_fields(start_chain_hash);
    let mut items = Vec::with_capacity(n);
    for i in 0..n {
        let block_id = [(i as u8).wrapping_mul(17).wrapping_add(1); 32];
        let claim = [
            Block128::from(0xC0DE_0000_u128 + i as u128),
            Block128::from(0xD00D_0000_u128 + i as u128),
        ];
        let inner = compress(&block_id, &claim_bytes(claim));
        chain = compress(&chain, &inner);
        items.push(ChainAccumulatorItem {
            block_id: digest_to_fields(block_id),
            chain_claim: claim,
        });
    }
    ChainAccumulatorBatchInputs {
        start_chain_hash,
        items,
        expected_chain_hash: digest_to_fields(chain),
    }
}

fn header_hash_inputs(n: usize) -> Vec<HeaderHashInputs> {
    (0..n)
        .map(|i| {
            let fields: [Block128; 16] = std::array::from_fn(|j| {
                Block128::from(0x4800_0000_u128 + (i as u128) * 0x100 + j as u128)
            });
            let mut pow = Poseidon2bSponge::with_iv(capacity_iv(TAG_POWHDR));
            for pair in fields.chunks_exact(2) {
                pow.absorb_pair(pair[0], pair[1]);
            }
            let mut block = Poseidon2bSponge::with_iv(capacity_iv(TAG_BLOCKHDR));
            for pair in fields.chunks_exact(2) {
                block.absorb_pair(pair[0], pair[1]);
            }
            HeaderHashInputs {
                fields,
                expected_pow_digest: digest_to_fields(pow.finalize_no_pad()),
                expected_block_id: digest_to_fields(block.finalize()),
            }
        })
        .collect()
}

fn checkpoint_poseidon_fixture(
    n: usize,
) -> (
    ChainAccumulator,
    ChainAccumulator,
    AcceptedClaimBatchWitness,
) {
    let start = ChainAccumulator {
        height: 0,
        state_root: [0x11; 32],
        chain_hash: [0x22; 32],
    };
    let mut acc = start.clone();
    let mut prev = [0u8; 32];
    let mut headers = Vec::with_capacity(n);
    let mut claims = Vec::with_capacity(n);
    for i in 0..n {
        let height = i as u64 + 1;
        let state_root = [(0x40u8).wrapping_add(i as u8); 32];
        let header = noid_chain::BlockHeader {
            prev_block_hash: prev,
            state_root,
            tx_root: [(0x80u8).wrapping_add(i as u8); 32],
            timestamp: 1_767_225_600 + height * 15,
            height,
            miner_address: Address([(0x20u8).wrapping_add(i as u8); 32]),
            nonce: i as u128,
            difficulty_target: MAX_TARGET,
            log_slots: 24,
            active_slot_count: i as u64,
            alloc_counter: i as u64,
        };
        let witness = HeaderWitness::from_header(&header);
        let claim = [
            Block128::from(0xC000_0000_u128 + i as u128),
            Block128::from(0xD000_0000_u128 + i as u128),
        ];
        acc = acc.extend(state_root, witness.block_id, height, claim);
        prev = witness.block_id;
        headers.push(witness);
        claims.push(claim);
    }
    (
        start,
        acc,
        AcceptedClaimBatchWitness {
            headers,
            accepted_block_claims: claims,
        },
    )
}

fn slot_value(seed: u128) -> SlotValue {
    SlotValue {
        value: Block128::from((seed as u64).wrapping_mul(17).wrapping_add(1) as u128),
        owner_hi: Block128::from(seed.wrapping_mul(0xA24B_AED4_963E_E407)),
        owner_lo: Block128::from(seed ^ 0x9FB2_1C65_1E98_DF25),
    }
}

fn slot_leaf_input(seed: u128) -> SlotLeafInputs {
    let slot = slot_value(seed);
    SlotLeafInputs {
        amount: slot.value.to_u128() as u64,
        owner_hi: slot.owner_hi,
        owner_lo: slot.owner_lo,
        expected_leaf: digest_to_fields(slot_leaf_hash(slot)),
    }
}

fn guard_bucket_input(seed: u128) -> GuardBucketHashInputs {
    let base = (seed as u32).wrapping_mul(16);
    let bucket = GuardBucket::Occupied {
        absolute_height: 1_000 + seed as u64,
        spent_slots: vec![base + 1, base + 3, base + 7, base + 15],
    };
    GuardBucketHashInputs {
        occupied: true,
        absolute_height: 1_000 + seed as u64,
        spent_slots: vec![base + 1, base + 3, base + 7, base + 15],
        expected_hash: digest_to_fields(guard_bucket_hash(&bucket)),
    }
}

fn state_root_input(seed: u128) -> CompositeStateRootInputs {
    let utxo_root = [seed as u8; 32];
    let guard_root = [(seed as u8) ^ 0x5A; 32];
    let log_slots = 24;
    CompositeStateRootInputs {
        log_slots,
        utxo_root: digest_to_fields(utxo_root),
        guard_root: digest_to_fields(guard_root),
        expected_state_root: digest_to_fields(composite_state_root(
            log_slots, utxo_root, guard_root,
        )),
    }
}

fn merkle_inputs(depth: usize, seed: u128) -> MerklePathInputs {
    merkle_inputs_with_tag(depth, seed, TAG_COMPRESS)
}

fn merkle_inputs_with_tag(
    depth: usize,
    seed: u128,
    tag: noid_poseidon2b::native::domain::DomainTag,
) -> MerklePathInputs {
    assert!((1..=MAX_MERKLE_DEPTH).contains(&depth));
    let circuit = MerkleCircuit::build_with_tag(tag);
    let leaf = field_pair(seed + 1);
    let mut siblings = [[Block128::ZERO; 2]; MAX_MERKLE_DEPTH];
    for (level, sibling) in siblings.iter_mut().enumerate().take(depth) {
        *sibling = field_pair(seed + 100 + level as u128 * 17);
    }
    let expected_root = compute_merkle_root(&circuit, leaf, &siblings[..depth], depth);
    MerklePathInputs {
        leaf,
        siblings,
        directions: [false; MAX_MERKLE_DEPTH],
        expected_root,
        active_depth: depth,
    }
}

fn exact_state_killshot_inputs(n: usize) -> ExactStateKillShotInputs {
    let slot_leaves: Vec<_> = (0..(2 * n))
        .map(|i| slot_leaf_input(0xE000 + i as u128))
        .collect();
    let state_paths: Vec<_> = (0..(2 * n))
        .map(|i| merkle_inputs_with_tag(MAX_MERKLE_DEPTH, 0xE100 + i as u128 * 1000, TAG_EXSTNOD))
        .collect();
    let guard_buckets: Vec<_> = (0..(2 * n))
        .map(|i| guard_bucket_input(0xE200 + i as u128))
        .collect();
    let guard_paths: Vec<_> = (0..(2 * n))
        .map(|i| merkle_inputs_with_tag(8, 0xE300 + i as u128 * 1000, TAG_RGDNODE))
        .collect();
    let state_roots: Vec<_> = (0..(2 * n))
        .map(|i| state_root_input(0xE400 + i as u128))
        .collect();
    ExactStateKillShotInputs {
        slot_leaves,
        state_paths,
        guard_buckets: Some(guard_buckets),
        guard_paths: Some(guard_paths),
        state_roots,
    }
}

fn standard_spine_inputs(seed: u128) -> SpineInputs {
    SpineInputs {
        epoch_anchor: field_pair(seed + 11),
        fee_leaf: field_pair(seed + 33),
        input_leaves: [[Block128::from(seed + 1); 4]; 4],
        output_leaves: [[Block128::from(seed + 2); 4]; 8],
        is_coinbase_leaf: field_pair(seed + 55),
        pad_leaf: [Block128::ZERO; 2],
    }
}

fn collect_standard_state_ins(
    circuit: &SpineCircuit,
    inputs: &[SpineInputs],
) -> Vec<[Block128; STATE_SIZE]> {
    let mut out = Vec::new();
    for input in inputs {
        let states = reconstruct_slot_states(circuit, input);
        out.extend(states.iter().map(|(state_in, _)| *state_in));
    }
    out
}

fn bench_chain_accumulator(n: usize) {
    println!("  ---------------------------------------------------------------------");
    println!("  ChainAccumulatorProof KillShot: {n} accepted claims");
    println!("  ---------------------------------------------------------------------");
    let inputs = chain_accumulator_inputs(n);
    let (prove_time, (proof, reductions)) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        prove_chain_accumulator_killshot(&inputs, &mut ch)
    });
    let (verify_time, verified) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        verify_chain_accumulator_killshot(&proof, &inputs, &mut ch)
    });
    print_metric("prove", prove_time);
    print_metric("verify", verify_time);
    print_size("proof logical", proof.byte_len());
    println!("    num_vars                  {}", proof.num_vars);
    println!("    live_slots                {}", proof.live_slots);
    println!(
        "    verify result             {}",
        verified == Some(reductions)
    );
    println!();
}

fn bench_header_hash(n: usize) {
    println!("  ---------------------------------------------------------------------");
    println!("  HeaderHashProof KillShot: {n} headers");
    println!("  ---------------------------------------------------------------------");
    let inputs = header_hash_inputs(n);
    let (prove_time, (proof, reductions)) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        prove_header_hash_killshot(&inputs, &mut ch)
    });
    let (verify_time, verified) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        verify_header_hash_killshot(&proof, &inputs, &mut ch)
    });
    print_metric("prove", prove_time);
    print_metric("verify", verify_time);
    print_size("proof logical", proof.byte_len());
    println!("    num_vars                  {}", proof.num_vars);
    println!("    live_slots                {}", proof.live_slots);
    println!(
        "    verify result             {}",
        verified == Some(reductions)
    );
    println!();
}

fn bench_checkpoint_poseidon(n: usize) {
    println!("  ---------------------------------------------------------------------");
    println!("  CheckpointPoseidonProof composed: {n} headers/claims");
    println!("  ---------------------------------------------------------------------");
    let (start, end, witness) = checkpoint_poseidon_fixture(n);
    let (prove_time, proof) =
        time_once(|| prove_checkpoint_poseidon(&start, &end, &witness).unwrap());
    let (verify_time, verified) =
        time_once(|| verify_checkpoint_poseidon(&start, &end, &witness, &proof).is_ok());
    print_metric("prove", prove_time);
    print_metric("verify", verify_time);
    print_size("proof logical", proof.byte_len());
    println!("    verify result             {verified}");
    println!();
}

fn bench_merkle_many(n_paths: usize) {
    println!("  ---------------------------------------------------------------------");
    println!("  BatchedMerkleProofKillShot: {n_paths} depth-{MAX_MERKLE_DEPTH} paths");
    println!("  ---------------------------------------------------------------------");
    let circuit = MerkleCircuit::build();
    let inputs: Vec<_> = (0..n_paths)
        .map(|i| merkle_inputs(MAX_MERKLE_DEPTH, 0xBEEF + i as u128 * 1000))
        .collect();
    let (batch_prove_time, (batch_proof, batch_reductions)) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        prove_batched_merkle_killshot(&circuit, &inputs, &mut ch)
    });
    let (batch_verify_time, batch_verified) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        verify_batched_merkle_killshot(&circuit, &batch_proof, &inputs, &mut ch)
    });
    print_metric("prove", batch_prove_time);
    print_metric("verify", batch_verify_time);
    print_size("proof logical", batch_proof.byte_len(&inputs));
    println!("    num_vars                  {}", batch_proof.num_vars);
    println!("    live_slots                {}", batch_proof.live_slots);
    println!(
        "    verify result             {}",
        batch_verified == Some(batch_reductions)
    );
    println!();
}

fn bench_exact_state_components(n: usize) {
    println!("  ---------------------------------------------------------------------");
    println!("  Exact-state KillShot components: {n} leaves/buckets/roots");
    println!("  ---------------------------------------------------------------------");

    let slot_inputs: Vec<_> = (0..n)
        .map(|i| slot_leaf_input(0xD00D + i as u128))
        .collect();
    let (slot_prove, (slot_proof, slot_reductions)) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        prove_batched_slot_leaf_killshot(&slot_inputs, &mut ch)
    });
    let (slot_verify, slot_verified) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        verify_batched_slot_leaf_killshot(&slot_proof, &slot_inputs, &mut ch)
    });

    println!("    SlotLeaf EXSTSLT_");
    print_metric("prove", slot_prove);
    print_metric("verify", slot_verify);
    print_size("proof logical", slot_proof.byte_len());
    println!(
        "    verify result             {}",
        slot_verified == Some(slot_reductions)
    );

    let bucket_inputs: Vec<_> = (0..n)
        .map(|i| guard_bucket_input(0xB000 + i as u128))
        .collect();
    let (bucket_prove, (bucket_proof, bucket_reductions)) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        prove_batched_guard_bucket_killshot(&bucket_inputs, &mut ch)
    });
    let (bucket_verify, bucket_verified) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        verify_batched_guard_bucket_killshot(&bucket_proof, &bucket_inputs, &mut ch)
    });

    println!("    GuardBucket RGDBUCK_");
    print_metric("prove", bucket_prove);
    print_metric("verify", bucket_verify);
    print_size("proof logical", bucket_proof.byte_len());
    println!(
        "    verify result             {}",
        bucket_verified == Some(bucket_reductions)
    );

    let root_inputs: Vec<_> = (0..n)
        .map(|i| state_root_input(0xA000 + i as u128))
        .collect();
    let (root_prove, (root_proof, root_reductions)) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        prove_batched_state_root_killshot(&root_inputs, &mut ch)
    });
    let (root_verify, root_verified) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        verify_batched_state_root_killshot(&root_proof, &root_inputs, &mut ch)
    });

    println!("    CompositeStateRoot EXSTROT_");
    print_metric("prove", root_prove);
    print_metric("verify", root_verify);
    print_size("proof logical", root_proof.byte_len());
    println!(
        "    verify result             {}",
        root_verified == Some(root_reductions)
    );
    println!();
}

fn bench_exact_state_composed(n: usize) {
    println!("  ---------------------------------------------------------------------");
    println!("  ExactStateKillShotProof composed: {n} transition-shaped items");
    println!("  ---------------------------------------------------------------------");
    let inputs = exact_state_killshot_inputs(n);
    let (prove_time, proof) = time_once(|| prove_exact_state_killshot(&inputs).unwrap());
    let (verify_time, verified) =
        time_once(|| verify_exact_state_killshot(&inputs, &proof).is_ok());
    print_metric("prove", prove_time);
    print_metric("verify", verify_time);
    print_size("proof logical", proof.byte_len(&inputs));
    println!("    slot leaf claims          {}", inputs.slot_leaves.len());
    println!("    state paths               {}", inputs.state_paths.len());
    println!(
        "    guard bucket claims       {}",
        inputs.guard_buckets.as_ref().map_or(0, Vec::len)
    );
    println!(
        "    guard paths               {}",
        inputs.guard_paths.as_ref().map_or(0, Vec::len)
    );
    println!("    state root claims         {}", inputs.state_roots.len());
    println!("    verify result             {verified}");
    println!();
}

fn bench_owner_auth() {
    println!("  ---------------------------------------------------------------------");
    println!("  OwnerAuthProofKillShot: Standard1x2, Standard4x8, Sweep25x2");
    println!("  ---------------------------------------------------------------------");
    let standard_1x2 = standard_fixture(standard_scenario("owner standard 1x2", 1, 2, 9_000, 0x41));
    let standard = standard_fixture(standard_scenario("owner standard", 4, 8, 10_000, 0x51));
    let sweep = sweep_fixture(sweep_scenario("owner sweep", 25, 20_000, 0x71));

    let standard_1x2_circuit = noid_gkr::OwnerAuthCircuit::build(standard_1x2.auth_inputs.layout);
    let (std_1x2_prove, (std_1x2_proof, std_1x2_red)) = time_once(|| {
        let mut ch = owner_auth_gkr_channel();
        prove_owner_auth_killshot(&standard_1x2_circuit, &standard_1x2.auth_inputs, &mut ch)
    });
    let (std_1x2_verify, std_1x2_verified) = time_once(|| {
        let mut ch = owner_auth_gkr_channel();
        verify_owner_auth_killshot(
            &std_1x2_proof,
            &standard_1x2_circuit,
            &standard_1x2.auth_public,
            &mut ch,
        )
    });

    let standard_circuit = noid_gkr::OwnerAuthCircuit::build(standard.auth_inputs.layout);
    let (std_prove, (std_proof, std_red)) = time_once(|| {
        let mut ch = owner_auth_gkr_channel();
        prove_owner_auth_killshot(&standard_circuit, &standard.auth_inputs, &mut ch)
    });
    let (std_verify, std_verified) = time_once(|| {
        let mut ch = owner_auth_gkr_channel();
        verify_owner_auth_killshot(
            &std_proof,
            &standard_circuit,
            &standard.auth_public,
            &mut ch,
        )
    });

    let sweep_circuit = noid_gkr::OwnerAuthCircuit::build(sweep.auth_inputs.layout);
    let (sweep_prove, (sweep_proof, sweep_red)) = time_once(|| {
        let mut ch = owner_auth_gkr_channel();
        prove_owner_auth_killshot(&sweep_circuit, &sweep.auth_inputs, &mut ch)
    });
    let (sweep_verify, sweep_verified) = time_once(|| {
        let mut ch = owner_auth_gkr_channel();
        verify_owner_auth_killshot(&sweep_proof, &sweep_circuit, &sweep.auth_public, &mut ch)
    });

    println!("    Standard1x2");
    print_metric("prove", std_1x2_prove);
    print_metric("verify", std_1x2_verify);
    print_owner_auth_breakdown(&std_1x2_proof);
    println!(
        "    verify result             {}",
        std_1x2_verified == Some(std_1x2_red)
    );
    println!("    Standard4x8");
    print_metric("prove", std_prove);
    print_metric("verify", std_verify);
    print_owner_auth_breakdown(&std_proof);
    println!(
        "    verify result             {}",
        std_verified == Some(std_red)
    );
    println!("    Sweep25x2");
    print_metric("prove", sweep_prove);
    print_metric("verify", sweep_verify);
    print_owner_auth_breakdown(&sweep_proof);
    println!(
        "    verify result             {}",
        sweep_verified == Some(sweep_red)
    );
    println!();
}

fn bench_owner_auth_batch_verify(n: usize) {
    println!("  ---------------------------------------------------------------------");
    println!("  OwnerAuthProofKillShot batch verify: {n} Standard4x8 proofs");
    println!("  ---------------------------------------------------------------------");
    let standard = standard_fixture(standard_scenario(
        "owner standard batch",
        4,
        8,
        30_000,
        0x91,
    ));
    let circuit = noid_gkr::OwnerAuthCircuit::build(standard.auth_inputs.layout);
    let mut ch = owner_auth_gkr_channel();
    let (proof, _) = prove_owner_auth_killshot(&circuit, &standard.auth_inputs, &mut ch);
    let proofs = vec![proof; n];

    let (verify_time, all_ok) = time_once(|| {
        proofs.par_iter().all(|proof| {
            let mut ch = owner_auth_gkr_channel();
            verify_owner_auth_killshot(proof, &circuit, &standard.auth_public, &mut ch).is_some()
        })
    });

    print_metric("verify total", verify_time);
    print_metric("verify per proof", verify_time / n as u32);
    print_size(
        "sidecar logical total",
        proofs.iter().map(|p| p.byte_len()).sum(),
    );
    print_size("sidecar logical each", proofs[0].byte_len());
    println!("    verify result             {all_ok}");
    println!();
}

fn bench_auth_fs_transcript(n: usize) {
    println!("  ---------------------------------------------------------------------");
    println!("  FiatShamirTranscriptBatchProof KillShot: {n} Standard4x8 auth verifier traces");
    println!("  ---------------------------------------------------------------------");
    let fixture = standard_fixture(standard_scenario("auth fs transcript", 4, 8, 40_000, 0xA7));
    let tx = tx_from_body(fixture.scenario.body.clone());
    let block = noid_chain::Block {
        header: noid_chain::BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [1u8; 32],
            tx_root: [2u8; 32],
            timestamp: 1,
            height: 1,
            miner_address: Address([0x33; 32]),
            nonce: 0,
            difficulty_target: [0xFF; 32],
            log_slots: 24,
            active_slot_count: 1,
            alloc_counter: 1,
        },
        transactions: vec![tx],
    };
    let (_, traces) = verify_authorization_batch_native_with_traces(&block, &[fixture.auth_proof])
        .expect("auth trace verifies");
    let trace = traces.into_iter().next().expect("one auth trace");
    if n > FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH {
        println!(
            "    skipped: direct transcript batch cap is {} traces; retained block proofs chunk larger auth sets",
            FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH
        );
        println!();
        return;
    }
    let traces = vec![trace.transcript; n];

    let (prove_time, (proof, reductions)) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        prove_fiat_shamir_transcript_batch_killshot(&traces, &mut ch).expect("prove fs transcript")
    });
    let (verify_time, verified) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        verify_fiat_shamir_transcript_batch_killshot(&traces, &proof, &mut ch)
    });
    let discharge_ok = verified.as_ref().is_ok_and(|red| {
        noid_recursive::discharge_fiat_shamir_transcript_batch_reductions_native(&traces, red)
    });

    print_metric("prove", prove_time);
    print_metric("verify", verify_time);
    print_size("proof logical", proof.byte_len());
    println!("    transcript ops total      {}", proof.n_ops);
    println!("    permutations              {}", proof.n_permutations);
    println!("    num_vars                  {}", proof.num_vars);
    println!("    live_slots                {}", proof.live_slots);
    println!(
        "    verify result             {}",
        verified == Ok(reductions)
    );
    println!("    native discharge          {discharge_ok}");
    println!();
}

fn bench_standard_block_spine(n: usize) {
    println!("  ---------------------------------------------------------------------");
    println!("  BlockSpineProof KillShot: {n} standard tx spines");
    println!("  ---------------------------------------------------------------------");
    let circuit = SpineCircuit::build();
    let inputs: Vec<_> = (0..n)
        .map(|i| standard_spine_inputs(0xC0DE + i as u128 * 100))
        .collect();
    let (build_time, (mle, tx_body_hashes, state_ins)) = time_once(|| {
        let state_ins = collect_standard_state_ins(&circuit, &inputs);
        let tx_body_hashes: Vec<_> = inputs
            .iter()
            .map(|input| compute_tx_body_hash(&circuit, input))
            .collect();
        let mle = BlockSpineMle::build(n, &state_ins);
        (mle, tx_body_hashes, state_ins)
    });
    let (prove_time, (proof, reductions)) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        prove_block_spine_killshot(n, &mle, &tx_body_hashes, &mut ch)
    });
    let (verify_time, verified) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        verify_block_spine_killshot(&proof, n, &tx_body_hashes, &mut ch)
    });
    let discharge_ok = verified
        .as_ref()
        .is_some_and(|red| discharge_block_spine_reductions_native(n, &state_ins, red));
    print_metric("build mle/context", build_time);
    print_metric("prove", prove_time);
    print_metric("verify", verify_time);
    print_size("proof logical", proof.byte_len());
    println!("    num_vars                  {}", proof.num_vars);
    println!("    live_slots                {}", proof.live_slots);
    println!(
        "    verify result             {}",
        verified == Some(reductions)
    );
    println!("    native discharge          {discharge_ok}");
    println!();
}

fn bench_sweep_block_spine(n: usize) {
    println!("  ---------------------------------------------------------------------");
    println!("  SweepBlockSpineProof KillShot: {n} sweep tx spines");
    println!("  ---------------------------------------------------------------------");
    let circuit = SweepSpineCircuit::build();
    let inputs: Vec<_> = (0..n)
        .map(|i| {
            sweep_fixture(sweep_scenario(
                "sweep block spine",
                25,
                2_000_000 + i as u32 * 100,
                0x901 + i as u128 * 0x100,
            ))
            .spine_inputs
        })
        .collect();
    let (build_time, (mle, tx_body_hashes)) = time_once(|| {
        let tx_body_hashes: Vec<_> = inputs
            .iter()
            .map(|input| compute_sweep_tx_body_hash(&circuit, input))
            .collect();
        let mle = SweepBlockSpineMle::build(&inputs);
        (mle, tx_body_hashes)
    });
    let (prove_time, (proof, reductions)) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        prove_sweep_block_spine_killshot(n, &mle, &tx_body_hashes, &mut ch)
    });
    let (verify_time, verified) = time_once(|| {
        let mut ch = Poseidon2bChannel::new();
        verify_sweep_block_spine_killshot(&proof, n, &tx_body_hashes, &mut ch)
    });
    let discharge_ok = verified
        .as_ref()
        .is_some_and(|red| discharge_sweep_block_spine_reductions_native(&inputs, red));
    print_metric("build mle/context", build_time);
    print_metric("prove", prove_time);
    print_metric("verify", verify_time);
    print_size("proof logical", proof.byte_len());
    println!("    num_vars                  {}", proof.num_vars);
    println!("    live_slots                {}", proof.live_slots);
    println!(
        "    verify result             {}",
        verified == Some(reductions)
    );
    println!("    native discharge          {discharge_ok}");
    println!();
}

fn main() {
    let standard_ns = env_usize_list("NOID_KILLSHOT_STANDARD_NS", DEFAULT_STANDARD_NS);
    let sweep_ns = env_usize_list("NOID_KILLSHOT_SWEEP_NS", DEFAULT_SWEEP_NS);
    let merkle_many = env_usize("NOID_KILLSHOT_MERKLE_MANY", DEFAULT_MERKLE_MANY);
    let auth_verify_n = env_usize("NOID_KILLSHOT_AUTH_VERIFY_N", DEFAULT_AUTH_VERIFY_N);
    let auth_trace_n = env_usize("NOID_KILLSHOT_AUTH_TRACE_N", DEFAULT_AUTH_TRACE_N);
    let state_component_n = env_usize("NOID_KILLSHOT_STATE_N", DEFAULT_STATE_COMPONENT_N);
    let chain_acc_n = env_usize("NOID_KILLSHOT_CHAIN_N", DEFAULT_CHAIN_ACC_N);
    let header_hash_n = env_usize("NOID_KILLSHOT_HEADER_N", DEFAULT_HEADER_HASH_N);

    println!();
    println!("  =====================================================================");
    println!("  PARANOID KillShot/FROST Component Benchmark");
    println!("  =====================================================================");
    println!("  Measures Poseidon2b-heavy GKR components only.");
    println!("  Standard block-spine sizes: {standard_ns:?}");
    println!("  Sweep block-spine sizes:    {sweep_ns:?}");
    println!("  Batched Merkle paths:       {merkle_many}");
    println!("  Auth batch verify proofs:   {auth_verify_n}");
    println!("  Auth transcript traces:     {auth_trace_n}");
    println!("  Exact-state component N:    {state_component_n}");
    println!("  Chain accumulator items:    {chain_acc_n}");
    println!("  Header hash items:          {header_hash_n}");
    println!("  Override:");
    println!("    NOID_KILLSHOT_STANDARD_NS=1,4,16,32");
    println!("    NOID_KILLSHOT_SWEEP_NS=1,4,8");
    println!("    NOID_KILLSHOT_MERKLE_MANY=32");
    println!("    NOID_KILLSHOT_AUTH_VERIFY_N=255");
    println!("    NOID_KILLSHOT_AUTH_TRACE_N=16");
    println!("    NOID_KILLSHOT_STATE_N=64");
    println!("    NOID_KILLSHOT_CHAIN_N=32");
    println!("    NOID_KILLSHOT_HEADER_N=32");
    println!();

    bench_chain_accumulator(chain_acc_n);
    bench_header_hash(header_hash_n);
    bench_checkpoint_poseidon(header_hash_n);
    bench_merkle_many(merkle_many);
    bench_exact_state_components(state_component_n);
    bench_exact_state_composed(state_component_n);
    bench_owner_auth();
    bench_owner_auth_batch_verify(auth_verify_n);
    bench_auth_fs_transcript(auth_trace_n);
    for n in standard_ns {
        bench_standard_block_spine(n);
    }
    for n in sweep_ns {
        bench_sweep_block_spine(n);
    }

    println!("  ---------------------------------------------------------------------");
    println!("  NOTES:");
    println!("    - These are Poseidon2b-heavy components for the production O(1) path.");
    println!("    - Public authority still requires batch/checkpoint composition tests.");
    println!("  ---------------------------------------------------------------------");
    println!("  Reproduce: cargo bench -p bench_prover --bench killshot_components");
    println!();
}
