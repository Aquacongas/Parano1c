// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Integration tests for the recursive proof pipeline.
//!
//! Tests are marked `#[ignore]` where they require full STARK proving (slow).
//! The lightweight unit tests (AIR check, accumulator, verify errors) run always.

use noid_core::{Block128, TowerField};
use noid_recursive::{
    accumulator::genesis_accumulator,
    air::{
        build_recursive_trace, RecursiveBlockAir, RecursiveBlockWitness, BLOCK_SUMCHECK_ROUNDS,
        LOG_ROWS, N_COLS, REC_SUMCHECK_ROUNDS,
    },
    verify::RecVerifyError,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn honest_witness(seed: u128) -> RecursiveBlockWitness {
    let block_initial_claim = Block128::from(seed ^ 0xB10C_u128);
    let block_secondary_initial_claim = Block128::from(seed ^ 0xB20C_u128);
    let rec_initial_claim = Block128::from(seed ^ 0x0EC0_u128);

    let mut block_rounds: Vec<Vec<Block128>> = Vec::new();
    let mut block_challenges: Vec<Block128> = Vec::new();
    let mut block_claim = block_initial_claim;
    for i in 0..BLOCK_SUMCHECK_ROUNDS {
        let p0 = Block128::from(seed.wrapping_add(i as u128 * 7 + 1));
        let p1 = block_claim + p0;
        let p2 = Block128::from(seed.wrapping_add(i as u128 * 23 + 9));
        let r = Block128::from(seed.wrapping_add(i as u128 * 17 + 3));
        let round = vec![p0, p1, p2];
        block_challenges.push(r);
        block_claim = noid_stark::lagrange_eval_at_pub(&round, r);
        block_rounds.push(round);
    }
    let mut block_secondary_rounds: Vec<Vec<Block128>> = Vec::new();
    let mut block_secondary_challenges: Vec<Block128> = Vec::new();
    let mut block_secondary_claim = block_secondary_initial_claim;
    for i in 0..BLOCK_SUMCHECK_ROUNDS {
        let p0 = Block128::from(seed.wrapping_add(i as u128 * 31 + 11));
        let p1 = block_secondary_claim + p0;
        let p2 = Block128::from(seed.wrapping_add(i as u128 * 37 + 13));
        let r = Block128::from(seed.wrapping_add(i as u128 * 41 + 17));
        let round = vec![p0, p1, p2];
        block_secondary_challenges.push(r);
        block_secondary_claim = noid_stark::lagrange_eval_at_pub(&round, r);
        block_secondary_rounds.push(round);
    }

    let mut rec_rounds: Vec<Vec<Block128>> = Vec::new();
    let mut rec_challenges: Vec<Block128> = Vec::new();
    let mut rec_claim = rec_initial_claim;
    for i in 0..REC_SUMCHECK_ROUNDS {
        let p0 = Block128::from(seed.wrapping_add(i as u128 * 5 + 100));
        let p1 = rec_claim + p0;
        let p2 = Block128::from(seed.wrapping_add(i as u128 * 29 + 700));
        let r = Block128::from(seed.wrapping_add(i as u128 * 19 + 300));
        let round = vec![p0, p1, p2];
        rec_challenges.push(r);
        rec_claim = noid_stark::lagrange_eval_at_pub(&round, r);
        rec_rounds.push(round);
    }
    let v = seed.to_le_bytes();
    let mut prev_state_root = [0u8; 32];
    prev_state_root[..16].copy_from_slice(&v);
    prev_state_root[16..].copy_from_slice(&v);
    let mut new_state_root = [0xffu8; 32];
    new_state_root[0] = (seed & 0xFF) as u8;

    RecursiveBlockWitness {
        block_multipoint_rounds: block_rounds,
        block_initial_claim,
        block_challenges,
        block_secondary_multipoint_rounds: block_secondary_rounds,
        block_secondary_initial_claim,
        block_secondary_challenges,
        rec_multipoint_rounds: rec_rounds,
        rec_initial_claim,
        rec_challenges,
        acc_prev_state_root: prev_state_root,
        acc_new_state_root: new_state_root,
    }
}

fn make_trace_obj(cols: Vec<Vec<Block128>>) -> noid_air::Trace {
    noid_air::Trace {
        columns: cols,
        domains: vec![noid_air::ColumnDomain::Block128; N_COLS],
        log_rows: LOG_ROWS,
    }
}

// ---------------------------------------------------------------------------
// Accumulator tests
// ---------------------------------------------------------------------------

#[test]
fn accumulator_genesis_deterministic() {
    let g1 = genesis_accumulator([0x11u8; 32], [0x22u8; 32]);
    let g2 = genesis_accumulator([0x11u8; 32], [0x22u8; 32]);
    assert_eq!(g1.chain_hash, g2.chain_hash);
    assert_eq!(g1.height, 0);
}

#[test]
fn accumulator_chain_hash_binds_header() {
    let genesis = genesis_accumulator([0u8; 32], [0u8; 32]);
    let a = genesis.extend([1u8; 32], [10u8; 32], 1, Block128::ZERO);
    let b = genesis.extend([1u8; 32], [11u8; 32], 1, Block128::ZERO);
    assert_ne!(a.chain_hash, b.chain_hash);
    assert_eq!(a.height, 1);
}

#[test]
fn accumulator_chain_hash_binds_initial_claim() {
    // Forging block_initial_claim = ZERO for a block with a real claim must
    // produce a different chain_hash — the core S-2 fix.
    let genesis = genesis_accumulator([0u8; 32], [0u8; 32]);
    let real_claim = Block128::from(0xDEAD_BEEF_CAFE_1234u128);
    let real = genesis.extend([1u8; 32], [10u8; 32], 1, real_claim);
    let forged = genesis.extend([1u8; 32], [10u8; 32], 1, Block128::ZERO);
    assert_ne!(
        real.chain_hash, forged.chain_hash,
        "null-witness substitution must be detectable via chain_hash divergence"
    );
    assert_eq!(real.height, forged.height);
    assert_eq!(real.state_root, forged.state_root);
}

#[test]
fn accumulator_state_root_binds() {
    let genesis = genesis_accumulator([0u8; 32], [0u8; 32]);
    let a = genesis.extend([1u8; 32], [10u8; 32], 1, Block128::ZERO);
    let b = genesis.extend([2u8; 32], [10u8; 32], 1, Block128::ZERO);
    assert_ne!(a.state_root, b.state_root);
    assert_eq!(a.chain_hash, b.chain_hash); // same block_hash + same claim
}

// ---------------------------------------------------------------------------
// RecursiveBlockAir constraint tests
// ---------------------------------------------------------------------------

#[test]
fn recursive_air_honest_trace_passes_check() {
    let witness = honest_witness(0xDEAD_BEEF_CAFE_BABE);
    let air = RecursiveBlockAir::new(&witness);
    let trace = build_recursive_trace(&witness);

    assert_eq!(trace.len(), N_COLS);
    for col in &trace {
        assert_eq!(col.len(), 1 << LOG_ROWS);
    }

    let ok = noid_air::check_legacy(&air, &make_trace_obj(trace));
    assert!(ok, "RecursiveBlockAir honest trace should pass");
}

#[test]
fn recursive_air_tampered_fold_fails() {
    let witness = honest_witness(42);
    let air = RecursiveBlockAir::new(&witness);
    let mut trace = build_recursive_trace(&witness);
    trace[noid_recursive::air::COL_CLAIM_OUT][0] += Block128::ONE;
    assert!(!noid_air::check_legacy(&air, &make_trace_obj(trace)));
}

#[test]
fn recursive_air_tampered_secondary_fold_fails() {
    let witness = honest_witness(43);
    let air = RecursiveBlockAir::new(&witness);
    let mut trace = build_recursive_trace(&witness);
    trace[noid_recursive::air::COL_CLAIM_OUT]
        [noid_recursive::air::BLOCK_SECONDARY_SUMCHECK_START] += Block128::ONE;
    assert!(!noid_air::check_legacy(&air, &make_trace_obj(trace)));
}

#[test]
fn recursive_air_acc_row_state_root_pin() {
    let witness = honest_witness(1234);
    let air = RecursiveBlockAir::new(&witness);
    let mut trace = build_recursive_trace(&witness);
    trace[noid_recursive::air::COL_P0][noid_recursive::air::ACC_ROW] += Block128::ONE;
    assert!(!noid_air::check_legacy(&air, &make_trace_obj(trace)));
}

#[test]
fn recursive_block_witness_zero_rounds_is_valid() {
    let witness = RecursiveBlockWitness {
        block_multipoint_rounds: vec![vec![Block128::ZERO; 3]; BLOCK_SUMCHECK_ROUNDS],
        block_initial_claim: Block128::ZERO,
        block_challenges: vec![Block128::ZERO; BLOCK_SUMCHECK_ROUNDS],
        block_secondary_multipoint_rounds: vec![vec![Block128::ZERO; 3]; BLOCK_SUMCHECK_ROUNDS],
        block_secondary_initial_claim: Block128::ZERO,
        block_secondary_challenges: vec![Block128::ZERO; BLOCK_SUMCHECK_ROUNDS],
        rec_multipoint_rounds: vec![vec![Block128::ZERO; 3]; REC_SUMCHECK_ROUNDS],
        rec_initial_claim: Block128::ZERO,
        rec_challenges: vec![Block128::ZERO; REC_SUMCHECK_ROUNDS],
        acc_prev_state_root: [0u8; 32],
        acc_new_state_root: [0u8; 32],
    };
    let air = RecursiveBlockAir::new(&witness);
    let trace = build_recursive_trace(&witness);
    assert!(noid_air::check_legacy(&air, &make_trace_obj(trace)));
}

// ---------------------------------------------------------------------------
// verify_tip error type tests
// ---------------------------------------------------------------------------

#[test]
fn verify_error_types_are_debug() {
    let e = RecVerifyError::ChainHashMismatch;
    let msg = format!("{e:?}");
    assert!(msg.contains("ChainHashMismatch"));
    let e2 = RecVerifyError::StarkInvalid(noid_stark::VerifyError::ConstraintViolated);
    let _ = format!("{e2:?}");
}

// ---------------------------------------------------------------------------
// prove + verify roundtrip (slow — ignored by default)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "slow full STARK prove/verify, run with --ignored"]
fn recursive_prove_verify_roundtrip_accumulator() {
    use noid_chain::{hash_block_header, BlockHeader};
    use noid_poseidon2b::primitives::Address;
    use noid_recursive::{
        null_block_replay_witness, prove_genesis_recursive, prove_recursive_step,
        verify_step_stark_only,
    };

    let genesis_header = noid_chain::consensus::genesis::genesis_header();
    let mut prev_header = genesis_header;
    let mut prev_proof = prove_genesis_recursive();

    verify_step_stark_only(&prev_proof, &[0u8; 32], &genesis_header.state_root)
        .expect("genesis recursive proof verifies through snapshot step path");

    for height in 1..=3u64 {
        let mut state_root = [0u8; 32];
        state_root[..8].copy_from_slice(&height.to_le_bytes());
        let block_header = BlockHeader {
            prev_block_hash: hash_block_header(&prev_header),
            state_root,
            tx_root: [0u8; 32],
            timestamp: 1_700_000_000 + height,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: [0xFFu8; 32],
            proof_transcript_hash: [1u8; 32],
            witness_root: [2u8; 32],
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        };

        let prev_acc = prev_proof.acc.clone();
        let proof = prove_recursive_step(
            &null_block_replay_witness(),
            &block_header,
            &prev_acc,
            Some(&prev_proof),
        );

        verify_step_stark_only(&proof, &prev_header.state_root, &block_header.state_root)
            .unwrap_or_else(|e| panic!("recursive proof at h={height} must verify: {e:?}"));
        assert_eq!(proof.acc.height, height);
        assert_eq!(proof.acc.state_root, block_header.state_root);

        prev_header = block_header;
        prev_proof = proof;
    }
}
