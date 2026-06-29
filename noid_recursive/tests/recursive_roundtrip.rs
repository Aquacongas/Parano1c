// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Tests for local history cache and accepted-claim batch boundaries.

use noid_chain::{block_work, hash_block_header, BlockHeader};
use noid_core::{Block128, TowerField};
use noid_gkr::HISTORY_CLAIM_FIELDS;
use noid_poseidon2b::primitives::Address;
use noid_recursive::{
    accepted_block_claim_witness_from_fields, accumulator::genesis_accumulator,
    advance_local_history_cache, empty_accepted_block_witness, init_genesis_history_cache,
    verify_local_history_cache_step, RecVerifyError, HISTORY_PROOF_VERSION,
};

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
    let a = genesis.extend([1u8; 32], [10u8; 32], 1, [Block128::ZERO; 2]);
    let b = genesis.extend([1u8; 32], [11u8; 32], 1, [Block128::ZERO; 2]);
    assert_ne!(a.chain_hash, b.chain_hash);
    assert_eq!(a.height, 1);
}

#[test]
fn accumulator_chain_hash_binds_accepted_claim() {
    let genesis = genesis_accumulator([0u8; 32], [0u8; 32]);
    let real_claim = [
        Block128::from(0xDEAD_BEEF_CAFE_1234u128),
        Block128::from(0xFACE_FEED_CAFE_1234u128),
    ];
    let real = genesis.extend([1u8; 32], [10u8; 32], 1, real_claim);
    let forged = genesis.extend([1u8; 32], [10u8; 32], 1, [Block128::ZERO; 2]);
    let forged_hi = genesis.extend([1u8; 32], [10u8; 32], 1, [real_claim[0], Block128::ZERO]);
    assert_ne!(real.chain_hash, forged.chain_hash);
    assert_ne!(real.chain_hash, forged_hi.chain_hash);
    assert_eq!(real.height, forged.height);
    assert_eq!(real.state_root, forged.state_root);
}

#[test]
fn accumulator_state_root_binds() {
    let genesis = genesis_accumulator([0u8; 32], [0u8; 32]);
    let a = genesis.extend([1u8; 32], [10u8; 32], 1, [Block128::ZERO; 2]);
    let b = genesis.extend([2u8; 32], [10u8; 32], 1, [Block128::ZERO; 2]);
    assert_ne!(a.state_root, b.state_root);
    assert_eq!(a.chain_hash, b.chain_hash);
}

#[test]
fn verify_error_types_are_debug() {
    let msg = format!("{:?}", RecVerifyError::ChainHashMismatch);
    assert!(msg.contains("ChainHashMismatch"));
    let msg = format!("{:?}", RecVerifyError::PublicSnapshotAuthorityDisabled);
    assert!(msg.contains("PublicSnapshotAuthorityDisabled"));
}

#[test]
fn local_history_cache_roundtrip_accumulator() {
    let genesis_header = noid_chain::consensus::genesis::genesis_header();
    let mut prev_header = genesis_header;
    let mut prev_cache = init_genesis_history_cache();

    verify_local_history_cache_step(&prev_cache, &[0u8; 32], &genesis_header.state_root)
        .expect("genesis local history cache verifies");

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
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        };

        let witness = if height == 2 {
            let mut fields = [Block128::ZERO; HISTORY_CLAIM_FIELDS];
            fields[0] = Block128::from(HISTORY_PROOF_VERSION as u128);
            fields[1] = Block128::from(height as u128);
            write_digest_fields(&mut fields, 2, &hash_block_header(&block_header));
            write_digest_fields(&mut fields, 4, &prev_cache.anchor.block_id);
            write_digest_fields(&mut fields, 6, &prev_header.state_root);
            write_digest_fields(&mut fields, 8, &block_header.state_root);
            accepted_block_claim_witness_from_fields(fields).expect("claim witness")
        } else {
            let mut fields = empty_accepted_block_witness().claim_fields;
            fields[0] = Block128::from(HISTORY_PROOF_VERSION as u128);
            fields[1] = Block128::from(height as u128);
            write_digest_fields(&mut fields, 2, &hash_block_header(&block_header));
            write_digest_fields(&mut fields, 4, &prev_cache.anchor.block_id);
            write_digest_fields(&mut fields, 6, &prev_header.state_root);
            write_digest_fields(&mut fields, 8, &block_header.state_root);
            accepted_block_claim_witness_from_fields(fields).expect("claim witness")
        };
        let cumulative_chainwork = noid_chain::add_work(
            &prev_cache.anchor.cumulative_chainwork,
            &block_work(&block_header.difficulty_target),
        );
        let cache =
            advance_local_history_cache(&prev_cache, &witness, &block_header, cumulative_chainwork)
                .expect("advance cache");

        verify_local_history_cache_step(&cache, &prev_header.state_root, &block_header.state_root)
            .unwrap_or_else(|e| panic!("local history cache at h={height} must verify: {e:?}"));
        assert_eq!(cache.acc.height, height);
        assert_eq!(cache.acc.state_root, block_header.state_root);
        assert_eq!(cache.chain_claim, witness.chain_claim);

        prev_header = block_header;
        prev_cache = cache;
    }
}

fn write_digest_fields(
    fields: &mut [Block128; HISTORY_CLAIM_FIELDS],
    idx: usize,
    digest: &[u8; 32],
) {
    fields[idx] = Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap()));
    fields[idx + 1] = Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap()));
}
