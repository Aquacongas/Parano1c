// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Current Tx8x2 owner-auth and body-spine component measurements.

use bench_prover::{fmt_bytes, fmt_ms, time_once, tx8x2_scenario};
use noid_core::Block128;
use noid_gkr::{
    discharge_block_spine_reductions_native, prove_block_spine_killshot,
    prove_wallet_authorization, reconstruct_slot_states, spine_inputs_from_body,
    verify_block_spine_killshot, verify_wallet_authorization_proof, BlockSpineMle,
    OwnerAuthWitness, SpineCircuit, N_SPINE_SLOTS, N_SPINE_SLOTS_PADDED, N_SPINE_SLOT_VARS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::primitives::TxBodyHash;

fn requested_sizes() -> Vec<usize> {
    std::env::var("NOID_KILLSHOT_TX_COUNTS")
        .unwrap_or_else(|_| "1,8".into())
        .split(',')
        .filter_map(|part| part.trim().parse().ok())
        .filter(|&n| n > 0 && n <= 255)
        .collect()
}

fn hash_fields(hash: TxBodyHash) -> [Block128; 2] {
    hash.as_fields()
}

fn bench_owner_auth() {
    let scenario = tx8x2_scenario("owner-auth-max", 8, 2, 0, 0xA011);
    let (prove_time, proof) = time_once(|| {
        prove_wallet_authorization(
            &scenario.body,
            OwnerAuthWitness::new(scenario.spend_secret()),
        )
        .expect("selected witness-hiding authorization")
        .proof
    });
    let (verify_time, ()) = time_once(|| {
        verify_wallet_authorization_proof(&scenario.body, &proof)
            .expect("selected authorization verifies")
    });
    println!("  selected ZK one-owner authorization (Tx8x2 max actions)");
    println!("    prove: {}", fmt_ms(prove_time));
    println!("    verify:{}", fmt_ms(verify_time));
    println!(
        "    proof: {}",
        fmt_bytes(proof.to_bytes().expect("canonical proof wire").len())
    );
}

fn bench_body_spine(n: usize) {
    let circuit = SpineCircuit::build();
    let scenarios: Vec<_> = (0..n)
        .map(|index| {
            tx8x2_scenario(
                "body-spine",
                8,
                2,
                (index * 2_048) as u32,
                0x5A11 + index as u128,
            )
        })
        .collect();
    let spine_inputs: Vec<_> = scenarios
        .iter()
        .map(|scenario| spine_inputs_from_body(&scenario.body))
        .collect();
    let tx_hashes: Vec<_> = scenarios
        .iter()
        .map(|scenario| hash_fields(scenario.body.txid()))
        .collect();
    let (mle_time, (mle, state_ins)) = time_once(|| {
        let state_ins: Vec<_> = spine_inputs
            .iter()
            .flat_map(|input| reconstruct_slot_states(&circuit, input))
            .map(|(state_in, _)| state_in)
            .collect();
        let mle = BlockSpineMle::build(n, &state_ins);
        (mle, state_ins)
    });
    let (prove_time, (proof, reductions)) = time_once(|| {
        let mut channel = Poseidon2bChannel::new();
        prove_block_spine_killshot(n, &mle, &tx_hashes, &mut channel)
    });
    let (verify_time, verified) = time_once(|| {
        let mut channel = Poseidon2bChannel::new();
        verify_block_spine_killshot(&proof, n, &tx_hashes, &mut channel)
    });
    assert_eq!(verified, Some(reductions));
    assert!(discharge_block_spine_reductions_native(
        n,
        &state_ins,
        verified.as_ref().unwrap()
    ));
    println!("  Tx8x2 body spine x {n}");
    println!("    MLE build: {}", fmt_ms(mle_time));
    println!("    prove:     {}", fmt_ms(prove_time));
    println!("    verify:    {}", fmt_ms(verify_time));
    println!("    proof:     {}", fmt_bytes(proof.byte_len()));
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    assert_eq!(SpineCircuit::build().slots.len(), 31);
    assert_eq!(N_SPINE_SLOTS, 31);
    assert_eq!(N_SPINE_SLOTS_PADDED, 32);
    assert_eq!(N_SPINE_SLOT_VARS, 5);
    println!("PARANOID current component bench — Tx8x2 only");
    println!("Single current transaction axis; no pre-cutover golden.\n");
    bench_owner_auth();
    for n in requested_sizes() {
        bench_body_spine(n);
    }
}
