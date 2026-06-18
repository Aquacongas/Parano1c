// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use noid_core::{Block128, TowerField};
use noid_gkr::{
    compute_sweep_tx_body_hash, discharge_sweep_block_spine_reductions_native,
    prove_sweep_block_spine_killshot, verify_sweep_block_spine_killshot, SweepBlockSpineMle,
    SweepSpineCircuit, SweepSpineInputs, N_SWEEP_SPINE_SLOTS,
};
use noid_poseidon2b::channel::Poseidon2bChannel;

fn fixture_inputs(seed: u128) -> SweepSpineInputs {
    let mut input_leaves = [[Block128::ZERO; 4]; 25];
    for (i, leaf) in input_leaves.iter_mut().enumerate() {
        *leaf = [
            Block128::from(seed + 1_000 + i as u128),
            Block128::from(seed + 2_000 + i as u128),
            Block128::from(seed + 3_000 + i as u128),
            Block128::from(seed + 4_000 + i as u128),
        ];
    }

    let mut output_leaves = [[Block128::ZERO; 4]; 2];
    for (i, leaf) in output_leaves.iter_mut().enumerate() {
        *leaf = [
            Block128::from(seed + 5_000 + i as u128),
            Block128::from(seed + 6_000 + i as u128),
            Block128::from(seed + 7_000 + i as u128),
            Block128::from(seed + 8_000 + i as u128),
        ];
    }

    SweepSpineInputs {
        epoch_anchor: [Block128::from(seed + 11), Block128::from(seed + 12)],
        fee_leaf: [Block128::from(seed + 21), Block128::from(seed + 22)],
        shape_leaf: [Block128::from(seed + 31), Block128::from(seed + 32)],
        input_leaves,
        output_leaves,
        is_coinbase_leaf: [Block128::from(seed + 41), Block128::from(seed + 42)],
        pad_leaf: [Block128::ZERO, Block128::ZERO],
    }
}

#[test]
fn sweep_block_spine_mle_uses_142_slots_per_tx() {
    let inputs = vec![fixture_inputs(1), fixture_inputs(2)];
    let mle = SweepBlockSpineMle::build(&inputs);
    assert_eq!(mle.n_instances, 2);
    assert_eq!(mle.inner.live_slots, 2 * N_SWEEP_SPINE_SLOTS);
    assert_eq!(mle.inner.num_vars, 18);
}

fn prove_fixture(
    inputs: Vec<SweepSpineInputs>,
) -> (
    Vec<[Block128; 2]>,
    noid_gkr::SweepBlockSpineProof,
    noid_gkr::SweepBlockSpineReductions,
) {
    let circuit = SweepSpineCircuit::build();
    let hashes: Vec<[Block128; 2]> = inputs
        .iter()
        .map(|input| compute_sweep_tx_body_hash(&circuit, input))
        .collect();
    let mle = SweepBlockSpineMle::build(&inputs);

    let mut ch_p = Poseidon2bChannel::new();
    let (proof, reductions) =
        prove_sweep_block_spine_killshot(inputs.len(), &mle, &hashes, &mut ch_p);
    (hashes, proof, reductions)
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_block_spine_1tx_roundtrip_and_native_discharge() {
    let inputs = vec![fixture_inputs(42)];
    let (hashes, proof, reductions) = prove_fixture(inputs.clone());
    assert!(proof.byte_len() > 0);
    assert!(discharge_sweep_block_spine_reductions_native(
        &inputs,
        &reductions
    ));

    let mut ch_v = Poseidon2bChannel::new();
    let verified = verify_sweep_block_spine_killshot(&proof, inputs.len(), &hashes, &mut ch_v)
        .expect("verify sweep block spine");
    assert_eq!(verified, reductions);
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_block_spine_2tx_roundtrip() {
    let inputs = vec![fixture_inputs(100), fixture_inputs(200)];
    let (hashes, proof, reductions) = prove_fixture(inputs.clone());
    assert!(discharge_sweep_block_spine_reductions_native(
        &inputs,
        &reductions
    ));

    let mut ch_v = Poseidon2bChannel::new();
    let verified = verify_sweep_block_spine_killshot(&proof, inputs.len(), &hashes, &mut ch_v)
        .expect("verify sweep block spine");
    assert_eq!(verified, reductions);
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_block_spine_rejects_wrong_tx_body_hash() {
    let inputs = vec![fixture_inputs(7)];
    let (mut hashes, proof, _) = prove_fixture(inputs.clone());

    hashes[0][0] += Block128::ONE;
    let mut ch_v = Poseidon2bChannel::new();
    assert!(verify_sweep_block_spine_killshot(&proof, inputs.len(), &hashes, &mut ch_v).is_none());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_block_spine_rejects_proof_field_tamper() {
    let inputs = vec![fixture_inputs(9)];
    let (hashes, mut proof, _) = prove_fixture(inputs.clone());

    proof.kill_shot.main.s_in_dec_at_r += Block128::ONE;
    let mut ch_v = Poseidon2bChannel::new();
    assert!(verify_sweep_block_spine_killshot(&proof, inputs.len(), &hashes, &mut ch_v).is_none());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_block_spine_native_discharge_rejects_input_tamper() {
    let inputs = vec![fixture_inputs(11)];
    let (_, _, reductions) = prove_fixture(inputs.clone());

    let mut tampered = inputs.clone();
    tampered[0].input_leaves[3][1] += Block128::ONE;
    assert!(!discharge_sweep_block_spine_reductions_native(
        &tampered,
        &reductions
    ));
}
