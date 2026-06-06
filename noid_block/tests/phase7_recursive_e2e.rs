// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Phase 7 end-to-end test: prove_recursive_step + verify_tip.
//!
//! Builds a single-transaction block proof (reusing stage_g_roundtrip
//! infrastructure), then wraps it in a RecursiveBlockProof and verifies
//! with verify_tip (O(1) chain verification).
//!
//! Marked `#[ignore]` — runs the full block STARK prove (heavy).
//! Execute with:  `cargo test -p noid_block --ignored phase7 --release`

use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_air::Air;
use noid_block::{prove_block, TxBlockWitness, BLOCK_BASE_LOG};
use noid_chain::{hash_block_header, BlockHeader};
use noid_core::mle::split::split_mle_into_slices;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    auth_gkr_channel, build_auth_unified_from_inputs, compute_auth_boundary, prove_auth_killshot,
    AuthCircuit, AuthInputs, AuthProofKillShot, AuthPublicInputs, SpineInputs, N_AUTH_INPUTS,
    N_AUTH_UNIFIED_VARS,
};
use noid_poseidon2b::primitives::{
    derive_address, hash_auth_tag, Address, SpendSecret, TxBodyHash,
};
use noid_recursive::accumulator::genesis_accumulator;
use noid_recursive::{
    prove::prove_recursive_step, verify::verify_tip, witness::BlockReplayWitness,
};
use noid_tx::{PublicInputs, TxBody, TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS};

// ---------------------------------------------------------------------------
// Test helpers (mirrors stage_g_roundtrip.rs)
// ---------------------------------------------------------------------------

fn mk_secret(seed: u128) -> [Block128; 2] {
    [
        Block128::from(seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xA5A5_A5A5_A5A5_A5A5),
        Block128::from(seed.wrapping_mul(0xBF58476D1CE4E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A),
    ]
}

fn fields_to_bytes(f: [Block128; 2]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&f[0].to_u128().to_le_bytes());
    out[16..].copy_from_slice(&f[1].to_u128().to_le_bytes());
    out
}

fn mk_test_body() -> TxBody {
    let secrets = [mk_secret(0xA1), mk_secret(0xB2)];
    let addrs: Vec<_> = secrets
        .iter()
        .map(|s| derive_address(&SpendSecret(fields_to_bytes(*s))))
        .collect();

    let mut inputs = vec![
        TxInput {
            slot_index: 0,
            value: 100,
            owner: addrs[0],
            spend_secret: SpendSecret(fields_to_bytes(secrets[0])),
            auth_tag: noid_poseidon2b::primitives::AuthTag([0u8; 32]),
            valid: true,
        },
        TxInput {
            slot_index: 1,
            value: 50,
            owner: addrs[1],
            spend_secret: SpendSecret(fields_to_bytes(secrets[1])),
            auth_tag: noid_poseidon2b::primitives::AuthTag([0u8; 32]),
            valid: true,
        },
    ];
    while inputs.len() < MAX_INPUTS {
        inputs.push(TxInput::dummy());
    }
    let mut outputs = vec![
        TxOutput {
            slot_index: 10,
            value: 80,
            owner: addrs[0],
            valid: true,
        },
        TxOutput {
            slot_index: 11,
            value: 60,
            owner: addrs[1],
            valid: true,
        },
    ];
    while outputs.len() < MAX_OUTPUTS {
        outputs.push(TxOutput::dummy());
    }
    let mut body = TxBody {
        epoch_anchor: [0xAA; 32],
        fee: 10,
        inputs,
        outputs,
        is_coinbase: false,
    };
    let pins = boundary_pins_from_body(&body);
    let tx_body_hash = pins.tx_body_hash;
    for i in 0..2 {
        let tag = hash_auth_tag(
            &SpendSecret(fields_to_bytes(secrets[i])),
            &TxBodyHash(fields_to_bytes(tx_body_hash)),
        );
        body.inputs[i].auth_tag = tag;
    }
    body
}

fn build_fixture(body: &TxBody) -> (TxLogicAir, noid_air::Trace, PublicInputs, SpineInputs) {
    use noid_tx::compute_claims_commitment;
    let pins = boundary_pins_from_body(body);
    let air = TxLogicAir::new(pins);
    let witness = witness_from_body(body);
    let trace = air.build_trace(&witness);
    let n_live_inputs = body.inputs.iter().filter(|i| i.valid).count() as u8;
    let n_live_outputs = body.outputs.iter().filter(|o| o.valid).count() as u8;
    let claims = compute_claims_commitment(&body.inputs, &body.outputs);
    let mut is_activation = [false; MAX_OUTPUTS];
    for (j, o) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
        is_activation[j] = o.valid;
    }
    let mut is_deactivation = [false; MAX_INPUTS];
    for (i, inp) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
        is_deactivation[i] = inp.valid;
    }
    let pi = PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash: TxBodyHash(fields_to_bytes(pins.tx_body_hash)),
        fee: body.fee,
        n_live_inputs,
        n_live_outputs,
        coinbase_credit: 0,
        log_slots: 24,
        claims_commitment: claims,
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
    (air, trace, pi, spine_inputs)
}

fn wallet_auth(
    body: &TxBody,
    tx_body_hash: [Block128; 2],
) -> (AuthPublicInputs, AuthProofKillShot, Vec<Vec<Block128>>) {
    let secrets = [
        mk_secret(0xA1),
        mk_secret(0xB2),
        mk_secret(0xC3),
        mk_secret(0xD4),
    ];
    let circuit = AuthCircuit::build();
    let n_live = body.inputs.iter().filter(|i| i.valid).count();
    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for i in 0..n_live {
        spend_secret[i] = secrets[i];
    }
    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&circuit, spend_secret, tx_body_hash);
    let auth_inputs = AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    };
    let mut ch = auth_gkr_channel();
    let (proof, _) = prove_auth_killshot(&circuit, &auth_inputs, &mut ch);
    let auth_mle = build_auth_unified_from_inputs(&circuit, &auth_inputs);
    let slices = split_mle_into_slices(&auth_mle.state, N_AUTH_UNIFIED_VARS, BLOCK_BASE_LOG);
    (auth_inputs.to_public(), proof, slices)
}

// ---------------------------------------------------------------------------
// Phase 7 E2E test
// ---------------------------------------------------------------------------

/// Full Phase 7 roundtrip:
/// 1. Build a real single-tx BlockProof (via prove_block).
/// 2. Extract BlockReplayWitness.
/// 3. prove_recursive_step → RecursiveBlockProof (~11 KB).
/// 4. Verify RecursiveBlockAir constraints (check_legacy).
/// 5. verify_tip → O(1) chain verification.
#[test]
#[ignore = "phase7_e2e: full block prove + recursive step (heavy); run with --ignored"]
fn phase7_recursive_step_and_verify_tip() {
    // ----- Build block proof -----
    let body = mk_test_body();
    let (air, trace, pi, spine_inputs) = build_fixture(&body);
    let tx_body_hash = pi.tx_body_hash.as_fields();
    let (auth_public, auth_proof, auth_slices) = wallet_auth(&body, tx_body_hash);

    let witness = TxBlockWitness {
        air: &air as &dyn Air,
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_public: &auth_public,
        auth_proof: &auth_proof,
        auth_slices: &auth_slices,
    };

    let prev_state_root = pi.epoch_anchor;
    let block_proof = prove_block(prev_state_root, std::slice::from_ref(&witness), &[])
        .expect("prove_block must succeed");

    // ----- Build a minimal block header -----
    let block_header = BlockHeader {
        prev_block_hash: [0u8; 32],
        state_root: prev_state_root, // reuse for test
        tx_root: [0u8; 32],
        timestamp: 1_700_000_000,
        height: 1,
        miner_address: Address([0u8; 32]),
        nonce: 0,
        difficulty_target: [0xFFu8; 32],
        proof_transcript_hash: block_proof
            .commitment
            .cap
            .hashes
            .first()
            .copied()
            .unwrap_or([1u8; 32]),
        witness_root: [2u8; 32],
        log_slots: 24,
        active_slot_count: 0,
        alloc_counter: 0,
    };

    // ----- Set up genesis accumulator -----
    let genesis_block_hash = hash_block_header(&block_header);
    // For testing, the genesis covers block 0 with zero state root.
    let genesis_acc = genesis_accumulator([0u8; 32], genesis_block_hash);

    // ----- Extract BlockReplayWitness -----
    let block_witness = BlockReplayWitness::from_parts(
        block_proof.commitment.cap.clone(),
        block_proof.state_binding_algebraics.clone(),
        block_proof.block_col_openings.clone(),
        block_proof.block_multipoint_rounds.clone(),
        block_proof.mixed_opening.fri_proof.clone(),
        block_proof.mixed_opening.all_openings.clone(),
        block_proof.block_initial_claim,
    );

    // ----- prove_recursive_step -----
    eprintln!("[phase7] Running prove_recursive_step...");
    let rec_proof = prove_recursive_step(&block_witness, &block_header, &genesis_acc, None);
    eprintln!(
        "[phase7] RecursiveBlockProof: ~{} bytes",
        rec_proof.byte_len()
    );

    assert_eq!(rec_proof.acc.height, block_header.height);
    assert_eq!(rec_proof.acc.state_root, block_header.state_root);

    // ----- Check RecursiveBlockAir constraints hold -----
    {
        use noid_air::ColumnDomain;
        use noid_recursive::air::{
            build_recursive_trace, RecursiveBlockAir, RecursiveBlockWitness, LOG_ROWS, N_COLS,
            REC_SUMCHECK_ROUNDS,
        };

        // Build a synthetic witness from the block proof's multipoint rounds.
        let synthetic_witness = RecursiveBlockWitness {
            block_multipoint_rounds: block_proof.block_multipoint_rounds.clone(),
            block_initial_claim: Block128::ZERO,
            block_challenges: block_proof
                .block_multipoint_rounds
                .iter()
                .map(|_| Block128::ZERO)
                .collect(),
            rec_multipoint_rounds: vec![vec![Block128::ZERO; 2]; REC_SUMCHECK_ROUNDS],
            rec_initial_claim: Block128::ZERO,
            rec_challenges: vec![Block128::ZERO; REC_SUMCHECK_ROUNDS],
            acc_prev_state_root: genesis_acc.state_root,
            acc_new_state_root: rec_proof.acc.state_root,
        };

        let rec_air = RecursiveBlockAir::new(&synthetic_witness);
        let trace = build_recursive_trace(&synthetic_witness);
        let trace_obj = noid_air::Trace {
            columns: trace,
            domains: vec![ColumnDomain::Block128; N_COLS],
            log_rows: LOG_ROWS,
        };
        let ok = noid_air::check_legacy(&rec_air, &trace_obj);
        assert!(ok, "RecursiveBlockAir AIR check must pass");
        eprintln!("[phase7] RecursiveBlockAir AIR check: PASS");
    }

    // ----- verify_tip -----
    // For a single-block chain, the "tip" is block 1.
    // rec_proof covers block 1 (height=1). The next block would be the tip.
    // For testing, treat rec_proof as covering blocks up to N-1=1,
    // and the "tip" is block N=2 with prev_state_root = rec_proof.acc.state_root.
    {
        use noid_recursive::air::{RecursiveBlockAir, RecursiveBlockWitness, REC_SUMCHECK_ROUNDS};

        let tip_height = block_header.height + 1; // tip is one block after
        let tip_prev_state_root = rec_proof.acc.state_root;

        // Build a minimal RecursiveBlockAir for verification.
        let verify_witness = RecursiveBlockWitness {
            block_multipoint_rounds: block_proof.block_multipoint_rounds.clone(),
            block_initial_claim: Block128::ZERO,
            block_challenges: block_proof
                .block_multipoint_rounds
                .iter()
                .map(|_| Block128::ZERO)
                .collect(),
            rec_multipoint_rounds: vec![vec![Block128::ZERO; 2]; REC_SUMCHECK_ROUNDS],
            rec_initial_claim: Block128::ZERO,
            rec_challenges: vec![Block128::ZERO; REC_SUMCHECK_ROUNDS],
            acc_prev_state_root: genesis_acc.state_root,
            acc_new_state_root: rec_proof.acc.state_root,
        };
        let rec_air_for_verify = RecursiveBlockAir::new(&verify_witness);

        eprintln!("[phase7] Running verify_tip...");
        let result = verify_tip(
            &rec_proof,
            &rec_air_for_verify,
            &tip_prev_state_root,
            tip_height,
            &genesis_acc,
            None, // no expected_chain_hash: test doesn't have full header chain
        );
        assert!(result.is_ok(), "verify_tip must succeed: {result:?}");
        eprintln!("[phase7] verify_tip: PASS — O(1) chain verification works!");
    }
}

/// Fast accumulator-only test (no STARK proving — always runs).
#[test]
fn phase7_accumulator_chain_e2e() {
    let genesis = genesis_accumulator([0x00u8; 32], [0xAAu8; 32]);
    let block1_hash = [0x11u8; 32];
    let acc1 = genesis.extend([0x22u8; 32], block1_hash, 1);
    let block2_hash = [0x33u8; 32];
    let acc2 = acc1.extend([0x44u8; 32], block2_hash, 2);

    // chain_hash is deterministic
    let expected_1 = noid_poseidon2b::native::compress(&genesis.chain_hash, &block1_hash);
    assert_eq!(acc1.chain_hash, expected_1);

    let expected_2 = noid_poseidon2b::native::compress(&acc1.chain_hash, &block2_hash);
    assert_eq!(acc2.chain_hash, expected_2);

    // Different block hashes → different chain hashes
    let acc_alt = genesis.extend([0x22u8; 32], [0xFF_u8; 32], 1);
    assert_ne!(acc1.chain_hash, acc_alt.chain_hash);

    eprintln!("[phase7] 3-step accumulator chain: genesis → block1 → block2, all consistent");
}

/// AIR constraint check for RecursiveBlockAir with zero data (fast, always runs).
#[test]
fn phase7_recursive_air_zero_data_check() {
    use noid_air::ColumnDomain;
    use noid_recursive::air::{
        build_recursive_trace, RecursiveBlockAir, RecursiveBlockWitness, BLOCK_SUMCHECK_ROUNDS,
        LOG_ROWS, N_COLS, REC_SUMCHECK_ROUNDS,
    };

    let witness = RecursiveBlockWitness {
        block_multipoint_rounds: vec![vec![Block128::ZERO; 2]; BLOCK_SUMCHECK_ROUNDS],
        block_initial_claim: Block128::ZERO,
        block_challenges: vec![Block128::ZERO; BLOCK_SUMCHECK_ROUNDS],
        rec_multipoint_rounds: vec![vec![Block128::ZERO; 2]; REC_SUMCHECK_ROUNDS],
        rec_initial_claim: Block128::ZERO,
        rec_challenges: vec![Block128::ZERO; REC_SUMCHECK_ROUNDS],
        acc_prev_state_root: [0u8; 32],
        acc_new_state_root: [0u8; 32],
    };
    let air = RecursiveBlockAir::new(&witness);
    let trace = build_recursive_trace(&witness);
    let trace_obj = noid_air::Trace {
        columns: trace,
        domains: vec![ColumnDomain::Block128; N_COLS],
        log_rows: LOG_ROWS,
    };
    assert!(noid_air::check_legacy(&air, &trace_obj));
}
