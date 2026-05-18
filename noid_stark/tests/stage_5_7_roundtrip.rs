// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.
//
// Auth <-> Spine bridge soundness tests.
#![allow(clippy::manual_memcpy)]

//
// Attack vector: an attacker knows their own spend_secret but wants to
// steal a victim's UTXO. They construct:
//   - spine_inputs with victim's address in input_leaves (real state)
//   - auth_inputs with attacker's secret (proves attacker's address)
//   - STARK trace with victim's UTXO values (owner cols unconstrained)
//
// Without the bridge check the verifier would accept: auth GKR proves
// the attacker knows *some* secret, spine GKR proves tx_body_hash
// commits to the victim's address, but nothing ties the two together.
// The bridge ensures `auth.expected_address[i] == spine.input_leaves[i].owner`.

use noid_air::composition::tx_validity_with_spine::fixture;
use noid_core::{Block128, TowerField};
use noid_gkr::{compute_auth_boundary, AuthCircuit, AuthInputs, SpineInputs, N_AUTH_INPUTS};

/// Lower the composite's boundary pins to the `SpineInputs` shape the
/// GKR spine consumes. Mirrors the pin semantics documented on
/// `TxBodyMerkleBoundaryPins`: the tree-leaf ordering is
/// `[L0, L1, L2..L5, L6..L13, L14, L15]`.
fn spine_inputs_from_composite(
    comp: &noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine,
) -> SpineInputs {
    let pins = comp.boundary_pins();
    SpineInputs {
        prev_state_root: pins.prev_state_root,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    }
}

#[test]
#[ignore = "bridge_soundness: heavy (full prove_tx); run with --ignored"]
fn verify_tx_rejects_forged_address_via_bridge() {
    use noid_air::composition::tx_validity_with_spine::fixture::mk_secret;
    use noid_stark::prove_tx::{prove_tx, verify_tx, TxWitness, VerifyTxError};

    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let pi = comp.public_inputs();
    let spine_inputs = spine_inputs_from_composite(&comp);

    // Honest auth: secrets match fixture owners (mk_secret(0xA1), mk_secret(0xB2))
    let circuit = AuthCircuit::build();
    let n_live = pi.n_live_inputs as usize;
    let honest_secrets = [
        mk_secret(0xA1),
        mk_secret(0xB2),
        mk_secret(0xC3),
        mk_secret(0xD4),
    ];
    let mut spend_secret_honest = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for i in 0..n_live {
        spend_secret_honest[i] = honest_secrets[i];
    }
    let tx_body_hash = comp.tx_body_hash_fields();
    let (honest_addr, honest_tag) =
        compute_auth_boundary(&circuit, spend_secret_honest, tx_body_hash);
    let honest_auth = AuthInputs {
        spend_secret: spend_secret_honest,
        tx_body_hash,
        expected_address: honest_addr,
        expected_auth_tag: honest_tag,
    };

    // Honest proof passes
    let witness = TxWitness {
        air: comp.air(),
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_inputs: &honest_auth,
    };
    let proof = prove_tx(&witness).expect("honest prove_tx must succeed");
    verify_tx(comp.air(), &pi, &spine_inputs, &honest_auth, &proof)
        .expect("honest verify_tx must succeed");

    // --- Attack: use attacker's secrets instead of victim's ---
    // Attacker secret differs from fixture's mk_secret(0xA1)
    let attacker_secrets = [
        mk_secret(0xFF),
        mk_secret(0xEE),
        mk_secret(0xDD),
        mk_secret(0xCC),
    ];
    let mut spend_secret_attack = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for i in 0..n_live {
        spend_secret_attack[i] = attacker_secrets[i];
    }
    let (attacker_addr, attacker_tag) =
        compute_auth_boundary(&circuit, spend_secret_attack, tx_body_hash);
    let forged_auth = AuthInputs {
        spend_secret: spend_secret_attack,
        tx_body_hash,
        expected_address: attacker_addr,
        expected_auth_tag: attacker_tag,
    };

    // Attacker's address differs from spine leaf owner
    assert_ne!(
        attacker_addr[0], honest_addr[0],
        "attacker must have a different address"
    );

    // Build a forged proof: the prover uses attacker's auth_inputs
    // with the victim's spine/trace. prove_tx succeeds because:
    //   - AIR owner columns are free (unconstrained)
    //   - spine GKR uses spine_inputs (victim's owners)
    //   - auth GKR uses forged_auth (attacker's secrets/addresses)
    //   - They don't cross-check each other during proving
    let forged_witness = TxWitness {
        air: comp.air(),
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_inputs: &forged_auth,
    };
    let forged_proof =
        prove_tx(&forged_witness).expect("forged prove_tx succeeds (prover is malicious)");

    // verify_tx MUST reject: bridge detects address mismatch
    let result = verify_tx(comp.air(), &pi, &spine_inputs, &forged_auth, &forged_proof);
    assert!(result.is_err(), "verify_tx must reject forged address");
    match result.unwrap_err() {
        VerifyTxError::AuthSpineBridge => {}
        other => panic!(
            "expected AuthSpineBridge, got {:?} — bridge not triggered",
            other
        ),
    }
}

#[test]
#[ignore = "bridge_soundness: heavy (full prove_tx); run with --ignored"]
fn verify_tx_rejects_mismatched_tx_body_hash_in_auth() {
    use noid_air::composition::tx_validity_with_spine::fixture::mk_secret;
    use noid_stark::prove_tx::{prove_tx, verify_tx, TxWitness};

    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let pi = comp.public_inputs();
    let spine_inputs = spine_inputs_from_composite(&comp);

    let circuit = AuthCircuit::build();
    let n_live = pi.n_live_inputs as usize;
    let secrets = [
        mk_secret(0xA1),
        mk_secret(0xB2),
        mk_secret(0xC3),
        mk_secret(0xD4),
    ];
    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for i in 0..n_live {
        spend_secret[i] = secrets[i];
    }
    let tx_body_hash = comp.tx_body_hash_fields();
    let (addr, tag) = compute_auth_boundary(&circuit, spend_secret, tx_body_hash);
    let honest_auth = AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address: addr,
        expected_auth_tag: tag,
    };

    // Honest proof
    let witness = TxWitness {
        air: comp.air(),
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_inputs: &honest_auth,
    };
    let proof = prove_tx(&witness).expect("prove_tx");

    // Tamper auth_inputs.tx_body_hash (replay attack vector)
    let mut bad_hash = tx_body_hash;
    bad_hash[0] += Block128::ONE;
    let tampered_auth = AuthInputs {
        spend_secret,
        tx_body_hash: bad_hash,
        expected_address: addr,
        expected_auth_tag: tag,
    };

    // verify_tx must reject — either AuthKillShot (channel diverges)
    // or AuthSpineBridge (tx_body_hash mismatch). Both are acceptable
    // since the system rejects the forgery.
    let result = verify_tx(comp.air(), &pi, &spine_inputs, &tampered_auth, &proof);
    assert!(
        result.is_err(),
        "verify_tx must reject tampered tx_body_hash in auth_inputs"
    );
}
