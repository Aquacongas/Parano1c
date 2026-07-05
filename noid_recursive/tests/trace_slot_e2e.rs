// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! End-to-end: a real verifier-replay + discharge trace slot proven and
//! verified through the FieldR1cs pipeline (the same prover/verifier the
//! recursion slot replays).

use noid_core::Block128;
use noid_gkr::accepted_claim_killshot::{
    prove_accepted_claim_hash_killshot, AcceptedClaimHashInputs, ACCEPTED_CLAIM_FIELDS,
};
use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, RawChannelTrace};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::verifier::verify_field;
use noid_ivc_prover::field_prover::prove_field;
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ACCBLK};
use noid_recursive::acceptance::trace::accepted_claim_hash::build_accepted_claim_hash_slot;

fn fixture_input(seed: u128) -> AcceptedClaimHashInputs {
    let fields: [Block128; ACCEPTED_CLAIM_FIELDS] = std::array::from_fn(|i| {
        Block128::from(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) + i as u128)
    });
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_ACCBLK));
    for pair in fields.chunks_exact(2) {
        sponge.absorb_pair(pair[0], pair[1]);
    }
    let digest = sponge.finalize_no_pad();
    AcceptedClaimHashInputs {
        fields,
        expected_claim: [
            Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
            Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
        ],
    }
}

/// The accepted_claim_hash slot ([K]+[D], the full step-1 deliverable) built
/// into a FieldR1cs, proven with `prove_field` and verified with
/// `verify_field` — the first whole-killshot π-substrate roundtrip.
#[test]
fn accepted_claim_hash_slot_proves_end_to_end() {
    let inputs = vec![fixture_input(1)];
    let mut ch_p = Poseidon2bChannel::new();
    let (killshot_proof, _) = prove_accepted_claim_hash_killshot(&inputs, &mut ch_p);

    let mut b = FieldR1csBuilder::new();
    let mut ch = RawChannelTrace::new();
    let _ = build_accepted_claim_hash_slot(&mut b, &mut ch, &killshot_proof, &inputs);
    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "slot must satisfy before proving");

    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut prover_challenger = FsLaneChallenger::new(b"trace-slot-e2e");
    let (proof, commitment, claim_p) = prove_field(&r1cs, &z, &params, &mut prover_challenger);

    let mut verifier_challenger = FsLaneChallenger::new(b"trace-slot-e2e");
    let claim_v = verify_field(&r1cs, &commitment, &proof, &mut verifier_challenger)
        .expect("field proof of the accepted_claim_hash slot verifies");
    assert_eq!(claim_p, claim_v);
}
