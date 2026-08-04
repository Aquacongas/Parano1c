//! Closed native C1 History proof: wide zerocheck, lincheck, and BaseFold
//! over the unchanged F128 witness commitment.

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_r1cs::{CompactFieldR1cs, synthetic_satisfiable};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::proof::FieldShape;
use noid_ivc_core::verifier::verify_field_c1;
use noid_ivc_prover::field_prover::{prove_field_c1, prove_field_compact_c1};

fn params_for(m: usize) -> PcsParams {
    PcsParams {
        m: m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    }
}

#[test]
fn field_c1_resident_and_compact_proofs_match_and_verify() {
    let (r1cs, witness) = synthetic_satisfiable(10, 7, 0xC1_E2E);
    let params = params_for(r1cs.m);
    let mut resident_challenger = FsLaneChallenger::new_c1(b"field-c1-e2e");
    let (resident_proof, resident_commitment, resident_claim) =
        prove_field_c1(&r1cs, &witness, &params, &mut resident_challenger);

    let mut verifier = FsLaneChallenger::new_c1(b"field-c1-e2e");
    let verified_claim =
        verify_field_c1(&r1cs, &resident_commitment, &resident_proof, &mut verifier)
            .expect("honest resident C1 field proof rejected");
    assert_eq!(verified_claim, resident_claim);

    let shape = FieldShape::of(&r1cs);
    let digest = r1cs.structural_statement_digest();
    let mut artifact = Vec::new();
    r1cs.write_artifact(&mut artifact).unwrap();
    let compact = CompactFieldR1cs::open_packed(artifact.into_boxed_slice(), shape, digest)
        .expect("authenticated packed relation");
    let mut compact_challenger = FsLaneChallenger::new_c1(b"field-c1-e2e");
    let (compact_proof, compact_commitment, compact_claim) =
        prove_field_compact_c1(&compact, &witness, &params, &mut compact_challenger);

    assert_eq!(compact_commitment.root, resident_commitment.root);
    assert_eq!(compact_claim, resident_claim);
    assert_eq!(
        bincode::serialize(&compact_proof).unwrap(),
        bincode::serialize(&resident_proof).unwrap(),
        "packed and resident C1 proof transcripts diverged",
    );

    let mut verifier = FsLaneChallenger::new_c1(b"field-c1-e2e");
    verify_field_c1(&r1cs, &compact_commitment, &compact_proof, &mut verifier)
        .expect("honest packed-relation C1 field proof rejected");
}

#[test]
fn field_c1_rejects_false_witness_and_message_mutation() {
    let (r1cs, witness) = synthetic_satisfiable(10, 7, 0xC1_BAD);
    let params = params_for(r1cs.m);
    let mut prover = FsLaneChallenger::new_c1(b"field-c1-reject");
    let (proof, commitment, _) = prove_field_c1(&r1cs, &witness, &params, &mut prover);

    let mut mutated = proof.clone();
    mutated.zerocheck.final_a_eval.hi.lo ^= 1;
    let mut verifier = FsLaneChallenger::new_c1(b"field-c1-reject");
    assert!(verify_field_c1(&r1cs, &commitment, &mutated, &mut verifier).is_err());

    let mut false_witness = witness;
    false_witness[37] += F128::ONE;
    assert!(!r1cs.satisfies(&false_witness));
    let mut prover = FsLaneChallenger::new_c1(b"field-c1-false");
    let (false_proof, false_commitment, _) =
        prove_field_c1(&r1cs, &false_witness, &params, &mut prover);
    let mut verifier = FsLaneChallenger::new_c1(b"field-c1-false");
    assert!(verify_field_c1(&r1cs, &false_commitment, &false_proof, &mut verifier,).is_err());
}
