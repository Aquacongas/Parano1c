//! Guards for the row-major lincheck fold (constraint-matrix double-storage
//! diet). Two properties:
//!   1. The prover produces byte-identical proofs — the row-major fold is
//!      value-identical to the CSC fold, so the transcript is unchanged.
//!   2. The prover never materializes the CSC transpose, so only ONE matrix
//!      representation is resident through the lincheck+open peak.

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::field_r1cs::{CompactFieldR1cs, synthetic_satisfiable};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::proof::FieldShape;
use noid_ivc_prover::field_prover::{prove_field, prove_field_compact};

fn params_for(m_elems: usize) -> PcsParams {
    PcsParams {
        m: m_elems + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    }
}

/// Stable digest of the serialized proof for fixed instances. The value is
/// pinned so a regression that perturbs the transcript (e.g. a non-identical
/// fold) is caught. Verified equal to the pre-change (CSC-fold) prover.
#[test]
fn field_proof_byte_digest() {
    let mut all = Vec::new();
    for &(m, k_log, seed) in &[(10usize, 7usize, 1u64), (12, 8, 2), (13, 10, 3)] {
        let (r1cs, z) = synthetic_satisfiable(m, k_log, seed);
        let params = params_for(m);
        let mut ch = FsLaneChallenger::new(b"field-r1cs-byte-identity-v0");
        let (proof, commitment, _claim) = prove_field(&r1cs, &z, &params, &mut ch);
        let mut bytes = bincode::serialize(&proof).unwrap();
        bytes.extend_from_slice(&bincode::serialize(&commitment).unwrap());
        let digest =
            noid_poseidon2b::native::poseidon2b_hash_byte_slices(b"BYTE-IDENTITY-PROBE", &[&bytes]);
        all.extend_from_slice(&digest);
    }
    let top = noid_poseidon2b::native::poseidon2b_hash_byte_slices(b"BYTE-IDENTITY-TOP", &[&all]);
    // Pinned digest. Re-pinned 2026-07-12; a bisect attributed both shifts
    // since the 2026-07-09 pin to deliberate protocol commits only: the
    // cryptographic-boundary/final-ladder cut (bf6aa115) and finite-length
    // UDR query derivation (4eaed4d0). Every other commit in the range —
    // including all four prove-time cuts — reproduced the digest byte-exact,
    // so the pin still catches ACCIDENTAL transcript perturbations such as a
    // non-identical fold.
    assert_eq!(
        hex(&top),
        "5a6b326250bf36e3ee07f882e8f58877594b44915c1b74a7178d6297fc7a7545",
        "proof bytes changed — the transcript must be byte-stable"
    );
}

/// The prover must NOT materialize the CSC transpose: after a full
/// `prove_field`, `csc_cache` stays empty (the lincheck folds off the
/// row-major `a_0`/`b_0`). Direct evidence that the CSC duplicate — 20 B/nnz
/// per matrix — is no longer resident through the lincheck+open peak.
#[test]
fn prover_does_not_materialize_csc() {
    let (r1cs, z) = synthetic_satisfiable(16, 16, 7);
    let params = params_for(16);
    let mut ch = FsLaneChallenger::new(b"csc-residency-probe-v0");
    let _ = prove_field(&r1cs, &z, &params, &mut ch);
    assert!(
        r1cs.csc_cache.get().is_none(),
        "prover materialized the CSC transpose — double-storage not eliminated"
    );
}

#[test]
fn authenticated_compact_prover_is_byte_identical_to_resident_csr() {
    let (r1cs, z) = synthetic_satisfiable(12, 12, 0xC04A_C7A1);
    let shape = FieldShape::of(&r1cs);
    let digest = r1cs.structural_statement_digest();
    let mut artifact = Vec::new();
    r1cs.write_artifact(&mut artifact).unwrap();
    let compact = CompactFieldR1cs::open(artifact.into_boxed_slice(), shape, digest).unwrap();
    let params = params_for(shape.m);

    let mut resident_ch = FsLaneChallenger::new(b"compact-field-byte-identity-v0");
    let (resident_proof, resident_commitment, resident_claim) =
        prove_field(&r1cs, &z, &params, &mut resident_ch);
    let mut compact_ch = FsLaneChallenger::new(b"compact-field-byte-identity-v0");
    let (compact_proof, compact_commitment, compact_claim) =
        prove_field_compact(&compact, &z, &params, &mut compact_ch);

    assert_eq!(
        bincode::serialize(&(compact_proof, compact_commitment)).unwrap(),
        bincode::serialize(&(resident_proof, resident_commitment)).unwrap(),
        "authenticated compact relation changed proof or commitment",
    );
    assert_eq!(
        compact_claim, resident_claim,
        "compact output claims drifted"
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
