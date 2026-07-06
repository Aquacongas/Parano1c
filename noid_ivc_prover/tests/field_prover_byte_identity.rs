//! Guards for the row-major lincheck fold (constraint-matrix double-storage
//! diet). Two properties:
//!   1. The prover produces byte-identical proofs — the row-major fold is
//!      value-identical to the CSC fold, so the transcript is unchanged.
//!   2. The prover never materializes the CSC transpose, so only ONE matrix
//!      representation is resident through the lincheck+open peak.

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::field_r1cs::synthetic_satisfiable;
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_prover::field_prover::prove_field;

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
    // Pinned digest, identical on the pre-change (CSC-fold) prover.
    assert_eq!(
        hex(&top),
        "d820e54279bb8c61436620c89443bf35ac7db181d8896added181d004f371448",
        "proof bytes changed — the row-major fold must be value-identical to the CSC fold"
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
