// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Capsule-local PCS openings for AuthGKR MLE columns.
//!
//! `BatchEvalProof` reduces a set of claims on one private MLE column to a
//! single `(point, value)`, but that reduced claim is sound only if it is
//! discharged against a commitment to the same column. The wallet commits
//! and opens the private MLE locally through the capsule PCS
//! (`noid_fri_binius::capsule`: rate 1/32, 1-permutation flat feed-forward
//! tree nodes, two arity-16 fold layers, 16-bit pre-query grind) and
//! serializes only the compact commitment/opening proof, never the raw
//! column.

use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_fri::Channel;
use noid_fri_binius::capsule::{
    capsule_commit, capsule_open, capsule_verify, CapsuleCommitment, CapsuleOpeningProof,
    CapsuleProverState,
};
use zeroize::Zeroize;

use crate::batch_eval::BatchEvalReduction;

/// Auth capsule slice base. Matches tx/block trace row count so the same
/// capsule machinery can be reused without raw slice serialization.
pub const AUTH_PCS_BASE_LOG: usize = 9;

/// Compact opening of one AuthGKR MLE column at one reduced batch-eval point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthMleOpeningProof {
    pub commitment: CapsuleCommitment,
    pub opening: CapsuleOpeningProof,
}

impl AuthMleOpeningProof {
    pub fn byte_len(&self) -> usize {
        let cap = self.commitment.cap.hashes.len() * 32;
        let opening = self.opening.byte_len();
        if std::env::var("NOID_AUTH_PCS_PROFILE").is_ok() {
            eprintln!(
                "auth_pcs bytes cap={} opening={} total={}",
                cap,
                opening,
                cap + opening
            );
        }
        cap + opening
    }
}

pub struct AuthMleCommittedColumn {
    pub commitment: CapsuleCommitment,
    column: Vec<Block128>,
    /// Prover state retained from commitment so the opening does not
    /// re-encode and re-hash the whole column. Consumed by the one opening.
    state: Option<CapsuleProverState>,
}

impl Drop for AuthMleCommittedColumn {
    fn drop(&mut self) {
        self.column.zeroize();
        // The RS-encoded column is secret-derived; wipe it as well.
        if let Some(state) = self.state.as_mut() {
            state.encoded.zeroize();
        }
    }
}

/// Commit one private AuthGKR MLE column before any AuthGKR challenge is drawn.
pub fn commit_auth_mle_column(column: &[Block128], num_vars: usize) -> AuthMleCommittedColumn {
    assert_eq!(column.len(), 1usize << num_vars);
    assert!(num_vars >= AUTH_PCS_BASE_LOG);

    let (commitment, state) = capsule_commit(column, num_vars);
    AuthMleCommittedColumn {
        commitment,
        column: column.to_vec(),
        state: Some(state),
    }
}

/// Absorb an Auth capsule MLE commitment into the AuthGKR Fiat-Shamir channel.
/// This must happen before GKR sumcheck challenges are squeezed.
pub fn absorb_auth_mle_commitment<T: FiatShamir<Block128>>(
    channel: &mut T,
    commitment: &CapsuleCommitment,
) {
    const AUTH_PCS_COMMIT_TAG: u128 = 0xA07D_6B12_C011_17ED_u128;
    channel.absorb(Block128::from(AUTH_PCS_COMMIT_TAG));
    channel.absorb(Block128::from(commitment.log_rows as u128));
    channel.absorb(Block128::from(commitment.cap.hashes.len() as u128));
    // Capsule digests are FLAT-basis lanes; convert each half flat→tower so
    // the absorbed element IS the digest lane (see the capsule transcript
    // helpers for the same convention).
    for h in &commitment.cap.hashes {
        let lo = u128::from_le_bytes(h[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(h[16..].try_into().unwrap());
        channel.absorb(Block128::from(noid_core::hardware::flat_to_tower_u128(lo)));
        channel.absorb(Block128::from(noid_core::hardware::flat_to_tower_u128(hi)));
    }
}

pub fn open_auth_mle_committed(
    committed: &mut AuthMleCommittedColumn,
    num_vars: usize,
    reduction: &BatchEvalReduction,
) -> AuthMleOpeningProof {
    assert!(num_vars >= AUTH_PCS_BASE_LOG);
    assert_eq!(reduction.point.len(), num_vars);
    assert_eq!(committed.commitment.log_rows, num_vars);

    let mut state = committed
        .state
        .take()
        .expect("auth MLE commitment supports exactly one opening");
    let mut channel = Channel::new();
    let opening = capsule_open(
        &committed.column,
        &state,
        &committed.commitment,
        &reduction.point,
        &mut channel,
    );
    debug_assert_eq!(opening.value, reduction.value);

    // The RS-encoded column is secret-derived; wipe it before dropping.
    state.encoded.zeroize();

    AuthMleOpeningProof {
        commitment: committed.commitment.clone(),
        opening,
    }
}

pub fn verify_auth_mle_opening(
    proof: &AuthMleOpeningProof,
    num_vars: usize,
    reduction: &BatchEvalReduction,
) -> bool {
    if num_vars < AUTH_PCS_BASE_LOG || reduction.point.len() != num_vars {
        return false;
    }
    if proof.commitment.log_rows != num_vars {
        return false;
    }

    let mut channel = Channel::new();
    match capsule_verify(&proof.commitment, &reduction.point, &proof.opening, &mut channel) {
        Ok(value) => value == reduction.value,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::mle::evaluate::evaluate_slice;
    use noid_core::TowerField;

    #[test]
    fn auth_mle_opening_roundtrip() {
        let num_vars = AUTH_PCS_BASE_LOG + 2;
        let column: Vec<Block128> = (0..(1usize << num_vars))
            .map(|i| Block128::from((i as u128).wrapping_mul(17) ^ 0xA5A5))
            .collect();
        let point: Vec<Block128> = (0..num_vars)
            .map(|i| Block128::from(0x1000u128 + i as u128))
            .collect();
        let value = evaluate_slice(&column, &point);
        let reduction = BatchEvalReduction { point, value };

        let mut committed = commit_auth_mle_column(&column, num_vars);
        let proof = open_auth_mle_committed(&mut committed, num_vars, &reduction);
        assert!(verify_auth_mle_opening(&proof, num_vars, &reduction));
    }

    #[test]
    fn auth_mle_opening_rejects_wrong_value() {
        let num_vars = AUTH_PCS_BASE_LOG + 1;
        let column: Vec<Block128> = (0..(1usize << num_vars))
            .map(|i| Block128::from((i as u128).wrapping_mul(9) ^ 0x5A5A))
            .collect();
        let point: Vec<Block128> = (0..num_vars)
            .map(|i| Block128::from(0x2000u128 + i as u128))
            .collect();
        let value = evaluate_slice(&column, &point);
        let reduction = BatchEvalReduction { point, value };
        let mut committed = commit_auth_mle_column(&column, num_vars);
        let proof = open_auth_mle_committed(&mut committed, num_vars, &reduction);

        let bad = BatchEvalReduction {
            point: reduction.point.clone(),
            value: reduction.value + Block128::ONE,
        };
        assert!(!verify_auth_mle_opening(&proof, num_vars, &bad));
    }
}
