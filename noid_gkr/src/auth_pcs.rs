// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Capsule-local PCS openings for AuthGKR MLE columns.
//!
//! `BatchEvalProof` reduces a set of claims on one private MLE column to a
//! single `(point, value)`, but that reduced claim is sound only if it is
//! discharged against a commitment to the same column. Historically the caller
//! did this by serializing raw `auth_slices` into wallet/block artifacts. This
//! module keeps the same FRI-Binius commitment machinery but moves it inside the
//! Auth KillShot capsule: the wallet commits/opens the private MLE locally and
//! serializes only the compact commitment/opening proof, never the raw slices.

use noid_core::transcript::FiatShamir;
use noid_core::{AdditiveNTT, Block128};
use noid_fri::Channel;
use noid_fri_binius::interleaved_commit::SourceMerkleTree;
use noid_fri_binius::{
    absorb_cap, interleaved_commit_arithmetic, prove_mixed_opening, verify_mixed_opening,
    CommitmentHashBackend, InterleavedCommitment, InterleavedProverState, MixedOpeningProof,
    COMPACT_NUM_QUERIES,
};
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use zeroize::Zeroize;

use crate::batch_eval::BatchEvalReduction;

/// Auth capsule slice base. Matches tx/block trace row count so the same compact
/// FRI machinery can be reused without raw slice serialization.
pub const AUTH_PCS_BASE_LOG: usize = 9;

/// Compact opening of one AuthGKR MLE column at one reduced batch-eval point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthMleOpeningProof {
    pub commitment: InterleavedCommitment,
    pub opening: MixedOpeningProof,
}

impl AuthMleOpeningProof {
    pub fn byte_len(&self) -> usize {
        let cap = self.commitment.cap.hashes.len() * 32;
        let openings = self.opening.all_openings.len() * 16;
        let fri = self.opening.fri_proof.byte_len();
        let source = self.opening.source_proof.byte_len();
        if std::env::var("NOID_AUTH_PCS_PROFILE").is_ok() {
            eprintln!(
                "auth_pcs bytes cap={} openings={} fri={} source={} total={}",
                cap,
                openings,
                fri,
                source,
                cap + openings + fri + source
            );
        }
        cap + openings + fri + source
    }
}

pub struct AuthMleCommittedColumn {
    pub commitment: InterleavedCommitment,
    column: Vec<Block128>,
    /// Prover-state parts retained from commitment so the opening does not
    /// re-encode and re-hash the whole column (that would double the PCS
    /// cost, which dominates wallet proving). Consumed by the one opening.
    encoded_cols: Option<Vec<Vec<Block128>>>,
    source_tree: Option<SourceMerkleTree>,
}

impl Drop for AuthMleCommittedColumn {
    fn drop(&mut self) {
        self.column.zeroize();
        // The RS-encoded column is secret-derived; wipe it as well.
        if let Some(encoded_cols) = self.encoded_cols.as_mut() {
            for col in encoded_cols.iter_mut() {
                col.zeroize();
            }
        }
    }
}

/// Commit one private AuthGKR MLE column before any AuthGKR challenge is drawn.
pub fn commit_auth_mle_column(column: &[Block128], num_vars: usize) -> AuthMleCommittedColumn {
    assert_eq!(column.len(), 1usize << num_vars);
    assert!(num_vars >= AUTH_PCS_BASE_LOG);

    let ntt = AdditiveNTT::<Block128>::new(num_vars + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let column = column.to_vec();
    let col_refs: [&[Block128]; 1] = [column.as_slice()];
    let (commitment, prover_state) = interleaved_commit_arithmetic(&col_refs, &ntt, &hasher);
    let InterleavedProverState {
        encoded_cols,
        source_tree,
        ..
    } = prover_state;
    AuthMleCommittedColumn {
        commitment,
        column,
        encoded_cols: Some(encoded_cols),
        source_tree: Some(source_tree),
    }
}

/// Absorb an Auth capsule MLE commitment into the AuthGKR Fiat-Shamir channel.
/// This must happen before GKR sumcheck challenges are squeezed.
pub fn absorb_auth_mle_commitment<T: FiatShamir<Block128>>(
    channel: &mut T,
    commitment: &InterleavedCommitment,
) {
    const AUTH_PCS_COMMIT_TAG: u128 = 0xA07D_6B12_C011_17ED_u128;
    channel.absorb(Block128::from(AUTH_PCS_COMMIT_TAG));
    channel.absorb(Block128::from(commitment.log_rows as u128));
    channel.absorb(Block128::from(commitment.n_cols as u128));
    channel.absorb(Block128::from(commitment.hash_backend.as_u128()));
    channel.absorb(Block128::from(commitment.cap.hashes.len() as u128));
    for h in &commitment.cap.hashes {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        lo.copy_from_slice(&h[..16]);
        hi.copy_from_slice(&h[16..]);
        channel.absorb(Block128::from(u128::from_le_bytes(lo)));
        channel.absorb(Block128::from(u128::from_le_bytes(hi)));
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
    assert_eq!(committed.commitment.n_cols, 1);

    let ntt = AdditiveNTT::<Block128>::new(num_vars + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let encoded_cols = committed
        .encoded_cols
        .take()
        .expect("auth MLE commitment supports exactly one opening");
    let source_tree = committed
        .source_tree
        .take()
        .expect("auth MLE commitment supports exactly one opening");
    let prover_state = InterleavedProverState {
        raw_cols: vec![committed.column.as_slice()],
        log_rows: num_vars,
        n_cols: 1,
        encoded_cols,
        source_tree,
        hash_backend: committed.commitment.hash_backend,
    };
    let primary_point = reduction.point.clone();
    let mut channel = Channel::new();
    absorb_cap(&mut channel, &committed.commitment.cap);
    let opening = prove_mixed_opening(
        &prover_state,
        &primary_point,
        &[],
        &ntt,
        &mut channel,
        &hasher,
        COMPACT_NUM_QUERIES,
    );

    debug_assert_eq!(opening.all_openings.len(), 1);
    debug_assert_eq!(opening.all_openings[0], reduction.value);

    // The RS-encoded column is secret-derived; wipe it before dropping.
    let InterleavedProverState {
        mut encoded_cols, ..
    } = prover_state;
    for col in encoded_cols.iter_mut() {
        col.zeroize();
    }

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
    if proof.commitment.log_rows != num_vars || proof.commitment.n_cols != 1 {
        return false;
    }
    if proof.commitment.hash_backend != CommitmentHashBackend::Arithmetic {
        return false;
    }

    let primary_point = reduction.point.clone();
    let ntt = AdditiveNTT::<Block128>::new(num_vars + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let mut channel = Channel::new();
    absorb_cap(&mut channel, &proof.commitment.cap);
    let openings = match verify_mixed_opening(
        &proof.commitment,
        &primary_point,
        &[],
        &proof.opening,
        &ntt,
        &mut channel,
        &hasher,
        COMPACT_NUM_QUERIES,
    ) {
        Ok(openings) => openings,
        Err(_) => return false,
    };
    openings.len() == 1 && openings[0] == reduction.value
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
        assert_eq!(
            proof.commitment.hash_backend,
            CommitmentHashBackend::Arithmetic
        );
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
