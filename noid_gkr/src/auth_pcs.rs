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
use noid_fri_binius::{
    absorb_cap, interleaved_commit, prove_mixed_opening, verify_mixed_opening,
    InterleavedCommitment, MixedOpeningProof, COMPACT_NUM_QUERIES,
};
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use zeroize::Zeroize;

use crate::batch_eval::BatchEvalReduction;

/// Auth capsule slice base. Matches tx/block trace row count so the same compact
/// FRI machinery can be reused without raw slice serialization.
pub const AUTH_PCS_BASE_LOG: usize = noid_air::airs::tx_body_spine::SPINE_LOG_ROWS;

/// Compact opening of one AuthGKR MLE column at one reduced batch-eval point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthMleOpeningProof {
    pub commitment: InterleavedCommitment,
    pub opening: MixedOpeningProof,
}

impl AuthMleOpeningProof {
    pub fn byte_len(&self) -> usize {
        self.commitment.cap.hashes.len() * 32 + self.opening.byte_len()
    }
}

/// Compact opening of multiple AuthGKR MLE columns at one shared reduced point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthMleMultiOpeningProof {
    pub commitment: InterleavedCommitment,
    pub opening: MixedOpeningProof,
}

impl AuthMleMultiOpeningProof {
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
}

impl Drop for AuthMleCommittedColumn {
    fn drop(&mut self) {
        self.column.zeroize();
    }
}

pub struct AuthMleCommittedColumns {
    pub commitment: InterleavedCommitment,
    logical_columns: usize,
    columns: Vec<Vec<Block128>>,
}

impl Drop for AuthMleCommittedColumns {
    fn drop(&mut self) {
        self.columns.zeroize();
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
    let (commitment, _) = interleaved_commit(&col_refs, &ntt, &hasher);
    AuthMleCommittedColumn { commitment, column }
}

/// Commit several private AuthGKR MLE columns into one interleaved commitment.
/// Slices are stored column-major: all slices of logical column 0, then column 1, etc.
pub fn commit_auth_mle_columns(
    columns: &[&[Block128]],
    num_vars: usize,
) -> AuthMleCommittedColumns {
    assert!(!columns.is_empty());
    assert!(num_vars >= AUTH_PCS_BASE_LOG);
    let expected_len = 1usize << num_vars;
    let owned_columns: Vec<Vec<Block128>> = columns
        .iter()
        .map(|column| {
            assert_eq!(column.len(), expected_len);
            column.to_vec()
        })
        .collect();

    let col_refs: Vec<&[Block128]> = owned_columns.iter().map(Vec::as_slice).collect();
    let ntt = AdditiveNTT::<Block128>::new(num_vars + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let (commitment, _) = interleaved_commit(&col_refs, &ntt, &hasher);
    AuthMleCommittedColumns {
        commitment,
        logical_columns: columns.len(),
        columns: owned_columns,
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
    committed: &AuthMleCommittedColumn,
    num_vars: usize,
    reduction: &BatchEvalReduction,
) -> AuthMleOpeningProof {
    assert!(num_vars >= AUTH_PCS_BASE_LOG);
    assert_eq!(reduction.point.len(), num_vars);
    assert_eq!(committed.commitment.log_rows, num_vars);
    assert_eq!(committed.commitment.n_cols, 1);

    let ntt = AdditiveNTT::<Block128>::new(num_vars + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let raw_cols: [&[Block128]; 1] = [committed.column.as_slice()];
    let (rebuilt_commitment, prover_state) = interleaved_commit(&raw_cols, &ntt, &hasher);
    assert_eq!(rebuilt_commitment.cap, committed.commitment.cap);
    assert_eq!(rebuilt_commitment.log_rows, committed.commitment.log_rows);
    assert_eq!(rebuilt_commitment.n_cols, committed.commitment.n_cols);
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

    AuthMleOpeningProof {
        commitment: committed.commitment.clone(),
        opening,
    }
}

pub fn open_auth_mle_columns_committed(
    committed: &AuthMleCommittedColumns,
    num_vars: usize,
    reductions: &[BatchEvalReduction],
) -> AuthMleMultiOpeningProof {
    assert!(num_vars >= AUTH_PCS_BASE_LOG);
    assert!(!reductions.is_empty());
    assert_eq!(reductions.len(), committed.logical_columns);
    assert_eq!(committed.commitment.log_rows, num_vars);
    assert_eq!(committed.commitment.n_cols, reductions.len());
    for reduction in reductions {
        assert_eq!(reduction.point.len(), num_vars);
        assert_eq!(reduction.point, reductions[0].point);
    }

    let ntt = AdditiveNTT::<Block128>::new(num_vars + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let raw_cols: Vec<&[Block128]> = committed.columns.iter().map(Vec::as_slice).collect();
    let (rebuilt_commitment, prover_state) = interleaved_commit(&raw_cols, &ntt, &hasher);
    assert_eq!(rebuilt_commitment.cap, committed.commitment.cap);
    assert_eq!(rebuilt_commitment.log_rows, committed.commitment.log_rows);
    assert_eq!(rebuilt_commitment.n_cols, committed.commitment.n_cols);
    let primary_point = reductions[0].point.clone();
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

    debug_assert_eq!(opening.all_openings.len(), reductions.len());
    for (col_idx, reduction) in reductions.iter().enumerate() {
        debug_assert_eq!(opening.all_openings[col_idx], reduction.value);
    }

    AuthMleMultiOpeningProof {
        commitment: committed.commitment.clone(),
        opening,
    }
}

/// Convenience helper for tests and non-Fiat-Shamir-sensitive callers. AuthGKR
/// production code should use `commit_auth_mle_column`, absorb the commitment,
/// then call `open_auth_mle_committed` after reductions are known.
pub fn prove_auth_mle_opening(
    column: &[Block128],
    num_vars: usize,
    reduction: &BatchEvalReduction,
) -> AuthMleOpeningProof {
    let committed = commit_auth_mle_column(column, num_vars);
    open_auth_mle_committed(&committed, num_vars, reduction)
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

pub fn verify_auth_mle_multi_opening(
    proof: &AuthMleMultiOpeningProof,
    num_vars: usize,
    reductions: &[BatchEvalReduction],
) -> bool {
    if num_vars < AUTH_PCS_BASE_LOG || reductions.is_empty() {
        return false;
    }
    if proof.commitment.log_rows != num_vars || proof.commitment.n_cols != reductions.len() {
        return false;
    }
    for reduction in reductions {
        if reduction.point.len() != num_vars || reduction.point != reductions[0].point {
            return false;
        }
    }

    let primary_point = reductions[0].point.clone();
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
    if openings.len() != reductions.len() {
        return false;
    }

    for (col_idx, reduction) in reductions.iter().enumerate() {
        if openings[col_idx] != reduction.value {
            return false;
        }
    }
    true
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

        let proof = prove_auth_mle_opening(&column, num_vars, &reduction);
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
        let proof = prove_auth_mle_opening(&column, num_vars, &reduction);

        let bad = BatchEvalReduction {
            point: reduction.point.clone(),
            value: reduction.value + Block128::ONE,
        };
        assert!(!verify_auth_mle_opening(&proof, num_vars, &bad));
    }

    #[test]
    fn auth_mle_multi_opening_roundtrip() {
        let num_vars = AUTH_PCS_BASE_LOG + 2;
        let columns: Vec<Vec<Block128>> = (0..3)
            .map(|c| {
                (0..(1usize << num_vars))
                    .map(|i| {
                        Block128::from(
                            (i as u128).wrapping_mul(17 + c as u128) ^ (0xA5A5 + c as u128),
                        )
                    })
                    .collect()
            })
            .collect();
        let point: Vec<Block128> = (0..num_vars)
            .map(|i| Block128::from(0x3000u128 + i as u128))
            .collect();
        let reductions: Vec<BatchEvalReduction> = columns
            .iter()
            .map(|column| BatchEvalReduction {
                point: point.clone(),
                value: evaluate_slice(column, &point),
            })
            .collect();
        let col_refs: Vec<&[Block128]> = columns.iter().map(Vec::as_slice).collect();
        let committed = commit_auth_mle_columns(&col_refs, num_vars);
        let proof = open_auth_mle_columns_committed(&committed, num_vars, &reductions);
        assert!(verify_auth_mle_multi_opening(&proof, num_vars, &reductions));
    }

    #[test]
    fn auth_mle_multi_opening_rejects_wrong_value() {
        let num_vars = AUTH_PCS_BASE_LOG + 1;
        let columns: Vec<Vec<Block128>> = (0..3)
            .map(|c| {
                (0..(1usize << num_vars))
                    .map(|i| {
                        Block128::from(
                            (i as u128).wrapping_mul(9 + c as u128) ^ (0x5A5A + c as u128),
                        )
                    })
                    .collect()
            })
            .collect();
        let point: Vec<Block128> = (0..num_vars)
            .map(|i| Block128::from(0x4000u128 + i as u128))
            .collect();
        let reductions: Vec<BatchEvalReduction> = columns
            .iter()
            .map(|column| BatchEvalReduction {
                point: point.clone(),
                value: evaluate_slice(column, &point),
            })
            .collect();
        let col_refs: Vec<&[Block128]> = columns.iter().map(Vec::as_slice).collect();
        let committed = commit_auth_mle_columns(&col_refs, num_vars);
        let proof = open_auth_mle_columns_committed(&committed, num_vars, &reductions);

        let mut bad = reductions.clone();
        bad[2].value += Block128::ONE;
        assert!(!verify_auth_mle_multi_opening(&proof, num_vars, &bad));
    }
}
