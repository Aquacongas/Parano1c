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

use noid_core::mle::split::{reconstruct_from_slices, split_mle_into_slices};
use noid_core::transcript::FiatShamir;
use noid_core::{AdditiveNTT, Block128};
use noid_fri::Channel;
use noid_fri_binius::{
    absorb_cap, interleaved_commit, prove_mixed_opening, verify_mixed_opening,
    InterleavedCommitment, InterleavedProverState, MixedOpeningProof, COMPACT_NUM_QUERIES,
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
        self.commitment.cap.hashes.len() * 32 + self.opening.byte_len()
    }
}

pub struct AuthMleCommittedColumn {
    pub commitment: InterleavedCommitment,
    slices: Vec<Vec<Block128>>,
}

impl Drop for AuthMleCommittedColumn {
    fn drop(&mut self) {
        self.slices.zeroize();
    }
}

pub struct AuthMleCommittedColumns {
    pub commitment: InterleavedCommitment,
    logical_columns: usize,
    slices_per_column: usize,
    slices: Vec<Vec<Block128>>,
}

impl Drop for AuthMleCommittedColumns {
    fn drop(&mut self) {
        self.slices.zeroize();
    }
}

/// Commit one private AuthGKR MLE column before any AuthGKR challenge is drawn.
pub fn commit_auth_mle_column(column: &[Block128], num_vars: usize) -> AuthMleCommittedColumn {
    assert_eq!(column.len(), 1usize << num_vars);
    assert!(num_vars >= AUTH_PCS_BASE_LOG);

    let slices = split_mle_into_slices(column, num_vars, AUTH_PCS_BASE_LOG);
    let expected_slices = 1usize << (num_vars - AUTH_PCS_BASE_LOG);
    assert_eq!(slices.len(), expected_slices);

    let col_refs: Vec<&[Block128]> = slices.iter().map(Vec::as_slice).collect();
    let ntt = AdditiveNTT::<Block128>::new(AUTH_PCS_BASE_LOG + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let (commitment, _) = interleaved_commit(&col_refs, &ntt, &hasher);
    AuthMleCommittedColumn { commitment, slices }
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
    let expected_slices = 1usize << (num_vars - AUTH_PCS_BASE_LOG);
    let mut slices = Vec::with_capacity(columns.len() * expected_slices);
    for column in columns {
        assert_eq!(column.len(), expected_len);
        let mut col_slices = split_mle_into_slices(column, num_vars, AUTH_PCS_BASE_LOG);
        assert_eq!(col_slices.len(), expected_slices);
        slices.append(&mut col_slices);
    }

    let col_refs: Vec<&[Block128]> = slices.iter().map(Vec::as_slice).collect();
    let ntt = AdditiveNTT::<Block128>::new(AUTH_PCS_BASE_LOG + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let (commitment, _) = interleaved_commit(&col_refs, &ntt, &hasher);
    AuthMleCommittedColumns {
        commitment,
        logical_columns: columns.len(),
        slices_per_column: expected_slices,
        slices,
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
    let expected_slices = 1usize << (num_vars - AUTH_PCS_BASE_LOG);
    assert_eq!(committed.commitment.log_rows, AUTH_PCS_BASE_LOG);
    assert_eq!(committed.commitment.n_cols, expected_slices);

    let ntt = AdditiveNTT::<Block128>::new(AUTH_PCS_BASE_LOG + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let raw_cols: Vec<&[Block128]> = committed.slices.iter().map(Vec::as_slice).collect();
    let prover_state = InterleavedProverState {
        raw_cols,
        log_rows: committed.commitment.log_rows,
        n_cols: committed.commitment.n_cols,
    };
    let primary_point = reduction.point[..AUTH_PCS_BASE_LOG].to_vec();
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

    debug_assert!(opening.all_openings.len() >= expected_slices);
    debug_assert_eq!(
        reconstruct_from_slices(
            &opening.all_openings[..expected_slices],
            &reduction.point[AUTH_PCS_BASE_LOG..],
        ),
        reduction.value
    );

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
    let expected_slices = 1usize << (num_vars - AUTH_PCS_BASE_LOG);
    assert_eq!(committed.slices_per_column, expected_slices);
    assert_eq!(committed.commitment.log_rows, AUTH_PCS_BASE_LOG);
    assert_eq!(
        committed.commitment.n_cols,
        reductions.len() * expected_slices
    );
    for reduction in reductions {
        assert_eq!(reduction.point.len(), num_vars);
        assert_eq!(reduction.point, reductions[0].point);
    }

    let ntt = AdditiveNTT::<Block128>::new(AUTH_PCS_BASE_LOG + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let raw_cols: Vec<&[Block128]> = committed.slices.iter().map(Vec::as_slice).collect();
    let prover_state = InterleavedProverState {
        raw_cols,
        log_rows: committed.commitment.log_rows,
        n_cols: committed.commitment.n_cols,
    };
    let primary_point = reductions[0].point[..AUTH_PCS_BASE_LOG].to_vec();
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

    for (col_idx, reduction) in reductions.iter().enumerate() {
        let start = col_idx * expected_slices;
        let end = start + expected_slices;
        debug_assert_eq!(
            reconstruct_from_slices(
                &opening.all_openings[start..end],
                &reduction.point[AUTH_PCS_BASE_LOG..],
            ),
            reduction.value
        );
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
    let expected_slices = 1usize << (num_vars - AUTH_PCS_BASE_LOG);
    if proof.commitment.log_rows != AUTH_PCS_BASE_LOG || proof.commitment.n_cols != expected_slices
    {
        return false;
    }

    let primary_point = reduction.point[..AUTH_PCS_BASE_LOG].to_vec();
    let ntt = AdditiveNTT::<Block128>::new(AUTH_PCS_BASE_LOG + noid_fri::code::LOG_RATE);
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
    if openings.len() < expected_slices {
        return false;
    }

    reconstruct_from_slices(
        &openings[..expected_slices],
        &reduction.point[AUTH_PCS_BASE_LOG..],
    ) == reduction.value
}

pub fn verify_auth_mle_multi_opening(
    proof: &AuthMleMultiOpeningProof,
    num_vars: usize,
    reductions: &[BatchEvalReduction],
) -> bool {
    if num_vars < AUTH_PCS_BASE_LOG || reductions.is_empty() {
        return false;
    }
    let expected_slices = 1usize << (num_vars - AUTH_PCS_BASE_LOG);
    if proof.commitment.log_rows != AUTH_PCS_BASE_LOG
        || proof.commitment.n_cols != reductions.len() * expected_slices
    {
        return false;
    }
    for reduction in reductions {
        if reduction.point.len() != num_vars || reduction.point != reductions[0].point {
            return false;
        }
    }

    let primary_point = reductions[0].point[..AUTH_PCS_BASE_LOG].to_vec();
    let ntt = AdditiveNTT::<Block128>::new(AUTH_PCS_BASE_LOG + noid_fri::code::LOG_RATE);
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
    if openings.len() < reductions.len() * expected_slices {
        return false;
    }

    for (col_idx, reduction) in reductions.iter().enumerate() {
        let start = col_idx * expected_slices;
        let end = start + expected_slices;
        if reconstruct_from_slices(&openings[start..end], &reduction.point[AUTH_PCS_BASE_LOG..])
            != reduction.value
        {
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
