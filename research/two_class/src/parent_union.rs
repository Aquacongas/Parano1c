// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical m23/m24 parent-proof union layout.
//!
//! This module certifies the exact shape delta that a two-matrix HistoryStep
//! must absorb. It deliberately does not claim to be the complete parent
//! verifier: transcript replay, PCS equations and matrix-fold equations stay
//! in production primitives. The certificate prevents the implementation
//! from growing an accidental `current × parent` matrix bank while those
//! primitives are made shape-polymorphic.

use noid_ivc_core::pcs::{
    compute_fri_arities, default_fri_queries, fri_commit_layout, PcsParams, LOG_PACKING,
};

#[cfg(test)]
use crate::circuit_support::{mul, pin_zero, FieldR1csBuilder, LinExpr, F128};

pub const B128_OUTER_M: usize = 23;
pub const B256_OUTER_M: usize = 24;
pub const HISTORY_K_SKIP: usize = 6;
pub const HISTORY_PCS_LOG_INV_RATE: usize = 2;
pub const HISTORY_PCS_LOG_BATCH_SIZE: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParentProofClass {
    B128,
    B256,
}

impl ParentProofClass {
    pub const fn outer_m(self) -> usize {
        match self {
            Self::B128 => B128_OUTER_M,
            Self::B256 => B256_OUTER_M,
        }
    }

    pub const fn is_m24(self) -> bool {
        matches!(self, Self::B256)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentProofGeometry {
    pub class: ParentProofClass,
    pub outer_m: usize,
    pub zerocheck_multilinear_rounds: usize,
    pub lincheck_rounds: usize,
    pub pcs_rounds: usize,
    pub pcs_log_dim: usize,
    pub pcs_k_code: usize,
    pub fri_arities: Vec<usize>,
    pub fri_commitments: usize,
    pub plaintext_tail_fields: usize,
    pub fri_queries: usize,
    pub region_query_leaf_fields: usize,
    pub matrix_fold_phase1_rounds: usize,
    pub matrix_fold_phase2_rounds: usize,
    pub path_free_proof_fields: usize,
}

impl ParentProofGeometry {
    pub fn canonical(class: ParentProofClass) -> Self {
        let outer_m = class.outer_m();
        let params = PcsParams {
            m: outer_m + LOG_PACKING,
            log_inv_rate: HISTORY_PCS_LOG_INV_RATE,
            log_batch_size: HISTORY_PCS_LOG_BATCH_SIZE,
            profile: Default::default(),
        };
        let pcs_log_dim = params.log_dim();
        let pcs_k_code = params.k_code();
        let fri_arities = compute_fri_arities(pcs_log_dim);
        let (fri_commitments, tail_layout) = fri_commit_layout(pcs_k_code, &fri_arities);
        let plaintext_tail_fields = tail_layout.map_or(0, |(len, _)| len);
        let fri_queries = default_fri_queries(pcs_log_dim, params.log_inv_rate);

        // HistoryStep allocates predecessor Merkle paths into the shared [R]
        // sidecar, not into the main proof trace. Per query the path-free
        // payload is: 32 initial lanes, 16 post-row-batch lanes and one
        // 16-lane leaf for each committed epoch.
        let region_query_leaf_fields = (1usize << params.log_batch_size)
            + (1usize << fri_arities.first().copied().unwrap_or(0))
            + fri_arities
                .iter()
                .skip(1)
                .take(fri_commitments)
                .map(|&arity| 1usize << arity)
                .sum::<usize>();

        let zerocheck_fields = 2 * (1usize << HISTORY_K_SKIP) + 2 * (outer_m - HISTORY_K_SKIP) + 3;
        let lincheck_fields = 2 * (outer_m - HISTORY_K_SKIP) + (1usize << HISTORY_K_SKIP);
        let pcs_fields = 2 * outer_m
            + 2 // post-row-batch commitment digest
            + 2 * fri_commitments
            + 2 // final_a/final_b
            + (1usize << params.log_inv_rate)
            + plaintext_tail_fields
            + 1 // PoW nonce lane
            + fri_queries * region_query_leaf_fields;
        let matrix_fold_fields = 2 * (outer_m + 1) + 2 + 2 * outer_m + 1;

        Self {
            class,
            outer_m,
            zerocheck_multilinear_rounds: outer_m - HISTORY_K_SKIP,
            lincheck_rounds: outer_m - HISTORY_K_SKIP,
            pcs_rounds: outer_m,
            pcs_log_dim,
            pcs_k_code,
            fri_arities,
            fri_commitments,
            plaintext_tail_fields,
            fri_queries,
            region_query_leaf_fields,
            matrix_fold_phase1_rounds: outer_m + 1,
            matrix_fold_phase2_rounds: outer_m,
            path_free_proof_fields: zerocheck_fields
                + lincheck_fields
                + pcs_fields
                + matrix_fold_fields,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentUnionLayout {
    pub b128: ParentProofGeometry,
    pub b256: ParentProofGeometry,
    /// Maximum-shape payload cells that are absent from canonical m23.
    pub inactive_m23_suffix_fields: usize,
}

impl ParentUnionLayout {
    pub fn canonical() -> Self {
        let b128 = ParentProofGeometry::canonical(ParentProofClass::B128);
        let b256 = ParentProofGeometry::canonical(ParentProofClass::B256);
        assert_eq!(b128.fri_queries, b256.fri_queries);
        assert_eq!(b128.fri_commitments, b256.fri_commitments);
        assert_eq!(b128.region_query_leaf_fields, b256.region_query_leaf_fields);
        let inactive_m23_suffix_fields = b256
            .path_free_proof_fields
            .checked_sub(b128.path_free_proof_fields)
            .expect("m24 parent payload contains m23");
        Self {
            b128,
            b256,
            inactive_m23_suffix_fields,
        }
    }
}

/// Build the canonical inactive-suffix relation used by the future union
/// verifier. The maximum m24 payload is always allocated. For an m23 parent,
/// every shape-only suffix cell is constrained to zero.
#[cfg(test)]
fn build_suffix_relation(
    class: ParentProofClass,
    corrupt_first_inactive: bool,
) -> (noid_ivc_core::field_r1cs::FieldR1cs, Vec<F128>) {
    let layout = ParentUnionLayout::canonical();
    let mut builder = FieldR1csBuilder::new();
    let parent_is_m24 = LinExpr::from_wire(builder.alloc_bool(class.is_m24()));
    let parent_is_m23 = parent_is_m24.add_const(F128::ONE);

    for index in 0..layout.inactive_m23_suffix_fields {
        let live_value = if class.is_m24() {
            F128::new(index as u64 + 1, 0)
        } else if corrupt_first_inactive && index == 0 {
            F128::ONE
        } else {
            F128::ZERO
        };
        let cell = LinExpr::from_wire(builder.alloc_f128(live_value));
        let inactive_residual = mul(&mut builder, &parent_is_m23, &cell);
        pin_zero(&mut builder, &inactive_residual);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_shapes_have_one_canonical_union_delta() {
        let layout = ParentUnionLayout::canonical();
        assert_eq!(layout.b128.fri_arities, [4, 4, 4, 4, 2]);
        assert_eq!(layout.b256.fri_arities, [4, 4, 4, 4, 3]);
        assert_eq!(layout.b128.fri_commitments, 2);
        assert_eq!(layout.b256.fri_commitments, 2);
        assert_eq!(layout.b128.plaintext_tail_fields, 256);
        assert_eq!(layout.b256.plaintext_tail_fields, 512);
        assert_eq!(layout.b128.region_query_leaf_fields, 80);
        assert_eq!(layout.b256.region_query_leaf_fields, 80);
        assert_eq!(layout.inactive_m23_suffix_fields, 266);
    }

    #[test]
    fn parent_class_changes_witness_not_suffix_matrix() {
        let (m23_matrix, m23_witness) = build_suffix_relation(ParentProofClass::B128, false);
        let (m24_matrix, m24_witness) = build_suffix_relation(ParentProofClass::B256, false);
        assert!(m23_matrix.satisfies(&m23_witness));
        assert!(m24_matrix.satisfies(&m24_witness));
        assert_eq!(m23_matrix.useful_rows, m24_matrix.useful_rows);
        assert_eq!(
            m23_matrix.structural_statement_digest(),
            m24_matrix.structural_statement_digest()
        );

        let (_, corrupt_m23) = build_suffix_relation(ParentProofClass::B128, true);
        assert!(!m23_matrix.satisfies(&corrupt_m23));
    }
}
