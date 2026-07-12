// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native algebra for the future witness-hiding authorization capsule.
//!
//! This module fixes natural novel-coefficient order, LOW-to-HIGH MLE folds,
//! contiguous affine-code leaves, the Phase-B `upper` linkage, and query-index
//! conventions in executable form. It is deliberately disconnected from the
//! active proof, wire format, transcript, and verifier.

use noid_core::mle::evaluate::evaluate_slice;
use noid_core::mle::fold::fold_variable_inplace;
use noid_core::{Block128, TowerField};

use crate::zk_affine_code::{AffineHighPaddingRankCertificate, ZkAffineCodeError, ZkAffineLchCode};
use crate::zk_capsule::ZK_AUTH_CAPSULE_GEOMETRY;

pub const JOINT_SOURCE_BANK_SYMBOLS: usize = ZK_AUTH_CAPSULE_GEOMETRY.source_bank_symbols_per_leaf;
pub const JOINT_SOURCE_COMPANION_SYMBOLS: usize =
    ZK_AUTH_CAPSULE_GEOMETRY.source_companion_symbols_per_leaf;
pub const JOINT_SOURCE_LEAF_SYMBOLS: usize = ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_symbols;
pub const SOURCE_STANDARD_FOLDS: usize = ZK_AUTH_CAPSULE_GEOMETRY.source_standard_fold_log;
pub const MID_STANDARD_FOLDS: usize = ZK_AUTH_CAPSULE_GEOMETRY.second_wide_fold_log;
pub const OWNER_STATE_POINT_VARS: usize = ZK_AUTH_CAPSULE_GEOMETRY.state_vars;
pub const OWNER_BANK_POINT_VARS: usize = ZK_AUTH_CAPSULE_GEOMETRY.bank_log;
pub const OWNER_STATE_RELATION_LEN: usize = ZK_AUTH_CAPSULE_GEOMETRY.state_len;
pub const OWNER_BANK_RELATION_LEN: usize = ZK_AUTH_CAPSULE_GEOMETRY.bank_len;
pub const PHASE_B_LOW_VARS: usize =
    SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS + ZK_AUTH_CAPSULE_GEOMETRY.tail_local_fold_log;
pub const PHASE_B_HIGH_VARS: usize = OWNER_BANK_POINT_VARS - PHASE_B_LOW_VARS;
pub const UPPER_SYMBOLS: usize = 1 << PHASE_B_LOW_VARS;
pub const TAIL_SYMBOLS: usize = ZK_AUTH_CAPSULE_GEOMETRY.tail_len;
pub const FINAL_H_SYMBOLS: usize = ZK_AUTH_CAPSULE_GEOMETRY.final_h_len;
pub const SOURCE_QUERY_BITS: usize = ZK_AUTH_CAPSULE_GEOMETRY.query_width_bits;

const SOURCE_LOCAL_BITS: usize = SOURCE_STANDARD_FOLDS;
const MID_LOCAL_BITS: usize = MID_STANDARD_FOLDS;

const _: () = assert!(
    JOINT_SOURCE_BANK_SYMBOLS + JOINT_SOURCE_COMPANION_SYMBOLS == JOINT_SOURCE_LEAF_SYMBOLS
);
const _: () = assert!(JOINT_SOURCE_BANK_SYMBOLS == 1 << SOURCE_STANDARD_FOLDS);
const _: () = assert!(ZK_AUTH_CAPSULE_GEOMETRY.mid_leaf_symbols == 1 << MID_STANDARD_FOLDS);
const _: () = assert!(OWNER_BANK_POINT_VARS - OWNER_STATE_POINT_VARS == 2);
const _: () = assert!(PHASE_B_LOW_VARS == 8);
const _: () = assert!(PHASE_B_HIGH_VARS == 3);
const _: () = assert!(UPPER_SYMBOLS == 256);
const _: () = assert!(TAIL_SYMBOLS == 2 * FINAL_H_SYMBOLS);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkCapsuleAlgebraError {
    SourceLeafOutOfRange,
    MidLeafOutOfRange,
    SourceCodewordLengthMismatch,
    MidCodewordLengthMismatch,
    AffineCode(ZkAffineCodeError),
}

impl From<ZkAffineCodeError> for ZkCapsuleAlgebraError {
    fn from(value: ZkAffineCodeError) -> Self {
        Self::AffineCode(value)
    }
}

/// Native decomposition of one uniform 13-bit joint-source-leaf query.
///
/// Bit numbering is LSB-first. For source bits `s[0..13]`:
///
/// - source path directions are `s[0..8]`, source cap is `s[8..13]`;
/// - after three adjacent folds, the source leaf is the mid position;
/// - mid member bits are `s[0..4]` and mid leaf bits are `s[4..13]`;
/// - mid path is `s[4..12]`, mid cap is `s[12..13]`.
///
/// The path-direction union carries `s[0..12]`. One auxiliary cell carries
/// `s[12]`, selecting both caps. Power-of-two depth-eight paths expose their
/// roots from the final node rather than a spare root-copy tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkCapsuleQueryMapping {
    pub source_leaf_index: usize,
    pub source_bits_lsb: [bool; SOURCE_QUERY_BITS],
    pub source_path_index: usize,
    pub source_cap_index: usize,
    pub mid_position: usize,
    pub mid_leaf_index: usize,
    pub mid_member_index: usize,
    pub mid_path_index: usize,
    pub mid_cap_index: usize,
}

impl ZkCapsuleQueryMapping {
    /// Recompose the source leaf from its source-tree path and cap indices.
    #[inline]
    pub const fn source_tree_roundtrip(&self) -> usize {
        (self.source_cap_index << ZK_AUTH_CAPSULE_GEOMETRY.source_path_depth)
            | self.source_path_index
    }

    /// Recompose the mid leaf from its mid-tree path and cap indices.
    #[inline]
    pub const fn mid_tree_roundtrip(&self) -> usize {
        (self.mid_cap_index << ZK_AUTH_CAPSULE_GEOMETRY.mid_path_depth) | self.mid_path_index
    }

    /// Recompose the source leaf from the mid leaf and selected mid cell.
    #[inline]
    pub const fn source_from_mid_roundtrip(&self) -> usize {
        (self.mid_leaf_index << MID_LOCAL_BITS) | self.mid_member_index
    }
}

/// Interleave one bank coset and one companion coset in the mandatory
/// adjacent layout `[bank0, companion0, ..., bank7, companion7]`.
pub fn interleave_joint_source_leaf(
    bank: &[Block128; JOINT_SOURCE_BANK_SYMBOLS],
    companion: &[Block128; JOINT_SOURCE_COMPANION_SYMBOLS],
) -> [Block128; JOINT_SOURCE_LEAF_SYMBOLS] {
    std::array::from_fn(|slot| {
        let pair = slot / 2;
        if slot & 1 == 0 {
            bank[pair]
        } else {
            companion[pair]
        }
    })
}

/// The eight contiguous affine-code positions opened from each equal encoded
/// bank for one joint source leaf.
pub fn joint_source_leaf_positions(
    source_leaf_index: usize,
) -> Result<[usize; JOINT_SOURCE_BANK_SYMBOLS], ZkCapsuleAlgebraError> {
    let g = ZK_AUTH_CAPSULE_GEOMETRY;
    if source_leaf_index >= g.source_leaf_count {
        return Err(ZkCapsuleAlgebraError::SourceLeafOutOfRange);
    }
    let start = source_leaf_index << SOURCE_LOCAL_BITS;
    Ok(std::array::from_fn(|member| start | member))
}

/// Apply the affine encoder's structural hiding certificate to the actual
/// source-leaf query map. Repeated leaves are harmless: their eight codeword
/// positions are deduplicated before the rank is certified.
pub fn certify_source_query_hiding_rank(
    code: &ZkAffineLchCode,
    source_leaf_indices: &[usize],
) -> Result<AffineHighPaddingRankCertificate, ZkCapsuleAlgebraError> {
    let mut positions = Vec::with_capacity(source_leaf_indices.len() * JOINT_SOURCE_BANK_SYMBOLS);
    for &leaf in source_leaf_indices {
        positions.extend_from_slice(&joint_source_leaf_positions(leaf)?);
    }
    Ok(code.certify_high_padding_rank(&positions)?)
}

/// Materialize one adjacent joint leaf from the two equal affine codewords.
pub fn build_joint_source_leaf(
    bank_codeword: &[Block128],
    companion_codeword: &[Block128],
    source_leaf_index: usize,
) -> Result<[Block128; JOINT_SOURCE_LEAF_SYMBOLS], ZkCapsuleAlgebraError> {
    let g = ZK_AUTH_CAPSULE_GEOMETRY;
    if bank_codeword.len() != g.source_domain_len || companion_codeword.len() != g.source_domain_len
    {
        return Err(ZkCapsuleAlgebraError::SourceCodewordLengthMismatch);
    }
    let positions = joint_source_leaf_positions(source_leaf_index)?;
    let bank = std::array::from_fn(|member| bank_codeword[positions[member]]);
    let companion = std::array::from_fn(|member| companion_codeword[positions[member]]);
    Ok(interleave_joint_source_leaf(&bank, &companion))
}

/// Materialize one contiguous 16-symbol mid leaf.
pub fn build_mid_leaf(
    mid_codeword: &[Block128],
    mid_leaf_index: usize,
) -> Result<[Block128; 1 << MID_STANDARD_FOLDS], ZkCapsuleAlgebraError> {
    let g = ZK_AUTH_CAPSULE_GEOMETRY;
    if mid_codeword.len() != 1usize << g.mid_domain_log {
        return Err(ZkCapsuleAlgebraError::MidCodewordLengthMismatch);
    }
    if mid_leaf_index >= g.mid_leaf_count {
        return Err(ZkCapsuleAlgebraError::MidLeafOutOfRange);
    }
    let start = mid_leaf_index << MID_LOCAL_BITS;
    Ok(std::array::from_fn(|member| mid_codeword[start | member]))
}

/// Apply the characteristic-two masking line to all eight adjacent pairs.
///
/// `(1 - gamma) * bank + gamma * companion` is evaluated as
/// `bank + gamma * (bank + companion)`.
pub fn joint_source_line_fold(
    joint_leaf: &[Block128; JOINT_SOURCE_LEAF_SYMBOLS],
    gamma: Block128,
) -> [Block128; JOINT_SOURCE_BANK_SYMBOLS] {
    std::array::from_fn(|pair| {
        let bank = joint_leaf[2 * pair];
        let companion = joint_leaf[2 * pair + 1];
        bank + gamma * (bank + companion)
    })
}

/// Fold one contiguous source coset through the selected affine LCH schedule.
/// Challenges consume logical variables 0, 1, and 2 in that order.
pub fn source_standard_fold3(
    code: &ZkAffineLchCode,
    symbols: &[Block128; JOINT_SOURCE_BANK_SYMBOLS],
    source_leaf_index: usize,
    challenges: &[Block128; SOURCE_STANDARD_FOLDS],
) -> Result<Block128, ZkCapsuleAlgebraError> {
    if source_leaf_index >= ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_count {
        return Err(ZkCapsuleAlgebraError::SourceLeafOutOfRange);
    }
    Ok(code.fold_contiguous_coset(symbols, 0, source_leaf_index, challenges)?)
}

/// Apply the masking-line fold and then the three LOW-to-HIGH source folds.
pub fn fold_joint_source_leaf(
    code: &ZkAffineLchCode,
    joint_leaf: &[Block128; JOINT_SOURCE_LEAF_SYMBOLS],
    gamma: Block128,
    source_leaf_index: usize,
    challenges: &[Block128; SOURCE_STANDARD_FOLDS],
) -> Result<Block128, ZkCapsuleAlgebraError> {
    let virtual_masked = joint_source_line_fold(joint_leaf, gamma);
    source_standard_fold3(code, &virtual_masked, source_leaf_index, challenges)
}

/// Fold one contiguous mid coset through logical variables 3..6.
pub fn mid_standard_fold4(
    code: &ZkAffineLchCode,
    symbols: &[Block128; 1 << MID_STANDARD_FOLDS],
    mid_leaf_index: usize,
    challenges: &[Block128; MID_STANDARD_FOLDS],
) -> Result<Block128, ZkCapsuleAlgebraError> {
    if mid_leaf_index >= ZK_AUTH_CAPSULE_GEOMETRY.mid_leaf_count {
        return Err(ZkCapsuleAlgebraError::MidLeafOutOfRange);
    }
    Ok(code.fold_contiguous_coset(symbols, SOURCE_STANDARD_FOLDS, mid_leaf_index, challenges)?)
}

/// Re-encode the revealed 16-cell tail with the surviving prefix of the
/// master affine transform after seven LOW-to-HIGH folds.
pub fn encode_tail16(
    code: &ZkAffineLchCode,
    tail: &[Block128; TAIL_SYMBOLS],
) -> Result<Vec<Block128>, ZkCapsuleAlgebraError> {
    Ok(code.encode_after_low_folds(tail, SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS)?)
}

/// Fold logical variable 7 locally. Adjacent cells, not the two table halves,
/// are paired because the entire Phase-B order is LOW-to-HIGH.
pub fn tail16_local_fold(
    tail: &[Block128; TAIL_SYMBOLS],
    challenge: Block128,
) -> [Block128; FINAL_H_SYMBOLS] {
    std::array::from_fn(|index| {
        let at_zero = tail[2 * index];
        let at_one = tail[2 * index + 1];
        at_zero + challenge * (at_zero + at_one)
    })
}

/// Contract the three highest claim coordinates for each Boolean assignment
/// of the eight LOW Phase-B variables. The result is the public `upper[256]`.
pub fn contract_high3_for_each_low8(
    bank: &[Block128; OWNER_BANK_RELATION_LEN],
    high_point: &[Block128; PHASE_B_HIGH_VARS],
) -> [Block128; UPPER_SYMBOLS] {
    std::array::from_fn(|low_index| {
        let high_line: [Block128; 1 << PHASE_B_HIGH_VARS] =
            std::array::from_fn(|high_index| bank[low_index | (high_index << PHASE_B_LOW_VARS)]);
        evaluate_slice(&high_line, high_point)
    })
}

/// Evaluate `upper` at either the original low claim point or the random
/// Phase-B fold point.
pub fn evaluate_upper_at_low8(
    upper: &[Block128; UPPER_SYMBOLS],
    low_point: &[Block128; PHASE_B_LOW_VARS],
) -> Block128 {
    evaluate_slice(upper, low_point)
}

/// Fold all eight LOW variables of a bank table in protocol order. The result
/// is the 8-cell high-variable table linked to `upper(beta)`.
pub fn fold_bank_low8(
    bank: &[Block128; OWNER_BANK_RELATION_LEN],
    beta_low: &[Block128; PHASE_B_LOW_VARS],
) -> [Block128; FINAL_H_SYMBOLS] {
    let mut folded = bank.to_vec();
    for &challenge in beta_low {
        fold_variable_inplace(&mut folded, challenge, 0);
    }
    folded
        .try_into()
        .expect("eight low folds of a 2^11 table leave 2^3 cells")
}

/// Construct `r9 || [0, 0]` solely to check fundamental-slice alignment.
///
/// # Warning
///
/// The resulting bank evaluation selects the raw `[0, 512)` slice and must
/// never be serialized as an authorization opening claim. Protocol terminal
/// points remain arbitrary 11-variable challenges and use
/// [`evaluate_fundamental_slice_embedding`] instead.
pub fn fundamental_slice_alignment_point(
    state_point: &[Block128; OWNER_STATE_POINT_VARS],
) -> [Block128; OWNER_BANK_POINT_VARS] {
    let mut lifted = [Block128::ZERO; OWNER_BANK_POINT_VARS];
    lifted[..OWNER_STATE_POINT_VARS].copy_from_slice(state_point);
    lifted
}

/// Equality-selector weight of the two high Boolean coordinates `[0, 0]`.
pub fn eq_high_zero(high: &[Block128; 2]) -> Block128 {
    (Block128::ONE - high[0]) * (Block128::ONE - high[1])
}

/// Embed one 9-variable relation table into the high-`00` state slice of an
/// 11-variable table, with every other high slice identically zero.
pub fn fundamental_slice_relation_embedding(
    relation: &[Block128; OWNER_STATE_RELATION_LEN],
) -> [Block128; OWNER_BANK_RELATION_LEN] {
    let mut embedded = [Block128::ZERO; OWNER_BANK_RELATION_LEN];
    embedded[..OWNER_STATE_RELATION_LEN].copy_from_slice(relation);
    embedded
}

/// Evaluate the state-slice embedding at an arbitrary 11-variable terminal
/// point without replacing its two high challenges by zero.
pub fn evaluate_fundamental_slice_embedding(
    relation: &[Block128; OWNER_STATE_RELATION_LEN],
    terminal_point: &[Block128; OWNER_BANK_POINT_VARS],
) -> Block128 {
    let high_point = [
        terminal_point[OWNER_STATE_POINT_VARS],
        terminal_point[OWNER_STATE_POINT_VARS + 1],
    ];
    evaluate_slice(relation, &terminal_point[..OWNER_STATE_POINT_VARS]) * eq_high_zero(&high_point)
}

/// Convert a checked joint-source-leaf index to its LSB-first query bits.
pub fn source_query_bits(
    source_leaf_index: usize,
) -> Result<[bool; SOURCE_QUERY_BITS], ZkCapsuleAlgebraError> {
    if source_leaf_index >= ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_count {
        return Err(ZkCapsuleAlgebraError::SourceLeafOutOfRange);
    }
    Ok(std::array::from_fn(|bit| {
        (source_leaf_index >> bit) & 1 == 1
    }))
}

/// Recompose a joint source leaf from the complete LSB-first query bit set.
pub fn source_leaf_from_query_bits(bits: &[bool; SOURCE_QUERY_BITS]) -> usize {
    bits.iter().enumerate().fold(0usize, |index, (bit, set)| {
        index | (usize::from(*set) << bit)
    })
}

/// Map one uniform joint-source-leaf query into both authenticated trees.
pub fn map_source_query_leaf(
    source_leaf_index: usize,
) -> Result<ZkCapsuleQueryMapping, ZkCapsuleAlgebraError> {
    let g = ZK_AUTH_CAPSULE_GEOMETRY;
    let source_bits_lsb = source_query_bits(source_leaf_index)?;
    let source_path_index = source_leaf_index & ((1usize << g.source_path_depth) - 1);
    let source_cap_index = source_leaf_index >> g.source_path_depth;

    // Three adjacent folds collapse source leaf L directly to mid position L.
    let mid_position = source_leaf_index;
    let mid_leaf_index = mid_position >> MID_LOCAL_BITS;
    let mid_member_index = mid_position & ((1usize << MID_LOCAL_BITS) - 1);
    let mid_path_index = mid_leaf_index & ((1usize << g.mid_path_depth) - 1);
    let mid_cap_index = mid_leaf_index >> g.mid_path_depth;

    Ok(ZkCapsuleQueryMapping {
        source_leaf_index,
        source_bits_lsb,
        source_path_index,
        source_cap_index,
        mid_position,
        mid_leaf_index,
        mid_member_index,
        mid_path_index,
        mid_cap_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elem(index: usize, domain: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left((index % 127) as u32)
                ^ (index as u128 * 0x9E37_79B9),
        )
    }

    fn message(domain: u128) -> [Block128; OWNER_BANK_RELATION_LEN] {
        std::array::from_fn(|index| elem(index, domain))
    }

    #[test]
    fn joint_leaf_layout_and_contiguous_positions_are_exact() {
        let bank = std::array::from_fn(|i| elem(i, 0xB4A9));
        let companion = std::array::from_fn(|i| elem(i, 0xC09A));
        let joint = interleave_joint_source_leaf(&bank, &companion);
        for pair in 0..JOINT_SOURCE_BANK_SYMBOLS {
            assert_eq!(joint[2 * pair], bank[pair]);
            assert_eq!(joint[2 * pair + 1], companion[pair]);
        }

        for leaf in [
            0,
            1,
            255,
            256,
            ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_count - 1,
        ] {
            let positions = joint_source_leaf_positions(leaf).unwrap();
            assert_eq!(positions, std::array::from_fn(|member| 8 * leaf + member));
        }

        let code = ZkAffineLchCode::selected().unwrap();
        let leaves: Vec<usize> = (0..ZK_AUTH_CAPSULE_GEOMETRY.query_count()).collect();
        let certificate = certify_source_query_hiding_rank(&code, &leaves).unwrap();
        assert_eq!(certificate.distinct_query_count, 512);
        assert_eq!(certificate.certified_rank, 512);

        let repeated = [17usize; 64];
        let certificate = certify_source_query_hiding_rank(&code, &repeated).unwrap();
        assert_eq!(certificate.distinct_query_count, 8);
        assert_eq!(certificate.certified_rank, 8);
    }

    #[test]
    fn gamma_then_source_and_mid_folds_match_full_affine_codewords() {
        let code = ZkAffineLchCode::selected().unwrap();
        let bank = message(0xB4A9);
        let companion = message(0xC09A);
        let gamma = elem(3, 0x6A77A);
        let source_challenges = std::array::from_fn(|i| elem(i, 0x503CE));
        let mid_challenges = std::array::from_fn(|i| elem(i, 0xA11D));

        let bank_code = code.encode(&bank).unwrap();
        let companion_code = code.encode(&companion).unwrap();
        let virtual_message: Vec<Block128> = bank
            .iter()
            .zip(companion.iter())
            .map(|(&b, &c)| b + gamma * (b + c))
            .collect();
        let mut mid_code = code.encode(&virtual_message).unwrap();
        for (round, &challenge) in source_challenges.iter().enumerate() {
            mid_code = code
                .fold_codeword_once(&mid_code, round, challenge)
                .unwrap();
        }

        for source_leaf in [
            0,
            1,
            127,
            4_097,
            ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_count - 1,
        ] {
            let joint = build_joint_source_leaf(&bank_code, &companion_code, source_leaf).unwrap();
            assert_eq!(
                fold_joint_source_leaf(&code, &joint, gamma, source_leaf, &source_challenges,)
                    .unwrap(),
                mid_code[source_leaf]
            );
        }

        let mut tail_code = mid_code.clone();
        for (inner, &challenge) in mid_challenges.iter().enumerate() {
            tail_code = code
                .fold_codeword_once(&tail_code, SOURCE_STANDARD_FOLDS + inner, challenge)
                .unwrap();
        }
        for mid_leaf in [0, 1, 31, 255, ZK_AUTH_CAPSULE_GEOMETRY.mid_leaf_count - 1] {
            let leaf = build_mid_leaf(&mid_code, mid_leaf).unwrap();
            assert_eq!(
                mid_standard_fold4(&code, &leaf, mid_leaf, &mid_challenges).unwrap(),
                tail_code[mid_leaf]
            );
        }
    }

    #[test]
    fn phase_b_upper_and_tail_link_the_same_bank() {
        let code = ZkAffineLchCode::selected().unwrap();
        let bank = message(0xB411C);
        let claim_point: [Block128; OWNER_BANK_POINT_VARS] =
            std::array::from_fn(|i| elem(i, 0xC1A1));
        let low_point: [Block128; PHASE_B_LOW_VARS] = std::array::from_fn(|i| claim_point[i]);
        let high_point: [Block128; PHASE_B_HIGH_VARS] =
            std::array::from_fn(|i| claim_point[PHASE_B_LOW_VARS + i]);
        let beta: [Block128; PHASE_B_LOW_VARS] = std::array::from_fn(|i| elem(i, 0xBE7A));

        let upper = contract_high3_for_each_low8(&bank, &high_point);
        assert_eq!(
            evaluate_upper_at_low8(&upper, &low_point),
            evaluate_slice(&bank, &claim_point)
        );

        let h = fold_bank_low8(&bank, &beta);
        assert_eq!(
            evaluate_upper_at_low8(&upper, &beta),
            evaluate_slice(&h, &high_point)
        );

        let mut after_seven = bank.to_vec();
        for &challenge in &beta[..SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS] {
            fold_variable_inplace(&mut after_seven, challenge, 0);
        }
        let tail: [Block128; TAIL_SYMBOLS] = after_seven.try_into().unwrap();
        assert_eq!(tail16_local_fold(&tail, beta[7]), h);
        assert_eq!(encode_tail16(&code, &tail).unwrap().len(), 512);
    }

    #[test]
    fn fundamental_slice_embedding_uses_arbitrary_terminal_high_coordinates() {
        let relation = std::array::from_fn(|i| elem(i, 0xAE1A710));
        let embedded = fundamental_slice_relation_embedding(&relation);
        let terminal = std::array::from_fn(|i| elem(i + 17, 0x7E2A11));
        let low_point = std::array::from_fn(|i| terminal[i]);
        let alignment_point = fundamental_slice_alignment_point(&low_point);

        assert_eq!(
            evaluate_slice(&embedded, &alignment_point),
            evaluate_slice(&relation, &low_point)
        );
        assert_eq!(
            evaluate_slice(&embedded, &terminal),
            evaluate_fundamental_slice_embedding(&relation, &terminal)
        );
        assert_eq!(eq_high_zero(&[Block128::ZERO; 2]), Block128::ONE);
        assert_eq!(
            eq_high_zero(&[Block128::ONE, Block128::ZERO]),
            Block128::ZERO
        );
    }

    #[test]
    fn source_and_mid_query_mapping_roundtrips_exhaustively() {
        let g = ZK_AUTH_CAPSULE_GEOMETRY;
        assert_eq!(g.source_tree_depth, SOURCE_QUERY_BITS);
        assert_eq!(g.source_leaf_count, 1 << SOURCE_QUERY_BITS);

        for source_leaf in 0..g.source_leaf_count {
            let mapping = map_source_query_leaf(source_leaf).unwrap();
            assert_eq!(
                source_leaf_from_query_bits(&mapping.source_bits_lsb),
                source_leaf
            );
            assert_eq!(mapping.source_tree_roundtrip(), source_leaf);
            assert_eq!(mapping.mid_tree_roundtrip(), mapping.mid_leaf_index);
            assert_eq!(mapping.source_from_mid_roundtrip(), source_leaf);
            assert_eq!(mapping.mid_position, source_leaf);
            assert_eq!(mapping.mid_member_index, source_leaf & 15);
            assert_eq!(mapping.mid_leaf_index, source_leaf >> 4);
            assert_eq!(
                joint_source_leaf_positions(source_leaf).unwrap(),
                std::array::from_fn(|member| (source_leaf << SOURCE_LOCAL_BITS) | member)
            );
            assert_eq!(
                mapping.mid_position,
                (mapping.mid_leaf_index << MID_LOCAL_BITS) | mapping.mid_member_index
            );

            // Source path q0..q7; mid path q4..q11; auxiliary q12.
            for bit in 0..8 {
                assert_eq!(
                    (mapping.source_path_index >> bit) & 1,
                    (source_leaf >> bit) & 1
                );
                assert_eq!(
                    (mapping.mid_path_index >> bit) & 1,
                    (source_leaf >> (bit + 4)) & 1
                );
            }
            assert_eq!(mapping.source_cap_index, source_leaf >> 8);
            assert_eq!(mapping.mid_cap_index, source_leaf >> 12);
        }

        assert_eq!(
            map_source_query_leaf(g.source_leaf_count),
            Err(ZkCapsuleAlgebraError::SourceLeafOutOfRange)
        );
    }

    #[test]
    fn source_queries_lift_each_tail_code_coordinate_with_exact_uniform_density() {
        let g = ZK_AUTH_CAPSULE_GEOMETRY;
        let mut preimages = vec![0usize; g.mid_leaf_count];
        for source_leaf in 0..g.source_leaf_count {
            let mapping = map_source_query_leaf(source_leaf).unwrap();
            preimages[mapping.mid_leaf_index] += 1;
        }
        assert!(
            preimages
                .iter()
                .all(|&count| count == 1usize << MID_LOCAL_BITS),
            "q -> q>>4 must give every tail-code coordinate sixteen preimages"
        );

        // An arbitrary tail-code error set therefore lifts to exactly the same
        // relative density in the uniform source-query domain.
        let marked = (0..g.mid_leaf_count)
            .filter(|index| (index * 17 + 5) % 29 < 7)
            .collect::<std::collections::BTreeSet<_>>();
        let lifted = (0..g.source_leaf_count)
            .filter(|&source_leaf| {
                let tail_position = map_source_query_leaf(source_leaf).unwrap().mid_leaf_index;
                marked.contains(&tail_position)
            })
            .count();
        assert_eq!(lifted, marked.len() * (1usize << MID_LOCAL_BITS));
        assert_eq!(
            lifted * g.mid_leaf_count,
            marked.len() * g.source_leaf_count
        );
    }

    #[test]
    fn tail_local_fold_consumes_the_low_remaining_variable() {
        let tail = std::array::from_fn(|i| elem(i, 0x7A11));
        let challenge = elem(4, 0x10CA1);
        let got = tail16_local_fold(&tail, challenge);
        let expected =
            std::array::from_fn(|i| tail[2 * i] + challenge * (tail[2 * i] + tail[2 * i + 1]));

        assert_eq!(got, expected);
        assert_eq!(
            tail16_local_fold(&tail, Block128::ZERO),
            std::array::from_fn(|i| tail[2 * i])
        );
        assert_eq!(
            tail16_local_fold(&tail, Block128::ONE),
            std::array::from_fn(|i| tail[2 * i + 1])
        );
    }
}
