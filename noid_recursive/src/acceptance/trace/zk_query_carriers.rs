// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Disconnected recursive query-carrier gate for the selected ZK capsule.
//!
//! The selected source and mid Merkle families both have depth-eight live
//! direction columns.  For every one of the 64 packed 13-bit queries:
//!
//! - source `D[0]` through `D[7]` carry `q0` through `q7`;
//! - mid `D[0]` through `D[7]` carry `q4` through `q11`;
//! - one separately boolean auxiliary cell carries `q12` and is the cap
//!   selector for both families.
//!
//! Thus `q4` through `q7` have two physical path carriers and need four exact copy
//! pins per query.  The transcript binding consumes source `q0..q7`, mid
//! `q8..q11`, and the auxiliary `q12` directly through
//! [`packed_queries_from_seeds_with_bound_bits_for_count`].  Path-direction
//! booleanity belongs to the two FF-Merkle families and is deliberately not
//! charged again here.

use noid_fri_binius::capsule::{capsule_query_bit_location, CAPSULE_QUERY_SEED_BITS};
use noid_fri_binius::zk_capsule::ZK_AUTH_CAPSULE_GEOMETRY;

use super::fri_pcs::{expr_tower_value, packed_queries_from_seeds_with_bound_bits_for_count};
use super::{pin_eq, FieldR1csBuilder, LinExpr};

/// Fixed mainnet query count of the selected capsule geometry.
pub const ZK_QUERY_COUNT: usize = ZK_AUTH_CAPSULE_GEOMETRY.query_count;
/// Source-leaf position width (`log2(8192)`).
pub const ZK_QUERY_WIDTH_BITS: usize = ZK_AUTH_CAPSULE_GEOMETRY.query_width_bits;
/// Number of 128-bit transcript squeezes carrying all query bits.
pub const ZK_QUERY_SEED_COUNT: usize = ZK_AUTH_CAPSULE_GEOMETRY.query_seed_count;
/// Live direction cells in each selected FF-Merkle path.
pub const ZK_PATH_DIRECTION_BITS: usize = ZK_AUTH_CAPSULE_GEOMETRY.source_path_depth;
/// First query bit hosted by the mid direction family.
pub const ZK_MID_QUERY_BIT_START: usize = 4;
/// Query bit hosted by the separately allocated cap selector.
pub const ZK_CAP_QUERY_BIT: usize = 12;
/// Number of physically duplicated source/mid direction bits per query.
pub const ZK_DUPLICATE_BITS_PER_QUERY: usize = 4;

/// Packed seed capacity not consumed by 64 consecutive 13-bit query words.
pub const ZK_UNUSED_PACKED_SEED_BITS: usize =
    ZK_QUERY_SEED_COUNT * CAPSULE_QUERY_SEED_BITS - ZK_QUERY_COUNT * ZK_QUERY_WIDTH_BITS;

/// Incremental rows for the one auxiliary cap-selector boolean per query.
pub const ZK_AUX_BOOLEAN_ROWS: usize = ZK_QUERY_COUNT;
/// Incremental rows for unused packed-seed bits, which still need exact seed
/// recomposition and therefore remain separately allocated booleans.
pub const ZK_UNUSED_SEED_BOOLEAN_ROWS: usize = ZK_UNUSED_PACKED_SEED_BITS;
/// Incremental rows joining the four duplicated source/mid D cells.
pub const ZK_DUPLICATE_EQUALITY_ROWS: usize = ZK_QUERY_COUNT * ZK_DUPLICATE_BITS_PER_QUERY;
/// One exact 128-bit recomposition pin per packed transcript seed.
pub const ZK_SEED_RECOMPOSITION_ROWS: usize = ZK_QUERY_SEED_COUNT;
/// Total incremental carrier-gate cost; pre-existing path D cells are not
/// included because their FF families already allocate and prove them boolean.
pub const ZK_QUERY_CARRIER_ROWS: usize = ZK_AUX_BOOLEAN_ROWS
    + ZK_UNUSED_SEED_BOOLEAN_ROWS
    + ZK_DUPLICATE_EQUALITY_ROWS
    + ZK_SEED_RECOMPOSITION_ROWS;

/// Previous 64-query, 14-bit carrier paid one duplicated D equality per query
/// and seven recomposition pins, with no auxiliary or unused seed bits.
pub const PREVIOUS_QUERY_CARRIER_ROWS: usize = ZK_QUERY_COUNT + ZK_QUERY_SEED_COUNT;
/// Exact incremental delta of the selected carrier against that old geometry.
pub const ZK_QUERY_CARRIER_ROWS_OVER_PREVIOUS: usize =
    ZK_QUERY_CARRIER_ROWS - PREVIOUS_QUERY_CARRIER_ROWS;

const _: () = assert!(ZK_QUERY_COUNT == 64);
const _: () = assert!(ZK_QUERY_WIDTH_BITS == 13);
const _: () = assert!(ZK_QUERY_SEED_COUNT == 7);
const _: () = assert!(ZK_PATH_DIRECTION_BITS == 8);
const _: () = assert!(ZK_AUTH_CAPSULE_GEOMETRY.mid_path_depth == ZK_PATH_DIRECTION_BITS);
const _: () = assert!(ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_count == 1 << ZK_QUERY_WIDTH_BITS);
const _: () = assert!(ZK_CAP_QUERY_BIT + 1 == ZK_QUERY_WIDTH_BITS);
const _: () = assert!(ZK_UNUSED_PACKED_SEED_BITS == 64);

/// Query expressions and cap selectors returned by
/// [`bind_zk_capsule_query_carriers`].
#[derive(Clone, Debug)]
pub struct BoundZkCapsuleQueries {
    /// Native packed query indices, each strictly below `2^13`.
    pub indices: Vec<usize>,
    /// Transcript-bound query bits, `[query][bit]`, LSB first.
    pub bits: Vec<Vec<LinExpr>>,
    /// Five source-cap selector bits `q8..q12`. Bits `q8..q11` alias the
    /// high half of the mid D carrier and `q12` aliases the auxiliary cell.
    pub source_cap_bits: Vec<Vec<LinExpr>>,
    /// The one-bit mid-cap selectors `q12`, aliasing exactly the same
    /// auxiliary expressions used as the last source-cap bit.
    pub mid_cap_selectors: Vec<LinExpr>,
}

/// Bind the selected source/mid query carriers to seven packed transcript
/// seeds.
///
/// `source_d[q][i]` must be the separately booleanity-proven source path
/// direction `q_i`; `mid_d[q][i]` must be the mid direction `q_(4+i)`.
/// Both matrices are exact `64 × 8` shapes. The gate allocates only `q12`,
/// uses it for both cap families, reuses all 832 live query bits in the packed
/// seed decomposition, and pins the four duplicated D pairs per query.
pub fn bind_zk_capsule_query_carriers(
    b: &mut FieldR1csBuilder,
    seeds: &[LinExpr],
    source_d: &[Vec<LinExpr>],
    mid_d: &[Vec<LinExpr>],
) -> BoundZkCapsuleQueries {
    assert_eq!(seeds.len(), ZK_QUERY_SEED_COUNT, "ZK query seed count");
    assert_eq!(source_d.len(), ZK_QUERY_COUNT, "source query count");
    assert_eq!(mid_d.len(), ZK_QUERY_COUNT, "mid query count");
    assert!(
        source_d
            .iter()
            .all(|directions| directions.len() == ZK_PATH_DIRECTION_BITS),
        "source direction depth"
    );
    assert!(
        mid_d
            .iter()
            .all(|directions| directions.len() == ZK_PATH_DIRECTION_BITS),
        "mid direction depth"
    );

    // q12 is already one concrete bit in the packed seed stream. Allocate it
    // once, then reuse the same expression for both cap families.
    let cap_selectors = (0..ZK_QUERY_COUNT)
        .map(|query| {
            let (seed, bit) =
                capsule_query_bit_location(query, ZK_CAP_QUERY_BIT, ZK_QUERY_WIDTH_BITS);
            let value = (expr_tower_value(b, &seeds[seed]).0 >> bit) & 1 == 1;
            LinExpr::from_wire(b.alloc_bool(value))
        })
        .collect::<Vec<_>>();

    let bound = (0..ZK_QUERY_COUNT)
        .map(|query| {
            (0..ZK_QUERY_WIDTH_BITS)
                .map(|query_bit| match query_bit {
                    0..=7 => Some(source_d[query][query_bit].clone()),
                    8..=11 => Some(mid_d[query][query_bit - ZK_MID_QUERY_BIT_START].clone()),
                    ZK_CAP_QUERY_BIT => Some(cap_selectors[query].clone()),
                    _ => unreachable!("selected capsule has exactly thirteen query bits"),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let (indices, bits) = packed_queries_from_seeds_with_bound_bits_for_count(
        b,
        seeds,
        ZK_QUERY_COUNT,
        ZK_QUERY_WIDTH_BITS,
        Some(&bound),
    );

    // q4..q7 physically drive both paths. Bind the mid copies to the source
    // expressions that were consumed by seed recomposition.
    for query in 0..ZK_QUERY_COUNT {
        for duplicate in 0..ZK_DUPLICATE_BITS_PER_QUERY {
            pin_eq(
                b,
                &source_d[query][ZK_MID_QUERY_BIT_START + duplicate],
                &mid_d[query][duplicate],
            );
        }
    }

    let source_cap_bits = bits
        .iter()
        .map(|query_bits| query_bits[8..=ZK_CAP_QUERY_BIT].to_vec())
        .collect();
    BoundZkCapsuleQueries {
        indices,
        bits,
        source_cap_bits,
        mid_cap_selectors: cap_selectors,
    }
}

#[cfg(test)]
mod tests {
    use super::super::alloc_blocks;
    use super::*;
    use noid_core::Block128;
    use noid_ivc_core::field::F128;

    fn seeds(salt: u128) -> Vec<Block128> {
        (0..ZK_QUERY_SEED_COUNT)
            .map(|i| {
                Block128::from(
                    salt.rotate_left((i * 17) as u32)
                        ^ 0x9E37_79B9_7F4A_7C15u128.wrapping_mul(i as u128 + 1),
                )
            })
            .collect()
    }

    fn native_queries(seeds: &[Block128]) -> Vec<usize> {
        (0..ZK_QUERY_COUNT)
            .map(|query| {
                (0..ZK_QUERY_WIDTH_BITS).fold(0usize, |index, query_bit| {
                    let (seed, bit) =
                        capsule_query_bit_location(query, query_bit, ZK_QUERY_WIDTH_BITS);
                    index | ((((seeds[seed].0 >> bit) & 1) as usize) << query_bit)
                })
            })
            .collect()
    }

    fn alloc_path_directions(
        b: &mut FieldR1csBuilder,
        queries: &[usize],
        first_query_bit: usize,
    ) -> Vec<Vec<LinExpr>> {
        queries
            .iter()
            .map(|&query| {
                (0..ZK_PATH_DIRECTION_BITS)
                    .map(|bit| {
                        LinExpr::from_wire(
                            b.alloc_bool((query >> (first_query_bit + bit)) & 1 == 1),
                        )
                    })
                    .collect()
            })
            .collect()
    }

    fn wire(expr: &LinExpr) -> usize {
        assert_eq!(expr.terms.len(), 1);
        assert_eq!(expr.terms[0].1, F128::ONE);
        assert_eq!(expr.constant, F128::ZERO);
        expr.terms[0].0 as usize
    }

    struct Fixture {
        builder: FieldR1csBuilder,
        expected: Vec<usize>,
        source: Vec<Vec<LinExpr>>,
        mid: Vec<Vec<LinExpr>>,
        bound: BoundZkCapsuleQueries,
        gate_rows: usize,
    }

    fn fixture(salt: u128) -> Fixture {
        let native_seeds = seeds(salt);
        let expected = native_queries(&native_seeds);
        let mut builder = FieldR1csBuilder::new();
        let seed_wires = alloc_blocks(&mut builder, &native_seeds);
        // These model D cells already allocated and booleanity-proven by the
        // two FF path families; their rows are outside this gate's ledger.
        let source = alloc_path_directions(&mut builder, &expected, 0);
        let mid = alloc_path_directions(&mut builder, &expected, ZK_MID_QUERY_BIT_START);
        let before = builder.num_wires();
        let bound = bind_zk_capsule_query_carriers(&mut builder, &seed_wires, &source, &mid);
        let gate_rows = builder.num_wires() - before;
        Fixture {
            builder,
            expected,
            source,
            mid,
            bound,
            gate_rows,
        }
    }

    #[test]
    fn selected_carriers_bind_honestly_and_map_every_query_bit() {
        let f = fixture(0xD15C_A11E_CAFE_BABEu128);
        assert_eq!(f.bound.indices, f.expected);
        assert!(f.bound.indices.iter().all(|&index| index < 1 << 13));
        assert_eq!(f.bound.bits.len(), ZK_QUERY_COUNT);

        for query in 0..ZK_QUERY_COUNT {
            assert_eq!(f.bound.bits[query].len(), ZK_QUERY_WIDTH_BITS);
            for bit in 0..ZK_QUERY_WIDTH_BITS {
                let actual = f.bound.bits[query][bit].eval(f.builder.values()) != F128::ZERO;
                assert_eq!(actual, (f.expected[query] >> bit) & 1 == 1);
            }
            for bit in 0..8 {
                assert_eq!(f.bound.bits[query][bit], f.source[query][bit]);
            }
            for duplicate in 0..ZK_DUPLICATE_BITS_PER_QUERY {
                assert_eq!(
                    f.source[query][ZK_MID_QUERY_BIT_START + duplicate].eval(f.builder.values()),
                    f.mid[query][duplicate].eval(f.builder.values())
                );
            }
            for bit in 8..12 {
                assert_eq!(
                    f.bound.bits[query][bit],
                    f.mid[query][bit - ZK_MID_QUERY_BIT_START]
                );
            }
            assert_eq!(
                f.bound.source_cap_bits[query],
                f.bound.bits[query][8..=ZK_CAP_QUERY_BIT]
            );
            assert_eq!(
                f.bound.source_cap_bits[query][4],
                f.bound.mid_cap_selectors[query]
            );
            assert_eq!(
                f.bound.bits[query][ZK_CAP_QUERY_BIT],
                f.bound.mid_cap_selectors[query]
            );
        }

        let (r1cs, witness) = f.builder.build();
        assert!(r1cs.satisfies(&witness));
    }

    #[test]
    fn selected_carrier_gate_has_the_exact_bounded_row_ledger() {
        let f = fixture(0xA55A_5AA5_1234_5678u128);
        assert_eq!(ZK_AUX_BOOLEAN_ROWS, 64);
        assert_eq!(ZK_UNUSED_SEED_BOOLEAN_ROWS, 64);
        assert_eq!(ZK_DUPLICATE_EQUALITY_ROWS, 256);
        assert_eq!(ZK_SEED_RECOMPOSITION_ROWS, 7);
        assert_eq!(ZK_QUERY_CARRIER_ROWS, 391);
        assert_eq!(f.gate_rows, ZK_QUERY_CARRIER_ROWS);

        assert_eq!(PREVIOUS_QUERY_CARRIER_ROWS, 71);
        assert_eq!(ZK_QUERY_CARRIER_ROWS_OVER_PREVIOUS, 320);
    }

    #[test]
    fn transcript_primary_duplicate_and_aux_tampering_all_reject() {
        let f = fixture(0xF00D_CAFE_55AA_33CCu128);
        let primary = wire(&f.source[3][2]);
        let duplicate = wire(&f.mid[5][0]);
        let high_mid = wire(&f.mid[11][7]);
        let aux = wire(&f.bound.mid_cap_selectors[17]);
        let (r1cs, witness) = f.builder.build();
        assert!(r1cs.satisfies(&witness));

        for (name, target) in [
            ("source transcript primary", primary),
            ("mid q4 duplicate", duplicate),
            ("mid q11 transcript primary", high_mid),
            ("shared q12 cap selector", aux),
        ] {
            let mut bad = witness.clone();
            bad[target] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "{name} mutation was accepted");
        }
    }

    #[test]
    fn carrier_matrix_shape_is_content_invariant() {
        let left = fixture(0x1111_2222_3333_4444u128);
        let right = fixture(0xAAAA_BBBB_CCCC_DDDDu128);
        let (left_r1cs, left_witness) = left.builder.build();
        let (right_r1cs, right_witness) = right.builder.build();
        assert!(left_r1cs.satisfies(&left_witness));
        assert!(right_r1cs.satisfies(&right_witness));
        assert_eq!(left_r1cs.statement_digest(), right_r1cs.statement_digest());
    }
}
