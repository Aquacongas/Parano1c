// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shape-only A128 prototype for transposed capsule-leaf hashing.
//!
//! The production Wallet-A region currently stores every nine-permutation
//! capsule leaf in a sixteen-slot tile.  This prototype transposes the leaf
//! chains: round `r` of every leaf occupies one dyadic `2^14` slice, so no
//! seven-slot tail is paid per leaf.  It deliberately stops before the block
//! sidecar/VK/freezer boundary.  The eventual sidecar must authenticate all
//! 54 slices and the same-index carry relation modelled by
//! [`verify_transposed_capsule_leaf_trace`].

use noid_ivc_core::deep_chain::capsule_leaf::{
    capsule_leaf_iv_flat, CapsuleLeafData, CAPSULE_LEAF_SLOTS,
};
use noid_ivc_core::deep_chain::source_tree::run_perm;
use noid_ivc_core::public_io::WitnessSlice;
use noid_poseidon2b::native::permutation::STATE_SIZE;

use crate::circuit_support::{pin_eq, poseidon2b_permute, FieldR1csBuilder, LinExpr, F128};

/// Launch authorization capacity.
pub const A128_TRANSPOSED_CAPSULES: usize = 128;
/// Source and mid capsule-leaf families.
pub const A128_TRANSPOSED_FAMILIES: usize = 2;
/// Transcript-derived openings in each family.
pub const A128_TRANSPOSED_QUERIES: usize = 64;
/// Exactly `128 * 2 * 64 = 2^14` capsule leaves.
pub const A128_TRANSPOSED_LEAVES: usize =
    A128_TRANSPOSED_CAPSULES * A128_TRANSPOSED_FAMILIES * A128_TRANSPOSED_QUERIES;
/// Native capsule-leaf sponge rounds: one metadata round plus eight absorbs.
pub const A128_TRANSPOSED_ROUNDS: usize = CAPSULE_LEAF_SLOTS;
/// `IN0, IN1, C0, C1, C2, C3` in every round slice.
pub const A128_TRANSPOSED_COMMITTED_COLUMNS: usize = 2 + STATE_SIZE;
/// Every round has one exact `2^14` domain.
pub const A128_TRANSPOSED_ROUND_LOG: usize = 14;
pub const A128_TRANSPOSED_ROUND_LEN: usize = 1 << A128_TRANSPOSED_ROUND_LOG;
/// Exact committed-cell ledger for the transposed A128 Wallet-A prototype.
pub const A128_TRANSPOSED_COMMITTED_CELLS: usize =
    A128_TRANSPOSED_ROUNDS * A128_TRANSPOSED_COMMITTED_COLUMNS * A128_TRANSPOSED_ROUND_LEN;
/// Exact per-capsule contribution of the transposed Wallet-A columns.
pub const A128_TRANSPOSED_COMMITTED_CELLS_PER_CAPSULE: usize =
    A128_TRANSPOSED_COMMITTED_CELLS / A128_TRANSPOSED_CAPSULES;

/// The allocation this prototype explicitly forbids: flattening all active
/// rounds first and then rounding each of the six columns to `2^18`.
pub const A128_MONOLITHIC_W_LOG: usize = 18;
pub const A128_MONOLITHIC_COMMITTED_CELLS: usize =
    A128_TRANSPOSED_COMMITTED_COLUMNS * (1 << A128_MONOLITHIC_W_LOG);

/// Nine Poseidon permutations plus four output pins after every permutation.
/// This is a differential constraint prototype, not the intended sidecar
/// cost: production authenticates the committed permutation columns through
/// a post-commit vertical rather than replaying every S-box in the main R1CS.
pub const TRANSPOSED_CAPSULE_LEAF_TRACE_ROWS: usize = A128_TRANSPOSED_ROUNDS
    * (noid_ivc_core::field_circuit::POSEIDON2B_PERMUTE_CONSTRAINTS + STATE_SIZE);

const _: () = assert!(A128_TRANSPOSED_LEAVES == 1 << A128_TRANSPOSED_ROUND_LOG);
const _: () = assert!(A128_TRANSPOSED_ROUNDS == 9);
const _: () = assert!(A128_TRANSPOSED_COMMITTED_COLUMNS == 6);
const _: () = assert!(A128_TRANSPOSED_COMMITTED_CELLS == 884_736);
const _: () = assert!(A128_TRANSPOSED_COMMITTED_CELLS_PER_CAPSULE == 6_912);
const _: () = assert!(A128_MONOLITHIC_COMMITTED_CELLS == 1_572_864);
const _: () = assert!(TRANSPOSED_CAPSULE_LEAF_TRACE_ROWS == 3_276);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransposedCapsuleLeafLayoutProposal {
    /// Fifty-four separately committed dyadic slices, all beginning at one
    /// `2^14`-aligned cursor.
    RoundMajor { start_wire: usize },
    /// A six-column domain covering all nine rounds at once.  This erases the
    /// transpose saving and is rejected even if a caller supplies another log.
    Monolithic { start_wire: usize, w_log: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransposedCapsuleLeafError {
    MisalignedStart { start_wire: usize, alignment: usize },
    AllocationOverflow,
    MonolithicAllocationRejected { start_wire: usize, w_log: usize },
    LeafCount { expected: usize, actual: usize },
    RoundLog { expected: usize, actual: usize },
    ColumnShape { round: usize, column: usize },
    PermutationMismatch { round: usize, leaf: usize },
}

/// Exact shape certificate for the only accepted A128 allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A128TransposedCapsuleLeafLayout {
    round_slices: [[WitnessSlice; A128_TRANSPOSED_COMMITTED_COLUMNS]; A128_TRANSPOSED_ROUNDS],
    start_wire: usize,
    end_wire: usize,
}

impl A128TransposedCapsuleLeafLayout {
    pub fn certify(
        proposal: TransposedCapsuleLeafLayoutProposal,
    ) -> Result<Self, TransposedCapsuleLeafError> {
        let start_wire = match proposal {
            TransposedCapsuleLeafLayoutProposal::RoundMajor { start_wire } => start_wire,
            TransposedCapsuleLeafLayoutProposal::Monolithic { start_wire, w_log } => {
                return Err(TransposedCapsuleLeafError::MonolithicAllocationRejected {
                    start_wire,
                    w_log,
                });
            }
        };
        if start_wire % A128_TRANSPOSED_ROUND_LEN != 0 {
            return Err(TransposedCapsuleLeafError::MisalignedStart {
                start_wire,
                alignment: A128_TRANSPOSED_ROUND_LEN,
            });
        }
        let end_wire = start_wire
            .checked_add(A128_TRANSPOSED_COMMITTED_CELLS)
            .ok_or(TransposedCapsuleLeafError::AllocationOverflow)?;
        let first_index = start_wire >> A128_TRANSPOSED_ROUND_LOG;
        let round_slices = std::array::from_fn(|round| {
            std::array::from_fn(|column| WitnessSlice {
                log2_len: A128_TRANSPOSED_ROUND_LOG,
                index: first_index + round * A128_TRANSPOSED_COMMITTED_COLUMNS + column,
            })
        });
        Ok(Self {
            round_slices,
            start_wire,
            end_wire,
        })
    }

    pub fn round_slices(
        &self,
    ) -> &[[WitnessSlice; A128_TRANSPOSED_COMMITTED_COLUMNS]; A128_TRANSPOSED_ROUNDS] {
        &self.round_slices
    }

    pub const fn start_wire(&self) -> usize {
        self.start_wire
    }

    pub const fn end_wire(&self) -> usize {
        self.end_wire
    }

    pub const fn committed_cells(&self) -> usize {
        self.end_wire - self.start_wire
    }
}

/// Six committed value columns plus the producer-only permutation columns
/// needed by a future post-commit sidecar.
#[derive(Clone, Debug)]
pub struct TransposedCapsuleLeafRoundColumns {
    committed: [Vec<F128>; A128_TRANSPOSED_COMMITTED_COLUMNS],
    s0: [Vec<F128>; STATE_SIZE],
    s_out: [Vec<F128>; STATE_SIZE],
}

impl TransposedCapsuleLeafRoundColumns {
    pub fn committed(&self) -> &[Vec<F128>; A128_TRANSPOSED_COMMITTED_COLUMNS] {
        &self.committed
    }

    pub fn s0(&self) -> &[Vec<F128>; STATE_SIZE] {
        &self.s0
    }

    pub fn s_out(&self) -> &[Vec<F128>; STATE_SIZE] {
        &self.s_out
    }
}

/// Native-value carrier for nine independent dyadic round slices.
#[derive(Clone, Debug)]
pub struct TransposedCapsuleLeafColumns {
    round_log: usize,
    rounds: [TransposedCapsuleLeafRoundColumns; A128_TRANSPOSED_ROUNDS],
}

impl TransposedCapsuleLeafColumns {
    pub fn round_log(&self) -> usize {
        self.round_log
    }

    pub fn leaf_count(&self) -> usize {
        1usize << self.round_log
    }

    pub fn rounds(&self) -> &[TransposedCapsuleLeafRoundColumns; A128_TRANSPOSED_ROUNDS] {
        &self.rounds
    }

    pub fn digest(&self, leaf: usize) -> [F128; 2] {
        assert!(leaf < self.leaf_count(), "transposed capsule leaf index");
        let last = &self.rounds[A128_TRANSPOSED_ROUNDS - 1].committed;
        [last[2][leaf], last[3][leaf]]
    }

    /// Re-evaluate every permutation from committed inputs and the preceding
    /// round's committed `C0..C3`.  This is the exact cross-round relation the
    /// future sidecar must prove at a shared leaf coordinate.
    pub fn validate_relation(&self) -> Result<(), TransposedCapsuleLeafError> {
        let leaves = self.leaf_count();
        for (round, columns) in self.rounds.iter().enumerate() {
            for (column, values) in columns.committed.iter().enumerate() {
                if values.len() != leaves {
                    return Err(TransposedCapsuleLeafError::ColumnShape { round, column });
                }
            }
            for (column, values) in columns.s0.iter().enumerate() {
                if values.len() != leaves {
                    return Err(TransposedCapsuleLeafError::ColumnShape {
                        round,
                        column: A128_TRANSPOSED_COMMITTED_COLUMNS + column,
                    });
                }
            }
            for (column, values) in columns.s_out.iter().enumerate() {
                if values.len() != leaves {
                    return Err(TransposedCapsuleLeafError::ColumnShape {
                        round,
                        column: A128_TRANSPOSED_COMMITTED_COLUMNS + STATE_SIZE + column,
                    });
                }
            }
        }

        let iv = capsule_leaf_iv_flat();
        for leaf in 0..leaves {
            for round in 0..A128_TRANSPOSED_ROUNDS {
                let columns = &self.rounds[round];
                let raw = if round == 0 {
                    [
                        columns.committed[0][leaf],
                        columns.committed[1][leaf],
                        iv[0],
                        iv[1],
                    ]
                } else {
                    let previous = &self.rounds[round - 1].committed;
                    [
                        previous[2][leaf] + columns.committed[0][leaf],
                        previous[3][leaf] + columns.committed[1][leaf],
                        previous[4][leaf],
                        previous[5][leaf],
                    ]
                };
                let (s0, s_out) = run_perm(raw);
                let committed_out: [F128; STATE_SIZE] =
                    std::array::from_fn(|lane| columns.committed[2 + lane][leaf]);
                let stored_s0: [F128; STATE_SIZE] =
                    std::array::from_fn(|lane| columns.s0[lane][leaf]);
                let stored_s_out: [F128; STATE_SIZE] =
                    std::array::from_fn(|lane| columns.s_out[lane][leaf]);
                if s0 != stored_s0 || s_out != stored_s_out || s_out != committed_out {
                    return Err(TransposedCapsuleLeafError::PermutationMismatch { round, leaf });
                }
            }
        }
        Ok(())
    }
}

/// Build the transposed native columns for one exact dyadic set of leaves.
/// `leaves` are ordered `(capsule, family, query)` and that order is retained
/// at the same coordinate in all nine slices.
pub fn build_transposed_capsule_leaf_columns(
    leaves: &[CapsuleLeafData],
    round_log: usize,
) -> Result<TransposedCapsuleLeafColumns, TransposedCapsuleLeafError> {
    let leaf_count = 1usize
        .checked_shl(round_log as u32)
        .ok_or(TransposedCapsuleLeafError::AllocationOverflow)?;
    if leaves.len() != leaf_count {
        return Err(TransposedCapsuleLeafError::LeafCount {
            expected: leaf_count,
            actual: leaves.len(),
        });
    }
    let mut rounds: [TransposedCapsuleLeafRoundColumns; A128_TRANSPOSED_ROUNDS] =
        std::array::from_fn(|_| TransposedCapsuleLeafRoundColumns {
            committed: std::array::from_fn(|_| vec![F128::ZERO; leaf_count]),
            s0: std::array::from_fn(|_| vec![F128::ZERO; leaf_count]),
            s_out: std::array::from_fn(|_| vec![F128::ZERO; leaf_count]),
        });
    let iv = capsule_leaf_iv_flat();
    for (leaf, data) in leaves.iter().enumerate() {
        for round in 0..A128_TRANSPOSED_ROUNDS {
            let absorb = if round == 0 {
                [
                    noid_ivc_core::deep_chain::capsule_leaf::raw_flat_lane(data.msg_log as u128),
                    noid_ivc_core::deep_chain::capsule_leaf::raw_flat_lane(data.leaf_index as u128),
                ]
            } else {
                [data.syms[2 * (round - 1)], data.syms[2 * (round - 1) + 1]]
            };
            rounds[round].committed[0][leaf] = absorb[0];
            rounds[round].committed[1][leaf] = absorb[1];
            let raw = if round == 0 {
                [absorb[0], absorb[1], iv[0], iv[1]]
            } else {
                let previous = &rounds[round - 1].committed;
                [
                    previous[2][leaf] + absorb[0],
                    previous[3][leaf] + absorb[1],
                    previous[4][leaf],
                    previous[5][leaf],
                ]
            };
            let (s0, s_out) = run_perm(raw);
            for lane in 0..STATE_SIZE {
                rounds[round].committed[2 + lane][leaf] = s_out[lane];
                rounds[round].s0[lane][leaf] = s0[lane];
                rounds[round].s_out[lane][leaf] = s_out[lane];
            }
        }
    }
    Ok(TransposedCapsuleLeafColumns { round_log, rounds })
}

/// Prototype allocator for the exact A128 columns.  It aligns once, then
/// allocates the 54 certified slices contiguously.  Alignment rows are
/// returned separately and are never misreported as committed Wallet-A cells.
pub fn allocate_a128_transposed_capsule_leaf_columns(
    b: &mut FieldR1csBuilder,
    columns: &TransposedCapsuleLeafColumns,
) -> Result<(A128TransposedCapsuleLeafLayout, usize), TransposedCapsuleLeafError> {
    if columns.round_log != A128_TRANSPOSED_ROUND_LOG {
        return Err(TransposedCapsuleLeafError::RoundLog {
            expected: A128_TRANSPOSED_ROUND_LOG,
            actual: columns.round_log,
        });
    }
    columns.validate_relation()?;
    let before_alignment = b.num_wires();
    while b.num_wires() % A128_TRANSPOSED_ROUND_LEN != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let start_wire = b.num_wires();
    let alignment_rows = start_wire - before_alignment;
    let layout = A128TransposedCapsuleLeafLayout::certify(
        TransposedCapsuleLeafLayoutProposal::RoundMajor { start_wire },
    )?;
    for round in 0..A128_TRANSPOSED_ROUNDS {
        for column in 0..A128_TRANSPOSED_COMMITTED_COLUMNS {
            let slice = layout.round_slices[round][column];
            assert_eq!(slice.start(), b.num_wires(), "transposed slice cursor");
            for &value in &columns.rounds[round].committed[column] {
                b.alloc_f128(value);
            }
        }
    }
    assert_eq!(b.num_wires(), layout.end_wire());
    Ok((layout, alignment_rows))
}

/// R1CS differential twin for one transposed leaf.  Every output is pinned to
/// its committed round cell, and round `r+1` consumes round `r`'s pinned
/// output at the same leaf coordinate.
pub fn verify_transposed_capsule_leaf_trace(
    b: &mut FieldR1csBuilder,
    round_inputs: &[[LinExpr; 2]; A128_TRANSPOSED_ROUNDS],
    round_outputs: &[[LinExpr; STATE_SIZE]; A128_TRANSPOSED_ROUNDS],
) -> [LinExpr; 2] {
    let trace_start = b.num_wires();
    let iv = capsule_leaf_iv_flat();
    let mut previous: Option<[LinExpr; STATE_SIZE]> = None;
    for round in 0..A128_TRANSPOSED_ROUNDS {
        let raw = if let Some(previous) = previous.as_ref() {
            [
                previous[0].add(&round_inputs[round][0]),
                previous[1].add(&round_inputs[round][1]),
                previous[2].clone(),
                previous[3].clone(),
            ]
        } else {
            [
                round_inputs[round][0].clone(),
                round_inputs[round][1].clone(),
                LinExpr::constant(iv[0]),
                LinExpr::constant(iv[1]),
            ]
        };
        let computed = poseidon2b_permute(b, raw);
        for lane in 0..STATE_SIZE {
            pin_eq(b, &computed[lane], &round_outputs[round][lane]);
        }
        previous = Some(round_outputs[round].clone());
    }
    debug_assert_eq!(
        b.num_wires() - trace_start,
        TRANSPOSED_CAPSULE_LEAF_TRACE_ROWS
    );
    let final_state = previous.expect("capsule leaf has nine rounds");
    [final_state[0].clone(), final_state[1].clone()]
}

#[cfg(test)]
mod tests {
    use noid_core::hardware::tower_to_flat_u128;
    use noid_core::Block128;
    use noid_fri_binius::capsule::capsule_leaf_hash;
    use noid_ivc_core::deep_chain::capsule_leaf::{
        build_capsule_leaf_columns, flat_capsule_leaf_hash, raw_flat_lane,
        CAPSULE_LEAF_DIGEST_SLOT, CAPSULE_LEAF_STRIDE, CAPSULE_LEAF_SYMBOLS,
    };

    use super::*;

    fn native_symbols(leaf: usize) -> [Block128; CAPSULE_LEAF_SYMBOLS] {
        std::array::from_fn(|symbol| {
            Block128::from(
                ((leaf as u128 + 1) << 96)
                    ^ ((symbol as u128 + 3) << 32)
                    ^ (leaf as u128 * 0x9E37_79B9)
                    ^ symbol as u128,
            )
        })
    }

    fn flat_symbol(value: Block128) -> F128 {
        let flat = tower_to_flat_u128(value.0);
        F128 {
            lo: flat as u64,
            hi: (flat >> 64) as u64,
        }
    }

    fn digest_lanes(digest: [u8; 32]) -> [F128; 2] {
        [
            raw_flat_lane(u128::from_le_bytes(digest[..16].try_into().unwrap())),
            raw_flat_lane(u128::from_le_bytes(digest[16..].try_into().unwrap())),
        ]
    }

    fn leaves(log: usize) -> (Vec<CapsuleLeafData>, Vec<[Block128; CAPSULE_LEAF_SYMBOLS]>) {
        let native = (0..1usize << log).map(native_symbols).collect::<Vec<_>>();
        let flat = native
            .iter()
            .enumerate()
            .map(|(leaf, symbols)| CapsuleLeafData {
                msg_log: if leaf & 1 == 0 { 12 } else { 8 },
                leaf_index: leaf * 17 + 3,
                syms: symbols.map(flat_symbol),
            })
            .collect();
        (flat, native)
    }

    #[test]
    fn a128_layout_certificate_is_exact_and_monolithic_is_rejected() {
        let layout = A128TransposedCapsuleLeafLayout::certify(
            TransposedCapsuleLeafLayoutProposal::RoundMajor { start_wire: 0 },
        )
        .unwrap();
        assert_eq!(layout.start_wire(), 0);
        assert_eq!(layout.end_wire(), 884_736);
        assert_eq!(layout.committed_cells(), A128_TRANSPOSED_COMMITTED_CELLS);
        assert_eq!(layout.round_slices().len(), 9);
        for (linear, slice) in layout.round_slices().iter().flatten().enumerate() {
            assert_eq!(slice.log2_len, A128_TRANSPOSED_ROUND_LOG);
            assert_eq!(slice.index, linear);
            assert_eq!(slice.start(), linear * A128_TRANSPOSED_ROUND_LEN);
        }
        assert_eq!(
            A128TransposedCapsuleLeafLayout::certify(
                TransposedCapsuleLeafLayoutProposal::Monolithic {
                    start_wire: 0,
                    w_log: A128_MONOLITHIC_W_LOG,
                }
            ),
            Err(TransposedCapsuleLeafError::MonolithicAllocationRejected {
                start_wire: 0,
                w_log: 18,
            })
        );
        assert_eq!(A128_MONOLITHIC_COMMITTED_CELLS, 1_572_864);
        assert_eq!(
            A128_MONOLITHIC_COMMITTED_CELLS - A128_TRANSPOSED_COMMITTED_CELLS,
            688_128
        );
    }

    #[test]
    fn transposed_rounds_match_native_and_legacy_tiled_leaf_values() {
        const LOG: usize = 2;
        let (leaves, native) = leaves(LOG);
        let transposed = build_transposed_capsule_leaf_columns(&leaves, LOG).unwrap();
        transposed.validate_relation().unwrap();
        let (_, legacy_digests) = build_capsule_leaf_columns(
            &leaves,
            LOG + CAPSULE_LEAF_STRIDE.trailing_zeros() as usize,
        );
        for leaf in 0..1usize << LOG {
            let direct = flat_capsule_leaf_hash(
                leaves[leaf].msg_log,
                leaves[leaf].leaf_index,
                &leaves[leaf].syms,
            );
            let native = digest_lanes(capsule_leaf_hash(
                leaves[leaf].msg_log,
                leaves[leaf].leaf_index,
                &native[leaf],
            ));
            assert_eq!(transposed.digest(leaf), direct);
            assert_eq!(transposed.digest(leaf), native);
            assert_eq!(transposed.digest(leaf), legacy_digests[leaf]);
            let legacy_slot = leaf * CAPSULE_LEAF_STRIDE + CAPSULE_LEAF_DIGEST_SLOT;
            assert!(legacy_slot < (1usize << LOG) * CAPSULE_LEAF_STRIDE);
        }
    }

    #[test]
    fn trace_pins_every_round_and_uses_same_coordinate_carry() {
        let (leaves, _) = leaves(0);
        let columns = build_transposed_capsule_leaf_columns(&leaves, 0).unwrap();
        let mut b = FieldR1csBuilder::new();
        let round_inputs: [[LinExpr; 2]; A128_TRANSPOSED_ROUNDS] = std::array::from_fn(|round| {
            std::array::from_fn(|lane| {
                LinExpr::from_wire(b.alloc_f128(columns.rounds[round].committed[lane][0]))
            })
        });
        let round_outputs: [[LinExpr; STATE_SIZE]; A128_TRANSPOSED_ROUNDS] =
            std::array::from_fn(|round| {
                std::array::from_fn(|lane| {
                    LinExpr::from_wire(b.alloc_f128(columns.rounds[round].committed[2 + lane][0]))
                })
            });
        let before = b.num_wires();
        let digest = verify_transposed_capsule_leaf_trace(&mut b, &round_inputs, &round_outputs);
        assert_eq!(b.num_wires() - before, TRANSPOSED_CAPSULE_LEAF_TRACE_ROWS);
        assert_eq!(digest.map(|lane| lane.eval(b.values())), columns.digest(0));
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
    }

    #[test]
    fn relation_rejects_a_broken_cross_round_carry() {
        let (leaves, _) = leaves(0);
        let mut columns = build_transposed_capsule_leaf_columns(&leaves, 0).unwrap();
        columns.rounds[3].committed[2][0] += F128::ONE;
        assert_eq!(
            columns.validate_relation(),
            Err(TransposedCapsuleLeafError::PermutationMismatch { round: 3, leaf: 0 })
        );
    }
}
