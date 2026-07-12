// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact in-witness bridge between the disconnected Owner and Main duplex
//! families of the selected ZK authorization capsule.
//!
//! The Owner transcript closes with a full fixed absorb at slot 117. Its four
//! output carry cells are the bridge. The Main transcript absorbs those same
//! four values as dynamic data lanes 0 through 3 before `sigma` (data lane 4):
//!
//! ```text
//! Owner C0..C3[117]
//!        |  |  |  |
//!        v  v  v  v
//! Main A1[0], A0[1], A1[1], A0[2]    Main A1[2] = sigma
//! ```
//!
//! This primitive adds four direct equality rows between already allocated
//! committed-column cells. It deliberately allocates no intermediate bridge
//! values: the bridge is neither a proof field nor a second witness copy.

use noid_ivc_core::deep_chain::schedule::{DuplexLayout, LaneSource};
use noid_ivc_core::public_io::WitnessSlice;

use super::region_source_binding::{duplex_data_positions, slot_cell};
use super::{pin_eq, FieldR1csBuilder, LinExpr};
use crate::acceptance::zk_auth_capsule_schedule::{
    ZkAuthCapsuleDuplexSchedules, ZK_AUTH_BRIDGE_LANES, ZK_AUTH_MAIN_COMPILED_SLOTS,
    ZK_AUTH_MAIN_FROM_OWNER_TAG, ZK_AUTH_MAIN_SIGMA_DATA_INDEX, ZK_AUTH_MAIN_TILE_LOG,
    ZK_AUTH_OWNER_BRIDGE_SLOT, ZK_AUTH_OWNER_COMPILED_SLOTS, ZK_AUTH_OWNER_TILE_LOG,
    ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG,
};

/// The four Main absorb cells that receive Owner `C0..C3`, in bridge-lane
/// order. Each pair is `(slot, rate_lane)` relative to the selected Main tile.
pub const ZK_AUTH_MAIN_BRIDGE_CELLS: [(usize, usize); ZK_AUTH_BRIDGE_LANES] =
    [(0, 1), (1, 0), (1, 1), (2, 0)];

/// The Main absorb cell carrying `sigma`, immediately after the four bridge
/// lanes. This cell must remain distinct from every bridge destination.
pub const ZK_AUTH_MAIN_SIGMA_CELL: (usize, usize) = (2, 1);

/// Exact incremental R1CS cost of one selected Owner-to-Main bridge.
pub const ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS: usize = ZK_AUTH_BRIDGE_LANES;

const _: () = assert!(ZK_AUTH_BRIDGE_LANES == 4);
const _: () = assert!(ZK_AUTH_OWNER_BRIDGE_SLOT == 117);
const _: () = assert!(ZK_AUTH_MAIN_SIGMA_DATA_INDEX == ZK_AUTH_BRIDGE_LANES);

/// Raw committed-cell aliases exposed by [`pin_zk_auth_split_bridge`]. None
/// of these expressions allocates a wire; `sigma` is returned so the caller
/// can consume the existing Main absorb cell directly.
#[derive(Clone, Debug)]
pub struct ZkAuthSplitBridgeCells {
    pub owner_final_state: [LinExpr; ZK_AUTH_BRIDGE_LANES],
    pub main_absorb: [LinExpr; ZK_AUTH_BRIDGE_LANES],
    pub sigma: LinExpr,
}

fn assert_pairwise_disjoint(slices: &[WitnessSlice]) {
    for (index, left) in slices.iter().enumerate() {
        let left_range = left.start()..left.start() + left.len();
        for right in &slices[index + 1..] {
            let right_range = right.start()..right.start() + right.len();
            assert!(
                left_range.end <= right_range.start || right_range.end <= left_range.start,
                "Owner/Main duplex columns must occupy disjoint witness slices"
            );
        }
    }
}

fn assert_selected_layouts(owner: &DuplexLayout, main: &DuplexLayout) {
    assert_eq!(owner.slots.len(), ZK_AUTH_OWNER_COMPILED_SLOTS);
    assert_eq!(main.slots.len(), ZK_AUTH_MAIN_COMPILED_SLOTS);
    assert_eq!(
        owner.slots.len().next_power_of_two(),
        1 << ZK_AUTH_OWNER_TILE_LOG
    );
    assert_eq!(
        main.slots.len().next_power_of_two(),
        1 << ZK_AUTH_MAIN_TILE_LOG
    );
    assert_eq!(ZK_AUTH_OWNER_BRIDGE_SLOT, owner.slots.len() - 1);
    assert_eq!(
        owner.slots[ZK_AUTH_OWNER_BRIDGE_SLOT].lanes,
        [
            Some(LaneSource::Const(ZK_AUTH_OWNER_TO_MAIN_CLOSE_TAG)),
            Some(LaneSource::Const(0)),
        ],
        "Owner closing slot drifted"
    );

    let positions = duplex_data_positions(main);
    assert!(positions.len() > ZK_AUTH_MAIN_SIGMA_DATA_INDEX);
    assert_eq!(
        &positions[..ZK_AUTH_BRIDGE_LANES],
        &ZK_AUTH_MAIN_BRIDGE_CELLS,
        "Main bridge data placement drifted"
    );
    assert_eq!(
        positions[ZK_AUTH_MAIN_SIGMA_DATA_INDEX], ZK_AUTH_MAIN_SIGMA_CELL,
        "Main sigma placement drifted"
    );
    assert!(
        !ZK_AUTH_MAIN_BRIDGE_CELLS.contains(&ZK_AUTH_MAIN_SIGMA_CELL),
        "sigma aliases a bridge absorb cell"
    );
    assert_eq!(
        main.slots[0].lanes,
        [
            Some(LaneSource::Const(ZK_AUTH_MAIN_FROM_OWNER_TAG)),
            Some(LaneSource::Data(0)),
        ],
        "Main bridge prefix drifted"
    );
}

fn validate_column_slices(
    owner_c: &[WitnessSlice; ZK_AUTH_BRIDGE_LANES],
    main_a: &[WitnessSlice; 2],
) -> usize {
    assert!(
        owner_c
            .iter()
            .all(|slice| slice.log2_len >= ZK_AUTH_OWNER_TILE_LOG),
        "Owner carry columns must contain at least one selected m7 tile"
    );
    assert!(
        main_a
            .iter()
            .all(|slice| slice.log2_len >= ZK_AUTH_MAIN_TILE_LOG),
        "Main absorb columns must contain at least one selected m8 tile"
    );
    assert!(
        owner_c
            .iter()
            .all(|slice| slice.log2_len == owner_c[0].log2_len),
        "Owner carry columns must have one common tiled domain"
    );
    assert!(
        main_a
            .iter()
            .all(|slice| slice.log2_len == main_a[0].log2_len),
        "Main absorb columns must have one common tiled domain"
    );

    let owner_tiles = 1usize << (owner_c[0].log2_len - ZK_AUTH_OWNER_TILE_LOG);
    let main_tiles = 1usize << (main_a[0].log2_len - ZK_AUTH_MAIN_TILE_LOG);
    assert_eq!(
        owner_tiles, main_tiles,
        "Owner and Main duplex unions must contain the same transaction tiles"
    );

    let all_slices = owner_c
        .iter()
        .chain(main_a.iter())
        .copied()
        .collect::<Vec<_>>();
    assert_pairwise_disjoint(&all_slices);
    owner_tiles
}

fn pin_zk_auth_split_bridge_at_validated(
    b: &mut FieldR1csBuilder,
    owner_c: &[WitnessSlice; ZK_AUTH_BRIDGE_LANES],
    main_a: &[WitnessSlice; 2],
    tile_index: usize,
) -> ZkAuthSplitBridgeCells {
    let owner_base = tile_index << ZK_AUTH_OWNER_TILE_LOG;
    let main_base = tile_index << ZK_AUTH_MAIN_TILE_LOG;
    let owner_final_state = std::array::from_fn(|lane| {
        slot_cell(&owner_c[lane], owner_base + ZK_AUTH_OWNER_BRIDGE_SLOT)
    });
    let main_absorb = std::array::from_fn(|lane| {
        let (slot, rate_lane) = ZK_AUTH_MAIN_BRIDGE_CELLS[lane];
        slot_cell(&main_a[rate_lane], main_base + slot)
    });
    let sigma = slot_cell(
        &main_a[ZK_AUTH_MAIN_SIGMA_CELL.1],
        main_base + ZK_AUTH_MAIN_SIGMA_CELL.0,
    );

    for lane in 0..ZK_AUTH_BRIDGE_LANES {
        pin_eq(b, &owner_final_state[lane], &main_absorb[lane]);
    }

    ZkAuthSplitBridgeCells {
        owner_final_state,
        main_absorb,
        sigma,
    }
}

/// Pin one transaction tile inside production Owner/Main duplex unions.
///
/// Owner tiles have stride 128 and Main tiles stride 256. The committed
/// column domains may be larger than those strides (B255 uses m15/m16), but
/// all Owner columns must share a domain, all Main columns must share a
/// domain, and both unions must contain the same number of transaction tiles.
/// This call appends exactly four rows for `tile_index`.
pub fn pin_zk_auth_split_bridge_at(
    b: &mut FieldR1csBuilder,
    owner_c: &[WitnessSlice; ZK_AUTH_BRIDGE_LANES],
    main_a: &[WitnessSlice; 2],
    tile_index: usize,
) -> ZkAuthSplitBridgeCells {
    let schedules = ZkAuthCapsuleDuplexSchedules::selected();
    assert_selected_layouts(&schedules.owner_layout(), &schedules.main_layout());
    let tile_count = validate_column_slices(owner_c, main_a);
    assert!(tile_index < tile_count, "bridge tile index out of range");
    pin_zk_auth_split_bridge_at_validated(b, owner_c, main_a, tile_index)
}

/// Pin every corresponding transaction tile in production Owner/Main duplex
/// unions. The returned entries are raw cell aliases in transaction order;
/// the helper appends exactly `4 * tile_count` rows.
pub fn pin_zk_auth_split_bridges(
    b: &mut FieldR1csBuilder,
    owner_c: &[WitnessSlice; ZK_AUTH_BRIDGE_LANES],
    main_a: &[WitnessSlice; 2],
) -> Vec<ZkAuthSplitBridgeCells> {
    let schedules = ZkAuthCapsuleDuplexSchedules::selected();
    assert_selected_layouts(&schedules.owner_layout(), &schedules.main_layout());
    let tile_count = validate_column_slices(owner_c, main_a);
    (0..tile_count)
        .map(|tile| pin_zk_auth_split_bridge_at_validated(b, owner_c, main_a, tile))
        .collect()
}

/// Pin the four selected Owner closing-state cells directly to Main dynamic
/// absorb cells 0 through 3.
///
/// `owner_c` must be the four separately committed Owner carry columns over
/// its exact m7 tile; `main_a` must be the two separately committed Main absorb
/// columns over its exact m8 tile. The six slices must not overlap. Exactly
/// four equality rows are appended, and no bridge witness is allocated.
pub fn pin_zk_auth_split_bridge(
    b: &mut FieldR1csBuilder,
    owner_c: &[WitnessSlice; ZK_AUTH_BRIDGE_LANES],
    main_a: &[WitnessSlice; 2],
) -> ZkAuthSplitBridgeCells {
    let schedules = ZkAuthCapsuleDuplexSchedules::selected();
    assert_selected_layouts(&schedules.owner_layout(), &schedules.main_layout());
    assert_eq!(
        validate_column_slices(owner_c, main_a),
        1,
        "single-tile bridge wrapper requires exact m7/m8 columns"
    );
    pin_zk_auth_split_bridge_at_validated(b, owner_c, main_a, 0)
}

#[cfg(test)]
mod tests {
    use noid_ivc_core::deep_chain::schedule::{build_duplex_columns, flat_of_tower_u128};
    use noid_ivc_core::field::F128;
    use noid_ivc_core::field_r1cs::FieldR1cs;
    use noid_poseidon2b::native::domain::{capacity_iv, TAG_KSCHANNL};

    use super::super::region_source_binding::alloc_column_slice;
    use super::*;

    fn sample(seed: u128, index: usize) -> F128 {
        flat_of_tower_u128(
            seed.wrapping_add(
                0x9E37_79B9_7F4A_7C15_6C8E_9CF5_7093_2BD5u128.wrapping_mul(index as u128 + 1),
            )
            .rotate_left(((17 * index + 11) % 127) as u32),
        )
    }

    fn stream(layout: &DuplexLayout, seed: u128) -> Vec<F128> {
        (0..layout.n_data)
            .map(|index| sample(seed, index))
            .collect()
    }

    fn iv_flat() -> [F128; 2] {
        let [hi, lo] = capacity_iv(TAG_KSCHANNL);
        [flat_of_tower_u128(hi.0), flat_of_tower_u128(lo.0)]
    }

    struct NativeFixture {
        owner_c: [Vec<F128>; ZK_AUTH_BRIDGE_LANES],
        main_a: [Vec<F128>; 2],
    }

    fn native_fixture(
        owner_seed: u128,
        main_seed: u128,
        splice_seed: Option<u128>,
    ) -> NativeFixture {
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner_layout = schedules.owner_layout();
        let main_layout = schedules.main_layout();
        assert_selected_layouts(&owner_layout, &main_layout);

        let owner = build_duplex_columns(
            &owner_layout,
            iv_flat(),
            &stream(&owner_layout, owner_seed),
            ZK_AUTH_OWNER_TILE_LOG,
        );
        let bridge: [F128; ZK_AUTH_BRIDGE_LANES] = if let Some(other_seed) = splice_seed {
            let other = build_duplex_columns(
                &owner_layout,
                iv_flat(),
                &stream(&owner_layout, other_seed),
                ZK_AUTH_OWNER_TILE_LOG,
            );
            std::array::from_fn(|lane| other.c[lane][ZK_AUTH_OWNER_BRIDGE_SLOT])
        } else {
            std::array::from_fn(|lane| owner.c[lane][ZK_AUTH_OWNER_BRIDGE_SLOT])
        };

        let mut main_data = stream(&main_layout, main_seed);
        main_data[..ZK_AUTH_BRIDGE_LANES].copy_from_slice(&bridge);
        let main = build_duplex_columns(&main_layout, iv_flat(), &main_data, ZK_AUTH_MAIN_TILE_LOG);
        NativeFixture {
            owner_c: owner.c,
            main_a: main.a,
        }
    }

    fn native_k2_fixture(
        owner_seeds: [u128; 2],
        main_seeds: [u128; 2],
        main_bridge_source: [usize; 2],
    ) -> NativeFixture {
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner_layout = schedules.owner_layout();
        let main_layout = schedules.main_layout();
        assert_selected_layouts(&owner_layout, &main_layout);
        assert!(main_bridge_source.iter().all(|&source| source < 2));

        let owners = owner_seeds.map(|seed| {
            build_duplex_columns(
                &owner_layout,
                iv_flat(),
                &stream(&owner_layout, seed),
                ZK_AUTH_OWNER_TILE_LOG,
            )
        });
        let mains = std::array::from_fn::<_, 2, _>(|tile| {
            let mut data = stream(&main_layout, main_seeds[tile]);
            let source = main_bridge_source[tile];
            for lane in 0..ZK_AUTH_BRIDGE_LANES {
                data[lane] = owners[source].c[lane][ZK_AUTH_OWNER_BRIDGE_SLOT];
            }
            build_duplex_columns(&main_layout, iv_flat(), &data, ZK_AUTH_MAIN_TILE_LOG)
        });

        NativeFixture {
            owner_c: std::array::from_fn(|lane| {
                owners
                    .iter()
                    .flat_map(|owner| owner.c[lane].iter().copied())
                    .collect()
            }),
            main_a: std::array::from_fn(|lane| {
                mains
                    .iter()
                    .flat_map(|main| main.a[lane].iter().copied())
                    .collect()
            }),
        }
    }

    struct BuiltFixture {
        r1cs: FieldR1cs,
        witness: Vec<F128>,
        owner_cells: [usize; ZK_AUTH_BRIDGE_LANES],
        main_cells: [usize; ZK_AUTH_BRIDGE_LANES],
        sigma_cell: usize,
        bridge_row_start: usize,
    }

    fn build_fixture(owner_seed: u128, main_seed: u128, splice_seed: Option<u128>) -> BuiltFixture {
        let native = native_fixture(owner_seed, main_seed, splice_seed);
        let mut b = FieldR1csBuilder::new();
        let owner_slices: [WitnessSlice; ZK_AUTH_BRIDGE_LANES] = std::array::from_fn(|lane| {
            alloc_column_slice(&mut b, &native.owner_c[lane], ZK_AUTH_OWNER_TILE_LOG).0
        });
        let main_slices: [WitnessSlice; 2] = std::array::from_fn(|lane| {
            alloc_column_slice(&mut b, &native.main_a[lane], ZK_AUTH_MAIN_TILE_LOG).0
        });
        let owner_cells =
            std::array::from_fn(|lane| owner_slices[lane].start() + ZK_AUTH_OWNER_BRIDGE_SLOT);
        let main_cells = std::array::from_fn(|lane| {
            let (slot, rate_lane) = ZK_AUTH_MAIN_BRIDGE_CELLS[lane];
            main_slices[rate_lane].start() + slot
        });
        let sigma_cell = main_slices[ZK_AUTH_MAIN_SIGMA_CELL.1].start() + ZK_AUTH_MAIN_SIGMA_CELL.0;
        let bridge_row_start = b.num_wires();
        let cells = pin_zk_auth_split_bridge(&mut b, &owner_slices, &main_slices);
        assert_eq!(
            b.num_wires() - bridge_row_start,
            ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS
        );
        for lane in 0..ZK_AUTH_BRIDGE_LANES {
            assert_eq!(cells.owner_final_state[lane].terms.len(), 1);
            assert_eq!(
                cells.owner_final_state[lane].terms[0].0 as usize,
                owner_cells[lane]
            );
            assert_eq!(cells.main_absorb[lane].terms.len(), 1);
            assert_eq!(
                cells.main_absorb[lane].terms[0].0 as usize,
                main_cells[lane]
            );
        }
        assert_eq!(cells.sigma.terms.len(), 1);
        assert_eq!(cells.sigma.terms[0].0 as usize, sigma_cell);
        assert!(!main_cells.contains(&sigma_cell));
        let (r1cs, witness) = b.build();
        BuiltFixture {
            r1cs,
            witness,
            owner_cells,
            main_cells,
            sigma_cell,
            bridge_row_start,
        }
    }

    struct BuiltK2Fixture {
        r1cs: FieldR1cs,
        witness: Vec<F128>,
        owner_cells: [[usize; ZK_AUTH_BRIDGE_LANES]; 2],
        main_cells: [[usize; ZK_AUTH_BRIDGE_LANES]; 2],
        bridge_row_start: usize,
    }

    fn build_k2_fixture(main_bridge_source: [usize; 2]) -> BuiltK2Fixture {
        let native = native_k2_fixture(
            [0xB255_0A00, 0xB255_0A01],
            [0xB255_0B00, 0xB255_0B01],
            main_bridge_source,
        );
        let mut b = FieldR1csBuilder::new();
        let owner_log = ZK_AUTH_OWNER_TILE_LOG + 1;
        let main_log = ZK_AUTH_MAIN_TILE_LOG + 1;
        let owner_slices: [WitnessSlice; ZK_AUTH_BRIDGE_LANES] = std::array::from_fn(|lane| {
            alloc_column_slice(&mut b, &native.owner_c[lane], owner_log).0
        });
        let main_slices: [WitnessSlice; 2] = std::array::from_fn(|lane| {
            alloc_column_slice(&mut b, &native.main_a[lane], main_log).0
        });
        let owner_cells = std::array::from_fn(|tile| {
            std::array::from_fn(|lane| {
                owner_slices[lane].start()
                    + (tile << ZK_AUTH_OWNER_TILE_LOG)
                    + ZK_AUTH_OWNER_BRIDGE_SLOT
            })
        });
        let main_cells = std::array::from_fn(|tile| {
            std::array::from_fn(|lane| {
                let (slot, rate_lane) = ZK_AUTH_MAIN_BRIDGE_CELLS[lane];
                main_slices[rate_lane].start() + (tile << ZK_AUTH_MAIN_TILE_LOG) + slot
            })
        });

        let bridge_row_start = b.num_wires();
        let cells = pin_zk_auth_split_bridges(&mut b, &owner_slices, &main_slices);
        assert_eq!(cells.len(), 2);
        assert_eq!(
            b.num_wires() - bridge_row_start,
            2 * ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS
        );
        for tile in 0..2 {
            for lane in 0..ZK_AUTH_BRIDGE_LANES {
                assert_eq!(
                    cells[tile].owner_final_state[lane].terms[0].0 as usize,
                    owner_cells[tile][lane]
                );
                assert_eq!(
                    cells[tile].main_absorb[lane].terms[0].0 as usize,
                    main_cells[tile][lane]
                );
            }
        }
        let (r1cs, witness) = b.build();
        BuiltK2Fixture {
            r1cs,
            witness,
            owner_cells,
            main_cells,
            bridge_row_start,
        }
    }

    #[test]
    fn selected_schedule_geometry_is_exact_and_sigma_does_not_alias() {
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner = schedules.owner_layout();
        let main = schedules.main_layout();
        assert_selected_layouts(&owner, &main);
        assert_eq!(owner.slots.len(), 118);
        assert_eq!(ZK_AUTH_OWNER_BRIDGE_SLOT, 117);
        assert_eq!(
            duplex_data_positions(&main)[..5],
            [(0, 1), (1, 0), (1, 1), (2, 0), (2, 1),]
        );
        assert_eq!(main.challenges[0], (2, 0));
    }

    #[test]
    fn real_duplex_columns_pin_honestly_in_exactly_four_rows() {
        let fixture = build_fixture(0x0A11_CE01, 0x0A11_CE02, None);
        assert_eq!(ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS, 4);
        assert_eq!(fixture.r1cs.useful_rows, fixture.bridge_row_start + 4);
        assert!(fixture.r1cs.satisfies(&fixture.witness));
        assert!(!fixture.main_cells.contains(&fixture.sigma_cell));
    }

    #[test]
    fn owner_and_main_committed_cell_tampering_rejects() {
        let fixture = build_fixture(0xC011_EC70, 0xC011_EC71, None);
        assert!(fixture.r1cs.satisfies(&fixture.witness));

        for (label, wire) in [
            ("Owner closing C cell", fixture.owner_cells[2]),
            ("Main bridge A cell", fixture.main_cells[1]),
        ] {
            let mut bad = fixture.witness.clone();
            bad[wire] += F128::ONE;
            assert!(!fixture.r1cs.satisfies(&bad), "{label} tamper survived");
        }
    }

    #[test]
    fn cross_owner_main_splice_rejects() {
        let fixture = build_fixture(0x51A7_E001, 0x51A7_E002, Some(0x51A7_E003));
        assert!(
            fixture
                .owner_cells
                .iter()
                .zip(fixture.main_cells)
                .any(|(&owner, main)| fixture.witness[owner] != fixture.witness[main]),
            "splice fixture accidentally reused the same bridge"
        );
        assert!(
            !fixture.r1cs.satisfies(&fixture.witness),
            "Main transcript spliced from another Owner was accepted"
        );
    }

    #[test]
    fn k2_union_pins_both_tiles_in_exactly_four_rows_each() {
        let fixture = build_k2_fixture([0, 1]);
        assert_eq!(
            fixture.r1cs.useful_rows,
            fixture.bridge_row_start + 2 * ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS
        );
        assert!(fixture.r1cs.satisfies(&fixture.witness));

        // Both transaction-relative bases are live constraints, on both sides
        // of the bridge. This catches a helper accidentally hard-coding tile 0.
        for tile in 0..2 {
            for (label, wire) in [
                ("Owner union tile", fixture.owner_cells[tile][tile + 1]),
                ("Main union tile", fixture.main_cells[tile][3 - tile]),
            ] {
                let mut bad = fixture.witness.clone();
                bad[wire] += F128::ONE;
                assert!(
                    !fixture.r1cs.satisfies(&bad),
                    "{label} {tile} mutation survived"
                );
            }
        }
    }

    #[test]
    fn k2_cross_tile_splice_rejects() {
        let fixture = build_k2_fixture([1, 0]);
        for tile in 0..2 {
            assert!(
                fixture.owner_cells[tile]
                    .iter()
                    .zip(fixture.main_cells[tile])
                    .any(|(&owner, main)| fixture.witness[owner] != fixture.witness[main]),
                "cross-tile splice fixture {tile} accidentally matched"
            );
        }
        assert!(
            !fixture.r1cs.satisfies(&fixture.witness),
            "cross-transaction Owner/Main bridge splice was accepted"
        );
    }

    #[test]
    fn indexed_k2_helper_pins_the_requested_transaction_base() {
        let native = native_k2_fixture([0xA700, 0xA701], [0xB700, 0xB701], [0, 1]);
        let mut b = FieldR1csBuilder::new();
        let owner_slices: [WitnessSlice; ZK_AUTH_BRIDGE_LANES] = std::array::from_fn(|lane| {
            alloc_column_slice(&mut b, &native.owner_c[lane], ZK_AUTH_OWNER_TILE_LOG + 1).0
        });
        let main_slices: [WitnessSlice; 2] = std::array::from_fn(|lane| {
            alloc_column_slice(&mut b, &native.main_a[lane], ZK_AUTH_MAIN_TILE_LOG + 1).0
        });
        let before = b.num_wires();
        let cells = pin_zk_auth_split_bridge_at(&mut b, &owner_slices, &main_slices, 1);
        assert_eq!(b.num_wires() - before, ZK_AUTH_SPLIT_BRIDGE_PIN_ROWS);
        assert_eq!(
            cells.owner_final_state[0].terms[0].0 as usize,
            owner_slices[0].start() + (1 << ZK_AUTH_OWNER_TILE_LOG) + ZK_AUTH_OWNER_BRIDGE_SLOT
        );
        assert_eq!(
            cells.main_absorb[0].terms[0].0 as usize,
            main_slices[1].start() + (1 << ZK_AUTH_MAIN_TILE_LOG)
        );
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
    }

    #[test]
    fn bridge_matrix_is_witness_invariant() {
        let left = build_fixture(0x1E57_0001, 0x1E57_0002, None);
        let right = build_fixture(0xA11C_0001, 0xA11C_0002, None);
        assert!(left.r1cs.satisfies(&left.witness));
        assert!(right.r1cs.satisfies(&right.witness));
        assert_eq!(left.r1cs.useful_rows, right.r1cs.useful_rows);
        assert_eq!(left.r1cs.a_0, right.r1cs.a_0);
        assert_eq!(left.r1cs.b_0, right.r1cs.b_0);
        assert_eq!(
            left.r1cs.structural_statement_digest(),
            right.r1cs.structural_statement_digest(),
            "bridge witness contents changed the R1CS matrix"
        );
    }
}
