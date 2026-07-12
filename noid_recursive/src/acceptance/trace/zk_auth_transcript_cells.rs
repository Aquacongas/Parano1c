// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Zero-row cell view of the selected tiled Owner/Main authorization
//! transcripts.
//!
//! The two duplex walks already commit their absorb (`A0/A1`) and carry
//! (`C0..C3`) columns.  Authorization algebra must consume those exact cells:
//! copying a transcript field into a fresh witness wire would both spend a row
//! and create a second value that has to be pinned.  This module instead maps
//! every dynamic field and every challenge through the compiled
//! [`DuplexLayout`] and returns raw one-wire [`LinExpr`] aliases.
//!
//! Owner tiles have stride `2^7`; Main tiles have stride `2^8`.  Larger column
//! domains are unions of an equal number of transaction tiles.  The view
//! validates that geometry, all twelve committed slices, and the complete
//! selected layouts before it exposes a cell.

use noid_ivc_core::deep_chain::schedule::{DuplexLayout, LaneSource};
use noid_ivc_core::public_io::WitnessSlice;

use super::region_source_binding::slot_cell;
use super::LinExpr;
use crate::acceptance::zk_auth_capsule_schedule::{
    ZkAuthCapsuleDuplexSchedules, ZK_AUTH_BETA_FIELDS, ZK_AUTH_BRIDGE_LANES,
    ZK_AUTH_MAIN_COMPILED_SLOTS, ZK_AUTH_MAIN_DYNAMIC_LANES, ZK_AUTH_MAIN_MID_CAP_DATA_START,
    ZK_AUTH_MAIN_NONCE_DATA_INDEX, ZK_AUTH_MAIN_PHASE_A_DATA_START,
    ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX, ZK_AUTH_MAIN_SIGMA_DATA_INDEX, ZK_AUTH_MAIN_SQUEEZES,
    ZK_AUTH_MAIN_TAIL_DATA_START, ZK_AUTH_MAIN_TILE_LOG, ZK_AUTH_MAIN_UPPER_DATA_START,
    ZK_AUTH_MID_CAP_LANES, ZK_AUTH_MLECHECK_ROUND_FIELDS, ZK_AUTH_MLECHECK_VARS,
    ZK_AUTH_OWNER_COMPILED_SLOTS, ZK_AUTH_OWNER_DYNAMIC_LANES,
    ZK_AUTH_OWNER_PUBLIC_STATEMENT_FIELDS, ZK_AUTH_OWNER_SQUEEZES, ZK_AUTH_OWNER_TILE_LOG,
    ZK_AUTH_PHASE_A_ROUND_FIELDS, ZK_AUTH_QUERY_SEEDS, ZK_AUTH_SOURCE_CAP_HASHES,
    ZK_AUTH_SOURCE_CAP_LANES, ZK_AUTH_TAIL_FIELDS, ZK_AUTH_TERMINAL_FIELDS, ZK_AUTH_UPPER_FIELDS,
};

pub const ZK_AUTH_OWNER_PUBLIC_STATEMENT_DATA_START: usize = 0;
pub const ZK_AUTH_OWNER_SOURCE_CAP_DATA_START: usize = 4;
pub const ZK_AUTH_OWNER_MASK_MU_DATA_INDEX: usize = 68;
pub const ZK_AUTH_OWNER_ROUND_DATA_START: usize = 69;
pub const ZK_AUTH_OWNER_MASK_FINAL_DATA_INDEX: usize = 179;
pub const ZK_AUTH_OWNER_OPERAND_CLAIMS_DATA_START: usize = 180;
pub const ZK_AUTH_OWNER_OPERAND_CLAIMS: usize = 5;

pub const ZK_AUTH_OWNER_RHO_CHALLENGE_START: usize = 0;
pub const ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX: usize = 11;
pub const ZK_AUTH_OWNER_ROUND_CHALLENGE_START: usize = 12;
pub const ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX: usize = 23;

pub const ZK_AUTH_MAIN_GAMMA_CHALLENGE_INDEX: usize = 0;
pub const ZK_AUTH_MAIN_PHASE_A_CHALLENGE_START: usize = 1;
pub const ZK_AUTH_MAIN_BETA_CHALLENGE_START: usize = 12;
pub const ZK_AUTH_MAIN_GRIND_CHALLENGE_INDEX: usize = 20;
pub const ZK_AUTH_MAIN_QUERY_SEED_CHALLENGE_START: usize = 21;

const _: () = assert!(ZK_AUTH_OWNER_PUBLIC_STATEMENT_DATA_START == 0);
const _: () = assert!(ZK_AUTH_OWNER_SOURCE_CAP_DATA_START == 4);
const _: () = assert!(ZK_AUTH_OWNER_SOURCE_CAP_DATA_START + ZK_AUTH_SOURCE_CAP_LANES == 68);
const _: () = assert!(ZK_AUTH_OWNER_MASK_MU_DATA_INDEX == 68);
const _: () = assert!(ZK_AUTH_OWNER_ROUND_DATA_START == 69);
const _: () = assert!(
    ZK_AUTH_OWNER_ROUND_DATA_START + ZK_AUTH_MLECHECK_VARS * ZK_AUTH_MLECHECK_ROUND_FIELDS
        == ZK_AUTH_OWNER_MASK_FINAL_DATA_INDEX
);
const _: () =
    assert!(ZK_AUTH_OWNER_MASK_FINAL_DATA_INDEX + 1 == ZK_AUTH_OWNER_OPERAND_CLAIMS_DATA_START);
const _: () = assert!(
    ZK_AUTH_OWNER_OPERAND_CLAIMS_DATA_START + ZK_AUTH_OWNER_OPERAND_CLAIMS
        == ZK_AUTH_OWNER_DYNAMIC_LANES
);
const _: () = assert!(ZK_AUTH_OWNER_OPERAND_CLAIMS + 1 == ZK_AUTH_TERMINAL_FIELDS);
const _: () = assert!(ZK_AUTH_OWNER_RHO_CHALLENGE_START == 0);
const _: () = assert!(ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX == ZK_AUTH_MLECHECK_VARS);
const _: () =
    assert!(ZK_AUTH_OWNER_ROUND_CHALLENGE_START == ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX + 1);
const _: () = assert!(
    ZK_AUTH_OWNER_ROUND_CHALLENGE_START + ZK_AUTH_MLECHECK_VARS
        == ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX
);
const _: () = assert!(ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX + 1 == ZK_AUTH_OWNER_SQUEEZES);

const _: () = assert!(ZK_AUTH_MAIN_SIGMA_DATA_INDEX == ZK_AUTH_BRIDGE_LANES);
const _: () = assert!(ZK_AUTH_MAIN_PHASE_A_DATA_START == 5);
const _: () = assert!(
    ZK_AUTH_MAIN_PHASE_A_DATA_START + ZK_AUTH_MLECHECK_VARS * ZK_AUTH_PHASE_A_ROUND_FIELDS
        == ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX
);
const _: () = assert!(ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX + 1 == ZK_AUTH_MAIN_UPPER_DATA_START);
const _: () = assert!(
    ZK_AUTH_MAIN_UPPER_DATA_START + ZK_AUTH_UPPER_FIELDS == ZK_AUTH_MAIN_MID_CAP_DATA_START
);
const _: () = assert!(
    ZK_AUTH_MAIN_MID_CAP_DATA_START + ZK_AUTH_MID_CAP_LANES == ZK_AUTH_MAIN_TAIL_DATA_START
);
const _: () =
    assert!(ZK_AUTH_MAIN_TAIL_DATA_START + ZK_AUTH_TAIL_FIELDS == ZK_AUTH_MAIN_NONCE_DATA_INDEX);
const _: () = assert!(ZK_AUTH_MAIN_NONCE_DATA_INDEX + 1 == ZK_AUTH_MAIN_DYNAMIC_LANES);
const _: () = assert!(ZK_AUTH_MAIN_GAMMA_CHALLENGE_INDEX == 0);
const _: () = assert!(ZK_AUTH_MAIN_PHASE_A_CHALLENGE_START == 1);
const _: () = assert!(
    ZK_AUTH_MAIN_PHASE_A_CHALLENGE_START + ZK_AUTH_MLECHECK_VARS
        == ZK_AUTH_MAIN_BETA_CHALLENGE_START
);
const _: () = assert!(
    ZK_AUTH_MAIN_BETA_CHALLENGE_START + ZK_AUTH_BETA_FIELDS == ZK_AUTH_MAIN_GRIND_CHALLENGE_INDEX
);
const _: () =
    assert!(ZK_AUTH_MAIN_GRIND_CHALLENGE_INDEX + 1 == ZK_AUTH_MAIN_QUERY_SEED_CHALLENGE_START);
const _: () =
    assert!(ZK_AUTH_MAIN_QUERY_SEED_CHALLENGE_START + ZK_AUTH_QUERY_SEEDS == ZK_AUTH_MAIN_SQUEEZES);

/// Dynamic Owner absorb cells and squeezed challenges for one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZkAuthOwnerTranscriptCells {
    pub public_statement: [LinExpr; ZK_AUTH_OWNER_PUBLIC_STATEMENT_FIELDS],
    /// Hash-major, lane-interleaved: `source_cap[2 * cap_index + digest_lane]`.
    pub source_cap: [LinExpr; ZK_AUTH_SOURCE_CAP_LANES],
    pub mask_mu: LinExpr,
    pub round_coefficients: [[LinExpr; ZK_AUTH_MLECHECK_ROUND_FIELDS]; ZK_AUTH_MLECHECK_VARS],
    pub mask_final: LinExpr,
    /// Padded `state_inc(r)` followed by padded lane operands 0 through 3.
    pub operand_claims: [LinExpr; ZK_AUTH_OWNER_OPERAND_CLAIMS],
    pub rho: [LinExpr; ZK_AUTH_MLECHECK_VARS],
    pub lambda: LinExpr,
    /// Owner MLE-check challenges in transcript HIGH-to-LOW round order.
    pub round_challenges: [LinExpr; ZK_AUTH_MLECHECK_VARS],
    pub eta: LinExpr,
}

impl ZkAuthOwnerTranscriptCells {
    /// Phase-B's `[digest_lane][cap_index]` view of the same source-cap cells.
    pub(crate) fn source_cap_by_digest_lane(&self) -> [[LinExpr; ZK_AUTH_SOURCE_CAP_HASHES]; 2] {
        std::array::from_fn(|lane| {
            std::array::from_fn(|node| self.source_cap[2 * node + lane].clone())
        })
    }
}

/// Dynamic Main absorb cells and squeezed challenges for one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZkAuthMainTranscriptCells {
    /// Derived Owner closing state, absorbed as Main data lanes 0 through 3.
    pub bridge: [LinExpr; ZK_AUTH_BRIDGE_LANES],
    pub sigma: LinExpr,
    pub phase_a_round_coefficients:
        [[LinExpr; ZK_AUTH_PHASE_A_ROUND_FIELDS]; ZK_AUTH_MLECHECK_VARS],
    pub phase_b_value: LinExpr,
    pub upper: [LinExpr; ZK_AUTH_UPPER_FIELDS],
    /// Hash-major, lane-interleaved: `mid_cap[2 * cap_index + digest_lane]`.
    pub mid_cap: [LinExpr; ZK_AUTH_MID_CAP_LANES],
    pub tail: [LinExpr; ZK_AUTH_TAIL_FIELDS],
    pub nonce: LinExpr,
    pub gamma: LinExpr,
    /// Phase-A challenges in transcript HIGH-to-LOW round order.
    pub phase_a_challenges: [LinExpr; ZK_AUTH_MLECHECK_VARS],
    pub beta: [LinExpr; ZK_AUTH_BETA_FIELDS],
    pub grind: LinExpr,
    pub query_seeds: [LinExpr; ZK_AUTH_QUERY_SEEDS],
}

impl ZkAuthMainTranscriptCells {
    /// Phase-B's `[digest_lane][cap_index]` view of the same mid-cap cells.
    pub(crate) fn mid_cap_by_digest_lane(&self) -> [[LinExpr; ZK_AUTH_MID_CAP_LANES / 2]; 2] {
        std::array::from_fn(|lane| {
            std::array::from_fn(|node| self.mid_cap[2 * node + lane].clone())
        })
    }
}

/// Alias-only view of both disconnected transcript tiles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZkAuthTranscriptCells {
    pub owner: ZkAuthOwnerTranscriptCells,
    pub main: ZkAuthMainTranscriptCells,
}

fn assert_layout_eq(actual: &DuplexLayout, selected: &DuplexLayout, name: &str) {
    assert_eq!(actual.n_data, selected.n_data, "{name} data-count drift");
    assert_eq!(
        actual.challenges, selected.challenges,
        "{name} challenge placement drift"
    );
    assert_eq!(
        actual.slots.len(),
        selected.slots.len(),
        "{name} slot-count drift"
    );
    for (slot, (actual, selected)) in actual.slots.iter().zip(&selected.slots).enumerate() {
        assert_eq!(
            actual.lanes, selected.lanes,
            "{name} absorb placement drift at slot {slot}"
        );
    }
}

fn assert_selected_layouts(owner: &DuplexLayout, main: &DuplexLayout) {
    let selected = ZkAuthCapsuleDuplexSchedules::selected();
    let selected_owner = selected.owner_layout();
    let selected_main = selected.main_layout();
    assert_layout_eq(owner, &selected_owner, "Owner");
    assert_layout_eq(main, &selected_main, "Main");
    assert_eq!(owner.n_data, ZK_AUTH_OWNER_DYNAMIC_LANES);
    assert_eq!(main.n_data, ZK_AUTH_MAIN_DYNAMIC_LANES);
    assert_eq!(owner.challenges.len(), ZK_AUTH_OWNER_SQUEEZES);
    assert_eq!(main.challenges.len(), ZK_AUTH_MAIN_SQUEEZES);
    assert_eq!(owner.slots.len(), ZK_AUTH_OWNER_COMPILED_SLOTS);
    assert_eq!(main.slots.len(), ZK_AUTH_MAIN_COMPILED_SLOTS);
}

fn checked_range(slice: &WitnessSlice) -> std::ops::Range<usize> {
    let start = slice.start();
    let end = start
        .checked_add(slice.len())
        .expect("duplex witness slice range overflow");
    assert!(
        end <= u32::MAX as usize,
        "duplex witness slice exceeds LinExpr wire address space"
    );
    start..end
}

fn assert_pairwise_disjoint(slices: &[WitnessSlice]) {
    for (index, left) in slices.iter().enumerate() {
        let left = checked_range(left);
        for right in &slices[index + 1..] {
            let right = checked_range(right);
            assert!(
                left.end <= right.start || right.end <= left.start,
                "Owner/Main duplex columns must occupy disjoint witness slices"
            );
        }
    }
}

fn validate_column_slices(
    owner_a: &[WitnessSlice; 2],
    owner_c: &[WitnessSlice; 4],
    main_a: &[WitnessSlice; 2],
    main_c: &[WitnessSlice; 4],
) -> usize {
    let owner = owner_a
        .iter()
        .chain(owner_c.iter())
        .copied()
        .collect::<Vec<_>>();
    let main = main_a
        .iter()
        .chain(main_c.iter())
        .copied()
        .collect::<Vec<_>>();
    assert!(
        owner
            .iter()
            .all(|slice| slice.log2_len >= ZK_AUTH_OWNER_TILE_LOG),
        "Owner columns must contain at least one selected m7 tile"
    );
    assert!(
        main.iter()
            .all(|slice| slice.log2_len >= ZK_AUTH_MAIN_TILE_LOG),
        "Main columns must contain at least one selected m8 tile"
    );
    assert!(
        owner
            .iter()
            .all(|slice| slice.log2_len == owner[0].log2_len),
        "Owner A/C columns must share one tiled domain"
    );
    assert!(
        main.iter().all(|slice| slice.log2_len == main[0].log2_len),
        "Main A/C columns must share one tiled domain"
    );

    let owner_tiles = 1usize << (owner[0].log2_len - ZK_AUTH_OWNER_TILE_LOG);
    let main_tiles = 1usize << (main[0].log2_len - ZK_AUTH_MAIN_TILE_LOG);
    assert_eq!(
        owner_tiles, main_tiles,
        "Owner and Main duplex unions must have equal tile counts"
    );

    let all = owner.into_iter().chain(main).collect::<Vec<_>>();
    assert_pairwise_disjoint(&all);
    owner_tiles
}

/// Return data-index -> `(slot, A lane)` from the compiled schedule.
///
/// This deliberately rejects duplicates and holes instead of allowing a
/// default physical cell to stand in for a malformed layout.
fn data_positions(layout: &DuplexLayout) -> Vec<(usize, usize)> {
    let mut positions = vec![None; layout.n_data];
    for (slot, descriptor) in layout.slots.iter().enumerate() {
        for (lane, source) in descriptor.lanes.iter().enumerate() {
            if let Some(LaneSource::Data(index)) = source {
                assert!(*index < positions.len(), "duplex data index out of range");
                assert!(
                    positions[*index].replace((slot, lane)).is_none(),
                    "duplicate duplex data index {index}"
                );
            }
        }
    }
    positions
        .into_iter()
        .enumerate()
        .map(|(index, position)| {
            position.unwrap_or_else(|| panic!("missing duplex data index {index}"))
        })
        .collect()
}

fn data_aliases(
    layout: &DuplexLayout,
    columns: &[WitnessSlice; 2],
    tile_base: usize,
) -> Vec<LinExpr> {
    data_positions(layout)
        .into_iter()
        .map(|(slot, lane)| slot_cell(&columns[lane], tile_base + slot))
        .collect()
}

fn challenge_aliases(
    layout: &DuplexLayout,
    columns: &[WitnessSlice; 4],
    tile_base: usize,
) -> Vec<LinExpr> {
    layout
        .challenges
        .iter()
        .map(|&(slot, lane)| {
            assert!(
                lane < columns.len(),
                "duplex challenge carry lane out of range"
            );
            assert!(
                slot < layout.slots.len(),
                "duplex challenge slot out of range"
            );
            slot_cell(&columns[lane], tile_base + slot)
        })
        .collect()
}

/// Build the zero-row transcript-cell view for one selected transaction tile.
///
/// The supplied layouts must be byte-for-byte equivalent to the selected
/// Owner/Main compiled layouts.  Each family may use a larger tiled domain,
/// but all six columns in that family must have the same log-domain; Owner and
/// Main must encode the same number of transaction tiles.  All twelve slices
/// must be pairwise disjoint.
///
/// This function has no builder parameter and cannot allocate or constrain a
/// row.  Every returned expression is a one-wire alias of an existing A/C
/// committed cell selected through `layout.slots` or `layout.challenges`.
pub(crate) fn view_zk_auth_transcript_tile(
    owner_layout: &DuplexLayout,
    owner_a: &[WitnessSlice; 2],
    owner_c: &[WitnessSlice; 4],
    main_layout: &DuplexLayout,
    main_a: &[WitnessSlice; 2],
    main_c: &[WitnessSlice; 4],
    tile_index: usize,
) -> ZkAuthTranscriptCells {
    assert_selected_layouts(owner_layout, main_layout);
    let tile_count = validate_column_slices(owner_a, owner_c, main_a, main_c);
    assert!(
        tile_index < tile_count,
        "transcript tile index out of range"
    );

    let owner_data = data_aliases(owner_layout, owner_a, tile_index << ZK_AUTH_OWNER_TILE_LOG);
    let owner_challenges =
        challenge_aliases(owner_layout, owner_c, tile_index << ZK_AUTH_OWNER_TILE_LOG);
    let main_data = data_aliases(main_layout, main_a, tile_index << ZK_AUTH_MAIN_TILE_LOG);
    let main_challenges =
        challenge_aliases(main_layout, main_c, tile_index << ZK_AUTH_MAIN_TILE_LOG);

    let owner = ZkAuthOwnerTranscriptCells {
        public_statement: std::array::from_fn(|index| {
            owner_data[ZK_AUTH_OWNER_PUBLIC_STATEMENT_DATA_START + index].clone()
        }),
        source_cap: std::array::from_fn(|index| {
            owner_data[ZK_AUTH_OWNER_SOURCE_CAP_DATA_START + index].clone()
        }),
        mask_mu: owner_data[ZK_AUTH_OWNER_MASK_MU_DATA_INDEX].clone(),
        round_coefficients: std::array::from_fn(|round| {
            std::array::from_fn(|coefficient| {
                owner_data[ZK_AUTH_OWNER_ROUND_DATA_START
                    + round * ZK_AUTH_MLECHECK_ROUND_FIELDS
                    + coefficient]
                    .clone()
            })
        }),
        mask_final: owner_data[ZK_AUTH_OWNER_MASK_FINAL_DATA_INDEX].clone(),
        operand_claims: std::array::from_fn(|index| {
            owner_data[ZK_AUTH_OWNER_OPERAND_CLAIMS_DATA_START + index].clone()
        }),
        rho: std::array::from_fn(|index| {
            owner_challenges[ZK_AUTH_OWNER_RHO_CHALLENGE_START + index].clone()
        }),
        lambda: owner_challenges[ZK_AUTH_OWNER_LAMBDA_CHALLENGE_INDEX].clone(),
        round_challenges: std::array::from_fn(|round| {
            owner_challenges[ZK_AUTH_OWNER_ROUND_CHALLENGE_START + round].clone()
        }),
        eta: owner_challenges[ZK_AUTH_OWNER_ETA_CHALLENGE_INDEX].clone(),
    };

    let main = ZkAuthMainTranscriptCells {
        bridge: std::array::from_fn(|index| main_data[index].clone()),
        sigma: main_data[ZK_AUTH_MAIN_SIGMA_DATA_INDEX].clone(),
        phase_a_round_coefficients: std::array::from_fn(|round| {
            std::array::from_fn(|coefficient| {
                main_data[ZK_AUTH_MAIN_PHASE_A_DATA_START
                    + round * ZK_AUTH_PHASE_A_ROUND_FIELDS
                    + coefficient]
                    .clone()
            })
        }),
        phase_b_value: main_data[ZK_AUTH_MAIN_PHASE_B_VALUE_DATA_INDEX].clone(),
        upper: std::array::from_fn(|index| {
            main_data[ZK_AUTH_MAIN_UPPER_DATA_START + index].clone()
        }),
        mid_cap: std::array::from_fn(|index| {
            main_data[ZK_AUTH_MAIN_MID_CAP_DATA_START + index].clone()
        }),
        tail: std::array::from_fn(|index| main_data[ZK_AUTH_MAIN_TAIL_DATA_START + index].clone()),
        nonce: main_data[ZK_AUTH_MAIN_NONCE_DATA_INDEX].clone(),
        gamma: main_challenges[ZK_AUTH_MAIN_GAMMA_CHALLENGE_INDEX].clone(),
        phase_a_challenges: std::array::from_fn(|round| {
            main_challenges[ZK_AUTH_MAIN_PHASE_A_CHALLENGE_START + round].clone()
        }),
        beta: std::array::from_fn(|index| {
            main_challenges[ZK_AUTH_MAIN_BETA_CHALLENGE_START + index].clone()
        }),
        grind: main_challenges[ZK_AUTH_MAIN_GRIND_CHALLENGE_INDEX].clone(),
        query_seeds: std::array::from_fn(|index| {
            main_challenges[ZK_AUTH_MAIN_QUERY_SEED_CHALLENGE_START + index].clone()
        }),
    };

    ZkAuthTranscriptCells { owner, main }
}

#[cfg(test)]
mod tests {
    use noid_ivc_core::deep_chain::schedule::{build_duplex_columns, flat_of_tower_u128};
    use noid_ivc_core::field::F128;
    use noid_ivc_core::field_circuit::FieldR1csBuilder;
    use noid_poseidon2b::native::domain::{capacity_iv, TAG_KSCHANNL};

    use super::super::region_source_binding::alloc_column_slice;
    use super::*;

    fn sample(seed: u128, index: usize) -> F128 {
        flat_of_tower_u128(
            seed.wrapping_add(
                0x9E37_79B9_7F4A_7C15_6C8E_9CF5_7093_2BD5u128.wrapping_mul(index as u128 + 1),
            )
            .rotate_left(((19 * index + 7) % 127) as u32),
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

    fn flatten_owner_data(cells: &ZkAuthOwnerTranscriptCells) -> Vec<LinExpr> {
        let mut out = Vec::with_capacity(ZK_AUTH_OWNER_DYNAMIC_LANES);
        out.extend(cells.public_statement.iter().cloned());
        out.extend(cells.source_cap.iter().cloned());
        out.push(cells.mask_mu.clone());
        for round in &cells.round_coefficients {
            out.extend(round.iter().cloned());
        }
        out.push(cells.mask_final.clone());
        out.extend(cells.operand_claims.iter().cloned());
        out
    }

    fn flatten_owner_challenges(cells: &ZkAuthOwnerTranscriptCells) -> Vec<LinExpr> {
        let mut out = Vec::with_capacity(ZK_AUTH_OWNER_SQUEEZES);
        out.extend(cells.rho.iter().cloned());
        out.push(cells.lambda.clone());
        out.extend(cells.round_challenges.iter().cloned());
        out.push(cells.eta.clone());
        out
    }

    fn flatten_main_data(cells: &ZkAuthMainTranscriptCells) -> Vec<LinExpr> {
        let mut out = Vec::with_capacity(ZK_AUTH_MAIN_DYNAMIC_LANES);
        out.extend(cells.bridge.iter().cloned());
        out.push(cells.sigma.clone());
        for round in &cells.phase_a_round_coefficients {
            out.extend(round.iter().cloned());
        }
        out.push(cells.phase_b_value.clone());
        out.extend(cells.upper.iter().cloned());
        out.extend(cells.mid_cap.iter().cloned());
        out.extend(cells.tail.iter().cloned());
        out.push(cells.nonce.clone());
        out
    }

    fn flatten_main_challenges(cells: &ZkAuthMainTranscriptCells) -> Vec<LinExpr> {
        let mut out = Vec::with_capacity(ZK_AUTH_MAIN_SQUEEZES);
        out.push(cells.gamma.clone());
        out.extend(cells.phase_a_challenges.iter().cloned());
        out.extend(cells.beta.iter().cloned());
        out.push(cells.grind.clone());
        out.extend(cells.query_seeds.iter().cloned());
        out
    }

    fn assert_alias(expr: &LinExpr, wire: usize, expected: F128, values: &[F128]) {
        assert_eq!(expr.terms, vec![(wire as u32, F128::ONE)]);
        assert_eq!(expr.constant, F128::ZERO);
        assert_eq!(expr.eval(values), expected);
    }

    struct BuiltFixture {
        builder: FieldR1csBuilder,
        owner_layout: DuplexLayout,
        main_layout: DuplexLayout,
        owner_a: [WitnessSlice; 2],
        owner_c: [WitnessSlice; 4],
        main_a: [WitnessSlice; 2],
        main_c: [WitnessSlice; 4],
        owner_data: Vec<Vec<F128>>,
        owner_challenges: Vec<Vec<F128>>,
        main_data: Vec<Vec<F128>>,
        main_challenges: Vec<Vec<F128>>,
    }

    fn build_fixture(tile_count: usize, salt: u128) -> BuiltFixture {
        assert!(tile_count.is_power_of_two());
        let tile_log = tile_count.trailing_zeros() as usize;
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner_layout = schedules.owner_layout();
        let main_layout = schedules.main_layout();

        let mut owner_data = Vec::with_capacity(tile_count);
        let mut owner_challenges = Vec::with_capacity(tile_count);
        let mut main_data = Vec::with_capacity(tile_count);
        let mut main_challenges = Vec::with_capacity(tile_count);
        let mut owner_columns_a: [Vec<F128>; 2] = std::array::from_fn(|_| Vec::new());
        let mut owner_columns_c: [Vec<F128>; 4] = std::array::from_fn(|_| Vec::new());
        let mut main_columns_a: [Vec<F128>; 2] = std::array::from_fn(|_| Vec::new());
        let mut main_columns_c: [Vec<F128>; 4] = std::array::from_fn(|_| Vec::new());

        for tile in 0..tile_count {
            let owner_stream = stream(&owner_layout, salt ^ (tile as u128 + 1) * 0x101);
            let owner = build_duplex_columns(
                &owner_layout,
                iv_flat(),
                &owner_stream,
                ZK_AUTH_OWNER_TILE_LOG,
            );
            let mut main_stream = stream(&main_layout, salt ^ (tile as u128 + 1) * 0x10001);
            for lane in 0..ZK_AUTH_BRIDGE_LANES {
                main_stream[lane] = owner.c[lane][owner_layout.slots.len() - 1];
            }
            let main =
                build_duplex_columns(&main_layout, iv_flat(), &main_stream, ZK_AUTH_MAIN_TILE_LOG);

            for lane in 0..2 {
                owner_columns_a[lane].extend_from_slice(&owner.a[lane]);
                main_columns_a[lane].extend_from_slice(&main.a[lane]);
            }
            for lane in 0..4 {
                owner_columns_c[lane].extend_from_slice(&owner.c[lane]);
                main_columns_c[lane].extend_from_slice(&main.c[lane]);
            }
            owner_data.push(owner_stream);
            owner_challenges.push(owner.challenges);
            main_data.push(main_stream);
            main_challenges.push(main.challenges);
        }

        let mut builder = FieldR1csBuilder::new();
        let owner_log = ZK_AUTH_OWNER_TILE_LOG + tile_log;
        let main_log = ZK_AUTH_MAIN_TILE_LOG + tile_log;
        let owner_a = std::array::from_fn(|lane| {
            alloc_column_slice(&mut builder, &owner_columns_a[lane], owner_log).0
        });
        let owner_c = std::array::from_fn(|lane| {
            alloc_column_slice(&mut builder, &owner_columns_c[lane], owner_log).0
        });
        let main_a = std::array::from_fn(|lane| {
            alloc_column_slice(&mut builder, &main_columns_a[lane], main_log).0
        });
        let main_c = std::array::from_fn(|lane| {
            alloc_column_slice(&mut builder, &main_columns_c[lane], main_log).0
        });

        BuiltFixture {
            builder,
            owner_layout,
            main_layout,
            owner_a,
            owner_c,
            main_a,
            main_c,
            owner_data,
            owner_challenges,
            main_data,
            main_challenges,
        }
    }

    fn assert_complete_mapping(fixture: &BuiltFixture, tile: usize, cells: &ZkAuthTranscriptCells) {
        let values = fixture.builder.values();
        let owner_base = tile << ZK_AUTH_OWNER_TILE_LOG;
        let main_base = tile << ZK_AUTH_MAIN_TILE_LOG;
        let owner_positions = data_positions(&fixture.owner_layout);
        let main_positions = data_positions(&fixture.main_layout);

        let owner_data = flatten_owner_data(&cells.owner);
        let owner_challenges = flatten_owner_challenges(&cells.owner);
        let main_data = flatten_main_data(&cells.main);
        let main_challenges = flatten_main_challenges(&cells.main);
        assert_eq!(owner_data.len(), ZK_AUTH_OWNER_DYNAMIC_LANES);
        assert_eq!(owner_challenges.len(), ZK_AUTH_OWNER_SQUEEZES);
        assert_eq!(main_data.len(), ZK_AUTH_MAIN_DYNAMIC_LANES);
        assert_eq!(main_challenges.len(), ZK_AUTH_MAIN_SQUEEZES);

        for (index, expr) in owner_data.iter().enumerate() {
            let (slot, lane) = owner_positions[index];
            assert_alias(
                expr,
                fixture.owner_a[lane].start() + owner_base + slot,
                fixture.owner_data[tile][index],
                values,
            );
        }
        for (index, expr) in owner_challenges.iter().enumerate() {
            let (slot, lane) = fixture.owner_layout.challenges[index];
            assert_alias(
                expr,
                fixture.owner_c[lane].start() + owner_base + slot,
                fixture.owner_challenges[tile][index],
                values,
            );
        }
        for (index, expr) in main_data.iter().enumerate() {
            let (slot, lane) = main_positions[index];
            assert_alias(
                expr,
                fixture.main_a[lane].start() + main_base + slot,
                fixture.main_data[tile][index],
                values,
            );
        }
        for (index, expr) in main_challenges.iter().enumerate() {
            let (slot, lane) = fixture.main_layout.challenges[index];
            assert_alias(
                expr,
                fixture.main_c[lane].start() + main_base + slot,
                fixture.main_challenges[tile][index],
                values,
            );
        }
    }

    #[test]
    fn k1_real_duplex_columns_map_every_cell_in_zero_rows() {
        let fixture = build_fixture(1, 0xA11C_E001);
        let before = fixture.builder.num_wires();
        let cells = view_zk_auth_transcript_tile(
            &fixture.owner_layout,
            &fixture.owner_a,
            &fixture.owner_c,
            &fixture.main_layout,
            &fixture.main_a,
            &fixture.main_c,
            0,
        );
        assert_eq!(fixture.builder.num_wires(), before);
        assert_complete_mapping(&fixture, 0, &cells);

        let source_by_lane = cells.owner.source_cap_by_digest_lane();
        for lane in 0..2 {
            for node in 0..ZK_AUTH_SOURCE_CAP_HASHES {
                assert_eq!(
                    source_by_lane[lane][node],
                    cells.owner.source_cap[2 * node + lane]
                );
            }
        }
        let mid_by_lane = cells.main.mid_cap_by_digest_lane();
        for lane in 0..2 {
            for node in 0..ZK_AUTH_MID_CAP_LANES / 2 {
                assert_eq!(mid_by_lane[lane][node], cells.main.mid_cap[2 * node + lane]);
            }
        }
        for bridge in &cells.main.bridge {
            assert_ne!(bridge, &cells.main.sigma, "sigma aliases a bridge cell");
        }
    }

    #[test]
    fn k2_real_duplex_columns_preserve_tile_isolation_in_zero_rows() {
        let fixture = build_fixture(2, 0x715E_1A7E);
        let before = fixture.builder.num_wires();
        let tile0 = view_zk_auth_transcript_tile(
            &fixture.owner_layout,
            &fixture.owner_a,
            &fixture.owner_c,
            &fixture.main_layout,
            &fixture.main_a,
            &fixture.main_c,
            0,
        );
        let tile1 = view_zk_auth_transcript_tile(
            &fixture.owner_layout,
            &fixture.owner_a,
            &fixture.owner_c,
            &fixture.main_layout,
            &fixture.main_a,
            &fixture.main_c,
            1,
        );
        assert_eq!(fixture.builder.num_wires(), before);
        assert_complete_mapping(&fixture, 0, &tile0);
        assert_complete_mapping(&fixture, 1, &tile1);

        for (left, right) in flatten_owner_data(&tile0.owner)
            .iter()
            .zip(flatten_owner_data(&tile1.owner))
        {
            assert_ne!(left, &right, "Owner tile aliases overlap");
        }
        for (left, right) in flatten_main_challenges(&tile0.main)
            .iter()
            .zip(flatten_main_challenges(&tile1.main))
        {
            assert_ne!(left, &right, "Main tile aliases overlap");
        }
    }

    fn built_matrix(salt: u128) -> noid_ivc_core::field_r1cs::FieldR1cs {
        let fixture = build_fixture(1, salt);
        let before = fixture.builder.num_wires();
        let _ = view_zk_auth_transcript_tile(
            &fixture.owner_layout,
            &fixture.owner_a,
            &fixture.owner_c,
            &fixture.main_layout,
            &fixture.main_a,
            &fixture.main_c,
            0,
        );
        assert_eq!(fixture.builder.num_wires(), before);
        fixture.builder.build().0
    }

    #[test]
    fn alias_view_is_matrix_and_witness_value_invariant() {
        let left = built_matrix(0x1111_2222);
        let right = built_matrix(0xAAAA_BBBB);
        assert_eq!(left.useful_rows, right.useful_rows);
        assert_eq!(left.a_0, right.a_0);
        assert_eq!(left.b_0, right.b_0);
        assert_eq!(
            left.structural_statement_digest(),
            right.structural_statement_digest()
        );
    }

    #[test]
    fn selected_schedule_drift_is_rejected_before_mapping() {
        let fixture = build_fixture(1, 0x5C4E_DA1F);
        let mut owner = fixture.owner_layout.clone();
        owner.challenges[0].0 += 1;
        let rejected = std::panic::catch_unwind(|| {
            view_zk_auth_transcript_tile(
                &owner,
                &fixture.owner_a,
                &fixture.owner_c,
                &fixture.main_layout,
                &fixture.main_a,
                &fixture.main_c,
                0,
            )
        });
        assert!(
            rejected.is_err(),
            "Owner challenge-placement drift survived"
        );

        let mut main = fixture.main_layout.clone();
        main.slots[0].lanes[1] = Some(LaneSource::Data(1));
        let rejected = std::panic::catch_unwind(|| {
            view_zk_auth_transcript_tile(
                &fixture.owner_layout,
                &fixture.owner_a,
                &fixture.owner_c,
                &main,
                &fixture.main_a,
                &fixture.main_c,
                0,
            )
        });
        assert!(rejected.is_err(), "Main absorb-placement drift survived");
    }
}
