// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! MLE column packing tests for the layered Poseidon2b witness.

use noid_core::mle::evaluate::evaluate_slice;
use noid_core::Block128;
use noid_gkr::layers::evaluate_permutation;
use noid_gkr::mle_layout::{
    index_to_point, pack_column, PermColumn, PermMle, N_PERM_CELLS, N_PERM_VARS,
};
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn rand_state(rng: &mut StdRng) -> [Block128; STATE_SIZE] {
    [
        Block128::from(rng.gen::<u128>()),
        Block128::from(rng.gen::<u128>()),
        Block128::from(rng.gen::<u128>()),
        Block128::from(rng.gen::<u128>()),
    ]
}

#[test]
fn column_mle_at_hypercube_vertex_returns_raw_cell() {
    let mut rng = StdRng::seed_from_u64(0x11);
    let w = evaluate_permutation(rand_state(&mut rng));

    for col in [
        PermColumn::State,
        PermColumn::Sin,
        PermColumn::X2,
        PermColumn::X3,
        PermColumn::X4,
        PermColumn::Sout,
    ] {
        let mle = pack_column(&w, col);
        assert_eq!(mle.len(), N_PERM_CELLS);

        // Check every active (row, lane) — MLE evaluated at the bit
        // vector of idx = (row<<2)|lane equals the raw witness cell.
        for row in 0..=N_ROUNDS {
            for lane in 0..STATE_SIZE {
                let idx = (row << 2) | lane;
                let point = index_to_point(idx);
                let v = evaluate_slice(&mle, &point);
                let expected = match col {
                    PermColumn::State => w.state[row][lane],
                    PermColumn::Sin => w.sin[row][lane],
                    PermColumn::X2 => w.x2[row][lane],
                    PermColumn::X3 => w.x3[row][lane],
                    PermColumn::X4 => w.x4[row][lane],
                    PermColumn::Sout => w.sout[row][lane],
                };
                assert_eq!(v, expected, "col {col:?} row={row} lane={lane}");
            }
        }
    }
}

#[test]
fn column_mle_at_padding_is_zero() {
    let mut rng = StdRng::seed_from_u64(0x22);
    let w = evaluate_permutation(rand_state(&mut rng));
    let mle = pack_column(&w, PermColumn::State);
    // Row 127 (last padded) must be zero on every lane.
    let padded_row = 127;
    for lane in 0..STATE_SIZE {
        let idx = (padded_row << 2) | lane;
        let point = index_to_point(idx);
        let v = evaluate_slice(&mle, &point);
        assert_eq!(v, Block128::from(0u128));
    }
}

#[test]
fn permmle_is_deterministic() {
    let input = [Block128::from(1u128); STATE_SIZE];
    let w1 = evaluate_permutation(input);
    let w2 = evaluate_permutation(input);
    let m1 = PermMle::from_witness(&w1);
    let m2 = PermMle::from_witness(&w2);
    assert_eq!(m1.state, m2.state);
    assert_eq!(m1.sin, m2.sin);
    assert_eq!(m1.x2, m2.x2);
    assert_eq!(m1.x3, m2.x3);
    assert_eq!(m1.x4, m2.x4);
    assert_eq!(m1.sout, m2.sout);
}

#[test]
fn n_perm_vars_matches_constants() {
    assert_eq!(N_PERM_VARS, 9);
    assert_eq!(N_PERM_CELLS, 512);
}
