// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::needless_range_loop)]

//! Layered witness tests — the layered witness must byte-equal native
//! Poseidon2b on the final state, and each S-box / MDS sub-relation
//! must hold row-by-row, lane-by-lane.

use noid_core::Block128;
use noid_gkr::layers::{
    apply_mds_full, apply_mds_partial, evaluate_permutation, round_kind, PermLayerWitness,
    RoundKind,
};
use noid_poseidon2b::native::permutation::{
    sbox_x7, Poseidon2bPermutation, F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS,
    ROUND_CONSTANTS, STATE_SIZE,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const ZERO: Block128 = Block128(0u128);

fn rand_state(rng: &mut StdRng) -> [Block128; STATE_SIZE] {
    [
        Block128::from(rng.gen::<u128>()),
        Block128::from(rng.gen::<u128>()),
        Block128::from(rng.gen::<u128>()),
        Block128::from(rng.gen::<u128>()),
    ]
}

fn native_permute(input: [Block128; STATE_SIZE]) -> [Block128; STATE_SIZE] {
    let mut s = input;
    Poseidon2bPermutation.permute_mut(&mut s);
    s
}

#[test]
fn witness_final_state_matches_native_random() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    for _ in 0..100 {
        let input = rand_state(&mut rng);
        let w = evaluate_permutation(input);
        assert_eq!(w.n_rows(), N_ROUNDS + 1);
        assert_eq!(w.final_state(), native_permute(input));
    }
}

#[test]
fn witness_final_state_matches_native_edge_cases() {
    let cases = [
        [ZERO, ZERO, ZERO, ZERO],
        [Block128::from(1u128), ZERO, ZERO, ZERO],
        [ZERO, ZERO, ZERO, Block128::from(u128::MAX)],
        [
            Block128::from(u128::MAX),
            Block128::from(u128::MAX),
            Block128::from(u128::MAX),
            Block128::from(u128::MAX),
        ],
    ];
    for input in cases {
        let w = evaluate_permutation(input);
        assert_eq!(w.final_state(), native_permute(input));
    }
}

#[test]
fn sbox_x7_relations_hold_every_round() {
    let mut rng = StdRng::seed_from_u64(0xABCD);
    let w = evaluate_permutation(rand_state(&mut rng));

    for r in 0..N_ROUNDS {
        let kind = w.kind[r];
        for lane in 0..STATE_SIZE {
            let sin = w.sin[r][lane];
            let x2 = w.x2[r][lane];
            let x4 = w.x4[r][lane];
            let x3 = w.x3[r][lane];
            let sout = w.sout[r][lane];

            if kind == RoundKind::Partial && lane != 0 {
                // Lanes 1..3 are zeroed on partial rows (matches AIR).
                assert_eq!(sin, ZERO, "partial row {r} lane {lane}: sin");
                assert_eq!(x2, ZERO);
                assert_eq!(x4, ZERO);
                assert_eq!(x3, ZERO);
                assert_eq!(sout, ZERO);
                continue;
            }

            // sin = state + rc
            let rc = Block128::from(ROUND_CONSTANTS[lane][r]);
            assert_eq!(sin, w.state[r][lane] + rc, "sin at r={r} l={lane}");
            // S-box relations.
            assert_eq!(x2, sin * sin, "x2 at r={r} l={lane}");
            assert_eq!(x4, x2 * x2, "x4 at r={r} l={lane}");
            assert_eq!(x3, x2 * sin, "x3 at r={r} l={lane}");
            assert_eq!(sout, x4 * x3, "sout at r={r} l={lane}");
            assert_eq!(sout, sbox_x7(sin), "sout==x^7 at r={r} l={lane}");
        }
    }
}

#[test]
fn mds_blend_matches_schedule() {
    let mut rng = StdRng::seed_from_u64(0xDEED);
    let w = evaluate_permutation(rand_state(&mut rng));

    // For every round, state[r+1] must equal the correct MDS of the
    // corresponding S-box output, chosen by round kind.
    for r in 0..N_ROUNDS {
        let expected_next = match w.kind[r] {
            RoundKind::Full => {
                let mut v = w.sout[r];
                apply_mds_full(&mut v);
                v
            }
            RoundKind::Partial => {
                // Partial-round MDS input: lane 0 is sout[0], lanes
                // 1..3 are the raw state (not the zeroed S-box cells).
                let input = [w.sout[r][0], w.state[r][1], w.state[r][2], w.state[r][3]];
                apply_mds_partial(input)
            }
        };
        assert_eq!(w.state[r + 1], expected_next, "state transition at r={r}");
    }
}

#[test]
fn partial_round_sbox_kill() {
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    let w = evaluate_permutation(rand_state(&mut rng));
    for r in (F_ROUNDS / 2)..(F_ROUNDS / 2 + P_ROUNDS) {
        assert_eq!(w.kind[r], RoundKind::Partial);
        for lane in 1..STATE_SIZE {
            assert_eq!(w.sin[r][lane], ZERO);
            assert_eq!(w.x2[r][lane], ZERO);
            assert_eq!(w.x3[r][lane], ZERO);
            assert_eq!(w.x4[r][lane], ZERO);
            assert_eq!(w.sout[r][lane], ZERO);
        }
    }
}

#[test]
fn round_kind_schedule_is_4_58_4() {
    let full_head = (0..F_ROUNDS / 2)
        .filter(|&r| round_kind(r) == RoundKind::Full)
        .count();
    let partial_mid = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS)
        .filter(|&r| round_kind(r) == RoundKind::Partial)
        .count();
    let full_tail = (F_ROUNDS / 2 + P_ROUNDS..N_ROUNDS)
        .filter(|&r| round_kind(r) == RoundKind::Full)
        .count();
    assert_eq!(full_head, 4);
    assert_eq!(partial_mid, 58);
    assert_eq!(full_tail, 4);
    assert_eq!(full_head + partial_mid + full_tail, N_ROUNDS);
}

#[test]
fn mds_helpers_are_deterministic() {
    // Sanity on the re-derived helpers vs. the library constants.
    let mut rng = StdRng::seed_from_u64(0xF00D);
    let s: [Block128; STATE_SIZE] = rand_state(&mut rng);
    let mut a = s;
    apply_mds_full(&mut a);
    let mut b = s;
    apply_mds_full(&mut b);
    assert_eq!(a, b);

    let c = apply_mds_partial(s);
    let d = apply_mds_partial(s);
    assert_eq!(c, d);

    // Sanity that the helpers actually read MDS_FULL / MDS_PARTIAL.
    // `MDS_FULL[0][0] = 5`: if we zero every input but lane 0 and set
    // lane 0 = 1, output[0] must equal 5.
    let one = Block128::from(1u128);
    let zero = ZERO;
    let mut probe = [one, zero, zero, zero];
    apply_mds_full(&mut probe);
    assert_eq!(probe[0], Block128::from(MDS_FULL[0][0]));

    let probe_p = apply_mds_partial([one, zero, zero, zero]);
    assert_eq!(probe_p[0], Block128::from(MDS_PARTIAL[0][0]));
}

#[test]
fn witness_state_row_zero_is_post_initial_mds() {
    // Native: state_0 = MDS_FULL(input). Witness row 0 must match.
    let mut rng = StdRng::seed_from_u64(0x1234);
    let input = rand_state(&mut rng);
    let w: PermLayerWitness = evaluate_permutation(input);

    let mut expected = input;
    apply_mds_full(&mut expected);
    assert_eq!(w.state[0], expected);
}
