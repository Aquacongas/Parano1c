// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3c-1.2 — S-box `x^7` chain as an AIR sub-circuit.
//!
//! Native reference: `noid_poseidon2b::native::permutation::sbox_x7`,
//!
//! ```text
//! x2 = x  · x        (square)
//! x4 = x2 · x2       (square)
//! x3 = x2 · x        (mul)
//! x7 = x4 · x3       (mul)
//! ```
//!
//! One lane of the S-box is therefore a degree-2 sub-circuit with four
//! constraints over four auxiliary columns (`x2`, `x4`, `x3`, `x7`)
//! and one input column (`sin`). All local-only — no rotation.
//!
//! This module only emits gates; it does NOT own trace layout. The
//! `PoseidonPermAir` (3c-1.4) passes concrete column indices via
//! [`SboxX7Layout`] and stitches many S-box lanes + MDS + RC into one
//! trace, the same way `BalanceGateAir` stitches many `BitAdderAir`
//! instances via `BitAdderLayout`.

use crate::gates::{MulGate, SquareGate};
use crate::Constraint;

/// Column indices for one lane of the `x^7` S-box.
#[derive(Debug, Clone, Copy)]
pub struct SboxX7Layout {
    /// Input column (`sin`): value of the S-box input on this row.
    pub sin: usize,
    /// `x2 = sin · sin`.
    pub x2: usize,
    /// `x4 = x2 · x2`.
    pub x4: usize,
    /// `x3 = x2 · sin`.
    pub x3: usize,
    /// `x7 = x4 · x3` — the S-box output column.
    pub sout: usize,
}

impl SboxX7Layout {
    /// Lane starting at `base`, aux columns contiguous:
    /// `sin, x2, x4, x3, sout` at offsets 0..5.
    pub fn contiguous(base: usize) -> Self {
        Self {
            sin: base,
            x2: base + 1,
            x4: base + 2,
            x3: base + 3,
            sout: base + 4,
        }
    }
}

/// Number of witness columns one S-box lane occupies in the
/// `contiguous` layout.
pub const SBOX_X7_N_COLS: usize = 5;

/// Emit the four degree-2 constraints for one S-box lane.
pub fn emit_sbox_x7_constraints(layout: SboxX7Layout) -> Vec<Box<dyn Constraint>> {
    vec![
        Box::new(SquareGate::new(layout.x2, layout.sin)),
        Box::new(SquareGate::new(layout.x4, layout.x2)),
        Box::new(MulGate::new(layout.x3, layout.x2, layout.sin)),
        Box::new(MulGate::new(layout.sout, layout.x4, layout.x3)),
    ]
}

/// Fill one lane's aux/output columns given the already-populated
/// `sin` column. Matches the native `sbox_x7` chain bit-for-bit.
pub fn build_sbox_x7_columns(sin: &[noid_core::Block128]) -> [Vec<noid_core::Block128>; 4] {
    use noid_core::Block128;
    let n = sin.len();
    let mut x2 = vec![Block128::from(0u128); n];
    let mut x4 = vec![Block128::from(0u128); n];
    let mut x3 = vec![Block128::from(0u128); n];
    let mut sout = vec![Block128::from(0u128); n];
    for i in 0..n {
        x2[i] = sin[i] * sin[i];
        x4[i] = x2[i] * x2[i];
        x3[i] = x2[i] * sin[i];
        sout[i] = x4[i] * x3[i];
    }
    [x2, x4, x3, sout]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};
    use noid_core::{Block128, TowerField};
    use noid_poseidon2b::native::permutation::sbox_x7 as native_sbox_x7;

    fn mk_input(n: usize, seed: u128) -> Vec<Block128> {
        (0..n)
            .map(|i| {
                Block128::from(
                    seed.wrapping_mul(0x9E3779B97F4A7C15)
                        .wrapping_add(i as u128 ^ 0xA5A5),
                )
            })
            .collect()
    }

    #[test]
    fn sbox_x7_build_matches_native() {
        let sin = mk_input(16, 0xCAFEBABE);
        let [_, _, _, sout] = build_sbox_x7_columns(&sin);
        for (i, &x) in sin.iter().enumerate() {
            assert_eq!(sout[i], native_sbox_x7(x), "lane mismatch at row {i}");
        }
    }

    #[test]
    fn sbox_x7_air_accepts_honest_trace() {
        let sin = mk_input(16, 0xFEEDFACE);
        let [x2, x4, x3, sout] = build_sbox_x7_columns(&sin);
        let layout = SboxX7Layout::contiguous(0);
        let air = CompositeAir::from_parts(4, SBOX_X7_N_COLS, emit_sbox_x7_constraints(layout));
        let trace = Trace::new(vec![sin, x2, x4, x3, sout]);
        assert!(air.check(&trace));
    }

    #[test]
    fn sbox_x7_air_rejects_x2_tamper() {
        let sin = mk_input(16, 0x1234_5678);
        let [mut x2, x4, x3, sout] = build_sbox_x7_columns(&sin);
        x2[3] += Block128::ONE;
        let air = CompositeAir::from_parts(
            4,
            SBOX_X7_N_COLS,
            emit_sbox_x7_constraints(SboxX7Layout::contiguous(0)),
        );
        assert!(!air.check(&Trace::new(vec![sin, x2, x4, x3, sout])));
    }

    #[test]
    fn sbox_x7_air_rejects_x4_tamper() {
        let sin = mk_input(16, 0x1234_5678);
        let [x2, mut x4, x3, sout] = build_sbox_x7_columns(&sin);
        x4[0] += Block128::ONE;
        let air = CompositeAir::from_parts(
            4,
            SBOX_X7_N_COLS,
            emit_sbox_x7_constraints(SboxX7Layout::contiguous(0)),
        );
        assert!(!air.check(&Trace::new(vec![sin, x2, x4, x3, sout])));
    }

    #[test]
    fn sbox_x7_air_rejects_x3_tamper() {
        let sin = mk_input(16, 0x1234_5678);
        let [x2, x4, mut x3, sout] = build_sbox_x7_columns(&sin);
        x3[5] += Block128::ONE;
        let air = CompositeAir::from_parts(
            4,
            SBOX_X7_N_COLS,
            emit_sbox_x7_constraints(SboxX7Layout::contiguous(0)),
        );
        assert!(!air.check(&Trace::new(vec![sin, x2, x4, x3, sout])));
    }

    #[test]
    fn sbox_x7_air_rejects_sout_tamper() {
        let sin = mk_input(16, 0x1234_5678);
        let [x2, x4, x3, mut sout] = build_sbox_x7_columns(&sin);
        sout[9] += Block128::ONE;
        let air = CompositeAir::from_parts(
            4,
            SBOX_X7_N_COLS,
            emit_sbox_x7_constraints(SboxX7Layout::contiguous(0)),
        );
        assert!(!air.check(&Trace::new(vec![sin, x2, x4, x3, sout])));
    }

    #[test]
    fn sbox_x7_layout_shifted_still_sound() {
        // Place the lane at column offset 2 (cols 0..2 are untouched
        // padding) — emulates how PoseidonPermAir will embed many
        // lanes side-by-side.
        let sin = mk_input(16, 0xDEADBEEF);
        let [x2, x4, x3, sout] = build_sbox_x7_columns(&sin);
        let pad0 = vec![Block128::from(0u128); 16];
        let pad1 = vec![Block128::from(0u128); 16];
        let layout = SboxX7Layout::contiguous(2);
        let air = CompositeAir::from_parts(4, 2 + SBOX_X7_N_COLS, emit_sbox_x7_constraints(layout));
        let trace = Trace::new(vec![pad0, pad1, sin, x2, x4, x3, sout]);
        assert!(air.check(&trace));
    }
}
