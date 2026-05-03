// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3c-1.3 — MDS mixing layer as an AIR sub-circuit.
//!
//! Native reference: `noid_poseidon2b::native::permutation::{apply_mds_full,
//! apply_mds_partial, MDS_FULL, MDS_PARTIAL}`. For each row (= one
//! Poseidon2b round step) the MDS layer enforces
//!
//! ```text
//! next(s[i]) = Σ_j M[i][j] · sout[j]     for i ∈ 0..4
//! ```
//!
//! where `sout[j]` is the S-box output column of lane `j` (produced by
//! `poseidon_sbox`) and `next(s[i])` is the lane-`i` state column at
//! the cyclically-next row. One degree-1 rotation gate per lane —
//! four constraints per round. `MDS_FULL` vs `MDS_PARTIAL` is selected
//! by the caller (`PoseidonPermAir` picks per round).
//!
//! The matrix coefficients are tower-basis monomials in `Block128`;
//! they multiply through the constraint engine exactly like the
//! weights in `WeightedLinearGate`.

use crate::{Constraint, EvalFrame};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{MDS_FULL, MDS_PARTIAL, STATE_SIZE};

/// Column indices for one round of the MDS layer.
///
/// - `sout[j]` — S-box output column of lane `j`, read at the CURRENT
///   row.
/// - `s_next[i]` — state column of lane `i`, read at the NEXT row (the
///   post-MDS output is the input to the next round's RC step).
#[derive(Debug, Clone, Copy)]
pub struct MdsLayout {
    pub sout: [usize; STATE_SIZE],
    pub s_next: [usize; STATE_SIZE],
}

impl MdsLayout {
    /// Contiguous layout: state lanes at `s_base..s_base+4`, S-box
    /// outputs at `sout_base..sout_base+4`.
    pub fn new(sout_base: usize, s_base: usize) -> Self {
        Self {
            sout: [sout_base, sout_base + 1, sout_base + 2, sout_base + 3],
            s_next: [s_base, s_base + 1, s_base + 2, s_base + 3],
        }
    }
}

/// Which MDS matrix to use on a given row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdsKind {
    Full,
    Partial,
}

impl MdsKind {
    fn matrix(self) -> &'static [[u128; STATE_SIZE]; STATE_SIZE] {
        match self {
            MdsKind::Full => &MDS_FULL,
            MdsKind::Partial => &MDS_PARTIAL,
        }
    }
}

/// `next(s[lane]) + Σ_j M[lane][j] · sout[j] == 0` — one degree-1
/// rotation gate per output lane. Local reads: `sout[0..4]`; next
/// read: `s[lane]`.
pub struct MdsRowGate {
    row_coeffs: [u128; STATE_SIZE],
    locals: [usize; STATE_SIZE],
    shifted: [usize; 1],
}

impl MdsRowGate {
    pub fn new(lane: usize, kind: MdsKind, layout: MdsLayout) -> Self {
        assert!(lane < STATE_SIZE);
        let row_coeffs = kind.matrix()[lane];
        Self {
            row_coeffs,
            locals: layout.sout,
            shifted: [layout.s_next[lane]],
        }
    }
}

impl Constraint for MdsRowGate {
    fn degree(&self) -> usize {
        1
    }
    fn columns(&self) -> &[usize] {
        &self.locals
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let s_next = frame.next[0];
        let mut acc = s_next;
        for j in 0..STATE_SIZE {
            let w = self.row_coeffs[j];
            if w == 1 {
                acc = acc + frame.local[j];
            } else if w != 0 {
                acc = acc + Block128::from(w) * frame.local[j];
            }
        }
        acc
    }
}

/// Emit 4 gates for one row's MDS layer (one gate per output lane).
pub fn emit_mds_row_constraints(
    kind: MdsKind,
    layout: MdsLayout,
) -> Vec<Box<dyn Constraint>> {
    (0..STATE_SIZE)
        .map(|lane| Box::new(MdsRowGate::new(lane, kind, layout)) as Box<dyn Constraint>)
        .collect()
}

/// Native reference: apply one round of MDS (full or partial) to a 4-lane
/// row. Used to seed the `s_next` columns when building a permutation
/// trace.
pub fn apply_mds_row(kind: MdsKind, sout: [Block128; STATE_SIZE]) -> [Block128; STATE_SIZE] {
    let m = kind.matrix();
    let mut out = [Block128::ZERO; STATE_SIZE];
    for i in 0..STATE_SIZE {
        let mut acc = Block128::ZERO;
        for j in 0..STATE_SIZE {
            let w = m[i][j];
            if w == 1 {
                acc = acc + sout[j];
            } else if w != 0 {
                acc = acc + Block128::from(w) * sout[j];
            }
        }
        out[i] = acc;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    fn mk_rows(n: usize, seed: u128) -> [Vec<Block128>; STATE_SIZE] {
        let mut out: [Vec<Block128>; STATE_SIZE] =
            [vec![], vec![], vec![], vec![]];
        for i in 0..n {
            for lane in 0..STATE_SIZE {
                out[lane].push(Block128::from(
                    seed.wrapping_mul(0x9E3779B97F4A7C15)
                        .wrapping_add((i as u128) << 16)
                        .wrapping_add(lane as u128 + 1),
                ));
            }
        }
        out
    }

    fn build_trace(
        kind: MdsKind,
        n: usize,
        seed: u128,
    ) -> (Vec<Vec<Block128>>, Vec<Vec<Block128>>) {
        // Layout: cols 0..4 = s (state at row start), cols 4..8 = sout
        // (post-sbox). For MDS alone we treat `sout` as independent
        // witness; the S-box coupling is tested separately in
        // poseidon_sbox::tests.
        let sout_cols: Vec<Vec<Block128>> = mk_rows(n, seed).to_vec();
        // Compute next-row state from this row's sout via native MDS.
        let mut s_cols: Vec<Vec<Block128>> = (0..STATE_SIZE).map(|_| vec![Block128::ZERO; n]).collect();
        // The AIR reads s at NEXT row, so s_cols[lane][i+1] = MDS(sout at row i).
        // Row 0 of s is unconstrained (acts as input to round 0); set it to 0.
        for i in 0..n {
            let row_sout = [sout_cols[0][i], sout_cols[1][i], sout_cols[2][i], sout_cols[3][i]];
            let next_s = apply_mds_row(kind, row_sout);
            // Cyclic next: (i + 1) % n
            let nxt = (i + 1) % n;
            for lane in 0..STATE_SIZE {
                s_cols[lane][nxt] = next_s[lane];
            }
        }
        (s_cols, sout_cols)
    }

    #[test]
    fn mds_full_row_accepts_honest_trace() {
        let n = 8;
        let (s_cols, sout_cols) = build_trace(MdsKind::Full, n, 0xBEEF);
        let layout = MdsLayout::new(/*sout_base*/ 4, /*s_base*/ 0);
        let constraints = emit_mds_row_constraints(MdsKind::Full, layout);
        let air = CompositeAir::from_parts(3, 8, constraints);
        let mut cols = s_cols.clone();
        cols.extend(sout_cols);
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    #[test]
    fn mds_partial_row_accepts_honest_trace() {
        let n = 8;
        let (s_cols, sout_cols) = build_trace(MdsKind::Partial, n, 0x5AFE);
        let layout = MdsLayout::new(4, 0);
        let constraints = emit_mds_row_constraints(MdsKind::Partial, layout);
        let air = CompositeAir::from_parts(3, 8, constraints);
        let mut cols = s_cols.clone();
        cols.extend(sout_cols);
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn mds_full_row_rejects_s_next_tamper() {
        let n = 8;
        let (mut s_cols, sout_cols) = build_trace(MdsKind::Full, n, 0xBEEF);
        s_cols[2][5] = s_cols[2][5] + Block128::ONE;
        let layout = MdsLayout::new(4, 0);
        let constraints = emit_mds_row_constraints(MdsKind::Full, layout);
        let air = CompositeAir::from_parts(3, 8, constraints);
        let mut cols = s_cols;
        cols.extend(sout_cols);
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn mds_full_row_rejects_sout_tamper() {
        let n = 8;
        let (s_cols, mut sout_cols) = build_trace(MdsKind::Full, n, 0xBEEF);
        sout_cols[1][0] = sout_cols[1][0] + Block128::ONE;
        let layout = MdsLayout::new(4, 0);
        let constraints = emit_mds_row_constraints(MdsKind::Full, layout);
        let air = CompositeAir::from_parts(3, 8, constraints);
        let mut cols = s_cols;
        cols.extend(sout_cols);
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn mds_full_vs_partial_differs() {
        // Independent sanity: native MDS_FULL != MDS_PARTIAL on at least
        // one input (catches accidental sharing between arms).
        let sout = [Block128::from(1u8), Block128::from(2u8), Block128::from(3u8), Block128::from(4u8)];
        let f = apply_mds_row(MdsKind::Full, sout);
        let p = apply_mds_row(MdsKind::Partial, sout);
        assert_ne!(f, p);
    }
}
