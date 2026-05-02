// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `BoolGate`: `v · (v + 1) == 0` in char-2, forcing `v ∈ {0, 1}`.

use crate::{Constraint, EvalFrame};
use noid_core::Block128;

/// `v * (v + 1) == 0` (char-2): forces `v ∈ {0,1}`.
pub struct BoolGate {
    cols: [usize; 1],
}

impl BoolGate {
    pub fn new(col: usize) -> Self {
        Self { cols: [col] }
    }
}

impl Constraint for BoolGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let v = frame.local[0];
        v * v + v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    #[test]
    fn bool_gate_rejects_non_bit() {
        let air = CompositeAir::from_parts(2, 1, vec![Box::new(BoolGate::new(0))]);
        let mut col = vec![Block128::ZERO; 4];
        col[2] = Block128::from(5u128);
        let trace = Trace::new(vec![col]);
        assert!(!air.check(&trace));
    }
}
