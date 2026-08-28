// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Minimal Field-R1CS vocabulary used by the parent-union certificate.

pub use noid_ivc_core::field::F128;
pub use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};

#[inline]
pub fn mul(builder: &mut FieldR1csBuilder, left: &LinExpr, right: &LinExpr) -> LinExpr {
    if right.is_const() {
        return left.scale(right.constant);
    }
    if left.is_const() {
        return right.scale(left.constant);
    }
    LinExpr::from_wire(builder.mul(left, right))
}

#[inline]
pub fn pin_zero(builder: &mut FieldR1csBuilder, expression: &LinExpr) {
    builder.pin_f128(expression, F128::ZERO);
}
