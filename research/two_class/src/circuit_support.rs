// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Minimal local vocabulary for exploratory Field-R1CS relations.
//!
//! Keeping these helpers here avoids depending on private acceptance modules
//! or widening any production visibility solely for research.

use noid_core::Block128;

pub use noid_ivc_core::field::F128;
pub use noid_ivc_core::field_circuit::{
    flat_const, poseidon2b_permute, FieldR1csBuilder, LinExpr, Wire,
};

#[inline]
pub fn flat_of(value: Block128) -> F128 {
    flat_const(value.0)
}

#[inline]
pub fn alloc_block(builder: &mut FieldR1csBuilder, value: Block128) -> LinExpr {
    LinExpr::from_wire(builder.alloc_f128(flat_of(value)))
}

#[inline]
pub fn const_block(value: Block128) -> LinExpr {
    LinExpr::constant(flat_of(value))
}

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

#[inline]
pub fn pin_eq(builder: &mut FieldR1csBuilder, left: &LinExpr, right: &LinExpr) {
    pin_zero(builder, &left.add(right));
}

/// Prove that the tower-basis value in `expression` fits in `bit_count` bits.
pub fn range_check_bits(
    builder: &mut FieldR1csBuilder,
    expression: &LinExpr,
    bit_count: usize,
) -> Vec<Wire> {
    use noid_core::hardware::flat_to_tower_u128;

    assert!(bit_count <= 128);
    let flat = expression.eval(builder.values());
    let tower = flat_to_tower_u128((flat.lo as u128) | ((flat.hi as u128) << 64));
    let bits = (0..bit_count)
        .map(|index| builder.alloc_bool((tower >> index) & 1 == 1))
        .collect::<Vec<_>>();
    let reconstructed = bits
        .iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (index, bit)| {
            sum.add(&LinExpr::from_wire(*bit).scale(flat_const(1u128 << index)))
        });
    pin_zero(builder, &reconstructed.add(expression));
    bits
}

#[cfg(test)]
pub fn tower_value(builder: &FieldR1csBuilder, expression: &LinExpr) -> Block128 {
    use noid_core::hardware::flat_to_tower_u128;

    let flat = expression.eval(builder.values());
    Block128::from(flat_to_tower_u128(
        (flat.lo as u128) | ((flat.hi as u128) << 64),
    ))
}
