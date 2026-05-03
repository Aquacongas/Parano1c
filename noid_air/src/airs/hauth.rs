// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3c-3 — `HAuthAir` (4-field sponge, `hash_auth_tag`).
//!
//! Witnesses the native `noid_poseidon2b::primitives::hash_auth_tag`
//! pipeline:
//!
//! ```text
//! state = [0, 0, capacity_iv(TAG_AUTHTAG)]           // IV seed
//! state[0] ^= secret_hi; state[1] ^= secret_lo
//! permute                                             // perm A (absorb #1)
//! state[0] ^= tx_body_hi; state[1] ^= tx_body_lo
//! permute                                             // perm B (absorb #2)
//! state[0] ^= PAD_0; state[1] ^= PAD_1
//! permute                                             // perm C (padding flush)
//! output = state[0] || state[1]
//! ```
//!
//! Column layout (90 cols = 3 × [`POSEIDON_PERM_N_COLS`]): three perm
//! blocks at bases `0`, `30`, `60`, each identical to the `HAddrAir`
//! block shape, all sharing the row axis (256 rows at the STARK
//! floor).
//!
//! Constraints emitted: `3 × emit_perm_all_at = 87` gates covering the
//! permutation interiors. Boundary ties (capacity-IV, each absorb XOR,
//! inter-permutation carries, output squeeze) are deferred to §3d's
//! `RowSelectorGate` / `ConstColumnGate` bundle — same posture as
//! §3c-1 and §3c-2.

use crate::airs::poseidon_perm::{
    write_perm_trace_at, PermLayout, POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS,
    POSEIDON_PERM_N_ROWS,
};
use crate::airs::haddr::{HADDR_PAD_0, HADDR_PAD_1};
use crate::{Air, Constraint, Trace};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_AUTHTAG};
use noid_poseidon2b::native::permutation::STATE_SIZE;

pub const HAUTH_PERM_A_BASE: usize = 0;
pub const HAUTH_PERM_B_BASE: usize = POSEIDON_PERM_N_COLS;
pub const HAUTH_PERM_C_BASE: usize = 2 * POSEIDON_PERM_N_COLS;
pub const HAUTH_N_COLS: usize = 3 * POSEIDON_PERM_N_COLS;
pub const HAUTH_LOG_ROWS: usize = POSEIDON_PERM_LOG_ROWS;
pub const HAUTH_N_ROWS: usize = POSEIDON_PERM_N_ROWS;

pub const HAUTH_LAYOUT_A: PermLayout = PermLayout::at(HAUTH_PERM_A_BASE);
pub const HAUTH_LAYOUT_B: PermLayout = PermLayout::at(HAUTH_PERM_B_BASE);
pub const HAUTH_LAYOUT_C: PermLayout = PermLayout::at(HAUTH_PERM_C_BASE);

/// Build an honest witness trace for
/// `hash_auth_tag(spend_secret, tx_body_hash)`. Inputs are the
/// `as_fields()`-decomposed halves of each.
pub fn build_hauth_trace(
    secret: [Block128; 2],
    tx_body: [Block128; 2],
) -> Vec<Vec<Block128>> {
    let mut cols: Vec<Vec<Block128>> = (0..HAUTH_N_COLS)
        .map(|_| vec![Block128::ZERO; HAUTH_N_ROWS])
        .collect();

    // Perm A: seed with IV, XOR absorb (secret_hi, secret_lo) into rate.
    let [iv_hi, iv_lo] = capacity_iv(TAG_AUTHTAG);
    let perm_a_input: [Block128; STATE_SIZE] = [secret[0], secret[1], iv_hi, iv_lo];
    let state_after_a = write_perm_trace_at(&mut cols, HAUTH_LAYOUT_A, perm_a_input);

    // Perm B: XOR absorb (tx_body_hi, tx_body_lo) into rate; capacity
    // flows through unchanged.
    let perm_b_input: [Block128; STATE_SIZE] = [
        state_after_a[0] + tx_body[0],
        state_after_a[1] + tx_body[1],
        state_after_a[2],
        state_after_a[3],
    ];
    let state_after_b = write_perm_trace_at(&mut cols, HAUTH_LAYOUT_B, perm_b_input);

    // Perm C: padding flush.
    let pad0 = Block128::from(HADDR_PAD_0);
    let pad1 = Block128::from(HADDR_PAD_1);
    let perm_c_input: [Block128; STATE_SIZE] = [
        state_after_b[0] + pad0,
        state_after_b[1] + pad1,
        state_after_b[2],
        state_after_b[3],
    ];
    write_perm_trace_at(&mut cols, HAUTH_LAYOUT_C, perm_c_input);

    cols
}

/// Extract the `(out[0], out[1])` state at row `N_ROUNDS` of block C.
pub fn extract_hauth_output(cols: &[Vec<Block128>]) -> [Block128; 2] {
    let row = noid_poseidon2b::native::permutation::N_ROUNDS;
    [
        cols[HAUTH_LAYOUT_C.s][row],
        cols[HAUTH_LAYOUT_C.s + 1][row],
    ]
}

/// Emit the three interior constraint blocks.
pub fn emit_hauth_constraints() -> Vec<Box<dyn Constraint>> {
    let mut out = Vec::with_capacity(87);
    out.extend(crate::airs::emit_perm_all_at(HAUTH_LAYOUT_A));
    out.extend(crate::airs::emit_perm_all_at(HAUTH_LAYOUT_B));
    out.extend(crate::airs::emit_perm_all_at(HAUTH_LAYOUT_C));
    out
}

pub struct HAuthAir {
    constraints: Vec<Box<dyn Constraint>>,
}

impl HAuthAir {
    pub fn new() -> Self {
        Self {
            constraints: emit_hauth_constraints(),
        }
    }

    pub fn build_trace(
        &self,
        secret: [Block128; 2],
        tx_body: [Block128; 2],
    ) -> Trace {
        Trace::new(build_hauth_trace(secret, tx_body))
    }
}

impl Default for HAuthAir {
    fn default() -> Self {
        Self::new()
    }
}

impl Air for HAuthAir {
    fn n_columns(&self) -> usize {
        HAUTH_N_COLS
    }
    fn log_rows(&self) -> usize {
        HAUTH_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::CanonicalSerialize;

    fn mk_fields(seed: u128) -> [Block128; 2] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    #[test]
    fn hauth_trace_matches_primitives_hash_auth_tag() {
        use noid_poseidon2b::primitives::{hash_auth_tag, SpendSecret, TxBodyHash};
        let secret_fields = mk_fields(0xA07_5EED);
        let txbody_fields = mk_fields(0x5C0FF_B0D);

        let mut sb = [0u8; 32];
        sb[..16].copy_from_slice(&secret_fields[0].to_bytes());
        sb[16..].copy_from_slice(&secret_fields[1].to_bytes());
        let mut tb = [0u8; 32];
        tb[..16].copy_from_slice(&txbody_fields[0].to_bytes());
        tb[16..].copy_from_slice(&txbody_fields[1].to_bytes());

        let native = hash_auth_tag(&SpendSecret(sb), &TxBodyHash(tb));

        let cols = build_hauth_trace(secret_fields, txbody_fields);
        let out_fields = extract_hauth_output(&cols);
        let mut out_bytes = [0u8; 32];
        out_bytes[..16].copy_from_slice(&out_fields[0].to_bytes());
        out_bytes[16..].copy_from_slice(&out_fields[1].to_bytes());
        assert_eq!(out_bytes, native.0);
    }

    #[test]
    fn hauth_air_accepts_honest_trace() {
        let air = HAuthAir::new();
        let trace = air.build_trace(mk_fields(0xCAFE), mk_fields(0xBABE));
        assert!(air.check(&trace));
    }

    #[test]
    fn hauth_air_rejects_perm_a_sout_tamper() {
        let air = HAuthAir::new();
        let mut cols = build_hauth_trace(mk_fields(1), mk_fields(2));
        cols[HAUTH_LAYOUT_A.sout + 2][1] = cols[HAUTH_LAYOUT_A.sout + 2][1] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hauth_air_rejects_perm_b_mds_tamper() {
        let air = HAuthAir::new();
        let mut cols = build_hauth_trace(mk_fields(3), mk_fields(4));
        cols[HAUTH_LAYOUT_B.s + 1][3] = cols[HAUTH_LAYOUT_B.s + 1][3] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hauth_air_rejects_perm_c_partial_sin_kill() {
        let air = HAuthAir::new();
        let mut cols = build_hauth_trace(mk_fields(5), mk_fields(6));
        cols[HAUTH_LAYOUT_C.sin + 2][5] = Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hauth_air_rejects_perm_c_rc_tamper() {
        let air = HAuthAir::new();
        let mut cols = build_hauth_trace(mk_fields(7), mk_fields(8));
        // Row 1 is a full round (rows 0..4 full, 4..62 partial, 62..66
        // full). Lane 1's rc binding is gated by `is_full`, so we must
        // tamper on a full-round row for the breakage to be observed.
        cols[HAUTH_LAYOUT_C.rc + 1][1] = cols[HAUTH_LAYOUT_C.rc + 1][1] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hauth_blocks_disjoint() {
        let layouts = [HAUTH_LAYOUT_A, HAUTH_LAYOUT_B, HAUTH_LAYOUT_C];
        for i in 0..3 {
            for j in (i + 1)..3 {
                assert_ne!(layouts[i].s, layouts[j].s);
                assert_ne!(layouts[i].rc, layouts[j].rc);
            }
        }
        assert_eq!(HAUTH_N_COLS, 3 * POSEIDON_PERM_N_COLS);
    }
}
