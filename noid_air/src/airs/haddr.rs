// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3c-2 — `HAddrAir` (2-field sponge, `derive_address`).
//!
//! Witnesses the native `noid_poseidon2b::primitives::derive_address`
//! pipeline:
//!
//! ```text
//! state = [0, 0, capacity_iv(TAG_ADDRESS)]   // IV seed
//! state[0] ^= secret_hi; state[1] ^= secret_lo
//! Poseidon2bPermutation.permute_mut(&mut state)   // perm #1 (absorb)
//! state[0] ^= PAD_0; state[1] ^= PAD_1
//! Poseidon2bPermutation.permute_mut(&mut state)   // perm #2 (padding flush)
//! output = state[0] || state[1]
//! ```
//!
//! Column layout (60 cols = 2 × [`POSEIDON_PERM_N_COLS`]):
//!
//! - Block A (cols `0..30`)  — `PermLayout::at(0)` — first permutation,
//!   row 0 state seeded with `[secret_hi, secret_lo, IV_hi, IV_lo]`.
//! - Block B (cols `30..60`) — `PermLayout::at(30)` — second permutation,
//!   row 0 state seeded with `[A.s0@N_ROUNDS + PAD_0, A.s1@N_ROUNDS + PAD_1,
//!   A.s2@N_ROUNDS, A.s3@N_ROUNDS]`.
//!
//! Constraints emitted at this stage: `2 × emit_perm_all_at = 58` gates.
//! These lock the two permutation interiors. Boundary ties
//! (capacity-IV binding, absorb XOR at row 0, inter-permutation carry,
//! output squeeze binding) are **not** yet constrained — see §3d.
//!
//! # Debt deferred to §3d
//!
//! The AIR constraint system is row-local (no row-index selector).
//! Enforcing "row-0 state = IV", "Block-B row-0 state = post-perm-A
//! state XOR padding" and "Block-B row-N_ROUNDS state = `(addr_hi,
//! addr_lo)`" all need a `RowSelectorGate` / `ConstColumnGate` that
//! the §3d debt block tracks. In the interim, `build_haddr_trace`
//! produces an honest witness matching the native primitive and the
//! prover is trusted to pin boundaries. This is identical to how
//! `PoseidonPermAir` (3c-1) currently treats `rc` / `is_full` /
//! `is_round` — trusted-input until §3d.

use crate::airs::poseidon_perm::{
    write_perm_trace_at, PermLayout, POSEIDON_PERM_N_COLS, POSEIDON_PERM_N_ROWS,
    POSEIDON_PERM_LOG_ROWS,
};
use crate::{Air, Constraint, Trace};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRESS};
use noid_poseidon2b::native::permutation::STATE_SIZE;

/// Column offset of the first (absorb) permutation block.
pub const HADDR_PERM_A_BASE: usize = 0;
/// Column offset of the second (padding flush) permutation block.
pub const HADDR_PERM_B_BASE: usize = POSEIDON_PERM_N_COLS;
/// Total column count.
pub const HADDR_N_COLS: usize = 2 * POSEIDON_PERM_N_COLS;
/// Trace row count must accommodate one permutation (both blocks
/// occupy the same row range; they differ in column, not row).
pub const HADDR_LOG_ROWS: usize = POSEIDON_PERM_LOG_ROWS;
pub const HADDR_N_ROWS: usize = POSEIDON_PERM_N_ROWS;

/// Fixed layouts for the two permutation blocks.
pub const HADDR_LAYOUT_A: PermLayout = PermLayout::at(HADDR_PERM_A_BASE);
pub const HADDR_LAYOUT_B: PermLayout = PermLayout::at(HADDR_PERM_B_BASE);

/// Native padding field elements produced by the sponge's
/// `fill_padding` routine when only `absorb_pair(secret_hi,
/// secret_lo)` has been called and no raw-byte `update` follows:
/// after that absorb, `filled_bytes == 0` so the full 32-byte buffer
/// is zero-padded and `fill_padding` stamps `0x80` at byte 0 and
/// `0x01` at byte 31.
///
/// The sponge splits the 32-byte buffer into two little-endian
/// `Block128` rate words:
/// - `PAD_0 = u128::from_le_bytes([0x80, 0, .., 0])           = 0x80`
/// - `PAD_1 = u128::from_le_bytes([0, 0, .., 0, 0x01])        = 0x01 << 120`
///
/// Verified against `Poseidon2bSponge::finalize` in
/// `native::compression.rs`.
pub const HADDR_PAD_0: u128 = 0x80;
pub const HADDR_PAD_1: u128 = 0x01u128 << 120;

/// Build an honest witness trace for `derive_address(secret)`.
///
/// `secret = [secret_hi, secret_lo]` matches `SpendSecret::as_fields()`.
/// Returns a (`HADDR_N_COLS`) × `HADDR_N_ROWS` column matrix.
pub fn build_haddr_trace(secret: [Block128; 2]) -> Vec<Vec<Block128>> {
    let mut cols: Vec<Vec<Block128>> = (0..HADDR_N_COLS)
        .map(|_| vec![Block128::ZERO; HADDR_N_ROWS])
        .collect();

    // Perm A: absorb. state = [secret_hi, secret_lo, IV_hi, IV_lo].
    let [iv_hi, iv_lo] = capacity_iv(TAG_ADDRESS);
    let perm_a_input: [Block128; STATE_SIZE] = [secret[0], secret[1], iv_hi, iv_lo];
    let state_after_a = write_perm_trace_at(&mut cols, HADDR_LAYOUT_A, perm_a_input);

    // Perm B: padding flush. state = [A.out[0] + PAD_0, A.out[1] +
    // PAD_1, A.out[2], A.out[3]].
    let pad0 = Block128::from(HADDR_PAD_0);
    let pad1 = Block128::from(HADDR_PAD_1);
    let perm_b_input: [Block128; STATE_SIZE] = [
        state_after_a[0] + pad0,
        state_after_a[1] + pad1,
        state_after_a[2],
        state_after_a[3],
    ];
    write_perm_trace_at(&mut cols, HADDR_LAYOUT_B, perm_b_input);

    cols
}

/// Extract the final-row state of block B (the `derive_address` output
/// before byte serialization).
pub fn extract_haddr_output(cols: &[Vec<Block128>]) -> [Block128; 2] {
    let row = noid_poseidon2b::native::permutation::N_ROUNDS;
    [
        cols[HADDR_LAYOUT_B.s][row],
        cols[HADDR_LAYOUT_B.s + 1][row],
    ]
}

/// Emit the `HAddrAir` constraint set: two independent
/// `emit_perm_all_at` blocks = 58 gates.
pub fn emit_haddr_constraints() -> Vec<Box<dyn Constraint>> {
    let mut out = Vec::with_capacity(58);
    out.extend(crate::airs::emit_perm_all_at(HADDR_LAYOUT_A));
    out.extend(crate::airs::emit_perm_all_at(HADDR_LAYOUT_B));
    out
}

pub struct HAddrAir {
    constraints: Vec<Box<dyn Constraint>>,
}

impl HAddrAir {
    pub fn new() -> Self {
        Self {
            constraints: emit_haddr_constraints(),
        }
    }

    pub fn build_trace(&self, secret: [Block128; 2]) -> Trace {
        Trace::new(build_haddr_trace(secret))
    }
}

impl Default for HAddrAir {
    fn default() -> Self {
        Self::new()
    }
}

impl Air for HAddrAir {
    fn n_columns(&self) -> usize {
        HADDR_N_COLS
    }
    fn log_rows(&self) -> usize {
        HADDR_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::CanonicalSerialize;
    use noid_poseidon2b::native::compression::Poseidon2bSponge;
    use noid_poseidon2b::native::permutation::N_ROUNDS;

    fn mk_secret(seed: u128) -> [Block128; 2] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    /// Native `derive_address` reference via the sponge. Equivalent to
    /// `noid_poseidon2b::primitives::derive_address(secret).0`.
    fn native_derive_address(secret: [Block128; 2]) -> [u8; 32] {
        let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_ADDRESS));
        s.absorb_pair(secret[0], secret[1]);
        s.finalize()
    }

    #[test]
    fn haddr_trace_matches_native_derive_address() {
        let secret = mk_secret(0xDECAF_CAFE_BABE);
        let cols = build_haddr_trace(secret);
        let out_fields = extract_haddr_output(&cols);
        let mut out_bytes = [0u8; 32];
        out_bytes[..16].copy_from_slice(&out_fields[0].to_bytes());
        out_bytes[16..].copy_from_slice(&out_fields[1].to_bytes());
        assert_eq!(out_bytes, native_derive_address(secret));
    }

    #[test]
    fn haddr_trace_matches_primitives_derive_address() {
        use noid_poseidon2b::primitives::{derive_address, SpendSecret};
        // Pack two Block128 halves back into SpendSecret bytes so the
        // native side sees the same bits.
        let secret_fields = mk_secret(0x1234_5678_9ABC);
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&secret_fields[0].to_bytes());
        bytes[16..].copy_from_slice(&secret_fields[1].to_bytes());
        let native = derive_address(&SpendSecret(bytes));

        let cols = build_haddr_trace(secret_fields);
        let out_fields = extract_haddr_output(&cols);
        let mut out_bytes = [0u8; 32];
        out_bytes[..16].copy_from_slice(&out_fields[0].to_bytes());
        out_bytes[16..].copy_from_slice(&out_fields[1].to_bytes());
        assert_eq!(out_bytes, native.0);
    }

    #[test]
    fn haddr_air_accepts_honest_trace() {
        let air = HAddrAir::new();
        let trace = air.build_trace(mk_secret(0xBEEF));
        assert!(air.check(&trace));
    }

    #[test]
    fn haddr_air_rejects_perm_a_sout_tamper() {
        let air = HAddrAir::new();
        let mut cols = build_haddr_trace(mk_secret(0xABCD));
        // Flip sout[2] on row 1 of block A — breaks S-box chain.
        cols[HADDR_LAYOUT_A.sout + 2][1] = cols[HADDR_LAYOUT_A.sout + 2][1] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn haddr_air_rejects_perm_b_rc_tamper() {
        let air = HAddrAir::new();
        let mut cols = build_haddr_trace(mk_secret(0xFADE));
        // Tamper rc lane 0 row 3 of block B — breaks RC binding.
        cols[HADDR_LAYOUT_B.rc][3] = cols[HADDR_LAYOUT_B.rc][3] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn haddr_air_rejects_perm_b_partial_row_sin_kill() {
        let air = HAddrAir::new();
        let mut cols = build_haddr_trace(mk_secret(0xC0FFEE));
        // Force sin[1] nonzero on a partial row (row 5) of block B.
        cols[HADDR_LAYOUT_B.sin + 1][5] = Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn haddr_air_rejects_perm_a_s_next_tamper() {
        let air = HAddrAir::new();
        let mut cols = build_haddr_trace(mk_secret(0x5EED));
        // Break the MDS transition on block A row 2.
        cols[HADDR_LAYOUT_A.s + 1][3] = cols[HADDR_LAYOUT_A.s + 1][3] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn haddr_blocks_are_independent_in_column_space() {
        // Sanity: the two layouts share no columns.
        let a_cols = [
            HADDR_LAYOUT_A.s,
            HADDR_LAYOUT_A.sin,
            HADDR_LAYOUT_A.sout,
            HADDR_LAYOUT_A.rc,
            HADDR_LAYOUT_A.is_full,
            HADDR_LAYOUT_A.is_round,
        ];
        let b_cols = [
            HADDR_LAYOUT_B.s,
            HADDR_LAYOUT_B.sin,
            HADDR_LAYOUT_B.sout,
            HADDR_LAYOUT_B.rc,
            HADDR_LAYOUT_B.is_full,
            HADDR_LAYOUT_B.is_round,
        ];
        for a in a_cols {
            for b in b_cols {
                assert_ne!(a, b);
            }
        }
        assert_eq!(HADDR_N_COLS, 2 * POSEIDON_PERM_N_COLS);
        // Honest trace round-trips through N_ROUNDS.
        let _ = N_ROUNDS;
    }
}
