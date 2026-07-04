//! `FieldR1csBuilder` and the base in-circuit gadgets of the acceptance-
//! proof trace (the arithmetic F128 replay of the block verifiers).
//!
//! The builder emits a satisfiable [`FieldR1cs`] (option A: F128 coefficients
//! in the sparse matrices, `C = I`) together with its witness. Linear
//! combinations are **symbolic** ([`LinExpr`]) — they live in the matrix rows
//! of the multiplication constraints that consume them and cost no
//! constraints of their own. Only multiplications (and explicit pins /
//! allocations) materialize witness wires.
//!
//! ## Basis convention (load-bearing)
//!
//! Circuit wires carry values in the **flat (GCM) basis** of GF(2^128), which
//! is bit-for-bit the `noid_ivc_core` [`F128`] field (`clmul_gcm` ==
//! `F128::mul` on the same u128 layout — pinned by test). Native reference
//! objects (Poseidon2b states, killshot transcripts) live in the **tower
//! basis** (`Block128`); they map into the circuit through the F2-linear
//! isomorphism `noid_core::hardware::tower_to_flat_u128` and back via
//! `flat_to_tower_u128`. Addition (XOR) commutes with the map; every tower
//! multiplication corresponds to an F128 multiplication of the flat images.
//! The Poseidon2b round constants and MDS coefficients are φ-mapped once into
//! static tables. This matches the native permutation itself, which already
//! evaluates in the flat basis internally (`noid_poseidon2b`'s
//! `permute_mut`).
//!
//! ## Gadget inventory (constraints, option A)
//!
//! - [`FieldR1csBuilder::pow7`] — 4
//! - [`poseidon2b_permute`] — 360 (8 full rounds × 4 lanes + 58 partial, ×4
//!   muls per S-box; all MDS/RC layers symbolic)
//! - [`FieldR1csBuilder::horner_eval`] — deg
//! - [`FieldR1csBuilder::eq_eval_trace`] — n − 1 (n ≥ 1)
//! - [`FsChannelTrace`] — 360 per sponge permutation; the op schedule is the
//!   [`crate::challenger::FsLaneChallenger`] lane protocol, one lane-affine
//!   absorb per element, no byte splitting.
//! - [`FsChannelTrace::verify_pow_trace`] — 360 + (128 − bits) boolean wires
//!   + 1 pin.

use crate::challenger::{
    FS_KIND_SCALAR, FS_KIND_SLICE, FS_OP_BYTES, FS_OP_DOMAIN, FS_OP_LABEL, FS_OP_OBSERVE,
    FS_OP_POW, FS_OP_SQUEEZE, fs_lane_iv_flat, fs_op_lane, fs_pack_bytes_lanes, fs_pad_lane_flat,
    fs_pow_iv_flat,
};
use crate::field::F128;
use crate::field_r1cs::{FieldR1cs, SparseFieldMatrix};
use noid_core::hardware::tower_to_flat_u128;
use noid_poseidon2b::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};

#[inline]
pub fn f128_from_u128(v: u128) -> F128 {
    F128 {
        lo: v as u64,
        hi: (v >> 64) as u64,
    }
}

#[inline]
pub fn f128_to_u128(v: F128) -> u128 {
    (v.lo as u128) | ((v.hi as u128) << 64)
}

/// φ-map a tower-basis constant into the circuit (flat) basis.
#[inline]
pub fn flat_const(tower: u128) -> F128 {
    f128_from_u128(tower_to_flat_u128(tower))
}

// ---------------------------------------------------------------------------
// Wires and symbolic linear expressions
// ---------------------------------------------------------------------------

/// Index of a materialized witness element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wire(pub u32);

/// Symbolic affine combination `Σ coeff·wire + constant`. Terms are kept
/// sorted by wire index and consolidated on every combination, so expression
/// size is bounded by the support (set of distinct wires), not by the number
/// of operations that produced it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinExpr {
    /// Sorted by wire index; no duplicates; no zero coefficients.
    pub terms: Vec<(u32, F128)>,
    pub constant: F128,
}

impl LinExpr {
    pub fn constant(c: F128) -> Self {
        Self {
            terms: Vec::new(),
            constant: c,
        }
    }

    pub fn zero() -> Self {
        Self::constant(F128::ZERO)
    }

    pub fn from_wire(w: Wire) -> Self {
        Self {
            terms: vec![(w.0, F128::ONE)],
            constant: F128::ZERO,
        }
    }

    pub fn is_const(&self) -> bool {
        self.terms.is_empty()
    }

    /// `self + other` with sorted-merge consolidation.
    pub fn add(&self, other: &Self) -> Self {
        let mut terms = Vec::with_capacity(self.terms.len() + other.terms.len());
        let (mut i, mut j) = (0usize, 0usize);
        while i < self.terms.len() && j < other.terms.len() {
            let (wa, ca) = self.terms[i];
            let (wb, cb) = other.terms[j];
            match wa.cmp(&wb) {
                std::cmp::Ordering::Less => {
                    terms.push((wa, ca));
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    terms.push((wb, cb));
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let c = ca + cb;
                    if c != F128::ZERO {
                        terms.push((wa, c));
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
        terms.extend_from_slice(&self.terms[i..]);
        terms.extend_from_slice(&other.terms[j..]);
        Self {
            terms,
            constant: self.constant + other.constant,
        }
    }

    /// `self · scalar` (F128-linear).
    pub fn scale(&self, scalar: F128) -> Self {
        if scalar == F128::ZERO {
            return Self::zero();
        }
        Self {
            terms: self
                .terms
                .iter()
                .map(|&(w, c)| (w, c * scalar))
                .collect(),
            constant: self.constant * scalar,
        }
    }

    pub fn add_const(&self, c: F128) -> Self {
        Self {
            terms: self.terms.clone(),
            constant: self.constant + c,
        }
    }

    /// Evaluate against a witness.
    pub fn eval(&self, values: &[F128]) -> F128 {
        let mut acc = self.constant;
        for &(w, c) in &self.terms {
            acc += c * values[w as usize];
        }
        acc
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builds a satisfiable single-block [`FieldR1cs`] (`m = k_log`, `n_outer =
/// 1`) plus its witness. Wire 0 is the constant-one wire (row `z_0 = z_0²`,
/// `const_pin = Some(0)` — the lincheck β-pin proves the committed column is
/// all-ones, excluding the `z_0 = 0` root).
pub struct FieldR1csBuilder {
    values: Vec<F128>,
    rows_a: Vec<Vec<(u32, F128)>>,
    rows_b: Vec<Vec<(u32, F128)>>,
    /// `(wire, value)` pairs registered through [`Self::alloc_public_f128`].
    publics: Vec<(u32, F128)>,
}

impl Default for FieldR1csBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldR1csBuilder {
    pub fn new() -> Self {
        let mut b = Self {
            values: Vec::new(),
            rows_a: Vec::new(),
            rows_b: Vec::new(),
            publics: Vec::new(),
        };
        // Wire 0: the constant-one wire, z_0 = z_0 · z_0.
        let w = b.push_wire(F128::ONE);
        debug_assert_eq!(w.0, 0);
        b.rows_a[0] = vec![(0, F128::ONE)];
        b.rows_b[0] = vec![(0, F128::ONE)];
        b
    }

    /// The constant-one wire as an expression.
    pub fn one(&self) -> LinExpr {
        LinExpr::from_wire(Wire(0))
    }

    pub fn num_wires(&self) -> usize {
        self.values.len()
    }

    fn push_wire(&mut self, value: F128) -> Wire {
        let idx = self.values.len();
        assert!(idx < u32::MAX as usize);
        self.values.push(value);
        self.rows_a.push(Vec::new());
        self.rows_b.push(Vec::new());
        Wire(idx as u32)
    }

    /// Convert an expression into a sparse matrix row: terms + the constant
    /// folded onto the constant-one column.
    fn expr_to_row(expr: &LinExpr) -> Vec<(u32, F128)> {
        let mut row = Vec::with_capacity(expr.terms.len() + 1);
        let mut const_coeff = expr.constant;
        for &(w, c) in &expr.terms {
            if w == 0 {
                const_coeff += c;
            } else {
                row.push((w, c));
            }
        }
        if const_coeff != F128::ZERO {
            // Keep the row sorted: column 0 first.
            row.insert(0, (0, const_coeff));
        }
        row
    }

    /// Free (unconstrained) input wire: tautology row `z_i = z_i · 1`.
    pub fn alloc_f128(&mut self, value: F128) -> Wire {
        let w = self.push_wire(value);
        self.rows_a[w.0 as usize] = vec![(w.0, F128::ONE)];
        self.rows_b[w.0 as usize] = vec![(0, F128::ONE)];
        w
    }

    /// Public-input wire: row forces `z_i = value` (`A_i = value·col_0`,
    /// `B_i = col_0`), and the pair is recorded in the public-input list.
    /// The pinned value is part of the statement (it lives in the matrix,
    /// which the statement digest covers).
    pub fn alloc_public_f128(&mut self, value: F128) -> Wire {
        let w = self.push_wire(value);
        if value != F128::ZERO {
            self.rows_a[w.0 as usize] = vec![(0, value)];
        }
        self.rows_b[w.0 as usize] = vec![(0, F128::ONE)];
        self.publics.push((w.0, value));
        w
    }

    /// Boolean wire: row `z_i = z_i · z_i` ⇒ `z_i ∈ {0, 1}` (the only
    /// idempotents of a field). Zero multiplication cost beyond the row.
    pub fn alloc_bool(&mut self, bit: bool) -> Wire {
        let w = self.push_wire(if bit { F128::ONE } else { F128::ZERO });
        self.rows_a[w.0 as usize] = vec![(w.0, F128::ONE)];
        self.rows_b[w.0 as usize] = vec![(w.0, F128::ONE)];
        w
    }

    /// One multiplication constraint: new wire `w = x · y`.
    pub fn mul(&mut self, x: &LinExpr, y: &LinExpr) -> Wire {
        let value = x.eval(&self.values) * y.eval(&self.values);
        let w = self.push_wire(value);
        self.rows_a[w.0 as usize] = Self::expr_to_row(x);
        self.rows_b[w.0 as usize] = Self::expr_to_row(y);
        w
    }

    /// Materialize an expression into a single wire (`w = expr · 1`).
    pub fn materialize(&mut self, expr: &LinExpr) -> Wire {
        self.mul(expr, &self.one())
    }

    /// Assert `expr == expected` (one wire, self-cancelling row:
    /// `z_w = (z_w + expr + expected) · 1` ⇒ `expr + expected = 0`).
    pub fn pin_f128(&mut self, expr: &LinExpr, expected: F128) {
        let w = self.push_wire(F128::ZERO);
        let full = expr
            .add(&LinExpr::from_wire(w))
            .add_const(expected);
        self.rows_a[w.0 as usize] = Self::expr_to_row(&full);
        self.rows_b[w.0 as usize] = vec![(0, F128::ONE)];
        debug_assert_eq!(
            expr.eval(&self.values),
            expected,
            "pin_f128: witness does not satisfy the pinned equality"
        );
    }

    /// Finish: pad to the next power of two (≥ 2^7 — the zerocheck needs
    /// `m ≥ K_SKIP + 1` and the lincheck `k_skip ≤ k_log`), emit a
    /// single-block `FieldR1cs` (`m = k_log`, `n_outer = 1`) and the witness.
    pub fn build(self) -> (FieldR1cs, Vec<F128>) {
        let n_wires = self.values.len();
        let k_log = n_wires
            .next_power_of_two()
            .trailing_zeros()
            .max(7) as usize;
        let k = 1usize << k_log;

        let mut rows_a = self.rows_a;
        let mut rows_b = self.rows_b;
        rows_a.resize(k, Vec::new());
        rows_b.resize(k, Vec::new());
        let mut values = self.values;
        values.resize(k, F128::ZERO);

        let r1cs = FieldR1cs {
            m: k_log,
            k_log,
            k_skip: crate::zerocheck::K_SKIP,
            useful_rows: n_wires,
            a_0: SparseFieldMatrix {
                num_rows: k,
                num_cols: k,
                rows: rows_a,
            },
            b_0: SparseFieldMatrix {
                num_rows: k,
                num_cols: k,
                rows: rows_b,
            },
            const_pin: Some(0),
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        };
        r1cs.validate_shape();
        (r1cs, values)
    }

    /// Registered public inputs (wire, value).
    pub fn public_inputs(&self) -> &[(u32, F128)] {
        &self.publics
    }

    /// Current witness snapshot (for tests / expression evaluation).
    pub fn values(&self) -> &[F128] {
        &self.values
    }

    // -----------------------------------------------------------------------
    // Base gadgets
    // -----------------------------------------------------------------------

    /// `x^7` — 4 multiplications (x², x⁴, x³, x⁷), the Poseidon2b S-box.
    pub fn pow7(&mut self, x: &LinExpr) -> LinExpr {
        let x2 = LinExpr::from_wire(self.mul(x, x));
        let x4 = LinExpr::from_wire(self.mul(&x2, &x2));
        let x3 = LinExpr::from_wire(self.mul(&x2, x));
        LinExpr::from_wire(self.mul(&x4, &x3))
    }

    /// Horner evaluation of `Σ coeffs[i]·x^i` (coeffs LSB-first, degree =
    /// `coeffs.len() − 1`): `deg` multiplications.
    pub fn horner_eval(&mut self, coeffs: &[LinExpr], x: &LinExpr) -> LinExpr {
        assert!(!coeffs.is_empty());
        let mut acc = coeffs[coeffs.len() - 1].clone();
        for c in coeffs.iter().rev().skip(1) {
            let prod = LinExpr::from_wire(self.mul(&acc, x));
            acc = prod.add(c);
        }
        acc
    }

    /// `eq(r, x) = Π_i (1 + r_i + x_i)` — `n − 1` multiplications (`n ≥ 1`).
    pub fn eq_eval_trace(&mut self, r: &[LinExpr], x: &[LinExpr]) -> LinExpr {
        assert_eq!(r.len(), x.len());
        assert!(!r.is_empty());
        let factor =
            |i: usize| -> LinExpr { r[i].add(&x[i]).add_const(F128::ONE) };
        let mut acc = factor(0);
        for i in 1..r.len() {
            acc = LinExpr::from_wire(self.mul(&acc, &factor(i)));
        }
        acc
    }

    /// Bit-decompose `expr` into `n_bits` boolean wires (LSB-first) and
    /// enforce `expr = Σ b_i·x^i`. Because only `n_bits` bit wires exist,
    /// this simultaneously proves that `expr`'s bits above `n_bits − 1` are
    /// all zero. Returns the bit wires. Cost: `n_bits` boolean rows + 1 pin.
    pub fn decompose_bits_le(&mut self, expr: &LinExpr, n_bits: usize) -> Vec<Wire> {
        assert!(n_bits <= 128);
        let value = f128_to_u128(expr.eval(&self.values));
        let bits: Vec<Wire> = (0..n_bits)
            .map(|i| self.alloc_bool((value >> i) & 1 == 1))
            .collect();
        let mut sum = LinExpr::zero();
        for (i, b) in bits.iter().enumerate() {
            sum = sum.add(&LinExpr::from_wire(*b).scale(f128_from_u128(1u128 << i)));
        }
        self.pin_f128(&sum.add(expr), F128::ZERO);
        bits
    }
}

// ---------------------------------------------------------------------------
// Poseidon2b permutation gadget
// ---------------------------------------------------------------------------

struct PoseidonFlatTables {
    rc: [[F128; N_ROUNDS]; STATE_SIZE],
    mds_full: [[F128; STATE_SIZE]; STATE_SIZE],
    mds_partial: [[F128; STATE_SIZE]; STATE_SIZE],
}

fn poseidon_flat_tables() -> &'static PoseidonFlatTables {
    static TABLES: std::sync::OnceLock<PoseidonFlatTables> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        let mut rc = [[F128::ZERO; N_ROUNDS]; STATE_SIZE];
        for i in 0..STATE_SIZE {
            for r in 0..N_ROUNDS {
                rc[i][r] = flat_const(ROUND_CONSTANTS[i][r]);
            }
        }
        let mut mds_full = [[F128::ZERO; STATE_SIZE]; STATE_SIZE];
        let mut mds_partial = [[F128::ZERO; STATE_SIZE]; STATE_SIZE];
        for i in 0..STATE_SIZE {
            for j in 0..STATE_SIZE {
                mds_full[i][j] = flat_const(MDS_FULL[i][j]);
                mds_partial[i][j] = flat_const(MDS_PARTIAL[i][j]);
            }
        }
        PoseidonFlatTables {
            rc,
            mds_full,
            mds_partial,
        }
    })
}

fn apply_mds_symbolic(
    state: &[LinExpr; STATE_SIZE],
    mds: &[[F128; STATE_SIZE]; STATE_SIZE],
) -> [LinExpr; STATE_SIZE] {
    std::array::from_fn(|i| {
        let mut acc = LinExpr::zero();
        for j in 0..STATE_SIZE {
            acc = acc.add(&state[j].scale(mds[i][j]));
        }
        acc
    })
}

/// In-circuit Poseidon2b permutation over flat-basis state lanes.
/// Line-by-line shadow of `Poseidon2bPermutation::permute_mut` (which itself
/// runs in the flat basis): initial MDS_FULL, then 4 full / 58 partial / 4
/// full rounds. 360 multiplication constraints; every linear layer is
/// symbolic.
pub fn poseidon2b_permute(
    b: &mut FieldR1csBuilder,
    state: [LinExpr; STATE_SIZE],
) -> [LinExpr; STATE_SIZE] {
    let t = poseidon_flat_tables();
    let mut state = apply_mds_symbolic(&state, &t.mds_full);
    for r in 0..N_ROUNDS {
        if !(F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&r) {
            for (i, lane) in state.iter_mut().enumerate() {
                let x = lane.add_const(t.rc[i][r]);
                *lane = b.pow7(&x);
            }
            state = apply_mds_symbolic(&state, &t.mds_full);
        } else {
            let x = state[0].add_const(t.rc[0][r]);
            state[0] = b.pow7(&x);
            state = apply_mds_symbolic(&state, &t.mds_partial);
        }
    }
    state
}

/// Multiplication constraints per permutation (S-boxes only; MDS/RC are
/// symbolic): 8 full rounds × 4 lanes × 4 + 58 partial × 4 = **360**.
pub const POSEIDON2B_PERMUTE_CONSTRAINTS: usize =
    (F_ROUNDS * STATE_SIZE + P_ROUNDS) * 4;

// ---------------------------------------------------------------------------
// Fiat-Shamir channel trace gadget
// ---------------------------------------------------------------------------

/// In-circuit replay of the [`crate::challenger::FsLaneChallenger`] duplex
/// sponge — the LaneExpr pattern of `noid_recursive::fs_transcript`, lifted
/// to symbolic expressions. State lanes, buffering, padding and the pending
/// squeeze lane mirror the native challenger op for op; the op-header lanes
/// are the shared constants from `crate::challenger`.
///
/// Every observed value enters as a [`LinExpr`] (witness data or a public
/// constant); every squeeze returns the state-lane expression, which the
/// caller's replayed verifier algebra then consumes — the transcript
/// invariant of the recursion: the in-circuit channel matches the native
/// challenger bit-for-bit (permutation, IV, padding, absorb/squeeze order).
pub struct FsChannelTrace {
    state: [LinExpr; STATE_SIZE],
    buffered: Option<LinExpr>,
    pending: Option<LinExpr>,
    perms: usize,
}

impl FsChannelTrace {
    /// Mirror of `FsLaneChallenger::new(domain)`.
    pub fn new(b: &mut FieldR1csBuilder, domain: &[u8]) -> Self {
        let [iv0, iv1] = fs_lane_iv_flat();
        let mut t = Self {
            state: [
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::constant(iv0),
                LinExpr::constant(iv1),
            ],
            buffered: None,
            pending: None,
            perms: 0,
        };
        t.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_DOMAIN, 0, domain.len() as u64)),
        );
        for lane in fs_pack_bytes_lanes(domain) {
            t.absorb_lane(b, LinExpr::constant(lane));
        }
        t
    }

    /// Number of permutations executed so far (must match the native
    /// challenger's count in lockstep tests).
    pub fn perms(&self) -> usize {
        self.perms
    }

    fn permute(&mut self, b: &mut FieldR1csBuilder) {
        self.state = poseidon2b_permute(b, std::mem::take(&mut self.state));
        self.perms += 1;
    }

    /// Rate-2 absorb with pair buffering (mirror of the sponge byte buffer,
    /// which at the lane level always holds 0 or 1 whole lanes).
    fn absorb_lane(&mut self, b: &mut FieldR1csBuilder, lane: LinExpr) {
        self.pending = None;
        if let Some(first) = self.buffered.take() {
            self.state[0] = self.state[0].add(&first);
            self.state[1] = self.state[1].add(&lane);
            self.permute(b);
        } else {
            self.buffered = Some(lane);
        }
    }

    /// Commit a buffered odd lane with the sponge pad block.
    fn flush(&mut self, b: &mut FieldR1csBuilder) {
        if let Some(first) = self.buffered.take() {
            self.state[0] = self.state[0].add(&first);
            self.state[1] = self.state[1].add_const(fs_pad_lane_flat());
            self.permute(b);
        }
    }

    fn squeeze_lane(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        if let Some(p) = self.pending.take() {
            return p;
        }
        self.flush(b);
        let out = self.state[0].clone();
        self.pending = Some(self.state[1].clone());
        self.permute(b);
        out
    }

    // ---- Challenger-op mirrors (same order and lane encoding as
    //      FsLaneChallenger) ------------------------------------------------

    pub fn observe_label(&mut self, b: &mut FieldR1csBuilder, label: &[u8]) {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_LABEL, 0, label.len() as u64)),
        );
        for lane in fs_pack_bytes_lanes(label) {
            self.absorb_lane(b, LinExpr::constant(lane));
        }
    }

    pub fn observe_f128(&mut self, b: &mut FieldR1csBuilder, value: &LinExpr) {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_OBSERVE, FS_KIND_SCALAR, 0)),
        );
        self.absorb_lane(b, value.clone());
    }

    pub fn observe_f128_slice(&mut self, b: &mut FieldR1csBuilder, values: &[LinExpr]) {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_OBSERVE, FS_KIND_SLICE, values.len() as u64)),
        );
        for v in values {
            self.absorb_lane(b, v.clone());
        }
    }

    /// Constant byte observation (statement digests, roots known at build
    /// time). Witness-carried byte data must be observed as lane expressions
    /// via [`Self::observe_lanes`] with the same header.
    pub fn observe_bytes_const(&mut self, b: &mut FieldR1csBuilder, bytes: &[u8]) {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_BYTES, 0, bytes.len() as u64)),
        );
        for lane in fs_pack_bytes_lanes(bytes) {
            self.absorb_lane(b, LinExpr::constant(lane));
        }
    }

    /// Witness-carried byte observation: the caller supplies the packed
    /// lanes as expressions plus the true byte length for the header.
    pub fn observe_lanes(&mut self, b: &mut FieldR1csBuilder, byte_len: u64, lanes: &[LinExpr]) {
        assert_eq!(lanes.len() as u64, byte_len.div_ceil(16));
        self.absorb_lane(b, LinExpr::constant(fs_op_lane(FS_OP_BYTES, 0, byte_len)));
        for lane in lanes {
            self.absorb_lane(b, lane.clone());
        }
    }

    pub fn sample_f128(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SCALAR, 0)),
        );
        self.squeeze_lane(b)
    }

    pub fn sample_f128_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_SQUEEZE, FS_KIND_SLICE, n as u64)),
        );
        (0..n).map(|_| self.squeeze_lane(b)).collect()
    }

    /// In-trace mirror of `FsLaneChallenger::verify_pow`: peek the flushed
    /// state, run one PoW permutation over `[d0 + nonce, d1, POW_IV]`, prove
    /// the output lane has `bits` leading zeros (via a `128 − bits`-bit
    /// decomposition — the missing top wires force the zeros), then absorb
    /// the nonce. The nonce enters as an expression (witness).
    pub fn verify_pow_trace(
        &mut self,
        b: &mut FieldR1csBuilder,
        nonce: &LinExpr,
        bits: u32,
    ) {
        assert!(bits <= 64, "leading-zero window limited to the top limb");
        self.flush(b);
        // Non-advancing peek of the two rate lanes.
        let d0 = self.state[0].clone();
        let d1 = self.state[1].clone();
        let [pow_iv0, pow_iv1] = fs_pow_iv_flat();
        let pow_state = [
            d0.add(nonce),
            d1,
            LinExpr::constant(pow_iv0),
            LinExpr::constant(pow_iv1),
        ];
        // NOTE: the PoW permutation is a separate sponge instance — it is
        // deliberately NOT counted in `perms` (which tracks the transcript
        // sponge only, so it stays comparable with the native challenger,
        // whose grind may run many search permutations).
        let out = poseidon2b_permute(b, pow_state);
        if bits > 0 {
            // h must satisfy: top `bits` bits zero ⇔ h = Σ_{i<128−bits} b_i·x^i.
            b.decompose_bits_le(&out[0], 128 - bits as usize);
        }
        // Absorb the nonce (mirror of the native observe).
        self.absorb_lane(
            b,
            LinExpr::constant(fs_op_lane(FS_OP_POW, 0, bits as u64)),
        );
        self.absorb_lane(b, nonce.clone());
    }
}

// ---------------------------------------------------------------------------
// Raw Fiat-Shamir channel trace gadget
// ---------------------------------------------------------------------------

/// In-circuit replay of the production killshot channel
/// (`noid_poseidon2b::channel::Poseidon2bChannel` — the `FiatShamir<Block128>`
/// implementation every `noid_gkr` verifier runs on). Unlike
/// [`FsChannelTrace`], the raw channel has NO op-header lanes and NO domain
/// absorb: it is a bare rate-2 duplex seeded with the `KSCHANNL` capacity IV,
/// where every absorbed `Block128` is one whole lane and every squeeze emits
/// `state[0]` / holds `state[1]` pending.
///
/// Basis: absorbed tower values enter as their flat (GCM) images
/// (`flat_const` for constants, φ-mapped witness wires otherwise); squeezed
/// expressions evaluate to the flat images of the native channel's tower
/// challenges. XOR commutes with φ and the permutation gadget shadows the
/// native permutation on flat images, so the trace state is φ(native state)
/// lane-for-lane (the transcript-lockstep invariant).
pub struct RawChannelTrace {
    state: [LinExpr; STATE_SIZE],
    buffered: Option<LinExpr>,
    pending: Option<LinExpr>,
    perms: usize,
}

impl RawChannelTrace {
    /// Mirror of `Poseidon2bChannel::new()`: zero rate lanes, `KSCHANNL`
    /// capacity IV, empty buffer, no pending challenge.
    pub fn new() -> Self {
        let [iv0, iv1] = crate::challenger::ks_channel_iv_flat();
        Self {
            state: [
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::constant(iv0),
                LinExpr::constant(iv1),
            ],
            buffered: None,
            pending: None,
            perms: 0,
        }
    }

    /// Transcript permutations executed so far (lockstep pin).
    pub fn perms(&self) -> usize {
        self.perms
    }

    fn permute(&mut self, b: &mut FieldR1csBuilder) {
        self.state = poseidon2b_permute(b, std::mem::take(&mut self.state));
        self.perms += 1;
    }

    /// Mirror of `FiatShamir::absorb`: one whole lane, rate-2 pair buffering
    /// (`Poseidon2bSponge::update` with 16-byte writes keeps 0 or 1 whole
    /// lanes buffered). Absorbing invalidates any pending challenge.
    pub fn absorb(&mut self, b: &mut FieldR1csBuilder, lane: &LinExpr) {
        self.pending = None;
        if let Some(first) = self.buffered.take() {
            self.state[0] = self.state[0].add(&first);
            self.state[1] = self.state[1].add(lane);
            self.permute(b);
        } else {
            self.buffered = Some(lane.clone());
        }
    }

    /// Absorb a build-time constant (tower basis), φ-mapped.
    pub fn absorb_const_tower(&mut self, b: &mut FieldR1csBuilder, tower: u128) {
        self.absorb(b, &LinExpr::constant(flat_const(tower)));
    }

    /// Mirror of `Poseidon2bSponge::flush_to_squeeze`: commit a buffered odd
    /// lane with the sponge pad block (`0x80 … 0x01`).
    fn flush(&mut self, b: &mut FieldR1csBuilder) {
        if let Some(first) = self.buffered.take() {
            self.state[0] = self.state[0].add(&first);
            self.state[1] = self
                .state[1]
                .add_const(crate::challenger::fs_pad_lane_flat());
            self.permute(b);
        }
    }

    /// Mirror of `Poseidon2bChannel::squeeze`: pending lane if buffered from
    /// the previous squeeze, else flush + emit `state[0]`, hold `state[1]`
    /// pending, advance the sponge.
    pub fn squeeze(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        if let Some(p) = self.pending.take() {
            return p;
        }
        self.flush(b);
        let out = self.state[0].clone();
        self.pending = Some(self.state[1].clone());
        self.permute(b);
        out
    }

    /// Mirror of `FiatShamir::squeeze_n`.
    pub fn squeeze_n(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        (0..n).map(|_| self.squeeze(b)).collect()
    }
}

impl Default for RawChannelTrace {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::{Challenger, FsLaneChallenger};
    use noid_core::hardware::clmul_gcm;
    use noid_core::{Block128, TowerField};
    use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn f128(&mut self) -> F128 {
            F128 {
                lo: self.next_u64(),
                hi: self.next_u64(),
            }
        }
        fn u128v(&mut self) -> u128 {
            ((self.next_u64() as u128) << 64) | self.next_u64() as u128
        }
    }

    /// The load-bearing basis fact: the flat (GCM) basis multiplication IS
    /// the noid_ivc F128 multiplication on the same u128 bit layout, and the
    /// tower↔flat conversion is its inverse pair.
    #[test]
    fn flat_basis_is_ivc_f128() {
        use noid_core::hardware::flat_to_tower_u128;
        let mut rng = Rng::new(0xBA515);
        for _ in 0..2000 {
            let a = rng.u128v();
            let b = rng.u128v();
            let fa = f128_from_u128(a);
            let fb = f128_from_u128(b);
            assert_eq!(f128_to_u128(fa * fb), clmul_gcm(a, b));
            assert_eq!(flat_to_tower_u128(tower_to_flat_u128(a)), a);
        }
    }

    /// Builder smoke: mul/lin/pin produce a satisfiable instance; a broken
    /// pin is caught by `satisfies`.
    #[test]
    fn builder_basic_satisfiability() {
        let mut rng = Rng::new(1);
        let mut b = FieldR1csBuilder::new();
        let x = LinExpr::from_wire(b.alloc_f128(rng.f128()));
        let y = LinExpr::from_wire(b.alloc_f128(rng.f128()));
        let xv = x.eval(b.values());
        let yv = y.eval(b.values());
        let prod = LinExpr::from_wire(b.mul(&x, &y));
        let combo = prod.scale(F128 { lo: 3, hi: 0 }).add(&x).add_const(F128::ONE);
        b.pin_f128(&combo, F128 { lo: 3, hi: 0 } * (xv * yv) + xv + F128::ONE);
        let pub_w = b.alloc_public_f128(F128 { lo: 42, hi: 7 });
        let pub_e = LinExpr::from_wire(pub_w);
        b.pin_f128(&pub_e, F128 { lo: 42, hi: 7 });

        let (r1cs, mut z) = b.build();
        assert!(r1cs.satisfies(&z));

        // Corrupt the public wire → unsat.
        z[pub_w.0 as usize] += F128::ONE;
        assert!(!r1cs.satisfies(&z));
    }

    /// pow7 == native S-box through the φ map, and costs exactly 4 wires.
    #[test]
    fn pow7_matches_native_sbox() {
        use noid_poseidon2b::native::permutation::sbox_x7;
        let mut rng = Rng::new(2);
        for _ in 0..32 {
            let tower = rng.u128v();
            let mut b = FieldR1csBuilder::new();
            let x = LinExpr::from_wire(b.alloc_f128(flat_const(tower)));
            let before = b.num_wires();
            let out = b.pow7(&x);
            assert_eq!(b.num_wires() - before, 4, "pow7 must cost 4 constraints");
            let expected = flat_const(sbox_x7(Block128(tower)).0);
            assert_eq!(out.eval(b.values()), expected);
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }

    /// The permutation gadget matches `Poseidon2bPermutation::permute_mut`
    /// through φ on random states (all 66 rounds, MDS full/partial), is
    /// satisfiable, and costs ≤ 400 constraints (exactly 360).
    #[test]
    fn poseidon2b_permute_matches_native() {
        let perm = Poseidon2bPermutation;
        let mut rng = Rng::new(3);
        for case in 0..16 {
            let tower_state: [Block128; STATE_SIZE] = std::array::from_fn(|_| {
                if case == 0 {
                    Block128::ZERO
                } else {
                    Block128(rng.u128v())
                }
            });
            let mut expected = tower_state;
            perm.permute_mut(&mut expected);

            let mut b = FieldR1csBuilder::new();
            let state: [LinExpr; STATE_SIZE] = std::array::from_fn(|i| {
                LinExpr::from_wire(b.alloc_f128(flat_const(tower_state[i].0)))
            });
            let before = b.num_wires();
            let out = poseidon2b_permute(&mut b, state);
            let cost = b.num_wires() - before;
            assert_eq!(cost, POSEIDON2B_PERMUTE_CONSTRAINTS);
            assert!(cost <= 400, "permutation gadget budget: ≤ 400 constraints");

            for i in 0..STATE_SIZE {
                assert_eq!(
                    out[i].eval(b.values()),
                    flat_const(expected[i].0),
                    "lane {i} mismatch (case {case})"
                );
            }
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }

    /// horner_eval == native Horner; eq_eval_trace == multilinear::eq_eval.
    #[test]
    fn horner_and_eq_eval_match_native() {
        let mut rng = Rng::new(4);
        for deg in [1usize, 3, 9] {
            let mut b = FieldR1csBuilder::new();
            let coeffs_v: Vec<F128> = (0..=deg).map(|_| rng.f128()).collect();
            let x_v = rng.f128();
            let coeffs: Vec<LinExpr> = coeffs_v
                .iter()
                .map(|&c| LinExpr::from_wire(b.alloc_f128(c)))
                .collect();
            let x = LinExpr::from_wire(b.alloc_f128(x_v));
            let before = b.num_wires();
            let out = b.horner_eval(&coeffs, &x);
            assert_eq!(b.num_wires() - before, deg);
            let mut expected = F128::ZERO;
            for &c in coeffs_v.iter().rev() {
                expected = expected * x_v + c;
            }
            assert_eq!(out.eval(b.values()), expected);
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }

        for n in [1usize, 4, 11] {
            let mut b = FieldR1csBuilder::new();
            let r_v: Vec<F128> = (0..n).map(|_| rng.f128()).collect();
            let x_v: Vec<F128> = (0..n).map(|_| rng.f128()).collect();
            let r: Vec<LinExpr> = r_v
                .iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect();
            let x: Vec<LinExpr> = x_v
                .iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect();
            let before = b.num_wires();
            let out = b.eq_eval_trace(&r, &x);
            assert_eq!(b.num_wires() - before, n - 1);
            assert_eq!(
                out.eval(b.values()),
                crate::zerocheck::multilinear::eq_eval(&r_v, &x_v)
            );
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }

    /// decompose_bits_le proves the value fits in n bits: honest witness
    /// satisfies; a value with a higher bit set has NO satisfying assignment
    /// of the bit wires (checked via the builder's own dishonest witness).
    #[test]
    fn decompose_bits_forces_range() {
        let mut b = FieldR1csBuilder::new();
        let v = F128 { lo: 0xAB47, hi: 0 };
        let x = LinExpr::from_wire(b.alloc_f128(v));
        b.decompose_bits_le(&x, 16);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));

        // Out-of-range: bit 16 set. The builder still produces SOME witness
        // (its debug_assert would fire in dev; here we hand-corrupt): flip
        // the input value in the finished witness — the pin row must break.
        let mut bad = z.clone();
        bad[1] += F128 {
            lo: 1 << 16,
            hi: 0,
        };
        assert!(!r1cs.satisfies(&bad));
    }

    /// THE lockstep gate: 1000 random op schedules; the trace gadget
    /// mirrors `FsLaneChallenger` exactly — same permutation count, squeezed
    /// expressions evaluate to the native challenges, and the built R1CS is
    /// satisfiable. Covers labels, scalar/slice observes, byte observes,
    /// scalar/vec samples, sponge padding (odd/even lane parity) and PoW
    /// grind/verify.
    #[test]
    fn fs_channel_trace_lockstep_1000_random_traces() {
        let mut rng = Rng::new(0x10C_57E9);
        for trace_idx in 0..1000 {
            let domain = format!("lockstep-{}", trace_idx % 7);
            let mut native = FsLaneChallenger::new(domain.as_bytes());
            let mut b = FieldR1csBuilder::new();
            let mut trace = FsChannelTrace::new(&mut b, domain.as_bytes());

            let n_ops = 1 + (rng.next_u64() % 8) as usize;
            for _ in 0..n_ops {
                match rng.next_u64() % 7 {
                    0 => {
                        let label = format!("phase-{}", rng.next_u64() % 5);
                        native.observe_label(label.as_bytes());
                        trace.observe_label(&mut b, label.as_bytes());
                    }
                    1 => {
                        let v = rng.f128();
                        native.observe_f128(v);
                        let w = LinExpr::from_wire(b.alloc_f128(v));
                        trace.observe_f128(&mut b, &w);
                    }
                    2 => {
                        let n = (rng.next_u64() % 4) as usize;
                        let vals: Vec<F128> = (0..n).map(|_| rng.f128()).collect();
                        native.observe_f128_slice(&vals);
                        let exprs: Vec<LinExpr> = vals
                            .iter()
                            .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                            .collect();
                        trace.observe_f128_slice(&mut b, &exprs);
                    }
                    3 => {
                        let len = (rng.next_u64() % 40) as usize;
                        let bytes: Vec<u8> =
                            (0..len).map(|_| rng.next_u64() as u8).collect();
                        native.observe_bytes(&bytes);
                        trace.observe_bytes_const(&mut b, &bytes);
                    }
                    4 => {
                        let c = native.sample_f128();
                        let e = trace.sample_f128(&mut b);
                        assert_eq!(e.eval(b.values()), c, "scalar sample diverged");
                    }
                    5 => {
                        let n = 1 + (rng.next_u64() % 3) as usize;
                        let cs = native.sample_f128_vec(n);
                        let es = trace.sample_f128_vec(&mut b, n);
                        for (e, c) in es.iter().zip(cs.iter()) {
                            assert_eq!(e.eval(b.values()), *c, "vec sample diverged");
                        }
                    }
                    _ => {
                        let bits = (rng.next_u64() % 5) as u32; // 0..=4
                        let nonce = native.grind_pow(bits);
                        let nonce_expr = LinExpr::from_wire(b.alloc_f128(F128 {
                            lo: nonce,
                            hi: 0,
                        }));
                        trace.verify_pow_trace(&mut b, &nonce_expr, bits);
                    }
                }
            }
            // Final divergence check: one more challenge each.
            let c = native.sample_f128();
            let e = trace.sample_f128(&mut b);
            assert_eq!(e.eval(b.values()), c, "trailing sample diverged");
            assert_eq!(trace.perms(), native.perms(), "permutation count diverged");

            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "trace {trace_idx} unsatisfiable");
        }
    }

    /// THE raw-channel lockstep gate: 1000 random absorb/squeeze schedules; the raw
    /// channel trace mirrors the production `Poseidon2bChannel` exactly —
    /// every squeezed expression evaluates to the flat image of the native
    /// tower challenge, and the built R1CS is satisfiable. Covers pair
    /// buffering (odd/even absorb parity), the pad-flush on odd squeezes,
    /// pending-lane reuse and pending invalidation by interleaved absorbs.
    #[test]
    fn raw_channel_trace_lockstep_1000_random_schedules() {
        use noid_core::transcript::FiatShamir;
        use noid_poseidon2b::channel::Poseidon2bChannel;

        let mut rng = Rng::new(0x0A0B_CDEF_1234_5678);
        for schedule_idx in 0..1000 {
            let mut native = Poseidon2bChannel::new();
            let mut b = FieldR1csBuilder::new();
            let mut trace = RawChannelTrace::new();

            let n_ops = 1 + (rng.next_u64() % 12) as usize;
            for _ in 0..n_ops {
                match rng.next_u64() % 3 {
                    0 => {
                        // Witness-carried absorb (tower value → flat wire).
                        let tower = rng.u128v();
                        native.absorb(Block128(tower));
                        let w = LinExpr::from_wire(b.alloc_f128(flat_const(tower)));
                        trace.absorb(&mut b, &w);
                    }
                    1 => {
                        // Constant absorb (public statement data).
                        let tower = rng.next_u64() as u128;
                        native.absorb(Block128(tower));
                        trace.absorb_const_tower(&mut b, tower);
                    }
                    _ => {
                        let c = native.squeeze();
                        let e = trace.squeeze(&mut b);
                        assert_eq!(
                            e.eval(b.values()),
                            flat_const(c.0),
                            "squeeze diverged (schedule {schedule_idx})"
                        );
                    }
                }
            }
            // Trailing divergence check: two more challenges (exercises the
            // pending lane and the no-buffer squeeze path).
            for _ in 0..2 {
                let c = native.squeeze();
                let e = trace.squeeze(&mut b);
                assert_eq!(
                    e.eval(b.values()),
                    flat_const(c.0),
                    "trailing squeeze diverged (schedule {schedule_idx})"
                );
            }

            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "schedule {schedule_idx} unsatisfiable");
        }
    }

    /// A tampered PoW nonce makes the trace unsatisfiable — the PoW
    /// permutation rows were built for the honest nonce, and the
    /// leading-zero decomposition pins the honest output. Negative twin of
    /// the lockstep grind coverage.
    #[test]
    fn verify_pow_trace_rejects_wrong_nonce() {
        let mut native = FsLaneChallenger::new(b"pow-neg");
        native.observe_bytes(b"root");
        let bits = 8u32;
        let nonce = native.grind_pow(bits);

        // Honest trace, then corrupt the nonce wire in the finished witness.
        let mut b = FieldR1csBuilder::new();
        let mut trace = FsChannelTrace::new(&mut b, b"pow-neg");
        trace.observe_bytes_const(&mut b, b"root");
        let nonce_wire = b.alloc_f128(F128 { lo: nonce, hi: 0 });
        trace.verify_pow_trace(&mut b, &LinExpr::from_wire(nonce_wire), bits);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest nonce trace must satisfy");

        let mut bad = z.clone();
        bad[nonce_wire.0 as usize] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad),
            "tampered nonce produced a satisfiable trace"
        );
    }
}
