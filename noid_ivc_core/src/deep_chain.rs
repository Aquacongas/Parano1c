//! Deep-chain layer walk: a data-parallel GKR over the Poseidon2b round
//! structure.
//!
//! The prover holds `W = 2^w_log` permutation executions as four state
//! COLUMNS per layer (one F128 lane per column per slot) and proves, layer
//! by layer, that every slot's output is the Poseidon2b permutation of its
//! input — with the verifier paying only sumcheck rounds, never hashing.
//!
//! Layer structure mirrors `noid_poseidon2b::native::permutation`
//! exactly: the caller applies the initial `MDS_FULL` when building the
//! layer-0 columns (it is linear, so input-wiring relations absorb it for
//! free), then layer `ℓ ∈ 1..=66` applies round `ℓ−1`:
//!
//! - full round (`q ∉ [F/2, F/2 + P)`): every lane gets the round constant,
//!   the x^7 S-box, then `MDS_FULL`;
//! - partial round: lane 0 only, then `MDS_PARTIAL`.
//!
//! The WALK reduces evaluation claims on the layer-66 (output) columns to a
//! claim on the layer-0 (input) columns: per layer, the batched claim
//! `Σ_{g,i} α^{4g+i+1} · S_ℓ,i~(ρ_g)` equals
//!
//! ```text
//!   Σ_w Σ_j E_j(w) · term_j(S_{ℓ−1}(w))      E_j(w) = Σ_g c_{g,j}·eq(ρ_g, w)
//! ```
//!
//! with `c_{g,j} = Σ_i α^{4g+i+1}·MDS[i][j]` verifier-computable constants
//! and `term_j` the S-box (degree 7) or identity per the round type — one
//! degree-8 sumcheck over the `w_log` slot variables. Its final claim is
//! the four `S_{ℓ−1}` lane evaluations at the derived point, which seed the
//! next layer. Intermediate layers are bound by this chain alone: nothing
//! per-slot is ever absorbed or committed, and the walk's terminal claim
//! lands on the layer-0 columns, which the caller discharges against
//! committed data (witness slices via the public-IO opening claims).
//!
//! Round polynomials travel in the compressed wire form `[c_0, c_2..c_8]`
//! (the linear coefficient is reconstructed from the running claim, so
//! `p(0) + p(1) = claim` holds by construction).

pub mod encode_kernel;
pub mod family;
pub mod leaf_hash;
pub mod relations;
pub mod schedule;
pub mod source_tree;
pub mod spine;

use crate::challenger::Challenger;
use crate::field::F128;
use crate::lincheck::build_eq_table;
use noid_core::hardware::tower_to_flat_u128;
use noid_poseidon2b::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};
use rayon::prelude::*;

/// Degree of a walk round polynomial: `eq` (1) × S-box on a multilinear (7).
pub const WALK_DEGREE: usize = 8;

/// Checkpoint spacing for the prover's layer-column rebuilds.
const CHECKPOINT_SPACING: usize = 8;

#[inline]
fn f128_of_u128(v: u128) -> F128 {
    F128 {
        lo: v as u64,
        hi: (v >> 64) as u64,
    }
}

/// x^7 over the flat basis: `x · x² · x⁴`.
#[inline]
pub fn sbox7(x: F128) -> F128 {
    let x2 = x * x;
    let x4 = x2 * x2;
    x * x2 * x4
}

/// Round schedule in the flat basis (converted once from the tower-basis
/// protocol constants, exactly as the native permutation does internally).
struct FlatSchedule {
    rc: [[F128; N_ROUNDS]; STATE_SIZE],
    mds_full: [[F128; STATE_SIZE]; STATE_SIZE],
    mds_partial: [[F128; STATE_SIZE]; STATE_SIZE],
}

fn schedule() -> &'static FlatSchedule {
    static S: std::sync::OnceLock<FlatSchedule> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        let mut rc = [[F128::ZERO; N_ROUNDS]; STATE_SIZE];
        let mut mds_full = [[F128::ZERO; STATE_SIZE]; STATE_SIZE];
        let mut mds_partial = [[F128::ZERO; STATE_SIZE]; STATE_SIZE];
        for i in 0..STATE_SIZE {
            for q in 0..N_ROUNDS {
                rc[i][q] = f128_of_u128(tower_to_flat_u128(ROUND_CONSTANTS[i][q]));
            }
            for j in 0..STATE_SIZE {
                mds_full[i][j] = f128_of_u128(tower_to_flat_u128(MDS_FULL[i][j]));
                mds_partial[i][j] = f128_of_u128(tower_to_flat_u128(MDS_PARTIAL[i][j]));
            }
        }
        FlatSchedule {
            rc,
            mds_full,
            mds_partial,
        }
    })
}

/// Whether round `q ∈ 0..N_ROUNDS` is a full round.
#[inline]
pub fn is_full_round(q: usize) -> bool {
    !(F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&q)
}

/// Flat-basis round constant of `lane` at round `q` (a protocol constant —
/// verifier twins fold it into affine expressions).
pub fn flat_round_constant(lane: usize, q: usize) -> F128 {
    schedule().rc[lane][q]
}

/// Flat-basis MDS matrix (full or partial) — protocol constants.
pub fn flat_mds(full: bool) -> &'static [[F128; STATE_SIZE]; STATE_SIZE] {
    if full {
        &schedule().mds_full
    } else {
        &schedule().mds_partial
    }
}

/// The initial `MDS_FULL` the permutation applies before round 0 — callers
/// fold it into the layer-0 columns (it is linear, so chain-wiring
/// relations compose with it for free).
pub fn initial_mds(raw: [F128; STATE_SIZE]) -> [F128; STATE_SIZE] {
    mds_apply(&schedule().mds_full, raw)
}

#[inline]
fn mds_apply(
    mds: &[[F128; STATE_SIZE]; STATE_SIZE],
    input: [F128; STATE_SIZE],
) -> [F128; STATE_SIZE] {
    std::array::from_fn(|i| {
        let mut acc = F128::ZERO;
        for j in 0..STATE_SIZE {
            acc += mds[i][j] * input[j];
        }
        acc
    })
}

/// Apply round `q` to one slot's state (mirrors the native round order).
pub fn apply_round(q: usize, state: [F128; STATE_SIZE]) -> [F128; STATE_SIZE] {
    let sch = schedule();
    if is_full_round(q) {
        let boxed = std::array::from_fn(|i| sbox7(state[i] + sch.rc[i][q]));
        mds_apply(&sch.mds_full, boxed)
    } else {
        let mut boxed = state;
        boxed[0] = sbox7(state[0] + sch.rc[0][q]);
        mds_apply(&sch.mds_partial, boxed)
    }
}

/// A group of four per-lane evaluation claims at one point:
/// `column_i~(point) = values[i]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneClaimGroup {
    pub point: Vec<F128>,
    pub values: [F128; STATE_SIZE],
}

/// One layer's wire data: `w_log` compressed degree-8 round polynomials
/// plus the four next-layer lane evaluations at the derived point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalkLayerProof {
    /// Per sumcheck round: `[c_0, c_2..c_8]` (8 coefficients).
    pub round_coeffs: Vec<[F128; WALK_DEGREE]>,
    pub next_values: [F128; STATE_SIZE],
}

/// The full walk: layer 66 first, down to layer 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeepChainWalkProof {
    pub layers: Vec<WalkLayerProof>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// Proof shape disagrees with (w_log, N_ROUNDS).
    Shape,
    /// A layer's final check failed (claim vs reassembled relation).
    LayerMismatch(usize),
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalkError::Shape => write!(f, "walk proof shape mismatch"),
            WalkError::LayerMismatch(l) => write!(f, "walk layer {l} claim mismatch"),
        }
    }
}

// ---------------------------------------------------------------------------
// Interpolation constants (evaluations at 0..=8 → monomial coefficients)
// ---------------------------------------------------------------------------

pub(crate) fn f128_inv_pub(x: F128) -> F128 {
    // Fermat: x^(2^128 − 2).
    let exp: u128 = u128::MAX - 1;
    let mut result = F128::ONE;
    let mut base = x;
    for bit in 0..128 {
        if (exp >> bit) & 1 == 1 {
            result = result * base;
        }
        base = base * base;
    }
    result
}

/// Lagrange basis in coefficient form for nodes `t_i = i`, `i ∈ 0..=8`:
/// `coeffs = Σ_i evals[i] · basis[i]`.
fn interpolation_basis() -> &'static [[F128; WALK_DEGREE + 1]; WALK_DEGREE + 1] {
    static B: std::sync::OnceLock<[[F128; WALK_DEGREE + 1]; WALK_DEGREE + 1]> =
        std::sync::OnceLock::new();
    B.get_or_init(|| {
        let nodes: Vec<F128> = (0..=WALK_DEGREE as u128).map(f128_of_u128).collect();
        std::array::from_fn(|i| {
            // Numerator Π_{j≠i} (X + t_j), char-2.
            let mut poly = [F128::ZERO; WALK_DEGREE + 1];
            poly[0] = F128::ONE;
            let mut deg = 0usize;
            let mut denom = F128::ONE;
            for (j, &t_j) in nodes.iter().enumerate() {
                if j == i {
                    continue;
                }
                denom = denom * (nodes[i] + t_j);
                // poly *= (X + t_j)
                let mut next = [F128::ZERO; WALK_DEGREE + 1];
                for d in 0..=deg {
                    next[d + 1] += poly[d];
                    next[d] += poly[d] * t_j;
                }
                deg += 1;
                poly = next;
            }
            let inv = f128_inv_pub(denom);
            std::array::from_fn(|d| poly[d] * inv)
        })
    })
}

fn interpolate(evals: &[F128; WALK_DEGREE + 1]) -> [F128; WALK_DEGREE + 1] {
    let basis = interpolation_basis();
    let mut coeffs = [F128::ZERO; WALK_DEGREE + 1];
    for (i, &e) in evals.iter().enumerate() {
        if e == F128::ZERO {
            continue;
        }
        for d in 0..=WALK_DEGREE {
            coeffs[d] += e * basis[i][d];
        }
    }
    coeffs
}

#[inline]
fn horner(coeffs: &[F128; WALK_DEGREE + 1], x: F128) -> F128 {
    let mut acc = coeffs[WALK_DEGREE];
    for d in (0..WALK_DEGREE).rev() {
        acc = acc * x + coeffs[d];
    }
    acc
}

/// Reconstruct the full coefficient vector from the wire form: the linear
/// coefficient is `claim + Σ_{i≥2} c_i` (char 2), making `p(0) + p(1) =
/// claim` hold by construction.
fn reconstruct(wire: &[F128; WALK_DEGREE], claim: F128) -> [F128; WALK_DEGREE + 1] {
    let mut c1 = claim;
    for &c in &wire[1..] {
        c1 += c;
    }
    let mut full = [F128::ZERO; WALK_DEGREE + 1];
    full[0] = wire[0];
    full[1] = c1;
    full[2..].copy_from_slice(&wire[1..]);
    full
}

fn compress(full: &[F128; WALK_DEGREE + 1]) -> [F128; WALK_DEGREE] {
    let mut wire = [F128::ZERO; WALK_DEGREE];
    wire[0] = full[0];
    wire[1..].copy_from_slice(&full[2..]);
    wire
}

// ---------------------------------------------------------------------------
// Shared transcript pieces
// ---------------------------------------------------------------------------

/// `c_{g,j} = Σ_i w_{g,i} · MDS[i][j]` for one group's lane weights.
fn column_weights(
    q: usize,
    lane_weights: &[F128; STATE_SIZE],
) -> [F128; STATE_SIZE] {
    let sch = schedule();
    let mds = if is_full_round(q) {
        &sch.mds_full
    } else {
        &sch.mds_partial
    };
    std::array::from_fn(|j| {
        let mut acc = F128::ZERO;
        for i in 0..STATE_SIZE {
            acc += lane_weights[i] * mds[i][j];
        }
        acc
    })
}

/// `term_j` of the layer relation applied to next-layer lane values.
fn layer_terms(q: usize, u: &[F128; STATE_SIZE]) -> [F128; STATE_SIZE] {
    let sch = schedule();
    if is_full_round(q) {
        std::array::from_fn(|j| sbox7(u[j] + sch.rc[j][q]))
    } else {
        let mut t = *u;
        t[0] = sbox7(u[0] + sch.rc[0][q]);
        t
    }
}

/// Per-group lane weights from one squeezed α: group g lane i gets
/// `α^{4g+i+1}`.
fn lane_weight_table(alpha: F128, groups: usize) -> Vec<[F128; STATE_SIZE]> {
    let mut power = F128::ONE;
    (0..groups)
        .map(|_| {
            std::array::from_fn(|_| {
                power = power * alpha;
                power
            })
        })
        .collect()
}

fn absorb_groups<Ch: Challenger>(challenger: &mut Ch, groups: &[LaneClaimGroup]) {
    challenger.observe_label(b"history-deep-chain-walk-v0");
    for g in groups {
        challenger.observe_f128_slice(&g.point);
        challenger.observe_f128_slice(&g.values);
    }
}

/// eq(a, b) for equal-length points.
pub(crate) fn eq_eval_pub(a: &[F128], b: &[F128]) -> F128 {
    eq_eval(a, b)
}

fn eq_eval(a: &[F128], b: &[F128]) -> F128 {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = F128::ONE;
    for (x, y) in a.iter().zip(b.iter()) {
        acc = acc * (*x * *y + (F128::ONE + *x) * (F128::ONE + *y));
    }
    acc
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// Prove the walk from claims on the layer-66 output columns down to a
/// claim on the layer-0 input columns (returned). `s0` holds the four
/// layer-0 columns, each of length `2^w_log`; every claim group's point has
/// `w_log` coordinates and its values must be true output-column MLE
/// evaluations (the caller's selection relations produce them).
pub fn prove_deep_chain_walk<Ch: Challenger>(
    s0: &[Vec<F128>; STATE_SIZE],
    out_groups: &[LaneClaimGroup],
    challenger: &mut Ch,
) -> (DeepChainWalkProof, LaneClaimGroup) {
    let w = s0[0].len();
    assert!(w.is_power_of_two(), "column length must be a power of two");
    let w_log = w.trailing_zeros() as usize;
    assert!(s0.iter().all(|c| c.len() == w));
    assert!(!out_groups.is_empty());
    for g in out_groups {
        assert_eq!(g.point.len(), w_log, "claim point arity");
    }

    // Layer checkpoints S_0, S_8, …: rebuild any layer with ≤7 round passes.
    let mut checkpoints: Vec<[Vec<F128>; STATE_SIZE]> = vec![s0.clone()];
    {
        let mut current = s0.clone();
        let mut q = 0usize;
        while q < N_ROUNDS {
            let step = CHECKPOINT_SPACING.min(N_ROUNDS - q);
            for dq in 0..step {
                apply_round_columns(q + dq, &mut current);
            }
            q += step;
            checkpoints.push(current.clone());
        }
    }
    let rebuild = |layer_minus_1: usize| -> [Vec<F128>; STATE_SIZE] {
        let cp = layer_minus_1 / CHECKPOINT_SPACING;
        let mut cols = checkpoints[cp].clone();
        for q in cp * CHECKPOINT_SPACING..layer_minus_1 {
            apply_round_columns(q, &mut cols);
        }
        cols
    };

    absorb_groups(challenger, out_groups);

    let mut groups: Vec<LaneClaimGroup> = out_groups.to_vec();
    let mut layers = Vec::with_capacity(N_ROUNDS);
    for layer in (1..=N_ROUNDS).rev() {
        let q = layer - 1;
        let alpha = challenger.sample_f128();
        let weights = lane_weight_table(alpha, groups.len());

        // Running claim and the E_j tables.
        let mut claim = F128::ZERO;
        for (g, w_g) in groups.iter().zip(weights.iter()) {
            for i in 0..STATE_SIZE {
                claim += w_g[i] * g.values[i];
            }
        }
        let mut e_tables: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![F128::ZERO; w]);
        for (g, w_g) in groups.iter().zip(weights.iter()) {
            let c = column_weights(q, w_g);
            let eq = build_eq_table(&g.point);
            for j in 0..STATE_SIZE {
                if c[j] == F128::ZERO {
                    continue;
                }
                e_tables[j]
                    .par_iter_mut()
                    .zip(eq.par_iter())
                    .for_each(|(slot, e)| *slot += c[j] * *e);
            }
        }
        let mut s_tables = rebuild(q);

        let mut round_coeffs = Vec::with_capacity(w_log);
        let mut point = Vec::with_capacity(w_log);
        for _round in 0..w_log {
            let half = e_tables[0].len() / 2;
            let evals = (0..half)
                .into_par_iter()
                .fold(
                    || [F128::ZERO; WALK_DEGREE + 1],
                    |mut acc, p| {
                        let mut e_base = [F128::ZERO; STATE_SIZE];
                        let mut e_delta = [F128::ZERO; STATE_SIZE];
                        let mut s_base = [F128::ZERO; STATE_SIZE];
                        let mut s_delta = [F128::ZERO; STATE_SIZE];
                        for j in 0..STATE_SIZE {
                            e_base[j] = e_tables[j][2 * p];
                            e_delta[j] = e_tables[j][2 * p] + e_tables[j][2 * p + 1];
                            s_base[j] = s_tables[j][2 * p];
                            s_delta[j] = s_tables[j][2 * p] + s_tables[j][2 * p + 1];
                        }
                        for (t, slot) in acc.iter_mut().enumerate() {
                            let t_f = f128_of_u128(t as u128);
                            let e_t: [F128; STATE_SIZE] =
                                std::array::from_fn(|j| e_base[j] + t_f * e_delta[j]);
                            let s_t: [F128; STATE_SIZE] =
                                std::array::from_fn(|j| s_base[j] + t_f * s_delta[j]);
                            let terms = layer_terms(q, &s_t);
                            let mut contrib = F128::ZERO;
                            for j in 0..STATE_SIZE {
                                contrib += e_t[j] * terms[j];
                            }
                            *slot += contrib;
                        }
                        acc
                    },
                )
                .reduce(
                    || [F128::ZERO; WALK_DEGREE + 1],
                    |mut a, b| {
                        for (x, y) in a.iter_mut().zip(b.iter()) {
                            *x += *y;
                        }
                        a
                    },
                );
            let full = interpolate(&evals);
            debug_assert_eq!(full[0] + horner(&full, F128::ONE), claim);
            let wire = compress(&full);
            challenger.observe_f128_slice(&wire);
            let r = challenger.sample_f128();
            claim = horner(&full, r);
            point.push(r);
            round_coeffs.push(wire);
            for j in 0..STATE_SIZE {
                fold_in_place(&mut e_tables[j], r);
                fold_in_place(&mut s_tables[j], r);
            }
        }

        let next_values: [F128; STATE_SIZE] = std::array::from_fn(|j| s_tables[j][0]);
        challenger.observe_f128_slice(&next_values);
        debug_assert_eq!(
            {
                let terms = layer_terms(q, &next_values);
                let mut acc = F128::ZERO;
                for j in 0..STATE_SIZE {
                    acc += e_tables[j][0] * terms[j];
                }
                acc
            },
            claim,
            "layer {layer} prover-side final mismatch"
        );

        layers.push(WalkLayerProof {
            round_coeffs,
            next_values,
        });
        groups = vec![LaneClaimGroup {
            point: point.clone(),
            values: next_values,
        }];
    }

    (
        DeepChainWalkProof { layers },
        groups.pop().expect("one terminal group"),
    )
}

fn apply_round_columns(q: usize, cols: &mut [Vec<F128>; STATE_SIZE]) {
    let w = cols[0].len();
    let mut out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let chunk = 1usize.max(w / (rayon::current_num_threads().max(1) * 4));
    out.par_iter_mut().enumerate().for_each(|(i, out_col)| {
        // Recompute per output lane to keep the loop embarrassingly
        // parallel without slot-major transposes.
        out_col
            .par_chunks_mut(chunk)
            .enumerate()
            .for_each(|(c, slots)| {
                for (dw, slot) in slots.iter_mut().enumerate() {
                    let widx = c * chunk + dw;
                    let state: [F128; STATE_SIZE] =
                        std::array::from_fn(|j| cols[j][widx]);
                    *slot = apply_round(q, state)[i];
                }
            });
    });
    *cols = out;
}

#[inline]
fn fold_in_place(table: &mut Vec<F128>, r: F128) {
    let half = table.len() / 2;
    let folded: Vec<F128> = (0..half)
        .into_par_iter()
        .map(|p| {
            let a = table[2 * p];
            let b = table[2 * p + 1];
            a + r * (a + b)
        })
        .collect();
    *table = folded;
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify the walk; returns the terminal layer-0 claim the caller must
/// discharge against committed input columns.
pub fn verify_deep_chain_walk<Ch: Challenger>(
    w_log: usize,
    out_groups: &[LaneClaimGroup],
    proof: &DeepChainWalkProof,
    challenger: &mut Ch,
) -> Result<LaneClaimGroup, WalkError> {
    if out_groups.is_empty()
        || out_groups.iter().any(|g| g.point.len() != w_log)
        || proof.layers.len() != N_ROUNDS
        || proof
            .layers
            .iter()
            .any(|l| l.round_coeffs.len() != w_log)
    {
        return Err(WalkError::Shape);
    }

    absorb_groups(challenger, out_groups);

    let mut groups: Vec<LaneClaimGroup> = out_groups.to_vec();
    for (li, layer_proof) in proof.layers.iter().enumerate() {
        let layer = N_ROUNDS - li;
        let q = layer - 1;
        let alpha = challenger.sample_f128();
        let weights = lane_weight_table(alpha, groups.len());

        let mut claim = F128::ZERO;
        for (g, w_g) in groups.iter().zip(weights.iter()) {
            for i in 0..STATE_SIZE {
                claim += w_g[i] * g.values[i];
            }
        }

        let mut point = Vec::with_capacity(w_log);
        for wire in &layer_proof.round_coeffs {
            challenger.observe_f128_slice(wire);
            let full = reconstruct(wire, claim);
            let r = challenger.sample_f128();
            claim = horner(&full, r);
            point.push(r);
        }
        challenger.observe_f128_slice(&layer_proof.next_values);

        // E_j(point) = Σ_g c_{g,j} · eq(ρ_g, point), then reassemble.
        let mut expected = F128::ZERO;
        let terms = layer_terms(q, &layer_proof.next_values);
        for (g, w_g) in groups.iter().zip(weights.iter()) {
            let c = column_weights(q, w_g);
            let eq = eq_eval(&g.point, &point);
            let mut dot = F128::ZERO;
            for j in 0..STATE_SIZE {
                dot += c[j] * terms[j];
            }
            expected += eq * dot;
        }
        if expected != claim {
            return Err(WalkError::LayerMismatch(layer));
        }

        groups = vec![LaneClaimGroup {
            point,
            values: layer_proof.next_values,
        }];
    }

    Ok(groups.pop().expect("one terminal group"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::FsLaneChallenger;

    struct Rng(u64);
    impl Rng {
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
    }

    fn mle_eval(col: &[F128], point: &[F128]) -> F128 {
        let eq = build_eq_table(point);
        let mut acc = F128::ZERO;
        for (v, e) in col.iter().zip(eq.iter()) {
            acc += *v * *e;
        }
        acc
    }

    fn random_columns(w_log: usize, seed: u64) -> [Vec<F128>; STATE_SIZE] {
        let mut rng = Rng(seed);
        std::array::from_fn(|_| (0..1usize << w_log).map(|_| rng.f128()).collect())
    }

    fn output_columns(s0: &[Vec<F128>; STATE_SIZE]) -> [Vec<F128>; STATE_SIZE] {
        let w = s0[0].len();
        let mut out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
        for widx in 0..w {
            let mut state: [F128; STATE_SIZE] = std::array::from_fn(|j| s0[j][widx]);
            for q in 0..N_ROUNDS {
                state = apply_round(q, state);
            }
            for j in 0..STATE_SIZE {
                out[j][widx] = state[j];
            }
        }
        out
    }

    /// The layer schedule composed with `initial_mds` IS the production
    /// permutation, slot by slot — the structural anchor of the whole walk.
    #[test]
    fn rounds_compose_to_the_native_permutation() {
        use noid_poseidon2b::native::permutation::permute_flat_u128;
        let mut rng = Rng(0xD5E9);
        for _ in 0..8 {
            let raw: [F128; STATE_SIZE] = std::array::from_fn(|_| rng.f128());
            let mut state = initial_mds(raw);
            for q in 0..N_ROUNDS {
                state = apply_round(q, state);
            }
            let mut flat: [u128; STATE_SIZE] =
                std::array::from_fn(|i| (raw[i].lo as u128) | ((raw[i].hi as u128) << 64));
            permute_flat_u128(&mut flat);
            let expected: [F128; STATE_SIZE] = std::array::from_fn(|i| F128 {
                lo: flat[i] as u64,
                hi: (flat[i] >> 64) as u64,
            });
            assert_eq!(state, expected, "walk rounds diverge from permute_flat");
        }
    }

    #[test]
    fn interpolation_roundtrips() {
        let mut rng = Rng(0x1E77);
        let coeffs: [F128; WALK_DEGREE + 1] = std::array::from_fn(|_| rng.f128());
        let evals: [F128; WALK_DEGREE + 1] =
            std::array::from_fn(|t| horner(&coeffs, f128_of_u128(t as u128)));
        assert_eq!(interpolate(&evals), coeffs);
    }

    #[test]
    fn walk_roundtrip_single_and_multi_group() {
        for (w_log, n_groups, seed) in [(0usize, 1usize, 11u64), (4, 1, 12), (5, 2, 13)] {
            let s0 = random_columns(w_log, seed);
            let out = output_columns(&s0);
            let mut rng = Rng(seed ^ 0xFF);
            let groups: Vec<LaneClaimGroup> = (0..n_groups)
                .map(|_| {
                    let point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
                    let values: [F128; STATE_SIZE] =
                        std::array::from_fn(|j| mle_eval(&out[j], &point));
                    LaneClaimGroup { point, values }
                })
                .collect();

            let mut ch_p = FsLaneChallenger::new(b"deep-chain-test");
            let (proof, s0_claim_p) = prove_deep_chain_walk(&s0, &groups, &mut ch_p);

            let mut ch_v = FsLaneChallenger::new(b"deep-chain-test");
            let s0_claim_v = verify_deep_chain_walk(w_log, &groups, &proof, &mut ch_v)
                .unwrap_or_else(|e| panic!("honest walk rejected (w_log={w_log}): {e}"));
            assert_eq!(s0_claim_p, s0_claim_v);
            assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "lockstep");

            // The terminal claim is TRUE against the layer-0 columns.
            for j in 0..STATE_SIZE {
                assert_eq!(
                    mle_eval(&s0[j], &s0_claim_v.point),
                    s0_claim_v.values[j],
                    "terminal claim lane {j}"
                );
            }
        }
    }

    /// A forged output claim yields a walk whose terminal claim is FALSE
    /// against the true input columns — the discharge (committed-column
    /// opening) is what catches it, exactly as designed.
    #[test]
    fn forged_output_claim_shifts_the_terminal_claim() {
        let w_log = 4;
        let s0 = random_columns(w_log, 21);
        let out = output_columns(&s0);
        let mut rng = Rng(0x21FF);
        let point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
        let mut values: [F128; STATE_SIZE] =
            std::array::from_fn(|j| mle_eval(&out[j], &point));
        values[2] += F128::ONE;
        let groups = [LaneClaimGroup { point, values }];

        let mut ch_p = FsLaneChallenger::new(b"deep-chain-test");
        let (proof, _) = prove_deep_chain_walk(&s0, &groups, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(b"deep-chain-test");
        match verify_deep_chain_walk(w_log, &groups, &proof, &mut ch_v) {
            // The layer chain catches the forged batched claim directly...
            Err(_) => {}
            // ...or the surviving terminal claim must be FALSE against the
            // true input columns, so the committed-column discharge kills it.
            Ok(claim) => {
                let honest = (0..STATE_SIZE)
                    .all(|j| mle_eval(&s0[j], &claim.point) == claim.values[j]);
                assert!(!honest, "forged output claim survived to an honest terminal");
            }
        }
    }

    /// Wire-level mutations: flipping any round coefficient or next-value
    /// lane in any layer must be rejected (or shift the terminal claim off
    /// the true columns — either way the proof chain cannot survive).
    #[test]
    fn walk_rejects_wire_mutations() {
        let w_log = 3;
        let s0 = random_columns(w_log, 31);
        let out = output_columns(&s0);
        let mut rng = Rng(0x31AA);
        let point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
        let values: [F128; STATE_SIZE] = std::array::from_fn(|j| mle_eval(&out[j], &point));
        let groups = [LaneClaimGroup { point, values }];

        let mut ch_p = FsLaneChallenger::new(b"deep-chain-test");
        let (proof, _) = prove_deep_chain_walk(&s0, &groups, &mut ch_p);

        let mut survivors = Vec::new();
        for li in [0usize, 1, N_ROUNDS / 2, N_ROUNDS - 1] {
            for round in 0..w_log {
                for coeff in 0..WALK_DEGREE {
                    let mut bad = proof.clone();
                    bad.layers[li].round_coeffs[round][coeff] += F128::ONE;
                    let mut ch = FsLaneChallenger::new(b"deep-chain-test");
                    match verify_deep_chain_walk(w_log, &groups, &bad, &mut ch) {
                        Err(_) => {}
                        Ok(claim) => {
                            let honest = (0..STATE_SIZE).all(|j| {
                                mle_eval(&s0[j], &claim.point) == claim.values[j]
                            });
                            if honest {
                                survivors.push((li, round, coeff));
                            }
                        }
                    }
                }
            }
            for lane in 0..STATE_SIZE {
                let mut bad = proof.clone();
                bad.layers[li].next_values[lane] += F128::ONE;
                let mut ch = FsLaneChallenger::new(b"deep-chain-test");
                match verify_deep_chain_walk(w_log, &groups, &bad, &mut ch) {
                    Err(_) => {}
                    Ok(claim) => {
                        let honest = (0..STATE_SIZE)
                            .all(|j| mle_eval(&s0[j], &claim.point) == claim.values[j]);
                        if honest {
                            survivors.push((li, 99, lane));
                        }
                    }
                }
            }
        }
        assert!(survivors.is_empty(), "walk mutation survivors: {survivors:?}");
    }

    #[test]
    fn walk_rejects_shape_mismatches() {
        let w_log = 3;
        let s0 = random_columns(w_log, 41);
        let out = output_columns(&s0);
        let mut rng = Rng(0x41BB);
        let point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
        let values: [F128; STATE_SIZE] = std::array::from_fn(|j| mle_eval(&out[j], &point));
        let groups = [LaneClaimGroup { point, values }];
        let mut ch_p = FsLaneChallenger::new(b"deep-chain-test");
        let (proof, _) = prove_deep_chain_walk(&s0, &groups, &mut ch_p);

        let mut short = proof.clone();
        short.layers.pop();
        let mut ch = FsLaneChallenger::new(b"deep-chain-test");
        assert_eq!(
            verify_deep_chain_walk(w_log, &groups, &short, &mut ch),
            Err(WalkError::Shape)
        );

        let mut ch = FsLaneChallenger::new(b"deep-chain-test");
        assert_eq!(
            verify_deep_chain_walk(w_log + 1, &groups, &proof, &mut ch),
            Err(WalkError::Shape)
        );
    }
}
