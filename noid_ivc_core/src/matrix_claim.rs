//! Deferred matrix-consistency claims for the self-verification chain.
//!
//! The lincheck verifier's final consistency is a bilinear evaluation of
//! the CONSTANT instance matrices:
//!
//! ```text
//!   final = Σ_{r,c} (α·A + B)[r,c] · u[r] · v[c] + β·v[const_pin]
//!   u[r]  = λ(z_skip)[r mod 64] · eq(x_inner_rest)[r div 64]
//!   v[c]  = z_partial[c mod 64] · eq(r_inner_rest)[c div 64]
//! ```
//!
//! A trace that replays a verifier of ITS OWN proof class cannot bake
//! those matrices as constants (the matrix would have to contain its own
//! description). This module removes the matrices from the trace
//! entirely: the α-batched bilinear form becomes a CLAIM about the
//! stacked matrix `M̂ = [A; B]` (one extra top row bit `b`, with the α
//! weight moved into the multilinear factor `ŵ(b) = α + b·(α+1)`), and
//! each chain link FOLDS its fresh structured claim with the incoming
//! accumulated claim into one plain MLE claim `M̂~(point) = value`,
//! carried in the link's public IO. Only the DECIDER ever touches the
//! matrix: one native `M̂~` evaluation against the final accumulator.
//!
//! The fold is two dense product sumchecks (domain split, everything
//! O(nnz + 2^{k_log}) for the prover, O(k_log) rounds for the verifier):
//!
//! - Phase 1 over `y = (r, b)`:
//!   `t + γ·gate·w_in = Σ_y [ ŵu(y)·G_v(y) + γ·gate·eq(p_in^{rb}, y)·G_e(y) ]`
//!   with `G_v = M̂·v`, `G_e = M̂·eq(p_in^c, ·)` dense row images.
//! - Phase 2 over `c`, after batching the two derived G-claims with δ:
//!   `G_v~(ρ) + δ·gate·G_e~(ρ) = Σ_c H(c)·[v(c) + δ·gate·eq(p_in^c, c)]`
//!   with `H(c) = Σ_y eq(ρ, y)·M̂[y, c]`; its final value is exactly
//!   `M̂~(ρ ‖ σ)` — the outgoing accumulator claim.
//!
//! Claim point order: `point = [ρ_0..ρ_{k_log}] ‖ [σ_0..σ_{k_log−1}]`
//! where ρ covers the row bits LSB-first with the stack bit `b` LAST
//! (index `k_log`), and σ covers the column bits LSB-first.
//!
//! The genesis link has no incoming claim: `gate = 0` multiplies the
//! incoming weight out of BOTH phases, and the accumulator degenerates
//! to the fresh claim's reduction.

use crate::challenger::Challenger;
use crate::field::F128;
use crate::field_r1cs::FieldR1cs;
use crate::field_r1cs::FieldR1csArtifactError;
use crate::lincheck::build_eq_table;
use crate::proof::FieldShape;
use crate::zerocheck::multilinear::lagrange_weights_naive;
use rayon::prelude::*;

/// A plain accumulated claim `M̂~(point) = value` on the stacked matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatrixAccClaim {
    /// `2·k_log + 1` coordinates (see the module docs for the order).
    pub point: Vec<F128>,
    pub value: F128,
}

impl MatrixAccClaim {
    pub fn zero(k_log: usize) -> Self {
        Self {
            point: vec![F128::ZERO; 2 * k_log + 1],
            value: F128::ZERO,
        }
    }
}

/// The structured claim a deferred lincheck final emits: the transcript
/// ingredients that define `u`, `v`, the α weight and the claimed value
/// `t = Σ ŵ(b)·u[r]·v[c]·M̂[(r,b),c]`.
#[derive(Clone, Debug)]
pub struct FreshLincheckClaim {
    pub alpha: F128,
    pub z_skip: F128,
    pub x_inner_rest: Vec<F128>,
    pub r_inner_rest: Vec<F128>,
    pub z_partial: Vec<F128>,
    pub value: F128,
}

/// Authenticated evaluations produced by a matrix claim source in one pass.
///
/// The structural digest is deliberately returned alongside the values: a
/// caller must compare it with its canonical class registry before accepting
/// either optional evaluation.  Disk-backed implementations compute all
/// requested values from the exact row bytes fed into this digest, so a
/// matrix never needs to be materialized as a resident [`FieldR1cs`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedMatrixClaimEvaluations {
    structural_digest: [u8; 32],
    fresh_value: Option<F128>,
    accumulated_value: Option<F128>,
}

impl AuthenticatedMatrixClaimEvaluations {
    pub const fn structural_digest(&self) -> [u8; 32] {
        self.structural_digest
    }

    pub const fn fresh_value(&self) -> Option<F128> {
        self.fresh_value
    }

    pub const fn accumulated_value(&self) -> Option<F128> {
        self.accumulated_value
    }

    pub(crate) const fn new(
        structural_digest: [u8; 32],
        fresh_value: Option<F128>,
        accumulated_value: Option<F128>,
    ) -> Self {
        Self {
            structural_digest,
            fresh_value,
            accumulated_value,
        }
    }
}

/// Bounded matrix-evaluation boundary used by the terminal history decider.
///
/// At most one fresh and one accumulated claim are needed for a class at a
/// time.  Keeping that bound in the API lets an on-disk implementation scan
/// both canonical matrices once with fixed-size buffers.  Implementations
/// must recompute `structural_digest` from the same decoded rows used for the
/// evaluations; cached or externally supplied digest metadata is not valid
/// authority here. The success object has no public constructor: external
/// adapters may delegate to a core evaluator, but cannot manufacture a digest
/// or claim value in safe Rust.
pub trait MatrixClaimEvaluator {
    fn field_shape(&self) -> FieldShape;

    fn evaluate_matrix_claims(
        &mut self,
        fresh: Option<&FreshLincheckClaim>,
        accumulated: Option<&MatrixAccClaim>,
    ) -> Result<AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError>;
}

impl MatrixClaimEvaluator for FieldR1cs {
    fn field_shape(&self) -> FieldShape {
        FieldShape::of(self)
    }

    fn evaluate_matrix_claims(
        &mut self,
        fresh: Option<&FreshLincheckClaim>,
        accumulated: Option<&MatrixAccClaim>,
    ) -> Result<AuthenticatedMatrixClaimEvaluations, FieldR1csArtifactError> {
        if let Some(claim) = fresh {
            let rest = self.k_log - self.k_skip;
            if claim.x_inner_rest.len() != rest || claim.r_inner_rest.len() != rest {
                return Err(FieldR1csArtifactError::MatrixClaimShape(
                    "fresh inner-rest width",
                ));
            }
            if claim.z_partial.len() != 1usize << self.k_skip {
                return Err(FieldR1csArtifactError::MatrixClaimShape(
                    "fresh partial window",
                ));
            }
        }
        if accumulated.is_some_and(|claim| claim.point.len() != 2 * self.k_log + 1) {
            return Err(FieldR1csArtifactError::MatrixClaimShape(
                "accumulated point width",
            ));
        }
        Ok(AuthenticatedMatrixClaimEvaluations::new(
            self.structural_statement_digest(),
            fresh.map(|claim| fresh_claim_value(self, claim)),
            accumulated.map(|claim| stacked_matrix_mle_eval(self, claim)),
        ))
    }
}

/// Proof wires of one accumulator fold: phase-1 rounds (`k_log + 1`),
/// the two derived G values, phase-2 rounds (`k_log`), and the final
/// matrix evaluation (= the outgoing claim value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatrixFoldProof {
    /// Compressed degree-2 rounds `[c_0, c_2]`.
    pub phase1_rounds: Vec<[F128; 2]>,
    pub g_v: F128,
    pub g_e: F128,
    pub phase2_rounds: Vec<[F128; 2]>,
    pub final_matrix_eval: F128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixFoldError {
    Shape,
    FinalMismatch,
}

impl std::fmt::Display for MatrixFoldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatrixFoldError::Shape => write!(f, "matrix fold proof shape mismatch"),
            MatrixFoldError::FinalMismatch => write!(f, "matrix fold final mismatch"),
        }
    }
}

/// eq(a, b) over two equal-length coordinate vectors.
pub fn eq_points(a: &[F128], b: &[F128]) -> F128 {
    assert_eq!(a.len(), b.len());
    let mut acc = F128::ONE;
    for (x, y) in a.iter().zip(b.iter()) {
        acc = acc * (*x * *y + (F128::ONE + *x) * (F128::ONE + *y));
    }
    acc
}

/// MLE of a small value vector (the λ / z_partial 64-slot windows) at a
/// point of `log2(len)` coordinates.
pub fn small_mle_eval(values: &[F128], point: &[F128]) -> F128 {
    assert_eq!(values.len(), 1usize << point.len());
    let eq = build_eq_table(point);
    let mut acc = F128::ZERO;
    for (v, e) in values.iter().zip(eq.iter()) {
        acc += *v * *e;
    }
    acc
}

/// `ŵ(x_b) = α + x_b·(α + 1)`: the multilinear α weight of the stack bit
/// (`ŵ(0) = α` selects A, `ŵ(1) = 1` selects B).
fn alpha_weight(alpha: F128, x_b: F128) -> F128 {
    alpha + x_b * (alpha + F128::ONE)
}

/// The u-side weight MLE at a row point (λ window on the low `k_skip`
/// coordinates, eq(x_inner_rest) on the rest, ŵ on the stack bit).
fn u_weight_eval(fresh: &FreshLincheckClaim, k_skip: usize, rho: &[F128]) -> F128 {
    let ell_log = k_skip;
    let lambda = lagrange_weights_naive(k_skip, fresh.z_skip);
    let lam = small_mle_eval(&lambda, &rho[..ell_log]);
    let e = eq_points(&fresh.x_inner_rest, &rho[ell_log..rho.len() - 1]);
    let w = alpha_weight(fresh.alpha, rho[rho.len() - 1]);
    lam * e * w
}

/// The v-side weight MLE at a column point.
fn v_weight_eval(fresh: &FreshLincheckClaim, k_skip: usize, sigma: &[F128]) -> F128 {
    let zp = small_mle_eval(&fresh.z_partial, &sigma[..k_skip]);
    let q = eq_points(&fresh.r_inner_rest, &sigma[k_skip..]);
    zp * q
}

fn absorb_fold_header<Ch: Challenger>(
    ch: &mut Ch,
    fresh: &FreshLincheckClaim,
    incoming: &MatrixAccClaim,
    gate: F128,
) {
    ch.observe_label(b"history-matrix-claim-fold-v0");
    ch.observe_f128(fresh.alpha);
    ch.observe_f128(fresh.z_skip);
    ch.observe_f128_slice(&fresh.x_inner_rest);
    ch.observe_f128_slice(&fresh.r_inner_rest);
    ch.observe_f128_slice(&fresh.z_partial);
    ch.observe_f128(fresh.value);
    ch.observe_f128_slice(&incoming.point);
    ch.observe_f128(incoming.value);
    ch.observe_f128(gate);
}

fn fold_table_pairs(table: &mut Vec<F128>, r: F128) {
    let half = table.len() / 2;
    if half >= 1024 {
        let folded: Vec<F128> = (0..half)
            .into_par_iter()
            .map(|p| {
                let a = table[2 * p];
                let b = table[2 * p + 1];
                a + r * (a + b)
            })
            .collect();
        *table = folded;
    } else {
        for p in 0..half {
            let a = table[2 * p];
            let b = table[2 * p + 1];
            table[p] = a + r * (a + b);
        }
        table.truncate(half);
    }
}

/// One degree-2 product-sumcheck round over paired tables: evaluations of
/// `Σ_p Π_i tbl_i` at t ∈ {0, 1, 2} for two product terms.
fn round_evals_two_products(w1: &[F128], g1: &[F128], w2: &[F128], g2: &[F128]) -> [F128; 3] {
    let half = w1.len() / 2;
    let two = F128 { lo: 2, hi: 0 };
    (0..half)
        .into_par_iter()
        .fold(
            || [F128::ZERO; 3],
            |mut acc, p| {
                let pairs = [
                    (w1[2 * p], w1[2 * p + 1], g1[2 * p], g1[2 * p + 1]),
                    (w2[2 * p], w2[2 * p + 1], g2[2 * p], g2[2 * p + 1]),
                ];
                for (w0, w1v, g0, g1v) in pairs {
                    let wd = w0 + w1v;
                    let gd = g0 + g1v;
                    acc[0] += w0 * g0;
                    acc[1] += w1v * g1v;
                    let w2v = w0 + two * wd;
                    let g2v = g0 + two * gd;
                    acc[2] += w2v * g2v;
                }
                acc
            },
        )
        .reduce(
            || [F128::ZERO; 3],
            |mut a, b| {
                for (x, y) in a.iter_mut().zip(b.iter()) {
                    *x += *y;
                }
                a
            },
        )
}

/// Run one phase of the fold: a degree-2 sumcheck over two product terms
/// with compressed `[c_0, c_2]` round wires. Returns (rounds, point).
fn run_phase<Ch: Challenger>(
    mut claim: F128,
    mut w1: Vec<F128>,
    mut g1: Vec<F128>,
    mut w2: Vec<F128>,
    mut g2: Vec<F128>,
    ch: &mut Ch,
) -> (Vec<[F128; 2]>, Vec<F128>, F128, [F128; 4]) {
    let n_rounds = w1.len().trailing_zeros() as usize;
    let mut rounds = Vec::with_capacity(n_rounds);
    let mut point = Vec::with_capacity(n_rounds);
    let two = F128 { lo: 2, hi: 0 };
    for _ in 0..n_rounds {
        let evals = round_evals_two_products(&w1, &g1, &w2, &g2);
        // Degree-2 interpolation at nodes 0,1,2 (char-2 exact, flat basis).
        let c0 = evals[0];
        let s1 = evals[1] + c0;
        let s2 = evals[2] + c0;
        let det_inv = crate::deep_chain::f128_inv_pub(two * two + two);
        let c2 = (s2 + two * s1) * det_inv;
        let c1 = s1 + c2;
        debug_assert_eq!(evals[0] + evals[1], claim, "phase round sum mismatch");
        let wire = [c0, c2];
        ch.observe_f128_slice(&wire);
        let r = ch.sample_f128();
        claim = (c2 * r + c1) * r + c0;
        rounds.push(wire);
        point.push(r);
        fold_table_pairs(&mut w1, r);
        fold_table_pairs(&mut g1, r);
        fold_table_pairs(&mut w2, r);
        fold_table_pairs(&mut g2, r);
    }
    (rounds, point, claim, [w1[0], g1[0], w2[0], g2[0]])
}

/// Prove one accumulator fold. `gate` is 1 to include the incoming claim
/// (regular links) or 0 to ignore it (the genesis link, whose incoming
/// lanes are unconstrained). Returns the proof and the outgoing claim.
pub fn prove_matrix_claim_fold<Ch: Challenger>(
    r1cs: &FieldR1cs,
    fresh: &FreshLincheckClaim,
    incoming: &MatrixAccClaim,
    gate: bool,
    ch: &mut Ch,
) -> (MatrixFoldProof, MatrixAccClaim) {
    let k_log = r1cs.k_log;
    let k_skip = r1cs.k_skip;
    let k = 1usize << k_log;
    assert_eq!(fresh.x_inner_rest.len(), k_log - k_skip);
    assert_eq!(fresh.r_inner_rest.len(), k_log - k_skip);
    assert_eq!(fresh.z_partial.len(), 1usize << k_skip);
    assert_eq!(incoming.point.len(), 2 * k_log + 1);

    let gate_f = if gate { F128::ONE } else { F128::ZERO };
    absorb_fold_header(ch, fresh, incoming, gate_f);
    let gamma = ch.sample_f128();

    let (p_in_row, p_in_col) = incoming.point.split_at(k_log + 1);

    // Dense weight/value tables.
    // v(c) = z_partial[c mod 64]·eq(r_inner_rest)[c div 64].
    let q_tensor = build_eq_table(&fresh.r_inner_rest);
    let mut v_table = vec![F128::ZERO; k];
    v_table
        .par_chunks_mut(1 << k_skip)
        .zip(q_tensor.par_iter())
        .for_each(|(chunk, &q)| {
            for (slot, zp) in chunk.iter_mut().zip(fresh.z_partial.iter()) {
                *slot = *zp * q;
            }
        });
    // e_c(c) = eq(p_in^c, c).
    let e_c = build_eq_table(p_in_col);

    // G_v, G_e: row images of M̂ against v and e_c. Row index y = r + b·k.
    let mut g_v = vec![F128::ZERO; 2 * k];
    let mut g_e = vec![F128::ZERO; 2 * k];
    let halves = [(&r1cs.a_0, 0usize), (&r1cs.b_0, k)];
    for (m, off) in halves {
        g_v[..]
            .par_iter_mut()
            .zip(g_e.par_iter_mut())
            .skip(off)
            .take(k)
            .enumerate()
            .for_each(|(r, (gv, ge))| {
                if r < m.num_rows {
                    let mut av = F128::ZERO;
                    let mut ae = F128::ZERO;
                    for (c, kappa) in m.row(r) {
                        av += kappa * v_table[c as usize];
                        ae += kappa * e_c[c as usize];
                    }
                    *gv = av;
                    *ge = ae;
                }
            });
    }

    // Phase-1 weights over y = (r, b): ŵu and γ·gate·eq(p_in^{rb}).
    let lambda = lagrange_weights_naive(k_skip, fresh.z_skip);
    let e_tensor = build_eq_table(&fresh.x_inner_rest);
    let mut w_u = vec![F128::ZERO; 2 * k];
    let (alpha_a, alpha_b) = (fresh.alpha, F128::ONE);
    w_u.par_chunks_mut(1 << k_skip)
        .enumerate()
        .for_each(|(hi, chunk)| {
            let b = hi >> (k_log - k_skip);
            let e = e_tensor[hi & ((1 << (k_log - k_skip)) - 1)];
            let wa = if b == 0 { alpha_a } else { alpha_b };
            for (slot, lam) in chunk.iter_mut().zip(lambda.iter()) {
                *slot = *lam * e * wa;
            }
        });
    let mut w_in_row = build_eq_table(p_in_row);
    let gg = gamma * gate_f;
    w_in_row.par_iter_mut().for_each(|x| *x = *x * gg);

    let target1 = fresh.value + gg * incoming.value;
    let (phase1_rounds, rho, claim1, finals1) = run_phase(target1, w_u, g_v, w_in_row, g_e, ch);
    // finals1 = [ŵu~(ρ), G_v~(ρ), γ·gate·eq~(ρ), G_e~(ρ)].
    let g_v_val = finals1[1];
    let g_e_val = finals1[3];
    debug_assert_eq!(
        finals1[0] * g_v_val + finals1[2] * g_e_val,
        claim1,
        "phase-1 terminal mismatch"
    );
    ch.observe_f128(g_v_val);
    ch.observe_f128(g_e_val);
    let delta = ch.sample_f128();

    // H(c) = Σ_y eq(ρ, y)·M̂[y, c].
    let eq_rho = build_eq_table(&rho);
    let mut h = vec![F128::ZERO; k];
    {
        // Scatter per row: H[c] += eq_rho[y]·κ. Parallel over column
        // stripes would race; accumulate per thread then reduce.
        let parts: Vec<Vec<F128>> = halves
            .par_iter()
            .map(|(m, off)| {
                let mut acc = vec![F128::ZERO; k];
                for r in 0..m.num_rows {
                    let w = eq_rho[off + r];
                    if w == F128::ZERO {
                        continue;
                    }
                    for (c, kappa) in m.row(r) {
                        acc[c as usize] += kappa * w;
                    }
                }
                acc
            })
            .collect();
        for part in parts {
            h.par_iter_mut().zip(part.par_iter()).for_each(|(a, b)| {
                *a += *b;
            });
        }
    }

    // Phase 2 over c: target = G_v~ + δ·gate·G_e~, weight = v + δ·gate·e_c.
    let dg = delta * gate_f;
    let mut w2 = v_table;
    w2.par_iter_mut().zip(e_c.par_iter()).for_each(|(w, e)| {
        *w += dg * *e;
    });
    let target2 = g_v_val + dg * g_e_val;
    let zero = vec![F128::ZERO; k];
    let (phase2_rounds, sigma, claim2, finals2) = run_phase(target2, w2, h, zero.clone(), zero, ch);
    let final_matrix_eval = finals2[1];
    debug_assert_eq!(
        finals2[0] * final_matrix_eval,
        claim2,
        "phase-2 terminal mismatch"
    );
    ch.observe_f128(final_matrix_eval);

    let mut point = rho;
    point.extend(sigma);
    (
        MatrixFoldProof {
            phase1_rounds,
            g_v: g_v_val,
            g_e: g_e_val,
            phase2_rounds,
            final_matrix_eval,
        },
        MatrixAccClaim {
            point,
            value: final_matrix_eval,
        },
    )
}

/// Verify one accumulator fold (matrix-free: only claim data and the
/// proof wires). Returns the outgoing accumulated claim.
pub fn verify_matrix_claim_fold<Ch: Challenger>(
    k_log: usize,
    k_skip: usize,
    fresh: &FreshLincheckClaim,
    incoming: &MatrixAccClaim,
    gate: F128,
    proof: &MatrixFoldProof,
    ch: &mut Ch,
) -> Result<MatrixAccClaim, MatrixFoldError> {
    if fresh.x_inner_rest.len() != k_log - k_skip
        || fresh.r_inner_rest.len() != k_log - k_skip
        || fresh.z_partial.len() != 1usize << k_skip
        || incoming.point.len() != 2 * k_log + 1
        || proof.phase1_rounds.len() != k_log + 1
        || proof.phase2_rounds.len() != k_log
    {
        return Err(MatrixFoldError::Shape);
    }

    absorb_fold_header(ch, fresh, incoming, gate);
    let gamma = ch.sample_f128();
    let gg = gamma * gate;
    let (p_in_row, p_in_col) = incoming.point.split_at(k_log + 1);

    let mut claim = fresh.value + gg * incoming.value;
    let mut rho = Vec::with_capacity(k_log + 1);
    for wire in &proof.phase1_rounds {
        ch.observe_f128_slice(wire);
        let c1 = claim + wire[1];
        let r = ch.sample_f128();
        claim = (wire[1] * r + c1) * r + wire[0];
        rho.push(r);
    }
    // Terminal: ŵu~(ρ)·G_v + γ·gate·eq(p_in^{rb}, ρ)·G_e == claim.
    let wu = u_weight_eval(fresh, k_skip, &rho);
    let ein = eq_points(p_in_row, &rho);
    if wu * proof.g_v + gg * ein * proof.g_e != claim {
        return Err(MatrixFoldError::FinalMismatch);
    }
    ch.observe_f128(proof.g_v);
    ch.observe_f128(proof.g_e);
    let delta = ch.sample_f128();
    let dg = delta * gate;

    let mut claim = proof.g_v + dg * proof.g_e;
    let mut sigma = Vec::with_capacity(k_log);
    for wire in &proof.phase2_rounds {
        ch.observe_f128_slice(wire);
        let c1 = claim + wire[1];
        let r = ch.sample_f128();
        claim = (wire[1] * r + c1) * r + wire[0];
        sigma.push(r);
    }
    // Terminal: [ṽ(σ) + δ·gate·eq(p_in^c, σ)]·M̂~(ρ‖σ) == claim.
    let v = v_weight_eval(fresh, k_skip, &sigma);
    let ec = eq_points(p_in_col, &sigma);
    if (v + dg * ec) * proof.final_matrix_eval != claim {
        return Err(MatrixFoldError::FinalMismatch);
    }
    ch.observe_f128(proof.final_matrix_eval);

    let mut point = rho;
    point.extend(sigma);
    Ok(MatrixAccClaim {
        point,
        value: proof.final_matrix_eval,
    })
}

/// Exact tensor-factored eq table.
///
/// A dense table over `d` variables retains `2^d` field elements. Splitting
/// the low/high coordinates retains only `2^floor(d/2) + 2^ceil(d/2)` and
/// reconstructs an entry with one multiplication. Indexing remains LSB-first,
/// exactly matching [`build_eq_table`].
struct FactoredEqTable {
    low: Vec<F128>,
    high: Vec<F128>,
    low_bits: usize,
    low_mask: usize,
}

impl FactoredEqTable {
    fn new(point: &[F128]) -> Self {
        let low_bits = point.len() / 2;
        let low = build_eq_table(&point[..low_bits]);
        let high = build_eq_table(&point[low_bits..]);
        Self {
            low,
            high,
            low_bits,
            low_mask: (1usize << low_bits) - 1,
        }
    }

    #[inline(always)]
    fn value(&self, index: usize) -> F128 {
        self.low[index & self.low_mask] * self.high[index >> self.low_bits]
    }
}

/// The decider's native check of an accumulated claim: evaluate the
/// stacked matrix MLE `M̂~(point)` directly from the sparse rows.
///
/// Both row and column equality tensors are factored, so the retained scratch
/// is `O(2^(k_log/2))`, not `O(2^k_log)`. At production `k_log = 24`, four
/// 4096-element factors replace two 16,777,216-element dense tables.
pub fn stacked_matrix_mle_eval(r1cs: &FieldR1cs, claim: &MatrixAccClaim) -> F128 {
    let k_log = r1cs.k_log;
    assert_eq!(claim.point.len(), 2 * k_log + 1);
    let (p_row, p_col) = claim.point.split_at(k_log + 1);
    let x_b = p_row[k_log];
    let eq_row = FactoredEqTable::new(&p_row[..k_log]);
    let eq_col = FactoredEqTable::new(p_col);
    let halves = [
        (&r1cs.a_0, F128::ONE + x_b), // b = 0 side
        (&r1cs.b_0, x_b),             // b = 1 side
    ];
    halves
        .par_iter()
        .map(|(m, w_b)| {
            (0..m.num_rows)
                .into_par_iter()
                .map(|r| {
                    let mut acc = F128::ZERO;
                    for (c, kappa) in m.row(r) {
                        acc += kappa * eq_col.value(c as usize);
                    }
                    acc * eq_row.value(r)
                })
                .reduce(|| F128::ZERO, |a, b| a + b)
                * *w_b
        })
        .reduce(|| F128::ZERO, |a, b| a + b)
}

/// The fresh-claim value a deferred lincheck final should carry, computed
/// directly from the matrices (prover/test side; the trace never runs
/// this).
pub fn fresh_claim_value(r1cs: &FieldR1cs, fresh: &FreshLincheckClaim) -> F128 {
    let k_skip = r1cs.k_skip;
    let lambda = lagrange_weights_naive(k_skip, fresh.z_skip);
    let e_tensor = FactoredEqTable::new(&fresh.x_inner_rest);
    let q_tensor = FactoredEqTable::new(&fresh.r_inner_rest);
    let mask = (1usize << k_skip) - 1;
    let halves = [(&r1cs.a_0, fresh.alpha), (&r1cs.b_0, F128::ONE)];
    halves
        .par_iter()
        .map(|(m, w)| {
            (0..m.num_rows)
                .into_par_iter()
                .map(|r| {
                    let u = lambda[r & mask] * e_tensor.value(r >> k_skip);
                    let mut acc = F128::ZERO;
                    for (c, kappa) in m.row(r) {
                        let c = c as usize;
                        acc += kappa * fresh.z_partial[c & mask] * q_tensor.value(c >> k_skip);
                    }
                    acc * u
                })
                .reduce(|| F128::ZERO, |a, b| a + b)
                * *w
        })
        .reduce(|| F128::ZERO, |a, b| a + b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::FsLaneChallenger;
    use crate::field_r1cs::SparseFieldMatrix;

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

    fn random_instance(rng: &mut Rng, k_log: usize, nnz_per_row: usize) -> FieldR1cs {
        let k = 1usize << k_log;
        let mk = |rng: &mut Rng| {
            SparseFieldMatrix::from_rows(
                k,
                (0..k)
                    .map(|_| {
                        (0..nnz_per_row)
                            .map(|_| ((rng.next_u64() as usize % k) as u32, rng.f128()))
                            .collect()
                    })
                    .collect(),
            )
        };
        FieldR1cs {
            m: k_log,
            k_log,
            k_skip: 6,
            useful_rows: k,
            a_0: mk(rng),
            b_0: mk(rng),
            const_pin: Some(0),
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        }
    }

    fn random_fresh(rng: &mut Rng, r1cs: &FieldR1cs) -> FreshLincheckClaim {
        let rest = r1cs.k_log - r1cs.k_skip;
        let mut fresh = FreshLincheckClaim {
            alpha: rng.f128(),
            z_skip: rng.f128(),
            x_inner_rest: (0..rest).map(|_| rng.f128()).collect(),
            r_inner_rest: (0..rest).map(|_| rng.f128()).collect(),
            z_partial: (0..1 << r1cs.k_skip).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        fresh.value = fresh_claim_value(r1cs, &fresh);
        fresh
    }

    fn random_true_acc(rng: &mut Rng, r1cs: &FieldR1cs) -> MatrixAccClaim {
        let mut acc = MatrixAccClaim {
            point: (0..2 * r1cs.k_log + 1).map(|_| rng.f128()).collect(),
            value: F128::ZERO,
        };
        acc.value = stacked_matrix_mle_eval(r1cs, &acc);
        acc
    }

    fn stacked_matrix_mle_eval_dense_reference(r1cs: &FieldR1cs, claim: &MatrixAccClaim) -> F128 {
        let k_log = r1cs.k_log;
        let (p_row, p_col) = claim.point.split_at(k_log + 1);
        let x_b = p_row[k_log];
        let eq_row = build_eq_table(&p_row[..k_log]);
        let eq_col = build_eq_table(p_col);
        let mut total = F128::ZERO;
        for (matrix, weight) in [(&r1cs.a_0, F128::ONE + x_b), (&r1cs.b_0, x_b)] {
            let mut half = F128::ZERO;
            for r in 0..matrix.num_rows {
                let mut row = F128::ZERO;
                for (c, kappa) in matrix.row(r) {
                    row += kappa * eq_col[c as usize];
                }
                half += row * eq_row[r];
            }
            total += half * weight;
        }
        total
    }

    fn fresh_claim_value_dense_reference(r1cs: &FieldR1cs, fresh: &FreshLincheckClaim) -> F128 {
        let lambda = lagrange_weights_naive(r1cs.k_skip, fresh.z_skip);
        let e_tensor = build_eq_table(&fresh.x_inner_rest);
        let q_tensor = build_eq_table(&fresh.r_inner_rest);
        let mask = (1usize << r1cs.k_skip) - 1;
        let mut total = F128::ZERO;
        for (matrix, weight) in [(&r1cs.a_0, fresh.alpha), (&r1cs.b_0, F128::ONE)] {
            let mut half = F128::ZERO;
            for r in 0..matrix.num_rows {
                let u = lambda[r & mask] * e_tensor[r >> r1cs.k_skip];
                let mut row = F128::ZERO;
                for (c, kappa) in matrix.row(r) {
                    let c = c as usize;
                    row += kappa * fresh.z_partial[c & mask] * q_tensor[c >> r1cs.k_skip];
                }
                half += row * u;
            }
            total += half * weight;
        }
        total
    }

    #[test]
    fn factored_eq_lookup_and_matrix_evaluators_match_dense_reference() {
        let mut rng = Rng(0xFAC7_0E0D);
        for dimensions in 0..=12 {
            let point = (0..dimensions).map(|_| rng.f128()).collect::<Vec<_>>();
            let dense = build_eq_table(&point);
            let factored = FactoredEqTable::new(&point);
            for (index, expected) in dense.into_iter().enumerate() {
                assert_eq!(factored.value(index), expected);
            }
        }

        for k_log in 6..=10 {
            let r1cs = random_instance(&mut rng, k_log, 3);
            let claim = MatrixAccClaim {
                point: (0..2 * k_log + 1).map(|_| rng.f128()).collect(),
                value: F128::ZERO,
            };
            assert_eq!(
                stacked_matrix_mle_eval(&r1cs, &claim),
                stacked_matrix_mle_eval_dense_reference(&r1cs, &claim),
                "factored accumulated claim at k_log={k_log}"
            );

            let fresh = random_fresh(&mut rng, &r1cs);
            assert_eq!(
                fresh_claim_value(&r1cs, &fresh),
                fresh_claim_value_dense_reference(&r1cs, &fresh),
                "factored fresh claim at k_log={k_log}"
            );
        }
    }

    /// Honest fold roundtrip: chained accumulators stay TRUE against the
    /// matrix (decider check), with and without the genesis gate.
    #[test]
    fn fold_roundtrip_chained() {
        let mut rng = Rng(0xACC0);
        let r1cs = random_instance(&mut rng, 8, 3);

        // Genesis: gate = 0, incoming ignored (junk lanes).
        let fresh0 = random_fresh(&mut rng, &r1cs);
        let junk = MatrixAccClaim {
            point: (0..17).map(|_| rng.f128()).collect(),
            value: rng.f128(),
        };
        let mut ch_p = FsLaneChallenger::new(b"fold-test");
        let (proof0, acc0) = prove_matrix_claim_fold(&r1cs, &fresh0, &junk, false, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(b"fold-test");
        let acc0_v = verify_matrix_claim_fold(8, 6, &fresh0, &junk, F128::ZERO, &proof0, &mut ch_v)
            .expect("genesis fold verifies");
        assert_eq!(acc0, acc0_v);
        assert_eq!(
            stacked_matrix_mle_eval(&r1cs, &acc0),
            acc0.value,
            "genesis accumulator claim is true"
        );

        // Link 1: fold a fresh claim with acc0.
        let fresh1 = random_fresh(&mut rng, &r1cs);
        let (proof1, acc1) = prove_matrix_claim_fold(&r1cs, &fresh1, &acc0, true, &mut ch_p);
        let acc1_v = verify_matrix_claim_fold(8, 6, &fresh1, &acc0, F128::ONE, &proof1, &mut ch_v)
            .expect("link fold verifies");
        assert_eq!(acc1, acc1_v);
        assert_eq!(
            stacked_matrix_mle_eval(&r1cs, &acc1),
            acc1.value,
            "chained accumulator claim is true"
        );
        assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "lockstep");
    }

    /// A false fresh claim or a false incoming claim cannot yield a
    /// verifier-accepted TRUE accumulator: the compressed rounds thread
    /// the (false) target through the verifier's `c_1` reconstruction, so
    /// the run is rejected — or, if some mutation slips it through, the
    /// accumulated claim is false against the matrix and the decider's
    /// evaluation catches it. A gated-off (genesis) incoming claim is
    /// excused by construction.
    #[test]
    fn false_claims_rejected_or_poison_the_accumulator() {
        let mut rng = Rng(0xACC1);
        let r1cs = random_instance(&mut rng, 8, 3);

        let caught = |r1cs: &FieldR1cs,
                      fresh: &FreshLincheckClaim,
                      acc_in: &MatrixAccClaim,
                      gate: bool,
                      proof: &MatrixFoldProof| {
            let mut ch = FsLaneChallenger::new(b"fold-false-v");
            let gate_f = if gate { F128::ONE } else { F128::ZERO };
            match verify_matrix_claim_fold(8, 6, fresh, acc_in, gate_f, proof, &mut ch) {
                Err(_) => true,
                Ok(acc) => stacked_matrix_mle_eval(r1cs, &acc) != acc.value,
            }
        };

        // False fresh value.
        let mut fresh = random_fresh(&mut rng, &r1cs);
        fresh.value += F128::ONE;
        let acc_in = random_true_acc(&mut rng, &r1cs);
        let mut ch = FsLaneChallenger::new(b"fold-false-v");
        let (proof, _) = prove_matrix_claim_fold(&r1cs, &fresh, &acc_in, true, &mut ch);
        assert!(
            caught(&r1cs, &fresh, &acc_in, true, &proof),
            "false fresh claim accepted with a true accumulator"
        );

        // False incoming value under an honest fresh claim.
        let fresh = random_fresh(&mut rng, &r1cs);
        let mut acc_bad = random_true_acc(&mut rng, &r1cs);
        acc_bad.value += F128::ONE;
        let mut ch = FsLaneChallenger::new(b"fold-false-v");
        let (proof, _) = prove_matrix_claim_fold(&r1cs, &fresh, &acc_bad, true, &mut ch);
        assert!(
            caught(&r1cs, &fresh, &acc_bad, true, &proof),
            "false incoming claim accepted with a true accumulator"
        );

        // The same false incoming with gate = 0 is EXCUSED (genesis): the
        // verifier accepts and the accumulator is TRUE.
        let mut ch_p = FsLaneChallenger::new(b"fold-false-g");
        let (proof, acc) = prove_matrix_claim_fold(&r1cs, &fresh, &acc_bad, false, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(b"fold-false-g");
        let acc_v = verify_matrix_claim_fold(8, 6, &fresh, &acc_bad, F128::ZERO, &proof, &mut ch_v)
            .expect("gated-off incoming verifies");
        assert_eq!(acc, acc_v);
        assert_eq!(
            stacked_matrix_mle_eval(&r1cs, &acc),
            acc.value,
            "gated-off incoming must not affect the accumulator"
        );
    }

    /// Proof-wire mutations: every mutated wire is rejected outright or
    /// lands on a false accumulator.
    #[test]
    fn fold_wire_mutations() {
        let mut rng = Rng(0xACC2);
        let r1cs = random_instance(&mut rng, 7, 3);
        let fresh = random_fresh(&mut rng, &r1cs);
        let acc_in = random_true_acc(&mut rng, &r1cs);
        let mut ch = FsLaneChallenger::new(b"fold-mut");
        let (proof, _) = prove_matrix_claim_fold(&r1cs, &fresh, &acc_in, true, &mut ch);

        let check = |bad: &MatrixFoldProof| {
            let mut ch = FsLaneChallenger::new(b"fold-mut");
            match verify_matrix_claim_fold(7, 6, &fresh, &acc_in, F128::ONE, bad, &mut ch) {
                Err(_) => true,
                Ok(acc) => stacked_matrix_mle_eval(&r1cs, &acc) != acc.value,
            }
        };

        for i in 0..proof.phase1_rounds.len() {
            for j in 0..2 {
                let mut bad = proof.clone();
                bad.phase1_rounds[i][j] += F128::ONE;
                assert!(check(&bad), "phase1 round {i}/{j} survived");
            }
        }
        for i in 0..proof.phase2_rounds.len() {
            for j in 0..2 {
                let mut bad = proof.clone();
                bad.phase2_rounds[i][j] += F128::ONE;
                assert!(check(&bad), "phase2 round {i}/{j} survived");
            }
        }
        for field in 0..3 {
            let mut bad = proof.clone();
            match field {
                0 => bad.g_v += F128::ONE,
                1 => bad.g_e += F128::ONE,
                _ => bad.final_matrix_eval += F128::ONE,
            }
            assert!(check(&bad), "terminal wire {field} survived");
        }
    }
}
