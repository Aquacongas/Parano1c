//! Column relations for the deep-chain layer walk: the sumchecks that tie
//! the walk's endpoint columns to committed data.
//!
//! The walk (`super`) binds layers 1..=66 to each other but says nothing
//! about WHERE its layer-0 inputs come from or where its layer-66 outputs
//! go. Three relation shapes close the loop, all instances of ONE generic
//! sumcheck over products of column MLEs:
//!
//! - SELECTION (before the walk): `0 = Σ_w eq(ρ,x)·[O(w) + mask(w)·S_out(w)]`
//!   — exposed outputs and carry columns are lane selections of the output
//!   columns. Terminal claims: committed columns (discharged through the
//!   batched PCS opening via public-IO) and output-column claims that seed
//!   the walk as a start group.
//! - SUBSTITUTION (after the walk): the walk's terminal claim
//!   `Σ_e α_e·S_in,e~(σ)` is re-expressed through the chain wiring —
//!   `S_in = MDS_FULL·raw` with `raw` a selector-gated combination of
//!   shifted carry columns and absorb columns. Terminal claims: committed
//!   columns and SHIFTED committed columns.
//! - BOOLEANITY: `0 = Σ_w eq(ρ,w)·(b(w)² + b(w))` for witness selector
//!   columns.
//!
//! A SHIFTED-column claim `Σ_w eq(σ,w)·col(w−1) = v` is not a plain MLE
//! evaluation; [`prove_shift_discharge`] reduces it to one with a degree-2
//! sumcheck against the successor kernel `N(σ,w) = eq(σ, w+1)`, whose
//! closed form ([`shift_kernel_eval`]) both verifiers evaluate in O(n).
//!
//! Round polynomials use the compressed wire form (`[c_0, c_2..c_d]`, the
//! linear coefficient reconstructed from the running claim).

use crate::challenger::Challenger;
use crate::field::F128;
use crate::lincheck::build_eq_table;
use rayon::prelude::*;

/// Maximum column factors per term (degree 3 with the eq prefix).
pub const MAX_TERM_FACTORS: usize = 2;

/// Relation sumcheck degree: eq · (≤ two column factors).
pub const RELATION_DEGREE: usize = 1 + MAX_TERM_FACTORS;

/// A reference to one column of the relation instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ColRef {
    /// A committed column (region/carry/selector) — its terminal claim
    /// discharges through the batched PCS opening.
    Committed(usize),
    /// A committed column read at the PREDECESSOR slot (`col(w−1)`, zero at
    /// slot 0) — its terminal claim needs [`prove_shift_discharge`].
    CommittedShift(usize),
    /// An internal (uncommitted) column — its terminal claim must feed a
    /// walk claim group or another relation's target.
    Internal(usize),
}

/// One product term: `coeff · Π factors` (0..=2 factors; empty = constant).
#[derive(Clone, Debug)]
pub struct RelationTerm {
    pub coeff: F128,
    pub factors: Vec<ColRef>,
}

/// Proof wires of one relation sumcheck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnRelationProof {
    /// Per round: `[c_0, c_2, c_3]`.
    pub rounds: Vec<[F128; RELATION_DEGREE]>,
    /// MLE evaluation at the derived point per DISTINCT ColRef, in
    /// first-occurrence order over the term list.
    pub final_values: Vec<F128>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationError {
    Shape,
    FinalMismatch,
}

impl std::fmt::Display for RelationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationError::Shape => write!(f, "relation proof shape mismatch"),
            RelationError::FinalMismatch => write!(f, "relation final claim mismatch"),
        }
    }
}

/// Distinct ColRefs in first-occurrence order — the layout of
/// `final_values` and of the returned claims.
pub fn distinct_refs(terms: &[RelationTerm]) -> Vec<ColRef> {
    let mut out = Vec::new();
    for t in terms {
        assert!(
            t.factors.len() <= MAX_TERM_FACTORS,
            "term arity above degree budget"
        );
        for f in &t.factors {
            if !out.contains(f) {
                out.push(*f);
            }
        }
    }
    out
}

/// The columns backing a relation instance, prover side.
pub struct RelationColumns<'a> {
    pub committed: &'a [&'a [F128]],
    pub internal: &'a [&'a [F128]],
}

impl RelationColumns<'_> {
    fn resolve(&self, r: ColRef, w: usize) -> Vec<F128> {
        match r {
            ColRef::Committed(i) => self.committed[i].to_vec(),
            ColRef::Internal(i) => self.internal[i].to_vec(),
            ColRef::CommittedShift(i) => {
                let col = self.committed[i];
                let mut shifted = vec![F128::ZERO; w];
                shifted[1..].copy_from_slice(&col[..w - 1]);
                shifted
            }
        }
    }
}

fn absorb_relation_header<Ch: Challenger>(
    challenger: &mut Ch,
    target: F128,
    eq_point: &[F128],
    terms: &[RelationTerm],
) {
    challenger.observe_label(b"history-deep-chain-relation-v0");
    challenger.observe_f128(target);
    challenger.observe_f128_slice(eq_point);
    // Bind the relation structure: counts plus each term's coefficient and
    // factor encoding (kind, index).
    let lane = |a: u64, b: u64| F128 { lo: a, hi: b };
    let mut lanes = vec![lane(terms.len() as u64, 0)];
    for t in terms {
        lanes.push(t.coeff);
        lanes.push(lane(t.factors.len() as u64, 0));
        for f in &t.factors {
            let (kind, idx) = match f {
                ColRef::Committed(i) => (0u64, *i as u64),
                ColRef::CommittedShift(i) => (1, *i as u64),
                ColRef::Internal(i) => (2, *i as u64),
            };
            lanes.push(lane(kind, idx));
        }
    }
    challenger.observe_f128_slice(&lanes);
}

#[inline]
fn f128_of_usize(t: usize) -> F128 {
    F128 {
        lo: t as u64,
        hi: 0,
    }
}

fn reconstruct_deg3(wire: &[F128; RELATION_DEGREE], claim: F128) -> [F128; RELATION_DEGREE + 1] {
    // c_1 = claim + Σ_{i≥2} c_i (char 2).
    let mut c1 = claim;
    for &c in &wire[1..] {
        c1 += c;
    }
    [wire[0], c1, wire[1], wire[2]]
}

#[inline]
fn horner4(coeffs: &[F128; RELATION_DEGREE + 1], x: F128) -> F128 {
    ((coeffs[3] * x + coeffs[2]) * x + coeffs[1]) * x + coeffs[0]
}

/// Interpolate a degree-3 polynomial from evaluations at 0..=3 into
/// monomial coefficients (char-2 exact).
fn interpolate_deg3(evals: &[F128; RELATION_DEGREE + 1]) -> [F128; RELATION_DEGREE + 1] {
    // Nodes 0,1,2,3 in the flat basis. Precompute basis once.
    static BASIS: std::sync::OnceLock<[[F128; 4]; 4]> = std::sync::OnceLock::new();
    let basis = BASIS.get_or_init(|| {
        let nodes: [F128; 4] = std::array::from_fn(|i| f128_of_usize(i));
        std::array::from_fn(|i| {
            let mut poly = [F128::ZERO; 4];
            poly[0] = F128::ONE;
            let mut deg = 0usize;
            let mut denom = F128::ONE;
            for (j, &t_j) in nodes.iter().enumerate() {
                if j == i {
                    continue;
                }
                denom = denom * (nodes[i] + t_j);
                let mut next = [F128::ZERO; 4];
                for d in 0..=deg {
                    next[d + 1] += poly[d];
                    next[d] += poly[d] * t_j;
                }
                deg += 1;
                poly = next;
            }
            let inv = super::f128_inv_pub(denom);
            std::array::from_fn(|d| poly[d] * inv)
        })
    });
    let mut coeffs = [F128::ZERO; 4];
    for (i, &e) in evals.iter().enumerate() {
        for d in 0..4 {
            coeffs[d] += e * basis[i][d];
        }
    }
    coeffs
}

/// Prove `target = Σ_w eq(eq_point, w) · Σ_terms coeff · Π factors(w)`.
///
/// Returns the proof and the derived point with per-distinct-ref values —
/// the caller turns Committed refs into PCS opening claims, CommittedShift
/// refs into [`prove_shift_discharge`] runs, and Internal refs into walk
/// claim groups or downstream targets.
pub fn prove_column_relation<Ch: Challenger>(
    target: F128,
    eq_point: &[F128],
    terms: &[RelationTerm],
    columns: &RelationColumns<'_>,
    challenger: &mut Ch,
) -> (ColumnRelationProof, Vec<F128>, Vec<F128>) {
    let w_log = eq_point.len();
    let w = 1usize << w_log;
    let refs = distinct_refs(terms);

    absorb_relation_header(challenger, target, eq_point, terms);

    // Materialize one working table per distinct ref plus the eq table.
    let mut tables: Vec<Vec<F128>> = refs.iter().map(|&r| columns.resolve(r, w)).collect();
    for t in &tables {
        assert_eq!(t.len(), w, "column length mismatch");
    }
    let mut eq = build_eq_table(eq_point);

    // Term factor indices into `refs`.
    let term_refs: Vec<(F128, Vec<usize>)> = terms
        .iter()
        .map(|t| {
            (
                t.coeff,
                t.factors
                    .iter()
                    .map(|f| refs.iter().position(|r| r == f).expect("distinct ref"))
                    .collect(),
            )
        })
        .collect();

    let mut claim = target;
    let mut rounds = Vec::with_capacity(w_log);
    let mut point = Vec::with_capacity(w_log);
    for _round in 0..w_log {
        let half = eq.len() / 2;
        let evals = (0..half)
            .into_par_iter()
            .fold(
                || [F128::ZERO; RELATION_DEGREE + 1],
                |mut acc, p| {
                    let eq_base = eq[2 * p];
                    let eq_delta = eq[2 * p] + eq[2 * p + 1];
                    let bases: Vec<(F128, F128)> = tables
                        .iter()
                        .map(|t| (t[2 * p], t[2 * p] + t[2 * p + 1]))
                        .collect();
                    for (t, slot) in acc.iter_mut().enumerate() {
                        let t_f = f128_of_usize(t);
                        let eq_t = eq_base + t_f * eq_delta;
                        let mut sum = F128::ZERO;
                        for (coeff, fidx) in &term_refs {
                            let mut prod = *coeff;
                            for &fi in fidx {
                                let (b, d) = bases[fi];
                                prod = prod * (b + t_f * d);
                            }
                            sum += prod;
                        }
                        *slot += eq_t * sum;
                    }
                    acc
                },
            )
            .reduce(
                || [F128::ZERO; RELATION_DEGREE + 1],
                |mut a, b| {
                    for (x, y) in a.iter_mut().zip(b.iter()) {
                        *x += *y;
                    }
                    a
                },
            );
        let full = interpolate_deg3(&evals);
        debug_assert_eq!(full[0] + horner4(&full, F128::ONE), claim);
        let wire = [full[0], full[2], full[3]];
        challenger.observe_f128_slice(&wire);
        let r = challenger.sample_f128();
        claim = horner4(&full, r);
        point.push(r);
        rounds.push(wire);
        fold_table(&mut eq, r);
        for t in tables.iter_mut() {
            fold_table(t, r);
        }
    }

    let final_values: Vec<F128> = tables.iter().map(|t| t[0]).collect();
    challenger.observe_f128_slice(&final_values);
    debug_assert_eq!(
        {
            let mut sum = F128::ZERO;
            for (coeff, fidx) in &term_refs {
                let mut prod = *coeff;
                for &fi in fidx {
                    prod = prod * final_values[fi];
                }
                sum += prod;
            }
            eq[0] * sum
        },
        claim,
        "relation prover-side final mismatch"
    );

    (
        ColumnRelationProof {
            rounds,
            final_values: final_values.clone(),
        },
        point,
        final_values,
    )
}

/// Verify a relation sumcheck; returns the derived point (the per-ref
/// values live in `proof.final_values`, ordered by [`distinct_refs`]).
pub fn verify_column_relation<Ch: Challenger>(
    w_log: usize,
    target: F128,
    eq_point: &[F128],
    terms: &[RelationTerm],
    proof: &ColumnRelationProof,
    challenger: &mut Ch,
) -> Result<Vec<F128>, RelationError> {
    let refs = distinct_refs(terms);
    if eq_point.len() != w_log
        || proof.rounds.len() != w_log
        || proof.final_values.len() != refs.len()
    {
        return Err(RelationError::Shape);
    }

    absorb_relation_header(challenger, target, eq_point, terms);

    let mut claim = target;
    let mut point = Vec::with_capacity(w_log);
    for wire in &proof.rounds {
        challenger.observe_f128_slice(wire);
        let full = reconstruct_deg3(wire, claim);
        let r = challenger.sample_f128();
        claim = horner4(&full, r);
        point.push(r);
    }
    challenger.observe_f128_slice(&proof.final_values);

    let mut sum = F128::ZERO;
    for t in terms {
        let mut prod = t.coeff;
        for f in &t.factors {
            let fi = refs.iter().position(|r| r == f).expect("distinct ref");
            prod = prod * proof.final_values[fi];
        }
        sum += prod;
    }
    let eq = super::eq_eval_pub(eq_point, &point);
    if eq * sum != claim {
        return Err(RelationError::FinalMismatch);
    }
    Ok(point)
}

fn fold_table(table: &mut Vec<F128>, r: F128) {
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
// Shift discharge
// ---------------------------------------------------------------------------

/// Closed form of the successor kernel
/// `N(ρ, σ) = Σ_w eq(ρ, w+1)·eq(σ, w)` (sum over non-overflowing w):
/// grouping by the carry length k of `w → w+1`,
///
/// ```text
///   N = Σ_{k<n} [Π_{i<k} σ_i(1+ρ_i)] · ρ_k(1+σ_k) · [Π_{i>k} (ρ_iσ_i + (1+ρ_i)(1+σ_i))]
/// ```
pub fn shift_kernel_eval(rho: &[F128], sigma: &[F128]) -> F128 {
    assert_eq!(rho.len(), sigma.len());
    let n = rho.len();
    // Suffix products of the matched factors.
    let mut suffix = vec![F128::ONE; n + 1];
    for i in (0..n).rev() {
        let matched = rho[i] * sigma[i] + (F128::ONE + rho[i]) * (F128::ONE + sigma[i]);
        suffix[i] = matched * suffix[i + 1];
    }
    let mut acc = F128::ZERO;
    let mut prefix = F128::ONE;
    for k in 0..n {
        acc += prefix * rho[k] * (F128::ONE + sigma[k]) * suffix[k + 1];
        prefix = prefix * sigma[k] * (F128::ONE + rho[k]);
    }
    acc
}

/// Proof wires of one shift discharge (degree-2 rounds `[c_0, c_2]` plus
/// the terminal plain MLE value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShiftDischargeProof {
    pub rounds: Vec<[F128; 2]>,
    pub final_value: F128,
}

/// Prove `target = Σ_w N(σ, w)·col(w)` — i.e. discharge a shifted-column
/// claim at σ into the plain claim `col~(derived point) = final_value`.
pub fn prove_shift_discharge<Ch: Challenger>(
    col: &[F128],
    sigma: &[F128],
    target: F128,
    challenger: &mut Ch,
) -> (ShiftDischargeProof, Vec<F128>) {
    let w = col.len();
    assert!(w.is_power_of_two());
    let w_log = w.trailing_zeros() as usize;
    assert_eq!(sigma.len(), w_log);

    challenger.observe_label(b"history-deep-chain-shift-v0");
    challenger.observe_f128(target);
    challenger.observe_f128_slice(sigma);

    // N table: N[w] = eq(σ, w+1), 0 at the top slot.
    let eq_sigma = build_eq_table(sigma);
    let mut n_table = vec![F128::ZERO; w];
    if w > 1 {
        n_table[..w - 1].copy_from_slice(&eq_sigma[1..]);
    }
    let mut col_table = col.to_vec();

    let mut claim = target;
    let mut rounds = Vec::with_capacity(w_log);
    let mut point = Vec::with_capacity(w_log);
    for _round in 0..w_log {
        let half = n_table.len() / 2;
        let evals = (0..half)
            .into_par_iter()
            .fold(
                || [F128::ZERO; 3],
                |mut acc, p| {
                    let nb = n_table[2 * p];
                    let nd = n_table[2 * p] + n_table[2 * p + 1];
                    let cb = col_table[2 * p];
                    let cd = col_table[2 * p] + col_table[2 * p + 1];
                    for (t, slot) in acc.iter_mut().enumerate() {
                        let t_f = f128_of_usize(t);
                        *slot += (nb + t_f * nd) * (cb + t_f * cd);
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
            );
        let full = interpolate_deg2(&evals);
        // p(0) + p(1) = c_1 + c_2 must equal the running claim (char 2).
        debug_assert_eq!(full[1] + full[2], claim);
        let wire = [full[0], full[2]];
        challenger.observe_f128_slice(&wire);
        let r = challenger.sample_f128();
        claim = (full[2] * r + full[1]) * r + full[0];
        point.push(r);
        rounds.push(wire);
        fold_table(&mut n_table, r);
        fold_table(&mut col_table, r);
    }

    let final_value = col_table[0];
    challenger.observe_f128(final_value);
    debug_assert_eq!(n_table[0] * final_value, claim);

    (
        ShiftDischargeProof {
            rounds,
            final_value,
        },
        point,
    )
}

/// Verify a shift discharge; returns the derived point (pair it with
/// `proof.final_value` as the plain committed-column claim).
pub fn verify_shift_discharge<Ch: Challenger>(
    w_log: usize,
    sigma: &[F128],
    target: F128,
    proof: &ShiftDischargeProof,
    challenger: &mut Ch,
) -> Result<Vec<F128>, RelationError> {
    if sigma.len() != w_log || proof.rounds.len() != w_log {
        return Err(RelationError::Shape);
    }
    challenger.observe_label(b"history-deep-chain-shift-v0");
    challenger.observe_f128(target);
    challenger.observe_f128_slice(sigma);

    let mut claim = target;
    let mut point = Vec::with_capacity(w_log);
    for wire in &proof.rounds {
        challenger.observe_f128_slice(wire);
        // c_1 = claim + c_2 (char 2, degree 2).
        let c1 = claim + wire[1];
        let r = challenger.sample_f128();
        claim = (wire[1] * r + c1) * r + wire[0];
        point.push(r);
    }
    challenger.observe_f128(proof.final_value);

    if shift_kernel_eval(sigma, &point) * proof.final_value != claim {
        return Err(RelationError::FinalMismatch);
    }
    Ok(point)
}

fn interpolate_deg2(evals: &[F128; 3]) -> [F128; 3] {
    // Nodes 0, 1, 2 (flat basis). c_0 = p(0). Solve the 2×2 system for
    // c_1, c_2 (char-2 exact): p(1) = c_0 + c_1 + c_2;
    // p(2) = c_0 + 2·c_1 + 4·c_2 with 2 = x, 4 = x² in the flat basis.
    static INV: std::sync::OnceLock<(F128, F128, F128)> = std::sync::OnceLock::new();
    let (two, four, inv_det) = *INV.get_or_init(|| {
        let two = f128_of_usize(2);
        let four = two * two;
        // det = 2·(4 + ... solve directly: from
        //   s1 = c_1 + c_2, s2 = 2c_1 + 4c_2:
        //   c_2 = (s2 + 2·s1) / (4 + 2), c_1 = s1 + c_2.
        let det = four + two;
        (two, four, super::f128_inv_pub(det))
    });
    let _ = four;
    let c0 = evals[0];
    let s1 = evals[1] + c0;
    let s2 = evals[2] + c0;
    let c2 = (s2 + two * s1) * inv_det;
    let c1 = s1 + c2;
    [c0, c1, c2]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::{Challenger, FsLaneChallenger};

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
        fn bit(&mut self) -> F128 {
            if self.next_u64() & 1 == 1 {
                F128::ONE
            } else {
                F128::ZERO
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

    fn random_col(rng: &mut Rng, w: usize) -> Vec<F128> {
        (0..w).map(|_| rng.f128()).collect()
    }

    #[test]
    fn shift_kernel_matches_direct_sum() {
        let mut rng = Rng(0x511F7);
        for n in [1usize, 2, 4, 6] {
            let rho: Vec<F128> = (0..n).map(|_| rng.f128()).collect();
            let sigma: Vec<F128> = (0..n).map(|_| rng.f128()).collect();
            let eq_rho = build_eq_table(&rho);
            let eq_sigma = build_eq_table(&sigma);
            let mut direct = F128::ZERO;
            for w in 0..(1usize << n) - 1 {
                direct += eq_rho[w + 1] * eq_sigma[w];
            }
            assert_eq!(shift_kernel_eval(&rho, &sigma), direct, "n={n}");
        }
    }

    #[test]
    fn shift_discharge_roundtrip_and_mutations() {
        let mut rng = Rng(0xD15C);
        let w_log = 5;
        let w = 1usize << w_log;
        let col = random_col(&mut rng, w);
        let sigma: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
        // target = Σ_w eq(σ,w)·col(w−1)
        let eq = build_eq_table(&sigma);
        let mut target = F128::ZERO;
        for i in 1..w {
            target += eq[i] * col[i - 1];
        }

        let mut ch_p = FsLaneChallenger::new(b"shift-test");
        let (proof, point_p) = prove_shift_discharge(&col, &sigma, target, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(b"shift-test");
        let point_v = verify_shift_discharge(w_log, &sigma, target, &proof, &mut ch_v)
            .expect("honest shift discharge");
        assert_eq!(point_p, point_v);
        assert_eq!(mle_eval(&col, &point_v), proof.final_value);
        assert_eq!(ch_p.sample_f128(), ch_v.sample_f128());

        // Forged target rejected (kernel-vs-final check catches whp).
        let mut ch = FsLaneChallenger::new(b"shift-test");
        let bad = verify_shift_discharge(w_log, &sigma, target + F128::ONE, &proof, &mut ch);
        assert!(bad.is_err());

        // Any wire mutation rejected or lands on a false plain claim.
        for round in 0..w_log {
            for c in 0..2 {
                let mut bad = proof.clone();
                bad.rounds[round][c] += F128::ONE;
                let mut ch = FsLaneChallenger::new(b"shift-test");
                match verify_shift_discharge(w_log, &sigma, target, &bad, &mut ch) {
                    Err(_) => {}
                    Ok(pt) => assert_ne!(
                        mle_eval(&col, &pt),
                        bad.final_value,
                        "mutation {round}/{c} survived"
                    ),
                }
            }
        }
    }

    /// A wiring-shaped relation: two committed columns, one shifted carry,
    /// one witness selector, one internal column — the full generality the
    /// capsule wiring needs.
    #[test]
    fn column_relation_roundtrip_and_claims() {
        let mut rng = Rng(0xC01A);
        let w_log = 4;
        let w = 1usize << w_log;
        let carry = random_col(&mut rng, w);
        let absorb = random_col(&mut rng, w);
        let sel: Vec<F128> = (0..w).map(|_| rng.bit()).collect();
        let internal = random_col(&mut rng, w);
        let committed: Vec<&[F128]> = vec![&carry, &absorb, &sel];
        let internal_cols: Vec<&[F128]> = vec![&internal];
        let columns = RelationColumns {
            committed: &committed,
            internal: &internal_cols,
        };

        // relation(w) = 3·sel(w)·carry(w−1) + 5·(absorb(w)) + 7·internal(w)
        let terms = vec![
            RelationTerm {
                coeff: f128_of_usize(3),
                factors: vec![ColRef::Committed(2), ColRef::CommittedShift(0)],
            },
            RelationTerm {
                coeff: f128_of_usize(5),
                factors: vec![ColRef::Committed(1)],
            },
            RelationTerm {
                coeff: f128_of_usize(7),
                factors: vec![ColRef::Internal(0)],
            },
        ];
        let eq_point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
        let eq = build_eq_table(&eq_point);
        let mut target = F128::ZERO;
        for i in 0..w {
            let shifted = if i == 0 { F128::ZERO } else { carry[i - 1] };
            let val = f128_of_usize(3) * sel[i] * shifted
                + f128_of_usize(5) * absorb[i]
                + f128_of_usize(7) * internal[i];
            target += eq[i] * val;
        }

        let mut ch_p = FsLaneChallenger::new(b"relation-test");
        let (proof, point_p, values_p) =
            prove_column_relation(target, &eq_point, &terms, &columns, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(b"relation-test");
        let point_v = verify_column_relation(w_log, target, &eq_point, &terms, &proof, &mut ch_v)
            .expect("honest relation");
        assert_eq!(point_p, point_v);
        assert_eq!(values_p, proof.final_values);
        assert_eq!(ch_p.sample_f128(), ch_v.sample_f128());

        // Every terminal value is TRUE against its column.
        let refs = distinct_refs(&terms);
        for (r, v) in refs.iter().zip(proof.final_values.iter()) {
            let expected = match r {
                ColRef::Committed(2) => mle_eval(&sel, &point_v),
                ColRef::Committed(1) => mle_eval(&absorb, &point_v),
                ColRef::Internal(0) => mle_eval(&internal, &point_v),
                ColRef::CommittedShift(0) => {
                    let mut shifted = vec![F128::ZERO; w];
                    shifted[1..].copy_from_slice(&carry[..w - 1]);
                    mle_eval(&shifted, &point_v)
                }
                _ => unreachable!(),
            };
            assert_eq!(*v, expected, "terminal claim for {r:?}");
        }

        // Forged target and wire mutations rejected.
        let mut ch = FsLaneChallenger::new(b"relation-test");
        assert!(verify_column_relation(
            w_log,
            target + F128::ONE,
            &eq_point,
            &terms,
            &proof,
            &mut ch
        )
        .is_err());

        let mut survivors = Vec::new();
        for round in 0..w_log {
            for c in 0..RELATION_DEGREE {
                let mut bad = proof.clone();
                bad.rounds[round][c] += F128::ONE;
                let mut ch = FsLaneChallenger::new(b"relation-test");
                match verify_column_relation(w_log, target, &eq_point, &terms, &bad, &mut ch) {
                    Err(_) => {}
                    Ok(pt) => {
                        // A surviving run must have shifted the derived point
                        // (fresh challenges) — its terminal claims must then
                        // be false against at least one true column.
                        let refs = distinct_refs(&terms);
                        let all_true =
                            refs.iter()
                                .zip(bad.final_values.iter())
                                .all(|(r, v)| match r {
                                    ColRef::Committed(1) => mle_eval(&absorb, &pt) == *v,
                                    ColRef::Committed(2) => mle_eval(&sel, &pt) == *v,
                                    ColRef::Internal(0) => mle_eval(&internal, &pt) == *v,
                                    ColRef::CommittedShift(0) => {
                                        let mut shifted = vec![F128::ZERO; w];
                                        shifted[1..].copy_from_slice(&carry[..w - 1]);
                                        mle_eval(&shifted, &pt) == *v
                                    }
                                    _ => unreachable!(),
                                });
                        if all_true {
                            survivors.push((round, c));
                        }
                    }
                }
            }
        }
        assert!(survivors.is_empty(), "relation mutation survivors: {survivors:?}");
    }

    /// Booleanity as a relation: `0 = Σ eq·(b² + b)` accepts boolean
    /// columns and rejects a non-boolean lane.
    #[test]
    fn booleanity_relation() {
        let mut rng = Rng(0xB001);
        let w_log = 4;
        let w = 1usize << w_log;
        let good: Vec<F128> = (0..w).map(|_| rng.bit()).collect();
        let terms = vec![
            RelationTerm {
                coeff: F128::ONE,
                factors: vec![ColRef::Committed(0), ColRef::Committed(0)],
            },
            RelationTerm {
                coeff: F128::ONE,
                factors: vec![ColRef::Committed(0)],
            },
        ];
        let eq_point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();

        let committed: Vec<&[F128]> = vec![&good];
        let columns = RelationColumns {
            committed: &committed,
            internal: &[],
        };
        let mut ch_p = FsLaneChallenger::new(b"bool-test");
        let (proof, _, _) =
            prove_column_relation(F128::ZERO, &eq_point, &terms, &columns, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(b"bool-test");
        let pt = verify_column_relation(w_log, F128::ZERO, &eq_point, &terms, &proof, &mut ch_v)
            .expect("boolean column accepted");
        assert_eq!(proof.final_values[0], mle_eval(&good, &pt));

        // Non-boolean column: the honest prover's target over it is nonzero
        // whp, so proving "= 0" yields a rejected or false-claim run.
        let mut bad_col = good.clone();
        bad_col[3] = rng.f128();
        let committed: Vec<&[F128]> = vec![&bad_col];
        let columns = RelationColumns {
            committed: &committed,
            internal: &[],
        };
        let mut ch_p = FsLaneChallenger::new(b"bool-test");
        let (proof, _, _) =
            prove_column_relation(F128::ZERO, &eq_point, &terms, &columns, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(b"bool-test");
        match verify_column_relation(w_log, F128::ZERO, &eq_point, &terms, &proof, &mut ch_v) {
            Err(_) => {}
            Ok(pt) => {
                assert_ne!(
                    proof.final_values[0],
                    mle_eval(&bad_col, &pt),
                    "non-boolean column produced a consistent zero-check"
                );
            }
        }
    }
}
