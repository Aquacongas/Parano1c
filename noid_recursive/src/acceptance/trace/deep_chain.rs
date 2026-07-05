//! Trace twins of the deep-chain engine verifiers — the [G] slot bodies.
//!
//! Line-by-line transliterations of `noid_ivc_core::deep_chain`:
//! [`verify_deep_chain_walk_trace`] replays the 66-layer walk verifier,
//! [`verify_column_relation_trace`] the generic column-relation sumcheck,
//! [`verify_shift_discharge_trace`] the successor-kernel reduction. Same
//! absorb/squeeze order on the [`FsChannelTrace`], same checks; every
//! proof field is witness, every relation structure and round schedule is
//! a protocol constant baked at build time.
//!
//! Cost drivers (per the module they mirror): the walk absorbs
//! `w_log`×8-lane compressed round polynomials per layer (~5 permutations
//! each) — near-flat in transaction count; the relation and shift twins
//! are O(w_log) rounds each. All MDS/round-constant algebra folds into
//! affine expressions (zero rows); the only multiplications are Horner
//! walks, S-boxes on claimed values, per-group eq evaluations, and claim
//! batching.

use noid_ivc_core::deep_chain::relations::{
    claimed_refs, ColRef, ColumnRelationProof, FixedPattern, RelationTerm, ShiftDischargeProof,
    WeightedSumProof, MAX_TERM_FACTORS, RELATION_DEGREE,
};
use noid_ivc_core::deep_chain::schedule::flat_of_tower_u128;
use noid_ivc_core::deep_chain::{
    flat_mds, flat_round_constant, is_full_round, DeepChainWalkProof, WALK_DEGREE,
};
use noid_ivc_core::field_circuit::FsChannelTrace;
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

use super::{mul, pin_eq, FieldR1csBuilder, LinExpr, F128};

// ---------------------------------------------------------------------------
// Proof wires
// ---------------------------------------------------------------------------

/// A claim group as expressions.
pub struct LaneClaimGroupTrace {
    pub point: Vec<LinExpr>,
    pub values: [LinExpr; STATE_SIZE],
}

/// Witness allocation of a [`DeepChainWalkProof`].
pub struct DeepChainWalkProofTrace {
    pub layers: Vec<WalkLayerProofTrace>,
}

pub struct WalkLayerProofTrace {
    pub round_coeffs: Vec<[LinExpr; WALK_DEGREE]>,
    pub next_values: [LinExpr; STATE_SIZE],
}

impl DeepChainWalkProofTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &DeepChainWalkProof, w_log: usize) -> Self {
        assert_eq!(native.layers.len(), N_ROUNDS, "walk proof layer count");
        let layers = native
            .layers
            .iter()
            .map(|l| {
                assert_eq!(l.round_coeffs.len(), w_log, "walk proof round count");
                WalkLayerProofTrace {
                    round_coeffs: l
                        .round_coeffs
                        .iter()
                        .map(|wire| std::array::from_fn(|i| alloc_expr(b, wire[i])))
                        .collect(),
                    next_values: std::array::from_fn(|i| alloc_expr(b, l.next_values[i])),
                }
            })
            .collect();
        Self { layers }
    }
}

fn alloc_expr(b: &mut FieldR1csBuilder, v: F128) -> LinExpr {
    LinExpr::from_wire(b.alloc_f128(v))
}

/// x^7 on an expression: 4 multiplication rows.
pub fn sbox7_trace(b: &mut FieldR1csBuilder, x: &LinExpr) -> LinExpr {
    let x2 = mul(b, x, x);
    let x4 = mul(b, &x2, &x2);
    let x3 = mul(b, x, &x2);
    mul(b, &x3, &x4)
}

// ---------------------------------------------------------------------------
// Shared sumcheck pieces
// ---------------------------------------------------------------------------

/// Reconstruct + Horner for a compressed wire `[c_0, c_2..c_d]`: the linear
/// coefficient is `claim + Σ_{i≥2} c_i` (free XOR algebra), then evaluate
/// at `r` with d multiplications.
fn compressed_horner(
    b: &mut FieldR1csBuilder,
    wire: &[LinExpr],
    claim: &LinExpr,
    r: &LinExpr,
) -> LinExpr {
    let mut c1 = claim.clone();
    for c in &wire[1..] {
        c1 = c1.add(c);
    }
    // coeffs = [wire[0], c1, wire[1], .., wire[d−1]] — Horner top-down.
    let mut acc = wire[wire.len() - 1].clone();
    for c in wire[1..wire.len() - 1].iter().rev() {
        let t = mul(b, &acc, r);
        acc = t.add(c);
    }
    let t = mul(b, &acc, r);
    acc = t.add(&c1);
    let t = mul(b, &acc, r);
    t.add(&wire[0])
}

// ---------------------------------------------------------------------------
// The walk verifier twin
// ---------------------------------------------------------------------------

/// Trace twin of `deep_chain::verify_deep_chain_walk`. Group points and
/// values are expressions the caller ties to its relation twins; returns
/// the terminal layer-0 claim group for the wiring substitution.
pub fn verify_deep_chain_walk_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    w_log: usize,
    out_groups: &[LaneClaimGroupTrace],
    proof: &DeepChainWalkProofTrace,
) -> LaneClaimGroupTrace {
    assert!(!out_groups.is_empty());
    for g in out_groups {
        assert_eq!(g.point.len(), w_log, "walk group point arity");
    }
    assert_eq!(proof.layers.len(), N_ROUNDS);

    ch.observe_label(b, b"history-deep-chain-walk-v0");
    for g in out_groups {
        ch.observe_f128_slice(b, &g.point);
        ch.observe_f128_slice(b, &g.values);
    }

    let mut group_points: Vec<Vec<LinExpr>> =
        out_groups.iter().map(|g| g.point.clone()).collect();
    let mut group_values: Vec<[LinExpr; STATE_SIZE]> =
        out_groups.iter().map(|g| g.values.clone()).collect();

    let mut terminal: Option<LaneClaimGroupTrace> = None;
    for (li, layer_proof) in proof.layers.iter().enumerate() {
        let layer = N_ROUNDS - li;
        let q = layer - 1;
        let alpha = ch.sample_f128(b);

        // Lane weights α^{4g+i+1} — a running product chain of wires.
        let mut weights: Vec<[LinExpr; STATE_SIZE]> =
            Vec::with_capacity(group_points.len());
        let mut power = LinExpr::constant(F128::ONE);
        for _ in 0..group_points.len() {
            let w: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| {
                power = mul(b, &power, &alpha);
                power.clone()
            });
            weights.push(w);
        }

        // Running claim.
        let mut claim = LinExpr::zero();
        for (vals, w_g) in group_values.iter().zip(weights.iter()) {
            for i in 0..STATE_SIZE {
                claim = claim.add(&mul(b, &w_g[i], &vals[i]));
            }
        }

        let mut point = Vec::with_capacity(w_log);
        for wire in &layer_proof.round_coeffs {
            ch.observe_f128_slice(b, wire);
            let r = ch.sample_f128(b);
            claim = compressed_horner(b, wire, &claim, &r);
            point.push(r);
        }
        ch.observe_f128_slice(b, &layer_proof.next_values);

        // term_j on the claimed next values (round constants are free adds).
        let mds = flat_mds(is_full_round(q));
        let terms: [LinExpr; STATE_SIZE] = if is_full_round(q) {
            std::array::from_fn(|j| {
                let x = layer_proof.next_values[j]
                    .add(&LinExpr::constant(flat_round_constant(j, q)));
                sbox7_trace(b, &x)
            })
        } else {
            std::array::from_fn(|j| {
                if j == 0 {
                    let x = layer_proof.next_values[0]
                        .add(&LinExpr::constant(flat_round_constant(0, q)));
                    sbox7_trace(b, &x)
                } else {
                    layer_proof.next_values[j].clone()
                }
            })
        };

        // expected = Σ_g eq(ρ_g, point) · Σ_j c_{g,j}·term_j with
        // c_{g,j} = Σ_i w_{g,i}·MDS[i][j] — MDS entries are constants, so
        // c_{g,j} is affine in the weight wires (zero rows).
        let mut expected = LinExpr::zero();
        for (g_point, w_g) in group_points.iter().zip(weights.iter()) {
            let mut dot = LinExpr::zero();
            for j in 0..STATE_SIZE {
                let mut c_gj = LinExpr::zero();
                for i in 0..STATE_SIZE {
                    c_gj = c_gj.add(&w_g[i].scale(mds[i][j]));
                }
                dot = dot.add(&mul(b, &c_gj, &terms[j]));
            }
            let eq = b.eq_eval_trace(g_point, &point);
            expected = expected.add(&mul(b, &eq, &dot));
        }
        pin_eq(b, &expected, &claim);

        group_points = vec![point.clone()];
        group_values = vec![layer_proof.next_values.clone()];
        terminal = Some(LaneClaimGroupTrace {
            point,
            values: layer_proof.next_values.clone(),
        });
    }
    terminal.expect("N_ROUNDS ≥ 1")
}

// ---------------------------------------------------------------------------
// Column-relation verifier twin
// ---------------------------------------------------------------------------

/// Witness allocation of a [`ColumnRelationProof`].
pub struct ColumnRelationProofTrace {
    pub rounds: Vec<[LinExpr; RELATION_DEGREE]>,
    pub final_values: Vec<LinExpr>,
}

impl ColumnRelationProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &ColumnRelationProof,
        w_log: usize,
        n_refs: usize,
    ) -> Self {
        assert_eq!(native.rounds.len(), w_log, "relation round count");
        assert_eq!(native.final_values.len(), n_refs, "relation value count");
        Self {
            rounds: native
                .rounds
                .iter()
                .map(|wire| std::array::from_fn(|i| alloc_expr(b, wire[i])))
                .collect(),
            final_values: native
                .final_values
                .iter()
                .map(|&v| alloc_expr(b, v))
                .collect(),
        }
    }
}

/// The relation term list as the trace consumes it: structure (factor refs)
/// is a protocol constant; coefficients may be expressions (challenge-
/// derived, e.g. the α-batched MDS weights of a wiring substitution).
pub struct RelationTermTrace {
    pub coeff: LinExpr,
    pub factors: Vec<ColRef>,
}

/// The native header absorbs `(target, eq_point, structure lanes)`; the
/// twin mirrors it with the structure lanes as constants. The structure
/// lanes bind ONLY the term/factor encoding — coefficients are absorbed as
/// expressions so challenge-derived coefficients stay sound.
fn absorb_relation_header_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    target: &LinExpr,
    eq_point: &[LinExpr],
    terms: &[RelationTermTrace],
) {
    ch.observe_label(b, b"history-deep-chain-relation-v0");
    ch.observe_f128(b, target);
    ch.observe_f128_slice(b, eq_point);
    let lane = |a: u64, bb: u64| LinExpr::constant(F128 { lo: a, hi: bb });
    let mut lanes = vec![lane(terms.len() as u64, 0)];
    for t in terms {
        lanes.push(t.coeff.clone());
        lanes.push(lane(t.factors.len() as u64, 0));
        for f in &t.factors {
            match f {
                ColRef::Committed(i) => lanes.push(lane(0, *i as u64)),
                ColRef::CommittedShift(i) => lanes.push(lane(1, *i as u64)),
                ColRef::Internal(i) => lanes.push(lane(2, *i as u64)),
                ColRef::Fixed(i) => lanes.push(lane(3, *i as u64)),
                ColRef::CommittedShift2(i) => lanes.push(lane(4, *i as u64)),
                ColRef::Window {
                    col,
                    stride_log,
                    offset,
                } => {
                    lanes.push(lane(5, *col as u64));
                    lanes.push(lane(*stride_log as u64, *offset as u64));
                }
            }
        }
    }
    ch.observe_f128_slice(b, &lanes);
}

/// Closed-form MLE evaluation of a [`FixedPattern`] at an expression point:
/// build the eq tensor of the low `low_log` coordinates (2^low_log − 1
/// multiplications), then dot it with the constant table (zero rows).
pub fn fixed_pattern_eval_trace(
    b: &mut FieldR1csBuilder,
    pattern: &FixedPattern,
    point: &[LinExpr],
) -> LinExpr {
    assert!(point.len() >= pattern.low_log, "fixed pattern point arity");
    let mut tensor: Vec<LinExpr> = vec![LinExpr::constant(F128::ONE)];
    for p_j in &point[..pattern.low_log] {
        // Mirrors `build_eq_table`: the new variable is the HIGH bit;
        // (1+p)·t = t + p·t, so one multiplication per parent entry.
        let his: Vec<LinExpr> = tensor.iter().map(|t| mul(b, t, p_j)).collect();
        let mut next = Vec::with_capacity(tensor.len() * 2);
        for (t, hi) in tensor.iter().zip(his.iter()) {
            next.push(t.add(hi));
        }
        next.extend(his);
        tensor = next;
    }
    let mut acc = LinExpr::zero();
    for (v, t) in pattern.table.iter().zip(tensor.iter()) {
        if *v != F128::ZERO {
            acc = acc.add(&t.scale(*v));
        }
    }
    acc
}

/// Trace twin of `relations::verify_column_relation`; returns the derived
/// point (final claim values live in `proof.final_values`, ordered by
/// [`claimed_refs`]-equivalent structure order; Fixed factors are
/// evaluated in closed form from the protocol-constant patterns).
pub fn verify_column_relation_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    w_log: usize,
    target: &LinExpr,
    eq_point: &[LinExpr],
    terms: &[RelationTermTrace],
    fixed: &[FixedPattern],
    proof: &ColumnRelationProofTrace,
) -> Vec<LinExpr> {
    assert_eq!(eq_point.len(), w_log);
    assert_eq!(proof.rounds.len(), w_log);
    let native_shape: Vec<RelationTerm> = terms
        .iter()
        .map(|t| {
            assert!(t.factors.len() <= MAX_TERM_FACTORS);
            RelationTerm {
                coeff: F128::ZERO,
                factors: t.factors.clone(),
            }
        })
        .collect();
    let claimed = claimed_refs(&native_shape);
    assert_eq!(proof.final_values.len(), claimed.len());

    absorb_relation_header_trace(b, ch, target, eq_point, terms);

    let mut claim = target.clone();
    let mut point = Vec::with_capacity(w_log);
    for wire in &proof.rounds {
        ch.observe_f128_slice(b, wire);
        let r = ch.sample_f128(b);
        claim = compressed_horner(b, wire, &claim, &r);
        point.push(r);
    }
    ch.observe_f128_slice(b, &proof.final_values);

    // Each distinct Fixed ref is evaluated once per relation.
    let mut fixed_cache: Vec<Option<LinExpr>> = vec![None; fixed.len()];
    let mut sum = LinExpr::zero();
    for t in terms {
        let mut prod = t.coeff.clone();
        for f in &t.factors {
            let value = match f {
                ColRef::Fixed(i) => {
                    if fixed_cache[*i].is_none() {
                        fixed_cache[*i] =
                            Some(fixed_pattern_eval_trace(b, &fixed[*i], &point));
                    }
                    fixed_cache[*i].clone().expect("cached")
                }
                _ => {
                    let fi = claimed
                        .iter()
                        .position(|r| r == f)
                        .expect("claimed ref");
                    proof.final_values[fi].clone()
                }
            };
            prod = mul(b, &prod, &value);
        }
        sum = sum.add(&prod);
    }
    let eq = b.eq_eval_trace(eq_point, &point);
    let expected = mul(b, &eq, &sum);
    pin_eq(b, &expected, &claim);
    point
}

// ---------------------------------------------------------------------------
// Shift-discharge verifier twin
// ---------------------------------------------------------------------------

pub struct ShiftDischargeProofTrace {
    pub rounds: Vec<[LinExpr; 2]>,
    pub final_value: LinExpr,
}

impl ShiftDischargeProofTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &ShiftDischargeProof, w_log: usize) -> Self {
        assert_eq!(native.rounds.len(), w_log, "shift round count");
        Self {
            rounds: native
                .rounds
                .iter()
                .map(|wire| std::array::from_fn(|i| alloc_expr(b, wire[i])))
                .collect(),
            final_value: alloc_expr(b, native.final_value),
        }
    }
}

/// Closed-form successor kernel `N(ρ, σ)` on expressions (see
/// `relations::shift_kernel_eval`): prefix/suffix products over the
/// coordinate pairs — O(n) multiplications.
pub fn shift_kernel_eval_trace(
    b: &mut FieldR1csBuilder,
    rho: &[LinExpr],
    sigma: &[LinExpr],
) -> LinExpr {
    assert_eq!(rho.len(), sigma.len());
    let n = rho.len();
    let one = LinExpr::constant(F128::ONE);
    let mut suffix = vec![LinExpr::constant(F128::ONE); n + 1];
    for i in (0..n).rev() {
        let m1 = mul(b, &rho[i], &sigma[i]);
        let m2 = mul(b, &one.add(&rho[i]), &one.add(&sigma[i]));
        let matched = m1.add(&m2);
        suffix[i] = mul(b, &matched, &suffix[i + 1]);
    }
    let mut acc = LinExpr::zero();
    let mut prefix = LinExpr::constant(F128::ONE);
    for k in 0..n {
        let t1 = mul(b, &prefix, &rho[k]);
        let t2 = mul(b, &t1, &one.add(&sigma[k]));
        acc = acc.add(&mul(b, &t2, &suffix[k + 1]));
        let p1 = mul(b, &prefix, &sigma[k]);
        prefix = mul(b, &p1, &one.add(&rho[k]));
    }
    acc
}

/// `2^shift_log`-step kernel on expressions (see
/// `relations::shift_pow2_kernel_eval`): matched low coordinates times the
/// successor kernel on the rest.
pub fn shift_pow2_kernel_eval_trace(
    b: &mut FieldR1csBuilder,
    shift_log: usize,
    rho: &[LinExpr],
    sigma: &[LinExpr],
) -> LinExpr {
    assert_eq!(rho.len(), sigma.len());
    assert!(shift_log < rho.len());
    let one = LinExpr::constant(F128::ONE);
    let mut acc = LinExpr::constant(F128::ONE);
    for i in 0..shift_log {
        let m1 = mul(b, &rho[i], &sigma[i]);
        let m2 = mul(b, &one.add(&rho[i]), &one.add(&sigma[i]));
        let matched = m1.add(&m2);
        acc = mul(b, &acc, &matched);
    }
    let high = shift_kernel_eval_trace(b, &rho[shift_log..], &sigma[shift_log..]);
    mul(b, &acc, &high)
}

/// Trace twin of `relations::verify_shift_discharge` (and its
/// `2^shift_log` variant); returns the derived point (pair it with
/// `proof.final_value` as the plain column claim).
pub fn verify_shift_discharge_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    w_log: usize,
    sigma: &[LinExpr],
    target: &LinExpr,
    shift_log: usize,
    proof: &ShiftDischargeProofTrace,
) -> Vec<LinExpr> {
    assert_eq!(sigma.len(), w_log);
    assert_eq!(proof.rounds.len(), w_log);
    assert!(shift_log < w_log);

    ch.observe_label(b, b"history-deep-chain-shift-v0");
    ch.observe_f128(
        b,
        &LinExpr::constant(F128 {
            lo: shift_log as u64,
            hi: 0,
        }),
    );
    ch.observe_f128(b, target);
    ch.observe_f128_slice(b, sigma);

    let mut claim = target.clone();
    let mut point = Vec::with_capacity(w_log);
    for wire in &proof.rounds {
        ch.observe_f128_slice(b, wire);
        // Degree 2: c_1 = claim + c_2; p(r) = (c_2·r + c_1)·r + c_0.
        let c1 = claim.add(&wire[1]);
        let r = ch.sample_f128(b);
        let t = mul(b, &wire[1], &r);
        let t = mul(b, &t.add(&c1), &r);
        claim = t.add(&wire[0]);
        point.push(r);
    }
    ch.observe_f128(b, &proof.final_value);

    let kernel = shift_pow2_kernel_eval_trace(b, shift_log, sigma, &point);
    let expected = mul(b, &kernel, &proof.final_value);
    pin_eq(b, &expected, &claim);
    point
}

// ---------------------------------------------------------------------------
// Weighted-sum discharge verifier twin + source-binding encode kernel
// ---------------------------------------------------------------------------

pub struct WeightedSumProofTrace {
    pub rounds: Vec<[LinExpr; 2]>,
    pub final_value: LinExpr,
}

impl WeightedSumProofTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &WeightedSumProof, w_log: usize) -> Self {
        assert_eq!(native.rounds.len(), w_log, "weighted-sum round count");
        Self {
            rounds: native
                .rounds
                .iter()
                .map(|wire| std::array::from_fn(|i| alloc_expr(b, wire[i])))
                .collect(),
            final_value: alloc_expr(b, native.final_value),
        }
    }
}

/// Trace twin of `relations::verify_weighted_sum`: the degree-2 sumcheck
/// `Σ_i weights[i]·col[i] = target` reduced to a plain `col~(point)` claim.
/// `weight_eval` builds `weights~(point)` as an expression from the derived
/// point (the closed-form kernel — only known after the rounds are drawn),
/// mirroring the native callback. Returns the derived point.
pub fn verify_weighted_sum_trace<W>(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    w_log: usize,
    target: &LinExpr,
    proof: &WeightedSumProofTrace,
    weight_eval: W,
) -> Vec<LinExpr>
where
    W: FnOnce(&mut FieldR1csBuilder, &[LinExpr]) -> LinExpr,
{
    assert_eq!(proof.rounds.len(), w_log);
    ch.observe_label(b, b"history-deep-chain-weighted-v0");
    ch.observe_f128(b, target);

    let mut claim = target.clone();
    let mut point = Vec::with_capacity(w_log);
    for wire in &proof.rounds {
        ch.observe_f128_slice(b, wire);
        // Degree 2: c_1 = claim + c_2; p(r) = (c_2·r + c_1)·r + c_0.
        let c1 = claim.add(&wire[1]);
        let r = ch.sample_f128(b);
        let t = mul(b, &wire[1], &r);
        let t = mul(b, &t.add(&c1), &r);
        claim = t.add(&wire[0]);
        point.push(r);
    }
    ch.observe_f128(b, &proof.final_value);

    let weight = weight_eval(b, &point);
    let expected = mul(b, &weight, &proof.final_value);
    pin_eq(b, &expected, &claim);
    point
}

/// Trace twin of `encode_kernel::source_weight_at`: the MLE of the
/// source-binding weight sequence `W_i = K_i(z)·eq(right,i)` at an expression
/// point `x`. Flat-basis twiddles `tower_to_flat(2^{c+l})` are constants, so
/// the only multiplications are the per-bit tensor folds — `O(n_rounds)`.
pub fn source_weight_at_trace(
    b: &mut FieldR1csBuilder,
    z: &[LinExpr],
    right: &[LinExpr],
    x: &[LinExpr],
    n_rounds: usize,
) -> LinExpr {
    assert_eq!(z.len(), n_rounds + 2, "encode kernel point arity");
    assert_eq!(right.len(), n_rounds, "right arity");
    assert_eq!(x.len(), n_rounds, "message point arity");
    let z_pos = &z[..n_rounds];
    let z_hi = &z[n_rounds..];
    let one = LinExpr::constant(F128::ONE);
    let mut total = LinExpr::zero();
    for c in 0..4usize {
        // eq₂(z_hi; c).
        let mut eq2 = one.clone();
        for (k, zk) in z_hi.iter().enumerate() {
            let factor = if (c >> k) & 1 == 1 {
                zk.clone()
            } else {
                one.add(zk)
            };
            eq2 = mul(b, &eq2, &factor);
        }
        // Π_l [ h_l(0)(1+x_l) + h_l(1)·x_l ], h_l(bit) = f_l(bit)·g_l(bit).
        let mut prod = one.clone();
        for l in 0..n_rounds {
            let two = LinExpr::constant(flat_of_tower_u128(1u128 << (c + l)));
            // f0 = 1 + z_l·(1+two); f1 = 1 + z_l·two (mul-by-const folds).
            let f0 = one.add(&mul(b, &z_pos[l], &one.add(&two)));
            let f1 = one.add(&mul(b, &z_pos[l], &two));
            let g0 = one.add(&right[l]);
            let g1 = right[l].clone();
            let h0 = mul(b, &f0, &g0);
            let h1 = mul(b, &f1, &g1);
            let lo = mul(b, &h0, &one.add(&x[l]));
            let hi = mul(b, &h1, &x[l]);
            let term = lo.add(&hi);
            prod = mul(b, &prod, &term);
        }
        total = total.add(&mul(b, &eq2, &prod));
    }
    total
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
    use noid_ivc_core::deep_chain::relations::{
        prove_column_relation, prove_shift_discharge, RelationColumns,
    };
    use noid_ivc_core::deep_chain::{
        apply_round, prove_deep_chain_walk, LaneClaimGroup,
    };
    use noid_ivc_core::lincheck::build_eq_table;

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

    /// Walk twin: lockstep with the native verifier, satisfiable trace,
    /// proof-wire auto-mutator with 0 survivors, measured row count.
    #[test]
    fn walk_twin_lockstep_and_mutations() {
        let w_log = 3;
        let w = 1usize << w_log;
        let mut rng = Rng(0x7A1C);
        let s0: [Vec<F128>; STATE_SIZE] =
            std::array::from_fn(|_| (0..w).map(|_| rng.f128()).collect());
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
        let point: Vec<F128> = (0..w_log).map(|_| rng.f128()).collect();
        let values: [F128; STATE_SIZE] = std::array::from_fn(|j| mle_eval(&out[j], &point));
        let groups = [LaneClaimGroup {
            point: point.clone(),
            values,
        }];

        let mut ch_native = FsLaneChallenger::new(b"walk-twin-test");
        let (proof, native_terminal) = prove_deep_chain_walk(&s0, &groups, &mut ch_native);

        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"walk-twin-test");
        let groups_e = [LaneClaimGroupTrace {
            point: point.iter().map(|&v| alloc_expr(&mut b, v)).collect(),
            values: std::array::from_fn(|j| alloc_expr(&mut b, values[j])),
        }];
        let mutation_start = b.num_wires();
        let proof_e = DeepChainWalkProofTrace::alloc(&mut b, &proof, w_log);
        let mutation_end = b.num_wires();
        let terminal = verify_deep_chain_walk_trace(&mut b, &mut ch, w_log, &groups_e, &proof_e);
        let rows = b.num_wires();

        // Lockstep + terminal agreement.
        let c_n = ch_native.sample_f128();
        let c_t = ch.sample_f128(&mut b);
        assert_eq!(c_t.eval(b.values()), c_n, "walk twin transcript diverged");
        for j in 0..STATE_SIZE {
            assert_eq!(
                terminal.values[j].eval(b.values()),
                native_terminal.values[j],
                "terminal value lane {j}"
            );
        }
        eprintln!("[deep-chain] walk twin rows @w_log={w_log}: {rows}");

        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest walk twin unsatisfiable");

        use rayon::prelude::*;
        let survivors: Vec<usize> = (mutation_start..mutation_end)
            .into_par_iter()
            .filter(|&t| {
                let mut bad = z.clone();
                bad[t] += F128::ONE;
                r1cs.satisfies(&bad)
            })
            .collect();
        assert!(survivors.is_empty(), "walk twin survivors: {survivors:?}");
    }

    /// Fixed-pattern factors in the twin: a periodic selector gating a
    /// 3-factor term, lockstep with the native verifier, mutations
    /// rejected. Exercises the closed-form tensor evaluation.
    #[test]
    fn fixed_pattern_twin_lockstep_and_mutations() {
        use noid_ivc_core::deep_chain::relations::FixedPattern;
        let w_log = 4;
        let low_log = 2;
        let w = 1usize << w_log;
        let mut rng = Rng(0xF17ED2);
        let sel: Vec<F128> = (0..w)
            .map(|_| {
                if rng.f128().lo & 1 == 1 {
                    F128::ONE
                } else {
                    F128::ZERO
                }
            })
            .collect();
        let a: Vec<F128> = (0..w).map(|_| rng.f128()).collect();
        let mut table = vec![F128::ZERO; 1 << low_log];
        table[1] = F128::ONE;
        table[2] = F128 { lo: 9, hi: 0 };
        let fixed = vec![FixedPattern::new(low_log, table.clone())];
        let terms = vec![
            noid_ivc_core::deep_chain::relations::RelationTerm {
                coeff: F128::ONE,
                factors: vec![ColRef::Fixed(0), ColRef::Committed(0), ColRef::Committed(1)],
            },
            noid_ivc_core::deep_chain::relations::RelationTerm {
                coeff: F128::ONE,
                factors: vec![ColRef::Committed(1)],
            },
        ];
        let mut rng2 = Rng(0xEE2);
        let eq_point: Vec<F128> = (0..w_log).map(|_| rng2.f128()).collect();
        let eq = build_eq_table(&eq_point);
        let mut target = F128::ZERO;
        for i in 0..w {
            let pat = table[i & ((1 << low_log) - 1)];
            target += eq[i] * (pat * sel[i] * a[i] + a[i]);
        }

        let committed: Vec<&[F128]> = vec![&sel, &a];
        let columns = RelationColumns {
            committed: &committed,
            internal: &[],
            fixed: &fixed,
        };
        let mut ch_native = FsLaneChallenger::new(b"fixed-twin-test");
        let (proof, native_point, _) =
            prove_column_relation(target, &eq_point, &terms, &columns, &mut ch_native);

        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"fixed-twin-test");
        let target_e = alloc_expr(&mut b, target);
        let eq_point_e: Vec<LinExpr> = eq_point.iter().map(|&v| alloc_expr(&mut b, v)).collect();
        let terms_e: Vec<RelationTermTrace> = terms
            .iter()
            .map(|t| RelationTermTrace {
                coeff: LinExpr::constant(t.coeff),
                factors: t.factors.clone(),
            })
            .collect();
        let mutation_start = b.num_wires();
        let proof_e = ColumnRelationProofTrace::alloc(&mut b, &proof, w_log, 2);
        let mutation_end = b.num_wires();
        let point_e = verify_column_relation_trace(
            &mut b, &mut ch, w_log, &target_e, &eq_point_e, &terms_e, &fixed, &proof_e,
        );

        let c_n = ch_native.sample_f128();
        let c_t = ch.sample_f128(&mut b);
        assert_eq!(c_t.eval(b.values()), c_n, "fixed twin transcript diverged");
        for (e, n) in point_e.iter().zip(native_point.iter()) {
            assert_eq!(e.eval(b.values()), *n);
        }

        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest fixed twin unsatisfiable");

        use rayon::prelude::*;
        let survivors: Vec<usize> = (mutation_start..mutation_end)
            .into_par_iter()
            .filter(|&t| {
                let mut bad = z.clone();
                bad[t] += F128::ONE;
                r1cs.satisfies(&bad)
            })
            .collect();
        assert!(survivors.is_empty(), "fixed twin survivors: {survivors:?}");
    }

    /// Relation + shift twins: lockstep on a wiring-shaped relation and its
    /// shift discharge, satisfiable, wire mutations rejected.
    #[test]
    fn relation_and_shift_twins_lockstep_and_mutations() {
        let w_log = 3;
        let w = 1usize << w_log;
        let mut rng = Rng(0x511AD);
        let carry: Vec<F128> = (0..w).map(|_| rng.f128()).collect();
        let absorb: Vec<F128> = (0..w).map(|_| rng.f128()).collect();
        let committed: Vec<&[F128]> = vec![&carry, &absorb];
        let columns = RelationColumns {
            committed: &committed,
            internal: &[],
            fixed: &[],
        };
        let coeff3 = F128 { lo: 3, hi: 0 };
        let coeff5 = F128 { lo: 5, hi: 0 };
        let terms = vec![
            noid_ivc_core::deep_chain::relations::RelationTerm {
                coeff: coeff3,
                factors: vec![ColRef::CommittedShift(0)],
            },
            noid_ivc_core::deep_chain::relations::RelationTerm {
                coeff: coeff5,
                factors: vec![ColRef::Committed(1)],
            },
        ];
        let mut rng2 = Rng(0xEEE);
        let eq_point: Vec<F128> = (0..w_log).map(|_| rng2.f128()).collect();
        let eq = build_eq_table(&eq_point);
        let mut target = F128::ZERO;
        for i in 0..w {
            let sh = if i == 0 { F128::ZERO } else { carry[i - 1] };
            target += eq[i] * (coeff3 * sh + coeff5 * absorb[i]);
        }

        let mut ch_native = FsLaneChallenger::new(b"relation-twin-test");
        let (proof, native_point, _) =
            prove_column_relation(target, &eq_point, &terms, &columns, &mut ch_native);
        // Follow with the shift discharge natively.
        let shift_value = proof.final_values[0];
        let (shift_proof, native_shift_point) =
            prove_shift_discharge(&carry, &native_point, shift_value, &mut ch_native);

        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"relation-twin-test");
        let target_e = alloc_expr(&mut b, target);
        let eq_point_e: Vec<LinExpr> = eq_point.iter().map(|&v| alloc_expr(&mut b, v)).collect();
        let terms_e = vec![
            RelationTermTrace {
                coeff: LinExpr::constant(coeff3),
                factors: vec![ColRef::CommittedShift(0)],
            },
            RelationTermTrace {
                coeff: LinExpr::constant(coeff5),
                factors: vec![ColRef::Committed(1)],
            },
        ];
        let mutation_start = b.num_wires();
        let proof_e = ColumnRelationProofTrace::alloc(&mut b, &proof, w_log, 2);
        let shift_e = ShiftDischargeProofTrace::alloc(&mut b, &shift_proof, w_log);
        let mutation_end = b.num_wires();

        let point_e = verify_column_relation_trace(
            &mut b, &mut ch, w_log, &target_e, &eq_point_e, &terms_e, &[], &proof_e,
        );
        let shift_point_e = verify_shift_discharge_trace(
            &mut b,
            &mut ch,
            w_log,
            &point_e,
            &proof_e.final_values[0],
            0,
            &shift_e,
        );

        let c_n = ch_native.sample_f128();
        let c_t = ch.sample_f128(&mut b);
        assert_eq!(c_t.eval(b.values()), c_n, "relation twin transcript diverged");
        for (e, n) in point_e.iter().zip(native_point.iter()) {
            assert_eq!(e.eval(b.values()), *n);
        }
        for (e, n) in shift_point_e.iter().zip(native_shift_point.iter()) {
            assert_eq!(e.eval(b.values()), *n);
        }

        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest relation twin unsatisfiable");

        use rayon::prelude::*;
        let survivors: Vec<usize> = (mutation_start..mutation_end)
            .into_par_iter()
            .filter(|&t| {
                let mut bad = z.clone();
                bad[t] += F128::ONE;
                r1cs.satisfies(&bad)
            })
            .collect();
        assert!(survivors.is_empty(), "relation twin survivors: {survivors:?}");
    }

    /// The source-binding discharge twin: the in-trace weighted-sum verifier
    /// with the encode-kernel weight (`K_i(z)·eq(right,i)`) matches the native
    /// reduction lane-for-lane — same transcript, same derived point, honest
    /// R1CS satisfiable, and the terminal claim is the true `H` opening.
    #[test]
    fn weighted_sum_source_binding_twin() {
        use noid_ivc_core::deep_chain::encode_kernel::source_weight_at;
        use noid_ivc_core::deep_chain::relations::prove_weighted_sum;

        let n_rounds = 5usize;
        let w = 1usize << n_rounds;
        let mut rng = Rng(0x50FA11);
        let h: Vec<F128> = (0..w).map(|_| rng.f128()).collect();
        let right: Vec<F128> = (0..n_rounds).map(|_| rng.f128()).collect();
        let z: Vec<F128> = (0..n_rounds + 2).map(|_| rng.f128()).collect();
        let weights: Vec<F128> = (0..w)
            .map(|i| {
                let x: Vec<F128> = (0..n_rounds)
                    .map(|l| {
                        if (i >> l) & 1 == 1 {
                            F128::ONE
                        } else {
                            F128::ZERO
                        }
                    })
                    .collect();
                source_weight_at(&z, &right, &x, n_rounds)
            })
            .collect();
        let mut target = F128::ZERO;
        for i in 0..w {
            target += weights[i] * h[i];
        }

        let mut ch_native = FsLaneChallenger::new(b"wsum-twin");
        let (proof, native_point) = prove_weighted_sum(&h, &weights, target, &mut ch_native);

        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"wsum-twin");
        let target_e = alloc_expr(&mut b, target);
        let z_e: Vec<LinExpr> = z.iter().map(|&v| alloc_expr(&mut b, v)).collect();
        let right_e: Vec<LinExpr> = right.iter().map(|&v| alloc_expr(&mut b, v)).collect();
        let mutation_start = b.num_wires();
        let proof_e = WeightedSumProofTrace::alloc(&mut b, &proof, n_rounds);
        let mutation_end = b.num_wires();

        let point_e = verify_weighted_sum_trace(
            &mut b,
            &mut ch,
            n_rounds,
            &target_e,
            &proof_e,
            |b, pt| source_weight_at_trace(b, &z_e, &right_e, pt, n_rounds),
        );

        let c_n = ch_native.sample_f128();
        let c_t = ch.sample_f128(&mut b);
        assert_eq!(c_t.eval(b.values()), c_n, "wsum twin transcript diverged");
        for (e, n) in point_e.iter().zip(native_point.iter()) {
            assert_eq!(e.eval(b.values()), *n, "wsum twin point diverged");
        }
        // The terminal claim is the true H opening at the derived point.
        assert_eq!(mle_eval(&h, &native_point), proof.final_value);

        let (r1cs, zz) = b.build();
        assert!(r1cs.satisfies(&zz), "honest wsum twin unsatisfiable");

        // Every allocated proof wire is constrained (0 surviving mutants).
        use rayon::prelude::*;
        let survivors: Vec<usize> = (mutation_start..mutation_end)
            .into_par_iter()
            .filter(|&t| {
                let mut bad = zz.clone();
                bad[t] += F128::ONE;
                r1cs.satisfies(&bad)
            })
            .collect();
        assert!(survivors.is_empty(), "wsum twin survivors: {survivors:?}");
    }
}
