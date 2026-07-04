// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The self-verification slot: the `noid_ivc_core` FieldR1cs verifier
//! (`verifier::verify_field`) replayed as an arithmetic F128 trace, so a
//! proof can verify its predecessor in-circuit.
//!
//! Everything in this module lives in the **flat (GCM) basis** end to end:
//! the verified proof's field elements are `noid_ivc_core::F128` values
//! (flat by definition), the transcript twin is [`FsChannelTrace`] (whose
//! native challenger keeps its state in the flat basis), and the PCS Merkle
//! primitives are the flat-basis constructions of `noid_ivc_core::merkle`.
//! Unlike the killshot traces, NO value in this module is φ-mapped from the
//! tower basis — wires carry the native bit patterns directly.
//!
//! ## Digest convention
//!
//! A 32-byte Merkle digest travels as two **flat lanes** ([`FlatDigestExpr`]):
//! `lanes[0] = LE(bytes[0..16])`, `lanes[1] = LE(bytes[16..32])`, each read
//! as an F128 flat value. This is bit-compatible with both consumers:
//! the flat Merkle sponge XORs exactly these lanes into its state, and the
//! lane challenger's `observe_bytes` packs bytes into exactly these lanes.
//! (The killshot-side `fri_pcs::DigestExpr` instead carries φ(tower-lane)
//! images — do not mix the two conventions.)

use noid_ivc_core::field::PHI_8_TABLE;
use noid_ivc_core::field_circuit::{f128_from_u128, FsChannelTrace};
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::merkle::{self, Hash};
use noid_ivc_core::ntt::AdditiveNttF128;
use noid_ivc_core::pcs::{self, compute_fri_arities, default_fri_queries, PcsParams, LOG_PACKING};
use noid_ivc_core::zerocheck::{self, K_SKIP};
use noid_poseidon2b::native::{capacity_iv_flat, DomainTag};

use super::{mul, pin_eq, poseidon2b_permute, FieldR1csBuilder, LinExpr, F128};

/// A 32-byte digest as two little-endian **flat** u128 lanes (see module
/// docs — this is NOT the φ-mapped `fri_pcs::DigestExpr` convention).
pub type FlatDigestExpr = [LinExpr; 2];

/// The `IVCPCSL_` / `IVCPCSN_` tags of `noid_ivc_core::merkle`, duplicated
/// here because the merkle module keeps them private; pinned against native
/// by the lockstep tests below.
const MERKLE_LEAF_TAG: DomainTag = DomainTag::new(b"IVCPCSL_");
const MERKLE_NODE_TAG: DomainTag = DomainTag::new(b"IVCPCSN_");

/// Split a native digest into its two flat lane values.
pub fn flat_digest_lanes(d: &Hash) -> [F128; 2] {
    [
        f128_from_u128(u128::from_le_bytes(d[..16].try_into().unwrap())),
        f128_from_u128(u128::from_le_bytes(d[16..].try_into().unwrap())),
    ]
}

/// Allocate a witness digest (two flat lanes).
pub fn alloc_flat_digest(b: &mut FieldR1csBuilder, d: &Hash) -> FlatDigestExpr {
    let [lo, hi] = flat_digest_lanes(d);
    [
        LinExpr::from_wire(b.alloc_f128(lo)),
        LinExpr::from_wire(b.alloc_f128(hi)),
    ]
}

/// Build-time constant digest (two flat lanes).
pub fn const_flat_digest(d: &Hash) -> FlatDigestExpr {
    let [lo, hi] = flat_digest_lanes(d);
    [LinExpr::constant(lo), LinExpr::constant(hi)]
}

/// Pin two digests equal (both lanes).
pub fn pin_flat_digest_eq(b: &mut FieldR1csBuilder, x: &FlatDigestExpr, y: &FlatDigestExpr) {
    pin_eq(b, &x[0], &y[0]);
    pin_eq(b, &x[1], &y[1]);
}

/// Concrete flat value carried by an expression at build time.
fn expr_flat_u128(b: &FieldR1csBuilder, e: &LinExpr) -> u128 {
    let v = e.eval(b.values());
    (v.lo as u128) | ((v.hi as u128) << 64)
}

fn digest_bytes_of_lanes(lo: u128, hi: u128) -> Hash {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&lo.to_le_bytes());
    out[16..].copy_from_slice(&hi.to_le_bytes());
    out
}

/// Capacity-IV lanes of a tag as flat F128 constants.
fn tag_iv_flat_f128(tag: DomainTag) -> [F128; 2] {
    let [hi, lo] = capacity_iv_flat(tag);
    [f128_from_u128(hi), f128_from_u128(lo)]
}

// ---------------------------------------------------------------------------
// Merkle primitives (trace twins of noid_ivc_core::merkle)
// ---------------------------------------------------------------------------

/// Trace twin of `noid_ivc_core::merkle::hash_pair` — ONE feed-forward
/// permutation over `[l0, l1, r0 ⊕ IV_hi, r1 ⊕ IV_lo]`, output
/// `(state[0] ⊕ l0, state[1] ⊕ l1)`. All-constant inputs fold to the native
/// digest (value-identical; these hashes never touch the FS channel).
pub fn merkle_hash_pair_trace(
    b: &mut FieldR1csBuilder,
    l: &FlatDigestExpr,
    r: &FlatDigestExpr,
) -> FlatDigestExpr {
    if l.iter().chain(r.iter()).all(|e| e.is_const()) {
        let lb = digest_bytes_of_lanes(expr_flat_u128(b, &l[0]), expr_flat_u128(b, &l[1]));
        let rb = digest_bytes_of_lanes(expr_flat_u128(b, &r[0]), expr_flat_u128(b, &r[1]));
        return const_flat_digest(&merkle::hash_pair(&lb, &rb));
    }
    let [iv_hi, iv_lo] = tag_iv_flat_f128(MERKLE_NODE_TAG);
    let state = [
        l[0].clone(),
        l[1].clone(),
        r[0].add_const(iv_hi),
        r[1].add_const(iv_lo),
    ];
    let out = poseidon2b_permute(b, state);
    [out[0].add(&l[0]), out[1].add(&l[1])]
}

/// Sponge pad lanes in the flat basis (raw `0x80…01` bit patterns — the
/// flat sponge XORs these into a flat state directly, with no φ map).
fn pad_full_block_lanes() -> [F128; 2] {
    // fill_padding over a whole 32-byte block: byte 0 = 0x80, byte 31 = 0x01.
    [
        f128_from_u128(0x80u128),
        f128_from_u128(0x01u128 << 120),
    ]
}

fn pad_half_block_lane() -> F128 {
    // fill_padding over the trailing 16 bytes: byte 16 = 0x80, byte 31 = 0x01
    // — both land in the second lane.
    f128_from_u128(0x80u128 | (0x01u128 << 120))
}

/// Trace twin of `noid_ivc_core::merkle::hash_leaf` for a lane-aligned leaf
/// (`data = lanes × 16 bytes` — every PCS leaf payload is a slice of
/// F_{2^128} values). Mirrors the native length dispatch: an even lane
/// count (block-aligned bytes) runs the fixed-length no-pad mode
/// (`IVCPCSF_`, length-bound IV, one permutation per block); an odd count
/// runs the padded `IVCPCSL_` duplex. All-constant inputs fold.
pub fn merkle_hash_leaf_lanes_trace(
    b: &mut FieldR1csBuilder,
    lanes: &[LinExpr],
) -> FlatDigestExpr {
    if lanes.iter().all(|e| e.is_const()) {
        let mut bytes = Vec::with_capacity(lanes.len() * 16);
        for e in lanes {
            bytes.extend_from_slice(&expr_flat_u128(b, e).to_le_bytes());
        }
        return const_flat_digest(&merkle::hash_leaf(&bytes));
    }

    let fixed = !lanes.is_empty() && lanes.len() % 2 == 0;
    let [iv_hi, iv_lo] = if fixed {
        let [hi, lo] = merkle::leaf_fixed_iv_flat(lanes.len() * 16);
        [f128_from_u128(hi), f128_from_u128(lo)]
    } else {
        tag_iv_flat_f128(MERKLE_LEAF_TAG)
    };
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        LinExpr::constant(iv_hi),
        LinExpr::constant(iv_lo),
    ];
    let absorb_block = |b: &mut FieldR1csBuilder,
                            state: &mut [LinExpr; 4],
                            lane0: &LinExpr,
                            lane1: &LinExpr| {
        state[0] = state[0].add(lane0);
        state[1] = state[1].add(lane1);
        *state = poseidon2b_permute(b, std::mem::take(state));
    };
    let mut chunks = lanes.chunks_exact(2);
    for pair in &mut chunks {
        absorb_block(b, &mut state, &pair[0].clone(), &pair[1].clone());
    }
    match chunks.remainder() {
        [last] => {
            // Buffered odd lane: pad occupies the second lane of the block.
            let pad = LinExpr::constant(pad_half_block_lane());
            absorb_block(b, &mut state, &last.clone(), &pad);
        }
        _ if !fixed => {
            // Padded mode, whole number of blocks: a full pad block follows.
            let [p0, p1] = pad_full_block_lanes();
            absorb_block(
                b,
                &mut state,
                &LinExpr::constant(p0),
                &LinExpr::constant(p1),
            );
        }
        _ => {
            // Fixed no-pad mode: squeeze the block-aligned state directly.
        }
    }
    [state[0].clone(), state[1].clone()]
}

/// Absorb a witness digest into the FS channel exactly as the native
/// `challenger.observe_bytes(&digest)` does: `FS_OP_BYTES` header for 32
/// bytes, then the two flat lanes. The lane packing of `observe_bytes`
/// (LE 16-byte chunks read as flat u128s) is bit-identical to
/// [`FlatDigestExpr`]'s lane convention — pinned by test.
pub fn observe_flat_digest(
    b: &mut FieldR1csBuilder,
    ch: &mut noid_ivc_core::field_circuit::FsChannelTrace,
    d: &FlatDigestExpr,
) {
    ch.observe_lanes(b, 32, &[d[0].clone(), d[1].clone()]);
}

// ---------------------------------------------------------------------------
// Statement binding
// ---------------------------------------------------------------------------

/// Trace twin of `noid_ivc_core::proof::bind_statement_field`. The instance
/// (matrices, dimensions) and the PCS parameters are protocol constants per
/// shape class (fixed-shape invariant), so their digests enter as constant
/// byte observes; the commitment root is proof data (witness lanes).
pub fn bind_statement_field_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    r1cs: &FieldR1cs,
    pcs_params: &PcsParams,
    root: &FlatDigestExpr,
) {
    ch.observe_label(b, b"history-field-r1cs");
    ch.observe_bytes_const(b, &r1cs.statement_digest());
    ch.observe_bytes_const(
        b,
        &noid_ivc_core::proof::pcs_params_statement_bytes(pcs_params),
    );
    observe_flat_digest(b, ch, root);
}

// ---------------------------------------------------------------------------
// Lagrange interpolation over φ_8 node windows
// ---------------------------------------------------------------------------

/// Lagrange weights at expression point `z` over the constant node window
/// `PHI_8_TABLE[node_start .. node_start + node_count]`, returned for nodes
/// `keep_from ..` (window-relative).
///
/// Shared trace twin of `lagrange_weights_naive` (`start 0, keep 0`),
/// `lagrange_weights_lambda_naive` (`start 2^k, keep 0`) and the combined
/// S ∪ Λ weights inside `interpolate_at_z_combined` (`start 0, count 2^{k+1},
/// keep 2^k`). Numerators use shared prefix/suffix products of the affine
/// factors `z + s_j` (association of products — value-identical to native's
/// sequential Π); denominators are all-constant and fold natively.
/// Cost: ~3·node_count multiplications.
fn lagrange_weights_window_trace(
    b: &mut FieldR1csBuilder,
    z: &LinExpr,
    node_start: usize,
    node_count: usize,
    keep_from: usize,
) -> Vec<LinExpr> {
    assert!(node_start + node_count <= PHI_8_TABLE.len());
    assert!(keep_from < node_count);
    let nodes = &PHI_8_TABLE[node_start..node_start + node_count];

    // Affine factors f_j = z + s_j (0 constraints).
    let factors: Vec<LinExpr> = nodes.iter().map(|&s| z.add_const(s)).collect();

    // prefix[i] = Π_{j<i} f_j, suffix[i] = Π_{j>=i} f_j.
    let mut prefix = vec![LinExpr::constant(F128::ONE)];
    for f in &factors[..node_count - 1] {
        let last = prefix.last().unwrap().clone();
        prefix.push(mul(b, &last, f));
    }
    let mut suffix = vec![LinExpr::constant(F128::ONE); node_count + 1];
    for i in (0..node_count).rev() {
        if i + 1 > keep_from {
            // suffix[i] is only read for i > keep_from; skip dead products.
            let next = suffix[i + 1].clone();
            suffix[i] = mul(b, &next, &factors[i]);
        }
    }

    (keep_from..node_count)
        .map(|i| {
            let num = mul(b, &prefix[i], &suffix[i + 1]);
            // den_i = Π_{j≠i} (s_i + s_j): all-constant, native fold.
            let mut den = F128::ONE;
            for (j, &sj) in nodes.iter().enumerate() {
                if j != i {
                    den *= nodes[i] + sj;
                }
            }
            num.scale(den.inv())
        })
        .collect()
}

/// Dot product `Σ w_i · v_i` (one multiplication per term).
fn dot_trace(b: &mut FieldR1csBuilder, w: &[LinExpr], v: &[LinExpr]) -> LinExpr {
    assert_eq!(w.len(), v.len());
    let mut acc = LinExpr::zero();
    for (wi, vi) in w.iter().zip(v.iter()) {
        acc = acc.add(&mul(b, wi, vi));
    }
    acc
}

/// Trace twin of `zerocheck::multilinear::interpolate_at_z_on_lambda`.
fn interpolate_at_z_on_lambda_trace(
    b: &mut FieldR1csBuilder,
    values: &[LinExpr],
    k_skip: usize,
    z: &LinExpr,
) -> LinExpr {
    let ell = 1usize << k_skip;
    assert_eq!(values.len(), ell);
    let weights = lagrange_weights_window_trace(b, z, ell, ell, 0);
    dot_trace(b, &weights, values)
}

/// Trace twin of `zerocheck::multilinear::interpolate_at_z_combined`
/// (degree-< 2·2^k_skip polynomial, zero on S, Λ evaluations given).
fn interpolate_at_z_combined_trace(
    b: &mut FieldR1csBuilder,
    values_on_lambda: &[LinExpr],
    k_skip: usize,
    z: &LinExpr,
) -> LinExpr {
    let ell = 1usize << k_skip;
    assert_eq!(values_on_lambda.len(), ell);
    let weights = lagrange_weights_window_trace(b, z, 0, 2 * ell, ell);
    dot_trace(b, &weights, values_on_lambda)
}

/// Witness inversion: allocate `x^{-1}` and pin `x · x^{-1} = 1`. The
/// honest witness inverse is computed from the builder's tracked values
/// (`x = 0` would make the pin unsatisfiable — same failure point as the
/// native `.inv()` on a zero divisor).
fn inverse_trace(b: &mut FieldR1csBuilder, x: &LinExpr) -> LinExpr {
    let x_val = x.eval(b.values());
    let inv = LinExpr::from_wire(b.alloc_f128(x_val.inv()));
    let prod = mul(b, x, &inv);
    pin_eq(b, &prod, &LinExpr::constant(F128::ONE));
    inv
}

// ---------------------------------------------------------------------------
// Field zerocheck verify replay
// ---------------------------------------------------------------------------

/// Witness allocation of a `zerocheck::ZerocheckProof` under the frozen
/// shape (native shape checks → alloc asserts).
pub struct ZerocheckProofTrace {
    pub round1_ab: Vec<LinExpr>,
    pub round1_c: Vec<LinExpr>,
    pub multilinear_rounds: Vec<(LinExpr, LinExpr)>,
    pub final_a_eval: LinExpr,
    pub final_b_eval: LinExpr,
    pub final_c_eval: LinExpr,
}

impl ZerocheckProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &zerocheck::ZerocheckProof,
        m: usize,
    ) -> Self {
        let ell = 1usize << K_SKIP;
        assert!(m >= K_SKIP + 1, "log_n too small for the univariate skip");
        assert_eq!(native.round1_ab.len(), ell, "round1_ab off shape");
        assert_eq!(native.round1_c.len(), ell, "round1_c off shape");
        assert_eq!(
            native.multilinear_rounds.len(),
            m - K_SKIP,
            "multilinear rounds off shape"
        );
        let alloc_vec = |b: &mut FieldR1csBuilder, vs: &[F128]| -> Vec<LinExpr> {
            vs.iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect()
        };
        Self {
            round1_ab: alloc_vec(b, &native.round1_ab),
            round1_c: alloc_vec(b, &native.round1_c),
            multilinear_rounds: native
                .multilinear_rounds
                .iter()
                .map(|&(m1, mi)| {
                    (
                        LinExpr::from_wire(b.alloc_f128(m1)),
                        LinExpr::from_wire(b.alloc_f128(mi)),
                    )
                })
                .collect(),
            final_a_eval: LinExpr::from_wire(b.alloc_f128(native.final_a_eval)),
            final_b_eval: LinExpr::from_wire(b.alloc_f128(native.final_b_eval)),
            final_c_eval: LinExpr::from_wire(b.alloc_f128(native.final_c_eval)),
        }
    }
}

/// The `zerocheck::ZerocheckClaim` as expressions.
pub struct ZerocheckClaimTrace {
    pub z: LinExpr,
    pub mlv_challenges: Vec<LinExpr>,
    pub r_rest: Vec<LinExpr>,
    pub a_eval: LinExpr,
    pub b_eval: LinExpr,
    pub c_eval: LinExpr,
}

/// Trace twin of `zerocheck::field::verify` — line-by-line replay on the
/// lane channel. Native value checks (`CEvalMismatch`,
/// `SumcheckFinalFailed`) become pins.
pub fn zerocheck_field_verify_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    log_n: usize,
    proof: &ZerocheckProofTrace,
) -> ZerocheckClaimTrace {
    let m = log_n;
    let k_skip = K_SKIP;
    let n_mlv = m - k_skip;

    ch.observe_label(b, b"history-field-zerocheck-v0");

    // ---- Re-derive the rest eq weights.
    let r_rest = ch.sample_f128_vec(b, n_mlv);

    // ---- Observe round-1 messages, sample z.
    ch.observe_f128_slice(b, &proof.round1_ab);
    ch.observe_f128_slice(b, &proof.round1_c);
    let z = ch.sample_f128(b);

    // ---- Reconstruct ĉ(z, r_rest) from round1_c; native mismatch → pin.
    let computed_c_eval = interpolate_at_z_on_lambda_trace(b, &proof.round1_c, k_skip, &z);
    pin_eq(b, &computed_c_eval, &proof.final_c_eval);

    // ---- Initial AB running claim via the S-zero trick. Native evaluates
    // `interpolate_at_z_on_lambda(round1_c, …)` a second time for P^C(z);
    // the value is identical to `computed_c_eval` (same inputs, same
    // formula), so the trace shares it — association-of-products allowance.
    let combined_at_lambda: Vec<LinExpr> = proof
        .round1_ab
        .iter()
        .zip(&proof.round1_c)
        .map(|(x, y)| x.add(y))
        .collect();
    let combined_at_z = interpolate_at_z_combined_trace(b, &combined_at_lambda, k_skip, &z);
    let mut c_running = combined_at_z.add(&computed_c_eval);

    // ---- Multilinear chain (per round: g0 reconstruction needs the eq
    // weight's inverse — a witness inverse wire pinned to the product 1).
    let mut mlv_rhos: Vec<LinExpr> = Vec::with_capacity(n_mlv);
    for (i, (msg_1, msg_inf)) in proof.multilinear_rounds.iter().enumerate() {
        let r_eq = &r_rest[i];
        let one_plus_r_eq = r_eq.add_const(F128::ONE);
        let inv = inverse_trace(b, &one_plus_r_eq);

        let g1 = msg_1;
        let g_inf = msg_inf;
        let r_eq_g1 = mul(b, r_eq, g1);
        let g0 = mul(b, &c_running.add(&r_eq_g1), &inv);

        ch.observe_f128(b, msg_1);
        ch.observe_f128(b, msg_inf);
        let rho = ch.sample_f128(b);
        mlv_rhos.push(rho.clone());

        let one_plus_rho = rho.add_const(F128::ONE);
        let t0 = mul(b, &g0, &one_plus_rho);
        let t1 = mul(b, g1, &rho);
        let t2 = mul(b, g_inf, &rho);
        let t2 = mul(b, &t2, &one_plus_rho);
        c_running = t0.add(&t1).add(&t2);
    }

    // ---- Final consistency: G_final(ρ_all) = â·b̂ (native reject → pin).
    let expected_final = mul(b, &proof.final_a_eval, &proof.final_b_eval);
    pin_eq(b, &c_running, &expected_final);

    // ---- FS-bind the final â, b̂ claims (mirrors native).
    ch.observe_f128(b, &proof.final_a_eval);
    ch.observe_f128(b, &proof.final_b_eval);

    ZerocheckClaimTrace {
        z,
        mlv_challenges: mlv_rhos,
        r_rest,
        a_eval: proof.final_a_eval.clone(),
        b_eval: proof.final_b_eval.clone(),
        c_eval: proof.final_c_eval.clone(),
    }
}

// ---------------------------------------------------------------------------
// Lincheck verify replay
// ---------------------------------------------------------------------------

/// A `lincheck::QuirkyPoint` as expressions.
pub struct QuirkyPointTrace {
    pub z_skip: LinExpr,
    pub x_inner_rest: Vec<LinExpr>,
    pub x_outer: Vec<LinExpr>,
}

/// Witness allocation of a `lincheck::LincheckProof` under the frozen shape.
pub struct LincheckProofTrace {
    pub rounds: Vec<(LinExpr, LinExpr)>,
    pub z_partial: Vec<LinExpr>,
}

impl LincheckProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &noid_ivc_core::lincheck::LincheckProof,
        k_log: usize,
        k_skip: usize,
    ) -> Self {
        assert_eq!(native.rounds.len(), k_log - k_skip, "rounds off shape");
        assert_eq!(native.z_partial.len(), 1usize << k_skip, "z_partial off shape");
        Self {
            rounds: native
                .rounds
                .iter()
                .map(|&(e1, einf)| {
                    (
                        LinExpr::from_wire(b.alloc_f128(e1)),
                        LinExpr::from_wire(b.alloc_f128(einf)),
                    )
                })
                .collect(),
            z_partial: native
                .z_partial
                .iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect(),
        }
    }
}

/// The `lincheck::LincheckClaim` as expressions.
pub struct LincheckClaimTrace {
    pub r_inner_skip: LinExpr,
    pub r_inner_rest: Vec<LinExpr>,
    pub w: LinExpr,
}

/// The final lincheck consistency sum `Σ_s comb_partial[s] · z_partial[s]`
/// as a bilinear form over the CONSTANT matrices (fixed-shape invariant: the
/// verified instance's matrices are protocol constants, which is exactly
/// what makes this replay affordable).
///
/// Native computes `comb_vec = α·(A^T·eq_inner) + B^T·eq_inner (+β·1_pin)`
/// over all `2^k_log` columns, folds it through the sumcheck challenges,
/// and dots with `z_partial`. Expanding instead (field identity — exact
/// value, FS schedule untouched):
///
/// ```text
/// F = Σ_{(r,c)∈M'} κ_rc · λ[r_s]·e[r_x] · zp[c_s]·q[c_x]  (+ β·zp[p_s]·q[p_x])
///   = Σ_{64×64 blocks (R,X)} e[R]·q[X] · (Σ_{(i,j)∈block} κ·λ_i·zp_j)
/// ```
///
/// where `λ` = skip Lagrange weights at `z_skip`, `e` = eq(x_inner_rest),
/// `q` = eq(r_inner_rest) (the fold weights of the bound rounds), `zp` =
/// z_partial. The inner block sums are symbolic over the ≤ 2^{2·k_skip}
/// materialized products `P[i][j] = λ_i·zp_j`, so the cost is
/// `2·2^{k_log−k_skip}` (tensors) + `|P|` + ~2 muls per nonzero block —
/// instead of Θ(2^k_log) for a materialized comb_vec.
fn lincheck_final_sum_trace(
    b: &mut FieldR1csBuilder,
    r1cs: &FieldR1cs,
    alpha: &LinExpr,
    beta: Option<&LinExpr>,
    lambda: &[LinExpr],
    e_rest: &[LinExpr],
    q_rest: &[LinExpr],
    z_partial: &[LinExpr],
) -> LinExpr {
    use std::collections::BTreeMap;

    let ell = 1usize << r1cs.k_skip;
    assert_eq!(lambda.len(), ell);
    assert_eq!(z_partial.len(), ell);
    assert_eq!(e_rest.len(), 1usize << (r1cs.k_log - r1cs.k_skip));
    assert_eq!(q_rest.len(), e_rest.len());

    // ---- Collect per-block coefficient lists from the constant matrices.
    // BTreeMaps keep wire allocation deterministic (fixed shape).
    type Block = Vec<(usize, usize, F128)>; // (i, j, κ)
    let mut blocks_a: BTreeMap<(usize, usize), Block> = BTreeMap::new();
    let mut blocks_b: BTreeMap<(usize, usize), Block> = BTreeMap::new();
    let k_skip = r1cs.k_skip;
    let mask = ell - 1;
    for (rows, blocks) in [(&r1cs.a_0.rows, &mut blocks_a), (&r1cs.b_0.rows, &mut blocks_b)] {
        for (r, row) in rows.iter().enumerate() {
            for &(c, kappa) in row {
                let c = c as usize;
                blocks
                    .entry((r >> k_skip, c >> k_skip))
                    .or_default()
                    .push((r & mask, c & mask, kappa));
            }
        }
    }

    // ---- Materialize the needed P[i][j] = λ_i · zp_j products.
    let mut p: BTreeMap<(usize, usize), LinExpr> = BTreeMap::new();
    for block in blocks_a.values().chain(blocks_b.values()) {
        for &(i, j, _) in block {
            p.entry((i, j))
                .or_insert_with_key(|_| LinExpr::zero());
        }
    }
    let keys: Vec<(usize, usize)> = p.keys().copied().collect();
    for (i, j) in keys {
        let prod = mul(b, &lambda[i], &z_partial[j]);
        p.insert((i, j), prod);
    }

    // ---- Per-block: t = e[R]·q[X] (shared between A and B), then one mul
    // with each symbolic block sum.
    let mut pair_products: BTreeMap<(usize, usize), LinExpr> = BTreeMap::new();
    let mut all_keys: Vec<(usize, usize)> = blocks_a.keys().chain(blocks_b.keys()).copied().collect();
    all_keys.sort_unstable();
    all_keys.dedup();
    for &(r_blk, x_blk) in &all_keys {
        let t = mul(b, &e_rest[r_blk], &q_rest[x_blk]);
        pair_products.insert((r_blk, x_blk), t);
    }

    // Per-block products are fresh single wires allocated in ascending
    // order, so the block sums are assembled as one sorted term list —
    // NOT by repeated `LinExpr::add` (which is quadratic in block count).
    let block_sum = |blocks: &BTreeMap<(usize, usize), Block>,
                     p: &BTreeMap<(usize, usize), LinExpr>,
                     b: &mut FieldR1csBuilder,
                     pair_products: &BTreeMap<(usize, usize), LinExpr>|
     -> LinExpr {
        let mut terms: Vec<(u32, F128)> = Vec::with_capacity(blocks.len());
        for (key, entries) in blocks {
            let mut g = LinExpr::zero();
            for &(i, j, kappa) in entries {
                g = g.add(&p[&(i, j)].scale(kappa));
            }
            let prod = mul(b, &pair_products[key], &g);
            debug_assert!(prod.terms.len() == 1 && prod.constant == F128::ZERO);
            terms.push(prod.terms[0]);
        }
        debug_assert!(terms.windows(2).all(|w| w[0].0 < w[1].0));
        LinExpr {
            terms,
            constant: F128::ZERO,
        }
    };
    let t_a = block_sum(&blocks_a, &p, b, &pair_products);
    let t_b = block_sum(&blocks_b, &p, b, &pair_products);

    let mut f = mul(b, alpha, &t_a).add(&t_b);

    // ---- Constant-wire pin: comb_vec[pin] += β folds to β·zp[p_s]·q[p_x].
    if let (Some(beta), Some(col)) = (beta, r1cs.const_pin) {
        let u_pin = mul(b, &z_partial[col & mask], &q_rest[col >> k_skip]);
        f = f.add(&mul(b, beta, &u_pin));
    }
    f
}

/// Trace twin of `lincheck::verify` for a **protocol-constant** FieldR1cs
/// instance (its CSC circuit is `r1cs.csc_lincheck_circuit()` — coefficient
/// semantics enter through the constant matrices). Native shape errors are
/// alloc/build asserts; the two value checks (sumcheck-final consistency)
/// are pins.
#[allow(clippy::too_many_arguments)]
pub fn lincheck_verify_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    r1cs: &FieldR1cs,
    m: usize,
    x_ab: &QuirkyPointTrace,
    v_a: &LinExpr,
    v_b: &LinExpr,
    proof: &LincheckProofTrace,
) -> LincheckClaimTrace {
    let k_log = r1cs.k_log;
    let k_skip = r1cs.k_skip;
    let ell = 1usize << k_skip;
    let inner_rest_len = k_log - k_skip;
    assert!(k_skip <= k_log, "k_skip exceeds k_log");
    assert_eq!(x_ab.x_inner_rest.len(), inner_rest_len, "x_inner_rest off shape");
    assert_eq!(x_ab.x_outer.len(), m - k_log, "x_outer off shape");
    assert_eq!(proof.rounds.len(), inner_rest_len, "rounds off shape");
    assert_eq!(proof.z_partial.len(), ell, "z_partial off shape");

    ch.observe_label(b, b"history-lincheck-v0");

    // 1. Sample α (matches prover's order).
    let alpha = ch.sample_f128(b);

    // 2. The α-batched comb fold is deferred into the final bilinear sum
    //    (see lincheck_final_sum_trace); here only its ingredients that
    //    depend on x_ab: λ(z_skip) and eq(x_inner_rest).
    let lambda = lagrange_weights_window_trace(b, &x_ab.z_skip, 0, ell, 0);
    let e_rest = super::eq_ind_partial_eval_trace(b, &x_ab.x_inner_rest);

    // 3. Replay the product-sumcheck. β is sampled after α (mirror of the
    //    native const-pin branch); the initial target gains +β.
    let v_a_alpha = mul(b, &alpha, v_a);
    let mut target = v_a_alpha.add(v_b);
    let beta = if r1cs.const_pin.is_some() {
        let beta = ch.sample_f128(b);
        target = target.add(&beta);
        Some(beta)
    } else {
        None
    };
    let mut running = target;
    let mut r_rounds: Vec<LinExpr> = Vec::with_capacity(inner_rest_len);
    for (e1, einf) in &proof.rounds {
        ch.observe_f128(b, e1);
        ch.observe_f128(b, einf);
        let r = ch.sample_f128(b);
        // q(0) = claim + q(1) in char 2; q(X) = einf·X² + c1·X + e0.
        let e0 = running.add(e1);
        let c1 = e0.add(e1).add(einf);
        let r_sq = mul(b, &r, &r);
        running = mul(b, einf, &r_sq).add(&mul(b, &c1, &r)).add(&e0);
        r_rounds.push(r);
    }

    // 4. Observe z_partial AFTER the sumcheck rounds (matches prover order).
    ch.observe_f128_slice(b, &proof.z_partial);

    // 5. Final sumcheck consistency (native `ConsistencyFailed` → pin). The
    //    fold weights of the bound rounds are eq(r_inner_rest) LSB-first.
    let r_inner_rest: Vec<LinExpr> = r_rounds.iter().rev().cloned().collect();
    let q_rest = super::eq_ind_partial_eval_trace(b, &r_inner_rest);
    let final_sum = lincheck_final_sum_trace(
        b,
        r1cs,
        &alpha,
        beta.as_ref(),
        &lambda,
        &e_rest,
        &q_rest,
        &proof.z_partial,
    );
    pin_eq(b, &running, &final_sum);

    // 6. Sample fresh z_skip AFTER z_partial — SZ on the φ8 dim.
    let r_inner_skip = ch.sample_f128(b);

    // 7. Output claim value via φ8 Lagrange on z_partial at r_inner_skip.
    let lambda_out = lagrange_weights_window_trace(b, &r_inner_skip, 0, ell, 0);
    let w = dot_trace(b, &lambda_out, &proof.z_partial);

    LincheckClaimTrace {
        r_inner_skip,
        r_inner_rest,
        w,
    }
}

// ---------------------------------------------------------------------------
// BaseFold PCS verify replay
// ---------------------------------------------------------------------------

/// Witness allocation of one `basefold::QueryOpening`. The query `position`
/// is trace STRUCTURE (it selects Merkle leaf indices and coset offsets);
/// soundness of the binding is the pinned bit decomposition of the squeezed
/// position challenge in [`basefold_verify_trace`]. Structure derived from
/// proof data is interim until the shape-freeze pass turns index bits into
/// witness selectors (the recursion needs protocol-constant matrices) —
/// same caveat as the wallet-capsule `gen_compact_queries_trace`.
pub struct QueryOpeningTrace {
    pub position: usize,
    pub initial_leaf: Vec<LinExpr>,
    pub post_row_batch_leaf: Vec<LinExpr>,
    pub epoch_leaves: Vec<Vec<LinExpr>>,
}

/// Witness allocation of a `pcs::BaseFoldProof` under the frozen shape
/// derived from the (protocol-constant) `PcsParams`. Every native
/// `InvalidProofShape` branch is an alloc assert here.
pub struct BaseFoldProofTrace {
    pub round_messages: Vec<(LinExpr, LinExpr)>,
    pub post_row_batch_commit: FlatDigestExpr,
    pub round_commitments: Vec<FlatDigestExpr>,
    pub final_a: LinExpr,
    pub final_b: LinExpr,
    pub final_codeword: Vec<LinExpr>,
    /// Plaintext-tail FRI layer (empty iff the shape has no tail boundary).
    pub plaintext_tail: Vec<LinExpr>,
    /// Pre-query grinding nonce as a flat lane (`lo = nonce, hi = 0`).
    pub pow_nonce: LinExpr,
    pub queries: Vec<QueryOpeningTrace>,
    pub initial_multi_proof: Vec<FlatDigestExpr>,
    pub post_row_batch_multi_proof: Vec<FlatDigestExpr>,
    pub epoch_multi_proofs: Vec<Vec<FlatDigestExpr>>,
}

impl BaseFoldProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &pcs::BaseFoldProof,
        params: &PcsParams,
    ) -> Self {
        let log_msg_len = params.m - LOG_PACKING;
        let log_batch_size = params.log_batch_size;
        assert!(log_batch_size <= log_msg_len, "invalid proof shape");
        let log_dim = log_msg_len - log_batch_size;
        let k_code = log_dim + params.log_inv_rate;
        let num_ntts = 1usize << log_batch_size;
        let arities = compute_fri_arities(log_dim);
        let (num_fri_commits, tail_layout) = pcs::fri_commit_layout(k_code, &arities);
        let arity_0 = arities.first().copied().unwrap_or(0);

        assert_eq!(native.round_messages.len(), log_msg_len, "rounds off shape");
        assert_eq!(
            native.plaintext_tail.len(),
            tail_layout.map_or(0, |(len, _)| len),
            "plaintext tail off shape"
        );
        assert_eq!(
            native.round_commitments.len(),
            num_fri_commits,
            "round commitments off shape"
        );
        // SECURITY (mirror of the native check): the query count is a
        // soundness parameter, not a prover choice.
        assert_eq!(
            native.queries.len(),
            default_fri_queries(params.log_inv_rate),
            "query count off shape"
        );
        assert_eq!(
            native.final_codeword.len(),
            1usize << params.log_inv_rate,
            "final codeword off shape"
        );
        assert_eq!(
            native.epoch_multi_proofs.len(),
            num_fri_commits,
            "epoch multi-proofs off shape"
        );

        let alloc_vec = |b: &mut FieldR1csBuilder, vs: &[F128]| -> Vec<LinExpr> {
            vs.iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect()
        };
        let alloc_digests = |b: &mut FieldR1csBuilder, ds: &[Hash]| -> Vec<FlatDigestExpr> {
            ds.iter().map(|d| alloc_flat_digest(b, d)).collect()
        };

        let round_messages = native
            .round_messages
            .iter()
            .map(|m| {
                (
                    LinExpr::from_wire(b.alloc_f128(m.u_0)),
                    LinExpr::from_wire(b.alloc_f128(m.u_2)),
                )
            })
            .collect();
        let post_row_batch_commit = alloc_flat_digest(b, &native.post_row_batch_commit.root);
        let round_commitments = native
            .round_commitments
            .iter()
            .map(|c| alloc_flat_digest(b, &c.root))
            .collect();
        let final_a = LinExpr::from_wire(b.alloc_f128(native.final_a));
        let final_b = LinExpr::from_wire(b.alloc_f128(native.final_b));
        let final_codeword = alloc_vec(b, &native.final_codeword);
        let plaintext_tail = alloc_vec(b, &native.plaintext_tail);
        // The native challenger absorbs the nonce as `F128 { lo, hi: 0 }`.
        let pow_nonce =
            LinExpr::from_wire(b.alloc_f128(f128_from_u128(native.pow_nonce as u128)));

        let queries = native
            .queries
            .iter()
            .map(|q| {
                assert!(q.position < (1usize << k_code), "query position off shape");
                assert_eq!(q.initial_leaf.len(), num_ntts, "initial leaf off shape");
                if arities.is_empty() {
                    assert!(q.post_row_batch_leaf.is_empty(), "post-rb leaf off shape");
                } else {
                    assert_eq!(
                        q.post_row_batch_leaf.len(),
                        1usize << arity_0,
                        "post-rb leaf off shape"
                    );
                }
                assert_eq!(q.epoch_leaves.len(), num_fri_commits, "epoch leaves off shape");
                for (i, leaf) in q.epoch_leaves.iter().enumerate() {
                    assert_eq!(leaf.len(), 1usize << arities[i + 1], "epoch leaf off shape");
                }
                QueryOpeningTrace {
                    position: q.position,
                    initial_leaf: alloc_vec(b, &q.initial_leaf),
                    post_row_batch_leaf: alloc_vec(b, &q.post_row_batch_leaf),
                    epoch_leaves: q
                        .epoch_leaves
                        .iter()
                        .map(|l| alloc_vec(b, l))
                        .collect(),
                }
            })
            .collect();

        Self {
            round_messages,
            post_row_batch_commit,
            round_commitments,
            final_a,
            final_b,
            final_codeword,
            plaintext_tail,
            pow_nonce,
            queries,
            initial_multi_proof: alloc_digests(b, &native.initial_multi_proof),
            post_row_batch_multi_proof: alloc_digests(b, &native.post_row_batch_multi_proof),
            epoch_multi_proofs: native
                .epoch_multi_proofs
                .iter()
                .map(|p| alloc_digests(b, p))
                .collect(),
        }
    }
}

/// Bind the query positions carried by ONE squeezed lane: the native rule
/// (`pcs::sample_query_positions`) reads `floor(128 / k_code)` positions as
/// consecutive `k_code`-bit windows of the lane's FLAT bit pattern, low
/// windows first. The trace pins
/// `lane = Σ_w Σ_{i<k_code} pos_w[i]·2^{w·k_code+i} + Σ leftover b_j·2^j`
/// with the used windows' position bits as structural constants and every
/// bit outside them as a witness boolean (flat-basis powers — NOT φ(2^i):
/// the native rule reads flat bits). Returns the structural indices.
fn bind_query_positions_lane_trace(
    b: &mut FieldR1csBuilder,
    lane: &LinExpr,
    k_code: usize,
    n_used: usize,
) -> Vec<usize> {
    let per_lane = 128 / k_code;
    assert!(n_used >= 1 && n_used <= per_lane, "window count off shape");
    let raw = expr_flat_u128(b, lane);
    let mask = (1u128 << k_code) - 1;
    let mut sum = LinExpr::zero();
    let mut positions = Vec::with_capacity(n_used);
    for w in 0..n_used {
        let pos = ((raw >> (w * k_code)) & mask) as usize;
        positions.push(pos);
        for i in 0..k_code {
            if (pos >> i) & 1 == 1 {
                sum = sum.add_const(f128_from_u128(1u128 << (w * k_code + i)));
            }
        }
    }
    for j in (n_used * k_code)..128 {
        let bit = b.alloc_bool((raw >> j) & 1 == 1);
        sum = sum.add(&LinExpr::from_wire(bit).scale(f128_from_u128(1u128 << j)));
    }
    super::pin_zero(b, &sum.add(lane));
    positions
}

/// Trace twin of `basefold::row_batch_fold_one` (nested per-round folds of
/// one position's lanes): one multiplication per fold pair.
fn row_batch_fold_one_trace(
    b: &mut FieldR1csBuilder,
    lanes: &[LinExpr],
    challenges: &[LinExpr],
) -> LinExpr {
    assert_eq!(lanes.len(), 1usize << challenges.len());
    let mut buf = lanes.to_vec();
    for r in challenges {
        let half = buf.len() / 2;
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            let u = &buf[2 * j];
            let v = &buf[2 * j + 1];
            next.push(u.add(&mul(b, r, &u.add(v))));
        }
        buf = next;
    }
    buf.pop().unwrap()
}

/// Trace twin of `basefold::fri_fold_coset`. `fold_pair` with a constant
/// twiddle is affine up to the challenge product:
/// `v = v_in + u_in; u = u_in + v·t; out = u + r·(u + v)` — one
/// multiplication per pair.
fn fri_fold_coset_trace(
    b: &mut FieldR1csBuilder,
    coset: &[LinExpr],
    challenges: &[LinExpr],
    ntt: &AdditiveNttF128,
    input_layer: usize,
    coset_idx: usize,
) -> LinExpr {
    assert_eq!(coset.len(), 1usize << challenges.len());
    let mut buf = coset.to_vec();
    for (k, r) in challenges.iter().enumerate() {
        let post_fold_layer = input_layer - k - 1;
        let n = buf.len() / 2;
        let mut next = Vec::with_capacity(n);
        for j in 0..n {
            let u_in = &buf[2 * j];
            let v_in = &buf[2 * j + 1];
            let pos = coset_idx * n + j;
            let twiddle = ntt.twiddle(post_fold_layer, pos);
            let v = v_in.add(u_in);
            let u = u_in.add(&v.scale(twiddle));
            next.push(u.add(&mul(b, r, &u.add(&v))));
        }
        buf = next;
    }
    buf.pop().unwrap()
}

/// Trace twin of `basefold::verify_multi_with_dedup` +
/// `merkle::verify_merkle_multi_proof`. The sort/dedup schedule and the
/// per-level sibling consumption order are trace structure derived from the
/// (position-bound) query indices; the value checks — duplicate-position
/// leaf equality and the final root equality — are pins.
fn verify_multi_with_dedup_trace(
    b: &mut FieldR1csBuilder,
    root: &FlatDigestExpr,
    num_leaves: usize,
    positions: &[usize],
    leaf_hashes: &[FlatDigestExpr],
    proof: &[FlatDigestExpr],
) {
    assert!(num_leaves.is_power_of_two() && num_leaves > 0);
    assert_eq!(positions.len(), leaf_hashes.len());
    if positions.is_empty() {
        assert!(proof.is_empty(), "unused multi-proof siblings");
        return;
    }

    // Sort + dedup (query order preserved among equals — stable sort, as
    // native); duplicated positions must carry equal leaf hashes.
    let mut paired: Vec<(usize, FlatDigestExpr)> = positions
        .iter()
        .copied()
        .zip(leaf_hashes.iter().cloned())
        .collect();
    paired.sort_by_key(|(p, _)| *p);
    let mut active: Vec<(usize, FlatDigestExpr)> = Vec::with_capacity(paired.len());
    for (p, h) in paired {
        assert!(p < num_leaves, "leaf position out of range");
        if let Some(last) = active.last() {
            if last.0 == p {
                let kept = active.last().unwrap().1.clone();
                pin_flat_digest_eq(b, &kept, &h);
                continue;
            }
        }
        active.push((p, h));
    }

    if num_leaves == 1 {
        assert!(proof.is_empty(), "unused multi-proof siblings");
        pin_flat_digest_eq(b, &active[0].1, root);
        return;
    }

    let mut proof_iter = proof.iter();
    let mut level_len = num_leaves;
    while level_len > 1 {
        let mut next: Vec<(usize, FlatDigestExpr)> = Vec::with_capacity(active.len());
        let mut i = 0usize;
        while i < active.len() {
            let (p, h) = active[i].clone();
            let sib_active = i + 1 < active.len() && active[i + 1].0 == (p ^ 1);
            let (left, right) = if sib_active {
                let h_sib = active[i + 1].1.clone();
                i += 2;
                (h, h_sib)
            } else {
                // Native "proof exhausted" → structural build failure.
                let sib = proof_iter
                    .next()
                    .expect("insufficient multi-proof siblings")
                    .clone();
                i += 1;
                if p & 1 == 0 { (h, sib) } else { (sib, h) }
            };
            let parent = merkle_hash_pair_trace(b, &left, &right);
            next.push((p >> 1, parent));
        }
        active = next;
        level_len >>= 1;
    }
    assert!(proof_iter.next().is_none(), "unused multi-proof siblings");
    assert_eq!(active.len(), 1);
    pin_flat_digest_eq(b, &active[0].1, root);
}

/// Trace twin of `basefold::verify`. Replays the sumcheck/commit transcript
/// on the lane channel, binds resampled query positions, replays every
/// query's leaf hashing / row-batch fold / FRI coset folds / final-codeword
/// check, and batch-verifies the per-tree Merkle multi-proofs. Native value
/// rejections → pins; shape rejections were alloc asserts. Returns the
/// sumcheck challenges.
pub fn basefold_verify_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    target: &LinExpr,
    proof: &BaseFoldProofTrace,
    initial_codeword_root: &FlatDigestExpr,
    params: &PcsParams,
) -> Vec<LinExpr> {
    let log_msg_len = params.m - LOG_PACKING;
    let log_batch_size = params.log_batch_size;
    let log_inv_rate = params.log_inv_rate;
    let log_dim = log_msg_len - log_batch_size;
    let k_code = log_dim + log_inv_rate;
    let arities = compute_fri_arities(log_dim);
    let (num_fri_commits, tail_layout) = pcs::fri_commit_layout(k_code, &arities);
    let arity_0 = arities.first().copied().unwrap_or(0);
    let ntt = AdditiveNttF128::standard(k_code);

    ch.observe_label(b, b"history-basefold-v0");

    // ---- Sumcheck rounds in lockstep, with the T2 / epoch commit observes.
    let mut running = target.clone();
    let mut challenges: Vec<LinExpr> = Vec::with_capacity(log_msg_len);
    let mut current_epoch = 0usize;
    let mut rounds_in_epoch = 0usize;
    for round in 0..log_msg_len {
        let (u_0, u_2) = &proof.round_messages[round];
        ch.observe_f128(b, u_0);
        ch.observe_f128(b, u_2);
        let r = ch.sample_f128(b);

        let u_1 = running.add(u_2);
        let r_sq = mul(b, &r, &r);
        running = u_0.add(&mul(b, &r, &u_1)).add(&mul(b, &r_sq, u_2));
        challenges.push(r);

        if round + 1 == log_batch_size && !arities.is_empty() {
            // Full-digest binding: both flat lanes of the root, matching the
            // native verifier's two-lane absorb.
            ch.observe_f128(b, &proof.post_row_batch_commit[0]);
            ch.observe_f128(b, &proof.post_row_batch_commit[1]);
        }
        if round >= log_batch_size {
            rounds_in_epoch += 1;
            if rounds_in_epoch == arities[current_epoch] {
                let boundary = current_epoch + 1;
                if boundary <= num_fri_commits {
                    ch.observe_f128(b, &proof.round_commitments[current_epoch][0]);
                    ch.observe_f128(b, &proof.round_commitments[current_epoch][1]);
                } else if tail_layout.is_some() && boundary == num_fri_commits + 1 {
                    // Plaintext-tail boundary: absorb the whole layer, one
                    // lane per element (mirror of the native absorb).
                    for lane in &proof.plaintext_tail {
                        ch.observe_f128(b, lane);
                    }
                }
                rounds_in_epoch = 0;
                current_epoch += 1;
            }
        }
    }

    // ---- Final sumcheck consistency (native reject → pin).
    let ab = mul(b, &proof.final_a, &proof.final_b);
    pin_eq(b, &ab, &running);

    // ---- Final codeword constancy + equality with final_a.
    let constant = &proof.final_codeword[0];
    for v in proof.final_codeword.iter().skip(1) {
        pin_eq(b, v, constant);
    }
    pin_eq(b, constant, &proof.final_a);

    // ---- Grinding check, then resample query positions with one vector
    // squeeze; bind each to its allocated structure.
    ch.verify_pow_trace(b, &proof.pow_nonce, pcs::QUERY_GRIND_BITS);
    let n_queries = proof.queries.len();
    let per_lane = 128 / k_code;
    let lanes = ch.sample_f128_vec(b, n_queries.div_ceil(per_lane));
    let mut qi = 0usize;
    for lane in &lanes {
        let used = per_lane.min(n_queries - qi);
        for position in bind_query_positions_lane_trace(b, lane, k_code, used) {
            // Native `q.position != positions[qi]` → the allocated structure
            // must match the transcript-derived index (build-time assert).
            assert_eq!(
                proof.queries[qi].position, position,
                "query position desynced from transcript"
            );
            qi += 1;
        }
    }
    assert_eq!(qi, n_queries, "query positions exhausted off shape");

    // ---- Per-query fold replay + per-tree leaf-hash accumulation.
    let mut initial_positions = Vec::with_capacity(n_queries);
    let mut initial_hashes: Vec<FlatDigestExpr> = Vec::with_capacity(n_queries);
    let mut post_rb_positions = Vec::with_capacity(n_queries);
    let mut post_rb_hashes: Vec<FlatDigestExpr> = Vec::with_capacity(n_queries);
    let mut epoch_positions: Vec<Vec<usize>> = vec![Vec::with_capacity(n_queries); num_fri_commits];
    let mut epoch_hashes: Vec<Vec<FlatDigestExpr>> =
        vec![Vec::with_capacity(n_queries); num_fri_commits];

    for q in &proof.queries {
        initial_positions.push(q.position);
        initial_hashes.push(merkle_hash_leaf_lanes_trace(b, &q.initial_leaf));

        // Row-batch fold T1's lanes to one post-row-batch value.
        let post_row_batch_value =
            row_batch_fold_one_trace(b, &q.initial_leaf, &challenges[..log_batch_size]);

        let fri_challenge_start = log_batch_size;
        let mut cum_arity = arity_0;
        let mut expected;
        if arities.is_empty() {
            expected = post_row_batch_value;
        } else {
            let post_leaf_idx = q.position >> arity_0;
            post_rb_positions.push(post_leaf_idx);
            post_rb_hashes.push(merkle_hash_leaf_lanes_trace(b, &q.post_row_batch_leaf));

            // Cross-check T2 against the row-batch fold (value check → pin).
            let inner_offset = q.position & ((1usize << arity_0) - 1);
            pin_eq(b, &q.post_row_batch_leaf[inner_offset], &post_row_batch_value);

            expected = fri_fold_coset_trace(
                b,
                &q.post_row_batch_leaf,
                &challenges[fri_challenge_start..fri_challenge_start + arity_0],
                &ntt,
                k_code,
                post_leaf_idx,
            );
        }

        for i in 0..num_fri_commits {
            let leaf = &q.epoch_leaves[i];
            let next_arity = arities[i + 1];
            let p_at_this_layer = q.position >> cum_arity;
            let leaf_idx = p_at_this_layer >> next_arity;
            let offset = p_at_this_layer & ((1usize << next_arity) - 1);

            epoch_positions[i].push(leaf_idx);
            epoch_hashes[i].push(merkle_hash_leaf_lanes_trace(b, leaf));

            pin_eq(b, &leaf[offset], &expected);

            let input_layer = k_code - cum_arity;
            expected = fri_fold_coset_trace(
                b,
                leaf,
                &challenges[fri_challenge_start + cum_arity
                    ..fri_challenge_start + cum_arity + next_arity],
                &ntt,
                input_layer,
                leaf_idx,
            );
            cum_arity += next_arity;
        }

        // Final per-query check: against the plaintext tail when one
        // exists (the tail folds to the final codeword once, below), else
        // directly against the final codeword.
        if let Some((_, tail_cum)) = tail_layout {
            assert_eq!(cum_arity, tail_cum, "tail layer offset off shape");
            let p_tail = q.position >> cum_arity;
            pin_eq(b, &proof.plaintext_tail[p_tail], &expected);
        } else {
            let p_final = q.position >> cum_arity;
            pin_eq(b, &proof.final_codeword[p_final], &expected);
        }
    }

    // ---- The plaintext tail folds to the final codeword: one coset of
    // 2^rem elements per final-layer slot (value checks → pins).
    if let Some((tail_len, tail_cum)) = tail_layout {
        let rem = log_dim - tail_cum;
        let coset = 1usize << rem;
        assert_eq!(tail_len >> rem, 1usize << log_inv_rate, "tail off shape");
        let fri_challenge_start = log_batch_size;
        let rem_challenges =
            &challenges[fri_challenge_start + tail_cum..fri_challenge_start + log_dim];
        let input_layer = k_code - tail_cum;
        for f in 0..(tail_len >> rem) {
            let folded = fri_fold_coset_trace(
                b,
                &proof.plaintext_tail[f * coset..(f + 1) * coset],
                rem_challenges,
                &ntt,
                input_layer,
                f,
            );
            pin_eq(b, &folded, &proof.final_codeword[f]);
        }
    }

    // ---- Batched Merkle verification, one multi-proof per tree.
    verify_multi_with_dedup_trace(
        b,
        initial_codeword_root,
        1usize << k_code,
        &initial_positions,
        &initial_hashes,
        &proof.initial_multi_proof,
    );
    if !arities.is_empty() {
        verify_multi_with_dedup_trace(
            b,
            &proof.post_row_batch_commit,
            1usize << (k_code - arity_0),
            &post_rb_positions,
            &post_rb_hashes,
            &proof.post_row_batch_multi_proof,
        );
    }
    let mut cum_arity_check = arity_0;
    for i in 0..num_fri_commits {
        let next_arity = arities[i + 1];
        verify_multi_with_dedup_trace(
            b,
            &proof.round_commitments[i],
            1usize << (k_code - cum_arity_check - next_arity),
            &epoch_positions[i],
            &epoch_hashes[i],
            &proof.epoch_multi_proofs[i],
        );
        cum_arity_check += next_arity;
    }

    challenges
}

// ---------------------------------------------------------------------------
// Quirky-direct batched opening verify replay
// ---------------------------------------------------------------------------

/// A `pcs::QuirkyDirectClaim` as expressions (the claim point comes from
/// replayed sub-protocol challenges; only the value is fresh proof data).
pub struct QuirkyDirectClaimTrace {
    pub z_skip: LinExpr,
    pub k_skip: usize,
    pub x_rest: Vec<LinExpr>,
    pub value: LinExpr,
}

/// Trace twin of `pcs::verify_opening_batch_quirky_direct`: mirror
/// transcript (labels, per-claim value observes, γ batching), the shared
/// BaseFold replay, then the quirky `final_b` factorization
/// `(Σ_i eq(challenges[..k_skip], i)·L_i(z_skip)) · eq(x_rest, challenges[k_skip..])`
/// pinned against the proof's `final_b`.
pub fn verify_opening_batch_quirky_direct_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    commitment_root: &FlatDigestExpr,
    claims: &[QuirkyDirectClaimTrace],
    proof: &BaseFoldProofTrace,
    params: &PcsParams,
) {
    assert!(!claims.is_empty(), "need at least one claim");
    let l_log = params.m - LOG_PACKING;
    for c in claims {
        assert_eq!(c.x_rest.len() + c.k_skip, l_log, "claim point off shape");
    }

    ch.observe_label(b, b"history-pcs-open-field-v0");
    for c in claims {
        ch.observe_label(b, b"history-pcs-quirky-direct-v0");
        ch.observe_f128(b, &c.value);
    }
    let gammas: Vec<LinExpr> = (0..claims.len()).map(|_| ch.sample_f128(b)).collect();

    let mut target_combined = LinExpr::zero();
    for (c, g) in claims.iter().zip(gammas.iter()) {
        target_combined = target_combined.add(&mul(b, g, &c.value));
    }

    let challenges =
        basefold_verify_trace(b, ch, &target_combined, proof, commitment_root, params);
    assert_eq!(challenges.len(), l_log);

    let mut expected_final_b = LinExpr::zero();
    for (c, g) in claims.iter().zip(gammas.iter()) {
        let ell = 1usize << c.k_skip;
        let weights = lagrange_weights_window_trace(b, &c.z_skip, 0, ell, 0);
        let eq_skip = super::eq_ind_partial_eval_trace(b, &challenges[..c.k_skip]);
        let skip_factor = dot_trace(b, &weights, &eq_skip);
        let eq_rest = b.eq_eval_trace(&c.x_rest, &challenges[c.k_skip..]);
        let term = mul(b, g, &skip_factor);
        expected_final_b = expected_final_b.add(&mul(b, &term, &eq_rest));
    }
    pin_eq(b, &expected_final_b, &proof.final_b);
}

// ---------------------------------------------------------------------------
// Top-level FieldR1cs verifier replay ([R])
// ---------------------------------------------------------------------------

/// A `proof::ZClaim` as expressions (quirky point + value).
pub struct ZClaimTrace {
    pub z_skip: LinExpr,
    pub x_inner_rest: Vec<LinExpr>,
    pub x_outer: Vec<LinExpr>,
    pub value: LinExpr,
}

/// The `proof::R1csClaim` pair as expressions.
pub struct R1csClaimTrace {
    pub ab: ZClaimTrace,
    pub c: ZClaimTrace,
}

/// Witness allocation of a full `proof::FieldR1csProof`.
pub struct FieldR1csProofTrace {
    pub zerocheck: ZerocheckProofTrace,
    pub lincheck: LincheckProofTrace,
    pub pcs_open: BaseFoldProofTrace,
}

impl FieldR1csProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &noid_ivc_core::proof::FieldR1csProof,
        r1cs: &FieldR1cs,
        pcs_params: &PcsParams,
    ) -> Self {
        Self {
            zerocheck: ZerocheckProofTrace::alloc(b, &native.zerocheck, r1cs.m),
            lincheck: LincheckProofTrace::alloc(b, &native.lincheck, r1cs.k_log, r1cs.k_skip),
            pcs_open: BaseFoldProofTrace::alloc(b, &native.pcs_open, pcs_params),
        }
    }
}

/// Trace twin of `verifier::verify_field` — the [R] slot body. The verified
/// instance and its PCS parameters are protocol constants; the commitment
/// root and every proof field are witness. Statement binding → field
/// zerocheck → shared lincheck → batched quirky-direct PCS opening; returns
/// the two z-claims for the caller's public-input chaining.
pub fn verify_field_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FsChannelTrace,
    r1cs: &FieldR1cs,
    pcs_params: &PcsParams,
    commitment_root: &FlatDigestExpr,
    proof: &FieldR1csProofTrace,
) -> R1csClaimTrace {
    assert_eq!(
        pcs_params.m,
        r1cs.m + LOG_PACKING,
        "pcs_params.m must be r1cs.m + LOG_PACKING"
    );

    // ---- Bind the FS transcript to the statement.
    bind_statement_field_trace(b, ch, r1cs, pcs_params, commitment_root);

    // ---- Field zerocheck.
    let zc_claim = zerocheck_field_verify_trace(b, ch, r1cs.m, &proof.zerocheck);

    // ---- Lincheck at the zerocheck's quirky point.
    let inner_rest_len = r1cs.k_log - r1cs.k_skip;
    let x_ab = QuirkyPointTrace {
        z_skip: zc_claim.z.clone(),
        x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };
    let lc_claim = lincheck_verify_trace(
        b,
        ch,
        r1cs,
        r1cs.m,
        &x_ab,
        &zc_claim.a_eval,
        &zc_claim.b_eval,
        &proof.lincheck,
    );

    // ---- The two z-claims (mirror of verify_field_inner).
    let ab = ZClaimTrace {
        z_skip: lc_claim.r_inner_skip.clone(),
        x_inner_rest: lc_claim.r_inner_rest.clone(),
        x_outer: x_ab.x_outer.clone(),
        value: lc_claim.w.clone(),
    };
    let c = ZClaimTrace {
        z_skip: zc_claim.z.clone(),
        x_inner_rest: zc_claim.r_rest[..inner_rest_len].to_vec(),
        x_outer: zc_claim.r_rest[inner_rest_len..].to_vec(),
        value: zc_claim.c_eval.clone(),
    };

    // ---- Batched quirky-direct PCS opening over both claims.
    let x_rest_of = |zc: &ZClaimTrace| -> Vec<LinExpr> {
        let mut v = zc.x_inner_rest.clone();
        v.extend_from_slice(&zc.x_outer);
        v
    };
    let claims = [
        QuirkyDirectClaimTrace {
            z_skip: ab.z_skip.clone(),
            k_skip: r1cs.k_skip,
            x_rest: x_rest_of(&ab),
            value: ab.value.clone(),
        },
        QuirkyDirectClaimTrace {
            z_skip: c.z_skip.clone(),
            k_skip: r1cs.k_skip,
            x_rest: x_rest_of(&c),
            value: c.value.clone(),
        },
    ];
    verify_opening_batch_quirky_direct_trace(
        b,
        ch,
        commitment_root,
        &claims,
        &proof.pcs_open,
        pcs_params,
    );

    R1csClaimTrace { ab, c }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::challenger::{fs_pack_bytes_lanes, Challenger, FsLaneChallenger};
    use noid_ivc_core::field_circuit::FsChannelTrace;

    struct Rng(u128);
    impl Rng {
        fn next_u128(&mut self) -> u128 {
            self.0 = self
                .0
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0xB5AD_4ECE_DA1C_E2A9);
            self.0
        }
        fn next_hash(&mut self) -> Hash {
            digest_bytes_of_lanes(self.next_u128(), self.next_u128())
        }
        fn next_f128(&mut self) -> F128 {
            f128_from_u128(self.next_u128())
        }
    }

    fn assert_digest_is(b: &FieldR1csBuilder, d: &FlatDigestExpr, native: &Hash, what: &str) {
        let got = digest_bytes_of_lanes(expr_flat_u128(b, &d[0]), expr_flat_u128(b, &d[1]));
        assert_eq!(&got, native, "{what} diverged from native");
    }

    /// The module's private tag copies match the ones `noid_ivc_core::merkle`
    /// actually hashes with: a one-permutation feed-forward compress plus
    /// both leaf modes (fixed no-pad for block-aligned lengths, padded
    /// otherwise) built here from the DUPLICATED tags / shared IV helper
    /// reproduce the native digests.
    #[test]
    fn duplicated_tags_match_native_merkle() {
        use noid_poseidon2b::native::{
            compress_flat_feed_forward_with_tag, Poseidon2bFlatSponge,
        };
        let mut rng = Rng(0x7A65);
        let (l, r) = (rng.next_hash(), rng.next_hash());
        assert_eq!(
            merkle::hash_pair(&l, &r),
            compress_flat_feed_forward_with_tag(MERKLE_NODE_TAG, &l, &r),
        );
        // Block-aligned leaf → fixed no-pad mode on the length-bound IV.
        let data: Vec<u8> = (0..64u8).collect();
        let mut s = Poseidon2bFlatSponge::with_iv_flat(merkle::leaf_fixed_iv_flat(data.len()));
        s.update(&data);
        assert_eq!(merkle::hash_leaf(&data), s.finalize_no_pad());
        // Odd-lane leaf → padded duplex on the module's duplicated tag.
        let data: Vec<u8> = (0..48u8).collect();
        let mut s = Poseidon2bFlatSponge::with_tag(MERKLE_LEAF_TAG);
        s.update(&data);
        assert_eq!(merkle::hash_leaf(&data), s.finalize());
    }

    #[test]
    fn hash_pair_trace_matches_native() {
        let mut rng = Rng(0xBEEF);
        for case in 0..8 {
            let (l, r) = (rng.next_hash(), rng.next_hash());
            let native = merkle::hash_pair(&l, &r);

            let mut b = FieldR1csBuilder::new();
            let le = alloc_flat_digest(&mut b, &l);
            let re = alloc_flat_digest(&mut b, &r);
            let out = merkle_hash_pair_trace(&mut b, &le, &re);
            assert_digest_is(&b, &out, &native, "hash_pair");

            // Constant folding is value-identical and allocates nothing.
            let before = b.num_wires();
            let out_const =
                merkle_hash_pair_trace(&mut b, &const_flat_digest(&l), &const_flat_digest(&r));
            assert_eq!(b.num_wires(), before, "const fold must not allocate");
            assert_digest_is(&b, &out_const, &native, "hash_pair const fold");

            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "case {case}");
        }
    }

    #[test]
    fn hash_leaf_trace_matches_native_even_and_odd_lanes() {
        let mut rng = Rng(0xF00D);
        for n_lanes in [1usize, 2, 3, 4, 8, 32, 33] {
            let lanes: Vec<F128> = (0..n_lanes).map(|_| rng.next_f128()).collect();
            let mut bytes = Vec::with_capacity(n_lanes * 16);
            for v in &lanes {
                bytes.extend_from_slice(&(v.lo as u128 | ((v.hi as u128) << 64)).to_le_bytes());
            }
            let native = merkle::hash_leaf(&bytes);

            let mut b = FieldR1csBuilder::new();
            let lane_exprs: Vec<LinExpr> = lanes
                .iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect();
            let out = merkle_hash_leaf_lanes_trace(&mut b, &lane_exprs);
            assert_digest_is(&b, &out, &native, "hash_leaf");
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "n_lanes={n_lanes}");
        }
    }

    /// A tampered leaf lane makes a root pin unsatisfiable — the negative
    /// twin of the lockstep tests.
    #[test]
    fn tampered_leaf_breaks_root_pin() {
        let mut rng = Rng(0x5AD);
        let lanes: Vec<F128> = (0..4).map(|_| rng.next_f128()).collect();
        let mut bytes = Vec::with_capacity(64);
        for v in &lanes {
            bytes.extend_from_slice(&(v.lo as u128 | ((v.hi as u128) << 64)).to_le_bytes());
        }
        let native = merkle::hash_leaf(&bytes);

        let mut b = FieldR1csBuilder::new();
        let wires: Vec<_> = lanes.iter().map(|&v| b.alloc_f128(v)).collect();
        let lane_exprs: Vec<LinExpr> = wires.iter().map(|&w| LinExpr::from_wire(w)).collect();
        let out = merkle_hash_leaf_lanes_trace(&mut b, &lane_exprs);
        pin_flat_digest_eq(&mut b, &out, &const_flat_digest(&native));
        let (r1cs, mut z) = b.build();
        assert!(r1cs.satisfies(&z));
        z[wires[2].0 as usize] += F128::ONE;
        assert!(!r1cs.satisfies(&z), "tampered lane accepted");
    }

    /// Lagrange-weight windows match the three native helpers exactly.
    #[test]
    fn lagrange_windows_match_native() {
        use noid_ivc_core::zerocheck::multilinear::{
            interpolate_at_z_combined, interpolate_at_z_on_lambda, lagrange_weights_lambda_naive,
            lagrange_weights_naive,
        };
        let mut rng = Rng(0x1A6);
        for k in [3usize, 6] {
            let ell = 1usize << k;
            let z = rng.next_f128();
            let vals: Vec<F128> = (0..ell).map(|_| rng.next_f128()).collect();

            let mut b = FieldR1csBuilder::new();
            let ze = LinExpr::from_wire(b.alloc_f128(z));
            let vals_e: Vec<LinExpr> = vals
                .iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect();

            let w_s = lagrange_weights_window_trace(&mut b, &ze, 0, ell, 0);
            for (we, wn) in w_s.iter().zip(lagrange_weights_naive(k, z)) {
                assert_eq!(we.eval(b.values()), wn, "S weight k={k}");
            }
            let w_l = lagrange_weights_window_trace(&mut b, &ze, ell, ell, 0);
            for (we, wn) in w_l.iter().zip(lagrange_weights_lambda_naive(k, z)) {
                assert_eq!(we.eval(b.values()), wn, "Λ weight k={k}");
            }

            let on_lambda = interpolate_at_z_on_lambda_trace(&mut b, &vals_e, k, &ze);
            assert_eq!(
                on_lambda.eval(b.values()),
                interpolate_at_z_on_lambda(&vals, k, z),
                "interp Λ k={k}"
            );
            let combined = interpolate_at_z_combined_trace(&mut b, &vals_e, k, &ze);
            assert_eq!(
                combined.eval(b.values()),
                interpolate_at_z_combined(&vals, k, z),
                "interp combined k={k}"
            );
            let (r1cs, zz) = b.build();
            assert!(r1cs.satisfies(&zz));
        }
    }

    fn random_zerocheck_instance(
        m: usize,
        seed: u128,
    ) -> (zerocheck::ZerocheckProof, zerocheck::ZerocheckClaim) {
        let mut rng = Rng(seed);
        let n = 1usize << m;
        let a: Vec<F128> = (0..n).map(|_| rng.next_f128()).collect();
        let b: Vec<F128> = (0..n).map(|_| rng.next_f128()).collect();
        let c: Vec<F128> = a.iter().zip(&b).map(|(x, y)| *x * *y).collect();
        let mut ch = FsLaneChallenger::new(b"self-verify-zc-test");
        let (proof, claim) = zerocheck::field::prove(&a, &b, &c, m, &mut ch);
        (proof, claim)
    }

    /// THE zerocheck lockstep gate: honest proofs at several sizes; the
    /// trace replay reproduces every native claim field, keeps the channel
    /// in lockstep, and the built R1CS is satisfiable.
    #[test]
    fn zerocheck_replay_lockstep_matches_native() {
        for &(m, seed) in &[(7usize, 1u128), (8, 2), (10, 3)] {
            let (proof, _) = random_zerocheck_instance(m, seed);

            let mut ch_native = FsLaneChallenger::new(b"self-verify-zc-test");
            let native_claim = zerocheck::field::verify(m, &proof, &mut ch_native)
                .expect("native verify accepts honest proof");

            let mut b = FieldR1csBuilder::new();
            let mut ch = FsChannelTrace::new(&mut b, b"self-verify-zc-test");
            let proof_e = ZerocheckProofTrace::alloc(&mut b, &proof, m);
            let claim = zerocheck_field_verify_trace(&mut b, &mut ch, m, &proof_e);

            assert_eq!(claim.z.eval(b.values()), native_claim.z, "z (m={m})");
            for (e, n) in claim.mlv_challenges.iter().zip(&native_claim.mlv_challenges) {
                assert_eq!(e.eval(b.values()), *n, "mlv challenge (m={m})");
            }
            for (e, n) in claim.r_rest.iter().zip(&native_claim.r_rest) {
                assert_eq!(e.eval(b.values()), *n, "r_rest (m={m})");
            }
            assert_eq!(claim.a_eval.eval(b.values()), native_claim.a_eval);
            assert_eq!(claim.b_eval.eval(b.values()), native_claim.b_eval);
            assert_eq!(claim.c_eval.eval(b.values()), native_claim.c_eval);

            // Post-verify transcript lockstep.
            let c_n = ch_native.sample_f128();
            let c_t = ch.sample_f128(&mut b);
            assert_eq!(c_t.eval(b.values()), c_n, "post-verify challenge (m={m})");

            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "m={m}");
        }
    }

    /// Mutating any zerocheck proof field makes the trace unsatisfiable —
    /// the replay-completeness mirror of the native `mutations_rejected`.
    #[test]
    fn zerocheck_replay_rejects_mutations() {
        let m = 8usize;
        let (proof, _) = random_zerocheck_instance(m, 0xDEAD);

        let n_mutations = {
            // one wire per allocated proof field, in alloc order:
            // round1_ab(64) + round1_c(64) + rounds(2·(m−6)) + 3 finals
            64 + 64 + 2 * (m - K_SKIP) + 3
        };
        let mut survivors = Vec::new();
        for target in 0..n_mutations {
            let mut b = FieldR1csBuilder::new();
            let mut ch = FsChannelTrace::new(&mut b, b"self-verify-zc-test");
            // Proof wires are allocated first and contiguously (wire 0 is
            // the constant): the target index maps directly.
            let first_wire = b.num_wires();
            let proof_e = ZerocheckProofTrace::alloc(&mut b, &proof, m);
            let _ = zerocheck_field_verify_trace(&mut b, &mut ch, m, &proof_e);
            let (r1cs, mut z) = b.build();
            assert!(r1cs.satisfies(&z));
            z[first_wire + target] += F128::ONE;
            if r1cs.satisfies(&z) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "zerocheck mutation survivors: {survivors:?}"
        );
    }

    /// Native prove pipeline (zerocheck + lincheck) over a synthetic
    /// satisfiable FieldR1cs, for the lincheck lockstep/mutation gates.
    fn lincheck_fixture(
        m: usize,
        k_log: usize,
        seed: u64,
    ) -> (
        FieldR1cs,
        zerocheck::ZerocheckProof,
        noid_ivc_core::lincheck::LincheckProof,
    ) {
        use noid_ivc_core::field_r1cs::synthetic_satisfiable;
        use noid_ivc_core::lincheck::{self, QuirkyPoint};

        let (r1cs, z) = synthetic_satisfiable(m, k_log, seed);
        let a = r1cs.apply_a(&z);
        let bb = r1cs.apply_b(&z);
        // C = I ⇒ the zerocheck statement a·b + c = 0 holds with c = z.
        let mut ch = FsLaneChallenger::new(b"self-verify-lc-test");
        let (zc_proof, zc_claim) = zerocheck::field::prove(&a, &bb, &z, m, &mut ch);
        let inner_rest_len = r1cs.k_log - r1cs.k_skip;
        let x_ab = QuirkyPoint {
            z_skip: zc_claim.z,
            x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
            x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
        };
        let (lc_proof, _) = lincheck::prove_field(
            &z,
            m,
            r1cs.k_log,
            r1cs.k_skip,
            r1cs.useful_rows,
            r1cs.csc_lincheck_circuit(),
            &x_ab,
            &mut ch,
        );
        (r1cs, zc_proof, lc_proof)
    }

    /// THE lincheck lockstep gate: replay zerocheck + lincheck in-trace
    /// against the native verify chain — claims, transcript and
    /// satisfiability all in lockstep. Exercises both a block-diagonal
    /// instance (m > k_log) and the builder shape (m = k_log).
    #[test]
    fn lincheck_replay_lockstep_matches_native() {
        use noid_ivc_core::lincheck::{self, QuirkyPoint};

        for &(m, k_log, seed) in &[(10usize, 8usize, 7u64), (9, 9, 8), (8, 7, 9)] {
            let (r1cs, zc_proof, lc_proof) = lincheck_fixture(m, k_log, seed);

            // ---- Native verify chain.
            let mut ch_native = FsLaneChallenger::new(b"self-verify-lc-test");
            let zc_claim = zerocheck::field::verify(m, &zc_proof, &mut ch_native)
                .expect("native zerocheck accepts");
            let inner_rest_len = r1cs.k_log - r1cs.k_skip;
            let x_ab = QuirkyPoint {
                z_skip: zc_claim.z,
                x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
                x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
            };
            let native_claim = lincheck::verify(
                m,
                r1cs.k_log,
                r1cs.k_skip,
                r1cs.csc_lincheck_circuit(),
                &x_ab,
                zc_claim.a_eval,
                zc_claim.b_eval,
                &lc_proof,
                &mut ch_native,
            )
            .expect("native lincheck accepts");

            // ---- Trace replay chain.
            let mut b = FieldR1csBuilder::new();
            let mut ch = FsChannelTrace::new(&mut b, b"self-verify-lc-test");
            let zc_e = ZerocheckProofTrace::alloc(&mut b, &zc_proof, m);
            let zc_claim_e = zerocheck_field_verify_trace(&mut b, &mut ch, m, &zc_e);
            let x_ab_e = QuirkyPointTrace {
                z_skip: zc_claim_e.z.clone(),
                x_inner_rest: zc_claim_e.mlv_challenges[..inner_rest_len].to_vec(),
                x_outer: zc_claim_e.mlv_challenges[inner_rest_len..].to_vec(),
            };
            let lc_e = LincheckProofTrace::alloc(&mut b, &lc_proof, r1cs.k_log, r1cs.k_skip);
            let claim = lincheck_verify_trace(
                &mut b,
                &mut ch,
                &r1cs,
                m,
                &x_ab_e,
                &zc_claim_e.a_eval,
                &zc_claim_e.b_eval,
                &lc_e,
            );

            assert_eq!(
                claim.r_inner_skip.eval(b.values()),
                native_claim.r_inner_skip,
                "r_inner_skip (m={m},k_log={k_log})"
            );
            for (e, n) in claim.r_inner_rest.iter().zip(&native_claim.r_inner_rest) {
                assert_eq!(e.eval(b.values()), *n, "r_inner_rest (m={m},k_log={k_log})");
            }
            assert_eq!(
                claim.w.eval(b.values()),
                native_claim.w,
                "w (m={m},k_log={k_log})"
            );

            let c_n = ch_native.sample_f128();
            let c_t = ch.sample_f128(&mut b);
            assert_eq!(c_t.eval(b.values()), c_n, "post-verify challenge");

            let (out_r1cs, out_z) = b.build();
            assert!(out_r1cs.satisfies(&out_z), "m={m} k_log={k_log}");
        }
    }

    /// Mutating any lincheck proof wire makes the trace unsatisfiable.
    #[test]
    fn lincheck_replay_rejects_mutations() {
        let (m, k_log, seed) = (9usize, 8usize, 0x11u64);
        let (r1cs, zc_proof, lc_proof) = lincheck_fixture(m, k_log, seed);
        let inner_rest_len = r1cs.k_log - r1cs.k_skip;
        let n_lc_wires = 2 * inner_rest_len + (1usize << r1cs.k_skip);

        let mut survivors = Vec::new();
        for target in 0..n_lc_wires {
            let mut b = FieldR1csBuilder::new();
            let mut ch = FsChannelTrace::new(&mut b, b"self-verify-lc-test");
            let zc_e = ZerocheckProofTrace::alloc(&mut b, &zc_proof, m);
            let zc_claim_e = zerocheck_field_verify_trace(&mut b, &mut ch, m, &zc_e);
            let x_ab_e = QuirkyPointTrace {
                z_skip: zc_claim_e.z.clone(),
                x_inner_rest: zc_claim_e.mlv_challenges[..inner_rest_len].to_vec(),
                x_outer: zc_claim_e.mlv_challenges[inner_rest_len..].to_vec(),
            };
            let first_wire = b.num_wires();
            let lc_e = LincheckProofTrace::alloc(&mut b, &lc_proof, r1cs.k_log, r1cs.k_skip);
            let _ = lincheck_verify_trace(
                &mut b,
                &mut ch,
                &r1cs,
                m,
                &x_ab_e,
                &zc_claim_e.a_eval,
                &zc_claim_e.b_eval,
                &lc_e,
            );
            let (out_r1cs, mut out_z) = b.build();
            assert!(out_r1cs.satisfies(&out_z));
            out_z[first_wire + target] += F128::ONE;
            if out_r1cs.satisfies(&out_z) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "lincheck mutation survivors: {survivors:?}"
        );
    }

    /// Native commit + quirky-direct batched open over a random element
    /// witness, for the PCS lockstep/mutation gates.
    fn pcs_fixture(
        l_log: usize,
        lb: usize,
        lir: usize,
        k_skip: usize,
        seed: u128,
    ) -> (
        PcsParams,
        pcs::Commitment,
        Vec<pcs::QuirkyDirectClaim>,
        pcs::BaseFoldProof,
    ) {
        use noid_ivc_core::lincheck::build_eq_table;
        use noid_ivc_core::zerocheck::multilinear::lagrange_weights_naive;

        let params = PcsParams {
            m: l_log + LOG_PACKING,
            log_inv_rate: lir,
            log_batch_size: lb,
            profile: Default::default(),
        };
        let mut rng = Rng(seed);
        let witness: Vec<F128> = (0..1usize << l_log).map(|_| rng.next_f128()).collect();
        let (commitment, prover_data) = pcs::commit(&witness, &params);

        // Two quirky claims at random points; values by direct evaluation.
        let quirky_eval = |z_skip: F128, x_rest: &[F128]| -> F128 {
            let ell = 1usize << k_skip;
            let weights = lagrange_weights_naive(k_skip, z_skip);
            let eq = build_eq_table(x_rest);
            let mut acc = F128::ZERO;
            for (i, &v) in witness.iter().enumerate() {
                acc += v * weights[i % ell] * eq[i / ell];
            }
            acc
        };
        let claims: Vec<pcs::QuirkyDirectClaim> = (0..2)
            .map(|_| {
                let z_skip = rng.next_f128();
                let x_rest: Vec<F128> = (0..l_log - k_skip).map(|_| rng.next_f128()).collect();
                let value = quirky_eval(z_skip, &x_rest);
                pcs::QuirkyDirectClaim {
                    z_skip,
                    k_skip,
                    x_rest,
                    value,
                }
            })
            .collect();

        let mut ch = FsLaneChallenger::new(b"self-verify-pcs-test");
        let proof = pcs::open_batch_quirky_direct(
            &witness,
            &prover_data,
            &commitment,
            &claims,
            &mut ch,
        );
        (params, commitment, claims, proof)
    }

    /// Build the trace replay of a quirky-direct opening; returns the built
    /// instance/witness plus the proof-wire range for the mutation gate.
    fn build_pcs_trace(
        params: &PcsParams,
        commitment: &pcs::Commitment,
        claims: &[pcs::QuirkyDirectClaim],
        proof: &pcs::BaseFoldProof,
    ) -> (FieldR1cs, Vec<F128>, std::ops::Range<usize>) {
        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"self-verify-pcs-test");

        let mutation_start = b.num_wires();
        let root = alloc_flat_digest(&mut b, &commitment.root);
        let claims_e: Vec<QuirkyDirectClaimTrace> = claims
            .iter()
            .map(|c| QuirkyDirectClaimTrace {
                z_skip: LinExpr::from_wire(b.alloc_f128(c.z_skip)),
                k_skip: c.k_skip,
                x_rest: c
                    .x_rest
                    .iter()
                    .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                    .collect(),
                value: LinExpr::from_wire(b.alloc_f128(c.value)),
            })
            .collect();
        let proof_e = BaseFoldProofTrace::alloc(&mut b, proof, params);
        let mutation_end = b.num_wires();

        verify_opening_batch_quirky_direct_trace(&mut b, &mut ch, &root, &claims_e, &proof_e, params);

        // Native/trace transcript lockstep after the full replay.
        let mut ch_native = FsLaneChallenger::new(b"self-verify-pcs-test");
        let refs: Vec<pcs::QuirkyDirectClaimRef> = claims
            .iter()
            .map(|c| pcs::QuirkyDirectClaimRef {
                z_skip: c.z_skip,
                k_skip: c.k_skip,
                x_rest: &c.x_rest,
                value: c.value,
            })
            .collect();
        pcs::verify_opening_batch_quirky_direct(commitment, &refs, proof, &mut ch_native)
            .expect("native accepts honest opening");
        let c_n = ch_native.sample_f128();
        let c_t = ch.sample_f128(&mut b);
        assert_eq!(c_t.eval(b.values()), c_n, "post-verify challenge diverged");

        let (r1cs, z) = b.build();
        (r1cs, z, mutation_start..mutation_end)
    }

    /// THE PCS lockstep gate: honest quirky-direct openings replay to a
    /// satisfiable trace, in transcript lockstep with the native verifier —
    /// covering a single-epoch shape and a multi-epoch (FRI commit) shape.
    #[test]
    fn pcs_replay_lockstep_matches_native() {
        for &(l_log, lb, lir, k_skip, seed) in
            &[(6usize, 2usize, 2usize, 4usize, 0xA1u128), (9, 2, 3, 6, 0xB2)]
        {
            let (params, commitment, claims, proof) = pcs_fixture(l_log, lb, lir, k_skip, seed);
            let (r1cs, z, _) = build_pcs_trace(&params, &commitment, &claims, &proof);
            assert!(r1cs.satisfies(&z), "l_log={l_log} lir={lir}");
        }
    }

    /// THE PCS mutation gate: flipping ANY wire of the allocated proof data
    /// (commitment root, claim points/values, every BaseFold proof field,
    /// every multi-proof sibling) leaves the trace unsatisfiable.
    #[test]
    fn pcs_replay_rejects_mutations() {
        let (params, commitment, claims, proof) = pcs_fixture(6, 2, 2, 4, 0xC3);
        let (r1cs, z, range) = build_pcs_trace(&params, &commitment, &claims, &proof);
        assert!(r1cs.satisfies(&z));

        let mut survivors = Vec::new();
        for target in range {
            let mut bad = z.clone();
            bad[target] += F128::ONE;
            if r1cs.satisfies(&bad) {
                survivors.push(target);
            }
        }
        assert!(survivors.is_empty(), "PCS mutation survivors: {survivors:?}");
    }

    /// Full prove_field pipeline over a synthetic satisfiable instance —
    /// the [R] gate fixture.
    fn field_proof_fixture(
        m: usize,
        lir: usize,
        seed: u64,
    ) -> (
        FieldR1cs,
        PcsParams,
        pcs::Commitment,
        noid_ivc_core::proof::FieldR1csProof,
        noid_ivc_core::proof::R1csClaim,
    ) {
        use noid_ivc_core::field_r1cs::synthetic_satisfiable;
        use noid_ivc_prover::field_prover::prove_field;

        let (r1cs, z) = synthetic_satisfiable(m, m, seed);
        let params = PcsParams {
            m: m + LOG_PACKING,
            log_inv_rate: lir,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch = FsLaneChallenger::new(b"self-verify-field-test");
        let (proof, commitment, claim) = prove_field(&r1cs, &z, &params, &mut ch);
        (r1cs, params, commitment, proof, claim)
    }

    /// Build the full [R] trace; returns instance/witness, the proof-wire
    /// mutation range, and the claim expressions' evaluations.
    #[allow(clippy::type_complexity)]
    fn build_field_verify_trace(
        r1cs: &FieldR1cs,
        params: &PcsParams,
        commitment: &pcs::Commitment,
        proof: &noid_ivc_core::proof::FieldR1csProof,
    ) -> (
        FieldR1cs,
        Vec<F128>,
        std::ops::Range<usize>,
        [(F128, F128); 2],
        usize,
    ) {
        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"self-verify-field-test");

        let mutation_start = b.num_wires();
        let root = alloc_flat_digest(&mut b, &commitment.root);
        let proof_e = FieldR1csProofTrace::alloc(&mut b, proof, r1cs, params);
        let mutation_end = b.num_wires();

        let claim = verify_field_trace(&mut b, &mut ch, r1cs, params, &root, &proof_e);
        let rows = b.num_wires();

        // Native lockstep reference.
        let mut ch_native = FsLaneChallenger::new(b"self-verify-field-test");
        noid_ivc_core::verifier::verify_field(r1cs, commitment, proof, &mut ch_native)
            .expect("native verify_field accepts honest proof");
        let c_n = ch_native.sample_f128();
        let c_t = ch.sample_f128(&mut b);
        assert_eq!(c_t.eval(b.values()), c_n, "post-verify challenge diverged");

        let claim_evals = [
            (claim.ab.value.eval(b.values()), claim.ab.z_skip.eval(b.values())),
            (claim.c.value.eval(b.values()), claim.c.z_skip.eval(b.values())),
        ];
        let (out_r1cs, out_z) = b.build();
        (out_r1cs, out_z, mutation_start..mutation_end, claim_evals, rows)
    }

    /// THE [R] lockstep gate: the full verify_field replay on an honest
    /// prove_field proof — claims match native, transcript in lockstep,
    /// trace satisfiable. Also reports the measured [R] row count for this
    /// shape (the production-shape measurement lives in bench_prover).
    #[test]
    fn verify_field_replay_lockstep_e2e() {
        let (r1cs, params, commitment, proof, native_claim) = field_proof_fixture(8, 2, 42);
        let (out_r1cs, out_z, _, claim_evals, rows) =
            build_field_verify_trace(&r1cs, &params, &commitment, &proof);

        assert_eq!(claim_evals[0].0, native_claim.ab.value, "ab value");
        assert_eq!(claim_evals[0].1, native_claim.ab.point.z_skip, "ab z_skip");
        assert_eq!(claim_evals[1].0, native_claim.c.value, "c value");
        assert_eq!(claim_evals[1].1, native_claim.c.point.z_skip, "c z_skip");

        eprintln!(
            "[self-verify] m={} lir={} → [R] rows = {}",
            r1cs.m, params.log_inv_rate, rows
        );
        assert!(out_r1cs.satisfies(&out_z), "honest [R] trace unsatisfiable");
    }

    /// THE [R] auto-mutator gate: flipping ANY allocated proof wire —
    /// commitment root, every zerocheck/lincheck/BaseFold proof field, every
    /// query leaf lane, every multi-proof sibling — leaves the trace
    /// unsatisfiable. 0 survivors.
    #[test]
    fn verify_field_replay_rejects_all_proof_mutations() {
        use rayon::prelude::*;

        let (r1cs, params, commitment, proof, _) = field_proof_fixture(7, 2, 43);
        let (out_r1cs, out_z, range, _, _) =
            build_field_verify_trace(&r1cs, &params, &commitment, &proof);
        assert!(out_r1cs.satisfies(&out_z));

        let survivors: Vec<usize> = range
            .into_par_iter()
            .filter(|&target| {
                let mut bad = out_z.clone();
                bad[target] += F128::ONE;
                out_r1cs.satisfies(&bad)
            })
            .collect();
        assert!(
            survivors.is_empty(),
            "[R] mutation survivors: {survivors:?}"
        );
    }

    /// `observe_flat_digest` keeps the trace channel in lockstep with the
    /// native challenger observing the same digest bytes — pins the
    /// digest-lane ↔ `fs_pack_bytes_lanes` compatibility claim.
    #[test]
    fn observe_flat_digest_lockstep() {
        let mut rng = Rng(0x0B5E);
        for _ in 0..8 {
            let d = rng.next_hash();
            let mut native = FsLaneChallenger::new(b"self-verify-test");
            let mut b = FieldR1csBuilder::new();
            let mut trace = FsChannelTrace::new(&mut b, b"self-verify-test");

            native.observe_bytes(&d);
            let de = alloc_flat_digest(&mut b, &d);
            observe_flat_digest(&mut b, &mut trace, &de);

            // Cross-check the lane packing itself.
            let packed = fs_pack_bytes_lanes(&d);
            assert_eq!(packed, flat_digest_lanes(&d).to_vec());

            let c = native.sample_f128();
            let e = trace.sample_f128(&mut b);
            assert_eq!(e.eval(b.values()), c, "post-observe challenge diverged");
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }
}
