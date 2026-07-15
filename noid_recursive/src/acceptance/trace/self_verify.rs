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
use noid_ivc_core::field_circuit::{f128_from_u128, f128_to_u128, FsChannelOps};
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::merkle::{self, Hash};
use noid_ivc_core::ntt::AdditiveNttF128;
use noid_ivc_core::pcs::{self, compute_fri_arities, default_fri_queries, PcsParams, LOG_PACKING};
use noid_ivc_core::public_io::POST_COMMIT_CLASS_BINDING_LABEL;
use noid_ivc_core::zerocheck::{self, K_SKIP};
use noid_poseidon2b::native::{capacity_iv_flat, DomainTag};

use super::{
    evaluate_slice_trace, mul, pin_eq, poseidon2b_permute, FieldR1csBuilder, LinExpr, F128,
};

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

/// Absorb a verifier-key digest with the native byte transcript encoding.
/// The digest travels as two data lanes pinned to exact constants in the
/// enclosing matrix, so the compiled schedule is independent of absolute
/// witness-slice addresses while the transcript value remains authenticated.
pub(crate) fn observe_pinned_digest<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    digest: &Hash,
) {
    let lanes = flat_digest_lanes(digest).map(|lane| {
        let wire = LinExpr::from_wire(b.alloc_f128(lane));
        pin_eq(b, &wire, &LinExpr::constant(lane));
        wire
    });
    channel.observe_lanes(b, 32, &lanes);
}

/// Keep verifier-derived claim coordinates out of a recorded transcript's
/// constant schedule. Constant coordinates are still fixed by matrix rows;
/// only their transcript representation becomes a data lane. Non-constant
/// coordinates already have a witness source and are reused unchanged.
fn pin_transcript_constant_coordinates(
    b: &mut FieldR1csBuilder,
    coordinates: &[LinExpr],
) -> Vec<LinExpr> {
    coordinates
        .iter()
        .map(|coordinate| {
            if !coordinate.is_const() {
                return coordinate.clone();
            }
            let value = coordinate.eval(b.values());
            let wire = LinExpr::from_wire(b.alloc_f128(value));
            pin_eq(b, &wire, coordinate);
            wire
        })
        .collect()
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

/// The `IVCPCSN_` node capacity IV in flat lanes — the ff-leg family IV of
/// the [R] PCS walk discharge ([`super::r_pcs_region`]).
pub(crate) fn pcs_node_iv_flat() -> [F128; 2] {
    tag_iv_flat_f128(MERKLE_NODE_TAG)
}

/// The length-bound `IVCPCSF_` leaf capacity IV in flat lanes for an
/// even `lanes`-lane leaf (the fixed no-pad sponge mode every [R] PCS
/// leaf uses).
pub(crate) fn pcs_leaf_iv_flat(lanes: usize) -> [F128; 2] {
    assert!(lanes > 0 && lanes % 2 == 0, "fixed-IV leaves are even-lane");
    let [hi, lo] = merkle::leaf_fixed_iv_flat(lanes * 16);
    [f128_from_u128(hi), f128_from_u128(lo)]
}

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
    [f128_from_u128(0x80u128), f128_from_u128(0x01u128 << 120)]
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
pub fn merkle_hash_leaf_lanes_trace(b: &mut FieldR1csBuilder, lanes: &[LinExpr]) -> FlatDigestExpr {
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
    let absorb_block =
        |b: &mut FieldR1csBuilder, state: &mut [LinExpr; 4], lane0: &LinExpr, lane1: &LinExpr| {
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
    ch: &mut impl FsChannelOps,
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
    ch: &mut impl FsChannelOps,
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

/// Twin of `proof::bind_statement_field_parts`: the verified instance's
/// digest enters as WIRES (the self-verification chain reads it from the
/// previous envelope's IO) instead of a baked constant; the PCS
/// parameters stay a class constant.
pub fn bind_statement_field_parts_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    statement_digest: &FlatDigestExpr,
    pcs_params: &PcsParams,
    root: &FlatDigestExpr,
) {
    ch.observe_label(b, b"history-field-r1cs");
    observe_flat_digest(b, ch, statement_digest);
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
pub fn lagrange_weights_window_trace(
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
    pub fn alloc(b: &mut FieldR1csBuilder, native: &zerocheck::ZerocheckProof, m: usize) -> Self {
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
    ch: &mut impl FsChannelOps,
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
        assert_eq!(
            native.z_partial.len(),
            1usize << k_skip,
            "z_partial off shape"
        );
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
    for (m, blocks) in [(&r1cs.a_0, &mut blocks_a), (&r1cs.b_0, &mut blocks_b)] {
        for r in 0..m.num_rows {
            for (c, kappa) in m.row(r) {
                let c = c as usize;
                blocks.entry((r >> k_skip, c >> k_skip)).or_default().push((
                    r & mask,
                    c & mask,
                    kappa,
                ));
            }
        }
    }

    // ---- Materialize the needed P[i][j] = λ_i · zp_j products.
    let mut p: BTreeMap<(usize, usize), LinExpr> = BTreeMap::new();
    for block in blocks_a.values().chain(blocks_b.values()) {
        for &(i, j, _) in block {
            p.entry((i, j)).or_insert_with_key(|_| LinExpr::zero());
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
    let mut all_keys: Vec<(usize, usize)> =
        blocks_a.keys().chain(blocks_b.keys()).copied().collect();
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
    ch: &mut impl FsChannelOps,
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
    assert_eq!(
        x_ab.x_inner_rest.len(),
        inner_rest_len,
        "x_inner_rest off shape"
    );
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

/// Twin of `lincheck::verify_deferred` — the matrix-free lincheck replay
/// of the self-verification chain. Transcript-identical to
/// [`lincheck_verify_trace`] (same absorbs and samples), but instead of
/// the baked-matrix bilinear final sum it returns the deferred claim
/// wires for the accumulator fold: the β const-pin term is peeled off
/// in-trace (one eq product over constant pin bits — no tensors), and no
/// λ/eq tensors are materialized at all.
#[allow(clippy::too_many_arguments)]
pub fn lincheck_verify_trace_deferred(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    k_log: usize,
    k_skip: usize,
    const_pin: Option<usize>,
    m: usize,
    x_ab: &QuirkyPointTrace,
    v_a: &LinExpr,
    v_b: &LinExpr,
    proof: &LincheckProofTrace,
) -> (
    LincheckClaimTrace,
    super::matrix_fold::FreshLincheckClaimTrace,
) {
    let ell = 1usize << k_skip;
    let inner_rest_len = k_log - k_skip;
    assert!(k_skip <= k_log, "k_skip exceeds k_log");
    assert_eq!(
        x_ab.x_inner_rest.len(),
        inner_rest_len,
        "x_inner_rest off shape"
    );
    assert_eq!(x_ab.x_outer.len(), m - k_log, "x_outer off shape");
    assert_eq!(proof.rounds.len(), inner_rest_len, "rounds off shape");
    assert_eq!(proof.z_partial.len(), ell, "z_partial off shape");

    ch.observe_label(b, b"history-lincheck-v0");

    let alpha = ch.sample_f128(b);

    let v_a_alpha = mul(b, &alpha, v_a);
    let mut target = v_a_alpha.add(v_b);
    let beta = if const_pin.is_some() {
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
        let e0 = running.add(e1);
        let c1 = e0.add(e1).add(einf);
        let r_sq = mul(b, &r, &r);
        running = mul(b, einf, &r_sq).add(&mul(b, &c1, &r)).add(&e0);
        r_rounds.push(r);
    }

    ch.observe_f128_slice(b, &proof.z_partial);

    let r_inner_rest: Vec<LinExpr> = r_rounds.iter().rev().cloned().collect();

    // Peel the matrix-independent β pin term: β·zp[pin mod 2^k_skip]·
    // eq(r_inner_rest, bits(pin div 2^k_skip)) — the eq against CONSTANT
    // bits is a product of affine factors.
    let mut fresh_value = running.clone();
    if let (Some(beta), Some(col)) = (beta, const_pin) {
        let mask = ell - 1;
        let one = LinExpr::constant(F128::ONE);
        let mut q_pin = LinExpr::constant(F128::ONE);
        for (i, r) in r_inner_rest.iter().enumerate() {
            let bit = (col >> k_skip >> i) & 1;
            let factor = if bit == 1 { r.clone() } else { one.add(r) };
            q_pin = mul(b, &q_pin, &factor);
        }
        let t = mul(b, &beta, &proof.z_partial[col & mask]);
        fresh_value = fresh_value.add(&mul(b, &t, &q_pin));
    }
    let fresh = super::matrix_fold::FreshLincheckClaimTrace {
        alpha,
        z_skip: x_ab.z_skip.clone(),
        x_inner_rest: x_ab.x_inner_rest.clone(),
        r_inner_rest: r_inner_rest.clone(),
        z_partial: proof.z_partial.clone(),
        value: fresh_value,
    };

    let r_inner_skip = ch.sample_f128(b);
    let lambda_out = lagrange_weights_window_trace(b, &r_inner_skip, 0, ell, 0);
    let w = dot_trace(b, &lambda_out, &proof.z_partial);

    (
        LincheckClaimTrace {
            r_inner_skip,
            r_inner_rest,
            w,
        },
        fresh,
    )
}

// ---------------------------------------------------------------------------
// BaseFold PCS verify replay
// ---------------------------------------------------------------------------

/// Witness allocation of one `basefold::QueryOpening`. The query replay is
/// fully shape-fixed: Merkle directions, coset offsets, twiddles and the
/// tail slot are all driven by the transcript-bound position bits (witness
/// booleans pinned to the squeezed lanes in [`basefold_verify_trace`]);
/// the hashing schedule is query count × fixed tree depths. `position` is
/// kept only as builder-input data — bool witness values and the
/// build-time desync assert; it shapes nothing. (The wallet-capsule
/// `gen_compact_queries_trace` still carries the old interim caveat.)
pub struct QueryOpeningTrace {
    pub position: usize,
    pub initial_leaf: Vec<LinExpr>,
    pub initial_path: Vec<FlatDigestExpr>,
    pub post_row_batch_leaf: Vec<LinExpr>,
    pub post_row_batch_path: Vec<FlatDigestExpr>,
    pub epoch_leaves: Vec<Vec<LinExpr>>,
    pub epoch_paths: Vec<Vec<FlatDigestExpr>>,
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
}

impl BaseFoldProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &pcs::BaseFoldProof,
        params: &PcsParams,
    ) -> Self {
        Self::alloc_mode(b, native, params, true)
    }

    /// [`Self::alloc`] with the path allocation switchable: the walk-
    /// discharge mode ([`PcsWalkObligations`]) never materializes sibling
    /// digests as wires — they live only as walk-B column data — so the
    /// query path vectors stay empty. Shape asserts on the NATIVE proof
    /// run in both modes.
    pub fn alloc_mode(
        b: &mut FieldR1csBuilder,
        native: &pcs::BaseFoldProof,
        params: &PcsParams,
        alloc_paths: bool,
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
            default_fri_queries(params.log_dim(), params.log_inv_rate),
            "query count off shape"
        );
        assert_eq!(
            native.final_codeword.len(),
            1usize << params.log_inv_rate,
            "final codeword off shape"
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
        let pow_nonce = LinExpr::from_wire(b.alloc_f128(f128_from_u128(native.pow_nonce as u128)));

        let queries = native
            .queries
            .iter()
            .map(|q| {
                assert!(q.position < (1usize << k_code), "query position off shape");
                assert_eq!(q.initial_leaf.len(), num_ntts, "initial leaf off shape");
                assert_eq!(q.initial_path.len(), k_code, "initial path off shape");
                if arities.is_empty() {
                    assert!(q.post_row_batch_leaf.is_empty(), "post-rb leaf off shape");
                    assert!(q.post_row_batch_path.is_empty(), "post-rb path off shape");
                } else {
                    assert_eq!(
                        q.post_row_batch_leaf.len(),
                        1usize << arity_0,
                        "post-rb leaf off shape"
                    );
                    assert_eq!(
                        q.post_row_batch_path.len(),
                        k_code - arity_0,
                        "post-rb path off shape"
                    );
                }
                assert_eq!(
                    q.epoch_leaves.len(),
                    num_fri_commits,
                    "epoch leaves off shape"
                );
                assert_eq!(
                    q.epoch_paths.len(),
                    num_fri_commits,
                    "epoch paths off shape"
                );
                let mut cum = arity_0;
                for (i, (leaf, path)) in q.epoch_leaves.iter().zip(&q.epoch_paths).enumerate() {
                    assert_eq!(leaf.len(), 1usize << arities[i + 1], "epoch leaf off shape");
                    assert_eq!(
                        path.len(),
                        k_code - cum - arities[i + 1],
                        "epoch path off shape"
                    );
                    cum += arities[i + 1];
                }
                QueryOpeningTrace {
                    position: q.position,
                    initial_leaf: alloc_vec(b, &q.initial_leaf),
                    initial_path: if alloc_paths {
                        alloc_digests(b, &q.initial_path)
                    } else {
                        Vec::new()
                    },
                    post_row_batch_leaf: alloc_vec(b, &q.post_row_batch_leaf),
                    post_row_batch_path: if alloc_paths {
                        alloc_digests(b, &q.post_row_batch_path)
                    } else {
                        Vec::new()
                    },
                    epoch_leaves: q.epoch_leaves.iter().map(|l| alloc_vec(b, l)).collect(),
                    epoch_paths: if alloc_paths {
                        q.epoch_paths.iter().map(|p| alloc_digests(b, p)).collect()
                    } else {
                        q.epoch_paths.iter().map(|_| Vec::new()).collect()
                    },
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
/// the native rule reads flat bits).
///
/// EVERY lane bit is a witness boolean; the used windows' bits are returned
/// per query, LSB-first, and drive the Merkle direction muxes, the coset
/// offset selections and the affine twiddles downstream — the query-loop
/// trace structure no longer depends on the sampled positions. The native
/// window value rides along for build-time desync asserts only.
fn bind_query_positions_lane_trace(
    b: &mut FieldR1csBuilder,
    lane: &LinExpr,
    k_code: usize,
    n_used: usize,
) -> (Vec<(usize, Vec<LinExpr>)>, std::ops::Range<usize>) {
    let per_lane = 128 / k_code;
    assert!(n_used >= 1 && n_used <= per_lane, "window count off shape");
    let raw = expr_flat_u128(b, lane);
    let mask = (1u128 << k_code) - 1;
    let mut sum = LinExpr::zero();
    let mut out = Vec::with_capacity(n_used);
    let bits_start = b.num_wires();
    for w in 0..n_used {
        let base = w * k_code;
        let pos = ((raw >> base) & mask) as usize;
        let mut bits = Vec::with_capacity(k_code);
        for i in 0..k_code {
            let bit = b.alloc_bool((raw >> (base + i)) & 1 == 1);
            let e = LinExpr::from_wire(bit);
            sum = sum.add(&e.scale(f128_from_u128(1u128 << (base + i))));
            bits.push(e);
        }
        out.push((pos, bits));
    }
    for j in (n_used * k_code)..128 {
        let bit = b.alloc_bool((raw >> j) & 1 == 1);
        sum = sum.add(&LinExpr::from_wire(bit).scale(f128_from_u128(1u128 << j)));
    }
    // The gated range covers exactly the bit wires; the pin below
    // materializes a helper wire whose row constrains the SUM, and a dead
    // helper wire legitimately survives a flip.
    let bits_range = bits_start..b.num_wires();
    super::pin_zero(b, &sum.add(lane));
    (out, bits_range)
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
/// multiplication per pair. Used where the coset index is structural (the
/// once-per-proof plaintext-tail fold, indexed by final-layer slot).
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

/// Per-query variant of [`fri_fold_coset_trace`]: the coset index is given
/// as transcript-bound witness bits (LSB-first), so the trace structure is
/// independent of the sampled position. The additive-NTT twiddle is
/// F_2-linear in the position bits —
/// `twiddle(l, b) = Σ_j bit_j(b)·Ŵ(β_j)` — so the twiddle at
/// `pos = coset_idx·n + j` is an affine expression in the coset bits
/// (constants from `ntt.twiddle` at single-bit blocks) and the fold costs
/// two multiplications per pair (`v·t` and the challenge product).
fn fri_fold_coset_bits_trace(
    b: &mut FieldR1csBuilder,
    coset: &[LinExpr],
    challenges: &[LinExpr],
    ntt: &AdditiveNttF128,
    input_layer: usize,
    coset_idx_bits: &[LinExpr],
) -> LinExpr {
    assert_eq!(coset.len(), 1usize << challenges.len());
    let mut buf = coset.to_vec();
    for (k, r) in challenges.iter().enumerate() {
        let post_fold_layer = input_layer - k - 1;
        let n = buf.len() / 2;
        let log_n = n.trailing_zeros() as usize;
        // Affine twiddle basis for this layer: the structural intra-coset
        // part contributes constants; each coset bit contributes
        // twiddle(layer, 2^(log_n + i)).
        let bit_coeffs: Vec<F128> = (0..coset_idx_bits.len())
            .map(|i| ntt.twiddle(post_fold_layer, 1usize << (log_n + i)))
            .collect();
        let mut next = Vec::with_capacity(n);
        for j in 0..n {
            let u_in = &buf[2 * j];
            let v_in = &buf[2 * j + 1];
            let mut twiddle = LinExpr::constant(ntt.twiddle(post_fold_layer, j));
            for (bit, &coeff) in coset_idx_bits.iter().zip(&bit_coeffs) {
                twiddle = twiddle.add(&bit.scale(coeff));
            }
            let v = v_in.add(u_in);
            let u = u_in.add(&mul(b, &v, &twiddle));
            next.push(u.add(&mul(b, r, &u.add(&v))));
        }
        buf = next;
    }
    buf.pop().unwrap()
}

/// Trace twin of `merkle::verify_merkle_proof`: fold the leaf hash up its
/// own full-depth path and pin the reconstructed root. Fully shape-fixed:
/// the hashing schedule is `path.len()` compressions, and the per-level
/// left/right order is a mux on the transcript-bound position bit
/// (`dir_bits[d]` = bit `d` of the leaf index; bit = 1 → our node is the
/// RIGHT child). Two multiplications per level (one shared mux product per
/// digest lane).
fn verify_merkle_path_trace(
    b: &mut FieldR1csBuilder,
    root: &FlatDigestExpr,
    leaf_hash: &FlatDigestExpr,
    dir_bits: &[LinExpr],
    path: &[FlatDigestExpr],
) {
    assert_eq!(dir_bits.len(), path.len(), "direction bits off shape");
    let mut acc = leaf_hash.clone();
    for (bit, sibling) in dir_bits.iter().zip(path) {
        let mut left = [LinExpr::zero(), LinExpr::zero()];
        let mut right = [LinExpr::zero(), LinExpr::zero()];
        for lane in 0..2 {
            let t = mul(b, bit, &acc[lane].add(&sibling[lane]));
            left[lane] = acc[lane].add(&t);
            right[lane] = sibling[lane].add(&t);
        }
        acc = merkle_hash_pair_trace(b, &left, &right);
    }
    pin_flat_digest_eq(b, &acc, root);
}

/// One [R] PCS leaf-hash obligation for the walk discharge: the absorbed
/// lanes (proof wires — the fold algebra consumes the same wires, so the
/// walk-A tile's absorb-cell pins bind the hashing to the folded values).
/// Lane counts are even (the fixed-IV no-pad leaf mode), so a tile is a
/// pure rate-2 absorb chain with the length-bound `IVCPCSF_` capacity IV.
pub struct PcsLeafObligation {
    pub lanes: Vec<LinExpr>,
}

/// One [R] PCS Merkle-path obligation: an `IVCPCSN_` feed-forward node
/// chain from the digest of leaf obligation `leaf` up to `root`. Sibling
/// digests are PURE WITNESS — they exist only as walk-B column data (any
/// values satisfying the chain to the pinned root), so the obligation
/// carries none; the assembly reads them from the native proof in the
/// same deterministic order.
pub struct PcsPathObligation {
    /// Index into the leaf obligation list — the entry digest tile.
    pub leaf: usize,
    /// Transcript-bound position bits, LSB-first, one per level (bit = 1
    /// ⇒ our node is the RIGHT child).
    pub dir_bits: Vec<LinExpr>,
    /// The FS-observed root wires the recomputed root pins to (absorbed
    /// before the query draw — the capsule's authentication-root rule).
    pub root: FlatDigestExpr,
}

/// Collected [R] PCS hashing obligations (region mode): the twin skips
/// every inline leaf sponge and path replay — 94% of the per-query rows —
/// and records the data instead; the link's walk assembly hosts them
/// (leaf tiles on walk A, ff legs on walk B). Push order is the
/// deterministic per-query order (initial, post-row-batch, epochs), which
/// the assembly's native column builder mirrors over the native proof.
#[derive(Default)]
pub struct PcsWalkObligations {
    pub leaves: Vec<PcsLeafObligation>,
    pub paths: Vec<PcsPathObligation>,
}

impl PcsWalkObligations {
    fn push(&mut self, lanes: &[LinExpr], dir_bits: &[LinExpr], root: &FlatDigestExpr) {
        assert!(
            !lanes.is_empty() && lanes.len() % 2 == 0,
            "PCS leaf obligations are even-lane (fixed-IV no-pad mode)"
        );
        let leaf = self.leaves.len();
        self.leaves.push(PcsLeafObligation {
            lanes: lanes.to_vec(),
        });
        self.paths.push(PcsPathObligation {
            leaf,
            dir_bits: dir_bits.to_vec(),
            root: root.clone(),
        });
    }
}

/// Trace twin of `basefold::verify`. Replays the sumcheck/commit transcript
/// on the lane channel, binds resampled query positions, replays every
/// query's leaf hashing / row-batch fold / FRI coset folds / final-codeword
/// check, and verifies every query's independent Merkle paths with
/// witness-bit direction muxes. Native value rejections → pins; shape
/// rejections were alloc asserts. Returns the sumcheck challenges plus the
/// wire ranges of the transcript-bound position bits (for the mutation
/// gate: those bits are verifier-internal witness, not proof wires).
///
/// `region = Some(out)` is the WALK-DISCHARGE mode: every leaf sponge and
/// Merkle path is recorded as an obligation instead of replayed inline
/// (the proof trace must then be allocated path-free); the fold algebra,
/// offset cross-checks and tail checks stay inline. Soundness moves to
/// the caller: an obligation is discharged only when its tile/leg rides a
/// walk whose opening claims the class threads through public IO.
pub fn basefold_verify_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    target: &LinExpr,
    proof: &BaseFoldProofTrace,
    initial_codeword_root: &FlatDigestExpr,
    params: &PcsParams,
    mut region: Option<&mut PcsWalkObligations>,
) -> (Vec<LinExpr>, Vec<std::ops::Range<usize>>) {
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
    let mut ledger = b.num_wires();

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

    crate::acceptance::row_ledger_mark(b, &mut ledger, "R-pcs: sumcheck rounds");

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
    // squeeze. Every position bit becomes a transcript-bound witness
    // boolean; the whole per-query replay below is driven by those bits,
    // so its structure is a pure function of the shape.
    ch.verify_pow(b, &proof.pow_nonce, pcs::QUERY_GRIND_BITS);
    let n_queries = proof.queries.len();
    let per_lane = 128 / k_code;
    let lanes = ch.sample_f128_vec(b, n_queries.div_ceil(per_lane));
    let mut query_bits: Vec<Vec<LinExpr>> = Vec::with_capacity(n_queries);
    let mut bit_ranges: Vec<std::ops::Range<usize>> = Vec::with_capacity(lanes.len());
    for lane in &lanes {
        let used = per_lane.min(n_queries - query_bits.len());
        let (bound, range) = bind_query_positions_lane_trace(b, lane, k_code, used);
        bit_ranges.push(range);
        for (position, bits) in bound {
            // Build-time sanity: the proof's query must carry the
            // transcript-derived position (native `q.position !=
            // positions[qi]` reject); soundness is the lane pin.
            assert_eq!(
                proof.queries[query_bits.len()].position,
                position,
                "query position desynced from transcript"
            );
            query_bits.push(bits);
        }
    }
    assert_eq!(query_bits.len(), n_queries, "query positions off shape");
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R-pcs: grind + query sample");

    // ---- Per-query fold replay + per-query independent Merkle paths.
    for (q, bits) in proof.queries.iter().zip(&query_bits) {
        if let Some(obs) = region.as_deref_mut() {
            assert!(
                q.initial_path.is_empty(),
                "region mode expects path-free alloc"
            );
            obs.push(&q.initial_leaf, bits, initial_codeword_root);
        } else {
            let initial_leaf_hash = merkle_hash_leaf_lanes_trace(b, &q.initial_leaf);
            verify_merkle_path_trace(
                b,
                initial_codeword_root,
                &initial_leaf_hash,
                bits,
                &q.initial_path,
            );
        }

        // Row-batch fold T1's lanes to one post-row-batch value.
        let post_row_batch_value =
            row_batch_fold_one_trace(b, &q.initial_leaf, &challenges[..log_batch_size]);

        let fri_challenge_start = log_batch_size;
        let mut cum_arity = arity_0;
        let mut expected;
        if arities.is_empty() {
            expected = post_row_batch_value;
        } else {
            if let Some(obs) = region.as_deref_mut() {
                assert!(
                    q.post_row_batch_path.is_empty(),
                    "region mode expects path-free alloc"
                );
                obs.push(
                    &q.post_row_batch_leaf,
                    &bits[arity_0..],
                    &proof.post_row_batch_commit,
                );
            } else {
                let post_leaf_hash = merkle_hash_leaf_lanes_trace(b, &q.post_row_batch_leaf);
                verify_merkle_path_trace(
                    b,
                    &proof.post_row_batch_commit,
                    &post_leaf_hash,
                    &bits[arity_0..],
                    &q.post_row_batch_path,
                );
            }

            // Cross-check T2 against the row-batch fold: select the leaf
            // slot by the offset bits (eq-tensor dot; value check → pin).
            let at_offset = evaluate_slice_trace(b, &q.post_row_batch_leaf, &bits[..arity_0]);
            pin_eq(b, &at_offset, &post_row_batch_value);

            expected = fri_fold_coset_bits_trace(
                b,
                &q.post_row_batch_leaf,
                &challenges[fri_challenge_start..fri_challenge_start + arity_0],
                &ntt,
                k_code,
                &bits[arity_0..],
            );
        }

        for i in 0..num_fri_commits {
            let leaf = &q.epoch_leaves[i];
            let next_arity = arities[i + 1];

            if let Some(obs) = region.as_deref_mut() {
                assert!(
                    q.epoch_paths[i].is_empty(),
                    "region mode expects path-free alloc"
                );
                obs.push(
                    leaf,
                    &bits[cum_arity + next_arity..],
                    &proof.round_commitments[i],
                );
            } else {
                let epoch_leaf_hash = merkle_hash_leaf_lanes_trace(b, leaf);
                verify_merkle_path_trace(
                    b,
                    &proof.round_commitments[i],
                    &epoch_leaf_hash,
                    &bits[cum_arity + next_arity..],
                    &q.epoch_paths[i],
                );
            }

            let at_offset = evaluate_slice_trace(b, leaf, &bits[cum_arity..cum_arity + next_arity]);
            pin_eq(b, &at_offset, &expected);

            let input_layer = k_code - cum_arity;
            expected = fri_fold_coset_bits_trace(
                b,
                leaf,
                &challenges
                    [fri_challenge_start + cum_arity..fri_challenge_start + cum_arity + next_arity],
                &ntt,
                input_layer,
                &bits[cum_arity + next_arity..],
            );
            cum_arity += next_arity;
        }

        // Final per-query check: select the tail slot by the remaining
        // position bits when a tail exists (the tail folds to the final
        // codeword once, below); else pin against the final codeword,
        // whose constancy is already pinned — any slot equals slot 0.
        if let Some((_, tail_cum)) = tail_layout {
            assert_eq!(cum_arity, tail_cum, "tail layer offset off shape");
            let at_tail = evaluate_slice_trace(b, &proof.plaintext_tail, &bits[cum_arity..]);
            pin_eq(b, &at_tail, &expected);
        } else {
            pin_eq(b, &proof.final_codeword[0], &expected);
        }
    }

    crate::acceptance::row_ledger_mark(b, &mut ledger, "R-pcs: per-query folds+paths");

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

    crate::acceptance::row_ledger_mark(b, &mut ledger, "R-pcs: plaintext tail");

    (challenges, bit_ranges)
}

// ---------------------------------------------------------------------------
// Quirky-direct batched opening verify replay
// ---------------------------------------------------------------------------

/// A `pcs::QuirkyDirectClaim` as expressions (the claim point comes from
/// replayed sub-protocol challenges; only the value is fresh proof data).
#[derive(Clone)]
pub struct QuirkyDirectClaimTrace {
    pub z_skip: LinExpr,
    pub k_skip: usize,
    pub x_rest: Vec<LinExpr>,
    pub value: LinExpr,
}

/// The canonical dead-variant anchor claim: the committed IO slice evaluated
/// at the all-zero window point, which is exactly `io[0]` (the slice start
/// has zero low index bits).  True for every honestly bound envelope, so
/// banked verifier compositions can pad their claim stream with claims whose
/// native lane values never depend on the disabled variant.
pub fn io_anchor_claim(
    spec: &noid_ivc_core::public_io::PublicIoSpec,
    io0: F128,
    total_vars: usize,
) -> pcs::QuirkyDirectClaim {
    let mut x_rest = vec![F128::ZERO; spec.io_slice.log2_len];
    x_rest.extend(spec.io_slice.prefix_coords(total_vars));
    pcs::QuirkyDirectClaim {
        z_skip: F128::ZERO,
        k_skip: 0,
        x_rest,
        value: io0,
    }
}

/// Opaque recursive-trace capability for a causally post-commit auxiliary
/// verifier. It delegates the exact enclosing FS channel and owns the claim
/// sink appended to that proof's shared PCS replay.
pub struct FieldPostCommitTraceContext<'a, C> {
    commitment_root: &'a FlatDigestExpr,
    total_vars: usize,
    channel: &'a mut C,
    claims: Vec<QuirkyDirectClaimTrace>,
}

impl<'a, C> FieldPostCommitTraceContext<'a, C> {
    fn new(commitment_root: &'a FlatDigestExpr, total_vars: usize, channel: &'a mut C) -> Self {
        Self {
            commitment_root,
            total_vars,
            channel,
            claims: Vec::new(),
        }
    }

    fn finish(self) -> Vec<QuirkyDirectClaimTrace> {
        self.claims
    }

    pub fn commitment_root(&self) -> &'a FlatDigestExpr {
        self.commitment_root
    }

    pub fn total_vars(&self) -> usize {
        self.total_vars
    }

    pub fn append_claim(&mut self, claim: QuirkyDirectClaimTrace) {
        self.claims.push(claim);
    }

    pub fn append_claims(&mut self, claims: impl IntoIterator<Item = QuirkyDirectClaimTrace>) {
        self.claims.extend(claims);
    }

    pub fn claim_count(&self) -> usize {
        self.claims.len()
    }

    /// Open a CHILD post-commit context over a different channel (the
    /// union-recorder discipline): same verified proof, same claim authority,
    /// but every transcript op lands on `channel` instead of the enclosing
    /// inline sponge.  The caller must drain the child's claims back into
    /// this context with [`Self::adopt_child_claims`] — the child cannot
    /// discharge openings on its own.
    pub(crate) fn child<'c, C2>(&self, channel: &'c mut C2) -> FieldPostCommitTraceContext<'c, C2>
    where
        'a: 'c,
    {
        FieldPostCommitTraceContext::new(self.commitment_root, self.total_vars, channel)
    }

    /// Detached context for SCRATCH replays (schedule derivation, recording
    /// prefill).  Nothing built through it enters a real proof: the claims
    /// are dropped by the caller and the commitment root is never read by
    /// the recorded child protocols.
    pub(crate) fn detached(
        commitment_root: &'a FlatDigestExpr,
        total_vars: usize,
        channel: &'a mut C,
    ) -> Self {
        Self::new(commitment_root, total_vars, channel)
    }

    /// Drain a banked variant's child claims into this sink while keeping the
    /// batch shape independent of which variant is live.  Every child claim
    /// gets a freshly allocated wire mirror of its own constant/wire
    /// coordinate pattern (so both arms cost identical wires and rows): the
    /// live arm adopts the real claims and discards the mirrors, the dead arm
    /// adopts the mirrors — witnessed to the caller's anchor claim, whose
    /// truth the shared batched opening then enforces — and discards the
    /// unprovable walk claims.
    pub(crate) fn adopt_child_claims_banked<C2>(
        &mut self,
        b: &mut FieldR1csBuilder,
        child: FieldPostCommitTraceContext<'_, C2>,
        anchor: &pcs::QuirkyDirectClaim,
        live: bool,
    ) {
        let claims = child.finish();
        for claim in claims {
            debug_assert_eq!(claim.k_skip, anchor.k_skip, "banked claim skip window");
            debug_assert_eq!(
                claim.x_rest.len(),
                anchor.x_rest.len(),
                "banked claim point arity"
            );
            let x_rest = claim
                .x_rest
                .iter()
                .zip(anchor.x_rest.iter())
                .map(|(coordinate, &value)| {
                    if coordinate.is_const() {
                        LinExpr::constant(value)
                    } else {
                        LinExpr::from_wire(b.alloc_f128(value))
                    }
                })
                .collect();
            let mirror = QuirkyDirectClaimTrace {
                z_skip: LinExpr::constant(anchor.z_skip),
                k_skip: anchor.k_skip,
                x_rest,
                value: LinExpr::from_wire(b.alloc_f128(anchor.value)),
            };
            self.claims.push(if live { claim } else { mirror });
        }
    }
}

impl<C: FsChannelOps> FsChannelOps for FieldPostCommitTraceContext<'_, C> {
    fn observe_label(&mut self, b: &mut FieldR1csBuilder, label: &[u8]) {
        self.channel.observe_label(b, label);
    }

    fn observe_f128(&mut self, b: &mut FieldR1csBuilder, value: &LinExpr) {
        self.channel.observe_f128(b, value);
    }

    fn observe_f128_slice(&mut self, b: &mut FieldR1csBuilder, values: &[LinExpr]) {
        self.channel.observe_f128_slice(b, values);
    }

    fn sample_f128(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        self.channel.sample_f128(b)
    }

    fn sample_f128_vec(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        self.channel.sample_f128_vec(b, n)
    }

    fn verify_pow(&mut self, b: &mut FieldR1csBuilder, nonce: &LinExpr, bits: u32) {
        self.channel.verify_pow(b, nonce, bits);
    }

    fn observe_bytes_const(&mut self, b: &mut FieldR1csBuilder, bytes: &[u8]) {
        self.channel.observe_bytes_const(b, bytes);
    }

    fn observe_lanes(&mut self, b: &mut FieldR1csBuilder, byte_len: u64, lanes: &[LinExpr]) {
        self.channel.observe_lanes(b, byte_len, lanes);
    }
}

/// Trace twin of `pcs::verify_opening_batch_quirky_direct`: mirror
/// transcript (labels, per-claim value observes, γ batching), the shared
/// BaseFold replay, then the quirky `final_b` factorization
/// `(Σ_i eq(challenges[..k_skip], i)·L_i(z_skip)) · eq(x_rest, challenges[k_skip..])`
/// pinned against the proof's `final_b`.
pub fn verify_opening_batch_quirky_direct_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    commitment_root: &FlatDigestExpr,
    claims: &[QuirkyDirectClaimTrace],
    proof: &BaseFoldProofTrace,
    params: &PcsParams,
) -> Vec<std::ops::Range<usize>> {
    verify_opening_batch_quirky_direct_trace_region(
        b,
        ch,
        commitment_root,
        claims,
        proof,
        params,
        None,
    )
}

/// [`verify_opening_batch_quirky_direct_trace`] with the walk-discharge
/// mode switch (see [`basefold_verify_trace`]).
#[allow(clippy::too_many_arguments)]
pub fn verify_opening_batch_quirky_direct_trace_region(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    commitment_root: &FlatDigestExpr,
    claims: &[QuirkyDirectClaimTrace],
    proof: &BaseFoldProofTrace,
    params: &PcsParams,
    region: Option<&mut PcsWalkObligations>,
) -> Vec<std::ops::Range<usize>> {
    assert!(!claims.is_empty(), "need at least one claim");
    let l_log = params.m - LOG_PACKING;
    for c in claims {
        assert_eq!(c.x_rest.len() + c.k_skip, l_log, "claim point off shape");
    }

    ch.observe_label(b, b"history-pcs-open-field-v1");
    for c in claims {
        ch.observe_label(b, b"history-pcs-quirky-direct-v1");
        ch.observe_f128(b, &c.z_skip);
        ch.observe_f128(b, &LinExpr::constant(F128::new(c.k_skip as u64, 0)));
        let transcript_x_rest = pin_transcript_constant_coordinates(b, &c.x_rest);
        ch.observe_f128_slice(b, &transcript_x_rest);
        ch.observe_f128(b, &c.value);
    }
    let gammas: Vec<LinExpr> = (0..claims.len()).map(|_| ch.sample_f128(b)).collect();

    let mut target_combined = LinExpr::zero();
    for (c, g) in claims.iter().zip(gammas.iter()) {
        target_combined = target_combined.add(&mul(b, g, &c.value));
    }

    let (challenges, query_bit_ranges) = basefold_verify_trace(
        b,
        ch,
        &target_combined,
        proof,
        commitment_root,
        params,
        region,
    );
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
    query_bit_ranges
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
        Self::alloc_shape(
            b,
            native,
            &noid_ivc_core::proof::FieldShape::of(r1cs),
            pcs_params,
        )
    }

    /// [`Self::alloc`] from the class shape alone (the self-verification
    /// chain has no materialized instance of the verified class).
    pub fn alloc_shape(
        b: &mut FieldR1csBuilder,
        native: &noid_ivc_core::proof::FieldR1csProof,
        shape: &noid_ivc_core::proof::FieldShape,
        pcs_params: &PcsParams,
    ) -> Self {
        Self::alloc_shape_mode(b, native, shape, pcs_params, true)
    }

    /// [`Self::alloc_shape`] with the path allocation switchable — the
    /// walk-discharge [R] mode allocates the proof PATH-FREE (see
    /// [`BaseFoldProofTrace::alloc_mode`]).
    pub fn alloc_shape_mode(
        b: &mut FieldR1csBuilder,
        native: &noid_ivc_core::proof::FieldR1csProof,
        shape: &noid_ivc_core::proof::FieldShape,
        pcs_params: &PcsParams,
        alloc_paths: bool,
    ) -> Self {
        Self {
            zerocheck: ZerocheckProofTrace::alloc(b, &native.zerocheck, shape.m),
            lincheck: LincheckProofTrace::alloc(b, &native.lincheck, shape.k_log, shape.k_skip),
            pcs_open: BaseFoldProofTrace::alloc_mode(b, &native.pcs_open, pcs_params, alloc_paths),
        }
    }
}

/// Trace twin of `public_io::bind_public_io`: absorb the spec constants and
/// the envelope-lane wires, sample the binding point, and derive the claim
/// list appended to the batched opening. The spec is a protocol constant of
/// the verified instance; the envelope lanes are witness wires (the caller
/// pins them to whatever carries the verified proof's public values).
pub fn bind_public_io_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    spec: &noid_ivc_core::public_io::PublicIoSpec,
    io: &[LinExpr],
    total_vars: usize,
) -> Vec<QuirkyDirectClaimTrace> {
    spec.validate(total_vars);
    assert_eq!(io.len(), spec.io_len, "envelope length must match the spec");

    ch.observe_label(b, b"history-public-io-v0");
    let spec_lanes: Vec<LinExpr> = spec
        .transcript_lanes()
        .iter()
        .map(|v| LinExpr::constant(*v))
        .collect();
    ch.observe_f128_slice(b, &spec_lanes);
    ch.observe_f128_slice(b, io);
    let y = ch.sample_f128_vec(b, spec.io_slice.log2_len);

    let eq = super::eq_ind_partial_eval_trace(b, &y);
    let io_value = dot_trace(b, &eq[..io.len()], io);
    let prefix = |slice: &noid_ivc_core::public_io::WitnessSlice| -> Vec<LinExpr> {
        slice
            .prefix_coords(total_vars)
            .into_iter()
            .map(LinExpr::constant)
            .collect()
    };
    let mut x_rest = y;
    x_rest.extend(prefix(&spec.io_slice));
    let mut claims = vec![QuirkyDirectClaimTrace {
        z_skip: LinExpr::zero(),
        k_skip: 0,
        x_rest,
        value: io_value,
    }];

    for c in &spec.claims {
        let mut x_rest: Vec<LinExpr> = io[c.point.clone()].to_vec();
        x_rest.extend(prefix(&c.slice));
        claims.push(QuirkyDirectClaimTrace {
            z_skip: LinExpr::zero(),
            k_skip: 0,
            x_rest,
            value: io[c.value].clone(),
        });
    }
    claims
}

/// Trace twin of `verifier::verify_field` — the [R] slot body. The verified
/// instance and its PCS parameters are protocol constants; the commitment
/// root and every proof field are witness. Statement binding → field
/// zerocheck → shared lincheck → batched quirky-direct PCS opening; returns
/// the two z-claims for the caller's public-input chaining.
pub fn verify_field_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    r1cs: &FieldR1cs,
    pcs_params: &PcsParams,
    commitment_root: &FlatDigestExpr,
    proof: &FieldR1csProofTrace,
) -> R1csClaimTrace {
    verify_field_trace_inner(b, ch, r1cs, pcs_params, commitment_root, proof, None)
}

/// Trace twin of `verifier::verify_field_with_public_io` — [`verify_field_trace`]
/// plus the envelope binding and its appended opening claims. `io` wires
/// carry the verified proof's public values; the spec is that instance's
/// protocol constant.
pub fn verify_field_trace_with_public_io(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    r1cs: &FieldR1cs,
    pcs_params: &PcsParams,
    commitment_root: &FlatDigestExpr,
    proof: &FieldR1csProofTrace,
    spec: &noid_ivc_core::public_io::PublicIoSpec,
    io: &[LinExpr],
) -> R1csClaimTrace {
    verify_field_trace_inner(
        b,
        ch,
        r1cs,
        pcs_params,
        commitment_root,
        proof,
        Some((spec, io)),
    )
}

/// Twin of `verifier::verify_field_deferred_matrix` — the matrix-free
/// [R] body of the self-verification chain. The verified class enters
/// only through its SHAPE (a protocol constant) and its statement digest
/// WIRES (from the previous envelope's IO); the lincheck final becomes
/// the returned deferred claim, which the caller folds into the chain
/// accumulator ([`super::matrix_fold`]).
#[allow(clippy::too_many_arguments)]
pub fn verify_field_trace_deferred(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    shape: &noid_ivc_core::proof::FieldShape,
    pcs_params: &PcsParams,
    statement_digest: &FlatDigestExpr,
    commitment_root: &FlatDigestExpr,
    proof: &FieldR1csProofTrace,
    spec: &noid_ivc_core::public_io::PublicIoSpec,
    io: &[LinExpr],
) -> (R1csClaimTrace, super::matrix_fold::FreshLincheckClaimTrace) {
    verify_field_trace_deferred_region(
        b,
        ch,
        shape,
        pcs_params,
        statement_digest,
        commitment_root,
        proof,
        spec,
        io,
        None,
    )
}

/// [`verify_field_trace_deferred`] with the walk-discharge mode switch:
/// `region = Some(out)` records every PCS leaf sponge and Merkle path as
/// an obligation instead of replaying it inline (the proof trace must be
/// allocated path-free via [`FieldR1csProofTrace::alloc_shape_mode`]);
/// the caller hosts the obligations on the link's walks and threads the
/// walk opening claims through public IO.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_trace_deferred_region(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    shape: &noid_ivc_core::proof::FieldShape,
    pcs_params: &PcsParams,
    statement_digest: &FlatDigestExpr,
    commitment_root: &FlatDigestExpr,
    proof: &FieldR1csProofTrace,
    spec: &noid_ivc_core::public_io::PublicIoSpec,
    io: &[LinExpr],
    region: Option<&mut PcsWalkObligations>,
) -> (R1csClaimTrace, super::matrix_fold::FreshLincheckClaimTrace) {
    verify_field_trace_deferred_region_with_post_commit(
        b,
        ch,
        shape,
        pcs_params,
        statement_digest,
        commitment_root,
        proof,
        spec,
        io,
        region,
        |_, _| Vec::new(),
    )
}

/// [`verify_field_trace_deferred_region`] with a post-commit auxiliary
/// verifier. The callback runs after the verified proof's statement root and
/// public IO have entered the SAME channel, but before zerocheck draws its
/// first challenge. Returned claims are appended to that proof's shared PCS
/// batch after the public-IO claims.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_trace_deferred_region_with_post_commit<C, PostCommit>(
    b: &mut FieldR1csBuilder,
    ch: &mut C,
    shape: &noid_ivc_core::proof::FieldShape,
    pcs_params: &PcsParams,
    statement_digest: &FlatDigestExpr,
    commitment_root: &FlatDigestExpr,
    proof: &FieldR1csProofTrace,
    spec: &noid_ivc_core::public_io::PublicIoSpec,
    io: &[LinExpr],
    region: Option<&mut PcsWalkObligations>,
    post_commit: PostCommit,
) -> (R1csClaimTrace, super::matrix_fold::FreshLincheckClaimTrace)
where
    C: FsChannelOps,
    PostCommit: FnOnce(&mut FieldR1csBuilder, &mut C) -> Vec<QuirkyDirectClaimTrace>,
{
    assert_eq!(
        pcs_params.m,
        shape.m + LOG_PACKING,
        "pcs_params.m must be shape.m + LOG_PACKING"
    );

    let mut ledger = b.num_wires();
    bind_statement_field_parts_trace(b, ch, statement_digest, pcs_params, commitment_root);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: statement bind");
    let io_claims = bind_public_io_trace(b, ch, spec, io, shape.m);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: public-IO bind");
    let auxiliary_claims = post_commit(b, ch);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: post-commit auxiliary");

    let zc_claim = zerocheck_field_verify_trace(b, ch, shape.m, &proof.zerocheck);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: zerocheck");

    let inner_rest_len = shape.k_log - shape.k_skip;
    let x_ab = QuirkyPointTrace {
        z_skip: zc_claim.z.clone(),
        x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };
    let (lc_claim, fresh) = lincheck_verify_trace_deferred(
        b,
        ch,
        shape.k_log,
        shape.k_skip,
        shape.const_pin,
        shape.m,
        &x_ab,
        &zc_claim.a_eval,
        &zc_claim.b_eval,
        &proof.lincheck,
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: lincheck");

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

    let x_rest_of = |zc: &ZClaimTrace| -> Vec<LinExpr> {
        let mut v = zc.x_inner_rest.clone();
        v.extend_from_slice(&zc.x_outer);
        v
    };
    let mut claims = vec![
        QuirkyDirectClaimTrace {
            z_skip: ab.z_skip.clone(),
            k_skip: shape.k_skip,
            x_rest: x_rest_of(&ab),
            value: ab.value.clone(),
        },
        QuirkyDirectClaimTrace {
            z_skip: c.z_skip.clone(),
            k_skip: shape.k_skip,
            x_rest: x_rest_of(&c),
            value: c.value.clone(),
        },
    ];
    claims.extend(io_claims);
    claims.extend(auxiliary_claims);
    verify_opening_batch_quirky_direct_trace_region(
        b,
        ch,
        commitment_root,
        &claims,
        &proof.pcs_open,
        pcs_params,
        region,
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: PCS opening batch");

    (R1csClaimTrace { ab, c }, fresh)
}

/// Typestate trace twin of
/// `verifier::verify_field_deferred_matrix_with_post_commit_context`.
/// It binds the explicit class digest after public IO, then gives the callback
/// an opaque SAME-channel context whose internal claims are appended
/// automatically to the verified proof's PCS batch.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_trace_deferred_region_with_post_commit_context<C, PostCommit>(
    b: &mut FieldR1csBuilder,
    ch: &mut C,
    shape: &noid_ivc_core::proof::FieldShape,
    pcs_params: &PcsParams,
    statement_digest: &FlatDigestExpr,
    commitment_root: &FlatDigestExpr,
    proof: &FieldR1csProofTrace,
    spec: &noid_ivc_core::public_io::PublicIoSpec,
    io: &[LinExpr],
    post_commit_class_digest: &[u8; 32],
    region: Option<&mut PcsWalkObligations>,
    post_commit: PostCommit,
) -> (R1csClaimTrace, super::matrix_fold::FreshLincheckClaimTrace)
where
    C: FsChannelOps,
    PostCommit: FnOnce(&mut FieldR1csBuilder, &mut FieldPostCommitTraceContext<'_, C>),
{
    let class_digest = const_flat_digest(post_commit_class_digest);
    verify_field_trace_deferred_region_with_post_commit_context_expr(
        b,
        ch,
        shape,
        pcs_params,
        statement_digest,
        commitment_root,
        proof,
        spec,
        io,
        &class_digest,
        region,
        post_commit,
    )
}

/// Witness-digest twin of
/// [`verify_field_trace_deferred_region_with_post_commit_context`].  Link
/// recursion uses it after one-hot selecting the previous class: the two flat
/// digest lanes are absorbed with the exact 32-byte `observe_bytes` header,
/// so a host cannot select a sidecar class outside the inherited whitelist.
#[allow(clippy::too_many_arguments)]
pub fn verify_field_trace_deferred_region_with_post_commit_context_expr<C, PostCommit>(
    b: &mut FieldR1csBuilder,
    ch: &mut C,
    shape: &noid_ivc_core::proof::FieldShape,
    pcs_params: &PcsParams,
    statement_digest: &FlatDigestExpr,
    commitment_root: &FlatDigestExpr,
    proof: &FieldR1csProofTrace,
    spec: &noid_ivc_core::public_io::PublicIoSpec,
    io: &[LinExpr],
    post_commit_class_digest: &FlatDigestExpr,
    region: Option<&mut PcsWalkObligations>,
    post_commit: PostCommit,
) -> (R1csClaimTrace, super::matrix_fold::FreshLincheckClaimTrace)
where
    C: FsChannelOps,
    PostCommit: FnOnce(&mut FieldR1csBuilder, &mut FieldPostCommitTraceContext<'_, C>),
{
    verify_field_trace_deferred_region_with_post_commit(
        b,
        ch,
        shape,
        pcs_params,
        statement_digest,
        commitment_root,
        proof,
        spec,
        io,
        region,
        |b, channel| {
            channel.observe_label(b, POST_COMMIT_CLASS_BINDING_LABEL);
            observe_flat_digest(b, channel, post_commit_class_digest);
            let mut context = FieldPostCommitTraceContext::new(commitment_root, shape.m, channel);
            post_commit(b, &mut context);
            context.finish()
        },
    )
}

fn verify_field_trace_inner(
    b: &mut FieldR1csBuilder,
    ch: &mut impl FsChannelOps,
    r1cs: &FieldR1cs,
    pcs_params: &PcsParams,
    commitment_root: &FlatDigestExpr,
    proof: &FieldR1csProofTrace,
    public_io: Option<(&noid_ivc_core::public_io::PublicIoSpec, &[LinExpr])>,
) -> R1csClaimTrace {
    assert_eq!(
        pcs_params.m,
        r1cs.m + LOG_PACKING,
        "pcs_params.m must be r1cs.m + LOG_PACKING"
    );

    let mut ledger = b.num_wires();
    // ---- Bind the FS transcript to the statement.
    bind_statement_field_trace(b, ch, r1cs, pcs_params, commitment_root);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: statement bind");

    // ---- Public-IO envelope binding (mirrors verify_field_with_public_io).
    let io_claims: Vec<QuirkyDirectClaimTrace> = match public_io {
        Some((spec, io)) => bind_public_io_trace(b, ch, spec, io, r1cs.m),
        None => Vec::new(),
    };
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: public-IO bind");

    // ---- Field zerocheck.
    let zc_claim = zerocheck_field_verify_trace(b, ch, r1cs.m, &proof.zerocheck);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: zerocheck");

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
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: lincheck");

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
    let mut claims = vec![
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
    claims.extend(io_claims);
    verify_opening_batch_quirky_direct_trace(
        b,
        ch,
        commitment_root,
        &claims,
        &proof.pcs_open,
        pcs_params,
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "R: PCS opening batch");

    R1csClaimTrace { ab, c }
}

// ---------------------------------------------------------------------------
// Shape-only proof synthesis (recording-layout derivation)
// ---------------------------------------------------------------------------

fn canonical_zero_merkle_path(lanes: usize, depth: usize) -> (Vec<Hash>, Hash) {
    let leaf = merkle::hash_leaf(&vec![0u8; lanes * 16]);
    let mut carried = leaf;
    let mut path = Vec::with_capacity(depth);
    for _ in 0..depth {
        path.push(carried);
        carried = merkle::hash_pair(&carried, &carried);
    }
    (path, carried)
}

/// Zero-valued `FieldR1csProof` and its exact commitment root for recording
/// layout derivation. It cannot verify algebraically, but every Merkle path is
/// an honest path in the uniform zero-leaf tree. This matters even under the
/// disabled base arm: the post-commit region columns still enforce their
/// native hash relation and may never be populated with fake zero roots.
/// Query positions start at zero; the layout driver patches them between its
/// two passes. Uniform-tree siblings make the authenticated root independent
/// of those positions.
pub(crate) fn shape_only_field_r1cs_proof(
    shape: &noid_ivc_core::proof::FieldShape,
    pcs_params: &PcsParams,
) -> (noid_ivc_core::proof::FieldR1csProof, Hash) {
    let log_msg_len = pcs_params.m - LOG_PACKING;
    let log_batch_size = pcs_params.log_batch_size;
    let log_dim = log_msg_len - log_batch_size;
    let k_code = log_dim + pcs_params.log_inv_rate;
    let arities = compute_fri_arities(log_dim);
    let (num_fri_commits, tail_layout) = pcs::fri_commit_layout(k_code, &arities);
    let arity_0 = arities.first().copied().unwrap_or(0);
    let n_queries = default_fri_queries(pcs_params.log_dim(), pcs_params.log_inv_rate);

    // The proof carries full-length zero Merkle paths: the path-free trace
    // allocation still shape-checks the native path lengths (it only skips
    // allocating wires for them).
    let mut cum = arity_0;
    let epoch_shapes: Vec<(usize, usize)> = (0..num_fri_commits)
        .map(|i| {
            let shape = (1usize << arities[i + 1], k_code - cum - arities[i + 1]);
            cum += arities[i + 1];
            shape
        })
        .collect();
    let (initial_path, initial_root) = canonical_zero_merkle_path(1usize << log_batch_size, k_code);
    let (post_row_batch_path, post_row_batch_root) = if arities.is_empty() {
        (Vec::new(), [0u8; 32])
    } else {
        canonical_zero_merkle_path(1usize << arity_0, k_code - arity_0)
    };
    let epoch_paths_and_roots = epoch_shapes
        .iter()
        .map(|&(lanes, depth)| canonical_zero_merkle_path(lanes, depth))
        .collect::<Vec<_>>();
    let query = pcs::basefold::QueryOpening {
        position: 0,
        initial_leaf: vec![F128::ZERO; 1usize << log_batch_size],
        initial_path,
        post_row_batch_leaf: if arities.is_empty() {
            Vec::new()
        } else {
            vec![F128::ZERO; 1usize << arity_0]
        },
        post_row_batch_path: if arities.is_empty() {
            Vec::new()
        } else {
            post_row_batch_path
        },
        epoch_leaves: epoch_shapes
            .iter()
            .map(|&(lanes, _)| vec![F128::ZERO; lanes])
            .collect(),
        epoch_paths: epoch_paths_and_roots
            .iter()
            .map(|(path, _)| path.clone())
            .collect(),
    };
    let proof = noid_ivc_core::proof::FieldR1csProof {
        zerocheck: zerocheck::ZerocheckProof {
            round1_ab: vec![F128::ZERO; 1usize << K_SKIP],
            round1_c: vec![F128::ZERO; 1usize << K_SKIP],
            multilinear_rounds: vec![(F128::ZERO, F128::ZERO); shape.m - K_SKIP],
            final_a_eval: F128::ZERO,
            final_b_eval: F128::ZERO,
            final_c_eval: F128::ZERO,
        },
        lincheck: noid_ivc_core::lincheck::LincheckProof {
            rounds: vec![(F128::ZERO, F128::ZERO); shape.k_log - shape.k_skip],
            z_partial: vec![F128::ZERO; 1usize << shape.k_skip],
        },
        pcs_open: pcs::BaseFoldProof {
            round_messages: vec![
                pcs::basefold::RoundMessage {
                    u_0: F128::ZERO,
                    u_2: F128::ZERO,
                };
                log_msg_len
            ],
            post_row_batch_commit: pcs::RoundCommitment {
                root: post_row_batch_root,
            },
            round_commitments: epoch_paths_and_roots
                .iter()
                .map(|(_, root)| pcs::RoundCommitment { root: *root })
                .collect(),
            final_a: F128::ZERO,
            final_b: F128::ZERO,
            final_codeword: vec![F128::ZERO; 1usize << pcs_params.log_inv_rate],
            plaintext_tail: match tail_layout {
                Some((tail_len, _)) => vec![F128::ZERO; tail_len],
                None => Vec::new(),
            },
            pow_nonce: 0,
            queries: vec![query; n_queries],
        },
    };
    (proof, initial_root)
}

/// Overwrite a shape-only proof's query positions with the transcript-derived
/// values harvested from a first recording pass (see the layout-derivation
/// drivers in `r_pcs_region`).  The final `div_ceil(n_queries, 128/k_code)`
/// squeezed challenges of an [R]-replay recording are exactly the
/// query-position lanes: the batched PCS opening is the replay's last channel
/// consumer and nothing squeezes after the query draw.
pub(crate) fn patch_shape_only_query_positions(
    proof: &mut noid_ivc_core::proof::FieldR1csProof,
    pcs_params: &PcsParams,
    query_lane_values: &[F128],
) {
    let log_msg_len = pcs_params.m - LOG_PACKING;
    let log_dim = log_msg_len - pcs_params.log_batch_size;
    let k_code = log_dim + pcs_params.log_inv_rate;
    let per_lane = 128 / k_code;
    let n_queries = proof.pcs_open.queries.len();
    assert_eq!(
        query_lane_values.len(),
        n_queries.div_ceil(per_lane),
        "query-lane harvest count"
    );
    let mask = (1u128 << k_code) - 1;
    let mut query = 0usize;
    for lane in query_lane_values {
        let raw = f128_to_u128(*lane);
        for w in 0..per_lane.min(n_queries - query) {
            proof.pcs_open.queries[query].position = ((raw >> (w * k_code)) & mask) as usize;
            query += 1;
        }
    }
    assert_eq!(query, n_queries, "query position patch count");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::challenger::{fs_pack_bytes_lanes, Challenger, FsLaneChallenger};
    use noid_ivc_core::deep_chain::schedule::{compile_duplex, DuplexLayout};
    use noid_ivc_core::field_circuit::FsChannelUnionRecorder;

    fn lanes_bytes(lanes: &[F128]) -> Vec<u8> {
        lanes
            .iter()
            .flat_map(|lane| f128_to_u128(*lane).to_le_bytes())
            .collect()
    }

    #[test]
    fn shape_only_envelope_uses_honest_uniform_merkle_trees() {
        use crate::acceptance::history_step_bank::{
            canonical_history_step_pcs_params, canonical_history_step_shape,
            CanonicalHistoryStepClassId, HISTORY_STEP_TIER_SLOT_COUNT,
        };

        for slot in 0..HISTORY_STEP_TIER_SLOT_COUNT {
            let class = CanonicalHistoryStepClassId::new(slot).unwrap();
            let params = canonical_history_step_pcs_params(class);
            let shape = canonical_history_step_shape(class);
            let (mut proof, commitment_root) = shape_only_field_r1cs_proof(&shape, &params);
            let log_dim = params.log_dim();
            let k_code = log_dim + params.log_inv_rate;
            let arities = compute_fri_arities(log_dim);
            let arity_0 = arities[0];
            let position = (1usize << k_code) - 1;
            proof.pcs_open.queries[0].position = position;
            let query = &proof.pcs_open.queries[0];

            let initial_leaf = merkle::hash_leaf(&lanes_bytes(&query.initial_leaf));
            assert!(merkle::verify_merkle_proof(
                &commitment_root,
                &initial_leaf,
                position,
                &query.initial_path,
            ));
            let post_leaf = merkle::hash_leaf(&lanes_bytes(&query.post_row_batch_leaf));
            assert!(merkle::verify_merkle_proof(
                &proof.pcs_open.post_row_batch_commit.root,
                &post_leaf,
                position >> arity_0,
                &query.post_row_batch_path,
            ));
            let mut consumed = arity_0;
            for (index, (leaf, path)) in query
                .epoch_leaves
                .iter()
                .zip(&query.epoch_paths)
                .enumerate()
            {
                consumed += arities[index + 1];
                let leaf_hash = merkle::hash_leaf(&lanes_bytes(leaf));
                assert!(merkle::verify_merkle_proof(
                    &proof.pcs_open.round_commitments[index].root,
                    &leaf_hash,
                    position >> consumed,
                    path,
                ));
            }
        }
    }
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
        use noid_poseidon2b::native::{compress_flat_feed_forward_with_tag, Poseidon2bFlatSponge};
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
            for (e, n) in claim
                .mlv_challenges
                .iter()
                .zip(&native_claim.mlv_challenges)
            {
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
        let proof =
            pcs::open_batch_quirky_direct(&witness, &prover_data, &commitment, &claims, &mut ch);
        (params, commitment, claims, proof)
    }

    /// Build the trace replay of a quirky-direct opening; returns the built
    /// instance/witness plus the proof-wire range for the mutation gate.
    fn build_pcs_trace(
        params: &PcsParams,
        commitment: &pcs::Commitment,
        claims: &[pcs::QuirkyDirectClaim],
        proof: &pcs::BaseFoldProof,
    ) -> (FieldR1cs, Vec<F128>, Vec<std::ops::Range<usize>>) {
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

        // The transcript-bound query position bits are verifier-internal
        // witness (not proof wires); gate them too — a bit flipped off its
        // lane pin must never satisfy the trace.
        let query_bit_ranges = verify_opening_batch_quirky_direct_trace(
            &mut b, &mut ch, &root, &claims_e, &proof_e, params,
        );

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
        let mut ranges = vec![mutation_start..mutation_end];
        ranges.extend(query_bit_ranges);
        (r1cs, z, ranges)
    }

    /// THE PCS lockstep gate: honest quirky-direct openings replay to a
    /// satisfiable trace, in transcript lockstep with the native verifier —
    /// covering a single-epoch shape and a multi-epoch (FRI commit) shape.
    #[test]
    fn pcs_replay_lockstep_matches_native() {
        for &(l_log, lb, lir, k_skip, seed) in &[
            (6usize, 2usize, 2usize, 4usize, 0xA1u128),
            (9, 2, 3, 6, 0xB2),
        ] {
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
        let (r1cs, z, ranges) = build_pcs_trace(&params, &commitment, &claims, &proof);
        assert!(r1cs.satisfies(&z));

        let mut battery = r1cs.flip_battery(&z);
        let mut survivors = Vec::new();
        for range in ranges {
            survivors.extend(battery.survivors(range));
        }
        assert!(
            survivors.is_empty(),
            "PCS mutation survivors: {survivors:?}"
        );
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
            (
                claim.ab.value.eval(b.values()),
                claim.ab.z_skip.eval(b.values()),
            ),
            (
                claim.c.value.eval(b.values()),
                claim.c.z_skip.eval(b.values()),
            ),
        ];
        let (out_r1cs, out_z) = b.build();
        (
            out_r1cs,
            out_z,
            mutation_start..mutation_end,
            claim_evals,
            rows,
        )
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
        let (r1cs, params, commitment, proof, _) = field_proof_fixture(7, 2, 43);
        let (out_r1cs, out_z, range, _, _) =
            build_field_verify_trace(&r1cs, &params, &commitment, &proof);
        assert!(out_r1cs.satisfies(&out_z));

        let survivors = out_r1cs.flip_battery(&out_z).survivors(range);
        assert!(
            survivors.is_empty(),
            "[R] mutation survivors: {survivors:?}"
        );
    }

    /// Public-IO lockstep gate: the extended verifier replay (envelope
    /// binding + appended opening claims) accepts an honest
    /// `prove_field_with_public_io` proof in transcript lockstep, and
    /// flipping ANY envelope-lane wire or proof wire leaves the trace
    /// unsatisfiable.
    #[test]
    fn verify_field_replay_with_public_io_lockstep_and_mutations() {
        use noid_ivc_core::field_r1cs::SparseFieldMatrix;
        use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};
        use noid_ivc_prover::field_prover::prove_field_with_public_io;

        // A verified instance whose non-constant rows are free
        // (`z_i = z_i · z_0`), so the io lanes and the claim target can be
        // placed anywhere.
        let (m, k_log) = (7usize, 7usize);
        let k = 1usize << k_log;
        let inner = FieldR1cs {
            m,
            k_log,
            k_skip: K_SKIP,
            useful_rows: k,
            a_0: SparseFieldMatrix::from_rows(
                k,
                (0..k)
                    .map(|r| vec![(if r == 0 { 0 } else { r as u32 }, F128::ONE)])
                    .collect(),
            ),
            b_0: SparseFieldMatrix::from_rows(k, (0..k).map(|_| vec![(0u32, F128::ONE)]).collect()),
            const_pin: Some(0),
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        };
        let mut rng = Rng(0x10CA11);
        let mut z: Vec<F128> = (0..1usize << m).map(|_| rng.next_f128()).collect();
        for blk in 0..(1usize << (m - k_log)) {
            z[blk * k] = F128::ONE;
        }

        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 3,
                index: 2,
            },
            io_len: 4,
            claims: vec![IoClaimSpec {
                slice: WitnessSlice {
                    log2_len: 2,
                    index: 9,
                },
                point: 0..2,
                value: 2,
            }],
        };
        let p = [rng.next_f128(), rng.next_f128()];
        let eq = noid_ivc_core::lincheck::build_eq_table(&p);
        let mut v = F128::ZERO;
        for (t, e) in eq.iter().enumerate() {
            v += z[36 + t] * *e;
        }
        let io = vec![p[0], p[1], v, rng.next_f128()];
        for (t, lane) in io.iter().enumerate() {
            z[16 + t] = *lane;
        }
        for t in io.len()..8 {
            z[16 + t] = F128::ZERO;
        }
        assert!(inner.satisfies(&z));

        let params = PcsParams {
            m: m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(b"self-verify-io-test");
        let (proof, commitment, _) =
            prove_field_with_public_io(&inner, &z, &params, &spec, &io, &mut ch_p);

        // Native lockstep reference.
        let mut ch_native = FsLaneChallenger::new(b"self-verify-io-test");
        noid_ivc_core::verifier::verify_field_with_public_io(
            &inner,
            &commitment,
            &proof,
            &spec,
            &io,
            &mut ch_native,
        )
        .expect("native verify accepts the honest public-io proof");

        // Trace replay.
        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"self-verify-io-test");
        let mutation_start = b.num_wires();
        let root = alloc_flat_digest(&mut b, &commitment.root);
        let io_wires: Vec<LinExpr> = io
            .iter()
            .map(|&lane| LinExpr::from_wire(b.alloc_f128(lane)))
            .collect();
        let proof_e = FieldR1csProofTrace::alloc(&mut b, &proof, &inner, &params);
        let mutation_end = b.num_wires();
        let _ = verify_field_trace_with_public_io(
            &mut b, &mut ch, &inner, &params, &root, &proof_e, &spec, &io_wires,
        );
        let c_n = ch_native.sample_f128();
        let c_t = ch.sample_f128(&mut b);
        assert_eq!(
            c_t.eval(b.values()),
            c_n,
            "post-verify challenge diverged (public-io)"
        );

        let (out_r1cs, out_z) = b.build();
        assert!(out_r1cs.satisfies(&out_z), "honest public-io trace unsat");

        let survivors = out_r1cs
            .flip_battery(&out_z)
            .survivors(mutation_start..mutation_end);
        assert!(
            survivors.is_empty(),
            "public-io mutation survivors: {survivors:?}"
        );
    }

    /// Deferred-matrix [R] lockstep gate: the matrix-free replay (digest
    /// as WIRES, deferred lincheck claim) accepts an honest public-io
    /// proof in lockstep with `verify_field_deferred_matrix`, the fold
    /// twin folds the fresh claim in lockstep with the native fold, the
    /// accumulator agrees and is TRUE against the verified matrices, and
    /// every allocated wire (digest lanes included) mutates to unsat.
    #[test]
    fn verify_field_deferred_lockstep_and_mutations() {
        use noid_ivc_core::field_r1cs::SparseFieldMatrix;
        use noid_ivc_core::matrix_claim::{
            prove_matrix_claim_fold, stacked_matrix_mle_eval, MatrixAccClaim,
        };
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
        use noid_ivc_prover::field_prover::prove_field_with_public_io;

        use crate::acceptance::trace::matrix_fold::{
            verify_matrix_claim_fold_trace, MatrixAccClaimTrace, MatrixFoldProofTrace,
        };

        let (m, k_log) = (7usize, 7usize);
        let k = 1usize << k_log;
        let inner = FieldR1cs {
            m,
            k_log,
            k_skip: K_SKIP,
            useful_rows: k,
            a_0: SparseFieldMatrix::from_rows(
                k,
                (0..k)
                    .map(|r| vec![(if r == 0 { 0 } else { r as u32 }, F128::ONE)])
                    .collect(),
            ),
            b_0: SparseFieldMatrix::from_rows(k, (0..k).map(|_| vec![(0u32, F128::ONE)]).collect()),
            const_pin: Some(0),
            digest_cache: std::sync::OnceLock::new(),
            csc_cache: std::sync::OnceLock::new(),
        };
        let mut rng = Rng(0xDEF2);
        let mut z: Vec<F128> = (0..1usize << m).map(|_| rng.next_f128()).collect();
        for blk in 0..(1usize << (m - k_log)) {
            z[blk * k] = F128::ONE;
        }
        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 2,
                index: 4,
            },
            io_len: 4,
            claims: vec![],
        };
        let io: Vec<F128> = (0..4).map(|_| rng.next_f128()).collect();
        for (t, lane) in io.iter().enumerate() {
            z[16 + t] = *lane;
        }
        assert!(inner.satisfies(&z));

        let params = PcsParams {
            m: m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(b"self-verify-def-test");
        let (proof, commitment, _) =
            prove_field_with_public_io(&inner, &z, &params, &spec, &io, &mut ch_p);

        // Native deferred reference + native fold (genesis gate).
        let shape = FieldShape::of(&inner);
        let digest = inner.statement_digest();
        let mut ch_native = FsLaneChallenger::new(b"self-verify-def-test");
        let (_, fresh_native) = noid_ivc_core::verifier::verify_field_deferred_matrix(
            &shape,
            &digest,
            &commitment,
            &proof,
            &spec,
            &io,
            &mut ch_native,
        )
        .expect("native deferred verify accepts");
        let junk = MatrixAccClaim::zero(k_log);
        let mut fold_native = FsLaneChallenger::new(b"self-verify-def-fold");
        let (fold_proof, acc_native) =
            prove_matrix_claim_fold(&inner, &fresh_native, &junk, false, &mut fold_native);
        assert_eq!(
            stacked_matrix_mle_eval(&inner, &acc_native),
            acc_native.value,
            "native accumulator claim is true"
        );

        // Trace replay: digest as wires, deferred lincheck, fold twin.
        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"self-verify-def-test");
        let mutation_start = b.num_wires();
        let digest_e = alloc_flat_digest(&mut b, &digest);
        let root = alloc_flat_digest(&mut b, &commitment.root);
        let io_wires: Vec<LinExpr> = io
            .iter()
            .map(|&lane| LinExpr::from_wire(b.alloc_f128(lane)))
            .collect();
        let proof_e = FieldR1csProofTrace::alloc_shape(&mut b, &proof, &shape, &params);
        let incoming_e = MatrixAccClaimTrace::alloc(&mut b, &junk);
        let fold_proof_e = MatrixFoldProofTrace::alloc(&mut b, &fold_proof, k_log);
        let mutation_end = b.num_wires();
        let (_claim, fresh_e) = verify_field_trace_deferred(
            &mut b, &mut ch, &shape, &params, &digest_e, &root, &proof_e, &spec, &io_wires,
        );
        let mut fold_ch = FsChannelTrace::new(&mut b, b"self-verify-def-fold");
        let gate = LinExpr::zero();
        let acc_e = verify_matrix_claim_fold_trace(
            &mut b,
            &mut fold_ch,
            k_log,
            K_SKIP,
            &fresh_e,
            &incoming_e,
            &gate,
            &fold_proof_e,
        );
        let rows = b.num_wires();
        eprintln!("[self-verify] deferred m={m} rows = {rows}");

        // Lockstep on both channels; fresh + accumulator agreement.
        let c_n = ch_native.sample_f128();
        let c_t = ch.sample_f128(&mut b);
        assert_eq!(c_t.eval(b.values()), c_n, "deferred transcript diverged");
        let f_n = fold_native.sample_f128();
        let f_t = fold_ch.sample_f128(&mut b);
        assert_eq!(f_t.eval(b.values()), f_n, "fold transcript diverged");
        assert_eq!(
            fresh_e.value.eval(b.values()),
            fresh_native.value,
            "deferred claim value diverged"
        );
        for (e, n) in acc_e.point.iter().zip(acc_native.point.iter()) {
            assert_eq!(e.eval(b.values()), *n, "accumulator point diverged");
        }
        assert_eq!(acc_e.value.eval(b.values()), acc_native.value);

        let (out_r1cs, out_z) = b.build();
        assert!(out_r1cs.satisfies(&out_z), "honest deferred trace unsat");

        let survivors = out_r1cs
            .flip_battery(&out_z)
            .survivors(mutation_start..mutation_end);
        assert!(
            survivors.is_empty(),
            "deferred mutation survivors: {survivors:?}"
        );
    }

    /// Post-commit auxiliary claims occupy the same transcript position in
    /// native matrix-free verification and its recursive trace twin: after
    /// statement/root/public-IO binding, before zerocheck, and in the final
    /// PCS batch. This is the causality gate used by region sidecars.
    #[test]
    fn verify_field_deferred_post_commit_auxiliary_lockstep() {
        use noid_ivc_core::field_r1cs::synthetic_satisfiable;
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
        use noid_ivc_core::verifier::{verify_field_deferred_matrix_with_post_commit, VerifyError};
        use noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit;

        #[derive(Clone)]
        struct Aux {
            point: Vec<F128>,
            value: F128,
        }

        let (m, seed) = (8usize, 0x51DEC4u64);
        let (inner, z) = synthetic_satisfiable(m, m, seed);
        let shape = FieldShape::of(&inner);
        let digest = inner.statement_digest();
        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 2,
                index: 4,
            },
            io_len: 4,
            claims: Vec::new(),
        };
        let io: Vec<F128> = z[16..20].to_vec();
        let params = PcsParams {
            m: m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };

        let mut ch_p = FsLaneChallenger::new(b"self-verify-post-commit-test");
        let (proof, auxiliary, commitment, _) = prove_field_with_public_io_and_post_commit(
            &inner,
            &z,
            &params,
            &spec,
            &io,
            &mut ch_p,
            |z, _, ch| {
                ch.observe_label(b"self-verify-post-commit-aux-v0");
                let point = ch.sample_f128_vec(m);
                let value = z
                    .iter()
                    .zip(noid_ivc_core::lincheck::build_eq_table(&point))
                    .fold(F128::ZERO, |sum, (&v, eq)| sum + v * eq);
                ch.observe_f128(value);
                let claim = pcs::QuirkyDirectClaim {
                    z_skip: F128::ZERO,
                    k_skip: 0,
                    x_rest: point.clone(),
                    value,
                };
                (Aux { point, value }, vec![claim])
            },
        );

        let mut ch_native = FsLaneChallenger::new(b"self-verify-post-commit-test");
        let (_, fresh_native) = verify_field_deferred_matrix_with_post_commit(
            &shape,
            &digest,
            &commitment,
            &proof,
            &spec,
            &io,
            &auxiliary,
            &mut ch_native,
            |aux, ch| {
                ch.observe_label(b"self-verify-post-commit-aux-v0");
                if ch.sample_f128_vec(m) != aux.point {
                    return Err(VerifyError::Auxiliary);
                }
                ch.observe_f128(aux.value);
                Ok(vec![pcs::QuirkyDirectClaim {
                    z_skip: F128::ZERO,
                    k_skip: 0,
                    x_rest: aux.point.clone(),
                    value: aux.value,
                }])
            },
        )
        .expect("native post-commit deferred verify");

        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"self-verify-post-commit-test");
        let digest_e = alloc_flat_digest(&mut b, &digest);
        let root = alloc_flat_digest(&mut b, &commitment.root);
        let io_e: Vec<LinExpr> = io
            .iter()
            .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
            .collect();
        let proof_e = FieldR1csProofTrace::alloc_shape(&mut b, &proof, &shape, &params);
        let aux_start = b.num_wires();
        let aux_point_e: Vec<LinExpr> = auxiliary
            .point
            .iter()
            .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
            .collect();
        let aux_value_e = LinExpr::from_wire(b.alloc_f128(auxiliary.value));
        let aux_end = b.num_wires();
        let (_, fresh_e) = verify_field_trace_deferred_region_with_post_commit(
            &mut b,
            &mut ch,
            &shape,
            &params,
            &digest_e,
            &root,
            &proof_e,
            &spec,
            &io_e,
            None,
            |b, ch| {
                ch.observe_label(b, b"self-verify-post-commit-aux-v0");
                let expected = ch.sample_f128_vec(b, m);
                for (got, expected) in aux_point_e.iter().zip(&expected) {
                    pin_eq(b, got, expected);
                }
                ch.observe_f128(b, &aux_value_e);
                vec![QuirkyDirectClaimTrace {
                    z_skip: LinExpr::zero(),
                    k_skip: 0,
                    x_rest: aux_point_e.clone(),
                    value: aux_value_e.clone(),
                }]
            },
        );

        assert_eq!(fresh_e.value.eval(b.values()), fresh_native.value);
        let post_native = ch_native.sample_f128();
        let post_trace = ch.sample_f128(&mut b);
        assert_eq!(post_trace.eval(b.values()), post_native);
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
        let survivors = r1cs.flip_battery(&witness).survivors(aux_start..aux_end);
        assert!(
            survivors.is_empty(),
            "post-commit auxiliary mutation survivors: {survivors:?}"
        );
    }

    #[test]
    fn verify_field_deferred_post_commit_context_lockstep() {
        use noid_ivc_core::field_r1cs::synthetic_satisfiable;
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
        use noid_ivc_core::verifier::{
            verify_field_deferred_matrix_with_post_commit_context, VerifyError,
        };
        use noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit_context;

        const CLASS_DIGEST: [u8; 32] = [0xAC; 32];

        #[derive(Clone)]
        struct Aux {
            point: Vec<F128>,
            value: F128,
        }

        let (m, seed) = (7usize, 0xC07E57u64);
        let (inner, z) = synthetic_satisfiable(m, m, seed);
        let shape = FieldShape::of(&inner);
        let digest = inner.statement_digest();
        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 2,
                index: 4,
            },
            io_len: 4,
            claims: Vec::new(),
        };
        let io: Vec<F128> = z[16..20].to_vec();
        let params = PcsParams {
            m: m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };

        let mut ch_p = FsLaneChallenger::new(b"self-verify-post-commit-context-test");
        let (proof, auxiliary, commitment, _) = prove_field_with_public_io_and_post_commit_context(
            &inner,
            &z,
            &params,
            &spec,
            &io,
            &CLASS_DIGEST,
            &mut ch_p,
            |context| {
                context.observe_label(b"self-verify-post-commit-context-aux-v1");
                let point = context.sample_f128_vec(m);
                let value = context
                    .witness()
                    .iter()
                    .zip(noid_ivc_core::lincheck::build_eq_table(&point))
                    .fold(F128::ZERO, |sum, (&v, eq)| sum + v * eq);
                context.observe_f128(value);
                context.append_claim(pcs::QuirkyDirectClaim {
                    z_skip: F128::ZERO,
                    k_skip: 0,
                    x_rest: point.clone(),
                    value,
                });
                Aux { point, value }
            },
        );

        let mut ch_native = FsLaneChallenger::new(b"self-verify-post-commit-context-test");
        let (_, fresh_native) = verify_field_deferred_matrix_with_post_commit_context(
            &shape,
            &digest,
            &commitment,
            &proof,
            &spec,
            &io,
            &CLASS_DIGEST,
            &auxiliary,
            &mut ch_native,
            |auxiliary, context| {
                context.observe_label(b"self-verify-post-commit-context-aux-v1");
                if context.sample_f128_vec(m) != auxiliary.point {
                    return Err(VerifyError::Auxiliary);
                }
                context.observe_f128(auxiliary.value);
                context.append_claim(pcs::QuirkyDirectClaim {
                    z_skip: F128::ZERO,
                    k_skip: 0,
                    x_rest: auxiliary.point.clone(),
                    value: auxiliary.value,
                });
                Ok(())
            },
        )
        .expect("native post-commit context deferred verify");

        let mut b = FieldR1csBuilder::new();
        let mut ch = FsChannelTrace::new(&mut b, b"self-verify-post-commit-context-test");
        let digest_e = alloc_flat_digest(&mut b, &digest);
        let root = alloc_flat_digest(&mut b, &commitment.root);
        let io_e: Vec<LinExpr> = io
            .iter()
            .map(|&value| LinExpr::from_wire(b.alloc_f128(value)))
            .collect();
        let proof_e = FieldR1csProofTrace::alloc_shape(&mut b, &proof, &shape, &params);
        let point_e: Vec<LinExpr> = auxiliary
            .point
            .iter()
            .map(|&value| LinExpr::from_wire(b.alloc_f128(value)))
            .collect();
        let value_e = LinExpr::from_wire(b.alloc_f128(auxiliary.value));
        let (_, fresh_e) = verify_field_trace_deferred_region_with_post_commit_context(
            &mut b,
            &mut ch,
            &shape,
            &params,
            &digest_e,
            &root,
            &proof_e,
            &spec,
            &io_e,
            &CLASS_DIGEST,
            None,
            |b, context| {
                assert_eq!(context.total_vars(), m);
                assert_eq!(
                    context.commitment_root()[0].eval(b.values()),
                    root[0].eval(b.values())
                );
                context.observe_label(b, b"self-verify-post-commit-context-aux-v1");
                let expected = context.sample_f128_vec(b, m);
                for (got, expected) in point_e.iter().zip(&expected) {
                    pin_eq(b, got, expected);
                }
                context.observe_f128(b, &value_e);
                context.append_claim(QuirkyDirectClaimTrace {
                    z_skip: LinExpr::zero(),
                    k_skip: 0,
                    x_rest: point_e.clone(),
                    value: value_e.clone(),
                });
                assert_eq!(context.claim_count(), 1);
            },
        );

        assert_eq!(fresh_e.value.eval(b.values()), fresh_native.value);
        let post_native = ch_native.sample_f128();
        let post_trace = ch.sample_f128(&mut b);
        assert_eq!(post_trace.eval(b.values()), post_native);
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
    }

    /// The walk-discharge (region) mode of the deferred [R] replay:
    /// identical transcript and deferred claim to the inline mode (the
    /// hashing never touched the channel), a satisfiable path-free trace,
    /// the expected obligation structure (one leaf+path pair per tree per
    /// query, dir-bit lengths matching the tree depths, even lane counts)
    /// and a strictly smaller trace.
    #[test]
    fn verify_field_deferred_region_obligation_parity() {
        use noid_ivc_core::field_r1cs::synthetic_satisfiable;
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
        use noid_ivc_prover::field_prover::prove_field_with_public_io;

        let (m, k_log, seed) = (10usize, 10usize, 0x0B11u64);
        let (inner, z) = synthetic_satisfiable(m, k_log, seed);
        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 2,
                index: 4,
            },
            io_len: 4,
            claims: vec![],
        };
        let io: Vec<F128> = (16..20).map(|t| z[t]).collect();
        let params = PcsParams {
            m: m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let mut ch_p = FsLaneChallenger::new(b"self-verify-region-test");
        let (proof, commitment, _) =
            prove_field_with_public_io(&inner, &z, &params, &spec, &io, &mut ch_p);
        let shape = FieldShape::of(&inner);
        let digest = inner.statement_digest();

        // Shared per-mode driver.
        let run = |alloc_paths: bool,
                   region: Option<&mut PcsWalkObligations>|
         -> (usize, F128, F128) {
            let mut b = FieldR1csBuilder::new();
            let mut ch = FsChannelTrace::new(&mut b, b"self-verify-region-test");
            let digest_e = alloc_flat_digest(&mut b, &digest);
            let root = alloc_flat_digest(&mut b, &commitment.root);
            let io_wires: Vec<LinExpr> = io
                .iter()
                .map(|&lane| LinExpr::from_wire(b.alloc_f128(lane)))
                .collect();
            let proof_e =
                FieldR1csProofTrace::alloc_shape_mode(&mut b, &proof, &shape, &params, alloc_paths);
            let (_claim, fresh_e) = verify_field_trace_deferred_region(
                &mut b, &mut ch, &shape, &params, &digest_e, &root, &proof_e, &spec, &io_wires,
                region,
            );
            let post = ch.sample_f128(&mut b);
            let rows = b.num_wires();
            let fresh_v = fresh_e.value.eval(b.values());
            let post_v = post.eval(b.values());
            let (r1cs_t, z_t) = b.build();
            assert!(
                r1cs_t.satisfies(&z_t),
                "trace unsatisfiable (alloc_paths={alloc_paths})"
            );
            (rows, fresh_v, post_v)
        };

        let (rows_inline, fresh_inline, post_inline) = run(true, None);
        let mut obs = PcsWalkObligations::default();
        let (rows_region, fresh_region, post_region) = run(false, Some(&mut obs));
        eprintln!(
            "[self-verify] region-mode rows {rows_region} vs inline {rows_inline} \
             ({} leaf/path obligations)",
            obs.leaves.len()
        );

        // Transcript + claim parity (the hashing never touched the channel).
        assert_eq!(
            post_region, post_inline,
            "region mode diverged the transcript"
        );
        assert_eq!(
            fresh_region, fresh_inline,
            "region mode changed the deferred claim"
        );
        assert!(
            rows_region < rows_inline,
            "region mode did not shrink the trace"
        );

        // Obligation structure: per query one pair per verified tree, dir
        // bits matching the tree depths, even lane counts throughout.
        let log_msg_len = params.m - LOG_PACKING;
        let log_dim = log_msg_len - params.log_batch_size;
        let k_code = log_dim + params.log_inv_rate;
        let arities = compute_fri_arities(log_dim);
        let (num_fri_commits, _) = pcs::fri_commit_layout(k_code, &arities);
        let arity_0 = arities.first().copied().unwrap_or(0);
        let n_queries = proof.pcs_open.queries.len();
        let trees = 1 + usize::from(!arities.is_empty()) + num_fri_commits;
        assert_eq!(obs.leaves.len(), n_queries * trees, "leaf obligation count");
        assert_eq!(obs.paths.len(), obs.leaves.len(), "path obligation count");
        for (i, p) in obs.paths.iter().enumerate() {
            assert_eq!(p.leaf, i, "leaf/path pairing");
            assert!(obs.leaves[i].lanes.len() % 2 == 0, "odd leaf lanes");
        }
        for q in 0..n_queries {
            let base = q * trees;
            assert_eq!(obs.paths[base].dir_bits.len(), k_code, "initial path depth");
            if !arities.is_empty() {
                assert_eq!(
                    obs.paths[base + 1].dir_bits.len(),
                    k_code - arity_0,
                    "post-row-batch path depth"
                );
            }
        }
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

    #[test]
    fn observe_pinned_digest_matches_native_bytes() {
        let digest = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];
        let domain = b"pinned-vk-digest-test";
        let mut native = FsLaneChallenger::new(domain);
        native.observe_bytes(&digest);
        let expected = native.sample_f128();

        let mut b = FieldR1csBuilder::new();
        let mut trace = FsChannelTrace::new(&mut b, domain);
        observe_pinned_digest(&mut b, &mut trace, &digest);
        let actual = trace.sample_f128(&mut b);
        assert_eq!(actual.eval(b.values()), expected);

        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
    }

    fn pinned_coordinate_recording(values: &[F128]) -> (DuplexLayout, F128) {
        let domain = b"pinned-claim-coordinates-test";
        let mut native = FsLaneChallenger::new(domain);
        native.observe_f128_slice(values);
        let expected = native.sample_f128();

        let mut b = FieldR1csBuilder::new();
        let coordinates = values
            .iter()
            .copied()
            .map(LinExpr::constant)
            .collect::<Vec<_>>();
        let coordinates = pin_transcript_constant_coordinates(&mut b, &coordinates);
        let mut recorder = FsChannelUnionRecorder::new(domain);
        recorder.observe_f128_slice(&mut b, &coordinates);
        let actual = recorder.sample_f128(&mut b);
        let recording = recorder.finish();

        assert_eq!(actual.eval(b.values()), expected);
        assert_eq!(recording.data_flat, values);
        let layout = compile_duplex(&recording.ops);
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
        (layout, expected)
    }

    #[test]
    fn pinned_claim_coordinates_are_value_independent_transcript_data() {
        let (first, first_challenge) =
            pinned_coordinate_recording(&[F128::ZERO, F128::ONE, F128::ZERO, F128::ONE]);
        let (second, second_challenge) =
            pinned_coordinate_recording(&[F128::ONE, F128::ZERO, F128::ONE, F128::ZERO]);
        assert_eq!(first, second);
        assert_eq!(first.n_data, 4);
        assert_ne!(first_challenge, second_challenge);
    }
}
