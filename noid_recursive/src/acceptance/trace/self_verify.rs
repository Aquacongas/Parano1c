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
use noid_ivc_core::pcs::PcsParams;
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
/// F_{2^128} values). Replays the `IVCPCSL_` flat duplex: rate-2 absorbs,
/// `0x80…01` pad, digest = the two rate lanes. All-constant inputs fold.
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

    let [iv_hi, iv_lo] = tag_iv_flat_f128(MERKLE_LEAF_TAG);
    let mut state = [
        LinExpr::zero(),
        LinExpr::zero(),
        LinExpr::constant(iv_hi),
        LinExpr::constant(iv_lo),
    ];
    let mut absorb_block = |b: &mut FieldR1csBuilder,
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
        _ => {
            // Whole number of blocks absorbed: a full pad block follows.
            let [p0, p1] = pad_full_block_lanes();
            absorb_block(
                b,
                &mut state,
                &LinExpr::constant(p0),
                &LinExpr::constant(p1),
            );
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
    /// actually hashes with: a one-permutation feed-forward compress and a
    /// flat leaf sponge built here from the DUPLICATED tags reproduce the
    /// native digests.
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
        let data: Vec<u8> = (0..64u8).collect();
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
