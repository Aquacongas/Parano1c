//! The self-verification link — the recursion fixed point.
//!
//! A LINK is a FieldR1cs proof over the link class whose trace verifies
//! the PREVIOUS link's proof (same class) and folds the deferred matrix
//! claim into the chain accumulator. The class matrix contains NOTHING
//! of itself: the verified statement digest is a witness wire fed from
//! public IO, and the lincheck's matrix consistency is deferred into
//! the accumulator ([`noid_ivc_core::matrix_claim`]). The chain closes
//! at the DECIDER: one native check that the tip's IO carries the class
//! digest and that the accumulated claim evaluates true against the
//! class matrix.
//!
//! Public IO layout (in order): `w_D` (2 lanes — the digest the link
//! verified against), `g` (1 lane — genesis flag), the accumulator
//! point (`2·k_log + 1` lanes) and value (1 lane).
//!
//! In-trace rules:
//! - `g` boolean; `g = 1` forces `w_D = D_T` (the digest of the FIXED
//!   tiny genesis instance — a different class, so its digest and its
//!   single-block matrix sums are legal bake-ins) and checks the
//!   deferred lincheck claim against T's baked block sums directly;
//! - `gate = (1 + g)·(1 + g_prev)` gates the digest-inheritance pin
//!   `w_D_prev = w_D` and the incoming accumulator inside the fold (a
//!   genesis link's accumulator lanes are dead — the next link folds
//!   them out);
//! - the fold twin runs on its own transcript channel and its outgoing
//!   claim is pinned to the link's own IO lanes.
//!
//! Chain soundness (decider view): tip IO `w_D = D_B` ∧ `g = 0` ⇒ the
//! tip verified a class proof whose IO the tip's PCS binds; every
//! non-genesis link below inherited the same digest, down to a link
//! with `g = 1` whose in-matrix pins forced it to have verified the
//! fixed dummy T. The accumulator collects every link's deferred
//! lincheck consistency and is checked once, natively.
//!
//! Bootstrap order (nothing circular): T and its proof exist without
//! the class; building the GENESIS link's trace against T produces the
//! class matrix itself (the trace never contains the class digest or
//! matrix); every later link re-builds the identical structure — gated
//! by a statement-digest equality between builds.

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, FsChannelTrace, LinExpr};
use noid_ivc_core::field_r1cs::{FieldR1cs, SparseFieldMatrix};
use noid_ivc_core::matrix_claim::{prove_matrix_claim_fold, MatrixAccClaim};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::proof::{FieldR1csProof, FieldShape};
use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};

use super::trace::matrix_fold::{
    verify_matrix_claim_fold_trace, FreshLincheckClaimTrace, MatrixAccClaimTrace,
    MatrixFoldProofTrace,
};
use super::trace::self_verify::{
    alloc_flat_digest, flat_digest_lanes, lagrange_weights_window_trace,
    verify_field_trace_deferred, FieldR1csProofTrace, FlatDigestExpr,
};
use super::trace::{mul, pin_eq};

/// The genesis dummy instance: the link class's SHAPE with all real
/// constraints inside the single top-left `2^k_skip × 2^k_skip` block
/// (`useful_rows = 2^k_skip`), so the genesis arm's baked bilinear check
/// needs no eq tensors — only the block-(0,0) weights. Rows:
/// `z_0·z_0 = z_0` (the constant pin) and `z_r·z_0 = z_r` for the rest
/// of the block.
pub fn genesis_instance(shape: &FieldShape) -> FieldR1cs {
    let k = 1usize << shape.k_log;
    let ell = 1usize << shape.k_skip;
    let a_0 = SparseFieldMatrix {
        num_rows: k,
        num_cols: k,
        rows: (0..k)
            .map(|r| {
                if r == 0 {
                    vec![(0u32, F128::ONE)]
                } else if r < ell {
                    vec![(r as u32, F128::ONE)]
                } else {
                    vec![]
                }
            })
            .collect(),
    };
    let b_0 = SparseFieldMatrix {
        num_rows: k,
        num_cols: k,
        rows: (0..k)
            .map(|r| if r < ell { vec![(0u32, F128::ONE)] } else { vec![] })
            .collect(),
    };
    FieldR1cs {
        m: shape.m,
        k_log: shape.k_log,
        k_skip: shape.k_skip,
        useful_rows: ell,
        a_0,
        b_0,
        const_pin: Some(0),
        digest_cache: std::sync::OnceLock::new(),
        csc_cache: std::sync::OnceLock::new(),
    }
}

/// A satisfying witness for [`genesis_instance`] (IO lanes zero — a
/// genesis link gates every use of them off).
pub fn genesis_witness(shape: &FieldShape) -> Vec<F128> {
    let n = 1usize << shape.m;
    let k = 1usize << shape.k_log;
    let mut z = vec![F128::ZERO; n];
    for blk in 0..(n / k) {
        z[blk * k] = F128::ONE;
    }
    z
}

/// IO lane offsets within the class IO vector.
#[derive(Clone, Copy, Debug)]
pub struct LinkIoLayout {
    pub w_d: usize,
    pub g: usize,
    pub acc_point: usize,
    pub acc_value: usize,
    pub len: usize,
}

pub fn link_io_layout(k_log: usize) -> LinkIoLayout {
    let acc_len = 2 * k_log + 1;
    LinkIoLayout {
        w_d: 0,
        g: 2,
        acc_point: 3,
        acc_value: 3 + acc_len,
        len: 4 + acc_len,
    }
}

/// The class IO spec: one dyadic slice right after the padding head,
/// no derived claims (the chain pins read lanes as wires directly).
pub fn link_io_spec(k_log: usize) -> PublicIoSpec {
    let layout = link_io_layout(k_log);
    let log2_len = layout.len.next_power_of_two().trailing_zeros() as usize;
    PublicIoSpec {
        io_slice: WitnessSlice { log2_len, index: 1 },
        io_len: layout.len,
        claims: vec![],
    }
}

/// The link class constants.
pub struct LinkClass {
    pub shape: FieldShape,
    pub pcs_params: PcsParams,
    pub spec: PublicIoSpec,
    pub genesis: FieldR1cs,
    pub genesis_digest: [u8; 32],
}

impl LinkClass {
    pub fn new(shape: FieldShape, pcs_params: PcsParams) -> Self {
        let genesis = genesis_instance(&shape);
        let genesis_digest = genesis.statement_digest();
        Self {
            shape,
            pcs_params,
            spec: link_io_spec(shape.k_log),
            genesis,
            genesis_digest,
        }
    }
}

/// Everything a link exposes to its successor.
pub struct LinkEnvelope {
    pub proof: FieldR1csProof,
    pub commitment: pcs::Commitment,
    pub io: Vec<F128>,
}

/// One link build's inputs: the previous envelope (a class link, or the
/// genesis dummy proof for `genesis = true`) and the digest of the
/// instance that proof was proven over.
pub struct LinkInput<'a> {
    pub prev: &'a LinkEnvelope,
    pub verified_digest: [u8; 32],
    pub genesis: bool,
    /// The matrix the previous proof was proven over — used ONLY by the
    /// native fold prover (T for the genesis link, the class matrix for
    /// regular links). Never enters the trace.
    pub fold_matrix: &'a FieldR1cs,
}

fn alloc_expr(b: &mut FieldR1csBuilder, v: F128) -> LinExpr {
    LinExpr::from_wire(b.alloc_f128(v))
}

/// The genesis arm's baked bilinear check: T's matrices live entirely
/// in block (0,0), so `Σ (α·A_T + B_T)[r,c]·u[r]·v[c]` collapses to
/// `e₀·q₀·(α·Σ_r λ_r·zp_r + (Σ_r λ_r)·zp_0)` with `e₀ = Π(1 + x_i)`,
/// `q₀ = Π(1 + r_i)` — no tensors. Returns the value the deferred
/// fresh claim must equal when `g = 1`.
fn genesis_baked_claim_value(
    b: &mut FieldR1csBuilder,
    genesis: &FieldR1cs,
    fresh: &FreshLincheckClaimTrace,
) -> LinExpr {
    let ell = 1usize << genesis.k_skip;
    let one = LinExpr::constant(F128::ONE);
    let lambda = lagrange_weights_window_trace(b, &fresh.z_skip, 0, ell, 0);
    let mut e0 = LinExpr::constant(F128::ONE);
    for x in &fresh.x_inner_rest {
        e0 = mul(b, &e0, &one.add(x));
    }
    let mut q0 = LinExpr::constant(F128::ONE);
    for r in &fresh.r_inner_rest {
        q0 = mul(b, &q0, &one.add(r));
    }
    let mut a_sum = LinExpr::zero();
    let mut lam_sum = LinExpr::zero();
    for r in 0..ell {
        a_sum = a_sum.add(&mul(b, &lambda[r], &fresh.z_partial[r]));
        lam_sum = lam_sum.add(&lambda[r]);
    }
    let b_sum = mul(b, &lam_sum, &fresh.z_partial[0]);
    let a_part = mul(b, &fresh.alpha, &a_sum);
    let block = a_part.add(&b_sum);
    let eq00 = mul(b, &e0, &q0);
    mul(b, &eq00, &block)
}

/// A built link: the class instance/witness pair (identical instance
/// for every input — the fixed-shape gate asserts it) and the link's
/// IO values.
pub struct BuiltLink {
    pub r1cs: FieldR1cs,
    pub witness: Vec<F128>,
    pub io: Vec<F128>,
}

/// Assemble one link. Runs the NATIVE deferred verification + fold
/// first (all IO values known up front), then builds the trace: IO
/// slice cells first (they ARE the exposed wires), the deferred [R]
/// replay of the previous proof, the genesis arm, the chain pins, and
/// the accumulator-fold twin pinned back to the IO cells.
pub fn build_link(class: &LinkClass, input: &LinkInput<'_>) -> BuiltLink {
    let k_log = class.shape.k_log;
    let layout = link_io_layout(k_log);
    assert_eq!(class.spec.io_len, layout.len);
    assert_eq!(input.prev.io.len(), layout.len, "previous envelope IO");

    // ---- Native pass: deferred verify of the previous proof, then the
    // accumulator fold. Every IO value is known before the trace starts.
    let mut ch_native = FsLaneChallenger::new(b"history-link-v0");
    let (_claims, fresh_native) = noid_ivc_core::verifier::verify_field_deferred_matrix(
        &class.shape,
        &input.verified_digest,
        &input.prev.commitment,
        &input.prev.proof,
        &class.spec,
        &input.prev.io,
        &mut ch_native,
    )
    .expect("link input proof must verify (deferred)");

    let g_own = input.genesis;
    let g_prev = input.prev.io[layout.g];
    let gate_native = !g_own && g_prev == F128::ZERO;
    let incoming_native = MatrixAccClaim {
        point: input.prev.io[layout.acc_point..layout.acc_value].to_vec(),
        value: input.prev.io[layout.acc_value],
    };
    let mut fold_ch_native = FsLaneChallenger::new(b"history-link-fold-v0");
    let (fold_proof, acc_out) = prove_matrix_claim_fold(
        input.fold_matrix,
        &fresh_native,
        &incoming_native,
        gate_native,
        &mut fold_ch_native,
    );

    let digest_lanes = flat_digest_lanes(&input.verified_digest);
    let mut io = vec![F128::ZERO; layout.len];
    io[layout.w_d] = digest_lanes[0];
    io[layout.w_d + 1] = digest_lanes[1];
    io[layout.g] = if g_own { F128::ONE } else { F128::ZERO };
    io[layout.acc_point..layout.acc_value].copy_from_slice(&acc_out.point);
    io[layout.acc_value] = acc_out.value;

    // ---- Trace pass.
    let mut b = FieldR1csBuilder::new();

    // IO slice cells at their fixed dyadic position (wire 0 is the
    // builder's constant-one pin; pad up to the slice start).
    let io_start = class.spec.io_slice.start();
    while b.num_wires() < io_start {
        b.alloc_f128(F128::ZERO);
    }
    let io_cells: Vec<LinExpr> = (0..1usize << class.spec.io_slice.log2_len)
        .map(|t| {
            let v = if t < layout.len { io[t] } else { F128::ZERO };
            alloc_expr(&mut b, v)
        })
        .collect();
    let w_d: FlatDigestExpr = [
        io_cells[layout.w_d].clone(),
        io_cells[layout.w_d + 1].clone(),
    ];
    let g = io_cells[layout.g].clone();

    // Previous envelope wires.
    let prev_root = alloc_flat_digest(&mut b, &input.prev.commitment.root);
    let prev_io_wires: Vec<LinExpr> = input
        .prev
        .io
        .iter()
        .map(|&v| alloc_expr(&mut b, v))
        .collect();
    let proof_e = FieldR1csProofTrace::alloc_shape(
        &mut b,
        &input.prev.proof,
        &class.shape,
        &class.pcs_params,
    );

    // The deferred [R] replay of the previous proof.
    let mut ch = FsChannelTrace::new(&mut b, b"history-link-v0");
    let (_claims_e, fresh) = verify_field_trace_deferred(
        &mut b,
        &mut ch,
        &class.shape,
        &class.pcs_params,
        &w_d,
        &prev_root,
        &proof_e,
        &class.spec,
        &prev_io_wires,
    );

    // ---- Rules.
    let one = LinExpr::constant(F128::ONE);
    let not_g = one.add(&g);
    // g boolean.
    let g_bool = mul(&mut b, &g, &not_g);
    pin_eq(&mut b, &g_bool, &LinExpr::zero());
    // g = 1 ⇒ w_D = D_T.
    let d_t = flat_digest_lanes(&class.genesis_digest);
    for lane in 0..2 {
        let diff = w_d[lane].add(&LinExpr::constant(d_t[lane]));
        let gated = mul(&mut b, &g, &diff);
        pin_eq(&mut b, &gated, &LinExpr::zero());
    }
    // g = 1 ⇒ the deferred claim equals T's baked bilinear value.
    let baked = genesis_baked_claim_value(&mut b, &class.genesis, &fresh);
    let diff = fresh.value.add(&baked);
    let gated = mul(&mut b, &g, &diff);
    pin_eq(&mut b, &gated, &LinExpr::zero());
    // Chain gate and digest inheritance.
    let g_prev_e = prev_io_wires[layout.g].clone();
    let not_g_prev = one.add(&g_prev_e);
    let gate = mul(&mut b, &not_g, &not_g_prev);
    for lane in 0..2 {
        let diff = prev_io_wires[layout.w_d + lane].add(&w_d[lane]);
        let gated = mul(&mut b, &gate, &diff);
        pin_eq(&mut b, &gated, &LinExpr::zero());
    }

    // ---- The accumulator fold twin, pinned to the IO cells.
    let incoming_e = MatrixAccClaimTrace {
        point: prev_io_wires[layout.acc_point..layout.acc_value].to_vec(),
        value: prev_io_wires[layout.acc_value].clone(),
    };
    let fold_proof_e = MatrixFoldProofTrace::alloc(&mut b, &fold_proof, k_log);
    let mut fold_ch = FsChannelTrace::new(&mut b, b"history-link-fold-v0");
    let acc_e = verify_matrix_claim_fold_trace(
        &mut b,
        &mut fold_ch,
        k_log,
        class.shape.k_skip,
        &fresh,
        &incoming_e,
        &gate,
        &fold_proof_e,
    );
    for (i, p) in acc_e.point.iter().enumerate() {
        pin_eq(&mut b, p, &io_cells[layout.acc_point + i]);
    }
    pin_eq(&mut b, &acc_e.value, &io_cells[layout.acc_value]);

    // ---- Pad to the class size (the fixed point: the trace of a class
    // verifier must itself fit the class shape).
    let target = 1usize << class.shape.m;
    assert!(
        b.num_wires() <= target,
        "link trace outgrew the class shape: {} > {}",
        b.num_wires(),
        target
    );
    let used = b.num_wires();
    while b.num_wires() < target {
        b.alloc_f128(F128::ZERO);
    }
    let (r1cs, witness) = b.build();
    assert_eq!(r1cs.m, class.shape.m, "class shape mismatch after padding");
    let _ = used;
    BuiltLink { r1cs, witness, io }
}

/// The decider: natively verify the tip envelope against the class and
/// check the chain terminals — the tip verified THIS class (`w_D =
/// D_B`), is not a genesis link, and its accumulated matrix claim
/// evaluates true against the class matrix.
pub fn decide_tip(
    class: &LinkClass,
    class_r1cs: &FieldR1cs,
    tip: &LinkEnvelope,
) -> Result<(), String> {
    let layout = link_io_layout(class.shape.k_log);
    let mut ch = FsLaneChallenger::new(b"history-link-v0");
    noid_ivc_core::verifier::verify_field_with_public_io(
        class_r1cs,
        &tip.commitment,
        &tip.proof,
        &class.spec,
        &tip.io,
        &mut ch,
    )
    .map_err(|e| format!("tip proof rejected: {e:?}"))?;

    let d_b = flat_digest_lanes(&class_r1cs.statement_digest());
    if tip.io[layout.w_d] != d_b[0] || tip.io[layout.w_d + 1] != d_b[1] {
        return Err("tip did not verify the link class".into());
    }
    if tip.io[layout.g] != F128::ZERO {
        return Err("tip is a genesis link".into());
    }
    let acc = MatrixAccClaim {
        point: tip.io[layout.acc_point..layout.acc_value].to_vec(),
        value: tip.io[layout.acc_value],
    };
    if noid_ivc_core::matrix_claim::stacked_matrix_mle_eval(class_r1cs, &acc) != acc.value {
        return Err("accumulated matrix claim is false".into());
    }
    Ok(())
}
