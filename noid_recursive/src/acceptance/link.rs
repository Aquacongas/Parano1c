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
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};

use super::trace::matrix_fold::{
    verify_matrix_claim_fold_trace, FreshLincheckClaimTrace, MatrixAccClaimTrace,
    MatrixFoldProofTrace,
};
use super::trace::self_verify::{
    alloc_flat_digest, flat_digest_lanes, lagrange_weights_window_trace,
    verify_field_trace_deferred, FieldR1csProofTrace, FlatDigestExpr,
};
use super::trace::region_source_binding::{RegionDischargeParams, RegionPcsClaim};
use super::trace::accepted_claim_batch::digest_lanes;
use super::trace::{flat_of, mul, pin_eq};
use super::block_slots::{
    build_block_slots_with_config, region_wallet_pcs_native, BlockSlots, BlockSlotsConfig,
};
use noid_ivc_prover::field_prover::prove_field_with_public_io;
use crate::accumulator::ChainAccumulator;
use crate::block_certificate_backend::{
    AcceptedBlockBatchComponentInputs, AcceptedBlockBatchComponentProof,
};
use noid_core::Block128;

/// The block chain accumulator as flat IO lanes, in the layout's order.
fn block_acc_lanes(acc: &ChainAccumulator) -> [F128; 5] {
    let sr = digest_lanes(&acc.state_root);
    let ch = digest_lanes(&acc.chain_hash);
    [
        flat_of(Block128::from(acc.height)),
        flat_of(sr[0]),
        flat_of(sr[1]),
        flat_of(ch[0]),
        flat_of(ch[1]),
    ]
}

/// The genesis dummy instance: the link class's SHAPE with all real
/// constraints inside the single top-left `2^k_skip × 2^k_skip` block
/// (`useful_rows = 2^k_skip`), so the genesis arm's baked bilinear check
/// needs no eq tensors — only the block-(0,0) weights. Rows:
/// `z_0·z_0 = z_0` (the constant pin) and `z_r·z_0 = z_r` for the rest
/// of the block.
pub fn genesis_instance(shape: &FieldShape) -> FieldR1cs {
    let k = 1usize << shape.k_log;
    let ell = 1usize << shape.k_skip;
    let a_0 = SparseFieldMatrix::from_rows(
        k,
        (0..k)
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
    );
    let b_0 = SparseFieldMatrix::from_rows(
        k,
        (0..k)
            .map(|r| if r < ell { vec![(0u32, F128::ONE)] } else { vec![] })
            .collect(),
    );
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
///
/// The recursion lanes (`w_d`, `g`, the matrix-claim accumulator) are
/// always present. A BLOCK-BEARING class appends the block chain
/// accumulator `acc_h` (height, state_root, chain_hash) so the decider can
/// anchor the tip against local headers and successive links can chain
/// `start == prev.end`.
#[derive(Clone, Copy, Debug)]
pub struct LinkIoLayout {
    pub w_d: usize,
    pub g: usize,
    pub acc_point: usize,
    pub acc_value: usize,
    pub block_bearing: bool,
    /// Block chain accumulator lanes (only meaningful when block_bearing).
    pub block_height: usize,
    pub block_state_root: usize,
    pub block_chain_hash: usize,
    /// First IO lane of the region wallet-PCS opening-claim tail (== `len`
    /// when there is no region tail).
    pub region_tail_offset: usize,
    /// Number of IO lanes in the region tail (0 when no region tail).
    pub region_len: usize,
    pub len: usize,
}

/// A frozen region wallet-PCS opening-claim descriptor: the committed column
/// slice and the claim point's arity (== `slice.log2_len`). The absolute slice
/// positions are class-deterministic (same params + block structure ⇒ same
/// wire layout), so one freeze is valid for every link in the class;
/// [`build_link`] asserts the live discharge reproduces exactly this shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionFrozenClaim {
    pub slice: WitnessSlice,
    pub arity: usize,
}

/// Region-tail sizing: the number of opening claims and the maximum claim
/// arity, from which every tail lane position is derived.
#[derive(Clone, Copy, Debug)]
pub struct RegionIoShape {
    pub n_claims: usize,
    pub max_arity: usize,
}

pub fn link_io_layout(k_log: usize) -> LinkIoLayout {
    link_io_layout_region(k_log, false, None)
}

pub fn link_io_layout_for(k_log: usize, block_bearing: bool) -> LinkIoLayout {
    link_io_layout_region(k_log, block_bearing, None)
}

/// The full IO layout, with an optional region wallet-PCS opening-claim tail
/// appended after the recursion + block lanes. Each claim occupies
/// `max_arity + 1` lanes (point coordinates padded to `max_arity`, then the
/// opened value). `region = None` reproduces the non-region layout exactly.
pub fn link_io_layout_region(
    k_log: usize,
    block_bearing: bool,
    region: Option<RegionIoShape>,
) -> LinkIoLayout {
    let acc_len = 2 * k_log + 1;
    let recursion_len = 4 + acc_len;
    let block_height = recursion_len;
    let base_len = if block_bearing {
        recursion_len + 5
    } else {
        recursion_len
    };
    let region_len = match region {
        Some(s) => s.n_claims * (s.max_arity + 1),
        None => 0,
    };
    LinkIoLayout {
        w_d: 0,
        g: 2,
        acc_point: 3,
        acc_value: 3 + acc_len,
        block_bearing,
        block_height,
        block_state_root: block_height + 1,
        block_chain_hash: block_height + 3,
        region_tail_offset: base_len,
        region_len,
        len: base_len + region_len,
    }
}

/// The class IO spec: one dyadic slice right after the padding head,
/// no derived claims (the chain pins read lanes as wires directly).
pub fn link_io_spec(k_log: usize) -> PublicIoSpec {
    link_io_spec_for(k_log, false)
}

pub fn link_io_spec_for(k_log: usize, block_bearing: bool) -> PublicIoSpec {
    let layout = link_io_layout_for(k_log, block_bearing);
    let log2_len = layout.len.next_power_of_two().trailing_zeros() as usize;
    PublicIoSpec {
        io_slice: WitnessSlice { log2_len, index: 1 },
        io_len: layout.len,
        claims: vec![],
    }
}

/// The region-mode spec: the base spec plus one derived opening claim per
/// frozen region claim, reading its point coordinates and value out of the
/// region tail lanes. `max_arity` sizes the per-claim lane stride (each
/// point range is only `claim.arity` lanes; the surplus up to `max_arity`
/// is canonical-zero padding the binding claim also constrains).
pub fn link_io_spec_region(
    k_log: usize,
    block_bearing: bool,
    frozen: &[RegionFrozenClaim],
    max_arity: usize,
) -> PublicIoSpec {
    let layout = link_io_layout_region(
        k_log,
        block_bearing,
        Some(RegionIoShape {
            n_claims: frozen.len(),
            max_arity,
        }),
    );
    let log2_len = layout.len.next_power_of_two().trailing_zeros() as usize;
    let stride = max_arity + 1;
    let claims = frozen
        .iter()
        .enumerate()
        .map(|(ci, fc)| {
            let base = layout.region_tail_offset + ci * stride;
            IoClaimSpec {
                slice: fc.slice,
                point: base..base + fc.arity,
                value: base + max_arity,
            }
        })
        .collect();
    PublicIoSpec {
        io_slice: WitnessSlice { log2_len, index: 1 },
        io_len: layout.len,
        claims,
    }
}

/// The link class constants.
pub struct LinkClass {
    pub shape: FieldShape,
    pub pcs_params: PcsParams,
    pub spec: PublicIoSpec,
    pub genesis: FieldR1cs,
    pub genesis_digest: [u8; 32],
    /// True when links in this class carry an accepted block ([B] slots +
    /// the block chain accumulator IO lanes).
    pub block_bearing: bool,
    /// The block accumulator a genesis link starts from (canonical for a
    /// block-bearing class; unused otherwise).
    pub genesis_block_accumulator: ChainAccumulator,
    /// When `Some`, the block [B] slots discharge the wallet-capsule PCS via
    /// the shape-fixed region layer with these parameters, and the resulting
    /// committed-column opening claims are threaded through this class's
    /// public IO (`spec.claims` + the region tail lanes). `None` = no region
    /// discharge (the recursion-ready or pure-stub classes).
    pub region_params: Option<RegionDischargeParams>,
    /// The frozen region opening-claim shape (empty unless `region_params`).
    /// Every link in the class reproduces exactly these `(slice, arity)`
    /// pairs; [`build_link`] asserts it.
    pub region_claims: Vec<RegionFrozenClaim>,
    /// The maximum region claim arity (the per-claim lane stride is
    /// `region_max_arity + 1`).
    pub region_max_arity: usize,
    /// When true, this block-bearing region class verifies each block's
    /// owner-authorization killshots via the shape-fixed KSCHANNL walk-C
    /// discharge (`discharge_owner_auth_killshots_via_region`) — one tiled
    /// data-parallel walk over all K transcripts, so owner-auth verification
    /// is transaction-count flat — instead of the inline per-tx channel replay.
    /// The frozen `region_claims` then include the owner-auth walk-C opening
    /// claims as a PREFIX (before the wallet-PCS claims), so the region IO tail
    /// carries both. Only meaningful when `region_params` is `Some` (the region
    /// owner-auth discharge produces the obligations the wallet-PCS discharge
    /// then consumes).
    pub owner_auth_region: bool,
}

impl LinkClass {
    pub fn new(shape: FieldShape, pcs_params: PcsParams) -> Self {
        let zero_acc = ChainAccumulator {
            height: 0,
            state_root: [0u8; 32],
            chain_hash: [0u8; 32],
        };
        Self::new_configured(shape, pcs_params, false, zero_acc)
    }

    /// A block-bearing class: links carry [B] block slots and chain the
    /// block accumulator, with `genesis_block_accumulator` as the height-0
    /// start the genesis link pins.
    pub fn new_block_bearing(
        shape: FieldShape,
        pcs_params: PcsParams,
        genesis_block_accumulator: ChainAccumulator,
    ) -> Self {
        Self::new_configured(shape, pcs_params, true, genesis_block_accumulator)
    }

    fn new_configured(
        shape: FieldShape,
        pcs_params: PcsParams,
        block_bearing: bool,
        genesis_block_accumulator: ChainAccumulator,
    ) -> Self {
        let genesis = genesis_instance(&shape);
        let genesis_digest = genesis.statement_digest();
        Self {
            shape,
            pcs_params,
            spec: link_io_spec_for(shape.k_log, block_bearing),
            genesis,
            genesis_digest,
            block_bearing,
            genesis_block_accumulator,
            region_params: None,
            region_claims: Vec::new(),
            region_max_arity: 0,
            owner_auth_region: false,
        }
    }

    /// A COMPLETE block-bearing class: like [`Self::new_block_bearing`] but the
    /// wallet-capsule PCS opening is discharged in the shape-fixed region layer
    /// and its committed-column opening claims are threaded through the class's
    /// public IO, so every link is a complete (no shape-drift) block proof.
    ///
    /// The region claim SHAPE (how many claims, their column slices and
    /// arities) is frozen ONCE here by building one sample block-bearing link
    /// trace and reading its live discharge. `sample_block` must be a block of
    /// the same tier every link in the class carries; its accumulators/config
    /// are otherwise unused (the discharge config is forced to the region
    /// path). The freeze runs a full link build (including a genesis dummy
    /// proof over the class shape) — the caller runs this off any block; the
    /// resulting class is reused for the whole chain.
    ///
    /// `owner_auth_region` selects whether each block's owner-authorization
    /// killshots are ALSO verified in the region (the transaction-count-flat
    /// KSCHANNL walk-C discharge) rather than the inline per-tx replay. When
    /// true, the frozen region claim shape gains the owner-auth walk-C opening
    /// claims (a prefix before the wallet-PCS claims), so the freeze probe
    /// captures the FULL claim count and every link discharges owner-auth flatly.
    pub fn new_region_block_bearing(
        shape: FieldShape,
        pcs_params: PcsParams,
        genesis_block_accumulator: ChainAccumulator,
        region_params: RegionDischargeParams,
        sample_block: &LinkBlock<'_>,
        owner_auth_region: bool,
    ) -> Self {
        freeze_region_block_bearing(
            shape,
            pcs_params,
            genesis_block_accumulator,
            region_params,
            sample_block,
            owner_auth_region,
        )
    }

    /// The full IO layout, region tail included when this is a region class.
    /// Derived from `spec.io_len` so it is correct in every construction phase
    /// (the freeze uses a placeholder-claim spec of the same size).
    fn layout(&self) -> LinkIoLayout {
        let mut l = link_io_layout_for(self.shape.k_log, self.block_bearing);
        if self.region_params.is_some() {
            // The region tail is everything in `spec.io_len` past the base
            // recursion + block lanes.
            l.region_tail_offset = l.len;
            l.region_len = self.spec.io_len - l.len;
            l.len = self.spec.io_len;
        }
        l
    }

    /// The block-slot config a region class forces on every link: the region
    /// wallet-PCS discharge with the class parameters.
    fn block_config(&self, block: &LinkBlock<'_>) -> BlockSlotsConfig {
        match self.region_params {
            Some(params) => BlockSlotsConfig {
                discharge_wallet_pcs: true,
                wallet_pcs_region: Some(params),
                owner_auth_region: self.owner_auth_region,
            },
            None => block.config,
        }
    }
}

/// The block content a block-bearing link verifies: the single-block
/// component objects plus the block's accumulator boundary. The [R] leg
/// is unchanged; this is the [B] leg.
pub struct LinkBlock<'a> {
    pub start_accumulator: &'a ChainAccumulator,
    pub end_accumulator: &'a ChainAccumulator,
    pub inputs: &'a AcceptedBlockBatchComponentInputs,
    pub proof: &'a AcceptedBlockBatchComponentProof,
    pub config: BlockSlotsConfig,
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
    /// The accepted block this link verifies (required for a block-bearing
    /// class, `None` for a pure-recursion stub class).
    pub block: Option<LinkBlock<'a>>,
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
    /// The live region wallet-PCS opening claims produced by the block-slot
    /// discharge (empty for non-region classes). The region freeze reads their
    /// slices; a region-mode `build_link` also asserts they match the frozen
    /// shape and pins them to the region IO tail.
    pub region_claims: Vec<RegionPcsClaim>,
}

/// Assemble one link. Runs the NATIVE deferred verification + fold
/// first (all IO values known up front), then builds the trace: IO
/// slice cells first (they ARE the exposed wires), the deferred [R]
/// replay of the previous proof, the genesis arm, the chain pins, and
/// the accumulator-fold twin pinned back to the IO cells.
///
/// For a REGION-MODE class (`region_params` set + a frozen `region_claims`
/// shape) the block-slot wallet-PCS discharge is class-fixed and its
/// committed-column opening claims are threaded through the public-IO tail:
/// each claim's `(point, value)` wires are pinned to the tail IO cells, and
/// `class.spec.claims` (a class constant) turns them into opening claims on
/// the previous link's committed columns when the NEXT link replays this one.
pub fn build_link(class: &LinkClass, input: &LinkInput<'_>) -> BuiltLink {
    build_link_inner(class, input, false)
}

/// [`build_link`] core. `freeze = true` is the region shape-freeze pass: the
/// class carries `region_params` but an empty `region_claims`, so the live
/// discharge is captured and RETURNED (`BuiltLink::region_claims`) WITHOUT the
/// frozen-shape assert or the region IO-tail pinning (the tail lanes stay
/// zero). The caller reads the live claim slices to build the class's frozen
/// shape and its real spec.
fn build_link_inner(class: &LinkClass, input: &LinkInput<'_>, freeze: bool) -> BuiltLink {
    let region_mode = class.region_params.is_some();
    let k_log = class.shape.k_log;
    let layout = class.layout();
    assert_eq!(class.spec.io_len, layout.len);
    assert_eq!(input.prev.io.len(), layout.len, "previous envelope IO");
    assert_eq!(
        input.block.is_some(),
        class.block_bearing,
        "block presence must match the class"
    );

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
    if let Some(block) = &input.block {
        let lanes = block_acc_lanes(block.end_accumulator);
        io[layout.block_height] = lanes[0];
        io[layout.block_state_root] = lanes[1];
        io[layout.block_state_root + 1] = lanes[2];
        io[layout.block_chain_hash] = lanes[3];
        io[layout.block_chain_hash + 1] = lanes[4];
    }

    // ---- Region wallet-PCS opening claims: NATIVE values into the IO tail.
    // The tail IO cells must hold exactly the region opening claims'
    // (point, value) that the in-trace discharge produces, so the tail pins
    // below are satisfiable. Those values are a deterministic function of the
    // block content (independent of the builder), so a throwaway discharge in
    // a scratch builder recovers them before the real trace allocates the IO
    // cells. Only in REAL region mode; the freeze leaves the tail zero.
    if region_mode && !freeze {
        let block = input.block.as_ref().expect("region class requires a block");
        let params = class.region_params.expect("region mode has params");
        // Recover the region claims' native (point, value) via an auth-only
        // scratch discharge (NOT the whole block slots — the block-[B] killshots
        // are irrelevant to the region values). The count must match the frozen
        // class shape; the full trace pass below re-derives the same claims with
        // their wires + slices and asserts the complete shape.
        let region_native =
            region_wallet_pcs_native(block.inputs, params, class.block_config(block).owner_auth_region);
        assert_eq!(
            region_native.len(),
            class.region_claims.len(),
            "region native claim count {} != frozen {}",
            region_native.len(),
            class.region_claims.len()
        );
        let stride = class.region_max_arity + 1;
        for (ci, (np, nv)) in region_native.iter().enumerate() {
            let base = layout.region_tail_offset + ci * stride;
            assert!(np.len() <= class.region_max_arity, "region claim arity over max");
            for (kk, &p) in np.iter().enumerate() {
                io[base + kk] = p;
            }
            io[base + class.region_max_arity] = *nv;
        }
    }

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

    // ---- Block [B] slots (block-bearing class only).
    let mut live_region: Vec<RegionPcsClaim> = Vec::new();
    if let Some(block) = &input.block {
        let cfg = class.block_config(block);
        let mut slots: BlockSlots = build_block_slots_with_config(
            &mut b,
            block.start_accumulator,
            block.end_accumulator,
            block.inputs,
            block.proof,
            cfg,
        );
        live_region = std::mem::take(&mut slots.pending_wallet_pcs);
        // The block's end accumulator IS this link's exposed block_acc.
        let end_lanes = [
            &slots.end_acc.height,
            &slots.end_acc.state_root[0],
            &slots.end_acc.state_root[1],
            &slots.end_acc.chain_hash[0],
            &slots.end_acc.chain_hash[1],
        ];
        let io_end = [
            layout.block_height,
            layout.block_state_root,
            layout.block_state_root + 1,
            layout.block_chain_hash,
            layout.block_chain_hash + 1,
        ];
        for (w, &cell) in end_lanes.iter().zip(io_end.iter()) {
            pin_eq(&mut b, w, &io_cells[cell]);
        }
        // Chain the block start accumulator:
        //   genesis (g = 1): start == the class genesis block accumulator;
        //   otherwise:       start == the PREVIOUS link's exposed block_acc.
        let start_lanes = [
            &slots.start_acc.height,
            &slots.start_acc.state_root[0],
            &slots.start_acc.state_root[1],
            &slots.start_acc.chain_hash[0],
            &slots.start_acc.chain_hash[1],
        ];
        let genesis_start = block_acc_lanes(&class.genesis_block_accumulator);
        let prev_block_io = [
            layout.block_height,
            layout.block_state_root,
            layout.block_state_root + 1,
            layout.block_chain_hash,
            layout.block_chain_hash + 1,
        ];
        for (i, sw) in start_lanes.iter().enumerate() {
            // g · (start - genesis_const) = 0.
            let to_genesis = (*sw).add(&LinExpr::constant(genesis_start[i]));
            let g_gated = mul(&mut b, &g, &to_genesis);
            pin_eq(&mut b, &g_gated, &LinExpr::zero());
            // (1 + g) · (start - prev_block_acc) = 0.
            let to_prev = (*sw).add(&prev_io_wires[prev_block_io[i]]);
            let ng_gated = mul(&mut b, &not_g, &to_prev);
            pin_eq(&mut b, &ng_gated, &LinExpr::zero());
        }

        // ---- Region wallet-PCS opening claims → the public-IO tail. Assert
        // the live discharge reproduces the frozen class shape (slices AND
        // arities — same builder context as the freeze), then pin each claim's
        // point/value wires to the tail IO cells. `class.spec.claims` (a class
        // constant) turns those tail lanes into opening claims on THIS link's
        // committed columns when its successor replays it. Skipped in the
        // freeze pass (which only reads the live slices).
        if region_mode && !freeze {
            assert_eq!(
                live_region.len(),
                class.region_claims.len(),
                "region claim count drift (trace): live {} vs frozen {}",
                live_region.len(),
                class.region_claims.len()
            );
            let stride = class.region_max_arity + 1;
            for (ci, c) in live_region.iter().enumerate() {
                let fc = &class.region_claims[ci];
                assert_eq!(c.slice, fc.slice, "region claim {ci} slice drift (trace)");
                assert_eq!(c.point.len(), fc.arity, "region claim {ci} arity drift (trace)");
                let base = layout.region_tail_offset + ci * stride;
                for (kk, p) in c.point.iter().enumerate() {
                    pin_eq(&mut b, p, &io_cells[base + kk]);
                }
                pin_eq(&mut b, &c.value, &io_cells[base + class.region_max_arity]);
            }
        }
    }

    // ---- Pad to the class size (the fixed point: the trace of a class
    // verifier must itself fit the class shape).
    let target = 1usize << class.shape.m;
    let used = b.num_wires();
    eprintln!(
        "[link] build_link: {used} wires (region_mode={region_mode}, freeze={freeze}, \
         region_claims={})",
        live_region.len()
    );
    if region_mode {
        // Memory guard: a region block-bearing link must stay well under 2^24
        // wires (a runaway combined trace once OOM'd at ~30 GB).
        assert!(used < (1usize << 24), "region link wire guard: {used} >= 2^24");
    }
    assert!(
        used <= target,
        "link trace outgrew the class shape: {used} > {target}"
    );
    while b.num_wires() < target {
        b.alloc_f128(F128::ZERO);
    }
    let (r1cs, witness) = b.build();
    assert_eq!(r1cs.m, class.shape.m, "class shape mismatch after padding");
    BuiltLink {
        r1cs,
        witness,
        io,
        region_claims: live_region,
    }
}

/// Freeze the region opening-claim shape for a COMPLETE block-bearing class.
///
/// The region discharge's claim COUNT and ARITIES are class constants
/// (functions of the wallet-proof shape + `region_params`, not the block
/// content), so a cheap standalone discharge recovers them. But the absolute
/// column SLICES depend on the whole link wire layout, so we build one full
/// link (a genesis link over `sample_block`, in freeze mode against a
/// placeholder-claim spec of the correct size) and read the live discharge
/// slices. The placeholder spec has the SAME claim COUNT and IO-slice size as
/// the final spec, so the link wire layout — hence every region slice — is
/// identical to every real build in the class; [`build_link`] re-asserts it.
fn freeze_region_block_bearing(
    shape: FieldShape,
    pcs_params: PcsParams,
    genesis_block_accumulator: ChainAccumulator,
    region_params: RegionDischargeParams,
    sample_block: &LinkBlock<'_>,
    owner_auth_region: bool,
) -> LinkClass {
    let region_cfg = BlockSlotsConfig {
        discharge_wallet_pcs: true,
        wallet_pcs_region: Some(region_params),
        owner_auth_region,
    };

    // ---- Probe: a standalone discharge reveals the claim count + arities.
    let (n_claims, arities, max_arity) = {
        let mut pb = FieldR1csBuilder::new();
        let slots = build_block_slots_with_config(
            &mut pb,
            sample_block.start_accumulator,
            sample_block.end_accumulator,
            sample_block.inputs,
            sample_block.proof,
            region_cfg,
        );
        let arities: Vec<usize> = slots.pending_wallet_pcs.iter().map(|c| c.point.len()).collect();
        let max_arity = arities.iter().copied().max().unwrap_or(0);
        (arities.len(), arities, max_arity)
    };
    assert!(n_claims > 0, "region discharge produced no opening claims");

    let genesis_digest = genesis_instance(&shape).statement_digest();

    // ---- Placeholder spec: N claims of the right arities, pointing at safe
    // all-zero columns of the genesis dummy (index 1 excludes the const-one
    // wire 0). It shares the final spec's claim count + IO-slice size, so the
    // freeze build reproduces the real link's wire layout exactly.
    let placeholders: Vec<RegionFrozenClaim> = arities
        .iter()
        .map(|&a| RegionFrozenClaim {
            slice: WitnessSlice { log2_len: a, index: 1 },
            arity: a,
        })
        .collect();
    let freeze_spec = link_io_spec_region(shape.k_log, true, &placeholders, max_arity);

    let freeze_class = LinkClass {
        shape,
        pcs_params: pcs_params.clone(),
        spec: freeze_spec,
        genesis: genesis_instance(&shape),
        genesis_digest,
        block_bearing: true,
        genesis_block_accumulator: genesis_block_accumulator.clone(),
        region_params: Some(region_params),
        region_claims: Vec::new(),
        region_max_arity: max_arity,
        owner_auth_region,
    };

    // ---- Genesis dummy T + its proof over the placeholder spec (all-zero IO,
    // so every placeholder claim opens an all-zero column to zero — satisfied
    // by the single-block genesis witness).
    let t_witness = genesis_witness(&shape);
    let t_io = vec![F128::ZERO; freeze_class.spec.io_len];
    let mut ch = FsLaneChallenger::new(b"history-link-v0");
    let (t_proof, t_commitment, _) = prove_field_with_public_io(
        &freeze_class.genesis,
        &t_witness,
        &pcs_params,
        &freeze_class.spec,
        &t_io,
        &mut ch,
    );
    let env_t = LinkEnvelope {
        proof: t_proof,
        commitment: t_commitment,
        io: t_io,
    };

    // ---- Freeze build: a genesis link over the sample block, freeze mode.
    let freeze_block = LinkBlock {
        start_accumulator: sample_block.start_accumulator,
        end_accumulator: sample_block.end_accumulator,
        inputs: sample_block.inputs,
        proof: sample_block.proof,
        config: region_cfg,
    };
    let built = build_link_inner(
        &freeze_class,
        &LinkInput {
            prev: &env_t,
            verified_digest: genesis_digest,
            genesis: true,
            fold_matrix: &freeze_class.genesis,
            block: Some(freeze_block),
        },
        true,
    );
    let frozen: Vec<RegionFrozenClaim> = built
        .region_claims
        .iter()
        .map(|c| RegionFrozenClaim {
            slice: c.slice,
            arity: c.point.len(),
        })
        .collect();
    assert_eq!(frozen.len(), n_claims, "freeze claim count mismatch");
    drop(built);

    // ---- The real spec (frozen slices) + the final class.
    let real_spec = link_io_spec_region(shape.k_log, true, &frozen, max_arity);
    LinkClass {
        shape,
        pcs_params,
        spec: real_spec,
        genesis: genesis_instance(&shape),
        genesis_digest,
        block_bearing: true,
        genesis_block_accumulator,
        region_params: Some(region_params),
        region_claims: frozen,
        region_max_arity: max_arity,
        owner_auth_region,
    }
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
    let layout = class.layout();
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

/// The tip's exposed block chain accumulator (block-bearing class only) —
/// the value a fresh peer anchors against its locally validated headers
/// (I8). Returns `None` for a non-block-bearing class.
pub fn tip_block_accumulator(class: &LinkClass, tip: &LinkEnvelope) -> Option<ChainAccumulator> {
    if !class.block_bearing {
        return None;
    }
    let layout = class.layout();
    let lane_bytes = |a: F128, b: F128| -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&flat_to_block(a).to_le_bytes());
        out[16..].copy_from_slice(&flat_to_block(b).to_le_bytes());
        out
    };
    Some(ChainAccumulator {
        height: flat_to_block(tip.io[layout.block_height]) as u64,
        state_root: lane_bytes(
            tip.io[layout.block_state_root],
            tip.io[layout.block_state_root + 1],
        ),
        chain_hash: lane_bytes(
            tip.io[layout.block_chain_hash],
            tip.io[layout.block_chain_hash + 1],
        ),
    })
}

/// Recover the u128 a flat IO lane encodes (the inverse of `flat_of` on an
/// integer/digest-lane `Block128`).
fn flat_to_block(v: F128) -> u128 {
    use noid_core::hardware::flat_to_tower_u128;
    flat_to_tower_u128((v.lo as u128) | ((v.hi as u128) << 64))
}
