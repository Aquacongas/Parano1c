// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The SPLIT self-verification link — the link half of the two-level π.
//!
//! A split link verifies TWO proofs: the previous link (same link shape,
//! possibly a different link class) and one block proof `π_block` (the
//! standalone block class of this link class's ladder slot,
//! [`super::block_class`]). The block classes live on a LADDER of shapes
//! (one capacity per shape — an [R] replay's transcript schedule is
//! structural in the verified shape and spec, so each link class hosts
//! exactly one block class); all link classes share ONE shape and ONE
//! public-IO spec, so `[R]_prev` is structurally identical everywhere and
//! only baked constants differ per class (its slot's block-class digest
//! and spec).
//!
//! Nothing of any LINK class is baked into a link matrix. The ladder's
//! link-class digests ride the public IO as a WHITELIST lane block that
//! every non-genesis link inherits unchanged from its predecessor and the
//! decider pins natively at the tip; the digest `[R]_prev` verifies
//! against is derived as `Σ_a β_a·WL_a + g·D_T` from one-hot selector
//! bits `β` (`Σ β_a = 1 + g`), which also subsumes the genesis digest
//! rule. The block-class digest IS baked (the block class has no
//! self-reference, so it is an ordinary protocol constant).
//!
//! Deferred matrix claims accumulate in PER-MATRIX LANES: one lane per
//! link class plus one lane per block class, each `2·k_log + 1` point
//! lanes, a value lane and a LIVENESS bit. A link runs exactly TWO fold
//! twins — the `[R]_prev` claim folds into the β-muxed link lane, the
//! `[R]_B` claim into its own slot's block lane — and pins every other
//! lane through unchanged. Liveness is monotone (`out = sel OR in`),
//! starts dead at the chain root (the genesis dummy T carries all-zero
//! IO) and gates each fold's incoming claim: the old genesis gating,
//! generalized per lane. A selected lane's outgoing liveness is
//! identically 1 (char-2 OR against any incoming value), so a malicious
//! T cannot un-mark a folded claim; extra live lanes planted via T's
//! unconstrained IO can only ADD claims the decider then evaluates —
//! rejection-only power.
//!
//! Chain rules: the block proof's exposed `start_acc` must equal the
//! previous link's exposed block accumulator (or the class's genesis
//! accumulator under `g = 1`), and its `end_acc` is pinned to this
//! link's own block-accumulator IO. Block-internal transition validity
//! (state roots, heights, the chain hash) is the block class's job.
//!
//! The decider verifies the tip natively against its published class
//! matrix, pins the whitelist lanes to the true link-class digests,
//! rejects genesis tips, and evaluates each LIVE lane's accumulated
//! claim against that lane's matrix — one native MLE pass per USED
//! matrix; dead lanes need no matrix at all.

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, FsChannelTrace, LinExpr};
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::matrix_claim::{
    prove_matrix_claim_fold, stacked_matrix_mle_eval, MatrixAccClaim,
};
use noid_ivc_core::pcs::PcsParams;
use noid_ivc_core::proof::FieldShape;
use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};

use super::block_class::{BlockClass, BLOCK_IO_END_ACC, BLOCK_IO_START_ACC};
use super::link::{
    block_acc_lanes, genesis_baked_claim_value, genesis_instance, genesis_witness,
    LinkEnvelope, RegionFrozenClaim,
};
use super::trace::matrix_fold::{
    verify_matrix_claim_fold_trace, MatrixAccClaimTrace, MatrixFoldProofTrace,
};
use super::trace::r_pcs_region::{
    alloc_r_pcs_columns, discharge_r_pcs_via_region, r_pcs_region_native, RPcsProof,
};
use super::trace::self_verify::{
    alloc_flat_digest, flat_digest_lanes, verify_field_trace_deferred_region,
    FieldR1csProofTrace, FlatDigestExpr, PcsWalkObligations,
};
use super::trace::{mul, pin_eq};
use crate::accumulator::ChainAccumulator;
use noid_ivc_core::public_io::IoClaimSpec;
use noid_ivc_prover::field_prover::prove_field_with_public_io;

/// One ladder slot's protocol constants, as seen by EVERY link class (the
/// lane widths must be known to lay out the shared IO). The full block
/// spec is only needed by the slot's OWN link class.
#[derive(Clone, Copy, Debug)]
pub struct LadderSlotInfo {
    /// The consensus user-tx capacity this slot hosts.
    pub tier: usize,
    /// The block class shape (fixes the slot's fold-lane width).
    pub b_shape: FieldShape,
    /// The block class statement digest ([R]_B verifies against it; baked
    /// into the slot's link-class matrix).
    pub b_digest: [u8; 32],
}

/// Offsets of one per-matrix accumulator lane within the link IO.
#[derive(Clone, Copy, Debug)]
pub struct SplitLaneLayout {
    /// First point coordinate (`2·k_log + 1` lanes).
    pub point: usize,
    /// The accumulated claim value.
    pub value: usize,
    /// The liveness bit (0 = lane dead/unused, 1 = carries a claim).
    pub live: usize,
}

impl SplitLaneLayout {
    fn new(offset: usize, k_log: usize) -> (Self, usize) {
        let point_len = 2 * k_log + 1;
        (
            Self {
                point: offset,
                value: offset + point_len,
                live: offset + point_len + 1,
            },
            offset + point_len + 2,
        )
    }
}

/// The split-link public-IO layout, shared by every link class of a
/// ladder: `[g | whitelist (2 lanes per slot) | link lanes | block
/// lanes | block_acc (ACC_LANES)]`.
#[derive(Clone, Debug)]
pub struct SplitIoLayout {
    pub g: usize,
    /// First whitelist lane (`2 · n_slots` lanes: the link-class
    /// statement digests, inherited along the chain).
    pub wl: usize,
    /// Per-link-class accumulator lanes (all at the link k_log).
    pub link_lanes: Vec<SplitLaneLayout>,
    /// Per-block-class accumulator lanes (slot-specific k_log).
    pub b_lanes: Vec<SplitLaneLayout>,
    /// The covered block's end accumulator ([`ACC_LANES`] lanes).
    pub block_acc: usize,
    /// First lane of the [R]-PCS walk opening-claim tail.
    pub region_tail_offset: usize,
    /// Region tail length (`n_claims × (max_arity + 1)`).
    pub region_len: usize,
    pub len: usize,
}

pub fn split_io_layout(
    link_k_log: usize,
    ladder: &[LadderSlotInfo],
    n_claims: usize,
    max_arity: usize,
) -> SplitIoLayout {
    let n = ladder.len();
    let g = 0usize;
    let wl = 1usize;
    let mut off = wl + 2 * n;
    let mut link_lanes = Vec::with_capacity(n);
    for _ in 0..n {
        let (lane, next) = SplitLaneLayout::new(off, link_k_log);
        link_lanes.push(lane);
        off = next;
    }
    let mut b_lanes = Vec::with_capacity(n);
    for slot in ladder {
        let (lane, next) = SplitLaneLayout::new(off, slot.b_shape.k_log);
        b_lanes.push(lane);
        off = next;
    }
    let region_tail_offset = off + super::link::ACC_LANES;
    let region_len = n_claims * (max_arity + 1);
    SplitIoLayout {
        g,
        wl,
        link_lanes,
        b_lanes,
        block_acc: off,
        region_tail_offset,
        region_len,
        len: region_tail_offset + region_len,
    }
}

/// The shared spec: one dyadic IO slice plus one derived opening claim
/// per frozen [R]-PCS walk claim, reading its point/value out of the
/// region tail lanes (identical mechanics to the block class's spec —
/// the successor's `[R]_prev` replay enforces the walk claims against
/// THIS link's committed walk columns).
pub fn split_io_spec(
    link_k_log: usize,
    ladder: &[LadderSlotInfo],
    frozen: &[RegionFrozenClaim],
    max_arity: usize,
) -> PublicIoSpec {
    let layout = split_io_layout(link_k_log, ladder, frozen.len(), max_arity);
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

/// One ladder slot's LINK class constants.
pub struct SplitLinkClass {
    /// The link shape — identical for every class of the ladder.
    pub shape: FieldShape,
    pub pcs_params: PcsParams,
    /// The shared spec (identical across the ladder's link classes).
    pub spec: PublicIoSpec,
    /// Statement digest of THIS class's matrix — filled by the first
    /// build, seeded into every later instance.
    pub class_statement_digest: std::sync::OnceLock<[u8; 32]>,
    /// The genesis dummy T (shape + spec constants only — one T proof
    /// serves every class of the ladder).
    pub genesis: FieldR1cs,
    pub genesis_digest: [u8; 32],
    /// The block accumulator a genesis link's block must start from.
    pub genesis_block_accumulator: ChainAccumulator,
    pub ladder: Vec<LadderSlotInfo>,
    /// This class's ladder slot (selects the hosted block class).
    pub slot: usize,
    /// The slot's block-class spec ([R]_B replays it; a baked structural
    /// constant of this class).
    pub b_spec: PublicIoSpec,
    /// The slot's block-class PCS parameters.
    pub b_pcs_params: PcsParams,
    /// The frozen [R]-PCS walk opening-claim shape; every build
    /// reproduces exactly these `(slice, arity)` pairs.
    pub region_claims: Vec<RegionFrozenClaim>,
    pub region_max_arity: usize,
}

impl SplitLinkClass {
    /// Freeze the slot's link class from the (already frozen AND once
    /// built — the digest must exist) block class plus one sample
    /// `π_block` envelope of the slot. Mirrors the block class's freeze
    /// discipline for the [R]-PCS walk claims:
    ///
    /// 1. a BOOTSTRAP T proof (claimless base spec) feeds the native
    ///    probe [`r_pcs_region_native`] — walk claim COUNT and ARITIES
    ///    are functions of the two PCS parameter sets alone, which fixes
    ///    the IO layout;
    /// 2. a placeholder-claim spec of the final size, a second T proof
    ///    over it, and one FREEZE-mode build (tail zeros, no tail pins)
    ///    reveal the claims' committed-column SLICES — the freeze build
    ///    shares the real builds' wire layout because the placeholder
    ///    spec has the same claim count and IO-slice size;
    /// 3. the real spec re-freezes the claims at their live slices.
    ///
    /// The class MATRIX is created by the first real build (the freeze
    /// matrix omits the tail pin rows) and every later build must
    /// reproduce it bit-exactly (I1; the per-class fixity gates).
    pub fn freeze(
        shape: FieldShape,
        pcs_params: PcsParams,
        genesis_block_accumulator: ChainAccumulator,
        ladder: Vec<LadderSlotInfo>,
        slot: usize,
        block_class: &BlockClass,
        sample_block: &LinkEnvelope,
        block_matrix: &FieldR1cs,
    ) -> Self {
        assert!(slot < ladder.len(), "slot out of ladder");
        assert_eq!(ladder[slot].b_shape, block_class.shape, "slot shape vs block class");
        let b_digest = *block_class
            .class_statement_digest
            .get()
            .expect("block class digest requires one real block build");
        assert_eq!(ladder[slot].b_digest, b_digest, "slot digest vs block class");
        let genesis = genesis_instance(&shape);
        // statement_digest() also warms the instance's digest cache, so
        // every T prove reads it instead of re-hashing the serialization.
        let genesis_digest = genesis.statement_digest();

        // ---- Phase 1: bootstrap T proof + native probe → count/arities.
        let base_spec = split_io_spec(shape.k_log, &ladder, &[], 0);
        let t_witness = genesis_witness(&shape);
        let t_io = vec![F128::ZERO; base_spec.io_len];
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (t_proof, t_commitment, _) = prove_field_with_public_io(
            &genesis,
            &t_witness,
            &pcs_params,
            &base_spec,
            &t_io,
            &mut ch,
        );
        let probe = r_pcs_region_native(&[
            RPcsProof {
                native: &t_proof.pcs_open,
                params: &pcs_params,
                commitment_root: flat_digest_lanes(&t_commitment.root),
            },
            RPcsProof {
                native: &sample_block.proof.pcs_open,
                params: &block_class.pcs_params,
                commitment_root: flat_digest_lanes(&sample_block.commitment.root),
            },
        ]);
        let arities: Vec<usize> = probe.iter().map(|(pt, _)| pt.len()).collect();
        let max_arity = arities.iter().copied().max().unwrap_or(0);
        assert!(!arities.is_empty(), "walk discharge produced no opening claims");

        // ---- Phase 2: placeholder spec + freeze-mode genesis build.
        let placeholders: Vec<RegionFrozenClaim> = arities
            .iter()
            .map(|&a| RegionFrozenClaim {
                slice: WitnessSlice { log2_len: a, index: 1 },
                arity: a,
            })
            .collect();
        let freeze_class = Self {
            shape,
            pcs_params: pcs_params.clone(),
            spec: split_io_spec(shape.k_log, &ladder, &placeholders, max_arity),
            class_statement_digest: std::sync::OnceLock::new(),
            genesis,
            genesis_digest,
            genesis_block_accumulator: genesis_block_accumulator.clone(),
            ladder,
            slot,
            b_spec: block_class.spec.clone(),
            b_pcs_params: block_class.pcs_params.clone(),
            region_claims: placeholders,
            region_max_arity: max_arity,
        };
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
        let built = build_split_link_inner(
            &freeze_class,
            &SplitLinkInput {
                prev: &env_t,
                verified_digest: freeze_class.genesis_digest,
                prev_slot: 0,
                genesis: true,
                link_class_digests: vec![[0u8; 32]; freeze_class.ladder.len()],
                block: sample_block,
                fold_matrix_link: &freeze_class.genesis,
                fold_matrix_block: block_matrix,
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
        assert_eq!(frozen.len(), arities.len(), "freeze claim count vs native probe");
        drop(built);

        // ---- Phase 3: the real spec (frozen slices).
        let spec = split_io_spec(shape.k_log, &freeze_class.ladder, &frozen, max_arity);
        Self {
            spec,
            class_statement_digest: std::sync::OnceLock::new(),
            region_claims: frozen,
            ..freeze_class
        }
    }

    pub fn layout(&self) -> SplitIoLayout {
        split_io_layout(
            self.shape.k_log,
            &self.ladder,
            self.region_claims.len(),
            self.region_max_arity,
        )
    }
}

/// One split-link build's inputs.
pub struct SplitLinkInput<'a> {
    /// The previous link envelope (or the genesis dummy T's proof when
    /// `genesis = true`).
    pub prev: &'a LinkEnvelope,
    /// Digest of the instance `prev` was proven over (`D_T` at genesis,
    /// else the previous link class's statement digest — must equal the
    /// whitelist entry at `prev_slot`).
    pub verified_digest: [u8; 32],
    /// The previous link's ladder slot (drives β; ignored at genesis).
    pub prev_slot: usize,
    pub genesis: bool,
    /// The whitelist values: every ladder slot's LINK-class statement
    /// digest. Witness data (never baked); the decider pins the tip's.
    /// A throwaway matrix-derivation build passes zeros.
    pub link_class_digests: Vec<[u8; 32]>,
    /// The covered block's proof envelope (`π_block`, this class's slot).
    pub block: &'a LinkEnvelope,
    /// The matrix the PREVIOUS proof was proven over — native fold
    /// prover only (T at genesis, else the previous link class's
    /// matrix). Never enters the trace.
    pub fold_matrix_link: &'a FieldR1cs,
    /// The slot's block-class matrix — native fold prover only.
    pub fold_matrix_block: &'a FieldR1cs,
}

/// A built split link.
pub struct BuiltSplitLink {
    pub r1cs: FieldR1cs,
    pub witness: Vec<F128>,
    pub io: Vec<F128>,
    /// The live [R]-PCS walk opening claims (the freeze pass reads their
    /// slices; real builds assert them against the frozen class shape).
    pub region_claims: Vec<super::trace::region_source_binding::RegionPcsClaim>,
}

fn alloc_expr(b: &mut FieldR1csBuilder, v: F128) -> LinExpr {
    LinExpr::from_wire(b.alloc_f128(v))
}

/// Assemble one split link. Native pass first (both deferred verifies +
/// both folds — every IO value is known before the trace starts), then
/// the trace: IO cells, both envelopes, the two [R] replays IN REGION
/// MODE (path-free — their PCS hashing lands on the link's two walks),
/// the chain rules, the two fold twins, the lane routing pins, the walk
/// discharge and the region-tail pins.
pub fn build_split_link(class: &SplitLinkClass, input: &SplitLinkInput<'_>) -> BuiltSplitLink {
    build_split_link_inner(class, input, false)
}

/// [`build_split_link`] core. `freeze = true` is the walk-claim
/// shape-freeze pass: the region tail stays zero and UNPINNED (the
/// freeze matrix omits those rows) and the live claims are returned for
/// the class to freeze; the class digest is never seeded.
fn build_split_link_inner(
    class: &SplitLinkClass,
    input: &SplitLinkInput<'_>,
    freeze: bool,
) -> BuiltSplitLink {
    let layout = class.layout();
    let n = class.ladder.len();
    let k_l = class.shape.k_log;
    let slot = class.slot;
    let b_shape = class.ladder[slot].b_shape;
    assert_eq!(class.spec.io_len, layout.len);
    assert_eq!(input.prev.io.len(), layout.len, "previous envelope IO");
    assert_eq!(input.block.io.len(), class.b_spec.io_len, "block envelope IO");
    assert_eq!(input.link_class_digests.len(), n, "whitelist size");
    assert!(input.genesis || input.prev_slot < n, "prev slot out of ladder");

    // ---- Native pass.
    let mut ch_native = FsLaneChallenger::new(b"history-link-v0");
    let (_pc, fresh_link) = noid_ivc_core::verifier::verify_field_deferred_matrix(
        &class.shape,
        &input.verified_digest,
        &input.prev.commitment,
        &input.prev.proof,
        &class.spec,
        &input.prev.io,
        &mut ch_native,
    )
    .expect("previous link proof must verify (deferred)");
    let mut chb_native = FsLaneChallenger::new(b"history-block-v0");
    let (_bc, fresh_block) = noid_ivc_core::verifier::verify_field_deferred_matrix(
        &b_shape,
        &class.ladder[slot].b_digest,
        &input.block.commitment,
        &input.block.proof,
        &class.b_spec,
        &input.block.io,
        &mut chb_native,
    )
    .expect("block proof must verify (deferred)");

    // Link-lane fold: incoming = the β-selected lane of the previous IO
    // (identically zero at genesis — β is all-zero and T's IO is zero).
    let (incoming_link, in_live_link) = if input.genesis {
        (
            MatrixAccClaim {
                point: vec![F128::ZERO; 2 * k_l + 1],
                value: F128::ZERO,
            },
            F128::ZERO,
        )
    } else {
        let lane = &layout.link_lanes[input.prev_slot];
        (
            MatrixAccClaim {
                point: input.prev.io[lane.point..lane.value].to_vec(),
                value: input.prev.io[lane.value],
            },
            input.prev.io[lane.live],
        )
    };
    let gate_link = !input.genesis && in_live_link == F128::ONE;
    let mut chf_native = FsLaneChallenger::new(b"history-link-fold-v0");
    let (fold_proof_link, acc_link) = prove_matrix_claim_fold(
        input.fold_matrix_link,
        &fresh_link,
        &incoming_link,
        gate_link,
        &mut chf_native,
    );

    // Block-lane fold: incoming = this slot's block lane of the previous
    // IO. NOT gated by g — a genesis link folds its block 0 claim too.
    let b_lane = &layout.b_lanes[slot];
    let incoming_block = MatrixAccClaim {
        point: input.prev.io[b_lane.point..b_lane.value].to_vec(),
        value: input.prev.io[b_lane.value],
    };
    let gate_block = input.prev.io[b_lane.live] == F128::ONE;
    let mut chf2_native = FsLaneChallenger::new(b"history-block-fold-v0");
    let (fold_proof_block, acc_block) = prove_matrix_claim_fold(
        input.fold_matrix_block,
        &fresh_block,
        &incoming_block,
        gate_block,
        &mut chf2_native,
    );

    // ---- IO values.
    let mut io = vec![F128::ZERO; layout.len];
    io[layout.g] = if input.genesis { F128::ONE } else { F128::ZERO };
    for (a, d) in input.link_class_digests.iter().enumerate() {
        let lanes = flat_digest_lanes(d);
        io[layout.wl + 2 * a] = lanes[0];
        io[layout.wl + 2 * a + 1] = lanes[1];
    }
    for (a, lane) in layout.link_lanes.iter().enumerate() {
        if !input.genesis && a == input.prev_slot {
            io[lane.point..lane.value].copy_from_slice(&acc_link.point);
            io[lane.value] = acc_link.value;
            io[lane.live] = F128::ONE;
        } else {
            // Pass-through (T's lanes are zero at genesis).
            io[lane.point..=lane.live]
                .copy_from_slice(&input.prev.io[lane.point..=lane.live]);
        }
    }
    for (t, lane) in layout.b_lanes.iter().enumerate() {
        if t == slot {
            io[lane.point..lane.value].copy_from_slice(&acc_block.point);
            io[lane.value] = acc_block.value;
            io[lane.live] = F128::ONE;
        } else {
            io[lane.point..=lane.live]
                .copy_from_slice(&input.prev.io[lane.point..=lane.live]);
        }
    }
    io[layout.block_acc..layout.block_acc + super::link::ACC_LANES].copy_from_slice(
        &input.block.io[BLOCK_IO_END_ACC..BLOCK_IO_END_ACC + super::link::ACC_LANES],
    );

    // ---- [R]-PCS walk opening claims: NATIVE values into the IO tail
    // (deterministic in the two proofs; the trace discharge below
    // re-derives the same claims with their wires and asserts the frozen
    // shape). The freeze pass leaves the tail zero.
    let r_pcs_proofs = [
        RPcsProof {
            native: &input.prev.proof.pcs_open,
            params: &class.pcs_params,
            commitment_root: flat_digest_lanes(&input.prev.commitment.root),
        },
        RPcsProof {
            native: &input.block.proof.pcs_open,
            params: &class.b_pcs_params,
            commitment_root: flat_digest_lanes(&input.block.commitment.root),
        },
    ];
    if !freeze {
        let region_native = r_pcs_region_native(&r_pcs_proofs);
        assert_eq!(
            region_native.len(),
            class.region_claims.len(),
            "region native claim count vs frozen"
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
    let mut ledger = 0usize;
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
    let g = io_cells[layout.g].clone();

    // ---- Walk-column allocation FIRST (right after the IO cells): the
    // columns' slices — hence the class's opening-claim spec — must be
    // identical across every link class of the ladder, so nothing
    // class-specific (envelope sizes differ per slot!) may precede them.
    let r_cols = alloc_r_pcs_columns(&mut b, &r_pcs_proofs);
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: walk columns");

    // Envelope wires: the previous link, then the block proof.
    let prev_root = alloc_flat_digest(&mut b, &input.prev.commitment.root);
    let prev_io_wires: Vec<LinExpr> = input
        .prev
        .io
        .iter()
        .map(|&v| alloc_expr(&mut b, v))
        .collect();
    let prev_proof_e = FieldR1csProofTrace::alloc_shape_mode(
        &mut b,
        &input.prev.proof,
        &class.shape,
        &class.pcs_params,
        false,
    );
    let block_root = alloc_flat_digest(&mut b, &input.block.commitment.root);
    let block_io_wires: Vec<LinExpr> = input
        .block
        .io
        .iter()
        .map(|&v| alloc_expr(&mut b, v))
        .collect();
    let block_proof_e = FieldR1csProofTrace::alloc_shape_mode(
        &mut b,
        &input.block.proof,
        &b_shape,
        &class.b_pcs_params,
        false,
    );
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: IO + envelope alloc");

    // ---- β selector: one-hot over the previous link's ladder slot,
    // all-zero at genesis (Σ β = 1 + g).
    let one = LinExpr::constant(F128::ONE);
    let not_g = one.add(&g);
    let beta: Vec<LinExpr> = (0..n)
        .map(|a| {
            let v = if !input.genesis && a == input.prev_slot {
                F128::ONE
            } else {
                F128::ZERO
            };
            alloc_expr(&mut b, v)
        })
        .collect();
    // g and every β boolean; Σ β = 1 + g.
    let g_bool = mul(&mut b, &g, &not_g);
    pin_eq(&mut b, &g_bool, &LinExpr::zero());
    let mut beta_sum = LinExpr::zero();
    for ba in &beta {
        let nb = one.add(ba);
        let bb = mul(&mut b, ba, &nb);
        pin_eq(&mut b, &bb, &LinExpr::zero());
        beta_sum = beta_sum.add(ba);
    }
    pin_eq(&mut b, &beta_sum, &not_g);

    // ---- The verified digest: w_D = Σ β_a·WL_a + g·D_T. Subsumes the
    // genesis rule (β all-zero under g = 1 by the sum pin).
    let d_t = flat_digest_lanes(&class.genesis_digest);
    let w_d: FlatDigestExpr = [0usize, 1usize].map(|lane| {
        let mut acc = g.scale(d_t[lane]);
        for (a, ba) in beta.iter().enumerate() {
            let wl_cell = &io_cells[layout.wl + 2 * a + lane];
            acc = acc.add(&mul(&mut b, ba, wl_cell));
        }
        acc
    });

    // ---- [R]_prev: the deferred replay of the previous link's proof,
    // in REGION mode — its PCS hashing lands on the link walks below.
    let mut obs_prev = PcsWalkObligations::default();
    let mut ch = FsChannelTrace::new(&mut b, b"history-link-v0");
    let (_pce, fresh_link_e) = verify_field_trace_deferred_region(
        &mut b,
        &mut ch,
        &class.shape,
        &class.pcs_params,
        &w_d,
        &prev_root,
        &prev_proof_e,
        &class.spec,
        &prev_io_wires,
        Some(&mut obs_prev),
    );
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: [R]_prev replay");

    // ---- [R]_B: the deferred replay of the block proof, against the
    // BAKED block-class digest.
    let d_b = flat_digest_lanes(&class.ladder[slot].b_digest);
    let w_b: FlatDigestExpr = [LinExpr::constant(d_b[0]), LinExpr::constant(d_b[1])];
    let mut obs_block = PcsWalkObligations::default();
    let mut chb = FsChannelTrace::new(&mut b, b"history-block-v0");
    let (_bce, fresh_block_e) = verify_field_trace_deferred_region(
        &mut b,
        &mut chb,
        &b_shape,
        &class.b_pcs_params,
        &w_b,
        &block_root,
        &block_proof_e,
        &class.b_spec,
        &block_io_wires,
        Some(&mut obs_block),
    );
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: [R]_B replay");

    // ---- Genesis arm: the fresh [R]_prev claim equals T's baked
    // bilinear value under g = 1.
    let baked = genesis_baked_claim_value(&mut b, &class.genesis, &fresh_link_e);
    let diff = fresh_link_e.value.add(&baked);
    let gated = mul(&mut b, &g, &diff);
    pin_eq(&mut b, &gated, &LinExpr::zero());

    // ---- Whitelist inheritance (gated off only at genesis).
    for j in 0..2 * n {
        let diff = io_cells[layout.wl + j].add(&prev_io_wires[layout.wl + j]);
        let gated = mul(&mut b, &not_g, &diff);
        pin_eq(&mut b, &gated, &LinExpr::zero());
    }

    // ---- Link-lane fold twin: incoming = β-mux over the previous link
    // lanes; the fold's incoming gate = the muxed liveness (β is already
    // zero at genesis, so no extra not_g factor is needed).
    let mux_lane = |b: &mut FieldR1csBuilder, pick: &dyn Fn(&SplitLaneLayout) -> usize| {
        let mut acc = LinExpr::zero();
        for (a, ba) in beta.iter().enumerate() {
            let src = prev_io_wires[pick(&layout.link_lanes[a])].clone();
            acc = acc.add(&mul(b, ba, &src));
        }
        acc
    };
    let incoming_link_e = MatrixAccClaimTrace {
        point: (0..2 * k_l + 1)
            .map(|j| mux_lane(&mut b, &|lane: &SplitLaneLayout| lane.point + j))
            .collect(),
        value: mux_lane(&mut b, &|lane: &SplitLaneLayout| lane.value),
    };
    let gate_link_e = mux_lane(&mut b, &|lane: &SplitLaneLayout| lane.live);
    let fold_proof_link_e = MatrixFoldProofTrace::alloc(&mut b, &fold_proof_link, k_l);
    let mut chf = FsChannelTrace::new(&mut b, b"history-link-fold-v0");
    let acc_link_e = verify_matrix_claim_fold_trace(
        &mut b,
        &mut chf,
        k_l,
        class.shape.k_skip,
        &fresh_link_e,
        &incoming_link_e,
        &gate_link_e,
        &fold_proof_link_e,
    );

    // Link-lane routing: lane a carries the fold output when β_a = 1,
    // otherwise passes the previous lane through; liveness is the
    // monotone OR of selection and inheritance.
    for (a, lane) in layout.link_lanes.iter().enumerate() {
        let ba = &beta[a];
        for j in 0..=2 * k_l + 1 {
            let (own, prev_v, fold_v) = if j <= 2 * k_l {
                (
                    &io_cells[lane.point + j],
                    &prev_io_wires[lane.point + j],
                    &acc_link_e.point[j],
                )
            } else {
                (&io_cells[lane.value], &prev_io_wires[lane.value], &acc_link_e.value)
            };
            let delta = fold_v.add(prev_v);
            let picked = mul(&mut b, ba, &delta);
            pin_eq(&mut b, own, &prev_v.add(&picked));
        }
        let prev_live = &prev_io_wires[lane.live];
        let overlap = mul(&mut b, ba, prev_live);
        pin_eq(
            &mut b,
            &io_cells[lane.live],
            &ba.add(prev_live).add(&overlap),
        );
    }

    // ---- Block-lane fold twin (own slot; no β, no genesis gating — a
    // genesis link folds its block 0 claim; the incoming gate rides the
    // previous liveness alone, dead against T's zero IO).
    let incoming_block_e = MatrixAccClaimTrace {
        point: (b_lane.point..b_lane.value)
            .map(|j| prev_io_wires[j].clone())
            .collect(),
        value: prev_io_wires[b_lane.value].clone(),
    };
    let gate_block_e = prev_io_wires[b_lane.live].clone();
    let fold_proof_block_e = MatrixFoldProofTrace::alloc(&mut b, &fold_proof_block, b_shape.k_log);
    let mut chf2 = FsChannelTrace::new(&mut b, b"history-block-fold-v0");
    let acc_block_e = verify_matrix_claim_fold_trace(
        &mut b,
        &mut chf2,
        b_shape.k_log,
        b_shape.k_skip,
        &fresh_block_e,
        &incoming_block_e,
        &gate_block_e,
        &fold_proof_block_e,
    );
    for (t, lane) in layout.b_lanes.iter().enumerate() {
        if t == slot {
            for (j, p) in acc_block_e.point.iter().enumerate() {
                pin_eq(&mut b, p, &io_cells[lane.point + j]);
            }
            pin_eq(&mut b, &acc_block_e.value, &io_cells[lane.value]);
            // Selected liveness is identically 1 (OR with anything).
            pin_eq(&mut b, &io_cells[lane.live], &one);
        } else {
            for j in lane.point..=lane.live {
                pin_eq(&mut b, &io_cells[j], &prev_io_wires[j]);
            }
        }
    }
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: folds + lane routing");

    // ---- Block chaining: the block's start accumulator continues the
    // chain (genesis pins the class constant), its end accumulator IS
    // this link's exposed block accumulator.
    let genesis_start = block_acc_lanes(&class.genesis_block_accumulator);
    for i in 0..super::link::ACC_LANES {
        let sw = &block_io_wires[BLOCK_IO_START_ACC + i];
        let to_genesis = sw.add(&LinExpr::constant(genesis_start[i]));
        let g_gated = mul(&mut b, &g, &to_genesis);
        pin_eq(&mut b, &g_gated, &LinExpr::zero());
        let to_prev = sw.add(&prev_io_wires[layout.block_acc + i]);
        let ng_gated = mul(&mut b, &not_g, &to_prev);
        pin_eq(&mut b, &ng_gated, &LinExpr::zero());
        let ew = &block_io_wires[BLOCK_IO_END_ACC + i];
        pin_eq(&mut b, ew, &io_cells[layout.block_acc + i]);
    }
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: chain rules");

    // ---- The [R]-PCS walk discharge: both replays' obligations land on
    // the two link walks; the resulting committed-column opening claims
    // thread through the region tail (frozen-shape asserted + pinned in
    // real builds; the freeze pass returns them for the class to read).
    let live_region =
        discharge_r_pcs_via_region(&mut b, r_cols, &[&obs_prev, &obs_block]);
    if !freeze {
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
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: walk discharge + tail pins");

    // ---- Pad to the class size.
    let target = 1usize << class.shape.m;
    let used = b.num_wires();
    eprintln!(
        "[split-link] build: {used} wires (slot {slot}, genesis={}, freeze={freeze})",
        input.genesis
    );
    assert!(used <= target, "split link outgrew the class shape: {used} > {target}");
    while b.num_wires() < target {
        b.alloc_f128(F128::ZERO);
    }
    let (r1cs, witness) = b.build();
    assert_eq!(r1cs.m, class.shape.m, "class shape mismatch after padding");
    if !freeze {
        // The class matrix is a protocol constant (I1): hash it once per
        // class — on the first real build — and seed every later
        // instance. Freeze builds are excluded: their matrix omits the
        // region tail pin rows.
        let class_digest = class
            .class_statement_digest
            .get_or_init(|| r1cs.statement_digest());
        r1cs.seed_statement_digest(*class_digest);
    }
    BuiltSplitLink {
        r1cs,
        witness,
        io,
        region_claims: live_region,
    }
}

/// The split-chain decider: natively verify the tip against its
/// published class matrix, pin the whitelist to the true link-class
/// digests, reject genesis tips and evaluate every LIVE lane's
/// accumulated claim against its matrix. `link_matrices[a]` /
/// `block_matrices[t]` may be `None` for DEAD lanes (unused classes need
/// no local rebuild).
pub fn decide_tip_split(
    tip_class: &SplitLinkClass,
    tip_class_r1cs: &FieldR1cs,
    tip: &LinkEnvelope,
    link_class_digests: &[[u8; 32]],
    link_matrices: &[Option<&FieldR1cs>],
    block_matrices: &[Option<&FieldR1cs>],
) -> Result<(), String> {
    let layout = tip_class.layout();
    let n = tip_class.ladder.len();
    assert_eq!(link_class_digests.len(), n);
    assert_eq!(link_matrices.len(), n);
    assert_eq!(block_matrices.len(), n);

    let mut ch = FsLaneChallenger::new(b"history-link-v0");
    noid_ivc_core::verifier::verify_field_with_public_io(
        tip_class_r1cs,
        &tip.commitment,
        &tip.proof,
        &tip_class.spec,
        &tip.io,
        &mut ch,
    )
    .map_err(|e| format!("tip proof rejected: {e:?}"))?;

    if tip_class_r1cs.statement_digest() != link_class_digests[tip_class.slot] {
        return Err("tip class matrix is not the published one".into());
    }
    if tip.io[layout.g] != F128::ZERO {
        return Err("tip is a genesis link".into());
    }
    for (a, d) in link_class_digests.iter().enumerate() {
        let lanes = flat_digest_lanes(d);
        if tip.io[layout.wl + 2 * a] != lanes[0] || tip.io[layout.wl + 2 * a + 1] != lanes[1] {
            return Err(format!("whitelist lane {a} does not carry the class digest"));
        }
    }
    let check_lane = |lane: &SplitLaneLayout,
                      matrix: Option<&FieldR1cs>,
                      what: &str|
     -> Result<(), String> {
        let live = tip.io[lane.live];
        if live == F128::ZERO {
            return Ok(());
        }
        if live != F128::ONE {
            return Err(format!("{what}: non-boolean liveness"));
        }
        let m = matrix.ok_or_else(|| format!("{what}: live lane without its matrix"))?;
        let acc = MatrixAccClaim {
            point: tip.io[lane.point..lane.value].to_vec(),
            value: tip.io[lane.value],
        };
        if acc.point.len() != 2 * m.k_log + 1 {
            return Err(format!("{what}: lane width does not match the matrix shape"));
        }
        if stacked_matrix_mle_eval(m, &acc) != acc.value {
            return Err(format!("{what}: accumulated matrix claim is false"));
        }
        Ok(())
    };
    for a in 0..n {
        check_lane(&layout.link_lanes[a], link_matrices[a], &format!("link lane {a}"))?;
    }
    for t in 0..n {
        check_lane(&layout.b_lanes[t], block_matrices[t], &format!("block lane {t}"))?;
    }
    Ok(())
}

/// The tip's exposed block chain accumulator — the value a fresh peer
/// anchors against its locally validated headers (I8).
pub fn tip_block_accumulator_split(
    tip_class: &SplitLinkClass,
    tip: &LinkEnvelope,
) -> ChainAccumulator {
    let layout = tip_class.layout();
    let lane_bytes = |a: F128, b: F128| -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&flat_to_block(a).to_le_bytes());
        out[16..].copy_from_slice(&flat_to_block(b).to_le_bytes());
        out
    };
    ChainAccumulator {
        height: flat_to_block(tip.io[layout.block_acc]) as u64,
        state_root: lane_bytes(
            tip.io[layout.block_acc + 1],
            tip.io[layout.block_acc + 2],
        ),
        chain_hash: lane_bytes(
            tip.io[layout.block_acc + 3],
            tip.io[layout.block_acc + 4],
        ),
        active_slot_count: flat_to_block(tip.io[layout.block_acc + 5]) as u64,
        alloc_counter: flat_to_block(tip.io[layout.block_acc + 6]) as u64,
    }
}

/// Recover the u128 a flat IO lane encodes.
fn flat_to_block(v: F128) -> u128 {
    use noid_core::hardware::flat_to_tower_u128;
    flat_to_tower_u128((v.lo as u128) | ((v.hi as u128) << 64))
}
