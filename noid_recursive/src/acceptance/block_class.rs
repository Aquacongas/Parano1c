// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The standalone per-tier BLOCK class `B_t` — the block half of the
//! two-level π split.
//!
//! `B_t` hosts the block slots and the FULL region stack (wallet-PCS walks,
//! owner-auth, spine, exact-state, tx-root, liveness) at tier-natural padded
//! size, plus the block statement IO. It contains NO verifier — no [R]
//! replay, no chain rules, no matrix fold — so it has no self-reference
//! knot: its class matrix is an ordinary protocol constant per tier. The
//! LINK class verifies `π_block` through its second [R] replay and binds
//! this class's public IO (the accumulator boundary and the region opening
//! claims) into the chain rules.
//!
//! Public IO layout: `[start_acc (5 lanes) | end_acc (5 lanes) | region
//! claim tail]`. The accumulator lanes are `height, state_root×2,
//! chain_hash×2` in the same flat encoding the link uses; the region tail
//! carries every frozen walk opening claim's (point ‖ value) exactly like
//! the link's region tail does, so a verifier replaying this proof enforces
//! the claims against the committed walk columns via the envelope-IO
//! machinery unchanged.
//!
//! Freeze discipline (mirrors the link class): the region claim COUNT and
//! ARITIES come from a cheap native probe (`region_wallet_pcs_native` on a
//! sample block of the tier), which fixes the IO layout; a freeze-mode
//! trace build with the SAME IO head then reveals the claims' committed-
//! column slices. The class MATRIX is created by the first real build (the
//! freeze matrix omits the IO pin rows) and every later build must
//! reproduce it bit-exactly (I1; per-tier fixity gates).

use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::pcs::PcsParams;
use noid_ivc_core::proof::FieldShape;
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};

use super::block_slots::{
    build_block_slots_with_config, region_wallet_pcs_native, BlockSlotsConfig,
};
use super::link::{block_acc_lanes, LinkBlock, RegionFrozenClaim, ACC_LANES};
use super::trace::pin_eq;
use super::trace::region_source_binding::{RegionDischargeParams, RegionPcsClaim};

/// Public-IO layout of a block class.
#[derive(Clone, Copy, Debug)]
pub struct BlockIoLayout {
    /// Start accumulator: [`ACC_LANES`] lanes (height, state_root×2,
    /// chain_hash×2, active_slot_count, alloc_counter).
    pub start_acc: usize,
    /// End accumulator: [`ACC_LANES`] lanes.
    pub end_acc: usize,
    /// First region-tail lane.
    pub region_tail_offset: usize,
    /// Region tail length (`n_claims × (max_arity + 1)`).
    pub region_len: usize,
    /// Total IO length.
    pub len: usize,
}

/// Fixed offsets of the accumulator lanes within a block class's IO —
/// independent of the region tail, so link-side consumers can address them
/// without knowing the frozen claim shape.
pub const BLOCK_IO_START_ACC: usize = 0;
pub const BLOCK_IO_END_ACC: usize = ACC_LANES;

pub fn block_io_layout(n_claims: usize, max_arity: usize) -> BlockIoLayout {
    let region_len = n_claims * (max_arity + 1);
    BlockIoLayout {
        start_acc: BLOCK_IO_START_ACC,
        end_acc: BLOCK_IO_END_ACC,
        region_tail_offset: 2 * ACC_LANES,
        region_len,
        len: 2 * ACC_LANES + region_len,
    }
}

/// The block-class IO spec: the accumulator lanes are plain IO (the LINK's
/// chain rules read them as wires of ITS [R]-replayed envelope); each frozen
/// region claim reads its point/value out of the tail lanes — identical
/// mechanics to the link's region spec.
pub fn block_io_spec(frozen: &[RegionFrozenClaim], max_arity: usize) -> PublicIoSpec {
    let layout = block_io_layout(frozen.len(), max_arity);
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

/// The per-tier block class constants.
pub struct BlockClass {
    /// The consensus standard-tx tier this class hosts (capacity).
    pub tier: usize,
    pub shape: FieldShape,
    /// Statement digest of the CLASS matrix — filled on the first real
    /// build, seeded into every later instance (same discipline as the
    /// link class).
    pub class_statement_digest: std::sync::OnceLock<[u8; 32]>,
    pub pcs_params: PcsParams,
    pub spec: PublicIoSpec,
    /// The block-slot configuration every build in this class uses (full
    /// region stack at `tier` capacity).
    pub config_template: BlockSlotsConfig,
    /// The frozen region opening-claim shape; every build reproduces
    /// exactly these `(slice, arity)` pairs.
    pub region_claims: Vec<RegionFrozenClaim>,
    pub region_max_arity: usize,
}

/// One assembled block proof trace.
pub struct BuiltBlock {
    pub r1cs: FieldR1cs,
    pub witness: Vec<F128>,
    pub io: Vec<F128>,
}

impl BlockClass {
    /// Freeze the class from a sample block of the tier. Two phases:
    /// a native probe fixes the claim count/arities (hence the IO layout),
    /// then a freeze-mode trace build with the real IO head reveals the
    /// claims' committed-column slices.
    pub fn freeze(
        shape: FieldShape,
        pcs_params: PcsParams,
        region_params: RegionDischargeParams,
        sample: &LinkBlock<'_>,
        tier: usize,
    ) -> Self {
        let config_template = BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: region_params,
            owner_auth_region: true,
            exact_state_region: true,
            tx_root_region: true,
            spine_region: true,
            tier_user_tx_capacity: Some(tier),
        };
        // Phase 1: native probe → arities → layout.
        let native = region_wallet_pcs_native(
            sample.inputs,
            region_params,
            true,
            true,
            true,
            true,
            Some(tier),
        );
        let max_arity = native.iter().map(|(p, _)| p.len()).max().unwrap_or(0);
        let layout = block_io_layout(native.len(), max_arity);
        let io_slice_log2 = layout.len.next_power_of_two().trailing_zeros() as usize;

        // Phase 2: freeze build (zero IO, no pins) with the real IO head.
        let (live, _built) = build_block_trace_parts(
            shape,
            sample,
            config_template,
            io_slice_log2,
            layout.len,
            &vec![F128::ZERO; layout.len],
            None,
        );
        assert_eq!(live.len(), native.len(), "freeze claim count vs native probe");
        let frozen: Vec<RegionFrozenClaim> = live
            .iter()
            .map(|c| RegionFrozenClaim {
                slice: c.slice,
                arity: c.point.len(),
            })
            .collect();
        let spec = block_io_spec(&frozen, max_arity);
        Self {
            tier,
            shape,
            class_statement_digest: std::sync::OnceLock::new(),
            pcs_params,
            spec,
            config_template,
            region_claims: frozen,
            region_max_arity: max_arity,
        }
    }
}

/// Assemble one block proof trace: statement IO cells, the block slots +
/// region stack, the accumulator and region-tail pins, padding to the class
/// size.
pub fn build_block_proof_trace(class: &BlockClass, block: &LinkBlock<'_>) -> BuiltBlock {
    // Native pass: the IO values are known before the trace starts.
    let layout = block_io_layout(class.region_claims.len(), class.region_max_arity);
    assert_eq!(class.spec.io_len, layout.len);
    let mut io = vec![F128::ZERO; layout.len];
    io[layout.start_acc..layout.start_acc + ACC_LANES]
        .copy_from_slice(&block_acc_lanes(block.start_accumulator));
    io[layout.end_acc..layout.end_acc + ACC_LANES]
        .copy_from_slice(&block_acc_lanes(block.end_accumulator));
    let region_native = region_wallet_pcs_native(
        block.inputs,
        class.config_template.wallet_pcs_params,
        class.config_template.owner_auth_region,
        class.config_template.exact_state_region,
        class.config_template.tx_root_region,
        class.config_template.spine_region,
        class.config_template.tier_user_tx_capacity,
    );
    assert_eq!(
        region_native.len(),
        class.region_claims.len(),
        "block-class region native claim count drift"
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

    let (live, built) = build_block_trace_parts(
        class.shape,
        block,
        class.config_template,
        class.spec.io_slice.log2_len,
        class.spec.io_len,
        &io,
        Some(class),
    );
    let (r1cs, witness) = built.expect("real build returns the instance");
    // Frozen-shape assert.
    assert_eq!(live.len(), class.region_claims.len(), "block region claim count drift");
    for (ci, c) in live.iter().enumerate() {
        let fc = &class.region_claims[ci];
        assert_eq!(c.slice, fc.slice, "block region claim {ci} slice drift");
        assert_eq!(c.point.len(), fc.arity, "block region claim {ci} arity drift");
    }
    let class_digest = class
        .class_statement_digest
        .get_or_init(|| r1cs.statement_digest());
    r1cs.seed_statement_digest(*class_digest);
    BuiltBlock { r1cs, witness, io }
}

/// Shared trace assembly. `finish = None` is the freeze pass: the IO cells
/// hold zeros and stay UNPINNED (the freeze matrix omits the pin rows,
/// exactly like the link's freeze), the live claims are returned and no
/// instance is built. `finish = Some(class)` pins the accumulator lanes and
/// every region claim to the IO cells and builds the padded instance.
#[allow(clippy::type_complexity)]
fn build_block_trace_parts(
    shape: FieldShape,
    block: &LinkBlock<'_>,
    config: BlockSlotsConfig,
    io_slice_log2: usize,
    io_len: usize,
    io_vals: &[F128],
    finish: Option<&BlockClass>,
) -> (Vec<RegionPcsClaim>, Option<(FieldR1cs, Vec<F128>)>) {
    let mut b = FieldR1csBuilder::new();
    let mut ledger = 0usize;

    // IO slice at dyadic index 1 of its size: wires [2^log2, 2^(log2+1)).
    let io_start = 1usize << io_slice_log2;
    while b.num_wires() < io_start {
        b.alloc_f128(F128::ZERO);
    }
    let io_cells: Vec<LinExpr> = (0..1usize << io_slice_log2)
        .map(|t| {
            let v = if t < io_len { io_vals[t] } else { F128::ZERO };
            LinExpr::from_wire(b.alloc_f128(v))
        })
        .collect();
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "block: IO cells");

    let mut slots = build_block_slots_with_config(
        &mut b,
        block.start_accumulator,
        block.end_accumulator,
        block.inputs,
        block.proof,
        config,
    );
    let live = std::mem::take(&mut slots.pending_wallet_pcs);
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "block: slots total");

    match finish {
        Some(class) => {
            let layout = block_io_layout(class.region_claims.len(), class.region_max_arity);
            let start_lanes = [
                &slots.start_acc.height,
                &slots.start_acc.state_root[0],
                &slots.start_acc.state_root[1],
                &slots.start_acc.chain_hash[0],
                &slots.start_acc.chain_hash[1],
                &slots.start_acc.active_slot_count,
                &slots.start_acc.alloc_counter,
            ];
            let end_lanes = [
                &slots.end_acc.height,
                &slots.end_acc.state_root[0],
                &slots.end_acc.state_root[1],
                &slots.end_acc.chain_hash[0],
                &slots.end_acc.chain_hash[1],
                &slots.end_acc.active_slot_count,
                &slots.end_acc.alloc_counter,
            ];
            for (i, w) in start_lanes.iter().enumerate() {
                pin_eq(&mut b, w, &io_cells[layout.start_acc + i]);
            }
            for (i, w) in end_lanes.iter().enumerate() {
                pin_eq(&mut b, w, &io_cells[layout.end_acc + i]);
            }
            let stride = class.region_max_arity + 1;
            for (ci, c) in live.iter().enumerate() {
                let base = layout.region_tail_offset + ci * stride;
                for (kk, p) in c.point.iter().enumerate() {
                    pin_eq(&mut b, p, &io_cells[base + kk]);
                }
                pin_eq(&mut b, &c.value, &io_cells[base + class.region_max_arity]);
            }
            crate::acceptance::row_ledger_mark(&b, &mut ledger, "block: IO pins");

            let target = 1usize << shape.m;
            let used = b.num_wires();
            eprintln!("[block-class] build: {used} wires (tier {})", class.tier);
            assert!(used <= target, "block trace outgrew the class: {used} > {target}");
            while b.num_wires() < target {
                b.alloc_f128(F128::ZERO);
            }
            let (r1cs, witness) = b.build();
            assert_eq!(r1cs.m, shape.m, "block class shape after padding");
            (live, Some((r1cs, witness)))
        }
        None => {
            eprintln!(
                "[block-class] freeze probe: {} wires, {} claims",
                b.num_wires(),
                live.len()
            );
            (live, None)
        }
    }
}
