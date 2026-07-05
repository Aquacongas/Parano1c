// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The exact-state killshots in the trace.
//!
//! Trace twins of:
//! - [`verify_batched_slot_leaf_killshot_trace`] ←
//!   `noid_gkr::state_leaf_killshot::verify_batched_slot_leaf_killshot`,
//! - [`verify_batched_guard_bucket_killshot_trace`] ←
//!   `noid_gkr::guard_bucket_killshot::verify_batched_guard_bucket_killshot`,
//! - [`verify_batched_state_root_killshot_trace`] ←
//!   `noid_gkr::state_root_killshot::verify_batched_state_root_killshot`,
//! plus their discharges, and [`build_exact_state_slot`] — the component
//! twin of `block_certificate_backend::verify_exact_state_killshot`
//! (slot leaves → state paths → guard buckets → guard paths → state roots,
//! each killshot on its own fresh channel).
//!
//! Native implicit integer bounds become explicit range decompositions:
//! slot-leaf `amount: u64`, guard `absolute_height: u64` and
//! `spent_slots: Vec<u32>` (plus the strict-ascending canonicity check from
//! `inputs_are_canonical`), state-root `log_slots: u32`. The guard update
//! statement is fully witness-carried: occupancy, heights, digests and the
//! class-padded spent list travel as wires with liveness selectors, so the
//! guard slot's matrix depends only on the class's spend capacity.

use noid_core::{Block128, TowerField};
use noid_gkr::guard_bucket_killshot::{
    guard_slots_chain_len, guard_update_live_slots, GuardBucketUpdateInputs,
    GuardLeafHashInputs, GUARD_BUCKET_LINEAR_RELATION_TAG, GUARD_BUCKET_PIN_LANES,
    GUARD_LEAF_CHAIN_SLOTS,
};
use noid_gkr::merkle_circuit::MerkleCircuit;
use noid_gkr::state_leaf_killshot::{
    SlotLeafInputs, SLOT_LEAF_LINEAR_RELATION_TAG, SLOT_LEAF_PERMS,
    SLOT_LEAF_PIN_LANES,
};
use noid_gkr::state_root_killshot::{
    CompositeStateRootInputs, STATE_ROOT_LINEAR_RELATION_TAG,
    STATE_ROOT_PERMS, STATE_ROOT_PIN_LANES,
};
use noid_poseidon2b::native::domain::{
    capacity_iv, TAG_EXSTNOD, TAG_EXSTROT, TAG_EXSTSLT, TAG_RGDBUCK, TAG_RGDNODE, TAG_RGDSLOT,
};

use super::batch_eval::{
    verify_linear_eval_prebound_trace, LinearEvalClaimTrace, LinearEvalProofTrace,
    LinearEvalTermTrace, MultiBatchEvalProofTrace,
};
use super::block_spine::{
    close_spine_family_batch, discharge_sponge_chains_trace, spine_point_index,
    sponge_chain_claims_trace, verify_block_spine_shift_trace, verify_block_spine_unified_trace,
    BlockSpineShiftProofTrace, BlockSpineUnifiedProofTrace, ColumnAccumulator, SpongeChainTrace,
};
use super::merkle_path::{
    discharge_batched_merkle_trace, verify_batched_merkle_killshot_trace, BatchedMerkleProofTrace,
    MerklePathInputsTrace,
};
use super::{
    alloc_block, const_block, flat_of, lt_strict_expr, mul, pin_zero, range_check_bits,
    BatchEvalReductionTrace, FieldR1csBuilder, LinExpr, RawChannelTrace,
};
use noid_poseidon2b::native::permutation::{MDS_FULL, N_ROUNDS, STATE_SIZE};

fn pad_after_one_field() -> Block128 {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x80;
    bytes[15] = 0x01;
    Block128::from(u128::from_le_bytes(bytes))
}

fn pad_empty_block() -> [Block128; 2] {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo[0] = 0x80;
    hi[15] = 0x01;
    [
        Block128::from(u128::from_le_bytes(lo)),
        Block128::from(u128::from_le_bytes(hi)),
    ]
}

/// Family proof wires shared by the three sponge-chain killshots.
pub struct SpongeFamilyProofTrace {
    pub main: BlockSpineUnifiedProofTrace,
    pub shift: BlockSpineShiftProofTrace,
    pub chain: LinearEvalProofTrace,
    pub batch: MultiBatchEvalProofTrace,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl SpongeFamilyProofTrace {
    fn alloc(
        b: &mut FieldR1csBuilder,
        kill_shot: &noid_gkr::BlockSpineKillShotProof,
        chain: &noid_gkr::batch_eval::LinearEvalProof,
        batch: &noid_gkr::batch_eval::MultiBatchEvalProof,
        proof_num_vars: usize,
        proof_live_slots: usize,
        live_slots: usize,
    ) -> Self {
        let num_vars = noid_gkr::block_spine::num_vars_for(live_slots);
        assert_eq!(proof_live_slots, live_slots, "proof off the trace shape");
        assert_eq!(proof_num_vars, num_vars, "proof off the trace shape");
        Self {
            main: BlockSpineUnifiedProofTrace::alloc(b, &kill_shot.main, num_vars),
            shift: BlockSpineShiftProofTrace::alloc(b, &kill_shot.shift, num_vars),
            chain: LinearEvalProofTrace::alloc(b, chain, num_vars),
            batch: MultiBatchEvalProofTrace::alloc(b, batch, num_vars, 3),
            num_vars,
            live_slots,
        }
    }

    /// unified → shift → prebound chain → multi-batch closure (the shared
    /// verifier tail of every sponge-chain killshot).
    fn verify_tail(
        &self,
        b: &mut FieldR1csBuilder,
        ch: &mut RawChannelTrace,
        chain_claims: &[super::batch_eval::LinearEvalClaimTrace],
        relation_tag: u128,
    ) -> [BatchEvalReductionTrace; 3] {
        let main_red =
            verify_block_spine_unified_trace(b, ch, &self.main, self.num_vars, self.live_slots);
        let shift_red =
            verify_block_spine_shift_trace(b, ch, &self.shift, &main_red, self.num_vars);
        let chain_red = verify_linear_eval_prebound_trace(
            b,
            ch,
            &self.chain,
            chain_claims,
            self.num_vars,
            relation_tag,
        );
        close_spine_family_batch(b, ch, &main_red, &shift_red, &chain_red, &self.batch, self.num_vars)
    }
}

// ---------------------------------------------------------------------------
// slot_leaf (grouped here with its exact-state siblings)
// ---------------------------------------------------------------------------

/// Trace twin of `SlotLeafInputs`. `amount` carries the native `u64` bound
/// as an explicit 64-bit range decomposition.
pub struct SlotLeafInputsTrace {
    pub amount: LinExpr,
    pub owner_hi: LinExpr,
    pub owner_lo: LinExpr,
    pub expected_leaf: [LinExpr; 2],
}

impl SlotLeafInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &SlotLeafInputs) -> Self {
        let amount = alloc_block(b, Block128::from(native.amount));
        range_check_bits(b, &amount, 64);
        Self {
            amount,
            owner_hi: alloc_block(b, native.owner_hi),
            owner_lo: alloc_block(b, native.owner_lo),
            expected_leaf: std::array::from_fn(|i| alloc_block(b, native.expected_leaf[i])),
        }
    }

    /// Trace twin of `evaluate_slot_leaf`'s rate blocks (2 perms).
    fn blocks(&self) -> Vec<[LinExpr; 2]> {
        vec![
            [self.amount.clone(), self.owner_hi.clone()],
            [self.owner_lo.clone(), const_block(pad_after_one_field())],
        ]
    }
}

/// Trace twin of `verify_batched_slot_leaf_killshot`.
pub fn verify_batched_slot_leaf_killshot_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &SpongeFamilyProofTrace,
    inputs: &[SlotLeafInputsTrace],
) -> [BatchEvalReductionTrace; 3] {
    assert!(!inputs.is_empty());
    assert_eq!(proof.live_slots, inputs.len() * SLOT_LEAF_PERMS);

    // absorb_public_batch
    ch.absorb_const_tower(b, inputs.len() as u128);
    ch.absorb_const_tower(b, TAG_EXSTSLT.as_u64() as u128);
    for input in inputs {
        ch.absorb(b, &input.amount);
        ch.absorb(b, &input.owner_hi);
        ch.absorb(b, &input.owner_lo);
        ch.absorb(b, &input.expected_leaf[0]);
        ch.absorb(b, &input.expected_leaf[1]);
    }

    // chain_claims_at_offset per leaf == the shared sponge-chain relation.
    let mut chain_claims = Vec::new();
    for (idx, input) in inputs.iter().enumerate() {
        chain_claims.extend(sponge_chain_claims_trace(
            &input.blocks(),
            capacity_iv(TAG_EXSTSLT),
            &input.expected_leaf[..SLOT_LEAF_PIN_LANES],
            idx * SLOT_LEAF_PERMS,
            proof.num_vars,
        ));
    }
    proof.verify_tail(b, ch, &chain_claims, SLOT_LEAF_LINEAR_RELATION_TAG)
}

/// Trace twin of `discharge_batched_slot_leaf_reductions_native`.
pub fn discharge_batched_slot_leaf_trace(
    b: &mut FieldR1csBuilder,
    inputs: &[SlotLeafInputsTrace],
    reductions: &[BatchEvalReductionTrace; 3],
) {
    let chains: Vec<SpongeChainTrace> = inputs
        .iter()
        .map(|input| SpongeChainTrace {
            blocks: input.blocks(),
            iv: capacity_iv(TAG_EXSTSLT),
            expected: input.expected_leaf.clone(),
        })
        .collect();
    discharge_sponge_chains_trace(b, &chains, reductions);
}

// ---------------------------------------------------------------------------
// guard_bucket (step 6)
// ---------------------------------------------------------------------------

/// Trace twin of `GuardLeafHashInputs`: everything is a witness wire.
/// Occupancy is a boolean selector; the canonical empty form (zero height
/// and digest) is enforced in-circuit through the complement selector.
pub struct GuardLeafHashInputsTrace {
    pub occupied: LinExpr,
    pub absolute_height: LinExpr,
    pub slots_digest: [LinExpr; 2],
    pub expected_hash: [LinExpr; 2],
}

impl GuardLeafHashInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &GuardLeafHashInputs) -> Self {
        let occupied = LinExpr::from_wire(b.alloc_bool(native.occupied));
        let absolute_height = alloc_block(b, Block128::from(native.absolute_height));
        range_check_bits(b, &absolute_height, 64);
        let slots_digest: [LinExpr; 2] =
            std::array::from_fn(|i| alloc_block(b, native.slots_digest[i]));
        // Canonical empty leaf: (1 + occupied) selects the ghost form and
        // zeroes height and digest.
        let ghost = occupied.add(&const_block(Block128::ONE));
        let v = mul(b, &ghost, &absolute_height);
        pin_zero(b, &v);
        for lane in &slots_digest {
            let v = mul(b, &ghost, lane);
            pin_zero(b, &v);
        }
        Self {
            occupied,
            absolute_height,
            slots_digest,
            expected_hash: std::array::from_fn(|i| alloc_block(b, native.expected_hash[i])),
        }
    }

    /// Trace twin of `leaf_blocks`: the fixed three-block leaf chain.
    fn blocks(&self) -> Vec<[LinExpr; 2]> {
        let [p0, p1] = pad_empty_block();
        vec![
            [self.occupied.clone(), self.absolute_height.clone()],
            [self.slots_digest[0].clone(), self.slots_digest[1].clone()],
            [const_block(p0), const_block(p1)],
        ]
    }
}

/// Trace twin of `GuardBucketUpdateInputs`. The spent list is carried at
/// the class's spend capacity with field-position liveness selectors
/// `h_q = [q <= len]` (boolean, monotone, unary-bound to the length wire);
/// zero tails are pinned through the complement selectors and the
/// strict-ascending canonicity check is gated per adjacent live pair.
pub struct GuardBucketUpdateInputsTrace {
    pub old_leaf: GuardLeafHashInputsTrace,
    pub new_leaf: GuardLeafHashInputsTrace,
    pub padded_spent_len: usize,
    pub live_len: LinExpr,
    pub spent_slots: Vec<LinExpr>,
    /// `h_q` for `q` in `1..=padded_spent_len`.
    pub slot_live: Vec<LinExpr>,
}

impl GuardBucketUpdateInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &GuardBucketUpdateInputs) -> Self {
        let len = native.spent_slots.len();
        assert!(len >= 1, "non-canonical guard update (empty spend list)");
        assert!(len <= native.padded_spent_len);

        let old_leaf = GuardLeafHashInputsTrace::alloc(b, &native.old_leaf);
        let new_leaf = GuardLeafHashInputsTrace::alloc(b, &native.new_leaf);
        // The new leaf is always occupied: pin its selector to one.
        pin_zero(b, &new_leaf.occupied.add(&const_block(Block128::ONE)));

        let live_len = alloc_block(b, Block128::from(len as u64));
        let spent_slots: Vec<LinExpr> = (0..native.padded_spent_len)
            .map(|i| {
                let v = native.spent_slots.get(i).copied().unwrap_or(0);
                alloc_block(b, Block128::from(v))
            })
            .collect();

        // Liveness selectors: boolean, monotone, single-boundary telescoping
        // binding to the length wire (same construction as the owner-auth
        // slot selectors).
        let slot_live: Vec<LinExpr> = (0..native.padded_spent_len)
            .map(|i| LinExpr::from_wire(b.alloc_bool(i < len)))
            .collect();
        for s in 1..slot_live.len() {
            let prev_ghost = slot_live[s - 1].add(&const_block(Block128::ONE));
            let violation = mul(b, &slot_live[s], &prev_ghost);
            pin_zero(b, &violation);
        }
        let mut unary_value = LinExpr::zero();
        for s in 0..slot_live.len() {
            let boundary = if s + 1 < slot_live.len() {
                slot_live[s].add(&slot_live[s + 1])
            } else {
                slot_live[s].clone()
            };
            unary_value = unary_value.add(&boundary.scale(flat_of(Block128::from(s as u128 + 1))));
        }
        pin_zero(b, &unary_value.add(&live_len));

        // Zero tails, u32 ranges, and the gated strict-ascending pins:
        // adjacent live pairs must ascend; pairs with a ghost member are
        // exempt (their violation term is zeroed by the pair selector).
        let bit_decs: Vec<_> = spent_slots
            .iter()
            .map(|s| range_check_bits(b, s, 32))
            .collect();
        for (i, slot) in spent_slots.iter().enumerate() {
            let ghost = slot_live[i].add(&const_block(Block128::ONE));
            let v = mul(b, &ghost, slot);
            pin_zero(b, &v);
        }
        for i in 1..spent_slots.len() {
            let lt = lt_strict_expr(b, &bit_decs[i - 1], &bit_decs[i]);
            let not_lt = lt.add(&const_block(Block128::ONE));
            // Both live (monotone: h_{i+1} implies h_i) and not ascending.
            let violation = mul(b, &slot_live[i], &not_lt);
            pin_zero(b, &violation);
        }

        Self {
            old_leaf,
            new_leaf,
            padded_spent_len: native.padded_spent_len,
            live_len,
            spent_slots,
            slot_live,
        }
    }

    /// Field-position liveness `h_q` over the absorbed stream (`q = 0` is
    /// the always-live length field; positions past the capacity are ghost).
    fn h(&self, q: isize) -> LinExpr {
        if q <= 0 {
            const_block(Block128::ONE)
        } else if q as usize <= self.padded_spent_len {
            self.slot_live[q as usize - 1].clone()
        } else {
            LinExpr::zero()
        }
    }

    /// Trace twin of `slots_field_at`: the absorbed-field stream value at
    /// position `q`, affine in the liveness selectors (the two sponge pad
    /// markers enter on the stream boundary indicators).
    fn field_expr(&self, q: usize) -> LinExpr {
        if q == 0 {
            return self.live_len.clone();
        }
        let qi = q as isize;
        // Ghost slot wires are pinned zero, so the liveness selection
        // `h_q * slot_q` is the identity on every satisfying witness —
        // using the wire directly keeps the stream affine.
        let mut expr = if q <= self.padded_spent_len {
            self.spent_slots[q - 1].clone()
        } else {
            LinExpr::zero()
        };
        let at_pad = self.h(qi - 1).add(&self.h(qi));
        if q % 2 == 0 {
            expr = expr.add(&at_pad.scale(flat_of(pad_empty_block()[0])));
        } else {
            expr = expr.add(&at_pad.scale(flat_of(pad_after_one_field())));
            let at_pad_hi = self.h(qi - 2).add(&self.h(qi - 1));
            expr = expr.add(&at_pad_hi.scale(flat_of(pad_empty_block()[1])));
        }
        expr
    }

    /// Chain-block liveness `l_p = h(2p - 1)` (block 0 is always live).
    fn block_live(&self, p: usize) -> LinExpr {
        if p == 0 {
            const_block(Block128::ONE)
        } else {
            self.h(2 * p as isize - 1)
        }
    }

    /// Last-live-block boundary `l_p - l_{p+1}` (char-2 sum).
    fn block_boundary(&self, p: usize) -> LinExpr {
        self.h(2 * p as isize - 1).add(&self.h(2 * p as isize + 1))
    }
}

/// Trace twin of `verify_batched_guard_bucket_killshot`.
pub fn verify_batched_guard_bucket_killshot_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &SpongeFamilyProofTrace,
    inputs: &GuardBucketUpdateInputsTrace,
) -> [BatchEvalReductionTrace; 3] {
    assert_eq!(
        proof.live_slots,
        guard_update_live_slots(inputs.padded_spent_len)
    );

    // absorb_public_batch
    ch.absorb_const_tower(b, TAG_RGDBUCK.as_u64() as u128);
    ch.absorb_const_tower(b, inputs.padded_spent_len as u128);
    for leaf in [&inputs.old_leaf, &inputs.new_leaf] {
        ch.absorb(b, &leaf.occupied);
        ch.absorb(b, &leaf.absolute_height);
        ch.absorb(b, &leaf.slots_digest[0]);
        ch.absorb(b, &leaf.slots_digest[1]);
        ch.absorb(b, &leaf.expected_hash[0]);
        ch.absorb(b, &leaf.expected_hash[1]);
    }
    ch.absorb(b, &inputs.live_len);
    for slot in &inputs.spent_slots {
        ch.absorb(b, slot);
    }

    let chain_claims = guard_update_chain_claims_trace(b, inputs, proof.num_vars);
    proof.verify_tail(b, ch, &chain_claims, GUARD_BUCKET_LINEAR_RELATION_TAG)
}

/// Trace twin of `guard_update_chain_claims`: two fixed leaf chains plus
/// the selector-scheduled spent-slot chain.
fn guard_update_chain_claims_trace(
    b: &mut FieldR1csBuilder,
    inputs: &GuardBucketUpdateInputsTrace,
    num_vars: usize,
) -> Vec<LinearEvalClaimTrace> {
    let mds = |row: usize, col: usize| Block128::from(MDS_FULL[row][col]);

    let mut claims = sponge_chain_claims_trace(
        &inputs.old_leaf.blocks(),
        capacity_iv(TAG_RGDBUCK),
        &inputs.old_leaf.expected_hash[..GUARD_BUCKET_PIN_LANES],
        0,
        num_vars,
    );
    claims.extend(sponge_chain_claims_trace(
        &inputs.new_leaf.blocks(),
        capacity_iv(TAG_RGDBUCK),
        &inputs.new_leaf.expected_hash[..GUARD_BUCKET_PIN_LANES],
        GUARD_LEAF_CHAIN_SLOTS,
        num_vars,
    ));

    // Spent-slot chain (offset 2 * GUARD_LEAF_CHAIN_SLOTS): every term
    // coefficient is the class-fixed structure scaled by the liveness /
    // boundary selectors, mirroring `slots_chain_claims` value-for-value.
    let offset = 2 * GUARD_LEAF_CHAIN_SLOTS;
    let chain_len = guard_slots_chain_len(inputs.padded_spent_len);
    let iv = capacity_iv(TAG_RGDSLOT);
    for p in 0..chain_len {
        let slot = offset + p;
        let f_a = inputs.field_expr(2 * p);
        let f_b = inputs.field_expr(2 * p + 1);
        let live = inputs.block_live(p);
        for lane in 0..STATE_SIZE {
            let mut terms = vec![LinearEvalTermTrace {
                index: spine_point_index(num_vars, slot, 0, lane),
                coeff: live.clone(),
            }];
            let absorbed = f_a
                .scale(flat_of(mds(lane, 0)))
                .add(&f_b.scale(flat_of(mds(lane, 1))));
            let value = if p == 0 {
                absorbed.add_const(flat_of(mds(lane, 2) * iv[0] + mds(lane, 3) * iv[1]))
            } else {
                for src_lane in 0..STATE_SIZE {
                    terms.push(LinearEvalTermTrace {
                        index: spine_point_index(num_vars, slot - 1, N_ROUNDS, src_lane),
                        coeff: live.scale(flat_of(mds(lane, src_lane))),
                    });
                }
                mul(b, &live, &absorbed)
            };
            claims.push(LinearEvalClaimTrace { terms, value });
        }
    }
    for lane in 0..GUARD_BUCKET_PIN_LANES {
        let terms = (0..chain_len)
            .map(|p| LinearEvalTermTrace {
                index: spine_point_index(num_vars, offset + p, N_ROUNDS, lane),
                coeff: inputs.block_boundary(p),
            })
            .collect();
        claims.push(LinearEvalClaimTrace {
            terms,
            value: inputs.new_leaf.slots_digest[lane].clone(),
        });
    }
    claims
}

/// Trace twin of `discharge_batched_guard_bucket_reductions_native`: the two
/// leaf chains replay as fixed sponge chains; the spent-slot chain replays
/// with selector-muxed state feeds (a ghost position runs the permutation on
/// the all-zero state, exactly the padded prover schedule) and pins the
/// digest at the boundary-selected last live position.
pub fn discharge_batched_guard_bucket_trace(
    b: &mut FieldR1csBuilder,
    inputs: &GuardBucketUpdateInputsTrace,
    reductions: &[BatchEvalReductionTrace; 3],
) {
    let live_slots = guard_update_live_slots(inputs.padded_spent_len);
    let mut acc = ColumnAccumulator::new(b, &reductions[0].point, live_slots);

    for leaf in [&inputs.old_leaf, &inputs.new_leaf] {
        let iv = capacity_iv(TAG_RGDBUCK);
        let mut state: [LinExpr; STATE_SIZE] = [
            LinExpr::zero(),
            LinExpr::zero(),
            const_block(iv[0]),
            const_block(iv[1]),
        ];
        for block in &leaf.blocks() {
            state[0] = state[0].add(&block[0]);
            state[1] = state[1].add(&block[1]);
            state = acc.push_slot(b, &state);
        }
        pin_zero(b, &state[0].add(&leaf.expected_hash[0]));
        pin_zero(b, &state[1].add(&leaf.expected_hash[1]));
    }

    let iv = capacity_iv(TAG_RGDSLOT);
    let chain_len = guard_slots_chain_len(inputs.padded_spent_len);
    let mut prev_out: [LinExpr; STATE_SIZE] = [
        LinExpr::zero(),
        LinExpr::zero(),
        const_block(iv[0]),
        const_block(iv[1]),
    ];
    let mut digest_sel: [LinExpr; 2] = [LinExpr::zero(), LinExpr::zero()];
    for p in 0..chain_len {
        let live = inputs.block_live(p);
        let mut state_in: [LinExpr; STATE_SIZE] = prev_out.clone();
        state_in[0] = state_in[0].add(&inputs.field_expr(2 * p));
        state_in[1] = state_in[1].add(&inputs.field_expr(2 * p + 1));
        if p > 0 {
            // Ghost positions run on the all-zero state: mux the whole
            // chained input through the liveness selector.
            state_in = std::array::from_fn(|lane| mul(b, &live, &state_in[lane]));
        }
        let out = acc.push_slot(b, &state_in);
        let boundary = inputs.block_boundary(p);
        for lane in 0..2 {
            digest_sel[lane] = digest_sel[lane].add(&mul(b, &boundary, &out[lane]));
        }
        prev_out = out;
    }
    pin_zero(b, &digest_sel[0].add(&inputs.new_leaf.slots_digest[0]));
    pin_zero(b, &digest_sel[1].add(&inputs.new_leaf.slots_digest[1]));

    let (state_value, sin_value, sout_value) = acc.finish();
    pin_zero(b, &state_value.add(&reductions[0].value));
    pin_zero(b, &sin_value.add(&reductions[1].value));
    pin_zero(b, &sout_value.add(&reductions[2].value));
}

// ---------------------------------------------------------------------------
// state_root (step 8)
// ---------------------------------------------------------------------------

/// Trace twin of `CompositeStateRootInputs` (`log_slots` range-checked to
/// the native `u32` bound).
pub struct CompositeStateRootInputsTrace {
    pub log_slots: LinExpr,
    pub utxo_root: [LinExpr; 2],
    pub guard_root: [LinExpr; 2],
    pub expected_state_root: [LinExpr; 2],
}

impl CompositeStateRootInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &CompositeStateRootInputs) -> Self {
        let log_slots = alloc_block(b, Block128::from(native.log_slots));
        range_check_bits(b, &log_slots, 32);
        Self {
            log_slots,
            utxo_root: std::array::from_fn(|i| alloc_block(b, native.utxo_root[i])),
            guard_root: std::array::from_fn(|i| alloc_block(b, native.guard_root[i])),
            expected_state_root: std::array::from_fn(|i| {
                alloc_block(b, native.expected_state_root[i])
            }),
        }
    }

    /// Trace twin of `rate_blocks` (3 perms).
    fn blocks(&self) -> Vec<[LinExpr; 2]> {
        vec![
            [self.log_slots.clone(), self.utxo_root[0].clone()],
            [self.utxo_root[1].clone(), self.guard_root[0].clone()],
            [
                self.guard_root[1].clone(),
                const_block(pad_after_one_field()),
            ],
        ]
    }
}

/// Trace twin of `verify_batched_state_root_killshot`.
pub fn verify_batched_state_root_killshot_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &SpongeFamilyProofTrace,
    inputs: &[CompositeStateRootInputsTrace],
) -> [BatchEvalReductionTrace; 3] {
    assert!(!inputs.is_empty());
    assert_eq!(proof.live_slots, inputs.len() * STATE_ROOT_PERMS);

    // absorb_public_batch
    ch.absorb_const_tower(b, inputs.len() as u128);
    ch.absorb_const_tower(b, TAG_EXSTROT.as_u64() as u128);
    for input in inputs {
        ch.absorb(b, &input.log_slots);
        ch.absorb(b, &input.utxo_root[0]);
        ch.absorb(b, &input.utxo_root[1]);
        ch.absorb(b, &input.guard_root[0]);
        ch.absorb(b, &input.guard_root[1]);
        ch.absorb(b, &input.expected_state_root[0]);
        ch.absorb(b, &input.expected_state_root[1]);
    }

    let mut chain_claims = Vec::new();
    for (idx, input) in inputs.iter().enumerate() {
        chain_claims.extend(sponge_chain_claims_trace(
            &input.blocks(),
            capacity_iv(TAG_EXSTROT),
            &input.expected_state_root[..STATE_ROOT_PIN_LANES],
            idx * STATE_ROOT_PERMS,
            proof.num_vars,
        ));
    }
    proof.verify_tail(b, ch, &chain_claims, STATE_ROOT_LINEAR_RELATION_TAG)
}

/// Trace twin of `discharge_batched_state_root_reductions_native`.
pub fn discharge_batched_state_root_trace(
    b: &mut FieldR1csBuilder,
    inputs: &[CompositeStateRootInputsTrace],
    reductions: &[BatchEvalReductionTrace; 3],
) {
    let chains: Vec<SpongeChainTrace> = inputs
        .iter()
        .map(|input| SpongeChainTrace {
            blocks: input.blocks(),
            iv: capacity_iv(TAG_EXSTROT),
            expected: input.expected_state_root.clone(),
        })
        .collect();
    discharge_sponge_chains_trace(b, &chains, reductions);
}

// ---------------------------------------------------------------------------
// Component assembly — verify_exact_state_killshot twin
// ---------------------------------------------------------------------------

/// The statement wires of one exact-state component slot, returned for the
/// [B] bindings.
pub struct ExactStateSlotWires {
    pub slot_leaves: Vec<SlotLeafInputsTrace>,
    pub state_paths: Vec<MerklePathInputsTrace>,
    pub guard_buckets: Option<GuardBucketUpdateInputsTrace>,
    pub guard_paths: Option<Vec<MerklePathInputsTrace>>,
    pub state_roots: Vec<CompositeStateRootInputsTrace>,
}

/// Trace twin of `block_certificate_backend::verify_exact_state_killshot`:
/// `validate_exact_state_inputs` shape checks become asserts, then the five
/// killshots run, each on its own fresh channel (native runs them in a
/// rayon join tree, one `Poseidon2bChannel::new()` each).
pub fn build_exact_state_slot(
    b: &mut FieldR1csBuilder,
    inputs: &crate::block_certificate_backend::ExactStateKillShotInputs,
    proof: &crate::block_certificate_backend::ExactStateKillShotProof,
) -> ExactStateSlotWires {
    // validate_exact_state_inputs
    assert!(!inputs.slot_leaves.is_empty());
    assert!(!inputs.state_paths.is_empty());
    assert!(!inputs.state_roots.is_empty());
    assert!(inputs.state_roots.len() % 2 == 0);
    assert_eq!(inputs.guard_buckets.is_some(), inputs.guard_paths.is_some());
    assert_eq!(inputs.guard_buckets.is_some(), proof.guard_buckets.is_some());
    assert_eq!(inputs.guard_paths.is_some(), proof.guard_paths.is_some());

    // Slot leaves.
    let slot_leaves: Vec<SlotLeafInputsTrace> = inputs
        .slot_leaves
        .iter()
        .map(|i| SlotLeafInputsTrace::alloc(b, i))
        .collect();
    let leaf_proof = SpongeFamilyProofTrace::alloc(
        b,
        &proof.slot_leaves.kill_shot,
        &proof.slot_leaves.chain,
        &proof.slot_leaves.batch,
        proof.slot_leaves.num_vars,
        proof.slot_leaves.live_slots,
        inputs.slot_leaves.len() * SLOT_LEAF_PERMS,
    );
    assert_eq!(proof.slot_leaves.n_leaves, inputs.slot_leaves.len());
    let mut ch = RawChannelTrace::new();
    let leaf_reds = verify_batched_slot_leaf_killshot_trace(b, &mut ch, &leaf_proof, &slot_leaves);
    discharge_batched_slot_leaf_trace(b, &slot_leaves, &leaf_reds);

    // State Merkle paths (TAG_EXSTNOD).
    let state_circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
    let state_paths: Vec<MerklePathInputsTrace> = inputs
        .state_paths
        .iter()
        .map(|i| MerklePathInputsTrace::alloc(b, i))
        .collect();
    let state_path_proof = BatchedMerkleProofTrace::alloc(b, &proof.state_paths, &state_paths);
    let mut ch = RawChannelTrace::new();
    let state_path_reds = verify_batched_merkle_killshot_trace(
        b,
        &mut ch,
        &state_circuit,
        &state_path_proof,
        &state_paths,
    );
    discharge_batched_merkle_trace(b, &state_circuit, &state_paths, &state_path_reds);

    // Guard buckets + guard paths (optional, present together).
    let guard_buckets = match (&inputs.guard_buckets, &proof.guard_buckets) {
        (Some(bucket_inputs), Some(bucket_proof)) => {
            let update = GuardBucketUpdateInputsTrace::alloc(b, bucket_inputs);
            assert_eq!(bucket_proof.padded_spent_len, update.padded_spent_len);
            let family = SpongeFamilyProofTrace::alloc(
                b,
                &bucket_proof.kill_shot,
                &bucket_proof.chain,
                &bucket_proof.batch,
                bucket_proof.num_vars,
                bucket_proof.live_slots,
                guard_update_live_slots(update.padded_spent_len),
            );
            let mut ch = RawChannelTrace::new();
            let reds = verify_batched_guard_bucket_killshot_trace(b, &mut ch, &family, &update);
            discharge_batched_guard_bucket_trace(b, &update, &reds);
            Some(update)
        }
        (None, None) => None,
        _ => unreachable!("guard presence asserted above"),
    };

    let guard_paths = match (&inputs.guard_paths, &proof.guard_paths) {
        (Some(path_inputs), Some(path_proof)) => {
            let circuit = MerkleCircuit::build_with_tag(TAG_RGDNODE);
            let paths: Vec<MerklePathInputsTrace> = path_inputs
                .iter()
                .map(|i| MerklePathInputsTrace::alloc(b, i))
                .collect();
            let proof_t = BatchedMerkleProofTrace::alloc(b, path_proof, &paths);
            let mut ch = RawChannelTrace::new();
            let reds =
                verify_batched_merkle_killshot_trace(b, &mut ch, &circuit, &proof_t, &paths);
            discharge_batched_merkle_trace(b, &circuit, &paths, &reds);
            Some(paths)
        }
        (None, None) => None,
        _ => unreachable!("guard presence asserted above"),
    };

    // Composite state roots.
    let state_roots: Vec<CompositeStateRootInputsTrace> = inputs
        .state_roots
        .iter()
        .map(|i| CompositeStateRootInputsTrace::alloc(b, i))
        .collect();
    let root_family = SpongeFamilyProofTrace::alloc(
        b,
        &proof.state_roots.kill_shot,
        &proof.state_roots.chain,
        &proof.state_roots.batch,
        proof.state_roots.num_vars,
        proof.state_roots.live_slots,
        inputs.state_roots.len() * STATE_ROOT_PERMS,
    );
    assert_eq!(proof.state_roots.n_roots, inputs.state_roots.len());
    let mut ch = RawChannelTrace::new();
    let root_reds =
        verify_batched_state_root_killshot_trace(b, &mut ch, &root_family, &state_roots);
    discharge_batched_state_root_trace(b, &state_roots, &root_reds);

    ExactStateSlotWires {
        slot_leaves,
        state_paths,
        guard_buckets,
        guard_paths,
        state_roots,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::TowerField;
    use crate::block_certificate_backend::{
        verify_exact_state_killshot, ExactStateKillShotInputs, ExactStateKillShotProof,
    };
    use noid_gkr::guard_bucket_killshot::prove_batched_guard_bucket_killshot;
    use noid_gkr::merkle_batch_killshot::prove_batched_merkle_killshot;
    use noid_gkr::merkle_circuit::{MerklePathInputs, MAX_MERKLE_DEPTH};
    use noid_gkr::merkle_oracle::compute_merkle_root_with_directions;
    use noid_gkr::state_leaf_killshot::prove_batched_slot_leaf_killshot;
    use noid_gkr::state_root_killshot::prove_batched_state_root_killshot;
    use noid_poseidon2b::channel::Poseidon2bChannel;
    use noid_poseidon2b::native::compression::Poseidon2bSponge;

    fn leaf_fixture(seed: u128) -> SlotLeafInputs {
        let amount = (seed as u64) | 1;
        let owner_hi = Block128::from(seed + 7);
        let owner_lo = Block128::from(seed + 13);
        // evaluate_slot_leaf semantics via the sponge: absorb [amount,
        // owner_hi] then [owner_lo, pad].
        let [iv_hi, iv_lo] = capacity_iv(TAG_EXSTSLT);
        let mut sponge = Poseidon2bSponge::with_iv([iv_hi, iv_lo]);
        sponge.absorb_pair(Block128::from(amount), owner_hi);
        sponge.absorb_pair(owner_lo, super::pad_after_one_field());
        let digest = sponge.finalize_no_pad();
        SlotLeafInputs {
            amount,
            owner_hi,
            owner_lo,
            expected_leaf: [
                Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
                Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
            ],
        }
    }

    fn sponge_chain(iv: [Block128; 2], fields: &[Block128]) -> [Block128; 2] {
        let perm = noid_poseidon2b::native::permutation::Poseidon2bPermutation;
        let mut state = [Block128::ZERO, Block128::ZERO, iv[0], iv[1]];
        let mut blocks = Vec::new();
        let mut it = fields.chunks_exact(2);
        for pair in &mut it {
            blocks.push([pair[0], pair[1]]);
        }
        let rem = it.remainder();
        if rem.is_empty() {
            blocks.push(super::pad_empty_block());
        } else {
            blocks.push([rem[0], super::pad_after_one_field()]);
        }
        for block in blocks {
            state[0] += block[0];
            state[1] += block[1];
            perm.permute_mut(&mut state);
        }
        [state[0], state[1]]
    }

    fn guard_slots_digest_fixture(slots: &[u32]) -> [Block128; 2] {
        let mut fields = vec![Block128::from(slots.len() as u64)];
        fields.extend(slots.iter().map(|&s| Block128::from(s)));
        sponge_chain(capacity_iv(noid_poseidon2b::native::domain::TAG_RGDSLOT), &fields)
    }

    fn guard_leaf_fixture(occupied: bool, height: u64, slots: &[u32]) -> GuardLeafHashInputs {
        let slots_digest = if occupied {
            guard_slots_digest_fixture(slots)
        } else {
            [Block128::ZERO; 2]
        };
        let expected_hash = sponge_chain(
            capacity_iv(TAG_RGDBUCK),
            &[
                Block128::from(occupied as u128),
                Block128::from(height),
                slots_digest[0],
                slots_digest[1],
            ],
        );
        GuardLeafHashInputs {
            occupied,
            absolute_height: if occupied { height } else { 0 },
            slots_digest,
            expected_hash,
        }
    }

    fn guard_update_fixture(seed: u64, old_occupied: bool, n_slots: usize) -> GuardBucketUpdateInputs {
        let old_slots: Vec<u32> = (0..2u32).map(|i| (seed as u32) + 7 * i).collect();
        let spent_slots: Vec<u32> = (0..n_slots)
            .map(|i| (seed as u32) + 3 * i as u32)
            .collect();
        GuardBucketUpdateInputs {
            old_leaf: guard_leaf_fixture(old_occupied, if old_occupied { 700 + seed } else { 0 }, &old_slots),
            new_leaf: guard_leaf_fixture(true, 1000 + seed, &spent_slots),
            spent_slots,
            padded_spent_len: 8,
        }
    }

    fn root_fixture(seed: u128) -> CompositeStateRootInputs {
        let log_slots = 20 + (seed as u32 % 4);
        let utxo_root = [Block128::from(seed + 1), Block128::from(seed + 2)];
        let guard_root = [Block128::from(seed + 3), Block128::from(seed + 4)];
        let [iv_hi, iv_lo] = capacity_iv(TAG_EXSTROT);
        let perm = noid_poseidon2b::native::permutation::Poseidon2bPermutation;
        let mut state = [Block128::ZERO, Block128::ZERO, iv_hi, iv_lo];
        for block in [
            [Block128::from(log_slots), utxo_root[0]],
            [utxo_root[1], guard_root[0]],
            [guard_root[1], super::pad_after_one_field()],
        ] {
            state[0] += block[0];
            state[1] += block[1];
            perm.permute_mut(&mut state);
        }
        CompositeStateRootInputs {
            log_slots,
            utxo_root,
            guard_root,
            expected_state_root: [state[0], state[1]],
        }
    }

    fn path_fixture(circuit: &MerkleCircuit, seed: u64, depth: usize, dirs: u32) -> MerklePathInputs {
        let mut s = seed as u128 | 1;
        let mut rnd = || {
            s = s.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(13);
            Block128::from(s)
        };
        let leaf = [rnd(), rnd()];
        let mut siblings = [[Block128::ZERO; 2]; MAX_MERKLE_DEPTH];
        let mut directions = [false; MAX_MERKLE_DEPTH];
        for level in 0..depth {
            siblings[level] = [rnd(), rnd()];
            directions[level] = (dirs >> level) & 1 == 1;
        }
        let expected_root = compute_merkle_root_with_directions(
            circuit,
            leaf,
            &siblings[..depth],
            &directions,
            depth,
        );
        MerklePathInputs {
            leaf,
            siblings,
            directions,
            expected_root,
            active_depth: depth,
        }
    }

    fn fixture(with_guard: bool) -> (ExactStateKillShotInputs, ExactStateKillShotProof) {
        let state_circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
        let guard_circuit = MerkleCircuit::build_with_tag(TAG_RGDNODE);

        let slot_leaves = vec![leaf_fixture(3), leaf_fixture(4)];
        let state_paths = vec![
            path_fixture(&state_circuit, 1, 3, 0b011),
            path_fixture(&state_circuit, 2, 2, 0b10),
        ];
        let guard_buckets = with_guard.then(|| guard_update_fixture(7, true, 3));
        let guard_paths = with_guard.then(|| vec![path_fixture(&guard_circuit, 9, 2, 0b01)]);
        let state_roots = vec![root_fixture(11), root_fixture(12)];

        let inputs = ExactStateKillShotInputs {
            slot_leaves: slot_leaves.clone(),
            state_paths: state_paths.clone(),
            guard_buckets: guard_buckets.clone(),
            guard_paths: guard_paths.clone(),
            state_roots: state_roots.clone(),
        };

        let mut ch = Poseidon2bChannel::new();
        let (leaf_proof, _) = prove_batched_slot_leaf_killshot(&slot_leaves, &mut ch);
        let mut ch = Poseidon2bChannel::new();
        let (state_path_proof, _) =
            prove_batched_merkle_killshot(&state_circuit, &state_paths, &mut ch);
        let bucket_proof = guard_buckets.as_ref().map(|buckets| {
            let mut ch = Poseidon2bChannel::new();
            prove_batched_guard_bucket_killshot(buckets, &mut ch).0
        });
        let guard_path_proof = guard_paths.as_ref().map(|paths| {
            let mut ch = Poseidon2bChannel::new();
            prove_batched_merkle_killshot(&guard_circuit, paths, &mut ch).0
        });
        let mut ch = Poseidon2bChannel::new();
        let (root_proof, _) = prove_batched_state_root_killshot(&state_roots, &mut ch);

        let proof = ExactStateKillShotProof {
            slot_leaves: leaf_proof,
            state_paths: state_path_proof,
            guard_buckets: bucket_proof,
            guard_paths: guard_path_proof,
            state_roots: root_proof,
        };
        (inputs, proof)
    }

    fn trace_accepts(inputs: &ExactStateKillShotInputs, proof: &ExactStateKillShotProof) -> bool {
        let mut b = FieldR1csBuilder::new();
        let _ = build_exact_state_slot(&mut b, inputs, proof);
        let (r1cs, z) = b.build();
        r1cs.satisfies(&z)
    }

    /// Positive: full exact-state component (with and without guard legs)
    /// accepted natively and in-trace.
    #[test]
    fn exact_state_trace_positive() {
        for with_guard in [true, false] {
            let (inputs, proof) = fixture(with_guard);
            assert!(
                verify_exact_state_killshot(&inputs, &proof).is_ok(),
                "native fixture broken (guard={with_guard})"
            );
            let mut b = FieldR1csBuilder::new();
            let _ = build_exact_state_slot(&mut b, &inputs, &proof);
            let (r1cs, z) = b.build();
            assert!(
                r1cs.satisfies(&z),
                "honest exact-state trace unsat (guard={with_guard})"
            );
            if with_guard {
                eprintln!(
                    "exact-state slot (2 leaves, 2+1 paths, 2 buckets, 2 roots): {} useful rows (k_log = {})",
                    r1cs.useful_rows, r1cs.k_log
                );
            }
        }
    }

    /// Statement/discharge mutator across every component's witness lanes
    /// (representative fields from each of the five killshots).
    #[test]
    fn exact_state_statement_mutator_kills_all() {
        let (inputs, proof) = fixture(true);
        let mut survivors = Vec::new();
        let mutations: Vec<Box<dyn Fn(&mut ExactStateKillShotInputs)>> = vec![
            Box::new(|i| i.slot_leaves[0].amount = i.slot_leaves[0].amount.wrapping_add(1)),
            Box::new(|i| i.slot_leaves[0].owner_hi += Block128::ONE),
            Box::new(|i| i.slot_leaves[1].expected_leaf[1] += Block128::ONE),
            Box::new(|i| i.state_paths[0].leaf[0] += Block128::ONE),
            Box::new(|i| i.state_paths[0].siblings[1][0] += Block128::ONE),
            Box::new(|i| i.state_paths[1].expected_root[0] += Block128::ONE),
            Box::new(|i| {
                let update = i.guard_buckets.as_mut().unwrap();
                update.old_leaf.absolute_height = update.old_leaf.absolute_height.wrapping_add(1);
            }),
            Box::new(|i| {
                let update = i.guard_buckets.as_mut().unwrap();
                update.new_leaf.absolute_height = update.new_leaf.absolute_height.wrapping_add(1);
            }),
            Box::new(|i| {
                let update = i.guard_buckets.as_mut().unwrap();
                update.spent_slots[1] += 1;
            }),
            Box::new(|i| {
                let update = i.guard_buckets.as_mut().unwrap();
                update.new_leaf.slots_digest[0] += Block128::ONE;
            }),
            Box::new(|i| {
                let update = i.guard_buckets.as_mut().unwrap();
                update.old_leaf.slots_digest[1] += Block128::ONE;
            }),
            Box::new(|i| {
                let update = i.guard_buckets.as_mut().unwrap();
                update.new_leaf.expected_hash[0] += Block128::ONE;
            }),
            Box::new(|i| {
                let update = i.guard_buckets.as_mut().unwrap();
                update.old_leaf.expected_hash[1] += Block128::ONE;
            }),
            Box::new(|i| {
                let paths = i.guard_paths.as_mut().unwrap();
                paths[0].expected_root[1] += Block128::ONE;
            }),
            Box::new(|i| i.state_roots[0].log_slots += 1),
            Box::new(|i| i.state_roots[0].utxo_root[0] += Block128::ONE),
            Box::new(|i| i.state_roots[1].guard_root[1] += Block128::ONE),
            Box::new(|i| i.state_roots[1].expected_state_root[0] += Block128::ONE),
        ];
        for (idx, mutate) in mutations.iter().enumerate() {
            let mut bad = inputs.clone();
            mutate(&mut bad);
            assert!(
                verify_exact_state_killshot(&bad, &proof).is_err(),
                "native accepted statement mutant {idx}"
            );
            if trace_accepts(&bad, &proof) {
                survivors.push(idx);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving exact-state statement mutants: {survivors:?}"
        );
    }

    /// The strict-ascending canonicity pin: an unsorted spent-slot list is
    /// rejected natively (`inputs_are_canonical`) and unsatisfiable in-trace
    /// (the gated less-than pins), even when the digests and leaf hashes are
    /// recomputed to match the reordered data.
    #[test]
    fn exact_state_rejects_unsorted_guard_slots() {
        let (mut inputs, proof) = fixture(true);
        let update = inputs.guard_buckets.as_mut().unwrap();
        update.spent_slots.swap(0, 1);
        // Recompute the digest and leaf so ONLY the canonicity check can
        // catch it.
        update.new_leaf = guard_leaf_fixture(
            true,
            update.new_leaf.absolute_height,
            &update.spent_slots,
        );
        assert!(
            verify_exact_state_killshot(&inputs, &proof).is_err(),
            "native accepted an unsorted bucket"
        );
        assert!(
            !trace_accepts(&inputs, &proof),
            "trace accepted an unsorted bucket"
        );
    }

    /// Fixed-matrix class gate for the guard slot: two updates in one class
    /// (same spend capacity) with different occupancies, heights, spend
    /// counts and slot values must produce byte-identical matrices.
    #[test]
    fn guard_fixed_matrix_within_class() {
        let digest = |seed: u64, old_occupied: bool, n_slots: usize| {
            let update = guard_update_fixture(seed, old_occupied, n_slots);
            let mut ch = Poseidon2bChannel::new();
            let (proof, _) = prove_batched_guard_bucket_killshot(&update, &mut ch);
            let mut b = FieldR1csBuilder::new();
            let trace = GuardBucketUpdateInputsTrace::alloc(&mut b, &update);
            let family = SpongeFamilyProofTrace::alloc(
                &mut b,
                &proof.kill_shot,
                &proof.chain,
                &proof.batch,
                proof.num_vars,
                proof.live_slots,
                guard_update_live_slots(update.padded_spent_len),
            );
            let mut ch = RawChannelTrace::new();
            let reds =
                verify_batched_guard_bucket_killshot_trace(&mut b, &mut ch, &family, &trace);
            discharge_batched_guard_bucket_trace(&mut b, &trace, &reds);
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "honest guard slot unsat");
            r1cs.statement_digest()
        };
        assert_eq!(
            digest(7, true, 3),
            digest(1234, false, 7),
            "guard slot matrix must depend only on the shape class"
        );
    }

    /// Proof mutator: representative fields from each of the five
    /// sub-proofs (full per-field sweeps for the shared machinery live in
    /// the sibling modules' mutators — the machinery is identical).
    #[test]
    fn exact_state_proof_mutator_kills_all() {
        let (inputs, proof) = fixture(true);
        let mut survivors = Vec::new();
        let mutations: Vec<Box<dyn Fn(&mut ExactStateKillShotProof)>> = vec![
            Box::new(|p| p.slot_leaves.kill_shot.main.state_at_r += Block128::ONE),
            Box::new(|p| p.slot_leaves.chain.b_final += Block128::ONE),
            Box::new(|p| p.slot_leaves.batch.b_finals[0] += Block128::ONE),
            Box::new(|p| p.state_paths.kill_shot.shift.s_in_at_r2 += Block128::ONE),
            Box::new(|p| p.state_paths.chain.rounds[0].evals_at_1_2[1] += Block128::ONE),
            Box::new(|p| {
                let g = p.guard_buckets.as_mut().unwrap();
                g.kill_shot.main.round_polys[0].coeffs_no_linear[3] += Block128::ONE;
            }),
            Box::new(|p| {
                let g = p.guard_paths.as_mut().unwrap();
                g.batch.b_finals[2] += Block128::ONE;
            }),
            Box::new(|p| p.state_roots.kill_shot.shift.round_polys[1].coeffs_no_linear[0] += Block128::ONE),
            Box::new(|p| p.state_roots.batch.rounds[2].evals_at_1_2[0] += Block128::ONE),
        ];
        for (idx, mutate) in mutations.iter().enumerate() {
            let mut bad = proof.clone();
            mutate(&mut bad);
            assert!(
                verify_exact_state_killshot(&inputs, &bad).is_err(),
                "native accepted proof mutant {idx}"
            );
            if trace_accepts(&inputs, &bad) {
                survivors.push(idx);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving exact-state proof mutants: {survivors:?}"
        );
    }
}
