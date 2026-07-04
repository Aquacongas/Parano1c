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
//! `inputs_are_canonical`), state-root `log_slots: u32`. Bucket occupancy
//! and spent-slot counts are trace structure (see the shape note in
//! `merkle_path.rs` — the same selector-freeze resolution applies).

use noid_core::Block128;
use noid_gkr::guard_bucket_killshot::{
    GuardBucketHashInputs, GUARD_BUCKET_LINEAR_RELATION_TAG,
    GUARD_BUCKET_PIN_LANES,
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
    capacity_iv, TAG_EXSTNOD, TAG_EXSTROT, TAG_EXSTSLT, TAG_RGDBUCK, TAG_RGDNODE,
};

use super::batch_eval::{
    verify_linear_eval_prebound_trace, LinearEvalProofTrace, MultiBatchEvalProofTrace,
};
use super::block_spine::{
    close_spine_family_batch, discharge_sponge_chains_trace, sponge_chain_claims_trace,
    verify_block_spine_shift_trace, verify_block_spine_unified_trace, BlockSpineShiftProofTrace,
    BlockSpineUnifiedProofTrace, SpongeChainTrace,
};
use super::merkle_path::{
    discharge_batched_merkle_trace, verify_batched_merkle_killshot_trace, BatchedMerkleProofTrace,
    MerklePathInputsTrace,
};
use super::{
    alloc_block, const_block, pin_lt_strict, range_check_bits, BatchEvalReductionTrace,
    FieldR1csBuilder, LinExpr, RawChannelTrace,
};

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

/// Trace twin of `GuardBucketHashInputs`. `occupied` and the spent-slot
/// count are trace structure; heights and slots are range-checked witness
/// values with the strict-ascending canonicity pins from
/// `inputs_are_canonical`.
pub struct GuardBucketHashInputsTrace {
    pub occupied: bool,
    pub absolute_height: LinExpr,
    pub spent_slots: Vec<LinExpr>,
    pub expected_hash: [LinExpr; 2],
}

impl GuardBucketHashInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &GuardBucketHashInputs) -> Self {
        if !native.occupied {
            // Canonical empty bucket: structural constants.
            assert_eq!(native.absolute_height, 0, "non-canonical empty bucket");
            assert!(native.spent_slots.is_empty(), "non-canonical empty bucket");
            return Self {
                occupied: false,
                absolute_height: LinExpr::zero(),
                spent_slots: Vec::new(),
                expected_hash: std::array::from_fn(|i| alloc_block(b, native.expected_hash[i])),
            };
        }
        assert!(!native.spent_slots.is_empty(), "non-canonical bucket");
        let absolute_height = alloc_block(b, Block128::from(native.absolute_height));
        range_check_bits(b, &absolute_height, 64);
        let spent_slots: Vec<LinExpr> = native
            .spent_slots
            .iter()
            .map(|&s| alloc_block(b, Block128::from(s)))
            .collect();
        // Strict ascending order (inputs_are_canonical): range-check each
        // slot to u32, then pin pairwise a < b.
        let bit_decs: Vec<_> = spent_slots
            .iter()
            .map(|s| range_check_bits(b, s, 32))
            .collect();
        for w in bit_decs.windows(2) {
            pin_lt_strict(b, &w[0], &w[1]);
        }
        Self {
            occupied: true,
            absolute_height,
            spent_slots,
            expected_hash: std::array::from_fn(|i| alloc_block(b, native.expected_hash[i])),
        }
    }

    /// Trace twin of `bucket_blocks`.
    fn blocks(&self) -> Vec<[LinExpr; 2]> {
        if !self.occupied {
            return vec![[LinExpr::zero(), const_block(pad_after_one_field())]];
        }
        let mut blocks = vec![[const_block(Block128::from(1u8)), self.absolute_height.clone()]];
        let mut fields = Vec::with_capacity(self.spent_slots.len() + 1);
        fields.push(const_block(Block128::from(self.spent_slots.len() as u64)));
        fields.extend(self.spent_slots.iter().cloned());
        let mut iter = fields.chunks_exact(2);
        for pair in &mut iter {
            blocks.push([pair[0].clone(), pair[1].clone()]);
        }
        let rem = iter.remainder();
        if rem.is_empty() {
            let [p0, p1] = pad_empty_block();
            blocks.push([const_block(p0), const_block(p1)]);
        } else {
            blocks.push([rem[0].clone(), const_block(pad_after_one_field())]);
        }
        blocks
    }
}

/// Trace twin of `verify_batched_guard_bucket_killshot`.
pub fn verify_batched_guard_bucket_killshot_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &SpongeFamilyProofTrace,
    inputs: &[GuardBucketHashInputsTrace],
) -> [BatchEvalReductionTrace; 3] {
    assert!(!inputs.is_empty());
    let live_slots: usize = inputs.iter().map(|i| i.blocks().len()).sum();
    assert_eq!(proof.live_slots, live_slots);

    // absorb_public_batch
    ch.absorb_const_tower(b, inputs.len() as u128);
    ch.absorb_const_tower(b, TAG_RGDBUCK.as_u64() as u128);
    for input in inputs {
        ch.absorb_const_tower(b, input.occupied as u128);
        ch.absorb(b, &input.absolute_height);
        ch.absorb_const_tower(b, input.spent_slots.len() as u128);
        for slot in &input.spent_slots {
            ch.absorb(b, slot);
        }
        ch.absorb(b, &input.expected_hash[0]);
        ch.absorb(b, &input.expected_hash[1]);
    }

    let mut chain_claims = Vec::new();
    let mut slot_offset = 0usize;
    for input in inputs {
        let blocks = input.blocks();
        chain_claims.extend(sponge_chain_claims_trace(
            &blocks,
            capacity_iv(TAG_RGDBUCK),
            &input.expected_hash[..GUARD_BUCKET_PIN_LANES],
            slot_offset,
            proof.num_vars,
        ));
        slot_offset += blocks.len();
    }
    proof.verify_tail(b, ch, &chain_claims, GUARD_BUCKET_LINEAR_RELATION_TAG)
}

/// Trace twin of `discharge_batched_guard_bucket_reductions_native`.
pub fn discharge_batched_guard_bucket_trace(
    b: &mut FieldR1csBuilder,
    inputs: &[GuardBucketHashInputsTrace],
    reductions: &[BatchEvalReductionTrace; 3],
) {
    let chains: Vec<SpongeChainTrace> = inputs
        .iter()
        .map(|input| SpongeChainTrace {
            blocks: input.blocks(),
            iv: capacity_iv(TAG_RGDBUCK),
            expected: input.expected_hash.clone(),
        })
        .collect();
    discharge_sponge_chains_trace(b, &chains, reductions);
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
    pub guard_buckets: Option<Vec<GuardBucketHashInputsTrace>>,
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
            let buckets: Vec<GuardBucketHashInputsTrace> = bucket_inputs
                .iter()
                .map(|i| GuardBucketHashInputsTrace::alloc(b, i))
                .collect();
            let live_slots: usize = buckets.iter().map(|i| i.blocks().len()).sum();
            let family = SpongeFamilyProofTrace::alloc(
                b,
                &bucket_proof.kill_shot,
                &bucket_proof.chain,
                &bucket_proof.batch,
                bucket_proof.num_vars,
                bucket_proof.live_slots,
                live_slots,
            );
            assert_eq!(bucket_proof.n_buckets, buckets.len());
            let mut ch = RawChannelTrace::new();
            let reds = verify_batched_guard_bucket_killshot_trace(b, &mut ch, &family, &buckets);
            discharge_batched_guard_bucket_trace(b, &buckets, &reds);
            Some(buckets)
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

    fn bucket_fixture(seed: u64, occupied: bool, n_slots: usize) -> GuardBucketHashInputs {
        let (absolute_height, spent_slots) = if occupied {
            (1000 + seed, (0..n_slots).map(|i| (seed as u32) + 3 * i as u32).collect())
        } else {
            (0, Vec::new())
        };
        let mut input = GuardBucketHashInputs {
            occupied,
            absolute_height,
            spent_slots,
            expected_hash: [Block128::ZERO; 2],
        };
        // Derive the honest hash through the native evaluation by asking the
        // prover-side helper: replicate bucket_blocks + sponge chain.
        let [iv_hi, iv_lo] = capacity_iv(TAG_RGDBUCK);
        let mut state = [Block128::ZERO, Block128::ZERO, iv_hi, iv_lo];
        let blocks = {
            // Same layout as guard_bucket_killshot::bucket_blocks.
            if !input.occupied {
                vec![[Block128::ZERO, super::pad_after_one_field()]]
            } else {
                let mut blocks =
                    vec![[Block128::from(1u8), Block128::from(input.absolute_height)]];
                let mut fields = vec![Block128::from(input.spent_slots.len() as u64)];
                fields.extend(input.spent_slots.iter().map(|&s| Block128::from(s)));
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
                blocks
            }
        };
        let perm = noid_poseidon2b::native::permutation::Poseidon2bPermutation;
        for block in blocks {
            state[0] += block[0];
            state[1] += block[1];
            perm.permute_mut(&mut state);
        }
        input.expected_hash = [state[0], state[1]];
        input
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
        let guard_buckets = with_guard.then(|| vec![bucket_fixture(7, true, 3), bucket_fixture(8, false, 0)]);
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
                let buckets = i.guard_buckets.as_mut().unwrap();
                buckets[0].absolute_height = buckets[0].absolute_height.wrapping_add(1);
            }),
            Box::new(|i| {
                let buckets = i.guard_buckets.as_mut().unwrap();
                buckets[0].spent_slots[1] += 1;
            }),
            Box::new(|i| {
                let buckets = i.guard_buckets.as_mut().unwrap();
                buckets[0].expected_hash[0] += Block128::ONE;
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
    /// (`pin_lt_strict`), even when the bucket hash is recomputed to match
    /// the reordered data.
    #[test]
    fn exact_state_rejects_unsorted_guard_slots() {
        let (mut inputs, proof) = fixture(true);
        let bucket = &mut inputs.guard_buckets.as_mut().unwrap()[0];
        bucket.spent_slots.swap(0, 1);
        // Recompute the hash so ONLY the canonicity check can catch it.
        *bucket = {
            let mut b = bucket_fixture(7, true, 3);
            b.spent_slots = bucket.spent_slots.clone();
            let [iv_hi, iv_lo] = capacity_iv(TAG_RGDBUCK);
            let perm = noid_poseidon2b::native::permutation::Poseidon2bPermutation;
            let mut state = [Block128::ZERO, Block128::ZERO, iv_hi, iv_lo];
            let mut fields = vec![Block128::from(b.spent_slots.len() as u64)];
            fields.extend(b.spent_slots.iter().map(|&s| Block128::from(s)));
            let mut blocks = vec![[Block128::from(1u8), Block128::from(b.absolute_height)]];
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
            b.expected_hash = [state[0], state[1]];
            b
        };
        assert!(
            verify_exact_state_killshot(&inputs, &proof).is_err(),
            "native accepted an unsorted bucket"
        );
        assert!(
            !trace_accepts(&inputs, &proof),
            "trace accepted an unsorted bucket"
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
