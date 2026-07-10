// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact-state slot-leaf and EXSTNOD path verification in the recursive trace.
//!
//! Root/depth binding is direct: every old path is tied to the parent header
//! root (or its one-level grow with the canonical zero subtree), every new path
//! to the child header root, and every path depth to the child `log_slots`.
//! C' still owns the separate ActionSurface/recombination relation binding the
//! canonical body actions to these packed leaves.

use noid_chain::exact_state_hash::zero_slot_roots;
use noid_core::Block128;
use noid_gkr::merkle_circuit::MerkleCircuit;
use noid_gkr::state_leaf_killshot::{
    SlotLeafInputs, SLOT_LEAF_LINEAR_RELATION_TAG, SLOT_LEAF_PERMS, SLOT_LEAF_PIN_LANES,
};
use noid_ivc_core::deep_chain::leaf_hash::flat_sponge_leaf_hash;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_EXSTNOD, TAG_EXSTSLT};

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
    alloc_block, const_block, flat_of, mul, pin_eq, poseidon2b_permute, BatchEvalReductionTrace,
    FieldR1csBuilder, LinExpr, RawChannelTrace, F128,
};

fn pad_after_one_field() -> Block128 {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x80;
    bytes[15] = 0x01;
    Block128::from(u128::from_le_bytes(bytes))
}

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
        close_spine_family_batch(
            b,
            ch,
            &main_red,
            &shift_red,
            &chain_red,
            &self.batch,
            self.num_vars,
        )
    }
}

pub struct SlotLeafInputsTrace {
    pub packed_value: LinExpr,
    pub owner_hi: LinExpr,
    pub owner_lo: LinExpr,
    pub expected_leaf: [LinExpr; 2],
}

impl SlotLeafInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &SlotLeafInputs) -> Self {
        Self {
            packed_value: alloc_block(b, native.packed_value),
            owner_hi: alloc_block(b, native.owner_hi),
            owner_lo: alloc_block(b, native.owner_lo),
            expected_leaf: std::array::from_fn(|i| alloc_block(b, native.expected_leaf[i])),
        }
    }

    fn blocks(&self) -> Vec<[LinExpr; 2]> {
        vec![
            [self.packed_value.clone(), self.owner_hi.clone()],
            [self.owner_lo.clone(), const_block(pad_after_one_field())],
        ]
    }
}

pub fn verify_batched_slot_leaf_killshot_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &SpongeFamilyProofTrace,
    inputs: &[SlotLeafInputsTrace],
) -> [BatchEvalReductionTrace; 3] {
    assert!(!inputs.is_empty());
    assert_eq!(proof.live_slots, inputs.len() * SLOT_LEAF_PERMS);
    ch.absorb_const_tower(b, inputs.len() as u128);
    ch.absorb_const_tower(b, TAG_EXSTSLT.as_u64() as u128);
    for input in inputs {
        ch.absorb(b, &input.packed_value);
        ch.absorb(b, &input.owner_hi);
        ch.absorb(b, &input.owner_lo);
        ch.absorb(b, &input.expected_leaf[0]);
        ch.absorb(b, &input.expected_leaf[1]);
    }
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

pub struct ExactStateRootWires {
    pub old_root: [LinExpr; 2],
    pub new_root: [LinExpr; 2],
    pub active_depth: usize,
}

pub struct ExactStateSlotWires {
    pub slot_leaves: Vec<SlotLeafInputsTrace>,
    /// Empty in region mode; the walk-B leg carries the path hashing there.
    pub state_paths: Vec<MerklePathInputsTrace>,
    pub roots: ExactStateRootWires,
}

pub struct ExactStateLeafRegion {
    pub packed_value_w: LinExpr,
    pub owner_hi_w: LinExpr,
    pub owner_lo_w: LinExpr,
    pub expected_leaf_w: [LinExpr; 2],
    pub packed_value_flat: F128,
    pub owner_hi_flat: F128,
    pub owner_lo_flat: F128,
    pub expected_leaf_flat: [F128; 2],
}

pub struct ExactStatePathRegion {
    pub siblings: Vec<[F128; 2]>,
    pub directions: Vec<bool>,
    pub entry_leaf_index: usize,
    pub is_old: bool,
}

pub struct ExactStateRegionData {
    pub leaves: Vec<ExactStateLeafRegion>,
    pub paths: Vec<ExactStatePathRegion>,
    pub d_state: usize,
    pub old_root_w: [LinExpr; 2],
    pub old_root_flat: [F128; 2],
    pub new_root_w: [LinExpr; 2],
    pub new_root_flat: [F128; 2],
}

fn flat2(fields: [Block128; 2]) -> [F128; 2] {
    [flat_of(fields[0]), flat_of(fields[1])]
}

fn alloc_exact_roots(
    b: &mut FieldR1csBuilder,
    inputs: &crate::block_certificate_backend::ExactStateKillShotInputs,
) -> ExactStateRootWires {
    assert_eq!(inputs.slot_leaves.len(), inputs.state_paths.len());
    assert!(!inputs.state_paths.is_empty());
    assert_eq!(inputs.state_paths.len() % 2, 0, "old ++ new halves");
    let t = inputs.state_paths.len() / 2;
    let active_depth = inputs.state_paths[0].active_depth;
    let old_native = inputs.state_paths[0].expected_root;
    let new_native = inputs.state_paths[t].expected_root;
    for (j, path) in inputs.state_paths.iter().enumerate() {
        assert_eq!(
            path.active_depth, active_depth,
            "all state paths share depth"
        );
        assert_eq!(path.leaf, inputs.slot_leaves[j].expected_leaf);
        assert_eq!(
            path.expected_root,
            if j < t { old_native } else { new_native },
            "path half must share one expected root"
        );
    }
    ExactStateRootWires {
        old_root: std::array::from_fn(|i| alloc_block(b, old_native[i])),
        new_root: std::array::from_fn(|i| alloc_block(b, new_native[i])),
        active_depth,
    }
}

fn assemble_exact_state_region_data(
    inputs: &crate::block_certificate_backend::ExactStateKillShotInputs,
    slot_leaves: &[SlotLeafInputsTrace],
    roots: &ExactStateRootWires,
) -> ExactStateRegionData {
    let t = inputs.state_paths.len() / 2;
    let leaves = inputs
        .slot_leaves
        .iter()
        .zip(slot_leaves.iter())
        .map(|(native, wires)| {
            let leaf = ExactStateLeafRegion {
                packed_value_w: wires.packed_value.clone(),
                owner_hi_w: wires.owner_hi.clone(),
                owner_lo_w: wires.owner_lo.clone(),
                expected_leaf_w: wires.expected_leaf.clone(),
                packed_value_flat: flat_of(native.packed_value),
                owner_hi_flat: flat_of(native.owner_hi),
                owner_lo_flat: flat_of(native.owner_lo),
                expected_leaf_flat: flat2(native.expected_leaf),
            };
            assert_eq!(
                flat_sponge_leaf_hash(
                    leaf.packed_value_flat,
                    leaf.owner_hi_flat,
                    leaf.owner_lo_flat,
                ),
                leaf.expected_leaf_flat,
                "slot-leaf statement digest != flat sponge replay"
            );
            leaf
        })
        .collect();
    let paths = inputs
        .state_paths
        .iter()
        .enumerate()
        .map(|(j, path)| ExactStatePathRegion {
            siblings: path.siblings[..roots.active_depth]
                .iter()
                .map(|s| flat2(*s))
                .collect(),
            directions: path.directions[..roots.active_depth].to_vec(),
            entry_leaf_index: j,
            is_old: j < t,
        })
        .collect();
    ExactStateRegionData {
        leaves,
        paths,
        d_state: roots.active_depth,
        old_root_w: roots.old_root.clone(),
        old_root_flat: flat2(inputs.state_paths[0].expected_root),
        new_root_w: roots.new_root.clone(),
        new_root_flat: flat2(inputs.state_paths[t].expected_root),
    }
}

pub fn scratch_exact_state_region_data(
    b: &mut FieldR1csBuilder,
    inputs: &crate::block_certificate_backend::ExactStateKillShotInputs,
) -> ExactStateRegionData {
    let slot_leaves = inputs
        .slot_leaves
        .iter()
        .map(|input| SlotLeafInputsTrace::alloc(b, input))
        .collect::<Vec<_>>();
    let roots = alloc_exact_roots(b, inputs);
    assemble_exact_state_region_data(inputs, &slot_leaves, &roots)
}

pub fn build_exact_state_slot(
    b: &mut FieldR1csBuilder,
    inputs: &crate::block_certificate_backend::ExactStateKillShotInputs,
    proof: &crate::block_certificate_backend::ExactStateKillShotProof,
) -> ExactStateSlotWires {
    build_exact_state_slot_with_config(b, inputs, proof, false).0
}

pub fn build_exact_state_slot_with_config(
    b: &mut FieldR1csBuilder,
    inputs: &crate::block_certificate_backend::ExactStateKillShotInputs,
    proof: &crate::block_certificate_backend::ExactStateKillShotProof,
    region: bool,
) -> (ExactStateSlotWires, Option<ExactStateRegionData>) {
    assert!(!inputs.slot_leaves.is_empty());
    assert!(!inputs.state_paths.is_empty());
    let slot_leaves = inputs
        .slot_leaves
        .iter()
        .map(|input| SlotLeafInputsTrace::alloc(b, input))
        .collect::<Vec<_>>();
    let roots = alloc_exact_roots(b, inputs);

    let state_paths = if region {
        Vec::new()
    } else {
        let mut ch = RawChannelTrace::new();
        let family = SpongeFamilyProofTrace::alloc(
            b,
            &proof.slot_leaves.kill_shot,
            &proof.slot_leaves.chain,
            &proof.slot_leaves.batch,
            proof.slot_leaves.num_vars,
            proof.slot_leaves.live_slots,
            inputs.slot_leaves.len() * SLOT_LEAF_PERMS,
        );
        let reductions = verify_batched_slot_leaf_killshot_trace(b, &mut ch, &family, &slot_leaves);
        discharge_batched_slot_leaf_trace(b, &slot_leaves, &reductions);

        let paths = inputs
            .state_paths
            .iter()
            .map(|input| MerklePathInputsTrace::alloc(b, input))
            .collect::<Vec<_>>();
        let path_proof = BatchedMerkleProofTrace::alloc(b, &proof.state_paths, &paths);
        let circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
        let mut ch = RawChannelTrace::new();
        let reductions =
            verify_batched_merkle_killshot_trace(b, &mut ch, &circuit, &path_proof, &paths);
        discharge_batched_merkle_trace(b, &circuit, &paths, &reductions);

        let t = paths.len() / 2;
        for (j, path) in paths.iter().enumerate() {
            pin_pair(b, &path.leaf, &slot_leaves[j].expected_leaf);
            pin_pair(
                b,
                &path.expected_root,
                if j < t {
                    &roots.old_root
                } else {
                    &roots.new_root
                },
            );
        }
        paths
    };

    let region_data =
        region.then(|| assemble_exact_state_region_data(inputs, &slot_leaves, &roots));
    (
        ExactStateSlotWires {
            slot_leaves,
            state_paths,
            roots,
        },
        region_data,
    )
}

fn pin_pair(b: &mut FieldR1csBuilder, a: &[LinExpr; 2], c: &[LinExpr; 2]) {
    pin_eq(b, &a[0], &c[0]);
    pin_eq(b, &a[1], &c[1]);
}

/// Bind exact-state path roots/depth directly to the parent and child header
/// statement wires. `parent_log_slots` is class/native metadata already bound
/// to `parent_log`; `roots.active_depth` is the child path class.
pub fn bind_exact_state_header_roots(
    b: &mut FieldR1csBuilder,
    roots: &ExactStateRootWires,
    parent_root: &[LinExpr; 2],
    parent_log: &LinExpr,
    parent_log_slots: u32,
    child_root: &[LinExpr; 2],
    child_log: &LinExpr,
) -> LinExpr {
    let child_log_slots = roots.active_depth as u32;
    assert!(
        child_log_slots == parent_log_slots || child_log_slots == parent_log_slots + 1,
        "exact-state depth must stay equal or grow by one"
    );
    assert!(child_log_slots > 0, "exact-state paths have non-zero depth");
    let grows = child_log_slots == parent_log_slots + 1;
    let grow = LinExpr::from_wire(b.alloc_bool(grows));
    // Fixed child-depth matrix: parent depth is selected between d and d-1.
    // Integer encodings are tower constants; selection in characteristic two
    // uses `d + grow * (d XOR (d-1))`.
    let parent_same = Block128::from(child_log_slots as u128);
    let parent_grow = Block128::from((child_log_slots - 1) as u128);
    let parent_selected =
        const_block(parent_same).add(&grow.scale(flat_of(parent_same + parent_grow)));
    pin_eq(b, parent_log, &parent_selected);
    pin_eq(
        b,
        child_log,
        &const_block(Block128::from(child_log_slots as u128)),
    );
    pin_pair(b, &roots.new_root, child_root);
    // Always compute the grow candidate at d-1 so equal/grow share one matrix.
    let grow_parent_depth = child_log_slots as usize - 1;
    let zeros = zero_slot_roots(grow_parent_depth);
    let zero = digest_to_fields(zeros[grow_parent_depth]);
    let iv = capacity_iv(TAG_EXSTNOD);
    let state = poseidon2b_permute(
        b,
        [
            parent_root[0].clone(),
            parent_root[1].clone(),
            const_block(iv[0]),
            const_block(iv[1]),
        ],
    );
    let state = poseidon2b_permute(
        b,
        [
            state[0].add(&const_block(zero[0])),
            state[1].add(&const_block(zero[1])),
            state[2].clone(),
            state[3].clone(),
        ],
    );
    for lane in 0..2 {
        let delta = state[lane].add(&parent_root[lane]);
        let selected = parent_root[lane].add(&mul(b, &grow, &delta));
        pin_eq(b, &roots.old_root[lane], &selected);
    }
    grow
}

fn digest_to_fields(hash: [u8; 32]) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap())),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::exact_state_hash::state_node_hash;
    use noid_ivc_core::field::F128 as Field;
    use noid_ivc_core::field_r1cs::FieldR1cs;

    fn root_wires(
        b: &mut FieldR1csBuilder,
        old: [Block128; 2],
        new: [Block128; 2],
        depth: usize,
    ) -> ExactStateRootWires {
        ExactStateRootWires {
            old_root: std::array::from_fn(|i| alloc_block(b, old[i])),
            new_root: std::array::from_fn(|i| alloc_block(b, new[i])),
            active_depth: depth,
        }
    }

    struct BindingCase {
        r1cs: FieldR1cs,
        z: Vec<Field>,
        parent_root: [usize; 2],
        old_root: [usize; 2],
        new_root: [usize; 2],
        child_root: [usize; 2],
        parent_log: usize,
        child_log: usize,
        grow: usize,
    }

    fn wire(expr: &LinExpr) -> usize {
        expr.terms[0].0 as usize
    }

    fn binding_case(grows: bool) -> BindingCase {
        const CHILD_DEPTH: usize = 5;
        let parent_digest = [7u8; 32];
        let parent = digest_to_fields(parent_digest);
        let zeros = zero_slot_roots(CHILD_DEPTH - 1);
        let old = if grows {
            digest_to_fields(state_node_hash(parent_digest, zeros[CHILD_DEPTH - 1]))
        } else {
            parent
        };
        let child = [Block128::from(31u128), Block128::from(32u128)];
        let mut b = FieldR1csBuilder::new();
        let roots = root_wires(&mut b, old, child, CHILD_DEPTH);
        let parent_w = std::array::from_fn(|i| alloc_block(&mut b, parent[i]));
        let child_w = std::array::from_fn(|i| alloc_block(&mut b, child[i]));
        let parent_depth = CHILD_DEPTH - usize::from(grows);
        let parent_log = alloc_block(&mut b, Block128::from(parent_depth as u128));
        let child_log = alloc_block(&mut b, Block128::from(CHILD_DEPTH as u128));
        let grow = bind_exact_state_header_roots(
            &mut b,
            &roots,
            &parent_w,
            &parent_log,
            parent_depth as u32,
            &child_w,
            &child_log,
        );
        let parent_root = std::array::from_fn(|lane| wire(&parent_w[lane]));
        let old_root = std::array::from_fn(|lane| wire(&roots.old_root[lane]));
        let new_root = std::array::from_fn(|lane| wire(&roots.new_root[lane]));
        let child_root = std::array::from_fn(|lane| wire(&child_w[lane]));
        let parent_log = wire(&parent_log);
        let child_log = wire(&child_log);
        let grow = wire(&grow);
        let (r1cs, z) = b.build();
        BindingCase {
            r1cs,
            z,
            parent_root,
            old_root,
            new_root,
            child_root,
            parent_log,
            child_log,
            grow,
        }
    }

    #[test]
    fn equal_and_grow_share_one_child_depth_matrix() {
        let equal = binding_case(false);
        let grow = binding_case(true);
        assert!(equal.r1cs.satisfies(&equal.z));
        assert!(grow.r1cs.satisfies(&grow.z));
        assert_eq!(
            equal.r1cs.statement_digest(),
            grow.r1cs.statement_digest(),
            "grow selector must not change the child-depth matrix"
        );
    }

    #[test]
    fn root_depth_grow_and_zero_subtree_tamper_reject() {
        for grows in [false, true] {
            let case = binding_case(grows);
            assert!(case.r1cs.satisfies(&case.z));
            for (wire, label) in [
                (case.parent_root[0], "parent header root lane 0"),
                (case.parent_root[1], "parent header root lane 1"),
                (case.old_root[0], "old path root lane 0"),
                (case.old_root[1], "old path root lane 1"),
                (case.new_root[0], "new path root lane 0"),
                (case.new_root[1], "new path root lane 1"),
                (case.child_root[0], "child header root lane 0"),
                (case.child_root[1], "child header root lane 1"),
                (case.parent_log, "parent depth"),
                (case.child_log, "child depth"),
                (case.grow, "grow selector"),
            ] {
                let mut bad = case.z.clone();
                bad[wire] += Field::ONE;
                assert!(
                    !case.r1cs.satisfies(&bad),
                    "{label} tamper must fail in grows={grows} branch"
                );
            }
        }
    }
}
