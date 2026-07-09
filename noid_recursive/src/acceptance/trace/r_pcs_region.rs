// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The [R] PCS hashing discharged through LINK-LOCAL region walks — the
//! split link's diet ([`super::self_verify::PcsWalkObligations`] consumer).
//!
//! A deferred [R] replay in region mode records every PCS leaf sponge and
//! Merkle path as an obligation instead of replaying it inline (~90% of
//! the replay). This module hosts the obligations of BOTH of the split
//! link's [R]s on TWO shared walks:
//!
//! - **walk L-A (leaves)** — one combined duplex union: each (proof,
//!   query) is a tile whose sub-channels are that query's leaf hashes,
//!   compiled as absorb-only schedules with the length-bound `IVCPCSF_`
//!   capacity IV (every [R] PCS leaf is even-lane, fixed no-pad mode).
//!   A leaf's digest is the C0/C1 carry cells at its sub-channel's last
//!   real slot; its absorbed lanes pin to the A-lane cells (the same
//!   proof wires the fold algebra consumes — Stage-2 cell pins).
//! - **walk L-B (paths)** — one ff-Merkle union with the `IVCPCSN_`
//!   capacity IV (the 1-permutation feed-forward node of the proof-core
//!   PCS): one leg family per (proof, tree), one path per query block.
//!   The block axis is the QUERY (patterns stay `O(2^block_log)`, flat
//!   in the query count). Entry binding: fresh digest wires pin to BOTH
//!   the walk L-A digest cells and the leg's CR(start) cells; direction
//!   cells pin to the transcript-bound query-position bits; the
//!   recomputed root `C + CR + D·(CR + SIB)` at each path's last node
//!   pins to the FS-observed root wire (commitment root / post-row-batch
//!   commit / epoch commits — all absorbed before the query draw, the
//!   capsule's authentication-root rule).
//!
//! Both walks' committed columns are opened through [`RegionPcsClaim`]s
//! the caller threads through the link's public IO; the walks' own
//! discharge transcripts replay inline (a walk cannot host its own
//! transcript, and at link scale the two transcripts are cheap).
//!
//! Tree-structure invariant: every ladder shape yields the same leaf
//! signature — `[2^log_batch_size, 2^a0, 2^a0, 2^a0]` lanes (the
//! trailing sub-arity-`a0` fold layers live in the plaintext tail, never
//! behind a commitment) — asserted at assembly, so one sub-channel
//! schedule serves every tile.

use noid_ivc_core::deep_chain::ff_merkle::{
    ff_merkle_fixed_patterns, build_ff_merkle_path_columns, FfMerkleFamilyRefs,
    FfMerklePathFamily, FfMerklePathWitness,
};
use noid_ivc_core::deep_chain::relations::FixedPattern;
use noid_ivc_core::deep_chain::schedule::{compile_duplex, TranscriptOp};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, FsChannelTrace, LinExpr};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::WitnessSlice;
use noid_poseidon2b::native::permutation::STATE_SIZE;

use super::region_source_binding::{
    alloc_column_slice, build_combined_duplex_union, common_period_ones, common_period_pattern,
    discharge_duplex_union, discharge_merkle_union, duplex_data_positions, place_ff,
    run_duplex_union_native, run_merkle_union_native, slot_cell, DuplexUnion, FfLegSpec,
    MerkleLeg, RegionPcsClaim, SubChannel,
};
use super::self_verify::{
    flat_digest_lanes, pcs_leaf_iv_flat, pcs_node_iv_flat, PcsWalkObligations,
};
use super::{mul, pin_eq};

const DOMAIN_LA: &[u8] = b"r-pcs-leaf-union-v0";
const DOMAIN_LB: &[u8] = b"r-pcs-merkle-union-v0";

/// Walk L-B committed column layout (the wallet walk-B convention):
/// `C0..C3` at 0..4, `CR0..CR1` at 4..6, `SIB0..SIB1` at 6..8, `D` at 8.
const N_COMMITTED_B: usize = 9;

/// One verified proof's PCS side, as the assembly consumes it.
pub struct RPcsProof<'a> {
    pub native: &'a pcs::BaseFoldProof,
    pub params: &'a PcsParams,
    /// The initial codeword commitment root (flat lanes) — tree 0's root;
    /// the later trees' roots live in the proof itself.
    pub commitment_root: [F128; 2],
}

/// One authenticated tree of a proof: its leaf lane count and path depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TreeInfo {
    lanes: usize,
    depth: usize,
}

/// The per-proof tree ladder, mirroring `basefold_verify_trace`'s shape
/// math: the initial codeword tree, the post-row-batch tree, then one
/// tree per FRI epoch commitment.
fn tree_structure(params: &PcsParams) -> Vec<TreeInfo> {
    let log_msg_len = params.m - pcs::LOG_PACKING;
    let log_batch_size = params.log_batch_size;
    let log_dim = log_msg_len - log_batch_size;
    let k_code = log_dim + params.log_inv_rate;
    let arities = pcs::compute_fri_arities(log_dim);
    let (num_fri_commits, _) = pcs::fri_commit_layout(k_code, &arities);
    let arity_0 = arities.first().copied().unwrap_or(0);
    let mut trees = vec![TreeInfo { lanes: 1 << log_batch_size, depth: k_code }];
    if !arities.is_empty() {
        trees.push(TreeInfo {
            lanes: 1 << arity_0,
            depth: k_code - arity_0,
        });
        let mut cum = arity_0;
        for i in 0..num_fri_commits {
            let next = arities[i + 1];
            trees.push(TreeInfo {
                lanes: 1 << next,
                depth: k_code - cum - next,
            });
            cum += next;
        }
    }
    trees
}

/// The native leaf lanes of tree `t` for query `q`.
fn native_leaf_lanes<'a>(q: &'a pcs::basefold::QueryOpening, t: usize) -> &'a [F128] {
    match t {
        0 => &q.initial_leaf,
        1 => &q.post_row_batch_leaf,
        _ => &q.epoch_leaves[t - 2],
    }
}

/// The native sibling digests of tree `t` for query `q`, bottom-up flat.
fn native_path(q: &pcs::basefold::QueryOpening, t: usize) -> Vec<[F128; 2]> {
    let path = match t {
        0 => &q.initial_path,
        1 => &q.post_row_batch_path,
        _ => &q.epoch_paths[t - 2],
    };
    path.iter().map(flat_digest_lanes).collect()
}

/// The native root lanes of tree `t` (tree 0's root is the commitment,
/// supplied by the caller).
fn native_root(p: &RPcsProof<'_>, t: usize) -> [F128; 2] {
    match t {
        0 => p.commitment_root,
        1 => flat_digest_lanes(&p.native.post_row_batch_commit.root),
        _ => flat_digest_lanes(&p.native.round_commitments[t - 2].root),
    }
}

/// The direction-bit offset of tree `t`'s path within the query-position
/// bits (mirror of the replay's `&bits[..]` slices).
fn dir_bit_offset(trees: &[TreeInfo], t: usize, k_code: usize) -> usize {
    // depth = k_code - offset for every tree.
    k_code - trees[t].depth
}

/// Native leaf digest: `merkle::hash_leaf` over the flat lane bytes.
fn native_leaf_digest(lanes: &[F128]) -> [F128; 2] {
    let mut bytes = Vec::with_capacity(lanes.len() * 16);
    for l in lanes {
        let v = (l.lo as u128) | ((l.hi as u128) << 64);
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    flat_digest_lanes(&noid_ivc_core::merkle::hash_leaf(&bytes))
}

/// Everything both the native mirror and the trace discharge derive from
/// the native proofs — built ONCE, deterministically.
struct Assembly {
    u_a: DuplexUnion,
    /// Per (proof, query, tree): the native leaf digest.
    digests: Vec<Vec<Vec<[F128; 2]>>>,
    /// Per proof: the tree ladder.
    trees: Vec<Vec<TreeInfo>>,
    /// Sub-channel stride log of walk L-A (`S = 2^s_log` slots per sub).
    s_log: usize,
    n_queries: usize,
    // ---- walk L-B ----
    cb: Vec<Vec<F128>>,
    s0b: [Vec<F128>; STATE_SIZE],
    soutb: [Vec<F128>; STATE_SIZE],
    fixed_b: Vec<FixedPattern>,
    ff_specs: Vec<FfLegSpec>,
    /// Per (proof, tree): the leg's slot offset within a query block.
    leg_offsets: Vec<Vec<usize>>,
    block_log_b: usize,
    w_log_b: usize,
}

fn build_assembly(proofs: &[RPcsProof<'_>]) -> Assembly {
    assert!(!proofs.is_empty(), "at least one [R] proof");
    let trees: Vec<Vec<TreeInfo>> = proofs.iter().map(|p| tree_structure(p.params)).collect();
    let n_queries = proofs[0].native.queries.len();
    for p in proofs {
        assert_eq!(p.native.queries.len(), n_queries, "query counts must agree");
    }
    // One shared leaf-schedule signature (lane counts per tree).
    let lanes_sig: Vec<usize> = trees[0].iter().map(|t| t.lanes).collect();
    for tr in &trees {
        let sig: Vec<usize> = tr.iter().map(|t| t.lanes).collect();
        assert_eq!(
            sig, lanes_sig,
            "the [R] proofs must share the leaf-schedule signature (lanes per tree)"
        );
    }
    let n_trees = lanes_sig.len();

    // ---- Walk L-A: sub-channels + tiles.
    let subs: Vec<SubChannel> = lanes_sig
        .iter()
        .map(|&lanes| {
            assert!(lanes >= 2 && lanes % 2 == 0, "even-lane leaves only");
            SubChannel {
                layout: compile_duplex(&[TranscriptOp::Absorb(vec![None; lanes])]),
                iv_flat: pcs_leaf_iv_flat(lanes),
            }
        })
        .collect();
    let s = subs
        .iter()
        .map(|c| c.layout.slots.len())
        .max()
        .unwrap()
        .max(1)
        .next_power_of_two();
    let s_log = s.trailing_zeros() as usize;
    let mut tiles: Vec<Vec<Vec<F128>>> = Vec::with_capacity(proofs.len() * n_queries);
    let mut digests: Vec<Vec<Vec<[F128; 2]>>> = Vec::with_capacity(proofs.len());
    for p in proofs {
        let mut per_proof = Vec::with_capacity(n_queries);
        for q in &p.native.queries {
            let mut tile = Vec::with_capacity(n_trees);
            let mut ds = Vec::with_capacity(n_trees);
            for t in 0..n_trees {
                let lanes = native_leaf_lanes(q, t);
                assert_eq!(lanes.len(), lanes_sig[t], "native leaf off signature");
                tile.push(lanes.to_vec());
                ds.push(native_leaf_digest(lanes));
            }
            tiles.push(tile);
            per_proof.push(ds);
        }
        digests.push(per_proof);
    }
    let u_a = build_combined_duplex_union(&subs, &tiles);
    // Sanity: the C0/C1 cells at each sub-channel's last real slot carry
    // the native leaf digest (the fixed no-pad sponge reads its state
    // directly after the last absorb permutation).
    let per_tile = 1usize << u_a.block_log;
    for (pi, per_proof) in digests.iter().enumerate() {
        for (qi, ds) in per_proof.iter().enumerate() {
            let tile_off = (pi * n_queries + qi) * per_tile;
            for (t, d) in ds.iter().enumerate() {
                let dslot = tile_off + t * s + lanes_sig[t] / 2 - 1;
                assert_eq!(
                    [u_a.committed[2][dslot], u_a.committed[3][dslot]],
                    *d,
                    "leaf digest cell mismatch (proof {pi}, query {qi}, tree {t})"
                );
            }
        }
    }

    // ---- Walk L-B: ff legs per (proof, tree), one path per query block.
    let iv_node = pcs_node_iv_flat();
    let mut leg_offsets: Vec<Vec<usize>> = Vec::with_capacity(proofs.len());
    let mut off = 0usize;
    for tr in &trees {
        let mut per_proof = Vec::with_capacity(tr.len());
        for t in tr {
            per_proof.push(off);
            off += t.depth.next_power_of_two();
        }
        leg_offsets.push(per_proof);
    }
    let block_b = off.next_power_of_two();
    let block_log_b = block_b.trailing_zeros() as usize;
    let n_blocks_b = n_queries.next_power_of_two();
    let pb = n_blocks_b * block_b;
    let w_log_b = pb.trailing_zeros() as usize;

    let mut cb: Vec<Vec<F128>> = (0..N_COMMITTED_B).map(|_| vec![F128::ZERO; pb]).collect();
    let mut s0b: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let mut soutb: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let (gh0, gho) = noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..pb {
        for j in 0..STATE_SIZE {
            s0b[j][slot] = gh0[j];
            soutb[j][slot] = gho[j];
            cb[j][slot] = gho[j];
        }
    }
    let mut fixed_b: Vec<FixedPattern> = Vec::new();
    let mut ff_specs: Vec<FfLegSpec> = Vec::new();
    for (pi, p) in proofs.iter().enumerate() {
        for (t, tree) in trees[pi].iter().enumerate() {
            let family = FfMerklePathFamily { depth: tree.depth, n_paths: 1 };
            let stride = family.stride();
            let base = fixed_b.len();
            for pat in ff_merkle_fixed_patterns(&family, iv_node) {
                fixed_b.push(common_period_pattern(
                    &pat.table,
                    leg_offsets[pi][t],
                    1,
                    block_log_b,
                ));
            }
            fixed_b.push(common_period_ones(leg_offsets[pi][t], stride, block_log_b));
            ff_specs.push(FfLegSpec {
                refs: FfMerkleFamilyRefs {
                    cr: [4, 5],
                    sib: [6, 7],
                    d: 8,
                    c: std::array::from_fn(|i| i),
                    node: base,
                    nodens: base + 1,
                    start: base + 2,
                    iv: [base + 3, base + 4],
                },
                region: base + 5,
            });
            // Place every query's path chain for this leg. The query axis
            // is padded to a power of two and the family patterns are
            // PERIODIC over the query blocks, so the pad blocks must
            // carry VALID (zero-witness) chains — never bare ghost
            // permutations.
            let fam_wlog = stride.trailing_zeros() as usize;
            let root = native_root(p, t);
            let bit_off = dir_bit_offset(&trees[pi], t, trees[pi][0].depth);
            for qi in 0..n_blocks_b {
                let wit = if let Some(q) = p.native.queries.get(qi) {
                    FfMerklePathWitness {
                        entry: digests[pi][qi][t],
                        siblings: native_path(q, t),
                        directions: (0..tree.depth)
                            .map(|kk| (q.position >> (bit_off + kk)) & 1 == 1)
                            .collect(),
                    }
                } else {
                    FfMerklePathWitness {
                        entry: [F128::ZERO; 2],
                        siblings: vec![[F128::ZERO; 2]; tree.depth],
                        directions: vec![false; tree.depth],
                    }
                };
                let fcols = build_ff_merkle_path_columns(&family, iv_node, &[wit], fam_wlog);
                if qi < n_queries {
                    assert_eq!(
                        fcols.roots[0], root,
                        "ff leg root != committed root (proof {pi}, tree {t}, query {qi})"
                    );
                }
                place_ff(
                    &mut cb,
                    &mut s0b,
                    &mut soutb,
                    &fcols,
                    qi * block_b + leg_offsets[pi][t],
                    stride,
                );
            }
        }
    }

    Assembly {
        u_a,
        digests,
        trees,
        s_log,
        n_queries,
        cb,
        s0b,
        soutb,
        fixed_b,
        ff_specs,
        leg_offsets,
        block_log_b,
        w_log_b,
    }
}

/// The native (point, value) stream of every walk opening claim, in the
/// exact discharge order — the split link's IO fill (mirror of
/// `region_wallet_pcs_native`). Deterministic in the proofs alone.
pub fn r_pcs_region_native(proofs: &[RPcsProof<'_>]) -> Vec<(Vec<F128>, F128)> {
    let asm = build_assembly(proofs);
    let native_a = run_duplex_union_native(&asm.u_a, DOMAIN_LA);
    let committed_b: Vec<&[F128]> = asm.cb.iter().map(|c| c.as_slice()).collect();
    let c_refs: [usize; STATE_SIZE] = std::array::from_fn(|i| i);
    let legs: Vec<MerkleLeg> = Vec::new();
    let native_b = run_merkle_union_native(
        &committed_b,
        &asm.s0b,
        &asm.soutb,
        &asm.fixed_b,
        &c_refs,
        &asm.ff_specs,
        &legs,
        asm.w_log_b,
        DOMAIN_LB,
    );
    let mut out: Vec<(Vec<F128>, F128)> = Vec::new();
    for (_, pt, v) in &native_a.pending {
        out.push((pt.clone(), *v));
    }
    for (_, pt, v) in &native_b.pending {
        out.push((pt.clone(), *v));
    }
    out
}

/// Discharge BOTH [R]s' PCS obligations on the two link walks: allocate
/// the committed columns, replay each walk's discharge in-trace, and bind
/// every obligation (leaf lanes → A cells, leaf digests → L-A digest
/// cells AND L-B entry cells, direction bits → D cells, recomputed roots
/// → the FS-observed root wires). Returns the committed-column opening
/// claims for the caller's public-IO tail — claim order matches
/// [`r_pcs_region_native`].
pub(crate) fn discharge_r_pcs_via_region(
    b: &mut FieldR1csBuilder,
    proofs: &[RPcsProof<'_>],
    obligations: &[&PcsWalkObligations],
) -> Vec<RegionPcsClaim> {
    assert_eq!(proofs.len(), obligations.len(), "one obligation set per proof");
    let asm = build_assembly(proofs);
    let n_trees = asm.trees[0].len();
    for (pi, obs) in obligations.iter().enumerate() {
        assert_eq!(
            obs.leaves.len(),
            asm.n_queries * n_trees,
            "proof {pi}: leaf obligation count off the tree ladder"
        );
        assert_eq!(obs.paths.len(), obs.leaves.len(), "proof {pi}: path/leaf pairing");
    }

    // ---- Natives (both walks) + column allocation.
    let native_a = run_duplex_union_native(&asm.u_a, DOMAIN_LA);
    let committed_b: Vec<&[F128]> = asm.cb.iter().map(|c| c.as_slice()).collect();
    let c_refs: [usize; STATE_SIZE] = std::array::from_fn(|i| i);
    let legs: Vec<MerkleLeg> = Vec::new();
    let native_b = run_merkle_union_native(
        &committed_b,
        &asm.s0b,
        &asm.soutb,
        &asm.fixed_b,
        &c_refs,
        &asm.ff_specs,
        &legs,
        asm.w_log_b,
        DOMAIN_LB,
    );
    let slices_a: Vec<WitnessSlice> = asm
        .u_a
        .committed
        .iter()
        .map(|c| alloc_column_slice(b, c, asm.u_a.w_log).0)
        .collect();
    let slices_b: Vec<WitnessSlice> = asm
        .cb
        .iter()
        .map(|c| alloc_column_slice(b, c, asm.w_log_b).0)
        .collect();

    // ---- The two walk discharges (inline transcripts — a walk cannot
    // host its own transcript, and at link scale both are cheap).
    let mut ch_a = FsChannelTrace::new(b, DOMAIN_LA);
    let mut claims = discharge_duplex_union(b, &mut ch_a, &asm.u_a, &native_a, 0);
    let mut ch_b = FsChannelTrace::new(b, DOMAIN_LB);
    let (mut claims_b, leg_pins) = discharge_merkle_union(
        b,
        &mut ch_b,
        &asm.fixed_b,
        &c_refs,
        &asm.ff_specs,
        &legs,
        asm.w_log_b,
        &native_b,
    );
    assert!(leg_pins.is_empty(), "no 2-perm legs in the link walks");
    for c in claims_b.iter_mut() {
        c.slice += slices_a.len();
    }
    claims.extend(claims_b);

    // ---- Stage-2 cell pins.
    let per_tile = 1usize << asm.u_a.block_log;
    let s = 1usize << asm.s_log;
    let block_b = 1usize << asm.block_log_b;
    let data_positions = duplex_data_positions(&asm.u_a.layout);
    for (pi, obs) in obligations.iter().enumerate() {
        for qi in 0..asm.n_queries {
            let tile_off = (pi * asm.n_queries + qi) * per_tile;
            // Leaf lanes → A-lane cells (tile-flattened sub order == the
            // obligation push order: initial, post, epochs).
            let flat: Vec<&LinExpr> = (0..n_trees)
                .flat_map(|t| obs.leaves[qi * n_trees + t].lanes.iter())
                .collect();
            assert_eq!(flat.len(), data_positions.len(), "leaf lane count vs layout");
            for (wire, &(slot, lane)) in flat.iter().zip(data_positions.iter()) {
                pin_eq(b, wire, &slot_cell(&slices_a[asm.u_a.refs.a[lane]], tile_off + slot));
            }
            for t in 0..n_trees {
                let ob = &obs.paths[qi * n_trees + t];
                assert_eq!(ob.leaf, qi * n_trees + t, "leaf/path pairing");
                let depth = asm.trees[pi][t].depth;
                assert_eq!(ob.dir_bits.len(), depth, "direction bit count");
                // Digest wires: pinned to BOTH the L-A digest cells and
                // the leg's CR(start) cells (the cross-walk entry join).
                let dslot = tile_off + t * s + asm.trees[pi][t].lanes / 2 - 1;
                let leg_slot = qi * block_b + asm.leg_offsets[pi][t];
                for lane in 0..2 {
                    let w = LinExpr::from_wire(b.alloc_f128(asm.digests[pi][qi][t][lane]));
                    pin_eq(b, &w, &slot_cell(&slices_a[asm.u_a.refs.c[lane]], dslot));
                    pin_eq(b, &w, &slot_cell(&slices_b[4 + lane], leg_slot));
                }
                // Direction cells → the transcript-bound position bits.
                for (kk, bit) in ob.dir_bits.iter().enumerate() {
                    pin_eq(b, bit, &slot_cell(&slices_b[8], leg_slot + kk));
                }
                // Recomputed root == the FS-observed root wire.
                let last = leg_slot + depth - 1;
                let d_cell = slot_cell(&slices_b[8], last);
                for lane in 0..2 {
                    let c_cell = slot_cell(&slices_b[lane], last);
                    let cr_cell = slot_cell(&slices_b[4 + lane], last);
                    let sib_cell = slot_cell(&slices_b[6 + lane], last);
                    let mix = mul(b, &d_cell, &cr_cell.add(&sib_cell));
                    pin_eq(b, &c_cell.add(&cr_cell).add(&mix), &ob.root[lane]);
                }
            }
        }
    }

    // ---- Resolve column indices to committed slices.
    let all_slices: Vec<WitnessSlice> = slices_a.into_iter().chain(slices_b).collect();
    claims
        .into_iter()
        .map(|c| RegionPcsClaim {
            slice: all_slices[c.slice],
            point: c.point,
            value: c.value,
            native_point: c.native_point,
            native_value: c.native_value,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::trace::self_verify::{
        alloc_flat_digest, FieldR1csProofTrace, verify_field_trace_deferred_region,
    };
    use noid_ivc_core::challenger::FsLaneChallenger;
    use noid_ivc_core::field_r1cs::synthetic_satisfiable;
    use noid_ivc_core::pcs::LOG_PACKING;
    use noid_ivc_core::proof::FieldShape;
    use noid_ivc_core::public_io::PublicIoSpec;
    use noid_ivc_prover::field_prover::prove_field_with_public_io;

    /// The full [R] PCS walk discharge on TWO proofs of DIFFERENT shapes:
    /// path-free region replays collect the obligations, the two link
    /// walks discharge them, the trace satisfies, the native mirror
    /// agrees claim-for-claim, and one-flip negatives break each binding
    /// class (leaf lane, direction bit, observed root).
    #[test]
    fn r_pcs_region_discharge_two_proofs_and_negatives() {
        let mk = |m: usize, seed: u64| {
            let (inner, z) = synthetic_satisfiable(m, m, seed);
            let spec = PublicIoSpec {
                io_slice: noid_ivc_core::public_io::WitnessSlice { log2_len: 2, index: 4 },
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
            let mut ch = FsLaneChallenger::new(b"r-pcs-region-test");
            let (proof, commitment, _) =
                prove_field_with_public_io(&inner, &z, &params, &spec, &io, &mut ch);
            let digest = inner.statement_digest();
            (FieldShape::of(&inner), params, spec, io, proof, commitment, digest)
        };
        let (shape0, params0, spec0, io0, proof0, com0, dig0) = mk(10, 0xA11CE);
        let (shape1, params1, spec1, io1, proof1, com1, dig1) = mk(11, 0xB0B);

        let mut b = FieldR1csBuilder::new();
        let run = |b: &mut FieldR1csBuilder,
                       shape: &FieldShape,
                       params: &PcsParams,
                       spec: &PublicIoSpec,
                       io: &[F128],
                       proof: &noid_ivc_core::proof::FieldR1csProof,
                       com: &noid_ivc_core::pcs::Commitment,
                       dig: &[u8; 32]|
         -> PcsWalkObligations {
            let digest_e = alloc_flat_digest(b, dig);
            let root = alloc_flat_digest(b, &com.root);
            let io_wires: Vec<LinExpr> =
                io.iter().map(|&v| LinExpr::from_wire(b.alloc_f128(v))).collect();
            let proof_e = FieldR1csProofTrace::alloc_shape_mode(b, proof, shape, params, false);
            let mut ch = FsChannelTrace::new(b, b"r-pcs-region-test");
            let mut obs = PcsWalkObligations::default();
            let _ = verify_field_trace_deferred_region(
                b, &mut ch, shape, params, &digest_e, &root, &proof_e, spec, &io_wires,
                Some(&mut obs),
            );
            obs
        };
        let obs0 = run(&mut b, &shape0, &params0, &spec0, &io0, &proof0, &com0, &dig0);
        let obs1 = run(&mut b, &shape1, &params1, &spec1, &io1, &proof1, &com1, &dig1);

        let proofs = [
            RPcsProof {
                native: &proof0.pcs_open,
                params: &params0,
                commitment_root: flat_digest_lanes(&com0.root),
            },
            RPcsProof {
                native: &proof1.pcs_open,
                params: &params1,
                commitment_root: flat_digest_lanes(&com1.root),
            },
        ];
        let claims = discharge_r_pcs_via_region(&mut b, &proofs, &[&obs0, &obs1]);
        assert!(!claims.is_empty(), "walk opening claims present");
        let rows = b.num_wires();
        eprintln!(
            "[r-pcs-region] two-proof discharge: {rows} wires, {} claims, {} obligations",
            claims.len(),
            obs0.leaves.len() + obs1.leaves.len()
        );

        // Native mirror parity: same claim stream, same (point, value)s.
        let natives = r_pcs_region_native(&proofs);
        assert_eq!(natives.len(), claims.len(), "native mirror claim count");
        for (i, ((npt, nv), c)) in natives.iter().zip(claims.iter()).enumerate() {
            assert_eq!(&c.native_point, npt, "claim {i} native point");
            assert_eq!(c.native_value, *nv, "claim {i} native value");
            for (e, n) in c.point.iter().zip(npt.iter()) {
                assert_eq!(e.eval(b.values()), *n, "claim {i} point wire vs native");
            }
            assert_eq!(c.value.eval(b.values()), *nv, "claim {i} value wire vs native");
        }

        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest r-pcs walk discharge unsatisfiable");

        // One-flip negatives on each binding class.
        let wire_of = |e: &LinExpr| -> usize {
            assert_eq!(e.terms.len(), 1, "single-wire expression expected");
            e.terms[0].0 as usize
        };
        let mut flips: Vec<(usize, &str)> = Vec::new();
        flips.push((wire_of(&obs0.leaves[0].lanes[0]), "leaf lane (proof 0)"));
        flips.push((wire_of(&obs1.leaves[3].lanes[1]), "leaf lane (proof 1)"));
        flips.push((wire_of(&obs0.paths[0].dir_bits[0]), "direction bit"));
        flips.push((wire_of(&obs1.paths[1].root[0]), "observed root lane"));
        for (w, what) in flips {
            let mut bad = z.clone();
            bad[w] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "{what} flip slipped through");
        }
    }
}
