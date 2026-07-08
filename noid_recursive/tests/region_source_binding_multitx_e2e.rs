// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! [G] step 4 Stage 1 — MULTI-TX gate for the plural
//! `discharge_auth_pcs_obligations_via_region`. Builds K wallet-capsule
//! obligations in ONE builder, discharges them all in ONE call (tiling walk A
//! source-tree+leaves and walk B merkle at common-period offsets, K per-tree
//! exposures, per-tx algebra), wraps the returned committed-column opening
//! claims in the public-IO discharge, and exercises honest + a money negative.
//!
//! The K txs' hashing-heavy families TILE into ONE walk A + ONE walk B, so the
//! walk cost is logarithmic in the tiled domain — the flatness the 255-tx block
//! rests on, proven end to end in-trace at K=2.

use noid_core::Block128;
use noid_gkr::auth_pcs::{commit_auth_mle_column, open_auth_mle_committed, AuthMleOpeningProof};
use noid_gkr::batch_eval::BatchEvalReduction;

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};

use noid_recursive::acceptance::trace::fri_pcs::alloc_digest;
use noid_recursive::acceptance::trace::owner_auth::PendingAuthPcsObligation;
use noid_recursive::acceptance::trace::region_source_binding::{
    discharge_auth_pcs_obligations_via_region, RegionDischargeParams, RegionPcsClaim,
    SpineInstanceRegion, SpineRegionData,
};
use noid_recursive::acceptance::trace::{alloc_block, alloc_blocks, BatchEvalReductionTrace};

const NQ: usize = 4;
const SB8_AUTH_LAYERS: usize = 2;
const OUTER: &[u8] = b"region-source-binding-multitx-e2e";

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn f128_block(&mut self) -> Block128 {
        Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
    }
}

fn capsule_fixture(num_vars: usize, seed: u64) -> (Vec<Block128>, BatchEvalReduction, AuthMleOpeningProof) {
    use noid_core::mle::evaluate::evaluate_slice;
    let mut rng = Rng(seed);
    let column: Vec<Block128> = (0..(1usize << num_vars)).map(|_| rng.f128_block()).collect();
    let point: Vec<Block128> = (0..num_vars).map(|_| rng.f128_block()).collect();
    let value = evaluate_slice(&column, &point);
    let reduction = BatchEvalReduction { point: point.clone(), value };
    let mut committed = commit_auth_mle_column(&column, num_vars);
    let proof = open_auth_mle_committed(&mut committed, num_vars, &reduction);
    (point, reduction, proof)
}

fn alloc_column_slice(b: &mut FieldR1csBuilder, col: &[F128], log2_len: usize) -> (WitnessSlice, Vec<LinExpr>) {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    let wires: Vec<LinExpr> = col.iter().map(|&v| LinExpr::from_wire(b.alloc_f128(v))).collect();
    for _ in col.len()..block {
        b.alloc_f128(F128::ZERO);
    }
    (WitnessSlice { log2_len, index }, wires)
}

/// FLATNESS: the region wallet-PCS discharge yields the SAME number of opening
/// claims regardless of the tx count -- the K txs' capsule families tile into ONE
/// walk A/B/C (cost O(log domain)) and every terminal claim is class-fixed. This
/// is the non-negotiable "the proof must not depend on the tx count": 1 tx, up to
/// 255 standard (4x8) or up to 40 sweep (25x2). Build-only (no PCS prove): scan
/// K = 1..256 and assert the claim count is CONSTANT.
///
/// Measured (num_vars=9, nq=2): claims = 75 at every K; wires 4.11M @K=1 ->
/// 12.39M @K=256 -- only ~3x for a 256x tx increase (sublinear, near-log; the
/// walk discharges are flat, so only the per-tx capsule tiles + ~4k-row/tx
/// algebra grow). That is the design's "attack proof ~2-3x typical, bounded", a
/// 35x reduction from the inline replay (433M rows @255). The constant claim
/// count is the recursion/[R] flatness the O(1) snapshot sync rests on.
#[test]
fn region_discharge_claims_flat_in_tx_count() {
    let num_vars = 9usize;
    let params = RegionDischargeParams { nq: 2, sb8_auth_layers: 1 };
    let mut ref_claims: Option<usize> = None;
    for &k in &[1usize, 2, 4, 8, 16, 64, 256] {
        let fixtures: Vec<(Vec<Block128>, BatchEvalReduction, AuthMleOpeningProof)> = (0..k)
            .map(|tx| capsule_fixture(num_vars, 0xA55E_C0DE + tx as u64 * 0x1111))
            .collect();
        let mut b = FieldR1csBuilder::new();
        let mut obligations: Vec<PendingAuthPcsObligation> = Vec::with_capacity(k);
        let natives: Vec<AuthMleOpeningProof> = fixtures.iter().map(|(_, _, p)| p.clone()).collect();
        for (point, red, proof) in &fixtures {
            let cap_lanes: Vec<[LinExpr; 2]> =
                proof.commitment.cap.hashes.iter().map(|h| alloc_digest(&mut b, h)).collect();
            let point_w = alloc_blocks(&mut b, point);
            let value_w = alloc_block(&mut b, red.value);
            obligations.push(PendingAuthPcsObligation {
                commitment_cap_lanes: cap_lanes,
                num_vars,
                reduction: BatchEvalReductionTrace { point: point_w, value: value_w },
            });
        }
        let claims =
            discharge_auth_pcs_obligations_via_region(&mut b, &obligations, &natives, params, None, None, None);
        eprintln!("[flatness] K={k:>2}: claims={} wires={}", claims.len(), b.num_wires());
        match ref_claims {
            None => ref_claims = Some(claims.len()),
            Some(r) => assert_eq!(
                claims.len(),
                r,
                "region discharge claim count must be FLAT in tx count (K={k})"
            ),
        }
    }
}

#[test]
fn region_source_binding_multitx_end_to_end() {
    let num_vars = 9usize;
    let k = 2usize;

    // K capsule openings (distinct seeds ⇒ distinct source bindings/queries).
    let fixtures: Vec<(Vec<Block128>, BatchEvalReduction, AuthMleOpeningProof)> =
        (0..k).map(|tx| capsule_fixture(num_vars, 0xA55E_C0DE + tx as u64 * 0x1111)).collect();

    // Build K obligations in ONE builder (the cap + reduction point/value wires).
    let mut b = FieldR1csBuilder::new();
    let mut obligations: Vec<PendingAuthPcsObligation> = Vec::with_capacity(k);
    let natives: Vec<AuthMleOpeningProof> = fixtures.iter().map(|(_, _, p)| p.clone()).collect();
    for (point, red, proof) in &fixtures {
        assert_eq!(proof.commitment.log_rows, num_vars);
        let cap_lanes: Vec<[LinExpr; 2]> =
            proof.commitment.cap.hashes.iter().map(|h| alloc_digest(&mut b, h)).collect();
        let point_w = alloc_blocks(&mut b, point);
        let value_w = alloc_block(&mut b, red.value);
        obligations.push(PendingAuthPcsObligation {
            commitment_cap_lanes: cap_lanes,
            num_vars,
            reduction: BatchEvalReductionTrace { point: point_w, value: value_w },
        });
    }
    let params = RegionDischargeParams { nq: NQ, sb8_auth_layers: SB8_AUTH_LAYERS };

    // ONE plural call: discharge all K txs, collect opening claims.
    let claims: Vec<RegionPcsClaim> =
        discharge_auth_pcs_obligations_via_region(&mut b, &obligations, &natives, params, None, None, None);

    // Wrap the claims in ONE public-IO discharge.
    let max_arity = claims.iter().map(|c| c.point.len()).max().unwrap();
    let lanes_per = max_arity + 1;
    let io_len = claims.len() * lanes_per;
    let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
    let mut io_values = Vec::with_capacity(io_len);
    for c in &claims {
        for kk in 0..max_arity {
            io_values.push(if kk < c.native_point.len() { c.native_point[kk] } else { F128::ZERO });
        }
        io_values.push(c.native_value);
    }
    let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
    for (ci, c) in claims.iter().enumerate() {
        let g = ci * lanes_per;
        for (kk, pt) in c.point.iter().enumerate() {
            noid_recursive::acceptance::trace::pin_eq(&mut b, pt, &io_wires[g + kk]);
        }
        noid_recursive::acceptance::trace::pin_eq(&mut b, &c.value, &io_wires[g + max_arity]);
    }
    let spec = PublicIoSpec {
        io_slice,
        io_len,
        claims: claims
            .iter()
            .enumerate()
            .map(|(ci, c)| IoClaimSpec {
                slice: c.slice,
                point: ci * lanes_per..ci * lanes_per + c.point.len(),
                value: ci * lanes_per + max_arity,
            })
            .collect(),
    };

    let n_wires = b.num_wires();
    eprintln!("[src-multitx] K={k}, wires before build = {n_wires}, claims = {}", claims.len());

    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "honest multi-tx source-binding trace unsatisfiable");
    let params_pcs = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut chp = FsLaneChallenger::new(OUTER);
    let (pf, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &z, &params_pcs, &spec, &io_values, &mut chp,
    );
    let mut chv = FsLaneChallenger::new(OUTER);
    noid_ivc_core::verifier::verify_field_with_public_io(
        &r1cs, &commitment, &pf, &spec, &io_values, &mut chv,
    )
    .expect("multi-tx source-binding composition verifies");
    eprintln!(
        "[src-multitx] ONE proof for K={k} txs: rows = {} (m = {}), claims = {}",
        z.len(),
        r1cs.m,
        claims.len()
    );

    // Money negative: flip one committed lane of the FIRST claim's column. The
    // tampering is caught either at the trace level (a Stage-2 pin_eq binds that
    // cell to an algebra wire) or at the PCS level (a free cell whose column
    // opening claim breaks) -- both are rejections.
    let bad_col = claims[0].slice;
    let mut bad_z = z.clone();
    bad_z[bad_col.start() + 5] += F128::ONE;
    let caught = if !r1cs.satisfies(&bad_z) {
        true
    } else {
        let mut chp = FsLaneChallenger::new(OUTER);
        let (bp, bc, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
            &r1cs, &bad_z, &params_pcs, &spec, &io_values, &mut chp,
        );
        let mut chv = FsLaneChallenger::new(OUTER);
        noid_ivc_core::verifier::verify_field_with_public_io(
            &r1cs, &bc, &bp, &spec, &io_values, &mut chv,
        )
        .is_err()
    };
    assert!(caught, "a flipped committed column lane must be caught");

    // Tiling coverage: the ONE tiled source-tree exposure sumcheck must catch a
    // corruption in ANY tree, not just tx 0. walk-A columns are allocated first
    // and in order (CODE0, CODE1, KID0, ..), so sorting the distinct claim slices
    // by start() puts KID0 at global index 2. Flip its node-1 cell in tx 1's tree
    // block (the upper half of the walk-A domain for k=2): the tiled exposure
    // (KID == C[2w+1] over ALL trees) no longer holds, so its re-pointed KID0
    // opening breaks and the PCS rejects.
    let mut uniq: Vec<WitnessSlice> = claims.iter().map(|c| c.slice).collect();
    uniq.sort_by_key(|s| s.start());
    uniq.dedup_by_key(|s| s.start());
    let kid0 = uniq[2];
    let p_col = 1usize << kid0.log2_len;
    let tree1_node1 = kid0.start() + p_col / 2 + 1; // tx 1's tree, KID node slot 1
    let mut bad2 = z.clone();
    bad2[tree1_node1] += F128::ONE;
    let caught2 = if !r1cs.satisfies(&bad2) {
        true
    } else {
        let mut chp = FsLaneChallenger::new(OUTER);
        let (bp, bc, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
            &r1cs, &bad2, &params_pcs, &spec, &io_values, &mut chp,
        );
        let mut chv = FsLaneChallenger::new(OUTER);
        noid_ivc_core::verifier::verify_field_with_public_io(
            &r1cs, &bc, &bp, &spec, &io_values, &mut chv,
        )
        .is_err()
    };
    assert!(caught2, "the tiled exposure must catch a corrupted second-tree KID lane");
}

/// SPINE families at per-block capacity 2 WITH a ghost instance: K = 2
/// obligations carry THREE spine instances (cap = ceil(3/2) = 2, so block 1
/// holds one real instance + one canonical zero-body GHOST), exercising the
/// chunked layout, the cap_log = 1 instance coordinates in the gated
/// exposure's re-point, and the ghost fill — the exact shape a real block
/// (user txs + coinbase) produces. Honest build satisfies; a flipped KID
/// LEAF cell (pinned to a chain-digest wire) breaks a Stage-2 pin; a flipped
/// INTERNAL KID cell in the GHOST-PADDED chunk breaks the gated tiled
/// exposure's re-pointed opening at the PCS.
#[test]
fn region_spine_families_multitx_with_ghosts() {
    use noid_ivc_core::deep_chain::spine::{
        build_spine_instance_columns, SpineInstanceFlat, SPINE_TREE_KID_LEAF_BASE,
    };

    let num_vars = 9usize;
    let k = 2usize;
    let n_inst = 3usize;

    let fixtures: Vec<(Vec<Block128>, BatchEvalReduction, AuthMleOpeningProof)> =
        (0..k).map(|tx| capsule_fixture(num_vars, 0x59147E + tx as u64 * 0x2222)).collect();

    let mut b = FieldR1csBuilder::new();
    let mut obligations: Vec<PendingAuthPcsObligation> = Vec::with_capacity(k);
    let natives: Vec<AuthMleOpeningProof> = fixtures.iter().map(|(_, _, p)| p.clone()).collect();
    for (point, red, proof) in &fixtures {
        let cap_lanes: Vec<[LinExpr; 2]> =
            proof.commitment.cap.hashes.iter().map(|h| alloc_digest(&mut b, h)).collect();
        let point_w = alloc_blocks(&mut b, point);
        let value_w = alloc_block(&mut b, red.value);
        obligations.push(PendingAuthPcsObligation {
            commitment_cap_lanes: cap_lanes,
            num_vars,
            reduction: BatchEvalReductionTrace { point: point_w, value: value_w },
        });
    }

    // Three synthetic spine instances (random flat statement lanes; the
    // builder is separately gated against the native tower spine).
    let mut rng = Rng(0xF00D);
    let mut f = |rng: &mut Rng| -> F128 {
        F128 { lo: rng.next_u64(), hi: rng.next_u64() }
    };
    let instances: Vec<SpineInstanceRegion> = (0..n_inst)
        .map(|_| {
            let flat = SpineInstanceFlat {
                epoch_anchor: [f(&mut rng), f(&mut rng)],
                fee_leaf: [f(&mut rng), f(&mut rng)],
                input_leaves: std::array::from_fn(|_| std::array::from_fn(|_| f(&mut rng))),
                output_leaves: std::array::from_fn(|_| std::array::from_fn(|_| f(&mut rng))),
                is_coinbase_leaf: [f(&mut rng), f(&mut rng)],
                pad_leaf: [F128::ZERO; 2],
            };
            let tx_hash = build_spine_instance_columns(&flat).tx_hash;
            let w2 = |b: &mut FieldR1csBuilder, v: [F128; 2]| -> [LinExpr; 2] {
                std::array::from_fn(|i| LinExpr::from_wire(b.alloc_f128(v[i])))
            };
            let w4 = |b: &mut FieldR1csBuilder, v: [F128; 4]| -> [LinExpr; 4] {
                std::array::from_fn(|i| LinExpr::from_wire(b.alloc_f128(v[i])))
            };
            SpineInstanceRegion {
                input_leaves_w: flat.input_leaves.iter().map(|p| w4(&mut b, *p)).collect(),
                output_leaves_w: flat.output_leaves.iter().map(|p| w4(&mut b, *p)).collect(),
                anchor_w: w2(&mut b, flat.epoch_anchor),
                fee_w: w2(&mut b, flat.fee_leaf),
                coinbase_w: w2(&mut b, flat.is_coinbase_leaf),
                pad_w: w2(&mut b, flat.pad_leaf),
                tx_hash_w: w2(&mut b, tx_hash),
                tx_hash_flat: tx_hash,
                flat,
            }
        })
        .collect();
    let spine = SpineRegionData { instances };

    let params = RegionDischargeParams { nq: 2, sb8_auth_layers: 1 };
    let claims: Vec<RegionPcsClaim> = discharge_auth_pcs_obligations_via_region(
        &mut b,
        &obligations,
        &natives,
        params,
        None,
        None,
        Some(&spine),
    );

    // Public-IO wrap (same as the e2e test above).
    let max_arity = claims.iter().map(|c| c.point.len()).max().unwrap();
    let lanes_per = max_arity + 1;
    let io_len = claims.len() * lanes_per;
    let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
    let mut io_values = Vec::with_capacity(io_len);
    for c in &claims {
        for kk in 0..max_arity {
            io_values.push(if kk < c.native_point.len() { c.native_point[kk] } else { F128::ZERO });
        }
        io_values.push(c.native_value);
    }
    let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
    for (ci, c) in claims.iter().enumerate() {
        let g = ci * lanes_per;
        for (kk, pt) in c.point.iter().enumerate() {
            noid_recursive::acceptance::trace::pin_eq(&mut b, pt, &io_wires[g + kk]);
        }
        noid_recursive::acceptance::trace::pin_eq(&mut b, &c.value, &io_wires[g + max_arity]);
    }
    let spec = PublicIoSpec {
        io_slice,
        io_len,
        claims: claims
            .iter()
            .enumerate()
            .map(|(ci, c)| IoClaimSpec {
                slice: c.slice,
                point: ci * lanes_per..ci * lanes_per + c.point.len(),
                value: ci * lanes_per + max_arity,
            })
            .collect(),
    };

    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "spine multitx+ghost region trace unsatisfiable");
    eprintln!(
        "[spine-ghost] K={k}, instances={n_inst} (cap=2, 1 ghost): rows={} claims={}",
        z.len(),
        claims.len()
    );

    // Walk-A column slices are allocated first and in the meta order
    // (CODE0, CODE1, KID0, KID1, IN0, IN1, C0..C3) — recover KID0 as the
    // third distinct slice and the per-tx block size from its length / k.
    let mut uniq: Vec<WitnessSlice> = claims.iter().map(|c| c.slice).collect();
    uniq.sort_by_key(|s| s.start());
    uniq.dedup_by_key(|s| s.start());
    let kid0 = uniq[2];
    let p_col = 1usize << kid0.log2_len;
    let per_tx_block_a = p_col / k;
    // Recover the spine-tree base by locating instance 2's L2 leaf digest
    // (a known value, computed by the gated builder) inside tx block 1's
    // KID0 slice — robust against the wallet-family layout details.
    let inst2_l2 = build_spine_instance_columns(&spine.instances[2].flat).chain_digests[0][0];
    let blk1 = kid0.start() + per_tx_block_a;
    let hit = (0..per_tx_block_a)
        .find(|&w| z[blk1 + w] == inst2_l2)
        .expect("instance 2's L2 digest present in block 1's KID0");
    // Instance 2 is block 1's in-block instance 0, leaf L2 = KID position
    // SPINE_TREE_KID_LEAF_BASE + 2 within its tree.
    let spine_tree_base = hit - (SPINE_TREE_KID_LEAF_BASE + 2);
    assert_eq!(spine_tree_base % 128, 0, "tree base 64*cap alignment");

    // Negative 1 (Stage-2 pin): flip instance 2's KID LEAF cell (block 1,
    // in-block instance 0) — pinned to its chain-digest wire, so the trace
    // itself must reject.
    {
        let cell = blk1 + spine_tree_base + SPINE_TREE_KID_LEAF_BASE + 2;
        let mut bad = z.clone();
        bad[cell] += F128::ONE;
        assert!(!r1cs.satisfies(&bad), "flipped KID leaf cell accepted");
    }

    // Negative 2 (gated exposure): flip an INTERNAL KID cell of the REAL
    // instance in the ghost-padded chunk (block 1, instance 0, node 5). No
    // pin covers internal children — the gated tiled exposure's re-pointed
    // KID0 opening must break at the PCS.
    {
        let cell = blk1 + spine_tree_base + 5;
        let mut bad = z.clone();
        bad[cell] += F128::ONE;
        let caught = if !r1cs.satisfies(&bad) {
            true
        } else {
            let params_pcs = PcsParams {
                m: r1cs.m + pcs::LOG_PACKING,
                log_inv_rate: 2,
                log_batch_size: 2,
                profile: Default::default(),
            };
            let mut chp = FsLaneChallenger::new(OUTER);
            let (bp, bc, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
                &r1cs, &bad, &params_pcs, &spec, &io_values, &mut chp,
            );
            let mut chv = FsLaneChallenger::new(OUTER);
            noid_ivc_core::verifier::verify_field_with_public_io(
                &r1cs, &bc, &bp, &spec, &io_values, &mut chv,
            )
            .is_err()
        };
        assert!(caught, "the gated exposure must catch a corrupted internal KID cell");
    }
}
