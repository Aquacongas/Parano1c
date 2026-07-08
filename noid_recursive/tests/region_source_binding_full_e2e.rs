// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! [G] — gate for the SRC function `discharge_auth_pcs_obligation_via_region`
//! on the CAPSULE geometry. The whole wallet-capsule PCS opening
//! AUTHENTICATION (leaf sponges, feed-forward paths, arity-16 fold chain,
//! upper-contraction checks, grind, FRICHANL transcript) is discharged
//! IN-TRACE by that reusable function (region families, THREE union walks,
//! ONE builder); this test builds the obligation + `AuthMleOpeningProof`
//! from a capsule fixture, calls the src fn, wraps the returned
//! committed-column opening claims in the public-IO discharge, and exercises
//! the honest case + the negatives. ONE source of truth (the src fn),
//! guarded here.
//!
//! ## The transcript-binding this geometry carries
//! Each ff leg's recomputed root — the LinExpr `C + CR + D·(CR+SIB)` at the
//! path's last node slot — is `pin_eq`'d to the Fiat-Shamir-OBSERVED root
//! wire (the cap lane muxed by the rc bits for the source leg; the absorbed
//! `mid_root` wires for the mid leg), both absorbed into the channel BEFORE
//! the query draw. Flipping the recomputed-root cell breaks the pin
//! (unsatisfiable); flipping a sibling breaks the walk substitution's
//! opening claim (PCS rejects) — together they prove a prover cannot
//! authenticate answers against a root chosen after the query positions are
//! known. Query POSITIONS are pinned exactly: the ff direction cells equal
//! the transcript-derived position bits and the leaf-tile meta cells equal
//! the bit-recomposed leaf index.

use noid_core::Block128;
use noid_fri_binius::capsule::{capsule_tree_depth, CAPSULE_CAP_DEPTH};
use noid_ivc_core::deep_chain::capsule_leaf::CAPSULE_LEAF_STRIDE;
use noid_gkr::auth_pcs::{commit_auth_mle_column, open_auth_mle_committed};
use noid_gkr::batch_eval::BatchEvalReduction;

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};

use noid_recursive::acceptance::trace::owner_auth::PendingAuthPcsObligation;
use noid_recursive::acceptance::trace::region_source_binding::{
    discharge_auth_pcs_obligation_via_region, RegionDischargeParams, RegionPcsClaim,
};
use noid_recursive::acceptance::trace::{alloc_block, alloc_blocks, BatchEvalReductionTrace};

// The number of queries actually DISCHARGED per tree (small for memory
// safety; the channel is still driven with CAPSULE_NUM_QUERIES inside the
// src fn). Must be a power of two.
const NQ: usize = 4;

const OUTER: &[u8] = b"region-source-binding-full-e2e";

// ---------------------------------------------------------------------------
// Fixture + basis helpers.
// ---------------------------------------------------------------------------
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

fn capsule_fixture(
    num_vars: usize,
    seed: u64,
) -> (Vec<Block128>, BatchEvalReduction, noid_gkr::auth_pcs::AuthMleOpeningProof) {
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

fn alloc_column_slice(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> (WitnessSlice, Vec<LinExpr>) {
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

/// Allocate one raw-flat digest lane pair (the capsule cap lanes carry the
/// raw flat digest halves under the flat→tower absorb convention).
fn alloc_digest_raw(b: &mut FieldR1csBuilder, d: &[u8; 32]) -> [LinExpr; 2] {
    let lo = u128::from_le_bytes(d[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(d[16..].try_into().unwrap());
    let lane = |v: u128| F128 { lo: v as u64, hi: (v >> 64) as u64 };
    [
        LinExpr::from_wire(b.alloc_f128(lane(lo))),
        LinExpr::from_wire(b.alloc_f128(lane(hi))),
    ]
}

#[test]
fn region_source_binding_full_end_to_end() {
    // -------------------------------------------------------------------
    // The real capsule opening.
    // -------------------------------------------------------------------
    let num_vars = 9usize;
    let (point, red, proof) = capsule_fixture(num_vars, 0xA55E_C0DE);
    let log_n = proof.commitment.log_rows;
    assert_eq!(log_n, num_vars);

    // -------------------------------------------------------------------
    // Build the obligation exactly as the owner-auth slot would: the cap +
    // reduction point/value as wires in the SAME builder the src fn discharges
    // into (so the src fn drives the channel from THESE wires, not fresh ones).
    // -------------------------------------------------------------------
    let mut b = FieldR1csBuilder::new();
    let cap_lanes: Vec<[LinExpr; 2]> =
        proof.commitment.cap.hashes.iter().map(|h| alloc_digest_raw(&mut b, h)).collect();
    let point_w = alloc_blocks(&mut b, &point);
    let value_w = alloc_block(&mut b, red.value);
    let obligation = PendingAuthPcsObligation {
        commitment_cap_lanes: cap_lanes,
        num_vars,
        reduction: BatchEvalReductionTrace { point: point_w, value: value_w },
    };
    let params = RegionDischargeParams { nq: NQ };

    // -------------------------------------------------------------------
    // ONE call to the src fn: discharge, collect opening claims.
    // -------------------------------------------------------------------
    let claims: Vec<RegionPcsClaim> =
        discharge_auth_pcs_obligation_via_region(&mut b, &obligation, &proof, params);

    // -------------------------------------------------------------------
    // Wrap the returned claims in ONE public-IO discharge (caller's job).
    // -------------------------------------------------------------------
    let max_arity = claims.iter().map(|c| c.point.len()).max().unwrap();
    let lanes_per = max_arity + 1;
    let io_len = claims.len() * lanes_per;
    let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
    let mut io_values = Vec::with_capacity(io_len);
    for c in &claims {
        for k in 0..max_arity {
            io_values.push(if k < c.native_point.len() { c.native_point[k] } else { F128::ZERO });
        }
        io_values.push(c.native_value);
    }
    let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
    for (ci, c) in claims.iter().enumerate() {
        let g = ci * lanes_per;
        for (k, pt) in c.point.iter().enumerate() {
            noid_recursive::acceptance::trace::pin_eq(&mut b, pt, &io_wires[g + k]);
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

    // Memory guard: with THREE union walks (A leaf tiles, B ff+2perm legs, C
    // the FRICHANL channel duplex) this must stay under 2^23 wires.
    let n_wires = b.num_wires();
    eprintln!("[src-full] wires before build = {n_wires}, claims = {}", claims.len());
    assert!(n_wires < (1usize << 23), "wire guard {n_wires}");

    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "honest source-binding-full trace unsatisfiable");
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
    .expect("source-binding-full composition verifies");
    eprintln!(
        "[src-full] ONE proof: rows = {} (m = {}), num_vars = {}, NQ = {}, claims = {}, walks = 3",
        z.len(),
        r1cs.m,
        num_vars,
        NQ,
        claims.len(),
    );

    // -------------------------------------------------------------------
    // Recompute the (deterministic) column layout so the negatives can poke
    // specific committed lanes. The discharge LOGIC lives ONLY in the src fn;
    // here we only recompute offsets + map global column -> WitnessSlice.
    // -------------------------------------------------------------------
    // Walk-A per-tx block: two capsule-leaf families of NQ 16-slot tiles.
    let src_fam_base = 0usize;
    let mid_fam_base = NQ * CAPSULE_LEAF_STRIDE;
    // Walk-B: the two ff legs (source-to-cap, mid-to-root), nq paths each.
    let depth_s = capsule_tree_depth(num_vars) - CAPSULE_CAP_DEPTH;
    let depth_m = capsule_tree_depth(num_vars - 4);
    let stride_s = depth_s.next_power_of_two();
    let ff_base_s = 0usize;
    let ff_base_m = NQ * stride_s;

    // Global column -> WitnessSlice. Claimed columns: walk A {IN0, IN1,
    // C0..C3} (KID0/1 exist but are unclaimed without the spine handoff),
    // walk B all 9 {C0..C3, E0, E1, SIB0, SIB1, D}, walk C all 6. Committed
    // slices are allocated strictly in order, so sorting the distinct claim
    // slices by start() recovers a stable global order:
    //   0..6   -> walk A IN0, IN1, C0..C3
    //   6..15  -> walk B C0..C3, E0, E1, SIB0, SIB1, D
    //   15..21 -> walk C A0, A1, C0..C3
    let mut uniq: Vec<WitnessSlice> = claims.iter().map(|c| c.slice).collect();
    uniq.sort_by_key(|s| s.start());
    uniq.dedup_by_key(|s| s.start());
    assert_eq!(uniq.len(), 6 + 9 + 6, "every claimed committed column accounted for");
    let col_slice = |g: usize| uniq[g];
    let (a_in0, a_c0) = (0usize, 2usize);
    let (b_c0, b_sib0) = (6usize, 12usize);

    // -------------------------------------------------------------------
    // Negatives: flip a committed lane -> the tampering is CAUGHT. A cell
    // reached by a Stage-2 `pin_eq` (symbols, meta lanes, digests, channel
    // absorbs/challenges, ff roots) is trace-bound, so the flip breaks
    // satisfiability; a cell touched only by a walk discharge (e.g. a path
    // sibling) stays a free wire, so the flip breaks that column's opening
    // claim and the PCS rejects. Either path is a rejection.
    // -------------------------------------------------------------------
    let flip = |g: usize, off: usize| -> bool {
        let mut bad = z.clone();
        bad[col_slice(g).start() + off] += F128::ONE;
        if !r1cs.satisfies(&bad) {
            return true; // pin_eq-bound cell: tampering breaks the trace itself
        }
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
    // (a) a source-coset symbol — walk-A IN0 at tile 0's first symbol slot.
    assert!(flip(a_in0, src_fam_base + 1), "flipped source coset symbol accepted");
    // (b) a mid-coset symbol — walk-A IN1 at mid tile 0's first symbol slot.
    assert!(flip(a_in0 + 1, mid_fam_base + 1), "flipped mid coset symbol accepted");
    // (c) a leaf-tile meta cell (the bit-recomposed leaf index) — IN1 at the
    //     tile's slot 0 is pinned to the transcript-derived position bits.
    assert!(flip(a_in0 + 1, src_fam_base), "flipped leaf-index meta cell accepted");
    // (d) a tile digest cell — walk-A C0 at tile 0's digest slot feeds the ff
    //     leg entry through a shared wire pin.
    assert!(flip(a_c0, src_fam_base + 8), "flipped tile digest cell accepted");
    // (e) a path SIBLING lane in each ff leg (SIB0 at the leg's path-0 node 0
    //     -> the path misses its committed cap lane / mid root).
    assert!(flip(b_sib0, ff_base_s), "flipped source-path sibling accepted");
    assert!(flip(b_sib0, ff_base_m), "flipped mid-path sibling accepted");
    // (f) a direction cell (D at path-0 node 1) — pinned to the query bit.
    assert!(flip(b_c0 + 8, ff_base_s + 1), "flipped direction cell accepted");

    // -------------------------------------------------------------------
    // Transcript-binding of the authentication roots: the recomputed ff root
    // `C + CR + D·(CR+SIB)` at the last node slot is pinned to the
    // FS-observed wire (cap-lane mux / mid_root). Flipping the C0 cell at the
    // last node slot of path 0 breaks that pin — the honest witness is
    // unsatisfiable. Together with the sibling flips (e) this proves the
    // walk-authenticated root IS the transcript-seeded root.
    // -------------------------------------------------------------------
    assert!(
        flip(b_c0, ff_base_s + depth_s - 1),
        "flipped source-leg recomputed-root cell accepted (root not transcript-bound)"
    );
    assert!(
        flip(b_c0, ff_base_m + depth_m - 1),
        "flipped mid-leg recomputed-root cell accepted (root not transcript-bound)"
    );
}
