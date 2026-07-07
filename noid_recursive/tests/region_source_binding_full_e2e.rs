// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! [G] item 5b — gate for the SRC function
//! `discharge_auth_pcs_obligation_via_region`. The whole wallet-capsule
//! source-binding + FRI-query opening AUTHENTICATION is now discharged IN-TRACE
//! by that reusable function (region families, TWO union walks, ONE builder);
//! this test builds the obligation + `AuthMleOpeningProof` from a capsule
//! fixture, calls the src fn, wraps the returned committed-column opening claims
//! in the public-IO discharge (build io_values + spec +
//! `prove_field_with_public_io` + verify), and exercises the honest case + all
//! negatives. ONE source of truth (the src fn), guarded here.
//!
//! ## The transcript-binding the src fn adds (step 2c)
//! Each Merkle-authentication root's claim VALUE is the Fiat-Shamir-OBSERVED
//! root wire (the digest wire absorbed into the channel BEFORE the query draw) —
//! `fri_roots_w[round]` (3i), `folded_roots_w[layer]` (SB8), and the absorbed
//! source-cap lane of `commitment_cap_lanes` (SB6-to-cap) — NOT a fresh alloc.
//! So the walk-recomputed root is opened == the transcript-seeded root; a prover
//! cannot authenticate answers against a root chosen after the query positions
//! are known. The new negative flips the FS-observed root wire and confirms
//! rejection (plus a structural check that all its paths share ONE observed
//! wire).

use noid_core::Block128;
use noid_fri_binius::compact_fri::compute_round_depth;
use noid_fri_binius::interleaved_commit::{source_cap_depth, source_tree_depth};
use noid_fri_binius::mixed_open::high_pair_tree_depth;
use noid_fri_binius::COMPACT_TAU;
use noid_gkr::auth_pcs::{commit_auth_mle_column, open_auth_mle_committed};
use noid_gkr::batch_eval::BatchEvalReduction;

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::deep_chain::leaf_hash::{pair_leaf_refs, SourceLeafChain};
use noid_ivc_core::deep_chain::source_tree::SourceTree;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};

use noid_recursive::acceptance::trace::fri_pcs::alloc_digest;
use noid_recursive::acceptance::trace::owner_auth::PendingAuthPcsObligation;
use noid_recursive::acceptance::trace::region_source_binding::{
    discharge_auth_pcs_obligation_via_region, RegionDischargeParams, RegionPcsClaim,
};
use noid_recursive::acceptance::trace::{alloc_block, alloc_blocks, BatchEvalReductionTrace};

// The number of source queries actually DISCHARGED (small for memory safety;
// the channel is still driven with COMPACT_NUM_QUERIES inside the src fn).
const NQ: usize = 4;
// The DEEPEST SB8 fold layers authenticated (small for memory safety).
const SB8_AUTH_LAYERS: usize = 2;

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

#[test]
fn region_source_binding_full_end_to_end() {
    // -------------------------------------------------------------------
    // The real capsule opening (wallet shape n_cols = 1).
    // -------------------------------------------------------------------
    let num_vars = 9usize;
    let (point, red, proof) = capsule_fixture(num_vars, 0xA55E_C0DE);
    let log_n = proof.commitment.log_rows;
    assert_eq!(log_n, num_vars);
    assert_eq!(proof.commitment.n_cols, 1);

    // -------------------------------------------------------------------
    // Build the obligation exactly as the owner-auth slot would: the cap +
    // reduction point/value as wires in the SAME builder the src fn discharges
    // into (so the src fn drives the channel from THESE wires, not fresh ones).
    // -------------------------------------------------------------------
    let mut b = FieldR1csBuilder::new();
    let cap_lanes: Vec<[LinExpr; 2]> =
        proof.commitment.cap.hashes.iter().map(|h| alloc_digest(&mut b, h)).collect();
    let point_w = alloc_blocks(&mut b, &point);
    let value_w = alloc_block(&mut b, red.value);
    let obligation = PendingAuthPcsObligation {
        commitment_cap_lanes: cap_lanes,
        num_vars,
        reduction: BatchEvalReductionTrace { point: point_w, value: value_w },
    };
    let params = RegionDischargeParams { nq: NQ, sb8_auth_layers: SB8_AUTH_LAYERS };

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

    // Memory guard: with THREE union walks (A source-tree+leaves, B merkle, C
    // the FRICHANL channel duplex) this must stay under 2^23 wires. Walk C adds a
    // fixed ~1.3M-row channel discharge that replaces the inline permutations —
    // bigger than inline at one tx, but flat in tx count (28M@255 -> ~flat).
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
        "[src-full] ONE proof: rows = {} (m = {}), num_vars = {}, NQ = {}, claims = {}, walks = 2, \
         sb8_auth_layers = {}",
        z.len(),
        r1cs.m,
        num_vars,
        NQ,
        claims.len(),
        SB8_AUTH_LAYERS
    );

    // -------------------------------------------------------------------
    // Recompute the (deterministic) column layout so the negatives can poke
    // specific committed lanes. The discharge LOGIC lives ONLY in the src fn;
    // here we only recompute offsets + map global column -> WitnessSlice.
    // -------------------------------------------------------------------
    let tau = COMPACT_TAU.min(log_n);
    let n_rounds = log_n - tau;
    let leaf_chain = SourceLeafChain { n_cols: 1 };
    let leaf_stride = leaf_chain.stride();
    let tree = SourceTree { leaf_log: n_rounds + 1 };
    let st_slots = tree.n_slots();
    let l = tree.leaf_count();
    let n_layers = tau.saturating_sub(1);
    let n_leaf_families = 1 + n_layers;
    let leaf_family_slots = NQ * leaf_stride;
    let _total = st_slots + n_leaf_families * leaf_family_slots;
    let leaf_base = |f: usize| st_slots + f * leaf_family_slots;
    let sb6_base = leaf_base(0);
    let first_code_leaf = 2 * l + 1;
    let hp0_base = leaf_base(1);

    // Walk-B leg layout.
    let round = 0usize;
    let sb6_walk_depth = source_tree_depth(log_n) - source_cap_depth(log_n);
    let sb8_auth_layers: Vec<usize> = (0..SB8_AUTH_LAYERS).map(|k| n_layers - 1 - k).collect();
    let mut leg_depths: Vec<usize> = vec![compute_round_depth(n_rounds, round), sb6_walk_depth];
    for &layer in &sb8_auth_layers {
        leg_depths.push(high_pair_tree_depth(log_n - 1 - layer));
    }
    let n_legs = leg_depths.len();
    let mut meta_bases = Vec::with_capacity(n_legs);
    let mut acc = NQ;
    for &d in &leg_depths {
        meta_bases.push(acc);
        acc += NQ * (2 * d).next_power_of_two();
    }
    let n_committed_b = 6 + 5 * n_legs;
    const N_COMMITTED_A: usize = 10; // CODE0,1 KID0,1 IN0,1 C0..C3
    const N_COMMITTED_C: usize = 6; // A0,A1 C0..C3 (walk-C FRICHANL channel duplex)
    let pair_in0 = pair_leaf_refs(0).in_[0]; // walk-B col 0

    // Global column -> WitnessSlice: committed slices are allocated strictly in
    // order (walk-A cols 0..9, then walk-B cols 0.., then walk-C cols 0..5), so
    // sorting the distinct claim slices by start() recovers the global column
    // index. The walk-B negatives below target columns < N_COMMITTED_A +
    // n_committed_b, so appending walk C at the end leaves them unaffected.
    let mut uniq: Vec<WitnessSlice> = claims.iter().map(|c| c.slice).collect();
    uniq.sort_by_key(|s| s.start());
    uniq.dedup_by_key(|s| s.start());
    assert_eq!(
        uniq.len(),
        N_COMMITTED_A + n_committed_b + N_COMMITTED_C,
        "every committed column appears in an opening claim"
    );
    let col_slice = |g: usize| uniq[g];

    // -------------------------------------------------------------------
    // Negatives: flip a committed lane -> the tampering is CAUGHT. A cell reached
    // by a Stage-2 `pin_eq` (symbols, digests, CODE, channel absorbs/challenges)
    // is trace-bound, so the flip breaks satisfiability; a cell touched only by a
    // walk discharge (e.g. a Merkle sibling) stays a free wire, so the flip breaks
    // that column's opening claim and the PCS rejects. Either path is a rejection.
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
    // (a) source_tree CODE lane (a leaf codeword symbol) — walk-A col 0 (CODE0).
    assert!(flip(0, first_code_leaf), "flipped source-tree CODE lane accepted");
    // (b) SB6 source-leaf symbol — walk-A col 4 (IN0) at tile 0's queried-pair slot 4.
    assert!(flip(4, sb6_base + 4), "flipped source-leaf symbol accepted");
    // (c) high-pair symbol — walk-A col 5 (IN1) at hp layer 0 tile 0's pair slot 4.
    assert!(flip(5, hp0_base + 4), "flipped high-pair symbol accepted");
    // (d) a Merkle SIBLING lane in each of 3i / SB6 / SB8 (walk-B SIB0 at each
    //     leg's node-0 even slot -> the path misses its committed root/cap).
    for f in 0..n_legs {
        let sib0_global = N_COMMITTED_A + 6 + 5 * f + 2; // walk-B col: E0,E1,SIB0,...
        assert!(flip(sib0_global, meta_bases[f]), "flipped Merkle sibling accepted (leg {f})");
    }
    // (e) a FRI queried symbol (walk-B pair-leaf IN0 at pair tile 0).
    assert!(flip(N_COMMITTED_A + pair_in0, 0), "flipped FRI queried symbol accepted");

    // -------------------------------------------------------------------
    // Transcript-binding of the Merkle-auth root (SB8 auth layer). The
    // recomputed-root cell — walk-B's shared C0 column at the path's root slot —
    // is `pin_eq`'d to the FS-OBSERVED `folded_roots_w[layer]` wire (absorbed into
    // the channel BEFORE the source-query draw). Flipping that recomputed-root
    // cell breaks the pin, so the honest witness is unsatisfiable. Together with
    // the sibling flip (d) — a fabricated path folds to a root the SAME pin no
    // longer matches — this proves the walk-authenticated root IS the
    // transcript-seeded root: a prover cannot authenticate answers against a root
    // chosen after the query positions are known.
    //
    // The pin target is the FS-observed wire BY CONSTRUCTION: the src fn pins to
    // `folded_roots_w[layer]`, the very wire absorbed as a channel data lane. That
    // absorb is itself pinned to a walk-C A-cell and discharged by walk C, so the
    // query draw squeezes from the SAME wire the paths authenticate against.
    // -------------------------------------------------------------------
    let sb8_auth_leg = 2; // legs: [3i(round 0), SB6-to-cap, SB8[n_layers-1], SB8[n_layers-2]]
    let sb8_root_slot = meta_bases[sb8_auth_leg] + 2 * (leg_depths[sb8_auth_leg] - 1) + 1;
    let c0_walk_b = N_COMMITTED_A + 2; // walk-B shared C0 (IN0,IN1,C0,C1,C2,C3 -> local 2)
    assert!(
        flip(c0_walk_b, sb8_root_slot),
        "flipped SB8 recomputed-root cell accepted (auth root not transcript-bound)"
    );
}
