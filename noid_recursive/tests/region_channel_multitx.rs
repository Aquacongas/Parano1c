//! [G] step 4 Stage 1 — the multi-tx CHANNEL-union flatness mechanism, proven
//! NATIVELY (fast; no heavy prove).
//!
//! The wallet-PCS discharge drives TWO Poseidon2b duplex transcript channels
//! per tx (FRICHANL, the capsule FRI channel; KSCHANNL, the owner-auth
//! channel), whose squeezed outputs feed the per-tx algebra. §4.2.1 wants them
//! discharged as a data-parallel DUPLEX KILLSHOT — ONE walk over ALL txs'
//! channel chains — NOT replayed inline per tx (~211+100 perms/tx → 28M @255).
//!
//! The duplex is a permutation chain like the leaf/Merkle families, so the same
//! common-period tiling applies, with TWO duplex-specific wrinkles this gate
//! checks:
//!   1. **Per-block IV seeding.** Each tx's channel starts fresh with the
//!      capacity IV at its block's slot 0 (the `START`/`CONST` patterns fire
//!      periodically per tx block); `build_duplex_columns` seeds it and the
//!      substitution's `START·C(w−1)` term cancels the cross-block carry read
//!      in char 2, so the chain re-initializes at every tx without a per-tx
//!      relation.
//!   2. **Continuing-chain ghost tail.** The duplex substitution's leading
//!      `C_j(w−1)` carry term is UNGATED (fires at every slot), so ghost slots
//!      must continue the chain (`raw = carry`), NOT the constant `perm([0;4])`
//!      fill the leaf/Merkle families use. Building the whole per-tx block with
//!      `build_duplex_columns` (schedule slots + ghost tail) gives exactly that.
//!
//! Gate: honest K = 2 verifies; corrupting one tx's absorbed lane is caught by
//! the single relation set; the walk round count is flat (log-in-K) at
//! K = 1/2/4/8.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, verify_column_relation,
    verify_shift_discharge, ColRef, RelationColumns, RelationTerm,
};
use noid_ivc_core::deep_chain::schedule::{
    build_duplex_columns, carry_selection_terms, compile_duplex, duplex_fixed_patterns,
    duplex_substitution_terms, flat_of_tower_u128, DuplexFamilyRefs, DuplexLayout, TranscriptOp,
};
use noid_ivc_core::deep_chain::{prove_deep_chain_walk, verify_deep_chain_walk, LaneClaimGroup};
use noid_ivc_core::field::F128;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_FRICHANL};
use noid_poseidon2b::native::permutation::STATE_SIZE;

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn f128(&mut self) -> F128 {
        F128 {
            lo: self.next_u64(),
            hi: self.next_u64(),
        }
    }
}

fn iv_flat() -> [F128; 2] {
    let iv = capacity_iv(TAG_FRICHANL);
    [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
}

/// A representative channel schedule exercising every duplex feature: a
/// three-lane absorb (one full slot + one pending), a constant-lane absorb, a
/// two-challenge squeeze (read + pending + the eager permutation), an
/// absorb-after-squeeze reset, and a pad-flush squeeze.
fn channel_ops() -> Vec<TranscriptOp> {
    const TAG: u128 = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10;
    vec![
        TranscriptOp::Absorb(vec![None, None, None]),
        TranscriptOp::Absorb(vec![Some(TAG)]),
        TranscriptOp::Squeeze(2),
        TranscriptOp::Absorb(vec![None, None]),
        TranscriptOp::Absorb(vec![None]),
        TranscriptOp::Squeeze(3),
    ]
}

/// A duplex family's refs over caller tables: global carries `c_refs`, this
/// channel's `A0, A1` at `col_base`, its patterns at `fixed_base`.
fn refs_for(col_base: usize, fixed_base: usize, c_refs: [usize; STATE_SIZE]) -> DuplexFamilyRefs {
    DuplexFamilyRefs {
        a: [col_base, col_base + 1],
        c: c_refs,
        start: fixed_base,
        abs: [fixed_base + 1, fixed_base + 2],
        consts: std::array::from_fn(|i| fixed_base + 3 + i),
    }
}

/// K txs' channel chains tiled into ONE walk at a common per-tx block period.
/// Column layout: global carries `C0..C3` at columns `0..4`; the channel's
/// `A0, A1` at `4..6`. Patterns (start, abs0/1, const0..3) are periodic per tx
/// block (`low_log = block_log`), covering every tx.
struct DuplexUnion {
    committed: Vec<Vec<F128>>,
    s0: [Vec<F128>; STATE_SIZE],
    s_out: [Vec<F128>; STATE_SIZE],
    fixed: Vec<noid_ivc_core::deep_chain::relations::FixedPattern>,
    refs: DuplexFamilyRefs,
    c_refs: [usize; STATE_SIZE],
    w_log: usize,
    /// Per-tx squeezed challenges (read from the carry cells) — the values the
    /// per-tx algebra consumes; asserted equal across the tiling.
    challenges: Vec<Vec<F128>>,
}

fn build_duplex_union(k_tx: usize, seed: u64) -> DuplexUnion {
    let mut rng = Rng(seed);
    let iv = iv_flat();
    let c_refs: [usize; STATE_SIZE] = std::array::from_fn(|i| i);
    let layout: DuplexLayout = compile_duplex(&channel_ops());

    let per_tx_block = layout.slots.len().next_power_of_two();
    let block_log = per_tx_block.trailing_zeros() as usize;
    let total = k_tx * per_tx_block;
    let w_log = total.trailing_zeros() as usize;
    assert_eq!(1usize << w_log, total, "domain must be a power of two");
    let p = 1usize << w_log;

    let mut committed: Vec<Vec<F128>> = (0..6).map(|_| vec![F128::ZERO; p]).collect();
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut challenges: Vec<Vec<F128>> = Vec::with_capacity(k_tx);

    // Build each tx's WHOLE block (schedule + continuing-chain ghost tail,
    // IV-seeded at the block's slot 0) with one build_duplex_columns, then tile.
    for t in 0..k_tx {
        let data: Vec<F128> = (0..layout.n_data).map(|_| rng.f128()).collect();
        let cols = build_duplex_columns(&layout, iv, &data, block_log);
        let off = t * per_tx_block;
        for j in 0..2 {
            committed[4 + j][off..off + per_tx_block].copy_from_slice(&cols.a[j]);
        }
        for j in 0..STATE_SIZE {
            committed[j][off..off + per_tx_block].copy_from_slice(&cols.c[j]);
            s0[j][off..off + per_tx_block].copy_from_slice(&cols.s0[j]);
            s_out[j][off..off + per_tx_block].copy_from_slice(&cols.s_out[j]);
        }
        challenges.push(cols.challenges);
    }

    // The channel's patterns are already periodic over the block (start/IV at
    // slot 0, absorb/const per schedule); low_log = block_log makes them fire in
    // every tx. The eq tensor stays O(block) — flat in K.
    let fixed = duplex_fixed_patterns(&layout, iv, block_log);
    let refs = refs_for(4, 0, c_refs);

    DuplexUnion {
        committed,
        s0,
        s_out,
        fixed,
        refs,
        c_refs,
        w_log,
        challenges,
    }
}

/// Full native discharge over every tx's channel chain in ONE walk; returns the
/// walk's per-layer sumcheck round count (= `w_log`, the flatness witness).
fn run_duplex_union(u: &DuplexUnion) -> usize {
    let committed: Vec<&[F128]> = u.committed.iter().map(|c| c.as_slice()).collect();
    let internal: Vec<&[F128]> = u.s_out.iter().map(|c| c.as_slice()).collect();
    let w_log = u.w_log;
    let mut ch_p = FsLaneChallenger::new(b"duplex-union");
    let mut ch_v = FsLaneChallenger::new(b"duplex-union");

    // ONE carry-selection over the shared C carries.
    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&u.c_refs, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns {
            committed: &committed,
            internal: &internal,
            fixed: &u.fixed,
        },
        &mut ch_p,
    );
    let sel_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &sel_terms,
        &u.fixed,
        &sel_proof,
        &mut ch_v,
    )
    .expect("native duplex-union selection");
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms)
        .iter()
        .zip(sel_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(_) => {}
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }

    // ONE deep-chain walk over the shared s0.
    let groups = vec![LaneClaimGroup {
        point: sel_point,
        values: gv,
    }];
    let (walk_proof, _) = prove_deep_chain_walk(&u.s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native duplex walk");

    // ONE substitution over the channel wiring (covers every tx).
    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms: Vec<RelationTerm> = duplex_substitution_terms(&u.refs, alpha);
    let mut target = F128::ZERO;
    let mut pw = F128::ONE;
    for e in 0..STATE_SIZE {
        pw = pw * alpha;
        target += pw * terminal.values[e];
    }
    let (sub_proof, _, _) = prove_column_relation(
        target,
        &terminal.point,
        &sub_terms,
        &RelationColumns {
            committed: &committed,
            internal: &[],
            fixed: &u.fixed,
        },
        &mut ch_p,
    );
    let sub_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &sub_terms,
        &u.fixed,
        &sub_proof,
        &mut ch_v,
    )
    .expect("native duplex-union substitution");

    // Discharge the distance-1 carry shift claims.
    for (r, v) in claimed_refs(&sub_terms)
        .iter()
        .zip(sub_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(_) => {}
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(
        ch_p.sample_f128(),
        ch_v.sample_f128(),
        "native duplex-union lockstep"
    );
    walk_proof
        .layers
        .first()
        .map_or(0, |l| l.round_coeffs.len())
}

/// Honest multi-tx channel union verifies; every tx squeezes its own
/// challenges (read from its block's carry cells); corrupting one tx's absorbed
/// lane is caught by the single relation set.
#[test]
fn common_period_multitx_duplex_union_native() {
    let u = build_duplex_union(2, 0xC0FFEE);
    // Distinct data per tx ⇒ distinct squeezed challenges (the per-tx values the
    // downstream algebra reads), all recovered from the same tiled walk.
    assert_ne!(
        u.challenges[0], u.challenges[1],
        "per-tx channels squeeze distinct challenges"
    );
    let _ = run_duplex_union(&u);

    // Negative: flip tx 1's first absorbed lane (A0 at its block's slot 0). The
    // single relation set must reject (the absorb term changes the chain).
    let mut bad = build_duplex_union(2, 0xC0FFEE);
    let per_tx_block = compile_duplex(&channel_ops())
        .slots
        .len()
        .next_power_of_two();
    let slot = per_tx_block; // tx 1, slot 0
    bad.committed[4][slot] += F128::ONE; // A0
                                         // The carry column must move too, else selection catches it first; corrupt
                                         // the absorbed A lane only and let the substitution catch the wiring break.
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_duplex_union(&bad)));
    assert!(
        caught.is_err(),
        "corrupted tx-1 absorbed lane accepted by the shared relation set"
    );
}

/// The walk cost is FLAT in tx count: doubling K adds only ~1 walk round
/// (`log K`) — the tx-independence property for the duplex channels.
#[test]
fn common_period_multitx_duplex_walk_is_flat() {
    let r1 = run_duplex_union(&build_duplex_union(1, 0xA1));
    let r2 = run_duplex_union(&build_duplex_union(2, 0xA2));
    let r4 = run_duplex_union(&build_duplex_union(4, 0xA4));
    let r8 = run_duplex_union(&build_duplex_union(8, 0xA8));
    eprintln!("[duplex-flat] walk rounds: K=1 {r1}, K=2 {r2}, K=4 {r4}, K=8 {r8}");
    assert_eq!(r2, r1 + 1, "K:1->2 adds exactly one walk round");
    assert_eq!(r4, r1 + 2, "K:1->4 adds exactly two walk rounds");
    assert_eq!(r8, r1 + 3, "K:1->8 adds exactly three walk rounds");
}
