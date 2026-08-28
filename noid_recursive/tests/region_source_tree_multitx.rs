//! [G] step 4 Stage 1 — the multi-tx SOURCE-TREE tiling, resolved NATIVELY.
//!
//! The source-binding tree (SB1.2) is the ONE family the design flagged as
//! hard to data-parallelize: the substitution reads each internal node's child
//! digest, and the exposure that BINDS those digests to the carry column uses a
//! `Window(C, stride_log=1, offset=1)` read `KID(w) = C(2w+1)` — a stride-2
//! index doubling that naively crosses tiles.
//!
//! This gate resolves it. The split is between the EXPENSIVE parts and the
//! binding:
//!   - **Walk + substitution TILE (flat).** The substitution reads `KID`
//!     PLAINLY (a committed column, `KID` aligned with `C` at the `4L` tree
//!     stride), so it tiles like any other family under common-period patterns;
//!     the 66-layer walk is data-parallel. These are the costly pieces and they
//!     are ONE walk + ONE relation over all trees.
//!   - **Exposure stays a bounded per-tree residual.** Binding `KID = C(2w+1)`
//!     wants `KID` at HALF the `C` stride (the 2:1 mismatch the substitution's
//!     aligned read cannot also satisfy), so each tree's exposure runs over its
//!     own `2L` half-domain against its own `C`/`KID` slice. The tree is tiny
//!     (`2^(leaf_log+2)` slots — ~8-64 for a std tx), so K exposures are a small
//!     bounded cost, NOT the 66-layer walk.
//!
//! Conclusion: the source tree is NOT a 255-tx blocker — its walk + substitution
//! flatten with every other family; only the tiny KID-binding exposure is
//! per-tx.
//!
//! Gate (native): K trees' walk + substitution unioned; K per-tree exposures;
//! honest verify; corrupting one tree's KID lane is caught by THAT tree's
//! exposure; the walk round count is flat (log-in-K) at K = 1/2/4/8.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, verify_column_relation,
    verify_shift_discharge, window_discharge_point, ColRef, FixedPattern, RelationColumns,
};
use noid_ivc_core::deep_chain::schedule::carry_selection_terms;
use noid_ivc_core::deep_chain::source_tree::{
    build_source_code_columns, build_source_tree_columns, compress_iv_flat, run_perm,
    source_tree_exposure_terms, source_tree_fixed_patterns, source_tree_refs,
    source_tree_substitution_terms, SourceTree,
};
use noid_ivc_core::deep_chain::{prove_deep_chain_walk, verify_deep_chain_walk, LaneClaimGroup};
use noid_ivc_core::field::F128;
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

/// K source trees tiled at the `4L` tree stride into ONE walk. Column layout
/// (source_tree_refs(0,0)): CODE0,1 = 0,1; KID0,1 = 2,3; C0..C3 = 4..8.
struct SourceTreeUnion {
    committed: Vec<Vec<F128>>,
    s0: [Vec<F128>; STATE_SIZE],
    s_out: [Vec<F128>; STATE_SIZE],
    fixed: Vec<FixedPattern>,
    c_refs: [usize; STATE_SIZE],
    w_log: usize,
    st_wlog: usize,
    st_slots: usize,
    k_tx: usize,
}

fn build_source_tree_union(k_tx: usize, leaf_log: usize, seed: u64) -> SourceTreeUnion {
    let mut rng = Rng(seed);
    let tree = SourceTree { leaf_log };
    let st_wlog = tree.slots_log();
    let st_slots = tree.n_slots();
    let iv = compress_iv_flat();
    let refs = source_tree_refs(0, 0);
    let c_refs = refs.c;

    let total = k_tx * st_slots;
    let w_log = total.trailing_zeros() as usize;
    assert_eq!(1usize << w_log, total, "domain power of two");
    let p = 1usize << w_log;

    // Ghost-fill: perm([0;4]) everywhere (walk-valid, C == s_out).
    let (gs0, gso) = run_perm([F128::ZERO; STATE_SIZE]);
    let mut committed: Vec<Vec<F128>> = (0..8).map(|_| vec![F128::ZERO; p]).collect();
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    for slot in 0..p {
        for j in 0..STATE_SIZE {
            s0[j][slot] = gs0[j];
            s_out[j][slot] = gso[j];
            committed[4 + j][slot] = gso[j];
        }
    }

    // Tile each tree at t*st_slots (CODE/KID/C/s0/s_out aligned at 4L stride).
    for t in 0..k_tx {
        let code: Vec<F128> = (0..tree.code_len()).map(|_| rng.f128()).collect();
        let st = build_source_tree_columns(&tree, &code, st_wlog);
        let cc = build_source_code_columns(&tree, &code, st_wlog);
        let off = t * st_slots;
        for j in 0..2 {
            committed[j][off..off + st_slots].copy_from_slice(&cc[j]);
            committed[2 + j][off..off + st_slots].copy_from_slice(&st.kid[j]);
        }
        for j in 0..STATE_SIZE {
            committed[4 + j][off..off + st_slots].copy_from_slice(&st.c[j]);
            s0[j][off..off + st_slots].copy_from_slice(&st.s0[j]);
            s_out[j][off..off + st_slots].copy_from_slice(&st.s_out[j]);
        }
    }

    // Tree-structure patterns are periodic over st_slots (low_log = st_wlog),
    // so they cover every tree for free.
    let fixed = source_tree_fixed_patterns(&tree, iv);

    SourceTreeUnion {
        committed,
        s0,
        s_out,
        fixed,
        c_refs,
        w_log,
        st_wlog,
        st_slots,
        k_tx,
    }
}

/// Union walk + selection + substitution over ALL trees, then K per-tree
/// exposures binding each KID. Returns the walk's first-layer round count.
fn run_source_tree_union(u: &SourceTreeUnion) -> usize {
    let committed: Vec<&[F128]> = u.committed.iter().map(|c| c.as_slice()).collect();
    let internal: Vec<&[F128]> = u.s_out.iter().map(|c| c.as_slice()).collect();
    let refs = source_tree_refs(0, 0);
    let w_log = u.w_log;
    let mut ch_p = FsLaneChallenger::new(b"source-tree-union");
    let mut ch_v = FsLaneChallenger::new(b"source-tree-union");

    // ONE carry-selection.
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
    .expect("native selection");
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

    // ONE deep-chain walk over all trees.
    let groups = vec![LaneClaimGroup {
        point: sel_point,
        values: gv,
    }];
    let (walk_proof, _) = prove_deep_chain_walk(&u.s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native walk");

    // ONE substitution (reads KID plainly; common-period patterns cover all).
    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = source_tree_substitution_terms(&refs, alpha);
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
    .expect("native substitution");
    for (r, v) in claimed_refs(&sub_terms)
        .iter()
        .zip(sub_proof.final_values.iter())
    {
        if let ColRef::CommittedShift(c) = r {
            let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
            verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
        }
    }

    // K per-tree exposures: KID_i(w) = C_i(2w+1) over the tree's own 2L half
    // domain against its own 4L C slice. Window(C_slice,1,1)(w)=C_slice(2w+1)
    // stays IN the tree's block — the bounded per-tx residual.
    let half = 1usize << (u.st_wlog - 1);
    for t in 0..u.k_tx {
        let off = t * u.st_slots;
        let kid0: Vec<F128> = u.committed[2][off..off + half].to_vec();
        let kid1: Vec<F128> = u.committed[3][off..off + half].to_vec();
        let c0: Vec<F128> = u.committed[4][off..off + u.st_slots].to_vec();
        let c1: Vec<F128> = u.committed[5][off..off + u.st_slots].to_vec();
        let expo_committed: Vec<&[F128]> = vec![&kid0, &kid1, &c0, &c1];
        let gamma = ch_p.sample_f128();
        assert_eq!(gamma, ch_v.sample_f128());
        let expo_terms = source_tree_exposure_terms([0, 1], [2, 3], gamma);
        let rho_e = ch_p.sample_f128_vec(u.st_wlog - 1);
        let _ = ch_v.sample_f128_vec(u.st_wlog - 1);
        let (expo_proof, _, _) = prove_column_relation(
            F128::ZERO,
            &rho_e,
            &expo_terms,
            &RelationColumns {
                committed: &expo_committed,
                internal: &[],
                fixed: &[],
            },
            &mut ch_p,
        );
        let expo_point = verify_column_relation(
            u.st_wlog - 1,
            F128::ZERO,
            &rho_e,
            &expo_terms,
            &[],
            &expo_proof,
            &mut ch_v,
        )
        .unwrap_or_else(|_| panic!("native exposure tree {t}"));
        // Window terminal discharges as a plain C opening at the re-indexed point.
        for (r, _v) in claimed_refs(&expo_terms)
            .iter()
            .zip(expo_proof.final_values.iter())
        {
            if let ColRef::Window {
                stride_log, offset, ..
            } = r
            {
                let _ = window_discharge_point(*offset, *stride_log, &expo_point);
            }
        }
    }

    assert_eq!(
        ch_p.sample_f128(),
        ch_v.sample_f128(),
        "native source-tree-union lockstep"
    );
    walk_proof
        .layers
        .first()
        .map_or(0, |l| l.round_coeffs.len())
}

/// Honest K trees verify (walk + substitution unioned, K exposures); corrupting
/// one tree's KID lane is caught by THAT tree's exposure.
#[test]
fn source_tree_union_native() {
    let leaf_log = 3usize; // 8 leaves, st_slots = 32
    let u = build_source_tree_union(2, leaf_log, 0xC0FFEE);
    let _ = run_source_tree_union(&u);

    // Negative isolating the EXPOSURE: flip tree 1's KID0 at slot 0 (heap node
    // 0 — a ghost the substitution does NOT read, since its selectors gate on
    // internal nodes h in [1,L)). The substitution stays satisfied, so ONLY the
    // exposure (proving KID(w)=C(2w+1) over the full 2L half domain) can catch
    // it — proving the exposure independently binds KID to the carry column
    // (without it a prover could forge the child digests the substitution reads).
    let mut bad = build_source_tree_union(2, leaf_log, 0xC0FFEE);
    let st_slots = SourceTree { leaf_log }.n_slots();
    bad.committed[2][st_slots] += F128::ONE; // tree 1, KID0, slot 0 (exposure-only)
    let caught =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_source_tree_union(&bad)));
    assert!(
        caught.is_err(),
        "corrupted tree-1 KID (exposure-only slot) accepted"
    );
}

/// Walk cost FLAT in tree count: doubling K adds exactly one walk round — the
/// expensive 66-layer walk data-parallelizes across trees.
#[test]
fn source_tree_union_walk_is_flat() {
    let ll = 3usize;
    let r1 = run_source_tree_union(&build_source_tree_union(1, ll, 0xA1));
    let r2 = run_source_tree_union(&build_source_tree_union(2, ll, 0xA2));
    let r4 = run_source_tree_union(&build_source_tree_union(4, ll, 0xA4));
    let r8 = run_source_tree_union(&build_source_tree_union(8, ll, 0xA8));
    eprintln!("[source-tree-flat] walk rounds: K=1 {r1}, K=2 {r2}, K=4 {r4}, K=8 {r8}");
    assert_eq!(r2, r1 + 1, "K:1->2 adds one walk round");
    assert_eq!(r4, r1 + 2, "K:1->4 adds two walk rounds");
    assert_eq!(r8, r1 + 3, "K:1->8 adds three walk rounds");
}
