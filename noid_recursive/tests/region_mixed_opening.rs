//! [G] item 5b — the WHOLE wallet-capsule `verify_mixed_opening` reproduced via
//! the region families against a REAL capsule opening, returning the same
//! opening value the native verifier does.
//!
//! Reproduces, driving the SAME FRICHANL channel as the native verifier:
//! steps 1-2 (γ, batched claim); the compact-FRI fold rounds (3a-3f: eval
//! consistency, τ tensor-batching draw β, per-round sumcheck + fri-root
//! absorbs, final codeword); the source binding SB1-SB9; then the FRI query
//! phase (3h-3j). Every hash is delegated to a region family:
//!   - SB1.1/SB1.2  H-claim + source_tree(Code(H·eq_right)) root == fri_roots[0]
//!   - SB2/SB3      source-binding commitment absorbs + source query draw
//!   - SB6          source leaves (flat_source_leaf_hash) + to-cap Merkle family
//!   - SB7/SB8/SB9  the fold chain: source pair → τ layers of
//!                  tensor_high_fold_pair (high_pair leaf + Merkle family per
//!                  layer, parity pins) → folded == h_code
//!   - 3i/3j        per-round FRI openings (flat_hash_pair leaf + Merkle
//!                  family) + noid_fri::code::fold → folded == final_codeword
//! The private helpers (eq_ind_partial_eval, compute_batched_claim_flat for
//! n_cols=1, observe_source_binding_commitments) are reproduced — no internal
//! exposure. Honest-accept returns the SAME opening as native (validating the
//! transcript↔algebra JOIN: a diverged channel would make the openings /
//! codeword checks fail against the committed symbols); tampering a source,
//! folded, or FRI symbol is caught. This is the native reference the in-trace
//! `discharge_auth_pcs_obligation_via_region` will shadow.

use noid_core::mle::evaluate::evaluate_slice;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::code::{fold, Code, LOG_RATE};
use noid_fri::merkle::VectorCommitment;
use noid_fri::Channel;
use noid_fri_binius::compact_fri::{
    compute_round_depth, expand_batched_merkle_proof, expand_batched_merkle_proof_to_cap,
    gen_compact_queries, BatchedMerkleProof,
};
use noid_fri_binius::interleaved_commit::{
    source_cap_depth, source_cap_from_commitment_cap, source_leaf_hash, source_tree_depth,
    CommitmentHashBackend,
};
use noid_fri_binius::mixed_open::{
    high_pair_leaf_hash_for_trace, high_pair_leaf_index, high_pair_parity, high_pair_tree_depth,
    tensor_high_fold_pair, MIXED_OPEN_TAG, MIXED_SOURCE_BINDING_TAG,
};
use noid_fri_binius::COMPACT_TAU;
use noid_gkr::auth_pcs::{commit_auth_mle_column, open_auth_mle_committed, AuthMleOpeningProof};
use noid_gkr::batch_eval::BatchEvalReduction;
use noid_ivc_core::deep_chain::leaf_hash::{flat_high_pair_leaf_hash, flat_source_leaf_hash};
use noid_ivc_core::deep_chain::schedule::{
    build_merkle_path_columns, flat_of_tower_u128, MerklePathFamily, MerklePathWitness,
};
use noid_ivc_core::deep_chain::source_tree::{build_source_tree_columns, flat_hash_pair, SourceTree};
use noid_ivc_core::field::F128;
use noid_poseidon2b::hasher::CryptographicHasher;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_COMPRESS};
use noid_poseidon2b::Poseidon2bSponge;

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn block(&mut self) -> Block128 {
        Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
    }
}

fn phi(b: Block128) -> F128 {
    flat_of_tower_u128(b.0)
}
fn lanes(d: &[u8; 32]) -> [F128; 2] {
    [
        flat_of_tower_u128(u128::from_le_bytes(d[..16].try_into().unwrap())),
        flat_of_tower_u128(u128::from_le_bytes(d[16..].try_into().unwrap())),
    ]
}
fn iv_flat() -> [F128; 2] {
    let iv = capacity_iv(TAG_COMPRESS);
    [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
}

/// eq(point, i) tensor over the tower basis (mirror of eq_ind_partial_eval).
fn eq_tensor(point: &[Block128]) -> Vec<Block128> {
    let mut t = vec![Block128::ONE; 1usize << point.len()];
    for (i, slot) in t.iter_mut().enumerate() {
        let mut e = Block128::ONE;
        for (l, &p) in point.iter().enumerate() {
            e = e * if (i >> l) & 1 == 1 { p } else { Block128::ONE + p };
        }
        *slot = e;
    }
    t
}

fn mle_eval(vals: &[Block128], z: &[Block128]) -> Block128 {
    let eq = eq_tensor(z);
    let mut acc = Block128::ZERO;
    for (v, e) in vals.iter().zip(eq.iter()) {
        acc += *v * *e;
    }
    acc
}

fn capsule_fixture(num_vars: usize, seed: u64) -> (Vec<Block128>, BatchEvalReduction, AuthMleOpeningProof) {
    let mut rng = Rng(seed);
    let column: Vec<Block128> = (0..(1usize << num_vars)).map(|_| rng.block()).collect();
    let point: Vec<Block128> = (0..num_vars).map(|_| rng.block()).collect();
    let value = evaluate_slice(&column, &point);
    let reduction = BatchEvalReduction { point: point.clone(), value };
    let mut committed = commit_auth_mle_column(&column, num_vars);
    let proof = open_auth_mle_committed(&mut committed, num_vars, &reduction);
    (point, reduction, proof)
}

/// Fold one query's independent path (native leaf hashes for the octopus,
/// region flat leaf digests for the family entry) through MerklePathFamily to
/// its single root; assert the region root == φ(native root). Region leaf
/// digest is asserted == φ(native leaf).
fn region_merkle_to_root(
    native_leaves: &[[u8; 32]],
    region_leaves: &[[F128; 2]],
    batch: &BatchedMerkleProof,
    depth: usize,
    pair_indices: &[usize],
    hasher: &dyn CryptographicHasher,
    root_flat: [F128; 2],
) -> Result<(), String> {
    let paths = expand_batched_merkle_proof(batch, depth, pair_indices, native_leaves, hasher)?;
    let by_index: std::collections::HashMap<usize, [F128; 2]> =
        pair_indices.iter().copied().zip(region_leaves.iter().copied()).collect();
    let family = MerklePathFamily { depth, n_paths: paths.len() };
    let w_log = family.n_slots().next_power_of_two().trailing_zeros() as usize;
    let mut witnesses = Vec::with_capacity(paths.len());
    for p in &paths {
        let entry = by_index[&p.leaf_index];
        if entry != lanes(&p.leaf_hash) {
            return Err("region leaf digest != φ(native leaf)".into());
        }
        witnesses.push(MerklePathWitness {
            entry,
            siblings: p.siblings.iter().map(lanes).collect(),
            directions: p.directions.clone(),
        });
    }
    let cols = build_merkle_path_columns(&family, iv_flat(), &witnesses, w_log);
    for r in &cols.roots {
        if *r != root_flat {
            return Err("region Merkle root != φ(committed root)".into());
        }
    }
    Ok(())
}

/// The to-cap variant (SB6): fold walk_depth levels, pin each surviving node
/// to the committed cap `cap_flat[leaf_index >> walk_depth]`.
fn region_merkle_to_cap(
    native_leaves: &[[u8; 32]],
    region_leaves: &[[F128; 2]],
    batch: &BatchedMerkleProof,
    tree_depth: usize,
    cap_depth: usize,
    pair_indices: &[usize],
    hasher: &dyn CryptographicHasher,
    cap_flat: &[[F128; 2]],
) -> Result<(), String> {
    let walk_depth = tree_depth - cap_depth;
    let paths = expand_batched_merkle_proof_to_cap(batch, tree_depth, cap_depth, pair_indices, native_leaves, hasher)?;
    let by_index: std::collections::HashMap<usize, [F128; 2]> =
        pair_indices.iter().copied().zip(region_leaves.iter().copied()).collect();
    let family = MerklePathFamily { depth: walk_depth, n_paths: paths.len() };
    let w_log = family.n_slots().next_power_of_two().trailing_zeros() as usize;
    let mut witnesses = Vec::with_capacity(paths.len());
    let mut cap_idx_of = Vec::with_capacity(paths.len());
    for p in &paths {
        let entry = by_index[&p.leaf_index];
        if entry != lanes(&p.leaf_hash) {
            return Err("region source-leaf digest != φ(native leaf)".into());
        }
        witnesses.push(MerklePathWitness {
            entry,
            siblings: p.siblings.iter().map(lanes).collect(),
            directions: p.directions.clone(),
        });
        cap_idx_of.push(p.leaf_index >> walk_depth);
    }
    let cols = build_merkle_path_columns(&family, iv_flat(), &witnesses, w_log);
    for (i, r) in cols.roots.iter().enumerate() {
        if *r != cap_flat[cap_idx_of[i]] {
            return Err("region source cap node != φ(committed cap)".into());
        }
    }
    Ok(())
}

/// The source-binding half of verify_mixed_opening (n_cols = 1), reproduced
/// with every hash delegated to a region family, driving the real channel.
/// Returns the primary opening on success.
#[allow(clippy::too_many_arguments)]
fn verify_mixed_opening_via_region(
    proof: &AuthMleOpeningProof,
    primary_point: &[Block128],
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
    num_queries: usize,
) -> Result<Block128, String> {
    let commitment = &proof.commitment;
    let opening = &proof.opening;
    let log_n = commitment.log_rows;
    let n_cols = commitment.n_cols;
    assert_eq!(n_cols, 1, "wallet shape");
    assert_eq!(primary_point.len(), log_n);

    // Steps 1-2: absorb tag + openings, draw γ; batched_claim = openings[0].
    channel.observe_field_elem(Block128::from(MIXED_OPEN_TAG));
    channel.observe_field_elems(&opening.all_openings);
    let _gamma = channel.get_random_point();
    let batched_claim = opening.all_openings[0];

    // 3a: absorb eval_point.
    channel.observe_field_elems(primary_point);
    let tau = COMPACT_TAU.min(log_n);
    let (right, left) = primary_point.split_at(log_n - tau);
    let fri = &opening.fri_proof;
    if fri.upper_partial_evals.len() != (1usize << tau) {
        return Err("upper eval length".into());
    }

    // 3c: eval consistency.
    let left_eq = eq_tensor(left);
    let mut derived = Block128::ZERO;
    for (l, u) in left_eq.iter().zip(fri.upper_partial_evals.iter()) {
        derived += *l * *u;
    }
    if derived != batched_claim {
        return Err("derived eval != batched claim".into());
    }
    channel.observe_field_elem(batched_claim);

    // 3d: tensor batching (β), initial claim.
    let beta = channel.get_random_points(tau);
    let batching_eq = eq_tensor(&beta);
    let mut claim = Block128::ZERO;
    for (u, b) in fri.upper_partial_evals.iter().zip(batching_eq.iter()) {
        claim += *u * *b;
    }
    let initial_sumcheck_claim = claim;

    // 3e: sumcheck rounds → random_point; absorb fri roots.
    let n_rounds = right.len();
    let mut random_point = Vec::with_capacity(n_rounds);
    for round in 0..n_rounds {
        let [c0, c1] = fri.sum_check_oracles[round];
        if c1 != claim {
            return Err(format!("sumcheck round {round}"));
        }
        channel.observe_field_elem(c0);
        channel.observe_field_elem(c1);
        let depth = compute_round_depth(n_rounds, round);
        channel.observe_vector_commitment(&VectorCommitment { root: fri.fri_roots[round], depth });
        let r = channel.get_random_point();
        random_point.push(r);
        claim = c0 + c1 * r;
    }
    // 3f: absorb final codeword.
    channel.observe_field_elems(&fri.final_codeword);

    // ---- Source binding (folded-layer path; wallet shape).
    let src = &opening.source_proof;
    let expected_layers = tau.saturating_sub(1);
    if src.h_evals.len() != (1usize << n_rounds)
        || src.folded_roots.len() != expected_layers
        || src.folded_queried_symbols.len() != expected_layers
    {
        return Err("source shape".into());
    }

    // SB1.1: H(right) == initial_sumcheck_claim.
    if mle_eval(&src.h_evals, right) != initial_sumcheck_claim {
        return Err("H-claim".into());
    }
    // SB1.2: source_tree(Code(H·eq_right)) root == fri_roots[0].
    let eq_r = eq_tensor(right);
    let g: Vec<Block128> = src.h_evals.iter().zip(eq_r.iter()).map(|(&h, &e)| h * e).collect();
    let g_code = Code::new_parallel(&g, ntt);
    let g_code_flat: Vec<F128> = g_code.encoding.iter().map(|&b| phi(b)).collect();
    let tree = SourceTree { leaf_log: n_rounds + 1 };
    if tree.code_len() == g_code_flat.len() {
        let cols = build_source_tree_columns(&tree, &g_code_flat, tree.slots_log());
        if cols.root != lanes(&fri.fri_roots[0]) {
            return Err("Code(H) tree root != fri_roots[0]".into());
        }
    }

    // SB2: observe source-binding commitments.
    channel.observe_field_elem(Block128::from(MIXED_SOURCE_BINDING_TAG));
    channel.observe_field_elems(&src.h_evals);
    for (i, root) in src.folded_roots.iter().enumerate() {
        let layer_log = log_n - 1 - i;
        channel.observe_vector_commitment(&VectorCommitment { root: *root, depth: high_pair_tree_depth(layer_log) });
    }
    // SB3: source query draw.
    let query_indices = gen_compact_queries(channel, log_n + LOG_RATE, num_queries);
    let n_queries = query_indices.len();

    // SB4-SB6: source leaves + to-cap Merkle.
    let source_cap = source_cap_from_commitment_cap(&commitment.cap, log_n)
        .ok_or("missing source cap")?;
    let cap_flat: Vec<[F128; 2]> = source_cap.iter().map(lanes).collect();
    let source_pair_indices: Vec<usize> =
        query_indices.iter().map(|&qi| high_pair_leaf_index(qi, log_n)).collect();
    if src.source_symbols.len() != source_pair_indices.len() * n_cols * 2 {
        return Err("source symbol length".into());
    }
    let mut native_source_leaves = Vec::with_capacity(source_pair_indices.len());
    let mut region_source_leaves = Vec::with_capacity(source_pair_indices.len());
    for (q, &leaf_idx) in source_pair_indices.iter().enumerate() {
        let start = q * n_cols * 2;
        let syms = &src.source_symbols[start..start + n_cols * 2];
        native_source_leaves.push(source_leaf_hash(
            CommitmentHashBackend::Arithmetic, log_n, n_cols, leaf_idx, syms, hasher,
        ));
        let syms_flat: Vec<F128> = syms.iter().map(|&b| phi(b)).collect();
        region_source_leaves.push(flat_source_leaf_hash(log_n, n_cols, leaf_idx, &syms_flat));
    }
    region_merkle_to_cap(
        &native_source_leaves,
        &region_source_leaves,
        &BatchedMerkleProof { siblings: src.source_merkle_batch.siblings.clone() },
        source_tree_depth(log_n),
        source_cap_depth(log_n),
        &source_pair_indices,
        hasher,
        &cap_flat,
    )?;

    // SB7: source pair (n_cols = 1, no γ-batch) → tensor_high_fold_pair(β[τ-1]).
    let h_code = Code::new_parallel(&src.h_evals, ntt);
    let mut folded: Vec<Block128> = Vec::with_capacity(n_queries);
    for q in 0..n_queries {
        let s0 = src.source_symbols[q * 2];
        let s1 = src.source_symbols[q * 2 + 1];
        folded.push(tensor_high_fold_pair(beta[tau - 1], log_n, source_pair_indices[q], s0, s1));
    }

    // SB8: per high-fold layer — high_pair leaf + Merkle to its single folded
    // root, parity pin, tensor_high_fold_pair(β[τ-2-layer]).
    let mut current = source_pair_indices;
    for (layer, symbols) in src.folded_queried_symbols.iter().enumerate() {
        let layer_log = log_n - 1 - layer;
        if symbols.len() != n_queries {
            return Err("layer symbol count".into());
        }
        let pair_indices: Vec<usize> =
            current.iter().map(|&idx| high_pair_leaf_index(idx, layer_log)).collect();
        let mut native_leaves = Vec::with_capacity(n_queries);
        let mut region_leaves = Vec::with_capacity(n_queries);
        for (q, &(s0, s1)) in symbols.iter().enumerate() {
            native_leaves.push(high_pair_leaf_hash_for_trace(layer_log, pair_indices[q], s0, s1, hasher));
            region_leaves.push(flat_high_pair_leaf_hash(layer_log, pair_indices[q], phi(s0), phi(s1)));
        }
        region_merkle_to_root(
            &native_leaves,
            &region_leaves,
            &BatchedMerkleProof { siblings: src.folded_merkle_batch[layer].siblings.clone() },
            high_pair_tree_depth(layer_log),
            &pair_indices,
            hasher,
            lanes(&src.folded_roots[layer]),
        )?;
        let r = beta[tau - 2 - layer];
        let mut next = Vec::with_capacity(n_queries);
        for q in 0..n_queries {
            let (s0, s1) = symbols[q];
            let expected = if high_pair_parity(current[q], layer_log) == 1 { s1 } else { s0 };
            if folded[q] != expected {
                return Err(format!("high-fold parity pin at query {q} layer {layer}"));
            }
            next.push(tensor_high_fold_pair(r, layer_log, pair_indices[q], s0, s1));
        }
        folded = next;
        current = pair_indices;
    }

    // SB9: folded == h_code[current[q]].
    for q in 0..n_queries {
        if folded[q] != h_code.idx(current[q]) {
            return Err(format!("H-code mismatch at query {q}"));
        }
    }

    // ---- 3h-3j: the FRI query phase (drawn AFTER the source query), with the
    // per-round openings delegated to region Merkle families and the fold via
    // noid_fri::code::fold.
    let fri_queries = gen_compact_queries(channel, n_rounds + LOG_RATE, num_queries);
    let nq = fri_queries.len();
    let mut folded_syms: Vec<Option<Block128>> = vec![None; nq];
    for round in 0..n_rounds {
        let symbols = &fri.fri_queried_symbols[round];
        if symbols.len() != nq {
            return Err(format!("fri symbol count round {round}"));
        }
        // Fold-consistency against the previous round.
        for (i, &(s0, s1)) in symbols.iter().enumerate() {
            if round > 0 {
                let parity = (fri_queries[i] >> round) & 1;
                let expected = if parity == 1 { s1 } else { s0 };
                if folded_syms[i] != Some(expected) {
                    return Err(format!("fri fold-consistency at query {i} round {round}"));
                }
            }
        }
        let pair_indices: Vec<usize> =
            fri_queries.iter().map(|&qi| (qi >> round) >> 1).collect();
        let mut native_leaves = Vec::with_capacity(nq);
        let mut region_leaves = Vec::with_capacity(nq);
        for &(s0, s1) in symbols {
            native_leaves.push(hasher.hash_pair(&s0, &s1));
            region_leaves.push(flat_hash_pair(phi(s0), phi(s1)));
        }
        region_merkle_to_root(
            &native_leaves,
            &region_leaves,
            &BatchedMerkleProof { siblings: fri.fri_merkle_batch[round].siblings.clone() },
            compute_round_depth(n_rounds, round),
            &pair_indices,
            hasher,
            lanes(&fri.fri_roots[round]),
        )?;
        // Fold.
        for (i, &(s0, s1)) in symbols.iter().enumerate() {
            let pair_idx = (fri_queries[i] >> round) >> 1;
            folded_syms[i] = Some(fold(random_point[round], round, pair_idx, s0, s1, ntt));
        }
    }
    // 3j: final codeword.
    let final_len = fri.final_codeword.len();
    for (i, sym) in folded_syms.iter().enumerate() {
        if let Some(s) = sym {
            let final_idx = fri_queries[i] >> n_rounds;
            if *s != fri.final_codeword[final_idx % final_len] {
                return Err(format!("final codeword mismatch at query {i}"));
            }
        }
    }

    Ok(opening.all_openings[0])
}

/// The source-binding half reproduces via the region families against a REAL
/// capsule opening: honest accepts (returning the opening), a diverged
/// channel / fold chain would fail, and tampering a source or folded symbol is
/// caught.
#[test]
fn mixed_opening_via_region_matches_native() {
    for (num_vars, seed) in [(9usize, 0xA9u64), (11, 0xB11)] {
        let (point, reduction, proof) = capsule_fixture(num_vars, seed);
        let ntt = AdditiveNTT::<Block128>::new(num_vars + LOG_RATE);
        let hasher = Poseidon2bSponge::new();
        let nq = noid_fri_binius::COMPACT_NUM_QUERIES;

        // Native baseline: the full verifier accepts and returns the value.
        let mut ch_native = Channel::new();
        noid_fri_binius::absorb_cap(&mut ch_native, &proof.commitment.cap);
        let native = noid_fri_binius::verify_mixed_opening(
            &proof.commitment, &point, &[], &proof.opening, &ntt, &mut ch_native, &hasher, nq,
        )
        .expect("native honest opening verifies");
        assert_eq!(native, vec![reduction.value]);

        // Region source half: honest accepts, returns the same opening.
        let mut ch = Channel::new();
        noid_fri_binius::absorb_cap(&mut ch, &proof.commitment.cap);
        let got = verify_mixed_opening_via_region(&proof, &point, &ntt, &mut ch, &hasher, nq)
            .expect("region full opening accepts honest proof");
        assert_eq!(got, reduction.value, "nv={num_vars}");

        // Negative: tamper one source symbol -> SB6 (leaf) / SB9 breaks.
        {
            let mut bad = proof.clone();
            bad.opening.source_proof.source_symbols[1] += Block128::from(1u128);
            let mut ch = Channel::new();
            noid_fri_binius::absorb_cap(&mut ch, &bad.commitment.cap);
            assert!(
                verify_mixed_opening_via_region(&bad, &point, &ntt, &mut ch, &hasher, nq).is_err(),
                "nv={num_vars}: tampered source symbol accepted"
            );
        }
        // Negative: tamper a folded-layer symbol -> parity pin / H-code breaks.
        {
            let mut bad = proof.clone();
            if let Some(layer) = bad.opening.source_proof.folded_queried_symbols.first_mut() {
                layer[0].0 += Block128::from(1u128);
            }
            let mut ch = Channel::new();
            noid_fri_binius::absorb_cap(&mut ch, &bad.commitment.cap);
            assert!(
                verify_mixed_opening_via_region(&bad, &point, &ntt, &mut ch, &hasher, nq).is_err(),
                "nv={num_vars}: tampered folded symbol accepted"
            );
        }
        // Negative: tamper a FRI-round queried symbol -> the round-0 Merkle
        // opening (region family) / fold-consistency / final codeword breaks.
        {
            let mut bad = proof.clone();
            bad.opening.fri_proof.fri_queried_symbols[0][0].0 += Block128::from(1u128);
            let mut ch = Channel::new();
            noid_fri_binius::absorb_cap(&mut ch, &bad.commitment.cap);
            assert!(
                verify_mixed_opening_via_region(&bad, &point, &ntt, &mut ch, &hasher, nq).is_err(),
                "nv={num_vars}: tampered FRI symbol accepted"
            );
        }

        eprintln!("[region-mixed-opening] nv={num_vars}: tau={}, n_rounds={}", COMPACT_TAU.min(num_vars), num_vars - COMPACT_TAU.min(num_vars));
    }
}
