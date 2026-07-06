// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared compact-FRI PCS trace primitives — the gadget family for
//! replaying wallet-PCS openings (and FRI-style verifiers generally)
//! in-circuit.
//!
//! Trace twins of the `noid_fri` transcript/Merkle/code layer that
//! `noid_fri_binius`'s mixed opening is built on:
//!
//! - [`FriChannelTrace`] — in-circuit mirror of `noid_fri::Channel` (a
//!   zero-IV `Poseidon2bSponge` duplex; every absorb in the protocol is
//!   rate-lane aligned since the `observe_vector_commitment` u128-depth
//!   amendment landed together with this module).
//! - [`hash_pair_trace`] / [`compress_digest_trace`] — the
//!   `CryptographicHasher` pair used by every FRI Merkle layer
//!   (`hash_pair` = one bare permutation over `[a, b, 0, 0]`; `compress` =
//!   the fixed two-permutation `TAG_COMPRESS` schedule). Digests travel as
//!   two little-endian u128 lanes ([`DigestExpr`]). When every input lane is
//!   a build-time constant the digest is computed natively and enters as a
//!   constant — value-identical, no witness involved (the association-of-
//!   products allowance of the module docs; FS scheduling is untouched
//!   because these hashes never touch the channel).
//! - [`verify_batched_merkle_proof_trace`] /
//!   [`verify_batched_merkle_proof_to_cap_trace`] — trace twins of the
//!   dedup-compressed batch Merkle verifiers (`compact_fri.rs` /
//!   `interleaved_commit.rs`). The dedup/merge schedule is trace STRUCTURE
//!   derived from the query indices; native `Err` branches that depend only
//!   on structure are build asserts, value branches are pins.
//! - [`gen_compact_queries_trace`] — the query-index rule. Query indices are
//!   the low tower bits of squeezed challenges; the trace pins each squeezed
//!   challenge to `Σ index-bit·φ(2^i) + Σ top-bit·φ(2^i)` where the index
//!   bits are structural constants and the top bits are witness booleans.
//!   The R1CS matrix therefore depends on the proof instance — interim
//!   until the shape-freeze pass turns index bits into witness selectors
//!   (the recursion needs protocol-constant matrices).
//! - [`code_new_trace`] / [`fold_trace`] — the Reed-Solomon layer. The
//!   additive-NTT encode is F128-linear with constant twiddles, so encoding
//!   is pure `LinExpr` algebra (0 constraints); a FRI fold costs exactly one
//!   multiplication per pair.

use noid_core::hardware::flat_to_tower_u128;
use noid_core::{AdditiveNTT, Block128};
use noid_fri::hasher::{CryptographicHasher, HashOutput};
use noid_poseidon2b::native::compression::Poseidon2bSponge;

use super::accepted_claim_batch::{compress_trace, digest_lanes};
use super::{
    alloc_block, const_block, flat_const, mul, pin_eq, pin_zero, poseidon2b_permute,
    FieldR1csBuilder, LinExpr,
};

/// A 32-byte digest as two little-endian u128 lanes (φ-mapped), the
/// `digest_lanes` convention shared with every killshot trace slot.
pub type DigestExpr = [LinExpr; 2];

/// Allocate a witness digest.
pub fn alloc_digest(b: &mut FieldR1csBuilder, d: &HashOutput) -> DigestExpr {
    let [lo, hi] = digest_lanes(d);
    [alloc_block(b, lo), alloc_block(b, hi)]
}

/// Build-time constant digest.
pub fn const_digest(d: &HashOutput) -> DigestExpr {
    let [lo, hi] = digest_lanes(d);
    [const_block(lo), const_block(hi)]
}

/// Pin two digests equal (both lanes).
pub fn pin_digest_eq(b: &mut FieldR1csBuilder, x: &DigestExpr, y: &DigestExpr) {
    pin_eq(b, &x[0], &y[0]);
    pin_eq(b, &x[1], &y[1]);
}

/// Concrete tower value carried by an expression at build time (the same
/// mechanism as `range_check_bits` — the builder tracks the honest witness).
pub fn expr_tower_value(b: &FieldR1csBuilder, e: &LinExpr) -> Block128 {
    let f = e.eval(b.values());
    let flat = (f.lo as u128) | ((f.hi as u128) << 64);
    Block128(flat_to_tower_u128(flat))
}

fn digest_bytes_of(lanes: [Block128; 2]) -> HashOutput {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&lanes[0].0.to_le_bytes());
    out[16..].copy_from_slice(&lanes[1].0.to_le_bytes());
    out
}

/// Trace twin of `CryptographicHasher::hash_pair` for `Poseidon2bSponge`:
/// ONE bare permutation over `[a, b, 0, 0]`, digest = the two rate lanes.
/// Constant inputs fold to a constant digest (computed by the native
/// hasher — bit-identical).
pub fn hash_pair_trace(b: &mut FieldR1csBuilder, x: &LinExpr, y: &LinExpr) -> DigestExpr {
    if x.is_const() && y.is_const() {
        let xa = expr_tower_value(b, x);
        let ya = expr_tower_value(b, y);
        let native = Poseidon2bSponge::new().hash_pair(&xa, &ya);
        return const_digest(&native);
    }
    let state = poseidon2b_permute(
        b,
        [x.clone(), y.clone(), LinExpr::zero(), LinExpr::zero()],
    );
    [state[0].clone(), state[1].clone()]
}

/// Trace twin of `CryptographicHasher::compress` (= `noid_poseidon2b::native::compress`,
/// the fixed two-permutation `TAG_COMPRESS` schedule). Constant inputs fold.
pub fn compress_digest_trace(
    b: &mut FieldR1csBuilder,
    l: &DigestExpr,
    r: &DigestExpr,
) -> DigestExpr {
    if l.iter().chain(r.iter()).all(|e| e.is_const()) {
        let la = digest_bytes_of([expr_tower_value(b, &l[0]), expr_tower_value(b, &l[1])]);
        let ra = digest_bytes_of([expr_tower_value(b, &r[0]), expr_tower_value(b, &r[1])]);
        let native = noid_poseidon2b::native::compress(&la, &ra);
        return const_digest(&native);
    }
    compress_trace(b, l, r)
}

/// Full Merkle root over a power-of-two leaf-digest layer (the trace twin of
/// `MerkleTree::new` + `get_root`, `compress` inner nodes).
pub fn merkle_root_trace(b: &mut FieldR1csBuilder, mut layer: Vec<DigestExpr>) -> DigestExpr {
    assert!(layer.len().is_power_of_two() && !layer.is_empty());
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|pair| compress_digest_trace(b, &pair[0], &pair[1]))
            .collect();
    }
    layer.pop().unwrap()
}

// ---------------------------------------------------------------------------
// noid_fri::Channel trace
// ---------------------------------------------------------------------------

/// In-circuit replay of `noid_fri::Channel`: a `FRICHANL`-IV
/// `Poseidon2bSponge` duplex (no domain absorb, no op headers),
/// byte-streaming buffer that — with every protocol absorb 16-byte aligned —
/// always holds 0 or 1 whole lanes. `squeeze` mirrors
/// `Channel::squeeze_block`: pad-flush once on the absorb→squeeze
/// transition, emit `state[0]`, hold `state[1]` pending, advance the sponge;
/// an absorb drops any pending lane and re-enters absorb mode
/// (`enter_absorb_mode`).
pub struct FriChannelTrace {
    state: [LinExpr; 4],
    buffered: Option<LinExpr>,
    pending: Option<LinExpr>,
    squeezing: bool,
    perms: usize,
}

impl FriChannelTrace {
    /// Mirror of `Channel::new()`: zero rate lanes, `FRICHANL` capacity IV
    /// (φ-mapped into the flat wire basis, like every absorbed tower value).
    pub fn new() -> Self {
        let [iv_hi, iv_lo] =
            noid_poseidon2b::native::capacity_iv(noid_poseidon2b::native::TAG_FRICHANL);
        Self {
            state: [
                LinExpr::zero(),
                LinExpr::zero(),
                LinExpr::constant(flat_const(iv_hi.0)),
                LinExpr::constant(flat_const(iv_lo.0)),
            ],
            buffered: None,
            pending: None,
            squeezing: false,
            perms: 0,
        }
    }

    /// Sponge permutations executed so far (lockstep pin for tests).
    pub fn perms(&self) -> usize {
        self.perms
    }

    fn permute(&mut self, b: &mut FieldR1csBuilder) {
        self.state = poseidon2b_permute(b, std::mem::take(&mut self.state));
        self.perms += 1;
    }

    fn enter_absorb_mode(&mut self) {
        if self.squeezing {
            self.pending = None;
            self.squeezing = false;
        }
    }

    /// One whole absorbed lane (`Poseidon2bSponge::update` with 16-byte
    /// aligned writes keeps 0 or 1 lanes buffered).
    fn update_lane(&mut self, b: &mut FieldR1csBuilder, lane: &LinExpr) {
        if let Some(first) = self.buffered.take() {
            self.state[0] = self.state[0].add(&first);
            self.state[1] = self.state[1].add(lane);
            self.permute(b);
        } else {
            self.buffered = Some(lane.clone());
        }
    }

    /// Mirror of `Channel::observe_field_elem` (16 LE bytes = one lane).
    pub fn observe_field_elem(&mut self, b: &mut FieldR1csBuilder, elem: &LinExpr) {
        self.enter_absorb_mode();
        self.update_lane(b, elem);
    }

    /// Mirror of `Channel::observe_field_elems`.
    pub fn observe_field_elems(&mut self, b: &mut FieldR1csBuilder, elems: &[LinExpr]) {
        self.enter_absorb_mode();
        for e in elems {
            self.update_lane(b, e);
        }
    }

    /// Build-time tower constant as one absorbed lane.
    pub fn observe_const_tower(&mut self, b: &mut FieldR1csBuilder, tower: u128) {
        self.observe_field_elem(b, &LinExpr::constant(flat_const(tower)));
    }

    /// Mirror of `Channel::observe_vector_commitment` (post lane-alignment):
    /// 32-byte root (two lanes) + the depth as one whole u128-LE lane.
    pub fn observe_vector_commitment(
        &mut self,
        b: &mut FieldR1csBuilder,
        root: &DigestExpr,
        depth: usize,
    ) {
        self.enter_absorb_mode();
        self.update_lane(b, &root[0]);
        self.update_lane(b, &root[1]);
        self.update_lane(b, &LinExpr::constant(flat_const(depth as u128)));
    }

    /// Mirror of `Poseidon2bSponge::flush_to_squeeze` (pad block `0x80…01`
    /// on a buffered odd lane).
    fn flush(&mut self, b: &mut FieldR1csBuilder) {
        if let Some(first) = self.buffered.take() {
            self.state[0] = self.state[0].add(&first);
            self.state[1] = self
                .state[1]
                .add_const(noid_ivc_core::challenger::fs_pad_lane_flat());
            self.permute(b);
        }
    }

    /// Mirror of `Channel::squeeze_block` / `get_random_point`.
    pub fn squeeze(&mut self, b: &mut FieldR1csBuilder) -> LinExpr {
        if !self.squeezing {
            self.flush(b);
            self.squeezing = true;
        }
        if let Some(p) = self.pending.take() {
            return p;
        }
        // `Poseidon2bSponge::squeeze`: emit the current rate lanes, then
        // advance the state by one permutation.
        let out = self.state[0].clone();
        self.pending = Some(self.state[1].clone());
        self.permute(b);
        out
    }

    /// Mirror of `Channel::get_random_points`.
    pub fn squeeze_n(&mut self, b: &mut FieldR1csBuilder, n: usize) -> Vec<LinExpr> {
        (0..n).map(|_| self.squeeze(b)).collect()
    }
}

impl Default for FriChannelTrace {
    fn default() -> Self {
        Self::new()
    }
}

/// Trace twin of `noid_fri_binius::compact_fri::gen_compact_queries`.
///
/// Each query index is the low `log_max_len` TOWER bits of a squeezed
/// challenge. The indices become trace structure; soundness of the binding
/// is the pinned decomposition `challenge = Σ_{i<log} idx_i·φ(2^i) +
/// Σ_{i≥log} b_i·φ(2^i)` with the top bits allocated as witness booleans
/// (φ is F2-linear, so the sum forces the exact tower bit pattern).
pub fn gen_compact_queries_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FriChannelTrace,
    log_max_len: usize,
    num_queries: usize,
) -> Vec<usize> {
    gen_compact_queries_trace_with_bits(b, ch, log_max_len, num_queries).0
}

/// [`gen_compact_queries_trace`] that also returns, per query, the low
/// `log_max_len` position bits as witness wires (LSB first). Downstream FRI /
/// high-fold gadgets that need a query-position bit (a fold twiddle's coset, a
/// pair's parity selector) must consume these WIRES rather than re-deriving the
/// bit from the native index and baking it as a matrix constant — the latter
/// drifts the shape between blocks with different query positions, breaking
/// class fixity (the recursion invariant). The bits are transcript-bound: the
/// full 128-bit decomposition is pinned equal to the squeezed challenge and
/// each bit is booleanity-constrained.
pub fn gen_compact_queries_trace_with_bits(
    b: &mut FieldR1csBuilder,
    ch: &mut FriChannelTrace,
    log_max_len: usize,
    num_queries: usize,
) -> (Vec<usize>, Vec<Vec<LinExpr>>) {
    assert!(log_max_len < usize::BITS as usize);
    let domain_size = 1usize << log_max_len;
    let n_queries = num_queries.min(domain_size);
    let bit_mask = (domain_size - 1) as u128;
    let random_elems = ch.squeeze_n(b, n_queries);
    let mut indices = Vec::with_capacity(n_queries);
    let mut all_bits = Vec::with_capacity(n_queries);
    for e in &random_elems {
        let tower = expr_tower_value(b, e).0;
        let idx = (tower & bit_mask) as usize;
        // Decompose ALL 128 bits into witness booleans (not just the high bits
        // past the position mask): baking the low position bits as `add_const`
        // constants put the query position into the pinning row's constant term
        // and drifted the matrix across blocks. `pin_zero(sum + e)` binds the
        // decomposition to the squeezed challenge, booleanity pins each bit.
        let mut sum = LinExpr::zero();
        let mut bits = Vec::with_capacity(log_max_len);
        for i in 0..128 {
            let bit = LinExpr::from_wire(b.alloc_bool((tower >> i) & 1 == 1));
            sum = sum.add(&bit.scale(flat_const(1u128 << i)));
            if i < log_max_len {
                bits.push(bit);
            }
        }
        pin_zero(b, &sum.add(e));
        indices.push(idx);
        all_bits.push(bits);
    }
    (indices, all_bits)
}

// ---------------------------------------------------------------------------
// Batched Merkle verification
// ---------------------------------------------------------------------------

fn sorted_unique_leaf_digests(
    b: &mut FieldR1csBuilder,
    leaf_indices: &[usize],
    leaf_hashes: &[DigestExpr],
) -> (Vec<usize>, Vec<DigestExpr>) {
    assert_eq!(leaf_indices.len(), leaf_hashes.len());
    let mut pairs: Vec<(usize, DigestExpr)> = leaf_indices
        .iter()
        .copied()
        .zip(leaf_hashes.iter().cloned())
        .collect();
    pairs.sort_by_key(|(idx, _)| *idx);

    let mut indices: Vec<usize> = Vec::with_capacity(pairs.len());
    let mut hashes: Vec<DigestExpr> = Vec::with_capacity(pairs.len());
    for (idx, hash) in pairs {
        if indices.last().copied() == Some(idx) {
            // Native rejects when a duplicated index carries two different
            // hashes — the trace pins them equal.
            let kept = hashes.last().unwrap().clone();
            pin_digest_eq(b, &kept, &hash);
        } else {
            indices.push(idx);
            hashes.push(hash);
        }
    }
    (indices, hashes)
}

/// Shared walk of the dedup-compressed batch Merkle verifier
/// (`verify_batched_merkle_proof` / `verify_source_batched_merkle_proof_to_cap`
/// are the same algorithm, differing only in where the walk stops and what
/// the surviving nodes are compared against). Returns the surviving
/// `(index, digest)` layer after `depth − cap_depth` levels and asserts the
/// sibling stream was consumed exactly.
fn batched_merkle_walk(
    b: &mut FieldR1csBuilder,
    siblings: &[DigestExpr],
    depth: usize,
    cap_depth: usize,
    leaf_indices: &[usize],
    leaf_hashes: &[DigestExpr],
) -> (Vec<usize>, Vec<DigestExpr>) {
    assert!(cap_depth <= depth);
    let (mut known_indices, mut known_hashes) =
        sorted_unique_leaf_digests(b, leaf_indices, leaf_hashes);

    let mut sib_cursor = 0usize;
    for _d in 0..(depth - cap_depth) {
        let mut next_indices = Vec::new();
        let mut next_hashes: Vec<DigestExpr> = Vec::new();
        let mut cursor = 0usize;
        while cursor < known_indices.len() {
            let parent = known_indices[cursor] >> 1;
            let left_child = parent * 2;
            let right_child = left_child + 1;
            let mut left: Option<DigestExpr> = None;
            let mut right: Option<DigestExpr> = None;
            while cursor < known_indices.len() && (known_indices[cursor] >> 1) == parent {
                let idx = known_indices[cursor];
                if idx == left_child {
                    left = Some(known_hashes[cursor].clone());
                } else {
                    debug_assert_eq!(idx, right_child);
                    right = Some(known_hashes[cursor].clone());
                }
                cursor += 1;
            }
            let parent_hash = match (left, right) {
                (Some(l), Some(r)) => compress_digest_trace(b, &l, &r),
                (Some(l), None) => {
                    // Native: "insufficient siblings" — the proof's sibling
                    // count is trace structure, so a short stream is a build
                    // failure, exactly where native rejects.
                    assert!(sib_cursor < siblings.len(), "insufficient siblings");
                    let r = siblings[sib_cursor].clone();
                    sib_cursor += 1;
                    compress_digest_trace(b, &l, &r)
                }
                (None, Some(r)) => {
                    assert!(sib_cursor < siblings.len(), "insufficient siblings");
                    let l = siblings[sib_cursor].clone();
                    sib_cursor += 1;
                    compress_digest_trace(b, &l, &r)
                }
                (None, None) => unreachable!("orphan parent"),
            };
            next_indices.push(parent);
            next_hashes.push(parent_hash);
        }
        known_indices = next_indices;
        known_hashes = next_hashes;
    }
    assert_eq!(
        sib_cursor,
        siblings.len(),
        "unused siblings in batched Merkle proof"
    );
    (known_indices, known_hashes)
}

/// Trace twin of `noid_fri_binius::compact_fri::verify_batched_merkle_proof`.
pub fn verify_batched_merkle_proof_trace(
    b: &mut FieldR1csBuilder,
    root: &DigestExpr,
    siblings: &[DigestExpr],
    depth: usize,
    leaf_indices: &[usize],
    leaf_hashes: &[DigestExpr],
) {
    let (known_indices, known_hashes) =
        batched_merkle_walk(b, siblings, depth, 0, leaf_indices, leaf_hashes);
    assert!(known_indices.len() == 1 && known_indices[0] == 0, "failed to reach root");
    pin_digest_eq(b, &known_hashes[0], root);
}

/// Trace twin of
/// `noid_fri_binius::interleaved_commit::verify_source_batched_merkle_proof_to_cap`.
pub fn verify_batched_merkle_proof_to_cap_trace(
    b: &mut FieldR1csBuilder,
    cap_nodes: &[DigestExpr],
    cap_depth: usize,
    siblings: &[DigestExpr],
    depth: usize,
    leaf_indices: &[usize],
    leaf_hashes: &[DigestExpr],
) {
    assert_eq!(cap_nodes.len(), 1usize << cap_depth, "source cap width mismatch");
    let (known_indices, known_hashes) =
        batched_merkle_walk(b, siblings, depth, cap_depth, leaf_indices, leaf_hashes);
    for (idx, hash) in known_indices.iter().zip(known_hashes.iter()) {
        assert!(*idx < cap_nodes.len(), "source cap node index out of range");
        pin_digest_eq(b, hash, &cap_nodes[*idx]);
    }
}

// ---------------------------------------------------------------------------
// Reed-Solomon layer
// ---------------------------------------------------------------------------

/// Trace twin of `noid_core::ntt::forward_ntt` over expressions. The
/// butterflies are affine with constant basis twiddles — 0 constraints.
pub fn forward_ntt_trace(coeffs: &[LinExpr], basis: &[Block128]) -> Vec<LinExpr> {
    let n = coeffs.len();
    assert!(n.is_power_of_two());
    assert_eq!(basis.len(), n.trailing_zeros() as usize);
    let mut evals = coeffs.to_vec();
    let mut len = 1usize;
    for &bb in basis.iter() {
        let b_flat = flat_const(bb.0);
        for start in (0..n).step_by(2 * len) {
            for i in start..start + len {
                let u = evals[i].clone();
                let v = evals[i + len].clone();
                let sum = u.add(&v);
                evals[i] = sum.clone();
                evals[i + len] = sum.scale(b_flat).add(&v);
            }
        }
        len *= 2;
    }
    evals
}

/// Trace twin of `noid_fri::code::Code::new`: RATE coset transforms with the
/// canonical shifted basis (`AdditiveNTT::forward_transform` with
/// `round = coset`). Pure linear algebra — 0 constraints.
pub fn code_new_trace(message: &[LinExpr]) -> Vec<LinExpr> {
    let log_n = message.len().trailing_zeros() as usize;
    assert_eq!(message.len(), 1usize << log_n);
    let mut encoding = Vec::with_capacity(message.len() * noid_fri::code::RATE);
    for round in 0..noid_fri::code::RATE {
        let basis: Vec<Block128> = (round..round + log_n)
            .map(|i| Block128::from(1u128 << i))
            .collect();
        encoding.extend(forward_ntt_trace(message, &basis));
    }
    encoding
}

/// Trace twin of `noid_fri::code::fold`: with the constant twiddle
/// `t = ntt.get_subspace_eval(round, idx)`,
/// `x0 = v0 + (v0+v1)·t` is affine and the fold costs ONE multiplication
/// (`r · (x0 + x1)`).
pub fn fold_trace(
    b: &mut FieldR1csBuilder,
    r: &LinExpr,
    round: usize,
    idx: usize,
    v0: &LinExpr,
    v1: &LinExpr,
    ntt: &AdditiveNTT<Block128>,
) -> LinExpr {
    let twiddle = ntt.get_subspace_eval(round, idx);
    let x1 = v0.add(v1);
    let x0 = v0.add(&x1.scale(flat_const(twiddle.0)));
    x0.add(&mul(b, r, &x0.add(&x1)))
}

/// [`fold_trace`] with the fold coset carried as WITNESS bits instead of a
/// native index. `get_subspace_eval(round, idx) = Σ_{j<round} idx_bit_j ·
/// basis[j]` is F2-linear in `idx` with no offset, so the twiddle is an affine
/// expression `Σ_j idx_bits[j]·basis[j]` over the (transcript-bound) query
/// bits — the fold stays class-fixed. `fold_trace`'s native-index form bakes
/// the twiddle as a matrix constant and drifts the shape between blocks with
/// different query positions; the region (recursion) path must use this form.
/// `idx_bits` must expose at least `round` bits (LSB first).
pub fn fold_trace_bits(
    b: &mut FieldR1csBuilder,
    r: &LinExpr,
    round: usize,
    idx_bits: &[LinExpr],
    v0: &LinExpr,
    v1: &LinExpr,
    ntt: &AdditiveNTT<Block128>,
) -> LinExpr {
    let mut twiddle = LinExpr::zero();
    for j in 0..round {
        let basis_j = ntt.get_subspace_eval(round, 1usize << j);
        twiddle = twiddle.add(&idx_bits[j].scale(flat_const(basis_j.0)));
    }
    let x1 = v0.add(v1);
    // `x1 · twiddle` is a wire product now (twiddle is a wire), not a constant
    // scaling — one extra multiplication versus `fold_trace`.
    let x0 = v0.add(&mul(b, &x1, &twiddle));
    x0.add(&mul(b, r, &x0.add(&x1)))
}

/// Trace twin of `noid_fri_binius::mixed_open`'s `mle_evaluate_small`
/// (highest-variable fold loop; `2^n − 1` multiplications).
pub fn mle_evaluate_small_trace(
    b: &mut FieldR1csBuilder,
    evals: &[LinExpr],
    point: &[LinExpr],
) -> LinExpr {
    if point.is_empty() {
        return evals[0].clone();
    }
    let mut buf = evals.to_vec();
    for r in point.iter().rev() {
        let half = buf.len() / 2;
        for i in 0..half {
            let diff = buf[i].add(&buf[i + half]);
            buf[i] = buf[i].add(&mul(b, r, &diff));
        }
        buf.truncate(half);
    }
    buf[0].clone()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::test_support::{assert_expr_is, tower_value};
    use super::super::alloc_blocks;
    use super::*;
    use noid_fri::merkle::VectorCommitment;
    use noid_fri::Channel;

    struct Rng(u128);
    impl Rng {
        fn next_u128(&mut self) -> u128 {
            self.0 = self
                .0
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0xB5AD_4ECE_DA1C_E2A9);
            self.0
        }
        fn next_block(&mut self) -> Block128 {
            Block128::from(self.next_u128())
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next_u128() % n as u128) as usize
        }
    }

    /// FriChannelTrace vs the native `noid_fri::Channel`, 1000 random
    /// schedules of field/vector-commitment observes and squeezes —
    /// challenge values AND permutation counts in lockstep.
    #[test]
    fn fri_channel_trace_lockstep_1000_random_schedules() {
        for seed in 0..1000u128 {
            let mut rng = Rng(seed.wrapping_mul(0xC0FFEE) + 7);
            let mut native = Channel::new();
            let mut b = FieldR1csBuilder::new();
            let mut trace = FriChannelTrace::new();
            let ops = 3 + rng.below(12);
            for _ in 0..ops {
                match rng.below(4) {
                    0 => {
                        let v = rng.next_block();
                        native.observe_field_elem(v);
                        let e = alloc_block(&mut b, v);
                        trace.observe_field_elem(&mut b, &e);
                    }
                    1 => {
                        let n = 1 + rng.below(5);
                        let vs: Vec<Block128> = (0..n).map(|_| rng.next_block()).collect();
                        native.observe_field_elems(&vs);
                        let es = alloc_blocks(&mut b, &vs);
                        trace.observe_field_elems(&mut b, &es);
                    }
                    2 => {
                        let mut root = [0u8; 32];
                        root[..16].copy_from_slice(&rng.next_u128().to_le_bytes());
                        root[16..].copy_from_slice(&rng.next_u128().to_le_bytes());
                        let depth = rng.below(24);
                        native.observe_vector_commitment(&VectorCommitment { root, depth });
                        let d = alloc_digest(&mut b, &root);
                        trace.observe_vector_commitment(&mut b, &d, depth);
                    }
                    _ => {
                        let n = 1 + rng.below(4);
                        let native_pts = native.get_random_points(n);
                        let trace_pts = trace.squeeze_n(&mut b, n);
                        for (nv, te) in native_pts.iter().zip(trace_pts.iter()) {
                            assert_expr_is(&b, te, *nv, "fri channel challenge");
                        }
                    }
                }
            }
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "seed {seed}");
        }
    }

    #[test]
    fn gen_compact_queries_trace_matches_native() {
        use noid_fri_binius::compact_fri::gen_compact_queries;
        for (seed, log_d, nq) in [(1u128, 11usize, 64usize), (2, 3, 64), (3, 8, 10)] {
            let mut native = Channel::new();
            let mut b = FieldR1csBuilder::new();
            let mut trace = FriChannelTrace::new();
            let mut rng = Rng(seed);
            let v = rng.next_block();
            native.observe_field_elem(v);
            let e = alloc_block(&mut b, v);
            trace.observe_field_elem(&mut b, &e);

            let native_idx = gen_compact_queries(&mut native, log_d, nq);
            let trace_idx = gen_compact_queries_trace(&mut b, &mut trace, log_d, nq);
            assert_eq!(native_idx, trace_idx);
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }

    #[test]
    fn hash_pair_and_compress_traces_match_native() {
        let mut rng = Rng(42);
        let hasher = Poseidon2bSponge::new();
        let mut b = FieldR1csBuilder::new();
        let (x, y) = (rng.next_block(), rng.next_block());
        let (xe, ye) = (alloc_block(&mut b, x), alloc_block(&mut b, y));

        let hp = hash_pair_trace(&mut b, &xe, &ye);
        let native_hp = hasher.hash_pair(&x, &y);
        let [lo, hi] = digest_lanes(&native_hp);
        assert_eq!(tower_value(&b, &hp[0]), lo);
        assert_eq!(tower_value(&b, &hp[1]), hi);

        // Constant folding must be value-identical.
        let hp_const = hash_pair_trace(&mut b, &const_block(x), &const_block(y));
        assert!(hp_const[0].is_const() && hp_const[1].is_const());
        assert_eq!(tower_value(&b, &hp_const[0]), lo);
        assert_eq!(tower_value(&b, &hp_const[1]), hi);

        let mut r = [0u8; 32];
        r[..16].copy_from_slice(&rng.next_u128().to_le_bytes());
        r[16..].copy_from_slice(&rng.next_u128().to_le_bytes());
        let rd = alloc_digest(&mut b, &r);
        let cp = compress_digest_trace(&mut b, &hp, &rd);
        let native_cp = hasher.compress(&native_hp, &r);
        let [clo, chi] = digest_lanes(&native_cp);
        assert_eq!(tower_value(&b, &cp[0]), clo);
        assert_eq!(tower_value(&b, &cp[1]), chi);

        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
    }

    #[test]
    fn code_and_fold_traces_match_native() {
        use noid_fri::code::{fold, Code, LOG_RATE};
        let log_n = 4usize;
        let mut rng = Rng(7);
        let msg: Vec<Block128> = (0..1usize << log_n).map(|_| rng.next_block()).collect();
        let ntt = AdditiveNTT::<Block128>::new(log_n + LOG_RATE);
        let code = Code::new(&msg, &ntt);

        let mut b = FieldR1csBuilder::new();
        let msg_e = alloc_blocks(&mut b, &msg);
        let enc = code_new_trace(&msg_e);
        assert_eq!(enc.len(), code.encoding.len());
        for (e, nv) in enc.iter().zip(code.encoding.iter()) {
            assert_expr_is(&b, e, *nv, "code symbol");
        }

        let r = rng.next_block();
        let re = alloc_block(&mut b, r);
        for round in 0..2usize {
            for idx in [0usize, 3, 7] {
                let (v0, v1) = (rng.next_block(), rng.next_block());
                let v0e = alloc_block(&mut b, v0);
                let v1e = alloc_block(&mut b, v1);
                let f = fold_trace(&mut b, &re, round, idx, &v0e, &v1e, &ntt);
                let nf = fold(r, round, idx, v0, v1, &ntt);
                assert_expr_is(&b, &f, nf, "fold");
            }
        }
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
    }

    #[test]
    fn batched_merkle_trace_accepts_and_pins_root() {
        use noid_fri::merkle::{compute_leaf_hashes, MerkleTree};
        use noid_fri_binius::compact_fri::build_batched_merkle_proof;

        let mut rng = Rng(1234);
        let hasher = Poseidon2bSponge::new();
        let vals: Vec<Block128> = (0..64).map(|_| rng.next_block()).collect();
        let leaf_hashes = compute_leaf_hashes(&vals, &hasher);
        let tree = MerkleTree::new(leaf_hashes.clone(), &hasher);
        let depth = tree.num_layers() - 1;
        let indices: Vec<usize> = (0..10).map(|_| rng.below(32)).collect();
        let batch = build_batched_merkle_proof(&tree, &indices, depth);

        let mut b = FieldR1csBuilder::new();
        let root = alloc_digest(&mut b, &tree.get_root());
        let sibs: Vec<DigestExpr> = batch
            .siblings
            .iter()
            .map(|s| alloc_digest(&mut b, s))
            .collect();
        let leaves: Vec<DigestExpr> = indices
            .iter()
            .map(|&i| alloc_digest(&mut b, &leaf_hashes[i]))
            .collect();
        verify_batched_merkle_proof_trace(&mut b, &root, &sibs, depth, &indices, &leaves);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
    }

    #[test]
    fn batched_merkle_trace_rejects_wrong_leaf() {
        use noid_fri::merkle::{compute_leaf_hashes, MerkleTree};
        use noid_fri_binius::compact_fri::build_batched_merkle_proof;

        let mut rng = Rng(555);
        let hasher = Poseidon2bSponge::new();
        let vals: Vec<Block128> = (0..32).map(|_| rng.next_block()).collect();
        let leaf_hashes = compute_leaf_hashes(&vals, &hasher);
        let tree = MerkleTree::new(leaf_hashes.clone(), &hasher);
        let depth = tree.num_layers() - 1;
        let indices = vec![1usize, 5, 9];
        let batch = build_batched_merkle_proof(&tree, &indices, depth);

        let mut b = FieldR1csBuilder::new();
        let root = alloc_digest(&mut b, &tree.get_root());
        let sibs: Vec<DigestExpr> = batch
            .siblings
            .iter()
            .map(|s| alloc_digest(&mut b, s))
            .collect();
        let mut bad = leaf_hashes[5];
        bad[3] ^= 1;
        let leaves: Vec<DigestExpr> = [leaf_hashes[1], bad, leaf_hashes[9]]
            .iter()
            .map(|h| alloc_digest(&mut b, h))
            .collect();
        verify_batched_merkle_proof_trace(&mut b, &root, &sibs, depth, &indices, &leaves);
        let (r1cs, z) = b.build();
        assert!(!r1cs.satisfies(&z), "tampered leaf must be unsatisfiable");
    }

    #[test]
    fn mle_evaluate_small_trace_matches_native() {
        let mut rng = Rng(31);
        for n in [0usize, 1, 3, 5] {
            let evals: Vec<Block128> = (0..1usize << n).map(|_| rng.next_block()).collect();
            let point: Vec<Block128> = (0..n).map(|_| rng.next_block()).collect();
            let mut buf = evals.clone();
            for &r in point.iter().rev() {
                let half = buf.len() / 2;
                for i in 0..half {
                    buf[i] = buf[i] + r * (buf[i] + buf[i + half]);
                }
                buf.truncate(half);
            }
            let native = buf[0];

            let mut b = FieldR1csBuilder::new();
            let evals_e = alloc_blocks(&mut b, &evals);
            let point_e = alloc_blocks(&mut b, &point);
            let got = mle_evaluate_small_trace(&mut b, &evals_e, &point_e);
            assert_expr_is(&b, &got, native, "mle_evaluate_small");
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }
}
