// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! FRI-committed UTXO state.
//!
//! The chain state is a vector of `2^log_slots` UTXO slots. Each slot is
//! a `SlotValue { value, owner_hi, owner_lo }` tuple. The commitment is
//! a Poseidon2b sponge over three independent FRI Merkle roots — one
//! per slot-column — keyed by `TAG_FRISTATE` capacity IV with `log_slots`
//! absorbed first. Unused / spent slots carry `SlotValue::EMPTY` (all
//! zeros). Poseidon2b (not Blake3) was chosen so that the in-circuit
//! combiner AIR reuses the already-arithmetised
//! `PoseidonPermAir` primitive. FRI Merkle internals still use Blake3.
//!
//! Why FRI over SMT: opening a slot is a batched FRI opening, which the
//! transaction AIR verifies via sumcheck rather than through 32+ hash
//! compressions. For transparent chains (no leaf hiding), FRI-state
//! replaces the per-input Merkle path and removes ~85 % of the in-circuit
//! Poseidon work.
//!
//! State transitions are **linear**: spending `slot_i` is `slot_i ← 0`,
//! minting into `slot_j` is `slot_j ← new`. `apply_delta` applies a batch
//! of such updates in place and returns the new root.

use std::borrow::Cow;

use noid_core::{Block128, TowerField};

/// Segment size used by `SegmentedFriState`.
/// Each segment independently holds and commits `2^LOG_SEGMENT_SIZE` slots.
/// When `log_slots <= LOG_SEGMENT_SIZE` (tests), the state is monolithic
/// (one segment whose size is `2^log_slots`).
pub const LOG_SEGMENT_SIZE: usize = 16;
use noid_fri::channel::Channel;
use noid_fri_binius::{
    absorb_cap, interleaved_commit, prove_mixed_opening, verify_mixed_opening,
    InterleavedCommitment, MixedOpeningProof, COMPACT_NUM_QUERIES,
};
use noid_poseidon2b::native::compress;
use noid_poseidon2b::native::compression::Poseidon2bSponge;

/// Genesis `log_slots` for mainnet: 16 777 216 slots at block 0. Not
/// a circuit-wide constant — the AIR and STARK transcript are
/// parameterised by the header-declared `log_slots` (see
/// `noid_tx::public::PublicInputs::log_slots` and `MAX_LOG_SLOTS`),
/// which may grow to at most `32` via the `§15.3` expansion trigger.
/// This value is used only as the seed depth when instantiating a
/// fresh `ChainState` without an existing header. Tests override with
/// smaller values through [`FriState::new_empty`].
pub const STATE_LOG_SLOTS: usize = 24;

/// Per-slot payload: `(value, owner)` where `owner` is 256 bits split
/// into two 128-bit halves. All-zeros means "slot empty / spent".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SlotValue {
    pub value: Block128,
    pub owner_hi: Block128,
    pub owner_lo: Block128,
}

impl SlotValue {
    pub const EMPTY: Self = Self {
        value: Block128(0),
        owner_hi: Block128(0),
        owner_lo: Block128(0),
    };

    #[inline]
    pub fn is_empty(&self) -> bool {
        *self == Self::EMPTY
    }
}

/// 32-byte state root.
pub type StateRoot = [u8; 32];

/// Errors returned by state updates and openings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    SlotOutOfRange,
    /// A FRI opening did not verify against the cached column root.
    OpeningFailed,
}

/// Batched FRI opening of all three state columns for one segment at an arbitrary eval point.
///
/// Uses the compact `noid_fri_binius` interleaved commitment scheme — the SAME scheme
/// as the block-level FRI proof, enabling efficient compact FRI + Merkle path openings.
///
/// For **slot openings** (`local_idx`-based), `eval_point` is the boolean hypercube
/// encoding of `local_idx`; `slot_vals` are the actual slot values.
/// For **MLE openings** (`eval_point` from `BlockStateBindingAir`), `slot_vals` are
/// the batched MLE evaluations used in `prev/new_lane_openings`.
#[derive(Debug, Clone)]
pub struct SlotOpening {
    pub slot_index: u32,
    pub log_slots: usize,
    /// Segment `slot_index` belongs to (= slot_index >> effective_log_seg).
    pub segment_id: u16,
    /// Local index within the segment (= slot_index & (segment_size - 1)).
    pub local_idx: u16,
    /// Interleaved commitment to [values, owners_hi, owners_lo] columns.
    /// `cap_to_seg_root_with_depth(commitment.cap, eff_log) == seg_root`.
    pub commitment: InterleavedCommitment,
    /// MLE evaluations `[value, owner_hi, owner_lo]` at `eval_point`.
    pub slot_vals: [Block128; 3],
    /// Mixed opening proof for the 3 columns at `eval_point`.
    pub proof: MixedOpeningProof,
    /// Compact FRI segment root: `cap_to_seg_root_with_depth(commitment.cap, eff_log)`.
    pub seg_root: StateRoot,
    /// Poseidon2b Merkle siblings from `seg_root` up to `state_root` (bottom-up).
    /// Empty when `num_segments == 1` (single-segment / test mode).
    pub merkle_siblings: Vec<StateRoot>,
    /// Global state root at open time.
    pub state_root: StateRoot,
}

impl SlotOpening {
    /// Reconstruct the `SlotValue` that the opening claims.
    pub fn slot(&self) -> SlotValue {
        SlotValue {
            value: self.slot_vals[0],
            owner_hi: self.slot_vals[1],
            owner_lo: self.slot_vals[2],
        }
    }

    /// Effective log segment size (min of log_slots and LOG_SEGMENT_SIZE).
    #[inline]
    pub fn effective_log_seg(&self) -> usize {
        self.log_slots.min(LOG_SEGMENT_SIZE)
    }
}

/// FRI-committed UTXO state.
#[derive(Debug, Clone)]
pub struct FriState {
    log_slots: usize,
    values: Vec<Block128>,
    owners_hi: Vec<Block128>,
    owners_lo: Vec<Block128>,
    /// Cached root. Invalidated (set to `None`) on every mutation.
    cached_root: Option<StateRoot>,
}

impl FriState {
    /// Empty state vector with `2^log_slots` zero slots.
    ///
    /// Mainnet: `log_slots = STATE_LOG_SLOTS`. Tests should pick a small
    /// value (e.g. 4) to keep memory bounded.
    pub fn new_empty(log_slots: usize) -> Self {
        assert!(log_slots >= 1, "FriState needs at least one slot");
        let n = 1usize << log_slots;
        Self {
            log_slots,
            values: vec![Block128::ZERO; n],
            owners_hi: vec![Block128::ZERO; n],
            owners_lo: vec![Block128::ZERO; n],
            cached_root: None,
        }
    }

    #[inline]
    pub fn log_slots(&self) -> usize {
        self.log_slots
    }

    #[inline]
    pub fn num_slots(&self) -> u64 {
        1u64 << self.log_slots
    }

    /// Read the slot at `idx`. Returns `SlotValue::EMPTY` for any
    /// in-range index that has never been written.
    pub fn slot(&self, idx: u32) -> SlotValue {
        let i = idx as usize;
        assert!(i < self.values.len(), "slot index out of range");
        SlotValue {
            value: self.values[i],
            owner_hi: self.owners_hi[i],
            owner_lo: self.owners_lo[i],
        }
    }

    /// Apply a batch of `(index, new_value)` updates in place and
    /// return the post-update state root. Later entries in `deltas`
    /// override earlier ones at the same index.
    pub fn apply_delta(&mut self, deltas: &[(u32, SlotValue)]) -> Result<StateRoot, StateError> {
        for (idx, _) in deltas {
            if (*idx as u64) >= self.num_slots() {
                return Err(StateError::SlotOutOfRange);
            }
        }
        for (idx, v) in deltas {
            let i = *idx as usize;
            self.values[i] = v.value;
            self.owners_hi[i] = v.owner_hi;
            self.owners_lo[i] = v.owner_lo;
        }
        self.cached_root = None;
        Ok(self.root())
    }

    /// Write one slot and return the new root.
    pub fn set_slot(&mut self, idx: u32, v: SlotValue) -> Result<StateRoot, StateError> {
        self.apply_delta(&[(idx, v)])
    }

    /// Compute (or return cached) state root.
    ///
    /// Uses `noid_fri_binius::interleaved_commit` over the three columns,
    /// then reduces the cap to a single 32-byte root via
    /// `cap_to_seg_root`. This is the SAME scheme as `SegmentedFriState`
    /// and as the block-level FRI proof, ensuring all commitments are
    /// cryptographically consistent.
    pub fn root(&mut self) -> StateRoot {
        if let Some(r) = self.cached_root {
            return r;
        }
        let r = compute_segment_root(
            self.log_slots,
            &self.values,
            &self.owners_hi,
            &self.owners_lo,
        );
        self.cached_root = Some(r);
        r
    }

    /// Consume `self` and return the three raw columns. Useful for the
    /// Prover-side witness builder that needs the whole evaluation vector.
    pub fn into_columns(self) -> (Vec<Block128>, Vec<Block128>, Vec<Block128>) {
        (self.values, self.owners_hi, self.owners_lo)
    }

    /// Borrow the three columns without taking ownership.
    pub fn columns(&self) -> (&[Block128], &[Block128], &[Block128]) {
        (&self.values, &self.owners_hi, &self.owners_lo)
    }

    /// Open a single slot using compact FRI (same scheme as SegmentedFriState).
    ///
    /// Monolithic / single-segment: `segment_id = 0`, `merkle_siblings = []`,
    /// `seg_root == state_root`.
    pub fn open(&self, idx: u32) -> Result<SlotOpening, StateError> {
        if (idx as u64) >= self.num_slots() {
            return Err(StateError::SlotOutOfRange);
        }
        let point = eval_point_for_index(idx, self.log_slots);
        let (commitment, slot_vals, proof, seg_root) = open_segment_at_point(
            self.log_slots,
            &self.values,
            &self.owners_hi,
            &self.owners_lo,
            &point,
        );
        Ok(SlotOpening {
            slot_index: idx,
            log_slots: self.log_slots,
            segment_id: 0,
            local_idx: idx as u16,
            commitment,
            slot_vals,
            proof,
            seg_root,
            merkle_siblings: vec![],
            state_root: seg_root,
        })
    }

    /// Open a batch of slots. Each opening is independent; duplicates
    /// are accepted and each produces its own proof.
    pub fn open_batch(&self, indices: &[u32]) -> Result<Vec<SlotOpening>, StateError> {
        let mut out = Vec::with_capacity(indices.len());
        for &idx in indices {
            out.push(self.open(idx)?);
        }
        Ok(out)
    }
}

/// Multilinear evaluation point corresponding to slot `idx` on a state
/// vector of depth `log_slots`. Bit `i` of `idx` is placed at variable
/// `i`, matching the FRI prover's column orientation (low bits first).
pub fn eval_point_for_index(idx: u32, log_slots: usize) -> Vec<Block128> {
    (0..log_slots)
        .map(|i| {
            if (idx >> i) & 1 == 1 {
                Block128::ONE
            } else {
                Block128::ZERO
            }
        })
        .collect()
}

/// Evaluation point for a segment-local index (`local_idx` within a 2^`log_size` segment).
/// Identical logic to `eval_point_for_index` but operates on the local index only.
/// Used by `SegmentedFriState` where each segment is a `2^log_size`-element column.
pub fn eval_point_for_local_index(local_idx: u16, log_size: usize) -> Vec<Block128> {
    (0..log_size)
        .map(|i| {
            if (local_idx >> i) & 1 == 1 {
                Block128::ONE
            } else {
                Block128::ZERO
            }
        })
        .collect()
}

fn mle_eval_native(evals: &[Block128], point: &[Block128]) -> Block128 {
    let mut buf = evals.to_vec();
    for &r in point.iter().rev() {
        let half = buf.len() / 2;
        for i in 0..half {
            buf[i] = buf[i] + r * (buf[i + half] + buf[i]);
        }
        buf.truncate(half);
    }
    buf[0]
}

/// Open all three segment columns at `point` using compact interleaved FRI.
/// Returns `(commitment, slot_vals, proof, seg_root)`.
///
/// Used by both `FriState::open()` (boolean eval point = slot index) and
/// `SegmentedFriState::open()` (same), and for compact FRI + Merkle
/// path openings from `BlockStateBindingAir` (random eval point).
pub fn open_segment_at_point(
    eff_log: usize,
    values: &[Block128],
    owners_hi: &[Block128],
    owners_lo: &[Block128],
    point: &[Block128],
) -> (
    InterleavedCommitment,
    [Block128; 3],
    MixedOpeningProof,
    StateRoot,
) {
    // Use same padding as compute_segment_root for consistency.
    let commit_log = eff_log.max(MIN_COMMIT_LOG);
    let commit_n = 1usize << commit_log;
    let v = pad_column_borrowed(values, commit_n);
    let h = pad_column_borrowed(owners_hi, commit_n);
    let l = pad_column_borrowed(owners_lo, commit_n);

    // Eval point must have commit_log dimensions (extend with zeros for padded columns).
    // MLE(padded, [original_bits..., 0...]) == MLE(original, original_bits) because
    // zero-padding means the upper half has all-zero values.
    let padded_point: Vec<Block128> = {
        let mut p = point.to_vec();
        p.resize(commit_log, Block128::ZERO);
        p
    };

    let ntt = noid_core::AdditiveNTT::<Block128>::new(commit_log + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let cols: [&[Block128]; 3] = [v.as_ref(), h.as_ref(), l.as_ref()];
    let (commitment, prover_state) = interleaved_commit(&cols, &ntt, &hasher);
    let seg_root = cap_to_seg_root_with_depth(&commitment.cap, eff_log);
    let mut ch = Channel::new();
    absorb_cap(&mut ch, &commitment.cap);
    let proof = prove_mixed_opening(
        &prover_state,
        &padded_point,
        &[],
        &ntt,
        &mut ch,
        &hasher,
        COMPACT_NUM_QUERIES,
    );
    // MLE values at the ORIGINAL point (not padded) — these are the actual slot values.
    let slot_vals = [
        mle_eval_native(values, point),
        mle_eval_native(owners_hi, point),
        mle_eval_native(owners_lo, point),
    ];
    (commitment, slot_vals, proof, seg_root)
}

/// Verify a single-slot opening against a claimed `StateRoot`.
///
/// Steps:
/// 1. Verify compact FRI batched opening of the 3 columns at the slot eval point.
/// 2. Re-derive `seg_root = cap_to_seg_root(commitment.cap)` and check.
/// 3. Verify Poseidon2b Merkle path `seg_root → state_root`.
pub fn verify_opening(state_root: &StateRoot, op: &SlotOpening) -> Result<SlotValue, StateError> {
    if (op.slot_index as u64) >= (1u64 << op.log_slots) {
        return Err(StateError::SlotOutOfRange);
    }
    let eff_log = op.effective_log_seg();
    let point = eval_point_for_local_index(op.local_idx, eff_log);

    // Verify compact FRI batched opening.
    // Use same padding/point extension as open_segment_at_point.
    let commit_log = eff_log.max(MIN_COMMIT_LOG);
    let padded_point: Vec<Block128> = {
        let mut p = point.clone();
        p.resize(commit_log, Block128::ZERO);
        p
    };
    let ntt = noid_core::AdditiveNTT::<Block128>::new(commit_log + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let mut ch = Channel::new();
    absorb_cap(&mut ch, &op.commitment.cap);
    let col_evals = verify_mixed_opening(
        &op.commitment,
        &padded_point,
        &[],
        &op.proof,
        &ntt,
        &mut ch,
        &hasher,
        COMPACT_NUM_QUERIES,
    )
    .map_err(|_| StateError::OpeningFailed)?;

    // col_evals are at padded_point; slot_vals are at original point.
    // For slot openings they're equal (MLE preserves values at lower hypercube).
    // For MLE openings at random eval_point they're also equal by construction.
    if col_evals.len() < 3
        || col_evals[0] != op.slot_vals[0]
        || col_evals[1] != op.slot_vals[1]
        || col_evals[2] != op.slot_vals[2]
    {
        return Err(StateError::OpeningFailed);
    }

    // seg_root must match commitment cap + eff_log.
    let derived = cap_to_seg_root_with_depth(&op.commitment.cap, eff_log);
    if derived != op.seg_root {
        return Err(StateError::OpeningFailed);
    }

    // Merkle path seg_root → state_root.
    if op.merkle_siblings.is_empty() {
        if op.seg_root != *state_root {
            return Err(StateError::OpeningFailed);
        }
    } else {
        let computed = merkle_root_from_leaf(&op.seg_root, op.segment_id, &op.merkle_siblings);
        if computed != *state_root {
            return Err(StateError::OpeningFailed);
        }
    }
    Ok(op.slot())
}

/// Walk a Poseidon2b Merkle path from `leaf` (at position `seg_id`) upward
/// through `siblings` (bottom-up order) to compute the expected root.
pub fn merkle_root_from_leaf(leaf: &StateRoot, seg_id: u16, siblings: &[StateRoot]) -> StateRoot {
    use noid_poseidon2b::native::compress;
    let mut current = *leaf;
    let mut idx = seg_id as usize;
    for sib in siblings {
        current = if idx % 2 == 0 {
            compress(&current, sib)
        } else {
            compress(sib, &current)
        };
        idx >>= 1;
    }
    current
}

// ---------------------------------------------------------------------------
// Root computation (compact FRI scheme)
// ---------------------------------------------------------------------------

/// Minimum log2(n) for `interleaved_commit` to be data-sensitive
/// (cap_size = 2^MERKLE_CAP_DEPTH = 32 requires n >= 32).
const MIN_COMMIT_LOG: usize = noid_fri_binius::MERKLE_CAP_DEPTH;

fn pad_column_borrowed(col: &[Block128], commit_n: usize) -> Cow<'_, [Block128]> {
    if col.len() < commit_n {
        let mut padded = col.to_vec();
        padded.resize(commit_n, Block128::ZERO);
        Cow::Owned(padded)
    } else {
        Cow::Borrowed(col)
    }
}

/// Compute the segment root from three column vectors using compact interleaved FRI.
///
/// `seg_root = cap_to_seg_root(interleaved_commit(padded_cols).cap)` where
/// padding to `2^max(eff_log, MIN_COMMIT_LOG)` ensures the cap captures all data.
/// For production (`eff_log=16`): no padding needed. For small test segments
/// (`eff_log < 5`): zero-padded to 32 elements before commitment.
pub fn compute_segment_root(
    eff_log: usize,
    values: &[Block128],
    owners_hi: &[Block128],
    owners_lo: &[Block128],
) -> StateRoot {
    let commit_log = eff_log.max(MIN_COMMIT_LOG);
    let commit_n = 1usize << commit_log;
    // Pad to commit_n if needed (zero-extends, preserves MLE on lower hypercube).
    // Production segments already have commit_n rows, so borrow them to avoid
    // copying three full 2^16 columns before every root/opening computation.
    let v = pad_column_borrowed(values, commit_n);
    let h = pad_column_borrowed(owners_hi, commit_n);
    let l = pad_column_borrowed(owners_lo, commit_n);
    let ntt = noid_core::AdditiveNTT::<Block128>::new(commit_log + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let cols: [&[Block128]; 3] = [v.as_ref(), h.as_ref(), l.as_ref()];
    let (commitment, _) = interleaved_commit(&cols, &ntt, &hasher);
    cap_to_seg_root_with_depth(&commitment.cap, eff_log)
}

/// Reduce an interleaved FRI cap to a single 32-byte state root via pairwise
/// Poseidon2b compression, then mix in `eff_log` for domain separation across
/// segment sizes.
///
/// Modern caps contain the 32 legacy segment hashes plus a source-code root used
/// by source-bound mixed openings.  The source root is part of the state
/// commitment: odd layers are padded with a deterministic domain-separated leaf
/// instead of silently dropping the final hash.
///
/// Including `eff_log` ensures states with different `log_slots` produce
/// distinct roots even when all data is zero.
pub fn cap_to_seg_root(cap: &noid_fri_binius::MerkleCap) -> StateRoot {
    let mut layer: Vec<[u8; 32]> = cap.hashes.clone();
    assert!(!layer.is_empty(), "state cap must not be empty");
    let mut level = 0u64;
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(state_cap_odd_pad(level, layer.len()));
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks_exact(2) {
            next.push(compress(&chunk[0], &chunk[1]));
        }
        layer = next;
        level += 1;
    }
    layer[0]
}

fn state_cap_odd_pad(level: u64, layer_len: usize) -> [u8; 32] {
    let mut pad = [0u8; 32];
    pad[..8].copy_from_slice(&level.to_le_bytes());
    pad[8..16].copy_from_slice(&(layer_len as u64).to_le_bytes());
    pad[16..].copy_from_slice(b"NOID_STATE_PAD_v");
    pad
}

/// Like `cap_to_seg_root` but mixes in the ORIGINAL `eff_log` so that
/// empty segments of different depths produce distinct roots.
///
/// Use this everywhere a segment root is computed or verified.
pub fn cap_to_seg_root_with_depth(cap: &noid_fri_binius::MerkleCap, eff_log: usize) -> StateRoot {
    let base = cap_to_seg_root(cap);
    // Mix eff_log into the root via one Poseidon2b compression.
    let mut depth = [0u8; 32];
    depth[..8].copy_from_slice(&(eff_log as u64).to_le_bytes());
    compress(&base, &depth)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(seed: u128) -> SlotValue {
        SlotValue {
            value: Block128::from(seed),
            owner_hi: Block128::from(seed.wrapping_mul(3) + 1),
            owner_lo: Block128::from(seed.wrapping_mul(7) + 2),
        }
    }

    #[test]
    fn empty_state_root_is_deterministic() {
        let mut a = FriState::new_empty(4);
        let mut b = FriState::new_empty(4);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn empty_roots_differ_by_depth() {
        let mut a = FriState::new_empty(4);
        let mut b = FriState::new_empty(5);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn writing_a_slot_changes_the_root() {
        let mut state = FriState::new_empty(4);
        let r0 = state.root();
        state.set_slot(3, sv(42)).unwrap();
        let r1 = state.root();
        assert_ne!(r0, r1);
    }

    #[test]
    fn delta_is_idempotent_on_zero_write() {
        let mut state = FriState::new_empty(4);
        let r0 = state.root();
        state.apply_delta(&[(2, SlotValue::EMPTY)]).unwrap();
        assert_eq!(state.root(), r0);
    }

    #[test]
    fn spending_then_rewriting_restores_root() {
        let mut state = FriState::new_empty(4);
        let seed = sv(9);
        let r0 = state.root();
        state.set_slot(1, seed).unwrap();
        let r1 = state.root();
        state.set_slot(1, SlotValue::EMPTY).unwrap();
        assert_eq!(state.root(), r0);
        state.set_slot(1, seed).unwrap();
        assert_eq!(state.root(), r1);
    }

    #[test]
    fn batch_delta_equals_sequential() {
        let deltas = [(0u32, sv(1)), (5, sv(2)), (10, sv(3))];
        let mut batched = FriState::new_empty(4);
        batched.apply_delta(&deltas).unwrap();

        let mut seq = FriState::new_empty(4);
        for (i, v) in deltas {
            seq.set_slot(i, v).unwrap();
        }
        assert_eq!(batched.root(), seq.root());
    }

    #[test]
    fn out_of_range_errors() {
        let mut state = FriState::new_empty(2); // 4 slots
        assert_eq!(
            state.apply_delta(&[(4, sv(1))]),
            Err(StateError::SlotOutOfRange)
        );
    }

    #[test]
    fn open_then_verify_round_trip() {
        let mut state = FriState::new_empty(4);
        let v = sv(123);
        state.set_slot(5, v).unwrap();
        let root = state.root();
        let op = state.open(5).expect("open");
        let got = verify_opening(&root, &op).expect("verify");
        assert_eq!(got, v);
    }

    #[test]
    fn open_empty_slot_verifies_as_empty() {
        let mut state = FriState::new_empty(4);
        let root = state.root();
        let op = state.open(2).expect("open");
        let got = verify_opening(&root, &op).expect("verify");
        assert_eq!(got, SlotValue::EMPTY);
    }

    #[test]
    fn tampered_opening_fails_verify() {
        let mut state = FriState::new_empty(4);
        state.set_slot(1, sv(1)).unwrap();
        let root = state.root();
        let mut op = state.open(1).expect("open");
        // Tamper with the first slot_val — proof should no longer match.
        op.slot_vals[0] += Block128::ONE;
        assert_eq!(verify_opening(&root, &op), Err(StateError::OpeningFailed));
    }

    #[test]
    fn opening_against_wrong_root_fails() {
        let mut state = FriState::new_empty(4);
        state.set_slot(0, sv(7)).unwrap();
        let op = state.open(0).expect("open");
        let bad_root = [0xAAu8; 32];
        assert_eq!(
            verify_opening(&bad_root, &op),
            Err(StateError::OpeningFailed)
        );
    }

    #[test]
    fn open_batch_matches_individual_opens() {
        let mut state = FriState::new_empty(4);
        state.set_slot(0, sv(1)).unwrap();
        state.set_slot(3, sv(2)).unwrap();
        let root = state.root();
        let batch = state.open_batch(&[0, 3, 7]).unwrap();
        assert_eq!(batch.len(), 3);
        for op in &batch {
            verify_opening(&root, op).expect("batch verify");
        }
    }

    #[test]
    fn open_out_of_range_errors() {
        let state = FriState::new_empty(2); // 4 slots
        assert!(matches!(state.open(4), Err(StateError::SlotOutOfRange)));
    }

    #[test]
    fn slot_reads_back_what_was_written() {
        let mut state = FriState::new_empty(3);
        let v = sv(777);
        state.set_slot(6, v).unwrap();
        assert_eq!(state.slot(6), v);
        assert_eq!(state.slot(0), SlotValue::EMPTY);
    }
}
