// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! FRI-committed UTXO state.
//!
//! The chain state is a vector of `2^log_slots` UTXO slots. Each slot is
//! a `SlotValue { value, owner_hi, owner_lo }` tuple. The commitment is
//! a Poseidon2b sponge over three independent FRI Merkle roots — one
//! per slot-column — keyed by `TAG_FRISTATE` capacity IV with `log_slots`
//! absorbed first. Unused / spent slots carry `SlotValue::EMPTY` (all
//! zeros). Poseidon2b (not Blake3) was chosen so that the in-circuit
//! Stage 4c.3 combiner AIR reuses the already-arithmetised
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

use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::channel::Channel;
use noid_fri::hasher::Blake3Hasher;
use noid_fri::prover::{
    commit_fast as fri_commit_fast, prove as fri_prove, EvalProof, FriCommitment,
};
use noid_fri::verifier::verify as fri_verify;
use noid_poseidon2b::native::{capacity_iv, Poseidon2bSponge, TAG_FRISTATE};

/// Genesis `log_slots` for mainnet: 16 777 216 slots at block 0. Not
/// a circuit-wide constant — the AIR and STARK transcript are
/// parameterised by the header-declared `log_slots` (Stage E.6, see
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

/// A per-column FRI opening for a single slot.
///
/// `commitment.vector_commitment.root` re-derives the column's FRI root
/// that also feeds into the combined `StateRoot`; the verifier checks
/// that the claimed `value` is the evaluation of the committed MLE at
/// the slot-index bit-decomposition, and that the combined
/// `StateRoot` matches.
#[derive(Debug, Clone)]
pub struct SlotColumnOpening {
    pub commitment: FriCommitment,
    pub value: Block128,
    pub proof: EvalProof,
}

/// A batched opening of a single slot across the three state columns.
#[derive(Debug, Clone)]
pub struct SlotOpening {
    pub slot_index: u32,
    pub log_slots: usize,
    pub values: SlotColumnOpening,
    pub owners_hi: SlotColumnOpening,
    pub owners_lo: SlotColumnOpening,
}

impl SlotOpening {
    /// Reconstruct the `SlotValue` that the opening claims.
    pub fn slot(&self) -> SlotValue {
        SlotValue {
            value: self.values.value,
            owner_hi: self.owners_hi.value,
            owner_lo: self.owners_lo.value,
        }
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

    /// Compute (or return cached) state root. The root is
    ///
    /// ```text
    /// Poseidon2bSponge::with_iv(capacity_iv(TAG_FRISTATE))
    ///     .absorb( log_slots (LE u32, zero-padded to 32 bytes) )
    ///     .absorb( fri_root(values) )
    ///     .absorb( fri_root(owners_hi) )
    ///     .absorb( fri_root(owners_lo) )
    ///     .finalize()
    /// ```
    ///
    /// Each column root is the FRI Merkle commitment of the column's
    /// MLE evaluation vector over the hypercube — the same object the
    /// transaction AIR will open (via sumcheck) during Stage 3.
    pub fn root(&mut self) -> StateRoot {
        if let Some(r) = self.cached_root {
            return r;
        }
        let r = combined_root(
            self.log_slots,
            &self.values,
            &self.owners_hi,
            &self.owners_lo,
        );
        self.cached_root = Some(r);
        r
    }

    /// Consume `self` and return the three raw columns. Useful for the
    /// Stage 3 witness builder that needs the whole evaluation vector.
    pub fn into_columns(self) -> (Vec<Block128>, Vec<Block128>, Vec<Block128>) {
        (self.values, self.owners_hi, self.owners_lo)
    }

    /// Borrow the three columns without taking ownership.
    pub fn columns(&self) -> (&[Block128], &[Block128], &[Block128]) {
        (&self.values, &self.owners_hi, &self.owners_lo)
    }

    /// Open a single slot. Produces a per-column FRI opening for each of
    /// the three state columns, all at the same evaluation point
    /// `eval_point_for_index(idx, log_slots)`.
    pub fn open(&self, idx: u32) -> Result<SlotOpening, StateError> {
        if (idx as u64) >= self.num_slots() {
            return Err(StateError::SlotOutOfRange);
        }
        let point = eval_point_for_index(idx, self.log_slots);
        let values = open_column(self.log_slots, &self.values, &point);
        let owners_hi = open_column(self.log_slots, &self.owners_hi, &point);
        let owners_lo = open_column(self.log_slots, &self.owners_lo, &point);
        Ok(SlotOpening {
            slot_index: idx,
            log_slots: self.log_slots,
            values,
            owners_hi,
            owners_lo,
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

fn open_column(log_slots: usize, evals: &[Block128], point: &[Block128]) -> SlotColumnOpening {
    let ntt = AdditiveNTT::<Block128>::new(log_slots + noid_fri::code::LOG_RATE);
    let hasher = Blake3Hasher::new();
    let commitment = fri_commit_fast(evals, &ntt);
    let mut ch = Channel::new();
    ch.observe_fri_commitment(&commitment);
    let proof = fri_prove(evals, point, &ntt, &mut ch, &hasher);
    let value = mle_eval_native(evals, point);
    SlotColumnOpening {
        commitment,
        value,
        proof,
    }
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

/// Verify a single-slot opening against a claimed `StateRoot`. The
/// verifier re-derives the combined root from the per-column FRI roots
/// inside the opening and checks every column's FRI proof.
pub fn verify_opening(state_root: &StateRoot, op: &SlotOpening) -> Result<SlotValue, StateError> {
    if (op.slot_index as u64) >= (1u64 << op.log_slots) {
        return Err(StateError::SlotOutOfRange);
    }
    let point = eval_point_for_index(op.slot_index, op.log_slots);
    for col in [&op.values, &op.owners_hi, &op.owners_lo] {
        if col.commitment.log_len != op.log_slots {
            return Err(StateError::OpeningFailed);
        }
        let ntt = AdditiveNTT::<Block128>::new(op.log_slots + noid_fri::code::LOG_RATE);
        let hasher = Blake3Hasher::new();
        let mut ch = Channel::new();
        ch.observe_fri_commitment(&col.commitment);
        fri_verify(&point, col.value, col.proof.clone(), &ntt, &mut ch, &hasher)
            .map_err(|_| StateError::OpeningFailed)?;
    }

    let combined: StateRoot = combine_roots(
        op.log_slots,
        &op.values.commitment.vector_commitment.root,
        &op.owners_hi.commitment.vector_commitment.root,
        &op.owners_lo.commitment.vector_commitment.root,
    );
    if combined != *state_root {
        return Err(StateError::OpeningFailed);
    }
    Ok(op.slot())
}

// ---------------------------------------------------------------------------
// Root computation
// ---------------------------------------------------------------------------

fn column_root(log_slots: usize, evals: &[Block128]) -> [u8; 32] {
    debug_assert_eq!(evals.len(), 1usize << log_slots);
    let ntt = AdditiveNTT::<Block128>::new(log_slots + noid_fri::code::LOG_RATE);
    let commitment = fri_commit_fast(evals, &ntt);
    commitment.vector_commitment.root
}

/// Domain-separated Poseidon2b sponge over `log_slots` and the three
/// per-lane FRI roots. Matches the in-circuit Stage 4c.3 combiner AIR
/// (`noid_air::airs::fri_state_combiner`): both absorb the same
/// `log_slots ‖ r_val ‖ r_hi ‖ r_lo` preimage under `TAG_FRISTATE` and
/// must yield bit-identical 32-byte digests.
pub fn combine_roots(
    log_slots: usize,
    r_val: &[u8; 32],
    r_hi: &[u8; 32],
    r_lo: &[u8; 32],
) -> StateRoot {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_FRISTATE));
    let mut depth = [0u8; 32];
    depth[..4].copy_from_slice(&(log_slots as u32).to_le_bytes());
    sponge.update(&depth);
    sponge.update(r_val);
    sponge.update(r_hi);
    sponge.update(r_lo);
    sponge.finalize()
}

fn combined_root(
    log_slots: usize,
    values: &[Block128],
    owners_hi: &[Block128],
    owners_lo: &[Block128],
) -> StateRoot {
    let r_val = column_root(log_slots, values);
    let r_hi = column_root(log_slots, owners_hi);
    let r_lo = column_root(log_slots, owners_lo);
    combine_roots(log_slots, &r_val, &r_hi, &r_lo)
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
        op.values.value = op.values.value + Block128::ONE;
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

    // ------------------------------------------------------------------
    // Stage 4 closure — native `combine_roots` <-> AIR combiner identity.
    //
    // Closes the `{prev,new}_state_root` arrow: the 32-byte digest
    // `combine_roots` produces for a given preimage (log_slots, three
    // FRI roots) is bit-identical to the digest the Stage 4c.3 combiner
    // AIR pins as `expected_state_root_fields`. Any drift between the
    // native root-computation path and the arithmetised sponge would
    // desync `PublicInputs.{prev,new}_state_root` between prover and
    // node — this test is the fixed point that catches it.
    // ------------------------------------------------------------------
    #[test]
    fn combine_roots_matches_stage_4c3_combiner_air() {
        use noid_air::airs::{
            build_combiner_side_trace, extract_combiner_digest, FriStateCombinerComposite,
            FriStateCombinerPreimage, COMBINER_PERM_LAYOUT,
        };

        // Two distinct preimages — one stands in for `prev`, one for
        // `new`. Bytes are arbitrary but deterministic.
        let mk = |seed: u8| FriStateCombinerPreimage {
            log_slots: 24,
            r_val: std::array::from_fn(|i| seed ^ (i as u8)),
            r_owner_hi: std::array::from_fn(|i| {
                seed.wrapping_add(0x11) ^ (i as u8).wrapping_mul(3)
            }),
            r_owner_lo: std::array::from_fn(|i| {
                seed.wrapping_add(0x22) ^ (i as u8).wrapping_mul(5)
            }),
        };

        let prev = mk(0x11);
        let new = mk(0x77);

        // Native digest through `combine_roots`.
        let native_prev = combine_roots(
            prev.log_slots as usize,
            &prev.r_val,
            &prev.r_owner_hi,
            &prev.r_owner_lo,
        );
        let native_new = combine_roots(
            new.log_slots as usize,
            &new.r_val,
            &new.r_owner_hi,
            &new.r_owner_lo,
        );

        // Digest extracted from an honest AIR trace.
        let air_prev =
            extract_combiner_digest(&build_combiner_side_trace(&prev), COMBINER_PERM_LAYOUT);
        let air_new =
            extract_combiner_digest(&build_combiner_side_trace(&new), COMBINER_PERM_LAYOUT);

        assert_eq!(
            native_prev, air_prev,
            "Stage 4c.3 combiner AIR diverged from native combine_roots on prev side"
        );
        assert_eq!(
            native_new, air_new,
            "Stage 4c.3 combiner AIR diverged from native combine_roots on new side"
        );

        // The same digests, split into the two 16-byte little-endian
        // field lanes, are what the composite pins as public inputs;
        // the honest trace must accept.
        let to_fields = |d: &[u8; 32]| -> [Block128; 2] {
            let mut lo = [0u8; 16];
            let mut hi = [0u8; 16];
            lo.copy_from_slice(&d[..16]);
            hi.copy_from_slice(&d[16..]);
            [
                Block128::from(u128::from_le_bytes(lo)),
                Block128::from(u128::from_le_bytes(hi)),
            ]
        };

        let composite = FriStateCombinerComposite::new(
            prev,
            to_fields(&native_prev),
            new,
            to_fields(&native_new),
        );
        let trace = composite.build_trace();
        assert!(
            <FriStateCombinerComposite as noid_air::Air>::check(&composite, &trace),
            "composite must accept the honest trace under native-derived expected fields"
        );
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
