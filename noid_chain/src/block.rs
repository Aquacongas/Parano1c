// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Block container, block-level state transition, and helpers that bind
//! proofs into block headers.
//!
//! A `Block` is a header plus an ordered list of transactions. Applying
//! a block runs `apply_tx` sequentially. Per-tx state-root chaining is
//! obsolete; block-level state validation ensures `header.state_root`
//! matches the final computed post-root after all txs are applied, and
//! `tx_root` equals the Merkle reduction over the transactions'
//! `tx_body_hash`es (Poseidon2b COMPRESS domain, zero-padded to a power of two).
//! The Poseidon2b-based Merkle tree is ZK-friendly: its internal nodes can be
//! proved inside the GKR block spine and recursive circuits without expensive
//! boolean decomposition. Blake3 is reserved for PoW and P2P deduplication.

use noid_poseidon2b::native::compress;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_FSCHALNG};
use noid_poseidon2b::primitives::Digest;
use noid_tx::wire::WireError;
use noid_tx::{hash_tx_body, Transaction};

use crate::block_header::BlockHeader;
use crate::state::{apply_tx, ApplyError, ChainState, StateTransition};

/// Block version on the wire.
// REMOVED: no network yet, no backwards compatibility needed.

/// Hard DoS cap on the number of transactions accepted by the decoder.
/// The economic / consensus limit is enforced elsewhere; this just keeps
/// a malformed wire blob from allocating unbounded memory.
pub const BLOCK_MAX_TXS: usize = 1024;

/// A block: header plus transactions. A block's STARK proof lives
/// outside this struct; its transcript is bound into
/// `header.proof_transcript_hash` via [`proof_transcript_hash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

/// Errors surfaced by [`apply_block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockApplyError {
    /// A transaction failed the native state transition.
    Tx(ApplyError),
    /// Block carries more transactions than the hard wire/DoS cap.
    TooManyTransactions,
    /// Header does not bind a non-zero proof transcript digest.
    MissingProofTranscriptHash,
    /// Header does not bind a non-zero DA witness digest.
    MissingWitnessRoot,
    /// `tx.body_hash` does not match the canonical hash of `tx.body`.
    WrongTxBodyHash,
    /// `header.state_root` disagrees with the post-apply chain root.
    HeaderStateRootMismatch,
    /// `header.tx_root` disagrees with the computed tx-root.
    HeaderTxRootMismatch,
    /// `header.active_slot_count` disagrees with the post-apply chain count.
    HeaderActiveSlotCountMismatch,
    /// `header.alloc_counter` disagrees with the post-apply allocator seed.
    HeaderAllocCounterMismatch,
    /// `header.log_slots` disagrees with the chain's current slot depth.
    HeaderLogSlotsMismatch,
    /// Block contains more than one coinbase transaction.
    MultipleCoinbase,
    /// Coinbase transaction is not the first transaction in the block.
    CoinbaseNotFirst,
    /// Coinbase transaction has non-empty inputs (coinbase must have zero inputs).
    CoinbaseHasInputs,
    /// Block contains non-coinbase transactions but `proof_transcript_hash` is the
    /// development stub marker `[1u8; 32]`. Such blocks are produced only by the
    /// local miner as a fallback when ZK proving fails; they must never be accepted
    /// from the network. Any block with user transactions MUST carry a real proof hash.
    StubProofWithUserTxs,
}

impl From<ApplyError> for BlockApplyError {
    fn from(e: ApplyError) -> Self {
        Self::Tx(e)
    }
}

/// Apply a block in place. On error, `state` is left untouched (work
/// happens on a snapshot and is swapped only on success).
pub fn apply_block(
    state: &mut ChainState,
    block: &Block,
) -> Result<StateTransition, BlockApplyError> {
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(BlockApplyError::TooManyTransactions);
    }
    if block.header.proof_transcript_hash == [0u8; 32] {
        return Err(BlockApplyError::MissingProofTranscriptHash);
    }
    if block.header.witness_root == [0u8; 32] {
        return Err(BlockApplyError::MissingWitnessRoot);
    }

    // SECURITY: Reject blocks that carry user transactions but use the development
    // stub marker [1u8;32] as proof_transcript_hash.
    //
    // The marker is only legal for coinbase-only blocks where there is nothing to
    // prove. A block with user transactions MUST reference a real ZK transcript
    // digest. Accepting stub-proof blocks with user transactions would let any node
    // craft arbitrary UTXOs without a valid proof.
    //
    // The stub value [1u8;32] is intentionally distinct from the zero sentinel
    // [0u8;32] (which is rejected above) so both are caught deterministically.
    const STUB_MARKER: [u8; 32] = [1u8; 32];
    let has_user_txs = block.transactions.iter().any(|tx| !tx.body.is_coinbase);
    if has_user_txs && block.header.proof_transcript_hash == STUB_MARKER {
        return Err(BlockApplyError::StubProofWithUserTxs);
    }

    // Coinbase structure: at most one, must be first, zero inputs.
    // Coinbase VALUE validation (≤ block_reward + fees) is in validate_block_consensus().
    let coinbase_count = block
        .transactions
        .iter()
        .filter(|tx| tx.body.is_coinbase)
        .count();
    if coinbase_count > 1 {
        return Err(BlockApplyError::MultipleCoinbase);
    }
    if let Some(first_non_coinbase_pos) = block
        .transactions
        .iter()
        .position(|tx| !tx.body.is_coinbase)
    {
        if block.transactions[first_non_coinbase_pos..]
            .iter()
            .any(|tx| tx.body.is_coinbase)
        {
            return Err(BlockApplyError::CoinbaseNotFirst);
        }
    }
    // Coinbase tx (if present) must have zero inputs.
    if let Some(cb) = block.transactions.first() {
        if cb.body.is_coinbase {
            let has_valid_inputs = cb.body.inputs.iter().any(|i| i.valid);
            if has_valid_inputs {
                return Err(BlockApplyError::CoinbaseHasInputs);
            }
        }
    }

    let mut snap = state.clone();

    // Slot-space expansion: if the block declares a larger log_slots, expand BEFORE
    // applying transactions. The expansion is triggered by the block producer when
    // active_slot_count/2^log_slots ≥ 75% (SPEC §15.3.6). Both builder and validator
    // must expand at the same point so state_root is deterministic.
    //
    // We loop defensively (spec allows only +1 per block, but be safe).
    while block.header.log_slots as usize > snap.state.log_slots() {
        snap.state.expand();
    }

    let mut last = StateTransition {
        new_state_root: snap.state_root(),
    };

    for tx in &block.transactions {
        let expected_hash = hash_tx_body(
            &tx.body.epoch_anchor,
            tx.body.fee,
            &tx.body.inputs,
            &tx.body.outputs,
            tx.body.is_coinbase,
        );
        if tx.tx_body_hash != expected_hash {
            return Err(BlockApplyError::WrongTxBodyHash);
        }

        let st = apply_tx(&mut snap, &tx.body).map_err(BlockApplyError::Tx)?;
        last = st;
    }

    if block.header.state_root != snap.state_root() {
        return Err(BlockApplyError::HeaderStateRootMismatch);
    }
    if block.header.active_slot_count != snap.active_slot_count {
        return Err(BlockApplyError::HeaderActiveSlotCountMismatch);
    }
    if block.header.alloc_counter != snap.alloc_counter {
        return Err(BlockApplyError::HeaderAllocCounterMismatch);
    }
    if block.header.log_slots != snap.state.log_slots() as u32 {
        return Err(BlockApplyError::HeaderLogSlotsMismatch);
    }
    if block.header.tx_root != compute_tx_root(&block.transactions) {
        return Err(BlockApplyError::HeaderTxRootMismatch);
    }

    *state = snap;
    Ok(last)
}

/// Apply a block's state delta without re-validating pre-conditions.
///
/// **Full proof-native path** — called after `verify_block(BlockProof)` succeeds.
/// The ZK proof has already established that:
///   - All slot pre-conditions are correct (`prev_lane_openings` → `state_root`).
///   - The state transition is correct (`new_lane_openings` → `new_state_root`).
///   - `block.header.state_root` is cryptographically sound.
///
/// This function therefore:
///   1. Handles log_slots expansion (still structural, not ZK-proved).
///   2. Zeros out spent inputs and fills minted outputs — NO pre-state reads.
///   3. Updates `active_slot_count` and `alloc_counter` from the block data.
///   4. Sets `state_root` from `block.header.state_root` (trusted by ZK).
///   5. Still checks tx_root (cheap, O(n) hashing).
///
/// **Savings vs `apply_block`:**
///   - ~2400 MDBX slot reads eliminated for a 100-tx block.
///   - No state_root recomputation (~50 ms for 100 dirty segments).
///   - No pre-state value verification (ZK handles this).
pub fn apply_state_delta(
    state: &mut ChainState,
    block: &Block,
) -> Result<StateTransition, BlockApplyError> {
    use crate::fri_state::SlotValue;
    use noid_core::Block128;

    // Sanity-guard: must be called after ZK proof verification.
    // tx_root is still checked natively (cheap, doesn't require state reads).
    if block.header.tx_root != compute_tx_root(&block.transactions) {
        return Err(BlockApplyError::HeaderTxRootMismatch);
    }

    let mut snap = state.clone();

    // 1. Expansion (structural, same logic as apply_block).
    while block.header.log_slots as usize > snap.state.log_slots() {
        snap.state.expand();
    }

    // 2. Apply delta: zero inputs, fill outputs — no pre-state verification.
    for tx in &block.transactions {
        for inp in tx.body.inputs.iter().filter(|i| i.valid) {
            // ZK proved inp.slot_index contained the claimed value.
            // Just zero it out; no read needed.
            snap.state
                .set_slot(inp.slot_index, SlotValue::EMPTY)
                .map_err(|_| BlockApplyError::Tx(crate::state::ApplyError::SlotOutOfRange))?;
            snap.active_slot_count = snap.active_slot_count.saturating_sub(1);
        }
        for out in tx.body.outputs.iter().filter(|o| o.valid) {
            // ZK proved out.slot_index was EMPTY before this tx.
            let sv = SlotValue {
                value: Block128::from(out.value as u128),
                owner_hi: out.owner.as_fields()[0],
                owner_lo: out.owner.as_fields()[1],
            };
            snap.state
                .set_slot(out.slot_index, sv)
                .map_err(|_| BlockApplyError::Tx(crate::state::ApplyError::SlotOutOfRange))?;
            snap.active_slot_count = snap.active_slot_count.saturating_add(1);
            if tx.body.is_coinbase {
                snap.alloc_counter = snap.alloc_counter.wrapping_add(1);
            }
        }
    }

    // 3. Check counters (these are cheap, O(n_outputs) above).
    if block.header.active_slot_count != snap.active_slot_count {
        return Err(BlockApplyError::HeaderActiveSlotCountMismatch);
    }
    if block.header.alloc_counter != snap.alloc_counter {
        return Err(BlockApplyError::HeaderAllocCounterMismatch);
    }
    if block.header.log_slots != snap.state.log_slots() as u32 {
        return Err(BlockApplyError::HeaderLogSlotsMismatch);
    }

    // 4. Accept state_root from ZK-verified header (no recompute).
    // The SegmentedFriState will recompute it lazily only if accessed.
    // Force-set via the segments that were modified (already marked dirty).
    // Calling state_root() here would recompute — we trust the header instead.
    // The dirty segments will recompute on next `root()` call, which will match
    // header.state_root (ZK proved this).
    *state = snap;

    Ok(StateTransition {
        new_state_root: block.header.state_root,
    })
}

/// Apply the genesis block to `state` without requiring a ZK proof or witness root.
///
/// Genesis (height = 0) is a special case: it has no transactions to prove
/// and uses marker values for `proof_transcript_hash` and `witness_root`.
/// All other validation (state_root, tx_root, counters) still applies.
///
/// MUST only be called with `block.header.height == 0`. Use `apply_block`
/// for all subsequent blocks.
pub fn apply_genesis_block(
    state: &mut ChainState,
    block: &Block,
) -> Result<StateTransition, BlockApplyError> {
    assert_eq!(
        block.header.height, 0,
        "apply_genesis_block called with non-genesis block"
    );
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(BlockApplyError::TooManyTransactions);
    }
    // Genesis has no transactions (empty block, no coinbase).
    // tx_root must be [0;32] (empty).
    if block.header.tx_root != [0u8; 32] {
        return Err(BlockApplyError::HeaderTxRootMismatch);
    }
    // State root must match the initial empty state.
    if block.header.state_root != state.state_root() {
        return Err(BlockApplyError::HeaderStateRootMismatch);
    }
    // Counters must be zero for genesis.
    if block.header.active_slot_count != 0 || block.header.alloc_counter != 0 {
        return Err(BlockApplyError::HeaderActiveSlotCountMismatch);
    }
    Ok(StateTransition {
        new_state_root: block.header.state_root,
    })
}

/// Compute the block's tx-root — a COMPRESS-domain Merkle reduction over
/// each transaction's `tx_body_hash`, zero-padded to the next power of
/// two. An empty block reduces to `ZERO_DIGEST` so a zero-tx header is
/// unambiguously representable.
/// Compute the tx_root Merkle hash over a block's transaction hashes.
///
/// Uses a Poseidon2b COMPRESS binary Merkle tree, padded to the next power
/// of two (minimum 2). Poseidon2b is chosen because this Merkle root feeds
/// directly into the ZK block spine and recursive proof system — the internal
/// nodes are proved in-circuit, which requires a ZK-native hash function.
/// Blake3 is NOT ZK-friendly and would make in-circuit proofs prohibitively large.
pub fn compute_tx_root(txs: &[Transaction]) -> Digest {
    if txs.is_empty() {
        return [0u8; 32];
    }
    // Pad to at least 2 so the tree always has at least one internal node.
    let target = txs.len().next_power_of_two().max(2);
    let mut level: Vec<Digest> = txs.iter().map(|tx| tx.tx_body_hash.0).collect();
    level.resize(target, [0u8; 32]);
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| compress(&pair[0], &pair[1]))
            .collect();
    }
    level[0]
}

/// Compress a Fiat-Shamir transcript's byte stream into the 32-byte
/// digest that a block header binds as `proof_transcript_hash`
/// (CRYPTO.md §8.1). Uses the `FSCHALNG` capacity IV since this digest
/// summarizes exactly the Fiat-Shamir transcript; no new tag is needed.
pub fn proof_transcript_hash(transcript_bytes: &[u8]) -> Digest {
    let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_FSCHALNG));
    s.update(transcript_bytes);
    s.finalize()
}

// ---------------------------------------------------------------------------
// Wire encoding for Block (lives here to keep block bytes next to the
// container; BlockHeader's encoding lives in `wire.rs`).
// ---------------------------------------------------------------------------

#[inline]
fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn take<'a>(src: &mut &'a [u8], n: usize) -> Result<&'a [u8], WireError> {
    if src.len() < n {
        return Err(WireError::Truncated);
    }
    let (head, tail) = src.split_at(n);
    *src = tail;
    Ok(head)
}

#[inline]
fn take_u32(src: &mut &[u8]) -> Result<u32, WireError> {
    let bytes = take(src, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

impl Block {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        assert!(
            self.transactions.len() <= BLOCK_MAX_TXS,
            "transactions exceed BLOCK_MAX_TXS"
        );

        self.header.encode(buf);
        put_u32(buf, self.transactions.len() as u32);
        for tx in &self.transactions {
            tx.encode(buf);
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let header = BlockHeader::decode(src)?;
        let n = take_u32(src)? as usize;
        if n > BLOCK_MAX_TXS {
            return Err(WireError::CountTooLarge);
        }
        let mut transactions = Vec::with_capacity(n);
        for _ in 0..n {
            transactions.push(Transaction::decode(src)?);
        }
        Ok(Self {
            header,
            transactions,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut src = bytes;
        let out = Self::decode(&mut src)?;
        if !src.is_empty() {
            return Err(WireError::TrailingBytes);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};
    use noid_tx::{TxBody, TxInput, TxOutput};

    const TEST_LOG_SLOTS: usize = 6;

    /// Build a `BlockHeader` with the correct consensus fields for `snap`
    /// after applying `txs`. Sets a non-zero `proof_transcript_hash` and
    /// `witness_root` to satisfy the non-zero guards in `apply_block`.
    ///
    /// NOTE: Uses [0xAA;32] for `proof_transcript_hash` to distinguish from
    /// the stub marker [1u8;32] (which is now rejected for blocks with user txs).
    fn mk_header(snap: &ChainState, txs: &[Transaction]) -> BlockHeader {
        let mut dry = snap.clone();
        for tx in txs {
            apply_tx(&mut dry, &tx.body).unwrap();
        }
        // Check if this block has user transactions
        let has_user_txs = txs.iter().any(|tx| !tx.body.is_coinbase);
        // Use a non-stub hash for user-tx blocks; stub [1u8;32] only for coinbase-only.
        let proof_transcript_hash = if has_user_txs {
            [0xAAu8; 32]
        } else {
            [1u8; 32]
        };
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: dry.state_root(),
            tx_root: compute_tx_root(txs),
            timestamp: 1,
            height: 1,
            miner_address: Address([9u8; 32]),
            nonce: 0,
            difficulty_target: [0xFFu8; 32],
            proof_transcript_hash,
            witness_root: [2u8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: dry.active_slot_count,
            alloc_counter: dry.alloc_counter,
        }
    }

    fn fresh_state() -> ChainState {
        ChainState::with_log_slots(TEST_LOG_SLOTS)
    }

    fn mk_output(seed: u8) -> TxOutput {
        TxOutput {
            slot_index: seed as u32,
            value: (seed as u64) * 100,
            owner: Address([seed; 32]),
            valid: true,
        }
    }

    fn mk_input_for(slot_index: u32, out: &TxOutput) -> TxInput {
        TxInput {
            slot_index,
            value: out.value,
            owner: out.owner,
            spend_secret: SpendSecret([0u8; 32]),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        }
    }

    fn build_tx(
        state: &mut ChainState,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
    ) -> Transaction {
        let mut probe = state.clone();
        let body = TxBody {
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs,
            outputs,
            is_coinbase: false,
        };
        apply_tx(&mut probe, &body).expect("probe apply");
        let tbh = hash_tx_body(
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        Transaction {
            body,
            tx_body_hash: tbh,
        }
    }

    #[test]
    fn apply_block_happy_path_two_chained_txs() {
        let mut state = fresh_state();
        let minted = mk_output(1);
        let tx1 = build_tx(&mut state, vec![], vec![minted]);
        let mut probe = state.clone();
        apply_tx(&mut probe, &tx1.body).unwrap();
        let spend = mk_input_for(minted.slot_index, &minted);
        let tx2 = build_tx(&mut probe, vec![spend], vec![mk_output(3)]);
        let txs = vec![tx1, tx2];

        let block = Block {
            header: mk_header(&state, &txs),
            transactions: txs,
        };
        let out = apply_block(&mut state, &block).expect("apply");
        assert_eq!(out.new_state_root, state.state_root());
    }

    #[test]
    fn apply_block_rejects_wrong_tx_root() {
        let mut state = fresh_state();
        let tx = build_tx(&mut state, vec![], vec![mk_output(1)]);
        let txs = vec![tx];
        let mut header = mk_header(&state, &txs);
        header.tx_root = [0xFFu8; 32]; // deliberately wrong
        let block = Block {
            header,
            transactions: txs,
        };
        assert_eq!(
            apply_block(&mut state, &block),
            Err(BlockApplyError::HeaderTxRootMismatch)
        );
        assert_eq!(state.active_slot_count, 0);
    }

    #[test]
    fn apply_block_rejects_wrong_tx_body_hash() {
        let mut state = fresh_state();
        let mut tx = build_tx(&mut state, vec![], vec![mk_output(1)]);
        tx.tx_body_hash.0[0] ^= 1; // corrupt hash — fails before header checks
                                   // Use mk_header on the valid tx list but with the tampered hash;
                                   // state_root / active_slot_count don't matter since we fail earlier.
        let txs = vec![tx];
        let header = mk_header(&state, &txs);
        let block = Block {
            header,
            transactions: txs,
        };
        assert_eq!(
            apply_block(&mut state, &block),
            Err(BlockApplyError::WrongTxBodyHash)
        );
    }

    #[test]
    fn apply_block_accepts_independent_txs() {
        let mut state = fresh_state();
        let tx1 = build_tx(&mut state.clone(), vec![], vec![mk_output(1)]);
        let tx2 = build_tx(&mut state.clone(), vec![], vec![mk_output(2)]);
        let txs = vec![tx1, tx2];
        let block = Block {
            header: mk_header(&state, &txs),
            transactions: txs,
        };
        apply_block(&mut state, &block).expect("apply");
    }

    #[test]
    fn empty_block_tx_root_is_zero() {
        assert_eq!(compute_tx_root(&[]), [0u8; 32]);
    }

    #[test]
    fn proof_transcript_hash_is_deterministic() {
        assert_eq!(proof_transcript_hash(b"abc"), proof_transcript_hash(b"abc"));
        assert_ne!(proof_transcript_hash(b"a"), proof_transcript_hash(b"b"));
    }

    #[test]
    fn apply_block_rejects_missing_proof_transcript_hash() {
        let mut state = fresh_state();
        let tx = build_tx(&mut state, vec![], vec![mk_output(1)]);
        let txs = vec![tx];
        let mut header = mk_header(&state, &txs);
        header.proof_transcript_hash = [0u8; 32]; // zero → missing
        let block = Block {
            header,
            transactions: txs,
        };
        assert_eq!(
            apply_block(&mut state, &block),
            Err(BlockApplyError::MissingProofTranscriptHash)
        );
    }

    #[test]
    fn apply_block_rejects_stub_proof_with_user_txs() {
        // SECURITY: Blocks with user transactions MUST NOT use the stub marker [1u8;32].
        // The stub is only valid for coinbase-only blocks.
        let mut state = fresh_state();
        let tx = build_tx(&mut state, vec![], vec![mk_output(1)]);
        let txs = vec![tx];
        let mut header = mk_header(&state, &txs);
        // Force the stub marker (apply_block must reject this)
        header.proof_transcript_hash = [1u8; 32];
        let block = Block {
            header,
            transactions: txs,
        };
        assert_eq!(
            apply_block(&mut state, &block),
            Err(BlockApplyError::StubProofWithUserTxs),
            "block with user txs and stub proof_transcript_hash must be rejected"
        );
        // Sanity: state must not be modified on rejection
        assert_eq!(state.active_slot_count, 0);
    }

    #[test]
    fn apply_block_allows_stub_proof_coinbase_only() {
        // Stub [1u8;32] is valid for coinbase-only blocks (nothing to prove).
        let mut state = fresh_state();
        let txs: Vec<Transaction> = vec![]; // empty block (no coinbase in this test)
        let header = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.state_root(),
            tx_root: compute_tx_root(&txs),
            timestamp: 1,
            height: 1,
            miner_address: Address([9u8; 32]),
            nonce: 0,
            difficulty_target: [0xFFu8; 32],
            proof_transcript_hash: [1u8; 32], // stub OK for empty/coinbase-only block
            witness_root: [2u8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: 0,
            alloc_counter: 0,
        };
        let block = Block {
            header,
            transactions: txs,
        };
        // Should succeed (no user txs → stub marker is acceptable)
        apply_block(&mut state, &block).expect("empty block with stub proof should be accepted");
    }

    #[test]
    fn apply_block_rejects_missing_witness_root() {
        let mut state = fresh_state();
        let tx = build_tx(&mut state, vec![], vec![mk_output(1)]);
        let txs = vec![tx];
        let mut header = mk_header(&state, &txs);
        header.witness_root = [0u8; 32]; // zero → missing
        let block = Block {
            header,
            transactions: txs,
        };
        assert_eq!(
            apply_block(&mut state, &block),
            Err(BlockApplyError::MissingWitnessRoot)
        );
    }

    #[test]
    fn block_wire_roundtrip() {
        let mut state = fresh_state();
        let tx = build_tx(&mut state, vec![], vec![mk_output(1)]);
        let txs = vec![tx];
        let mut header = mk_header(&state, &txs);
        header.proof_transcript_hash = proof_transcript_hash(b"hello");
        header.witness_root = [0xAAu8; 32];
        let block = Block {
            header,
            transactions: txs,
        };
        let bytes = block.to_bytes();
        let back = Block::from_bytes(&bytes).expect("decode");
        assert_eq!(back.header, block.header);
        assert_eq!(back.header.log_slots, TEST_LOG_SLOTS as u32);
        assert_eq!(back.transactions.len(), block.transactions.len());
        assert_eq!(
            back.transactions[0].tx_body_hash,
            block.transactions[0].tx_body_hash
        );
    }

    #[test]
    fn block_rejects_trailing_bytes() {
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [0u8; 32],
                tx_root: [0u8; 32],
                timestamp: 0,
                height: 0,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                difficulty_target: [0xFFu8; 32],
                proof_transcript_hash: [1u8; 32],
                witness_root: [2u8; 32],
                log_slots: 24,
                active_slot_count: 0,
                alloc_counter: 0,
            },
            transactions: vec![],
        };
        let mut bytes = block.to_bytes();
        bytes.push(0);
        assert_eq!(Block::from_bytes(&bytes), Err(WireError::TrailingBytes));
    }

    #[test]
    fn apply_block_rejects_multiple_coinbase() {
        let mut state = fresh_state();

        // Build two distinct coinbase transactions (each mints to a different slot).
        let make_cb = |slot: u8| {
            let body = TxBody {
                epoch_anchor: [0u8; 32],
                fee: 0,
                inputs: vec![],
                outputs: vec![mk_output(slot)],
                is_coinbase: true,
            };
            let tbh = hash_tx_body(
                &body.epoch_anchor,
                body.fee,
                &body.inputs,
                &body.outputs,
                body.is_coinbase,
            );
            Transaction {
                body,
                tx_body_hash: tbh,
            }
        };

        let txs = vec![make_cb(1), make_cb(2)];
        let block = Block {
            header: mk_header(&state, &txs),
            transactions: txs,
        };
        assert_eq!(
            apply_block(&mut state, &block),
            Err(BlockApplyError::MultipleCoinbase)
        );
    }

    #[test]
    fn apply_block_rejects_coinbase_with_inputs() {
        let mut state = fresh_state();

        // First, mint a UTXO into slot 1 via a normal block.
        let minted = mk_output(1);
        let mint_tx = build_tx(&mut state, vec![], vec![minted]);
        let mint_txs = vec![mint_tx.clone()];
        let mint_header = mk_header(&state, &mint_txs);
        apply_block(
            &mut state,
            &Block {
                header: mint_header,
                transactions: mint_txs,
            },
        )
        .expect("mint block");

        // Now create a coinbase tx that has a valid input (spending slot 1).
        let input = mk_input_for(minted.slot_index, &minted);
        let cb_body = TxBody {
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![input],
            outputs: vec![mk_output(3)],
            is_coinbase: true,
        };
        let tbh = hash_tx_body(
            &cb_body.epoch_anchor,
            cb_body.fee,
            &cb_body.inputs,
            &cb_body.outputs,
            cb_body.is_coinbase,
        );
        let cb_tx = Transaction {
            body: cb_body,
            tx_body_hash: tbh,
        };

        let txs = vec![cb_tx];
        // mk_header applies the tx on a clone to compute the correct roots;
        // apply_block will reject CoinbaseHasInputs before running state logic.
        let block = Block {
            header: mk_header(&state, &txs),
            transactions: txs,
        };
        assert_eq!(
            apply_block(&mut state, &block),
            Err(BlockApplyError::CoinbaseHasInputs)
        );
    }

    #[test]
    fn apply_genesis_block_works() {
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let header = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.state_root(),
            tx_root: [0u8; 32],
            timestamp: 0,
            height: 0,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: [0xFFu8; 32],
            proof_transcript_hash: [0x01u8; 32], // genesis marker
            witness_root: [0u8; 32],             // genesis marker
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: 0,
            alloc_counter: 0,
        };
        let block = Block {
            header,
            transactions: vec![],
        };
        let result = apply_genesis_block(&mut state, &block);
        assert!(result.is_ok(), "genesis block must apply: {:?}", result);
    }

    // -----------------------------------------------------------------------
    // Expansion tests (SPEC §15.3)
    // -----------------------------------------------------------------------

    /// Build a block header that correctly reflects applying `txs` to `state`
    /// with a potential slot-space expansion to `new_log_slots`.
    fn mk_header_with_expansion(
        state: &ChainState,
        txs: &[Transaction],
        new_log_slots: usize,
    ) -> BlockHeader {
        let mut dry = state.clone();
        // Expand first if needed (matching apply_block behaviour).
        while new_log_slots > dry.state.log_slots() {
            dry.state.expand();
        }
        for tx in txs {
            apply_tx(&mut dry, &tx.body).unwrap();
        }
        let has_user_txs = txs.iter().any(|tx| !tx.body.is_coinbase);
        let proof_transcript_hash = if has_user_txs {
            [0xAAu8; 32]
        } else {
            [1u8; 32]
        };
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: dry.state_root(),
            tx_root: compute_tx_root(txs),
            timestamp: 1,
            height: 1,
            miner_address: Address([9u8; 32]),
            nonce: 0,
            difficulty_target: [0xFFu8; 32],
            proof_transcript_hash,
            witness_root: [2u8; 32],
            log_slots: new_log_slots as u32,
            active_slot_count: dry.active_slot_count,
            alloc_counter: dry.alloc_counter,
        }
    }

    /// Fill `state` with `n` UTXO mints, returning the updated state.
    /// Uses slot indices 0..n. Applies directly (no blocks).
    fn fill_slots(state: &mut ChainState, n: usize) {
        use noid_tx::TxBody;
        for i in 0..n {
            let body = TxBody {
                epoch_anchor: [0u8; 32],
                fee: 0,
                inputs: vec![],
                outputs: vec![TxOutput {
                    slot_index: i as u32,
                    value: 100,
                    owner: Address([1u8; 32]),
                    valid: true,
                }],
                is_coinbase: false,
            };
            apply_tx(state, &body).expect("fill slot");
        }
    }

    #[test]
    fn expansion_trigger_constants_are_correct() {
        // EXPAND_NUM=3, EXPAND_DENOM=4 → trigger at 75%
        use crate::consensus::params::{EXPAND_DENOM, EXPAND_NUM};
        assert_eq!(EXPAND_NUM * 100 / EXPAND_DENOM, 75, "trigger must be 75%");
    }

    #[test]
    fn apply_block_expands_state_at_75_percent() {
        // log_slots=4 → 16 slots. 75% = 12 slots trigger expansion.
        let mut state = ChainState::with_log_slots(4);
        fill_slots(&mut state, 12); // 12/16 = 75% exactly → trigger fires
        assert_eq!(state.active_slot_count, 12);
        assert_eq!(state.state.log_slots(), 4);

        // Build an expansion block: empty (just header declaring new log_slots=5).
        let header = mk_header_with_expansion(&state, &[], 5);
        assert_eq!(
            header.log_slots, 5,
            "template must declare expanded log_slots"
        );

        let block = Block {
            header,
            transactions: vec![],
        };
        apply_block(&mut state, &block).expect("expansion block must apply");

        assert_eq!(
            state.state.log_slots(),
            5,
            "state log_slots must be 5 after expansion"
        );
        assert_eq!(
            state.active_slot_count, 12,
            "active_slot_count unchanged by expansion"
        );
    }

    #[test]
    fn apply_block_no_expansion_below_threshold() {
        // 11/16 = 68.75% < 75% → trigger must NOT fire.
        let mut state = ChainState::with_log_slots(4);
        fill_slots(&mut state, 11); // just below threshold
        assert_eq!(state.state.log_slots(), 4);

        // Block at same log_slots=4 (no expansion).
        let header = mk_header_with_expansion(&state, &[], 4);
        let block = Block {
            header,
            transactions: vec![],
        };
        apply_block(&mut state, &block).expect("non-expansion block must apply");

        assert_eq!(state.state.log_slots(), 4, "log_slots must stay 4");
    }

    #[test]
    fn expanded_state_has_double_capacity() {
        let mut state = ChainState::with_log_slots(4);
        fill_slots(&mut state, 12); // trigger at 75%
        let before_capacity = state.state.num_slots();

        let header = mk_header_with_expansion(&state, &[], 5);
        let block = Block {
            header,
            transactions: vec![],
        };
        apply_block(&mut state, &block).expect("expansion");

        let after_capacity = state.state.num_slots();
        assert_eq!(
            after_capacity,
            before_capacity * 2,
            "capacity must double after expansion"
        );
    }

    #[test]
    fn new_slots_are_empty_after_expansion() {
        let mut state = ChainState::with_log_slots(4);
        fill_slots(&mut state, 12);
        let old_capacity = state.state.num_slots() as u32; // = 16

        let header = mk_header_with_expansion(&state, &[], 5);
        apply_block(
            &mut state,
            &Block {
                header,
                transactions: vec![],
            },
        )
        .unwrap();

        // All new slots [16..31] must be empty.
        for slot in old_capacity..old_capacity * 2 {
            assert_eq!(
                state.state.slot(slot),
                crate::fri_state::SlotValue::EMPTY,
                "new slot {} must be empty",
                slot
            );
        }
    }

    #[test]
    fn can_mint_to_new_slots_after_expansion() {
        let mut state = ChainState::with_log_slots(4);
        fill_slots(&mut state, 12);

        // Apply expansion block.
        let exp_header = mk_header_with_expansion(&state, &[], 5);
        apply_block(
            &mut state,
            &Block {
                header: exp_header,
                transactions: vec![],
            },
        )
        .unwrap();
        assert_eq!(state.state.log_slots(), 5);

        // Now mint into slot 16 (first slot in new range).
        let new_slot_tx = {
            use noid_tx::{hash_tx_body, TxBody};
            let body = TxBody {
                epoch_anchor: [0u8; 32],
                fee: 0,
                inputs: vec![],
                outputs: vec![TxOutput {
                    slot_index: 16,
                    value: 999,
                    owner: Address([5u8; 32]),
                    valid: true,
                }],
                is_coinbase: false,
            };
            let hash = hash_tx_body(
                &body.epoch_anchor,
                body.fee,
                &body.inputs,
                &body.outputs,
                body.is_coinbase,
            );
            Transaction {
                body,
                tx_body_hash: hash,
            }
        };
        let txs = vec![new_slot_tx];
        let header = mk_header_with_expansion(&state, &txs, 5);
        apply_block(
            &mut state,
            &Block {
                header,
                transactions: txs,
            },
        )
        .unwrap();

        // Slot 16 should now be live.
        let sv = state.state.slot(16);
        assert_ne!(
            sv,
            crate::fri_state::SlotValue::EMPTY,
            "slot 16 must be live after mint"
        );
        assert_eq!(state.active_slot_count, 13);
    }

    #[test]
    fn slot_hints_cover_expanded_range() {
        use crate::consensus::allocator::generate_slot_hints;

        // After expansion from 4 to 5: valid range is [0, 32).
        // With enough hints, at least one should land in [16, 32).
        let hints = generate_slot_hints(0, 5, 100);
        let in_new_range: Vec<_> = hints.iter().filter(|&&s| s >= 16 && s < 32).collect();
        assert!(
            !in_new_range.is_empty(),
            "splitmix64 with log_slots=5 must produce hints in the new range [16,32); got {:?}",
            &hints[..10]
        );
    }

    #[test]
    fn expansion_state_root_is_deterministic() {
        // Two independent paths to the same state must give the same root.
        let mut s1 = ChainState::with_log_slots(4);
        let mut s2 = ChainState::with_log_slots(4);
        fill_slots(&mut s1, 12);
        fill_slots(&mut s2, 12);

        let h1 = mk_header_with_expansion(&s1, &[], 5);
        let h2 = mk_header_with_expansion(&s2, &[], 5);
        apply_block(
            &mut s1,
            &Block {
                header: h1,
                transactions: vec![],
            },
        )
        .unwrap();
        apply_block(
            &mut s2,
            &Block {
                header: h2,
                transactions: vec![],
            },
        )
        .unwrap();

        assert_eq!(
            s1.state_root(),
            s2.state_root(),
            "identical state histories must yield identical roots after expansion"
        );
    }

    #[test]
    fn expansion_block_validates_with_consensus() {
        use crate::consensus::{
            genesis::GENESIS_TIMESTAMP,
            params::BLOCK_TIME,
            pow::full_block_hash,
            validation::{validate_block_consensus, AnchorInfo},
        };
        use crate::nullifier::NullifierSet;
        const TEST_TARGET: [u8; 32] = [0xFF; 32];

        // Use log_slots=4 (tiny) so we can fill it fast.
        let mut state = ChainState::with_log_slots(4);
        fill_slots(&mut state, 12); // 12/16 = 75% → trigger

        // Build the parent header (simulating genesis-like parent with log_slots=4).
        let parent = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.state_root(), // lie: pretend this was the pre-state
            tx_root: [0u8; 32],
            timestamp: GENESIS_TIMESTAMP,
            height: 0,
            miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: 4,
            active_slot_count: 12, // this is what triggers expansion in validator
            alloc_counter: 12,
        };

        // Build the expansion block header.
        let mut exp_state = state.clone();
        exp_state.state.expand();
        let mut expansion_header = BlockHeader {
            prev_block_hash: full_block_hash(&parent),
            state_root: exp_state.state_root(),
            tx_root: compute_tx_root(&[]),
            timestamp: GENESIS_TIMESTAMP + BLOCK_TIME,
            height: 1,
            miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: 5,          // expanded!
            active_slot_count: 12, // unchanged (no mints/spends)
            alloc_counter: 12,
        };
        expansion_header.nonce = 0; // TEST_TARGET: any nonce works

        let block = Block {
            header: expansion_header,
            transactions: vec![],
        };
        let anchor = AnchorInfo {
            anchor_height: 0,
            anchor_timestamp: GENESIS_TIMESTAMP,
            anchor_target: TEST_TARGET,
        };
        let mut apply_state = state.clone();
        // Supply EXPANSION_WINDOW copies of the triggering occupancy so
        // the median equals the parent's active_slot_count and fires.
        let active_window = vec![parent.active_slot_count; 18];
        let result = validate_block_consensus(
            &block,
            &parent,
            &[parent.timestamp],
            &active_window,
            block.header.timestamp + 1,
            &anchor,
            &NullifierSet::new(),
            &mut apply_state,
        );
        assert!(
            result.is_ok(),
            "expansion block must pass validate_block_consensus: {:?}",
            result
        );
        assert_eq!(
            apply_state.state.log_slots(),
            5,
            "state must be expanded after validation"
        );
    }
}
