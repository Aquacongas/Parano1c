// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block container, block-level state transition, and helpers that bind
//! proofs into block headers.
//!
//! A `Block` is a header plus an ordered list of transactions. Live full-node
//! validation is proof-native: the block proof establishes the state transition,
//! then the node commits the sealed exact slot updates through
//! `ChainState::apply_verified_exact_transition`. The native sequential
//! interpreter remains only for in-memory tests and local utilities.
//! Per-tx state-root chaining is obsolete; block-level state validation ensures
//! `header.state_root` matches the final computed post-root after all txs are applied, and
//! `tx_root` equals the Merkle reduction over the transactions'
//! `tx_body_hash`es (Poseidon2b COMPRESS domain, zero-padded to a power of two).
//! The Poseidon2b-based Merkle tree is ZK-friendly: its internal nodes can be
//! proved inside the GKR block spine and recursive circuits without expensive
//! boolean decomposition. Byte-native hashes are reserved for transport/object IDs.

use noid_poseidon2b::native::compress;
use noid_poseidon2b::primitives::Digest;
use noid_tx::wire::WireError;
use noid_tx::{hash_tx_body_for_shape, Transaction};

use crate::block_header::BlockHeader;
use crate::consensus::params;
use crate::state::{apply_tx, ApplyError, ChainState, StateTransition};

/// Hard DoS cap on the number of transactions accepted by the decoder.
///
/// The consensus throughput budget is the semantic block budget in
/// `consensus::params`; this cap only keeps malformed wire blobs from
/// allocating unbounded memory.
pub const BLOCK_MAX_TXS: usize = crate::consensus::params::BLOCK_MAX_TXS;

/// A semantic block: header plus ordered transactions.
///
/// Validation proofs live outside this struct as detachable witnesses. Their
/// serialized bytes are mandatory for accepting user-transaction blocks, but
/// they are not part of semantic block identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

/// Errors returned when checking detached witness presence for a semantic block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofBindingError {
    /// A block with user transactions did not include detached `BlockProof` bytes.
    MissingProof,
    /// A structurally no-user block carried proof bytes. Consensus separately
    /// requires its mandatory coinbase.
    UnexpectedProofForCoinbaseOnly,
}

impl std::fmt::Display for ProofBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingProof => write!(f, "user-transaction block is missing BlockProof bytes"),
            Self::UnexpectedProofForCoinbaseOnly => {
                write!(f, "coinbase-only block unexpectedly carried proof bytes")
            }
        }
    }
}

impl std::error::Error for ProofBindingError {}

/// Validate detached witness presence required before proof-native consensus checks.
pub fn validate_block_proof_binding(
    block: &Block,
    block_proof_bytes: &[u8],
) -> Result<(), ProofBindingError> {
    let has_user_txs = block.transactions.iter().any(|tx| !tx.body.is_coinbase);
    if has_user_txs {
        if block_proof_bytes.is_empty() {
            return Err(ProofBindingError::MissingProof);
        }
    } else {
        if !block_proof_bytes.is_empty() {
            return Err(ProofBindingError::UnexpectedProofForCoinbaseOnly);
        }
    }
    Ok(())
}

/// Errors surfaced by [`apply_block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockApplyError {
    /// A transaction failed the native state transition.
    Tx(ApplyError),
    /// Block carries more transactions than the hard wire/DoS cap.
    TooManyTransactions,
    /// Canonical genesis must have an empty transaction list.
    GenesisHasTransactions,
    /// Transaction uses a shape that is not supported by the current proof stack.
    UnsupportedTxShape,
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
}

impl From<ApplyError> for BlockApplyError {
    fn from(e: ApplyError) -> Self {
        Self::Tx(e)
    }
}

/// Sequential state-transition interpreter.
///
/// This is not the live MDBX/node production validity path for
/// user-transaction blocks. Full nodes verify `BlockProof` and then commit the
/// sealed exact transition. This interpreter is kept for in-memory tests and
/// utility contexts that need to recompute a transition directly. On error,
/// `state` is left untouched (work happens on a snapshot and is swapped only on
/// success).
pub(crate) fn apply_block(
    state: &mut ChainState,
    block: &Block,
) -> Result<StateTransition, BlockApplyError> {
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(BlockApplyError::TooManyTransactions);
    }
    // Coinbase structure: at most one, must be first, zero inputs.
    // Coinbase VALUE validation (≤ block_reward + fees) is in consensus checks.
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
        snap.expand_one();
    }

    for tx in &block.transactions {
        if !tx.body.shape.proof_supported()
            || tx.body.inputs.len() > tx.body.shape.max_inputs()
            || tx.body.outputs.len() > tx.body.shape.max_outputs()
        {
            return Err(BlockApplyError::UnsupportedTxShape);
        }
        let expected_hash = hash_tx_body_for_shape(
            tx.body.shape,
            &tx.body.epoch_anchor,
            tx.body.fee,
            &tx.body.inputs,
            &tx.body.outputs,
            tx.body.is_coinbase,
        );
        if tx.tx_body_hash != expected_hash {
            return Err(BlockApplyError::WrongTxBodyHash);
        }

        apply_tx(&mut snap, &tx.body).map_err(BlockApplyError::Tx)?;
    }

    if block.header.state_root
        != snap
            .try_state_root()
            .map_err(|_| BlockApplyError::Tx(ApplyError::ExactStateUnavailable))?
    {
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
    Ok(StateTransition {
        new_state_root: state.cached_state_root(),
    })
}

/// Test-only differential primitive that applies a block delta without
/// re-validating pre-conditions.
///
/// **Proof-native path** — called after the minimal block verifier succeeds.
/// The verifier has already established that:
///   - Every user transaction satisfies the exact public transaction predicate.
///   - Every user transaction has a valid authorization proof.
///   - The exact authenticated state transition matches parent and child roots.
///
/// This function therefore:
///   1. Handles log_slots expansion (still structural, not covered by the proof layer).
///   2. Zeros out spent inputs and fills minted outputs — NO pre-state reads.
///   3. Updates `active_slot_count` and `alloc_counter` from the block data.
///   4. Recomputes the post-delta state root and requires it to match
///      `block.header.state_root`.
///   5. Still checks tx_root (cheap, O(n) hashing).
///
/// Production acceptance commits the sealed exact transition returned by the
/// verifier and never calls this blind interpreter.
#[cfg(test)]
pub(crate) fn apply_state_delta(
    state: &mut ChainState,
    block: &Block,
) -> Result<StateTransition, BlockApplyError> {
    use crate::fri_state::SlotValue;

    // Sanity-guard: must be called after BlockProof verification.
    // tx_root is still checked natively (cheap, doesn't require state reads).
    if block.header.tx_root != compute_tx_root(&block.transactions) {
        return Err(BlockApplyError::HeaderTxRootMismatch);
    }
    let mut snap = state.clone();

    // 1. Expansion (structural, same logic as apply_block).
    while block.header.log_slots as usize > snap.state.log_slots() {
        snap.expand_one();
    }

    // 2. Apply delta: zero inputs, fill outputs — no pre-state verification.
    // Keep the exact old operation order, but avoid `set_slot()` because it
    // recomputes the FRI/Merkle root after every individual slot update.
    let mut deltas = Vec::new();
    for tx in &block.transactions {
        for inp in tx.body.inputs.iter().filter(|i| i.valid) {
            // The exact state certificate established that this slot matched the claim.
            // Just zero it out; no read needed.
            deltas.push((inp.slot_index, SlotValue::EMPTY));
            snap.active_slot_count =
                snap.active_slot_count
                    .checked_sub(1)
                    .ok_or(BlockApplyError::Tx(
                        crate::state::ApplyError::ActiveSlotCountUnderflow,
                    ))?;
        }
        for out in tx.body.outputs.iter().filter(|o| o.valid) {
            // The exact state certificate established that this output slot was empty.
            let creation_id = snap
                .alloc_counter
                .checked_add(1)
                .ok_or(BlockApplyError::Tx(
                    crate::state::ApplyError::AllocCounterOverflow,
                ))?;
            let active_slot_count =
                snap.active_slot_count
                    .checked_add(1)
                    .ok_or(BlockApplyError::Tx(
                        crate::state::ApplyError::ActiveSlotCountOverflow,
                    ))?;
            let sv = SlotValue::with_owner_fields(out.value, creation_id, out.owner.as_fields());
            deltas.push((out.slot_index, sv));
            snap.active_slot_count = active_slot_count;
            snap.alloc_counter = creation_id;
        }
    }
    snap.state
        .apply_delta_unrooted(&deltas)
        .map_err(|_| BlockApplyError::Tx(crate::state::ApplyError::SlotOutOfRange))?;

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

    // 4. Native post-root guard. The proof layer proves the transition, but full nodes still
    // recompute the dirty segment roots before accepting the local state update.
    let computed_post_root = snap
        .try_state_root()
        .map_err(|_| BlockApplyError::Tx(ApplyError::ExactStateUnavailable))?;
    if block.header.state_root != computed_post_root {
        return Err(BlockApplyError::HeaderStateRootMismatch);
    }

    *state = snap;

    Ok(StateTransition {
        new_state_root: computed_post_root,
    })
}

/// Apply the genesis block to `state` without requiring a BlockProof or witness root.
///
/// Genesis (height = 0) is a special case: it has no transactions to prove
/// and uses zero detached witness metadata.
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
    // Genesis alone has no transactions and no coinbase. Check the body list
    // itself before trusting its independently supplied tx_root.
    if !block.transactions.is_empty() {
        return Err(BlockApplyError::GenesisHasTransactions);
    }
    // tx_root must be [0;32] (empty).
    if block.header.tx_root != [0u8; 32] {
        return Err(BlockApplyError::HeaderTxRootMismatch);
    }
    // State root must match the initial empty state.
    if block.header.state_root
        != state
            .try_state_root()
            .map_err(|_| BlockApplyError::Tx(ApplyError::ExactStateUnavailable))?
    {
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
/// each transaction's `tx_body_hash`, zero-padded to the block's
/// TIER-QUANTIZED transaction capacity ([`params::tx_tree_target`]). An
/// zero-transaction genesis reduces to `ZERO_DIGEST` so its header is
/// unambiguously representable. Every non-genesis block has at least the
/// mandatory coinbase leaf.
///
/// Uses a Poseidon2b COMPRESS binary Merkle tree. Padding to the shape
/// class's capacity (not the real count) keeps the tree depth a pure
/// function of the block's tier, so the per-tier proof classes replay one
/// fixed path depth. Poseidon2b is chosen because this Merkle root feeds
/// directly into the block proof and history-proof relations.
pub fn compute_tx_root(txs: &[Transaction]) -> Digest {
    if txs.is_empty() {
        return [0u8; 32];
    }
    let (standard, sweep) = txs
        .iter()
        .fold((0usize, 0usize), |(s, w), tx| match tx.body.shape {
            _ if tx.body.is_coinbase => (s, w),
            noid_tx::TxShape::Standard4x8 => (s + 1, w),
            noid_tx::TxShape::Sweep25x2 => (s, w + 1),
        });
    let non_user = txs.len() - standard - sweep;
    let target = params::tx_tree_target(standard, sweep, non_user);
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

// ---------------------------------------------------------------------------
// Wire encoding for Block (lives here to keep block bytes next to the
// container; BlockHeader's encoding lives in `wire.rs`).
// ---------------------------------------------------------------------------

/// Canonical format marker for the packed-incarnation, secret-free public
/// transaction representation.
pub const BLOCK_WIRE_VERSION: u8 = 0xB2;

/// Byte offset of the semantic [`BlockHeader`] inside serialized [`Block`]
/// bytes. The leading byte is the block-wire version marker.
pub const BLOCK_WIRE_HEADER_OFFSET: usize = 1;

/// Byte offset of `BlockHeader::nonce` inside serialized [`Block`] bytes.
/// External miners must patch this offset, not the header-relative offset.
pub const BLOCK_WIRE_NONCE_OFFSET: usize =
    BLOCK_WIRE_HEADER_OFFSET + crate::wire::BLOCK_HEADER_NONCE_OFFSET;

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

        buf.push(BLOCK_WIRE_VERSION);
        self.header.encode(buf);
        put_u32(buf, self.transactions.len() as u32);
        for tx in &self.transactions {
            tx.encode_public(buf);
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let version = *take(src, 1)?.first().expect("one byte requested");
        if version != BLOCK_WIRE_VERSION {
            return Err(WireError::UnsupportedVersion);
        }
        let header = BlockHeader::decode(src)?;
        let n = take_u32(src)? as usize;
        if n > BLOCK_MAX_TXS {
            return Err(WireError::CountTooLarge);
        }
        let mut transactions = Vec::with_capacity(n);
        for _ in 0..n {
            transactions.push(Transaction::decode_public(src)?);
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
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::{hash_tx_body, TxBody, TxInput, TxOutput};

    const TEST_LOG_SLOTS: usize = 6;

    /// Build a `BlockHeader` with the correct consensus fields for `snap`
    /// after applying `txs`. Detached witness fields are deliberately populated
    /// with detached witness metadata so tests can prove they do not affect `apply_block`.
    fn mk_header(snap: &ChainState, txs: &[Transaction]) -> BlockHeader {
        mk_header_at(snap, txs, 1)
    }

    fn mk_header_at(snap: &ChainState, txs: &[Transaction], height: u64) -> BlockHeader {
        let mut dry = snap.clone();
        for tx in txs {
            apply_tx(&mut dry, &tx.body).unwrap();
        }
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: dry.state_root(),
            tx_root: compute_tx_root(txs),
            timestamp: height,
            height,
            miner_address: Address([9u8; 32]),
            nonce: 0,
            difficulty_target: [0xFFu8; 32],
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
            creation_id: 1,
            owner: out.owner,
            spend_secret: SpendSecret([0u8; 32]),
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
            shape: noid_tx::TxShape::Standard4x8,
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
    fn apply_state_delta_accepts_correct_post_root() {
        let mut state = fresh_state();
        let tx = build_tx(&mut state, vec![], vec![mk_output(1)]);
        let txs = vec![tx];
        let block = Block {
            header: mk_header(&state, &txs),
            transactions: txs,
        };
        let expected_root = block.header.state_root;

        let out = apply_state_delta(&mut state, &block).expect("delta apply");
        assert_eq!(out.new_state_root, expected_root);
        assert_eq!(state.state_root(), expected_root);
    }

    #[test]
    fn apply_state_delta_rejects_wrong_post_root_and_preserves_state() {
        let mut state = fresh_state();
        let pre_root = state.state_root();
        let tx = build_tx(&mut state, vec![], vec![mk_output(1)]);
        let txs = vec![tx];
        let mut block = Block {
            header: mk_header(&state, &txs),
            transactions: txs,
        };
        block.header.state_root[0] ^= 0x80;

        assert_eq!(
            apply_state_delta(&mut state, &block),
            Err(BlockApplyError::HeaderStateRootMismatch)
        );
        assert_eq!(
            state.state_root(),
            pre_root,
            "state must not be swapped on rejection"
        );
        assert_eq!(
            state.active_slot_count, 0,
            "counters must not change on rejection"
        );
    }

    #[test]
    fn apply_state_delta_rejects_alloc_counter_overflow_without_writes() {
        let mut state = fresh_state();
        state.alloc_counter = u64::MAX;
        let before_root = state.state_root();
        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![mk_output(1)],
            is_coinbase: true,
        };
        let tx = Transaction {
            tx_body_hash: hash_tx_body(
                &body.epoch_anchor,
                body.fee,
                &body.inputs,
                &body.outputs,
                body.is_coinbase,
            ),
            body,
        };
        let transactions = vec![tx];
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: before_root,
                tx_root: compute_tx_root(&transactions),
                timestamp: 1,
                height: 1,
                miner_address: Address([9u8; 32]),
                nonce: 0,
                difficulty_target: [0xFFu8; 32],
                log_slots: TEST_LOG_SLOTS as u32,
                active_slot_count: 0,
                alloc_counter: u64::MAX,
            },
            transactions,
        };

        assert_eq!(
            apply_state_delta(&mut state, &block),
            Err(BlockApplyError::Tx(ApplyError::AllocCounterOverflow))
        );
        assert_eq!(state.state_root(), before_root);
        assert_eq!(state.active_slot_count, 0);
        assert_eq!(state.alloc_counter, u64::MAX);
    }

    #[test]
    fn apply_state_delta_matches_native_apply_block_on_small_block() {
        let mut native_state = fresh_state();
        let mut delta_state = native_state.clone();
        let tx1 = build_tx(&mut native_state, vec![], vec![mk_output(1)]);
        let mut probe = native_state.clone();
        apply_tx(&mut probe, &tx1.body).unwrap();
        let spend = mk_input_for(1, &mk_output(1));
        let tx2 = build_tx(&mut probe, vec![spend], vec![mk_output(3)]);
        let txs = vec![tx1, tx2];
        let block = Block {
            header: mk_header(&native_state, &txs),
            transactions: txs,
        };

        let native_out = apply_block(&mut native_state, &block).expect("native apply");
        let delta_out = apply_state_delta(&mut delta_state, &block).expect("delta apply");
        assert_eq!(delta_out.new_state_root, native_out.new_state_root);
        assert_eq!(delta_state.state_root(), native_state.state_root());
        assert_eq!(
            delta_state.active_slot_count,
            native_state.active_slot_count
        );
        assert_eq!(delta_state.alloc_counter, native_state.alloc_counter);
    }

    #[test]
    fn native_apply_paths_allow_spend_then_mint_with_fresh_creation_id() {
        let mut state = fresh_state();
        let live = mk_output(2);
        state
            .state
            .set_slot(
                live.slot_index,
                crate::fri_state::SlotValue::with_owner_fields(
                    live.value,
                    1,
                    live.owner.as_fields(),
                ),
            )
            .unwrap();
        state.active_slot_count = 1;
        state.alloc_counter = 1;

        let spend = build_tx(
            &mut state.clone(),
            vec![mk_input_for(live.slot_index, &live)],
            vec![],
        );
        let mut after_spend = state.clone();
        apply_tx(&mut after_spend, &spend.body).unwrap();
        let mint = build_tx(&mut after_spend, vec![], vec![live]);
        let txs = vec![spend, mint];
        let block = Block {
            header: mk_header(&state, &txs),
            transactions: txs,
        };
        let mut sequential = state.clone();
        apply_block(&mut sequential, &block).expect("sequential immediate reuse");
        apply_state_delta(&mut state, &block).expect("delta immediate reuse");
        let reused = sequential.state.slot(2);
        assert_eq!(reused.creation_id(), 2);
        assert_eq!(state.state.slot(2), reused);

        let stale = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![mk_input_for(2, &mk_output(2))],
            outputs: vec![],
            is_coinbase: false,
        };
        assert_eq!(
            apply_tx(&mut sequential, &stale),
            Err(ApplyError::UnknownOrSpentInput),
            "the stale creation ID must not spend the replacement UTXO"
        );
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
    fn internal_interpreter_can_apply_structurally_empty_noop() {
        let mut state = fresh_state();
        let txs: Vec<Transaction> = vec![]; // internal interpreter no-op, not an accepted child
        let header = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.state_root(),
            tx_root: compute_tx_root(&txs),
            timestamp: 1,
            height: 1,
            miner_address: Address([9u8; 32]),
            nonce: 0,
            difficulty_target: [0xFFu8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: 0,
            alloc_counter: 0,
        };
        let block = Block {
            header,
            transactions: txs,
        };
        // `apply_block` is crate-private and does not establish consensus by
        // itself. Every non-genesis accepted entry point first runs the shared
        // mandatory-coinbase predicate.
        apply_block(&mut state, &block).expect("internal no-op transition applies");
    }

    #[test]
    fn block_wire_roundtrip() {
        let mut state = fresh_state();
        let tx = build_tx(&mut state, vec![], vec![mk_output(1)]);
        let txs = vec![tx];
        let header = mk_header(&state, &txs);
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
    fn block_wire_omits_spend_secrets_and_is_secret_invariant() {
        let input = TxInput {
            slot_index: 7,
            value: 1_000,
            creation_id: 41,
            owner: Address([0x51; 32]),
            spend_secret: SpendSecret([0xA6; 32]),
            valid: true,
        };
        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0x31; 32],
            fee: 0,
            inputs: vec![input],
            outputs: vec![TxOutput {
                slot_index: 8,
                value: 1_000,
                owner: Address([0x52; 32]),
                valid: true,
            }],
            is_coinbase: false,
        };
        let tx = Transaction {
            tx_body_hash: hash_tx_body(
                &body.epoch_anchor,
                body.fee,
                &body.inputs,
                &body.outputs,
                body.is_coinbase,
            ),
            body,
        };
        let header = BlockHeader {
            prev_block_hash: [0x11; 32],
            state_root: [0x12; 32],
            tx_root: compute_tx_root(std::slice::from_ref(&tx)),
            timestamp: 1,
            height: 1,
            miner_address: Address([0x13; 32]),
            nonce: 0,
            difficulty_target: [0xFF; 32],
            log_slots: 24,
            active_slot_count: 1,
            alloc_counter: 42,
        };
        let block = Block {
            header,
            transactions: vec![tx],
        };

        let bytes = block.to_bytes();
        let mut different_secret = block.clone();
        different_secret.transactions[0].body.inputs[0].spend_secret = SpendSecret([0xD7; 32]);
        assert_eq!(
            different_secret.to_bytes(),
            bytes,
            "consensus block bytes must not carry witness secrets"
        );

        let decoded = Block::from_bytes(&bytes).expect("public block decode");
        assert_eq!(
            decoded.transactions[0].body.inputs[0].spend_secret,
            SpendSecret([0u8; 32])
        );
        assert_eq!(
            decoded.transactions[0].body.inputs[0].creation_id,
            block.transactions[0].body.inputs[0].creation_id,
            "the public input incarnation remains on wire"
        );
        assert_eq!(
            decoded.transactions[0].tx_body_hash,
            block.transactions[0].tx_body_hash
        );
    }

    #[test]
    fn serialized_nonce_offset_preserves_version_and_roundtrips() {
        let mut state = fresh_state();
        let tx = build_tx(&mut state, vec![], vec![mk_output(1)]);
        let txs = vec![tx];
        let mut expected = Block {
            header: mk_header(&state, &txs),
            transactions: txs,
        };
        let mut bytes = expected.to_bytes();
        let version_prefix = bytes[..BLOCK_WIRE_HEADER_OFFSET].to_vec();
        let nonce = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;

        bytes[BLOCK_WIRE_NONCE_OFFSET..BLOCK_WIRE_NONCE_OFFSET + 16]
            .copy_from_slice(&nonce.to_le_bytes());
        expected.header.nonce = nonce;

        assert_eq!(version_prefix, [BLOCK_WIRE_VERSION]);
        assert_eq!(
            &bytes[..BLOCK_WIRE_HEADER_OFFSET],
            version_prefix.as_slice(),
            "patching the serialized nonce must not overwrite the wire epoch"
        );
        assert_eq!(Block::from_bytes(&bytes), Ok(expected));
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
    fn block_rejects_missing_format_marker() {
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
                log_slots: 24,
                active_slot_count: 0,
                alloc_counter: 0,
            },
            transactions: vec![],
        };
        let mut bytes = block.to_bytes();
        bytes.remove(0);
        assert_eq!(
            Block::from_bytes(&bytes),
            Err(WireError::UnsupportedVersion)
        );
    }

    #[test]
    fn apply_block_rejects_multiple_coinbase() {
        let mut state = fresh_state();

        // Build two distinct coinbase transactions (each mints to a different slot).
        let make_cb = |slot: u8| {
            let body = TxBody {
                shape: noid_tx::TxShape::Standard4x8,
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
            shape: noid_tx::TxShape::Standard4x8,
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

        let mut nonempty = block;
        nonempty
            .transactions
            .push(build_tx(&mut state, vec![], vec![mk_output(1)]));
        assert_eq!(
            apply_genesis_block(&mut state, &nonempty),
            Err(BlockApplyError::GenesisHasTransactions),
            "genesis must reject a body even when the header claims the empty tx root"
        );
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
            dry.expand_one();
        }
        for tx in txs {
            apply_tx(&mut dry, &tx.body).unwrap();
        }
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: dry.state_root(),
            tx_root: compute_tx_root(txs),
            timestamp: 1,
            height: 1,
            miner_address: Address([9u8; 32]),
            nonce: 0,
            difficulty_target: [0xFFu8; 32],
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
                shape: noid_tx::TxShape::Standard4x8,
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
                shape: noid_tx::TxShape::Standard4x8,
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
        let in_new_range: Vec<_> = hints.iter().filter(|&&s| (16..32).contains(&s)).collect();
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
            template::build_block_template,
            validation::{validate_block_consensus, AnchorInfo},
        };
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
            log_slots: 4,
            active_slot_count: 12, // this is what triggers expansion in validator
            alloc_counter: 12,
        };

        // Supply EXPANSION_WINDOW copies of the triggering occupancy so
        // the median equals the parent's active_slot_count and fires.
        let active_window = vec![parent.active_slot_count; 18];
        let template = build_block_template(
            &parent,
            &state,
            &active_window,
            vec![],
            noid_poseidon2b::primitives::Address([0u8; 32]),
            GENESIS_TIMESTAMP + BLOCK_TIME,
            TEST_TARGET,
        )
        .expect("canonical expansion coinbase template");
        let block = Block {
            header: template.clone().into_header(0),
            transactions: template.all_txs(),
        };
        assert_eq!(block.header.log_slots, 5);
        let anchor = AnchorInfo {
            anchor_height: 0,
            anchor_timestamp: GENESIS_TIMESTAMP,
            anchor_target: TEST_TARGET,
        };
        let mut apply_state = state.clone();
        let result = validate_block_consensus(
            &block,
            &parent,
            &[parent.timestamp],
            &active_window,
            block.header.timestamp + 1,
            &anchor,
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
