// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block container and deterministic public-body state materialization.
//!
//! A `Block` is a header plus an ordered list of transactions. Live full-node
//! acceptance first verifies the bundled recursive HistoryStep terminal, then
//! materializes these public actions into the exact hot state.
//! Block-level state validation ensures `header.state_root` matches the final
//! computed post-root after all transactions are applied, and
//! `tx_root` equals the count-bound universal Merkle root over the derived
//! transaction ids.
//! The Poseidon2b-based Merkle tree is ZK-friendly: its internal nodes can be
//! proved inside the GKR block spine and recursive circuits without expensive
//! boolean decomposition. Byte-native hashes are reserved for transport/object IDs.

use noid_poseidon2b::primitives::Digest;
use noid_tx::wire::WireError;
use noid_tx::{PagedSpendError, Transaction, TxPage};

use crate::block_header::BlockHeader;
use crate::state::{apply_tx_at, ApplyError, ChainState, StateTransition};

/// Hard DoS cap on the number of transactions accepted by the decoder.
///
/// The consensus throughput budget is the semantic block budget in
/// `consensus::params`; this cap only keeps malformed wire blobs from
/// allocating unbounded memory.
pub const BLOCK_MAX_TXS: usize = crate::consensus::params::BLOCK_MAX_TXS;

/// A semantic block: header plus ordered transactions.
///
/// Network acceptance transports this body together with its full HistoryStep
/// terminal in `AcceptedBlockBundle`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    /// Fixed public records: coinbase at index zero followed by an ordered
    /// physical PagedSpend page stream. The legacy field name is retained to
    /// avoid copying the block body through every exact-state consumer.
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockPageStreamError {
    MissingCoinbase,
    CoinbaseNotFirst,
    MultipleCoinbase,
    PagedSpend(crate::consensus::paged_spend::PagedSpendStreamError),
}

impl std::fmt::Display for BlockPageStreamError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for BlockPageStreamError {}

/// Errors surfaced by [`apply_block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockApplyError {
    /// A transaction failed the native state transition.
    Tx(ApplyError),
    /// Block carries more transactions than the hard wire/DoS cap.
    TooManyTransactions,
    /// Canonical genesis must have an empty transaction list.
    GenesisHasTransactions,
    /// Transaction body is not the canonical fixed construction.
    InvalidTxBody,
    /// User records do not form one canonical PagedSpend stream.
    InvalidPagedSpend,
    /// Two live actions in the block touch the same physical slot.
    SlotConflict,
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

/// Deterministically materialize an already-verified accepted block body.
///
/// The caller must verify the block's full HistoryStep terminal before calling
/// this function. It applies only public block actions and independently
/// requires the resulting exact root/counters/tx root to match the header. On
/// error `state` is left untouched.
pub fn materialize_accepted_block_state(
    state: &mut ChainState,
    block: &Block,
) -> Result<[u8; 32], BlockApplyError> {
    apply_block(state, block).map(|transition| transition.new_state_root)
}

/// Shared state-transition implementation for consensus and the public
/// accepted-block materializer.
pub(crate) fn apply_block(
    state: &mut ChainState,
    block: &Block,
) -> Result<StateTransition, BlockApplyError> {
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(BlockApplyError::TooManyTransactions);
    }
    validate_block_page_stream(&block.transactions)
        .map_err(|_| BlockApplyError::InvalidPagedSpend)?;
    crate::consensus::checks::validate_block_slot_conflicts(&block.transactions)
        .map_err(|_| BlockApplyError::SlotConflict)?;
    // Coinbase structure: at most one, must be first, zero inputs.
    // Coinbase VALUE validation (≤ block_reward + claimable fees) is in consensus checks.
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
            if cb.body.live_input_count() != 0 {
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

    for (index, tx) in block.transactions.iter().enumerate() {
        if index == 0 {
            tx.body
                .validate_canonical()
                .map_err(|_| BlockApplyError::InvalidTxBody)?;
        }

        apply_tx_at(&mut snap, &tx.body, block.header.height).map_err(BlockApplyError::Tx)?;
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
    if block.header.tx_root
        != try_compute_tx_root(&block.transactions)
            .map_err(|_| BlockApplyError::InvalidPagedSpend)?
    {
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

    crate::consensus::checks::validate_block_slot_conflicts(&block.transactions)
        .map_err(|_| BlockApplyError::SlotConflict)?;
    validate_block_page_stream(&block.transactions)
        .map_err(|_| BlockApplyError::InvalidPagedSpend)?;

    // Sanity-guard: must be called only after full HistoryStep verification.
    // tx_root is still checked natively (cheap, doesn't require state reads).
    if block.header.tx_root
        != try_compute_tx_root(&block.transactions)
            .map_err(|_| BlockApplyError::InvalidPagedSpend)?
    {
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
        for (_, inp) in tx.body.live_inputs() {
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
        for (_, out) in tx.body.live_outputs() {
            // The exact state certificate established that this output slot was empty.
            let next_alloc = snap
                .alloc_counter
                .checked_add(1)
                .ok_or(BlockApplyError::Tx(
                    crate::state::ApplyError::AllocCounterOverflow,
                ))?;
            if crate::consensus::params::is_coinbase_creation_id(next_alloc) {
                return Err(BlockApplyError::Tx(
                    crate::state::ApplyError::AllocCounterOverflow,
                ));
            }
            let creation_id = if tx.body.is_coinbase {
                crate::consensus::params::coinbase_creation_id(block.header.height)
            } else {
                next_alloc
            };
            let active_slot_count =
                snap.active_slot_count
                    .checked_add(1)
                    .ok_or(BlockApplyError::Tx(
                        crate::state::ApplyError::ActiveSlotCountOverflow,
                    ))?;
            let sv = SlotValue::with_owner_fields(out.amount, creation_id, out.owner.as_fields());
            deltas.push((out.slot_index, sv));
            snap.active_slot_count = active_slot_count;
            snap.alloc_counter = next_alloc;
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

/// Apply the built-in genesis block to `state`.
///
/// Genesis (height = 0) is a special case and is never transported as an
/// accepted block bundle.
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

/// Validate coinbase placement and the complete physical user-page stream.
pub fn validate_block_page_stream(
    txs: &[Transaction],
) -> Result<crate::consensus::paged_spend::PagedSpendStreamFacts, BlockPageStreamError> {
    let Some(coinbase) = txs.first() else {
        return Err(BlockPageStreamError::MissingCoinbase);
    };
    if !coinbase.body.is_coinbase {
        return Err(BlockPageStreamError::CoinbaseNotFirst);
    }
    if txs[1..].iter().any(|tx| tx.body.is_coinbase) {
        return Err(BlockPageStreamError::MultipleCoinbase);
    }
    crate::consensus::paged_spend::validate_paged_spend_transaction_stream(&txs[1..])
        .map_err(BlockPageStreamError::PagedSpend)
}

/// Compute the final count-bound universal 256-leaf logical transaction root.
///
/// Coinbase occupies leaf zero. Complete PagedSpend groups occupy the
/// following leaves; continuation pages never get independent leaves.
/// Genesis alone uses the zero root.
pub fn try_compute_tx_root(txs: &[Transaction]) -> Result<Digest, BlockPageStreamError> {
    if txs.is_empty() {
        return Ok([0u8; 32]);
    }
    let stream = validate_block_page_stream(txs)?;
    let hashes: Vec<_> = std::iter::once(txs[0].txid().0)
        .chain(stream.groups.iter().map(|group| group.spend.logical_txid.0))
        .collect();
    Ok(crate::tx_tree::root_from_hashes(&hashes))
}

/// Infallible builder helper for an already-canonical block page stream.
pub fn compute_tx_root(txs: &[Transaction]) -> Digest {
    try_compute_tx_root(txs).expect("compute_tx_root requires coinbase plus canonical PagedSpend")
}

// ---------------------------------------------------------------------------
// Wire encoding for Block (lives here to keep block bytes next to the
// container; BlockHeader's encoding lives in `wire.rs`).
// ---------------------------------------------------------------------------

/// Canonical format marker for the packed-incarnation, secret-free public
/// transaction representation.
pub const BLOCK_WIRE_MARKER: u8 = 0xB3;

/// Byte offset of the semantic [`BlockHeader`] inside serialized [`Block`]
/// bytes. The leading byte is the fixed construction marker.
pub const BLOCK_WIRE_HEADER_OFFSET: usize = 1;

/// Fixed bytes before the first transaction: marker, header, and tx count.
pub const BLOCK_WIRE_FIXED_OVERHEAD: usize =
    1 + crate::wire::BLOCK_HEADER_WIRE_SIZE + core::mem::size_of::<u32>();

/// Return the exact canonical wire length for a fixed-width transaction list
/// without invoking the encoder.
///
/// Validation uses this before body canonicality has been established.  It
/// therefore must remain pure checked arithmetic: calling `Block::to_bytes`
/// here would expose the encoder's invariant assertions to malformed
/// in-memory candidates.
pub fn canonical_block_wire_len(tx_count: usize) -> Result<usize, WireError> {
    if tx_count > BLOCK_MAX_TXS {
        return Err(WireError::LengthOverflow);
    }
    tx_count
        .checked_mul(noid_tx::wire::TRANSACTION_WIRE_SIZE)
        .and_then(|tx_bytes| BLOCK_WIRE_FIXED_OVERHEAD.checked_add(tx_bytes))
        .ok_or(WireError::LengthOverflow)
}

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
    /// Exact wire length derived only from the bounded fixed transaction count.
    pub fn canonical_wire_len(&self) -> Result<usize, WireError> {
        canonical_block_wire_len(self.transactions.len())
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        assert!(
            self.transactions.len() <= BLOCK_MAX_TXS,
            "transactions exceed BLOCK_MAX_TXS"
        );

        if !self.transactions.is_empty() {
            validate_block_page_stream(&self.transactions)
                .expect("cannot encode a non-canonical block page stream");
        }

        buf.push(BLOCK_WIRE_MARKER);
        self.header.encode(buf);
        put_u32(buf, self.transactions.len() as u32);
        if let Some(coinbase) = self.transactions.first() {
            coinbase.encode(buf);
        }
        for tx in self.transactions.iter().skip(1) {
            TxPage {
                body: tx.body.clone(),
            }
            .encode(buf)
            .expect("validated block page stream has canonical page bodies");
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    pub fn decode(src: &mut &[u8]) -> Result<Self, WireError> {
        let marker = *take(src, 1)?.first().expect("one byte requested");
        if marker != BLOCK_WIRE_MARKER {
            return Err(WireError::BadMarker);
        }
        let header = BlockHeader::decode(src)?;
        let n = take_u32(src)? as usize;
        if n > BLOCK_MAX_TXS {
            return Err(WireError::LengthOverflow);
        }
        let mut transactions = Vec::with_capacity(n);
        if n > 0 {
            let coinbase = Transaction::decode(src)?;
            if !coinbase.body.is_coinbase {
                return Err(WireError::NonCanonicalBody);
            }
            transactions.push(coinbase);
        }
        for _ in 1..n {
            let page = TxPage::decode(src).map_err(page_wire_error)?;
            transactions.push(Transaction::new(page.body));
        }
        if n > 0 {
            validate_block_page_stream(&transactions).map_err(|_| WireError::NonCanonicalBody)?;
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

fn page_wire_error(error: PagedSpendError) -> WireError {
    match error {
        PagedSpendError::Wire(error) => error,
        _ => WireError::NonCanonicalBody,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, TxBody, TxInput, TxOutput, PAGED_SPEND_END_BIT, PAGED_SPEND_START_BIT,
        TX_INPUTS, TX_OUTPUTS,
    };

    fn user_tx() -> Transaction {
        user_tx_at(1, 2)
    }

    fn user_tx_at(input_slot: u32, output_slot: u32) -> Transaction {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: input_slot,
            amount: 11,
            creation_id: 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: output_slot,
            amount: 10,
            owner: Address([2u8; 32]),
        };
        Transaction::new(TxBody {
            epoch_anchor: [3u8; 32],
            fee: 1,
            input_owner: Address([1u8; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0) | PAGED_SPEND_START_BIT | PAGED_SPEND_END_BIT,
            is_coinbase: false,
        })
    }

    fn coinbase() -> Transaction {
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 200,
            amount: 0,
            owner: Address([9u8; 32]),
        };
        Transaction::new(TxBody {
            epoch_anchor: [7u8; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        })
    }

    fn state() -> ChainState {
        let mut state = ChainState::with_log_slots(8);
        state
            .state
            .set_slot(
                1,
                crate::fri_state::SlotValue::with_owner_fields(
                    11,
                    1,
                    Address([1u8; 32]).as_fields(),
                ),
            )
            .unwrap();
        state.active_slot_count = 1;
        state.alloc_counter = 1;
        state
    }

    fn block_for(state: &ChainState, user_pages: Vec<Transaction>) -> Block {
        let mut txs = Vec::with_capacity(user_pages.len() + 1);
        let mut reward = coinbase();
        reward.body.outputs[0].slot_index = (200..256)
            .find(|slot| state.state.slot(*slot).is_empty())
            .expect("test state has a free reward slot");
        txs.push(reward);
        txs.extend(user_pages);
        let mut dry = state.clone();
        for tx in &txs {
            apply_tx_at(&mut dry, &tx.body, 1).unwrap();
        }
        Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: dry.state_root(),
                tx_root: compute_tx_root(&txs),
                timestamp: 1,
                height: 1,
                miner_address: Address([9u8; 32]),
                nonce: 0,
                difficulty_target: [0xff; 32],
                log_slots: 8,
                active_slot_count: dry.active_slot_count,
                alloc_counter: dry.alloc_counter,
            },
            transactions: txs,
        }
    }

    #[test]
    fn native_fixed_body_transition_is_atomic() {
        let mut state = state();
        let block = block_for(&state, vec![user_tx()]);
        apply_block(&mut state, &block).unwrap();
        assert_eq!(state.state.slot(1), crate::fri_state::SlotValue::EMPTY);
        assert_eq!(state.state.slot(2).amount(), 10);

        let before = state.clone();
        let mut bad = block_for(&state, vec![]);
        bad.header.tx_root = [9u8; 32];
        assert_eq!(
            apply_block(&mut state, &bad),
            Err(BlockApplyError::HeaderTxRootMismatch)
        );
        assert_eq!(state.active_slot_count, before.active_slot_count);
    }

    #[test]
    fn both_direct_interpreters_enforce_block_wide_disjointness() {
        let mut state = state();
        let first = user_tx_at(1, 2);
        let second = user_tx_at(3, 1);
        let mut block = block_for(&state, vec![first.clone()]);
        block.transactions = vec![coinbase(), first, second];
        block.header.tx_root = [0u8; 32];

        assert_eq!(
            apply_block(&mut state, &block),
            Err(BlockApplyError::InvalidPagedSpend)
        );
        assert_eq!(
            apply_state_delta(&mut state, &block),
            Err(BlockApplyError::SlotConflict)
        );
    }

    #[test]
    fn block_wire_uses_one_fixed_marker_and_no_cached_txid() {
        let state = state();
        let block = block_for(&state, vec![user_tx()]);
        let bytes = block.to_bytes();
        assert_eq!(bytes[0], BLOCK_WIRE_MARKER);
        assert_eq!(Block::from_bytes(&bytes), Ok(block));

        let mut bad = bytes;
        bad[0] ^= 1;
        assert_eq!(Block::from_bytes(&bad), Err(WireError::BadMarker));
    }

    #[test]
    fn maximum_canonical_block_wire_is_exact() {
        let mut txs = vec![coinbase()];
        txs.extend((0..255).map(|index| {
            let input_slot = 1_000 + index as u32;
            let output_slot = 2_000 + index as u32;
            let mut tx = user_tx_at(input_slot, output_slot);
            tx.body.inputs[0].creation_id = index as u64 + 1;
            tx.body.epoch_anchor = [index as u8; 32];
            tx
        }));
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [0u8; 32],
                tx_root: compute_tx_root(&txs),
                timestamp: 1,
                height: 1,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                difficulty_target: [0xff; 32],
                log_slots: 24,
                active_slot_count: 0,
                alloc_counter: 0,
            },
            transactions: txs,
        };
        assert_eq!(block.canonical_wire_len(), Ok(82_905));
        assert_eq!(block.to_bytes().len(), 82_905);
        assert_eq!(Block::from_bytes(&block.to_bytes()).unwrap(), block);
        assert_eq!(
            canonical_block_wire_len(BLOCK_MAX_TXS + 1),
            Err(WireError::LengthOverflow)
        );
    }

    #[test]
    fn logical_root_compacts_continuation_pages() {
        let mut first = user_tx_at(1, 20);
        for (index, input) in first.body.inputs.iter_mut().enumerate() {
            *input = TxInput {
                slot_index: index as u32 + 1,
                amount: 2,
                creation_id: index as u64 + 1,
            };
        }
        first.body.outputs[0].amount = 19;
        first.body.validity_bitmap = 0x00ff | output_bitmap_bit(0) | PAGED_SPEND_START_BIT;
        first.body.fee = 1;

        let mut second = user_tx_at(2, 21);
        second.body.inputs[0] = TxInput {
            slot_index: 9,
            amount: 4,
            creation_id: 9,
        };
        second.body.outputs = [TxOutput::dummy(); TX_OUTPUTS];
        second.body.fee = 0;
        second.body.validity_bitmap = 1 | PAGED_SPEND_END_BIT;
        second.body.input_owner = first.body.input_owner;
        second.body.epoch_anchor = first.body.epoch_anchor;

        let txs = vec![coinbase(), first, second];
        let stream = validate_block_page_stream(&txs).unwrap();
        assert_eq!(stream.page_count, 2);
        assert_eq!(stream.logical_count, 1);
        let logical_root = compute_tx_root(&txs);
        let physical_root =
            crate::tx_tree::root_from_hashes(&txs.iter().map(|tx| tx.txid().0).collect::<Vec<_>>());
        assert_ne!(logical_root, physical_root);

        let mut changed = txs;
        changed[2].body.inputs[0].creation_id ^= 1;
        assert_ne!(compute_tx_root(&changed), logical_root);
    }

    #[test]
    fn genesis_is_empty_and_zero_rooted() {
        let mut state = ChainState::with_log_slots(8);
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: state.state_root(),
                tx_root: [0u8; 32],
                timestamp: 0,
                height: 0,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                difficulty_target: [0xff; 32],
                log_slots: 8,
                active_slot_count: 0,
                alloc_counter: 0,
            },
            transactions: vec![],
        };
        assert!(apply_genesis_block(&mut state, &block).is_ok());
    }
}
