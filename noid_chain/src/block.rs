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
//! `tx_body_hash`es (COMPRESS domain, zero-padded to a power of two).

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
    /// (SPECIFICATION.md §15.3.3, §16 invariant 10)
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

/// Compute the block's tx-root — a COMPRESS-domain Merkle reduction over
/// each transaction's `tx_body_hash`, zero-padded to the next power of
/// two. An empty block reduces to `ZERO_DIGEST` so a zero-tx header is
/// unambiguously representable.
pub fn compute_tx_root(txs: &[Transaction]) -> Digest {
    if txs.is_empty() {
        return [0u8; 32];
    }
    let target = txs.len().next_power_of_two().max(2);
    let mut level: Vec<Digest> = Vec::with_capacity(target);
    for tx in txs {
        level.push(tx.tx_body_hash.0);
    }
    level.resize(target, [0u8; 32]);
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(compress(&pair[0], &pair[1]));
        }
        level = next;
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
    fn mk_header(snap: &ChainState, txs: &[Transaction]) -> BlockHeader {
        let mut dry = snap.clone();
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
            proof_transcript_hash: [1u8; 32],
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
}
