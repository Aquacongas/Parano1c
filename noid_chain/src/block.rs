// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Block container, block-level state transition, and helpers that bind
//! proofs into block headers.
//!
//! A `Block` is a header plus an ordered list of transactions. Applying
//! a block runs `apply_tx` sequentially with root chaining: each tx's
//! `prev_state_root` must equal the previous tx's `new_state_root`. The
//! block header's `state_root` must equal the final post-root and
//! `tx_root` must equal the Merkle reduction over the transactions'
//! `tx_body_hash`es (COMPRESS domain, zero-padded to a power of two).

use noid_poseidon2b::native::compress;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_FSCHALNG};
use noid_poseidon2b::primitives::Digest;
use noid_tx::wire::WireError;
use noid_tx::Transaction;

use crate::block_header::BlockHeader;
use crate::state::{apply_tx, ApplyError, ChainState, StateTransition};

/// Block version on the wire.
pub const BLOCK_VERSION: u8 = 1;

/// Hard DoS cap on the number of transactions accepted by the decoder.
/// The economic / consensus limit is enforced elsewhere; this just keeps
/// a malformed wire blob from allocating unbounded memory.
pub const BLOCK_MAX_TXS: usize = 1 << 20;

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
    /// `tx.body.prev_state_root` does not match the running chain root.
    UnchainedPrevRoot,
    /// `tx.body.new_state_root` disagrees with what `apply_tx` computed.
    WrongNewStateRoot,
    /// Same check for nullifier_root.
    WrongNullifierRoot,
    /// `header.state_root` disagrees with the post-apply chain root.
    HeaderStateRootMismatch,
    /// `header.tx_root` disagrees with the computed tx-root.
    HeaderTxRootMismatch,
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
    let mut snap = state.clone();
    let mut last = StateTransition {
        new_state_root: snap.state_root(),
        nullifier_root: snap.nullifier_root(),
    };

    for tx in &block.transactions {
        if tx.body.prev_state_root != snap.state_root() {
            return Err(BlockApplyError::UnchainedPrevRoot);
        }
        let st = apply_tx(&mut snap, &tx.body).map_err(BlockApplyError::Tx)?;
        if tx.body.new_state_root != st.new_state_root {
            return Err(BlockApplyError::WrongNewStateRoot);
        }
        if tx.body.nullifier_root != st.nullifier_root {
            return Err(BlockApplyError::WrongNullifierRoot);
        }
        last = st;
    }

    if block.header.state_root != snap.state_root() {
        return Err(BlockApplyError::HeaderStateRootMismatch);
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
        buf.push(BLOCK_VERSION);
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
        let v = take(src, 1)?[0];
        if v != BLOCK_VERSION {
            return Err(WireError::UnknownVersion);
        }
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
    use noid_core::{Block128, TowerField};
    use noid_poseidon2b::primitives::{
        derive_view_key, hash_commitment, hash_scan_tag, Address, MasterSecret, Nullifier,
    };
    use noid_tx::{hash_tx_body, TxBody, TxInput, TxOutput};

    fn mk_output(seed: u8, salt: u128) -> TxOutput {
        let addr = Address([seed; 32]);
        let c = hash_commitment(
            seed as u128,
            &addr,
            Block128::from(seed as u128),
            Block128::ZERO,
        );
        let vk = derive_view_key(&MasterSecret([seed; 32]));
        let salt = Block128::from(salt);
        TxOutput {
            commitment: c,
            salt,
            scan_tag: hash_scan_tag(&vk, salt),
            valid: true,
        }
    }

    fn mk_input(seed: u8) -> TxInput {
        let addr = Address([seed; 32]);
        let c = hash_commitment(
            seed as u128,
            &addr,
            Block128::from(seed as u128),
            Block128::ZERO,
        );
        let mut n = [0u8; 32];
        n[0] = seed;
        n[1] = 0xAB;
        TxInput {
            commitment: c,
            nullifier: Nullifier(n),
            valid: true,
        }
    }

    /// Build a transaction whose `new_state_root` / `nullifier_root` /
    /// `tx_body_hash` are filled in against a probe of the given state.
    /// The resulting tx applies cleanly as long as `state` doesn't drift
    /// between the probe and the real apply.
    fn build_tx(state: &ChainState, inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Transaction {
        let mut probe = state.clone();
        let mut body = TxBody {
            prev_state_root: state.state_root(),
            new_state_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            fee: 0,
            inputs,
            outputs,
        };
        let st = apply_tx(&mut probe, &body).expect("probe apply");
        body.new_state_root = st.new_state_root;
        body.nullifier_root = st.nullifier_root;
        let tbh = hash_tx_body(
            &body.prev_state_root,
            body.fee,
            &body.inputs,
            &body.outputs,
        );
        Transaction {
            body,
            tx_body_hash: tbh,
            auth_tags: vec![],
        }
    }

    #[test]
    fn apply_block_happy_path_two_chained_txs() {
        let mut state = ChainState::new();
        let tx1 = build_tx(&state, vec![], vec![mk_output(1, 1)]);
        let mut probe = state.clone();
        apply_tx(&mut probe, &tx1.body).unwrap();
        let tx2 = build_tx(&probe, vec![mk_input(2)], vec![mk_output(3, 3)]);

        let txs = vec![tx1, tx2];
        let tx_root = compute_tx_root(&txs);

        let mut dry = state.clone();
        let mut last = StateTransition {
            new_state_root: dry.state_root(),
            nullifier_root: dry.nullifier_root(),
        };
        for tx in &txs {
            last = apply_tx(&mut dry, &tx.body).unwrap();
        }
        let st_final = last;

        let header = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: st_final.new_state_root,
            tx_root,
            timestamp: 1,
            miner_address: Address([9u8; 32]),
            nonce: 0,
            proof_transcript_hash: [0u8; 32],
        };
        let block = Block {
            header,
            transactions: txs,
        };
        let out = apply_block(&mut state, &block).expect("apply");
        assert_eq!(out.new_state_root, state.state_root());
    }

    #[test]
    fn apply_block_rejects_wrong_tx_root() {
        let mut state = ChainState::new();
        let tx = build_tx(&state, vec![], vec![mk_output(1, 1)]);
        let mut probe = state.clone();
        let st = apply_tx(&mut probe, &tx.body).unwrap();
        let header = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: st.new_state_root,
            tx_root: [0xFFu8; 32],
            timestamp: 1,
            miner_address: Address([9u8; 32]),
            nonce: 0,
            proof_transcript_hash: [0u8; 32],
        };
        let block = Block {
            header,
            transactions: vec![tx],
        };
        assert_eq!(
            apply_block(&mut state, &block),
            Err(BlockApplyError::HeaderTxRootMismatch)
        );
        assert_eq!(state.next_leaf_index, 0);
    }

    #[test]
    fn apply_block_rejects_broken_chain() {
        let mut state = ChainState::new();
        let tx1 = build_tx(&state, vec![], vec![mk_output(1, 1)]);
        // Second tx also uses the pre-tx1 root — not chained.
        let tx2 = build_tx(&state, vec![], vec![mk_output(2, 2)]);
        let txs = vec![tx1, tx2];
        let header = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [0u8; 32],
            tx_root: compute_tx_root(&txs),
            timestamp: 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            proof_transcript_hash: [0u8; 32],
        };
        let block = Block {
            header,
            transactions: txs,
        };
        assert_eq!(
            apply_block(&mut state, &block),
            Err(BlockApplyError::UnchainedPrevRoot)
        );
    }

    #[test]
    fn empty_block_tx_root_is_zero() {
        assert_eq!(compute_tx_root(&[]), [0u8; 32]);
    }

    #[test]
    fn proof_transcript_hash_is_deterministic() {
        assert_eq!(
            proof_transcript_hash(b"abc"),
            proof_transcript_hash(b"abc")
        );
        assert_ne!(proof_transcript_hash(b"a"), proof_transcript_hash(b"b"));
    }

    #[test]
    fn block_wire_roundtrip() {
        let state = ChainState::new();
        let tx = build_tx(&state, vec![], vec![mk_output(1, 1)]);
        let mut probe = state.clone();
        let st = apply_tx(&mut probe, &tx.body).unwrap();
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: st.new_state_root,
                tx_root: compute_tx_root(std::slice::from_ref(&tx)),
                timestamp: 42,
                miner_address: Address([7u8; 32]),
                nonce: 99,
                proof_transcript_hash: proof_transcript_hash(b"hello"),
            },
            transactions: vec![tx],
        };
        let bytes = block.to_bytes();
        let back = Block::from_bytes(&bytes).expect("decode");
        assert_eq!(back.header, block.header);
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
                miner_address: Address([0u8; 32]),
                nonce: 0,
                proof_transcript_hash: [0u8; 32],
            },
            transactions: vec![],
        };
        let mut bytes = block.to_bytes();
        bytes.push(0);
        assert_eq!(Block::from_bytes(&bytes), Err(WireError::TrailingBytes));
    }

    #[test]
    fn block_rejects_wrong_version() {
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [0u8; 32],
                tx_root: [0u8; 32],
                timestamp: 0,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                proof_transcript_hash: [0u8; 32],
            },
            transactions: vec![],
        };
        let mut bytes = block.to_bytes();
        bytes[0] = 0xFF;
        assert_eq!(Block::from_bytes(&bytes), Err(WireError::UnknownVersion));
    }
}
