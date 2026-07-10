// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Immutable local checkpoint packages.
//!
//! A checkpoint package is not a consensus acceptance shortcut. It is a
//! deterministic, immutable record over an already-accepted finalized prefix:
//! the exact state root, active UTXO segment payloads, and retained
//! block/proof/authorization-sidecar byte roots.

use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

const MANIFEST_DIGEST_DOMAIN: &[u8] = b"NOID_IMMUTABLE_CHECKPOINT_MANIFEST";
const MERKLE_EMPTY_TAG: &[u8] = b"empty";
const MERKLE_LEAF_TAG: &[u8] = b"leaf";
const MERKLE_NODE_TAG: &[u8] = b"node";
const MERKLE_ROOT_TAG: &[u8] = b"root";

pub const CHECKPOINT_BLOCK_BODY_ROOT_DOMAIN: &[u8] = b"NOID_CHECKPOINT_BLOCK_BODY_ROOT";
pub const CHECKPOINT_BLOCK_PROOF_ROOT_DOMAIN: &[u8] = b"NOID_CHECKPOINT_BLOCK_PROOF_ROOT";
pub const CHECKPOINT_AUTH_SIDECAR_ROOT_DOMAIN: &[u8] = b"NOID_CHECKPOINT_AUTH_SIDECAR_ROOT";
pub const CHECKPOINT_SEGMENT_PAYLOAD_ROOT_DOMAIN: &[u8] = b"NOID_CHECKPOINT_SEGMENT_PAYLOAD_ROOT";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImmutableCheckpointManifest {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub state_root: [u8; 32],
    /// Retained post-genesis block payload range covered by the byte roots.
    /// Empty at genesis: `covered_from = 1`, `covered_to = 0`.
    pub covered_from: u64,
    pub covered_to: u64,
    pub block_body_root: [u8; 32],
    pub block_proof_root: [u8; 32],
    pub block_auth_sidecar_root: [u8; 32],
    pub segment_payload_root: [u8; 32],
    pub segment_count: u32,
}

impl ImmutableCheckpointManifest {
    pub fn checkpoint_id(&self) -> [u8; 32] {
        checkpoint_manifest_digest(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointSegmentPayload {
    pub segment_id: u16,
    pub effective_log_segment_size: u8,
    pub encoded_segment: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImmutableCheckpointPackage {
    pub manifest: ImmutableCheckpointManifest,
    pub segments: Vec<CheckpointSegmentPayload>,
}

impl ImmutableCheckpointPackage {
    pub fn checkpoint_id(&self) -> [u8; 32] {
        self.manifest.checkpoint_id()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointCoverage {
    pub checkpoint_id: [u8; 32],
    pub height: u64,
    pub block_hash: [u8; 32],
    pub covered_from: u64,
    pub covered_to: u64,
    /// `None` means this is local package coverage only. Pruning and public
    /// trustless snapshot sync must wait until a real history proof
    /// explicitly covers this prefix.
    pub history_proof_covered_to: Option<u64>,
}

pub fn checkpoint_manifest_digest(manifest: &ImmutableCheckpointManifest) -> [u8; 32] {
    let bytes = bincode::serialize(manifest)
        .expect("ImmutableCheckpointManifest serialization must be infallible");
    poseidon2b_hash_byte_slices(MANIFEST_DIGEST_DOMAIN, &[&bytes])
}

pub fn checkpoint_leaf_hash(domain: &[u8], ordinal: u64, bytes: &[u8]) -> [u8; 32] {
    let ordinal_bytes = ordinal.to_le_bytes();
    poseidon2b_hash_byte_slices(domain, &[MERKLE_LEAF_TAG, &ordinal_bytes, bytes])
}

pub fn checkpoint_merkle_root(domain: &[u8], leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return poseidon2b_hash_byte_slices(domain, &[MERKLE_EMPTY_TAG]);
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(poseidon2b_hash_byte_slices(
                domain,
                &[MERKLE_NODE_TAG, &pair[0], right],
            ));
        }
        level = next;
    }

    let leaf_count = (leaves.len() as u64).to_le_bytes();
    poseidon2b_hash_byte_slices(domain, &[MERKLE_ROOT_TAG, &leaf_count, &level[0]])
}

pub fn checkpoint_payload_root<I>(domain: &[u8], leaves: I) -> [u8; 32]
where
    I: IntoIterator<Item = (u64, Vec<u8>)>,
{
    let leaf_hashes: Vec<[u8; 32]> = leaves
        .into_iter()
        .map(|(ordinal, bytes)| checkpoint_leaf_hash(domain, ordinal, &bytes))
        .collect();
    checkpoint_merkle_root(domain, &leaf_hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_merkle_root_is_deterministic_and_ordered() {
        let a = checkpoint_payload_root(b"TEST", [(1, b"a".to_vec()), (2, b"b".to_vec())]);
        let b = checkpoint_payload_root(b"TEST", [(1, b"a".to_vec()), (2, b"b".to_vec())]);
        let c = checkpoint_payload_root(b"TEST", [(2, b"b".to_vec()), (1, b"a".to_vec())]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn manifest_digest_changes_when_roots_change() {
        let mut manifest = ImmutableCheckpointManifest {
            height: 7,
            block_hash: [1; 32],
            cumulative_chainwork: [2; 32],
            log_slots: 24,
            active_slot_count: 5,
            alloc_counter: 8,
            state_root: [5; 32],
            covered_from: 1,
            covered_to: 7,
            block_body_root: [6; 32],
            block_proof_root: [7; 32],
            block_auth_sidecar_root: [8; 32],
            segment_payload_root: [9; 32],
            segment_count: 2,
        };
        let a = manifest.checkpoint_id();
        manifest.block_body_root[0] ^= 1;
        assert_ne!(a, manifest.checkpoint_id());
    }
}
