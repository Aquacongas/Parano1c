// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded ReuseGuard for exact-state ABA protection.

use noid_core::Block128;
use noid_poseidon2b::native::compression::{compress_with_tag, Poseidon2bSponge};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_RGDBUCK, TAG_RGDNODE};

use crate::consensus::params::ANCHOR_DEPTH;
use crate::exact_state_hash::StateHash;

/// Slot reuse quarantine length.
pub const REUSE_DELAY: u64 = ANCHOR_DEPTH + 1;
/// Fixed ring size for guard buckets.
pub const REUSE_GUARD_BUCKETS: usize = 256;
const GUARD_DEPTH: usize = 8;
pub const REUSE_GUARD_DEPTH: usize = GUARD_DEPTH;

/// One canonical ReuseGuard bucket.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum GuardBucket {
    #[default]
    Empty,
    Occupied {
        absolute_height: u64,
        spent_slots: Vec<u32>,
    },
}

/// Fixed-size ReuseGuard state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReuseGuard {
    buckets: [GuardBucket; REUSE_GUARD_BUCKETS],
    root: StateHash,
}

/// Returned by [`ReuseGuard::apply_spends`] for non-empty spend blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardBucketUpdate {
    pub bucket_index: usize,
    pub old_bucket: GuardBucket,
    pub new_bucket: GuardBucket,
    pub siblings: [StateHash; GUARD_DEPTH],
    pub old_root: StateHash,
    pub new_root: StateHash,
}

/// Errors returned by ReuseGuard operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReuseGuardError {
    BucketIndexOutOfRange {
        index: usize,
    },
    BucketHeightMismatch {
        index: usize,
        absolute_height: u64,
    },
    EmptyOccupiedBucket {
        index: usize,
    },
    UnsortedOrDuplicateSlots {
        index: usize,
    },
    ActiveBucketOverwrite {
        index: usize,
        old_height: u64,
        height: u64,
    },
    RootMismatch,
}

impl core::fmt::Display for ReuseGuardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BucketIndexOutOfRange { index } => {
                write!(f, "reuse guard bucket index {index} out of range")
            }
            Self::BucketHeightMismatch {
                index,
                absolute_height,
            } => write!(
                f,
                "bucket height {absolute_height} is not congruent to index {index}"
            ),
            Self::EmptyOccupiedBucket { index } => {
                write!(f, "occupied reuse guard bucket {index} has no spent slots")
            }
            Self::UnsortedOrDuplicateSlots { index } => {
                write!(
                    f,
                    "reuse guard bucket {index} slots are not strictly sorted"
                )
            }
            Self::ActiveBucketOverwrite {
                index,
                old_height,
                height,
            } => write!(
                f,
                "height {height} tried to overwrite active bucket {index} from {old_height}"
            ),
            Self::RootMismatch => write!(f, "reuse guard root mismatch"),
        }
    }
}

impl std::error::Error for ReuseGuardError {}

impl Default for ReuseGuard {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl ReuseGuard {
    /// Build an empty guard.
    pub fn new_empty() -> Self {
        let buckets = std::array::from_fn(|_| GuardBucket::Empty);
        let root = guard_root_from_buckets(&buckets);
        Self { buckets, root }
    }

    /// Build a guard from canonical buckets and verify the derived root.
    pub fn from_buckets(
        buckets: [GuardBucket; REUSE_GUARD_BUCKETS],
    ) -> Result<Self, ReuseGuardError> {
        validate_buckets(&buckets)?;
        let root = guard_root_from_buckets(&buckets);
        Ok(Self { buckets, root })
    }

    /// Return whether `slot` is active-guarded at `at_height`.
    pub fn is_guarded(&self, slot: u32, at_height: u64) -> bool {
        self.buckets.iter().any(|bucket| match bucket {
            GuardBucket::Empty => false,
            GuardBucket::Occupied {
                absolute_height,
                spent_slots,
            } => {
                is_active_height(*absolute_height, at_height)
                    && spent_slots.binary_search(&slot).is_ok()
            }
        })
    }

    #[inline]
    pub fn bucket(&self, index: usize) -> &GuardBucket {
        &self.buckets[index]
    }

    #[inline]
    pub fn root(&self) -> StateHash {
        self.root
    }

    /// Return the canonical bucket array for durable storage.
    #[inline]
    pub fn buckets(&self) -> &[GuardBucket; REUSE_GUARD_BUCKETS] {
        &self.buckets
    }

    /// Rebuild the derived root from canonical buckets and compare it to the
    /// stored root. The active set is scanned from buckets in this implementation.
    pub fn rebuild_cache_and_verify_root(&mut self) -> Result<(), ReuseGuardError> {
        validate_buckets(&self.buckets)?;
        let rebuilt = guard_root_from_buckets(&self.buckets);
        if rebuilt != self.root {
            return Err(ReuseGuardError::RootMismatch);
        }
        Ok(())
    }

    /// Check whether bucket `height % 256` can be overwritten at `height`.
    pub fn ensure_bucket_reusable_at(&self, height: u64) -> Result<(), ReuseGuardError> {
        let bucket_index = bucket_index_for_height(height);
        ensure_reusable_bucket(&self.buckets[bucket_index], bucket_index, height)
    }

    /// Apply the current block's sorted unique spend set.
    ///
    /// Empty spend sets leave the root byte-identical and return `Ok(None)`.
    pub fn apply_spends(
        &mut self,
        height: u64,
        spent_slots: &[u32],
    ) -> Result<Option<GuardBucketUpdate>, ReuseGuardError> {
        if spent_slots.is_empty() {
            return Ok(None);
        }
        let bucket_index = bucket_index_for_height(height);
        validate_spent_slots(spent_slots, bucket_index)?;
        let old_bucket = self.buckets[bucket_index].clone();
        ensure_reusable_bucket(&old_bucket, bucket_index, height)?;
        let siblings = guard_path(&self.buckets, bucket_index);
        let old_root = self.root;
        let new_bucket = GuardBucket::Occupied {
            absolute_height: height,
            spent_slots: spent_slots.to_vec(),
        };
        self.buckets[bucket_index] = new_bucket.clone();
        self.root = guard_root_from_buckets(&self.buckets);
        let new_root = self.root;
        Ok(Some(GuardBucketUpdate {
            bucket_index,
            old_bucket,
            new_bucket,
            siblings,
            old_root,
            new_root,
        }))
    }

    /// Install a bucket update that has already been authenticated by an exact
    /// state transition proof.
    pub fn apply_verified_bucket_update(
        &mut self,
        bucket_index: usize,
        new_bucket: GuardBucket,
        expected_root: StateHash,
    ) -> Result<(), ReuseGuardError> {
        if bucket_index >= REUSE_GUARD_BUCKETS {
            return Err(ReuseGuardError::BucketIndexOutOfRange {
                index: bucket_index,
            });
        }
        let mut next = self.buckets.clone();
        next[bucket_index] = new_bucket;
        validate_buckets(&next)?;
        let root = guard_root_from_buckets(&next);
        if root != expected_root {
            return Err(ReuseGuardError::RootMismatch);
        }
        self.buckets = next;
        self.root = root;
        Ok(())
    }
}

/// Return the ring bucket index for a block height.
#[inline]
pub fn bucket_index_for_height(height: u64) -> usize {
    (height as usize) & (REUSE_GUARD_BUCKETS - 1)
}

/// Return true iff a bucket written at `spent_height` is active at `at_height`.
#[inline]
pub fn is_active_height(spent_height: u64, at_height: u64) -> bool {
    at_height < spent_height.saturating_add(REUSE_DELAY)
}

/// Hash a canonical guard bucket.
pub fn guard_bucket_hash(bucket: &GuardBucket) -> StateHash {
    let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_RGDBUCK));
    match bucket {
        GuardBucket::Empty => {
            s.absorb(Block128::from(0u8));
        }
        GuardBucket::Occupied {
            absolute_height,
            spent_slots,
        } => {
            s.absorb_pair(Block128::from(1u8), Block128::from(*absolute_height));
            s.absorb(Block128::from(spent_slots.len() as u64));
            for &slot in spent_slots {
                s.absorb(Block128::from(slot));
            }
        }
    }
    s.finalize()
}

/// Hash one ReuseGuard Merkle node.
pub fn guard_node_hash(left: StateHash, right: StateHash) -> StateHash {
    compress_with_tag(TAG_RGDNODE, &left, &right)
}

/// Compute the fixed depth-8 guard root.
pub fn guard_root_from_buckets(buckets: &[GuardBucket; REUSE_GUARD_BUCKETS]) -> StateHash {
    let mut level: Vec<StateHash> = buckets.iter().map(guard_bucket_hash).collect();
    for _ in 0..GUARD_DEPTH {
        level = level
            .chunks_exact(2)
            .map(|pair| guard_node_hash(pair[0], pair[1]))
            .collect();
    }
    level[0]
}

/// Verify one fixed-depth bucket update and return `(old_root, new_root)`.
pub fn verify_guard_update_roots(
    bucket_index: usize,
    old_bucket: &GuardBucket,
    new_bucket: &GuardBucket,
    siblings: &[StateHash; GUARD_DEPTH],
) -> Result<(StateHash, StateHash), ReuseGuardError> {
    if bucket_index >= REUSE_GUARD_BUCKETS {
        return Err(ReuseGuardError::BucketIndexOutOfRange {
            index: bucket_index,
        });
    }
    validate_bucket_at(bucket_index, old_bucket)?;
    validate_bucket_at(bucket_index, new_bucket)?;
    let old_root = reconstruct_guard_root(bucket_index, guard_bucket_hash(old_bucket), siblings);
    let new_root = reconstruct_guard_root(bucket_index, guard_bucket_hash(new_bucket), siblings);
    Ok((old_root, new_root))
}

fn reconstruct_guard_root(
    bucket_index: usize,
    mut hash: StateHash,
    siblings: &[StateHash; GUARD_DEPTH],
) -> StateHash {
    let mut idx = bucket_index;
    for sibling in siblings {
        hash = if idx & 1 == 0 {
            guard_node_hash(hash, *sibling)
        } else {
            guard_node_hash(*sibling, hash)
        };
        idx >>= 1;
    }
    hash
}

fn guard_path(
    buckets: &[GuardBucket; REUSE_GUARD_BUCKETS],
    bucket_index: usize,
) -> [StateHash; GUARD_DEPTH] {
    let mut level: Vec<StateHash> = buckets.iter().map(guard_bucket_hash).collect();
    let mut idx = bucket_index;
    std::array::from_fn(|_| {
        let sibling = level[idx ^ 1];
        level = level
            .chunks_exact(2)
            .map(|pair| guard_node_hash(pair[0], pair[1]))
            .collect();
        idx >>= 1;
        sibling
    })
}

fn ensure_reusable_bucket(
    bucket: &GuardBucket,
    index: usize,
    height: u64,
) -> Result<(), ReuseGuardError> {
    validate_bucket_at(index, bucket)?;
    if let GuardBucket::Occupied {
        absolute_height, ..
    } = bucket
    {
        if absolute_height.saturating_add(REUSE_DELAY) > height {
            return Err(ReuseGuardError::ActiveBucketOverwrite {
                index,
                old_height: *absolute_height,
                height,
            });
        }
    }
    Ok(())
}

fn validate_buckets(buckets: &[GuardBucket; REUSE_GUARD_BUCKETS]) -> Result<(), ReuseGuardError> {
    for (idx, bucket) in buckets.iter().enumerate() {
        validate_bucket_at(idx, bucket)?;
    }
    Ok(())
}

fn validate_bucket_at(index: usize, bucket: &GuardBucket) -> Result<(), ReuseGuardError> {
    if index >= REUSE_GUARD_BUCKETS {
        return Err(ReuseGuardError::BucketIndexOutOfRange { index });
    }
    match bucket {
        GuardBucket::Empty => Ok(()),
        GuardBucket::Occupied {
            absolute_height,
            spent_slots,
        } => {
            if (*absolute_height as usize) & (REUSE_GUARD_BUCKETS - 1) != index {
                return Err(ReuseGuardError::BucketHeightMismatch {
                    index,
                    absolute_height: *absolute_height,
                });
            }
            validate_spent_slots(spent_slots, index)
        }
    }
}

fn validate_spent_slots(slots: &[u32], index: usize) -> Result<(), ReuseGuardError> {
    if slots.is_empty() {
        return Err(ReuseGuardError::EmptyOccupiedBucket { index });
    }
    if slots.windows(2).any(|w| w[0] >= w[1]) {
        return Err(ReuseGuardError::UnsortedOrDuplicateSlots { index });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_guard_root_is_deterministic() {
        let g1 = ReuseGuard::new_empty();
        let g2 = ReuseGuard::new_empty();
        assert_eq!(g1.root(), g2.root());
        assert!(!g1.is_guarded(7, 0));
    }

    #[test]
    fn active_boundary_is_exact() {
        let s = 1000;
        let mut guard = ReuseGuard::new_empty();
        guard.apply_spends(s, &[7, 9, 11]).unwrap();
        assert!(guard.is_guarded(7, s));
        assert!(guard.is_guarded(7, s + 1));
        assert!(guard.is_guarded(7, s + 144));
        assert!(!guard.is_guarded(7, s + 145));
    }

    #[test]
    fn no_spend_block_leaves_root_unchanged() {
        let mut guard = ReuseGuard::new_empty();
        let root = guard.root();
        let update = guard.apply_spends(42, &[]).unwrap();
        assert_eq!(update, None);
        assert_eq!(guard.root(), root);
    }

    #[test]
    fn ring_wrap_rejects_active_and_allows_expired_overwrite() {
        let mut guard = ReuseGuard::new_empty();
        guard.apply_spends(255, &[1]).unwrap();
        guard.apply_spends(256, &[2]).unwrap();
        assert!(guard.is_guarded(1, 300));
        assert!(guard.is_guarded(2, 300));
        guard.apply_spends(511, &[3]).unwrap();
        assert!(guard.is_guarded(3, 511));
        assert!(!guard.is_guarded(1, 511));
    }

    #[test]
    fn active_bucket_overwrite_rejects() {
        let mut buckets = std::array::from_fn(|_| GuardBucket::Empty);
        buckets[42] = GuardBucket::Occupied {
            absolute_height: 42,
            spent_slots: vec![1],
        };
        let mut guard = ReuseGuard::from_buckets(buckets).unwrap();
        assert_eq!(
            guard.apply_spends(42, &[2]),
            Err(ReuseGuardError::ActiveBucketOverwrite {
                index: 42,
                old_height: 42,
                height: 42
            })
        );
    }

    #[test]
    fn update_path_reconstructs_old_and_new_roots() {
        let mut guard = ReuseGuard::new_empty();
        let update = guard.apply_spends(42, &[2, 4, 6]).unwrap().unwrap();
        let (old_root, new_root) = verify_guard_update_roots(
            update.bucket_index,
            &update.old_bucket,
            &update.new_bucket,
            &update.siblings,
        )
        .unwrap();
        assert_eq!(old_root, update.old_root);
        assert_eq!(new_root, update.new_root);
        assert_eq!(new_root, guard.root());
    }

    #[test]
    fn wrong_path_or_bucket_changes_reconstructed_root() {
        let mut guard = ReuseGuard::new_empty();
        let mut update = guard.apply_spends(42, &[2, 4, 6]).unwrap().unwrap();
        update.siblings[0][0] ^= 1;
        let (_old_root, new_root) = verify_guard_update_roots(
            update.bucket_index,
            &update.old_bucket,
            &update.new_bucket,
            &update.siblings,
        )
        .unwrap();
        assert_ne!(new_root, guard.root());
    }

    #[test]
    fn unsorted_duplicate_or_empty_bucket_rejects() {
        let mut guard = ReuseGuard::new_empty();
        assert_eq!(
            guard.apply_spends(1, &[2, 2]),
            Err(ReuseGuardError::UnsortedOrDuplicateSlots { index: 1 })
        );
        let mut buckets = std::array::from_fn(|_| GuardBucket::Empty);
        buckets[5] = GuardBucket::Occupied {
            absolute_height: 5,
            spent_slots: vec![],
        };
        assert_eq!(
            ReuseGuard::from_buckets(buckets),
            Err(ReuseGuardError::EmptyOccupiedBucket { index: 5 })
        );
    }

    #[test]
    fn rebuild_detects_root_corruption() {
        let mut guard = ReuseGuard::new_empty();
        guard.apply_spends(7, &[1, 2]).unwrap();
        assert_eq!(guard.rebuild_cache_and_verify_root(), Ok(()));
        guard.root[0] ^= 1;
        assert_eq!(
            guard.rebuild_cache_and_verify_root(),
            Err(ReuseGuardError::RootMismatch)
        );
    }
}
