// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded ReuseGuard for exact-state ABA protection.

use std::collections::BTreeSet;

use noid_core::Block128;
use noid_poseidon2b::native::compression::{compress_with_tag, Poseidon2bSponge};
use noid_core::TowerField;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_RGDBUCK, TAG_RGDNODE, TAG_RGDSLOT};
use noid_tx::Transaction;

use crate::consensus::params::{ANCHOR_DEPTH, BLOCK_MAX_LIVE_INPUTS};
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
        #[serde(deserialize_with = "deserialize_spent_slots")]
        spent_slots: Vec<u32>,
    },
}

fn deserialize_spent_slots<'de, D>(deserializer: D) -> Result<Vec<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoundedSlots;

    impl<'de> serde::de::Visitor<'de> for BoundedSlots {
        type Value = Vec<u32>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                formatter,
                "at most {BLOCK_MAX_LIVE_INPUTS} reuse-guard slots"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            if let Some(actual) = seq.size_hint() {
                if actual > BLOCK_MAX_LIVE_INPUTS {
                    return Err(serde::de::Error::invalid_length(actual, &self));
                }
            }
            let mut slots = Vec::with_capacity(
                seq.size_hint()
                    .unwrap_or(0)
                    .min(BLOCK_MAX_LIVE_INPUTS),
            );
            while let Some(slot) = seq.next_element()? {
                if slots.len() == BLOCK_MAX_LIVE_INPUTS {
                    return Err(serde::de::Error::invalid_length(
                        slots.len().saturating_add(1),
                        &self,
                    ));
                }
                slots.push(slot);
            }
            Ok(slots)
        }
    }

    deserializer.deserialize_seq(BoundedSlots)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    TooManySpentSlots {
        index: usize,
        actual: usize,
        max: usize,
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
            Self::TooManySpentSlots { index, actual, max } => write!(
                f,
                "reuse guard bucket {index} has {actual} spent slots, maximum is {max}"
            ),
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

/// Kind of slot action checked against ReuseGuard and the current block prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseGuardActionKind {
    Spend,
    Mint,
}

/// Errors returned by the shared ReuseGuard action predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseGuardActionError {
    /// The action targets a slot quarantined by a recent spend.
    ActiveGuardedSlot { slot_index: u32 },
    /// A block prefix already spent this slot and then tried to recreate it.
    MintAfterSpendSameBlock { slot_index: u32 },
}

impl core::fmt::Display for ReuseGuardActionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ActiveGuardedSlot { slot_index } => {
                write!(f, "slot {slot_index} is active in the reuse guard")
            }
            Self::MintAfterSpendSameBlock { slot_index } => write!(
                f,
                "slot {slot_index} cannot be minted after a spend in the same block"
            ),
        }
    }
}

impl std::error::Error for ReuseGuardActionError {}

/// Stateful ReuseGuard predicate for an ordered block action stream.
///
/// The state records spends already accepted in the current block so a later
/// mint cannot reuse their slots. A mint followed by a spend remains legal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReuseGuardActionState {
    spent_in_block: BTreeSet<u32>,
}

impl ReuseGuardActionState {
    /// Check a mint without changing the accepted block prefix.
    pub fn validate_mint(
        &self,
        guard: &ReuseGuard,
        height: u64,
        slot_index: u32,
    ) -> Result<(), ReuseGuardActionError> {
        if guard.is_guarded(slot_index, height) {
            return Err(ReuseGuardActionError::ActiveGuardedSlot { slot_index });
        }
        if self.spent_in_block.contains(&slot_index) {
            return Err(ReuseGuardActionError::MintAfterSpendSameBlock { slot_index });
        }
        Ok(())
    }

    pub fn validate_action(
        &mut self,
        guard: &ReuseGuard,
        height: u64,
        kind: ReuseGuardActionKind,
        slot_index: u32,
    ) -> Result<(), ReuseGuardActionError> {
        match kind {
            ReuseGuardActionKind::Spend => {
                if guard.is_guarded(slot_index, height) {
                    return Err(ReuseGuardActionError::ActiveGuardedSlot { slot_index });
                }
                self.spent_in_block.insert(slot_index);
            }
            ReuseGuardActionKind::Mint => {
                self.validate_mint(guard, height, slot_index)?;
            }
        }
        Ok(())
    }

    /// Validate one transaction in canonical input-then-output action order.
    pub fn validate_transaction(
        &mut self,
        guard: &ReuseGuard,
        height: u64,
        tx: &Transaction,
    ) -> Result<(), ReuseGuardActionError> {
        for input in tx.body.inputs.iter().filter(|input| input.valid) {
            self.validate_action(
                guard,
                height,
                ReuseGuardActionKind::Spend,
                input.slot_index,
            )?;
        }
        for output in tx.body.outputs.iter().filter(|output| output.valid) {
            self.validate_action(
                guard,
                height,
                ReuseGuardActionKind::Mint,
                output.slot_index,
            )?;
        }
        Ok(())
    }
}

/// Validate the ordered ReuseGuard action stream of a complete block body.
pub fn validate_reuse_guard_actions(
    guard: &ReuseGuard,
    height: u64,
    txs: &[Transaction],
) -> Result<(), ReuseGuardActionError> {
    let mut state = ReuseGuardActionState::default();
    for tx in txs {
        state.validate_transaction(guard, height, tx)?;
    }
    Ok(())
}

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

/// Hash a canonical spent-slot list: the inner digest nested inside a guard
/// bucket leaf. Keeping the (unbounded) slot list one indirection below the
/// leaf means any consumer that only needs to bind a bucket's height — in
/// particular the reuse-expiry check on the bucket being overwritten — can
/// open the constant-size leaf preimage without ever walking the old list.
pub fn guard_slots_digest(spent_slots: &[u32]) -> [Block128; 2] {
    let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_RGDSLOT));
    s.absorb(Block128::from(spent_slots.len() as u64));
    for &slot in spent_slots {
        s.absorb(Block128::from(slot));
    }
    crate::exact_state_hash::fields_from_digest(s.finalize())
}

/// Hash a canonical guard bucket leaf: a fixed four-field sponge over
/// `(occupied, absolute_height, slots_digest)`. Empty buckets hash the
/// all-zero preimage; occupied buckets nest [`guard_slots_digest`].
pub fn guard_bucket_hash(bucket: &GuardBucket) -> StateHash {
    let (occupied, absolute_height, digest) = match bucket {
        GuardBucket::Empty => (Block128::ZERO, Block128::ZERO, [Block128::ZERO; 2]),
        GuardBucket::Occupied {
            absolute_height,
            spent_slots,
        } => (
            Block128::from(1u8),
            Block128::from(*absolute_height),
            guard_slots_digest(spent_slots),
        ),
    };
    let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_RGDBUCK));
    s.absorb_pair(occupied, absolute_height);
    s.absorb_pair(digest[0], digest[1]);
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
    // A block can spend at most the semantic live-input budget, so no
    // canonical bucket may carry more. The serde visitor enforces the same
    // limit before allocating a decoded vector.
    if slots.len() > BLOCK_MAX_LIVE_INPUTS {
        return Err(ReuseGuardError::TooManySpentSlots {
            index,
            actual: slots.len(),
            max: BLOCK_MAX_LIVE_INPUTS,
        });
    }
    if slots.windows(2).any(|w| w[0] >= w[1]) {
        return Err(ReuseGuardError::UnsortedOrDuplicateSlots { index });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::{hash_tx_body, TxBody, TxInput, TxOutput, TxShape};

    fn action_tx(input_slots: &[u32], output_slots: &[u32]) -> Transaction {
        let body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: input_slots
                .iter()
                .copied()
                .map(|slot_index| TxInput {
                    slot_index,
                    value: 1,
                    owner: Address([1u8; 32]),
                    spend_secret: SpendSecret([2u8; 32]),
                    valid: true,
                })
                .collect(),
            outputs: output_slots
                .iter()
                .copied()
                .map(|slot_index| TxOutput {
                    slot_index,
                    value: 1,
                    owner: Address([1u8; 32]),
                    valid: true,
                })
                .collect(),
            is_coinbase: false,
        };
        let tx_body_hash = hash_tx_body(
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        Transaction { body, tx_body_hash }
    }

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
    fn spent_slot_bucket_cap_accepts_1020_and_rejects_1021() {
        assert_eq!(BLOCK_MAX_LIVE_INPUTS, 1020);
        let mut guard = ReuseGuard::new_empty();
        let at_cap: Vec<u32> = (0..BLOCK_MAX_LIVE_INPUTS as u32).collect();
        guard.apply_spends(1, &at_cap).unwrap();
        let encoded_at_cap = bincode::serialize(&GuardBucket::Occupied {
            absolute_height: 1,
            spent_slots: at_cap,
        })
        .unwrap();
        bincode::deserialize::<GuardBucket>(&encoded_at_cap).unwrap();

        let above_cap: Vec<u32> = (0..=BLOCK_MAX_LIVE_INPUTS as u32).collect();
        assert_eq!(
            guard.apply_spends(2, &above_cap),
            Err(ReuseGuardError::TooManySpentSlots {
                index: 2,
                actual: 1021,
                max: 1020,
            })
        );
        let encoded_above_cap = bincode::serialize(&GuardBucket::Occupied {
            absolute_height: 2,
            spent_slots: above_cap,
        })
        .unwrap();
        assert!(bincode::deserialize::<GuardBucket>(&encoded_above_cap).is_err());
    }

    #[test]
    fn shared_action_checker_enforces_expiry_and_action_order() {
        let mut guard = ReuseGuard::new_empty();
        guard.apply_spends(1, &[7]).unwrap();
        let mint_guarded = action_tx(&[], &[7]);
        assert_eq!(
            validate_reuse_guard_actions(&guard, 145, &[mint_guarded.clone()]),
            Err(ReuseGuardActionError::ActiveGuardedSlot { slot_index: 7 })
        );
        validate_reuse_guard_actions(&guard, 146, &[mint_guarded]).unwrap();

        let empty_guard = ReuseGuard::new_empty();
        let spend = action_tx(&[9], &[]);
        let mint = action_tx(&[], &[9]);
        assert_eq!(
            validate_reuse_guard_actions(&empty_guard, 10, &[spend.clone(), mint.clone()]),
            Err(ReuseGuardActionError::MintAfterSpendSameBlock { slot_index: 9 })
        );
        validate_reuse_guard_actions(&empty_guard, 10, &[mint, spend]).unwrap();
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
