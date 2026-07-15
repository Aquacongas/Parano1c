// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! All consensus constants.

/// Target inter-block interval in seconds.
///
/// ASERT adjusts PoW difficulty so all hardware converges to this target.
/// Bounded below by `prove_block_time` on the miner's hardware; PoW is
/// ordering-only, not security-critical.
pub const BLOCK_TIME: u64 = 15;

/// Number of blocks per ASERT epoch.
pub const EPOCH_LENGTH: u64 = 6;

/// ASERT halflife in seconds = EPOCH_LENGTH × BLOCK_TIME.
pub const HALFLIFE: u64 = EPOCH_LENGTH * BLOCK_TIME; // 90s at BLOCK_TIME=15

/// Maximum seconds a block timestamp may exceed local wall clock.
pub const MAX_FUTURE_DRIFT: u64 = 120;

/// Number of previous blocks used for median-time-past.
pub const MEDIAN_TIME_BLOCKS: usize = 11;

// ---------------------------------------------------------------------------
// Block limits
// ---------------------------------------------------------------------------

/// Maximum transactions decoded in one block, including coinbase.
///
/// This is a hard decoder/DoS cap. The consensus throughput budget is the
/// semantic block budget below: 255 fixed-shape user transactions plus one
/// mandatory coinbase.
pub const BLOCK_MAX_TXS: usize = 256;

/// Fixed input capacity of every transaction body.
pub const MAX_INPUTS: usize = 8;

/// Fixed output capacity of every transaction body.
pub const MAX_OUTPUTS: usize = 2;

/// Maximum non-coinbase transactions accepted by consensus.
pub const BLOCK_MAX_USER_TXS: usize = BLOCK_MAX_TXS - 1;

/// Maximum live user inputs accepted in one block.
pub const BLOCK_MAX_LIVE_INPUTS: usize = 1_020;

/// Maximum live user outputs accepted in one block.
pub const BLOCK_MAX_USER_OUTPUTS: usize = 510;

/// Maximum bitmap-live user action capacity accepted by consensus.
pub const BLOCK_MAX_USER_ACTIONS: usize = BLOCK_MAX_LIVE_INPUTS + BLOCK_MAX_USER_OUTPUTS;

/// Maximum accepted live action count including the mandatory coinbase output.
pub const BLOCK_MAX_ACTIONS: usize = BLOCK_MAX_USER_ACTIONS + 1;

/// Maximum number of distinct dense state segments a block may make resident.
/// This is an availability/DoS bound and is checked before segment preload.
pub const BLOCK_MAX_DISTINCT_SEGMENTS: usize = 256;

// ---------------------------------------------------------------------------
// HistoryStep classes
// ---------------------------------------------------------------------------

/// Fixed-body user-transaction count tiers. Every HistoryStep-facing per-block
/// structure is padded up to the smallest tier holding the block's user
/// tx count, so the recursive relation sees a small fixed family of shapes
/// instead of per-count structures. Every node can derive each class matrix
/// locally. Blocks below the lowest tier (including coinbase-only blocks) pad
/// up to it with protocol ghost transactions; the worst-case padding ratio is
/// bounded by the largest adjacent-tier step (4x).
pub const USER_TX_CLASS_TIERS: [usize; 4] = [8, 32, 64, 255];

/// Smallest tier in `tiers` holding `count`, or None past the top tier.
#[inline]
fn class_tier_for(tiers: &[usize], count: usize) -> Option<usize> {
    tiers.iter().copied().find(|&tier| tier >= count)
}

/// Proof class tier for a block's user transaction count.
#[inline]
pub fn user_tx_class_tier(count: usize) -> Option<usize> {
    class_tier_for(&USER_TX_CLASS_TIERS, count)
}

/// Live-input (spend) capacity of a proof class: what the class's per-input
/// proof structures are padded to. Capped by the semantic
/// block budget, which admits the tier mix only up to the global
/// live-input maximum.
#[inline]
pub fn block_class_spend_capacity(user_tier: usize) -> usize {
    (user_tier * MAX_INPUTS).min(BLOCK_MAX_LIVE_INPUTS)
}

/// Live user-output capacity of one proof class.
#[inline]
pub fn block_class_output_capacity(user_tier: usize) -> usize {
    (user_tier * MAX_OUTPUTS).min(BLOCK_MAX_USER_OUTPUTS)
}

/// Maximum exact-state touched surface, including the mandatory coinbase.
#[inline]
pub fn block_class_touched_capacity(user_tier: usize) -> usize {
    block_class_spend_capacity(user_tier) + block_class_output_capacity(user_tier) + 1
}

/// Spend capacity of the proof class holding a block with the given user-tx
/// composition, or None past the tier tables (over consensus limits).
#[inline]
pub fn block_class_spend_capacity_for_count(user_txs: usize) -> Option<usize> {
    user_tx_class_tier(user_txs).map(block_class_spend_capacity)
}

/// Number of blocks for the transaction replay-protection epoch.
///
/// This is a separate protocol clock from ASERT's short difficulty epoch.
pub const TX_EPOCH_BLOCKS: u64 = 144;

const _: () = assert!(
    TX_EPOCH_BLOCKS == noid_tx::TX_EPOCH_BLOCKS,
    "noid_chain TX_EPOCH_BLOCKS must equal noid_tx"
);

// ---------------------------------------------------------------------------
// Finality
// ---------------------------------------------------------------------------

/// Consensus hard-finality depth.
///
/// Reorgs that would change the finalized prefix are rejected by fork choice.
/// Pre-launch provisional value; publication freeze must ratify it independently.
pub const CONSENSUS_FINALITY_DEPTH: u64 = 18;

/// Undo-log retention depth for local shallow reorg recovery.
///
/// This is intentionally separate from consensus finality. Retention may be
/// tuned for operational needs; it must not silently define finality.
pub const UNDO_RETENTION_DEPTH: u64 = 18;

/// Recent full-block retention depth for peer serving and normal catch-up.
///
/// Nodes keep accepted block bodies and undo material only for this recent
/// window, plus the preceding HistoryStep terminal. Headers remain permanent.
pub const RECENT_BLOCK_RETENTION_DEPTH: u64 = UNDO_RETENTION_DEPTH;

/// Number of finalised block headers used for the expansion trigger median.
/// Using median over this window makes the trigger immune to single-block spam.
/// Must be ≤ available recent-header retention.
pub const EXPANSION_WINDOW: u64 = CONSENSUS_FINALITY_DEPTH;

// ---------------------------------------------------------------------------
// Slot state
// ---------------------------------------------------------------------------

/// Initial `log_slots` at genesis: 2^24 = 16,777,216 slots.
pub const LOG_SLOTS_GENESIS: u32 = 24;

/// Maximum `log_slots`: 2^32 = 4,294,967,296 slots.
pub const LOG_SLOTS_MAX: u32 = 32;

/// Each segment holds 2^LOG_SEGMENT_SIZE slots.
pub const LOG_SEGMENT_SIZE: u32 = 16;

const _: () = assert!(
    LOG_SEGMENT_SIZE as usize == crate::fri_state::LOG_SEGMENT_SIZE,
    "consensus and state segment geometry must match"
);

/// Fraction of current capacity that triggers expansion (numerator/denominator).
/// When `active_slot_count * EXPAND_DENOM >= 2^log_slots * EXPAND_NUM`, expand.
pub const EXPAND_NUM: u64 = 3; // 75 %
pub const EXPAND_DENOM: u64 = 4;

// ---------------------------------------------------------------------------
// PoW
// ---------------------------------------------------------------------------

/// Genesis difficulty target = 2^237.
///
/// Calibrated to roughly the same wall-clock genesis solve time as the previous
/// difficulty floor, using production Poseidon2b PoW on the current 12-core laptop:
///   measured parallel Poseidon2b PoW ≈ 186 KH/s
///   avg_nonces = 2^(256-237) = 2^19 = 524,288
///   time = 524K / 186K ≈ 2.8s
///
/// LE 256-bit layout: byte 29 = 0x40 (bit 238 = bit 6 of byte 29).
/// Bytes 30-31 = 0x00 so the target value equals 2^238.
///
/// This is the minimum allowed difficulty floor. ASERT may only move harder.
/// Halved difficulty (2^237 -> 2^238 target, owner decision 2026-07-13) so
/// young-network block discovery is twice as fast; ASERT converges to
/// BLOCK_TIME either way.
pub const GENESIS_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[29] = 0x40; // bit 6 of byte 29 -> 2^(8*29+6) = 2^238
    t
};

/// Minimum cumulative PoW work required to accept a state snapshot.
///
/// Stored as LE u256, matching `add_work`/`block_work` layout.
///
/// # Derivation
///
/// Chainwork accounting uses the strict-`< target` expected-trial-count
/// formula:
///   Work(T) = floor((2^256 - 1) / T) + 1.
///
/// For `GENESIS_TARGET = 2^237`, every block contributes:
///   block_work(GENESIS_TARGET) = 2^19 = 524,288
///
/// We require CONSENSUS_FINALITY_DEPTH (18) blocks' worth of work:
///
///   MIN_SNAPSHOT_CHAINWORK = CONSENSUS_FINALITY_DEPTH * block_work(GENESIS_TARGET)
///                          = 18 * 2^19 = 9,437,184 = 0x0090_0000
///
/// # Why CONSENSUS_FINALITY_DEPTH?
///
/// Public snapshot sync uses the finalized O(1) boundary, and this chainwork
/// floor remains a resource/sanity guard:
///
///   tip < 18  -> no finalized history boundary and chainwork < threshold
///   tip >= 18 -> the finalized HistoryStep boundary may serve snapshots
///
/// # Security vs fake snapshots
///
///   - 155 fake MAX_TARGET blocks (work=2/block) -> chainwork = 310 << 9.4M -> FAILS
///   - 18 real blocks + genesis  -> chainwork >= 18 * 2^19 -> PASSES
pub const MIN_SNAPSHOT_CHAINWORK: [u8; 32] = {
    let mut w = [0u8; 32];
    // 18 * 2^19 = 0x90_0000 = 9,437,184
    // In LE bytes: byte[2] = 0x90.
    w[2] = 0x90; // = CONSENSUS_FINALITY_DEPTH(18) * block_work(GENESIS_TARGET)
    w
};

/// Minimum allowed target (maximum difficulty). Theoretical floor.
pub const MIN_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[0] = 1;
    t
};

/// Maximum allowed target (minimum difficulty = trivially satisfied).
pub const MAX_TARGET: [u8; 32] = [0xFF; 32];

// ---------------------------------------------------------------------------
// DA retention
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// Precision: 1 NOID = 1_000_000 μNOID (microNOID).
pub const MICRONOID_PER_NOID: u64 = 1_000_000;

/// Starting block reward at zero occupancy: 50 NOID.
pub const BASE_REWARD_MICRONOID: u64 = 50 * MICRONOID_PER_NOID;

/// Reward floor: 1 NOID forever.
pub const FLOOR_REWARD_MICRONOID: u64 = MICRONOID_PER_NOID;

// ---------------------------------------------------------------------------
// Height-tagged coinbase creation ids
// ---------------------------------------------------------------------------

/// High-bit tag marking a coinbase mint's `creation_id`.
///
/// Coinbase outputs store `creation_id = COINBASE_CREATION_TAG | mint_height`.
/// Normal mints use the monotone `alloc_counter` namespace, which consensus
/// keeps strictly below `2^63` (allocation fails closed at the namespace
/// boundary), so the two id spaces can never collide. Exactly one live
/// coinbase output exists per block (canonical coinbase bitmap), so tagged
/// ids stay unique per chain history.
pub const COINBASE_CREATION_TAG: u64 = 1 << 63;

/// True when a `creation_id` names a coinbase mint.
#[inline]
pub const fn is_coinbase_creation_id(creation_id: u64) -> bool {
    creation_id & COINBASE_CREATION_TAG != 0
}

/// The tagged `creation_id` of the unique coinbase output minted at `height`.
#[inline]
pub const fn coinbase_creation_id(height: u64) -> u64 {
    COINBASE_CREATION_TAG | height
}

/// Mint height encoded in a tagged coinbase `creation_id`.
#[inline]
pub const fn coinbase_creation_height(creation_id: u64) -> u64 {
    creation_id & !COINBASE_CREATION_TAG
}

/// Whether a live slot's creation id can exist at one authenticated chain
/// boundary. User outputs are bounded by the monotone allocator; coinbase
/// outputs occupy the disjoint tagged namespace and are bounded by mint
/// height instead.
pub const fn creation_id_within_boundary(
    creation_id: u64,
    alloc_counter: u64,
    height: u64,
) -> bool {
    if is_coinbase_creation_id(creation_id) {
        coinbase_creation_height(creation_id) <= height
    } else {
        creation_id <= alloc_counter
    }
}

// ---------------------------------------------------------------------------
// Slot allocator PRNG
// ---------------------------------------------------------------------------
// splitmix64 constants are embedded in noid_chain::consensus::allocator.
// No separate params needed — the algorithm uses fixed Weyl/mixing constants.

// ---------------------------------------------------------------------------
// Fee policy
// ---------------------------------------------------------------------------

/// Base minimum fee in μNOID per non-coinbase transaction.
pub const MIN_FEE_BASE: u64 = 5_000; // 0.005 NOID

/// Small anti-DoS fee charged per live input verified by a transaction.
///
/// Inputs do not grow chain state, so this intentionally stays much lower than
/// the output fee. It keeps very large-input transactions from becoming free
/// relay/prover spam without penalising useful state-shrinking transactions.
pub const FEE_PER_INPUT: u64 = 100; // 0.0001 NOID per input

/// Fee charged per live output created by a transaction.
///
/// Outputs are the main user-visible driver of fee because they create UTXOs and
/// may increase state pressure. The 1-input/2-output low-pressure send remains
/// at the historical 9_000 μNOID baseline together with state-growth burn.
pub const FEE_PER_OUTPUT: u64 = 700; // 0.0007 NOID per output

/// Base fee charged per net-new live UTXO slot at low occupancy.
/// This state-growth component is burned by consensus.
pub const STATE_GROWTH_FEE_BASE: u64 = 2_500; // 0.0025 NOID per net-new slot

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_block_caps_are_exact() {
        assert_eq!(BLOCK_MAX_TXS, 256);
        assert_eq!(BLOCK_MAX_USER_TXS, 255);
        assert_eq!(MAX_INPUTS, 8);
        assert_eq!(MAX_OUTPUTS, 2);
        assert_eq!(BLOCK_MAX_LIVE_INPUTS, 1_020);
        assert_eq!(BLOCK_MAX_USER_OUTPUTS, 510);
        assert_eq!(BLOCK_MAX_USER_ACTIONS, 1_530);
        assert_eq!(BLOCK_MAX_ACTIONS, 1_531);
    }

    #[test]
    fn history_step_user_classes_are_exact() {
        assert_eq!(USER_TX_CLASS_TIERS, [8, 32, 64, 255]);
        assert_eq!(user_tx_class_tier(0), Some(8));
        assert_eq!(user_tx_class_tier(9), Some(32));
        assert_eq!(user_tx_class_tier(255), Some(255));
        assert_eq!(user_tx_class_tier(256), None);
        assert_eq!(block_class_spend_capacity(255), BLOCK_MAX_LIVE_INPUTS);
        assert_eq!(block_class_output_capacity(255), BLOCK_MAX_USER_OUTPUTS);
        assert_eq!(block_class_touched_capacity(255), 1_531);
    }

    #[test]
    fn creation_id_boundary_uses_disjoint_user_and_coinbase_bounds() {
        assert!(creation_id_within_boundary(9, 9, 7));
        assert!(!creation_id_within_boundary(10, 9, 7));
        assert!(creation_id_within_boundary(coinbase_creation_id(7), 0, 7));
        assert!(!creation_id_within_boundary(
            coinbase_creation_id(8),
            u64::MAX,
            7,
        ));
    }

    #[test]
    fn transaction_epoch_is_not_asert_epoch() {
        assert_eq!(TX_EPOCH_BLOCKS, 144);
        assert_ne!(TX_EPOCH_BLOCKS, EPOCH_LENGTH);
    }
}
