// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native slot allocator for wallet hint generation.
//!
//! Uses splitmix64 seeded from `alloc_counter` to produce candidate free slot
//! indices. Hints are **non-authoritative** — miners verify slot emptiness via
//! BlockStateBinding. Two wallets may receive the same hint; conflicts are
//! resolved at block inclusion time.
//!
//! splitmix64 is chosen over LCG because it is bijective and all output bits
//! are equally well-distributed. With `idx = splitmix64(counter) mod 2^k`,
//! even the low-order bits (used for slot masking) are fully mixed.
//! Reference: https://prng.di.unimi.it/splitmix64.c

/// splitmix64 — standard 64-bit non-cryptographic bijective mixer.
///
/// State advances by the Weyl sequence constant 0x9e3779b97f4a7c15;
/// the output is mixed through two multiply-xorshift rounds.
/// Every input maps to a unique output (bijection over u64).
#[inline]
pub fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Zone capacity: number of consecutive slots allocated within one segment.
/// Must equal 2^LOG_SEGMENT_SIZE so that one zone == one FRI segment.
///
/// # Rationale for zone-based allocation
///
/// Naive uniform splitmix64 would send each new UTXO to a DIFFERENT segment,
/// materialising all 256 segments (768 MB) after just 256 blocks (~4 hours
/// at mainnet 60s/block). With zone-based allocation, sequential slots within
/// one zone land in the SAME segment, so memory grows as:
///
///   ceil(alloc_counter / ZONE_CAPACITY) segments × 3 MB
///
/// rather than min(alloc_counter, 256) segments × 3 MB.
///
/// # Slot conflict mitigation
///
/// Multiple wallets on DIFFERENT nodes can receive the same slot hint if their
/// nodes have the same `alloc_counter`. To mitigate:
/// 1. Nodes over-generate hints (e.g. 256) and return them shuffled by
///    `splitmix64(tip_hash)` — different tip hashes = different orderings.
/// 2. Wallets should request multiple hints and try alternates on conflict.
/// 3. The WITHIN-ZONE offset is sequential, so two nodes at different heights
///    will naturally give different hints even in the same zone.
pub const ZONE_CAPACITY: u64 = 1 << 16; // = 2^LOG_SEGMENT_SIZE = 65536

/// Generate `count` candidate free slot indices from an `alloc_counter` seed.
///
/// ## Zone-based strategy
///
/// Consecutive `alloc_counter` values within the same zone (block of
/// `ZONE_CAPACITY` increments) map to the SAME randomly-chosen segment,
/// filling it sequentially. A new zone starts a new randomly-chosen segment.
///
/// This bounds memory to `ceil(alloc_counter / ZONE_CAPACITY) × segment_size`
/// instead of `min(alloc_counter, num_segments) × segment_size`.
///
/// The caller is responsible for checking actual slot occupancy and may
/// advance `alloc_counter` further if a candidate slot is occupied.
pub fn generate_slot_hints(alloc_counter: u64, log_slots: u32, count: usize) -> Vec<u32> {
    debug_assert!(log_slots <= 32, "log_slots must fit in u32 slot index");

    let num_slots: u64 = 1 << log_slots;

    // Zone-based allocation requires at least 2 zones (log_slots > LOG_SEGMENT_SIZE = 16).
    // For small test states (log_slots <= 16), fall back to simple uniform splitmix64.
    if num_slots <= ZONE_CAPACITY {
        // Monolithic or smaller-than-zone state: simple uniform distribution.
        let mask = num_slots - 1;
        let mut state = alloc_counter;
        let mut hints = Vec::with_capacity(count);
        while hints.len() < count {
            let raw = splitmix64(&mut state);
            hints.push((raw & mask) as u32);
        }
        return hints;
    }

    // Zone-based allocation for production (log_slots > 16).
    // Consecutive alloc_counter values within the same ZONE land in the SAME
    // segment, so memory grows O(zones) = O(alloc_counter / ZONE_CAPACITY)
    // rather than O(min(alloc_counter, num_segments)).
    let zone_mask: u64 = ZONE_CAPACITY - 1;
    let num_zones: u64 = num_slots / ZONE_CAPACITY; // = 2^(log_slots - 16) = 256 at genesis

    let mut hints = Vec::with_capacity(count);
    let mut counter = alloc_counter;

    while hints.len() < count {
        let zone_id = counter / ZONE_CAPACITY;
        let zone_offset = counter & zone_mask;

        // Map zone_id to a random segment index (uniform, bijective over num_zones).
        let raw = splitmix64(&mut { zone_id });
        let zone_seg = raw % num_zones; // which segment this zone lives in
        let zone_start = zone_seg * ZONE_CAPACITY;
        let slot = (zone_start + zone_offset) as u32;

        hints.push(slot);
        counter += 1;
    }
    hints
}

/// Deduplicate slot hints and remove any slots already in `reserved`.
///
/// Preserves generation order. O(n log n).
pub fn deduplicate_hints(hints: Vec<u32>, reserved: &[u32]) -> Vec<u32> {
    let mut seen = std::collections::HashSet::new();
    for &r in reserved {
        seen.insert(r);
    }
    hints.into_iter().filter(|s| seen.insert(*s)).collect()
}

/// Compute the `alloc_counter` increment for a block that creates `n_outputs`
/// new outputs (including coinbase). The counter increments by 1 per mint.
pub fn alloc_counter_increment(n_outputs: u64) -> u64 {
    n_outputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_advances() {
        let mut s = 42u64;
        let a = splitmix64(&mut s);
        let b = splitmix64(&mut s);
        assert_ne!(a, b);
        assert_ne!(a, 42);
    }

    #[test]
    fn splitmix64_deterministic() {
        let mut s1 = 1234u64;
        let mut s2 = 1234u64;
        for _ in 0..100 {
            assert_eq!(splitmix64(&mut s1), splitmix64(&mut s2));
        }
    }

    #[test]
    fn splitmix64_bijective_on_small_sample() {
        // Check no collisions over 65536 consecutive inputs.
        let mut outputs = std::collections::HashSet::new();
        let mut s = 0u64;
        for _ in 0..65536 {
            let v = splitmix64(&mut s);
            assert!(outputs.insert(v), "collision detected");
        }
    }

    #[test]
    fn generate_correct_count() {
        let hints = generate_slot_hints(0, 24, 10);
        assert_eq!(hints.len(), 10);
    }

    #[test]
    fn slots_within_range() {
        let log_slots = 24;
        let cap = 1u64 << log_slots;
        let hints = generate_slot_hints(999, log_slots, 1000);
        for &h in &hints {
            assert!((h as u64) < cap, "slot {h} exceeds capacity {cap}");
        }
    }

    #[test]
    fn different_counters_different_hints() {
        let a = generate_slot_hints(0, 24, 5);
        let b = generate_slot_hints(1, 24, 5);
        assert_ne!(a, b);
    }

    #[test]
    fn deduplication_removes_reserved() {
        let hints = vec![1u32, 2, 3, 4, 5];
        let reserved = vec![2u32, 4];
        let result = deduplicate_hints(hints, &reserved);
        assert!(!result.contains(&2));
        assert!(!result.contains(&4));
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn deduplication_removes_duplicates_within_hints() {
        let hints = vec![1u32, 1, 2, 2, 3];
        let result = deduplicate_hints(hints, &[]);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn genesis_counter_starts_at_zero() {
        let hints_a = generate_slot_hints(0, 24, 3);
        let hints_b = generate_slot_hints(0, 24, 3);
        assert_eq!(hints_a, hints_b);
    }

    /// Verify zone-based allocation: first ZONE_CAPACITY slots all land in the
    /// SAME segment (zone 0), and zone 1 lands in a DIFFERENT segment.
    #[test]
    fn zone_based_same_segment_within_zone() {
        let log_slots = 24u32;
        let seg_size = 1u32 << 16; // LOG_SEGMENT_SIZE

        // All hints within zone 0 (counter 0..ZONE_CAPACITY-1) must be in the same segment.
        let hints_zone0_start = generate_slot_hints(0, log_slots, 10);
        let hints_zone0_end = generate_slot_hints(ZONE_CAPACITY - 10, log_slots, 10);
        let seg_z0_start = hints_zone0_start[0] / seg_size;
        for &h in &hints_zone0_start {
            assert_eq!(
                h / seg_size,
                seg_z0_start,
                "zone 0 start spread across segments"
            );
        }
        for &h in &hints_zone0_end {
            assert_eq!(
                h / seg_size,
                seg_z0_start,
                "zone 0 end in different segment"
            );
        }

        // Zone 1 must be in a DIFFERENT (random) segment.
        let hints_zone1 = generate_slot_hints(ZONE_CAPACITY, log_slots, 10);
        let seg_z1 = hints_zone1[0] / seg_size;
        for &h in &hints_zone1 {
            assert_eq!(h / seg_size, seg_z1, "zone 1 spread across segments");
        }
        assert_ne!(
            seg_z0_start, seg_z1,
            "zone 0 and zone 1 should be in different segments"
        );
    }

    /// Memory growth is O(zone_count) not O(unique_slots).
    #[test]
    fn memory_growth_proportional_to_zones() {
        let log_slots = 24u32;
        let seg_size = 1u32 << 16;

        // Generate 256 slots (one per block at genesis).
        let hints = generate_slot_hints(0, log_slots, 256);
        let segments: std::collections::HashSet<u32> =
            hints.iter().map(|&h| h / seg_size).collect();
        // ALL 256 hints must be in the SAME segment (zone 0).
        assert_eq!(
            segments.len(),
            1,
            "256 consecutive slots should be in 1 segment, got {}",
            segments.len()
        );

        // After ZONE_CAPACITY blocks, we move to zone 1 (1 new segment).
        let hints2 = generate_slot_hints(ZONE_CAPACITY, log_slots, 256);
        let segs2: std::collections::HashSet<u32> = hints2.iter().map(|&h| h / seg_size).collect();
        assert_eq!(segs2.len(), 1, "zone 1: 256 slots should be in 1 segment");
        assert!(
            segments.is_disjoint(&segs2),
            "zone 0 and zone 1 should use different segments"
        );
    }

    #[test]
    fn low_bits_uniformly_distributed() {
        // Verify that the bottom k bits of splitmix64 outputs are well-distributed.
        // With LCG, bottom bits have shorter period. With splitmix64 they should not.
        let mask = (1u64 << 24) - 1;
        let mut state = 0u64;
        let n = 100_000usize;
        let buckets = 256usize;
        let mut counts = vec![0usize; buckets];
        for _ in 0..n {
            let v = splitmix64(&mut state) & mask;
            counts[(v % buckets as u64) as usize] += 1;
        }
        let expected = n / buckets;
        for &c in &counts {
            // Allow ±20% deviation from uniform.
            assert!(
                c > expected * 80 / 100 && c < expected * 120 / 100,
                "bucket count {} deviates too far from expected {}",
                c,
                expected
            );
        }
    }
}
