//! Light (no-prove) checks of the region-mode link public-IO layout/spec math.
//!
//! The region wallet-PCS opening claims are threaded through the link's public
//! IO as a tail appended after the recursion + block lanes. The tail offsets,
//! per-claim point ranges and value lanes must be mutually consistent between
//! `link_io_layout_region` (used to size `io` + place the native values in
//! `build_link`) and `link_io_spec_region` (the `IoClaimSpec` the verifier
//! opens), and must lie strictly in the tail without touching the recursion
//! lanes. This guards the offset arithmetic `build_link`'s io fill + pins
//! depend on, WITHOUT the heavy m=24 block-bearing prove (the full end-to-end
//! is the `region_complete_block_bearing_link_e2e` #[ignore] gate).

use noid_ivc_core::public_io::WitnessSlice;
use noid_recursive::acceptance::link::{
    link_io_layout_for, link_io_layout_region, link_io_spec_region, RegionFrozenClaim,
    RegionIoShape,
};

#[test]
fn region_tail_layout_and_spec_are_consistent() {
    let k_log = 23usize;
    let block_bearing = true;
    let base = link_io_layout_for(k_log, block_bearing).len;

    // Frozen claims with VARYING arities (each claim opens a committed column,
    // so arity == slice.log2_len — the column's variable count); max_arity is
    // the widest, and narrower claims zero-pad up to it. Mirrors the real
    // freeze shape (max_arity = 8 for the nq=4 discharge).
    let frozen = vec![
        RegionFrozenClaim {
            slice: WitnessSlice {
                log2_len: 8,
                index: 40,
            },
            arity: 8,
        },
        RegionFrozenClaim {
            slice: WitnessSlice {
                log2_len: 5,
                index: 41,
            },
            arity: 5,
        },
        RegionFrozenClaim {
            slice: WitnessSlice {
                log2_len: 8,
                index: 42,
            },
            arity: 8,
        },
        RegionFrozenClaim {
            slice: WitnessSlice {
                log2_len: 1,
                index: 43,
            },
            arity: 1,
        },
    ];
    let max_arity = 8usize;
    let stride = max_arity + 1;

    let layout = link_io_layout_region(
        k_log,
        block_bearing,
        Some(RegionIoShape {
            n_claims: frozen.len(),
            max_arity,
        }),
    );
    assert_eq!(
        layout.region_tail_offset, base,
        "tail starts right after the base lanes"
    );
    assert_eq!(layout.region_len, frozen.len() * stride);
    assert_eq!(layout.len, base + frozen.len() * stride);

    let spec = link_io_spec_region(k_log, block_bearing, &frozen, max_arity);
    assert_eq!(spec.io_len, layout.len, "spec io_len == layout len");
    assert_eq!(
        spec.claims.len(),
        frozen.len(),
        "one IoClaimSpec per frozen claim"
    );
    assert_eq!(
        spec.io_slice.index, 1,
        "io slice at the fixed dyadic position"
    );

    for (ci, (fc, claim)) in frozen.iter().zip(spec.claims.iter()).enumerate() {
        let b = base + ci * stride;
        // The point range is EXACTLY the claim's arity lanes at the tile base;
        // arity == slice.log2_len is the PublicIoSpec::validate contract.
        assert_eq!(claim.point, b..b + fc.arity, "claim {ci} point range");
        assert_eq!(
            claim.point.len(),
            fc.slice.log2_len,
            "claim {ci} arity == slice vars"
        );
        // The value lane is at the padded max_arity offset (canonical zero
        // padding fills arity..max_arity for the narrow claims).
        assert_eq!(claim.value, b + max_arity, "claim {ci} value lane");
        assert_eq!(claim.slice, fc.slice, "claim {ci} slice");
        // Every referenced lane is strictly in the tail and inside io_len.
        assert!(
            claim.point.start >= base,
            "claim {ci} point in tail (no recursion overlap)"
        );
        assert!(claim.value < spec.io_len, "claim {ci} value within io_len");
        assert!(
            claim.point.end <= claim.value,
            "claim {ci} point ends before its value lane"
        );
    }

    // Tiles are contiguous — no gaps, no overlaps — over [base, len).
    for ci in 1..frozen.len() {
        let prev_end = base + (ci - 1) * stride + max_arity + 1;
        let cur_start = base + ci * stride;
        assert_eq!(prev_end, cur_start, "tiles contiguous at tile {ci}");
    }

    // Default (None) layout is byte-identical (link_io_layout_for delegates to
    // link_io_layout_region(.., None)): zero tail, len == base.
    let d = link_io_layout_region(k_log, block_bearing, None);
    assert_eq!(d.region_len, 0, "no region tail in the default layout");
    assert_eq!(
        d.region_tail_offset, base,
        "default tail offset == base len"
    );
    assert_eq!(d.len, base, "default len unchanged");
    assert_eq!(d.len, link_io_layout_for(k_log, block_bearing).len);
}

/// The empty region shape (n_claims = 0) must collapse to the base layout —
/// a region-mode class with a zero-claim discharge is byte-identical to a
/// non-region one.
#[test]
fn empty_region_shape_is_base_layout() {
    for k_log in [7usize, 22, 23] {
        for bb in [false, true] {
            let base = link_io_layout_for(k_log, bb).len;
            let l = link_io_layout_region(
                k_log,
                bb,
                Some(RegionIoShape {
                    n_claims: 0,
                    max_arity: 8,
                }),
            );
            assert_eq!(l.region_len, 0);
            assert_eq!(l.len, base);
            let spec = link_io_spec_region(k_log, bb, &[], 8);
            assert!(spec.claims.is_empty());
            assert_eq!(spec.io_len, base);
        }
    }
}
